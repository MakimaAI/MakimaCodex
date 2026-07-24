import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { arch, platform } from "node:os";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { ArtifactRef } from "../../phase1/artifacts/interfaces/artifact-store";
import type { Phase2Runtime } from "./runtime";
import {
  evaluateExecutionEligibility,
  hashAssignment,
  type Assignment,
  type Execution,
  type ExecutionAttempt,
  type ExecutionBinding,
} from "../core/domain";
import { negotiateAdapterProtocol, type FakeRuntimeScenario, type RuntimeAdapter, type NormalizedRuntimeEvent } from "../runtime/protocol";
import { LocalRuntimeDiscovery, SafeRuntimeProbeExecutor } from "../runtime/discovery";
import type { RunnerCapabilities, RunnerExecutionRequest, RunnerExecutionStatus } from "../runner/local-runner-host";
import type { RunnerLease } from "../runner/lease-store";
import type { GitWorktreeWorkspaceManager, WorkspaceStatus } from "../workspace/git-worktree-manager";
import type { ContextBundleCompiler } from "../context/context-bundle";
import type { CodexPromptRenderer } from "../context/prompt-renderer";
import type { MechanicalVerifier } from "../verification/mechanical-verifier";
import { parseVerificationPlan, derivePhase2Result, type Phase2Result, type VerificationResult } from "../verification/models";
import { compareWithBaseline, type KnownBaselineFailure } from "../verification/baseline";
import { EvidencePackageBuilder } from "../evidence/evidence-package";
import { SqlitePhase2Store } from "../persistence/sqlite-store";
import { RetryCircuitBreaker } from "./retry-policy";
import { CompletionSagaService } from "./completion-saga";

export interface RunnerClient {
  getCapabilities(): Promise<RunnerCapabilities>;
  startExecution(request: RunnerExecutionRequest): Promise<RunnerLease>;
  streamEvents(executionId: string, fromSequence?: number): AsyncIterable<NormalizedRuntimeEvent>;
  getStatus(executionId: string): Promise<RunnerExecutionStatus>;
  cancelExecution(executionId: string): Promise<unknown>;
  collectArtifacts(executionId: string): Promise<{ stdout_path: string; stderr_path: string; event_count: number }>;
}

export interface SingleAgentRunRequest {
  task_id: string;
  repository_id: string;
  repository_path: string;
  base_commit: string;
  assignment?: Omit<Assignment, "schema_version" | "assignment_id" | "revision" | "previous_revision_hash" | "task_id" | "contract_ref" | "created_by" | "created_at">;
  binding?: Omit<ExecutionBinding, "schema_version" | "binding_id" | "assignment_id" | "assignment_revision" | "runtime_ref" | "created_by" | "created_at">;
  existing_assignment_id?: string;
  existing_binding_id?: string;
  expected_changed_files?: string[];
  runtime_scenario?: FakeRuntimeScenario;
  known_baseline_failures?: KnownBaselineFailure[];
}

export interface SingleAgentRunReport {
  task_id: string;
  assignment_id: string;
  binding_id: string;
  execution_id: string;
  attempt_id: string;
  workspace_id: string;
  result: Phase2Result;
  changed_files: string[];
  evidence_package_artifact_id: string;
  steps: string[];
}

export class SingleAgentExecutionCoordinator {
  private readonly runtime: Phase2Runtime;
  private readonly adapter: RuntimeAdapter;
  private readonly runner: RunnerClient;
  private readonly workspaceManager: GitWorktreeWorkspaceManager;
  private readonly contextCompiler: ContextBundleCompiler;
  private readonly promptRenderer: CodexPromptRenderer;
  private readonly verifier: MechanicalVerifier;
  private readonly runRoot: string;

  constructor(options: {
    runtime: Phase2Runtime;
    adapter: RuntimeAdapter;
    runner: RunnerClient;
    workspaceManager: GitWorktreeWorkspaceManager;
    contextCompiler: ContextBundleCompiler;
    promptRenderer: CodexPromptRenderer;
    verifier: MechanicalVerifier;
    runRoot: string;
  }) {
    this.runtime = options.runtime;
    this.adapter = options.adapter;
    this.runner = options.runner;
    this.workspaceManager = options.workspaceManager;
    this.contextCompiler = options.contextCompiler;
    this.promptRenderer = options.promptRenderer;
    this.verifier = options.verifier;
    this.runRoot = options.runRoot;
    mkdirSync(this.runRoot, { recursive: true });
  }

  async run(request: SingleAgentRunRequest): Promise<SingleAgentRunReport> {
    const steps: string[] = [];
    const task = this.runtime.phase1.store.getTask(request.task_id);
    if (!task) throw new Error("TASK_NOT_FOUND");
    steps.push("task-read");
    if (!task.active_contract_revision_id) throw new Error("CONTRACT_NOT_ACTIVE");
    const contract = this.runtime.phase1.store.getContractRevision(task.active_contract_revision_id);
    if (!contract || contract.status !== "APPROVED") throw new Error("CONTRACT_NOT_APPROVED");
    steps.push("contract-approved");

    let assignment: Assignment;
    let binding: ExecutionBinding;
    if (request.existing_assignment_id || request.existing_binding_id) {
      if (!request.existing_assignment_id || !request.existing_binding_id) throw new Error("EXISTING_ASSIGNMENT_AND_BINDING_REQUIRED");
      const storedAssignment = this.runtime.store.getAssignment(request.existing_assignment_id);
      const storedBinding = this.runtime.store.getBinding(request.existing_binding_id);
      if (!storedAssignment || !storedBinding || storedAssignment.task_id !== task.task_id) throw new Error("ASSIGNMENT_OR_BINDING_NOT_FOUND");
      if (storedBinding.assignment_id !== storedAssignment.assignment_id || storedBinding.assignment_revision !== storedAssignment.revision) {
        throw new Error("BINDING_MISMATCH");
      }
      assignment = storedAssignment;
      binding = storedBinding;
      steps.push("assignment-read", "binding-read");
    } else {
      if (!request.assignment || !request.binding) throw new Error("ASSIGNMENT_AND_BINDING_INPUT_REQUIRED");
      const assignmentId = this.runtime.ids.next("assignment");
      assignment = requireValue(this.executePhase2({
        type: "CreateAssignment",
        taskId: task.task_id,
        aggregateId: assignmentId,
        expectedVersion: 0,
        payload: { contract_ref: { revision_id: contract.revision_id, hash: contract.canonical_hash }, ...request.assignment },
      })).assignment!;
      steps.push("assignment-created");

      const bindingId = this.runtime.ids.next("binding");
      binding = requireValue(this.executePhase2({
        type: "CreateExecutionBinding",
        taskId: task.task_id,
        aggregateId: bindingId,
        expectedVersion: 0,
        payload: {
          assignment_id: assignment.assignment_id,
          assignment_revision: assignment.revision,
          runtime_ref: { id: this.adapter.manifest.runtime_id, adapter_version: this.adapter.manifest.adapter.version },
          ...request.binding,
        },
      })).binding!;
      steps.push("binding-created");
    }

    const [runtimeSnapshot] = await new LocalRuntimeDiscovery({ probeExecutor: new SafeRuntimeProbeExecutor({ timeoutMs: 5_000 }) })
      .scan([this.adapter]);
    if (!runtimeSnapshot || runtimeSnapshot.probe.health.status !== "HEALTHY") throw new Error("RUNTIME_NOT_HEALTHY");
    const eligibility = evaluateExecutionEligibility({ assignment, binding, task_risk: task.risk.level, capabilities: runtimeSnapshot.probe.capabilities });
    if (!eligibility.allowed) throw new Error(`RUNTIME_CAPABILITY_DENIED: ${JSON.stringify(eligibility)}`);
    steps.push("runtime-healthy");

    const executionId = this.runtime.ids.next("execution");
    let execution = requireValue(this.executePhase2({
      type: "CreateExecution",
      taskId: task.task_id,
      aggregateId: executionId,
      expectedVersion: 0,
      payload: { assignment_id: assignment.assignment_id, assignment_revision: assignment.revision, binding_id: binding.binding_id },
    })).execution!;
    execution = this.transitionExecution(task.task_id, execution, "QUEUED");
    execution = this.transitionExecution(task.task_id, execution, "PREPARING");

    let previousAttemptFailure: { type: string; retry_strategy: string; signature: string } | null = null;
    while (true) {
    const attemptId = this.runtime.ids.next("attempt");
    const workspaceId = this.runtime.ids.next("workspace");
    let workspacePrepared = false;
    let runnerStarted = false;
    let manifestArtifact: ArtifactRef | null = null;
    try {
    const context = this.contextCompiler.compile({
      context_bundle_id: this.runtime.ids.next("context-bundle"),
      assignment,
      contract: contract.document,
      contract_hash: contract.canonical_hash,
      workspace: {
        root: this.workspaceManager.plannedPath(workspaceId),
        base_commit: request.base_commit,
        allowed_paths: assignment.scope.allowed_paths,
        denied_paths: this.workspaceManager.effectiveDeniedPaths(assignment.scope.denied_paths),
      },
      workflow: { ...task.workflow_ref, summary: "Follow the pinned software development workflow." },
      policy: { ...task.policy_pack_ref, summary: "Fail closed on policy, secret, path, and verification failures." },
      project_sources: [],
      previous_attempts: previousAttemptFailure ? [{
        attempt: this.runtime.store.listAttempts(executionId).length,
        summary: `Previous attempt failed with ${previousAttemptFailure.type}; retry strategy ${previousAttemptFailure.retry_strategy}.`,
        failure_signature: previousAttemptFailure.signature,
        artifact_refs: [],
      }] : [],
      risk: task.risk.level,
      budget: { contract_tokens: 3_000, project_rules_tokens: 4_000, repository_summary_tokens: 5_000, previous_attempt_tokens: 2_000, total_target_tokens: 16_000 },
    });
    const prompt = this.promptRenderer.render(context);
    const attemptRunRoot = join(this.runRoot, shortId(attemptId));
    mkdirSync(attemptRunRoot, { recursive: true });
    const promptPath = join(attemptRunRoot, "prompt.md");
    writeFileSync(promptPath, prompt.content, "utf8");

    execution = this.runtime.store.getExecution(executionId)!;
    let attempt = requireValue(this.executePhase2({
      type: "CreateExecutionAttempt",
      taskId: task.task_id,
      aggregateId: execution.execution_id,
      expectedVersion: execution.aggregate_version,
      payload: {
        attempt_id: attemptId,
        base_commit: request.base_commit,
        workspace_id: workspaceId,
        workspace_root: this.workspaceManager.rootPath(),
        context_bundle_hash: context.provenance.content_hash,
        binding_hash: canonicalSha256(binding),
        failure_of_previous_attempt: previousAttemptFailure
          ? { type: encodeAttemptFailure(previousAttemptFailure.type, previousAttemptFailure.signature), retry_strategy: previousAttemptFailure.retry_strategy }
          : null,
      },
    })).attempt!;
    for (const status of ["LEASED", "WORKSPACE_PREPARING"] as const) attempt = this.transitionAttempt(task.task_id, attempt, status);

    const workspace = await this.workspaceManager.prepare({
      workspace_id: workspaceId,
      repository_id: request.repository_id,
      repository_path: request.repository_path,
      task_id: task.task_id,
      attempt_id: attemptId,
      base_commit: request.base_commit,
      allowed_paths: assignment.scope.allowed_paths,
      denied_paths: assignment.scope.denied_paths,
      submodules: "DENY",
    });
    if (workspace.worktree_path !== this.workspaceManager.plannedPath(workspaceId) || workspace.base_commit.toLowerCase() !== request.base_commit.toLowerCase()) {
      throw new Error("WORKSPACE_PREPARATION_DIVERGED_FROM_RESERVED_ATTEMPT");
    }
    workspacePrepared = true;
    steps.push("worktree-created");

    const commandSteps = assignment.verification.commands.map((command, index) => ({
      id: `command-${index + 1}`,
      type: "command" as const,
      command: { executable: command.executable, arguments: command.args },
      timeout_seconds: command.timeout_seconds,
      required: true,
    }));
    const recoveryIdentity = {
      execution_id: execution.execution_id,
      attempt_id: attempt.attempt_id,
      workspace_path: workspace.worktree_path,
    };
    const baseline = await this.verifier.run(parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: `verification:baseline-${shortId(attemptId)}`,
      steps: commandSteps,
    }), {
      workspace_id: workspaceId,
      path: workspace.worktree_path,
      base_commit: workspace.base_commit,
      environment_hash: canonicalSha256({ platform: platform(), arch: arch(), bun: Bun.version }),
      sealed: true,
      changed_files: [],
      path_policy: { decision: "ALLOW", allowed: [], denied: [] },
      patch: "",
    }, recoveryIdentity);
    const baselineFailureSignatures = baseline.steps.filter(step => step.status !== "PASSED").map(step => step.signature);
    const baselineComparison = compareWithBaseline({
      baseline_failure_signatures: baselineFailureSignatures,
      current_failure_signatures: baselineFailureSignatures,
      known_failures: request.known_baseline_failures ?? [],
      now: new Date().toISOString(),
    });
    if (baseline.status !== "PASSED" && baselineComparison.status !== "KNOWN_BASELINE_FAILURES_ONLY") throw new Error("BASELINE_VERIFICATION_FAILED");
    steps.push("baseline-passed");

    for (const status of ["CONTEXT_PREPARING", "STARTING"] as const) attempt = this.transitionAttempt(task.task_id, attempt, status);
    steps.push("context-compiled");

    const manifest = {
      execution_manifest_version: 1 as const,
      task: { id: task.task_id, contract_hash: contract.canonical_hash },
      assignment: { id: assignment.assignment_id, revision: assignment.revision, hash: hashAssignment(assignment) },
      workflow: task.workflow_ref,
      policy: task.policy_pack_ref,
      source: { repository: request.repository_id, base_commit: workspace.base_commit, tree_hash: workspace.tree_hash },
      runtime: {
        id: this.adapter.manifest.runtime_id,
        binary_version: runtimeSnapshot.detection.binary?.version ?? "unknown",
        adapter_version: this.adapter.manifest.adapter.version,
        protocol_version: 1,
      },
      model: { provider: binding.model_ref.provider, resolved_id: binding.model_ref.resolved_model ?? "unknown" },
      environment: { provider: binding.environment_ref.type, fingerprint: canonicalSha256({ platform: platform(), arch: arch(), bun: Bun.version }) },
      context: { bundle_hash: context.provenance.content_hash, prompt_hash: prompt.rendered_hash },
      started_at: new Date().toISOString(),
    };
    manifestArtifact = this.putJson(manifest);

    execution = this.runtime.store.getExecution(execution.execution_id)!;
    if (execution.status !== "RUNNING") execution = this.transitionExecution(task.task_id, execution, "RUNNING");

    const runnerCapabilities = await this.runner.getCapabilities();
    const protocol = negotiateAdapterProtocol(runnerCapabilities.protocol_version, this.adapter.manifest.protocol);
    if (!protocol.ok) throw new Error(protocol.failure);
    runnerStarted = true;
    await this.runner.startExecution({
      adapter_id: this.adapter.manifest.adapter.id,
      runtime_request: {
        execution_id: execution.execution_id,
        attempt_id: attempt.attempt_id,
        workspace_path: workspace.worktree_path,
        prompt_path: promptPath,
        prompt_hash: prompt.rendered_hash,
        inherited_environment: ["PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "CODEX_HOME"],
        injected_secret_refs: [],
        timeouts: {
          startup_seconds: Math.min(60, assignment.budgets.max_wall_time_seconds),
          idle_seconds: assignment.budgets.max_idle_seconds,
          tool_seconds: Math.min(900, assignment.budgets.max_wall_time_seconds),
          total_seconds: assignment.budgets.max_wall_time_seconds,
          graceful_shutdown_seconds: 5,
        },
        output_limit_bytes: assignment.budgets.max_output_bytes,
        scenario: this.adapter.manifest.adapter.id === "fake-runtime" ? (request.runtime_scenario ?? "successful-edit") : undefined,
        resolved_model: binding.model_ref.resolved_model,
      },
    });
    steps.push("runner-started");
    const runtimeEvents: NormalizedRuntimeEvent[] = [];
    for await (const event of this.runner.streamEvents(execution.execution_id, 1)) {
      if (event.attempt_id !== attempt.attempt_id) continue;
      runtimeEvents.push(event);
      this.recordRuntimeEvent(task.task_id, execution.execution_id, event);
      if (event.type === "execution.started" && attempt.status === "STARTING") attempt = this.transitionAttempt(task.task_id, attempt, "RUNNING");
    }
    steps.push("events-streamed");
    const runnerStatus = await this.runner.getStatus(execution.execution_id);
    if (!runnerStatus.event_integrity.complete) throw new Error(`EVENT_STREAM_INCOMPLETE:${runnerStatus.event_integrity.missing_sequences.join(",")}`);
    if (!runnerStatus.exit || runnerStatus.exit.exit_code !== 0 || runnerStatus.exit.timed_out || runnerStatus.exit.failure_type) {
      throw new Error(runnerStatus.exit?.failure_type ?? runnerStatus.exit?.classification.failure_type ?? "RUNTIME_EXECUTION_FAILED");
    }
    const workspaceStatus = await this.workspaceManager.inspect(workspaceId);
    const changedFiles = workspaceStatus.changed_files.map(file => file.path);
    if (request.expected_changed_files) {
      const expected = [...request.expected_changed_files].sort();
      if (JSON.stringify(changedFiles) !== JSON.stringify(expected)) {
        throw new Error(`EXPECTED_CHANGED_FILES: expected=${expected.join(",")} actual=${changedFiles.join(",")}`);
      }
      steps.push("two-files-edited");
    } else steps.push("changes-collected");
    steps.push("runtime-exited");

    if (attempt.status !== "RUNNING") throw new Error("ATTEMPT_NEVER_STARTED");
    attempt = this.transitionAttempt(task.task_id, attempt, "COLLECTING");
    const sealed = await this.workspaceManager.seal(workspaceId);
    steps.push("workspace-sealed");
    if (sealed.path_policy.decision !== "ALLOW") throw new Error("PATH_POLICY_VIOLATION");
    if (!sealed.main_branch_unchanged) throw new Error("MAIN_BRANCH_CHANGED");
    steps.push("path-policy-passed");
    const patch = await this.workspaceManager.exportPatch(workspaceId);
    const patchArtifact = this.putText(patch.content, "text/x-diff");
    steps.push("diff-created");
    attempt = this.transitionAttempt(task.task_id, attempt, "VERIFYING");

    const verificationPlan = parseVerificationPlan({
      schema_version: 1,
      verification_plan_id: `verification:post-${shortId(attemptId)}`,
      steps: [
        ...commandSteps,
        { id: "path-scope", type: "changed-path-policy", required: true },
        { id: "secret-scan", type: "secret-scan", required: true },
        { id: "dependency-change", type: "dependency-change", required: true },
      ],
    });
    const verification = await this.verifier.run(
      verificationPlan,
      sealedWorkspace(workspaceStatus, patch.content, context.provenance.content_hash),
      recoveryIdentity,
    );
    const postVerificationSeal = await this.workspaceManager.assertSeal(workspaceId, sealed.snapshot_hash);
    if (!postVerificationSeal.main_branch_unchanged || !postVerificationSeal.main_worktree_status_unchanged) throw new Error("MAIN_BRANCH_CHANGED");
    const postFailureSignatures = verification.steps.filter(step => step.status !== "PASSED").map(step => step.signature);
    const postBaselineComparison = compareWithBaseline({
      baseline_failure_signatures: baselineFailureSignatures,
      current_failure_signatures: postFailureSignatures,
      known_failures: request.known_baseline_failures ?? [],
      now: new Date().toISOString(),
    });
    const verificationAccepted = verification.status === "PASSED" || postBaselineComparison.status === "KNOWN_BASELINE_FAILURES_ONLY";
    if (!verificationAccepted) throw new Error("MECHANICAL_VERIFICATION_FAILED");
    steps.push("mechanical-verification-passed");
    const secretStep = verification.steps.find(step => step.type === "secret-scan");
    if (secretStep?.status !== "PASSED") throw new Error("SECRET_SCAN_FAILED");
    steps.push("secret-scan-passed");

    const baselineArtifact = this.putJson(baseline);
    const eventsArtifact = this.putJson(runtimeEvents);
    const effectiveVerification: VerificationResult = verificationAccepted && verification.status !== "PASSED"
      ? { ...verification, status: "PASSED", failure_classification: null }
      : verification;
    const verificationArtifact = this.putJson({ verification, baseline_comparison: postBaselineComparison, effective_verification: effectiveVerification });
    const changedFilesArtifact = this.putJson(workspaceStatus.changed_files);
    const secretScanArtifact = this.putJson(secretStep);
    const runnerArtifacts = await this.runner.collectArtifacts(execution.execution_id);
    const runtimeOutputArtifact = this.putText(`${readRequiredEvidenceLog(runnerArtifacts.stdout_path)}\n${readRequiredEvidenceLog(runnerArtifacts.stderr_path)}`, "text/plain");
    const verifierLogArtifacts = verification.steps.flatMap(step => step.artifact_paths).map(path => this.putText(readRequiredEvidenceLog(path), "text/plain"));
    const evidenceArtifacts = [
      baselineArtifact,
      eventsArtifact,
      changedFilesArtifact,
      patchArtifact,
      verificationArtifact,
      secretScanArtifact,
      runtimeOutputArtifact,
      ...verifierLogArtifacts,
    ];
    const evidenceEntries = [
      evidence("baseline", baselineArtifact),
      evidence("runtime-events", eventsArtifact),
      evidence("changed-files", changedFilesArtifact),
      evidence("code-diff", patchArtifact),
      evidence("test-result", verificationArtifact),
      evidence("secret-scan", secretScanArtifact),
      evidence("runtime-summary", runtimeOutputArtifact),
      ...verifierLogArtifacts.map(artifact => evidence("verifier-log", artifact)),
    ];
    const preCompletionSeal = await this.workspaceManager.assertSeal(workspaceId, sealed.snapshot_hash);
    if (!preCompletionSeal.main_branch_unchanged || !preCompletionSeal.main_worktree_status_unchanged) throw new Error("MAIN_BRANCH_CHANGED");

    const result = derivePhase2Result({ execution_completed: true, verification: effectiveVerification });
    if (result !== "READY_FOR_REVIEW") throw new Error(`UNEXPECTED_PHASE2_RESULT: ${result}`);

    const restarted = new SqlitePhase2Store({ databasePath: this.runtime.store.databasePath });
    try {
      if (restarted.getExecution(execution.execution_id)?.status !== "RUNNING") throw new Error("RESTART_EXECUTION_STATE_MISSING");
    } finally { restarted.close(); }
    if (!sealed.main_branch_unchanged) throw new Error("MAIN_BRANCH_CHANGED");

    const completion = new CompletionSagaService(this.runtime);
    completion.prepare({
      execution_id: execution.execution_id,
      task_id: task.task_id,
      attempt_id: attempt.attempt_id,
      assignment_id: assignment.assignment_id,
      contract_revision_id: contract.revision_id,
      criterion_key: contract.document.acceptance_criteria[0]!.key,
      repository_commit: workspace.base_commit,
      manifest_artifact: manifestArtifact,
      evidence_artifacts: evidenceArtifacts,
      evidence_entries: evidenceEntries,
      mechanical_verification: "PASSED",
    });

    execution = this.runtime.store.getExecution(execution.execution_id)!;
    const terminal = requireValue(this.executePhase2({
      type: "CompleteExecutionAttempt",
      taskId: task.task_id,
      aggregateId: execution.execution_id,
      expectedVersion: execution.aggregate_version,
      payload: {},
      actor: { type: "system", id: "system:local-runner" },
    }));
    attempt = terminal.attempt!;
    execution = terminal.execution!;
    steps.push("execution-completed");
    const finalized = completion.finalize(execution.execution_id);
    steps.push("evidence-package-created");
    steps.push("task-ready-for-review");

    const completedRestart = new SqlitePhase2Store({ databasePath: this.runtime.store.databasePath });
    try {
      if (completedRestart.getExecution(execution.execution_id)?.status !== "COMPLETED"
        || completedRestart.getCompletionSaga(execution.execution_id)?.status !== "DONE") throw new Error("RESTART_COMPLETION_SAGA_MISSING");
    } finally { completedRestart.close(); }
    if (this.runtime.store.listEvents(execution.execution_id).length === 0 || this.runtime.phase1.store.listArtifacts(task.task_id).length === 0) {
      throw new Error("PERSISTED_TIMELINE_OR_ARTIFACT_MISSING");
    }
    steps.push("control-plane-restarted");
    steps.push("timeline-persisted");
    steps.push("main-branch-unchanged");

    return {
      task_id: task.task_id,
      assignment_id: assignment.assignment_id,
      binding_id: binding.binding_id,
      execution_id: execution.execution_id,
      attempt_id: attempt.attempt_id,
      workspace_id: workspaceId,
      result,
      changed_files: changedFiles,
      evidence_package_artifact_id: finalized.package_artifact.artifact_id,
      steps,
    };
    } catch (error) {
      const pendingCompletion = this.runtime.store.getCompletionSaga(executionId);
      const terminalExecution = this.runtime.store.getExecution(executionId);
      if (pendingCompletion && terminalExecution?.status === "COMPLETED") {
        steps.push("completion-saga-pending");
        return {
          task_id: task.task_id,
          assignment_id: assignment.assignment_id,
          binding_id: binding.binding_id,
          execution_id: executionId,
          attempt_id: attemptId,
          workspace_id: workspaceId,
          result: "BLOCKED",
          changed_files: [],
          evidence_package_artifact_id: pendingCompletion.package_artifact?.artifact_id ?? pendingCompletion.manifest_artifact.artifact_id,
          steps,
        };
      }
      const failure = await this.handleRunFailure({
        task_id: task.task_id,
        contract_revision_id: contract.revision_id,
        criterion_key: contract.document.acceptance_criteria[0]!.key,
        repository_commit: request.base_commit,
        assignment_id: assignment.assignment_id,
        binding_id: binding.binding_id,
        execution_id: executionId,
        attempt_id: attemptId,
        workspace_id: workspaceId,
        workspace_prepared: workspacePrepared,
        runner_started: runnerStarted,
        manifest_artifact: manifestArtifact,
        max_attempts: assignment.budgets.max_attempts,
        steps,
        error,
      });
      if (failure.retry) {
        previousAttemptFailure = failure.previous_attempt_failure;
        steps.push("fresh-attempt-scheduled");
        continue;
      }
      return failure.report;
    }
    }
  }

  private async handleRunFailure(input: {
    task_id: string;
    contract_revision_id: string;
    criterion_key: string;
    repository_commit: string;
    assignment_id: string;
    binding_id: string;
    execution_id: string;
    attempt_id: string;
    workspace_id: string;
    workspace_prepared: boolean;
    runner_started: boolean;
    manifest_artifact: ArtifactRef | null;
    max_attempts: number;
    steps: string[];
    error: unknown;
  }): Promise<{
    report: SingleAgentRunReport;
    retry: boolean;
    previous_attempt_failure: { type: string; retry_strategy: string; signature: string };
  }> {
    const failureType = classifyCoordinatorFailure(input.error);
    let runnerTerminal = !input.runner_started;
    if (input.runner_started) {
      try {
        await this.runner.cancelExecution(input.execution_id);
        const deadline = Date.now() + 10_000;
        while (Date.now() < deadline) {
          const status = await this.runner.getStatus(input.execution_id);
          if (status.status === "EXITED" || status.status === "INTERRUPTED") { runnerTerminal = true; break; }
          await new Promise(resolve => setTimeout(resolve, 25));
        }
      } catch { runnerTerminal = false; }
    }

    let workspaceQuarantined = false;
    if (input.workspace_prepared) {
      try {
        await this.workspaceManager.cleanup(input.workspace_id, { action: "QUARANTINE", reason: `execution failure: ${failureType}` });
        workspaceQuarantined = true;
      } catch { workspaceQuarantined = false; }
    }

    let attempt = this.runtime.store.getAttempt(input.attempt_id);
    if (attempt && !["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"].includes(attempt.status)) {
      attempt = this.transitionAttempt(input.task_id, attempt, attempt.status === "CREATED" ? "CANCELLED" : "FAILED");
    }
    const failureSignature = canonicalSha256({ failure_type: failureType, reason: normalizeFailureReason(input.error) });
    const priorAttempts = this.runtime.store.listAttempts(input.execution_id).slice(1).map(previous => ({
      failure_signature: decodeAttemptFailure(previous.failure_of_previous_attempt?.type).signature,
      action_signature: previous.failure_of_previous_attempt?.retry_strategy ?? "initial",
      progress: false,
    }));
    const retryDecision = new RetryCircuitBreaker({
      max_attempts: input.max_attempts,
      same_error_threshold: 2,
      similar_action_threshold: 3,
      no_progress_threshold: 2,
    }).decide({
      attempts: priorAttempts,
      failure_type: failureType,
      failure_signature: failureSignature,
      action_signature: "bounded-single-agent-run",
      progress: input.workspace_prepared,
    });
    const attemptCount = this.runtime.store.listAttempts(input.execution_id).length;
    const retry = ["RETRY_TRANSIENT", "REDISPATCH_FRESH_CONTEXT"].includes(retryDecision)
      && attemptCount < input.max_attempts
      && runnerTerminal
      && (workspaceQuarantined || !input.workspace_prepared);
    let execution = this.runtime.store.getExecution(input.execution_id);
    if (!retry && execution && !["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)) {
      execution = this.transitionExecution(input.task_id, execution, execution.status === "CREATED" ? "CANCELLED" : "FAILED");
    }

    const result: Phase2Result = retryDecision === "CREATE_REPAIR" || retryDecision === "RETRY_TRANSIENT" || retryDecision === "REDISPATCH_FRESH_CONTEXT" || retryDecision === "CONTINUE"
      ? "REPAIR_REQUIRED"
      : "BLOCKED";
    const failureArtifact = this.putJson({
      schema_version: 1,
      failure_type: failureType,
      failure_signature: failureSignature,
      runner_terminal_confirmed: runnerTerminal,
      workspace_quarantined: workspaceQuarantined,
      retry_decision: retryDecision,
    });
    const manifestArtifact = input.manifest_artifact ?? this.putJson({
      schema_version: 1,
      execution_id: input.execution_id,
      assignment_id: input.assignment_id,
      attempt_id: input.attempt_id,
      failure_before_manifest: true,
    });
    const evidencePackage = new EvidencePackageBuilder(this.runtime.phase1.artifacts).build({
      task_id: input.task_id,
      contract_revision_id: input.contract_revision_id,
      assignment_id: input.assignment_id,
      attempt_id: input.attempt_id,
      manifest_ref: { artifact_id: manifestArtifact.artifact_id, content_hash: manifestArtifact.content_hash },
      evidence: [evidence("failure", failureArtifact)],
      result: { execution_completed: false, mechanical_verification: result === "REPAIR_REQUIRED" ? "FAILED" : "BLOCKED" },
    }, [manifestArtifact, failureArtifact]);
    const packageArtifact = this.putJson(evidencePackage);
    this.recordAndVerifyPhase1Evidence(
      input.task_id,
      input.contract_revision_id,
      input.criterion_key,
      [manifestArtifact, failureArtifact, packageArtifact],
      input.repository_commit,
      "opencodex.execution-failure",
      `Phase 2 attempt failed with ${failureType}; decision ${retryDecision}.`,
    );
    input.steps.push("failure-classified");
    if (workspaceQuarantined) input.steps.push("workspace-quarantined");
    input.steps.push(retry ? "attempt-terminal" : "execution-terminal");
    return {
      retry,
      previous_attempt_failure: { type: failureType, retry_strategy: retryDecision, signature: failureSignature },
      report: {
        task_id: input.task_id,
        assignment_id: input.assignment_id,
        binding_id: input.binding_id,
        execution_id: input.execution_id,
        attempt_id: input.attempt_id,
        workspace_id: input.workspace_id,
        result,
        changed_files: [],
        evidence_package_artifact_id: packageArtifact.artifact_id,
        steps: input.steps,
      },
    };
  }

  private executePhase2(input: { type: string; taskId: string; aggregateId: string; expectedVersion: number; payload: unknown; actor?: { type: "human" | "system"; id: string }; idempotencyKey?: string }) {
    const commandId = this.runtime.ids.next("command");
    return this.runtime.bus.execute({
      schema_version: 1,
      command_id: commandId,
      command_type: input.type,
      task_id: input.taskId,
      aggregate_id: input.aggregateId,
      expected_aggregate_version: input.expectedVersion,
      actor: input.actor ?? { type: "human", id: "human:local-owner" },
      idempotency_key: input.idempotencyKey ?? commandId,
      payload: input.payload,
    });
  }

  private transitionExecution(taskId: string, execution: Execution, status: Execution["status"]): Execution {
    return requireValue(this.executePhase2({ type: "TransitionExecution", taskId, aggregateId: execution.execution_id, expectedVersion: execution.aggregate_version, payload: { to_status: status } })).execution!;
  }

  private transitionAttempt(taskId: string, attempt: ExecutionAttempt, status: ExecutionAttempt["status"]): ExecutionAttempt {
    const execution = this.runtime.store.getExecution(attempt.execution_id)!;
    return requireValue(this.executePhase2({
      type: "TransitionExecutionAttempt",
      taskId,
      aggregateId: attempt.attempt_id,
      expectedVersion: execution.aggregate_version,
      payload: { to_status: status },
      actor: { type: "system", id: "system:local-runner" },
    })).attempt!;
  }

  private recordRuntimeEvent(taskId: string, executionId: string, event: NormalizedRuntimeEvent): void {
    const execution = this.runtime.store.getExecution(executionId)!;
    requireValue(this.executePhase2({
      type: "RecordRuntimeEvent",
      taskId,
      aggregateId: executionId,
      expectedVersion: execution.aggregate_version,
      payload: event,
      actor: { type: "system", id: "system:local-runner" },
      idempotencyKey: `runner-event:${event.event_id}`,
    }));
  }

  private putJson(value: unknown): ArtifactRef { return this.putText(JSON.stringify(value, null, 2), "application/json"); }
  private putText(content: string, mediaType: string): ArtifactRef {
    return this.runtime.phase1.artifacts.put({
      content,
      media_type: mediaType,
      classification: "internal",
      retention_policy: "execution-evidence",
      created_by: { type: "system", id: "system:local-runner" },
    });
  }

  private recordAndVerifyPhase1Evidence(
    taskId: string,
    revisionId: string,
    criterionKey: string,
    artifacts: ArtifactRef[],
    repositoryCommit: string,
    evidenceType = "opencodex.execution-package",
    summary = "Phase 2 bounded execution and mechanical verification package.",
  ): void {
    const command = (type: string, payload: unknown) => {
      const commandId = this.runtime.phase1.ids.next("command");
      const result = this.runtime.phase1.bus.execute({
        schema_version: 1,
        command_id: commandId,
        command_type: type,
        task_id: taskId,
        expected_aggregate_version: this.runtime.phase1.store.getTask(taskId)!.aggregate_version,
        actor: { type: "system", id: "system:local-cli" },
        idempotency_key: commandId,
        payload,
      });
      if (!result.ok) throw new Error(`PHASE1_COMMAND_FAILED: ${JSON.stringify(result.error)}`);
    };
    command("RecordEvidence", {
      contract_revision_id: revisionId,
      criterion_key: criterionKey,
      type: evidenceType,
      summary,
      artifacts: uniqueArtifacts(artifacts),
      environment: { repository_commit: repositoryCommit },
    });
    const evidenceRecord = this.runtime.phase1.store.listEvidence(taskId).at(-1);
    if (!evidenceRecord) throw new Error("PHASE1_EVIDENCE_NOT_RECORDED");
    command("VerifyEvidence", { evidence_id: evidenceRecord.evidence_id });
  }

  private transitionPhase1Task(taskId: string, to: string): void {
    const task = this.runtime.phase1.store.getTask(taskId)!;
    const commandId = this.runtime.phase1.ids.next("command");
    const result = this.runtime.phase1.bus.execute({
      schema_version: 1,
      command_id: commandId,
      command_type: "TransitionTaskStage",
      task_id: taskId,
      expected_aggregate_version: task.aggregate_version,
      actor: { type: "human", id: "human:local-owner" },
      idempotency_key: commandId,
      payload: { from_stage: task.stage, to_stage: to },
    });
    if (!result.ok || result.value.transition_applied === false) throw new Error(`PHASE1_TRANSITION_FAILED: ${JSON.stringify(result)}`);
  }
}

function requireValue(result: ReturnType<Phase2Runtime["bus"]["execute"]>): Extract<typeof result, { ok: true }>["value"] {
  if (!result.ok) throw new Error(`PHASE2_COMMAND_FAILED: ${JSON.stringify(result.error)}`);
  return result.value;
}

function sealedWorkspace(status: WorkspaceStatus, patch: string, environmentHash: string) {
  return {
    workspace_id: status.workspace.workspace_id,
    path: status.workspace.worktree_path,
    base_commit: status.workspace.base_commit,
    environment_hash: environmentHash,
    sealed: true,
    changed_files: status.changed_files.map(file => ({ path: file.path, dependency_file: file.dependency_file })),
    path_policy: status.path_policy,
    patch,
  };
}

function evidence(type: string, artifact: ArtifactRef): { type: string; artifact_id: string; content_hash: string } {
  return { type, artifact_id: artifact.artifact_id, content_hash: artifact.content_hash };
}
function artifactById(id: string, artifacts: ArtifactRef[]): ArtifactRef | undefined { return artifacts.find(artifact => artifact.artifact_id === id); }
function uniqueArtifacts(artifacts: ArtifactRef[]): ArtifactRef[] { return [...new Map(artifacts.map(artifact => [artifact.artifact_id, artifact])).values()]; }
export function readRequiredEvidenceLog(path: string): string {
  try {
    if (!lstatSync(path).isFile()) throw new Error("not a regular file");
    return readFileSync(path, "utf8");
  } catch (error) {
    throw new Error(`EVIDENCE_LOG_MISSING_OR_UNREADABLE: ${path}`, { cause: error });
  }
}
function shortId(value: string): string { return canonicalSha256(value).slice("sha256:".length, "sha256:".length + 24); }
function encodeAttemptFailure(type: string, signature: string): string { return `${type}@${signature}`.slice(0, 160); }
function decodeAttemptFailure(value: string | undefined): { type: string; signature: string } {
  if (!value) return { type: "none", signature: "none" };
  const separator = value.lastIndexOf("@sha256:");
  return separator < 0
    ? { type: value, signature: canonicalSha256({ legacy_failure_type: value }) }
    : { type: value.slice(0, separator), signature: value.slice(separator + 1) };
}
function normalizeFailureReason(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/\b(?:execution|attempt|workspace|artifact|command):[A-Za-z0-9._:@/-]+/g, "<entity>")
    .replace(/[A-Fa-f0-9]{40,64}/g, "<hash>")
    .replace(/\b\d{4,}\b/g, "<number>")
    .slice(0, 2_000);
}
function classifyCoordinatorFailure(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  if (/SECRET/i.test(message)) return "SECRET_LEAK_DETECTED";
  if (/PATH_POLICY|MAIN_BRANCH|WORKSPACE_SEAL/i.test(message)) return "PATH_POLICY_VIOLATION";
  if (/EVENT_STREAM/i.test(message)) return "EVENT_STREAM_INCOMPLETE";
  if (/ADAPTER_PROTOCOL|PROTOCOL_ERROR/i.test(message)) return "PROTOCOL_ERROR";
  if (/BASELINE|MECHANICAL_VERIFICATION|EXPECTED_CHANGED_FILES/i.test(message)) return "VERIFICATION_FAILED";
  if (/STARTUP_TIMEOUT/i.test(message)) return "STARTUP_TIMEOUT";
  if (/RUNTIME_EXECUTION|RUNTIME_STARTUP/i.test(message)) return "RUNTIME_STARTUP_FAILED";
  if (/TIMEOUT/i.test(message)) return "TOTAL_TIMEOUT";
  return "UNKNOWN";
}
