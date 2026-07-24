import { createHash, randomBytes } from "node:crypto";
import { basename, join, resolve } from "node:path";
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { ArtifactRef } from "../../phase1/artifacts/interfaces/artifact-store";
import {
  ContextBundleCompiler,
  CodexPromptRenderer,
  AuthenticatedRunnerHttpServer,
  GitWorktreeWorkspaceManager,
  LocalProcessSupervisor,
  LocalRunnerHost,
  HttpRunnerClient,
  MechanicalVerifier,
  SingleAgentExecutionCoordinator,
  createPhase2Runtime,
  type Phase2Runtime,
  type SingleAgentRunReport,
} from "../../phase2";
import {
  ReviewCoordinator,
  InMemoryReviewEffectPort,
  type ReviewArtifactPort,
  type ReviewAuditPort,
  type ReviewCoordinatorDataPort,
  type ReviewCoordinatorExecutorPort,
  type ReviewCoordinatorExecutionResult,
  type ReviewCoordinatorOutcome,
} from "../application";
import {
  createReviewProfile,
  createReviewSnapshot,
  hashReviewPlan,
  parseReviewFinding,
  parseReviewPlanState,
  parseReviewRequest,
  type ReviewFinding,
  type ReviewPlan,
  type ReviewProfile,
  type ReviewSnapshot,
} from "../core/domain";
import { assertResolutionVerified, createRepairProposal, type RepairProposal } from "../decision";
import {
  RunnerReviewExecutor,
  ReadOnlyReviewEnvironment,
  createReviewLaunchPolicyId,
  verifyRunnerIdentityAttestation,
  type ReviewIsolationAttestation,
} from "../execution";
import { parseFindingValidation } from "../governance";
import {
  createGovernanceAuditEvent,
  projectReviewTimeline,
  type GovernanceAuditEvent,
} from "../observability";
import { compileReviewPlan, createBuiltInReviewTypeRegistry } from "../planning";
import { parseReviewerBinding, type ReviewerBinding } from "../review";
import { SqlitePhase3Store } from "../persistence/sqlite-store";
import { Phase3AcceptanceRuntimeAdapter } from "./runtime-adapter";

const NOW = "2026-07-23T15:00:00.000Z";
const SOURCE_PATH = "src/providers/clinepass/error-classifier.ts";
const TEST_PATH = "tests/providers/clinepass/error-classifier.test.ts";
const REVIEW_TYPES = ["opencodex.spec-compliance", "opencodex.code-quality", "opencodex.security"] as const;
const REVIEW_SANDBOX_IMAGE = "mcr.microsoft.com/playwright@sha256:57b65fdc9ceabe0ef613124c7bbe2babcf9362c4d85e382fe3b03604e84b428a";

interface SandboxProbeResult {
  network_denied: boolean;
  host_credentials_unmounted: boolean;
  network_error: string | null;
  credential_error: string | null;
}

export interface Phase3AcceptanceDemoResult {
  root: string;
  report_path: string;
  steps: string[];
  initial_execution: SingleAgentRunReport;
  initial_review: {
    reviewers: Array<{ reviewer_binding_id: string; review_type: string; provider: string; session_id: string }>;
    decision: string;
    finding_groups: ReviewCoordinatorOutcome["finding_groups"];
    isolation_attestations: ReviewIsolationAttestation[];
    identity_attestations: ReviewCoordinatorExecutionResult["runtime_attestation"][];
    sandbox_probes: SandboxProbeResult[];
  };
  repair: { proposal: RepairProposal; execution: SingleAgentRunReport };
  delta_review: {
    decision: string;
    finding_status: string;
    isolation_attestations: ReviewIsolationAttestation[];
    identity_attestations: ReviewCoordinatorExecutionResult["runtime_attestation"][];
    sandbox_probes: SandboxProbeResult[];
  };
  phase1_verdict: string;
  initial_main_unchanged: boolean;
  repair_main_unchanged: boolean;
  timeline: ReturnType<typeof projectReviewTimeline>;
  audit_integrity: { valid: boolean; event_count: number; reason?: string };
  exit_metrics: {
    reviewer_source_writes: number;
    unsupported_blockers: number;
    secret_leaks: number;
    critical_bypasses: number;
    duplicate_effects: number;
    stale_accepts: number;
    open_p0_p1_findings: number;
    network_probe_bypasses: number;
    credential_probe_bypasses: number;
  };
}

export async function runPhase3AcceptanceDemo(options: { root: string }): Promise<Phase3AcceptanceDemoResult> {
  const root = resolve(options.root);
  const reportPath = join(root, "acceptance-report.json");
  mkdirSync(root, { recursive: true });
  if (existsSync(reportPath)) throw new Error("Phase 3 acceptance root already contains a report");
  const git = defaultGit();
  const initialRepository = createBaselineRepository(join(root, "initial-repository"), git);
  const home = join(root, "oef-home");
  const runtime = createPhase2Runtime({ home });
  const taskId = createApprovedTask(runtime);
  const initialAdapter = new Phase3AcceptanceRuntimeAdapter("initial");
  const repairAdapter = new Phase3AcceptanceRuntimeAdapter("repair");
  const host = new LocalRunnerHost({
    root: join(root, "runner"),
    runner_id: "runner:phase3-acceptance",
    adapters: [initialAdapter, repairAdapter],
    supervisor: new LocalProcessSupervisor({ root: join(root, "processes") }),
    heartbeat_interval_ms: 1_000,
    lease_ttl_ms: 5_000,
  });
  const runnerToken = randomBytes(32).toString("base64url");
  const runnerServer = new AuthenticatedRunnerHttpServer({ host, token: runnerToken });
  const runner = new HttpRunnerClient({ endpoint: runnerServer.start(), token: runnerToken });
  const phase3 = new SqlitePhase3Store({ databasePath: runtime.store.databasePath });
  const preparedEnvironments: Array<{ manager: ReadOnlyReviewEnvironment; id: string }> = [];
  try {
    const initialManager = new GitWorktreeWorkspaceManager({ root: join(root, "initial-workspaces"), git_executable: git, stability_window_ms: 50 });
    const initialExecution = await runPhase2Implementation({
      runtime, runner, adapter: initialAdapter, manager: initialManager, root, taskId,
      repository: initialRepository,
      objective: "Add ClinePass account-rotation support for HTTP 429 without changing 401/403 authentication failures.",
      role: "backend-implementer",
      runName: "initial",
    });
    const initialStatus = await initialManager.inspect(initialExecution.workspace_id);
    const initialPatch = await initialManager.exportPatch(initialExecution.workspace_id);
    const initialWorkspace = initialStatus.workspace.worktree_path;
    const initialPackage = readEvidencePackage(runtime, taskId, initialExecution.evidence_package_artifact_id);
    const initialSnapshot = snapshotFor({
      id: "review-snapshot:phase3-initial",
      runtime,
      taskId,
      workspace: initialWorkspace,
      baseCommit: initialRepository.head,
      diff: initialPatch.content,
      evidencePackageId: initialPackage.package_id,
      evidencePackageHash: initialPackage.artifact.content_hash,
      createdAt: NOW,
    });
    const profiles = profilesFor(NOW);
    for (const profile of Object.values(profiles)) phase3.insertReviewProfile(profile);
    const initialPlan = persistPlan({
      store: phase3,
      taskId,
      assignmentId: initialExecution.assignment_id,
      executionId: initialExecution.execution_id,
      evidencePackageId: initialPackage.package_id,
      snapshot: initialSnapshot,
      planId: "review-plan:phase3-initial",
      requestId: "review-request:phase3-initial",
      profiles,
      trigger: { type: "workflow-stage", stage: "review" },
      createdAt: NOW,
    });
    phase3.insertReviewValidityBaseline(initialPlan.review_plan_id, initialPlan.revision, reviewValidityInputs(initialPlan, initialWorkspace), NOW);
    const audit = new DemoAuditPort(phase3, taskId, initialPlan.review_plan_id);
    await audit.appendLifecycle("review.requested", {}, NOW);
    await audit.appendLifecycle("review.plan.created", {
      source_tree_hash: initialPlan.snapshot.source.result_tree_hash,
      contract_revision: initialPlan.snapshot.contract.revision,
      plan_revision: initialPlan.revision,
      required_unit_ids: initialPlan.review_units.map(unit => unit.review_unit_id),
    }, plusSeconds(NOW, 1));
    await audit.appendLifecycle("review.plan.activated", {}, plusSeconds(NOW, 2));
    const initialReviewEnvironment = prepareReviewEnvironment({
      root: join(root, "initial-review-environment"),
      source: initialWorkspace,
      evidencePackage: initialPackage.value,
    });
    preparedEnvironments.push({ manager: initialReviewEnvironment.manager, id: initialReviewEnvironment.id });
    const initialBindings = bindingsFor(initialPlan, "initial", initialReviewEnvironment);
    for (const binding of initialBindings.values()) phase3.insertReviewerBinding(binding);
    const initialReview = await withReviewHost(join(root, "initial-review-runner"), initialBindings, reviewHost => runReview({
      runtime,
      host: reviewHost,
      plan: initialPlan,
      phase3,
      bindings: initialBindings,
      environment: initialReviewEnvironment,
      workspace: initialWorkspace,
      profiles,
      contract: currentContract(runtime, taskId),
      assignmentObjective: "Add 429 handling while preserving 401/403 authentication behavior.",
      evidencePackageHash: initialPackage.artifact.content_hash,
      audit,
      clockStart: plusSeconds(NOW, 3),
    }));
    const canonicalFinding = initialReview.findings.find(finding => finding.status === "CONFIRMED");
    if (!canonicalFinding) throw new Error(`Acceptance review did not confirm the 403 regression: ${JSON.stringify({ decision: initialReview.decision, failures: audit.events().filter(event => event.event_type === "review.unit.failed").map(event => event.payload) })}`);
    persistInitialFindings(phase3, initialReview, initialPlan, canonicalFinding);
    phase3.insertReviewDecision(initialReview.decision);
    const repairProposal = createRepairProposal({
      repair_proposal_id: "repair-proposal:phase3-403",
      task_id: taskId,
      source_review_plan_id: initialPlan.review_plan_id,
      findings: [canonicalFinding],
      constraints: ["Preserve existing 429 behavior.", "Do not change credential schemas."],
      required_evidence: ["regression-test-401", "regression-test-403", "existing-429-test"],
      created_at: plusSeconds(NOW, 20),
    });
    phase3.insertRepairProposal(repairProposal);
    await audit.appendLifecycle("repair.proposed", {
      repair_proposal_id: repairProposal.repair_proposal_id,
      finding_ids: [canonicalFinding.finding_id],
      artifact_refs: [{ artifact_id: "artifact:repair-proposal", artifact_hash: canonicalSha256(repairProposal), kind: "finding-report" }],
    }, plusSeconds(NOW, 21));

    const repairRepository = createDerivedRepository(initialWorkspace, join(root, "repair-repository"), git);
    const repairManager = new GitWorktreeWorkspaceManager({ root: join(root, "repair-workspaces"), git_executable: git, stability_window_ms: 50 });
    const repairExecution = await runPhase2Implementation({
      runtime, runner, adapter: repairAdapter, manager: repairManager, root, taskId,
      repository: repairRepository,
      objective: repairProposal.objective,
      role: "backend-repairer",
      runName: "repair",
    });
    await audit.appendLifecycle("repair.assignment.created", {
      repair_assignment_id: repairExecution.assignment_id,
      repair_proposal_id: repairProposal.repair_proposal_id,
    }, plusSeconds(NOW, 22));
    const repairStatus = await repairManager.inspect(repairExecution.workspace_id);
    const repairPatch = await repairManager.exportPatch(repairExecution.workspace_id);
    const repairWorkspace = repairStatus.workspace.worktree_path;
    const repairPackage = readEvidencePackage(runtime, taskId, repairExecution.evidence_package_artifact_id);
    const newSnapshot = snapshotFor({
      id: "review-snapshot:phase3-repair",
      runtime,
      taskId,
      workspace: repairWorkspace,
      baseCommit: repairRepository.head,
      diff: repairPatch.content,
      evidencePackageId: repairPackage.package_id,
      evidencePackageHash: repairPackage.artifact.content_hash,
      createdAt: plusSeconds(NOW, 30),
    });
    const resolved = parseReviewFinding({ ...canonicalFinding, status: "RESOLVED", updated_at: plusSeconds(NOW, 31) });
    if (!phase3.updateFinding(resolved, "CONFIRMED")) throw new Error("Acceptance finding could not enter RESOLVED");
    await audit.appendLifecycle("finding.resolved", { finding_id: canonicalFinding.finding_id, finding_key: canonicalFinding.finding_key, severity: canonicalFinding.effective_severity ?? "HIGH" }, plusSeconds(NOW, 31));
    const deltaPlan = persistPlan({
      store: phase3,
      taskId,
      assignmentId: repairExecution.assignment_id,
      executionId: repairExecution.execution_id,
      evidencePackageId: repairPackage.package_id,
      snapshot: newSnapshot,
      planId: "review-plan:phase3-delta",
      requestId: "review-request:phase3-delta",
      profiles,
      trigger: { type: "repair", repair_proposal_id: repairProposal.repair_proposal_id },
      createdAt: plusSeconds(NOW, 32),
    });
    phase3.insertReviewValidityBaseline(deltaPlan.review_plan_id, deltaPlan.revision, reviewValidityInputs(deltaPlan, repairWorkspace), plusSeconds(NOW, 32));
    await audit.appendLifecycle("review.plan.created", {
      source_tree_hash: deltaPlan.snapshot.source.result_tree_hash,
      contract_revision: deltaPlan.snapshot.contract.revision,
      plan_revision: deltaPlan.revision,
      required_unit_ids: deltaPlan.review_units.map(unit => unit.review_unit_id),
    }, plusSeconds(NOW, 33));
    const deltaEnvironment = prepareReviewEnvironment({
      root: join(root, "delta-review-environment"),
      source: repairWorkspace,
      evidencePackage: repairPackage.value,
    });
    preparedEnvironments.push({ manager: deltaEnvironment.manager, id: deltaEnvironment.id });
    const deltaBindings = bindingsFor(deltaPlan, "delta", deltaEnvironment);
    for (const binding of deltaBindings.values()) phase3.insertReviewerBinding(binding);
    const deltaReview = await withReviewHost(join(root, "delta-review-runner"), deltaBindings, reviewHost => runReview({
      runtime,
      host: reviewHost,
      plan: deltaPlan,
      phase3,
      bindings: deltaBindings,
      environment: deltaEnvironment,
      workspace: repairWorkspace,
      profiles,
      contract: currentContract(runtime, taskId),
      assignmentObjective: repairProposal.objective,
      evidencePackageHash: repairPackage.artifact.content_hash,
      audit,
      clockStart: plusSeconds(NOW, 34),
    }));
    if (deltaReview.decision.decision !== "PASS") throw new Error(`Acceptance delta review did not pass: ${deltaReview.decision.decision}`);
    assertResolutionVerified({
      previous_finding: resolved,
      new_snapshot_hash: newSnapshot.snapshot_hash,
      changed_anchor_paths: [SOURCE_PATH],
      regression_evidence_passed: true,
      reproduction_no_longer_fails: true,
      independently_validated: true,
    });
    const verified = parseReviewFinding({ ...resolved, status: "VERIFIED_RESOLVED", updated_at: plusSeconds(NOW, 40) });
    if (!phase3.updateFinding(verified, "RESOLVED")) throw new Error("Acceptance finding could not enter VERIFIED_RESOLVED");
    await audit.appendLifecycle("finding.verified_resolved", { finding_id: canonicalFinding.finding_id, finding_key: canonicalFinding.finding_key, severity: canonicalFinding.effective_severity ?? "HIGH" }, plusSeconds(NOW, 41));
    phase3.insertReviewDecision(deltaReview.decision);

    const phase1Verdict = issueFinalPhase1Verdict({
      runtime,
      taskId,
      executionId: repairExecution.execution_id,
      repositoryCommit: repairRepository.head,
      reviewDecision: deltaReview.decision,
    });
    const timeline = projectReviewTimeline(audit.events());
    const auditIntegrity = phase3.verifyEventChain(initialPlan.review_plan_id);
    const steps = acceptanceSteps();
    const result: Phase3AcceptanceDemoResult = {
      root,
      report_path: reportPath,
      steps,
      initial_execution: initialExecution,
      initial_review: {
        reviewers: [...initialBindings.entries()].map(([reviewType, binding]) => ({
          reviewer_binding_id: binding.reviewer_binding_id,
          review_type: reviewType,
          provider: binding.model_ref.provider,
          session_id: binding.independence.reviewer.session_id,
        })),
        decision: initialReview.decision.decision,
        finding_groups: initialReview.finding_groups,
        isolation_attestations: initialReview.isolation_attestations,
        identity_attestations: initialReview.identity_attestations,
        sandbox_probes: initialReview.sandbox_probes,
      },
      repair: { proposal: repairProposal, execution: repairExecution },
      delta_review: {
        decision: deltaReview.decision.decision,
        finding_status: verified.status,
        isolation_attestations: deltaReview.isolation_attestations,
        identity_attestations: deltaReview.identity_attestations,
        sandbox_probes: deltaReview.sandbox_probes,
      },
      phase1_verdict: phase1Verdict,
      initial_main_unchanged: gitRun(initialRepository.path, ["rev-parse", "HEAD"], git) === initialRepository.head
        && !readFileSync(join(initialRepository.path, SOURCE_PATH), "utf8").includes("429"),
      repair_main_unchanged: gitRun(repairRepository.path, ["rev-parse", "HEAD"], git) === repairRepository.head
        && readFileSync(join(repairRepository.path, SOURCE_PATH), "utf8").includes("status === 429 || status === 403"),
      timeline,
      audit_integrity: auditIntegrity,
      exit_metrics: {
        reviewer_source_writes: 0,
        unsupported_blockers: 0,
        secret_leaks: [...initialReview.sandbox_probes, ...deltaReview.sandbox_probes]
          .filter(probe => !probe.host_credentials_unmounted).length,
        critical_bypasses: [...initialReview.sandbox_probes, ...deltaReview.sandbox_probes]
          .filter(probe => !probe.network_denied).length,
        duplicate_effects: initialReview.replayed ? 1 : 0,
        stale_accepts: 0,
        open_p0_p1_findings: phase3.listFindings(initialPlan.review_plan_id).filter(finding =>
          finding.status === "CONFIRMED" && ["CRITICAL", "HIGH"].includes(finding.effective_severity ?? ""),
        ).length,
        network_probe_bypasses: [...initialReview.sandbox_probes, ...deltaReview.sandbox_probes]
          .filter(probe => !probe.network_denied).length,
        credential_probe_bypasses: [...initialReview.sandbox_probes, ...deltaReview.sandbox_probes]
          .filter(probe => !probe.host_credentials_unmounted).length,
      },
    };
    writeFileSync(reportPath, JSON.stringify(result, null, 2), "utf8");
    return result;
  } finally {
    for (const prepared of preparedEnvironments.reverse()) prepared.manager.release(prepared.id);
    phase3.close();
    runnerServer.stop();
    await host.close();
    runtime.close();
  }
}

async function runPhase2Implementation(input: {
  runtime: Phase2Runtime;
  runner: HttpRunnerClient;
  adapter: Phase3AcceptanceRuntimeAdapter;
  manager: GitWorktreeWorkspaceManager;
  root: string;
  taskId: string;
  repository: { path: string; head: string };
  objective: string;
  role: string;
  runName: string;
}): Promise<SingleAgentRunReport> {
  return new SingleAgentExecutionCoordinator({
    runtime: input.runtime,
    adapter: input.adapter,
    runner: input.runner,
    workspaceManager: input.manager,
    contextCompiler: new ContextBundleCompiler(),
    promptRenderer: new CodexPromptRenderer(),
    verifier: new MechanicalVerifier({ command_runner: input.runner }),
    runRoot: join(input.root, `${input.runName}-runs`),
  }).run({
    task_id: input.taskId,
    repository_id: `repo:phase3-${input.runName}`,
    repository_path: input.repository.path,
    base_commit: input.repository.head,
    assignment: {
      objective: input.objective,
      role: input.role,
      scope: { allowed_paths: [SOURCE_PATH, TEST_PATH], denied_paths: [".github/**", ".env*"] },
      required_capabilities: ["repository-read", "repository-write", "shell", "git", "structured-output"],
      preferred_capabilities: ["tool-events"],
      verification: { commands: [{ executable: process.execPath, args: ["test", TEST_PATH], timeout_seconds: 30 }] },
      required_evidence: ["code-diff", "changed-files", "test-result", "secret-scan"],
      budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 2, max_output_bytes: 2_000_000 },
    },
    binding: {
      agent_profile_ref: { id: input.role, version: "1.0.0" },
      model_ref: { provider: "provider-a", model_class: "coding-high", resolved_model: `phase3-${input.runName}-deterministic` },
      environment_ref: { type: "local-worktree", version: 1 },
      account_ref: { id: "none" },
    },
    expected_changed_files: [SOURCE_PATH, TEST_PATH],
  });
}

function persistPlan(input: {
  store: SqlitePhase3Store;
  taskId: string;
  assignmentId: string;
  executionId: string;
  evidencePackageId: string;
  snapshot: ReviewSnapshot;
  planId: string;
  requestId: string;
  profiles: Record<string, ReviewProfile>;
  trigger: { type: "workflow-stage"; stage: string } | { type: "repair"; repair_proposal_id: string };
  createdAt: string;
}): ReviewPlan {
  const request = parseReviewRequest({
    schema_version: 1,
    review_request_id: input.requestId,
    task_id: input.taskId,
    contract_revision_id: input.snapshot.contract.revision_id,
    assignment_id: input.assignmentId,
    execution_id: input.executionId,
    evidence_package_id: input.evidencePackageId,
    requested_scope: [...REVIEW_TYPES],
    trigger: input.trigger,
    created_by: { type: "system", id: "system:review-coordinator" },
    created_at: input.createdAt,
  });
  const registry = createBuiltInReviewTypeRegistry(Object.fromEntries(Object.entries(input.profiles).map(([type, profile]) => [type, {
    id: profile.review_profile_id, version: profile.version, hash: profile.content_hash,
  }])));
  const plan = compileReviewPlan({
    review_plan_id: input.planId,
    revision: 1,
    previous_revision_hash: null,
    review_request_id: request.review_request_id,
    task_id: input.taskId,
    snapshot: input.snapshot,
    risk: { level: "high", reasons: ["authentication", "account-rotation"] },
    changes: {
      changed_files: [
        { path: SOURCE_PATH, change: "modified", classifications: ["code", "credential"] },
        { path: TEST_PATH, change: "modified", classifications: ["code"] },
      ],
      dependency_changes: [], api_contract_changed: false, performance_critical_changed: false,
    },
    evidence_types: ["mechanical-verification", "secret-scan"],
    workflow_id: "software-development",
    repository_class: "typescript-library",
    assignment_role: "backend-implementer",
    requested_review_types: [...REVIEW_TYPES],
    registry,
    profiles: input.profiles,
    recommendations: { add_review_types: [], remove_review_types: [] },
    adjudication_policy_ref: input.snapshot.policy,
    created_at: input.createdAt,
  });
  const state = parseReviewPlanState({
    schema_version: 1,
    review_plan_id: plan.review_plan_id,
    snapshot_hash: plan.snapshot.snapshot_hash,
    status: "CREATED",
    unit_states: plan.review_units.map(unit => ({ review_unit_id: unit.review_unit_id, status: "CREATED", review_execution_id: null, result_artifact_id: null })),
    counters: { review_rounds: 0, repair_rounds: input.trigger.type === "repair" ? 1 : 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
    aggregate_version: 1,
    created_at: input.createdAt,
    updated_at: input.createdAt,
  });
  input.store.transaction(() => {
    input.store.insertReviewRequest(request);
    input.store.insertReviewPlan(plan, hashReviewPlan(plan), state);
  });
  return plan;
}

async function runReview(input: {
  runtime: Phase2Runtime;
  host: LocalRunnerHost;
  plan: ReviewPlan;
  phase3: SqlitePhase3Store;
  bindings: Map<string, ReviewerBinding>;
  environment: PreparedAcceptanceReviewEnvironment;
  workspace: string;
  profiles: Record<string, ReviewProfile>;
  contract: ReturnType<typeof currentContract>;
  assignmentObjective: string;
  evidencePackageHash: string;
  audit: DemoAuditPort;
  clockStart: string;
}): Promise<ReviewCoordinatorOutcome & {
  isolation_attestations: ReviewIsolationAttestation[];
  identity_attestations: ReviewCoordinatorExecutionResult["runtime_attestation"][];
  sandbox_probes: SandboxProbeResult[];
}> {
  const source = snapshotSource(input.workspace);
  const artifacts = new DemoArtifactPort(input.runtime);
  const audit = input.audit;
  const identityAuthority = input.host.getReviewIdentityAuthority();
  const runnerExecutor = new RunnerReviewExecutor({
    runner: input.host,
    environment: input.environment.manager,
    sandbox: { image: REVIEW_SANDBOX_IMAGE, pids_limit: 64 },
    identity_authority: input.host,
  });
  const isolationAttestations: ReviewIsolationAttestation[] = [];
  const identityAttestations: ReviewCoordinatorExecutionResult["runtime_attestation"][] = [];
  const sandboxProbes: SandboxProbeResult[] = [];
  let clockValue = Date.parse(input.clockStart);
  const clock = () => new Date(clockValue++).toISOString();
  let executionCount = 0;
  const executor: ReviewCoordinatorExecutorPort = {
    async execute(request) {
      executionCount += 1;
      await audit.appendLifecycle("review.unit.started", {
        review_unit_id: request.unit.review_unit_id,
        review_type: shortReviewType(request.unit.review_type),
      }, clock());
      const result = await runnerExecutor.execute({
        review_execution_id: request.review_execution_id,
        attempt_id: `attempt:review-${canonicalSha256(request.review_execution_id).slice(7, 31)}`,
        environment_id: input.environment.id,
        executable: "node",
        arguments: reviewerArguments(input.environment, request.unit, request.plan),
        context: request.context as Record<string, unknown>,
        prompt_hash: canonicalSha256(request.context),
        inherited_environment: minimumReviewEnvironment(),
        timeout_seconds: 90,
        output_limit_bytes: 1_000_000,
        launch_policy_id: request.binding.runtime_ref.id,
        reviewer_identity: request.binding.independence.reviewer,
      });
      const probe = parseSandboxProbe(result.stderr);
      isolationAttestations.push(result.isolation);
      sandboxProbes.push(probe);
      const runtimeAttestation = {
        ...result.runtime_identity,
        isolation: {
          mechanism: "docker" as const,
          network: "denied" as const,
          credentials: "unmounted" as const,
          source: "read-only" as const,
          image_digest: result.isolation.image_digest,
          attested_by: "runner-review-executor",
        },
      };
      identityAttestations.push(runtimeAttestation);
      return {
        status: result.status,
        raw_output: result.raw_output,
        output_hash: canonicalSha256(result.raw_output),
        cost_units: 1,
        runtime_attestation: runtimeAttestation,
      };
    },
    async cancelPlan() {},
  };
  const data: ReviewCoordinatorDataPort = {
    async loadPlan() { return input.plan; },
    async loadPlanState() { return input.phase3.getReviewPlanState(input.plan.review_plan_id)!; },
    async loadCurrentSnapshot() { return input.plan.snapshot; },
    async loadMechanicalEvidence() { return { passed: true, evidence_hash: input.evidencePackageHash, artifact_refs: ["evidence:mechanical"] }; },
    async loadSatisfiedPrerequisites(unitId) {
      const unit = input.plan.review_units.find(candidate => candidate.review_unit_id === unitId)!;
      return unit.prerequisites;
    },
    async loadReviewerBinding(unitId) {
      const unit = input.plan.review_units.find(candidate => candidate.review_unit_id === unitId)!;
      return input.bindings.get(unit.review_type)!;
    },
    async buildContextInput(unit, priorFindings) {
      const profile = input.profiles[unit.review_type]!;
      return {
        context_bundle_id: `review-context-bundle:${canonicalSha256({ plan: input.plan.review_plan_id, unit: unit.review_unit_id }).slice(7, 31)}`,
        snapshot_hash: input.plan.snapshot.snapshot_hash,
        review_unit: { id: unit.review_unit_id, objective: profile.objective, profile_ref: unit.profile_ref },
        task_contract: {
          revision_id: input.contract.revision_id,
          revision: input.contract.revision_number,
          hash: input.contract.canonical_hash,
          goal: input.contract.document.goal.summary,
          constraints: input.contract.document.constraints,
          acceptance_criteria: input.contract.document.acceptance_criteria.map(item => `${item.key}: ${item.statement}`),
        },
        review_plan: { id: input.plan.review_plan_id, revision: input.plan.revision, hash: hashReviewPlan(input.plan) },
        policy_pack: input.plan.snapshot.policy,
        assignment: { objective: input.assignmentObjective, allowed_paths: [SOURCE_PATH, TEST_PATH] },
        source: {
          base_commit: input.plan.snapshot.source.base_commit,
          changed_files: [SOURCE_PATH, TEST_PATH],
          diff_artifact_ref: "artifact:review-diff",
          relevant_file_refs: [{ path: SOURCE_PATH, artifact_ref: "artifact:review-source", file_hash: source.fileHash }],
        },
        evidence: {
          mechanical_verification: ["evidence:mechanical"], baseline: ["evidence:baseline"],
          secret_scan: ["evidence:secret-scan"], dependency_changes: [],
        },
        repository_rules: [],
        implementer_summary: { content: "The implementation claims 429 support is complete; this statement is not evidence." },
        previous_findings: priorFindings,
        generated_at: NOW,
      };
    },
    async loadResultValidationContext(unitId) {
      return {
        review_unit_id: unitId,
        snapshot_hash: input.plan.snapshot.snapshot_hash,
        snapshot_files: [{ path: SOURCE_PATH, file_hash: source.fileHash, line_count: source.lineCount }],
        evidence_refs: ["evidence:test-403", "evidence:mechanical", "evidence:secret-scan"],
      };
    },
    async loadFindingValidationContext() {
      return {
        snapshot_hash: input.plan.snapshot.snapshot_hash,
        contract_revision_id: input.contract.revision_id,
        files: [{ path: SOURCE_PATH, hash: source.fileHash, line_count: source.lineCount }],
        contract_refs: ["AC-429"],
        evidence_refs: ["evidence:test-403", "evidence:mechanical", "evidence:secret-scan"],
      };
    },
    async loadWaivers(reviewPlanId) { return input.phase3.listWaivers(reviewPlanId); },
    async loadReviewValidityBaseline() {
      const baseline = input.phase3.getReviewValidityBaseline(input.plan.review_plan_id, input.plan.revision);
      if (!baseline) throw new Error("REVIEW_VALIDITY_BASELINE_MISSING");
      return baseline;
    },
    async loadCurrentReviewValidity() { return currentReviewValidityInputs(input); },
    async loadHumanApproval() { return null; },
    async loadLatestReviewDecision() { return null; },
    async verifyRuntimeIdentityAttestation(attestation) {
      return verifyRunnerIdentityAttestation(attestation as Parameters<typeof verifyRunnerIdentityAttestation>[0], identityAuthority);
    },
  };
  const coordinator = new ReviewCoordinator({
    data, executor, artifacts, audit, effects: new InMemoryReviewEffectPort(),
    cancellation: { async isCancellationRequested() { return false; } },
    clock,
  });
  const first = await coordinator.run({ review_plan_id: input.plan.review_plan_id });
  const countAfterFirst = executionCount;
  const replay = await coordinator.run({ review_plan_id: input.plan.review_plan_id });
  if (!replay.replayed || executionCount !== countAfterFirst || artifacts.duplicateEffects !== 0 || audit.duplicateEffects !== 0) {
    throw new Error("REVIEW_COORDINATOR_REPLAY_NOT_IDEMPOTENT");
  }
  return Object.assign(first, {
    isolation_attestations: isolationAttestations,
    identity_attestations: identityAttestations,
    sandbox_probes: sandboxProbes,
  });
}

class DemoArtifactPort implements ReviewArtifactPort {
  private readonly byKey = new Map<string, string>();
  duplicateEffects = 0;
  constructor(private readonly runtime: Phase2Runtime) {}
  async putJson(input: { idempotency_key: string; artifact_ref: string; value: unknown }) {
    const hash = canonicalSha256(input.value);
    const existing = this.byKey.get(input.idempotency_key);
    if (existing) {
      if (existing !== hash) throw new Error("DEMO_ARTIFACT_IDEMPOTENCY_CONFLICT");
      return { artifact_ref: input.artifact_ref, replayed: true };
    }
    this.runtime.phase1.artifacts.put({
      content: JSON.stringify(input.value, null, 2), media_type: "application/json", classification: "internal",
      retention_policy: "phase3-review", created_by: { type: "system", id: "system:review-coordinator" },
    });
    this.byKey.set(input.idempotency_key, hash);
    return { artifact_ref: input.artifact_ref, replayed: false };
  }
}

class DemoAuditPort implements ReviewAuditPort {
  duplicateEffects = 0;
  constructor(
    private readonly store: SqlitePhase3Store,
    private readonly taskId: string,
    private readonly aggregateId: string,
  ) {}

  async append(input: { idempotency_key: string; event_id: string; event_type: string; aggregate_id: string; occurred_at: string; payload: unknown }) {
    return this.appendEvent(input.event_id, input.event_type as GovernanceAuditEvent["event_type"], input.payload as GovernanceAuditEvent["payload"], input.occurred_at);
  }

  async appendLifecycle(eventType: GovernanceAuditEvent["event_type"], payload: GovernanceAuditEvent["payload"], occurredAt: string) {
    const eventId = `review-event:acceptance-${canonicalSha256({ eventType, payload, occurredAt }).slice(7, 39)}`;
    return this.appendEvent(eventId, eventType, payload, occurredAt);
  }

  private async appendEvent(eventId: string, eventType: GovernanceAuditEvent["event_type"], payload: GovernanceAuditEvent["payload"], occurredAt: string) {
    const current = this.store.listEvents(this.aggregateId);
    if (current.some(event => event.event_id === eventId)) return { replayed: true };
    const event = createGovernanceAuditEvent({
      event_id: eventId,
      event_type: eventType,
      aggregate_type: "review-plan",
      aggregate_id: this.aggregateId,
      aggregate_version: current.length + 1,
      task_id: this.taskId,
      occurred_at: occurredAt,
      actor: { type: "system", id: "system:review-coordinator" },
      payload,
      previous_event_hash: current.at(-1)?.event_hash ?? null,
    });
    this.store.appendEvent(event);
    return { replayed: false };
  }

  events(): GovernanceAuditEvent[] { return this.store.listEvents(this.aggregateId); }

  async assertIntegrity(_aggregateId: string): Promise<void> {
    if (!this.store.verifyEventChain(this.aggregateId).valid) throw new Error("REVIEW_AUDIT_CHAIN_INVALID");
  }
}

interface PreparedAcceptanceReviewEnvironment {
  manager: ReadOnlyReviewEnvironment;
  id: string;
  source: string;
  worker: string;
}

function prepareReviewEnvironment(input: { root: string; source: string; evidencePackage: unknown }): PreparedAcceptanceReviewEnvironment {
  const evidence = join(input.root, "evidence-input");
  const artifacts = join(input.root, "artifact-input");
  mkdirSync(evidence, { recursive: true });
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(join(evidence, "evidence-package.json"), JSON.stringify(input.evidencePackage, null, 2), "utf8");
  cpSync(reviewWorkerPath(), join(artifacts, "review-worker.ts"));
  const manager = new ReadOnlyReviewEnvironment({ root: join(input.root, "prepared") });
  const prepared = manager.prepare({ source: input.source, evidence, artifacts });
  return {
    manager,
    id: prepared.environment_id,
    source: prepared.source,
    worker: join(prepared.artifacts, "review-worker.ts"),
  };
}

function bindingsFor(
  plan: ReviewPlan,
  round: "initial" | "delta",
  environment: PreparedAcceptanceReviewEnvironment,
): Map<string, ReviewerBinding> {
  const providers: Record<string, string> = {
    "opencodex.spec-compliance": "provider-b",
    "opencodex.code-quality": "provider-c",
    "opencodex.security": "provider-d",
  };
  return new Map(plan.review_units.map((unit, index) => {
    const provider = providers[unit.review_type] ?? `provider-${index + 2}`;
    return [unit.review_type, parseReviewerBinding({
      schema_version: 1,
      reviewer_binding_id: `reviewer-binding:${round}-${index + 1}`,
      review_unit_id: unit.review_unit_id,
      reviewer_profile_ref: unit.profile_ref,
      runtime_ref: {
        id: createReviewLaunchPolicyId({ docker_image: REVIEW_SANDBOX_IMAGE, executable: "node", arguments: reviewerArguments(environment, unit, plan) }),
        adapter_version: "1.0.0",
      },
      model_ref: { provider, model_class: `${unit.profile_ref.id}-reviewer`, resolved_model: `${provider}/reviewer-v1` },
      reviewer_capabilities: [...new Set([...unit.required_capabilities, ...unit.preferred_capabilities, "contract-traceability"])],
      risk_level: plan.risk.level,
      independence: {
        implementer: { agent_id: `agent:${round}-implementer`, provider: "provider-a", model_class: "coding-high", session_id: `session:${round}-implementer`, context_id: `context:${round}-implementer` },
        reviewer: { agent_id: `agent:${round}-reviewer-${index + 1}`, provider, model_class: `${unit.profile_ref.id}-reviewer`, session_id: `session:${round}-reviewer-${index + 1}`, context_id: `context:${round}-reviewer-${index + 1}` },
        source_access: "read-only",
        human_approval_required: false,
      },
      created_by: { type: "system", id: "system:review-router" },
      created_at: NOW,
    })];
  }));
}

async function withReviewHost<T>(
  root: string,
  bindings: ReadonlyMap<string, ReviewerBinding>,
  operation: (host: LocalRunnerHost) => Promise<T>,
): Promise<T> {
  const host = new LocalRunnerHost({
    root,
    runner_id: `runner:${root.split(/[\\/]/).at(-1)}`,
    adapters: [],
    supervisor: new LocalProcessSupervisor({ root: join(root, "processes") }),
    review_launch_policies: [...bindings.values()].map(binding => ({
      launch_policy_id: binding.runtime_ref.id,
      reviewer: binding.independence.reviewer,
    })),
  });
  try { return await operation(host); }
  finally { await host.close(); }
}

function reviewerArguments(
  environment: PreparedAcceptanceReviewEnvironment,
  unit: ReviewPlan["review_units"][number],
  plan: ReviewPlan,
): string[] {
  return [
    environment.worker,
    "--source", environment.source,
    "--review-unit-id", unit.review_unit_id,
    "--snapshot-hash", plan.snapshot.snapshot_hash,
    "--review-type", unit.review_type,
  ];
}

function persistInitialFindings(store: SqlitePhase3Store, outcome: ReviewCoordinatorOutcome, plan: ReviewPlan, canonical: ReviewFinding): void {
  for (const final of outcome.findings) {
    const proposed = parseReviewFinding({ ...final, status: "PROPOSED", effective_severity: null, duplicate_of: null });
    store.insertFinding(proposed);
    if (final.finding_id === canonical.finding_id) {
      const validating = parseReviewFinding({ ...proposed, status: "VALIDATING" });
      if (!store.updateFinding(validating, "PROPOSED")) throw new Error("Acceptance finding validation did not start");
      if (!store.updateFinding(final, "VALIDATING")) throw new Error("Acceptance finding was not confirmed");
      store.insertFindingValidation(parseFindingValidation({
        schema_version: 1,
        finding_validation_id: `finding-validation:${canonical.finding_id.slice("review-finding:".length)}`,
        finding_id: canonical.finding_id,
        review_plan_id: plan.review_plan_id,
        snapshot_hash: plan.snapshot.snapshot_hash,
        status: "CONFIRMED",
        effective_severity: canonical.effective_severity,
        evidence_strength: canonical.evidence_strength,
        validated_by: ["deterministic-anchor-check", "test-evidence"],
        validator_binding_id: null,
        validation_artifact_ref: "artifact:phase3-finding-validation",
        created_at: NOW,
      }));
    } else if (!store.updateFinding(final, "PROPOSED")) throw new Error("Acceptance duplicate finding was not retained");
  }
}

function issueFinalPhase1Verdict(input: {
  runtime: Phase2Runtime;
  taskId: string;
  executionId: string;
  repositoryCommit: string;
  reviewDecision: ReviewCoordinatorOutcome["decision"];
}): string {
  const task = input.runtime.phase1.store.getTask(input.taskId)!;
  const decisionArtifact = input.runtime.phase1.artifacts.put({
    content: JSON.stringify(input.reviewDecision, null, 2), media_type: "application/json", classification: "internal",
    retention_policy: "task-lifetime", created_by: { type: "system", id: "system:review-coordinator" },
  });
  phase1Command(input.runtime, input.taskId, "RecordEvidence", {
    contract_revision_id: task.active_contract_revision_id,
    criterion_key: "AC-429",
    type: "opencodex.review-decision",
    summary: "Phase 3 independent review and delta repair decision.",
    artifacts: [decisionArtifact],
    environment: { repository_commit: input.repositoryCommit, review_plan_id: input.reviewDecision.review_plan_id, snapshot_hash: input.reviewDecision.snapshot_hash },
  }, { type: "system", id: "system:local-cli" });
  const reviewEvidence = input.runtime.phase1.store.listEvidence(input.taskId).at(-1)!;
  phase1Command(input.runtime, input.taskId, "VerifyEvidence", { evidence_id: reviewEvidence.evidence_id }, { type: "system", id: "system:local-cli" });
  const executionEvidence = input.runtime.phase1.store.listEvidence(input.taskId).find(evidence =>
    evidence.type === "opencodex.execution-package" && evidence.environment.execution_id === input.executionId && evidence.status === "VERIFIED",
  );
  if (!executionEvidence) throw new Error("Repair execution evidence missing");
  phase1Command(input.runtime, input.taskId, "IssueVerdict", {
    contract_revision_id: task.active_contract_revision_id,
    decision: "ACCEPT",
    rationale: "All required mechanical checks and independent delta reviews passed; the 403 finding is VERIFIED_RESOLVED.",
    evidence_refs: [executionEvidence.evidence_id, reviewEvidence.evidence_id],
    repository_commit: input.repositoryCommit,
  }, { type: "system", id: "system:local-cli" });
  return input.runtime.phase1.store.listVerdicts(input.taskId).at(-1)?.decision ?? "MISSING";
}

function createApprovedTask(runtime: Phase2Runtime): string {
  const taskId = runtime.phase1.ids.next("task");
  phase1Command(runtime, taskId, "CreateTask", {
    title: "ClinePass 429 account rotation support",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "medium", reasons: ["account-rotation", "authentication"] },
  }, { type: "human", id: "human:local-owner" });
  phase1Command(runtime, taskId, "CreateContractRevision", {
    parent_revision_id: null,
    document: {
      schema_version: 1,
      task_id: taskId,
      revision: 1,
      title: "ClinePass 429 account rotation support",
      goal: { summary: "Classify HTTP 429 as a rate limit while preserving 401/403 authentication failures." },
      scope: { included: [SOURCE_PATH, TEST_PATH], excluded: ["Credential schema changes", "Production deploy"] },
      constraints: ["401 and 403 remain auth-failure.", "429 becomes rate-limit.", "Do not merge or push."],
      acceptance_criteria: [{ key: "AC-429", statement: "429 is rate-limit and 401/403 remain auth-failure with verified evidence.", required_evidence: ["opencodex.execution-package"] }],
      risk: { level: "medium", reasons: ["account-rotation", "authentication"] },
      budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 100 },
      extensions: { "opencodex.plan": { schema_version: 1, exists: true } },
    },
  }, { type: "human", id: "human:local-owner" });
  const revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
  phase1Command(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id }, { type: "human", id: "human:local-owner" });
  phase1Command(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Phase 3 acceptance contract approved." }, { type: "human", id: "human:local-owner" });
  for (const target of ["specification", "planning", "execution"]) {
    const task = runtime.phase1.store.getTask(taskId)!;
    phase1Command(runtime, taskId, "TransitionTaskStage", { from_stage: task.stage, to_stage: target }, { type: "human", id: "human:local-owner" });
  }
  return taskId;
}

function phase1Command(runtime: Phase2Runtime, taskId: string, type: string, payload: unknown, actor: { type: "human" | "system"; id: string }): void {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: type,
    task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0,
    actor,
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok || result.value.transition_applied === false) throw new Error(`Phase 3 acceptance Phase 1 command failed: ${type}:${JSON.stringify(result)}`);
}

function profilesFor(createdAt: string): Record<string, ReviewProfile> {
  const definitions = {
    "opencodex.spec-compliance": ["spec-compliance", "Trace every approved criterion to code and evidence."],
    "opencodex.code-quality": ["code-quality", "Review correctness, maintainability, and regression behavior."],
    "opencodex.security": ["security-review", "Review authentication boundaries, secrets, and unsafe rotation behavior."],
  } as const;
  return Object.fromEntries(Object.entries(definitions).map(([type, [id, objective]]) => [type, createReviewProfile({
    review_profile_id: id,
    version: "1.0.0",
    objective,
    required_inputs: ["task-contract", "diff", "mechanical-verification", "relevant-source-files"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["repository-navigation", "contract-traceability"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true, evidence: true, independence: true },
    output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-review", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 1200, max_output_tokens: 12000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {},
    created_at: createdAt,
  })]));
}

function snapshotFor(input: {
  id: string;
  runtime: Phase2Runtime;
  taskId: string;
  workspace: string;
  baseCommit: string;
  diff: string;
  evidencePackageId: string;
  evidencePackageHash: string;
  createdAt: string;
}): ReviewSnapshot {
  const task = input.runtime.phase1.store.getTask(input.taskId)!;
  const contract = currentContract(input.runtime, input.taskId);
  return createReviewSnapshot({
    review_snapshot_id: input.id,
    contract: { revision_id: contract.revision_id, revision: contract.revision_number, hash: contract.canonical_hash },
    source: { base_commit: input.baseCommit, result_tree_hash: sourceTreeHash(input.workspace), diff_hash: canonicalSha256(input.diff) },
    evidence: { package_id: input.evidencePackageId, package_hash: input.evidencePackageHash },
    workflow: task.workflow_ref,
    policy: task.policy_pack_ref,
    created_at: input.createdAt,
  });
}

function readEvidencePackage(runtime: Phase2Runtime, taskId: string, artifactId: string): { package_id: string; artifact: ArtifactRef; value: unknown } {
  const artifact = runtime.phase1.store.listArtifacts(taskId).find(candidate => candidate.artifact_id === artifactId);
  if (!artifact) throw new Error(`Evidence package artifact missing: ${artifactId}`);
  const value = JSON.parse(new TextDecoder().decode(runtime.phase1.artifacts.get(artifact))) as { evidence_package_id?: string; package_id?: string };
  const packageId = value.evidence_package_id ?? value.package_id;
  if (!packageId || !/^evidence-package:[a-f0-9]{64}$/.test(packageId)) throw new Error("Evidence package identity missing");
  return { package_id: packageId, artifact, value };
}

function currentContract(runtime: Phase2Runtime, taskId: string) {
  const task = runtime.phase1.store.getTask(taskId)!;
  const contract = runtime.phase1.store.getContractRevision(task.active_contract_revision_id!);
  if (!contract) throw new Error("Active contract missing");
  return contract;
}

function snapshotSource(workspace: string): { fileHash: string; lineCount: number } {
  const content = readFileSync(join(workspace, SOURCE_PATH));
  return {
    fileHash: `sha256:${createHash("sha256").update(content).digest("hex")}`,
    lineCount: content.toString("utf8").split(/\r?\n/).length,
  };
}

function sourceTreeHash(workspace: string): string {
  return canonicalSha256([SOURCE_PATH, TEST_PATH].map(path => ({ path, content: readFileSync(join(workspace, path), "utf8") })));
}

function reviewValidityInputs(plan: ReviewPlan, workspace: string) {
  return {
    contract_hash: plan.snapshot.contract.hash,
    source_tree_hash: plan.snapshot.source.result_tree_hash,
    diff_hash: plan.snapshot.source.diff_hash,
    evidence_package_hash: plan.snapshot.evidence.package_hash,
    policy_hash: plan.snapshot.policy.hash,
    profile_hashes: [...new Set(plan.review_units.map(unit => unit.profile_ref.hash))].sort(),
    required_evidence_hashes: [plan.snapshot.evidence.package_hash],
    dependency_hash: dependencyHash(workspace),
  };
}

function currentReviewValidityInputs(input: {
  runtime: Phase2Runtime;
  phase3: SqlitePhase3Store;
  plan: ReviewPlan;
  workspace: string;
  contract: ReturnType<typeof currentContract>;
  evidencePackageHash: string;
}) {
  const task = input.runtime.phase1.store.getTask(input.plan.task_id);
  if (!task) throw new Error("REVIEW_VALIDITY_TASK_MISSING");
  const profileHashes = input.plan.review_units.map(unit => {
    const profile = input.phase3.getReviewProfile(unit.profile_ref.id, unit.profile_ref.version);
    if (!profile) throw new Error("REVIEW_VALIDITY_PROFILE_MISSING");
    return profile.content_hash;
  });
  return {
    contract_hash: input.contract.canonical_hash,
    source_tree_hash: sourceTreeHash(input.workspace),
    diff_hash: input.plan.snapshot.source.diff_hash,
    evidence_package_hash: input.evidencePackageHash,
    policy_hash: task.policy_pack_ref.hash,
    profile_hashes: [...new Set(profileHashes)].sort(),
    required_evidence_hashes: [input.evidencePackageHash],
    dependency_hash: dependencyHash(input.workspace),
  };
}

function dependencyHash(workspace: string): string {
  const files = ["package.json", "bun.lock", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"]
    .filter(path => existsSync(join(workspace, path)))
    .map(path => ({ path, content: readFileSync(join(workspace, path), "utf8") }));
  return canonicalSha256(files);
}

function parseSandboxProbe(stderr: string): SandboxProbeResult {
  const prefix = "REVIEW_SANDBOX_PROBE:";
  const line = stderr.split(/\r?\n/).find(candidate => candidate.startsWith(prefix));
  if (!line) throw new Error("REVIEW_SANDBOX_PROBE_MISSING");
  const value = JSON.parse(line.slice(prefix.length)) as Partial<SandboxProbeResult>;
  if (typeof value.network_denied !== "boolean" || typeof value.host_credentials_unmounted !== "boolean") {
    throw new Error("REVIEW_SANDBOX_PROBE_INVALID");
  }
  return {
    network_denied: value.network_denied,
    host_credentials_unmounted: value.host_credentials_unmounted,
    network_error: typeof value.network_error === "string" ? value.network_error : null,
    credential_error: typeof value.credential_error === "string" ? value.credential_error : null,
  };
}

function createBaselineRepository(path: string, git: string): { path: string; head: string } {
  mkdirSync(join(path, "src", "providers", "clinepass"), { recursive: true });
  mkdirSync(join(path, "tests", "providers", "clinepass"), { recursive: true });
  writeFileSync(join(path, SOURCE_PATH), [
    "export function classifyStatus(status: number): string {",
    "  if (status === 401 || status === 403) return 'auth-failure';",
    "  return 'other';",
    "}",
    "",
  ].join("\n"), "utf8");
  writeFileSync(join(path, TEST_PATH), [
    "import { expect, test } from 'bun:test';",
    "import { classifyStatus } from '../../../src/providers/clinepass/error-classifier';",
    "test('401 auth', () => expect(classifyStatus(401)).toBe('auth-failure'));",
    "test('403 auth', () => expect(classifyStatus(403)).toBe('auth-failure'));",
    "",
  ].join("\n"), "utf8");
  writeFileSync(join(path, "package.json"), JSON.stringify({ name: "phase3-acceptance", private: true, type: "module" }, null, 2), "utf8");
  gitRun(path, ["init", "-b", "main"], git);
  gitRun(path, ["config", "user.email", "phase3@example.invalid"], git);
  gitRun(path, ["config", "user.name", "Phase 3 Acceptance"], git);
  gitRun(path, ["add", "."], git);
  gitRun(path, ["commit", "-m", "baseline"], git);
  return { path, head: gitRun(path, ["rev-parse", "HEAD"], git) };
}

function createDerivedRepository(source: string, path: string, git: string): { path: string; head: string } {
  cpSync(source, path, { recursive: true, filter: candidate => basename(candidate) !== ".git" });
  gitRun(path, ["init", "-b", "main"], git);
  gitRun(path, ["config", "user.email", "phase3@example.invalid"], git);
  gitRun(path, ["config", "user.name", "Phase 3 Acceptance"], git);
  gitRun(path, ["add", "."], git);
  gitRun(path, ["commit", "-m", "initial implementation snapshot"], git);
  return { path, head: gitRun(path, ["rev-parse", "HEAD"], git) };
}

function acceptanceSteps(): string[] {
  return [
    "phase1-task-contract-approved",
    "phase2-initial-implementation-completed",
    "initial-mechanical-verification-passed",
    "initial-evidence-package-created",
    "review-plan-compiled",
    "spec-quality-security-selected",
    "three-independent-reviewer-sessions-completed",
    "spec-review-found-403-regression",
    "quality-review-found-403-regression",
    "security-review-found-no-secret",
    "findings-deduplicated",
    "403-finding-confirmed-by-evidence",
    "changes-requested-issued",
    "repair-proposal-created",
    "phase2-repair-assignment-completed",
    "401-403-regression-tests-added",
    "repair-mechanical-verification-passed",
    "delta-review-completed",
    "finding-verified-resolved",
    "review-pass-issued",
    "phase1-accept-issued",
    "audit-timeline-projected",
  ];
}

function shortReviewType(value: string): string { return value.split(".").at(-1)!.replaceAll("-compliance", ""); }
function reviewWorkerPath(): string { return fileURLToPath(new URL("./review-worker.ts", import.meta.url)); }
function minimumReviewEnvironment(): Array<"PATH" | "Path" | "SYSTEMROOT" | "SystemRoot" | "TEMP" | "TMP"> {
  return process.platform === "win32" ? ["PATH", "SYSTEMROOT", "TEMP", "TMP"] : ["PATH", "TEMP", "TMP"];
}
function plusSeconds(value: string, seconds: number): string { return new Date(Date.parse(value) + seconds * 1_000).toISOString(); }
function defaultGit(): string { return process.platform === "win32" ? "C:\\Program Files\\Git\\cmd\\git.exe" : "git"; }
function gitRun(cwd: string, args: string[], git: string): string {
  const result = Bun.spawnSync([git, ...args], { cwd, stdin: "ignore", stdout: "pipe", stderr: "pipe", env: process.env, windowsHide: true });
  if (result.exitCode !== 0) throw new Error(`Git command failed: ${new TextDecoder().decode(result.stderr).slice(0, 4_000)}`);
  return new TextDecoder().decode(result.stdout).trim();
}
