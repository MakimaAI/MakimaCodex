import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ExecutionReconciler,
  CompletionSagaService,
  discoverRunnerResource,
  inspectProcessIdentity,
  LocalProcessSupervisor,
  LocalReconciliationActionExecutor,
  ProgressDetector,
  RetryCircuitBreaker,
  RunnerEventSpool,
  StartupReconciliationWorker,
  createPhase2Runtime,
  parseCheckpoint,
  parseRunnerInstance,
  parseRuntimeDefinition,
  type Phase2Runtime,
  verifyPersistedProcessIdentity,
} from "../src/oef/phase2";

const HASH = `sha256:${"4".repeat(64)}`;
const processWorker = new URL("./fixtures/oef-phase2-process-worker.ts", import.meta.url).pathname.replace(/^\/(.:)/, "$1");
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) try { rmSync(root, { recursive: true, force: true }); } catch {} });

describe("Phase 2 recovery foundations", () => {
  test("models runner/runtime identity and checkpoints without persisting native resume secrets", () => {
    expect(parseRuntimeDefinition({
      schema_version: 1,
      runtime_id: "runtime:codex-local",
      adapter_id: "codex",
      adapter_version: "1.0.0",
      protocol: { min: 1, max: 1 },
      installed_at: "2026-07-23T10:00:00.000Z",
    }).runtime_id).toBe("runtime:codex-local");
    expect(parseRunnerInstance({
      schema_version: 1,
      runner_id: "runner:local-1",
      instance_nonce: "nonce-1234567890",
      protocol_version: 1,
      status: "HEALTHY",
      started_at: "2026-07-23T10:00:00.000Z",
      heartbeat_at: "2026-07-23T10:00:10.000Z",
    }).status).toBe("HEALTHY");
    const checkpoint = parseCheckpoint({
      schema_version: 1,
      checkpoint_id: "checkpoint:one",
      type: "RUNTIME_SESSION",
      attempt_id: "attempt:one",
      sequence: 87,
      workspace: { commit_or_snapshot: "snapshot:3", diff_hash: HASH },
      runtime: { native_session_id_ref: "secret-ref:session-one", resumable: true },
      progress: { completed_steps: ["inspect-provider-interface", "add-error-classifier"] },
      created_at: "2026-07-23T10:00:00.000Z",
    });
    expect(checkpoint.runtime.native_session_id_ref).toBe("secret-ref:session-one");
    expect(() => parseCheckpoint({ ...checkpoint, runtime: { ...checkpoint.runtime, native_session_id: "raw-secret" } })).toThrow();
  });

  test("classifies restart states without killing a PID that lacks full identity proof", () => {
    const reconciler = new ExecutionReconciler();
    expect(reconciler.assess({
      control_status: "RUNNING",
      runner_status: "RUNNING",
      lease_status: "ACTIVE",
      process: { alive: true, identity_verified: true },
      event_sequences_match: true,
      resumable: true,
    })).toEqual({ state: "HEALTHY", action: "REATTACH" });

    expect(reconciler.assess({
      control_status: "RUNNING",
      runner_status: "MISSING",
      lease_status: "EXPIRED",
      process: { alive: true, identity_verified: false },
      event_sequences_match: false,
      resumable: false,
    })).toEqual({ state: "RUNNER_LOST_PROCESS_UNVERIFIED", action: "DO_NOT_KILL_MARK_ORPHANED" });

    expect(reconciler.assess({
      control_status: "RUNNING",
      runner_status: "MISSING",
      lease_status: "EXPIRED",
      process: { alive: false, identity_verified: false },
      event_sequences_match: false,
      resumable: false,
    })).toEqual({ state: "STATE_ONLY_ORPHAN", action: "MARK_INTERRUPTED_PRESERVE_WORKSPACE" });
  });

  test("binds recovery discovery to the current attempt and rejects multiple live attestations", () => {
    const runnerRoot = mkdtempSync(join(tmpdir(), "oef-phase2-attempt-discovery-"));
    roots.push(runnerRoot);
    const executionId = "execution:retry-race";
    const attemptId = "attempt:retry-2";
    const stateRoot = join(runnerRoot, "state");
    const processesRoot = join(runnerRoot, "processes");
    mkdirSync(stateRoot, { recursive: true });
    mkdirSync(processesRoot, { recursive: true });
    writeFileSync(join(stateRoot, `${createHash("sha256").update(executionId).digest("hex")}.json`), JSON.stringify({
      execution_id: executionId,
      attempt_id: "attempt:retry-1",
      workspace_path: join(runnerRoot, "old-workspace"),
      status: "EXITED",
      process_identity: {
        pid: 999_999, os_start_identity: "dead", executable_path: "dead", executable_hash: HASH,
        started_at: new Date().toISOString(), target_executable_hash: HASH, runner_nonce: "old", attestation_path: "missing",
      },
    }));
    const observed = inspectProcessIdentity(process.pid);
    expect(observed).not.toBeNull();
    const writeAttestation = (directoryName: string, nonce: string) => {
      const directory = join(processesRoot, directoryName);
      mkdirSync(directory, { recursive: true });
      const attestationPath = join(directory, "process-identity.json");
      const identity = {
        ...observed!,
        started_at: new Date().toISOString(),
        target_executable_hash: observed!.executable_hash,
        runner_nonce: nonce,
        attestation_path: attestationPath,
        recovery_identity: { execution_id: executionId, attempt_id: attemptId, workspace_path: join(runnerRoot, "current-workspace") },
      };
      writeFileSync(attestationPath, JSON.stringify(identity));
      return identity;
    };
    const current = writeAttestation("current", "current-nonce");
    mkdirSync(join(processesRoot, "corrupt"));
    writeFileSync(join(processesRoot, "corrupt", "process-identity.json"), "{");
    expect(discoverRunnerResource(runnerRoot, executionId, attemptId)).toMatchObject({
      attempt_id: attemptId,
      process_identity: { pid: current.pid, runner_nonce: "current-nonce" },
      state: null,
    });

    writeAttestation("duplicate-current", "duplicate-nonce");
    expect(() => discoverRunnerResource(runnerRoot, executionId, attemptId))
      .toThrow(`RECOVERY_RESOURCE_AMBIGUOUS:${executionId}:${attemptId}`);
  });

  test("terminates a verified live runner resource whose durable execution is absent", async () => {
    const home = mkdtempSync(join(tmpdir(), "oef-phase2-orphan-resource-"));
    roots.push(home);
    const runtime = createPhase2Runtime({ home });
    const runnerRoot = join(home, "phase2", "runner");
    const supervisor = new LocalProcessSupervisor({ root: join(runnerRoot, "processes") });
    try {
      const ref = await supervisor.start({
        executable: process.execPath,
        arguments: [processWorker, "heartbeat"],
        working_directory: home,
        environment: { inherited: ["PATH", "SYSTEMROOT", "WINDIR", "TEMP"], injected_secret_refs: [] },
        stdin: { mode: "closed" },
        output_protocol: { type: "text", version: 1 },
        timeouts: { startup_seconds: 5, idle_seconds: 5, tool_seconds: 5, total_seconds: 10, graceful_shutdown_seconds: 0.05 },
        output_limit_bytes: 1_000_000,
        prompt_hash: HASH,
      }, {}, {
        execution_id: "execution:missing",
        attempt_id: "attempt:missing",
        workspace_path: home,
      });
      supervisor.notifyStarted(ref.process_id);
      expect(verifyPersistedProcessIdentity(ref.identity)).toBeTrue();
      expect(await new StartupReconciliationWorker(runtime, { runner_root: runnerRoot }).run()).toEqual([]);
      await supervisor.wait(ref.process_id);
      expect(verifyPersistedProcessIdentity(ref.identity)).toBeFalse();
    } finally {
      await supervisor.killAll("test cleanup");
      runtime.close();
    }
  }, 15_000);

  test("executes startup reconciliation and terminalizes durable orphan state", async () => {
    const home = mkdtempSync(join(tmpdir(), "oef-phase2-reconcile-"));
    roots.push(home);
    const runtime = createPhase2Runtime({ home });
    try {
      const taskId = approvedTask(runtime);
      const assignmentId = runtime.ids.next("assignment");
      p2(runtime, "CreateAssignment", taskId, assignmentId, 0, {
        contract_ref: {
          revision_id: runtime.phase1.store.getTask(taskId)!.active_contract_revision_id,
          hash: runtime.phase1.store.getContractRevision(runtime.phase1.store.getTask(taskId)!.active_contract_revision_id!)!.canonical_hash,
        },
        objective: "Reconcile an orphan.", role: "backend-implementer",
        scope: { allowed_paths: ["src/**"], denied_paths: [] }, required_capabilities: ["repository-read"], preferred_capabilities: [],
        verification: { commands: [] }, required_evidence: ["failure"],
        budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 2, max_output_bytes: 100_000 },
      });
      const bindingId = runtime.ids.next("binding");
      p2(runtime, "CreateExecutionBinding", taskId, bindingId, 0, {
        assignment_id: assignmentId, assignment_revision: 1,
        agent_profile_ref: { id: "coding-primary", version: "1.0.0" }, runtime_ref: { id: "fake-local", adapter_version: "1.0.0" },
        model_ref: { provider: "fake", model_class: "test", resolved_model: null }, environment_ref: { type: "local-worktree", version: 1 }, account_ref: { id: "none" },
      });
      const executionId = runtime.ids.next("execution");
      p2(runtime, "CreateExecution", taskId, executionId, 0, { assignment_id: assignmentId, assignment_revision: 1, binding_id: bindingId });
      let execution = runtime.store.getExecution(executionId)!;
      for (const status of ["QUEUED", "PREPARING"] as const) {
        p2(runtime, "TransitionExecution", taskId, executionId, execution.aggregate_version, { to_status: status });
        execution = runtime.store.getExecution(executionId)!;
      }
      const attemptId = runtime.ids.next("attempt");
      p2(runtime, "CreateExecutionAttempt", taskId, executionId, execution.aggregate_version, {
        attempt_id: attemptId, base_commit: "abc123", workspace_id: runtime.ids.next("workspace"),
        context_bundle_hash: HASH, binding_hash: `sha256:${"5".repeat(64)}`, failure_of_previous_attempt: null,
      });
      for (const status of ["LEASED", "WORKSPACE_PREPARING", "CONTEXT_PREPARING", "STARTING", "RUNNING"] as const) {
        execution = runtime.store.getExecution(executionId)!;
        p2(runtime, "TransitionExecutionAttempt", taskId, attemptId, execution.aggregate_version, { to_status: status }, { type: "system", id: "system:local-runner" });
      }
      execution = runtime.store.getExecution(executionId)!;
      p2(runtime, "TransitionExecution", taskId, executionId, execution.aggregate_version, { to_status: "RUNNING" });

      const runnerRoot = join(home, "phase2", "runner");
      new RunnerEventSpool({ root: join(runnerRoot, "events") }).append({
        schema_version: 1,
        event_id: "runtime-event:reconciliation-started",
        sequence: 1,
        execution_id: executionId,
        attempt_id: attemptId,
        type: "execution.started",
        correlation: { call_id: null },
        payload: {},
        source: { runtime: "fake-local", adapter: "fake-runtime@1.0.0" },
        confidence: "AUTHORITATIVE",
        occurred_at: new Date().toISOString(),
      });
      expect(await new LocalReconciliationActionExecutor(runtime, runnerRoot).replayMissingEvents(execution, runtime.store.getAttempt(attemptId))).toBeTrue();
      expect(runtime.store.listEvents(executionId).some(event => event.event_type === "runtime-event.recorded")).toBeTrue();

      const failureEvidenceStates: Array<{ execution: string; attempt: string | null }> = [];
      const actions = {
        replayMissingEvents: async () => true,
        reattach: async () => true,
        terminateVerifiedTree: async () => true,
        terminateVerifiedResource: async () => true,
        quarantineWorkspace: async () => true,
        recordFailure: async (_taskId: string, observedExecution: { status: string }, observedAttempt: { status: string } | null) => {
          failureEvidenceStates.push({ execution: observedExecution.status, attempt: observedAttempt?.status ?? null });
        },
      };
      const healthy = await new StartupReconciliationWorker(runtime, { observer: { observe: () => ({
        control_status: "RUNNING", runner_status: "RUNNING", lease_status: "ACTIVE",
        process: { alive: true, identity_verified: true }, event_sequences_match: true, resumable: true,
      }) }, actions }).run();
      expect(healthy).toEqual([expect.objectContaining({ execution_id: executionId, execution_status: "RUNNING", attempt_status: "RUNNING" })]);

      const task = runtime.phase1.store.getTask(taskId)!;
      const revision = runtime.phase1.store.getContractRevision(task.active_contract_revision_id!)!;
      const put = (label: string) => runtime.phase1.artifacts.put({
        content: label, media_type: "application/json", classification: "internal", retention_policy: "execution-evidence",
        created_by: { type: "system", id: "system:local-runner" },
      });
      const manifest = put("recovery manifest");
      const evidenceArtifact = put("recovery evidence");
      new CompletionSagaService(runtime).prepare({
        execution_id: executionId, task_id: taskId, attempt_id: attemptId, assignment_id: assignmentId,
        contract_revision_id: revision.revision_id, criterion_key: revision.document.acceptance_criteria[0]!.key,
        repository_commit: "abc123", manifest_artifact: manifest, evidence_artifacts: [evidenceArtifact],
        evidence_entries: [{ type: "failure", artifact_id: evidenceArtifact.artifact_id, content_hash: evidenceArtifact.content_hash }],
        mechanical_verification: "PASSED",
      });

      const failedActions = { ...actions, quarantineWorkspace: async () => false };
      await expect(new StartupReconciliationWorker(runtime, { actions: failedActions }).run())
        .rejects.toThrow("RECONCILIATION_WORKSPACE_NOT_QUARANTINED");
      expect(runtime.store.getExecution(executionId)?.status).toBe("RUNNING");
      expect(runtime.store.getAttempt(attemptId)?.status).toBe("RUNNING");
      expect(runtime.store.getCompletionSaga(executionId)).toMatchObject({ status: "PREPARED", outcome: "PENDING" });

      const reports = await new StartupReconciliationWorker(runtime, { actions }).run();
      expect(reports).toEqual([expect.objectContaining({ execution_id: executionId, execution_status: "INTERRUPTED", attempt_status: "ORPHANED" })]);
      expect(runtime.store.getExecution(executionId)?.status).toBe("INTERRUPTED");
      expect(runtime.store.getAttempt(attemptId)?.status).toBe("ORPHANED");
      expect(runtime.store.getCompletionSaga(executionId)).toMatchObject({ status: "DONE", outcome: "ABORTED" });
      expect(failureEvidenceStates).toEqual([{ execution: "RUNNING", attempt: "RUNNING" }]);

      const abortedSaga = runtime.store.getCompletionSaga(executionId)!;
      runtime.store.saveCompletionSaga({ ...abortedSaga, status: "PREPARED", outcome: "PENDING", completed_at: null });
      expect(new CompletionSagaService(runtime).resumePending()).toEqual([{ execution_id: executionId, completed: true }]);
      expect(runtime.store.getCompletionSaga(executionId)).toMatchObject({ status: "DONE", outcome: "ABORTED" });
      await new LocalReconciliationActionExecutor(runtime, runnerRoot).recordFailure(
        taskId,
        runtime.store.getExecution(executionId)!,
        runtime.store.getAttempt(attemptId),
        reports[0]!.assessment,
      );
      expect(runtime.phase1.store.listEvidence(taskId)).toEqual([
        expect.objectContaining({ type: "opencodex.execution-failure", status: "VERIFIED", environment: expect.objectContaining({ reconciliation: true }) }),
      ]);
    } finally { runtime.close(); }
  });
});

function approvedTask(runtime: Phase2Runtime): string {
  const taskId = runtime.phase1.ids.next("task");
  p1(runtime, taskId, "CreateTask", { title: "Reconciliation", workflow: { id: "software-development", version: "1.0.0" }, policy: { id: "safe-default", version: "1.0.0" }, risk: { level: "low", reasons: [] } });
  p1(runtime, taskId, "CreateContractRevision", { parent_revision_id: null, document: {
    schema_version: 1, task_id: taskId, revision: 1, title: "Reconciliation", goal: { summary: "Reconcile safely." },
    scope: { included: ["src/**"], excluded: [] }, constraints: ["Preserve workspace."],
    acceptance_criteria: [{ key: "safe", statement: "Orphan is terminalized.", required_evidence: ["opencodex.test-result"] }],
    risk: { level: "low", reasons: [] }, budgets: { max_attempts: 2, max_parallel_writers: 1, max_cost_units: 5 }, extensions: {},
  } });
  const revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
  p1(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id });
  p1(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Approved." });
  return taskId;
}

function p1(runtime: Phase2Runtime, taskId: string, type: string, payload: unknown): void {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({ schema_version: 1, command_id: commandId, command_type: type, task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0, actor: { type: "human", id: "human:local-owner" }, idempotency_key: commandId, payload });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
}

function p2(runtime: Phase2Runtime, type: string, taskId: string, aggregateId: string, version: number, payload: unknown, actor: { type: "human" | "system"; id: string } = { type: "human", id: "human:local-owner" }): void {
  const commandId = runtime.ids.next("command");
  const result = runtime.bus.execute({ schema_version: 1, command_id: commandId, command_type: type, task_id: taskId, aggregate_id: aggregateId,
    expected_aggregate_version: version, actor, idempotency_key: commandId, payload });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
}

describe("bounded retry and progress decisions", () => {
  test("stops repeated failures and maps failures to safe actions deterministically", () => {
    const breaker = new RetryCircuitBreaker({ max_attempts: 3, same_error_threshold: 3, similar_action_threshold: 3, no_progress_threshold: 5 });
    expect(breaker.decide({ attempts: [], failure_type: "NETWORK_FAILED", failure_signature: HASH, action_signature: "fetch", progress: true }))
      .toBe("RETRY_TRANSIENT");
    expect(breaker.decide({ attempts: [], failure_type: "CONTEXT_LIMIT_EXCEEDED", failure_signature: HASH, action_signature: "prompt", progress: false }))
      .toBe("REDISPATCH_FRESH_CONTEXT");
    expect(breaker.decide({ attempts: [], failure_type: "VERIFICATION_FAILED", failure_signature: HASH, action_signature: "verify", progress: false }))
      .toBe("CREATE_REPAIR");
    expect(breaker.decide({
      attempts: [
        { failure_signature: HASH, action_signature: "same", progress: false },
        { failure_signature: HASH, action_signature: "same", progress: false },
        { failure_signature: HASH, action_signature: "same", progress: false },
      ],
      failure_type: "NETWORK_FAILED",
      failure_signature: HASH,
      action_signature: "same",
      progress: false,
    })).toBe("STOP_BUDGET");
  });

  test("counts measurable state change as progress but not prose or token consumption", () => {
    const detector = new ProgressDetector();
    const previous = {
      changed_files_hash: HASH,
      failing_tests: 3,
      evidence_count: 1,
      failure_signature: HASH,
      build_stage: 1,
      assistant_message_bytes: 10,
      tokens_used: 100,
    };
    expect(detector.evaluate(previous, { ...previous, assistant_message_bytes: 10_000, tokens_used: 10_000 }))
      .toEqual({ progressed: false, signals: [] });
    expect(detector.evaluate(previous, { ...previous, failing_tests: 2, evidence_count: 2 })).toEqual({
      progressed: true,
      signals: ["FAILING_TESTS_REDUCED", "NEW_EVIDENCE"],
    });
  });
});
