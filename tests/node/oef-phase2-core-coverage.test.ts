import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";

const bundlePath = process.env.OEF_PHASE2_CORE_BUNDLE;
if (!bundlePath) {
  test("Phase 2 core coverage harness runs only through coverage:oef:phase2:core", { skip: true }, () => {});
} else {
const core = await import(pathToFileURL(bundlePath).href);
const {
  ExecutionReconciler,
  ProgressDetector,
  RetryCircuitBreaker,
  createAssignmentRevision,
  createPhase2IdGenerator,
  evaluateExecutionEligibility,
  evaluatePathPolicy,
  hashAssignment,
  parseAssignment,
  parseCheckpoint,
  parseExecution,
  parseExecutionAttempt,
  parseExecutionBinding,
  parseExecutionManifest,
  parseFailure,
  parseRunnerInstance,
  parseRuntimeDefinition,
  transitionAttempt,
  transitionExecution,
} = core;

const hashA = `sha256:${"a".repeat(64)}`;
const hashB = `sha256:${"b".repeat(64)}`;
const actor = { type: "human", id: "human:coverage" };
const assignment = () => ({
  schema_version: 1,
  assignment_id: "assignment:coverage",
  revision: 1,
  previous_revision_hash: null,
  task_id: "task:coverage",
  contract_ref: { revision_id: "contract-revision:coverage", hash: hashA },
  objective: "Cover execution decisions.",
  role: "implementer",
  scope: { allowed_paths: ["src/**"], denied_paths: ["src/security/**"] },
  required_capabilities: ["repository-read", "repository-write", "shell", "git"],
  preferred_capabilities: ["structured-output"],
  verification: { commands: [] },
  required_evidence: ["code-diff"],
  budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 3, max_output_bytes: 1000 },
  created_by: actor,
  created_at: "2026-07-23T10:00:00.000Z",
});
const binding = () => ({
  schema_version: 1,
  binding_id: "binding:coverage",
  assignment_id: "assignment:coverage",
  assignment_revision: 1,
  agent_profile_ref: { id: "coding", version: "1.0.0" },
  runtime_ref: { id: "fake", adapter_version: "1.0.0" },
  model_ref: { provider: "fake", model_class: "test", resolved_model: null },
  environment_ref: { type: "local-worktree", version: 1 },
  account_ref: { id: "none" },
  created_by: actor,
  created_at: "2026-07-23T10:00:00.000Z",
});

describe("Phase 2 domain coverage", () => {
  test("assignment validation and revisions", () => {
    const first = parseAssignment(assignment());
    assert.match(hashAssignment(first), /^sha256:/);
    assert.throws(() => parseAssignment({ ...first, revision: 2 }));
    assert.throws(() => parseAssignment({ ...first, required_capabilities: ["git", "git"] }));
    assert.throws(() => parseAssignment({ ...first, preferred_capabilities: ["git"] }));
    const next = createAssignmentRevision(first, { ...first, revision: 2, previous_revision_hash: hashAssignment(first), created_at: "2026-07-23T10:01:00.000Z" });
    assert.equal(next.revision, 2);
    assert.throws(() => createAssignmentRevision(first, { ...next, assignment_id: "assignment:other" }));
    assert.throws(() => createAssignmentRevision(first, { ...next, task_id: "task:other" }));
    assert.throws(() => createAssignmentRevision(first, { ...next, revision: 3 }));
    assert.throws(() => createAssignmentRevision(first, { ...next, previous_revision_hash: hashB }));
    assert.throws(() => createAssignmentRevision(first, { ...next, created_at: "2026-07-23T09:00:00.000Z" }));
  });

  test("binding eligibility and state transitions", () => {
    const a = parseAssignment(assignment());
    const b = parseExecutionBinding(binding());
    const low = evaluateExecutionEligibility({
      assignment: a, binding: b, task_risk: "low",
      capabilities: {
        "repository-read": { supported: true, enforcement: "OBSERVED" },
        "repository-write": { supported: true, enforcement: "ENFORCED" },
        shell: { supported: true, enforcement: "OBSERVED" },
        git: { supported: true, enforcement: "OBSERVED" },
      },
    });
    assert.equal(low.allowed, true);
    const high = evaluateExecutionEligibility({
      assignment: a, binding: b, task_risk: "high",
      capabilities: {
        "repository-read": { supported: true, enforcement: "OBSERVED" },
        "repository-write": { supported: true, enforcement: "ENFORCED" },
        shell: { supported: false, enforcement: "NONE" },
        git: { supported: true, enforcement: "ADVISORY" },
      },
    });
    assert.equal(high.allowed, false);
    assert.throws(() => evaluateExecutionEligibility({ assignment: a, binding: { ...b, assignment_revision: 2 }, task_risk: "low", capabilities: {} }));
    assert.equal(transitionExecution("CREATED", "QUEUED"), "QUEUED");
    assert.throws(() => transitionExecution("CREATED", "CREATED"));
    assert.throws(() => transitionExecution("CREATED", "COMPLETED"));
    assert.equal(transitionAttempt("CREATED", "LEASED"), "LEASED");
    assert.throws(() => transitionAttempt("SUCCEEDED", "RUNNING"));
  });

  test("execution, attempt, failure, and manifest parsers", () => {
    const execution = {
      schema_version: 1, execution_id: "execution:coverage", assignment_id: "assignment:coverage", assignment_revision: 1,
      binding_id: "binding:coverage", status: "RUNNING", current_attempt_id: "attempt:one", attempt_count: 1,
      created_at: "2026-07-23T10:00:00.000Z", started_at: "2026-07-23T10:01:00.000Z", completed_at: null, aggregate_version: 2,
    };
    assert.deepEqual(parseExecution(execution), execution);
    assert.throws(() => parseExecution({ ...execution, attempt_count: 0 }));
    assert.throws(() => parseExecution({ ...execution, status: "COMPLETED" }));
    const attempt = {
      schema_version: 1, attempt_id: "attempt:one", execution_id: "execution:coverage", attempt_number: 1,
      base_commit: "abc", workspace_id: "workspace:one", context_bundle_hash: hashA, binding_hash: hashB,
      status: "RUNNING", failure_of_previous_attempt: null, started_at: "2026-07-23T10:01:00.000Z", ended_at: null,
    };
    assert.deepEqual(parseExecutionAttempt(attempt), attempt);
    assert.throws(() => parseExecutionAttempt({ ...attempt, attempt_number: 2 }));
    assert.throws(() => parseExecutionAttempt({ ...attempt, status: "SUCCEEDED" }));
    assert.throws(() => parseExecutionAttempt({ ...attempt, attempt_id: "attempt:same", attempt_number: 2, failure_of_previous_attempt: { type: "x", retry_strategy: "fresh" } }, { previous_attempt_number: 1, previous_attempt_id: "attempt:same" }));
    assert.throws(() => parseExecutionAttempt({ ...attempt, attempt_id: "attempt:two", attempt_number: 3, failure_of_previous_attempt: { type: "x", retry_strategy: "fresh" } }, { previous_attempt_number: 1, previous_attempt_id: "attempt:one" }));
    assert.equal(parseFailure({ schema_version: 1, failure_id: "failure:one", type: "UNKNOWN", category: "unknown", retryability: "never", scope: { runtime: false, model: false, account: false, task: false }, safe_actions: [], unsafe_actions: [], signature: hashA, evidence_refs: [] }).type, "UNKNOWN");
    assert.equal(parseExecutionManifest({ execution_manifest_version: 1, task: { id: "task:coverage", contract_hash: hashA }, assignment: { id: "assignment:coverage", revision: 1, hash: hashB }, workflow: { id: "w", version: "1.0.0", hash: hashA }, policy: { id: "p", version: "1.0.0", hash: hashB }, source: { repository: "r", base_commit: "abc", tree_hash: hashA }, runtime: { id: "fake", binary_version: "1", adapter_version: "1.0.0", protocol_version: 1 }, model: { provider: "fake", resolved_id: "m" }, environment: { provider: "local", fingerprint: hashB }, context: { bundle_hash: hashA, prompt_hash: hashB }, started_at: "2026-07-23T10:00:00.000Z" }).execution_manifest_version, 1);
  });

  test("ids and infrastructure schemas", () => {
    let now = 10;
    const ids = createPhase2IdGenerator({ now: () => now, random: size => new Uint8Array(size) });
    const first = ids.next("attempt");
    const second = ids.next("attempt");
    now += 1;
    assert.ok(first < second && second < ids.next("attempt"));
    assert.throws(() => createPhase2IdGenerator({ now: () => -1 }).next("attempt"));
    let backwards = 2;
    const bad = createPhase2IdGenerator({ now: () => backwards-- });
    bad.next("attempt");
    assert.throws(() => bad.next("attempt"));
    assert.equal(parseRuntimeDefinition({ schema_version: 1, runtime_id: "runtime:x", adapter_id: "a", adapter_version: "1.0.0", protocol: { min: 1, max: 2 }, installed_at: "2026-07-23T10:00:00.000Z" }).runtime_id, "runtime:x");
    assert.throws(() => parseRuntimeDefinition({ schema_version: 1, runtime_id: "runtime:x", adapter_id: "a", adapter_version: "1.0.0", protocol: { min: 2, max: 1 }, installed_at: "2026-07-23T10:00:00.000Z" }));
    assert.equal(parseRunnerInstance({ schema_version: 1, runner_id: "runner:x", instance_nonce: "123456789012", protocol_version: 1, status: "HEALTHY", started_at: "2026-07-23T10:00:00.000Z", heartbeat_at: "2026-07-23T10:00:01.000Z" }).status, "HEALTHY");
    assert.throws(() => parseRunnerInstance({ schema_version: 1, runner_id: "runner:x", instance_nonce: "123456789012", protocol_version: 1, status: "HEALTHY", started_at: "2026-07-23T10:00:02.000Z", heartbeat_at: "2026-07-23T10:00:01.000Z" }));
    const checkpoint = { schema_version: 1, checkpoint_id: "checkpoint:x", type: "RUNTIME_SESSION", attempt_id: "attempt:x", sequence: 1, workspace: { commit_or_snapshot: "s", diff_hash: hashA }, runtime: { native_session_id_ref: "secret-ref:x", resumable: true }, progress: { completed_steps: [] }, created_at: "2026-07-23T10:00:00.000Z" };
    assert.equal(parseCheckpoint(checkpoint).sequence, 1);
    assert.throws(() => parseCheckpoint({ ...checkpoint, runtime: { native_session_id_ref: null, resumable: true } }));
  });
});

describe("Phase 2 recovery and policy coverage", () => {
  test("every reconciliation outcome", () => {
    const r = new ExecutionReconciler();
    const base = { control_status: "RUNNING", runner_status: "RUNNING", lease_status: "ACTIVE", process: { alive: true, identity_verified: true }, event_sequences_match: true, resumable: true };
    assert.equal(r.assess(base).state, "HEALTHY");
    assert.equal(r.assess({ ...base, event_sequences_match: false }).state, "EVENT_STREAM_DIVERGED");
    assert.equal(r.assess({ ...base, lease_status: "EXPIRED" }).state, "CONTROL_PLANE_LOST");
    assert.equal(r.assess({ ...base, runner_status: "MISSING", process: { alive: true, identity_verified: true } }).state, "RUNNER_LOST_PROCESS_VERIFIED");
    assert.equal(r.assess({ ...base, runner_status: "MISSING", process: { alive: true, identity_verified: false } }).state, "RUNNER_LOST_PROCESS_UNVERIFIED");
    assert.equal(r.assess({ ...base, runner_status: "EXITED", process: { alive: false, identity_verified: false } }).state, "PROCESS_LOST");
    assert.equal(r.assess({ ...base, runner_status: "MISSING", process: { alive: false, identity_verified: false } }).state, "STATE_ONLY_ORPHAN");
    assert.equal(r.assess({ ...base, control_status: "TERMINAL" }).state, "TERMINAL");
  });

  test("every retry and progress outcome", () => {
    const breaker = new RetryCircuitBreaker({ max_attempts: 4, same_error_threshold: 2, similar_action_threshold: 2, no_progress_threshold: 3 });
    const decide = (failure_type, progress = false, attempts = []) => breaker.decide({ attempts, failure_type, failure_signature: hashA, action_signature: "a", progress });
    assert.equal(decide("NETWORK_FAILED"), "RETRY_TRANSIENT");
    assert.equal(decide("CONTEXT_LIMIT_EXCEEDED"), "REDISPATCH_FRESH_CONTEXT");
    assert.equal(decide("VERIFICATION_FAILED"), "CREATE_REPAIR");
    assert.equal(decide("AUTHENTICATION_FAILED"), "NEEDS_HUMAN");
    assert.equal(decide("MODEL_REFUSAL"), "ESCALATE_MODEL");
    assert.equal(decide("UNKNOWN", true), "CONTINUE");
    assert.equal(decide("UNKNOWN", false), "NEEDS_HUMAN");
    assert.equal(decide("NETWORK_FAILED", false, [{ failure_signature: hashA, action_signature: "b", progress: true }]), "NEEDS_HUMAN");
    assert.equal(decide("NETWORK_FAILED", false, [{ failure_signature: hashB, action_signature: "a", progress: true }]), "ESCALATE_ARCHITECTURE");
    assert.equal(decide("NETWORK_FAILED", false, Array.from({ length: 4 }, () => ({ failure_signature: hashB, action_signature: "b", progress: true }))), "STOP_BUDGET");
    const detector = new ProgressDetector();
    const p = { changed_files_hash: hashA, failing_tests: 2, evidence_count: 1, failure_signature: hashA, build_stage: 1, assistant_message_bytes: 1, tokens_used: 1 };
    assert.equal(detector.evaluate(p, p).progressed, false);
    assert.deepEqual(detector.evaluate(p, { ...p, changed_files_hash: hashB, failing_tests: 1, evidence_count: 2, failure_signature: hashB, build_stage: 2 }).signals, ["CHANGED_FILES_DIFFER", "FAILING_TESTS_REDUCED", "NEW_EVIDENCE", "FAILURE_SIGNATURE_CHANGED", "BUILD_STAGE_ADVANCED"]);
  });

  test("path policy canonicalization and glob branches", () => {
    assert.deepEqual(evaluatePathPolicy("src/a.ts", ["src/**"], []), { allowed: true, reason: "ALLOWED_PATH" });
    assert.deepEqual(evaluatePathPolicy("src/security/a.ts", ["src/**"], ["src/security/**"]), { allowed: false, reason: "DENIED_PATH" });
    assert.deepEqual(evaluatePathPolicy("test/a.ts", ["src/**"], []), { allowed: false, reason: "NOT_ALLOWED" });
    for (const path of ["../x", "/x", "C:/x", "a//b", "a/./b", " a", "a?b"]) assert.equal(evaluatePathPolicy(path, ["**"], []).reason, "INVALID_PATH");
    assert.equal(evaluatePathPolicy("a/b/c.ts", ["a/**/c.*"], []).allowed, true);
    assert.equal(evaluatePathPolicy("a/c.ts", ["a/**/c.*"], []).allowed, true);
    assert.equal(evaluatePathPolicy("a/b", ["a/***"], []).reason, "INVALID_PATH");
  });
});
}
