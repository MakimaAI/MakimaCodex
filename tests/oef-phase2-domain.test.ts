import { describe, expect, test } from "bun:test";
import {
  createAssignmentRevision,
  evaluateExecutionEligibility,
  hashAssignment,
  parseAssignment,
  parseExecution,
  parseExecutionAttempt,
  parseExecutionBinding,
  parseExecutionManifest,
  parseFailure,
  transitionAttempt,
  transitionExecution,
} from "../src/oef/phase2";

const HASH = `sha256:${"a".repeat(64)}`;
const OTHER_HASH = `sha256:${"b".repeat(64)}`;

const assignment = {
  schema_version: 1 as const,
  assignment_id: "assignment:demo",
  revision: 1,
  previous_revision_hash: null,
  task_id: "task:demo",
  contract_ref: { revision_id: "contract-revision:demo", hash: HASH },
  objective: "Implement the bounded execution layer.",
  role: "backend-implementer",
  scope: {
    allowed_paths: ["src/oef/phase2/**", "tests/oef-phase2-*.test.ts"],
    denied_paths: [".github/**", "src/security/**"],
  },
  required_capabilities: ["repository-read", "repository-write", "shell", "git"],
  preferred_capabilities: ["structured-output", "tool-events"],
  verification: {
    commands: [
      { executable: "bun", args: ["test", "tests/oef-phase2-domain.test.ts"], timeout_seconds: 60 },
    ],
  },
  required_evidence: ["code-diff", "changed-files", "test-result"],
  budgets: {
    max_wall_time_seconds: 3_600,
    max_idle_seconds: 300,
    max_attempts: 3,
    max_output_bytes: 50_000_000,
  },
  created_by: { type: "human" as const, id: "human:owner" },
  created_at: "2026-07-23T10:00:00.000Z",
};

describe("Phase 2 assignment and binding boundaries", () => {
  test("keeps work intent independent from runtime, model, account, and environment selection", () => {
    expect(parseAssignment(assignment)).toEqual(assignment);
    expect(() => parseAssignment({ ...assignment, runtime_ref: { id: "codex-local" } })).toThrow();
    expect(() => parseAssignment({ ...assignment, model_ref: { provider: "openai" } })).toThrow();
  });

  test("requires a monotonic, hash-linked assignment revision", () => {
    const next = createAssignmentRevision(assignment, {
      ...assignment,
      revision: 2,
      previous_revision_hash: hashAssignment(assignment),
      objective: "Implement and verify the bounded execution layer.",
      created_at: "2026-07-23T10:05:00.000Z",
    });
    expect(next.revision).toBe(2);
    expect(() => createAssignmentRevision(assignment, { ...next, revision: 3 })).toThrow("revision");
    expect(() => createAssignmentRevision(assignment, { ...next, task_id: "task:other" })).toThrow("task");
  });

  test("binds execution choices separately and rejects missing capabilities", () => {
    const binding = parseExecutionBinding({
      schema_version: 1,
      binding_id: "binding:demo",
      assignment_id: assignment.assignment_id,
      assignment_revision: 1,
      agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
      runtime_ref: { id: "codex-local", adapter_version: "1.0.0" },
      model_ref: { provider: "openai", model_class: "coding-high", resolved_model: null },
      environment_ref: { type: "local-worktree", version: 1 },
      account_ref: { id: "account-pool-default" },
      created_by: { type: "human", id: "human:owner" },
      created_at: "2026-07-23T10:01:00.000Z",
    });
    const eligible = evaluateExecutionEligibility({
      assignment: parseAssignment(assignment),
      binding,
      task_risk: "low",
      capabilities: {
        "repository-read": { supported: true, enforcement: "OBSERVED" },
        "repository-write": { supported: true, enforcement: "ENFORCED" },
        shell: { supported: true, enforcement: "OBSERVED" },
        git: { supported: true, enforcement: "OBSERVED" },
      },
    });
    expect(eligible).toEqual({ allowed: true, missing_capabilities: [], insufficient_enforcement: [] });

    const denied = evaluateExecutionEligibility({
      assignment: parseAssignment(assignment),
      binding,
      task_risk: "critical",
      capabilities: {
        "repository-read": { supported: true, enforcement: "OBSERVED" },
        "repository-write": { supported: true, enforcement: "ENFORCED" },
        shell: { supported: true, enforcement: "ADVISORY" },
        git: { supported: false, enforcement: "NONE" },
      },
    });
    expect(denied.allowed).toBeFalse();
    expect(denied.missing_capabilities).toEqual(["git"]);
    expect(denied.insufficient_enforcement).toContain("repository-write");
  });
});

describe("Phase 2 execution state and reproducibility", () => {
  test("keeps execution and attempt state machines distinct and fail-closed", () => {
    expect(transitionExecution("CREATED", "QUEUED")).toBe("QUEUED");
    expect(transitionExecution("RUNNING", "COMPLETED")).toBe("COMPLETED");
    expect(() => transitionExecution("CREATED", "COMPLETED")).toThrow("execution transition");
    expect(transitionAttempt("RUNNING", "COLLECTING")).toBe("COLLECTING");
    expect(transitionAttempt("VERIFYING", "SUCCEEDED")).toBe("SUCCEEDED");
    expect(() => transitionAttempt("CREATED", "SUCCEEDED")).toThrow("attempt transition");
  });

  test("requires each retry to be a new, sequential attempt", () => {
    const execution = parseExecution({
      schema_version: 1,
      execution_id: "execution:demo",
      assignment_id: assignment.assignment_id,
      assignment_revision: 1,
      binding_id: "binding:demo",
      status: "RUNNING",
      current_attempt_id: "attempt:demo-2",
      attempt_count: 2,
      created_at: "2026-07-23T10:02:00.000Z",
      started_at: "2026-07-23T10:03:00.000Z",
      completed_at: null,
      aggregate_version: 4,
    });
    expect(execution.status).toBe("RUNNING");
    expect(() => parseExecutionAttempt({
      schema_version: 1,
      attempt_id: "attempt:demo-2",
      execution_id: execution.execution_id,
      attempt_number: 1,
      base_commit: "abc123",
      workspace_id: "workspace:demo-2",
      context_bundle_hash: HASH,
      binding_hash: OTHER_HASH,
      status: "RUNNING",
      failure_of_previous_attempt: null,
      started_at: "2026-07-23T10:03:00.000Z",
      ended_at: null,
    }, { previous_attempt_number: 1, previous_attempt_id: "attempt:demo-1" })).toThrow("attempt_number");
  });

  test("validates structured failures and the complete execution manifest", () => {
    const failure = parseFailure({
      schema_version: 1,
      failure_id: "failure:demo",
      type: "CONTEXT_LIMIT_EXCEEDED",
      category: "runtime",
      retryability: "conditional",
      scope: { runtime: false, model: true, account: false, task: true },
      safe_actions: ["rebuild-smaller-context", "change-model", "fresh-attempt"],
      unsafe_actions: ["blind-retry-same-context"],
      signature: HASH,
      evidence_refs: ["artifact:stderr"],
    });
    expect(failure.type).toBe("CONTEXT_LIMIT_EXCEEDED");

    const manifest = parseExecutionManifest({
      execution_manifest_version: 1,
      task: { id: "task:demo", contract_hash: HASH },
      assignment: { id: "assignment:demo", revision: 1, hash: OTHER_HASH },
      workflow: { id: "software-development", version: "1.0.0", hash: HASH },
      policy: { id: "safe-default", version: "1.0.0", hash: OTHER_HASH },
      source: { repository: "opencodex", base_commit: "abc123", tree_hash: HASH },
      runtime: { id: "codex-local", binary_version: "1.2.3", adapter_version: "1.0.0", protocol_version: 1 },
      model: { provider: "openai", resolved_id: "gpt-5.6" },
      environment: { provider: "local-worktree", fingerprint: OTHER_HASH },
      context: { bundle_hash: HASH, prompt_hash: OTHER_HASH },
      started_at: "2026-07-23T10:03:00.000Z",
    });
    expect(manifest.context.prompt_hash).toBe(OTHER_HASH);
    expect(() => parseExecutionManifest({ ...manifest, context: { bundle_hash: HASH } })).toThrow();
  });
});
