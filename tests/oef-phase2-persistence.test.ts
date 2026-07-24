import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createPhase2Runtime, type Phase2Runtime } from "../src/oef/phase2";
import type { Actor } from "../src/oef/phase1/core/shared/actor";

const homes: string[] = [];
afterEach(() => {
  for (const home of homes.splice(0)) {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* Bun can retain a closed WAL handle briefly on Windows */ }
  }
});

function home(): string {
  const value = mkdtempSync(join(tmpdir(), "oef-phase2-store-"));
  homes.push(value);
  return value;
}

function phase1Command(runtime: Phase2Runtime, taskId: string, commandType: string, payload: unknown) {
  const commandId = runtime.phase1.ids.next("command");
  const result = runtime.phase1.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: commandType,
    task_id: taskId,
    expected_aggregate_version: runtime.phase1.store.getTask(taskId)?.aggregate_version ?? 0,
    actor: { type: "human", id: "human:local-owner" },
    idempotency_key: commandId,
    payload,
  });
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
}

function approvedTask(runtime: Phase2Runtime): { taskId: string; revisionId: string; contractHash: string } {
  const taskId = runtime.phase1.ids.next("task");
  phase1Command(runtime, taskId, "CreateTask", {
    title: "Phase 2 persistence",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "low", reasons: [] },
  });
  phase1Command(runtime, taskId, "CreateContractRevision", {
    parent_revision_id: null,
    document: {
      schema_version: 1,
      task_id: taskId,
      revision: 1,
      title: "Phase 2 persistence",
      goal: { summary: "Persist bounded single-agent executions." },
      scope: { included: ["src/oef/phase2/**"], excluded: [".github/**"] },
      constraints: ["No direct runner database writes."],
      acceptance_criteria: [{ key: "persist", statement: "State survives restart.", required_evidence: ["opencodex.test-result"] }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 3, max_parallel_writers: 1, max_cost_units: 10 },
      extensions: { "opencodex.plan": { schema_version: 1, exists: true } },
    },
  });
  const revision = runtime.phase1.store.listContractRevisions(taskId)[0]!;
  phase1Command(runtime, taskId, "ProposeContractRevision", { revision_id: revision.revision_id });
  phase1Command(runtime, taskId, "ApproveContractRevision", { revision_id: revision.revision_id, rationale: "Approved for execution." });
  return { taskId, revisionId: revision.revision_id, contractHash: revision.canonical_hash };
}

function command(runtime: Phase2Runtime, input: {
  commandId?: string;
  type: string;
  taskId: string;
  aggregateId: string;
  expectedVersion: number;
  payload: unknown;
  actor?: Actor;
}) {
  const commandId = input.commandId ?? runtime.ids.next("command");
  return runtime.bus.execute({
    schema_version: 1,
    command_id: commandId,
    command_type: input.type,
    task_id: input.taskId,
    aggregate_id: input.aggregateId,
    expected_aggregate_version: input.expectedVersion,
    actor: input.actor ?? { type: "human", id: "human:local-owner" },
    idempotency_key: commandId,
    payload: input.payload,
  });
}

describe("Phase 2 command persistence", () => {
  test("requires an approved Phase 1 contract and persists immutable assignment revisions", () => {
    const runtime = createPhase2Runtime({ home: home(), clock: () => "2026-07-23T10:00:00.000Z" });
    try {
      const unapprovedTaskId = runtime.phase1.ids.next("task");
      phase1Command(runtime, unapprovedTaskId, "CreateTask", {
        title: "Unapproved",
        workflow: { id: "software-development", version: "1.0.0" },
        policy: { id: "safe-default", version: "1.0.0" },
        risk: { level: "low", reasons: [] },
      });
      const denied = command(runtime, {
        type: "CreateAssignment",
        taskId: unapprovedTaskId,
        aggregateId: "assignment:denied",
        expectedVersion: 0,
        payload: { objective: "Should fail." },
      });
      expect(denied).toMatchObject({ ok: false, error: { code: "contract_not_active" } });

      const task = approvedTask(runtime);
      const assignmentId = runtime.ids.next("assignment");
      const created = command(runtime, {
        type: "CreateAssignment",
        taskId: task.taskId,
        aggregateId: assignmentId,
        expectedVersion: 0,
        payload: {
          contract_ref: { revision_id: task.revisionId, hash: task.contractHash },
          objective: "Implement persistence.",
          role: "backend-implementer",
          scope: { allowed_paths: ["src/oef/phase2/**"], denied_paths: [".github/**"] },
          required_capabilities: ["repository-read", "repository-write", "git"],
          preferred_capabilities: ["structured-output"],
          verification: { commands: [{ executable: "bun", args: ["test"], timeout_seconds: 60 }] },
          required_evidence: ["code-diff", "test-result"],
          budgets: { max_wall_time_seconds: 300, max_idle_seconds: 60, max_attempts: 3, max_output_bytes: 1_000_000 },
        },
      });
      expect(created).toMatchObject({ ok: true, replayed: false, value: { assignment: { revision: 1 } } });

      const revised = command(runtime, {
        type: "ReviseAssignment",
        taskId: task.taskId,
        aggregateId: assignmentId,
        expectedVersion: 1,
        payload: { objective: "Implement persistence and restart recovery." },
      });
      expect(revised).toMatchObject({ ok: true, value: { assignment: { revision: 2 } } });
      expect(runtime.store.listAssignmentRevisions(assignmentId)).toHaveLength(2);
      expect(runtime.store.verifyEventChain(assignmentId)).toEqual({ valid: true, event_count: 2 });
    } finally {
      runtime.close();
    }
  });

  test("creates binding and execution separately, applies optimistic transitions, and replays idempotently", () => {
    const runtime = createPhase2Runtime({ home: home(), clock: () => "2026-07-23T10:00:00.000Z" });
    try {
      const task = approvedTask(runtime);
      const assignmentId = runtime.ids.next("assignment");
      const assignmentResult = command(runtime, {
        type: "CreateAssignment", taskId: task.taskId, aggregateId: assignmentId, expectedVersion: 0,
        payload: {
          contract_ref: { revision_id: task.revisionId, hash: task.contractHash }, objective: "Run safely.", role: "implementer",
          scope: { allowed_paths: ["src/**"], denied_paths: [".github/**"] },
          required_capabilities: ["repository-read"], preferred_capabilities: [],
          verification: { commands: [] }, required_evidence: ["code-diff"],
          budgets: { max_wall_time_seconds: 300, max_idle_seconds: 60, max_attempts: 2, max_output_bytes: 1_000_000 },
        },
      });
      expect(assignmentResult.ok).toBeTrue();
      const bindingId = runtime.ids.next("binding");
      expect(command(runtime, {
        type: "CreateExecutionBinding", taskId: task.taskId, aggregateId: bindingId, expectedVersion: 0,
        payload: {
          assignment_id: assignmentId, assignment_revision: 1,
          agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
          runtime_ref: { id: "fake", adapter_version: "1.0.0" },
          model_ref: { provider: "local", model_class: "test", resolved_model: null },
          environment_ref: { type: "local-worktree", version: 1 }, account_ref: { id: "none" },
        },
      })).toMatchObject({ ok: true, value: { binding: { binding_id: bindingId } } });

      const executionId = runtime.ids.next("execution");
      expect(command(runtime, {
        type: "CreateExecution", taskId: task.taskId, aggregateId: executionId, expectedVersion: 0,
        payload: { assignment_id: assignmentId, assignment_revision: 1, binding_id: bindingId },
      })).toMatchObject({ ok: true, value: { execution: { status: "CREATED", aggregate_version: 1 } } });

      const commandId = runtime.ids.next("command");
      const transition = {
        commandId, type: "TransitionExecution", taskId: task.taskId, aggregateId: executionId,
        expectedVersion: 1, payload: { to_status: "QUEUED" },
      };
      expect(command(runtime, transition)).toMatchObject({ ok: true, replayed: false, value: { execution: { status: "QUEUED" } } });
      expect(command(runtime, transition)).toMatchObject({ ok: true, replayed: true, value: { execution: { status: "QUEUED" } } });
      expect(command(runtime, { ...transition, commandId: runtime.ids.next("command"), expectedVersion: 1, payload: { to_status: "PREPARING" } }))
        .toMatchObject({ ok: false, error: { code: "concurrency_conflict", expected: 1, actual: 2 } });
      expect(runtime.store.listEvents(executionId)).toHaveLength(2);
    } finally {
      runtime.close();
    }
  });

  test("records an at-least-once runtime event with zero additional effect on duplicate delivery", () => {
    const runtime = createPhase2Runtime({ home: home(), clock: () => "2026-07-23T10:00:00.000Z" });
    try {
      const task = approvedTask(runtime);
      const assignmentId = runtime.ids.next("assignment");
      expect(command(runtime, {
        type: "CreateAssignment", taskId: task.taskId, aggregateId: assignmentId, expectedVersion: 0,
        payload: {
          contract_ref: { revision_id: task.revisionId, hash: task.contractHash }, objective: "Record runtime events once.", role: "implementer",
          scope: { allowed_paths: ["src/**"], denied_paths: [] }, required_capabilities: ["repository-read"], preferred_capabilities: [],
          verification: { commands: [] }, required_evidence: ["runtime-events"],
          budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 1, max_output_bytes: 10_000 },
        },
      }).ok).toBeTrue();

      const bindingId = runtime.ids.next("binding");
      expect(command(runtime, {
        type: "CreateExecutionBinding", taskId: task.taskId, aggregateId: bindingId, expectedVersion: 0,
        payload: {
          assignment_id: assignmentId, assignment_revision: 1,
          agent_profile_ref: { id: "coding-primary", version: "1.0.0" },
          runtime_ref: { id: "fake", adapter_version: "1.0.0" },
          model_ref: { provider: "local", model_class: "test", resolved_model: null },
          environment_ref: { type: "local-worktree", version: 1 }, account_ref: { id: "none" },
        },
      }).ok).toBeTrue();

      const executionId = runtime.ids.next("execution");
      expect(command(runtime, {
        type: "CreateExecution", taskId: task.taskId, aggregateId: executionId, expectedVersion: 0,
        payload: { assignment_id: assignmentId, assignment_revision: 1, binding_id: bindingId },
      }).ok).toBeTrue();

      const attemptId = runtime.ids.next("attempt");
      expect(command(runtime, {
        type: "CreateExecutionAttempt", taskId: task.taskId, aggregateId: executionId, expectedVersion: 1,
        payload: {
          attempt_id: attemptId, base_commit: "0123456789abcdef", workspace_id: runtime.ids.next("workspace"),
          context_bundle_hash: `sha256:${"1".repeat(64)}`, binding_hash: `sha256:${"2".repeat(64)}`,
          failure_of_previous_attempt: null,
        },
      }).ok).toBeTrue();

      const eventCommandId = runtime.ids.next("command");
      const delivery = {
        commandId: eventCommandId,
        type: "RecordRuntimeEvent",
        taskId: task.taskId,
        aggregateId: executionId,
        expectedVersion: 2,
        actor: { type: "system", id: "system:local-runner" } as const,
        payload: {
          schema_version: 1,
          event_id: "runtime-event:delivery-1",
          sequence: 1,
          execution_id: executionId,
          attempt_id: attemptId,
          type: "execution.started",
          correlation: { call_id: null },
          payload: {},
          source: { runtime: "fake", adapter: "fake-v1" },
          confidence: "AUTHORITATIVE",
          occurred_at: "2026-07-23T10:00:00.000Z",
        },
      };
      const first = command(runtime, delivery);
      const eventCount = runtime.store.listEvents(executionId).length;
      const duplicate = command(runtime, { ...delivery, commandId: runtime.ids.next("command") });

      expect(first).toMatchObject({ ok: true, replayed: false, value: { execution: { aggregate_version: 3 } } });
      expect(duplicate).toMatchObject({ ok: true, replayed: true, value: { execution: { aggregate_version: 3 } } });
      expect(runtime.store.getExecution(executionId)?.aggregate_version).toBe(3);
      expect(runtime.store.listEvents(executionId)).toHaveLength(eventCount);
      expect(runtime.store.listEvents(executionId).filter(event => event.event_type === "runtime-event.recorded")).toHaveLength(1);
    } finally {
      runtime.close();
    }
  });

  test("survives restart and protects audit events from mutation", () => {
    const runtimeHome = home();
    const runtime = createPhase2Runtime({ home: runtimeHome, clock: () => "2026-07-23T10:00:00.000Z" });
    const task = approvedTask(runtime);
    const assignmentId = runtime.ids.next("assignment");
    const result = command(runtime, {
      type: "CreateAssignment", taskId: task.taskId, aggregateId: assignmentId, expectedVersion: 0,
      payload: {
        contract_ref: { revision_id: task.revisionId, hash: task.contractHash }, objective: "Persist after restart.", role: "implementer",
        scope: { allowed_paths: ["src/**"], denied_paths: [] }, required_capabilities: ["repository-read"], preferred_capabilities: [],
        verification: { commands: [] }, required_evidence: ["changed-files"],
        budgets: { max_wall_time_seconds: 60, max_idle_seconds: 10, max_attempts: 1, max_output_bytes: 10_000 },
      },
    });
    expect(result.ok).toBeTrue();
    const databasePath = runtime.phase1.store.databasePath;
    runtime.close();

    const reopened = createPhase2Runtime({ home: runtimeHome });
    try {
      expect(reopened.store.getAssignment(assignmentId)?.objective).toBe("Persist after restart.");
      expect(reopened.store.verifyEventChain(assignmentId).valid).toBeTrue();
    } finally {
      reopened.close();
    }

    const database = new Database(databasePath, { strict: true });
    try {
      expect(() => database.exec("UPDATE phase2_events SET event_type = 'tampered'")).toThrow();
      expect(() => database.exec("DELETE FROM phase2_events")).toThrow();
    } finally {
      database.close();
    }
  });
});
