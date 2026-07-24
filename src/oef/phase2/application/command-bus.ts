import { z } from "zod";
import type { ContractRevision } from "../../phase1/core/contract/revision";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema, type Actor } from "../../phase1/core/shared/actor";
import type { Task } from "../../phase1/core/task/task";
import {
  ATTEMPT_STATUSES,
  EXECUTION_STATUSES,
  assignmentCreatePayloadSchema,
  createAssignmentRevision,
  executionBindingSchema,
  hashAssignment,
  parseAssignment,
  parseExecution,
  parseExecutionAttempt,
  parseExecutionBinding,
  transitionAttempt,
  transitionExecution,
  type Assignment,
  type Execution,
  type ExecutionAttempt,
  type ExecutionBinding,
} from "../core/domain";
import type { Phase2IdGenerator } from "../core/ids";
import type { Phase2CommandStore, Phase2Event } from "./ports/store";
import { normalizedRuntimeEventSchema } from "../runtime/protocol";

const commandTypes = [
  "CreateAssignment",
  "ReviseAssignment",
  "CreateExecutionBinding",
  "CreateExecution",
  "TransitionExecution",
  "CreateExecutionAttempt",
  "TransitionExecutionAttempt",
  "CompleteExecutionAttempt",
  "RecordRuntimeEvent",
] as const;

export const phase2CommandEnvelopeSchema = z.object({
  schema_version: z.literal(1),
  command_id: z.string().trim().min(1).max(300),
  command_type: z.enum(commandTypes),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  aggregate_id: z.string().trim().min(1).max(500),
  expected_aggregate_version: z.number().int().nonnegative(),
  actor: actorSchema,
  idempotency_key: z.string().trim().min(1).max(500),
  payload: z.unknown(),
}).strict();

type Phase2Command = z.infer<typeof phase2CommandEnvelopeSchema>;

const assignmentRevisionPayloadSchema = assignmentCreatePayloadSchema.partial().strict();

const bindingCreatePayloadSchema = executionBindingSchema.omit({
  schema_version: true,
  binding_id: true,
  created_by: true,
  created_at: true,
});

const createExecutionPayloadSchema = z.object({
  assignment_id: z.string().regex(/^assignment:/),
  assignment_revision: z.number().int().positive(),
  binding_id: z.string().regex(/^binding:/),
}).strict();

const transitionExecutionPayloadSchema = z.object({ to_status: z.enum(EXECUTION_STATUSES) }).strict();

const createAttemptPayloadSchema = z.object({
  attempt_id: z.string().regex(/^attempt:/),
  base_commit: z.string().trim().min(1).max(500),
  workspace_id: z.string().regex(/^workspace:/),
  workspace_root: z.string().trim().min(1).max(4_000).optional(),
  context_bundle_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  binding_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  failure_of_previous_attempt: z.object({
    type: z.string().trim().min(1).max(160),
    retry_strategy: z.string().trim().min(1).max(160),
  }).strict().nullable(),
}).strict();

const transitionAttemptPayloadSchema = z.object({ to_status: z.enum(ATTEMPT_STATUSES) }).strict();

export interface Phase1ExecutionReadPort {
  getTask(taskId: string): Task | null;
  getContractRevision(revisionId: string): ContractRevision | null;
}

export interface Phase2Principal {
  actor: Actor;
  roles: readonly ("assignment_admin" | "execution_operator" | "runner_host")[];
}

type Phase2Error =
  | { code: "invalid_command"; message: string }
  | { code: "actor_forbidden" }
  | { code: "task_not_found" }
  | { code: "contract_not_active" }
  | { code: "contract_mismatch" }
  | { code: "aggregate_not_found" }
  | { code: "aggregate_already_exists" }
  | { code: "concurrency_conflict"; expected: number; actual: number }
  | { code: "idempotency_conflict" }
  | { code: "binding_mismatch" }
  | { code: "attempt_limit_exceeded" };

export type Phase2CommandResult =
  | { ok: true; replayed: boolean; value: { assignment?: Assignment; binding?: ExecutionBinding; execution?: Execution; attempt?: ExecutionAttempt; event: Phase2Event } }
  | { ok: false; replayed: boolean; error: Phase2Error };

type Outcome =
  | { ok: true; aggregateType: Phase2Event["aggregate_type"]; aggregateId: string; aggregateVersion: number; eventType: string; payload: Record<string, unknown>; value: Omit<Extract<Phase2CommandResult, { ok: true }>["value"], "event"> }
  | { ok: false; error: Phase2Error };

const requiredRole: Record<typeof commandTypes[number], Phase2Principal["roles"][number]> = {
  CreateAssignment: "assignment_admin",
  ReviseAssignment: "assignment_admin",
  CreateExecutionBinding: "assignment_admin",
  CreateExecution: "execution_operator",
  TransitionExecution: "execution_operator",
  CreateExecutionAttempt: "execution_operator",
  TransitionExecutionAttempt: "runner_host",
  CompleteExecutionAttempt: "runner_host",
  RecordRuntimeEvent: "runner_host",
};

export class Phase2CommandBus {
  private readonly store: Phase2CommandStore;
  private readonly phase1: Phase1ExecutionReadPort;
  private readonly ids: Phase2IdGenerator;
  private readonly clock: () => string;
  private readonly principals: ReadonlyMap<string, Phase2Principal>;

  constructor(options: {
    store: Phase2CommandStore;
    phase1: Phase1ExecutionReadPort;
    ids: Phase2IdGenerator;
    principals: readonly Phase2Principal[];
    clock?: () => string;
  }) {
    this.store = options.store;
    this.phase1 = options.phase1;
    this.ids = options.ids;
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.principals = new Map(options.principals.map(principal => [principal.actor.id, principal]));
  }

  execute(input: unknown): Phase2CommandResult {
    const parsed = phase2CommandEnvelopeSchema.safeParse(input);
    if (!parsed.success) return this.failure({ code: "invalid_command", message: parsed.error.message });
    const command = parsed.data;
    const principal = this.principals.get(command.actor.id);
    if (!principal || principal.actor.type !== command.actor.type || !principal.roles.includes(requiredRole[command.command_type])) {
      return this.failure({ code: "actor_forbidden" });
    }
    const authenticated = { ...command, actor: principal.actor };
    const commandHash = canonicalSha256(authenticated);
    try {
      return this.store.transaction(() => {
        const previous = this.store.getIdempotency(command.idempotency_key);
        if (previous) {
          if (previous.commandHash !== commandHash) return this.failure({ code: "idempotency_conflict" });
          return { ...(previous.result as Omit<Phase2CommandResult, "replayed">), replayed: true } as Phase2CommandResult;
        }
        if (command.command_type === "RecordRuntimeEvent") {
          const runtimeEvent = normalizedRuntimeEventSchema.safeParse(command.payload);
          if (runtimeEvent.success) {
            const receipt = this.store.findRuntimeEventReceipt(
              runtimeEvent.data.event_id,
              runtimeEvent.data.attempt_id,
              runtimeEvent.data.sequence,
            );
            if (receipt) {
              const runtimeEventHash = canonicalSha256(runtimeEvent.data);
              if (receipt.runtime_event_id !== runtimeEvent.data.event_id || receipt.runtime_event_hash !== runtimeEventHash) {
                const failed = { ok: false as const, error: { code: "invalid_command" as const, message: "Runtime event identity or sequence conflict" } };
                this.store.saveIdempotency(command.idempotency_key, commandHash, failed, this.clock());
                return { ...failed, replayed: false };
              }
              const execution = this.store.getExecution(command.aggregate_id);
              if (!execution) return this.failure({ code: "aggregate_not_found" });
              const value = { execution, event: receipt.phase2_event };
              const stored = { ok: true as const, value };
              this.store.saveIdempotency(command.idempotency_key, commandHash, stored, this.clock());
              return { ...stored, replayed: true };
            }
          }
        }
        const outcome = this.apply(authenticated);
        if (!outcome.ok) {
          const failed = { ok: false as const, error: outcome.error };
          this.store.saveIdempotency(command.idempotency_key, commandHash, failed, this.clock());
          return { ...failed, replayed: false };
        }
        const previousEventHash = this.store.latestEventHash(outcome.aggregateId);
        const content = {
          schema_version: 1 as const,
          event_id: this.ids.next("event"),
          event_type: outcome.eventType,
          aggregate_type: outcome.aggregateType,
          aggregate_id: outcome.aggregateId,
          aggregate_version: outcome.aggregateVersion,
          task_id: command.task_id,
          occurred_at: this.clock(),
          actor: authenticated.actor,
          payload: outcome.payload,
          previous_event_hash: previousEventHash,
        };
        const event: Phase2Event = { ...content, event_hash: canonicalSha256(content) };
        this.store.appendEvent(event);
        this.store.appendOutbox(event);
        if (command.command_type === "RecordRuntimeEvent") {
          const runtimeEvent = normalizedRuntimeEventSchema.parse(command.payload);
          this.store.appendRuntimeEventReceipt(runtimeEvent, canonicalSha256(runtimeEvent), event);
        }
        const value = { ...outcome.value, event };
        const stored = { ok: true as const, value };
        this.store.saveIdempotency(command.idempotency_key, commandHash, stored, event.occurred_at);
        return { ...stored, replayed: false };
      });
    } catch (error) {
      return this.failure({ code: "invalid_command", message: error instanceof Error ? error.message : String(error) });
    }
  }

  private apply(command: Phase2Command): Outcome {
    const task = this.phase1.getTask(command.task_id);
    if (!task) return { ok: false, error: { code: "task_not_found" } };
    if (!task.active_contract_revision_id) return { ok: false, error: { code: "contract_not_active" } };
    const contract = this.phase1.getContractRevision(task.active_contract_revision_id);
    if (!contract || contract.status !== "APPROVED") return { ok: false, error: { code: "contract_not_active" } };
    switch (command.command_type) {
      case "CreateAssignment": return this.createAssignment(command, contract);
      case "ReviseAssignment": return this.reviseAssignment(command, contract);
      case "CreateExecutionBinding": return this.createBinding(command);
      case "CreateExecution": return this.createExecution(command);
      case "TransitionExecution": return this.changeExecution(command);
      case "CreateExecutionAttempt": return this.createAttempt(command);
      case "TransitionExecutionAttempt": return this.changeAttempt(command);
      case "CompleteExecutionAttempt": return this.completeExecutionAttempt(command);
      case "RecordRuntimeEvent": return this.recordRuntimeEvent(command);
    }
  }

  private createAssignment(command: Phase2Command, contract: ContractRevision): Outcome {
    if (command.expected_aggregate_version !== 0) return this.conflict(command.expected_aggregate_version, 0);
    if (this.store.getAssignment(command.aggregate_id)) return { ok: false, error: { code: "aggregate_already_exists" } };
    const payload = assignmentCreatePayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (payload.data.contract_ref.revision_id !== contract.revision_id || payload.data.contract_ref.hash !== contract.canonical_hash) {
      return { ok: false, error: { code: "contract_mismatch" } };
    }
    const assignment = parseAssignment({
      schema_version: 1,
      assignment_id: command.aggregate_id,
      revision: 1,
      previous_revision_hash: null,
      task_id: command.task_id,
      ...payload.data,
      created_by: command.actor,
      created_at: this.clock(),
    });
    this.store.insertAssignment(assignment, hashAssignment(assignment));
    return {
      ok: true,
      aggregateType: "assignment",
      aggregateId: assignment.assignment_id,
      aggregateVersion: 1,
      eventType: "assignment.created",
      payload: { assignment_hash: hashAssignment(assignment), contract_revision_id: contract.revision_id },
      value: { assignment },
    };
  }

  private reviseAssignment(command: Phase2Command, contract: ContractRevision): Outcome {
    const previous = this.store.getAssignment(command.aggregate_id);
    if (!previous) return { ok: false, error: { code: "aggregate_not_found" } };
    if (previous.revision !== command.expected_aggregate_version) return this.conflict(command.expected_aggregate_version, previous.revision);
    if (previous.task_id !== command.task_id) return { ok: false, error: { code: "aggregate_not_found" } };
    const patch = assignmentRevisionPayloadSchema.safeParse(command.payload);
    if (!patch.success) return this.invalid(patch.error.message);
    const next = createAssignmentRevision(previous, {
      ...previous,
      ...patch.data,
      revision: previous.revision + 1,
      previous_revision_hash: hashAssignment(previous),
      created_by: command.actor,
      created_at: this.clock(),
    });
    if (next.contract_ref.revision_id !== contract.revision_id || next.contract_ref.hash !== contract.canonical_hash) {
      return { ok: false, error: { code: "contract_mismatch" } };
    }
    this.store.insertAssignment(next, hashAssignment(next));
    return {
      ok: true,
      aggregateType: "assignment",
      aggregateId: next.assignment_id,
      aggregateVersion: next.revision,
      eventType: "assignment.revised",
      payload: { assignment_hash: hashAssignment(next), previous_revision_hash: next.previous_revision_hash },
      value: { assignment: next },
    };
  }

  private createBinding(command: Phase2Command): Outcome {
    if (command.expected_aggregate_version !== 0) return this.conflict(command.expected_aggregate_version, 0);
    if (this.store.getBinding(command.aggregate_id)) return { ok: false, error: { code: "aggregate_already_exists" } };
    const payload = bindingCreatePayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const assignment = this.store.getAssignment(payload.data.assignment_id, payload.data.assignment_revision);
    if (!assignment || assignment.task_id !== command.task_id) return { ok: false, error: { code: "aggregate_not_found" } };
    const binding = parseExecutionBinding({
      schema_version: 1,
      binding_id: command.aggregate_id,
      ...payload.data,
      created_by: command.actor,
      created_at: this.clock(),
    });
    const hash = canonicalSha256(binding);
    this.store.insertBinding(command.task_id, binding, hash);
    return {
      ok: true,
      aggregateType: "binding",
      aggregateId: binding.binding_id,
      aggregateVersion: 1,
      eventType: "execution-binding.created",
      payload: { binding_hash: hash, assignment_id: binding.assignment_id, assignment_revision: binding.assignment_revision },
      value: { binding },
    };
  }

  private createExecution(command: Phase2Command): Outcome {
    if (command.expected_aggregate_version !== 0) return this.conflict(command.expected_aggregate_version, 0);
    if (this.store.getExecution(command.aggregate_id)) return { ok: false, error: { code: "aggregate_already_exists" } };
    const payload = createExecutionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const assignment = this.store.getAssignment(payload.data.assignment_id, payload.data.assignment_revision);
    const binding = this.store.getBinding(payload.data.binding_id);
    if (!assignment || assignment.task_id !== command.task_id) return { ok: false, error: { code: "aggregate_not_found" } };
    if (!binding || binding.assignment_id !== assignment.assignment_id || binding.assignment_revision !== assignment.revision) {
      return { ok: false, error: { code: "binding_mismatch" } };
    }
    const now = this.clock();
    const execution = parseExecution({
      schema_version: 1,
      execution_id: command.aggregate_id,
      assignment_id: assignment.assignment_id,
      assignment_revision: assignment.revision,
      binding_id: binding.binding_id,
      status: "CREATED",
      current_attempt_id: null,
      attempt_count: 0,
      created_at: now,
      started_at: null,
      completed_at: null,
      aggregate_version: 1,
    });
    this.store.insertExecution(command.task_id, execution);
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: execution.execution_id,
      aggregateVersion: execution.aggregate_version,
      eventType: "execution.created",
      payload: { assignment_id: assignment.assignment_id, assignment_revision: assignment.revision, binding_id: binding.binding_id },
      value: { execution },
    };
  }

  private changeExecution(command: Phase2Command): Outcome {
    const current = this.store.getExecution(command.aggregate_id);
    if (!current) return { ok: false, error: { code: "aggregate_not_found" } };
    if (current.aggregate_version !== command.expected_aggregate_version) return this.conflict(command.expected_aggregate_version, current.aggregate_version);
    const payload = transitionExecutionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const status = transitionExecution(current.status, payload.data.to_status);
    const now = this.clock();
    const terminal = ["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(status);
    const execution = parseExecution({
      ...current,
      status,
      started_at: status === "RUNNING" ? (current.started_at ?? now) : current.started_at,
      completed_at: terminal ? now : null,
      aggregate_version: current.aggregate_version + 1,
    });
    if (!this.store.updateExecution(execution, current.aggregate_version)) return this.conflict(command.expected_aggregate_version, this.store.getExecution(command.aggregate_id)?.aggregate_version ?? -1);
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: execution.execution_id,
      aggregateVersion: execution.aggregate_version,
      eventType: `execution.${status.toLowerCase()}`,
      payload: { from_status: current.status, to_status: status },
      value: { execution },
    };
  }

  private createAttempt(command: Phase2Command): Outcome {
    const execution = this.store.getExecution(command.aggregate_id);
    if (!execution) return { ok: false, error: { code: "aggregate_not_found" } };
    if (execution.aggregate_version !== command.expected_aggregate_version) return this.conflict(command.expected_aggregate_version, execution.aggregate_version);
    const assignment = this.store.getAssignment(execution.assignment_id, execution.assignment_revision);
    if (!assignment) return { ok: false, error: { code: "aggregate_not_found" } };
    if (execution.attempt_count >= assignment.budgets.max_attempts) return { ok: false, error: { code: "attempt_limit_exceeded" } };
    const payload = createAttemptPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const previous = this.store.listAttempts(execution.execution_id).at(-1);
    const attemptId = payload.data.attempt_id;
    if (this.store.getAttempt(attemptId)) return { ok: false, error: { code: "aggregate_already_exists" } };
    const { attempt_id: ignoredAttemptId, ...attemptPayload } = payload.data;
    const attempt = parseExecutionAttempt({
      schema_version: 1,
      attempt_id: attemptId,
      execution_id: execution.execution_id,
      attempt_number: execution.attempt_count + 1,
      ...attemptPayload,
      status: "CREATED",
      started_at: null,
      ended_at: null,
    }, previous ? { previous_attempt_number: previous.attempt_number, previous_attempt_id: previous.attempt_id } : undefined);
    this.store.insertAttempt(attempt);
    const updated = parseExecution({
      ...execution,
      current_attempt_id: attempt.attempt_id,
      attempt_count: attempt.attempt_number,
      aggregate_version: execution.aggregate_version + 1,
    });
    if (!this.store.updateExecution(updated, execution.aggregate_version)) return this.conflict(command.expected_aggregate_version, this.store.getExecution(command.aggregate_id)?.aggregate_version ?? -1);
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: updated.execution_id,
      aggregateVersion: updated.aggregate_version,
      eventType: "execution-attempt.created",
      payload: { attempt_id: attempt.attempt_id, attempt_number: attempt.attempt_number },
      value: { execution: updated, attempt },
    };
  }

  private changeAttempt(command: Phase2Command): Outcome {
    const attempt = this.store.getAttempt(command.aggregate_id);
    if (!attempt) return { ok: false, error: { code: "aggregate_not_found" } };
    const execution = this.store.getExecution(attempt.execution_id);
    if (!execution || execution.aggregate_version !== command.expected_aggregate_version) {
      return this.conflict(command.expected_aggregate_version, execution?.aggregate_version ?? -1);
    }
    const payload = transitionAttemptPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const status = transitionAttempt(attempt.status, payload.data.to_status);
    const terminal = ["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"].includes(status);
    const now = this.clock();
    const next = parseExecutionAttempt({
      ...attempt,
      status,
      started_at: status === "RUNNING" ? (attempt.started_at ?? now) : attempt.started_at,
      ended_at: terminal ? now : null,
    });
    if (!this.store.updateAttempt(next, attempt.status)) return this.invalid("Attempt changed concurrently");
    const updatedExecution = parseExecution({ ...execution, aggregate_version: execution.aggregate_version + 1 });
    if (!this.store.updateExecution(updatedExecution, execution.aggregate_version)) return this.conflict(command.expected_aggregate_version, this.store.getExecution(execution.execution_id)?.aggregate_version ?? -1);
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: execution.execution_id,
      aggregateVersion: updatedExecution.aggregate_version,
      eventType: `execution-attempt.${status.toLowerCase()}`,
      payload: { attempt_id: next.attempt_id, from_status: attempt.status, to_status: next.status },
      value: { execution: updatedExecution, attempt: next },
    };
  }

  private completeExecutionAttempt(command: Phase2Command): Outcome {
    const execution = this.store.getExecution(command.aggregate_id);
    if (!execution) return { ok: false, error: { code: "aggregate_not_found" } };
    if (execution.aggregate_version !== command.expected_aggregate_version) return this.conflict(command.expected_aggregate_version, execution.aggregate_version);
    if (execution.status !== "RUNNING" || !execution.current_attempt_id) return this.invalid("Execution is not ready for atomic completion");
    const attempt = this.store.getAttempt(execution.current_attempt_id);
    if (!attempt || attempt.status !== "VERIFYING") return this.invalid("Active attempt is not ready for atomic completion");
    const now = this.clock();
    const completedAttempt = parseExecutionAttempt({ ...attempt, status: transitionAttempt(attempt.status, "SUCCEEDED"), ended_at: now });
    const completedExecution = parseExecution({
      ...execution,
      status: transitionExecution(execution.status, "COMPLETED"),
      completed_at: now,
      aggregate_version: execution.aggregate_version + 1,
    });
    if (!this.store.updateAttempt(completedAttempt, attempt.status)) throw new Error("Atomic completion attempt update failed");
    if (!this.store.updateExecution(completedExecution, execution.aggregate_version)) throw new Error("Atomic completion execution update failed");
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: completedExecution.execution_id,
      aggregateVersion: completedExecution.aggregate_version,
      eventType: "execution.completed",
      payload: { attempt_id: completedAttempt.attempt_id, attempt_status: completedAttempt.status, execution_status: completedExecution.status },
      value: { execution: completedExecution, attempt: completedAttempt },
    };
  }

  private recordRuntimeEvent(command: Phase2Command): Outcome {
    const execution = this.store.getExecution(command.aggregate_id);
    if (!execution) return { ok: false, error: { code: "aggregate_not_found" } };
    if (execution.aggregate_version !== command.expected_aggregate_version) return this.conflict(command.expected_aggregate_version, execution.aggregate_version);
    const parsed = normalizedRuntimeEventSchema.safeParse(command.payload);
    if (!parsed.success) return this.invalid(parsed.error.message);
    if (JSON.stringify(parsed.data).length > 100_000) return this.invalid("Runtime event payload exceeds 100000 characters");
    if (parsed.data.execution_id !== execution.execution_id || parsed.data.attempt_id !== execution.current_attempt_id) {
      return this.invalid("Runtime event does not target the active execution attempt");
    }
    const updated = parseExecution({ ...execution, aggregate_version: execution.aggregate_version + 1 });
    if (!this.store.updateExecution(updated, execution.aggregate_version)) return this.conflict(command.expected_aggregate_version, this.store.getExecution(command.aggregate_id)?.aggregate_version ?? -1);
    return {
      ok: true,
      aggregateType: "execution",
      aggregateId: execution.execution_id,
      aggregateVersion: updated.aggregate_version,
      eventType: "runtime-event.recorded",
      payload: { runtime_event: parsed.data },
      value: { execution: updated },
    };
  }

  private invalid(message: string): Outcome { return { ok: false, error: { code: "invalid_command", message } }; }
  private conflict(expected: number, actual: number): Outcome { return { ok: false, error: { code: "concurrency_conflict", expected, actual } }; }
  private failure(error: Phase2Error): Phase2CommandResult { return { ok: false, replayed: false, error }; }
}
