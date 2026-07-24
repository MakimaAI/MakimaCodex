import type { Actor } from "../../../phase1/core/shared/actor";
import type { Assignment, Execution, ExecutionAttempt, ExecutionBinding } from "../../core/domain";
import type { NormalizedRuntimeEvent } from "../../runtime/protocol";
import type { CompletionSagaRecord } from "../completion-saga";

export interface Phase2Event {
  schema_version: 1;
  event_id: string;
  event_type: string;
  aggregate_type: "assignment" | "binding" | "execution" | "attempt";
  aggregate_id: string;
  aggregate_version: number;
  task_id: string;
  occurred_at: string;
  actor: Actor;
  payload: Record<string, unknown>;
  previous_event_hash: string | null;
  event_hash: string;
}

export interface StoredPhase2IdempotencyResult {
  commandHash: string;
  result: { ok: true; value: unknown } | { ok: false; error: unknown };
}

export interface RuntimeEventReceipt {
  runtime_event_id: string;
  attempt_id: string;
  sequence: number;
  runtime_event_hash: string;
  phase2_event: Phase2Event;
}

export interface Phase2CommandStore {
  transaction<T>(operation: () => T): T;
  insertAssignment(assignment: Assignment, hash: string): void;
  getAssignment(assignmentId: string, revision?: number): Assignment | null;
  listAssignmentRevisions(assignmentId: string): Assignment[];
  insertBinding(taskId: string, binding: ExecutionBinding, hash: string): void;
  getBinding(bindingId: string): ExecutionBinding | null;
  insertExecution(taskId: string, execution: Execution): void;
  getExecution(executionId: string): Execution | null;
  getExecutionTaskId(executionId: string): string | null;
  listNonterminalExecutions(): Array<{ task_id: string; execution: Execution }>;
  updateExecution(execution: Execution, expectedVersion: number): boolean;
  insertAttempt(attempt: ExecutionAttempt): void;
  getAttempt(attemptId: string): ExecutionAttempt | null;
  listAttempts(executionId: string): ExecutionAttempt[];
  updateAttempt(attempt: ExecutionAttempt, expectedStatus: string): boolean;
  latestEventHash(aggregateId: string): string | null;
  appendEvent(event: Phase2Event): void;
  appendOutbox(event: Phase2Event): void;
  findRuntimeEventReceipt(eventId: string, attemptId: string, sequence: number): RuntimeEventReceipt | null;
  appendRuntimeEventReceipt(event: NormalizedRuntimeEvent, hash: string, phase2Event: Phase2Event): void;
  listEvents(aggregateId: string): Phase2Event[];
  getIdempotency(key: string): StoredPhase2IdempotencyResult | null;
  saveIdempotency(key: string, commandHash: string, result: StoredPhase2IdempotencyResult["result"], createdAt: string): void;
  saveCompletionSaga(saga: CompletionSagaRecord): void;
  getCompletionSaga(executionId: string): CompletionSagaRecord | null;
  listPendingCompletionSagas(): CompletionSagaRecord[];
}
