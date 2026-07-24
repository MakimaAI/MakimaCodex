import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  parseAssignment,
  parseExecution,
  parseExecutionAttempt,
  parseExecutionBinding,
  type Assignment,
  type Execution,
  type ExecutionAttempt,
  type ExecutionBinding,
} from "../core/domain";
import type {
  Phase2CommandStore,
  Phase2Event,
  RuntimeEventReceipt,
  StoredPhase2IdempotencyResult,
} from "../application/ports/store";
import type { NormalizedRuntimeEvent } from "../runtime/protocol";
import { parseCompletionSagaRecord, type CompletionSagaRecord } from "../application/completion-saga";

const migrations = [
  { id: "001_execution_core", url: new URL("./migrations/001_execution_core.sql", import.meta.url) },
  { id: "002_runtime_event_identity", url: new URL("./migrations/002_runtime_event_identity.sql", import.meta.url) },
  { id: "003_completion_sagas", url: new URL("./migrations/003_completion_sagas.sql", import.meta.url) },
] as const;

interface MigrationRow { migration_id: string; checksum: string }
interface JsonRow { value_json: string }
interface IdempotencyRow { command_hash: string; result_json: string }
interface HashRow { event_hash: string }
interface TaskIdRow { task_id: string }
interface ExecutionRow { task_id: string; value_json: string }
interface RuntimeReceiptRow {
  runtime_event_id: string;
  attempt_id: string;
  sequence: number;
  runtime_event_hash: string;
  event_json: string;
}

export class SqlitePhase2Store implements Phase2CommandStore {
  readonly databasePath: string;
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.databasePath = options.databasePath;
    mkdirSync(dirname(options.databasePath), { recursive: true });
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode = WAL;");
    this.database.exec("PRAGMA foreign_keys = ON;");
    this.database.exec("PRAGMA busy_timeout = 5000;");
    this.applyMigrations();
  }

  private applyMigrations(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS phase2_schema_migrations (
        migration_id TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
    `);
    const get = this.database.query<MigrationRow, [string]>(
      "SELECT migration_id, checksum FROM phase2_schema_migrations WHERE migration_id = ?",
    );
    const insert = this.database.query(
      "INSERT INTO phase2_schema_migrations (migration_id, checksum, applied_at) VALUES (?, ?, ?)",
    );
    for (const migration of migrations) {
      const sql = readFileSync(migration.url, "utf8");
      const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
      const existing = get.get(migration.id);
      if (existing) {
        if (existing.checksum !== checksum) throw new Error(`Applied Phase 2 migration checksum mismatch: ${migration.id}`);
        continue;
      }
      this.database.transaction(() => {
        this.database.exec(sql);
        insert.run(migration.id, checksum, new Date().toISOString());
      })();
    }
  }

  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  getAppliedMigrations(): string[] {
    return this.database.query<{ migration_id: string }, []>(
      "SELECT migration_id FROM phase2_schema_migrations ORDER BY migration_id",
    ).all().map(row => row.migration_id);
  }

  insertAssignment(assignment: Assignment, hash: string): void {
    const value = parseAssignment(assignment);
    this.database.query(
      `INSERT INTO phase2_assignment_revisions
       (assignment_id, revision, task_id, assignment_hash, assignment_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(value.assignment_id, value.revision, value.task_id, hash, JSON.stringify(value), value.created_at);
  }

  getAssignment(assignmentId: string, revision?: number): Assignment | null {
    const row = revision === undefined
      ? this.database.query<JsonRow, [string]>(
        `SELECT assignment_json AS value_json FROM phase2_assignment_revisions
         WHERE assignment_id = ? ORDER BY revision DESC LIMIT 1`,
      ).get(assignmentId)
      : this.database.query<JsonRow, [string, number]>(
        `SELECT assignment_json AS value_json FROM phase2_assignment_revisions
         WHERE assignment_id = ? AND revision = ?`,
      ).get(assignmentId, revision);
    return row ? parseAssignment(JSON.parse(row.value_json)) : null;
  }

  listAssignmentRevisions(assignmentId: string): Assignment[] {
    return this.database.query<JsonRow, [string]>(
      `SELECT assignment_json AS value_json FROM phase2_assignment_revisions
       WHERE assignment_id = ? ORDER BY revision`,
    ).all(assignmentId).map(row => parseAssignment(JSON.parse(row.value_json)));
  }

  insertBinding(taskId: string, binding: ExecutionBinding, hash: string): void {
    const value = parseExecutionBinding(binding);
    this.database.query(
      `INSERT INTO phase2_bindings
       (binding_id, assignment_id, assignment_revision, task_id, binding_hash, binding_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(value.binding_id, value.assignment_id, value.assignment_revision, taskId, hash, JSON.stringify(value), value.created_at);
  }

  getBinding(bindingId: string): ExecutionBinding | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT binding_json AS value_json FROM phase2_bindings WHERE binding_id = ?",
    ).get(bindingId);
    return row ? parseExecutionBinding(JSON.parse(row.value_json)) : null;
  }

  insertExecution(taskId: string, execution: Execution): void {
    const value = parseExecution(execution);
    this.database.query(
      `INSERT INTO phase2_executions
       (execution_id, task_id, assignment_id, assignment_revision, binding_id, aggregate_version, status, execution_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      value.execution_id,
      taskId,
      value.assignment_id,
      value.assignment_revision,
      value.binding_id,
      value.aggregate_version,
      value.status,
      JSON.stringify(value),
      value.created_at,
      value.created_at,
    );
  }

  getExecution(executionId: string): Execution | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT execution_json AS value_json FROM phase2_executions WHERE execution_id = ?",
    ).get(executionId);
    return row ? parseExecution(JSON.parse(row.value_json)) : null;
  }

  getExecutionTaskId(executionId: string): string | null {
    return this.database.query<TaskIdRow, [string]>(
      "SELECT task_id FROM phase2_executions WHERE execution_id = ?",
    ).get(executionId)?.task_id ?? null;
  }

  listNonterminalExecutions(): Array<{ task_id: string; execution: Execution }> {
    return this.database.query<ExecutionRow, []>(
      `SELECT task_id, execution_json AS value_json FROM phase2_executions
       WHERE status NOT IN ('COMPLETED', 'FAILED', 'INTERRUPTED', 'CANCELLED')
       ORDER BY created_at, execution_id`,
    ).all().map(row => ({ task_id: row.task_id, execution: parseExecution(JSON.parse(row.value_json)) }));
  }

  updateExecution(execution: Execution, expectedVersion: number): boolean {
    const value = parseExecution(execution);
    const changed = this.database.query(
      `UPDATE phase2_executions SET aggregate_version = ?, status = ?, execution_json = ?, updated_at = ?
       WHERE execution_id = ? AND aggregate_version = ?`,
    ).run(value.aggregate_version, value.status, JSON.stringify(value), new Date().toISOString(), value.execution_id, expectedVersion);
    return changed.changes === 1;
  }

  insertAttempt(attempt: ExecutionAttempt): void {
    const value = parseExecutionAttempt(attempt);
    this.database.query(
      `INSERT INTO phase2_attempts (attempt_id, execution_id, attempt_number, status, attempt_json, updated_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(value.attempt_id, value.execution_id, value.attempt_number, value.status, JSON.stringify(value), new Date().toISOString());
  }

  getAttempt(attemptId: string): ExecutionAttempt | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT attempt_json AS value_json FROM phase2_attempts WHERE attempt_id = ?",
    ).get(attemptId);
    return row ? parseExecutionAttempt(JSON.parse(row.value_json)) : null;
  }

  listAttempts(executionId: string): ExecutionAttempt[] {
    return this.database.query<JsonRow, [string]>(
      "SELECT attempt_json AS value_json FROM phase2_attempts WHERE execution_id = ? ORDER BY attempt_number",
    ).all(executionId).map(row => parseExecutionAttempt(JSON.parse(row.value_json)));
  }

  updateAttempt(attempt: ExecutionAttempt, expectedStatus: string): boolean {
    const value = parseExecutionAttempt(attempt);
    const changed = this.database.query(
      `UPDATE phase2_attempts SET status = ?, attempt_json = ?, updated_at = ?
       WHERE attempt_id = ? AND status = ?`,
    ).run(value.status, JSON.stringify(value), new Date().toISOString(), value.attempt_id, expectedStatus);
    return changed.changes === 1;
  }

  latestEventHash(aggregateId: string): string | null {
    return this.database.query<HashRow, [string]>(
      "SELECT event_hash FROM phase2_events WHERE aggregate_id = ? ORDER BY aggregate_version DESC LIMIT 1",
    ).get(aggregateId)?.event_hash ?? null;
  }

  appendEvent(event: Phase2Event): void {
    this.database.query(
      `INSERT INTO phase2_events
       (event_id, event_type, aggregate_type, aggregate_id, aggregate_version, task_id, occurred_at,
        actor_json, payload_json, previous_event_hash, event_hash, event_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      event.event_id,
      event.event_type,
      event.aggregate_type,
      event.aggregate_id,
      event.aggregate_version,
      event.task_id,
      event.occurred_at,
      JSON.stringify(event.actor),
      JSON.stringify(event.payload),
      event.previous_event_hash,
      event.event_hash,
      JSON.stringify(event),
    );
  }

  appendOutbox(event: Phase2Event): void {
    this.database.query(
      "INSERT INTO phase2_outbox (event_id, event_json, created_at) VALUES (?, ?, ?)",
    ).run(event.event_id, JSON.stringify(event), event.occurred_at);
  }

  findRuntimeEventReceipt(eventId: string, attemptId: string, sequence: number): RuntimeEventReceipt | null {
    const row = this.database.query<RuntimeReceiptRow, [string, string, number]>(
      `SELECT r.runtime_event_id, r.attempt_id, r.sequence, r.runtime_event_hash, e.event_json
       FROM phase2_runtime_event_receipts r
       JOIN phase2_events e ON e.event_id = r.phase2_event_id
       WHERE r.runtime_event_id = ? OR (r.attempt_id = ? AND r.sequence = ?)
       LIMIT 1`,
    ).get(eventId, attemptId, sequence);
    return row ? {
      runtime_event_id: row.runtime_event_id,
      attempt_id: row.attempt_id,
      sequence: row.sequence,
      runtime_event_hash: row.runtime_event_hash,
      phase2_event: JSON.parse(row.event_json) as Phase2Event,
    } : null;
  }

  appendRuntimeEventReceipt(event: NormalizedRuntimeEvent, hash: string, phase2Event: Phase2Event): void {
    this.database.query(
      `INSERT INTO phase2_runtime_event_receipts
       (runtime_event_id, execution_id, attempt_id, sequence, runtime_event_hash, phase2_event_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(event.event_id, event.execution_id, event.attempt_id, event.sequence, hash, phase2Event.event_id, phase2Event.occurred_at);
  }

  listEvents(aggregateId: string): Phase2Event[] {
    return this.database.query<JsonRow, [string]>(
      "SELECT event_json AS value_json FROM phase2_events WHERE aggregate_id = ? ORDER BY aggregate_version",
    ).all(aggregateId).map(row => JSON.parse(row.value_json) as Phase2Event);
  }

  verifyEventChain(aggregateId: string): { valid: boolean; event_count: number; reason?: string } {
    const events = this.listEvents(aggregateId);
    let previous: string | null = null;
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index]!;
      const { event_hash: ignored, ...content } = event;
      if (event.aggregate_version !== index + 1) return { valid: false, event_count: events.length, reason: "version-gap" };
      if (event.previous_event_hash !== previous) return { valid: false, event_count: events.length, reason: "previous-hash-mismatch" };
      if (canonicalSha256(content) !== event.event_hash) return { valid: false, event_count: events.length, reason: "event-hash-mismatch" };
      previous = event.event_hash;
    }
    return { valid: true, event_count: events.length };
  }

  getIdempotency(key: string): StoredPhase2IdempotencyResult | null {
    const row = this.database.query<IdempotencyRow, [string]>(
      "SELECT command_hash, result_json FROM phase2_idempotency WHERE idempotency_key = ?",
    ).get(key);
    return row ? { commandHash: row.command_hash, result: JSON.parse(row.result_json) } : null;
  }

  saveIdempotency(
    key: string,
    commandHash: string,
    result: StoredPhase2IdempotencyResult["result"],
    createdAt: string,
  ): void {
    this.database.query(
      "INSERT INTO phase2_idempotency (idempotency_key, command_hash, result_json, created_at) VALUES (?, ?, ?, ?)",
    ).run(key, commandHash, JSON.stringify(result), createdAt);
  }

  saveCompletionSaga(input: CompletionSagaRecord): void {
    const saga = parseCompletionSagaRecord(input);
    this.database.query(
      `INSERT INTO phase2_completion_sagas (execution_id, status, saga_json, updated_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(execution_id) DO UPDATE SET status = excluded.status, saga_json = excluded.saga_json, updated_at = excluded.updated_at`,
    ).run(saga.execution_id, saga.status, JSON.stringify(saga), new Date().toISOString());
  }

  getCompletionSaga(executionId: string): CompletionSagaRecord | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT saga_json AS value_json FROM phase2_completion_sagas WHERE execution_id = ?",
    ).get(executionId);
    return row ? parseCompletionSagaRecord(JSON.parse(row.value_json)) : null;
  }

  listPendingCompletionSagas(): CompletionSagaRecord[] {
    return this.database.query<JsonRow, []>(
      "SELECT saga_json AS value_json FROM phase2_completion_sagas WHERE status != 'DONE' ORDER BY updated_at, execution_id",
    ).all().map(row => parseCompletionSagaRecord(JSON.parse(row.value_json)));
  }
}
