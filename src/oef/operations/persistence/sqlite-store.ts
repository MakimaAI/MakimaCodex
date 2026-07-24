import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  assertOperationErrorSafe, assertOperationOwner, assertOperationPayload, assertOperationTimestamp, assertOperationTransition,
  effectReceiptSchema, jobStateSchema, leaseExpiry, operationAttemptSchema, operationJobSchema, retryAvailableAt,
  type EffectReceipt, type OperationAttempt, type OperationJob,
} from "../core";

type JobRow = Omit<OperationJob, "payload"> & { payload_json: string };

export class SqliteOperationsStore {
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.database.exec(readFileSync(join(import.meta.dir, "migrations", "001_operations.sql"), "utf8"));
  }

  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  enqueue(input: { kind: string; idempotency_key: string; payload: Record<string, unknown>; priority: number; max_attempts: number; now: string }): OperationJob {
    assertOperationTimestamp(input.now); assertOperationPayload(input.payload);
    if (!input.kind.trim() || input.kind.length > 200 || !input.idempotency_key.trim() || input.idempotency_key.length > 500) throw new Error("OPERATION_ENQUEUE_INVALID");
    if (!Number.isSafeInteger(input.priority) || !Number.isSafeInteger(input.max_attempts) || input.max_attempts < 1 || input.max_attempts > 30) throw new Error("OPERATION_ENQUEUE_INVALID");
    return this.transaction(() => {
      const existing = this.getByKindAndKey(input.kind, input.idempotency_key);
      if (existing) return existing;
      const jobId = `operation:${canonicalSha256({ kind: input.kind, idempotency_key: input.idempotency_key }).slice("sha256:".length, "sha256:".length + 32)}`;
      this.database.query(`INSERT INTO operation_jobs (job_id, kind, idempotency_key, payload_json, priority, max_attempts, attempt_count, state, available_at, lease_owner, lease_expires_at, lease_acquired_at, run_started_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 0, 'PENDING', ?, NULL, NULL, NULL, NULL, ?, ?)`)
        .run(jobId, input.kind, input.idempotency_key, JSON.stringify(input.payload), input.priority, input.max_attempts, input.now, input.now, input.now);
      return this.getRequired(jobId);
    });
  }

  get(jobId: string): OperationJob | null { return this.decodeJob(this.database.query("SELECT * FROM operation_jobs WHERE job_id=?").get(jobId)); }
  list(): OperationJob[] { return (this.database.query("SELECT * FROM operation_jobs ORDER BY created_at, job_id").all() as unknown[]).map(row => this.decodeJob(row)!); }
  attempts(jobId: string): OperationAttempt[] { return (this.database.query("SELECT payload_json FROM operation_attempts WHERE job_id=? ORDER BY attempt_number").all(jobId) as Array<{ payload_json: string }>).map(row => operationAttemptSchema.parse(JSON.parse(row.payload_json))); }
  effectReceipt(jobId: string): EffectReceipt | null { const row = this.database.query("SELECT payload_json FROM operation_effect_receipts WHERE job_id=?").get(jobId) as { payload_json: string } | null; return row ? effectReceiptSchema.parse(JSON.parse(row.payload_json)) : null; }

  claim(input: { owner: string; now: string; lease_ms: number }): OperationJob | null {
    assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => {
      this.reconcileExpiredWithin(input.now, 1_000);
      const candidate = this.database.query(`SELECT job_id FROM operation_jobs
        WHERE state IN ('PENDING', 'RETRY_PENDING') AND julianday(available_at) <= julianday(?)
        ORDER BY priority DESC, available_at, created_at, job_id LIMIT 1`).get(input.now) as { job_id: string } | null;
      if (!candidate) return null;
      this.database.query(`UPDATE operation_jobs SET state='LEASED', lease_owner=?, lease_expires_at=?, lease_acquired_at=?, run_started_at=NULL, updated_at=?
        WHERE job_id=? AND state IN ('PENDING', 'RETRY_PENDING')`).run(input.owner, expiresAt, input.now, input.now, candidate.job_id);
      return this.getRequired(candidate.job_id);
    });
  }

  heartbeat(input: { job_id: string; owner: string; now: string; lease_ms: number }): OperationJob {
    assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => {
      const job = this.requireActiveLease(input.job_id, input.owner, input.now);
      this.database.query("UPDATE operation_jobs SET lease_expires_at=?, updated_at=? WHERE job_id=?").run(expiresAt, input.now, job.job_id);
      return this.getRequired(job.job_id);
    });
  }

  start(input: { job_id: string; owner: string; now: string }): OperationJob {
    assertOperationOwner(input.owner); assertOperationTimestamp(input.now);
    return this.transaction(() => {
      const job = this.requireActiveLease(input.job_id, input.owner, input.now);
      if (job.state !== "LEASED") throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      assertOperationTransition(job.state, "RUNNING");
      this.database.query("UPDATE operation_jobs SET state='RUNNING', run_started_at=?, updated_at=? WHERE job_id=?").run(input.now, input.now, job.job_id);
      return this.getRequired(job.job_id);
    });
  }

  succeed(input: { job_id: string; owner: string; effect_hash: string; now: string }): OperationJob {
    assertOperationOwner(input.owner); assertOperationTimestamp(input.now); if (!input.effect_hash.trim() || input.effect_hash.length > 500) throw new Error("OPERATION_EFFECT_HASH_INVALID");
    return this.transaction(() => {
      const receipt = this.effectReceipt(input.job_id);
      if (receipt) {
        if (receipt.effect_hash !== input.effect_hash) throw new Error("OPERATION_EFFECT_RECEIPT_CONFLICT");
        return this.getRequired(input.job_id);
      }
      const job = this.requireActiveLease(input.job_id, input.owner, input.now);
      if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      assertOperationTransition(job.state, "SUCCEEDED");
      const attempt = this.recordAttempt(job, input.owner, "SUCCEEDED", null, input.now);
      const receiptValue = { job_id: job.job_id, effect_hash: input.effect_hash, succeeded_at: input.now };
      this.database.query("INSERT INTO operation_effect_receipts (job_id, effect_hash, succeeded_at, payload_json) VALUES (?, ?, ?, ?)").run(job.job_id, input.effect_hash, input.now, JSON.stringify(receiptValue));
      this.database.query("UPDATE operation_jobs SET state='SUCCEEDED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE job_id=?").run(attempt.attempt_number, input.now, job.job_id);
      return this.getRequired(job.job_id);
    });
  }

  fail(input: { job_id: string; owner: string; error: string; now: string; base_backoff_ms: number }): OperationJob {
    assertOperationOwner(input.owner); assertOperationTimestamp(input.now); assertOperationErrorSafe(input.error);
    return this.transaction(() => {
      const job = this.requireActiveLease(input.job_id, input.owner, input.now);
      if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      return this.finishFailedAttempt(job, input.owner, input.error, input.now, input.base_backoff_ms, "FAILED");
    });
  }

  cancel(input: { job_id: string; now: string }): OperationJob {
    assertOperationTimestamp(input.now);
    return this.transaction(() => {
      const job = this.getRequired(input.job_id);
      if (job.state === "CANCELLED") return job;
      if (["SUCCEEDED", "FAILED", "DEAD_LETTER"].includes(job.state)) throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      assertOperationTransition(job.state, "CANCELLED");
      this.database.query("UPDATE operation_jobs SET state='CANCELLED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE job_id=?").run(input.now, job.job_id);
      return this.getRequired(job.job_id);
    });
  }

  reconcileExpired(input: { now: string; base_backoff_ms: number }): number {
    assertOperationTimestamp(input.now);
    return this.transaction(() => this.reconcileExpiredWithin(input.now, input.base_backoff_ms));
  }

  private reconcileExpiredWithin(now: string, baseBackoffMs: number): number {
    const expired = (this.database.query("SELECT * FROM operation_jobs WHERE state IN ('LEASED', 'RUNNING') AND julianday(lease_expires_at) <= julianday(?) ORDER BY job_id").all(now) as unknown[]).map(row => this.decodeJob(row)!);
    for (const job of expired) {
      if (job.state === "LEASED") {
        assertOperationTransition(job.state, "PENDING");
        this.database.query("UPDATE operation_jobs SET state='PENDING', lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, updated_at=? WHERE job_id=?").run(now, job.job_id);
      } else {
        this.finishFailedAttempt(job, job.lease_owner!, "lease expired", now, baseBackoffMs, "LEASE_EXPIRED");
      }
    }
    return expired.length;
  }

  private finishFailedAttempt(job: OperationJob, owner: string, error: string, now: string, baseBackoffMs: number, outcome: "FAILED" | "LEASE_EXPIRED"): OperationJob {
    const attempt = this.recordAttempt(job, owner, outcome, error, now);
    const exhausted = attempt.attempt_number >= job.max_attempts;
    const nextState = exhausted ? "DEAD_LETTER" : "RETRY_PENDING";
    assertOperationTransition(job.state, nextState);
    const availableAt = exhausted ? now : retryAvailableAt(now, baseBackoffMs, attempt.attempt_number);
    this.database.query("UPDATE operation_jobs SET state=?, attempt_count=?, available_at=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE job_id=?")
      .run(nextState, attempt.attempt_number, availableAt, now, job.job_id);
    return this.getRequired(job.job_id);
  }

  private recordAttempt(job: OperationJob, owner: string, outcome: OperationAttempt["outcome"], error: string | null, finishedAt: string): OperationAttempt {
    const attemptNumber = job.attempt_count + 1;
    const value = { attempt_id: `attempt:${canonicalSha256({ job: job.job_id, attempt: attemptNumber }).slice("sha256:".length, "sha256:".length + 32)}`, job_id: job.job_id, attempt_number: attemptNumber, owner, outcome, error, started_at: job.run_started_at ?? job.lease_acquired_at ?? finishedAt, finished_at: finishedAt };
    operationAttemptSchema.parse(value);
    this.database.query("INSERT INTO operation_attempts (attempt_id, job_id, attempt_number, owner, outcome, error, started_at, finished_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(value.attempt_id, value.job_id, value.attempt_number, value.owner, value.outcome, value.error, value.started_at, value.finished_at, JSON.stringify(value));
    return value;
  }

  private requireActiveLease(jobId: string, owner: string, now: string): OperationJob {
    const job = this.getRequired(jobId);
    if (job.state !== "LEASED" && job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID");
    if (job.lease_owner !== owner) throw new Error("OPERATION_LEASE_OWNER_MISMATCH");
    if (!job.lease_expires_at || Date.parse(job.lease_expires_at) <= Date.parse(now)) throw new Error("OPERATION_LEASE_EXPIRED");
    return job;
  }

  private getByKindAndKey(kind: string, key: string): OperationJob | null { return this.decodeJob(this.database.query("SELECT * FROM operation_jobs WHERE kind=? AND idempotency_key=?").get(kind, key)); }
  private getRequired(jobId: string): OperationJob { const job = this.get(jobId); if (!job) throw new Error("OPERATION_NOT_FOUND"); return job; }
  private decodeJob(row: unknown): OperationJob | null {
    if (!row || typeof row !== "object") return null;
    const source = row as JobRow;
    const job = { ...source, payload: JSON.parse(source.payload_json) };
    delete (job as Partial<JobRow>).payload_json;
    return operationJobSchema.parse(job);
  }
}
