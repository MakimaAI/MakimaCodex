import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertOperationOwner, assertOperationScope, assertOperationTimestamp, assertOperationTransition, canonicalEffectDescriptor, leaseExpiry, parseOperationFailure, parseRetryPolicy, retryAvailableAt, serializeOperationPayload, type EffectReceipt, type FailureDetails, type OperationAttempt, type OperationJob, type RetryPolicy } from "../core";

type JobRow = Omit<OperationJob, "payload" | "retry_policy"> & { payload_json: string; retry_policy_json: string };

export class SqliteOperationsStore {
  private readonly database: Database;
  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.database.exec(readFileSync(join(import.meta.dir, "migrations", "001_operations.sql"), "utf8"));
    this.database.exec(readFileSync(join(import.meta.dir, "migrations", "002_scope_boundary.sql"), "utf8"));
  }
  close(): void { this.database.close(); }
  private transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  enqueue(input: { scope_id: string; kind: string; idempotency_key: string; payload: Record<string, unknown>; priority: number; max_attempts: number; retry_policy: RetryPolicy; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationTimestamp(input.now); const payload = serializeOperationPayload(input.payload); const retryPolicy = parseRetryPolicy(input.retry_policy);
    if (!input.kind.trim() || input.kind.length > 200 || !input.idempotency_key.trim() || input.idempotency_key.length > 500 || !Number.isSafeInteger(input.priority) || !Number.isSafeInteger(input.max_attempts) || input.max_attempts < 1 || input.max_attempts > 30) throw new Error("OPERATION_ENQUEUE_INVALID");
    return this.transaction(() => {
      const existing = this.getByKindAndKey(input.scope_id, input.kind, input.idempotency_key); if (existing) return existing;
      const jobId = `operation:${canonicalSha256({ scope: input.scope_id, kind: input.kind, idempotency_key: input.idempotency_key }).slice("sha256:".length, "sha256:".length + 32)}`;
      this.database.query(`INSERT INTO operation_jobs_v2 (job_id, scope_id, kind, idempotency_key, payload_json, priority, max_attempts, retry_policy_json, attempt_count, state, available_at, lease_owner, lease_expires_at, lease_acquired_at, run_started_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 'PENDING', ?, NULL, NULL, NULL, NULL, ?, ?)`).run(jobId, input.scope_id, input.kind, input.idempotency_key, payload.json, input.priority, input.max_attempts, JSON.stringify(retryPolicy), input.now, input.now, input.now);
      return this.getRequired(input.scope_id, jobId);
    });
  }

  get(input: { scope_id: string; job_id: string }): OperationJob | null { assertOperationScope(input.scope_id); return this.decodeJob(this.database.query("SELECT * FROM operation_jobs_v2 WHERE scope_id=? AND job_id=?").get(input.scope_id, input.job_id)); }
  list(input: { scope_id: string }): OperationJob[] { assertOperationScope(input.scope_id); return (this.database.query("SELECT * FROM operation_jobs_v2 WHERE scope_id=? ORDER BY created_at, job_id").all(input.scope_id) as unknown[]).map(row => this.decodeJob(row)!); }
  attempts(input: { scope_id: string; job_id: string }): OperationAttempt[] { assertOperationScope(input.scope_id); return (this.database.query("SELECT payload_json FROM operation_attempts_v2 WHERE scope_id=? AND job_id=? ORDER BY attempt_number").all(input.scope_id, input.job_id) as Array<{ payload_json: string }>).map(row => JSON.parse(row.payload_json) as OperationAttempt); }
  effectReceipt(input: { scope_id: string; job_id: string }): EffectReceipt | null { assertOperationScope(input.scope_id); const row = this.database.query("SELECT payload_json FROM operation_effect_receipts_v2 WHERE scope_id=? AND job_id=?").get(input.scope_id, input.job_id) as { payload_json: string } | null; return row ? JSON.parse(row.payload_json) as EffectReceipt : null; }

  claim(input: { scope_id: string; owner: string; now: string; lease_ms: number }): OperationJob | null {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => {
      this.reconcileExpiredWithin(input.scope_id, input.now);
      const candidate = this.database.query(`SELECT job_id FROM operation_jobs_v2 WHERE scope_id=? AND state IN ('PENDING', 'RETRY_PENDING') AND julianday(available_at) <= julianday(?) ORDER BY priority DESC, available_at, created_at, job_id LIMIT 1`).get(input.scope_id, input.now) as { job_id: string } | null;
      if (!candidate) return null;
      this.database.query("UPDATE operation_jobs_v2 SET state='LEASED', lease_owner=?, lease_expires_at=?, lease_acquired_at=?, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=? AND state IN ('PENDING', 'RETRY_PENDING')").run(input.owner, expiresAt, input.now, input.now, input.scope_id, candidate.job_id);
      return this.getRequired(input.scope_id, candidate.job_id);
    });
  }
  heartbeat(input: { scope_id: string; job_id: string; owner: string; now: string; lease_ms: number }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); this.database.query("UPDATE operation_jobs_v2 SET lease_expires_at=?, updated_at=? WHERE scope_id=? AND job_id=?").run(expiresAt, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id); });
  }
  start(input: { scope_id: string; job_id: string; owner: string; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); if (job.state !== "LEASED") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); assertOperationTransition(job.state, "RUNNING"); this.database.query("UPDATE operation_jobs_v2 SET state='RUNNING', run_started_at=?, updated_at=? WHERE scope_id=? AND job_id=?").run(input.now, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id); });
  }
  succeed(input: { scope_id: string; job_id: string; owner: string; effect: Record<string, unknown>; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const effect = canonicalEffectDescriptor(input.effect);
    return this.transaction(() => {
      const receipt = this.effectReceipt({ scope_id: input.scope_id, job_id: input.job_id });
      if (receipt) { if (receipt.effect_hash !== effect.effect_hash) throw new Error("OPERATION_EFFECT_RECEIPT_CONFLICT"); return this.getRequired(input.scope_id, input.job_id); }
      const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); assertOperationTransition(job.state, "SUCCEEDED");
      const attempt = this.recordAttempt(job, input.owner, "SUCCEEDED", null, input.now);
      const receiptValue: EffectReceipt = { scope_id: input.scope_id, job_id: job.job_id, effect_hash: effect.effect_hash, effect: effect.effect, succeeded_at: input.now };
      this.database.query("INSERT INTO operation_effect_receipts_v2 (scope_id, job_id, effect_hash, effect_json, succeeded_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)").run(input.scope_id, job.job_id, effect.effect_hash, effect.effect_json, input.now, JSON.stringify(receiptValue));
      this.database.query("UPDATE operation_jobs_v2 SET state='SUCCEEDED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id);
    });
  }
  fail(input: { scope_id: string; job_id: string; owner: string; failure: FailureDetails; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const failure = parseOperationFailure(input.failure);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); return this.finishFailedAttempt(job, input.owner, failure, input.now, "FAILED"); });
  }
  cancel(input: { scope_id: string; job_id: string; owner?: string; cancellation_authority?: { scope_id: string; authority_id: string }; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationTimestamp(input.now);
    return this.transaction(() => {
      const job = this.getRequired(input.scope_id, input.job_id); if (job.state === "CANCELLED") return job;
      if (["SUCCEEDED", "FAILED", "DEAD_LETTER"].includes(job.state)) throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      if (job.state === "LEASED" || job.state === "RUNNING") {
        if (input.owner !== undefined) { assertOperationOwner(input.owner); if (job.lease_owner !== input.owner) throw new Error("OPERATION_LEASE_OWNER_MISMATCH"); }
        else this.assertCancellationAuthority(input.scope_id, input.cancellation_authority);
        const attempt = this.recordAttempt(job, job.lease_owner!, "CANCELLED", null, input.now);
        this.database.query("UPDATE operation_jobs_v2 SET state='CANCELLED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, input.scope_id, job.job_id);
      } else {
        this.assertCancellationAuthority(input.scope_id, input.cancellation_authority);
        assertOperationTransition(job.state, "CANCELLED"); this.database.query("UPDATE operation_jobs_v2 SET state='CANCELLED', lease_owner=NULL, lease_expires_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(input.now, input.scope_id, job.job_id);
      }
      return this.getRequired(input.scope_id, job.job_id);
    });
  }
  reconcileExpired(input: { scope_id: string; now: string }): number { assertOperationScope(input.scope_id); assertOperationTimestamp(input.now); return this.transaction(() => this.reconcileExpiredWithin(input.scope_id, input.now)); }

  private reconcileExpiredWithin(scopeId: string, now: string): number {
    const expired = (this.database.query("SELECT * FROM operation_jobs_v2 WHERE scope_id=? AND state IN ('LEASED', 'RUNNING') AND julianday(lease_expires_at) <= julianday(?) ORDER BY job_id").all(scopeId, now) as unknown[]).map(row => this.decodeJob(row)!);
    for (const job of expired) {
      if (job.state === "LEASED") { assertOperationTransition(job.state, "PENDING"); this.database.query("UPDATE operation_jobs_v2 SET state='PENDING', lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(now, scopeId, job.job_id); }
      else this.finishFailedAttempt(job, job.lease_owner!, { code: "LEASE_EXPIRED", summary: "Lease expired without completion", artifact_ref: null }, now, "LEASE_EXPIRED");
    }
    return expired.length;
  }
  private finishFailedAttempt(job: OperationJob, owner: string, failure: FailureDetails, now: string, outcome: "FAILED" | "LEASE_EXPIRED"): OperationJob {
    const attempt = this.recordAttempt(job, owner, outcome, failure, now); const exhausted = attempt.attempt_number >= job.max_attempts; const nextState = exhausted ? "DEAD_LETTER" : "RETRY_PENDING"; assertOperationTransition(job.state, nextState);
    const availableAt = exhausted ? now : retryAvailableAt(now, job.retry_policy, attempt.attempt_number);
    this.database.query("UPDATE operation_jobs_v2 SET state=?, attempt_count=?, available_at=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(nextState, attempt.attempt_number, availableAt, now, job.scope_id, job.job_id); return this.getRequired(job.scope_id, job.job_id);
  }
  private recordAttempt(job: OperationJob, owner: string, outcome: OperationAttempt["outcome"], failure: FailureDetails | null, finishedAt: string): OperationAttempt {
    const attemptNumber = job.attempt_count + 1; const value: OperationAttempt = { attempt_id: `attempt:${canonicalSha256({ scope: job.scope_id, job: job.job_id, attempt: attemptNumber }).slice("sha256:".length, "sha256:".length + 32)}`, scope_id: job.scope_id, job_id: job.job_id, attempt_number: attemptNumber, owner, outcome, failure, started_at: job.run_started_at ?? job.lease_acquired_at ?? finishedAt, finished_at: finishedAt };
    const snapshot = serializeOperationPayload(value);
    this.database.query("INSERT INTO operation_attempts_v2 (attempt_id, scope_id, job_id, attempt_number, owner, outcome, failure_json, started_at, finished_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(value.attempt_id, value.scope_id, value.job_id, value.attempt_number, value.owner, value.outcome, failure === null ? null : JSON.stringify(failure), value.started_at, value.finished_at, snapshot.json); return value;
  }
  private assertCancellationAuthority(scopeId: string, authority: { scope_id: string; authority_id: string } | undefined): void { if (!authority || authority.scope_id !== scopeId) throw new Error("OPERATION_CANCELLATION_AUTHORITY_REQUIRED"); assertOperationScope(authority.scope_id); assertOperationOwner(authority.authority_id); }
  private requireActiveLease(scopeId: string, jobId: string, owner: string, now: string): OperationJob { const job = this.getRequired(scopeId, jobId); if (job.state !== "LEASED" && job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); if (job.lease_owner !== owner) throw new Error("OPERATION_LEASE_OWNER_MISMATCH"); if (!job.lease_expires_at || Date.parse(job.lease_expires_at) <= Date.parse(now)) throw new Error("OPERATION_LEASE_EXPIRED"); return job; }
  private getByKindAndKey(scopeId: string, kind: string, key: string): OperationJob | null { return this.decodeJob(this.database.query("SELECT * FROM operation_jobs_v2 WHERE scope_id=? AND kind=? AND idempotency_key=?").get(scopeId, kind, key)); }
  private getRequired(scopeId: string, jobId: string): OperationJob { const job = this.get({ scope_id: scopeId, job_id: jobId }); if (!job) throw new Error("OPERATION_NOT_FOUND"); return job; }
  private decodeJob(row: unknown): OperationJob | null { if (!row || typeof row !== "object") return null; const source = row as JobRow; return { ...source, payload: JSON.parse(source.payload_json) as Record<string, never>, retry_policy: parseRetryPolicy(JSON.parse(source.retry_policy_json) as RetryPolicy) }; }
}
