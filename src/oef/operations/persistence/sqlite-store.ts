import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertCausalTime, assertOperationOwner, assertOperationScope, assertOperationTimestamp, assertOperationTransition, canonicalEffectDescriptor, canonicalJson, jobStateSchema, leaseExpiry, parseOperationFailure, parseRetryPolicy, retryAvailableAt, serializeOperationPayload, type CancellationCapabilityVerifier, type EffectReceipt, type FailureDetails, type JsonValue, type OperationAttempt, type OperationJob, type RetryPolicy } from "../core";

type JobRow = Omit<OperationJob, "payload" | "retry_policy"> & { payload_json: string; payload_hash: string; retry_policy_json: string };

const jobRowKeys = ["available_at", "attempt_count", "created_at", "idempotency_key", "job_id", "kind", "lease_acquired_at", "lease_expires_at", "lease_owner", "max_attempts", "payload_hash", "payload_json", "priority", "retry_policy_json", "run_started_at", "scope_id", "state", "updated_at"];
const attemptRowKeys = ["actor", "attempt_id", "attempt_number", "failure_json", "finished_at", "job_id", "outcome", "owner", "payload_json", "scope_id", "started_at"];
const receiptRowKeys = ["effect_hash", "effect_json", "job_id", "payload_json", "scope_id", "succeeded_at"];
const attemptSnapshotKeys = ["actor", "attempt_id", "attempt_number", "failure", "finished_at", "job_id", "outcome", "owner", "scope_id", "started_at"];
const receiptSnapshotKeys = ["effect", "effect_hash", "job_id", "scope_id", "succeeded_at"];

function hasExactKeys(value: object, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every(key => Object.hasOwn(value, key));
}
function assertPersistedId(value: unknown, prefix: "operation" | "attempt"): asserts value is string {
  if (typeof value !== "string" || !new RegExp(`^${prefix}:[a-f0-9]{32}$`).test(value)) throw new Error("tampered");
}

export class SqliteOperationsStore {
  private readonly database: Database;
  private readonly cancellationCapabilityVerifier: CancellationCapabilityVerifier | undefined;
  constructor(options: { databasePath: string; cancellationCapabilityVerifier?: CancellationCapabilityVerifier }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.cancellationCapabilityVerifier = options.cancellationCapabilityVerifier;
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.database.exec(readFileSync(join(import.meta.dir, "migrations", "001_operations.sql"), "utf8"));
  }
  close(): void { this.database.close(); }
  private transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  enqueue(input: { scope_id: string; kind: string; idempotency_key: string; payload: Record<string, unknown>; priority: number; max_attempts: number; retry_policy: RetryPolicy; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationTimestamp(input.now); const payload = serializeOperationPayload(input.payload); const retryPolicy = parseRetryPolicy(input.retry_policy);
    if (!input.kind.trim() || input.kind.length > 200 || !input.idempotency_key.trim() || input.idempotency_key.length > 500 || !Number.isSafeInteger(input.priority) || !Number.isSafeInteger(input.max_attempts) || input.max_attempts < 1 || input.max_attempts > 30) throw new Error("OPERATION_ENQUEUE_INVALID");
    return this.transaction(() => {
      const existing = this.getByKindAndKey(input.scope_id, input.kind, input.idempotency_key); if (existing) return existing;
      const jobId = `operation:${canonicalSha256({ scope: input.scope_id, kind: input.kind, idempotency_key: input.idempotency_key }).slice("sha256:".length, "sha256:".length + 32)}`;
      this.database.query(`INSERT INTO operation_jobs (job_id, scope_id, kind, idempotency_key, payload_json, payload_hash, priority, max_attempts, retry_policy_json, attempt_count, state, available_at, lease_owner, lease_expires_at, lease_acquired_at, run_started_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'PENDING', ?, NULL, NULL, NULL, NULL, ?, ?)`).run(jobId, input.scope_id, input.kind, input.idempotency_key, payload.json, canonicalSha256(canonicalJson(payload.value)), input.priority, input.max_attempts, JSON.stringify(retryPolicy), input.now, input.now, input.now);
      return this.getRequired(input.scope_id, jobId);
    });
  }

  get(input: { scope_id: string; job_id: string }): OperationJob | null { assertOperationScope(input.scope_id); return this.decodeJob(this.database.query("SELECT * FROM operation_jobs WHERE scope_id=? AND job_id=?").get(input.scope_id, input.job_id)); }
  list(input: { scope_id: string }): OperationJob[] { assertOperationScope(input.scope_id); return (this.database.query("SELECT * FROM operation_jobs WHERE scope_id=? ORDER BY created_at, job_id").all(input.scope_id) as unknown[]).map(row => this.decodeJob(row)!); }
  attempts(input: { scope_id: string; job_id: string }): OperationAttempt[] { assertOperationScope(input.scope_id); return (this.database.query("SELECT * FROM operation_attempts WHERE scope_id=? AND job_id=? ORDER BY attempt_number").all(input.scope_id, input.job_id) as Array<Record<string, unknown>>).map(row => this.decodeAttempt(row, input.scope_id, input.job_id)); }
  effectReceipt(input: { scope_id: string; job_id: string }): EffectReceipt | null { assertOperationScope(input.scope_id); const row = this.database.query("SELECT * FROM operation_effect_receipts WHERE scope_id=? AND job_id=?").get(input.scope_id, input.job_id) as Record<string, unknown> | null; return row ? this.decodeReceipt(row, input.scope_id, input.job_id) : null; }

  claim(input: { scope_id: string; owner: string; now: string; lease_ms: number }): OperationJob | null {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => {
      this.reconcileExpiredWithin(input.scope_id, input.now);
      const candidate = this.database.query(`SELECT job_id FROM operation_jobs WHERE scope_id=? AND state IN ('PENDING', 'RETRY_PENDING') AND julianday(available_at) <= julianday(?) ORDER BY priority DESC, available_at, created_at, job_id LIMIT 1`).get(input.scope_id, input.now) as { job_id: string } | null;
      if (!candidate) return null;
      this.database.query("UPDATE operation_jobs SET state='LEASED', lease_owner=?, lease_expires_at=?, lease_acquired_at=?, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=? AND state IN ('PENDING', 'RETRY_PENDING')").run(input.owner, expiresAt, input.now, input.now, input.scope_id, candidate.job_id);
      return this.getRequired(input.scope_id, candidate.job_id);
    });
  }
  heartbeat(input: { scope_id: string; job_id: string; owner: string; now: string; lease_ms: number }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const expiresAt = leaseExpiry(input.now, input.lease_ms);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); assertCausalTime(input.now, job.updated_at); if (job.lease_expires_at && Date.parse(expiresAt) < Date.parse(job.lease_expires_at)) throw new Error("OPERATION_LEASE_SHORTENING_REJECTED"); this.database.query("UPDATE operation_jobs SET lease_expires_at=?, updated_at=? WHERE scope_id=? AND job_id=?").run(expiresAt, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id); });
  }
  start(input: { scope_id: string; job_id: string; owner: string; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); assertCausalTime(input.now, job.updated_at); if (job.state !== "LEASED") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); assertOperationTransition(job.state, "RUNNING"); this.database.query("UPDATE operation_jobs SET state='RUNNING', run_started_at=?, updated_at=? WHERE scope_id=? AND job_id=?").run(input.now, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id); });
  }
  succeed(input: { scope_id: string; job_id: string; owner: string; effect: Record<string, unknown>; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const effect = canonicalEffectDescriptor(input.effect);
    return this.transaction(() => {
      const receipt = this.effectReceipt({ scope_id: input.scope_id, job_id: input.job_id });
      if (receipt) { if (receipt.effect_hash !== effect.effect_hash) throw new Error("OPERATION_EFFECT_RECEIPT_CONFLICT"); return this.getRequired(input.scope_id, input.job_id); }
      const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); assertOperationTransition(job.state, "SUCCEEDED");
      assertCausalTime(input.now, job.updated_at); const attempt = this.recordAttempt(job, input.owner, input.owner, "SUCCEEDED", null, input.now);
      const receiptValue: EffectReceipt = { scope_id: input.scope_id, job_id: job.job_id, effect_hash: effect.effect_hash, effect: effect.effect, succeeded_at: input.now };
      this.database.query("INSERT INTO operation_effect_receipts (scope_id, job_id, effect_hash, effect_json, succeeded_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)").run(input.scope_id, job.job_id, effect.effect_hash, effect.effect_json, input.now, JSON.stringify(receiptValue));
      this.database.query("UPDATE operation_jobs SET state='SUCCEEDED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, input.scope_id, job.job_id); return this.getRequired(input.scope_id, job.job_id);
    });
  }
  fail(input: { scope_id: string; job_id: string; owner: string; failure: FailureDetails; retryable?: boolean; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationOwner(input.owner); assertOperationTimestamp(input.now); const failure = parseOperationFailure(input.failure);
    return this.transaction(() => { const job = this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now); if (failure.artifact_ref !== null && !failure.artifact_ref.startsWith(`artifact:${job.scope_id}:`)) throw new Error("OPERATION_FAILURE_ARTIFACT_SCOPE_INVALID"); assertCausalTime(input.now, job.updated_at); if (job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); if (input.retryable === false) { const attempt = this.recordAttempt(job, input.owner, input.owner, "FAILED", failure, input.now); assertOperationTransition(job.state, "FAILED"); this.database.query("UPDATE operation_jobs SET state='FAILED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, job.scope_id, job.job_id); return this.getRequired(job.scope_id, job.job_id); } return this.finishFailedAttempt(job, input.owner, failure, input.now, "FAILED"); });
  }
  cancel(input: { scope_id: string; job_id: string; owner?: string; capability?: string; actor?: string; now: string }): OperationJob {
    assertOperationScope(input.scope_id); assertOperationTimestamp(input.now);
    return this.transaction(() => {
      const job = this.getRequired(input.scope_id, input.job_id); if (job.state === "CANCELLED") return job;
      if (["SUCCEEDED", "FAILED", "DEAD_LETTER"].includes(job.state)) throw new Error("OPERATION_STATE_TRANSITION_INVALID");
      if (job.state === "LEASED" || job.state === "RUNNING") {
        assertCausalTime(input.now, job.updated_at); const actor = input.owner !== undefined ? input.owner : this.verifyCancellationCapability(input, job.job_id);
        if (input.owner !== undefined) this.requireActiveLease(input.scope_id, input.job_id, input.owner, input.now);
        const attempt = this.recordAttempt(job, job.lease_owner!, actor, "CANCELLED", null, input.now);
        this.database.query("UPDATE operation_jobs SET state='CANCELLED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, input.scope_id, job.job_id);
      } else {
        const actor = this.verifyCancellationCapability(input, job.job_id); assertCausalTime(input.now, job.updated_at);
        const attempt = this.recordAttempt(job, actor, actor, "CANCELLED", null, input.now);
        assertOperationTransition(job.state, "CANCELLED"); this.database.query("UPDATE operation_jobs SET state='CANCELLED', attempt_count=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(attempt.attempt_number, input.now, input.scope_id, job.job_id);
      }
      return this.getRequired(input.scope_id, job.job_id);
    });
  }
  reconcileExpired(input: { scope_id: string; now: string }): number { assertOperationScope(input.scope_id); assertOperationTimestamp(input.now); return this.transaction(() => this.reconcileExpiredWithin(input.scope_id, input.now)); }

  private reconcileExpiredWithin(scopeId: string, now: string): number {
    const expired = (this.database.query("SELECT * FROM operation_jobs WHERE scope_id=? AND state IN ('LEASED', 'RUNNING') AND julianday(lease_expires_at) <= julianday(?) ORDER BY job_id").all(scopeId, now) as unknown[]).map(row => this.decodeJob(row)!);
    for (const job of expired) {
      assertCausalTime(now, job.updated_at);
      if (job.state === "LEASED") { assertOperationTransition(job.state, "PENDING"); this.database.query("UPDATE operation_jobs SET state='PENDING', lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(now, scopeId, job.job_id); }
      else this.finishFailedAttempt(job, job.lease_owner!, { code: "LEASE_EXPIRED", summary: "Lease expired without completion", artifact_ref: null }, now, "LEASE_EXPIRED");
    }
    return expired.length;
  }
  private finishFailedAttempt(job: OperationJob, owner: string, failure: FailureDetails, now: string, outcome: "FAILED" | "LEASE_EXPIRED"): OperationJob {
    const attempt = this.recordAttempt(job, owner, owner, outcome, failure, now); const exhausted = attempt.attempt_number >= job.max_attempts; const nextState = exhausted ? "DEAD_LETTER" : "RETRY_PENDING"; assertOperationTransition(job.state, nextState);
    const availableAt = exhausted ? now : retryAvailableAt(now, job.retry_policy, attempt.attempt_number);
    this.database.query("UPDATE operation_jobs SET state=?, attempt_count=?, available_at=?, lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL, updated_at=? WHERE scope_id=? AND job_id=?").run(nextState, attempt.attempt_number, availableAt, now, job.scope_id, job.job_id); return this.getRequired(job.scope_id, job.job_id);
  }
  private recordAttempt(job: OperationJob, owner: string, actor: string, outcome: OperationAttempt["outcome"], failure: FailureDetails | null, finishedAt: string): OperationAttempt {
    const attemptNumber = job.attempt_count + 1; const value: OperationAttempt = { attempt_id: `attempt:${canonicalSha256({ scope: job.scope_id, job: job.job_id, attempt: attemptNumber }).slice("sha256:".length, "sha256:".length + 32)}`, scope_id: job.scope_id, job_id: job.job_id, attempt_number: attemptNumber, owner, actor, outcome, failure, started_at: job.run_started_at ?? job.lease_acquired_at ?? finishedAt, finished_at: finishedAt };
    const snapshot = serializeOperationPayload(value);
    this.database.query("INSERT INTO operation_attempts (attempt_id, scope_id, job_id, attempt_number, owner, actor, outcome, failure_json, started_at, finished_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").run(value.attempt_id, value.scope_id, value.job_id, value.attempt_number, value.owner, value.actor, value.outcome, failure === null ? null : JSON.stringify(failure), value.started_at, value.finished_at, snapshot.json); return value;
  }
  private verifyCancellationCapability(input: { scope_id: string; capability?: string; actor?: string; now: string }, jobId: string): string { if (!this.cancellationCapabilityVerifier || !input.capability || !input.actor) throw new Error("OPERATION_CANCELLATION_CAPABILITY_INVALID"); assertOperationOwner(input.actor); const verified = this.cancellationCapabilityVerifier.verify({ capability: input.capability, scope_id: input.scope_id, job_id: jobId, action: "CANCEL", actor: input.actor, now: input.now }); if (!verified || verified.actor !== input.actor) throw new Error("OPERATION_CANCELLATION_CAPABILITY_INVALID"); assertOperationOwner(verified.actor); assertOperationTimestamp(verified.expires_at); if (Date.parse(verified.expires_at) <= Date.parse(input.now)) throw new Error("OPERATION_CANCELLATION_CAPABILITY_INVALID"); return verified.actor; }
  private requireActiveLease(scopeId: string, jobId: string, owner: string, now: string): OperationJob { const job = this.getRequired(scopeId, jobId); if (job.state !== "LEASED" && job.state !== "RUNNING") throw new Error("OPERATION_STATE_TRANSITION_INVALID"); if (job.lease_owner !== owner) throw new Error("OPERATION_LEASE_OWNER_MISMATCH"); if (!job.lease_expires_at || Date.parse(job.lease_expires_at) <= Date.parse(now)) throw new Error("OPERATION_LEASE_EXPIRED"); return job; }
  private getByKindAndKey(scopeId: string, kind: string, key: string): OperationJob | null { return this.decodeJob(this.database.query("SELECT * FROM operation_jobs WHERE scope_id=? AND kind=? AND idempotency_key=?").get(scopeId, kind, key)); }
  private getRequired(scopeId: string, jobId: string): OperationJob { const job = this.get({ scope_id: scopeId, job_id: jobId }); if (!job) throw new Error("OPERATION_NOT_FOUND"); return job; }
  private decodeJob(row: unknown): OperationJob | null {
    if (!row || typeof row !== "object") return null;
    try {
      if (!hasExactKeys(row, jobRowKeys)) throw new Error("tampered");
      const source = row as JobRow; const payload = serializeOperationPayload(JSON.parse(source.payload_json)); const retryPolicy = parseRetryPolicy(JSON.parse(source.retry_policy_json) as RetryPolicy);
      if (payload.json !== source.payload_json || canonicalSha256(canonicalJson(payload.value)) !== source.payload_hash || JSON.stringify(retryPolicy) !== source.retry_policy_json || !jobStateSchema.safeParse(source.state).success) throw new Error("tampered");
      for (const time of [source.available_at, source.created_at, source.updated_at, source.lease_expires_at, source.lease_acquired_at, source.run_started_at]) if (time !== null) assertOperationTimestamp(time);
      assertOperationScope(source.scope_id); assertPersistedId(source.job_id, "operation"); if (typeof source.kind !== "string" || !source.kind.trim() || source.kind.length > 200 || typeof source.idempotency_key !== "string" || !source.idempotency_key.trim() || source.idempotency_key.length > 500 || !Number.isSafeInteger(source.priority) || !Number.isSafeInteger(source.max_attempts) || source.max_attempts < 1 || source.max_attempts > 30 || !Number.isSafeInteger(source.attempt_count) || source.attempt_count < 0 || source.attempt_count > source.max_attempts) throw new Error("tampered"); if (source.lease_owner !== null) assertOperationOwner(source.lease_owner); if (Date.parse(source.updated_at) < Date.parse(source.created_at) || (source.run_started_at && source.lease_acquired_at && Date.parse(source.run_started_at) < Date.parse(source.lease_acquired_at))) throw new Error("tampered");
      const hasLease = source.lease_owner !== null && source.lease_expires_at !== null && source.lease_acquired_at !== null; const active = source.state === "LEASED" || source.state === "RUNNING";
      if (active !== hasLease || (source.state === "RUNNING" && source.run_started_at === null) || (source.state === "LEASED" && source.run_started_at !== null) || (!active && (source.lease_owner !== null || source.lease_expires_at !== null || source.lease_acquired_at !== null || source.run_started_at !== null))) throw new Error("tampered");
      return { job_id: source.job_id, scope_id: source.scope_id, kind: source.kind, idempotency_key: source.idempotency_key, payload: payload.value, priority: source.priority, max_attempts: source.max_attempts, retry_policy: retryPolicy, attempt_count: source.attempt_count, state: source.state, available_at: source.available_at, lease_owner: source.lease_owner, lease_expires_at: source.lease_expires_at, lease_acquired_at: source.lease_acquired_at, run_started_at: source.run_started_at, created_at: source.created_at, updated_at: source.updated_at };
    } catch { throw new Error("OPERATION_PERSISTENCE_TAMPERED"); }
  }
  private decodeAttempt(row: Record<string, unknown>, scopeId: string, jobId: string): OperationAttempt {
    try { if (!hasExactKeys(row, attemptRowKeys)) throw new Error("tampered"); const payloadJson = String(row.payload_json); const raw = JSON.parse(payloadJson) as OperationAttempt; const snapshot = serializeOperationPayload(raw); if (!hasExactKeys(raw, attemptSnapshotKeys) || snapshot.json !== payloadJson || raw.scope_id !== scopeId || raw.job_id !== jobId || raw.attempt_id !== row.attempt_id || raw.scope_id !== row.scope_id || raw.job_id !== row.job_id || raw.attempt_number !== row.attempt_number || raw.owner !== row.owner || raw.actor !== row.actor || raw.outcome !== row.outcome || raw.started_at !== row.started_at || raw.finished_at !== row.finished_at || JSON.stringify(raw.failure) !== (row.failure_json === null ? "null" : row.failure_json) || !Number.isSafeInteger(raw.attempt_number) || raw.attempt_number < 1) throw new Error("tampered"); assertPersistedId(raw.attempt_id, "attempt"); assertPersistedId(raw.job_id, "operation"); assertOperationScope(raw.scope_id); assertOperationOwner(raw.owner); assertOperationOwner(raw.actor); assertOperationTimestamp(raw.started_at); assertOperationTimestamp(raw.finished_at); if (Date.parse(raw.finished_at) < Date.parse(raw.started_at) || !["SUCCEEDED", "FAILED", "LEASE_EXPIRED", "CANCELLED"].includes(raw.outcome) || ((raw.outcome === "SUCCEEDED" || raw.outcome === "CANCELLED") && raw.failure !== null) || ((raw.outcome === "FAILED" || raw.outcome === "LEASE_EXPIRED") && raw.failure === null)) throw new Error("tampered"); if (raw.failure !== null) { parseOperationFailure(raw.failure); if (raw.failure.artifact_ref && !raw.failure.artifact_ref.startsWith(`artifact:${raw.scope_id}:`)) throw new Error("tampered"); } return { attempt_id: raw.attempt_id, scope_id: raw.scope_id, job_id: raw.job_id, attempt_number: raw.attempt_number, owner: raw.owner, actor: raw.actor, outcome: raw.outcome, failure: raw.failure, started_at: raw.started_at, finished_at: raw.finished_at }; } catch { throw new Error("OPERATION_PERSISTENCE_TAMPERED"); }
  }
  private decodeReceipt(row: Record<string, unknown>, scopeId: string, jobId: string): EffectReceipt {
    try { if (!hasExactKeys(row, receiptRowKeys)) throw new Error("tampered"); const payloadJson = String(row.payload_json); const raw = JSON.parse(payloadJson) as EffectReceipt; const snapshot = serializeOperationPayload(raw); const effect = canonicalEffectDescriptor(raw.effect); if (!hasExactKeys(raw, receiptSnapshotKeys) || snapshot.json !== payloadJson || raw.scope_id !== scopeId || raw.job_id !== jobId || raw.scope_id !== row.scope_id || raw.job_id !== row.job_id || raw.effect_hash !== row.effect_hash || raw.effect_hash !== effect.effect_hash || effect.effect_json !== row.effect_json || raw.succeeded_at !== row.succeeded_at) throw new Error("tampered"); assertPersistedId(raw.job_id, "operation"); assertOperationScope(raw.scope_id); assertOperationTimestamp(raw.succeeded_at); return { scope_id: raw.scope_id, job_id: raw.job_id, effect_hash: raw.effect_hash, effect: effect.effect, succeeded_at: raw.succeeded_at }; } catch { throw new Error("OPERATION_PERSISTENCE_TAMPERED"); }
  }
}
