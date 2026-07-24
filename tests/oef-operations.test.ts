import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import {
  JOB_STATES, SqliteOperationsStore, assertOperationTimestamp, canonicalEffectDescriptor, leaseExpiry,
  jobStateSchema, parseOperationFailure, retryAvailableAt, type CancellationCapabilityVerifier, type FailureDetails, type RetryPolicy,
} from "../src/oef/operations";

const roots: string[] = [];
const t0 = "2026-07-24T12:00:00.000Z";
const scopeA = "scope:alpha";
const scopeB = "scope:beta";
const retryPolicy: RetryPolicy = { base_backoff_ms: 1_000, max_backoff_ms: 8_000 };

afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function store(cancellationCapabilityVerifier?: CancellationCapabilityVerifier): SqliteOperationsStore {
  const root = mkdtempSync(join(tmpdir(), "oef-operations-")); roots.push(root);
  return new SqliteOperationsStore({ databasePath: join(root, "operations.sqlite"), cancellationCapabilityVerifier });
}

function enqueue(target: SqliteOperationsStore, overrides: Record<string, unknown> = {}) {
  return target.enqueue({
    scope_id: scopeA,
    kind: "opencodex.operation.test",
    idempotency_key: "key:one",
    payload: { subject: "safe" },
    priority: 10,
    max_attempts: 3,
    retry_policy: retryPolicy,
    now: t0,
    ...overrides,
  });
}

function claimAndStart(target: SqliteOperationsStore, jobId: string, now = t0): void {
  expect(target.claim({ scope_id: scopeA, owner: "worker:a", now, lease_ms: 5_000 })?.job_id).toBe(jobId);
  target.start({ scope_id: scopeA, job_id: jobId, owner: "worker:a", now });
}

describe("durable operations", () => {
  test("defines only the strict durable job states", () => {
    expect(JOB_STATES).toEqual(["PENDING", "LEASED", "RUNNING", "RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"]);
    expect(() => jobStateSchema.parse("UNKNOWN")).toThrow();
  });

  test("scopes idempotency, reads, claims, and cancellation boundaries durably", () => {
    const target = store();
    const alpha = enqueue(target);
    const beta = enqueue(target, { scope_id: scopeB });
    expect(alpha.job_id).not.toBe(beta.job_id);
    expect(target.get({ scope_id: scopeB, job_id: alpha.job_id })).toBeNull();
    expect(target.claim({ scope_id: scopeB, owner: "worker:b", now: t0, lease_ms: 1_000 })?.job_id).toBe(beta.job_id);
    expect(() => target.cancel({ scope_id: scopeB, job_id: alpha.job_id, now: t0, owner: "worker:b" })).toThrow("OPERATION_NOT_FOUND");
    target.close();
  });

  test("persists an idempotent job and its retry policy across restart", () => {
    const first = store(); const job = enqueue(first);
    expect(enqueue(first, { payload: { subject: "ignored" } }).job_id).toBe(job.job_id);
    first.close();
    const reopened = new SqliteOperationsStore({ databasePath: join(roots[0]!, "operations.sqlite") });
    expect(enqueue(reopened).retry_policy).toEqual(retryPolicy);
    expect(reopened.list({ scope_id: scopeA })).toHaveLength(1);
    reopened.close();
  });

  test("permits takeover only after expiry and requires exact lease ownership", () => {
    const target = store(); const job = enqueue(target);
    target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 1_000 });
    expect(target.claim({ scope_id: scopeA, owner: "worker:b", now: "2026-07-24T12:00:00.500Z", lease_ms: 1_000 })).toBeNull();
    expect(target.claim({ scope_id: scopeA, owner: "worker:b", now: "2026-07-24T12:00:01.001Z", lease_ms: 1_000 })?.job_id).toBe(job.job_id);
    expect(() => target.heartbeat({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", now: "2026-07-24T12:00:01.001Z", lease_ms: 1_000 })).toThrow("OPERATION_LEASE_OWNER_MISMATCH");
    target.close();
  });

  test("requires owner or scoped authority to cancel active work and preserves cancellation evidence", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    expect(() => target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0, owner: "worker:b" })).toThrow("OPERATION_LEASE_OWNER_MISMATCH");
    expect(target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0, owner: "worker:a" }).state).toBe("CANCELLED");
    expect(target.attempts({ scope_id: scopeA, job_id: job.job_id })[0]?.outcome).toBe("CANCELLED");
    expect(target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0 }).state).toBe("CANCELLED");
    target.close();
  });

  test("computes a canonical exactly-once effect identity and fails closed on conflict", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    const effect = { provider: "local", output_id: "result:1" };
    const succeeded = target.succeed({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", effect, now: t0 });
    expect(succeeded.state).toBe("SUCCEEDED");
    expect(target.succeed({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", effect, now: t0 }).state).toBe("SUCCEEDED");
    expect(target.effectReceipt({ scope_id: scopeA, job_id: job.job_id })?.effect_hash).toBe(canonicalEffectDescriptor(effect).effect_hash);
    expect(() => target.succeed({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", effect: { provider: "local", output_id: "result:2" }, now: t0 })).toThrow("OPERATION_EFFECT_RECEIPT_CONFLICT");
    expect(() => canonicalEffectDescriptor("sha256:not-a-descriptor")).toThrow("OPERATION_EFFECT_DESCRIPTOR_INVALID");
    target.close();
  });

  test("uses the persisted retry policy for explicit failure and expiry recovery with capped date arithmetic", () => {
    const target = store(); const policy: RetryPolicy = { base_backoff_ms: 500, max_backoff_ms: 500 };
    const failed = enqueue(target, { retry_policy: policy }); claimAndStart(target, failed.job_id);
    expect(target.fail({ scope_id: scopeA, job_id: failed.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "temporary network failure", artifact_ref: "artifact:scope:alpha:network-1" }, now: t0 }).available_at).toBe("2026-07-24T12:00:00.500Z");
    const expired = enqueue(target, { idempotency_key: "key:expired", retry_policy: policy }); claimAndStart(target, expired.job_id);
    expect(target.reconcileExpired({ scope_id: scopeA, now: "2026-07-24T12:00:05.001Z" })).toBe(1);
    expect(target.get({ scope_id: scopeA, job_id: expired.job_id })?.available_at).toBe("2026-07-24T12:00:05.501Z");
    expect(retryAvailableAt("9999-12-31T23:59:59.999Z", { base_backoff_ms: 86_400_000, max_backoff_ms: 86_400_000 }, 1)).toBe("9999-12-31T23:59:59.999Z");
    expect(() => leaseExpiry("9999-12-31T23:59:59.999Z", 1)).toThrow("OPERATION_LEASE_INVALID");
    target.close();
  });

  test("stores only bounded sanitized failure snapshots and rejects raw failure evidence", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    expect(() => parseOperationFailure({ code: "RAW", summary: "safe", raw_error: "untrusted raw log text" })).toThrow("OPERATION_FAILURE_INVALID");
    target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "connection timed out", artifact_ref: "artifact:scope:alpha:log-1" }, now: t0 });
    expect(target.attempts({ scope_id: scopeA, job_id: job.job_id })[0]?.failure).toEqual({ code: "NETWORK", summary: "connection timed out", artifact_ref: "artifact:scope:alpha:log-1" });
    target.close();
  });

  test("rejects non-canonical timestamps and non-plain or secret snapshots", () => {
    expect(() => assertOperationTimestamp("2026-02-30T12:00:00.000Z")).toThrow("OPERATION_TIMESTAMP_INVALID");
    expect(() => assertOperationTimestamp("2026-07-24T12:00:00Z")).toThrow("OPERATION_TIMESTAMP_INVALID");
    expect(() => assertOperationTimestamp("2026-07-24T12:00:00.000+03:00")).toThrow("OPERATION_TIMESTAMP_INVALID");
    const target = store();
    expect(() => enqueue(target, { payload: { toJSON: () => ({ api_key: "abcdefghijklmnop" }) } })).toThrow("OPERATION_PAYLOAD_INVALID");
    expect(() => enqueue(target, { payload: { value: Number.NaN } })).toThrow("OPERATION_PAYLOAD_INVALID");
    target.close();
  });

  test("rejects forged cancellation capabilities and persists only a verified cancelling actor", () => {
    const verifier: CancellationCapabilityVerifier = {
      verify(input) {
        if (input.capability !== "approved-capability" || input.scope_id !== scopeA || input.action !== "CANCEL" || input.actor !== "human:owner") return null;
        return { actor: "human:owner", expires_at: "2026-07-24T12:05:00.000Z" };
      },
    };
    const target = store(verifier); const job = enqueue(target); claimAndStart(target, job.job_id);
    expect(() => target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0, capability: "forged", actor: "human:owner" })).toThrow("OPERATION_CANCELLATION_CAPABILITY_INVALID");
    target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0, capability: "approved-capability", actor: "human:owner" });
    const attempt = target.attempts({ scope_id: scopeA, job_id: job.job_id })[0]!;
    expect(attempt.actor).toBe("human:owner");
    expect(JSON.stringify(attempt)).not.toContain("approved-capability");
    target.close();
  });

  test("rejects stack-shaped failure summaries while retaining scope-bound artifact references", () => {
    expect(() => parseOperationFailure({ code: "NETWORK", summary: "Error: boom\n at worker.ts:1", artifact_ref: "artifact:scope:alpha:log-1" })).toThrow("OPERATION_FAILURE_INVALID");
    expect(() => parseOperationFailure({ code: "NETWORK", summary: "tab\tseparated", artifact_ref: "artifact:scope:alpha:log-1" })).toThrow("OPERATION_FAILURE_INVALID");
    expect(parseOperationFailure({ code: "NETWORK", summary: "Request timed out", artifact_ref: "artifact:scope:alpha:log-1" }).artifact_ref).toBe("artifact:scope:alpha:log-1");
  });

  test("rejects failure artifact references outside the job scope", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    expect(() => target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: "artifact:scope:beta:log-1" }, now: t0 })).toThrow("OPERATION_FAILURE_ARTIFACT_SCOPE_INVALID");
    target.close();
  });

  test("preserves dangerous-looking JSON keys and hashes distinct descriptors distinctly", () => {
    const first = canonicalEffectDescriptor(JSON.parse('{"__proto__":"one","constructor":"two","prototype":"three"}'));
    const second = canonicalEffectDescriptor(JSON.parse('{"__proto__":"four","constructor":"two","prototype":"three"}'));
    expect(first.effect["__proto__"]).toBe("one");
    expect(first.effect.constructor).toBe("two");
    expect(first.effect.prototype).toBe("three");
    expect(first.effect_hash).not.toBe(second.effect_hash);
  });

  test("fails closed on tampered durable rows and exposes no persistence columns", () => {
    const target = store(); const job = enqueue(target);
    expect(target.get({ scope_id: scopeA, job_id: job.job_id })).not.toHaveProperty("payload_json");
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET payload_json='{}' WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("fails closed on tampered attempt and receipt columns", () => {
    const target = store(); const failed = enqueue(target); claimAndStart(target, failed.job_id);
    target.fail({ scope_id: scopeA, job_id: failed.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: null }, now: t0 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_attempts SET actor='worker:forged' WHERE scope_id=? AND job_id=?").run(scopeA, failed.job_id);
    expect(() => target.attempts({ scope_id: scopeA, job_id: failed.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    const succeeded = enqueue(target, { idempotency_key: "key:receipt" }); claimAndStart(target, succeeded.job_id);
    target.succeed({ scope_id: scopeA, job_id: succeeded.job_id, owner: "worker:a", effect: { output: "ok" }, now: t0 });
    database.query("UPDATE operation_effect_receipts SET effect_hash='sha256:forged' WHERE scope_id=? AND job_id=?").run(scopeA, succeeded.job_id);
    expect(() => target.effectReceipt({ scope_id: scopeA, job_id: succeeded.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects causally regressing lifecycle times and lease-shortening heartbeats", () => {
    const target = store(); const job = enqueue(target);
    target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 5_000 });
    expect(() => target.heartbeat({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", now: "2026-07-24T11:59:59.999Z", lease_ms: 5_000 })).toThrow("OPERATION_TIME_CAUSALITY_INVALID");
    expect(() => target.heartbeat({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", now: "2026-07-24T12:00:01.000Z", lease_ms: 1_000 })).toThrow("OPERATION_LEASE_SHORTENING_REJECTED");
    target.close();
  });

  test("creates only final scoped tables and records explicit non-retryable failures as FAILED", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    expect(target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "PERMANENT", summary: "Input is invalid", artifact_ref: null }, retryable: false, now: t0 }).state).toBe("FAILED");
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const tables = (database.query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'operation_%' ORDER BY name").all() as Array<{ name: string }>).map(row => row.name);
    expect(tables).toEqual(["operation_attempts", "operation_effect_receipts", "operation_jobs"]);
    database.close(); target.close();
  });

  test("rejects an expired lease owner cancellation but permits a verified capability override", () => {
    const verifier: CancellationCapabilityVerifier = { verify: () => ({ actor: "human:owner", expires_at: "2026-07-24T12:05:00.000Z" }) };
    const target = store(verifier); const job = enqueue(target);
    target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 1_000 });
    const afterLease = "2026-07-24T12:00:01.001Z";
    expect(() => target.cancel({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", now: afterLease })).toThrow("OPERATION_LEASE_EXPIRED");
    expect(target.cancel({ scope_id: scopeA, job_id: job.job_id, capability: "verified", actor: "human:owner", now: afterLease }).state).toBe("CANCELLED");
    target.close();
  });

  test("rejects a cancellation capability that expires exactly at cancellation time", () => {
    const verifier: CancellationCapabilityVerifier = { verify: () => ({ actor: "human:owner", expires_at: t0 }) };
    const target = store(verifier); const job = enqueue(target);
    expect(() => target.cancel({ scope_id: scopeA, job_id: job.job_id, capability: "boundary", actor: "human:owner", now: t0 })).toThrow("OPERATION_CANCELLATION_CAPABILITY_INVALID");
    target.close();
  });

  test("hashes dangerous-key payloads distinctly and detects dangerous-key payload tampering", () => {
    const target = store();
    const first = enqueue(target, { idempotency_key: "key:dangerous-one", payload: JSON.parse('{"__proto__":"one","constructor":"two","prototype":"three"}') });
    const second = enqueue(target, { idempotency_key: "key:dangerous-two", payload: JSON.parse('{"__proto__":"four","constructor":"two","prototype":"three"}') });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const hashes = database.query("SELECT job_id, payload_hash FROM operation_jobs WHERE scope_id=? AND job_id IN (?, ?) ORDER BY job_id").all(scopeA, first.job_id, second.job_id) as Array<{ job_id: string; payload_hash: string }>;
    expect(hashes).toHaveLength(2);
    expect(hashes[0]!.payload_hash).not.toBe(hashes[1]!.payload_hash);
    database.query("UPDATE operation_jobs SET payload_json=? WHERE scope_id=? AND job_id=?").run('{"__proto__":"tampered","constructor":"two","prototype":"three"}', scopeA, first.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: first.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects fractional and negative decoded attempt counts", () => {
    const target = store(); const fractional = enqueue(target, { idempotency_key: "key:fractional" }); const negative = enqueue(target, { idempotency_key: "key:negative" });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET attempt_count=0.5 WHERE scope_id=? AND job_id=?").run(scopeA, fractional.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: fractional.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.exec("PRAGMA ignore_check_constraints=ON");
    database.query("UPDATE operation_jobs SET attempt_count=-1 WHERE scope_id=? AND job_id=?").run(scopeA, negative.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: negative.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects PENDING decoded jobs that retain lease fields", () => {
    const target = store(); const job = enqueue(target); const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET lease_owner='worker:a', lease_expires_at='2026-07-24T12:00:01.000Z', lease_acquired_at=? WHERE scope_id=? AND job_id=?").run(t0, scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects RUNNING decoded jobs without complete lease ownership and timing", () => {
    const target = store(); const job = enqueue(target); const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET state='RUNNING', lease_owner=NULL, lease_expires_at=NULL, lease_acquired_at=NULL, run_started_at=NULL WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects terminal decoded jobs that retain lease fields", () => {
    const target = store(); const job = enqueue(target); const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET state='CANCELLED', lease_owner='worker:a', lease_expires_at='2026-07-24T12:00:01.000Z', lease_acquired_at=?, run_started_at=? WHERE scope_id=? AND job_id=?").run(t0, t0, scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects extra keys in a decoded job row", () => {
    const target = store(); const job = enqueue(target); const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.exec("ALTER TABLE operation_jobs ADD COLUMN injected_job_key TEXT");
    database.query("UPDATE operation_jobs SET injected_job_key='unexpected' WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    database.close(); target.close();
    const reopened = new SqliteOperationsStore({ databasePath: join(roots[0]!, "operations.sqlite") });
    expect(() => reopened.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    reopened.close();
  });

  test("rejects extra keys in a decoded attempt snapshot", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id); target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: null }, now: t0 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const row = database.query("SELECT payload_json FROM operation_attempts WHERE scope_id=? AND job_id=?").get(scopeA, job.job_id) as { payload_json: string };
    const tampered = JSON.parse(row.payload_json) as Record<string, unknown>; tampered.injected_attempt_key = "unexpected";
    database.query("UPDATE operation_attempts SET payload_json=? WHERE scope_id=? AND job_id=?").run(JSON.stringify(tampered), scopeA, job.job_id);
    expect(() => target.attempts({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects extra keys in a decoded receipt snapshot", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id); target.succeed({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", effect: { output: "ok" }, now: t0 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const row = database.query("SELECT payload_json FROM operation_effect_receipts WHERE scope_id=? AND job_id=?").get(scopeA, job.job_id) as { payload_json: string };
    const tampered = JSON.parse(row.payload_json) as Record<string, unknown>; tampered.injected_receipt_key = "unexpected";
    database.query("UPDATE operation_effect_receipts SET payload_json=? WHERE scope_id=? AND job_id=?").run(JSON.stringify(tampered), scopeA, job.job_id);
    expect(() => target.effectReceipt({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects decoded attempt outcome and failure combinations that are impossible", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id); target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: null }, now: t0 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const row = database.query("SELECT payload_json FROM operation_attempts WHERE scope_id=? AND job_id=?").get(scopeA, job.job_id) as { payload_json: string };
    const tampered = JSON.parse(row.payload_json) as Record<string, unknown>; tampered.failure = null;
    database.query("UPDATE operation_attempts SET failure_json=NULL, payload_json=? WHERE scope_id=? AND job_id=?").run(JSON.stringify(tampered), scopeA, job.job_id);
    expect(() => target.attempts({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects read-side attempt artifacts from another scope after consistent JSON tampering", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id); target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: "artifact:scope:alpha:log-1" }, now: t0 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    const row = database.query("SELECT payload_json FROM operation_attempts WHERE scope_id=? AND job_id=?").get(scopeA, job.job_id) as { payload_json: string };
    const tampered = JSON.parse(row.payload_json) as { failure: { artifact_ref: string } }; tampered.failure.artifact_ref = "artifact:scope:beta:log-1";
    const failure = { code: "NETWORK", summary: "Request timed out", artifact_ref: "artifact:scope:beta:log-1" };
    database.query("UPDATE operation_attempts SET failure_json=?, payload_json=? WHERE scope_id=? AND job_id=?").run(JSON.stringify(failure), JSON.stringify(tampered), scopeA, job.job_id);
    expect(() => target.attempts({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects causal time regression for pending and retry-pending cancellation and persists the verified actor", () => {
    const verifier: CancellationCapabilityVerifier = { verify: () => ({ actor: "human:owner", expires_at: "2026-07-24T12:05:00.000Z" }) };
    const target = store(verifier); const pending = enqueue(target, { idempotency_key: "key:pending-cancel" });
    expect(() => target.cancel({ scope_id: scopeA, job_id: pending.job_id, capability: "verified", actor: "human:owner", now: "2026-07-24T11:59:59.999Z" })).toThrow("OPERATION_TIME_CAUSALITY_INVALID");
    target.cancel({ scope_id: scopeA, job_id: pending.job_id, capability: "verified", actor: "human:owner", now: t0 });
    expect(target.attempts({ scope_id: scopeA, job_id: pending.job_id })[0]?.actor).toBe("human:owner");
    const retry = enqueue(target, { idempotency_key: "key:retry-cancel" }); claimAndStart(target, retry.job_id);
    target.fail({ scope_id: scopeA, job_id: retry.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "Request timed out", artifact_ref: null }, now: "2026-07-24T12:00:00.001Z" });
    expect(() => target.cancel({ scope_id: scopeA, job_id: retry.job_id, capability: "verified", actor: "human:owner", now: t0 })).toThrow("OPERATION_TIME_CAUSALITY_INVALID");
    target.cancel({ scope_id: scopeA, job_id: retry.job_id, capability: "verified", actor: "human:owner", now: "2026-07-24T12:00:00.001Z" });
    expect(target.attempts({ scope_id: scopeA, job_id: retry.job_id })[1]?.actor).toBe("human:owner");
    target.close();
  });

  test("rejects active leases whose expiry is before or equal to acquisition", () => {
    const target = store(); const equal = enqueue(target, { idempotency_key: "key:lease-expiry-equal" }); const before = enqueue(target, { idempotency_key: "key:lease-expiry-before" });
    target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 5_000 });
    target.claim({ scope_id: scopeA, owner: "worker:b", now: t0, lease_ms: 5_000 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET lease_expires_at=? WHERE scope_id=? AND job_id=?").run(t0, scopeA, equal.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: equal.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.query("UPDATE operation_jobs SET lease_expires_at='2026-07-24T11:59:59.999Z' WHERE scope_id=? AND job_id=?").run(scopeA, before.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: before.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects active leases acquired after their updated time", () => {
    const target = store(); const job = enqueue(target); target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 5_000 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET lease_acquired_at='2026-07-24T12:00:00.001Z' WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects RUNNING jobs started after their updated time", () => {
    const target = store(); const job = enqueue(target); claimAndStart(target, job.job_id);
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET run_started_at='2026-07-24T12:00:00.001Z' WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });

  test("rejects active leases whose expiry is at or before their updated time", () => {
    const target = store(); const job = enqueue(target); target.claim({ scope_id: scopeA, owner: "worker:a", now: t0, lease_ms: 5_000 });
    const database = new Database(join(roots[0]!, "operations.sqlite"));
    database.query("UPDATE operation_jobs SET updated_at='2026-07-24T12:00:00.001Z', lease_expires_at='2026-07-24T12:00:00.001Z' WHERE scope_id=? AND job_id=?").run(scopeA, job.job_id);
    expect(() => target.get({ scope_id: scopeA, job_id: job.job_id })).toThrow("OPERATION_PERSISTENCE_TAMPERED");
    database.close(); target.close();
  });
});
