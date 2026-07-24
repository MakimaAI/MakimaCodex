import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  JOB_STATES, SqliteOperationsStore, assertOperationTimestamp, canonicalEffectDescriptor, leaseExpiry,
  jobStateSchema, parseOperationFailure, retryAvailableAt, type FailureDetails, type RetryPolicy,
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

function store(): SqliteOperationsStore {
  const root = mkdtempSync(join(tmpdir(), "oef-operations-")); roots.push(root);
  return new SqliteOperationsStore({ databasePath: join(root, "operations.sqlite") });
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
    expect(() => target.cancel({ scope_id: scopeB, job_id: alpha.job_id, now: t0, cancellation_authority: { scope_id: scopeB, authority_id: "admin:b" } })).toThrow("OPERATION_NOT_FOUND");
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
    expect(target.cancel({ scope_id: scopeA, job_id: job.job_id, now: t0, cancellation_authority: { scope_id: scopeA, authority_id: "admin:a" } }).state).toBe("CANCELLED");
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
    expect(target.fail({ scope_id: scopeA, job_id: failed.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "temporary network failure", artifact_ref: "artifact:network-1" }, now: t0 }).available_at).toBe("2026-07-24T12:00:00.500Z");
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
    target.fail({ scope_id: scopeA, job_id: job.job_id, owner: "worker:a", failure: { code: "NETWORK", summary: "connection timed out", artifact_ref: "artifact:log-1" }, now: t0 });
    expect(target.attempts({ scope_id: scopeA, job_id: job.job_id })[0]?.failure).toEqual({ code: "NETWORK", summary: "connection timed out", artifact_ref: "artifact:log-1" });
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
});
