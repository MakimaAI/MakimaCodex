import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as operations from "../src/oef/operations";

const roots: string[] = [];
const t0 = "2026-07-24T12:00:00.000Z";
const api = operations as Record<string, any>;

afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function store() {
  const root = mkdtempSync(join(tmpdir(), "oef-operations-")); roots.push(root);
  return new api.SqliteOperationsStore({ databasePath: join(root, "operations.sqlite") });
}

function enqueue(target: any, overrides: Record<string, unknown> = {}) {
  return target.enqueue({
    kind: "opencodex.operation.test",
    idempotency_key: "key:one",
    payload: { subject: "safe" },
    priority: 10,
    max_attempts: 3,
    now: t0,
    ...overrides,
  });
}

describe("durable operations", () => {
  test("defines only the strict durable job states", () => {
    expect(api.JOB_STATES).toEqual(["PENDING", "LEASED", "RUNNING", "RETRY_PENDING", "SUCCEEDED", "FAILED", "DEAD_LETTER", "CANCELLED"]);
    expect(() => api.jobStateSchema.parse("UNKNOWN")).toThrow();
  });

  test("persists idempotent enqueue across a restart without duplicating a job", () => {
    const first = store();
    const job = enqueue(first);
    const duplicate = enqueue(first, { payload: { subject: "ignored when idempotent" } });
    expect(duplicate.job_id).toBe(job.job_id);
    first.close();

    const reopened = new api.SqliteOperationsStore({ databasePath: join(roots[0]!, "operations.sqlite") });
    expect(enqueue(reopened).job_id).toBe(job.job_id);
    expect(reopened.list()).toHaveLength(1);
    reopened.close();
  });

  test("claims highest priority work and permits takeover only after lease expiry", () => {
    const target = store();
    const low = enqueue(target, { idempotency_key: "key:low", priority: 1 });
    const high = enqueue(target, { idempotency_key: "key:high", priority: 9 });
    const claimed = target.claim({ owner: "worker:a", now: t0, lease_ms: 1_000 });
    expect(claimed?.job_id).toBe(high.job_id);
    expect(target.claim({ owner: "worker:b", now: "2026-07-24T12:00:00.500Z", lease_ms: 1_000 })?.job_id).toBe(low.job_id);
    expect(target.claim({ owner: "worker:b", now: "2026-07-24T12:00:00.750Z", lease_ms: 1_000 })).toBeNull();
    expect(target.claim({ owner: "worker:b", now: "2026-07-24T12:00:01.001Z", lease_ms: 1_000 })?.job_id).toBe(high.job_id);
    target.close();
  });

  test("requires the exact lease owner for heartbeat and start", () => {
    const target = store(); const job = enqueue(target);
    target.claim({ owner: "worker:a", now: t0, lease_ms: 1_000 });
    expect(() => target.heartbeat({ job_id: job.job_id, owner: "worker:b", now: t0, lease_ms: 1_000 })).toThrow("OPERATION_LEASE_OWNER_MISMATCH");
    expect(target.heartbeat({ job_id: job.job_id, owner: "worker:a", now: "2026-07-24T12:00:00.500Z", lease_ms: 2_000 }).state).toBe("LEASED");
    expect(() => target.start({ job_id: job.job_id, owner: "worker:b", now: t0 })).toThrow("OPERATION_LEASE_OWNER_MISMATCH");
    expect(target.start({ job_id: job.job_id, owner: "worker:a", now: t0 }).state).toBe("RUNNING");
    target.close();
  });

  test("writes an exactly-once effect receipt and fails closed on an effect conflict", () => {
    const target = store(); const job = enqueue(target);
    target.claim({ owner: "worker:a", now: t0, lease_ms: 1_000 }); target.start({ job_id: job.job_id, owner: "worker:a", now: t0 });
    const succeeded = target.succeed({ job_id: job.job_id, owner: "worker:a", effect_hash: "sha256:effect-a", now: t0 });
    expect(succeeded.state).toBe("SUCCEEDED");
    expect(target.succeed({ job_id: job.job_id, owner: "worker:a", effect_hash: "sha256:effect-a", now: t0 }).state).toBe("SUCCEEDED");
    expect(target.effectReceipt(job.job_id)?.effect_hash).toBe("sha256:effect-a");
    expect(() => target.succeed({ job_id: job.job_id, owner: "worker:a", effect_hash: "sha256:effect-b", now: t0 })).toThrow("OPERATION_EFFECT_RECEIPT_CONFLICT");
    target.close();
  });

  test("records immutable attempts with deterministic exponential retry backoff and dead-letters at the limit", () => {
    const target = store(); const job = enqueue(target, { max_attempts: 2 });
    target.claim({ owner: "worker:a", now: t0, lease_ms: 5_000 }); target.start({ job_id: job.job_id, owner: "worker:a", now: t0 });
    const retry = target.fail({ job_id: job.job_id, owner: "worker:a", error: "network", now: t0, base_backoff_ms: 1_000 });
    expect(retry.state).toBe("RETRY_PENDING");
    expect(retry.available_at).toBe("2026-07-24T12:00:01.000Z");
    target.claim({ owner: "worker:a", now: retry.available_at, lease_ms: 5_000 }); target.start({ job_id: job.job_id, owner: "worker:a", now: retry.available_at });
    expect(target.fail({ job_id: job.job_id, owner: "worker:a", error: "network", now: retry.available_at, base_backoff_ms: 1_000 }).state).toBe("DEAD_LETTER");
    expect(target.attempts(job.job_id)).toHaveLength(2);
    target.close();
  });

  test("cancels terminally and reconciles expired running leases without losing attempts", () => {
    const target = store(); const job = enqueue(target);
    expect(target.cancel({ job_id: job.job_id, now: t0 }).state).toBe("CANCELLED");
    expect(target.cancel({ job_id: job.job_id, now: t0 }).state).toBe("CANCELLED");
    const leased = enqueue(target, { idempotency_key: "key:expired" });
    target.claim({ owner: "worker:a", now: t0, lease_ms: 1_000 });
    target.start({ job_id: leased.job_id, owner: "worker:a", now: t0 });
    expect(target.reconcileExpired({ now: "2026-07-24T12:00:01.001Z", base_backoff_ms: 1_000 })).toBe(1);
    expect(target.get(leased.job_id)?.state).toBe("RETRY_PENDING");
    expect(target.attempts(leased.job_id)).toHaveLength(1);
    target.close();
  });

  test("rejects malformed timestamps, unsafe owners, obvious secrets, and illegal terminal transitions", () => {
    const target = store();
    expect(() => enqueue(target, { now: "not-a-timestamp" })).toThrow("OPERATION_TIMESTAMP_INVALID");
    expect(() => enqueue(target, { payload: { api_key: "abcdefghijklmnop" } })).toThrow("OPERATION_PAYLOAD_SECRET_REJECTED");
    const circular: Record<string, unknown> = {}; circular.self = circular;
    expect(() => enqueue(target, { payload: circular })).toThrow("OPERATION_PAYLOAD_INVALID");
    const job = enqueue(target);
    expect(() => target.claim({ owner: "", now: t0, lease_ms: 1_000 })).toThrow("OPERATION_OWNER_INVALID");
    target.cancel({ job_id: job.job_id, now: t0 });
    expect(() => target.start({ job_id: job.job_id, owner: "worker:a", now: t0 })).toThrow("OPERATION_STATE_TRANSITION_INVALID");
    target.close();
  });
});
