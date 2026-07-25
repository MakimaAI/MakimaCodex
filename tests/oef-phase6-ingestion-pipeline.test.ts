import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const observedAt = "2026-07-25T08:00:00.000Z";

afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function openStore(label: string) {
  const root = mkdtempSync(join(tmpdir(), `phase6-${label}-`));
  roots.push(root);
  const databasePath = join(root, "memory.sqlite");
  return { root, databasePath, store: new api.SqliteMemoryStore({ databasePath }) };
}

function sourceEvent(overrides: Record<string, unknown> = {}) {
  return {
    schema_version: 1,
    event_id: "event:phase2-task-142-attempt-1",
    idempotency_key: "phase2:task-142:attempt-1:verification-failed",
    source: { phase: 2, kind: "execution.evidence", ref: "evidence:task-142-attempt-1" },
    scopes: [{ type: "TASK", id: "task-142" }, { type: "REPOSITORY", id: "opencodex" }],
    subject: { type: "task-attempt", key: "task-142-attempt-1" },
    summary: "Task 142 attempt 1 misclassified HTTP 403 and failed verification.",
    structured: { status_code: 403, classification: "quota" },
    evidence_refs: ["artifact:test-output-403", "finding:confirmed-403"],
    sensitivity: "INTERNAL",
    observed_at: observedAt,
    ...overrides,
  };
}

describe("Phase 6 durable ingestion pipeline", () => {
  test("redacts before durable enqueue and deduplicates the source event after restart", () => {
    expect(typeof api.createMemorySourceEvent).toBe("function");
    expect(typeof api.DurableMemoryIngestionQueue).toBe("function");
    const { databasePath, store } = openStore("queue-dedup");
    const queue = new api.DurableMemoryIngestionQueue(store);
    const event = api.createMemorySourceEvent(sourceEvent({
      summary: "HTTP 403 Authorization: Bearer abcdefghijklmnop",
      structured: { api_key: "sk-proj-1234567890abcdef", status_code: 403 },
    }));

    expect(JSON.stringify(event)).not.toContain("abcdefghijklmnop");
    expect(JSON.stringify(event)).not.toContain("sk-proj-1234567890abcdef");
    const first = queue.enqueue(event, { priority: 20, max_attempts: 3, at: observedAt });
    const duplicate = queue.enqueue(event, { priority: 20, max_attempts: 3, at: observedAt });
    expect(duplicate).toEqual({ ...first, deduplicated: true });
    store.close();

    const reopened = new api.SqliteMemoryStore({ databasePath });
    try {
      const afterRestart = new api.DurableMemoryIngestionQueue(reopened).enqueue(event, { priority: 20, max_attempts: 3, at: observedAt });
      expect(afterRestart.job_id).toBe(first.job_id);
      expect(afterRestart.deduplicated).toBeTrue();
      expect(JSON.stringify(reopened.inspectIngestionJob(first.job_id))).not.toContain("sk-proj-1234567890abcdef");
    } finally { reopened.close(); }
  });

  test("recovers an expired lease and dead-letters only after the configured attempt limit", () => {
    const { store } = openStore("lease-recovery");
    try {
      const queue = new api.DurableMemoryIngestionQueue(store);
      const queued = queue.enqueue(api.createMemorySourceEvent(sourceEvent()), { priority: 10, max_attempts: 2, at: observedAt });
      const first = queue.claim({ worker_id: "worker:a", now: observedAt, lease_ms: 1_000 });
      expect(first).toMatchObject({ job_id: queued.job_id, status: "LEASED", lease_owner: "worker:a", attempt_count: 1 });
      expect(queue.claim({ worker_id: "worker:b", now: "2026-07-25T08:00:00.500Z", lease_ms: 1_000 })).toBeNull();

      const recovered = queue.claim({ worker_id: "worker:b", now: "2026-07-25T08:00:01.001Z", lease_ms: 1_000 });
      expect(recovered).toMatchObject({ job_id: queued.job_id, lease_owner: "worker:b", attempt_count: 2 });
      const terminal = queue.fail({
        job_id: queued.job_id,
        worker_id: "worker:b",
        lease_token: recovered.lease_token,
        at: "2026-07-25T08:00:01.100Z",
        error: { code: "EXTRACTOR_POISON", message: "unsupported payload" },
      });
      expect(terminal).toMatchObject({ status: "DEAD_LETTER", attempt_count: 2 });
      expect(queue.claim({ worker_id: "worker:c", now: "2026-07-25T09:00:00.000Z", lease_ms: 1_000 })).toBeNull();
    } finally { store.close(); }
  });

  test("fences a stale attempt even when the same worker id reacquires the lease", () => {
    const { store } = openStore("lease-fencing");
    try {
      const queue = new api.DurableMemoryIngestionQueue(store);
      queue.enqueue(api.createMemorySourceEvent(sourceEvent()), { priority: 10, max_attempts: 3, at: observedAt });
      const first = queue.claim({ worker_id: "worker:same", now: observedAt, lease_ms: 1_000 });
      const second = queue.claim({ worker_id: "worker:same", now: "2026-07-25T08:00:01.001Z", lease_ms: 1_000 });
      expect(second.lease_token).not.toBe(first.lease_token);
      expect(() => queue.complete({
        job_id: first.job_id, worker_id: "worker:same", lease_token: first.lease_token,
        at: "2026-07-25T08:00:01.100Z", output_memory_ids: ["memory:stale-output"],
      })).toThrow("MEMORY_JOB_LEASE_MISMATCH");
      expect(queue.complete({
        job_id: second.job_id, worker_id: "worker:same", lease_token: second.lease_token,
        at: "2026-07-25T08:00:01.100Z", output_memory_ids: ["memory:fresh-output"],
      })).toMatchObject({ status: "COMPLETED", output_memory_ids: ["memory:fresh-output"] });
    } finally { store.close(); }
  });

  test("a failed job does not lock the queue and a later event compiles into an observed episode", () => {
    const { store } = openStore("worker-continue");
    try {
      const queue = new api.DurableMemoryIngestionQueue(store);
      queue.enqueue(api.createMemorySourceEvent(sourceEvent({
        event_id: "event:poison",
        idempotency_key: "poison",
        source: { phase: 2, kind: "unsupported.event", ref: "evidence:poison" },
      })), { priority: 20, max_attempts: 1, at: observedAt });
      queue.enqueue(api.createMemorySourceEvent(sourceEvent({
        event_id: "event:good",
        idempotency_key: "good",
      })), { priority: 10, max_attempts: 2, at: observedAt });
      const worker = new api.MemoryIngestionWorker({ store, queue, compiler: new api.MemoryEpisodeCompiler() });

      expect(worker.runOnce({ worker_id: "worker:one", now: observedAt, lease_ms: 5_000 })).toMatchObject({ status: "DEAD_LETTER" });
      const completed = worker.runOnce({ worker_id: "worker:one", now: "2026-07-25T08:00:01.000Z", lease_ms: 5_000 });
      expect(completed).toMatchObject({ status: "COMPLETED" });
      const episode = store.get(completed.memory_ids[0]);
      expect(episode).toMatchObject({ layer: "EPISODE", lifecycle: { status: "OBSERVED" } });
      expect(episode.provenance.source_refs).toEqual(expect.arrayContaining(["artifact:test-output-403", "finding:confirmed-403"]));
      expect(episode.content.summary).not.toContain("raw_tool_output");
    } finally { store.close(); }
  });

  test("promotes a lesson candidate only through a verifier or human evidence gate", () => {
    const { store } = openStore("promotion");
    try {
      const service = new api.MemoryCandidateService(store);
      const candidate = service.propose({
        candidate_id: "memory-candidate:lesson-403",
        idempotency_key: "lesson:clinepass:v3:403",
        layer: "LESSON",
        kind: "opencodex.lesson.failure-pattern",
        scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "PROVIDER", id: "clinepass" }],
        subject: { type: "error-classification", key: "http-403" },
        summary: "ClinePass provider v3 treats HTTP 403 as authorization or permission failure, never quota.",
        structured: { status_code: 403, provider_version: 3 },
        evidence_refs: ["evidence:test-403-v3"],
        derived_from: ["memory:episode-task-142-attempt-1"],
        access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer", "reviewer"] },
        retention_policy: "repository-durable",
        proposed_by: { type: "agent", id: "agent:lesson-extractor" },
        proposed_at: observedAt,
      });
      expect(candidate.status).toBe("CANDIDATE");
      expect(() => service.promote(candidate.candidate_id, {
        actor: { type: "agent", id: "agent:self-promoter" },
        evidence_refs: ["finding:verified-resolved"],
        at: "2026-07-25T08:10:00.000Z",
      })).toThrow("MEMORY_PROMOTION_ACTOR_UNAUTHORIZED");
      expect(() => service.promote(candidate.candidate_id, {
        actor: { type: "verifier", id: "verifier:phase3" }, evidence_refs: [], at: "2026-07-25T08:10:00.000Z",
      })).toThrow("MEMORY_PROMOTION_EVIDENCE_REQUIRED");

      const promoted = service.promote(candidate.candidate_id, {
        actor: { type: "verifier", id: "verifier:phase3" },
        evidence_refs: ["finding:verified-resolved", "documentation:clinepass-v3"],
        at: "2026-07-25T08:10:00.000Z",
      });
      expect(promoted.record).toMatchObject({ layer: "LESSON", lifecycle: { status: "VERIFIED" }, created_by: { type: "verifier" } });
      expect(promoted.record.provenance.source_refs).toEqual(expect.arrayContaining([
        "evidence:test-403-v3", "finding:verified-resolved", "documentation:clinepass-v3",
      ]));
      expect(service.list({ status: "PROMOTED" })).toHaveLength(1);
      expect(() => service.promote(candidate.candidate_id, {
        actor: { type: "verifier", id: "verifier:phase3" }, evidence_refs: ["evidence:again"], at: "2026-07-25T08:11:00.000Z",
      })).toThrow("MEMORY_CANDIDATE_ALREADY_DECIDED");
    } finally { store.close(); }
  });
});
