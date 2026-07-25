import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const now = "2026-07-25T13:00:00.000Z";
afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

describe("Phase 6 deterministic property invariants", () => {
  test("preserves one current revision, idempotent ingestion, and no recall after forgetting", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-properties-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    const queue = new api.DurableMemoryIngestionQueue(store);
    for (let index = 0; index < 40; index += 1) {
      const event = api.createMemorySourceEvent({
        schema_version: 1, event_id: `event:property-${index % 10}`, idempotency_key: `property-${index % 10}`,
        source: { phase: 2, kind: "execution.evidence", ref: `evidence:property-${index % 10}` },
        scopes: [{ type: "REPOSITORY", id: "opencodex" }], subject: { type: "attempt", key: `attempt-${index % 10}` },
        summary: `Property episode ${index % 10}`, evidence_refs: [`artifact:property-${index % 10}`], sensitivity: "INTERNAL", observed_at: now,
      });
      const result = queue.enqueue(event, { priority: 1, max_attempts: 2, at: now });
      if (index >= 10) expect(result.deduplicated).toBeTrue();
    }
    let processed = 0;
    const worker = new api.MemoryIngestionWorker({ store, queue, compiler: new api.MemoryEpisodeCompiler() });
    while (worker.runOnce({ worker_id: "worker:property", now, lease_ms: 1_000 })) processed += 1;
    expect(processed).toBe(10);
    expect(store.listCurrentRecords()).toHaveLength(10);

    const forgotten = store.listCurrentRecords()[0];
    store.forget(forgotten.memory_id, { mode: "HARD_DELETE", reason: "property invariant", at: now });
    const pack = await new api.MemoryRetrievalEngine({ store }).recall({
      query_id: "memory-query:property", text: forgotten.content.summary,
      requester: { role: "any-role", authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }], max_sensitivity: "INTERNAL" },
      scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }] }, layers: { include: ["EPISODE"] }, trust: { minimum: "LOW" },
      temporal: { at: now }, budget: { max_tokens: 1_000, max_records: 20 }, usage_mode: "CLI_RESEARCH", explain: true,
    });
    expect(pack.provenance.memory_revisions).not.toContain(forgotten.revision_id);
    expect(store.getTombstone(forgotten.memory_id)).toMatchObject({ content_retained: false });
    store.close();
  });
});
