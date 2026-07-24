import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const now = "2026-07-24T12:00:00.000Z";

afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function rawInput(summary: string, structured: Record<string, unknown> = {}) {
  return {
    memory_id: "memory:sensitive-ingestion",
    layer: "OBSERVED" === "OBSERVED" ? "EPISODE" : "EPISODE",
    kind: "opencodex.episode.execution",
    scopes: [{ type: "REPOSITORY", id: "opencodex" }],
    subject: { type: "task-attempt", key: "secret-redaction" },
    content: { summary, structured },
    lifecycle: { status: "OBSERVED" },
    trust: { level: "LOW", confidence: 0.5 },
    temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: null },
    provenance: { source_refs: ["event:secret-redaction"], extractor_ref: null },
    relations: { supersedes: [], contradicts: [], derived_from: [] },
    access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer"] },
    retention: { policy: "task-history" },
    created_at: now,
    created_by: { type: "system", id: "system:memory-pipeline" },
  };
}

describe("Phase 6 security and forgetting", () => {
  test("requires redaction before canonical record creation", () => {
    expect(typeof api.sanitizeMemoryRecordInput).toBe("function");
    const unsafe = rawInput("Provider returned Authorization: Bearer sk-proj-1234567890abcdef", {
      api_key: "sk-proj-1234567890abcdef",
    });
    expect(() => api.createMemoryRecord(unsafe)).toThrow("MEMORY_SECRET_CONTENT_FORBIDDEN");

    const sanitized = api.sanitizeMemoryRecordInput(unsafe);
    const record = api.createMemoryRecord(sanitized);
    expect(JSON.stringify(record.content)).not.toContain("sk-proj-1234567890abcdef");
    expect(record.content.summary).toContain("[REDACTED]");
    expect(record.content.structured.api_key).toBe("[REDACTED]");
  });

  test("hard delete removes recallable content, derived packs, and leaves a non-sensitive tombstone", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-forget-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(rawInput("Safe historical episode."));
      store.create(record);
      const queryId = "memory-query:delete-projection";
      await new api.MemoryRetrievalEngine({ store }).recall({
        query_id: queryId,
        text: "historical episode",
        requester: { role: "backend-implementer", authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }], max_sensitivity: "INTERNAL" },
        scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }] },
        layers: { include: ["EPISODE"] },
        trust: { minimum: "LOW" },
        temporal: { at: now },
        budget: { max_tokens: 800, max_records: 4 },
      });
      expect(store.explainQuery(queryId)).not.toBeNull();
      store.forget(record.memory_id, { mode: "HARD_DELETE", reason: "owner-requested hard delete", at: now });

      expect(store.get(record.memory_id)).toBeNull();
      expect(store.explainQuery(queryId)).toBeNull();
      expect(store.lexicalSearch({
        text: "historical episode",
        scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        layers: ["EPISODE"],
        role: "backend-implementer",
        max_sensitivity: "INTERNAL",
        minimum_trust: "LOW",
        at: now,
        limit: 10,
      })).toHaveLength(0);
      expect(() => store.create(record)).toThrow("MEMORY_ID_TOMBSTONED");
    } finally {
      store.close();
    }
  });
});
