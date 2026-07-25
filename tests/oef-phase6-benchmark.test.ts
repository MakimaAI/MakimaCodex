import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const now = "2026-07-25T12:00:00.000Z";
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function lesson(id: string, summary: string, repository = "opencodex") {
  return api.createMemoryRecord({
    memory_id: id, layer: "LESSON", kind: "opencodex.lesson.failure-pattern",
    scopes: [{ type: "REPOSITORY", id: repository }], subject: { type: "failure", key: id },
    content: { summary }, lifecycle: { status: "VERIFIED" }, trust: { level: "HIGH", confidence: 0.97 },
    temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: now },
    provenance: { source_refs: [`evidence:${id}`], extractor_ref: null },
    relations: { supersedes: [], contradicts: [], derived_from: [] },
    access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer"] }, retention: { policy: "repository-durable" },
    created_at: now, created_by: { type: "verifier", id: "verifier:benchmark" },
  });
}

function query(id: string, text: string) {
  return {
    query_id: id, text,
    requester: { role: "backend-implementer", authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }], max_sensitivity: "INTERNAL" },
    scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }] }, layers: { include: ["LESSON"] }, trust: { minimum: "MEDIUM" },
    temporal: { at: now }, budget: { max_tokens: 1_000, max_records: 3 }, usage_mode: "CLI_RESEARCH", explain: true,
  };
}

describe("Phase 6 retrieval benchmark", () => {
  test("measures precision, verified precision, citations, and leakage from real context packs", async () => {
    expect(typeof api.runMemoryRetrievalBenchmark).toBe("function");
    const root = mkdtempSync(join(tmpdir(), "phase6-benchmark-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    const auth = lesson("memory:auth-403", "ClinePass HTTP 403 permission authorization failure");
    const timeout = lesson("memory:socket-timeout", "Socket timeout requires bounded exponential retry");
    const hidden = lesson("memory:hidden-project", "ClinePass HTTP 403 permission authorization failure", "private-other");
    store.create(auth); store.create(timeout); store.create(hidden);
    const report = await api.runMemoryRetrievalBenchmark({
      engine: new api.MemoryRetrievalEngine({ store }),
      cases: [
        { case_id: "auth", query: query("memory-query:benchmark-auth", "ClinePass HTTP 403 permission authorization"), relevant_memory_ids: [auth.memory_id], forbidden_memory_ids: [hidden.memory_id] },
        { case_id: "timeout", query: query("memory-query:benchmark-timeout", "Socket timeout bounded exponential retry"), relevant_memory_ids: [timeout.memory_id], forbidden_memory_ids: [hidden.memory_id] },
      ],
    });
    expect(report).toMatchObject({
      cases: 2,
      retrieval_precision: 1,
      verified_memory_precision: 1,
      citation_completeness: 1,
      cross_scope_leakage: 0,
      secret_leakage: 0,
      passed: true,
    });
    store.close();
  });
});
