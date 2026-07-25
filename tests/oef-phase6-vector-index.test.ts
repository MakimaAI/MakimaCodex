import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const now = "2026-07-25T09:00:00.000Z";

afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function memory(id: string, summary: string, sensitivity = "INTERNAL") {
  return api.createMemoryRecord({
    memory_id: id,
    layer: "LESSON",
    kind: "opencodex.lesson.failure-pattern",
    scopes: [{ type: "REPOSITORY", id: "opencodex" }],
    subject: { type: "failure", key: id },
    content: { summary },
    lifecycle: { status: "VERIFIED" },
    trust: { level: "HIGH", confidence: 0.95 },
    temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: now },
    provenance: { source_refs: [`evidence:${id}`], extractor_ref: null },
    relations: { supersedes: [], contradicts: [], derived_from: [] },
    access: { sensitivity, read_roles: ["backend-implementer"] },
    retention: { policy: "repository-durable" },
    created_at: now,
    created_by: { type: "verifier", id: "verifier:test" },
  });
}

function profile(version = "1.0.0") {
  return {
    id: "memory-local-hash",
    version,
    dimensions: 64,
    provider: "LOCAL_DETERMINISTIC",
    max_sensitivity: "CONFIDENTIAL",
  };
}

describe("Phase 6 versioned local vector index", () => {
  test("rebuilds from canonical current revisions and remains searchable after restart", async () => {
    expect(typeof api.LocalHashEmbeddingProvider).toBe("function");
    expect(typeof api.SqliteVectorMemoryIndex).toBe("function");
    const root = mkdtempSync(join(tmpdir(), "phase6-vector-restart-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    const store = new api.SqliteMemoryStore({ databasePath });
    const auth = memory("memory:authorization", "HTTP 403 permission authorization failure for provider v3");
    const timeout = memory("memory:timeout", "Socket timeout requires bounded exponential retry");
    store.create(auth); store.create(timeout); store.close();

    let index = new api.SqliteVectorMemoryIndex({
      databasePath,
      provider: new api.LocalHashEmbeddingProvider(profile()),
    });
    const rebuilt = await index.rebuild({ at: now });
    expect(rebuilt).toMatchObject({ indexed_records: 2, skipped_restricted: 0, profile: { version: "1.0.0" } });
    expect(index.status()).toMatchObject({ status: "HEALTHY", indexed_records: 2, profile: { version: "1.0.0" } });
    const firstHits = await index.search({
      text: "403 authorization permission",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      layers: ["LESSON"],
      limit: 2,
    });
    expect(firstHits[0]).toMatchObject({ revision_id: auth.revision_id });
    index.close();

    index = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(profile()) });
    try {
      expect((await index.search({
        text: "socket timeout retry",
        scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        layers: ["LESSON"],
        limit: 1,
      }))[0]).toMatchObject({ revision_id: timeout.revision_id });
    } finally { index.close(); }
  });

  test("atomically preserves the active generation when re-embedding fails", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-vector-atomic-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    const store = new api.SqliteMemoryStore({ databasePath });
    store.create(memory("memory:stable", "stable authorization guidance"));
    store.close();

    const stable = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(profile("1.0.0")) });
    await stable.rebuild({ at: now });
    const activeBefore = stable.status().generation_id;
    stable.close();

    class FailingProvider {
      profile = profile("2.0.0");
      private failNext = true;
      private readonly fallback = new api.LocalHashEmbeddingProvider(this.profile);
      embed(text: string): number[] {
        if (this.failNext) {
          this.failNext = false;
          throw new Error("EMBEDDING_PROVIDER_DOWN");
        }
        return this.fallback.embed(text);
      }
    }
    const failing = new api.SqliteVectorMemoryIndex({ databasePath, provider: new FailingProvider() });
    await expect(failing.rebuild({ at: "2026-07-25T09:10:00.000Z" })).rejects.toThrow("EMBEDDING_PROVIDER_DOWN");
    expect(failing.status()).toMatchObject({ status: "HEALTHY", generation_id: activeBefore, profile: { version: "1.0.0" } });
    failing.close();
    const recovered = new api.SqliteVectorMemoryIndex({ databasePath });
    expect((await recovered.search({
      text: "stable authorization",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      layers: ["LESSON"],
      limit: 1,
    }))).toHaveLength(1);
    recovered.close();
  });

  test("does not embed records above the profile sensitivity ceiling", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-vector-policy-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    const store = new api.SqliteMemoryStore({ databasePath });
    store.create(memory("memory:internal", "publicly indexable permission guidance"));
    store.create(memory("memory:restricted", "restricted incident details", "RESTRICTED"));
    store.close();
    const index = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(profile()) });
    try {
      expect(await index.rebuild({ at: now })).toMatchObject({ indexed_records: 1, skipped_restricted: 1 });
      const hits = await index.search({
        text: "restricted incident details",
        scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        layers: ["LESSON"],
        limit: 10,
      });
      expect(hits.some((hit: { revision_id: string }) => hit.revision_id.includes("restricted"))).toBeFalse();
      expect(index.status()).toMatchObject({ skipped_restricted: 1 });
    } finally { index.close(); }
  });

  test("loads the active local profile after restart and rejects an explicitly mismatched provider", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-vector-profile-drift-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    const store = new api.SqliteMemoryStore({ databasePath });
    const stored = memory("memory:profile-drift", "profile drift authorization guidance");
    store.create(stored); store.close();
    const activeProfile = { ...profile("3.0.0"), dimensions: 128 };
    let index = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(activeProfile) });
    await index.rebuild({ at: now });
    index.close();

    index = new api.SqliteVectorMemoryIndex({ databasePath });
    expect(index.status()).toMatchObject({ profile: { version: "3.0.0", dimensions: 128 } });
    expect((await index.search({
      text: "profile drift authorization",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      layers: ["LESSON"],
      limit: 1,
    }))[0]).toMatchObject({ revision_id: stored.revision_id });
    index.close();

    const mismatched = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(profile("1.0.0")) });
    await expect(mismatched.search({
      text: "profile drift authorization",
      scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      layers: ["LESSON"],
      limit: 1,
    })).rejects.toThrow("MEMORY_EMBEDDING_PROFILE_MISMATCH");
    mismatched.close();
  });

  test("does not activate a generation when canonical revisions change during embedding", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-vector-concurrent-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    const store = new api.SqliteMemoryStore({ databasePath });
    store.create(memory("memory:first", "first authorization record"));
    let release!: () => void;
    let started!: () => void;
    const startedPromise = new Promise<void>(resolve => { started = resolve; });
    const releasePromise = new Promise<void>(resolve => { release = resolve; });
    const base = new api.LocalHashEmbeddingProvider(profile());
    class PausingProvider {
      profile = profile();
      private first = true;
      async embed(text: string): Promise<number[]> {
        if (this.first) { this.first = false; started(); await releasePromise; }
        return base.embed(text);
      }
    }
    const index = new api.SqliteVectorMemoryIndex({ databasePath, provider: new PausingProvider() });
    const rebuilding = index.rebuild({ at: now });
    await startedPromise;
    store.create(memory("memory:second", "second timeout record"));
    release();
    await expect(rebuilding).rejects.toThrow("MEMORY_VECTOR_CANONICAL_CHANGED");
    expect(index.status()).toMatchObject({ status: "EMPTY", indexed_records: 0 });
    index.close(); store.close();

    const retry = new api.SqliteVectorMemoryIndex({ databasePath, provider: new api.LocalHashEmbeddingProvider(profile()) });
    expect(await retry.rebuild({ at: "2026-07-25T09:01:00.000Z" })).toMatchObject({ indexed_records: 2 });
    expect(retry.status()).toMatchObject({ status: "HEALTHY", indexed_records: 2, canonical_drift: 0 });
    retry.close();
  });
});
