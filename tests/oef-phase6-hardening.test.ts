import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import * as phase6 from "../src/oef/phase6";

const api = phase6 as Record<string, any>;
const roots: string[] = [];
const now = "2026-07-24T12:00:00.000Z";
afterEach(() => {
  Bun.gc(true);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

function input(overrides: Record<string, unknown> = {}) {
  return {
    memory_id: "memory:hardening",
    layer: "LESSON",
    kind: "opencodex.lesson.failure-pattern",
    scopes: [{ type: "REPOSITORY", id: "opencodex" }],
    subject: { type: "failure", key: "provider-auth" },
    content: { summary: "Provider authorization behavior is verified." },
    lifecycle: { status: "VERIFIED" },
    trust: { level: "HIGH", confidence: 0.95 },
    temporal: { observed_at: now, valid_from: now, valid_until: null, last_verified_at: now },
    provenance: { source_refs: ["evidence:hardening"], extractor_ref: null },
    relations: { supersedes: [], contradicts: [], derived_from: [] },
    access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer"] },
    retention: { policy: "repository-durable" },
    created_at: now,
    created_by: { type: "verifier", id: "verifier:hardening" },
    ...overrides,
  };
}

function query(overrides: Record<string, unknown> = {}) {
  return {
    query_id: `memory-query:${Math.random().toString(16).slice(2)}`,
    text: "authorization verified",
    requester: {
      role: "backend-implementer",
      authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
      max_sensitivity: "INTERNAL",
    },
    scopes: { include: [{ type: "REPOSITORY", id: "opencodex" }] },
    layers: { include: ["LESSON"] },
    trust: { minimum: "LOW" },
    temporal: { at: now },
    budget: { max_tokens: 1_000, max_records: 10 },
    usage_mode: "CLI_RESEARCH",
    explain: true,
    ...overrides,
  };
}

describe("Phase 6 hardening", () => {
  test("requires authority for every scope on a record and direct-id access", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-scope-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(input({
        scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "USER", id: "alice" }],
      }));
      store.create(record);
      const unauthorized = await new api.MemoryRetrievalEngine({ store }).recall(query());
      expect(unauthorized.provenance.memory_revisions).toHaveLength(0);
      expect(() => store.getAuthorized(record.memory_id, {
        role: "backend-implementer",
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        max_sensitivity: "INTERNAL",
      })).toThrow("MEMORY_SCOPE_ACCESS_DENIED");

      const authority = {
        role: "backend-implementer",
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "USER", id: "alice" }],
        max_sensitivity: "INTERNAL",
      };
      expect(store.getAuthorized(record.memory_id, authority)?.memory_id).toBe(record.memory_id);
      const authorized = await new api.MemoryRetrievalEngine({ store }).recall(query({ requester: authority }));
      expect(authorized.provenance.memory_revisions).toContain(record.revision_id);
    } finally { store.close(); }
  });

  test("treats an empty role ACL as deny-all and wildcard as explicit allow", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-role-acl-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const denied = api.createMemoryRecord(input({ memory_id: "memory:deny-all", access: { sensitivity: "INTERNAL", read_roles: [] } }));
      const wildcard = api.createMemoryRecord(input({ memory_id: "memory:wildcard", access: { sensitivity: "INTERNAL", read_roles: ["*"] } }));
      store.create(denied);
      store.create(wildcard);

      const pack = await new api.MemoryRetrievalEngine({ store }).recall(query());
      expect(pack.provenance.memory_revisions).not.toContain(denied.revision_id);
      expect(pack.provenance.memory_revisions).toContain(wildcard.revision_id);
      expect(() => store.getAuthorized(denied.memory_id, {
        role: "backend-implementer",
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        max_sensitivity: "INTERNAL",
      })).toThrow("MEMORY_ROLE_ACCESS_DENIED");
    } finally { store.close(); }
  });

  test("validates every revision actor and lifecycle transition", () => {
    const verified = api.createMemoryRecord(input());
    expect(() => api.appendMemoryRevision(verified, {}, {
      expected_revision: 1, reason: "agent escalation", actor: { type: "agent", id: "agent:worker" }, at: now,
    })).toThrow("MEMORY_REVISION_ACTOR_UNAUTHORIZED");
    expect(() => api.createMemoryRecord(input({ created_by: { type: "system", id: "system:pipeline" } })))
      .toThrow("MEMORY_REVISION_ACTOR_UNAUTHORIZED");
    expect(() => api.appendMemoryRevision(verified, { lifecycle: { status: "CANDIDATE" } }, {
      expected_revision: 1, reason: "invalid backwards transition", actor: { type: "human", id: "human:owner" }, at: now,
    })).toThrow("MEMORY_LIFECYCLE_TRANSITION_INVALID");
    const governance = api.createMemoryRecord(input({
      memory_id: "memory:governance-hardening", layer: "GOVERNANCE", kind: "opencodex.governance.constitution",
      lifecycle: { status: "PROMOTED" }, created_by: { type: "human", id: "human:owner" },
    }));
    expect(() => api.appendMemoryRevision(governance, {}, {
      expected_revision: 1, reason: "agent governance edit", actor: { type: "agent", id: "agent:architect" }, at: now,
    })).toThrow("MEMORY_GOVERNANCE_HUMAN_APPROVAL_REQUIRED");
  });

  test("caps trust by revision actor and reserves terminal states for governance operations", () => {
    expect(() => api.createMemoryRecord(input({
      memory_id: "memory:agent-trust",
      layer: "EPISODE",
      kind: "opencodex.episode.execution",
      lifecycle: { status: "OBSERVED" },
      trust: { level: "AUTHORITATIVE", confidence: 1 },
      created_by: { type: "agent", id: "agent:worker" },
    }))).toThrow("MEMORY_TRUST_ACTOR_UNAUTHORIZED");
    const deprecated = api.createMemoryRecord(input({ memory_id: "memory:terminal", lifecycle: { status: "DEPRECATED" } }));
    expect(() => api.appendMemoryRevision(deprecated, { content: { summary: "Mutated terminal content." } }, {
      expected_revision: 1, reason: "terminal mutation", actor: { type: "human", id: "human:owner" }, at: now,
    })).toThrow("MEMORY_LIFECYCLE_TRANSITION_INVALID");
    const verified = api.createMemoryRecord(input());
    expect(() => api.appendMemoryRevision(verified, { lifecycle: { status: "FORGOTTEN" } }, {
      expected_revision: 1, reason: "bypass forgetting transaction", actor: { type: "human", id: "human:owner" }, at: now,
    })).toThrow("MEMORY_FORGET_REQUIRES_TRANSACTION");
    expect(() => api.createMemoryRecord(input({ memory_id: "memory:initial-forgotten", lifecycle: { status: "FORGOTTEN" } })))
      .toThrow("MEMORY_FORGET_REQUIRES_TRANSACTION");
  });

  test("rejects secrets in metadata and revision reasons", () => {
    expect(() => api.createMemoryRecord(input({
      memory_id: "memory:metadata-secret",
      subject: { type: "failure", key: "sk-proj-1234567890abcdef" },
    }))).toThrow("MEMORY_SECRET_CONTENT_FORBIDDEN");
    const verified = api.createMemoryRecord(input());
    expect(() => api.appendMemoryRevision(verified, {}, {
      expected_revision: 1,
      reason: "token=sk-proj-1234567890abcdef",
      actor: { type: "human", id: "human:owner" },
      at: now,
    })).toThrow("MEMORY_SECRET_CONTENT_FORBIDDEN");
  });

  test("verifies canonical hashes and blocks tombstone resurrection", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-integrity-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(input());
      const forged = { ...record, integrity: { ...record.integrity, content_hash: `sha256:${"0".repeat(64)}` } };
      expect(() => store.create(forged)).toThrow("MEMORY_INTEGRITY_MISMATCH");
      store.create(record);
      store.forget(record.memory_id, { mode: "SOFT_FORGET", reason: "obsolete", at: now });
      const next = api.appendMemoryRevision(record, { lifecycle: { status: "DEPRECATED" } }, {
        expected_revision: 1, reason: "try resurrection", actor: { type: "human", id: "human:owner" }, at: now,
      });
      expect(() => store.appendRevision(next, 1)).toThrow("MEMORY_ID_TOMBSTONED");
    } finally { store.close(); }
  });

  test("fails closed for unsupported legal and secret purge modes", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-purge-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(input()); store.create(record);
      expect(() => store.forget(record.memory_id, { mode: "HARD_DELETE", reason: "token=sk-proj-1234567890abcdef", at: now }))
        .toThrow("MEMORY_SECRET_CONTENT_FORBIDDEN");
      expect(() => store.forget(record.memory_id, { mode: "LEGAL_DELETE", reason: "request", at: now }))
        .toThrow("MEMORY_DELETE_MODE_NOT_IMPLEMENTED");
      expect(() => store.forget(record.memory_id, { mode: "SECRET_PURGE", reason: "incident", at: now }))
        .toThrow("MEMORY_DELETE_MODE_NOT_IMPLEMENTED");
      expect(store.get(record.memory_id)).not.toBeNull();
    } finally { store.close(); }
  });

  test("exposes soft forget as an explicit effective lifecycle overlay", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-soft-forget-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(input({ memory_id: "memory:soft-forget-view" }));
      store.create(record);
      store.forget(record.memory_id, { mode: "SOFT_FORGET", reason: "owner requested", at: now });

      expect(store.get(record.memory_id)?.lifecycle.status).toBe("VERIFIED");
      expect(store.getEffective(record.memory_id)).toMatchObject({
        record: expect.objectContaining({ memory_id: record.memory_id }),
        effective_lifecycle_status: "FORGOTTEN",
        tombstone: { mode: "SOFT_FORGET", content_retained: true },
      });
    } finally { store.close(); }
  });

  test("budgets the final serialized pack and admits vector-only candidates", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-budget-vector-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const record = api.createMemoryRecord(input({
        content: { summary: `Semantically related provider rule ${"x".repeat(900)}` },
        provenance: { source_refs: Array.from({ length: 20 }, (_, index) => `evidence:long-${index}`), extractor_ref: null },
      }));
      store.create(record);
      const pack = await new api.MemoryRetrievalEngine({
        store,
        vectorIndex: { search: async () => [{ revision_id: record.revision_id, score: 0.99 }] },
      }).recall(query({ text: "no lexical overlap zulu", budget: { max_tokens: 1_000, max_records: 5 } }));
      expect(pack.provenance.memory_revisions).toContain(record.revision_id);
      expect(pack.budget.actual_tokens).toBeLessThanOrEqual(1_000);
      expect(Math.ceil(JSON.stringify(pack).length / 4)).toBeLessThanOrEqual(1_000);
      expect(pack.budget.tokenizer_profile).toEqual({
        id: "json-char-estimate",
        version: "1.0.0",
        safety_margin: 0.25,
        exact: false,
      });
    } finally { store.close(); }
  });

  test("does not disclose conflicts unless every member is visible and rejects secret conflict metadata", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-conflict-acl-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const visible = api.createMemoryRecord(input({ memory_id: "memory:visible-claim" }));
      const hidden = api.createMemoryRecord(input({
        memory_id: "memory:hidden-claim",
        scopes: [{ type: "REPOSITORY", id: "opencodex" }, { type: "USER", id: "alice" }],
      }));
      store.create(visible); store.create(hidden);
      store.createConflict({
        conflict_id: "memory-conflict:acl",
        memory_ids: [visible.memory_id, hidden.memory_id],
        status: "UNRESOLVED",
        resolution_requirements: ["human-review"],
        created_at: now,
      });
      const pack = await new api.MemoryRetrievalEngine({ store }).recall(query());
      expect(pack.provenance.memory_revisions).toContain(visible.revision_id);
      expect(pack.sections.open_conflicts).toHaveLength(0);
      expect(pack.sections.relevant_lessons.find((item: { memory_id: string }) => item.memory_id === visible.memory_id))
        .toMatchObject({ conflict_status: "UNRESOLVED" });
      expect(JSON.stringify(pack)).not.toContain(hidden.memory_id);
      expect(() => store.createConflict({
        conflict_id: "memory-conflict:secret",
        memory_ids: [visible.memory_id, hidden.memory_id],
        status: "UNRESOLVED",
        resolution_requirements: ["token=sk-proj-1234567890abcdef"],
        created_at: now,
      })).toThrow("MEMORY_SECRET_CONTENT_FORBIDDEN");
    } finally { store.close(); }
  });

  test("authorizes every historical provenance revision", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-provenance-acl-")); roots.push(root);
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const first = api.createMemoryRecord(input({
        memory_id: "memory:provenance-acl",
        access: { sensitivity: "CONFIDENTIAL", read_roles: ["reviewer"] },
      }));
      store.create(first);
      const second = api.appendMemoryRevision(first, { access: { sensitivity: "INTERNAL", read_roles: ["backend-implementer"] } }, {
        expected_revision: 1, reason: "broaden current access", actor: { type: "human", id: "human:owner" }, at: now,
      });
      store.appendRevision(second, 1);
      expect(() => store.provenanceAuthorized(first.memory_id, {
        role: "backend-implementer",
        authorized_scopes: [{ type: "REPOSITORY", id: "opencodex" }],
        max_sensitivity: "INTERNAL",
      })).toThrow("MEMORY_PROVENANCE_REVISION_ACCESS_DENIED");
    } finally { store.close(); }
  });

  test("hard delete uses exact projection membership and health detects FTS content poisoning", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-exact-delete-health-")); roots.push(root);
    const databasePath = join(root, "memory.sqlite");
    let store = new api.SqliteMemoryStore({ databasePath });
    const short = api.createMemoryRecord(input({ memory_id: "memory:foo" }));
    const longer = api.createMemoryRecord(input({ memory_id: "memory:foobar" }));
    store.create(short); store.create(longer);
    store.saveQueryExplanation("memory-query:foobar-only", { selected: [{ memory_id: longer.memory_id, revision_id: longer.revision_id }] }, now);
    store.forget(short.memory_id, { mode: "HARD_DELETE", reason: "exact deletion", at: now });
    expect(store.explainQuery("memory-query:foobar-only")).not.toBeNull();
    store.close();

    const database = new Database(databasePath);
    database.run("UPDATE memory_fts SET summary='poisoned projection' WHERE revision_id=?", longer.revision_id);
    database.close();
    store = new api.SqliteMemoryStore({ databasePath });
    try {
      expect(store.health()).toMatchObject({ lexical_index: "DEGRADED" });
    } finally { store.close(); }
  });

  test("exposes the complete provenance chain and reruns the acceptance demo", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-rerun-")); roots.push(root);
    const first = await api.runPhase6AcceptanceDemo({ root });
    const second = await api.runPhase6AcceptanceDemo({ root });
    expect(first.status).toBe("PASS");
    expect(second.status).toBe("PASS");
    const store = new api.SqliteMemoryStore({ databasePath: join(root, "memory.sqlite") });
    try {
      const provenance = store.provenance("memory:lesson-403");
      expect(provenance.revisions.map((revision: { revision_number: number }) => revision.revision_number)).toEqual([1, 2]);
      expect(store.health()).toMatchObject({ canonical_store: "HEALTHY", lexical_index: "HEALTHY" });
    } finally { store.close(); }
  });
});
