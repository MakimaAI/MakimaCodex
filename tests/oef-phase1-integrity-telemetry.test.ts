import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import {
  JsonlTraceExporter,
  LocalArtifactStore,
  OefCommandBus,
  SqliteOefStore,
  createSortableIdGenerator,
  upcastStoredEvent,
  verifyTaskIntegrity,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* failed fixture may retain a handle */ }
  }
});

const newRoot = (): string => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-integrity-"));
  roots.push(root);
  return root;
};

const actor = { type: "human", id: "human:owner" } as const;

const setup = () => {
  const root = newRoot();
  let now = 1_700_000_000_000;
  const ids = createSortableIdGenerator({
    now: () => now++,
    randomBytes: size => new Uint8Array(size).fill(2),
  });
  const databasePath = join(root, "oef.sqlite");
  const store = new SqliteOefStore({ databasePath });
  const artifacts = new LocalArtifactStore({ root: join(root, "artifacts"), ids });
  store.installWorkflow({
    schema_version: 1,
    workflow_id: "minimal",
    version: "1.0.0",
    stages: [{ id: "intake" }, { id: "done", terminal: true }],
    transitions: [{ from: "intake", to: "done" }],
  });
  store.installPolicy({
    schema_version: 1,
    policy_pack_id: "minimal",
    version: "1.0.0",
    rules: [],
  });
  const bus = new OefCommandBus({
    store,
    artifactStore: artifacts,
    ids,
    clock: () => "2026-07-23T12:00:00.000Z",
    principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }],
  });
  const base = (type: string, version: number, key: string, payload: unknown) => ({
    schema_version: 1,
    command_id: `command:${key}`,
    command_type: type,
    task_id: "task:integrity",
    expected_aggregate_version: version,
    actor,
    idempotency_key: key,
    payload,
  });
  bus.execute(base("CreateTask", 0, "create", {
    title: "Integrity task",
    workflow: { id: "minimal", version: "1.0.0" },
    policy: { id: "minimal", version: "1.0.0" },
    risk: { level: "low", reasons: [] },
  }));
  bus.execute(base("CreateContractRevision", 1, "contract:create", {
    document: {
      schema_version: 1,
      task_id: "task:integrity",
      revision: 1,
      title: "Integrity contract",
      goal: { summary: "Verify every persisted integrity boundary." },
      scope: { included: ["Integrity"], excluded: ["Model calls"] },
      constraints: ["Append only."],
      acceptance_criteria: [{
        key: "integrity",
        statement: "Hash chains verify.",
        required_evidence: ["opencodex.integrity-check"],
      }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
      extensions: {},
    },
    parent_revision_id: null,
  }));
  const revision = store.listContractRevisions("task:integrity")[0];
  bus.execute(base("ProposeContractRevision", 2, "contract:propose", { revision_id: revision.revision_id }));
  bus.execute(base("ApproveContractRevision", 3, "contract:approve", {
    revision_id: revision.revision_id,
    rationale: "Integrity contract approved.",
  }));
  return { root, databasePath, store, artifacts, bus };
};

describe("Phase 1 audit and integrity", () => {
  test("verifies event chain, active contract, and artifacts as one integrity view", () => {
    const { store, artifacts } = setup();
    expect(verifyTaskIntegrity({ taskId: "task:integrity", store, artifactStore: artifacts })).toEqual({
      valid: true,
      events: { count: 4, hash_chain_valid: true },
      artifacts: { count: 0, integrity_valid: true, invalid_artifact_ids: [] },
      active_contract: { hash_valid: true },
    });

    store.insertArtifact("task:integrity", {
      artifact_id: "artifact:missing",
      content_hash: `sha256:${"a".repeat(64)}`,
      media_type: "text/plain",
      size_bytes: 1,
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: { type: "system", id: "system:test" },
      storage_key: `aa/aa/${"a".repeat(64)}`,
      deduplicated: false,
    });
    expect(verifyTaskIntegrity({ taskId: "task:integrity", store, artifactStore: artifacts })).toMatchObject({
      valid: false,
      artifacts: { count: 1, integrity_valid: false, invalid_artifact_ids: ["artifact:missing"] },
    });
    store.close();
  });

  test("database triggers forbid event mutation and deletion", () => {
    const { databasePath, store } = setup();
    store.close();
    const raw = new Database(databasePath);
    expect(() => raw.query("UPDATE events SET event_type = 'tampered' WHERE aggregate_id = ?").run("task:integrity"))
      .toThrow("events are append-only");
    expect(() => raw.query("DELETE FROM events WHERE aggregate_id = ?").run("task:integrity"))
      .toThrow("events are append-only");
    raw.close();
  });

  test("rejects a valid event prefix that does not reach the task aggregate version", () => {
    const { root, databasePath, store } = setup();
    store.close();
    const raw = new Database(databasePath);
    raw.exec("DROP TRIGGER events_no_delete");
    raw.query("DELETE FROM events WHERE aggregate_id = ? AND aggregate_version = 4").run("task:integrity");
    raw.close();
    const reopened = new SqliteOefStore({ databasePath });
    const artifacts = new LocalArtifactStore({ root: join(root, "artifacts") });
    expect(verifyTaskIntegrity({ taskId: "task:integrity", store: reopened, artifactStore: artifacts })).toMatchObject({
      valid: false,
      events: { count: 3, hash_chain_valid: false },
    });
    reopened.close();
  });

  test("protects and reads approved contract content from the authoritative document column", () => {
    const { databasePath, store } = setup();
    const revision = store.listContractRevisions("task:integrity")[0];
    store.close();
    const raw = new Database(databasePath);
    expect(() => raw.query(`
      UPDATE contract_revisions
      SET revision_json = json_set(revision_json, '$.document.title', 'tampered')
      WHERE revision_id = ?
    `).run(revision.revision_id)).toThrow("immutable");
    raw.exec("DROP TRIGGER approved_contract_revision_document_immutable");
    raw.query(`
      UPDATE contract_revisions
      SET revision_json = json_set(revision_json, '$.document.title', 'metadata-copy-tampered')
      WHERE revision_id = ?
    `).run(revision.revision_id);
    raw.close();

    const reopened = new SqliteOefStore({ databasePath });
    expect(reopened.getContractRevision(revision.revision_id)?.document.title).toBe("Integrity contract");
    reopened.close();
  });

  test("dispatches pending outbox entries once without mutating audit events", () => {
    const { store } = setup();
    const pending = store.listPendingOutbox(10);
    expect(pending).toHaveLength(4);
    for (const item of pending) store.markOutboxProcessed(item.event_id, "2026-07-23T12:01:00.000Z");
    expect(store.listPendingOutbox(10)).toEqual([]);
    expect(store.listEvents("task:integrity")).toHaveLength(4);
    store.close();
  });
});

describe("Phase 1 schema evolution and operational traces", () => {
  test("upcasts an immutable legacy event at read time", () => {
    const legacy = {
      event_id: "event:legacy",
      event_type: "task.created",
      event_schema_version: 0,
      aggregate: { type: "task", id: "task:legacy", version: 1 },
      actor_id: "human:legacy-owner",
      payload: { title: "Legacy task" },
    };
    const current = upcastStoredEvent(legacy);
    expect(current).toMatchObject({
      event_id: "event:legacy",
      event_schema_version: 1,
      actor: { type: "human", id: "human:legacy-owner" },
      payload: { title: "Legacy task" },
    });
    expect(legacy).not.toHaveProperty("actor");
    expect(() => upcastStoredEvent({ ...legacy, event_schema_version: 99 })).toThrow("upcaster");
  });

  test("exports redacted JSONL spans separately from audit events", () => {
    const root = join(newRoot(), "traces");
    const exporter = new JsonlTraceExporter({ root });
    exporter.export({
      schema_version: 1,
      trace_id: "trace:1",
      span_id: "span:1",
      parent_span_id: null,
      name: "policy.evaluate",
      status: "ok",
      started_at: "2026-07-23T12:00:00.000Z",
      ended_at: "2026-07-23T12:00:00.024Z",
      attributes: {
        task_id: "task:integrity",
        policy_pack: "minimal@1.0.0",
        authorization: "Bearer abcdefghijklmnopqrstuvwxyz",
      },
    });

    const line = readFileSync(join(root, "2026-07-23.jsonl"), "utf8").trim();
    expect(JSON.parse(line)).toMatchObject({
      name: "policy.evaluate",
      attributes: { authorization: "[REDACTED]" },
    });
    expect(line).not.toContain("abcdefghijklmnopqrstuvwxyz");
    expect(line).not.toContain("event_type");
  });
});
