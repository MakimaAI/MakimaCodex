import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Database } from "bun:sqlite";
import {
  OefCommandBus,
  SqliteOefStore,
  createSortableIdGenerator,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* failed fixture */ }
  }
});
const newRoot = () => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-hardening-"));
  roots.push(root);
  return root;
};

const ids = () => {
  let now = 1_700_000_000_000;
  return createSortableIdGenerator({ now: () => now++, randomBytes: size => new Uint8Array(size).fill(4) });
};
const human = { type: "human", id: "human:owner" } as const;

const workflowV1 = {
  schema_version: 1,
  workflow_id: "versioned",
  version: "1.0.0",
  stages: [{ id: "intake" }, { id: "specification" }, { id: "done", terminal: true }],
  transitions: [{ from: "intake", to: "specification" }, { from: "specification", to: "done" }],
} as const;
const workflowV2 = {
  schema_version: 1,
  workflow_id: "versioned",
  version: "2.0.0",
  stages: [{ id: "intake" }, { id: "design" }, { id: "done", terminal: true }],
  transitions: [{ from: "intake", to: "design" }, { from: "design", to: "done" }],
} as const;
const policy = { schema_version: 1, policy_pack_id: "empty", version: "1.0.0", rules: [] } as const;

const setup = () => {
  const root = newRoot();
  const databasePath = join(root, "oef.sqlite");
  const store = new SqliteOefStore({ databasePath });
  store.installWorkflow(workflowV1);
  store.installPolicy(policy);
  const bus = new OefCommandBus({
    store,
    ids: ids(),
    clock: () => "2026-07-23T12:00:00.000Z",
    principals: [
      { actor: human, roles: ["human_owner", "task_operator", "verifier"] },
      { actor: { type: "agent", id: "agent:migrator" }, roles: ["task_operator"] },
    ],
  });
  return { root, databasePath, store, bus };
};

const command = (type: string, version: number, key: string, payload: unknown, actor = human, taskId = "task:hardening") => ({
  schema_version: 1,
  command_id: `command:${key}`,
  command_type: type,
  task_id: taskId,
  expected_aggregate_version: version,
  actor,
  idempotency_key: key,
  payload,
});

const createTask = (bus: OefCommandBus, taskId = "task:hardening") => bus.execute(command("CreateTask", 0, `create:${taskId}`, {
  title: "Hardening task",
  workflow: { id: "versioned", version: "1.0.0" },
  policy: { id: "empty", version: "1.0.0" },
  risk: { level: "low", reasons: [] },
}, human, taskId));

describe("Phase 1 migration and crash hardening", () => {
  test("rolls an old v1 fixture forward without dropping its data", () => {
    const root = newRoot();
    const databasePath = join(root, "old.sqlite");
    const sqlPath = join(import.meta.dir, "..", "src", "oef", "phase1", "persistence", "migrations", "001_initial.sql");
    const sql = readFileSync(sqlPath, "utf8");
    const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
    const raw = new Database(databasePath, { create: true });
    raw.exec(`CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL);`);
    raw.exec(sql);
    raw.query("INSERT INTO schema_migrations VALUES (?, ?, ?)").run("001_initial", checksum, "2026-07-22T00:00:00.000Z");
    raw.query("INSERT INTO policy_packs VALUES (?, ?, ?, ?)").run("legacy", "1.0.0", `sha256:${"1".repeat(64)}`, "{}");
    raw.close();

    const store = new SqliteOefStore({ databasePath });
    expect(store.getAppliedMigrations()).toEqual([
      "001_initial",
      "002_artifact_classification",
      "003_append_only_events",
      "004_contract_immutability",
      "005_contract_authority",
      "006_contract_document_repair",
    ]);
    const verify = new Database(databasePath, { readonly: true });
    expect(verify.query("SELECT policy_pack_id FROM policy_packs").get()).toEqual({ policy_pack_id: "legacy" });
    expect(verify.query("PRAGMA table_info(artifacts)").all().some((column: any) => column.name === "classification")).toBe(true);
    verify.close();
    store.close();
  });

  test("rolls back when a crash occurs after event insert but before outbox insert", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
    store.installWorkflow(workflowV1);
    store.installPolicy(policy);
    const bus = new OefCommandBus({
      store,
      ids: ids(),
      principals: [{ actor: human, roles: ["human_owner", "task_operator", "verifier"] }],
      failpoint(point) {
        if (point === "after-event-before-outbox") throw new Error("crash-after-event");
      },
    });
    expect(() => createTask(bus)).toThrow("crash-after-event");
    expect(store.getTask("task:hardening")).toBeNull();
    expect(store.listEvents("task:hardening")).toEqual([]);
    expect(store.listOutbox("task:hardening")).toEqual([]);
    store.close();
  });

  test("repairs wrapper-shaped document_json after a legacy revision status progressed", () => {
    const root = newRoot();
    const databasePath = join(root, "progressed.sqlite");
    const migrationRoot = join(import.meta.dir, "..", "src", "oef", "phase1", "persistence", "migrations");
    const raw = new Database(databasePath, { create: true });
    raw.exec("CREATE TABLE schema_migrations (migration_id TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TEXT NOT NULL)");
    for (const id of ["001_initial", "002_artifact_classification", "003_append_only_events", "004_contract_immutability"]) {
      const sql = readFileSync(join(migrationRoot, `${id}.sql`), "utf8");
      raw.exec(sql);
      raw.query("INSERT INTO schema_migrations VALUES (?, ?, ?)").run(
        id,
        createHash("sha256").update(sql, "utf8").digest("hex"),
        "2026-07-22T00:00:00.000Z",
      );
    }
    raw.query("INSERT INTO tasks (task_id, aggregate_version, status, stage, task_json) VALUES (?, 1, 'OPEN', 'intake', ?)")
      .run("task:legacy-progressed", JSON.stringify({ task_id: "task:legacy-progressed" }));
    const document = {
      schema_version: 1,
      task_id: "task:legacy-progressed",
      revision: 1,
      title: "Legacy authoritative document",
      goal: { summary: "Repair wrapper data." },
      scope: { included: ["Repair"], excluded: [] },
      constraints: [],
      acceptance_criteria: [{ key: "repair", statement: "Repaired.", required_evidence: [] }],
      risk: { level: "low", reasons: [] },
      budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
      extensions: {},
    };
    const draft = {
      schema_version: 1,
      revision_id: "contract-revision:legacy-progressed",
      task_id: "task:legacy-progressed",
      revision_number: 1,
      parent_revision_id: null,
      status: "DRAFT",
      canonical_hash: `sha256:${"a".repeat(64)}`,
      document,
      created_by: human,
      created_at: "2026-07-22T00:00:00.000Z",
      approved_by: null,
      approved_at: null,
      change_summary: { added: [], changed: [], removed: [], diff: null },
    };
    raw.query(`
      INSERT INTO contract_revisions
        (revision_id, task_id, revision_number, status, canonical_hash, revision_json, document_json)
      VALUES (?, ?, 1, 'PROPOSED', ?, ?, ?)
    `).run(
      draft.revision_id,
      draft.task_id,
      draft.canonical_hash,
      JSON.stringify({ ...draft, status: "PROPOSED" }),
      JSON.stringify(draft),
    );
    raw.close();

    const store = new SqliteOefStore({ databasePath });
    expect(store.getContractRevision(draft.revision_id)).toMatchObject({
      status: "PROPOSED",
      document: { title: "Legacy authoritative document" },
    });
    expect(store.getAppliedMigrations()).toContain("006_contract_document_repair");
    store.close();
  });
});

describe("Phase 1 version and lifecycle hardening", () => {
  test("keeps existing tasks pinned when a newer workflow is installed", () => {
    const { store, bus } = setup();
    createTask(bus);
    store.installWorkflow(workflowV2);
    const transitioned = bus.execute(command("TransitionTaskStage", 1, "transition:pinned", {
      from_stage: "intake",
      to_stage: "specification",
    }));
    expect(transitioned.ok).toBe(true);
    expect(store.getTask("task:hardening")?.workflow_ref.version).toBe("1.0.0");
    store.close();
  });

  test("requires an explicit human-approved workflow migration with a stage map", () => {
    const { store, bus } = setup();
    createTask(bus);
    store.installWorkflow(workflowV2);
    const payload = {
      from: { id: "versioned", version: "1.0.0" },
      to: { id: "versioned", version: "2.0.0" },
      stage_map: { intake: "intake", specification: "design", done: "done" },
      rationale: "Adopt the design stage explicitly.",
    };
    expect(bus.execute(command(
      "MigrateWorkflow",
      1,
      "migrate:agent",
      payload,
      { type: "agent", id: "agent:migrator" },
    ))).toMatchObject({ ok: false, error: { code: "actor_forbidden" } });
    expect(bus.execute(command("MigrateWorkflow", 1, "migrate:human", payload)).ok).toBe(true);
    expect(store.getTask("task:hardening")).toMatchObject({
      workflow_ref: { id: "versioned", version: "2.0.0", hash: expect.any(String) },
      stage: "intake",
      aggregate_version: 2,
    });
    expect(store.listApprovals("task:hardening")).toEqual([
      expect.objectContaining({ subject: { type: "workflow_migration", id: "versioned@2.0.0" } }),
    ]);
    store.close();
  });

  test("supports explicit contract rejection and block-to-unblock transitions", () => {
    const { store, bus } = setup();
    createTask(bus);
    bus.execute(command("CreateContractRevision", 1, "reject:create", {
      parent_revision_id: null,
      document: {
        schema_version: 1,
        task_id: "task:hardening",
        revision: 1,
        title: "Rejected contract",
        goal: { summary: "Exercise rejection." },
        scope: { included: ["Reject"], excluded: [] },
        constraints: [],
        acceptance_criteria: [{ key: "reject", statement: "Reject explicitly.", required_evidence: [] }],
        risk: { level: "low", reasons: [] },
        budgets: { max_attempts: 1, max_parallel_writers: 1, max_cost_units: 1 },
        extensions: { "company.unknown": { schema_version: 7, opaque: { retained: true } } },
      },
    }));
    const revision = store.listContractRevisions("task:hardening")[0];
    bus.execute(command("ProposeContractRevision", 2, "reject:propose", { revision_id: revision.revision_id }));
    expect(bus.execute(command("RejectContractRevision", 3, "reject:reject", {
      revision_id: revision.revision_id,
      rationale: "Scope is incomplete.",
    })).ok).toBe(true);
    expect(store.getContractRevision(revision.revision_id)).toMatchObject({
      status: "REJECTED",
      document: { extensions: { "company.unknown": { schema_version: 7, opaque: { retained: true } } } },
    });
    expect(bus.execute(command("BlockTask", 4, "block", { reason: "Waiting." })).ok).toBe(true);
    expect(bus.execute(command("UnblockTask", 5, "unblock", { reason: "Dependency arrived." })).ok).toBe(true);
    expect(store.getTask("task:hardening")).toMatchObject({ status: "OPEN", aggregate_version: 6 });
    store.close();
  });
});
