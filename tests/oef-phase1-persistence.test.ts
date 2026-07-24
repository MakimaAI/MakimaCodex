import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OefCommandBus,
  SqliteOefStore,
  createSortableIdGenerator,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* open RED-test fixture */ }
  }
});

const newRoot = (): string => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-persistence-"));
  roots.push(root);
  return root;
};

const workflow = {
  schema_version: 1,
  workflow_id: "software-development",
  version: "1.0.0",
  stages: [
    { id: "intake" },
    { id: "specification" },
    { id: "planning" },
    { id: "done", terminal: true },
  ],
  transitions: [
    { from: "intake", to: "specification" },
    { from: "specification", to: "planning", guards: ["contract.approved"] },
    { from: "planning", to: "done", guards: ["verdict.accepted"] },
  ],
} as const;

const policy = {
  schema_version: 1,
  policy_pack_id: "safe-default",
  version: "1.0.0",
  rules: [
    {
      id: "approved-contract-before-planning",
      when: { operation: "transition", transition_to: "planning" },
      require: { contract_status: "APPROVED" },
    },
  ],
} as const;

const ids = () => createSortableIdGenerator({
  now: (() => {
    let value = 1_700_000_000_000;
    return () => value++;
  })(),
  randomBytes: size => new Uint8Array(size).fill(9),
});

const actor = { type: "human", id: "human:owner" } as const;

const createTaskCommand = (taskId = "task:phase1-persistence") => ({
  schema_version: 1,
  command_id: "command:create-task",
  command_type: "CreateTask",
  task_id: taskId,
  expected_aggregate_version: 0,
  actor,
  idempotency_key: `create:${taskId}`,
  payload: {
    title: "Persistent task",
    workflow: { id: "software-development", version: "1.0.0" },
    policy: { id: "safe-default", version: "1.0.0" },
    risk: { level: "low", reasons: [] },
  },
});

describe("Phase 1 SQLite persistence", () => {
  test("applies roll-forward migrations with safe local SQLite settings", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });

    expect(store.getAppliedMigrations()).toEqual([
      "001_initial",
      "002_artifact_classification",
      "003_append_only_events",
      "004_contract_immutability",
      "005_contract_authority",
      "006_contract_document_repair",
    ]);
    expect(store.sqliteSettings()).toEqual({
      journal_mode: "wal",
      foreign_keys: 1,
      busy_timeout: 5_000,
    });
    store.close();
  });

  test("rolls back state, event, and outbox together at injected crash points", () => {
    const root = newRoot();
    const databasePath = join(root, "oef.sqlite");
    const store = new SqliteOefStore({ databasePath });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({
      store,
      ids: ids(),
      clock: () => "2026-07-23T12:00:00.000Z",
      principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }],
      failpoint(point: string) {
        if (point === "after-state-before-event") throw new Error("simulated-crash");
      },
    });

    expect(() => bus.execute(createTaskCommand())).toThrow("simulated-crash");
    expect(store.getTask("task:phase1-persistence")).toBeNull();
    expect(store.listEvents("task:phase1-persistence")).toEqual([]);
    expect(store.listOutbox("task:phase1-persistence")).toEqual([]);
    store.close();

    const reopened = new SqliteOefStore({ databasePath });
    expect(reopened.getTask("task:phase1-persistence")).toBeNull();
    reopened.close();
  });

  test("persists pinned task state and timeline across restart", () => {
    const root = newRoot();
    const databasePath = join(root, "oef.sqlite");
    let store = new SqliteOefStore({ databasePath });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({
      store,
      ids: ids(),
      clock: () => "2026-07-23T12:00:00.000Z",
      principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }],
    });
    const result = bus.execute(createTaskCommand());
    expect(result.ok).toBe(true);
    expect(result.replayed).toBe(false);
    store.close();

    store = new SqliteOefStore({ databasePath });
    const task = store.getTask("task:phase1-persistence");
    expect(task).toMatchObject({
      task_id: "task:phase1-persistence",
      status: "OPEN",
      stage: "intake",
      aggregate_version: 1,
      workflow_ref: { id: "software-development", version: "1.0.0" },
      policy_pack_ref: { id: "safe-default", version: "1.0.0" },
    });
    expect(task?.workflow_ref.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(task?.policy_pack_ref.hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(store.getTimeline("task:phase1-persistence")).toEqual([
      expect.objectContaining({ aggregate_version: 1, event_type: "task.created" }),
    ]);
    expect(store.listOutbox("task:phase1-persistence")).toHaveLength(1);
    store.close();
  });

  test("replays one idempotent result without duplicate state or events", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({ store, ids: ids(), clock: () => "2026-07-23T12:00:00.000Z", principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }] });
    const command = createTaskCommand();

    const first = bus.execute(command);
    for (let attempt = 0; attempt < 99; attempt += 1) {
      const replay = bus.execute(command);
      expect(replay.ok).toBe(true);
      expect(replay.replayed).toBe(true);
      expect(replay.value).toEqual(first.value);
    }

    expect(store.listEvents(command.task_id)).toHaveLength(1);
    expect(store.listOutbox(command.task_id)).toHaveLength(1);
    expect(store.getTask(command.task_id)?.aggregate_version).toBe(1);
    store.close();
  });

  test("allows one writer and rejects the stale expected aggregate version", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({ store, ids: ids(), clock: () => "2026-07-23T12:00:00.000Z", principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }] });
    bus.execute(createTaskCommand());

    const block = bus.execute({
      schema_version: 1,
      command_id: "command:block",
      command_type: "BlockTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 1,
      actor,
      idempotency_key: "block:phase1",
      payload: { reason: "Waiting for evidence." },
    });
    const stale = bus.execute({
      schema_version: 1,
      command_id: "command:cancel",
      command_type: "CancelTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 1,
      actor,
      idempotency_key: "cancel:phase1",
      payload: { reason: "No longer needed." },
    });

    expect(block.ok).toBe(true);
    expect(stale).toEqual({
      ok: false,
      replayed: false,
      error: { code: "concurrency_conflict", expected: 1, actual: 2 },
    });
    expect(store.getTask("task:phase1-persistence")?.status).toBe("BLOCKED");
    expect(store.listEvents("task:phase1-persistence").map(event => event.aggregate.version)).toEqual([1, 2]);
    store.close();
  });

  test("maps a barrier-controlled conflict from two SQLite connections to concurrency_conflict", async () => {
    const root = newRoot();
    const databasePath = join(root, "oef.sqlite");
    const barrierRoot = join(root, "barriers");
    mkdirSync(barrierRoot);
    const setupStore = new SqliteOefStore({ databasePath });
    setupStore.installWorkflow(workflow);
    setupStore.installPolicy(policy);
    const setupBus = new OefCommandBus({
      store: setupStore,
      ids: ids(),
      clock: () => "2026-07-23T12:00:00.000Z",
      principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }],
    });
    expect(setupBus.execute(createTaskCommand()).ok).toBe(true);
    setupStore.close();

    const helper = join(import.meta.dir, "fixtures", "oef-phase1-concurrent-writer.ts");
    const writerB = Bun.spawn({
      cmd: [process.execPath, helper, "b", databasePath, barrierRoot],
      cwd: join(import.meta.dir, ".."),
      stdout: "pipe",
      stderr: "pipe",
    });
    const waitFor = async (name: string) => {
      const path = join(barrierRoot, name);
      const deadline = Date.now() + 10_000;
      while (!existsSync(path)) {
        if (Date.now() > deadline) throw new Error(`Timed out waiting for concurrency barrier: ${name}`);
        await Bun.sleep(10);
      }
    };
    await waitFor("b-opened");
    const writerA = Bun.spawn({
      cmd: [process.execPath, helper, "a", databasePath, barrierRoot],
      cwd: join(import.meta.dir, ".."),
      stdout: "pipe",
      stderr: "pipe",
    });
    await waitFor("a-ready");
    writeFileSync(join(barrierRoot, "b-go"), "go", "utf8");
    await waitFor("b-attempt");
    writeFileSync(join(barrierRoot, "a-release"), "go", "utf8");

    const [exitA, exitB, stdoutA, stdoutB, stderrA, stderrB] = await Promise.all([
      writerA.exited,
      writerB.exited,
      new Response(writerA.stdout).text(),
      new Response(writerB.stdout).text(),
      new Response(writerA.stderr).text(),
      new Response(writerB.stderr).text(),
    ]);
    expect(exitA, stderrA).toBe(0);
    expect(exitB, stderrB).toBe(0);
    expect(JSON.parse(stdoutA.trim())).toMatchObject({ ok: true, value: { task: { status: "BLOCKED" } } });
    expect(JSON.parse(stdoutB.trim())).toEqual({
      ok: false,
      replayed: false,
      error: { code: "concurrency_conflict", expected: 1, actual: 2 },
    });
    const verifyStore = new SqliteOefStore({ databasePath });
    expect(verifyStore.getTask("task:phase1-persistence")).toMatchObject({ status: "BLOCKED", aggregate_version: 2 });
    expect(verifyStore.listEvents("task:phase1-persistence").map(event => event.aggregate.version)).toEqual([1, 2]);
    verifyStore.close();
  });

  test("replays the first failed command result even after state later changes", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({ store, ids: ids(), clock: () => "2026-07-23T12:00:00.000Z", principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }] });
    bus.execute(createTaskCommand());
    const earlyUnblock = {
      schema_version: 1,
      command_id: "command:unblock-early",
      command_type: "UnblockTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 1,
      actor,
      idempotency_key: "unblock:early",
      payload: { reason: "Not blocked yet." },
    } as const;
    const first = bus.execute(earlyUnblock);
    expect(first).toEqual({
      ok: false,
      replayed: false,
      error: { code: "invalid_state", status: "OPEN" },
    });
    expect(bus.execute({
      schema_version: 1,
      command_id: "command:block-after-failure",
      command_type: "BlockTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 1,
      actor,
      idempotency_key: "block:after-failure",
      payload: { reason: "Now blocked." },
    }).ok).toBe(true);
    expect(bus.execute(earlyUnblock)).toEqual({ ...first, replayed: true });
    expect(store.getTask("task:phase1-persistence")).toMatchObject({ status: "BLOCKED", aggregate_version: 2 });
    expect(store.listEvents("task:phase1-persistence")).toHaveLength(2);
    store.close();
  });

  test("does not let a blocked task transition stages or emit duplicate block events", () => {
    const root = newRoot();
    const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
    store.installWorkflow(workflow);
    store.installPolicy(policy);
    const bus = new OefCommandBus({ store, ids: ids(), clock: () => "2026-07-23T12:00:00.000Z", principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }] });
    bus.execute(createTaskCommand());
    expect(bus.execute({
      schema_version: 1,
      command_id: "command:block-once",
      command_type: "BlockTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 1,
      actor,
      idempotency_key: "block:once",
      payload: { reason: "Blocked." },
    }).ok).toBe(true);
    expect(bus.execute({
      schema_version: 1,
      command_id: "command:block-twice",
      command_type: "BlockTask",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 2,
      actor,
      idempotency_key: "block:twice",
      payload: { reason: "Still blocked." },
    })).toMatchObject({ ok: false, error: { code: "invalid_state", status: "BLOCKED" } });
    expect(bus.execute({
      schema_version: 1,
      command_id: "command:transition-blocked",
      command_type: "TransitionTaskStage",
      task_id: "task:phase1-persistence",
      expected_aggregate_version: 2,
      actor,
      idempotency_key: "transition:blocked",
      payload: { from_stage: "intake", to_stage: "specification" },
    })).toMatchObject({ ok: false, error: { code: "invalid_state", status: "BLOCKED" } });
    expect(store.getTask("task:phase1-persistence")).toMatchObject({ status: "BLOCKED", stage: "intake", aggregate_version: 2 });
    expect(store.listEvents("task:phase1-persistence")).toHaveLength(2);
    store.close();
  });
});
