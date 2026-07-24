import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  OefCommandBus,
  SqliteOefStore,
  createSortableIdGenerator,
  type OefCommandStore,
} from "../../src/oef/phase1";

const [mode, databasePath, barrierRoot] = process.argv.slice(2);
if ((mode !== "a" && mode !== "b") || !databasePath || !barrierRoot) {
  throw new Error("Expected mode, database path, and barrier root");
}

const blocker = new Int32Array(new SharedArrayBuffer(4));
const waitFor = (name: string): void => {
  const path = join(barrierRoot, name);
  while (!existsSync(path)) Atomics.wait(blocker, 0, 0, 10);
};
const signal = (name: string): void => writeFileSync(join(barrierRoot, name), "ready", "utf8");
const actor = { type: "human", id: "human:owner" } as const;
const store = new SqliteOefStore({ databasePath });
let commandStore: OefCommandStore = store;
if (mode === "b") {
  commandStore = new Proxy(store, {
    get(target, property) {
      if (property === "transaction") {
        return <T>(operation: () => T): T => {
          signal("b-attempt");
          return target.transaction(operation);
        };
      }
      const value = Reflect.get(target, property, target) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  }) as unknown as OefCommandStore;
  signal("b-opened");
  waitFor("b-go");
}

let now = mode === "a" ? 1_700_000_100_000 : 1_700_000_200_000;
const bus = new OefCommandBus({
  store: commandStore,
  ids: createSortableIdGenerator({
    now: () => now++,
    randomBytes: size => new Uint8Array(size).fill(mode === "a" ? 1 : 2),
  }),
  principals: [{ actor, roles: ["human_owner", "task_operator", "verifier"] }],
  clock: () => "2026-07-23T12:00:00.000Z",
  failpoint: mode === "a" ? point => {
    if (point === "after-state-before-event") {
      signal("a-ready");
      waitFor("a-release");
    }
  } : undefined,
});

try {
  const result = bus.execute({
    schema_version: 1,
    command_id: `command:writer-${mode}`,
    command_type: mode === "a" ? "BlockTask" : "CancelTask",
    task_id: "task:phase1-persistence",
    expected_aggregate_version: 1,
    actor,
    idempotency_key: `writer:${mode}`,
    payload: { reason: `Writer ${mode}` },
  });
  console.log(JSON.stringify(result));
} finally {
  store.close();
}
