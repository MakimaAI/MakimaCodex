import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
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
    try { rmSync(root, { recursive: true, force: true }); } catch { /* failed property fixture */ }
  }
});

const randomForSeed = (seed: number) => {
  let state = seed || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
};

describe("Phase 1 state-machine properties", () => {
  test("preserves aggregate, event, terminal, and idempotency invariants across generated sequences", () => {
    for (let seed = 1; seed <= 40; seed += 1) {
      const root = mkdtempSync(join(tmpdir(), `oef-phase1-property-${seed}-`));
      roots.push(root);
      const store = new SqliteOefStore({ databasePath: join(root, "oef.sqlite") });
      store.installWorkflow({
        schema_version: 1,
        workflow_id: "property",
        version: "1.0.0",
        stages: [{ id: "open" }, { id: "done", terminal: true }],
        transitions: [{ from: "open", to: "done" }],
      });
      store.installPolicy({ schema_version: 1, policy_pack_id: "property", version: "1.0.0", rules: [] });
      let clock = 1_700_000_000_000 + seed * 10_000;
      const ids = createSortableIdGenerator({
        now: () => clock++,
        randomBytes: size => new Uint8Array(size).fill(seed % 255),
      });
      const bus = new OefCommandBus({
        store,
        ids,
        clock: () => new Date(clock).toISOString(),
        principals: [{
          actor: { type: "human", id: "human:property" },
          roles: ["human_owner", "task_operator", "verifier"],
        }],
      });
      const taskId = `task:property-${seed}`;
      const create = {
        schema_version: 1,
        command_id: `command:create-${seed}`,
        command_type: "CreateTask",
        task_id: taskId,
        expected_aggregate_version: 0,
        actor: { type: "human", id: "human:property" },
        idempotency_key: `create:${seed}`,
        payload: {
          title: `Property ${seed}`,
          workflow: { id: "property", version: "1.0.0" },
          policy: { id: "property", version: "1.0.0" },
          risk: { level: "low", reasons: [] },
        },
      } as const;
      expect(bus.execute(create).ok).toBe(true);
      const random = randomForSeed(seed);
      const successfulCommands: Array<Record<string, unknown>> = [create];

      for (let step = 0; step < 30; step += 1) {
        const before = store.getTask(taskId)!;
        const eventsBefore = store.listEvents(taskId);
        if (random() < 0.12) {
          const replay = successfulCommands[Math.floor(random() * successfulCommands.length)];
          const result = bus.execute(replay);
          expect(result.ok).toBe(true);
          expect(result.replayed).toBe(true);
          expect(store.getTask(taskId)?.aggregate_version).toBe(before.aggregate_version);
          expect(store.listEvents(taskId)).toHaveLength(eventsBefore.length);
          continue;
        }

        const choice = Math.floor(random() * 5);
        const commandType = ["BlockTask", "UnblockTask", "CancelTask", "ReopenTask", "TransitionTaskStage"][choice];
        const payload = commandType === "TransitionTaskStage"
          ? { from_stage: before.stage, to_stage: before.stage === "open" ? "done" : "open" }
          : commandType === "ReopenTask"
            ? { to_stage: "open", rationale: "Generated explicit reopen." }
            : { reason: `Generated ${commandType}.` };
        const generated = {
          schema_version: 1,
          command_id: `command:${seed}-${step}`,
          command_type: commandType,
          task_id: taskId,
          expected_aggregate_version: before.aggregate_version,
          actor: { type: "human", id: "human:property" },
          idempotency_key: `property:${seed}:${step}`,
          payload,
        };
        const result = bus.execute(generated);
        const after = store.getTask(taskId)!;
        const eventsAfter = store.listEvents(taskId);
        if (result.ok) {
          successfulCommands.push(generated);
          expect(after.aggregate_version).toBe(before.aggregate_version + 1);
          expect(eventsAfter).toHaveLength(eventsBefore.length + 1);
          expect(eventsAfter.at(-1)?.aggregate.version).toBe(after.aggregate_version);
        } else {
          expect(after.aggregate_version).toBe(before.aggregate_version);
          expect(eventsAfter).toHaveLength(eventsBefore.length);
        }
        if (before.status === "COMPLETED" || before.status === "CANCELLED") {
          if (result.ok) expect(commandType).toBe("ReopenTask");
        }
        expect(after.task_id).toBe(taskId);
        expect(eventsAfter.map(event => event.aggregate.version)).toEqual(
          Array.from({ length: eventsAfter.length }, (_, index) => index + 1),
        );
      }
      store.close();
    }
  });
});
