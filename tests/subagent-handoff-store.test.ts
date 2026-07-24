import { describe, expect, test } from "bun:test";
import {
  HANDOFF_MAX_MESSAGE_BYTES,
  HANDOFF_MAX_RECORDS,
  HANDOFF_MAX_TOTAL_BYTES,
  HANDOFF_TTL_MS,
  SubagentHandoffStore,
  normalizeSpawnNameBase,
} from "../src/subagent-bridge/handoff-store";

describe("SubagentHandoffStore", () => {
  const target = (index: number) => `/root/worker_${index.toString(16).padStart(12, "0")}`;

  test("normalizes spawn names, appends a unique 12-hex suffix, and consumes once", () => {
    const suffixes = ["001122334455", "001122334455", "aabbccddeeff"];
    const store = new SubagentHandoffStore({ randomHex: () => suffixes.shift()! });
    expect(normalizeSpawnNameBase("  Héllo, WORLD! this name is deliberately much longer than forty chars  "))
      .toBe("hello_world_this_name_is_deliberately_mu");

    const first = store.stageSpawn({ taskName: " Worker One ", model: "vendor/model", message: "first" });
    const second = store.stageSpawn({ taskName: " Worker One ", model: "vendor/model", message: "second" });
    expect(first.taskName).toBe("worker_one_001122334455");
    expect(second.taskName).toBe("worker_one_aabbccddeeff");
    expect(store.consume(`/root/${first.taskName}`, "NEW_TASK", "vendor/model")?.message).toBe("first");
    expect(store.consume(`/root/${first.taskName}`, "NEW_TASK", "vendor/model")).toBeNull();
  });

  test("matches FIFO by isolated target and Codex message type", () => {
    const store = new SubagentHandoffStore();
    store.stageMessage({ kind: "message", target: target(1), message: "a1" });
    store.stageMessage({ kind: "followup", target: target(1), message: "a2" });
    store.stageMessage({ kind: "message", target: target(2), message: "b1" });
    const spawn = store.stageSpawn({ taskName: "a", model: "vendor/model", message: "spawn" });

    expect(store.consume(target(1), "MESSAGE")?.message).toBe("a1");
    expect(store.consume(`/root/${spawn.taskName}`, "NEW_TASK", "vendor/model")?.message).toBe("spawn");
    expect(store.consume(target(1), "MESSAGE")).toBeNull();
    expect(store.consume(target(1), "NEW_TASK")?.message).toBe("a2");
    expect(store.consume(target(2), "MESSAGE")?.message).toBe("b1");
  });

  test("matches only verified leaf/canonical targets and rejects arbitrary prefixes", () => {
    const store = new SubagentHandoffStore();
    const leaf = "reviewer_abcdef012345";
    store.stageMessage({ kind: "message", target: `/root/parent/${leaf}`, message: "secret" });

    expect(store.consume(`/evil/${leaf}`, "MESSAGE")).toBeNull();
    expect(store.consume(`prefix/${leaf}`, "MESSAGE")).toBeNull();
    expect(store.consume(leaf, "MESSAGE")?.message).toBe("secret");
    expect(() => store.stageMessage({ kind: "message", target: "/root/unverified", message: "no" })).toThrow("invalid_target");
  });

  test("isolates sibling canonical targets that share a generated leaf", () => {
    const store = new SubagentHandoffStore();
    const leaf = "reviewer_abcdef012345";
    store.stageMessage({ kind: "message", target: `/root/alpha/${leaf}`, message: "alpha only" });

    expect(store.consume(`/root/beta/${leaf}`, "MESSAGE")).toBeNull();
    expect(store.consume(`/root/alpha/${leaf}`, "MESSAGE")?.message).toBe("alpha only");
  });

  test("expires at exactly 300 seconds and prunes before capacity checks", () => {
    let now = 10_000;
    const store = new SubagentHandoffStore({ now: () => now });
    store.stageMessage({ kind: "message", target: target(1), message: "old" });
    now += HANDOFF_TTL_MS;
    expect(store.consume(target(1), "MESSAGE")).toBeNull();
    expect(store.stats()).toEqual({ records: 0, totalBytes: 0 });
  });

  test("enforces the exact UTF-8 per-message limit", () => {
    const store = new SubagentHandoffStore();
    expect(() => store.stageMessage({ kind: "message", target: target(1), message: "x".repeat(HANDOFF_MAX_MESSAGE_BYTES) })).not.toThrow();
    expect(() => store.stageMessage({ kind: "message", target: target(1), message: "x".repeat(HANDOFF_MAX_MESSAGE_BYTES + 1) })).toThrow("message_too_large");
    expect(() => new SubagentHandoffStore().stageMessage({ kind: "message", target: target(1), message: "é".repeat(HANDOFF_MAX_MESSAGE_BYTES / 2 + 1) })).toThrow("message_too_large");
  });

  test("rejects the 257th active record without evicting the first 256", () => {
    const store = new SubagentHandoffStore();
    for (let i = 0; i < HANDOFF_MAX_RECORDS; i += 1) {
      store.stageMessage({ kind: "message", target: target(i), message: `${i}` });
    }
    expect(() => store.stageMessage({ kind: "message", target: target(HANDOFF_MAX_RECORDS), message: "no" })).toThrow("record_capacity_exceeded");
    expect(store.stats().records).toBe(HANDOFF_MAX_RECORDS);
    expect(store.consume(target(0), "MESSAGE")?.message).toBe("0");
  });

  test("rejects bytes above 4 MiB without evicting active records", () => {
    const store = new SubagentHandoffStore();
    const full = "x".repeat(HANDOFF_MAX_MESSAGE_BYTES);
    for (let i = 0; i < HANDOFF_MAX_TOTAL_BYTES / HANDOFF_MAX_MESSAGE_BYTES; i += 1) {
      store.stageMessage({ kind: "message", target: target(i), message: full });
    }
    expect(store.stats()).toEqual({ records: 64, totalBytes: HANDOFF_MAX_TOTAL_BYTES });
    expect(() => store.stageMessage({ kind: "message", target: target(64), message: "x" })).toThrow("byte_capacity_exceeded");
    expect(store.consume(target(0), "MESSAGE")?.message).toBe(full);
  });
});
