import { describe, expect, test } from "bun:test";
import {
  atomicWriteFile,
  AtomicWriteResidualTempError,
  AtomicWriteSecretResidualError,
  backupConfigBeforeOpenAiTierMigration,
  OpenAiTierBackupCleanupError,
  OpenAiTierBackupCollisionError,
  OpenAiTierBackupRollbackError,
  OpenAiTierBackupSecretResidualError,
  type OpenAiTierBackupIO,
} from "../src/config";
import { runOpenAiTierStartupMigration } from "../src/providers/openai-tier-startup";
import { OpenAiTierMigrationCollisionError, projectOpenAiTierMigration } from "../src/providers/openai-tiers";
import type { OcxConfig } from "../src/types";

const config: OcxConfig = {
  port: 10100,
  defaultProvider: "openai",
  providers: { openai: { adapter: "openai-responses", baseUrl: "https://chatgpt.com/backend-api/codex", authMode: "forward" } },
};

function virtualBackupIO(initial: Record<string, string>, fail: {
  publish?: Error;
  tempUnlink?: number;
  backupUnlink?: number;
  truncate?: number;
  harden?: number;
  read?: number;
  create?: number;
  write?: number;
  writeAfter?: number;
} = {}) {
  type Inode = { bytes: Uint8Array; hardened: boolean };
  const files = new Map<string, Inode>(Object.entries(initial).map(([path, value]) => [path, {
    bytes: new TextEncoder().encode(value),
    hardened: path.endsWith(".bak"),
  }]));
  const calls: string[] = [];
  let writeCount = 0;
  const io: OpenAiTierBackupIO = {
    exists: path => files.has(path),
    read: path => {
      calls.push(`read:${path}`);
      if ((fail.read ?? 0) > 0) {
        fail.read!--;
        throw new Error("read failed");
      }
      const inode = files.get(path);
      if (!inode) throw Object.assign(new Error("missing"), { code: "ENOENT" });
      return inode.bytes.slice();
    },
    createExclusive: path => {
      calls.push(`create:${path}`);
      if ((fail.create ?? 0) > 0) {
        fail.create!--;
        throw new Error("create failed");
      }
      if (files.has(path)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      files.set(path, { bytes: new Uint8Array(), hardened: false });
    },
    write: (path, bytes) => {
      calls.push(`write:${path}`);
      writeCount += 1;
      if ((fail.write ?? 0) > 0) {
        fail.write!--;
        throw new Error("write failed");
      }
      if (fail.writeAfter !== undefined && writeCount > fail.writeAfter) throw new Error("write failed");
      files.get(path)!.bytes = bytes.slice();
    },
    harden: path => {
      calls.push(`harden:${path}`);
      if ((fail.harden ?? 0) > 0) {
        fail.harden!--;
        throw new Error("harden failed");
      }
      files.get(path)!.hardened = true;
    },
    publishNoReplace: (temp, backup) => {
      calls.push(`publish:${backup}`);
      if (fail.publish) throw fail.publish;
      if (files.has(backup)) throw Object.assign(new Error("exists"), { code: "EEXIST" });
      files.set(backup, files.get(temp)!);
    },
    truncate: path => {
      calls.push(`truncate:${path}`);
      if ((fail.truncate ?? 0) > 0) {
        fail.truncate!--;
        throw new Error("truncate failed");
      }
      files.get(path)!.bytes = new Uint8Array();
    },
    unlink: path => {
      calls.push(`unlink:${path}`);
      const isBackup = path.endsWith(".bak");
      if (isBackup && (fail.backupUnlink ?? 0) > 0) {
        fail.backupUnlink!--;
        throw new Error("backup unlink failed");
      }
      if (!isBackup && (fail.tempUnlink ?? 0) > 0) {
        fail.tempUnlink!--;
        throw new Error("temp unlink failed");
      }
      files.delete(path);
    },
  };
  return { io, files, calls };
}

describe("OpenAI provider option startup coordinator", () => {
  test("uses project -> backup -> save order and returns the projection", () => {
    const calls: string[] = [];
    const projected = {
      ...config,
      providers: { openai: { ...config.providers.openai!, codexAccountMode: "pool" as const } },
      openaiProviderTierVersion: 2 as const,
    };
    const result = runOpenAiTierStartupMigration(config, {
      project: () => { calls.push("project"); return { config: projected, changed: true, resolvedMode: "pool", warnings: [] }; },
      backup: () => { calls.push("backup"); },
      save: value => { calls.push("save"); expect(value).toBe(projected); },
    });
    expect(calls).toEqual(["project", "backup", "save"]);
    expect(result).toBe(projected);
  });

  test("emits path-only warnings after save succeeds", () => {
    const calls: string[] = [];
    const originalWarn = console.warn;
    console.warn = message => { calls.push(`warn:${String(message)}`); };
    try {
      runOpenAiTierStartupMigration(config, {
        project: () => ({ config: { ...config, providerContextCaps: { openai: 100_000 }, openaiProviderTierVersion: 2 }, changed: true, resolvedMode: "pool", warnings: ["providerContextCaps.openai: conflict resolved"] }),
        backup: () => { calls.push("backup"); },
        save: () => { calls.push("save"); },
      });
    } finally {
      console.warn = originalWarn;
    }
    expect(calls).toEqual([
      "backup",
      "save",
      "warn:[openai-provider-migration] providerContextCaps.openai: conflict resolved",
    ]);
  });

  test("projection collision performs zero backup/save", () => {
    const calls: string[] = [];
    expect(() => runOpenAiTierStartupMigration(config, {
      project: () => { calls.push("project"); throw new OpenAiTierMigrationCollisionError(); },
      backup: () => { calls.push("backup"); },
      save: () => { calls.push("save"); },
    })).toThrow(OpenAiTierMigrationCollisionError);
    expect(calls).toEqual(["project"]);
  });

  test("backup failure performs no save", () => {
    const calls: string[] = [];
    expect(() => runOpenAiTierStartupMigration(config, {
      project: () => ({ config: { ...config, providerContextCaps: { openai: 100_000 } }, changed: true, resolvedMode: "pool", warnings: [] }),
      backup: () => { calls.push("backup"); throw new Error("backup failed"); },
      save: () => { calls.push("save"); },
    })).toThrow("backup failed");
    expect(calls).toEqual(["backup"]);
  });

  test("unchanged projection skips backup and save entirely", () => {
    const calls: string[] = [];
    const result = runOpenAiTierStartupMigration(config, {
      project: () => { calls.push("project"); return { config: { ...config }, changed: false, resolvedMode: "pool", warnings: [] }; },
      backup: () => { calls.push("backup"); },
      save: () => { calls.push("save"); },
    });
    expect(calls).toEqual(["project"]);
    expect(result.defaultProvider).toBe(config.defaultProvider);
  });

  test("version-marker-only projection skips a stale backup but still saves the marker", () => {
    const calls: string[] = [];
    const projected = { ...config, openaiProviderTierVersion: 2 as const };
    const result = runOpenAiTierStartupMigration(config, {
      project: () => { calls.push("project"); return { config: projected, changed: true, resolvedMode: "pool", warnings: [] }; },
      backup: () => { calls.push("backup"); throw new OpenAiTierBackupCollisionError(); },
      save: value => { calls.push("save"); expect(value).toBe(projected); },
    });
    expect(calls).toEqual(["project", "save"]);
    expect(result.openaiProviderTierVersion).toBe(2);
  });

  test("real non-OpenAI config treats undefined projection fields as non-persistent", () => {
    const routedOnly: OcxConfig = {
      port: 10100,
      defaultProvider: "routed",
      providers: { routed: { adapter: "openai-chat", baseUrl: "https://example.test/v1" } },
      subagentModels: ["routed/model"],
      subagentBridge: { enabled: true },
    };
    const calls: string[] = [];
    const result = runOpenAiTierStartupMigration(routedOnly, {
      project: projectOpenAiTierMigration,
      backup: () => { calls.push("backup"); throw new OpenAiTierBackupCollisionError(); },
      save: () => { calls.push("save"); },
    });
    expect(calls).toEqual(["save"]);
    expect(result.openaiProviderTierVersion).toBe(2);
  });

  test("save failure propagates without masking", () => {
    expect(() => runOpenAiTierStartupMigration(config, {
      project: () => ({ config: { ...config }, changed: true, resolvedMode: "pool", warnings: ["must not emit"] }),
      backup: () => {},
      save: () => { throw new Error("disk full"); },
    })).toThrow("disk full");
  });

  test("absent original file produces a no-op backup", () => {
    const state = virtualBackupIO({});
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/nonexistent.json", state.io)).toBe("absent");
    expect(state.calls).toEqual([]);
  });

  test("atomic writer reports a scrubbed residual when unlink permanently fails", () => {
    let scrubbed = false;
    expect(() => atomicWriteFile("/virtual/config.json", "secret", {
      write: () => {},
      harden: () => {},
      rename: () => { throw new Error("rename failed"); },
      truncate: () => { scrubbed = true; },
      unlink: () => { throw new Error("unlink failed"); },
    })).toThrow(AtomicWriteResidualTempError);
    expect(scrubbed).toBe(true);
  });

  test("atomic writer hardens an empty temp before placing secret content in it", () => {
    const events: string[] = [];
    atomicWriteFile("/virtual/config.json", "secret", {
      write: (_path, value) => { events.push(`write:${value}`); },
      harden: () => { events.push("harden"); },
      rename: () => { events.push("rename"); },
      truncate: () => { events.push("truncate"); },
      unlink: () => { events.push("unlink"); },
    });

    expect(events).toEqual(["write:", "harden", "write:secret", "rename"]);
  });

  test("atomic writer fails closed when ACL hardening reports a soft failure", () => {
    const files = new Map<string, string>([["/virtual/config.json", "original"]]);
    expect(() => atomicWriteFile("/virtual/config.json", "TOP-SECRET", {
      write: (path, value) => { files.set(path, value); },
      harden: () => ({ ok: false, diagnostics: "ACL hardening timed out" }),
      rename: (source, destination) => {
        files.set(destination, files.get(source)!);
        files.delete(source);
      },
      truncate: path => { files.set(path, ""); },
      unlink: path => { files.delete(path); },
    })).toThrow("ACL hardening timed out");

    expect(files.get("/virtual/config.json")).toBe("original");
    expect([...files.values()]).not.toContain("TOP-SECRET");
  });

  test("atomic writer reports an honest secret residual when scrub and removal both fail", () => {
    let writes = 0;
    expect(() => atomicWriteFile("/virtual/config.json", "secret", {
      write: () => {
        writes += 1;
        if (writes > 1) throw new Error("overwrite failed");
      },
      harden: () => {},
      rename: () => { throw new Error("rename failed"); },
      truncate: () => { throw new Error("truncate failed"); },
      unlink: () => { throw new Error("unlink failed"); },
    })).toThrow(AtomicWriteSecretResidualError);
  });

  test("atomic writer cleans initial write and harden failures without touching the destination", () => {
    for (const stage of ["write", "harden"] as const) {
      const files = new Map([["/virtual/config.json", "original"]]);
      let writeCalls = 0;
      expect(() => atomicWriteFile("/virtual/config.json", "secret", {
        write: (path, value) => {
          writeCalls += 1;
          if (stage === "write" && writeCalls === 1) throw new Error("write failed");
          files.set(path, value);
        },
        harden: () => { if (stage === "harden") throw new Error("harden failed"); },
        rename: (source, destination) => { files.set(destination, files.get(source)!); files.delete(source); },
        truncate: path => { files.set(path, ""); },
        unlink: path => { files.delete(path); },
      })).toThrow(`${stage} failed`);
      expect(files.get("/virtual/config.json")).toBe("original");
      expect([...files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
    }
  });

  test("backup creates a hardened no-replace snapshot and removes its hard-link temp", () => {
    const state = virtualBackupIO({ "/virtual/config.json": "original-secret" });
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io)).toBe("created");
    const backup = state.files.get("/virtual/config.json.pre-openai-tiers-v2.bak");
    expect(new TextDecoder().decode(backup?.bytes)).toBe("original-secret");
    expect(backup?.hardened).toBe(true);
    expect([...state.files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
  });

  test("backup hardens its empty exclusive temp before writing config secrets", () => {
    const state = virtualBackupIO({ "/virtual/config.json": "api-key-secret" });
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io)).toBe("created");

    const createIndex = state.calls.findIndex(call => call.startsWith("create:"));
    const hardenIndex = state.calls.findIndex(call => call.startsWith("harden:"));
    const writeIndex = state.calls.findIndex(call => call.startsWith("write:"));
    const publishIndex = state.calls.findIndex(call => call.startsWith("publish:"));
    expect([createIndex, hardenIndex, writeIndex, publishIndex]).toEqual([1, 2, 3, 4]);
  });

  test("backup fails closed when ACL hardening reports a soft failure", () => {
    const state = virtualBackupIO({ "/virtual/config.json": "api-key-secret" });
    state.io.harden = () => ({ ok: false, diagnostics: "ACL hardening timed out" });

    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io))
      .toThrow("ACL hardening timed out");
    expect(state.files.has("/virtual/config.json.pre-openai-tiers-v2.bak")).toBe(false);
    expect([...state.files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
  });

  test("v2 backup creation never overwrites the historical v1 snapshot", () => {
    const state = virtualBackupIO({
      "/virtual/config.json": "three-tier-state",
      "/virtual/config.json.pre-openai-tiers-v1.bak": "pre-three-tier-state",
    });
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io)).toBe("created");
    expect(new TextDecoder().decode(state.files.get("/virtual/config.json.pre-openai-tiers-v1.bak")?.bytes)).toBe("pre-three-tier-state");
    expect(new TextDecoder().decode(state.files.get("/virtual/config.json.pre-openai-tiers-v2.bak")?.bytes)).toBe("three-tier-state");
  });

  test("backup reuses only byte-identical snapshots and rejects collisions", () => {
    const equal = virtualBackupIO({
      "/virtual/config.json": "same",
      "/virtual/config.json.pre-openai-tiers-v2.bak": "same",
    });
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/config.json", equal.io)).toBe("reused");
    expect(equal.calls.some(call => call.startsWith("create:"))).toBe(false);

    const different = virtualBackupIO({
      "/virtual/config.json": "current",
      "/virtual/config.json.pre-openai-tiers-v2.bak": "older",
    });
    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", different.io))
      .toThrow(OpenAiTierBackupCollisionError);
  });

  test("an EEXIST publication race compares and reuses the winner", () => {
    const race = virtualBackupIO({ "/virtual/config.json": "same" }, {
      publish: Object.assign(new Error("race"), { code: "EEXIST" }),
    });
    const originalPublish = race.io.publishNoReplace;
    race.io.publishNoReplace = (temp, backup) => {
      race.files.set(backup, { bytes: new TextEncoder().encode("same"), hardened: true });
      originalPublish(temp, backup);
    };
    expect(backupConfigBeforeOpenAiTierMigration("/virtual/config.json", race.io)).toBe("reused");
    expect([...race.files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
  });

  test("post-publication cleanup rolls back before scrubbing the shared temp", () => {
    const state = virtualBackupIO({ "/virtual/config.json": "original-secret" }, { tempUnlink: 2 });
    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io))
      .toThrow(OpenAiTierBackupCleanupError);
    expect(state.files.has("/virtual/config.json.pre-openai-tiers-v2.bak")).toBe(false);
    expect([...state.files.values()].some(inode => new TextDecoder().decode(inode.bytes).includes("secret"))).toBe(true);
    expect([...state.files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
  });

  test("rollback failure preserves both hardened links with complete bytes", () => {
    const state = virtualBackupIO(
      { "/virtual/config.json": "original-secret" },
      { tempUnlink: 2, backupUnlink: 1 },
    );
    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io))
      .toThrow(OpenAiTierBackupRollbackError);
    const survivors = [...state.files.entries()].filter(([path]) => path !== "/virtual/config.json");
    expect(survivors).toHaveLength(2);
    for (const [, inode] of survivors) {
      expect(new TextDecoder().decode(inode.bytes)).toBe("original-secret");
      expect(inode.hardened).toBe(true);
    }
  });

  test("backup harden failures leave only empty temps while post-write rollback reports secret residuals", () => {
    const beforePublish = virtualBackupIO(
      { "/virtual/config.json": "backup-secret" },
      { harden: 1, truncate: 1, writeAfter: 1, tempUnlink: 2 },
    );
    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", beforePublish.io))
      .toThrow(OpenAiTierBackupCleanupError);
    const emptyResidual = [...beforePublish.files.entries()].find(([path]) => path.endsWith(".tmp"));
    expect(new TextDecoder().decode(emptyResidual?.[1].bytes)).toBe("");

    const afterRollback = virtualBackupIO(
      { "/virtual/config.json": "backup-secret" },
      { tempUnlink: 4, truncate: 1, writeAfter: 1 },
    );
    expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", afterRollback.io))
      .toThrow(OpenAiTierBackupSecretResidualError);
    expect(afterRollback.files.has("/virtual/config.json.pre-openai-tiers-v2.bak")).toBe(false);
    const residual = [...afterRollback.files.entries()].find(([path]) => path.endsWith(".tmp"));
    expect(new TextDecoder().decode(residual?.[1].bytes)).toBe("backup-secret");
    expect(afterRollback.calls.filter(call => call.startsWith("unlink:") && call.endsWith(".tmp"))).toHaveLength(4);
  });

  test("backup aborts cleanly at every pre-publication stage", () => {
    for (const stage of ["read", "create", "write", "harden", "publish"] as const) {
      const failure = stage === "publish"
        ? { publish: new Error("publish failed") }
        : { [stage]: 1 };
      const state = virtualBackupIO({ "/virtual/config.json": "original-secret" }, failure);
      expect(() => backupConfigBeforeOpenAiTierMigration("/virtual/config.json", state.io)).toThrow(`${stage} failed`);
      expect(new TextDecoder().decode(state.files.get("/virtual/config.json")?.bytes)).toBe("original-secret");
      expect(state.files.has("/virtual/config.json.pre-openai-tiers-v2.bak")).toBe(false);
      expect([...state.files.keys()].filter(path => path.endsWith(".tmp"))).toEqual([]);
      const expectedPrefix = stage === "read" ? ["read:/virtual/config.json"] : ["read:/virtual/config.json", expect.stringContaining("create:")];
      expect(state.calls.slice(0, expectedPrefix.length)).toEqual(expectedPrefix);
    }
  });
});
