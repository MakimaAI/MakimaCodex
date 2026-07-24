import { describe, expect, test } from "bun:test";
import {
  chmodSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  installSubagentBridge,
  inspectCodexPluginRegistration,
  removeSubagentBridge,
  statusSubagentBridge,
  type SubagentBridgeLifecycleOptions,
} from "../src/subagent-bridge/lifecycle";
import * as lifecycleModule from "../src/subagent-bridge/lifecycle";
import { cmdSubagents } from "../src/cli/subagents";

const repoRoot = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const bundleDir = join(repoRoot, "plugins", "opencodex-subagent-bridge");
const cliPath = join(repoRoot, "src", "cli", "index.ts");
const runCodexCommand = (...args: any[]) => (lifecycleModule as any).runCodexCommand(...args);
const readSecureSubagentBridgeToken = (...args: any[]) => (lifecycleModule as any).readSecureSubagentBridgeToken(...args);
const isSecurePosixBridgeTokenFile = (...args: any[]) => (lifecycleModule as any).isSecurePosixBridgeTokenFile(...args);
const SELECTOR = "opencodex-subagent-bridge@my-personal-market";
const LOCK_FILE = "subagent-bridge-lifecycle.lock";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "ocx-subagent-bridge-"));
  const homeDir = join(root, "home");
  const configDir = join(root, "opencodex");
  mkdirSync(join(homeDir, ".agents", "plugins"), { recursive: true });
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.json"), JSON.stringify({
    port: 10100,
    providers: { custom: { adapter: "openai-chat", baseUrl: "https://example.test/v1", apiKey: "keep-me" } },
    defaultProvider: "custom",
    unrelatedSetting: { preserve: true },
    subagentBridge: { enabled: false },
  }, null, 2));
  writeFileSync(join(homeDir, ".agents", "plugins", "marketplace.json"), JSON.stringify({
    name: "my-personal-market",
    interface: { displayName: "My plugins", keep: "yes" },
    topLevelExtra: { preserve: true },
    plugins: [
      { name: "alpha", source: { source: "local", path: "./plugins/alpha" }, custom: true },
      { name: "omega", source: { source: "local", path: "./plugins/omega" }, custom: true },
    ],
  }, null, 2));
  const invocations: Array<{ command: string; args: string[] }> = [];
  const registrations = new Map<string, { installed: boolean; enabled: boolean }>();
  const options: SubagentBridgeLifecycleOptions = {
    homeDir,
    configDir,
    bundleDir,
    runtimeCommand: process.execPath,
    runtimeArgs: [cliPath, "__subagent-bridge-mcp"],
    codexCommand: process.execPath,
    now: () => new Date("2026-07-21T12:34:56Z"),
    randomBytes: length => new Uint8Array(Array.from({ length }, (_, i) => i)),
    runCodex: (command, args) => {
      invocations.push({ command, args });
      if (args[0] === "plugin" && args[1] === "add" && args[2]) registrations.set(args[2], { installed: true, enabled: true });
      if (args[0] === "plugin" && args[1] === "remove" && args[2]) registrations.delete(args[2]);
      return { status: 0 };
    },
    inspectRegistration: (_command, selector) => registrations.get(selector) ?? { installed: false, enabled: false },
    hardenSecret: () => {},
    hardenConfigDir: () => {},
    inspectTokenSecurity: () => true,
  };
  return { root, homeDir, configDir, invocations, registrations, options };
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, "utf8"));
}

describe("ocx subagents bridge lifecycle", () => {
  test("the exact CLI command installs without restarting and prints restart/new-task guidance", () => {
    const f = fixture();
    const stdout: string[] = [];
    const stderr: string[] = [];
    try {
      const exitCode = cmdSubagents(["bridge", "install"], {
        lifecycle: f.options,
        stdout: line => stdout.push(line),
        stderr: line => stderr.push(line),
      });
      expect(exitCode).toBe(0);
      expect(stderr).toEqual([]);
      expect(stdout.join("\n")).toContain("ocx restart");
      expect(stdout.join("\n")).toContain("new task");
      expect(f.invocations).toEqual([{ command: process.execPath, args: ["plugin", "add", "opencodex-subagent-bridge@my-personal-market"] }]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("first install seeds the default personal marketplace when it is absent", () => {
    const f = fixture();
    try {
      rmSync(join(f.homeDir, ".agents"), { recursive: true, force: true });
      installSubagentBridge(f.options);
      const marketplace = readJson(join(f.homeDir, ".agents", "plugins", "marketplace.json"));
      expect(marketplace.name).toBe("personal");
      expect(marketplace.interface.displayName).toBe("Personal");
      expect(marketplace.plugins.map((entry: any) => entry.name)).toEqual(["opencodex-subagent-bridge"]);
      expect(f.invocations[0]).toEqual({ command: process.execPath, args: ["plugin", "add", "opencodex-subagent-bridge@personal"] });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("first install is isolated, preserves unrelated state, and writes a reliable MCP invocation", () => {
    const f = fixture();
    try {
      const result = installSubagentBridge(f.options);
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      expect(result.ready).toBe(true);
      expect(JSON.stringify(result)).not.toContain("AAECAwQ");
      expect(existsSync(pluginDir)).toBe(true);
      expect(readJson(join(pluginDir, ".mcp.json"))).toEqual({
        mcpServers: {
          "opencodex-subagent-bridge": {
            command: process.execPath,
            args: [cliPath, "__subagent-bridge-mcp"],
          },
        },
      });
      expect(readJson(join(pluginDir, ".codex-plugin", "plugin.json")).version)
        .toMatch(/^0\.1\.0\+codex\.local-20260721-123456\d{3}-\d+-\d+-[0-9a-f]{12}$/);

      const marketplace = readJson(join(f.homeDir, ".agents", "plugins", "marketplace.json"));
      expect(marketplace.name).toBe("my-personal-market");
      expect(marketplace.interface).toEqual({ displayName: "My plugins", keep: "yes" });
      expect(marketplace.topLevelExtra).toEqual({ preserve: true });
      expect(marketplace.plugins.map((entry: any) => entry.name)).toEqual(["alpha", "omega", "opencodex-subagent-bridge"]);
      expect(marketplace.plugins[0].custom).toBe(true);
      expect(marketplace.plugins[2]).toEqual({
        name: "opencodex-subagent-bridge",
        source: { source: "local", path: "./plugins/opencodex-subagent-bridge" },
        policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
        category: "Productivity",
      });
      expect(f.invocations).toEqual([{ command: process.execPath, args: ["plugin", "add", "opencodex-subagent-bridge@my-personal-market"] }]);

      const token = readFileSync(join(f.configDir, "subagent-bridge-token"), "utf8").trim();
      expect(Buffer.from(token, "base64url")).toHaveLength(32);
      const config = readJson(join(f.configDir, "config.json"));
      expect(config.subagentBridge).toEqual({ enabled: true });
      expect(config.unrelatedSetting).toEqual({ preserve: true });
      expect(config.providers.custom.apiKey).toBe("keep-me");
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("reinstall replaces only its marketplace slot, refreshes cachebuster, and preserves the token", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      const tokenPath = join(f.configDir, "subagent-bridge-token");
      const firstToken = readFileSync(tokenPath, "utf8");
      writeFileSync(join(pluginDir, "stale.txt"), "remove on reinstall");
      f.options.now = () => new Date("2026-07-21T12:35:57Z");
      installSubagentBridge(f.options);

      expect(existsSync(join(pluginDir, "stale.txt"))).toBe(false);
      expect(readFileSync(tokenPath, "utf8")).toBe(firstToken);
      const marketplace = readJson(join(f.homeDir, ".agents", "plugins", "marketplace.json"));
      expect(marketplace.plugins.filter((entry: any) => entry.name === "opencodex-subagent-bridge")).toHaveLength(1);
      expect(marketplace.plugins.map((entry: any) => entry.name)).toEqual(["alpha", "omega", "opencodex-subagent-bridge"]);
      expect(readJson(join(pluginDir, ".codex-plugin", "plugin.json")).version)
        .toMatch(/^0\.1\.0\+codex\.local-20260721-123557\d{3}-\d+-\d+-[0-9a-f]{12}$/);
      expect(f.invocations).toHaveLength(2);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("status is read-only and content-free", () => {
    const f = fixture();
    const stdout: string[] = [];
    try {
      installSubagentBridge(f.options);
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const configPath = join(f.configDir, "config.json");
      const before = [readFileSync(marketplacePath, "utf8"), readFileSync(configPath, "utf8")];
      const status = statusSubagentBridge(f.options);
      expect(status).toMatchObject({ installed: true, enabled: true, tokenPresent: true, marketplaceReady: true, ready: true });
      expect(JSON.stringify(status)).not.toContain(readFileSync(join(f.configDir, "subagent-bridge-token"), "utf8").trim());
      expect([readFileSync(marketplacePath, "utf8"), readFileSync(configPath, "utf8")]).toEqual(before);
      expect(f.invocations).toHaveLength(1);
      expect(cmdSubagents(["bridge", "status"], {
        lifecycle: f.options,
        stdout: line => stdout.push(line),
      })).toBe(0);
      expect(stdout.join("\n")).toContain("Bridge installation: ready");
      expect(stdout.join("\n")).toContain("Runtime: not checked");
      expect(stdout.join("\n")).toContain("ocx health");
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("remove deletes only verified owned bridge state and preserves unrelated fields and order", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      mkdirSync(join(f.homeDir, "plugins", "unrelated"), { recursive: true });
      writeFileSync(join(f.homeDir, "plugins", "unrelated", "keep.txt"), "keep");

      const result = removeSubagentBridge(f.options);
      expect(result.removed).toBe(true);
      expect(existsSync(pluginDir)).toBe(false);
      expect(existsSync(join(f.homeDir, "plugins", "unrelated", "keep.txt"))).toBe(true);
      expect(existsSync(join(f.configDir, "subagent-bridge-token"))).toBe(false);
      const marketplace = readJson(join(f.homeDir, ".agents", "plugins", "marketplace.json"));
      expect(marketplace.plugins.map((entry: any) => entry.name)).toEqual(["alpha", "omega"]);
      expect(marketplace.interface).toEqual({ displayName: "My plugins", keep: "yes" });
      expect(marketplace.topLevelExtra).toEqual({ preserve: true });
      const config = readJson(join(f.configDir, "config.json"));
      expect(config.subagentBridge).toEqual({ enabled: false });
      expect(config.unrelatedSetting).toEqual({ preserve: true });
      expect(f.invocations.at(-1)).toEqual({ command: process.execPath, args: ["plugin", "remove", SELECTOR] });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("the remove CLI prints mandatory restart and new-task guidance", () => {
    const f = fixture();
    const stdout: string[] = [];
    try {
      installSubagentBridge(f.options);
      expect(cmdSubagents(["bridge", "remove"], {
        lifecycle: f.options,
        stdout: line => stdout.push(line),
      })).toBe(0);
      expect(stdout.join("\n")).toContain("ocx restart");
      expect(stdout.join("\n")).toContain("new task");
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("default process execution preserves a true argv boundary and never enables a shell", () => {
    let observed: { command?: string; args?: readonly string[]; shell?: boolean } = {};
    const result = runCodexCommand(process.execPath, ["plugin", "add", "bridge@personal"], ((command, args, options) => {
      observed = { command: String(command), args: args as string[], shell: options?.shell as boolean | undefined };
      return { status: 0 } as never;
    }) as never);
    expect(result.status).toBe(0);
    expect(observed).toEqual({
      command: process.execPath,
      args: ["plugin", "add", "bridge@personal"],
      shell: false,
    });
  });

  test("registration inspection uses bounded read-only argv and requires the exact installed/enabled selector", () => {
    let observed: { command?: string; args?: readonly string[]; shell?: boolean; timeout?: number; maxBuffer?: number } = {};
    const state = inspectCodexPluginRegistration(process.execPath, SELECTOR, ((command, args, options) => {
      observed = {
        command: String(command),
        args: args as string[],
        shell: options?.shell as boolean | undefined,
        timeout: options?.timeout as number | undefined,
        maxBuffer: options?.maxBuffer as number | undefined,
      };
      return {
        status: 0,
        stdout: JSON.stringify({ installed: [
          { pluginId: "opencodex-subagent-bridge@other-market", name: "opencodex-subagent-bridge", marketplaceName: "other-market", installed: true, enabled: true },
          { pluginId: SELECTOR, name: "opencodex-subagent-bridge", marketplaceName: "my-personal-market", installed: true, enabled: false },
        ] }),
      } as never;
    }) as never);
    expect(state).toEqual({ installed: true, enabled: false });
    expect(observed).toEqual({
      command: process.execPath,
      args: ["plugin", "list", "--json"],
      shell: false,
      timeout: 5_000,
      maxBuffer: 1024 * 1024,
    });
  });

  test("registration inspection treats a process timeout as unknown", () => {
    const timedOut = new Error("timed out") as NodeJS.ErrnoException;
    timedOut.code = "ETIMEDOUT";
    expect(inspectCodexPluginRegistration(process.execPath, SELECTOR, (() => ({
      status: null,
      stdout: "",
      error: timedOut,
    })) as never)).toBeNull();
  });

  test("registration inspection rejects malformed, duplicate, and oversized registration output", () => {
    const exact = {
      pluginId: SELECTOR,
      name: "opencodex-subagent-bridge",
      marketplaceName: "my-personal-market",
      installed: true,
      enabled: true,
    };
    const outputs = [
      '{"installed":',
      JSON.stringify({ installed: [{ ...exact, enabled: "yes" }] }),
      JSON.stringify({ installed: [exact, { ...exact }] }),
      JSON.stringify({ installed: [exact], padding: "x".repeat(1024 * 1024) }),
    ];
    for (const stdout of outputs) {
      expect(inspectCodexPluginRegistration(process.execPath, SELECTOR, (() => ({
        status: 0,
        stdout,
      })) as never)).toBeNull();
    }
  });

  test("first install refuses to claim an already-active exact registration without an owned record", () => {
    const f = fixture();
    try {
      f.registrations.set(SELECTOR, { installed: true, enabled: true });
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const configPath = join(f.configDir, "config.json");
      const before = [readFileSync(marketplacePath), readFileSync(configPath)];
      expect(() => installSubagentBridge(f.options)).toThrow(/already active|owned install record/i);
      expect([readFileSync(marketplacePath), readFileSync(configPath)]).toEqual(before);
      expect(f.invocations).toEqual([]);
      expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
      expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: true });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install and remove reject a valid owned record whose marketplace differs before mutation", () => {
    for (const action of [installSubagentBridge, removeSubagentBridge]) {
      const f = fixture();
      try {
        installSubagentBridge(f.options);
        const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
        const marketplace = readJson(marketplacePath);
        marketplace.name = "renamed-personal-market";
        writeFileSync(marketplacePath, `${JSON.stringify(marketplace, null, 2)}\n`);
        const paths = [
          marketplacePath,
          join(f.configDir, "config.json"),
          join(f.configDir, "subagent-bridge-token"),
          join(f.configDir, "subagent-bridge-install.json"),
          join(f.homeDir, "plugins", "opencodex-subagent-bridge", ".mcp.json"),
        ];
        const before = paths.map(path => readFileSync(path));
        const invocationCount = f.invocations.length;
        expect(() => action(f.options)).toThrow(/marketplace.*mismatch/i);
        expect(paths.map(path => readFileSync(path))).toEqual(before);
        expect(f.invocations).toHaveLength(invocationCount);
        expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: true });
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("an exclusive lifecycle lock rejects a concurrent remove until install completes", () => {
    const f = fixture();
    try {
      let nestedFailure = "";
      f.options.copyDir = (source, destination) => {
        try {
          removeSubagentBridge(f.options);
        } catch (error) {
          nestedFailure = error instanceof Error ? error.message : String(error);
        }
        cpSync(source, destination, { recursive: true });
      };
      const result = installSubagentBridge(f.options);
      expect(nestedFailure).toMatch(/lifecycle.*in progress|lock/i);
      expect(result.ready).toBe(true);
      expect(f.invocations.map(call => call.args[1])).toEqual(["add"]);
      expect(existsSync(join(f.configDir, LOCK_FILE))).toBe(false);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("stale lifecycle recovery requires owned metadata, sufficient age, and a dead PID", () => {
    const now = new Date("2026-07-21T12:34:56.000Z");
    const cases = [
      { name: "malformed", lock: Buffer.from("{not-json"), alive: false },
      {
        name: "live",
        lock: Buffer.from(JSON.stringify({ owner: "opencodex", plugin: "opencodex-subagent-bridge", version: 1, pid: 424242, createdAtMs: now.getTime() - 120_000, nonce: "00112233445566778899aabb" })),
        alive: true,
      },
      {
        name: "young",
        lock: Buffer.from(JSON.stringify({ owner: "opencodex", plugin: "opencodex-subagent-bridge", version: 1, pid: 424242, createdAtMs: now.getTime() - 1_000, nonce: "00112233445566778899aabb" })),
        alive: false,
      },
    ];
    for (const item of cases) {
      const f = fixture();
      try {
        f.options.now = () => now;
        (f.options as any).isProcessAlive = () => item.alive;
        const lockPath = join(f.configDir, LOCK_FILE);
        writeFileSync(lockPath, item.lock, { mode: 0o600 });
        expect(() => installSubagentBridge(f.options), item.name).toThrow(/lifecycle.*in progress|lock/i);
        expect(readFileSync(lockPath)).toEqual(item.lock);
        expect(f.invocations).toEqual([]);
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }

    const f = fixture();
    try {
      f.options.now = () => now;
      (f.options as any).isProcessAlive = () => false;
      const lockPath = join(f.configDir, LOCK_FILE);
      writeFileSync(lockPath, JSON.stringify({
        owner: "opencodex",
        plugin: "opencodex-subagent-bridge",
        version: 1,
        pid: 424242,
        createdAtMs: now.getTime() - 120_000,
        nonce: "00112233445566778899aabb",
      }), { mode: 0o600 });
      expect(installSubagentBridge(f.options).ready).toBe(true);
      expect(existsSync(lockPath)).toBe(false);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("Windows lifecycle lock recovery fails closed when owner or ACL inspection is unknown", () => {
    const f = fixture();
    try {
      const now = new Date("2026-07-21T12:34:56.000Z");
      f.options.now = () => now;
      f.options.isProcessAlive = () => false;
      f.options.inspectTokenSecurity = path => path.endsWith(LOCK_FILE) ? null : true;
      const lockPath = join(f.configDir, LOCK_FILE);
      const bytes = Buffer.from(JSON.stringify({
        owner: "opencodex",
        plugin: "opencodex-subagent-bridge",
        version: 1,
        pid: 424242,
        createdAtMs: now.getTime() - 120_000,
        nonce: "00112233445566778899aabb",
      }));
      writeFileSync(lockPath, bytes, { mode: 0o600 });
      expect(() => installSubagentBridge(f.options)).toThrow(/lifecycle.*in progress|lock/i);
      expect(readFileSync(lockPath)).toEqual(bytes);
      expect(f.invocations).toEqual([]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("cachebuster versions remain unique for installs in the same millisecond", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const manifestPath = join(f.homeDir, "plugins", "opencodex-subagent-bridge", ".codex-plugin", "plugin.json");
      const first = readJson(manifestPath).version;
      installSubagentBridge(f.options);
      const second = readJson(manifestPath).version;
      expect(first).not.toBe(second);
      expect(first).toMatch(/codex\.local-\d{8}-\d{9}-\d+-\d+-[0-9a-f]{12}$/);
      expect(second).toMatch(/codex\.local-\d{8}-\d{9}-\d+-\d+-[0-9a-f]{12}$/);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install rejects bundles with a foreign manifest declaration, extra MCP server, or empty handoff skill", () => {
    const corruptions: Array<(dir: string) => void> = [
      dir => {
        const path = join(dir, ".codex-plugin", "plugin.json");
        const manifest = readJson(path);
        manifest.mcpServers = "./foreign.json";
        writeFileSync(path, JSON.stringify(manifest));
      },
      dir => {
        const path = join(dir, ".mcp.json");
        const mcp = readJson(path);
        mcp.mcpServers.foreign = { command: "foreign", args: [] };
        writeFileSync(path, JSON.stringify(mcp));
      },
      dir => writeFileSync(join(dir, "skills", "subagent-handoff", "SKILL.md"), " \n"),
    ];
    for (const corrupt of corruptions) {
      const f = fixture();
      try {
        const customBundle = join(f.root, "bundle");
        cpSync(bundleDir, customBundle, { recursive: true });
        corrupt(customBundle);
        f.options.bundleDir = customBundle;
        expect(() => installSubagentBridge(f.options)).toThrow(/manifest|MCP|handoff skill/i);
        expect(f.invocations).toEqual([]);
        expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("status fails closed for an invalid installed manifest, non-exact MCP declaration, or empty handoff skill", () => {
    const corruptions: Array<(dir: string) => void> = [
      dir => {
        const path = join(dir, ".codex-plugin", "plugin.json");
        const manifest = readJson(path);
        manifest.skills = "./foreign-skills/";
        writeFileSync(path, JSON.stringify(manifest));
      },
      dir => {
        const path = join(dir, ".mcp.json");
        const mcp = readJson(path);
        mcp.mcpServers.foreign = { command: process.execPath, args: [cliPath, "__subagent-bridge-mcp"] };
        writeFileSync(path, JSON.stringify(mcp));
      },
      dir => writeFileSync(join(dir, "skills", "subagent-handoff", "SKILL.md"), ""),
    ];
    for (const corrupt of corruptions) {
      const f = fixture();
      try {
        installSubagentBridge(f.options);
        const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
        corrupt(pluginDir);
        expect(statusSubagentBridge(f.options)).toMatchObject({ mcpReady: false, ready: false });
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("the secure bridge-token reader rejects POSIX symlinks, weak mode, and foreign ownership", () => {
    const f = fixture();
    try {
      const tokenPath = join(f.configDir, "subagent-bridge-token");
      const token = Buffer.alloc(32, 7).toString("base64url");
      writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
      const uid = lstatSync(tokenPath).uid;
      const regular = { uid, mode: 0o100600, isFile: () => true, isSymbolicLink: () => false };
      expect(isSecurePosixBridgeTokenFile(regular, uid)).toBe(true);
      expect(isSecurePosixBridgeTokenFile({ ...regular, mode: 0o100640 }, uid)).toBe(false);
      expect(isSecurePosixBridgeTokenFile(regular, uid + 1)).toBe(false);
      expect(isSecurePosixBridgeTokenFile({ ...regular, isSymbolicLink: () => true }, uid)).toBe(false);
      if (process.platform !== "win32") {
        expect(readSecureSubagentBridgeToken({ configDir: f.configDir, platform: "linux", expectedUid: uid })).toBe(token);
      }
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("the explicit Windows migration reader fails closed when ACL state is insecure, unknown, or inspection throws", () => {
    const f = fixture();
    try {
      const tokenPath = join(f.configDir, "subagent-bridge-token");
      const token = Buffer.alloc(32, 9).toString("base64url");
      writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
      const migration = { tokenPath, platform: "win32" as const, allowWindowsAclMigration: true };
      expect(readSecureSubagentBridgeToken({ ...migration, inspectTokenSecurity: () => true })).toBe(token);
      expect(readSecureSubagentBridgeToken({ ...migration, inspectTokenSecurity: () => false })).toBeNull();
      expect(readSecureSubagentBridgeToken({ ...migration, inspectTokenSecurity: () => null })).toBeNull();
      expect(readSecureSubagentBridgeToken({ ...migration, inspectTokenSecurity: () => { throw new Error("probe failed"); } })).toBeNull();
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install refuses an existing insecure bridge token before reading it into a transaction snapshot", () => {
    const f = fixture();
    try {
      const tokenPath = join(f.configDir, "subagent-bridge-token");
      const tokenBytes = Buffer.from(`${Buffer.alloc(32, 5).toString("base64url")}\n`);
      writeFileSync(tokenPath, tokenBytes, { mode: 0o600 });
      f.options.inspectTokenSecurity = path => path.endsWith(LOCK_FILE) ? true : false;
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const configPath = join(f.configDir, "config.json");
      const before = [readFileSync(marketplacePath), readFileSync(configPath)];
      expect(() => installSubagentBridge(f.options)).toThrow(/existing bridge token.*insecure|secure token/i);
      expect(readFileSync(tokenPath)).toEqual(tokenBytes);
      expect([readFileSync(marketplacePath), readFileSync(configPath)]).toEqual(before);
      expect(f.invocations).toEqual([]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install rejects hostile marketplace identifiers and foreign same-name collisions before mutation", () => {
    for (const entry of [
      { name: "alpha", source: { source: "local", path: "./plugins/alpha" } },
      { name: "opencodex-subagent-bridge", source: { source: "git", url: "https://example.test/foreign.git" } },
    ]) {
      const f = fixture();
      try {
        const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
        const marketplace = readJson(marketplacePath);
        if (entry.name === "alpha") marketplace.name = "personal & calc.exe";
        else marketplace.plugins.push(entry);
        const before = `${JSON.stringify(marketplace, null, 2)}\n`;
        writeFileSync(marketplacePath, before);
        const configBefore = readFileSync(join(f.configDir, "config.json"));
        expect(() => installSubagentBridge(f.options)).toThrow();
        expect(readFileSync(marketplacePath, "utf8")).toBe(before);
        expect(readFileSync(join(f.configDir, "config.json"))).toEqual(configBefore);
        expect(f.invocations).toEqual([]);
        expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("install and remove refuse malformed config byte-for-byte before any mutation", () => {
    for (const action of [installSubagentBridge, removeSubagentBridge]) {
      const f = fixture();
      try {
        const configPath = join(f.configDir, "config.json");
        const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
        const malformed = Buffer.from('{"providers":');
        writeFileSync(configPath, malformed);
        const marketplaceBefore = readFileSync(marketplacePath);
        expect(() => action(f.options)).toThrow("config");
        expect(readFileSync(configPath)).toEqual(malformed);
        expect(readFileSync(marketplacePath)).toEqual(marketplaceBefore);
        expect(f.invocations).toEqual([]);
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("install refuses a malformed owned registration record before staging", () => {
    const f = fixture();
    try {
      const recordPath = join(f.configDir, "subagent-bridge-install.json");
      const malformed = Buffer.from('{"owner":"opencodex"');
      writeFileSync(recordPath, malformed);
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const before = readFileSync(marketplacePath);
      expect(() => installSubagentBridge(f.options)).toThrow("install record");
      expect(readFileSync(recordPath)).toEqual(malformed);
      expect(readFileSync(marketplacePath)).toEqual(before);
      expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
      expect(f.invocations).toEqual([]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("failed reinstall registration restores the working install and every owned file byte-for-byte", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      const paths = [
        join(f.configDir, "config.json"),
        join(f.configDir, "subagent-bridge-token"),
        join(f.configDir, "subagent-bridge-install.json"),
        join(f.homeDir, ".agents", "plugins", "marketplace.json"),
        join(pluginDir, ".codex-plugin", "plugin.json"),
        join(pluginDir, ".mcp.json"),
      ];
      const before = new Map(paths.map(path => [path, readFileSync(path)]));
      f.options.now = () => new Date("2026-07-21T12:59:59Z");
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        return { status: args[1] === "add" ? 1 : 0 };
      };
      expect(() => installSubagentBridge(f.options)).toThrow("plugin add failed");
      for (const [path, bytes] of before) expect(readFileSync(path)).toEqual(bytes);
      expect(existsSync(join(pluginDir, "stale.txt"))).toBe(false);
      expect(f.invocations.at(-1)?.args).toEqual(["plugin", "add", SELECTOR]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("copy and write failures leave pre-existing marketplace and config bytes untouched", () => {
    for (const failure of ["copy", "marketplace-write"] as const) {
      const f = fixture();
      try {
        const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
        const configPath = join(f.configDir, "config.json");
        const before = [readFileSync(marketplacePath), readFileSync(configPath)];
        if (failure === "copy") {
          f.options.copyDir = () => { throw new Error("copy injected failure"); };
        } else {
          f.options.writeBytes = (path, bytes, secret) => {
            if (path === marketplacePath) throw new Error("write injected failure");
            mkdirSync(dirname(path), { recursive: true });
            writeFileSync(path, bytes, { mode: secret ? 0o600 : undefined });
          };
        }
        expect(() => installSubagentBridge(f.options)).toThrow("injected failure");
        expect([readFileSync(marketplacePath), readFileSync(configPath)]).toEqual(before);
        expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
        expect(f.invocations).toEqual([]);
      } finally {
        rmSync(f.root, { recursive: true, force: true });
      }
    }
  });

  test("failed remove registration restores directory, marketplace, config, token, and registration", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      writeFileSync(join(pluginDir, "working.txt"), "working-install");
      const paths = [
        join(f.configDir, "config.json"),
        join(f.configDir, "subagent-bridge-token"),
        join(f.configDir, "subagent-bridge-install.json"),
        join(f.homeDir, ".agents", "plugins", "marketplace.json"),
        join(pluginDir, "working.txt"),
      ];
      const before = new Map(paths.map(path => [path, readFileSync(path)]));
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        return { status: args[1] === "remove" ? 1 : 0 };
      };
      expect(() => removeSubagentBridge(f.options)).toThrow("plugin remove failed");
      for (const [path, bytes] of before) expect(readFileSync(path)).toEqual(bytes);
      expect(f.invocations.at(-1)?.args).toEqual(["plugin", "remove", SELECTOR]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("status requires an owned registration, real launcher paths, and secure POSIX token mode", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      const installRecord = join(f.configDir, "subagent-bridge-install.json");
      rmSync(installRecord);
      expect(statusSubagentBridge(f.options)).toMatchObject({ registered: false, ready: false });

      writeFileSync(installRecord, JSON.stringify({ owner: "opencodex", plugin: "opencodex-subagent-bridge", marketplace: "my-personal-market", version: 1 }));
      f.registrations.delete(SELECTOR);
      f.registrations.set("opencodex-subagent-bridge@other-market", { installed: true, enabled: true });
      expect(statusSubagentBridge(f.options)).toMatchObject({ registered: false, ready: false });
      f.registrations.set(SELECTOR, { installed: true, enabled: true });
      const mcpPath = join(f.homeDir, "plugins", "opencodex-subagent-bridge", ".mcp.json");
      writeFileSync(mcpPath, JSON.stringify({ mcpServers: { "opencodex-subagent-bridge": { command: join(f.root, "missing-runtime"), args: [join(f.root, "missing-cli"), "__subagent-bridge-mcp"] } } }));
      expect(statusSubagentBridge(f.options)).toMatchObject({ registered: true, mcpReady: false, ready: false });

      writeFileSync(mcpPath, JSON.stringify({ mcpServers: { "opencodex-subagent-bridge": { command: process.execPath, args: [cliPath, "__subagent-bridge-mcp", "extra"] } } }));
      expect(statusSubagentBridge(f.options)).toMatchObject({ mcpReady: false, ready: false });

      writeFileSync(mcpPath, JSON.stringify({ mcpServers: { "opencodex-subagent-bridge": { command: cliPath, args: [cliPath, "__subagent-bridge-mcp"] } } }));
      expect(statusSubagentBridge(f.options)).toMatchObject({ mcpReady: false, ready: false });

      writeFileSync(mcpPath, JSON.stringify({ mcpServers: { "opencodex-subagent-bridge": { command: process.execPath, args: [cliPath, "__subagent-bridge-mcp"] } } }));
      chmodSync(join(f.configDir, "subagent-bridge-token"), 0o644);
      f.options.platform = "linux";
      f.options.expectedUid = lstatSync(join(f.configDir, "subagent-bridge-token")).uid;
      delete f.options.inspectTokenSecurity;
      expect(statusSubagentBridge(f.options)).toMatchObject({ tokenPresent: true, tokenSecure: false, ready: false });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install compensation changes only the exact selector when inspection proves a transition", () => {
    const f = fixture();
    try {
      let inspections = 0;
      f.options.inspectRegistration = (_command, selector) => {
        inspections += 1;
        return f.registrations.get(selector) ?? { installed: false, enabled: false };
      };
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        if (args[1] === "add") {
          f.registrations.set(SELECTOR, { installed: true, enabled: true });
          return { status: 1 };
        }
        if (args[1] === "remove") f.registrations.delete(args[2]!);
        return { status: 0 };
      };
      expect(() => installSubagentBridge(f.options)).toThrow("plugin add failed");
      expect(f.invocations.map(item => item.args)).toEqual([
        ["plugin", "add", SELECTOR],
        ["plugin", "remove", SELECTOR],
      ]);
      expect(inspections).toBe(3);
      expect(f.registrations.get(SELECTOR)).toBeUndefined();
      expect(f.registrations.has("opencodex-subagent-bridge@other-market")).toBe(false);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install fails honestly when compensation does not restore the inspected exact state", () => {
    const f = fixture();
    try {
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        if (args[1] === "add") f.registrations.set(SELECTOR, { installed: true, enabled: true });
        return { status: args[1] === "add" ? 1 : 0 };
      };
      expect(() => installSubagentBridge(f.options)).toThrow("registration compensation failed");
      expect(f.invocations.map(item => item.args)).toEqual([
        ["plugin", "add", SELECTOR],
        ["plugin", "remove", SELECTOR],
      ]);
      expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: true });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install refuses a disabled exact registration before mutating local or Codex state", () => {
    const f = fixture();
    try {
      f.registrations.set(SELECTOR, { installed: true, enabled: false });
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const configPath = join(f.configDir, "config.json");
      const before = [readFileSync(marketplacePath), readFileSync(configPath)];
      expect(() => installSubagentBridge(f.options)).toThrow("disabled");
      expect([readFileSync(marketplacePath), readFileSync(configPath)]).toEqual(before);
      expect(existsSync(join(f.homeDir, "plugins", "opencodex-subagent-bridge"))).toBe(false);
      expect(f.invocations).toEqual([]);
      expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: false });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("remove refuses a disabled exact registration before mutating any owned state", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      f.registrations.set(SELECTOR, { installed: true, enabled: false });
      const paths = [
        join(f.configDir, "config.json"),
        join(f.configDir, "subagent-bridge-token"),
        join(f.configDir, "subagent-bridge-install.json"),
        join(f.homeDir, ".agents", "plugins", "marketplace.json"),
        join(f.homeDir, "plugins", "opencodex-subagent-bridge", ".mcp.json"),
      ];
      const before = paths.map(path => readFileSync(path));
      const invocationCount = f.invocations.length;
      expect(() => removeSubagentBridge(f.options)).toThrow("disabled");
      expect(paths.map(path => readFileSync(path))).toEqual(before);
      expect(f.invocations).toHaveLength(invocationCount);
      expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: false });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("remove rollback re-adds the exact selector only after inspection confirms removal", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        if (args[1] === "remove") {
          f.registrations.delete(args[2]!);
          return { status: 1 };
        }
        if (args[1] === "add") f.registrations.set(args[2]!, { installed: true, enabled: true });
        return { status: 0 };
      };
      expect(() => removeSubagentBridge(f.options)).toThrow("plugin remove failed");
      expect(f.invocations.slice(-2).map(item => item.args)).toEqual([
        ["plugin", "remove", SELECTOR],
        ["plugin", "add", SELECTOR],
      ]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("failed reinstall re-adds only when inspection proves the exact prior selector disappeared", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      let failedAdd = false;
      f.options.runCodex = (command, args) => {
        f.invocations.push({ command, args });
        if (args[1] === "add" && !failedAdd) {
          failedAdd = true;
          f.registrations.delete(args[2]!);
          return { status: 1 };
        }
        if (args[1] === "add") f.registrations.set(args[2]!, { installed: true, enabled: true });
        return { status: 0 };
      };
      expect(() => installSubagentBridge(f.options)).toThrow("plugin add failed");
      expect(f.invocations.slice(-2).map(item => item.args)).toEqual([
        ["plugin", "add", SELECTOR],
        ["plugin", "add", SELECTOR],
      ]);
      expect(f.registrations.get(SELECTOR)).toEqual({ installed: true, enabled: true });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("install fails closed when secret ACL hardening reports failure", () => {
    const f = fixture();
    try {
      f.options.hardenSecret = path => !path.endsWith("subagent-bridge-token");
      expect(() => installSubagentBridge(f.options)).toThrow("token ACL hardening failed");
      expect(existsSync(join(f.configDir, "subagent-bridge-token"))).toBe(false);
      expect(f.invocations).toEqual([]);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("CLI authentication status validates the attestation without repeated ACL inspection", () => {
    const f = fixture();
    try {
      installSubagentBridge(f.options);
      let inspections = 0;
      f.options.inspectTokenSecurity = () => {
        inspections += 1;
        return false;
      };
      const stdout: string[] = [];
      expect(cmdSubagents(["bridge", "status"], { lifecycle: f.options, stdout: line => stdout.push(line) })).toBe(0);
      expect(stdout.join("\n")).toContain("Authentication: secure");
      expect(inspections).toBe(0);
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("remove refuses an unowned target directory", () => {
    const f = fixture();
    try {
      const pluginDir = join(f.homeDir, "plugins", "opencodex-subagent-bridge");
      mkdirSync(pluginDir, { recursive: true });
      writeFileSync(join(pluginDir, "user-file.txt"), "must survive");
      expect(() => removeSubagentBridge(f.options)).toThrow("not owned");
      expect(readFileSync(join(pluginDir, "user-file.txt"), "utf8")).toBe("must survive");
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });

  test("remove preserves a same-named marketplace entry with a foreign source", () => {
    const f = fixture();
    try {
      const marketplacePath = join(f.homeDir, ".agents", "plugins", "marketplace.json");
      const marketplace = readJson(marketplacePath);
      marketplace.plugins.push({
        name: "opencodex-subagent-bridge",
        source: { source: "git", url: "https://example.test/foreign.git" },
        foreign: true,
      });
      writeFileSync(marketplacePath, JSON.stringify(marketplace, null, 2));
      removeSubagentBridge(f.options);
      const after = readJson(marketplacePath);
      expect(after.plugins.at(-1)).toMatchObject({ name: "opencodex-subagent-bridge", foreign: true });
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  });
});
