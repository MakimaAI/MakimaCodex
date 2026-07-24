import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getConfigPath } from "../src/config";
import { handleManagementAPI } from "../src/server/management-api";
import * as bridgeStatusInspector from "../src/subagent-bridge/status-inspector";
import type { OcxConfig } from "../src/types";

const repoRoot = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
let previousOpenCodexHome: string | undefined;
let isolatedOpenCodexHome = "";

beforeEach(() => {
  previousOpenCodexHome = process.env.OPENCODEX_HOME;
  isolatedOpenCodexHome = mkdtempSync(join(tmpdir(), "ocx-subagent-surface-"));
  process.env.OPENCODEX_HOME = isolatedOpenCodexHome;
});

afterEach(() => {
  if (previousOpenCodexHome === undefined) delete process.env.OPENCODEX_HOME;
  else process.env.OPENCODEX_HOME = previousOpenCodexHome;
  if (isolatedOpenCodexHome) rmSync(isolatedOpenCodexHome, { recursive: true, force: true });
  isolatedOpenCodexHome = "";
});

function config(): OcxConfig {
  return {
    port: 10100,
    defaultProvider: "routed",
    providers: {
      routed: {
        adapter: "openai-chat",
        baseUrl: "https://example.test/v1",
        apiKey: "test",
        models: ["eligible", "not-featured"],
        reasoningEfforts: ["low", "high"],
      },
    },
    subagentModels: ["gpt-5.6-sol", "routed/eligible"],
    subagentBridge: { enabled: true },
  } as OcxConfig;
}

describe("subagent bridge management metadata", () => {
  test("API live readiness accepts only normalized literal-loopback bind endpoints", async () => {
    const cases = [
      { hostname: undefined, ready: true },
      { hostname: "localhost", ready: true },
      { hostname: "127.0.0.1", ready: true },
      { hostname: "::1", ready: true },
      { hostname: "0.0.0.0", ready: false },
      { hostname: "::", ready: false },
      { hostname: "proxy.local", ready: false },
    ] as const;

    for (const entry of cases) {
      const cfg = config();
      cfg.hostname = entry.hostname;
      const response = await handleManagementAPI(
        new Request("http://localhost/api/subagent-bridge"),
        new URL("http://localhost/api/subagent-bridge"),
        cfg,
        { subagentBridgeStatus: () => ({ installed: true, enabled: true, tokenPresent: true, marketplaceReady: true, ready: true, warnings: [] }) },
      );
      const body = await response!.json() as any;
      expect(body).toMatchObject({ ready: entry.ready, liveReady: entry.ready });
      if (entry.ready) expect(body.warnings).toEqual([]);
      else expect(body.warnings).toContain("Subagent bridge requires a literal loopback proxy bind (127.0.0.1 or ::1).");
    }
  });

  test("GET preserves chosen/available and adds stable V2 classification/readiness metadata", async () => {
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-models"),
      new URL("http://localhost/api/subagent-models"),
      config(),
      {
        subagentBridgeStatus: () => ({ installed: true, enabled: true, tokenPresent: true, marketplaceReady: true, ready: true, warnings: [] }),
        subagentV2Efforts: slugs => new Map(slugs.filter(slug => slug === "gpt-5.6-sol" || slug === "routed/eligible").map(slug => [slug, ["low", "high"]])),
      },
    );
    expect(response?.status).toBe(200);
    const body = await response!.json() as any;
    expect(body.chosen).toEqual(["gpt-5.6-sol", "routed/eligible"]);
    expect(body.available).toContain("gpt-5.6-sol");
    expect(body.available).toContain("routed/eligible");
    expect(body.bridge).toMatchObject({ enabled: true, ready: true, requiredForRoutedV2: true });
    expect(body.warnings).toEqual([]);
    expect(body.models.find((row: any) => row.id === "gpt-5.6-sol")).toMatchObject({
      classification: "native", bridgeRequired: false, bridgeReady: true, v2Eligible: true, ready: true,
    });
    expect(body.models.find((row: any) => row.id === "routed/eligible")).toMatchObject({
      classification: "routed", bridgeRequired: true, bridgeReady: true, v2Eligible: true, ready: true,
    });
    expect(body.models.find((row: any) => row.id === "routed/not-featured")).toMatchObject({
      classification: "routed", bridgeRequired: true, v2Eligible: false,
    });
  });

  test("catalog V2 eligibility remains true while separate overall readiness reflects a disabled bridge", async () => {
    const cfg = config();
    cfg.subagentBridge = { enabled: false };
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-models"),
      new URL("http://localhost/api/subagent-models"),
      cfg,
      {
        subagentBridgeStatus: () => ({ installed: true, enabled: false, tokenPresent: true, marketplaceReady: true, ready: false, warnings: [] }),
        subagentV2Efforts: slugs => new Map(slugs.filter(slug => slug === "routed/eligible").map(slug => [slug, ["high"]])),
      },
    );
    const body = await response!.json() as any;
    const routed = body.models.find((row: any) => row.id === "routed/eligible");
    expect(routed).toMatchObject({
      selected: true,
      v2Eligible: true,
      bridgeRequired: true,
      bridgeReady: false,
      ready: false,
      reasoningEfforts: ["high"],
    });
  });

  test("PUT preserves ok/applied and reports bridge warnings when routed V2 is not ready", async () => {
    const cfg = config();
    cfg.subagentBridge = { enabled: false };
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-models", {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ models: ["routed/eligible"] }),
      }),
      new URL("http://localhost/api/subagent-models"),
      cfg,
      {
        refreshCodexCatalog: async () => {},
        subagentBridgeStatus: () => ({ installed: false, enabled: false, tokenPresent: false, marketplaceReady: false, ready: false, warnings: ["Bridge plugin is not installed."] }),
        subagentV2Efforts: () => new Map(),
      },
    );
    const body = await response!.json() as any;
    expect(body.ok).toBe(true);
    expect(body.applied).toEqual(["routed/eligible"]);
    expect(body.bridge).toMatchObject({ ready: false, requiredForRoutedV2: true });
    expect(body.models[0]).toMatchObject({ id: "routed/eligible", classification: "routed", v2Eligible: false });
    expect(body.warnings).toContain("Bridge plugin is not installed.");
    expect(getConfigPath()).toBe(join(isolatedOpenCodexHome, "config.json"));
    expect(JSON.parse(readFileSync(getConfigPath(), "utf8"))).toMatchObject({
      defaultProvider: "routed",
      subagentModels: ["routed/eligible"],
    });
  });

  test("routed eligibility is false when Task 1's live catalog gate has no V2 effort entry", async () => {
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-models"),
      new URL("http://localhost/api/subagent-models"),
      config(),
      {
        subagentBridgeStatus: () => ({ installed: true, enabled: true, tokenPresent: true, marketplaceReady: true, ready: true, warnings: [] }),
        subagentV2Efforts: slugs => new Map(slugs.filter(slug => slug === "gpt-5.6-sol").map(slug => [slug, ["low"]])),
      },
    );
    const body = await response!.json() as any;
    const routed = body.models.find((row: any) => row.id === "routed/eligible");
    expect(routed).toMatchObject({ classification: "routed", v2Eligible: false, reasoningEfforts: [] });
    expect(routed.warnings).toContain("Model is not V2-eligible in the active Codex catalog.");
  });

  test("GET /api/subagent-bridge is content-free installation and health state", async () => {
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-bridge"),
      new URL("http://localhost/api/subagent-bridge"),
      config(),
      { subagentBridgeStatus: () => ({ installed: true, enabled: true, tokenPresent: true, marketplaceReady: true, ready: true, warnings: [] }) },
    );
    const text = await response!.text();
    expect(response?.status).toBe(200);
    expect(JSON.parse(text)).toMatchObject({
      installed: true,
      enabled: true,
      tokenPresent: true,
      marketplaceReady: true,
      ready: true,
      liveReady: true,
      restartRequired: false,
      warnings: [],
    });
    expect(text).not.toContain("message");
    expect(text).not.toContain("token\":");
  });

  test("installed disk readiness stays visible while the active disabled proxy reports restart required", async () => {
    const cfg = config();
    cfg.subagentBridge = { enabled: false };
    const response = await handleManagementAPI(
      new Request("http://localhost/api/subagent-bridge"),
      new URL("http://localhost/api/subagent-bridge"),
      cfg,
      {
        subagentBridgeStatus: () => ({
          installed: true,
          registered: true,
          enabled: true,
          tokenPresent: true,
          tokenSecure: true,
          marketplaceReady: true,
          mcpReady: true,
          ready: true,
          warnings: [],
        }),
      },
    );
    const body = await response!.json() as any;
    expect(body).toMatchObject({
      installed: true,
      installedReady: true,
      ready: false,
      liveReady: false,
      restartRequired: true,
    });
  });

  test("isolated status inspection cannot block the main event loop while its inspector is slow", async () => {
    const inspect = (bridgeStatusInspector as any).inspectSubagentBridgeStatusIsolated;
    expect(typeof inspect).toBe("function");
    if (typeof inspect !== "function") return;
    const statusPromise = inspect({
      workerUrl: new URL("./fixtures/subagent-status-slow-worker.ts", import.meta.url),
      timeoutMs: 2_000,
      cacheTtlMs: 0,
    });
    const first = await Promise.race([
      statusPromise.then(() => "status"),
      new Promise<string>(resolve => setTimeout(() => resolve("data-plane"), 20)),
    ]);
    expect(first).toBe("data-plane");
    expect(await statusPromise).toMatchObject({ installed: true, ready: true });
  });
});

describe("bundled subagent bridge plugin and package surface", () => {
  test("plugin bundle declares one MCP server and explicit immediate-before-native-tool guidance", () => {
    const pluginDir = join(repoRoot, "plugins", "opencodex-subagent-bridge");
    const manifest = JSON.parse(readFileSync(join(pluginDir, ".codex-plugin", "plugin.json"), "utf8"));
    const mcp = JSON.parse(readFileSync(join(pluginDir, ".mcp.json"), "utf8"));
    const guidance = readFileSync(join(pluginDir, "skills", "subagent-handoff", "SKILL.md"), "utf8");
    expect(manifest.name).toBe("opencodex-subagent-bridge");
    expect(manifest.mcpServers).toBe("./.mcp.json");
    expect(Object.keys(mcp.mcpServers)).toEqual(["opencodex-subagent-bridge"]);
    expect(mcp.mcpServers["opencodex-subagent-bridge"]).toEqual({ command: "ocx", args: ["__subagent-bridge-mcp"] });
    expect(guidance).toContain("immediately before");
    expect(guidance).toContain("prepare_subagent_handoff");
    expect(guidance).toContain("spawn_agent");
    expect(guidance).toContain("send_message");
    expect(guidance).toContain("followup_task");
    expect(guidance).toContain("Never prepare a handoff for a native model");
    expect(guidance).toContain("If preparation fails");
    expect(guidance).toContain("do not call the collaboration tool");
    expect(guidance).toContain("subagent_handoff_missing");
    expect(guidance).toContain("ocx health");
    expect(guidance).toContain("ocx restart");
    expect(guidance).toContain("start a new Codex task");
    expect(guidance).toContain("retry once");
  });

  test("npm package allowlist includes the complete plugin directory", () => {
    const pkg = JSON.parse(readFileSync(join(repoRoot, "package.json"), "utf8"));
    expect(pkg.files).toContain("plugins/opencodex-subagent-bridge");
  });
});
