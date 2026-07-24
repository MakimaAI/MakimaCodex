import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, test } from "bun:test";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startServer } from "../src/server";
import { hardenSecretPath } from "../src/lib/windows-secret-acl";
import { SubagentHandoffStore, subagentHandoffStore } from "../src/subagent-bridge/handoff-store";
import {
  createSubagentBridgeMcpServer,
  type PrepareSubagentHandoff,
} from "../src/subagent-bridge/mcp";
import * as mcpModule from "../src/subagent-bridge/mcp";
import * as runtimeModule from "../src/subagent-bridge/runtime";
import * as httpModule from "../src/subagent-bridge/http";
import * as lifecycleModule from "../src/subagent-bridge/lifecycle";
import { handleSubagentHandoffRequest } from "../src/subagent-bridge/http";
import {
  createSubagentBridgeHealthProof,
  createSubagentBridgeRequestSignature,
  sealSubagentBridgeRequestBody,
  SUBAGENT_BRIDGE_INSTANCE_HEADER,
  SUBAGENT_BRIDGE_ISSUED_AT_HEADER,
  SUBAGENT_BRIDGE_REQUEST_ID_HEADER,
  SUBAGENT_BRIDGE_SIGNATURE_HEADER,
  SubagentBridgeReplayGuard,
} from "../src/subagent-bridge/auth";

const SECRET_MESSAGE = "handoff-message-must-never-leak";
const TARGET_LEAF = "reviewer_abcdef012345";
const TARGET_CANONICAL = `/root/${TARGET_LEAF}`;
const prepareViaProxy = (input: any, deps?: any) => (mcpModule as any).prepareViaProxy(input, deps);
const HANDLER_TOKEN = Buffer.alloc(32, 61).toString("base64url");
const HANDLER_INSTANCE = Buffer.alloc(32, 62).toString("base64url");
const HANDLER_NOW_MS = 5_000_000;
let handlerRequestSequence = 0;

function signedHandlerRequest(
  bodyText: string,
  options: { body?: BodyInit; signingToken?: string; includeSignature?: boolean } = {},
): Request {
  const requestId = Buffer.alloc(32, ++handlerRequestSequence).toString("base64url");
  const signingToken = options.signingToken ?? HANDLER_TOKEN;
  const wireBody = sealSubagentBridgeRequestBody({
    token: signingToken,
    protocol: (runtimeModule as any).SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    method: "POST",
    path: "/internal/subagent-handoffs",
    instanceId: HANDLER_INSTANCE,
    requestId,
    issuedAtMs: HANDLER_NOW_MS,
    body: bodyText,
    randomBytesFn: () => Buffer.from(requestId, "base64url").subarray(0, 12),
  });
  if (!wireBody) throw new Error("test request sealing failed");
  const signature = createSubagentBridgeRequestSignature({
    token: signingToken,
    protocol: (runtimeModule as any).SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    method: "POST",
    path: "/internal/subagent-handoffs",
    instanceId: HANDLER_INSTANCE,
    requestId,
    issuedAtMs: HANDLER_NOW_MS,
    body: wireBody,
  });
  return new Request("http://localhost/internal/subagent-handoffs", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [SUBAGENT_BRIDGE_INSTANCE_HEADER]: HANDLER_INSTANCE,
      [SUBAGENT_BRIDGE_REQUEST_ID_HEADER]: requestId,
      [SUBAGENT_BRIDGE_ISSUED_AT_HEADER]: String(HANDLER_NOW_MS),
      ...(options.includeSignature === false ? {} : { [SUBAGENT_BRIDGE_SIGNATURE_HEADER]: signature! }),
    },
    body: options.body ?? wireBody,
  });
}

function signedHandlerDeps(store: SubagentHandoffStore, overrides: Record<string, unknown> = {}): any {
  return {
    readToken: () => HANDLER_TOKEN,
    runtimeEligible: true,
    instanceId: HANDLER_INSTANCE,
    replayGuard: new SubagentBridgeReplayGuard(),
    now: () => HANDLER_NOW_MS,
    store,
    ...overrides,
  };
}

function bodyText(result: { content: Array<{ type: string; text?: string }> }): string {
  return result.content.map(item => item.type === "text" ? item.text ?? "" : "").join("\n");
}

describe("subagent bridge internal API", () => {
  test("live health capability follows the normalized actual bind endpoint", async () => {
    const cases = [
      { configured: undefined, urlHost: "127.0.0.1", eligible: true },
      { configured: "localhost", urlHost: "127.0.0.1", eligible: true },
      { configured: "127.0.0.1", urlHost: "127.0.0.1", eligible: true },
      { configured: "::1", urlHost: "[::1]", eligible: true },
      { configured: "0.0.0.0", urlHost: "127.0.0.1", eligible: false },
    ] as const;

    for (const entry of cases) {
      const opencodexHome = mkdtempSync(join(tmpdir(), "ocx-bridge-bind-health-"));
      const previousHome = process.env.OPENCODEX_HOME;
      const previousApiToken = process.env.OPENCODEX_API_AUTH_TOKEN;
      process.env.OPENCODEX_HOME = opencodexHome;
      process.env.OPENCODEX_API_AUTH_TOKEN = "bind-health-test-token";
      writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
        port: 0,
        ...(entry.configured === undefined ? {} : { hostname: entry.configured }),
        providers: {
          openai: {
            adapter: "openai-responses",
            baseUrl: "https://chatgpt.com/backend-api/codex",
            authMode: "forward",
          },
        },
        defaultProvider: "openai",
        subagentBridge: { enabled: true },
      }));
      const server = startServer(0);
      try {
        const response = await fetch(`http://${entry.urlHost}:${server.port}/healthz`);
        expect(response.status).toBe(200);
        expect(await response.json()).toMatchObject({
          subagentBridge: { eligible: entry.eligible },
        });
      } finally {
        await server.stop(true);
        if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
        else process.env.OPENCODEX_HOME = previousHome;
        if (previousApiToken === undefined) delete process.env.OPENCODEX_API_AUTH_TOKEN;
        else process.env.OPENCODEX_API_AUTH_TOKEN = previousApiToken;
        rmSync(opencodexHome, { recursive: true, force: true });
      }
    }
  }, 15_000);

  test("HTTP and MCP share the fail-closed secure token reader used by lifecycle status", () => {
    const configDir = mkdtempSync(join(tmpdir(), "ocx-bridge-token-reader-"));
    const previousHome = process.env.OPENCODEX_HOME;
    process.env.OPENCODEX_HOME = configDir;
    const tokenPath = join(configDir, "subagent-bridge-token");
    const token = Buffer.alloc(32, 3).toString("base64url");
    try {
      expect((httpModule as any).readSubagentBridgeToken)
        .toBe((lifecycleModule as any).readSecureSubagentBridgeToken);
      writeFileSync(tokenPath, `${token}\n`, { mode: 0o644 });
      const expectedUid = lstatSync(tokenPath).uid;
      expect((httpModule as any).readSubagentBridgeToken({
        configDir,
        platform: "linux",
        expectedUid,
      })).toBeNull();
    } finally {
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(configDir, { recursive: true, force: true });
    }
  });

  test("the live server routes signed staging before normal management API handling", async () => {
    const opencodexHome = mkdtempSync(join(tmpdir(), "ocx-bridge-api-"));
    const previousHome = process.env.OPENCODEX_HOME;
    process.env.OPENCODEX_HOME = opencodexHome;
    mkdirSync(opencodexHome, { recursive: true });
    writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
      port: 0,
      providers: {
        openai: {
          adapter: "openai-responses",
          baseUrl: "https://chatgpt.com/backend-api/codex",
          authMode: "forward",
        },
      },
      defaultProvider: "openai",
      subagentBridge: { enabled: true },
    }));
    const validToken = Buffer.alloc(32, 7).toString("base64url");
    writeFileSync(join(opencodexHome, "subagent-bridge-token"), "too-short\n");
    subagentHandoffStore.clear();
    chmodSync(join(opencodexHome, "subagent-bridge-token"), 0o600);
    expect(hardenSecretPath(join(opencodexHome, "subagent-bridge-token"), {
      required: true,
      verifyIsolation: true,
    }).ok).toBe(true);
    const server = startServer(0);
    try {
      const health = await fetch(new URL("/healthz", server.url)).then(response => response.json()) as any;
      expect(health).toMatchObject({
        pid: process.pid,
        port: server.port,
        subagentBridge: {
          protocol: (runtimeModule as any).SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
          eligible: true,
        },
      });
      const missing = await fetch(new URL("/internal/subagent-handoffs", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ kind: "message", target: TARGET_CANONICAL, message: SECRET_MESSAGE }),
      });
      expect(missing.status).toBe(401);
      expect(await missing.text()).not.toContain(SECRET_MESSAGE);

      const malformedToken = await fetch(new URL("/internal/subagent-handoffs", server.url), {
        method: "POST",
        headers: { authorization: "Bearer too-short", "content-type": "application/json" },
        body: JSON.stringify({ kind: "message", target: TARGET_CANONICAL, message: SECRET_MESSAGE }),
      });
      expect(malformedToken.status).toBe(401);
      expect(await malformedToken.text()).not.toContain(SECRET_MESSAGE);

      writeFileSync(join(opencodexHome, "subagent-bridge-token"), `${validToken}\n`);
      expect((lifecycleModule as any).repairSubagentBridgeTokenAttestation({
        configDir: opencodexHome,
        platform: "win32",
        inspectTokenSecurity: () => true,
      })).toBe(true);

      const bearerOnly = await fetch(new URL("/internal/subagent-handoffs", server.url), {
        method: "POST",
        headers: { authorization: `Bearer ${validToken}`, "content-type": "application/json" },
        body: JSON.stringify({ kind: "message", target: TARGET_CANONICAL, message: SECRET_MESSAGE }),
      });
      expect(bearerOnly.status).toBe(401);

      const located = await (runtimeModule as any).findLiveSubagentBridgeProxy({
        readPidFn: () => process.pid,
        readRuntimeFn: () => ({ pid: process.pid, port: server.port, hostname: "127.0.0.1" }),
        readToken: () => validToken,
        randomBytesFn: () => Buffer.alloc(32, 31),
        timeoutMs: 3_000,
      });
      expect(located?.instanceId).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const valid = await prepareViaProxy(
        { kind: "message", target: TARGET_CANONICAL, message: SECRET_MESSAGE },
        {
          findProxy: async () => located,
          readToken: () => validToken,
          randomBytesFn: () => Buffer.alloc(32, 32),
        },
      );
      expect(valid).toEqual({ target: TARGET_CANONICAL, expires_in_seconds: 300 });
      expect(subagentHandoffStore.stats().records).toBe(1);
    } finally {
      subagentHandoffStore.clear();
      await server.stop(true);
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(opencodexHome, { recursive: true, force: true });
    }
  });

  test("requires its own signed transport and never echoes request content", async () => {
    const store = new SubagentHandoffStore({ now: () => 1_000, randomHex: () => "abcdef012345" });
    const deps = signedHandlerDeps(store);
    const body = JSON.stringify({ kind: "spawn", task_name: "review", model: "provider/model", message: SECRET_MESSAGE });

    for (const request of [
      signedHandlerRequest(body, { includeSignature: false }),
      signedHandlerRequest(body, { signingToken: Buffer.alloc(32, 63).toString("base64url") }),
    ]) {
      const response = await handleSubagentHandoffRequest(request, deps);
      expect(response.status).toBe(401);
      expect(await response.text()).not.toContain(SECRET_MESSAGE);
      expect(store.stats()).toEqual({ records: 0, totalBytes: 0 });
    }
  });

  test("stages strict spawn, message, and followup schemas with content-free results", async () => {
    const store = new SubagentHandoffStore({ now: () => 10_000, randomHex: () => "abcdef012345" });
    const deps = signedHandlerDeps(store);
    const post = (body: unknown) => handleSubagentHandoffRequest(signedHandlerRequest(JSON.stringify(body)), deps);

    const spawn = await post({ kind: "spawn", task_name: "Review API", model: "provider/model", message: SECRET_MESSAGE });
    expect(spawn.status).toBe(200);
    const spawnBody = await spawn.json() as { task_name: string; expires_in_seconds: number };
    expect(spawnBody).toEqual({ task_name: "review_api_abcdef012345", expires_in_seconds: 300 });
    expect(JSON.stringify(spawnBody)).not.toContain(SECRET_MESSAGE);

    for (const kind of ["message", "followup"] as const) {
      const target = kind === "message" ? TARGET_LEAF : TARGET_CANONICAL;
      const response = await post({ kind, target, message: SECRET_MESSAGE });
      expect(response.status).toBe(200);
      const result = await response.json() as { target: string; expires_in_seconds: number };
      expect(result).toEqual({ target, expires_in_seconds: 300 });
      expect(JSON.stringify(result)).not.toContain(SECRET_MESSAGE);
    }
    expect(store.consume(TARGET_CANONICAL, "MESSAGE")?.target).toBe(TARGET_LEAF);
    expect(store.consume(TARGET_LEAF, "NEW_TASK")?.target).toBe(TARGET_CANONICAL);
  });

  test("rejects malformed or extra fields without reflecting message content", async () => {
    const store = new SubagentHandoffStore();
    const cases = [
      { kind: "spawn", task_name: "x", message: SECRET_MESSAGE },
      { kind: "message", target: "", message: SECRET_MESSAGE },
      { kind: "message", target: "reviewer", message: SECRET_MESSAGE },
      { kind: "message", target: "019f85e8-6bcc-7d21-a50d-1af5ec2976c6", message: SECRET_MESSAGE },
      { kind: "message", target: "/root/../reviewer_abcdef012345", message: SECRET_MESSAGE },
      { kind: "message", target: "/evil/reviewer_abcdef012345", message: SECRET_MESSAGE },
      { kind: "followup", target: TARGET_LEAF, message: SECRET_MESSAGE, model: "not-allowed" },
      { kind: "unknown", target: TARGET_LEAF, message: SECRET_MESSAGE },
    ];
    for (const body of cases) {
      const response = await handleSubagentHandoffRequest(
        signedHandlerRequest(JSON.stringify(body)),
        signedHandlerDeps(store),
      );
      expect(response.status).toBe(400);
      expect(await response.text()).not.toContain(SECRET_MESSAGE);
    }
    expect(store.stats().records).toBe(0);
  });

  test("bounds chunked JSON before parsing while accepting an exact 64 KiB message", async () => {
    const store = new SubagentHandoffStore();
    const deps = signedHandlerDeps(store);
    const exact = "x".repeat(64 * 1024);
    const acceptedBody = JSON.stringify({
      kind: "message", target: TARGET_LEAF, message: exact,
    });
    const accepted = await handleSubagentHandoffRequest(signedHandlerRequest(acceptedBody), deps);
    expect(accepted.status).toBe(200);
    expect(await accepted.text()).not.toContain(exact.slice(0, 128));

    let canceled = false;
    const oversized = JSON.stringify({
      kind: "message", target: TARGET_LEAF, message: "z".repeat(500_000),
    });
    let offset = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (offset >= oversized.length) return controller.close();
        const next = oversized.slice(offset, offset + 8192);
        offset += next.length;
        controller.enqueue(new TextEncoder().encode(next));
      },
      cancel() { canceled = true; },
    });
    const rejected = await handleSubagentHandoffRequest(
      signedHandlerRequest(oversized, { body: stream }),
      deps,
    );
    expect(rejected.status).toBe(413);
    expect(await rejected.text()).not.toContain("zzzzzzzz");
    expect(canceled).toBe(true);

    const metadataBody = JSON.stringify({
      kind: "spawn", task_name: "review", model: "m".repeat(513), message: "ok",
    });
    const metadata = await handleSubagentHandoffRequest(signedHandlerRequest(metadataBody), deps);
    expect(metadata.status).toBe(400);
  });

  test("rejects staging before token/body handling when the active proxy is disabled or explicit V1", async () => {
    const store = new SubagentHandoffStore();
    let tokenReads = 0;
    for (const runtimeEligible of [undefined, false]) {
      const body = JSON.stringify({ kind: "message", target: TARGET_LEAF, message: SECRET_MESSAGE });
      const response = await handleSubagentHandoffRequest(signedHandlerRequest(body), signedHandlerDeps(store, {
        runtimeEligible,
        readToken: () => {
          tokenReads += 1;
          return HANDLER_TOKEN;
        },
      }));
      expect(response.status).toBe(503);
      expect(await response.text()).not.toContain(SECRET_MESSAGE);
    }
    expect(tokenReads).toBe(0);
    expect(store.stats().records).toBe(0);
  });

  test("the live server rejects staging under active disabled and explicit-V1 configurations", async () => {
    for (const configOverride of [
      { subagentBridge: { enabled: false } },
      { subagentBridge: { enabled: true }, multiAgentMode: "v1" },
    ]) {
      const opencodexHome = mkdtempSync(join(tmpdir(), "ocx-bridge-ineligible-"));
      const previousHome = process.env.OPENCODEX_HOME;
      process.env.OPENCODEX_HOME = opencodexHome;
      const token = Buffer.alloc(32, 6).toString("base64url");
      writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
        port: 0,
        providers: {
          openai: {
            adapter: "openai-responses",
            baseUrl: "https://chatgpt.com/backend-api/codex",
            authMode: "forward",
          },
        },
        defaultProvider: "openai",
        ...configOverride,
      }));
      writeFileSync(join(opencodexHome, "subagent-bridge-token"), `${token}\n`, { mode: 0o600 });
      const server = startServer(0);
      try {
        const health = await fetch(new URL("/healthz", server.url)).then(response => response.json()) as any;
        expect(health.subagentBridge).toMatchObject({ eligible: false });
        const response = await fetch(new URL("/internal/subagent-handoffs", server.url), {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify({ kind: "message", target: TARGET_LEAF, message: SECRET_MESSAGE }),
        });
        expect(response.status).toBe(503);
        expect(await response.text()).not.toContain(SECRET_MESSAGE);
      } finally {
        await server.stop(true);
        if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
        else process.env.OPENCODEX_HOME = previousHome;
        rmSync(opencodexHome, { recursive: true, force: true });
      }
    }
  });
});

describe("subagent bridge MCP proxy identity", () => {
  test("runtime records persist normalized actual hosts while endpoint safety stays literal", () => {
    const normalize = (runtimeModule as any).normalizedActualBindHostname;
    const endpointHost = (runtimeModule as any).literalLoopbackEndpointHost;
    const runtimeState = (runtimeModule as any).subagentBridgeRuntimePortState;

    expect(normalize(undefined)).toBe("127.0.0.1");
    expect(normalize("localhost")).toBe("127.0.0.1");
    expect(normalize("127.0.0.1")).toBe("127.0.0.1");
    expect(normalize("::1")).toBe("::1");
    expect(normalize("0.0.0.0")).toBe("0.0.0.0");

    expect(endpointHost("127.0.0.1")).toBe("127.0.0.1");
    expect(endpointHost("::1")).toBe("[::1]");
    expect(endpointHost("[::1]")).toBe("[::1]");
    for (const unsafe of [undefined, "", "localhost", "0.0.0.0", "::", "[::]", "proxy.local"]) {
      expect(endpointHost(unsafe)).toBeNull();
    }

    expect(runtimeState(4321, 58195, undefined)).toEqual({ pid: 4321, port: 58195, hostname: "127.0.0.1" });
    expect(runtimeState(4321, 58195, "localhost")).toEqual({ pid: 4321, port: 58195, hostname: "127.0.0.1" });
    expect(runtimeState(4321, 58195, "127.0.0.1")).toEqual({ pid: 4321, port: 58195, hostname: "127.0.0.1" });
    expect(runtimeState(4321, 58195, "::1")).toEqual({ pid: 4321, port: 58195, hostname: "::1" });
    expect(runtimeState(4321, 58195, "0.0.0.0")).toEqual({ pid: 4321, port: 58195, hostname: "0.0.0.0" });
  });

  test("bridge-specific locator requires exact loopback runtime and a nonce-authenticated health proof", async () => {
    const findBridgeProxy = (runtimeModule as any).findLiveSubagentBridgeProxy;
    const protocol = (runtimeModule as any).SUBAGENT_BRIDGE_HEALTH_PROTOCOL;
    expect(typeof findBridgeProxy).toBe("function");
    expect(typeof protocol).toBe("string");
    if (typeof findBridgeProxy !== "function") return;

    const token = Buffer.alloc(32, 41).toString("base64url");
    const nonceBytes = Buffer.alloc(32, 42);
    const nonce = nonceBytes.toString("base64url");
    const instanceId = Buffer.alloc(32, 43).toString("base64url");
    const exactHealth = {
      status: "ok",
      service: "opencodex",
      pid: 4321,
      port: 58195,
      subagentBridge: {
        protocol,
        eligible: true,
        instanceId,
        proof: createSubagentBridgeHealthProof({ token, protocol, instanceId, nonce, pid: 4321, port: 58195 }),
      },
    };
    const calls: string[] = [];
    let pidInspections = 0;
    const exact = await findBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: (pid?: number) => pid === 4321
        ? { pid: 4321, port: 58195, hostname: "127.0.0.1" }
        : null,
      verifyPidFn: (pid: number) => {
        pidInspections += 1;
        return pid;
      },
      randomBytesFn: () => nonceBytes,
      readToken: () => token,
      fetchFn: (async (url: string | URL | Request) => {
        calls.push(String(url));
        return Response.json(exactHealth);
      }) as typeof fetch,
    });
    expect(exact).toEqual({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId });
    expect(calls).toEqual([`http://127.0.0.1:58195/healthz?challenge=${nonce}`]);
    expect(pidInspections).toBe(0);

    for (const health of [
      { status: "ok", version: "legacy", uptime: 1 },
      { ...exactHealth, pid: 9999 },
      { ...exactHealth, port: 10100 },
      { ...exactHealth, subagentBridge: { protocol, eligible: false } },
      { ...exactHealth, subagentBridge: { protocol: "stale", eligible: true } },
    ]) {
      expect(await findBridgeProxy({
        readPidFn: () => 4321,
        readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
        randomBytesFn: () => nonceBytes,
        readToken: () => token,
        fetchFn: (async () => Response.json(health)) as typeof fetch,
      })).toBeNull();
    }
    expect(await findBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "localhost" }),
      randomBytesFn: () => nonceBytes,
      readToken: () => token,
      fetchFn: (async () => Response.json(exactHealth)) as typeof fetch,
    })).toBeNull();
    const ipv6Calls: string[] = [];
    expect(await findBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "::1" }),
      randomBytesFn: () => nonceBytes,
      readToken: () => token,
      fetchFn: (async (url: string | URL | Request) => {
        ipv6Calls.push(String(url));
        return Response.json(exactHealth);
      }) as typeof fetch,
    })).toEqual({ pid: 4321, port: 58195, hostname: "[::1]", instanceId });
    expect(ipv6Calls).toEqual([`http://[::1]:58195/healthz?challenge=${nonce}`]);
    for (const hostname of ["0.0.0.0", "::", "[::]", "proxy.local"]) {
      let fetched = false;
      expect(await findBridgeProxy({
        readPidFn: () => 4321,
        readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname }),
        randomBytesFn: () => nonceBytes,
        readToken: () => token,
        fetchFn: (async () => {
          fetched = true;
          return Response.json(exactHealth);
        }) as typeof fetch,
      })).toBeNull();
      expect(fetched).toBe(false);
    }
  });

  test("failed bridge identity never reads the token or sends plaintext", async () => {
    let tokenReads = 0;
    let fetches = 0;
    await expect(prepareViaProxy(
      { kind: "message", target: TARGET_LEAF, message: SECRET_MESSAGE },
      {
        findProxy: async () => null,
        readToken: () => {
          tokenReads += 1;
          return "bridge-token";
        },
        fetchFn: (async () => {
          fetches += 1;
          return Response.json({});
        }) as typeof fetch,
      },
    )).rejects.toThrow("unavailable");
    expect(tokenReads).toBe(0);
    expect(fetches).toBe(0);
  });

  test("default delivery finds an identity-checked live local proxy", async () => {
    const opencodexHome = mkdtempSync(join(tmpdir(), "ocx-bridge-mcp-live-"));
    const previousHome = process.env.OPENCODEX_HOME;
    process.env.OPENCODEX_HOME = opencodexHome;
    const token = Buffer.alloc(32, 9).toString("base64url");
    writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
      port: 0,
      providers: { openai: { adapter: "openai-responses", baseUrl: "https://chatgpt.com/backend-api/codex", authMode: "forward" } },
      defaultProvider: "openai",
      subagentBridge: { enabled: true },
    }));
    writeFileSync(join(opencodexHome, "subagent-bridge-token"), `${token}\n`, { mode: 0o600 });
    const server = startServer(0);
    expect(hardenSecretPath(join(opencodexHome, "subagent-bridge-token"), {
      required: true,
      verifyIsolation: true,
    }).ok).toBe(true);
    expect((lifecycleModule as any).repairSubagentBridgeTokenAttestation({
      configDir: opencodexHome,
      platform: "win32",
      inspectTokenSecurity: () => true,
    })).toBe(true);
    writeFileSync(join(opencodexHome, "runtime-port.json"), JSON.stringify({
      pid: process.pid, port: server.port, hostname: "127.0.0.1",
    }));
    subagentHandoffStore.clear();
    try {
      expect(await fetch(new URL("/healthz", server.url)).then(response => response.json())).toMatchObject({
        pid: process.pid,
        port: server.port,
        subagentBridge: {
          protocol: (runtimeModule as any).SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
          eligible: true,
        },
      });
      const findProxy = () => (runtimeModule as any).findLiveSubagentBridgeProxy({
        readPidFn: () => process.pid,
        readRuntimeFn: () => ({ pid: process.pid, port: server.port, hostname: "127.0.0.1" }),
        timeoutMs: 3_000,
      });
      const located = await findProxy();
      expect(located).toMatchObject({ pid: process.pid, port: server.port, hostname: "127.0.0.1" });
      expect(located?.instanceId).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const result = await prepareViaProxy(
        { kind: "message", target: TARGET_LEAF, message: SECRET_MESSAGE },
        {
          findProxy: async () => located,
        },
      );
      expect(result).toEqual({ target: TARGET_LEAF, expires_in_seconds: 300 });
      expect(subagentHandoffStore.consume(TARGET_CANONICAL, "MESSAGE")?.message).toBe(SECRET_MESSAGE);
    } finally {
      subagentHandoffStore.clear();
      await server.stop(true);
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(opencodexHome, { recursive: true, force: true });
    }
  });

  test("refuses a stale runtime record pointing at a foreign listener before sending plaintext", async () => {
    const opencodexHome = mkdtempSync(join(tmpdir(), "ocx-bridge-mcp-foreign-"));
    const previousHome = process.env.OPENCODEX_HOME;
    process.env.OPENCODEX_HOME = opencodexHome;
    let internalRequests = 0;
    const foreign = Bun.serve({
      port: 0,
      fetch(req) {
        if (new URL(req.url).pathname === "/internal/subagent-handoffs") internalRequests += 1;
        return Response.json({ status: "ok", service: "foreign", pid: process.pid });
      },
    });
    writeFileSync(join(opencodexHome, "config.json"), JSON.stringify({
      port: foreign.port,
      providers: { openai: { adapter: "openai-responses", baseUrl: "https://chatgpt.com/backend-api/codex", authMode: "forward" } },
      defaultProvider: "openai",
    }));
    writeFileSync(join(opencodexHome, "runtime-port.json"), JSON.stringify({ pid: process.pid, port: foreign.port, hostname: "127.0.0.1" }));
    writeFileSync(join(opencodexHome, "subagent-bridge-token"), `${Buffer.alloc(32, 4).toString("base64url")}\n`);
    try {
      await expect(prepareViaProxy({ kind: "message", target: TARGET_LEAF, message: SECRET_MESSAGE })).rejects.toThrow("unavailable");
      expect(internalRequests).toBe(0);
    } finally {
      await foreign.stop(true);
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(opencodexHome, { recursive: true, force: true });
    }
  });
});

describe("subagent bridge MCP server", () => {
  async function connectedServer(prepare: PrepareSubagentHandoff) {
    const server = createSubagentBridgeMcpServer({ prepare });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    const client = new Client({ name: "bridge-test", version: "1.0.0" });
    await client.connect(clientTransport);
    return { client, server };
  }

  test("exposes exactly prepare_subagent_handoff and returns no message content", async () => {
    const calls: unknown[] = [];
    const { client, server } = await connectedServer(async input => {
      calls.push(input);
      return input.kind === "spawn"
        ? { task_name: "review_abcdef012345", expires_in_seconds: 300 }
        : { target: input.target, expires_in_seconds: 300 };
    });
    try {
      const tools = await client.listTools();
      expect(tools.tools.map(tool => tool.name)).toEqual(["prepare_subagent_handoff"]);
      const result = await client.callTool({
        name: "prepare_subagent_handoff",
        arguments: { kind: "spawn", task_name: "review", model: "provider/model", message: SECRET_MESSAGE },
      });
      expect(result.isError).not.toBe(true);
      expect(bodyText(result as never)).toContain("review_abcdef012345");
      expect(JSON.stringify(result)).not.toContain(SECRET_MESSAGE);
      expect(calls).toHaveLength(1);
    } finally {
      await client.close();
      await server.close();
    }
  });

  test("reports validation and service errors without reflecting content", async () => {
    const { client, server } = await connectedServer(async () => {
      throw new Error(`service unavailable: ${SECRET_MESSAGE}`);
    });
    try {
      const unavailable = await client.callTool({
        name: "prepare_subagent_handoff",
        arguments: { kind: "message", target: TARGET_CANONICAL, message: SECRET_MESSAGE },
      });
      expect(unavailable.isError).toBe(true);
      expect(JSON.stringify(unavailable)).not.toContain(SECRET_MESSAGE);
      expect(bodyText(unavailable as never)).toContain("unavailable");

      let validationResult: unknown;
      try {
        validationResult = await client.callTool({
          name: "prepare_subagent_handoff",
          arguments: { kind: "spawn", task_name: "review", message: SECRET_MESSAGE },
        });
      } catch (error) {
        validationResult = error instanceof Error ? error.message : String(error);
      }
      expect(JSON.stringify(validationResult)).not.toContain(SECRET_MESSAGE);
      expect(JSON.stringify(validationResult)).toContain("model");
    } finally {
      await client.close();
      await server.close();
    }
  });
});
