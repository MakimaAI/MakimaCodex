import { describe, expect, test } from "bun:test";
import { createHash, createHmac } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "../src/server";
import { SubagentHandoffStore, subagentHandoffStore } from "../src/subagent-bridge/handoff-store";
import {
  hardenSecretDir,
  hardenSecretPath,
  resetHardenedStateForTests,
} from "../src/lib/windows-secret-acl";
import * as httpModule from "../src/subagent-bridge/http";
import * as authModule from "../src/subagent-bridge/auth";
import * as lifecycleModule from "../src/subagent-bridge/lifecycle";
import * as mcpModule from "../src/subagent-bridge/mcp";
import * as runtimeModule from "../src/subagent-bridge/runtime";
import type { SubagentBridgeLifecycleOptions } from "../src/subagent-bridge/lifecycle";

const repoRoot = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const bundleDir = join(repoRoot, "plugins", "opencodex-subagent-bridge");
const cliPath = join(repoRoot, "src", "cli", "index.ts");
const TOKEN_FILE = "subagent-bridge-token";
const PROTOCOL = "opencodex-subagent-handoff-v2";
const HEALTH_DOMAIN = "opencodex-subagent-bridge/health/v1";
const REQUEST_DOMAIN = "opencodex-subagent-bridge/request/v1";
const RESPONSE_DOMAIN = "opencodex-subagent-bridge/response/v1";
const INSTANCE_HEADER = "x-opencodex-bridge-instance";
const REQUEST_ID_HEADER = "x-opencodex-bridge-request-id";
const SIGNATURE_HEADER = "x-opencodex-bridge-signature";
const ISSUED_AT_HEADER = "x-opencodex-bridge-issued-at";
const RESPONSE_SIGNATURE_HEADER = "x-opencodex-bridge-response-signature";
const STAGING_PATH = "/internal/subagent-handoffs";
const SECRET_MESSAGE = "hardening-handoff-plaintext";
const TARGET = "reviewer_abcdef012345";
const REQUEST_MAX_AGE_MS = 30_000;
const REQUEST_FUTURE_SKEW_MS = 5_000;
const REPLAY_RETENTION_MS = 60_000;
const TEST_NOW_MS = 4_000_000;

function tokenValue(fill: number): string {
  return Buffer.alloc(32, fill).toString("base64url");
}

function macInput(fields: readonly string[]): Buffer {
  const chunks: Buffer[] = [];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(bytes.byteLength);
    chunks.push(length, bytes);
  }
  return Buffer.concat(chunks);
}

function testMac(token: string, fields: readonly string[]): string {
  return createHmac("sha256", Buffer.from(token, "base64url")).update(macInput(fields)).digest("base64url");
}

function digest(body: string | Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

function healthProof(token: string, nonce: string, instanceId: string, pid: number, port: number): string {
  return testMac(token, [HEALTH_DOMAIN, PROTOCOL, instanceId, nonce, String(pid), String(port)]);
}

function requestSignature(
  token: string,
  instanceId: string,
  requestId: string,
  issuedAtMs: number,
  body: string,
  path = STAGING_PATH,
): string {
  return testMac(token, [REQUEST_DOMAIN, PROTOCOL, "POST", path, instanceId, requestId, String(issuedAtMs), digest(body)]);
}

function responseSignature(
  token: string,
  instanceId: string,
  requestId: string,
  status: number,
  body: string,
): string {
  return testMac(token, [RESPONSE_DOMAIN, PROTOCOL, instanceId, requestId, String(status), digest(body)]);
}

function sealedRequestBody(options: {
  token: string;
  instanceId: string;
  requestId: string;
  issuedAtMs: number;
  body: string;
  path?: string;
}): string {
  const sealed = (authModule as any).sealSubagentBridgeRequestBody({
    token: options.token,
    protocol: PROTOCOL,
    method: "POST",
    path: options.path ?? STAGING_PATH,
    instanceId: options.instanceId,
    requestId: options.requestId,
    issuedAtMs: options.issuedAtMs,
    body: options.body,
    randomBytesFn: () => Buffer.from(options.requestId, "base64url").subarray(0, 12),
  });
  if (typeof sealed !== "string") throw new Error("test request sealing failed");
  return sealed;
}

function replayGuard(options?: Record<string, unknown>): any {
  const Guard = (httpModule as any).SubagentBridgeReplayGuard;
  expect(typeof Guard).toBe("function");
  return new Guard(options);
}

function signedRequest(options: {
  token: string;
  instanceId: string;
  requestId: string;
  issuedAtMs?: number;
  body: string;
  signatureBody?: string;
  url?: string;
  signaturePath?: string;
  headers?: Record<string, string>;
}): Request {
  const issuedAtMs = options.issuedAtMs ?? TEST_NOW_MS;
  const wireBody = sealedRequestBody({
    token: options.token,
    instanceId: options.instanceId,
    requestId: options.requestId,
    issuedAtMs,
    body: options.body,
  });
  const signatureBody = options.signatureBody === undefined
    ? wireBody
    : sealedRequestBody({
        token: options.token,
        instanceId: options.instanceId,
        requestId: options.requestId,
        issuedAtMs,
        body: options.signatureBody,
      });
  return new Request(options.url ?? `http://127.0.0.1${STAGING_PATH}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [INSTANCE_HEADER]: options.instanceId,
      [REQUEST_ID_HEADER]: options.requestId,
      [ISSUED_AT_HEADER]: String(issuedAtMs),
      [SIGNATURE_HEADER]: requestSignature(
        options.token,
        options.instanceId,
        options.requestId,
        issuedAtMs,
        signatureBody,
        options.signaturePath,
      ),
      ...options.headers,
    },
    body: wireBody,
  });
}

function freshnessSignedRequest(options: {
  token: string;
  instanceId: string;
  requestId: string;
  issuedAtMs: number;
  body: string;
}): Request {
  const wireBody = sealedRequestBody({
    token: options.token,
    instanceId: options.instanceId,
    requestId: options.requestId,
    issuedAtMs: options.issuedAtMs,
    body: options.body,
  });
  const signature = (authModule as any).createSubagentBridgeRequestSignature({
    token: options.token,
    protocol: PROTOCOL,
    method: "POST",
    path: STAGING_PATH,
    instanceId: options.instanceId,
    requestId: options.requestId,
    issuedAtMs: options.issuedAtMs,
    body: wireBody,
  });
  return new Request(`http://127.0.0.1${STAGING_PATH}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      [INSTANCE_HEADER]: options.instanceId,
      [REQUEST_ID_HEADER]: options.requestId,
      [ISSUED_AT_HEADER]: String(options.issuedAtMs),
      [SIGNATURE_HEADER]: signature,
    },
    body: wireBody,
  });
}

function attestationPath(tokenPath: string): string {
  const fn = (lifecycleModule as any).subagentBridgeTokenAttestationPath;
  expect(typeof fn).toBe("function");
  return fn(tokenPath);
}

function repairAttestation(tokenPath: string): boolean {
  const fn = (lifecycleModule as any).repairSubagentBridgeTokenAttestation;
  expect(typeof fn).toBe("function");
  return fn({
    tokenPath,
    platform: "win32",
    inspectTokenSecurity: () => true,
    hardenConfigDir: () => true,
  });
}

function readFast(tokenPath: string, inspected: { count: number }): string | null {
  return (lifecycleModule as any).readSecureSubagentBridgeToken({
    tokenPath,
    platform: "win32",
    inspectTokenSecurity: () => {
      inspected.count += 1;
      throw new Error("deep ACL inspection must not run");
    },
  });
}

function prepareRealServerToken(tokenPath: string): void {
  expect(hardenSecretDir(dirname(tokenPath), { required: true, verifyIsolation: true }).ok).toBe(true);
  expect(hardenSecretPath(tokenPath, { required: true, verifyIsolation: true }).ok).toBe(true);
  expect(repairAttestation(tokenPath)).toBe(true);
  // startServer represents the next process: it must preflight the already-secure directory
  // instead of relying on this process's memoized hardening state.
  resetHardenedStateForTests();
}

function lifecycleFixture() {
  const root = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-lifecycle-"));
  const homeDir = join(root, "home");
  const configDir = join(root, "opencodex");
  mkdirSync(join(homeDir, ".agents", "plugins"), { recursive: true });
  mkdirSync(configDir, { recursive: true });
  writeFileSync(join(configDir, "config.json"), JSON.stringify({
    port: 10100,
    providers: { custom: { adapter: "openai-chat", baseUrl: "https://example.test/v1", apiKey: "keep" } },
    defaultProvider: "custom",
    subagentBridge: { enabled: false },
  }));
  writeFileSync(join(homeDir, ".agents", "plugins", "marketplace.json"), JSON.stringify({
    name: "personal",
    interface: { displayName: "Personal" },
    plugins: [],
  }));
  const registrations = new Map<string, { installed: boolean; enabled: boolean }>();
  const invocations: string[][] = [];
  const options: SubagentBridgeLifecycleOptions = {
    homeDir,
    configDir,
    bundleDir,
    runtimeCommand: process.execPath,
    runtimeArgs: [cliPath, "__subagent-bridge-mcp"],
    codexCommand: process.execPath,
    platform: "win32",
    randomBytes: length => new Uint8Array(Array.from({ length }, (_, index) => index)),
    hardenSecret: () => true,
    hardenConfigDir: () => true,
    inspectTokenSecurity: () => true,
    runCodex: (_command, args) => {
      invocations.push(args);
      const selector = args[2];
      if (args[1] === "add" && selector) registrations.set(selector, { installed: true, enabled: true });
      if (args[1] === "remove" && selector) registrations.delete(selector);
      return { status: 0 };
    },
    inspectRegistration: (_command, selector) => registrations.get(selector) ?? { installed: false, enabled: false },
  };
  return { root, homeDir, configDir, registrations, invocations, options };
}

describe("Windows subagent bridge token attestation", () => {
  test("normal Windows reads require attestation without invoking deep ACL inspection", () => {
    const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-required-"));
    const tokenPath = join(dir, TOKEN_FILE);
    writeFileSync(tokenPath, `${tokenValue(1)}\n`, { mode: 0o600 });
    const inspected = { count: 0 };
    try {
      expect(readFast(tokenPath, inspected)).toBeNull();
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("explicit repair writes a bounded versioned attestation used by fast reads", () => {
    const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-create-"));
    const tokenPath = join(dir, TOKEN_FILE);
    const token = tokenValue(2);
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    try {
      expect(repairAttestation(tokenPath)).toBe(true);
      const path = attestationPath(tokenPath);
      const bytes = readFileSync(path);
      expect(bytes.byteLength).toBeGreaterThan(0);
      expect(bytes.byteLength).toBeLessThanOrEqual(2048);
      expect(JSON.parse(bytes.toString("utf8"))).toMatchObject({
        owner: "opencodex",
        plugin: "opencodex-subagent-bridge",
        version: 1,
        fingerprint: {
          type: "file",
          noSymlink: true,
          size: "44",
        },
      });
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBe(token);
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("malformed or tampered attestations fail closed without deep fallback", () => {
    for (const mutate of [
      (path: string) => writeFileSync(path, "{not-json"),
      (path: string) => {
        const value = JSON.parse(readFileSync(path, "utf8"));
        value.mac = "A".repeat(43);
        writeFileSync(path, JSON.stringify(value));
      },
    ]) {
      const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-tamper-"));
      const tokenPath = join(dir, TOKEN_FILE);
      writeFileSync(tokenPath, `${tokenValue(3)}\n`, { mode: 0o600 });
      try {
        expect(repairAttestation(tokenPath)).toBe(true);
        mutate(attestationPath(tokenPath));
        const inspected = { count: 0 };
        expect(readFast(tokenPath, inspected)).toBeNull();
        expect(inspected.count).toBe(0);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  test("a replaced token file invalidates its prior attestation", () => {
    const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-replace-"));
    const tokenPath = join(dir, TOKEN_FILE);
    const replacement = join(dir, "replacement");
    writeFileSync(tokenPath, `${tokenValue(4)}\n`, { mode: 0o600 });
    try {
      expect(repairAttestation(tokenPath)).toBe(true);
      writeFileSync(replacement, `${tokenValue(5)}\n`, { mode: 0o600 });
      unlinkSync(tokenPath);
      renameSync(replacement, tokenPath);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBeNull();
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("ctime drift invalidates an otherwise unchanged token and attestation", () => {
    const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-ctime-"));
    const tokenPath = join(dir, TOKEN_FILE);
    const token = tokenValue(6);
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    try {
      expect(repairAttestation(tokenPath)).toBe(true);
      const before = lstatSync(tokenPath, { bigint: true });
      chmodSync(tokenPath, 0o400);
      chmodSync(tokenPath, 0o600);
      const after = lstatSync(tokenPath, { bigint: true });
      expect(after.dev).toBe(before.dev);
      expect(after.ino).toBe(before.ino);
      expect(after.ctimeNs).not.toBe(before.ctimeNs);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBeNull();
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reinstall migrates a deeply verified legacy token to a fresh attestation", () => {
    const fixture = lifecycleFixture();
    const tokenPath = join(fixture.configDir, TOKEN_FILE);
    const token = tokenValue(7);
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    try {
      expect((lifecycleModule as any).installSubagentBridge(fixture.options).ready).toBe(true);
      expect(readFileSync(tokenPath, "utf8").trim()).toBe(token);
      expect(existsSync(attestationPath(tokenPath))).toBe(true);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBe(token);
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("install hardens the config directory before token hardening and attestation", () => {
    const fixture = lifecycleFixture();
    let directoryHardened = false;
    (fixture.options as any).hardenConfigDir = (path: string) => {
      expect(path).toBe(fixture.configDir);
      directoryHardened = true;
      return true;
    };
    fixture.options.hardenSecret = path => path.endsWith(TOKEN_FILE) ? directoryHardened : true;
    try {
      expect(() => (lifecycleModule as any).installSubagentBridge(fixture.options)).not.toThrow();
      expect(directoryHardened).toBe(true);
      const tokenPath = join(fixture.configDir, TOKEN_FILE);
      expect(existsSync(attestationPath(tokenPath))).toBe(true);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("reinstall tolerates its own directory-hardening ctime change and refreshes attestation", () => {
    const fixture = lifecycleFixture();
    const tokenPath = join(fixture.configDir, TOKEN_FILE);
    try {
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      const token = readFileSync(tokenPath, "utf8").trim();
      const before = lstatSync(tokenPath, { bigint: true });
      fixture.options.hardenConfigDir = () => {
        writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
        return true;
      };

      expect(() => (lifecycleModule as any).installSubagentBridge(fixture.options)).not.toThrow();
      const after = lstatSync(tokenPath, { bigint: true });
      expect(after.dev).toBe(before.dev);
      expect(after.ino).toBe(before.ino);
      expect(after.ctimeNs).not.toBe(before.ctimeNs);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBe(token);
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("reinstall directory-hardening failure preserves the prior owned installation", () => {
    const fixture = lifecycleFixture();
    const tokenPath = join(fixture.configDir, TOKEN_FILE);
    const pluginDir = join(fixture.homeDir, "plugins", "opencodex-subagent-bridge");
    try {
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      const token = readFileSync(tokenPath, "utf8").trim();
      const manifestBefore = readFileSync(join(pluginDir, ".codex-plugin", "plugin.json"));
      fixture.options.hardenConfigDir = () => false;

      expect(() => (lifecycleModule as any).installSubagentBridge(fixture.options)).toThrow("config directory ACL hardening failed");
      expect(existsSync(pluginDir)).toBe(true);
      expect(readFileSync(join(pluginDir, ".codex-plugin", "plugin.json"))).toEqual(manifestBefore);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBe(token);
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("POSIX install and reinstall preserve the existing config directory mode", () => {
    if (process.platform === "win32") return;
    const fixture = lifecycleFixture();
    chmodSync(fixture.configDir, 0o750);
    fixture.options.platform = "linux";
    fixture.options.expectedUid = lstatSync(fixture.configDir).uid;
    delete fixture.options.hardenConfigDir;
    fixture.options.hardenSecret = path => {
      if (path === fixture.configDir) chmodSync(path, 0o700);
      return true;
    };
    try {
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      expect(lstatSync(fixture.configDir).mode & 0o777).toBe(0o750);
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      expect(lstatSync(fixture.configDir).mode & 0o777).toBe(0o750);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("platform gate excludes POSIX from config directory stabilization", () => {
    const required = (lifecycleModule as any).subagentBridgeConfigDirStabilizationRequired;
    expect(typeof required).toBe("function");
    expect(required("linux")).toBe(false);
    expect(required("darwin")).toBe(false);
    expect(required("win32")).toBe(true);
  });

  test("remove deletes the owned token attestation with bridge state", () => {
    const fixture = lifecycleFixture();
    const tokenPath = join(fixture.configDir, TOKEN_FILE);
    try {
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      const path = attestationPath(tokenPath);
      expect(existsSync(path)).toBe(true);
      (lifecycleModule as any).removeSubagentBridge(fixture.options);
      expect(existsSync(path)).toBe(false);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("failed reinstall rollback leaves a fast-verifiable attestation", () => {
    const fixture = lifecycleFixture();
    const tokenPath = join(fixture.configDir, TOKEN_FILE);
    try {
      (lifecycleModule as any).installSubagentBridge(fixture.options);
      const token = readFileSync(tokenPath, "utf8").trim();
      fixture.options.runCodex = (_command, args) => {
        fixture.invocations.push(args);
        return { status: args[1] === "add" ? 1 : 0 };
      };
      expect(() => (lifecycleModule as any).installSubagentBridge(fixture.options)).toThrow("plugin add failed");
      expect(existsSync(attestationPath(tokenPath))).toBe(true);
      const inspected = { count: 0 };
      expect(readFast(tokenPath, inspected)).toBe(token);
      expect(inspected.count).toBe(0);
    } finally {
      rmSync(fixture.root, { recursive: true, force: true });
    }
  });

  test("parallel fresh-process fast reads do not invoke ACL child-process inspection", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ocx-bridge-attestation-concurrency-"));
    const tokenPath = join(dir, TOKEN_FILE);
    writeFileSync(tokenPath, `${tokenValue(8)}\n`, { mode: 0o600 });
    try {
      expect(repairAttestation(tokenPath)).toBe(true);
      const worker = join(repoRoot, "tests", "fixtures", "subagent-token-read-worker.ts");
      const children = Array.from({ length: 8 }, () => Bun.spawn([process.execPath, worker], {
        env: { ...process.env, OPENCODEX_HOME: dir },
        stdout: "pipe",
        stderr: "pipe",
      }));
      const results = await Promise.all(children.map(async child => ({
        exitCode: await child.exited,
        stdout: await new Response(child.stdout).text(),
        stderr: await new Response(child.stderr).text(),
      })));
      expect(results).toEqual(Array.from({ length: 8 }, () => ({ exitCode: 0, stdout: "ok", stderr: "" })));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("cryptographic subagent bridge health proof", () => {
  test("locator authenticates a nonce-bound proof without PID command-line inspection", async () => {
    const token = tokenValue(9);
    const nonceBytes = Buffer.alloc(32, 10);
    const nonce = nonceBytes.toString("base64url");
    const instanceId = Buffer.alloc(32, 11).toString("base64url");
    let tokenReads = 0;
    let requestedUrl = "";
    let pidInspections = 0;
    const find = (runtimeModule as any).findLiveSubagentBridgeProxy;
    const located = await find({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
      verifyPidFn: (pid: number) => {
        pidInspections += 1;
        return pid;
      },
      randomBytesFn: () => nonceBytes,
      readToken: () => {
        tokenReads += 1;
        return token;
      },
      fetchFn: (async (url: string | URL | Request) => {
        requestedUrl = String(url);
        return Response.json({
          status: "ok",
          service: "opencodex",
          pid: 4321,
          port: 58195,
          subagentBridge: {
            protocol: PROTOCOL,
            eligible: true,
            instanceId,
            proof: healthProof(token, nonce, instanceId, 4321, 58195),
          },
        });
      }) as typeof fetch,
    });
    expect(located).toEqual({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId });
    expect(new URL(requestedUrl).searchParams.get("challenge")).toBe(nonce);
    expect(tokenReads).toBe(1);
    expect(pidInspections).toBe(0);
  });

  test("locator validates public health fields before reading the local token", async () => {
    let tokenReads = 0;
    let requestedUrl = "";
    const located = await (runtimeModule as any).findLiveSubagentBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
      verifyPidFn: (pid: number) => pid,
      randomBytesFn: () => Buffer.alloc(32, 12),
      readToken: () => {
        tokenReads += 1;
        return tokenValue(9);
      },
      fetchFn: (async (url: string | URL | Request) => {
        requestedUrl = String(url);
        return Response.json({
          status: "ok",
          service: "foreign",
          pid: 4321,
          port: 58195,
          subagentBridge: { protocol: PROTOCOL, eligible: true },
        });
      }) as typeof fetch,
    });
    expect(located).toBeNull();
    expect(new URL(requestedUrl).searchParams.has("challenge")).toBe(true);
    expect(tokenReads).toBe(0);
  });

  test("locator rejects a missing health proof before reading the token", async () => {
    let tokenReads = 0;
    const located = await (runtimeModule as any).findLiveSubagentBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
      verifyPidFn: (pid: number) => pid,
      randomBytesFn: () => Buffer.alloc(32, 13),
      readToken: () => {
        tokenReads += 1;
        return tokenValue(9);
      },
      fetchFn: (async () => Response.json({
        status: "ok",
        service: "opencodex",
        pid: 4321,
        port: 58195,
        subagentBridge: {
          protocol: PROTOCOL,
          eligible: true,
          instanceId: Buffer.alloc(32, 14).toString("base64url"),
        },
      })) as typeof fetch,
    });
    expect(located).toBeNull();
    expect(tokenReads).toBe(0);
  });

  test("locator rejects wrong-token and wrong-nonce health proofs", async () => {
    const token = tokenValue(9);
    const instanceId = Buffer.alloc(32, 15).toString("base64url");
    for (const proofToken of [tokenValue(10), token]) {
      const nonceBytes = Buffer.alloc(32, 16);
      const nonce = nonceBytes.toString("base64url");
      let tokenReads = 0;
      const proofNonce = proofToken === token ? Buffer.alloc(32, 17).toString("base64url") : nonce;
      const located = await (runtimeModule as any).findLiveSubagentBridgeProxy({
        readPidFn: () => 4321,
        readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
        verifyPidFn: (pid: number) => pid,
        randomBytesFn: () => nonceBytes,
        readToken: () => {
          tokenReads += 1;
          return token;
        },
        fetchFn: (async () => Response.json({
          status: "ok",
          service: "opencodex",
          pid: 4321,
          port: 58195,
          subagentBridge: {
            protocol: PROTOCOL,
            eligible: true,
            instanceId,
            proof: healthProof(proofToken, proofNonce, instanceId, 4321, 58195),
          },
        })) as typeof fetch,
      });
      expect(located).toBeNull();
      expect(tokenReads).toBe(1);
    }
  });

  test("locator cancels a chunked health body as soon as it exceeds 64 KiB", async () => {
    let pulls = 0;
    let cancels = 0;
    let tokenReads = 0;
    const chunk = new Uint8Array(64 * 1024).fill(32);
    const responseBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        if (pulls === 1) controller.enqueue(chunk);
        else if (pulls === 2) controller.enqueue(new Uint8Array([32]));
        else return new Promise<void>(() => {});
      },
      cancel() { cancels += 1; },
    });

    const located = await (runtimeModule as any).findLiveSubagentBridgeProxy({
      readPidFn: () => 4321,
      readRuntimeFn: () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1" }),
      randomBytesFn: () => Buffer.alloc(32, 18),
      readToken: () => {
        tokenReads += 1;
        return tokenValue(17);
      },
      fetchFn: (async () => new Response(responseBody, { status: 200 })) as typeof fetch,
    });

    expect(located).toBeNull();
    // A WHATWG stream may perform one final pull to discover EOF after the two
    // data chunks; cancellation, not pull count, is the bounded-read contract.
    expect(pulls).toBeLessThanOrEqual(3);
    expect(cancels).toBe(1);
    expect(tokenReads).toBe(0);
  });

  test("the shared response reader accepts exactly 64 KiB", async () => {
    const body = new Uint8Array(64 * 1024).fill(65);
    const read = await runtimeModule.readBoundedSubagentBridgeResponse(new Response(body));

    expect(read).not.toBeNull();
    expect(read?.byteLength).toBe(64 * 1024);
    expect(read).toEqual(body);
  });

  test("the shared response reader does not await a stalled overflow cancellation", async () => {
    let cancels = 0;
    const responseBody = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(64 * 1024 + 1)); },
      cancel() {
        cancels += 1;
        return new Promise<void>(() => {});
      },
    });

    const outcome = await Promise.race([
      runtimeModule.readBoundedSubagentBridgeResponse(new Response(responseBody)).then(() => "completed" as const),
      new Promise<"timed_out">(resolve => setTimeout(() => resolve("timed_out"), 50)),
    ]);

    expect(outcome).toBe("completed");
    expect(cancels).toBe(1);
  });

  test("live health returns proof only for a valid challenge and never returns the token", async () => {
    const configDir = mkdtempSync(join(tmpdir(), "ocx-bridge-live-health-proof-"));
    const previousHome = process.env.OPENCODEX_HOME;
    const token = tokenValue(18);
    process.env.OPENCODEX_HOME = configDir;
    writeFileSync(join(configDir, "config.json"), JSON.stringify({
      port: 0,
      providers: { openai: { adapter: "openai-responses", baseUrl: "https://chatgpt.com/backend-api/codex", authMode: "forward" } },
      defaultProvider: "openai",
      subagentBridge: { enabled: true },
    }));
    const tokenPath = join(configDir, TOKEN_FILE);
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    prepareRealServerToken(tokenPath);
    expect((lifecycleModule as any).readSecureSubagentBridgeToken()).toBe(token);
    const tokenStatBeforeStart = lstatSync(tokenPath, { bigint: true });
    const attestationBeforeStart = readFileSync(attestationPath(tokenPath));
    const server = startServer(0);
    try {
      const tokenStatAfterStart = lstatSync(tokenPath, { bigint: true });
      expect(process.env.OPENCODEX_HOME).toBe(configDir);
      expect(tokenStatAfterStart.ctimeNs).toBe(tokenStatBeforeStart.ctimeNs);
      expect(readFileSync(attestationPath(tokenPath))).toEqual(attestationBeforeStart);
      expect((lifecycleModule as any).readSecureSubagentBridgeToken()).toBe(token);
      const ordinary = await fetch(new URL("/healthz", server.url)).then(response => response.json()) as any;
      expect(ordinary.subagentBridge.proof).toBeUndefined();
      expect(ordinary.subagentBridge.instanceId).toBeUndefined();
      expect(JSON.stringify(ordinary)).not.toContain(token);

      const nonce = Buffer.alloc(32, 19).toString("base64url");
      const challenged = await fetch(new URL(`/healthz?challenge=${nonce}`, server.url)).then(response => response.json()) as any;
      expect(challenged.subagentBridge.instanceId).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(challenged.subagentBridge.proof).toBe(healthProof(
        token,
        nonce,
        challenged.subagentBridge.instanceId,
        process.pid,
        server.port,
      ));
      expect(JSON.stringify(challenged)).not.toContain(token);
    } finally {
      await server.stop(true);
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(configDir, { recursive: true, force: true });
    }
  });
});

describe("signed subagent handoff staging", () => {
  test("missing instance or replay state fails before token, body, or store access", async () => {
    const token = tokenValue(48);
    const instanceId = Buffer.alloc(32, 49).toString("base64url");
    let tokenReads = 0;
    const requests: Request[] = [];
    const store = new SubagentHandoffStore();
    for (const missing of [
      {},
      { instanceId },
      { replayGuard: replayGuard() },
    ]) {
      const body = new ReadableStream<Uint8Array>({
        pull(controller) {
          controller.enqueue(new TextEncoder().encode(JSON.stringify({
            kind: "message", target: TARGET, message: SECRET_MESSAGE,
          })));
          controller.close();
        },
      });
      const request = new Request(
        `http://127.0.0.1${STAGING_PATH}`,
        {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body,
        },
      );
      requests.push(request);
      const response = await (httpModule as any).handleSubagentHandoffRequest(request, {
        runtimeEligible: true,
        readToken: () => {
          tokenReads += 1;
          return token;
        },
        store,
        ...missing,
      });
      expect(response.status).toBe(503);
    }
    expect(tokenReads).toBe(0);
    expect(requests.every(request => request.bodyUsed === false)).toBe(true);
    expect(store.stats().records).toBe(0);
  });

  test("the exact captured request is rejected after replay retention expires in one instance", async () => {
    const token = tokenValue(50);
    const instanceId = Buffer.alloc(32, 51).toString("base64url");
    const requestId = Buffer.alloc(32, 52).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    let now = 1_000_000;
    const issuedAtMs = now;
    const guard = replayGuard({ now: () => now, ttlMs: REPLAY_RETENTION_MS, maxEntries: 8 });
    const store = new SubagentHandoffStore();
    const deps = {
      runtimeEligible: true,
      instanceId,
      replayGuard: guard,
      readToken: () => token,
      now: () => now,
      store,
    };
    const captured = () => freshnessSignedRequest({ token, instanceId, requestId, issuedAtMs, body });

    expect((await (httpModule as any).handleSubagentHandoffRequest(captured(), deps)).status).toBe(200);
    now += REPLAY_RETENTION_MS + 1;
    expect((await (httpModule as any).handleSubagentHandoffRequest(captured(), deps)).status).toBe(401);
    expect(store.stats().records).toBe(1);
  });

  test("a slow captured body cannot outlive freshness and replay retention", async () => {
    const token = tokenValue(61);
    const instanceId = Buffer.alloc(32, 62).toString("base64url");
    const requestId = Buffer.alloc(32, 63).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const issuedAtMs = 1_500_000;
    let now = issuedAtMs;
    let tokenReads = 0;
    const guard = replayGuard({ now: () => now, ttlMs: REPLAY_RETENTION_MS, maxEntries: 8 });
    const store = new SubagentHandoffStore();
    const deps = {
      runtimeEligible: true,
      instanceId,
      replayGuard: guard,
      readToken: () => {
        tokenReads += 1;
        return token;
      },
      now: () => now,
      store,
    };

    expect((await (httpModule as any).handleSubagentHandoffRequest(
      freshnessSignedRequest({ token, instanceId, requestId, issuedAtMs, body }),
      deps,
    )).status).toBe(200);
    expect(tokenReads).toBe(1);
    expect(store.stats().records).toBe(1);

    now = issuedAtMs + REQUEST_MAX_AGE_MS - 1;
    const stream = new TransformStream<Uint8Array, Uint8Array>();
    const wireBody = sealedRequestBody({ token, instanceId, requestId, issuedAtMs, body });
    const slowReplay = new Request(`http://127.0.0.1${STAGING_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [INSTANCE_HEADER]: instanceId,
        [REQUEST_ID_HEADER]: requestId,
        [ISSUED_AT_HEADER]: String(issuedAtMs),
        [SIGNATURE_HEADER]: requestSignature(token, instanceId, requestId, issuedAtMs, wireBody),
      },
      body: stream.readable,
    });
    const pendingReplay = (httpModule as any).handleSubagentHandoffRequest(slowReplay, deps);

    now = issuedAtMs + REPLAY_RETENTION_MS + 1;
    const writer = stream.writable.getWriter();
    await writer.write(new TextEncoder().encode(wireBody));
    await writer.close();

    expect((await pendingReplay).status).toBe(401);
    expect(tokenReads).toBe(1);
    expect(store.stats().records).toBe(1);
  });

  test("a never-ending signed body is cancelled at its remaining freshness deadline", async () => {
    const token = tokenValue(64);
    const instanceId = Buffer.alloc(32, 65).toString("base64url");
    const requestId = Buffer.alloc(32, 66).toString("base64url");
    const now = 2_000_000;
    const issuedAtMs = now - REQUEST_MAX_AGE_MS + 20;
    const plaintext = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const wireBody = sealedRequestBody({ token, instanceId, requestId, issuedAtMs, body: plaintext });
    const requestAbort = new AbortController();
    let streamController!: ReadableStreamDefaultController<Uint8Array>;
    let cancels = 0;
    let tokenReads = 0;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { streamController = controller; },
      pull() { /* deliberately remains pending */ },
      cancel() { cancels += 1; },
    });
    const request = new Request(`http://127.0.0.1${STAGING_PATH}`, {
      method: "POST",
      signal: requestAbort.signal,
      headers: {
        "content-type": "application/json",
        [INSTANCE_HEADER]: instanceId,
        [REQUEST_ID_HEADER]: requestId,
        [ISSUED_AT_HEADER]: String(issuedAtMs),
        [SIGNATURE_HEADER]: requestSignature(token, instanceId, requestId, issuedAtMs, wireBody),
      },
      body: stream,
    });
    const pending = (httpModule as any).handleSubagentHandoffRequest(request, {
      runtimeEligible: true,
      instanceId,
      replayGuard: replayGuard({ now: () => now }),
      readToken: () => {
        tokenReads += 1;
        return token;
      },
      now: () => now,
      store: new SubagentHandoffStore(),
    }) as Promise<Response>;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      pending.then(response => ({ response })),
      new Promise<{ timedOut: true }>(resolve => {
        timeout = setTimeout(() => resolve({ timedOut: true }), 250);
      }),
    ]);
    if (timeout !== undefined) clearTimeout(timeout);
    if ("timedOut" in outcome) {
      requestAbort.abort(new Error("test cleanup after missing freshness deadline"));
      try { streamController.error(new Error("test cleanup")); } catch { /* already cancelled */ }
      await pending.catch(() => undefined);
    }

    expect("timedOut" in outcome).toBe(false);
    if ("response" in outcome) expect(outcome.response.status).toBe(401);
    expect(cancels).toBe(1);
    expect(tokenReads).toBe(0);
  });

  test("request cancellation stops a pending signed body before token access", async () => {
    const token = tokenValue(67);
    const instanceId = Buffer.alloc(32, 68).toString("base64url");
    const requestId = Buffer.alloc(32, 69).toString("base64url");
    const plaintext = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const wireBody = sealedRequestBody({ token, instanceId, requestId, issuedAtMs: TEST_NOW_MS, body: plaintext });
    const requestAbort = new AbortController();
    let streamController!: ReadableStreamDefaultController<Uint8Array>;
    let cancels = 0;
    let tokenReads = 0;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { streamController = controller; },
      pull() { /* deliberately remains pending */ },
      cancel() { cancels += 1; },
    });
    const request = new Request(`http://127.0.0.1${STAGING_PATH}`, {
      method: "POST",
      signal: requestAbort.signal,
      headers: {
        "content-type": "application/json",
        [INSTANCE_HEADER]: instanceId,
        [REQUEST_ID_HEADER]: requestId,
        [ISSUED_AT_HEADER]: String(TEST_NOW_MS),
        [SIGNATURE_HEADER]: requestSignature(token, instanceId, requestId, TEST_NOW_MS, wireBody),
      },
      body: stream,
    });
    const pending = (httpModule as any).handleSubagentHandoffRequest(request, {
      runtimeEligible: true,
      instanceId,
      replayGuard: replayGuard({ now: () => TEST_NOW_MS }),
      readToken: () => {
        tokenReads += 1;
        return token;
      },
      now: () => TEST_NOW_MS,
      store: new SubagentHandoffStore(),
    }) as Promise<Response>;
    setTimeout(() => requestAbort.abort(new DOMException("client closed", "AbortError")), 10);
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      pending.then(response => ({ response }), error => ({ error })),
      new Promise<{ timedOut: true }>(resolve => {
        timeout = setTimeout(() => resolve({ timedOut: true }), 250);
      }),
    ]);
    if (timeout !== undefined) clearTimeout(timeout);
    if ("timedOut" in outcome) {
      try { streamController.error(new Error("test cleanup")); } catch { /* already cancelled */ }
      await pending.catch(() => undefined);
    }

    expect("timedOut" in outcome).toBe(false);
    expect("error" in outcome).toBe(false);
    if ("response" in outcome) expect(outcome.response.status).toBe(499);
    expect(cancels).toBe(1);
    expect(tokenReads).toBe(0);
  });

  test("request freshness accepts the exact age boundary and rejects one millisecond older", async () => {
    const token = tokenValue(53);
    const instanceId = Buffer.alloc(32, 54).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const now = 2_000_000;
    for (const [offset, status] of [
      [-REQUEST_MAX_AGE_MS, 200],
      [-REQUEST_MAX_AGE_MS - 1, 401],
    ] as const) {
      const store = new SubagentHandoffStore();
      const response = await (httpModule as any).handleSubagentHandoffRequest(freshnessSignedRequest({
        token,
        instanceId,
        requestId: Buffer.alloc(32, status === 200 ? 55 : 56).toString("base64url"),
        issuedAtMs: now + offset,
        body,
      }), {
        runtimeEligible: true,
        instanceId,
        replayGuard: replayGuard({ now: () => now, ttlMs: REPLAY_RETENTION_MS }),
        readToken: () => token,
        now: () => now,
        store,
      });
      expect(response.status).toBe(status);
      expect(store.stats().records).toBe(status === 200 ? 1 : 0);
    }
  });

  test("request freshness accepts bounded future skew and rejects one millisecond beyond it", async () => {
    const token = tokenValue(57);
    const instanceId = Buffer.alloc(32, 58).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const now = 3_000_000;
    for (const [offset, status] of [
      [REQUEST_FUTURE_SKEW_MS, 200],
      [REQUEST_FUTURE_SKEW_MS + 1, 401],
    ] as const) {
      const store = new SubagentHandoffStore();
      const response = await (httpModule as any).handleSubagentHandoffRequest(freshnessSignedRequest({
        token,
        instanceId,
        requestId: Buffer.alloc(32, status === 200 ? 59 : 60).toString("base64url"),
        issuedAtMs: now + offset,
        body,
      }), {
        runtimeEligible: true,
        instanceId,
        replayGuard: replayGuard({ now: () => now, ttlMs: REPLAY_RETENTION_MS }),
        readToken: () => token,
        now: () => now,
        store,
      });
      expect(response.status).toBe(status);
      expect(store.stats().records).toBe(status === 200 ? 1 : 0);
    }
  });

  test("valid staging uses no bearer and returns a signature over exact response bytes", async () => {
    const token = tokenValue(20);
    const instanceId = Buffer.alloc(32, 21).toString("base64url");
    const requestId = Buffer.alloc(32, 22).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const request = signedRequest({ token, instanceId, requestId, body });
    const store = new SubagentHandoffStore({ randomHex: () => "abcdef012345" });
    const response = await (httpModule as any).handleSubagentHandoffRequest(request, {
      runtimeEligible: true,
      instanceId,
      replayGuard: replayGuard(),
      readToken: () => token,
      now: () => TEST_NOW_MS,
      store,
    });
    const responseBody = await response.text();
    expect(response.status).toBe(200);
    expect(request.headers.has("authorization")).toBe(false);
    expect(JSON.stringify(Object.fromEntries(request.headers))).not.toContain(token);
    expect(response.headers.get(RESPONSE_SIGNATURE_HEADER)).toBe(responseSignature(
      token,
      instanceId,
      requestId,
      response.status,
      responseBody,
    ));
    expect(responseBody).not.toContain(SECRET_MESSAGE);
    expect(store.consume(`/root/${TARGET}`, "MESSAGE")?.message).toBe(SECRET_MESSAGE);
  });

  test("altered body, path, instance, or request ID cannot stage a signed request", async () => {
    const token = tokenValue(23);
    const instanceId = Buffer.alloc(32, 24).toString("base64url");
    const requestId = Buffer.alloc(32, 25).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const cases = [
      {
        expectedStatus: 401,
        expectedTokenReads: 1,
        request: signedRequest({ token, instanceId, requestId, body: `${body} `, signatureBody: body }),
      },
      {
        expectedStatus: 404,
        expectedTokenReads: 0,
        request: signedRequest({
          token,
          instanceId,
          requestId,
          body,
          url: "http://127.0.0.1/internal/subagent-handoffs-altered",
          signaturePath: STAGING_PATH,
        }),
      },
      {
        expectedStatus: 401,
        expectedTokenReads: 0,
        request: signedRequest({
          token,
          instanceId,
          requestId,
          body,
          headers: { [INSTANCE_HEADER]: Buffer.alloc(32, 26).toString("base64url") },
        }),
      },
      {
        expectedStatus: 401,
        expectedTokenReads: 1,
        request: signedRequest({
          token,
          instanceId,
          requestId,
          body,
          headers: { [REQUEST_ID_HEADER]: Buffer.alloc(32, 27).toString("base64url") },
        }),
      },
    ];
    for (const entry of cases) {
      let tokenReads = 0;
      const store = new SubagentHandoffStore();
      const response = await (httpModule as any).handleSubagentHandoffRequest(entry.request, {
        runtimeEligible: true,
        instanceId,
        replayGuard: replayGuard(),
        readToken: () => {
          tokenReads += 1;
          return token;
        },
        now: () => TEST_NOW_MS,
        store,
      });
      expect(response.status).toBe(entry.expectedStatus);
      expect(tokenReads).toBe(entry.expectedTokenReads);
      expect(store.stats().records).toBe(0);
    }
  });

  test("duplicate signed request IDs stage at most once", async () => {
    const token = tokenValue(28);
    const instanceId = Buffer.alloc(32, 29).toString("base64url");
    const requestId = Buffer.alloc(32, 30).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const guard = replayGuard();
    const store = new SubagentHandoffStore();
    const deps = {
      runtimeEligible: true,
      instanceId,
      replayGuard: guard,
      readToken: () => token,
      now: () => TEST_NOW_MS,
      store,
    };
    const first = await (httpModule as any).handleSubagentHandoffRequest(
      signedRequest({ token, instanceId, requestId, body }),
      deps,
    );
    const replayed = await (httpModule as any).handleSubagentHandoffRequest(
      signedRequest({ token, instanceId, requestId, body }),
      deps,
    );
    expect(first.status).toBe(200);
    expect(replayed.status).toBe(409);
    expect(store.stats().records).toBe(1);
  });

  test("a proxy restart instance ID invalidates captured signed requests", async () => {
    const token = tokenValue(31);
    const oldInstance = Buffer.alloc(32, 32).toString("base64url");
    const newInstance = Buffer.alloc(32, 33).toString("base64url");
    const requestId = Buffer.alloc(32, 34).toString("base64url");
    const body = JSON.stringify({ kind: "message", target: TARGET, message: SECRET_MESSAGE });
    const captured = () => signedRequest({ token, instanceId: oldInstance, requestId, body });
    const oldStore = new SubagentHandoffStore();
    const accepted = await (httpModule as any).handleSubagentHandoffRequest(captured(), {
      runtimeEligible: true,
      instanceId: oldInstance,
      replayGuard: replayGuard(),
      readToken: () => token,
      now: () => TEST_NOW_MS,
      store: oldStore,
    });
    const newStore = new SubagentHandoffStore();
    const rejected = await (httpModule as any).handleSubagentHandoffRequest(captured(), {
      runtimeEligible: true,
      instanceId: newInstance,
      replayGuard: replayGuard(),
      readToken: () => token,
      now: () => TEST_NOW_MS,
      store: newStore,
    });
    expect(accepted.status).toBe(200);
    expect(rejected.status).toBe(401);
    expect(newStore.stats().records).toBe(0);
  });

  test("the replay cache is bounded and cannot retain IDs for less than the freshness horizon", () => {
    let now = 1_000;
    expect(() => replayGuard({
      now: () => now,
      ttlMs: REQUEST_MAX_AGE_MS + REQUEST_FUTURE_SKEW_MS,
      maxEntries: 2,
    })).toThrow("replay bounds");
    expect(() => replayGuard({
      now: () => now,
      ttlMs: REQUEST_MAX_AGE_MS + REQUEST_FUTURE_SKEW_MS - 1,
      maxEntries: 2,
    })).toThrow("replay bounds");
    const guard = replayGuard({ now: () => now, ttlMs: REPLAY_RETENTION_MS, maxEntries: 2 });
    expect(guard.claim("a")).toBe(true);
    expect(guard.claim("a")).toBe(false);
    expect(guard.claim("b")).toBe(true);
    expect(guard.claim("c")).toBe(false);
    now += REPLAY_RETENTION_MS + 1;
    expect(guard.claim("c")).toBe(true);
  });

  test("MCP rejects unsigned or badly signed success responses", async () => {
    const token = tokenValue(35);
    const instanceId = Buffer.alloc(32, 36).toString("base64url");
    for (const signature of [undefined, "A".repeat(43)]) {
      let sentAuthorization: string | null = "not-called";
      const fetchFn = (async (_url: string | URL | Request, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        sentAuthorization = headers.get("authorization");
        return new Response(JSON.stringify({ target: TARGET, expires_in_seconds: 300 }), {
          status: 200,
          headers: signature ? { [RESPONSE_SIGNATURE_HEADER]: signature } : undefined,
        });
      }) as typeof fetch;
      await expect((mcpModule as any).prepareViaProxy(
        { kind: "message", target: TARGET, message: SECRET_MESSAGE },
        {
          findProxy: async () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId }),
          readToken: () => token,
          randomBytesFn: () => Buffer.alloc(32, 37),
          now: () => TEST_NOW_MS,
          fetchFn,
        },
      )).rejects.toThrow("unavailable");
      expect(sentAuthorization).toBeNull();
    }
  });

  test("MCP cancels a chunked success body as soon as it exceeds 64 KiB", async () => {
    const token = tokenValue(70);
    const instanceId = Buffer.alloc(32, 71).toString("base64url");
    let pulls = 0;
    let cancels = 0;
    const chunk = new Uint8Array(64 * 1024).fill(32);
    const responseBody = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulls += 1;
        if (pulls === 1) controller.enqueue(chunk);
        else if (pulls === 2) controller.enqueue(new Uint8Array([32]));
        else return new Promise<void>(() => {});
      },
      cancel() { cancels += 1; },
    });

    await expect((mcpModule as any).prepareViaProxy(
      { kind: "message", target: TARGET, message: SECRET_MESSAGE },
      {
        findProxy: async () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId }),
        readToken: () => token,
        randomBytesFn: () => Buffer.alloc(32, 72),
        now: () => TEST_NOW_MS,
        fetchFn: (async () => new Response(responseBody, { status: 200 })) as typeof fetch,
      },
    )).rejects.toThrow("unavailable");

    // A WHATWG stream may perform one final pull to discover EOF after the two
    // data chunks; cancellation, not pull count, is the bounded-read contract.
    expect(pulls).toBeLessThanOrEqual(3);
    expect(cancels).toBe(1);
  });

  test("MCP does not await a stalled non-success body cancellation", async () => {
    const token = tokenValue(73);
    const instanceId = Buffer.alloc(32, 74).toString("base64url");
    let cancels = 0;
    const responseBody = new ReadableStream<Uint8Array>({
      cancel() {
        cancels += 1;
        return new Promise<void>(() => {});
      },
    });

    const request = (mcpModule as any).prepareViaProxy(
      { kind: "message", target: TARGET, message: SECRET_MESSAGE },
      {
        findProxy: async () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId }),
        readToken: () => token,
        randomBytesFn: () => Buffer.alloc(32, 75),
        now: () => TEST_NOW_MS,
        fetchFn: (async () => new Response(responseBody, { status: 503 })) as typeof fetch,
      },
    );
    const outcome = await Promise.race([
      request.then(() => "resolved" as const, () => "rejected" as const),
      new Promise<"timed_out">(resolve => setTimeout(() => resolve("timed_out"), 50)),
    ]);

    expect(outcome).toBe("rejected");
    expect(cancels).toBe(1);
  });

  test("MCP accepts a signed response and sends no Authorization or token substring", async () => {
    const token = tokenValue(38);
    const instanceId = Buffer.alloc(32, 39).toString("base64url");
    let capturedHeaders = new Headers();
    let capturedBody = "";
    const fetchFn = (async (_url: string | URL | Request, init?: RequestInit) => {
      capturedHeaders = new Headers(init?.headers);
      capturedBody = String(init?.body ?? "");
      const requestId = capturedHeaders.get(REQUEST_ID_HEADER) ?? Buffer.alloc(32, 47).toString("base64url");
      const responseBody = JSON.stringify({ target: TARGET, expires_in_seconds: 300 });
      return new Response(responseBody, {
        status: 200,
        headers: {
          "content-type": "application/json",
          [RESPONSE_SIGNATURE_HEADER]: responseSignature(token, instanceId, requestId, 200, responseBody),
        },
      });
    }) as typeof fetch;
    const result = await (mcpModule as any).prepareViaProxy(
      { kind: "message", target: TARGET, message: SECRET_MESSAGE },
      {
        findProxy: async () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId }),
        readToken: () => token,
        randomBytesFn: () => Buffer.alloc(32, 40),
        now: () => TEST_NOW_MS,
        fetchFn,
      },
    );
    expect(result).toEqual({ target: TARGET, expires_in_seconds: 300 });
    expect(capturedHeaders.get("authorization")).toBeNull();
    expect(JSON.stringify(Object.fromEntries(capturedHeaders))).not.toContain(token);
    expect(capturedHeaders.get(SIGNATURE_HEADER)).toBe(requestSignature(
      token,
      instanceId,
      Buffer.alloc(32, 40).toString("base64url"),
      TEST_NOW_MS,
      capturedBody,
    ));
    expect(capturedBody).not.toContain(SECRET_MESSAGE);
    const opened = (authModule as any).openSubagentBridgeRequestBody(capturedBody, {
      token,
      protocol: PROTOCOL,
      method: "POST",
      path: STAGING_PATH,
      instanceId,
      requestId: Buffer.alloc(32, 40).toString("base64url"),
      issuedAtMs: TEST_NOW_MS,
    });
    expect(JSON.parse(new TextDecoder().decode(opened))).toEqual({
      kind: "message",
      target: TARGET,
      message: SECRET_MESSAGE,
    });
  });

  test("a public-health spoof without the key receives no handoff plaintext", async () => {
    const token = tokenValue(41);
    let handoffRequests = 0;
    let leakedPlaintext = false;
    const foreign = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === "/healthz") {
          return Response.json({
            status: "ok",
            service: "opencodex",
            pid: 4321,
            port: foreign.port,
            subagentBridge: {
              protocol: PROTOCOL,
              eligible: true,
              instanceId: Buffer.alloc(32, 42).toString("base64url"),
              proof: "A".repeat(43),
            },
          });
        }
        if (url.pathname === STAGING_PATH) {
          handoffRequests += 1;
          return req.text().then(body => {
            leakedPlaintext ||= body.includes(SECRET_MESSAGE);
            return Response.json({ error: "unavailable" }, { status: 503 });
          });
        }
        return new Response(null, { status: 404 });
      },
    });
    try {
      await expect((mcpModule as any).prepareViaProxy(
        { kind: "message", target: TARGET, message: SECRET_MESSAGE },
        {
          findProxy: () => (runtimeModule as any).findLiveSubagentBridgeProxy({
            readPidFn: () => 4321,
            readRuntimeFn: () => ({ pid: 4321, port: foreign.port, hostname: "127.0.0.1" }),
            verifyPidFn: (pid: number) => pid,
            randomBytesFn: () => Buffer.alloc(32, 43),
            readToken: () => token,
          }),
          readToken: () => token,
        },
      )).rejects.toThrow("unavailable");
      expect(handoffRequests).toBe(0);
      expect(leakedPlaintext).toBe(false);
    } finally {
      await foreign.stop(true);
    }
  });

  test("a listener rebound after authenticated discovery receives no handoff plaintext", async () => {
    const token = tokenValue(48);
    const instanceId = Buffer.alloc(32, 49).toString("base64url");
    let capturedBody = "";
    const fetchFn = (async (_url: string | URL | Request, init?: RequestInit) => {
      capturedBody = String(init?.body ?? "");
      return Response.json({ error: "foreign listener" }, { status: 503 });
    }) as typeof fetch;

    await expect((mcpModule as any).prepareViaProxy(
      { kind: "message", target: TARGET, message: SECRET_MESSAGE },
      {
        findProxy: async () => ({ pid: 4321, port: 58195, hostname: "127.0.0.1", instanceId }),
        readToken: () => token,
        randomBytesFn: () => Buffer.alloc(32, 50),
        now: () => TEST_NOW_MS,
        fetchFn,
      },
    )).rejects.toThrow("unavailable");

    expect(capturedBody).not.toContain(SECRET_MESSAGE);
  });

  test("prepareViaProxy completes through a real authenticated local server", async () => {
    const configDir = mkdtempSync(join(tmpdir(), "ocx-bridge-signed-e2e-"));
    const previousHome = process.env.OPENCODEX_HOME;
    const token = tokenValue(44);
    process.env.OPENCODEX_HOME = configDir;
    writeFileSync(join(configDir, "config.json"), JSON.stringify({
      port: 0,
      providers: { openai: { adapter: "openai-responses", baseUrl: "https://chatgpt.com/backend-api/codex", authMode: "forward" } },
      defaultProvider: "openai",
      subagentBridge: { enabled: true },
    }));
    const tokenPath = join(configDir, TOKEN_FILE);
    writeFileSync(tokenPath, `${token}\n`, { mode: 0o600 });
    prepareRealServerToken(tokenPath);
    expect((lifecycleModule as any).readSecureSubagentBridgeToken()).toBe(token);
    const server = startServer(0);
    subagentHandoffStore.clear();
    try {
      const live = await (runtimeModule as any).findLiveSubagentBridgeProxy({
        readPidFn: () => process.pid,
        readRuntimeFn: () => ({ pid: process.pid, port: server.port, hostname: "127.0.0.1" }),
        verifyPidFn: (pid: number) => pid,
        readToken: () => token,
        randomBytesFn: () => Buffer.alloc(32, 45),
        timeoutMs: 3_000,
      });
      expect(live?.instanceId).toMatch(/^[A-Za-z0-9_-]{43}$/);
      let authorization: string | null = "not-called";
      let tokenInHeaders = true;
      const result = await (mcpModule as any).prepareViaProxy(
        { kind: "message", target: TARGET, message: SECRET_MESSAGE },
        {
          findProxy: async () => live,
          readToken: () => token,
          randomBytesFn: () => Buffer.alloc(32, 46),
          fetchFn: (async (url: string | URL | Request, init?: RequestInit) => {
            const headers = new Headers(init?.headers);
            authorization = headers.get("authorization");
            tokenInHeaders = JSON.stringify(Object.fromEntries(headers)).includes(token);
            return fetch(url, init);
          }) as typeof fetch,
        },
      );
      expect(result).toEqual({ target: TARGET, expires_in_seconds: 300 });
      expect(authorization).toBeNull();
      expect(tokenInHeaders).toBe(false);
      expect(subagentHandoffStore.consume(`/root/${TARGET}`, "MESSAGE")?.message).toBe(SECRET_MESSAGE);
    } finally {
      subagentHandoffStore.clear();
      await server.stop(true);
      if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = previousHome;
      rmSync(configDir, { recursive: true, force: true });
    }
  });
});
