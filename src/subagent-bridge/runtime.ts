import {
  readAlivePid,
  readRuntimePort,
  type RuntimePortState,
} from "../config";
import type { OcxConfig } from "../types";
import {
  createSubagentBridgeHealthProof,
  createSubagentBridgeRandomValue,
  isSubagentBridgeRandomValue,
  subagentBridgeMacMatches,
} from "./auth";
import { readSecureSubagentBridgeToken } from "./lifecycle";

export const SUBAGENT_BRIDGE_HEALTH_PROTOCOL = "opencodex-subagent-handoff-v2";
export const SUBAGENT_BRIDGE_MAX_RESPONSE_BYTES = 64 * 1024;

export interface LiveSubagentBridgeProxy {
  pid: number;
  port: number;
  hostname: "127.0.0.1" | "[::1]";
  instanceId: string;
}

export interface SubagentBridgeLocatorIo {
  fetchFn?: typeof fetch;
  readPidFn?: () => number | null;
  readRuntimeFn?: (expectedPid?: number) => RuntimePortState | null;
  randomBytesFn?: (length: number) => Uint8Array;
  readToken?: () => string | null;
  timeoutMs?: number;
}

function cancelResponseReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  reason: unknown,
): void {
  try { void reader.cancel(reason).catch(() => undefined); } catch { /* best-effort transport cleanup */ }
}

/** Read an untrusted loopback response without retaining more than the bridge's fixed cap. */
export async function readBoundedSubagentBridgeResponse(
  response: Response,
  maxBytes = SUBAGENT_BRIDGE_MAX_RESPONSE_BYTES,
): Promise<Uint8Array | null> {
  const body = response.body;
  if (!body) return new Uint8Array();
  const reader = body.getReader();
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      cancelResponseReader(reader, new DOMException("bridge response too large", "QuotaExceededError"));
      return null;
    }
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (value.byteLength > maxBytes - total) {
        cancelResponseReader(reader, new DOMException("bridge response too large", "QuotaExceededError"));
        return null;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch (error) {
    cancelResponseReader(reader, error);
    return null;
  } finally {
    try { reader.releaseLock(); } catch { /* cancellation may retain the lock briefly */ }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

export function normalizedActualBindHostname(hostname: string | undefined): string {
  const value = hostname?.trim() ?? "";
  if (!value || /^localhost$/i.test(value)) return "127.0.0.1";
  return value;
}

export function literalLoopbackEndpointHost(
  hostname: string | undefined,
): "127.0.0.1" | "[::1]" | null {
  const value = hostname?.trim() ?? "";
  if (value === "127.0.0.1") return "127.0.0.1";
  if (value === "::1" || value === "[::1]") return "[::1]";
  return null;
}

export function subagentBridgeRuntimePortState(
  pid: number,
  port: number,
  configuredHostname: string | undefined,
): RuntimePortState {
  return { pid, port, hostname: normalizedActualBindHostname(configuredHostname) };
}

export function subagentBridgeRuntimeEligible(
  config: Pick<OcxConfig, "hostname" | "subagentBridge" | "multiAgentMode">,
  actualBindHostname = normalizedActualBindHostname(config.hostname),
): boolean {
  return config.subagentBridge?.enabled === true
    && config.multiAgentMode !== "v1"
    && literalLoopbackEndpointHost(actualBindHostname) !== null;
}

/**
 * Locate only the active bridge-capable proxy recorded for the exact owned process.
 * Unlike general CLI liveness, this deliberately has no configured-port or legacy-health fallback.
 */
export async function findLiveSubagentBridgeProxy(
  io: SubagentBridgeLocatorIo = {},
): Promise<LiveSubagentBridgeProxy | null> {
  const pid = (io.readPidFn ?? readAlivePid)();
  if (pid === null) return null;
  const runtime = (io.readRuntimeFn ?? readRuntimePort)(pid);
  if (!runtime
    || runtime.pid !== pid
    || !Number.isSafeInteger(runtime.port)
    || runtime.port <= 0
    || runtime.port > 65535) return null;
  const hostname = literalLoopbackEndpointHost(runtime.hostname);
  if (!hostname) return null;

  try {
    const nonce = createSubagentBridgeRandomValue(io.randomBytesFn);
    const healthUrl = new URL(`http://${hostname}:${runtime.port}/healthz`);
    healthUrl.searchParams.set("challenge", nonce);
    const response = await (io.fetchFn ?? fetch)(healthUrl, {
      signal: AbortSignal.timeout(io.timeoutMs ?? 750),
    });
    if (!response.ok) return null;
    const responseBytes = await readBoundedSubagentBridgeResponse(response);
    if (!responseBytes) return null;
    let body: Record<string, any> | null = null;
    try {
      body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(responseBytes)) as Record<string, any>;
    } catch { return null; }
    if (!body
      || body.status !== "ok"
      || body.service !== "opencodex"
      || body.pid !== pid
      || body.port !== runtime.port
      || body.subagentBridge?.protocol !== SUBAGENT_BRIDGE_HEALTH_PROTOCOL
      || body.subagentBridge?.eligible !== true
      || !isSubagentBridgeRandomValue(body.subagentBridge?.instanceId)
      || !isSubagentBridgeRandomValue(body.subagentBridge?.proof)) {
      return null;
    }
    const token = (io.readToken ?? readSecureSubagentBridgeToken)();
    if (!token) return null;
    const expectedProof = createSubagentBridgeHealthProof({
      token,
      protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
      instanceId: body.subagentBridge.instanceId,
      nonce,
      pid,
      port: runtime.port,
    });
    if (!subagentBridgeMacMatches(body.subagentBridge.proof, expectedProof)) return null;
    return { pid, port: runtime.port, hostname, instanceId: body.subagentBridge.instanceId };
  } catch {
    return null;
  }
}
