import { z } from "zod";
import { jsonResponse } from "../server/auth-cors";
import {
  HANDOFF_MAX_MESSAGE_BYTES,
  HANDOFF_TTL_MS,
  SubagentHandoffError,
  SubagentHandoffStore,
  subagentHandoffStore,
} from "./handoff-store";
import { readSecureSubagentBridgeToken } from "./lifecycle";
export { readSecureSubagentBridgeToken as readSubagentBridgeToken } from "./lifecycle";
import { parseVerifiedSubagentTarget } from "./target";
import {
  createSubagentBridgeRequestSignature,
  createSubagentBridgeResponseSignature,
  isSubagentBridgeRandomValue,
  openSubagentBridgeRequestBody,
  SUBAGENT_BRIDGE_ISSUED_AT_HEADER,
  SUBAGENT_BRIDGE_INSTANCE_HEADER,
  SUBAGENT_BRIDGE_REQUEST_FUTURE_SKEW_MS,
  SUBAGENT_BRIDGE_REQUEST_ID_HEADER,
  SUBAGENT_BRIDGE_REQUEST_MAX_AGE_MS,
  SUBAGENT_BRIDGE_RESPONSE_SIGNATURE_HEADER,
  SUBAGENT_BRIDGE_SIGNATURE_HEADER,
  SUBAGENT_BRIDGE_STAGING_PATH,
  SubagentBridgeReplayGuard,
  subagentBridgeMacMatches,
} from "./auth";
import { SUBAGENT_BRIDGE_HEALTH_PROTOCOL } from "./runtime";
export { SubagentBridgeReplayGuard } from "./auth";

const SpawnSchema = z.object({
  kind: z.literal("spawn"),
  task_name: z.string().trim().min(1).max(200),
  model: z.string().trim().min(1).max(512),
  message: z.string().min(1),
}).strict();

const MessageSchema = z.object({
  kind: z.enum(["message", "followup"]),
  target: z.string().min(1).max(1024),
  message: z.string().min(1),
}).strict();

export const SubagentHandoffRequestSchema = z.discriminatedUnion("kind", [SpawnSchema, MessageSchema]);
export type SubagentHandoffRequest = z.infer<typeof SubagentHandoffRequestSchema>;

export interface SubagentHandoffHttpDeps {
  readToken?: () => string | null;
  runtimeEligible?: boolean;
  store?: SubagentHandoffStore;
  instanceId?: string;
  replayGuard?: SubagentBridgeReplayGuard;
  now?: () => number;
}

const HANDOFF_MAX_REQUEST_BYTES = HANDOFF_MAX_MESSAGE_BYTES * 6 + 4096;
export function canonicalizeVerifiedSubagentTarget(value: string): string | null {
  return parseVerifiedSubagentTarget(value)?.value ?? null;
}

const BODY_FRESHNESS_EXPIRED = Symbol("bridge body freshness expired");
const BODY_REQUEST_ABORTED = Symbol("bridge body request aborted");

function cancelRequestReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  reason: unknown,
): void {
  try { void reader.cancel(reason).catch(() => undefined); } catch { /* best-effort cleanup */ }
}

async function readBoundedBody(
  req: Request,
  options: { freshnessRemainingMs: number },
): Promise<{ bytes?: Uint8Array; status?: number }> {
  const contentLength = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(contentLength) && contentLength > HANDOFF_MAX_REQUEST_BYTES) {
    try {
      void req.body?.cancel(new DOMException("handoff request too large", "QuotaExceededError")).catch(() => undefined);
    } catch { /* no body */ }
    return { status: 413 };
  }
  if (!req.body) return { status: 400 };
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let freshnessTimer: ReturnType<typeof setTimeout> | undefined;
  const freshnessExpired = new Promise<typeof BODY_FRESHNESS_EXPIRED>(resolve => {
    freshnessTimer = setTimeout(
      () => resolve(BODY_FRESHNESS_EXPIRED),
      Math.max(0, options.freshnessRemainingMs),
    );
  });
  let resolveAbort: (() => void) | undefined;
  const requestAborted = new Promise<typeof BODY_REQUEST_ABORTED>(resolve => {
    resolveAbort = () => resolve(BODY_REQUEST_ABORTED);
  });
  const onAbort = () => resolveAbort?.();
  req.signal.addEventListener("abort", onAbort, { once: true });
  if (req.signal.aborted) onAbort();
  try {
    while (true) {
      const read = reader.read();
      void read.catch(() => undefined);
      const outcome = await Promise.race([read, freshnessExpired, requestAborted]);
      if (outcome === BODY_FRESHNESS_EXPIRED) {
        cancelRequestReader(reader, new DOMException("handoff request expired", "TimeoutError"));
        return { status: 401 };
      }
      if (outcome === BODY_REQUEST_ABORTED || req.signal.aborted) {
        cancelRequestReader(reader, req.signal.reason);
        return { status: 499 };
      }
      const { value, done } = outcome as ReadableStreamReadResult<Uint8Array>;
      if (done) break;
      if (!value || value.byteLength === 0) continue;
      if (value.byteLength > HANDOFF_MAX_REQUEST_BYTES - total) {
        cancelRequestReader(reader, new DOMException("handoff request too large", "QuotaExceededError"));
        return { status: 413 };
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } catch {
    cancelRequestReader(reader, req.signal.reason);
    return { status: req.signal.aborted ? 499 : 400 };
  } finally {
    if (freshnessTimer !== undefined) clearTimeout(freshnessTimer);
    req.signal.removeEventListener("abort", onAbort);
    try { reader.releaseLock(); } catch { /* canceled read may retain briefly */ }
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes };
}

interface SignedResponseContext {
  token: string;
  instanceId: string;
  requestId: string;
}

function canonicalIssuedAt(value: string | null): number | null {
  if (!value || !/^(?:0|[1-9]\d{0,15})$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed >= 0 && String(parsed) === value ? parsed : null;
}

function currentRequestTime(nowFn: () => number): number | null {
  try {
    const now = nowFn();
    return Number.isSafeInteger(now) && now >= 0 ? now : null;
  } catch {
    return null;
  }
}

function requestIsFreshAt(issuedAtMs: number, now: number): boolean {
  return issuedAtMs >= now - SUBAGENT_BRIDGE_REQUEST_MAX_AGE_MS
    && issuedAtMs <= now + SUBAGENT_BRIDGE_REQUEST_FUTURE_SKEW_MS;
}

function signedJsonResponse(data: unknown, status: number, context: SignedResponseContext): Response {
  const body = JSON.stringify(data);
  const signature = createSubagentBridgeResponseSignature({
    token: context.token,
    protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    instanceId: context.instanceId,
    requestId: context.requestId,
    status,
    body,
  });
  if (!signature) return jsonResponse({ error: "handoff unavailable", code: "handoff_unavailable" }, 503);
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json",
      [SUBAGENT_BRIDGE_RESPONSE_SIGNATURE_HEADER]: signature,
    },
  });
}

function handoffErrorData(error: unknown): { data: Record<string, string>; status: number } {
  if (!(error instanceof SubagentHandoffError)) {
    return { data: { error: "handoff unavailable", code: "handoff_unavailable" }, status: 503 };
  }
  if (error.code === "message_too_large") return { data: { error: "handoff rejected", code: error.code }, status: 413 };
  if (error.code === "record_capacity_exceeded" || error.code === "byte_capacity_exceeded") {
    return { data: { error: "handoff unavailable", code: error.code }, status: 429 };
  }
  return { data: { error: "handoff rejected", code: error.code }, status: 400 };
}

export async function handleSubagentHandoffRequest(
  req: Request,
  deps: SubagentHandoffHttpDeps = {},
): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "method not allowed" }, 405);
  let path: string;
  try { path = new URL(req.url).pathname; } catch { return jsonResponse({ error: "not found" }, 404); }
  if (path !== SUBAGENT_BRIDGE_STAGING_PATH) return jsonResponse({ error: "not found" }, 404);
  if (!isSubagentBridgeRandomValue(deps.instanceId) || !deps.replayGuard) {
    return jsonResponse({ error: "handoff unavailable", code: "handoff_unavailable" }, 503);
  }
  if (deps.runtimeEligible !== true) {
    return jsonResponse({ error: "handoff unavailable", code: "handoff_unavailable" }, 503);
  }
  const requestInstance = req.headers.get(SUBAGENT_BRIDGE_INSTANCE_HEADER);
  const requestId = req.headers.get(SUBAGENT_BRIDGE_REQUEST_ID_HEADER);
  const issuedAtMs = canonicalIssuedAt(req.headers.get(SUBAGENT_BRIDGE_ISSUED_AT_HEADER));
  const actualSignature = req.headers.get(SUBAGENT_BRIDGE_SIGNATURE_HEADER);
  if (requestInstance !== deps.instanceId
    || !isSubagentBridgeRandomValue(requestId)
    || issuedAtMs === null
    || !isSubagentBridgeRandomValue(actualSignature)) {
    return jsonResponse({ error: "bridge authentication required" }, 401);
  }
  const nowFn = deps.now ?? Date.now;
  const receivedAt = currentRequestTime(nowFn);
  if (receivedAt === null) {
    return jsonResponse({ error: "handoff unavailable", code: "handoff_unavailable" }, 503);
  }
  if (!requestIsFreshAt(issuedAtMs, receivedAt)) {
    return jsonResponse({ error: "bridge authentication required" }, 401);
  }
  const freshnessRemainingMs = SUBAGENT_BRIDGE_REQUEST_MAX_AGE_MS - (receivedAt - issuedAtMs);
  const bounded = await readBoundedBody(req, { freshnessRemainingMs });
  if (bounded.status === 401) return jsonResponse({ error: "bridge authentication required" }, 401);
  if (bounded.status === 499) return jsonResponse({ error: "client cancelled" }, 499);
  if (bounded.status) return jsonResponse({ error: bounded.status === 413 ? "request too large" : "invalid request" }, bounded.status);
  const bodyReceivedAt = currentRequestTime(nowFn);
  if (bodyReceivedAt === null) {
    return jsonResponse({ error: "handoff unavailable", code: "handoff_unavailable" }, 503);
  }
  if (!requestIsFreshAt(issuedAtMs, bodyReceivedAt)) {
    return jsonResponse({ error: "bridge authentication required" }, 401);
  }
  const token = (deps.readToken ?? readSecureSubagentBridgeToken)();
  if (!token) return jsonResponse({ error: "bridge authentication required" }, 401);
  const expectedSignature = createSubagentBridgeRequestSignature({
    token,
    protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    method: req.method,
    path,
    instanceId: deps.instanceId,
    requestId,
    issuedAtMs,
    body: bounded.bytes!,
  });
  if (!subagentBridgeMacMatches(actualSignature, expectedSignature)) {
    return jsonResponse({ error: "bridge authentication required" }, 401);
  }
  const signedContext: SignedResponseContext = { token, instanceId: deps.instanceId, requestId };
  if (!deps.replayGuard.claim(requestId)) {
    return signedJsonResponse({ error: "handoff rejected", code: "request_replayed" }, 409, signedContext);
  }
  const plaintext = openSubagentBridgeRequestBody(bounded.bytes!, {
    token,
    protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    method: req.method,
    path,
    instanceId: deps.instanceId,
    requestId,
    issuedAtMs,
  });
  if (!plaintext) {
    return signedJsonResponse({ error: "invalid request" }, 400, signedContext);
  }
  let raw: unknown;
  try { raw = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext)); }
  catch {
    return signedJsonResponse({ error: "invalid request" }, 400, signedContext);
  }
  const parsed = SubagentHandoffRequestSchema.safeParse(raw);
  if (!parsed.success) {
    return signedJsonResponse({ error: "invalid request" }, 400, signedContext);
  }
  const store = deps.store ?? subagentHandoffStore;
  try {
    if (parsed.data.kind === "spawn") {
      const result = store.stageSpawn({
        taskName: parsed.data.task_name,
        model: parsed.data.model,
        message: parsed.data.message,
      });
      const data = { task_name: result.taskName, expires_in_seconds: HANDOFF_TTL_MS / 1000 };
      return signedJsonResponse(data, 200, signedContext);
    }
    const target = canonicalizeVerifiedSubagentTarget(parsed.data.target);
    if (!target) {
      return signedJsonResponse({ error: "invalid request" }, 400, signedContext);
    }
    const result = store.stageMessage({
      kind: parsed.data.kind,
      target,
      message: parsed.data.message,
    });
    const data = { target: result.target, expires_in_seconds: HANDOFF_TTL_MS / 1000 };
    return signedJsonResponse(data, 200, signedContext);
  } catch (error) {
    const response = handoffErrorData(error);
    return signedJsonResponse(response.data, response.status, signedContext);
  }
}
