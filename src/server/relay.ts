import type { ResponsesTerminalStatus } from "../bridge";
import { isUsageDebugEnabled } from "../usage/debug";
import {
  addRequestLog,
  addFinalRequestLog,
  httpStatusForRequestLogTerminal,
  inspectResponseLogJson,
  inspectResponseLogSsePayload,
  recordFirstOutput,
  type RequestLogContext,
  type RequestLogEntry,
} from "./request-log";

const nativePassthroughSseResponses = new WeakSet<Response>();

export function relayWithAbort(
  body: ReadableStream<Uint8Array> | null,
  upstream: AbortController,
): ReadableStream<Uint8Array> | null {
  if (!body) return null;
  const reader = body.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        try { controller.error(err); } catch { /* already torn down */ }
      }
    },
    cancel(reason) {
      // Client disconnected: abort the upstream fetch and release the reader so we do not leak it.
      upstream.abort(reason);
      reader.cancel(reason).catch(() => {});
    },
  });
}

/**
 * Relay a passthrough SSE body like relayWithAbort, but convert a MID-STREAM failure (upstream
 * reset after headers) into a clean terminal: any partial block is closed off, then a synthetic
 * `response.failed` event and `data: [DONE]` are emitted and the stream closes. Without this the
 * client sees a raw socket teardown with no terminal SSE event. Deliberately NOT a resend: the
 * upstream already committed the request (duplicate-completion risk — same policy as cursor's
 * committed=non-replayable transport retry).
 */
export function relaySseWithFailedTail(
  body: ReadableStream<Uint8Array>,
  upstream: AbortController,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  const encoder = new TextEncoder();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (err) {
        const failure = {
          type: "upstream_error",
          code: "upstream_reset",
          message: `Upstream stream terminated unexpectedly: ${err instanceof Error ? err.message : String(err)}`,
        };
        const payload = JSON.stringify({
          type: "response.failed",
          response: { status: "failed", error: failure, last_error: failure },
        });
        try {
          // Leading blank line terminates a partial SSE block so the failed frame parses cleanly.
          controller.enqueue(encoder.encode(`\n\nevent: response.failed\ndata: ${payload}\n\ndata: [DONE]\n\n`));
          controller.close();
        } catch { /* client already torn down */ }
        upstream.abort();
      }
    },
    cancel(reason) {
      upstream.abort(reason);
      reader.cancel(reason).catch(() => {});
    },
  });
}

const SENSITIVE_FAILURE_CODE_METADATA: Record<string, { status: number; type: string }> = {
  client_closed_request: { status: 499, type: "invalid_request_error" },
  client_cancelled: { status: 499, type: "client_cancelled" },
  context_length_exceeded: { status: 400, type: "invalid_request_error" },
  tool_catalog_too_large: { status: 400, type: "invalid_request_error" },
  origin_rejected: { status: 400, type: "invalid_request_error" },
  invalid_request_error: { status: 400, type: "invalid_request_error" },
  invalid_api_key: { status: 401, type: "authentication_error" },
  permission_denied: { status: 403, type: "permission_error" },
  subscription_required: { status: 403, type: "permission_error" },
  insufficient_quota: { status: 429, type: "insufficient_quota" },
  rate_limit_exceeded: { status: 429, type: "rate_limit_error" },
  server_is_overloaded: { status: 503, type: "server_error" },
  upstream_server_error: { status: 502, type: "server_error" },
  upstream_reset: { status: 502, type: "upstream_error" },
};

const SENSITIVE_FAILURE_TYPE_STATUS: Record<string, number> = {
  client_cancelled: 499,
  invalid_request_error: 400,
  authentication_error: 401,
  permission_error: 403,
  insufficient_quota: 429,
  rate_limit_error: 429,
  proxy_error: 500,
  server_error: 502,
  upstream_error: 502,
};

function sensitiveFailureError(payload: unknown): Record<string, unknown> | undefined {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return undefined;
  const root = payload as Record<string, unknown>;
  const response = root.response && typeof root.response === "object" && !Array.isArray(root.response)
    ? root.response as Record<string, unknown>
    : root;
  const candidate = response.error ?? response.last_error ?? root.error ?? root.last_error;
  return candidate && typeof candidate === "object" && !Array.isArray(candidate)
    ? candidate as Record<string, unknown>
    : undefined;
}

function defaultSensitiveFailure(status: number): { type: string; code: string } {
  if (status === 499) return { type: "invalid_request_error", code: "client_closed_request" };
  if (status === 400) return { type: "invalid_request_error", code: "invalid_request_error" };
  if (status === 401) return { type: "authentication_error", code: "invalid_api_key" };
  if (status === 403) return { type: "permission_error", code: "permission_denied" };
  if (status === 429) return { type: "rate_limit_error", code: "rate_limit_exceeded" };
  if (status === 503) return { type: "server_error", code: "server_is_overloaded" };
  if (status >= 500) return { type: "server_error", code: "upstream_server_error" };
  return { type: "upstream_error", code: "upstream_server_error" };
}

export function sensitiveFailureMetadata(
  payload: unknown,
  fallbackStatus = 502,
): { status: number; error: { type: string; code: string; message: string }; classificationCode?: string } {
  const rawError = sensitiveFailureError(payload);
  const rawCode = typeof rawError?.code === "string" ? rawError.code : undefined;
  const codeMetadata = rawCode ? SENSITIVE_FAILURE_CODE_METADATA[rawCode] : undefined;
  const rawType = typeof rawError?.type === "string" ? rawError.type : undefined;
  const typeStatus = rawType ? SENSITIVE_FAILURE_TYPE_STATUS[rawType] : undefined;
  const status = codeMetadata
    ? (fallbackStatus >= 500 && codeMetadata.status >= 500 ? fallbackStatus : codeMetadata.status)
    : typeStatus !== undefined
      ? (fallbackStatus >= 500 && typeStatus >= 500 ? fallbackStatus : typeStatus)
      : fallbackStatus >= 400
        ? fallbackStatus
        : 502;
  const defaults = defaultSensitiveFailure(status);
  const type = codeMetadata?.type
    ?? (typeStatus !== undefined ? rawType! : defaults.type);
  const code = codeMetadata ? rawCode! : defaults.code;
  return {
    status,
    error: { type, code, message: `Provider error ${status}` },
    ...(codeMetadata ? { classificationCode: rawCode } : typeStatus !== undefined ? { classificationCode: rawType } : {}),
  };
}

export function sensitiveFailureClassificationText(text: string, status: number): string {
  try {
    return sensitiveFailureMetadata(JSON.parse(text), status).classificationCode ?? `Provider error ${status}`;
  } catch {
    return `Provider error ${status}`;
  }
}

export function rebuildSensitiveFailedJson(text: string, fallbackStatus = 502): string | null {
  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
  const response = payload.response && typeof payload.response === "object" && !Array.isArray(payload.response)
    ? payload.response as Record<string, unknown>
    : undefined;
  if (payload.status !== "failed" && payload.type !== "response.failed" && response?.status !== "failed") {
    return null;
  }
  const failure = sensitiveFailureMetadata(payload, fallbackStatus);
  return JSON.stringify({ status: "failed", error: failure.error });
}

function sensitivePassthroughBlock(block: string): string {
  let eventName: string | null = null;
  for (const line of block.split(/\r\n|\r|\n/)) {
    if (!line || line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    if (field !== "event") continue;
    let value = colon < 0 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    eventName = value;
  }
  const namedFailure = eventName === "response.failed";
  const payload = sseDataPayload(block);
  if (!namedFailure && (!payload || payload === "[DONE]")) return block;
  let event: Record<string, unknown> | undefined;
  if (payload) {
    try {
      event = JSON.parse(payload) as Record<string, unknown>;
    } catch { /* a named response.failed block still fails closed below */ }
  }
  const partialFailure = payload !== null
    && /(?:^|[,{}]\s*)"type"\s*:\s*"response\.failed"/.test(payload);
  if (event?.type !== "response.failed" && !namedFailure && !partialFailure) return block;

  const failure = sensitiveFailureMetadata(event, 200);
  const publicEvent = {
    type: "response.failed",
    response: { status: "failed", error: failure.error },
  };
  return `event: response.failed\ndata: ${JSON.stringify(publicEvent)}`;
}

const MAX_RETAINED_SSE_BLOCK_BYTES = 4 * 1024 * 1024;

class SseBlockTooLargeError extends Error {
  constructor() {
    super(`SSE block exceeded ${MAX_RETAINED_SSE_BLOCK_BYTES} bytes`);
    this.name = "SseBlockTooLargeError";
  }
}

/** Incrementally finds SSE blank-line boundaries while retaining at most one bounded block. */
class BoundedSseBlocks {
  private bytes = new Uint8Array(4096);
  private length = 0;
  private readonly decoder = new TextDecoder();
  private skipLfAfterDelimiter = false;

  push(chunk: Uint8Array, onBlock: (block: string) => void): void {
    for (let index = 0; index < chunk.byteLength; index += 1) {
      const byte = chunk[index]!;
      if (this.skipLfAfterDelimiter) {
        this.skipLfAfterDelimiter = false;
        if (byte === 10) continue;
      }
      if (this.length === this.bytes.byteLength) {
        const capacity = Math.min(MAX_RETAINED_SSE_BLOCK_BYTES + 4, this.bytes.byteLength * 2);
        if (capacity <= this.bytes.byteLength) throw new SseBlockTooLargeError();
        const grown = new Uint8Array(capacity);
        grown.set(this.bytes);
        this.bytes = grown;
      }
      this.bytes[this.length++] = byte;
      const delimiterLength = this.delimiterLength();
      if (delimiterLength === 0) {
        if (this.length - this.trailingLineEndingLength() > MAX_RETAINED_SSE_BLOCK_BYTES) {
          throw new SseBlockTooLargeError();
        }
        continue;
      }
      const blockLength = this.length - delimiterLength;
      if (blockLength > MAX_RETAINED_SSE_BLOCK_BYTES) throw new SseBlockTooLargeError();
      const delimiterEndsWithCr = this.bytes[this.length - 1] === 13;
      onBlock(this.decoder.decode(this.bytes.subarray(0, blockLength)));
      this.length = 0;
      this.skipLfAfterDelimiter = delimiterEndsWithCr;
    }
  }

  finish(onBlock: (block: string) => void): void {
    if (this.length === 0) return;
    if (this.length > MAX_RETAINED_SSE_BLOCK_BYTES) throw new SseBlockTooLargeError();
    onBlock(this.decoder.decode(this.bytes.subarray(0, this.length)));
    this.length = 0;
  }

  private delimiterLength(): number {
    const end = this.length;
    if (end >= 4
      && this.bytes[end - 4] === 13
      && this.bytes[end - 3] === 10
      && this.bytes[end - 2] === 13
      && this.bytes[end - 1] === 10) return 4;
    if (end >= 3
      && ((this.bytes[end - 3] === 13 && this.bytes[end - 2] === 10 && this.bytes[end - 1] === 10)
        || (this.bytes[end - 3] === 10 && this.bytes[end - 2] === 13 && this.bytes[end - 1] === 10))) return 3;
    if (end >= 3
      && this.bytes[end - 3] === 13
      && this.bytes[end - 2] === 10
      && this.bytes[end - 1] === 13) return 3;
    if (end >= 2
      && ((this.bytes[end - 2] === 10 && this.bytes[end - 1] === 10)
        || (this.bytes[end - 2] === 10 && this.bytes[end - 1] === 13)
        || (this.bytes[end - 2] === 13 && this.bytes[end - 1] === 13))) return 2;
    return 0;
  }

  private trailingLineEndingLength(): number {
    if (this.length === 0) return 0;
    const last = this.bytes[this.length - 1];
    if (last === 13) return 1;
    if (last !== 10) return 0;
    return this.length >= 2 && this.bytes[this.length - 2] === 13 ? 2 : 1;
  }
}

function releaseReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try { reader.releaseLock(); } catch { /* already released or a read is still pending */ }
}

function cancelAndReleaseReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  reason: unknown,
): void {
  let cancellation: Promise<void> | undefined;
  try { cancellation = reader.cancel(reason); } catch { /* source may already be errored */ }
  releaseReader(reader);
  if (cancellation) {
    void cancellation.then(
      () => releaseReader(reader),
      () => releaseReader(reader),
    );
  }
}

/** Relay native Responses SSE while rebuilding response.failed blocks from safe metadata. */
export function relaySensitivePassthroughSse(
  body: ReadableStream<Uint8Array>,
  upstream: AbortController,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  const encoder = new TextEncoder();
  const blocks = new BoundedSseBlocks();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) {
            blocks.finish(block => controller.enqueue(encoder.encode(sensitivePassthroughBlock(block))));
            releaseReader(reader);
            controller.close();
            return;
          }
          let emitted = false;
          blocks.push(value, block => {
            emitted = true;
            controller.enqueue(encoder.encode(`${sensitivePassthroughBlock(block)}\n\n`));
          });
          if (emitted) return;
        }
      } catch (error) {
        const failure = {
          type: "upstream_error",
          code: "upstream_reset",
          message: "Provider error 502",
        };
        const payload = JSON.stringify({
          type: "response.failed",
          response: { status: "failed", error: failure, last_error: failure },
        });
        try {
          controller.enqueue(encoder.encode(`\n\nevent: response.failed\ndata: ${payload}\n\ndata: [DONE]\n\n`));
          controller.close();
        } catch { /* client already torn down */ }
        upstream.abort(error);
        cancelAndReleaseReader(reader, error);
      }
    },
    async cancel(reason) {
      upstream.abort(reason);
      cancelAndReleaseReader(reader, reason);
    },
  });
}

export function nextSseBlock(buffer: string): { block: string; rest: string } | null {
  for (let index = 0; index < buffer.length;) {
    const firstLength = sseLineEndingLengthAt(buffer, index);
    if (firstLength === 0) {
      index += 1;
      continue;
    }
    const secondLength = sseLineEndingLengthAt(buffer, index + firstLength);
    if (secondLength > 0) {
      return {
        block: buffer.slice(0, index),
        rest: buffer.slice(index + firstLength + secondLength),
      };
    }
    index += firstLength;
  }
  return null;
}

function sseLineEndingLengthAt(value: string, index: number): number {
  const char = value.charCodeAt(index);
  if (char === 10) return 1;
  if (char !== 13) return 0;
  return value.charCodeAt(index + 1) === 10 ? 2 : 1;
}

export function sseDataPayload(block: string): string | null {
  const data: string[] = [];
  for (const line of block.split(/\r\n|\r|\n/)) {
    if (!line.startsWith("data:")) continue;
    const value = line.slice(5);
    data.push(value.startsWith(" ") ? value.slice(1) : value);
  }
  return data.length > 0 ? data.join("\n") : null;
}

export function terminalStatusFromSsePayload(payload: string): ResponsesTerminalStatus | null {
  return terminalStatusFromSsePayloadInner(payload);
}

/** True when a native Responses SSE payload carries the FIRST kind of non-empty model output. */
export function isFirstOutputSsePayload(payload: string | null): boolean {
  if (!payload || payload === "[DONE]") return false;
  try {
    const event = JSON.parse(payload) as { type?: unknown; delta?: unknown };
    return (event.type === "response.output_text.delta"
      || event.type === "response.reasoning_summary_text.delta"
      || event.type === "response.reasoning_text.delta")
      && typeof event.delta === "string"
      && event.delta.length > 0;
  } catch {
    return false;
  }
}

function createFirstOutputReporter(onFirstOutput?: () => void): (payload: string | null) => void {
  let reported = false;
  return payload => {
    if (reported || !isFirstOutputSsePayload(payload)) return;
    reported = true;
    try { onFirstOutput?.(); } catch { /* metrics must not break the stream */ }
  };
}

function terminalStatusFromSsePayloadInner(payload: string): ResponsesTerminalStatus | null {
  if (payload === "[DONE]") return null;
  try {
    const json = JSON.parse(payload) as { type?: unknown };
    switch (json.type) {
      case "response.completed":
        return "completed";
      case "response.failed":
        return "failed";
      case "response.incomplete":
        return "incomplete";
      default:
        return null;
    }
  } catch {
    return null;
  }
}

/** Extract the response object from a `response.completed` SSE payload, or null. */
export function completedResponseFromSsePayload(payload: string): { id?: unknown; output?: unknown; status?: unknown } | null {
  if (payload === "[DONE]") return null;
  try {
    const json = JSON.parse(payload) as { type?: unknown; response?: unknown };
    if (json.type !== "response.completed") return null;
    const response = json.response;
    if (!response || typeof response !== "object" || Array.isArray(response)) return null;
    return response as { id?: unknown; output?: unknown; status?: unknown };
  } catch {
    return null;
  }
}

export function trackSseForRequestLog(
  body: ReadableStream<Uint8Array>,
  onTerminal: (status: ResponsesTerminalStatus) => void,
  onCancel: () => void,
  logCtx?: RequestLogContext,
  onFirstOutput?: () => void,
): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let blocks: BoundedSseBlocks | null = new BoundedSseBlocks();
  let terminalReported = false;
  const reportFirstOutput = createFirstOutputReporter(onFirstOutput);

  const reportTerminal = (status: ResponsesTerminalStatus) => {
    if (terminalReported) return;
    terminalReported = true;
    onTerminal(status);
  };

  const inspectPayload = (payload: string | null) => {
    if (!payload) return;
    if (logCtx) inspectResponseLogSsePayload(logCtx, payload);
    reportFirstOutput(payload);
    const status = terminalStatusFromSsePayload(payload);
    if (status) reportTerminal(status);
  };

  const inspectChunk = (value: Uint8Array) => {
    if (!blocks) return;
    try {
      blocks.push(value, block => inspectPayload(sseDataPayload(block)));
    } catch (error) {
      if (!(error instanceof SseBlockTooLargeError)) throw error;
      // Logging is best-effort. Stop retaining provider bytes but keep relaying the client body.
      blocks = null;
    }
  };

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          blocks?.finish(block => {
            if (block.trim()) inspectPayload(sseDataPayload(block));
          });
          if (!terminalReported) reportTerminal("incomplete");
          releaseReader(reader);
          controller.close();
          return;
        }
        controller.enqueue(value);
        inspectChunk(value);
      } catch (err) {
        let failure = err;
        if (!terminalReported) {
          try { reportTerminal("incomplete"); } catch (callbackError) { failure = callbackError; }
        }
        cancelAndReleaseReader(reader, failure);
        try { controller.error(failure); } catch { /* already torn down */ }
      }
    },
    async cancel(reason) {
      let failure: unknown;
      try { onCancel(); } catch (error) { failure = error; }
      cancelAndReleaseReader(reader, failure ?? reason);
      if (failure) throw failure;
    },
  });
}

export function responseWithDeferredRequestLog(
  response: Response,
  requestId: string,
  start: number,
  logCtx: RequestLogContext,
  addLog: (entry: RequestLogEntry) => void = addRequestLog,
): Response {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (isUsageDebugEnabled() && !logCtx.usageDebugContentType && contentType) {
    logCtx.usageDebugContentType = contentType;
  }
  if (isNativePassthroughSseResponse(response)) {
    return response;
  }
  if (!response.body || !contentType.includes("text/event-stream")) {
    if (response.body && (contentType.includes("application/json") || response.status >= 400)) {
      const finalizeJsonLog = async () => {
        const text = await response.text();
        // Non-JSON error bodies: inspect/log only a bounded prefix (the stored
        // upstreamError is 500 chars anyway); the FULL text is still forwarded to the
        // client below, unchanged. JSON bodies keep full inspection (usage parsing).
        const isJson = contentType.includes("application/json");
        inspectResponseLogJson(logCtx, isJson ? text : text.slice(0, 8192));
        addFinalRequestLog(requestId, start, logCtx, response.status, { closeReason: "non_stream" }, addLog);
        return text;
      };
      const body = new ReadableStream<Uint8Array>({
        async start(controller) {
          try {
            controller.enqueue(new TextEncoder().encode(await finalizeJsonLog()));
            controller.close();
          } catch (err) {
            addFinalRequestLog(requestId, start, logCtx, 502, { closeReason: "non_stream" }, addLog);
            try { controller.error(err); } catch { /* already torn down */ }
          }
        },
      });
      return new Response(body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    }
    if (isUsageDebugEnabled() && logCtx.usageDebugBodyKind === undefined) {
      logCtx.usageDebugBodyKind = response.body ? "other" : "none";
    }
    addFinalRequestLog(requestId, start, logCtx, response.status, { closeReason: "non_stream" }, addLog);
    return response;
  }

  let logged = false;
  const body = trackSseForRequestLog(
    response.body,
    status => {
      if (logged) return;
      logged = true;
      addFinalRequestLog(requestId, start, logCtx, httpStatusForRequestLogTerminal(status, logCtx), {
        terminalStatus: status,
        closeReason: "terminal",
      }, addLog);
    },
    () => {
      if (logged) return;
      logged = true;
      addFinalRequestLog(requestId, start, logCtx, 499, { closeReason: "client_cancel" }, addLog);
    },
    logCtx,
    () => recordFirstOutput(logCtx, start),
  );
  return new Response(body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
}

export function markNativePassthroughSseResponse(response: Response): Response {
  nativePassthroughSseResponses.add(response);
  return response;
}

export function isNativePassthroughSseResponse(response: Response): boolean {
  return nativePassthroughSseResponses.has(response);
}

export function relaySseWithHeartbeat(
  body: ReadableStream<Uint8Array> | null,
  upstream: AbortController,
  heartbeatMs = 15_000,
  onTerminal?: (status: ResponsesTerminalStatus) => void,
  options?: { onStart?: () => void; onDone?: () => void },
): ReadableStream<Uint8Array> | null {
  if (!body) return null;
  const reader = body.getReader();
  const decoder = new TextDecoder();
  const heartbeat = new TextEncoder().encode(": opencodex keepalive\n\n");
  let timer: ReturnType<typeof setInterval> | undefined;
  let closed = false;
  let clientCancelled = false;
  let terminalReported = false;
  let buffer = "";

  const reportTerminal = (status: ResponsesTerminalStatus) => {
    if (terminalReported || clientCancelled || closed) return;
    terminalReported = true;
    onTerminal?.(status);
  };

  const inspectPayload = (payload: string | null) => {
    if (!payload) return;
    const status = terminalStatusFromSsePayload(payload);
    if (status) reportTerminal(status);
  };

  const inspectChunk = (value: Uint8Array) => {
    buffer += decoder.decode(value, { stream: true });
    let next: { block: string; rest: string } | null;
    while ((next = nextSseBlock(buffer))) {
      buffer = next.rest;
      inspectPayload(sseDataPayload(next.block));
    }
  };

  const cleanup = () => {
    if (closed) return;
    closed = true;
    if (timer) clearInterval(timer);
    timer = undefined;
    options?.onDone?.();
  };

  return new ReadableStream<Uint8Array>({
    start(controller) {
      options?.onStart?.();
      timer = setInterval(() => {
        if (closed) return;
        try {
          controller.enqueue(heartbeat);
        } catch {
          cleanup();
        }
      }, heartbeatMs);
    },
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          if (buffer.trim()) inspectPayload(sseDataPayload(buffer));
          if (!terminalReported && !clientCancelled) reportTerminal("incomplete");
          cleanup();
          controller.close();
          return;
        }
        inspectChunk(value);
        controller.enqueue(value);
      } catch (err) {
        if (!clientCancelled) reportTerminal("incomplete");
        cleanup();
        try { controller.error(err); } catch { /* already torn down */ }
      }
    },
    cancel(reason) {
      clientCancelled = true;
      cleanup();
      upstream.abort(reason);
      reader.cancel(reason).catch(() => {});
    },
  });
}

/**
 * Background-consume an SSE stream purely for terminal-outcome inspection (quota tracking).
 * Does not produce output; safe to ignore errors (the client-facing stream is separate).
 */
export function consumeForInspection(
  body: ReadableStream<Uint8Array>,
  onTerminal: (status: ResponsesTerminalStatus) => void,
  signal?: AbortSignal,
  onDone?: () => void,
  logCtx?: RequestLogContext,
  onCancel?: () => void,
  onCompletedResponse?: (response: { id?: unknown; output?: unknown; status?: unknown }) => void,
  onFirstOutput?: () => void,
): void {
  const reader = body.getReader();
  const blocks = new BoundedSseBlocks();
  let reported = false;
  let cancelled = false;
  const reportFirstOutput = createFirstOutputReporter(onFirstOutput);
  if (signal) {
    if (signal.aborted) {
      // Aborted before we could read anything (Codex disconnects the instant it finishes reading).
      // Finalize as a client-cancel and release the turn — the early return skips pump()'s finally,
      // so onDone/onCancel must run here or the entry is silently dropped (#44).
      cancelled = true;
      void cancelAndReleaseReader(reader, signal.reason);
      onCancel?.();
      onDone?.();
      return;
    }
    signal.addEventListener("abort", () => {
      // Mid-drain disconnect: record a client-cancel entry (idempotent downstream) instead of the
      // suppressed onTerminal path. onDone still fires via pump()'s finally after the read rejects.
      cancelled = true;
      void reader.cancel(signal.reason).catch(() => undefined);
      onCancel?.();
    }, { once: true });
  }
  const pump = async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          blocks.finish(block => {
            if (!block.trim() || reported) return;
            const payload = sseDataPayload(block);
            if (logCtx) inspectResponseLogSsePayload(logCtx, payload);
            reportFirstOutput(payload);
            if (payload) {
              const status = terminalStatusFromSsePayload(payload);
              if (status) { reported = true; onTerminal(status); }
              if (onCompletedResponse) {
                const response = completedResponseFromSsePayload(payload);
                if (response) onCompletedResponse(response);
              }
            }
          });
          if (!reported && !cancelled) onTerminal("incomplete");
          releaseReader(reader);
          return;
        }
        blocks.push(value, block => {
          if (reported && !onCompletedResponse) return;
          const payload = sseDataPayload(block);
          if (!reported && logCtx) inspectResponseLogSsePayload(logCtx, payload);
          reportFirstOutput(payload);
          if (!payload) return;
          if (!reported) {
            const status = terminalStatusFromSsePayload(payload);
            if (status) { reported = true; onTerminal(status); }
          }
          if (onCompletedResponse) {
            const response = completedResponseFromSsePayload(payload);
            if (response) onCompletedResponse(response);
          }
        });
      }
    } catch (error) {
      cancelAndReleaseReader(reader, error);
      if (!reported && !cancelled) {
        try { onTerminal("incomplete"); } catch { /* inspection callbacks are best-effort */ }
      }
    } finally {
      releaseReader(reader);
      try { onDone?.(); } catch { /* lifecycle reporting must not leak the reader */ }
    }
  };
  pump();
}

export function consumeForResponseLogMetadata(
  body: ReadableStream<Uint8Array>,
  logCtx: RequestLogContext,
  signal?: AbortSignal,
  onDone?: () => void,
  onCompletedResponse?: (response: { id?: unknown; output?: unknown; status?: unknown }) => void,
  onFirstOutput?: () => void,
): void {
  const reader = body.getReader();
  const blocks = new BoundedSseBlocks();
  const reportFirstOutput = createFirstOutputReporter(onFirstOutput);
  if (signal) {
    if (signal.aborted) {
      void cancelAndReleaseReader(reader, signal.reason);
      onDone?.();
      return;
    }
    signal.addEventListener("abort", () => {
      void reader.cancel(signal.reason).catch(() => undefined);
    }, { once: true });
  }
  const pump = async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) {
          blocks.finish(block => {
            if (!block.trim()) return;
            const payload = sseDataPayload(block);
            inspectResponseLogSsePayload(logCtx, payload);
            reportFirstOutput(payload);
            if (payload && onCompletedResponse) {
              const response = completedResponseFromSsePayload(payload);
              if (response) onCompletedResponse(response);
            }
          });
          releaseReader(reader);
          return;
        }
        blocks.push(value, block => {
          const payload = sseDataPayload(block);
          inspectResponseLogSsePayload(logCtx, payload);
          reportFirstOutput(payload);
          if (payload && onCompletedResponse) {
            const response = completedResponseFromSsePayload(payload);
            if (response) onCompletedResponse(response);
          }
        });
      }
    } catch (error) {
      cancelAndReleaseReader(reader, error);
      /* metadata inspection must not affect the client-facing stream */
    } finally {
      releaseReader(reader);
      try { onDone?.(); } catch { /* lifecycle reporting must not leak the reader */ }
    }
  };
  pump();
}

/**
 * Bun's fetch auto-decompresses the response body but leaves the upstream `content-encoding`
 * (and a now-stale `content-length`) on `response.headers`. Relaying those with the already-decoded
 * body makes the caller (Codex) double-decode / truncate → "stream error" on every gpt passthrough.
 * Drop encoding + hop-by-hop headers; relay everything else (content-type, etc.) verbatim.
 */
export function sanitizePassthroughHeaders(upstream: Headers): Headers {
  const DROP = new Set([
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "te",
    "trailer",
    "upgrade",
  ]);
  const out = new Headers();
  upstream.forEach((value, key) => {
    if (!DROP.has(key.toLowerCase())) out.set(key, value);
  });
  return out;
}
