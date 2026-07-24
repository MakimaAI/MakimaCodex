import { describe, expect, test } from "bun:test";
import {
  consumeForInspection,
  consumeForResponseLogMetadata,
  relaySensitivePassthroughSse,
  trackSseForRequestLog,
} from "../src/server/relay";

const encoder = new TextEncoder();

function guardedEndlessBlock(guardPulls = 80): {
  stream: ReadableStream<Uint8Array>;
  stats: { pulls: number; cancels: number; reason?: unknown };
} {
  const nonce = "PROVIDER_PRIVATE_UNTERMINATED_SSE_7f2c";
  const prefix = `data: ${nonce}`;
  const chunk = encoder.encode(prefix + "x".repeat(64 * 1024 - prefix.length));
  const stats: { pulls: number; cancels: number; reason?: unknown } = { pulls: 0, cancels: 0 };
  return {
    stats,
    stream: new ReadableStream<Uint8Array>({
      pull(controller) {
        if (stats.pulls >= guardPulls) {
          controller.error(new Error("test guard reached before bounded cancellation"));
          return;
        }
        stats.pulls += 1;
        controller.enqueue(chunk);
      },
      cancel(reason) {
        stats.cancels += 1;
        stats.reason = reason;
      },
    }),
  };
}

function streamFromByteFragments(text: string): ReadableStream<Uint8Array> {
  const bytes = encoder.encode(text);
  let offset = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (offset >= bytes.byteLength) {
        controller.close();
        return;
      }
      controller.enqueue(bytes.subarray(offset, offset + 1));
      offset += 1;
    },
  });
}

function finiteStream(chunks: Uint8Array[], onCancel?: (reason: unknown) => void): ReadableStream<Uint8Array> {
  let index = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[index++]!);
    },
    cancel(reason) {
      onCancel?.(reason);
    },
  });
}

function trackedFiniteStream(chunks: Uint8Array[]): {
  stream: ReadableStream<Uint8Array>;
  stats: { cancels: number; reason?: unknown };
} {
  const stats: { cancels: number; reason?: unknown } = { cancels: 0 };
  return {
    stats,
    stream: finiteStream(chunks, reason => {
      stats.cancels += 1;
      stats.reason = reason;
    }),
  };
}

function trackedOpenStream(chunk: Uint8Array): {
  stream: ReadableStream<Uint8Array>;
  stats: { cancels: number; reason?: unknown };
} {
  const stats: { cancels: number; reason?: unknown } = { cancels: 0 };
  let emitted = false;
  return {
    stats,
    stream: new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!emitted) {
          emitted = true;
          controller.enqueue(chunk);
          return;
        }
        return new Promise<void>(() => {});
      },
      cancel(reason) {
        stats.cancels += 1;
        stats.reason = reason;
      },
    }),
  };
}

function stubbornCancellationStream(chunk: Uint8Array): {
  stream: ReadableStream<Uint8Array>;
  stats: { cancels: number };
} {
  const stats = { cancels: 0 };
  let emitted = false;
  return {
    stats,
    stream: new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!emitted) {
          emitted = true;
          controller.enqueue(chunk);
          return;
        }
        return new Promise<void>(() => {});
      },
      cancel() {
        stats.cancels += 1;
        return new Promise<void>(() => {});
      },
    }),
  };
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let output = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) return output + decoder.decode();
    output += decoder.decode(value, { stream: true });
  }
}

function completion<T>(): { promise: Promise<T>; resolve: (value: T) => void } {
  let resolve!: (value: T) => void;
  return { promise: new Promise<T>(done => { resolve = done; }), resolve };
}

describe("bounded incremental SSE blocks", () => {
  test("data-only malformed response.failed payloads fail closed without reflecting provider bytes", async () => {
    const nonce = "MALFORMED_DATA_ONLY_PRIVATE_NONCE_41fd";
    const wire = `data: {"type":"response.failed","response":{"error":{"message":"${nonce}"}}\n\n`;

    const output = await readAll(relaySensitivePassthroughSse(
      streamFromByteFragments(wire),
      new AbortController(),
    ));

    expect(output).toContain('event: response.failed');
    expect(output).toContain('"message":"Provider error 502"');
    expect(output).not.toContain(nonce);
  });

  test("lone-CR frames are parsed consistently and sensitive failures are sanitized", async () => {
    const nonce = "LONE_CR_PRIVATE_NONCE_2ef1";
    const failedWire = [
      `id: ${nonce}`,
      "event: response.failed",
      `data: {"type":"response.failed","response":{"error":{"message":"${nonce}"}}}`,
      "",
      "",
    ].join("\r");
    const failedOutput = await readAll(relaySensitivePassthroughSse(
      streamFromByteFragments(failedWire),
      new AbortController(),
    ));

    expect(failedOutput).toContain('event: response.failed');
    expect(failedOutput).toContain('"message":"Provider error 502"');
    expect(failedOutput).not.toContain(nonce);

    const completed = {
      type: "response.completed",
      response: { id: "resp_lone_cr", status: "completed", output: [] },
    };
    const completedWire = `event: response.completed\rdata: ${JSON.stringify(completed)}\r\r`;
    const inspectionDone = completion<void>();
    const terminals: string[] = [];
    consumeForInspection(
      streamFromByteFragments(completedWire),
      status => terminals.push(status),
      undefined,
      () => inspectionDone.resolve(),
    );
    await inspectionDone.promise;
    expect(terminals).toEqual(["completed"]);

    const metadataDone = completion<void>();
    const metadataResponses: unknown[] = [];
    consumeForResponseLogMetadata(
      streamFromByteFragments(completedWire),
      { model: "", provider: "" },
      undefined,
      () => metadataDone.resolve(),
      response => metadataResponses.push(response),
    );
    await metadataDone.promise;
    expect(metadataResponses).toEqual([completed.response]);
  });

  test("sensitive relay cancels an endless unterminated provider block and emits only a safe failure", async () => {
    const source = guardedEndlessBlock();
    const upstream = new AbortController();

    const output = await readAll(relaySensitivePassthroughSse(source.stream, upstream));

    expect(source.stats.pulls).toBeLessThanOrEqual(66);
    expect(source.stats.cancels).toBe(1);
    expect(upstream.signal.aborted).toBe(true);
    expect(output).toContain('"type":"response.failed"');
    expect(output).toContain('"message":"Provider error 502"');
    expect(output).not.toContain("PROVIDER_PRIVATE_UNTERMINATED_SSE_7f2c");
  });

  test("both background inspectors cancel an oversized unterminated block deterministically", async () => {
    const quotaSource = guardedEndlessBlock();
    const quotaDone = completion<void>();
    const terminal: string[] = [];
    consumeForInspection(
      quotaSource.stream,
      status => terminal.push(status),
      undefined,
      () => quotaDone.resolve(),
    );
    await quotaDone.promise;

    expect(quotaSource.stats.pulls).toBeLessThanOrEqual(66);
    expect(quotaSource.stats.cancels).toBe(1);
    expect(terminal).toEqual(["incomplete"]);

    const metadataSource = guardedEndlessBlock();
    const metadataDone = completion<void>();
    consumeForResponseLogMetadata(
      metadataSource.stream,
      { model: "", provider: "" },
      undefined,
      () => metadataDone.resolve(),
    );
    await metadataDone.promise;

    expect(metadataSource.stats.pulls).toBeLessThanOrEqual(66);
    expect(metadataSource.stats.cancels).toBe(1);
  });

  test("byte-fragmented normal SSE remains intact for relay and both inspectors", async () => {
    const completed = {
      type: "response.completed",
      response: { id: "resp_fragmented", status: "completed", output: [] },
    };
    const wire = `event: response.completed\r\ndata: ${JSON.stringify(completed)}\r\n\r\n`;
    const relayed = await readAll(relaySensitivePassthroughSse(
      streamFromByteFragments(wire),
      new AbortController(),
    ));
    expect(relayed).toBe(wire.replace(/\r\n\r\n$/, "\n\n"));

    const inspectionDone = completion<void>();
    const terminals: string[] = [];
    const inspectedResponses: unknown[] = [];
    consumeForInspection(
      streamFromByteFragments(wire),
      status => terminals.push(status),
      undefined,
      () => inspectionDone.resolve(),
      undefined,
      undefined,
      response => inspectedResponses.push(response),
    );
    await inspectionDone.promise;
    expect(terminals).toEqual(["completed"]);
    expect(inspectedResponses).toEqual([completed.response]);

    const metadataDone = completion<void>();
    const metadataResponses: unknown[] = [];
    consumeForResponseLogMetadata(
      streamFromByteFragments(wire),
      { model: "", provider: "" },
      undefined,
      () => metadataDone.resolve(),
      response => metadataResponses.push(response),
    );
    await metadataDone.promise;
    expect(metadataResponses).toEqual([completed.response]);
  });

  test("a multibyte payload split at every encoded byte remains valid", async () => {
    const completed = {
      type: "response.completed",
      response: { id: "yanit-🧠-çığ", status: "completed", output: [] },
    };
    const wire = `event: response.completed\r\ndata: ${JSON.stringify(completed)}\r\n\r\n`;
    const relayed = await readAll(relaySensitivePassthroughSse(
      streamFromByteFragments(wire),
      new AbortController(),
    ));
    expect(relayed).toBe(wire.replace(/\r\n\r\n$/, "\n\n"));
    expect(JSON.parse(relayed.split("data: ")[1]!.trim())).toEqual(completed);

    const done = completion<void>();
    const responses: unknown[] = [];
    consumeForResponseLogMetadata(
      streamFromByteFragments(wire),
      { model: "", provider: "" },
      undefined,
      () => done.resolve(),
      response => responses.push(response),
    );
    await done.promise;
    expect(responses).toEqual([completed.response]);
  });

  test("accepts an exact 4 MiB block and rejects the next byte", async () => {
    const limit = 4 * 1024 * 1024;
    const exactBlock = `data: ${"x".repeat(limit - "data: ".length)}`;
    const exactSource = trackedFiniteStream([encoder.encode(`${exactBlock}\n\n`)]);
    const exactOutput = await readAll(relaySensitivePassthroughSse(
      exactSource.stream,
      new AbortController(),
    ));
    expect(exactOutput).toBe(`${exactBlock}\n\n`);
    expect(exactSource.stats.cancels).toBe(0);

    const oversizedNonce = "OVER_LIMIT_PRIVATE_NONCE_a933";
    const oversizedBlock = `data: ${oversizedNonce}${"x".repeat(limit - "data: ".length - oversizedNonce.length + 1)}`;
    const oversizedSource = trackedOpenStream(encoder.encode(`${oversizedBlock}\n\n`));
    const oversizedUpstream = new AbortController();
    const oversizedOutput = await readAll(relaySensitivePassthroughSse(
      oversizedSource.stream,
      oversizedUpstream,
    ));
    expect(oversizedOutput).toContain('"message":"Provider error 502"');
    expect(oversizedOutput).not.toContain(oversizedNonce);
    expect(oversizedSource.stats.cancels).toBe(1);
    expect(oversizedUpstream.signal.aborted).toBe(true);
    expect(oversizedSource.stream.locked).toBe(false);
  });

  test("background callback failures cancel and release their source readers", async () => {
    const completed = `data: ${JSON.stringify({
      type: "response.completed",
      response: { id: "callback_failure", status: "completed" },
    })}\n\n`;
    const inspectionSource = trackedFiniteStream([encoder.encode(completed)]);
    const inspectionDone = completion<void>();
    consumeForInspection(
      inspectionSource.stream,
      () => { throw new Error("terminal callback failed"); },
      undefined,
      () => inspectionDone.resolve(),
    );
    await inspectionDone.promise;
    expect(inspectionSource.stats.cancels).toBe(1);
    expect(inspectionSource.stream.locked).toBe(false);

    const metadataSource = trackedFiniteStream([encoder.encode(completed)]);
    const metadataDone = completion<void>();
    consumeForResponseLogMetadata(
      metadataSource.stream,
      { model: "", provider: "" },
      undefined,
      () => metadataDone.resolve(),
      () => { throw new Error("metadata callback failed"); },
    );
    await metadataDone.promise;
    expect(metadataSource.stats.cancels).toBe(1);
    expect(metadataSource.stream.locked).toBe(false);
  });

  test("a source with a stuck cancel hook cannot retain the reader after a pump error", async () => {
    const completed = `data: ${JSON.stringify({
      type: "response.completed",
      response: { id: "stuck_cancel", status: "completed" },
    })}\n\n`;
    const source = stubbornCancellationStream(encoder.encode(completed));
    const done = completion<void>();
    consumeForInspection(
      source.stream,
      () => { throw new Error("terminal callback failed"); },
      undefined,
      () => done.resolve(),
    );

    const finalized = await Promise.race([
      done.promise.then(() => true),
      new Promise<false>(resolve => setTimeout(() => resolve(false), 100)),
    ]);
    expect(finalized).toBe(true);
    expect(source.stats.cancels).toBe(1);
    expect(source.stream.locked).toBe(false);
  });

  test("request-log callback failures preserve raw bytes before cancelling and releasing", async () => {
    const wire = `data: ${JSON.stringify({
      type: "response.completed",
      response: { id: "request_log_callback_failure", status: "completed" },
    })}\n\n`;
    const source = trackedFiniteStream([encoder.encode(wire), encoder.encode("data: never-read\n\n")]);
    const tracked = trackSseForRequestLog(
      source.stream,
      () => { throw new Error("request log callback failed"); },
      () => {},
    );
    const reader = tracked.getReader();
    const decoder = new TextDecoder();
    let output = "";
    let failure: unknown;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        output += decoder.decode(value, { stream: true });
      }
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    expect(output).toBe(wire);
    expect(source.stats.cancels).toBe(1);
    expect(source.stream.locked).toBe(false);
  });

  test("request-log overflow disables inspection without changing or cancelling the client stream", async () => {
    const oversizedBlock = `data: ${"x".repeat(4 * 1024 * 1024 + 1)}\n\n`;
    const completedBlock = `event: response.completed\ndata: ${JSON.stringify({
      type: "response.completed",
      response: { id: "must_not_be_inspected_after_overflow", status: "completed" },
    })}\n\n`;
    let sourceCancels = 0;
    let clientCancels = 0;
    const terminals: string[] = [];
    const tracked = trackSseForRequestLog(
      finiteStream(
        [encoder.encode(oversizedBlock), encoder.encode(completedBlock)],
        () => { sourceCancels += 1; },
      ),
      status => terminals.push(status),
      () => { clientCancels += 1; },
    );

    const output = await readAll(tracked);

    expect(output).toBe(oversizedBlock + completedBlock);
    expect(terminals).toEqual(["incomplete"]);
    expect(sourceCancels).toBe(0);
    expect(clientCancels).toBe(0);
  });
});
