import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { AnthropicOAuthFlow, refreshAnthropicToken } from "../src/oauth/anthropic";
import { ChatGPTOAuthFlow, refreshChatGPTToken } from "../src/oauth/chatgpt";
import { loginKimi, refreshKimiToken } from "../src/oauth/kimi";

const TEST_DIR = join(import.meta.dir, ".tmp-oauth-network-cancellation");
const originalFetch = globalThis.fetch;
const previousHome = process.env.OPENCODEX_HOME;

interface DelayedFetch {
  fetch: typeof fetch;
  started: Promise<void>;
  signal(): AbortSignal | undefined;
}

function delayedFetch(cleanupMs = 150): DelayedFetch {
  let observedSignal: AbortSignal | undefined;
  let markStarted!: () => void;
  const started = new Promise<void>(resolve => { markStarted = resolve; });
  const fetch = ((_input: RequestInfo | URL, init?: RequestInit) => {
    observedSignal = init?.signal ?? undefined;
    markStarted();
    return new Promise<Response>((_resolve, reject) => {
      let settled = false;
      const finish = (reason: unknown) => {
        if (settled) return;
        settled = true;
        clearTimeout(cleanup);
        reject(reason);
      };
      const cleanup = setTimeout(() => finish(new Error("test cleanup: request was not aborted")), cleanupMs);
      if (observedSignal?.aborted) finish(observedSignal.reason);
      else observedSignal?.addEventListener("abort", () => finish(observedSignal!.reason), { once: true });
    });
  }) as typeof globalThis.fetch;
  return { fetch, started, signal: () => observedSignal };
}

async function rejectionOf(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    return error;
  }
}

function expectComposedAbort(observed: AbortSignal | undefined, parent: AbortSignal): void {
  expect(observed).toBeDefined();
  expect(observed).not.toBe(parent);
  expect(observed?.aborted).toBe(true);
}

describe("OAuth network cancellation", () => {
  beforeEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
    process.env.OPENCODEX_HOME = TEST_DIR;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
    else process.env.OPENCODEX_HOME = previousHome;
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  test("Kimi aborts a pending device-authorization request and never starts polling", async () => {
    const parent = new AbortController();
    const delayed = delayedFetch();
    let authPublished = false;
    let calls = 0;
    globalThis.fetch = ((input, init) => {
      calls += 1;
      return delayed.fetch(input, init);
    }) as typeof fetch;

    const pending = loginKimi({
      signal: parent.signal,
      onAuth: () => { authPublished = true; },
    });
    await delayed.started;
    const reason = new DOMException("user cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
    await Bun.sleep(20);
    expect(calls).toBe(1);
    expect(authPublished).toBe(false);
  });

  test("Kimi aborts the in-flight token poll and schedules no later poll", async () => {
    const parent = new AbortController();
    const delayed = delayedFetch();
    let calls = 0;
    globalThis.fetch = (async (input, init) => {
      calls += 1;
      if (calls === 1) {
        return Response.json({
          user_code: "ABCD-EFGH",
          device_code: "device-code",
          verification_uri: "https://auth.kimi.example/device",
          expires_in: 60,
          interval: 1,
        });
      }
      return delayed.fetch(input, init);
    }) as typeof fetch;

    const pending = loginKimi({ signal: parent.signal });
    await delayed.started;
    const reason = new DOMException("poll cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
    await Bun.sleep(20);
    expect(calls).toBe(2);
  });

  test("Kimi refresh composes caller cancellation with a finite request deadline", async () => {
    const parent = new AbortController();
    const delayed = delayedFetch();
    globalThis.fetch = delayed.fetch;

    const pending = refreshKimiToken("refresh-token", parent.signal);
    await delayed.started;
    const reason = new DOMException("refresh cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
  });

  test("ChatGPT authorization-code exchange aborts its pending token request", async () => {
    const parent = new AbortController();
    const flow = new ChatGPTOAuthFlow({ signal: parent.signal });
    await flow.generateAuthUrl("state", "http://localhost:1455/auth/callback");
    const delayed = delayedFetch();
    globalThis.fetch = delayed.fetch;

    const pending = flow.exchangeToken("code", "state", "http://localhost:1455/auth/callback");
    await delayed.started;
    const reason = new DOMException("exchange cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
  });

  test("ChatGPT refresh composes caller cancellation with a finite request deadline", async () => {
    const parent = new AbortController();
    const delayed = delayedFetch();
    globalThis.fetch = delayed.fetch;

    const pending = refreshChatGPTToken("refresh-token", parent.signal);
    await delayed.started;
    const reason = new DOMException("refresh cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
  });

  test("Anthropic authorization-code exchange combines timeout and parent cancellation", async () => {
    const parent = new AbortController();
    const flow = new AnthropicOAuthFlow({ signal: parent.signal });
    await flow.generateAuthUrl("state", "http://localhost:54545/callback");
    const delayed = delayedFetch();
    globalThis.fetch = delayed.fetch;

    const pending = flow.exchangeToken("code", "state", "http://localhost:54545/callback");
    await delayed.started;
    const reason = new DOMException("exchange cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
  });

  test("Anthropic refresh composes caller cancellation with its request timeout", async () => {
    const parent = new AbortController();
    const delayed = delayedFetch();
    globalThis.fetch = delayed.fetch;

    const pending = refreshAnthropicToken("refresh-token", parent.signal);
    await delayed.started;
    const reason = new DOMException("refresh cancelled", "AbortError");
    parent.abort(reason);

    expect(await rejectionOf(pending)).toBe(reason);
    expectComposedAbort(delayed.signal(), parent.signal);
  });
});
