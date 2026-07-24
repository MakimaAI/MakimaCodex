import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, saveConfig } from "../src/config";
import { clearKeyCooldowns } from "../src/providers/key-failover";
import { getAccountSet, saveCredential } from "../src/oauth/store";
import { deriveXaiConvId } from "../src/providers/xai-transport";
import { startServer } from "../src/server";
import type { OcxConfig } from "../src/types";
import { installIsolatedCodexHome, type IsolatedCodexHome } from "./helpers/isolated-codex-home";

let testDir = "";
let previousHome: string | undefined;
let isolatedCodexHome: IsolatedCodexHome | null = null;
let upstream: ReturnType<typeof Bun.serve> | null = null;

beforeEach(() => {
  previousHome = process.env.OPENCODEX_HOME;
  isolatedCodexHome = installIsolatedCodexHome("ocx-keyfail-e2e-codex-");
  testDir = mkdtempSync(join(tmpdir(), "ocx-keyfail-e2e-"));
  process.env.OPENCODEX_HOME = testDir;
  clearKeyCooldowns();
});

afterEach(() => {
  upstream?.stop(true);
  upstream = null;
  if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
  else process.env.OPENCODEX_HOME = previousHome;
  isolatedCodexHome?.restore();
  isolatedCodexHome = null;
  if (testDir) rmSync(testDir, { recursive: true, force: true });
  clearKeyCooldowns();
});

describe("server 429 key failover (end-to-end)", () => {
  test("Cline account 429 switches to the next logged-in account and makes it active", async () => {
    const originalFetch = globalThis.fetch;
    const seenAuth: string[] = [];
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.cline.bot/api/v1/chat/completions") {
        seenAuth.push(new Headers(init?.headers).get("authorization") ?? "");
        if (seenAuth.length === 1) {
          return new Response(JSON.stringify({ error: { message: "rate limited" } }), {
            status: 429,
            headers: { "retry-after": "30", "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({
          id: "chatcmpl-cline", object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "ok after account rotate" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }), { headers: { "content-type": "application/json" } });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    await saveCredential("cline", {
      access: "cline-access-a", refresh: "cline-refresh-a", expires: Date.now() + 3600_000,
      accountId: "cline-a", email: "a@example.com",
    });
    await saveCredential("cline", {
      access: "cline-access-b", refresh: "cline-refresh-b", expires: Date.now() + 3600_000,
      accountId: "cline-b", email: "b@example.com",
    });
    expect(getAccountSet("cline")?.accounts).toHaveLength(2);

    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "cline",
      providers: {
        cline: {
          adapter: "openai-chat",
          baseUrl: "https://api.cline.bot/api/v1",
          authMode: "oauth",
          defaultModel: "anthropic/claude-opus-4.6",
          models: ["anthropic/claude-opus-4.6"],
        },
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const response = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline/anthropic-claude-opus-4.6", input: "hello", stream: false }),
      });
      expect(response.status).toBe(200);
      expect(seenAuth).toEqual(["Bearer workos:cline-access-b", "Bearer workos:cline-access-a"]);
      const active = getAccountSet("cline")?.accounts.find(account => account.id === getAccountSet("cline")?.activeAccountId);
      expect(active?.credential.accountId).toBe("cline-a");
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("ClinePass 402 rotates to the next subscription key and keeps the official wire model id", async () => {
    const originalFetch = globalThis.fetch;
    const seen: Array<{ auth: string | null; model: string | undefined }> = [];
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.cline.bot/api/v1/chat/completions") {
        const body = JSON.parse(String(init?.body)) as { model?: string };
        seen.push({ auth: new Headers(init?.headers).get("authorization"), model: body.model });
        if (seen.length === 1) {
          return new Response(JSON.stringify({ error: { message: "subscription limit reached" } }), {
            status: 402,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({
          id: "chatcmpl-cline-pass", object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "ok after pass rotate" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }), { headers: { "content-type": "application/json" } });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "cline-pass",
      providers: {
        "cline-pass": {
          adapter: "openai-chat",
          baseUrl: "https://api.cline.bot/api/v1",
          authMode: "key",
          apiKey: "key-alpha-000111222333",
          apiKeyPool: [
            { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
            { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
          ],
        },
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const response = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline-pass/kimi-k2.7-code", input: "hello", stream: false }),
      });
      expect(response.status).toBe(200);
      expect(seen).toEqual([
        { auth: "Bearer key-alpha-000111222333", model: "cline-pass/kimi-k2.7-code" },
        { auth: "Bearer key-beta-444555666777", model: "cline-pass/kimi-k2.7-code" },
      ]);
      expect(loadConfig().providers["cline-pass"]?.apiKey).toBe("key-beta-444555666777");
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("failed Cline and ClinePass fallbacks do not change the selected account or key", async () => {
    const originalFetch = globalThis.fetch;
    let clineCalls = 0;
    let passCalls = 0;
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.cline.bot/api/v1/chat/completions") {
        const auth = new Headers(init?.headers).get("authorization");
        if (auth?.startsWith("Bearer workos:cline-access")) {
          clineCalls++;
          return new Response(JSON.stringify({ error: { message: clineCalls === 1 ? "limited" : "broken fallback" } }), {
            status: clineCalls === 1 ? 429 : 500,
            headers: { "content-type": "application/json" },
          });
        }
        passCalls++;
        return new Response(JSON.stringify({ error: { message: passCalls === 1 ? "subscription limit" : "broken fallback" } }), {
          status: passCalls === 1 ? 402 : 500,
          headers: { "content-type": "application/json" },
        });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    await saveCredential("cline", {
      access: "cline-access-a", refresh: "cline-refresh-a", expires: Date.now() + 3600_000,
      accountId: "cline-a", email: "a@example.com",
    });
    await saveCredential("cline", {
      access: "cline-access-b", refresh: "cline-refresh-b", expires: Date.now() + 3600_000,
      accountId: "cline-b", email: "b@example.com",
    });
    const originalAccountId = getAccountSet("cline")!.activeAccountId;
    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "cline",
      providers: {
        cline: {
          adapter: "openai-chat", baseUrl: "https://api.cline.bot/api/v1", authMode: "oauth",
          defaultModel: "anthropic/claude-opus-4.6", models: ["anthropic/claude-opus-4.6"],
        },
        "cline-pass": {
          adapter: "openai-chat", baseUrl: "https://api.cline.bot/api/v1", authMode: "key",
          apiKey: "key-alpha-000111222333",
          apiKeyPool: [
            { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
            { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
          ],
        },
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const clineResponse = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline/anthropic-claude-opus-4.6", input: "hello", stream: false }),
      });
      const passResponse = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline-pass/kimi-k2.7-code", input: "hello", stream: false }),
      });
      expect(clineResponse.status).toBe(500);
      expect(passResponse.status).toBe(500);
      expect(getAccountSet("cline")?.activeAccountId).toBe(originalAccountId);
      expect(loadConfig().providers["cline-pass"]?.apiKey).toBe("key-alpha-000111222333");
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("ClinePass keeps the selected key when a 2xx fallback stream terminates with an adapter error", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.cline.bot/api/v1/chat/completions") {
        calls++;
        if (calls === 1) {
          return new Response(JSON.stringify({ error: { message: "subscription limit" } }), {
            status: 402,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response("data: {not-json}\n\ndata: [DONE]\n\n", {
          headers: { "content-type": "text/event-stream" },
        });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    saveConfig({
      port: 0, hostname: "127.0.0.1", defaultProvider: "cline-pass",
      providers: {
        "cline-pass": {
          adapter: "openai-chat", baseUrl: "https://api.cline.bot/api/v1", authMode: "key",
          apiKey: "key-alpha-000111222333",
          apiKeyPool: [
            { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
            { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
          ],
        },
      },
    } as OcxConfig);

    const server = startServer(0);
    try {
      const response = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline-pass/kimi-k2.7-code", input: "hello", stream: true }),
      });
      expect(response.status).toBe(200);
      expect(await response.text()).toContain("response.failed");
      expect(calls).toBe(2);
      expect(loadConfig().providers["cline-pass"]?.apiKey).toBe("key-alpha-000111222333");
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("Cline keeps the selected account when a 2xx fallback body parses as an adapter error", async () => {
    const originalFetch = globalThis.fetch;
    let calls = 0;
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.cline.bot/api/v1/chat/completions") {
        calls++;
        if (calls === 1) {
          return new Response(JSON.stringify({ error: { message: "rate limited" } }), {
            status: 429,
            headers: { "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({ choices: [] }), {
          headers: { "content-type": "application/json" },
        });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    await saveCredential("cline", {
      access: "cline-access-a", refresh: "cline-refresh-a", expires: Date.now() + 3600_000,
      accountId: "cline-a", email: "a@example.com",
    });
    await saveCredential("cline", {
      access: "cline-access-b", refresh: "cline-refresh-b", expires: Date.now() + 3600_000,
      accountId: "cline-b", email: "b@example.com",
    });
    const originalAccountId = getAccountSet("cline")!.activeAccountId;
    saveConfig({
      port: 0, hostname: "127.0.0.1", defaultProvider: "cline",
      providers: {
        cline: {
          adapter: "openai-chat", baseUrl: "https://api.cline.bot/api/v1", authMode: "oauth",
          defaultModel: "anthropic/claude-opus-4.6", models: ["anthropic/claude-opus-4.6"],
        },
      },
    } as OcxConfig);

    const server = startServer(0);
    try {
      const response = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "cline/anthropic-claude-opus-4.6", input: "hello", stream: false }),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ status: "failed" });
      expect(calls).toBe(2);
      expect(getAccountSet("cline")?.activeAccountId).toBe(originalAccountId);
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("xAI API-key rotation preserves cache affinity and never adds OAuth CLI headers", async () => {
    const originalFetch = globalThis.fetch;
    const promptCacheKey = "codex-session-high-entropy-429-e2e";
    const seenHeaders: Headers[] = [];
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://api.x.ai/v1/chat/completions") {
        const headers = new Headers(init?.headers);
        seenHeaders.push(headers);
        if (seenHeaders.length === 1) {
          return new Response(JSON.stringify({ error: { message: "rate limited" } }), {
            status: 429,
            headers: { "retry-after": "30", "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({
          id: "chatcmpl-xai-rotate",
          object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "ok after rotate" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }), { headers: { "content-type": "application/json" } });
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    let server: ReturnType<typeof startServer> | null = null;
    try {
      const config: OcxConfig = {
        port: 0,
        hostname: "127.0.0.1",
        defaultProvider: "xai",
        providers: {
          xai: {
            adapter: "openai-chat",
            baseUrl: "https://api.x.ai/v1",
            authMode: "key",
            apiKey: "key-alpha-000111222333",
            apiKeyPool: [
              { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
              { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
            ],
          },
        },
      } as OcxConfig;
      saveConfig(config);
      server = startServer(0);
      const res = await originalFetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "xai/grok-4.5",
          input: "hello",
          stream: false,
          prompt_cache_key: promptCacheKey,
        }),
      });
      expect(res.status).toBe(200);
      const json = await res.json() as { output?: { type: string; content?: { text?: string }[] }[] };
      expect(json.output?.find(o => o.type === "message")?.content?.[0]?.text).toBe("ok after rotate");
      expect(seenHeaders).toHaveLength(2);
      expect(seenHeaders.map(headers => headers.get("authorization"))).toEqual([
        "Bearer key-alpha-000111222333",
        "Bearer key-beta-444555666777",
      ]);
      for (const headers of seenHeaders) {
        expect(headers.get("x-grok-conv-id")).toBe(deriveXaiConvId(promptCacheKey));
        expect(headers.get("x-grok-client-identifier")).toBeNull();
        expect(headers.get("x-grok-client-version")).toBeNull();
        expect(headers.get("x-xai-token-auth")).toBeNull();
        for (const [name, value] of headers.entries()) {
          expect(name).not.toContain(promptCacheKey);
          expect(value).not.toContain(promptCacheKey);
        }
      }
    } finally {
      server?.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("routed 429 rotates to the pool's next key and succeeds", async () => {
    const seenAuth: string[] = [];
    upstream = Bun.serve({
      hostname: "127.0.0.1", port: 0,
      fetch(req) {
        seenAuth.push(req.headers.get("authorization") ?? "");
        if (seenAuth.length === 1) {
          return new Response(JSON.stringify({ error: { message: "rate limited" } }), {
            status: 429, headers: { "retry-after": "30", "content-type": "application/json" },
          });
        }
        return new Response(JSON.stringify({
          id: "chatcmpl-1", object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "ok after rotate" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }), { headers: { "content-type": "application/json" } });
      },
    });
    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "pooled",
      providers: {
        pooled: {
          adapter: "openai-chat",
          baseUrl: `http://127.0.0.1:${upstream.port}/v1`,
          allowPrivateNetwork: true,
          apiKey: "key-alpha-000111222333",
          apiKeyPool: [
            { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
            { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
          ],
        },
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const res = await fetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "pooled/some-model", input: "hello", stream: false }),
      });
      expect(res.status).toBe(200);
      const json = await res.json() as { output?: { type: string; content?: { text?: string }[] }[] };
      const message = json.output?.find(o => o.type === "message");
      expect(message?.content?.[0]?.text).toBe("ok after rotate");
      expect(seenAuth[0]).toBe("Bearer key-alpha-000111222333");
      expect(seenAuth[1]).toBe("Bearer key-beta-444555666777");
    } finally {
      server.stop(true);
    }
  });

  test("network failure after a 429 key rotation surfaces the retry error", async () => {
    const originalFetch = globalThis.fetch;
    let upstreamAttempts = 0;
    globalThis.fetch = (async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      if (url === "https://fault-injected.example/v1/chat/completions") {
        upstreamAttempts += 1;
        if (upstreamAttempts === 1) {
          return new Response(JSON.stringify({ error: { message: "original rate limit" } }), {
            status: 429,
            headers: { "retry-after": "30", "content-type": "application/json" },
          });
        }
        throw new TypeError("rotated retry socket reset");
      }
      return originalFetch(input, init);
    }) as typeof fetch;

    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "pooled-network-failure",
      providers: {
        "pooled-network-failure": {
          adapter: "openai-chat",
          baseUrl: "https://fault-injected.example/v1",
          apiKey: "key-alpha-000111222333",
          apiKeyPool: [
            { id: "k1", key: "key-alpha-000111222333", addedAt: 1 },
            { id: "k2", key: "key-beta-444555666777", addedAt: 2 },
          ],
        },
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const res = await fetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "pooled-network-failure/some-model", input: "hello", stream: false }),
      });
      const json = await res.json() as { error?: { message?: string } };

      expect(upstreamAttempts).toBe(2);
      expect(res.status).toBe(502);
      expect(json.error?.message).toContain("rotated retry socket reset");
      expect(json.error?.message).not.toContain("original rate limit");
    } finally {
      server.stop(true);
      globalThis.fetch = originalFetch;
    }
  });

  test("noVisionModels model with no sidecar plan gets images stripped fail-closed", async () => {
    let upstreamBody = "";
    upstream = Bun.serve({
      hostname: "127.0.0.1", port: 0,
      async fetch(req) {
        upstreamBody = await req.text();
        return new Response(JSON.stringify({
          id: "chatcmpl-2", object: "chat.completion",
          choices: [{ index: 0, message: { role: "assistant", content: "text only" }, finish_reason: "stop" }],
          usage: { prompt_tokens: 3, completion_tokens: 2, total_tokens: 5 },
        }), { headers: { "content-type": "application/json" } });
      },
    });
    const config: OcxConfig = {
      port: 0, hostname: "127.0.0.1", defaultProvider: "textonly",
      providers: {
        textonly: {
          adapter: "openai-chat",
          baseUrl: `http://127.0.0.1:${upstream.port}/v1`,
          allowPrivateNetwork: true,
          apiKey: "key-alpha-000111222333",
          noVisionModels: ["blind-model"],
        },
        // No forward provider in config → planVisionSidecar cannot run.
      },
    } as OcxConfig;
    saveConfig(config);
    const server = startServer(0);
    try {
      const res = await fetch(new URL("/v1/responses", server.url), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "textonly/blind-model", stream: false,
          input: [{ type: "message", role: "user", content: [
            { type: "input_text", text: "describe this" },
            { type: "input_image", image_url: "data:image/png;base64,aGVsbG8=" },
          ]}],
        }),
      });
      expect(res.status).toBe(200);
      expect(upstreamBody).toContain("[image omitted");
      expect(upstreamBody).not.toContain("aGVsbG8=");
    } finally {
      server.stop(true);
    }
  });
});
