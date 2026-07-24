import { describe, expect, test } from "bun:test";
import { createOpenAIChatAdapter } from "../src/adapters/openai-chat";
import { buildModelsRequest } from "../src/oauth";
import { normalizeClineCatalog, toClineWireModelId } from "../src/providers/cline-catalog";
import type { OcxProviderConfig } from "../src/types";

const payload = {
  recommended: [
    { id: "anthropic/claude-opus-4.6", name: "Claude Opus 4.6" },
    { id: "openai/gpt-5.3-codex", name: "GPT-5.3 Codex" },
  ],
  free: [
    { id: "kwaipilot/kat-coder-pro", name: "KAT Coder Pro" },
    { id: "cline-pass/kimi-k2.7-code", name: "Duplicate through free" },
  ],
  clinePass: [
    { id: "cline-pass/kimi-k2.7-code", name: "Kimi K2.7 Code" },
    { id: "cline-pass/glm-5.2", name: "GLM 5.2" },
  ],
};

describe("Cline recommended model catalog", () => {
  test("Cline account exposes recommended and free groups with native IDs", () => {
    expect(normalizeClineCatalog(payload, "cline")).toEqual([
      "anthropic/claude-opus-4.6",
      "openai/gpt-5.3-codex",
      "kwaipilot/kat-coder-pro",
      "cline-pass/kimi-k2.7-code",
    ]);
  });

  test("ClinePass exposes subscription and free groups with clean local IDs", () => {
    expect(normalizeClineCatalog(payload, "cline-pass")).toEqual([
      "kimi-k2.7-code",
      "glm-5.2",
      "kwaipilot/kat-coder-pro",
    ]);
    expect(toClineWireModelId("cline-pass", "kimi-k2.7-code")).toBe("cline-pass/kimi-k2.7-code");
    expect(toClineWireModelId("cline-pass", "cline-pass/glm-5.2")).toBe("cline-pass/glm-5.2");
    expect(toClineWireModelId("cline", "anthropic/claude-opus-4.6")).toBe("anthropic/claude-opus-4.6");
  });

  test("rejects malformed or empty catalog payloads", () => {
    expect(normalizeClineCatalog({}, "cline")).toBeUndefined();
    expect(normalizeClineCatalog({ recommended: [{ nope: true }] }, "cline-pass")).toBeUndefined();
  });

  test("provider connectivity uses Cline's real recommended-models endpoint", () => {
    const request = buildModelsRequest({
      adapter: "openai-chat",
      baseUrl: "https://api.cline.bot/api/v1",
      authMode: "oauth",
    }, "cline-token", "cline");
    expect(request.url).toBe("https://api.cline.bot/api/v1/ai/cline/recommended-models");
    expect(request.headers.Authorization).toBe("Bearer workos:cline-token");

    const alreadyFormatted = buildModelsRequest({
      adapter: "openai-chat",
      baseUrl: "https://api.cline.bot/api/v1",
      authMode: "oauth",
    }, "workos:cline-token", "cline");
    expect(alreadyFormatted.headers.Authorization).toBe("Bearer workos:cline-token");

    const clinePass = buildModelsRequest({
      adapter: "openai-chat",
      baseUrl: "https://api.cline.bot/api/v1",
      authMode: "key",
    }, "cline-pass-key", "cline-pass");
    expect(clinePass.headers.Authorization).toBe("Bearer cline-pass-key");
  });

  test("ClinePass sends the clean selected model with the required wire prefix", async () => {
    const provider = {
      adapter: "openai-chat",
      baseUrl: "https://api.cline.bot/api/v1",
      authMode: "key",
      apiKey: "test-key",
      modelIdPrefix: "cline-pass/",
    } as OcxProviderConfig;
    const request = await createOpenAIChatAdapter(provider).buildRequest({
      modelId: "kimi-k2.7-code",
      context: { messages: [{ role: "user", content: "hello" }], tools: [] },
      stream: false,
      options: {},
    });
    expect(JSON.parse(request.body).model).toBe("cline-pass/kimi-k2.7-code");

    const freeRequest = await createOpenAIChatAdapter(provider).buildRequest({
      modelId: "kwaipilot/kat-coder-pro",
      context: { messages: [{ role: "user", content: "hello" }], tools: [] },
      stream: false,
      options: {},
    });
    expect(JSON.parse(freeRequest.body).model).toBe("kwaipilot/kat-coder-pro");
  });

  test("Cline non-stream responses unwrap the data envelope", async () => {
    const adapter = createOpenAIChatAdapter({
      adapter: "openai-chat",
      baseUrl: "https://api.cline.bot/api/v1",
      authMode: "oauth",
      apiKey: "workos:test-token",
    } as OcxProviderConfig);
    const events = await adapter.parseResponse!(Response.json({
      data: {
        choices: [{ message: { role: "assistant", content: "OK" } }],
        usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
      },
    }));
    expect(events).toEqual([
      { type: "text_delta", text: "OK" },
      { type: "done", usage: { inputTokens: 3, outputTokens: 1 } },
    ]);
  });
});
