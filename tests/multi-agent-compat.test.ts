/**
 * Multi-agent compatibility shims (follow-up to devlog/260709_v2_gated_ultra):
 * models are no longer v1-pinned by ocx, but legacy/v1-surface requests still need
 * the Proactive delegation prompt when they arrive with the synthetic top tier.
 */
import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleResponses, injectDeveloperMessage, multiAgentGuidanceText, sanitizeEncryptedContentInPlace } from "../src/server/responses";
import { recoverSelectedRoutedSubagentRequest } from "../src/subagent-bridge/recovery";
import { HANDOFF_MAX_MESSAGE_BYTES, SubagentHandoffStore, subagentHandoffStore } from "../src/subagent-bridge/handoff-store";
import { handleSubagentHandoffRequest } from "../src/subagent-bridge/http";
import {
  createSubagentBridgeRequestSignature,
  sealSubagentBridgeRequestBody,
  SUBAGENT_BRIDGE_ISSUED_AT_HEADER,
  SUBAGENT_BRIDGE_INSTANCE_HEADER,
  SUBAGENT_BRIDGE_REQUEST_ID_HEADER,
  SUBAGENT_BRIDGE_SIGNATURE_HEADER,
  SUBAGENT_BRIDGE_STAGING_PATH,
  SubagentBridgeReplayGuard,
} from "../src/subagent-bridge/auth";
import { SUBAGENT_BRIDGE_HEALTH_PROTOCOL } from "../src/subagent-bridge/runtime";
import { parseRequest } from "../src/responses/parser";
import type { OcxParsedRequest } from "../src/types";
import { clearResponseStateForTests, flushResponseState, rememberResponseState } from "../src/responses/state";
import { responseWithDeferredRequestLog } from "../src/server/relay";
import { clearRequestLogsForTests, getRequestLogEntries, type RequestLogContext } from "../src/server/request-log";

const savedCodexHome = process.env.CODEX_HOME;

afterEach(() => {
  if (savedCodexHome === undefined) delete process.env.CODEX_HOME;
  else process.env.CODEX_HOME = savedCodexHome;
});

function codexHomeFixture(configToml: string): string {
  const dir = mkdtempSync(join(tmpdir(), "ocx-v1pin-"));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "config.toml"), configToml);
  process.env.CODEX_HOME = dir;
  return dir;
}

/** Write an injected-catalog fixture into the active CODEX_HOME. */
function catalogFixture(dir: string, models: Array<{ slug: string; efforts: string[]; multiAgentVersion?: string }>): void {
  writeFileSync(join(dir, "opencodex-catalog.json"), JSON.stringify({
    models: models.map(m => ({
      slug: m.slug,
      display_name: m.slug,
      multi_agent_version: m.multiAgentVersion ?? "v2",
      supported_reasoning_levels: m.efforts.map(effort => ({ effort, description: effort })),
    })),
  }));
}

const V2_ON = "[features.multi_agent_v2]\nenabled = true\n";
const V2_OFF = "[features]\nmulti_agent = true\n";
const REAL_FERNET = "gAAAAABnX6DqvQfLy4CIvIQp9x1G7m2JXjvXgWIBu8VG6OKoyHDyEwE6Q9H9YfdwWlQF-Qj3Hb_RkPBMFa9_k54XfOpfK0S7Ng==";

function agentMessage(recipient: string, messageType: "NEW_TASK" | "MESSAGE" = "MESSAGE") {
  return { type: "agent_message", recipient, content: [
    { type: "input_text", text: `Message Type: ${messageType}\nTask name: ${recipient}\nSender: /root\nPayload:\n` },
    { type: "encrypted_content", encrypted_content: REAL_FERNET },
  ] };
}

function routedBridgeConfig(overrides: Record<string, unknown> = {}) {
  return {
    port: 10100,
    defaultProvider: "vendor",
    providers: { vendor: { adapter: "openai-chat", baseUrl: "https://example.test/v1" } },
    subagentModels: ["vendor/model"],
    subagentBridge: { enabled: true },
    ...overrides,
  } as never;
}

function chatSuccess(): Response {
  return Response.json({
    id: "chatcmpl-bridge",
    object: "chat.completion",
    model: "model",
    choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 2, completion_tokens: 1, total_tokens: 3 },
  });
}

function parsedFixture(over: {
  reasoning?: string;
  tools?: Array<{ name: string; namespace?: string }>;
  rawInput?: unknown;
}): OcxParsedRequest {
  return {
    modelId: "gpt-5.5",
    context: {
      messages: [{ role: "user", content: "hi", timestamp: 1 }],
      tools: (over.tools ?? [{ name: "spawn_agent" }]) as never,
    },
    stream: true,
    options: over.reasoning ? { reasoning: over.reasoning as never } : {},
    _rawBody: { model: "gpt-5.5", input: over.rawInput ?? [] },
  };
}

describe("multiAgentGuidanceText", () => {
  test("v1 tool surface + max injects the tagged Proactive text", async () => {
    codexHomeFixture(V2_OFF); // guidance fires regardless of v2 flag
    const text = await multiAgentGuidanceText(parsedFixture({
      reasoning: "max",
      tools: [{ name: "spawn_agent", namespace: "agents" }, { name: "send_input", namespace: "agents" }],
    }));
    expect(text).toContain("<multi_agent_mode>");
    expect(text).toContain("Proactive multi-agent delegation is active");
  });

  test("v1 tool surface below the top tier stays silent", async () => {
    codexHomeFixture(V2_OFF);
    const v1Tools = [{ name: "spawn_agent", namespace: "agents" }];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "high", tools: v1Tools }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ tools: v1Tools }))).toBeNull();
  });

  test("v2 or non-agent tool surfaces stay silent even at max", async () => {
    codexHomeFixture(V2_OFF);
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: [{ name: "spawn_agent" }] }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: [{ name: "shell" }] }))).toBeNull();
  });

  test("flat v2 surface + injectionModel injects the designation with fork_turns rules", async () => {
    codexHomeFixture(V2_ON);
    const v2Tools = [{ name: "spawn_agent" }];
    const text = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "medium", tools: v2Tools }),
      "anthropic/claude-sonnet-5",
    );
    expect(text).toContain("<multi_agent_mode>");
    expect(text).toContain('"anthropic/claude-sonnet-5"');
    expect(text).toContain("fork_turns");
    expect(text).toContain('"none"');
    // schema hides model on native backends — the prompt must pre-empt schema doubt
    expect(text).toContain("never claim sub-agent models cannot be selected");
    // codex-rs supplies the Proactive text on v2 — the proxy must NOT duplicate it.
    expect(text).not.toContain("Proactive multi-agent delegation is active");
  });

  test("NATIVE v2 wire shape (collaboration namespace + v2 companions) is classified v2", async () => {
    codexHomeFixture(V2_ON);
    // The ChatGPT backend registers reserved namespaced collab tools:
    // collaboration.spawn_agent + send_message/followup_task/wait_agent/... (spec_plan.rs)
    const nativeV2 = [
      { name: "spawn_agent", namespace: "collaboration" },
      { name: "send_message", namespace: "collaboration" },
      { name: "followup_task", namespace: "collaboration" },
      { name: "wait_agent", namespace: "collaboration" },
      { name: "list_agents", namespace: "collaboration" },
    ];
    const text = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "medium", tools: nativeV2 }),
      "anthropic/claude-sonnet-5",
    );
    expect(text).toContain('"anthropic/claude-sonnet-5"');
    expect(text).toContain("fork_turns");
    expect(text).not.toContain("Proactive multi-agent delegation is active");
    // and WITHOUT an injectionModel it stays silent (codex-rs owns the v2 Proactive text)
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "ultra", tools: nativeV2 }))).toBeNull();
  });

  test("responses_lite WS shape: tools inside input additional_tools are seen (real Codex Desktop capture)", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [{ slug: "gpt-5.6-terra", efforts: ["high", "max", "ultra"] }]);
    // Shape captured live from Codex Desktop 0.143.0 (responses_websockets lite): NO body.tools;
    // an input item {type:"additional_tools", role, tools:[...]} carries the tool specs.
    const parsed = parseRequest({
      model: "gpt-5.6-sol",
      stream: true,
      reasoning: { effort: "high" },
      input: [
        {
          type: "additional_tools",
          role: "developer",
          tools: [
            { type: "custom", name: "exec", description: "..." },
            { type: "function", name: "wait", description: "...", parameters: {} },
            { type: "namespace", name: "collaboration", description: "...", tools: [
              { type: "function", name: "followup_task", description: "...", parameters: {} },
              { type: "function", name: "interrupt_agent", description: "...", parameters: {} },
              { type: "function", name: "list_agents", description: "...", parameters: {} },
              { type: "function", name: "send_message", description: "...", parameters: {} },
              { type: "function", name: "spawn_agent", description: "...", parameters: {} },
              { type: "function", name: "wait_agent", description: "...", parameters: {} },
            ] },
          ],
        },
        { type: "message", role: "user", content: [{ type: "input_text", text: "gpt-5.6-terra 호출해봐" }] },
      ],
    });
    const names = (parsed.context.tools ?? []).map(t => (t.namespace ? `${t.namespace}.${t.name}` : t.name));
    expect(names).toContain("collaboration.spawn_agent");
    const text = await multiAgentGuidanceText(parsed, "gpt-5.6-sol", "xhigh", ["gpt-5.6-terra"]);
    expect(text).toContain("never claim sub-agent models cannot be selected");
    expect(text).toContain('(reasoning_effort high/max/ultra): "gpt-5.6-terra"');
  });

  test("v1 wire shape (multi_agent_v1 namespace + send_input) still classifies v1", async () => {
    codexHomeFixture(V2_OFF);
    const v1Tools = [
      { name: "spawn_agent", namespace: "multi_agent_v1" },
      { name: "send_input", namespace: "multi_agent_v1" },
      { name: "wait_agent", namespace: "multi_agent_v1" },
      { name: "close_agent", namespace: "multi_agent_v1" },
    ];
    const text = await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: v1Tools }));
    expect(text).toContain("Proactive multi-agent delegation is active");
  });

  test("subagentModels roster: per-model ladders on v2; v1 carries NO roster", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [
      { slug: "gpt-5.6-sol", efforts: ["high", "max", "ultra"] },
      { slug: "anthropic/claude-sonnet-5", efforts: ["low", "medium", "high", "xhigh"] },
    ]);
    const roster = ["gpt-5.6-sol", "anthropic/claude-sonnet-5", "missing/model"];
    const v2 = await multiAgentGuidanceText(
      parsedFixture({ tools: [{ name: "spawn_agent" }] }),
      "anthropic/claude-sonnet-5", undefined, roster,
    );
    // differing ladders -> per-model annotation
    expect(v2).toContain('"gpt-5.6-sol" (high/max/ultra)');
    expect(v2).toContain('"anthropic/claude-sonnet-5" (low/medium/high/xhigh)');
    expect(v2).not.toContain("missing/model"); // not in the catalog -> omitted

    const v1 = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "max", tools: [{ name: "spawn_agent", namespace: "multi_agent_v1" }, { name: "send_input", namespace: "multi_agent_v1" }] }),
      undefined, undefined, roster,
    );
    expect(v1).toContain("Proactive multi-agent delegation is active");
    expect(v1).not.toContain("Available models"); // v1 stays lean: Proactive text only
  });

  test("roster is silent when unset or nothing resolves in the catalog", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [{ slug: "gpt-5.5", efforts: ["low", "medium"] }]);
    const v1Tools = [{ name: "spawn_agent", namespace: "multi_agent_v1" }, { name: "send_input", namespace: "multi_agent_v1" }];
    const unset = await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: v1Tools }));
    expect(unset).not.toContain("Available models");
    // an UNRESOLVED roster does not fire guidance on v2 either
    expect(await multiAgentGuidanceText(parsedFixture({ tools: [{ name: "spawn_agent" }] }), undefined, undefined, ["nope/none"])).toBeNull();
  });

  test("roster excludes catalog rows that Codex cannot accept as V2 subagents", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [
      { slug: "vendor/eligible", efforts: ["low", "high"], multiAgentVersion: "v2" },
      { slug: "vendor/v1-only", efforts: ["low", "high"], multiAgentVersion: "v1" },
      { slug: "vendor/no-efforts", efforts: [], multiAgentVersion: "v2" },
      { slug: "vendor/bad-effort", efforts: ["banana"], multiAgentVersion: "v2" },
    ]);
    const text = await multiAgentGuidanceText(
      parsedFixture({ tools: [{ name: "spawn_agent" }] }),
      undefined,
      undefined,
      ["vendor/eligible", "vendor/v1-only", "vendor/no-efforts", "vendor/bad-effort", "vendor/unknown"],
    );
    expect(text).toContain("vendor/eligible");
    expect(text).not.toContain("vendor/v1-only");
    expect(text).not.toContain("vendor/no-efforts");
    expect(text).not.toContain("vendor/bad-effort");
    expect(text).not.toContain("vendor/unknown");
  });

  test("recovers a real Fernet V2 child payload only for a selected routed model", () => {
    const token = "gAAAAABnX6DqvQfLy4CIvIQp9x1G7m2JXjvXgWIBu8VG6OKoyHDyEwE6Q9H9YfdwWlQF-Qj3Hb_RkPBMFa9_k54XfOpfK0S7Ng==";
    const body = {
      model: "vendor/model",
      input: [{
        type: "agent_message",
        author: "/root",
        recipient: "/root/worker_001122334455",
        content: [
          { type: "input_text", text: "Message Type: NEW_TASK\nTask name: /root/worker_001122334455\nSender: /root\nPayload:\n" },
          { type: "encrypted_content", encrypted_content: token },
        ],
      }],
    };
    const store = new SubagentHandoffStore({ randomHex: () => "001122334455" });
    store.stageSpawn({ taskName: "worker", model: "vendor/model", message: "plain staged task" });

    expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store })).toEqual({ status: "recovered", count: 1 });
    expect(body.input[0].content[0]).toEqual({ type: "input_text", text: "Message Type: NEW_TASK\nTask name: /root/worker_001122334455\nSender: /root\nPayload:\n" });
    expect(body.input[0].content[1]).toEqual({ type: "input_text", text: "plain staged task" });
    expect(sanitizeEncryptedContentInPlace(body.input)).toBe(0);
    const parsedContent = parseRequest(body).context.messages[0]?.content;
    expect(JSON.stringify(parsedContent)).toContain("plain staged task");
  });

  test("recovers exact-limit base64-like and embedded-Fernet plaintext byte-for-byte as input_text", () => {
    const payloads = [
      "A".repeat(HANDOFF_MAX_MESSAGE_BYTES),
      `literal before ${REAL_FERNET} literal after`,
    ];

    for (const [index, payload] of payloads.entries()) {
      const recipient = `/root/exact_${(index + 1).toString(16).padStart(12, "0")}`;
      const body = { model: "vendor/model", input: [agentMessage(recipient)] };
      const store = new SubagentHandoffStore();
      store.stageMessage({ kind: "message", target: recipient, message: payload });

      expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store }))
        .toEqual({ status: "recovered", count: 1 });
      expect(body.input[0].content[1]).toEqual({ type: "input_text", text: payload });
      expect((body.input[0].content[1] as { text: string }).text).toBe(payload);
      expect(sanitizeEncryptedContentInPlace(body.input)).toBe(0);
      const parsed = parseRequest(body).context.messages[0]?.content;
      expect(parsed).toEqual([
        { type: "text", text: body.input[0].content[0].text },
        { type: "text", text: payload },
      ]);
    }
  });

  test("multiple Fernet payload parts fail closed and do not consume", () => {
    const recipient = "/root/multiple_000000000001";
    const body = { model: "vendor/model", input: [agentMessage(recipient)] };
    body.input[0].content.push({ type: "encrypted_content", encrypted_content: REAL_FERNET });
    const before = structuredClone(body);
    const store = new SubagentHandoffStore();
    store.stageMessage({ kind: "message", target: recipient, message: "must remain staged" });

    expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store }))
      .toEqual({ status: "invalid", reason: "multiple_envelopes" });
    expect(body).toEqual(before);
    expect(store.consume(recipient, "MESSAGE")?.message).toBe("must remain staged");
  });

  test("malformed and future-version routed handoff envelopes fail closed without consuming", () => {
    const futureBytes = Buffer.from(REAL_FERNET, "base64url");
    futureBytes[0] = 0x81;
    const envelopes = [
      { value: "gAAAA-not-a-complete-fernet-token", reason: "malformed_envelope" },
      { value: futureBytes.toString("base64url"), reason: "unsupported_envelope_version" },
    ] as const;

    for (const [index, envelope] of envelopes.entries()) {
      const recipient = `/root/invalid_${(index + 1).toString(16).padStart(12, "0")}`;
      const body = { model: "vendor/model", input: [agentMessage(recipient)] };
      body.input[0].content[1] = { type: "encrypted_content", encrypted_content: envelope.value };
      const before = structuredClone(body);
      const store = new SubagentHandoffStore();
      store.stageMessage({ kind: "message", target: recipient, message: "must remain staged" });

      expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store }))
        .toEqual({ status: "invalid", reason: envelope.reason });
      expect(body).toEqual(before);
      expect(store.consume(recipient, "MESSAGE")?.message).toBe("must remain staged");
    }
  });

  test("a valid handoff envelope with an invalid request sibling does not consume", async () => {
    const target = "/root/preflight_000000000001";
    const plaintext = "MUST_SURVIVE_REQUEST_PREFLIGHT_4a11d8";
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target, message: plaintext });
    try {
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "vendor/model",
          stream: "not-a-boolean",
          input: [agentMessage(target)],
        }),
      }), routedBridgeConfig(), {} as never);

      expect(response.status).toBe(400);
      expect(subagentHandoffStore.consume(target, "MESSAGE")?.message).toBe(plaintext);
    } finally {
      subagentHandoffStore.clear();
    }
  });

  test("invalid routed handoff envelopes stop before provider dispatch while non-candidates still dispatch", async () => {
    const futureBytes = Buffer.from(REAL_FERNET, "base64url");
    futureBytes[0] = 0x81;
    const invalidContents = [
      [{ type: "encrypted_content", encrypted_content: "gAAAA-truncated" }],
      [{ type: "encrypted_content", encrypted_content: futureBytes.toString("base64url") }],
      [
        { type: "encrypted_content", encrypted_content: REAL_FERNET },
        { type: "encrypted_content", encrypted_content: REAL_FERNET },
      ],
    ];
    const originalFetch = globalThis.fetch;
    let providerCalls = 0;
    globalThis.fetch = (async () => {
      providerCalls += 1;
      return chatSuccess();
    }) as typeof fetch;
    const send = (model: string, content: unknown[]) => handleResponses(new Request("http://127.0.0.1/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model,
        stream: false,
        store: false,
        input: [{
          type: "agent_message",
          recipient: "/root/invalid_000000000001",
          content: [
            { type: "input_text", text: "Message Type: MESSAGE\nTask name: /root/invalid_000000000001\nSender: /root\nPayload:\n" },
            ...content,
          ],
        }],
      }),
    }), routedBridgeConfig(), {} as never);

    try {
      for (const content of invalidContents) {
        const response = await send("vendor/model", content);
        const responseText = await response.text();
        expect(response.status).toBe(400);
        expect((JSON.parse(responseText) as { error: { code: string } }).error.code).toBe("subagent_handoff_invalid");
        expect(responseText).not.toContain("encrypted_content");
      }
      expect(providerCalls).toBe(0);

      expect((await send("vendor/other", invalidContents[0]!)).status).toBe(200);
      expect(providerCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("spawn recovery requires routed-model equivalence and a mismatch does not consume", () => {
    const store = new SubagentHandoffStore({ randomHex: () => "001122334455" });
    const { taskName } = store.stageSpawn({
      taskName: "model bound",
      model: "vendor/native/path",
      message: "model-bound task",
    });
    const mismatched = { model: "vendor/other", input: [agentMessage(`/root/${taskName}`, "NEW_TASK")] };
    const equivalent = { model: "vendor/native-path", input: [agentMessage(`/root/${taskName}`, "NEW_TASK")] };

    expect(recoverSelectedRoutedSubagentRequest(mismatched, {
      enabled: true,
      selectedModels: ["vendor/other", "vendor/native-path"],
      store,
    })).toEqual({ status: "missing" });
    expect(mismatched.input[0].content[1]).toEqual({ type: "encrypted_content", encrypted_content: REAL_FERNET });
    expect(recoverSelectedRoutedSubagentRequest(equivalent, {
      enabled: true,
      selectedModels: ["vendor/other", "vendor/native-path"],
      store,
    })).toEqual({ status: "recovered", count: 1 });
    expect(equivalent.input[0].content[1]).toEqual({ type: "input_text", text: "model-bound task" });
  });

  test("fails closed when selected routed child has no staged match and preserves native ciphertext", () => {
    const token = "gAAAAABnX6DqvQfLy4CIvIQp9x1G7m2JXjvXgWIBu8VG6OKoyHDyEwE6Q9H9YfdwWlQF-Qj3Hb_RkPBMFa9_k54XfOpfK0S7Ng==";
    const makeBody = (model: string) => ({
      model,
      input: [{ type: "agent_message", recipient: "/root/worker", content: [
        { type: "input_text", text: "Message Type: MESSAGE\nTask name: /root/worker\nSender: /root\nPayload:\n" },
        { type: "encrypted_content", encrypted_content: token },
      ] }],
    });
    const routed = makeBody("vendor/model");
    expect(recoverSelectedRoutedSubagentRequest(routed, { enabled: true, selectedModels: ["vendor/model"], store: new SubagentHandoffStore() }))
      .toEqual({ status: "missing" });
    expect(routed.input[0].content[1].encrypted_content).toBe(token);

    const native = makeBody("gpt-5.6-sol");
    expect(recoverSelectedRoutedSubagentRequest(native, { enabled: true, selectedModels: ["gpt-5.6-sol"], store: new SubagentHandoffStore() }))
      .toEqual({ status: "unchanged" });
    expect(native.input[0].content[1].encrypted_content).toBe(token);
  });

  test("request boundary returns content-free 409 subagent_handoff_missing", async () => {
    subagentHandoffStore.clear();
    const token = "gAAAAABnX6DqvQfLy4CIvIQp9x1G7m2JXjvXgWIBu8VG6OKoyHDyEwE6Q9H9YfdwWlQF-Qj3Hb_RkPBMFa9_k54XfOpfK0S7Ng==";
    const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "vendor/model",
        stream: false,
        input: [{ type: "agent_message", recipient: "/root/worker", content: [
          { type: "input_text", text: "Message Type: MESSAGE\nTask name: /root/worker\nSender: /root\nPayload:\n" },
          { type: "encrypted_content", encrypted_content: token },
        ] }],
      }),
    }), {
      port: 10100,
      defaultProvider: "vendor",
      providers: { vendor: { adapter: "openai-chat", baseUrl: "https://example.test/v1" } },
      subagentModels: ["vendor/model"],
      subagentBridge: { enabled: true },
    }, {} as never);
    expect(response.status).toBe(409);
    const payload = await response.json() as { error: { code: string; message: string } };
    expect(payload.error.code).toBe("subagent_handoff_missing");
    expect(payload.error.message).not.toContain(token);
  });

  test("spawn routed-model mismatch returns content-free 409 and leaves the handoff for its model", async () => {
    subagentHandoffStore.clear();
    const plaintext = "MODEL_BOUND_PLAINTEXT_8f37c6";
    const spawn = subagentHandoffStore.stageSpawn({ taskName: "bound request", model: "vendor/model", message: plaintext });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => chatSuccess()) as typeof fetch;
    try {
      const send = (model: string) => handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model, stream: false, store: false, input: [agentMessage(`/root/${spawn.taskName}`, "NEW_TASK")] }),
      }), routedBridgeConfig({ subagentModels: ["vendor/model", "vendor/other"] }), {} as never);

      const mismatch = await send("vendor/other");
      const mismatchText = await mismatch.text();
      expect(mismatch.status).toBe(409);
      expect(mismatchText).toContain("subagent_handoff_missing");
      expect(mismatchText).not.toContain(plaintext);
      expect(mismatchText).not.toContain(REAL_FERNET);

      const matched = await send("vendor/model");
      expect(matched.status).toBe(200);
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
    }
  });

  test("request-boundary spawn, send_message, and followup_task handoffs recover exact nonce plaintext once in FIFO/type order", async () => {
    const staged = {
      spawn: "spawn-nonce-4d24e9c1",
      message: "message-nonce-09a3f6bd",
      followup: "followup-nonce-e1872a45",
    };
    const token = Buffer.alloc(32, 41).toString("base64url");
    const instanceId = Buffer.alloc(32, 42).toString("base64url");
    const now = 4_000_000;
    const replayGuard = new SubagentBridgeReplayGuard({ now: () => now });
    let requestSequence = 0;
    subagentHandoffStore.clear();
    const post = (body: unknown) => {
      const plaintext = JSON.stringify(body);
      const requestId = Buffer.alloc(32, ++requestSequence).toString("base64url");
      const encoded = sealSubagentBridgeRequestBody({
        token,
        protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
        method: "POST",
        path: SUBAGENT_BRIDGE_STAGING_PATH,
        instanceId,
        requestId,
        issuedAtMs: now,
        body: plaintext,
        randomBytesFn: () => Buffer.from(requestId, "base64url").subarray(0, 12),
      });
      expect(encoded).not.toBeNull();
      const signature = createSubagentBridgeRequestSignature({
        token,
        protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
        method: "POST",
        path: SUBAGENT_BRIDGE_STAGING_PATH,
        instanceId,
        requestId,
        issuedAtMs: now,
        body: encoded!,
      });
      expect(signature).not.toBeNull();
      return handleSubagentHandoffRequest(new Request(`http://127.0.0.1${SUBAGENT_BRIDGE_STAGING_PATH}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          [SUBAGENT_BRIDGE_INSTANCE_HEADER]: instanceId,
          [SUBAGENT_BRIDGE_REQUEST_ID_HEADER]: requestId,
          [SUBAGENT_BRIDGE_ISSUED_AT_HEADER]: String(now),
          [SUBAGENT_BRIDGE_SIGNATURE_HEADER]: signature!,
        },
        body: encoded!,
      }), {
        readToken: () => token,
        runtimeEligible: true,
        store: subagentHandoffStore,
        instanceId,
        replayGuard,
        now: () => now,
      });
    };

    const spawn = await post({ kind: "spawn", task_name: "boundary", model: "vendor/model", message: staged.spawn });
    const spawnText = await spawn.text();
    const taskName = (JSON.parse(spawnText) as { task_name: string }).task_name;
    const message = await post({ kind: "message", target: `/root/${taskName}`, message: staged.message });
    const messageText = await message.text();
    const followup = await post({ kind: "followup", target: taskName, message: staged.followup });
    const followupText = await followup.text();
    expect([spawn.status, message.status, followup.status]).toEqual([200, 200, 200]);
    expect(`${spawnText}${messageText}${followupText}`).not.toContain("nonce-");

    const seenBodies: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, init) => {
      seenBodies.push(String(init?.body ?? ""));
      return chatSuccess();
    }) as typeof fetch;
    const send = (messageType: "NEW_TASK" | "MESSAGE") => handleResponses(new Request("http://127.0.0.1/v1/responses", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "vendor/model",
        stream: false,
        store: false,
        input: [agentMessage(`/root/${taskName}`, messageType)],
      }),
    }), routedBridgeConfig(), {} as never);

    try {
      // MESSAGE skips the earlier NEW_TASK record; NEW_TASK records then remain FIFO.
      expect((await send("MESSAGE")).status).toBe(200);
      expect((await send("NEW_TASK")).status).toBe(200);
      expect((await send("NEW_TASK")).status).toBe(200);
      expect(seenBodies).toHaveLength(3);
      expect(seenBodies[0]).toContain(staged.message);
      expect(seenBodies[0]).not.toContain(staged.spawn);
      expect(seenBodies[1]).toContain(staged.spawn);
      expect(seenBodies[1]).not.toContain(staged.followup);
      expect(seenBodies[2]).toContain(staged.followup);

      const consumed = await send("MESSAGE");
      const consumedText = await consumed.text();
      expect(consumed.status).toBe(409);
      expect(consumedText).toContain("subagent_handoff_missing");
      expect(consumedText).not.toContain(REAL_FERNET);
      for (const nonce of Object.values(staged)) expect(consumedText).not.toContain(nonce);
      expect(seenBodies).toHaveLength(3);
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
    }
  });

  test("recovers only the newest encrypted agent_message, not ciphertext in child history", () => {
    const token = "gAAAAABnX6DqvQfLy4CIvIQp9x1G7m2JXjvXgWIBu8VG6OKoyHDyEwE6Q9H9YfdwWlQF-Qj3Hb_RkPBMFa9_k54XfOpfK0S7Ng==";
    const agentMessage = (recipient: string) => ({ type: "agent_message", recipient, content: [
      { type: "input_text", text: `Message Type: MESSAGE\nTask name: ${recipient}\nSender: /root\nPayload:\n` },
      { type: "encrypted_content", encrypted_content: token },
    ] });
    const body = { model: "vendor/model", input: [agentMessage("/root/historical_000000000001"), agentMessage("/root/current_000000000002")] };
    const store = new SubagentHandoffStore();
    store.stageMessage({ kind: "message", target: "/root/current_000000000002", message: "new payload" });

    expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store }))
      .toEqual({ status: "recovered", count: 1 });
    expect(body.input[0].content[1].encrypted_content).toBe(token);
    expect(body.input[1].content[1]).toEqual({ type: "input_text", text: "new payload" });
  });

  test("historical ciphertext followed by newer non-agent input stays unchanged and unconsumed", () => {
    const body = {
      model: "vendor/model",
      input: [agentMessage("/root/historical_000000000001"), { type: "message", role: "user", content: [{ type: "input_text", text: "continue normally" }] }],
    };
    const store = new SubagentHandoffStore();
    store.stageMessage({ kind: "message", target: "/root/historical_000000000001", message: "must stay staged" });

    expect(recoverSelectedRoutedSubagentRequest(body, { enabled: true, selectedModels: ["vendor/model"], store }))
      .toEqual({ status: "unchanged" });
    expect(body.input[0].content[1].encrypted_content).toBe(REAL_FERNET);
    expect(store.consume("/root/historical_000000000001", "MESSAGE")?.message).toBe("must stay staged");
  });

  test("bridge-enabled ordinary requests do not clone unless a handoff candidate is present", async () => {
    const originalFetch = globalThis.fetch;
    const originalStructuredClone = globalThis.structuredClone;
    let cloneCalls = 0;
    globalThis.fetch = (async () => chatSuccess()) as typeof fetch;
    globalThis.structuredClone = ((value: unknown, options?: StructuredSerializeOptions) => {
      cloneCalls += 1;
      return originalStructuredClone(value, options);
    }) as typeof structuredClone;
    try {
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          model: "vendor/model",
          stream: false,
          store: false,
          input: "ordinary parent request",
        }),
      }), routedBridgeConfig(), {} as never);

      expect(response.status).toBe(200);
      expect(cloneCalls).toBe(0);
    } finally {
      globalThis.structuredClone = originalStructuredClone;
      globalThis.fetch = originalFetch;
    }
  });

  test("previous-response continuation does not consume a handoff from replayed history", async () => {
    const priorHome = process.env.OPENCODEX_HOME;
    const home = mkdtempSync(join(tmpdir(), "ocx-bridge-continuation-"));
    process.env.OPENCODEX_HOME = home;
    clearResponseStateForTests();
    const previous = { id: "resp_bridge_history", status: "completed", output: [{ type: "message", role: "assistant", content: [{ type: "output_text", text: "prior" }] }] };
    rememberResponseState({ model: "vendor/model", input: [agentMessage("/root/historical_000000000001")] }, previous);
    const storeMessage = "must remain queued";
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target: "/root/historical_000000000001", message: storeMessage });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => chatSuccess()) as typeof fetch;
    try {
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "vendor/model", previous_response_id: previous.id, stream: false, store: false, input: [{ type: "message", role: "user", content: [{ type: "input_text", text: "next" }] }] }),
      }), routedBridgeConfig(), {} as never);
      expect(response.status).toBe(200);
      expect(subagentHandoffStore.consume("/root/historical_000000000001", "MESSAGE")?.message).toBe(storeMessage);
    } finally {
      globalThis.fetch = originalFetch;
      clearResponseStateForTests();
      if (priorHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = priorHome;
      rmSync(home, { recursive: true, force: true });
      subagentHandoffStore.clear();
    }
  });

  test("explicit V1 mode bypasses recovery and leaves the staged handoff untouched", async () => {
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target: "/root/worker_000000000003", message: "v1 staged" });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => chatSuccess()) as typeof fetch;
    try {
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "vendor/model", stream: false, store: false, input: [agentMessage("/root/worker_000000000003")] }),
      }), routedBridgeConfig({ multiAgentMode: "v1" }), {} as never);
      expect(response.status).toBe(200);
      expect(subagentHandoffStore.consume("/root/worker_000000000003", "MESSAGE")?.message).toBe("v1 staged");
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
    }
  });

  test("recovered plaintext never reaches the response-state disk snapshot", async () => {
    const priorHome = process.env.OPENCODEX_HOME;
    const home = mkdtempSync(join(tmpdir(), "ocx-bridge-state-"));
    process.env.OPENCODEX_HOME = home;
    clearResponseStateForTests();
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target: "/root/worker_000000000003", message: "NEVER_PERSIST_THIS_HANDOFF" });
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => chatSuccess()) as typeof fetch;
    try {
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "vendor/model", stream: false, store: true, input: [agentMessage("/root/worker_000000000003")] }),
      }), routedBridgeConfig(), {} as never);
      expect(response.status).toBe(200);
      flushResponseState();
      const snapshotPath = join(home, "responses-state.json");
      expect(existsSync(snapshotPath)).toBe(true);
      const snapshot = readFileSync(snapshotPath, "utf8");
      expect(snapshot).not.toContain("NEVER_PERSIST_THIS_HANDOFF");
      expect(snapshot).toContain(REAL_FERNET);
    } finally {
      globalThis.fetch = originalFetch;
      clearResponseStateForTests();
      if (priorHome === undefined) delete process.env.OPENCODEX_HOME;
      else process.env.OPENCODEX_HOME = priorHome;
      rmSync(home, { recursive: true, force: true });
      subagentHandoffStore.clear();
    }
  });

  test("selected routed combo recovers before dispatch and consumes exactly once", async () => {
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target: "/root/worker_000000000003", message: "combo plaintext" });
    const seenBodies: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, init) => {
      seenBodies.push(String(init?.body ?? ""));
      return chatSuccess();
    }) as typeof fetch;
    try {
      const config = routedBridgeConfig({
        subagentModels: ["combo/free"],
        combos: { free: { strategy: "failover", targets: [{ provider: "vendor", model: "model" }] } },
      });
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "combo/free", stream: false, store: false, input: [agentMessage("/root/worker_000000000003")] }),
      }), config, {} as never);
      expect(response.status).toBe(200);
      expect(seenBodies.join("\n")).toContain("combo plaintext");
      expect(subagentHandoffStore.consume("/root/worker_000000000003", "MESSAGE")).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
    }
  });

  test("an unselected combo never lets its selected member consume at an inner attempt", async () => {
    const target = "/root/outer_only_000000000001";
    const plaintext = "OUTER_BOUNDARY_ONLY_61d8b4";
    subagentHandoffStore.clear();
    subagentHandoffStore.stageMessage({ kind: "message", target, message: plaintext });
    const seenBodies: string[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input, init) => {
      seenBodies.push(String(init?.body ?? ""));
      return chatSuccess();
    }) as typeof fetch;
    try {
      const config = routedBridgeConfig({
        subagentModels: ["vendor/model"],
        combos: { free: { strategy: "failover", targets: [{ provider: "vendor", model: "model" }] } },
      });
      const response = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "combo/free", stream: false, store: false, input: [agentMessage(target)] }),
      }), config, {} as never);

      expect(response.status).toBe(200);
      expect(seenBodies.join("\n")).not.toContain(plaintext);
      expect(subagentHandoffStore.consume(target, "MESSAGE")?.message).toBe(plaintext);
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
    }
  });

  test("recovered upstream 4xx and 5xx failures are generic and content-free in response and request logs", async () => {
    const originalFetch = globalThis.fetch;
    clearRequestLogsForTests();
    try {
      for (const [index, status] of [400, 503].entries()) {
        const target = `/root/privacy_${(index + 1).toString(16).padStart(12, "0")}`;
        const plaintext = `SENSITIVE_HANDOFF_${status}_c7a9e2`;
        subagentHandoffStore.clear();
        subagentHandoffStore.stageMessage({ kind: "message", target, message: plaintext });
        globalThis.fetch = (async () => Response.json({
          error: { message: `provider echoed ${plaintext} and ${REAL_FERNET}` },
        }, { status })) as typeof fetch;
        const logCtx: RequestLogContext = { model: "", provider: "" };
        const started = Date.now();
        const raw = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
          method: "POST", headers: { "content-type": "application/json" },
          body: JSON.stringify({ model: "vendor/model", stream: false, store: false, input: [agentMessage(target)] }),
        }), routedBridgeConfig(), logCtx);
        const response = responseWithDeferredRequestLog(raw, `sensitive-${status}`, started, logCtx);
        const responseText = await response.text();
        const logText = JSON.stringify(getRequestLogEntries().at(-1));

        expect(response.status).toBe(status);
        expect((JSON.parse(responseText) as { error: { message: string; code: string } }).error)
          .toMatchObject({ message: `Provider error ${status}` });
        expect(responseText).not.toContain(plaintext);
        expect(responseText).not.toContain(REAL_FERNET);
        expect(logText).not.toContain(plaintext);
        expect(logText).not.toContain(REAL_FERNET);
      }

      const ordinaryDetail = "ordinary provider detail remains visible";
      globalThis.fetch = (async () => Response.json({ error: { message: ordinaryDetail } }, { status: 503 })) as typeof fetch;
      const ordinary = await handleResponses(new Request("http://127.0.0.1/v1/responses", {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "vendor/model", stream: false, store: false, input: "ordinary request" }),
      }), routedBridgeConfig(), { model: "", provider: "" });
      expect(await ordinary.text()).toContain(ordinaryDetail);
    } finally {
      globalThis.fetch = originalFetch;
      subagentHandoffStore.clear();
      clearRequestLogsForTests();
    }
  });

  test("v2 surface + injectionModel + injectionEffort names both", async () => {
    codexHomeFixture(V2_ON);
    const text = await multiAgentGuidanceText(
      parsedFixture({ tools: [{ name: "spawn_agent" }] }),
      "opencode-go/glm-5.2",
      "xhigh",
    );
    expect(text).toContain('Preferred sub-agent: model "opencode-go/glm-5.2", reasoning_effort "xhigh"');
  });

  test("injectionPrompt override replaces the v2 body with placeholder substitution", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [{ slug: "gpt-5.6-terra", efforts: ["high", "max"] }]);
    const custom = "CUSTOM RULES model={{model}} effort={{effort}}{{roster}}";
    const v2 = await multiAgentGuidanceText(
      parsedFixture({ tools: [{ name: "spawn_agent" }] }),
      "gpt-5.6-terra", "max", ["gpt-5.6-terra"], custom,
    );
    expect(v2).toBe("<multi_agent_mode>CUSTOM RULES model=gpt-5.6-terra effort=max"
      + " Available models (reasoning_effort high/max): \"gpt-5.6-terra\".</multi_agent_mode>");
    const v1 = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "max", tools: [{ name: "spawn_agent", namespace: "multi_agent_v1" }, { name: "send_input", namespace: "multi_agent_v1" }] }),
      undefined, undefined, undefined, "V1 BODY {{model}}|{{effort}}|{{roster}}",
    );
    // v1 ignores injectionPrompt entirely — it only mirrors the upstream Proactive text
    expect(v1).toContain("Proactive multi-agent delegation is active");
    expect(v1).not.toContain("V1 BODY");
    // gates unchanged: custom prompt does NOT make a bare v2 surface fire
    expect(await multiAgentGuidanceText(parsedFixture({ tools: [{ name: "spawn_agent" }] }), undefined, undefined, undefined, custom)).toBeNull();
  });

  test("v2 surface without injectionModel AND without roster stays silent at every effort", async () => {
    codexHomeFixture(V2_ON);
    const v2Tools = [{ name: "spawn_agent" }];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "ultra", tools: v2Tools }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: v2Tools }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "medium", tools: v2Tools }))).toBeNull();
  });

  test("v2 surface + roster alone (no injectionModel) fires with the argument-acceptance preamble", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [{ slug: "gpt-5.6-terra", efforts: ["high", "max", "ultra"] }]);
    const text = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "medium", tools: [{ name: "spawn_agent" }] }),
      undefined, undefined, ["gpt-5.6-terra"],
    );
    expect(text).toContain("never claim sub-agent models cannot be selected");
    expect(text).toContain('(reasoning_effort high/max/ultra): "gpt-5.6-terra"');
    expect(text).not.toContain("Preferred sub-agent");
  });

  test("ambiguous mixed surface (both spawn shapes) stays silent even with injectionModel", async () => {
    codexHomeFixture(V2_ON);
    const mixed = [{ name: "spawn_agent" }, { name: "spawn_agent", namespace: "agents" }];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: mixed }), "anthropic/claude-sonnet-5")).toBeNull();
    // contradictory companions (v1 send_input + v2 send_message) also veto
    const contradictory = [
      { name: "spawn_agent", namespace: "collaboration" },
      { name: "send_input", namespace: "collaboration" },
      { name: "send_message", namespace: "collaboration" },
    ];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: contradictory }), "anthropic/claude-sonnet-5")).toBeNull();
  });

  test("v2 flag off still fires guidance (ultra is always-on)", async () => {
    codexHomeFixture(V2_OFF);
    const text = await multiAgentGuidanceText(parsedFixture({
      reasoning: "max",
      tools: [{ name: "spawn_agent", namespace: "agents" }],
    }));
    expect(text).toContain("<multi_agent_mode>");
  });

  test("v1 at max carries ONLY the Proactive text — no designation payload", async () => {
    codexHomeFixture(V2_OFF);
    const text = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "max", tools: [{ name: "spawn_agent", namespace: "agents" }] }),
      "anthropic/claude-sonnet-5", "xhigh", ["anthropic/claude-sonnet-5"],
    );
    expect(text).toContain("Proactive multi-agent delegation is active");
    expect(text).not.toContain("anthropic/claude-sonnet-5");
    expect(text).not.toContain("Preferred sub-agent");
    expect(text).not.toContain("Available models");
  });

  test("v1 injectionModel does NOT relax the top-tier gate", async () => {
    codexHomeFixture(V2_OFF);
    const v1Tools = [{ name: "spawn_agent", namespace: "agents" }];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "high", tools: v1Tools }), "opencode-go/glm-5.2")).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ tools: v1Tools }), "anthropic/claude-opus-4-6")).toBeNull();
  });

  test("without injectionModel, low effort stays silent", async () => {
    codexHomeFixture(V2_OFF);
    const v1Tools = [{ name: "spawn_agent", namespace: "agents" }];
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "high", tools: v1Tools }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "medium", tools: v1Tools }))).toBeNull();
    expect(await multiAgentGuidanceText(parsedFixture({ reasoning: "max", tools: v1Tools }))).not.toBeNull();
  });

  test("v2 body stays within the 700-char budget with a full 5-model roster", async () => {
    const dir = codexHomeFixture(V2_ON);
    catalogFixture(dir, [
      { slug: "gpt-5.5", efforts: ["low", "medium", "high", "xhigh", "max", "ultra"] },
      { slug: "opencode-go/glm-5.2", efforts: ["low", "medium", "high", "xhigh", "max", "ultra"] },
      { slug: "anthropic/claude-opus-4-6", efforts: ["low", "medium", "high", "xhigh", "max", "ultra"] },
      { slug: "gpt-5.6-sol", efforts: ["low", "medium", "high", "xhigh", "max", "ultra"] },
      { slug: "gpt-5.6-terra", efforts: ["low", "medium", "high", "xhigh", "max", "ultra"] },
    ]);
    const text = await multiAgentGuidanceText(
      parsedFixture({ reasoning: "high", tools: [{ name: "spawn_agent" }] }),
      "gpt-5.6-sol", "xhigh",
      ["gpt-5.5", "opencode-go/glm-5.2", "anthropic/claude-opus-4-6", "gpt-5.6-sol", "gpt-5.6-terra"],
    );
    const body = text!.replace(/^<multi_agent_mode>/, "").replace(/<\/multi_agent_mode>$/, "");
    expect(body.length).toBeLessThanOrEqual(700);
    expect(body).toContain("Available models"); // roster fits inside the budget
  });
});

describe("injectDeveloperMessage", () => {
  test("appends to both the parsed messages and the raw passthrough input", () => {
    const parsed = parsedFixture({ reasoning: "max" });
    injectDeveloperMessage(parsed, "hello there");
    const last = parsed.context.messages.at(-1)!;
    expect(last.role).toBe("developer");
    expect(last.content).toBe("hello there");
    const rawInput = (parsed._rawBody as { input: unknown[] }).input;
    expect(rawInput.at(-1)).toEqual({
      type: "message",
      role: "developer",
      content: [{ type: "input_text", text: "hello there" }],
    });
  });

  test("string raw input is left alone", () => {
    const parsed = parsedFixture({ reasoning: "max", rawInput: "plain" });
    injectDeveloperMessage(parsed, "note");
    expect((parsed._rawBody as { input: unknown }).input).toBe("plain");
    expect(parsed.context.messages.at(-1)!.content).toBe("note");
  });

  test("inserts BEFORE compaction_trigger so it stays the final input item", () => {
    const parsed = parsedFixture({ reasoning: "max" });
    const rawBody = parsed._rawBody as { input: unknown[] };
    rawBody.input = [
      { type: "message", role: "user", content: "long conversation" },
      { type: "compaction_trigger" },
    ];
    injectDeveloperMessage(parsed, "guidance text");
    const input = rawBody.input;
    expect(input).toHaveLength(3);
    expect((input[1] as { type: string }).type).toBe("message");
    expect((input[1] as { role: string }).role).toBe("developer");
    expect((input[2] as { type: string }).type).toBe("compaction_trigger");
  });
});

describe("sanitizeEncryptedContentInPlace", () => {
  test("plaintext parked in encrypted slots becomes input_text; real blobs survive", () => {
    const blob = "gAAAAAB".padEnd(120, "Qw1_-=");
    const input = [
      { type: "message", role: "user", content: [
        { type: "encrypted_content", encrypted_content: "[CXC-LEAF-GUARD] plain text with spaces" },
        { type: "input_text", text: "untouched" },
      ] },
      { type: "function_call_output", call_id: "c1", output: { content: [
        { type: "encrypted_content", encrypted_content: blob },
        { type: "encrypted_content", encrypted_content: "short" },
      ] } },
    ];
    const rewritten = sanitizeEncryptedContentInPlace(input);
    expect(rewritten).toBe(2);
    const msgParts = (input[0] as { content: Array<Record<string, unknown>> }).content;
    expect(msgParts[0]).toEqual({ type: "input_text", text: "[CXC-LEAF-GUARD] plain text with spaces" });
    expect(msgParts[1]).toEqual({ type: "input_text", text: "untouched" });
    const outParts = ((input[1] as { output: { content: Array<Record<string, unknown>> } }).output).content;
    expect(outParts[0]).toEqual({ type: "encrypted_content", encrypted_content: blob });
    expect(outParts[1]).toEqual({ type: "input_text", text: "short" });
  });

  test("non-array input is a no-op", () => {
    expect(sanitizeEncryptedContentInPlace("plain")).toBe(0);
    expect(sanitizeEncryptedContentInPlace(undefined)).toBe(0);
  });

  test("mixed slot (hook preamble + embedded Fernet task) splits into text + encrypted parts", () => {
    const fernet = "gAAAA" + "Ab1_-".repeat(20) + "==";
    const input = [
      { type: "message", role: "user", content: [
        { type: "encrypted_content", encrypted_content: `[CXC-LEAF-GUARD] follow the rules.\n\n${fernet}` },
      ] },
    ];
    expect(sanitizeEncryptedContentInPlace(input)).toBe(1);
    const parts = (input[0] as { content: Array<Record<string, unknown>> }).content;
    expect(parts).toHaveLength(2);
    expect(parts[0]).toEqual({ type: "input_text", text: "[CXC-LEAF-GUARD] follow the rules.\n\n" });
    expect(parts[1]).toEqual({ type: "encrypted_content", encrypted_content: fernet });
  });

  test("pure Fernet slot stays byte-identical", () => {
    const fernet = "gAAAA" + "Ab1_-".repeat(20) + "==";
    const input = [
      { type: "message", role: "user", content: [
        { type: "encrypted_content", encrypted_content: fernet },
      ] },
    ];
    expect(sanitizeEncryptedContentInPlace(input)).toBe(0);
    const parts = (input[0] as { content: Array<Record<string, unknown>> }).content;
    expect(parts[0]).toEqual({ type: "encrypted_content", encrypted_content: fernet });
  });
});

describe("spawn-message delivery (agent_message + encrypted slot)", () => {
  test("sanitize-then-parse delivers the spawn task payload as a user message on routed paths", () => {
    // Mirrors handleResponses order: sanitize and normalize the RAW input, then parseRequest.
    // Regression for spawned sub-agents receiving empty task payloads when the routed parser
    // does not understand agent_message and its task rides in a plaintext encrypted slot.
    const body = {
      model: "anthropic/claude-fable-5",
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "env context" }] },
        { type: "agent_message", author: "/root", recipient: "/root/worker", content: [
          { type: "input_text", text: "Message Type: NEW_TASK\nTask name: /root/worker\nSender: /root\nPayload:\n" },
          { type: "encrypted_content", encrypted_content: "TASK: build the thing exactly as specified." },
        ] },
      ],
    };
    expect(sanitizeEncryptedContentInPlace(body.input)).toBe(1);
    expect(body.input[1]).toMatchObject({ type: "message", role: "user" });
    const parsed = parseRequest(body);
    const users = parsed.context.messages.filter(m => m.role === "user");
    expect(users).toHaveLength(2);
    const content = users[1].content;
    const flat = typeof content === "string"
      ? content
      : (content as Array<{ type: string; text?: string }>).map(p => p.text ?? "").join("");
    expect(flat).toContain("Message Type: NEW_TASK");
    expect(flat).toContain("TASK: build the thing exactly as specified.");
  });
});
