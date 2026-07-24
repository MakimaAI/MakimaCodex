import { describe, expect, test } from "bun:test";
import { createOpenAIChatAdapter } from "../src/adapters/openai-chat";
import { bridgeToResponsesSSE, buildResponseJSON } from "../src/bridge";
import { decodeReasoningEnvelope } from "../src/responses/reasoning-envelope";
import { parseRequest } from "../src/responses/parser";
import type { AdapterEvent } from "../src/types";

async function* replay(events: AdapterEvent[]): AsyncGenerator<AdapterEvent> {
  for (const event of events) yield event;
}

async function collectEvents(events: AsyncIterable<AdapterEvent>): Promise<AdapterEvent[]> {
  const collected: AdapterEvent[] = [];
  for await (const event of events) collected.push(event);
  return collected;
}

async function collectSse(stream: ReadableStream<Uint8Array>): Promise<Array<{ event?: string; data: Record<string, unknown> }>> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    text += decoder.decode(value, { stream: true });
  }
  return text.split("\n\n")
    .map(frame => frame.trim())
    .filter(frame => frame.length > 0 && frame !== "data: [DONE]")
    .map(frame => {
      const lines = frame.split("\n");
      const event = lines.find(line => line.startsWith("event: "))?.slice(7);
      const data = lines.find(line => line.startsWith("data: "))?.slice(6) ?? "{}";
      return { event, data: JSON.parse(data) as Record<string, unknown> };
    });
}

function openAiChatAdapter() {
  return createOpenAIChatAdapter({
    adapter: "openai-chat",
    baseUrl: "https://api.kimi.com/coding/v1",
    apiKey: "test-key",
    preserveReasoningContentModels: ["k3[1m]"],
  });
}

describe("openai-chat raw reasoning separation", () => {
  test("streaming reasoning_content remains a reasoning_raw_delta", async () => {
    const response = new Response([
      'data: {"choices":[{"delta":{"reasoning_content":"plan","content":"answer"},"finish_reason":"stop"}]}',
      "",
      "data: [DONE]",
      "",
    ].join("\n"), { headers: { "content-type": "text/event-stream" } });

    const events = await collectEvents(openAiChatAdapter().parseStream(response));
    expect(events.map(event => event.type)).toEqual(["reasoning_raw_delta", "text_delta", "done"]);
    expect(events[0]).toEqual({ type: "reasoning_raw_delta", text: "plan" });
  });

  test("non-streaming reasoning is emitted before final assistant text", async () => {
    const events = await openAiChatAdapter().parseResponse(new Response(JSON.stringify({
      choices: [{ message: { reasoning_content: "plan", content: "answer" }, finish_reason: "stop" }],
    })));

    expect(events.map(event => event.type)).toEqual(["reasoning_raw_delta", "text_delta", "done"]);
  });
});

describe("raw reasoning promotion to native summary", () => {
  test("streaming emits the native summary lifecycle and closes it before text", async () => {
    const frames = await collectSse(bridgeToResponsesSSE(replay([
      { type: "reasoning_raw_delta", text: "plan " },
      { type: "reasoning_raw_delta", text: "steps" },
      { type: "text_delta", text: "answer" },
      { type: "done" },
    ]), "kimi/k3[1m]", undefined, undefined, undefined, undefined, undefined, {
      promoteRawReasoningToSummary: true,
    }));

    expect(frames.filter(frame => frame.event === "response.reasoning_summary_text.delta").map(frame => frame.data.delta))
      .toEqual(["plan ", "steps"]);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);

    const reasoningDone = frames.findIndex(frame => frame.event === "response.output_item.done"
      && (frame.data.item as Record<string, unknown>)?.type === "reasoning");
    const messageAdded = frames.findIndex(frame => frame.event === "response.output_item.added"
      && (frame.data.item as Record<string, unknown>)?.type === "message");
    expect(reasoningDone).toBeGreaterThan(-1);
    expect(reasoningDone).toBeLessThan(messageAdded);

    const completed = frames.find(frame => frame.event === "response.completed")?.data.response as Record<string, unknown>;
    expect(completed.output).toMatchObject([
      { type: "reasoning", summary: [{ type: "summary_text", text: "plan steps" }] },
      { type: "message", content: [{ type: "output_text", text: "answer" }] },
    ]);
  });

  test("streaming closes promoted reasoning before a tool call", async () => {
    const frames = await collectSse(bridgeToResponsesSSE(replay([
      { type: "reasoning_raw_delta", text: "inspect" },
      { type: "tool_call_start", id: "call_1", name: "read_file" },
      { type: "tool_call_delta", arguments: '{"path":"README.md"}' },
      { type: "tool_call_end", id: "call_1" },
      { type: "done" },
    ]), "kimi/k3[1m]", undefined, undefined, undefined, undefined, undefined, {
      promoteRawReasoningToSummary: true,
    }));

    const doneItems = frames.filter(frame => frame.event === "response.output_item.done")
      .map(frame => frame.data.item as Record<string, unknown>);
    expect(doneItems.map(item => item.type)).toEqual(["reasoning", "function_call"]);
    expect(doneItems[0].summary).toEqual([{ type: "summary_text", text: "inspect" }]);
  });

  test("a thrown upstream error finalizes promoted reasoning before response.failed", async () => {
    async function* throwing(): AsyncGenerator<AdapterEvent> {
      yield { type: "reasoning_raw_delta", text: "partial plan" };
      throw new Error("upstream exploded");
    }

    const frames = await collectSse(bridgeToResponsesSSE(throwing(), "kimi/k3[1m]", undefined, undefined, undefined, undefined, undefined, {
      promoteRawReasoningToSummary: true,
    }));
    const summaryDone = frames.findIndex(frame => frame.event === "response.reasoning_summary_text.done");
    const failed = frames.findIndex(frame => frame.event === "response.failed");
    expect(summaryDone).toBeGreaterThan(-1);
    expect(summaryDone).toBeLessThan(failed);
  });

  test("non-streaming returns raw reasoning only as summary_text", () => {
    const response = buildResponseJSON([
      { type: "reasoning_raw_delta", text: "private plan" },
      { type: "text_delta", text: "public answer" },
      { type: "done" },
    ], "kimi/k3[1m]", { promoteRawReasoningToSummary: true });

    expect(response.output).toMatchObject([
      { type: "reasoning", summary: [{ type: "summary_text", text: "private plan" }] },
      { type: "message", content: [{ type: "output_text", text: "public answer" }] },
    ]);
    expect(JSON.stringify(response.output)).not.toContain("reasoning_text");
  });

  test("an explicit summary:none override keeps the encrypted replay envelope hidden", async () => {
    const frames = await collectSse(bridgeToResponsesSSE(replay([
      { type: "reasoning_raw_delta", text: "do not display" },
      { type: "done" },
    ]), "kimi/k3[1m]", undefined, undefined, undefined, undefined, undefined, {
      hideThinkingSummary: true,
      hideRawReasoningSummary: true,
      promoteRawReasoningToSummary: true,
    }));

    expect(frames.some(frame => frame.event === "response.reasoning_summary_text.delta")).toBe(false);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);
    const completed = frames.find(frame => frame.event === "response.completed")?.data.response as Record<string, unknown>;
    const reasoning = (completed.output as Record<string, unknown>[]).find(item => item.type === "reasoning")!;
    expect(decodeReasoningEnvelope(reasoning.encrypted_content as string)?.txt).toBe("do not display");
  });

  test("hidden raw reasoning alternated with text keeps unique ordered output indexes", async () => {
    const frames = await collectSse(bridgeToResponsesSSE(replay([
      { type: "reasoning_raw_delta", text: "first plan" },
      { type: "text_delta", text: "first answer" },
      { type: "reasoning_raw_delta", text: "second plan" },
      { type: "text_delta", text: "second answer" },
      { type: "done" },
    ]), "routed/model", undefined, undefined, undefined, undefined, undefined, {
      hideThinkingSummary: true,
      hideRawReasoningSummary: true,
    }));

    const doneFrames = frames.filter(frame => frame.event === "response.output_item.done");
    expect(doneFrames.map(frame => frame.data.output_index)).toEqual([0, 1, 2, 3]);
    expect(doneFrames.map(frame => (frame.data.item as Record<string, unknown>).type))
      .toEqual(["reasoning", "message", "reasoning", "message"]);
    const completed = frames.find(frame => frame.event === "response.completed")?.data.response as Record<string, unknown>;
    expect((completed.output as Record<string, unknown>[]).map(item => item.type))
      .toEqual(["reasoning", "message", "reasoning", "message"]);
  });

  test("hidden raw reasoning closes an active tool before allocating its own item", async () => {
    const frames = await collectSse(bridgeToResponsesSSE(replay([
      { type: "reasoning_raw_delta", text: "before tool" },
      { type: "tool_call_start", id: "call_1", name: "read_file" },
      { type: "tool_call_delta", arguments: "{}" },
      { type: "reasoning_raw_delta", text: "after tool" },
      { type: "text_delta", text: "answer" },
      { type: "done" },
    ]), "routed/model", undefined, undefined, undefined, undefined, undefined, {
      hideThinkingSummary: true,
      hideRawReasoningSummary: true,
    }));

    const doneFrames = frames.filter(frame => frame.event === "response.output_item.done");
    expect(doneFrames.map(frame => frame.data.output_index)).toEqual([0, 1, 2, 3]);
    expect(doneFrames.map(frame => (frame.data.item as Record<string, unknown>).type))
      .toEqual(["reasoning", "function_call", "reasoning", "message"]);
  });

  test("visible summary replays as assistant.reasoning_content across a tool continuation", () => {
    const first = buildResponseJSON([
      { type: "reasoning_raw_delta", text: "replay this plan" },
      { type: "tool_call_start", id: "call_1", name: "read_file" },
      { type: "tool_call_delta", arguments: '{"path":"README.md"}' },
      { type: "tool_call_end", id: "call_1" },
      { type: "done" },
    ], "kimi/k3[1m]", { promoteRawReasoningToSummary: true });
    const output = first.output as Record<string, unknown>[];
    expect(output[0]).toMatchObject({
      type: "reasoning",
      summary: [{ type: "summary_text", text: "replay this plan" }],
    });

    const parsed = parseRequest({
      model: "k3[1m]",
      stream: false,
      input: [
        { type: "message", role: "user", content: [{ type: "input_text", text: "inspect" }] },
        ...output,
        { type: "function_call_output", call_id: "call_1", output: "file contents" },
        { type: "message", role: "user", content: [{ type: "input_text", text: "continue" }] },
      ],
    });
    const body = JSON.parse(openAiChatAdapter().buildRequest(parsed).body) as { messages: Record<string, unknown>[] };
    const assistant = body.messages.find(message => message.role === "assistant" && message.reasoning_content !== undefined);
    expect(assistant).toMatchObject({
      reasoning_content: "replay this plan",
      tool_calls: [{ id: "call_1", function: { name: "read_file", arguments: '{"path":"README.md"}' } }],
    });
  });

  test("parser distinguishes an explicit summary:none from an omitted summary", () => {
    const omitted = parseRequest({ model: "k3[1m]", input: "hello" });
    const hidden = parseRequest({ model: "k3[1m]", input: "hello", reasoning: { summary: "none" } });
    expect(omitted.options.hideRawReasoningSummary).toBeUndefined();
    expect(hidden.options.hideRawReasoningSummary).toBe(true);
  });
});
