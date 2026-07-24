import { afterEach, describe, expect, test } from "bun:test";
import { decodeReasoningEnvelope } from "../src/responses/reasoning-envelope";
import { handleResponses } from "../src/server/responses";
import type { OcxConfig } from "../src/types";

const servers: Array<ReturnType<typeof Bun.serve>> = [];

afterEach(async () => {
  for (const server of servers.splice(0)) await server.stop(true);
});

function upstream() {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      const body = await request.json() as { stream?: boolean };
      if (body.stream) {
        const sse = [
          'data: {"choices":[{"delta":{"reasoning_content":"live plan"}}]}',
          "",
          'data: {"choices":[{"delta":{"content":"final answer"},"finish_reason":"stop"}]}',
          "",
          "data: [DONE]",
          "",
        ].join("\n");
        return new Response(sse, { headers: { "content-type": "text/event-stream" } });
      }
      return Response.json({
        choices: [{ message: { reasoning_content: "batch plan", content: "batch answer" }, finish_reason: "stop" }],
        usage: { prompt_tokens: 2, completion_tokens: 3, total_tokens: 5 },
      });
    },
  });
  servers.push(server);
  return server;
}

function config(server: ReturnType<typeof Bun.serve>, showRawReasoning: boolean): OcxConfig {
  return {
    port: 0,
    defaultProvider: "raw",
    providers: {
      raw: {
        adapter: "openai-chat",
        baseUrl: `${server.url.toString().replace(/\/$/, "")}/v1`,
        allowPrivateNetwork: true,
        apiKey: "test-key",
        models: ["k3[1m]"],
        preserveReasoningContentModels: ["k3[1m]"],
        showRawReasoning,
      },
    },
  };
}

function request(stream: boolean, summary?: "auto" | "none"): Request {
  return new Request("http://localhost/v1/responses", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: "raw/k3[1m]",
      input: "hello",
      stream,
      ...(summary ? { reasoning: { summary } } : {}),
    }),
  });
}

async function sseFrames(response: Response): Promise<Array<{ event?: string; data: Record<string, unknown> }>> {
  return (await response.text()).split("\n\n").flatMap(block => {
    const lines = block.trim().split("\n");
    const data = lines.find(line => line.startsWith("data: "))?.slice(6);
    if (!data || data === "[DONE]") return [];
    return [{
      event: lines.find(line => line.startsWith("event: "))?.slice(7),
      data: JSON.parse(data) as Record<string, unknown>,
    }];
  });
}

describe("HTTP Responses raw reasoning promotion", () => {
  test("normal streaming HTTP promotes opted-in reasoning and keeps the answer separate", async () => {
    const server = upstream();
    const response = await handleResponses(request(true, "auto"), config(server, true), { model: "", provider: "" });
    const frames = await sseFrames(response);

    expect(response.status).toBe(200);
    expect(frames.some(frame => frame.event === "response.reasoning_summary_text.delta"
      && frame.data.delta === "live plan")).toBe(true);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);
    expect(frames.some(frame => frame.event === "response.output_text.delta"
      && frame.data.delta === "final answer")).toBe(true);
  });

  test("provider opt-in still promotes when reasoning.summary is omitted", async () => {
    const server = upstream();
    const response = await handleResponses(request(true), config(server, true), { model: "", provider: "" });
    const frames = await sseFrames(response);

    expect(frames.some(frame => frame.event === "response.reasoning_summary_text.delta"
      && frame.data.delta === "live plan")).toBe(true);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);
  });

  test("provider opt-out keeps raw reasoning hidden even when summary:auto is requested", async () => {
    const server = upstream();
    const response = await handleResponses(request(true, "auto"), config(server, false), { model: "", provider: "" });
    const frames = await sseFrames(response);

    expect(frames.some(frame => frame.event === "response.reasoning_summary_text.delta")).toBe(false);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);
    const completed = frames.find(frame => frame.event === "response.completed")?.data.response as Record<string, unknown>;
    const reasoning = (completed.output as Record<string, unknown>[]).find(item => item.type === "reasoning")!;
    expect(decodeReasoningEnvelope(reasoning.encrypted_content as string)?.txt).toBe("live plan");
  });

  test("explicit summary:none overrides provider opt-in and retains hidden replay text", async () => {
    const server = upstream();
    const response = await handleResponses(request(true, "none"), config(server, true), { model: "", provider: "" });
    const frames = await sseFrames(response);

    expect(frames.some(frame => frame.event === "response.reasoning_summary_text.delta")).toBe(false);
    expect(frames.some(frame => frame.event === "response.reasoning_text.delta")).toBe(false);
    const completed = frames.find(frame => frame.event === "response.completed")?.data.response as Record<string, unknown>;
    const reasoning = (completed.output as Record<string, unknown>[]).find(item => item.type === "reasoning")!;
    expect(decodeReasoningEnvelope(reasoning.encrypted_content as string)?.txt).toBe("live plan");
  });

  test("non-streaming HTTP returns promoted reasoning as summary_text", async () => {
    const server = upstream();
    const response = await handleResponses(request(false, "auto"), config(server, true), { model: "", provider: "" });
    const body = await response.json() as { output: Record<string, unknown>[] };

    expect(response.status).toBe(200);
    expect(body.output.map(item => item.type)).toEqual(["reasoning", "message"]);
    expect(body.output[0]).toMatchObject({ summary: [{ type: "summary_text", text: "batch plan" }] });
    expect(body.output[1]).toMatchObject({ content: [{ type: "output_text", text: "batch answer" }] });
  });
});
