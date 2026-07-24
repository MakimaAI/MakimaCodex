import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { OpenAiCompatibleModelProvider } from "../src/oef/phase4";

let server: ReturnType<typeof Bun.serve>;
let baseUrl = "";
const seenBodies: unknown[] = [];

beforeAll(() => {
  server = Bun.serve({
    port: 0,
    async fetch(request) {
      if (request.headers.get("authorization") !== "Bearer phase4-contract-token") return Response.json({ error: "unauthorized" }, { status: 401 });
      const url = new URL(request.url);
      if (url.pathname === "/v1/models") return Response.json({ object: "list", data: [{ id: "atlas-2026-07", object: "model", created: 1, owned_by: "acme" }] });
      if (url.pathname === "/v1/chat/completions") {
        const body = await request.json() as Record<string, unknown>; seenBodies.push(body);
        if (Array.isArray(body.tools)) return Response.json({ choices: [{ message: { content: null, tool_calls: [{ function: { name: "phase4_probe", arguments: "{\"ok\":true}" } }] } }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
        const content = body.response_format ? "{\"ok\":true}" : "{\"answer\":\"ok\",\"complete\":true,\"contract\":true}";
        return Response.json({ choices: [{ message: { content } }], usage: { prompt_tokens: 10, completion_tokens: 5 } });
      }
      return new Response("not found", { status: 404 });
    },
  });
  baseUrl = `http://127.0.0.1:${server.port}/v1`;
});
afterAll(() => server.stop(true));

describe("Phase 4 OpenAI-compatible provider contract", () => {
  test("discovers real HTTP catalog metadata and probes structured output and tool calling without persisting credentials", async () => {
    const adapter = new OpenAiCompatibleModelProvider({
      providerId: "provider:contract-acme", baseUrl, selectedModel: "atlas-2026-07",
      secretRef: { type: "environment", name: "PHASE4_CONTRACT_TOKEN" },
      environment: { PHASE4_CONTRACT_TOKEN: "phase4-contract-token" },
      now: () => "2026-07-24T08:00:00.000Z", probeAttempts: 2,
    });
    const snapshot = await adapter.discoverModels();
    expect(snapshot.models).toHaveLength(1);
    expect(snapshot.models[0]?.provider_model_name).toBe("atlas-2026-07");
    expect(JSON.stringify(snapshot)).not.toContain("phase4-contract-token");
    const config = adapter.executionConfiguration("execution-config:contract-acme");
    const probes = await adapter.probe(config);
    expect(probes.find(value => value.capability === "structured-output")?.status).toBe("passed");
    expect(probes.find(value => value.capability === "tool-calling")?.status).toBe("passed");
    expect(seenBodies.some(value => JSON.stringify(value).includes("hidden_assertions"))).toBeFalse();
  });
});
