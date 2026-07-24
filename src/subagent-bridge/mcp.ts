import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { readSubagentBridgeToken, SubagentHandoffRequestSchema, type SubagentHandoffRequest } from "./http";
import {
  findLiveSubagentBridgeProxy,
  readBoundedSubagentBridgeResponse,
  SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
  type LiveSubagentBridgeProxy,
} from "./runtime";
import {
  createSubagentBridgeRandomValue,
  createSubagentBridgeRequestSignature,
  createSubagentBridgeResponseSignature,
  isSubagentBridgeRandomValue,
  sealSubagentBridgeRequestBody,
  SUBAGENT_BRIDGE_ISSUED_AT_HEADER,
  SUBAGENT_BRIDGE_INSTANCE_HEADER,
  SUBAGENT_BRIDGE_REQUEST_ID_HEADER,
  SUBAGENT_BRIDGE_RESPONSE_SIGNATURE_HEADER,
  SUBAGENT_BRIDGE_SIGNATURE_HEADER,
  SUBAGENT_BRIDGE_STAGING_PATH,
  subagentBridgeMacMatches,
} from "./auth";

export type PreparedSubagentHandoff =
  | { task_name: string; expires_in_seconds: 300 }
  | { target: string; expires_in_seconds: 300 };
export type PrepareSubagentHandoff = (input: SubagentHandoffRequest) => Promise<PreparedSubagentHandoff>;

export interface PrepareViaProxyDeps {
  findProxy?: () => Promise<LiveSubagentBridgeProxy | null>;
  readToken?: () => string | null;
  fetchFn?: typeof fetch;
  randomBytesFn?: (length: number) => Uint8Array;
  encryptionRandomBytesFn?: (length: number) => Uint8Array;
  now?: () => number;
}

export async function prepareViaProxy(
  input: SubagentHandoffRequest,
  deps: PrepareViaProxyDeps = {},
): Promise<PreparedSubagentHandoff> {
  const live = await (deps.findProxy ?? findLiveSubagentBridgeProxy)();
  if (!live || !isSubagentBridgeRandomValue(live.instanceId)) throw new Error("service unavailable");
  const token = (deps.readToken ?? readSubagentBridgeToken)();
  if (!token) throw new Error("service unavailable");
  let requestId: string;
  let issuedAtMs: number;
  let body: string;
  let signature: string | null;
  try {
    requestId = createSubagentBridgeRandomValue(deps.randomBytesFn);
    issuedAtMs = (deps.now ?? Date.now)();
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0) throw new Error("invalid time");
    const plaintext = JSON.stringify(input);
    const sealedBody = sealSubagentBridgeRequestBody({
      token,
      protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
      method: "POST",
      path: SUBAGENT_BRIDGE_STAGING_PATH,
      instanceId: live.instanceId,
      requestId,
      issuedAtMs,
      body: plaintext,
      randomBytesFn: deps.encryptionRandomBytesFn,
    });
    if (!sealedBody) throw new Error("request encryption failed");
    body = sealedBody;
    signature = createSubagentBridgeRequestSignature({
      token,
      protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
      method: "POST",
      path: SUBAGENT_BRIDGE_STAGING_PATH,
      instanceId: live.instanceId,
      requestId,
      issuedAtMs,
      body,
    });
  } catch {
    throw new Error("service unavailable");
  }
  if (!signature) throw new Error("service unavailable");
  let response: Response;
  try {
    response = await (deps.fetchFn ?? fetch)(`http://${live.hostname}:${live.port}${SUBAGENT_BRIDGE_STAGING_PATH}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [SUBAGENT_BRIDGE_INSTANCE_HEADER]: live.instanceId,
        [SUBAGENT_BRIDGE_REQUEST_ID_HEADER]: requestId,
        [SUBAGENT_BRIDGE_ISSUED_AT_HEADER]: String(issuedAtMs),
        [SUBAGENT_BRIDGE_SIGNATURE_HEADER]: signature,
      },
      body,
      signal: AbortSignal.timeout(3_000),
    });
  } catch {
    throw new Error("service unavailable");
  }
  if (!response.ok) {
    try { void response.body?.cancel().catch(() => undefined); } catch { /* best-effort transport cleanup */ }
    throw new Error("service unavailable");
  }
  const responseBytes = await readBoundedSubagentBridgeResponse(response);
  if (!responseBytes) throw new Error("service unavailable");
  const expectedResponseSignature = createSubagentBridgeResponseSignature({
    token,
    protocol: SUBAGENT_BRIDGE_HEALTH_PROTOCOL,
    instanceId: live.instanceId,
    requestId,
    status: response.status,
    body: responseBytes,
  });
  if (!subagentBridgeMacMatches(
    response.headers.get(SUBAGENT_BRIDGE_RESPONSE_SIGNATURE_HEADER),
    expectedResponseSignature,
  )) {
    throw new Error("service unavailable");
  }
  let result: Record<string, unknown>;
  try { result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(responseBytes)) as Record<string, unknown>; }
  catch { throw new Error("service unavailable"); }
  if (input.kind === "spawn"
    && typeof result.task_name === "string"
    && result.expires_in_seconds === 300) {
    return { task_name: result.task_name, expires_in_seconds: 300 };
  }
  if (input.kind !== "spawn"
    && typeof result.target === "string"
    && result.expires_in_seconds === 300) {
    return { target: result.target, expires_in_seconds: 300 };
  }
  throw new Error("service unavailable");
}

export function createSubagentBridgeMcpServer(
  deps: { prepare?: PrepareSubagentHandoff } = {},
): McpServer {
  const prepare = deps.prepare ?? prepareViaProxy;
  const server = new McpServer({ name: "opencodex-subagent-bridge", version: "1.0.0" });
  server.registerTool(
    "prepare_subagent_handoff",
    {
      description: "Stage a routed subagent handoff immediately before the matching native collaboration tool call.",
      inputSchema: SubagentHandoffRequestSchema,
    },
    async input => {
      try {
        const result = await prepare(input);
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch {
        return {
          isError: true,
          content: [{ type: "text" as const, text: "Subagent handoff service unavailable." }],
        };
      }
    },
  );
  return server;
}

export async function runSubagentBridgeMcpServer(): Promise<void> {
  const server = createSubagentBridgeMcpServer();
  await server.connect(new StdioServerTransport());
}
