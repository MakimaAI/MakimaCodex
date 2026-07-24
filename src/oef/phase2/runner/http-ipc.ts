import { timingSafeEqual } from "node:crypto";
import { normalizedRuntimeEventSchema, type NormalizedRuntimeEvent } from "../runtime/protocol";
import type {
  RunnerCapabilities, RunnerExecutionRequest, RunnerExecutionStatus,
  RunnerReviewIdentityAuthority, RunnerReviewLaunchPolicy, RunnerVerificationCommandRequest, RunnerVerifiedCommandResult,
} from "./local-runner-host";
import { LocalRunnerHost } from "./local-runner-host";
import type { RunnerLease } from "./lease-store";
import { KILL_SWITCH_STATES, type KillSwitchState } from "./kill-switch";

const MAX_REQUEST_BYTES = 1_000_000;

export class AuthenticatedRunnerHttpServer {
  private readonly host: LocalRunnerHost;
  private readonly token: string;
  private server: ReturnType<typeof Bun.serve> | null = null;

  private readonly onShutdown?: () => void;

  constructor(options: { host: LocalRunnerHost; token: string; onShutdown?: () => void }) {
    if (!/^[A-Za-z0-9_-]{32,512}$/.test(options.token)) throw new Error("Runner IPC token must contain at least 32 safe characters");
    this.host = options.host;
    this.token = options.token;
    this.onShutdown = options.onShutdown;
  }

  start(): string {
    if (this.server) throw new Error("Runner IPC server is already started");
    this.server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      maxRequestBodySize: MAX_REQUEST_BYTES,
      fetch: request => this.handle(request),
      error: () => json({ error: "RUNNER_IPC_INTERNAL_ERROR" }, 500),
    });
    return `http://127.0.0.1:${this.server.port}`;
  }

  stop(): void {
    this.server?.stop(true);
    this.server = null;
  }

  private async handle(request: Request): Promise<Response> {
    if (!this.authorized(request)) return json({ error: "UNAUTHORIZED" }, 401);
    const url = new URL(request.url);
    try {
      if (request.method === "GET" && url.pathname === "/v1/capabilities") return json(this.host.getCapabilities());
      if (request.method === "GET" && url.pathname === "/v1/review-identity-authority") return json(this.host.getReviewIdentityAuthority());
      const reviewPolicy = url.pathname.match(/^\/v1\/review-launch-policies\/([^/]+)$/);
      if (request.method === "GET" && reviewPolicy) return json(this.host.getReviewLaunchPolicy(decodeURIComponent(reviewPolicy[1]!)));
      if (request.method === "GET" && url.pathname === "/v1/control") {
        return json({ kill_switch: this.host.killSwitch.current(), executions: this.host.listExecutionStatuses() });
      }
      if (request.method === "POST" && url.pathname === "/v1/control") {
        const body = await readJsonBody(request) as { state?: unknown; reason?: unknown };
        if (typeof body.state !== "string" || !(KILL_SWITCH_STATES as readonly string[]).includes(body.state) || typeof body.reason !== "string") {
          throw new Error("INVALID_RUNNER_CONTROL_REQUEST");
        }
        return json({ kill_switch: await this.host.applyControlState(body.state as KillSwitchState, body.reason), executions: this.host.listExecutionStatuses() });
      }
      if (request.method === "POST" && url.pathname === "/v1/shutdown") {
        if (!this.onShutdown) return json({ error: "RUNNER_SHUTDOWN_NOT_AVAILABLE" }, 409);
        setTimeout(() => this.onShutdown?.(), 0);
        return json({ shutdown_requested: true });
      }
      if (request.method === "POST" && url.pathname === "/v1/executions") {
        const body = await readJsonBody(request);
        return json(await this.host.startExecution(body as RunnerExecutionRequest), 201);
      }
      if (request.method === "POST" && url.pathname === "/v1/verifications/commands") {
        const body = await readJsonBody(request);
        return json(await this.host.runVerificationCommand(body as RunnerVerificationCommandRequest), 201);
      }
      const match = url.pathname.match(/^\/v1\/executions\/([^/]+)\/(status|cancel|events|artifacts)$/);
      if (!match) return json({ error: "NOT_FOUND" }, 404);
      const executionId = decodeURIComponent(match[1]!);
      const operation = match[2]!;
      if (request.method === "GET" && operation === "status") return json(await this.host.getStatus(executionId));
      if (request.method === "POST" && operation === "cancel") {
        await this.host.cancelExecution(executionId);
        return json({ cancelled: true });
      }
      if (request.method === "GET" && operation === "events") {
        const from = parsePositiveInteger(url.searchParams.get("from") ?? "1");
        return json(await this.host.readEventSnapshot(executionId, from));
      }
      if (request.method === "GET" && operation === "artifacts") return json(await this.host.collectArtifacts(executionId));
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    } catch (error) {
      const message = error instanceof Error ? error.message : "RUNNER_IPC_REQUEST_FAILED";
      const safe = /^[A-Z0-9_:-]{1,200}$/.test(message) ? message : "RUNNER_IPC_REQUEST_FAILED";
      return json({ error: safe }, message.includes("NOT_FOUND") ? 404 : 400);
    }
  }

  private authorized(request: Request): boolean {
    const header = request.headers.get("authorization") ?? "";
    const prefix = "Bearer ";
    if (!header.startsWith(prefix)) return false;
    const provided = Buffer.from(header.slice(prefix.length), "utf8");
    const expected = Buffer.from(this.token, "utf8");
    return provided.length === expected.length && timingSafeEqual(provided, expected);
  }
}

export class HttpRunnerClient {
  private readonly endpoint: string;
  private readonly token: string;
  constructor(options: { endpoint: string; token: string }) {
    const url = new URL(options.endpoint);
    if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]", "::1"].includes(url.hostname)) {
      throw new Error("Runner IPC client only permits loopback HTTP endpoints");
    }
    this.endpoint = options.endpoint.replace(/\/$/, "");
    this.token = options.token;
  }

  getCapabilities(): Promise<RunnerCapabilities> {
    return this.request("GET", "/v1/capabilities");
  }
  startExecution(request: RunnerExecutionRequest): Promise<RunnerLease> {
    return this.request("POST", "/v1/executions", request);
  }
  runVerificationCommand(request: RunnerVerificationCommandRequest) {
    const timeoutMs = Math.ceil((request.plan.timeouts.total_seconds + request.plan.timeouts.graceful_shutdown_seconds + 30) * 1_000);
    return this.request<RunnerVerifiedCommandResult>("POST", "/v1/verifications/commands", request, timeoutMs);
  }
  getReviewIdentityAuthority(): Promise<RunnerReviewIdentityAuthority> {
    return this.request("GET", "/v1/review-identity-authority");
  }
  getReviewLaunchPolicy(policyId: string): Promise<RunnerReviewLaunchPolicy> {
    return this.request("GET", `/v1/review-launch-policies/${encodeURIComponent(policyId)}`);
  }
  getStatus(executionId: string): Promise<RunnerExecutionStatus> {
    return this.request("GET", `/v1/executions/${encodeURIComponent(executionId)}/status`);
  }
  cancelExecution(executionId: string): Promise<{ cancelled: true }> {
    return this.request("POST", `/v1/executions/${encodeURIComponent(executionId)}/cancel`, {});
  }
  collectArtifacts(executionId: string): Promise<{ stdout_path: string; stderr_path: string; event_count: number }> {
    return this.request("GET", `/v1/executions/${encodeURIComponent(executionId)}/artifacts`);
  }
  getControl(): Promise<{ kill_switch: { state: KillSwitchState }; executions: RunnerExecutionStatus[] }> {
    return this.request("GET", "/v1/control");
  }
  applyControl(state: KillSwitchState, reason: string): Promise<{ kill_switch: { state: KillSwitchState }; executions: RunnerExecutionStatus[] }> {
    return this.request("POST", "/v1/control", { state, reason });
  }
  shutdown(): Promise<{ shutdown_requested: true }> { return this.request("POST", "/v1/shutdown", {}); }
  async *streamEvents(executionId: string, fromSequence = 1): AsyncIterable<NormalizedRuntimeEvent> {
    let next = fromSequence;
    while (true) {
      const snapshot = await this.request<{ events: unknown[]; terminal: boolean }>(
        "GET",
        `/v1/executions/${encodeURIComponent(executionId)}/events?from=${next}`,
      );
      for (const input of snapshot.events) {
        const event = normalizedRuntimeEventSchema.parse(input);
        yield event;
        next = Math.max(next, event.sequence + 1);
      }
      if (snapshot.terminal) return;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
  }

  private async request<T>(method: string, path: string, body?: unknown, timeoutMs = 30_000): Promise<T> {
    const response = await fetch(`${this.endpoint}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${this.token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const value = await response.json() as T & { error?: string };
    if (!response.ok) throw new Error(value.error ?? `RUNNER_IPC_HTTP_${response.status}`);
    return value;
  }
}

async function readJsonBody(request: Request): Promise<unknown> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > MAX_REQUEST_BYTES) throw new Error("RUNNER_IPC_BODY_TOO_LARGE");
  const text = await request.text();
  if (Buffer.byteLength(text) > MAX_REQUEST_BYTES) throw new Error("RUNNER_IPC_BODY_TOO_LARGE");
  return JSON.parse(text);
}

function parsePositiveInteger(value: string): number {
  if (!/^\d+$/.test(value)) throw new Error("INVALID_EVENT_SEQUENCE");
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1) throw new Error("INVALID_EVENT_SEQUENCE");
  return number;
}
function json(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
