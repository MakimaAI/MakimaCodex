import { createHash } from "node:crypto";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { delimiter, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { canonicalSha256 } from "../../../phase1/core/contract/task-contract";
import {
  capabilitiesHash,
  normalizedRuntimeEventSchema,
  parseRuntimeLaunchPlan,
  runtimeManifestSchema,
  type ClassifiedRuntimeExit,
  type NormalizedRuntimeEvent,
  type RuntimeAdapter,
  type RuntimeDetectionContext,
  type RuntimeDetectionResult,
  type RuntimeExecutionRequest,
  type RuntimeExitInput,
  type RuntimeLaunchPlan,
  type RuntimeManifest,
  type RuntimeOutputChunk,
  type RuntimeProbeContext,
  type RuntimeProbeResult,
  type RuntimeResumeRequest,
} from "../protocol";

export interface CodexRuntimeAdapterOptions {
  binaryCandidates?: readonly string[];
}

export class CodexRuntimeAdapter implements RuntimeAdapter {
  readonly manifest: RuntimeManifest = runtimeManifestSchema.parse({
    schema_version: 1,
    runtime_id: "codex-local",
    adapter: { id: "codex", version: "1.0.0" },
    protocol: { min: 1, max: 1 },
    capabilities: {
      "repository-read": { supported: true, enforcement: "OBSERVED" },
      "repository-write": { supported: true, enforcement: "ENFORCED" },
      shell: { supported: true, enforcement: "ENFORCED" },
      git: { supported: true, enforcement: "OBSERVED" },
      "structured-output": { supported: true, enforcement: "OBSERVED" },
      "tool-events": { supported: true, enforcement: "OBSERVED" },
      streaming: { supported: true, enforcement: "OBSERVED" },
      "session-resume": { supported: true, enforcement: "OBSERVED" },
      "native-worktree": { supported: false, enforcement: "NONE" },
      "file-edit": { supported: true, enforcement: "ENFORCED" },
      "test-execution": { supported: true, enforcement: "OBSERVED" },
      "usage-reporting": { supported: true, enforcement: "OBSERVED" },
      cancellation: { supported: true, enforcement: "ENFORCED" },
      "network-access": { supported: true, enforcement: "ADVISORY" },
    },
  });

  private readonly candidates: readonly string[];
  private readonly buffers = new Map<string, string>();
  private readonly sequences = new Map<string, number>();

  constructor(options: CodexRuntimeAdapterOptions = {}) {
    this.candidates = options.binaryCandidates ?? defaultCodexCandidates();
  }

  async detect(context: RuntimeDetectionContext): Promise<RuntimeDetectionResult> {
    const path = findExecutable(this.candidates, context.environment_path);
    if (!path) return { found: false, binary: null, authentication: "MISSING", details: ["Codex binary was not found"] };
    const result = context.probe_executor
      ? await context.probe_executor.run(path, ["--version"])
      : { exit_code: null, stdout: "", stderr: "", timed_out: false };
    const version = parseCodexVersion(`${result.stdout}\n${result.stderr}`) ?? "unknown";
    const fingerprint = fingerprintFile(path);
    const authenticationResult = context.probe_executor && result.exit_code === 0
      ? await context.probe_executor.run(path, ["login", "status"])
      : null;
    const authentication = !authenticationResult || authenticationResult.timed_out
      ? "UNKNOWN"
      : authenticationResult.exit_code === 0
        ? "READY"
        : "MISSING";
    const details = [result.timed_out
      ? ["Codex version probe timed out"]
      : result.exit_code === 0
        ? ["Codex version probe completed"]
        : ["Codex binary found; version probe unavailable"],
      authentication === "READY" ? ["Codex authentication probe ready"] : [`Codex authentication probe ${authentication.toLowerCase()}`],
    ].flat();
    return { found: true, binary: { path, version, fingerprint }, authentication, details };
  }

  async probe(context: RuntimeProbeContext): Promise<RuntimeProbeResult> {
    const versionKnown = context.detection.binary?.version !== "unknown";
    const status = !context.detection.found
      ? "MISSING"
      : !versionKnown || context.detection.authentication === "UNKNOWN"
        ? "DEGRADED"
        : context.detection.authentication === "READY"
          ? "HEALTHY"
          : "UNHEALTHY";
    return {
      runtime_id: this.manifest.runtime_id,
      binary: context.detection.binary,
      health: { status, checked_at: context.checked_at, latency_ms: 0 },
      capabilities: this.manifest.capabilities,
      capabilities_hash: capabilitiesHash(this.manifest.capabilities),
    };
  }

  async prepareLaunch(request: RuntimeExecutionRequest): Promise<RuntimeLaunchPlan> {
    const executable = findExecutable(this.candidates, process.env.PATH ?? "") ?? this.candidates[0];
    if (!executable) throw new Error("Codex runtime has no binary candidate");
    const arguments_ = [
      "exec",
      "--json",
      "--color",
      "never",
      "--sandbox",
      "workspace-write",
      "--cd",
      request.workspace_path,
    ];
    if (request.resolved_model) arguments_.push("--model", request.resolved_model);
    arguments_.push("-");
    return parseRuntimeLaunchPlan({
      executable,
      arguments: arguments_,
      working_directory: request.workspace_path,
      environment: {
        inherited: [...request.inherited_environment],
        injected_secret_refs: [...request.injected_secret_refs],
        path_prepend: codexResourcePathPrepend(executable),
      },
      stdin: { mode: "file", path: request.prompt_path },
      output_protocol: { type: "jsonl", version: 1 },
      timeouts: request.timeouts,
      output_limit_bytes: request.output_limit_bytes,
      prompt_hash: request.prompt_hash,
    });
  }

  async buildResumePlan(request: RuntimeResumeRequest): Promise<RuntimeLaunchPlan> {
    const base = await this.prepareLaunch(request);
    const modelArgs = request.resolved_model ? ["--model", request.resolved_model] : [];
    return parseRuntimeLaunchPlan({
      ...base,
      arguments: ["exec", "resume", "--json", ...modelArgs, request.native_session_id, "-"],
    });
  }

  async parseEvent(input: RuntimeOutputChunk): Promise<NormalizedRuntimeEvent[]> {
    const key = `${input.attempt_id}\u0000${input.stream}`;
    const source = (this.buffers.get(key) ?? "") + input.chunk;
    const lines = source.split(/\r?\n/);
    this.buffers.set(key, lines.pop() ?? "");
    const events: NormalizedRuntimeEvent[] = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch {
        events.push(this.event(input, "runtime.warning", { reason: "malformed-runtime-json" }, null));
        continue;
      }
      const mapped = mapCodexRow(row);
      for (const entry of mapped) events.push(this.event(input, entry.type, entry.payload, entry.callId));
    }
    return events;
  }

  async classifyExit(input: RuntimeExitInput): Promise<ClassifiedRuntimeExit> {
    if (input.timed_out) {
      return {
        classification: "RUNTIME_FAILED",
        failure_type: `${input.timed_out.toUpperCase()}_TIMEOUT`,
        retryability: input.timed_out === "tool" ? "conditional" : "retryable",
      };
    }
    if (input.signal) return { classification: "RUNTIME_CANCELLED", failure_type: "CANCELLED_BY_USER", retryability: "never" };
    if (input.exit_code === 0) return { classification: "RUNTIME_EXITED", failure_type: null, retryability: "never" };
    const stderr = input.stderr_tail.toLowerCase();
    if (/\b429\b|rate.?limit/.test(stderr)) return { classification: "RUNTIME_FAILED", failure_type: "RATE_LIMITED", retryability: "retryable" };
    if (/\b401\b|\b403\b|unauth|forbidden/.test(stderr)) return { classification: "RUNTIME_FAILED", failure_type: "AUTHENTICATION_FAILED", retryability: "never" };
    if (/context.{0,20}(length|limit)|token.{0,20}limit/.test(stderr)) return { classification: "RUNTIME_FAILED", failure_type: "CONTEXT_LIMIT_EXCEEDED", retryability: "conditional" };
    if (/protocol|invalid json|jsonl/.test(stderr)) return { classification: "RUNTIME_FAILED", failure_type: "PROTOCOL_ERROR", retryability: "conditional" };
    return { classification: "RUNTIME_FAILED", failure_type: "UNKNOWN", retryability: "conditional" };
  }

  private event(
    input: RuntimeOutputChunk,
    type: NormalizedRuntimeEvent["type"],
    payload: Record<string, unknown>,
    callId: string | null,
  ): NormalizedRuntimeEvent {
    const sequence = (this.sequences.get(input.attempt_id) ?? 0) + 1;
    this.sequences.set(input.attempt_id, sequence);
    const identity = canonicalSha256({ attempt_id: input.attempt_id, sequence, type, payload });
    return normalizedRuntimeEventSchema.parse({
      schema_version: 1,
      event_id: `runtime-event:${identity.slice("sha256:".length)}`,
      sequence,
      execution_id: input.execution_id,
      attempt_id: input.attempt_id,
      type,
      correlation: { call_id: callId },
      payload,
      source: { runtime: this.manifest.runtime_id, adapter: `${this.manifest.adapter.id}@${this.manifest.adapter.version}` },
      confidence: "AUTHORITATIVE",
      occurred_at: input.received_at,
    });
  }
}

export function codexResourcePathPrepend(executable: string): string[] {
  if (process.platform !== "win32") return [];
  const candidates: string[] = [];
  try {
    const resolvedExecutable = realpathSync(executable);
    candidates.push(join(resolve(dirname(resolvedExecutable), ".."), "codex-resources"));
  } catch { /* unresolved candidate is ignored */ }
  if (process.env.LOCALAPPDATA) {
    const cachedRoot = join(process.env.LOCALAPPDATA, "OpenAI", "Codex", "bin");
    try {
      for (const entry of new Bun.Glob("*/codex-windows-sandbox-setup.exe").scanSync({ cwd: cachedRoot, absolute: true })) {
        candidates.push(dirname(entry));
      }
    } catch { /* optional app-managed helper cache */ }
  }
  return [...new Set(candidates.filter(directory => existsSync(join(directory, "codex-windows-sandbox-setup.exe"))))];
}

function defaultCodexCandidates(): string[] {
  const values = ["codex"];
  if (process.platform === "win32" && process.env.LOCALAPPDATA) {
    values.unshift(join(process.env.LOCALAPPDATA, "Programs", "OpenAI", "Codex", "bin", "codex.exe"));
  }
  return values;
}

function findExecutable(candidates: readonly string[], environmentPath: string): string | null {
  const pathEntries = environmentPath.split(delimiter).filter(Boolean);
  const extensions = process.platform === "win32" ? ["", ".exe", ".cmd", ".bat"] : [""];
  for (const candidate of candidates) {
    if (isAbsolute(candidate) || candidate.includes("/") || candidate.includes("\\")) {
      const absolute = resolve(candidate);
      if (existsSync(absolute)) return absolute;
      continue;
    }
    for (const directory of pathEntries) {
      for (const extension of extensions) {
        const path = join(directory, extname(candidate) ? candidate : `${candidate}${extension}`);
        if (existsSync(path)) return resolve(path);
      }
    }
  }
  return null;
}

function parseCodexVersion(output: string): string | null {
  return output.match(/codex(?:-cli)?\s+v?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)/i)?.[1] ?? null;
}

function fingerprintFile(path: string): string {
  try {
    return `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
  } catch {
    return canonicalSha256({ path });
  }
}

type MappedEvent = { type: NormalizedRuntimeEvent["type"]; payload: Record<string, unknown>; callId: string | null };

function mapCodexRow(row: Record<string, unknown>): MappedEvent[] {
  const rowType = typeof row.type === "string" ? row.type : "unknown";
  if (rowType === "thread.started") {
    return [{ type: "runtime.session.created", payload: { native_session_id: stringValue(row.thread_id), resumable: true }, callId: null }];
  }
  if (rowType === "turn.started") return [{ type: "execution.started", payload: {}, callId: null }];
  if (rowType === "turn.completed") {
    const usage = objectValue(row.usage);
    return [
      { type: "usage.reported", payload: usage, callId: null },
      { type: "execution.completed", payload: { runtime_claim: true }, callId: null },
    ];
  }
  if (rowType === "turn.failed" || rowType === "error") {
    return [{ type: "execution.failed", payload: { runtime_claim: true, code: stringValue(row.code) }, callId: null }];
  }
  if (rowType !== "item.started" && rowType !== "item.completed") return [];
  const item = objectValue(row.item);
  const itemType = stringValue(item.type);
  const callId = stringValue(item.id) || null;
  if (itemType === "reasoning") return [];
  if (itemType === "command_execution") {
    const command = stringValue(item.command);
    const payload = {
      command_summary: summarizeCommand(command),
      ...(rowType === "item.completed" ? { exit_code: numberValue(item.exit_code), status: stringValue(item.status) } : {}),
    };
    return [{ type: rowType === "item.started" ? "command.started" : "command.completed", payload, callId }];
  }
  if (itemType === "agent_message") {
    return rowType === "item.completed"
      ? [{ type: "assistant.message.delta", payload: { text: stringValue(item.text) }, callId }]
      : [];
  }
  if (itemType === "file_change") {
    const changes = Array.isArray(item.changes) ? item.changes : [];
    const paths = changes.map(change => stringValue(objectValue(change).path)).filter(Boolean);
    return [{ type: "file.observed", payload: { paths }, callId }];
  }
  if (itemType === "mcp_tool_call" || itemType === "web_search") {
    return [{ type: rowType === "item.started" ? "tool.started" : "tool.completed", payload: { tool: itemType, status: stringValue(item.status) }, callId }];
  }
  return [{ type: "runtime.observation", payload: { item_type: itemType || "unknown", lifecycle: rowType }, callId }];
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}
function stringValue(value: unknown): string { return typeof value === "string" ? value : ""; }
function numberValue(value: unknown): number | null { return typeof value === "number" && Number.isFinite(value) ? value : null; }
function summarizeCommand(command: string): string {
  const executable = command.trim().split(/\s+/, 1)[0] ?? "";
  const argumentCount = command.trim() ? Math.max(0, command.trim().split(/\s+/).length - 1) : 0;
  return executable ? `${executable} (+${argumentCount} args)` : "command";
}
