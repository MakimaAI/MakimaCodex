import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { canonicalSha256 } from "../../../phase1/core/contract/task-contract";
import {
  capabilitiesHash,
  normalizedRuntimeEventSchema,
  parseRuntimeLaunchPlan,
  runtimeManifestSchema,
  type ClassifiedRuntimeExit,
  type FakeRuntimeScenario,
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
} from "../protocol";

export class FakeRuntimeAdapter implements RuntimeAdapter {
  static readonly SCENARIOS = [
    "successful-edit",
    "startup-timeout",
    "idle-timeout",
    "malformed-json",
    "duplicate-event",
    "missing-sequence",
    "tool-failure",
    "path-violation",
    "secret-output",
    "child-process-hang",
    "context-limit",
  ] as const satisfies readonly FakeRuntimeScenario[];

  readonly manifest: RuntimeManifest = runtimeManifestSchema.parse({
    schema_version: 1,
    runtime_id: "fake-local",
    adapter: { id: "fake-runtime", version: "1.0.0" },
    protocol: { min: 1, max: 1 },
    capabilities: {
      "repository-read": { supported: true, enforcement: "OBSERVED" },
      "repository-write": { supported: true, enforcement: "ENFORCED" },
      shell: { supported: true, enforcement: "OBSERVED" },
      git: { supported: true, enforcement: "OBSERVED" },
      "structured-output": { supported: true, enforcement: "OBSERVED" },
      "tool-events": { supported: true, enforcement: "OBSERVED" },
      streaming: { supported: true, enforcement: "OBSERVED" },
      "session-resume": { supported: false, enforcement: "NONE" },
      cancellation: { supported: true, enforcement: "ENFORCED" },
    },
  });

  async detect(_context: RuntimeDetectionContext): Promise<RuntimeDetectionResult> {
    const path = process.execPath;
    return {
      found: true,
      binary: {
        path,
        version: Bun.version,
        fingerprint: `sha256:${createHash("sha256").update(path).digest("hex")}`,
      },
      authentication: "READY",
      details: ["Deterministic in-process test runtime"],
    };
  }

  async probe(context: RuntimeProbeContext): Promise<RuntimeProbeResult> {
    return {
      runtime_id: this.manifest.runtime_id,
      binary: context.detection.binary,
      health: {
        status: context.detection.found ? "HEALTHY" : "MISSING",
        checked_at: context.checked_at,
        latency_ms: 0,
      },
      capabilities: this.manifest.capabilities,
      capabilities_hash: capabilitiesHash(this.manifest.capabilities),
    };
  }

  async prepareLaunch(request: RuntimeExecutionRequest): Promise<RuntimeLaunchPlan> {
    const worker = fileURLToPath(new URL("./fake-worker.ts", import.meta.url));
    return parseRuntimeLaunchPlan({
      executable: process.execPath,
      arguments: [
        worker,
        "--scenario",
        request.scenario ?? "successful-edit",
        "--execution-id",
        request.execution_id,
        "--attempt-id",
        request.attempt_id,
      ],
      working_directory: request.workspace_path,
      environment: {
        inherited: [...request.inherited_environment],
        injected_secret_refs: [...request.injected_secret_refs],
      },
      stdin: { mode: "closed" },
      output_protocol: { type: "jsonl", version: 1 },
      timeouts: request.timeouts,
      output_limit_bytes: request.output_limit_bytes,
      prompt_hash: request.prompt_hash,
    });
  }

  async parseEvent(input: RuntimeOutputChunk): Promise<NormalizedRuntimeEvent[]> {
    const events: NormalizedRuntimeEvent[] = [];
    for (const line of input.chunk.split(/\r?\n/).filter(Boolean)) {
      let raw: Record<string, unknown>;
      try {
        raw = JSON.parse(line) as Record<string, unknown>;
      } catch {
        raw = { sequence: 1, type: "runtime.warning", payload: { reason: "malformed-runtime-json" } };
      }
      const sequence = typeof raw.sequence === "number" && Number.isInteger(raw.sequence) && raw.sequence > 0 ? raw.sequence : 1;
      const type = typeof raw.type === "string" ? raw.type : "runtime.warning";
      const correlationValue = raw.correlation;
      const callId = correlationValue && typeof correlationValue === "object" && typeof (correlationValue as Record<string, unknown>).call_id === "string"
        ? (correlationValue as Record<string, unknown>).call_id as string
        : null;
      const payload = raw.payload && typeof raw.payload === "object" && !Array.isArray(raw.payload)
        ? raw.payload as Record<string, unknown>
        : {};
      const identity = canonicalSha256({ input: input.attempt_id, sequence, type, payload });
      events.push(normalizedRuntimeEventSchema.parse({
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
      }));
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
    return { classification: "RUNTIME_FAILED", failure_type: "UNKNOWN", retryability: "conditional" };
  }

  async scenarioEvents(scenario: FakeRuntimeScenario, request: RuntimeExecutionRequest): Promise<NormalizedRuntimeEvent[]> {
    const raw = scenarioRows(scenario);
    const lines = raw.map(value => JSON.stringify(value)).join("\n") + "\n";
    return this.parseEvent({
      stream: "stdout",
      chunk: lines,
      execution_id: request.execution_id,
      attempt_id: request.attempt_id,
      received_at: "2026-07-23T10:00:01.000Z",
    });
  }
}

export function scenarioRows(scenario: FakeRuntimeScenario): Array<Record<string, unknown>> {
  switch (scenario) {
    case "successful-edit": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "file.observed", payload: { path: "src/generated.txt" } },
      { sequence: 3, type: "execution.completed", payload: { exit_code: 0 } },
    ];
    case "startup-timeout": return [];
    case "idle-timeout": return [{ sequence: 1, type: "execution.started", payload: {} }];
    case "malformed-json": return [{ sequence: 1, type: "runtime.warning", payload: { reason: "malformed-runtime-json" } }];
    case "duplicate-event": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "command.completed", payload: { exit_code: 0 } },
      { sequence: 2, type: "command.completed", payload: { exit_code: 0 } },
    ];
    case "missing-sequence": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 3, type: "execution.completed", payload: { exit_code: 0 } },
    ];
    case "tool-failure": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "tool.completed", payload: { success: false } },
      { sequence: 3, type: "execution.failed", payload: { failure_type: "TOOL_FAILED" } },
    ];
    case "path-violation": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "file.observed", payload: { path: ".github/workflows/release.yml" } },
      { sequence: 3, type: "execution.failed", payload: { failure_type: "PATH_POLICY_VIOLATION" } },
    ];
    case "secret-output": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "assistant.message.delta", payload: { text: "SECRET_SENTINEL_VALUE" } },
      { sequence: 3, type: "execution.failed", payload: { failure_type: "SECRET_LEAK_DETECTED" } },
    ];
    case "child-process-hang": return [{ sequence: 1, type: "execution.started", payload: {} }];
    case "context-limit": return [
      { sequence: 1, type: "execution.started", payload: {} },
      { sequence: 2, type: "execution.failed", payload: { failure_type: "CONTEXT_LIMIT_EXCEEDED" } },
    ];
  }
}
