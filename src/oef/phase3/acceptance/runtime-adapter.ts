import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
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
} from "../../phase2/runtime/protocol";
import { FakeRuntimeAdapter } from "../../phase2/runtime/adapters/fake";

export type Phase3AcceptanceMode = "initial" | "repair";

export class Phase3AcceptanceRuntimeAdapter implements RuntimeAdapter {
  readonly manifest: RuntimeManifest;
  private readonly delegate = new FakeRuntimeAdapter();

  constructor(readonly mode: Phase3AcceptanceMode) {
    this.manifest = runtimeManifestSchema.parse({
      schema_version: 1,
      runtime_id: `phase3-acceptance-${mode}`,
      adapter: { id: `phase3-acceptance-${mode}-runtime`, version: "1.0.0" },
      protocol: { min: 1, max: 1 },
      capabilities: {
        "repository-read": { supported: true, enforcement: "OBSERVED" },
        "repository-write": { supported: true, enforcement: "ENFORCED" },
        shell: { supported: true, enforcement: "OBSERVED" },
        git: { supported: true, enforcement: "OBSERVED" },
        "structured-output": { supported: true, enforcement: "ENFORCED" },
        "tool-events": { supported: true, enforcement: "ENFORCED" },
        streaming: { supported: true, enforcement: "OBSERVED" },
        "session-resume": { supported: false, enforcement: "NONE" },
        cancellation: { supported: true, enforcement: "ENFORCED" },
      },
    });
  }

  async detect(_context: RuntimeDetectionContext): Promise<RuntimeDetectionResult> {
    return {
      found: true,
      binary: {
        path: process.execPath,
        version: Bun.version,
        fingerprint: `sha256:${createHash("sha256").update(process.execPath).digest("hex")}`,
      },
      authentication: "READY",
      details: [`Deterministic Phase 3 ${this.mode} acceptance runtime`],
    };
  }

  async probe(context: RuntimeProbeContext): Promise<RuntimeProbeResult> {
    return {
      runtime_id: this.manifest.runtime_id,
      binary: context.detection.binary,
      health: { status: context.detection.found ? "HEALTHY" : "MISSING", checked_at: context.checked_at, latency_ms: 0 },
      capabilities: this.manifest.capabilities,
      capabilities_hash: capabilitiesHash(this.manifest.capabilities),
    };
  }

  async prepareLaunch(request: RuntimeExecutionRequest): Promise<RuntimeLaunchPlan> {
    return parseRuntimeLaunchPlan({
      executable: process.execPath,
      arguments: [
        fileURLToPath(new URL("./runtime-worker.ts", import.meta.url)),
        "--mode", this.mode,
        "--execution-id", request.execution_id,
        "--attempt-id", request.attempt_id,
      ],
      working_directory: request.workspace_path,
      environment: { inherited: [...request.inherited_environment], injected_secret_refs: [] },
      stdin: { mode: "closed" },
      output_protocol: { type: "jsonl", version: 1 },
      timeouts: request.timeouts,
      output_limit_bytes: request.output_limit_bytes,
      prompt_hash: request.prompt_hash,
    });
  }

  async parseEvent(input: RuntimeOutputChunk): Promise<NormalizedRuntimeEvent[]> {
    const events = await this.delegate.parseEvent(input);
    return events.map(event => normalizedRuntimeEventSchema.parse({
      ...event,
      source: { runtime: this.manifest.runtime_id, adapter: `${this.manifest.adapter.id}@${this.manifest.adapter.version}` },
    }));
  }

  classifyExit(input: RuntimeExitInput): Promise<ClassifiedRuntimeExit> {
    return this.delegate.classifyExit(input);
  }
}
