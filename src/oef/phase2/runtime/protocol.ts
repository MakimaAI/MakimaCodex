import { z } from "zod";
import { isAbsolute } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  ENFORCEMENT_LEVELS,
  RUNTIME_CAPABILITIES,
  capabilityStateSchema,
  type CapabilityState,
  type RuntimeCapability,
} from "../core/domain";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);

export const runtimeProtocolRangeSchema = z.object({
  min: z.number().int().positive(),
  max: z.number().int().positive(),
}).strict().refine(value => value.min <= value.max, "Runtime protocol minimum cannot exceed maximum");

export type RuntimeProtocolRange = z.infer<typeof runtimeProtocolRangeSchema>;

export const runtimeManifestSchema = z.object({
  schema_version: z.literal(1),
  runtime_id: z.string().trim().min(1).max(300),
  adapter: z.object({ id: z.string().trim().min(1).max(300), version: semverSchema }).strict(),
  protocol: runtimeProtocolRangeSchema,
  capabilities: z.partialRecord(z.enum(RUNTIME_CAPABILITIES), capabilityStateSchema),
}).strict();

export type RuntimeManifest = z.infer<typeof runtimeManifestSchema>;

export function negotiateAdapterProtocol(
  runnerProtocolVersion: number,
  adapterRangeInput: RuntimeProtocolRange,
): { ok: true; negotiated_version: number } | { ok: false; failure: "ADAPTER_PROTOCOL_INCOMPATIBLE" } {
  const adapterRange = runtimeProtocolRangeSchema.parse(adapterRangeInput);
  if (!Number.isInteger(runnerProtocolVersion) || runnerProtocolVersion < adapterRange.min || runnerProtocolVersion > adapterRange.max) {
    return { ok: false, failure: "ADAPTER_PROTOCOL_INCOMPATIBLE" };
  }
  return { ok: true, negotiated_version: runnerProtocolVersion };
}

export const runtimeLaunchPlanSchema = z.object({
  executable: z.string().trim().min(1).max(4_000),
  arguments: z.array(z.string().max(50_000)).max(1_024),
  working_directory: z.string().trim().min(1).max(4_000),
  environment: z.object({
    inherited: z.array(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/)).max(128),
    injected_secret_refs: z.array(z.string().regex(/^secret-ref:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/)).max(64),
    path_prepend: z.array(z.string().trim().min(1).max(4_000).refine(value => isAbsolute(value), "PATH prepend entries must be absolute")).max(32).optional(),
  }).strict(),
  stdin: z.discriminatedUnion("mode", [
    z.object({ mode: z.literal("closed") }).strict(),
    z.object({ mode: z.literal("pipe") }).strict(),
    z.object({ mode: z.literal("file"), path: z.string().trim().min(1).max(4_000) }).strict(),
  ]),
  output_protocol: z.object({ type: z.enum(["jsonl", "text"]), version: z.number().int().positive() }).strict(),
  timeouts: z.object({
    startup_seconds: z.number().positive().max(3_600),
    idle_seconds: z.number().positive().max(86_400),
    tool_seconds: z.number().positive().max(86_400),
    total_seconds: z.number().positive().max(604_800),
    graceful_shutdown_seconds: z.number().nonnegative().max(600),
  }).strict(),
  output_limit_bytes: z.number().int().positive().max(10_000_000_000),
  prompt_hash: hashSchema,
}).strict();

export type RuntimeLaunchPlan = z.infer<typeof runtimeLaunchPlanSchema>;
export function parseRuntimeLaunchPlan(input: unknown): RuntimeLaunchPlan { return runtimeLaunchPlanSchema.parse(input); }

export const NORMALIZED_RUNTIME_EVENT_TYPES = [
  "execution.started",
  "runtime.session.created",
  "assistant.message.delta",
  "tool.started",
  "tool.completed",
  "command.started",
  "command.completed",
  "file.observed",
  "usage.reported",
  "checkpoint.created",
  "runtime.warning",
  "runtime.observation",
  "execution.completed",
  "execution.failed",
] as const;

export const EVENT_CONFIDENCE = ["AUTHORITATIVE", "PARSED", "INFERRED", "UNKNOWN"] as const;

export const normalizedRuntimeEventSchema = z.object({
  schema_version: z.literal(1),
  event_id: z.string().regex(/^runtime-event:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  sequence: z.number().int().positive(),
  execution_id: z.string().regex(/^execution:/),
  attempt_id: z.string().regex(/^attempt:/),
  type: z.enum(NORMALIZED_RUNTIME_EVENT_TYPES),
  correlation: z.object({ call_id: z.string().trim().min(1).max(500).nullable() }).strict(),
  payload: z.record(z.string(), z.unknown()),
  source: z.object({ runtime: z.string().trim().min(1), adapter: z.string().trim().min(1) }).strict(),
  confidence: z.enum(EVENT_CONFIDENCE),
  occurred_at: z.string().datetime(),
}).strict();

export type NormalizedRuntimeEvent = z.infer<typeof normalizedRuntimeEventSchema>;
export function parseNormalizedRuntimeEvent(input: unknown): NormalizedRuntimeEvent { return normalizedRuntimeEventSchema.parse(input); }

export interface RuntimeProbeExecutor {
  run(executable: string, arguments_: readonly string[]): Promise<{ exit_code: number | null; stdout: string; stderr: string; timed_out: boolean }>;
}
export interface RuntimeDetectionContext {
  environment_path: string;
  probe_executor?: RuntimeProbeExecutor;
}
export interface RuntimeBinarySnapshot { path: string; version: string; fingerprint: string }
export interface RuntimeDetectionResult {
  found: boolean;
  binary: RuntimeBinarySnapshot | null;
  authentication: "READY" | "UNKNOWN" | "MISSING";
  details: readonly string[];
}

export const RUNTIME_HEALTH_STATUSES = ["UNKNOWN", "HEALTHY", "DEGRADED", "UNHEALTHY", "MISSING", "INCOMPATIBLE", "QUARANTINED"] as const;
export type RuntimeHealthStatus = typeof RUNTIME_HEALTH_STATUSES[number];

export interface RuntimeProbeContext { detection: RuntimeDetectionResult; checked_at: string }
export interface RuntimeProbeResult {
  runtime_id: string;
  binary: RuntimeBinarySnapshot | null;
  health: { status: RuntimeHealthStatus; checked_at: string; latency_ms: number };
  capabilities: Partial<Record<RuntimeCapability, CapabilityState>>;
  capabilities_hash: string;
}

export type FakeRuntimeScenario =
  | "successful-edit"
  | "startup-timeout"
  | "idle-timeout"
  | "malformed-json"
  | "duplicate-event"
  | "missing-sequence"
  | "tool-failure"
  | "path-violation"
  | "secret-output"
  | "child-process-hang"
  | "context-limit";

export interface RuntimeExecutionRequest {
  execution_id: string;
  attempt_id: string;
  workspace_path: string;
  prompt_path: string;
  prompt_hash: string;
  inherited_environment: string[];
  injected_secret_refs: string[];
  timeouts: RuntimeLaunchPlan["timeouts"];
  output_limit_bytes: number;
  scenario?: FakeRuntimeScenario;
  resolved_model?: string | null;
}

export interface RuntimeOutputChunk {
  stream: "stdout" | "stderr";
  chunk: string;
  execution_id: string;
  attempt_id: string;
  received_at: string;
}

export interface RuntimeExitInput {
  exit_code: number | null;
  signal: string | null;
  stderr_tail: string;
  timed_out: "startup" | "idle" | "tool" | "total" | null;
}

export interface ClassifiedRuntimeExit {
  classification: "RUNTIME_EXITED" | "RUNTIME_FAILED" | "RUNTIME_CANCELLED";
  failure_type: string | null;
  retryability: "never" | "conditional" | "retryable";
}

export interface RuntimeResumeRequest extends RuntimeExecutionRequest {
  native_session_id: string;
  resume_token_ref: string | null;
}

export interface RuntimeSessionRef { runtime_id: string; native_session_id: string }

export interface RuntimeAdapter {
  readonly manifest: RuntimeManifest;
  detect(context: RuntimeDetectionContext): Promise<RuntimeDetectionResult>;
  probe(context: RuntimeProbeContext): Promise<RuntimeProbeResult>;
  prepareLaunch(request: RuntimeExecutionRequest): Promise<RuntimeLaunchPlan>;
  parseEvent(input: RuntimeOutputChunk): Promise<NormalizedRuntimeEvent[]>;
  classifyExit(input: RuntimeExitInput): Promise<ClassifiedRuntimeExit>;
  buildResumePlan?(request: RuntimeResumeRequest): Promise<RuntimeLaunchPlan>;
  cleanup?(session: RuntimeSessionRef): Promise<void>;
}

export function capabilitiesHash(capabilities: Partial<Record<RuntimeCapability, CapabilityState>>): string {
  return canonicalSha256(capabilities);
}

export type RuntimeEventAcceptResult =
  | { status: "ACCEPTED" }
  | { status: "DUPLICATE" }
  | { status: "GAP"; missing_sequences: number[] }
  | { status: "CONFLICT"; sequence: number };

export class RuntimeEventSequenceTracker {
  private readonly events = new Map<number, NormalizedRuntimeEvent>();
  private readonly missing = new Set<number>();
  private maximumSequence = 0;

  accept(input: NormalizedRuntimeEvent): RuntimeEventAcceptResult {
    const event = parseNormalizedRuntimeEvent(input);
    const existing = this.events.get(event.sequence);
    if (existing) {
      return canonicalSha256(existing) === canonicalSha256(event)
        ? { status: "DUPLICATE" }
        : { status: "CONFLICT", sequence: event.sequence };
    }
    const gaps: number[] = [];
    if (event.sequence > this.maximumSequence + 1) {
      for (let sequence = this.maximumSequence + 1; sequence < event.sequence; sequence += 1) {
        if (!this.events.has(sequence)) {
          this.missing.add(sequence);
          gaps.push(sequence);
        }
      }
    }
    this.events.set(event.sequence, event);
    this.missing.delete(event.sequence);
    this.maximumSequence = Math.max(this.maximumSequence, event.sequence);
    return gaps.length > 0 ? { status: "GAP", missing_sequences: gaps } : { status: "ACCEPTED" };
  }

  acceptedEvents(): NormalizedRuntimeEvent[] {
    return [...this.events.values()].sort((left, right) => left.sequence - right.sequence);
  }

  integrity(): { complete: boolean; next_expected_sequence: number; missing_sequences: number[] } {
    const missing = [...this.missing].sort((left, right) => left - right);
    return {
      complete: missing.length === 0,
      next_expected_sequence: missing[0] ?? this.maximumSequence + 1,
      missing_sequences: missing,
    };
  }
}

export function enforcementLevelIsValid(value: string): value is typeof ENFORCEMENT_LEVELS[number] {
  return (ENFORCEMENT_LEVELS as readonly string[]).includes(value);
}
