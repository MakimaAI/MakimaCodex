import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

export const phase4HashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const entityId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._/@-]*$`));
const semver = z.string().regex(/^\d+\.\d+\.\d+$/);
const isoDate = z.string().datetime();
const score = z.number().min(0).max(1);

export const MODEL_LIFECYCLE_STATUSES = [
  "DISCOVERED", "METADATA_VALIDATED", "COMPATIBILITY_PROBED", "SCREENED", "ROLE_QUALIFIED",
  "SHADOW_READY", "CANARY_READY", "ACTIVE", "DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED",
] as const;
export type ModelLifecycleStatus = typeof MODEL_LIFECYCLE_STATUSES[number];

const transitions: Readonly<Record<ModelLifecycleStatus, readonly ModelLifecycleStatus[]>> = {
  DISCOVERED: ["METADATA_VALIDATED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  METADATA_VALIDATED: ["COMPATIBILITY_PROBED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  COMPATIBILITY_PROBED: ["SCREENED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  SCREENED: ["ROLE_QUALIFIED", "DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  ROLE_QUALIFIED: ["SHADOW_READY", "DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  SHADOW_READY: ["DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  CANARY_READY: ["ACTIVE", "DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  ACTIVE: ["DEGRADED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  DEGRADED: ["COMPATIBILITY_PROBED", "QUARANTINED", "DEPRECATED", "RETIRED"],
  QUARANTINED: ["COMPATIBILITY_PROBED", "DEPRECATED", "RETIRED"],
  DEPRECATED: ["RETIRED"], RETIRED: [],
};

export function transitionModelLifecycle(current: ModelLifecycleStatus, next: ModelLifecycleStatus, humanApproved = false): ModelLifecycleStatus {
  if (next === "CANARY_READY" || next === "ACTIVE") throw new Error("PHASE4_CANNOT_ACTIVATE_MODEL");
  if (current === "QUARANTINED" && next !== "DEPRECATED" && next !== "RETIRED" && !humanApproved) {
    throw new Error("QUARANTINE_REQUIRES_HUMAN_APPROVAL");
  }
  if (!transitions[current].includes(next)) throw new Error("INVALID_MODEL_LIFECYCLE_TRANSITION");
  return next;
}

const sourceSchema = z.object({
  source_type: z.enum(["provider-api", "official-documentation", "official-release-note", "runtime-documentation", "community-report", "local-observation", "benchmark-result", "human-confirmed"]),
  observed_at: isoDate,
  content_hash: phase4HashSchema,
}).strict();

const modelVersionContentSchema = z.object({
  schema_version: z.literal(1),
  model_version_id: entityId("model-version"),
  family_id: entityId("model-family"),
  provider_id: entityId("provider"),
  provider_model_name: z.string().trim().min(1).max(300),
  release: z.object({ first_seen_at: isoDate, provider_release_date: isoDate.nullable(), knowledge_cutoff: isoDate.nullable() }).strict(),
  modalities: z.object({ text_input: z.boolean(), image_input: z.boolean(), text_output: z.boolean() }).strict(),
  context: z.object({ advertised_tokens: z.number().int().positive().nullable(), observed_safe_tokens: z.number().int().positive().nullable() }).strict(),
  features: z.object({ tool_calling_claimed: z.boolean(), structured_output_claimed: z.boolean(), streaming_claimed: z.boolean() }).strict(),
  commercial: z.object({ input_cost_per_million: z.number().nonnegative(), output_cost_per_million: z.number().nonnegative(), currency: z.string().length(3) }).strict().nullable(),
  lifecycle_status: z.enum(MODEL_LIFECYCLE_STATUSES),
  provenance: z.array(sourceSchema).min(1),
}).strict();
export const modelVersionSchema = modelVersionContentSchema.extend({ metadata_hash: phase4HashSchema }).strict();
export type ModelVersion = z.infer<typeof modelVersionSchema>;

export function createModelVersion(input: Omit<z.input<typeof modelVersionContentSchema>, "schema_version" | "features" | "commercial"> & {
  features?: z.input<typeof modelVersionContentSchema>["features"];
  commercial?: z.input<typeof modelVersionContentSchema>["commercial"];
}): ModelVersion {
  const content = modelVersionContentSchema.parse({
    schema_version: 1,
    features: { tool_calling_claimed: false, structured_output_claimed: false, streaming_claimed: false },
    commercial: null,
    ...input,
  });
  // Observation timestamps and lifecycle state are operational facts, not model identity.
  // Excluding them prevents a routine catalog rescan from masquerading as model drift.
  const metadataIdentity = {
    schema_version: content.schema_version,
    model_version_id: content.model_version_id,
    family_id: content.family_id,
    provider_id: content.provider_id,
    provider_model_name: content.provider_model_name,
    release: { provider_release_date: content.release.provider_release_date, knowledge_cutoff: content.release.knowledge_cutoff },
    modalities: content.modalities,
    context: content.context,
    features: content.features,
    commercial: content.commercial,
    provenance: content.provenance.map(source => ({ source_type: source.source_type, content_hash: source.content_hash })),
  };
  return freeze(modelVersionSchema.parse({ ...content, metadata_hash: canonicalSha256(metadataIdentity) }));
}

const capabilityClaimContentSchema = z.object({
  schema_version: z.literal(1), claim_id: entityId("capability-claim"), model_version_id: entityId("model-version"),
  capability: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), claimed_value: z.enum(["supported", "partial", "unsupported"]),
  source: z.object({ type: sourceSchema.shape.source_type, source_hash: phase4HashSchema }).strict(),
  observed_at: isoDate, expires_at: isoDate, confidence: z.enum(["low", "medium", "high"]),
}).strict();
export const capabilityClaimSchema = capabilityClaimContentSchema.extend({ claim_hash: phase4HashSchema }).strict();
export type CapabilityClaim = z.infer<typeof capabilityClaimSchema>;
export function createCapabilityClaim(input: Omit<z.input<typeof capabilityClaimContentSchema>, "schema_version">): CapabilityClaim {
  const content = capabilityClaimContentSchema.parse({ schema_version: 1, ...input });
  if (Date.parse(content.expires_at) <= Date.parse(content.observed_at)) throw new Error("CAPABILITY_CLAIM_EXPIRY_INVALID");
  return freeze(capabilityClaimSchema.parse({ ...content, claim_hash: canonicalSha256(content) }));
}

const observationContentSchema = z.object({
  schema_version: z.literal(1), observation_id: entityId("capability-observation"), execution_config_id: entityId("execution-config"),
  capability: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), probe_version: z.string().trim().min(1).max(160),
  result: z.object({ status: z.enum(["passed", "partial", "failed", "unsupported"]), valid_calls: z.number().int().nonnegative(), invalid_calls: z.number().int().nonnegative(), total_calls: z.number().int().positive() }).strict(),
  evidence_refs: z.array(entityId("artifact")).min(1), observed_at: isoDate,
}).strict().superRefine((value, context) => {
  if (value.result.valid_calls + value.result.invalid_calls !== value.result.total_calls) context.addIssue({ code: "custom", path: ["result"], message: "Probe call totals do not match" });
});
export const capabilityObservationSchema = observationContentSchema.extend({
  reliability: score, confidence_interval: z.object({ lower: score, upper: score }).strict(), observation_hash: phase4HashSchema,
}).strict();
export type CapabilityObservation = z.infer<typeof capabilityObservationSchema>;
export function createCapabilityObservation(input: Omit<z.input<typeof observationContentSchema>, "schema_version">): CapabilityObservation {
  const content = observationContentSchema.parse({ schema_version: 1, ...input });
  const reliability = content.result.valid_calls / content.result.total_calls;
  const confidence_interval = wilsonInterval(content.result.valid_calls, content.result.total_calls);
  return freeze(capabilityObservationSchema.parse({ ...content, reliability, confidence_interval, observation_hash: canonicalSha256(content) }));
}

const versionRefSchema = z.object({ id: z.string().trim().min(1).max(200), version: semver }).strict();
const executionConfigContentSchema = z.object({
  schema_version: z.literal(1), execution_config_id: entityId("execution-config"),
  model: z.object({ version_id: entityId("model-version"), deployment_id: entityId("deployment") }).strict(),
  runtime: z.object({ id: entityId("runtime"), adapter_version: semver }).strict(),
  prompt_profile: versionRefSchema, tool_bundle: versionRefSchema, context_policy: versionRefSchema,
  generation: z.object({ temperature: z.number().min(0).max(2), max_output_tokens: z.number().int().positive() }).strict(),
  environment: z.object({ class: z.string().trim().min(1).max(160), version: z.string().trim().min(1).max(80) }).strict(),
}).strict();
export const executionConfigurationSchema = executionConfigContentSchema.extend({ configuration_hash: phase4HashSchema }).strict();
export type ExecutionConfiguration = z.infer<typeof executionConfigurationSchema>;
export function createExecutionConfiguration(input: Omit<z.input<typeof executionConfigContentSchema>, "schema_version">): ExecutionConfiguration {
  const content = executionConfigContentSchema.parse({ schema_version: 1, ...input });
  return freeze(executionConfigurationSchema.parse({ ...content, configuration_hash: canonicalSha256(content) }));
}

const roleContentSchema = z.object({
  schema_version: z.literal(1), id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), version: semver,
  objective: z.string().trim().min(1).max(10_000), dimensions: z.record(z.string().regex(/^[a-z0-9][a-z0-9_-]*$/), score),
  hard_requirements: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)), disqualifiers: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)),
  minimum_tasks: z.object({ screened: z.number().int().positive(), qualified: z.number().int().positive(), high_confidence: z.number().int().positive() }).strict(),
}).strict().superRefine((value, context) => {
  const weight = Object.values(value.dimensions).reduce((sum, item) => sum + item, 0);
  if (Math.abs(weight - 1) > 1e-9) context.addIssue({ code: "custom", path: ["dimensions"], message: "Role dimension weights must sum to 1" });
  if (!(value.minimum_tasks.screened <= value.minimum_tasks.qualified && value.minimum_tasks.qualified <= value.minimum_tasks.high_confidence)) context.addIssue({ code: "custom", path: ["minimum_tasks"], message: "Role sample thresholds must be ordered" });
});
export const roleProfileSchema = roleContentSchema.extend({ content_hash: phase4HashSchema }).strict();
export type RoleProfile = z.infer<typeof roleProfileSchema>;
export function createRoleProfile(input: Omit<z.input<typeof roleContentSchema>, "schema_version">): RoleProfile {
  const content = roleContentSchema.parse({ schema_version: 1, ...input });
  return freeze(roleProfileSchema.parse({ ...content, content_hash: canonicalSha256(content) }));
}

export const DATASET_SPLITS = ["public_baseline", "validation", "private_holdout"] as const;
const benchmarkTaskSchema = z.object({
  task_id: entityId("benchmark-task"), version: z.number().int().positive(), split: z.enum(DATASET_SPLITS),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), prompt: z.string().trim().min(1).max(20_000),
  hidden_assertions: z.array(z.string().trim().min(1).max(2_000)), sensitivity: z.enum(["public", "internal", "private"]),
  data_policy: z.object({ allow_external_provider: z.boolean(), allowed_providers: z.array(z.string().regex(/^[a-z0-9-]+$/)) }).strict(),
  verifier: z.object({ type: z.literal("deterministic-json"), expected_answer_hash: phase4HashSchema, require_task_binding: z.boolean() }).strict(),
  provenance: z.object({ source: z.string().trim().min(1), license: z.string().trim().min(1), created_at: isoDate, updated_at: isoDate, contamination_risk: z.enum(["low", "medium", "high"]), human_verified_by: z.string().trim().min(1) }).strict(),
}).strict();
export type BenchmarkTask = z.infer<typeof benchmarkTaskSchema>;
const suiteContentSchema = z.object({
  schema_version: z.literal(1), benchmark_suite_id: entityId("benchmark-suite"), version: semver,
  target_role: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), evaluator_profile_ref: versionRefSchema, environment_profile_ref: versionRefSchema,
  tasks: z.array(benchmarkTaskSchema).min(1), license: z.object({ allowed_use: z.literal("evaluation") }).strict(),
}).strict().superRefine((value, context) => {
  const ids = new Set(value.tasks.map(task => `${task.task_id}@${task.version}`));
  if (ids.size !== value.tasks.length) context.addIssue({ code: "custom", path: ["tasks"], message: "Benchmark tasks must be unique" });
});
export const benchmarkSuiteSchema = suiteContentSchema.extend({
  splits: z.object({ public_baseline: z.number().int().nonnegative(), validation: z.number().int().nonnegative(), private_holdout: z.number().int().nonnegative() }).strict(),
  content_hash: phase4HashSchema,
}).strict();
export type BenchmarkSuite = z.infer<typeof benchmarkSuiteSchema>;
type BenchmarkTaskInput = Omit<z.input<typeof benchmarkTaskSchema>, "prompt" | "sensitivity" | "data_policy" | "provenance" | "verifier"> & Partial<Pick<z.input<typeof benchmarkTaskSchema>, "prompt" | "sensitivity" | "data_policy" | "provenance" | "verifier">>;
export function createBenchmarkSuite(input: Omit<z.input<typeof suiteContentSchema>, "schema_version" | "tasks"> & { tasks: BenchmarkTaskInput[] }): BenchmarkSuite {
  const tasks = input.tasks.map(task => benchmarkTaskSchema.parse({
    prompt: `Complete ${task.category} task ${task.task_id}. Return the exact solution marker "solution:${task.task_id}" in the answer field.`, sensitivity: task.split === "private_holdout" ? "private" : "public",
    data_policy: { allow_external_provider: task.split !== "private_holdout", allowed_providers: task.split === "private_holdout" ? ["fake", "local"] : [] },
    provenance: { source: "phase4-built-in", license: "evaluation", created_at: "2026-07-24T00:00:00.000Z", updated_at: "2026-07-24T00:00:00.000Z", contamination_risk: "low", human_verified_by: "human:local-owner" },
    verifier: { type: "deterministic-json", expected_answer_hash: canonicalSha256(`solution:${task.task_id}`), require_task_binding: true },
    ...task,
  }));
  const content = suiteContentSchema.parse({ schema_version: 1, ...input, tasks });
  const splits = Object.fromEntries(DATASET_SPLITS.map(split => [split, tasks.filter(task => task.split === split).length])) as Record<typeof DATASET_SPLITS[number], number>;
  return freeze(benchmarkSuiteSchema.parse({ ...content, splits, content_hash: canonicalSha256(content) }));
}

export const EVALUATION_FAILURE_TYPES = ["MODEL_FAILURE", "RUNTIME_FAILURE", "ADAPTER_FAILURE", "PROVIDER_FAILURE", "ACCOUNT_FAILURE", "TOOL_FAILURE", "ENVIRONMENT_FAILURE", "EVALUATOR_FAILURE", "DATASET_FAILURE", "POLICY_VIOLATION", "TIMEOUT", "CONTEXT_LIMIT", "RATE_LIMIT", "UNKNOWN"] as const;
export type EvaluationFailureType = typeof EVALUATION_FAILURE_TYPES[number];
export type DimensionScores = Record<string, number>;

export interface EvaluationManifest {
  schema_version: 1; evaluation_run_id: string; execution_config_id: string; configuration_hash: string;
  role_profile_ref: { id: string; version: string; hash: string }; benchmark_ref: { id: string; version: string; hash: string };
  evaluator: { profile_id: string; version: string }; environment: { image_digest: string; os: string; architecture: string };
  runtime: { id: string; adapter_version: string }; generation: { temperature: number; seed: number; max_output_tokens: number };
  budgets: { max_tasks: number; max_attempts_per_task: number; max_total_tokens: number; max_cost_units: number; max_wall_time_seconds: number; max_parallelism: number };
  started_at: string; manifest_hash: string;
}
export interface EvaluationAttempt {
  attempt_id: string; evaluation_run_id: string; task_id: string; task_version: number; split: typeof DATASET_SPLITS[number]; attempt: number;
  status: "COMPLETED" | "FAILED"; dimensions: DimensionScores; cost_units: number; latency_ms: number; output_hash: string;
  failure_type: EvaluationFailureType | null; critical_violations: string[]; completed_at: string;
}
export interface EvaluationRun {
  evaluation_run_id: string; idempotency_key: string; manifest: EvaluationManifest; status: "CREATED" | "RUNNING" | "INCOMPLETE" | "COMPLETED" | "FAILED";
  expected_attempts: number; completed_attempts: number; attempts: EvaluationAttempt[]; created_at: string; completed_at: string | null;
}
export type QualificationLevel = "Q0" | "Q1" | "Q2" | "Q3" | "Q4" | "Q5";
export interface RoleScorecard {
  schema_version: 1; scorecard_id: string; version: number; role_profile_ref: { id: string; version: string; hash: string };
  execution_config_ref: { id: string; hash: string }; benchmark_ref: { id: string; version: string; hash: string };
  dimensions: DimensionScores; utility: number; reliability: { timeout_rate: number; structured_output_rate: number; tool_protocol_rate: number };
  operations: { mean_cost_units: number; mean_latency_ms: number }; sample: { tasks: number; attempts: number };
  confidence: { level: "low" | "medium" | "high"; interval_95: { lower: number; upper: number }; standard_deviation: number };
  qualification_level: QualificationLevel; lifecycle: { status: "valid" | "stale" | "expired" | "quarantined"; valid_from: string; valid_until: string; reason: string | null };
  capability_observation_hashes: Record<string, string>;
  evidence_refs: string[]; evaluation_run_id: string; scorecard_hash: string;
}

export interface AliasRecord { provider_id: string; alias: string; resolved_model_version_id: string; metadata_hash: string; revision: number; observed_at: string }
export interface RequalificationJob { job_id: string; execution_config_id: string; type: "full" | "targeted" | "incident-driven" | "periodic"; reason: string; status: "pending" | "completed"; created_at: string }
export interface AuditEvent { event_id: string; event_type: string; subject_id: string; payload: Record<string, unknown>; occurred_at: string; event_hash: string }
export interface ArtifactRef { artifact_id: string; path: string; sha256: string; media_type: string; sensitivity: "public" | "internal" | "private"; producer_version: string; evaluation_run_id: string; model_version_id: string; benchmark_version: string }

export function confidenceFor(values: number[], thresholds: { qualified: number; high_confidence: number }): RoleScorecard["confidence"] {
  if (values.length === 0) return { level: "low", interval_95: { lower: 0, upper: 1 }, standard_deviation: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.length > 1 ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1) : 0;
  const sd = Math.sqrt(variance);
  const margin = values.length > 1 ? 1.96 * sd / Math.sqrt(values.length) : 0.5;
  const level = values.length >= thresholds.high_confidence ? "high" : values.length >= thresholds.qualified ? "medium" : "low";
  return { level, interval_95: { lower: clamp(mean - margin), upper: clamp(mean + margin) }, standard_deviation: sd };
}

export function paretoFrontier<T>(values: readonly T[], metrics: (value: T) => { quality: number; reliability: number; cost: number; latency: number }): T[] {
  return values.filter(candidate => !values.some(other => {
    if (other === candidate) return false;
    const a = metrics(other); const b = metrics(candidate);
    return a.quality >= b.quality && a.reliability >= b.reliability && a.cost <= b.cost && a.latency <= b.latency
      && (a.quality > b.quality || a.reliability > b.reliability || a.cost < b.cost || a.latency < b.latency);
  }));
}

function wilsonInterval(successes: number, total: number): { lower: number; upper: number } {
  const p = successes / total; const z = 1.96; const denominator = 1 + z * z / total;
  const center = (p + z * z / (2 * total)) / denominator;
  const margin = z * Math.sqrt((p * (1 - p) + z * z / (4 * total)) / total) / denominator;
  return { lower: clamp(center - margin), upper: clamp(center + margin) };
}
function clamp(value: number): number { return Math.max(0, Math.min(1, value)); }
function freeze<T>(value: T): T { return Object.freeze(value); }
