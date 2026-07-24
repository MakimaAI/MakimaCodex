import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema } from "../../phase1/core/shared/actor";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const id = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));
const namespacedTypeSchema = z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/);
const definitionRefSchema = z.object({ id: z.string().trim().min(1).max(300), version: semverSchema, hash: hashSchema }).strict();

export const reviewRequestSchema = z.object({
  schema_version: z.literal(1),
  review_request_id: id("review-request"),
  task_id: id("task"),
  contract_revision_id: id("contract-revision"),
  assignment_id: id("assignment"),
  execution_id: id("execution"),
  evidence_package_id: z.string().regex(/^evidence-package:[a-f0-9]{64}$/),
  requested_scope: z.array(namespacedTypeSchema).min(1).max(32),
  trigger: z.discriminatedUnion("type", [
    z.object({ type: z.literal("workflow-stage"), stage: z.string().trim().min(1).max(160) }).strict(),
    z.object({ type: z.literal("manual"), reason: z.string().trim().min(1).max(2_000) }).strict(),
    z.object({ type: z.literal("repair"), repair_proposal_id: id("repair-proposal") }).strict(),
  ]),
  created_by: actorSchema,
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => unique(value.requested_scope, context, ["requested_scope"]));
export type ReviewRequest = z.infer<typeof reviewRequestSchema>;
export function parseReviewRequest(input: unknown): ReviewRequest { return reviewRequestSchema.parse(input); }

const reviewSnapshotContentSchema = z.object({
  schema_version: z.literal(1),
  review_snapshot_id: id("review-snapshot"),
  contract: z.object({ revision_id: id("contract-revision"), revision: z.number().int().positive(), hash: hashSchema }).strict(),
  source: z.object({ base_commit: z.string().trim().min(1).max(500), result_tree_hash: hashSchema, diff_hash: hashSchema }).strict(),
  evidence: z.object({ package_id: z.string().regex(/^evidence-package:[a-f0-9]{64}$/), package_hash: hashSchema }).strict(),
  workflow: definitionRefSchema,
  policy: definitionRefSchema,
  created_at: z.string().datetime(),
}).strict();

export const reviewSnapshotSchema = reviewSnapshotContentSchema.extend({ snapshot_hash: hashSchema }).strict().superRefine((value, context) => {
  const { snapshot_hash: ignored, ...content } = value;
  if (canonicalSha256(content) !== value.snapshot_hash) context.addIssue({ code: "custom", path: ["snapshot_hash"], message: "Review snapshot content hash mismatch" });
});
export type ReviewSnapshot = z.infer<typeof reviewSnapshotSchema>;

export function createReviewSnapshot(input: unknown): ReviewSnapshot {
  const content = reviewSnapshotContentSchema.parse({ schema_version: 1, ...(input as object) });
  return deepFreeze(reviewSnapshotSchema.parse({ ...content, snapshot_hash: canonicalSha256(content) }));
}

export function assertReviewSnapshotCurrent(expectedInput: unknown, currentInput: unknown): true {
  try {
    const expected = reviewSnapshotSchema.parse(expectedInput);
    const current = reviewSnapshotSchema.parse(currentInput);
    if (expected.snapshot_hash !== current.snapshot_hash) throw new Error("mismatch");
    return true;
  } catch { throw new Error("REVIEW_SNAPSHOT_STALE"); }
}

export const REVIEWER_CAPABILITIES = [
  "diff-analysis", "repository-navigation", "architecture-reasoning", "security-analysis", "multimodal-review",
  "browser-observation", "accessibility-analysis", "performance-analysis", "structured-findings", "evidence-citation",
  "contract-traceability",
] as const;
export type ReviewerCapability = typeof REVIEWER_CAPABILITIES[number];

const profileContentSchema = z.object({
  schema_version: z.literal(1),
  review_profile_id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
  version: semverSchema,
  objective: z.string().trim().min(1).max(20_000),
  required_inputs: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).min(1).max(64),
  required_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)).min(1).max(REVIEWER_CAPABILITIES.length),
  preferred_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)).max(REVIEWER_CAPABILITIES.length),
  workspace: z.object({ source_mode: z.literal("read-only"), temp_write: z.enum(["allowed", "denied"]), network: z.literal("denied") }).strict(),
  checks: z.record(z.string().regex(/^[a-z0-9][a-z0-9-]*$/), z.boolean()),
  output_schema_ref: z.object({ id: z.string().trim().min(1).max(300), version: z.number().int().positive() }).strict(),
  renderer_ref: z.object({ id: z.string().trim().min(1).max(300), version: semverSchema }).strict(),
  budgets: z.object({ max_wall_time_seconds: z.number().int().positive().max(86_400), max_output_tokens: z.number().int().positive().max(1_000_000) }).strict(),
  independence: z.object({
    different_session: z.literal("required"),
    different_context: z.literal("required"),
    different_provider: z.enum(["preferred", "required"]),
  }).strict(),
  extensions: z.record(z.string(), z.unknown()),
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  unique(value.required_inputs, context, ["required_inputs"]);
  unique(value.required_capabilities, context, ["required_capabilities"]);
  unique(value.preferred_capabilities, context, ["preferred_capabilities"]);
  const overlap = value.preferred_capabilities.filter(item => value.required_capabilities.includes(item));
  if (overlap.length > 0) context.addIssue({ code: "custom", path: ["preferred_capabilities"], message: "Required and preferred capabilities cannot overlap" });
});

export const reviewProfileSchema = profileContentSchema.extend({ content_hash: hashSchema }).strict().superRefine((value, context) => {
  const { content_hash: ignored, ...content } = value;
  if (canonicalSha256(content) !== value.content_hash) context.addIssue({ code: "custom", path: ["content_hash"], message: "Review profile content hash mismatch" });
});
export type ReviewProfile = z.infer<typeof reviewProfileSchema>;

export function createReviewProfile(input: unknown): ReviewProfile {
  const source = input && typeof input === "object" ? input as Record<string, unknown> : {};
  const { content_hash: ignoredHash, schema_version: ignoredVersion, ...rest } = source;
  const content = profileContentSchema.parse({ schema_version: 1, ...rest });
  return deepFreeze(reviewProfileSchema.parse({ ...content, content_hash: canonicalSha256(content) }));
}

export function assertPinnedReviewProfile(
  ref: { id: string; version: string; hash: string },
  profileInput: unknown,
): true {
  const profile = reviewProfileSchema.parse(profileInput);
  if (ref.id !== profile.review_profile_id || ref.version !== profile.version || ref.hash !== profile.content_hash) {
    throw new Error("REVIEW_PROFILE_HASH_MISMATCH");
  }
  return true;
}

export const REVIEW_UNIT_STATUSES = ["CREATED", "WAITING_PREREQUISITES", "READY", "RUNNING", "COMPLETED", "FAILED", "CANCELLED", "SUPERSEDED"] as const;
export const REVIEW_PLAN_STATUSES = [
  "CREATED", "WAITING_PREREQUISITES", "READY", "RUNNING", "COLLECTING", "VALIDATING_FINDINGS", "ADJUDICATING", "COMPLETED",
  "PASSED", "CHANGES_REQUESTED", "BLOCKED", "NEEDS_HUMAN", "INCONCLUSIVE", "CANCELLED", "SUPERSEDED",
] as const;
export type ReviewPlanStatus = typeof REVIEW_PLAN_STATUSES[number];

export const reviewUnitSchema = z.object({
  review_unit_id: id("review-unit"),
  review_type: namespacedTypeSchema,
  profile_ref: z.object({ id: z.string().trim().min(1).max(160), version: semverSchema, hash: hashSchema }).strict(),
  required: z.boolean(),
  required_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)).min(1),
  preferred_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)),
  depends_on: z.array(id("review-unit")),
  prerequisites: z.array(z.string().regex(/^[a-z0-9][a-z0-9.-]*$/)).max(32),
}).strict();

export const reviewPlanSchema = z.object({
  schema_version: z.literal(1),
  review_plan_id: id("review-plan"),
  revision: z.number().int().positive(),
  previous_revision_hash: hashSchema.nullable(),
  review_request_id: id("review-request"),
  task_id: id("task"),
  snapshot: reviewSnapshotSchema,
  risk: z.object({ level: z.enum(["low", "medium", "high", "critical"]), reasons: z.array(z.string().trim().min(1).max(160)).max(64) }).strict(),
  review_units: z.array(reviewUnitSchema).min(1).max(32),
  execution_strategy: z.object({ parallel_groups: z.array(z.array(id("review-unit")).min(1)).min(1).max(32) }).strict(),
  adjudication_policy_ref: definitionRefSchema,
  quorum: z.object({
    required_review_types: z.array(namespacedTypeSchema).min(1),
    minimum_independent_providers: z.number().int().positive().max(16),
    minimum_independence_score: z.number().int().nonnegative().max(9),
    human_approval: z.enum(["not-required", "required"]),
  }).strict(),
  budget: z.object({
    max_wall_time_seconds: z.number().int().positive().max(604_800),
    max_total_output_tokens: z.number().int().positive().max(10_000_000),
    max_review_units: z.number().int().positive().max(64),
    max_parallel_units: z.number().int().positive().max(32),
  }).strict(),
  limits: z.object({
    max_review_rounds: z.number().int().positive().max(100),
    max_repair_rounds: z.number().int().positive().max(100),
    max_evidence_requests: z.number().int().nonnegative().max(1_000),
    max_adjudication_rounds: z.number().int().positive().max(100),
    max_total_cost_units: z.number().int().positive().max(1_000_000),
  }).strict(),
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if ((value.revision === 1) !== (value.previous_revision_hash === null)) {
    context.addIssue({ code: "custom", path: ["previous_revision_hash"], message: "Review plan revisions must be hash-linked" });
  }
  if (value.review_units.length > value.budget.max_review_units) context.addIssue({ code: "custom", path: ["review_units"], message: "Review unit budget exceeded" });
  if (value.execution_strategy.parallel_groups.some(group => group.length > value.budget.max_parallel_units)) {
    context.addIssue({ code: "custom", path: ["execution_strategy"], message: "Review parallelism budget exceeded" });
  }
  const units = new Set(value.review_units.map(unit => unit.review_unit_id));
  if (units.size !== value.review_units.length) context.addIssue({ code: "custom", path: ["review_units"], message: "Review unit ids must be unique" });
  for (const unit of value.review_units) {
    for (const dependency of unit.depends_on) if (!units.has(dependency)) context.addIssue({ code: "custom", path: ["review_units"], message: `Unknown review dependency: ${dependency}` });
  }
  const scheduled = value.execution_strategy.parallel_groups.flat();
  if (scheduled.some(unit => !units.has(unit)) || new Set(scheduled).size !== scheduled.length || scheduled.length !== units.size) {
    context.addIssue({ code: "custom", path: ["execution_strategy"], message: "Every review unit must be scheduled exactly once" });
  }
  const availableReviewTypes = new Set(value.review_units.filter(unit => unit.required).map(unit => unit.review_type));
  if (value.quorum.required_review_types.some(type => !availableReviewTypes.has(type))) {
    context.addIssue({ code: "custom", path: ["quorum", "required_review_types"], message: "Quorum review types must map to required review units" });
  }
});
export type ReviewPlan = z.infer<typeof reviewPlanSchema>;
export function parseReviewPlan(input: unknown): ReviewPlan { return reviewPlanSchema.parse(input); }
export function hashReviewPlan(input: unknown): string { return canonicalSha256(parseReviewPlan(input)); }

export const reviewPlanStateSchema = z.object({
  schema_version: z.literal(1),
  review_plan_id: id("review-plan"),
  snapshot_hash: hashSchema,
  status: z.enum(REVIEW_PLAN_STATUSES),
  unit_states: z.array(z.object({
    review_unit_id: id("review-unit"),
    status: z.enum(REVIEW_UNIT_STATUSES),
    review_execution_id: id("review-execution").nullable(),
    result_artifact_id: id("artifact").nullable(),
  }).strict()).min(1).max(32),
  counters: z.object({
    review_rounds: z.number().int().nonnegative(),
    repair_rounds: z.number().int().nonnegative(),
    evidence_requests: z.number().int().nonnegative(),
    adjudication_rounds: z.number().int().nonnegative(),
    total_cost_units: z.number().int().nonnegative(),
  }).strict(),
  aggregate_version: z.number().int().positive(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (Date.parse(value.updated_at) < Date.parse(value.created_at)) context.addIssue({ code: "custom", path: ["updated_at"], message: "Review state update cannot predate creation" });
  if (new Set(value.unit_states.map(unit => unit.review_unit_id)).size !== value.unit_states.length) {
    context.addIssue({ code: "custom", path: ["unit_states"], message: "Review unit state ids must be unique" });
  }
  for (const unit of value.unit_states) {
    if ((unit.status === "RUNNING") !== (unit.review_execution_id !== null)) {
      context.addIssue({ code: "custom", path: ["unit_states"], message: "Only running units require a review execution" });
    }
    if ((unit.status === "COMPLETED") !== (unit.result_artifact_id !== null)) {
      context.addIssue({ code: "custom", path: ["unit_states"], message: "Only completed units require a result artifact" });
    }
  }
});
export type ReviewPlanState = z.infer<typeof reviewPlanStateSchema>;
export function parseReviewPlanState(input: unknown): ReviewPlanState { return reviewPlanStateSchema.parse(input); }

export function assertPlanStateMatchesPlan(planInput: unknown, stateInput: unknown): true {
  const plan = reviewPlanSchema.parse(planInput);
  const state = reviewPlanStateSchema.parse(stateInput);
  const plannedUnits = plan.review_units.map(unit => unit.review_unit_id).sort();
  const stateUnits = state.unit_states.map(unit => unit.review_unit_id).sort();
  if (
    state.review_plan_id !== plan.review_plan_id
    || state.snapshot_hash !== plan.snapshot.snapshot_hash
    || JSON.stringify(stateUnits) !== JSON.stringify(plannedUnits)
  ) throw new Error("REVIEW_PLAN_STATE_MISMATCH");
  return true;
}

const reviewPlanTransitions: Readonly<Record<ReviewPlanStatus, readonly ReviewPlanStatus[]>> = {
  CREATED: ["WAITING_PREREQUISITES", "CANCELLED"],
  WAITING_PREREQUISITES: ["READY", "BLOCKED", "INCONCLUSIVE", "CANCELLED"],
  READY: ["RUNNING", "CANCELLED"],
  RUNNING: ["COLLECTING", "BLOCKED", "INCONCLUSIVE", "CANCELLED"],
  COLLECTING: ["VALIDATING_FINDINGS", "INCONCLUSIVE", "CANCELLED"],
  VALIDATING_FINDINGS: ["ADJUDICATING", "INCONCLUSIVE", "NEEDS_HUMAN", "CANCELLED"],
  ADJUDICATING: ["COMPLETED", "NEEDS_HUMAN", "INCONCLUSIVE", "CANCELLED"],
  COMPLETED: ["PASSED", "CHANGES_REQUESTED", "BLOCKED", "NEEDS_HUMAN", "INCONCLUSIVE"],
  PASSED: ["SUPERSEDED"], CHANGES_REQUESTED: ["SUPERSEDED"], BLOCKED: ["SUPERSEDED"], NEEDS_HUMAN: ["SUPERSEDED"],
  INCONCLUSIVE: ["SUPERSEDED"], CANCELLED: [], SUPERSEDED: [],
};
export function transitionReviewPlan(current: ReviewPlanStatus, next: ReviewPlanStatus): ReviewPlanStatus {
  if (current === next || !reviewPlanTransitions[current]?.includes(next)) throw new Error(`Invalid review plan transition: ${current} -> ${next}`);
  return next;
}

export const FINDING_SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export type FindingSeverity = typeof FINDING_SEVERITIES[number];
export const EVIDENCE_STRENGTHS = ["AUTHORITATIVE", "STRONG", "SUPPORTED", "OPINION", "UNSUPPORTED"] as const;
export const FINDING_STATUSES = [
  "PROPOSED", "VALIDATING", "CONFIRMED", "DISMISSED", "DUPLICATE", "RESOLVED", "VERIFIED_RESOLVED", "WAIVED", "SUPERSEDED", "STALE",
] as const;
export type FindingStatus = typeof FINDING_STATUSES[number];

const repositoryPathSchema = z.string().trim().min(1).max(4_000).superRefine((value, context) => {
  const normalized = value.replaceAll("\\", "/");
  if (normalized.startsWith("/") || /^[A-Za-z]:/.test(normalized) || normalized.split("/").includes("..")) {
    context.addIssue({ code: "custom", message: "Code anchor must use a safe repository-relative path" });
  }
});

export const findingAnchorSchema = z.object({
  type: z.literal("code"),
  path: repositoryPathSchema,
  line_start: z.number().int().positive(),
  line_end: z.number().int().positive(),
  file_hash: hashSchema,
  symbol: z.object({ type: z.enum(["function", "method", "class", "module", "json-pointer", "yaml-path"]), name: z.string().trim().min(1).max(500) }).strict().nullable(),
  snippet_hash: hashSchema,
}).strict().refine(value => value.line_start <= value.line_end, { path: ["line_end"], message: "Code anchor line range is reversed" });

export const reviewFindingSchema = z.object({
  schema_version: z.literal(1),
  finding_id: id("review-finding"),
  finding_key: z.string().regex(/^FIND-[A-Z0-9-]+$/),
  review_plan_id: id("review-plan"),
  review_unit_id: id("review-unit"),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
  proposed_severity: z.enum(FINDING_SEVERITIES),
  effective_severity: z.enum(FINDING_SEVERITIES).nullable(),
  confidence: z.number().min(0).max(1),
  status: z.enum(FINDING_STATUSES),
  claim: z.string().trim().min(1).max(20_000),
  impact: z.string().trim().min(1).max(20_000),
  scope: z.object({ snapshot_hash: hashSchema, contract_revision_id: id("contract-revision"), source_tree_hash: hashSchema, diff_hash: hashSchema }).strict(),
  anchors: z.array(findingAnchorSchema).min(1).max(64),
  contract_refs: z.array(z.string().trim().min(1).max(300)).max(64),
  evidence_refs: z.array(z.string().trim().min(1).max(500)).max(256),
  evidence_strength: z.enum(EVIDENCE_STRENGTHS),
  proposed_by: z.object({ reviewer_binding_id: id("reviewer-binding") }).strict(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  duplicate_of: id("review-finding").nullable(),
}).strict().superRefine((value, context) => {
  if (Date.parse(value.updated_at) < Date.parse(value.created_at)) context.addIssue({ code: "custom", path: ["updated_at"], message: "Finding update cannot predate creation" });
  if (value.status === "DUPLICATE" && value.duplicate_of === null) context.addIssue({ code: "custom", path: ["duplicate_of"], message: "Duplicate finding requires a target" });
  if (value.status !== "DUPLICATE" && value.duplicate_of !== null) context.addIssue({ code: "custom", path: ["duplicate_of"], message: "Only duplicate findings may link duplicate_of" });
  if (["CONFIRMED", "RESOLVED", "VERIFIED_RESOLVED", "WAIVED"].includes(value.status) && value.effective_severity === null) {
    context.addIssue({ code: "custom", path: ["effective_severity"], message: "Validated findings require policy severity" });
  }
  if (value.status === "CONFIRMED" && value.evidence_strength === "UNSUPPORTED") context.addIssue({ code: "custom", path: ["evidence_strength"], message: "Unsupported findings cannot be confirmed" });
});
export type ReviewFinding = z.infer<typeof reviewFindingSchema>;
export function parseReviewFinding(input: unknown): ReviewFinding { return reviewFindingSchema.parse(input); }

const findingTransitions: Readonly<Record<FindingStatus, readonly FindingStatus[]>> = {
  PROPOSED: ["VALIDATING", "DISMISSED", "DUPLICATE", "STALE"],
  VALIDATING: ["CONFIRMED", "DISMISSED", "DUPLICATE", "STALE"],
  CONFIRMED: ["RESOLVED", "WAIVED", "SUPERSEDED", "STALE"],
  RESOLVED: ["VERIFIED_RESOLVED", "CONFIRMED", "STALE"],
  DISMISSED: ["SUPERSEDED"], DUPLICATE: ["SUPERSEDED"], VERIFIED_RESOLVED: ["STALE"], WAIVED: ["STALE"], SUPERSEDED: [], STALE: [],
};
export function transitionFinding(current: FindingStatus, next: FindingStatus): FindingStatus {
  if (current === next || !findingTransitions[current]?.includes(next)) throw new Error(`Invalid finding transition: ${current} -> ${next}`);
  return next;
}

export const waiverSchema = z.object({
  schema_version: z.literal(1),
  waiver_id: id("review-waiver"),
  finding_id: id("review-finding"),
  decision: z.literal("ACCEPTED_RISK"),
  rationale: z.string().trim().min(1).max(10_000),
  approved_by: actorSchema.refine(actor => actor.type === "human", "Waivers require a human approver"),
  expires_at: z.string().datetime().nullable(),
  conditions: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).max(64),
  snapshot_hash: hashSchema,
  finding_snapshot_hash: hashSchema,
  finding_hash: hashSchema,
  effective_severity_at_approval: z.enum(FINDING_SEVERITIES),
  created_at: z.string().datetime(),
  status: z.enum(["ACTIVE", "EXPIRED", "REVOKED", "STALE"]),
}).strict();
export type Waiver = z.infer<typeof waiverSchema>;

export function createWaiver(input: {
  waiver_id: string;
  finding: ReviewFinding;
  decision: "ACCEPTED_RISK";
  rationale: string;
  approved_by: z.infer<typeof actorSchema>;
  expires_at: string | null;
  conditions: string[];
  snapshot_hash: string;
  created_at: string;
}): Waiver {
  const finding = parseReviewFinding(input.finding);
  if (finding.status !== "CONFIRMED") throw new Error("WAIVER_FINDING_NOT_CONFIRMED");
  if (finding.effective_severity === "CRITICAL") throw new Error("CRITICAL_FINDING_WAIVER_FORBIDDEN");
  if (finding.scope.snapshot_hash !== input.snapshot_hash) throw new Error("WAIVER_SNAPSHOT_MISMATCH");
  if (input.expires_at && Date.parse(input.expires_at) <= Date.parse(input.created_at)) throw new Error("WAIVER_EXPIRED_AT_CREATION");
  return waiverSchema.parse({
    schema_version: 1,
    waiver_id: input.waiver_id,
    finding_id: finding.finding_id,
    decision: input.decision,
    rationale: input.rationale,
    approved_by: input.approved_by,
    expires_at: input.expires_at,
    conditions: input.conditions,
    snapshot_hash: input.snapshot_hash,
    finding_snapshot_hash: finding.scope.snapshot_hash,
    finding_hash: waiverFindingHash(finding),
    effective_severity_at_approval: finding.effective_severity,
    created_at: input.created_at,
    status: "ACTIVE",
  });
}

const severityRank: Record<FindingSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export function assertWaiverApplies(waiverInput: unknown, findingInput: unknown, snapshotHash: string, at: string): true {
  const waiver = waiverSchema.parse(waiverInput);
  const finding = parseReviewFinding(findingInput);
  if (waiver.effective_severity_at_approval === "CRITICAL" || finding.effective_severity === "CRITICAL") throw new Error("CRITICAL_FINDING_WAIVER_FORBIDDEN");
  if (waiver.status !== "ACTIVE") throw new Error("WAIVER_NOT_ACTIVE");
  if (waiver.snapshot_hash !== snapshotHash || waiver.finding_snapshot_hash !== finding.scope.snapshot_hash) throw new Error("WAIVER_SNAPSHOT_MISMATCH");
  if (waiver.finding_id !== finding.finding_id) throw new Error("WAIVER_FINDING_MISMATCH");
  if (waiver.finding_hash !== waiverFindingHash(finding)) throw new Error("WAIVER_FINDING_CHANGED");
  if (waiver.expires_at && Date.parse(at) >= Date.parse(waiver.expires_at)) throw new Error("WAIVER_EXPIRED");
  if (!finding.effective_severity || severityRank[finding.effective_severity] > severityRank[waiver.effective_severity_at_approval]) throw new Error("WAIVER_SEVERITY_INCREASED");
  return true;
}

function waiverFindingHash(finding: ReviewFinding): string {
  const { created_at: ignoredCreatedAt, updated_at: ignoredUpdatedAt, ...stableFinding } = finding;
  return canonicalSha256(stableFinding);
}

function unique(values: readonly string[], context: z.RefinementCtx, path: (string | number)[]): void {
  if (new Set(values).size !== values.length) context.addIssue({ code: "custom", path, message: "Values must be unique" });
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
