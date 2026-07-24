import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  assertPinnedReviewProfile,
  parseReviewPlan,
  reviewProfileSchema,
  type ReviewPlan,
} from "../core/domain";
import type {
  CompileReviewPlanInput,
  ReviewChangedFile,
  ReviewPlanningPolicy,
} from "./types";

const REVIEW_TYPES = {
  spec: "opencodex.spec-compliance",
  quality: "opencodex.code-quality",
  security: "opencodex.security",
  migration: "opencodex.data-migration",
  rollback: "opencodex.rollback",
  visual: "opencodex.visual",
  accessibility: "opencodex.accessibility",
  dependencySecurity: "opencodex.dependency-security",
  compatibility: "opencodex.backward-compatibility",
  performance: "opencodex.performance",
} as const;

const CODE_EXTENSIONS = new Set([
  ".c", ".cc", ".cpp", ".cs", ".css", ".go", ".graphql", ".h", ".html", ".java", ".js", ".jsx",
  ".kt", ".php", ".proto", ".py", ".rb", ".rs", ".scss", ".sql", ".svelte", ".swift", ".ts", ".tsx", ".vue",
]);
const FRONTEND_EXTENSIONS = new Set([".css", ".html", ".jsx", ".scss", ".svelte", ".tsx", ".vue"]);

export const DEFAULT_REVIEW_PLANNING_POLICY: ReviewPlanningPolicy = Object.freeze({
  quorum_by_risk: Object.freeze({
    low: Object.freeze({ minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" }),
    medium: Object.freeze({ minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" }),
    high: Object.freeze({ minimum_independent_providers: 1, minimum_independence_score: 3, human_approval: "not-required" }),
    critical: Object.freeze({ minimum_independent_providers: 2, minimum_independence_score: 4, human_approval: "required" }),
  }),
  budget: Object.freeze({
    max_wall_time_seconds: 14_400,
    max_total_output_tokens: 500_000,
    max_review_units: 32,
    max_parallel_units: 8,
  }),
  limits: Object.freeze({
    max_review_rounds: 3,
    max_repair_rounds: 3,
    max_evidence_requests: 5,
    max_adjudication_rounds: 2,
    max_total_cost_units: 1_000,
  }),
});

interface Selection {
  required: boolean;
}

export function compileReviewPlan(input: CompileReviewPlanInput): ReviewPlan {
  const policy = input.planning_policy ?? DEFAULT_REVIEW_PLANNING_POLICY;
  const selection = new Map<string, Selection>();
  const require = (reviewType: string) => selection.set(reviewType, { required: true });

  for (const requested of normalizeTypes(input.requested_review_types)) require(requested);

  const facts = classifyChanges(input.changes.changed_files);
  const normalizedReasons = sortedUnique(input.risk.reasons.map(normalizeFact));
  const reasonSet = new Set(normalizedReasons);
  if (facts.code) {
    require(REVIEW_TYPES.spec);
    require(REVIEW_TYPES.quality);
  }
  if (input.risk.level === "critical" || facts.credentials || [...reasonSet].some(reason => /credential|authentication|authorization|secret/.test(reason))) {
    require(REVIEW_TYPES.security);
  }
  if (facts.migration) {
    require(REVIEW_TYPES.migration);
    require(REVIEW_TYPES.rollback);
  }
  if (facts.frontend) {
    require(REVIEW_TYPES.visual);
    require(REVIEW_TYPES.accessibility);
  }
  if (input.changes.dependency_changes.some(change => change.change === "added")) {
    require(REVIEW_TYPES.dependencySecurity);
  }
  if (facts.apiContract || input.changes.api_contract_changed) require(REVIEW_TYPES.compatibility);
  if (facts.performanceCritical || input.changes.performance_critical_changed) require(REVIEW_TYPES.performance);

  for (const reviewType of normalizeTypes(input.recommendations.add_review_types)) {
    if (!selection.has(reviewType)) selection.set(reviewType, { required: false });
  }
  for (const reviewType of normalizeTypes(input.recommendations.remove_review_types)) {
    if (selection.get(reviewType)?.required === false) selection.delete(reviewType);
  }

  const selected = [...selection.entries()].sort(([left], [right]) => left.localeCompare(right));
  if (selected.length === 0) throw new Error("REVIEW_PLAN_EMPTY");
  if (selected.length > policy.budget.max_review_units) throw new Error("REVIEW_PLAN_UNIT_BUDGET_EXCEEDED");

  const units = selected.map(([reviewType, state]) => {
    const definition = input.registry.resolve(reviewType);
    if (!definition) throw new Error(`REVIEW_TYPE_NOT_REGISTERED:${reviewType}`);
    const rawProfile = input.profiles[reviewType];
    if (!rawProfile) throw new Error(`REVIEW_PROFILE_NOT_FOUND:${reviewType}`);
    const profile = reviewProfileSchema.parse(rawProfile);
    try {
      assertPinnedReviewProfile(definition.profile_ref, profile);
    } catch {
      throw new Error(`REVIEW_PROFILE_PIN_MISMATCH:${reviewType}`);
    }
    return {
      review_unit_id: deterministicUnitId(input.review_plan_id, reviewType),
      review_type: reviewType,
      profile_ref: { ...definition.profile_ref },
      required: state.required,
      required_capabilities: sortedUnique(definition.required_capabilities),
      preferred_capabilities: sortedUnique(definition.preferred_capabilities),
      depends_on: [],
      prerequisites: sortedUnique(definition.prerequisites),
    };
  });

  const parallelGroups = chunk(
    units.map(unit => unit.review_unit_id).sort(),
    policy.budget.max_parallel_units,
  );
  const riskQuorum = policy.quorum_by_risk[input.risk.level];
  return parseReviewPlan({
    schema_version: 1,
    review_plan_id: input.review_plan_id,
    revision: input.revision,
    previous_revision_hash: input.previous_revision_hash,
    review_request_id: input.review_request_id,
    task_id: input.task_id,
    snapshot: input.snapshot,
    risk: { level: input.risk.level, reasons: normalizedReasons },
    review_units: units,
    execution_strategy: { parallel_groups: parallelGroups },
    adjudication_policy_ref: input.adjudication_policy_ref,
    quorum: {
      required_review_types: units.filter(unit => unit.required).map(unit => unit.review_type).sort(),
      ...riskQuorum,
    },
    budget: { ...policy.budget },
    limits: { ...policy.limits },
    created_at: input.created_at,
  });
}

function classifyChanges(files: readonly ReviewChangedFile[]): {
  code: boolean;
  credentials: boolean;
  migration: boolean;
  frontend: boolean;
  apiContract: boolean;
  performanceCritical: boolean;
} {
  const result = { code: false, credentials: false, migration: false, frontend: false, apiContract: false, performanceCritical: false };
  for (const file of files) {
    const path = normalizePath(file.path);
    const extension = extensionOf(path);
    const tags = new Set(file.classifications.map(normalizeFact));
    if (CODE_EXTENSIONS.has(extension) || tags.has("code")) result.code = true;
    if (/(^|\/)(credentials?|secrets?|auth)(\/|\.|-|_)/.test(path) || tags.has("credential") || tags.has("credentials")) result.credentials = true;
    if (/(^|\/)(migrations?|schema-migrations?)(\/|\.|-|_)/.test(path) || tags.has("migration")) result.migration = true;
    if (FRONTEND_EXTENSIONS.has(extension) || /(^|\/)(frontend|ui|components|pages)(\/|$)/.test(path) || tags.has("frontend")) result.frontend = true;
    if (/(^|\/)(openapi|swagger)(\/|\.|-|_)|\.(graphql|proto)$/.test(path) || tags.has("api-contract")) result.apiContract = true;
    if (tags.has("performance-critical") || tags.has("hot-path")) result.performanceCritical = true;
  }
  return result;
}

function normalizePath(input: string): string {
  const path = input.trim().replaceAll("\\", "/").toLowerCase();
  if (!path || path.startsWith("/") || /^[a-z]:/.test(path) || path.split("/").includes("..")) throw new Error(`INVALID_REVIEW_CHANGE_PATH:${input}`);
  return path;
}

function extensionOf(path: string): string {
  const filename = path.split("/").at(-1) ?? path;
  const position = filename.lastIndexOf(".");
  return position < 0 ? "" : filename.slice(position);
}

function normalizeFact(value: string): string {
  return value.trim().toLowerCase().replaceAll("_", "-").replaceAll(" ", "-");
}

function normalizeTypes(values: readonly string[]): string[] {
  const normalized = sortedUnique(values.map(value => value.trim().toLowerCase()));
  for (const value of normalized) {
    if (!/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/.test(value)) throw new Error(`INVALID_REVIEW_TYPE:${value}`);
  }
  return normalized;
}

function sortedUnique<T extends string>(values: readonly T[]): T[] {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function deterministicUnitId(planId: string, reviewType: string): string {
  const digest = canonicalSha256({ plan_id: planId, review_type: reviewType }).slice("sha256:".length, "sha256:".length + 24);
  return `review-unit:${digest}`;
}

function chunk<T>(values: readonly T[], size: number): T[][] {
  if (!Number.isInteger(size) || size <= 0) throw new Error("INVALID_REVIEW_PARALLELISM_BUDGET");
  const result: T[][] = [];
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size));
  return result;
}
