import { z } from "zod";

export const reviewLimitsSchema = z.object({
  max_review_rounds: z.number().int().positive(),
  max_repair_rounds: z.number().int().positive(),
  max_evidence_requests: z.number().int().nonnegative(),
  max_adjudication_rounds: z.number().int().positive(),
  max_total_cost_units: z.number().int().positive(),
}).strict();

export const reviewBudgetSchema = z.object({
  max_wall_time_seconds: z.number().int().positive(),
  max_total_output_tokens: z.number().int().positive(),
  max_review_units: z.number().int().positive(),
  max_parallel_units: z.number().int().positive(),
}).strict();

const reviewUsageSchema = z.object({
  review_rounds: z.number().int().nonnegative(),
  repair_rounds: z.number().int().nonnegative(),
  evidence_requests: z.number().int().nonnegative(),
  adjudication_rounds: z.number().int().nonnegative(),
  total_cost_units: z.number().int().nonnegative(),
  wall_time_seconds: z.number().int().nonnegative(),
  total_output_tokens: z.number().int().nonnegative(),
  review_units: z.number().int().nonnegative(),
  parallel_units: z.number().int().nonnegative(),
}).strict();

const circuitStateSchema = z.object({
  recurring_finding_occurrences: z.number().int().nonnegative(),
  consecutive_unsupported_findings: z.number().int().nonnegative(),
}).strict();

const reviewLimitInputSchema = z.object({
  limits: reviewLimitsSchema,
  budget: reviewBudgetSchema,
  usage: reviewUsageSchema,
  circuit: circuitStateSchema,
}).strict();

export type ReviewLimits = z.infer<typeof reviewLimitsSchema>;
export type ReviewBudget = z.infer<typeof reviewBudgetSchema>;
export type ReviewUsage = z.infer<typeof reviewUsageSchema>;
export type ReviewLimitViolation =
  | "MAX_REVIEW_ROUNDS"
  | "MAX_REPAIR_ROUNDS"
  | "MAX_EVIDENCE_REQUESTS"
  | "MAX_ADJUDICATION_ROUNDS"
  | "MAX_TOTAL_COST_UNITS"
  | "MAX_WALL_TIME_SECONDS"
  | "MAX_TOTAL_OUTPUT_TOKENS"
  | "MAX_REVIEW_UNITS"
  | "MAX_PARALLEL_UNITS";

export interface ReviewLimitDecision {
  readonly action: "CONTINUE" | "ESCALATE_ARCHITECTURE" | "NEEDS_HUMAN";
  readonly runtime_model_degraded: boolean;
  readonly violations: readonly ReviewLimitViolation[];
}

export const DEFAULT_REVIEW_LIMITS: Readonly<ReviewLimits> = Object.freeze({
  max_review_rounds: 3,
  max_repair_rounds: 3,
  max_evidence_requests: 5,
  max_adjudication_rounds: 1,
  max_total_cost_units: 100,
});

export const DEFAULT_REVIEW_BUDGET: Readonly<ReviewBudget> = Object.freeze({
  max_wall_time_seconds: 3600,
  max_total_output_tokens: 40000,
  max_review_units: 5,
  max_parallel_units: 3,
});

export function evaluateReviewLimits(input: unknown): ReviewLimitDecision {
  const value = reviewLimitInputSchema.parse(input);
  const violations: ReviewLimitViolation[] = [];
  const checks: Array<[boolean, ReviewLimitViolation]> = [
    [value.usage.review_rounds > value.limits.max_review_rounds, "MAX_REVIEW_ROUNDS"],
    [value.usage.repair_rounds > value.limits.max_repair_rounds, "MAX_REPAIR_ROUNDS"],
    [value.usage.evidence_requests > value.limits.max_evidence_requests, "MAX_EVIDENCE_REQUESTS"],
    [value.usage.adjudication_rounds > value.limits.max_adjudication_rounds, "MAX_ADJUDICATION_ROUNDS"],
    [value.usage.total_cost_units > value.limits.max_total_cost_units, "MAX_TOTAL_COST_UNITS"],
    [value.usage.wall_time_seconds > value.budget.max_wall_time_seconds, "MAX_WALL_TIME_SECONDS"],
    [value.usage.total_output_tokens > value.budget.max_total_output_tokens, "MAX_TOTAL_OUTPUT_TOKENS"],
    [value.usage.review_units > value.budget.max_review_units, "MAX_REVIEW_UNITS"],
    [value.usage.parallel_units > value.budget.max_parallel_units, "MAX_PARALLEL_UNITS"],
  ];
  for (const [exceeded, violation] of checks) if (exceeded) violations.push(violation);

  const action = value.circuit.recurring_finding_occurrences >= 3
    ? "ESCALATE_ARCHITECTURE"
    : violations.length > 0 ? "NEEDS_HUMAN" : "CONTINUE";
  return Object.freeze({
    action,
    runtime_model_degraded: value.circuit.consecutive_unsupported_findings >= 3,
    violations: Object.freeze(violations),
  });
}
