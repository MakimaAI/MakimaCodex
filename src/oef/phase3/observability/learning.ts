import { z } from "zod";

const entityIdSchema = z.string().regex(/^[a-z][a-z0-9-]*[:\-][A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const severitySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

export const REVIEW_GROUND_TRUTH_SOURCES = [
  "deterministic-test",
  "human-decision",
  "repair-regression-test",
  "post-merge-incident",
  "production-rollback",
  "security-scanner",
  "independent-reproduction",
  "confirmed-bug-report",
] as const;

const groundTruthSchema = z.enum(REVIEW_GROUND_TRUTH_SOURCES);
const outcomeContentSchema = z.object({
  disposition: z.enum(["confirmed", "dismissed", "verified-resolved"]),
  classification: z.enum(["true-positive", "false-positive", "uncertain"]),
  confidence: z.enum(["low", "medium", "high"]),
  reason: z.string().trim().min(1).max(2_000).optional(),
  ground_truth_sources: z.array(groundTruthSchema).min(1).max(REVIEW_GROUND_TRUTH_SOURCES.length),
}).strict();

export const findingOutcomeSchema = outcomeContentSchema.extend({
  schema_version: z.literal(1),
  finding_id: entityIdSchema,
  recorded_at: z.string().datetime(),
}).strict();

export type FindingOutcome = z.infer<typeof findingOutcomeSchema>;

export function parseFindingOutcome(input: unknown): FindingOutcome {
  return deepFreeze(findingOutcomeSchema.parse(input));
}

const escapedDefectContentSchema = z.object({
  incident_id: entityIdSchema,
  original_review_plan_id: entityIdSchema,
  missed_category: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
  severity: severitySchema,
  ground_truth_source: groundTruthSchema,
  recorded_at: z.string().datetime(),
}).strict();

export const escapedDefectSchema = escapedDefectContentSchema.extend({ schema_version: z.literal(1) }).strict();
export type EscapedDefect = z.infer<typeof escapedDefectSchema>;

export function createEscapedDefect(input: unknown): EscapedDefect {
  return deepFreeze(escapedDefectSchema.parse({ schema_version: 1, ...(isRecord(input) ? input : {}) }));
}

const metricInputSchema = z.object({
  reviewer_key: z.string().trim().min(1).max(1_000),
  findings: z.array(z.object({
    finding_id: entityIdSchema,
    severity: severitySchema,
    evidence_strength: z.enum(["AUTHORITATIVE", "STRONG", "SUPPORTED", "OPINION", "UNSUPPORTED"]),
    outcome: outcomeContentSchema,
    human_agreement: z.boolean().nullable(),
    repair_accepted: z.boolean().nullable(),
    recurred: z.boolean().nullable(),
  }).strict()).max(100_000),
  escaped_defects: z.array(z.object({
    incident_id: entityIdSchema,
    original_review_plan_id: entityIdSchema,
    severity: severitySchema,
  }).strict()).max(100_000),
  review_runs: z.array(z.object({
    review_plan_id: entityIdSchema,
    decision: z.enum(["pass", "changes-requested", "blocked", "needs-human", "inconclusive"]),
    latency_ms: z.number().int().nonnegative(),
    cost_units: z.number().nonnegative(),
  }).strict()).max(100_000),
}).strict();

export interface ReviewerMetrics {
  readonly reviewer_key: string;
  readonly findings_total: number;
  readonly confirmed_findings: number;
  readonly dismissed_findings: number;
  readonly false_positive_rate: number;
  readonly high_severity_precision: number;
  readonly human_agreement_rate: number;
  readonly repair_acceptance_rate: number;
  readonly finding_recurrence_rate: number;
  readonly missed_defect_rate: number;
  readonly review_latency: { readonly average_ms: number; readonly p95_ms: number };
  readonly review_cost: { readonly total_cost_units: number; readonly average_cost_units: number };
  readonly unsupported_finding_rate: number;
}

export function calculateReviewerMetrics(input: unknown): ReviewerMetrics {
  const value = metricInputSchema.parse(input);
  const conclusive = value.findings.filter(finding => finding.outcome.classification !== "uncertain");
  const highConclusive = conclusive.filter(finding => finding.severity === "HIGH" || finding.severity === "CRITICAL");
  const humanLabeled = value.findings.filter(finding => finding.human_agreement !== null);
  const repairLabeled = value.findings.filter(finding => finding.repair_accepted !== null);
  const recurrenceLabeled = value.findings.filter(finding => finding.recurred !== null);
  const latencies = value.review_runs.map(run => run.latency_ms).sort((left, right) => left - right);
  const totalLatency = latencies.reduce((sum, latency) => sum + latency, 0);
  const totalCost = value.review_runs.reduce((sum, run) => sum + run.cost_units, 0);
  const confirmed = value.findings.filter(finding => finding.outcome.disposition === "confirmed").length;
  const passedPlans = new Set(value.review_runs.filter(run => run.decision === "pass").map(run => run.review_plan_id));
  const escapedPassedPlans = new Set(value.escaped_defects
    .map(defect => defect.original_review_plan_id)
    .filter(reviewPlanId => passedPlans.has(reviewPlanId)));

  return deepFreeze({
    reviewer_key: value.reviewer_key,
    findings_total: value.findings.length,
    confirmed_findings: confirmed,
    dismissed_findings: value.findings.filter(finding => finding.outcome.disposition === "dismissed").length,
    false_positive_rate: ratio(conclusive.filter(finding => finding.outcome.classification === "false-positive").length, conclusive.length),
    high_severity_precision: ratio(highConclusive.filter(finding => finding.outcome.classification === "true-positive").length, highConclusive.length),
    human_agreement_rate: ratio(humanLabeled.filter(finding => finding.human_agreement === true).length, humanLabeled.length),
    repair_acceptance_rate: ratio(repairLabeled.filter(finding => finding.repair_accepted === true).length, repairLabeled.length),
    finding_recurrence_rate: ratio(recurrenceLabeled.filter(finding => finding.recurred === true).length, recurrenceLabeled.length),
    missed_defect_rate: ratio(escapedPassedPlans.size, passedPlans.size),
    review_latency: {
      average_ms: ratio(totalLatency, latencies.length),
      p95_ms: latencies.length === 0 ? 0 : latencies[Math.ceil(latencies.length * 0.95) - 1]!,
    },
    review_cost: {
      total_cost_units: totalCost,
      average_cost_units: ratio(totalCost, value.review_runs.length),
    },
    unsupported_finding_rate: ratio(value.findings.filter(finding => finding.evidence_strength === "UNSUPPORTED").length, value.findings.length),
  });
}

export const reviewTrainingRecordSchema = z.object({
  schema_version: z.literal(1),
  task_features: z.object({
    type: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
    language: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(80),
    risk: z.enum(["low", "medium", "high", "critical"]),
  }).strict(),
  reviewer: z.object({
    profile: z.string().trim().min(1).max(500),
    model_ref: z.string().trim().min(1).max(500),
    runtime: z.string().trim().min(1).max(500),
  }).strict(),
  input_snapshot: z.object({ contract_hash: hashSchema, diff_hash: hashSchema, evidence_hash: hashSchema }).strict(),
  output: z.object({
    findings: z.array(z.object({
      finding_id: entityIdSchema,
      category: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
      severity: severitySchema,
      evidence_strength: z.enum(["AUTHORITATIVE", "STRONG", "SUPPORTED", "OPINION", "UNSUPPORTED"]),
    }).strict()).max(10_000),
    decision: z.enum(["pass", "changes-requested", "blocked", "needs-human", "inconclusive"]),
  }).strict(),
  outcomes: z.object({
    human_agreement: z.boolean().nullable(),
    confirmed_findings: z.number().int().nonnegative(),
    dismissed_findings: z.number().int().nonnegative(),
    escaped_defects: z.number().int().nonnegative(),
    repair_success: z.boolean().nullable(),
  }).strict(),
  metrics: z.object({ latency_ms: z.number().int().nonnegative(), cost_units: z.number().nonnegative() }).strict(),
  recorded_at: z.string().datetime(),
}).strict();

export type ReviewTrainingRecord = z.infer<typeof reviewTrainingRecordSchema>;

export function parseReviewTrainingRecord(input: unknown): ReviewTrainingRecord {
  if (containsHiddenReasoningField(input)) throw new Error("REVIEW_TRAINING_HIDDEN_REASONING_FORBIDDEN");
  return deepFreeze(reviewTrainingRecordSchema.parse(input));
}

function containsHiddenReasoningField(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsHiddenReasoningField);
  if (!isRecord(value)) return false;
  const forbidden = new Set(["chainofthought", "reasoningtrace", "internalreasoning", "rawreasoning", "scratchpad", "thoughtprocess"]);
  return Object.entries(value).some(([key, child]) => forbidden.has(key.toLowerCase().replace(/[^a-z]/g, "")) || containsHiddenReasoningField(child));
}

function ratio(numerator: number, denominator: number): number {
  return denominator === 0 ? 0 : numerator / denominator;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
