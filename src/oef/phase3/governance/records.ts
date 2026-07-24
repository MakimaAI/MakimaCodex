import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema } from "../../phase1/core/shared/actor";
import { EVIDENCE_STRENGTHS, FINDING_SEVERITIES } from "../core/domain";
import { REVIEW_DECISIONS } from "../decision";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const id = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));

const humanApprovalContentSchema = z.object({
  schema_version: z.literal(1),
  approval_id: id("review-approval"),
  review_plan_id: id("review-plan"),
  snapshot_hash: hashSchema,
  review_decision_id: id("review-decision"),
  review_decision_hash: hashSchema,
  finding_ids: z.array(id("review-finding")).max(1_000),
  decision: z.literal("APPROVE"),
  rationale: z.string().trim().min(1).max(20_000),
  approved_by: actorSchema.refine(actor => actor.type === "human", "Review approval requires a human actor"),
  approval_artifact_ref: id("artifact"),
  approved_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (new Set(value.finding_ids).size !== value.finding_ids.length) {
    context.addIssue({ code: "custom", path: ["finding_ids"], message: "Human approval finding bindings must be unique" });
  }
});

export const humanReviewApprovalSchema = humanApprovalContentSchema.extend({ approval_hash: hashSchema }).strict().superRefine((value, context) => {
  const { approval_hash: ignored, ...content } = value;
  if (canonicalSha256(content) !== value.approval_hash) context.addIssue({ code: "custom", path: ["approval_hash"], message: "Human approval hash mismatch" });
});
export type HumanReviewApproval = z.infer<typeof humanReviewApprovalSchema>;
export function createHumanReviewApproval(input: unknown): HumanReviewApproval {
  const source = input && typeof input === "object" ? input as Record<string, unknown> : {};
  const { approval_hash: ignored, ...rest } = source;
  const normalized = { ...rest, ...(Array.isArray(rest.finding_ids) ? { finding_ids: [...new Set(rest.finding_ids)].sort() } : {}) };
  const content = humanApprovalContentSchema.parse({ schema_version: 1, ...normalized });
  return humanReviewApprovalSchema.parse({ ...content, approval_hash: canonicalSha256(content) });
}
export function parseHumanReviewApproval(input: unknown): HumanReviewApproval { return humanReviewApprovalSchema.parse(input); }

export const REVIEW_EXECUTION_STATUSES = ["CREATED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"] as const;
export type ReviewExecutionStatus = typeof REVIEW_EXECUTION_STATUSES[number];

export const reviewExecutionRecordSchema = z.object({
  schema_version: z.literal(1),
  review_execution_id: id("review-execution"),
  review_plan_id: id("review-plan"),
  review_unit_id: id("review-unit"),
  reviewer_binding_id: id("reviewer-binding"),
  snapshot_hash: hashSchema,
  status: z.enum(REVIEW_EXECUTION_STATUSES),
  attempt_number: z.number().int().positive(),
  context_artifact_ref: id("artifact"),
  rendered_prompt_artifact_ref: id("artifact"),
  result_artifact_ref: id("artifact").nullable(),
  output_hash: hashSchema.nullable(),
  runtime_attestation_hash: hashSchema.nullable(),
  runtime_attestation_key_id: hashSchema.nullable(),
  runtime_attestation_signature: z.string().regex(/^[A-Za-z0-9_-]{64,256}$/).nullable(),
  protocol_errors: z.number().int().nonnegative(),
  aggregate_version: z.number().int().positive(),
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (Date.parse(value.updated_at) < Date.parse(value.created_at)) context.addIssue({ code: "custom", path: ["updated_at"], message: "Review execution update cannot predate creation" });
  if (value.status === "COMPLETED" && (!value.result_artifact_ref || !value.output_hash
    || !value.runtime_attestation_hash || !value.runtime_attestation_key_id || !value.runtime_attestation_signature)) {
    context.addIssue({ code: "custom", path: ["result_artifact_ref"], message: "Completed review execution requires immutable output artifacts" });
  }
  if (value.status !== "COMPLETED" && (value.result_artifact_ref !== null || value.output_hash !== null
    || value.runtime_attestation_hash !== null || value.runtime_attestation_key_id !== null || value.runtime_attestation_signature !== null)) {
    context.addIssue({ code: "custom", path: ["result_artifact_ref"], message: "Only completed review execution may publish output" });
  }
});
export type ReviewExecutionRecord = z.infer<typeof reviewExecutionRecordSchema>;
export function parseReviewExecutionRecord(input: unknown): ReviewExecutionRecord { return reviewExecutionRecordSchema.parse(input); }

const executionTransitions: Readonly<Record<ReviewExecutionStatus, readonly ReviewExecutionStatus[]>> = {
  CREATED: ["RUNNING", "CANCELLED"],
  RUNNING: ["COMPLETED", "FAILED", "CANCELLED"],
  COMPLETED: [], FAILED: [], CANCELLED: [],
};
export function transitionReviewExecution(current: ReviewExecutionStatus, next: ReviewExecutionStatus): ReviewExecutionStatus {
  if (current === next || !executionTransitions[current].includes(next)) throw new Error(`Invalid review execution transition: ${current} -> ${next}`);
  return next;
}

export const findingValidationSchema = z.object({
  schema_version: z.literal(1),
  finding_validation_id: id("finding-validation"),
  finding_id: id("review-finding"),
  review_plan_id: id("review-plan"),
  snapshot_hash: hashSchema,
  status: z.enum(["CONFIRMED", "DISMISSED", "DUPLICATE", "STALE"]),
  effective_severity: z.enum(FINDING_SEVERITIES).nullable(),
  evidence_strength: z.enum(EVIDENCE_STRENGTHS),
  validated_by: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).min(1).max(32),
  validator_binding_id: id("reviewer-binding").nullable(),
  validation_artifact_ref: id("artifact"),
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (value.status === "CONFIRMED" && value.effective_severity === null) context.addIssue({ code: "custom", path: ["effective_severity"], message: "Confirmed finding validation requires effective severity" });
  if (value.status === "CONFIRMED" && value.evidence_strength === "UNSUPPORTED") context.addIssue({ code: "custom", path: ["evidence_strength"], message: "Unsupported validation cannot confirm a finding" });
  if (new Set(value.validated_by).size !== value.validated_by.length) context.addIssue({ code: "custom", path: ["validated_by"], message: "Finding validators must be unique" });
});
export type FindingValidation = z.infer<typeof findingValidationSchema>;
export function parseFindingValidation(input: unknown): FindingValidation { return findingValidationSchema.parse(input); }

const severityCountsSchema = z.object({ CRITICAL: z.number().int().nonnegative(), HIGH: z.number().int().nonnegative(), MEDIUM: z.number().int().nonnegative(), LOW: z.number().int().nonnegative(), INFO: z.number().int().nonnegative() }).strict();
export const reviewDecisionRecordSchema = z.object({
  schema_version: z.literal(1),
  review_decision_id: id("review-decision"),
  review_plan_id: id("review-plan"),
  snapshot_hash: hashSchema,
  decision: z.enum(REVIEW_DECISIONS),
  decision_source: z.enum(["deterministic-policy", "adjudicator", "human"]),
  current_snapshot: z.boolean(),
  quorum_satisfied: z.boolean(),
  mechanical_verification_passed: z.boolean(),
  accepted_findings: z.array(id("review-finding")),
  dismissed_findings: z.array(id("review-finding")),
  unresolved_findings: z.array(id("review-finding")),
  waived_findings: z.array(id("review-finding")),
  waiver_ids: z.array(id("review-waiver")),
  human_approval: z.object({ approval_id: id("review-approval"), approval_hash: hashSchema, approval_artifact_ref: id("artifact") }).strict().nullable(),
  severity_counts: severityCountsSchema,
  reason_codes: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)),
  rationale: z.string().trim().min(1).max(50_000),
  next_action: z.object({ type: z.enum(["phase1-verdict", "repair", "human-gate", "redispatch", "none"]), ref: z.string().trim().min(1).max(500).nullable().optional() }).strict(),
  decision_artifact_ref: id("artifact"),
  issued_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  const pass = value.decision === "PASS" || value.decision === "PASS_WITH_NOTES";
  if (pass && !value.current_snapshot) context.addIssue({ code: "custom", path: ["current_snapshot"], message: "Stale review cannot pass" });
  if (pass && !value.quorum_satisfied) context.addIssue({ code: "custom", path: ["quorum_satisfied"], message: "Review quorum is required for pass" });
  if (pass && !value.mechanical_verification_passed) context.addIssue({ code: "custom", path: ["mechanical_verification_passed"], message: "Mechanical verification is required for pass" });
  if (pass && value.severity_counts.CRITICAL > 0) context.addIssue({ code: "custom", path: ["severity_counts", "CRITICAL"], message: "Confirmed critical finding cannot pass" });
  if (value.decision === "PASS" && Object.values(value.severity_counts).some(count => count > 0)) context.addIssue({ code: "custom", path: ["severity_counts"], message: "Clean pass cannot contain confirmed findings" });
  const allFindings = [...value.accepted_findings, ...value.dismissed_findings, ...value.unresolved_findings, ...value.waived_findings];
  if (new Set(allFindings).size !== allFindings.length) context.addIssue({ code: "custom", path: ["accepted_findings"], message: "Decision finding partitions must not overlap" });
});
export type ReviewDecisionRecord = z.infer<typeof reviewDecisionRecordSchema>;
export function parseReviewDecisionRecord(input: unknown): ReviewDecisionRecord { return reviewDecisionRecordSchema.parse(input); }
