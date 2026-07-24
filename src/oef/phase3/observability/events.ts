import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema } from "../../phase1/core/shared/actor";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const entityIdSchema = z.string().regex(/^[a-z][a-z0-9-]*[:][A-Za-z0-9][A-Za-z0-9._:@/-]*$/);

export const REVIEW_AUDIT_EVENT_TYPES = [
  "review.requested",
  "review.plan.created",
  "review.plan.activated",
  "review.unit.ready",
  "review.unit.started",
  "review.unit.completed",
  "review.unit.failed",
  "finding.proposed",
  "finding.validated",
  "finding.confirmed",
  "finding.dismissed",
  "finding.waived",
  "finding.resolved",
  "finding.verified_resolved",
  "finding.stale",
  "evidence.requested",
  "evidence.fulfilled",
  "adjudication.started",
  "adjudication.completed",
  "review.human-approved",
  "review.decision.issued",
  "review.decision.superseded",
  "repair.proposed",
  "repair.assignment.created",
] as const;

export type ReviewAuditEventType = (typeof REVIEW_AUDIT_EVENT_TYPES)[number];

export const REVIEW_ARTIFACT_KINDS = [
  "review-context",
  "rendered-review-prompt",
  "raw-review-output",
  "validated-review-result",
  "finding-report",
  "adjudication",
  "human-decision",
  "review-summary",
] as const;

export const reviewAuditPayloadSchema = z.object({
  source_tree_hash: hashSchema.optional(),
  contract_revision: z.number().int().positive().optional(),
  plan_revision: z.number().int().positive().optional(),
  required_unit_ids: z.array(entityIdSchema).max(64).optional(),
  review_unit_id: entityIdSchema.optional(),
  review_type: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160).optional(),
  finding_count: z.number().int().nonnegative().optional(),
  failure_code: z.string().regex(/^[A-Z0-9_:-]{1,200}$/).optional(),
  finding_id: entityIdSchema.optional(),
  waiver_id: entityIdSchema.optional(),
  human_approval_id: entityIdSchema.optional(),
  review_decision_id: entityIdSchema.optional(),
  review_decision_hash: hashSchema.optional(),
  finding_ids: z.array(entityIdSchema).max(1_000).optional(),
  snapshot_hash: hashSchema.optional(),
  finding_key: z.string().regex(/^FIND-[A-Z0-9-]+$/).optional(),
  severity: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).optional(),
  decision: z.enum(["pass", "repair", "blocked", "needs-human", "inconclusive"]).optional(),
  blocker_ids: z.array(entityIdSchema).max(1_000).optional(),
  repair_assignment_id: entityIdSchema.optional(),
  repair_proposal_id: entityIdSchema.optional(),
  rationale: z.string().trim().min(1).max(20_000).optional(),
  artifact_refs: z.array(z.object({
    artifact_id: entityIdSchema,
    artifact_hash: hashSchema,
    kind: z.enum(REVIEW_ARTIFACT_KINDS),
  }).strict()).max(32).optional(),
}).strict();

const auditEventContentSchema = z.object({
  schema_version: z.literal(1),
  event_id: entityIdSchema,
  event_type: z.enum(REVIEW_AUDIT_EVENT_TYPES),
  aggregate_type: z.literal("review-plan"),
  aggregate_id: entityIdSchema,
  aggregate_version: z.number().int().positive(),
  task_id: entityIdSchema,
  occurred_at: z.string().datetime(),
  actor: actorSchema,
  payload: reviewAuditPayloadSchema,
  previous_event_hash: hashSchema.nullable(),
}).strict().superRefine((value, context) => {
  if (value.event_type === "review.plan.created") {
    requirePayload(value.payload.source_tree_hash, "source_tree_hash", context);
    requirePayload(value.payload.contract_revision, "contract_revision", context);
    requirePayload(value.payload.plan_revision, "plan_revision", context);
    requirePayload(value.payload.required_unit_ids, "required_unit_ids", context);
  }
  if (["review.unit.ready", "review.unit.started", "review.unit.completed", "review.unit.failed"].includes(value.event_type)) {
    requirePayload(value.payload.review_unit_id, "review_unit_id", context);
  }
  if (["finding.proposed", "finding.validated", "finding.confirmed", "finding.dismissed", "finding.waived", "finding.resolved", "finding.verified_resolved", "finding.stale"].includes(value.event_type)) {
    requirePayload(value.payload.finding_id, "finding_id", context);
  }
  if (value.event_type === "review.decision.issued") requirePayload(value.payload.decision, "decision", context);
  if (value.event_type === "review.human-approved") {
    requirePayload(value.payload.human_approval_id, "human_approval_id", context);
    requirePayload(value.payload.snapshot_hash, "snapshot_hash", context);
    requirePayload(value.payload.review_decision_id, "review_decision_id", context);
    requirePayload(value.payload.review_decision_hash, "review_decision_hash", context);
    requirePayload(value.payload.finding_ids, "finding_ids", context);
    requirePayload(value.payload.artifact_refs, "artifact_refs", context);
  }
  if (value.event_type === "repair.proposed") {
    requirePayload(value.payload.repair_proposal_id, "repair_proposal_id", context);
    requirePayload(value.payload.finding_ids, "finding_ids", context);
    requirePayload(value.payload.artifact_refs, "artifact_refs", context);
  }
  if (value.event_type === "repair.assignment.created") {
    requirePayload(value.payload.repair_assignment_id, "repair_assignment_id", context);
    requirePayload(value.payload.repair_proposal_id, "repair_proposal_id", context);
  }
});

export const governanceAuditEventSchema = auditEventContentSchema.extend({
  event_hash: hashSchema,
}).strict().superRefine((value, context) => {
  const { event_hash: ignored, ...content } = value;
  if (canonicalSha256(content) !== value.event_hash) {
    context.addIssue({ code: "custom", path: ["event_hash"], message: "Audit event content hash mismatch" });
  }
});

export type GovernanceAuditEvent = z.infer<typeof governanceAuditEventSchema>;

export function createGovernanceAuditEvent(input: unknown): GovernanceAuditEvent {
  const source = asRecord(input);
  const parsed = auditEventContentSchema.safeParse({ schema_version: 1, ...source });
  if (!parsed.success) throw new Error("REVIEW_AUDIT_EVENT_INVALID");
  const event = governanceAuditEventSchema.parse({ ...parsed.data, event_hash: canonicalSha256(parsed.data) });
  return deepFreeze(event);
}

export function parseGovernanceAuditEvent(input: unknown): GovernanceAuditEvent {
  const parsed = governanceAuditEventSchema.safeParse(input);
  if (!parsed.success) throw new Error("REVIEW_AUDIT_EVENT_INVALID");
  return deepFreeze(parsed.data);
}

export function assertGovernanceAuditEventStream(input: readonly unknown[]): readonly GovernanceAuditEvent[] {
  try {
    const events = input.map(parseGovernanceAuditEvent);
    let previous: string | null = null;
    let aggregateId: string | null = null;
    for (const [index, event] of events.entries()) {
      if (event.aggregate_version !== index + 1) throw new Error("version");
      if (event.previous_event_hash !== previous) throw new Error("hash-link");
      if (aggregateId !== null && aggregateId !== event.aggregate_id) throw new Error("aggregate");
      aggregateId = event.aggregate_id;
      previous = event.event_hash;
    }
    assertReviewAuditCausality(events);
    return Object.freeze(events);
  } catch {
    throw new Error("REVIEW_AUDIT_CHAIN_INVALID");
  }
}

function assertReviewAuditCausality(events: readonly GovernanceAuditEvent[]): void {
  let planCreated = false;
  let requiredUnits = new Set<string>();
  const completedUnits = new Set<string>();
  const confirmedFindings = new Set<string>();
  let repairDecisionBlockers: ReadonlySet<string> | null = null;
  const repairProposals = new Map<string, ReadonlySet<string>>();
  for (const event of events) {
    if (event.event_type === "review.plan.created") {
      planCreated = true;
      requiredUnits = new Set(event.payload.required_unit_ids ?? []);
      completedUnits.clear();
      confirmedFindings.clear();
      repairDecisionBlockers = null;
      repairProposals.clear();
    }
    if (event.event_type === "review.unit.completed" && event.payload.review_unit_id) completedUnits.add(event.payload.review_unit_id);
    if (event.event_type === "finding.confirmed" && event.payload.finding_id) confirmedFindings.add(event.payload.finding_id);
    if (event.event_type === "review.decision.issued") {
      if (!planCreated) throw new Error("decision-before-plan");
      if (event.payload.decision === "pass" && [...requiredUnits].some(unit => !completedUnits.has(unit))) throw new Error("pass-before-required-units");
      if ((event.payload.decision === "repair" || event.payload.decision === "blocked")
        && (event.payload.blocker_ids ?? []).some(finding => !confirmedFindings.has(finding))) throw new Error("unsupported-decision-blocker");
      repairDecisionBlockers = event.payload.decision === "repair" ? new Set(event.payload.blocker_ids ?? []) : null;
      continue;
    }
    if (event.event_type === "repair.proposed") {
      if (!repairDecisionBlockers) throw new Error("repair-proposal-before-repair-decision");
      const findings = new Set(event.payload.finding_ids ?? []);
      if (!sameStringSet(findings, repairDecisionBlockers)) throw new Error("repair-proposal-blocker-mismatch");
      repairProposals.set(event.payload.repair_proposal_id!, findings);
      continue;
    }
    if (event.event_type === "repair.assignment.created" && !repairProposals.has(event.payload.repair_proposal_id!)) {
      throw new Error("repair-assignment-before-proposal");
    }
  }
}

function sameStringSet(left: ReadonlySet<string>, right: ReadonlySet<string>): boolean {
  return left.size === right.size && [...left].every(value => right.has(value));
}

function requirePayload(value: unknown, path: string, context: z.RefinementCtx): void {
  if (value === undefined) context.addIssue({ code: "custom", path: ["payload", path], message: `${path} is required for this event type` });
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
