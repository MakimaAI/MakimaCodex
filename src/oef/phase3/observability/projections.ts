import { assertGovernanceAuditEventStream, type GovernanceAuditEvent, type ReviewAuditEventType } from "./events";

export interface ReviewTimelineItem {
  readonly aggregate_version: number;
  readonly occurred_at: string;
  readonly event_type: ReviewAuditEventType;
  readonly label: string;
  readonly artifact_refs: GovernanceAuditEvent["payload"]["artifact_refs"];
}

export interface ReviewSummaryProjection {
  readonly schema_version: 1;
  readonly status: "running" | "passed" | "changes-requested" | "blocked" | "needs-human" | "inconclusive";
  readonly snapshot: { readonly source_tree_hash: string; readonly contract_revision: number };
  readonly units: { readonly required: number; readonly completed: number; readonly failed: number };
  readonly findings: {
    readonly critical: number;
    readonly high: number;
    readonly medium: number;
    readonly low: number;
    readonly info: number;
    readonly confirmed: number;
    readonly dismissed: number;
  };
  readonly decision: { readonly result: "pending" | "pass" | "repair" | "blocked" | "needs-human" | "inconclusive"; readonly blockers: readonly string[] };
  readonly next_action: { readonly repair_assignment_id: string | null };
}

export function projectReviewTimeline(input: readonly unknown[]): readonly ReviewTimelineItem[] {
  const events = assertGovernanceAuditEventStream(input);
  return Object.freeze(events.map(event => Object.freeze({
    aggregate_version: event.aggregate_version,
    occurred_at: event.occurred_at,
    event_type: event.event_type,
    label: timelineLabel(event),
    artifact_refs: event.payload.artifact_refs,
  })));
}

export function projectReviewSummary(input: readonly unknown[]): ReviewSummaryProjection {
  const events = assertGovernanceAuditEventStream(input);
  const planCreated = events.find(event => event.event_type === "review.plan.created");
  if (!planCreated?.payload.source_tree_hash || planCreated.payload.contract_revision === undefined) {
    throw new Error("REVIEW_SUMMARY_SNAPSHOT_MISSING");
  }

  const requiredUnits = new Set(planCreated.payload.required_unit_ids ?? []);
  const completedUnits = new Set<string>();
  const failedUnits = new Set<string>();
  const findings = new Map<string, { severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"; confirmed: boolean; dismissed: boolean }>();
  let decision: ReviewSummaryProjection["decision"] = { result: "pending", blockers: Object.freeze([]) };
  let status: ReviewSummaryProjection["status"] = "running";
  let repairAssignmentId: string | null = null;

  for (const event of events) {
    const payload = event.payload;
    if (event.event_type === "review.unit.completed" && payload.review_unit_id) completedUnits.add(payload.review_unit_id);
    if (event.event_type === "review.unit.failed" && payload.review_unit_id) failedUnits.add(payload.review_unit_id);
    if (event.event_type.startsWith("finding.") && payload.finding_id) {
      const previous = findings.get(payload.finding_id);
      const severity = payload.severity ?? previous?.severity;
      if (severity) {
        findings.set(payload.finding_id, {
          severity,
          confirmed: previous?.confirmed === true || event.event_type === "finding.confirmed",
          dismissed: event.event_type === "finding.dismissed",
        });
      }
    }
    if (event.event_type === "review.decision.issued" && payload.decision) {
      decision = { result: payload.decision, blockers: Object.freeze([...(payload.blocker_ids ?? [])]) };
      status = decisionStatus(payload.decision);
    }
    if (event.event_type === "repair.assignment.created") repairAssignmentId = payload.repair_assignment_id ?? null;
  }

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let confirmed = 0;
  let dismissed = 0;
  for (const finding of findings.values()) {
    severityCounts[finding.severity.toLowerCase() as keyof typeof severityCounts] += 1;
    if (finding.confirmed) confirmed += 1;
    if (finding.dismissed) dismissed += 1;
  }

  return deepFreeze({
    schema_version: 1,
    status,
    snapshot: { source_tree_hash: planCreated.payload.source_tree_hash, contract_revision: planCreated.payload.contract_revision },
    units: { required: requiredUnits.size, completed: completedUnits.size, failed: failedUnits.size },
    findings: { ...severityCounts, confirmed, dismissed },
    decision,
    next_action: { repair_assignment_id: repairAssignmentId },
  });
}

function timelineLabel(event: GovernanceAuditEvent): string {
  const reviewName = titleCase(event.payload.review_type ?? "review");
  switch (event.event_type) {
    case "review.requested": return "Review requested";
    case "review.plan.created": return "Review plan created";
    case "review.plan.activated": return "Review plan activated";
    case "review.unit.ready": return `${reviewName} review ready`;
    case "review.unit.started": return `${reviewName} review started`;
    case "review.unit.completed": {
      const count = event.payload.finding_count;
      return count === undefined
        ? `${reviewName} review completed`
        : `${reviewName} review completed — ${count} ${count === 1 ? "finding" : "findings"}`;
    }
    case "review.unit.failed": return `${reviewName} review failed`;
    case "review.human-approved": return "Human review approval recorded";
    case "review.decision.issued": return `Review decision issued — ${event.payload.decision === "repair" ? "changes requested" : event.payload.decision}`;
    case "review.decision.superseded": return "Review decision superseded";
    case "repair.assignment.created": return "Repair assignment created";
    default: return titleCase(event.event_type.replaceAll(".", " ").replaceAll("_", " "));
  }
}

function decisionStatus(decision: NonNullable<GovernanceAuditEvent["payload"]["decision"]>): ReviewSummaryProjection["status"] {
  if (decision === "pass") return "passed";
  if (decision === "repair") return "changes-requested";
  return decision;
}

function titleCase(value: string): string {
  return value.length === 0 ? value : value[0]!.toUpperCase() + value.slice(1);
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
  }
  return value;
}
