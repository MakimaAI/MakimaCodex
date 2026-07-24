import { describe, expect, test } from "bun:test";
import {
  DEFAULT_REVIEW_BUDGET,
  DEFAULT_REVIEW_LIMITS,
  REVIEW_AUDIT_EVENT_TYPES,
  REVIEW_ARTIFACT_KINDS,
  REVIEW_GROUND_TRUTH_SOURCES,
  calculateReviewerMetrics,
  createEscapedDefect,
  createGovernanceAuditEvent,
  createReviewAnalysisCacheKey,
  evaluateReviewLimits,
  parseFindingOutcome,
  parseReviewTrainingRecord,
  parseGovernanceAuditEvent,
  projectReviewSummary,
  projectReviewTimeline,
  upcastReviewRecord,
  type GovernanceAuditEvent,
} from "../src/oef/phase3";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const NOW = "2026-07-23T14:00:00.000Z";

function auditStream(
  definitions: Array<{ type: (typeof REVIEW_AUDIT_EVENT_TYPES)[number]; payload?: Record<string, unknown> }>,
): GovernanceAuditEvent[] {
  const events: GovernanceAuditEvent[] = [];
  for (const [index, definition] of definitions.entries()) {
    events.push(createGovernanceAuditEvent({
      event_id: `review-event:${index + 1}`,
      event_type: definition.type,
      aggregate_type: "review-plan",
      aggregate_id: "review-plan:test",
      aggregate_version: index + 1,
      task_id: "task:test",
      occurred_at: new Date(Date.parse(NOW) + index * 60_000).toISOString(),
      actor: { type: "system", id: "system:review-coordinator" },
      payload: definition.payload ?? {},
      previous_event_hash: events.at(-1)?.event_hash ?? null,
    }));
  }
  return events;
}

describe("Phase 3 review limits and circuit breaker", () => {
  test("allows bounded work and degrades a reviewer after three consecutive unsupported findings", () => {
    const decision = evaluateReviewLimits({
      limits: DEFAULT_REVIEW_LIMITS,
      budget: DEFAULT_REVIEW_BUDGET,
      usage: {
        review_rounds: 3,
        repair_rounds: 2,
        evidence_requests: 5,
        adjudication_rounds: 1,
        total_cost_units: 100,
        wall_time_seconds: 3600,
        total_output_tokens: 40000,
        review_units: 5,
        parallel_units: 3,
      },
      circuit: { recurring_finding_occurrences: 2, consecutive_unsupported_findings: 3 },
    });

    expect(decision.action).toBe("CONTINUE");
    expect(decision.runtime_model_degraded).toBeTrue();
    expect(decision.violations).toEqual([]);
  });

  test("escalates a finding repeated for three rounds and stops usage beyond a hard limit", () => {
    expect(evaluateReviewLimits({
      limits: DEFAULT_REVIEW_LIMITS,
      budget: DEFAULT_REVIEW_BUDGET,
      usage: {
        review_rounds: 1, repair_rounds: 1, evidence_requests: 0, adjudication_rounds: 0,
        total_cost_units: 10, wall_time_seconds: 60, total_output_tokens: 1000, review_units: 2, parallel_units: 2,
      },
      circuit: { recurring_finding_occurrences: 3, consecutive_unsupported_findings: 0 },
    }).action).toBe("ESCALATE_ARCHITECTURE");

    const exhausted = evaluateReviewLimits({
      limits: DEFAULT_REVIEW_LIMITS,
      budget: DEFAULT_REVIEW_BUDGET,
      usage: {
        review_rounds: 4, repair_rounds: 1, evidence_requests: 0, adjudication_rounds: 0,
        total_cost_units: 10, wall_time_seconds: 60, total_output_tokens: 1000, review_units: 2, parallel_units: 2,
      },
      circuit: { recurring_finding_occurrences: 0, consecutive_unsupported_findings: 0 },
    });
    expect(exhausted.action).toBe("NEEDS_HUMAN");
    expect(exhausted.violations).toEqual(["MAX_REVIEW_ROUNDS"]);
  });
});

describe("Phase 3 review audit projections", () => {
  test("uses the complete allowlisted audit vocabulary and rejects raw report payloads", () => {
    expect(REVIEW_AUDIT_EVENT_TYPES).toHaveLength(24);
    expect(REVIEW_ARTIFACT_KINDS).toHaveLength(8);
    expect(REVIEW_ARTIFACT_KINDS).toContain("validated-review-result");
    expect(REVIEW_AUDIT_EVENT_TYPES).toContain("finding.verified_resolved");
    expect(REVIEW_AUDIT_EVENT_TYPES).toContain("repair.assignment.created");
    expect(() => parseGovernanceAuditEvent({
      ...auditStream([{ type: "review.requested" }])[0],
      event_type: "review.verdict.cached",
    })).toThrow("REVIEW_AUDIT_EVENT_INVALID");
    expect(() => createGovernanceAuditEvent({
      event_id: "review-event:raw",
      event_type: "review.unit.completed",
      aggregate_type: "review-plan",
      aggregate_id: "review-plan:test",
      aggregate_version: 1,
      task_id: "task:test",
      occurred_at: NOW,
      actor: { type: "system", id: "system:test" },
      payload: { raw_review_output: "do not embed reports" },
      previous_event_hash: null,
    })).toThrow("REVIEW_AUDIT_EVENT_INVALID");
    expect(() => createGovernanceAuditEvent({
      event_id: "review-event:missing-finding",
      event_type: "finding.validated",
      aggregate_type: "review-plan",
      aggregate_id: "review-plan:test",
      aggregate_version: 1,
      task_id: "task:test",
      occurred_at: NOW,
      actor: { type: "system", id: "system:test" },
      payload: {},
      previous_event_hash: null,
    })).toThrow("REVIEW_AUDIT_EVENT_INVALID");
  });

  test("projects a readable append-only timeline and detects a broken hash chain", () => {
    const events = auditStream([
      { type: "review.plan.created", payload: { source_tree_hash: HASH_A, contract_revision: 3, plan_revision: 1, required_unit_ids: ["review-unit:spec"] } },
      { type: "review.unit.started", payload: { review_unit_id: "review-unit:spec", review_type: "spec" } },
      { type: "review.unit.completed", payload: { review_unit_id: "review-unit:spec", review_type: "spec", finding_count: 1 } },
      { type: "finding.confirmed", payload: { finding_id: "review-finding:1", finding_key: "FIND-001", severity: "HIGH" } },
      { type: "review.decision.issued", payload: { decision: "repair", blocker_ids: ["review-finding:1"] } },
      { type: "repair.proposed", payload: { repair_proposal_id: "repair-proposal:1", finding_ids: ["review-finding:1"], artifact_refs: [{ artifact_id: "artifact:repair-proposal", artifact_hash: HASH_B, kind: "finding-report" }] } },
      { type: "repair.assignment.created", payload: { repair_assignment_id: "assignment-repair:1", repair_proposal_id: "repair-proposal:1" } },
    ]);
    const timeline = projectReviewTimeline(events);
    expect(timeline.map(item => item.event_type)).toEqual([
      "review.plan.created", "review.unit.started", "review.unit.completed", "finding.confirmed",
      "review.decision.issued", "repair.proposed", "repair.assignment.created",
    ]);
    expect(timeline.map(item => item.aggregate_version)).toEqual([1, 2, 3, 4, 5, 6, 7]);

    const tampered = events.map(event => ({ ...event }));
    tampered[2] = { ...tampered[2]!, previous_event_hash: HASH_C };
    expect(() => projectReviewTimeline(tampered)).toThrow("REVIEW_AUDIT_CHAIN_INVALID");
    expect(() => projectReviewTimeline(auditStream([
      { type: "review.decision.issued", payload: { decision: "pass", blocker_ids: [] } },
    ]))).toThrow("REVIEW_AUDIT_CHAIN_INVALID");
    expect(() => projectReviewTimeline(auditStream([
      { type: "review.plan.created", payload: { source_tree_hash: HASH_A, contract_revision: 3, plan_revision: 1, snapshot_hash: HASH_A, required_unit_ids: ["review-unit:spec"] } },
      { type: "review.unit.completed", payload: { review_unit_id: "review-unit:spec", review_type: "spec", finding_count: 0 } },
      { type: "review.decision.issued", payload: { decision: "pass", blocker_ids: [] } },
      { type: "review.plan.created", payload: { source_tree_hash: HASH_C, contract_revision: 3, plan_revision: 2, snapshot_hash: HASH_C, required_unit_ids: ["review-unit:spec"] } },
      { type: "review.decision.issued", payload: { decision: "pass", blocker_ids: [] } },
    ]))).toThrow("REVIEW_AUDIT_CHAIN_INVALID");
  });

  test("projects unit, finding, decision, and next-action state without mutating history", () => {
    const events = auditStream([
      { type: "review.plan.created", payload: { source_tree_hash: HASH_A, contract_revision: 3, plan_revision: 1, required_unit_ids: ["review-unit:spec", "review-unit:quality"] } },
      { type: "review.unit.completed", payload: { review_unit_id: "review-unit:spec", review_type: "spec", finding_count: 1 } },
      { type: "review.unit.failed", payload: { review_unit_id: "review-unit:quality", review_type: "quality" } },
      { type: "finding.proposed", payload: { finding_id: "review-finding:1", finding_key: "FIND-001", severity: "HIGH" } },
      { type: "finding.confirmed", payload: { finding_id: "review-finding:1", finding_key: "FIND-001", severity: "HIGH" } },
      { type: "finding.proposed", payload: { finding_id: "review-finding:2", finding_key: "FIND-002", severity: "LOW" } },
      { type: "finding.dismissed", payload: { finding_id: "review-finding:2", finding_key: "FIND-002", severity: "LOW" } },
      { type: "review.decision.issued", payload: { decision: "repair", blocker_ids: ["review-finding:1"] } },
      { type: "repair.proposed", payload: { repair_proposal_id: "repair-proposal:1", finding_ids: ["review-finding:1"], artifact_refs: [{ artifact_id: "artifact:repair-proposal", artifact_hash: HASH_B, kind: "finding-report" }] } },
      { type: "repair.assignment.created", payload: { repair_assignment_id: "assignment-repair:1", repair_proposal_id: "repair-proposal:1" } },
    ]);
    const before = JSON.stringify(events);
    const summary = projectReviewSummary(events);
    expect(summary).toEqual({
      schema_version: 1,
      status: "changes-requested",
      snapshot: { source_tree_hash: HASH_A, contract_revision: 3 },
      units: { required: 2, completed: 1, failed: 1 },
      findings: { critical: 0, high: 1, medium: 0, low: 1, info: 0, confirmed: 1, dismissed: 1 },
      decision: { result: "repair", blockers: ["review-finding:1"] },
      next_action: { repair_assignment_id: "assignment-repair:1" },
    });
    expect(JSON.stringify(events)).toBe(before);
  });
});

describe("Phase 3 schema evolution and learning governance", () => {
  test("upcasts a copy through contiguous schema versions and rejects a missing path", () => {
    const legacy = { schema_version: 0, finding_id: "review-finding:legacy", claim: "Legacy claim" };
    const current = upcastReviewRecord(legacy, 2, [
      { from_version: 0, to_version: 1, upcast: record => ({ ...record, schema_version: 1, confidence: "medium" }) },
      { from_version: 1, to_version: 2, upcast: record => ({ ...record, schema_version: 2, evidence_refs: [] }) },
    ]);
    expect(current).toEqual({ ...legacy, schema_version: 2, confidence: "medium", evidence_refs: [] });
    expect(legacy).toEqual({ schema_version: 0, finding_id: "review-finding:legacy", claim: "Legacy claim" });
    expect(() => upcastReviewRecord(legacy, 2, [
      { from_version: 0, to_version: 1, upcast: record => ({ ...record, schema_version: 1 }) },
    ])).toThrow("SCHEMA_UPCAST_PATH_MISSING");
  });

  test("keeps uncertain dismissals distinct from false positives and records escaped defects", () => {
    const uncertain = parseFindingOutcome({
      schema_version: 1,
      finding_id: "review-finding:uncertain",
      disposition: "dismissed",
      classification: "uncertain",
      confidence: "medium",
      reason: "human-design-choice",
      ground_truth_sources: ["human-decision"],
      recorded_at: NOW,
    });
    expect(uncertain.classification).toBe("uncertain");
    expect(REVIEW_GROUND_TRUTH_SOURCES).toContain("post-merge-incident");

    const escaped = createEscapedDefect({
      incident_id: "incident-77",
      original_review_plan_id: "review-plan-142",
      missed_category: "concurrency",
      severity: "HIGH",
      ground_truth_source: "post-merge-incident",
      recorded_at: NOW,
    });
    expect(escaped.original_review_plan_id).toBe("review-plan-142");
  });

  test("calculates reviewer metrics only from explicit outcomes and ground truth", () => {
    const metrics = calculateReviewerMetrics({
      reviewer_key: "security-reviewer@1.0.0/provider-b/model-x/runtime-y",
      findings: [
        {
          finding_id: "review-finding:1", severity: "HIGH", evidence_strength: "STRONG",
          outcome: { disposition: "confirmed", classification: "true-positive", confidence: "high", ground_truth_sources: ["deterministic-test"] },
          human_agreement: true, repair_accepted: true, recurred: false,
        },
        {
          finding_id: "review-finding:2", severity: "HIGH", evidence_strength: "SUPPORTED",
          outcome: { disposition: "dismissed", classification: "false-positive", confidence: "high", ground_truth_sources: ["independent-reproduction"] },
          human_agreement: false, repair_accepted: null, recurred: false,
        },
        {
          finding_id: "review-finding:3", severity: "LOW", evidence_strength: "UNSUPPORTED",
          outcome: { disposition: "dismissed", classification: "uncertain", confidence: "medium", ground_truth_sources: ["human-decision"] },
          human_agreement: null, repair_accepted: null, recurred: null,
        },
      ],
      escaped_defects: [{ incident_id: "incident-77", original_review_plan_id: "review-plan:passed", severity: "HIGH" }],
      review_runs: [
        { review_plan_id: "review-plan:passed", decision: "pass", latency_ms: 100, cost_units: 3 },
        { review_plan_id: "review-plan:repair", decision: "changes-requested", latency_ms: 200, cost_units: 5 },
      ],
    });
    expect(metrics.findings_total).toBe(3);
    expect(metrics.confirmed_findings).toBe(1);
    expect(metrics.dismissed_findings).toBe(2);
    expect(metrics.false_positive_rate).toBe(0.5);
    expect(metrics.high_severity_precision).toBe(0.5);
    expect(metrics.human_agreement_rate).toBe(0.5);
    expect(metrics.repair_acceptance_rate).toBe(1);
    expect(metrics.finding_recurrence_rate).toBe(0);
    expect(metrics.missed_defect_rate).toBe(1);
    expect(metrics.review_latency).toEqual({ average_ms: 150, p95_ms: 200 });
    expect(metrics.review_cost).toEqual({ total_cost_units: 8, average_cost_units: 4 });
    expect(metrics.unsupported_finding_rate).toBeCloseTo(1 / 3);
  });

  test("accepts a structured training record but rejects hidden reasoning fields at any depth", () => {
    const record = {
      schema_version: 1,
      task_features: { type: "provider-feature", language: "typescript", risk: "high" },
      reviewer: { profile: "security-reviewer@1.0.0", model_ref: "provider-b/model-x", runtime: "runtime-y" },
      input_snapshot: { contract_hash: HASH_A, diff_hash: HASH_B, evidence_hash: HASH_C },
      output: {
        findings: [{ finding_id: "review-finding:1", category: "security", severity: "HIGH", evidence_strength: "STRONG" }],
        decision: "changes-requested",
      },
      outcomes: { human_agreement: true, confirmed_findings: 1, dismissed_findings: 0, escaped_defects: 0, repair_success: true },
      metrics: { latency_ms: 100, cost_units: 3 },
      recorded_at: NOW,
    };
    expect(parseReviewTrainingRecord(record).output.decision).toBe("changes-requested");
    expect(() => parseReviewTrainingRecord({
      ...record,
      output: { ...record.output, metadata: { chain_of_thought: "hidden trace" } },
    })).toThrow("REVIEW_TRAINING_HIDDEN_REASONING_FORBIDDEN");
  });

  test("creates only analysis cache keys and binds file, analyzer, and profile versions", () => {
    const base = createReviewAnalysisCacheKey({
      analysis_type: "ast-index",
      file_hash: HASH_A,
      analyzer_version: "ast-analyzer@2.0.0",
      review_profile_version: "security-reviewer@1.0.0",
    });
    expect(base.key).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(createReviewAnalysisCacheKey({
      analysis_type: "ast-index",
      file_hash: HASH_B,
      analyzer_version: "ast-analyzer@2.0.0",
      review_profile_version: "security-reviewer@1.0.0",
    }).key).not.toBe(base.key);
    expect(createReviewAnalysisCacheKey({
      analysis_type: "ast-index",
      file_hash: HASH_A,
      analyzer_version: "ast-analyzer@2.1.0",
      review_profile_version: "security-reviewer@1.0.0",
    }).key).not.toBe(base.key);
    expect(createReviewAnalysisCacheKey({
      analysis_type: "ast-index",
      file_hash: HASH_A,
      analyzer_version: "ast-analyzer@2.0.0",
      review_profile_version: "security-reviewer@2.0.0",
    }).key).not.toBe(base.key);
    expect(() => createReviewAnalysisCacheKey({
      analysis_type: "ast-index",
      file_hash: HASH_A,
      analyzer_version: "ast-analyzer@2.0.0",
      review_profile_version: "security-reviewer@1.0.0",
      verdict: "PASS",
    } as never)).toThrow("REVIEW_ANALYSIS_CACHE_KEY_INVALID");
  });
});
