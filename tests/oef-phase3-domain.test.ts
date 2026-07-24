import { describe, expect, test } from "bun:test";
import {
  assertPinnedReviewProfile,
  assertPlanStateMatchesPlan,
  assertReviewSnapshotCurrent,
  assertWaiverApplies,
  createReviewProfile,
  createReviewSnapshot,
  createWaiver,
  hashReviewPlan,
  parseReviewFinding,
  parseReviewPlan,
  parseReviewPlanState,
  parseReviewRequest,
  transitionFinding,
  transitionReviewPlan,
} from "../src/oef/phase3";

const HASH_A = `sha256:${"a".repeat(64)}`;
const HASH_B = `sha256:${"b".repeat(64)}`;
const HASH_C = `sha256:${"c".repeat(64)}`;
const NOW = "2026-07-23T15:00:00.000Z";

function snapshot() {
  return createReviewSnapshot({
    review_snapshot_id: "review-snapshot:test",
    contract: { revision_id: "contract-revision:test", revision: 3, hash: HASH_A },
    source: { base_commit: "abc123", result_tree_hash: HASH_B, diff_hash: HASH_C },
    evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: `sha256:${"d".repeat(64)}` },
    workflow: { id: "software-development", version: "1.0.0", hash: `sha256:${"e".repeat(64)}` },
    policy: { id: "safe-default", version: "1.0.0", hash: `sha256:${"f".repeat(64)}` },
    created_at: NOW,
  });
}

function profile() {
  return createReviewProfile({
    review_profile_id: "code-quality",
    version: "1.0.0",
    objective: "Review correctness and maintainability independently.",
    required_inputs: ["task-contract", "diff", "mechanical-verification"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["repository-navigation"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true, maintainability: true, style: false },
    output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-code-review", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 1200, max_output_tokens: 12000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {},
    created_at: NOW,
  });
}

function finding(overrides: Record<string, unknown> = {}) {
  return parseReviewFinding({
    schema_version: 1,
    finding_id: "review-finding:test-1",
    finding_key: "FIND-001",
    review_plan_id: "review-plan:test",
    review_unit_id: "review-unit:quality",
    category: "correctness",
    proposed_severity: "HIGH",
    effective_severity: "HIGH",
    confidence: 0.93,
    status: "PROPOSED",
    claim: "403 is classified as a rate limit.",
    impact: "Authentication failures can rotate to the wrong account.",
    scope: { snapshot_hash: snapshot().snapshot_hash, contract_revision_id: "contract-revision:test", source_tree_hash: HASH_B, diff_hash: HASH_C },
    anchors: [{
      type: "code",
      path: "src/providers/clinepass/error-classifier.ts",
      line_start: 42,
      line_end: 61,
      file_hash: HASH_A,
      symbol: { type: "function", name: "classifyError" },
      snippet_hash: HASH_B,
    }],
    contract_refs: ["AC-2"],
    evidence_refs: ["evidence:test-403"],
    evidence_strength: "STRONG",
    proposed_by: { reviewer_binding_id: "reviewer-binding:test" },
    created_at: NOW,
    updated_at: NOW,
    duplicate_of: null,
    ...overrides,
  });
}

describe("Phase 3 review domain", () => {
  test("keeps review requests model-agnostic and binds them to Phase 1/2 evidence", () => {
    const request = parseReviewRequest({
      schema_version: 1,
      review_request_id: "review-request:test",
      task_id: "task:test",
      contract_revision_id: "contract-revision:test",
      assignment_id: "assignment:test",
      execution_id: "execution:test",
      evidence_package_id: `evidence-package:${"d".repeat(64)}`,
      requested_scope: ["opencodex.spec-compliance", "opencodex.code-quality"],
      trigger: { type: "workflow-stage", stage: "review" },
      created_by: { type: "system", id: "system:review-coordinator" },
      created_at: NOW,
    });
    expect(request).not.toHaveProperty("model_ref");
    expect(request.requested_scope).toEqual(["opencodex.spec-compliance", "opencodex.code-quality"]);
  });

  test("hashes immutable snapshots and rejects stale source, contract, or evidence", () => {
    const current = snapshot();
    expect(current.snapshot_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(assertReviewSnapshotCurrent(current, current)).toBeTrue();
    expect(() => assertReviewSnapshotCurrent(current, {
      ...current,
      source: { ...current.source, diff_hash: HASH_A },
    })).toThrow("REVIEW_SNAPSHOT_STALE");
  });

  test("pins semantic profiles independently from runtime/model choice", () => {
    const pinned = profile();
    expect(pinned.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(pinned).not.toHaveProperty("model_ref");
    expect(assertPinnedReviewProfile({ id: pinned.review_profile_id, version: pinned.version, hash: pinned.content_hash }, pinned)).toBeTrue();
    const drifted = createReviewProfile({ ...pinned, objective: "Silently changed objective.", content_hash: undefined } as never);
    expect(() => assertPinnedReviewProfile({ id: pinned.review_profile_id, version: pinned.version, hash: pinned.content_hash }, drifted))
      .toThrow("REVIEW_PROFILE_HASH_MISMATCH");
  });

  test("validates a hash-linked deterministic review plan and separate unit state", () => {
    const pinned = profile();
    const plan = parseReviewPlan({
      schema_version: 1,
      review_plan_id: "review-plan:test",
      revision: 1,
      previous_revision_hash: null,
      review_request_id: "review-request:test",
      task_id: "task:test",
      snapshot: snapshot(),
      risk: { level: "high", reasons: ["authentication"] },
      review_units: [{
        review_unit_id: "review-unit:quality",
        review_type: "opencodex.code-quality",
        profile_ref: { id: pinned.review_profile_id, version: pinned.version, hash: pinned.content_hash },
        required: true,
        required_capabilities: ["diff-analysis", "structured-findings"],
        preferred_capabilities: ["repository-navigation"],
        depends_on: [],
        prerequisites: ["mechanical-verification.passed", "workspace.sealed"],
      }],
      execution_strategy: { parallel_groups: [["review-unit:quality"]] },
      adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: HASH_A },
      quorum: { required_review_types: ["opencodex.code-quality"], minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" },
      budget: { max_wall_time_seconds: 3600, max_total_output_tokens: 40000, max_review_units: 5, max_parallel_units: 3 },
      limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 5, max_adjudication_rounds: 1, max_total_cost_units: 100 },
      created_at: NOW,
    });
    expect(hashReviewPlan(plan)).toMatch(/^sha256:[a-f0-9]{64}$/);
    const state = parseReviewPlanState({
      schema_version: 1,
      review_plan_id: plan.review_plan_id,
      snapshot_hash: plan.snapshot.snapshot_hash,
      status: "CREATED",
      unit_states: [{ review_unit_id: "review-unit:quality", status: "CREATED", review_execution_id: null, result_artifact_id: null }],
      counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
      aggregate_version: 1,
      created_at: NOW,
      updated_at: NOW,
    });
    expect(state.unit_states[0]?.status).toBe("CREATED");
    expect(assertPlanStateMatchesPlan(plan, state)).toBeTrue();
    expect(() => assertPlanStateMatchesPlan(plan, {
      ...state,
      unit_states: [{ review_unit_id: "review-unit:invented", status: "CREATED", review_execution_id: null, result_artifact_id: null }],
    })).toThrow("REVIEW_PLAN_STATE_MISMATCH");
    expect(transitionReviewPlan("CREATED", "WAITING_PREREQUISITES")).toBe("WAITING_PREREQUISITES");
    expect(() => transitionReviewPlan("COMPLETED", "RUNNING")).toThrow("Invalid review plan transition");
  });

  test("keeps severity, confidence, evidence strength, and finding lifecycle distinct", () => {
    const proposed = finding();
    expect(proposed.proposed_severity).toBe("HIGH");
    expect(proposed.confidence).toBe(0.93);
    expect(proposed.evidence_strength).toBe("STRONG");
    expect(transitionFinding("PROPOSED", "VALIDATING")).toBe("VALIDATING");
    expect(transitionFinding("VALIDATING", "CONFIRMED")).toBe("CONFIRMED");
    expect(() => transitionFinding("PROPOSED", "VERIFIED_RESOLVED")).toThrow("Invalid finding transition");
    expect(() => finding({ anchors: [{ type: "code", path: "../secret", line_start: 2, line_end: 1, file_hash: HASH_A, symbol: null, snippet_hash: HASH_B }] }))
      .toThrow();
  });

  test("binds waivers to one snapshot and rejects critical waivers by default", () => {
    const current = snapshot();
    const low = finding({ proposed_severity: "LOW", effective_severity: "LOW", status: "CONFIRMED" });
    const waiver = createWaiver({
      waiver_id: "review-waiver:test",
      finding: low,
      decision: "ACCEPTED_RISK",
      rationale: "Tracked by issue #432.",
      approved_by: { type: "human", id: "human:local-owner" },
      expires_at: "2026-09-01T00:00:00.000Z",
      conditions: ["linked-issue-required", "no-severity-increase"],
      snapshot_hash: current.snapshot_hash,
      created_at: NOW,
    });
    expect(assertWaiverApplies(waiver, low, current.snapshot_hash, "2026-08-01T00:00:00.000Z")).toBeTrue();
    expect(() => assertWaiverApplies(waiver, { ...low, claim: "Mutated after approval." }, current.snapshot_hash, "2026-08-01T00:00:00.000Z"))
      .toThrow("WAIVER_FINDING_CHANGED");
    expect(() => assertWaiverApplies(waiver, low, HASH_A, "2026-08-01T00:00:00.000Z")).toThrow("WAIVER_SNAPSHOT_MISMATCH");
    expect(() => createWaiver({
      waiver_id: "review-waiver:critical",
      finding: finding({ proposed_severity: "CRITICAL", effective_severity: "CRITICAL", status: "CONFIRMED" }),
      decision: "ACCEPTED_RISK",
      rationale: "Not allowed.",
      approved_by: { type: "human", id: "human:local-owner" },
      expires_at: null,
      conditions: [],
      snapshot_hash: current.snapshot_hash,
      created_at: NOW,
    })).toThrow("CRITICAL_FINDING_WAIVER_FORBIDDEN");
    expect(() => createWaiver({
      waiver_id: "review-waiver:already-expired",
      finding: low,
      decision: "ACCEPTED_RISK",
      rationale: "An expired waiver must never become active.",
      approved_by: { type: "human", id: "human:local-owner" },
      expires_at: "2026-07-22T00:00:00.000Z",
      conditions: [],
      snapshot_hash: current.snapshot_hash,
      created_at: NOW,
    })).toThrow("WAIVER_EXPIRED_AT_CREATION");
    expect(() => assertWaiverApplies({
      ...waiver,
      effective_severity_at_approval: "CRITICAL",
    }, finding({ proposed_severity: "CRITICAL", effective_severity: "CRITICAL", status: "CONFIRMED" }), current.snapshot_hash, "2026-08-01T00:00:00.000Z"))
      .toThrow("CRITICAL_FINDING_WAIVER_FORBIDDEN");
  });
});
