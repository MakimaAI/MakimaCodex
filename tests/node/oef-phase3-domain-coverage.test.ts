import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";

const bundlePath = process.env.OEF_PHASE3_CORE_BUNDLE;
if (!bundlePath) {
  test("Phase 3 domain coverage harness runs only through its coverage script", { skip: true }, () => {});
} else {
const core = await import(pathToFileURL(bundlePath).href);
const {
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
  waiverSchema,
} = core;

const NOW = "2026-07-23T15:00:00.000Z";
const hash = (character: string) => `sha256:${character.repeat(64)}`;
const packageId = `evidence-package:${"d".repeat(64)}`;

function snapshot(overrides = {}) {
  return createReviewSnapshot({
    review_snapshot_id: "review-snapshot:coverage",
    contract: { revision_id: "contract-revision:coverage", revision: 1, hash: hash("a") },
    source: { base_commit: "abc", result_tree_hash: hash("b"), diff_hash: hash("c") },
    evidence: { package_id: packageId, package_hash: hash("d") },
    workflow: { id: "software-development", version: "1.0.0", hash: hash("e") },
    policy: { id: "safe-default", version: "1.0.0", hash: hash("f") },
    created_at: NOW,
    ...overrides,
  });
}

function profile(overrides = {}) {
  return createReviewProfile({
    review_profile_id: "code-quality", version: "1.0.0", objective: "Review independently.",
    required_inputs: ["task-contract", "diff"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["repository-navigation"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true }, output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic", version: "1.0.0" }, budgets: { max_wall_time_seconds: 60, max_output_tokens: 1000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {}, created_at: NOW, ...overrides,
  });
}

function plan(overrides = {}) {
  const p = profile();
  return {
    schema_version: 1, review_plan_id: "review-plan:coverage", revision: 1, previous_revision_hash: null,
    review_request_id: "review-request:coverage", task_id: "task:coverage", snapshot: snapshot(),
    risk: { level: "low", reasons: [] },
    review_units: [{ review_unit_id: "review-unit:quality", review_type: "opencodex.code-quality", profile_ref: { id: p.review_profile_id, version: p.version, hash: p.content_hash }, required: true, required_capabilities: ["diff-analysis"], preferred_capabilities: ["repository-navigation"], depends_on: [], prerequisites: [] }],
    execution_strategy: { parallel_groups: [["review-unit:quality"]] },
    adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: hash("a") },
    quorum: { required_review_types: ["opencodex.code-quality"], minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" },
    budget: { max_wall_time_seconds: 60, max_total_output_tokens: 1000, max_review_units: 3, max_parallel_units: 2 },
    limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 5, max_adjudication_rounds: 1, max_total_cost_units: 100 },
    created_at: NOW, ...overrides,
  };
}

function state(overrides = {}) {
  return {
    schema_version: 1, review_plan_id: "review-plan:coverage", snapshot_hash: snapshot().snapshot_hash, status: "CREATED",
    unit_states: [{ review_unit_id: "review-unit:quality", status: "CREATED", review_execution_id: null, result_artifact_id: null }],
    counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
    aggregate_version: 1, created_at: NOW, updated_at: NOW, ...overrides,
  };
}

function finding(overrides = {}) {
  return {
    schema_version: 1, finding_id: "review-finding:coverage", finding_key: "FIND-COVERAGE",
    review_plan_id: "review-plan:coverage", review_unit_id: "review-unit:quality", category: "correctness",
    proposed_severity: "HIGH", effective_severity: null, confidence: 0.9, status: "PROPOSED",
    claim: "403 is wrong.", impact: "Auth failures rotate accounts.",
    scope: { snapshot_hash: snapshot().snapshot_hash, contract_revision_id: "contract-revision:coverage", source_tree_hash: hash("b"), diff_hash: hash("c") },
    anchors: [{ type: "code", path: "src/a.ts", line_start: 1, line_end: 2, file_hash: hash("a"), symbol: null, snippet_hash: hash("b") }],
    contract_refs: ["AC-1"], evidence_refs: ["evidence:test"], evidence_strength: "STRONG",
    proposed_by: { reviewer_binding_id: "reviewer-binding:coverage" }, created_at: NOW, updated_at: NOW, duplicate_of: null,
    ...overrides,
  };
}

describe("Phase 3 domain branch coverage", () => {
  test("review request, snapshot, and profile invariants", () => {
    const request = {
      schema_version: 1, review_request_id: "review-request:coverage", task_id: "task:coverage",
      contract_revision_id: "contract-revision:coverage", assignment_id: "assignment:coverage", execution_id: "execution:coverage",
      evidence_package_id: packageId, requested_scope: ["opencodex.code-quality"],
      trigger: { type: "workflow-stage", stage: "review" }, created_by: { type: "system", id: "system:test" }, created_at: NOW,
    };
    assert.equal(parseReviewRequest(request).trigger.type, "workflow-stage");
    assert.equal(parseReviewRequest({ ...request, trigger: { type: "manual", reason: "coverage" } }).trigger.type, "manual");
    assert.equal(parseReviewRequest({ ...request, trigger: { type: "repair", repair_proposal_id: "repair-proposal:x" } }).trigger.type, "repair");
    assert.throws(() => parseReviewRequest({ ...request, requested_scope: ["opencodex.code-quality", "opencodex.code-quality"] }));
    const current = snapshot();
    assert.equal(assertReviewSnapshotCurrent(current, current), true);
    assert.throws(() => assertReviewSnapshotCurrent(current, { ...current, source: { ...current.source, diff_hash: hash("f") } }));
    assert.throws(() => assertReviewSnapshotCurrent({}, current));
    const p = profile();
    assert.equal(assertPinnedReviewProfile({ id: p.review_profile_id, version: p.version, hash: p.content_hash }, p), true);
    assert.throws(() => assertPinnedReviewProfile({ id: "other", version: p.version, hash: p.content_hash }, p));
    assert.throws(() => profile({ required_inputs: ["diff", "diff"] }));
    assert.throws(() => profile({ required_capabilities: ["diff-analysis"], preferred_capabilities: ["diff-analysis"] }));
  });

  test("review plan and mutable state invariants", () => {
    const valid = parseReviewPlan(plan());
    assert.match(hashReviewPlan(valid), /^sha256:/);
    assert.equal(assertPlanStateMatchesPlan(valid, parseReviewPlanState(state())), true);
    assert.throws(() => parseReviewPlan(plan({ revision: 2, previous_revision_hash: null })));
    assert.throws(() => parseReviewPlan(plan({ revision: 1, previous_revision_hash: hash("a") })));
    assert.throws(() => parseReviewPlan(plan({ budget: { ...plan().budget, max_review_units: 1 }, review_units: [...plan().review_units, { ...plan().review_units[0], review_unit_id: "review-unit:two", review_type: "opencodex.spec-compliance" }] })));
    assert.throws(() => parseReviewPlan(plan({ budget: { ...plan().budget, max_parallel_units: 1 }, execution_strategy: { parallel_groups: [["review-unit:quality", "review-unit:two"]] } })));
    assert.throws(() => parseReviewPlan(plan({ review_units: [{ ...plan().review_units[0], depends_on: ["review-unit:missing"] }] })));
    assert.throws(() => parseReviewPlan(plan({ execution_strategy: { parallel_groups: [["review-unit:missing"]] } })));
    assert.throws(() => parseReviewPlan(plan({ quorum: { ...plan().quorum, required_review_types: ["opencodex.spec-compliance"] } })));
    assert.throws(() => parseReviewPlanState(state({ updated_at: "2026-07-23T14:00:00.000Z" })));
    assert.throws(() => parseReviewPlanState(state({ unit_states: [state().unit_states[0], state().unit_states[0]] })));
    assert.throws(() => parseReviewPlanState(state({ unit_states: [{ ...state().unit_states[0], status: "RUNNING", review_execution_id: null }] })));
    assert.throws(() => parseReviewPlanState(state({ unit_states: [{ ...state().unit_states[0], result_artifact_id: "artifact:x" }] })));
    assert.throws(() => assertPlanStateMatchesPlan(valid, state({ review_plan_id: "review-plan:other" })));
  });

  test("state transition graphs", () => {
    const planEdges = {
      CREATED: "WAITING_PREREQUISITES", WAITING_PREREQUISITES: "READY", READY: "RUNNING", RUNNING: "COLLECTING",
      COLLECTING: "VALIDATING_FINDINGS", VALIDATING_FINDINGS: "ADJUDICATING", ADJUDICATING: "COMPLETED", COMPLETED: "PASSED",
      PASSED: "SUPERSEDED", CHANGES_REQUESTED: "SUPERSEDED", BLOCKED: "SUPERSEDED", NEEDS_HUMAN: "SUPERSEDED", INCONCLUSIVE: "SUPERSEDED",
    };
    for (const [from, to] of Object.entries(planEdges)) assert.equal(transitionReviewPlan(from, to), to);
    assert.throws(() => transitionReviewPlan("CREATED", "CREATED"));
    assert.throws(() => transitionReviewPlan("CANCELLED", "RUNNING"));
    const findingEdges = { PROPOSED: "VALIDATING", VALIDATING: "CONFIRMED", CONFIRMED: "RESOLVED", RESOLVED: "VERIFIED_RESOLVED", VERIFIED_RESOLVED: "STALE", WAIVED: "STALE" };
    for (const [from, to] of Object.entries(findingEdges)) assert.equal(transitionFinding(from, to), to);
    assert.throws(() => transitionFinding("PROPOSED", "VERIFIED_RESOLVED"));
    assert.throws(() => transitionFinding("STALE", "CONFIRMED"));
  });

  test("finding and waiver lifecycle guards", () => {
    assert.equal(parseReviewFinding(finding()).status, "PROPOSED");
    assert.throws(() => parseReviewFinding(finding({ updated_at: "2026-07-23T14:00:00.000Z" })));
    assert.throws(() => parseReviewFinding(finding({ status: "DUPLICATE", duplicate_of: null })));
    assert.throws(() => parseReviewFinding(finding({ duplicate_of: "review-finding:other" })));
    assert.throws(() => parseReviewFinding(finding({ status: "CONFIRMED", effective_severity: null })));
    assert.throws(() => parseReviewFinding(finding({ status: "CONFIRMED", effective_severity: "HIGH", evidence_strength: "UNSUPPORTED" })));
    assert.throws(() => parseReviewFinding(finding({ anchors: [{ ...finding().anchors[0], path: "../x" }] })));
    assert.throws(() => parseReviewFinding(finding({ anchors: [{ ...finding().anchors[0], line_start: 3, line_end: 2 }] })));
    const low = parseReviewFinding(finding({ status: "CONFIRMED", proposed_severity: "LOW", effective_severity: "LOW" }));
    const waiver = createWaiver({
      waiver_id: "review-waiver:coverage", finding: low, decision: "ACCEPTED_RISK", rationale: "Tracked.",
      approved_by: { type: "human", id: "human:owner" }, expires_at: "2026-09-01T00:00:00.000Z",
      conditions: ["linked-issue"], snapshot_hash: low.scope.snapshot_hash, created_at: NOW,
    });
    assert.equal(assertWaiverApplies(waiver, low, low.scope.snapshot_hash, "2026-08-01T00:00:00.000Z"), true);
    assert.throws(() => createWaiver({ waiver_id: "review-waiver:x", finding: parseReviewFinding(finding()), decision: "ACCEPTED_RISK", rationale: "x", approved_by: { type: "human", id: "human:x" }, expires_at: null, conditions: [], snapshot_hash: low.scope.snapshot_hash, created_at: NOW }));
    assert.throws(() => createWaiver({ waiver_id: "review-waiver:x", finding: parseReviewFinding(finding({ status: "CONFIRMED", effective_severity: "CRITICAL", proposed_severity: "CRITICAL" })), decision: "ACCEPTED_RISK", rationale: "x", approved_by: { type: "human", id: "human:x" }, expires_at: null, conditions: [], snapshot_hash: low.scope.snapshot_hash, created_at: NOW }));
    assert.throws(() => assertWaiverApplies({ ...waiver, status: "EXPIRED" }, low, low.scope.snapshot_hash, "2026-08-01T00:00:00.000Z"));
    assert.throws(() => assertWaiverApplies(waiver, low, hash("f"), "2026-08-01T00:00:00.000Z"));
    assert.throws(() => assertWaiverApplies(waiver, { ...low, finding_id: "review-finding:other" }, low.scope.snapshot_hash, "2026-08-01T00:00:00.000Z"));
    assert.throws(() => assertWaiverApplies(waiver, { ...low, claim: "changed" }, low.scope.snapshot_hash, "2026-08-01T00:00:00.000Z"));
    assert.throws(() => assertWaiverApplies(waiver, low, low.scope.snapshot_hash, "2026-09-01T00:00:00.000Z"));
    assert.throws(() => assertWaiverApplies(waiver, { ...low, effective_severity: "HIGH" }, low.scope.snapshot_hash, "2026-08-01T00:00:00.000Z"));
    assert.throws(() => waiverSchema.parse({ ...waiver, approved_by: { type: "system", id: "system:x" } }));
  });
});
}
