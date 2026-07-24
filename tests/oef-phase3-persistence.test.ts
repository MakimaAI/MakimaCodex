import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SqlitePhase3Store,
  createGovernanceAuditEvent,
  createHumanReviewApproval,
  createWaiver,
  createReviewProfile,
  createReviewSnapshot,
  hashReviewPlan,
  parseReviewFinding,
  parseReviewPlan,
  parseReviewPlanState,
  parseReviewDecisionRecord,
  parseReviewRequest,
  waiverSchema,
  type ReviewAuditEvent,
} from "../src/oef/phase3";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
const NOW = "2026-07-23T15:00:00.000Z";
const hash = (value: string) => `sha256:${value.repeat(64)}`;
function databasePath(): string { const root = mkdtempSync(join(tmpdir(), "oef-phase3-store-")); roots.push(root); return join(root, "oef.sqlite"); }

function fixtures() {
  const snapshot = createReviewSnapshot({
    review_snapshot_id: "review-snapshot:store",
    contract: { revision_id: "contract-revision:store", revision: 1, hash: hash("a") },
    source: { base_commit: "abc123", result_tree_hash: hash("b"), diff_hash: hash("c") },
    evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: hash("d") },
    workflow: { id: "software-development", version: "1.0.0", hash: hash("e") },
    policy: { id: "safe-default", version: "1.0.0", hash: hash("f") },
    created_at: NOW,
  });
  const profile = createReviewProfile({
    review_profile_id: "spec-compliance", version: "1.0.0", objective: "Trace every criterion to code and evidence.",
    required_inputs: ["task-contract", "diff"], required_capabilities: ["diff-analysis", "contract-traceability", "structured-findings"],
    preferred_capabilities: ["repository-navigation"], workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true }, output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-review", version: "1.0.0" }, budgets: { max_wall_time_seconds: 1200, max_output_tokens: 12000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {}, created_at: NOW,
  });
  const request = parseReviewRequest({
    schema_version: 1, review_request_id: "review-request:store", task_id: "task:store", contract_revision_id: "contract-revision:store",
    assignment_id: "assignment:store", execution_id: "execution:store", evidence_package_id: `evidence-package:${"d".repeat(64)}`,
    requested_scope: ["opencodex.spec-compliance"], trigger: { type: "workflow-stage", stage: "review" },
    created_by: { type: "system", id: "system:review-coordinator" }, created_at: NOW,
  });
  const plan = parseReviewPlan({
    schema_version: 1, review_plan_id: "review-plan:store", revision: 1, previous_revision_hash: null,
    review_request_id: request.review_request_id, task_id: request.task_id, snapshot, risk: { level: "low", reasons: [] },
    review_units: [{ review_unit_id: "review-unit:spec", review_type: "opencodex.spec-compliance", profile_ref: { id: profile.review_profile_id, version: profile.version, hash: profile.content_hash }, required: true, required_capabilities: ["diff-analysis", "contract-traceability", "structured-findings"], preferred_capabilities: ["repository-navigation"], depends_on: [], prerequisites: ["mechanical-verification.passed"] }],
    execution_strategy: { parallel_groups: [["review-unit:spec"]] }, adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: hash("a") },
    quorum: { required_review_types: ["opencodex.spec-compliance"], minimum_independent_providers: 1, minimum_independence_score: 1, human_approval: "not-required" },
    budget: { max_wall_time_seconds: 3600, max_total_output_tokens: 40000, max_review_units: 5, max_parallel_units: 3 },
    limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 5, max_adjudication_rounds: 1, max_total_cost_units: 100 },
    created_at: NOW,
  });
  const state = parseReviewPlanState({
    schema_version: 1, review_plan_id: plan.review_plan_id, snapshot_hash: snapshot.snapshot_hash, status: "CREATED",
    unit_states: [{ review_unit_id: "review-unit:spec", status: "CREATED", review_execution_id: null, result_artifact_id: null }],
    counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
    aggregate_version: 1, created_at: NOW, updated_at: NOW,
  });
  const finding = parseReviewFinding({
    schema_version: 1, finding_id: "review-finding:store", finding_key: "FIND-STORE", review_plan_id: plan.review_plan_id,
    review_unit_id: "review-unit:spec", category: "correctness", proposed_severity: "HIGH", effective_severity: null,
    confidence: 0.9, status: "PROPOSED", claim: "A required criterion is not satisfied.", impact: "The requested behavior is absent.",
    scope: { snapshot_hash: snapshot.snapshot_hash, contract_revision_id: request.contract_revision_id, source_tree_hash: snapshot.source.result_tree_hash, diff_hash: snapshot.source.diff_hash },
    anchors: [{ type: "code", path: "src/example.ts", line_start: 1, line_end: 3, file_hash: hash("a"), symbol: null, snippet_hash: hash("b") }],
    contract_refs: ["AC-1"], evidence_refs: [], evidence_strength: "SUPPORTED",
    proposed_by: { reviewer_binding_id: "reviewer-binding:spec" }, created_at: NOW, updated_at: NOW, duplicate_of: null,
  });
  return { snapshot, profile, request, plan, state, finding };
}

describe("Phase 3 SQLite persistence", () => {
  test("persists immutable profiles, requests, plans and restart-readable state", () => {
    const path = databasePath();
    const values = fixtures();
    const store = new SqlitePhase3Store({ databasePath: path });
    expect(store.getAppliedMigrations()).toEqual(["001_review_core", "002_review_governance", "003_review_approval", "004_review_validity"]);
    store.transaction(() => {
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), values.state);
    });
    const approval = createHumanReviewApproval({
      approval_id: "review-approval:store",
      review_plan_id: values.plan.review_plan_id,
      snapshot_hash: values.snapshot.snapshot_hash,
      review_decision_id: "review-decision:premature",
      review_decision_hash: hash("f"),
      finding_ids: [],
      decision: "APPROVE",
      rationale: "The pinned snapshot was reviewed by the accountable owner.",
      approved_by: { type: "human", id: "human:security-owner" },
      approval_artifact_ref: "artifact:approval-store",
      approved_at: NOW,
    });
    expect(() => store.insertHumanApproval(approval)).toThrow("Human approval requires a NEEDS_HUMAN review state");
    const validityBaseline = {
      contract_hash: values.snapshot.contract.hash,
      source_tree_hash: values.snapshot.source.result_tree_hash,
      diff_hash: values.snapshot.source.diff_hash,
      evidence_package_hash: values.snapshot.evidence.package_hash,
      policy_hash: values.snapshot.policy.hash,
      profile_hashes: [values.profile.content_hash],
      required_evidence_hashes: [values.snapshot.evidence.package_hash],
      dependency_hash: hash("8"),
    };
    store.insertReviewValidityBaseline(values.plan.review_plan_id, 1, validityBaseline, NOW);
    store.close();

    const reopened = new SqlitePhase3Store({ databasePath: path });
    try {
      expect(reopened.getReviewProfile("spec-compliance", "1.0.0")).toEqual(values.profile);
      expect(reopened.getReviewRequest(values.request.review_request_id)).toEqual(values.request);
      expect(reopened.getReviewPlan(values.plan.review_plan_id)).toEqual(values.plan);
      expect(reopened.getReviewPlanState(values.plan.review_plan_id)).toEqual(values.state);
      expect(reopened.getLatestHumanApproval(values.plan.review_plan_id)).toBeNull();
      expect(reopened.getReviewValidityBaseline(values.plan.review_plan_id)).toEqual(validityBaseline);
    } finally { reopened.close(); }
  });

  test("persists only an approval bound to the latest NEEDS_HUMAN decision and its findings", () => {
    const values = fixtures();
    const store = new SqlitePhase3Store({ databasePath: databasePath() });
    try {
      const needsHumanState = parseReviewPlanState({ ...values.state, status: "NEEDS_HUMAN" });
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), needsHumanState);
      const decision = parseReviewDecisionRecord({
        schema_version: 1,
        review_decision_id: "review-decision:human-gate",
        review_plan_id: values.plan.review_plan_id,
        snapshot_hash: values.snapshot.snapshot_hash,
        decision: "NEEDS_HUMAN",
        decision_source: "deterministic-policy",
        current_snapshot: true,
        quorum_satisfied: false,
        mechanical_verification_passed: true,
        accepted_findings: [values.finding.finding_id],
        dismissed_findings: [], unresolved_findings: [], waived_findings: [], waiver_ids: [], human_approval: null,
        severity_counts: { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
        reason_codes: ["critical-finding-human-approval-missing"],
        rationale: "A confirmed critical finding requires accountable human approval.",
        next_action: { type: "human-gate" },
        decision_artifact_ref: "artifact:human-gate-decision",
        issued_at: NOW,
      });
      store.insertReviewDecision(decision);
      const approval = createHumanReviewApproval({
        approval_id: "review-approval:bound",
        review_plan_id: values.plan.review_plan_id,
        snapshot_hash: values.snapshot.snapshot_hash,
        review_decision_id: decision.review_decision_id,
        review_decision_hash: canonicalSha256(decision),
        finding_ids: [values.finding.finding_id],
        decision: "APPROVE",
        rationale: "The accountable owner approved the exact decision and critical finding.",
        approved_by: { type: "human", id: "human:security-owner" },
        approval_artifact_ref: "artifact:approval-bound",
        approved_at: NOW,
      });
      store.insertHumanApproval(approval);
      expect(store.getLatestHumanApproval(values.plan.review_plan_id)).toEqual(approval);
      const unrelated = createHumanReviewApproval({ ...approval, approval_id: "review-approval:unrelated", finding_ids: [] });
      expect(() => store.insertHumanApproval(unrelated)).toThrow("Human approval finding binding mismatch");
    } finally { store.close(); }
  });

  test("enforces optimistic plan state and finding lifecycle updates", () => {
    const store = new SqlitePhase3Store({ databasePath: databasePath() });
    const values = fixtures();
    try {
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), values.state);
      const ready = parseReviewPlanState({ ...values.state, status: "WAITING_PREREQUISITES", aggregate_version: 2, updated_at: "2026-07-23T15:00:01.000Z" });
      expect(store.updateReviewPlanState(ready, 1)).toBeTrue();
      expect(store.updateReviewPlanState({ ...ready, aggregate_version: 3 }, 1)).toBeFalse();

      store.insertFinding(values.finding);
      expect(() => store.insertFinding(parseReviewFinding({
        ...values.finding,
        finding_id: "review-finding:terminal-insert",
        finding_key: "FIND-TERMINAL-INSERT",
        status: "CONFIRMED",
        effective_severity: "HIGH",
      }))).toThrow("New findings must start as PROPOSED");
      expect(() => store.insertWaiver(waiverSchema.parse({
        schema_version: 1,
        waiver_id: "review-waiver:critical-insert",
        finding_id: values.finding.finding_id,
        decision: "ACCEPTED_RISK",
        rationale: "Critical risk should never be persistable as a waiver.",
        approved_by: { type: "human", id: "human:security-owner" },
        expires_at: null,
        conditions: [],
        snapshot_hash: values.snapshot.snapshot_hash,
        finding_snapshot_hash: values.snapshot.snapshot_hash,
        finding_hash: hash("9"),
        effective_severity_at_approval: "CRITICAL",
        created_at: NOW,
        status: "ACTIVE",
      }))).toThrow("Critical findings cannot be waived");
      expect(() => store.updateFinding(parseReviewFinding({
        ...values.finding,
        status: "VERIFIED_RESOLVED",
        effective_severity: "HIGH",
        updated_at: "2026-07-23T15:00:01.000Z",
      }), "PROPOSED")).toThrow("Invalid finding transition");
      const validating = parseReviewFinding({ ...values.finding, status: "VALIDATING", updated_at: "2026-07-23T15:00:01.000Z" });
      expect(store.updateFinding(validating, "PROPOSED")).toBeTrue();
      expect(store.updateFinding({ ...validating, status: "DISMISSED" }, "PROPOSED")).toBeFalse();
      expect(store.listFindings(values.plan.review_plan_id)).toEqual([validating]);
    } finally { store.close(); }
  });

  test("stores an append-only hash-linked audit chain with idempotent event receipt", () => {
    const store = new SqlitePhase3Store({ databasePath: databasePath() });
    const values = fixtures();
    try {
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), values.state);
      const first: ReviewAuditEvent = createGovernanceAuditEvent({
        event_id: "review-event:1", event_type: "review.plan.created", aggregate_type: "review-plan",
        aggregate_id: values.plan.review_plan_id, aggregate_version: 1, task_id: values.plan.task_id, occurred_at: NOW,
        actor: { type: "system", id: "system:review-coordinator" },
        payload: { source_tree_hash: values.snapshot.source.result_tree_hash, contract_revision: 1, plan_revision: 1, required_unit_ids: ["review-unit:spec"] },
        previous_event_hash: null,
      });
      store.appendEvent(first);
      expect(store.appendEvent(first)).toEqual({ status: "DUPLICATE" });
      expect(store.listEvents(values.plan.review_plan_id)).toEqual([first]);
      expect(store.verifyEventChain(values.plan.review_plan_id)).toEqual({ valid: true, event_count: 1 });
      expect(() => store.appendEvent({ ...first, event_id: "review-event:tampered", event_hash: hash("1") }))
        .toThrow("REVIEW_AUDIT_EVENT_INVALID");
      const wrongLink = createGovernanceAuditEvent({
        event_id: "review-event:2", event_type: "review.plan.activated", aggregate_type: "review-plan",
        aggregate_id: values.plan.review_plan_id, aggregate_version: 2, task_id: values.plan.task_id, occurred_at: "2026-07-23T15:00:01.000Z",
        actor: { type: "system", id: "system:review-coordinator" }, payload: {}, previous_event_hash: hash("9"),
      });
      expect(() => store.appendEvent(wrongLink)).toThrow("REVIEW_AUDIT_CHAIN_INVALID");
    } finally { store.close(); }
  });

  test("database triggers prevent mutation of immutable review inputs", () => {
    const path = databasePath();
    const values = fixtures();
    const store = new SqlitePhase3Store({ databasePath: path });
    store.insertReviewProfile(values.profile);
    store.insertReviewRequest(values.request);
    store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), values.state);
    store.close();

    const raw = new Database(path, { strict: true });
    try {
      expect(() => raw.query("UPDATE phase3_review_profiles SET profile_json = '{}' WHERE profile_id = ?").run(values.profile.review_profile_id))
        .toThrow("phase3 review profiles are immutable");
      expect(() => raw.query("DELETE FROM phase3_review_plan_revisions WHERE review_plan_id = ?").run(values.plan.review_plan_id))
        .toThrow("phase3 review plan revisions are append-only");
    } finally { raw.close(); }
  });

  test("persists a hash-linked second plan revision and replaces only mutable state", () => {
    const store = new SqlitePhase3Store({ databasePath: databasePath() });
    const values = fixtures();
    try {
      const passed = parseReviewPlanState({
        ...values.state,
        status: "PASSED",
        unit_states: [{ review_unit_id: "review-unit:spec", status: "COMPLETED", review_execution_id: null, result_artifact_id: "artifact:revision-one-result" }],
      });
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), passed);
      const superseded = parseReviewPlanState({ ...passed, status: "SUPERSEDED", aggregate_version: 2, updated_at: "2026-07-23T15:00:01.000Z" });
      expect(store.updateReviewPlanState(superseded, 1)).toBeTrue();

      const nextSnapshot = createReviewSnapshot({
        review_snapshot_id: "review-snapshot:store-r2",
        contract: values.snapshot.contract,
        source: { ...values.snapshot.source, diff_hash: hash("9") },
        evidence: values.snapshot.evidence,
        workflow: values.snapshot.workflow,
        policy: values.snapshot.policy,
        created_at: "2026-07-23T15:00:02.000Z",
      });
      const revisionTwo = parseReviewPlan({
        ...values.plan,
        revision: 2,
        previous_revision_hash: hashReviewPlan(values.plan),
        snapshot: nextSnapshot,
        created_at: "2026-07-23T15:00:02.000Z",
      });
      const revisionTwoState = parseReviewPlanState({
        ...values.state,
        snapshot_hash: nextSnapshot.snapshot_hash,
        aggregate_version: 3,
        created_at: "2026-07-23T15:00:02.000Z",
        updated_at: "2026-07-23T15:00:02.000Z",
      });
      store.insertReviewPlan(revisionTwo, hashReviewPlan(revisionTwo), revisionTwoState);
      expect(store.getReviewPlan(values.plan.review_plan_id, 1)).toEqual(values.plan);
      expect(store.getReviewPlan(values.plan.review_plan_id)).toEqual(revisionTwo);
      expect(store.getReviewPlanState(values.plan.review_plan_id)).toEqual(revisionTwoState);
    } finally { store.close(); }
  });

  test("rejects same-snapshot reruns without governance and permits the exact snapshot after a waiver", () => {
    const store = new SqlitePhase3Store({ databasePath: databasePath() });
    const values = fixtures();
    try {
      const changes = parseReviewPlanState({ ...values.state, status: "CHANGES_REQUESTED" });
      store.insertReviewProfile(values.profile);
      store.insertReviewRequest(values.request);
      store.insertReviewPlan(values.plan, hashReviewPlan(values.plan), changes);
      store.insertFinding(values.finding);
      const validating = parseReviewFinding({ ...values.finding, status: "VALIDATING" });
      expect(store.updateFinding(validating, "PROPOSED")).toBeTrue();
      const confirmed = parseReviewFinding({ ...validating, status: "CONFIRMED", effective_severity: "HIGH" });
      expect(store.updateFinding(confirmed, "VALIDATING")).toBeTrue();
      const superseded = parseReviewPlanState({ ...changes, status: "SUPERSEDED", aggregate_version: 2, updated_at: "2026-07-23T15:00:01.000Z" });
      expect(store.updateReviewPlanState(superseded, 1)).toBeTrue();
      const revisionTwo = parseReviewPlan({ ...values.plan, revision: 2, previous_revision_hash: hashReviewPlan(values.plan), created_at: "2026-07-23T15:00:02.000Z" });
      const revisionTwoState = parseReviewPlanState({ ...values.state, aggregate_version: 3, created_at: "2026-07-23T15:00:02.000Z", updated_at: "2026-07-23T15:00:02.000Z" });
      expect(() => store.insertReviewPlan(revisionTwo, hashReviewPlan(revisionTwo), revisionTwoState))
        .toThrow("Review plan revision requires a new snapshot or a governance change");
      store.insertWaiver(createWaiver({
        waiver_id: "review-waiver:same-snapshot",
        finding: confirmed,
        decision: "ACCEPTED_RISK",
        rationale: "The owner accepts this bounded high-severity risk for this exact snapshot.",
        approved_by: { type: "human", id: "human:security-owner" },
        expires_at: null,
        conditions: ["no-severity-increase"],
        snapshot_hash: values.snapshot.snapshot_hash,
        created_at: NOW,
      }));
      store.insertReviewPlan(revisionTwo, hashReviewPlan(revisionTwo), revisionTwoState);
      expect(store.getReviewPlan(values.plan.review_plan_id)?.revision).toBe(2);
    } finally { store.close(); }
  });
});
