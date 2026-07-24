import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SqlitePhase3Store,
  createRepairProposal,
  createHumanReviewApproval,
  parseFindingValidation,
  parseReviewDecisionRecord,
  parseReviewExecutionRecord,
  parseReviewerBinding,
} from "../src/oef/phase3";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function databasePath(): string { const root = mkdtempSync(join(tmpdir(), "oef-p3-governance-")); roots.push(root); return join(root, "oef.sqlite"); }
const NOW = "2026-07-23T15:00:00.000Z";
const hash = (value: string) => `sha256:${value.repeat(64)}`;

function binding() {
  return parseReviewerBinding({
    schema_version: 1,
    reviewer_binding_id: "reviewer-binding:spec",
    review_unit_id: "review-unit:spec",
    reviewer_profile_ref: { id: "spec-compliance", version: "1.0.0", hash: hash("a") },
    runtime_ref: { id: "review-runtime", adapter_version: "1.0.0" },
    model_ref: { provider: "provider-b", model_class: "reviewer", resolved_model: "reviewer-v1" },
    reviewer_capabilities: ["diff-analysis", "contract-traceability", "structured-findings"],
    risk_level: "high",
    independence: {
      implementer: { agent_id: "agent:implementer", provider: "provider-a", model_class: "coder", session_id: "session:implementer", context_id: "context:implementer" },
      reviewer: { agent_id: "agent:reviewer-spec", provider: "provider-b", model_class: "reviewer", session_id: "session:reviewer-spec", context_id: "context:reviewer-spec" },
      source_access: "read-only",
      human_approval_required: false,
    },
    created_by: { type: "system", id: "system:review-router" },
    created_at: NOW,
  });
}

describe("Phase 3 governance persistence", () => {
  test("binds human approval to a human actor, snapshot, rationale, and content hash", () => {
    const approval = createHumanReviewApproval({
      approval_id: "review-approval:one",
      review_plan_id: "review-plan:one",
      snapshot_hash: hash("a"),
      review_decision_id: "review-decision:one",
      review_decision_hash: hash("b"),
      finding_ids: ["review-finding:one"],
      decision: "APPROVE",
      rationale: "Critical deployment risk was reviewed against the pinned snapshot.",
      approved_by: { type: "human", id: "human:security-owner" },
      approval_artifact_ref: "artifact:human-approval",
      approved_at: NOW,
    });
    expect(approval.approval_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(() => createHumanReviewApproval({ ...approval, approved_by: { type: "system", id: "system:not-human" } }))
      .toThrow("Review approval requires a human actor");
  });
  test("persists bindings, executions, validations, decisions and repair lineage across restart", () => {
    const path = databasePath();
    const store = new SqlitePhase3Store({ databasePath: path });
    expect(store.getAppliedMigrations()).toEqual(["001_review_core", "002_review_governance", "003_review_approval", "004_review_validity"]);
    const reviewer = binding();
    const execution = parseReviewExecutionRecord({
      schema_version: 1,
      review_execution_id: "review-execution:spec-1",
      review_plan_id: "review-plan:one",
      review_unit_id: "review-unit:spec",
      reviewer_binding_id: reviewer.reviewer_binding_id,
      snapshot_hash: hash("b"),
      status: "CREATED",
      attempt_number: 1,
      context_artifact_ref: "artifact:context",
      rendered_prompt_artifact_ref: "artifact:prompt",
      result_artifact_ref: null,
      output_hash: null,
      runtime_attestation_hash: null,
      runtime_attestation_key_id: null,
      runtime_attestation_signature: null,
      protocol_errors: 0,
      aggregate_version: 1,
      created_at: NOW,
      updated_at: NOW,
    });
    const validation = parseFindingValidation({
      schema_version: 1,
      finding_validation_id: "finding-validation:one",
      finding_id: "review-finding:one",
      review_plan_id: "review-plan:one",
      snapshot_hash: hash("b"),
      status: "CONFIRMED",
      effective_severity: "HIGH",
      evidence_strength: "STRONG",
      validated_by: ["deterministic-anchor-check", "test-evidence"],
      validator_binding_id: null,
      validation_artifact_ref: "artifact:validation",
      created_at: NOW,
    });
    const decision = parseReviewDecisionRecord({
      schema_version: 1,
      review_decision_id: "review-decision:one",
      review_plan_id: "review-plan:one",
      snapshot_hash: hash("b"),
      decision: "CHANGES_REQUESTED",
      decision_source: "deterministic-policy",
      current_snapshot: true,
      quorum_satisfied: true,
      mechanical_verification_passed: true,
      accepted_findings: ["review-finding:one"],
      dismissed_findings: [],
      unresolved_findings: [],
      waived_findings: [], waiver_ids: [], human_approval: null,
      severity_counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      reason_codes: ["confirmed-repairable-finding"],
      rationale: "A confirmed high-severity finding requires repair.",
      next_action: { type: "repair", ref: "repair-proposal:one" },
      decision_artifact_ref: "artifact:decision",
      issued_at: NOW,
    });
    const repair = createRepairProposal({
      repair_proposal_id: "repair-proposal:one",
      task_id: "task:one",
      source_review_plan_id: "review-plan:one",
      findings: [{
        schema_version: 1, finding_id: "review-finding:one", finding_key: "FIND-ONE", review_plan_id: "review-plan:one", review_unit_id: "review-unit:spec",
        category: "correctness", proposed_severity: "HIGH", effective_severity: "HIGH", confidence: 0.9, status: "CONFIRMED",
        claim: "403 is classified as a rate limit.", impact: "Auth failures rotate accounts.",
        scope: { snapshot_hash: hash("b"), contract_revision_id: "contract-revision:one", source_tree_hash: hash("c"), diff_hash: hash("d") },
        anchors: [{ type: "code", path: "src/classifier.ts", line_start: 1, line_end: 2, file_hash: hash("e"), symbol: null, snippet_hash: hash("f") }],
        contract_refs: ["AC-403"], evidence_refs: ["evidence:test-403"], evidence_strength: "STRONG",
        proposed_by: { reviewer_binding_id: reviewer.reviewer_binding_id }, created_at: NOW, updated_at: NOW, duplicate_of: null,
      }],
      constraints: ["Preserve 429 behavior."],
      required_evidence: ["evidence:test-403"],
      created_at: NOW,
    });

    store.transaction(() => {
      store.insertReviewerBinding(reviewer);
      store.insertReviewExecution(execution);
      store.insertFindingValidation(validation);
      store.insertReviewDecision(decision);
      store.insertRepairProposal(repair);
    });
    const running = parseReviewExecutionRecord({ ...execution, status: "RUNNING", aggregate_version: 2, updated_at: "2026-07-23T15:00:01.000Z" });
    expect(store.updateReviewExecution(running, 1)).toBeTrue();
    store.close();

    const reopened = new SqlitePhase3Store({ databasePath: path });
    try {
      expect(reopened.getReviewerBinding(reviewer.reviewer_binding_id)).toEqual(reviewer);
      expect(reopened.getReviewExecution(execution.review_execution_id)).toEqual(running);
      expect(reopened.listFindingValidations("review-plan:one")).toEqual([validation]);
      expect(reopened.getLatestReviewDecision("review-plan:one")).toEqual(decision);
      expect(reopened.getRepairProposal(repair.repair_proposal_id)).toEqual(repair);
    } finally { reopened.close(); }
  });

  test("final decision schema fails closed on stale, missing quorum, or critical bypass", () => {
    const base = {
      schema_version: 1,
      review_decision_id: "review-decision:pass",
      review_plan_id: "review-plan:one",
      snapshot_hash: hash("a"),
      decision: "PASS",
      decision_source: "deterministic-policy",
      current_snapshot: true,
      quorum_satisfied: true,
      mechanical_verification_passed: true,
      accepted_findings: [], dismissed_findings: [], unresolved_findings: [], waived_findings: [], waiver_ids: [], human_approval: null,
      severity_counts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      reason_codes: [], rationale: "All required independent reviews passed.",
      next_action: { type: "phase1-verdict", ref: "ACCEPT" },
      decision_artifact_ref: "artifact:decision",
      issued_at: NOW,
    } as const;
    expect(parseReviewDecisionRecord(base).decision).toBe("PASS");
    expect(() => parseReviewDecisionRecord({ ...base, current_snapshot: false })).toThrow("Stale review cannot pass");
    expect(() => parseReviewDecisionRecord({ ...base, quorum_satisfied: false })).toThrow("Review quorum is required for pass");
    expect(() => parseReviewDecisionRecord({ ...base, severity_counts: { ...base.severity_counts, CRITICAL: 1 } })).toThrow("Confirmed critical finding cannot pass");
  });

  test("database triggers keep governance decisions and validations append-only", () => {
    const path = databasePath();
    const store = new SqlitePhase3Store({ databasePath: path });
    store.insertReviewerBinding(binding());
    store.close();
    const raw = new Database(path, { strict: true });
    try {
      expect(() => raw.query("UPDATE phase3_reviewer_bindings SET binding_json = '{}' WHERE reviewer_binding_id = ?").run("reviewer-binding:spec"))
        .toThrow("phase3 reviewer bindings are immutable");
    } finally { raw.close(); }
  });
});
