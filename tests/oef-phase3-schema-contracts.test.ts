import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import {
  createRepairProposal,
  createHumanReviewApproval,
  createReviewProfile,
  createReviewSnapshot,
  createWaiver,
  parseReviewFinding,
  parseReviewPlan,
  type ReviewFinding,
} from "../src/oef/phase3";
import { PHASE3_PUBLIC_SCHEMAS, phase3JsonSchemaDocument } from "../scripts/generate-oef-phase3-schemas";

const schemaRoot = join(import.meta.dir, "..", "schemas", "oef-phase3");
const NOW = "2026-07-23T20:00:00.000Z";
const hash = (character: string) => `sha256:${character.repeat(64)}`;

function fixtures(): Record<string, unknown> {
  const profile = createReviewProfile({
    review_profile_id: "code-quality",
    version: "1.0.0",
    objective: "Review correctness and maintainability independently.",
    required_inputs: ["task-contract", "diff", "mechanical-verification"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["repository-navigation"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true, maintainability: true },
    output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-code-review", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 1_200, max_output_tokens: 12_000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {},
    created_at: NOW,
  });
  const snapshot = createReviewSnapshot({
    review_snapshot_id: "review-snapshot:schema",
    contract: { revision_id: "contract-revision:schema", revision: 1, hash: hash("a") },
    source: { base_commit: "abc123", result_tree_hash: hash("b"), diff_hash: hash("c") },
    evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: hash("d") },
    workflow: { id: "software-development", version: "1.0.0", hash: hash("e") },
    policy: { id: "safe-default", version: "1.0.0", hash: hash("f") },
    created_at: NOW,
  });
  const plan = parseReviewPlan({
    schema_version: 1,
    review_plan_id: "review-plan:schema",
    revision: 1,
    previous_revision_hash: null,
    review_request_id: "review-request:schema",
    task_id: "task:schema",
    snapshot,
    risk: { level: "high", reasons: ["authentication"] },
    review_units: [{
      review_unit_id: "review-unit:quality",
      review_type: "opencodex.code-quality",
      profile_ref: { id: profile.review_profile_id, version: profile.version, hash: profile.content_hash },
      required: true,
      required_capabilities: ["diff-analysis", "structured-findings"],
      preferred_capabilities: ["repository-navigation"],
      depends_on: [],
      prerequisites: ["mechanical-verification.passed", "workspace.sealed"],
    }],
    execution_strategy: { parallel_groups: [["review-unit:quality"]] },
    adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: hash("a") },
    quorum: { required_review_types: ["opencodex.code-quality"], minimum_independent_providers: 1, minimum_independence_score: 3, human_approval: "not-required" },
    budget: { max_wall_time_seconds: 3_600, max_total_output_tokens: 40_000, max_review_units: 5, max_parallel_units: 3 },
    limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 5, max_adjudication_rounds: 1, max_total_cost_units: 100 },
    created_at: NOW,
  });
  const finding = parseReviewFinding({
    schema_version: 1,
    finding_id: "review-finding:schema",
    finding_key: "FIND-SCHEMA-403",
    review_plan_id: plan.review_plan_id,
    review_unit_id: "review-unit:quality",
    category: "correctness",
    proposed_severity: "HIGH",
    effective_severity: "HIGH",
    confidence: 0.95,
    status: "CONFIRMED",
    claim: "A 403 response is incorrectly classified as a rate limit.",
    impact: "Authentication failures may rotate to the wrong account.",
    scope: { snapshot_hash: snapshot.snapshot_hash, contract_revision_id: "contract-revision:schema", source_tree_hash: hash("b"), diff_hash: hash("c") },
    anchors: [{ type: "code", path: "src/providers/clinepass/error-classifier.ts", line_start: 42, line_end: 61, file_hash: hash("a"), symbol: { type: "function", name: "classifyError" }, snippet_hash: hash("b") }],
    contract_refs: ["AC-403"],
    evidence_refs: ["evidence:test-403"],
    evidence_strength: "STRONG",
    proposed_by: { reviewer_binding_id: "reviewer-binding:quality" },
    created_at: NOW,
    updated_at: NOW,
    duplicate_of: null,
  });
  const waiver = createWaiver({
    waiver_id: "review-waiver:schema",
    finding,
    decision: "ACCEPTED_RISK",
    rationale: "Tracked as a time-bounded risk.",
    approved_by: { type: "human", id: "human:owner" },
    expires_at: "2026-08-23T20:00:00.000Z",
    conditions: ["linked-issue-required"],
    snapshot_hash: snapshot.snapshot_hash,
    created_at: NOW,
  });
  const repair = createRepairProposal({
    repair_proposal_id: "repair-proposal:schema",
    task_id: "task:schema",
    source_review_plan_id: plan.review_plan_id,
    findings: [finding],
    constraints: ["Preserve the existing 429 behavior."],
    required_evidence: ["regression-test-403"],
    created_at: NOW,
  });
  const approval = createHumanReviewApproval({
    approval_id: "review-approval:schema",
    review_plan_id: plan.review_plan_id,
    snapshot_hash: snapshot.snapshot_hash,
    review_decision_id: "review-decision:approval-target",
    review_decision_hash: hash("a"),
    finding_ids: [finding.finding_id],
    decision: "APPROVE",
    rationale: "The accountable owner approved this exact review snapshot.",
    approved_by: { type: "human", id: "human:security-owner" },
    approval_artifact_ref: "artifact:human-approval-schema",
    approved_at: NOW,
  });

  return {
    "review-profile-v1.schema.json": profile,
    "review-plan-v1.schema.json": plan,
    "review-result-v1.schema.json": {
      schema_version: 1,
      review_unit_id: "review-unit:quality",
      snapshot_hash: snapshot.snapshot_hash,
      decision: { recommendation: "changes-requested" },
      summary: "The 403 contract criterion is not satisfied.",
      findings: [{
        finding_key: "FIND-SCHEMA-403", category: "correctness", proposed_severity: "HIGH", confidence: 0.95,
        claim: finding.claim, impact: finding.impact, contract_refs: ["AC-403"],
        code_locations: [{ path: "src/providers/clinepass/error-classifier.ts", start_line: 42, end_line: 61, file_hash: hash("a") }],
        evidence_refs: ["evidence:test-403"], verification: { reproducible: true, reproduction_steps: ["Run the 403 regression test."] },
        recommendation: "Classify 403 as an authentication failure.",
      }],
      unanswered_questions: [], requested_evidence: [],
    },
    "review-finding-v1.schema.json": finding,
    "reviewer-binding-v1.schema.json": {
      schema_version: 1,
      reviewer_binding_id: "reviewer-binding:quality",
      review_unit_id: "review-unit:quality",
      reviewer_profile_ref: { id: profile.review_profile_id, version: profile.version, hash: profile.content_hash },
      runtime_ref: { id: "phase2-runner", adapter_version: "1.0.0" },
      model_ref: { provider: "provider-b", model_class: "review-model", resolved_model: null },
      reviewer_capabilities: ["diff-analysis", "structured-findings"],
      risk_level: "high",
      independence: {
        implementer: { agent_id: "agent:implementer", provider: "provider-a", model_class: "implementer-model", session_id: "session:implementer", context_id: "context:implementer" },
        reviewer: { agent_id: "agent:reviewer", provider: "provider-b", model_class: "review-model", session_id: "session:reviewer", context_id: "context:reviewer" },
        source_access: "read-only",
        human_approval_required: false,
      },
      created_by: { type: "system", id: "system:review-coordinator" }, created_at: NOW,
    },
    "review-decision-v1.schema.json": {
      schema_version: 1,
      review_decision_id: "review-decision:schema",
      review_plan_id: plan.review_plan_id,
      snapshot_hash: snapshot.snapshot_hash,
      decision: "CHANGES_REQUESTED",
      decision_source: "deterministic-policy",
      current_snapshot: true,
      quorum_satisfied: true,
      mechanical_verification_passed: true,
      accepted_findings: [finding.finding_id], dismissed_findings: [], unresolved_findings: [], waived_findings: [], waiver_ids: [], human_approval: null,
      severity_counts: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
      reason_codes: ["confirmed-repairable-finding"],
      rationale: "A confirmed high-severity finding requires repair.",
      next_action: { type: "repair", ref: repair.repair_proposal_id },
      decision_artifact_ref: "artifact:review-decision-schema",
      issued_at: NOW,
    },
    "finding-validation-v1.schema.json": {
      schema_version: 1,
      finding_validation_id: "finding-validation:schema",
      finding_id: finding.finding_id,
      review_plan_id: plan.review_plan_id,
      snapshot_hash: snapshot.snapshot_hash,
      status: "CONFIRMED",
      effective_severity: "HIGH",
      evidence_strength: "STRONG",
      validated_by: ["snapshot", "anchor", "contract", "evidence"],
      validator_binding_id: "reviewer-binding:quality",
      validation_artifact_ref: "artifact:finding-validation-schema",
      created_at: NOW,
    },
    "waiver-v1.schema.json": waiver,
    "repair-proposal-v1.schema.json": repair,
    "human-review-approval-v1.schema.json": approval,
  };
}

describe("Phase 3 public JSON schema contracts", () => {
  test("ships strict, generated schemas without checked-in drift", () => {
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    expect(PHASE3_PUBLIC_SCHEMAS).toHaveLength(10);
    for (const entry of PHASE3_PUBLIC_SCHEMAS) {
      const actual = JSON.parse(readFileSync(join(schemaRoot, entry.file), "utf8"));
      expect(actual, entry.file).toEqual(phase3JsonSchemaDocument(entry));
      expect(() => ajv.compile(actual), `${entry.file}: ${ajv.errorsText()}`).not.toThrow();
      expect(actual.additionalProperties, entry.file).toBeFalse();
    }
  });

  test("accepts one production-parsed fixture at both Zod and JSON Schema boundaries", () => {
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    const values = fixtures();
    for (const entry of PHASE3_PUBLIC_SCHEMAS) {
      const fixture = values[entry.file];
      expect(fixture, entry.file).toBeDefined();
      expect(() => entry.schema.parse(fixture), entry.file).not.toThrow();
      const document = JSON.parse(readFileSync(join(schemaRoot, entry.file), "utf8"));
      const validate = ajv.compile(document);
      expect(validate(fixture), `${entry.file}: ${ajv.errorsText(validate.errors)}`).toBeTrue();
    }
  });

  test("rejects unknown properties at both public boundaries", () => {
    const values = fixtures();
    const ajv = new Ajv2020({ strict: true });
    addFormats(ajv);
    for (const entry of PHASE3_PUBLIC_SCHEMAS) {
      const invalid = { ...(values[entry.file] as object), unexpected: true };
      expect(entry.schema.safeParse(invalid).success, entry.file).toBeFalse();
      const validate = ajv.compile(phase3JsonSchemaDocument(entry));
      expect(validate(invalid), entry.file).toBeFalse();
    }
  });
});
