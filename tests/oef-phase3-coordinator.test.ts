import { describe, expect, test } from "bun:test";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";
import {
  InMemoryReviewEffectPort,
  ReviewCoordinator,
  type ReviewArtifactPort,
  type ReviewAuditPort,
  type ReviewCancellationPort,
  type ReviewCoordinatorDataPort,
  type ReviewCoordinatorExecutorPort,
  type ReviewCoordinatorOutcome,
} from "../src/oef/phase3/application";
import {
  createReviewProfile,
  createReviewLaunchPolicyId,
  createWaiver,
  createReviewSnapshot,
  createHumanReviewApproval,
  hashReviewPlan,
  parseReviewPlan,
  parseReviewPlanState,
  REVIEW_AUDIT_EVENT_TYPES,
  reviewAuditPayloadSchema,
  verifyRunnerIdentityAttestation,
  type ReviewFinding,
  type ReviewerBinding,
  type Waiver,
} from "../src/oef/phase3";
import { TestReviewIdentityAuthority } from "./fixtures/phase3-review-identity-authority";

const NOW = "2026-07-23T15:00:00.000Z";
const HASH = (character: string) => `sha256:${character.repeat(64)}`;
const SOURCE_PATH = "src/providers/clinepass/error-classifier.ts";
const REVIEW_IMAGE = `example.invalid/reviewer@sha256:${"3".repeat(64)}`;

function profile(id: string) {
  return createReviewProfile({
    review_profile_id: id,
    version: "1.0.0",
    objective: `Review ${id} independently.`,
    required_inputs: ["task-contract", "diff", "mechanical-verification"],
    required_capabilities: ["diff-analysis", "structured-findings"],
    preferred_capabilities: ["contract-traceability"],
    workspace: { source_mode: "read-only", temp_write: "allowed", network: "denied" },
    checks: { correctness: true },
    output_schema_ref: { id: "review-result", version: 1 },
    renderer_ref: { id: "generic-review", version: "1.0.0" },
    budgets: { max_wall_time_seconds: 1200, max_output_tokens: 12000 },
    independence: { different_session: "required", different_context: "required", different_provider: "preferred" },
    extensions: {},
    created_at: NOW,
  });
}

const SNAPSHOT = createReviewSnapshot({
  review_snapshot_id: "review-snapshot:coordinator",
  contract: { revision_id: "contract-revision:coordinator", revision: 1, hash: HASH("a") },
  source: { base_commit: "abc123", result_tree_hash: HASH("b"), diff_hash: HASH("c") },
  evidence: { package_id: `evidence-package:${"d".repeat(64)}`, package_hash: HASH("d") },
  workflow: { id: "software-development", version: "1.0.0", hash: HASH("e") },
  policy: { id: "safe-default", version: "1.0.0", hash: HASH("f") },
  created_at: NOW,
});

const PROFILES = {
  spec: profile("spec-compliance"),
  quality: profile("code-quality"),
};

const PLAN = parseReviewPlan({
  schema_version: 1,
  review_plan_id: "review-plan:coordinator",
  revision: 1,
  previous_revision_hash: null,
  review_request_id: "review-request:coordinator",
  task_id: "task:coordinator",
  snapshot: SNAPSHOT,
  risk: { level: "high", reasons: ["authentication"] },
  review_units: [
    {
      review_unit_id: "review-unit:spec",
      review_type: "opencodex.spec-compliance",
      profile_ref: { id: PROFILES.spec.review_profile_id, version: PROFILES.spec.version, hash: PROFILES.spec.content_hash },
      required: true,
      required_capabilities: ["diff-analysis", "structured-findings"],
      preferred_capabilities: ["contract-traceability"],
      depends_on: [],
      prerequisites: ["mechanical-verification.passed"],
    },
    {
      review_unit_id: "review-unit:quality",
      review_type: "opencodex.code-quality",
      profile_ref: { id: PROFILES.quality.review_profile_id, version: PROFILES.quality.version, hash: PROFILES.quality.content_hash },
      required: true,
      required_capabilities: ["diff-analysis", "structured-findings"],
      preferred_capabilities: ["contract-traceability"],
      depends_on: [],
      prerequisites: ["mechanical-verification.passed"],
    },
  ],
  execution_strategy: { parallel_groups: [["review-unit:spec", "review-unit:quality"]] },
  adjudication_policy_ref: { id: "safe-default", version: "1.0.0", hash: HASH("1") },
  quorum: {
    required_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
    minimum_independent_providers: 2,
    minimum_independence_score: 6,
    human_approval: "not-required",
  },
  budget: { max_wall_time_seconds: 3600, max_total_output_tokens: 40000, max_review_units: 5, max_parallel_units: 3 },
  limits: { max_review_rounds: 3, max_repair_rounds: 3, max_evidence_requests: 5, max_adjudication_rounds: 1, max_total_cost_units: 100 },
  created_at: NOW,
});

const STATE = parseReviewPlanState({
  schema_version: 1,
  review_plan_id: PLAN.review_plan_id,
  snapshot_hash: PLAN.snapshot.snapshot_hash,
  status: "READY",
  unit_states: PLAN.review_units.map(unit => ({ review_unit_id: unit.review_unit_id, status: "READY", review_execution_id: null, result_artifact_id: null })),
  counters: { review_rounds: 0, repair_rounds: 0, evidence_requests: 0, adjudication_rounds: 0, total_cost_units: 0 },
  aggregate_version: 1,
  created_at: NOW,
  updated_at: NOW,
});

function binding(unit: "spec" | "quality", provider: string): ReviewerBinding {
  const selected = unit === "spec" ? PLAN.review_units[0]! : PLAN.review_units[1]!;
  return {
    schema_version: 1,
    reviewer_binding_id: `reviewer-binding:${unit}`,
    review_unit_id: selected.review_unit_id,
    reviewer_profile_ref: { ...selected.profile_ref },
    runtime_ref: {
      id: createReviewLaunchPolicyId({ docker_image: REVIEW_IMAGE, executable: "reviewer", arguments: [selected.review_type] }),
      adapter_version: "1.0.0",
    },
    model_ref: { provider, model_class: `review-${unit}`, resolved_model: `model-${unit}` },
    reviewer_capabilities: ["diff-analysis", "structured-findings", "contract-traceability"],
    risk_level: "high",
    independence: {
      implementer: { agent_id: "agent:implementer", provider: "provider-implementer", model_class: "coding", session_id: "session:implementer", context_id: "context:implementer" },
      reviewer: { agent_id: `agent:${unit}`, provider, model_class: `review-${unit}`, session_id: `session:${unit}`, context_id: `context:${unit}` },
      source_access: "read-only",
      human_approval_required: false,
    },
    created_by: { type: "system", id: "system:review-router" },
    created_at: NOW,
  };
}

function reviewResult(unit: "spec" | "quality", findingKey?: string) {
  const reviewUnitId = `review-unit:${unit}`;
  return {
    schema_version: 1,
    review_unit_id: reviewUnitId,
    snapshot_hash: SNAPSHOT.snapshot_hash,
    decision: { recommendation: findingKey ? "changes-requested" : "pass" },
    summary: findingKey ? "403 is classified incorrectly." : "No supported issue found.",
    findings: findingKey ? [{
      finding_key: findingKey,
      category: "correctness",
      proposed_severity: "HIGH",
      confidence: 0.94,
      claim: "403 responses are classified as rate limits.",
      impact: "Authentication failures rotate accounts incorrectly.",
      contract_refs: ["AC-403"],
      code_locations: [{ path: SOURCE_PATH, start_line: 42, end_line: 61, file_hash: HASH("9") }],
      evidence_refs: ["evidence:test-403"],
      verification: { reproducible: true, reproduction_steps: ["bun test tests/auth-403.test.ts"] },
      recommendation: "Classify 401 and 403 as authentication failures.",
    }] : [],
    unanswered_questions: [],
    requested_evidence: [],
  };
}

class MemoryEffects extends InMemoryReviewEffectPort {}

function harness(options: {
  outputs?: Record<string, unknown>;
  snapshots?: unknown[];
  mechanicalPassed?: boolean;
  cancelled?: boolean;
  counters?: Partial<typeof STATE.counters>;
  satisfiedPrerequisites?: readonly string[];
  bindingFactory?: (unit: "spec" | "quality") => ReviewerBinding;
  mechanicalEvidence?: Array<{ passed: boolean; evidence_hash: string; artifact_refs: string[] }>;
  currentValidity?: { contract_hash: string; source_tree_hash: string; diff_hash: string; evidence_package_hash: string; policy_hash: string; profile_hashes: string[]; required_evidence_hashes: string[]; dependency_hash: string };
  runtimeReviewerOverride?: Partial<ReviewerBinding["independence"]["reviewer"]>;
  forgedRuntimeAuthority?: boolean;
  waivers?: readonly Waiver[];
  auditIntegrityFailure?: boolean;
  clock?: () => string;
  onFinalGovernanceRead?: () => void;
  humanApproval?: unknown;
  latestDecision?: ReviewCoordinatorOutcome["decision"] | null;
} = {}) {
  const seenContexts: Array<{ unit: string; prior: readonly Pick<ReviewFinding, "finding_id" | "status" | "claim">[] }> = [];
  const artifacts: Array<{ key: string; artifact_ref: string; value: unknown }> = [];
  const events: Array<{ key: string; event_type: string; payload: unknown }> = [];
  const identityAuthority = new TestReviewIdentityAuthority();
  const signingAuthority = options.forgedRuntimeAuthority ? new TestReviewIdentityAuthority() : identityAuthority;
  let executions = 0;
  let cancelledExecutions = 0;
  let waiverReads = 0;
  const snapshots = [...(options.snapshots ?? [SNAPSHOT, SNAPSHOT])];
  const mechanicalEvidence = [...(options.mechanicalEvidence ?? [
    { passed: options.mechanicalPassed ?? true, evidence_hash: HASH("7"), artifact_refs: ["evidence:mechanical"] },
    { passed: options.mechanicalPassed ?? true, evidence_hash: HASH("7"), artifact_refs: ["evidence:mechanical"] },
  ])];
  const state = options.counters ? parseReviewPlanState({ ...STATE, counters: { ...STATE.counters, ...options.counters } }) : STATE;
  const validity = {
    contract_hash: PLAN.snapshot.contract.hash,
    source_tree_hash: PLAN.snapshot.source.result_tree_hash,
    diff_hash: PLAN.snapshot.source.diff_hash,
    evidence_package_hash: PLAN.snapshot.evidence.package_hash,
    policy_hash: PLAN.snapshot.policy.hash,
    profile_hashes: PLAN.review_units.map(unit => unit.profile_ref.hash).sort(),
    required_evidence_hashes: [HASH("7")],
    dependency_hash: HASH("2"),
  };

  const data: ReviewCoordinatorDataPort = {
    async loadPlan() { return PLAN; },
    async loadPlanState() { return state; },
    async loadCurrentSnapshot() { return snapshots.shift() ?? SNAPSHOT; },
    async loadMechanicalEvidence() {
      return mechanicalEvidence.shift() ?? { passed: options.mechanicalPassed ?? true, evidence_hash: HASH("7"), artifact_refs: ["evidence:mechanical"] };
    },
    async loadSatisfiedPrerequisites() { return options.satisfiedPrerequisites ?? ["mechanical-verification.passed"]; },
    async loadReviewerBinding(unitId) {
      const unit = unitId.endsWith("spec") ? "spec" : "quality";
      return options.bindingFactory?.(unit) ?? binding(unit, `provider-${unit}`);
    },
    async buildContextInput(unit, priorFindings) {
      seenContexts.push({ unit: unit.review_unit_id, prior: [...priorFindings] });
      return {
        context_bundle_id: `review-context-bundle:${unit.review_unit_id.split(":").at(-1)}`,
        snapshot_hash: SNAPSHOT.snapshot_hash,
        review_unit: { id: unit.review_unit_id, objective: `Review ${unit.review_type}.`, profile_ref: { ...unit.profile_ref } },
        task_contract: {
          revision_id: SNAPSHOT.contract.revision_id, revision: SNAPSHOT.contract.revision, hash: SNAPSHOT.contract.hash,
          goal: "Classify provider errors correctly.", constraints: ["Do not rotate on auth errors."], acceptance_criteria: ["403 is an auth error."],
        },
        review_plan: { id: PLAN.review_plan_id, revision: PLAN.revision, hash: hashReviewPlan(PLAN) },
        policy_pack: { ...PLAN.adjudication_policy_ref },
        assignment: { objective: "Fix classification.", allowed_paths: [SOURCE_PATH] },
        source: {
          base_commit: SNAPSHOT.source.base_commit, changed_files: [SOURCE_PATH], diff_artifact_ref: "artifact:diff",
          relevant_file_refs: [{ path: SOURCE_PATH, artifact_ref: "artifact:source", file_hash: HASH("9") }],
        },
        evidence: { mechanical_verification: ["evidence:mechanical"], baseline: [], secret_scan: ["evidence:secret"], dependency_changes: [] },
        repository_rules: [], implementer_summary: { content: "Implemented status-specific classification." },
        previous_findings: priorFindings, generated_at: NOW,
      };
    },
    async loadResultValidationContext(unitId) {
      return { review_unit_id: unitId, snapshot_hash: SNAPSHOT.snapshot_hash, snapshot_files: [{ path: SOURCE_PATH, file_hash: HASH("9"), line_count: 100 }], evidence_refs: ["evidence:test-403"] };
    },
    async loadFindingValidationContext() {
      return {
        snapshot_hash: SNAPSHOT.snapshot_hash, contract_revision_id: SNAPSHOT.contract.revision_id,
        files: [{ path: SOURCE_PATH, hash: HASH("9"), line_count: 100 }], contract_refs: ["AC-403"], evidence_refs: ["evidence:test-403"],
      };
    },
    async loadWaivers() {
      waiverReads += 1;
      if (waiverReads > 1) options.onFinalGovernanceRead?.();
      return options.waivers ?? [];
    },
    async loadReviewValidityBaseline() { return validity; },
    async loadCurrentReviewValidity() { return options.currentValidity ?? validity; },
    async loadHumanApproval() { return options.humanApproval ?? null; },
    async loadLatestReviewDecision() { return options.latestDecision ?? null; },
    async verifyRuntimeIdentityAttestation(attestation) {
      return verifyRunnerIdentityAttestation(
        attestation as Parameters<typeof verifyRunnerIdentityAttestation>[0],
        identityAuthority.getReviewIdentityAuthority(),
      );
    },
  };
  const executor: ReviewCoordinatorExecutorPort = {
    async execute(input) {
      executions += 1;
      const key = input.unit.review_unit_id.endsWith("spec") ? "spec" : "quality";
      const raw_output = options.outputs?.[key] ?? reviewResult(key, key === "spec" ? "FIND-SPEC-403" : "FIND-QUALITY-403");
      const reviewer = { ...input.binding.independence.reviewer, ...options.runtimeReviewerOverride };
      const isolation = { mechanism: "docker" as const, network: "denied" as const, credentials: "unmounted" as const, source: "read-only" as const, image_digest: HASH("3"), attested_by: "phase2-runner:docker" };
      const identityContent = {
        review_execution_id: input.review_execution_id,
        phase2_execution_id: `execution:review-${input.review_execution_id.slice("review-execution:".length)}`,
        runner_process_id: `supervised-process:${key}`,
        reviewer,
        identity_source: "runner-authenticated-launch-binding" as const,
        container_image_digest: HASH("3"),
        command_hash: canonicalSha256({ unit: input.unit.review_unit_id, context: input.context }),
        isolation_hash: canonicalSha256(isolation),
        launch_policy_id: input.binding.runtime_ref.id,
        output_hash: canonicalSha256(raw_output),
        attested_by: "phase2-runner-host" as const,
      };
      const signed = await signingAuthority.attestReviewIdentity(identityContent);
      return {
        status: "COMPLETED", raw_output, output_hash: canonicalSha256(raw_output), cost_units: 5,
        runtime_attestation: {
          ...identityContent,
          attestation_hash: signed.content_hash,
          attestation_key_id: signed.key_id,
          attestation_signature: signed.signature,
          attestation_algorithm: signed.algorithm,
          attestation_public_key: signed.public_key_spki,
          isolation,
        },
      };
    },
    async cancelPlan() { cancelledExecutions += 1; },
  };
  const artifactPort: ReviewArtifactPort = {
    async putJson(input) { artifacts.push({ key: input.idempotency_key, artifact_ref: input.artifact_ref, value: input.value }); return { artifact_ref: input.artifact_ref, replayed: false }; },
  };
  const auditPort: ReviewAuditPort = {
    async append(input) { events.push({ key: input.idempotency_key, event_type: input.event_type, payload: input.payload }); return { replayed: false }; },
    async assertIntegrity() { if (options.auditIntegrityFailure) throw new Error("REVIEW_AUDIT_CHAIN_INVALID"); },
  };
  const cancellation: ReviewCancellationPort = { async isCancellationRequested() { return options.cancelled ?? false; } };
  const effects = new MemoryEffects();
  const coordinator = new ReviewCoordinator({ data, executor, artifacts: artifactPort, audit: auditPort, effects, cancellation, clock: options.clock ?? (() => NOW) });
  return { coordinator, effects, seenContexts, artifacts, events, get executions() { return executions; }, get cancelledExecutions() { return cancelledExecutions; } };
}

describe("Phase 3 ReviewCoordinator", () => {
  test("runs blind parallel reviews, validates and deduplicates supported findings, then requests changes", async () => {
    const testHarness = harness();
    const outcome = await testHarness.coordinator.run({ review_plan_id: PLAN.review_plan_id });

    expect(outcome.replayed).toBeFalse();
    expect(outcome.decision.decision).toBe("CHANGES_REQUESTED");
    expect(outcome.decision.next_action.type).toBe("repair");
    expect(outcome.finding_groups).toHaveLength(1);
    expect(outcome.finding_groups[0]?.members).toHaveLength(2);
    expect(outcome.findings.every(finding => finding.evidence_strength !== "UNSUPPORTED")).toBeTrue();
    expect(outcome.decision.severity_counts.HIGH).toBe(1);
    expect(testHarness.seenContexts).toHaveLength(2);
    expect(testHarness.seenContexts.every(entry => entry.prior.length === 0)).toBeTrue();
    expect(new Set(testHarness.artifacts.map(effect => effect.key)).size).toBe(testHarness.artifacts.length);
    expect(new Set(testHarness.events.map(effect => effect.key)).size).toBe(testHarness.events.length);
    expect(testHarness.events.map(event => event.event_type)).toContain("review.decision.issued");
    expect(testHarness.events.map(event => event.event_type)).toContain("finding.validated");
    expect(testHarness.events.every(event => REVIEW_AUDIT_EVENT_TYPES.includes(event.event_type as never))).toBeTrue();
    expect(testHarness.events.every(event => reviewAuditPayloadSchema.safeParse(event.payload).success)).toBeTrue();
    expect(testHarness.artifacts.some(artifact => artifact.key.endsWith(":findings"))).toBeTrue();
  });

  test("returns a clean PASS only for current evidence, complete quorum, and successful mechanical verification", async () => {
    const testHarness = harness({ outputs: { spec: reviewResult("spec"), quality: reviewResult("quality") } });
    const outcome = await testHarness.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(outcome.decision.decision).toBe("PASS");
    expect(outcome.decision.quorum_satisfied).toBeTrue();
    expect(outcome.decision.current_snapshot).toBeTrue();
    expect(outcome.decision.mechanical_verification_passed).toBeTrue();
    expect(outcome.decision.next_action.type).toBe("phase1-verdict");
  });

  test("fails closed on stale snapshots, mechanical failure, malformed reviewer output, and missing required prerequisites", async () => {
    const staleSnapshot = createReviewSnapshot({
      review_snapshot_id: "review-snapshot:new",
      contract: SNAPSHOT.contract,
      source: { ...SNAPSHOT.source, diff_hash: HASH("0") },
      evidence: SNAPSHOT.evidence,
      workflow: SNAPSHOT.workflow,
      policy: SNAPSHOT.policy,
      created_at: NOW,
    });
    const stale = harness({ snapshots: [SNAPSHOT, staleSnapshot] });
    expect((await stale.coordinator.run({ review_plan_id: PLAN.review_plan_id })).decision.decision).toBe("INCONCLUSIVE");

    const evidenceDrift = harness({ mechanicalEvidence: [
      { passed: true, evidence_hash: HASH("7"), artifact_refs: ["evidence:mechanical"] },
      { passed: true, evidence_hash: HASH("6"), artifact_refs: ["evidence:mechanical-new"] },
    ] });
    const evidenceDriftOutcome = await evidenceDrift.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(evidenceDriftOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(evidenceDriftOutcome.decision.reason_codes).toContain("mechanical-evidence-stale");

    const mechanical = harness({ mechanicalPassed: false });
    expect((await mechanical.coordinator.run({ review_plan_id: PLAN.review_plan_id })).decision.decision).toBe("INCONCLUSIVE");
    expect(mechanical.executions).toBe(0);

    const malformed = harness({ outputs: { spec: "not-json", quality: reviewResult("quality") } });
    const malformedOutcome = await malformed.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(malformedOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(malformedOutcome.decision.reason_codes).toContain("review-unit-failed");

    const missingPrerequisite = harness({ satisfiedPrerequisites: [] });
    const prerequisiteOutcome = await missingPrerequisite.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(prerequisiteOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(prerequisiteOutcome.decision.reason_codes).toContain("required-prerequisite-missing");
    expect(missingPrerequisite.executions).toBe(0);

    const validityDrift = harness({ currentValidity: {
      contract_hash: PLAN.snapshot.contract.hash,
      source_tree_hash: PLAN.snapshot.source.result_tree_hash,
      diff_hash: PLAN.snapshot.source.diff_hash,
      evidence_package_hash: PLAN.snapshot.evidence.package_hash,
      policy_hash: PLAN.snapshot.policy.hash,
      profile_hashes: PLAN.review_units.map(unit => unit.profile_ref.hash).sort(),
      required_evidence_hashes: [HASH("7")],
      dependency_hash: HASH("0"),
    } });
    const driftOutcome = await validityDrift.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(driftOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(driftOutcome.decision.reason_codes).toContain("dependency-changed");
    expect(validityDrift.executions).toBe(0);
  });

  test("never converts unsupported recommendations or unresolved evidence requests into PASS or a blocker", async () => {
    const unsupported = harness({
      outputs: {
        spec: { ...reviewResult("spec"), decision: { recommendation: "blocked" }, summary: "Blocked, but no supported finding was produced." },
        quality: reviewResult("quality"),
      },
    });
    const unsupportedOutcome = await unsupported.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(unsupportedOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(unsupportedOutcome.decision.reason_codes).toContain("unsupported-review-recommendation");

    const evidenceRequest = harness({
      outputs: {
        spec: { ...reviewResult("spec"), decision: { recommendation: "inconclusive" }, requested_evidence: ["evidence:runtime-403"] },
        quality: reviewResult("quality"),
      },
    });
    const evidenceOutcome = await evidenceRequest.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(evidenceOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(evidenceOutcome.decision.reason_codes).toContain("additional-evidence-required");

    const exhausted = harness({
      counters: { evidence_requests: PLAN.limits.max_evidence_requests },
      outputs: {
        spec: { ...reviewResult("spec"), decision: { recommendation: "inconclusive" }, requested_evidence: ["evidence:runtime-403"] },
        quality: reviewResult("quality"),
      },
    });
    const exhaustedOutcome = await exhausted.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(exhaustedOutcome.decision.decision).toBe("NEEDS_HUMAN");
    expect(exhaustedOutcome.decision.reason_codes).toContain("evidence-request-limit-reached");
  });

  test("rejects a mismatched reviewer binding and never lets a confirmed critical finding bypass BLOCKED", async () => {
    const mismatched = harness({
      bindingFactory(unit) {
        const selected = binding(unit, `provider-${unit}`);
        return unit === "spec" ? { ...selected, review_unit_id: "review-unit:quality" } : selected;
      },
    });
    const mismatchOutcome = await mismatched.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(mismatchOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(mismatchOutcome.decision.reason_codes).toContain("review-unit-failed");

    const runtimeMismatch = harness({ runtimeReviewerOverride: { session_id: "session:forged-runtime" } });
    const runtimeMismatchOutcome = await runtimeMismatch.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(runtimeMismatchOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(runtimeMismatchOutcome.decision.reason_codes).toContain("review-unit-failed");

    const forgedAuthority = harness({ forgedRuntimeAuthority: true });
    const forgedAuthorityOutcome = await forgedAuthority.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(forgedAuthorityOutcome.decision.decision).toBe("INCONCLUSIVE");
    expect(forgedAuthorityOutcome.decision.reason_codes).toContain("review-unit-failed");

    const spec = reviewResult("spec", "FIND-SPEC-CRITICAL");
    const criticalFinding = { ...(spec.findings[0] as Record<string, unknown>), proposed_severity: "CRITICAL" };
    const critical = harness({ outputs: { spec: { ...spec, decision: { recommendation: "blocked" }, findings: [criticalFinding] }, quality: reviewResult("quality") } });
    const criticalOutcome = await critical.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(criticalOutcome.decision.decision).toBe("NEEDS_HUMAN");
    expect(criticalOutcome.decision.reason_codes).toContain("critical-finding-independent-source-missing");

    const qualityCritical = reviewResult("quality", "FIND-QUALITY-CRITICAL-CORROBORATED");
    const corroborated = harness({ outputs: {
      spec: { ...spec, decision: { recommendation: "blocked" }, findings: [criticalFinding] },
      quality: { ...qualityCritical, decision: { recommendation: "blocked" }, findings: [{ ...(qualityCritical.findings[0] as Record<string, unknown>), proposed_severity: "CRITICAL" }] },
    } });
    const corroboratedOutcome = await corroborated.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(corroboratedOutcome.decision.decision).toBe("NEEDS_HUMAN");
    expect(corroboratedOutcome.decision.reason_codes).toContain("critical-finding-human-approval-missing");
    expect(corroboratedOutcome.decision.severity_counts.CRITICAL).toBe(1);
    expect(corroboratedOutcome.decision.next_action.type).toBe("human-gate");
    const approval = createHumanReviewApproval({
      approval_id: "review-approval:critical-decision",
      review_plan_id: PLAN.review_plan_id,
      snapshot_hash: PLAN.snapshot.snapshot_hash,
      review_decision_id: corroboratedOutcome.decision.review_decision_id,
      review_decision_hash: canonicalSha256(corroboratedOutcome.decision),
      finding_ids: [...corroboratedOutcome.decision.accepted_findings, ...corroboratedOutcome.decision.unresolved_findings],
      decision: "APPROVE",
      rationale: "The accountable owner approves this exact critical decision and finding set.",
      approved_by: { type: "human", id: "human:security-owner" },
      approval_artifact_ref: "artifact:critical-human-approval",
      approved_at: NOW,
    });
    const approvedCritical = harness({
      outputs: {
        spec: { ...spec, decision: { recommendation: "blocked" }, findings: [criticalFinding] },
        quality: { ...qualityCritical, decision: { recommendation: "blocked" }, findings: [{ ...(qualityCritical.findings[0] as Record<string, unknown>), proposed_severity: "CRITICAL" }] },
      },
      humanApproval: approval,
      latestDecision: corroboratedOutcome.decision,
    });
    const approvedOutcome = await approvedCritical.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(approvedOutcome.decision.decision).toBe("BLOCKED");
    expect(approvedOutcome.decision.human_approval?.approval_id).toBe(approval.approval_id);

    const low = reviewResult("spec", "FIND-SPEC-LOW");
    const criticalSameIssue = reviewResult("quality", "FIND-QUALITY-CRITICAL");
    const severityShadow = harness({ outputs: {
      spec: { ...low, findings: [{ ...(low.findings[0] as Record<string, unknown>), proposed_severity: "LOW" }] },
      quality: { ...criticalSameIssue, decision: { recommendation: "blocked" }, findings: [{ ...(criticalSameIssue.findings[0] as Record<string, unknown>), proposed_severity: "CRITICAL" }] },
    } });
    const shadowOutcome = await severityShadow.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(shadowOutcome.decision.decision).toBe("NEEDS_HUMAN");
    expect(shadowOutcome.decision.reason_codes).toContain("critical-finding-independent-source-missing");
  });

  test("applies only current hash-bound waivers and fails closed on audit integrity", async () => {
    const initial = harness({ outputs: { spec: reviewResult("spec", "FIND-SPEC-WAIVER"), quality: reviewResult("quality") } });
    const initialOutcome = await initial.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    const confirmed = initialOutcome.findings.find(finding => finding.status === "CONFIRMED")!;
    const waiver = createWaiver({
      waiver_id: "review-waiver:coordinator",
      finding: confirmed,
      decision: "ACCEPTED_RISK",
      rationale: "A human owner accepted this bounded risk until the next release.",
      approved_by: { type: "human", id: "human:local-owner" },
      expires_at: "2026-08-01T00:00:00.000Z",
      conditions: ["no-severity-increase"],
      snapshot_hash: PLAN.snapshot.snapshot_hash,
      created_at: NOW,
    });
    const active = harness({ outputs: { spec: reviewResult("spec", "FIND-SPEC-WAIVER"), quality: reviewResult("quality") }, waivers: [waiver] });
    const activeOutcome = await active.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(activeOutcome.decision.decision).toBe("PASS");
    expect(activeOutcome.decision.waived_findings).toEqual([confirmed.finding_id]);
    expect(activeOutcome.decision.waiver_ids).toEqual([waiver.waiver_id]);
    expect(active.events.map(event => event.event_type)).toContain("finding.waived");

    const expired = harness({ outputs: { spec: reviewResult("spec", "FIND-SPEC-WAIVER"), quality: reviewResult("quality") }, waivers: [{ ...waiver, expires_at: "2026-07-22T00:00:00.000Z" }] });
    expect((await expired.coordinator.run({ review_plan_id: PLAN.review_plan_id })).decision.decision).toBe("CHANGES_REQUESTED");

    const brokenAudit = harness({ outputs: { spec: reviewResult("spec"), quality: reviewResult("quality") }, auditIntegrityFailure: true });
    await expect(brokenAudit.coordinator.run({ review_plan_id: PLAN.review_plan_id })).rejects.toThrow("REVIEW_AUDIT_CHAIN_INVALID");

    let evaluationTime = NOW;
    const expiring = harness({
      outputs: { spec: reviewResult("spec", "FIND-SPEC-WAIVER"), quality: reviewResult("quality") },
      waivers: [waiver],
      clock: () => evaluationTime,
    });
    const beforeExpiry = await expiring.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(beforeExpiry.decision.decision).toBe("PASS");
    evaluationTime = "2026-08-02T00:00:00.000Z";
    const afterExpiry = await expiring.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(afterExpiry.replayed).toBeFalse();
    expect(afterExpiry.decision.decision).toBe("CHANGES_REQUESTED");

    let midRunTime = NOW;
    const expiresDuringRun = harness({
      outputs: { spec: reviewResult("spec", "FIND-SPEC-WAIVER"), quality: reviewResult("quality") },
      waivers: [waiver],
      clock: () => midRunTime,
      onFinalGovernanceRead: () => { midRunTime = "2026-08-02T00:00:00.000Z"; },
    });
    const staleGovernance = await expiresDuringRun.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(staleGovernance.decision.decision).toBe("INCONCLUSIVE");
    expect(staleGovernance.decision.reason_codes).toContain("review-governance-stale");
  });

  test("honors cancellation and circuit limits without starting a reviewer", async () => {
    const cancelled = harness({ cancelled: true });
    expect((await cancelled.coordinator.run({ review_plan_id: PLAN.review_plan_id })).decision.decision).toBe("CANCELLED");
    expect(cancelled.executions).toBe(0);
    expect(cancelled.cancelledExecutions).toBe(1);

    const circuit = harness({ counters: { review_rounds: PLAN.limits.max_review_rounds } });
    const outcome = await circuit.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(outcome.decision.decision).toBe("NEEDS_HUMAN");
    expect(outcome.decision.reason_codes).toContain("review-round-limit-reached");
    expect(circuit.executions).toBe(0);
  });

  test("replays the complete orchestration effect without duplicate executions, artifacts, or audit events", async () => {
    const testHarness = harness();
    const first = await testHarness.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    const counts = { executions: testHarness.executions, artifacts: testHarness.artifacts.length, events: testHarness.events.length };
    const second = await testHarness.coordinator.run({ review_plan_id: PLAN.review_plan_id });
    expect(second.replayed).toBeTrue();
    expect(stripReplay(second)).toEqual(stripReplay(first));
    expect(testHarness.executions).toBe(counts.executions);
    expect(testHarness.artifacts).toHaveLength(counts.artifacts);
    expect(testHarness.events).toHaveLength(counts.events);
  });
});

function stripReplay(outcome: ReviewCoordinatorOutcome): Omit<ReviewCoordinatorOutcome, "replayed"> {
  const { replayed: ignored, ...rest } = outcome;
  return rest;
}
