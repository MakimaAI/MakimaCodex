import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  assertPlanStateMatchesPlan,
  assertReviewSnapshotCurrent,
  assertWaiverApplies,
  hashReviewPlan,
  parseReviewFinding,
  parseReviewPlan,
  parseReviewPlanState,
  reviewSnapshotSchema,
  type FindingSeverity,
  type ReviewFinding,
  type ReviewPlan,
  type Waiver,
} from "../core/domain";
import {
  adjudicateReview,
  assessReviewValidity,
  computeIndependenceScore,
  deduplicateFindings,
  validateFinding,
  verifyQuorum,
  type FindingGroup,
  type ReviewDecision,
  type ReviewValidityInputs,
} from "../decision";
import { parseHumanReviewApproval, parseReviewDecisionRecord, type HumanReviewApproval, type ReviewDecisionRecord } from "../governance";
import type { ReviewAuditEventType } from "../observability";
import {
  ReviewContextBundleCompiler,
  assertReviewerCapabilities,
  parseReviewerBinding,
  validateReviewResult,
  type ReviewerBinding,
  type ReviewResult,
} from "../review";
import type {
  IdempotentReviewEffectPort,
  MechanicalReviewEvidence,
  ReviewArtifactPort,
  ReviewAuditPort,
  ReviewCancellationPort,
  ReviewCoordinatorDataPort,
  ReviewCoordinatorExecutorPort,
} from "./ports";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const mechanicalEvidenceSchema = z.object({
  passed: z.boolean(),
  evidence_hash: hashSchema,
  artifact_refs: z.array(z.string().trim().min(1).max(500)).max(10_000),
}).strict();
const runtimeAttestationSchema = z.object({
  reviewer: z.object({
    agent_id: z.string().startsWith("agent:"),
    provider: z.string().trim().min(1),
    model_class: z.string().trim().min(1),
    session_id: z.string().startsWith("session:"),
    context_id: z.string().startsWith("context:"),
  }).strict(),
  review_execution_id: z.string().startsWith("review-execution:"),
  phase2_execution_id: z.string().startsWith("execution:review-"),
  runner_process_id: z.string().startsWith("supervised-process:"),
  identity_source: z.literal("runner-authenticated-launch-binding"),
  container_image_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  command_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  portable_command_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  isolation_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  launch_policy_id: z.string().regex(/^review-launch-policy:[a-f0-9]{32}$/),
  output_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  attested_by: z.literal("phase2-runner-host"),
  attestation_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  attestation_key_id: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  attestation_signature: z.string().regex(/^[A-Za-z0-9_-]{64,256}$/),
  attestation_algorithm: z.literal("Ed25519"),
  attestation_public_key: z.string().regex(/^[A-Za-z0-9_-]{32,512}$/),
  isolation: z.object({
    mechanism: z.literal("docker"),
    network: z.literal("denied"),
    credentials: z.literal("unmounted"),
    source: z.literal("read-only"),
    image_digest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    attested_by: z.string().trim().min(1),
  }).strict(),
}).strict();

interface CompletedUnit {
  readonly unit: ReviewPlan["review_units"][number];
  readonly binding: ReviewerBinding;
  readonly result: ReviewResult;
  readonly costUnits: number;
}

interface CoreOutcome {
  readonly decision: ReviewDecisionRecord;
  readonly findings: ReviewFinding[];
  readonly finding_groups: FindingGroup[];
  readonly completed_review_units: string[];
}

interface GovernanceInputs {
  readonly waivers: readonly Waiver[];
  readonly validityBaseline: ReviewValidityInputs;
  readonly currentValidity: ReviewValidityInputs;
  readonly humanApproval: unknown | null;
  readonly approvalDecision: ReviewDecisionRecord | null;
  readonly evaluatedAt: string;
  readonly fingerprint: string;
}

export interface ReviewCoordinatorOutcome extends CoreOutcome {
  readonly replayed: boolean;
}

export class ReviewCoordinator {
  private readonly contextCompiler = new ReviewContextBundleCompiler();

  constructor(private readonly ports: {
    data: ReviewCoordinatorDataPort;
    executor: ReviewCoordinatorExecutorPort;
    artifacts: ReviewArtifactPort;
    audit: ReviewAuditPort;
    effects: IdempotentReviewEffectPort;
    cancellation: ReviewCancellationPort;
    clock: () => string;
  }) {}

  async run(input: { review_plan_id: string }): Promise<ReviewCoordinatorOutcome> {
    const reviewPlanId = z.string().regex(/^review-plan:/).parse(input.review_plan_id);
    const plan = parseReviewPlan(await this.ports.data.loadPlan(reviewPlanId));
    const state = parseReviewPlanState(await this.ports.data.loadPlanState(reviewPlanId));
    assertPlanStateMatchesPlan(plan, state);
    const initialCurrentSnapshot = reviewSnapshotSchema.parse(await this.ports.data.loadCurrentSnapshot(plan.task_id));
    const mechanical = mechanicalEvidenceSchema.parse(await this.ports.data.loadMechanicalEvidence(plan.review_plan_id));
    const evaluatedAt = this.ports.clock();
    const waivers = await this.ports.data.loadWaivers(plan.review_plan_id);
    const validityBaseline = await this.ports.data.loadReviewValidityBaseline(plan.review_plan_id);
    const currentValidity = await this.ports.data.loadCurrentReviewValidity(plan.review_plan_id);
    const humanApproval = await this.ports.data.loadHumanApproval(plan.review_plan_id);
    const approvalDecision = humanApproval === null ? null : await this.ports.data.loadLatestReviewDecision(plan.review_plan_id);
    const fingerprint = canonicalSha256({
      waivers: waivers.map(waiver => ({
        content_hash: canonicalSha256(waiver),
        expired: waiver.expires_at !== null && Date.parse(evaluatedAt) >= Date.parse(waiver.expires_at),
      })).sort((left, right) => left.content_hash.localeCompare(right.content_hash)),
      validityBaseline,
      currentValidity,
      humanApproval: humanApproval === null ? null : canonicalSha256(humanApproval),
      approvalDecision: approvalDecision === null ? null : canonicalSha256(approvalDecision),
    });
    const governance: GovernanceInputs = { waivers, validityBaseline, currentValidity, humanApproval, approvalDecision, evaluatedAt, fingerprint };
    const effectKey = [
      "review-coordinator", plan.review_plan_id, `revision-${plan.revision}`, `state-${state.aggregate_version}`,
      initialCurrentSnapshot.snapshot_hash, mechanical.evidence_hash, fingerprint,
    ].join(":");
    const inputHash = canonicalSha256({ plan, state, initialCurrentSnapshot, mechanical, fingerprint });
    const effect = await this.ports.effects.runOnce(effectKey, inputHash, () => this.orchestrate(plan, state, initialCurrentSnapshot, mechanical, governance));
    return { ...effect.value, replayed: effect.replayed };
  }

  private async orchestrate(
    plan: ReviewPlan,
    state: ReturnType<typeof parseReviewPlanState>,
    initialCurrentSnapshot: ReturnType<typeof reviewSnapshotSchema.parse>,
    mechanical: MechanicalReviewEvidence,
    governance: GovernanceInputs,
  ): Promise<CoreOutcome> {
    if (await this.ports.cancellation.isCancellationRequested(plan.review_plan_id)) {
      await this.ports.executor.cancelPlan(plan.review_plan_id);
      return this.terminal(plan, "CANCELLED", ["review-cancelled"], false, mechanical.passed, [], [], []);
    }
    if (state.counters.review_rounds >= plan.limits.max_review_rounds) {
      return this.terminal(plan, "NEEDS_HUMAN", ["review-round-limit-reached"], false, mechanical.passed, [], [], []);
    }
    if (state.counters.total_cost_units >= plan.limits.max_total_cost_units) {
      return this.terminal(plan, "NEEDS_HUMAN", ["review-cost-limit-reached"], false, mechanical.passed, [], [], []);
    }
    try {
      assertReviewSnapshotCurrent(plan.snapshot, initialCurrentSnapshot);
    } catch {
      return this.terminal(plan, "INCONCLUSIVE", ["review-snapshot-stale"], false, mechanical.passed, [], [], []);
    }
    if (!mechanical.passed) {
      return this.terminal(plan, "INCONCLUSIVE", ["mechanical-verification-failed"], true, false, [], [], []);
    }
    const initialValidity = assessReviewValidity(
      governance.validityBaseline,
      governance.currentValidity,
    );
    if (initialValidity.status === "STALE") {
      return this.terminal(plan, "INCONCLUSIVE", initialValidity.reasons, false, true, [], [], []);
    }

    const prerequisites = await Promise.all(plan.review_units.map(async unit => ({
      unit,
      satisfied: new Set(await this.ports.data.loadSatisfiedPrerequisites(unit.review_unit_id)),
    })));
    if (prerequisites.some(entry => entry.unit.required && entry.unit.prerequisites.some(item => !entry.satisfied.has(item)))) {
      return this.terminal(plan, "INCONCLUSIVE", ["required-prerequisite-missing"], true, true, [], [], []);
    }

    const completed: CompletedUnit[] = [];
    const proposed: ReviewFinding[] = [];
    let costUnits = state.counters.total_cost_units;
    const completedIds = new Set<string>();
    for (const group of plan.execution_strategy.parallel_groups) {
      if (await this.ports.cancellation.isCancellationRequested(plan.review_plan_id)) {
        await this.ports.executor.cancelPlan(plan.review_plan_id);
        return this.terminal(plan, "CANCELLED", ["review-cancelled"], true, true, proposed, [], completed);
      }
      const groupUnits = group.map(id => plan.review_units.find(unit => unit.review_unit_id === id)!);
      if (groupUnits.some(unit => unit.required && unit.depends_on.some(dependency => !completedIds.has(dependency)))) {
        return this.terminal(plan, "INCONCLUSIVE", ["review-dependency-missing"], true, true, proposed, [], completed);
      }
      const priorFindings = proposed.map(finding => ({ finding_id: finding.finding_id, status: finding.status, claim: finding.claim }));
      const settled = await Promise.allSettled(groupUnits.map(unit => this.executeUnit(plan, unit, priorFindings)));
      let groupFailed = false;
      for (let index = 0; index < settled.length; index += 1) {
        const result = settled[index]!;
        if (result.status === "rejected") {
          groupFailed = true;
          await this.audit(plan, "review.unit.failed", {
            review_unit_id: groupUnits[index]!.review_unit_id,
            review_type: shortReviewType(groupUnits[index]!.review_type),
            failure_code: safeFailureCode(result.reason),
          });
          continue;
        }
        const unitResult = result.value;
        completed.push(unitResult);
        completedIds.add(unitResult.unit.review_unit_id);
        costUnits += unitResult.costUnits;
        proposed.push(...unitResult.result.findings.map(finding => this.toFinding(plan, unitResult.binding, unitResult.unit, finding)));
      }
      if (groupFailed) return this.terminal(plan, "INCONCLUSIVE", ["review-unit-failed"], true, true, proposed, [], completed);
      if (costUnits > plan.limits.max_total_cost_units) {
        return this.terminal(plan, "NEEDS_HUMAN", ["review-cost-limit-reached"], true, true, proposed, [], completed);
      }
    }

    const findingContext = await this.ports.data.loadFindingValidationContext(plan.review_plan_id);
    if (findingContext.snapshot_hash !== plan.snapshot.snapshot_hash
      || findingContext.contract_revision_id !== plan.snapshot.contract.revision_id) throw new Error("REVIEW_FINDING_VALIDATION_AUTHORITY_MISMATCH");
    for (const finding of proposed) {
      await this.audit(plan, "finding.proposed", { finding_id: finding.finding_id, finding_key: finding.finding_key, severity: finding.proposed_severity });
    }
    const validated = proposed.map(finding => validateFinding(finding, findingContext, this.ports.clock()).finding);
    const confirmed = validated.filter(finding => finding.status === "CONFIRMED");
    const groups = deduplicateFindings(confirmed);
    const canonicalIds = new Set(groups.map(group => group.canonical_finding_id));
    const duplicateTargets = new Map(groups.flatMap(group => group.members
      .filter(member => member.finding_id !== group.canonical_finding_id)
      .map(member => [member.finding_id, group.canonical_finding_id] as const)));
    const deduplicatedFindings = validated.map(finding => {
      const duplicateOf = duplicateTargets.get(finding.finding_id);
      return duplicateOf ? parseReviewFinding({ ...finding, status: "DUPLICATE", effective_severity: null, duplicate_of: duplicateOf }) : finding;
    });
    const waivers = governance.waivers;
    const appliedWaivers = new Map<string, Waiver>();
    const finalFindings = deduplicatedFindings.map(finding => {
      if (finding.status !== "CONFIRMED") return finding;
      const applicable = waivers.find(waiver => {
        if (waiver.finding_id !== finding.finding_id) return false;
        try { return assertWaiverApplies(waiver, finding, plan.snapshot.snapshot_hash, governance.evaluatedAt); }
        catch { return false; }
      });
      if (applicable) appliedWaivers.set(finding.finding_id, applicable);
      return applicable ? parseReviewFinding({ ...finding, status: "WAIVED", updated_at: this.ports.clock() }) : finding;
    });
    const canonicalConfirmed = finalFindings.filter(finding => canonicalIds.has(finding.finding_id) && finding.status === "CONFIRMED");
    const findingsArtifactRef = deterministicId("artifact", {
      plan: plan.review_plan_id,
      revision: plan.revision,
      snapshot: plan.snapshot.snapshot_hash,
      type: "validated-findings",
    });
    await this.ports.artifacts.putJson({
      idempotency_key: `${plan.review_plan_id}:revision-${plan.revision}:${plan.snapshot.snapshot_hash}:findings`,
      artifact_ref: findingsArtifactRef,
      value: { findings: finalFindings, finding_groups: groups },
    });
    for (const finding of finalFindings) {
      await this.audit(plan, "finding.validated", {
        finding_id: finding.finding_id,
        finding_key: finding.finding_key,
        ...(finding.effective_severity ? { severity: finding.effective_severity } : {}),
      });
      const beforeWaiver = deduplicatedFindings.find(candidate => candidate.finding_id === finding.finding_id);
      if (beforeWaiver?.status === "CONFIRMED") {
        await this.audit(plan, "finding.confirmed", { finding_id: finding.finding_id, finding_key: finding.finding_key, severity: beforeWaiver.effective_severity ?? undefined });
      } else if (beforeWaiver?.status === "DISMISSED") {
        await this.audit(plan, "finding.dismissed", { finding_id: finding.finding_id, finding_key: finding.finding_key, severity: finding.proposed_severity });
      }
      const waiver = appliedWaivers.get(finding.finding_id);
      if (waiver) await this.audit(plan, "finding.waived", { finding_id: finding.finding_id, finding_key: finding.finding_key, severity: finding.effective_severity ?? undefined, waiver_id: waiver.waiver_id });
    }

    let humanApproved = false;
    let humanApproval: HumanReviewApproval | null = null;
    const approvalInput = governance.humanApproval;
    if (approvalInput !== null) {
      try {
        const approval = parseHumanReviewApproval(approvalInput);
        const approvalDecision = governance.approvalDecision;
        const expectedFindingIds = approvalDecision
          ? [...new Set([...approvalDecision.accepted_findings, ...approvalDecision.unresolved_findings])].sort()
          : [];
        const currentFindingIds = canonicalConfirmed.map(finding => finding.finding_id).sort();
        humanApproved = approvalDecision !== null
          && approvalDecision.decision === "NEEDS_HUMAN"
          && approval.review_plan_id === plan.review_plan_id
          && approval.snapshot_hash === plan.snapshot.snapshot_hash
          && approval.review_decision_id === approvalDecision.review_decision_id
          && approval.review_decision_hash === canonicalSha256(approvalDecision)
          && canonicalSha256(approval.finding_ids) === canonicalSha256(expectedFindingIds)
          && canonicalSha256(approval.finding_ids) === canonicalSha256(currentFindingIds);
        if (humanApproved) {
          humanApproval = approval;
          await this.audit(plan, "review.human-approved", {
            human_approval_id: approval.approval_id,
            snapshot_hash: approval.snapshot_hash,
            review_decision_id: approval.review_decision_id,
            review_decision_hash: approval.review_decision_hash,
            finding_ids: approval.finding_ids,
            artifact_refs: [{ artifact_id: approval.approval_artifact_ref, artifact_hash: approval.approval_hash, kind: "human-decision" }],
          });
        }
      } catch { humanApproved = false; }
    }
    const completedReviewers = completed.map(entry => ({
      review_type: entry.unit.review_type,
      provider: entry.binding.model_ref.provider,
      agent_id: entry.binding.independence.reviewer.agent_id,
      session_id: entry.binding.independence.reviewer.session_id,
      context_id: entry.binding.independence.reviewer.context_id,
      independence_score: independenceScore(entry.binding),
      completed: true,
    }));
    const quorum = verifyQuorum(plan.quorum, completedReviewers, humanApproved);
    const requestedEvidence = completed.flatMap(entry => entry.result.requested_evidence);
    const requiredRecommendations = completed.filter(entry => entry.unit.required);
    const unsupportedRecommendation = requiredRecommendations.some(entry =>
      (entry.result.decision.recommendation === "blocked" || entry.result.decision.recommendation === "changes-requested")
      && !confirmed.some(finding => finding.review_unit_id === entry.unit.review_unit_id),
    );
    const reviewerNeedsHuman = requiredRecommendations.some(entry => entry.result.decision.recommendation === "needs-human");
    const reviewerInconclusive = requiredRecommendations.some(entry => entry.result.decision.recommendation === "inconclusive");
    const completedBindings = new Map(completed.map(entry => [entry.binding.reviewer_binding_id, entry.binding]));
    const criticalFindingPresent = canonicalConfirmed.some(finding => finding.effective_severity === "CRITICAL");
    const criticalSourceMissing = canonicalConfirmed.some(finding => {
      if (finding.effective_severity !== "CRITICAL") return false;
      const group = groups.find(candidate => candidate.canonical_finding_id === finding.finding_id);
      const sources = new Set((group?.members ?? [finding])
        .filter(member => member.effective_severity === "CRITICAL")
        .map(member => completedBindings.get(member.proposed_by.reviewer_binding_id))
        .filter((binding): binding is ReviewerBinding => Boolean(binding))
        .map(binding => {
          const source = binding.independence.reviewer;
          return `${source.agent_id}|${source.session_id}|${source.context_id}`;
        }));
      return sources.size < 2;
    });
    let adjudication: { decision: ReviewDecision; reason_codes: string[] };
    if (state.counters.evidence_requests + requestedEvidence.length > plan.limits.max_evidence_requests) {
      adjudication = { decision: "NEEDS_HUMAN", reason_codes: ["evidence-request-limit-reached"] };
    } else if (requestedEvidence.length > 0) {
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["additional-evidence-required"] };
    } else if (unsupportedRecommendation) {
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["unsupported-review-recommendation"] };
    } else if (reviewerNeedsHuman) {
      adjudication = { decision: "NEEDS_HUMAN", reason_codes: ["reviewer-needs-human"] };
    } else if (reviewerInconclusive) {
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["reviewer-inconclusive"] };
    } else if (criticalSourceMissing) {
      adjudication = { decision: "NEEDS_HUMAN", reason_codes: ["critical-finding-independent-source-missing"] };
    } else if (criticalFindingPresent && !humanApproved) {
      adjudication = { decision: "NEEDS_HUMAN", reason_codes: ["critical-finding-human-approval-missing"] };
    } else if (quorum.satisfied) {
      adjudication = adjudicateReview({
        mechanical_verification_passed: true,
        required_review_types: plan.quorum.required_review_types,
        completed_review_types: completed.map(entry => entry.unit.review_type),
        confirmed_findings: canonicalConfirmed,
        unresolved_disagreement: false,
        human_approval_required: plan.quorum.human_approval === "required" || criticalFindingPresent,
        human_approved: humanApproved,
      });
    } else {
      adjudication = quorum.reasons.includes("human-approval-missing")
        ? { decision: "NEEDS_HUMAN", reason_codes: quorum.reasons }
        : { decision: "INCONCLUSIVE", reason_codes: quorum.reasons };
    }

    let current = true;
    try {
      assertReviewSnapshotCurrent(plan.snapshot, await this.ports.data.loadCurrentSnapshot(plan.task_id));
    } catch {
      current = false;
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["review-snapshot-stale"] };
    }
    let mechanicalCurrent = true;
    try {
      const currentMechanical = mechanicalEvidenceSchema.parse(await this.ports.data.loadMechanicalEvidence(plan.review_plan_id));
      if (canonicalSha256(currentMechanical) !== canonicalSha256(mechanical)) throw new Error("MECHANICAL_EVIDENCE_CHANGED");
    } catch {
      mechanicalCurrent = false;
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["mechanical-evidence-stale"] };
    }
    try {
      const finalValidity = assessReviewValidity(
        await this.ports.data.loadReviewValidityBaseline(plan.review_plan_id),
        await this.ports.data.loadCurrentReviewValidity(plan.review_plan_id),
      );
      if (finalValidity.status === "STALE") {
        current = false;
        adjudication = { decision: "INCONCLUSIVE", reason_codes: finalValidity.reasons };
      }
    } catch {
      current = false;
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["review-validity-unavailable"] };
    }
    try {
      const finalWaivers = await this.ports.data.loadWaivers(plan.review_plan_id);
      const finalApproval = await this.ports.data.loadHumanApproval(plan.review_plan_id);
      const sameWaivers = canonicalSha256(finalWaivers) === canonicalSha256(governance.waivers);
      const sameApproval = canonicalSha256(finalApproval) === canonicalSha256(governance.humanApproval);
      const finalTime = this.ports.clock();
      const appliedStillValid = [...appliedWaivers.entries()].every(([findingId, waiver]) => {
        const finding = deduplicatedFindings.find(candidate => candidate.finding_id === findingId);
        if (!finding) return false;
        try { return assertWaiverApplies(waiver, finding, plan.snapshot.snapshot_hash, finalTime); }
        catch { return false; }
      });
      if (!sameWaivers || !sameApproval || !appliedStillValid) {
        adjudication = { decision: "INCONCLUSIVE", reason_codes: ["review-governance-stale"] };
      }
    } catch {
      adjudication = { decision: "INCONCLUSIVE", reason_codes: ["review-governance-unavailable"] };
    }
    return this.terminal(
      plan, adjudication.decision, adjudication.reason_codes, current, mechanicalCurrent, finalFindings, groups, completed, quorum.satisfied,
      { waiverIds: [...new Set(appliedWaivers.values().map(waiver => waiver.waiver_id))].sort(), humanApproval },
    );
  }

  private async executeUnit(
    plan: ReviewPlan,
    unit: ReviewPlan["review_units"][number],
    priorFindings: readonly Pick<ReviewFinding, "finding_id" | "status" | "claim">[],
  ): Promise<CompletedUnit> {
    const binding = parseReviewerBinding(await this.ports.data.loadReviewerBinding(unit.review_unit_id));
    if (binding.review_unit_id !== unit.review_unit_id
      || binding.reviewer_profile_ref.id !== unit.profile_ref.id
      || binding.reviewer_profile_ref.version !== unit.profile_ref.version
      || binding.reviewer_profile_ref.hash !== unit.profile_ref.hash
      || binding.risk_level !== plan.risk.level) throw new Error("REVIEWER_BINDING_MISMATCH");
    assertReviewerCapabilities(binding, unit.required_capabilities);
    const context = this.contextCompiler.compile(await this.ports.data.buildContextInput(unit, priorFindings));
    if (context.snapshot_hash !== plan.snapshot.snapshot_hash
      || context.review_unit.id !== unit.review_unit_id
      || canonicalSha256(context.review_unit.profile_ref) !== canonicalSha256(unit.profile_ref)
      || context.task_contract.revision_id !== plan.snapshot.contract.revision_id
      || context.task_contract.revision !== plan.snapshot.contract.revision
      || context.task_contract.hash !== plan.snapshot.contract.hash
      || context.review_plan.id !== plan.review_plan_id
      || context.review_plan.revision !== plan.revision
      || context.review_plan.hash !== hashReviewPlan(plan)
      || canonicalSha256(context.policy_pack) !== canonicalSha256(plan.adjudication_policy_ref)
      || context.source.base_commit !== plan.snapshot.source.base_commit) throw new Error("REVIEW_CONTEXT_AUTHORITY_MISMATCH");
    const executionId = deterministicId("review-execution", { plan: plan.review_plan_id, revision: plan.revision, unit: unit.review_unit_id });
    await this.ports.artifacts.putJson({
      idempotency_key: `${executionId}:context`, artifact_ref: deterministicId("artifact", { executionId, type: "context" }), value: context,
    });
    const execution = await this.ports.executor.execute({ review_execution_id: executionId, plan, unit, binding, context });
    if (execution.status !== "COMPLETED") throw new Error("REVIEW_EXECUTION_FAILED");
    const attestation = runtimeAttestationSchema.parse(execution.runtime_attestation);
    const {
      isolation: ignoredIsolation,
      attestation_hash: ignoredHash,
      attestation_key_id: ignoredKeyId,
      attestation_signature: ignoredSignature,
      attestation_algorithm: ignoredAlgorithm,
      attestation_public_key: ignoredPublicKey,
      ...identityContent
    } = attestation;
    if (attestation.review_execution_id !== executionId
      || attestation.container_image_digest !== attestation.isolation.image_digest
      || attestation.isolation_hash !== canonicalSha256(attestation.isolation)
      || attestation.launch_policy_id !== binding.runtime_ref.id
      || attestation.output_hash !== execution.output_hash
      || canonicalSha256(identityContent) !== attestation.attestation_hash
      || !(await this.ports.data.verifyRuntimeIdentityAttestation(attestation))) throw new Error("REVIEW_RUNTIME_ATTESTATION_INVALID");
    const expectedReviewer = binding.independence.reviewer;
    if (attestation.reviewer.agent_id !== expectedReviewer.agent_id
      || attestation.reviewer.provider !== expectedReviewer.provider
      || attestation.reviewer.model_class !== expectedReviewer.model_class
      || attestation.reviewer.session_id !== expectedReviewer.session_id
      || attestation.reviewer.context_id !== expectedReviewer.context_id) throw new Error("REVIEW_RUNTIME_IDENTITY_MISMATCH");
    hashSchema.parse(execution.output_hash);
    if (canonicalSha256(execution.raw_output) !== execution.output_hash) throw new Error("REVIEW_EXECUTION_OUTPUT_HASH_MISMATCH");
    if (!Number.isInteger(execution.cost_units) || execution.cost_units < 0) throw new Error("REVIEW_EXECUTION_COST_INVALID");
    const validationContext = await this.ports.data.loadResultValidationContext(unit.review_unit_id);
    if (validationContext.review_unit_id !== unit.review_unit_id || validationContext.snapshot_hash !== plan.snapshot.snapshot_hash) {
      throw new Error("REVIEW_RESULT_VALIDATION_AUTHORITY_MISMATCH");
    }
    const result = validateReviewResult(execution.raw_output, validationContext);
    await this.ports.artifacts.putJson({
      idempotency_key: `${executionId}:result`, artifact_ref: deterministicId("artifact", { executionId, type: "result" }), value: result,
    });
    await this.audit(plan, "review.unit.completed", {
      review_unit_id: unit.review_unit_id,
      review_type: shortReviewType(unit.review_type),
      finding_count: result.findings.length,
    });
    return { unit, binding, result, costUnits: execution.cost_units };
  }

  private toFinding(
    plan: ReviewPlan,
    binding: ReviewerBinding,
    unit: ReviewPlan["review_units"][number],
    finding: ReviewResult["findings"][number],
  ): ReviewFinding {
    const snapshotSuffix = plan.snapshot.snapshot_hash.slice("sha256:".length, "sha256:".length + 12).toUpperCase();
    const storedFindingKey = `${finding.finding_key}-S${snapshotSuffix}`;
    const findingId = deterministicId("review-finding", {
      plan: plan.review_plan_id, snapshot: plan.snapshot.snapshot_hash,
      unit: unit.review_unit_id, finding_key: finding.finding_key,
    });
    return parseReviewFinding({
      schema_version: 1,
      finding_id: findingId,
      finding_key: storedFindingKey,
      review_plan_id: plan.review_plan_id,
      review_unit_id: unit.review_unit_id,
      category: finding.category,
      proposed_severity: finding.proposed_severity,
      effective_severity: null,
      confidence: finding.confidence,
      status: "PROPOSED",
      claim: finding.claim,
      impact: finding.impact,
      scope: {
        snapshot_hash: plan.snapshot.snapshot_hash,
        contract_revision_id: plan.snapshot.contract.revision_id,
        source_tree_hash: plan.snapshot.source.result_tree_hash,
        diff_hash: plan.snapshot.source.diff_hash,
      },
      anchors: finding.code_locations.map(location => ({
        type: "code",
        path: location.path,
        line_start: location.start_line,
        line_end: location.end_line,
        file_hash: location.file_hash,
        symbol: null,
        snippet_hash: canonicalSha256({ location, claim: finding.claim }),
      })),
      contract_refs: finding.contract_refs,
      evidence_refs: finding.evidence_refs,
      evidence_strength: evidenceStrength(finding),
      proposed_by: { reviewer_binding_id: binding.reviewer_binding_id },
      created_at: this.ports.clock(),
      updated_at: this.ports.clock(),
      duplicate_of: null,
    });
  }

  private async terminal(
    plan: ReviewPlan,
    decision: ReviewDecision,
    reasonCodes: string[],
    currentSnapshot: boolean,
    mechanicalPassed: boolean,
    findings: ReviewFinding[],
    groups: FindingGroup[],
    completed: CompletedUnit[],
    quorumSatisfied = false,
    governance: { waiverIds: string[]; humanApproval: HumanReviewApproval | null } = { waiverIds: [], humanApproval: null },
  ): Promise<CoreOutcome> {
    const canonical = new Set(groups.map(group => group.canonical_finding_id));
    const accepted = findings.filter(finding => finding.status === "CONFIRMED" && (groups.length === 0 || canonical.has(finding.finding_id)));
    const dismissed = findings.filter(finding => ["DISMISSED", "DUPLICATE"].includes(finding.status));
    const unresolved = findings.filter(finding => ["PROPOSED", "VALIDATING", "STALE"].includes(finding.status));
    const waived = findings.filter(finding => finding.status === "WAIVED");
    const severityCounts: Record<FindingSeverity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const finding of accepted) if (finding.effective_severity) severityCounts[finding.effective_severity] += 1;
    const decisionId = deterministicId("review-decision", {
      plan: plan.review_plan_id,
      revision: plan.revision,
      snapshot: plan.snapshot.snapshot_hash,
      decision,
      accepted: accepted.map(finding => finding.finding_id).sort(),
      dismissed: dismissed.map(finding => finding.finding_id).sort(),
      unresolved: unresolved.map(finding => finding.finding_id).sort(),
      waived: waived.map(finding => finding.finding_id).sort(),
      waiver_ids: governance.waiverIds,
      human_approval: governance.humanApproval?.approval_id ?? null,
      reasons: [...reasonCodes].sort(),
    });
    const decisionArtifactRef = deterministicId("artifact", { decisionId, type: "review-decision" });
    const record = parseReviewDecisionRecord({
      schema_version: 1,
      review_decision_id: decisionId,
      review_plan_id: plan.review_plan_id,
      snapshot_hash: plan.snapshot.snapshot_hash,
      decision,
      decision_source: "deterministic-policy",
      current_snapshot: currentSnapshot,
      quorum_satisfied: quorumSatisfied,
      mechanical_verification_passed: mechanicalPassed,
      accepted_findings: accepted.map(finding => finding.finding_id).sort(),
      dismissed_findings: dismissed.map(finding => finding.finding_id).sort(),
      unresolved_findings: unresolved.map(finding => finding.finding_id).sort(),
      waived_findings: waived.map(finding => finding.finding_id).sort(),
      waiver_ids: governance.waiverIds,
      human_approval: governance.humanApproval ? {
        approval_id: governance.humanApproval.approval_id,
        approval_hash: governance.humanApproval.approval_hash,
        approval_artifact_ref: governance.humanApproval.approval_artifact_ref,
      } : null,
      severity_counts: severityCounts,
      reason_codes: [...new Set(reasonCodes)].sort(),
      rationale: reasonCodes.length > 0 ? `Deterministic review policy: ${[...new Set(reasonCodes)].sort().join(", ")}.` : "All required review and evidence gates passed.",
      next_action: nextAction(decision),
      decision_artifact_ref: decisionArtifactRef,
      issued_at: this.ports.clock(),
    });
    await this.ports.audit.assertIntegrity(plan.review_plan_id);
    await this.audit(plan, "review.decision.issued", {
      decision: auditDecision(decision),
      blocker_ids: accepted.map(finding => finding.finding_id).sort(),
    });
    await this.ports.audit.assertIntegrity(plan.review_plan_id);
    await this.ports.artifacts.putJson({ idempotency_key: `${decisionId}:artifact`, artifact_ref: decisionArtifactRef, value: record });
    return {
      decision: record,
      findings,
      finding_groups: groups,
      completed_review_units: completed.map(entry => entry.unit.review_unit_id).sort(),
    };
  }

  private async audit(plan: ReviewPlan, eventType: ReviewAuditEventType, payload: unknown): Promise<void> {
    const eventId = deterministicId("review-event", { plan: plan.review_plan_id, revision: plan.revision, eventType, payload });
    await this.ports.audit.append({
      idempotency_key: `${eventId}:append`, event_id: eventId, event_type: eventType,
      aggregate_id: plan.review_plan_id, occurred_at: this.ports.clock(), payload,
    });
  }
}

function auditDecision(decision: ReviewDecision): "pass" | "repair" | "blocked" | "needs-human" | "inconclusive" {
  if (decision === "PASS" || decision === "PASS_WITH_NOTES") return "pass";
  if (decision === "CHANGES_REQUESTED") return "repair";
  if (decision === "BLOCKED") return "blocked";
  if (decision === "NEEDS_HUMAN") return "needs-human";
  return "inconclusive";
}

function independenceScore(binding: ReviewerBinding): number {
  const implementer = binding.independence.implementer;
  const reviewer = binding.independence.reviewer;
  return computeIndependenceScore({
    different_session: implementer.session_id !== reviewer.session_id,
    different_prompt_profile: false,
    different_runtime: false,
    different_model: implementer.model_class !== reviewer.model_class,
    different_provider: implementer.provider !== reviewer.provider,
    different_tool_pipeline: false,
  });
}

function evidenceStrength(finding: ReviewResult["findings"][number]): "STRONG" | "SUPPORTED" | "OPINION" {
  if (finding.evidence_refs.length > 0 && finding.verification.reproducible) return "STRONG";
  if (finding.evidence_refs.length > 0) return "SUPPORTED";
  return "OPINION";
}

function shortReviewType(value: string): string { return value.split(".").at(-1)!.replaceAll("-compliance", ""); }

function safeFailureCode(value: unknown): string {
  const message = value instanceof Error ? value.message : String(value);
  const normalized = message.toUpperCase().replace(/[^A-Z0-9_:-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 200);
  return normalized || "REVIEW_UNIT_EXECUTION_FAILED";
}

function deterministicId(prefix: string, input: unknown): string {
  return `${prefix}:${canonicalSha256(input).slice("sha256:".length, "sha256:".length + 32)}`;
}

function nextAction(decision: ReviewDecision): { type: "phase1-verdict" | "repair" | "human-gate" | "redispatch" | "none" } {
  if (decision === "PASS" || decision === "PASS_WITH_NOTES" || decision === "BLOCKED") return { type: "phase1-verdict" };
  if (decision === "CHANGES_REQUESTED") return { type: "repair" };
  if (decision === "NEEDS_HUMAN") return { type: "human-gate" };
  if (decision === "INCONCLUSIVE") return { type: "redispatch" };
  return { type: "none" };
}
