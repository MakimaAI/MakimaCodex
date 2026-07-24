import { describe, expect, test } from "bun:test";
import {
  adjudicateReview,
  assertResolutionVerified,
  assessReviewValidity,
  computeIndependenceScore,
  createRepairProposal,
  deduplicateFindings,
  determineDeltaReviewTypes,
  mapReviewDecisionToPhase1,
  parseReviewFinding,
  validateFinding,
  verifyQuorum,
  type ReviewFinding,
} from "../src/oef/phase3";

const NOW = "2026-07-23T15:00:00.000Z";
const hash = (value: string) => `sha256:${value.repeat(64)}`;

function finding(overrides: Partial<ReviewFinding> = {}): ReviewFinding {
  return parseReviewFinding({
    schema_version: 1,
    finding_id: "review-finding:one",
    finding_key: "FIND-ONE",
    review_plan_id: "review-plan:one",
    review_unit_id: "review-unit:spec",
    category: "correctness",
    proposed_severity: "HIGH",
    effective_severity: null,
    confidence: 0.93,
    status: "PROPOSED",
    claim: "403 responses are classified as rate limits.",
    impact: "Authentication failures rotate accounts incorrectly.",
    scope: {
      snapshot_hash: hash("a"),
      contract_revision_id: "contract-revision:one",
      source_tree_hash: hash("b"),
      diff_hash: hash("c"),
    },
    anchors: [{
      type: "code",
      path: "src/providers/clinepass/error-classifier.ts",
      line_start: 42,
      line_end: 61,
      file_hash: hash("d"),
      symbol: { type: "function", name: "classifyError" },
      snippet_hash: hash("e"),
    }],
    contract_refs: ["AC-403"],
    evidence_refs: ["evidence:test-403"],
    evidence_strength: "STRONG",
    proposed_by: { reviewer_binding_id: "reviewer-binding:one" },
    created_at: NOW,
    updated_at: NOW,
    duplicate_of: null,
    ...overrides,
  });
}

const validationContext = {
  snapshot_hash: hash("a"),
  contract_revision_id: "contract-revision:one",
  files: [{ path: "src/providers/clinepass/error-classifier.ts", hash: hash("d"), line_count: 100 }],
  contract_refs: ["AC-403"],
  evidence_refs: ["evidence:test-403"],
};

describe("Phase 3 finding validation and adjudication", () => {
  test("confirms only snapshot-bound findings with resolvable anchors and evidence", () => {
    const result = validateFinding(finding(), validationContext, NOW);
    expect(result.status).toBe("CONFIRMED");
    expect(result.finding.status).toBe("CONFIRMED");
    expect(result.finding.effective_severity).toBe("HIGH");
    expect(result.validated_by).toEqual(["snapshot", "anchor", "contract", "evidence"]);

    const stale = validateFinding(finding(), { ...validationContext, snapshot_hash: hash("f") }, NOW);
    expect(stale.status).toBe("STALE");
    expect(stale.finding.status).toBe("STALE");

    const unsupported = validateFinding(finding({ evidence_strength: "UNSUPPORTED", evidence_refs: [] }), {
      ...validationContext,
      evidence_refs: [],
    }, NOW);
    expect(unsupported.status).toBe("DISMISSED");
    expect(unsupported.reason).toBe("unsupported-finding");
  });

  test("deduplicates deterministically without deleting original findings", () => {
    const second = finding({
      finding_id: "review-finding:two",
      finding_key: "FIND-TWO",
      review_unit_id: "review-unit:quality",
      proposed_by: { reviewer_binding_id: "reviewer-binding:two" },
    });
    const groups = deduplicateFindings([second, finding()]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.members.map(item => item.finding_id)).toEqual(["review-finding:one", "review-finding:two"]);
    expect(groups[0]?.canonical_finding_id).toBe("review-finding:one");

    const distinctCritical = finding({
      finding_id: "review-finding:critical-distinct",
      finding_key: "FIND-CRITICAL-DISTINCT",
      status: "CONFIRMED",
      effective_severity: "CRITICAL",
      claim: "The same branch leaks a credential to the review output.",
      impact: "A repository secret can be exfiltrated.",
    });
    const confirmedLow = finding({ status: "CONFIRMED", proposed_severity: "LOW", effective_severity: "LOW" });
    expect(deduplicateFindings([confirmedLow, distinctCritical])).toHaveLength(2);

    const sameCritical = finding({
      finding_id: "review-finding:critical-same",
      finding_key: "FIND-CRITICAL-SAME",
      status: "CONFIRMED",
      effective_severity: "CRITICAL",
    });
    const severityGroup = deduplicateFindings([confirmedLow, sameCritical]);
    expect(severityGroup).toHaveLength(1);
    expect(severityGroup[0]?.canonical_finding_id).toBe(sameCritical.finding_id);
  });

  test("scores independence and enforces semantic quorum rather than reviewer majority", () => {
    expect(computeIndependenceScore({
      different_session: true,
      different_prompt_profile: true,
      different_runtime: true,
      different_model: true,
      different_provider: true,
      different_tool_pipeline: true,
    })).toBe(9);

    const quorum = verifyQuorum({
      required_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
      minimum_independent_providers: 2,
      minimum_independence_score: 6,
      human_approval: "not-required",
    }, [
      { review_type: "opencodex.spec-compliance", provider: "provider-a", agent_id: "agent:spec", session_id: "session:spec", context_id: "context:spec", independence_score: 7, completed: true },
      { review_type: "opencodex.code-quality", provider: "provider-b", agent_id: "agent:quality", session_id: "session:quality", context_id: "context:quality", independence_score: 8, completed: true },
    ], false);
    expect(quorum).toEqual({ satisfied: true, reasons: [] });

    const sharedSource = verifyQuorum({
      required_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
      minimum_independent_providers: 2,
      minimum_independence_score: 3,
      human_approval: "not-required",
    }, [
      { review_type: "opencodex.spec-compliance", provider: "provider-a", agent_id: "agent:shared", session_id: "session:shared", context_id: "context:shared", independence_score: 6, completed: true },
      { review_type: "opencodex.code-quality", provider: "provider-b", agent_id: "agent:shared", session_id: "session:shared", context_id: "context:shared", independence_score: 6, completed: true },
    ], false);
    expect(sharedSource.satisfied).toBeFalse();
    expect(sharedSource.reasons).toContain("reviewer-source-independence-missing");

    const noSpec = adjudicateReview({
      mechanical_verification_passed: true,
      required_review_types: ["opencodex.spec-compliance", "opencodex.code-quality"],
      completed_review_types: ["opencodex.code-quality", "opencodex.security", "opencodex.documentation"],
      confirmed_findings: [],
      unresolved_disagreement: false,
      human_approval_required: false,
      human_approved: false,
    });
    expect(noSpec.decision).toBe("INCONCLUSIVE");
    expect(noSpec.reason_codes).toContain("required-review-missing");
  });

  test("applies deterministic blocker rules and never lets unsupported findings block", () => {
    const confirmedHigh = finding({ status: "CONFIRMED", effective_severity: "HIGH" });
    expect(adjudicateReview({
      mechanical_verification_passed: true,
      required_review_types: ["opencodex.spec-compliance"],
      completed_review_types: ["opencodex.spec-compliance"],
      confirmed_findings: [confirmedHigh],
      unresolved_disagreement: false,
      human_approval_required: false,
      human_approved: false,
    }).decision).toBe("CHANGES_REQUESTED");

    const critical = finding({ status: "CONFIRMED", effective_severity: "CRITICAL", evidence_strength: "AUTHORITATIVE" });
    expect(adjudicateReview({
      mechanical_verification_passed: true,
      required_review_types: ["opencodex.security"],
      completed_review_types: ["opencodex.security"],
      confirmed_findings: [critical],
      unresolved_disagreement: false,
      human_approval_required: true,
      human_approved: false,
    }).decision).toBe("BLOCKED");

    expect(() => adjudicateReview({
      mechanical_verification_passed: true,
      required_review_types: ["opencodex.security"],
      completed_review_types: ["opencodex.security"],
      confirmed_findings: [finding({ status: "PROPOSED", evidence_strength: "UNSUPPORTED" })],
      unresolved_disagreement: false,
      human_approval_required: false,
      human_approved: false,
    })).not.toThrow();
  });
});

describe("Phase 3 repair and validity", () => {
  test("maps final review decisions to versioned Phase 1 outcomes", () => {
    expect(mapReviewDecisionToPhase1("PASS")).toBe("ACCEPT");
    expect(mapReviewDecisionToPhase1("PASS_WITH_NOTES")).toBe("ACCEPT_WITH_NOTES");
    expect(mapReviewDecisionToPhase1("CHANGES_REQUESTED")).toBe("REPAIR");
    expect(mapReviewDecisionToPhase1("BLOCKED")).toBe("BLOCK");
    expect(mapReviewDecisionToPhase1("NEEDS_HUMAN")).toBe("NEEDS_HUMAN");
  });

  test("creates scoped repair proposals only from confirmed findings", () => {
    const proposal = createRepairProposal({
      repair_proposal_id: "repair-proposal:one",
      task_id: "task:one",
      source_review_plan_id: "review-plan:one",
      findings: [finding({ status: "CONFIRMED", effective_severity: "HIGH" })],
      constraints: ["Preserve existing 429 behavior."],
      required_evidence: ["regression-test-403", "existing-429-test"],
      created_at: NOW,
    });
    expect(proposal.target_findings).toEqual(["review-finding:one"]);
    expect(proposal.scope.allowed_paths).toEqual(["src/providers/clinepass/error-classifier.ts"]);
    expect(proposal.objective).toContain("403 responses");
    expect(() => createRepairProposal({
      repair_proposal_id: "repair-proposal:bad",
      task_id: "task:one",
      source_review_plan_id: "review-plan:one",
      findings: [finding()],
      constraints: [], required_evidence: [], created_at: NOW,
    })).toThrow("REPAIR_REQUIRES_CONFIRMED_FINDINGS");
  });

  test("selects deterministic delta reviews and verifies resolution on a new snapshot", () => {
    expect(determineDeltaReviewTypes({
      changed_files: ["src/providers/clinepass/error-classifier.ts"],
      risk_level: "high",
      public_api_changed: false,
    })).toEqual(["opencodex.spec-compliance", "opencodex.code-quality", "opencodex.security"]);
    expect(determineDeltaReviewTypes({
      changed_files: ["src/ui/button.css"], risk_level: "low", public_api_changed: false,
    })).toEqual(["opencodex.code-quality", "opencodex.visual", "opencodex.accessibility"]);

    expect(assertResolutionVerified({
      previous_finding: finding({ status: "RESOLVED", effective_severity: "HIGH" }),
      new_snapshot_hash: hash("f"),
      changed_anchor_paths: ["src/providers/clinepass/error-classifier.ts"],
      regression_evidence_passed: true,
      reproduction_no_longer_fails: true,
      independently_validated: true,
    })).toBeTrue();
    expect(() => assertResolutionVerified({
      previous_finding: finding({ status: "RESOLVED", effective_severity: "HIGH" }),
      new_snapshot_hash: hash("a"),
      changed_anchor_paths: ["src/providers/clinepass/error-classifier.ts"],
      regression_evidence_passed: true,
      reproduction_no_longer_fails: true,
      independently_validated: true,
    })).toThrow("RESOLUTION_REQUIRES_NEW_SNAPSHOT");
  });

  test("marks any changed review input stale and forbids stale acceptance", () => {
    const pinned = {
      contract_hash: hash("a"), source_tree_hash: hash("b"), diff_hash: hash("c"), evidence_package_hash: hash("d"),
      policy_hash: hash("e"), profile_hashes: [hash("f")], required_evidence_hashes: [hash("1")], dependency_hash: hash("2"),
    };
    expect(assessReviewValidity(pinned, pinned)).toEqual({ status: "CURRENT", reasons: [] });
    expect(assessReviewValidity(pinned, { ...pinned, diff_hash: hash("3") })).toEqual({ status: "STALE", reasons: ["diff-changed"] });
  });
});
