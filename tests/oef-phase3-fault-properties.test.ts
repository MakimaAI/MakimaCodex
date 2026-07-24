import { describe, expect, test } from "bun:test";
import {
  assessReviewValidity,
  deduplicateFindings,
  parseReviewFinding,
  verifyQuorum,
  type FindingSeverity,
  type ReviewFinding,
} from "../src/oef/phase3";

const NOW = "2026-07-23T15:00:00.000Z";
const hash = (character: string) => `sha256:${character.repeat(64)}`;
const rank: Record<FindingSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function finding(id: number, severity: FindingSeverity, claim = "The authentication branch misclassifies HTTP 403."): ReviewFinding {
  return parseReviewFinding({
    schema_version: 1,
    finding_id: `review-finding:property-${id}`,
    finding_key: `FIND-PROPERTY-${id}`,
    review_plan_id: "review-plan:property",
    review_unit_id: `review-unit:property-${id}`,
    category: "correctness",
    proposed_severity: severity,
    effective_severity: severity,
    confidence: 0.95,
    status: "CONFIRMED",
    claim,
    impact: "Account rotation can hide invalid credentials.",
    scope: { snapshot_hash: hash("a"), contract_revision_id: "contract-revision:property", source_tree_hash: hash("b"), diff_hash: hash("c") },
    anchors: [{ type: "code", path: "src/classifier.ts", line_start: 1, line_end: 4, file_hash: hash("d"), symbol: null, snippet_hash: hash("e") }],
    contract_refs: ["AC-403"], evidence_refs: ["evidence:test-403"], evidence_strength: "AUTHORITATIVE",
    proposed_by: { reviewer_binding_id: `reviewer-binding:property-${id}` },
    created_at: NOW, updated_at: NOW, duplicate_of: null,
  });
}

function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function shuffle<T>(values: readonly T[], next: () => number): T[] {
  const result = [...values];
  for (let index = result.length - 1; index > 0; index -= 1) {
    const target = Math.floor(next() * (index + 1));
    [result[index], result[target]] = [result[target]!, result[index]!];
  }
  return result;
}

describe("Phase 3 deterministic security properties", () => {
  test("never lets input ordering hide the highest severity duplicate", () => {
    const next = random(0x403429);
    const source = [finding(1, "LOW"), finding(2, "HIGH"), finding(3, "CRITICAL"), finding(4, "MEDIUM")];
    for (let run = 0; run < 500; run += 1) {
      const group = deduplicateFindings(shuffle(source, next))[0]!;
      const canonical = group.members.find(item => item.finding_id === group.canonical_finding_id)!;
      expect(rank[canonical.effective_severity!]).toBe(rank.CRITICAL);
    }
  });

  test("never merges distinct claims that merely share an anchor and evidence", () => {
    const next = random(0x51a1e);
    for (let run = 0; run < 250; run += 1) {
      const count = 2 + Math.floor(next() * 8);
      const findings = Array.from({ length: count }, (_, index) => finding(index + 10, "HIGH", `Distinct supported claim ${run}-${index}.`));
      expect(deduplicateFindings(shuffle(findings, next))).toHaveLength(count);
    }
  });

  test("rejects any reviewer quorum with a reused agent, session, or context", () => {
    const dimensions = ["agent_id", "session_id", "context_id"] as const;
    for (const dimension of dimensions) {
      const first = {
        review_type: "opencodex.spec-compliance", provider: "provider-a", agent_id: "agent:a", session_id: "session:a", context_id: "context:a",
        independence_score: 6, completed: true,
      };
      const second = {
        review_type: "opencodex.code-quality", provider: "provider-b", agent_id: "agent:b", session_id: "session:b", context_id: "context:b",
        independence_score: 6, completed: true, [dimension]: first[dimension],
      };
      const result = verifyQuorum({
        required_review_types: [first.review_type, second.review_type], minimum_independent_providers: 2,
        minimum_independence_score: 3, human_approval: "not-required",
      }, [first, second], false);
      expect(result.satisfied).toBeFalse();
      expect(result.reasons).toContain("reviewer-source-independence-missing");
    }
  });

  test("marks every review-validity input mutation stale", () => {
    const baseline = {
      contract_hash: hash("a"), source_tree_hash: hash("b"), diff_hash: hash("c"), evidence_package_hash: hash("d"),
      policy_hash: hash("e"), profile_hashes: [hash("f"), hash("1")], required_evidence_hashes: [hash("2")], dependency_hash: hash("3"),
    };
    const mutations = [
      { contract_hash: hash("4") }, { source_tree_hash: hash("4") }, { diff_hash: hash("4") },
      { evidence_package_hash: hash("4") }, { policy_hash: hash("4") }, { profile_hashes: [hash("4")] },
      { required_evidence_hashes: [hash("4")] }, { dependency_hash: hash("4") },
    ];
    expect(assessReviewValidity(baseline, baseline).status).toBe("CURRENT");
    for (const mutation of mutations) expect(assessReviewValidity(baseline, { ...baseline, ...mutation }).status).toBe("STALE");
  });
});
