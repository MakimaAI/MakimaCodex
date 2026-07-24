import { z } from "zod";
import {
  FINDING_SEVERITIES,
  parseReviewFinding,
  type FindingSeverity,
  type ReviewFinding,
} from "../core/domain";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const namespacedTypeSchema = z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/);
const severityRank: Record<FindingSeverity, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export interface FindingValidationContext {
  snapshot_hash: string;
  contract_revision_id: string;
  files: Array<{ path: string; hash: string; line_count: number }>;
  contract_refs: string[];
  evidence_refs: string[];
}

export interface FindingValidationResult {
  status: "CONFIRMED" | "DISMISSED" | "STALE";
  finding: ReviewFinding;
  validated_by: string[];
  reason?: string;
}

export function validateFinding(
  findingInput: unknown,
  contextInput: FindingValidationContext,
  validatedAt: string,
): FindingValidationResult {
  const finding = parseReviewFinding(findingInput);
  const context = z.object({
    snapshot_hash: hashSchema,
    contract_revision_id: z.string().startsWith("contract-revision:"),
    files: z.array(z.object({ path: z.string().min(1), hash: hashSchema, line_count: z.number().int().nonnegative() }).strict()),
    contract_refs: z.array(z.string()),
    evidence_refs: z.array(z.string()),
  }).strict().parse(contextInput);

  if (finding.scope.snapshot_hash !== context.snapshot_hash || finding.scope.contract_revision_id !== context.contract_revision_id) {
    return {
      status: "STALE",
      finding: parseReviewFinding({ ...finding, status: "STALE", updated_at: validatedAt }),
      validated_by: ["snapshot"],
      reason: "snapshot-mismatch",
    };
  }
  if (finding.evidence_strength === "UNSUPPORTED") {
    return {
      status: "DISMISSED",
      finding: parseReviewFinding({ ...finding, status: "DISMISSED", updated_at: validatedAt }),
      validated_by: ["snapshot"],
      reason: "unsupported-finding",
    };
  }

  for (const anchor of finding.anchors) {
    const file = context.files.find(candidate => candidate.path === anchor.path);
    if (!file || file.hash !== anchor.file_hash || anchor.line_end > file.line_count) {
      return {
        status: "STALE",
        finding: parseReviewFinding({ ...finding, status: "STALE", updated_at: validatedAt }),
        validated_by: ["snapshot"],
        reason: "anchor-mismatch",
      };
    }
  }
  if (finding.contract_refs.some(reference => !context.contract_refs.includes(reference))) {
    return {
      status: "DISMISSED",
      finding: parseReviewFinding({ ...finding, status: "DISMISSED", updated_at: validatedAt }),
      validated_by: ["snapshot", "anchor"],
      reason: "unknown-contract-reference",
    };
  }
  if (finding.evidence_refs.some(reference => !context.evidence_refs.includes(reference))) {
    return {
      status: "DISMISSED",
      finding: parseReviewFinding({ ...finding, status: "DISMISSED", updated_at: validatedAt }),
      validated_by: ["snapshot", "anchor", "contract"],
      reason: "unknown-evidence-reference",
    };
  }
  const effectiveSeverity = applySeverityPolicy(finding);
  return {
    status: "CONFIRMED",
    finding: parseReviewFinding({
      ...finding,
      status: "CONFIRMED",
      effective_severity: effectiveSeverity,
      updated_at: validatedAt,
    }),
    validated_by: ["snapshot", "anchor", "contract", "evidence"],
  };
}

function applySeverityPolicy(finding: ReviewFinding): FindingSeverity {
  if (finding.evidence_strength === "OPINION" && severityRank[finding.proposed_severity] > severityRank.MEDIUM) return "MEDIUM";
  if (finding.evidence_strength === "SUPPORTED" && finding.proposed_severity === "CRITICAL") return "HIGH";
  return finding.proposed_severity;
}

export interface FindingGroup {
  finding_group_id: string;
  canonical_finding_id: string;
  members: ReviewFinding[];
}

export function deduplicateFindings(findingsInput: readonly ReviewFinding[]): FindingGroup[] {
  const findings = findingsInput.map(parseReviewFinding).sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  const groups = new Map<string, ReviewFinding[]>();
  for (const finding of findings) {
    const anchors = finding.anchors.map(anchor => `${anchor.path}:${anchor.symbol?.type ?? "line"}:${anchor.symbol?.name ?? `${anchor.line_start}-${anchor.line_end}`}`).sort();
    const key = JSON.stringify([
      finding.category,
      normalizeFindingText(finding.claim),
      normalizeFindingText(finding.impact),
      [...finding.contract_refs].sort(),
      anchors,
      [...finding.evidence_refs].sort(),
    ]);
    const group = groups.get(key) ?? [];
    group.push(finding);
    groups.set(key, group);
  }
  return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right)).map(([, rawMembers]) => {
    const members = [...rawMembers].sort((left, right) => {
      const severity = severityRank[right.effective_severity ?? right.proposed_severity]
        - severityRank[left.effective_severity ?? left.proposed_severity];
      return severity || left.finding_id.localeCompare(right.finding_id);
    });
    return {
      finding_group_id: `finding-group:${stableSlug(members[0]!.finding_key)}`,
      canonical_finding_id: members[0]!.finding_id,
      members,
    };
  });
}

function stableSlug(value: string): string { return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, ""); }
function normalizeFindingText(value: string): string { return value.trim().toLowerCase().replace(/\s+/g, " "); }

export interface IndependenceFactors {
  different_session: boolean;
  different_prompt_profile: boolean;
  different_runtime: boolean;
  different_model: boolean;
  different_provider: boolean;
  different_tool_pipeline: boolean;
}

export function computeIndependenceScore(factors: IndependenceFactors): number {
  return Number(factors.different_session)
    + Number(factors.different_prompt_profile)
    + Number(factors.different_runtime)
    + Number(factors.different_model) * 2
    + Number(factors.different_provider) * 3
    + Number(factors.different_tool_pipeline);
}

export interface SemanticQuorum {
  required_review_types: string[];
  minimum_independent_providers: number;
  minimum_independence_score: number;
  human_approval: "not-required" | "required";
}

export interface CompletedReviewer {
  review_type: string;
  provider: string;
  agent_id: string;
  session_id: string;
  context_id: string;
  independence_score: number;
  completed: boolean;
}

export function verifyQuorum(quorumInput: SemanticQuorum, reviewersInput: CompletedReviewer[], humanApproved: boolean): { satisfied: boolean; reasons: string[] } {
  const quorum = z.object({
    required_review_types: z.array(namespacedTypeSchema).min(1),
    minimum_independent_providers: z.number().int().positive(),
    minimum_independence_score: z.number().int().nonnegative().max(9),
    human_approval: z.enum(["not-required", "required"]),
  }).strict().parse(quorumInput);
  const reviewers = z.array(z.object({
    review_type: namespacedTypeSchema,
    provider: z.string().trim().min(1),
    agent_id: z.string().startsWith("agent:"),
    session_id: z.string().startsWith("session:"),
    context_id: z.string().startsWith("context:"),
    independence_score: z.number().int().nonnegative().max(9),
    completed: z.boolean(),
  }).strict()).parse(reviewersInput).filter(reviewer => reviewer.completed);
  const reasons: string[] = [];
  const completedTypes = new Set(reviewers.map(reviewer => reviewer.review_type));
  if (quorum.required_review_types.some(type => !completedTypes.has(type))) reasons.push("required-review-missing");
  if (new Set(reviewers.map(reviewer => reviewer.provider)).size < quorum.minimum_independent_providers) reasons.push("independent-provider-quorum-missing");
  if (new Set(reviewers.map(reviewer => reviewer.agent_id)).size !== reviewers.length
    || new Set(reviewers.map(reviewer => reviewer.session_id)).size !== reviewers.length
    || new Set(reviewers.map(reviewer => reviewer.context_id)).size !== reviewers.length) reasons.push("reviewer-source-independence-missing");
  if (reviewers.some(reviewer => reviewer.independence_score < quorum.minimum_independence_score)) reasons.push("independence-score-too-low");
  if (quorum.human_approval === "required" && !humanApproved) reasons.push("human-approval-missing");
  return { satisfied: reasons.length === 0, reasons };
}

export const REVIEW_DECISIONS = ["PASS", "PASS_WITH_NOTES", "CHANGES_REQUESTED", "BLOCKED", "NEEDS_HUMAN", "INCONCLUSIVE", "CANCELLED", "SUPERSEDED"] as const;
export type ReviewDecision = typeof REVIEW_DECISIONS[number];

export interface AdjudicationInput {
  mechanical_verification_passed: boolean;
  required_review_types: string[];
  completed_review_types: string[];
  confirmed_findings: ReviewFinding[];
  unresolved_disagreement: boolean;
  human_approval_required: boolean;
  human_approved: boolean;
}

export function adjudicateReview(input: AdjudicationInput): { decision: ReviewDecision; reason_codes: string[] } {
  const required = [...new Set(input.required_review_types)].sort();
  const completed = new Set(input.completed_review_types);
  if (!input.mechanical_verification_passed) return { decision: "INCONCLUSIVE", reason_codes: ["mechanical-verification-failed"] };
  if (required.some(type => !completed.has(type))) return { decision: "INCONCLUSIVE", reason_codes: ["required-review-missing"] };
  if (input.unresolved_disagreement) return { decision: "NEEDS_HUMAN", reason_codes: ["reviewer-disagreement"] };

  const findings = input.confirmed_findings.map(parseReviewFinding).filter(finding => finding.status === "CONFIRMED");
  if (findings.some(finding => finding.evidence_strength === "UNSUPPORTED")) throw new Error("UNSUPPORTED_FINDING_CANNOT_BLOCK");
  if (findings.some(finding => finding.effective_severity === "CRITICAL")) return { decision: "BLOCKED", reason_codes: ["confirmed-critical-finding"] };
  if (input.human_approval_required && !input.human_approved) return { decision: "NEEDS_HUMAN", reason_codes: ["human-approval-missing"] };
  if (findings.some(finding => ["HIGH", "MEDIUM"].includes(finding.effective_severity ?? ""))) {
    return { decision: "CHANGES_REQUESTED", reason_codes: ["confirmed-repairable-finding"] };
  }
  if (findings.length > 0) return { decision: "PASS_WITH_NOTES", reason_codes: ["nonblocking-findings"] };
  return { decision: "PASS", reason_codes: [] };
}

export type Phase1ReviewVerdict = "ACCEPT" | "ACCEPT_WITH_NOTES" | "REPAIR" | "BLOCK" | "NEEDS_HUMAN" | "REDISPATCH";
export function mapReviewDecisionToPhase1(decision: ReviewDecision): Phase1ReviewVerdict {
  const mapping: Record<ReviewDecision, Phase1ReviewVerdict> = {
    PASS: "ACCEPT",
    PASS_WITH_NOTES: "ACCEPT_WITH_NOTES",
    CHANGES_REQUESTED: "REPAIR",
    BLOCKED: "BLOCK",
    NEEDS_HUMAN: "NEEDS_HUMAN",
    INCONCLUSIVE: "REDISPATCH",
    CANCELLED: "REDISPATCH",
    SUPERSEDED: "REDISPATCH",
  };
  return mapping[decision];
}

export const repairProposalSchema = z.object({
  schema_version: z.literal(1),
  repair_proposal_id: z.string().startsWith("repair-proposal:"),
  task_id: z.string().startsWith("task:"),
  source_review_plan_id: z.string().startsWith("review-plan:"),
  target_findings: z.array(z.string().startsWith("review-finding:")).min(1),
  objective: z.string().trim().min(1),
  scope: z.object({ allowed_paths: z.array(z.string().trim().min(1)).min(1) }).strict(),
  constraints: z.array(z.string().trim().min(1)),
  required_evidence: z.array(z.string().trim().min(1)),
  created_at: z.string().datetime(),
}).strict();
export type RepairProposal = z.infer<typeof repairProposalSchema>;

export function createRepairProposal(input: {
  repair_proposal_id: string;
  task_id: string;
  source_review_plan_id: string;
  findings: ReviewFinding[];
  constraints: string[];
  required_evidence: string[];
  created_at: string;
}): RepairProposal {
  const findings = input.findings.map(parseReviewFinding);
  if (findings.length === 0 || findings.some(finding => finding.status !== "CONFIRMED")) throw new Error("REPAIR_REQUIRES_CONFIRMED_FINDINGS");
  const ordered = [...findings].sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  return repairProposalSchema.parse({
    schema_version: 1,
    repair_proposal_id: input.repair_proposal_id,
    task_id: input.task_id,
    source_review_plan_id: input.source_review_plan_id,
    target_findings: ordered.map(finding => finding.finding_id),
    objective: ordered.map(finding => `${finding.claim} ${finding.impact}`).join("\n"),
    scope: { allowed_paths: [...new Set(ordered.flatMap(finding => finding.anchors.map(anchor => anchor.path)))].sort() },
    constraints: [...new Set(input.constraints)],
    required_evidence: [...new Set(input.required_evidence)],
    created_at: input.created_at,
  });
}

export function determineDeltaReviewTypes(input: { changed_files: string[]; risk_level: "low" | "medium" | "high" | "critical"; public_api_changed: boolean }): string[] {
  const types = new Set<string>(["opencodex.code-quality"]);
  const paths = input.changed_files.map(path => path.toLowerCase().replaceAll("\\", "/"));
  const onlyTests = paths.length > 0 && paths.every(path => /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\./.test(path));
  const onlyPresentation = paths.length > 0 && paths.every(path => /\.(css|scss|sass|less)$/.test(path));
  if (!onlyTests && !onlyPresentation) types.add("opencodex.spec-compliance");
  if (paths.some(path => /(auth|credential|secret|security|provider)/.test(path)) || ["high", "critical"].includes(input.risk_level)) types.add("opencodex.security");
  if (input.public_api_changed || paths.some(path => /(^|\/)(api|public)(\/|$)/.test(path))) types.add("opencodex.backward-compatibility");
  if (paths.some(path => /\.(css|scss|sass|less)$|(^|\/)(ui|frontend|components)(\/|$)/.test(path))) {
    types.add("opencodex.visual");
    types.add("opencodex.accessibility");
  }
  const order = [
    "opencodex.spec-compliance", "opencodex.code-quality", "opencodex.security",
    "opencodex.backward-compatibility", "opencodex.visual", "opencodex.accessibility",
  ];
  return order.filter(type => types.has(type));
}

export function assertResolutionVerified(input: {
  previous_finding: ReviewFinding;
  new_snapshot_hash: string;
  changed_anchor_paths: string[];
  regression_evidence_passed: boolean;
  reproduction_no_longer_fails: boolean;
  independently_validated: boolean;
}): true {
  const finding = parseReviewFinding(input.previous_finding);
  if (finding.status !== "RESOLVED") throw new Error("FINDING_NOT_RESOLVED");
  if (input.new_snapshot_hash === finding.scope.snapshot_hash) throw new Error("RESOLUTION_REQUIRES_NEW_SNAPSHOT");
  if (!finding.anchors.some(anchor => input.changed_anchor_paths.includes(anchor.path))) throw new Error("RESOLUTION_ANCHOR_UNCHANGED");
  if (!input.regression_evidence_passed) throw new Error("RESOLUTION_REGRESSION_EVIDENCE_MISSING");
  if (!input.reproduction_no_longer_fails) throw new Error("RESOLUTION_REPRODUCTION_STILL_FAILS");
  if (!input.independently_validated) throw new Error("RESOLUTION_INDEPENDENT_VALIDATION_MISSING");
  return true;
}

export interface ReviewValidityInputs {
  contract_hash: string;
  source_tree_hash: string;
  diff_hash: string;
  evidence_package_hash: string;
  policy_hash: string;
  profile_hashes: string[];
  required_evidence_hashes: string[];
  dependency_hash: string;
}

export const reviewValidityInputsSchema = z.object({
  contract_hash: hashSchema,
  source_tree_hash: hashSchema,
  diff_hash: hashSchema,
  evidence_package_hash: hashSchema,
  policy_hash: hashSchema,
  profile_hashes: z.array(hashSchema),
  required_evidence_hashes: z.array(hashSchema),
  dependency_hash: hashSchema,
}).strict();

export function assessReviewValidity(expectedInput: ReviewValidityInputs, currentInput: ReviewValidityInputs): { status: "CURRENT" | "STALE"; reasons: string[] } {
  const expected = reviewValidityInputsSchema.parse(expectedInput);
  const current = reviewValidityInputsSchema.parse(currentInput);
  const comparisons: Array<[keyof ReviewValidityInputs, string]> = [
    ["contract_hash", "contract-changed"],
    ["source_tree_hash", "source-tree-changed"],
    ["diff_hash", "diff-changed"],
    ["evidence_package_hash", "evidence-package-changed"],
    ["policy_hash", "policy-changed"],
    ["profile_hashes", "profile-changed"],
    ["required_evidence_hashes", "required-evidence-changed"],
    ["dependency_hash", "dependency-changed"],
  ];
  const reasons = comparisons.filter(([key]) => JSON.stringify(expected[key]) !== JSON.stringify(current[key])).map(([, reason]) => reason);
  return reasons.length === 0 ? { status: "CURRENT", reasons } : { status: "STALE", reasons };
}

export { FINDING_SEVERITIES };
