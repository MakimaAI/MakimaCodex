import { z } from "zod";
import { RISK_LEVELS } from "../contract/task-contract";

const namespacedType = z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/i);

const policyRuleSchema = z.object({
  id: z.string().regex(/^[a-z][a-z0-9-]{0,119}$/),
  when: z.object({
    operation: z.enum(["transition", "verdict"]),
    transition_to: z.string().optional(),
    verdict: z.enum(["ACCEPT", "REPAIR", "REDISPATCH", "ESCALATE_MODEL", "ESCALATE_ARCHITECTURE", "NEEDS_HUMAN", "BLOCK"]).optional(),
    risk_levels: z.array(z.enum(RISK_LEVELS)).optional(),
    risk_reasons: z.array(z.string().trim().min(1)).optional(),
  }).strict(),
  require: z.object({
    contract_status: z.enum(["DRAFT", "PROPOSED", "APPROVED", "REJECTED", "SUPERSEDED"]).optional(),
    human_approvals: z.number().int().nonnegative().optional(),
    evidence_types: z.array(namespacedType).optional(),
    all_contract_evidence: z.boolean().optional(),
  }).strict(),
}).strict();

export const policyPackSchema = z.object({
  schema_version: z.literal(1),
  policy_pack_id: z.string().regex(/^[a-z][a-z0-9-]{0,99}$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  rules: z.array(policyRuleSchema).max(512),
}).strict().superRefine((pack, context) => {
  const ids = new Set<string>();
  pack.rules.forEach((rule, index) => {
    if (ids.has(rule.id)) context.addIssue({ code: "custom", path: ["rules", index, "id"], message: "Duplicate rule id" });
    ids.add(rule.id);
    if (rule.when.operation === "transition" && rule.when.verdict) {
      context.addIssue({ code: "custom", path: ["rules", index, "when", "verdict"], message: "Verdict matcher cannot be used for transitions" });
    }
    if (rule.when.operation === "verdict" && rule.when.transition_to) {
      context.addIssue({ code: "custom", path: ["rules", index, "when", "transition_to"], message: "Transition matcher cannot be used for verdicts" });
    }
  });
});

export type PolicyPack = z.infer<typeof policyPackSchema>;

export function parsePolicyPack(input: unknown): PolicyPack {
  return policyPackSchema.parse(input);
}

type PolicyOperation =
  | { kind: "transition"; to: string }
  | { kind: "verdict"; decision: "ACCEPT" | "REPAIR" | "REDISPATCH" | "ESCALATE_MODEL" | "ESCALATE_ARCHITECTURE" | "NEEDS_HUMAN" | "BLOCK" };

export interface PolicyEvaluationInput {
  pack: PolicyPack;
  operation: PolicyOperation;
  task: {
    risk_level: typeof RISK_LEVELS[number];
    risk_reasons: readonly string[];
    contract_status: "DRAFT" | "PROPOSED" | "APPROVED" | "REJECTED" | "SUPERSEDED";
    required_evidence: readonly EvidenceRequirement[];
  };
  human_approval_count: number;
  verified_evidence: readonly EvidenceRequirement[];
}

export interface EvidenceRequirement {
  criterion_key: string;
  evidence_type: string;
}

export type PolicyDecision =
  | { allowed: true; decision: "allowed"; evaluated_policy: { id: string; version: string } }
  | {
      allowed: false;
      decision: "denied";
      denied_by: string[];
      reasons: string[];
      missing_requirements: string[];
      evaluated_policy: { id: string; version: string };
    };

function ruleApplies(rule: PolicyPack["rules"][number], input: PolicyEvaluationInput): boolean {
  if (rule.when.operation !== input.operation.kind) return false;
  if (input.operation.kind === "transition" && rule.when.transition_to && rule.when.transition_to !== input.operation.to) return false;
  if (input.operation.kind === "verdict" && rule.when.verdict && rule.when.verdict !== input.operation.decision) return false;
  if (rule.when.risk_levels && !rule.when.risk_levels.includes(input.task.risk_level)) return false;
  if (rule.when.risk_reasons && !rule.when.risk_reasons.some(reason => input.task.risk_reasons.includes(reason))) return false;
  return true;
}

export function evaluatePolicy(input: PolicyEvaluationInput): PolicyDecision {
  const verifiedTypes = new Set(input.verified_evidence.map(item => item.evidence_type));
  const verifiedRequirements = new Set(input.verified_evidence.map(
    item => `${item.criterion_key}\u0000${item.evidence_type}`,
  ));
  const deniedBy: string[] = [];
  const missing: string[] = [];
  for (const rule of input.pack.rules) {
    if (!ruleApplies(rule, input)) continue;
    const ruleMissing: string[] = [];
    if (rule.require.contract_status && input.task.contract_status !== rule.require.contract_status) {
      ruleMissing.push(`contract.status=${rule.require.contract_status}`);
    }
    if ((rule.require.human_approvals ?? 0) > input.human_approval_count) {
      ruleMissing.push(`human_approvals:${rule.require.human_approvals}`);
    }
    for (const type of rule.require.evidence_types ?? []) {
      if (!verifiedTypes.has(type)) ruleMissing.push(`evidence:${type}`);
    }
    if (rule.require.all_contract_evidence) {
      for (const requirement of input.task.required_evidence) {
        if (!verifiedRequirements.has(`${requirement.criterion_key}\u0000${requirement.evidence_type}`)) {
          ruleMissing.push(`evidence:${requirement.criterion_key}:${requirement.evidence_type}`);
        }
      }
    }
    if (ruleMissing.length > 0) {
      deniedBy.push(rule.id);
      missing.push(...ruleMissing);
    }
  }
  const evaluatedPolicy = { id: input.pack.policy_pack_id, version: input.pack.version };
  if (deniedBy.length === 0) {
    return { allowed: true, decision: "allowed", evaluated_policy: evaluatedPolicy };
  }
  const uniqueMissing = [...new Set(missing)];
  return {
    allowed: false,
    decision: "denied",
    denied_by: deniedBy,
    reasons: deniedBy.map(id => `Policy rule ${id} denied the operation.`),
    missing_requirements: uniqueMissing,
    evaluated_policy: evaluatedPolicy,
  };
}
