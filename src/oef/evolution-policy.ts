import { z } from "zod";
import { parseAgentId, type AgentId } from "./identity";
import { isApprovalReference, isHumanId, isRollbackReference, isServiceId } from "./references";

export const EVOLUTION_ZONES = ["candidate-worktree", "benchmark", "canary", "production-core"] as const;
export const EVOLUTION_ARTIFACT_KINDS = [
  "skill",
  "prompt",
  "routing-policy",
  "memory-policy",
  "control-kernel",
] as const;

export type EvolutionZone = typeof EVOLUTION_ZONES[number];

const agentIdSchema = z.custom<AgentId>(value => {
  try {
    parseAgentId(value);
    return true;
  } catch {
    return false;
  }
});

export const evolutionChangeRequestSchema = z.object({
  actor: z.discriminatedUnion("kind", [
    z.object({ kind: z.literal("agent"), id: agentIdSchema }).strict(),
    z.object({ kind: z.literal("human"), id: z.string().refine(isHumanId) }).strict(),
    z.object({ kind: z.literal("promotion-service"), id: z.string().refine(isServiceId) }).strict(),
  ]),
  sourceZone: z.enum(EVOLUTION_ZONES),
  targetZone: z.enum(EVOLUTION_ZONES),
  artifactKind: z.enum(EVOLUTION_ARTIFACT_KINDS),
  gates: z.object({
    benchmarkPassed: z.boolean(),
    securityPassed: z.boolean(),
    holdoutPassed: z.boolean(),
    humanApprovalId: z.string().refine(isApprovalReference).optional(),
    rollbackPoint: z.string().refine(isRollbackReference).optional(),
  }).strict(),
}).strict();

export type EvolutionChangeRequest = z.infer<typeof evolutionChangeRequestSchema>;

export type EvolutionDecision =
  | {
      allowed: true;
      reason: "candidate-contained" | "evaluation-transition" | "canary-admission" | "gated-promotion";
    }
  | {
      allowed: false;
      reason:
        | "invalid-request"
        | "invalid-transition"
        | "agent-cannot-modify-production-core"
        | "agent-transition-forbidden"
        | "promotion-service-required"
        | "promotion-source-must-be-canary"
        | "promotion-gates-incomplete";
    };

export const OEF_CONSTITUTION = Object.freeze({
  deterministicControlKernel: true,
  liveCoreSelfModification: false,
  secretsInMemory: false,
  evidenceBeforeAcceptance: true,
  humanGateForCorePromotion: true,
});

function validApprovalReference(value: string | undefined): boolean {
  return isApprovalReference(value);
}

function validRollbackReference(value: string | undefined): boolean {
  return isRollbackReference(value);
}

export function decideEvolutionChange(requestInput: unknown): EvolutionDecision {
  const result = evolutionChangeRequestSchema.safeParse(requestInput);
  if (!result.success) return { allowed: false, reason: "invalid-request" };
  const request = result.data;

  if (request.actor.kind === "agent") {
    if (request.targetZone === "production-core") {
      return { allowed: false, reason: "agent-cannot-modify-production-core" };
    }
    if (
      request.sourceZone === "candidate-worktree"
      && request.targetZone === "candidate-worktree"
    ) {
      return { allowed: true, reason: "candidate-contained" };
    }
    return { allowed: false, reason: "agent-transition-forbidden" };
  }
  if (request.actor.kind !== "promotion-service") {
    return { allowed: false, reason: "promotion-service-required" };
  }
  if (request.sourceZone === "candidate-worktree" && request.targetZone === "benchmark") {
    return { allowed: true, reason: "evaluation-transition" };
  }
  if (request.sourceZone === "benchmark" && request.targetZone === "canary") {
    if (
      !request.gates.benchmarkPassed
      || !request.gates.securityPassed
      || !request.gates.holdoutPassed
      || !validRollbackReference(request.gates.rollbackPoint)
    ) return { allowed: false, reason: "promotion-gates-incomplete" };
    return { allowed: true, reason: "canary-admission" };
  }
  if (request.targetZone === "production-core") {
    if (request.sourceZone !== "canary") {
      return { allowed: false, reason: "promotion-source-must-be-canary" };
    }
    const gates = request.gates;
    if (
      !gates.benchmarkPassed
      || !gates.securityPassed
      || !gates.holdoutPassed
      || !validApprovalReference(gates.humanApprovalId)
      || !validRollbackReference(gates.rollbackPoint)
    ) {
      return { allowed: false, reason: "promotion-gates-incomplete" };
    }
    return { allowed: true, reason: "gated-promotion" };
  }
  return { allowed: false, reason: "invalid-transition" };
}
