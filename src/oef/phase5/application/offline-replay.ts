import type { Candidate, RoutingContextSnapshot, RoutingPlan, RoutingPolicy, TaskFingerprint, TeamPlan } from "../core/domain";
import { RoutingKernel } from "./routing-kernel";

export function replayRoutingDecision(input: {
  recorded: RoutingPlan; fingerprint: TaskFingerprint; team_plan: TeamPlan; candidates: Candidate[]; policy: RoutingPolicy;
  context: RoutingContextSnapshot; now: string; seed: number; kernel?: RoutingKernel;
}): { match: boolean; expected_plan_hash: string; actual_plan_hash: string; mismatches: string[] } {
  if (input.recorded.status !== "POLICY_VALIDATED") throw new Error("POLICY_VALIDATED_DECISION_SNAPSHOT_REQUIRED");
  const actual = (input.kernel ?? new RoutingKernel()).plan({ ...input, required_context_tokens: input.recorded.routing_constraints.required_context_tokens });
  const mismatches = [
    ...(actual.plan_hash === input.recorded.plan_hash ? [] : ["plan_hash"]),
    ...(JSON.stringify(actual.assignments) === JSON.stringify(input.recorded.assignments) ? [] : ["assignments"]),
    ...(actual.context_hash === input.recorded.context_hash ? [] : ["context_hash"]),
  ];
  return { match: mismatches.length === 0, expected_plan_hash: input.recorded.plan_hash, actual_plan_hash: actual.plan_hash, mismatches };
}
