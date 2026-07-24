import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  buildCandidateSet,
  assertRoutingPlanIntegrity,
  assertTeamPlanDag,
  candidateSchema,
  routingContextSnapshotSchema,
  routingPolicySchema,
  taskFingerprintSchema,
  teamPlanSchema,
  transitionRoutingPlan,
  type Candidate,
  type CandidateSet,
  type RoutingAssignment,
  type RoutingContextSnapshot,
  type RoutingPlan,
  type RoutingPolicy,
  type TaskFingerprint,
  type TeamPlan,
} from "../core/domain";

export interface BudgetAuthority {
  reserve(input: { routing_plan_id: string; amount: number; idempotency_key: string; now: string }): Promise<{ reservation_id: string; amount: number }>;
}

export class InMemoryBudgetAuthority implements BudgetAuthority {
  private remaining: number;
  private readonly reservations = new Map<string, { reservation_id: string; amount: number }>();
  constructor(capacity: number) { this.remaining = capacity; }
  async reserve(input: { routing_plan_id: string; amount: number; idempotency_key: string }): Promise<{ reservation_id: string; amount: number }> {
    const prior = this.reservations.get(input.idempotency_key);
    if (prior) return prior;
    if (input.amount > this.remaining) throw new Error("BUDGET_RESERVATION_FAILED");
    const reservation = { reservation_id: `budget-reservation:${canonicalSha256(input.idempotency_key).slice(7, 27)}`, amount: input.amount };
    this.remaining -= input.amount; this.reservations.set(input.idempotency_key, reservation); return reservation;
  }
}

export class RoutingKernel {
  plan(input: { fingerprint: TaskFingerprint; team_plan: TeamPlan; candidates: Candidate[]; policy: RoutingPolicy; context: RoutingContextSnapshot; now: string; seed: number; required_context_tokens?: number }): RoutingPlan {
    taskFingerprintSchema.parse(input.fingerprint); teamPlanSchema.parse(input.team_plan); routingPolicySchema.parse(input.policy); routingContextSnapshotSchema.parse(input.context);
    assertHash(input.fingerprint, "fingerprint_hash", "TASK_FINGERPRINT_HASH_MISMATCH");
    assertHash(input.team_plan, "team_plan_hash", "TEAM_PLAN_HASH_MISMATCH");
    assertHash(input.policy, "policy_hash", "ROUTING_POLICY_HASH_MISMATCH");
    assertHash(input.context, "context_hash", "ROUTING_CONTEXT_HASH_MISMATCH");
    assertTeamPlanDag(input.team_plan);
    validatePinnedInputs(input);
    const candidates = input.candidates.map(candidate => {
      const parsed = candidateSchema.parse(candidate) as Candidate;
      const { candidate_hash: ignored, ...content } = parsed;
      if (canonicalSha256(content) !== parsed.candidate_hash) throw new Error("CANDIDATE_HASH_MISMATCH");
      return parsed;
    });
    const sets = input.team_plan.nodes.map(node => buildCandidateSet({
      role_id: node.role_id,
      candidates: candidates.filter(value => value.role_id === node.role_id),
      now: input.now,
      task_privacy: input.fingerprint.privacy,
      task_risk: input.fingerprint.risk.level,
      required_capabilities: roleCapabilities(node.role_id, input.fingerprint.required_capabilities),
      required_context_tokens: input.required_context_tokens ?? 32_000,
      required_modalities: roleModalities(node.role_id, input.fingerprint.modalities), required_permissions: rolePermissions(node.role_id),
      require_sandbox: (input.fingerprint.risk.level === "high" || input.fingerprint.risk.level === "critical") && (node.role_id.includes("implementer") || node.role_id === "test-engineer"),
    }));
    const empty = sets.find(set => set.eligible.length === 0);
    if (empty) throw new Error(`HUMAN_ESCALATION:NO_ELIGIBLE_CANDIDATE:${empty.role_id}`);
    const scored = new Map<string, number>();
    for (const set of sets) for (const candidate of set.eligible) scored.set(candidate.candidate_id, scoreCandidate(candidate, input.fingerprint, input.policy));
    const assignments = selectTeam(input.team_plan, sets, scored, input.fingerprint, input.policy);
    const selected = assignments.map(value => candidates.find(candidate => candidate.candidate_id === value.candidate_id)!);
    const costP50 = round(selected.reduce((sum, value) => sum + value.metrics.cost_p50, 0));
    const costP90 = round(selected.reduce((sum, value) => sum + value.metrics.cost_p90, 0));
    const latencyP50 = criticalPathLatency(input.team_plan, selected, "latency_p50_ms");
    const latencyP90 = criticalPathLatency(input.team_plan, selected, "latency_p90_ms");
    const identity = canonicalSha256({ fingerprint: input.fingerprint.fingerprint_hash, team: input.team_plan.team_plan_hash, policy: input.policy.policy_hash, context: input.context.context_hash, candidate_hashes: candidates.map(value => value.candidate_hash).sort(), seed: input.seed });
    const content = {
      schema_version: 1 as const, routing_plan_id: `routing-plan:${identity.slice(7, 27)}`, revision: 1, task_id: input.fingerprint.task_id,
      status: "POLICY_VALIDATED" as const, fingerprint_hash: input.fingerprint.fingerprint_hash, team_plan_hash: input.team_plan.team_plan_hash,
      policy_hash: input.policy.policy_hash, context_hash: input.context.context_hash, seed: input.seed, assignments,
      candidates: [...candidates].sort((a, b) => a.candidate_id.localeCompare(b.candidate_id)), rejected_candidates: sets.flatMap(set => set.rejected),
      routing_constraints: { task_risk: input.fingerprint.risk.level, task_privacy: input.fingerprint.privacy, task_modalities: [...input.fingerprint.modalities], required_capabilities: [...input.fingerprint.required_capabilities], required_context_tokens: input.required_context_tokens ?? 32_000, budget_multiplier: input.policy.limits.budget_multiplier },
      score_basis: input.fingerprint.risk.level === "high" || input.fingerprint.risk.level === "critical" ? "lower-confidence-bound" as const : "mean" as const,
      team_utility: round(assignments.reduce((sum, value) => sum + value.score, 0) - correlationPenalty(assignments, input.policy)),
      cost_estimate: { p50: costP50, p90: costP90 }, latency_estimate: { p50_ms: latencyP50, p90_ms: latencyP90 },
      budget_reservation: null, created_at: input.now, updated_at: input.now,
    };
    return immutable({ ...content, plan_hash: canonicalSha256(content) });
  }

  async reserveBudget(plan: RoutingPlan, authority: BudgetAuthority, now: string): Promise<RoutingPlan> {
    assertRoutingPlanIntegrity(plan);
    if (plan.status !== "POLICY_VALIDATED") throw new Error("ROUTING_PLAN_NOT_POLICY_VALIDATED");
    const amount = Math.ceil(plan.cost_estimate.p90 * plan.routing_constraints.budget_multiplier);
    const reservation = await authority.reserve({ routing_plan_id: plan.routing_plan_id, amount, idempotency_key: canonicalSha256({ plan: plan.plan_hash, amount }), now });
    const withReservation = rehash({ ...plan, budget_reservation: { ...reservation, reserved_at: now }, updated_at: now });
    return transitionRoutingPlan(withReservation, "BUDGET_RESERVED", now);
  }

  async activate(plan: RoutingPlan, input: {
    now: string; context: RoutingContextSnapshot; policy: RoutingPolicy;
    revalidate: (assignment: RoutingAssignment) => Promise<{ runtime_healthy: boolean; provider_healthy: boolean; account_capacity: number; scorecard_valid: boolean; qualification_valid: boolean; kill_switch_active: boolean; account_id: string }>;
  }): Promise<RoutingPlan> {
    assertRoutingPlanIntegrity(plan);
    if (plan.status !== "APPROVED" || !plan.budget_reservation) throw new Error("APPROVED_RESERVED_PLAN_REQUIRED");
    assertHash(input.context, "context_hash", "ROUTING_CONTEXT_HASH_MISMATCH"); assertHash(input.policy, "policy_hash", "ROUTING_POLICY_HASH_MISMATCH");
    if (input.context.context_hash !== plan.context_hash || input.context.policy_hash !== plan.policy_hash || input.policy.policy_hash !== plan.policy_hash) throw new Error("ACTIVATION_PIN_MISMATCH");
    if (input.context.kill_switch_active || Date.parse(input.context.expires_at) <= Date.parse(input.now) || Date.parse(input.policy.valid_from) > Date.parse(input.now) || Date.parse(input.policy.valid_until) <= Date.parse(input.now)) return transitionRoutingPlan(plan, "REBIND_REQUIRED", input.now);
    const results = await Promise.all(plan.assignments.map(async assignment => {
      try { return { assignment, candidate: plan.candidates.find(value => value.candidate_id === assignment.candidate_id), result: await input.revalidate(assignment) }; }
      catch { return { assignment, candidate: plan.candidates.find(value => value.candidate_id === assignment.candidate_id), result: null }; }
    }));
    const failed = results.find(({ candidate, result }) => !candidate || !result || candidate.lifecycle_status !== "valid" || Date.parse(candidate.valid_until) <= Date.parse(input.now)
      || !candidate.availability.runtime_healthy || !candidate.availability.provider_healthy || candidate.availability.account_capacity < 1 || Date.parse(candidate.availability.expires_at) <= Date.parse(input.now)
      || Number(candidate.qualification_level.slice(1)) < (plan.score_basis === "lower-confidence-bound" ? 3 : 2)
      || !result.runtime_healthy || !result.provider_healthy || result.account_capacity < 1 || !result.scorecard_valid || !result.qualification_valid || result.kill_switch_active || !candidate.account_pool.includes(result.account_id));
    if (failed) return transitionRoutingPlan(rehash({ ...plan, updated_at: input.now }), "REBIND_REQUIRED", input.now);
    const accountByRole = new Map(results.map(value => [value.assignment.role_node_id, value.result!.account_id]));
    return transitionRoutingPlan(rehash({ ...plan, assignments: plan.assignments.map(value => ({ ...value, account_id: accountByRole.get(value.role_node_id) ?? null })), updated_at: input.now }), "ACTIVE", input.now);
  }
}

function validatePinnedInputs(input: { fingerprint: TaskFingerprint; team_plan: TeamPlan; policy: RoutingPolicy; context: RoutingContextSnapshot; now: string }): void {
  if (input.context.kill_switch_active) throw new Error("ROUTING_KILL_SWITCH_ACTIVE");
  if (Date.parse(input.context.expires_at) <= Date.parse(input.now)) throw new Error("ROUTING_CONTEXT_EXPIRED");
  if (Date.parse(input.policy.valid_from) > Date.parse(input.now)) throw new Error("ROUTING_POLICY_NOT_YET_VALID");
  if (Date.parse(input.policy.valid_until) <= Date.parse(input.now)) throw new Error("ROUTING_POLICY_EXPIRED");
  if (input.context.fingerprint_hash !== input.fingerprint.fingerprint_hash || input.context.team_plan_hash !== input.team_plan.team_plan_hash || input.context.policy_hash !== input.policy.policy_hash) throw new Error("ROUTING_CONTEXT_PIN_MISMATCH");
  if (input.team_plan.nodes.length > input.policy.limits.max_roles || input.team_plan.max_parallelism > input.policy.limits.max_parallelism) throw new Error("ROUTING_POLICY_TEAM_LIMIT_EXCEEDED");
  if ((input.fingerprint.risk.level === "high" || input.fingerprint.risk.level === "critical") && !input.team_plan.nodes.some(node => node.role_id === "security-reviewer" || node.role_id === "final-reviewer")) throw new Error("INDEPENDENT_REVIEWER_REQUIRED");
}

function roleCapabilities(roleId: string, fingerprintCapabilities: string[]): string[] {
  if (roleId.includes("implementer")) return fingerprintCapabilities.filter(value => value !== "network-access");
  if (roleId === "internet-researcher") return ["network-access", "structured-output"];
  if (roleId === "test-engineer") return ["repository-read", "test-execution"];
  return ["repository-read", "structured-output"];
}
function roleModalities(roleId: string, taskModalities: string[]): string[] { return roleId === "visual-reviewer" || roleId === "spatial-planner" ? taskModalities : ["text"]; }
function rolePermissions(roleId: string): string[] { if (roleId.includes("implementer")) return ["repository-read", "repository-write", "shell"]; if (roleId === "internet-researcher") return ["repository-read", "network-access"]; if (roleId === "test-engineer") return ["repository-read", "repository-write", "shell"]; return ["repository-read"]; }

function scoreCandidate(candidate: Candidate, fingerprint: TaskFingerprint, policy: RoutingPolicy): number {
  const quality = fingerprint.risk.level === "high" || fingerprint.risk.level === "critical" ? candidate.metrics.confidence_lower : candidate.metrics.confidence_mean;
  const reliability = (candidate.metrics.tool_reliability + candidate.metrics.structured_output_reliability + candidate.metrics.operational_reliability) / 3;
  const cost = 1 / (1 + candidate.metrics.cost_p90 / 25);
  const latency = 1 / (1 + candidate.metrics.latency_p90_ms / 2_000);
  const raw = quality * policy.weights.quality + candidate.metrics.task_similarity * policy.weights.task_similarity
    + candidate.metrics.repository_affinity * policy.weights.repository_affinity + reliability * policy.weights.reliability
    + candidate.metrics.availability * policy.weights.availability + cost * policy.weights.cost + latency * policy.weights.latency;
  const penalty = fingerprint.uncertainty.score * policy.penalties.uncertainty + candidate.metrics.incident_penalty * policy.penalties.incident + candidate.metrics.staleness_penalty * policy.penalties.staleness;
  return round(Math.max(0, raw - penalty));
}

function selectTeam(team: TeamPlan, sets: CandidateSet[], scores: Map<string, number>, fingerprint: TaskFingerprint, policy: RoutingPolicy): RoutingAssignment[] {
  const byRole = new Map(sets.map(set => [set.role_id, set]));
  let beams: RoutingAssignment[][] = [[]];
  for (const node of team.nodes) {
    const ranked = [...(byRole.get(node.role_id)?.eligible ?? [])]
      .sort((a, b) => (scores.get(b.candidate_id)! - scores.get(a.candidate_id)!) || a.candidate_id.localeCompare(b.candidate_id))
      .slice(0, policy.limits.top_k_per_role);
    const requiresProviderIndependence = (node.role_id === "security-reviewer" || node.role_id === "final-reviewer") && (fingerprint.risk.level === "high" || fingerprint.risk.level === "critical");
    const expanded: RoutingAssignment[][] = [];
    for (const beam of beams) for (const selected of ranked) {
      const implementer = beam.find(value => value.role_id.endsWith("implementer"));
      if (requiresProviderIndependence && selected.provider_id === implementer?.provider_id) continue;
      expanded.push([...beam, { role_node_id: node.role_node_id, role_id: node.role_id, candidate_id: selected.candidate_id, provider_id: selected.provider_id, execution_config_id: selected.execution_config_id, score: scores.get(selected.candidate_id)!, account_id: null, explanation: [
        `hard constraints passed for ${node.role_id}`,
        `${fingerprint.risk.level === "high" || fingerprint.risk.level === "critical" ? "lower confidence bound" : "mean confidence"} applied`,
        `policy ${policy.policy_id}@${policy.version} score ${scores.get(selected.candidate_id)!.toFixed(4)}`,
        ...(requiresProviderIndependence ? ["provider independence from implementer passed"] : []),
      ] }]);
    }
    beams = expanded.sort((a, b) => beamUtility(b, policy) - beamUtility(a, policy) || beamKey(a).localeCompare(beamKey(b))).slice(0, policy.limits.beam_width);
    if (beams.length === 0) throw new Error(`HUMAN_ESCALATION:SEPARATION_OF_DUTIES:${node.role_id}`);
  }
  const selected = beams[0]!;
  if (fingerprint.risk.level === "high" || fingerprint.risk.level === "critical") {
    const implementers = selected.filter(value => value.role_id.endsWith("implementer")); const reviewers = selected.filter(value => value.role_id === "security-reviewer" || value.role_id === "final-reviewer");
    if (reviewers.some(reviewer => implementers.some(implementer => reviewer.provider_id === implementer.provider_id))) throw new Error("HUMAN_ESCALATION:SEPARATION_OF_DUTIES:provider-correlation");
  }
  return selected;
}

function beamUtility(assignments: RoutingAssignment[], policy: RoutingPolicy): number { return assignments.reduce((sum, value) => sum + value.score, 0) - correlationPenalty(assignments, policy); }
function beamKey(assignments: RoutingAssignment[]): string { return assignments.map(value => value.candidate_id).join("|"); }

function correlationPenalty(assignments: RoutingAssignment[], policy: RoutingPolicy): number {
  const duplicates = assignments.length - new Set(assignments.map(value => value.provider_id)).size;
  return duplicates * policy.penalties.provider_correlation;
}
function criticalPathLatency(team: TeamPlan, selected: Candidate[], key: "latency_p50_ms" | "latency_p90_ms"): number {
  const metric = new Map(team.nodes.map((node, index) => [node.role_id, selected[index]?.metrics[key] ?? 0]));
  const totals = new Map<string, number>();
  for (const node of team.nodes) totals.set(node.role_id, (metric.get(node.role_id) ?? 0) + Math.max(0, ...node.depends_on.map(value => totals.get(value) ?? 0)));
  return Math.round(Math.max(...totals.values()));
}
function round(value: number): number { return Math.round(value * 1_000_000) / 1_000_000; }
function rehash(plan: RoutingPlan): RoutingPlan { const { plan_hash: ignored, ...content } = plan; return { ...content, plan_hash: canonicalSha256(content) }; }
function immutable<T>(value: T): T { if (value && typeof value === "object" && !Object.isFrozen(value)) { for (const child of Object.values(value as Record<string, unknown>)) immutable(child); Object.freeze(value); } return value; }
function assertHash(value: object, hashKey: string, error: string): void { const content = { ...(value as Record<string, unknown>) }; const hash = content[hashKey]; delete content[hashKey]; if (canonicalSha256(content) !== hash) throw new Error(error); }
