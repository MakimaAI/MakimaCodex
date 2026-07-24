import { describe, expect, test } from "bun:test";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";
import {
  InMemoryBudgetAuthority,
  RoutingKernel,
  applyFallback,
  buildCandidateSet,
  compileTaskFingerprint,
  composeTeam,
  createBuiltinRoleCatalog,
  createBuiltinAgentProfiles,
  createBuiltinTeamBlueprints,
  createDefaultRoutingPolicy,
  createExecutionBindings,
  createHandoffPackage,
  rebindExecution,
  resolveReadyRoleNodes,
  transitionRoutingPlan,
  toPhase2ExecutionBinding,
  type Candidate,
  type RoutingContextSnapshot,
  type RoutingPlan,
} from "../src/oef/phase5";

const now = "2026-07-24T10:00:00.000Z";

function fingerprintInput(objective = "OpenCodex'e ClinePass çoklu hesap ve 403 hata sınıflandırma desteği ekle.") {
  return {
    task_id: "task:clinepass",
    contract_ref: { revision_id: "contract-revision:clinepass-r1", hash: `sha256:${"1".repeat(64)}` },
    objective,
    acceptance_criteria: ["TypeScript testleri geçmeli", "credential sırları sızmamalı"],
    repository: { languages: ["TypeScript"], paths: ["src/providers/cline.ts"], has_frontend: false, has_3d: false },
    metadata: { privacy: "confidential" as const, external_api: true },
  };
}

function candidate(overrides: Partial<Candidate> & Pick<Candidate, "candidate_id" | "role_id" | "provider_id">): Candidate {
  const value = {
    schema_version: 1 as const,
    candidate_id: overrides.candidate_id,
    role_id: overrides.role_id,
    agent_profile_id: `agent-profile:${overrides.role_id}`,
    agent_profile_version: "1.0.0",
    agent_profile_hash: `sha256:${"7".repeat(64)}`,
    execution_config_id: `execution-config:${overrides.candidate_id.replace("candidate:", "")}`,
    execution_config_hash: `sha256:${"2".repeat(64)}`,
    scorecard_id: `role-scorecard:${overrides.candidate_id.replace("candidate:", "")}`,
    scorecard_hash: `sha256:${"3".repeat(64)}`,
    provider_id: overrides.provider_id,
    model_version_id: `model-version:${overrides.candidate_id.replace("candidate:", "")}`,
    runtime_id: `runtime:${overrides.candidate_id.replace("candidate:", "")}`,
    runtime_adapter_version: "1.0.0",
    deployment_id: `deployment:${overrides.candidate_id.replace("candidate:", "")}`,
    qualification_level: "Q4" as const,
    lifecycle_status: "valid" as const,
    valid_until: "2026-07-25T10:00:00.000Z",
    capabilities: ["repository-read", "repository-write", "shell", "test-execution", "network-access", "structured-output"],
    modalities: ["text"],
    context_tokens: 128_000,
    permission_envelope: ["repository-read", "repository-write", "shell", "network-access"],
    sandbox_enforced: true,
    privacy_classes: ["public", "internal", "confidential"],
    metrics: {
      role_quality: 0.88,
      task_similarity: 0.84,
      repository_affinity: 0.82,
      tool_reliability: 0.9,
      structured_output_reliability: 0.9,
      operational_reliability: 0.91,
      availability: 0.95,
      confidence_lower: 0.78,
      confidence_mean: 0.88,
      incident_penalty: 0.02,
      staleness_penalty: 0,
      cost_p50: 15,
      cost_p90: 20,
      latency_p50_ms: 900,
      latency_p90_ms: 1_500,
    },
    availability: { runtime_healthy: true, provider_healthy: true, account_capacity: 2, observed_at: now, expires_at: "2026-07-24T10:01:00.000Z" },
    account_pool: [`account:${overrides.provider_id}-1`, `account:${overrides.provider_id}-2`],
    ...overrides,
  };
  const { candidate_hash: ignored, ...content } = value as Candidate;
  return { ...content, candidate_hash: canonicalSha256(content) } as Candidate;
}

function context(fingerprintHash: string, teamHash: string, policyHash: string): RoutingContextSnapshot {
  const content = {
    schema_version: 1,
    context_id: "routing-context:clinepass",
    observed_at: now,
    expires_at: "2026-07-24T10:02:00.000Z",
    fingerprint_hash: fingerprintHash,
    team_plan_hash: teamHash,
    policy_hash: policyHash,
    kill_switch_active: false,
  };
  return { ...content, context_hash: canonicalSha256(content) } as RoutingContextSnapshot;
}

describe("Phase 5 routing core", () => {
  test("compiles deterministic, revisioned fingerprints and rejects low-confidence hard constraints", () => {
    const first = compileTaskFingerprint(fingerprintInput(), { now, revision: 1, semantic_observations: [{ feature_key: "frontend", value: true, confidence: 0.3, source: "semantic-classifier" }] });
    const same = compileTaskFingerprint(fingerprintInput(), { now, revision: 1, semantic_observations: [{ feature_key: "frontend", value: true, confidence: 0.3, source: "semantic-classifier" }] });
    const changed = compileTaskFingerprint(fingerprintInput("OpenCodex'e güvenli ClinePass OAuth desteği ekle."), { now, revision: 2 });

    expect(first.fingerprint_hash).toBe(same.fingerprint_hash);
    expect(first.fingerprint_hash).not.toBe(changed.fingerprint_hash);
    expect(first.risk.level).toBe("high");
    expect(first.uncertainty.level).toBe("high");
    expect(first.signals.languages).toEqual(["typescript"]);
    expect(first.hard_constraints).not.toContain("frontend");
    expect(Object.isFrozen(first)).toBe(true);
  });

  test("composes a bounded role DAG and preserves mandatory independent review", () => {
    const fingerprint = compileTaskFingerprint(fingerprintInput(), { now, revision: 1 });
    const team = composeTeam(fingerprint, createBuiltinRoleCatalog(), {
      architect_proposal: { remove_roles: ["security-reviewer"], add_roles: ["visual-reviewer"] },
    });
    const ids = team.nodes.map(node => node.role_id);

    expect(ids).toContain("internet-researcher");
    expect(ids).toContain("chief-architect");
    expect(ids).toContain("backend-implementer");
    expect(ids).toContain("test-engineer");
    expect(ids).toContain("security-reviewer");
    expect(ids).not.toContain("visual-reviewer");
    expect(team.nodes.find(node => node.role_id === "security-reviewer")?.depends_on).toContain("backend-implementer");
    expect(team.nodes.length).toBeLessThanOrEqual(8);
    expect(team.nodes.every(node => node.status === "WAITING")).toBe(true);
    expect(createBuiltinAgentProfiles().every(profile => !profile.agent_profile_id.includes("model"))).toBe(true);
    expect(createBuiltinTeamBlueprints()[0]?.advisory_roles).toContain("backend-implementer");
  });

  test("hard-filters before scoring and records every rejection", () => {
    const good = candidate({ candidate_id: "candidate:good", role_id: "backend-implementer", provider_id: "provider:private" });
    const quarantined = candidate({ candidate_id: "candidate:quarantined", role_id: "backend-implementer", provider_id: "provider:private", lifecycle_status: "quarantined" });
    const external = candidate({ candidate_id: "candidate:external", role_id: "backend-implementer", provider_id: "provider:external", privacy_classes: ["public"] });
    const stale = candidate({ candidate_id: "candidate:stale", role_id: "backend-implementer", provider_id: "provider:private", availability: { ...good.availability, expires_at: "2026-07-24T09:59:00.000Z" } });
    const unsandboxed = candidate({ candidate_id: "candidate:unsandboxed", role_id: "backend-implementer", provider_id: "provider:private", sandbox_enforced: false });
    const set = buildCandidateSet({ role_id: "backend-implementer", candidates: [good, quarantined, external, stale, unsandboxed], now, task_privacy: "confidential", task_risk: "high", required_capabilities: ["repository-write"], required_context_tokens: 64_000, required_modalities: ["text"], required_permissions: ["repository-write"], require_sandbox: true });

    expect(set.eligible.map(value => value.candidate_id)).toEqual(["candidate:good"]);
    expect(set.rejected).toEqual(expect.arrayContaining([
      expect.objectContaining({ candidate_id: "candidate:quarantined", reasons: expect.arrayContaining(["QUARANTINED"]) }),
      expect.objectContaining({ candidate_id: "candidate:external", reasons: expect.arrayContaining(["PRIVACY_INCOMPATIBLE"]) }),
      expect.objectContaining({ candidate_id: "candidate:stale", reasons: expect.arrayContaining(["AVAILABILITY_EXPIRED"]) }),
      expect.objectContaining({ candidate_id: "candidate:unsandboxed", reasons: expect.arrayContaining(["SANDBOX_ENFORCEMENT_INSUFFICIENT"]) }),
    ]));
  });

  test("uses policy weights and lower confidence bounds for high-risk deterministic routing", () => {
    const fingerprint = compileTaskFingerprint(fingerprintInput(), { now, revision: 1 });
    const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
    const policy = createDefaultRoutingPolicy("premium", now);
    const all = team.nodes.flatMap((node, index) => [
      candidate({ candidate_id: `candidate:${node.role_id}-a`, role_id: node.role_id, provider_id: index % 2 ? "provider:a" : "provider:b" }),
      candidate({ candidate_id: `candidate:${node.role_id}-b`, role_id: node.role_id, provider_id: index % 2 ? "provider:b" : "provider:a", metrics: { ...candidate({ candidate_id: "candidate:template", role_id: node.role_id, provider_id: "provider:x" }).metrics, confidence_mean: 0.94, confidence_lower: 0.61 } }),
    ]);
    const kernel = new RoutingKernel();
    const first = kernel.plan({ fingerprint, team_plan: team, candidates: all, policy, context: context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash), now, seed: 142 });
    const second = kernel.plan({ fingerprint, team_plan: team, candidates: [...all].reverse(), policy, context: context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash), now, seed: 142 });

    expect(first.plan_hash).toBe(second.plan_hash);
    expect(first.status).toBe("POLICY_VALIDATED");
    expect(Object.isFrozen(first.assignments)).toBe(true);
    expect(first.assignments.every(item => item.explanation.length > 0)).toBe(true);
    const implementer = first.assignments.find(item => item.role_id === "backend-implementer")!;
    const reviewer = first.assignments.find(item => item.role_id === "security-reviewer")!;
    expect(implementer.provider_id).not.toBe(reviewer.provider_id);
    expect(first.score_basis).toBe("lower-confidence-bound");
  });

  test("requires reservation, approval, fresh context and activation revalidation", async () => {
    const fingerprint = compileTaskFingerprint(fingerprintInput("Küçük bir TypeScript backend düzeltmesi yap."), { now, revision: 1 });
    const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
    const policy = createDefaultRoutingPolicy("balanced", now);
    const candidates = team.nodes.map((node, index) => candidate({ candidate_id: `candidate:${node.role_id}`, role_id: node.role_id, provider_id: `provider:p${index}` }));
    const kernel = new RoutingKernel();
    const planned = kernel.plan({ fingerprint, team_plan: team, candidates, policy, context: context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash), now, seed: 9 });

    expect(() => transitionRoutingPlan(planned, "ACTIVE", now)).toThrow("INVALID_ROUTING_PLAN_TRANSITION");
    const budget = new InMemoryBudgetAuthority(500);
    await expect(kernel.reserveBudget({ ...planned, cost_estimate: { ...planned.cost_estimate, p90: 1 } }, budget, now)).rejects.toThrow("ROUTING_PLAN_HASH_MISMATCH");
    const reserved = await kernel.reserveBudget(planned, budget, now);
    const approved = transitionRoutingPlan(reserved, "APPROVED", now);
    const activationContext = context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash);
    const active = await kernel.activate(approved, {
      now,
      context: activationContext,
      policy,
      revalidate: async assignment => ({ runtime_healthy: assignment.candidate_id !== "candidate:none", provider_healthy: true, account_capacity: 1, scorecard_valid: true, qualification_valid: true, kill_switch_active: false, account_id: candidates.find(value => value.candidate_id === assignment.candidate_id)!.account_pool[0]! }),
    });
    expect(active.status).toBe("ACTIVE");
    expect(active.assignments.every(value => value.account_id?.startsWith("account:") === true)).toBe(true);
    expect(active.budget_reservation?.amount).toBeGreaterThanOrEqual(active.cost_estimate.p90);
    const activeBindings = createExecutionBindings(active, now);
    const ready = resolveReadyRoleNodes({ team_plan: team, routing_plan: active, binding_set: activeBindings, completed_role_ids: [] });
    expect(ready.every(value => value.depends_on.length === 0 && value.status === "READY")).toBe(true);
    expect(ready.length).toBeLessThanOrEqual(team.max_parallelism);
    const firstCompleted = ready[0]!.role_id;
    const nextReady = resolveReadyRoleNodes({ team_plan: team, routing_plan: active, binding_set: activeBindings, completed_role_ids: [firstCompleted] });
    expect(nextReady.map(value => value.role_id)).not.toContain(firstCompleted);
    expect(nextReady.map(value => value.role_id)).toContain("chief-architect");
    expect(nextReady.every(value => value.depends_on.every(dependency => dependency === firstCompleted))).toBe(true);
    const unpinnedTeamContent = { ...team, nodes: team.nodes.map(node => ({ ...node, depends_on: [] })) }; delete (unpinnedTeamContent as Partial<typeof team>).team_plan_hash;
    const unpinnedTeam = { ...unpinnedTeamContent, team_plan_hash: canonicalSha256(unpinnedTeamContent) } as typeof team;
    expect(() => resolveReadyRoleNodes({ team_plan: unpinnedTeam, routing_plan: active, binding_set: activeBindings, completed_role_ids: [] })).toThrow("TEAM_ROUTING_PLAN_PIN_MISMATCH");
    const invalidAccount = await kernel.activate(approved, { now, context: activationContext, policy, revalidate: async () => ({ runtime_healthy: true, provider_healthy: true, account_capacity: 1, scorecard_valid: true, qualification_valid: true, kill_switch_active: false, account_id: "account:not-in-pool" }) });
    expect(invalidAccount.status).toBe("REBIND_REQUIRED");
  });

  test("creates sticky Phase 2 bindings, versioned fallback rebinds, and safe handoffs", () => {
    const selected = candidate({ candidate_id: "candidate:impl", role_id: "backend-implementer", provider_id: "provider:a" });
    const independentReviewer = candidate({ candidate_id: "candidate:review", role_id: "security-reviewer", provider_id: "provider:b" });
    const planContent: Omit<RoutingPlan, "plan_hash"> = {
      schema_version: 1, routing_plan_id: "routing-plan:test", revision: 1, task_id: "task:test", status: "ACTIVE",
      fingerprint_hash: `sha256:${"1".repeat(64)}`, team_plan_hash: `sha256:${"2".repeat(64)}`, policy_hash: `sha256:${"3".repeat(64)}`, context_hash: `sha256:${"4".repeat(64)}`, seed: 1,
      assignments: [
        { role_node_id: "role-node:impl", role_id: "backend-implementer", candidate_id: selected.candidate_id, provider_id: selected.provider_id, execution_config_id: selected.execution_config_id, score: 0.8, explanation: ["qualified"], account_id: selected.account_pool[0]! },
        { role_node_id: "role-node:review", role_id: "security-reviewer", candidate_id: independentReviewer.candidate_id, provider_id: independentReviewer.provider_id, execution_config_id: independentReviewer.execution_config_id, score: 0.8, explanation: ["independent"], account_id: independentReviewer.account_pool[0]! },
      ],
      candidates: [selected, independentReviewer], rejected_candidates: [], score_basis: "lower-confidence-bound", team_utility: 1.6,
      routing_constraints: { task_risk: "high", task_privacy: "internal", task_modalities: ["text"], required_capabilities: ["repository-write"], required_context_tokens: 32_000, budget_multiplier: 1.1 },
      cost_estimate: { p50: 15, p90: 20 }, latency_estimate: { p50_ms: 900, p90_ms: 1_500 }, budget_reservation: { reservation_id: "budget-reservation:test", amount: 22, reserved_at: now }, created_at: now, updated_at: now,
    };
    const plan: RoutingPlan = { ...planContent, plan_hash: canonicalSha256(planContent) };
    const bindings = createExecutionBindings(plan, now);
    const phase2Binding = toPhase2ExecutionBinding({ binding_set: bindings, role_node_id: "role-node:impl", assignment_id: "assignment:test", assignment_revision: 1, environment_type: "git-worktree", environment_version: 1, created_at: now });
    expect(phase2Binding.assignment_id).toBe("assignment:test");
    expect(phase2Binding.agent_profile_ref).toEqual({ id: selected.agent_profile_id, version: selected.agent_profile_version });
    expect(phase2Binding.runtime_ref.adapter_version).toBe(selected.runtime_adapter_version);
    expect(bindings.bindings[0]?.execution_config_hash).toBe(selected.execution_config_hash);
    expect(() => toPhase2ExecutionBinding({ binding_set: { ...bindings, bindings: bindings.bindings.map((value, index) => index === 0 ? { ...value, account_id: "account:tampered" } : value) }, role_node_id: "role-node:impl", assignment_id: "assignment:test", assignment_revision: 1, environment_type: "git-worktree", environment_version: 1, created_at: now })).toThrow("BINDING_SET_HASH_MISMATCH");
    expect(() => rebindExecution(bindings, "role-node:impl", selected, "BETTER_MODEL_AVAILABLE", now)).toThrow("REBIND_REASON_NOT_ALLOWED");
    expect(() => createExecutionBindings({ ...plan, team_utility: 0.99 }, now)).toThrow("ROUTING_PLAN_HASH_MISMATCH");

    const alternate = candidate({ ...selected, candidate_id: "candidate:impl-alt", execution_config_id: "execution-config:impl-alt", runtime_id: "runtime:alt" });
    const fallback = applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "RUNTIME_UNHEALTHY", candidates: [alternate], now });
    expect(fallback.action).toBe("REBIND");
    expect(fallback.binding_set?.revision).toBe(2);
    expect(fallback.binding_set?.bindings[0]?.attempt).toBe(2);
    const sameRuntime = candidate({ ...selected, candidate_id: "candidate:impl-same-runtime", execution_config_id: "execution-config:impl-same-runtime" });
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "RUNTIME_UNHEALTHY", candidates: [sameRuntime], now }).action).toBe("HUMAN_ESCALATION");

    const rateLimited = applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "RATE_LIMIT", candidates: [selected], now });
    expect(rateLimited.action).toBe("RETRY_NEW_ACCOUNT");
    expect(rateLimited.binding_set?.bindings[0]?.account_id).toBe(selected.account_pool[1]);
    expect(applyFallback({ binding_set: rateLimited.binding_set!, role_node_id: "role-node:impl", failure_type: "RATE_LIMIT", candidates: [selected], now }).action).toBe("HUMAN_ESCALATION");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "AUTHENTICATION_FAILURE", candidates: [], now }).action).toBe("BLOCK");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "PERMISSION_DENIED", candidates: [], now }).action).toBe("BLOCK");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "SECURITY_VIOLATION", candidates: [], now }).action).toBe("BLOCK");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "VERIFICATION_FAILURE", candidates: [], now }).action).toBe("REPAIR");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "CONTEXT_LIMIT", candidates: [], now }).action).toBe("REBUILD_CONTEXT");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "PROVIDER_5XX", candidates: [], now }).action).toBe("HUMAN_ESCALATION");
    const unsafeAlternate = candidate({ ...alternate, candidate_id: "candidate:impl-quarantined", lifecycle_status: "quarantined" });
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:impl", failure_type: "RUNTIME_UNHEALTHY", candidates: [unsafeAlternate], now }).action).toBe("HUMAN_ESCALATION");
    const correlatedReviewer = candidate({ ...independentReviewer, candidate_id: "candidate:review-correlated", provider_id: selected.provider_id });
    expect(() => rebindExecution(bindings, "role-node:review", correlatedReviewer, "PROVIDER_UNAVAILABLE", now)).toThrow("REBIND_SEPARATION_OF_DUTIES_VIOLATION");
    expect(applyFallback({ binding_set: bindings, role_node_id: "role-node:review", failure_type: "PROVIDER_5XX", candidates: [correlatedReviewer], now }).action).toBe("HUMAN_ESCALATION");

    const handoff = createHandoffPackage({ task_id: "task:test", from_role_node_id: "role-node:research", to_role_node_id: "role-node:impl", claims: [{ statement: "403 davranışı belirsiz", trust: "SUPPORTED", evidence_refs: ["artifact:research"] }], open_questions: ["Provider 403 için hangi gövdeyi döndürüyor?"], created_at: now });
    expect(handoff.handoff_hash).toMatch(/^sha256:/);
    expect(() => createHandoffPackage({ task_id: "task:test", from_role_node_id: "role-node:research", to_role_node_id: "role-node:impl", claims: [{ statement: "secret=abc", trust: "UNVERIFIED", evidence_refs: [] }], open_questions: [], created_at: now })).toThrow("HANDOFF_FORBIDDEN_CONTENT");
    expect(() => createHandoffPackage({ task_id: "task:test", from_role_node_id: "role-node:research", to_role_node_id: "role-node:impl", claims: [{ statement: "Authorization: Bearer sk-proj-1234567890abcdef", trust: "UNVERIFIED", evidence_refs: [] }], open_questions: [], created_at: now })).toThrow("HANDOFF_FORBIDDEN_CONTENT");
  });

  test("keeps hard constraints invariant across randomized candidate orderings", () => {
    for (let seed = 1; seed <= 32; seed++) {
      const fingerprint = compileTaskFingerprint(fingerprintInput(), { now, revision: 1 });
      const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
      const policy = createDefaultRoutingPolicy("balanced", now);
      const candidates = team.nodes.flatMap((node, index) => {
        const safe = candidate({ candidate_id: `candidate:${node.role_id}-safe-${seed}`, role_id: node.role_id, provider_id: `provider:safe-${index}` });
        const quarantined = candidate({ candidate_id: `candidate:${node.role_id}-quarantined-${seed}`, role_id: node.role_id, provider_id: "provider:unsafe", lifecycle_status: "quarantined", metrics: { ...safe.metrics, confidence_lower: 0.99, confidence_mean: 0.99 } });
        return seed % 2 ? [quarantined, safe] : [safe, quarantined];
      });
      const plan = new RoutingKernel().plan({ fingerprint, team_plan: team, candidates, policy, context: context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash), now, seed });
      expect(plan.assignments.every(value => !value.candidate_id.includes("quarantined"))).toBe(true);
      expect(plan.assignments).toHaveLength(team.nodes.length);
    }
  });

  test("fails closed for malformed scoring, reviewer removal, kill switch, expiry, and budget exhaustion", async () => {
    const fingerprint = compileTaskFingerprint(fingerprintInput(), { now, revision: 1 });
    const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
    const policy = createDefaultRoutingPolicy("premium", now);
    const candidates = team.nodes.map((node, index) => candidate({ candidate_id: `candidate:${node.role_id}-fault`, role_id: node.role_id, provider_id: `provider:fault-${index}` }));
    const routingContext = context(fingerprint.fingerprint_hash, team.team_plan_hash, policy.policy_hash);
    const kernel = new RoutingKernel();

    const malformed = [...candidates]; malformed[0] = { ...malformed[0]!, metrics: { ...malformed[0]!.metrics, confidence_lower: Number.NaN } };
    expect(() => kernel.plan({ fingerprint, team_plan: team, candidates: malformed, policy, context: routingContext, now, seed: 1 })).toThrow();
    const killedContent = { ...routingContext, kill_switch_active: true }; delete (killedContent as Partial<RoutingContextSnapshot>).context_hash;
    expect(() => kernel.plan({ fingerprint, team_plan: team, candidates, policy, context: { ...killedContent, context_hash: canonicalSha256(killedContent) } as RoutingContextSnapshot, now, seed: 1 })).toThrow("ROUTING_KILL_SWITCH_ACTIVE");
    const unsafeTeamContent = { ...team, nodes: team.nodes.filter(node => node.role_id !== "security-reviewer") }; delete (unsafeTeamContent as Partial<typeof team>).team_plan_hash;
    const unsafeTeam = { ...unsafeTeamContent, team_plan_hash: canonicalSha256(unsafeTeamContent) } as typeof team;
    const unsafeContextContent = { ...routingContext, team_plan_hash: unsafeTeam.team_plan_hash }; delete (unsafeContextContent as Partial<RoutingContextSnapshot>).context_hash;
    expect(() => kernel.plan({ fingerprint, team_plan: unsafeTeam, candidates, policy, context: { ...unsafeContextContent, context_hash: canonicalSha256(unsafeContextContent) } as RoutingContextSnapshot, now, seed: 1 })).toThrow("INDEPENDENT_REVIEWER_REQUIRED");
    const expiredContent = { ...routingContext, expires_at: "2026-07-24T09:59:00.000Z" }; delete (expiredContent as Partial<RoutingContextSnapshot>).context_hash;
    expect(() => kernel.plan({ fingerprint, team_plan: team, candidates, policy, context: { ...expiredContent, context_hash: canonicalSha256(expiredContent) } as RoutingContextSnapshot, now, seed: 1 })).toThrow("ROUTING_CONTEXT_EXPIRED");

    const planned = kernel.plan({ fingerprint, team_plan: team, candidates, policy, context: routingContext, now, seed: 1 });
    await expect(kernel.reserveBudget(planned, new InMemoryBudgetAuthority(1), now)).rejects.toThrow("BUDGET_RESERVATION_FAILED");

    const reorderedContent = { ...team, nodes: [...team.nodes].sort((a, b) => a.role_id === "security-reviewer" ? -1 : b.role_id === "security-reviewer" ? 1 : 0) }; delete (reorderedContent as Partial<typeof team>).team_plan_hash;
    const reordered = { ...reorderedContent, team_plan_hash: canonicalSha256(reorderedContent) } as typeof team;
    const sharedProviderCandidates = reordered.nodes.map(node => candidate({ candidate_id: `candidate:${node.role_id}-shared`, role_id: node.role_id, provider_id: node.role_id === "backend-implementer" || node.role_id === "security-reviewer" ? "provider:shared" : `provider:${node.role_id}` }));
    const reorderedContextContent = { ...routingContext, team_plan_hash: reordered.team_plan_hash }; delete (reorderedContextContent as Partial<RoutingContextSnapshot>).context_hash;
    expect(() => kernel.plan({ fingerprint, team_plan: reordered, candidates: sharedProviderCandidates, policy, context: { ...reorderedContextContent, context_hash: canonicalSha256(reorderedContextContent) } as RoutingContextSnapshot, now, seed: 1 })).toThrow("HUMAN_ESCALATION:SEPARATION_OF_DUTIES");

    const cyclicContent = { ...team, nodes: team.nodes.map(node => node.role_id === "backend-implementer" ? { ...node, depends_on: [node.role_id] } : node) }; delete (cyclicContent as Partial<typeof team>).team_plan_hash;
    const cyclic = { ...cyclicContent, team_plan_hash: canonicalSha256(cyclicContent) } as typeof team;
    const cyclicContextContent = { ...routingContext, team_plan_hash: cyclic.team_plan_hash }; delete (cyclicContextContent as Partial<RoutingContextSnapshot>).context_hash;
    expect(() => kernel.plan({ fingerprint, team_plan: cyclic, candidates, policy, context: { ...cyclicContextContent, context_hash: canonicalSha256(cyclicContextContent) } as RoutingContextSnapshot, now, seed: 1 })).toThrow("TEAM_PLAN_SELF_DEPENDENCY");
  });
});
