import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";
import { createExecutionConfiguration, createModelVersion, type RoleScorecard } from "../src/oef/phase4";
import {
  Phase4CandidateProvider,
  InMemoryBudgetAuthority,
  RoutingKernel,
  SqliteBudgetAuthority,
  SqliteRoutingStore,
  compileTaskFingerprint,
  composeTeam,
  createBuiltinRoleCatalog,
  createDefaultRoutingPolicy,
  replayRoutingDecision,
  runPhase5AcceptanceDemo,
  transitionRoutingPlan,
} from "../src/oef/phase5";

const now = "2026-07-24T10:00:00.000Z";

function scorecard(role: string, configId: string, status: RoleScorecard["lifecycle"]["status"] = "valid", configHash = `sha256:${"2".repeat(64)}`): RoleScorecard {
  const base = {
    schema_version: 1 as const, scorecard_id: `role-scorecard:${role}-${configId.replace("execution-config:", "")}`, version: 1,
    role_profile_ref: { id: role, version: "1.0.0", hash: `sha256:${"1".repeat(64)}` },
    execution_config_ref: { id: configId, hash: configHash },
    benchmark_ref: { id: "benchmark-suite:test", version: "1.0.0", hash: `sha256:${"3".repeat(64)}` },
    dimensions: { quality: 0.88, task_similarity: 0.8, repository_affinity: 0.75 }, utility: 0.84,
    reliability: { timeout_rate: 0.02, structured_output_rate: 0.96, tool_protocol_rate: 0.95 },
    operations: { mean_cost_units: 10, mean_latency_ms: 800 }, sample: { tasks: 30, attempts: 60 },
    confidence: { level: "high" as const, interval_95: { lower: 0.78, upper: 0.92 }, standard_deviation: 0.06 },
    qualification_level: "Q4" as const,
    lifecycle: { status, valid_from: now, valid_until: status === "expired" ? "2026-07-23T10:00:00.000Z" : "2026-07-25T10:00:00.000Z", reason: null },
    capability_observation_hashes: { "structured-output": `sha256:${"4".repeat(64)}` }, evidence_refs: ["artifact:score"], evaluation_run_id: "evaluation-run:test",
  };
  return { ...base, scorecard_hash: canonicalSha256(base) };
}

describe("Phase 5 integrations", () => {
  test("builds immutable candidates only through the Phase 4 read port", () => {
    const config = createExecutionConfiguration({
      execution_config_id: "execution-config:qualified", model: { version_id: "model-version:qualified", deployment_id: "deployment:qualified" },
      runtime: { id: "runtime:local", adapter_version: "1.0.0" }, prompt_profile: { id: "prompt:default", version: "1.0.0" },
      tool_bundle: { id: "tools:default", version: "1.0.0" }, context_policy: { id: "context:default", version: "1.0.0" },
      generation: { temperature: 0, max_output_tokens: 4_096 }, environment: { class: "unsandboxed", version: "1" },
    });
    const model = createModelVersion({
      model_version_id: "model-version:qualified", family_id: "model-family:qualified", provider_id: "provider:private", provider_model_name: "qualified",
      release: { first_seen_at: now, provider_release_date: now, knowledge_cutoff: null }, modalities: { text_input: true, image_input: false, text_output: true },
      context: { advertised_tokens: 128_000, observed_safe_tokens: 96_000 }, lifecycle_status: "ROLE_QUALIFIED",
      provenance: [{ source_type: "benchmark-result", observed_at: now, content_hash: `sha256:${"5".repeat(64)}` }],
    });
    let writes = 0;
    const adapter = new Phase4CandidateProvider({
      listScorecards: role => role === "backend-implementer" ? [scorecard(role, config.execution_config_id, "valid", config.configuration_hash)] : [],
      getExecutionConfiguration: id => id === config.execution_config_id ? config : null,
      getModelVersion: id => id === model.model_version_id ? model : null,
      listObservations: () => [],
      isConfigurationQuarantined: () => false,
      isConfigurationStale: () => false,
      saveScorecard: () => { writes++; },
    }, {
      availability: () => ({ runtime_healthy: true, provider_healthy: true, account_capacity: 2, observed_at: now, expires_at: "2026-07-24T10:01:00.000Z", account_pool: ["account:private-1"], sandbox_enforced: false }),
      privacyClasses: provider => provider === "provider:private" ? ["public", "internal", "confidential"] : ["public"],
    });

    const candidates = adapter.forRole("backend-implementer");
    expect(candidates).toHaveLength(1);
    expect(candidates[0]).toMatchObject({ provider_id: "provider:private", context_tokens: 96_000, qualification_level: "Q4" });
    expect(candidates[0]?.sandbox_enforced).toBe(false);
    expect(Object.isFrozen(candidates[0])).toBe(true);
    expect(writes).toBe(0);
  });

  test("persists routing state, append-only events, and offline replay across restart", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase5-store-"));
    const db = join(root, "routing.sqlite");
    try {
      const fingerprint = compileTaskFingerprint({ task_id: "task:persist", contract_ref: { revision_id: "contract-revision:persist-r1", hash: `sha256:${"6".repeat(64)}` }, objective: "Küçük backend düzeltmesi", repository: { languages: ["TypeScript"], paths: ["src/a.ts"] } }, { now, revision: 1 });
      const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
      const store = new SqliteRoutingStore({ databasePath: db });
      store.saveTaskFingerprint(fingerprint);
      store.saveTeamPlan(team);
      expect(store.appendEvent({ event_id: "routing-event:one", event_type: "task.fingerprint.created", subject_id: fingerprint.fingerprint_id, payload: { hash: fingerprint.fingerprint_hash }, occurred_at: now })).toBe(true);
      expect(store.appendEvent({ event_id: "routing-event:one", event_type: "task.fingerprint.created", subject_id: fingerprint.fingerprint_id, payload: { hash: fingerprint.fingerprint_hash }, occurred_at: now })).toBe(false);
      const budget = new SqliteBudgetAuthority(store, { poolId: "production", limit: 100 });
      expect(await budget.reserve({ routing_plan_id: "routing-plan:one", amount: 60, idempotency_key: "budget-key-one", now })).toMatchObject({ amount: 60 });
      store.close();

      const reopened = new SqliteRoutingStore({ databasePath: db });
      expect(reopened.getTaskFingerprint(fingerprint.task_id)?.fingerprint_hash).toBe(fingerprint.fingerprint_hash);
      expect(reopened.getTeamPlan(team.team_plan_id)?.team_plan_hash).toBe(team.team_plan_hash);
      expect(reopened.listEvents()).toHaveLength(1);
      const reopenedBudget = new SqliteBudgetAuthority(reopened, { poolId: "production", limit: 100 });
      expect(await reopenedBudget.reserve({ routing_plan_id: "routing-plan:one", amount: 60, idempotency_key: "budget-key-one", now })).toMatchObject({ amount: 60 });
      await expect(reopenedBudget.reserve({ routing_plan_id: "routing-plan:two", amount: 50, idempotency_key: "budget-key-two", now })).rejects.toThrow("BUDGET_RESERVATION_FAILED");
      reopened.close();
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test("replays the same pinned routing decision byte-for-byte after active projection and restart", async () => {
    const fingerprint = compileTaskFingerprint({ task_id: "task:replay", contract_ref: { revision_id: "contract-revision:replay-r1", hash: `sha256:${"7".repeat(64)}` }, objective: "TypeScript backend düzeltmesi", repository: { languages: ["TypeScript"], paths: ["src/a.ts"] } }, { now, revision: 1 });
    const team = composeTeam(fingerprint, createBuiltinRoleCatalog());
    const policy = createDefaultRoutingPolicy("balanced", now);
    const provider = new Phase4CandidateProvider({
      listScorecards: role => {
        const config = createExecutionConfiguration({ execution_config_id: `execution-config:${role}`, model: { version_id: `model-version:${role}`, deployment_id: `deployment:${role}` }, runtime: { id: `runtime:${role}`, adapter_version: "1.0.0" }, prompt_profile: { id: "prompt:default", version: "1.0.0" }, tool_bundle: { id: "tools:default", version: "1.0.0" }, context_policy: { id: "context:default", version: "1.0.0" }, generation: { temperature: 0, max_output_tokens: 4096 }, environment: { class: "sandbox", version: "1" } });
        return [scorecard(role, config.execution_config_id, "valid", config.configuration_hash)];
      },
      getExecutionConfiguration: id => createExecutionConfiguration({ execution_config_id: id, model: { version_id: `model-version:${id.replace("execution-config:", "")}`, deployment_id: `deployment:${id.replace("execution-config:", "")}` }, runtime: { id: `runtime:${id.replace("execution-config:", "")}`, adapter_version: "1.0.0" }, prompt_profile: { id: "prompt:default", version: "1.0.0" }, tool_bundle: { id: "tools:default", version: "1.0.0" }, context_policy: { id: "context:default", version: "1.0.0" }, generation: { temperature: 0, max_output_tokens: 4096 }, environment: { class: "sandbox", version: "1" } }),
      getModelVersion: id => createModelVersion({ model_version_id: id, family_id: `model-family:${id.replace("model-version:", "")}`, provider_id: `provider:${id.replace("model-version:", "")}`, provider_model_name: id, release: { first_seen_at: now, provider_release_date: now, knowledge_cutoff: null }, modalities: { text_input: true, image_input: false, text_output: true }, context: { advertised_tokens: 128_000, observed_safe_tokens: 96_000 }, lifecycle_status: "ROLE_QUALIFIED", provenance: [{ source_type: "benchmark-result", observed_at: now, content_hash: `sha256:${"8".repeat(64)}` }] }),
      listObservations: () => [], isConfigurationQuarantined: () => false, isConfigurationStale: () => false,
    }, { availability: () => ({ runtime_healthy: true, provider_healthy: true, account_capacity: 1, observed_at: now, expires_at: "2026-07-24T10:01:00.000Z", account_pool: ["account:one"], sandbox_enforced: true }), privacyClasses: () => ["public", "internal"] });
    const candidates = team.nodes.flatMap(node => provider.forRole(node.role_id));
    const contextContent = { schema_version: 1 as const, context_id: "routing-context:replay", observed_at: now, expires_at: "2026-07-24T10:01:00.000Z", fingerprint_hash: fingerprint.fingerprint_hash, team_plan_hash: team.team_plan_hash, policy_hash: policy.policy_hash, kill_switch_active: false };
    const context = { ...contextContent, context_hash: canonicalSha256(contextContent) };
    const kernel = new RoutingKernel();
    const recorded = kernel.plan({ fingerprint, team_plan: team, candidates, policy, context, now, seed: 42 });
    const replay = replayRoutingDecision({ recorded, fingerprint, team_plan: team, candidates, policy, context, now, seed: 42, kernel });
    expect(replay.match).toBe(true);
    expect(replay.actual_plan_hash).toBe(recorded.plan_hash);
    const reserved = await kernel.reserveBudget(recorded, new InMemoryBudgetAuthority(500), now); const approved = transitionRoutingPlan(reserved, "APPROVED", now);
    const active = await kernel.activate(approved, { now, context, policy, revalidate: async assignment => ({ runtime_healthy: true, provider_healthy: true, account_capacity: 1, scorecard_valid: true, qualification_valid: true, kill_switch_active: false, account_id: candidates.find(value => value.candidate_id === assignment.candidate_id)!.account_pool[0]! }) });
    const root = mkdtempSync(join(tmpdir(), "phase5-replay-")); const databasePath = join(root, "routing.sqlite");
    try {
      const store = new SqliteRoutingStore({ databasePath }); store.saveRoutingPlan(recorded); store.saveRoutingPlan(active); store.close();
      const reopened = new SqliteRoutingStore({ databasePath }); const decision = reopened.getRoutingPlanDecision(recorded.routing_plan_id)!;
      expect(reopened.getRoutingPlan(recorded.routing_plan_id)?.status).toBe("ACTIVE");
      expect(decision.status).toBe("POLICY_VALIDATED");
      expect(replayRoutingDecision({ recorded: decision, fingerprint, team_plan: team, candidates, policy, context, now, seed: 42 }).match).toBe(true);
      reopened.close();
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

  test("runs the multi-role acceptance demo and writes every required decision artifact", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase5-demo-"));
    try {
      const report = await runPhase5AcceptanceDemo({ root, now: () => now });
      expect(report.status).toBe("PASS");
      expect(report.selected_roles).toEqual(expect.arrayContaining(["internet-researcher", "chief-architect", "backend-implementer", "test-engineer", "security-reviewer"]));
      expect(report.fallback.action).toBe("REBIND");
      for (const name of ["task-fingerprint.yaml", "team-plan.yaml", "candidate-set.json", "hard-filter-report.json", "candidate-score-report.json", "team-optimization-report.json", "routing-plan.yaml", "routing-explanation.md", "fallback-graph.yaml", "binding-set.yaml", "routing-outcome.json", "phase5-acceptance-report.json"]) expect(existsSync(join(root, name))).toBe(true);
    } finally { rmSync(root, { recursive: true, force: true }); }
  });
});
