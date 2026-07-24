import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { createExecutionConfiguration, createModelVersion, type ExecutionConfiguration, type ModelVersion, type RoleScorecard } from "../../phase4";
import { Phase4CandidateProvider, type Phase4CandidateReadPort } from "../adapters/phase4-candidate-provider";
import { InMemoryBudgetAuthority, RoutingKernel } from "../application/routing-kernel";
import { replayRoutingDecision } from "../application/offline-replay";
import {
  applyFallback, compileTaskFingerprint, composeTeam, createBuiltinRoleCatalog, createDefaultRoutingPolicy,
  createExecutionBindings, createHandoffPackage, transitionRoutingPlan, type Candidate,
} from "../core/domain";
import { SqliteRoutingStore } from "../persistence/sqlite-store";

export interface Phase5AcceptanceReport {
  schema_version: 1; status: "PASS" | "FAIL"; task_id: string; fingerprint_hash: string; team_plan_hash: string; routing_plan_hash: string;
  selected_roles: string[]; selected_candidates: string[]; rejected_candidates: number;
  constraints: { quarantined_selected: number; expired_selected: number; reviewer_independence: boolean; budget_reserved: boolean; sticky_binding_versioned: boolean };
  fallback: { action: string; binding_revision: number | null }; replay_match: boolean; routing_policy_mutations: 0; router_secret_reads: 0;
  replay_mismatches: string[];
  offline_calibration_queued: boolean; artifact_hashes: Record<string, string>; report_hash: string;
}

export async function runPhase5AcceptanceDemo(options: { root: string; now?: () => string }): Promise<Phase5AcceptanceReport> {
  const root = resolve(options.root); mkdirSync(root, { recursive: true });
  const now = options.now ?? (() => new Date().toISOString()); const timestamp = now();
  const fingerprint = compileTaskFingerprint({
    task_id: "task:clinepass-phase5", contract_ref: { revision_id: "contract-revision:clinepass-phase5-r1", hash: canonicalSha256("approved-clinepass-contract-r1") },
    objective: "OpenCodex'e ClinePass çoklu hesap ve 403 hata sınıflandırma desteği ekle.",
    acceptance_criteria: ["TypeScript regression testleri geçmeli", "Credential sırları sızmamalı", "403 davranışı resmi kaynakla doğrulanmalı"],
    repository: { languages: ["TypeScript"], paths: ["src/oauth/cline.ts", "src/providers/cline-catalog.ts"], has_frontend: false, has_3d: false },
    metadata: { privacy: "confidential", external_api: true, domains: ["provider-integration", "credential-management"] },
  }, { now: timestamp, revision: 1 });
  const catalog = createBuiltinRoleCatalog();
  const team = composeTeam(fingerprint, catalog, { architect_proposal: { remove_roles: ["security-reviewer"] } });
  const phase4 = createSyntheticPhase4Source(team.nodes.map(value => value.role_id), timestamp);
  const candidateProvider = new Phase4CandidateProvider(phase4.source, {
    availability: ({ configuration }) => ({ runtime_healthy: true, provider_healthy: true, account_capacity: 2, observed_at: timestamp, expires_at: new Date(Date.parse(timestamp) + 60_000).toISOString(), account_pool: [`account:${configuration.execution_config_id.replace("execution-config:", "")}-1`, `account:${configuration.execution_config_id.replace("execution-config:", "")}-2`], sandbox_enforced: true }),
    privacyClasses: () => ["public", "internal", "confidential"],
  });
  const candidates = team.nodes.flatMap(node => candidateProvider.forRole(node.role_id));
  const policy = createDefaultRoutingPolicy("premium", timestamp);
  const contextContent = { schema_version: 1 as const, context_id: "routing-context:clinepass-phase5", observed_at: timestamp, expires_at: new Date(Date.parse(timestamp) + 120_000).toISOString(), fingerprint_hash: fingerprint.fingerprint_hash, team_plan_hash: team.team_plan_hash, policy_hash: policy.policy_hash, kill_switch_active: false };
  const context = { ...contextContent, context_hash: canonicalSha256(contextContent) };
  const kernel = new RoutingKernel();
  const planned = kernel.plan({ fingerprint, team_plan: team, candidates, policy, context, now: timestamp, seed: 142, required_context_tokens: 48_000 });
  const replay = replayRoutingDecision({ recorded: planned, fingerprint, team_plan: team, candidates, policy, context, now: timestamp, seed: 142, kernel });
  const reserved = await kernel.reserveBudget(planned, new InMemoryBudgetAuthority(1_000), timestamp);
  const approved = transitionRoutingPlan(reserved, "APPROVED", timestamp);
  const active = await kernel.activate(approved, { now: timestamp, context, policy, revalidate: async assignment => {
    const candidate = candidates.find(value => value.candidate_id === assignment.candidate_id)!;
    return { runtime_healthy: candidate.availability.runtime_healthy, provider_healthy: candidate.availability.provider_healthy, account_capacity: candidate.availability.account_capacity, scorecard_valid: candidate.lifecycle_status === "valid", qualification_valid: candidate.qualification_level === "Q4" || candidate.qualification_level === "Q5", kill_switch_active: false, account_id: candidate.account_pool[0]! };
  } });
  const bindings = createExecutionBindings(active, timestamp);
  const handoff = createHandoffPackage({
    task_id: fingerprint.task_id, from_role_node_id: "role-node:internet-researcher", to_role_node_id: "role-node:chief-architect",
    claims: [{ statement: "403 davranışı credential, izin veya sağlayıcı politikası olarak doğrulanmadan kota sayılmamalıdır.", trust: "SUPPORTED", evidence_refs: ["artifact:clinepass-403-research"] }],
    open_questions: ["Sağlayıcının 403 yanıt gövdesi hangi hata kodlarını içeriyor?"], created_at: timestamp,
  });
  const fallback = applyFallback({ binding_set: bindings, role_node_id: "role-node:backend-implementer", failure_type: "RUNTIME_UNHEALTHY", candidates, now: timestamp });
  const finalBindings = fallback.binding_set ?? bindings;
  const outcomeBase = {
    schema_version: 1 as const, routing_outcome_id: "routing-outcome:clinepass-phase5", task_id: fingerprint.task_id,
    routing_plan_id: active.routing_plan_id, binding_set_hash: finalBindings.binding_set_hash, status: "ACCEPTED", selection_mode: "deterministic-router",
    role_results: team.nodes.map(node => ({ role_id: node.role_id, status: "COMPLETED", evidence_refs: [`artifact:${node.role_id}-result`] })),
    fallback_count: fallback.binding_set ? 1 : 0, policy_updated_online: false, offline_calibration_status: "QUEUED", recorded_at: timestamp,
  };
  const outcome = { ...outcomeBase, outcome_hash: canonicalSha256(outcomeBase) };
  const store = new SqliteRoutingStore({ databasePath: join(root, "routing.sqlite") });
  try {
    store.transaction(() => {
      store.saveTaskFingerprint(fingerprint); store.saveTeamPlan(team); store.saveRoutingContext(context); store.saveRoutingPolicy(policy); store.saveRoutingPlan(planned); store.saveRoutingPlan(active); store.saveBindingSet(bindings);
      if (fallback.binding_set) store.saveBindingSet(fallback.binding_set); store.saveHandoff(handoff); store.saveOutcome(outcome);
      store.appendEvent({ event_id: "routing-event:phase5-fingerprint", event_type: "task.fingerprint.created", subject_id: fingerprint.fingerprint_id, payload: { fingerprint_hash: fingerprint.fingerprint_hash }, occurred_at: timestamp });
      store.appendEvent({ event_id: "routing-event:phase5-active", event_type: "routing.plan.activated", subject_id: active.routing_plan_id, payload: { plan_hash: active.plan_hash }, occurred_at: timestamp });
      store.appendEvent({ event_id: "routing-event:phase5-fallback", event_type: "fallback.completed", subject_id: active.routing_plan_id, payload: { action: fallback.action, binding_revision: fallback.binding_set?.revision ?? null }, occurred_at: timestamp });
      store.appendEvent({ event_id: "routing-event:phase5-outcome", event_type: "routing.outcome.recorded", subject_id: outcome.routing_outcome_id, payload: { outcome_hash: outcome.outcome_hash }, occurred_at: timestamp });
    });
  } finally { store.close(); }

  const artifacts: Record<string, unknown> = {
    "task-fingerprint.yaml": fingerprint,
    "team-plan.yaml": team,
    "candidate-set.json": { schema_version: 1, candidates, content_hash: canonicalSha256(candidates.map(value => value.candidate_hash)) },
    "hard-filter-report.json": { schema_version: 1, rejected: planned.rejected_candidates, content_hash: canonicalSha256(planned.rejected_candidates) },
    "candidate-score-report.json": { schema_version: 1, assignments: planned.assignments.map(value => ({ role_id: value.role_id, candidate_id: value.candidate_id, score: value.score, explanation: value.explanation })), content_hash: canonicalSha256(planned.assignments) },
    "team-optimization-report.json": { schema_version: 1, team_utility: planned.team_utility, provider_diversity: new Set(planned.assignments.map(value => value.provider_id)).size, cost_estimate: planned.cost_estimate, content_hash: canonicalSha256({ utility: planned.team_utility, assignments: planned.assignments }) },
    "routing-plan.yaml": active,
    "fallback-graph.yaml": fallbackGraph(timestamp),
    "binding-set.yaml": finalBindings,
    "routing-outcome.json": outcome,
  };
  const artifactHashes: Record<string, string> = {};
  for (const [name, value] of Object.entries(artifacts)) { const text = `${JSON.stringify(value, null, 2)}\n`; writeFileSync(join(root, name), text, { encoding: "utf8", mode: 0o600 }); artifactHashes[name] = fileContentHash(text); }
  const explanation = routingExplanation(fingerprint, active, planned.rejected_candidates, fallback);
  writeFileSync(join(root, "routing-explanation.md"), explanation, { encoding: "utf8", mode: 0o600 }); artifactHashes["routing-explanation.md"] = fileContentHash(explanation);
  const implementer = active.assignments.find(value => value.role_id === "backend-implementer");
  const security = active.assignments.find(value => value.role_id === "security-reviewer");
  const selectedIds = new Set(active.assignments.map(value => value.candidate_id));
  const selectedCandidates = candidates.filter(value => selectedIds.has(value.candidate_id));
  const checks = active.status === "ACTIVE" && team.nodes.length === 5 && planned.rejected_candidates.length >= 2 && replay.match
    && Boolean(active.budget_reservation) && implementer?.provider_id !== security?.provider_id && fallback.action === "REBIND" && finalBindings.revision === 2
    && selectedCandidates.every(value => value.lifecycle_status !== "quarantined" && value.lifecycle_status !== "expired");
  const reportBase = {
    schema_version: 1 as const, status: checks ? "PASS" as const : "FAIL" as const, task_id: fingerprint.task_id,
    fingerprint_hash: fingerprint.fingerprint_hash, team_plan_hash: team.team_plan_hash, routing_plan_hash: active.plan_hash,
    selected_roles: active.assignments.map(value => value.role_id), selected_candidates: active.assignments.map(value => value.candidate_id), rejected_candidates: planned.rejected_candidates.length,
    constraints: { quarantined_selected: selectedCandidates.filter(value => value.lifecycle_status === "quarantined").length, expired_selected: selectedCandidates.filter(value => value.lifecycle_status === "expired").length, reviewer_independence: implementer?.provider_id !== security?.provider_id, budget_reserved: Boolean(active.budget_reservation), sticky_binding_versioned: finalBindings.revision === 2 },
    fallback: { action: fallback.action, binding_revision: fallback.binding_set?.revision ?? null }, replay_match: replay.match, replay_mismatches: replay.mismatches,
    routing_policy_mutations: 0 as const, router_secret_reads: 0 as const, offline_calibration_queued: outcome.offline_calibration_status === "QUEUED", artifact_hashes: artifactHashes,
  };
  const report: Phase5AcceptanceReport = { ...reportBase, report_hash: canonicalSha256(reportBase) };
  writeFileSync(join(root, "phase5-acceptance-report.json"), `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return report;
}

function createSyntheticPhase4Source(roles: string[], now: string): { source: Phase4CandidateReadPort } {
  const configurations = new Map<string, ExecutionConfiguration>(); const models = new Map<string, ModelVersion>(); const scorecards: RoleScorecard[] = [];
  const quarantined = new Set<string>();
  const providers: Record<string, string> = { "internet-researcher": "research", "chief-architect": "architecture", "backend-implementer": "coding", "test-engineer": "testing", "security-reviewer": "security" };
  for (const role of roles) add(role, role, providers[role] ?? role, 0.9, "valid", false);
  add("backend-implementer", "backend-alt-runtime", "coding", 0.76, "valid", false, "model-version:backend-implementer");
  add("backend-implementer", "expired", "expired", 0.99, "expired", false);
  add("backend-implementer", "quarantined", "quarantined", 0.99, "valid", true);
  function add(role: string, suffix: string, provider: string, utility: number, status: "valid" | "expired", isQuarantined: boolean, sharedModelId?: string): void {
    const configId = `execution-config:${suffix}`; const modelId = sharedModelId ?? `model-version:${suffix}`;
    const config = createExecutionConfiguration({ execution_config_id: configId, model: { version_id: modelId, deployment_id: `deployment:${suffix}` }, runtime: { id: `runtime:${suffix}`, adapter_version: "1.0.0" }, prompt_profile: { id: `prompt:${role}`, version: "1.0.0" }, tool_bundle: { id: `tools:${role}`, version: "1.0.0" }, context_policy: { id: "context:bounded", version: "1.0.0" }, generation: { temperature: 0, max_output_tokens: 8_192 }, environment: { class: "sandbox-enforced-worktree", version: "1" } });
    configurations.set(configId, config);
    if (!models.has(modelId)) models.set(modelId, createModelVersion({ model_version_id: modelId, family_id: `model-family:${provider}`, provider_id: `provider:${provider}`, provider_model_name: suffix, release: { first_seen_at: now, provider_release_date: now, knowledge_cutoff: null }, modalities: { text_input: true, image_input: false, text_output: true }, context: { advertised_tokens: 128_000, observed_safe_tokens: 96_000 }, lifecycle_status: "ROLE_QUALIFIED", provenance: [{ source_type: "benchmark-result", observed_at: now, content_hash: canonicalSha256({ role, suffix, provider }) }] }));
    const base = { schema_version: 1 as const, scorecard_id: `role-scorecard:${role}-${suffix}`, version: 1, role_profile_ref: { id: role, version: "1.0.0", hash: canonicalSha256(`role:${role}`) }, execution_config_ref: { id: configId, hash: config.configuration_hash }, benchmark_ref: { id: `benchmark-suite:${role}`, version: "1.0.0", hash: canonicalSha256(`suite:${role}`) }, dimensions: { quality: utility, task_similarity: utility * 0.97, repository_affinity: utility * 0.94 }, utility, reliability: { timeout_rate: 0.01, structured_output_rate: 0.98, tool_protocol_rate: 0.98 }, operations: { mean_cost_units: role === "chief-architect" ? 18 : 12, mean_latency_ms: 900 }, sample: { tasks: 40, attempts: 80 }, confidence: { level: "high" as const, interval_95: { lower: Math.max(0, utility - 0.06), upper: Math.min(1, utility + 0.04) }, standard_deviation: 0.04 }, qualification_level: "Q4" as const, lifecycle: { status, valid_from: now, valid_until: status === "expired" ? new Date(Date.parse(now) - 1).toISOString() : new Date(Date.parse(now) + 86_400_000).toISOString(), reason: status === "expired" ? "expired-for-demo" : null }, capability_observation_hashes: {}, evidence_refs: [`artifact:${role}-${suffix}-scorecard`], evaluation_run_id: `evaluation-run:${role}-${suffix}` };
    scorecards.push({ ...base, scorecard_hash: canonicalSha256(base) }); if (isQuarantined) quarantined.add(configId);
  }
  return { source: { listScorecards: role => scorecards.filter(value => !role || value.role_profile_ref.id === role), getExecutionConfiguration: id => configurations.get(id) ?? null, getModelVersion: id => models.get(id) ?? null, listObservations: () => [], isConfigurationQuarantined: id => quarantined.has(id), isConfigurationStale: () => false } };
}

function fallbackGraph(now: string): Record<string, unknown> {
  const content = { schema_version: 1, fallback_graph_id: "fallback-graph:phase5-default", version: "1.0.0", created_at: now, rules: { RATE_LIMIT: ["same-config-new-account", "alternate-deployment", "alternate-candidate", "human-escalation"], AUTHENTICATION_FAILURE: ["quarantine-credential", "block"], PERMISSION_DENIED: ["policy-review", "block"], PROVIDER_5XX: ["bounded-retry", "alternate-deployment", "alternate-candidate"], RUNTIME_UNHEALTHY: ["same-model-alternate-runtime", "alternate-candidate"], CONTEXT_LIMIT: ["shrink-context", "rebuild-context", "alternate-candidate", "decompose"], TOOL_PROTOCOL_FAILURE: ["same-model-alternate-runtime", "alternate-candidate"], VERIFICATION_FAILURE: ["repair"], SECURITY_VIOLATION: ["block"] }, max_hops: 4 };
  return { ...content, fallback_graph_hash: canonicalSha256(content) };
}
function routingExplanation(fingerprint: ReturnType<typeof compileTaskFingerprint>, plan: { assignments: Array<{ role_id: string; candidate_id: string; provider_id: string; score: number; explanation: string[] }>; cost_estimate: { p50: number; p90: number }; budget_reservation: { amount: number } | null }, rejected: Array<{ candidate_id: string; reasons: string[] }>, fallback: { action: string; reason: string }): string {
  return `# Routing explanation\n\nTask: ${fingerprint.objective}\n\nRisk: ${fingerprint.risk.level}; privacy: ${fingerprint.privacy}; uncertainty: ${fingerprint.uncertainty.level}.\n\n## Selected team\n\n${plan.assignments.map((value, index) => `${index + 1}. ${value.role_id}: ${value.candidate_id} (${value.provider_id}, ${value.score.toFixed(4)})\n   - ${value.explanation.join("\n   - ")}`).join("\n")}\n\n## Rejected candidates\n\n${rejected.map(value => `- ${value.candidate_id}: ${value.reasons.join(", ")}`).join("\n")}\n\n## Budget and fallback\n\nEstimated p50 ${plan.cost_estimate.p50}, p90 ${plan.cost_estimate.p90}; reserved ${plan.budget_reservation?.amount ?? 0}.\nFallback result: ${fallback.action} (${fallback.reason}).\n`;
}
function fileContentHash(content: string): string { return `sha256:${createHash("sha256").update(content, "utf8").digest("hex")}`; }
