import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalSha256 } from "../oef/phase1/core/contract/task-contract";
import { SqliteModelLabStore } from "../oef/phase4";
import {
  Phase4CandidateProvider, RoutingKernel, SqliteBudgetAuthority, SqliteRoutingStore, buildCandidateSet,
  assertRoutingPlanIntegrity,
  compileTaskFingerprint, composeTeam, createBuiltinRoleCatalog, createDefaultRoutingPolicy, createExecutionBindings,
  runPhase5AcceptanceDemo, taskCompilerInputHash, transitionRoutingPlan, type PrivacyLevel, type RoutingPlan, type TaskFingerprintInput,
} from "../oef/phase5";

interface ParsedArgs { positionals: string[]; options: Map<string, string | true>; json: boolean }
interface AvailabilityRecord { runtime_healthy: boolean; provider_healthy: boolean; account_capacity: number; observed_at: string; expires_at: string; account_pool: string[]; sandbox_enforced: boolean; scorecard_valid: boolean; qualification_valid: boolean; kill_switch_active: boolean }
interface AvailabilityFile { schema_version: 1; configurations: Record<string, AvailabilityRecord>; private_providers: string[] }

export async function cmdOefPhase5(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  try {
    if (group === "oef-phase5-demo") {
      const report = await runPhase5AcceptanceDemo({ root: resolve(required(parsed, "root")) });
      print(report); return report.status === "PASS" ? 0 : 1;
    }
    const home = resolve(option(parsed, "home") ?? join(process.cwd(), ".opencodex", "routing")); mkdirSync(home, { recursive: true });
    const store = new SqliteRoutingStore({ databasePath: join(home, "routing.sqlite") });
    try {
      const value = group === "route" ? await routeCommand(store, parsed, home) : group === "team" ? teamCommand(store, parsed) : fail(`Unknown Phase 5 command group: ${group}`);
      print(value); return 0;
    } finally { store.close(); }
  } catch (error) { console.error(error instanceof Error ? error.message : String(error)); return 1; }
}

async function routeCommand(store: SqliteRoutingStore, parsed: ParsedArgs, home: string): Promise<unknown> {
  const command = parsed.positionals[0] ?? "help";
  if (command === "help") return { commands: ["fingerprint", "candidates", "plan", "show", "explain", "validate", "activate", "fallback", "outcome"], json_supported: true };
  if (command === "fingerprint") {
    const show = parsed.positionals[1] === "show"; const rawTaskId = positional(parsed, show ? 2 : 1, "task id"); const taskId = normalizeTaskId(rawTaskId);
    if (show) return store.getTaskFingerprint(taskId) ?? fail(`Task fingerprint not found: ${taskId}`);
    const previous = store.getTaskFingerprint(taskId); const objective = required(parsed, "objective"); const acceptanceCriteria = splitCsv(option(parsed, "acceptance"));
    const repository = { languages: splitCsv(option(parsed, "languages")), paths: splitCsv(option(parsed, "paths")), has_frontend: optionalFlag(parsed, "frontend"), has_3d: optionalFlag(parsed, "spatial") };
    const metadata = { privacy: privacy(option(parsed, "privacy") ?? "internal"), external_api: optionalFlag(parsed, "external-api"), domains: splitCsv(option(parsed, "domains")) };
    const contractHash = option(parsed, "contract-hash") ?? canonicalSha256({ task_id: taskId, objective, acceptance_criteria: acceptanceCriteria, repository, metadata });
    const nextRevision = (previous?.revision ?? 0) + 1;
    const compilerInput: TaskFingerprintInput = { task_id: taskId, contract_ref: { revision_id: `contract-revision:${stripTask(taskId)}-r${nextRevision}`, hash: contractHash }, objective, acceptance_criteria: acceptanceCriteria, repository, metadata };
    if (previous?.compiler_input_hash === taskCompilerInputHash(compilerInput)) return previous;
    const now = new Date().toISOString();
    const fingerprint = compileTaskFingerprint(compilerInput, { now, revision: nextRevision });
    store.saveTaskFingerprint(fingerprint); store.appendEvent(event("task.fingerprint.created", fingerprint.fingerprint_id, { fingerprint_hash: fingerprint.fingerprint_hash }, now)); return fingerprint;
  }
  if (command === "candidates") {
    const taskId = normalizeTaskId(required(parsed, "task")); const roleId = required(parsed, "role"); const fingerprint = store.getTaskFingerprint(taskId) ?? fail(`Task fingerprint not found: ${taskId}`);
    const candidates = withPhase4Candidates(parsed, home, provider => provider.forRole(roleId));
    return buildCandidateSet({ role_id: roleId, candidates, now: new Date().toISOString(), task_privacy: fingerprint.privacy, task_risk: fingerprint.risk.level, required_capabilities: roleId.includes("implementer") ? fingerprint.required_capabilities.filter(value => value !== "network-access") : ["repository-read", "structured-output"], required_context_tokens: integerOption(parsed, "context-tokens", 32_000) });
  }
  if (command === "plan") {
    const taskId = normalizeTaskId(positional(parsed, 1, "task id")); const fingerprint = store.getTaskFingerprint(taskId) ?? fail(`Task fingerprint not found: ${taskId}`);
    const team = store.getLatestTeamPlanForTask(taskId) ?? composeAndSave(store, fingerprint);
    const policy = createDefaultRoutingPolicy(routingProfile(option(parsed, "profile") ?? "balanced"), new Date().toISOString()); const now = new Date().toISOString();
    const candidates = withPhase4Candidates(parsed, home, provider => team.nodes.flatMap(node => provider.forRole(node.role_id)));
    const contextContent = { schema_version: 1 as const, context_id: `routing-context:${stripTask(taskId)}-${Date.now()}`, observed_at: now, expires_at: new Date(Date.parse(now) + 120_000).toISOString(), fingerprint_hash: fingerprint.fingerprint_hash, team_plan_hash: team.team_plan_hash, policy_hash: policy.policy_hash, kill_switch_active: false };
    const context = { ...contextContent, context_hash: canonicalSha256(contextContent) };
    const plan = new RoutingKernel().plan({ fingerprint, team_plan: team, candidates, policy, context, now, seed: integerOption(parsed, "seed", 142), required_context_tokens: integerOption(parsed, "context-tokens", 32_000) });
    store.saveRoutingContext(context); store.saveRoutingPolicy(policy); store.saveRoutingPlan(plan); store.appendEvent(event("routing.plan.created", plan.routing_plan_id, { plan_hash: plan.plan_hash }, now)); return plan;
  }
  if (command === "show") return store.getRoutingPlan(positional(parsed, 1, "routing plan id")) ?? fail("Routing plan not found");
  if (command === "explain") return explainPlan(store.getRoutingPlan(positional(parsed, 1, "routing plan id")) ?? fail("Routing plan not found"));
  if (command === "validate") {
    const plan = store.getRoutingPlan(positional(parsed, 1, "routing plan id")) ?? fail("Routing plan not found");
    assertRoutingPlanIntegrity(plan);
    const fingerprint = store.getTaskFingerprintByHash(plan.fingerprint_hash); const team = store.getTeamPlanByHash(plan.team_plan_hash); const context = store.getRoutingContextByHash(plan.context_hash); const policy = store.getRoutingPolicyByHash(plan.policy_hash); const now = new Date().toISOString();
    const pinsValid = Boolean(fingerprint && team && context && policy && context.fingerprint_hash === plan.fingerprint_hash && context.team_plan_hash === plan.team_plan_hash && context.policy_hash === plan.policy_hash);
    const explanationsValid = plan.assignments.length > 0 && plan.assignments.every(value => value.explanation.length > 0) && plan.rejected_candidates.every(value => value.reasons.length > 0);
    const eligibleIds = new Set<string>();
    if (fingerprint && team) for (const node of team.nodes) {
      const set = buildCandidateSet({ role_id: node.role_id, candidates: plan.candidates.filter(value => value.role_id === node.role_id), now, task_privacy: fingerprint.privacy, task_risk: fingerprint.risk.level, required_capabilities: node.role_id.includes("implementer") ? fingerprint.required_capabilities.filter(value => value !== "network-access") : node.role_id === "internet-researcher" ? ["network-access", "structured-output"] : node.role_id === "test-engineer" ? ["repository-read", "test-execution"] : ["repository-read", "structured-output"], required_context_tokens: plan.routing_constraints.required_context_tokens, required_modalities: node.role_id === "visual-reviewer" || node.role_id === "spatial-planner" ? fingerprint.modalities : ["text"], required_permissions: node.role_id.includes("implementer") ? ["repository-read", "repository-write", "shell"] : node.role_id === "internet-researcher" ? ["repository-read", "network-access"] : node.role_id === "test-engineer" ? ["repository-read", "repository-write", "shell"] : ["repository-read"], require_sandbox: (fingerprint.risk.level === "high" || fingerprint.risk.level === "critical") && (node.role_id.includes("implementer") || node.role_id === "test-engineer") });
      for (const candidate of set.eligible) eligibleIds.add(candidate.candidate_id);
    }
    const selectionsValid = plan.assignments.every(value => eligibleIds.has(value.candidate_id) && plan.candidates.some(candidate => candidate.candidate_id === value.candidate_id && candidate.role_id === value.role_id && candidate.provider_id === value.provider_id && candidate.execution_config_id === value.execution_config_id));
    const implementers = plan.assignments.filter(value => value.role_id.endsWith("implementer")); const reviewers = plan.assignments.filter(value => value.role_id === "security-reviewer" || value.role_id === "final-reviewer");
    const separationValid = !fingerprint || (fingerprint.risk.level !== "high" && fingerprint.risk.level !== "critical") || (reviewers.length > 0 && reviewers.every(reviewer => implementers.every(implementer => reviewer.provider_id !== implementer.provider_id)));
    const validityValid = Boolean(context && policy && Date.parse(context.expires_at) > Date.parse(now) && Date.parse(policy.valid_from) <= Date.parse(now) && Date.parse(policy.valid_until) > Date.parse(now) && !context.kill_switch_active);
    const valid = pinsValid && explanationsValid && selectionsValid && separationValid && validityValid;
    return { valid, routing_plan_id: plan.routing_plan_id, plan_hash: plan.plan_hash, constraints: { pinned_inputs: pinsValid ? "PASSED" : "FAILED", explanations: explanationsValid ? "PASSED" : "FAILED", hard_filter: selectionsValid ? "PASSED" : "FAILED", reviewer_independence: separationValid ? "PASSED" : "FAILED", freshness: validityValid ? "PASSED" : "FAILED", budget: plan.budget_reservation ? "RESERVED" : "PENDING" } };
  }
  if (command === "activate") {
    let plan = store.getRoutingPlan(positional(parsed, 1, "routing plan id")) ?? fail("Routing plan not found"); const now = new Date().toISOString();
    const kernel = new RoutingKernel();
    const context = store.getRoutingContextByHash(plan.context_hash) ?? fail("Pinned routing context not found");
    const policy = store.getRoutingPolicyByHash(plan.policy_hash) ?? fail("Pinned routing policy not found");
    const availability = loadAvailability(parsed);
    if (plan.status === "POLICY_VALIDATED") plan = await kernel.reserveBudget(plan, new SqliteBudgetAuthority(store, { poolId: option(parsed, "budget-pool") ?? "default", limit: integerOption(parsed, "budget-limit", 0) || fail("Missing required option --budget-limit") }), now);
    if (plan.status === "BUDGET_RESERVED") plan = transitionRoutingPlan(plan, "APPROVED", now);
    plan = await kernel.activate(plan, { now, context, policy, revalidate: async assignment => {
      const candidate = plan.candidates.find(value => value.candidate_id === assignment.candidate_id) ?? fail("Selected candidate not found");
      const current = availability.configurations[candidate.execution_config_id] ?? fail(`Availability missing for ${candidate.execution_config_id}`);
      return { runtime_healthy: current.runtime_healthy && Date.parse(current.expires_at) > Date.parse(now), provider_healthy: current.provider_healthy, account_capacity: current.account_capacity, scorecard_valid: current.scorecard_valid, qualification_valid: current.qualification_valid, kill_switch_active: current.kill_switch_active, account_id: current.account_pool[0] ?? "" };
    } });
    store.saveRoutingPlan(plan); if (plan.status === "ACTIVE") store.saveBindingSet(createExecutionBindings(plan, now));
    store.appendEvent(event(plan.status === "ACTIVE" ? "routing.plan.activated" : "routing.plan.rebind-required", plan.routing_plan_id, { plan_hash: plan.plan_hash }, now)); return plan;
  }
  if (command === "fallback" && parsed.positionals[1] === "show") return fallbackView(store.getRoutingPlan(positional(parsed, 2, "routing plan id")) ?? fail("Routing plan not found"));
  if (command === "outcome") return store.getOutcomeForTask(normalizeTaskId(positional(parsed, 1, "task id"))) ?? fail("Routing outcome not found");
  return fail(`Unknown route command: ${command}`);
}

function teamCommand(store: SqliteRoutingStore, parsed: ParsedArgs): unknown {
  const command = parsed.positionals[0] ?? "help";
  if (command === "help") return { commands: ["compose", "show"], json_supported: true };
  if (command === "show") return store.getTeamPlan(positional(parsed, 1, "team plan id")) ?? fail("Team plan not found");
  if (command === "compose") {
    const taskId = normalizeTaskId(positional(parsed, 1, "task id")); const fingerprint = store.getTaskFingerprint(taskId) ?? fail(`Task fingerprint not found: ${taskId}`);
    return composeAndSave(store, fingerprint);
  }
  return fail(`Unknown team command: ${command}`);
}

function composeAndSave(store: SqliteRoutingStore, fingerprint: NonNullable<ReturnType<SqliteRoutingStore["getTaskFingerprint"]>>) {
  const now = new Date().toISOString(); const team = composeTeam(fingerprint, createBuiltinRoleCatalog()); store.saveTeamPlan(team); store.appendEvent(event("team.plan.created", team.team_plan_id, { team_plan_hash: team.team_plan_hash }, now)); return team;
}
function withPhase4Candidates<T>(parsed: ParsedArgs, home: string, operation: (provider: Phase4CandidateProvider) => T): T {
  const modelLabHome = resolve(option(parsed, "model-lab-home") ?? join(resolve(home, ".."), "model-lab"));
  const availability = loadAvailability(parsed);
  const phase4 = new SqliteModelLabStore({ databasePath: join(modelLabHome, "model-lab.sqlite") });
  try {
    const provider = new Phase4CandidateProvider(phase4, {
      availability: ({ configuration }) => availability.configurations[configuration.execution_config_id] ?? fail(`Availability missing for ${configuration.execution_config_id}`),
      privacyClasses: providerId => availability.private_providers.includes(providerId) ? ["public", "internal", "confidential", "restricted"] : ["public", "internal"],
    });
    return operation(provider);
  } finally { phase4.close(); }
}
function loadAvailability(parsed: ParsedArgs): AvailabilityFile {
  const path = resolve(required(parsed, "availability-file")); let value: unknown;
  try { value = JSON.parse(readFileSync(path, "utf8")); } catch { return fail(`Invalid availability file: ${path}`); }
  if (!value || typeof value !== "object") return fail("Availability file must be an object");
  const input = value as Partial<AvailabilityFile>; if (input.schema_version !== 1 || !input.configurations || !Array.isArray(input.private_providers)) return fail("Availability file schema is invalid");
  for (const [id, record] of Object.entries(input.configurations)) {
    if (!record || typeof record !== "object" || typeof record.runtime_healthy !== "boolean" || typeof record.provider_healthy !== "boolean" || !Number.isInteger(record.account_capacity) || record.account_capacity < 0 || !Array.isArray(record.account_pool) || typeof record.sandbox_enforced !== "boolean" || typeof record.scorecard_valid !== "boolean" || typeof record.qualification_valid !== "boolean" || typeof record.kill_switch_active !== "boolean" || !Number.isFinite(Date.parse(record.observed_at)) || !Number.isFinite(Date.parse(record.expires_at))) return fail(`Invalid availability record: ${id}`);
  }
  return input as AvailabilityFile;
}
function explainPlan(plan: RoutingPlan): unknown { return { routing_plan_id: plan.routing_plan_id, status: plan.status, selected_team: plan.assignments.map(value => ({ role: value.role_id, candidate: value.candidate_id, score: value.score, reason: value.explanation })), rejected: plan.rejected_candidates, budget: { estimated_p50: plan.cost_estimate.p50, estimated_p90: plan.cost_estimate.p90, reserved: plan.budget_reservation?.amount ?? null } }; }
function fallbackView(plan: RoutingPlan): unknown { return { routing_plan_id: plan.routing_plan_id, max_hops: 4, rules: { RATE_LIMIT: ["same-config-new-account", "deployment", "candidate"], AUTHENTICATION_FAILURE: ["quarantine-credential", "BLOCK"], PERMISSION_DENIED: ["policy-review", "BLOCK"], PROVIDER_5XX: ["bounded-retry", "deployment", "candidate"], RUNTIME_UNHEALTHY: ["same-model-alternate-runtime", "candidate"], CONTEXT_LIMIT: ["shrink", "rebuild", "candidate", "decompose"], TOOL_PROTOCOL_FAILURE: ["alternate-runtime", "candidate"], VERIFICATION_FAILURE: ["repair"], SECURITY_VIOLATION: ["BLOCK"] } }; }
function event(type: string, subject: string, payload: Record<string, unknown>, now: string) { return { event_id: `routing-event:${canonicalSha256({ type, subject, payload, now }).slice(7, 31)}`, event_type: type, subject_id: subject, payload, occurred_at: now }; }
function parseArgs(args: string[]): ParsedArgs { const positionals: string[] = []; const options = new Map<string, string | true>(); let json = false; for (let index = 0; index < args.length; index++) { const value = args[index]!; if (value === "--json") { json = true; continue; } if (!value.startsWith("--")) { positionals.push(value); continue; } const key = value.slice(2); const next = args[index + 1]; if (next && !next.startsWith("--")) { options.set(key, next); index++; } else options.set(key, true); } return { positionals, options, json }; }
function option(parsed: ParsedArgs, key: string): string | undefined { const value = parsed.options.get(key); return typeof value === "string" ? value : undefined; }
function flag(parsed: ParsedArgs, key: string): boolean { return parsed.options.get(key) === true || option(parsed, key) === "true"; }
function optionalFlag(parsed: ParsedArgs, key: string): boolean | undefined { return parsed.options.has(key) ? flag(parsed, key) : undefined; }
function required(parsed: ParsedArgs, key: string): string { return option(parsed, key) ?? fail(`Missing required option --${key}`); }
function positional(parsed: ParsedArgs, index: number, label: string): string { return parsed.positionals[index] ?? fail(`Missing ${label}`); }
function integerOption(parsed: ParsedArgs, key: string, fallback: number): number { const raw = option(parsed, key); if (!raw) return fallback; const value = Number(raw); return Number.isInteger(value) && value > 0 ? value : fail(`Invalid integer --${key}`); }
function splitCsv(value?: string): string[] { return value ? value.split(",").map(item => item.trim()).filter(Boolean) : []; }
function normalizeTaskId(value: string): string { return value.startsWith("task:") ? value : `task:${value}`; }
function stripTask(value: string): string { return value.replace(/^task:/, "").replace(/[^A-Za-z0-9._@/-]/g, "-"); }
function privacy(value: string): PrivacyLevel { return value === "public" || value === "internal" || value === "confidential" || value === "restricted" ? value : fail("Privacy must be public, internal, confidential, or restricted"); }
function routingProfile(value: string): "premium" | "balanced" | "economy" | "fast" | "private" { return value === "premium" || value === "balanced" || value === "economy" || value === "fast" || value === "private" ? value : fail("Invalid routing profile"); }
function print(value: unknown): void { console.log(JSON.stringify(value, null, 2)); }
function fail(message: string): never { throw new Error(message); }
