import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

export const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const isoDateSchema = z.string().datetime();
const entityId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;
export const PRIVACY_LEVELS = ["public", "internal", "confidential", "restricted"] as const;
export const ROLE_CATEGORIES = ["analysis", "production", "verification", "governance"] as const;
export const TRUST_LEVELS = ["VERIFIED", "SUPPORTED", "UNVERIFIED", "OPEN_QUESTION"] as const;
export const ROUTING_PLAN_STATUSES = [
  "DRAFT", "CANDIDATES_RESOLVED", "OPTIMIZED", "POLICY_VALIDATED", "BUDGET_RESERVED", "APPROVED", "ACTIVE", "COMPLETED",
  "REJECTED", "REBIND_REQUIRED", "SUPERSEDED", "CANCELLED", "EXPIRED",
] as const;
export const ROLE_NODE_STATUSES = ["WAITING", "READY", "BOUND", "RUNNING", "COMPLETED", "FAILED", "BLOCKED", "SKIPPED", "SUPERSEDED"] as const;
export const REBIND_REASONS = [
  "RUNTIME_UNHEALTHY", "PROVIDER_UNAVAILABLE", "RATE_LIMIT", "ACCOUNT_UNAVAILABLE", "CONTEXT_INSUFFICIENT", "TOOL_MISSING",
  "MODEL_BEHAVIOR_FAILURE", "POLICY_CHANGE", "HUMAN_OVERRIDE", "QUALIFICATION_INVALIDATED",
] as const;

export type RiskLevel = typeof RISK_LEVELS[number];
export type PrivacyLevel = typeof PRIVACY_LEVELS[number];
export type RoutingPlanStatus = typeof ROUTING_PLAN_STATUSES[number];
export type RebindReason = typeof REBIND_REASONS[number];

const observationSchema = z.object({
  feature_key: z.string().trim().min(1),
  value: z.unknown(),
  confidence: z.number().min(0).max(1),
  source: z.enum(["kernel-rule", "task-contract", "repository-scan", "human-metadata", "semantic-classifier", "model-proposal"]),
  observed_at: isoDateSchema,
  hard_constraint_eligible: z.boolean(),
}).strict();

const fingerprintContentSchema = z.object({
  schema_version: z.literal(1),
  fingerprint_id: entityId("task-fingerprint"),
  revision: z.number().int().positive(),
  compiler_input_hash: hashSchema,
  task_id: entityId("task"),
  contract_ref: z.object({ revision_id: entityId("contract-revision"), hash: hashSchema }).strict(),
  objective: z.string().trim().min(1).max(20_000),
  task_types: z.array(z.string()).min(1),
  domains: z.array(z.string()),
  signals: z.object({ languages: z.array(z.string()), paths: z.array(z.string()), has_frontend: z.boolean(), has_3d: z.boolean(), external_api: z.boolean(), credential_sensitive: z.boolean() }).strict(),
  required_capabilities: z.array(z.string()),
  modalities: z.array(z.string()),
  freshness: z.enum(["not-required", "recommended", "required"]),
  risk: z.object({ level: z.enum(RISK_LEVELS), reasons: z.array(z.string()) }).strict(),
  privacy: z.enum(PRIVACY_LEVELS),
  complexity: z.object({ level: z.enum(["low", "medium", "high"]), score: z.number().min(0).max(1) }).strict(),
  uncertainty: z.object({ level: z.enum(["low", "medium", "high"]), score: z.number().min(0).max(1), unresolved: z.array(z.string()) }).strict(),
  scope: z.object({ paths: z.array(z.string()), parallelizable: z.boolean() }).strict(),
  observations: z.array(observationSchema),
  hard_constraints: z.array(z.string()),
  compiled_at: isoDateSchema,
}).strict();

export const taskFingerprintSchema = fingerprintContentSchema.extend({ fingerprint_hash: hashSchema }).strict();
export type TaskFingerprint = z.infer<typeof taskFingerprintSchema>;

export interface TaskFingerprintInput {
  task_id: string;
  contract_ref: { revision_id: string; hash: string };
  objective: string;
  acceptance_criteria?: string[];
  repository?: { languages?: string[]; paths?: string[]; has_frontend?: boolean; has_3d?: boolean };
  metadata?: { privacy?: PrivacyLevel; external_api?: boolean; domains?: string[] };
}

export interface SemanticObservationInput {
  feature_key: string;
  value: unknown;
  confidence: number;
  source: "semantic-classifier" | "model-proposal";
}

export function taskCompilerInputHash(input: TaskFingerprintInput, semanticObservations: SemanticObservationInput[] = []): string {
  return canonicalSha256({
    task_id: input.task_id, contract_hash: input.contract_ref.hash, objective: input.objective, acceptance_criteria: input.acceptance_criteria ?? [],
    repository: { languages: input.repository?.languages ?? [], paths: input.repository?.paths ?? [], has_frontend: input.repository?.has_frontend ?? null, has_3d: input.repository?.has_3d ?? null },
    metadata: { privacy: input.metadata?.privacy ?? "internal", external_api: input.metadata?.external_api ?? null, domains: input.metadata?.domains ?? [] },
    semantic_observations: semanticObservations,
  });
}

export function compileTaskFingerprint(input: TaskFingerprintInput, options: { now: string; revision: number; semantic_observations?: SemanticObservationInput[] }): TaskFingerprint {
  const text = `${input.objective}\n${(input.acceptance_criteria ?? []).join("\n")}`.toLocaleLowerCase("tr-TR");
  const languages = unique((input.repository?.languages ?? []).map(value => value.toLowerCase()));
  const paths = unique(input.repository?.paths ?? []);
  const hasFrontend = input.repository?.has_frontend ?? /(frontend|react|css|arayüz|ui\b)/i.test(text);
  const has3d = input.repository?.has_3d ?? /\b(3d|webgl|spatial|three\.js)\b/i.test(text);
  const credentialSensitive = /(credential|secret|oauth|token|api key|hesap|kimlik bilg)/i.test(text);
  const externalApi = input.metadata?.external_api ?? /(external api|provider|oauth|403|429|api\b)/i.test(text);
  const taskTypes = unique([
    ...(hasFrontend ? ["frontend"] : []),
    ...(/(backend|provider|api|oauth|server|hata sınıflandır)/i.test(text) ? ["backend"] : []),
    ...(/(araştır|research|doküman|documentation)/i.test(text) ? ["research"] : []),
    ...(/(test|regression|doğrula)/i.test(text) ? ["verification"] : []),
  ]);
  if (taskTypes.length === 0) taskTypes.push("general-engineering");
  const riskReasons = unique([
    ...(credentialSensitive ? ["credential-sensitive"] : []),
    ...(input.metadata?.privacy === "restricted" ? ["restricted-data"] : []),
    ...(/(production deploy|canlıya al|para transfer|payment)/i.test(text) ? ["high-impact-operation"] : []),
  ]);
  const risk: RiskLevel = riskReasons.includes("high-impact-operation") || riskReasons.includes("restricted-data") ? "critical" : credentialSensitive ? "high" : externalApi ? "medium" : "low";
  const unresolved = unique([
    ...(/\b403\b/.test(text) ? ["provider-403-semantics"] : []),
    ...(/(belirsiz|unknown|tbd)/i.test(text) ? ["explicit-unknown"] : []),
    ...(externalApi && !/(doküman|documentation|specification)/i.test(text) ? ["external-api-behavior"] : []),
  ]);
  const uncertaintyScore = unresolved.length >= 2 ? 0.85 : unresolved.length === 1 ? 0.62 : 0.2;
  const uncertainty = uncertaintyScore >= 0.7 ? "high" : uncertaintyScore >= 0.4 ? "medium" : "low";
  const complexityScore = clamp(0.15 + taskTypes.length * 0.12 + paths.length * 0.04 + (risk === "high" ? 0.25 : risk === "critical" ? 0.35 : 0) + (uncertainty === "high" ? 0.18 : 0));
  const complexity = complexityScore >= 0.68 ? "high" : complexityScore >= 0.36 ? "medium" : "low";
  const requiredCapabilities = unique([
    "repository-read",
    ...(/(ekle|yap|düzelt|implement|change)/i.test(text) ? ["repository-write", "shell"] : []),
    ...(/test/i.test(text) ? ["test-execution"] : []),
    ...(externalApi ? ["network-access"] : []),
    "structured-output",
  ]);
  const deterministic = [
    observation("credential-sensitive", credentialSensitive, 1, "kernel-rule", options.now, true),
    observation("external-api", externalApi, 1, "task-contract", options.now, true),
    observation("frontend", hasFrontend, 1, "repository-scan", options.now, true),
    observation("languages", languages, 1, "repository-scan", options.now, true),
  ];
  const semantic = (options.semantic_observations ?? []).map(value => observation(value.feature_key, value.value, value.confidence, value.source, options.now, value.confidence >= 0.8));
  const hardConstraints = unique([
    ...(credentialSensitive ? ["credential-sensitive"] : []),
    ...((input.metadata?.privacy ?? "internal") !== "public" ? [`privacy:${input.metadata?.privacy ?? "internal"}`] : []),
    ...semantic.filter(value => value.hard_constraint_eligible && value.value === true).map(value => value.feature_key),
  ]);
  const content = fingerprintContentSchema.parse({
    schema_version: 1,
    fingerprint_id: `task-fingerprint:${stripPrefix(input.task_id)}-r${options.revision}`,
    revision: options.revision,
    compiler_input_hash: taskCompilerInputHash(input, options.semantic_observations ?? []),
    task_id: input.task_id,
    contract_ref: input.contract_ref,
    objective: input.objective,
    task_types: taskTypes,
    domains: unique(input.metadata?.domains ?? (externalApi ? ["provider-integration"] : ["software-engineering"])),
    signals: { languages, paths, has_frontend: hasFrontend, has_3d: has3d, external_api: externalApi, credential_sensitive: credentialSensitive },
    required_capabilities: requiredCapabilities,
    modalities: has3d || hasFrontend ? ["text", "image"] : ["text"],
    freshness: externalApi ? "required" : "not-required",
    risk: { level: risk, reasons: riskReasons },
    privacy: input.metadata?.privacy ?? "internal",
    complexity: { level: complexity, score: complexityScore },
    uncertainty: { level: uncertainty, score: uncertaintyScore, unresolved },
    scope: { paths, parallelizable: paths.length > 1 && !credentialSensitive },
    observations: [...deterministic, ...semantic],
    hard_constraints: hardConstraints,
    compiled_at: options.now,
  });
  return immutable(taskFingerprintSchema.parse({ ...content, fingerprint_hash: canonicalSha256(content) }));
}

const roleDefinitionContentSchema = z.object({
  schema_version: z.literal(1), role_id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/), version: semverSchema,
  objective: z.string().min(1), category: z.enum(ROLE_CATEGORIES), required_capabilities: z.array(z.string()),
  permissions: z.array(z.string()), outputs: z.array(z.string()), incompatible_roles: z.array(z.string()), optional: z.boolean(),
}).strict();
export const roleDefinitionSchema = roleDefinitionContentSchema.extend({ role_hash: hashSchema }).strict();
export type RoleDefinition = z.infer<typeof roleDefinitionSchema>;

export function createBuiltinRoleCatalog(): readonly RoleDefinition[] {
  const rows: Array<Omit<z.input<typeof roleDefinitionContentSchema>, "schema_version">> = [
    { role_id: "internet-researcher", version: "1.0.0", objective: "Resolve fresh external facts with sourced evidence.", category: "analysis", required_capabilities: ["network-access", "structured-output"], permissions: ["repository-read", "network-access"], outputs: ["research-handoff"], incompatible_roles: [], optional: true },
    { role_id: "chief-architect", version: "1.0.0", objective: "Produce a bounded implementation plan.", category: "analysis", required_capabilities: ["repository-read", "structured-output"], permissions: ["repository-read"], outputs: ["implementation-plan"], incompatible_roles: ["final-reviewer"], optional: true },
    { role_id: "backend-implementer", version: "1.0.0", objective: "Implement backend changes in an isolated workspace.", category: "production", required_capabilities: ["repository-read", "repository-write", "shell", "test-execution"], permissions: ["repository-read", "repository-write", "shell"], outputs: ["change-set", "test-evidence"], incompatible_roles: ["security-reviewer", "final-reviewer"], optional: false },
    { role_id: "frontend-implementer", version: "1.0.0", objective: "Implement frontend changes in an isolated workspace.", category: "production", required_capabilities: ["repository-read", "repository-write", "shell", "test-execution"], permissions: ["repository-read", "repository-write", "shell"], outputs: ["change-set", "browser-evidence"], incompatible_roles: ["visual-reviewer", "final-reviewer"], optional: false },
    { role_id: "spatial-planner", version: "1.0.0", objective: "Plan spatial and 3D interactions.", category: "analysis", required_capabilities: ["image-input", "structured-output"], permissions: ["repository-read"], outputs: ["spatial-plan"], incompatible_roles: [], optional: true },
    { role_id: "test-engineer", version: "1.0.0", objective: "Create and execute independent regression checks.", category: "verification", required_capabilities: ["repository-read", "test-execution"], permissions: ["repository-read", "repository-write", "shell"], outputs: ["verification-evidence"], incompatible_roles: [], optional: false },
    { role_id: "security-reviewer", version: "1.0.0", objective: "Independently review security-sensitive changes.", category: "governance", required_capabilities: ["repository-read", "structured-output"], permissions: ["repository-read"], outputs: ["security-verdict"], incompatible_roles: ["backend-implementer", "frontend-implementer"], optional: false },
    { role_id: "visual-reviewer", version: "1.0.0", objective: "Independently review rendered user experience.", category: "verification", required_capabilities: ["image-input", "browser"], permissions: ["repository-read"], outputs: ["visual-verdict"], incompatible_roles: ["frontend-implementer"], optional: true },
  ];
  return immutable(rows.map(row => {
    const content = roleDefinitionContentSchema.parse({ schema_version: 1, ...row });
    return roleDefinitionSchema.parse({ ...content, role_hash: canonicalSha256(content) });
  }));
}

const roleNodeSchema = z.object({
  role_node_id: entityId("role-node"), role_id: z.string(), depends_on: z.array(z.string()), status: z.enum(ROLE_NODE_STATUSES),
  path_scope: z.array(z.string()), mandatory: z.boolean(),
}).strict();
const teamPlanContentSchema = z.object({
  schema_version: z.literal(1), team_plan_id: entityId("team-plan"), revision: z.number().int().positive(), task_id: entityId("task"),
  fingerprint_hash: hashSchema, role_catalog_hash: hashSchema, nodes: z.array(roleNodeSchema).min(1).max(8), max_parallelism: z.number().int().min(1).max(3),
  architect_proposal_applied: z.array(z.string()), architect_proposal_rejected: z.array(z.string()),
}).strict();
export const teamPlanSchema = teamPlanContentSchema.extend({ team_plan_hash: hashSchema }).strict();
export type TeamPlan = z.infer<typeof teamPlanSchema>;

export function assertTeamPlanDag(team: TeamPlan): void {
  teamPlanSchema.parse(team); const roleIds = team.nodes.map(value => value.role_id); const nodeIds = team.nodes.map(value => value.role_node_id);
  if (new Set(roleIds).size !== roleIds.length) throw new Error("TEAM_PLAN_DUPLICATE_ROLE");
  if (new Set(nodeIds).size !== nodeIds.length) throw new Error("TEAM_PLAN_DUPLICATE_NODE");
  const known = new Set(roleIds);
  for (const node of team.nodes) {
    if (new Set(node.depends_on).size !== node.depends_on.length) throw new Error("TEAM_PLAN_DUPLICATE_DEPENDENCY");
    if (node.depends_on.includes(node.role_id)) throw new Error("TEAM_PLAN_SELF_DEPENDENCY");
    if (node.depends_on.some(value => !known.has(value))) throw new Error("TEAM_PLAN_UNKNOWN_DEPENDENCY");
  }
  assertAcyclic(team.nodes);
}

export function composeTeam(fingerprint: TaskFingerprint, catalog: readonly RoleDefinition[], options: { architect_proposal?: { add_roles?: string[]; remove_roles?: string[] } } = {}): TeamPlan {
  taskFingerprintSchema.parse(fingerprint);
  const known = new Map(catalog.map(role => [role.role_id, role]));
  const roles: string[] = [];
  if (fingerprint.freshness === "required" || fingerprint.uncertainty.level === "high") roles.push("internet-researcher");
  if (fingerprint.complexity.level !== "low") roles.push("chief-architect");
  if (fingerprint.task_types.includes("frontend")) roles.push("frontend-implementer");
  else roles.push("backend-implementer");
  if (fingerprint.signals.has_3d) roles.unshift("spatial-planner");
  roles.push("test-engineer");
  if (fingerprint.risk.level === "high" || fingerprint.risk.level === "critical" || fingerprint.signals.credential_sensitive) roles.push("security-reviewer");
  if (fingerprint.signals.has_frontend) roles.push("visual-reviewer");
  const mandatory = new Set<string>(roles.filter(role => role === "backend-implementer" || role === "frontend-implementer" || role === "test-engineer" || role === "security-reviewer"));
  const applied: string[] = [];
  const rejected: string[] = [];
  for (const remove of options.architect_proposal?.remove_roles ?? []) {
    const index = roles.indexOf(remove);
    if (index < 0) continue;
    if (mandatory.has(remove)) rejected.push(`remove:${remove}:mandatory`);
    else { roles.splice(index, 1); applied.push(`remove:${remove}`); }
  }
  for (const add of options.architect_proposal?.add_roles ?? []) {
    const allowed = known.has(add) && !(add === "visual-reviewer" && !fingerprint.signals.has_frontend) && !(add === "spatial-planner" && !fingerprint.signals.has_3d);
    if (!allowed || roles.includes(add) || roles.length >= 8) rejected.push(`add:${add}:policy`);
    else { roles.push(add); applied.push(`add:${add}`); }
  }
  const ordered = unique(roles).slice(0, 8);
  const production = ordered.filter(role => known.get(role)?.category === "production");
  const nodes = ordered.map(role => {
    const category = known.get(role)?.category;
    const dependencies = category === "production"
      ? ordered.filter(value => value === "internet-researcher" || value === "chief-architect" || value === "spatial-planner")
      : role === "chief-architect" ? ordered.filter(value => value === "internet-researcher" || value === "spatial-planner")
      : category === "verification" || category === "governance" ? [...production, ...(role === "security-reviewer" && ordered.includes("test-engineer") ? ["test-engineer"] : [])]
      : [];
    return { role_node_id: `role-node:${role}`, role_id: role, depends_on: unique(dependencies), status: "WAITING" as const, path_scope: fingerprint.scope.paths, mandatory: mandatory.has(role) };
  });
  assertAcyclic(nodes);
  const content = teamPlanContentSchema.parse({
    schema_version: 1, team_plan_id: `team-plan:${stripPrefix(fingerprint.task_id)}-r${fingerprint.revision}`, revision: fingerprint.revision,
    task_id: fingerprint.task_id, fingerprint_hash: fingerprint.fingerprint_hash,
    role_catalog_hash: canonicalSha256(catalog.map(role => role.role_hash).sort()), nodes, max_parallelism: Math.min(3, fingerprint.scope.parallelizable ? 3 : 1),
    architect_proposal_applied: applied, architect_proposal_rejected: rejected,
  });
  return immutable(teamPlanSchema.parse({ ...content, team_plan_hash: canonicalSha256(content) }));
}

export interface CandidateMetrics {
  role_quality: number; task_similarity: number; repository_affinity: number; tool_reliability: number;
  structured_output_reliability: number; operational_reliability: number; availability: number;
  confidence_lower: number; confidence_mean: number; incident_penalty: number; staleness_penalty: number;
  cost_p50: number; cost_p90: number; latency_p50_ms: number; latency_p90_ms: number;
}

export interface Candidate {
  schema_version: 1; candidate_id: string; role_id: string; agent_profile_id: string;
  agent_profile_version: string; agent_profile_hash: string;
  execution_config_id: string; execution_config_hash: string; scorecard_id: string; scorecard_hash: string;
  provider_id: string; model_version_id: string; runtime_id: string; runtime_adapter_version: string; deployment_id: string;
  qualification_level: "Q0" | "Q1" | "Q2" | "Q3" | "Q4" | "Q5";
  lifecycle_status: "valid" | "stale" | "expired" | "quarantined";
  valid_until: string; capabilities: string[]; modalities: string[]; context_tokens: number;
  permission_envelope: string[]; sandbox_enforced: boolean;
  privacy_classes: PrivacyLevel[]; metrics: CandidateMetrics;
  availability: { runtime_healthy: boolean; provider_healthy: boolean; account_capacity: number; observed_at: string; expires_at: string };
  account_pool: string[]; candidate_hash: string;
}

const candidateMetricsSchema = z.object({
  role_quality: z.number().min(0).max(1), task_similarity: z.number().min(0).max(1), repository_affinity: z.number().min(0).max(1),
  tool_reliability: z.number().min(0).max(1), structured_output_reliability: z.number().min(0).max(1), operational_reliability: z.number().min(0).max(1),
  availability: z.number().min(0).max(1), confidence_lower: z.number().min(0).max(1), confidence_mean: z.number().min(0).max(1),
  incident_penalty: z.number().min(0).max(1), staleness_penalty: z.number().min(0).max(1), cost_p50: z.number().nonnegative(), cost_p90: z.number().nonnegative(),
  latency_p50_ms: z.number().nonnegative(), latency_p90_ms: z.number().nonnegative(),
}).strict();
export const candidateSchema = z.object({
  schema_version: z.literal(1), candidate_id: entityId("candidate"), role_id: z.string().min(1), agent_profile_id: entityId("agent-profile"), agent_profile_version: semverSchema, agent_profile_hash: hashSchema,
  execution_config_id: entityId("execution-config"), execution_config_hash: hashSchema, scorecard_id: z.string().min(1), scorecard_hash: hashSchema,
  provider_id: entityId("provider"), model_version_id: entityId("model-version"), runtime_id: entityId("runtime"), runtime_adapter_version: semverSchema, deployment_id: entityId("deployment"),
  qualification_level: z.enum(["Q0", "Q1", "Q2", "Q3", "Q4", "Q5"]), lifecycle_status: z.enum(["valid", "stale", "expired", "quarantined"]),
  valid_until: isoDateSchema, capabilities: z.array(z.string()), modalities: z.array(z.string()), context_tokens: z.number().int().nonnegative(),
  permission_envelope: z.array(z.string()), sandbox_enforced: z.boolean(),
  privacy_classes: z.array(z.enum(PRIVACY_LEVELS)), metrics: candidateMetricsSchema,
  availability: z.object({ runtime_healthy: z.boolean(), provider_healthy: z.boolean(), account_capacity: z.number().int().nonnegative(), observed_at: isoDateSchema, expires_at: isoDateSchema }).strict(),
  account_pool: z.array(z.string()), candidate_hash: hashSchema,
}).strict();

export interface CandidateSet {
  schema_version: 1; candidate_set_id: string; role_id: string; eligible: Candidate[];
  rejected: Array<{ candidate_id: string; reasons: string[] }>;
  candidate_set_hash: string;
}
export const candidateSetSchema = z.object({
  schema_version: z.literal(1), candidate_set_id: entityId("candidate-set"), role_id: z.string().min(1), eligible: z.array(candidateSchema),
  rejected: z.array(z.object({ candidate_id: entityId("candidate"), reasons: z.array(z.string()).min(1) }).strict()), candidate_set_hash: hashSchema,
}).strict();

export function buildCandidateSet(input: { role_id: string; candidates: Candidate[]; now: string; task_privacy: PrivacyLevel; task_risk: RiskLevel; required_capabilities: string[]; required_context_tokens: number; required_modalities?: string[]; required_permissions?: string[]; require_sandbox?: boolean }): CandidateSet {
  const eligible: Candidate[] = [];
  const rejected: CandidateSet["rejected"] = [];
  for (const rawCandidate of [...input.candidates].sort((a, b) => a.candidate_id.localeCompare(b.candidate_id))) {
    const candidate = candidateSchema.parse(rawCandidate) as Candidate; const { candidate_hash: ignoredCandidateHash, ...candidateContent } = candidate;
    if (canonicalSha256(candidateContent) !== candidate.candidate_hash) throw new Error("CANDIDATE_HASH_MISMATCH");
    const reasons: string[] = [];
    if (candidate.role_id !== input.role_id) reasons.push("ROLE_MISMATCH");
    if (candidate.lifecycle_status === "quarantined") reasons.push("QUARANTINED");
    if (candidate.lifecycle_status === "expired" || Date.parse(candidate.valid_until) <= Date.parse(input.now)) reasons.push("SCORECARD_EXPIRED");
    if (candidate.lifecycle_status === "stale") reasons.push("SCORECARD_STALE");
    if (!candidate.availability.runtime_healthy) reasons.push("RUNTIME_UNHEALTHY");
    if (!candidate.availability.provider_healthy) reasons.push("PROVIDER_UNHEALTHY");
    if (candidate.availability.account_capacity < 1) reasons.push("ACCOUNT_CAPACITY_UNAVAILABLE");
    if (candidate.account_pool.length < 1) reasons.push("ACCOUNT_REFERENCE_UNAVAILABLE");
    if (Date.parse(candidate.availability.expires_at) <= Date.parse(input.now)) reasons.push("AVAILABILITY_EXPIRED");
    if (!candidate.privacy_classes.includes(input.task_privacy)) reasons.push("PRIVACY_INCOMPATIBLE");
    if (candidate.context_tokens < input.required_context_tokens) reasons.push("CONTEXT_INSUFFICIENT");
    if (input.required_capabilities.some(value => !candidate.capabilities.includes(value))) reasons.push("CAPABILITY_MISSING");
    if ((input.required_modalities ?? []).some(value => !candidate.modalities.includes(value))) reasons.push("MODALITY_INCOMPATIBLE");
    if ((input.required_permissions ?? []).some(value => !candidate.permission_envelope.includes(value))) reasons.push("PERMISSION_ENVELOPE_INSUFFICIENT");
    if (input.require_sandbox && !candidate.sandbox_enforced) reasons.push("SANDBOX_ENFORCEMENT_INSUFFICIENT");
    const qualificationRank = Number(candidate.qualification_level.slice(1));
    if (qualificationRank < (input.task_risk === "critical" ? 4 : input.task_risk === "high" ? 3 : 2)) reasons.push("QUALIFICATION_INSUFFICIENT");
    if (reasons.length) rejected.push({ candidate_id: candidate.candidate_id, reasons: unique(reasons) });
    else eligible.push(candidate);
  }
  const identity = { role_id: input.role_id, eligible: eligible.map(value => value.candidate_hash), rejected };
  return immutable({ schema_version: 1, candidate_set_id: `candidate-set:${input.role_id}-${canonicalSha256(identity).slice(7, 19)}`, role_id: input.role_id, eligible, rejected, candidate_set_hash: canonicalSha256(identity) });
}

export interface RoutingPolicy {
  schema_version: 1; policy_id: string; version: string; profile: "premium" | "balanced" | "economy" | "fast" | "private";
  weights: Record<"quality" | "task_similarity" | "repository_affinity" | "reliability" | "availability" | "cost" | "latency", number>;
  penalties: { uncertainty: number; incident: number; staleness: number; provider_correlation: number };
  limits: { top_k_per_role: number; beam_width: number; max_roles: number; max_parallelism: number; budget_multiplier: number };
  valid_from: string; valid_until: string; policy_hash: string;
}
export const routingPolicySchema = z.object({
  schema_version: z.literal(1), policy_id: entityId("routing-policy"), version: semverSchema, profile: z.enum(["premium", "balanced", "economy", "fast", "private"]),
  weights: z.object({ quality: z.number(), task_similarity: z.number(), repository_affinity: z.number(), reliability: z.number(), availability: z.number(), cost: z.number(), latency: z.number() }).strict(),
  penalties: z.object({ uncertainty: z.number().nonnegative(), incident: z.number().nonnegative(), staleness: z.number().nonnegative(), provider_correlation: z.number().nonnegative() }).strict(),
  limits: z.object({ top_k_per_role: z.number().int().positive(), beam_width: z.number().int().positive(), max_roles: z.number().int().positive(), max_parallelism: z.number().int().positive(), budget_multiplier: z.number().positive() }).strict(),
  valid_from: isoDateSchema, valid_until: isoDateSchema, policy_hash: hashSchema,
}).strict().superRefine((value, context) => {
  const weights = Object.values(value.weights); if (weights.some(weight => weight < 0)) context.addIssue({ code: "custom", path: ["weights"], message: "Routing weights must be nonnegative" });
  if (Math.abs(weights.reduce((sum, weight) => sum + weight, 0) - 1) > 1e-9) context.addIssue({ code: "custom", path: ["weights"], message: "Routing weights must sum to one" });
});

export function createDefaultRoutingPolicy(profile: RoutingPolicy["profile"], now: string): RoutingPolicy {
  const weights = profile === "premium"
    ? { quality: 0.28, task_similarity: 0.14, repository_affinity: 0.1, reliability: 0.2, availability: 0.1, cost: 0.08, latency: 0.1 }
    : profile === "economy"
      ? { quality: 0.18, task_similarity: 0.1, repository_affinity: 0.08, reliability: 0.16, availability: 0.08, cost: 0.3, latency: 0.1 }
      : profile === "fast"
        ? { quality: 0.18, task_similarity: 0.1, repository_affinity: 0.08, reliability: 0.16, availability: 0.12, cost: 0.08, latency: 0.28 }
        : profile === "private"
          ? { quality: 0.24, task_similarity: 0.12, repository_affinity: 0.1, reliability: 0.22, availability: 0.12, cost: 0.1, latency: 0.1 }
          : { quality: 0.23, task_similarity: 0.12, repository_affinity: 0.1, reliability: 0.19, availability: 0.1, cost: 0.14, latency: 0.12 };
  const content = {
    schema_version: 1 as const, policy_id: `routing-policy:${profile}`, version: "1.0.0", profile, weights,
    penalties: { uncertainty: 0.08, incident: 0.14, staleness: 0.12, provider_correlation: 0.06 },
    limits: { top_k_per_role: 4, beam_width: 20, max_roles: 8, max_parallelism: 3, budget_multiplier: 1.1 },
    valid_from: now, valid_until: new Date(Date.parse(now) + 365 * 24 * 60 * 60_000).toISOString(),
  };
  return immutable({ ...content, policy_hash: canonicalSha256(content) });
}

export interface RoutingContextSnapshot {
  schema_version: 1; context_id: string; observed_at: string; expires_at: string; fingerprint_hash: string;
  team_plan_hash: string; policy_hash: string; kill_switch_active: boolean; context_hash: string;
}
export const routingContextSnapshotSchema = z.object({
  schema_version: z.literal(1), context_id: entityId("routing-context"), observed_at: isoDateSchema, expires_at: isoDateSchema,
  fingerprint_hash: hashSchema, team_plan_hash: hashSchema, policy_hash: hashSchema, kill_switch_active: z.boolean(), context_hash: hashSchema,
}).strict();

export interface RoutingAssignment {
  role_node_id: string; role_id: string; candidate_id: string; provider_id: string; execution_config_id: string;
  score: number; explanation: string[]; account_id: string | null;
}

export interface RoutingPlan {
  schema_version: 1; routing_plan_id: string; revision: number; task_id: string; status: RoutingPlanStatus;
  fingerprint_hash: string; team_plan_hash: string; policy_hash: string; context_hash: string; seed: number;
  assignments: RoutingAssignment[]; candidates: Candidate[]; rejected_candidates: CandidateSet["rejected"];
  routing_constraints: { task_risk: RiskLevel; task_privacy: PrivacyLevel; task_modalities: string[]; required_capabilities: string[]; required_context_tokens: number; budget_multiplier: number };
  score_basis: "mean" | "lower-confidence-bound"; team_utility: number;
  cost_estimate: { p50: number; p90: number }; latency_estimate: { p50_ms: number; p90_ms: number };
  budget_reservation: { reservation_id: string; amount: number; reserved_at: string } | null;
  created_at: string; updated_at: string; plan_hash: string;
}
const routingAssignmentSchema = z.object({ role_node_id: entityId("role-node"), role_id: z.string().min(1), candidate_id: entityId("candidate"), provider_id: entityId("provider"), execution_config_id: entityId("execution-config"), score: z.number().min(0).max(1), explanation: z.array(z.string().min(1)).min(1), account_id: z.string().min(1).nullable() }).strict();
export const routingPlanSchema = z.object({
  schema_version: z.literal(1), routing_plan_id: entityId("routing-plan"), revision: z.number().int().positive(), task_id: entityId("task"), status: z.enum(ROUTING_PLAN_STATUSES),
  fingerprint_hash: hashSchema, team_plan_hash: hashSchema, policy_hash: hashSchema, context_hash: hashSchema, seed: z.number().int(), assignments: z.array(routingAssignmentSchema).min(1),
  candidates: z.array(candidateSchema), rejected_candidates: candidateSetSchema.shape.rejected, score_basis: z.enum(["mean", "lower-confidence-bound"]), team_utility: z.number(),
  routing_constraints: z.object({ task_risk: z.enum(RISK_LEVELS), task_privacy: z.enum(PRIVACY_LEVELS), task_modalities: z.array(z.string()), required_capabilities: z.array(z.string()), required_context_tokens: z.number().int().positive(), budget_multiplier: z.number().min(1).max(3) }).strict(),
  cost_estimate: z.object({ p50: z.number().nonnegative(), p90: z.number().nonnegative() }).strict(), latency_estimate: z.object({ p50_ms: z.number().nonnegative(), p90_ms: z.number().nonnegative() }).strict(),
  budget_reservation: z.object({ reservation_id: entityId("budget-reservation"), amount: z.number().nonnegative(), reserved_at: isoDateSchema }).strict().nullable(),
  created_at: isoDateSchema, updated_at: isoDateSchema, plan_hash: hashSchema,
}).strict();

const transitionMap: Record<RoutingPlanStatus, readonly RoutingPlanStatus[]> = {
  DRAFT: ["CANDIDATES_RESOLVED", "REJECTED", "CANCELLED"], CANDIDATES_RESOLVED: ["OPTIMIZED", "REJECTED", "CANCELLED"],
  OPTIMIZED: ["POLICY_VALIDATED", "REJECTED", "CANCELLED"], POLICY_VALIDATED: ["BUDGET_RESERVED", "REJECTED", "CANCELLED", "EXPIRED"],
  BUDGET_RESERVED: ["APPROVED", "REJECTED", "CANCELLED", "EXPIRED"], APPROVED: ["ACTIVE", "REBIND_REQUIRED", "CANCELLED", "EXPIRED"],
  ACTIVE: ["COMPLETED", "REBIND_REQUIRED", "CANCELLED"], REBIND_REQUIRED: ["APPROVED", "SUPERSEDED", "CANCELLED"],
  COMPLETED: [], REJECTED: [], SUPERSEDED: [], CANCELLED: [], EXPIRED: [],
};

export function transitionRoutingPlan(plan: RoutingPlan, next: RoutingPlanStatus, now: string): RoutingPlan {
  assertRoutingPlanIntegrity(plan);
  if (!transitionMap[plan.status].includes(next)) throw new Error("INVALID_ROUTING_PLAN_TRANSITION");
  if (next === "ACTIVE" && !plan.budget_reservation) throw new Error("BUDGET_RESERVATION_REQUIRED");
  return rehashPlan({ ...plan, status: next, updated_at: now });
}

export function assertRoutingPlanIntegrity(plan: RoutingPlan): void {
  routingPlanSchema.parse(plan); const { plan_hash: ignoredPlanHash, ...planContent } = plan;
  if (canonicalSha256(planContent) !== plan.plan_hash) throw new Error("ROUTING_PLAN_HASH_MISMATCH");
}

export interface ExecutionBindingSet {
  schema_version: 1; binding_set_id: string; routing_plan_id: string; routing_plan_hash: string; revision: number;
  previous_revision_hash: string | null; status: "ACTIVE" | "SUPERSEDED";
  routing_constraints: RoutingPlan["routing_constraints"];
  bindings: Array<{ binding_id: string; role_node_id: string; role_id: string; candidate_id: string; agent_profile_id: string; agent_profile_version: string; agent_profile_hash: string; execution_config_id: string; execution_config_hash: string; provider_id: string; model_version_id: string; runtime_id: string; runtime_adapter_version: string; deployment_id: string; account_id: string; attempt: number; created_at: string }>;
  rebind_history: Array<{ role_node_id: string; from_candidate_id: string; to_candidate_id: string; from_account_id: string; to_account_id: string; reason: RebindReason; occurred_at: string }>;
  binding_set_hash: string;
}
export const executionBindingSetSchema = z.object({
  schema_version: z.literal(1), binding_set_id: entityId("binding-set"), routing_plan_id: entityId("routing-plan"), routing_plan_hash: hashSchema,
  revision: z.number().int().positive(), previous_revision_hash: hashSchema.nullable(), status: z.enum(["ACTIVE", "SUPERSEDED"]),
  routing_constraints: routingPlanSchema.shape.routing_constraints,
  bindings: z.array(z.object({ binding_id: entityId("binding"), role_node_id: entityId("role-node"), role_id: z.string(), candidate_id: entityId("candidate"), agent_profile_id: entityId("agent-profile"), agent_profile_version: semverSchema, agent_profile_hash: hashSchema, execution_config_id: entityId("execution-config"), execution_config_hash: hashSchema, provider_id: entityId("provider"), model_version_id: entityId("model-version"), runtime_id: entityId("runtime"), runtime_adapter_version: semverSchema, deployment_id: entityId("deployment"), account_id: z.string().min(1), attempt: z.number().int().positive(), created_at: isoDateSchema }).strict()).min(1),
  rebind_history: z.array(z.object({ role_node_id: entityId("role-node"), from_candidate_id: entityId("candidate"), to_candidate_id: entityId("candidate"), from_account_id: z.string().min(1), to_account_id: z.string().min(1), reason: z.enum(REBIND_REASONS), occurred_at: isoDateSchema }).strict()),
  binding_set_hash: hashSchema,
}).strict();

export function assertExecutionBindingSetIntegrity(set: ExecutionBindingSet): void {
  executionBindingSetSchema.parse(set); const { binding_set_hash: ignoredHash, ...content } = set;
  if (canonicalSha256(content) !== set.binding_set_hash) throw new Error("BINDING_SET_HASH_MISMATCH");
  if ((set.revision === 1) !== (set.previous_revision_hash === null)) throw new Error("BINDING_SET_REVISION_LINK_INVALID");
  if (new Set(set.bindings.map(value => value.role_node_id)).size !== set.bindings.length) throw new Error("DUPLICATE_ACTIVE_ROLE_BINDING");
}

export function resolveReadyRoleNodes(input: { team_plan: TeamPlan; routing_plan: RoutingPlan; binding_set: ExecutionBindingSet; completed_role_ids: string[] }): Array<TeamPlan["nodes"][number] & { status: "READY" }> {
  assertTeamPlanDag(input.team_plan); assertRoutingPlanIntegrity(input.routing_plan); assertExecutionBindingSetIntegrity(input.binding_set);
  if (input.routing_plan.status !== "ACTIVE" || !input.routing_plan.budget_reservation) throw new Error("ACTIVE_RESERVED_ROUTING_PLAN_REQUIRED");
  if (input.routing_plan.team_plan_hash !== input.team_plan.team_plan_hash || input.routing_plan.task_id !== input.team_plan.task_id || input.routing_plan.fingerprint_hash !== input.team_plan.fingerprint_hash) throw new Error("TEAM_ROUTING_PLAN_PIN_MISMATCH");
  if (input.binding_set.routing_plan_id !== input.routing_plan.routing_plan_id || input.binding_set.routing_plan_hash !== input.routing_plan.plan_hash) throw new Error("BINDING_ROUTING_PLAN_MISMATCH");
  const completed = new Set(input.completed_role_ids); const bound = new Set(input.binding_set.bindings.map(value => value.role_node_id));
  return input.team_plan.nodes.filter(node => !completed.has(node.role_id) && bound.has(node.role_node_id) && node.depends_on.every(value => completed.has(value))).slice(0, input.team_plan.max_parallelism).map(node => ({ ...node, status: "READY" }));
}

export function createExecutionBindings(plan: RoutingPlan, now: string): ExecutionBindingSet {
  assertRoutingPlanIntegrity(plan);
  if (plan.status !== "ACTIVE") throw new Error("ACTIVE_ROUTING_PLAN_REQUIRED");
  const byId = new Map(plan.candidates.map(value => [value.candidate_id, value]));
  const bindings = plan.assignments.map(assignment => {
    const selected = byId.get(assignment.candidate_id);
    if (!selected) throw new Error("SELECTED_CANDIDATE_MISSING");
    const accountId = assignment.account_id ?? selected.account_pool[0]; if (!accountId || !selected.account_pool.includes(accountId)) throw new Error("VALIDATED_ACCOUNT_BINDING_REQUIRED");
    return { binding_id: `binding:${stripPrefix(plan.routing_plan_id)}-${stripPrefix(assignment.role_node_id)}-r1`, role_node_id: assignment.role_node_id, role_id: assignment.role_id, candidate_id: selected.candidate_id, agent_profile_id: selected.agent_profile_id, agent_profile_version: selected.agent_profile_version, agent_profile_hash: selected.agent_profile_hash, execution_config_id: selected.execution_config_id, execution_config_hash: selected.execution_config_hash, provider_id: selected.provider_id, model_version_id: selected.model_version_id, runtime_id: selected.runtime_id, runtime_adapter_version: selected.runtime_adapter_version, deployment_id: selected.deployment_id, account_id: accountId, attempt: 1, created_at: now };
  });
  return rehashBindings({ schema_version: 1, binding_set_id: `binding-set:${stripPrefix(plan.routing_plan_id)}`, routing_plan_id: plan.routing_plan_id, routing_plan_hash: plan.plan_hash, revision: 1, previous_revision_hash: null, status: "ACTIVE", routing_constraints: plan.routing_constraints, bindings, rebind_history: [] });
}

export function rebindExecution(set: ExecutionBindingSet, roleNodeId: string, candidate: Candidate, reason: string, now: string): ExecutionBindingSet {
  assertExecutionBindingSetIntegrity(set);
  if (!(REBIND_REASONS as readonly string[]).includes(reason)) throw new Error("REBIND_REASON_NOT_ALLOWED");
  const current = set.bindings.find(value => value.role_node_id === roleNodeId);
  if (!current) throw new Error("BINDING_NOT_FOUND");
  const eligibility = buildCandidateSet({ role_id: current.role_id, candidates: [candidate], now, task_privacy: set.routing_constraints.task_privacy, task_risk: set.routing_constraints.task_risk, required_capabilities: fallbackCapabilities(current.role_id, set.routing_constraints.required_capabilities), required_context_tokens: set.routing_constraints.required_context_tokens, required_modalities: fallbackModalities(current.role_id, set.routing_constraints.task_modalities), required_permissions: fallbackPermissions(current.role_id), require_sandbox: requiresSandbox(current.role_id, set.routing_constraints.task_risk) });
  if (eligibility.eligible.length !== 1) throw new Error(`REBIND_CANDIDATE_INELIGIBLE:${eligibility.rejected[0]?.reasons.join(",") ?? "UNKNOWN"}`);
  const { candidate_hash: ignoredCandidateHash, ...candidateContent } = candidate;
  if (canonicalSha256(candidateContent) !== candidate.candidate_hash) throw new Error("CANDIDATE_HASH_MISMATCH");
  const nextAccount = candidate.account_pool[0]; if (!nextAccount) throw new Error("REBIND_ACCOUNT_REQUIRED");
  if (current.candidate_id === candidate.candidate_id && current.runtime_id === candidate.runtime_id && current.account_id === nextAccount) throw new Error("REBIND_MUST_CHANGE_EXECUTION_TARGET");
  const revision = set.revision + 1;
  const bindings = set.bindings.map(value => value.role_node_id !== roleNodeId ? value : {
    ...value, binding_id: `${value.binding_id.replace(/-r\d+$/, "")}-r${revision}`, candidate_id: candidate.candidate_id,
    agent_profile_id: candidate.agent_profile_id, agent_profile_version: candidate.agent_profile_version, agent_profile_hash: candidate.agent_profile_hash,
    execution_config_id: candidate.execution_config_id, execution_config_hash: candidate.execution_config_hash, provider_id: candidate.provider_id, model_version_id: candidate.model_version_id,
    runtime_id: candidate.runtime_id, runtime_adapter_version: candidate.runtime_adapter_version, deployment_id: candidate.deployment_id, account_id: nextAccount,
    attempt: value.attempt + 1, created_at: now,
  });
  const rebound = rehashBindings({ ...set, revision, previous_revision_hash: set.binding_set_hash, bindings, rebind_history: [...set.rebind_history, { role_node_id: roleNodeId, from_candidate_id: current.candidate_id, to_candidate_id: candidate.candidate_id, from_account_id: current.account_id, to_account_id: nextAccount, reason: reason as RebindReason, occurred_at: now }] });
  if (set.routing_constraints.task_risk === "high" || set.routing_constraints.task_risk === "critical") {
    const implementers = rebound.bindings.filter(value => value.role_id.endsWith("implementer")); const reviewers = rebound.bindings.filter(value => value.role_id === "security-reviewer" || value.role_id === "final-reviewer");
    if (reviewers.some(reviewer => implementers.some(implementer => reviewer.provider_id === implementer.provider_id))) throw new Error("REBIND_SEPARATION_OF_DUTIES_VIOLATION");
  }
  return rebound;
}

export type FallbackFailureType = "RATE_LIMIT" | "AUTHENTICATION_FAILURE" | "PERMISSION_DENIED" | "PROVIDER_5XX" | "RUNTIME_UNHEALTHY" | "CONTEXT_LIMIT" | "TOOL_PROTOCOL_FAILURE" | "VERIFICATION_FAILURE" | "SECURITY_VIOLATION";
export interface FallbackResult { action: "REBIND" | "RETRY_NEW_ACCOUNT" | "REBUILD_CONTEXT" | "REPAIR" | "BLOCK" | "HUMAN_ESCALATION"; binding_set?: ExecutionBindingSet; reason: string }

export function applyFallback(input: { binding_set: ExecutionBindingSet; role_node_id: string; failure_type: FallbackFailureType; candidates: Candidate[]; now: string }): FallbackResult {
  assertExecutionBindingSetIntegrity(input.binding_set);
  const current = input.binding_set.bindings.find(value => value.role_node_id === input.role_node_id);
  if (!current) throw new Error("BINDING_NOT_FOUND");
  if (input.failure_type === "SECURITY_VIOLATION" || input.failure_type === "AUTHENTICATION_FAILURE" || input.failure_type === "PERMISSION_DENIED") return { action: "BLOCK", reason: input.failure_type };
  if (input.failure_type === "VERIFICATION_FAILURE") return { action: "REPAIR", reason: "VERIFICATION_REPAIR_REQUIRED" };
  if (input.failure_type === "CONTEXT_LIMIT") return { action: "REBUILD_CONTEXT", reason: "CONTEXT_REBUILD_REQUIRED" };
  if (input.binding_set.rebind_history.length >= 4) return { action: "HUMAN_ESCALATION", reason: "FALLBACK_MAX_HOPS_REACHED" };
  const eligible = buildCandidateSet({ role_id: current.role_id, candidates: input.candidates, now: input.now, task_privacy: input.binding_set.routing_constraints.task_privacy, task_risk: input.binding_set.routing_constraints.task_risk, required_capabilities: fallbackCapabilities(current.role_id, input.binding_set.routing_constraints.required_capabilities), required_context_tokens: input.binding_set.routing_constraints.required_context_tokens, required_modalities: fallbackModalities(current.role_id, input.binding_set.routing_constraints.task_modalities), required_permissions: fallbackPermissions(current.role_id), require_sandbox: requiresSandbox(current.role_id, input.binding_set.routing_constraints.task_risk) }).eligible;
  if (input.failure_type === "RATE_LIMIT" && current.account_id) {
    const visitedAccounts = new Set([current.account_id, ...input.binding_set.rebind_history.filter(value => value.role_node_id === input.role_node_id).flatMap(value => [value.from_account_id, value.to_account_id])]);
    const selected = eligible.find(value => value.candidate_id === current.candidate_id && value.agent_profile_id === current.agent_profile_id && value.agent_profile_version === current.agent_profile_version && value.agent_profile_hash === current.agent_profile_hash && value.execution_config_id === current.execution_config_id && value.execution_config_hash === current.execution_config_hash && value.provider_id === current.provider_id && value.model_version_id === current.model_version_id && value.runtime_id === current.runtime_id && value.runtime_adapter_version === current.runtime_adapter_version && value.deployment_id === current.deployment_id && value.account_pool.some(account => !visitedAccounts.has(account)));
    if (selected) {
      const accountPool = selected.account_pool.filter(account => !visitedAccounts.has(account));
      const { candidate_hash: ignoredHash, ...candidateContent } = { ...selected, account_pool: accountPool };
      const withNextAccount = { ...candidateContent, candidate_hash: canonicalSha256(candidateContent) } as Candidate;
      return { action: "RETRY_NEW_ACCOUNT", binding_set: rebindExecution(input.binding_set, input.role_node_id, withNextAccount, "RATE_LIMIT", input.now), reason: "ACCOUNT_CAPACITY_FALLBACK" };
    }
  }
  const history = new Set(input.binding_set.rebind_history.map(value => value.to_candidate_id));
  history.add(current.candidate_id);
  let alternates = eligible
    .filter(value => value.role_id === current.role_id && !history.has(value.candidate_id))
    .filter(value => input.failure_type !== "RUNTIME_UNHEALTHY" || (value.model_version_id === current.model_version_id && value.runtime_id !== current.runtime_id));
  if (input.failure_type === "TOOL_PROTOCOL_FAILURE") alternates = alternates.sort((a, b) => fallbackTier(a, current, "tool") - fallbackTier(b, current, "tool") || a.candidate_id.localeCompare(b.candidate_id));
  else if (input.failure_type === "PROVIDER_5XX") alternates = alternates.sort((a, b) => fallbackTier(a, current, "provider") - fallbackTier(b, current, "provider") || a.candidate_id.localeCompare(b.candidate_id));
  else alternates = alternates.sort((a, b) => a.candidate_id.localeCompare(b.candidate_id));
  const alternate = alternates[0];
  if (!alternate) return { action: "HUMAN_ESCALATION", reason: "FALLBACK_EXHAUSTED_OR_CYCLE_BLOCKED" };
  const reason: RebindReason = input.failure_type === "RUNTIME_UNHEALTHY" ? "RUNTIME_UNHEALTHY" : input.failure_type === "TOOL_PROTOCOL_FAILURE" ? "MODEL_BEHAVIOR_FAILURE" : "PROVIDER_UNAVAILABLE";
  try { return { action: "REBIND", binding_set: rebindExecution(input.binding_set, input.role_node_id, alternate, reason, input.now), reason }; }
  catch (error) { if (error instanceof Error && error.message === "REBIND_SEPARATION_OF_DUTIES_VIOLATION") return { action: "HUMAN_ESCALATION", reason: error.message }; throw error; }
}

const handoffContentSchema = z.object({
  schema_version: z.literal(1), handoff_id: entityId("handoff"), task_id: entityId("task"), from_role_node_id: entityId("role-node"), to_role_node_id: entityId("role-node"),
  claims: z.array(z.object({ statement: z.string().min(1).max(10_000), trust: z.enum(TRUST_LEVELS), evidence_refs: z.array(entityId("artifact")) }).strict()),
  open_questions: z.array(z.string().min(1).max(2_000)), created_at: isoDateSchema,
}).strict();
export const handoffPackageSchema = handoffContentSchema.extend({ handoff_hash: hashSchema }).strict();
export type HandoffPackage = z.infer<typeof handoffPackageSchema>;

export function createHandoffPackage(input: Omit<z.input<typeof handoffContentSchema>, "schema_version" | "handoff_id">): HandoffPackage {
  const serialized = JSON.stringify(input);
  if (/(secret|password|passphrase|token|client[_ -]?secret|access[_ -]?key|secret[_ -]?access[_ -]?key)\s*[=:]\s*\S+|api[_ -]?key\s*[=:]\s*\S+|authorization\s*[:=]\s*(?:bearer|basic)\s+\S+|\bbearer\s+[A-Za-z0-9._~+\/-]{12,}|\b(?:sk|sk-proj|sk-ant|ghp|github_pat)-[A-Za-z0-9_-]{10,}|\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|hidden reasoning|chain.of.thought|tool[_ -]?logs/i.test(serialized)) throw new Error("HANDOFF_FORBIDDEN_CONTENT");
  const id = canonicalSha256(input).slice(7, 27);
  const content = handoffContentSchema.parse({ schema_version: 1, handoff_id: `handoff:${id}`, ...input });
  return immutable(handoffPackageSchema.parse({ ...content, handoff_hash: canonicalSha256(content) }));
}

export const agentProfileSchema = z.object({
  schema_version: z.literal(1), agent_profile_id: entityId("agent-profile"), version: semverSchema, role_id: z.string().min(1),
  prompt_profile_ref: z.object({ id: z.string().min(1), version: semverSchema }).strict(), skills: z.array(z.string()), tool_bundle_ref: z.object({ id: z.string().min(1), version: semverSchema }).strict(),
  context_policy_ref: z.object({ id: z.string().min(1), version: semverSchema }).strict(), permission_envelope: z.array(z.string()), memory_scope: z.enum(["none", "task", "project"]), verification_requirements: z.array(z.string()), profile_hash: hashSchema,
}).strict();
export type AgentProfile = z.infer<typeof agentProfileSchema>;
export function createBuiltinAgentProfiles(catalog: readonly RoleDefinition[] = createBuiltinRoleCatalog()): readonly AgentProfile[] {
  return immutable(catalog.map(role => {
    const content = {
      schema_version: 1 as const, agent_profile_id: `agent-profile:${role.role_id}`, version: role.version, role_id: role.role_id,
      prompt_profile_ref: { id: `prompt-profile:${role.role_id}`, version: "1.0.0" }, skills: [...role.required_capabilities],
      tool_bundle_ref: { id: `tool-bundle:${role.role_id}`, version: "1.0.0" }, context_policy_ref: { id: "context-policy:bounded", version: "1.0.0" },
      permission_envelope: [...role.permissions], memory_scope: "task" as const, verification_requirements: [...role.outputs],
    };
    return agentProfileSchema.parse({ ...content, profile_hash: canonicalSha256(content) });
  }));
}
export const teamBlueprintSchema = z.object({
  schema_version: z.literal(1), team_blueprint_id: entityId("team-blueprint"), version: semverSchema, name: z.string().min(1), advisory_roles: z.array(z.string()), applicability: z.array(z.string()), blueprint_hash: hashSchema,
}).strict();
export type TeamBlueprint = z.infer<typeof teamBlueprintSchema>;
export function createBuiltinTeamBlueprints(): readonly TeamBlueprint[] {
  const rows = [
    { id: "team-blueprint:software-change", name: "Software change", roles: ["chief-architect", "backend-implementer", "test-engineer"], applicability: ["backend", "general-engineering"] },
    { id: "team-blueprint:risk-sensitive-change", name: "Risk-sensitive change", roles: ["internet-researcher", "chief-architect", "backend-implementer", "test-engineer", "security-reviewer"], applicability: ["credential-sensitive", "high-risk"] },
  ];
  return immutable(rows.map(row => {
    const content = { schema_version: 1 as const, team_blueprint_id: row.id, version: "1.0.0", name: row.name, advisory_roles: row.roles, applicability: row.applicability };
    return teamBlueprintSchema.parse({ ...content, blueprint_hash: canonicalSha256(content) });
  }));
}
export const fallbackGraphSchema = z.object({
  schema_version: z.literal(1), fallback_graph_id: entityId("fallback-graph"), version: semverSchema, created_at: isoDateSchema,
  rules: z.record(z.string(), z.array(z.string()).min(1)), max_hops: z.number().int().positive().max(16), fallback_graph_hash: hashSchema,
}).strict();
export const routingOutcomeSchema = z.object({
  schema_version: z.literal(1), routing_outcome_id: entityId("routing-outcome"), task_id: entityId("task"), routing_plan_id: entityId("routing-plan"),
  binding_set_hash: hashSchema, status: z.enum(["ACCEPTED", "REJECTED", "FAILED", "CANCELLED"]), selection_mode: z.enum(["deterministic-router", "human-override", "shadow"]),
  role_results: z.array(z.object({ role_id: z.string(), status: z.enum(["COMPLETED", "FAILED", "BLOCKED", "SKIPPED"]), evidence_refs: z.array(entityId("artifact")) }).strict()),
  fallback_count: z.number().int().nonnegative(), policy_updated_online: z.literal(false), offline_calibration_status: z.enum(["QUEUED", "NOT_QUEUED"]), recorded_at: isoDateSchema, outcome_hash: hashSchema,
}).strict();

function observation(feature_key: string, value: unknown, confidence: number, source: z.infer<typeof observationSchema>["source"], observed_at: string, eligible: boolean) {
  return observationSchema.parse({ feature_key, value, confidence, source, observed_at, hard_constraint_eligible: eligible });
}
function stripPrefix(value: string): string { return value.includes(":") ? value.slice(value.indexOf(":") + 1).replace(/[^A-Za-z0-9._@/-]/g, "-") : value; }
function fallbackCapabilities(roleId: string, required: string[]): string[] { if (roleId.includes("implementer")) return required.filter(value => value !== "network-access"); if (roleId === "internet-researcher") return ["network-access", "structured-output"]; if (roleId === "test-engineer") return ["repository-read", "test-execution"]; return ["repository-read", "structured-output"]; }
function fallbackModalities(roleId: string, taskModalities: string[]): string[] { return roleId === "visual-reviewer" || roleId === "spatial-planner" ? taskModalities : ["text"]; }
function fallbackPermissions(roleId: string): string[] { if (roleId.includes("implementer")) return ["repository-read", "repository-write", "shell"]; if (roleId === "internet-researcher") return ["repository-read", "network-access"]; if (roleId === "test-engineer") return ["repository-read", "repository-write", "shell"]; return ["repository-read"]; }
function requiresSandbox(roleId: string, risk: RiskLevel): boolean { return (risk === "high" || risk === "critical") && (roleId.includes("implementer") || roleId === "test-engineer"); }
function fallbackTier(candidate: Candidate, current: ExecutionBindingSet["bindings"][number], mode: "tool" | "provider"): number { if (mode === "tool") return candidate.model_version_id === current.model_version_id && candidate.runtime_id !== current.runtime_id ? 0 : 1; return candidate.provider_id === current.provider_id && candidate.model_version_id === current.model_version_id && candidate.deployment_id !== current.deployment_id ? 0 : 1; }
function unique<T>(values: readonly T[]): T[] { return [...new Set(values)]; }
function clamp(value: number): number { return Math.max(0, Math.min(1, value)); }
function immutable<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) immutable(child);
    Object.freeze(value);
  }
  return value;
}
function assertAcyclic(nodes: Array<{ role_id: string; depends_on: string[] }>): void {
  const visiting = new Set<string>(); const visited = new Set<string>(); const byId = new Map(nodes.map(value => [value.role_id, value]));
  const visit = (id: string): void => { if (visiting.has(id)) throw new Error("TEAM_PLAN_CYCLE"); if (visited.has(id)) return; visiting.add(id); for (const dependency of byId.get(id)?.depends_on ?? []) visit(dependency); visiting.delete(id); visited.add(id); };
  for (const node of nodes) visit(node.role_id);
}
function rehashPlan(plan: RoutingPlan): RoutingPlan {
  const { plan_hash: ignored, ...content } = plan;
  return immutable({ ...content, plan_hash: canonicalSha256(content) });
}
function rehashBindings(set: Omit<ExecutionBindingSet, "binding_set_hash"> | ExecutionBindingSet): ExecutionBindingSet {
  const { binding_set_hash: ignored, ...content } = set as ExecutionBindingSet;
  return immutable({ ...content, binding_set_hash: canonicalSha256(content) });
}

export const phase5Schemas = {
  taskFingerprint: taskFingerprintSchema,
  roleDefinition: roleDefinitionSchema,
  teamPlan: teamPlanSchema,
  agentProfile: agentProfileSchema,
  teamBlueprint: teamBlueprintSchema,
  candidate: candidateSchema,
  candidateSet: candidateSetSchema,
  routingContextSnapshot: routingContextSnapshotSchema,
  routingPolicy: routingPolicySchema,
  routingPlan: routingPlanSchema,
  fallbackGraph: fallbackGraphSchema,
  executionBindingSet: executionBindingSetSchema,
  handoffPackage: handoffPackageSchema,
  routingOutcome: routingOutcomeSchema,
};
