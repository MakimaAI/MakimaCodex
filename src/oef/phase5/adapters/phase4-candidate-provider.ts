import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { CapabilityObservation, ExecutionConfiguration, ModelVersion, RoleScorecard } from "../../phase4";
import { createBuiltinAgentProfiles, type Candidate, type PrivacyLevel } from "../core/domain";

export interface Phase4CandidateReadPort {
  listScorecards(roleId?: string): RoleScorecard[];
  getExecutionConfiguration(id: string): ExecutionConfiguration | null;
  getModelVersion(id: string): ModelVersion | null;
  listObservations(configId: string): CapabilityObservation[];
  isConfigurationQuarantined(id: string): boolean;
  isConfigurationStale(id: string): boolean;
}

export interface CandidateAvailability {
  runtime_healthy: boolean; provider_healthy: boolean; account_capacity: number;
  observed_at: string; expires_at: string; account_pool: string[]; sandbox_enforced: boolean;
}

export class Phase4CandidateProvider {
  constructor(private readonly source: Phase4CandidateReadPort, private readonly policy: {
    availability: (input: { roleId: string; scorecard: RoleScorecard; configuration: ExecutionConfiguration; model: ModelVersion }) => CandidateAvailability;
    privacyClasses: (providerId: string) => PrivacyLevel[];
  }) {}

  forRole(roleId: string): Candidate[] {
    const candidates: Candidate[] = [];
    for (const scorecard of this.source.listScorecards(roleId)) {
      const { scorecard_hash: ignoredScorecardHash, ...scorecardContent } = scorecard;
      if (canonicalSha256(scorecardContent) !== scorecard.scorecard_hash) throw new Error("PHASE4_SCORECARD_HASH_MISMATCH");
      const configuration = this.source.getExecutionConfiguration(scorecard.execution_config_ref.id);
      if (!configuration || configuration.configuration_hash !== scorecard.execution_config_ref.hash) continue;
      const model = this.source.getModelVersion(configuration.model.version_id);
      if (!model) continue;
      const availability = this.policy.availability({ roleId, scorecard, configuration, model });
      const agentProfile = createBuiltinAgentProfiles().find(value => value.role_id === roleId);
      if (!agentProfile) throw new Error(`AGENT_PROFILE_NOT_FOUND:${roleId}`);
      const observations = this.source.listObservations(configuration.execution_config_id);
      const observedCapabilities = observations.filter(value => value.result.status === "passed" || value.result.status === "partial").map(value => value.capability);
      const capabilities = unique([...baselineCapabilities(roleId), ...observedCapabilities]);
      const lifecycle = this.source.isConfigurationQuarantined(configuration.execution_config_id) ? "quarantined"
        : this.source.isConfigurationStale(configuration.execution_config_id) ? "stale" : scorecard.lifecycle.status;
      const content = {
        schema_version: 1 as const,
        candidate_id: `candidate:${roleId}-${configuration.execution_config_id.replace("execution-config:", "")}`,
        role_id: roleId, agent_profile_id: agentProfile.agent_profile_id, agent_profile_version: agentProfile.version, agent_profile_hash: agentProfile.profile_hash,
        execution_config_id: configuration.execution_config_id, execution_config_hash: configuration.configuration_hash,
        scorecard_id: scorecard.scorecard_id, scorecard_hash: scorecard.scorecard_hash,
        provider_id: model.provider_id, model_version_id: model.model_version_id, runtime_id: configuration.runtime.id, runtime_adapter_version: configuration.runtime.adapter_version, deployment_id: configuration.model.deployment_id,
        qualification_level: scorecard.qualification_level, lifecycle_status: lifecycle, valid_until: scorecard.lifecycle.valid_until,
        capabilities, modalities: ["text", ...(model.modalities.image_input ? ["image"] : [])],
        context_tokens: model.context.observed_safe_tokens ?? model.context.advertised_tokens ?? 0,
        permission_envelope: [...agentProfile.permission_envelope], sandbox_enforced: availability.sandbox_enforced,
        privacy_classes: unique(this.policy.privacyClasses(model.provider_id)),
        metrics: {
          role_quality: bounded(scorecard.dimensions.quality ?? scorecard.utility), task_similarity: bounded(scorecard.dimensions.task_similarity ?? scorecard.utility * 0.9),
          repository_affinity: bounded(scorecard.dimensions.repository_affinity ?? scorecard.utility * 0.85),
          tool_reliability: bounded(scorecard.reliability.tool_protocol_rate), structured_output_reliability: bounded(scorecard.reliability.structured_output_rate),
          operational_reliability: bounded(1 - scorecard.reliability.timeout_rate), availability: availability.runtime_healthy && availability.provider_healthy ? 1 : 0,
          confidence_lower: bounded(scorecard.confidence.interval_95.lower), confidence_mean: bounded(scorecard.utility), incident_penalty: 0,
          staleness_penalty: lifecycle === "stale" ? 1 : 0, cost_p50: nonnegative(scorecard.operations.mean_cost_units),
          cost_p90: round(nonnegative(scorecard.operations.mean_cost_units) * 1.5), latency_p50_ms: nonnegative(scorecard.operations.mean_latency_ms),
          latency_p90_ms: round(nonnegative(scorecard.operations.mean_latency_ms) * 1.5),
        },
        availability: { runtime_healthy: availability.runtime_healthy, provider_healthy: availability.provider_healthy, account_capacity: availability.account_capacity, observed_at: availability.observed_at, expires_at: availability.expires_at },
        account_pool: [...availability.account_pool],
      };
      candidates.push(immutable({ ...content, candidate_hash: canonicalSha256(content) }));
    }
    return candidates.sort((a, b) => a.candidate_id.localeCompare(b.candidate_id));
  }
}

function baselineCapabilities(roleId: string): string[] {
  if (roleId.includes("implementer")) return ["repository-read", "repository-write", "shell", "test-execution", "structured-output"];
  if (roleId === "internet-researcher") return ["repository-read", "network-access", "structured-output"];
  if (roleId === "test-engineer") return ["repository-read", "repository-write", "shell", "test-execution", "structured-output"];
  if (roleId === "visual-reviewer") return ["repository-read", "browser", "image-input", "structured-output"];
  return ["repository-read", "structured-output"];
}
function bounded(value: number): number { return Math.max(0, Math.min(1, value)); }
function nonnegative(value: number): number { return Math.max(0, value); }
function round(value: number): number { return Math.round(value * 1_000_000) / 1_000_000; }
function unique<T>(values: T[]): T[] { return [...new Set(values)]; }
function immutable<T>(value: T): T { if (value && typeof value === "object") { for (const child of Object.values(value as Record<string, unknown>)) immutable(child); Object.freeze(value); } return value; }
