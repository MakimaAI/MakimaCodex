import { describe, expect, test } from "bun:test";
import {
  createBenchmarkSuite,
  createCapabilityClaim,
  createCapabilityObservation,
  createExecutionConfiguration,
  createModelVersion,
  createRoleProfile,
  transitionModelLifecycle,
} from "../src/oef/phase4";

const at = "2026-07-24T08:00:00.000Z";

describe("Phase 4 model intelligence domain", () => {
  test("separates stable model identity, provider claims, observations, and execution configuration identity", () => {
    const model = createModelVersion({
      model_version_id: "model-version:acme/atlas/2026-07",
      family_id: "model-family:acme/atlas",
      provider_id: "provider:acme",
      provider_model_name: "atlas-latest",
      release: { first_seen_at: at, provider_release_date: null, knowledge_cutoff: null },
      modalities: { text_input: true, image_input: false, text_output: true },
      context: { advertised_tokens: 128_000, observed_safe_tokens: null },
      lifecycle_status: "DISCOVERED",
      provenance: [{ source_type: "provider-api", observed_at: at, content_hash: `sha256:${"1".repeat(64)}` }],
    });
    const claim = createCapabilityClaim({
      claim_id: "capability-claim:atlas-tools",
      model_version_id: model.model_version_id,
      capability: "tool-calling",
      claimed_value: "supported",
      source: { type: "official-documentation", source_hash: `sha256:${"2".repeat(64)}` },
      observed_at: at,
      expires_at: "2026-08-24T08:00:00.000Z",
      confidence: "medium",
    });
    const observation = createCapabilityObservation({
      observation_id: "capability-observation:atlas-tools",
      execution_config_id: "execution-config:atlas-backend",
      capability: "tool-calling",
      probe_version: "tool-call-probe@1.0.0",
      result: { status: "passed", valid_calls: 98, invalid_calls: 2, total_calls: 100 },
      evidence_refs: ["artifact:probe-atlas"],
      observed_at: at,
    });
    const config = createExecutionConfiguration({
      execution_config_id: "execution-config:atlas-backend",
      model: { version_id: model.model_version_id, deployment_id: "deployment:acme/global/atlas" },
      runtime: { id: "runtime:codex-local", adapter_version: "1.0.0" },
      prompt_profile: { id: "backend-implementer", version: "1.0.0" },
      tool_bundle: { id: "backend-standard", version: "1.0.0" },
      context_policy: { id: "repository-balanced", version: "1.0.0" },
      generation: { temperature: 0.2, max_output_tokens: 16_000 },
      environment: { class: "isolated-test", version: "1" },
    });

    expect(model.metadata_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(claim).not.toHaveProperty("reliability");
    expect(observation.reliability).toBe(0.98);
    expect(observation.confidence_interval.lower).toBeLessThan(observation.reliability);
    expect(config.configuration_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(() => transitionModelLifecycle("DISCOVERED", "ROLE_QUALIFIED")).toThrow("INVALID_MODEL_LIFECYCLE_TRANSITION");
    expect(() => transitionModelLifecycle("SHADOW_READY", "ACTIVE")).toThrow("PHASE4_CANNOT_ACTIVATE_MODEL");
  });

  test("versions role policy and preserves public, validation, and private holdout boundaries", () => {
    const role = createRoleProfile({
      id: "backend-implementer", version: "1.0.0", objective: "Implement backend changes safely.",
      dimensions: { quality: 0.45, reliability: 0.2, contract_fidelity: 0.15, cost_score: 0.1, latency_score: 0.1 },
      hard_requirements: ["structured-output"], disqualifiers: ["critical-policy-violation"],
      minimum_tasks: { screened: 2, qualified: 3, high_confidence: 6 },
    });
    const suite = createBenchmarkSuite({
      benchmark_suite_id: "benchmark-suite:backend-core", version: "1.0.0", target_role: role.id,
      evaluator_profile_ref: { id: "backend-deterministic", version: "1.0.0" },
      environment_profile_ref: { id: "isolated-test", version: "1.0.0" },
      tasks: [
        { task_id: "benchmark-task:public-1", version: 1, split: "public_baseline", category: "bugfix", hidden_assertions: ["hidden-public"] },
        { task_id: "benchmark-task:validation-1", version: 1, split: "validation", category: "refactor", hidden_assertions: ["hidden-validation"] },
        { task_id: "benchmark-task:private-1", version: 1, split: "private_holdout", category: "concurrency", hidden_assertions: ["hidden-private"] },
      ],
      license: { allowed_use: "evaluation" },
    });

    expect(Object.values(role.dimensions).reduce((a, b) => a + b, 0)).toBeCloseTo(1);
    expect(suite.splits).toEqual({ public_baseline: 1, validation: 1, private_holdout: 1 });
    expect(suite.content_hash).toMatch(/^sha256:/);
  });
});
