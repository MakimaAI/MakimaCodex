import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { createExecutionConfiguration, createModelVersion, type ExecutionConfiguration, type ModelVersion } from "../core/domain";
import { createExecutionReceipt, type CandidateTaskResult, type ModelCatalogAdapter, type ProbeMeasurement, type ProviderCatalogSnapshot } from "../application/model-lab";

export type FakeModelBehavior = "always-pass" | "always-fail" | "malformed-json" | "slow-model" | "rate-limited" | "high-quality-expensive" | "balanced" | "cheap-unreliable" | "tool-call-broken" | "alias-changed" | "secret-leaking";

export class FakeModelProvider implements ModelCatalogAdapter {
  readonly providerId: string;
  readonly adapterVersion = "1.0.0";
  readonly seenCandidateInputs: string[] = [];
  private currentVersionId: string;
  private readonly aliases = new Map<string, string>();
  private failDiscovery = false;

  constructor(private readonly options: { providerId: string; behavior: FakeModelBehavior }) {
    this.providerId = options.providerId;
    const slug = providerSlug(this.providerId);
    this.currentVersionId = `model-version:${slug}/${behaviorSlug(options.behavior)}/revision-1`;
    this.aliases.set("latest", this.currentVersionId);
  }

  failNextDiscovery(): void { this.failDiscovery = true; }
  changeAlias(alias: string, modelVersionId: string): void { this.currentVersionId = modelVersionId; this.aliases.set(alias, modelVersionId); }

  async discoverModels(): Promise<ProviderCatalogSnapshot> {
    if (this.failDiscovery) { this.failDiscovery = false; throw new Error("injected catalog outage"); }
    const model = this.model();
    const observedAt = "2026-07-24T08:00:00.000Z";
    const aliases = [...this.aliases].map(([alias, resolved_model_version_id]) => ({ alias, resolved_model_version_id, metadata_hash: model.metadata_hash }));
    const content = { provider_id: this.providerId, adapter_version: this.adapterVersion, models: [model], aliases, observed_at: observedAt };
    return { ...content, snapshot_hash: canonicalSha256(content) };
  }

  executionConfiguration(id: string): ExecutionConfiguration {
    return createExecutionConfiguration(this.configurationInput(id));
  }

  private configurationInput(id: string): Parameters<typeof createExecutionConfiguration>[0] {
    return {
      execution_config_id: id, model: { version_id: this.currentVersionId, deployment_id: `deployment:${providerSlug(this.providerId)}/global/${behaviorSlug(this.options.behavior)}` },
      runtime: { id: "runtime:codex-local", adapter_version: "1.0.0" }, prompt_profile: { id: "backend-implementer", version: "1.0.0" },
      tool_bundle: { id: "backend-standard", version: "1.0.0" }, context_policy: { id: "repository-balanced", version: "1.0.0" },
      generation: { temperature: 0.2, max_output_tokens: 16_000 }, environment: { class: "phase2-runner-isolated", version: "1" },
    };
  }

  async probe(config: ExecutionConfiguration): Promise<ProbeMeasurement[]> {
    this.assertConfiguration(config);
    const structured = ["malformed-json", "cheap-unreliable"].includes(this.options.behavior) ? 70 : 100;
    const tools = this.options.behavior === "tool-call-broken" ? 60 : 99;
    const critical = this.options.behavior === "secret-leaking" ? ["secret-leak"] : undefined;
    return [
      this.measurement(config, "basic-response", "passed", 20, 20),
      this.measurement(config, "structured-output", structured >= 98 ? "passed" : "failed", structured, 100),
      { ...this.measurement(config, "tool-calling", tools >= 97 ? "passed" : "partial", tools, 100), critical_violations: critical },
      this.measurement(config, "streaming", "passed", 20, 20),
      this.measurement(config, "cancellation", "passed", 20, 20),
    ];
  }

  async executeTask(input: { candidateInput: string; executionConfig: ExecutionConfiguration; seed: number; idempotencyKey: string }): Promise<CandidateTaskResult> {
    this.assertConfiguration(input.executionConfig);
    this.seenCandidateInputs.push(input.candidateInput);
    const presets: Record<FakeModelBehavior, { q: number; r: number; c: number; l: number }> = {
      "always-pass": { q: .99, r: .99, c: .4, l: .3 }, "always-fail": { q: .1, r: .2, c: .2, l: .2 },
      "malformed-json": { q: .55, r: .5, c: .2, l: .2 }, "slow-model": { q: .88, r: .9, c: .5, l: .95 },
      "rate-limited": { q: .8, r: .4, c: .3, l: .8 }, "high-quality-expensive": { q: .95, r: .97, c: .92, l: .78 },
      "balanced": { q: .89, r: .99, c: .35, l: .32 }, "cheap-unreliable": { q: .76, r: .68, c: .08, l: .18 },
      "tool-call-broken": { q: .7, r: .55, c: .3, l: .3 }, "alias-changed": { q: .84, r: .85, c: .4, l: .4 },
      "secret-leaking": { q: .9, r: .9, c: .4, l: .4 },
    };
    const preset = presets[this.options.behavior];
    const failure = this.options.behavior === "rate-limited" ? "RATE_LIMIT" as const : this.options.behavior === "always-fail" ? "MODEL_FAILURE" as const : undefined;
    let answer = "incorrect-solution";
    try {
      const task = JSON.parse(input.candidateInput) as { prompt?: unknown };
      const prompt = typeof task.prompt === "string" ? task.prompt : "";
      const sum = prompt.match(/integer sum (\d+) \+ (\d+)/);
      const marker = prompt.match(/solution marker "([^"]+)"/);
      const succeeds = ["high-quality-expensive", "balanced", "always-pass"].includes(this.options.behavior)
        || ((input.seed >>> 0) % 100) < Math.round(preset.q * 100);
      if (sum && succeeds) answer = String(Number(sum[1]) + Number(sum[2]));
      else if (marker?.[1] && succeeds) answer = marker[1];
    } catch { /* malformed candidate input remains incorrect */ }
    return {
      output: this.options.behavior === "secret-leaking"
        ? `api_key=${["sk", "phase4-test-secret-123456789"].join("-")}`
        : JSON.stringify({ answer, complete: preset.r >= .75, contract: true, task: canonicalSha256(input.candidateInput) }),
      cost_units: preset.c, latency_ms: preset.l * 1000, failure_type: failure, critical_violations: this.options.behavior === "secret-leaking" ? ["secret-leak"] : [],
      execution_receipt: createExecutionReceipt(this, input.executionConfig, input.idempotencyKey),
    };
  }

  private measurement(config: ExecutionConfiguration, capability: string, status: ProbeMeasurement["status"], valid: number, total: number): ProbeMeasurement {
    return { capability, status, valid_calls: valid, invalid_calls: total - valid, total_calls: total, execution_receipt: createExecutionReceipt(this, config, `probe:${capability}`) };
  }
  private assertConfiguration(config: ExecutionConfiguration): void {
    if (createExecutionConfiguration(this.configurationInput(config.execution_config_id)).configuration_hash !== config.configuration_hash || config.model.version_id !== this.currentVersionId) throw new Error("PROVIDER_EXECUTION_CONFIG_MISMATCH");
  }

  private model(): ModelVersion {
    const slug = providerSlug(this.providerId); const price = this.options.behavior === "high-quality-expensive" ? 30 : this.options.behavior === "balanced" ? 8 : 1;
    return createModelVersion({ model_version_id: this.currentVersionId, family_id: `model-family:${slug}/${behaviorSlug(this.options.behavior)}`, provider_id: this.providerId, provider_model_name: `${behaviorSlug(this.options.behavior)}-latest`, release: { first_seen_at: "2026-07-24T08:00:00.000Z", provider_release_date: null, knowledge_cutoff: null }, modalities: { text_input: true, image_input: false, text_output: true }, context: { advertised_tokens: 128_000, observed_safe_tokens: null }, features: { tool_calling_claimed: true, structured_output_claimed: true, streaming_claimed: true }, commercial: { input_cost_per_million: price, output_cost_per_million: price * 3, currency: "USD" }, lifecycle_status: "DISCOVERED", provenance: [{ source_type: "provider-api", observed_at: "2026-07-24T08:00:00.000Z", content_hash: canonicalSha256({ provider: this.providerId, version: this.currentVersionId }) }] });
  }
}

function providerSlug(providerId: string): string { return providerId.replace(/^provider:/, "").replace(/[^A-Za-z0-9._/-]/g, "-"); }
function behaviorSlug(value: string): string { return value.replace(/[^A-Za-z0-9._-]/g, "-"); }
function clamp(value: number): number { return Math.max(0, Math.min(1, value)); }
