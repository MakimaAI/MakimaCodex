import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  FakeModelProvider,
  ModelLab,
  SqliteModelLabStore,
  createBuiltinBenchmarkSuites,
  createBuiltinRoleProfiles,
  createBenchmarkSuite,
  createCapabilityClaim,
  createExecutionReceipt,
  createModelVersion,
  createRoleProfile,
  type ModelCatalogAdapter,
} from "../src/oef/phase4";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";

const homes: string[] = [];
afterEach(() => { for (const home of homes.splice(0)) { try { rmSync(home, { recursive: true, force: true }); } catch { /* Bun may retain a closed WAL handle briefly on Windows. */ } } });

function lab() {
  const home = mkdtempSync(join(tmpdir(), "oef-phase4-")); homes.push(home);
  const store = new SqliteModelLabStore({ databasePath: join(home, "lab.sqlite") });
  const value = new ModelLab({ store, artifactRoot: join(home, "artifacts"), now: () => "2026-07-24T08:00:00.000Z" });
  for (const role of createBuiltinRoleProfiles()) store.saveRoleProfile(role);
  for (const suite of createBuiltinBenchmarkSuites()) store.saveBenchmarkSuite(suite);
  return { home, store, lab: value };
}

describe("Phase 4 qualification governance", () => {
  test("fails closed on provider errors, protects holdout/evaluator state, and never qualifies incomplete runs", async () => {
    const fixture = lab();
    try {
      const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "high-quality-expensive" });
      await fixture.lab.scan(provider);
      const before = fixture.store.listModelVersions();
      provider.failNextDiscovery();
      await expect(fixture.lab.scan(provider)).rejects.toThrow("PROVIDER_FAILURE");
      expect(fixture.store.listModelVersions()).toEqual(before);

      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:high"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const incomplete = await fixture.lab.evaluate({
        executionConfigId: config.execution_config_id, roleId: "backend-implementer",
        suiteRef: "benchmark-suite:backend-quick@1.0.0", attemptsPerTask: 1, provider,
        interruptAfterAttempts: 1,
      });
      expect(incomplete.status).toBe("INCOMPLETE");
      expect(fixture.store.listScorecards("backend-implementer")).toHaveLength(0);
      expect(provider.seenCandidateInputs.some(value => value.includes("hidden_assertions"))).toBeFalse();
      expect(provider.seenCandidateInputs.some(value => value.includes("evaluator"))).toBeFalse();
    } finally { fixture.store.close(); }
  });

  test("detects alias drift, filters stale/quarantined cards, and resumes idempotently after restart", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:balanced"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const run = await fixture.lab.evaluate({
        executionConfigId: config.execution_config_id, roleId: "backend-implementer",
        suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider,
      });
      const scorecard = fixture.lab.qualify(run.evaluation_run_id);
      expect(scorecard.qualification_level).toBe("Q3");
      const artifact = fixture.store.getArtifact(scorecard.evidence_refs[0]!);
      expect(artifact && fixture.lab.verifyArtifact(artifact)).toBeTrue();

      fixture.store.close();
      const reopened = new SqliteModelLabStore({ databasePath: join(fixture.home, "lab.sqlite") });
      const resumed = new ModelLab({ store: reopened, artifactRoot: join(fixture.home, "artifacts"), now: () => "2026-07-24T08:00:00.000Z" });
      expect(resumed.qualify(run.evaluation_run_id).scorecard_id).toBe(scorecard.scorecard_id);

      provider.changeAlias("latest", "model-version:fake/balanced/revision-2");
      await resumed.scan(provider);
      expect(reopened.listRequalificationJobs()).toHaveLength(1);
      expect(resumed.recommend("backend-implementer", "balanced").selected).toBeNull();
      reopened.close();
    } finally {
      try { fixture.store.close(); } catch { /* already closed */ }
    }
  });

  test("coalesces duplicate evaluations and rejects a scorecard whose artifact was tampered", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:coalesced"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const request = { executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider };
      const [first, duplicate] = await Promise.all([fixture.lab.evaluate(request), fixture.lab.evaluate(request)]);
      expect(first.evaluation_run_id).toBe(duplicate.evaluation_run_id);
      expect(provider.seenCandidateInputs).toHaveLength(9);
      const card = fixture.lab.qualify(first.evaluation_run_id);
      const artifact = fixture.store.getArtifact(card.evidence_refs[0]!)!;
      writeFileSync(artifact.path, "{\"tampered\":true}\n", "utf8");
      expect(fixture.lab.recommend("backend-implementer", "balanced")).toMatchObject({ selected: null, excluded: [{ reason: "invalid-scorecard-artifact" }] });
    } finally { fixture.store.close(); }
  });

  test("turns silent metadata drift under the same provider model id into an immutable observed revision", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:metadata-drift"));
      const drifting: ModelCatalogAdapter = {
        providerId: provider.providerId, adapterVersion: provider.adapterVersion,
        async discoverModels() {
          const snapshot = await provider.discoverModels(); const original = snapshot.models[0]!;
          const changed = createModelVersion({
            model_version_id: original.model_version_id, family_id: original.family_id, provider_id: original.provider_id,
            provider_model_name: original.provider_model_name, release: original.release, modalities: original.modalities,
            context: { ...original.context, advertised_tokens: 256_000 }, features: original.features, commercial: original.commercial,
            lifecycle_status: original.lifecycle_status, provenance: original.provenance,
          });
          const aliases = snapshot.aliases.map(alias => ({ ...alias, metadata_hash: changed.metadata_hash }));
          const content = { provider_id: snapshot.provider_id, adapter_version: snapshot.adapter_version, models: [changed], aliases, observed_at: snapshot.observed_at };
          return { ...content, snapshot_hash: canonicalSha256(content) };
        },
        probe: value => provider.probe(value), executeTask: value => provider.executeTask(value),
      };
      await fixture.lab.scan(drifting);
      expect(fixture.store.listModelVersions()).toHaveLength(2);
      expect(fixture.store.isConfigurationStale(config.execution_config_id)).toBeTrue();
      expect(fixture.store.listRequalificationJobs()).toHaveLength(1);
      expect(fixture.store.listAuditEvents().some(event => event.event_type === "model.revision.detected")).toBeTrue();
      await fixture.lab.scan(drifting);
      expect(fixture.store.listRequalificationJobs()).toHaveLength(1);
    } finally { fixture.store.close(); }
  });

  test("persists claims separately and refuses provider/config identity substitution", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      const snapshot = await fixture.lab.scan(provider); const model = snapshot.models[0]!;
      const claim = createCapabilityClaim({
        claim_id: "capability-claim:separate", model_version_id: model.model_version_id, capability: "tool-calling", claimed_value: "supported",
        source: { type: "official-documentation", source_hash: `sha256:${"c".repeat(64)}` }, observed_at: "2026-07-24T08:00:00.000Z",
        expires_at: "2026-08-24T08:00:00.000Z", confidence: "medium",
      });
      fixture.lab.recordCapabilityClaim(claim);
      expect(fixture.store.listCapabilityClaims(model.model_version_id)).toEqual([claim]);
      expect(fixture.store.listObservations("execution-config:none")).toEqual([]);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:provider-bound"));
      const substituted: ModelCatalogAdapter = {
        providerId: "provider:other", adapterVersion: provider.adapterVersion,
        discoverModels: () => provider.discoverModels(), probe: value => provider.probe(value), executeTask: value => provider.executeTask(value),
      };
      await expect(fixture.lab.probe(config.execution_config_id, substituted)).rejects.toThrow("PROVIDER_EXECUTION_CONFIG_MISMATCH");
    } finally { fixture.store.close(); }
  });

  test("does not treat candidate completion claims as deterministic task success and recovers dead attempt leases", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:untrusted-output"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const lying: ModelCatalogAdapter = {
        providerId: provider.providerId, adapterVersion: provider.adapterVersion, discoverModels: () => provider.discoverModels(), probe: value => provider.probe(value),
        async executeTask(value) {
          const result = await provider.executeTask(value);
          return { ...result, output: JSON.stringify({ answer: "wrong", complete: true, contract: true, task: canonicalSha256(value.candidateInput) }) };
        },
      };
      const run = await fixture.lab.evaluate({ executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider: lying });
      expect(run.attempts.every(attempt => attempt.dimensions.quality === 0)).toBeTrue();
      expect(() => fixture.lab.qualify(run.evaluation_run_id)).toThrow("QUALIFICATION_HARD_GATE_FAILED");

      expect(fixture.store.claimEvaluationAttempt({ attemptId: "evaluation-attempt:dead-owner", runId: run.evaluation_run_id, owner: "process:2147483646", now: "2026-07-24T08:00:00.000Z", leaseExpiresAt: "2099-01-01T00:00:00.000Z" }).status).toBe("claimed");
      new ModelLab({ store: fixture.store, artifactRoot: join(fixture.home, "artifacts") });
      expect(fixture.store.claimEvaluationAttempt({ attemptId: "evaluation-attempt:dead-owner", runId: run.evaluation_run_id, owner: `process:${process.pid}`, now: "2026-07-24T08:00:00.000Z", leaseExpiresAt: "2099-01-01T00:00:00.000Z" }).status).toBe("claimed");
      expect(fixture.store.claimEvaluationAttempt({ attemptId: "evaluation-attempt:expired-live-owner", runId: run.evaluation_run_id, owner: `process:${process.pid}:old-worker`, now: "2026-07-24T08:00:00.000Z", leaseExpiresAt: "2026-07-24T08:01:00.000Z" }).status).toBe("claimed");
      expect(fixture.store.claimEvaluationAttempt({ attemptId: "evaluation-attempt:expired-live-owner", runId: run.evaluation_run_id, owner: `process:${process.pid}:new-worker`, now: "2026-07-24T08:02:00.000Z", leaseExpiresAt: "2026-07-24T08:07:00.000Z" }).status).toBe("claimed");
    } finally { fixture.store.close(); }
  });

  test("uses the newest probe observation and invalidates a scorecard after structured-output regression", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:reprobe"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const run = await fixture.lab.evaluate({ executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider });
      fixture.lab.qualify(run.evaluation_run_id);
      const regressed: ModelCatalogAdapter = {
        providerId: provider.providerId, adapterVersion: provider.adapterVersion, discoverModels: () => provider.discoverModels(), executeTask: value => provider.executeTask(value),
        async probe(value) {
          const measurements = await provider.probe(value);
          return measurements.map(measurement => measurement.capability === "structured-output" ? {
            ...measurement, status: "failed" as const, valid_calls: 0, invalid_calls: 100, total_calls: 100,
            execution_receipt: createExecutionReceipt(this, value, "probe:structured-output"),
          } : measurement);
        },
      };
      await fixture.lab.probe(config.execution_config_id, regressed);
      expect(fixture.store.listObservations(config.execution_config_id).find(value => value.capability === "structured-output")?.reliability).toBe(0);
      expect(() => fixture.lab.qualify(run.evaluation_run_id)).toThrow("QUALIFICATION_HARD_GATE_FAILED");
      expect(fixture.lab.recommend("backend-implementer", "balanced").selected).toBeNull();
    } finally { fixture.store.close(); }
  });

  test("serializes attempt ownership across two ModelLab instances in the same process", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    let secondStore: SqliteModelLabStore | null = null;
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:two-labs"));
      await fixture.lab.probe(config.execution_config_id, provider);
      secondStore = new SqliteModelLabStore({ databasePath: join(fixture.home, "lab.sqlite") });
      const secondLab = new ModelLab({ store: secondStore, artifactRoot: join(fixture.home, "artifacts"), now: () => "2026-07-24T08:00:00.000Z" });
      const request = { executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider };
      const results = await Promise.allSettled([fixture.lab.evaluate(request), secondLab.evaluate(request)]);
      expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
      expect(provider.seenCandidateInputs).toHaveLength(9);
      const completed = results.find(result => result.status === "fulfilled") as PromiseFulfilledResult<Awaited<ReturnType<ModelLab["evaluate"]>>>;
      const durable = fixture.store.listEvaluationAttempts(completed.value.evaluation_run_id);
      expect(durable).toHaveLength(9);
      expect(new Set(durable.map(attempt => attempt.attempt_id))).toEqual(new Set(completed.value.attempts.map(attempt => attempt.attempt_id)));
    } finally { secondStore?.close(); fixture.store.close(); }
  });

  test("reconstructs an adapter after restart and treats durable attempts as qualification authority", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "always-fail" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:durable-authority"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const run = await fixture.lab.evaluate({ executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider });
      expect(() => fixture.lab.qualify(run.evaluation_run_id)).toThrow("QUALIFICATION_HARD_GATE_FAILED");

      const attacker = new Database(join(fixture.home, "lab.sqlite"));
      const forged = { ...run, attempts: run.attempts.map(attempt => ({ ...attempt, status: "COMPLETED", dimensions: { quality: 1, reliability: 1, contract_fidelity: 1, cost_score: 1, latency_score: 1 }, failure_type: null, critical_violations: [] })) };
      attacker.query("UPDATE phase4_evaluation_runs SET run_json=? WHERE evaluation_run_id=?").run(JSON.stringify(forged), run.evaluation_run_id);
      attacker.close();
      expect(() => fixture.lab.qualify(run.evaluation_run_id)).toThrow("EVALUATION_ATTEMPT_STATE_MISMATCH");

      fixture.store.close();
      const reopened = new SqliteModelLabStore({ databasePath: join(fixture.home, "lab.sqlite") });
      const restartedLab = new ModelLab({ store: reopened, artifactRoot: join(fixture.home, "artifacts"), now: () => "2026-07-24T08:05:00.000Z" });
      const reconstructed = new FakeModelProvider({ providerId: "provider:fake", behavior: "always-fail" });
      await restartedLab.scan(reconstructed);
      const observations = await restartedLab.probe(config.execution_config_id, reconstructed);
      expect(observations.some(value => value.capability === "tool-calling")).toBeTrue();
      reopened.close();
    } finally { try { fixture.store.close(); } catch { /* already closed for restart */ } }
  });

  test("refreshes a scorecard after a successful later probe and rejects same-version policy conflicts", async () => {
    const fixture = lab();
    const provider = new FakeModelProvider({ providerId: "provider:fake", behavior: "balanced" });
    try {
      await fixture.lab.scan(provider);
      const config = fixture.lab.createConfiguration(provider.executionConfiguration("execution-config:refresh-card"));
      await fixture.lab.probe(config.execution_config_id, provider);
      const run = await fixture.lab.evaluate({ executionConfigId: config.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider });
      const first = fixture.lab.qualify(run.evaluation_run_id);
      const laterLab = new ModelLab({ store: fixture.store, artifactRoot: join(fixture.home, "artifacts"), now: () => "2026-07-25T08:00:00.000Z" });
      await laterLab.probe(config.execution_config_id, provider);
      const refreshed = laterLab.qualify(run.evaluation_run_id);
      expect(refreshed.scorecard_id).not.toBe(first.scorecard_id);
      expect(refreshed.version).toBe(2);
      expect(laterLab.recommend("backend-implementer", "balanced").selected?.scorecard_id).toBe(refreshed.scorecard_id);

      const role = fixture.store.getRoleProfile("backend-implementer")!;
      expect(() => fixture.store.saveRoleProfile(createRoleProfile({ id: role.id, version: role.version, objective: "Changed without version bump.", dimensions: role.dimensions, hard_requirements: role.hard_requirements, disqualifiers: role.disqualifiers, minimum_tasks: role.minimum_tasks }))).toThrow("ROLE_PROFILE_VERSION_IMMUTABLE");
      const suite = fixture.store.getBenchmarkSuite("benchmark-suite:backend-full", "1.0.0")!;
      expect(() => fixture.store.saveBenchmarkSuite(createBenchmarkSuite({ benchmark_suite_id: suite.benchmark_suite_id, version: suite.version, target_role: suite.target_role, evaluator_profile_ref: suite.evaluator_profile_ref, environment_profile_ref: suite.environment_profile_ref, tasks: suite.tasks.map(task => ({ ...task, category: task.task_id.endsWith("public") ? "changed" : task.category })), license: suite.license }))).toThrow("BENCHMARK_SUITE_VERSION_IMMUTABLE");
    } finally { fixture.store.close(); }
  });
});
