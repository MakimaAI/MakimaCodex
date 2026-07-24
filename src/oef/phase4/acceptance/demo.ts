import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { FakeModelProvider } from "../adapters/fake-model-provider";
import { ModelLab, createBuiltinBenchmarkSuites, createBuiltinRoleProfiles } from "../application/model-lab";
import { SqliteModelLabStore } from "../persistence/sqlite-store";

export interface Phase4AcceptanceReport {
  schema_version: 1;
  status: "PASS" | "FAIL";
  models_discovered: number;
  model_versions_registered: number;
  runtime_protocol_probe: { status: "passed" | "failed"; runtime: string; protocol: string };
  real_model_probe: { status: "not-run"; reason: string };
  config_c_eliminated: boolean;
  quality_leader: string | null;
  balanced_leader_before_drift: string | null;
  recommendation_after_drift: string | null;
  requalification_jobs: number;
  audit_event_count: number;
  router_mutations: 0;
  secret_leaks: number;
  hidden_holdout_leaks: number;
  scorecards: Array<{ id: string; execution_config_id: string; qualification: string; valid_until: string; artifact_verified: boolean }>;
  report_hash: string;
}

export async function runPhase4AcceptanceDemo(options: { root: string; now?: () => string }): Promise<Phase4AcceptanceReport> {
  const root = resolve(options.root); mkdirSync(root, { recursive: true });
  const now = options.now ?? (() => new Date().toISOString());
  const store = new SqliteModelLabStore({ databasePath: join(root, "model-lab.sqlite") });
  const lab = new ModelLab({ store, artifactRoot: join(root, "artifacts"), now });
  const premium = new FakeModelProvider({ providerId: "provider:fake-premium", behavior: "high-quality-expensive" });
  const balanced = new FakeModelProvider({ providerId: "provider:fake-balanced", behavior: "balanced" });
  const cheap = new FakeModelProvider({ providerId: "provider:fake-cheap", behavior: "cheap-unreliable" });
  try {
    for (const role of createBuiltinRoleProfiles()) store.saveRoleProfile(role);
    for (const suite of createBuiltinBenchmarkSuites()) store.saveBenchmarkSuite(suite);
    await lab.scan(premium); await lab.scan(balanced); await lab.scan(cheap);
    const candidateModelsDiscovered = store.listModelVersions().length;
    const configA = lab.createConfiguration(premium.executionConfiguration("execution-config:premium"));
    const configB = lab.createConfiguration(balanced.executionConfiguration("execution-config:balanced"));
    const configC = lab.createConfiguration(cheap.executionConfiguration("execution-config:economy"));
    const probesA = await lab.probe(configA.execution_config_id, premium);
    const probesB = await lab.probe(configB.execution_config_id, balanced);
    const probesC = await lab.probe(configC.execution_config_id, cheap);
    const configCEliminated = (probesC.find(value => value.capability === "structured-output")?.reliability ?? 0) < .98;
    await lab.evaluate({ executionConfigId: configC.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-quick@1.0.0", attemptsPerTask: 2, provider: cheap });

    // Persist an interrupted run and resume it through a reconstructed control-plane service.
    await lab.evaluate({ executionConfigId: configA.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider: premium, interruptAfterAttempts: 2 });
    const resumedLab = new ModelLab({ store, artifactRoot: join(root, "artifacts"), now });
    const runA = await resumedLab.evaluate({ executionConfigId: configA.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider: premium });
    const runB = await resumedLab.evaluate({ executionConfigId: configB.execution_config_id, roleId: "backend-implementer", suiteRef: "benchmark-suite:backend-full@1.0.0", attemptsPerTask: 3, provider: balanced });
    const cardA = resumedLab.qualify(runA.evaluation_run_id); const cardB = resumedLab.qualify(runB.evaluation_run_id);
    const cards = [cardA, cardB];
    const qualityLeader = [...cards].sort((a, b) => (b.dimensions.quality ?? 0) - (a.dimensions.quality ?? 0))[0]?.execution_config_ref.id ?? null;
    const beforeDrift = resumedLab.recommend("backend-implementer", "balanced").selected?.execution_config_ref.id ?? null;

    premium.changeAlias("latest", "model-version:fake-premium/high-quality-expensive/revision-2");
    await resumedLab.scan(premium);
    const afterDrift = resumedLab.recommend("backend-implementer", "balanced").selected?.execution_config_ref.id ?? null;
    const runtimeProbe = await probeLocalRuntimeProtocol();
    const artifacts = cards.map(card => store.getArtifact(card.evidence_refs[0]!)!).filter(Boolean);
    const artifactText = artifacts.map(artifact => readFileSync(artifact.path, "utf8")).join("\n");
    const reportBase = {
      schema_version: 1 as const,
      status: "PASS" as const,
      models_discovered: candidateModelsDiscovered,
      model_versions_registered: store.listModelVersions().length,
      runtime_protocol_probe: runtimeProbe,
      real_model_probe: { status: "not-run" as const, reason: "Deterministic acceptance does not require external provider credentials; run `models probe` separately." },
      config_c_eliminated: configCEliminated,
      quality_leader: qualityLeader,
      balanced_leader_before_drift: beforeDrift,
      recommendation_after_drift: afterDrift,
      requalification_jobs: store.listRequalificationJobs().length,
      audit_event_count: store.listAuditEvents().length,
      router_mutations: 0 as const,
      secret_leaks: /(sk-[A-Za-z0-9_-]{12,}|bearer\s+[A-Za-z0-9._-]{16,})/i.test(artifactText) ? 1 : 0,
      hidden_holdout_leaks: [premium, balanced, cheap].flatMap(provider => provider.seenCandidateInputs).some(value => value.includes("hidden_assertions") || value.includes("hidden-")) ? 1 : 0,
      scorecards: cards.map(card => ({ id: card.scorecard_id, execution_config_id: card.execution_config_ref.id, qualification: card.qualification_level, valid_until: card.lifecycle.valid_until, artifact_verified: resumedLab.verifyArtifact(store.getArtifact(card.evidence_refs[0]!)!) })),
    };
    const checks = reportBase.models_discovered === 3 && reportBase.model_versions_registered === 4 && runtimeProbe.status === "passed" && configCEliminated && qualityLeader === configA.execution_config_id && beforeDrift === configB.execution_config_id && afterDrift === configB.execution_config_id && reportBase.requalification_jobs === 1 && reportBase.secret_leaks === 0 && reportBase.hidden_holdout_leaks === 0 && reportBase.scorecards.every(card => card.artifact_verified);
    const normalized = { ...reportBase, status: checks ? "PASS" as const : "FAIL" as const };
    const report: Phase4AcceptanceReport = { ...normalized, report_hash: canonicalSha256(normalized) };
    writeFileSync(join(root, "phase4-acceptance-report.json"), JSON.stringify(report, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
    return report;
  } finally { store.close(); }
}

async function probeLocalRuntimeProtocol(): Promise<Phase4AcceptanceReport["runtime_protocol_probe"]> {
  const program = "const chunks=[];for await(const c of process.stdin)chunks.push(c);const x=JSON.parse(Buffer.concat(chunks).toString());process.stdout.write(JSON.stringify({structured:typeof x.prompt==='string',tool_call:{name:'phase4_probe',arguments:{ok:true}}}));";
  const child = Bun.spawn([process.execPath, "-e", program], { stdin: "pipe", stdout: "pipe", stderr: "pipe" });
  child.stdin.write(JSON.stringify({ prompt: "Return a structured tool call." })); child.stdin.end();
  const output = await new Response(child.stdout).text(); const exit = await child.exited;
  try { const parsed = JSON.parse(output) as { structured?: unknown; tool_call?: { name?: unknown } }; if (exit === 0 && parsed.structured === true && parsed.tool_call?.name === "phase4_probe") return { status: "passed", runtime: `bun-${Bun.version}`, protocol: "structured-tool-call@1" }; } catch { /* fail closed */ }
  return { status: "failed", runtime: `bun-${Bun.version}`, protocol: "structured-tool-call@1" };
}
