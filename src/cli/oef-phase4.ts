import { mkdirSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  ModelLab, OpenAiCompatibleModelProvider, SqliteModelLabStore, createBuiltinBenchmarkSuites,
  createBuiltinRoleProfiles, runPhase4AcceptanceDemo, type EnvironmentSecretRef,
} from "../oef/phase4";

interface ParsedArgs { positionals: string[]; options: Map<string, string | true>; json: boolean }

export async function cmdOefPhase4(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  try {
    if (group === "oef-phase4-demo") {
      const report = await runPhase4AcceptanceDemo({ root: resolve(required(parsed, "root")) });
      print(report, parsed.json); return report.status === "PASS" ? 0 : 1;
    }
    const home = resolve(option(parsed, "home") ?? join(process.cwd(), ".opencodex", "model-lab"));
    mkdirSync(home, { recursive: true });
    const store = new SqliteModelLabStore({ databasePath: join(home, "model-lab.sqlite") });
    const lab = new ModelLab({ store, artifactRoot: join(home, "artifacts") });
    try {
      seedDefinitions(store);
      const value = group === "models" ? await modelCommand(lab, parsed) : group === "benchmark" ? await benchmarkCommand(lab, parsed) : fail(`Unknown Phase 4 command group: ${group}`);
      print(value, parsed.json); return 0;
    } finally { store.close(); }
  } catch (error) { console.error(error instanceof Error ? error.message : String(error)); return 1; }
}

async function modelCommand(lab: ModelLab, parsed: ParsedArgs): Promise<unknown> {
  const command = parsed.positionals[0] ?? "help";
  if (command === "help") return { commands: ["scan", "list", "show", "aliases", "probe", "screen", "qualify", "compare", "scorecard", "recommend", "requalify", "quarantine"], json_supported: true, production_routing_mutation: false };
  if (command === "list") return lab.store.listModelVersions();
  if (command === "show") {
    const id = positional(parsed, 1, "model version id");
    return lab.store.getModelVersion(id) ?? fail(`Model version not found: ${id}`);
  }
  if (command === "aliases") return lab.store.listAliases();
  if (command === "scorecard") {
    const configId = positional(parsed, 1, "execution configuration id"); const role = required(parsed, "role");
    return lab.store.listScorecards(role).filter(card => card.execution_config_ref.id === configId);
  }
  if (command === "recommend") return lab.recommend(required(parsed, "role"), profile(option(parsed, "profile") ?? "balanced"));
  if (command === "compare") {
    const role = required(parsed, "role"); const ids = parsed.positionals.slice(1);
    if (ids.length < 2) fail("At least two execution configuration ids are required");
    return lab.store.listScorecards(role).filter(card => ids.includes(card.execution_config_ref.id)).sort((a, b) => b.utility - a.utility);
  }
  if (command === "requalify") return lab.requestRequalification(positional(parsed, 1, "execution configuration id"), requalificationType(option(parsed, "type") ?? "targeted"), required(parsed, "reason"));
  if (command === "quarantine") {
    const configId = positional(parsed, 1, "execution configuration id");
    if (!lab.store.getExecutionConfiguration(configId)) fail(`Execution configuration not found: ${configId}`);
    const reason = required(parsed, "reason"); lab.quarantine(configId, reason);
    return { execution_config_id: configId, status: "QUARANTINED", reason, production_activation: false };
  }
  if (command === "qualify") return lab.qualify(option(parsed, "run") ?? positional(parsed, 1, "evaluation run id"));

  const adapter = realAdapter(parsed);
  const snapshot = await lab.scan(adapter);
  if (command === "scan") return snapshot;
  const configId = command === "probe" ? positional(parsed, 1, "execution configuration id") : required(parsed, "execution-config");
  let config = lab.store.getExecutionConfiguration(configId);
  if (!config) config = lab.createConfiguration(adapter.executionConfiguration(configId));
  if (command === "probe") return lab.probe(config.execution_config_id, adapter);
  await lab.probe(config.execution_config_id, adapter);
  if (command === "screen") return lab.evaluate({ executionConfigId: config.execution_config_id, roleId: required(parsed, "role"), suiteRef: option(parsed, "suite") ?? "benchmark-suite:backend-quick@1.0.0", attemptsPerTask: 2, provider: adapter, qualificationCycle: option(parsed, "cycle") });
  fail(`Unknown models command: ${command}`);
}

async function benchmarkCommand(lab: ModelLab, parsed: ParsedArgs): Promise<unknown> {
  const store = lab.store;
  const command = parsed.positionals[0] ?? "help";
  if (command === "help") return { commands: ["list", "show", "validate", "run"], json_supported: true };
  if (command === "list") return store.listBenchmarkSuites().map(suite => publicBenchmarkSuite(suite, false));
  const ref = positional(parsed, 1, "benchmark suite ref"); const at = ref.lastIndexOf("@");
  if (at <= 0) fail("Benchmark suite ref must include @version");
  const suite = store.getBenchmarkSuite(ref.slice(0, at), ref.slice(at + 1)) ?? fail(`Benchmark suite not found: ${ref}`);
  if (command === "show") return publicBenchmarkSuite(suite, true);
  if (command === "validate") return { valid: suite.tasks.length === Object.values(suite.splits).reduce((a, b) => a + b, 0), suite_ref: ref, content_hash: suite.content_hash, private_holdout_tasks: suite.splits.private_holdout };
  if (command === "run") {
    const adapter = realAdapter(parsed); await lab.scan(adapter);
    const configId = required(parsed, "execution-config");
    let config = store.getExecutionConfiguration(configId);
    if (!config) config = lab.createConfiguration(adapter.executionConfiguration(configId));
    await lab.probe(configId, adapter);
    return lab.evaluate({ executionConfigId: configId, roleId: option(parsed, "role") ?? suite.target_role, suiteRef: ref, attemptsPerTask: integerOption(parsed, "attempts", 3), provider: adapter, qualificationCycle: option(parsed, "cycle") });
  }
  return fail(`Unknown benchmark command: ${command}`);
}

function realAdapter(parsed: ParsedArgs): OpenAiCompatibleModelProvider {
  const secretName = required(parsed, "secret-env");
  const secretRef: EnvironmentSecretRef = { type: "environment", name: secretName };
  const protocol = option(parsed, "protocol") ?? "chat-completions";
  if (protocol !== "chat-completions" && protocol !== "responses") fail("Protocol must be chat-completions or responses");
  const catalogMode = option(parsed, "catalog-mode") ?? "live";
  if (catalogMode !== "live" && catalogMode !== "selected") fail("Catalog mode must be live or selected");
  return new OpenAiCompatibleModelProvider({ providerId: required(parsed, "provider-id"), baseUrl: required(parsed, "url"), selectedModel: required(parsed, "model"), secretRef, probeAttempts: integerOption(parsed, "probe-attempts", 3), protocol, catalogMode });
}
function seedDefinitions(store: SqliteModelLabStore): void { for (const role of createBuiltinRoleProfiles()) store.saveRoleProfile(role); for (const suite of createBuiltinBenchmarkSuites()) store.saveBenchmarkSuite(suite); }
function publicBenchmarkSuite(suite: ReturnType<SqliteModelLabStore["listBenchmarkSuites"]>[number], includeTasks: boolean): unknown {
  return {
    schema_version: suite.schema_version,
    benchmark_suite_id: suite.benchmark_suite_id,
    version: suite.version,
    target_role: suite.target_role,
    evaluator_profile_ref: suite.evaluator_profile_ref,
    environment_profile_ref: suite.environment_profile_ref,
    splits: suite.splits,
    task_count: suite.tasks.length,
    tasks: includeTasks ? suite.tasks.map(task => ({ task_id: task.task_id, version: task.version, split: task.split, category: task.category, sensitivity: task.sensitivity, contamination_risk: task.provenance.contamination_risk })) : undefined,
    license: suite.license,
    content_hash: suite.content_hash,
  };
}
function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = []; const options = new Map<string, string | true>(); let json = false;
  for (let index = 0; index < args.length; index++) {
    const value = args[index]!;
    if (value === "--json") { json = true; continue; }
    if (!value.startsWith("--")) { positionals.push(value); continue; }
    const key = value.slice(2); const next = args[index + 1];
    if (next && !next.startsWith("--")) { options.set(key, next); index++; } else options.set(key, true);
  }
  return { positionals, options, json };
}
function option(parsed: ParsedArgs, key: string): string | undefined { const value = parsed.options.get(key); return typeof value === "string" ? value : undefined; }
function required(parsed: ParsedArgs, key: string): string { return option(parsed, key) ?? fail(`Missing required option --${key}`); }
function positional(parsed: ParsedArgs, index: number, label: string): string { return parsed.positionals[index] ?? fail(`Missing ${label}`); }
function integerOption(parsed: ParsedArgs, key: string, fallback: number): number { const value = option(parsed, key); if (!value) return fallback; const parsedValue = Number(value); return Number.isInteger(parsedValue) ? parsedValue : fail(`Invalid integer --${key}`); }
function profile(value: string): "premium" | "balanced" | "economy" { return value === "premium" || value === "balanced" || value === "economy" ? value : fail("Profile must be premium, balanced, or economy"); }
function requalificationType(value: string): "full" | "targeted" | "incident-driven" | "periodic" { return value === "full" || value === "targeted" || value === "incident-driven" || value === "periodic" ? value : fail("Invalid requalification type"); }
function print(value: unknown, json: boolean): void { console.log(JSON.stringify(value, null, json ? 0 : 2)); }
function fail(message: string): never { throw new Error(message); }
