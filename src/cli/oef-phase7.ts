import { mkdirSync, readFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { SqliteOperationsStore } from "../oef/operations";
import { SqliteMemoryStore } from "../oef/phase6";
import {
  IncidentIntelligenceService,
  SqliteIncidentRegistry,
  SqlitePhase6IncidentMemoryWriter,
  collectPhase2Failure,
  runPhase7AcceptanceDemo,
  type ConfirmRootCauseInput,
  type Phase7Scope,
  type TriagePriority,
  type TriageSeverity,
} from "../oef/phase7";

interface ParsedArgs { positionals: string[]; options: Map<string, string | true>; json: boolean }

export async function cmdOefPhase7(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  const command = group === "oef-phase7-demo" ? "demo" : parsed.positionals[0] ?? "help";
  try {
    if (group !== "incident" && group !== "oef-phase7-demo") throw new Error("PHASE7_COMMAND_GROUP_UNKNOWN");
    if (command === "demo") {
      const root = resolve(required(parsed, "root"));
      const report = await runPhase7AcceptanceDemo({ root, commitSha: required(parsed, "commit-sha") });
      print(report, parsed.json);
      return report.status === "PASS" ? 0 : 1;
    }
    const home = resolve(option(parsed, "home") ?? join(process.cwd(), ".opencodex", "incidents"));
    mkdirSync(home, { recursive: true });
    const registry = new SqliteIncidentRegistry({ databasePath: join(home, "incidents.sqlite") });
    const operations = new SqliteOperationsStore({ databasePath: join(home, "operations.sqlite") });
    const memory = new SqliteMemoryStore({ databasePath: join(home, "memory.sqlite") });
    try {
      const service = new IncidentIntelligenceService({ registry, operations, memoryWriter: new SqlitePhase6IncidentMemoryWriter(memory) });
      const result = await incidentCommand(command, parsed, registry, service);
      print(result, parsed.json);
      return 0;
    } finally {
      memory.close();
      operations.close();
      registry.close();
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (parsed.json) console.error(JSON.stringify({ error: message, command }));
    else console.error(message);
    return 1;
  }
}

async function incidentCommand(command: string, parsed: ParsedArgs, registry: SqliteIncidentRegistry, service: IncidentIntelligenceService): Promise<unknown> {
  if (command === "help") return { commands: ["ingest", "list", "show", "timeline", "triage", "root-cause", "close", "reopen", "provenance", "explain", "health", "demo"], json_supported: true, foundation_only: true };
  if (command === "ingest") return service.ingest(collectPhase2Failure(parseDataFile(required(parsed, "file"))));
  if (command === "list") return registry.listIncidents(parseScope(required(parsed, "scope")));
  if (command === "show") return registry.getIncident(positional(parsed, 1, "incident id")) ?? fail("PHASE7_INCIDENT_NOT_FOUND");
  if (command === "timeline") return registry.timeline(positional(parsed, 1, "incident id"));
  if (command === "provenance") return registry.provenance(positional(parsed, 1, "incident id"));
  if (command === "explain") return service.explain(positional(parsed, 1, "incident id"));
  if (command === "health") return registry.health();
  if (command === "triage") return service.triage(positional(parsed, 1, "incident id"), {
    severity: enumOption(parsed, "severity", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], "MEDIUM") as TriageSeverity,
    priority: enumOption(parsed, "priority", ["P0", "P1", "P2", "P3"], "P2") as TriagePriority,
    confidence: numberOption(parsed, "confidence", 0.8),
    actor: { type: "human", id: option(parsed, "actor") ?? "human:local-owner" },
    at: new Date().toISOString(),
  });
  if (command === "root-cause") return service.confirmRootCause(positional(parsed, 1, "incident id"), parseDataFile(required(parsed, "file")) as ConfirmRootCauseInput, { at: new Date().toISOString() });
  if (command === "close") return service.close(positional(parsed, 1, "incident id"), { actor: { type: "human", id: option(parsed, "actor") ?? "human:local-owner" }, reason: required(parsed, "reason"), at: new Date().toISOString() });
  if (command === "reopen") return service.reopen(positional(parsed, 1, "incident id"), { actor: { type: "human", id: option(parsed, "actor") ?? "human:local-owner" }, reason: required(parsed, "reason"), at: new Date().toISOString() });
  if (["research", "reproduce", "minimize", "repair", "deploy", "plugins", "critic"].includes(command)) throw new Error("PHASE7_FOUNDATION_COMMAND_UNSUPPORTED");
  throw new Error("PHASE7_COMMAND_UNKNOWN");
}

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (!value.startsWith("--")) { positionals.push(value); continue; }
    const equal = value.indexOf("=");
    if (equal > 2) { options.set(value.slice(2, equal), value.slice(equal + 1)); continue; }
    const key = value.slice(2);
    if (key === "json") { options.set(key, true); continue; }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) { options.set(key, true); continue; }
    options.set(key, next); index += 1;
  }
  return { positionals, options, json: options.has("json") };
}
function parseScope(value: string): Phase7Scope {
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) throw new Error("PHASE7_SCOPE_INVALID");
  const type = value.slice(0, separator).toUpperCase();
  if (!['ATTEMPT','TASK','REPOSITORY','PROJECT','USER','ROLE','MODEL','PROVIDER','ORGANIZATION','GLOBAL'].includes(type)) throw new Error("PHASE7_SCOPE_INVALID");
  return { type: type as Phase7Scope["type"], id: value.slice(separator + 1) };
}
function parseDataFile(pathInput: string): unknown {
  const path = resolve(pathInput); const source = readFileSync(path, "utf8");
  return extname(path).toLowerCase() === ".json" ? JSON.parse(source) : Bun.YAML.parse(source);
}
function enumOption(parsed: ParsedArgs, key: string, allowed: string[], fallback: string): string { const value = (option(parsed, key) ?? fallback).toUpperCase(); return allowed.includes(value) ? value : fail(`PHASE7_${key.toUpperCase()}_INVALID`); }
function numberOption(parsed: ParsedArgs, key: string, fallback: number): number { const raw = option(parsed, key); if (!raw) return fallback; const value = Number(raw); return Number.isFinite(value) ? value : fail(`PHASE7_${key.toUpperCase()}_INVALID`); }
function option(parsed: ParsedArgs, key: string): string | undefined { const value = parsed.options.get(key); return typeof value === "string" ? value : undefined; }
function required(parsed: ParsedArgs, key: string): string { return option(parsed, key) ?? fail(`Missing required option --${key}`); }
function positional(parsed: ParsedArgs, index: number, label: string): string { return parsed.positionals[index] ?? fail(`Missing ${label}`); }
function print(value: unknown, json: boolean): void { console.log(JSON.stringify(value, null, json ? 0 : 2)); }
function fail(message: string): never { throw new Error(message); }
