import { mkdirSync, readFileSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import { canonicalSha256 } from "../oef/phase1/core/contract/task-contract";
import {
  MEMORY_SCOPE_TYPES,
  MEMORY_LAYERS,
  LocalHashEmbeddingProvider,
  LocalMemoryArtifactPurger,
  MemoryCandidateService,
  MemoryForgettingService,
  MemoryHygieneService,
  MemoryRetrievalEngine,
  SqliteMemoryBackupService,
  SqliteMemoryStore,
  SqliteVectorMemoryIndex,
  appendMemoryRevision,
  runPhase6AcceptanceDemo,
  type MemoryLayer,
  type MemoryAuthorizationContext,
  type MemoryQuery,
  type MemoryScope,
  type MemorySensitivity,
  type MemoryTrustLevel,
  type EmbeddingProfile,
} from "../oef/phase6";

interface ParsedArgs {
  positionals: string[];
  options: Map<string, string | true>;
  json: boolean;
}

export async function cmdOefPhase6(group: string, args: string[]): Promise<number> {
  const parsed = parseArgs(args);
  try {
    if (group === "oef-phase6-demo") {
      const report = await runPhase6AcceptanceDemo({ root: required(parsed, "root") });
      print(report, parsed.json);
      return report.status === "PASS" ? 0 : 1;
    }
    if (group !== "memory") throw new Error(`Unknown Phase 6 command group: ${group}`);
    const home = resolve(option(parsed, "home") ?? join(process.cwd(), ".opencodex", "memory"));
    mkdirSync(home, { recursive: true });
    const databasePath = join(home, "memory.sqlite");
    if (parsed.positionals[0] === "restore") {
      const targetHome = resolve(required(parsed, "target-home"));
      const value = new SqliteMemoryBackupService({ databasePath }).restore({
        backup_directory: required(parsed, "backup"),
        target_database_path: join(targetHome, "memory.sqlite"),
        allow_overwrite: parsed.options.has("allow-overwrite"),
      });
      print(value, parsed.json);
      return 0;
    }
    const store = new SqliteMemoryStore({ databasePath });
    try {
      const value = await memoryCommand(store, parsed, databasePath);
      print(value, parsed.json);
      return 0;
    } finally {
      store.close();
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

async function memoryCommand(store: SqliteMemoryStore, parsed: ParsedArgs, databasePath: string): Promise<unknown> {
  const command = parsed.positionals[0] ?? "help";
  if (command === "help") {
    return { commands: ["search", "show", "provenance", "explain-query", "candidates", "promote", "correct", "deprecate", "forget", "hygiene", "health", "audit", "reindex", "reembed", "backup", "restore"], json_supported: true };
  }
  if (command === "search") {
    const text = positional(parsed, 1, "search text");
    const scopes = values(parsed, "scope").map(parseScope);
    if (scopes.length === 0) throw new Error("At least one --scope is required");
    const role = option(parsed, "role") ?? "backend-implementer";
    const at = option(parsed, "at") ?? "current";
    const queryId = option(parsed, "query-id") ?? `memory-query:${canonicalSha256({ text, scopes, role, at, nonce: Date.now() }).slice(7, 31)}`;
    const query: MemoryQuery = {
      query_id: queryId,
      text,
      requester: {
        role,
        task_id: option(parsed, "task"),
        authorized_scopes: scopes,
        max_sensitivity: sensitivity(option(parsed, "max-sensitivity") ?? "INTERNAL"),
      },
      scopes: { include: scopes },
      layers: { include: layers(option(parsed, "layers")) },
      trust: { minimum: trust(option(parsed, "minimum-trust") ?? "LOW") },
      temporal: { at },
      budget: {
        max_tokens: integerOption(parsed, "max-tokens", 4_000),
        max_records: integerOption(parsed, "max-records", 12),
      },
      usage_mode: "CLI_RESEARCH",
      explain: true,
    };
    const vector = new SqliteVectorMemoryIndex({ databasePath });
    try { return new MemoryRetrievalEngine({ store, vectorIndex: vector }).recall(query); }
    finally { vector.close(); }
  }
  if (command === "show") return store.getAuthorized(positional(parsed, 1, "memory id"), authorization(parsed), optionalInteger(parsed, "revision")) ?? fail("MEMORY_NOT_FOUND");
  if (command === "provenance") return store.provenanceAuthorized(positional(parsed, 1, "memory id"), authorization(parsed)) ?? fail("MEMORY_NOT_FOUND");
  if (command === "explain-query") return store.explainQueryAuthorized(positional(parsed, 1, "query id"), authorization(parsed)) ?? fail("MEMORY_QUERY_NOT_FOUND");
  if (command === "health") {
    const vector = new SqliteVectorMemoryIndex({ databasePath });
    try { return { ...store.health(), vector_index: vector.status() }; }
    finally { vector.close(); }
  }
  if (command === "audit") {
    const vector = new SqliteVectorMemoryIndex({ databasePath });
    try {
      const health = store.health();
      const vectorStatus = vector.status();
      return { status: health.canonical_store === "HEALTHY" && health.lexical_index === "HEALTHY" && ["HEALTHY", "EMPTY"].includes(String(vectorStatus.status)) ? "PASS" : "FAIL", ...health, vector_index: vectorStatus };
    } finally { vector.close(); }
  }
  if (command === "reindex") return store.reindexLexical();
  if (command === "reembed") {
    const profile = parseDataFile(required(parsed, "profile-file")) as EmbeddingProfile;
    const vector = new SqliteVectorMemoryIndex({ databasePath, provider: new LocalHashEmbeddingProvider(profile) });
    try { return await vector.rebuild({ at: new Date().toISOString() }); }
    finally { vector.close(); }
  }
  if (command === "backup") {
    const artifactManifestPath = option(parsed, "artifact-manifest");
    const artifactRoot = resolve(option(parsed, "artifact-root") ?? process.cwd());
    const manifest = artifactManifestPath ? parseDataFile(artifactManifestPath) as Record<string, string> : {};
    return new SqliteMemoryBackupService({ databasePath }).create({
      backup_root: required(parsed, "output"), at: new Date().toISOString(),
      artifact_files: Object.entries(manifest).map(([reference, path]) => ({ reference, path: resolve(artifactRoot, path) })),
    });
  }
  if (command === "hygiene") {
    if (parsed.positionals[1] !== "run") throw new Error("Usage: memory hygiene run");
    return new MemoryHygieneService(store).run({ at: option(parsed, "at") ?? new Date().toISOString() });
  }
  if (command === "candidates") {
    const authority = authorization(parsed);
    const rawStatus = option(parsed, "status")?.toUpperCase();
    if (rawStatus && !["CANDIDATE", "PROMOTED", "REJECTED"].includes(rawStatus)) throw new Error("MEMORY_CANDIDATE_STATUS_INVALID");
    return new MemoryCandidateService(store).list({ status: rawStatus as "CANDIDATE" | "PROMOTED" | "REJECTED" | undefined })
      .filter(candidate => candidateVisible(candidate, authority));
  }
  if (command === "promote") {
    const candidateId = positional(parsed, 1, "candidate id");
    const authority = authorization(parsed);
    const service = new MemoryCandidateService(store);
    const candidate = store.getMemoryCandidate(candidateId) ?? fail("MEMORY_CANDIDATE_NOT_FOUND");
    if (!candidateVisible(candidate, authority)) throw new Error("MEMORY_SCOPE_ACCESS_DENIED");
    const actorType = (option(parsed, "actor-type") ?? "human").toLowerCase();
    if (actorType !== "human" && actorType !== "verifier") throw new Error("MEMORY_PROMOTION_ACTOR_UNAUTHORIZED");
    return service.promote(candidateId, {
      actor: { type: actorType, id: option(parsed, "actor") ?? `${actorType}:local-owner` },
      evidence_refs: values(parsed, "evidence"),
      evaluation_ref: option(parsed, "evaluation"),
      at: new Date().toISOString(),
    });
  }
  if (command === "correct") {
    const memoryId = positional(parsed, 1, "memory id");
    const current = store.getAuthorized(memoryId, authorization(parsed)) ?? fail("MEMORY_NOT_FOUND");
    const patch = parseDataFile(required(parsed, "file"));
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw new Error("MEMORY_CORRECTION_FILE_INVALID");
    const next = appendMemoryRevision(current, patch, {
      expected_revision: current.revision_number,
      reason: required(parsed, "reason"),
      actor: { type: "human", id: option(parsed, "actor") ?? "human:local-owner" },
      at: new Date().toISOString(),
    });
    store.appendRevision(next, current.revision_number);
    return next;
  }
  if (command === "deprecate") {
    const memoryId = positional(parsed, 1, "memory id");
    const current = store.getAuthorized(memoryId, authorization(parsed)) ?? fail("MEMORY_NOT_FOUND");
    const next = appendMemoryRevision(current, { lifecycle: { status: "DEPRECATED" } }, {
      expected_revision: current.revision_number,
      reason: required(parsed, "reason"),
      actor: { type: "human", id: option(parsed, "actor") ?? "human:local-owner" },
      at: new Date().toISOString(),
    });
    store.appendRevision(next, current.revision_number);
    return next;
  }
  if (command === "forget") {
    const memoryId = positional(parsed, 1, "memory id");
    store.getAuthorized(memoryId, authorization(parsed)) ?? fail("MEMORY_NOT_FOUND");
    const mode = (option(parsed, "mode") ?? "soft-forget").replaceAll("-", "_").toUpperCase();
    if (!["SOFT_FORGET", "HARD_DELETE", "LEGAL_DELETE", "SECRET_PURGE"].includes(mode)) throw new Error("MEMORY_FORGET_MODE_INVALID");
    const vector = new SqliteVectorMemoryIndex({ databasePath });
    try {
      const manifestPath = option(parsed, "artifact-manifest");
      const purger = manifestPath ? new LocalMemoryArtifactPurger({
        root: required(parsed, "artifact-root"),
        manifest: parseDataFile(manifestPath) as Record<string, string>,
      }) : undefined;
      return new MemoryForgettingService({ store, derived_indexes: [vector], artifact_purger: purger }).forget(memoryId, {
        mode: mode as "SOFT_FORGET" | "HARD_DELETE" | "LEGAL_DELETE" | "SECRET_PURGE",
        reason: required(parsed, "reason"),
        at: new Date().toISOString(),
      });
    } finally { vector.close(); }
  }
  return fail(`Unknown memory command: ${command}`);
}

function parseArgs(args: string[]): ParsedArgs {
  const positionals: string[] = [];
  const options = new Map<string, string | true>();
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index]!;
    if (!value.startsWith("--")) { positionals.push(value); continue; }
    const equal = value.indexOf("=");
    if (equal > 2) { appendOption(options, value.slice(2, equal), value.slice(equal + 1)); continue; }
    const key = value.slice(2);
    if (key === "json") { options.set(key, true); continue; }
    const next = args[index + 1];
    if (!next || next.startsWith("--")) { options.set(key, true); continue; }
    appendOption(options, key, next);
    index += 1;
  }
  return { positionals, options, json: options.has("json") };
}

function appendOption(options: Map<string, string | true>, key: string, value: string): void {
  const existing = options.get(key);
  options.set(key, typeof existing === "string" ? `${existing}\u0000${value}` : value);
}

function values(parsed: ParsedArgs, key: string): string[] {
  const value = option(parsed, key);
  return value ? value.split("\u0000").filter(Boolean) : [];
}

function parseScope(value: string): MemoryScope {
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) throw new Error(`Invalid scope: ${value}`);
  const type = value.slice(0, separator).toUpperCase();
  if (!(MEMORY_SCOPE_TYPES as readonly string[]).includes(type)) throw new Error(`Invalid scope type: ${type}`);
  return { type: type as MemoryScope["type"], id: value.slice(separator + 1) };
}

function layers(value?: string): MemoryLayer[] {
  if (!value) return ["EVIDENCE", "EPISODE", "FACT", "LESSON", "PROCEDURE_CANDIDATE", "EVALUATION", "GOVERNANCE"];
  const parsed = value.split(",").map(item => item.trim().toUpperCase()).filter(Boolean);
  if (parsed.some(layer => !(MEMORY_LAYERS as readonly string[]).includes(layer))) throw new Error("Invalid memory layer");
  return parsed as MemoryLayer[];
}

function authorization(parsed: ParsedArgs): MemoryAuthorizationContext {
  const scopes = values(parsed, "scope").map(parseScope);
  if (scopes.length === 0) throw new Error("At least one --scope is required");
  return {
    role: option(parsed, "role") ?? "backend-implementer",
    authorized_scopes: scopes,
    max_sensitivity: sensitivity(option(parsed, "max-sensitivity") ?? "INTERNAL"),
  };
}

function trust(value: string): MemoryTrustLevel {
  const normalized = value.toUpperCase() as MemoryTrustLevel;
  if (!["UNTRUSTED", "LOW", "MEDIUM", "HIGH", "AUTHORITATIVE"].includes(normalized)) throw new Error("Invalid minimum trust");
  return normalized;
}

function sensitivity(value: string): Exclude<MemorySensitivity, "SECRET"> {
  const normalized = value.toUpperCase();
  if (!["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].includes(normalized)) throw new Error("Invalid max sensitivity");
  return normalized as Exclude<MemorySensitivity, "SECRET">;
}

function candidateVisible(candidate: { scopes: MemoryScope[]; access: { sensitivity: Exclude<MemorySensitivity, "SECRET">; read_roles: string[] } }, authorization: MemoryAuthorizationContext): boolean {
  const allowed = new Set(authorization.authorized_scopes.map(scope => `${scope.type}:${scope.id}`));
  return candidate.scopes.every(scope => allowed.has(`${scope.type}:${scope.id}`))
    && (candidate.access.read_roles.includes("*") || candidate.access.read_roles.includes(authorization.role))
    && ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].indexOf(candidate.access.sensitivity)
      <= ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"].indexOf(authorization.max_sensitivity);
}

function parseDataFile(pathInput: string): unknown {
  const path = resolve(pathInput);
  const source = readFileSync(path, "utf8");
  return extname(path).toLowerCase() === ".json" ? JSON.parse(source) : Bun.YAML.parse(source);
}

function option(parsed: ParsedArgs, key: string): string | undefined {
  const value = parsed.options.get(key);
  return typeof value === "string" ? value : undefined;
}

function required(parsed: ParsedArgs, key: string): string { return option(parsed, key) ?? fail(`Missing required option --${key}`); }
function positional(parsed: ParsedArgs, index: number, label: string): string { return parsed.positionals[index] ?? fail(`Missing ${label}`); }
function integerOption(parsed: ParsedArgs, key: string, fallback: number): number {
  const raw = option(parsed, key);
  if (!raw) return fallback;
  const value = Number(raw);
  return Number.isInteger(value) && value > 0 ? value : fail(`Invalid integer --${key}`);
}
function optionalInteger(parsed: ParsedArgs, key: string): number | undefined {
  const raw = option(parsed, key);
  if (!raw) return undefined;
  const value = Number(raw);
  return Number.isInteger(value) && value > 0 ? value : fail(`Invalid integer --${key}`);
}
function print(value: unknown, json: boolean): void { console.log(JSON.stringify(value, null, json ? 0 : 2)); }
function fail(message: string): never { throw new Error(message); }
