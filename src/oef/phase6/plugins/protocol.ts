import { z } from "zod";
import { redactSecrets } from "../../../lib/redact";
import { MEMORY_SCOPE_TYPES, scopeKey, type MemoryAuthorizationContext, type MemoryScope } from "../core/domain";

export const MEMORY_PLUGIN_PROTOCOL_VERSION = 1;
export const MEMORY_PLUGIN_CAPABILITIES = ["memory-search", "vector-search", "batch-upsert", "metadata-filter"] as const;

const identifier = z.string().trim().min(1).max(256).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/);
const scopeSchema = z.object({ type: z.enum(MEMORY_SCOPE_TYPES), id: identifier }).strict();
export const memoryPluginManifestSchema = z.object({
  plugin: z.object({ id: identifier, version: z.string().regex(/^\d+\.\d+\.\d+$/) }).strict(),
  protocol: z.object({ min: z.number().int().positive(), max: z.number().int().positive() }).strict(),
  capabilities: z.array(z.string().trim().min(1)).min(1),
  granted_scopes: z.array(scopeSchema),
}).strict();

export interface MemoryPluginManifest {
  plugin: { id: string; version: string };
  protocol: { min: number; max: number };
  capabilities: Array<typeof MEMORY_PLUGIN_CAPABILITIES[number]>;
  granted_scopes: MemoryScope[];
}

export interface ExternalMemoryResult {
  external_id: string;
  summary: string;
  scopes: MemoryScope[];
  source_refs: string[];
  claimed_status?: string;
  claimed_trust?: string;
}

export interface ExternalMemoryBackendAdapter {
  search(input: { text: string; scopes: MemoryScope[] }): Promise<ExternalMemoryResult[]>;
}

export function validateMemoryPluginManifest(input: unknown, options: { protocol_version?: number } = {}): MemoryPluginManifest {
  const parsed = memoryPluginManifestSchema.parse(input);
  const protocolVersion = options.protocol_version ?? MEMORY_PLUGIN_PROTOCOL_VERSION;
  if (parsed.protocol.min > parsed.protocol.max || protocolVersion < parsed.protocol.min || protocolVersion > parsed.protocol.max) {
    throw new Error("MEMORY_PLUGIN_INCOMPATIBLE");
  }
  if (parsed.capabilities.some(capability => !(MEMORY_PLUGIN_CAPABILITIES as readonly string[]).includes(capability))) {
    throw new Error("MEMORY_PLUGIN_CAPABILITY_FORBIDDEN");
  }
  return immutable(parsed as MemoryPluginManifest);
}

export class GuardedExternalMemoryBackend {
  private readonly manifest: MemoryPluginManifest;
  private readonly adapter: ExternalMemoryBackendAdapter;

  constructor(options: { manifest: MemoryPluginManifest; adapter: ExternalMemoryBackendAdapter }) {
    this.manifest = validateMemoryPluginManifest(options.manifest);
    this.adapter = options.adapter;
    if (!this.manifest.capabilities.includes("memory-search")) throw new Error("MEMORY_PLUGIN_CAPABILITY_MISSING");
  }

  search(input: { text: string; scopes: MemoryScope[]; authorization: MemoryAuthorizationContext }): Promise<Array<{
    external_id: string;
    summary: string;
    scopes: MemoryScope[];
    source_refs: string[];
    lifecycle_status: "OBSERVED";
    trust: "UNTRUSTED";
    instruction_authority: "NONE";
    backend: { plugin_id: string; plugin_version: string };
  }>> {
    const authorized = new Set(input.authorization.authorized_scopes.map(scopeKey));
    const granted = new Set(this.manifest.granted_scopes.map(scopeKey));
    if (input.scopes.some(scope => !authorized.has(scopeKey(scope)))) throw new Error("MEMORY_SCOPE_ACCESS_DENIED");
    if (input.scopes.some(scope => !granted.has(scopeKey(scope)))) throw new Error("MEMORY_PLUGIN_SCOPE_DENIED");
    if (!input.text.trim()) throw new Error("MEMORY_PLUGIN_QUERY_INVALID");
    return this.searchAuthorized(input, granted, authorized);
  }

  private async searchAuthorized(
    input: { text: string; scopes: MemoryScope[] },
    granted: ReadonlySet<string>,
    authorized: ReadonlySet<string>,
  ) {
    const results = await this.adapter.search({ text: input.text, scopes: input.scopes });
    if (!Array.isArray(results)) throw new Error("MEMORY_PLUGIN_RESULT_INVALID");
    return results.map(result => {
      if (result.scopes.some(scope => !granted.has(scopeKey(scope)) || !authorized.has(scopeKey(scope)))) {
        throw new Error("MEMORY_PLUGIN_RESULT_SCOPE_VIOLATION");
      }
      const safe = redactSecrets({
        external_id: result.external_id,
        summary: result.summary,
        scopes: result.scopes,
        source_refs: result.source_refs,
      }) as Pick<ExternalMemoryResult, "external_id" | "summary" | "scopes" | "source_refs">;
      return immutable({
        ...safe,
        lifecycle_status: "OBSERVED" as const,
        trust: "UNTRUSTED" as const,
        instruction_authority: "NONE" as const,
        backend: { plugin_id: this.manifest.plugin.id, plugin_version: this.manifest.plugin.version },
      });
    });
  }
}

function immutable<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) immutable(child);
    Object.freeze(value);
  }
  return value;
}
