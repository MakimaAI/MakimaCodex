import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { deepFreezePhase7, phase7HashSchema, phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema } from "../core/shared";

const manifestPayloadSchema = z.object({
  manifest_id: phase7IdentifierSchema,
  incident_id: phase7IdentifierSchema,
  scope: phase7ScopeSchema.refine(scope => scope.type === "REPOSITORY"),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/i),
  image_digest: phase7HashSchema,
  seed: z.number().int().nonnegative(),
  attempts: z.number().int().min(1).max(20),
  budgets: z.object({
    timeout_ms: z.number().int().min(1).max(600_000),
    max_output_bytes: z.number().int().min(1).max(10_000_000),
    max_memory_mb: z.number().int().min(64).max(32_768),
  }).strict(),
  production_access: z.literal(false),
  secret_refs: z.array(z.never()).length(0),
  network_access: z.literal(false),
  phase2_adapter: z.object({ id: z.literal("phase2-local-replay"), version: z.literal("1.0.0") }).strict(),
  created_at: phase7TimestampSchema,
}).strict();
const manifestSchema = manifestPayloadSchema.extend({ manifest_hash: phase7HashSchema }).strict();
export type ReproductionManifest = z.infer<typeof manifestSchema>;

export interface Phase2ReproductionAdapter {
  readonly id: "phase2-local-replay";
  replay(input: { manifest: ReproductionManifest; attempt: number; seed: number }): Promise<{ failure_reproduced: boolean; summary: string }>;
}

export interface ReproductionResult {
  result_id: string;
  incident_id: string;
  scope: ReproductionManifest["scope"];
  manifest_hash: string;
  classification: "REPRODUCIBLE" | "INTERMITTENT" | "NON_REPRODUCIBLE";
  reproduced: number;
  attempted: number;
  attempts: Array<{ attempt: number; failure_reproduced: boolean; summary: string; evidence_ref: string; evidence_hash: string }>;
  result_hash: string;
}

export function createReproductionManifest(input: unknown): ReproductionManifest {
  if (!input || typeof input !== "object") throw new Error("REPRODUCTION_MANIFEST_INCOMPLETE");
  const raw = input as Record<string, unknown>;
  if (raw.production_access === true) throw new Error("REPRODUCTION_PRODUCTION_ACCESS_FORBIDDEN");
  if (Array.isArray(raw.secret_refs) && raw.secret_refs.length > 0) throw new Error("REPRODUCTION_SECRET_FORBIDDEN");
  for (const field of ["source_commit", "image_digest", "seed", "budgets"] as const) {
    if (raw[field] === undefined || raw[field] === null) throw new Error("REPRODUCTION_MANIFEST_INCOMPLETE");
  }
  const payload = manifestPayloadSchema.parse(input);
  return deepFreezePhase7(manifestSchema.parse({ ...payload, manifest_hash: canonicalSha256(payload) }));
}

export function createDeterministicPhase2ReplayAdapter(input: { outcomes: boolean[] }): Phase2ReproductionAdapter {
  if (input.outcomes.length === 0) throw new Error("REPRODUCTION_OUTCOMES_REQUIRED");
  const outcomes = [...input.outcomes];
  return Object.freeze({
    id: "phase2-local-replay" as const,
    async replay(request: { manifest: ReproductionManifest; attempt: number; seed: number }) {
      const failureReproduced = outcomes[(request.attempt - 1) % outcomes.length]!;
      return { failure_reproduced: failureReproduced, summary: failureReproduced ? "pinned Phase 2 replay reproduced failure" : "pinned Phase 2 replay did not reproduce failure" };
    },
  });
}

export async function runPinnedReproduction(manifestInput: ReproductionManifest, adapter: Phase2ReproductionAdapter): Promise<ReproductionResult> {
  const manifest = manifestSchema.parse(manifestInput);
  if (canonicalSha256(stripHash(manifest)) !== manifest.manifest_hash) throw new Error("REPRODUCTION_MANIFEST_HASH_MISMATCH");
  if (adapter.id !== manifest.phase2_adapter.id) throw new Error("REPRODUCTION_PHASE2_ADAPTER_MISMATCH");
  const attempts: ReproductionResult["attempts"] = [];
  for (let attempt = 1; attempt <= manifest.attempts; attempt += 1) {
    const replay = await adapter.replay({ manifest, attempt, seed: manifest.seed + attempt - 1 });
    const evidence = { manifest_hash: manifest.manifest_hash, attempt, seed: manifest.seed + attempt - 1, ...replay };
    attempts.push({
      attempt,
      ...replay,
      evidence_ref: `artifact:${manifest.scope.id}:reproduction-${manifest.manifest_hash.slice(7, 19)}-${attempt}`,
      evidence_hash: canonicalSha256(evidence),
    });
  }
  const reproduced = attempts.filter(item => item.failure_reproduced).length;
  const classification: ReproductionResult["classification"] = reproduced === attempts.length ? "REPRODUCIBLE" : reproduced === 0 ? "NON_REPRODUCIBLE" : "INTERMITTENT";
  const payload = {
    result_id: `reproduction-result:${manifest.manifest_hash.slice(7, 39)}`,
    incident_id: manifest.incident_id,
    scope: manifest.scope,
    manifest_hash: manifest.manifest_hash,
    classification,
    reproduced,
    attempted: attempts.length,
    attempts,
  };
  return deepFreezePhase7({ ...payload, result_hash: canonicalSha256(payload) });
}

function stripHash(manifest: ReproductionManifest): Omit<ReproductionManifest, "manifest_hash"> {
  const { manifest_hash: _hash, ...payload } = manifest;
  return payload;
}
