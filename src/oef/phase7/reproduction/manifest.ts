import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { deepFreezePhase7, phase7HashSchema, phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema, samePhase7Scope } from "../core/shared";

const manifestPayloadSchema = z.object({
  manifest_id: phase7IdentifierSchema,
  incident_id: phase7IdentifierSchema,
  scope: phase7ScopeSchema.refine(scope => scope.type === "REPOSITORY"),
  source_commit: z.string().regex(/^[a-f0-9]{40}$/i),
  image_digest: phase7HashSchema,
  expected_signature: phase7HashSchema,
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
export const reproductionManifestSchema = manifestPayloadSchema.extend({ manifest_hash: phase7HashSchema }).strict();
export type ReproductionManifest = z.infer<typeof reproductionManifestSchema>;

const replayAttemptSchema = z.object({
  attempt: z.number().int().positive(),
  failure_reproduced: z.boolean(),
  summary: z.string().trim().min(1).max(2_000).refine(value => !/[\u0000-\u001f\u007f]/.test(value)),
  observed_signature: phase7HashSchema,
  evidence_ref: phase7IdentifierSchema,
  evidence_hash: phase7HashSchema,
}).strict();
export type Phase2ReplayAttempt = z.infer<typeof replayAttemptSchema>;

const resultPayloadSchema = z.object({
  result_id: phase7IdentifierSchema,
  incident_id: phase7IdentifierSchema,
  scope: phase7ScopeSchema,
  manifest_id: phase7IdentifierSchema,
  manifest_hash: phase7HashSchema,
  expected_signature: phase7HashSchema,
  classification: z.enum(["REPRODUCIBLE", "INTERMITTENT", "NON_REPRODUCIBLE"]),
  reproduced: z.number().int().nonnegative(),
  attempted: z.number().int().positive(),
  attempts: z.array(replayAttemptSchema).min(1).max(20),
}).strict();
export const reproductionResultSchema = resultPayloadSchema.extend({ result_hash: phase7HashSchema }).strict();
export type ReproductionResult = z.infer<typeof reproductionResultSchema>;

export interface Phase2ReproductionAdapter {
  readonly id: "phase2-local-replay";
  readonly version: "1.0.0";
  replay(input: { manifest: ReproductionManifest }): Promise<{ attempts: unknown[] }>;
}
export interface ReproductionEvidenceResolver {
  resolve(input: { artifact_ref: string; expected_hash: string; scope: ReproductionManifest["scope"] }): { artifact_id: string; artifact_hash: string; scope: ReproductionManifest["scope"] } | null;
}

export class LocalReproductionEvidenceStore implements ReproductionEvidenceResolver {
  private readonly artifacts = new Map<string, { artifact_id: string; artifact_hash: string; scope: ReproductionManifest["scope"] }>();
  record(input: { artifact_id: string; scope: ReproductionManifest["scope"]; content: unknown }): string {
    if (!input.artifact_id.startsWith(`artifact:${input.scope.id}:`)) throw new Error("REPRODUCTION_EVIDENCE_SCOPE_MISMATCH");
    const artifactHash = canonicalSha256(input.content);
    this.artifacts.set(input.artifact_id, { artifact_id: input.artifact_id, artifact_hash: artifactHash, scope: input.scope });
    return artifactHash;
  }
  resolve(input: { artifact_ref: string }): { artifact_id: string; artifact_hash: string; scope: ReproductionManifest["scope"] } | null {
    return this.artifacts.get(input.artifact_ref) ?? null;
  }
}

export function createReproductionManifest(input: unknown): ReproductionManifest {
  if (!input || typeof input !== "object") throw new Error("REPRODUCTION_MANIFEST_INCOMPLETE");
  const raw = input as Record<string, unknown>;
  if (raw.production_access === true) throw new Error("REPRODUCTION_PRODUCTION_ACCESS_FORBIDDEN");
  if (Array.isArray(raw.secret_refs) && raw.secret_refs.length > 0) throw new Error("REPRODUCTION_SECRET_FORBIDDEN");
  for (const field of ["source_commit", "image_digest", "expected_signature", "seed", "budgets"] as const) if (raw[field] === undefined || raw[field] === null) throw new Error("REPRODUCTION_MANIFEST_INCOMPLETE");
  const payload = manifestPayloadSchema.parse(input);
  assertReproductionSecretSafe(payload);
  return deepFreezePhase7(reproductionManifestSchema.parse({ ...payload, manifest_hash: canonicalSha256(payload) }));
}
export function parseReproductionManifest(input: unknown): ReproductionManifest {
  const manifest = reproductionManifestSchema.parse(input);
  if (canonicalSha256(stripManifestHash(manifest)) !== manifest.manifest_hash) throw new Error("REPRODUCTION_MANIFEST_HASH_MISMATCH");
  assertReproductionSecretSafe(manifest);
  return deepFreezePhase7(manifest);
}

export function createDeterministicPhase2ReplayAdapter(input: { outcomes: boolean[]; expected_signature: string; scope: ReproductionManifest["scope"]; evidence_store: LocalReproductionEvidenceStore }): Phase2ReproductionAdapter {
  if (input.outcomes.length === 0) throw new Error("REPRODUCTION_OUTCOMES_REQUIRED");
  const outcomes = [...input.outcomes];
  return Object.freeze({
    id: "phase2-local-replay" as const,
    version: "1.0.0" as const,
    async replay(request: { manifest: ReproductionManifest }) {
      return { attempts: outcomes.map((failureReproduced, index) => {
        const attempt = index + 1;
        const evidenceRef = `artifact:${input.scope.id}:reproduction-${request.manifest.manifest_hash.slice(7, 19)}-${attempt}`;
        const descriptor = { manifest_hash: request.manifest.manifest_hash, attempt, seed: request.manifest.seed + index, failure_reproduced: failureReproduced, observed_signature: input.expected_signature };
        const evidenceHash = input.evidence_store.record({ artifact_id: evidenceRef, scope: input.scope, content: descriptor });
        return { attempt, failure_reproduced: failureReproduced, summary: failureReproduced ? "pinned Phase 2 replay reproduced failure" : "pinned Phase 2 replay did not reproduce failure", observed_signature: input.expected_signature, evidence_ref: evidenceRef, evidence_hash: evidenceHash };
      }) };
    },
  });
}

export async function runPinnedReproduction(manifestInput: ReproductionManifest, adapter: Phase2ReproductionAdapter, resolver: ReproductionEvidenceResolver): Promise<ReproductionResult> {
  const manifest = parseReproductionManifest(manifestInput);
  if (adapter.id !== manifest.phase2_adapter.id || adapter.version !== manifest.phase2_adapter.version) throw new Error("REPRODUCTION_PHASE2_ADAPTER_MISMATCH");
  const replay = await adapter.replay({ manifest });
  if (!replay || !Array.isArray(replay.attempts) || replay.attempts.length !== manifest.attempts || replay.attempts.length === 0) throw new Error("REPRODUCTION_ATTEMPT_COUNT_MISMATCH");
  const attempts = replay.attempts.map(attempt => replayAttemptSchema.parse(attempt));
  if (attempts.some((attempt, index) => attempt.attempt !== index + 1)) throw new Error("REPRODUCTION_ATTEMPT_SEQUENCE_INVALID");
  if (attempts.some(attempt => attempt.observed_signature !== manifest.expected_signature)) throw new Error("REPRODUCTION_SIGNATURE_MISMATCH");
  for (const attempt of attempts) {
    if (!attempt.evidence_ref.startsWith(`artifact:${manifest.scope.id}:`)) throw new Error("REPRODUCTION_EVIDENCE_SCOPE_MISMATCH");
    const resolved = resolver.resolve({ artifact_ref: attempt.evidence_ref, expected_hash: attempt.evidence_hash, scope: manifest.scope });
    if (!resolved) throw new Error("REPRODUCTION_EVIDENCE_UNRESOLVED");
    if (resolved.artifact_id !== attempt.evidence_ref || resolved.artifact_hash !== attempt.evidence_hash || !samePhase7Scope(resolved.scope, manifest.scope)) throw new Error("REPRODUCTION_EVIDENCE_HASH_MISMATCH");
  }
  const reproduced = attempts.filter(item => item.failure_reproduced).length;
  const classification: ReproductionResult["classification"] = reproduced === attempts.length ? "REPRODUCIBLE" : reproduced === 0 ? "NON_REPRODUCIBLE" : "INTERMITTENT";
  const payload = resultPayloadSchema.parse({
    result_id: `reproduction-result:${manifest.manifest_hash.slice(7, 39)}`,
    incident_id: manifest.incident_id,
    scope: manifest.scope,
    manifest_id: manifest.manifest_id,
    manifest_hash: manifest.manifest_hash,
    expected_signature: manifest.expected_signature,
    classification,
    reproduced,
    attempted: attempts.length,
    attempts,
  });
  return deepFreezePhase7(reproductionResultSchema.parse({ ...payload, result_hash: canonicalSha256(payload) }));
}

export function parseReproductionResult(input: unknown, manifestInput: ReproductionManifest): ReproductionResult {
  const manifest = parseReproductionManifest(manifestInput);
  const result = reproductionResultSchema.parse(input);
  const { result_hash, ...payload } = result;
  if (canonicalSha256(payload) !== result_hash) throw new Error("REPRODUCTION_RESULT_HASH_MISMATCH");
  if (result.manifest_id !== manifest.manifest_id || result.manifest_hash !== manifest.manifest_hash || result.incident_id !== manifest.incident_id || result.expected_signature !== manifest.expected_signature || !samePhase7Scope(result.scope, manifest.scope)) throw new Error("REPRODUCTION_RESULT_MANIFEST_MISMATCH");
  if (result.attempted !== manifest.attempts || result.attempts.length !== result.attempted || result.attempted === 0 || result.reproduced !== result.attempts.filter(item => item.failure_reproduced).length) throw new Error("REPRODUCTION_RESULT_INCONSISTENT");
  const expectedClassification = result.reproduced === result.attempted ? "REPRODUCIBLE" : result.reproduced === 0 ? "NON_REPRODUCIBLE" : "INTERMITTENT";
  if (result.classification !== expectedClassification || result.attempts.some((attempt, index) => attempt.attempt !== index + 1 || attempt.observed_signature !== manifest.expected_signature)) throw new Error("REPRODUCTION_RESULT_INCONSISTENT");
  return deepFreezePhase7(result);
}

function stripManifestHash(manifest: ReproductionManifest): Omit<ReproductionManifest, "manifest_hash"> { const { manifest_hash: _hash, ...payload } = manifest; return payload; }
function assertReproductionSecretSafe(value: unknown): void { try { assertNoStructuredPhase1Secret(value); assertNoPhase1Secret(JSON.stringify(value), "Phase 7 reproduction"); } catch { throw new Error("REPRODUCTION_SECRET_FORBIDDEN"); } }
