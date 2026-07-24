import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { failureSchema, executionManifestSchema } from "../../phase2/core/domain";
import { createFailureObservation, type FailureObservation } from "../core/failure-observation";
import { phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema, deepFreezePhase7 } from "../core/shared";
import { SIGNATURE_PROFILE, signFailure, type FailureSignatures } from "./signatures";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const envelopeSchema = z.object({
  schema_version: z.literal(1),
  event_id: phase7IdentifierSchema,
  task_id: phase7IdentifierSchema,
  execution_id: phase7IdentifierSchema.nullable(),
  attempt_id: phase7IdentifierSchema.nullable(),
  scope: phase7ScopeSchema.refine(scope => scope.type === "REPOSITORY", "Phase 7 collector requires repository scope"),
  failure: failureSchema,
  execution_manifest: executionManifestSchema,
  artifact_hashes: z.record(z.string(), hashSchema),
  message: z.string().trim().min(1).max(100_000),
  environment: z.object({
    os: z.string().trim().min(1).max(160),
    arch: z.string().trim().min(1).max(160),
    tool: z.string().trim().min(1).max(300),
    operation: z.string().trim().min(1).max(300),
  }).strict(),
  http_status: z.number().int().min(100).max(599).nullable().optional(),
  error_code: z.string().trim().min(1).max(300).nullable().optional(),
  exception: z.string().trim().min(1).max(500).nullable().optional(),
  symbol: z.string().trim().min(1).max(500).nullable().optional(),
  sensitivity: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
  observed_at: phase7TimestampSchema,
}).strict();

export type Phase2FailureEnvelope = z.input<typeof envelopeSchema>;
export interface CollectedPhase2Failure {
  source_event_id: string;
  source_hash: string;
  observation: FailureObservation;
  signatures: FailureSignatures;
  phase2_failure_type: z.infer<typeof failureSchema>["type"];
  http_status: number | null;
  runtime_major: number;
  provider: string;
  runtime: string;
  source_commit: string;
}

export function collectPhase2Failure(input: unknown): CollectedPhase2Failure {
  const value = envelopeSchema.parse(input);
  if (value.execution_manifest.source.repository !== value.scope.id) throw new Error("PHASE2_FAILURE_SCOPE_MISMATCH");
  if (value.execution_manifest.task.id !== value.task_id) throw new Error("PHASE2_FAILURE_TASK_MISMATCH");
  if (value.execution_manifest.model.provider !== value.execution_manifest.environment.provider) throw new Error("PHASE2_FAILURE_PROVIDER_MISMATCH");
  for (const artifactId of value.failure.evidence_refs) {
    if (!artifactId.startsWith(`artifact:${value.scope.id}:`) || !value.artifact_hashes[artifactId]) {
      throw new Error("PHASE2_FAILURE_ARTIFACT_BOUNDARY_INVALID");
    }
  }
  assertSecretSafe(value);
  const category = value.failure.category.toUpperCase() as FailureObservation["failure"]["category"];
  const failureCode = `opencodex.${value.failure.type.toLowerCase().replaceAll("_", "-")}`;
  const observationId = `observation:${canonicalSha256({ source: value.event_id }).slice(7, 39)}`;
  const observation = createFailureObservation({
    observation_id: observationId,
    provenance_ids: [value.event_id, value.failure.failure_id, `manifest:${canonicalSha256(value.execution_manifest).slice(7, 39)}`],
    source_phase: 2,
    task_id: value.task_id,
    execution_id: value.execution_id,
    attempt_id: value.attempt_id,
    artifact_refs: value.failure.evidence_refs.map(artifact_id => ({ artifact_id, artifact_hash: value.artifact_hashes[artifact_id]! })),
    scope: value.scope,
    failure: { category, code: failureCode, summary: value.message },
    environment: {
      provider: value.execution_manifest.model.provider,
      runtime: value.execution_manifest.runtime.id,
      runtime_version: value.execution_manifest.runtime.binary_version,
      tool: value.environment.tool,
      operation: value.environment.operation,
      os: value.environment.os,
      arch: value.environment.arch,
      environment_id: `environment:${value.execution_manifest.environment.fingerprint.slice(7, 39)}`,
    },
    sensitivity: value.sensitivity,
    redaction: { state: "REDACTED", profile_version: "1.0.0" },
    observed_at: value.observed_at,
  });
  const signatures = signFailure({
    profile: SIGNATURE_PROFILE,
    scope: value.scope,
    message: value.message,
    category,
    code: failureCode,
    provider: value.execution_manifest.model.provider,
    runtime: value.execution_manifest.runtime.id,
    tool: value.environment.tool,
    operation: value.environment.operation,
    http_status: value.http_status ?? null,
    error_code: value.error_code ?? null,
    exception: value.exception ?? null,
    symbol: value.symbol ?? null,
    environment: {
      os: value.environment.os,
      arch: value.environment.arch,
      runtime_version: value.execution_manifest.runtime.binary_version,
    },
  });
  const runtimeMajor = Number.parseInt(value.execution_manifest.runtime.binary_version.match(/\d+/)?.[0] ?? "0", 10);
  return deepFreezePhase7({
    source_event_id: value.event_id,
    source_hash: canonicalSha256(value),
    observation,
    signatures,
    phase2_failure_type: value.failure.type,
    http_status: value.http_status ?? null,
    runtime_major: runtimeMajor,
    provider: value.execution_manifest.model.provider,
    runtime: value.execution_manifest.runtime.id,
    source_commit: value.execution_manifest.source.base_commit,
  });
}

function assertSecretSafe(value: unknown): void {
  try {
    assertNoStructuredPhase1Secret(value);
    assertNoPhase1Secret(JSON.stringify(value), "Phase 2 failure collector input");
  } catch {
    throw new Error("PHASE2_FAILURE_SECRET_REJECTED");
  }
}
