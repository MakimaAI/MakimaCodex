import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import {
  deepFreezePhase7,
  phase7HashSchema,
  phase7IdentifierSchema,
  phase7ScopeSchema,
  phase7SemverSchema,
  phase7TimestampSchema,
} from "./shared";
import { isValidFailureType } from "./taxonomy";

export const FAILURE_CATEGORIES = ["RUNTIME", "PROVIDER", "RUNNER", "WORKSPACE", "POLICY", "VERIFICATION", "USER", "UNKNOWN"] as const;
export const FAILURE_SENSITIVITIES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;

const failureCodeSchema = z.string().trim().min(3).max(256).refine(isValidFailureType, "Unknown reserved failure type");

const failureObservationPayloadSchema = z.object({
  schema_version: z.literal(1),
  observation_id: phase7IdentifierSchema,
  provenance_ids: z.array(phase7IdentifierSchema).min(1).max(256),
  source_phase: z.number().int().min(1).max(6),
  task_id: phase7IdentifierSchema,
  execution_id: phase7IdentifierSchema.nullable(),
  attempt_id: phase7IdentifierSchema.nullable(),
  artifact_refs: z.array(z.object({ artifact_id: phase7IdentifierSchema, artifact_hash: phase7HashSchema }).strict()).max(256),
  scope: phase7ScopeSchema,
  failure: z.object({
    category: z.enum(FAILURE_CATEGORIES),
    code: failureCodeSchema,
    summary: z.string().trim().min(1).max(2_000).refine(value => !/[\u0000-\u001f\u007f]/.test(value)),
  }).strict(),
  environment: z.object({
    provider: z.string().trim().min(1).max(160),
    runtime: z.string().trim().min(1).max(300),
    runtime_version: z.string().trim().min(1).max(300),
    tool: z.string().trim().min(1).max(300),
    operation: z.string().trim().min(1).max(300),
    os: z.string().trim().min(1).max(160),
    arch: z.string().trim().min(1).max(160),
    environment_id: phase7IdentifierSchema.optional(),
    container: z.string().trim().min(1).max(300).optional(),
    region: z.string().trim().min(1).max(300).optional(),
  }).strict(),
  sensitivity: z.enum(FAILURE_SENSITIVITIES),
  redaction: z.object({ state: z.enum(["NONE", "REDACTED"]), profile_version: phase7SemverSchema }).strict(),
  observed_at: phase7TimestampSchema,
}).strict().superRefine((value, context) => {
  for (const field of ["provenance_ids", "artifact_refs"] as const) {
    const keys = value[field].map(item => typeof item === "string" ? item : item.artifact_id);
    if (new Set(keys).size !== keys.length) context.addIssue({ code: "custom", path: [field], message: `${field} cannot contain duplicates` });
  }
});

export const failureObservationSchema = failureObservationPayloadSchema.extend({ canonical_hash: phase7HashSchema }).strict();
export type FailureObservation = z.infer<typeof failureObservationSchema>;
export type FailureObservationInput = Omit<z.input<typeof failureObservationPayloadSchema>, "schema_version">;

export function createFailureObservation(input: FailureObservationInput): FailureObservation {
  const payload = failureObservationPayloadSchema.parse({ schema_version: 1, ...input });
  assertArtifactScope(payload);
  assertObservationSecretSafe(payload);
  return deepFreezePhase7(failureObservationSchema.parse({ ...payload, canonical_hash: canonicalSha256(payload) }));
}

export function parseFailureObservation(input: unknown): FailureObservation {
  const value = failureObservationSchema.parse(input);
  assertArtifactScope(value);
  assertObservationSecretSafe(value);
  const { canonical_hash, ...payload } = value;
  if (canonicalSha256(payload) !== canonical_hash) throw new Error("FAILURE_OBSERVATION_HASH_MISMATCH");
  return deepFreezePhase7(value);
}

function assertArtifactScope(value: Pick<FailureObservation, "scope" | "artifact_refs">): void {
  const prefix = `artifact:${value.scope.id}:`;
  if (value.artifact_refs.some(reference => !reference.artifact_id.startsWith(prefix))) {
    throw new Error("FAILURE_OBSERVATION_ARTIFACT_SCOPE_MISMATCH");
  }
}

function assertObservationSecretSafe(value: unknown): void {
  try {
    assertNoStructuredPhase1Secret(value);
    assertNoPhase1Secret(JSON.stringify(value), "failure observation");
  } catch {
    throw new Error("FAILURE_OBSERVATION_SECRET_REJECTED");
  }
}
