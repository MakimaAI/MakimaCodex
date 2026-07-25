import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { actorSchema, type Actor } from "../../phase1/core/shared/actor";
import {
  deepFreezePhase7,
  phase7HashSchema,
  phase7IdentifierSchema,
  phase7ScopeSchema,
  phase7SemverSchema,
  phase7TimestampSchema,
  samePhase7Scope,
} from "./shared";
import { isValidFailureType } from "./taxonomy";

export const FAILURE_CATEGORIES = ["RUNTIME", "PROVIDER", "RUNNER", "WORKSPACE", "POLICY", "VERIFICATION", "USER", "UNKNOWN"] as const;
export const FAILURE_SENSITIVITIES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;

const failureCodeSchema = z.string().trim().min(3).max(256).refine(isValidFailureType, "Unknown reserved failure type");

const failureObservationPayloadSchema = z.object({
  schema_version: z.literal(1),
  observation_id: phase7IdentifierSchema,
  revision_id: phase7IdentifierSchema,
  revision: z.number().int().positive(),
  previous_revision_id: phase7IdentifierSchema.nullable(),
  previous_observation_hash: phase7HashSchema.nullable(),
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
  correction: z.object({ reason: z.string().trim().min(1).max(2_000), actor: actorSchema, at: phase7TimestampSchema }).strict().nullable(),
}).strict().superRefine((value, context) => {
  for (const field of ["provenance_ids", "artifact_refs"] as const) {
    const keys = value[field].map(item => typeof item === "string" ? item : item.artifact_id);
    if (new Set(keys).size !== keys.length) context.addIssue({ code: "custom", path: [field], message: `${field} cannot contain duplicates` });
  }
  const initial = value.revision === 1;
  const initialLineage = value.previous_revision_id === null && value.previous_observation_hash === null && value.correction === null;
  const correctionLineage = value.previous_revision_id !== null && value.previous_observation_hash !== null && value.correction !== null;
  if ((initial && !initialLineage) || (!initial && (!correctionLineage || value.previous_revision_id !== observationRevisionId(value.observation_id, value.revision - 1)))) {
    context.addIssue({ code: "custom", message: "Observation correction lineage is invalid" });
  }
  if (value.revision_id !== observationRevisionId(value.observation_id, value.revision)) {
    context.addIssue({ code: "custom", path: ["revision_id"], message: "Observation revision identity is invalid" });
  }
});

export const failureObservationSchema = failureObservationPayloadSchema.extend({ canonical_hash: phase7HashSchema }).strict();
export type FailureObservation = z.infer<typeof failureObservationSchema>;
export type FailureObservationInput = Omit<z.input<typeof failureObservationPayloadSchema>, "schema_version" | "revision_id" | "revision" | "previous_revision_id" | "previous_observation_hash" | "correction">;
export type FailureObservationCorrectionPatch = Partial<Pick<FailureObservation,
  "provenance_ids" | "artifact_refs" | "failure" | "environment" | "sensitivity" | "redaction" | "observed_at"
>>;
export type FailureObservationPredecessorResolver = (revisionId: string) => unknown;

export interface CorrectFailureObservationOptions {
  expected_revision: number;
  reason: string;
  actor: Actor;
  at: string;
  resolve_predecessor?: FailureObservationPredecessorResolver;
}

export function createFailureObservation(input: FailureObservationInput): FailureObservation {
  const payload = failureObservationPayloadSchema.parse({
    schema_version: 1,
    ...input,
    revision_id: observationRevisionId(input.observation_id, 1),
    revision: 1,
    previous_revision_id: null,
    previous_observation_hash: null,
    correction: null,
  });
  assertArtifactScope(payload);
  assertObservationSecretSafe(payload);
  return deepFreezePhase7(failureObservationSchema.parse({ ...payload, canonical_hash: canonicalSha256(payload) }));
}

export function correctFailureObservation(
  currentInput: FailureObservation,
  patch: FailureObservationCorrectionPatch,
  options: CorrectFailureObservationOptions,
): FailureObservation {
  const current = parseFailureObservation(currentInput, options.resolve_predecessor);
  if (current.revision !== options.expected_revision) throw new Error("FAILURE_OBSERVATION_REVISION_CONFLICT");
  assertPlainPatch(patch, "FAILURE_OBSERVATION_CORRECTION_FORBIDDEN_FIELD");
  const allowed = new Set(["provenance_ids", "artifact_refs", "failure", "environment", "sensitivity", "redaction", "observed_at"]);
  if (Object.keys(patch).some(key => !allowed.has(key))) throw new Error("FAILURE_OBSERVATION_CORRECTION_FORBIDDEN_FIELD");
  const floor = current.correction?.at ?? current.observed_at;
  if (Date.parse(options.at) < Date.parse(floor)) throw new Error("FAILURE_OBSERVATION_CORRECTION_TIME_INVALID");
  if (patch.provenance_ids && current.provenance_ids.some(reference => !patch.provenance_ids!.includes(reference))) {
    throw new Error("FAILURE_OBSERVATION_PROVENANCE_REMOVAL_FORBIDDEN");
  }
  const revision = current.revision + 1;
  const payload = failureObservationPayloadSchema.parse({
    schema_version: 1,
    observation_id: current.observation_id,
    revision_id: observationRevisionId(current.observation_id, revision),
    revision,
    previous_revision_id: current.revision_id,
    previous_observation_hash: current.canonical_hash,
    provenance_ids: patch.provenance_ids ?? current.provenance_ids,
    source_phase: current.source_phase,
    task_id: current.task_id,
    execution_id: current.execution_id,
    attempt_id: current.attempt_id,
    artifact_refs: patch.artifact_refs ?? current.artifact_refs,
    scope: current.scope,
    failure: patch.failure ?? current.failure,
    environment: patch.environment ?? current.environment,
    sensitivity: patch.sensitivity ?? current.sensitivity,
    redaction: patch.redaction ?? current.redaction,
    observed_at: patch.observed_at ?? current.observed_at,
    correction: { reason: options.reason, actor: options.actor, at: options.at },
  });
  assertArtifactScope(payload);
  assertObservationSecretSafe(payload);
  return deepFreezePhase7(failureObservationSchema.parse({ ...payload, canonical_hash: canonicalSha256(payload) }));
}

export function parseFailureObservation(input: unknown, resolvePredecessor?: FailureObservationPredecessorResolver): FailureObservation {
  return parseFailureObservationInternal(input, resolvePredecessor, new Set());
}

function parseFailureObservationInternal(input: unknown, resolvePredecessor: FailureObservationPredecessorResolver | undefined, visiting: Set<string>): FailureObservation {
  const value = failureObservationSchema.parse(input);
  assertArtifactScope(value);
  assertObservationSecretSafe(value);
  const { canonical_hash, ...payload } = value;
  if (canonicalSha256(payload) !== canonical_hash) throw new Error("FAILURE_OBSERVATION_HASH_MISMATCH");
  if (value.revision > 1) {
    if (!resolvePredecessor) throw new Error("FAILURE_OBSERVATION_PREDECESSOR_REQUIRED");
    if (visiting.has(value.revision_id)) throw new Error("FAILURE_OBSERVATION_PREDECESSOR_MISMATCH");
    visiting.add(value.revision_id);
    const predecessorInput = resolvePredecessor(value.previous_revision_id!);
    if (predecessorInput === undefined || predecessorInput === null) throw new Error("FAILURE_OBSERVATION_PREDECESSOR_NOT_FOUND");
    const predecessor = parseFailureObservationInternal(predecessorInput, resolvePredecessor, visiting);
    visiting.delete(value.revision_id);
    const sameSourceIdentity = predecessor.observation_id === value.observation_id
      && predecessor.source_phase === value.source_phase
      && predecessor.task_id === value.task_id
      && predecessor.execution_id === value.execution_id
      && predecessor.attempt_id === value.attempt_id
      && samePhase7Scope(predecessor.scope, value.scope);
    if (!sameSourceIdentity
      || predecessor.revision + 1 !== value.revision
      || predecessor.revision_id !== value.previous_revision_id
      || predecessor.canonical_hash !== value.previous_observation_hash) {
      throw new Error("FAILURE_OBSERVATION_PREDECESSOR_MISMATCH");
    }
  }
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

function observationRevisionId(observationId: string, revision: number): string {
  return `observation-revision:${canonicalSha256({ observation_id: observationId, revision }).slice(7, 39)}`;
}

function assertPlainPatch(value: unknown, code: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length > 0) throw new Error(code);
  if (Object.keys(value).some(key => !Object.getOwnPropertyDescriptor(value, key) || !("value" in Object.getOwnPropertyDescriptor(value, key)!))) throw new Error(code);
}
