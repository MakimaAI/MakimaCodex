import { z } from "zod";
import { actorSchema } from "../../phase1/core/shared/actor";
import { assertMemoryRecordIntegrity, memoryRecordSchema, type MemoryRecord } from "../../phase6/core/domain";
import { parsePlaybookCandidate } from "../core/playbook-candidate";
import { incidentSchema } from "../core/incident";
import { phase7HashSchema, phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema, type Phase7Scope } from "../core/shared";
import { parseReproductionManifest, parseReproductionResult, type ReproductionManifest } from "../reproduction/manifest";
import { regressionResultRecordSchema, remediationProposalSchema, reviewVerdictRecordSchema } from "../remediation/records";

export const INCIDENT_RECORD_KINDS = ["TRIAGE", "CONTAINMENT", "REPRODUCTION_MANIFEST", "REPRODUCTION", "HYPOTHESIS_EVIDENCE", "ROOT_CAUSE", "REMEDIATION", "REGRESSION", "REVIEW", "PLAYBOOK"] as const;
export type IncidentRecordKind = typeof INCIDENT_RECORD_KINDS[number];

const triageSchema = z.object({
  record_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema,
  severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]), priority: z.enum(["P0", "P1", "P2", "P3"]), confidence: z.number().min(0).max(1),
  required_approval: z.enum(["A3", "A4", "A5"]), actor: actorSchema, at: phase7TimestampSchema,
}).strict();
const containmentSchema = z.object({
  record_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, summary: z.string().trim().min(3).max(5_000),
  autonomy: z.enum(["A0", "A1", "A2", "A3", "A4", "A5"]), reversible: z.boolean(), state: z.enum(["EXECUTED", "PROPOSED"]), execution_kind: z.enum(["LOCAL_RECORD_ONLY", "NONE"]),
  required_approval: z.enum(["A3", "A4", "A5"]).nullable(), approved_by: actorSchema.nullable(), production_action_performed: z.literal(false), actor: actorSchema, at: phase7TimestampSchema,
}).strict();
const hypothesisEvidenceSchema = z.object({
  experiment_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, hypothesis_id: phase7IdentifierSchema,
  outcome: z.enum(["SUPPORTS", "REJECTS"]), evidence_refs: z.array(phase7IdentifierSchema).min(1).max(64), controlled_intervention: z.literal(true), actor: actorSchema, at: phase7TimestampSchema,
}).strict();
const rootCauseRecordSchema = z.object({ incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, adjudication_id: phase7IdentifierSchema, root_cause: incidentSchema.shape.root_cause, at: phase7TimestampSchema }).strict();

const recordSchemas: Record<Exclude<IncidentRecordKind, "REPRODUCTION_MANIFEST" | "REPRODUCTION" | "PLAYBOOK">, z.ZodType> = {
  TRIAGE: triageSchema,
  CONTAINMENT: containmentSchema,
  HYPOTHESIS_EVIDENCE: hypothesisEvidenceSchema,
  ROOT_CAUSE: rootCauseRecordSchema,
  REMEDIATION: remediationProposalSchema,
  REGRESSION: regressionResultRecordSchema,
  REVIEW: reviewVerdictRecordSchema,
};

export const incidentRecordEnvelopeSchema = z.object({
  schema_version: z.literal(1), record_type: z.enum(INCIDENT_RECORD_KINDS), record_id: phase7IdentifierSchema,
  incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, occurred_at: phase7TimestampSchema,
  data: z.record(z.string(), z.unknown()),
}).strict();
export type IncidentRecordEnvelope = z.infer<typeof incidentRecordEnvelopeSchema>;

export function validateIncidentRecordData(kind: IncidentRecordKind, data: unknown, manifest?: ReproductionManifest): Record<string, unknown> {
  if (kind === "REPRODUCTION_MANIFEST") return parseReproductionManifest(data) as unknown as Record<string, unknown>;
  if (kind === "REPRODUCTION") {
    if (!manifest) throw new Error("REPRODUCTION_MANIFEST_REQUIRED");
    return parseReproductionResult(data, manifest) as unknown as Record<string, unknown>;
  }
  if (kind === "PLAYBOOK") return parsePlaybookCandidate(data) as unknown as Record<string, unknown>;
  return recordSchemas[kind].parse(data) as Record<string, unknown>;
}

export function recordIdentity(kind: IncidentRecordKind, data: Record<string, unknown>): string {
  const key: Record<IncidentRecordKind, string> = { TRIAGE: "record_id", CONTAINMENT: "record_id", REPRODUCTION_MANIFEST: "manifest_id", REPRODUCTION: "result_id", HYPOTHESIS_EVIDENCE: "experiment_id", ROOT_CAUSE: "adjudication_id", REMEDIATION: "proposal_id", REGRESSION: "regression_id", REVIEW: "review_id", PLAYBOOK: "candidate_id" };
  const value = data[key[kind]];
  if (typeof value !== "string") throw new Error("PHASE7_RECORD_IDENTITY_INVALID");
  return value;
}

export const memoryWriteBatchPayloadSchema = z.object({
  schema_version: z.literal(1), batch_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema,
  closure_revision_hash: phase7HashSchema, records: z.array(memoryRecordSchema).length(3), created_at: phase7TimestampSchema,
}).strict();
export const memoryWriteBatchSchema = memoryWriteBatchPayloadSchema.extend({ batch_hash: phase7HashSchema }).strict();
export type MemoryWriteBatch = z.infer<typeof memoryWriteBatchSchema>;
export function assertMemoryBatchRecords(records: readonly MemoryRecord[]): void { for (const record of records) assertMemoryRecordIntegrity(record); }
