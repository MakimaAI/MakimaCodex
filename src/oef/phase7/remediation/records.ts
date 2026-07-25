import { z } from "zod";
import { actorSchema, type Actor } from "../../phase1/core/shared/actor";
import { deepFreezePhase7, phase7HashSchema, phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema, type Phase7Scope } from "../core/shared";

const evidenceRefsSchema = z.array(phase7IdentifierSchema).min(1).max(64).refine(values => new Set(values).size === values.length);
export interface RemediationProposalInput { proposal_id: string; summary: string; steps: string[]; plan_hash: string; patch_hash: string; evidence_refs: string[]; proposed_by: Actor; at: string }
export interface RegressionResultInput { regression_id: string; remediation_id: string; plan_hash: string; patch_hash: string; phase: "BEFORE" | "AFTER"; result: "FAIL" | "PASS"; evidence_ref: string; actor: Actor; at: string }
export interface ReviewVerdictInput { review_id: string; proposal_id: string; plan_hash: string; patch_hash: string; verdict: "APPROVED" | "REJECTED"; reviewer: Actor; rationale: string; evidence_refs: string[]; at: string }

export const remediationProposalSchema = z.object({
  proposal_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema,
  summary: z.string().trim().min(3).max(5_000), steps: z.array(z.string().trim().min(3).max(2_000)).min(1).max(64),
  plan_hash: phase7HashSchema, patch_hash: phase7HashSchema, evidence_refs: evidenceRefsSchema, proposed_by: actorSchema, at: phase7TimestampSchema,
  state: z.literal("PROPOSED"), source_write_performed: z.literal(false), production_deploy_performed: z.literal(false),
}).strict();
export const regressionResultRecordSchema = z.object({
  regression_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, remediation_id: phase7IdentifierSchema,
  plan_hash: phase7HashSchema, patch_hash: phase7HashSchema, phase: z.enum(["BEFORE", "AFTER"]), result: z.enum(["FAIL", "PASS"]), evidence_ref: phase7IdentifierSchema, actor: actorSchema, at: phase7TimestampSchema,
}).strict();
export const reviewVerdictRecordSchema = z.object({
  review_id: phase7IdentifierSchema, incident_id: phase7IdentifierSchema, scope: phase7ScopeSchema, proposal_id: phase7IdentifierSchema,
  plan_hash: phase7HashSchema, patch_hash: phase7HashSchema, verdict: z.enum(["APPROVED", "REJECTED"]), reviewer: actorSchema,
  rationale: z.string().trim().min(3).max(5_000), evidence_refs: evidenceRefsSchema, at: phase7TimestampSchema, independent: z.literal(true),
}).strict();
export type RemediationProposalRecord = z.infer<typeof remediationProposalSchema>;
export type RegressionResultRecord = z.infer<typeof regressionResultRecordSchema>;
export type ReviewVerdictRecord = z.infer<typeof reviewVerdictRecordSchema>;

export function remediationProposalRecord(incidentId: string, scope: Phase7Scope, input: RemediationProposalInput): RemediationProposalRecord {
  assertScoped(scope, input.evidence_refs, "REMEDIATION_EVIDENCE_SCOPE_MISMATCH");
  return deepFreezePhase7(remediationProposalSchema.parse({ ...input, incident_id: incidentId, scope, state: "PROPOSED", source_write_performed: false, production_deploy_performed: false }));
}
export function regressionResultRecord(incidentId: string, scope: Phase7Scope, input: RegressionResultInput): RegressionResultRecord {
  assertScoped(scope, [input.evidence_ref], "REGRESSION_EVIDENCE_SCOPE_MISMATCH");
  return deepFreezePhase7(regressionResultRecordSchema.parse({ ...input, incident_id: incidentId, scope }));
}
export function reviewVerdictRecord(incidentId: string, scope: Phase7Scope, input: ReviewVerdictInput): ReviewVerdictRecord {
  assertScoped(scope, input.evidence_refs, "REVIEW_EVIDENCE_SCOPE_MISMATCH");
  return deepFreezePhase7(reviewVerdictRecordSchema.parse({ ...input, incident_id: incidentId, scope, independent: true }));
}
function assertScoped(scope: Phase7Scope, refs: string[], code: string): void { if (refs.some(ref => !ref.startsWith(`artifact:${scope.id}:`))) throw new Error(code); }
