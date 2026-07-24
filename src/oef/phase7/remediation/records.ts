import type { Actor } from "../../phase1/core/shared/actor";

export interface RemediationProposalInput {
  proposal_id: string;
  summary: string;
  steps: string[];
  proposed_by: Actor;
  at: string;
}
export interface RegressionResultInput {
  regression_id: string;
  phase: "BEFORE" | "AFTER";
  result: "FAIL" | "PASS";
  evidence_ref: string;
  actor: Actor;
  at: string;
}
export interface ReviewVerdictInput {
  review_id: string;
  proposal_id: string;
  verdict: "APPROVED" | "REJECTED";
  reviewer: Actor;
  rationale: string;
  at: string;
}

export function remediationProposalRecord(incidentId: string, input: RemediationProposalInput): Record<string, unknown> {
  return { ...input, incident_id: incidentId, state: "PROPOSED", source_write_performed: false, production_deploy_performed: false };
}
export function regressionResultRecord(incidentId: string, input: RegressionResultInput): Record<string, unknown> {
  return { ...input, incident_id: incidentId };
}
export function reviewVerdictRecord(incidentId: string, input: ReviewVerdictInput): Record<string, unknown> {
  return { ...input, incident_id: incidentId, independent: true };
}
