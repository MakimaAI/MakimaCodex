import { z } from "zod";
import { actorSchema, type Actor } from "../shared/actor";
import { versionedDefinitionRefSchema, type VersionedDefinitionRef } from "../task/task";

export const VERDICT_DECISIONS = [
  "ACCEPT",
  "REPAIR",
  "REDISPATCH",
  "ESCALATE_MODEL",
  "ESCALATE_ARCHITECTURE",
  "NEEDS_HUMAN",
  "BLOCK",
] as const;
export const VERDICT_STATUSES = ["CURRENT", "STALE", "SUPERSEDED"] as const;

export type VerdictDecision = typeof VERDICT_DECISIONS[number];
export type VerdictStatus = typeof VERDICT_STATUSES[number];

export interface Verdict {
  schema_version: 1;
  verdict_id: string;
  task_id: string;
  scope: { type: "task"; id: string };
  contract_revision_id: string;
  decision: VerdictDecision;
  status: VerdictStatus;
  rationale: string;
  evidence_refs: string[];
  missing_requirements: string[];
  issued_by: Actor;
  policy_pack_ref: VersionedDefinitionRef;
  repository_commit: string | null;
  dependency_hashes: {
    contract: string;
    workflow: string;
    policy: string;
    evidence: Array<{ evidence_id: string; evidence_hash: string }>;
  };
  created_at: string;
}

export const verdictSchema = z.object({
  schema_version: z.literal(1),
  verdict_id: z.string().trim().min(1),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  scope: z.object({ type: z.literal("task"), id: z.string().trim().min(1) }).strict(),
  contract_revision_id: z.string().trim().min(1),
  decision: z.enum(VERDICT_DECISIONS),
  status: z.enum(VERDICT_STATUSES),
  rationale: z.string().trim().min(1).max(10_000),
  evidence_refs: z.array(z.string().trim().min(1)).max(256),
  missing_requirements: z.array(z.string().trim().min(1)).max(512),
  issued_by: actorSchema,
  policy_pack_ref: versionedDefinitionRefSchema,
  repository_commit: z.string().trim().min(1).max(300).nullable(),
  dependency_hashes: z.object({
    contract: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    workflow: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    policy: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    evidence: z.array(z.object({
      evidence_id: z.string().trim().min(1),
      evidence_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
    }).strict()).max(256),
  }).strict(),
  created_at: z.string().datetime(),
}).strict();

export function parseVerdict(input: unknown): Verdict {
  return verdictSchema.parse(input) as Verdict;
}
