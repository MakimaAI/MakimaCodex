import { z } from "zod";
import { artifactRefSchema, type ArtifactRef } from "../../artifacts/interfaces/artifact-store";
import { actorSchema, type Actor } from "../shared/actor";

export const EVIDENCE_STATUSES = ["RECORDED", "VERIFIED", "REJECTED", "INVALIDATED", "STALE"] as const;
export type EvidenceStatus = typeof EVIDENCE_STATUSES[number];

export interface EvidenceRecord {
  schema_version: 1;
  evidence_id: string;
  task_id: string;
  contract_revision_id: string;
  criterion_key: string;
  type: string;
  status: EvidenceStatus;
  producer: Actor;
  summary: string;
  artifacts: ArtifactRef[];
  environment: Record<string, unknown>;
  created_at: string;
  verified_at: string | null;
}

export const evidenceRecordSchema = z.object({
  schema_version: z.literal(1),
  evidence_id: z.string().trim().min(1),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  contract_revision_id: z.string().trim().min(1),
  criterion_key: z.string().trim().min(1),
  type: z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/i),
  status: z.enum(EVIDENCE_STATUSES),
  producer: actorSchema,
  summary: z.string().trim().min(1).max(10_000),
  artifacts: z.array(artifactRefSchema).max(64),
  environment: z.record(z.string(), z.unknown()),
  created_at: z.string().datetime(),
  verified_at: z.string().datetime().nullable(),
}).strict();

export function parseEvidenceRecord(input: unknown): EvidenceRecord {
  return evidenceRecordSchema.parse(input) as EvidenceRecord;
}
