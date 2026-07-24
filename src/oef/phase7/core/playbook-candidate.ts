import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { actorSchema } from "../../phase1/core/shared/actor";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { deepFreezePhase7, phase7HashSchema, phase7IdentifierSchema, phase7ScopeSchema, phase7TimestampSchema } from "./shared";

const playbookCandidatePayloadSchema = z.object({
  schema_version: z.literal(1),
  candidate_id: phase7IdentifierSchema,
  source_incident_id: phase7IdentifierSchema,
  scope: phase7ScopeSchema,
  title: z.string().trim().min(3).max(1_000),
  trigger_signature: phase7HashSchema,
  steps: z.array(z.string().trim().min(3).max(2_000)).min(1).max(64),
  status: z.literal("CANDIDATE"),
  created_at: phase7TimestampSchema,
  created_by: actorSchema,
}).strict();

export const playbookCandidateSchema = playbookCandidatePayloadSchema.extend({ candidate_hash: phase7HashSchema }).strict();
export type PlaybookCandidate = z.infer<typeof playbookCandidateSchema>;
export type PlaybookCandidateInput = Omit<z.input<typeof playbookCandidatePayloadSchema>, "schema_version" | "status">;

export function createPlaybookCandidate(input: PlaybookCandidateInput): PlaybookCandidate {
  const payload = playbookCandidatePayloadSchema.parse({ schema_version: 1, ...input, status: "CANDIDATE" });
  assertCandidateSecretSafe(payload);
  return deepFreezePhase7(playbookCandidateSchema.parse({ ...payload, candidate_hash: canonicalSha256(payload) }));
}
export function parsePlaybookCandidate(input: unknown): PlaybookCandidate {
  const value = playbookCandidateSchema.parse(input);
  assertCandidateSecretSafe(value);
  const { candidate_hash, ...payload } = value;
  if (canonicalSha256(payload) !== candidate_hash) throw new Error("PLAYBOOK_CANDIDATE_HASH_MISMATCH");
  return deepFreezePhase7(value);
}

function assertCandidateSecretSafe(value: unknown): void {
  try {
    assertNoStructuredPhase1Secret(value);
    assertNoPhase1Secret(JSON.stringify(value), "playbook candidate");
  } catch {
    throw new Error("PLAYBOOK_CANDIDATE_SECRET_REJECTED");
  }
}
