import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { ArtifactRef, ArtifactStore } from "../../phase1/artifacts/interfaces/artifact-store";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const artifactSchema = z.object({ artifact_id: z.string().regex(/^artifact:/), content_hash: hashSchema }).strict();
const evidenceInputSchema = artifactSchema.extend({ type: z.string().regex(/^[a-z0-9][a-z0-9-]*$/) }).strict();
const evidenceSchema = evidenceInputSchema.extend({ valid: z.literal(true) }).strict();

export const evidencePackageInputSchema = z.object({
  task_id: z.string().regex(/^task:/),
  contract_revision_id: z.string().regex(/^contract-revision:/),
  assignment_id: z.string().regex(/^assignment:/),
  attempt_id: z.string().regex(/^attempt:/),
  manifest_ref: artifactSchema,
  evidence: z.array(evidenceInputSchema).max(256),
  result: z.object({
    execution_completed: z.boolean(),
    mechanical_verification: z.enum(["PASSED", "FAILED", "BLOCKED", "NOT_RUN"]),
  }).strict(),
}).strict();

export type EvidencePackageInput = z.infer<typeof evidencePackageInputSchema>;

export interface EvidencePackage extends Omit<EvidencePackageInput, "evidence"> {
  schema_version: 1;
  evidence_package_id: string;
  evidence: Array<z.infer<typeof evidenceSchema>>;
  integrity: { package_hash: string; artifacts_valid: boolean };
}

export const evidencePackageSchema = evidencePackageInputSchema.omit({ evidence: true }).extend({
  schema_version: z.literal(1),
  evidence_package_id: z.string().regex(/^evidence-package:[a-f0-9]{64}$/),
  evidence: z.array(evidenceSchema).max(256),
  integrity: z.object({ package_hash: hashSchema, artifacts_valid: z.boolean() }).strict(),
}).strict();

export class EvidencePackageBuilder {
  constructor(private readonly artifactStore: ArtifactStore) {}

  build(input: EvidencePackageInput, artifactCatalog: readonly ArtifactRef[]): EvidencePackage {
    const parsed = evidencePackageInputSchema.parse(input);
    const catalog = new Map(artifactCatalog.map(ref => [ref.artifact_id, ref]));
    const checked = [parsed.manifest_ref, ...parsed.evidence].map(reference => {
      const stored = catalog.get(reference.artifact_id);
      if (!stored || stored.content_hash !== reference.content_hash) throw new Error(`EVIDENCE_ARTIFACT_REFERENCE_INVALID: ${reference.artifact_id}`);
      const integrity = this.artifactStore.verify(stored);
      if (!integrity.valid || integrity.content_hash !== reference.content_hash) throw new Error(`EVIDENCE_ARTIFACT_INTEGRITY_FAILED: ${reference.artifact_id}`);
      return stored;
    });
    if (new Set(checked.map(ref => ref.artifact_id)).size !== checked.length) throw new Error("EVIDENCE_ARTIFACT_REFERENCE_DUPLICATED");
    const evidence = parsed.evidence.map(item => ({ ...item, valid: true as const }));
    const content = { schema_version: 1 as const, ...parsed, evidence };
    const packageHash = canonicalSha256(content);
    return evidencePackageSchema.parse({
      ...content,
      evidence_package_id: `evidence-package:${packageHash.slice("sha256:".length)}`,
      integrity: { package_hash: packageHash, artifacts_valid: true },
    }) as EvidencePackage;
  }
}
