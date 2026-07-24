import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z, type ZodType } from "zod";
import {
  findingValidationSchema,
  humanReviewApprovalSchema,
  repairProposalSchema,
  reviewDecisionRecordSchema,
  reviewFindingSchema,
  reviewPlanSchema,
  reviewProfileSchema,
  reviewResultSchema,
  reviewerBindingSchema,
  waiverSchema,
} from "../src/oef/phase3";

export interface Phase3PublicSchemaEntry {
  readonly file: string;
  readonly schema: ZodType;
}

export const PHASE3_PUBLIC_SCHEMAS: readonly Phase3PublicSchemaEntry[] = [
  { file: "review-profile-v1.schema.json", schema: reviewProfileSchema },
  { file: "review-plan-v1.schema.json", schema: reviewPlanSchema },
  { file: "review-result-v1.schema.json", schema: reviewResultSchema },
  { file: "review-finding-v1.schema.json", schema: reviewFindingSchema },
  { file: "reviewer-binding-v1.schema.json", schema: reviewerBindingSchema },
  { file: "review-decision-v1.schema.json", schema: reviewDecisionRecordSchema },
  { file: "finding-validation-v1.schema.json", schema: findingValidationSchema },
  { file: "waiver-v1.schema.json", schema: waiverSchema },
  { file: "repair-proposal-v1.schema.json", schema: repairProposalSchema },
  { file: "human-review-approval-v1.schema.json", schema: humanReviewApprovalSchema },
] as const;

export function phase3JsonSchemaDocument(entry: Phase3PublicSchemaEntry): Record<string, unknown> {
  return {
    ...z.toJSONSchema(entry.schema),
    $id: `https://opencodex.local/schemas/oef/phase3/${entry.file}`,
  };
}

export function generatePhase3Schemas(outputRoot = fileURLToPath(new URL("../schemas/oef-phase3/", import.meta.url))): void {
  mkdirSync(outputRoot, { recursive: true });
  for (const entry of PHASE3_PUBLIC_SCHEMAS) {
    writeFileSync(join(outputRoot, entry.file), `${JSON.stringify(phase3JsonSchemaDocument(entry), null, 2)}\n`, "utf8");
  }
}

if (import.meta.main) generatePhase3Schemas();
