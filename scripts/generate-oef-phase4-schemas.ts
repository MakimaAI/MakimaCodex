import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z, type ZodType } from "zod";
import {
  benchmarkSuiteSchema, capabilityClaimSchema, capabilityObservationSchema, executionConfigurationSchema,
  modelVersionSchema, roleProfileSchema,
} from "../src/oef/phase4";

export const PHASE4_PUBLIC_SCHEMAS: readonly { file: string; schema: ZodType }[] = [
  { file: "model-version-v1.schema.json", schema: modelVersionSchema },
  { file: "capability-claim-v1.schema.json", schema: capabilityClaimSchema },
  { file: "capability-observation-v1.schema.json", schema: capabilityObservationSchema },
  { file: "execution-configuration-v1.schema.json", schema: executionConfigurationSchema },
  { file: "role-profile-v1.schema.json", schema: roleProfileSchema },
  { file: "benchmark-suite-v1.schema.json", schema: benchmarkSuiteSchema },
] as const;

export function phase4JsonSchemaDocument(entry: { file: string; schema: ZodType }): Record<string, unknown> {
  return { ...z.toJSONSchema(entry.schema), $id: `https://opencodex.local/schemas/oef/phase4/${entry.file}` };
}
export function generatePhase4Schemas(outputRoot = fileURLToPath(new URL("../schemas/oef-phase4/", import.meta.url))): void {
  mkdirSync(outputRoot, { recursive: true });
  for (const entry of PHASE4_PUBLIC_SCHEMAS) writeFileSync(join(outputRoot, entry.file), `${JSON.stringify(phase4JsonSchemaDocument(entry), null, 2)}\n`, "utf8");
}
if (import.meta.main) generatePhase4Schemas();
