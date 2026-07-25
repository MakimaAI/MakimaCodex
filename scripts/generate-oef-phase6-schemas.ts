import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z, type ZodType } from "zod";
import {
  embeddingProfileSchema,
  memoryCandidateSchema,
  memoryConflictSchema,
  memoryIngestionJobSchema,
  memoryPluginManifestSchema,
  memoryRecordSchema,
  memorySourceEventSchema,
} from "../src/oef/phase6";

export const PHASE6_PUBLIC_SCHEMAS: readonly { file: string; schema: ZodType }[] = [
  { file: "memory-record-v1.schema.json", schema: memoryRecordSchema },
  { file: "memory-conflict-v1.schema.json", schema: memoryConflictSchema },
  { file: "memory-source-event-v1.schema.json", schema: memorySourceEventSchema },
  { file: "memory-ingestion-job-v1.schema.json", schema: memoryIngestionJobSchema },
  { file: "memory-candidate-v1.schema.json", schema: memoryCandidateSchema },
  { file: "embedding-profile-v1.schema.json", schema: embeddingProfileSchema },
  { file: "memory-plugin-manifest-v1.schema.json", schema: memoryPluginManifestSchema },
] as const;

export function phase6JsonSchemaDocument(entry: { file: string; schema: ZodType }): Record<string, unknown> {
  return { ...z.toJSONSchema(entry.schema), $id: `https://opencodex.local/schemas/oef/phase6/${entry.file}` };
}

export function generatePhase6Schemas(outputRoot = fileURLToPath(new URL("../schemas/oef-phase6/", import.meta.url))): void {
  mkdirSync(outputRoot, { recursive: true });
  for (const entry of PHASE6_PUBLIC_SCHEMAS) {
    writeFileSync(join(outputRoot, entry.file), `${JSON.stringify(phase6JsonSchemaDocument(entry), null, 2)}\n`, "utf8");
  }
}

if (import.meta.main) generatePhase6Schemas();
