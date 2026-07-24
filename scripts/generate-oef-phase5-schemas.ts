import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { z, type ZodType } from "zod";
import {
  agentProfileSchema, candidateSchema, candidateSetSchema, executionBindingSetSchema, fallbackGraphSchema, handoffPackageSchema,
  roleDefinitionSchema, routingContextSnapshotSchema, routingOutcomeSchema, routingPlanSchema, routingPolicySchema,
  taskFingerprintSchema, teamBlueprintSchema, teamPlanSchema,
} from "../src/oef/phase5";

export const PHASE5_PUBLIC_SCHEMAS: readonly { file: string; schema: ZodType }[] = [
  { file: "task-fingerprint-v1.schema.json", schema: taskFingerprintSchema },
  { file: "role-definition-v1.schema.json", schema: roleDefinitionSchema },
  { file: "agent-profile-v1.schema.json", schema: agentProfileSchema },
  { file: "team-blueprint-v1.schema.json", schema: teamBlueprintSchema },
  { file: "team-plan-v1.schema.json", schema: teamPlanSchema },
  { file: "candidate-v1.schema.json", schema: candidateSchema },
  { file: "candidate-set-v1.schema.json", schema: candidateSetSchema },
  { file: "routing-context-snapshot-v1.schema.json", schema: routingContextSnapshotSchema },
  { file: "routing-policy-v1.schema.json", schema: routingPolicySchema },
  { file: "routing-plan-v1.schema.json", schema: routingPlanSchema },
  { file: "fallback-graph-v1.schema.json", schema: fallbackGraphSchema },
  { file: "execution-binding-set-v1.schema.json", schema: executionBindingSetSchema },
  { file: "handoff-package-v1.schema.json", schema: handoffPackageSchema },
  { file: "routing-outcome-v1.schema.json", schema: routingOutcomeSchema },
] as const;

export function phase5JsonSchemaDocument(entry: { file: string; schema: ZodType }): Record<string, unknown> {
  return { ...z.toJSONSchema(entry.schema), $id: `https://opencodex.local/schemas/oef/phase5/${entry.file}` };
}
export function generatePhase5Schemas(outputRoot = fileURLToPath(new URL("../schemas/oef-phase5/", import.meta.url))): void {
  mkdirSync(outputRoot, { recursive: true });
  for (const entry of PHASE5_PUBLIC_SCHEMAS) writeFileSync(join(outputRoot, entry.file), `${JSON.stringify(phase5JsonSchemaDocument(entry), null, 2)}\n`, "utf8");
}
if (import.meta.main) generatePhase5Schemas();
