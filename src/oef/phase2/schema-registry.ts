import type { ZodType } from "zod";
import {
  assignmentSchema,
  executionAttemptSchema,
  executionBindingSchema,
  executionManifestSchema,
  executionSchema,
  failureSchema,
} from "./core/domain";
import { phase2CommandEnvelopeSchema } from "./application/command-bus";
import {
  normalizedRuntimeEventSchema,
  runtimeLaunchPlanSchema,
  runtimeManifestSchema,
} from "./runtime/protocol";
import { contextBundleSchema } from "./context/context-bundle";
import { observableTrajectorySchema } from "./context/trajectory";
import { verificationPlanSchema } from "./verification/models";
import { evidencePackageSchema } from "./evidence/evidence-package";
import { checkpointSchema, runnerInstanceSchema, runtimeDefinitionSchema } from "./core/infrastructure";

export const PHASE2_PUBLIC_SCHEMAS: readonly { file: string; schema: ZodType }[] = [
  { file: "assignment-v1.schema.json", schema: assignmentSchema },
  { file: "execution-binding-v1.schema.json", schema: executionBindingSchema },
  { file: "execution-v1.schema.json", schema: executionSchema },
  { file: "execution-attempt-v1.schema.json", schema: executionAttemptSchema },
  { file: "failure-v1.schema.json", schema: failureSchema },
  { file: "execution-manifest-v1.schema.json", schema: executionManifestSchema },
  { file: "command-envelope-v1.schema.json", schema: phase2CommandEnvelopeSchema },
  { file: "runtime-manifest-v1.schema.json", schema: runtimeManifestSchema },
  { file: "runtime-launch-plan-v1.schema.json", schema: runtimeLaunchPlanSchema },
  { file: "normalized-runtime-event-v1.schema.json", schema: normalizedRuntimeEventSchema },
  { file: "context-bundle-v1.schema.json", schema: contextBundleSchema },
  { file: "observable-trajectory-v1.schema.json", schema: observableTrajectorySchema },
  { file: "verification-plan-v1.schema.json", schema: verificationPlanSchema },
  { file: "evidence-package-v1.schema.json", schema: evidencePackageSchema },
  { file: "runtime-definition-v1.schema.json", schema: runtimeDefinitionSchema },
  { file: "runner-instance-v1.schema.json", schema: runnerInstanceSchema },
  { file: "checkpoint-v1.schema.json", schema: checkpointSchema },
];
