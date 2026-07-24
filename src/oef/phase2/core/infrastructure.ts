import { z } from "zod";

const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);

export const runtimeDefinitionSchema = z.object({
  schema_version: z.literal(1),
  runtime_id: z.string().regex(/^runtime:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  adapter_id: z.string().trim().min(1).max(300),
  adapter_version: semverSchema,
  protocol: z.object({ min: z.number().int().positive(), max: z.number().int().positive() }).strict(),
  installed_at: z.string().datetime(),
}).strict().refine(value => value.protocol.min <= value.protocol.max, "Protocol minimum cannot exceed maximum");
export type Phase2RuntimeDefinition = z.infer<typeof runtimeDefinitionSchema>;
export function parseRuntimeDefinition(input: unknown): Phase2RuntimeDefinition { return runtimeDefinitionSchema.parse(input); }

export const runnerInstanceSchema = z.object({
  schema_version: z.literal(1),
  runner_id: z.string().regex(/^runner:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  instance_nonce: z.string().trim().min(12).max(500),
  protocol_version: z.number().int().positive(),
  status: z.enum(["STARTING", "HEALTHY", "DEGRADED", "PAUSED", "LOST", "STOPPED"]),
  started_at: z.string().datetime(),
  heartbeat_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (Date.parse(value.heartbeat_at) < Date.parse(value.started_at)) {
    context.addIssue({ code: "custom", path: ["heartbeat_at"], message: "Runner heartbeat cannot predate startup" });
  }
});
export type RunnerInstance = z.infer<typeof runnerInstanceSchema>;
export function parseRunnerInstance(input: unknown): RunnerInstance { return runnerInstanceSchema.parse(input); }

export const checkpointSchema = z.object({
  schema_version: z.literal(1),
  checkpoint_id: z.string().regex(/^checkpoint:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  type: z.enum(["WORKSPACE_SNAPSHOT", "RUNTIME_SESSION", "VERIFICATION_BASELINE", "MANUAL_CHECKPOINT"]),
  attempt_id: z.string().regex(/^attempt:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  sequence: z.number().int().nonnegative(),
  workspace: z.object({ commit_or_snapshot: z.string().trim().min(1).max(500), diff_hash: hashSchema }).strict(),
  runtime: z.object({
    native_session_id_ref: z.string().regex(/^secret-ref:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/).nullable(),
    resumable: z.boolean(),
  }).strict(),
  progress: z.object({ completed_steps: z.array(z.string().trim().min(1).max(500)).max(10_000) }).strict(),
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  if (value.runtime.resumable !== (value.runtime.native_session_id_ref !== null)) {
    context.addIssue({ code: "custom", path: ["runtime"], message: "Resumable checkpoints require only a secure session reference" });
  }
});
export type Checkpoint = z.infer<typeof checkpointSchema>;
export function parseCheckpoint(input: unknown): Checkpoint { return checkpointSchema.parse(input); }
