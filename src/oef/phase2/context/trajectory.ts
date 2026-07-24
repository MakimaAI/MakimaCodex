import { z } from "zod";

export const observableTrajectorySchema = z.object({
  schema_version: z.literal(1),
  trajectory_id: z.string().regex(/^trajectory:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  task_features: z.object({
    task_type: z.string().trim().min(1).max(160),
    languages: z.array(z.string().trim().min(1).max(80)).max(64),
    risk: z.enum(["low", "medium", "high", "critical"]),
  }).strict(),
  execution: z.object({
    agent_profile: z.string().trim().min(1).max(300),
    runtime: z.string().trim().min(1).max(300),
    adapter_version: z.string().regex(/^\d+\.\d+\.\d+$/),
    model_id: z.string().trim().min(1).max(500).nullable(),
  }).strict(),
  observable_actions: z.array(z.object({
    type: z.enum(["file-read", "file-write", "command", "tool", "test", "checkpoint", "human-correction"]),
    summary: z.string().trim().min(1).max(2_000),
  }).strict()).max(100_000),
  outcome: z.object({
    execution_status: z.enum(["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"]),
    verification_status: z.enum(["PASSED", "FAILED", "BLOCKED", "NOT_RUN"]),
    verdict: z.enum(["READY_FOR_REVIEW", "REPAIR_REQUIRED", "BLOCKED"]).nullable(),
  }).strict(),
  metrics: z.object({
    wall_time_ms: z.number().int().nonnegative(),
    tokens: z.number().int().nonnegative(),
    changed_files: z.number().int().nonnegative(),
    tests_passed: z.number().int().nonnegative(),
    tests_failed: z.number().int().nonnegative(),
  }).strict(),
}).strict();

export type ObservableTrajectory = z.infer<typeof observableTrajectorySchema>;
export function parseObservableTrajectory(input: unknown): ObservableTrajectory { return observableTrajectorySchema.parse(input); }
