import { z } from "zod";
import { actorSchema, type Actor } from "../shared/actor";

export const TASK_STATUSES = ["DRAFT", "OPEN", "BLOCKED", "COMPLETED", "CANCELLED"] as const;
export type TaskStatus = typeof TASK_STATUSES[number];

export interface VersionedDefinitionRef {
  id: string;
  version: string;
  hash: string;
}

export interface TaskRisk {
  level: "low" | "medium" | "high" | "critical";
  reasons: string[];
}

export interface Task {
  schema_version: 1;
  task_id: string;
  title: string;
  status: TaskStatus;
  stage: string;
  active_contract_revision_id: string | null;
  workflow_ref: VersionedDefinitionRef;
  policy_pack_ref: VersionedDefinitionRef;
  risk: TaskRisk;
  created_by: Actor;
  created_at: string;
  updated_at: string;
  aggregate_version: number;
}

export const versionedDefinitionRefSchema = z.object({
  id: z.string().trim().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
}).strict();

export const taskRiskSchema = z.object({
  level: z.enum(["low", "medium", "high", "critical"]),
  reasons: z.array(z.string().trim().min(1).max(160)).max(64),
}).strict();

export const taskSchema = z.object({
  schema_version: z.literal(1),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  title: z.string().trim().min(1).max(500),
  status: z.enum(TASK_STATUSES),
  stage: z.string().trim().min(1),
  active_contract_revision_id: z.string().trim().min(1).nullable(),
  workflow_ref: versionedDefinitionRefSchema,
  policy_pack_ref: versionedDefinitionRefSchema,
  risk: taskRiskSchema,
  created_by: actorSchema,
  created_at: z.string().datetime(),
  updated_at: z.string().datetime(),
  aggregate_version: z.number().int().nonnegative(),
}).strict();

export function parseTask(input: unknown): Task {
  return taskSchema.parse(input) as Task;
}
