import { z } from "zod";

const commandStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  type: z.literal("command"),
  command: z.object({
    executable: z.string().trim().min(1).max(4_000),
    arguments: z.array(z.string().max(50_000)).max(1_024),
  }).strict(),
  timeout_seconds: z.number().positive().max(86_400),
  required: z.boolean(),
}).strict();

const policyStepSchema = z.object({
  id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  type: z.enum(["changed-path-policy", "secret-scan", "dependency-change"]),
  required: z.boolean(),
}).strict();

export const verificationPlanSchema = z.object({
  schema_version: z.literal(1),
  verification_plan_id: z.string().regex(/^verification:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  steps: z.array(z.discriminatedUnion("type", [commandStepSchema, policyStepSchema])).min(1).max(128),
}).strict().superRefine((value, context) => {
  const seen = new Set<string>();
  for (const [index, step] of value.steps.entries()) {
    if (seen.has(step.id)) context.addIssue({ code: "custom", path: ["steps", index, "id"], message: `Duplicate verification step: ${step.id}` });
    seen.add(step.id);
  }
});

export type VerificationPlan = z.infer<typeof verificationPlanSchema>;
export function parseVerificationPlan(input: unknown): VerificationPlan { return verificationPlanSchema.parse(input); }

export interface SealedWorkspaceInput {
  workspace_id: string;
  path: string;
  base_commit: string;
  environment_hash: string;
  sealed: boolean;
  changed_files: Array<{ path: string; dependency_file: boolean }>;
  path_policy: { decision: "ALLOW" | "BLOCK"; allowed: string[]; denied: string[] };
  patch: string;
}

export type VerificationStepStatus = "PASSED" | "FAILED" | "FLAKY_SUSPECTED" | "TIMED_OUT" | "BLOCKED";

export interface VerificationStepResult {
  id: string;
  type: VerificationPlan["steps"][number]["type"];
  required: boolean;
  status: VerificationStepStatus;
  attempts: number;
  exit_code: number | null;
  duration_ms: number;
  artifact_paths: string[];
  signature: string;
  failure_kind: "DETERMINISTIC_FAILURE" | "FLAKY_SUSPECTED" | "TIMEOUT" | "PATH_POLICY_VIOLATION" | "SECRET_LEAK_DETECTED" | "DEPENDENCY_CHANGE_DETECTED" | null;
  findings: number;
}

export interface VerificationResult {
  schema_version: 1;
  verification_plan_id: string;
  workspace_id: string;
  status: "PASSED" | "FAILED" | "BLOCKED";
  steps: VerificationStepResult[];
  summary: { required_passed: number; required_failed: number; optional_failed: number };
  failure_classification: { type: "verification-failed"; repairable: boolean } | null;
  started_at: string;
  completed_at: string;
}

export type Phase2Result = "READY_FOR_REVIEW" | "REPAIR_REQUIRED" | "BLOCKED";

export function derivePhase2Result(input: { execution_completed: boolean; verification: VerificationResult }): Phase2Result {
  if (!input.execution_completed || input.verification.status === "BLOCKED") return "BLOCKED";
  if (input.verification.status !== "PASSED") return "REPAIR_REQUIRED";
  return "READY_FOR_REVIEW";
}
