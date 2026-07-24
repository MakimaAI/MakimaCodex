import { z } from "zod";
import { actorSchema } from "../../phase1/core/shared/actor";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const entityId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));

export const RUNTIME_CAPABILITIES = [
  "repository-read",
  "repository-write",
  "shell",
  "git",
  "structured-output",
  "tool-events",
  "streaming",
  "session-resume",
  "native-worktree",
  "subagents",
  "mcp",
  "browser",
  "image-input",
  "computer-use",
  "network-access",
  "file-edit",
  "test-execution",
  "usage-reporting",
  "cancellation",
] as const;

export type RuntimeCapability = typeof RUNTIME_CAPABILITIES[number];

export const ENFORCEMENT_LEVELS = ["NONE", "ADVISORY", "OBSERVED", "ENFORCED", "SANDBOX_ENFORCED"] as const;
export type EnforcementLevel = typeof ENFORCEMENT_LEVELS[number];

export const capabilityStateSchema = z.object({
  supported: z.boolean(),
  enforcement: z.enum(ENFORCEMENT_LEVELS),
}).strict();
export type CapabilityState = z.infer<typeof capabilityStateSchema>;

export const executableCommandSchema = z.object({
  executable: z.string().trim().min(1).max(2_000),
  args: z.array(z.string().max(20_000)).max(256),
  timeout_seconds: z.number().int().positive().max(86_400),
}).strict();

const assignmentBaseSchema = z.object({
  schema_version: z.literal(1),
  assignment_id: entityId("assignment"),
  revision: z.number().int().positive(),
  previous_revision_hash: hashSchema.nullable(),
  task_id: entityId("task"),
  contract_ref: z.object({
    revision_id: entityId("contract-revision"),
    hash: hashSchema,
  }).strict(),
  objective: z.string().trim().min(1).max(20_000),
  role: z.string().regex(/^[a-z0-9][a-z0-9-]*$/).max(160),
  scope: z.object({
    allowed_paths: z.array(z.string().trim().min(1).max(2_000)).min(1).max(512),
    denied_paths: z.array(z.string().trim().min(1).max(2_000)).max(512),
  }).strict(),
  required_capabilities: z.array(z.enum(RUNTIME_CAPABILITIES)).max(RUNTIME_CAPABILITIES.length),
  preferred_capabilities: z.array(z.enum(RUNTIME_CAPABILITIES)).max(RUNTIME_CAPABILITIES.length),
  verification: z.object({ commands: z.array(executableCommandSchema).max(64) }).strict(),
  required_evidence: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]*$/)).min(1).max(64),
  budgets: z.object({
    max_wall_time_seconds: z.number().int().positive().max(604_800),
    max_idle_seconds: z.number().int().positive().max(86_400),
    max_attempts: z.number().int().positive().max(100),
    max_output_bytes: z.number().int().positive().max(10_000_000_000),
  }).strict(),
  created_by: actorSchema,
  created_at: z.string().datetime(),
}).strict();

export const assignmentCreatePayloadSchema = assignmentBaseSchema.omit({
  schema_version: true,
  assignment_id: true,
  revision: true,
  previous_revision_hash: true,
  task_id: true,
  created_by: true,
  created_at: true,
});

export const assignmentSchema = assignmentBaseSchema.superRefine((value, context) => {
  if ((value.revision === 1) !== (value.previous_revision_hash === null)) {
    context.addIssue({ code: "custom", path: ["previous_revision_hash"], message: "Initial assignment has no previous revision; later revisions must be hash-linked" });
  }
  for (const field of ["required_capabilities", "preferred_capabilities"] as const) {
    const values = value[field];
    if (new Set(values).size !== values.length) {
      context.addIssue({ code: "custom", path: [field], message: `${field} cannot contain duplicates` });
    }
  }
  const overlap = value.preferred_capabilities.filter(item => value.required_capabilities.includes(item));
  if (overlap.length > 0) {
    context.addIssue({ code: "custom", path: ["preferred_capabilities"], message: `Capabilities cannot be both required and preferred: ${overlap.join(", ")}` });
  }
});

export type Assignment = z.infer<typeof assignmentSchema>;

export function parseAssignment(input: unknown): Assignment {
  return assignmentSchema.parse(input);
}

export function hashAssignment(input: unknown): string {
  return canonicalSha256(parseAssignment(input));
}

export function createAssignmentRevision(previousInput: unknown, nextInput: unknown): Assignment {
  const previous = parseAssignment(previousInput);
  const next = parseAssignment(nextInput);
  if (next.assignment_id !== previous.assignment_id) throw new Error("Assignment revision cannot change assignment_id");
  if (next.task_id !== previous.task_id) throw new Error("Assignment revision cannot change task_id");
  if (next.revision !== previous.revision + 1) throw new Error("Assignment revision must increase by exactly one");
  if (next.previous_revision_hash !== hashAssignment(previous)) throw new Error("Assignment revision previous_revision_hash mismatch");
  if (Date.parse(next.created_at) < Date.parse(previous.created_at)) throw new Error("Assignment revision cannot move backwards in time");
  return next;
}

export const executionBindingSchema = z.object({
  schema_version: z.literal(1),
  binding_id: entityId("binding"),
  assignment_id: entityId("assignment"),
  assignment_revision: z.number().int().positive(),
  agent_profile_ref: z.object({ id: z.string().trim().min(1).max(300), version: semverSchema }).strict(),
  runtime_ref: z.object({ id: z.string().trim().min(1).max(300), adapter_version: semverSchema }).strict(),
  model_ref: z.object({
    provider: z.string().trim().min(1).max(160),
    model_class: z.string().trim().min(1).max(300),
    resolved_model: z.string().trim().min(1).max(500).nullable(),
  }).strict(),
  environment_ref: z.object({ type: z.string().trim().min(1).max(160), version: z.number().int().positive() }).strict(),
  account_ref: z.object({ id: z.string().trim().min(1).max(300) }).strict(),
  created_by: actorSchema,
  created_at: z.string().datetime(),
}).strict();

export type ExecutionBinding = z.infer<typeof executionBindingSchema>;

export function parseExecutionBinding(input: unknown): ExecutionBinding {
  return executionBindingSchema.parse(input);
}

export interface ExecutionEligibility {
  allowed: boolean;
  missing_capabilities: RuntimeCapability[];
  insufficient_enforcement: RuntimeCapability[];
}

const enforcementRank: Record<EnforcementLevel, number> = {
  NONE: 0,
  ADVISORY: 1,
  OBSERVED: 2,
  ENFORCED: 3,
  SANDBOX_ENFORCED: 4,
};

const criticalIsolationCapabilities = new Set<RuntimeCapability>([
  "repository-write",
  "shell",
  "network-access",
  "computer-use",
]);

export function evaluateExecutionEligibility(input: {
  assignment: Assignment;
  binding: ExecutionBinding;
  task_risk: "low" | "medium" | "high" | "critical";
  capabilities: Partial<Record<RuntimeCapability, CapabilityState>>;
}): ExecutionEligibility {
  const assignment = parseAssignment(input.assignment);
  const binding = parseExecutionBinding(input.binding);
  if (binding.assignment_id !== assignment.assignment_id || binding.assignment_revision !== assignment.revision) {
    throw new Error("Execution binding does not target this assignment revision");
  }
  const missing = assignment.required_capabilities.filter(capability => !input.capabilities[capability]?.supported);
  const insufficient = assignment.required_capabilities.filter(capability => {
    const state = input.capabilities[capability];
    if (!state?.supported) return false;
    const minimum = (input.task_risk === "critical" || input.task_risk === "high")
      && criticalIsolationCapabilities.has(capability)
      ? "SANDBOX_ENFORCED"
      : "OBSERVED";
    return enforcementRank[state.enforcement] < enforcementRank[minimum];
  });
  return {
    allowed: missing.length === 0 && insufficient.length === 0,
    missing_capabilities: missing,
    insufficient_enforcement: insufficient,
  };
}

export const EXECUTION_STATUSES = [
  "CREATED", "QUEUED", "PREPARING", "RUNNING", "CANCELLING", "COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED",
] as const;
export type ExecutionStatus = typeof EXECUTION_STATUSES[number];

export const ATTEMPT_STATUSES = [
  "CREATED", "LEASED", "WORKSPACE_PREPARING", "CONTEXT_PREPARING", "STARTING", "RUNNING", "COLLECTING", "VERIFYING",
  "SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED",
] as const;
export type AttemptStatus = typeof ATTEMPT_STATUSES[number];

const executionTransitions: Readonly<Record<ExecutionStatus, readonly ExecutionStatus[]>> = {
  CREATED: ["QUEUED", "CANCELLED"],
  QUEUED: ["PREPARING", "CANCELLING", "FAILED", "INTERRUPTED"],
  PREPARING: ["RUNNING", "CANCELLING", "FAILED", "INTERRUPTED"],
  RUNNING: ["CANCELLING", "COMPLETED", "FAILED", "INTERRUPTED"],
  CANCELLING: ["CANCELLED", "FAILED", "INTERRUPTED"],
  COMPLETED: [],
  FAILED: [],
  INTERRUPTED: [],
  CANCELLED: [],
};

const attemptTransitions: Readonly<Record<AttemptStatus, readonly AttemptStatus[]>> = {
  CREATED: ["LEASED", "CANCELLED"],
  LEASED: ["WORKSPACE_PREPARING", "FAILED", "CANCELLED", "ORPHANED"],
  WORKSPACE_PREPARING: ["CONTEXT_PREPARING", "FAILED", "CANCELLED", "ORPHANED"],
  CONTEXT_PREPARING: ["STARTING", "FAILED", "CANCELLED", "ORPHANED"],
  STARTING: ["RUNNING", "FAILED", "CANCELLED", "ORPHANED"],
  RUNNING: ["COLLECTING", "FAILED", "CANCELLED", "ORPHANED"],
  COLLECTING: ["VERIFYING", "FAILED", "CANCELLED", "ORPHANED"],
  VERIFYING: ["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"],
  SUCCEEDED: [],
  FAILED: [],
  CANCELLED: [],
  ORPHANED: [],
};

function transition<T extends string>(kind: string, current: T, next: T, graph: Readonly<Record<T, readonly T[]>>): T {
  if (current === next || !graph[current]?.includes(next)) throw new Error(`Invalid ${kind} transition: ${current} -> ${next}`);
  return next;
}

export function transitionExecution(current: ExecutionStatus, next: ExecutionStatus): ExecutionStatus {
  return transition("execution", current, next, executionTransitions);
}

export function transitionAttempt(current: AttemptStatus, next: AttemptStatus): AttemptStatus {
  return transition("attempt", current, next, attemptTransitions);
}

export const executionSchema = z.object({
  schema_version: z.literal(1),
  execution_id: entityId("execution"),
  assignment_id: entityId("assignment"),
  assignment_revision: z.number().int().positive(),
  binding_id: entityId("binding"),
  status: z.enum(EXECUTION_STATUSES),
  current_attempt_id: entityId("attempt").nullable(),
  attempt_count: z.number().int().nonnegative(),
  created_at: z.string().datetime(),
  started_at: z.string().datetime().nullable(),
  completed_at: z.string().datetime().nullable(),
  aggregate_version: z.number().int().nonnegative(),
}).strict().superRefine((value, context) => {
  if ((value.attempt_count === 0) !== (value.current_attempt_id === null)) {
    context.addIssue({ code: "custom", path: ["current_attempt_id"], message: "current_attempt_id must track attempt_count" });
  }
  const terminal = ["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(value.status);
  if (terminal !== (value.completed_at !== null)) {
    context.addIssue({ code: "custom", path: ["completed_at"], message: "completed_at must match terminal execution state" });
  }
});

export type Execution = z.infer<typeof executionSchema>;
export function parseExecution(input: unknown): Execution { return executionSchema.parse(input); }

const previousAttemptFailureSchema = z.object({
  type: z.string().trim().min(1).max(160),
  retry_strategy: z.string().trim().min(1).max(160),
}).strict();

export const executionAttemptSchema = z.object({
  schema_version: z.literal(1),
  attempt_id: entityId("attempt"),
  execution_id: entityId("execution"),
  attempt_number: z.number().int().positive(),
  base_commit: z.string().trim().min(1).max(500),
  workspace_id: entityId("workspace"),
  workspace_root: z.string().trim().min(1).max(4_000).optional(),
  context_bundle_hash: hashSchema,
  binding_hash: hashSchema,
  status: z.enum(ATTEMPT_STATUSES),
  failure_of_previous_attempt: previousAttemptFailureSchema.nullable(),
  started_at: z.string().datetime().nullable(),
  ended_at: z.string().datetime().nullable(),
}).strict().superRefine((value, context) => {
  if ((value.attempt_number === 1) !== (value.failure_of_previous_attempt === null)) {
    context.addIssue({ code: "custom", path: ["failure_of_previous_attempt"], message: "Only retries require failure_of_previous_attempt" });
  }
  const terminal = ["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"].includes(value.status);
  if (terminal !== (value.ended_at !== null)) {
    context.addIssue({ code: "custom", path: ["ended_at"], message: "ended_at must match terminal attempt state" });
  }
});

export type ExecutionAttempt = z.infer<typeof executionAttemptSchema>;
export function parseExecutionAttempt(
  input: unknown,
  previous?: { previous_attempt_number: number; previous_attempt_id: string },
): ExecutionAttempt {
  const attempt = executionAttemptSchema.parse(input);
  if (previous) {
    if (attempt.attempt_id === previous.previous_attempt_id) throw new Error("A retry must use a new attempt_id");
    if (attempt.attempt_number !== previous.previous_attempt_number + 1) throw new Error("attempt_number must be sequential");
  }
  return attempt;
}

export const FAILURE_TYPES = [
  "RUNTIME_MISSING", "RUNTIME_INCOMPATIBLE", "RUNTIME_STARTUP_FAILED", "AUTHENTICATION_FAILED", "AUTHORIZATION_FAILED",
  "RATE_LIMITED", "PROVIDER_UNAVAILABLE", "NETWORK_FAILED", "STARTUP_TIMEOUT", "IDLE_TIMEOUT", "TOTAL_TIMEOUT",
  "OUTPUT_LIMIT_EXCEEDED", "CONTEXT_LIMIT_EXCEEDED", "PROTOCOL_ERROR", "EVENT_STREAM_INCOMPLETE", "TOOL_FAILED",
  "COMMAND_FAILED", "WORKSPACE_CONFLICT", "PATH_POLICY_VIOLATION", "SECRET_LEAK_DETECTED", "MODEL_REFUSAL",
  "MODEL_BEHAVIOR_ERROR", "VERIFICATION_FAILED", "CANCELLED_BY_USER", "RUNNER_LOST", "UNKNOWN",
] as const;

export const failureSchema = z.object({
  schema_version: z.literal(1),
  failure_id: entityId("failure"),
  type: z.enum(FAILURE_TYPES),
  category: z.enum(["runtime", "provider", "runner", "workspace", "policy", "verification", "user", "unknown"]),
  retryability: z.enum(["never", "conditional", "retryable"]),
  scope: z.object({ runtime: z.boolean(), model: z.boolean(), account: z.boolean(), task: z.boolean() }).strict(),
  safe_actions: z.array(z.string().trim().min(1).max(160)).max(64),
  unsafe_actions: z.array(z.string().trim().min(1).max(160)).max(64),
  signature: hashSchema,
  evidence_refs: z.array(entityId("artifact")).max(256),
}).strict();
export type Failure = z.infer<typeof failureSchema>;
export function parseFailure(input: unknown): Failure { return failureSchema.parse(input); }

const definitionManifestRefSchema = z.object({ id: z.string().trim().min(1), version: semverSchema, hash: hashSchema }).strict();

export const executionManifestSchema = z.object({
  execution_manifest_version: z.literal(1),
  task: z.object({ id: entityId("task"), contract_hash: hashSchema }).strict(),
  assignment: z.object({ id: entityId("assignment"), revision: z.number().int().positive(), hash: hashSchema }).strict(),
  workflow: definitionManifestRefSchema,
  policy: definitionManifestRefSchema,
  source: z.object({ repository: z.string().trim().min(1).max(1_000), base_commit: z.string().trim().min(1).max(500), tree_hash: hashSchema }).strict(),
  runtime: z.object({
    id: z.string().trim().min(1).max(300),
    binary_version: z.string().trim().min(1).max(500),
    adapter_version: semverSchema,
    protocol_version: z.number().int().positive(),
  }).strict(),
  model: z.object({ provider: z.string().trim().min(1).max(160), resolved_id: z.string().trim().min(1).max(500) }).strict(),
  environment: z.object({ provider: z.string().trim().min(1).max(160), fingerprint: hashSchema }).strict(),
  context: z.object({ bundle_hash: hashSchema, prompt_hash: hashSchema }).strict(),
  started_at: z.string().datetime(),
}).strict();
export type ExecutionManifest = z.infer<typeof executionManifestSchema>;
export function parseExecutionManifest(input: unknown): ExecutionManifest { return executionManifestSchema.parse(input); }
