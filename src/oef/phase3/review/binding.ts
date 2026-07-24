import { z } from "zod";
import { actorSchema } from "../../phase1/core/shared/actor";
import { REVIEWER_CAPABILITIES, type ReviewerCapability } from "../core/domain";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const semverSchema = z.string().regex(/^\d+\.\d+\.\d+$/);
const entityId = (prefix: string) => z.string().regex(new RegExp(`^${prefix}:[A-Za-z0-9][A-Za-z0-9._:@/-]*$`));
const boundedIdentifier = z.string().trim().min(1).max(300);

const participantSchema = z.object({
  agent_id: entityId("agent"),
  provider: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/).max(160),
  model_class: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/).max(160),
  session_id: entityId("session"),
  context_id: entityId("context"),
}).strict();

export const reviewerBindingSchema = z.object({
  schema_version: z.literal(1),
  reviewer_binding_id: entityId("reviewer-binding"),
  review_unit_id: entityId("review-unit"),
  reviewer_profile_ref: z.object({ id: boundedIdentifier, version: semverSchema, hash: hashSchema }).strict(),
  runtime_ref: z.object({ id: boundedIdentifier, adapter_version: semverSchema }).strict(),
  model_ref: z.object({
    provider: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/).max(160),
    model_class: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/).max(160),
    resolved_model: z.string().trim().min(1).max(500).nullable(),
  }).strict(),
  reviewer_capabilities: z.array(z.enum(REVIEWER_CAPABILITIES)).min(1).max(REVIEWER_CAPABILITIES.length),
  risk_level: z.enum(["low", "medium", "high", "critical"]),
  independence: z.object({
    implementer: participantSchema,
    reviewer: participantSchema,
    source_access: z.literal("read-only"),
    human_approval_required: z.boolean(),
  }).strict(),
  created_by: actorSchema,
  created_at: z.string().datetime(),
}).strict().superRefine((value, context) => {
  const { implementer, reviewer } = value.independence;
  addUniqueIssue(value.reviewer_capabilities, context, ["reviewer_capabilities"], "Reviewer capabilities must be unique");
  if (value.model_ref.provider !== reviewer.provider || value.model_ref.model_class !== reviewer.model_class) {
    context.addIssue({ code: "custom", path: ["model_ref"], message: "REVIEWER_MODEL_IDENTITY_MISMATCH" });
  }
  if (implementer.agent_id === reviewer.agent_id) {
    context.addIssue({ code: "custom", path: ["independence", "reviewer", "agent_id"], message: "REVIEWER_SELF_REVIEW_FORBIDDEN" });
  }
  if (implementer.session_id === reviewer.session_id) {
    context.addIssue({ code: "custom", path: ["independence", "reviewer", "session_id"], message: "REVIEWER_SESSION_NOT_INDEPENDENT" });
  }
  if (implementer.context_id === reviewer.context_id) {
    context.addIssue({ code: "custom", path: ["independence", "reviewer", "context_id"], message: "REVIEWER_CONTEXT_NOT_INDEPENDENT" });
  }
  const sameProvider = implementer.provider === reviewer.provider;
  const sameModelClass = implementer.model_class === reviewer.model_class;
  if (value.risk_level === "high" && sameProvider && sameModelClass) {
    context.addIssue({ code: "custom", path: ["independence"], message: "REVIEWER_HIGH_RISK_INDEPENDENCE_REQUIRED" });
  }
  if (value.risk_level === "critical") {
    if (sameProvider) context.addIssue({ code: "custom", path: ["independence"], message: "REVIEWER_CRITICAL_PROVIDER_INDEPENDENCE_REQUIRED" });
    if (!value.independence.human_approval_required) {
      context.addIssue({ code: "custom", path: ["independence", "human_approval_required"], message: "REVIEWER_CRITICAL_HUMAN_GATE_REQUIRED" });
    }
  }
});

export type ReviewerBinding = z.infer<typeof reviewerBindingSchema>;

export function parseReviewerBinding(input: unknown): ReviewerBinding {
  return reviewerBindingSchema.parse(input);
}

export function assertReviewerCapabilities(
  bindingInput: unknown,
  requiredCapabilities: readonly ReviewerCapability[],
): true {
  const binding = parseReviewerBinding(bindingInput);
  const required = z.array(z.enum(REVIEWER_CAPABILITIES)).min(1).max(REVIEWER_CAPABILITIES.length).parse(requiredCapabilities);
  if (new Set(required).size !== required.length || required.some(capability => !binding.reviewer_capabilities.includes(capability))) {
    throw new Error("REVIEWER_CAPABILITY_MISMATCH");
  }
  return true;
}

function addUniqueIssue(
  values: readonly string[],
  context: z.RefinementCtx,
  path: (string | number)[],
  message: string,
): void {
  if (new Set(values).size !== values.length) context.addIssue({ code: "custom", path, message });
}
