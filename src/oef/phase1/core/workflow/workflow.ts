import { z } from "zod";

const stageIdSchema = z.string().regex(/^[a-z][a-z0-9-]{0,79}$/);
const guardSchema = z.string().regex(/^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/);

export const workflowDefinitionSchema = z.object({
  schema_version: z.literal(1),
  workflow_id: z.string().regex(/^[a-z][a-z0-9-]{0,99}$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  stages: z.array(z.object({
    id: stageIdSchema,
    terminal: z.boolean().optional(),
  }).strict()).min(2).max(128),
  transitions: z.array(z.object({
    from: stageIdSchema,
    to: stageIdSchema,
    guards: z.array(guardSchema).max(64).optional(),
  }).strict()).max(512),
}).strict().superRefine((workflow, context) => {
  const stageIds = new Set<string>();
  workflow.stages.forEach((stage, index) => {
    if (stageIds.has(stage.id)) {
      context.addIssue({ code: "custom", path: ["stages", index, "id"], message: "Duplicate stage" });
    }
    stageIds.add(stage.id);
  });
  const transitions = new Set<string>();
  workflow.transitions.forEach((transition, index) => {
    if (!stageIds.has(transition.from)) {
      context.addIssue({ code: "custom", path: ["transitions", index, "from"], message: "Unknown stage" });
    }
    if (!stageIds.has(transition.to)) {
      context.addIssue({ code: "custom", path: ["transitions", index, "to"], message: "Unknown stage" });
    }
    if (workflow.stages.find(stage => stage.id === transition.from)?.terminal) {
      context.addIssue({ code: "custom", path: ["transitions", index, "from"], message: "Terminal stages cannot have outbound transitions" });
    }
    const key = `${transition.from}->${transition.to}`;
    if (transitions.has(key)) {
      context.addIssue({ code: "custom", path: ["transitions", index], message: "Duplicate transition" });
    }
    transitions.add(key);
  });
});

export type WorkflowDefinition = z.infer<typeof workflowDefinitionSchema>;

export function parseWorkflowDefinition(input: unknown): WorkflowDefinition {
  return workflowDefinitionSchema.parse(input);
}

export type WorkflowTransitionDecision =
  | { allowed: true; reason: "transition-allowed"; terminal: boolean }
  | { allowed: false; reason: "unknown-stage" | "transition-not-defined" | "guards-unsatisfied" | "terminal-stage"; missing_guards?: string[] };

export function evaluateWorkflowTransition(input: {
  workflow: WorkflowDefinition;
  from: string;
  to: string;
  satisfied_guards: readonly string[];
}): WorkflowTransitionDecision {
  const stages = new Map(input.workflow.stages.map(stage => [stage.id, stage]));
  const source = stages.get(input.from);
  const target = stages.get(input.to);
  if (!source || !target) return { allowed: false, reason: "unknown-stage" };
  if (source.terminal) return { allowed: false, reason: "terminal-stage" };
  const transition = input.workflow.transitions.find(item => item.from === input.from && item.to === input.to);
  if (!transition) return { allowed: false, reason: "transition-not-defined" };
  const satisfied = new Set(input.satisfied_guards);
  const missing = (transition.guards ?? []).filter(guard => !satisfied.has(guard));
  if (missing.length > 0) {
    return { allowed: false, reason: "guards-unsatisfied", missing_guards: missing };
  }
  return { allowed: true, reason: "transition-allowed", terminal: target.terminal === true };
}
