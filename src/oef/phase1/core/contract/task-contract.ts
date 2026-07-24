import { createHash } from "node:crypto";
import { z } from "zod";

export const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

const namespacedKeySchema = z.string().regex(
  /^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/i,
  "A namespaced key such as opencodex.test-result is required",
);

const extensionSchema = z.object({
  schema_version: z.number().int().positive(),
}).passthrough();

const criterionSchema = z.object({
  key: z.string().trim().min(1).max(160),
  statement: z.string().trim().min(1).max(10_000),
  required_evidence: z.array(namespacedKeySchema).max(64),
}).strict();

export const taskContractDocumentSchema = z.object({
  schema_version: z.literal(1),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  revision: z.number().int().positive(),
  title: z.string().trim().min(1).max(500),
  goal: z.object({ summary: z.string().trim().min(1).max(20_000) }).strict(),
  scope: z.object({
    included: z.array(z.string().trim().min(1).max(2_000)).min(1).max(256),
    excluded: z.array(z.string().trim().min(1).max(2_000)).max(256),
  }).strict(),
  constraints: z.array(z.string().trim().min(1).max(5_000)).max(256),
  acceptance_criteria: z.array(criterionSchema).min(1).max(256),
  risk: z.object({
    level: z.enum(RISK_LEVELS),
    reasons: z.array(z.string().trim().min(1).max(160)).max(64),
  }).strict(),
  budgets: z.object({
    max_attempts: z.number().int().positive().max(10_000),
    max_parallel_writers: z.number().int().positive().max(1_000),
    max_cost_units: z.number().nonnegative().finite(),
  }).strict(),
  extensions: z.record(namespacedKeySchema, extensionSchema),
}).strict().superRefine((contract, context) => {
  const seen = new Set<string>();
  for (const [index, criterion] of contract.acceptance_criteria.entries()) {
    if (seen.has(criterion.key)) {
      context.addIssue({
        code: "custom",
        path: ["acceptance_criteria", index, "key"],
        message: `Duplicate criterion key: ${criterion.key}`,
      });
    }
    seen.add(criterion.key);
  }
});

export type TaskContractDocument = z.infer<typeof taskContractDocumentSchema>;

export function parseTaskContractDocument(input: unknown): TaskContractDocument {
  return taskContractDocumentSchema.parse(input);
}

function normalizeCanonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(normalizeCanonical);
  if (value && typeof value === "object") {
    const normalized: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      const child = normalizeCanonical((value as Record<string, unknown>)[key]);
      if (child !== undefined) normalized[key] = child;
    }
    return normalized;
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeCanonical(value));
}

export function canonicalSha256(value: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalJson(value), "utf8").digest("hex")}`;
}

export function canonicalContractHash(input: unknown): string {
  const document = parseTaskContractDocument(input);
  return canonicalSha256(document);
}

export interface TaskContractDiff {
  added_criteria: string[];
  removed_criteria: string[];
  modified_criteria: Array<{ key: string; before: unknown; after: unknown }>;
  modified_constraints: Array<{ index: number; before: string; after: string }>;
  risk_changed?: { from: string; to: string };
}

export function diffTaskContracts(
  beforeInput: unknown,
  afterInput: unknown,
): TaskContractDiff {
  const before = parseTaskContractDocument(beforeInput);
  const after = parseTaskContractDocument(afterInput);
  const beforeCriteria = new Map(before.acceptance_criteria.map(item => [item.key, item]));
  const afterCriteria = new Map(after.acceptance_criteria.map(item => [item.key, item]));
  const added = [...afterCriteria.keys()].filter(key => !beforeCriteria.has(key)).sort();
  const removed = [...beforeCriteria.keys()].filter(key => !afterCriteria.has(key)).sort();
  const modified = [...beforeCriteria.keys()]
    .filter(key => afterCriteria.has(key) && canonicalJson(beforeCriteria.get(key)) !== canonicalJson(afterCriteria.get(key)))
    .sort()
    .map(key => ({ key, before: beforeCriteria.get(key), after: afterCriteria.get(key) }));
  const modifiedConstraints: TaskContractDiff["modified_constraints"] = [];
  const commonConstraintCount = Math.min(before.constraints.length, after.constraints.length);
  for (let index = 0; index < commonConstraintCount; index += 1) {
    if (before.constraints[index] !== after.constraints[index]) {
      modifiedConstraints.push({ index, before: before.constraints[index], after: after.constraints[index] });
    }
  }
  return {
    added_criteria: added,
    removed_criteria: removed,
    modified_criteria: modified,
    modified_constraints: modifiedConstraints,
    ...(before.risk.level === after.risk.level
      ? {}
      : { risk_changed: { from: before.risk.level, to: after.risk.level } }),
  };
}
