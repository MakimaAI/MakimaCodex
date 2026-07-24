import { z } from "zod";
import {
  parsePermissionEnvelopeId,
  parseTaskId,
  type PermissionEnvelopeId,
  type TaskId,
} from "./identity";
import { isAcceptanceCriterionId, isHumanId } from "./references";

const taskIdSchema = z.custom<TaskId>(value => {
  try {
    parseTaskId(value);
    return true;
  } catch {
    return false;
  }
}, "Expected a task: identifier");

const permissionEnvelopeIdSchema = z.custom<PermissionEnvelopeId>(value => {
  try {
    parsePermissionEnvelopeId(value);
    return true;
  } catch {
    return false;
  }
}, "Expected a permission: identifier");

const nonBlank = z.string().trim().min(1);
const pathList = z.array(nonBlank);

const acceptanceCriterionSchema = z.object({
  id: z.string().refine(isAcceptanceCriterionId),
  statement: nonBlank,
  verifier: z.object({
    kind: z.enum(["test", "typecheck", "build", "inspection", "human-approval"]),
    target: nonBlank,
  }).strict(),
}).strict();

const approvalSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("draft") }).strict(),
  z.object({
    status: z.literal("approved"),
    actorId: z.string().refine(isHumanId),
    approvedAt: z.string().datetime({ offset: true }),
  }).strict(),
]);

export const taskContractSchema = z.object({
  schemaVersion: z.literal("oef.task-contract/v1"),
  taskId: taskIdSchema,
  revision: z.number().int().positive(),
  title: nonBlank,
  objective: nonBlank,
  risk: z.object({
    level: z.enum(["low", "medium", "high", "critical"]),
    reasons: z.array(nonBlank).min(1),
  }).strict(),
  scope: z.object({
    read: pathList,
    write: pathList,
    deny: pathList,
  }).strict(),
  constraints: z.array(nonBlank),
  permissionEnvelopeId: permissionEnvelopeIdSchema,
  acceptanceCriteria: z.array(acceptanceCriterionSchema).min(1),
  approval: approvalSchema,
  createdAt: z.string().datetime({ offset: true }),
  supersedes: z.object({
    taskId: taskIdSchema,
    revision: z.number().int().positive(),
  }).strict().optional(),
}).strict().superRefine((contract, context) => {
  if (contract.revision === 1 && contract.supersedes) {
    context.addIssue({
      code: "custom",
      path: ["supersedes"],
      message: "Revision 1 cannot supersede an earlier contract",
    });
  }
  if (contract.revision > 1 && !contract.supersedes) {
    context.addIssue({
      code: "custom",
      path: ["supersedes"],
      message: "A revised contract must identify the revision it supersedes",
    });
  }
  if (contract.supersedes && contract.supersedes.taskId !== contract.taskId) {
    context.addIssue({
      code: "custom",
      path: ["supersedes", "taskId"],
      message: "A contract revision must supersede the same task",
    });
  }
  if (contract.supersedes && contract.supersedes.revision !== contract.revision - 1) {
    context.addIssue({
      code: "custom",
      path: ["supersedes", "revision"],
      message: "A contract must supersede the immediately preceding revision",
    });
  }
  const criterionIds = contract.acceptanceCriteria.map(criterion => criterion.id);
  if (new Set(criterionIds).size !== criterionIds.length) {
    context.addIssue({
      code: "custom",
      path: ["acceptanceCriteria"],
      message: "Acceptance criterion ids must be unique",
    });
  }
  if (
    contract.approval.status === "approved"
    && Date.parse(contract.approval.approvedAt) < Date.parse(contract.createdAt)
  ) {
    context.addIssue({
      code: "custom",
      path: ["approval", "approvedAt"],
      message: "Approval cannot predate contract creation",
    });
  }
});

export type TaskContract = z.infer<typeof taskContractSchema>;

function substantiveContract(contract: TaskContract): Omit<TaskContract, "approval"> {
  const { approval: _approval, ...substantive } = contract;
  return substantive;
}

export function assertTaskContractRevision(previous: TaskContract, next: TaskContract): void {
  if (JSON.stringify(previous) === JSON.stringify(next)) return;
  const substantiveUnchanged = JSON.stringify(substantiveContract(previous))
    === JSON.stringify(substantiveContract(next));
  if (substantiveUnchanged) {
    if (previous.approval.status === "draft" && next.approval.status === "approved") return;
    throw new Error("Only a draft contract may transition to approved without a new revision");
  }
  if (next.taskId !== previous.taskId) {
    throw new Error("A contract revision cannot change task identity");
  }
  if (next.revision !== previous.revision + 1) {
    throw new Error("A changed contract must increment revision exactly once");
  }
  if (
    next.supersedes?.taskId !== previous.taskId
    || next.supersedes.revision !== previous.revision
  ) {
    throw new Error("A changed contract revision must reference the exact superseded revision");
  }
  if (next.approval.status !== "draft") {
    throw new Error("A changed contract revision must return to draft for approval");
  }
}
