import { canonicalSha256 } from "../../core/contract/task-contract";
import type { ContractRevision } from "../../core/contract/revision";
import type { Task } from "../../core/task/task";

export function approvalAuthorizationContextHash(input: {
  task: Task;
  activeContract: ContractRevision | null;
  operation: string;
}): string {
  return canonicalSha256({
    schema_version: 1,
    task_id: input.task.task_id,
    operation: input.operation,
    active_contract: input.activeContract ? {
      revision_id: input.activeContract.revision_id,
      canonical_hash: input.activeContract.canonical_hash,
    } : null,
    workflow_ref: input.task.workflow_ref,
    policy_pack_ref: input.task.policy_pack_ref,
    risk: input.task.risk,
  });
}
