import type { Actor } from "../shared/actor";
import type { TaskContractDiff, TaskContractDocument } from "./task-contract";

export const CONTRACT_STATUSES = ["DRAFT", "PROPOSED", "APPROVED", "REJECTED", "SUPERSEDED"] as const;
export type ContractStatus = typeof CONTRACT_STATUSES[number];

export interface ContractRevision {
  schema_version: 1;
  revision_id: string;
  task_id: string;
  revision_number: number;
  parent_revision_id: string | null;
  status: ContractStatus;
  canonical_hash: string;
  document: TaskContractDocument;
  created_by: Actor;
  created_at: string;
  approved_by: Actor | null;
  approved_at: string | null;
  change_summary: {
    added: string[];
    changed: string[];
    removed: string[];
    diff: TaskContractDiff | null;
  };
}

export interface Approval {
  schema_version: 1;
  approval_id: string;
  task_id: string;
  subject:
    | { type: "contract_revision"; id: string }
    | { type: "task"; id: string; operation: string }
    | { type: "workflow_migration"; id: string };
  required_role: string;
  decision: "APPROVED" | "REJECTED";
  actor: Actor;
  rationale: string;
  subject_hash: string;
  created_at: string;
}
