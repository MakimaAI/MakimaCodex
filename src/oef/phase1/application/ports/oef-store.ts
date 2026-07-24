import type { ArtifactRef } from "../../artifacts/interfaces/artifact-store";
import type { Approval, ContractRevision } from "../../core/contract/revision";
import type { DomainEvent } from "../../core/events/events";
import type { EvidenceRecord } from "../../core/evidence/evidence";
import type { PolicyPack } from "../../core/policy/policy";
import type { Task, VersionedDefinitionRef } from "../../core/task/task";
import type { Verdict } from "../../core/verdict/verdict";
import type { WorkflowDefinition } from "../../core/workflow/workflow";

export interface StoredIdempotencyResult {
  commandHash: string;
  result: { ok: true; value: unknown } | { ok: false; error: unknown };
}

export interface OefCommandStore {
  transaction<T>(operation: () => T): T;
  getTask(taskId: string): Task | null;
  insertTask(task: Task): void;
  updateTask(task: Task, expectedVersion: number): boolean;
  getWorkflow(id: string, version: string): { definition: WorkflowDefinition; ref: VersionedDefinitionRef } | null;
  getPolicy(id: string, version: string): { definition: PolicyPack; ref: VersionedDefinitionRef } | null;
  getContractRevision(revisionId: string): ContractRevision | null;
  listContractRevisions(taskId: string): ContractRevision[];
  insertContractRevision(
    revision: ContractRevision,
    criteria: Array<{ criterion_id: string; key: string; value: unknown }>,
  ): void;
  updateContractRevision(revision: ContractRevision): void;
  insertApproval(approval: Approval): void;
  listApprovals(taskId: string): Approval[];
  insertArtifact(taskId: string, artifact: ArtifactRef): void;
  listArtifacts(taskId: string): ArtifactRef[];
  insertEvidence(evidence: EvidenceRecord): void;
  getEvidence(evidenceId: string): EvidenceRecord | null;
  listEvidence(taskId: string): EvidenceRecord[];
  updateEvidence(evidence: EvidenceRecord): void;
  insertVerdict(verdict: Verdict): void;
  listVerdicts(taskId: string): Verdict[];
  markVerdicts(taskId: string, from: "CURRENT", to: "STALE" | "SUPERSEDED"): string[];
  latestEventHash(taskId: string): string | null;
  appendEvent(event: DomainEvent): void;
  appendOutbox(event: DomainEvent): void;
  listEvents(taskId: string): DomainEvent[];
  getIdempotency(key: string): StoredIdempotencyResult | null;
  saveIdempotency(
    key: string,
    commandHash: string,
    result: StoredIdempotencyResult["result"],
    createdAt: string,
  ): void;
  refreshTaskSummary(taskId: string, validCurrentVerdictIds: readonly string[]): Record<string, unknown> | null;
}

export type OefIntegrityStore = Pick<
  OefCommandStore,
  "getTask" | "getContractRevision" | "listEvents" | "listArtifacts"
>;
