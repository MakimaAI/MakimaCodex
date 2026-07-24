import type { ArtifactStore } from "../../artifacts/interfaces/artifact-store";
import { canonicalSha256 } from "../../core/contract/task-contract";
import type { ContractRevision } from "../../core/contract/revision";
import type { Task } from "../../core/task/task";
import type { Verdict } from "../../core/verdict/verdict";
import type { OefCommandStore } from "../ports/oef-store";

export function isVerdictDependencyValid(input: {
  task: Task;
  revision: ContractRevision;
  verdict: Verdict;
  store: OefCommandStore;
  artifactStore?: ArtifactStore;
}): boolean {
  const { task, revision, verdict, store, artifactStore } = input;
  if (
    verdict.repository_commit === null
    || verdict.dependency_hashes?.contract !== revision.canonical_hash
    || verdict.dependency_hashes.workflow !== task.workflow_ref.hash
    || verdict.dependency_hashes.policy !== task.policy_pack_ref.hash
  ) return false;
  const dependencyHashes = new Map(
    verdict.dependency_hashes.evidence.map(item => [item.evidence_id, item.evidence_hash]),
  );
  const verified = new Set<string>();
  for (const evidenceId of verdict.evidence_refs) {
    const record = store.getEvidence(evidenceId);
    if (
      !record
      || record.status !== "VERIFIED"
      || record.task_id !== task.task_id
      || record.contract_revision_id !== revision.revision_id
      || record.environment.repository_commit !== verdict.repository_commit
      || dependencyHashes.get(record.evidence_id) !== canonicalSha256(record)
    ) return false;
    if (record.artifacts.length > 0 && !artifactStore) return false;
    if (record.artifacts.some(artifact => !artifactStore?.verify(artifact).valid)) return false;
    verified.add(`${record.criterion_key}\u0000${record.type}`);
  }
  return revision.document.acceptance_criteria.every(criterion => (
    criterion.required_evidence.every(type => verified.has(`${criterion.key}\u0000${type}`))
  ));
}

export function validCurrentVerdictIds(input: {
  task: Task;
  store: OefCommandStore;
  artifactStore?: ArtifactStore;
}): string[] {
  const revision = input.task.active_contract_revision_id
    ? input.store.getContractRevision(input.task.active_contract_revision_id)
    : null;
  if (!revision) return [];
  return input.store.listVerdicts(input.task.task_id)
    .filter(verdict => verdict.status === "CURRENT"
      && isVerdictDependencyValid({ ...input, revision, verdict }))
    .map(verdict => verdict.verdict_id);
}
