import type { ArtifactStore } from "../../artifacts/interfaces/artifact-store";
import { canonicalContractHash } from "../../core/contract/task-contract";
import { verifyDomainEventHash } from "../../core/events/events";
import type { OefIntegrityStore } from "../ports/oef-store";

export interface TaskIntegrityView {
  valid: boolean;
  events: { count: number; hash_chain_valid: boolean };
  artifacts: { count: number; integrity_valid: boolean; invalid_artifact_ids: string[] };
  active_contract: { hash_valid: boolean };
}

export function verifyTaskIntegrity(input: {
  taskId: string;
  store: OefIntegrityStore;
  artifactStore: ArtifactStore;
}): TaskIntegrityView {
  const task = input.store.getTask(input.taskId);
  if (!task) throw new Error(`Task not found: ${input.taskId}`);
  const events = input.store.listEvents(input.taskId);
  let previousHash: string | null = null;
  let expectedVersion = 1;
  const completeEventStream = events.length === task.aggregate_version;
  const hashChainValid = completeEventStream && events.every(event => {
    const valid = event.aggregate.id === input.taskId
      && event.aggregate.version === expectedVersion
      && event.integrity.previous_event_hash === previousHash
      && verifyDomainEventHash(event);
    previousHash = event.integrity.event_hash;
    expectedVersion += 1;
    return valid;
  }) && expectedVersion - 1 === task.aggregate_version;
  const artifacts = input.store.listArtifacts(input.taskId);
  const invalidArtifactIds = artifacts
    .filter(artifact => !input.artifactStore.verify(artifact).valid)
    .map(artifact => artifact.artifact_id);
  const revision = task.active_contract_revision_id
    ? input.store.getContractRevision(task.active_contract_revision_id)
    : null;
  const contractHashValid = revision
    ? revision.canonical_hash === canonicalContractHash(revision.document)
    : true;
  const valid = hashChainValid && invalidArtifactIds.length === 0 && contractHashValid;
  return {
    valid,
    events: { count: events.length, hash_chain_valid: hashChainValid },
    artifacts: {
      count: artifacts.length,
      integrity_valid: invalidArtifactIds.length === 0,
      invalid_artifact_ids: invalidArtifactIds,
    },
    active_contract: { hash_valid: contractHashValid },
  };
}
