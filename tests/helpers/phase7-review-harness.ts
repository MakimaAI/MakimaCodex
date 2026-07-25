import { canonicalSha256 } from "../../src/oef/phase1/core/contract/task-contract";
import { IncidentIntelligenceService, SqliteIncidentRegistry } from "../../src/oef/phase7";
import type { SqliteOperationsStore } from "../../src/oef/operations";

export class TestPhase7EvidenceStore {
  private readonly artifacts = new Map<string, { artifact_id: string; artifact_hash: string; scope: { type: "REPOSITORY"; id: string } }>();

  record(artifactId: string, scopeId: string, content: unknown): string {
    const artifactHash = canonicalSha256(content);
    this.artifacts.set(artifactId, { artifact_id: artifactId, artifact_hash: artifactHash, scope: { type: "REPOSITORY", id: scopeId } });
    return artifactHash;
  }

  resolve(input: { artifact_ref: string }): { artifact_id: string; artifact_hash: string; scope: { type: "REPOSITORY"; id: string } } | null {
    return this.artifacts.get(input.artifact_ref) ?? null;
  }
}

export function trustedPhase2ReplayPorts(input: {
  signature: string;
  scopeId?: string;
  outcomes?: boolean[];
  evidenceStore?: TestPhase7EvidenceStore;
}) {
  const scopeId = input.scopeId ?? "repo:makima";
  const outcomes = input.outcomes ?? [true, true, true, true, true];
  const evidenceStore = input.evidenceStore ?? new TestPhase7EvidenceStore();
  const adapter = {
    id: "phase2-local-replay" as const,
    version: "1.0.0" as const,
    async replay(request: { manifest: { manifest_hash: string; seed: number } }) {
      return {
        attempts: outcomes.map((failureReproduced, index) => {
          const attempt = index + 1;
          const evidenceRef = `artifact:${scopeId}:trusted-replay-${attempt}`;
          const descriptor = { manifest_hash: request.manifest.manifest_hash, attempt, seed: request.manifest.seed + index, failure_reproduced: failureReproduced, observed_signature: input.signature };
          const evidenceHash = evidenceStore.record(evidenceRef, scopeId, descriptor);
          return { attempt, failure_reproduced: failureReproduced, summary: failureReproduced ? "trusted replay reproduced failure" : "trusted replay did not reproduce failure", observed_signature: input.signature, evidence_ref: evidenceRef, evidence_hash: evidenceHash };
        }),
      };
    },
  };
  return { adapter, evidenceStore };
}

export function phase7Service(input: {
  registry: SqliteIncidentRegistry;
  signature: string;
  operations?: SqliteOperationsStore;
  memoryWriter?: { write(records: readonly unknown[]): void | Promise<void> };
  adapter?: unknown;
  evidenceStore?: TestPhase7EvidenceStore;
  containmentApprovalVerifier?: unknown;
}): IncidentIntelligenceService {
  const ports = input.adapter && input.evidenceStore
    ? { adapter: input.adapter, evidenceStore: input.evidenceStore }
    : trustedPhase2ReplayPorts({ signature: input.signature, evidenceStore: input.evidenceStore });
  return new IncidentIntelligenceService({
    registry: input.registry,
    operations: input.operations,
    memoryWriter: input.memoryWriter,
    reproductionAdapter: ports.adapter,
    evidenceResolver: ports.evidenceStore,
    containmentApprovalVerifier: input.containmentApprovalVerifier,
  } as never);
}

export const PHASE7_PINNED_IMAGE = canonicalSha256({ image: "phase7-local-replay", version: "1.0.0" });
