import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import type { ArtifactRef } from "../../phase1/artifacts/interfaces/artifact-store";
import type { Phase2Runtime } from "./runtime";
import type { ReconciliationAssessment } from "./recovery";
import type { Execution, ExecutionAttempt } from "../core/domain";
import type { RunnerExecutionStatus } from "../runner/local-runner-host";
import { RunnerEventSpool } from "../runner/event-spool";
import { verifyPersistedProcessIdentity, type PersistedProcessIdentity } from "../runner/process-identity";
import { GitWorktreeWorkspaceManager } from "../workspace/git-worktree-manager";
import { EvidencePackageBuilder } from "../evidence/evidence-package";

export interface ReconciliationActionExecutor {
  replayMissingEvents(execution: Execution, attempt: ExecutionAttempt | null): Promise<boolean>;
  reattach(execution: Execution, attempt: ExecutionAttempt | null): Promise<boolean>;
  terminateVerifiedTree(execution: Execution, attempt: ExecutionAttempt | null): Promise<boolean>;
  terminateVerifiedResource(resource: DiscoveredRunnerResource): Promise<boolean>;
  quarantineWorkspace(execution: Execution, attempt: ExecutionAttempt | null, reason: string): Promise<boolean>;
  recordFailure(taskId: string, execution: Execution, attempt: ExecutionAttempt | null, assessment: ReconciliationAssessment): Promise<void>;
}

export class LocalReconciliationActionExecutor implements ReconciliationActionExecutor {
  private readonly spool: RunnerEventSpool;
  constructor(private readonly runtime: Phase2Runtime, private readonly runnerRoot: string) {
    this.spool = new RunnerEventSpool({ root: join(runnerRoot, "events") });
  }

  async replayMissingEvents(execution: Execution, attempt: ExecutionAttempt | null): Promise<boolean> {
    if (!attempt) return false;
    try {
      for (const event of this.spool.read(execution.execution_id, 1).filter(value => value.attempt_id === attempt.attempt_id)) {
        if (this.runtime.store.findRuntimeEventReceipt(event.event_id, event.attempt_id, event.sequence)) continue;
        const current = this.runtime.store.getExecution(execution.execution_id);
        if (!current) return false;
        const commandId = this.runtime.ids.next("command");
        const result = this.runtime.bus.execute({
          schema_version: 1,
          command_id: commandId,
          command_type: "RecordRuntimeEvent",
          task_id: this.runtime.store.getExecutionTaskId(execution.execution_id)!,
          aggregate_id: execution.execution_id,
          expected_aggregate_version: current.aggregate_version,
          actor: { type: "system", id: "system:local-runner" },
          idempotency_key: `reconciliation-event:${event.event_id}`,
          payload: event,
        });
        if (!result.ok) return false;
      }
      return true;
    } catch { return false; }
  }

  async reattach(_execution: Execution, _attempt: ExecutionAttempt | null): Promise<boolean> {
    // The local stdio adapter has no safe cross-process pipe reattachment contract.
    return false;
  }

  async terminateVerifiedTree(execution: Execution, attempt: ExecutionAttempt | null): Promise<boolean> {
    if (!attempt) return false;
    const resource = discoverRunnerResource(this.runnerRoot, execution.execution_id, attempt.attempt_id);
    return resource ? this.terminateVerifiedResource(resource) : false;
  }

  async terminateVerifiedResource(resource: DiscoveredRunnerResource): Promise<boolean> {
    if (!verifyPersistedProcessIdentity(resource.process_identity)) return false;
    const pid = resource.process_identity.pid;
    try {
      if (process.platform === "win32") process.kill(pid);
      else process.kill(-pid, "SIGTERM");
    } catch { try { process.kill(pid, "SIGTERM"); } catch { return !processTreeIsAlive(pid); } }
    const deadline = Date.now() + 2_000;
    while (processTreeIsAlive(pid) && Date.now() < deadline) await Bun.sleep(20);
    if (processTreeIsAlive(pid)) {
      try {
        if (process.platform === "win32") process.kill(pid);
        else process.kill(-pid, "SIGKILL");
      } catch { try { process.kill(pid, "SIGKILL"); } catch { return false; } }
    }
    return !processTreeIsAlive(pid);
  }

  async quarantineWorkspace(execution: Execution, attempt: ExecutionAttempt | null, reason: string): Promise<boolean> {
    if (!attempt) return false;
    const resource = discoverRunnerResource(this.runnerRoot, execution.execution_id, attempt.attempt_id);
    const managerRoot = attempt.workspace_root
      ?? (resource?.workspace_path ? dirname(dirname(resource.workspace_path)) : null);
    if (!managerRoot) return false;
    try {
      return await new GitWorktreeWorkspaceManager({ root: managerRoot }).quarantinePreparedOrIntent(attempt.workspace_id, reason);
    } catch { return false; }
  }

  async recordFailure(taskId: string, execution: Execution, attempt: ExecutionAttempt | null, assessment: ReconciliationAssessment): Promise<void> {
    const task = this.runtime.phase1.store.getTask(taskId);
    const revisionId = task?.active_contract_revision_id;
    const revision = revisionId ? this.runtime.phase1.store.getContractRevision(revisionId) : null;
    const criterionKey = revision?.document.acceptance_criteria[0]?.key;
    if (!task || !revision || !criterionKey) throw new Error("RECONCILIATION_CONTRACT_MISSING");
    let existing = this.runtime.phase1.store.listEvidence(taskId).find(item => item.type === "opencodex.execution-failure"
      && item.environment.execution_id === execution.execution_id
      && item.environment.reconciliation === true);
    if (existing?.status === "VERIFIED") return;
    const put = (value: unknown): ArtifactRef => this.runtime.phase1.artifacts.put({
      content: JSON.stringify(value, null, 2), media_type: "application/json", classification: "internal",
      retention_policy: "execution-evidence", created_by: { type: "system", id: "system:local-runner" },
    });
    const manifest = put({
      schema_version: 1, execution_id: execution.execution_id, assignment_id: execution.assignment_id,
      attempt_id: attempt?.attempt_id ?? null, recovery_manifest: true,
    });
    const failure = put({ schema_version: 1, failure_type: "RUNNER_LOST", assessment, execution_status: execution.status });
    const packageValue = new EvidencePackageBuilder(this.runtime.phase1.artifacts).build({
      task_id: taskId,
      contract_revision_id: revision.revision_id,
      assignment_id: execution.assignment_id,
      attempt_id: attempt?.attempt_id ?? `attempt:recovery-${canonicalSha256(execution.execution_id).slice(7, 31)}`,
      manifest_ref: { artifact_id: manifest.artifact_id, content_hash: manifest.content_hash },
      evidence: [{ type: "failure", artifact_id: failure.artifact_id, content_hash: failure.content_hash }],
      result: { execution_completed: false, mechanical_verification: "BLOCKED" },
    }, [manifest, failure]);
    const packageArtifact = put(packageValue);
    const evidenceKey = `phase2-reconciliation-evidence:${execution.execution_id}`;
    if (!existing) {
      const record = this.phase1Command(taskId, "RecordEvidence", {
        contract_revision_id: revision.revision_id,
        criterion_key: criterionKey,
        type: "opencodex.execution-failure",
        summary: `Recovered nonterminal execution as ${assessment.state}.`,
        artifacts: [manifest, failure, packageArtifact],
        environment: { repository_commit: attempt?.base_commit ?? "unknown", execution_id: execution.execution_id, reconciliation: true },
      }, evidenceKey);
      if (!record.ok) throw new Error(`RECONCILIATION_EVIDENCE_RECORD_FAILED:${JSON.stringify(record.error)}`);
      existing = this.runtime.phase1.store.listEvidence(taskId).find(item => item.type === "opencodex.execution-failure"
        && item.environment.execution_id === execution.execution_id
        && item.environment.reconciliation === true);
    }
    const evidence = existing;
    if (!evidence) throw new Error("RECONCILIATION_EVIDENCE_MISSING");
    const verified = this.phase1Command(taskId, "VerifyEvidence", { evidence_id: evidence.evidence_id }, `${evidenceKey}:verify`);
    if (!verified.ok) throw new Error(`RECONCILIATION_EVIDENCE_VERIFY_FAILED:${JSON.stringify(verified.error)}`);
  }

  private phase1Command(taskId: string, type: string, payload: unknown, idempotencyKey: string) {
    const commandId = `command:${createHash("sha256").update(idempotencyKey).digest("hex")}`;
    return this.runtime.phase1.bus.execute({
      schema_version: 1, command_id: commandId, command_type: type, task_id: taskId,
      expected_aggregate_version: this.runtime.phase1.store.getTask(taskId)!.aggregate_version,
      actor: { type: "system", id: "system:local-cli" }, idempotency_key: idempotencyKey, payload,
    });
  }
}

export function readRunnerState(runnerRoot: string, executionId: string): RunnerExecutionStatus | null {
  const path = join(runnerRoot, "state", `${createHash("sha256").update(executionId).digest("hex")}.json`);
  if (!existsSync(path)) return null;
  try {
    const state = JSON.parse(readFileSync(path, "utf8")) as RunnerExecutionStatus;
    return state.execution_id === executionId ? state : null;
  } catch { return null; }
}

export interface DiscoveredRunnerResource {
  process_identity: PersistedProcessIdentity;
  attempt_id: string;
  workspace_path: string;
  state: RunnerExecutionStatus | null;
}

export function discoverRunnerResource(runnerRoot: string, executionId: string, attemptId: string): DiscoveredRunnerResource | null {
  const state = readRunnerState(runnerRoot, executionId);
  const matchingState = state?.attempt_id === attemptId ? state : null;
  const liveMatches = new Map(listVerifiedLiveRecoveryResources(runnerRoot)
    .filter(resource => resource.process_identity.recovery_identity?.execution_id === executionId
      && resource.attempt_id === attemptId)
    .map(resource => [processIdentityKey(resource.process_identity), resource.process_identity]));
  if (liveMatches.size > 1) throw new Error(`RECOVERY_RESOURCE_AMBIGUOUS:${executionId}:${attemptId}`);
  const liveIdentity = liveMatches.values().next().value as PersistedProcessIdentity | undefined;
  if (liveIdentity) {
    return {
      process_identity: liveIdentity,
      attempt_id: attemptId,
      workspace_path: liveIdentity.recovery_identity!.workspace_path,
      state: matchingState && sameProcessIdentity(matchingState.process_identity, liveIdentity) ? matchingState : null,
    };
  }
  return matchingState
    ? { process_identity: matchingState.process_identity, attempt_id: attemptId, workspace_path: matchingState.workspace_path, state: matchingState }
    : null;
}

export function listVerifiedLiveRecoveryResources(runnerRoot: string): DiscoveredRunnerResource[] {
  const processesRoot = join(runnerRoot, "processes");
  if (!existsSync(processesRoot)) return [];
  const resources = new Map<string, DiscoveredRunnerResource>();
  for (const entry of readdirSync(processesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const attestationPath = join(processesRoot, entry.name, "process-identity.json");
    if (!existsSync(attestationPath)) continue;
    try {
      const identity = JSON.parse(readFileSync(attestationPath, "utf8")) as PersistedProcessIdentity;
      const recovery = identity.recovery_identity;
      if (!recovery || !verifyPersistedProcessIdentity(identity)) continue;
      resources.set(processIdentityKey(identity), {
        process_identity: identity,
        attempt_id: recovery.attempt_id,
        workspace_path: recovery.workspace_path,
        state: null,
      });
    } catch { /* A corrupt sibling attestation must not hide a valid current one. */ }
  }
  return [...resources.values()];
}

function processIdentityKey(identity: PersistedProcessIdentity): string {
  return `${identity.pid}:${identity.runner_nonce}:${identity.attestation_path}`;
}

function sameProcessIdentity(left: PersistedProcessIdentity, right: PersistedProcessIdentity): boolean {
  return left.pid === right.pid
    && left.os_start_identity === right.os_start_identity
    && left.runner_nonce === right.runner_nonce
    && left.attestation_path === right.attestation_path;
}

function processIsAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

function processTreeIsAlive(pid: number): boolean {
  if (process.platform === "win32") return processIsAlive(pid);
  try { process.kill(-pid, 0); return true; } catch { return false; }
}
