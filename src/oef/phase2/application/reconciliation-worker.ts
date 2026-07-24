import { join } from "node:path";
import type { Phase2Runtime } from "./runtime";
import { ExecutionReconciler, type ReconciliationAssessment, type ReconciliationInput } from "./recovery";
import type { Execution, ExecutionAttempt } from "../core/domain";
import { RunnerLeaseStore } from "../runner/lease-store";
import { RunnerEventSpool } from "../runner/event-spool";
import { verifyPersistedProcessIdentity } from "../runner/process-identity";
import { discoverRunnerResource, listVerifiedLiveRecoveryResources, LocalReconciliationActionExecutor, type ReconciliationActionExecutor } from "./reconciliation-actions";
import { CompletionSagaService } from "./completion-saga";

export interface ReconciliationReport {
  execution_id: string;
  assessment: ReconciliationAssessment;
  execution_status: Execution["status"];
  attempt_status: ExecutionAttempt["status"] | null;
}

export interface ReconciliationObservationSource {
  observe(execution: Execution, attempt: ExecutionAttempt | null): ReconciliationInput;
}

export class StartupReconciliationWorker {
  private readonly observer: ReconciliationObservationSource;
  private readonly actions: ReconciliationActionExecutor;
  private readonly runnerRoot: string;
  constructor(private readonly runtime: Phase2Runtime, options: { runner_root?: string; observer?: ReconciliationObservationSource; actions?: ReconciliationActionExecutor } = {}) {
    const runnerRoot = options.runner_root ?? join(runtime.home, "phase2", "runner");
    this.runnerRoot = runnerRoot;
    this.observer = options.observer ?? new FilesystemReconciliationObserver(runtime, runnerRoot);
    this.actions = options.actions ?? new LocalReconciliationActionExecutor(runtime, runnerRoot);
  }

  async run(): Promise<ReconciliationReport[]> {
    const completion = new CompletionSagaService(this.runtime);
    const initialCompletion = completion.resumePending();
    const initialFailure = initialCompletion.find(result => !result.completed && !result.deferred);
    if (initialFailure) throw new Error(`COMPLETION_SAGA_RESUME_FAILED:${initialFailure.execution_id}:${initialFailure.error ?? "unknown"}`);
    const reports: ReconciliationReport[] = [];
    for (const record of this.runtime.store.listNonterminalExecutions()) {
      let execution = record.execution;
      let attempt = execution.current_attempt_id ? this.runtime.store.getAttempt(execution.current_attempt_id) : null;
      let assessment = new ExecutionReconciler().assess(this.observer.observe(execution, attempt));
      if (assessment.action === "REQUEST_MISSING_EVENTS") {
        if (!await this.actions.replayMissingEvents(execution, attempt)) throw new Error(`RECONCILIATION_EVENT_REPLAY_FAILED:${execution.execution_id}`);
        assessment = new ExecutionReconciler().assess(this.observer.observe(execution, attempt));
        if (assessment.action === "REQUEST_MISSING_EVENTS") throw new Error(`RECONCILIATION_EVENT_DIVERGENCE_UNRESOLVED:${execution.execution_id}`);
      }
      if (assessment.action === "REATTACH") {
        const reattached = await this.actions.reattach(execution, attempt);
        if (!reattached) {
          const observation = this.observer.observe(execution, attempt);
          assessment = new ExecutionReconciler().assess({ ...observation, resumable: false });
        }
      }
      if (requiresTerminalization(assessment)) {
        if (assessment.action === "QUARANTINE_AND_TERMINATE_TREE" && !await this.actions.terminateVerifiedTree(execution, attempt)) {
          throw new Error(`RECONCILIATION_PROCESS_TREE_NOT_TERMINATED:${execution.execution_id}`);
        }
        if (!await this.actions.quarantineWorkspace(execution, attempt, `startup reconciliation: ${assessment.state}`)) {
          throw new Error(`RECONCILIATION_WORKSPACE_NOT_QUARANTINED:${execution.execution_id}`);
        }
        await this.actions.recordFailure(record.task_id, execution, attempt, assessment);
        if (attempt && !["SUCCEEDED", "FAILED", "CANCELLED", "ORPHANED"].includes(attempt.status)) {
          const target = attempt.status === "CREATED" ? "CANCELLED" : "ORPHANED";
          attempt = this.transitionAttempt(record.task_id, attempt, target);
          execution = this.runtime.store.getExecution(execution.execution_id)!;
        }
        if (!["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)) {
          const target = execution.status === "CREATED" ? "CANCELLED" : "INTERRUPTED";
          execution = this.transitionExecution(record.task_id, execution, target);
        }
        completion.abort(execution.execution_id, `execution reconciled as ${assessment.state}`);
      }
      reports.push({ execution_id: execution.execution_id, assessment, execution_status: execution.status, attempt_status: attempt?.status ?? null });
    }
    for (const resource of listVerifiedLiveRecoveryResources(this.runnerRoot)) {
      const recovery = resource.process_identity.recovery_identity!;
      const execution = this.runtime.store.getExecution(recovery.execution_id);
      if (execution
        && !["COMPLETED", "FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)
        && execution.current_attempt_id === recovery.attempt_id) continue;
      if (!await this.actions.terminateVerifiedResource(resource)) {
        throw new Error(`RECONCILIATION_ORPHAN_RESOURCE_NOT_TERMINATED:${recovery.execution_id}:${recovery.attempt_id}`);
      }
    }
    const finalCompletion = completion.resumePending();
    const finalFailure = finalCompletion.find(result => !result.completed && !result.deferred);
    if (finalFailure) throw new Error(`COMPLETION_SAGA_RESUME_FAILED:${finalFailure.execution_id}:${finalFailure.error ?? "unknown"}`);
    return reports;
  }

  private transitionExecution(taskId: string, execution: Execution, to: Execution["status"]): Execution {
    const commandId = this.runtime.ids.next("command");
    const result = this.runtime.bus.execute({
      schema_version: 1, command_id: commandId, command_type: "TransitionExecution", task_id: taskId,
      aggregate_id: execution.execution_id, expected_aggregate_version: execution.aggregate_version,
      actor: { type: "human", id: "human:local-owner" }, idempotency_key: commandId, payload: { to_status: to },
    });
    if (!result.ok || !result.value.execution) throw new Error(`RECONCILIATION_EXECUTION_TRANSITION_FAILED:${JSON.stringify(result)}`);
    return result.value.execution;
  }

  private transitionAttempt(taskId: string, attempt: ExecutionAttempt, to: ExecutionAttempt["status"]): ExecutionAttempt {
    const execution = this.runtime.store.getExecution(attempt.execution_id)!;
    const commandId = this.runtime.ids.next("command");
    const result = this.runtime.bus.execute({
      schema_version: 1, command_id: commandId, command_type: "TransitionExecutionAttempt", task_id: taskId,
      aggregate_id: attempt.attempt_id, expected_aggregate_version: execution.aggregate_version,
      actor: { type: "system", id: "system:local-runner" }, idempotency_key: commandId, payload: { to_status: to },
    });
    if (!result.ok || !result.value.attempt) throw new Error(`RECONCILIATION_ATTEMPT_TRANSITION_FAILED:${JSON.stringify(result)}`);
    return result.value.attempt;
  }
}

export class FilesystemReconciliationObserver implements ReconciliationObservationSource {
  private readonly leases: RunnerLeaseStore;
  private readonly spool: RunnerEventSpool;
  constructor(private readonly runtime: Phase2Runtime, private readonly runnerRoot: string) {
    this.leases = new RunnerLeaseStore({ root: join(runnerRoot, "leases") });
    this.spool = new RunnerEventSpool({ root: join(runnerRoot, "events") });
  }

  observe(execution: Execution, attempt: ExecutionAttempt | null): ReconciliationInput {
    const resource = attempt ? discoverRunnerResource(this.runnerRoot, execution.execution_id, attempt.attempt_id) : null;
    const runner = resource?.state ?? null;
    const lease = this.leases.inspect(execution.execution_id);
    const alive = resource ? processIsAlive(resource.process_identity.pid) : false;
    return {
      control_status: execution.status === "CANCELLING" ? "CANCELLING" : "RUNNING",
      runner_status: runner
        ? (runner.status === "EXITED" || runner.status === "INTERRUPTED" ? "EXITED" : "RUNNING")
        : resource && alive ? "RUNNING" : "MISSING",
      lease_status: lease.status === "ACTIVE" ? "ACTIVE" : lease.status === "EXPIRED" ? "EXPIRED" : "MISSING",
      process: {
        alive,
        identity_verified: !!resource && alive && verifyPersistedProcessIdentity(resource.process_identity),
      },
      event_sequences_match: this.eventSequencesMatch(execution.execution_id, attempt?.attempt_id ?? resource?.attempt_id ?? null),
      resumable: false,
    };
  }

  private eventSequencesMatch(executionId: string, attemptId: string | null): boolean {
    if (!attemptId) return true;
    try {
      const spooled = this.spool.read(executionId, 1).filter(event => event.attempt_id === attemptId).map(event => `${event.sequence}:${event.event_id}`);
      const persisted = this.runtime.store.listEvents(executionId)
        .map(event => event.payload.runtime_event)
        .filter((event): event is { attempt_id: string; sequence: number; event_id: string } => !!event && typeof event === "object"
          && (event as { attempt_id?: unknown }).attempt_id === attemptId
          && typeof (event as { sequence?: unknown }).sequence === "number"
          && typeof (event as { event_id?: unknown }).event_id === "string")
        .map(event => `${event.sequence}:${event.event_id}`);
      return JSON.stringify(spooled) === JSON.stringify(persisted);
    } catch { return false; }
  }
}

function requiresTerminalization(assessment: ReconciliationAssessment): boolean {
  return [
    "QUARANTINE_AND_TERMINATE_TREE",
    "DO_NOT_KILL_MARK_ORPHANED",
    "MARK_INTERRUPTED_AND_PLAN_RECOVERY",
    "MARK_INTERRUPTED_PRESERVE_WORKSPACE",
  ].includes(assessment.action);
}

function processIsAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}
