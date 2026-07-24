import { createHash } from "node:crypto";
import { z } from "zod";
import { artifactRefSchema, type ArtifactRef } from "../../phase1/artifacts/interfaces/artifact-store";
import type { Phase2Runtime } from "./runtime";
import { EvidencePackageBuilder } from "../evidence/evidence-package";

const hashSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const evidenceEntrySchema = z.object({
  type: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
  artifact_id: z.string().regex(/^artifact:/),
  content_hash: hashSchema,
}).strict();

export const completionSagaRecordSchema = z.object({
  schema_version: z.literal(1),
  execution_id: z.string().regex(/^execution:/),
  task_id: z.string().regex(/^task:/),
  attempt_id: z.string().regex(/^attempt:/),
  assignment_id: z.string().regex(/^assignment:/),
  contract_revision_id: z.string().regex(/^contract-revision:/),
  criterion_key: z.string().trim().min(1),
  repository_commit: z.string().trim().min(1),
  manifest_artifact: artifactRefSchema,
  evidence_artifacts: z.array(artifactRefSchema).max(64),
  evidence_entries: z.array(evidenceEntrySchema).max(64),
  mechanical_verification: z.literal("PASSED"),
  package_artifact: artifactRefSchema.nullable(),
  status: z.enum(["PREPARED", "EXECUTION_COMPLETED", "DONE"]),
  outcome: z.enum(["PENDING", "COMPLETED", "ABORTED"]).default("PENDING"),
  last_error: z.string().max(4_000).nullable().default(null),
  prepared_at: z.string().datetime(),
  completed_at: z.string().datetime().nullable(),
}).strict();

export type CompletionSagaRecord = z.infer<typeof completionSagaRecordSchema>;
export function parseCompletionSagaRecord(value: unknown): CompletionSagaRecord { return completionSagaRecordSchema.parse(value); }

export class CompletionSagaService {
  constructor(private readonly runtime: Phase2Runtime) {}

  prepare(input: Omit<CompletionSagaRecord, "schema_version" | "package_artifact" | "status" | "outcome" | "last_error" | "prepared_at" | "completed_at">): CompletionSagaRecord {
    const existing = this.runtime.store.getCompletionSaga(input.execution_id);
    if (existing) return existing;
    const saga = parseCompletionSagaRecord({
      schema_version: 1,
      ...input,
      package_artifact: null,
      status: "PREPARED",
      outcome: "PENDING",
      last_error: null,
      prepared_at: new Date().toISOString(),
      completed_at: null,
    });
    this.runtime.store.saveCompletionSaga(saga);
    return saga;
  }

  markExecutionCompleted(executionId: string): CompletionSagaRecord {
    const saga = this.require(executionId);
    if (saga.status !== "PREPARED") return saga;
    const execution = this.runtime.store.getExecution(executionId);
    const attempt = this.runtime.store.getAttempt(saga.attempt_id);
    if (execution?.status !== "COMPLETED" || attempt?.status !== "SUCCEEDED") throw new Error("COMPLETION_SAGA_TERMINAL_STATE_MISSING");
    const next = parseCompletionSagaRecord({ ...saga, status: "EXECUTION_COMPLETED", completed_at: new Date().toISOString() });
    this.runtime.store.saveCompletionSaga(next);
    return next;
  }

  finalize(executionId: string): { saga: CompletionSagaRecord; package_artifact: ArtifactRef } {
    let saga = this.markExecutionCompleted(executionId);
    if (saga.status === "DONE" && saga.package_artifact) return { saga, package_artifact: saga.package_artifact };
    let packageArtifact = saga.package_artifact;
    if (!packageArtifact) {
      const packageValue = new EvidencePackageBuilder(this.runtime.phase1.artifacts).build({
        task_id: saga.task_id,
        contract_revision_id: saga.contract_revision_id,
        assignment_id: saga.assignment_id,
        attempt_id: saga.attempt_id,
        manifest_ref: { artifact_id: saga.manifest_artifact.artifact_id, content_hash: saga.manifest_artifact.content_hash },
        evidence: saga.evidence_entries,
        result: { execution_completed: true, mechanical_verification: saga.mechanical_verification },
      }, [saga.manifest_artifact, ...saga.evidence_artifacts]);
      packageArtifact = this.runtime.phase1.artifacts.put({
        content: JSON.stringify(packageValue, null, 2), media_type: "application/json", classification: "internal",
        retention_policy: "execution-evidence", created_by: { type: "system", id: "system:local-runner" },
      });
      saga = parseCompletionSagaRecord({ ...saga, package_artifact: packageArtifact });
      this.runtime.store.saveCompletionSaga(saga);
    }
    this.recordAndVerifyEvidence(saga, packageArtifact);
    this.advanceTaskToReview(saga.task_id, saga.execution_id);
    saga = parseCompletionSagaRecord({ ...saga, status: "DONE", outcome: "COMPLETED", last_error: null });
    this.runtime.store.saveCompletionSaga(saga);
    return { saga, package_artifact: packageArtifact };
  }

  resumePending(): Array<{ execution_id: string; completed: boolean; deferred?: boolean; error?: string }> {
    return this.runtime.store.listPendingCompletionSagas().map(saga => {
      try {
        const execution = this.runtime.store.getExecution(saga.execution_id);
        if (saga.status === "PREPARED" && execution?.status !== "COMPLETED") {
          if (execution && ["FAILED", "INTERRUPTED", "CANCELLED"].includes(execution.status)) {
            this.abort(saga.execution_id, `execution terminalized as ${execution.status}`);
            return { execution_id: saga.execution_id, completed: true };
          }
          return { execution_id: saga.execution_id, completed: false, deferred: true };
        }
        this.finalize(saga.execution_id);
        return { execution_id: saga.execution_id, completed: true };
      } catch (error) {
        return { execution_id: saga.execution_id, completed: false, error: error instanceof Error ? error.message : String(error) };
      }
    });
  }

  abort(executionId: string, reason: string): CompletionSagaRecord | null {
    const saga = this.runtime.store.getCompletionSaga(executionId);
    if (!saga || saga.status === "DONE") return saga;
    const aborted = parseCompletionSagaRecord({
      ...saga,
      status: "DONE",
      outcome: "ABORTED",
      last_error: reason.slice(0, 4_000),
      completed_at: new Date().toISOString(),
    });
    this.runtime.store.saveCompletionSaga(aborted);
    return aborted;
  }

  private recordAndVerifyEvidence(saga: CompletionSagaRecord, packageArtifact: ArtifactRef): void {
    const key = `phase2-completion-evidence:${saga.execution_id}`;
    let evidence = this.runtime.phase1.store.listEvidence(saga.task_id).find(item => item.type === "opencodex.execution-package"
      && item.environment.execution_id === saga.execution_id
      && item.environment.completion_saga === true);
    if (!evidence) {
      const record = this.phase1Command(saga.task_id, "RecordEvidence", {
        contract_revision_id: saga.contract_revision_id,
        criterion_key: saga.criterion_key,
        type: "opencodex.execution-package",
        summary: "Phase 2 bounded execution and mechanical verification package.",
        artifacts: uniqueArtifacts([saga.manifest_artifact, ...saga.evidence_artifacts, packageArtifact]),
        environment: { repository_commit: saga.repository_commit, execution_id: saga.execution_id, completion_saga: true },
      }, key);
      if (!record.ok) throw new Error(`COMPLETION_SAGA_EVIDENCE_RECORD_FAILED:${JSON.stringify(record.error)}`);
      evidence = this.runtime.phase1.store.listEvidence(saga.task_id).find(item => item.type === "opencodex.execution-package"
        && item.environment.execution_id === saga.execution_id
        && item.environment.completion_saga === true);
    }
    if (!evidence) throw new Error("COMPLETION_SAGA_EVIDENCE_MISSING");
    if (evidence.status === "VERIFIED") return;
    const verify = this.phase1Command(saga.task_id, "VerifyEvidence", { evidence_id: evidence.evidence_id }, `${key}:verify`);
    if (!verify.ok) throw new Error(`COMPLETION_SAGA_EVIDENCE_VERIFY_FAILED:${JSON.stringify(verify.error)}`);
  }

  private advanceTaskToReview(taskId: string, executionId: string): void {
    for (const target of ["verification", "review"] as const) {
      const task = this.runtime.phase1.store.getTask(taskId);
      if (!task) throw new Error("COMPLETION_SAGA_TASK_MISSING");
      if (task.stage === target || task.stage === "review") continue;
      const result = this.phase1Command(taskId, "TransitionTaskStage", { from_stage: task.stage, to_stage: target }, `phase2-completion-stage:${executionId}:${target}`);
      if (!result.ok || result.value.transition_applied === false) throw new Error(`COMPLETION_SAGA_STAGE_FAILED:${JSON.stringify(result)}`);
    }
  }

  private phase1Command(taskId: string, type: string, payload: unknown, idempotencyKey: string) {
    const commandId = `command:${createHash("sha256").update(idempotencyKey).digest("hex")}`;
    return this.runtime.phase1.bus.execute({
      schema_version: 1, command_id: commandId, command_type: type, task_id: taskId,
      expected_aggregate_version: this.runtime.phase1.store.getTask(taskId)!.aggregate_version,
      actor: { type: type === "TransitionTaskStage" ? "human" : "system", id: type === "TransitionTaskStage" ? "human:local-owner" : "system:local-cli" },
      idempotency_key: idempotencyKey, payload,
    });
  }

  private require(executionId: string): CompletionSagaRecord {
    const saga = this.runtime.store.getCompletionSaga(executionId);
    if (!saga) throw new Error(`COMPLETION_SAGA_NOT_FOUND:${executionId}`);
    return saga;
  }
}

function uniqueArtifacts(artifacts: ArtifactRef[]): ArtifactRef[] {
  return [...new Map(artifacts.map(artifact => [artifact.artifact_id, artifact])).values()];
}
