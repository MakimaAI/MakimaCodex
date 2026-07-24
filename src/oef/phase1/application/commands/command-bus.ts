import { z } from "zod";
import {
  canonicalContractHash,
  canonicalSha256,
  diffTaskContracts,
  parseTaskContractDocument,
} from "../../core/contract/task-contract";
import type { Approval, ContractRevision } from "../../core/contract/revision";
import type { ArtifactRef, ArtifactStore } from "../../artifacts/interfaces/artifact-store";
import type { EvidenceRecord } from "../../core/evidence/evidence";
import { createDomainEvent, type DomainEvent } from "../../core/events/events";
import { evaluatePolicy, type PolicyDecision } from "../../core/policy/policy";
import { containsStructuredPhase1Secret } from "../../core/security/secrets";
import { actorSchema } from "../../core/shared/actor";
import type { IdGenerator } from "../../core/shared/ids";
import type { Task } from "../../core/task/task";
import { VERDICT_DECISIONS, type Verdict } from "../../core/verdict/verdict";
import { evaluateWorkflowTransition, type WorkflowTransitionDecision } from "../../core/workflow/workflow";
import type { OefCommandStore } from "../ports/oef-store";
import {
  indexAuthenticatedPrincipals,
  type AuthenticatedPrincipal,
  type PrincipalRole,
} from "../security/principal";
import { approvalAuthorizationContextHash } from "../security/authorization-context";
import { isVerdictDependencyValid, validCurrentVerdictIds } from "../queries/verdict-validity";

const commandTypes = [
  "CreateTask",
  "CreateContractRevision",
  "ProposeContractRevision",
  "ApproveContractRevision",
  "RejectContractRevision",
  "GrantApproval",
  "MigrateWorkflow",
  "TransitionTaskStage",
  "RecordEvidence",
  "VerifyEvidence",
  "InvalidateEvidence",
  "IssueVerdict",
  "ReopenTask",
  "BlockTask",
  "UnblockTask",
  "CancelTask",
] as const;

const versionRefInputSchema = z.object({
  id: z.string().trim().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
}).strict();

export const commandEnvelopeSchema = z.object({
  schema_version: z.literal(1),
  command_id: z.string().trim().min(1).max(300),
  command_type: z.enum(commandTypes),
  task_id: z.string().regex(/^task:[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  expected_aggregate_version: z.number().int().nonnegative(),
  actor: actorSchema,
  idempotency_key: z.string().trim().min(1).max(500),
  payload: z.unknown(),
}).strict();

const createTaskPayloadSchema = z.object({
  title: z.string().trim().min(1).max(500),
  workflow: versionRefInputSchema,
  policy: versionRefInputSchema,
  risk: z.object({
    level: z.enum(["low", "medium", "high", "critical"]),
    reasons: z.array(z.string().trim().min(1).max(160)).max(64),
  }).strict(),
}).strict();

const createRevisionPayloadSchema = z.object({
  document: z.unknown(),
  parent_revision_id: z.string().trim().min(1).nullable(),
}).strict();
const revisionRefPayloadSchema = z.object({ revision_id: z.string().trim().min(1) }).strict();
const approveRevisionPayloadSchema = revisionRefPayloadSchema.extend({
  rationale: z.string().trim().min(1).max(5_000),
}).strict();
const grantApprovalPayloadSchema = z.object({
  subject: z.discriminatedUnion("type", [
    z.object({ type: z.literal("contract_revision"), id: z.string().trim().min(1) }).strict(),
    z.object({
      type: z.literal("task"),
      id: z.string().trim().min(1),
      operation: z.string().regex(/^(?:transition|verdict):[A-Za-z0-9-]+$/),
    }).strict(),
    z.object({ type: z.literal("workflow_migration"), id: z.string().trim().min(1) }).strict(),
  ]),
  subject_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  rationale: z.string().trim().min(1).max(5_000),
}).strict();
const transitionPayloadSchema = z.object({
  from_stage: z.string().trim().min(1),
  to_stage: z.string().trim().min(1),
}).strict();
const artifactRefSchema = z.object({
  artifact_id: z.string().trim().min(1),
  content_hash: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  media_type: z.string().trim().min(1),
  size_bytes: z.number().int().nonnegative(),
  classification: z.enum(["public", "internal", "confidential"]),
  retention_policy: z.string().trim().min(1),
  created_by: actorSchema,
  storage_key: z.string().regex(/^[a-f0-9]{2}\/[a-f0-9]{2}\/[a-f0-9]{64}$/),
  deduplicated: z.boolean(),
}).strict();
const recordEvidencePayloadSchema = z.object({
  contract_revision_id: z.string().trim().min(1),
  criterion_key: z.string().trim().min(1),
  type: z.string().regex(/^[a-z0-9][a-z0-9-]*(?:\.[a-z0-9][a-z0-9-]*)+$/i),
  summary: z.string().trim().min(1).max(10_000),
  artifacts: z.array(artifactRefSchema).max(64),
  environment: z.record(z.string(), z.unknown()),
}).strict();
const evidenceRefPayloadSchema = z.object({ evidence_id: z.string().trim().min(1) }).strict();
const issueVerdictPayloadSchema = z.object({
  contract_revision_id: z.string().trim().min(1),
  decision: z.enum(VERDICT_DECISIONS),
  rationale: z.string().trim().min(1).max(10_000),
  evidence_refs: z.array(z.string().trim().min(1)).max(256),
  repository_commit: z.string().trim().min(1).max(300).nullable().optional(),
}).strict();
const reopenPayloadSchema = z.object({
  to_stage: z.string().trim().min(1),
  rationale: z.string().trim().min(1).max(5_000),
}).strict();
const migrateWorkflowPayloadSchema = z.object({
  from: versionRefInputSchema,
  to: versionRefInputSchema,
  stage_map: z.record(z.string().trim().min(1), z.string().trim().min(1)),
  rationale: z.string().trim().min(1).max(5_000),
}).strict();
const reasonPayloadSchema = z.object({ reason: z.string().trim().min(1).max(5_000) }).strict();

type CommandError =
  | { code: "invalid_command"; message: string }
  | { code: "task_not_found" }
  | { code: "task_already_exists" }
  | { code: "definition_not_found"; definition: string }
  | { code: "concurrency_conflict"; expected: number; actual: number }
  | { code: "invalid_state"; status: string }
  | { code: "idempotency_conflict" }
  | { code: "revision_conflict"; expected_revision: number; actual_revision: number }
  | { code: "revision_not_found" }
  | { code: "invalid_contract_state"; status: string }
  | { code: "actor_forbidden"; required: "authenticated_principal" | PrincipalRole }
  | { code: "approval_subject_invalid" }
  | { code: "workflow_denied"; decision: WorkflowTransitionDecision }
  | { code: "policy_denied"; decision: PolicyDecision }
  | { code: "secret_detected" }
  | { code: "artifact_store_unavailable" }
  | { code: "artifact_integrity_failed"; artifact_id: string }
  | { code: "evidence_not_found" }
  | { code: "invalid_evidence_state"; status: string }
  | { code: "criterion_not_found" }
  | { code: "contract_not_active" }
  | { code: "verdict_evidence_invalid"; evidence_id: string }
  | { code: "repository_commit_required" }
  | { code: "repository_commit_mismatch"; evidence_id: string };

export type OefCommandResult =
  | {
      ok: true;
      replayed: boolean;
      value: {
        task: Task;
        event: DomainEvent;
        transition_applied?: boolean;
        transition_denial?: WorkflowTransitionDecision;
      };
    }
  | { ok: false; replayed: boolean; error: CommandError };

export type ParsedCommand = z.infer<typeof commandEnvelopeSchema>;

export function parseCommandEnvelope(input: unknown): ParsedCommand {
  return commandEnvelopeSchema.parse(input);
}

const requiredRoleByCommand: Record<typeof commandTypes[number], PrincipalRole> = {
  CreateTask: "task_operator",
  CreateContractRevision: "task_operator",
  ProposeContractRevision: "task_operator",
  ApproveContractRevision: "human_owner",
  RejectContractRevision: "human_owner",
  GrantApproval: "human_owner",
  MigrateWorkflow: "human_owner",
  TransitionTaskStage: "task_operator",
  RecordEvidence: "task_operator",
  VerifyEvidence: "verifier",
  InvalidateEvidence: "verifier",
  IssueVerdict: "verifier",
  ReopenTask: "human_owner",
  BlockTask: "task_operator",
  UnblockTask: "task_operator",
  CancelTask: "task_operator",
};
type CommandFailure = Extract<OefCommandResult, { ok: false }>;
type CommandOutcome =
  | {
      ok: true;
      task: Task;
      eventType: string;
      payload: Record<string, unknown>;
      resultMetadata?: {
        transition_applied: false;
        transition_denial: WorkflowTransitionDecision;
      };
    }
  | CommandFailure;

export interface OefCommandBusOptions {
  store: OefCommandStore;
  artifactStore?: ArtifactStore;
  ids: IdGenerator;
  principals: readonly AuthenticatedPrincipal[];
  clock?: () => string;
  failpoint?: (point: "after-state-before-event" | "after-event-before-outbox") => void;
}

export class OefCommandBus {
  private readonly store: OefCommandStore;
  private readonly ids: IdGenerator;
  private readonly artifactStore?: ArtifactStore;
  private readonly clock: () => string;
  private readonly failpoint?: OefCommandBusOptions["failpoint"];
  private readonly principals: ReadonlyMap<string, AuthenticatedPrincipal>;

  constructor(options: OefCommandBusOptions) {
    this.store = options.store;
    this.artifactStore = options.artifactStore;
    this.ids = options.ids;
    this.principals = indexAuthenticatedPrincipals(options.principals);
    this.clock = options.clock ?? (() => new Date().toISOString());
    this.failpoint = options.failpoint;
  }

  execute(input: unknown): OefCommandResult {
    const parsed = commandEnvelopeSchema.safeParse(input);
    if (!parsed.success) return this.invalid(parsed.error.message);
    if (containsStructuredPhase1Secret(parsed.data)) {
      return { ok: false, replayed: false, error: { code: "secret_detected" } };
    }
    const requestedActor = parsed.data.actor;
    const principal = this.principals.get(requestedActor.id);
    if (!principal || principal.actor.type !== requestedActor.type) {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "authenticated_principal" } };
    }
    const command = { ...parsed.data, actor: principal.actor };
    const requiredRole = requiredRoleByCommand[command.command_type];
    if (!principal.roles.includes(requiredRole)) {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: requiredRole } };
    }
    const commandHash = canonicalSha256(command);
    try {
      return this.store.transaction(() => {
        const previous = this.store.getIdempotency(command.idempotency_key);
        if (previous) {
          if (previous.commandHash !== commandHash) {
            return { ok: false, replayed: false, error: { code: "idempotency_conflict" } };
          }
          return { ...(previous.result as Omit<OefCommandResult, "replayed">), replayed: true } as OefCommandResult;
        }

        const outcome = this.applyCommand(command);
        if (!outcome.ok) {
          const failed = { ok: false as const, error: outcome.error };
          this.store.saveIdempotency(command.idempotency_key, commandHash, failed, this.clock());
          return { ...failed, replayed: false };
        }
        this.failpoint?.("after-state-before-event");
        const now = this.clock();
        const event = createDomainEvent({
          eventId: this.ids.next("event"),
          eventType: outcome.eventType,
          aggregateId: outcome.task.task_id,
          aggregateVersion: outcome.task.aggregate_version,
          actor: command.actor,
          traceId: this.ids.next("trace"),
          causationId: command.command_id,
          occurredAt: now,
          recordedAt: now,
          payload: outcome.payload,
          previousEventHash: this.store.latestEventHash(command.task_id),
        });
        this.store.appendEvent(event);
        this.failpoint?.("after-event-before-outbox");
        this.store.appendOutbox(event);
        this.store.refreshTaskSummary(command.task_id, validCurrentVerdictIds({
          task: outcome.task,
          store: this.store,
          artifactStore: this.artifactStore,
        }));
        const result = {
          ok: true as const,
          value: { task: outcome.task, event, ...outcome.resultMetadata },
        };
        this.store.saveIdempotency(command.idempotency_key, commandHash, result, now);
        return { ...result, replayed: false };
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const code = typeof error === "object" && error !== null && "code" in error
        ? String((error as { code?: unknown }).code ?? "")
        : "";
      if (/SQLITE_BUSY|SQLITE_BUSY_SNAPSHOT|database is locked/i.test(`${code} ${message}`)) {
        const actual = this.store.getTask(command.task_id)?.aggregate_version ?? command.expected_aggregate_version;
        return {
          ok: false,
          replayed: false,
          error: { code: "concurrency_conflict", expected: command.expected_aggregate_version, actual },
        };
      }
      throw error;
    }
  }

  private invalid(message: string): CommandFailure {
    return { ok: false, replayed: false, error: { code: "invalid_command", message } };
  }

  private nextTask(task: Task, changes: Partial<Task>): Task {
    return {
      ...task,
      ...changes,
      updated_at: this.clock(),
      aggregate_version: task.aggregate_version + 1,
    };
  }

  private persistTask(task: Task, previousVersion: number): CommandFailure | null {
    if (this.store.updateTask(task, previousVersion)) return null;
    const actual = this.store.getTask(task.task_id)?.aggregate_version ?? previousVersion;
    return { ok: false, replayed: false, error: { code: "concurrency_conflict", expected: previousVersion, actual } };
  }

  private validHumanApprovalCount(
    task: Task,
    activeContract: ContractRevision | null,
    operation: string,
  ): number {
    const authorizationHash = approvalAuthorizationContextHash({ task, activeContract, operation });
    const actorIds = this.store.listApprovals(task.task_id).filter(approval => {
      if (approval.decision !== "APPROVED" || approval.actor.type !== "human") return false;
      if (approval.subject.type === "contract_revision") {
        return activeContract !== null
          && approval.subject.id === activeContract.revision_id
          && approval.subject_hash === activeContract.canonical_hash;
      }
      if (approval.subject.type === "task") {
        return approval.subject.id === task.task_id
          && approval.subject.operation === operation
          && approval.subject_hash === authorizationHash;
      }
      return false;
    }).map(approval => approval.actor.id);
    return new Set(actorIds).size;
  }

  private applyCommand(command: ParsedCommand): CommandOutcome {
    if (command.command_type === "CreateTask") return this.createTask(command);
    const task = this.store.getTask(command.task_id);
    if (!task) return { ok: false, replayed: false, error: { code: "task_not_found" } };
    if (task.aggregate_version !== command.expected_aggregate_version) {
      return {
        ok: false,
        replayed: false,
        error: { code: "concurrency_conflict", expected: command.expected_aggregate_version, actual: task.aggregate_version },
      };
    }
    if ((task.status === "COMPLETED" || task.status === "CANCELLED") && command.command_type !== "ReopenTask") {
      return { ok: false, replayed: false, error: { code: "invalid_state", status: task.status } };
    }
    switch (command.command_type) {
      case "CreateContractRevision": return this.createContractRevision(command, task);
      case "ProposeContractRevision": return this.proposeContractRevision(command, task);
      case "ApproveContractRevision": return this.approveContractRevision(command, task);
      case "RejectContractRevision": return this.rejectContractRevision(command, task);
      case "GrantApproval": return this.grantApproval(command, task);
      case "MigrateWorkflow": return this.migrateWorkflow(command, task);
      case "TransitionTaskStage": return this.transitionTask(command, task);
      case "RecordEvidence": return this.recordEvidence(command, task);
      case "VerifyEvidence": return this.changeEvidenceStatus(command, task, "VERIFIED");
      case "InvalidateEvidence": return this.changeEvidenceStatus(command, task, "INVALIDATED");
      case "IssueVerdict": return this.issueVerdict(command, task);
      case "ReopenTask": return this.reopenTask(command, task);
      case "BlockTask": return this.changeTaskStatus(command, task, "BLOCKED", "task.blocked");
      case "UnblockTask": return this.unblockTask(command, task);
      case "CancelTask": return this.changeTaskStatus(command, task, "CANCELLED", "task.cancelled");
    }
  }

  private createTask(command: ParsedCommand): CommandOutcome {
    const payload = createTaskPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (this.store.getTask(command.task_id)) {
      return { ok: false, replayed: false, error: { code: "task_already_exists" } };
    }
    if (command.expected_aggregate_version !== 0) {
      return { ok: false, replayed: false, error: { code: "concurrency_conflict", expected: command.expected_aggregate_version, actual: 0 } };
    }
    const workflow = this.store.getWorkflow(payload.data.workflow.id, payload.data.workflow.version);
    if (!workflow) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `workflow:${payload.data.workflow.id}@${payload.data.workflow.version}` } };
    }
    const policy = this.store.getPolicy(payload.data.policy.id, payload.data.policy.version);
    if (!policy) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `policy:${payload.data.policy.id}@${payload.data.policy.version}` } };
    }
    const now = this.clock();
    const task: Task = {
      schema_version: 1,
      task_id: command.task_id,
      title: payload.data.title,
      status: "OPEN",
      stage: workflow.definition.stages[0].id,
      active_contract_revision_id: null,
      workflow_ref: workflow.ref,
      policy_pack_ref: policy.ref,
      risk: payload.data.risk,
      created_by: command.actor,
      created_at: now,
      updated_at: now,
      aggregate_version: 1,
    };
    this.store.insertTask(task);
    return {
      ok: true,
      task,
      eventType: "task.created",
      payload: { title: task.title, workflow_ref: task.workflow_ref, policy_pack_ref: task.policy_pack_ref, risk: task.risk },
    };
  }

  private createContractRevision(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = createRevisionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    let document;
    try { document = parseTaskContractDocument(payload.data.document); }
    catch (error) { return this.invalid(error instanceof Error ? error.message : "Invalid contract"); }
    if (document.task_id !== task.task_id) return this.invalid("Contract task_id does not match command task_id");
    const revisions = this.store.listContractRevisions(task.task_id);
    const expectedRevision = revisions.length + 1;
    const expectedParent = revisions.at(-1)?.revision_id ?? null;
    if (document.revision !== expectedRevision || payload.data.parent_revision_id !== expectedParent) {
      return { ok: false, replayed: false, error: { code: "revision_conflict", expected_revision: expectedRevision, actual_revision: document.revision } };
    }
    const parent = revisions.at(-1);
    const diff = parent ? diffTaskContracts(parent.document, document) : null;
    const revision: ContractRevision = {
      schema_version: 1,
      revision_id: this.ids.next("contract-revision"),
      task_id: task.task_id,
      revision_number: document.revision,
      parent_revision_id: payload.data.parent_revision_id,
      status: "DRAFT",
      canonical_hash: canonicalContractHash(document),
      document,
      created_by: command.actor,
      created_at: this.clock(),
      approved_by: null,
      approved_at: null,
      change_summary: {
        added: diff?.added_criteria ?? document.acceptance_criteria.map(item => item.key),
        changed: diff?.modified_criteria.map(item => item.key) ?? [],
        removed: diff?.removed_criteria ?? [],
        diff,
      },
    };
    this.store.insertContractRevision(revision, document.acceptance_criteria.map(criterion => ({
      criterion_id: this.ids.next("criterion"),
      key: criterion.key,
      value: criterion,
    })));
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "contract.revision.created",
      payload: { revision_id: revision.revision_id, revision_number: revision.revision_number, contract_hash: revision.canonical_hash, change_summary: revision.change_summary },
    };
  }

  private proposeContractRevision(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = revisionRefPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const revision = this.store.getContractRevision(payload.data.revision_id);
    if (!revision || revision.task_id !== task.task_id) {
      return { ok: false, replayed: false, error: { code: "revision_not_found" } };
    }
    if (revision.status !== "DRAFT") {
      return { ok: false, replayed: false, error: { code: "invalid_contract_state", status: revision.status } };
    }
    this.store.updateContractRevision({ ...revision, status: "PROPOSED" });
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return { ok: true, task: next, eventType: "contract.proposed", payload: { revision_id: revision.revision_id, contract_hash: revision.canonical_hash } };
  }

  private approveContractRevision(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = approveRevisionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (command.actor.type !== "human") {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "human_owner" } };
    }
    const revision = this.store.getContractRevision(payload.data.revision_id);
    if (!revision || revision.task_id !== task.task_id) {
      return { ok: false, replayed: false, error: { code: "revision_not_found" } };
    }
    if (revision.status !== "PROPOSED") {
      return { ok: false, replayed: false, error: { code: "invalid_contract_state", status: revision.status } };
    }
    const now = this.clock();
    const active = task.active_contract_revision_id
      ? this.store.getContractRevision(task.active_contract_revision_id)
      : null;
    const supersededContractRevisionId = active?.status === "APPROVED" ? active.revision_id : null;
    if (active?.status === "APPROVED") this.store.updateContractRevision({ ...active, status: "SUPERSEDED" });
    const approved: ContractRevision = {
      ...revision,
      status: "APPROVED",
      approved_by: command.actor,
      approved_at: now,
    };
    this.store.updateContractRevision(approved);
    const staleVerdictIds = this.store.markVerdicts(task.task_id, "CURRENT", "STALE");
    const approval: Approval = {
      schema_version: 1,
      approval_id: this.ids.next("approval"),
      task_id: task.task_id,
      subject: { type: "contract_revision", id: revision.revision_id },
      required_role: "human_owner",
      decision: "APPROVED",
      actor: command.actor,
      rationale: payload.data.rationale,
      subject_hash: revision.canonical_hash,
      created_at: now,
    };
    this.store.insertApproval(approval);
    const next = this.nextTask(task, {
      active_contract_revision_id: revision.revision_id,
      risk: revision.document.risk,
    });
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "contract.approved",
      payload: {
        revision_id: revision.revision_id,
        contract_hash: revision.canonical_hash,
        approval_id: approval.approval_id,
        secondary_state_changes: {
          superseded_contract_revision_id: supersededContractRevisionId,
          stale_verdict_ids: staleVerdictIds,
        },
      },
    };
  }

  private rejectContractRevision(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = approveRevisionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (command.actor.type !== "human") {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "human_owner" } };
    }
    const revision = this.store.getContractRevision(payload.data.revision_id);
    if (!revision || revision.task_id !== task.task_id) {
      return { ok: false, replayed: false, error: { code: "revision_not_found" } };
    }
    if (revision.status !== "PROPOSED") {
      return { ok: false, replayed: false, error: { code: "invalid_contract_state", status: revision.status } };
    }
    this.store.updateContractRevision({ ...revision, status: "REJECTED" });
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "contract.rejected",
      payload: {
        revision_id: revision.revision_id,
        contract_hash: revision.canonical_hash,
        rationale: payload.data.rationale,
      },
    };
  }

  private grantApproval(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = grantApprovalPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (command.actor.type !== "human") {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "human_owner" } };
    }
    if (!this.approvalSubjectMatches(task, payload.data.subject, payload.data.subject_hash)) {
      return { ok: false, replayed: false, error: { code: "approval_subject_invalid" } };
    }
    const approval: Approval = {
      schema_version: 1,
      approval_id: this.ids.next("approval"),
      task_id: task.task_id,
      subject: payload.data.subject,
      required_role: "human_owner",
      decision: "APPROVED",
      actor: command.actor,
      rationale: payload.data.rationale,
      subject_hash: payload.data.subject_hash,
      created_at: this.clock(),
    };
    this.store.insertApproval(approval);
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return { ok: true, task: next, eventType: "approval.granted", payload: { approval_id: approval.approval_id, subject: approval.subject, subject_hash: approval.subject_hash } };
  }

  private migrateWorkflow(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = migrateWorkflowPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (command.actor.type !== "human") {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "human_owner" } };
    }
    if (payload.data.from.id !== task.workflow_ref.id || payload.data.from.version !== task.workflow_ref.version) {
      return this.invalid("Workflow migration source does not match the task's pinned workflow");
    }
    const source = this.store.getWorkflow(payload.data.from.id, payload.data.from.version);
    const target = this.store.getWorkflow(payload.data.to.id, payload.data.to.version);
    if (!source || source.ref.hash !== task.workflow_ref.hash) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `workflow:${payload.data.from.id}@${payload.data.from.version}` } };
    }
    if (!target) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `workflow:${payload.data.to.id}@${payload.data.to.version}` } };
    }
    const sourceStages = new Set(source.definition.stages.map(stage => stage.id));
    const targetStages = new Set(target.definition.stages.map(stage => stage.id));
    for (const stage of sourceStages) {
      const mapped = payload.data.stage_map[stage];
      if (!mapped || !targetStages.has(mapped)) return this.invalid(`Missing or invalid workflow stage mapping for ${stage}`);
    }
    const mappedStage = payload.data.stage_map[task.stage];
    const approval: Approval = {
      schema_version: 1,
      approval_id: this.ids.next("approval"),
      task_id: task.task_id,
      subject: { type: "workflow_migration", id: `${target.ref.id}@${target.ref.version}` },
      required_role: "human_owner",
      decision: "APPROVED",
      actor: command.actor,
      rationale: payload.data.rationale,
      subject_hash: target.ref.hash,
      created_at: this.clock(),
    };
    this.store.insertApproval(approval);
    const staleVerdictIds = this.store.markVerdicts(task.task_id, "CURRENT", "STALE");
    const next = this.nextTask(task, { workflow_ref: target.ref, stage: mappedStage });
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "task.workflow.migrated",
      payload: {
        from: task.workflow_ref,
        to: target.ref,
        stage_map: payload.data.stage_map,
        approval_id: approval.approval_id,
        secondary_state_changes: { stale_verdict_ids: staleVerdictIds },
      },
    };
  }

  private transitionTask(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = transitionPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (task.status !== "OPEN") {
      return { ok: false, replayed: false, error: { code: "invalid_state", status: task.status } };
    }
    if (payload.data.from_stage !== task.stage) return this.invalid("from_stage does not match current stage");
    const workflow = this.store.getWorkflow(task.workflow_ref.id, task.workflow_ref.version);
    if (!workflow || workflow.ref.hash !== task.workflow_ref.hash) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `workflow:${task.workflow_ref.id}@${task.workflow_ref.version}` } };
    }
    const activeContract = task.active_contract_revision_id
      ? this.store.getContractRevision(task.active_contract_revision_id)
      : null;
    const verifiedEvidence = this.store.listEvidence(task.task_id).filter(
      item => item.contract_revision_id === activeContract?.revision_id && item.status === "VERIFIED",
    );
    const satisfiedGuards: string[] = [];
    if (activeContract?.status === "APPROVED") satisfiedGuards.push("contract.approved");
    if (activeContract && this.contractHasPlan(activeContract)) satisfiedGuards.push("plan.exists");
    if (
      activeContract
      && activeContract.document.budgets.max_attempts > 0
      && activeContract.document.budgets.max_parallel_writers > 0
      && activeContract.document.budgets.max_cost_units > 0
    ) satisfiedGuards.push("budget.available");
    if (activeContract && this.allRequiredEvidencePresent(activeContract, verifiedEvidence)) {
      satisfiedGuards.push("required-evidence.present");
    }
    const currentAcceptedVerdict = [...this.store.listVerdicts(task.task_id)].reverse().find(
      verdict => verdict.status === "CURRENT"
        && verdict.decision === "ACCEPT"
        && verdict.contract_revision_id === activeContract?.revision_id,
    );
    const currentVerdictValid = activeContract && currentAcceptedVerdict
      ? isVerdictDependencyValid({
          task,
          revision: activeContract,
          verdict: currentAcceptedVerdict,
          store: this.store,
          artifactStore: this.artifactStore,
        })
      : false;
    if (currentVerdictValid) {
      satisfiedGuards.push("verdict.accepted");
    }
    const workflowDecision = evaluateWorkflowTransition({
      workflow: workflow.definition,
      from: payload.data.from_stage,
      to: payload.data.to_stage,
      satisfied_guards: satisfiedGuards,
    });
    const transitionDefinition = workflow.definition.transitions.find(
      transition => transition.from === payload.data.from_stage && transition.to === payload.data.to_stage,
    );
    if (
      activeContract
      && currentAcceptedVerdict
      && !currentVerdictValid
      && transitionDefinition?.guards?.includes("verdict.accepted")
    ) {
      const staleVerdictIds = this.store.markVerdicts(task.task_id, "CURRENT", "STALE");
      const next = this.nextTask(task, {});
      const conflict = this.persistTask(next, task.aggregate_version);
      if (conflict) return conflict;
      return {
        ok: true,
        task: next,
        eventType: "verdict.stale.detected",
        payload: {
          attempted_transition: { from: payload.data.from_stage, to: payload.data.to_stage },
          secondary_state_changes: { stale_verdict_ids: staleVerdictIds },
        },
        resultMetadata: {
          transition_applied: false,
          transition_denial: workflowDecision,
        },
      };
    }
    if (!workflowDecision.allowed) {
      return { ok: false, replayed: false, error: { code: "workflow_denied", decision: workflowDecision } };
    }
    const policy = this.store.getPolicy(task.policy_pack_ref.id, task.policy_pack_ref.version);
    if (!policy || policy.ref.hash !== task.policy_pack_ref.hash) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `policy:${task.policy_pack_ref.id}@${task.policy_pack_ref.version}` } };
    }
    const policyDecision = evaluatePolicy({
      pack: policy.definition,
      operation: { kind: "transition", to: payload.data.to_stage },
      task: {
        risk_level: task.risk.level,
        risk_reasons: task.risk.reasons,
        contract_status: activeContract?.status ?? "DRAFT",
        required_evidence: activeContract ? this.requiredEvidence(activeContract) : [],
      },
      human_approval_count: this.validHumanApprovalCount(task, activeContract, `transition:${payload.data.to_stage}`),
      verified_evidence: verifiedEvidence.map(item => ({
        criterion_key: item.criterion_key,
        evidence_type: item.type,
      })),
    });
    if (!policyDecision.allowed) {
      return { ok: false, replayed: false, error: { code: "policy_denied", decision: policyDecision } };
    }
    const next = this.nextTask(task, {
      stage: payload.data.to_stage,
      status: workflowDecision.terminal ? "COMPLETED" : "OPEN",
    });
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: workflowDecision.terminal ? "task.completed" : "task.stage.transitioned",
      payload: { from_stage: payload.data.from_stage, to_stage: payload.data.to_stage },
    };
  }

  private recordEvidence(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = recordEvidencePayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (!task.active_contract_revision_id || payload.data.contract_revision_id !== task.active_contract_revision_id) {
      return { ok: false, replayed: false, error: { code: "contract_not_active" } };
    }
    const revision = this.store.getContractRevision(payload.data.contract_revision_id);
    if (!revision || revision.status !== "APPROVED") {
      return { ok: false, replayed: false, error: { code: "contract_not_active" } };
    }
    if (!revision.document.acceptance_criteria.some(item => item.key === payload.data.criterion_key)) {
      return { ok: false, replayed: false, error: { code: "criterion_not_found" } };
    }
    if (payload.data.artifacts.length > 0 && !this.artifactStore) {
      return { ok: false, replayed: false, error: { code: "artifact_store_unavailable" } };
    }
    const artifacts = payload.data.artifacts as ArtifactRef[];
    for (const artifact of artifacts) {
      if (!this.artifactStore?.verify(artifact).valid) {
        return { ok: false, replayed: false, error: { code: "artifact_integrity_failed", artifact_id: artifact.artifact_id } };
      }
    }
    const evidence: EvidenceRecord = {
      schema_version: 1,
      evidence_id: this.ids.next("evidence"),
      task_id: task.task_id,
      contract_revision_id: revision.revision_id,
      criterion_key: payload.data.criterion_key,
      type: payload.data.type,
      status: "RECORDED",
      producer: command.actor,
      summary: payload.data.summary,
      artifacts,
      environment: payload.data.environment,
      created_at: this.clock(),
      verified_at: null,
    };
    for (const artifact of artifacts) this.store.insertArtifact(task.task_id, artifact);
    this.store.insertEvidence(evidence);
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "evidence.recorded",
      payload: {
        evidence_id: evidence.evidence_id,
        contract_revision_id: evidence.contract_revision_id,
        criterion_key: evidence.criterion_key,
        evidence_type: evidence.type,
        artifact_refs: artifacts.map(artifact => ({ artifact_id: artifact.artifact_id, content_hash: artifact.content_hash })),
      },
    };
  }

  private changeEvidenceStatus(
    command: ParsedCommand,
    task: Task,
    status: "VERIFIED" | "INVALIDATED",
  ): CommandOutcome {
    const payload = evidenceRefPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    const evidence = this.store.getEvidence(payload.data.evidence_id);
    if (!evidence || evidence.task_id !== task.task_id) {
      return { ok: false, replayed: false, error: { code: "evidence_not_found" } };
    }
    const allowed = status === "VERIFIED"
      ? evidence.status === "RECORDED"
      : evidence.status === "RECORDED" || evidence.status === "VERIFIED";
    if (!allowed) {
      return { ok: false, replayed: false, error: { code: "invalid_evidence_state", status: evidence.status } };
    }
    if (status === "VERIFIED") {
      if (evidence.artifacts.length > 0 && !this.artifactStore) {
        return { ok: false, replayed: false, error: { code: "artifact_store_unavailable" } };
      }
      for (const artifact of evidence.artifacts) {
        if (!this.artifactStore?.verify(artifact).valid) {
          return { ok: false, replayed: false, error: { code: "artifact_integrity_failed", artifact_id: artifact.artifact_id } };
        }
      }
    }
    const nextEvidence: EvidenceRecord = {
      ...evidence,
      status,
      verified_at: status === "VERIFIED" ? this.clock() : evidence.verified_at,
    };
    this.store.updateEvidence(nextEvidence);
    const staleVerdictIds = status === "INVALIDATED"
      ? this.store.markVerdicts(task.task_id, "CURRENT", "STALE")
      : [];
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: status === "VERIFIED" ? "evidence.verified" : "evidence.invalidated",
      payload: {
        evidence_id: evidence.evidence_id,
        status,
        secondary_state_changes: { stale_verdict_ids: staleVerdictIds },
      },
    };
  }

  private issueVerdict(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = issueVerdictPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (!task.active_contract_revision_id || payload.data.contract_revision_id !== task.active_contract_revision_id) {
      return { ok: false, replayed: false, error: { code: "contract_not_active" } };
    }
    const revision = this.store.getContractRevision(payload.data.contract_revision_id);
    if (!revision || revision.status !== "APPROVED") {
      return { ok: false, replayed: false, error: { code: "contract_not_active" } };
    }
    const selectedEvidence: EvidenceRecord[] = [];
    for (const evidenceId of [...new Set(payload.data.evidence_refs)]) {
      const evidence = this.store.getEvidence(evidenceId);
      if (
        !evidence
        || evidence.task_id !== task.task_id
        || evidence.contract_revision_id !== revision.revision_id
        || evidence.status !== "VERIFIED"
      ) {
        return { ok: false, replayed: false, error: { code: "verdict_evidence_invalid", evidence_id: evidenceId } };
      }
      if (evidence.artifacts.length > 0 && !this.artifactStore) {
        return { ok: false, replayed: false, error: { code: "artifact_store_unavailable" } };
      }
      for (const artifact of evidence.artifacts) {
        if (!this.artifactStore?.verify(artifact).valid) {
          return { ok: false, replayed: false, error: { code: "artifact_integrity_failed", artifact_id: artifact.artifact_id } };
        }
      }
      selectedEvidence.push(evidence);
    }
    if (payload.data.decision === "ACCEPT" && !payload.data.repository_commit) {
      return { ok: false, replayed: false, error: { code: "repository_commit_required" } };
    }
    if (payload.data.repository_commit) {
      const mismatched = selectedEvidence.find(
        evidence => evidence.environment.repository_commit !== payload.data.repository_commit,
      );
      if (mismatched) {
        return {
          ok: false,
          replayed: false,
          error: { code: "repository_commit_mismatch", evidence_id: mismatched.evidence_id },
        };
      }
    }
    const policy = this.store.getPolicy(task.policy_pack_ref.id, task.policy_pack_ref.version);
    if (!policy || policy.ref.hash !== task.policy_pack_ref.hash) {
      return { ok: false, replayed: false, error: { code: "definition_not_found", definition: `policy:${task.policy_pack_ref.id}@${task.policy_pack_ref.version}` } };
    }
    const policyDecision = evaluatePolicy({
      pack: policy.definition,
      operation: { kind: "verdict", decision: payload.data.decision },
      task: {
        risk_level: task.risk.level,
        risk_reasons: task.risk.reasons,
        contract_status: revision.status,
        required_evidence: this.requiredEvidence(revision),
      },
      human_approval_count: this.validHumanApprovalCount(task, revision, `verdict:${payload.data.decision}`),
      verified_evidence: selectedEvidence.map(item => ({
        criterion_key: item.criterion_key,
        evidence_type: item.type,
      })),
    });
    if (!policyDecision.allowed) {
      return { ok: false, replayed: false, error: { code: "policy_denied", decision: policyDecision } };
    }
    const supersededVerdictIds = this.store.markVerdicts(task.task_id, "CURRENT", "SUPERSEDED");
    const verdict: Verdict = {
      schema_version: 1,
      verdict_id: this.ids.next("verdict"),
      task_id: task.task_id,
      scope: { type: "task", id: task.task_id },
      contract_revision_id: revision.revision_id,
      decision: payload.data.decision,
      status: "CURRENT",
      rationale: payload.data.rationale,
      evidence_refs: selectedEvidence.map(item => item.evidence_id),
      missing_requirements: [],
      issued_by: command.actor,
      policy_pack_ref: task.policy_pack_ref,
      repository_commit: payload.data.repository_commit ?? null,
      dependency_hashes: {
        contract: revision.canonical_hash,
        workflow: task.workflow_ref.hash,
        policy: task.policy_pack_ref.hash,
        evidence: selectedEvidence.map(item => ({
          evidence_id: item.evidence_id,
          evidence_hash: canonicalSha256(item),
        })),
      },
      created_at: this.clock(),
    };
    this.store.insertVerdict(verdict);
    const next = this.nextTask(task, {});
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "verdict.issued",
      payload: {
        verdict_id: verdict.verdict_id,
        contract_revision_id: verdict.contract_revision_id,
        decision: verdict.decision,
        evidence_refs: verdict.evidence_refs,
        policy_pack_ref: verdict.policy_pack_ref,
        dependency_hashes: verdict.dependency_hashes,
        secondary_state_changes: { superseded_verdict_ids: supersededVerdictIds },
      },
    };
  }

  private reopenTask(command: ParsedCommand, task: Task): CommandOutcome {
    const payload = reopenPayloadSchema.safeParse(command.payload);
    if (!payload.success) return this.invalid(payload.error.message);
    if (command.actor.type !== "human") {
      return { ok: false, replayed: false, error: { code: "actor_forbidden", required: "human_owner" } };
    }
    if (task.status !== "COMPLETED" && task.status !== "CANCELLED") {
      return { ok: false, replayed: false, error: { code: "invalid_state", status: task.status } };
    }
    const workflow = this.store.getWorkflow(task.workflow_ref.id, task.workflow_ref.version);
    const target = workflow?.definition.stages.find(stage => stage.id === payload.data.to_stage);
    if (!workflow || !target || target.terminal) return this.invalid("Reopen target must be a non-terminal stage in the pinned workflow");
    const next = this.nextTask(task, { status: "OPEN", stage: payload.data.to_stage });
    const staleVerdictIds = this.store.markVerdicts(task.task_id, "CURRENT", "STALE");
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return {
      ok: true,
      task: next,
      eventType: "task.reopened",
      payload: {
        from_status: task.status,
        to_stage: payload.data.to_stage,
        rationale: payload.data.rationale,
        secondary_state_changes: { stale_verdict_ids: staleVerdictIds },
      },
    };
  }

  private unblockTask(command: ParsedCommand, task: Task): CommandOutcome {
    const reason = reasonPayloadSchema.safeParse(command.payload);
    if (!reason.success) return this.invalid(reason.error.message);
    if (task.status !== "BLOCKED") {
      return { ok: false, replayed: false, error: { code: "invalid_state", status: task.status } };
    }
    const next = this.nextTask(task, { status: "OPEN" });
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return { ok: true, task: next, eventType: "task.unblocked", payload: { reason: reason.data.reason } };
  }

  private changeTaskStatus(
    command: ParsedCommand,
    task: Task,
    status: "BLOCKED" | "CANCELLED",
    eventType: string,
  ): CommandOutcome {
    const reason = reasonPayloadSchema.safeParse(command.payload);
    if (!reason.success) return this.invalid(reason.error.message);
    if (status === "BLOCKED" && task.status !== "OPEN") {
      return { ok: false, replayed: false, error: { code: "invalid_state", status: task.status } };
    }
    const next = this.nextTask(task, { status });
    const conflict = this.persistTask(next, task.aggregate_version);
    if (conflict) return conflict;
    return { ok: true, task: next, eventType, payload: { reason: reason.data.reason } };
  }

  private approvalSubjectMatches(
    task: Task,
    subject:
      | { type: "contract_revision"; id: string }
      | { type: "task"; id: string; operation: string }
      | { type: "workflow_migration"; id: string },
    subjectHash: string,
  ): boolean {
    if (subject.type === "contract_revision") {
      const revision = this.store.getContractRevision(subject.id);
      return revision?.task_id === task.task_id && revision.canonical_hash === subjectHash;
    }
    if (subject.type === "task") {
      const activeContract = task.active_contract_revision_id
        ? this.store.getContractRevision(task.active_contract_revision_id)
        : null;
      return subject.id === task.task_id
        && subjectHash === approvalAuthorizationContextHash({ task, activeContract, operation: subject.operation });
    }
    const separator = subject.id.lastIndexOf("@");
    if (separator <= 0) return false;
    const workflow = this.store.getWorkflow(subject.id.slice(0, separator), subject.id.slice(separator + 1));
    return workflow?.ref.hash === subjectHash;
  }

  private requiredEvidence(revision: ContractRevision): Array<{ criterion_key: string; evidence_type: string }> {
    return revision.document.acceptance_criteria.flatMap(criterion => (
      criterion.required_evidence.map(evidenceType => ({
        criterion_key: criterion.key,
        evidence_type: evidenceType,
      }))
    ));
  }

  private allRequiredEvidencePresent(
    revision: ContractRevision,
    evidence: readonly EvidenceRecord[],
  ): boolean {
    const verified = new Set(evidence.map(item => `${item.criterion_key}\u0000${item.type}`));
    return this.requiredEvidence(revision).every(
      requirement => verified.has(`${requirement.criterion_key}\u0000${requirement.evidence_type}`),
    );
  }

  private contractHasPlan(revision: ContractRevision): boolean {
    const value = revision.document.extensions["opencodex.plan"];
    return typeof value === "object"
      && value !== null
      && (value as Record<string, unknown>).schema_version === 1
      && (value as Record<string, unknown>).exists === true;
  }

}
