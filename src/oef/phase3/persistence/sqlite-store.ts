import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  parseReviewFinding,
  parseReviewPlan,
  parseReviewPlanState,
  parseReviewRequest,
  assertPlanStateMatchesPlan,
  transitionFinding,
  transitionReviewPlan,
  reviewProfileSchema,
  type FindingStatus,
  type ReviewFinding,
  type ReviewPlan,
  type ReviewPlanState,
  type ReviewProfile,
  type ReviewRequest,
  waiverSchema,
  assertWaiverApplies,
  type Waiver,
} from "../core/domain";
import { repairProposalSchema, reviewValidityInputsSchema, type RepairProposal, type ReviewValidityInputs } from "../decision";
import {
  findingValidationSchema,
  humanReviewApprovalSchema,
  parseFindingValidation,
  parseReviewDecisionRecord,
  parseReviewExecutionRecord,
  reviewDecisionRecordSchema,
  transitionReviewExecution,
  type FindingValidation,
  type HumanReviewApproval,
  type ReviewDecisionRecord,
  type ReviewExecutionRecord,
} from "../governance";
import { parseReviewerBinding, type ReviewerBinding } from "../review";
import {
  governanceAuditEventSchema,
  assertGovernanceAuditEventStream,
  parseGovernanceAuditEvent,
  type GovernanceAuditEvent,
} from "../observability/events";

export const reviewAuditEventSchema = governanceAuditEventSchema;
export type ReviewAuditEvent = GovernanceAuditEvent;

const migrations = [
  { id: "001_review_core", url: new URL("./migrations/001_review_core.sql", import.meta.url) },
  { id: "002_review_governance", url: new URL("./migrations/002_review_governance.sql", import.meta.url) },
  { id: "003_review_approval", url: new URL("./migrations/003_review_approval.sql", import.meta.url) },
  { id: "004_review_validity", url: new URL("./migrations/004_review_validity.sql", import.meta.url) },
] as const;

interface MigrationRow { migration_id: string; checksum: string }
interface JsonRow { value_json: string }
interface StatusJsonRow { status: string; value_json: string }
interface EventHashRow { event_hash: string; event_json: string }

export class SqlitePhase3Store {
  readonly databasePath: string;
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.databasePath = options.databasePath;
    mkdirSync(dirname(options.databasePath), { recursive: true });
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode = WAL;");
    this.database.exec("PRAGMA foreign_keys = ON;");
    this.database.exec("PRAGMA busy_timeout = 5000;");
    this.applyMigrations();
  }

  private applyMigrations(): void {
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS phase3_schema_migrations (
        migration_id TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
    `);
    const get = this.database.query<MigrationRow, [string]>(
      "SELECT migration_id, checksum FROM phase3_schema_migrations WHERE migration_id = ?",
    );
    const insert = this.database.query(
      "INSERT INTO phase3_schema_migrations (migration_id, checksum, applied_at) VALUES (?, ?, ?)",
    );
    for (const migration of migrations) {
      const sql = readFileSync(migration.url, "utf8");
      const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
      const existing = get.get(migration.id);
      if (existing) {
        if (existing.checksum !== checksum) throw new Error(`Applied Phase 3 migration checksum mismatch: ${migration.id}`);
        continue;
      }
      this.database.transaction(() => {
        this.database.exec(sql);
        insert.run(migration.id, checksum, new Date().toISOString());
      })();
    }
  }

  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  getAppliedMigrations(): string[] {
    return this.database.query<{ migration_id: string }, []>(
      "SELECT migration_id FROM phase3_schema_migrations ORDER BY migration_id",
    ).all().map(row => row.migration_id);
  }

  insertReviewProfile(profile: ReviewProfile): void {
    const value = reviewProfileSchema.parse(profile);
    this.database.query(
      `INSERT INTO phase3_review_profiles (profile_id, version, content_hash, profile_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(value.review_profile_id, value.version, value.content_hash, JSON.stringify(value), value.created_at);
  }

  getReviewProfile(profileId: string, version: string): ReviewProfile | null {
    const row = this.database.query<JsonRow, [string, string]>(
      "SELECT profile_json AS value_json FROM phase3_review_profiles WHERE profile_id = ? AND version = ?",
    ).get(profileId, version);
    return row ? reviewProfileSchema.parse(JSON.parse(row.value_json)) : null;
  }

  insertReviewRequest(request: ReviewRequest): void {
    const value = parseReviewRequest(request);
    this.database.query(
      `INSERT INTO phase3_review_requests (review_request_id, task_id, request_json, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run(value.review_request_id, value.task_id, JSON.stringify(value), value.created_at);
  }

  getReviewRequest(requestId: string): ReviewRequest | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT request_json AS value_json FROM phase3_review_requests WHERE review_request_id = ?",
    ).get(requestId);
    return row ? parseReviewRequest(JSON.parse(row.value_json)) : null;
  }

  insertReviewPlan(plan: ReviewPlan, planHash: string, state: ReviewPlanState): void {
    const value = parseReviewPlan(plan);
    const mutable = parseReviewPlanState(state);
    assertPlanStateMatchesPlan(value, mutable);
    if (canonicalSha256(value) !== planHash) throw new Error("Review plan hash mismatch");
    const previousPlan = this.getReviewPlan(value.review_plan_id);
    const previousState = this.getReviewPlanState(value.review_plan_id);
    if (value.revision === 1) {
      if (previousPlan || previousState) throw new Error("Review plan already exists");
    } else {
      if (!previousPlan || !previousState || previousPlan.revision + 1 !== value.revision) throw new Error("Review plan revision is not contiguous");
      if (value.previous_revision_hash !== canonicalSha256(previousPlan)) throw new Error("Review plan revision hash link mismatch");
      if (previousState.status !== "SUPERSEDED") throw new Error("Previous review plan revision must be superseded");
      if (previousPlan.snapshot.snapshot_hash === value.snapshot.snapshot_hash
        && this.listWaivers(value.review_plan_id).length === 0 && !this.getLatestHumanApproval(value.review_plan_id)) {
        throw new Error("Review plan revision requires a new snapshot or a governance change");
      }
      if (mutable.aggregate_version !== previousState.aggregate_version + 1) throw new Error("Review plan revision state version mismatch");
    }
    this.transaction(() => {
      this.database.query(
        `INSERT INTO phase3_review_plan_revisions
         (review_plan_id, revision, review_request_id, task_id, snapshot_hash, plan_hash, plan_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        value.review_plan_id, value.revision, value.review_request_id, value.task_id,
        value.snapshot.snapshot_hash, planHash, JSON.stringify(value), value.created_at,
      );
      if (previousState) {
        const updated = this.database.query(
          `UPDATE phase3_review_plan_state
           SET snapshot_hash = ?, status = ?, aggregate_version = ?, state_json = ?, created_at = ?, updated_at = ?
           WHERE review_plan_id = ? AND aggregate_version = ?`,
        ).run(
          mutable.snapshot_hash, mutable.status, mutable.aggregate_version, JSON.stringify(mutable), mutable.created_at, mutable.updated_at,
          mutable.review_plan_id, previousState.aggregate_version,
        );
        if (updated.changes !== 1) throw new Error("Review plan revision state conflict");
      } else {
        this.database.query(
          `INSERT INTO phase3_review_plan_state
           (review_plan_id, snapshot_hash, status, aggregate_version, state_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          mutable.review_plan_id, mutable.snapshot_hash, mutable.status, mutable.aggregate_version,
          JSON.stringify(mutable), mutable.created_at, mutable.updated_at,
        );
      }
    });
  }

  getReviewPlan(planId: string, revision?: number): ReviewPlan | null {
    const row = revision === undefined
      ? this.database.query<JsonRow, [string]>(
        `SELECT plan_json AS value_json FROM phase3_review_plan_revisions
         WHERE review_plan_id = ? ORDER BY revision DESC LIMIT 1`,
      ).get(planId)
      : this.database.query<JsonRow, [string, number]>(
        `SELECT plan_json AS value_json FROM phase3_review_plan_revisions
         WHERE review_plan_id = ? AND revision = ?`,
      ).get(planId, revision);
    return row ? parseReviewPlan(JSON.parse(row.value_json)) : null;
  }

  getReviewPlanState(planId: string): ReviewPlanState | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT state_json AS value_json FROM phase3_review_plan_state WHERE review_plan_id = ?",
    ).get(planId);
    return row ? parseReviewPlanState(JSON.parse(row.value_json)) : null;
  }

  insertReviewValidityBaseline(planId: string, revision: number, baseline: ReviewValidityInputs, createdAt: string): void {
    const value = reviewValidityInputsSchema.parse(baseline);
    const plan = this.getReviewPlan(planId, revision);
    if (!plan) throw new Error("Review plan revision not found for validity baseline");
    this.database.query(
      `INSERT INTO phase3_review_validity_baselines
       (review_plan_id, revision, baseline_hash, baseline_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(planId, revision, canonicalSha256(value), JSON.stringify(value), createdAt);
  }

  getReviewValidityBaseline(planId: string, revision?: number): ReviewValidityInputs | null {
    const targetRevision = revision ?? this.getReviewPlan(planId)?.revision;
    if (!targetRevision) return null;
    const row = this.database.query<JsonRow, [string, number]>(
      `SELECT baseline_json AS value_json FROM phase3_review_validity_baselines
       WHERE review_plan_id = ? AND revision = ?`,
    ).get(planId, targetRevision);
    return row ? reviewValidityInputsSchema.parse(JSON.parse(row.value_json)) : null;
  }

  updateReviewPlanState(state: ReviewPlanState, expectedVersion: number): boolean {
    const value = parseReviewPlanState(state);
    const current = this.getReviewPlanState(value.review_plan_id);
    const plan = this.getReviewPlan(value.review_plan_id);
    if (!current || !plan || current.aggregate_version !== expectedVersion) return false;
    assertPlanStateMatchesPlan(plan, value);
    transitionReviewPlan(current.status, value.status);
    const result = this.database.query(
      `UPDATE phase3_review_plan_state
       SET snapshot_hash = ?, status = ?, aggregate_version = ?, state_json = ?, updated_at = ?
       WHERE review_plan_id = ? AND aggregate_version = ?`,
    ).run(
      value.snapshot_hash, value.status, value.aggregate_version, JSON.stringify(value), value.updated_at,
      value.review_plan_id, expectedVersion,
    );
    return result.changes === 1;
  }

  insertFinding(finding: ReviewFinding): void {
    const value = parseReviewFinding(finding);
    if (value.status !== "PROPOSED") throw new Error("New findings must start as PROPOSED");
    const state = this.getReviewPlanState(value.review_plan_id);
    if (!state || state.snapshot_hash !== value.scope.snapshot_hash) throw new Error("Finding is not bound to the current review snapshot");
    this.database.query(
      `INSERT INTO phase3_review_findings
       (finding_id, finding_key, review_plan_id, review_unit_id, snapshot_hash, status, finding_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      value.finding_id, value.finding_key, value.review_plan_id, value.review_unit_id,
      value.scope.snapshot_hash, value.status, JSON.stringify(value), value.created_at, value.updated_at,
    );
  }

  updateFinding(finding: ReviewFinding, expectedStatus: FindingStatus): boolean {
    const value = parseReviewFinding(finding);
    const current = this.database.query<StatusJsonRow, [string]>(
      "SELECT status, finding_json AS value_json FROM phase3_review_findings WHERE finding_id = ?",
    ).get(value.finding_id);
    if (!current || current.status !== expectedStatus) return false;
    const previous = parseReviewFinding(JSON.parse(current.value_json));
    transitionFinding(previous.status, value.status);
    const result = this.database.query(
      `UPDATE phase3_review_findings SET status = ?, finding_json = ?, updated_at = ?
       WHERE finding_id = ? AND status = ? AND snapshot_hash = ?`,
    ).run(value.status, JSON.stringify(value), value.updated_at, value.finding_id, expectedStatus, value.scope.snapshot_hash);
    return result.changes === 1;
  }

  listFindings(planId: string): ReviewFinding[] {
    return this.database.query<JsonRow, [string]>(
      "SELECT finding_json AS value_json FROM phase3_review_findings WHERE review_plan_id = ? ORDER BY created_at, finding_id",
    ).all(planId).map(row => parseReviewFinding(JSON.parse(row.value_json)));
  }

  getFinding(findingId: string): ReviewFinding | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT finding_json AS value_json FROM phase3_review_findings WHERE finding_id = ?",
    ).get(findingId);
    return row ? parseReviewFinding(JSON.parse(row.value_json)) : null;
  }

  insertReviewerBinding(binding: ReviewerBinding): void {
    const value = parseReviewerBinding(binding);
    this.database.query(
      `INSERT INTO phase3_reviewer_bindings (reviewer_binding_id, review_unit_id, binding_json, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run(value.reviewer_binding_id, value.review_unit_id, JSON.stringify(value), value.created_at);
  }

  getReviewerBinding(bindingId: string): ReviewerBinding | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT binding_json AS value_json FROM phase3_reviewer_bindings WHERE reviewer_binding_id = ?",
    ).get(bindingId);
    return row ? parseReviewerBinding(JSON.parse(row.value_json)) : null;
  }

  insertReviewExecution(execution: ReviewExecutionRecord): void {
    const value = parseReviewExecutionRecord(execution);
    this.database.query(
      `INSERT INTO phase3_review_executions
       (review_execution_id, review_plan_id, review_unit_id, reviewer_binding_id, snapshot_hash, status,
        attempt_number, aggregate_version, execution_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      value.review_execution_id, value.review_plan_id, value.review_unit_id, value.reviewer_binding_id,
      value.snapshot_hash, value.status, value.attempt_number, value.aggregate_version,
      JSON.stringify(value), value.created_at, value.updated_at,
    );
  }

  getReviewExecution(executionId: string): ReviewExecutionRecord | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT execution_json AS value_json FROM phase3_review_executions WHERE review_execution_id = ?",
    ).get(executionId);
    return row ? parseReviewExecutionRecord(JSON.parse(row.value_json)) : null;
  }

  updateReviewExecution(execution: ReviewExecutionRecord, expectedVersion: number): boolean {
    const value = parseReviewExecutionRecord(execution);
    const current = this.getReviewExecution(value.review_execution_id);
    if (!current || current.aggregate_version !== expectedVersion) return false;
    transitionReviewExecution(current.status, value.status);
    if (
      current.review_plan_id !== value.review_plan_id
      || current.review_unit_id !== value.review_unit_id
      || current.reviewer_binding_id !== value.reviewer_binding_id
      || current.snapshot_hash !== value.snapshot_hash
      || current.attempt_number !== value.attempt_number
      || current.context_artifact_ref !== value.context_artifact_ref
      || current.rendered_prompt_artifact_ref !== value.rendered_prompt_artifact_ref
    ) throw new Error("REVIEW_EXECUTION_IDENTITY_MUTATION");
    const result = this.database.query(
      `UPDATE phase3_review_executions
       SET status = ?, aggregate_version = ?, execution_json = ?, updated_at = ?
       WHERE review_execution_id = ? AND aggregate_version = ?`,
    ).run(value.status, value.aggregate_version, JSON.stringify(value), value.updated_at, value.review_execution_id, expectedVersion);
    return result.changes === 1;
  }

  insertFindingValidation(validation: FindingValidation): void {
    const value = parseFindingValidation(validation);
    this.database.query(
      `INSERT INTO phase3_finding_validations
       (finding_validation_id, finding_id, review_plan_id, snapshot_hash, status, validation_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      value.finding_validation_id, value.finding_id, value.review_plan_id, value.snapshot_hash,
      value.status, JSON.stringify(value), value.created_at,
    );
  }

  listFindingValidations(planId: string): FindingValidation[] {
    return this.database.query<JsonRow, [string]>(
      "SELECT validation_json AS value_json FROM phase3_finding_validations WHERE review_plan_id = ? ORDER BY created_at, finding_validation_id",
    ).all(planId).map(row => findingValidationSchema.parse(JSON.parse(row.value_json)));
  }

  insertReviewDecision(decision: ReviewDecisionRecord): void {
    const value = parseReviewDecisionRecord(decision);
    this.database.query(
      `INSERT INTO phase3_review_decisions
       (review_decision_id, review_plan_id, snapshot_hash, decision, decision_json, issued_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run(value.review_decision_id, value.review_plan_id, value.snapshot_hash, value.decision, JSON.stringify(value), value.issued_at);
  }

  getLatestReviewDecision(planId: string): ReviewDecisionRecord | null {
    const row = this.database.query<JsonRow, [string]>(
      `SELECT decision_json AS value_json FROM phase3_review_decisions
       WHERE review_plan_id = ? ORDER BY issued_at DESC, review_decision_id DESC LIMIT 1`,
    ).get(planId);
    return row ? reviewDecisionRecordSchema.parse(JSON.parse(row.value_json)) : null;
  }

  insertHumanApproval(approval: HumanReviewApproval): void {
    const value = humanReviewApprovalSchema.parse(approval);
    const plan = this.getReviewPlan(value.review_plan_id);
    if (!plan || plan.snapshot.snapshot_hash !== value.snapshot_hash) throw new Error("Human approval is not bound to the current review snapshot");
    const state = this.getReviewPlanState(value.review_plan_id);
    if (!state || state.status !== "NEEDS_HUMAN") throw new Error("Human approval requires a NEEDS_HUMAN review state");
    const decision = this.getLatestReviewDecision(value.review_plan_id);
    if (!decision || decision.decision !== "NEEDS_HUMAN") throw new Error("Human approval requires the latest NEEDS_HUMAN decision");
    if (decision.snapshot_hash !== value.snapshot_hash
      || decision.review_decision_id !== value.review_decision_id
      || canonicalSha256(decision) !== value.review_decision_hash) {
      throw new Error("Human approval decision binding mismatch");
    }
    const expectedFindingIds = [...new Set([...decision.accepted_findings, ...decision.unresolved_findings])].sort();
    if (canonicalSha256(value.finding_ids) !== canonicalSha256(expectedFindingIds)) throw new Error("Human approval finding binding mismatch");
    this.database.query(
      `INSERT INTO phase3_human_review_approvals
       (approval_id, review_plan_id, snapshot_hash, approval_json, approved_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(value.approval_id, value.review_plan_id, value.snapshot_hash, JSON.stringify(value), value.approved_at);
  }

  getLatestHumanApproval(planId: string): HumanReviewApproval | null {
    const row = this.database.query<JsonRow, [string]>(
      `SELECT approval_json AS value_json FROM phase3_human_review_approvals
       WHERE review_plan_id = ? ORDER BY approved_at DESC, approval_id DESC LIMIT 1`,
    ).get(planId);
    return row ? humanReviewApprovalSchema.parse(JSON.parse(row.value_json)) : null;
  }

  insertWaiver(waiver: Waiver): void {
    const value = waiverSchema.parse(waiver);
    if (value.effective_severity_at_approval === "CRITICAL") throw new Error("Critical findings cannot be waived");
    if (value.expires_at && Date.parse(value.expires_at) <= Date.parse(value.created_at)) throw new Error("Expired waivers cannot be persisted");
    const finding = this.getFinding(value.finding_id);
    if (!finding) throw new Error("Waiver finding not found");
    assertWaiverApplies(value, finding, value.snapshot_hash, value.created_at);
    this.database.query(
      `INSERT INTO phase3_review_waivers (waiver_id, finding_id, snapshot_hash, waiver_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(value.waiver_id, value.finding_id, value.snapshot_hash, JSON.stringify(value), value.created_at);
  }

  getWaiver(waiverId: string): Waiver | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT waiver_json AS value_json FROM phase3_review_waivers WHERE waiver_id = ?",
    ).get(waiverId);
    return row ? waiverSchema.parse(JSON.parse(row.value_json)) : null;
  }

  listWaivers(reviewPlanId: string): Waiver[] {
    return this.database.query<JsonRow, [string]>(
      `SELECT waiver.waiver_json AS value_json
       FROM phase3_review_waivers waiver
       JOIN phase3_review_findings finding ON finding.finding_id = waiver.finding_id
       WHERE finding.review_plan_id = ? ORDER BY waiver.created_at, waiver.waiver_id`,
    ).all(reviewPlanId).map(row => waiverSchema.parse(JSON.parse(row.value_json)));
  }

  insertRepairProposal(proposal: RepairProposal): void {
    const value = repairProposalSchema.parse(proposal);
    const existing = this.getRepairProposal(value.repair_proposal_id);
    if (existing) {
      if (canonicalSha256(existing) !== canonicalSha256(value)) throw new Error("Conflicting repair proposal receipt");
      return;
    }
    this.database.query(
      `INSERT INTO phase3_repair_proposals
       (repair_proposal_id, task_id, source_review_plan_id, proposal_json, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(value.repair_proposal_id, value.task_id, value.source_review_plan_id, JSON.stringify(value), value.created_at);
  }

  getRepairProposal(proposalId: string): RepairProposal | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT proposal_json AS value_json FROM phase3_repair_proposals WHERE repair_proposal_id = ?",
    ).get(proposalId);
    return row ? repairProposalSchema.parse(JSON.parse(row.value_json)) : null;
  }

  appendEvent(input: ReviewAuditEvent): { status: "APPENDED" | "DUPLICATE" } {
    const event = parseGovernanceAuditEvent(input);
    const existing = this.database.query<EventHashRow, [string]>(
      "SELECT event_hash, event_json FROM phase3_review_events WHERE event_id = ?",
    ).get(event.event_id);
    if (existing) {
      if (existing.event_hash !== event.event_hash || existing.event_json !== JSON.stringify(event)) {
        throw new Error(`Conflicting Phase 3 event receipt: ${event.event_id}`);
      }
      return { status: "DUPLICATE" };
    }
    const previous = this.database.query<{ aggregate_version: number; event_hash: string }, [string]>(
      `SELECT aggregate_version, event_hash FROM phase3_review_events
       WHERE aggregate_id = ? ORDER BY aggregate_version DESC LIMIT 1`,
    ).get(event.aggregate_id);
    const expectedVersion = (previous?.aggregate_version ?? 0) + 1;
    const expectedHash = previous?.event_hash ?? null;
    if (event.aggregate_version !== expectedVersion || event.previous_event_hash !== expectedHash) {
      throw new Error("REVIEW_AUDIT_CHAIN_INVALID");
    }
    try { assertGovernanceAuditEventStream([...this.listEvents(event.aggregate_id), event]); }
    catch { throw new Error("REVIEW_AUDIT_CAUSALITY_INVALID"); }
    this.database.query(
      `INSERT INTO phase3_review_events
       (event_id, event_type, aggregate_type, aggregate_id, aggregate_version, task_id, occurred_at,
        previous_event_hash, event_hash, event_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      event.event_id, event.event_type, event.aggregate_type, event.aggregate_id, event.aggregate_version,
      event.task_id, event.occurred_at, event.previous_event_hash, event.event_hash, JSON.stringify(event),
    );
    return { status: "APPENDED" };
  }

  listEvents(aggregateId: string): ReviewAuditEvent[] {
    return this.database.query<JsonRow, [string]>(
      "SELECT event_json AS value_json FROM phase3_review_events WHERE aggregate_id = ? ORDER BY aggregate_version",
    ).all(aggregateId).map(row => reviewAuditEventSchema.parse(JSON.parse(row.value_json)));
  }

  verifyEventChain(aggregateId: string): { valid: boolean; event_count: number; reason?: string } {
    const events = this.listEvents(aggregateId);
    let previous: string | null = null;
    for (let index = 0; index < events.length; index += 1) {
      const event = events[index]!;
      const { event_hash: ignored, ...content } = event;
      if (event.aggregate_version !== index + 1) return { valid: false, event_count: events.length, reason: "version-gap" };
      if (event.previous_event_hash !== previous) return { valid: false, event_count: events.length, reason: "previous-hash-mismatch" };
      if (canonicalSha256(content) !== event.event_hash) return { valid: false, event_count: events.length, reason: "event-hash-mismatch" };
      previous = event.event_hash;
    }
    return { valid: true, event_count: events.length };
  }
}
