import { Database } from "bun:sqlite";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import { canonicalJson, canonicalSha256 } from "../core/contract/task-contract";
import type { DomainEvent } from "../core/events/events";
import type { Task, VersionedDefinitionRef } from "../core/task/task";
import type { Approval, ContractRevision } from "../core/contract/revision";
import type { ArtifactRef } from "../artifacts/interfaces/artifact-store";
import type { EvidenceRecord } from "../core/evidence/evidence";
import type { Verdict } from "../core/verdict/verdict";
import type { OefCommandStore, StoredIdempotencyResult } from "../application/ports/oef-store";
import { parsePolicyPack, type PolicyPack } from "../core/policy/policy";
import { parseWorkflowDefinition, type WorkflowDefinition } from "../core/workflow/workflow";

const migrations = [
  { id: "001_initial", url: new URL("./migrations/001_initial.sql", import.meta.url) },
  { id: "002_artifact_classification", url: new URL("./migrations/002_artifact_classification.sql", import.meta.url) },
  { id: "003_append_only_events", url: new URL("./migrations/003_append_only_events.sql", import.meta.url) },
  { id: "004_contract_immutability", url: new URL("./migrations/004_contract_immutability.sql", import.meta.url) },
  { id: "005_contract_authority", url: new URL("./migrations/005_contract_authority.sql", import.meta.url) },
  { id: "006_contract_document_repair", url: new URL("./migrations/006_contract_document_repair.sql", import.meta.url) },
] as const;

interface DefinitionRow {
  definition_hash?: string;
  definition_json?: string;
  policy_hash?: string;
  policy_json?: string;
}

interface JsonRow { task_json: string }
interface MigrationRow { migration_id: string; checksum: string }
interface EventRow { event_json: string }
interface IdempotencyRow { command_hash: string; result_json: string }
interface RevisionRow { revision_json: string; document_json: string }
interface ApprovalRow { approval_json: string }
interface EvidenceRow { evidence_json: string }
interface ArtifactRow { artifact_json: string }
interface VerdictRow { verdict_json: string }
interface SummaryRow { summary_json: string }
interface PendingOutboxRow { event_id: string; event_json: string }

export class SqliteOefStore implements OefCommandStore {
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
      CREATE TABLE IF NOT EXISTS schema_migrations (
        migration_id TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at TEXT NOT NULL
      );
    `);
    const lookup = this.database.query<MigrationRow, [string]>(
      "SELECT migration_id, checksum FROM schema_migrations WHERE migration_id = ?",
    );
    const insert = this.database.query(
      "INSERT INTO schema_migrations (migration_id, checksum, applied_at) VALUES (?, ?, ?)",
    );
    for (const migration of migrations) {
      const sql = readFileSync(migration.url, "utf8");
      const checksum = createHash("sha256").update(sql, "utf8").digest("hex");
      const existing = lookup.get(migration.id);
      if (existing) {
        if (existing.checksum !== checksum) {
          throw new Error(`Applied migration checksum mismatch: ${migration.id}`);
        }
        continue;
      }
      this.database.transaction(() => {
        this.database.exec(sql);
        insert.run(migration.id, checksum, new Date().toISOString());
      })();
    }
  }

  close(): void {
    this.database.close();
  }

  transaction<T>(operation: () => T): T {
    return this.database.transaction(operation).immediate();
  }

  getAppliedMigrations(): string[] {
    return this.database.query<{ migration_id: string }, []>(
      "SELECT migration_id FROM schema_migrations ORDER BY migration_id",
    ).all().map(row => row.migration_id);
  }

  sqliteSettings(): { journal_mode: string; foreign_keys: number; busy_timeout: number } {
    const journal = this.database.query<{ journal_mode: string }, []>("PRAGMA journal_mode").get();
    const foreignKeys = this.database.query<{ foreign_keys: number }, []>("PRAGMA foreign_keys").get();
    const timeout = this.database.query<{ timeout: number }, []>("PRAGMA busy_timeout").get();
    return {
      journal_mode: journal?.journal_mode.toLowerCase() ?? "",
      foreign_keys: foreignKeys?.foreign_keys ?? 0,
      busy_timeout: timeout?.timeout ?? 0,
    };
  }

  installWorkflow(input: unknown): VersionedDefinitionRef {
    const workflow = parseWorkflowDefinition(input);
    const hash = canonicalSha256(workflow);
    const existing = this.database.query<DefinitionRow, [string, string]>(
      "SELECT definition_hash, definition_json FROM workflow_definitions WHERE workflow_id = ? AND version = ?",
    ).get(workflow.workflow_id, workflow.version);
    if (existing && existing.definition_hash !== hash) {
      throw new Error(`Workflow version collision: ${workflow.workflow_id}@${workflow.version}`);
    }
    this.database.query(
      "INSERT OR IGNORE INTO workflow_definitions (workflow_id, version, definition_hash, definition_json) VALUES (?, ?, ?, ?)",
    ).run(workflow.workflow_id, workflow.version, hash, canonicalJson(workflow));
    return { id: workflow.workflow_id, version: workflow.version, hash };
  }

  installPolicy(input: unknown): VersionedDefinitionRef {
    const policy = parsePolicyPack(input);
    const hash = canonicalSha256(policy);
    const existing = this.database.query<DefinitionRow, [string, string]>(
      "SELECT policy_hash, policy_json FROM policy_packs WHERE policy_pack_id = ? AND version = ?",
    ).get(policy.policy_pack_id, policy.version);
    if (existing && existing.policy_hash !== hash) {
      throw new Error(`Policy version collision: ${policy.policy_pack_id}@${policy.version}`);
    }
    this.database.query(
      "INSERT OR IGNORE INTO policy_packs (policy_pack_id, version, policy_hash, policy_json) VALUES (?, ?, ?, ?)",
    ).run(policy.policy_pack_id, policy.version, hash, canonicalJson(policy));
    return { id: policy.policy_pack_id, version: policy.version, hash };
  }

  getWorkflow(id: string, version: string): { definition: WorkflowDefinition; ref: VersionedDefinitionRef } | null {
    const row = this.database.query<DefinitionRow, [string, string]>(
      "SELECT definition_hash, definition_json FROM workflow_definitions WHERE workflow_id = ? AND version = ?",
    ).get(id, version);
    if (!row?.definition_hash || !row.definition_json) return null;
    return {
      definition: parseWorkflowDefinition(JSON.parse(row.definition_json)),
      ref: { id, version, hash: row.definition_hash },
    };
  }

  getPolicy(id: string, version: string): { definition: PolicyPack; ref: VersionedDefinitionRef } | null {
    const row = this.database.query<DefinitionRow, [string, string]>(
      "SELECT policy_hash, policy_json FROM policy_packs WHERE policy_pack_id = ? AND version = ?",
    ).get(id, version);
    if (!row?.policy_hash || !row.policy_json) return null;
    return {
      definition: parsePolicyPack(JSON.parse(row.policy_json)),
      ref: { id, version, hash: row.policy_hash },
    };
  }

  getTask(taskId: string): Task | null {
    const row = this.database.query<JsonRow, [string]>(
      "SELECT task_json FROM tasks WHERE task_id = ?",
    ).get(taskId);
    return row ? JSON.parse(row.task_json) as Task : null;
  }

  insertTask(task: Task): void {
    this.database.query(
      "INSERT INTO tasks (task_id, aggregate_version, status, stage, task_json) VALUES (?, ?, ?, ?, ?)",
    ).run(task.task_id, task.aggregate_version, task.status, task.stage, canonicalJson(task));
    this.database.query(
      "INSERT INTO workflow_instances (task_id, workflow_id, workflow_version, workflow_hash, current_stage) VALUES (?, ?, ?, ?, ?)",
    ).run(task.task_id, task.workflow_ref.id, task.workflow_ref.version, task.workflow_ref.hash, task.stage);
  }

  updateTask(task: Task, expectedVersion: number): boolean {
    const result = this.database.query(
      "UPDATE tasks SET aggregate_version = ?, status = ?, stage = ?, task_json = ? WHERE task_id = ? AND aggregate_version = ?",
    ).run(task.aggregate_version, task.status, task.stage, canonicalJson(task), task.task_id, expectedVersion);
    if (result.changes === 1) {
      this.database.query(`
        UPDATE workflow_instances
        SET workflow_id = ?, workflow_version = ?, workflow_hash = ?, current_stage = ?
        WHERE task_id = ?
      `).run(
        task.workflow_ref.id,
        task.workflow_ref.version,
        task.workflow_ref.hash,
        task.stage,
        task.task_id,
      );
      return true;
    }
    return false;
  }

  insertContractRevision(
    revision: ContractRevision,
    criteria: Array<{ criterion_id: string; key: string; value: unknown }>,
  ): void {
    this.database.query(`
      INSERT INTO contract_revisions (
        revision_id, task_id, revision_number, status, canonical_hash, revision_json, document_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      revision.revision_id,
      revision.task_id,
      revision.revision_number,
      revision.status,
      revision.canonical_hash,
      canonicalJson(revision),
      canonicalJson(revision.document),
    );
    const insertCriterion = this.database.query(
      "INSERT INTO acceptance_criteria (criterion_id, revision_id, criterion_key, criterion_json) VALUES (?, ?, ?, ?)",
    );
    for (const criterion of criteria) {
      insertCriterion.run(criterion.criterion_id, revision.revision_id, criterion.key, canonicalJson(criterion.value));
    }
  }

  getContractRevision(revisionId: string): ContractRevision | null {
    const row = this.database.query<RevisionRow, [string]>(
      "SELECT revision_json, document_json FROM contract_revisions WHERE revision_id = ?",
    ).get(revisionId);
    return row ? this.hydrateContractRevision(row) : null;
  }

  listContractRevisions(taskId: string): ContractRevision[] {
    return this.database.query<RevisionRow, [string]>(
      "SELECT revision_json, document_json FROM contract_revisions WHERE task_id = ? ORDER BY revision_number",
    ).all(taskId).map(row => this.hydrateContractRevision(row));
  }

  updateContractRevision(revision: ContractRevision): void {
    this.database.query(
      "UPDATE contract_revisions SET status = ?, revision_json = ? WHERE revision_id = ?",
    ).run(revision.status, canonicalJson(revision), revision.revision_id);
  }

  private hydrateContractRevision(row: RevisionRow): ContractRevision {
    const revision = JSON.parse(row.revision_json) as ContractRevision;
    return { ...revision, document: JSON.parse(row.document_json) as ContractRevision["document"] };
  }

  insertApproval(approval: Approval): void {
    this.database.query(`
      INSERT INTO approvals (
        approval_id, task_id, subject_type, subject_id, subject_hash, approval_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      approval.approval_id,
      approval.task_id,
      approval.subject.type,
      approval.subject.id,
      approval.subject_hash,
      canonicalJson(approval),
    );
  }

  listApprovals(taskId: string): Approval[] {
    return this.database.query<ApprovalRow, [string]>(
      "SELECT approval_json FROM approvals WHERE task_id = ? ORDER BY rowid",
    ).all(taskId).map(row => JSON.parse(row.approval_json) as Approval);
  }

  insertArtifact(taskId: string, artifact: ArtifactRef): void {
    this.database.query(`
      INSERT OR IGNORE INTO artifacts (
        artifact_id, task_id, content_hash, size_bytes, artifact_json, classification
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      artifact.artifact_id,
      taskId,
      artifact.content_hash,
      artifact.size_bytes,
      canonicalJson(artifact),
      artifact.classification,
    );
  }

  getArtifact(artifactId: string): ArtifactRef | null {
    const row = this.database.query<ArtifactRow, [string]>(
      "SELECT artifact_json FROM artifacts WHERE artifact_id = ?",
    ).get(artifactId);
    return row ? JSON.parse(row.artifact_json) as ArtifactRef : null;
  }

  listArtifacts(taskId: string): ArtifactRef[] {
    return this.database.query<ArtifactRow, [string]>(
      "SELECT artifact_json FROM artifacts WHERE task_id = ? ORDER BY rowid",
    ).all(taskId).map(row => JSON.parse(row.artifact_json) as ArtifactRef);
  }

  insertEvidence(evidence: EvidenceRecord): void {
    this.database.query(`
      INSERT INTO evidence_records (
        evidence_id, task_id, revision_id, criterion_key, status, evidence_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      evidence.evidence_id,
      evidence.task_id,
      evidence.contract_revision_id,
      evidence.criterion_key,
      evidence.status,
      canonicalJson(evidence),
    );
  }

  getEvidence(evidenceId: string): EvidenceRecord | null {
    const row = this.database.query<EvidenceRow, [string]>(
      "SELECT evidence_json FROM evidence_records WHERE evidence_id = ?",
    ).get(evidenceId);
    return row ? JSON.parse(row.evidence_json) as EvidenceRecord : null;
  }

  listEvidence(taskId: string): EvidenceRecord[] {
    return this.database.query<EvidenceRow, [string]>(
      "SELECT evidence_json FROM evidence_records WHERE task_id = ? ORDER BY rowid",
    ).all(taskId).map(row => JSON.parse(row.evidence_json) as EvidenceRecord);
  }

  updateEvidence(evidence: EvidenceRecord): void {
    this.database.query(
      "UPDATE evidence_records SET status = ?, evidence_json = ? WHERE evidence_id = ?",
    ).run(evidence.status, canonicalJson(evidence), evidence.evidence_id);
  }

  insertVerdict(verdict: Verdict): void {
    this.database.query(`
      INSERT INTO verdicts (
        verdict_id, task_id, revision_id, status, decision, verdict_json
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      verdict.verdict_id,
      verdict.task_id,
      verdict.contract_revision_id,
      verdict.status,
      verdict.decision,
      canonicalJson(verdict),
    );
  }

  listVerdicts(taskId: string): Verdict[] {
    return this.database.query<VerdictRow, [string]>(
      "SELECT verdict_json FROM verdicts WHERE task_id = ? ORDER BY rowid",
    ).all(taskId).map(row => JSON.parse(row.verdict_json) as Verdict);
  }

  markVerdicts(taskId: string, from: "CURRENT", to: "STALE" | "SUPERSEDED"): string[] {
    const changed: string[] = [];
    for (const verdict of this.listVerdicts(taskId).filter(item => item.status === from)) {
      const next = { ...verdict, status: to } as Verdict;
      this.database.query(
        "UPDATE verdicts SET status = ?, verdict_json = ? WHERE verdict_id = ?",
      ).run(next.status, canonicalJson(next), next.verdict_id);
      changed.push(next.verdict_id);
    }
    return changed;
  }

  refreshTaskSummary(taskId: string, validCurrentVerdictIds: readonly string[]): Record<string, unknown> | null {
    const task = this.getTask(taskId);
    if (!task) return null;
    const revision = task.active_contract_revision_id
      ? this.getContractRevision(task.active_contract_revision_id)
      : null;
    const evidence = this.listEvidence(taskId).filter(item => item.contract_revision_id === revision?.revision_id);
    const verifiedByCriterion = new Map<string, Set<string>>();
    for (const item of evidence.filter(item => item.status === "VERIFIED")) {
      const values = verifiedByCriterion.get(item.criterion_key) ?? new Set<string>();
      values.add(item.type);
      verifiedByCriterion.set(item.criterion_key, values);
    }
    const criteria = revision?.document.acceptance_criteria ?? [];
    let passed = 0;
    let failed = 0;
    const blockers: string[] = [];
    for (const criterion of criteria) {
      const verified = verifiedByCriterion.get(criterion.key) ?? new Set<string>();
      const missing = criterion.required_evidence.filter(type => !verified.has(type));
      if (missing.length === 0) passed += 1;
      else {
        blockers.push(...missing.map(type => `${criterion.key} — ${type} missing`));
        if (evidence.some(item => item.criterion_key === criterion.key && ["REJECTED", "INVALIDATED"].includes(item.status))) failed += 1;
      }
    }
    const verdicts = this.listVerdicts(taskId);
    const validVerdicts = new Set(validCurrentVerdictIds);
    const latest = [...verdicts].reverse().find(item => {
      if (item.status !== "CURRENT") return false;
      if (!validVerdicts.has(item.verdict_id)) return false;
      if (
        !revision
        || item.contract_revision_id !== revision.revision_id
        || item.dependency_hashes?.contract !== revision.canonical_hash
        || item.dependency_hashes.workflow !== task.workflow_ref.hash
        || item.dependency_hashes.policy !== task.policy_pack_ref.hash
      ) return false;
      const hashes = new Map(item.dependency_hashes.evidence.map(value => [value.evidence_id, value.evidence_hash]));
      return item.evidence_refs.every(evidenceId => {
        const record = this.getEvidence(evidenceId);
        return record?.status === "VERIFIED"
          && record.environment.repository_commit === item.repository_commit
          && hashes.get(evidenceId) === canonicalSha256(record);
      });
    }) ?? null;
    const approvals = this.listApprovals(taskId).filter(item => item.decision === "APPROVED");
    const summary = {
      schema_version: 1,
      task_id: task.task_id,
      title: task.title,
      status: task.status,
      stage: task.stage,
      contract: revision ? { revision: revision.revision_number, status: revision.status, hash: revision.canonical_hash } : null,
      criteria: { total: criteria.length, passed, failed, waiting: criteria.length - passed - failed },
      approvals: { granted: approvals.length },
      latest_verdict: latest?.decision ?? null,
      blockers,
      aggregate_version: task.aggregate_version,
    };
    this.database.query(`
      INSERT INTO read_task_summary (task_id, summary_json, projection_version)
      VALUES (?, ?, ?)
      ON CONFLICT(task_id) DO UPDATE SET
        summary_json = excluded.summary_json,
        projection_version = excluded.projection_version
    `).run(taskId, canonicalJson(summary), task.aggregate_version);
    return summary;
  }

  getTaskSummary(taskId: string, validCurrentVerdictIds: readonly string[] = []): Record<string, unknown> | null {
    return this.refreshTaskSummary(taskId, validCurrentVerdictIds);
  }

  listEvents(taskId: string): DomainEvent[] {
    return this.database.query<EventRow, [string]>(
      "SELECT event_json FROM events WHERE aggregate_id = ? ORDER BY aggregate_version",
    ).all(taskId).map(row => JSON.parse(row.event_json) as DomainEvent);
  }

  getTimeline(taskId: string): Array<Record<string, unknown>> {
    return this.listEvents(taskId).map(event => ({
      event_id: event.event_id,
      event_type: event.event_type,
      aggregate_version: event.aggregate.version,
      actor: event.actor,
      occurred_at: event.occurred_at,
      payload: event.payload,
    }));
  }

  latestEventHash(taskId: string): string | null {
    const row = this.database.query<{ event_hash: string }, [string]>(
      "SELECT event_hash FROM events WHERE aggregate_id = ? ORDER BY aggregate_version DESC LIMIT 1",
    ).get(taskId);
    return row?.event_hash ?? null;
  }

  appendEvent(event: DomainEvent): void {
    this.database.query(`
      INSERT INTO events (
        event_id, aggregate_type, aggregate_id, aggregate_version, event_type,
        previous_event_hash, event_hash, event_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      event.event_id,
      event.aggregate.type,
      event.aggregate.id,
      event.aggregate.version,
      event.event_type,
      event.integrity.previous_event_hash,
      event.integrity.event_hash,
      canonicalJson(event),
    );
  }

  appendOutbox(event: DomainEvent): void {
    this.database.query(
      "INSERT INTO outbox (event_id, aggregate_id, event_json) VALUES (?, ?, ?)",
    ).run(event.event_id, event.aggregate.id, canonicalJson(event));
  }

  listOutbox(taskId: string): DomainEvent[] {
    return this.database.query<EventRow, [string]>(
      "SELECT event_json FROM outbox WHERE aggregate_id = ? ORDER BY outbox_id",
    ).all(taskId).map(row => JSON.parse(row.event_json) as DomainEvent);
  }

  listPendingOutbox(limit = 100): DomainEvent[] {
    if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) throw new Error("Invalid outbox limit");
    return this.database.query<PendingOutboxRow, [number]>(
      "SELECT event_id, event_json FROM outbox WHERE processed_at IS NULL ORDER BY outbox_id LIMIT ?",
    ).all(limit).map(row => JSON.parse(row.event_json) as DomainEvent);
  }

  markOutboxProcessed(eventId: string, processedAt: string): boolean {
    const result = this.database.query(
      "UPDATE outbox SET processed_at = ? WHERE event_id = ? AND processed_at IS NULL",
    ).run(processedAt, eventId);
    return result.changes === 1;
  }

  getIdempotency(key: string): StoredIdempotencyResult | null {
    const row = this.database.query<IdempotencyRow, [string]>(
      "SELECT command_hash, result_json FROM idempotency_records WHERE idempotency_key = ?",
    ).get(key);
    if (!row) return null;
    return { commandHash: row.command_hash, result: JSON.parse(row.result_json) as StoredIdempotencyResult["result"] };
  }

  saveIdempotency(key: string, commandHash: string, result: StoredIdempotencyResult["result"], createdAt: string): void {
    this.database.query(
      "INSERT INTO idempotency_records (idempotency_key, command_hash, result_json, created_at) VALUES (?, ?, ?, ?)",
    ).run(key, commandHash, canonicalJson(result), createdAt);
  }
}
