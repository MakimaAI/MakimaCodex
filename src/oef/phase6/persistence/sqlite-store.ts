import { Database } from "bun:sqlite";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  assertMemoryPersistenceSafe,
  assertMemoryRecordIntegrity,
  memoryConflictSchema,
  memoryRecordSchema,
  sensitivityRank,
  trustRank,
  type MemoryAuthorizationContext,
  type MemoryConflict,
  type MemoryRecord,
  type MemoryRelation,
  type MemoryStatus,
} from "../core/domain";
import type { LexicalMemoryQuery, MemoryMetadataQuery, MemoryRecordStore, MemoryRetrievalStore, MemorySearchHit } from "../storage/ports";
import {
  memoryCandidateSchema,
  memoryIngestionJobSchema,
  type MemoryCandidate,
  type MemoryIngestionJob,
} from "../ingestion/pipeline";
import {
  assertMemoryArtifactReceiptsAuthentic,
  type MemoryDeletionJob,
  type VerifiedMemoryArtifactReceipt,
} from "../governance/operations";

export class SqliteMemoryStore implements MemoryRecordStore, MemoryRetrievalStore {
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    const migrationRoot = join(import.meta.dir, "migrations");
    for (const file of readdirSync(migrationRoot).filter(file => /^\d+_.+\.sql$/.test(file)).sort()) {
      this.database.exec(readFileSync(join(migrationRoot, file), "utf8"));
    }
  }

  close(): void { this.database.close(); }

  transaction<T>(operation: () => T): T {
    return this.database.transaction(operation).immediate();
  }

  create(record: MemoryRecord): void {
    memoryRecordSchema.parse(record);
    assertMemoryRecordIntegrity(record);
    if (record.lifecycle.status === "FORGOTTEN") throw new Error("MEMORY_FORGET_REQUIRES_TRANSACTION");
    this.transaction(() => {
      const tombstone = this.database.query("SELECT memory_id FROM memory_tombstones WHERE memory_id=?").get(record.memory_id);
      if (tombstone) throw new Error("MEMORY_ID_TOMBSTONED");
      this.assertNoDeletedRelationTargets(record);
      const existing = this.database.query("SELECT current_revision_id, payload_json FROM memory_records WHERE memory_id=?").get(record.memory_id) as { current_revision_id: string; payload_json: string } | null;
      if (existing) {
        const current = decodeRecord(existing.payload_json);
        if (current.integrity.content_hash === record.integrity.content_hash) return;
        throw new Error("MEMORY_IMMUTABLE_RECORD_CONFLICT");
      }
      this.insertCurrent(record, false);
    });
  }

  appendRevision(revision: MemoryRecord, expectedRevision: number): void {
    memoryRecordSchema.parse(revision);
    assertMemoryRecordIntegrity(revision);
    this.transaction(() => {
      const tombstone = this.database.query("SELECT memory_id FROM memory_tombstones WHERE memory_id=?").get(revision.memory_id);
      if (tombstone) throw new Error("MEMORY_ID_TOMBSTONED");
      this.assertNoDeletedRelationTargets(revision);
      const current = this.database.query("SELECT current_revision_number, current_revision_id FROM memory_records WHERE memory_id=?").get(revision.memory_id) as { current_revision_number: number; current_revision_id: string } | null;
      if (!current || current.current_revision_number !== expectedRevision || revision.revision_number !== expectedRevision + 1 || revision.previous_revision_id !== current.current_revision_id) {
        throw new Error("MEMORY_REVISION_CONFLICT");
      }
      const prior = this.database.query("SELECT content_hash FROM memory_revisions WHERE revision_id=?").get(revision.revision_id) as { content_hash: string } | null;
      if (prior) {
        if (prior.content_hash === revision.integrity.content_hash) return;
        throw new Error("MEMORY_IMMUTABLE_RECORD_CONFLICT");
      }
      this.insertCurrent(revision, true);
    });
  }

  get(memoryId: string, revision?: number): MemoryRecord | null {
    const row = revision === undefined
      ? this.database.query("SELECT payload_json FROM memory_records WHERE memory_id=?").get(memoryId)
      : this.database.query("SELECT payload_json FROM memory_revisions WHERE memory_id=? AND revision_number=?").get(memoryId, revision);
    const value = parseRow<MemoryRecord>(row);
    if (value) assertMemoryRecordIntegrity(value);
    return value;
  }

  getByRevisionId(revisionId: string): MemoryRecord | null {
    const value = parseRow<MemoryRecord>(this.database.query("SELECT payload_json FROM memory_revisions WHERE revision_id=?").get(revisionId));
    if (value) assertMemoryRecordIntegrity(value);
    return value;
  }

  getAuthorized(memoryId: string, authorization: MemoryAuthorizationContext, revision?: number): MemoryRecord | null {
    const effective = this.getEffective(memoryId, revision);
    if (!effective) return null;
    if (effective.effective_lifecycle_status === "FORGOTTEN") throw new Error("MEMORY_FORGOTTEN");
    this.assertRecordAuthorized(effective.record, authorization);
    return effective.record;
  }

  getEffective(memoryId: string, revision?: number): {
    record: MemoryRecord;
    effective_lifecycle_status: MemoryStatus;
    tombstone: { mode: string; content_retained: boolean } | null;
  } | null {
    const record = this.get(memoryId, revision);
    if (!record) return null;
    const row = this.database.query("SELECT mode, content_retained FROM memory_tombstones WHERE memory_id=?").get(memoryId) as { mode: string; content_retained: number } | null;
    return {
      record,
      effective_lifecycle_status: row?.mode === "SOFT_FORGET" ? "FORGOTTEN" : record.lifecycle.status,
      tombstone: row ? { mode: row.mode, content_retained: row.content_retained === 1 } : null,
    };
  }

  isRecordVisible(record: MemoryRecord, query: MemoryMetadataQuery): boolean {
    try {
      this.assertRecordAuthorized(record, {
        role: query.role,
        authorized_scopes: query.authorized_scopes,
        max_sensitivity: query.max_sensitivity,
      });
      const current = this.getEffective(record.memory_id);
      return current?.record.revision_id === record.revision_id
        && current.effective_lifecycle_status === record.lifecycle.status
        && query.allowed_statuses.includes(record.lifecycle.status)
        && (query.usage_mode !== "GOVERNANCE_INSTRUCTION" || (record.layer === "GOVERNANCE" && record.change.actor.type === "human"))
        && trustRank(record.trust.level) >= trustRank(query.minimum_trust)
        && Date.parse(record.temporal.valid_from) <= Date.parse(query.at)
        && (record.temporal.valid_until === null || Date.parse(record.temporal.valid_until) > Date.parse(query.at))
        && (query.layers.length === 0 || query.layers.includes(record.layer))
        && query.scopes.every(scope => record.scopes.some(candidate => candidate.type === scope.type && candidate.id === scope.id));
    } catch {
      return false;
    }
  }

  queryMetadata(query: MemoryMetadataQuery): MemoryRecord[] {
    return this.searchCurrent(query, null).map(hit => hit.record);
  }

  lexicalSearch(query: LexicalMemoryQuery): MemorySearchHit[] {
    const ftsQuery = buildFtsQuery(query.text);
    if (!ftsQuery) return this.searchCurrent(query, null);
    return this.searchCurrent(query, ftsQuery);
  }

  link(relation: MemoryRelation): void {
    this.assertReferencesNotFenced([relation.from_memory_id, relation.to_memory_id]);
    if (!this.get(relation.from_memory_id) || !this.get(relation.to_memory_id)) throw new Error("MEMORY_RELATION_RECORD_NOT_FOUND");
    this.database.query("INSERT OR IGNORE INTO memory_relations (relation_id, relation_type, from_memory_id, to_memory_id, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?)")
      .run(relation.relation_id, relation.type, relation.from_memory_id, relation.to_memory_id, relation.created_at, JSON.stringify(relation));
  }

  createConflict(conflict: MemoryConflict): void {
    const parsed = memoryConflictSchema.parse(conflict);
    assertMemoryPersistenceSafe(parsed);
    if (parsed.memory_ids.some(memoryId => !this.get(memoryId))) throw new Error("MEMORY_CONFLICT_RECORD_NOT_FOUND");
    const existing = this.database.query("SELECT payload_json FROM memory_conflicts WHERE conflict_id=?").get(parsed.conflict_id) as { payload_json: string } | null;
    if (existing && existing.payload_json !== JSON.stringify(parsed)) throw new Error("MEMORY_CONFLICT_IMMUTABLE");
    this.database.query("INSERT OR IGNORE INTO memory_conflicts (conflict_id, status, created_at, payload_json) VALUES (?, ?, ?, ?)")
      .run(parsed.conflict_id, parsed.status, parsed.created_at, JSON.stringify(parsed));
  }

  listConflictsFor(memoryIds: string[], visibility?: MemoryMetadataQuery): MemoryConflict[] {
    if (memoryIds.length === 0) return [];
    const selected = new Set(memoryIds);
    return (this.database.query("SELECT payload_json FROM memory_conflicts WHERE status='UNRESOLVED' ORDER BY created_at, conflict_id").all() as Array<{ payload_json: string }>)
      .map(row => memoryConflictSchema.parse(JSON.parse(row.payload_json)))
      .filter(conflict => conflict.memory_ids.some(memoryId => selected.has(memoryId)))
      .filter(conflict => !visibility || conflict.memory_ids.every(memoryId => {
        const record = this.get(memoryId);
        return Boolean(record && this.isRecordVisible(record, visibility));
      }));
  }

  unresolvedConflictMemoryIds(memoryIds: string[]): string[] {
    if (memoryIds.length === 0) return [];
    const selected = new Set(memoryIds);
    const conflicted = new Set<string>();
    const rows = this.database.query("SELECT payload_json FROM memory_conflicts WHERE status='UNRESOLVED'").all() as Array<{ payload_json: string }>;
    for (const row of rows) {
      const conflict = memoryConflictSchema.parse(JSON.parse(row.payload_json));
      if (!conflict.memory_ids.some(memoryId => selected.has(memoryId))) continue;
      for (const memoryId of conflict.memory_ids) if (selected.has(memoryId)) conflicted.add(memoryId);
    }
    return [...conflicted].sort();
  }

  provenance(memoryId: string): { memory_id: string; revision_id: string; source_refs: string[]; relations: MemoryRecord["relations"]; revisions: Array<{ revision_id: string; revision_number: number; previous_revision_id: string | null; source_refs: string[]; content_hash: string; provenance_hash: string; changed_at: string; changed_by: MemoryRecord["change"]["actor"]; reason: string }> } | null {
    const record = this.get(memoryId);
    if (!record) return null;
    const revisions = (this.database.query("SELECT payload_json FROM memory_revisions WHERE memory_id=? ORDER BY revision_number").all(memoryId) as Array<{ payload_json: string }>)
      .map(row => decodeRecord(row.payload_json))
      .map(revision => ({
        revision_id: revision.revision_id,
        revision_number: revision.revision_number,
        previous_revision_id: revision.previous_revision_id,
        source_refs: revision.provenance.source_refs,
        content_hash: revision.integrity.content_hash,
        provenance_hash: revision.integrity.provenance_hash,
        changed_at: revision.change.at,
        changed_by: revision.change.actor,
        reason: revision.change.reason,
      }));
    return { memory_id: record.memory_id, revision_id: record.revision_id, source_refs: record.provenance.source_refs, relations: record.relations, revisions };
  }

  provenanceAuthorized(memoryId: string, authorization: MemoryAuthorizationContext): ReturnType<SqliteMemoryStore["provenance"]> {
    const current = this.getAuthorized(memoryId, authorization);
    if (!current) return null;
    const revisions = this.database.query("SELECT payload_json FROM memory_revisions WHERE memory_id=? ORDER BY revision_number").all(memoryId) as Array<{ payload_json: string }>;
    for (const row of revisions) {
      try { this.assertRecordAuthorized(decodeRecord(row.payload_json), authorization); }
      catch { throw new Error("MEMORY_PROVENANCE_REVISION_ACCESS_DENIED"); }
    }
    return this.provenance(memoryId);
  }

  wasInjected(input: { execution_id: string; session_id: string; revision_id: string }): boolean {
    return Boolean(this.database.query(`SELECT 1
      FROM memory_injection_ledger ledger
      JOIN memory_injection_deliveries delivery
        ON delivery.execution_id=ledger.execution_id
       AND delivery.session_id=ledger.session_id
       AND delivery.pack_hash=ledger.pack_hash
       AND delivery.status='DELIVERED'
      JOIN memory_injection_delivery_items item
        ON item.delivery_id=delivery.delivery_id
       AND item.memory_revision_id=ledger.memory_revision_id
      WHERE ledger.execution_id=? AND ledger.session_id=? AND ledger.memory_revision_id=?`)
      .get(input.execution_id, input.session_id, input.revision_id));
  }

  prepareInjection(input: { delivery_id: string; execution_id: string; session_id: string; revision_ids: string[]; pack_id: string; pack_hash: string; prepared_at: string }): void {
    assertMemoryPersistenceSafe(input);
    this.transaction(() => {
      const existing = this.database.query("SELECT execution_id, session_id, pack_id, pack_hash FROM memory_injection_deliveries WHERE delivery_id=?").get(input.delivery_id) as { execution_id: string; session_id: string; pack_id: string; pack_hash: string } | null;
      if (existing) {
        if (existing.execution_id !== input.execution_id || existing.session_id !== input.session_id || existing.pack_id !== input.pack_id || existing.pack_hash !== input.pack_hash) {
          throw new Error("MEMORY_INJECTION_DELIVERY_CONFLICT");
        }
        return;
      }
      this.database.query("INSERT INTO memory_injection_deliveries (delivery_id, execution_id, session_id, pack_id, pack_hash, status, prepared_at) VALUES (?, ?, ?, ?, ?, 'PREPARED', ?)")
        .run(input.delivery_id, input.execution_id, input.session_id, input.pack_id, input.pack_hash, input.prepared_at);
      const insert = this.database.query("INSERT INTO memory_injection_delivery_items (delivery_id, memory_revision_id) VALUES (?, ?)");
      for (const revisionId of [...new Set(input.revision_ids)]) insert.run(input.delivery_id, revisionId);
    });
  }

  acknowledgeInjection(input: { delivery_id: string; pack_hash: string; acknowledged_at: string }): void {
    assertMemoryPersistenceSafe(input);
    if (!Number.isFinite(Date.parse(input.acknowledged_at))) throw new Error("MEMORY_INJECTION_ACK_INVALID");
    this.transaction(() => {
      const delivery = this.database.query("SELECT execution_id, session_id, pack_hash, status FROM memory_injection_deliveries WHERE delivery_id=?").get(input.delivery_id) as { execution_id: string; session_id: string; pack_hash: string; status: string } | null;
      if (!delivery) throw new Error("MEMORY_INJECTION_DELIVERY_NOT_FOUND");
      if (delivery.pack_hash !== input.pack_hash) throw new Error("MEMORY_INJECTION_PACK_HASH_MISMATCH");
      if (delivery.status === "DELIVERED") return;
      const revisions = this.database.query("SELECT memory_revision_id FROM memory_injection_delivery_items WHERE delivery_id=? ORDER BY memory_revision_id").all(input.delivery_id) as Array<{ memory_revision_id: string }>;
      const insert = this.database.query(`INSERT INTO memory_injection_ledger
        (execution_id, session_id, memory_revision_id, pack_hash, injected_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(execution_id, session_id, memory_revision_id)
        DO UPDATE SET pack_hash=excluded.pack_hash, injected_at=excluded.injected_at`);
      for (const revision of revisions) insert.run(delivery.execution_id, delivery.session_id, revision.memory_revision_id, delivery.pack_hash, input.acknowledged_at);
      this.database.query("UPDATE memory_injection_deliveries SET status='DELIVERED', delivered_at=? WHERE delivery_id=? AND status='PREPARED'")
        .run(input.acknowledged_at, input.delivery_id);
    });
  }

  saveQueryExplanation(queryId: string, payload: unknown, executedAt: string): void {
    this.database.query("INSERT INTO memory_query_logs (query_id, executed_at, payload_json) VALUES (?, ?, ?) ON CONFLICT(query_id) DO UPDATE SET executed_at=excluded.executed_at, payload_json=excluded.payload_json")
      .run(queryId, executedAt, JSON.stringify(payload));
  }

  explainQuery(queryId: string): unknown | null {
    return parseRow(this.database.query("SELECT payload_json FROM memory_query_logs WHERE query_id=?").get(queryId));
  }

  explainQueryAuthorized(queryId: string, authorization: MemoryAuthorizationContext): unknown | null {
    const value = this.explainQuery(queryId);
    if (!value || typeof value !== "object") return value;
    const selected = (value as { selected?: Array<{ memory_id?: string }> }).selected ?? [];
    for (const item of selected) if (item.memory_id) this.getAuthorized(item.memory_id, authorization);
    return value;
  }

  saveContextPack(pack: { pack_id: string; query_id: string; pack_hash: string }, createdAt: string): void {
    this.database.query("INSERT OR REPLACE INTO memory_context_packs (pack_id, query_id, pack_hash, created_at, payload_json) VALUES (?, ?, ?, ?, ?)")
      .run(pack.pack_id, pack.query_id, pack.pack_hash, createdAt, JSON.stringify(pack));
  }

  enqueueIngestionJob(job: MemoryIngestionJob): { job: MemoryIngestionJob; deduplicated: boolean } {
    const parsed = memoryIngestionJobSchema.parse(job);
    assertMemoryPersistenceSafe(parsed);
    return this.transaction(() => {
      const existing = this.database.query("SELECT payload_json FROM memory_jobs WHERE json_extract(payload_json, '$.idempotency_key')=?")
        .get(parsed.idempotency_key) as { payload_json: string } | null;
      if (existing) {
        const current = memoryIngestionJobSchema.parse(JSON.parse(existing.payload_json));
        if (current.event_hash !== parsed.event_hash) throw new Error("MEMORY_JOB_IDEMPOTENCY_CONFLICT");
        return { job: current, deduplicated: true };
      }
      this.database.query("INSERT INTO memory_jobs (job_id, status, priority, payload_json) VALUES (?, ?, ?, ?)")
        .run(parsed.job_id, parsed.status, parsed.priority, JSON.stringify(parsed));
      return { job: parsed, deduplicated: false };
    });
  }

  inspectIngestionJob(jobId: string): MemoryIngestionJob | null {
    const row = this.database.query("SELECT payload_json FROM memory_jobs WHERE job_id=?").get(jobId) as { payload_json: string } | null;
    return row ? memoryIngestionJobSchema.parse(JSON.parse(row.payload_json)) : null;
  }

  claimIngestionJob(input: { worker_id: string; now: string; lease_expires_at: string }): MemoryIngestionJob | null {
    assertMemoryPersistenceSafe(input);
    return this.transaction(() => {
      const now = Date.parse(input.now);
      const rows = this.database.query("SELECT payload_json FROM memory_jobs WHERE status IN ('QUEUED', 'RETRY', 'LEASED') ORDER BY priority DESC, job_id")
        .all() as Array<{ payload_json: string }>;
      const eligible = rows
        .map(row => memoryIngestionJobSchema.parse(JSON.parse(row.payload_json)))
        .filter(job => (job.status === "LEASED"
          ? job.lease_expires_at !== null && Date.parse(job.lease_expires_at) <= now
          : Date.parse(job.next_attempt_at) <= now))
        .sort((left, right) => right.priority - left.priority || left.created_at.localeCompare(right.created_at) || left.job_id.localeCompare(right.job_id))[0];
      if (!eligible) return null;
      const leased = memoryIngestionJobSchema.parse({
        ...eligible,
        status: "LEASED",
        attempt_count: eligible.attempt_count + 1,
        lease_owner: input.worker_id,
        lease_token: `${eligible.job_id}:lease-${eligible.attempt_count + 1}`,
        lease_expires_at: input.lease_expires_at,
        updated_at: input.now,
      });
      this.persistMemoryJob(leased);
      const attemptId = `${leased.job_id}:attempt-${leased.attempt_count}`;
      this.database.query("INSERT OR REPLACE INTO memory_job_attempts (attempt_id, job_id, payload_json) VALUES (?, ?, ?)")
        .run(attemptId, leased.job_id, JSON.stringify({
          attempt_id: attemptId,
          job_id: leased.job_id,
          attempt_number: leased.attempt_count,
          worker_id: input.worker_id,
          status: "LEASED",
          started_at: input.now,
          lease_expires_at: input.lease_expires_at,
        }));
      return leased;
    });
  }

  completeIngestionJob(input: { job_id: string; worker_id: string; lease_token: string; at: string; output_memory_ids: string[] }): MemoryIngestionJob {
    assertMemoryPersistenceSafe(input);
    return this.transaction(() => {
      const current = this.requireLeasedJob(input.job_id, input.worker_id, input.lease_token, input.at);
      const completed = memoryIngestionJobSchema.parse({
        ...current,
        status: "COMPLETED",
        lease_owner: null,
        lease_token: null,
        lease_expires_at: null,
        output_memory_ids: [...new Set(input.output_memory_ids)],
        updated_at: input.at,
      });
      this.persistMemoryJob(completed);
      this.finishJobAttempt(completed, "COMPLETED", input.at, null);
      return completed;
    });
  }

  failIngestionJob(input: { job_id: string; worker_id: string; lease_token: string; at: string; error: { code: string; message: string } }): MemoryIngestionJob {
    assertMemoryPersistenceSafe(input);
    return this.transaction(() => {
      const current = this.requireLeasedJob(input.job_id, input.worker_id, input.lease_token, input.at);
      const status = current.attempt_count >= current.max_attempts ? "DEAD_LETTER" : "RETRY";
      const failed = memoryIngestionJobSchema.parse({
        ...current,
        status,
        lease_owner: null,
        lease_token: null,
        lease_expires_at: null,
        next_attempt_at: input.at,
        last_error: input.error,
        updated_at: input.at,
      });
      this.persistMemoryJob(failed);
      this.finishJobAttempt(failed, status, input.at, input.error);
      return failed;
    });
  }

  saveMemoryCandidate(candidate: MemoryCandidate): { candidate: MemoryCandidate; deduplicated: boolean } {
    const parsed = memoryCandidateSchema.parse(candidate);
    assertMemoryPersistenceSafe(parsed);
    return this.transaction(() => {
      const existing = this.database.query("SELECT payload_json FROM memory_candidates WHERE idempotency_key=? OR candidate_id=? ORDER BY candidate_id LIMIT 1")
        .get(parsed.idempotency_key, parsed.candidate_id) as { payload_json: string } | null;
      if (existing) {
        const current = memoryCandidateSchema.parse(JSON.parse(existing.payload_json));
        if (current.idempotency_key !== parsed.idempotency_key || canonicalCandidate(current) !== canonicalCandidate(parsed)) {
          throw new Error("MEMORY_CANDIDATE_IDEMPOTENCY_CONFLICT");
        }
        return { candidate: current, deduplicated: true };
      }
      this.database.query("INSERT INTO memory_candidates (candidate_id, idempotency_key, status, payload_json) VALUES (?, ?, ?, ?)")
        .run(parsed.candidate_id, parsed.idempotency_key, parsed.status, JSON.stringify(parsed));
      return { candidate: parsed, deduplicated: false };
    });
  }

  getMemoryCandidate(candidateId: string): MemoryCandidate | null {
    const row = this.database.query("SELECT payload_json FROM memory_candidates WHERE candidate_id=?").get(candidateId) as { payload_json: string } | null;
    return row ? memoryCandidateSchema.parse(JSON.parse(row.payload_json)) : null;
  }

  listMemoryCandidates(status?: MemoryCandidate["status"]): MemoryCandidate[] {
    const rows = status
      ? this.database.query("SELECT payload_json FROM memory_candidates WHERE status=? ORDER BY candidate_id").all(status)
      : this.database.query("SELECT payload_json FROM memory_candidates ORDER BY candidate_id").all();
    return (rows as Array<{ payload_json: string }>).map(row => memoryCandidateSchema.parse(JSON.parse(row.payload_json)));
  }

  decideMemoryCandidate(candidate: MemoryCandidate): void {
    const parsed = memoryCandidateSchema.parse(candidate);
    assertMemoryPersistenceSafe(parsed);
    this.transaction(() => {
      const current = this.getMemoryCandidate(parsed.candidate_id);
      if (!current) throw new Error("MEMORY_CANDIDATE_NOT_FOUND");
      if (current.status !== "CANDIDATE") throw new Error("MEMORY_CANDIDATE_ALREADY_DECIDED");
      if (parsed.status === "CANDIDATE" || !parsed.decided_at || !parsed.decided_by) throw new Error("MEMORY_CANDIDATE_DECISION_INVALID");
      this.database.query("UPDATE memory_candidates SET status=?, payload_json=? WHERE candidate_id=? AND status='CANDIDATE'")
        .run(parsed.status, JSON.stringify(parsed), parsed.candidate_id);
    });
  }

  reindexLexical(): { indexed_revisions: number } {
    return this.transaction(() => {
      this.database.exec("DELETE FROM memory_fts;");
      const rows = this.database.query("SELECT current_revision_id, memory_id, payload_json FROM memory_records ORDER BY memory_id").all() as Array<{ current_revision_id: string; memory_id: string; payload_json: string }>;
      const insert = this.database.query("INSERT INTO memory_fts (revision_id, memory_id, summary, structured_json) VALUES (?, ?, ?, ?)");
      for (const row of rows) {
        const record = JSON.parse(row.payload_json) as MemoryRecord;
        insert.run(row.current_revision_id, row.memory_id, record.content.summary, JSON.stringify(record.content.structured ?? {}));
      }
      this.database.query("UPDATE memory_index_registry SET status='HEALTHY', rebuilt_at=?, metadata_json=? WHERE index_id='lexical@1'")
        .run(new Date().toISOString(), JSON.stringify({ indexed_revisions: rows.length }));
      return { indexed_revisions: rows.length };
    });
  }

  forget(memoryId: string, input: { mode: "SOFT_FORGET" | "HARD_DELETE" | "LEGAL_DELETE" | "SECRET_PURGE"; reason: string; at: string; deletion_receipt?: { job_id: string; receipt_hash: string } }): void {
    assertMemoryPersistenceSafe(input);
    if (!input.reason.trim() || input.reason.length > 500 || !Number.isFinite(Date.parse(input.at))) throw new Error("MEMORY_FORGET_COMMAND_INVALID");
    if (input.mode === "LEGAL_DELETE" || input.mode === "SECRET_PURGE") {
      const receipt = input.deletion_receipt;
      const job = receipt ? this.getDeletionJob(receipt.job_id) : null;
      const expectedReceipts = job ? [...job.artifact_receipts].sort((a, b) => a.reference.localeCompare(b.reference)) : [];
      const receiptRefs = new Set(expectedReceipts.map(value => value.reference));
      const expectedHash = job ? canonicalSha256({ memory_ids: job.memory_ids, revision_ids: job.revision_ids, artifact_receipts: expectedReceipts }) : "";
      if (!receipt || !job || job.status !== "ARTIFACTS_VERIFIED" || job.receipt_hash !== receipt.receipt_hash || job.receipt_hash !== expectedHash
        || !job.memory_ids.includes(memoryId) || expectedReceipts.some(value => !["PURGED", "VERIFIED_ABSENT"].includes(value.status))
        || receiptRefs.size !== job.artifact_refs.length || job.artifact_refs.some(reference => !receiptRefs.has(reference))) {
        throw new Error("MEMORY_DELETE_ARTIFACT_RECEIPT_REQUIRED");
      }
    }
    const current = this.get(memoryId);
    if (!current) throw new Error("MEMORY_NOT_FOUND");
    this.transaction(() => {
      if (input.mode === "SOFT_FORGET") {
        this.database.query("UPDATE memory_records SET lifecycle_status='FORGOTTEN' WHERE memory_id=?").run(memoryId);
      } else {
        const revisions = this.database.query("SELECT revision_id FROM memory_revisions WHERE memory_id=?").all(memoryId) as Array<{ revision_id: string }>;
        for (const revision of revisions) {
          this.database.query("DELETE FROM memory_injection_ledger WHERE memory_revision_id=?").run(revision.revision_id);
          const deliveries = this.database.query("SELECT delivery_id FROM memory_injection_delivery_items WHERE memory_revision_id=?").all(revision.revision_id) as Array<{ delivery_id: string }>;
          for (const delivery of deliveries) this.database.query("DELETE FROM memory_injection_deliveries WHERE delivery_id=?").run(delivery.delivery_id);
        }
        for (const table of ["memory_context_packs", "memory_query_logs"] as const) {
          const id = table === "memory_context_packs" ? "pack_id" : "query_id";
          const rows = this.database.query(`SELECT ${id} AS id, payload_json FROM ${table}`).all() as Array<{ id: string; payload_json: string }>;
          for (const row of rows) if (payloadContainsExactReference(row.payload_json, new Set([memoryId, ...revisions.map(revision => revision.revision_id)]))) {
            this.database.query(`DELETE FROM ${table} WHERE ${id}=?`).run(row.id);
          }
        }
        this.database.query("DELETE FROM memory_relations WHERE from_memory_id=? OR to_memory_id=?").run(memoryId, memoryId);
        const conflicts = this.database.query("SELECT conflict_id, payload_json FROM memory_conflicts").all() as Array<{ conflict_id: string; payload_json: string }>;
        for (const conflict of conflicts) if ((JSON.parse(conflict.payload_json) as MemoryConflict).memory_ids.includes(memoryId)) {
          this.database.query("DELETE FROM memory_conflicts WHERE conflict_id=?").run(conflict.conflict_id);
        }
        this.database.query("DELETE FROM memory_fts WHERE memory_id=?").run(memoryId);
        this.database.query("DELETE FROM memory_vector_entries WHERE memory_id=?").run(memoryId);
        for (const table of ["memory_candidates", "memory_feedback", "memory_jobs", "memory_job_attempts"] as const) {
          const id = table === "memory_candidates" ? "candidate_id"
            : table === "memory_feedback" ? "feedback_id"
              : table === "memory_jobs" ? "job_id" : "attempt_id";
          const rows = this.database.query(`SELECT ${id} AS id, payload_json FROM ${table}`).all() as Array<{ id: string; payload_json: string }>;
          for (const row of rows) if (payloadContainsExactReference(row.payload_json, new Set([memoryId, ...revisions.map(revision => revision.revision_id)]))) {
            this.database.query(`DELETE FROM ${table} WHERE ${id}=?`).run(row.id);
          }
        }
        this.database.query("DELETE FROM memory_records WHERE memory_id=?").run(memoryId);
        this.database.query("DELETE FROM memory_revisions WHERE memory_id=?").run(memoryId);
      }
      this.database.query("INSERT OR REPLACE INTO memory_tombstones (memory_id, deleted_at, reason, mode, content_retained) VALUES (?, ?, ?, ?, ?)")
        .run(memoryId, input.at, input.reason, input.mode, input.mode === "SOFT_FORGET" ? 1 : 0);
    });
  }

  planMemoryDeletion(memoryId: string): { memory_ids: string[]; revision_ids: string[]; artifact_refs: string[] } {
    if (!this.get(memoryId)) throw new Error("MEMORY_NOT_FOUND");
    const records = this.listCurrentRecords();
    const selected = new Set([memoryId]);
    const revisionIds = new Set<string>();
    let changed = true;
    while (changed) {
      changed = false;
      revisionIds.clear();
      for (const selectedId of selected) {
        const rows = this.database.query("SELECT revision_id FROM memory_revisions WHERE memory_id=?").all(selectedId) as Array<{ revision_id: string }>;
        for (const row of rows) revisionIds.add(row.revision_id);
      }
      for (const record of records) {
        if (selected.has(record.memory_id)) continue;
        if (record.relations.derived_from.some(reference => selected.has(reference) || revisionIds.has(reference))) {
          selected.add(record.memory_id); changed = true;
        }
      }
    }
    revisionIds.clear();
    const artifactRefs = new Set<string>();
    for (const selectedId of selected) {
      const rows = this.database.query("SELECT revision_id, payload_json FROM memory_revisions WHERE memory_id=? ORDER BY revision_number").all(selectedId) as Array<{ revision_id: string; payload_json: string }>;
      for (const row of rows) {
        revisionIds.add(row.revision_id);
        const revision = decodeRecord(row.payload_json);
        for (const reference of revision.provenance.source_refs) if (reference.startsWith("artifact:")) artifactRefs.add(reference);
      }
    }
    return { memory_ids: [...selected].sort(), revision_ids: [...revisionIds].sort(), artifact_refs: [...artifactRefs].sort() };
  }

  prepareDeletionJob(job: MemoryDeletionJob): void {
    assertMemoryPersistenceSafe(job);
    if (job.status !== "PREPARED" || job.receipt_hash !== null || job.artifact_receipts.length !== 0 || job.canonical_deleted.length !== 0) throw new Error("MEMORY_DELETION_JOB_INVALID");
    this.transaction(() => {
      const currentPlan = this.planMemoryDeletion(job.root_memory_id);
      if (JSON.stringify(currentPlan) !== JSON.stringify({ memory_ids: job.memory_ids, revision_ids: job.revision_ids, artifact_refs: job.artifact_refs })) throw new Error("MEMORY_DELETION_PLAN_CHANGED");
      const existing = this.getDeletionJob(job.job_id);
      if (existing) {
        if (JSON.stringify({ ...existing, updated_at: job.updated_at }) !== JSON.stringify({ ...job, updated_at: job.updated_at })) throw new Error("MEMORY_DELETION_JOB_IMMUTABLE");
        return;
      }
      this.persistDeletionJob(job, false);
      const insert = this.database.query("INSERT INTO memory_deletion_fences (reference_id, job_id, status, created_at) VALUES (?, ?, 'ACTIVE', ?)");
      for (const reference of [...job.memory_ids, ...job.revision_ids]) {
        const fence = this.database.query("SELECT job_id FROM memory_deletion_fences WHERE reference_id=?").get(reference) as { job_id: string } | null;
        if (fence && fence.job_id !== job.job_id) throw new Error("MEMORY_DELETION_FENCE_CONFLICT");
        if (!fence) insert.run(reference, job.job_id, job.created_at);
      }
    });
  }

  verifyDeletionArtifacts(jobId: string, receipts: VerifiedMemoryArtifactReceipt[], at: string): MemoryDeletionJob {
    const job = this.getDeletionJob(jobId) ?? failMemory("MEMORY_DELETION_JOB_NOT_FOUND");
    if (!["PREPARED", "FAILED"].includes(job.status)) throw new Error("MEMORY_DELETION_JOB_TRANSITION_INVALID");
    assertMemoryArtifactReceiptsAuthentic(jobId, receipts);
    const sorted = [...receipts].sort((a, b) => a.reference.localeCompare(b.reference));
    const refs = new Set(sorted.map(receipt => receipt.reference));
    if (sorted.length !== job.artifact_refs.length || refs.size !== job.artifact_refs.length || job.artifact_refs.some(reference => !refs.has(reference))
      || sorted.some(receipt => !["PURGED", "VERIFIED_ABSENT"].includes(receipt.status))) throw new Error("MEMORY_DELETE_ARTIFACT_RECEIPTS_INCOMPLETE");
    const persistedReceipts = sorted.map(({ reference, status }) => ({
      reference, status: status as "PURGED" | "VERIFIED_ABSENT",
    }));
    const receiptHash = canonicalSha256({ memory_ids: job.memory_ids, revision_ids: job.revision_ids, artifact_receipts: persistedReceipts });
    const next: MemoryDeletionJob = { ...job, artifact_receipts: persistedReceipts, receipt_hash: receiptHash, status: "ARTIFACTS_VERIFIED", last_error: null, updated_at: at };
    this.persistDeletionJob(next, true); return next;
  }

  resumeVerifiedDeletionJob(jobId: string, at: string): MemoryDeletionJob {
    const job = this.getDeletionJob(jobId) ?? failMemory("MEMORY_DELETION_JOB_NOT_FOUND");
    if (job.status !== "FAILED" || !job.receipt_hash) throw new Error("MEMORY_DELETION_JOB_TRANSITION_INVALID");
    const refs = new Set(job.artifact_receipts.map(receipt => receipt.reference));
    if (job.artifact_receipts.length !== job.artifact_refs.length || refs.size !== job.artifact_refs.length
      || job.artifact_refs.some(reference => !refs.has(reference))) throw new Error("MEMORY_DELETE_ARTIFACT_RECEIPTS_INCOMPLETE");
    const expectedHash = canonicalSha256({
      memory_ids: job.memory_ids,
      revision_ids: job.revision_ids,
      artifact_receipts: [...job.artifact_receipts].sort((a, b) => a.reference.localeCompare(b.reference)),
    });
    if (expectedHash !== job.receipt_hash) throw new Error("MEMORY_DELETE_ARTIFACT_RECEIPT_REQUIRED");
    const next: MemoryDeletionJob = { ...job, status: "ARTIFACTS_VERIFIED", last_error: null, updated_at: at };
    this.persistDeletionJob(next, true); return next;
  }

  recordDeletionProgress(jobId: string, memoryId: string, at: string): MemoryDeletionJob {
    const job = this.getDeletionJob(jobId) ?? failMemory("MEMORY_DELETION_JOB_NOT_FOUND");
    if (job.status !== "ARTIFACTS_VERIFIED" || !job.memory_ids.includes(memoryId)) throw new Error("MEMORY_DELETION_JOB_TRANSITION_INVALID");
    const next = { ...job, canonical_deleted: [...new Set([...job.canonical_deleted, memoryId])].sort(), updated_at: at };
    this.persistDeletionJob(next, true); return next;
  }

  assertDeletionClosureComplete(jobId: string): void {
    const job = this.getDeletionJob(jobId) ?? failMemory("MEMORY_DELETION_JOB_NOT_FOUND");
    const references = new Set([...job.memory_ids, ...job.revision_ids]);
    for (const record of this.listCurrentRecords()) {
      if (record.relations.derived_from.some(reference => references.has(reference))) throw new Error("MEMORY_DELETION_CLOSURE_CHANGED");
    }
    if (job.memory_ids.some(memoryId => this.get(memoryId))) throw new Error("MEMORY_DELETION_CLOSURE_INCOMPLETE");
  }

  completeDeletionJob(jobId: string, at: string): MemoryDeletionJob {
    const job = this.getDeletionJob(jobId) ?? failMemory("MEMORY_DELETION_JOB_NOT_FOUND");
    if (job.status !== "ARTIFACTS_VERIFIED" || job.canonical_deleted.length !== job.memory_ids.length) throw new Error("MEMORY_DELETION_JOB_TRANSITION_INVALID");
    const next: MemoryDeletionJob = { ...job, status: "COMPLETED", updated_at: at };
    this.transaction(() => {
      this.persistDeletionJob(next, true);
      this.database.query("UPDATE memory_deletion_fences SET status='COMPLETED' WHERE job_id=?").run(jobId);
    });
    return next;
  }

  failDeletionJob(jobId: string, error: string, at: string): void {
    const job = this.getDeletionJob(jobId);
    if (!job || job.status === "COMPLETED") return;
    this.persistDeletionJob({ ...job, status: "FAILED", last_error: error, updated_at: at }, true);
  }

  getDeletionJob(jobId: string): MemoryDeletionJob | null {
    const row = this.database.query("SELECT payload_json FROM memory_deletion_jobs WHERE job_id=?").get(jobId) as { payload_json: string } | null;
    return row ? JSON.parse(row.payload_json) as MemoryDeletionJob : null;
  }

  getTombstone(memoryId: string): { memory_id: string; deleted_at: string; reason: string; mode: string; content_retained: boolean } | null {
    const row = this.database.query("SELECT memory_id, deleted_at, reason, mode, content_retained FROM memory_tombstones WHERE memory_id=?").get(memoryId) as {
      memory_id: string; deleted_at: string; reason: string; mode: string; content_retained: number;
    } | null;
    return row ? { ...row, content_retained: row.content_retained === 1 } : null;
  }

  listCurrentRecords(): MemoryRecord[] {
    return (this.database.query("SELECT payload_json FROM memory_records ORDER BY memory_id").all() as Array<{ payload_json: string }>)
      .map(row => decodeRecord(row.payload_json));
  }

  saveHealthSnapshot(snapshot: Record<string, unknown>): void {
    assertMemoryPersistenceSafe(snapshot);
    const observedAt = typeof snapshot.at === "string" && Number.isFinite(Date.parse(snapshot.at))
      ? new Date(snapshot.at).toISOString()
      : new Date().toISOString();
    const snapshotId = `memory-health:${observedAt.replace(/[^0-9]/g, "")}`;
    this.database.query("INSERT OR REPLACE INTO memory_health_snapshots (snapshot_id, observed_at, payload_json) VALUES (?, ?, ?)")
      .run(snapshotId, observedAt, JSON.stringify(snapshot));
  }

  health(): Record<string, unknown> {
    const integrity = this.database.query("PRAGMA integrity_check").get() as Record<string, string> | null;
    const canonical = this.database.query("SELECT COUNT(*) AS count FROM memory_records").get() as { count: number };
    const revisions = this.database.query("SELECT COUNT(*) AS count FROM memory_revisions").get() as { count: number };
    const fts = this.database.query("SELECT COUNT(*) AS count FROM memory_fts").get() as { count: number };
    const conflicts = this.database.query("SELECT COUNT(*) AS count FROM memory_conflicts WHERE status='UNRESOLVED'").get() as { count: number };
    let integrityFailures = 0;
    let projectionFailures = 0;
    let lexicalFailures = 0;
    let provenanceFailures = 0;
    const payloads = this.database.query("SELECT payload_json FROM memory_revisions").all() as Array<{ payload_json: string }>;
    for (const row of payloads) {
      try {
        const revision = decodeRecord(row.payload_json);
        const projectedRefs = (this.database.query("SELECT source_ref FROM memory_provenance WHERE revision_id=? ORDER BY source_ref").all(revision.revision_id) as Array<{ source_ref: string }>).map(value => value.source_ref);
        if (JSON.stringify(projectedRefs) !== JSON.stringify([...revision.provenance.source_refs].sort())) provenanceFailures += 1;
      } catch { integrityFailures += 1; }
    }
    const currentRows = this.database.query(`SELECT memory_id, current_revision_id, current_revision_number, layer, kind, lifecycle_status,
      trust_level, trust_rank, confidence, sensitivity, sensitivity_rank, valid_from, valid_until, payload_json FROM memory_records ORDER BY memory_id`).all() as Array<Record<string, string | number | null>>;
    for (const row of currentRows) {
      try {
        const record = decodeRecord(String(row.payload_json));
        const revision = this.database.query("SELECT payload_json FROM memory_revisions WHERE revision_id=?").get(record.revision_id) as { payload_json: string } | null;
        const tombstone = this.database.query("SELECT mode FROM memory_tombstones WHERE memory_id=?").get(record.memory_id) as { mode: string } | null;
        const expectedStatus = tombstone?.mode === "SOFT_FORGET" ? "FORGOTTEN" : record.lifecycle.status;
        const projected = row.memory_id === record.memory_id
          && row.current_revision_id === record.revision_id
          && row.current_revision_number === record.revision_number
          && row.layer === record.layer && row.kind === record.kind && row.lifecycle_status === expectedStatus
          && row.trust_level === record.trust.level && row.trust_rank === trustRank(record.trust.level) && row.confidence === record.trust.confidence
          && row.sensitivity === record.access.sensitivity && row.sensitivity_rank === sensitivityRank(record.access.sensitivity)
          && row.valid_from === record.temporal.valid_from && row.valid_until === record.temporal.valid_until
          && revision?.payload_json === row.payload_json;
        const scopes = (this.database.query("SELECT scope_type, scope_id FROM memory_scopes WHERE revision_id=? ORDER BY scope_type, scope_id").all(record.revision_id) as Array<{ scope_type: string; scope_id: string }>).map(scope => `${scope.scope_type}:${scope.scope_id}`);
        const expectedScopes = record.scopes.map(scope => `${scope.type}:${scope.id}`).sort();
        const roles = (this.database.query("SELECT role_id FROM memory_revision_roles WHERE revision_id=? ORDER BY role_id").all(record.revision_id) as Array<{ role_id: string }>).map(item => item.role_id);
        if (!projected || JSON.stringify(scopes) !== JSON.stringify(expectedScopes) || JSON.stringify(roles) !== JSON.stringify([...record.access.read_roles].sort())) projectionFailures += 1;
        const lexical = this.database.query("SELECT memory_id, summary, structured_json FROM memory_fts WHERE revision_id=?").all(record.revision_id) as Array<{ memory_id: string; summary: string; structured_json: string }>;
        if (lexical.length !== 1 || lexical[0]!.memory_id !== record.memory_id || lexical[0]!.summary !== record.content.summary || lexical[0]!.structured_json !== JSON.stringify(record.content.structured ?? {})) lexicalFailures += 1;
      } catch { integrityFailures += 1; }
    }
    return {
      canonical_store: Object.values(integrity ?? {})[0] === "ok" && integrityFailures === 0 && projectionFailures === 0 && provenanceFailures === 0 ? "HEALTHY" : "DEGRADED",
      lexical_index: lexicalFailures === 0 && fts.count === canonical.count ? "HEALTHY" : "DEGRADED",
      canonical_records: canonical.count,
      revisions: revisions.count,
      indexed_records: fts.count,
      open_contradictions: conflicts.count,
      integrity_failures: integrityFailures,
      projection_failures: projectionFailures,
      lexical_failures: lexicalFailures,
      provenance_failures: provenanceFailures,
    };
  }

  private insertCurrent(record: MemoryRecord, update: boolean): void {
    const payload = JSON.stringify(record);
    if (update) {
      this.database.query("DELETE FROM memory_fts WHERE memory_id=?").run(record.memory_id);
      this.database.query(`UPDATE memory_records SET current_revision_id=?, current_revision_number=?, layer=?, kind=?, lifecycle_status=?, trust_level=?, trust_rank=?, confidence=?, sensitivity=?, sensitivity_rank=?, valid_from=?, valid_until=?, payload_json=? WHERE memory_id=?`)
        .run(record.revision_id, record.revision_number, record.layer, record.kind, record.lifecycle.status, record.trust.level, trustRank(record.trust.level), record.trust.confidence, record.access.sensitivity, sensitivityRank(record.access.sensitivity), record.temporal.valid_from, record.temporal.valid_until, payload, record.memory_id);
    } else {
      this.database.query(`INSERT INTO memory_records (memory_id, current_revision_id, current_revision_number, layer, kind, lifecycle_status, trust_level, trust_rank, confidence, sensitivity, sensitivity_rank, valid_from, valid_until, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(record.memory_id, record.revision_id, record.revision_number, record.layer, record.kind, record.lifecycle.status, record.trust.level, trustRank(record.trust.level), record.trust.confidence, record.access.sensitivity, sensitivityRank(record.access.sensitivity), record.temporal.valid_from, record.temporal.valid_until, payload);
    }
    this.database.query("INSERT INTO memory_revisions (revision_id, memory_id, revision_number, previous_revision_id, content_hash, provenance_hash, created_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .run(record.revision_id, record.memory_id, record.revision_number, record.previous_revision_id, record.integrity.content_hash, record.integrity.provenance_hash, record.change.at, payload);
    const scopeInsert = this.database.query("INSERT INTO memory_scopes (revision_id, scope_type, scope_id) VALUES (?, ?, ?)");
    for (const scope of record.scopes) scopeInsert.run(record.revision_id, scope.type, scope.id);
    const roleInsert = this.database.query("INSERT INTO memory_revision_roles (revision_id, role_id) VALUES (?, ?)");
    for (const role of record.access.read_roles) roleInsert.run(record.revision_id, role);
    const provenanceInsert = this.database.query("INSERT INTO memory_provenance (revision_id, source_ref) VALUES (?, ?)");
    for (const source of record.provenance.source_refs) provenanceInsert.run(record.revision_id, source);
    this.database.query("INSERT INTO memory_fts (revision_id, memory_id, summary, structured_json) VALUES (?, ?, ?, ?)")
      .run(record.revision_id, record.memory_id, record.content.summary, JSON.stringify(record.content.structured ?? {}));
  }

  private persistMemoryJob(job: MemoryIngestionJob): void {
    this.database.query("UPDATE memory_jobs SET status=?, priority=?, payload_json=? WHERE job_id=?")
      .run(job.status, job.priority, JSON.stringify(job), job.job_id);
  }

  private persistDeletionJob(job: MemoryDeletionJob, update: boolean): void {
    if (update) {
      this.database.query("UPDATE memory_deletion_jobs SET status=?, receipt_hash=?, updated_at=?, payload_json=? WHERE job_id=?")
        .run(job.status, job.receipt_hash, job.updated_at, JSON.stringify(job), job.job_id);
    } else {
      this.database.query("INSERT INTO memory_deletion_jobs (job_id, root_memory_id, status, receipt_hash, created_at, updated_at, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
        .run(job.job_id, job.root_memory_id, job.status, job.receipt_hash, job.created_at, job.updated_at, JSON.stringify(job));
    }
  }

  private assertNoDeletedRelationTargets(record: MemoryRecord): void {
    this.assertReferencesNotFenced([...record.relations.derived_from, ...record.relations.supersedes, ...record.relations.contradicts]);
  }

  private assertReferencesNotFenced(references: string[]): void {
    for (const reference of references) {
      if (this.database.query("SELECT 1 FROM memory_deletion_fences WHERE reference_id=?").get(reference)
        || this.database.query("SELECT 1 FROM memory_tombstones WHERE memory_id=? AND mode IN ('LEGAL_DELETE','SECRET_PURGE')").get(reference)) {
        throw new Error("MEMORY_RELATION_TARGET_DELETION_PENDING");
      }
    }
  }

  private requireLeasedJob(jobId: string, workerId: string, leaseToken: string, at: string): MemoryIngestionJob {
    const current = this.inspectIngestionJob(jobId);
    if (!current) throw new Error("MEMORY_JOB_NOT_FOUND");
    if (current.status !== "LEASED" || current.lease_owner !== workerId || current.lease_token !== leaseToken) throw new Error("MEMORY_JOB_LEASE_MISMATCH");
    if (!current.lease_expires_at || Date.parse(current.lease_expires_at) <= Date.parse(at)) throw new Error("MEMORY_JOB_LEASE_EXPIRED");
    return current;
  }

  private finishJobAttempt(job: MemoryIngestionJob, status: string, at: string, error: { code: string; message: string } | null): void {
    const attemptId = `${job.job_id}:attempt-${job.attempt_count}`;
    this.database.query("INSERT OR REPLACE INTO memory_job_attempts (attempt_id, job_id, payload_json) VALUES (?, ?, ?)")
      .run(attemptId, job.job_id, JSON.stringify({
        attempt_id: attemptId,
        job_id: job.job_id,
        attempt_number: job.attempt_count,
        status,
        finished_at: at,
        error,
      }));
  }

  private searchCurrent(query: MemoryMetadataQuery, ftsQuery: string | null): MemorySearchHit[] {
    if (query.allowed_statuses.length === 0) return [];
    const parameters: Array<string | number | null> = [];
    const joins = ftsQuery ? "JOIN memory_fts ON memory_fts.revision_id=r.current_revision_id" : "";
    const predicates = [
      `r.lifecycle_status IN (${query.allowed_statuses.map(() => "?").join(",")})`,
      `r.trust_rank >= ?`,
      `r.sensitivity_rank <= ?`,
      `julianday(r.valid_from) <= julianday(?)`,
      `(r.valid_until IS NULL OR julianday(r.valid_until) > julianday(?))`,
      `EXISTS (SELECT 1 FROM memory_revision_roles rr WHERE rr.revision_id=r.current_revision_id AND (rr.role_id=? OR rr.role_id='*'))`,
    ];
    parameters.push(...query.allowed_statuses, trustRank(query.minimum_trust), sensitivityRank(query.max_sensitivity), query.at, query.at, query.role);
    if (query.usage_mode === "GOVERNANCE_INSTRUCTION") {
      predicates.push("r.layer='GOVERNANCE'", "json_extract(r.payload_json, '$.change.actor.type')='human'");
    }
    if (query.layers.length > 0) {
      predicates.push(`r.layer IN (${query.layers.map(() => "?").join(",")})`);
      parameters.push(...query.layers);
    }
    for (const scope of query.scopes) {
      predicates.push("EXISTS (SELECT 1 FROM memory_scopes ms WHERE ms.revision_id=r.current_revision_id AND ms.scope_type=? AND ms.scope_id=?)");
      parameters.push(scope.type, scope.id);
    }
    if (query.authorized_scopes.length === 0) return [];
    const authorizedTerms = query.authorized_scopes.map(() => "(mas.scope_type=? AND mas.scope_id=?)").join(" OR ");
    predicates.push(`NOT EXISTS (SELECT 1 FROM memory_scopes mas WHERE mas.revision_id=r.current_revision_id AND NOT (${authorizedTerms}))`);
    for (const scope of query.authorized_scopes) parameters.push(scope.type, scope.id);
    if (ftsQuery) {
      predicates.push("memory_fts MATCH ?");
      parameters.push(ftsQuery);
    }
    parameters.push(query.limit);
    const score = ftsQuery ? "bm25(memory_fts) AS lexical_rank" : "0 AS lexical_rank";
    const order = ftsQuery ? "lexical_rank ASC, r.confidence DESC, r.memory_id" : "r.confidence DESC, r.memory_id";
    const sql = `SELECT r.payload_json, ${score} FROM memory_records r ${joins} WHERE ${predicates.join(" AND ")} ORDER BY ${order} LIMIT ?`;
    const rows = this.database.query(sql).all(...parameters) as Array<{ payload_json: string; lexical_rank: number }>;
    return rows.map((row, index) => ({
      record: decodeRecord(row.payload_json),
      score: ftsQuery ? 1 / (1 + index) : 0.25 / (1 + index),
      signals: ftsQuery ? ["lexical", "scope", "lifecycle", "temporal", "acl"] : ["metadata", "scope", "lifecycle", "temporal", "acl"],
    }));
  }

  private assertRecordAuthorized(record: MemoryRecord, authorization: MemoryAuthorizationContext): void {
    const allowed = new Set(authorization.authorized_scopes.map(scope => `${scope.type}:${scope.id}`));
    if (record.scopes.some(scope => !allowed.has(`${scope.type}:${scope.id}`))) throw new Error("MEMORY_SCOPE_ACCESS_DENIED");
    if (!record.access.read_roles.includes("*") && !record.access.read_roles.includes(authorization.role)) throw new Error("MEMORY_ROLE_ACCESS_DENIED");
    if (sensitivityRank(record.access.sensitivity) > sensitivityRank(authorization.max_sensitivity)) throw new Error("MEMORY_SENSITIVITY_ACCESS_DENIED");
  }
}

function parseRow<T>(row: unknown): T | null {
  if (!row || typeof row !== "object") return null;
  const value = Object.values(row as Record<string, unknown>)[0];
  return typeof value === "string" ? JSON.parse(value) as T : null;
}

function decodeRecord(payload: string): MemoryRecord {
  const record = memoryRecordSchema.parse(JSON.parse(payload));
  assertMemoryRecordIntegrity(record);
  return record;
}

function payloadContainsExactReference(payload: string, references: ReadonlySet<string>): boolean {
  let value: unknown;
  try { value = JSON.parse(payload); } catch { return false; }
  const visit = (candidate: unknown): boolean => {
    if (typeof candidate === "string") return references.has(candidate);
    if (Array.isArray(candidate)) return candidate.some(visit);
    if (candidate && typeof candidate === "object") return Object.values(candidate as Record<string, unknown>).some(visit);
    return false;
  };
  return visit(value);
}

function buildFtsQuery(text: string): string {
  const tokens = text.match(/[\p{L}\p{N}_./:@-]+/gu) ?? [];
  return [...new Set(tokens.map(token => token.trim()).filter(Boolean))]
    .map(token => `"${token.replaceAll('"', '""')}"`)
    .join(" OR ");
}

function canonicalCandidate(candidate: MemoryCandidate): string {
  const { status: _status, promoted_memory_id: _memoryId, decided_at: _decidedAt, decided_by: _decidedBy, ...proposal } = candidate;
  return JSON.stringify(proposal);
}

function failMemory(message: string): never { throw new Error(message); }
