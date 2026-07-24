import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  MEMORY_STATUSES,
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
} from "../core/domain";
import type { LexicalMemoryQuery, MemoryMetadataQuery, MemoryRecordStore, MemorySearchHit } from "../storage/ports";

const ACTIVE_RECALL_STATUSES = MEMORY_STATUSES.filter(status =>
  !["REJECTED", "DISPUTED", "SUPERSEDED", "DEPRECATED", "QUARANTINED", "EXPIRED", "FORGOTTEN"].includes(status),
);

export class SqliteMemoryStore implements MemoryRecordStore {
  private readonly database: Database;

  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    const migration = readFileSync(join(import.meta.dir, "migrations", "001_memory_core.sql"), "utf8");
    this.database.exec(migration);
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
    const tombstone = this.database.query("SELECT memory_id FROM memory_tombstones WHERE memory_id=?").get(memoryId);
    if (tombstone) throw new Error("MEMORY_FORGOTTEN");
    const record = this.get(memoryId, revision);
    if (!record) return null;
    this.assertRecordAuthorized(record, authorization);
    return record;
  }

  isRecordVisible(record: MemoryRecord, query: MemoryMetadataQuery): boolean {
    try {
      this.assertRecordAuthorized(record, {
        role: query.role,
        authorized_scopes: query.authorized_scopes,
        max_sensitivity: query.max_sensitivity,
      });
      const current = this.get(record.memory_id);
      return current?.revision_id === record.revision_id
        && ACTIVE_RECALL_STATUSES.includes(record.lifecycle.status)
        && trustRank(record.trust.level) >= trustRank(query.minimum_trust)
        && record.temporal.valid_from <= query.at
        && (record.temporal.valid_until === null || record.temporal.valid_until > query.at)
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
    return Boolean(this.database.query("SELECT 1 FROM memory_injection_ledger WHERE execution_id=? AND session_id=? AND memory_revision_id=?").get(input.execution_id, input.session_id, input.revision_id));
  }

  recordInjection(input: { execution_id: string; session_id: string; revision_id: string; pack_hash: string; injected_at: string }): void {
    this.database.query("INSERT OR IGNORE INTO memory_injection_ledger (execution_id, session_id, memory_revision_id, pack_hash, injected_at) VALUES (?, ?, ?, ?, ?)")
      .run(input.execution_id, input.session_id, input.revision_id, input.pack_hash, input.injected_at);
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

  forget(memoryId: string, input: { mode: "SOFT_FORGET" | "HARD_DELETE" | "LEGAL_DELETE" | "SECRET_PURGE"; reason: string; at: string }): void {
    assertMemoryPersistenceSafe(input);
    if (!input.reason.trim() || input.reason.length > 500 || !Number.isFinite(Date.parse(input.at))) throw new Error("MEMORY_FORGET_COMMAND_INVALID");
    if (input.mode === "LEGAL_DELETE" || input.mode === "SECRET_PURGE") throw new Error("MEMORY_DELETE_MODE_NOT_IMPLEMENTED");
    const current = this.get(memoryId);
    if (!current) throw new Error("MEMORY_NOT_FOUND");
    this.transaction(() => {
      if (input.mode === "SOFT_FORGET") {
        this.database.query("UPDATE memory_records SET lifecycle_status='FORGOTTEN' WHERE memory_id=?").run(memoryId);
      } else {
        const revisions = this.database.query("SELECT revision_id FROM memory_revisions WHERE memory_id=?").all(memoryId) as Array<{ revision_id: string }>;
        for (const revision of revisions) this.database.query("DELETE FROM memory_injection_ledger WHERE memory_revision_id=?").run(revision.revision_id);
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
        this.database.query("DELETE FROM memory_records WHERE memory_id=?").run(memoryId);
        this.database.query("DELETE FROM memory_revisions WHERE memory_id=?").run(memoryId);
      }
      this.database.query("INSERT OR REPLACE INTO memory_tombstones (memory_id, deleted_at, reason, mode, content_retained) VALUES (?, ?, ?, ?, ?)")
        .run(memoryId, input.at, input.reason, input.mode, input.mode === "SOFT_FORGET" ? 1 : 0);
    });
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
    const payloads = this.database.query("SELECT payload_json FROM memory_revisions").all() as Array<{ payload_json: string }>;
    for (const row of payloads) { try { decodeRecord(row.payload_json); } catch { integrityFailures += 1; } }
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
      canonical_store: Object.values(integrity ?? {})[0] === "ok" && integrityFailures === 0 && projectionFailures === 0 ? "HEALTHY" : "DEGRADED",
      lexical_index: lexicalFailures === 0 && fts.count === canonical.count ? "HEALTHY" : "DEGRADED",
      canonical_records: canonical.count,
      revisions: revisions.count,
      indexed_records: fts.count,
      open_contradictions: conflicts.count,
      integrity_failures: integrityFailures,
      projection_failures: projectionFailures,
      lexical_failures: lexicalFailures,
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

  private searchCurrent(query: MemoryMetadataQuery, ftsQuery: string | null): MemorySearchHit[] {
    const parameters: Array<string | number | null> = [];
    const joins = ftsQuery ? "JOIN memory_fts ON memory_fts.revision_id=r.current_revision_id" : "";
    const predicates = [
      `r.lifecycle_status IN (${ACTIVE_RECALL_STATUSES.map(() => "?").join(",")})`,
      `r.trust_rank >= ?`,
      `r.sensitivity_rank <= ?`,
      `r.valid_from <= ?`,
      `(r.valid_until IS NULL OR r.valid_until > ?)`,
      `(NOT EXISTS (SELECT 1 FROM memory_revision_roles rr0 WHERE rr0.revision_id=r.current_revision_id) OR EXISTS (SELECT 1 FROM memory_revision_roles rr WHERE rr.revision_id=r.current_revision_id AND rr.role_id=?))`,
    ];
    parameters.push(...ACTIVE_RECALL_STATUSES, trustRank(query.minimum_trust), sensitivityRank(query.max_sensitivity), query.at, query.at, query.role);
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
    if (record.access.read_roles.length > 0 && !record.access.read_roles.includes(authorization.role)) throw new Error("MEMORY_ROLE_ACCESS_DENIED");
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
