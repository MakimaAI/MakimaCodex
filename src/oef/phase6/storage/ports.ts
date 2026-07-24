import type {
  MemoryConflict,
  MemoryLayer,
  MemoryRecord,
  MemoryRelation,
  MemoryScope,
  MemorySensitivity,
  MemoryStatus,
  MemoryTrustLevel,
  MemoryUsageMode,
} from "../core/domain";

export interface MemoryMetadataQuery {
  scopes: MemoryScope[];
  authorized_scopes: MemoryScope[];
  layers: MemoryLayer[];
  role: string;
  max_sensitivity: Exclude<MemorySensitivity, "SECRET">;
  minimum_trust: MemoryTrustLevel;
  at: string;
  limit: number;
  allowed_statuses: MemoryStatus[];
  usage_mode: MemoryUsageMode;
}

export interface LexicalMemoryQuery extends MemoryMetadataQuery {
  text: string;
}

export interface MemorySearchHit {
  record: MemoryRecord;
  score: number;
  signals: string[];
}

export interface MemoryRecordStore {
  create(record: MemoryRecord): void;
  appendRevision(revision: MemoryRecord, expectedRevision: number): void;
  get(memoryId: string, revision?: number): MemoryRecord | null;
  queryMetadata(query: MemoryMetadataQuery): MemoryRecord[];
  link(relation: MemoryRelation): void;
  createConflict(conflict: MemoryConflict): void;
}

export interface MemoryCanonicalReader {
  getByRevisionId(revisionId: string): MemoryRecord | null;
  isRecordVisible(record: MemoryRecord, query: MemoryMetadataQuery): boolean;
}

export interface MemoryLexicalIndex {
  lexicalSearch(query: LexicalMemoryQuery): MemorySearchHit[];
  queryMetadata(query: MemoryMetadataQuery): MemoryRecord[];
}

export interface MemoryConflictReader {
  listConflictsFor(memoryIds: string[], visibility?: MemoryMetadataQuery): MemoryConflict[];
  unresolvedConflictMemoryIds(memoryIds: string[]): string[];
}

export interface MemoryInjectionLedger {
  wasInjected(input: { execution_id: string; session_id: string; revision_id: string }): boolean;
  prepareInjection(input: {
    delivery_id: string;
    execution_id: string;
    session_id: string;
    revision_ids: string[];
    pack_id: string;
    pack_hash: string;
    prepared_at: string;
  }): void;
  acknowledgeInjection(input: { delivery_id: string; pack_hash: string; acknowledged_at: string }): void;
}

export interface MemoryQueryAuditStore {
  saveQueryExplanation(queryId: string, payload: unknown, executedAt: string): void;
  saveContextPack(pack: { pack_id: string; query_id: string; pack_hash: string }, createdAt: string): void;
}

export interface MemoryRetrievalStore extends MemoryCanonicalReader, MemoryLexicalIndex, MemoryConflictReader, MemoryInjectionLedger, MemoryQueryAuditStore {}

export interface MemoryTokenEstimator {
  profile: { id: string; version: string; safety_margin: number; exact: boolean };
  estimate(value: unknown): number;
}

export interface VectorMemoryIndex {
  search(query: {
    text: string;
    scopes: MemoryScope[];
    layers: MemoryLayer[];
    limit: number;
  }): Promise<Array<{ revision_id: string; score: number }>>;
}
