import type {
  MemoryConflict,
  MemoryLayer,
  MemoryRecord,
  MemoryRelation,
  MemoryScope,
  MemorySensitivity,
  MemoryTrustLevel,
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

export interface VectorMemoryIndex {
  search(query: {
    text: string;
    scopes: MemoryScope[];
    layers: MemoryLayer[];
    limit: number;
  }): Promise<Array<{ revision_id: string; score: number }>>;
}
