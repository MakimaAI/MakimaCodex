import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import {
  MEMORY_LAYERS,
  assertMemoryRecordIntegrity,
  memoryRecordSchema,
  sensitivityRank,
  type MemoryLayer,
  type MemoryScope,
  type MemorySensitivity,
} from "../core/domain";
import type { VectorMemoryIndex } from "../storage/ports";

export const embeddingProfileSchema = z.object({
  id: z.string().trim().min(1).max(128).regex(/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/),
  version: z.string().regex(/^\d+\.\d+\.\d+$/),
  dimensions: z.number().int().min(8).max(4_096),
  provider: z.string().trim().min(1).max(128),
  max_sensitivity: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]),
}).strict();

export type EmbeddingProfile = z.infer<typeof embeddingProfileSchema>;

export const DEFAULT_LOCAL_EMBEDDING_PROFILE: EmbeddingProfile = Object.freeze({
  id: "memory-local-hash",
  version: "1.0.0",
  dimensions: 64,
  provider: "LOCAL_DETERMINISTIC",
  max_sensitivity: "CONFIDENTIAL",
});

export interface MemoryEmbeddingProvider {
  readonly profile: EmbeddingProfile;
  embed(text: string): number[] | Promise<number[]>;
}

interface VectorMetadata {
  memory_id: string;
  layer: MemoryLayer;
  scopes: MemoryScope[];
  sensitivity: Exclude<MemorySensitivity, "SECRET">;
}

export class LocalHashEmbeddingProvider implements MemoryEmbeddingProvider {
  readonly profile: EmbeddingProfile;

  constructor(profile: EmbeddingProfile) {
    this.profile = embeddingProfileSchema.parse(profile);
    if (this.profile.provider !== "LOCAL_DETERMINISTIC") throw new Error("MEMORY_EMBEDDING_PROVIDER_PROFILE_INVALID");
  }

  embed(text: string): number[] {
    const vector: number[] = Array.from({ length: this.profile.dimensions }, () => 0);
    for (const token of tokenize(text)) {
      const first = stableHash(token);
      const second = stableHash(`salt:${token}`);
      const index = first % vector.length;
      vector[index] = vector[index]! + (second % 2 === 0 ? 1 : -1) * (1 + Math.log1p(token.length));
    }
    if (magnitude(vector) === 0) vector[0] = 1;
    return normalize(vector);
  }
}

export class SqliteVectorMemoryIndex implements VectorMemoryIndex {
  private readonly database: Database;
  private readonly profile: EmbeddingProfile;
  private readonly provider: MemoryEmbeddingProvider;

  constructor(options: { databasePath: string; provider?: MemoryEmbeddingProvider }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.database.exec(readFileSync(join(import.meta.dir, "..", "persistence", "migrations", "002_vector_index.sql"), "utf8"));
    this.provider = options.provider ?? new LocalHashEmbeddingProvider(this.loadActiveProfile() ?? DEFAULT_LOCAL_EMBEDDING_PROFILE);
    this.profile = embeddingProfileSchema.parse(this.provider.profile);
  }

  close(): void { this.database.close(); }

  async rebuild(input: { at: string }): Promise<{
    generation_id: string;
    indexed_records: number;
    skipped_restricted: number;
    profile: EmbeddingProfile;
  }> {
    if (!Number.isFinite(Date.parse(input.at))) throw new Error("MEMORY_VECTOR_REBUILD_TIME_INVALID");
    const at = new Date(input.at).toISOString();
    const rows = this.database.query("SELECT payload_json FROM memory_records WHERE lifecycle_status <> 'FORGOTTEN' ORDER BY memory_id").all() as Array<{ payload_json: string }>;
    const entries: Array<{ revision_id: string; memory_id: string; vector: number[]; norm: number; metadata: VectorMetadata }> = [];
    let skippedRestricted = 0;
    for (const row of rows) {
      const record = memoryRecordSchema.parse(JSON.parse(row.payload_json));
      assertMemoryRecordIntegrity(record);
      if (record.lifecycle.status === "FORGOTTEN") continue;
      if (sensitivityRank(record.access.sensitivity) > sensitivityRank(this.profile.max_sensitivity)) {
        skippedRestricted += 1;
        continue;
      }
      const vector = await this.provider.embed(`${record.content.summary}\n${JSON.stringify(record.content.structured ?? {})}`);
      validateVector(vector, this.profile.dimensions);
      const norm = magnitude(vector);
      entries.push({
        revision_id: record.revision_id,
        memory_id: record.memory_id,
        vector,
        norm,
        metadata: {
          memory_id: record.memory_id,
          layer: record.layer,
          scopes: record.scopes,
          sensitivity: record.access.sensitivity as Exclude<MemorySensitivity, "SECRET">,
        },
      });
    }
    const profileHash = canonicalSha256(this.profile);
    const generationId = `memory-vector-generation:${canonicalSha256({
      profile_hash: profileHash,
      at,
      revisions: entries.map(entry => entry.revision_id),
    }).slice(7, 31)}`;
    const profileKey = `${this.profile.id}@${this.profile.version}`;
    const metadata = { indexed_records: entries.length, skipped_restricted: skippedRestricted, profile: this.profile };
    this.database.transaction(() => {
      const snapshot = entries.map(entry => entry.revision_id).sort();
      if (JSON.stringify(this.canonicalRevisionIds(this.profile)) !== JSON.stringify(snapshot)) throw new Error("MEMORY_VECTOR_CANONICAL_CHANGED");
      const existingProfile = this.database.query("SELECT profile_hash FROM embedding_profiles WHERE profile_id=?").get(profileKey) as { profile_hash: string } | null;
      if (existingProfile && existingProfile.profile_hash !== profileHash) throw new Error("MEMORY_EMBEDDING_PROFILE_IMMUTABLE");
      this.database.query("INSERT OR IGNORE INTO embedding_profiles (profile_id, version, profile_hash, payload_json) VALUES (?, ?, ?, ?)")
        .run(profileKey, this.profile.version, profileHash, JSON.stringify(this.profile));
      this.database.query("UPDATE memory_vector_generations SET status='RETIRED' WHERE status='ACTIVE'").run();
      this.database.query("INSERT OR REPLACE INTO memory_vector_generations (generation_id, profile_key, profile_hash, status, created_at, metadata_json) VALUES (?, ?, ?, 'ACTIVE', ?, ?)")
        .run(generationId, profileKey, profileHash, at, JSON.stringify(metadata));
      const insert = this.database.query("INSERT INTO memory_vector_entries (generation_id, revision_id, memory_id, vector_json, vector_norm, metadata_json) VALUES (?, ?, ?, ?, ?, ?)");
      for (const entry of entries) insert.run(generationId, entry.revision_id, entry.memory_id, JSON.stringify(entry.vector), entry.norm, JSON.stringify(entry.metadata));
      this.database.query("UPDATE memory_index_registry SET status='HEALTHY', version=?, rebuilt_at=?, metadata_json=? WHERE index_id='vector@local'")
        .run(this.profile.version, at, JSON.stringify({ ...metadata, generation_id: generationId, profile_hash: profileHash }));
    }).immediate();
    return { generation_id: generationId, indexed_records: entries.length, skipped_restricted: skippedRestricted, profile: this.profile };
  }

  async search(query: { text: string; scopes: MemoryScope[]; layers: MemoryLayer[]; limit: number }): Promise<Array<{ revision_id: string; score: number }>> {
    if (!Number.isInteger(query.limit) || query.limit < 1) throw new Error("MEMORY_VECTOR_QUERY_LIMIT_INVALID");
    const active = this.activeGeneration();
    if (!active) return [];
    if (active.profile_hash !== canonicalSha256(this.profile)) throw new Error("MEMORY_EMBEDDING_PROFILE_MISMATCH");
    const queryVector = await this.provider.embed(query.text);
    validateVector(queryVector, this.profile.dimensions);
    const queryNorm = magnitude(queryVector);
    const requiredScopes = new Set(query.scopes.map(scope => `${scope.type}:${scope.id}`));
    const rows = this.database.query("SELECT revision_id, vector_json, vector_norm, metadata_json FROM memory_vector_entries WHERE generation_id=?")
      .all(active.generation_id) as Array<{ revision_id: string; vector_json: string; vector_norm: number; metadata_json: string }>;
    return rows
      .map(row => ({ row, vector: JSON.parse(row.vector_json) as number[], metadata: JSON.parse(row.metadata_json) as VectorMetadata }))
      .filter(value => query.layers.length === 0 || query.layers.includes(value.metadata.layer))
      .filter(value => {
        const scopes = new Set(value.metadata.scopes.map(scope => `${scope.type}:${scope.id}`));
        return [...requiredScopes].every(scope => scopes.has(scope));
      })
      .map(value => ({ revision_id: value.row.revision_id, score: round(cosine(queryVector, queryNorm, value.vector, value.row.vector_norm)) }))
      .filter(hit => hit.score > 0)
      .sort((left, right) => right.score - left.score || left.revision_id.localeCompare(right.revision_id))
      .slice(0, query.limit);
  }

  status(): Record<string, unknown> {
    const active = this.activeGeneration();
    if (!active) return { status: "EMPTY", generation_id: null, indexed_records: 0, profile: null, skipped_restricted: 0 };
    const metadata = JSON.parse(active.metadata_json) as { indexed_records: number; skipped_restricted: number; profile: EmbeddingProfile };
    const rows = this.database.query("SELECT revision_id, memory_id, vector_json, vector_norm, metadata_json FROM memory_vector_entries WHERE generation_id=? ORDER BY revision_id").all(active.generation_id) as Array<{
      revision_id: string; memory_id: string; vector_json: string; vector_norm: number; metadata_json: string;
    }>;
    const indexed = rows.map(row => row.revision_id);
    const expected = this.canonicalRevisionIds(metadata.profile);
    const indexedSet = new Set(indexed);
    const expectedSet = new Set(expected);
    const canonicalDrift = indexed.filter(revision => !expectedSet.has(revision)).length + expected.filter(revision => !indexedSet.has(revision)).length;
    let vectorFailures = 0;
    for (const row of rows) {
      try {
        const vector = JSON.parse(row.vector_json) as number[];
        validateVector(vector, metadata.profile.dimensions);
        if (Math.abs(magnitude(vector) - row.vector_norm) > 0.000001) throw new Error("norm mismatch");
        const projected = JSON.parse(row.metadata_json) as VectorMetadata;
        const canonicalRow = this.database.query("SELECT payload_json FROM memory_records WHERE current_revision_id=?").get(row.revision_id) as { payload_json: string } | null;
        if (!canonicalRow) throw new Error("canonical missing");
        const canonical = memoryRecordSchema.parse(JSON.parse(canonicalRow.payload_json));
        if (row.memory_id !== canonical.memory_id || projected.memory_id !== canonical.memory_id || projected.layer !== canonical.layer
          || projected.sensitivity !== canonical.access.sensitivity || JSON.stringify(projected.scopes) !== JSON.stringify(canonical.scopes)) throw new Error("metadata mismatch");
      } catch { vectorFailures += 1; }
    }
    return {
      status: indexed.length === metadata.indexed_records && canonicalDrift === 0 && vectorFailures === 0 ? "HEALTHY" : "DEGRADED",
      generation_id: active.generation_id,
      indexed_records: indexed.length,
      skipped_restricted: metadata.skipped_restricted,
      canonical_drift: canonicalDrift,
      vector_failures: vectorFailures,
      profile: metadata.profile,
    };
  }

  deleteMemory(memoryId: string): number {
    const result = this.database.query("DELETE FROM memory_vector_entries WHERE memory_id=?").run(memoryId);
    return Number(result.changes);
  }

  private activeGeneration(): { generation_id: string; profile_key: string; profile_hash: string; metadata_json: string } | null {
    return this.database.query("SELECT generation_id, profile_key, profile_hash, metadata_json FROM memory_vector_generations WHERE status='ACTIVE' LIMIT 1").get() as {
      generation_id: string; profile_key: string; profile_hash: string; metadata_json: string;
    } | null;
  }

  private loadActiveProfile(): EmbeddingProfile | null {
    const active = this.activeGeneration();
    if (!active) return null;
    const row = this.database.query("SELECT profile_hash, payload_json FROM embedding_profiles WHERE profile_id=?").get(active.profile_key) as {
      profile_hash: string; payload_json: string;
    } | null;
    if (!row || row.profile_hash !== active.profile_hash) throw new Error("MEMORY_EMBEDDING_PROFILE_INTEGRITY_MISMATCH");
    const profile = embeddingProfileSchema.parse(JSON.parse(row.payload_json));
    if (canonicalSha256(profile) !== row.profile_hash) throw new Error("MEMORY_EMBEDDING_PROFILE_INTEGRITY_MISMATCH");
    if (profile.provider !== "LOCAL_DETERMINISTIC") throw new Error("MEMORY_EMBEDDING_PROVIDER_UNAVAILABLE");
    return profile;
  }

  private canonicalRevisionIds(profile: EmbeddingProfile): string[] {
    const rows = this.database.query("SELECT payload_json FROM memory_records WHERE lifecycle_status <> 'FORGOTTEN' ORDER BY memory_id").all() as Array<{ payload_json: string }>;
    return rows
      .map(row => memoryRecordSchema.parse(JSON.parse(row.payload_json)))
      .filter(record => sensitivityRank(record.access.sensitivity) <= sensitivityRank(profile.max_sensitivity))
      .map(record => record.revision_id)
      .sort();
  }
}

function tokenize(text: string): string[] {
  const words = text.toLocaleLowerCase("en-US").match(/[\p{L}\p{N}_./:@-]+/gu) ?? [];
  return words.flatMap(word => word.length > 4 ? [word, ...Array.from({ length: word.length - 2 }, (_, index) => word.slice(index, index + 3))] : [word]);
}

function stableHash(value: string): number {
  let hash = 2_166_136_261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16_777_619);
  }
  return hash >>> 0;
}

function normalize(vector: number[]): number[] {
  const norm = magnitude(vector);
  return norm === 0 ? vector : vector.map(value => value / norm);
}

function magnitude(vector: number[]): number {
  return Math.sqrt(vector.reduce((sum, value) => sum + value * value, 0));
}

function cosine(left: number[], leftNorm: number, right: number[], rightNorm: number): number {
  let dot = 0;
  for (let index = 0; index < left.length; index += 1) dot += left[index]! * right[index]!;
  return Math.max(0, Math.min(1, dot / (leftNorm * rightNorm)));
}

function validateVector(vector: number[], dimensions: number): void {
  if (vector.length !== dimensions || vector.some(value => !Number.isFinite(value)) || magnitude(vector) === 0) {
    throw new Error("MEMORY_EMBEDDING_VECTOR_INVALID");
  }
}

function round(value: number): number { return Math.round(value * 1_000_000) / 1_000_000; }

export const EMBEDDING_LAYERS = MEMORY_LAYERS;
