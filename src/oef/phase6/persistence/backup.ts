import { Database } from "bun:sqlite";
import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertMemoryPersistenceSafe } from "../core/domain";
import { SqliteMemoryStore } from "./sqlite-store";
import { SqliteVectorMemoryIndex } from "../indexing/local-vector-index";

interface MemoryBackupManifest {
  schema_version: 1;
  created_at: string;
  database_file: "memory.sqlite";
  database_hash: string;
  database_size_bytes: number;
  source_name: string;
  artifact_manifest: Array<{ reference: string; content_hash: string; size_bytes: number; backup_file: string }>;
  artifact_manifest_hash: string;
  encryption: { key_material_included: false; mode: "external" };
}

export class SqliteMemoryBackupService {
  private readonly databasePath: string;

  constructor(options: { databasePath: string }) {
    this.databasePath = resolve(options.databasePath);
  }

  create(input: { backup_root: string; at: string; artifact_files?: Array<{ reference: string; path: string }> }): {
    directory: string;
    database_path: string;
    manifest_path: string;
    manifest: MemoryBackupManifest;
  } {
    if (!Number.isFinite(Date.parse(input.at))) throw new Error("MEMORY_BACKUP_TIME_INVALID");
    if (!existsSync(this.databasePath)) throw new Error("MEMORY_BACKUP_DATABASE_NOT_FOUND");
    const source = new SqliteMemoryStore({ databasePath: this.databasePath });
    try {
      const health = source.health();
      if (health.canonical_store !== "HEALTHY" || health.lexical_index !== "HEALTHY") throw new Error("MEMORY_BACKUP_SOURCE_UNHEALTHY");
      const vector = new SqliteVectorMemoryIndex({ databasePath: this.databasePath });
      try { if (vector.status().status === "DEGRADED") throw new Error("MEMORY_BACKUP_SOURCE_UNHEALTHY"); }
      finally { vector.close(); }
    } finally { source.close(); }
    const backupRoot = resolve(input.backup_root);
    if (existsSync(backupRoot) && lstatSync(backupRoot).isSymbolicLink()) throw new Error("MEMORY_BACKUP_ROOT_UNSAFE");
    mkdirSync(backupRoot, { recursive: true });
    const database = new Database(this.databasePath, { strict: true });
    let bytes: Uint8Array;
    try {
      database.exec("PRAGMA wal_checkpoint(PASSIVE)");
      bytes = database.serialize();
    } finally { database.close(); }
    const snapshotPath = join(backupRoot, `.memory-snapshot-${process.pid}-${randomUUID()}.sqlite`);
    writeFileSync(snapshotPath, bytes, { flag: "wx" });
    const referenceDatabase = new Database(snapshotPath, { readonly: true, strict: true });
    let requiredReferences: string[];
    try {
      requiredReferences = [];
      const rows = referenceDatabase.query("SELECT DISTINCT source_ref FROM memory_provenance WHERE source_ref LIKE 'artifact:%' ORDER BY source_ref").all() as Array<{ source_ref: string }>;
      for (const row of rows) requiredReferences.push(row.source_ref);
    }
    finally {
      referenceDatabase.close();
      rmSync(snapshotPath, { force: true });
      rmSync(`${snapshotPath}-wal`, { force: true });
      rmSync(`${snapshotPath}-shm`, { force: true });
    }
    const supplied = new Map<string, string>();
    for (const item of input.artifact_files ?? []) supplied.set(item.reference, item.path);
    if (supplied.size !== requiredReferences.length) throw new Error("MEMORY_BACKUP_ARTIFACT_UNRESOLVED");
    for (const reference of requiredReferences) if (!supplied.has(reference)) throw new Error("MEMORY_BACKUP_ARTIFACT_UNRESOLVED");
    const artifactBytes: Array<{ reference: string; bytes: Uint8Array; content_hash: string; size_bytes: number; backup_file: string }> = [];
    for (const reference of requiredReferences) {
      const path = resolve(supplied.get(reference)!);
      if (!existsSync(path) || lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile()) throw new Error("MEMORY_BACKUP_ARTIFACT_UNRESOLVED");
      const bytes = readFileSync(path);
      const contentHash = sha256(bytes);
      artifactBytes.push({ reference, bytes, content_hash: contentHash, size_bytes: bytes.byteLength, backup_file: `artifacts/${contentHash.slice(7)}` });
    }
    const artifactManifest: MemoryBackupManifest["artifact_manifest"] = [];
    for (const artifact of artifactBytes) artifactManifest.push({
      reference: artifact.reference,
      content_hash: artifact.content_hash,
      size_bytes: artifact.size_bytes,
      backup_file: artifact.backup_file,
    });
    assertMemoryPersistenceSafe(artifactManifest);
    const at = new Date(input.at).toISOString();
    const artifactManifestHash = canonicalSha256(artifactManifest);
    const directory = join(backupRoot, `memory-backup-${canonicalSha256({ at, database_hash: sha256(bytes), artifact_manifest_hash: artifactManifestHash }).slice(7, 23)}`);
    mkdirSync(directory, { recursive: true });
    mkdirSync(join(directory, "artifacts"), { recursive: true });
    for (const artifact of artifactBytes) writeFileSync(join(directory, artifact.backup_file), artifact.bytes, { flag: "w" });
    const databasePath = join(directory, "memory.sqlite");
    writeFileSync(databasePath, bytes, { flag: "w" });
    const manifest: MemoryBackupManifest = {
      schema_version: 1,
      created_at: at,
      database_file: "memory.sqlite",
      database_hash: sha256(bytes),
      database_size_bytes: bytes.byteLength,
      source_name: basename(this.databasePath),
      artifact_manifest: artifactManifest,
      artifact_manifest_hash: artifactManifestHash,
      encryption: { key_material_included: false, mode: "external" },
    };
    assertMemoryPersistenceSafe(manifest);
    const manifestPath = join(directory, "manifest.json");
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    return { directory, database_path: databasePath, manifest_path: manifestPath, manifest };
  }

  restore(input: { backup_directory: string; target_database_path: string; allow_overwrite: boolean }): {
    restored: true;
    lexical_rebuilt: true;
    vector_rebuild_required: true;
    rollback_path: string | null;
    health: Record<string, unknown>;
  } {
    const directory = resolve(input.backup_directory);
    const manifestPath = join(directory, "manifest.json");
    if (!existsSync(manifestPath)) throw new Error("MEMORY_BACKUP_MANIFEST_NOT_FOUND");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as MemoryBackupManifest;
    if (manifest.schema_version !== 1 || manifest.database_file !== "memory.sqlite") throw new Error("MEMORY_BACKUP_MANIFEST_INVALID");
    assertMemoryPersistenceSafe(manifest);
    if (manifest.artifact_manifest_hash !== canonicalSha256(manifest.artifact_manifest)) throw new Error("MEMORY_BACKUP_ARTIFACT_MANIFEST_HASH_MISMATCH");
    for (const artifact of manifest.artifact_manifest) {
      if (!/^artifacts\/[a-f0-9]{64}$/.test(artifact.backup_file)) throw new Error("MEMORY_BACKUP_ARTIFACT_MANIFEST_INVALID");
      const artifactPath = join(directory, artifact.backup_file);
      if (!existsSync(artifactPath) || lstatSync(artifactPath).isSymbolicLink() || !lstatSync(artifactPath).isFile()) throw new Error("MEMORY_BACKUP_ARTIFACT_MISSING");
      const artifactBytes = readFileSync(artifactPath);
      if (artifactBytes.byteLength !== artifact.size_bytes || sha256(artifactBytes) !== artifact.content_hash) throw new Error("MEMORY_BACKUP_ARTIFACT_HASH_MISMATCH");
    }
    const backupDatabasePath = join(directory, manifest.database_file);
    const bytes = readFileSync(backupDatabasePath);
    if (sha256(bytes) !== manifest.database_hash || bytes.byteLength !== manifest.database_size_bytes) throw new Error("MEMORY_BACKUP_HASH_MISMATCH");
    const validation = new Database(backupDatabasePath, { readonly: true, strict: true });
    try {
      const integrity = validation.query("PRAGMA integrity_check").get() as Record<string, string>;
      if (Object.values(integrity)[0] !== "ok") throw new Error("MEMORY_BACKUP_DATABASE_CORRUPT");
      const requiredReferences: string[] = [];
      const rows = validation.query("SELECT DISTINCT source_ref FROM memory_provenance WHERE source_ref LIKE 'artifact:%' ORDER BY source_ref").all() as Array<{ source_ref: string }>;
      for (const row of rows) requiredReferences.push(row.source_ref);
      const suppliedReferences = new Set<string>();
      for (const artifact of manifest.artifact_manifest) suppliedReferences.add(artifact.reference);
      if (manifest.artifact_manifest.length !== requiredReferences.length || suppliedReferences.size !== requiredReferences.length) {
        throw new Error("MEMORY_BACKUP_ARTIFACT_COVERAGE_MISMATCH");
      }
      for (const reference of requiredReferences) {
        if (!suppliedReferences.has(reference)) throw new Error("MEMORY_BACKUP_ARTIFACT_COVERAGE_MISMATCH");
      }
    } finally { validation.close(); }

    const target = resolve(input.target_database_path);
    mkdirSync(dirname(target), { recursive: true });
    if (existsSync(target) && !input.allow_overwrite) throw new Error("MEMORY_RESTORE_TARGET_EXISTS");
    if (existsSync(`${target}-wal`) || existsSync(`${target}-shm`)) throw new Error("MEMORY_RESTORE_TARGET_BUSY");
    const suffix = manifest.database_hash.slice(7, 19);
    const temporary = `${target}.restore-${suffix}.tmp`;
    const rollback = existsSync(target) ? `${target}.pre-restore-${suffix}` : null;
    if (existsSync(temporary)) rmSync(temporary, { force: true });
    copyFileSync(backupDatabasePath, temporary);
    if (rollback) renameSync(target, rollback);
    try {
      renameSync(temporary, target);
      const store = new SqliteMemoryStore({ databasePath: target });
      let health: Record<string, unknown>;
      try {
        store.reindexLexical();
        health = store.health();
        if (health.canonical_store !== "HEALTHY" || health.lexical_index !== "HEALTHY") throw new Error("MEMORY_RESTORE_VERIFICATION_FAILED");
      } finally { store.close(); }
      const derived = new Database(target, { strict: true });
      try {
        derived.transaction(() => {
          derived.run("DELETE FROM memory_vector_entries");
          derived.run("DELETE FROM memory_vector_generations");
          derived.run("UPDATE memory_index_registry SET status='EMPTY', version='0.0.0', rebuilt_at=NULL, metadata_json='{}' WHERE index_id='vector@local'");
        }).immediate();
      } finally { derived.close(); }
      return { restored: true, lexical_rebuilt: true, vector_rebuild_required: true, rollback_path: rollback, health };
    } catch (error) {
      if (existsSync(target)) rmSync(target, { force: true });
      if (rollback && existsSync(rollback)) renameSync(rollback, target);
      throw error;
    } finally {
      if (existsSync(temporary)) rmSync(temporary, { force: true });
    }
  }
}

function sha256(value: Uint8Array): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}
