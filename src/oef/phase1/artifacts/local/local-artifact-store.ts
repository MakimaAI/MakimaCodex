import { createHash, randomUUID } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { join, resolve, sep } from "node:path";
import { z } from "zod";
import { actorSchema } from "../../core/shared/actor";
import type { IdGenerator } from "../../core/shared/ids";
import { createSortableIdGenerator } from "../../core/shared/ids";
import { containsLikelyPhase1Secret } from "../../core/security/secrets";
import { artifactRefSchema, type ArtifactInput, type ArtifactRef, type ArtifactStore, type IntegrityResult } from "../interfaces/artifact-store";

const artifactInputSchema = z.object({
  content: z.union([z.string(), z.instanceof(Uint8Array)]),
  media_type: z.string().trim().min(1).max(200),
  classification: z.enum(["public", "internal", "confidential", "secret"]),
  retention_policy: z.string().trim().min(1).max(200),
  created_by: actorSchema,
}).strict();

const sha256 = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

const comparablePath = (path: string): string =>
  process.platform === "win32" ? path.toLowerCase() : path;

export class LocalArtifactStore implements ArtifactStore {
  readonly root: string;
  private readonly ids: IdGenerator;
  private readonly maxBytes: number;

  constructor(options: { root: string; ids?: IdGenerator; maxBytes?: number }) {
    if (!Number.isSafeInteger(options.maxBytes ?? 50 * 1024 * 1024) || (options.maxBytes ?? 1) <= 0) {
      throw new Error("Artifact size limit must be a positive safe integer");
    }
    const requestedRoot = resolve(options.root);
    if (existsSync(requestedRoot) && lstatSync(requestedRoot).isSymbolicLink()) {
      throw new Error("Artifact root cannot be a symlink");
    }
    mkdirSync(requestedRoot, { recursive: true });
    const actualRoot = realpathSync(requestedRoot);
    if (comparablePath(actualRoot) !== comparablePath(requestedRoot)) {
      throw new Error("Artifact root resolves through a symlink");
    }
    this.root = actualRoot;
    this.ids = options.ids ?? createSortableIdGenerator();
    this.maxBytes = options.maxBytes ?? 50 * 1024 * 1024;
  }

  put(input: ArtifactInput): ArtifactRef {
    const parsed = artifactInputSchema.parse(input);
    if (parsed.classification === "secret") throw new Error("Artifact classification secret is not persistable");
    const bytes = typeof parsed.content === "string"
      ? new TextEncoder().encode(parsed.content)
      : parsed.content;
    if (containsLikelyPhase1Secret(new TextDecoder().decode(bytes))) {
      throw new Error("Artifact contains a likely secret");
    }
    if (bytes.byteLength > this.maxBytes) throw new Error("Artifact size exceeds configured limit");
    const digest = sha256(bytes);
    const storageKey = `${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest}`;
    const destination = this.safePath(storageKey);
    this.ensureDirectory(join(this.root, digest.slice(0, 2)));
    this.ensureDirectory(join(this.root, digest.slice(0, 2), digest.slice(2, 4)));
    let deduplicated = false;
    if (existsSync(destination)) {
      if (lstatSync(destination).isSymbolicLink()) throw new Error("Artifact destination cannot be a symlink");
      if (sha256(readFileSync(destination)) !== digest) throw new Error("Artifact integrity mismatch at content address");
      deduplicated = true;
    } else {
      const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
      try {
        writeFileSync(temporary, bytes, { flag: "wx" });
        if (existsSync(destination)) {
          unlinkSync(temporary);
          deduplicated = true;
        } else {
          renameSync(temporary, destination);
        }
      } catch (error) {
        try { if (existsSync(temporary)) unlinkSync(temporary); } catch { /* best effort */ }
        throw error;
      }
    }
    return {
      artifact_id: this.ids.next("artifact"),
      content_hash: `sha256:${digest}`,
      media_type: parsed.media_type,
      size_bytes: bytes.byteLength,
      classification: parsed.classification,
      retention_policy: parsed.retention_policy,
      created_by: parsed.created_by,
      storage_key: storageKey,
      deduplicated,
    };
  }

  get(input: ArtifactRef): Uint8Array {
    const ref = artifactRefSchema.parse(input);
    const digest = ref.content_hash.slice("sha256:".length);
    const expectedKey = `${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest}`;
    if (ref.storage_key !== expectedKey) throw new Error("Artifact reference path does not match its hash");
    const path = this.safePath(ref.storage_key);
    if (!existsSync(path)) throw new Error("Artifact content is missing");
    if (lstatSync(path).isSymbolicLink()) throw new Error("Artifact content cannot be a symlink");
    const actualPath = realpathSync.native(path);
    const rootPrefix = this.root.endsWith(sep) ? this.root : `${this.root}${sep}`;
    if (!comparablePath(actualPath).startsWith(comparablePath(rootPrefix))) {
      throw new Error("Artifact content resolves outside the allowed root");
    }
    if (!lstatSync(actualPath).isFile()) throw new Error("Artifact content must be a regular file");
    return readFileSync(actualPath);
  }

  verify(ref: ArtifactRef): IntegrityResult {
    try {
      const content = this.get(ref);
      return sha256(content) === ref.content_hash.slice("sha256:".length)
        ? { valid: true, content_hash: ref.content_hash }
        : { valid: false, content_hash: ref.content_hash, reason: "hash-mismatch" };
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      return {
        valid: false,
        content_hash: ref.content_hash,
        reason: message.includes("missing") ? "missing" : "unsafe-path",
      };
    }
  }

  findOrphans(knownContentHashes: ReadonlySet<string>): string[] {
    const orphans: string[] = [];
    for (const first of readdirSync(this.root, { withFileTypes: true })) {
      if (!first.isDirectory() || first.isSymbolicLink() || !/^[a-f0-9]{2}$/.test(first.name)) continue;
      const firstPath = join(this.root, first.name);
      for (const second of readdirSync(firstPath, { withFileTypes: true })) {
        if (!second.isDirectory() || second.isSymbolicLink() || !/^[a-f0-9]{2}$/.test(second.name)) continue;
        const secondPath = join(firstPath, second.name);
        for (const file of readdirSync(secondPath, { withFileTypes: true })) {
          if (!file.isFile() || !/^[a-f0-9]{64}$/.test(file.name)) continue;
          const hash = `sha256:${file.name}`;
          if (!knownContentHashes.has(hash)) orphans.push(hash);
        }
      }
    }
    return orphans.sort();
  }

  private ensureDirectory(path: string): void {
    if (existsSync(path)) {
      const stats = lstatSync(path);
      if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Artifact path segment is unsafe");
      return;
    }
    mkdirSync(path);
  }

  private safePath(storageKey: string): string {
    const candidate = resolve(this.root, ...storageKey.split("/"));
    const rootPrefix = this.root.endsWith(sep) ? this.root : `${this.root}${sep}`;
    if (!comparablePath(candidate).startsWith(comparablePath(rootPrefix))) {
      throw new Error("Artifact path escapes the allowed root");
    }
    return candidate;
  }
}
