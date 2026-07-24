import { afterEach, describe, expect, test } from "bun:test";
import {
  mkdirSync,
  mkdtempSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  LocalArtifactStore,
  createSortableIdGenerator,
} from "../src/oef/phase1";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows may retain a failed symlink fixture briefly */ }
  }
});

const newRoot = (): string => {
  const root = mkdtempSync(join(tmpdir(), "oef-phase1-artifacts-"));
  roots.push(root);
  return root;
};

const ids = () => createSortableIdGenerator({
  now: () => 1_700_000_000_000,
  randomBytes: size => new Uint8Array(size).fill(3),
});

const producer = { type: "system", id: "system:test-runner" } as const;

describe("Phase 1 local artifact store", () => {
  test("stores by content hash and deduplicates physical content", () => {
    const root = join(newRoot(), "artifacts");
    const store = new LocalArtifactStore({ root, ids: ids(), maxBytes: 1_024 });
    const input = {
      content: new TextEncoder().encode('{"passed":true}'),
      media_type: "application/json",
      classification: "internal" as const,
      retention_policy: "task-lifetime",
      created_by: producer,
    };

    const first = store.put(input);
    const second = store.put(input);

    expect(first.content_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(first.storage_key).toMatch(/^[a-f0-9]{2}\/[a-f0-9]{2}\/[a-f0-9]{64}$/);
    expect(first.deduplicated).toBe(false);
    expect(second).toMatchObject({
      content_hash: first.content_hash,
      storage_key: first.storage_key,
      deduplicated: true,
    });
    expect(second.artifact_id).not.toBe(first.artifact_id);
    expect(new TextDecoder().decode(store.get(first))).toBe('{"passed":true}');
    expect(store.verify(first)).toEqual({ valid: true, content_hash: first.content_hash });
  });

  test("detects tampering and reports unregistered orphan content", () => {
    const root = join(newRoot(), "artifacts");
    const store = new LocalArtifactStore({ root, ids: ids() });
    const ref = store.put({
      content: "clean test result",
      media_type: "text/plain",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: producer,
    });
    writeFileSync(join(root, ...ref.storage_key.split("/")), "tampered", "utf8");

    expect(store.verify(ref)).toEqual({
      valid: false,
      content_hash: ref.content_hash,
      reason: "hash-mismatch",
    });
    expect(store.findOrphans(new Set())).toEqual([ref.content_hash]);
    expect(store.findOrphans(new Set([ref.content_hash]))).toEqual([]);
  });

  test("rejects secret content, secret classification, oversized data, and path-shaped input", () => {
    const root = join(newRoot(), "artifacts");
    const store = new LocalArtifactStore({ root, ids: ids(), maxBytes: 16 });
    const base = {
      media_type: "text/plain",
      classification: "internal" as const,
      retention_policy: "task-lifetime",
      created_by: producer,
    };

    expect(() => store.put({ ...base, content: "api_key=abcdefghijklmnop" })).toThrow("secret");
    expect(() => store.put({ ...base, content: "safe", classification: "secret" })).toThrow("secret");
    expect(() => store.put({ ...base, content: "x".repeat(17) })).toThrow("size");
    expect(() => store.put({ ...base, content: "safe", path: "../../outside" } as never)).toThrow();
    expect(() => store.get({ ...base, artifact_id: "artifact:x", content_hash: "sha256:../../outside", storage_key: "../../outside", size_bytes: 1 } as never)).toThrow();
  });

  test("refuses a symlinked artifact root instead of escaping the allowed directory", () => {
    const parent = newRoot();
    const target = join(parent, "outside");
    const linkedRoot = join(parent, "artifacts");
    mkdirSync(target);
    symlinkSync(target, linkedRoot, "junction");

    expect(() => new LocalArtifactStore({ root: linkedRoot, ids: ids() })).toThrow("symlink");
  });

  test("revalidates parent path segments before reading an artifact", () => {
    const parent = newRoot();
    const root = join(parent, "artifacts");
    const store = new LocalArtifactStore({ root, ids: ids() });
    const ref = store.put({
      content: "junction-safe-content",
      media_type: "text/plain",
      classification: "internal",
      retention_policy: "task-lifetime",
      created_by: producer,
    });
    const [first, second, digest] = ref.storage_key.split("/");
    const external = join(parent, "outside");
    mkdirSync(join(external, second), { recursive: true });
    writeFileSync(join(external, second, digest), "junction-safe-content", "utf8");
    rmSync(join(root, first), { recursive: true, force: true });
    symlinkSync(external, join(root, first), process.platform === "win32" ? "junction" : "dir");

    expect(() => store.get(ref)).toThrow("outside");
    expect(store.verify(ref)).toMatchObject({ valid: false, reason: "unsafe-path" });
  });
});
