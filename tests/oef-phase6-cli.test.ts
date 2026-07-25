import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const roots: string[] = [];
afterAll(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

async function cli(args: string[]): Promise<{ exit: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, "src/cli/index.ts", ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...Bun.env, OPENCODEX_NO_UPDATE_CHECK: "1" },
  });
  const [stdout, stderr, exit] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { exit, stdout, stderr };
}

describe("Phase 6 CLI", () => {
  let root: string;
  let demo: Awaited<ReturnType<typeof cli>>;

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "phase6-cli-")); roots.push(root);
    demo = await cli(["oef-phase6-demo", "--root", root, "--json"]);
  }, 60_000);

  test("runs the lifecycle demo", () => {
    expect(demo.exit).toBe(0);
    expect(JSON.parse(demo.stdout)).toMatchObject({
      status: "PASS",
      verified_lesson_recalled: true,
      raw_evidence_injected: false,
      repeated_memory_injected: false,
      supersession_verified: true,
      ingestion_pipeline: { status: "COMPLETED", duplicate_effect: 0 },
      promotion_gate: { status: "PROMOTED" },
      vector_index: { status: "HEALTHY" },
      plugin_boundary: { untrusted: true, instruction_authority: "NONE" },
    });
  });

  test("exposes scoped search and explainability", async () => {
    const search = await cli([
      "memory", "search", "HTTP 403 authorization", "--scope", "repository:opencodex",
      "--scope", "provider:clinepass",
      "--role", "backend-implementer", "--home", root, "--json",
    ]);
    expect(search.exit).toBe(0);
    const pack = JSON.parse(search.stdout);
    expect(pack.sections.relevant_lessons[0].memory_id).toBe("memory:lesson-403");

    const explanation = await cli(["memory", "explain-query", pack.query_id, "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(explanation.exit).toBe(0);
    expect(JSON.parse(explanation.stdout).selected.length).toBeGreaterThan(0);
  }, 60_000);

  test("enforces direct record scope authorization", async () => {
    const shown = await cli(["memory", "show", "memory:lesson-403", "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(shown.exit).toBe(0);
    expect(JSON.parse(shown.stdout)).toMatchObject({ memory_id: "memory:lesson-403", revision_number: 2 });

    const deniedShow = await cli(["memory", "show", "memory:lesson-403", "--scope", "repository:opencodex", "--home", root, "--json"]);
    expect(deniedShow.exit).toBe(1);
    expect(deniedShow.stderr).toContain("MEMORY_SCOPE_ACCESS_DENIED");
  }, 60_000);

  test("exposes provenance and health", async () => {
    const provenance = await cli(["memory", "provenance", "memory:lesson-403", "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(provenance.exit).toBe(0);
    expect(JSON.parse(provenance.stdout).source_refs).toContain("evidence:test-403-v3");

    const health = await cli(["memory", "health", "--home", root, "--json"]);
    expect(health.exit).toBe(0);
    expect(JSON.parse(health.stdout)).toMatchObject({ canonical_store: "HEALTHY", lexical_index: "HEALTHY", vector_index: { status: "HEALTHY" } });
  }, 60_000);

  test("runs candidate, hygiene, re-embedding, and audit operations", async () => {
    const candidates = await cli(["memory", "candidates", "--status", "promoted", "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(candidates.exit).toBe(0);
    expect(JSON.parse(candidates.stdout)[0]).toMatchObject({ candidate_id: "memory-candidate:lesson-403", status: "PROMOTED" });

    const hygiene = await cli(["memory", "hygiene", "run", "--home", root, "--json"]);
    expect(hygiene.exit).toBe(0);
    expect(JSON.parse(hygiene.stdout).scanned).toBeGreaterThan(0);

    const profilePath = join(root, "embedding-profile.json");
    writeFileSync(profilePath, JSON.stringify({
      id: "memory-local-hash", version: "2.0.0", dimensions: 64,
      provider: "LOCAL_DETERMINISTIC", max_sensitivity: "CONFIDENTIAL",
    }));
    const reembed = await cli(["memory", "reembed", "--profile-file", profilePath, "--home", root, "--json"]);
    expect(reembed.exit).toBe(0);
    expect(JSON.parse(reembed.stdout)).toMatchObject({ profile: { version: "2.0.0" } });

    const audit = await cli(["memory", "audit", "--home", root, "--json"]);
    expect(audit.exit).toBe(0);
    expect(JSON.parse(audit.stdout)).toMatchObject({ status: "PASS", canonical_store: "HEALTHY", lexical_index: "HEALTHY" });
  }, 60_000);

  test("creates and restores a hash-bound backup", async () => {
    const backupRoot = join(root, "backups");
    const backup = await cli(["memory", "backup", "--output", backupRoot, "--home", root,
      "--artifact-root", root, "--artifact-manifest", join(root, "phase6-artifact-manifest.json"), "--json"]);
    expect(backup.exit).toBe(0);
    const backupResult = JSON.parse(backup.stdout);
    expect(backupResult.manifest.database_hash).toMatch(/^sha256:/);
    const restoredHome = join(root, "restored");
    const restore = await cli(["memory", "restore", "--backup", backupResult.directory, "--target-home", restoredHome, "--home", root, "--json"]);
    expect(restore.exit).toBe(0);
    expect(JSON.parse(restore.stdout)).toMatchObject({ restored: true, lexical_rebuilt: true });
  }, 60_000);

  test("advertises the Memory OS commands in top-level help", async () => {
    const result = await cli(["--help"]);
    expect(result.exit).toBe(0);
    expect(result.stdout).toContain("ocx memory <sub>");
  }, 60_000);
});
