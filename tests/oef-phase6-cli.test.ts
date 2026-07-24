import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

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
  test("runs the lifecycle demo and exposes search, provenance, health, and explainability", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-cli-")); roots.push(root);
    const demo = await cli(["oef-phase6-demo", "--root", root, "--json"]);
    expect(demo.exit).toBe(0);
    expect(JSON.parse(demo.stdout)).toMatchObject({
      status: "PASS",
      verified_lesson_recalled: true,
      raw_evidence_injected: false,
      repeated_memory_injected: false,
      supersession_verified: true,
    });

    const search = await cli([
      "memory", "search", "HTTP 403 authorization", "--scope", "repository:opencodex",
      "--scope", "provider:clinepass",
      "--role", "backend-implementer", "--home", root, "--json",
    ]);
    expect(search.exit).toBe(0);
    const pack = JSON.parse(search.stdout);
    expect(pack.sections.relevant_lessons[0].memory_id).toBe("memory:lesson-403");

    const shown = await cli(["memory", "show", "memory:lesson-403", "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(shown.exit).toBe(0);
    expect(JSON.parse(shown.stdout)).toMatchObject({ memory_id: "memory:lesson-403", revision_number: 2 });

    const deniedShow = await cli(["memory", "show", "memory:lesson-403", "--scope", "repository:opencodex", "--home", root, "--json"]);
    expect(deniedShow.exit).toBe(1);
    expect(deniedShow.stderr).toContain("MEMORY_SCOPE_ACCESS_DENIED");

    const provenance = await cli(["memory", "provenance", "memory:lesson-403", "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(provenance.exit).toBe(0);
    expect(JSON.parse(provenance.stdout).source_refs).toContain("evidence:test-403-v3");

    const health = await cli(["memory", "health", "--home", root, "--json"]);
    expect(health.exit).toBe(0);
    expect(JSON.parse(health.stdout)).toMatchObject({ canonical_store: "HEALTHY", lexical_index: "HEALTHY" });

    const explanation = await cli(["memory", "explain-query", pack.query_id, "--scope", "repository:opencodex", "--scope", "provider:clinepass", "--home", root, "--json"]);
    expect(explanation.exit).toBe(0);
    expect(JSON.parse(explanation.stdout).selected.length).toBeGreaterThan(0);
  });

  test("advertises the Memory OS commands in top-level help", async () => {
    const result = await cli(["--help"]);
    expect(result.exit).toBe(0);
    expect(result.stdout).toContain("ocx memory <sub>");
  });
});
