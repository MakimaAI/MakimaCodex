import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PHASE7_COMMIT } from "./helpers/phase7-fixtures";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
async function cli(args: string[]): Promise<{ exit: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, "src/cli/index.ts", ...args], { stdout: "pipe", stderr: "pipe", env: { ...Bun.env, OPENCODEX_NO_UPDATE_CHECK: "1" } });
  const [stdout, stderr, exit] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { exit, stdout, stderr };
}

describe("Phase 7 CLI", () => {
  test("runs deterministic JSON demo and exposes registry read commands", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase7-cli-")); roots.push(root);
    const demo = await cli(["incident", "demo", "--root", root, "--commit-sha", PHASE7_COMMIT, "--json"]);
    expect(demo.exit).toBe(0);
    const report = JSON.parse(demo.stdout);
    expect(report).toMatchObject({ status: "PASS", commit_sha: PHASE7_COMMIT });

    const listed = await cli(["incident", "list", "--scope", "repository:repo:makima", "--home", root, "--json"]);
    expect(listed.exit).toBe(0);
    expect(JSON.parse(listed.stdout).length).toBeGreaterThanOrEqual(2);
    const incidentId = report.incident.incident_id;
    for (const command of ["show", "timeline", "provenance", "explain"] as const) {
      const result = await cli(["incident", command, incidentId, "--home", root, "--json"]);
      expect(result.exit, `${command}: ${result.stderr}`).toBe(0);
      expect(JSON.parse(result.stdout).incident_id ?? incidentId).toBe(incidentId);
    }
    const health = await cli(["incident", "health", "--home", root, "--json"]);
    expect(health.exit).toBe(0);
    expect(JSON.parse(health.stdout)).toMatchObject({ status: "HEALTHY", journal_mode: "wal" });
  });

  test("fails unsupported full-phase commands explicitly as JSON", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase7-cli-unsupported-")); roots.push(root);
    const result = await cli(["incident", "research", "--home", root, "--json"]);
    expect(result.exit).toBe(1);
    expect(JSON.parse(result.stderr)).toMatchObject({ error: "PHASE7_FOUNDATION_COMMAND_UNSUPPORTED", command: "research" });
  });

  test("advertises incident intelligence in top-level help", async () => {
    const result = await cli(["--help"]);
    expect(result.exit).toBe(0);
    expect(result.stdout).toContain("ocx incident <sub>");
  });
});
