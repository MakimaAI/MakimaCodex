import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

async function cli(args: string[]): Promise<{ exit: number; stdout: string; stderr: string }> {
  const child = Bun.spawn([process.execPath, "src/cli/index.ts", ...args], { stdout: "pipe", stderr: "pipe", env: { ...Bun.env, OPENCODEX_NO_UPDATE_CHECK: "1" } });
  const [stdout, stderr, exit] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
  return { exit, stdout, stderr };
}

describe("Phase 5 CLI", () => {
  test("persists fingerprint and team commands with machine-readable output", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase5-cli-")); roots.push(root);
    const fingerprint = await cli(["route", "fingerprint", "task-cli", "--objective", "TypeScript backend düzeltmesi yap", "--home", root, "--json"]);
    expect(fingerprint.exit).toBe(0);
    const fingerprintValue = JSON.parse(fingerprint.stdout);
    expect(fingerprintValue.task_id).toBe("task:task-cli");

    const shown = await cli(["route", "fingerprint", "show", "task-cli", "--home", root, "--json"]);
    expect(shown.exit).toBe(0);
    expect(JSON.parse(shown.stdout).fingerprint_hash).toBe(fingerprintValue.fingerprint_hash);

    const restricted = await cli(["route", "fingerprint", "task-cli", "--objective", "TypeScript backend düzeltmesi yap", "--privacy", "restricted", "--home", root, "--json"]);
    expect(restricted.exit).toBe(0);
    expect(JSON.parse(restricted.stdout)).toMatchObject({ revision: 2, privacy: "restricted" });

    const composed = await cli(["team", "compose", "task-cli", "--home", root, "--json"]);
    expect(composed.exit).toBe(0);
    expect(JSON.parse(composed.stdout).nodes.map((value: { role_id: string }) => value.role_id)).toContain("backend-implementer");

    const unsafeCandidates = await cli(["route", "candidates", "--task", "task-cli", "--role", "backend-implementer", "--home", root, "--json"]);
    expect(unsafeCandidates.exit).toBe(1);
    expect(unsafeCandidates.stderr).toContain("Missing required option --availability-file");
  });

  test("runs the full demo through the public CLI", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase5-cli-demo-")); roots.push(root);
    const result = await cli(["oef-phase5-demo", "--root", root, "--json"]);
    expect(result.exit).toBe(0);
    expect(JSON.parse(result.stdout)).toMatchObject({ status: "PASS", replay_match: true, routing_policy_mutations: 0 });
  });

  test("advertises route and team surfaces in top-level help", async () => {
    const result = await cli(["--help"]);
    expect(result.exit).toBe(0);
    expect(result.stdout).toContain("ocx route <sub>");
    expect(result.stdout).toContain("ocx team <sub>");
  });
});
