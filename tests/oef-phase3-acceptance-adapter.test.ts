import { afterEach, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Phase3AcceptanceRuntimeAdapter } from "../src/oef/phase3";
import { buildDeterministicReviewResult } from "../src/oef/phase3/acceptance/review-worker";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });
function repository(): string {
  const root = mkdtempSync(join(tmpdir(), "oef-p3-adapter-")); roots.push(root);
  mkdirSync(join(root, "src", "providers", "clinepass"), { recursive: true });
  mkdirSync(join(root, "tests", "providers", "clinepass"), { recursive: true });
  writeFileSync(join(root, "src", "providers", "clinepass", "error-classifier.ts"), [
    "export function classifyStatus(status: number): string {",
    "  if (status === 401 || status === 403) return 'auth-failure';",
    "  return 'other';",
    "}",
    "",
  ].join("\n"), "utf8");
  writeFileSync(join(root, "tests", "providers", "clinepass", "error-classifier.test.ts"), "baseline\n", "utf8");
  return root;
}

function request(workspace: string) {
  return {
    execution_id: "execution:adapter-test",
    attempt_id: "attempt:adapter-test",
    assignment_id: "assignment:adapter-test",
    assignment_revision: 1,
    workspace_id: "workspace:adapter-test",
    workspace_path: workspace,
    context_bundle_path: join(workspace, "context.json"),
    rendered_prompt_path: join(workspace, "prompt.txt"),
    inherited_environment: ["PATH"],
    injected_secret_refs: [],
    timeouts: { startup_seconds: 10, idle_seconds: 10, tool_seconds: 10, total_seconds: 30, graceful_shutdown_seconds: 1 },
    output_limit_bytes: 1_000_000,
    prompt_hash: `sha256:${"a".repeat(64)}`,
  } as const;
}

describe("Phase 3 acceptance runtime adapter", () => {
  test("creates the demonstrable 403 regression while adding correct 429 handling", async () => {
    const root = repository();
    const plan = await new Phase3AcceptanceRuntimeAdapter("initial").prepareLaunch(request(root));
    const result = Bun.spawnSync([plan.executable, ...plan.arguments], { cwd: plan.working_directory, stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode).toBe(0);
    const source = readFileSync(join(root, "src", "providers", "clinepass", "error-classifier.ts"), "utf8");
    const tests = readFileSync(join(root, "tests", "providers", "clinepass", "error-classifier.test.ts"), "utf8");
    expect(source).toContain("status === 429 || status === 403");
    expect(tests).toContain("403 is treated as rate limit (regression)");
    expect(tests).toContain("429 is a rate limit");
  });

  test("repairs 401/403 classification, preserves 429, and adds explicit regression tests", async () => {
    const root = repository();
    const initial = await new Phase3AcceptanceRuntimeAdapter("initial").prepareLaunch(request(root));
    expect(Bun.spawnSync([initial.executable, ...initial.arguments], { cwd: root }).exitCode).toBe(0);
    const repair = await new Phase3AcceptanceRuntimeAdapter("repair").prepareLaunch({ ...request(root), execution_id: "execution:repair", attempt_id: "attempt:repair" });
    expect(Bun.spawnSync([repair.executable, ...repair.arguments], { cwd: root }).exitCode).toBe(0);
    const source = readFileSync(join(root, "src", "providers", "clinepass", "error-classifier.ts"), "utf8");
    const tests = readFileSync(join(root, "tests", "providers", "clinepass", "error-classifier.test.ts"), "utf8");
    expect(source).toContain("status === 429");
    expect(source).toContain("status === 401 || status === 403");
    expect(tests).toContain("401 remains an auth failure");
    expect(tests).toContain("403 remains an auth failure");
    expect(tests).toContain("429 is a rate limit");
  });

  test("review worker derives its finding and PASS from the mounted source contents", async () => {
    const root = repository();
    const initial = await new Phase3AcceptanceRuntimeAdapter("initial").prepareLaunch(request(root));
    expect(Bun.spawnSync([initial.executable, ...initial.arguments], { cwd: root }).exitCode).toBe(0);
    const findingResult = buildDeterministicReviewResult({
      source_root: root,
      review_unit_id: "review-unit:dynamic-initial",
      snapshot_hash: `sha256:${"b".repeat(64)}`,
      review_type: "opencodex.spec-compliance",
    });
    expect(findingResult.decision.recommendation).toBe("changes-requested");
    expect(findingResult.findings).toHaveLength(1);
    expect(findingResult.findings[0]?.claim).toContain("HTTP 403");

    const repair = await new Phase3AcceptanceRuntimeAdapter("repair").prepareLaunch({
      ...request(root), execution_id: "execution:dynamic-repair", attempt_id: "attempt:dynamic-repair",
    });
    expect(Bun.spawnSync([repair.executable, ...repair.arguments], { cwd: root }).exitCode).toBe(0);
    const passResult = buildDeterministicReviewResult({
      source_root: root,
      review_unit_id: "review-unit:dynamic-repair",
      snapshot_hash: `sha256:${"c".repeat(64)}`,
      review_type: "opencodex.spec-compliance",
    });
    expect(passResult.decision.recommendation).toBe("pass");
    expect(passResult.findings).toHaveLength(0);
  });
});
