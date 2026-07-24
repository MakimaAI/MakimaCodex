import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { cmdOefPhase4 } from "../src/cli/oef-phase4";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows WAL delay */ } } });

describe("Phase 4 CLI", () => {
  test("runs the demo then exposes models, benchmark suites, scorecards, and recommendations as JSON", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase4-cli-")); roots.push(root);
    const demo = await invoke("oef-phase4-demo", ["--root", root, "--json"]);
    expect(demo.code).toBe(0);
    expect((demo.value as { status: string }).status).toBe("PASS");
    const models = await invoke("models", ["list", "--home", root, "--json"]);
    expect(models.code).toBe(0);
    expect((models.value as unknown[])).toHaveLength(4);
    const suites = await invoke("benchmark", ["list", "--home", root, "--json"]);
    expect((suites.value as unknown[]).length).toBeGreaterThanOrEqual(2);
    const suite = await invoke("benchmark", ["show", "benchmark-suite:backend-full@1.0.0", "--home", root, "--json"]);
    const publicText = JSON.stringify(suite.value);
    expect(publicText).not.toContain("hidden_assertions");
    expect(publicText).not.toContain("expected_answer_hash");
    expect(publicText).not.toContain("solution marker");
    const recommendation = await invoke("models", ["recommend", "--role", "backend-implementer", "--profile", "balanced", "--home", root, "--json"]);
    expect(recommendation.value).toMatchObject({ selected: { execution_config_ref: { id: "execution-config:balanced" } } });
    const modelHelp = await invoke("models", ["help", "--home", root, "--json"]);
    expect((modelHelp.value as { commands: string[] }).commands).toContain("quarantine");
    const benchmarkHelp = await invoke("benchmark", ["help", "--home", root, "--json"]);
    expect((benchmarkHelp.value as { commands: string[] }).commands).toContain("run");
    const quarantine = await invoke("models", ["quarantine", "execution-config:balanced", "--reason", "protocol incident", "--home", root, "--json"]);
    expect(quarantine.value).toMatchObject({ status: "QUARANTINED", production_activation: false });
    const excluded = await invoke("models", ["recommend", "--role", "backend-implementer", "--profile", "balanced", "--home", root, "--json"]);
    expect(excluded.value).toMatchObject({ selected: null });
  });
});

async function invoke(group: string, args: string[]): Promise<{ code: number; value: unknown }> {
  const output: string[] = []; const errors: string[] = [];
  const originalLog = console.log; const originalError = console.error;
  console.log = (...values: unknown[]) => output.push(values.map(String).join(" "));
  console.error = (...values: unknown[]) => errors.push(values.map(String).join(" "));
  try {
    const code = await cmdOefPhase4(group, args);
    if (code !== 0) throw new Error(errors.join("\n"));
    return { code, value: JSON.parse(output.join("\n")) };
  } finally { console.log = originalLog; console.error = originalError; }
}
