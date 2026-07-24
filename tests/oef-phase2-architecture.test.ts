import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { runnerClientFromHome } from "../src/oef/phase2";

const repo = join(import.meta.dir, "..");
const phase2 = join(repo, "src", "oef", "phase2");

function sourceFiles(root: string): string[] {
  return readdirSync(root, { withFileTypes: true }).flatMap(entry => {
    const path = join(root, entry.name);
    return entry.isDirectory() ? sourceFiles(path) : entry.name.endsWith(".ts") ? [path] : [];
  });
}

describe("Phase 2 architecture and public surface", () => {
  test("keeps domain, adapters, and runner on their assigned side of process and persistence boundaries", () => {
    for (const path of sourceFiles(join(phase2, "core"))) {
      const source = readFileSync(path, "utf8");
      expect(source, path).not.toMatch(/bun:sqlite|node:child_process|Bun\.spawn|CodexRuntimeAdapter|Claude|OpenAI/);
    }
    for (const path of sourceFiles(join(phase2, "runtime", "adapters"))) {
      if (path.endsWith("fake-worker.ts")) continue;
      const source = readFileSync(path, "utf8");
      expect(source, path).not.toMatch(/bun:sqlite|Database\b|node:child_process|Bun\.spawn|SqliteOefStore|Phase2CommandBus/);
    }
    for (const path of sourceFiles(join(phase2, "runner"))) {
      const source = readFileSync(path, "utf8");
      expect(source, path).not.toMatch(/bun:sqlite|SqliteOefStore|Phase2CommandBus|OefCommandBus/);
    }
    for (const path of sourceFiles(phase2)) {
      const source = readFileSync(path, "utf8");
      expect(source, path).not.toMatch(/shell\s*:\s*true/);
    }
  });

  test("publishes every required CLI family and generated JSON schema", () => {
    const cli = readFileSync(join(repo, "src", "cli", "index.ts"), "utf8");
    for (const group of ["runtimes", "runner", "assignment", "execution", "workspace", "verify"]) {
      expect(cli).toContain(`case "${group}"`);
    }
    const schemas = readdirSync(join(repo, "schemas", "oef", "phase2")).filter(name => name.endsWith(".schema.json"));
    expect(schemas).toHaveLength(17);
    expect(JSON.parse(readFileSync(join(repo, "package.json"), "utf8")).files).toContain("schemas");
  });

  test("includes and starts the persistent runner daemon from an npm package path containing spaces", async () => {
    const workRoot = join(repo, "work");
    const temporary = mkdtempSync(join(workRoot, "phase2 package path with spaces "));
    const result = Bun.spawnSync(["npm", "pack", "--json", "--pack-destination", temporary], { cwd: repo, stdout: "pipe", stderr: "pipe" });
    expect(result.exitCode, new TextDecoder().decode(result.stderr)).toBe(0);
    const packs = JSON.parse(new TextDecoder().decode(result.stdout)) as Array<{ filename: string; files: Array<{ path: string }> }>;
    expect(packs[0]?.files.some(file => file.path.replaceAll("\\", "/") === "src/oef/phase2/runner/daemon-entry.ts")).toBeTrue();
    const archive = join(temporary, packs[0]!.filename);
    const extract = Bun.spawnSync(["tar", "-xf", archive, "-C", temporary], { cwd: repo, stdout: "pipe", stderr: "pipe" });
    expect(extract.exitCode, new TextDecoder().decode(extract.stderr)).toBe(0);
    const launcher = join(temporary, "package", "src", "oef", "phase2", "runner", "daemon-entry.ts");
    const home = join(temporary, "daemon home with spaces");
    const child = Bun.spawn([process.execPath, launcher, "--home", home], { cwd: temporary, stdin: "ignore", stdout: "ignore", stderr: "ignore", windowsHide: true });
    try {
      const deadline = Date.now() + 15_000;
      while (true) {
        try {
          const client = runnerClientFromHome(home);
          await client.getCapabilities();
          await client.shutdown();
          break;
        } catch {
          if (child.exitCode !== null) throw new Error(`packaged daemon exited early: ${child.exitCode}`);
          if (Date.now() >= deadline) throw new Error("packaged daemon did not become ready");
          await Bun.sleep(25);
        }
      }
      expect(await child.exited).toBe(0);
    } finally {
      if (child.exitCode === null) child.kill();
      await child.exited;
      rmSync(temporary, { recursive: true, force: true });
    }
  }, 30_000);

  test("documents architecture, threats, operations, decisions, and all 70 acceptance steps", () => {
    const required = [
      "docs/architecture/phase-2-safe-execution.md",
      "docs/architecture/phase-2-threat-model.md",
      "docs/architecture/phase-2-operations.md",
      "docs/architecture/phase-2-acceptance-matrix.md",
      "docs/adr/0010-oef-safe-single-agent-execution.md",
    ];
    for (const relative of required) expect(existsSync(join(repo, relative)), relative).toBeTrue();
    const matrix = readFileSync(join(repo, "docs", "architecture", "phase-2-acceptance-matrix.md"), "utf8");
    for (let step = 1; step <= 70; step += 1) expect(matrix, `Adım ${step}`).toContain(`| ${step} |`);
    for (const gate of ["Functional", "Security", "Resilience", "Reproducibility", "Quality"]) expect(matrix).toContain(`## ${gate}`);
    expect(matrix).toContain("tests/oef-phase2-e2e.test.ts");
    expect(matrix).toContain("scripts/oef-phase2-acceptance-demo.ts");
  });
});
