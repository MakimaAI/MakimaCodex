import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join, relative } from "node:path";

const root = join(import.meta.dir, "..");
const read = (path: string) => readFileSync(join(root, path), "utf8");

describe("Phase 1 architecture boundaries", () => {
  test("keeps core free of persistence, filesystem, CLI, provider, and model routing dependencies", async () => {
    const coreFiles: string[] = [];
    for await (const path of new Bun.Glob("src/oef/phase1/core/**/*.ts").scan({ cwd: root, absolute: true })) {
      coreFiles.push(path);
    }
    expect(coreFiles.length).toBeGreaterThan(8);
    for (const file of coreFiles) {
      const source = readFileSync(file, "utf8");
      expect(source, relative(root, file)).not.toMatch(/from ["'](?:bun:sqlite|node:fs|node:http|\.\.\/\.\.\/cli)/);
      expect(source, relative(root, file)).not.toMatch(/if\s*\(.*(?:gemini|kimi|claude|openai|codex)/i);
    }
    for (const file of [
      join(root, "src", "oef", "phase1", "application", "commands", "command-bus.ts"),
      join(root, "src", "oef", "phase1", "application", "queries", "integrity.ts"),
    ]) {
      expect(readFileSync(file, "utf8"), relative(root, file)).not.toContain("persistence/sqlite-store");
    }
  });

  test("ships parseable versioned workflows, policies, and public JSON schemas", async () => {
    const dataFiles: string[] = [];
    for (const pattern of ["workflows/*.json", "policies/*.json", "schemas/oef/*.json"]) {
      for await (const path of new Bun.Glob(pattern).scan({ cwd: root, absolute: true })) dataFiles.push(path);
    }
    expect(dataFiles.length).toBeGreaterThanOrEqual(10);
    for (const file of dataFiles) {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
      if (file.endsWith(".schema.json")) {
        expect(parsed, relative(root, file)).toHaveProperty("$schema");
        expect(String(parsed.$id), relative(root, file)).toContain("-v1.schema.json");
        expect(parsed, relative(root, file)).toHaveProperty("properties");
      } else {
        expect(parsed, relative(root, file)).toHaveProperty("schema_version");
      }
    }
    const packageJson = JSON.parse(read("package.json")) as { files: string[] };
    expect(packageJson.files).toEqual(expect.arrayContaining(["src", "workflows", "policies", "schemas"]));
  });

  test("contains every required architecture and ADR artifact", () => {
    const architecture = [
      "phase-1-scope.md",
      "task-domain.md",
      "contract-versioning.md",
      "workflow-engine.md",
      "policy-engine.md",
      "events-vs-traces.md",
      "evidence-model.md",
      "artifact-store.md",
      "persistence.md",
      "schema-evolution.md",
      "security-boundaries.md",
      "extension-points.md",
      "phase-1-acceptance-matrix.md",
    ];
    const adrs = [
      "ADR-001-hybrid-state-and-events.md",
      "ADR-002-versioned-workflows.md",
      "ADR-003-versioned-policy-packs.md",
      "ADR-004-content-addressed-artifacts.md",
      "ADR-005-command-idempotency.md",
      "ADR-006-no-vendor-dependency-in-core.md",
      "ADR-007-namespaced-extensions.md",
    ];
    for (const file of architecture) expect(read(`docs/architecture/${file}`).length, file).toBeGreaterThan(200);
    for (const file of adrs) expect(read(`docs/architecture/adr/${file}`).length, file).toBeGreaterThan(200);
    expect(read("docs/architecture/phase-1-scope.md")).toContain("## Excluded");
  });
});
