import { describe, expect, test } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const root = join(import.meta.dir, "..");

describe("Phase 7 workflow and documentation contract", () => {
  test("pins actions and publishes byte-identical commit-bound acceptance evidence", () => {
    const path = join(root, ".github", "workflows", "phase7-foundation.yml");
    expect(existsSync(path)).toBe(true);
    if (!existsSync(path)) return;
    const workflow = readFileSync(path, "utf8");
    expect(workflow).toContain("actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0");
    expect(workflow).toContain("oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6");
    expect(workflow).toContain("actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a");
    expect(workflow).toContain("bun run typecheck");
    expect(workflow).toContain("bun run privacy:scan");
    expect(workflow).toContain("tests/oef-phase7-*.test.ts");
    expect(workflow.split("incident demo --root .artifacts/phase7 --commit-sha \"$GITHUB_SHA\" --json").length - 1).toBe(2);
    expect(workflow).toContain("cmp .artifacts/phase7/run-1.json .artifacts/phase7/run-2.json");
    expect(workflow).toContain("sha256sum -c SHA256SUMS");
    expect(workflow).toContain("phase7-evidence-${{ github.sha }}");
    expect(workflow).not.toMatch(/uses:\s+\S+@(?:v\d+|main|master)\b/);
  });

  test("documents the foundation boundary and deferred full Phase 7 increments", () => {
    const architecture = join(root, "docs", "architecture", "phase-7-incident-intelligence-scope.md");
    expect(existsSync(architecture)).toBe(true);
    if (!existsSync(architecture)) return;
    const docs = readFileSync(architecture, "utf8");
    for (const phrase of ["foundation", "shared outbox collectors", "real sandbox fleet", "bounded web research", "multi-agent critic", "Phase 2 repair assignment", "Phase 3 live review", "plugin backends", "advanced correlation", "property", "fault-injection", "metrics", "full CLI surface"]) expect(docs.toLowerCase()).toContain(phrase.toLowerCase());
    expect(docs).toContain("does not perform a production repair or deployment");
  });
});
