import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

function files(root: string): string[] {
  return readdirSync(root).flatMap(name => { const path = join(root, name); return statSync(path).isDirectory() ? files(path) : [path]; });
}

describe("Phase 5 architecture boundaries", () => {
  test("documents the six separate responsibilities and trust boundaries", () => {
    const document = readFileSync(join(import.meta.dir, "..", "docs", "architecture", "phase-5-routing-and-team-composition.md"), "utf8");
    for (const phrase of ["Task analysis", "Team composition", "Candidate selection", "Execution binding", "Account selection", "Execution", "Trust boundaries", "Human escalation conditions"]) expect(document).toContain(phrase);
  });

  test("does not read secrets or launch agent processes inside the routing layer", () => {
    const root = join(import.meta.dir, "..", "src", "oef", "phase5");
    const source = files(root).map(path => readFileSync(path, "utf8")).join("\n");
    expect(source).not.toContain("process.env");
    expect(source).not.toContain("Bun.spawn");
    expect(source).not.toContain("node:child_process");
    expect(source).not.toContain("readFileSync");
  });

  test("keeps Phase 4 integration read-only and Phase 2 execution behind an adapter", () => {
    const candidateAdapter = readFileSync(join(import.meta.dir, "..", "src", "oef", "phase5", "adapters", "phase4-candidate-provider.ts"), "utf8");
    const bindingAdapter = readFileSync(join(import.meta.dir, "..", "src", "oef", "phase5", "adapters", "phase2-binding-adapter.ts"), "utf8");
    expect(candidateAdapter).toContain("Phase4CandidateReadPort");
    expect(candidateAdapter).not.toContain("saveScorecard(");
    expect(bindingAdapter).toContain("executionBindingSchema.parse");
  });
});
