import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPhase2AcceptanceDemo } from "../src/oef/phase2";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* Windows can retain demo process handles briefly */ }
  }
});

describe("Phase 2 reusable acceptance demo", () => {
  test("runs deterministically with the fake runtime and writes a restart-readable report", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase2-acceptance-"));
    roots.push(root);
    const result = await runPhase2AcceptanceDemo({ root, runtime: "fake" });
    expect(result.report.result).toBe("READY_FOR_REVIEW");
    expect(result.report.steps).toHaveLength(23);
    expect(result.main_branch_unchanged).toBeTrue();
    expect(existsSync(result.report_path)).toBeTrue();
  }, 30_000);
});
