import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPhase7AcceptanceDemo } from "../src/oef/phase7";
import { PHASE7_COMMIT } from "./helpers/phase7-fixtures";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { try { rmSync(root, { recursive: true, force: true }); } catch { /* Bun SQLite can retain Windows test handles until process exit */ } } });

describe("Phase 7 foundation acceptance", () => {
  test("proves the 403-to-memory vertical slice twice with byte-identical SHA-bound evidence", async () => {
    const root = mkdtempSync(join(tmpdir(), "phase7-acceptance-")); roots.push(root);
    const first = await runPhase7AcceptanceDemo({ root, commitSha: PHASE7_COMMIT });
    const firstBytes = readFileSync(join(root, "phase7-demo-report.json"), "utf8");
    const second = await runPhase7AcceptanceDemo({ root, commitSha: PHASE7_COMMIT });
    const secondBytes = readFileSync(join(root, "phase7-demo-report.json"), "utf8");

    expect(first).toEqual(second);
    expect(firstBytes).toBe(secondBytes);
    expect(first).toMatchObject({
      status: "PASS",
      commit_sha: PHASE7_COMMIT,
      source: { phase: 2, http_status: 403, boundary: "STRUCTURED_FAILURE_AND_EXECUTION_MANIFEST" },
      incident: { severity: "HIGH", priority: "P1", closed: true, root_cause: "CONFIRMED" },
      containment: { state: "PROPOSED", production_action_performed: false },
      reproduction: { reproduced: 5, attempted: 5, adapter: "phase2-local-replay", production_access: false },
      experiment: { controlled: true, regression_before: "FAIL", regression_after: "PASS" },
      review: { independent: true, verdict: "APPROVED" },
      memory: { statuses: ["OBSERVED", "VERIFIED", "CANDIDATE"], count: 3 },
      repeated_signature: { matched: true, correlation: "POSSIBLE_DUPLICATE" },
      boundaries: { production_repair: false, production_deploy: false, web_research: false, active_skill_created: false },
    });
    expect(first.report_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});
