import { afterEach, describe, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPhase4AcceptanceDemo } from "../src/oef/phase4";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { try { rmSync(root, { recursive: true, force: true }); } catch { /* Bun may retain a closed WAL handle briefly on Windows. */ } } });

describe("Phase 4 acceptance demo", () => {
  test("evaluates three configurations, eliminates the incompatible candidate, and falls back after alias drift", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase4-demo-")); roots.push(root);
    const report = await runPhase4AcceptanceDemo({ root, now: () => "2026-07-24T08:00:00.000Z" });

    expect(report.status).toBe("PASS");
    expect(report.models_discovered).toBe(3);
    expect(report.runtime_protocol_probe.status).toBe("passed");
    expect(report.real_model_probe.status).toBe("not-run");
    expect(report.config_c_eliminated).toBeTrue();
    expect(report.quality_leader).toBe("execution-config:premium");
    expect(report.balanced_leader_before_drift).toBe("execution-config:balanced");
    expect(report.recommendation_after_drift).toBe("execution-config:balanced");
    expect(report.requalification_jobs).toBe(1);
    expect(report.audit_event_count).toBeGreaterThanOrEqual(20);
    expect(report.router_mutations).toBe(0);
    expect(report.secret_leaks).toBe(0);
    expect(report.hidden_holdout_leaks).toBe(0);
  });
});
