import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runPhase3AcceptanceDemo } from "../src/oef/phase3";

const roots: string[] = [];
const reviewSandboxImage = "mcr.microsoft.com/playwright@sha256:57b65fdc9ceabe0ef613124c7bbe2babcf9362c4d85e382fe3b03604e84b428a";
const dockerDaemonAvailable = Bun.spawnSync(["docker", "info", "--format", "{{.ServerVersion}}"], {
  stdout: "ignore",
  stderr: "ignore",
}).success;
const dockerAvailable = dockerDaemonAvailable && Bun.spawnSync(["docker", "image", "inspect", reviewSandboxImage], {
  stdout: "ignore",
  stderr: "ignore",
}).success;
afterEach(async () => {
  for (const root of roots.splice(0)) {
    for (let attempt = 0; attempt < 40 && existsSync(root); attempt += 1) {
      try { rmSync(root, { recursive: true, force: true }); }
      catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EBUSY" || attempt === 39) throw error;
        await Bun.sleep(50);
      }
    }
  }
});

describe("Phase 3 end-to-end acceptance demo", () => {
  test.skipIf(!dockerAvailable)("finds the 403 regression, repairs it through Phase 2, delta-reviews, and issues Phase 1 ACCEPT", async () => {
    const root = mkdtempSync(join(tmpdir(), "oef-phase3-acceptance-"));
    roots.push(root);
    const result = await runPhase3AcceptanceDemo({ root: join(root, "run") });

    expect(result.steps).toHaveLength(22);
    expect(result.steps[6]).toBe("three-independent-reviewer-sessions-completed");
    expect(result.initial_execution.result).toBe("READY_FOR_REVIEW");
    expect(result.initial_review.reviewers).toHaveLength(3);
    expect(result.initial_review.isolation_attestations).toHaveLength(3);
    expect(result.initial_review.identity_attestations).toHaveLength(3);
    expect(result.initial_review.identity_attestations.every(attestation =>
      attestation.attested_by === "phase2-runner-host"
      && attestation.attestation_algorithm === "Ed25519"
      && attestation.output_hash.startsWith("sha256:")
    )).toBeTrue();
    expect(result.initial_review.isolation_attestations.every(attestation =>
      attestation.provider === "docker"
      && attestation.network === "none"
      && attestation.root_filesystem === "read-only"
      && attestation.credentials === "not-mounted"
      && attestation.image_digest === "sha256:57b65fdc9ceabe0ef613124c7bbe2babcf9362c4d85e382fe3b03604e84b428a"
    )).toBeTrue();
    expect(result.initial_review.sandbox_probes).toHaveLength(3);
    expect(result.initial_review.sandbox_probes.every(probe =>
      probe.network_denied === true && probe.host_credentials_unmounted === true
    )).toBeTrue();
    expect(new Set(result.initial_review.reviewers.map(item => item.session_id)).size).toBe(3);
    expect(result.initial_review.decision).toBe("CHANGES_REQUESTED");
    expect(result.initial_review.finding_groups).toHaveLength(1);
    expect(result.initial_review.finding_groups[0]?.members).toHaveLength(2);
    expect(result.repair.proposal.target_findings).toHaveLength(1);
    expect(result.repair.execution.result).toBe("READY_FOR_REVIEW");
    expect(result.delta_review.decision).toBe("PASS");
    expect(result.delta_review.isolation_attestations.length).toBeGreaterThan(0);
    expect(result.delta_review.identity_attestations.every(attestation => attestation.output_hash.startsWith("sha256:"))).toBeTrue();
    expect(result.delta_review.finding_status).toBe("VERIFIED_RESOLVED");
    expect(result.phase1_verdict).toBe("ACCEPT");
    expect(result.initial_main_unchanged).toBeTrue();
    expect(result.repair_main_unchanged).toBeTrue();
    expect(result.audit_integrity).toEqual({ valid: true, event_count: result.timeline.length });
    expect(result.timeline.map(item => item.label)).toContain("Review decision issued — changes requested");
    expect(result.timeline.map(item => item.label)).toContain("Repair assignment created");
    expect(result.exit_metrics).toEqual({
      reviewer_source_writes: 0,
      unsupported_blockers: 0,
      secret_leaks: 0,
      critical_bypasses: 0,
      duplicate_effects: 0,
      stale_accepts: 0,
      open_p0_p1_findings: 0,
      network_probe_bypasses: 0,
      credential_probe_bypasses: 0,
    });
    expect(existsSync(result.report_path)).toBeTrue();
    expect(JSON.parse(readFileSync(result.report_path, "utf8")).phase1_verdict).toBe("ACCEPT");
  }, 120_000);
});
