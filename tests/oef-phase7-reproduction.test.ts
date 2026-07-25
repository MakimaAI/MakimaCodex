import { describe, expect, test } from "bun:test";
import {
  createDeterministicPhase2ReplayAdapter,
  createReproductionManifest,
  LocalReproductionEvidenceStore,
  runPinnedReproduction,
} from "../src/oef/phase7";
import { reproductionManifest } from "./helpers/phase7-fixtures";

describe("Phase 7 pinned reproduction", () => {
  test("rejects production access, secrets, and incomplete pins or budgets", () => {
    expect(() => createReproductionManifest(reproductionManifest({ production_access: true }))).toThrow("REPRODUCTION_PRODUCTION_ACCESS_FORBIDDEN");
    expect(() => createReproductionManifest(reproductionManifest({ secret_refs: ["secret:one"] }))).toThrow("REPRODUCTION_SECRET_FORBIDDEN");
    for (const field of ["source_commit", "image_digest", "expected_signature", "seed", "budgets"] as const) {
      const input = reproductionManifest();
      delete input[field];
      expect(() => createReproductionManifest(input)).toThrow("REPRODUCTION_MANIFEST_INCOMPLETE");
    }
  });

  test("uses the explicit Phase 2 replay port for deterministic 5/5 evidence", async () => {
    const manifest = createReproductionManifest(reproductionManifest());
    const evidenceStore = new LocalReproductionEvidenceStore();
    const adapter = createDeterministicPhase2ReplayAdapter({ outcomes: [true, true, true, true, true], expected_signature: manifest.expected_signature, scope: manifest.scope, evidence_store: evidenceStore });
    const first = await runPinnedReproduction(manifest, adapter, evidenceStore);
    const second = await runPinnedReproduction(manifest, adapter, evidenceStore);

    expect(first).toEqual(second);
    expect(first).toMatchObject({ classification: "REPRODUCIBLE", reproduced: 5, attempted: 5 });
    expect(first.attempts).toHaveLength(5);
    expect(first.attempts.every((attempt: { evidence_ref: string }) => attempt.evidence_ref.startsWith("artifact:repo:makima:"))).toBe(true);
  });
});
