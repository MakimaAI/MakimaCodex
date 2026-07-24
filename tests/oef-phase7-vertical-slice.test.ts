import { describe, expect, test } from "bun:test";

describe("Phase 7 incident intelligence vertical slice", () => {
  test("publishes the persistence, service, Phase 2 collector, reproduction, and acceptance API", async () => {
    const phase7 = await import("../src/oef/phase7").catch(() => null) as Record<string, unknown> | null;

    expect(phase7).not.toBeNull();
    expect(typeof phase7?.SqliteIncidentRegistry).toBe("function");
    expect(typeof phase7?.IncidentIntelligenceService).toBe("function");
    expect(typeof phase7?.collectPhase2Failure).toBe("function");
    expect(typeof phase7?.createReproductionManifest).toBe("function");
    expect(typeof phase7?.runPinnedReproduction).toBe("function");
    expect(typeof phase7?.createDeterministicPhase2ReplayAdapter).toBe("function");
    expect(typeof phase7?.runPhase7AcceptanceDemo).toBe("function");
    expect(typeof (phase7?.SqliteIncidentRegistry as { prototype?: Record<string, unknown> })?.prototype?.persistIngestion).toBe("function");
    expect(typeof (phase7?.IncidentIntelligenceService as { prototype?: Record<string, unknown> })?.prototype?.ingest).toBe("function");
    expect(typeof (phase7?.IncidentIntelligenceService as { prototype?: Record<string, unknown> })?.prototype?.close).toBe("function");
  });
});
