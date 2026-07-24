import { describe, expect, test } from "bun:test";

describe("OEF Phase 1 public surface", () => {
  test("exposes the provider-independent task backbone", async () => {
    const phase1 = await import("../src/oef/phase1/index.ts");
    const expectedFunctions = [
      "createSortableIdGenerator",
      "parseActor",
      "parseSecretRef",
      "parseTaskContractDocument",
      "canonicalContractHash",
      "diffTaskContracts",
      "parseWorkflowDefinition",
      "evaluateWorkflowTransition",
      "parsePolicyPack",
      "evaluatePolicy",
      "SqliteOefStore",
      "OefCommandBus",
      "LocalArtifactStore",
      "JsonlTraceExporter",
      "verifyTaskIntegrity",
      "upcastStoredEvent",
      "runPhase1Demo",
    ];

    for (const name of expectedFunctions) {
      expect(typeof phase1[name as keyof typeof phase1], name).toBe("function");
    }
  });
});
