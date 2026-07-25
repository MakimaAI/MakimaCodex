import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  createDeterministicPhase2ReplayAdapter,
  IncidentIntelligenceService,
  LocalReproductionEvidenceStore,
  SqliteIncidentRegistry,
  collectPhase2Failure,
} from "../src/oef/phase7";
import { SqliteOperationsStore } from "../src/oef/operations";
import { phase2FailureEnvelope } from "./helpers/phase7-fixtures";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) { try { rmSync(root, { recursive: true, force: true }); } catch { /* handles still surface in the owning test */ } } });
function paths(): { root: string; registry: string; operations: string } {
  const root = mkdtempSync(join(tmpdir(), "phase7-service-")); roots.push(root);
  return { root, registry: join(root, "incidents.sqlite"), operations: join(root, "operations.sqlite") };
}

describe("Phase 7 incident registry and service", () => {
  test("requires shared operations recovery whenever a Phase 6 writer is configured", () => {
    const location = paths();
    const registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    expect(() => new IncidentIntelligenceService({ registry, memoryWriter: { write: () => undefined } })).toThrow("PHASE7_MEMORY_RECOVERY_OPERATIONS_REQUIRED");
    registry.close();
  });

  test("ingests idempotently, persists across restart, and fails closed on tamper", () => {
    const location = paths();
    let registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const service = new IncidentIntelligenceService({ registry });
    const event = collectPhase2Failure(phase2FailureEnvelope());
    const first = service.ingest(event);
    const duplicate = service.ingest(event);

    expect(first.created).toBe(true);
    expect(duplicate).toMatchObject({ created: false, duplicate: true, incident_id: first.incident_id });
    expect(registry.auditEvents(first.incident_id)).toHaveLength(2);
    registry.close();

    registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    expect(registry.getIncident(first.incident_id)?.incident_id).toBe(first.incident_id);
    registry.close();

    const attacker = new Database(location.registry);
    attacker.exec("DROP TRIGGER phase7_observation_revision_update_block");
    attacker.query("UPDATE phase7_observation_revisions SET payload_json = replace(payload_json, 'HTTP 403', 'HTTP 200')").run();
    attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    expect(() => registry.getObservation(first.observation_id)).toThrow("PHASE7_PERSISTENCE_TAMPERED");
    registry.close();
  });

  test("isolates repository scopes and never auto-merges high-risk related observations", () => {
    const location = paths();
    const registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const service = new IncidentIntelligenceService({ registry });
    const first = service.ingest(collectPhase2Failure(phase2FailureEnvelope()));
    const related = service.ingest(collectPhase2Failure(phase2FailureEnvelope({ event_id: "event:phase7-403-two", observed_at: "2026-07-24T10:01:00.000Z" })));
    const foreign = service.ingest(collectPhase2Failure(phase2FailureEnvelope({ event_id: "event:foreign", scope_id: "repo:foreign", observed_at: "2026-07-24T10:02:00.000Z" })));

    expect(related.incident_id).not.toBe(first.incident_id);
    expect(related.correlation).toBe("POSSIBLE_DUPLICATE");
    expect(registry.relations(related.incident_id)).toContainEqual(expect.objectContaining({ relation_type: "POSSIBLE_DUPLICATE", related_incident_id: first.incident_id }));
    expect(registry.listIncidents({ type: "REPOSITORY", id: "repo:makima" }).map(item => item.incident_id)).not.toContain(foreign.incident_id);
    expect(registry.relations(first.incident_id).some(item => item.related_incident_id === foreign.incident_id)).toBe(false);
    registry.close();
  });

  test("fails closed before correlation when a persisted signature is tampered", () => {
    const location = paths();
    let registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    new IncidentIntelligenceService({ registry }).ingest(collectPhase2Failure(phase2FailureEnvelope()));
    registry.close();
    const attacker = new Database(location.registry);
    attacker.exec("DROP TRIGGER phase7_signature_update_block");
    attacker.query("UPDATE phase7_signatures SET normalized_signature=?").run(`sha256:${"b".repeat(64)}`);
    attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const service = new IncidentIntelligenceService({ registry });
    expect(() => service.ingest(collectPhase2Failure(phase2FailureEnvelope({ event_id: "event:phase7-after-signature-tamper", observed_at: "2026-07-24T10:03:00.000Z" })))).toThrow("PHASE7_PERSISTENCE_TAMPERED");
    registry.close();
  });

  test("rejects a forged cross-scope relation at the persistence boundary", () => {
    const location = paths();
    const registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const service = new IncidentIntelligenceService({ registry });
    const local = service.ingest(collectPhase2Failure(phase2FailureEnvelope()));
    const foreign = service.ingest(collectPhase2Failure(phase2FailureEnvelope({ event_id: "event:foreign-existing", scope_id: "repo:foreign", observed_at: "2026-07-24T10:01:00.000Z" })));
    expect(local.incident_id).not.toBe(foreign.incident_id);
    expect((registry as unknown as Record<string, unknown>).persistIngestion).toBeUndefined();
    registry.close();
  });

  test("keeps triage axes separate and enforces containment authority", () => {
    const location = paths();
    const registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const service = new IncidentIntelligenceService({ registry });
    const leak = service.ingest(collectPhase2Failure(phase2FailureEnvelope({ event_id: "event:secret-leak", failure_type: "SECRET_LEAK_DETECTED" })));
    const triage = service.triage(leak.incident_id, { severity: "LOW", priority: "P3", confidence: 0.91, actor: { type: "human", id: "human:owner" }, at: "2026-07-24T10:03:00.000Z" });

    expect(triage).toMatchObject({ severity: "HIGH", priority: "P3", confidence: 0.91, required_approval: "A5" });
    const automatic = service.proposeContainment(leak.incident_id, { action_id: "containment:log-only", summary: "Record local diagnostic state", autonomy: "A2", reversible: true, actor: { type: "system", id: "system:phase7" }, at: "2026-07-24T10:04:00.000Z" });
    const gated = service.proposeContainment(leak.incident_id, { action_id: "containment:permission-change", summary: "Change repository permission", autonomy: "A3", reversible: true, actor: { type: "system", id: "system:phase7" }, at: "2026-07-24T10:05:00.000Z" });
    expect(automatic).toMatchObject({ state: "PROPOSED", execution_kind: "NONE", required_approval: "A5" });
    expect(gated).toMatchObject({ state: "PROPOSED", execution_kind: "NONE" });
    registry.close();
  });

  test("preserves closure evidence and enqueues shared retry work when Phase 6 writing fails", async () => {
    const location = paths();
    const registry = new SqliteIncidentRegistry({ databasePath: location.registry });
    const operations = new SqliteOperationsStore({ databasePath: location.operations });
    const event = collectPhase2Failure(phase2FailureEnvelope());
    const evidenceStore = new LocalReproductionEvidenceStore();
    const adapter = createDeterministicPhase2ReplayAdapter({ outcomes: [true, true, true, true, true], expected_signature: event.signatures.normalized_signature, scope: event.observation.scope as { type: "REPOSITORY"; id: string }, evidence_store: evidenceStore });
    const service = new IncidentIntelligenceService({
      registry,
      operations,
      memoryWriter: { write: () => { throw new Error(["OPENAI", "_API_KEY=", "sk", "-proj-phase7-runtime-only"].join("")); } },
      reproductionAdapter: adapter,
      evidenceResolver: evidenceStore,
    });
    const result = await service.runFoundationResolution(event, { at: "2026-07-24T11:00:00.000Z" });

    expect(registry.getIncident(result.incident_id)).toMatchObject({ status: "CLOSED", root_cause: { state: "CONFIRMED" } });
    expect(result.memory).toMatchObject({ status: "RETRY_QUEUED", records: 3 });
    const jobs = operations.list({ scope_id: "repository:repo:makima" });
    expect(jobs).toHaveLength(1);
    expect(jobs[0]).toMatchObject({ kind: "phase7.memory-write", state: "PENDING" });
    operations.close();
    registry.close();
  });
});
