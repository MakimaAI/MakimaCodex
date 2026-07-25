import { afterEach, describe, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { canonicalSha256 } from "../src/oef/phase1/core/contract/task-contract";
import { SqliteOperationsStore } from "../src/oef/operations";
import {
  IncidentIntelligenceService,
  SqliteIncidentRegistry,
  collectPhase2Failure,
  correctFailureObservation,
} from "../src/oef/phase7";
import { PHASE7_COMMIT, phase2FailureEnvelope, reproductionManifest } from "./helpers/phase7-fixtures";
import { PHASE7_PINNED_IMAGE, TestPhase7EvidenceStore, phase7Service, trustedPhase2ReplayPorts } from "./helpers/phase7-review-harness";

const roots: string[] = [];
afterEach(() => { Bun.gc(true); for (const root of roots.splice(0)) { try { rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 }); } catch { /* a failing case may retain its diagnostic handle */ } } });
function location(prefix = "phase7-review-") { const root = mkdtempSync(join(tmpdir(), prefix)); roots.push(root); return { root, registry: join(root, "incidents.sqlite"), operations: join(root, "operations.sqlite") }; }
function collected(overrides: Record<string, unknown> = {}) { return collectPhase2Failure(phase2FailureEnvelope(overrides)); }
function manifestFor(incidentId: string, signature: string, overrides: Record<string, unknown> = {}) {
  return reproductionManifest({ incident_id: incidentId, expected_signature: signature, image_digest: PHASE7_PINNED_IMAGE, ...overrides });
}

async function closedFoundation(options: { memoryWriter?: { write(records: readonly unknown[]): void | Promise<void> }; operations?: SqliteOperationsStore } = {}) {
  const paths = location();
  const registry = new SqliteIncidentRegistry({ databasePath: paths.registry });
  const failure = collected();
  const ports = trustedPhase2ReplayPorts({ signature: failure.signatures.normalized_signature });
  const service = phase7Service({ registry, signature: failure.signatures.normalized_signature, operations: options.operations, memoryWriter: options.memoryWriter, adapter: ports.adapter, evidenceStore: ports.evidenceStore });
  const result = await service.runFoundationResolution(failure, { at: "2026-07-24T11:00:00.000Z" });
  return { paths, registry, service, failure, ports, result };
}

describe("Phase 7 review hardening", () => {
  test("removes the caller-forgeable public recordReproduction mutation", () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry });
    const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature });
    expect((service as unknown as Record<string, unknown>).recordReproduction).toBeUndefined();
    registry.close();
  });

  test("rejects a trusted replay port that returns forged zero-attempt reproduction", async () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected();
    const service = phase7Service({ registry, signature: failure.signatures.normalized_signature, adapter: { id: "phase2-local-replay", version: "1.0.0", replay: async () => ({ attempts: [] }) }, evidenceStore: new TestPhase7EvidenceStore() });
    const incident = service.ingest(failure);
    expect(typeof (service as unknown as Record<string, unknown>).reproduce).toBe("function");
    await expect((service as never as { reproduce(id: string, manifest: unknown, input: unknown): Promise<unknown> }).reproduce(incident.incident_id, manifestFor(incident.incident_id, failure.signatures.normalized_signature), { actor: { type: "system", id: "system:test" }, at: "2026-07-24T10:05:00.000Z" })).rejects.toThrow("REPRODUCTION_ATTEMPT_COUNT_MISMATCH");
    registry.close();
  });

  test("rejects inconsistent replay count and observed signature", async () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const evidence = new TestPhase7EvidenceStore();
    const ref = "artifact:repo:makima:one-attempt"; const hash = evidence.record(ref, "repo:makima", { attempt: 1 });
    const adapter = { id: "phase2-local-replay", version: "1.0.0", replay: async () => ({ attempts: [{ attempt: 1, failure_reproduced: true, summary: "one", observed_signature: `sha256:${"b".repeat(64)}`, evidence_ref: ref, evidence_hash: hash }] }) };
    const service = phase7Service({ registry, signature: failure.signatures.normalized_signature, adapter, evidenceStore: evidence }); const incident = service.ingest(failure);
    expect(typeof (service as unknown as Record<string, unknown>).reproduce).toBe("function");
    await expect((service as never as { reproduce(id: string, manifest: unknown, input: unknown): Promise<unknown> }).reproduce(incident.incident_id, manifestFor(incident.incident_id, failure.signatures.normalized_signature, { attempts: 1 }), { actor: { type: "system", id: "system:test" }, at: "2026-07-24T10:05:00.000Z" })).rejects.toThrow("REPRODUCTION_SIGNATURE_MISMATCH");
    registry.close();
  });

  test("rejects unresolved or hash-mismatched replay evidence", async () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected();
    const ref = "artifact:repo:makima:unresolved";
    const adapter = { id: "phase2-local-replay", version: "1.0.0", replay: async () => ({ attempts: [{ attempt: 1, failure_reproduced: true, summary: "forged", observed_signature: failure.signatures.normalized_signature, evidence_ref: ref, evidence_hash: canonicalSha256({ forged: true }) }] }) };
    const service = phase7Service({ registry, signature: failure.signatures.normalized_signature, adapter, evidenceStore: new TestPhase7EvidenceStore() }); const incident = service.ingest(failure);
    expect(typeof (service as unknown as Record<string, unknown>).reproduce).toBe("function");
    await expect((service as never as { reproduce(id: string, manifest: unknown, input: unknown): Promise<unknown> }).reproduce(incident.incident_id, manifestFor(incident.incident_id, failure.signatures.normalized_signature, { attempts: 1 }), { actor: { type: "system", id: "system:test" }, at: "2026-07-24T10:05:00.000Z" })).rejects.toThrow("REPRODUCTION_EVIDENCE_UNRESOLVED");
    registry.close();
  });

  test("exposes the registry as read-only and removes generic mutation bypasses", () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const surface = registry as unknown as Record<string, unknown>;
    expect(surface.persistIngestion).toBeUndefined();
    expect(surface.appendIncident).toBeUndefined();
    expect(surface.saveRecord).toBeUndefined();
    registry.close();
  });

  test("fails closed when incident history is missing revision one", () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature }); const ingested = service.ingest(failure);
    service.addHypothesis(ingested.incident_id, { hypothesis_id: "hypothesis:history", statement: "History prefix cause", causal_mechanism: "Missing prefix changes validation", falsifiable_prediction: "Restoring prefix validates", disproof_conditions: ["Prefix remains missing"], proposed_by: { type: "agent", id: "agent:history" } }, { actor: { type: "agent", id: "agent:history" }, at: "2026-07-24T10:05:00.000Z" });
    registry.close(); const attacker = new Database(paths.registry); attacker.exec("DROP TRIGGER phase7_incident_revision_delete_block"); attacker.query("DELETE FROM phase7_incident_revisions WHERE incident_id=? AND revision=1").run(ingested.incident_id); attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); expect(() => registry.getIncident(ingested.incident_id)).toThrow("PHASE7_PERSISTENCE_TAMPERED"); registry.close();
  });

  test("fails closed when relation row metadata points across scope", () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature });
    service.ingest(failure); const related = service.ingest(collected({ event_id: "event:related", observed_at: "2026-07-24T10:01:00.000Z" })); const foreign = service.ingest(collected({ event_id: "event:foreign-relation", scope_id: "repo:foreign", observed_at: "2026-07-24T10:02:00.000Z" }));
    registry.close(); const attacker = new Database(paths.registry); attacker.exec("DROP TRIGGER phase7_relation_update_block"); attacker.query("UPDATE phase7_incident_relations SET related_incident_id=? WHERE incident_id=?").run(foreign.incident_id, related.incident_id); attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); expect(() => registry.relations(related.incident_id)).toThrow("PHASE7_PERSISTENCE_TAMPERED"); registry.close();
  });

  test("fails closed when a gate-record row ID no longer matches its typed payload", () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature }); const ingested = service.ingest(failure);
    service.triage(ingested.incident_id, { severity: "HIGH", priority: "P1", confidence: 0.9, actor: { type: "system", id: "system:triage" }, at: "2026-07-24T10:03:00.000Z" });
    registry.close(); const attacker = new Database(paths.registry); attacker.exec("DROP TRIGGER phase7_triage_update_block"); attacker.query("UPDATE phase7_triage_records SET record_id='triage:forged-row-id'").run(); attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); expect(() => registry.records("TRIAGE", ingested.incident_id)).toThrow("PHASE7_PERSISTENCE_TAMPERED"); registry.close();
  });

  test("A5 triage overrides automatic A0-A2 containment without authenticated approval", () => {
    const paths = location(); const registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected({ event_id: "event:a5", failure_type: "SECRET_LEAK_DETECTED" });
    const verifier = { verify(input: { credential?: string }) { return input.credential === "approved-a5" ? { level: "A5", actor: { type: "human", id: "human:security" }, expires_at: "2026-07-24T11:00:00.000Z" } : null; } };
    const service = phase7Service({ registry, signature: failure.signatures.normalized_signature, containmentApprovalVerifier: verifier }); const incident = service.ingest(failure);
    service.triage(incident.incident_id, { severity: "LOW", priority: "P3", confidence: 0.9, actor: { type: "system", id: "system:triage" }, at: "2026-07-24T10:03:00.000Z" });
    const denied = service.proposeContainment(incident.incident_id, { action_id: "containment:a5-denied", summary: "Local diagnostic", autonomy: "A2", reversible: true, actor: { type: "system", id: "system:phase7" }, at: "2026-07-24T10:04:00.000Z" });
    expect(denied).toMatchObject({ state: "PROPOSED", required_approval: "A5" });
    const approved = (service as never as { proposeContainment(id: string, action: unknown): Record<string, unknown> }).proposeContainment(incident.incident_id, { action_id: "containment:a5-approved", summary: "Local diagnostic", autonomy: "A2", reversible: true, actor: { type: "system", id: "system:phase7" }, at: "2026-07-24T10:05:00.000Z", approval: { credential: "approved-a5", actor: { type: "human", id: "human:security" } } });
    expect(approved).toMatchObject({ state: "EXECUTED", approved_by: { id: "human:security" } });
    expect(JSON.stringify(approved)).not.toContain("approved-a5"); registry.close();
  });

  test("mixed remediation proposal, regression, and review lineages cannot close", async () => {
    const foundation = await closedFoundation(); const incidentId = String(foundation.result.incident_id); foundation.service.reopen(incidentId, { actor: { type: "human", id: "human:owner" }, reason: "verify lineage", at: "2026-07-24T12:00:00.000Z" }); foundation.registry.close();
    const attacker = new Database(foundation.paths.registry); for (const trigger of ["phase7_remediation_delete_block", "phase7_regression_delete_block", "phase7_review_delete_block", "phase7_playbook_delete_block"]) attacker.exec(`DROP TRIGGER ${trigger}`); for (const table of ["phase7_remediation_proposals", "phase7_regression_results", "phase7_review_verdicts", "phase7_playbook_candidates"]) attacker.exec(`DELETE FROM ${table}`); attacker.close();
    foundation.registry = new SqliteIncidentRegistry({ databasePath: foundation.paths.registry }); const service = phase7Service({ registry: foundation.registry, signature: foundation.failure.signatures.normalized_signature, adapter: foundation.ports.adapter, evidenceStore: foundation.ports.evidenceStore });
    const planA = canonicalSha256({ plan: "A" }); const patchA = canonicalSha256({ patch: "A" }); const planB = canonicalSha256({ plan: "B" }); const patchB = canonicalSha256({ patch: "B" });
    service.proposeRemediation(incidentId, { proposal_id: "remediation-proposal:A", summary: "Plan A", steps: ["Apply plan A"], proposed_by: { type: "agent", id: "agent:A" }, at: "2026-07-24T12:01:00.000Z", plan_hash: planA, patch_hash: patchA, evidence_refs: ["artifact:repo:makima:plan-a"] } as never);
    service.proposeRemediation(incidentId, { proposal_id: "remediation-proposal:B", summary: "Plan B", steps: ["Apply plan B"], proposed_by: { type: "agent", id: "agent:B" }, at: "2026-07-24T12:02:00.000Z", plan_hash: planB, patch_hash: patchB, evidence_refs: ["artifact:repo:makima:plan-b"] } as never);
    service.recordRegression(incidentId, { regression_id: "regression:A:before", remediation_id: "remediation-proposal:A", plan_hash: planA, patch_hash: patchA, phase: "BEFORE", result: "FAIL", evidence_ref: "artifact:repo:makima:a-before", actor: { type: "integration", id: "integration:review" }, at: "2026-07-24T12:03:00.000Z" } as never);
    service.recordRegression(incidentId, { regression_id: "regression:A:after", remediation_id: "remediation-proposal:A", plan_hash: planA, patch_hash: patchA, phase: "AFTER", result: "PASS", evidence_ref: "artifact:repo:makima:a-after", actor: { type: "integration", id: "integration:review" }, at: "2026-07-24T12:04:00.000Z" } as never);
    service.recordReview(incidentId, { review_id: "review:B", proposal_id: "remediation-proposal:B", plan_hash: planB, patch_hash: patchB, verdict: "APPROVED", reviewer: { type: "integration", id: "integration:review" }, rationale: "Only B reviewed", evidence_refs: ["artifact:repo:makima:plan-b", "artifact:repo:makima:b-review"], at: "2026-07-24T12:05:00.000Z" } as never);
    await expect(service.close(incidentId, { actor: { type: "integration", id: "integration:review" }, reason: "mixed evidence", at: "2026-07-24T12:06:00.000Z" })).rejects.toThrow("INCIDENT_CLOSE_REMEDIATION_LINEAGE_REQUIRED"); foundation.registry.close();
  });

  test("close, reopen, and reclose produce revision-scoped playbook and memory IDs", async () => {
    const foundation = await closedFoundation(); const incidentId = String(foundation.result.incident_id); const firstPlaybook = String(foundation.result.playbook_candidate_id);
    foundation.service.reopen(incidentId, { actor: { type: "human", id: "human:owner" }, reason: "revalidate", at: "2026-07-24T12:00:00.000Z" });
    const closing = foundation.service.close(incidentId, { actor: { type: "integration", id: "integration:phase3-independent-review" }, reason: "reclosed", at: "2026-07-24T12:01:00.000Z" });
    await expect(closing).resolves.toBeDefined();
    const second = await closing;
    expect(second.playbook_candidate_id).not.toBe(firstPlaybook);
    expect(foundation.registry.records("PLAYBOOK", incidentId)).toHaveLength(2);
    foundation.registry.close();
  });

  test("memory retry survives restart, revalidates its batch, and eventually succeeds", async () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); let operations = new SqliteOperationsStore({ databasePath: paths.operations }); const failure = collected(); const ports = trustedPhase2ReplayPorts({ signature: failure.signatures.normalized_signature });
    const secretShapedRuntimeMessage = ["OPENAI", "_API_KEY=", "sk", "-proj-phase7-runtime-only"].join("");
    let service = phase7Service({ registry, signature: failure.signatures.normalized_signature, operations, memoryWriter: { write: () => { throw new Error(secretShapedRuntimeMessage); } }, adapter: ports.adapter, evidenceStore: ports.evidenceStore });
    const resolved = await service.runFoundationResolution(failure, { at: "2026-07-24T11:00:00.000Z" }); const job = operations.list({ scope_id: "repository:repo:makima" })[0]!;
    expect(Object.keys(job.payload).sort()).toEqual(["batch_hash", "batch_id"]);
    expect(JSON.stringify(job)).not.toContain(secretShapedRuntimeMessage);
    registry.close(); operations.close(); registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); operations = new SqliteOperationsStore({ databasePath: paths.operations }); const written: unknown[][] = [];
    service = phase7Service({ registry, signature: failure.signatures.normalized_signature, operations, memoryWriter: { write: records => { written.push([...records]); } }, adapter: ports.adapter, evidenceStore: ports.evidenceStore });
    expect(typeof (service as unknown as Record<string, unknown>).processNextMemoryWrite).toBe("function");
    const processed = await (service as never as { processNextMemoryWrite(input: unknown): Promise<Record<string, unknown>> }).processNextMemoryWrite({ scope_id: "repository:repo:makima", owner: "worker:phase7-memory", now: "2026-07-24T11:10:00.000Z", lease_ms: 30_000 });
    expect(processed).toMatchObject({ status: "SUCCEEDED", records: 3, incident_id: resolved.incident_id }); expect(written[0]).toHaveLength(3); expect(operations.get({ scope_id: "repository:repo:makima", job_id: job.job_id })?.state).toBe("SUCCEEDED"); operations.close(); registry.close();
  });

  test("CLI rejects every unauthenticated mutation before parsing caller authority", async () => {
    const paths = location("phase7-cli-auth-");
    for (const [command, args] of [["ingest", []], ["triage", ["incident:any", "--actor", "human:forged"]], ["root-cause", ["incident:any", "--file", "forged.json"]], ["close", ["incident:any", "--reason", "forged"]], ["reopen", ["incident:any", "--reason", "forged"]], ["containment", ["incident:any"]]] as const) {
      const child = Bun.spawn([process.execPath, "src/cli/index.ts", "incident", command, ...args, "--home", paths.root, "--json"], { stdout: "pipe", stderr: "pipe", env: { ...Bun.env, OPENCODEX_NO_UPDATE_CHECK: "1" } }); const stderr = await new Response(child.stderr).text(); const exit = await child.exited;
      expect(exit, command).toBe(1); expect(JSON.parse(stderr), command).toEqual({ error: "PHASE7_AUTHORIZATION_REQUIRED", command });
    }
  });

  test("workflow uploads only hashed files and verifies embedded commit SHA", () => {
    const workflow = readFileSync(join(import.meta.dir, "..", ".github", "workflows", "phase7-foundation.yml"), "utf8");
    expect(workflow).toContain("report.commit_sha !== process.env.GITHUB_SHA");
    expect(workflow).not.toContain("path: .artifacts/phase7/");
    const upload = workflow.split("name: Upload commit-bound acceptance evidence")[1]!;
    for (const file of ["phase7-demo-report.json", "phase7-demo-report-run-1.json", "phase7-demo-report-run-2.json", "run-1.json", "run-2.json", "ci-metadata.json"]) expect(upload).toContain(file);
    expect(upload).not.toContain("incidents.sqlite");
  });

  test("historical observation lookup returns the requested immutable revision", () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature }); const ingested = service.ingest(failure); const first = registry.getObservation(ingested.observation_id)!;
    const second = correctFailureObservation(first, { failure: { ...first.failure, summary: "Corrected HTTP 403 summary" } }, { expected_revision: 1, reason: "correct summary", actor: { type: "human", id: "human:owner" }, at: "2026-07-24T10:10:00.000Z", resolve_predecessor: id => id === first.revision_id ? first : null });
    registry.close(); const database = new Database(paths.registry); database.query("INSERT INTO phase7_observation_revisions (revision_id, observation_id, revision, previous_revision_id, previous_observation_hash, scope_type, scope_id, canonical_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").run(second.revision_id, second.observation_id, second.revision, second.previous_revision_id, second.previous_observation_hash, second.scope.type, second.scope.id, second.canonical_hash, JSON.stringify(second)); database.query("UPDATE phase7_observations SET current_revision_id=?, current_revision=?, canonical_hash=?, payload_json=? WHERE observation_id=?").run(second.revision_id, second.revision, second.canonical_hash, JSON.stringify(second), second.observation_id); database.close();
    registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); expect(registry.getObservationByRevision(first.revision_id)).toMatchObject({ revision: 1, revision_id: first.revision_id }); expect(registry.getObservation(second.observation_id)).toMatchObject({ revision: 2, revision_id: second.revision_id }); registry.close();
  });

  test("historical observation lookup validates requested row metadata before returning", () => {
    const paths = location(); let registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); const failure = collected(); const service = phase7Service({ registry, signature: failure.signatures.normalized_signature }); const ingested = service.ingest(failure); const first = registry.getObservation(ingested.observation_id)!; registry.close();
    const attacker = new Database(paths.registry); attacker.exec("DROP TRIGGER phase7_observation_revision_update_block"); attacker.query("UPDATE phase7_observation_revisions SET scope_id='repo:foreign' WHERE revision_id=?").run(first.revision_id); attacker.close();
    registry = new SqliteIncidentRegistry({ databasePath: paths.registry }); expect(() => registry.getObservationByRevision(first.revision_id)).toThrow("PHASE7_PERSISTENCE_TAMPERED"); registry.close();
  });

  test("privacy fixtures never contain a static credential-shaped literal", () => {
    const source = readFileSync(join(import.meta.dir, "oef-phase7-service.test.ts"), "utf8"); const forbidden = ["OPENAI_API", "_KEY=", "sk", "-"].join(""); expect(source.includes(forbidden)).toBe(false);
  });
});
