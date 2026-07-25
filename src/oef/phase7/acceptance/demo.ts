import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Database } from "bun:sqlite";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { SqliteMemoryStore } from "../../phase6/persistence/sqlite-store";
import { SqliteOperationsStore } from "../../operations/persistence/sqlite-store";
import { SqlitePhase6IncidentMemoryWriter } from "../application/memory-writer";
import { IncidentIntelligenceService } from "../application/service";
import { collectPhase2Failure } from "../ingestion/phase2-failure-collector";
import { SqliteIncidentRegistry } from "../persistence/sqlite-store";
import { createDeterministicPhase2ReplayAdapter, LocalReproductionEvidenceStore } from "../reproduction/manifest";

export interface Phase7AcceptanceReport {
  status: "PASS";
  commit_sha: string;
  source: { phase: 2; http_status: 403; boundary: "STRUCTURED_FAILURE_AND_EXECUTION_MANIFEST" };
  observation: { sanitized: true; observation_id: string; stable_signature: string };
  incident: { incident_id: string; severity: "HIGH"; priority: "P1"; closed: true; root_cause: "CONFIRMED" };
  containment: { state: "PROPOSED"; production_action_performed: false };
  reproduction: { reproduced: 5; attempted: 5; adapter: "phase2-local-replay"; production_access: false };
  hypothesis: { falsifiable: true; supported: true };
  experiment: { controlled: true; regression_before: "FAIL"; regression_after: "PASS" };
  review: { independent: true; verdict: "APPROVED" };
  memory: { statuses: ["OBSERVED", "VERIFIED", "CANDIDATE"]; count: 3 };
  repeated_signature: { matched: true; correlation: "POSSIBLE_DUPLICATE" };
  boundaries: { production_repair: false; production_deploy: false; web_research: false; active_skill_created: false };
  report_hash: string;
}

export async function runPhase7AcceptanceDemo(options: { root: string; commitSha: string }): Promise<Phase7AcceptanceReport> {
  if (!/^[a-f0-9]{40}$/i.test(options.commitSha)) throw new Error("PHASE7_DEMO_COMMIT_SHA_REQUIRED");
  const root = resolve(options.root);
  mkdirSync(root, { recursive: true });
  const incidentPath = join(root, "incidents.sqlite");
  const operationsPath = join(root, "operations.sqlite");
  const memoryPath = join(root, "memory.sqlite");
  resetIncidentRegistry(incidentPath);
  const registry = new SqliteIncidentRegistry({ databasePath: incidentPath });
  const operations = new SqliteOperationsStore({ databasePath: operationsPath });
  const memoryStore = new SqliteMemoryStore({ databasePath: memoryPath });
  try {
    const first = collectPhase2Failure(phase2Envelope("event:phase7-demo-403-one", "2026-07-24T10:00:00.000Z", options.commitSha));
    const writer = new SqlitePhase6IncidentMemoryWriter(memoryStore);
    const evidenceStore = new LocalReproductionEvidenceStore();
    const adapter = createDeterministicPhase2ReplayAdapter({ outcomes: [true, true, true, true, true], expected_signature: first.signatures.normalized_signature, scope: first.observation.scope as { type: "REPOSITORY"; id: string }, evidence_store: evidenceStore });
    const service = new IncidentIntelligenceService({ registry, operations, memoryWriter: writer, reproductionAdapter: adapter, evidenceResolver: evidenceStore });
    const resolution = await service.runFoundationResolution(first, { at: "2026-07-24T10:10:00.000Z" });
    const incidentId = String(resolution.incident_id);
    const closed = registry.getIncident(incidentId)!;
    const triage = registry.records("TRIAGE", incidentId)[0]!.payload;
    const containment = registry.records("CONTAINMENT", incidentId)[0]!.payload;
    const reproduction = registry.records("REPRODUCTION", incidentId)[0]!.payload;
    const regressions = registry.records("REGRESSION", incidentId).map(item => item.payload);
    const review = registry.records("REVIEW", incidentId)[0]!.payload;
    const memoryIds = (resolution.memory as { memory_ids?: string[] }).memory_ids ?? [];
    const memoryStatuses = memoryIds.map(id => memoryStore.get(id)?.lifecycle.status);
    if (memoryStatuses.join(",") !== "OBSERVED,VERIFIED,CANDIDATE") throw new Error("PHASE7_DEMO_MEMORY_GATE_FAILED");
    const repeated = service.ingest(collectPhase2Failure(phase2Envelope("event:phase7-demo-403-repeat", "2026-07-24T10:20:00.000Z", options.commitSha)));
    const matched = registry.relations(repeated.incident_id).some(relation => relation.related_incident_id === incidentId);
    if (!matched || repeated.correlation !== "POSSIBLE_DUPLICATE") throw new Error("PHASE7_DEMO_SIGNATURE_GATE_FAILED");
    if (closed.status !== "CLOSED" || closed.root_cause.state !== "CONFIRMED" || triage.severity !== "HIGH" || triage.priority !== "P1") throw new Error("PHASE7_DEMO_INCIDENT_GATE_FAILED");
    if (containment.state !== "PROPOSED" || reproduction.reproduced !== 5 || reproduction.attempted !== 5 || review.independent !== true || review.verdict !== "APPROVED") throw new Error("PHASE7_DEMO_EVIDENCE_GATE_FAILED");
    if (!closed.hypotheses.some(item => item.status === "SUPPORTED")) throw new Error("PHASE7_DEMO_HYPOTHESIS_GATE_FAILED");
    if (regressions.find(item => item.phase === "BEFORE")?.result !== "FAIL" || regressions.find(item => item.phase === "AFTER")?.result !== "PASS") throw new Error("PHASE7_DEMO_REGRESSION_GATE_FAILED");
    const payload = {
      status: "PASS" as const,
      commit_sha: options.commitSha.toLowerCase(),
      source: { phase: 2 as const, http_status: 403 as const, boundary: "STRUCTURED_FAILURE_AND_EXECUTION_MANIFEST" as const },
      observation: { sanitized: true as const, observation_id: String(resolution.observation_id), stable_signature: first.signatures.normalized_signature },
      incident: { incident_id: incidentId, severity: "HIGH" as const, priority: "P1" as const, closed: true as const, root_cause: "CONFIRMED" as const },
      containment: { state: "PROPOSED" as const, production_action_performed: false as const },
      reproduction: { reproduced: 5 as const, attempted: 5 as const, adapter: "phase2-local-replay" as const, production_access: false as const },
      hypothesis: { falsifiable: true as const, supported: true as const },
      experiment: { controlled: true as const, regression_before: "FAIL" as const, regression_after: "PASS" as const },
      review: { independent: true as const, verdict: "APPROVED" as const },
      memory: { statuses: memoryStatuses as ["OBSERVED", "VERIFIED", "CANDIDATE"], count: memoryIds.length as 3 },
      repeated_signature: { matched: true as const, correlation: repeated.correlation as "POSSIBLE_DUPLICATE" },
      boundaries: { production_repair: false as const, production_deploy: false as const, web_research: false as const, active_skill_created: false as const },
    };
    const report: Phase7AcceptanceReport = { ...payload, report_hash: canonicalSha256(payload) };
    writeFileSync(join(root, "phase7-demo-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");
    return report;
  } finally {
    memoryStore.close();
    operations.close();
    registry.close();
  }
}

function phase2Envelope(eventId: string, observedAt: string, commitSha: string): Record<string, unknown> {
  const scopeId = "repo:makima";
  const artifactId = "artifact:repo:makima:phase2-403";
  const hash = canonicalSha256({ fixture: "phase7-403" });
  return {
    schema_version: 1,
    event_id: eventId,
    task_id: "task:phase7-demo",
    execution_id: "execution:phase7-demo",
    attempt_id: "attempt:phase7-demo-1",
    scope: { type: "REPOSITORY", id: scopeId },
    failure: {
      schema_version: 1,
      failure_id: `failure:${eventId}`,
      type: "AUTHORIZATION_FAILED",
      category: "provider",
      retryability: "never",
      scope: { runtime: true, model: false, account: true, task: true },
      safe_actions: ["inspect-permissions"],
      unsafe_actions: ["change-production-permissions"],
      signature: hash,
      evidence_refs: [artifactId],
    },
    execution_manifest: {
      execution_manifest_version: 1,
      task: { id: "task:phase7-demo", contract_hash: hash },
      assignment: { id: "assignment:phase7-demo", revision: 1, hash },
      workflow: { id: "workflow:phase7", version: "1.0.0", hash },
      policy: { id: "policy:phase7", version: "1.0.0", hash },
      source: { repository: scopeId, base_commit: commitSha, tree_hash: hash },
      runtime: { id: "codex", binary_version: "2.4.1", adapter_version: "1.0.0", protocol_version: 1 },
      model: { provider: "openai", resolved_id: "gpt-phase7" },
      environment: { provider: "openai", fingerprint: hash },
      context: { bundle_hash: hash, prompt_hash: hash },
      started_at: "2026-07-24T10:00:00.000Z",
    },
    artifact_hashes: { [artifactId]: hash },
    message: "HTTP 403 forbidden while checking repository permissions request_id=req_123456",
    environment: { os: "windows", arch: "x64", tool: "codex", operation: "provider-request" },
    http_status: 403,
    error_code: "permission_denied",
    exception: null,
    symbol: "provider.request",
    sensitivity: "INTERNAL",
    observed_at: observedAt,
  };
}

function resetIncidentRegistry(path: string): void {
  if (!existsSync(path)) return;
  const database = new Database(path, { strict: true });
  try {
    const triggers = database.query("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'phase7_%'").all() as Array<{ name: string }>;
    for (const trigger of triggers) database.exec(`DROP TRIGGER "${trigger.name}"`);
    const tables = [
      "phase7_ingestions", "phase7_audit_events", "phase7_incident_relations", "phase7_incident_observations",
      "phase7_signatures", "phase7_observation_revisions", "phase7_observations", "phase7_incident_revisions", "phase7_incidents",
      "phase7_triage_records", "phase7_containment_records", "phase7_reproduction_manifests", "phase7_reproduction_results", "phase7_hypothesis_evidence",
      "phase7_root_causes", "phase7_remediation_proposals", "phase7_regression_results", "phase7_review_verdicts", "phase7_playbook_candidates",
      "phase7_memory_write_batches",
    ];
    database.exec("PRAGMA foreign_keys=OFF");
    for (const table of tables) database.exec(`DELETE FROM "${table}"`);
  } finally { database.close(); }
}
