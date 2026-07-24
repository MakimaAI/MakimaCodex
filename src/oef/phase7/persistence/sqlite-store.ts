import { Database } from "bun:sqlite";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";
import { assertNoPhase1Secret, assertNoStructuredPhase1Secret } from "../../phase1/core/security/secrets";
import { parseFailureObservation, type FailureObservation } from "../core/failure-observation";
import { parseIncident, type Incident } from "../core/incident";
import { samePhase7Scope, type Phase7Scope } from "../core/shared";
import type { FailureSignatures } from "../ingestion/signatures";

export interface IncidentRelation {
  relation_id: string;
  incident_id: string;
  related_incident_id: string;
  relation_type: "POSSIBLE_DUPLICATE";
  reason: string;
  created_at: string;
}
export interface IngestionPersistenceInput {
  source_event_id: string;
  source_hash: string;
  observation: FailureObservation;
  signatures: FailureSignatures;
  provider: string;
  runtime: string;
  runtime_major: number;
  incident: Incident;
  relation: IncidentRelation | null;
  correlation: "NEW" | "AUTO_CORRELATED" | "POSSIBLE_DUPLICATE";
}
export interface IngestionPersistenceResult {
  created: boolean;
  duplicate: boolean;
  observation_id: string;
  incident_id: string;
  correlation: IngestionPersistenceInput["correlation"];
  result_hash: string;
}

const recordTables = {
  TRIAGE: "phase7_triage_records",
  CONTAINMENT: "phase7_containment_records",
  REPRODUCTION: "phase7_reproduction_results",
  HYPOTHESIS_EVIDENCE: "phase7_hypothesis_evidence",
  ROOT_CAUSE: "phase7_root_causes",
  REMEDIATION: "phase7_remediation_proposals",
  REGRESSION: "phase7_regression_results",
  REVIEW: "phase7_review_verdicts",
  PLAYBOOK: "phase7_playbook_candidates",
} as const;
export type IncidentRecordKind = keyof typeof recordTables;
export interface PersistedIncidentRecord { record_id: string; incident_id: string; scope_id: string; occurred_at: string; payload_hash: string; payload: Record<string, unknown> }

export class SqliteIncidentRegistry {
  private readonly database: Database;
  constructor(options: { databasePath: string }) {
    this.database = new Database(options.databasePath, { create: true, strict: true });
    this.database.exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;");
    this.database.exec(readFileSync(join(import.meta.dir, "migrations", "001_incident_registry.sql"), "utf8"));
  }
  close(): void { this.database.close(); }
  transaction<T>(operation: () => T): T { return this.database.transaction(operation).immediate(); }

  persistIngestion(input: IngestionPersistenceInput): IngestionPersistenceResult {
    const duplicate = this.existingIngestion(input.source_event_id, input.source_hash);
    if (duplicate) return duplicate;
    const observation = parseFailureObservation(input.observation);
    const incident = parseIncident(input.incident);
    if (input.relation) {
      const related = this.getIncident(input.relation.related_incident_id);
      if (input.correlation !== "POSSIBLE_DUPLICATE" || input.relation.incident_id !== incident.incident_id || input.relation.related_incident_id === incident.incident_id || !related || !samePhase7Scope(related.scope, incident.scope)) throw new Error("PHASE7_RELATION_SCOPE_MISMATCH");
    } else if (input.correlation === "POSSIBLE_DUPLICATE") {
      throw new Error("PHASE7_RELATION_REQUIRED");
    }
    if (!samePhase7Scope(observation.scope, incident.scope) || !incident.observation_ids.includes(observation.revision_id)) throw new Error("PHASE7_INGESTION_SCOPE_MISMATCH");
    return this.transaction(() => {
      const racedDuplicate = this.existingIngestion(input.source_event_id, input.source_hash);
      if (racedDuplicate) return racedDuplicate;
      this.insertObservation(observation);
      this.insertSignature(input);
      if (input.correlation === "AUTO_CORRELATED") {
        const current = this.getIncidentRequired(incident.incident_id);
        if (incident.revision !== current.revision + 1 || incident.previous_revision_hash !== current.revision_hash) throw new Error("PHASE7_INCIDENT_REVISION_CONFLICT");
        this.insertIncidentRevision(incident);
        this.database.query("UPDATE phase7_incidents SET current_revision=?, current_revision_hash=?, status=?, payload_json=? WHERE incident_id=? AND current_revision=?")
          .run(incident.revision, incident.revision_hash, incident.status, JSON.stringify(incident), incident.incident_id, current.revision);
      } else {
        this.insertIncident(incident);
      }
      this.database.query("INSERT INTO phase7_incident_observations (incident_id, observation_revision_id, linked_at) VALUES (?, ?, ?)")
        .run(incident.incident_id, observation.revision_id, observation.observed_at);
      if (input.relation) this.insertRelation(input.relation);
      this.appendAudit(incident.incident_id, "OBSERVATION_INGESTED", { observation_id: observation.observation_id, source_event_id: input.source_event_id }, observation.observed_at);
      this.appendAudit(incident.incident_id, input.relation ? "INCIDENT_RELATED" : "INCIDENT_OPENED", { correlation: input.correlation, related_incident_id: input.relation?.related_incident_id ?? null }, observation.observed_at);
      const base = { created: true, duplicate: false, observation_id: observation.observation_id, incident_id: incident.incident_id, correlation: input.correlation };
      const result: IngestionPersistenceResult = { ...base, result_hash: canonicalSha256(base) };
      this.database.query("INSERT INTO phase7_ingestions (source_event_id, source_hash, observation_id, incident_id, result_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?)")
        .run(input.source_event_id, input.source_hash, result.observation_id, result.incident_id, result.result_hash, JSON.stringify(result));
      return result;
    });
  }

  findCorrelation(input: { scope: Phase7Scope; signatures: FailureSignatures; provider: string; runtime: string; runtime_major: number }): { incident: Incident; observation_id: string } | null {
    const rows = this.database.query(`SELECT s.*, o.scope_type AS observation_scope_type, o.scope_id AS observation_scope_id, l.incident_id
      FROM phase7_signatures s
      JOIN phase7_observations o ON o.observation_id=s.observation_id
      JOIN phase7_incident_observations l ON l.observation_revision_id=o.current_revision_id
      WHERE o.scope_type=? AND o.scope_id=? ORDER BY l.incident_id, s.observation_id`)
      .all(input.scope.type, input.scope.id) as Array<Record<string, unknown>>;
    for (const row of rows) {
      const signature = decodeSignatureRow(row);
      if (signature.normalized_signature === input.signatures.normalized_signature
        && signature.structural_signature === input.signatures.structural_signature
        && signature.provider === input.provider
        && signature.runtime === input.runtime
        && signature.runtime_major === input.runtime_major) {
        return { observation_id: signature.observation_id, incident: this.getIncidentRequired(String(row.incident_id)) };
      }
    }
    return null;
  }

  getObservation(observationId: string): FailureObservation | null {
    const row = this.database.query("SELECT * FROM phase7_observations WHERE observation_id=?").get(observationId) as Record<string, unknown> | null;
    if (!row) return null;
    try {
      const observation = parseFailureObservation(JSON.parse(String(row.payload_json)), revisionId => {
        const predecessor = this.database.query("SELECT payload_json FROM phase7_observation_revisions WHERE revision_id=?").get(revisionId) as { payload_json: string } | null;
        return predecessor ? JSON.parse(predecessor.payload_json) : null;
      });
      const revisionRow = this.database.query("SELECT payload_json FROM phase7_observation_revisions WHERE revision_id=?").get(observation.revision_id) as { payload_json: string } | null;
      if (!revisionRow || revisionRow.payload_json !== row.payload_json) throw new Error("tampered");
      if (observation.observation_id !== row.observation_id || observation.revision_id !== row.current_revision_id || observation.revision !== row.current_revision || observation.canonical_hash !== row.canonical_hash || observation.scope.type !== row.scope_type || observation.scope.id !== row.scope_id) throw new Error("tampered");
      return observation;
    } catch { throw new Error("PHASE7_PERSISTENCE_TAMPERED"); }
  }

  getObservationByRevision(revisionId: string): FailureObservation | null {
    const row = this.database.query("SELECT observation_id FROM phase7_observation_revisions WHERE revision_id=?").get(revisionId) as { observation_id: string } | null;
    return row ? this.getObservation(row.observation_id) : null;
  }

  getIncident(incidentId: string): Incident | null {
    const row = this.database.query("SELECT * FROM phase7_incidents WHERE incident_id=?").get(incidentId) as Record<string, unknown> | null;
    if (!row) return null;
    try {
      const incident = parseIncident(JSON.parse(String(row.payload_json)));
      if (incident.incident_id !== row.incident_id || incident.revision !== row.current_revision || incident.revision_hash !== row.current_revision_hash || incident.scope.type !== row.scope_type || incident.scope.id !== row.scope_id || incident.status !== row.status) throw new Error("tampered");
      const revisions = this.database.query("SELECT * FROM phase7_incident_revisions WHERE incident_id=? ORDER BY revision").all(incidentId) as Array<Record<string, unknown>>;
      let previous: Incident | null = null;
      for (const revisionRow of revisions) {
        const revision = parseIncident(JSON.parse(String(revisionRow.payload_json)));
        if (revision.incident_id !== incidentId || revision.revision !== revisionRow.revision || revision.revision_hash !== revisionRow.revision_hash || revision.previous_revision_hash !== revisionRow.previous_revision_hash || revision.scope.type !== revisionRow.scope_type || revision.scope.id !== revisionRow.scope_id || (previous && revision.previous_revision_hash !== previous.revision_hash)) throw new Error("tampered");
        previous = revision;
      }
      if (!previous || previous.revision_hash !== incident.revision_hash) throw new Error("tampered");
      const links = this.database.query("SELECT observation_revision_id FROM phase7_incident_observations WHERE incident_id=? ORDER BY observation_revision_id").all(incidentId) as Array<{ observation_revision_id: string }>;
      if (links.length !== incident.observation_ids.length || links.some(link => !incident.observation_ids.includes(link.observation_revision_id))) throw new Error("tampered");
      for (const link of links) {
        const observationRow = this.database.query("SELECT observation_id FROM phase7_observation_revisions WHERE revision_id=?").get(link.observation_revision_id) as { observation_id: string } | null;
        const observation = observationRow ? this.getObservation(observationRow.observation_id) : null;
        if (!observation || !samePhase7Scope(observation.scope, incident.scope)) throw new Error("tampered");
      }
      return incident;
    } catch (error) {
      if (error instanceof Error && error.message === "PHASE7_PERSISTENCE_TAMPERED") throw error;
      throw new Error("PHASE7_PERSISTENCE_TAMPERED");
    }
  }

  listIncidents(scope: Phase7Scope): Incident[] {
    const rows = this.database.query("SELECT incident_id FROM phase7_incidents WHERE scope_type=? AND scope_id=? ORDER BY incident_id").all(scope.type, scope.id) as Array<{ incident_id: string }>;
    return rows.map(row => this.getIncidentRequired(row.incident_id));
  }

  appendIncident(incidentInput: Incident, eventType: string, payload: Record<string, unknown>): Incident {
    const incident = parseIncident(incidentInput);
    return this.transaction(() => {
      const current = this.getIncidentRequired(incident.incident_id);
      if (incident.revision !== current.revision + 1 || incident.previous_revision_hash !== current.revision_hash || !samePhase7Scope(incident.scope, current.scope)) throw new Error("PHASE7_INCIDENT_REVISION_CONFLICT");
      this.insertIncidentRevision(incident);
      this.database.query("UPDATE phase7_incidents SET current_revision=?, current_revision_hash=?, status=?, payload_json=? WHERE incident_id=? AND current_revision=?")
        .run(incident.revision, incident.revision_hash, incident.status, JSON.stringify(incident), incident.incident_id, current.revision);
      for (const observationId of incident.observation_ids.filter(id => !current.observation_ids.includes(id))) {
        this.database.query("INSERT INTO phase7_incident_observations (incident_id, observation_revision_id, linked_at) VALUES (?, ?, ?)").run(incident.incident_id, observationId, incident.change.at);
      }
      this.appendAudit(incident.incident_id, eventType, payload, incident.change.at);
      return this.getIncidentRequired(incident.incident_id);
    });
  }

  saveRecord(kind: IncidentRecordKind, input: { record_id: string; incident_id: string; scope_id: string; occurred_at: string; payload: Record<string, unknown> }): PersistedIncidentRecord {
    assertSecretSafe(input);
    const table = recordTables[kind];
    const payloadHash = canonicalSha256(input.payload);
    return this.transaction(() => {
      const existing = this.database.query(`SELECT * FROM ${table} WHERE record_id=?`).get(input.record_id) as Record<string, unknown> | null;
      if (existing) {
        const decoded = decodeRecord(existing);
        if (decoded.payload_hash !== payloadHash) throw new Error("PHASE7_RECORD_IDEMPOTENCY_CONFLICT");
        return decoded;
      }
      const incident = this.getIncidentRequired(input.incident_id);
      if (incident.scope.id !== input.scope_id) throw new Error("PHASE7_RECORD_SCOPE_MISMATCH");
      this.database.query(`INSERT INTO ${table} (record_id, incident_id, scope_id, occurred_at, payload_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?)`)
        .run(input.record_id, input.incident_id, input.scope_id, input.occurred_at, payloadHash, JSON.stringify(input.payload));
      this.appendAudit(input.incident_id, kind, { record_id: input.record_id, payload_hash: payloadHash }, input.occurred_at);
      return { ...input, payload_hash: payloadHash };
    });
  }

  records(kind: IncidentRecordKind, incidentId: string): PersistedIncidentRecord[] {
    const rows = this.database.query(`SELECT * FROM ${recordTables[kind]} WHERE incident_id=? ORDER BY occurred_at, record_id`).all(incidentId) as Array<Record<string, unknown>>;
    return rows.map(row => {
      const value = decodeRecord(row);
      if (this.getIncidentRequired(incidentId).scope.id !== value.scope_id) throw new Error("PHASE7_PERSISTENCE_TAMPERED");
      return value;
    });
  }

  auditEvents(incidentId: string): Array<Record<string, unknown>> {
    const rows = this.database.query("SELECT * FROM phase7_audit_events WHERE incident_id=? ORDER BY sequence").all(incidentId) as Array<Record<string, unknown>>;
    return rows.map(row => {
      try {
        const payload = JSON.parse(String(row.payload_json)) as Record<string, unknown>;
        if (canonicalSha256(payload) !== row.payload_hash || payload.event_id !== row.event_id || payload.incident_id !== row.incident_id || payload.sequence !== row.sequence || payload.event_type !== row.event_type || payload.occurred_at !== row.occurred_at) throw new Error("tampered");
        return payload;
      } catch { throw new Error("PHASE7_PERSISTENCE_TAMPERED"); }
    });
  }

  relations(incidentId: string): IncidentRelation[] {
    const rows = this.database.query("SELECT payload_json, payload_hash FROM phase7_incident_relations WHERE incident_id=? OR related_incident_id=? ORDER BY relation_id").all(incidentId, incidentId) as Array<{ payload_json: string; payload_hash: string }>;
    return rows.map(row => {
      const payload = JSON.parse(row.payload_json) as IncidentRelation;
      if (canonicalSha256(payload) !== row.payload_hash) throw new Error("PHASE7_PERSISTENCE_TAMPERED");
      return payload;
    });
  }

  timeline(incidentId: string): Array<Record<string, unknown>> {
    return this.auditEvents(incidentId);
  }
  provenance(incidentId: string): Record<string, unknown> {
    const incident = this.getIncidentRequired(incidentId);
    return { incident_id: incidentId, revision_hash: incident.revision_hash, observation_revision_ids: incident.observation_ids, audit_event_ids: this.auditEvents(incidentId).map(event => event.event_id) };
  }
  health(): Record<string, unknown> {
    const integrity = this.database.query("PRAGMA integrity_check").get() as Record<string, unknown>;
    const journal = this.database.query("PRAGMA journal_mode").get() as Record<string, unknown>;
    return { status: Object.values(integrity)[0] === "ok" ? "HEALTHY" : "DEGRADED", journal_mode: String(Object.values(journal)[0]).toLowerCase(), incidents: Number((this.database.query("SELECT COUNT(*) AS count FROM phase7_incidents").get() as { count: number }).count) };
  }

  private insertObservation(observation: FailureObservation): void {
    const parsed = parseFailureObservation(observation);
    this.database.query("INSERT INTO phase7_observation_revisions (revision_id, observation_id, revision, previous_revision_id, previous_observation_hash, scope_type, scope_id, canonical_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(parsed.revision_id, parsed.observation_id, parsed.revision, parsed.previous_revision_id, parsed.previous_observation_hash, parsed.scope.type, parsed.scope.id, parsed.canonical_hash, JSON.stringify(parsed));
    this.database.query("INSERT INTO phase7_observations (observation_id, current_revision_id, current_revision, scope_type, scope_id, canonical_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(parsed.observation_id, parsed.revision_id, parsed.revision, parsed.scope.type, parsed.scope.id, parsed.canonical_hash, JSON.stringify(parsed));
  }
  private insertSignature(input: IngestionPersistenceInput): void {
    const payload = { ...input.signatures, provider: input.provider, runtime: input.runtime, runtime_major: input.runtime_major, scope: input.observation.scope };
    this.database.query("INSERT INTO phase7_signatures (observation_id, scope_type, scope_id, normalized_signature, structural_signature, exact_hash, environment_fingerprint, provider, runtime, runtime_major, payload_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(input.observation.observation_id, input.observation.scope.type, input.observation.scope.id, input.signatures.normalized_signature, input.signatures.structural_signature, input.signatures.exact_hash, input.signatures.environment_fingerprint, input.provider, input.runtime, input.runtime_major, canonicalSha256(payload), JSON.stringify(payload));
  }
  private insertIncident(incident: Incident): void {
    const parsed = parseIncident(incident);
    this.insertIncidentRevision(parsed);
    this.database.query("INSERT INTO phase7_incidents (incident_id, current_revision, current_revision_hash, scope_type, scope_id, status, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(parsed.incident_id, parsed.revision, parsed.revision_hash, parsed.scope.type, parsed.scope.id, parsed.status, JSON.stringify(parsed));
  }
  private insertIncidentRevision(incident: Incident): void {
    this.database.query("INSERT INTO phase7_incident_revisions (incident_id, revision, revision_hash, previous_revision_hash, scope_type, scope_id, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(incident.incident_id, incident.revision, incident.revision_hash, incident.previous_revision_hash, incident.scope.type, incident.scope.id, JSON.stringify(incident));
  }
  private insertRelation(relation: IncidentRelation): void {
    const payloadHash = canonicalSha256(relation);
    this.database.query("INSERT INTO phase7_incident_relations (relation_id, incident_id, related_incident_id, relation_type, payload_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?)")
      .run(relation.relation_id, relation.incident_id, relation.related_incident_id, relation.relation_type, payloadHash, JSON.stringify(relation));
  }
  private appendAudit(incidentId: string, eventType: string, payload: Record<string, unknown>, occurredAt: string): void {
    const sequence = Number((this.database.query("SELECT COALESCE(MAX(sequence), 0) + 1 AS next FROM phase7_audit_events WHERE incident_id=?").get(incidentId) as { next: number }).next);
    const event = { event_id: `audit:${canonicalSha256({ incident_id: incidentId, sequence, event_type: eventType }).slice(7, 39)}`, incident_id: incidentId, sequence, event_type: eventType, occurred_at: occurredAt, payload };
    this.database.query("INSERT INTO phase7_audit_events (event_id, incident_id, sequence, event_type, occurred_at, payload_hash, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(event.event_id, incidentId, sequence, eventType, occurredAt, canonicalSha256(event), JSON.stringify(event));
  }
  private existingIngestion(sourceEventId: string, sourceHash: string): IngestionPersistenceResult | null {
    const existing = this.database.query("SELECT * FROM phase7_ingestions WHERE source_event_id=?").get(sourceEventId) as Record<string, unknown> | null;
    if (!existing) return null;
    if (existing.source_hash !== sourceHash) throw new Error("PHASE7_INGESTION_IDEMPOTENCY_CONFLICT");
    const stored = parseHashedPayload<IngestionPersistenceResult>(String(existing.payload_json), "result_hash");
    if (stored.observation_id !== existing.observation_id || stored.incident_id !== existing.incident_id || stored.result_hash !== existing.result_hash || stored.created !== true || stored.duplicate !== false) throw new Error("PHASE7_PERSISTENCE_TAMPERED");
    return { ...stored, created: false, duplicate: true };
  }
  private getIncidentRequired(incidentId: string): Incident { return this.getIncident(incidentId) ?? fail("PHASE7_INCIDENT_NOT_FOUND"); }
}

function decodeRecord(row: Record<string, unknown>): PersistedIncidentRecord {
  try {
    const payload = JSON.parse(String(row.payload_json)) as Record<string, unknown>;
    if (canonicalSha256(payload) !== row.payload_hash) throw new Error("tampered");
    return { record_id: String(row.record_id), incident_id: String(row.incident_id), scope_id: String(row.scope_id), occurred_at: String(row.occurred_at), payload_hash: String(row.payload_hash), payload };
  } catch { throw new Error("PHASE7_PERSISTENCE_TAMPERED"); }
}
function decodeSignatureRow(row: Record<string, unknown>): {
  observation_id: string; normalized_signature: string; structural_signature: string; provider: string; runtime: string; runtime_major: number;
} {
  try {
    const payload = JSON.parse(String(row.payload_json)) as Record<string, unknown>;
    const scope = payload.scope as { type?: unknown; id?: unknown };
    if (canonicalSha256(payload) !== row.payload_hash
      || payload.normalized_signature !== row.normalized_signature
      || payload.structural_signature !== row.structural_signature
      || payload.exact_hash !== row.exact_hash
      || payload.environment_fingerprint !== row.environment_fingerprint
      || payload.provider !== row.provider
      || payload.runtime !== row.runtime
      || payload.runtime_major !== row.runtime_major
      || scope.type !== row.scope_type || scope.id !== row.scope_id
      || row.scope_type !== row.observation_scope_type || row.scope_id !== row.observation_scope_id
      || typeof row.observation_id !== "string" || typeof row.incident_id !== "string") throw new Error("tampered");
    for (const hash of [payload.normalized_signature, payload.structural_signature, payload.exact_hash, payload.environment_fingerprint]) {
      if (typeof hash !== "string" || !/^sha256:[a-f0-9]{64}$/.test(hash)) throw new Error("tampered");
    }
    if (typeof payload.provider !== "string" || typeof payload.runtime !== "string" || !Number.isSafeInteger(payload.runtime_major)) throw new Error("tampered");
    return { observation_id: row.observation_id, normalized_signature: payload.normalized_signature as string, structural_signature: payload.structural_signature as string, provider: payload.provider, runtime: payload.runtime, runtime_major: payload.runtime_major as number };
  } catch { throw new Error("PHASE7_PERSISTENCE_TAMPERED"); }
}
function parseHashedPayload<T extends object>(json: string, hashKey: keyof T): T {
  try {
    const value = JSON.parse(json) as T;
    const { [hashKey]: hash, ...payload } = value;
    if (canonicalSha256(payload) !== hash) throw new Error("tampered");
    return value;
  } catch { throw new Error("PHASE7_PERSISTENCE_TAMPERED"); }
}
function assertSecretSafe(value: unknown): void {
  try { assertNoStructuredPhase1Secret(value); assertNoPhase1Secret(JSON.stringify(value), "Phase 7 incident record"); }
  catch { throw new Error("PHASE7_RECORD_SECRET_REJECTED"); }
}
function fail(message: string): never { throw new Error(message); }
