CREATE TABLE IF NOT EXISTS phase7_observations (
  observation_id TEXT PRIMARY KEY,
  current_revision_id TEXT NOT NULL UNIQUE,
  current_revision INTEGER NOT NULL CHECK(current_revision > 0),
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS phase7_observation_revisions (
  revision_id TEXT PRIMARY KEY,
  observation_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision > 0),
  previous_revision_id TEXT,
  previous_observation_hash TEXT,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(observation_id, revision)
);
CREATE TABLE IF NOT EXISTS phase7_signatures (
  observation_id TEXT PRIMARY KEY,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  normalized_signature TEXT NOT NULL,
  structural_signature TEXT NOT NULL,
  exact_hash TEXT NOT NULL,
  environment_fingerprint TEXT NOT NULL,
  provider TEXT NOT NULL,
  runtime TEXT NOT NULL,
  runtime_major INTEGER NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS phase7_signature_correlation ON phase7_signatures(scope_type, scope_id, normalized_signature, structural_signature, provider, runtime, runtime_major);
CREATE TABLE IF NOT EXISTS phase7_incidents (
  incident_id TEXT PRIMARY KEY,
  current_revision INTEGER NOT NULL CHECK(current_revision > 0),
  current_revision_hash TEXT NOT NULL UNIQUE,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  status TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS phase7_incident_revisions (
  incident_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision > 0),
  revision_hash TEXT NOT NULL UNIQUE,
  previous_revision_hash TEXT,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY(incident_id, revision)
);
CREATE TABLE IF NOT EXISTS phase7_incident_observations (
  incident_id TEXT NOT NULL,
  observation_revision_id TEXT NOT NULL,
  linked_at TEXT NOT NULL,
  PRIMARY KEY(incident_id, observation_revision_id)
);
CREATE TABLE IF NOT EXISTS phase7_ingestions (
  source_event_id TEXT PRIMARY KEY,
  source_hash TEXT NOT NULL,
  observation_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  result_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS phase7_audit_events (
  event_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence > 0),
  event_type TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(incident_id, sequence)
);
CREATE TABLE IF NOT EXISTS phase7_incident_relations (
  relation_id TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  related_incident_id TEXT NOT NULL,
  relation_type TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(incident_id, related_incident_id, relation_type)
);

CREATE TABLE IF NOT EXISTS phase7_triage_records (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_containment_records (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_reproduction_manifests (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_reproduction_results (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_hypothesis_evidence (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_root_causes (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_remediation_proposals (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_regression_results (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_review_verdicts (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_playbook_candidates (record_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, occurred_at TEXT NOT NULL, payload_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS phase7_memory_write_batches (batch_id TEXT PRIMARY KEY, incident_id TEXT NOT NULL, scope_id TEXT NOT NULL, closure_revision_hash TEXT NOT NULL, batch_hash TEXT NOT NULL, payload_json TEXT NOT NULL);

CREATE TRIGGER IF NOT EXISTS phase7_observation_revision_update_block BEFORE UPDATE ON phase7_observation_revisions BEGIN SELECT RAISE(ABORT, 'phase7 observation revisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_observation_revision_delete_block BEFORE DELETE ON phase7_observation_revisions BEGIN SELECT RAISE(ABORT, 'phase7 observation revisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_incident_revision_update_block BEFORE UPDATE ON phase7_incident_revisions BEGIN SELECT RAISE(ABORT, 'phase7 incident revisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_incident_revision_delete_block BEFORE DELETE ON phase7_incident_revisions BEGIN SELECT RAISE(ABORT, 'phase7 incident revisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_observation_link_update_block BEFORE UPDATE ON phase7_incident_observations BEGIN SELECT RAISE(ABORT, 'phase7 observation links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_observation_link_delete_block BEFORE DELETE ON phase7_incident_observations BEGIN SELECT RAISE(ABORT, 'phase7 observation links are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_audit_update_block BEFORE UPDATE ON phase7_audit_events BEGIN SELECT RAISE(ABORT, 'phase7 audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_audit_delete_block BEFORE DELETE ON phase7_audit_events BEGIN SELECT RAISE(ABORT, 'phase7 audit events are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_relation_update_block BEFORE UPDATE ON phase7_incident_relations BEGIN SELECT RAISE(ABORT, 'phase7 incident relations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_relation_delete_block BEFORE DELETE ON phase7_incident_relations BEGIN SELECT RAISE(ABORT, 'phase7 incident relations are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_signature_update_block BEFORE UPDATE ON phase7_signatures BEGIN SELECT RAISE(ABORT, 'phase7 signatures are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_signature_delete_block BEFORE DELETE ON phase7_signatures BEGIN SELECT RAISE(ABORT, 'phase7 signatures are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_ingestion_update_block BEFORE UPDATE ON phase7_ingestions BEGIN SELECT RAISE(ABORT, 'phase7 ingestions are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_ingestion_delete_block BEFORE DELETE ON phase7_ingestions BEGIN SELECT RAISE(ABORT, 'phase7 ingestions are immutable'); END;

CREATE TRIGGER IF NOT EXISTS phase7_triage_update_block BEFORE UPDATE ON phase7_triage_records BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_triage_delete_block BEFORE DELETE ON phase7_triage_records BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_containment_update_block BEFORE UPDATE ON phase7_containment_records BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_containment_delete_block BEFORE DELETE ON phase7_containment_records BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_reproduction_manifest_update_block BEFORE UPDATE ON phase7_reproduction_manifests BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_reproduction_manifest_delete_block BEFORE DELETE ON phase7_reproduction_manifests BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_reproduction_update_block BEFORE UPDATE ON phase7_reproduction_results BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_reproduction_delete_block BEFORE DELETE ON phase7_reproduction_results BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_hypothesis_update_block BEFORE UPDATE ON phase7_hypothesis_evidence BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_hypothesis_delete_block BEFORE DELETE ON phase7_hypothesis_evidence BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_root_cause_update_block BEFORE UPDATE ON phase7_root_causes BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_root_cause_delete_block BEFORE DELETE ON phase7_root_causes BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_remediation_update_block BEFORE UPDATE ON phase7_remediation_proposals BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_remediation_delete_block BEFORE DELETE ON phase7_remediation_proposals BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_regression_update_block BEFORE UPDATE ON phase7_regression_results BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_regression_delete_block BEFORE DELETE ON phase7_regression_results BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_review_update_block BEFORE UPDATE ON phase7_review_verdicts BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_review_delete_block BEFORE DELETE ON phase7_review_verdicts BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_playbook_update_block BEFORE UPDATE ON phase7_playbook_candidates BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_playbook_delete_block BEFORE DELETE ON phase7_playbook_candidates BEGIN SELECT RAISE(ABORT, 'phase7 records are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase7_memory_batch_update_block BEFORE UPDATE ON phase7_memory_write_batches BEGIN SELECT RAISE(ABORT, 'phase7 memory batches are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase7_memory_batch_delete_block BEFORE DELETE ON phase7_memory_write_batches BEGIN SELECT RAISE(ABORT, 'phase7 memory batches are immutable'); END;
