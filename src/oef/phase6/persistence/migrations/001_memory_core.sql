CREATE TABLE IF NOT EXISTS memory_records (
  memory_id TEXT PRIMARY KEY,
  current_revision_id TEXT NOT NULL UNIQUE,
  current_revision_number INTEGER NOT NULL CHECK(current_revision_number > 0),
  layer TEXT NOT NULL,
  kind TEXT NOT NULL,
  lifecycle_status TEXT NOT NULL,
  trust_level TEXT NOT NULL,
  trust_rank INTEGER NOT NULL,
  confidence REAL NOT NULL CHECK(confidence >= 0 AND confidence <= 1),
  sensitivity TEXT NOT NULL,
  sensitivity_rank INTEGER NOT NULL,
  valid_from TEXT NOT NULL,
  valid_until TEXT,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_revisions (
  revision_id TEXT PRIMARY KEY,
  memory_id TEXT NOT NULL,
  revision_number INTEGER NOT NULL CHECK(revision_number > 0),
  previous_revision_id TEXT,
  content_hash TEXT NOT NULL,
  provenance_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(memory_id, revision_number),
  FOREIGN KEY(memory_id) REFERENCES memory_records(memory_id) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS memory_scopes (
  revision_id TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  PRIMARY KEY(revision_id, scope_type, scope_id),
  FOREIGN KEY(revision_id) REFERENCES memory_revisions(revision_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS memory_scopes_lookup ON memory_scopes(scope_type, scope_id, revision_id);

CREATE TABLE IF NOT EXISTS memory_revision_roles (
  revision_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  PRIMARY KEY(revision_id, role_id),
  FOREIGN KEY(revision_id) REFERENCES memory_revisions(revision_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memory_relations (
  relation_id TEXT PRIMARY KEY,
  relation_type TEXT NOT NULL,
  from_memory_id TEXT NOT NULL,
  to_memory_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_provenance (
  revision_id TEXT NOT NULL,
  source_ref TEXT NOT NULL,
  PRIMARY KEY(revision_id, source_ref),
  FOREIGN KEY(revision_id) REFERENCES memory_revisions(revision_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memory_conflicts (
  conflict_id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_injection_ledger (
  execution_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  memory_revision_id TEXT NOT NULL,
  pack_hash TEXT NOT NULL,
  injected_at TEXT NOT NULL,
  PRIMARY KEY(execution_id, session_id, memory_revision_id)
);

CREATE TABLE IF NOT EXISTS memory_injection_deliveries (
  delivery_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  pack_id TEXT NOT NULL,
  pack_hash TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PREPARED', 'DELIVERED')),
  prepared_at TEXT NOT NULL,
  delivered_at TEXT
);

CREATE TABLE IF NOT EXISTS memory_injection_delivery_items (
  delivery_id TEXT NOT NULL,
  memory_revision_id TEXT NOT NULL,
  PRIMARY KEY(delivery_id, memory_revision_id),
  FOREIGN KEY(delivery_id) REFERENCES memory_injection_deliveries(delivery_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS memory_query_logs (
  query_id TEXT PRIMARY KEY,
  executed_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_context_packs (
  pack_id TEXT PRIMARY KEY,
  query_id TEXT NOT NULL,
  pack_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_tombstones (
  memory_id TEXT PRIMARY KEY,
  deleted_at TEXT NOT NULL,
  reason TEXT NOT NULL,
  mode TEXT NOT NULL,
  content_retained INTEGER NOT NULL CHECK(content_retained IN (0, 1))
);

CREATE TABLE IF NOT EXISTS memory_index_registry (
  index_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  status TEXT NOT NULL,
  version TEXT NOT NULL,
  rebuilt_at TEXT,
  metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS embedding_profiles (profile_id TEXT PRIMARY KEY, version TEXT NOT NULL, profile_hash TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_access_policies (policy_id TEXT PRIMARY KEY, version TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_candidates (candidate_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, status TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_feedback (feedback_id TEXT PRIMARY KEY, memory_id TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, priority INTEGER NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_job_attempts (attempt_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_retention_policies (policy_id TEXT PRIMARY KEY, version TEXT NOT NULL, payload_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory_health_snapshots (snapshot_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, payload_json TEXT NOT NULL);

CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
  revision_id UNINDEXED,
  memory_id UNINDEXED,
  summary,
  structured_json,
  tokenize = 'unicode61'
);

INSERT OR IGNORE INTO memory_index_registry(index_id, kind, status, version, metadata_json)
VALUES ('lexical@1', 'lexical', 'HEALTHY', '1.0.0', '{}');
