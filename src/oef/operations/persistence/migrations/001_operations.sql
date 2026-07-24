CREATE TABLE IF NOT EXISTS operation_jobs (
  job_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  priority INTEGER NOT NULL,
  max_attempts INTEGER NOT NULL CHECK(max_attempts > 0 AND max_attempts <= 30),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
  state TEXT NOT NULL,
  available_at TEXT NOT NULL,
  lease_owner TEXT,
  lease_expires_at TEXT,
  lease_acquired_at TEXT,
  run_started_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(kind, idempotency_key)
);
CREATE INDEX IF NOT EXISTS operation_jobs_claimable ON operation_jobs(state, available_at, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS operation_jobs_expiring ON operation_jobs(state, lease_expires_at);

CREATE TABLE IF NOT EXISTS operation_attempts (
  attempt_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  owner TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK(outcome IN ('SUCCEEDED', 'FAILED', 'LEASE_EXPIRED')),
  error TEXT,
  started_at TEXT NOT NULL,
  finished_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  UNIQUE(job_id, attempt_number),
  FOREIGN KEY(job_id) REFERENCES operation_jobs(job_id)
);
CREATE TABLE IF NOT EXISTS operation_effect_receipts (
  job_id TEXT PRIMARY KEY,
  effect_hash TEXT NOT NULL,
  succeeded_at TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  FOREIGN KEY(job_id) REFERENCES operation_jobs(job_id)
);
