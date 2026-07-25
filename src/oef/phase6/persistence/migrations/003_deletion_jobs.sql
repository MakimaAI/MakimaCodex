CREATE TABLE IF NOT EXISTS memory_deletion_jobs (
  job_id TEXT PRIMARY KEY,
  root_memory_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PREPARED', 'ARTIFACTS_VERIFIED', 'COMPLETED', 'FAILED')),
  receipt_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  payload_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS memory_deletion_fences (
  reference_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('ACTIVE', 'COMPLETED')),
  created_at TEXT NOT NULL,
  FOREIGN KEY(job_id) REFERENCES memory_deletion_jobs(job_id)
);
