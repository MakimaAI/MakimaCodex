CREATE TABLE IF NOT EXISTS workflow_definitions (
  workflow_id TEXT NOT NULL,
  version TEXT NOT NULL,
  definition_hash TEXT NOT NULL,
  definition_json TEXT NOT NULL,
  PRIMARY KEY (workflow_id, version)
);

CREATE TABLE IF NOT EXISTS policy_packs (
  policy_pack_id TEXT NOT NULL,
  version TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  PRIMARY KEY (policy_pack_id, version)
);

CREATE TABLE IF NOT EXISTS tasks (
  task_id TEXT PRIMARY KEY,
  aggregate_version INTEGER NOT NULL CHECK (aggregate_version >= 0),
  status TEXT NOT NULL,
  stage TEXT NOT NULL,
  task_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contract_revisions (
  revision_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  revision_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  canonical_hash TEXT NOT NULL,
  revision_json TEXT NOT NULL,
  UNIQUE (task_id, revision_number)
);

CREATE TABLE IF NOT EXISTS acceptance_criteria (
  criterion_id TEXT PRIMARY KEY,
  revision_id TEXT NOT NULL REFERENCES contract_revisions(revision_id),
  criterion_key TEXT NOT NULL,
  criterion_json TEXT NOT NULL,
  UNIQUE (revision_id, criterion_key)
);

CREATE TABLE IF NOT EXISTS approvals (
  approval_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  subject_type TEXT NOT NULL,
  subject_id TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  approval_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workflow_instances (
  task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
  workflow_id TEXT NOT NULL,
  workflow_version TEXT NOT NULL,
  workflow_hash TEXT NOT NULL,
  current_stage TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_records (
  evidence_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  revision_id TEXT NOT NULL REFERENCES contract_revisions(revision_id),
  criterion_key TEXT NOT NULL,
  status TEXT NOT NULL,
  evidence_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  content_hash TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  artifact_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS verdicts (
  verdict_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  revision_id TEXT NOT NULL REFERENCES contract_revisions(revision_id),
  status TEXT NOT NULL,
  decision TEXT NOT NULL,
  verdict_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  previous_event_hash TEXT,
  event_hash TEXT NOT NULL,
  event_json TEXT NOT NULL,
  UNIQUE (aggregate_type, aggregate_id, aggregate_version)
);

CREATE TABLE IF NOT EXISTS outbox (
  outbox_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id TEXT NOT NULL UNIQUE REFERENCES events(event_id),
  aggregate_id TEXT NOT NULL,
  event_json TEXT NOT NULL,
  processed_at TEXT
);

CREATE TABLE IF NOT EXISTS idempotency_records (
  idempotency_key TEXT PRIMARY KEY,
  command_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS read_task_summary (
  task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
  summary_json TEXT NOT NULL,
  projection_version INTEGER NOT NULL
);
