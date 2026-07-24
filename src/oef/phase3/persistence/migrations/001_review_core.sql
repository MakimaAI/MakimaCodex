CREATE TABLE IF NOT EXISTS phase3_review_profiles (
  profile_id TEXT NOT NULL,
  version TEXT NOT NULL,
  content_hash TEXT NOT NULL UNIQUE,
  profile_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (profile_id, version)
);

CREATE TABLE IF NOT EXISTS phase3_review_requests (
  review_request_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  request_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS phase3_review_requests_task_idx
  ON phase3_review_requests(task_id, created_at);

CREATE TABLE IF NOT EXISTS phase3_review_plan_revisions (
  review_plan_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  review_request_id TEXT NOT NULL,
  task_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  plan_hash TEXT NOT NULL UNIQUE,
  plan_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (review_plan_id, revision),
  FOREIGN KEY (review_request_id) REFERENCES phase3_review_requests(review_request_id)
);

CREATE INDEX IF NOT EXISTS phase3_review_plans_task_idx
  ON phase3_review_plan_revisions(task_id, review_plan_id, revision);

CREATE TABLE IF NOT EXISTS phase3_review_plan_state (
  review_plan_id TEXT PRIMARY KEY,
  snapshot_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
  state_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS phase3_review_findings (
  finding_id TEXT PRIMARY KEY,
  finding_key TEXT NOT NULL,
  review_plan_id TEXT NOT NULL,
  review_unit_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  finding_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (review_plan_id, finding_key),
  FOREIGN KEY (review_plan_id) REFERENCES phase3_review_plan_state(review_plan_id)
);

CREATE INDEX IF NOT EXISTS phase3_findings_plan_status_idx
  ON phase3_review_findings(review_plan_id, status, finding_id);

CREATE TABLE IF NOT EXISTS phase3_review_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
  task_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  previous_event_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE,
  event_json TEXT NOT NULL,
  UNIQUE (aggregate_id, aggregate_version)
);

CREATE INDEX IF NOT EXISTS phase3_events_task_idx
  ON phase3_review_events(task_id, occurred_at, event_id);

CREATE TABLE IF NOT EXISTS phase3_idempotency (
  idempotency_key TEXT PRIMARY KEY,
  command_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS phase3_profile_no_update
BEFORE UPDATE ON phase3_review_profiles
BEGIN
  SELECT RAISE(ABORT, 'phase3 review profiles are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase3_profile_no_delete
BEFORE DELETE ON phase3_review_profiles
BEGIN
  SELECT RAISE(ABORT, 'phase3 review profiles are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase3_request_no_update
BEFORE UPDATE ON phase3_review_requests
BEGIN
  SELECT RAISE(ABORT, 'phase3 review requests are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase3_request_no_delete
BEFORE DELETE ON phase3_review_requests
BEGIN
  SELECT RAISE(ABORT, 'phase3 review requests are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase3_plan_no_update
BEFORE UPDATE ON phase3_review_plan_revisions
BEGIN
  SELECT RAISE(ABORT, 'phase3 review plan revisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase3_plan_no_delete
BEFORE DELETE ON phase3_review_plan_revisions
BEGIN
  SELECT RAISE(ABORT, 'phase3 review plan revisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase3_event_no_update
BEFORE UPDATE ON phase3_review_events
BEGIN
  SELECT RAISE(ABORT, 'phase3 audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase3_event_no_delete
BEFORE DELETE ON phase3_review_events
BEGIN
  SELECT RAISE(ABORT, 'phase3 audit events are append-only');
END;
