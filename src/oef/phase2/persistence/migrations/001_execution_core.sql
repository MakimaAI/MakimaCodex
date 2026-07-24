CREATE TABLE IF NOT EXISTS phase2_assignment_revisions (
  assignment_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  assignment_hash TEXT NOT NULL,
  assignment_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (assignment_id, revision)
);

CREATE INDEX IF NOT EXISTS phase2_assignments_task_idx
  ON phase2_assignment_revisions(task_id, assignment_id, revision);

CREATE TABLE IF NOT EXISTS phase2_bindings (
  binding_id TEXT PRIMARY KEY,
  assignment_id TEXT NOT NULL,
  assignment_revision INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  binding_hash TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (assignment_id, assignment_revision)
    REFERENCES phase2_assignment_revisions(assignment_id, revision)
);

CREATE TABLE IF NOT EXISTS phase2_executions (
  execution_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  assignment_id TEXT NOT NULL,
  assignment_revision INTEGER NOT NULL,
  binding_id TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL,
  status TEXT NOT NULL,
  execution_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (assignment_id, assignment_revision)
    REFERENCES phase2_assignment_revisions(assignment_id, revision),
  FOREIGN KEY (binding_id) REFERENCES phase2_bindings(binding_id)
);

CREATE INDEX IF NOT EXISTS phase2_executions_task_idx
  ON phase2_executions(task_id, created_at);

CREATE TABLE IF NOT EXISTS phase2_attempts (
  attempt_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  status TEXT NOT NULL,
  attempt_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (execution_id, attempt_number),
  FOREIGN KEY (execution_id) REFERENCES phase2_executions(execution_id)
);

CREATE TABLE IF NOT EXISTS phase2_events (
  event_id TEXT PRIMARY KEY,
  event_type TEXT NOT NULL,
  aggregate_type TEXT NOT NULL,
  aggregate_id TEXT NOT NULL,
  aggregate_version INTEGER NOT NULL,
  task_id TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  actor_json TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  previous_event_hash TEXT,
  event_hash TEXT NOT NULL UNIQUE,
  event_json TEXT NOT NULL,
  UNIQUE (aggregate_id, aggregate_version)
);

CREATE INDEX IF NOT EXISTS phase2_events_task_idx
  ON phase2_events(task_id, occurred_at, event_id);

CREATE TABLE IF NOT EXISTS phase2_outbox (
  event_id TEXT PRIMARY KEY,
  event_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  dispatched_at TEXT,
  FOREIGN KEY (event_id) REFERENCES phase2_events(event_id)
);

CREATE TABLE IF NOT EXISTS phase2_idempotency (
  idempotency_key TEXT PRIMARY KEY,
  command_hash TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS phase2_assignment_no_update
BEFORE UPDATE ON phase2_assignment_revisions
BEGIN
  SELECT RAISE(ABORT, 'phase2 assignment revisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase2_assignment_no_delete
BEFORE DELETE ON phase2_assignment_revisions
BEGIN
  SELECT RAISE(ABORT, 'phase2 assignment revisions are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase2_binding_no_update
BEFORE UPDATE ON phase2_bindings
BEGIN
  SELECT RAISE(ABORT, 'phase2 bindings are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase2_binding_no_delete
BEFORE DELETE ON phase2_bindings
BEGIN
  SELECT RAISE(ABORT, 'phase2 bindings are immutable');
END;

CREATE TRIGGER IF NOT EXISTS phase2_event_no_update
BEFORE UPDATE ON phase2_events
BEGIN
  SELECT RAISE(ABORT, 'phase2 audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS phase2_event_no_delete
BEFORE DELETE ON phase2_events
BEGIN
  SELECT RAISE(ABORT, 'phase2 audit events are append-only');
END;
