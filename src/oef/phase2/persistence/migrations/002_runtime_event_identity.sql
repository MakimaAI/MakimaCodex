CREATE TABLE phase2_runtime_event_receipts (
  runtime_event_id TEXT PRIMARY KEY,
  execution_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK (sequence > 0),
  runtime_event_hash TEXT NOT NULL,
  phase2_event_id TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  UNIQUE (attempt_id, sequence),
  FOREIGN KEY (execution_id) REFERENCES phase2_executions(execution_id),
  FOREIGN KEY (attempt_id) REFERENCES phase2_attempts(attempt_id),
  FOREIGN KEY (phase2_event_id) REFERENCES phase2_events(event_id)
);

CREATE INDEX phase2_runtime_receipts_execution_idx
  ON phase2_runtime_event_receipts(execution_id, attempt_id, sequence);

CREATE TRIGGER phase2_runtime_receipt_no_update
BEFORE UPDATE ON phase2_runtime_event_receipts
BEGIN
  SELECT RAISE(ABORT, 'phase2 runtime event receipts are append-only');
END;

CREATE TRIGGER phase2_runtime_receipt_no_delete
BEFORE DELETE ON phase2_runtime_event_receipts
BEGIN
  SELECT RAISE(ABORT, 'phase2 runtime event receipts are append-only');
END;
