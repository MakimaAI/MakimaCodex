CREATE TABLE IF NOT EXISTS phase2_completion_sagas (
  execution_id TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('PREPARED', 'EXECUTION_COMPLETED', 'DONE')),
  saga_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (execution_id) REFERENCES phase2_executions(execution_id)
);

CREATE INDEX IF NOT EXISTS phase2_completion_sagas_status_idx
  ON phase2_completion_sagas(status, updated_at);
