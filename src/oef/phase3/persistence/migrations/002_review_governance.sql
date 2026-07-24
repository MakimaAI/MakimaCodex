CREATE TABLE IF NOT EXISTS phase3_reviewer_bindings (
  reviewer_binding_id TEXT PRIMARY KEY,
  review_unit_id TEXT NOT NULL,
  binding_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS phase3_review_executions (
  review_execution_id TEXT PRIMARY KEY,
  review_plan_id TEXT NOT NULL,
  review_unit_id TEXT NOT NULL,
  reviewer_binding_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  attempt_number INTEGER NOT NULL CHECK (attempt_number > 0),
  aggregate_version INTEGER NOT NULL CHECK (aggregate_version > 0),
  execution_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (reviewer_binding_id) REFERENCES phase3_reviewer_bindings(reviewer_binding_id)
);

CREATE INDEX IF NOT EXISTS phase3_review_executions_plan_idx
  ON phase3_review_executions(review_plan_id, review_unit_id, attempt_number);

CREATE TABLE IF NOT EXISTS phase3_finding_validations (
  finding_validation_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  review_plan_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  validation_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS phase3_validations_plan_idx
  ON phase3_finding_validations(review_plan_id, finding_id, created_at);

CREATE TABLE IF NOT EXISTS phase3_review_decisions (
  review_decision_id TEXT PRIMARY KEY,
  review_plan_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  decision TEXT NOT NULL,
  decision_json TEXT NOT NULL,
  issued_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS phase3_decisions_plan_idx
  ON phase3_review_decisions(review_plan_id, issued_at, review_decision_id);

CREATE TABLE IF NOT EXISTS phase3_review_waivers (
  waiver_id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  waiver_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS phase3_repair_proposals (
  repair_proposal_id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL,
  source_review_plan_id TEXT NOT NULL,
  proposal_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS phase3_binding_no_update
BEFORE UPDATE ON phase3_reviewer_bindings
BEGIN SELECT RAISE(ABORT, 'phase3 reviewer bindings are immutable'); END;
CREATE TRIGGER IF NOT EXISTS phase3_binding_no_delete
BEFORE DELETE ON phase3_reviewer_bindings
BEGIN SELECT RAISE(ABORT, 'phase3 reviewer bindings are immutable'); END;

CREATE TRIGGER IF NOT EXISTS phase3_validation_no_update
BEFORE UPDATE ON phase3_finding_validations
BEGIN SELECT RAISE(ABORT, 'phase3 finding validations are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase3_validation_no_delete
BEFORE DELETE ON phase3_finding_validations
BEGIN SELECT RAISE(ABORT, 'phase3 finding validations are append-only'); END;

CREATE TRIGGER IF NOT EXISTS phase3_decision_no_update
BEFORE UPDATE ON phase3_review_decisions
BEGIN SELECT RAISE(ABORT, 'phase3 review decisions are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase3_decision_no_delete
BEFORE DELETE ON phase3_review_decisions
BEGIN SELECT RAISE(ABORT, 'phase3 review decisions are append-only'); END;

CREATE TRIGGER IF NOT EXISTS phase3_waiver_no_update
BEFORE UPDATE ON phase3_review_waivers
BEGIN SELECT RAISE(ABORT, 'phase3 review waivers are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase3_waiver_no_delete
BEFORE DELETE ON phase3_review_waivers
BEGIN SELECT RAISE(ABORT, 'phase3 review waivers are append-only'); END;

CREATE TRIGGER IF NOT EXISTS phase3_repair_no_update
BEFORE UPDATE ON phase3_repair_proposals
BEGIN SELECT RAISE(ABORT, 'phase3 repair proposals are append-only'); END;
CREATE TRIGGER IF NOT EXISTS phase3_repair_no_delete
BEFORE DELETE ON phase3_repair_proposals
BEGIN SELECT RAISE(ABORT, 'phase3 repair proposals are append-only'); END;
