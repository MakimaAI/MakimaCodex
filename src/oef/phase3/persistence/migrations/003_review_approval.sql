CREATE TABLE IF NOT EXISTS phase3_human_review_approvals (
  approval_id TEXT PRIMARY KEY,
  review_plan_id TEXT NOT NULL,
  snapshot_hash TEXT NOT NULL,
  approval_json TEXT NOT NULL,
  approved_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS phase3_human_review_approvals_plan
  ON phase3_human_review_approvals(review_plan_id, approved_at, approval_id);

CREATE TRIGGER IF NOT EXISTS phase3_human_review_approval_no_update
BEFORE UPDATE ON phase3_human_review_approvals
BEGIN SELECT RAISE(ABORT, 'phase3 human review approvals are append-only'); END;

CREATE TRIGGER IF NOT EXISTS phase3_human_review_approval_no_delete
BEFORE DELETE ON phase3_human_review_approvals
BEGIN SELECT RAISE(ABORT, 'phase3 human review approvals are append-only'); END;
