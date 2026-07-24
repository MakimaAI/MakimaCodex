CREATE TABLE IF NOT EXISTS phase3_review_validity_baselines (
  review_plan_id TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK (revision > 0),
  baseline_hash TEXT NOT NULL,
  baseline_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (review_plan_id, revision),
  FOREIGN KEY (review_plan_id, revision) REFERENCES phase3_review_plan_revisions(review_plan_id, revision)
);

CREATE TRIGGER IF NOT EXISTS phase3_review_validity_no_update
BEFORE UPDATE ON phase3_review_validity_baselines
BEGIN SELECT RAISE(ABORT, 'phase3 review validity baselines are immutable'); END;

CREATE TRIGGER IF NOT EXISTS phase3_review_validity_no_delete
BEFORE DELETE ON phase3_review_validity_baselines
BEGIN SELECT RAISE(ABORT, 'phase3 review validity baselines are immutable'); END;
