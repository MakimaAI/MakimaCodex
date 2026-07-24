ALTER TABLE contract_revisions ADD COLUMN document_json TEXT;

UPDATE contract_revisions
SET document_json = revision_json
WHERE document_json IS NULL;

CREATE TRIGGER IF NOT EXISTS approved_contract_content_immutable
BEFORE UPDATE ON contract_revisions
WHEN OLD.status = 'APPROVED' AND (
  NEW.document_json IS NOT OLD.document_json OR
  NEW.canonical_hash IS NOT OLD.canonical_hash OR
  NEW.revision_number IS NOT OLD.revision_number OR
  NEW.task_id IS NOT OLD.task_id
)
BEGIN
  SELECT RAISE(ABORT, 'approved contract content is immutable');
END;
