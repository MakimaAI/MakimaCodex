UPDATE contract_revisions
SET document_json = json_extract(revision_json, '$.document')
WHERE document_json = revision_json
  AND json_valid(revision_json)
  AND json_type(revision_json, '$.document') = 'object';

CREATE TRIGGER IF NOT EXISTS approved_contract_revision_document_immutable
BEFORE UPDATE ON contract_revisions
WHEN OLD.status = 'APPROVED' AND (
  json_extract(NEW.revision_json, '$.document') IS NOT json_extract(OLD.revision_json, '$.document') OR
  NEW.document_json IS NOT OLD.document_json OR
  NEW.canonical_hash IS NOT OLD.canonical_hash OR
  NEW.revision_number IS NOT OLD.revision_number OR
  NEW.task_id IS NOT OLD.task_id
)
BEGIN
  SELECT RAISE(ABORT, 'approved contract authoritative content is immutable');
END;
