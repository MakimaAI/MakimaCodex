# Contract Versioning

Task Contracts use schema version 1 and contain goal, included/excluded scope, constraints, acceptance criteria, risk, budgets, and namespaced extensions.

The lifecycle is:

```text
DRAFT -> PROPOSED -> APPROVED
                  -> REJECTED
APPROVED -> SUPERSEDED when a newer revision is approved
```

Contract content is canonicalized by recursively sorting object keys, preserving array order and unknown extension data, then hashing canonical JSON with SHA-256. Approval records bind to this exact hash.

Revisions are append-only. Revision number must be the immediate successor and `parent_revision_id` must identify the previous revision. A machine-readable diff records added, changed, and removed criteria, constraint edits, and risk changes.

SQLite stores immutable `document_json` separately from mutable lifecycle metadata. A trigger prevents approved document, hash, task, or revision-number changes. Application commands expose no in-place contract update operation.
