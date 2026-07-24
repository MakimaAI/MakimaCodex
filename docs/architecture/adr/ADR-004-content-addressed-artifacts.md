# ADR-004: Content-Addressed Artifacts

Status: Accepted

## Decision

Store artifact bytes outside SQLite under a SHA-256-derived key. Keep metadata and references in SQLite and verify content before evidence verification or task integrity success.

## Consequences

Large output does not inflate the database, identical bytes are physically deduplicated, and corruption is observable. Callers cannot choose paths; secret, size, traversal, and symlink controls are mandatory in adapters.
