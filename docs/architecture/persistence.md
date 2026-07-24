# Persistence

Phase 1 uses a hybrid design:

- current-state tables for fast reads;
- append-only audit events for history and integrity;
- transactional outbox rows for subscribers;
- content-addressed artifact files; and
- rebuildable task-summary projections.

SQLite runs with WAL mode, foreign keys enabled, a 5-second busy timeout, and immediate write transactions. A command serializes before reading the aggregate version, computes state, then writes state, event, outbox, projection, and idempotency result atomically. Injected failures after state or after event roll back the complete transaction. Busy errors are mapped to the domain `concurrency_conflict`; a barrier-controlled two-process test proves that two real connections cannot both commit the same aggregate version and reports the winning version as `actual`.

Migrations are ordered SQL files with stored SHA-256 checksums. Each applies once in a transaction. A checksum mismatch fails closed. Migration tests open an old `001_initial` fixture, preserve its row, and roll forward through later migrations without drop/recreate. A separate progressed-revision fixture proves wrapper-shaped `document_json` is repaired even when status changes made it differ from `revision_json`. The authoritative contract document lives in `document_json`; reads merge status metadata from `revision_json` with that protected document, and database triggers prevent approved content from changing through either column.

The application depends on the store port surface, while only the persistence adapter imports `bun:sqlite`.
