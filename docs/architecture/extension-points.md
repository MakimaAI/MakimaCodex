# Extension Points

Phase 1 keeps the hard invariants small and exposes versioned extension points:

- Workflow definition files add task types and stages.
- Policy packs add declarative requirements.
- Namespaced contract extensions preserve plugin-specific data.
- Namespaced evidence types admit new verification tools.
- `ArtifactStore` admits local, S3, blob, or encrypted adapters.
- SQLite repository behavior can be replaced by a PostgreSQL adapter.
- `TraceExporter` admits JSONL or OpenTelemetry.
- Event outbox subscribers can add memory, notifications, analytics, webhooks, or TUI updates.
- `EventUpcaster` reads historical schemas without mutating stored events.

Unknown extension payloads must include `schema_version`, are round-tripped unchanged, and never change behavior unless a deliberately installed plugin validates and interprets that namespace.

Extension points cannot bypass immutable contracts, event append-only rules, idempotency, aggregate versions, secret rejection, artifact verification, or explicit terminal reopen.
