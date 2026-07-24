# Audit Events versus Operational Traces

Audit events represent durable business facts such as `contract.approved`, `evidence.verified`, or `verdict.issued`. They are written in the same SQLite transaction as current state and outbox rows. Their order is `aggregate.version`, never timestamp. Each event contains the previous event hash and its own canonical SHA-256 hash. SQLite triggers reject event update and deletion.

Trace spans represent operational detail such as policy evaluation duration. They are exported separately to `.opencodex/traces/YYYY-MM-DD.jsonl` through `TraceExporter`. Trace attributes are recursively redacted by sensitive key and token pattern. Trace failures do not rewrite audit history.

The event envelope links `trace_id`, `correlation_id`, and command `causation_id`, allowing operational diagnostics to correlate with a durable decision without embedding raw logs in the event.
