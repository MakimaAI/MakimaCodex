# ADR-005: Command Idempotency and Optimistic Concurrency

Status: Accepted

## Decision

Require `idempotency_key` and `expected_aggregate_version` on every command. Persist the first successful result in the same transaction as its effects.

## Consequences

Network retries return the first result and create no duplicate state or events. Competing writers cannot overwrite each other: one advances the aggregate, stale writers receive a structured concurrency conflict.
