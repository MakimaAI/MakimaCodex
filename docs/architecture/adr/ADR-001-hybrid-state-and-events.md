# ADR-001: Hybrid Current State and Events

Status: Accepted

## Decision

Keep normalized current-state tables for operational reads, append-only audit events for history, a transactional outbox for subscribers, and rebuildable projections. Do not use pure event sourcing.

## Consequences

Commands must write state, event, outbox, projection, and idempotency result in one transaction. Reads stay simple while event history remains independently verifiable. Projection rebuild tooling may be added without changing domain commands.
