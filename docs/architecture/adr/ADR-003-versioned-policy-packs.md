# ADR-003: Versioned Declarative Policy Packs

Status: Accepted

## Decision

Represent configurable authorization and evidence requirements as strict declarative JSON, pinned to tasks by id, version, and hash. Do not execute policy JavaScript in Phase 1.

## Consequences

Policy decisions are reproducible and attributable. A new policy version cannot silently alter an existing task. Hard security invariants remain ordinary code and database constraints.
