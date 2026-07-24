# ADR 0007: Require a versioned Task Contract before OEF execution

## Status

Accepted

## Context

Natural-language tasks can be reinterpreted during a long agent run. Helpful-looking scope expansion
can change files, cost, network access, or risk without the user seeing a new agreement. Acceptance
also becomes subjective when completion criteria are absent.

## Decision

OEF uses a strict `oef.task-contract/v1` document with stable task identity, monotonic revision,
risk reasons, explicit read/write/deny scope, constraints, a permission-envelope reference, and at
least one testable acceptance criterion.

Any substantive content change increments the revision by exactly one, references the immediately
prior revision, and returns to draft. A changed contract requires new approval. Draft-to-approved is
an explicit same-revision transition that permits no other field change. Unknown schema fields,
duplicate acceptance ids, revision gaps, and approval timestamps before creation are rejected.

## Consequences

- Silent scope expansion becomes an invalid contract transition.
- Acceptance criteria can be mapped to evidence and verifiers in phase one.
- Old and new task intent remain reconstructable in an audit ledger.
- Minor changes carry revision overhead, which is intentional for an autonomous execution system.
- Phase zero validates the boundary but does not yet persist or schedule contracts.
