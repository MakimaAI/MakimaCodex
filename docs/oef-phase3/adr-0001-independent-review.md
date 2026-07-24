# ADR: independent, snapshot-bound review

## Status

Accepted for the current Phase 3 domain boundary.

## Context

Mechanical checks establish that commands completed against a sealed Phase 2
workspace. They do not establish that the change satisfies the approved
contract, preserves architecture, or has adequate security properties. Letting
the implementer approve its own work would also combine the author and verifier
trust domains.

## Decision

1. Compile a review plan from a pinned review snapshot and versioned profile
   references, rather than a model name.
2. Bind each reviewer to a distinct session and context; policy can require a
   different provider for high-risk work.
3. Prepare copied review inputs as read-only Docker mounts, deny container
   networking and host credential mounts, and reserve writes for a separate
   temporary mount. Repair is a new Phase 2 assignment, not a reviewer mutation.
4. Treat model output as a `PROPOSED` finding. Validation, deduplication,
   quorum, current-snapshot checks, and deterministic adjudication precede a
   decision.
5. Persist only structured, schema-validated review records and audit
   artifacts. Context treats implementation summaries and repository text as
   untrusted claims or content.
6. Make a changed snapshot inconclusive rather than allowing an old review to
   pass. Resolution requires a new snapshot and independent validation.

## Consequences

Phase 3 gains review provenance and fail-closed decision gates at the cost of
additional profiles, artifacts, Docker availability, and review latency. The
Docker daemon is trusted infrastructure; unsandboxed execution and mutable image
tags are rejected.
