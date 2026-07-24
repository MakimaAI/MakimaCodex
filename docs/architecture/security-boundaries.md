# Security Boundaries

Phase 1 enforces security before persistence:

1. Strict command schema validation and trusted-principal lookup
2. Recursive scalar scan plus sensitive structured-field rejection
3. Task load and optimistic version check
4. Workflow and pinned policy evaluation
5. Artifact integrity verification
6. Atomic state, event, outbox, projection, and idempotency write

Actors are `human`, `agent`, `system`, `integration`, or `scheduler`, but the envelope cannot grant identity or privilege. The command boundary resolves the requested actor id through an injected authenticated-principal registry, derives the authoritative actor from that entry, and applies an exhaustive command-to-role map: owner decisions require `human_owner`, task/state/evidence production requires `task_operator`, and evidence verification/verdict commands require `verifier`. Approval subjects are re-resolved. Operation approvals hash the intended operation together with the active contract, pinned workflow and policy, and current risk, so they cannot survive a change in authorization context.

Secret-classified artifacts and likely credentials are rejected; raw artifact content never enters event payloads. Traces redact authorization, token, secret, password, cookie, key fields, and token-like values.

Artifact paths are derived from hashes beneath one canonical non-symlink root. Reads resolve the final real path again immediately before access, so a parent directory replaced by a junction cannot redirect content outside the root. Policy packs are declarative data and cannot execute arbitrary code. Core code contains no provider/model dispatch branches and cannot invoke a model.
