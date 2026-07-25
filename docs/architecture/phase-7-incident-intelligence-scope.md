# Phase 7 Incident Intelligence — Foundation Scope

## Status

This increment is the Phase 7 foundation vertical slice, not full Phase 7. It proves the durable authority path from a structured Phase 2 failure boundary through a closed incident and scoped Phase 6 memory candidates. It does not perform a production repair or deployment.

## Implemented foundation

- A SQLite WAL incident registry exposes read/query operations only. Internal typed commands validate canonical observations and signatures, contiguous immutable histories, row metadata, scope, hashes, transitions, and evidence lineage before storing relations, gate records, pinned reproduction manifests/results, playbook candidates, and memory-write batches. Large or raw evidence remains an artifact reference.
- The collector accepts a real Phase 2 `Failure` plus `ExecutionManifest` envelope, validates repository scope and artifact hashes, rejects secrets, creates a sanitized observation, and signs the normalized and structural failure shape.
- Ingestion is transactional and idempotent. Exact duplicate events have zero new effect. Automatic correlation requires the same repository scope, normalized and structural signatures, provider, runtime, and runtime major. HIGH or CRITICAL matches become `POSSIBLE_DUPLICATE` relations and are never silently merged. Cross-scope candidates are not queried.
- Triage persists severity, priority, and confidence independently. Secret-leak or permission-bypass findings have a HIGH floor and require A5 approval. That A5 override blocks automatic A0–A2 execution until an authenticated human/security approval is verified; higher actions remain proposals.
- Reproduction persists and validates a commit-, image-, seed-, budget-, adapter-, and expected-signature-bound manifest before invoking the configured Phase 2 replay port. Counts and classification are derived from non-empty attempts, and every scope-bound evidence reference is resolved and hash-checked. The deterministic acceptance replay is not a second execution system or a production sandbox.
- Hypothesis support and root-cause confirmation use the strict Phase 7 domain gates. Remediation is persisted only as a proposal and performs no source write. Closure requires reproducibility, a confirmed root cause, and fail-before/pass-after plus independent approval bound to one exact remediation ID, plan hash, patch hash, and evidence lineage.
- Safe closure creates revision-hash-scoped Phase 6 IDs for an `OBSERVED` episode, a `VERIFIED` confirmed lesson, and a `CANDIDATE` procedure. It first persists an immutable typed memory batch. A failed write enqueues only that batch ID/hash; the shared operations handler reloads and revalidates the batch across restart before retrying.
- The unauthenticated foundation CLI is read-only: `list`, `show`, `timeline`, `provenance`, `explain`, `health`, and deterministic `demo` remain available. `ingest`, `triage`, `root-cause`, `close`, `reopen`, and containment return deterministic `PHASE7_AUTHORIZATION_REQUIRED` until an authenticated authority resolver is integrated. Other deferred commands return `PHASE7_FOUNDATION_COMMAND_UNSUPPORTED`.

## Automatic and production boundaries

| Capability | Foundation behavior |
| --- | --- |
| Failure collection | Structured local Phase 2 envelope only |
| Correlation | Scope-bound; HIGH/CRITICAL matches require review |
| Containment | Reversible A0–A2 local record effects; A5 triage overrides automatic execution |
| Reproduction | Persisted pinned manifest, trusted Phase 2 replay, resolved hash-bound evidence |
| Remediation | Proposal record only; no source write |
| Review | Recorded independent foundation verdict |
| Deployment | Never performed |
| Memory | Revision-scoped Phase 6 candidates; immutable batch plus executable shared retry job |

The acceptance demo proves a deterministic local evidence chain. It does not claim production execution, production containment, production repair, deployment, live web research, or activation of a generated skill.

## Deferred full Phase 7 increments

Full Phase 7 remains incomplete. Deferred work includes:

- shared outbox collectors and production event subscriptions;
- a real sandbox fleet and environment minimization;
- bounded web research with source provenance;
- a multi-agent critic and adjudication fleet;
- Phase 2 repair assignment and execution handoff;
- Phase 3 live review integration;
- plugin backends and external incident-system connectors;
- advanced correlation, clustering, and failure minimization;
- property campaigns and fault-injection campaigns;
- service-level metrics, alerting, retention, and operational dashboards;
- the full CLI surface and production operator workflows.

These items must land as later increments with their own acceptance evidence. They are not implied by the foundation demo.
