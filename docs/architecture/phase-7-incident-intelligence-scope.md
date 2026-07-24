# Phase 7 Incident Intelligence — Foundation Scope

## Status

This increment is the Phase 7 foundation vertical slice, not full Phase 7. It proves the durable authority path from a structured Phase 2 failure boundary through a closed incident and scoped Phase 6 memory candidates. It does not perform a production repair or deployment.

## Implemented foundation

- A SQLite WAL incident registry stores canonical observations and signatures, incident current projections and immutable revisions, immutable observation links, append-only audit events, relations, triage, containment, reproduction results, hypothesis evidence, root causes, remediation proposals, regressions, review verdicts, and playbook candidates. Large or raw evidence remains an artifact reference.
- The collector accepts a real Phase 2 `Failure` plus `ExecutionManifest` envelope, validates repository scope and artifact hashes, rejects secrets, creates a sanitized observation, and signs the normalized and structural failure shape.
- Ingestion is transactional and idempotent. Exact duplicate events have zero new effect. Automatic correlation requires the same repository scope, normalized and structural signatures, provider, runtime, and runtime major. HIGH or CRITICAL matches become `POSSIBLE_DUPLICATE` relations and are never silently merged. Cross-scope candidates are not queried.
- Triage persists severity, priority, and confidence independently. Secret-leak or permission-bypass findings have a HIGH floor and require A5 approval. Only reversible A0–A2 local record actions can execute automatically; higher actions remain proposals.
- Reproduction requires a commit, image digest, seed, attempt count, explicit budgets, no secrets, no network, and no production access. The deterministic acceptance replay uses an explicit Phase 2 adapter port; it is not a second execution system or a production sandbox.
- Hypothesis support and root-cause confirmation use the strict Phase 7 domain gates. Remediation is persisted only as a proposal and performs no source write. Closure requires reproducibility, a confirmed root cause, fail-before/pass-after regression evidence, and an independent approving review.
- Safe closure creates three scope-bound Phase 6 records: an `OBSERVED` episode, a `VERIFIED` confirmed lesson, and a `CANDIDATE` procedure. A failed memory write leaves the closure evidence intact and enqueues a retryable `phase7.memory-write` job in the shared operations store.
- The CLI exposes JSON for `incident ingest`, `list`, `show`, `timeline`, `triage`, `root-cause`, `close`, `reopen`, `provenance`, `explain`, `health`, and deterministic `demo`. Deferred commands return `PHASE7_FOUNDATION_COMMAND_UNSUPPORTED` instead of simulating success.

## Automatic and production boundaries

| Capability | Foundation behavior |
| --- | --- |
| Failure collection | Structured local Phase 2 envelope only |
| Correlation | Scope-bound; HIGH/CRITICAL matches require review |
| Containment | Reversible A0–A2 local record effects only |
| Reproduction | Pinned deterministic replay through the Phase 2 port |
| Remediation | Proposal record only; no source write |
| Review | Recorded independent foundation verdict |
| Deployment | Never performed |
| Memory | Phase 6 candidates; shared retry job on write failure |

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
