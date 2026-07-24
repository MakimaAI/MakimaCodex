# Phase 1 Acceptance Matrix

This matrix maps the specification's exit gates to authoritative implementation evidence. Final test counts are recorded by the completion run, not hardcoded here.

| Requirement | Implementation | Evidence |
| --- | --- | --- |
| Task create and restart persistence | Command bus plus SQLite task repository | `oef-phase1-persistence`, `oef-phase1-demo-cli` |
| Immutable versioned contracts | Canonical hash, revision lifecycle, DB trigger | `oef-phase1-core`, `oef-phase1-lifecycle` |
| Versioned workflow and policy pinning | Definition tables and task hash refs | `oef-phase1-hardening` |
| Policy and authorization can deny operations | Declarative evaluator, authenticated principal registry, exhaustive role map, operation-context approvals | core, lifecycle, evidence/verdict tests |
| Criterion-bound evidence and verdict | Evidence/verdict models and commands | `oef-phase1-evidence-verdict` |
| Artifact-aware verdict projection | Application summary query validates dependency records and artifact bytes | evidence/verdict tamper regression |
| Timeline and integrity view | Event projection and integrity query | `oef-phase1-integrity-telemetry`, CLI test |
| No secret in events/artifacts/traces | Command scan, artifact rejection, trace redaction | artifact, evidence, telemetry tests plus privacy scan |
| Path traversal and symlink prevention | Hash-derived keys and canonical root checks | `oef-phase1-artifacts` |
| Atomic state/event/outbox | One SQLite transaction and crash seams | persistence and hardening crash tests |
| Idempotency and concurrency | Result records, expected versions, busy/snapshot mapping | 100-replay, stale-writer, and barrier-controlled two-process tests |
| Event ordering and append-only history | Aggregate version uniqueness, hash chain, triggers | persistence and integrity tests |
| Schema evolution | Versioned records, migrations, v0 upcaster | hardening and telemetry tests |
| Unknown extensions preserved | Passthrough extension schema and revision storage | core and hardening tests |
| Public/runtime schema parity | Strict nested JSON Schema plus Zod validators for all 11 public schemas | generated differential `oef-phase1-schema-parity` corpus |
| Coverage gates | Phase 1-wide line/function gate plus independent Node branch gate | `bun run coverage:oef` |
| End-to-end demo | Denial, repair, acceptance, every shipped stage through `done`, restart, integrity | `runPhase1Demo` and CLI E2E |
