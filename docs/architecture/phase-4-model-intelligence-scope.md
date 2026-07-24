# Phase 4 — Model Intelligence, Benchmark, and Qualification Scope

## Decision boundary

Phase 4 measures a versioned **Execution Configuration**: model version, deployment, runtime adapter, prompt profile, tool bundle, context policy, generation policy, and environment. A model name by itself is never a qualification subject.

The four operations remain distinct:

```text
Model Discovery != Model Qualification != Model Activation != Production Routing
```

The Model Lab may discover metadata, run compatibility probes and held-out benchmarks, create time-limited role scorecards, quarantine unsafe configurations, and issue recommendations. It has no port for modifying production router policy. `CANARY_READY` and `ACTIVE` are Phase 5 states; Phase 4 rejects transitions to them.

## Initial role and benchmark surface

The first executable policy catalog contains `backend-implementer`, `chief-architect`, and `code-quality-reviewer`. Role weights and sample thresholds are versioned data. Built-in suites include a backend quick screen, a backend public/validation/private qualification suite, and an architecture public/validation/private suite. New role and benchmark versions preserve historical results.

Provider catalog adapters may submit discovered family/version metadata and alias resolutions. A provider claim is stored as a claim with provenance and expiry; it is never converted into a capability observation. Only a versioned probe against an Execution Configuration creates an observation. Qualification requires completed attempts, a reproducibility manifest, a private holdout, minimum samples, structured-output and tool-protocol observations, and zero critical violations.

## Identity and drift

Provider, family, version, deployment, alias, runtime, and Execution Configuration IDs are separate. Configuration content is canonical-hashed and immutable. Alias revisions are recorded. When an alias changes, historical scorecards remain available, affected configurations become stale, and a full requalification job is created. The new alias target is not activated.

## Validity and safety

Scorecards are bound to the exact configuration, role profile, benchmark, evaluator, environment, and manifest hashes. They expire after 45 days. A changed alias, profile, benchmark, runtime, prompt, tool bundle, context policy, environment, incident, or quarantine makes the old evidence ineligible for recommendations.

Private holdout prompts expose neither hidden assertions nor evaluator policy. Candidate output is treated as untrusted data; scoring occurs in the trusted lab evaluator. Provider credentials are resolved transiently from an environment `SecretRef` and are never serialized to snapshots, events, results, or artifacts. Artifacts are redacted, atomically written, SHA-256 addressed, and verified before use.

Private tasks carry provider policy. A disallowed external provider is rejected before execution. Critical secret leakage or protocol violations quarantine the full model/deployment/runtime configuration. Quarantine removal requires root-cause remediation, requalification, and human approval; there is no automatic removal path.

## Phase 5 handoff

Phase 5 may read valid role scorecards, confidence intervals, Pareto position, operational metrics, exclusions, and recommendation explanations. It must independently combine these with task context, account/quota state, and production policy. A Phase 4 recommendation is evidence, not an activation command.

Human approval is required for quarantine removal, risk-bound overrides, canary/active promotion, production routing changes, and policy changes. Discovery, probes, deterministic evaluation, expiration, degradation detection, and requalification requests may run without changing production routing.
