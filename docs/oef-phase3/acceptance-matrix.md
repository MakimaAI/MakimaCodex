# Phase 3 acceptance trace (steps 1–83)

This table traces the specification to the implemented boundary. The local
acceptance demo is deterministic; its reviewer processes nevertheless run in a
real pinned Docker sandbox, inspect the mounted source, and measure that network
and host-credential probes are denied. It does not claim arbitrary external
model-provider coverage.

| Step | Requirement trace | Current boundary |
| ---: | --- | --- |
| 1 | Review domain entities | `core/domain`, governance records |
| 2 | Review plan model | `planning/compiler`, `reviewPlanSchema` |
| 3 | Review profile model | `reviewProfileSchema`, planning registry |
| 4 | Review unit model | `reviewUnitSchema`, registry |
| 5 | Reviewer binding | `review/binding` |
| 6 | Independence rules | binding validation, `computeIndependenceScore` |
| 7 | Review request | `reviewRequestSchema` |
| 8 | Snapshot pinning | `createReviewSnapshot`, current checks |
| 9 | Plan revision links | `reviewPlanSchema` refinements |
| 10 | Risk-driven selection | `compileReviewPlan` |
| 11 | Profile registry | `planning/registry` |
| 12 | Required review types | compiler and plan quorum |
| 13 | Spec review type | registry/profile contract |
| 14 | Code-quality review type | registry/profile contract |
| 15 | Security review selection | compiler risk/path signals |
| 16 | Architecture review extensibility | namespaced review types/profile capabilities |
| 17 | Performance review selection | compiler performance signal |
| 18 | Visual review selection | compiler frontend signal |
| 19 | Accessibility review selection | compiler frontend signal |
| 20 | Documentation/release extension | namespaced registry extension point |
| 21 | Review budget | plan budget/limits |
| 22 | Quorum | `verifyQuorum` |
| 23 | Critical-risk provider diversity | default critical quorum |
| 24 | Human approval gate | hash-bound, snapshot-bound human approval record + quorum |
| 25 | Reviewer workspace contract | review profile workspace fields |
| 26 | Read-only copied inputs | `ReadOnlyReviewEnvironment` |
| 27 | Separate temporary writes | prepared environment `temp` |
| 28 | Source integrity recheck | environment manifests |
| 29 | Phase 2 runner reuse | `RunnerReviewExecutor` through pinned Docker |
| 30 | Review execution purpose/binding | review execution record/executor |
| 31 | Bounded command execution | runner request timeout/output limit |
| 32 | Limited inherited environment | executor allowlist schema |
| 33 | No injected review secrets | executor fixed empty secret refs |
| 34 | Network-denied review contract | Docker `--network none` plus live acceptance probe |
| 35 | Context bundle | `ReviewContextBundleCompiler` |
| 36 | Trust ordering | `REVIEW_CONTEXT_TRUST_ORDER` |
| 37 | Prompt-injection resistance | context constraints/trust order |
| 38 | Secret rejection in context | Phase 1 secret detector call |
| 39 | Implementer-summary distrust | `unverified-claim` label |
| 40 | Structured reviewer output | `reviewResultSchema` |
| 41 | Output parse failure containment | coordinator rejects failed unit |
| 42 | Finding record | `reviewFindingSchema` |
| 43 | Code anchors | safe path and hashed anchor schema |
| 44 | Contract/evidence references | finding fields |
| 45 | Severity vs confidence | separate finding fields |
| 46 | Proposed-finding status | finding lifecycle |
| 47 | Finding validation | `validateFinding`, validation record |
| 48 | Unsupported blocker denial | finding/adjudication checks |
| 49 | Finding deduplication | claim/impact-bound grouping with highest-severity canonical selection |
| 50 | Finding transitions | `transitionFinding` |
| 51 | Waiver record | `waiverSchema`, `createWaiver` |
| 52 | Waiver snapshot binding | decision-time hash/snapshot/severity/expiry validation |
| 53 | Stale finding/review handling | live Phase 1/2 snapshot/full-validity checks at start/end plus terminal replay supersession |
| 54 | Deterministic adjudication | `adjudicateReview` |
| 55 | Mechanical evidence gate | coordinator/adjudicator input |
| 56 | Missing required review gate | quorum/adjudicator input |
| 57 | Critical finding block | adjudicator |
| 58 | High/medium repair decision | adjudicator |
| 59 | Low/info notes decision | adjudicator |
| 60 | Disagreement human escalation | adjudicator input |
| 61 | Review decision record | governance decision schema |
| 62 | Phase 1 verdict mapping | `mapReviewDecisionToPhase1` |
| 63 | Repair proposal | `createRepairProposal` |
| 64 | Repair only from confirmed findings | repair proposal validation |
| 65 | Repair path scope | finding anchor-derived scope |
| 66 | Delta review selection | `determineDeltaReviewTypes` |
| 67 | Verified resolution | `assertResolutionVerified` |
| 68 | Snapshot validity assessment | `assessReviewValidity` |
| 69 | Public schema versioning | ten v1 generated schemas, including human approval |
| 70 | Reviewer metrics model | `observability/learning` |
| 71 | Ground-truth outcomes | learning/outcome records |
| 72 | Escaped-defect tracking | learning records |
| 73 | False-positive tracking | learning records |
| 74 | Learning-data privacy boundary | observability schemas; no chain-of-thought field |
| 75 | Analysis-cache policy | `observability/cache` |
| 76 | Review CLI | durable pinned-Docker dispatch, full coordinator lifecycle/adjudication persistence, exact-execution cancellation, delta rerun, and real Phase 2 repair assignment |
| 77 | Live review presentation | JSON `review watch`; graphical presentation remains outside this phase |
| 78 | Review hardening | trust model and focused security tests |
| 79 | Cancellation/kill switch | coordinator cancellation port and exact Phase 2 review execution ids |
| 80 | Fault injection | source tamper, runner timeout, malformed output, stale inputs, audit corruption, cancellation |
| 81 | Domain/plan/security test strategy | `tests/oef-phase3-*.test.ts` |
| 82 | Property/invariant testing | 500-order severity/dedup, distinct-claim, pairwise-quorum, and validity mutation properties |
| 83 | End-to-end repair demo | Phase 2 initial/repair runs, three source-analyzing Docker reviewers, live isolation probes, causal hash-linked audit, delta PASS, Phase 1 ACCEPT |
