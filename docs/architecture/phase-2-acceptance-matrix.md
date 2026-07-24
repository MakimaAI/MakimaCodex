# OEF Phase 2 Acceptance Matrix

Every row links a specification step to its primary implementation and executable evidence. Focused tests are supplemented by `tests/oef-phase2-e2e.test.ts` and the reusable real/fake acceptance entrypoint `scripts/oef-phase2-acceptance-demo.ts`.

| Step | Requirement | Primary evidence |
|---:|---|---|
| 1 | Execution domain entities | `core/domain.ts`, domain tests |
| 2 | Separate execution/attempt state | `transitionExecution`, `transitionAttempt` |
| 3 | Capability model | runtime capability schemas and eligibility tests |
| 4 | Supported versus enforcement | enforcement levels and critical-risk denial |
| 5 | Runtime Adapter protocol | `runtime/protocol.ts` contract tests |
| 6 | Shell-free Launch Plan | strict launch schema and adapter tests |
| 7 | Protocol version handshake | `negotiateAdapterProtocol` tests |
| 8 | Discovery and health | Codex live `--version` probe tests |
| 9 | Runner Host boundary | persistent daemon, `LocalRunnerHost`, authenticated HTTP client/server tests |
| 10 | Lease and heartbeat | `RunnerLeaseStore` tests |
| 11 | Durable event spool | `RunnerEventSpool` restart tests |
| 12 | Workspace Manager interface | `GitWorktreeWorkspaceManager` tests |
| 13 | Git worktree preparation | base/branch/worktree tests |
| 14 | Pinned base integrity | tree/base/main assertions |
| 15 | Path allow/deny policy | actual diff and deny-precedence tests |
| 16 | Protected control files | default control denylist |
| 17 | Environment abstraction | `LocalWorktreeEnvironment` tests |
| 18 | Process Supervisor | `LocalProcessSupervisor` tests |
| 19 | Distinct timeouts | startup/idle/tool/total tests |
| 20 | Process-tree termination | Pre-attestation inventory, Linux parent-death watchdog/process group, Windows kill-on-close Job Object, child-hang and parent-exits-first tests |
| 21 | Output limits/backpressure | line/total/ring-buffer tests |
| 22 | Minimum environment and SecretResolver | environment/redaction tests |
| 23 | Redaction before persistence | supervisor live/disk assertions |
| 24 | Immutable Context Bundle | context determinism/freeze tests |
| 25 | Trust precedence | provenance/conflict tests |
| 26 | Context budget | pruning/non-prunable tests |
| 27 | Adapter prompt renderer | stable Codex prompt hash tests |
| 28 | Observable trajectory | no-chain-of-thought schema test |
| 29 | Normalized runtime events | fake/Codex parser tests |
| 30 | Event confidence | authoritative/parsed schema |
| 31 | Ordering and dedup | sequence tracker/spool tests |
| 32 | Runtime session/resume | Codex session mapping and resume plan |
| 33 | Execution manifest | manifest schema and E2E artifact |
| 34 | Failure taxonomy | `FAILURE_TYPES`, failure schema |
| 35 | Failure scope | structured failure scope fields |
| 36 | Failure-aware retry | failure retryability and new-attempt budget |
| 37 | Circuit breaker | max-attempt and repeated-failure foundation |
| 38 | Progress signals | observable file/command/test events |
| 39 | Idempotent cancellation | authenticated live CLI cancellation plus supervisor/runner double-cancel tests |
| 40 | Persistent kill switch | daemon pause/resume/kill-all IPC tests |
| 41 | Restart reconciliation | daemon startup worker terminalizes durable orphans; persisted spool and OEF restart E2E |
| 42 | Safe process identity | PID/start/hash/nonce identity plus Windows Job Object handle containment |
| 43 | Checkpoint foundation | checkpoint entity reservation and trajectory events |
| 44 | Baseline verification | coordinator baseline and verifier tests |
| 45 | Known baseline failures | coordinator-integrated `compareWithBaseline` policy and tests |
| 46 | Workspace seal | stability and seal tests |
| 47 | Independent verifier | separate command processes owned by the authenticated persistent Runner, with durable recovery identity |
| 48 | Verification Plan | strict structured plan schema |
| 49 | Standard verification result | verifier result/summary tests |
| 50 | Flaky policy | exactly-one retry tests |
| 51 | Diff/changed-file evidence | patch export and E2E artifacts |
| 52 | Dependency detection | dependency verification step |
| 53 | Secret scan | patch/file secret tests |
| 54 | Evidence Package | Artifact Store re-verification, immutable verifier logs, content-addressed package tests |
| 55 | Execution versus verdict | `derivePhase2Result`, no ACCEPT test |
| 56 | Command Bus integration | coordinator runtime-event commands |
| 57 | Runtime plugin loading boundary | adapter registry by manifest ID |
| 58 | First real adapter | `CodexRuntimeAdapter` live health and demo |
| 59 | Fake adapter | eleven deterministic scenarios |
| 60 | Shared adapter contract | runtime adapter contract tests |
| 61 | Minimal CLI | persistent runner and assignment-driven JSON CLI tests |
| 62 | Live watch output | execution watch/events commands |
| 63 | Observability metrics foundation | structured durations/counts/usage/events |
| 64 | Security threat controls | threat model and security tests |
| 65 | Repository instruction limits | context conflict tests |
| 66 | Workspace retention | quarantine-only cleanup |
| 67 | Orphan cleanup | quarantine/report behavior |
| 68 | Test strategy | focused Phase 2 test suites |
| 69 | Fault injection | timeout, malformed, gap, duplicate, secret, child, failure-saga, and startup-reconciliation fixtures |
| 70 | End-to-end demo | `tests/oef-phase2-e2e.test.ts`, acceptance script |

## Functional

- Real Codex detection/health and one live acceptance run are supported.
- Assignment and Binding are separate; every attempt uses a separate worktree.
- Runtime events, cancellation, diff, baseline, mechanical verification, evidence, restart persistence, and unchanged main are asserted by tests and the acceptance script.

## Security

- Shell strings are absent; environments are allowlisted; secrets are redacted/scanned.
- Denied paths and symlink escapes block; high/critical local execution is denied.
- Adapter/runner imports are architecture-gated away from database and credential control.

## Resilience

- Duplicate events have zero additional effect; gaps remain visible.
- Heartbeat expiry, restart spool reads, workspace preservation, process-tree kill, output/timeout limits, and max attempts have focused evidence.

## Reproducibility

- Manifests pin task/contract, assignment, workflow, policy, source commit/tree, runtime binary/adapter/protocol, model, environment, context bundle, prompt, and start time.

## Quality

- Public schemas are generated from runtime Zod schemas and drift-tested.
- Typecheck, privacy scan, focused/full regression, architecture boundaries, core coverage, real-runtime acceptance, and an independent final review are required before merge readiness.
