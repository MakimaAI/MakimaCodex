# OEF Phase 2: Safe Single-Agent Execution

Phase 2 connects an approved Phase 1 task contract to one bounded coding-agent execution. It does not add autonomous routing, semantic acceptance, merge, deployment, or self-evolution.

## Authority and component boundaries

```text
Phase 1 Task + approved Contract
        |
        v
Assignment (what) ---- ExecutionBinding (runtime/model/account/environment)
        |                         |
        +------------+------------+
                     v
          SingleAgentExecutionCoordinator
             | Command Bus | RunnerClient
             v             v
       SQLite audit     authenticated loopback HTTP
                             |
                  persistent Runner daemon
                       LocalRunnerHost
                      /       |       \
             RuntimeAdapter  spool  ProcessSupervisor
                    |                   |
               LaunchPlan        isolated worktree process
```

Only the coordinator crosses control-plane, workspace, runner, verification, and Phase 1 evidence boundaries. Runtime adapters do not spawn processes, select credentials, create worktrees, decide retries, change task state, or write databases. Runner and adapter packages do not import the OEF stores or command buses.

## Data separation

- `Assignment` says what to do and is revisioned with a previous-revision hash. It has no runtime, model, account, or environment selector.
- `ExecutionBinding` selects the agent profile, adapter/runtime, model class, environment, and account reference for one assignment revision.
- `Execution` is the durable aggregate. `ExecutionAttempt` is a new immutable identity for every retry.
- Task status, workflow stage, execution state, and attempt state use separate fail-closed transition graphs.
- A full execution manifest pins task/contract, assignment, workflow, policy, source commit/tree, runtime binary/adapter/protocol, model, environment fingerprint, context bundle, and rendered prompt.

## Execution sequence

1. Read the task and approved contract through the Phase 1 store.
2. Create Assignment, Binding, Execution, and Attempt through the Phase 2 command bus.
3. Probe the selected adapter and reject missing capabilities or insufficient enforcement.
4. Pin the Git base commit and create a separate worker branch/worktree.
5. Run baseline verification before the runtime writes files.
6. Compile an immutable, budgeted Context Bundle and render a stable prompt.
7. Send a shell-free launch plan to the authenticated Local Runner Host.
8. Redact output before parsing or durable spooling; enforce startup, idle, tool, total, output, and graceful-shutdown limits.
9. Record normalized events through the command bus with idempotency, durable event/sequence uniqueness, and audit hashing.
10. After process-tree exit, seal the stable workspace, inspect real Git changes, enforce path policy, and export the patch.
11. Submit Mechanical Verifier commands to the authenticated persistent Runner, bind every command tree to the authoritative execution/attempt/workspace identity, then re-hash the seal and re-check main before any success transition.
12. Re-verify every evidence reference against the immutable Artifact Store, including verifier stdout/stderr, before building the package.
13. On any runtime/verifier/evidence failure, cancel and await the runner, terminalize attempt/execution, quarantine the workspace, and emit a failure package.
14. Produce at most `READY_FOR_REVIEW`, `REPAIR_REQUIRED`, or `BLOCKED`. Phase 2 never issues final acceptance.

## Isolation statement

`LocalWorktreeEnvironment` is explicitly not a sandbox. It provides workspace separation, minimum environment inheritance, observable path enforcement, process-tree supervision, and output redaction. Filesystem and process enforcement are `OBSERVED`; network enforcement is `ADVISORY`. High and critical risk executions are denied unless a future sandbox provider supplies sufficient enforcement.

## Persistence and delivery

Phase 2 tables share the OEF SQLite file but use a separate migration ledger. Assignment revisions, bindings, audit events, and runtime-event receipts are append-only. Execution updates use optimistic aggregate versions. Command results are idempotent. Runner events use durable JSONL plus database uniqueness for global event IDs and `(attempt, sequence)`, at-least-once delivery, duplicate suppression, and explicit gap reporting.

`ocx runner start` launches a separate persistent daemon and publishes only its loopback endpoint, PID, and token-file path. The token value never appears in JSON output. Every spawned child enters the supervisor inventory before identity attestation. Windows gates the target until assignment to a kill-on-close Job Object; Linux runs the target below a parent-death-signaled watchdog that owns its detached process group. Daemon startup runs durable orphan reconciliation for both runtime and verifier process trees; authenticated control calls revoke admissions and perform bounded two-pass pause, cancellation, kill-all, and shutdown against the live host. Any unconfirmed termination degrades the host and keeps new execution disabled.

The reusable acceptance entrypoint is `scripts/oef-phase2-acceptance-demo.ts`. `--runtime fake` is deterministic; `--runtime codex` exercises the installed real Codex CLI and preserves the complete demo root for inspection.
