# ADR 0010: Safe Single-Agent Execution Layer

## Status

Accepted for OEF Phase 2.

## Context

Phase 1 established approved task contracts, workflow/policy gates, idempotent commands, audit events, artifacts, evidence, and verdicts. Running a coding agent directly from the control plane would conflate work intent with runtime selection, expose host state, lose process/event state on crashes, trust runtime claims, and make retries irreproducible.

## Decision

1. Keep Assignment independent from ExecutionBinding.
2. Give every execution retry a new ExecutionAttempt.
3. Put process lifecycle behind a RunnerClient and a separately launched, authenticated LocalRunnerHost daemon boundary.
4. Let adapters detect/parse/plan but never spawn, select credentials, create worktrees, write databases, decide success, or mutate tasks.
5. Use executable plus argument arrays; never shell strings.
6. Use one pinned Git worktree per attempt and judge path scope from the real diff.
7. Treat LocalWorktreeEnvironment as non-sandboxed and deny high/critical risk when enforcement is insufficient.
8. Redact output before parsing or persistence, spool normalized events durably, and record them through the command bus.
9. Seal the workspace before a separate Mechanical Verifier runs its commands through the persistent Runner, bind those process trees to the authoritative execution/attempt/workspace identity, and require the same content hash afterward.
10. Separate runtime exit, execution completion, verification, and task acceptance. Phase 2 ends at review readiness.
11. Use a Windows kill-on-close Job Object or, on Linux, a detached process group led by a `setpriv --pdeathsig` watchdog. The watchdog owns the target tree and terminates it when the daemon dies; Unix platforms without this crash-containment primitive fail closed.
12. Treat evidence validity as an Artifact Store verification result, never a caller-supplied boolean.

## Consequences

The system gains reproducible manifests, restart-readable state, bounded cancellation, durable event delivery, mechanical evidence, and a real-runtime acceptance path. It also adds process/worktree lifecycle complexity and does not provide strong host/network isolation. A sandbox provider and independent semantic reviewer remain later phases.
