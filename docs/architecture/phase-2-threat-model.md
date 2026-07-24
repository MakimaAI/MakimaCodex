# OEF Phase 2 Threat Model

## Assets and trust boundaries

Protected assets are the host filesystem, repository main branch, credentials, contract/policy/audit state, artifacts, runner identity, runtime output, and verification result. Lower-trust inputs include repository instructions, source comments, web material, tool output, runtime JSONL, model messages, and changed files.

The principal boundaries are Control Plane to Runner IPC, Runner to runtime process, worktree to host filesystem, secret resolver to process environment, runtime output to event/evidence stores, and repository content to Context Compiler.

## Threats and controls

| Threat | Primary controls | Failure result |
|---|---|---|
| Host filesystem access | Separate worktree, minimum environment, high-risk local denial, future sandbox interface | `INSUFFICIENT_SANDBOX_ENFORCEMENT` / `BLOCKED` |
| Main branch mutation | Pinned base, separate branch/worktree, pre/post main HEAD and status hashes | `MAIN_BRANCH_CHANGED` |
| Denied-path write | Canonical paths, deny precedence, real Git diff, symlink escape scan | `PATH_POLICY_VIOLATION` |
| Secret in context/output/artifact | Secret references only, exact and pattern redaction before parse/disk, diff scan, Phase 1 artifact rejection | `SECRET_LEAK_DETECTED` |
| Orphan runtime or verifier process | Persistent Runner ownership; pre-attestation process inventory; Linux `setpriv --pdeathsig` watchdog plus process group; Windows kill-on-close Job Object; exact child/job handles; execution/attempt-bound persisted identity; bounded two-pass cancellation | `RUNNER_LOST` / `ORPHANED` |
| Runner impersonation | Loopback-only bind, high-entropy bearer token, constant-time comparison, body limit | HTTP 401 |
| Shell injection | Executable plus argument arrays, strict launch/verification schemas, `shell:true` architecture gate | invalid plan |
| Malformed or oversized runtime output | Streaming line/output bounds, binary detection, schema validation, parser warning, adapter quarantine foundation | `PROTOCOL_ERROR` / `OUTPUT_LIMIT_EXCEEDED` |
| Duplicate or missing events | Event ID and sequence uniqueness, durable spool, idempotent command key, explicit missing set | duplicate has zero effect / `EVENT_STREAM_INCOMPLETE` |
| Prompt injection | Fixed trust precedence, immutable kernel/contract, conflict detection, high-risk preflight block | `CONTEXT_POLICY_CONFLICT` |
| Runtime claims tests passed | Independent Mechanical Verifier submits declared commands through the persistent Runner; post-verifier seal hash must remain unchanged | `REPAIR_REQUIRED` |
| Blind retry loop | New attempt identity, max-attempt budget, failure taxonomy, circuit-breaker foundation | `STOP_BUDGET` / `NEEDS_HUMAN` |
| Cleanup destroys evidence | Default quarantine/report; no silent recursive deletion | preserved workspace |

## Residual risk

Local worktrees do not prevent a malicious runtime from reading accessible host files or using the network. Phase 2 therefore rejects high/critical work on the local provider and records enforcement levels honestly. Windows containment uses a kill-on-close Job Object; Linux containment uses `setpriv` parent-death signaling and a watchdog-owned process group. These are process-containment controls, not filesystem or network sandboxing. Unsupported Unix hosts fail closed. A Docker/VM sandbox provider remains a later hardening option, not an implied property of this implementation.

Private chain-of-thought is neither requested nor stored. Only observable actions, normalized tool/command/file events, usage, failures, verification, and human corrections enter trajectory data.
