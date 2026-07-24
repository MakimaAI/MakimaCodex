# OEF Phase 2 Operations

Every command supports `--json`. Use `--home <path>` to select the OEF database and control directory. Workspace commands additionally require `--workspace-root <path>`.

## Runtime and runner

```text
ocx runtimes scan --json
ocx runtimes status --json
ocx runtimes inspect codex-local --json
ocx runtimes health codex-local --json

ocx runner start --json
ocx runner status --json
ocx runner pause --json
ocx runner resume --json
ocx runner kill-all --reason "security incident" --json
ocx runner stop --json
```

Runtime discovery performs bounded shell-free `--version` and `login status` probes. Credential content is never read. `runner start` launches a separate daemon; status is only `READY` after authenticated loopback capability probing succeeds. Linux execution additionally requires `/usr/bin/setpriv` or `/bin/setpriv`; the Runner fails closed when parent-death containment is unavailable.

## Assignment and execution

```text
ocx assignment create --task <task-id> --file assignment.json --json
ocx assignment show <assignment-id> --json

ocx execution start --assignment <assignment-id> --runtime fake-local --repository <repo> --json
ocx execution start --assignment <assignment-id> --runtime codex-local --repository <repo> --json
ocx execution watch <execution-id> --home <oef-home> --json
ocx execution status <execution-id> --home <oef-home> --json
ocx execution cancel <execution-id> --home <oef-home> --json
ocx execution events <execution-id> --home <oef-home> --json
ocx execution artifacts <execution-id> --home <oef-home> --json
```

`execution start` reads the existing Assignment, creates or validates an ExecutionBinding, and runs it through the persistent daemon in a fresh worker worktree. Use `ocx oef-phase2-demo --runtime <fake|codex> --root <new-root> --json` for the preserved 23-step acceptance slice.

## Workspace and verification

```text
ocx workspace list --workspace-root <root> --json
ocx workspace inspect <workspace-id> --workspace-root <root> --json
ocx workspace diff <workspace-id> --workspace-root <root> --json
ocx workspace cleanup <workspace-id> --workspace-root <root> --reason <reason> --json

ocx verify run --workspace <workspace-id> --workspace-root <root> --plan plan.json --home <oef-home> --json
ocx verify show <verification-id> --home <oef-home> --json
```

`verify run` ensures the authenticated local Runner is available. Verification command trees are owned by that daemon, included in `kill-all`/shutdown, and carry a durable execution/attempt/workspace recovery identity.

Cleanup is quarantine-only in Phase 2. It writes a report and preserves the worktree. Manual deletion is outside this command surface.

## Incident response and recovery

1. Send authenticated `CANCEL_ALL` with `runner kill-all`; the command revokes in-flight admissions, immediately terminates known runtime/verifier trees, waits only for a bounded admission barrier, performs a second inventory sweep, and terminalizes matching durable executions.
2. Inspect runner state, lease expiry, process identity, event integrity, workspace status, and audit chain.
3. Do not delete failed worktrees or partial spools. Quarantine and report them.
4. If a process remains, match PID, start time, executable hash, and runner nonce before termination.
5. Daemon startup runs reconciliation over nonterminal durable executions. Resume only through a runtime that declares session resume; otherwise preserve/quarantine the workspace and create a fresh attempt or repair plan.
6. Re-run integrity, path, secret, and verification checks before moving the task to review.

## Verification commands

```text
bun run typecheck
bun run coverage:oef:phase2
bun run generate:oef:phase2-schemas
bun run privacy:scan
bun scripts/oef-phase2-acceptance-demo.ts --runtime fake --root <new-root>
bun scripts/oef-phase2-acceptance-demo.ts --runtime codex --root <new-root>
```

The real-runtime demo is intentionally not part of routine automated tests because it uses a live model account. Preserve its `acceptance-report.json`, OEF home, runner spool, worktree, verifier logs, and artifacts as acceptance evidence.
