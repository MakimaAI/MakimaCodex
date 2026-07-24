# OEF Phase 1 Scope

Phase 1 builds the persistent task-control backbone. It executes no model and assigns no agent.

## Included

- Versioned Task Contract documents and canonical hashes
- Separate task, stage, contract, evidence, and verdict lifecycles
- Versioned JSON workflow and declarative policy packs
- Command validation, actor checks, optimistic concurrency, and idempotency
- Append-only audit events, hash chaining, transactional outbox, and JSONL traces
- Approval, evidence, artifact, verdict, projection, and integrity models
- SQLite persistence, roll-forward migrations, schema versions, and a v0 event upcaster
- Local content-addressed artifacts with secret, size, path, and symlink controls
- Minimal `task`, `contract`, `evidence`, `verdict`, `timeline`, and `integrity` CLI commands
- Domain, persistence, crash, compatibility, security, property, CLI, and demo tests

## Excluded

- Model calls, automatic agent or model selection, and multi-agent DAG execution
- Automatic research, learning memory, skill evolution, and model discovery
- TUI, remote workers, OpenHands integration, and production deployment

## Stable core versus versioned behavior

The hard core enforces immutability, monotonic aggregate versions, append-only events, command idempotency, artifact hashes, secret rejection, terminal-task reopen commands, and approval requirements. Workflow stages, transition guards, policy requirements, evidence types, risk classes, and namespaced extensions remain versioned data.

The implementation lives under `src/oef/phase1`. In this existing single-package repository that directory is the package boundary; its `core`, `application`, `persistence`, `artifacts`, and `telemetry` subdirectories preserve the dependency direction without introducing a second workspace toolchain.
