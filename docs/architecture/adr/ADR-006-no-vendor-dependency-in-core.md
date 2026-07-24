# ADR-006: No Vendor Dependency in Core

Status: Accepted

## Decision

The Phase 1 core knows actors, tasks, contracts, workflows, policies, evidence, verdicts, and events. It does not import SQLite, file-system artifact logic, HTTP, CLI, model providers, or agent runtimes.

## Consequences

Persistence, artifacts, telemetry, and CLI remain adapters. Future PostgreSQL, blob storage, OpenTelemetry, and runtime integrations can be added without changing domain invariants.
