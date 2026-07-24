# Task Domain

`Task` is a small aggregate root. It stores current status and stage, the active contract revision, pinned workflow and policy references, risk, timestamps, actor, and `aggregate_version`.

Task status is independent from workflow stage:

- Status: `DRAFT`, `OPEN`, `BLOCKED`, `COMPLETED`, `CANCELLED`
- Stage: a string owned by the pinned workflow definition

Contract, evidence, and verdict states use separate lifecycles. Model and runtime names never appear in task status.

Every mutating command carries an actor, idempotency key, and expected aggregate version. A successful command advances the aggregate exactly once and emits the event with the same version. Terminal tasks reject ordinary commands; only an explicit human `ReopenTask` can return one to a non-terminal stage.

The task pins `{id, version, hash}` for workflow and policy definitions. Installing a newer definition does not change an existing task. `MigrateWorkflow` requires an explicit stage map and a hash-bound human approval.
