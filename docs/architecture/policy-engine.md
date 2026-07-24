# Policy Engine

Workflow answers which transition exists. Policy answers whether that operation is currently permitted.

Policy packs are strict, versioned declarative JSON. They cannot execute JavaScript. A rule matches operation type, destination stage or verdict, risk levels, and risk reasons. Requirements may demand a contract status, human approval count, named evidence types, or every evidence type declared by the active contract.

Each decision records the evaluated policy id/version. Denials identify rule ids and missing requirements. The application evaluates the policy version and hash pinned to the task; installing `safe-default@2.0.0` cannot change a task pinned to `safe-default@1.0.0`.

Policy data cannot disable hard invariants: approved contract content remains immutable, aggregate versions remain monotonic, events stay append-only, secrets are rejected, idempotency is enforced, artifact hashes are checked, and terminal tasks require explicit reopen.
