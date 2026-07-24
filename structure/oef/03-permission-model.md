# OEF permission model

OEF authorization is deterministic, capability-based, and fail-closed. Model output is an
untrusted request for an operation, never proof that the operation is authorized.

## Decision inputs

Every permission decision binds:

- the exact agent subject
- one capability
- one resource class
- an optional normalized path
- concrete approval references
- the selected permission envelope

The initial capability vocabulary separates workspace read/write, network access, process
execution, credential use/read, memory read/write, deployment promotion, and policy proposal.

## Evaluation order

```text
subject mismatch
  -> DENY
matching explicit deny
  -> DENY
no matching explicit grant
  -> DENY
grant requires human approval but no approval reference
  -> DENY
matching explicit grant
  -> ALLOW
```

Explicit deny always wins. There is no implicit allow based on runtime capability, model quality,
role name, account ownership, local execution, or a broad task objective.

## Path restrictions

Path-bearing rules use repository-relative normalized paths. Phase zero rejects absolute paths,
drive paths, traversal, `.` segments, repeated separators, control characters, and malformed glob
segments before any rule is evaluated. Matching is segment-aware: `*` stays inside one segment and
`**` means zero or more segments. Later filesystem enforcement must additionally resolve symlinks,
junctions, and platform case behavior before opening a file. Lexical normalization alone is not a
safe filesystem sandbox.

## Credentials

- `credential.use` and `credential.read` are separate capabilities.
- Normal agents should receive `credential.use` only through a trusted runtime adapter.
- Raw credentials must not enter Task Contracts, prompts, traces, evidence, or memory.
- An account reference identifies which trusted credential may be used; it is not the credential.
- Permission decisions and secret retrieval must be auditable as separate events.

## Production and governance

The permission evaluator unconditionally reserves workspace writes to `production-core`; even a
misconfigured agent envelope cannot grant them. Core promotion is a
separate operation governed by the evolution policy and human approval. A permission grant cannot
bypass the evolution gate.

## Phase boundaries

Phase zero defines runtime-schema-validated pure decisions. Later phases must add persistence,
approval authenticity, expiry, revocation, filesystem canonicalization, process sandboxing, network egress enforcement, and an
append-only audit ledger. Those mechanisms must preserve the evaluation order above.
