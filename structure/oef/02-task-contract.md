# OEF Task Contract v1

A Task Contract is the approved boundary between user intent and execution. It is input to the
deterministic kernel; it is not a prompt that an agent may silently reinterpret.

## Required fields

| Field | Purpose |
| --- | --- |
| `schemaVersion` | Pins the parser contract to `oef.task-contract/v1` |
| `taskId` | Stable `task:` identity across revisions |
| `revision` | Monotonic user/policy-visible scope version |
| `title`, `objective` | Human-readable intent |
| `risk` | Level and explicit reasons |
| `scope` | Read, write, and deny path patterns |
| `constraints` | Non-negotiable execution constraints |
| `permissionEnvelopeId` | Authorization policy selected for this task |
| `acceptanceCriteria` | Testable statements with named verifiers |
| `approval` | Draft or human-approved status |
| `createdAt` | Audit timestamp |
| `supersedes` | Exact prior task/revision reference for revisions after 1 |

Unknown fields are rejected. Acceptance criteria cannot be empty. Risk reasons cannot be empty.

## Revision rule

An unchanged contract may be reused. Any content change must:

1. keep the same `taskId`
2. increment `revision` by exactly one
3. point `supersedes` to the exact immediately preceding task revision
4. return the new revision to `draft`
5. receive a new human or policy approval before execution resumes

This rule applies to apparently helpful scope expansion. An agent may propose a revision, but it
cannot approve or activate it.

Approval itself is not a substantive contract change. A draft may transition to approved at the
same revision only when every field except `approval` is byte-for-byte equivalent after schema
parsing. An approved contract cannot mutate approval metadata or return to draft at the same
revision. Approval timestamps cannot predate contract creation.

## Scope semantics

- `deny` is authoritative and wins over read/write declarations.
- Paths are declarations for later workspace enforcement; phase zero validates the contract shape.
- A Task Contract does not itself grant credentials, network access, or deployment rights. The
  referenced permission envelope must separately allow the concrete operation.
- Work outside the approved objective or acceptance criteria is a contract-change proposal, not an
  implementation detail.

## Acceptance criteria

Every criterion has a unique stable `ac:` identifier, a plain statement, and a verifier target. Supported
phase-zero verifier classes are test, typecheck, build, inspection, and human approval. Later phases
may add evidence references, but must not weaken the requirement that acceptance is testable.

## Example

```json
{
  "schemaVersion": "oef.task-contract/v1",
  "taskId": "task:oef-phase-0",
  "revision": 1,
  "title": "Establish OEF boundaries",
  "objective": "Make identity and safety boundaries enforceable.",
  "risk": { "level": "high", "reasons": ["Future self-evolution capability"] },
  "scope": {
    "read": ["src/**"],
    "write": ["src/oef/**"],
    "deny": ["src/server/**"]
  },
  "constraints": ["no-live-core-self-modification"],
  "permissionEnvelopeId": "permission:oef-phase-0",
  "acceptanceCriteria": [
    {
      "id": "ac:no-self-modification",
      "statement": "Agents cannot modify production core directly.",
      "verifier": { "kind": "test", "target": "tests/oef-phase0.test.ts" }
    }
  ],
  "approval": {
    "status": "approved",
    "actorId": "human:owner",
    "approvedAt": "2026-07-23T09:30:00.000Z"
  },
  "createdAt": "2026-07-23T09:00:00.000Z"
}
```
