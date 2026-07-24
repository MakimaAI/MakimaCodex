# OpenCodex Evolution Fabric: phase-zero invariants

Status: accepted phase-zero maintainer contract.

This directory is the source of truth for the boundaries that must exist before OEF gains a task
state machine, execution loop, model router, durable memory, or automated evolution jobs. The
TypeScript enforcement surface lives in `src/oef`.

## Scope

Phase zero establishes:

- separate identities for roles, agents, runtimes, providers, models, and accounts
- a versioned Task Contract shape and an explicit revision rule
- a fail-closed permission envelope
- a provenance-aware memory write policy that rejects secrets
- a containment and promotion policy for self-evolution candidates
- ADRs that record why these boundaries are architectural decisions

Phase zero does not implement task scheduling, trace persistence, evidence storage, worktree
creation, benchmark execution, canary traffic, deployment, or rollback execution. Later phases must
consume these policies rather than replace them with model judgment.

## Non-negotiable exit gates

1. Role, agent, runtime, provider, model, and account identifiers are not interchangeable in
   TypeScript or in their serialized prefix form.
2. An agent cannot directly modify the production core. Only the deterministic promotion service
   may cross from canary to production, and only with benchmark, security, holdout, human-approval,
   and rollback evidence.

These gates are executable in `tests/oef-phase0.test.ts` and
`tests/oef-type-boundaries.test.ts`. Prose or an agent's assertion cannot override them.

## Enforcement map

| Invariant | Code | Maintainer policy | ADR |
| --- | --- | --- | --- |
| Identity separation | `src/oef/identity.ts` | `01-terminology.md` | ADR 0006 |
| Contract and revision boundary | `src/oef/task-contract.ts` | `02-task-contract.md` | ADR 0007 |
| Default-deny authorization | `src/oef/permissions.ts` | `03-permission-model.md` | ADR 0008 |
| Secret and provenance gate | `src/oef/memory-policy.ts` | `04-memory-security-policy.md` | ADR 0008 |
| No live core self-modification | `src/oef/evolution-policy.ts` | `05-self-evolution-threat-model.md` | ADR 0009 |

## Constitution

The constants exported as `OEF_CONSTITUTION` describe policy, not a configurable preference:

- the control kernel is deterministic
- live core self-modification is disabled
- secrets are not memory
- acceptance requires evidence
- core promotion requires a human gate

Changing one of these values is a governance change. It requires a new Task Contract revision,
human approval, an ADR update, security review, and the same gated promotion path as control-kernel
code.

## Phase-zero acceptance checklist

- [x] Nominal and serialized identity boundaries exist.
- [x] Agent bindings reject model/account provider mismatches.
- [x] Task Contracts require acceptance criteria and explicit revisions.
- [x] Contract approval is an approval-only same-revision transition; substantive changes require
  the immediately next draft revision.
- [x] Permission decisions default to deny and explicit deny wins.
- [x] Permission, memory, and evolution requests are runtime-schema validated and fail closed.
- [x] Memory writes reject declared and recognizable secrets.
- [x] Agent assertions cannot become verified durable memory by assertion alone.
- [x] Non-observed memory requires a trusted canonical evidence capability.
- [x] Evidence and approvals bind record, content hash, actor, level, status, and scope; lifecycle
  changes require a trusted previous record.
- [x] L5 governance writes require a human actor and approval reference.
- [x] Agents cannot write directly to the production core.
- [x] Agents cannot write benchmark or canary zones; they remain inside candidate worktrees.
- [x] Production promotion requires all mandatory gates and a rollback point.
