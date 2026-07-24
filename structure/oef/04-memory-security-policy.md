# OEF memory security policy

Memory is a security boundary. It can carry prompt injection, secrets, false facts, stale policy,
and cross-project data just as easily as useful lessons.

## Memory levels

| Level | Content | Minimum provenance expectation |
| --- | --- | --- |
| L0 | Raw evidence references | Runtime-produced artifact and hash |
| L1 | Task episode | Evidence references for actions and outcome |
| L2 | Lesson or failure pattern | Reproduction or deterministic test |
| L3 | Skill or policy candidate | Generalized evidence and promotion gates |
| L4 | Model capability record | Measured role-specific samples |
| L5 | Constitution/governance | Human-approved and agent-immutable |

Raw artifacts stay outside prompts by default. Higher-level summaries point back to evidence rather
than copying unbounded logs into context.

## Classification and secret rule

Every write is classified as public, internal, confidential, or secret. Secret content is rejected,
not merely hidden later. Phase-zero detection also blocks recognizable private keys, bearer tokens,
OpenAI-style secret keys, AWS access keys, and common credential assignments.

The scan covers content, actor metadata, human approval metadata, and evidence references that
would be persisted with the record. Pattern detection is defense in depth, not a complete secret scanner. Upstream redaction,
credential isolation, bounded artifacts, and a dedicated secret scan remain mandatory. If the
system is uncertain whether content is a secret, it must avoid persistence and request review.

## Provenance and status

The status sequence is:

```text
OBSERVED -> REPRODUCED -> VERIFIED -> GENERALIZED -> PROMOTED
                                      -> SUPERSEDED -> DEPRECATED
```

A single agent assertion can only be `OBSERVED`. It cannot label itself reproduced, verified,
generalized, or promoted. Non-observed records require canonical
`artifact:sha256:<64 lowercase hex>` references that exist in a trusted evidence-capability map.
Every capability binds the memory record id, scope, actor, level, target status, content SHA-256,
and trusted source type. An unrelated artifact or an agent-supplied string cannot authorize a new
claim. L5 writes additionally require a canonical human actor and an approval capability bound to
the same claim fields.

Human actor ids and approval references are canonical on every memory level, even when the current
operation does not consume an approval gate. Malformed optional metadata is rejected at the runtime
schema boundary rather than being silently retained.

## Level and lifecycle policy

Each level has an explicit status allowlist. L0 is raw evidence and remains observed. L1 episodes
may be reproduced or verified. L2 lessons may progress through reproduced, verified, and
generalized, but cannot become promoted policy. L3 skill/policy candidates may reach promoted after
verified and generalized stages. L4 model capability records stop at generalized. L5 governance is
human-approved promoted state.

Normal status changes require a trusted previous record with the same record id, scope, actor,
level, and content hash. The allowed forward chain is:

```text
OBSERVED -> REPRODUCED -> VERIFIED -> GENERALIZED -> PROMOTED
```

An observed record may move directly to verified only when a trusted evidence capability targets
that exact transition. `SUPERSEDED` and `DEPRECATED` are terminal lifecycle operations and always
require trusted previous-record context. Initial L5 promotion is the one exception to previous-state
requirements because both evidence and human approval capabilities bind the complete claim.
L5 terminal correction is reachable only with a new approval capability targeting the exact
`SUPERSEDED` or `DEPRECATED` claim plus the previously promoted trusted record.

## Memory authorization

Passing content policy does not grant write authority. The agent must separately have
`memory.write` permission for the requested scope. Retrieval likewise requires `memory.read` for
the specific project, repository, role, or task scope. Credential and security-governance scopes
are not visible to ordinary agents.

## Poisoning and cross-scope defenses

- Store provenance, source type, evidence references, scope, and status with every record.
- Parse every runtime request through the strict memory schema before policy evaluation.
- Keep agent-generated text untrusted when retrieved; never treat it as a developer instruction.
- Prefer exact scoped retrieval before semantic expansion.
- Exclude superseded and deprecated records by default.
- Do not promote a lesson without reproduction or deterministic regression evidence.
- Do not reuse evidence or approval capabilities across a different record, scope, actor, content,
  level, or target status.
- Do not let a retrieved memory change its own trust status.
- Do not copy memory between users, repositories, or organizations without an explicit policy.

## Retention and correction

Later persistence must support correction, supersession, deprecation, retention limits, deletion,
and provenance drill-down. Immutable audit history may record that a value existed without retaining
the secret or personal content itself.
