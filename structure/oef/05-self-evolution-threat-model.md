# OEF self-evolution threat model

Status: phase-zero baseline. Review whenever a new promotion path, runtime, memory backend, tool,
or autonomous job is introduced.

## Security objective

Agents may produce change candidates in contained workspaces. They may not mutate the live control
kernel, its constitution, promotion policy, verifier, security gate, or rollback history. Crossing
into production is a deterministic, auditable promotion operation with independent evidence and a
human gate.

## Protected assets

- production control-kernel source and executable artifacts
- permission, memory, routing, verifier, and promotion policies
- credentials and provider accounts
- Task Contracts and human approval records
- benchmark, holdout, security, and canary evidence
- audit ledger and rollback points
- memory provenance and L5 governance records
- repository main branch and release channel

## Trust boundaries

```text
untrusted user/tool/model text
  -> agent candidate workspace
  -> benchmark and security evaluation
  -> canary artifact
  -> deterministic promotion service
  -> production core
```

Models, model output, retrieved memory, web content, tool output, candidate code, and agent-authored
evidence are untrusted. The promotion service, approval verifier, and policy constants are trusted
only within their narrow deterministic responsibilities.

Phase-zero transition ownership is explicit:

```text
agent: candidate-worktree -> candidate-worktree
promotion service: candidate-worktree -> benchmark
promotion service: benchmark -> canary (evaluation gates required)
promotion service: canary -> production-core (all gates required)
everything else: DENY
```

## Threat actors

- a prompt-injected or misaligned agent
- a compromised provider, model, runtime, or tool server
- malicious content retrieved from memory or the web
- a local process attempting to act as an authorized agent
- a compromised account or credential
- an authorized operator making an unsafe or mistaken approval
- candidate code that tampers with its evaluator

## Threats and required controls

| Threat | Impact | Phase-zero control | Required later enforcement |
| --- | --- | --- | --- |
| Agent writes production core directly | Persistent control compromise | `decideEvolutionChange` always denies agent-to-core writes | OS/repository isolation and protected branch |
| Agent forges an approval string | Unauthorized promotion | Agent transitions stop at candidate; promotion references must be canonical and all gates are mandatory | Signed, expiring, task-bound approvals |
| Candidate edits its verifier or benchmark | False success evidence | Candidate and promotion zones are distinct policy concepts | Immutable evaluator image and external evidence hashes |
| Prompt injection proposes policy weakening | Governance bypass | L5 is human-only; model output has no policy authority | Trusted UI diff and independent security review |
| Poisoned memory becomes durable policy | Repeated unsafe behavior | Agent assertions remain observed; evidence/approval capabilities bind the exact claim and status transition | Scoped retrieval, quarantine, correction, poisoning scans |
| Secret enters prompt, trace, or memory | Credential theft | Memory rejects declared and recognizable secrets | Secret broker, redaction at ingress, egress scanning |
| Model and account cross provider boundaries | Confused credential use | Binding rejects provider mismatch | Trusted account resolver and audit event |
| Path traversal, symlink, or junction escapes workspace | Host or core modification | Permission model carries resource/path limits | Canonical path checks and OS sandbox |
| Candidate changes after approval | Time-of-check/time-of-use bypass | Promotion requires a rollback point | Content-addressed artifacts and approval bound to digest |
| Evidence or rollback history is deleted | Promotion cannot be reconstructed | Evidence and rollback are mandatory concepts | Append-only ledger and protected artifact store |
| Same model implements and approves | Shared blind spot or collusion | Human gate cannot be supplied by an agent | Provider-diverse review and authenticated approver |
| Infinite candidate loops consume budget | Denial of service and cost | Stop conditions belong to agent profiles | Circuit breakers, budgets, quotas, kill switch |

## Mandatory promotion gates

The promotion service may move a control artifact from canary to production only when all are true:

- benchmark passed
- security review passed
- private holdout passed
- a concrete human approval is present
- a rollback point is present
- the source zone is canary

Approval references use the `approval:` namespace. Rollback references are pinned Git object ids or
content-addressed artifacts. Canonical format is not authenticity; later promotion infrastructure
must validate issuer, digest binding, scope, expiry, and revocation.
Optional gate metadata and human/service actor ids are validated even on transitions that do not
consume them, preventing malformed data from crossing an earlier zone and becoming trusted later.

The gates are conjunctive. A strong quality result cannot compensate for a failed security result,
missing approval, or missing rollback point.

## Forbidden paths

- agent -> production core
- agent -> benchmark or canary
- candidate worktree -> production core
- benchmark result -> production core without canary
- memory lesson -> active policy without a promotion workflow
- runtime capability -> implicit permission
- account ownership -> implicit credential disclosure
- human approval of one digest -> promotion of a different digest

## Recovery assumptions

Phase zero requires a rollback reference but does not execute rollback. Before production automation
is enabled, rollback must be tested, content-addressed, access-controlled, and independent of the
candidate being promoted. A candidate must never be able to delete its predecessor or the audit
record that authorized it.

## Residual risk

The pure TypeScript decisions can be bypassed by code paths that fail to call them. Later phases
must place enforcement at the narrow execution and promotion chokepoints, add tamper-evident audit,
and test negative paths end to end. Until then, OEF self-evolution is a design boundary and
candidate-policy library, not authorization to run autonomous production mutation.
