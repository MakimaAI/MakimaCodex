# Phase 5: Routing and Team Composition

Status: implemented vertical slice, fail-closed by default
Schema version: 1
Routing policy version: 1.0.0

## Purpose

Phase 5 turns an approved Phase 1 task contract into three pinned products:

1. a task fingerprint that describes the work without naming a model;
2. a bounded role DAG that describes the team without selecting accounts;
3. a routing plan and immutable execution-binding revisions that select qualified Phase 4 execution configurations for Phase 2.

The router never executes arbitrary agent proposals. It compiles, filters, scores, validates, reserves, and binds. Phase 2 remains the execution authority and Phase 3 remains the independent review authority.

## Boundary map

```text
Approved Task Contract (Phase 1)
  -> Task Intelligence Compiler
  -> immutable Task Fingerprint
  -> deterministic Team Composer
  -> Team Plan DAG
  -> Phase 4 Candidate Read Port
  -> hard filters
  -> policy-weighted scoring and bounded team selection
  -> Routing Plan
  -> budget reservation and activation revalidation
  -> Execution Binding Set revisions (Phase 2 compatible)
  -> structured handoffs
  -> Phase 2 execution and Phase 3 review
  -> Routing Outcome
  -> offline calibration queue
```

These concepts are deliberately separate:

| Concern | Owns | Must not own |
|---|---|---|
| Task analysis | task type, risk, privacy, uncertainty, capabilities | model or account selection |
| Team composition | roles, dependencies, path scope, parallelism | provider credentials or execution |
| Candidate selection | Phase 4 scorecards, hard filters, policy score | scorecard mutation or secret access |
| Execution binding | pinned model, runtime, deployment and account reference | secret material or process launch |
| Account selection | capacity-backed account reference | model qualification |
| Execution | Phase 2 assignment and runtime lifecycle | routing-policy mutation |

## Trust boundaries

- The task contract is authoritative. A semantic classifier may add observations, but an observation below 0.8 confidence cannot become a hard constraint.
- Feature precedence is kernel rule, task contract, repository scan, human metadata, semantic classifier, then model proposal.
- A chief architect may propose additions or removal of optional roles. The kernel rejects removal of mandatory implementer, test, and risk-review roles.
- Phase 4 is accessed through `Phase4CandidateReadPort`. Phase 5 has no scorecard write method and verifies the scorecard's pinned execution-configuration hash.
- The router stores provider, model, runtime, deployment and opaque account references. It never loads credential values.
- Plugins may propose namespaced observations or soft weights; they cannot remove hard constraints, clear quarantine, activate policy, reserve budget, or launch agents.
- Agents cannot spawn agents. A new-role proposal must create a new Team Plan revision and pass policy and budget validation.

## Task intelligence

`compileTaskFingerprint` combines contract text, acceptance criteria, deterministic repository signals, policy rules and optional semantic observations. The output carries observation source, confidence, timestamp, hard-constraint eligibility and a canonical SHA-256 hash.

A changed contract produces a new fingerprint revision. The fingerprint is deeply frozen after validation. Credential, restricted-data and high-impact signals raise risk. External provider behavior and explicit unknowns raise uncertainty and freshness requirements.

## Role catalog and team composition

The built-in catalog separates roles from models and execution configurations. It contains analysis, production, verification and governance roles. Agent profiles are independently schema-defined by prompt, skills, tools, context policy, permissions, memory scope and verification requirements.

Composition rules include:

- high uncertainty or fresh external facts require `internet-researcher`;
- low-complexity work may omit `chief-architect`;
- backend and frontend implementations select different production roles;
- credential-sensitive, high or critical work requires `security-reviewer`;
- non-frontend work cannot add `visual-reviewer`;
- 3D work may add `spatial-planner`;
- reviewer nodes depend on production nodes;
- a team has at most 8 roles and parallelism is capped at 3;
- path-overlapping work is represented as non-parallel by the plan.

Team Plan nodes begin in `WAITING`. The readiness projection can mark a node `READY` only after the Routing Plan is ACTIVE and budget-reserved, the matching Binding Set passes hash validation, the node has a binding, and every dependency is recorded complete. The projection is capped by `max_parallelism`.

## Candidate construction and hard filters

Candidate identity binds role, agent profile, Phase 4 execution configuration, scorecard, provider, model version, runtime, deployment and a short-lived availability snapshot. Candidate generation cannot mutate Phase 4.

Hard filters run before scoring and record every rejection reason. They cover:

- role and capability match;
- quarantine, staleness, scorecard expiry and qualification level;
- runtime/provider health and account capacity;
- availability TTL;
- privacy class and context capacity;
- task-risk qualification floor.

A role with no eligible candidate produces human escalation. The kernel never selects the least-bad invalid candidate.

## Scoring and team selection

All weights live in a versioned routing policy. Profiles are `premium`, `balanced`, `economy`, `fast`, and `private`. They cannot weaken hard constraints.

The score combines quality, task similarity, repository affinity, tool/structured/operational reliability, availability, forecast cost and forecast latency. Uncertainty, incident and staleness penalties are explicit. High and critical risk use the lower 95% confidence bound instead of the mean.

Candidates are deterministically ordered, truncated to the policy's top K, and selected within bounded limits. Team utility subtracts provider-correlation penalties. High/critical security review must use a provider different from the implementer. If that cannot be satisfied, the result is human escalation.

## Lifecycle, budget and activation

The permitted lifecycle is:

```text
DRAFT -> CANDIDATES_RESOLVED -> OPTIMIZED -> POLICY_VALIDATED
      -> BUDGET_RESERVED -> APPROVED -> ACTIVE -> COMPLETED
```

Terminal and alternate states are `REJECTED`, `REBIND_REQUIRED`, `SUPERSEDED`, `CANCELLED`, and `EXPIRED`. A plan cannot jump to `ACTIVE`.

The router reserves at least the p90 team cost before approval. Activation revalidates the runtime, provider, account capacity, availability TTL and kill-switch state. A failed revalidation yields `REBIND_REQUIRED`; it never starts a stale binding.

## Sticky bindings and fallback

An Execution Binding Set pins role node, agent-profile ID/version/hash, Phase 4 execution-configuration ID/hash, provider, model version, runtime/adapter version, deployment and opaque account reference. It also pins the task risk, privacy, capabilities and context requirement copied from the hashed Routing Plan. A caller cannot lower these constraints during fallback. A rebind creates a new set revision, increments the attempt, links the previous hash and records a permitted reason.

Permitted reasons are runtime/provider/account failure, rate limit, insufficient context, missing tool, model-behavior failure, policy change, human override, or qualification invalidation. “A better model is available” is not permitted.

Fallback is failure-specific:

| Failure | Action sequence |
|---|---|
| 429 | same configuration/new account, alternate deployment, alternate candidate, human |
| 401 | quarantine credential and block; no blind rotation |
| 403 | policy/permission review and block |
| provider 5xx | bounded retry, deployment, candidate |
| runtime unhealthy | same model/alternate runtime, candidate |
| context limit | shrink, rebuild, candidate, decompose |
| tool protocol | alternate runtime, candidate |
| verification failure | repair; no infrastructure fallback |
| security violation | block |

The binding history is used as a visited set, preventing cycles. Exhaustion escalates to a human.

## Handoffs and privacy

Handoffs contain claims, evidence references, open questions and one of `VERIFIED`, `SUPPORTED`, `UNVERIFIED`, or `OPEN_QUESTION`. Constructors reject credential-like content, hidden-reasoning markers and tool-log payloads. Raw chats, chain-of-thought, environment secrets and unbounded tool output are not routing artifacts.

## Persistence, replay and recovery

SQLite persists every Phase 5 entity family, routing events and offline replay jobs. Immutable records reject conflicting hashes. Event IDs are idempotent. Routing plans and binding revisions survive process restart.

Offline replay takes the historical fingerprint, team plan, candidate set, availability context, policy and seed. It reports a match only when the regenerated plan hash and assignments match the historical decision. A routing outcome is queued for offline calibration; it never changes a live scorecard or policy directly.

## Operations

Primary CLI surfaces:

```text
ocx route fingerprint <task> --objective <text> --json
ocx route fingerprint show <task> --json
ocx team compose <task> --json
ocx team show <team-plan-id> --json
ocx route candidates --task <task> --role <role> --availability-file <snapshot.json> --json
ocx route plan <task> --profile premium --availability-file <snapshot.json> --json
ocx route explain <routing-plan-id> --json
ocx route validate <routing-plan-id> --json
ocx route activate <routing-plan-id> --availability-file <fresh-snapshot.json> --budget-limit <units> [--budget-pool <id>] --json
ocx route fallback show <routing-plan-id> --json
ocx route outcome <task> --json
```

The deterministic acceptance command is:

```text
ocx oef-phase5-demo --root <artifact-directory> --json
```

It writes all required decision artifacts, performs a multi-role route, rejects expired and quarantined candidates, reserves budget, activates, creates a structured handoff, injects a runtime failure, produces a new binding revision, records an accepted outcome and confirms offline replay.

Production candidate, plan and activation commands require an explicit availability snapshot. The CLI does not synthesize healthy runtimes or account capacity. Each configuration record must include runtime/provider health, account capacity and opaque account references, observation/expiry timestamps, scorecard and qualification validity, and the current kill-switch state. Confidential/restricted routing is allowed only for provider IDs explicitly listed in the snapshot's `private_providers` array.

Activation also requires an explicit budget limit. The first activation creates a named SQLite budget pool; later processes must use the same limit and share its durable, idempotent reservation ledger. A new CLI process therefore cannot reset consumed capacity.

## Human escalation conditions

Escalation is required when no role has an eligible candidate, reviewer independence is impossible, budget cannot be reserved without removing a mandatory safety role, fallback is exhausted or cyclic, qualification becomes invalid, a policy is expired, a pinned snapshot does not match, or a human gate is required by the approved task contract.

## Explicit non-goals

Phase 5 does not self-modify policy, perform uncontrolled online learning, reveal secrets, recursively spawn agents, auto-deploy, auto-merge high-risk changes, unquarantine models, mutate Phase 4 scorecards, or let a model appoint itself.
