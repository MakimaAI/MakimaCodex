# ADR 0009: Contain OEF self-evolution and gate core promotion

## Status

Accepted

## Context

An agent that can change its own live scheduler, permission code, verifier, memory policy, or
promotion rules can remove the controls intended to evaluate it. Tests generated or executed inside
the same mutable boundary are not independent evidence. A failed change also needs a recoverable
predecessor.

## Decision

Agents may write only inside candidate worktrees. They may not populate benchmark or canary zones,
and may not write the production core directly, even if their request contains apparent benchmark,
security, holdout, approval, and rollback data.

Only a deterministic promotion service may move candidates into benchmark, admit benchmarked
artifacts to canary, or cross from canary to production core. Core promotion requires
all of the following: passed benchmark, passed security review, passed private holdout, concrete
human approval, and a canonical rollback point. Missing, malformed, or failed gates deny promotion.
Malformed runtime requests and unlisted transitions fail closed.

## Consequences

- Production core cannot live-self-modify through the OEF policy surface.
- Evolution remains possible through candidate, evaluation, canary, and promotion stages.
- A compromised agent cannot authorize itself by writing an approval field.
- Later phases must enforce these decisions at repository, process, artifact, and deployment
  chokepoints; the pure policy function alone is not a sandbox.
- Promotions take longer and require retained evidence, which is the intended safety tradeoff.
