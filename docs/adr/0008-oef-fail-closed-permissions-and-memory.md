# ADR 0008: Fail closed for OEF permissions and memory writes

## Status

Accepted

## Context

Runtime capability is not authorization. An agent able to execute a tool must still be constrained
by task, resource, path, credential, memory, and approval policy. Memory adds another authority
channel: an unsupported model assertion can become a persistent false fact, and secrets can be
reintroduced into later prompts.

## Decision

Permission envelopes default to deny. Explicit deny takes precedence over explicit grant, and
human-gated grants require a canonical approval reference. Repository paths are lexically validated
before segment-aware glob matching, and agent workspace writes to production core are reserved even
when an envelope is misconfigured.

Memory writes have a separate content/provenance policy. Secret-classified or recognizably secret
content and metadata are rejected. Agent assertions remain observed; non-observed states require
canonical evidence capabilities validated by trusted context. L5 governance records require a human
actor and trusted approval capability. Evidence and approval capabilities bind record id, scope,
actor, level, target status, and content hash; status changes require a matching trusted previous
record under an explicit per-level transition matrix. Passing memory content policy does not replace the need for
`memory.write` authorization. Runtime inputs are schema-validated before either decision.
Human ids and approval references are canonical at every level, and L5 terminal corrections require
a new claim-bound approval plus the previously promoted trusted record.

## Consequences

- Missing rules produce denial instead of accidental authority.
- Credential use and credential disclosure can be governed separately.
- Durable memory cannot promote its own trust level.
- Pattern-based secret detection reduces common leaks but requires later ingress/egress scanning and
  a real secret broker.
- Callers must handle explicit denial reasons and cannot assume runtime capability implies access.
