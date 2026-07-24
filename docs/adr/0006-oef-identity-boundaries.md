# ADR 0006: Separate OEF control-plane identities

## Status

Accepted

## Context

Multi-agent systems often use agent, model, provider, runtime, and account as loose synonyms. That
creates confused-deputy failures: a model name appears to grant tool authority, a provider appears
to identify credentials, or an account appears to be the process that executed a task.

OEF must reconstruct which policy subject acted, through which runtime, with which model and
provider account. Structural `string` identifiers cannot prevent accidental interchange.

## Decision

OEF defines role, agent, runtime, provider, model, and account as separate domain entities. Their
identifiers use distinct TypeScript brands and distinct serialized prefixes. Agent profiles refer
to the other entities; they do not collapse them.

Model/account binding is valid only when both belong to the same provider and the model is allowed
by the agent profile. Account records contain credential references, not raw credentials.

## Consequences

- TypeScript rejects accidental cross-entity assignment.
- Runtime parsing rejects an identifier carrying the wrong prefix.
- Traces and audit records can name every control-plane participant explicitly.
- Existing proxy types remain unchanged; OEF adapters must translate into the new domain types at
  their boundary.
- Callers must perform explicit construction and validation instead of passing arbitrary strings.
