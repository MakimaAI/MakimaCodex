# ADR-007: Namespaced Extensions

Status: Accepted

## Decision

Task Contract extensions use dotted namespaces and require their own positive `schema_version`. Runtime parsing preserves unknown extension fields but does not interpret them.

## Consequences

Plugins can evolve data without core-schema churn. Unknown data survives revision storage and restart. An extension gains behavioral authority only through an explicitly installed validator/interpreter; it cannot silently override core policy.
