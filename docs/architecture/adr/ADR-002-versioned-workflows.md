# ADR-002: Versioned Workflows

Status: Accepted

## Decision

Store workflow graphs as strict versioned JSON and pin each task to `{id, version, hash}`. Core code evaluates graph data but does not hardcode product-specific stages.

## Consequences

Existing tasks keep historical behavior. Changing workflow requires a new version. Cross-version task migration is an explicit human-approved command with a complete stage map.
