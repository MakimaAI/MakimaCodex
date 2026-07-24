# Workflow Engine

Workflow definitions are versioned JSON data validated against a strict schema. Stages are unique, transition endpoints must exist, duplicate edges are rejected, and terminal stages cannot define outbound transitions.

The engine evaluates only the task's pinned definition and returns a deterministic decision:

- transition allowed, including whether the target is terminal;
- unknown stage;
- undefined transition;
- unsatisfied guards; or
- terminal source stage.

Guards are namespaced facts derived from trusted persisted state rather than caller claims. The shipped software workflow resolves `contract.approved`, `plan.exists` only from the registered `opencodex.plan` v1 contract extension, `budget.available` from positive approved-contract limits, `required-evidence.present` from criterion-and-type pairs, and `verdict.accepted` only after revalidating verdict dependency hashes, evidence status, commit binding, and artifact bytes. Unknown extensions, including other names ending in `.plan`, remain opaque data and cannot change behavior.

When a guarded transition observes invalid dependencies on a current ACCEPT verdict, it atomically marks the verdict stale, advances the aggregate, refreshes the projection, and emits `verdict.stale.detected`. Because the command committed a state change, its result is a structured success containing the new task/event plus `transition_applied: false` and the transition denial details. Explicit workflow migration also stales current verdicts because the pinned workflow hash changed.

Workflow installation is immutable by `{id, version}`. A collision with different content is rejected. Migration to a newer workflow is an explicit human command containing source/target references, a complete stage map, rationale, and approval bound to the target definition hash.
