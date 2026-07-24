# Evidence Model

Each acceptance criterion declares required namespaced evidence types. An evidence record binds to task id, active contract revision id, criterion key, producer actor, type, summary, environment, and zero or more artifact references.

Evidence has its own lifecycle: `RECORDED`, `VERIFIED`, `REJECTED`, `INVALIDATED`, `STALE`. Recording does not imply verification. Verification recomputes every referenced artifact hash through the configured `ArtifactStore`.

An `ACCEPT` verdict can reference only verified evidence from the active contract revision. Requirements are compared as `(criterion_key, evidence_type)` pairs, so one result cannot satisfy two criteria that request the same type. ACCEPT also requires a repository commit and records hashes for the active contract, pinned workflow, pinned policy, and every selected evidence record. A later terminal guard revalidates those hashes, evidence status, commit binding, and artifact bytes. Evidence from an older contract, another criterion, an invalidated record, a mixed commit, or a tampered artifact cannot satisfy acceptance.

Evidence types are namespaced strings, allowing tools and plugins to add types without extending a core enum. Unknown types remain data and have no automatic authority unless a pinned contract or policy requires them.

The authoritative task-summary query recomputes current-verdict validity against artifact bytes before exposing `latest_verdict`. The persisted projection receives only artifact-validated verdict ids and fails closed when no integrity context is supplied, so external file tampering cannot leave an ACCEPT visible in a fresh summary read.
