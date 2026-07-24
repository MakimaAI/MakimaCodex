# Schema Evolution

Every command, contract, event, evidence record, verdict, trace, and projection carries a schema version. JSON schemas under `schemas/oef` document the public v1 envelopes; strict Zod schemas are the runtime authority. Parity tests send representative valid documents, root-extension failures, and generated nested pattern/limit/type failures for all 11 published schemas through both Ajv and the runtime validators. Cross-record semantic invariants such as workflow graph references and duplicate criterion keys remain explicit runtime checks because standard JSON Schema cannot express those identity relationships portably.

Historical rows are never rewritten merely to match a new in-memory shape. `EventUpcaster` transforms a copy at read time. The included v0 actor upcaster converts legacy `actor_id` into the v1 actor object and demonstrates the compatibility path.

Compatible changes include optional fields, new event/evidence types, and new namespaced extensions. Meaning changes, removed required fields, reused event meanings, or repurposed enum values require a new major schema version and an explicit upcaster.

Migration files are roll-forward only. Production data is not dropped and recreated.
