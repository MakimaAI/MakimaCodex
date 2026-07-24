# OEF Phase 5 operator guide

Phase 5 is the adaptive routing and bounded team-composition layer. Its authoritative design is [Phase 5 routing and team composition](../architecture/phase-5-routing-and-team-composition.md).

## Acceptance

Run the deterministic acceptance scenario into a fresh directory:

```powershell
bun run src/cli/index.ts oef-phase5-demo --root work/phase5-acceptance --json
```

Success requires `status: PASS`, no selected quarantined or expired candidates, an independent security reviewer, a budget reservation, a second binding revision after runtime failure, an exact offline replay match, zero policy mutations and zero router secret reads.

## Verification

```powershell
bun test --isolate tests/oef-phase5-routing-core.test.ts tests/oef-phase5-system.test.ts tests/oef-phase5-cli.test.ts tests/oef-phase5-schema-contracts.test.ts
bun scripts/oef-phase5-core-coverage.ts
bun x tsc --noEmit
bun scripts/privacy-scan.ts
```

Generated JSON Schemas live under `schemas/oef-phase5`. Regenerate them with `bun scripts/generate-oef-phase5-schemas.ts` and run the schema-contract test before committing changes.

`route candidates`, `route plan`, and `route activate` require `--availability-file <snapshot.json>`. This is deliberately fail-closed: the CLI never invents a healthy runtime, provider, qualification, kill-switch state, or account capacity.

`route activate` additionally requires `--budget-limit <units>`. Reservations are kept in the routing SQLite database under `--budget-pool` (default `default`), so capacity remains authoritative across CLI restarts.

## Incident posture

- 401: quarantine the affected credential reference; do not rotate blindly.
- 403: treat as permission or policy until validated; do not relabel as quota.
- 429: retry a different capacity-backed account under the same configuration before changing deployment or candidate.
- Security violation: block and escalate.
- Verification failure: return to repair; do not switch infrastructure.
- Stale availability or qualification: mark the plan `REBIND_REQUIRED` and create a new audited revision.
