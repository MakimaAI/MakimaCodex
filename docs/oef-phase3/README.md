# OEF Phase 3: independent review governance

Phase 3 turns a Phase 2 evidence package into a review decision. It does not
replace Phase 2 execution or make a deployment decision. A review is bound to
an immutable snapshot of the contract, source tree, diff, evidence, workflow,
and policy.

## What is implemented here

- Versioned review requests, profiles, plans, snapshots, findings, bindings,
  results, validations, decisions, waivers, and repair proposals.
- A deterministic plan compiler that selects review types from requested scope,
  changed paths, dependency changes, API changes, and risk signals.
- Independent reviewer bindings, structured result parsing, finding validation,
  deduplication, quorum evaluation, and deterministic adjudication.
- A copied review environment launched only through a pinned Docker image with
  `--network none`, a read-only root, dropped capabilities, no-new-privileges,
  read-only source/evidence/artifact mounts, integrity hashes, and one scoped
  writable temporary mount.
- Coordinator ports for execution, persistence, artifacts, audit, cancellation,
  and idempotent effects; the concrete Phase 2 runner can execute review
  commands through the review executor.
- A JSON `ocx review` CLI with durable run manifests, pinned-Docker dispatch,
  exact-execution cancellation receipts, a persistent `review start` lifecycle through adjudication,
  snapshot-bound delta reruns, and real Phase 2 repair-assignment creation, plus a deterministic 22-step acceptance demo
  that runs an initial Phase 2 implementation, three independent read-only
  reviewer sessions, a Phase 2 repair assignment, delta review, and the final
  Phase 1 `ACCEPT` handoff.
- Public JSON Schemas generated from the exported Zod schemas. Run
  `bun run generate:oef:phase3-schemas` after intentionally changing a public
  boundary.

## Deliberate boundaries

- Reviewers propose findings; they do not mutate the original source tree or
  issue a final task verdict themselves.
- Reviewer execution fails closed unless a digest-pinned Docker sandbox is
  configured. The executor denies networking, does not mount host credential
  paths, and rejects command paths outside the prepared review roots.
- The local acceptance runtime is deterministic, but its reviewer processes
  inspect the mounted source instead of replaying prepared verdicts. Each run
  probes that outbound networking and host Docker credentials are unavailable.
  It does not claim that every external model provider is production-integrated.
- A `PASS` is a Phase 3 review decision. Mapping it to a Phase 1 verdict is a
  separate explicit operation; the acceptance demo exercises that operation.

## Verification

```bash
bun run generate:oef:phase3-schemas
bun run coverage:oef:phase3
bun run oef:phase3:demo --root work/phase3-acceptance
```

Read [the lifecycle](lifecycle.md), [trust model](security-trust-model.md),
[ADR](adr-0001-independent-review.md), and [acceptance trace](acceptance-matrix.md)
with the source under `src/oef/phase3`.
