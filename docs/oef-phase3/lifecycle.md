# Phase 3 lifecycle

```text
Phase 2 sealed evidence
  -> ReviewRequest + snapshot
  -> compile/pin ReviewPlan and ReviewProfile
  -> bind independent reviewer
  -> copied read-only environment + structured context
  -> pinned, networkless Docker runner execution + runtime attestation
  -> schema-validated ReviewResult
  -> proposed finding -> validation -> deduplication
  -> quorum + current-snapshot check + deterministic adjudication
  -> ReviewDecision
     PASS/PASS_WITH_NOTES -> explicit Phase 1 verdict mapping
     CHANGES_REQUESTED   -> RepairProposal -> new Phase 2 assignment
     BLOCKED             -> explicit Phase 1 verdict mapping
     NEEDS_HUMAN         -> human gate
     INCONCLUSIVE        -> redispatch or new review plan
```

## State rules

- A review plan advances through prerequisites, execution, collection,
  validation, adjudication, and a terminal decision. It may be cancelled or
  superseded; terminal plans may only become superseded.
- A finding is an evidence-bound claim. `PROPOSED` is not a blocker;
  confirmation requires usable evidence. Duplicate records point at a canonical
  finding, and verified resolution needs a new snapshot plus independent
  validation, regression evidence, and a non-reproducing failure.
- A waiver is revalidated at decision time against its finding hash, severity,
  expiry, and snapshot. It does not travel silently to a changed review snapshot.
- The coordinator checks snapshot currency and the complete validity baseline
  (contract, source, diff, evidence, policy, profiles, required evidence, and
  dependencies) before execution and before issuing the decision. Any mismatch
  yields `INCONCLUSIVE`, never a pass.
- Cancellation preserves the review-level decision trail through ports, but
  does not cancel the original task automatically.
