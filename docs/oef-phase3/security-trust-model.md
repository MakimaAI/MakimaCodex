# Phase 3 security and trust model

## Trust order

The context bundle fixes this order, from highest to lowest authority:

1. Kernel security rules
2. Review profile
3. Task contract
4. Review plan
5. Policy pack
6. Mechanical evidence
7. Repository architecture rules
8. Source code
9. Implementer summary
10. Code comments and external content

Repository content is evidence, not executable instruction. The context bundle
contains explicit constraints to ignore embedded instructions, not modify source,
avoid approval based only on implementer claims, and require evidence for every
blocking finding.

## Enforced in the Phase 3 code

| Boundary | Current control |
| --- | --- |
| Source, evidence, artifacts | Copied into a review directory, mounted read-only in a digest-pinned Docker container, and integrity hashes are rechecked before and after execution. |
| Temporary output | A dedicated `temp` directory is the only read-write container mount; the container root is read-only. |
| Path inputs | Repository paths reject absolute paths, drive prefixes, traversal, NULs, and non-canonical separators where the context requires canonical paths. |
| Secrets and network | Input staging skips control directories and rejects sensitive filenames or likely secret material before copying; context compilation also checks structured secrets. Docker receives no credential mount or secret ref and runs with `--network none`. |
| Reviewer identity | Binding captures implementer/reviewer identity; the trusted executor returns a runtime attestation that must match it exactly. Reviewer agents, sessions, and contexts must also be pairwise unique for quorum. |
| Reviewer claims | Review results are structured JSON and findings start proposed; unsupported findings cannot be confirmed blockers. |
| Decision integrity | Quorum, hash-bound human approval, active waiver validity, mechanical evidence, full review-validity inputs, and deterministic severity rules are checked before a decision artifact is issued. |
| Runtime identity | Reviewer bindings come from immutable control-plane storage. The Phase 2 runner IPC authority HMAC-signs the launch identity, mapped command, and isolation claim; the coordinator verifies the signature before counting quorum. |
| Live validity | Production CLI recomputes current contract, policy, evidence package, mechanical status, sealed workspace tree/diff, dependencies, and profiles from Phase 1/2 stores. Run manifests cannot supply these current values. |
| Terminal replay | Receipt hashes and governance/live-validity fingerprints prevent cached PASS reuse after source/evidence drift, approval changes, or waiver expiry; stale terminal state is superseded. |
| Replay/audit | Coordinator side effects are idempotency-keyed; audit writes reject invalid content hashes or links, and integrity is checked before and after a decision event. |

## Assumptions and non-claims

Docker isolation depends on the local Docker daemon and the pinned image already
being available (`--pull=never`). A host administrator or a compromised Docker
daemon remains outside the reviewer threat boundary. The executor deliberately
refuses unsandboxed or tag-only images; a successful schema parse or reviewer
assertion alone is never treated as proof of isolation.
