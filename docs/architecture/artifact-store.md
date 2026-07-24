# Artifact Store

`ArtifactStore` is a core-facing port. The Phase 1 adapter is `LocalArtifactStore`; future S3 or blob adapters can implement the same contract.

Content is addressed by SHA-256 beneath the allowed root:

```text
artifacts/ab/cd/abcdef...64-hex
```

Callers submit bytes, never a destination path. The adapter derives the storage key, writes through a temporary file, and reuses existing physical content. Separate artifact metadata can point at the same content hash.

The local adapter rejects secret classification, likely token patterns, oversized input, malformed references, absolute/traversal keys, symlink roots, symlink path segments, and symlink destinations. `verify()` rereads and rehashes content. `findOrphans()` identifies content not registered in current metadata after a crash seam.
