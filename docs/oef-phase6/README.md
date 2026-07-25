# OpenCodex Memory OS — Faz 6 Operasyon Rehberi

Faz 6, Faz 1–5'in gerçek durumunu değiştirmez. Kanıt, episode, lesson ve procedure candidate kayıtlarını immutable revision ve provenance zinciriyle saklar; yalnızca scope/ACL, lifecycle, temporal validity, trust ve token-budget kontrollerinden geçen küçük bir Context Pack üretir.

## Güven sınırları

- Canonical gerçek: SQLite record + immutable revision chain + provenance.
- Türetilmiş gerçek olmayan yüzeyler: FTS ve vector index; canonical store'dan yeniden üretilebilir.
- `SECRET` memory kaydı yasaktır. Ingestion kalıcı kuyruğa girmeden önce redaction uygular.
- Agent, kendi çıktısını `VERIFIED`/`PROMOTED` yapamaz. Verifier veya human evidence gate gerekir.
- Governance yalnızca human actor ile oluşturulur veya değiştirilir.
- Harici backend sonucu `UNTRUSTED` + `OBSERVED` + `instruction_authority=NONE` olarak döner.
- Automatic injection yalnızca `prepareContextPack` sonrası doğru delivery ID + pack hash ACK'iyle deduplicate edilir.

## Ana komutlar

```text
ocx memory search "HTTP 403 authorization" --scope repository:opencodex --json
ocx memory show memory:lesson-403 --scope repository:opencodex --scope provider:clinepass --json
ocx memory provenance memory:lesson-403 --scope repository:opencodex --scope provider:clinepass --json
ocx memory explain-query memory-query:... --scope repository:opencodex --json
ocx memory candidates --status candidate --scope repository:opencodex --json
ocx memory promote memory-candidate:... --evidence evidence:... --scope repository:opencodex --json
ocx memory hygiene run --json
ocx memory health --json
ocx memory audit --json
ocx memory reindex --json
ocx memory reembed --profile-file embedding-profile.json --json
ocx memory backup --output backups --json
ocx memory restore --backup backups/memory-backup-... --target-home restored-memory --json
```

`correct`, `deprecate`, `forget`, `candidates`, `promote`, `show`, `provenance` ve `explain-query` komutlarında explicit `--scope` zorunludur. `LEGAL_DELETE` ve `SECRET_PURGE`, local artifact manifest/root olmadan fail-closed davranır.

## Durable ingestion davranışı

```text
Source event
→ redaction
→ idempotency hash
→ QUEUED
→ LEASED
→ episode compiler
→ canonical transaction
→ COMPLETED
```

Worker çökerse lease süresi dolunca başka worker görevi alır. Her claim attempt sayısını artırır. Sınır dolunca job `DEAD_LETTER` olur; sonraki job'lar çalışmaya devam eder. Aynı idempotency key + aynı event hash tek job üretir; aynı key + farklı içerik conflict olarak reddedilir.

## Vector ve re-embedding

Varsayılan adapter ağ çağrısı yapmayan deterministic local hash embedding kullanır. Profile; ID, semver, dimension, provider ve maksimum sensitivity taşır. `RESTRICTED` kayıt varsayılan profile ile embed edilmez. Rebuild önce bütün yeni generation'ı hazırlar, ardından tek transaction içinde active pointer'ı değiştirir. Provider hatası eski generation'ı aktif bırakır.

## Backup ve restore

Backup; serialized canonical SQLite, database SHA-256, gerçek artefakt byte kopyaları, her artefakt için SHA-256 + boyut ve encryption metadata içerir. Key material içermez. Backup öncesi canonical, provenance, scope, lexical ve mevcut vector generation sağlığı doğrulanır. Restore, hedefe yazmadan önce database ve artefakt byte hashlerini ve SQLite integrity check'i doğrular; lexical indexi canonical store'dan yeniden kurar, türetilmiş vector generation'ı siler ve `vector_rebuild_required=true` döndürür. Sonraki adım version-pinned `memory reembed` olmalıdır. Mevcut hedefin üzerine restore için explicit `--allow-overwrite` gerekir; `-wal`/`-shm` varsa restore fail-closed olur ve eski database rollback dosyası olarak korunur.

## Doğrulama

```text
bun test --isolate ./tests/oef-phase6*.test.ts
bun run typecheck
bun scripts/oef-phase6-core-coverage.ts
bun run privacy:scan
bun run src/cli/index.ts oef-phase6-demo --root <artifact-directory> --json
```

Coverage kapısı Memory Core içindeki dokuz kritik dosyanın her birinde Bun'un ölçebildiği functions ve lines değerlerinde en az %90 ister. Bun 1.3.14 LCOV çıktısı branch counter üretmediği için gerçek branch coverage yüzdesi ayrıca kanıtlanmış sayılmaz. Acceptance raporu ingestion, promotion, vector health, plugin boundary, backup hashes, retrieval precision, verified precision, citation completeness, scope leakage, secret leakage, supersession ve injection dedup sonuçlarını birlikte verir.

## Açık operasyon önkoşulları

Production rollout için Faz 1–5 outbox collector wiring, Faz 2 runtime delivery receipt entegrasyonu, authenticated network authorization resolver, vendor plugin process sandbox, application-level encryption/key rotation ve gerçek production dağılımını temsil eden büyük benchmark corpus'u gerekir. Bu yüzeyler mevcut local core tarafından aktifmiş gibi raporlanmaz.
