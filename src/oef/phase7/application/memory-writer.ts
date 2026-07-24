import type { MemoryRecord } from "../../phase6/core/domain";
import { SqliteMemoryStore } from "../../phase6/persistence/sqlite-store";
import type { Phase6IncidentMemoryWriter } from "./service";

export class SqlitePhase6IncidentMemoryWriter implements Phase6IncidentMemoryWriter {
  constructor(private readonly store: SqliteMemoryStore) {}

  write(records: readonly MemoryRecord[]): void {
    this.store.transaction(() => {
      for (const record of records) {
        const existing = this.store.get(record.memory_id);
        if (!existing) {
          this.store.create(record);
        } else if (existing.integrity.content_hash !== record.integrity.content_hash) {
          throw new Error("PHASE7_MEMORY_IDEMPOTENCY_CONFLICT");
        }
      }
    });
  }
}
