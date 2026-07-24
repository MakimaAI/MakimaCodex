import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PHASE4_PUBLIC_SCHEMAS, phase4JsonSchemaDocument } from "../scripts/generate-oef-phase4-schemas";

describe("Phase 4 public schema contracts", () => {
  test("keeps generated JSON schemas byte-equivalent to the authoritative Zod contracts", () => {
    const root = join(import.meta.dir, "..", "schemas", "oef-phase4");
    expect(PHASE4_PUBLIC_SCHEMAS).toHaveLength(6);
    for (const entry of PHASE4_PUBLIC_SCHEMAS) {
      const committed = JSON.parse(readFileSync(join(root, entry.file), "utf8"));
      expect(committed).toEqual(phase4JsonSchemaDocument(entry));
      expect(committed.$id).toBe(`https://opencodex.local/schemas/oef/phase4/${entry.file}`);
      expect(committed.additionalProperties).toBeFalse();
    }
  });
});
