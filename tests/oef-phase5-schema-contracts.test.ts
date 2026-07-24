import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { PHASE5_PUBLIC_SCHEMAS, phase5JsonSchemaDocument } from "../scripts/generate-oef-phase5-schemas";

describe("Phase 5 public schema contracts", () => {
  test("keeps every generated schema byte-equivalent to its authoritative contract", () => {
    const root = join(import.meta.dir, "..", "schemas", "oef-phase5");
    expect(PHASE5_PUBLIC_SCHEMAS).toHaveLength(14);
    for (const entry of PHASE5_PUBLIC_SCHEMAS) {
      const committed = JSON.parse(readFileSync(join(root, entry.file), "utf8"));
      expect(committed).toEqual(phase5JsonSchemaDocument(entry));
      expect(committed.$id).toBe(`https://opencodex.local/schemas/oef/phase5/${entry.file}`);
      expect(committed.additionalProperties).toBeFalse();
    }
  });
});
