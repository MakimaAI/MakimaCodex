import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import addFormats from "ajv-formats";
import { z } from "zod";
import { PHASE2_PUBLIC_SCHEMAS } from "../src/oef/phase2";

const schemaRoot = join(import.meta.dir, "..", "schemas", "oef", "phase2");

describe("Phase 2 public JSON schemas", () => {
  test("ships a parseable, strict, drift-free schema for every public boundary", () => {
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    expect(PHASE2_PUBLIC_SCHEMAS.length).toBeGreaterThanOrEqual(12);
    for (const entry of PHASE2_PUBLIC_SCHEMAS) {
      const actual = JSON.parse(readFileSync(join(schemaRoot, entry.file), "utf8"));
      const expected = {
        ...z.toJSONSchema(entry.schema),
        $id: `https://opencodex.local/schemas/oef/phase2/${entry.file}`,
      };
      expect(actual, entry.file).toEqual(expected);
      expect(() => ajv.compile(actual), `${entry.file}: ${ajv.errorsText()}`).not.toThrow();
      expect(actual.additionalProperties, entry.file).toBeFalse();
    }
  });
});
