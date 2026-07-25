import { afterEach, describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PHASE6_PUBLIC_SCHEMAS, generatePhase6Schemas, phase6JsonSchemaDocument } from "../scripts/generate-oef-phase6-schemas";

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

describe("Phase 6 public JSON schema contracts", () => {
  test("generates every public schema deterministically", () => {
    const root = mkdtempSync(join(tmpdir(), "phase6-schemas-")); roots.push(root);
    generatePhase6Schemas(root);
    expect(readdirSync(root).sort()).toEqual(PHASE6_PUBLIC_SCHEMAS.map(entry => entry.file).sort());
    for (const entry of PHASE6_PUBLIC_SCHEMAS) {
      const path = join(root, entry.file);
      expect(existsSync(path)).toBeTrue();
      expect(JSON.parse(readFileSync(path, "utf8"))).toEqual(phase6JsonSchemaDocument(entry));
    }
  });

  test("keeps checked-in schemas synchronized with runtime validators", () => {
    const root = join(process.cwd(), "schemas", "oef-phase6");
    for (const entry of PHASE6_PUBLIC_SCHEMAS) {
      expect(JSON.parse(readFileSync(join(root, entry.file), "utf8"))).toEqual(phase6JsonSchemaDocument(entry));
    }
  });
});
