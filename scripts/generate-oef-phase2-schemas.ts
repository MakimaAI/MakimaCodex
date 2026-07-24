import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { z } from "zod";
import { PHASE2_PUBLIC_SCHEMAS } from "../src/oef/phase2/schema-registry";

const root = fileURLToPath(new URL("../schemas/oef/phase2/", import.meta.url));
mkdirSync(root, { recursive: true });
for (const entry of PHASE2_PUBLIC_SCHEMAS) {
  const document = {
    ...z.toJSONSchema(entry.schema),
    $id: `https://opencodex.local/schemas/oef/phase2/${entry.file}`,
  };
  writeFileSync(join(root, entry.file), `${JSON.stringify(document, null, 2)}\n`, "utf8");
}
