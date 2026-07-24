import { resolve } from "node:path";
import { runPhase2AcceptanceDemo } from "../src/oef/phase2/application/acceptance-demo";

const args = process.argv.slice(2);
const value = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const runtime = value("--runtime");
if (runtime !== "fake" && runtime !== "codex") throw new Error("Usage: bun scripts/oef-phase2-acceptance-demo.ts --runtime <fake|codex> --root <path>");
const root = value("--root");
if (!root) throw new Error("--root is required");
console.log(JSON.stringify(await runPhase2AcceptanceDemo({ root: resolve(root), runtime }), null, 2));
