import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const args = process.argv.slice(2);
const option = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const mode = option("--mode");
if (mode !== "initial" && mode !== "repair") throw new Error("Phase 3 acceptance worker requires --mode initial|repair");

const implementation = join(process.cwd(), "src", "providers", "clinepass", "error-classifier.ts");
const testFile = join(process.cwd(), "tests", "providers", "clinepass", "error-classifier.test.ts");
mkdirSync(dirname(implementation), { recursive: true });
mkdirSync(dirname(testFile), { recursive: true });

const source = mode === "initial" ? [
  "export function classifyStatus(status: number): string {",
  "  if (status === 429 || status === 403) return 'rate-limit';",
  "  if (status === 401) return 'auth-failure';",
  "  return 'other';",
  "}",
  "",
] : [
  "export function classifyStatus(status: number): string {",
  "  if (status === 429) return 'rate-limit';",
  "  if (status === 401 || status === 403) return 'auth-failure';",
  "  return 'other';",
  "}",
  "",
];
const tests = mode === "initial" ? [
  "import { expect, test } from 'bun:test';",
  "import { classifyStatus } from '../../../src/providers/clinepass/error-classifier';",
  "test('401 remains an auth failure', () => expect(classifyStatus(401)).toBe('auth-failure'));",
  "test('403 is treated as rate limit (regression)', () => expect(classifyStatus(403)).toBe('rate-limit'));",
  "test('429 is a rate limit', () => expect(classifyStatus(429)).toBe('rate-limit'));",
  "",
] : [
  "import { expect, test } from 'bun:test';",
  "import { classifyStatus } from '../../../src/providers/clinepass/error-classifier';",
  "test('401 remains an auth failure', () => expect(classifyStatus(401)).toBe('auth-failure'));",
  "test('403 remains an auth failure', () => expect(classifyStatus(403)).toBe('auth-failure'));",
  "test('429 is a rate limit', () => expect(classifyStatus(429)).toBe('rate-limit'));",
  "",
];
writeFileSync(implementation, source.join("\n"), "utf8");
writeFileSync(testFile, tests.join("\n"), "utf8");

for (const row of [
  { sequence: 1, type: "execution.started", payload: { mode } },
  { sequence: 2, type: "file.observed", payload: { path: "src/providers/clinepass/error-classifier.ts" } },
  { sequence: 3, type: "file.observed", payload: { path: "tests/providers/clinepass/error-classifier.test.ts" } },
  { sequence: 4, type: "execution.completed", payload: { exit_code: 0, mode } },
]) process.stdout.write(`${JSON.stringify(row)}\n`);
