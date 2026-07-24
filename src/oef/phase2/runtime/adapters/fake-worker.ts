import { scenarioRows } from "./fake";
import type { FakeRuntimeScenario } from "../protocol";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const args = process.argv.slice(2);
const option = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const scenario = (option("--scenario") ?? "successful-edit") as FakeRuntimeScenario;
if (scenario === "successful-edit") {
  const implementation = join(process.cwd(), "src", "agent-target.ts");
  const testFile = join(process.cwd(), "tests", "agent-target.test.ts");
  mkdirSync(dirname(implementation), { recursive: true });
  mkdirSync(dirname(testFile), { recursive: true });
  const implementationSource = existsSync(implementation) ? readFileSync(implementation, "utf8") : "export const value = 1;\n";
  const testSource = existsSync(testFile)
    ? readFileSync(testFile, "utf8")
    : "import { expect, test } from 'bun:test';\nimport { value } from '../src/agent-target';\ntest('value', () => expect(value).toBe(1));\n";
  writeFileSync(implementation, implementationSource.replace("value = 1", "value = 2"), "utf8");
  writeFileSync(testFile, testSource.replace("value).toBe(1)", "value).toBe(2)"), "utf8");
}
for (const row of scenarioRows(scenario)) process.stdout.write(`${JSON.stringify(row)}\n`);

if (scenario === "startup-timeout" || scenario === "idle-timeout" || scenario === "child-process-hang") {
  setInterval(() => {}, 1_000);
}

if (scenario === "tool-failure" || scenario === "path-violation" || scenario === "secret-output" || scenario === "context-limit") {
  process.exitCode = 1;
}
