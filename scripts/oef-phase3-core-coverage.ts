import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

const workRoot = join(process.cwd(), "work");
mkdirSync(workRoot, { recursive: true });
const temporary = mkdtempSync(join(workRoot, "oef-phase3-core-coverage-"));
const entry = join(temporary, "entry.ts");
const bundle = join(temporary, "core.mjs");

try {
  await Bun.write(entry, `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase3", "core", "domain.ts"))};\n`);
  const build = await Bun.build({ entrypoints: [entry], target: "node", format: "esm", packages: "external", sourcemap: "inline" });
  if (!build.success) throw new Error(build.logs.map(String).join("\n"));
  await Bun.write(bundle, build.outputs[0]);
  const child = Bun.spawn({
    cmd: [
      "node",
      "--test",
      "--experimental-test-coverage",
      `--test-coverage-include=${bundle.replaceAll("\\", "/")}`,
      "--test-coverage-branches=90",
      "--test-coverage-functions=90",
      "--test-coverage-lines=90",
      join(process.cwd(), "tests", "node", "oef-phase3-domain-coverage.test.ts"),
    ],
    env: { ...process.env, OEF_PHASE3_CORE_BUNDLE: bundle },
    stdout: "inherit",
    stderr: "inherit",
  });
  process.exitCode = await child.exited;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
