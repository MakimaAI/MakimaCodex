import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

const workRoot = join(process.cwd(), "work");
mkdirSync(workRoot, { recursive: true });
const temporary = mkdtempSync(join(workRoot, "oef-phase2-core-coverage-"));
const entry = join(temporary, "entry.ts");
const bundle = join(temporary, "core.mjs");

try {
  await Bun.write(entry, [
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "core", "domain.ts"))};`,
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "core", "ids.ts"))};`,
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "core", "infrastructure.ts"))};`,
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "application", "retry-policy.ts"))};`,
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "application", "recovery.ts"))};`,
    `export * from ${JSON.stringify(join(process.cwd(), "src", "oef", "phase2", "workspace", "path-policy.ts"))};`,
  ].join("\n"));
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
      join(process.cwd(), "tests", "node", "oef-phase2-core-coverage.test.ts"),
    ],
    env: { ...process.env, OEF_PHASE2_CORE_BUNDLE: bundle },
    stdout: "inherit",
    stderr: "inherit",
  });
  process.exitCode = await child.exited;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
