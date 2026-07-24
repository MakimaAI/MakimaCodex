import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";

const workRoot = join(process.cwd(), "work");
mkdirSync(workRoot, { recursive: true });
const temporary = mkdtempSync(join(workRoot, "oef-phase1-core-coverage-"));
const bundlePath = join(temporary, "core.mjs");

try {
  const build = await Bun.build({
    entrypoints: [join(process.cwd(), "src", "oef", "phase1", "core", "index.ts")],
    target: "node",
    format: "esm",
    packages: "external",
    sourcemap: "inline",
  });
  if (!build.success) {
    for (const log of build.logs) console.error(log);
    process.exitCode = 1;
  } else {
    await Bun.write(bundlePath, build.outputs[0]);
    const child = Bun.spawn({
      cmd: [
        "node",
        "--test",
        "--experimental-test-coverage",
        `--test-coverage-include=${bundlePath.replaceAll("\\", "/")}`,
        "--test-coverage-branches=90",
        "--test-coverage-functions=90",
        "--test-coverage-lines=80",
        join(process.cwd(), "tests", "node", "oef-phase1-core-coverage.test.ts"),
      ],
      env: { ...process.env, OEF_CORE_BUNDLE: bundlePath },
      stdout: "inherit",
      stderr: "inherit",
    });
    process.exitCode = await child.exited;
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
