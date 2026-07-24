import { expect, test } from "bun:test";
import { join } from "node:path";

test("OEF identifiers remain nominally distinct under TypeScript", () => {
  const root = join(import.meta.dir, "..");
  const result = Bun.spawnSync({
    cmd: [process.execPath, "x", "tsc", "--noEmit", "-p", "tests/typecheck/oef-phase0.tsconfig.json"],
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });

  const output = `${result.stdout.toString()}${result.stderr.toString()}`;
  expect(result.exitCode, output).toBe(0);
});
