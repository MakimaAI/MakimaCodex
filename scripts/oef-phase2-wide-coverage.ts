import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative } from "node:path";

interface Totals { functionsFound: number; functionsHit: number; linesFound: number; linesHit: number }
const repositoryRoot = process.cwd();
const workRoot = join(repositoryRoot, "work");
mkdirSync(workRoot, { recursive: true });
const temporary = mkdtempSync(join(workRoot, "oef-phase2-wide-coverage-"));
const normalize = (value: string): string => value.replaceAll("\\", "/");
const files = (root: string): string[] => readdirSync(root, { withFileTypes: true }).flatMap(entry => {
  const path = join(root, entry.name);
  return entry.isDirectory() ? files(path) : entry.isFile() && entry.name.endsWith(".ts") ? [normalize(relative(repositoryRoot, path))] : [];
});

try {
  const tests = readdirSync(join(repositoryRoot, "tests"))
    .filter(name => name.startsWith("oef-phase2-") && name.endsWith(".test.ts"))
    .sort()
    .map(name => join(repositoryRoot, "tests", name));
  const child = Bun.spawn({
    cmd: [process.execPath, "test", "--isolate", "--coverage", "--coverage-reporter=lcov", "--coverage-dir", temporary, ...tests],
    cwd: repositoryRoot,
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) process.exit(exitCode);
  const coverage = new Map<string, Totals>();
  for (const block of readFileSync(join(temporary, "lcov.info"), "utf8").split("end_of_record")) {
    const source = block.match(/^SF:(.+)$/m)?.[1];
    if (!source) continue;
    const metric = (name: string) => Number(block.match(new RegExp(`^${name}:(\\d+)$`, "m"))?.[1] ?? 0);
    coverage.set(normalize(source), { functionsFound: metric("FNF"), functionsHit: metric("FNH"), linesFound: metric("LF"), linesHit: metric("LH") });
  }
  // These files execute only in separately spawned child processes. Their behavior is
  // covered by supervisor/daemon integration tests, while Bun cannot merge child LCOV.
  const childEntrypoints = new Set([
    "src/oef/phase2/runner/daemon-entry.ts",
    "src/oef/phase2/runner/fake-worker.ts",
    "src/oef/phase2/runner/unix-pdeathsig-watchdog.ts",
    "src/oef/phase2/runner/windows-job-bootstrap.ts",
    "src/oef/phase2/runtime/adapters/fake-worker.ts",
  ]);
  const expected = [...files(join(repositoryRoot, "src", "oef", "phase2")), "src/cli/oef-phase2.ts"]
    .filter(path => !childEntrypoints.has(path))
    .sort();
  const missing = expected.filter(path => !coverage.has(path));
  if (missing.length > 0) throw new Error(`Phase 2 coverage is missing production files:\n${missing.join("\n")}`);
  const totals = expected.reduce<Totals>((sum, path) => {
    const value = coverage.get(path)!;
    sum.functionsFound += value.functionsFound;
    sum.functionsHit += value.functionsHit;
    sum.linesFound += value.linesFound;
    sum.linesHit += value.linesHit;
    return sum;
  }, { functionsFound: 0, functionsHit: 0, linesFound: 0, linesHit: 0 });
  const functions = totals.functionsFound === 0 ? 100 : totals.functionsHit / totals.functionsFound * 100;
  const lines = totals.linesFound === 0 ? 100 : totals.linesHit / totals.linesFound * 100;
  console.log(`Phase 2 wide coverage: functions ${functions.toFixed(2)}%, lines ${lines.toFixed(2)}%`);
  if (functions < 90 || lines < 90) throw new Error("Phase 2 wide coverage must remain at or above 90% for functions and lines.");
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
