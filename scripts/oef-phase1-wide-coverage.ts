import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative } from "node:path";

interface CoverageTotals {
  functionsFound: number;
  functionsHit: number;
  linesFound: number;
  linesHit: number;
}

const repositoryRoot = process.cwd();
const workRoot = join(repositoryRoot, "work");
mkdirSync(workRoot, { recursive: true });
const temporary = mkdtempSync(join(workRoot, "oef-phase1-wide-coverage-"));

const normalize = (value: string): string => value.replaceAll("\\", "/");
const productionFiles = (root: string): string[] => readdirSync(root, { withFileTypes: true }).flatMap(entry => {
  const path = join(root, entry.name);
  if (entry.isDirectory()) return productionFiles(path);
  return entry.isFile() && entry.name.endsWith(".ts") ? [normalize(relative(repositoryRoot, path))] : [];
});

try {
  const phase1Tests = readdirSync(join(repositoryRoot, "tests"))
    .filter(name => name.startsWith("oef-phase1") && name.endsWith(".test.ts"))
    .sort()
    .map(name => join(repositoryRoot, "tests", name));
  const child = Bun.spawn({
    cmd: [
      process.execPath,
      "test",
      "--isolate",
      "--coverage",
      "--coverage-reporter=lcov",
      "--coverage-dir",
      temporary,
      ...phase1Tests,
    ],
    cwd: repositoryRoot,
    stdout: "inherit",
    stderr: "inherit",
  });
  const exitCode = await child.exited;
  if (exitCode !== 0) process.exit(exitCode);

  const blocks = readFileSync(join(temporary, "lcov.info"), "utf8").split("end_of_record");
  const coverage = new Map<string, CoverageTotals>();
  for (const block of blocks) {
    const source = block.match(/^SF:(.+)$/m)?.[1];
    if (!source) continue;
    const metric = (name: string): number => Number(block.match(new RegExp(`^${name}:(\\d+)$`, "m"))?.[1] ?? 0);
    coverage.set(normalize(source), {
      functionsFound: metric("FNF"),
      functionsHit: metric("FNH"),
      linesFound: metric("LF"),
      linesHit: metric("LH"),
    });
  }

  const expected = [
    ...productionFiles(join(repositoryRoot, "src", "oef", "phase1")),
    "src/cli/oef.ts",
  ].filter(path => path !== "src/oef/phase1/core/index.ts").sort();
  const missing = expected.filter(path => !coverage.has(path));
  if (missing.length > 0) {
    console.error(`Phase 1 coverage is missing production files:\n${missing.join("\n")}`);
    process.exit(1);
  }

  const totals = expected.reduce<CoverageTotals>((result, path) => {
    const current = coverage.get(path)!;
    result.functionsFound += current.functionsFound;
    result.functionsHit += current.functionsHit;
    result.linesFound += current.linesFound;
    result.linesHit += current.linesHit;
    return result;
  }, { functionsFound: 0, functionsHit: 0, linesFound: 0, linesHit: 0 });
  const functionRate = totals.functionsFound === 0 ? 100 : totals.functionsHit / totals.functionsFound * 100;
  const lineRate = totals.linesFound === 0 ? 100 : totals.linesHit / totals.linesFound * 100;
  console.log(`Phase 1 wide coverage: functions ${functionRate.toFixed(2)}%, lines ${lineRate.toFixed(2)}%`);
  if (functionRate < 80 || lineRate < 80) {
    console.error("Phase 1 wide coverage must remain at or above 80% for functions and lines.");
    process.exit(1);
  }
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
