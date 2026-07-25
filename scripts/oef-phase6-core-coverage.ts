import { join } from "node:path";

const tests = [
  "oef-phase6-domain.test.ts",
  "oef-phase6-storage-retrieval.test.ts",
  "oef-phase6-hardening.test.ts",
  "oef-phase6-ingestion-pipeline.test.ts",
  "oef-phase6-vector-index.test.ts",
  "oef-phase6-operations.test.ts",
  "oef-phase6-benchmark.test.ts",
].map(file => join(process.cwd(), "tests", file));

const child = Bun.spawn([process.execPath, "test", "--isolate", "--coverage", ...tests], {
  stdout: "pipe",
  stderr: "pipe",
  cwd: process.cwd(),
});
const [stdout, stderr, exitCode] = await Promise.all([
  new Response(child.stdout).text(),
  new Response(child.stderr).text(),
  child.exited,
]);
process.stdout.write(stdout);
process.stderr.write(stderr);
if (exitCode !== 0) process.exit(exitCode);

const required = [
  "core/domain.ts",
  "evaluation/benchmark.ts",
  "governance/operations.ts",
  "indexing/local-vector-index.ts",
  "ingestion/pipeline.ts",
  "persistence/backup.ts",
  "persistence/sqlite-store.ts",
  "plugins/protocol.ts",
  "retrieval/engine.ts",
];
const rows = `${stdout}\n${stderr}`.split(/\r?\n/)
  .filter(line => /phase6[\\/]/.test(line));
for (const suffix of required) {
  const row = rows.find(line => line.replaceAll("\\", "/").includes(`phase6/${suffix}`));
  if (!row) throw new Error(`Phase 6 core coverage row missing: ${suffix}`);
  const match = row.match(/\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/);
  if (!match) throw new Error(`Malformed coverage row: ${row}`);
  const functions = Number(match[1]);
  const lines = Number(match[2]);
  if (functions < 90 || lines < 90) {
    throw new Error(`Phase 6 core coverage below 90% for ${suffix}: functions=${functions}, lines=${lines}`);
  }
}
console.log("Phase 6 Memory Core coverage gate passed: every required core row >=90% functions/lines; true branch coverage is not emitted by Bun 1.3.14 and remains unproven.");
