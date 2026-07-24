import { join } from "node:path";

const child = Bun.spawn([
  process.execPath,
  "test",
  "--isolate",
  "--coverage",
  join(process.cwd(), "tests", "oef-phase4-domain.test.ts"),
], { stdout: "pipe", stderr: "pipe", cwd: process.cwd() });

const [stdout, stderr, exitCode] = await Promise.all([
  new Response(child.stdout).text(),
  new Response(child.stderr).text(),
  child.exited,
]);
process.stdout.write(stdout);
process.stderr.write(stderr);
if (exitCode !== 0) process.exit(exitCode);

const row = `${stdout}\n${stderr}`.split(/\r?\n/).find(line => /phase4[\\/]core[\\/]domain\.ts/.test(line));
const match = row?.match(/\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/);
if (!match) throw new Error("Phase 4 core coverage row was not found");
const functions = Number(match[1]);
const lines = Number(match[2]);
if (functions < 90 || lines < 90) throw new Error(`Phase 4 core coverage below 90%: functions=${functions}, lines=${lines}`);
console.log(`Phase 4 core coverage gate passed: functions=${functions}%, lines=${lines}%`);
