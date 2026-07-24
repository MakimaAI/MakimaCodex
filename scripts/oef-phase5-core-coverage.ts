import { join } from "node:path";

const child = Bun.spawn([process.execPath, "test", "--isolate", "--coverage", join(process.cwd(), "tests", "oef-phase5-routing-core.test.ts"), join(process.cwd(), "tests", "oef-phase5-system.test.ts")], { stdout: "pipe", stderr: "pipe", cwd: process.cwd() });
const [stdout, stderr, exitCode] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
process.stdout.write(stdout); process.stderr.write(stderr); if (exitCode !== 0) process.exit(exitCode);
const rows = `${stdout}\n${stderr}`.split(/\r?\n/).filter(line => /phase5[\\/]application[\\/]routing-kernel\.ts|phase5[\\/]core[\\/]domain\.ts/.test(line));
if (rows.length !== 2) throw new Error("Phase 5 routing core coverage rows were not found");
for (const row of rows) {
  const match = row.match(/\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|/); if (!match) throw new Error(`Malformed coverage row: ${row}`);
  const functions = Number(match[1]); const lines = Number(match[2]);
  if (functions < 90 || lines < 90) throw new Error(`Phase 5 routing core coverage below 90%: functions=${functions}, lines=${lines}`);
}
console.log("Phase 5 routing core coverage gate passed: all core rows >=90% functions/lines (Bun's available branch proxy).");
