import { readFileSync, readdirSync } from "node:fs";

interface WatchdogPlan {
  executable: string;
  arguments: string[];
  owner_pid: number;
  graceful_shutdown_ms: number;
}

const planPath = option("--plan");
if (!planPath) throw new Error("--plan is required");
const plan = JSON.parse(readFileSync(planPath, "utf8")) as WatchdogPlan;
if (!Number.isInteger(plan.owner_pid) || plan.owner_pid <= 0 || !plan.executable || !Array.isArray(plan.arguments)) {
  throw new Error("INVALID_UNIX_WATCHDOG_PLAN");
}
if (process.ppid !== plan.owner_pid || !processIsAlive(plan.owner_pid)) process.exit(125);

let shuttingDown = false;
const shutdown = () => {
  if (shuttingDown) return;
  shuttingDown = true;
  try { process.kill(-process.pid, "SIGTERM"); } catch {}
  setTimeout(() => {
    try { process.kill(-process.pid, "SIGKILL"); } catch { process.exit(137); }
  }, Math.max(1, plan.graceful_shutdown_ms));
};
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
process.on("SIGHUP", shutdown);

const target = Bun.spawn([plan.executable, ...plan.arguments], {
  cwd: process.cwd(),
  env: process.env,
  stdin: "inherit",
  stdout: "inherit",
  stderr: "inherit",
  windowsHide: true,
  detached: false,
});
const ownerWatch = setInterval(() => {
  if (process.ppid !== plan.owner_pid || !processIsAlive(plan.owner_pid)) shutdown();
}, 100);
const exitCode = await target.exited;
clearInterval(ownerWatch);
if (groupHasMembersExcludingSelf(process.pid)) {
  shutdown();
  await new Promise(() => {});
}
process.exit(Number.isInteger(exitCode) ? exitCode : 1);

function option(name: string): string | null {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] ?? null : null;
}

function processIsAlive(pid: number): boolean {
  try { process.kill(pid, 0); return true; }
  catch (error) { return (error as NodeJS.ErrnoException).code === "EPERM"; }
}

function groupHasMembersExcludingSelf(groupId: number): boolean {
  try {
    for (const entry of readdirSync("/proc")) {
      if (!/^\d+$/.test(entry) || Number(entry) === process.pid) continue;
      try {
        const stat = readFileSync(`/proc/${entry}/stat`, "utf8");
        const fields = stat.slice(stat.lastIndexOf(")") + 2).split(/\s+/);
        if (Number(fields[2]) === groupId) return true;
      } catch { /* process exited during scan */ }
    }
  } catch { return true; }
  return false;
}
