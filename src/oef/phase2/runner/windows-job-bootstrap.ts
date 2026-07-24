import { existsSync, readFileSync } from "node:fs";

const args = process.argv.slice(2);
const option = (name: string): string => {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : undefined;
  if (!value) throw new Error(`Missing ${name}`);
  return value;
};

const gatePath = option("--gate");
const shutdownPath = option("--shutdown");
const graceMs = Number(option("--grace-ms"));
if (!Number.isInteger(graceMs) || graceMs < 0 || graceMs > 600_000) throw new Error("WINDOWS_JOB_INVALID_GRACE_MS");
const planPath = option("--plan");
const deadline = Date.now() + 30_000;
while (!existsSync(gatePath)) {
  if (Date.now() >= deadline) throw new Error("WINDOWS_JOB_GATE_TIMEOUT");
  await Bun.sleep(2);
}

const plan = JSON.parse(readFileSync(planPath, "utf8")) as {
  executable: string;
  arguments: string[];
  stdin: { mode: "closed" } | { mode: "pipe" } | { mode: "bytes"; content_base64: string };
};
const child = Bun.spawn([plan.executable, ...plan.arguments], {
  stdin: plan.stdin.mode === "closed" ? "ignore" : "pipe",
  stdout: "inherit",
  stderr: "inherit",
  windowsHide: true,
});
if (plan.stdin.mode === "bytes") {
  if (!child.stdin || typeof child.stdin === "number") throw new Error("WINDOWS_JOB_CHILD_STDIN_MISSING");
  child.stdin.write(Buffer.from(plan.stdin.content_base64, "base64"));
  child.stdin.end();
} else if (plan.stdin.mode === "pipe" && child.stdin && typeof child.stdin !== "number") child.stdin.end();
let shutdownRequested = false;
let exitCode: number | null = null;
while (exitCode === null) {
  const outcome = await Promise.race([
    child.exited.then(code => ({ type: "exit" as const, code })),
    Bun.sleep(20).then(() => ({ type: "poll" as const, code: null })),
  ]);
  if (outcome.type === "exit") { exitCode = outcome.code; break; }
  if (!shutdownRequested && existsSync(shutdownPath)) {
    shutdownRequested = true;
    try { child.kill("SIGTERM"); } catch { /* child may have exited between poll and signal */ }
    await Bun.sleep(graceMs);
    exitCode = child.exitCode;
    break;
  }
}
process.exitCode = typeof exitCode === "number" ? exitCode : shutdownRequested ? 143 : 1;
