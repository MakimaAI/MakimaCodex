const args = process.argv.slice(2);
const mode = args[0] ?? "silent";
const option = (name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};

const emit = (value: unknown) => process.stdout.write(`${JSON.stringify(value)}\n`);

if (mode === "echo-env") {
  emit({
    sequence: 1,
    type: "execution.started",
    payload: {
      secret: process.env.TEST_PHASE2_SECRET ?? null,
      ambient: process.env.UNLISTED_PHASE2_SECRET ?? null,
    },
  });
} else if (mode === "idle") {
  emit({ sequence: 1, type: "execution.started", payload: {} });
  setInterval(() => {}, 1_000);
} else if (mode === "heartbeat") {
  let sequence = 0;
  setInterval(() => emit({ sequence: ++sequence, type: sequence === 1 ? "execution.started" : "runtime.observation", payload: {} }), 25);
} else if (mode === "output-limit") {
  emit({ sequence: 1, type: "execution.started", payload: {} });
  for (let index = 0; index < 300; index += 1) process.stdout.write(`${"x".repeat(400)}\n`);
  setInterval(() => {}, 1_000);
} else if (mode === "long-line") {
  emit({ sequence: 1, type: "execution.started", payload: {} });
  process.stdout.write(`${"y".repeat(20_000)}\n`);
} else if (mode === "child-hang") {
  const pidFile = option("--pid-file");
  if (!pidFile) throw new Error("--pid-file is required");
  const child = Bun.spawn([process.execPath, import.meta.path, "grandchild"], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
  child.unref();
  await Bun.write(pidFile, String(child.pid));
  emit({ sequence: 1, type: "execution.started", payload: { child_pid: child.pid } });
  setInterval(() => {}, 1_000);
} else if (mode === "parent-exits-first") {
  const pidFile = option("--pid-file");
  if (!pidFile) throw new Error("--pid-file is required");
  const child = Bun.spawn([process.execPath, import.meta.path, "grandchild"], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
  child.unref();
  await Bun.write(pidFile, String(child.pid));
  emit({ sequence: 1, type: "execution.started", payload: { child_pid: child.pid } });
} else if (mode === "grandchild" || mode === "silent") {
  setInterval(() => {}, 1_000);
} else {
  throw new Error(`Unknown fixture mode: ${mode}`);
}
