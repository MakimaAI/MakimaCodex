import { existsSync, writeFileSync } from "node:fs";

const mode = process.argv[2] ?? "pass";
const state = process.argv[3];
if (mode === "pass") {
  console.log("verification passed");
} else if (mode === "fail") {
  console.error("deterministic failure");
  process.exitCode = 2;
} else if (mode === "flaky") {
  if (!state) throw new Error("flaky mode requires state path");
  if (existsSync(state)) console.log("second run passed");
  else { writeFileSync(state, "seen"); console.error("first run failed"); process.exitCode = 1; }
} else if (mode === "hang") {
  setInterval(() => {}, 1_000);
} else if (mode === "wait-file") {
  if (!state) throw new Error("wait-file mode requires state path");
  const timer = setInterval(() => {
    if (!existsSync(state)) return;
    clearInterval(timer);
    console.log("release observed");
  }, 20);
} else if (mode === "secret") {
  console.log("Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456");
}
