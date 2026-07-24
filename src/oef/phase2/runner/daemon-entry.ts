import { runLocalRunnerDaemon } from "./daemon";

const homeIndex = process.argv.indexOf("--home");
const home = homeIndex >= 0 ? process.argv[homeIndex + 1] : undefined;
if (!home) throw new Error("Usage: bun daemon-entry.ts --home <path>");
await runLocalRunnerDaemon({ home });
