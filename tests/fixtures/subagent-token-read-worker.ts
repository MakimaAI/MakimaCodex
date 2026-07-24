import { readSecureSubagentBridgeToken } from "../../src/subagent-bridge/lifecycle";

const token = readSecureSubagentBridgeToken({
  platform: "win32",
  inspectTokenSecurity: () => {
    throw new Error("deep ACL inspection must not run");
  },
});

process.stdout.write(token ? "ok" : "unavailable");
