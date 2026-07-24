import {
  installSubagentBridge,
  removeSubagentBridge,
  statusSubagentBridge,
  type SubagentBridgeLifecycleOptions,
  type SubagentBridgeStatus,
} from "../subagent-bridge/lifecycle";

export interface SubagentCommandDeps {
  lifecycle?: SubagentBridgeLifecycleOptions;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
}

function printStatus(status: SubagentBridgeStatus, write: (line: string) => void): void {
  write(`Bridge installation: ${status.ready ? "ready" : "not ready"}`);
  write(`  Plugin: ${status.installed ? "installed" : "not installed"}`);
  write(`  Config: ${status.enabled ? "enabled" : "disabled"}`);
  write(`  MCP launcher: ${status.mcpReady ? "ready" : "not ready"}`);
  write(`  Marketplace: ${status.marketplaceReady ? "ready" : "missing"}`);
  const authentication = !status.tokenPresent
    ? "missing"
    : status.tokenSecure === true
      ? "secure"
      : status.tokenSecure === false
        ? "insecure"
        : "unknown";
  write(`  Authentication: ${authentication}`);
  write("  Runtime: not checked (run `ocx health`)");
  for (const warning of status.warnings) write(`  Warning: ${warning}`);
}

export function cmdSubagents(args: string[], deps: SubagentCommandDeps = {}): number {
  const stdout = deps.stdout ?? console.log;
  const stderr = deps.stderr ?? console.error;
  if (args[0] !== "bridge" || !["install", "status", "remove"].includes(args[1] ?? "") || args.length !== 2) {
    stderr("Usage: ocx subagents bridge <install|status|remove>");
    return 1;
  }
  try {
    if (args[1] === "install") {
      const status = installSubagentBridge(deps.lifecycle);
      printStatus(status, stdout);
      stdout("Run `ocx restart`, then start a new task so Codex loads the bridge plugin and MCP tool.");
      return 0;
    }
    if (args[1] === "remove") {
      const result = removeSubagentBridge(deps.lifecycle);
      stdout(result.removed ? "Subagent bridge removed." : "Subagent bridge was not installed.");
      stdout("Run `ocx restart`, then start a new task so Codex unloads the bridge plugin and MCP tool.");
      return 0;
    }
    printStatus(statusSubagentBridge(deps.lifecycle), stdout);
    return 0;
  } catch (error) {
    stderr(error instanceof Error ? error.message : String(error));
    return 1;
  }
}
