import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = dirname(fileURLToPath(new URL("../../package.json", import.meta.url)));

type HelpEntry = {
  usage: string;
  summary: string;
  details?: string[];
};

const helpEntries: Record<string, HelpEntry> = {
  init: { usage: "ocx init", summary: "Interactive setup for providers and Codex config injection." },
  start: { usage: "ocx start [--port <port>]", summary: "Start the proxy server and sync models to Codex." },
  stop: { usage: "ocx stop", summary: "Stop the proxy and restore native Codex config." },
  restore: {
    usage: "ocx restore [back]",
    summary: "Restore native Codex config without stopping the proxy; `restore back` re-points codex at the running proxy.",
  },
  eject: {
    usage: "ocx eject [back]",
    summary: "Restore native Codex config without stopping the proxy; `eject back` re-points codex at the running proxy.",
  },
  "recover-history": {
    usage: "ocx recover-history --legacy-openai",
    summary: "Explicitly recover pre-backup syncResumeHistory rows.",
  },
  uninstall: {
    usage: "ocx uninstall",
    summary: "Remove service/shim/config and restore native Codex.",
    details: ["Alias: ocx remove"],
  },
  remove: {
    usage: "ocx remove",
    summary: "Remove service/shim/config and restore native Codex.",
    details: ["Alias of: ocx uninstall"],
  },
  service: {
    usage: "ocx service [install|start|stop|status|uninstall|remove]",
    summary: "Run as a background service.",
    details: [
      "With no subcommand, installs/updates and starts the background service.",
      "Use `ocx service status` to see diagnostics and log paths.",
    ],
  },
  "codex-shim": {
    usage: "ocx codex-shim <install|status|uninstall|remove>",
    summary: "Auto-start the proxy when `codex` launches.",
    details: ["Use `remove` as an alias for `uninstall`."],
  },
  ensure: { usage: "ocx ensure", summary: "Ensure the proxy is running and Codex config/cache are current." },
  sync: { usage: "ocx sync", summary: "Fetch provider models and inject them into Codex config." },
  subagents: {
    usage: "ocx subagents bridge <install|status|remove>",
    summary: "Install, inspect, or safely remove the routed subagent bridge plugin.",
    details: ["After install, run `ocx restart` and start a new task so Codex loads the MCP tool."],
  },
  route: {
    usage: "ocx route <fingerprint|candidates|plan|show|explain|validate|activate|fallback|outcome> [options] [--json]",
    summary: "Compile task intelligence and produce, validate, activate, inspect, or replay Phase 5 routing decisions.",
  },
  team: {
    usage: "ocx team <compose|show> [task-or-team-id] [--json]",
    summary: "Compose and inspect bounded Phase 5 role DAGs.",
  },
  "oef-phase5-demo": {
    usage: "ocx oef-phase5-demo --root <artifact-directory> [--json]",
    summary: "Run the deterministic multi-role Phase 5 acceptance scenario.",
  },
  memory: {
    usage: "ocx memory <search|show|provenance|explain-query|correct|deprecate|forget|reindex|health> [options] [--json]",
    summary: "Query and govern the local-first Phase 6 Memory OS.",
    details: ["Search requires at least one explicit --scope; memory content is returned as evidence, never as system instruction."],
  },
  "oef-phase6-demo": {
    usage: "ocx oef-phase6-demo --root <artifact-directory> [--json]",
    summary: "Run the Phase 6 revision, recall, provenance, and injection-dedup acceptance scenario.",
  },
  incident: {
    usage: "ocx incident <ingest|list|show|timeline|triage|root-cause|close|reopen|provenance|explain|health|demo> [options] [--json]",
    summary: "Operate the Phase 7 incident-intelligence foundation registry.",
    details: ["Research, repair, deployment, plugin fleets, and the full Phase 7 command surface remain deferred."],
  },
  "oef-phase7-demo": {
    usage: "ocx oef-phase7-demo --root <artifact-directory> --commit-sha <sha> [--json]",
    summary: "Run the deterministic Phase 7 foundation acceptance scenario without production repair or deployment.",
  },
  "sync-cache": { usage: "ocx sync-cache", summary: "Refresh Codex's model cache from the active catalog." },
  status: { usage: "ocx status", summary: "Check proxy server status." },
  doctor: { usage: "ocx doctor", summary: "Diagnose environment/network issues (paths, WSL /mnt, proxy env, ChatGPT reachability)." },
  debug: {
    usage: "ocx debug [provider on|off|status|reset|logs [-f]|usage on|off|status|reset|logs [-f]]",
    summary: "Show or toggle runtime provider debug logging on the running proxy.",
    details: [
      "Provider: ocx debug provider on | off | status | reset | logs [-f]",
      "Usage JSONL: ocx debug usage on | off | status | reset | logs [-f]",
      "Env default: OCX_DEBUG=1 (legacy OCX_DEBUG_FRAMES still works)",
    ],
  },
  login: { usage: "ocx login <provider>", summary: "OAuth or API-key login for a provider." },
  logout: { usage: "ocx logout <provider>", summary: "Remove a stored provider login." },
  gui: { usage: "ocx gui", summary: "Open the opencodex dashboard." },
  update: {
    usage: "ocx update [--tag latest|preview]",
    summary: "Update opencodex. Preview installs stay on the preview tag unless overridden.",
  },
  provider: {
    usage: "ocx provider <list|add|remove|show|set-default>",
    summary: "Non-interactive provider management.",
    details: [
      "Subcommands: list, add <name>, remove <name>, show <name>, set-default <name>",
      "Registry providers are auto-configured by name. Custom providers need --adapter and --base-url.",
      "Run `ocx provider --help` for full usage and examples.",
    ],
  },
  account: {
    usage: "ocx account <list|current|use|refresh|auto-switch|remove|add-key> ...",
    summary: "List and switch provider accounts and API-key pools (GUI parity).",
    details: [
      "list [provider]     Codex account pool, OAuth accounts and API keys (identifiers shown masked as the API returns them).",
      "current <provider>  Show the active account or key.",
      "use <provider> <id> Switch the active credential; 'main' selects the Codex App login.",
      "refresh <provider>  Force-refresh Codex or provider quota reports.",
      "auto-switch <provider> <on|off|status|threshold N>  Control the Codex pool threshold.",
      "remove <provider> <id> --yes  Remove a stored account or key after an existence check.",
      "add-key <provider> [--label <label>]  Add a key read only from piped stdin.",
      "Codex pool switches apply to new sessions; running threads keep their account.",
    ],
  },
  models: {
    usage: "ocx models [--provider <name>] [--json] | ocx models <scan|list|show|aliases|probe|screen|qualify|compare|scorecard|recommend|requalify|quarantine> ... [--json]",
    summary: "List available models from configured providers or use the OEF Model Lab discovery and qualification surface.",
    details: [
      "Without a lab subcommand, shows configured provider models (legacy behavior).",
      "Model Lab recommendations are evidence only; they never modify production routing.",
      "Private prompts, hidden assertions, and evaluator policy are omitted from CLI output.",
    ],
  },
  benchmark: {
    usage: "ocx benchmark <list|show|validate|run> [suite@version] [--home <path>] [--json]",
    summary: "Inspect redacted OEF Model Lab benchmark metadata and validate versioned suites.",
  },
  "oef-phase4-demo": {
    usage: "ocx oef-phase4-demo --root <path> [--json]",
    summary: "Run the durable three-configuration Phase 4 acceptance demonstration.",
  },
  task: {
    usage: "ocx task <create|show|transition|migrate-workflow|timeline|block|unblock|cancel|reopen> ... [--json]",
    summary: "Manage persistent OEF Phase 1 tasks and workflow stages.",
  },
  contract: {
    usage: "ocx contract <create|propose|approve|reject> --task <id> ... [--json]",
    summary: "Create and approve immutable, versioned task contracts.",
  },
  evidence: {
    usage: "ocx evidence add --task <id> --criterion <key> --type <type> --file <path> [--commit <sha>] | evidence verify ...",
    summary: "Record artifact-backed criterion evidence and verify it.",
  },
  verdict: {
    usage: "ocx verdict issue --task <id> --decision <decision> --rationale <text> [--commit <sha>] [--json]",
    summary: "Issue a policy-governed verdict bound to the active contract and evidence.",
  },
  integrity: {
    usage: "ocx integrity verify <task-id> [--json]",
    summary: "Verify event, artifact, and active-contract integrity.",
  },
  claude: {
    usage: "ocx claude [claude args...]",
    summary: "Launch Claude Code wired to the proxy (env injection + gateway model discovery).",
    details: [
      "Ensures the proxy is running, then execs `claude` with ANTHROPIC_BASE_URL/ANTHROPIC_AUTH_TOKEN,",
      "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1 and model slots from config.claudeCode.",
      "Routed models appear in the native /model picker as claude-ocx-<provider>--<model> (Claude Code >= 2.1.129).",
      "Older versions: pick models via ANTHROPIC_MODEL or /model <id> directly (any string passes through).",
      "User-exported ANTHROPIC_* variables always take precedence.",
    ],
  },
  restart: {
    usage: "ocx restart",
    summary: "Stop the proxy and restart it (background). Equivalent to stop + ensure.",
  },
  health: {
    usage: "ocx health [--json]",
    summary: "Check proxy health. Exits 0 if healthy, 1 otherwise.",
    details: ["Use --json for structured output: {ok, pid, port}."],
  },
};

function packageVersion(): string {
  const raw = readFileSync(join(repoRoot, "package.json"), "utf8");
  const parsed = JSON.parse(raw) as { version?: unknown };
  return typeof parsed.version === "string" ? parsed.version : "unknown";
}

export function printVersion(): void {
  console.log(`opencodex ${packageVersion()}`);
}

export function printUsage(): void {
  console.log(`opencodex (ocx) — Universal provider proxy for Codex

Usage:
  ocx init                    Interactive setup (provider + Codex config injection)
  ocx start [--port <port>]   Start the proxy server (auto-syncs models to Codex)
  ocx stop                    Stop the proxy AND restore native Codex (plain codex works again)
  ocx restore                 Restore native Codex without stopping (alias: eject)
  ocx restore back            Re-point codex at the running proxy (undo restore)
  ocx recover-history --legacy-openai
                               Explicitly recover pre-backup syncResumeHistory rows
  ocx uninstall               Remove service/shim/config and restore native Codex (alias: remove)
  ocx service [sub]           Run as a background service (default: install/update/start)
  ocx codex-shim <sub>        Auto-start proxy when \`codex\` launches (install|status|uninstall|remove)
  ocx ensure                  Ensure the proxy is running and Codex config/cache are current
  ocx sync                    Fetch models from providers and inject into Codex config
  ocx subagents bridge <sub>  Install, inspect, or remove the routed subagent bridge
  ocx sync-cache              Refresh Codex's model cache from the active catalog
  ocx status                  Check proxy server status
  ocx doctor                  Diagnose environment/network issues (WSL, proxy, ChatGPT reachability)
  ocx debug [provider|usage ...]
                              provider/usage on|off|status|reset|logs [-f]
  ocx login <provider>        OAuth login (xai) — opens browser, stores token in ~/.opencodex/auth.json
  ocx logout <provider>       Remove a stored OAuth login
  ocx gui                     Open the opencodex dashboard
  ocx update [--tag <tag>]    Update opencodex (keeps preview installs on @preview)
  ocx restart                  Stop and restart the proxy
  ocx health [--json]          Check proxy health (exit 0=healthy, 1=not)
  ocx provider <sub>          Manage providers (list|add|remove|show|set-default)
  ocx account <sub>           Accounts/keys (list|current|use|refresh|auto-switch|remove|add-key)
  ocx models [--json]         List available models from configured providers
  ocx route <sub>             Compile and operate Phase 5 routing plans
  ocx team <sub>              Compose and inspect Phase 5 role teams
  ocx memory <sub>            Query and govern the Phase 6 Memory OS
  ocx incident <sub>          Operate the Phase 7 incident-intelligence foundation
  ocx task <sub>              Manage persistent OEF tasks and workflow stages
  ocx contract <sub>          Manage immutable task contract revisions
  ocx evidence <sub>          Record and verify criterion evidence
  ocx verdict issue           Issue a policy-governed verdict
  ocx integrity verify <id>   Verify task audit and artifact integrity
  ocx claude [args...]        Launch Claude Code wired to the proxy (model discovery on)
  ocx help [command]          Show help
  ocx --version | -v          Print version

Examples:
  ocx init                    Set up provider and inject into Codex
  ocx start                   Start on default port (10100)
  ocx start --port 8080       Start on custom port
  ocx help service            Show service command help
  ocx sync                    Sync available models to Codex`);
}

export function hasHelpFlag(values: string[]): boolean {
  return values.some(value => value === "--help" || value === "-h" || value === "help");
}

export function printSubcommandUsage(name: string | undefined): void {
  const entry = name ? helpEntries[name] : undefined;
  if (!entry) {
    console.error(`Unknown command: ${name ?? ""}`.trim());
    printUsage();
    process.exit(1);
  }
  console.log(`Usage: ${entry.usage}\n\n${entry.summary}`);
  if (entry.details?.length) console.log(`\n${entry.details.join("\n")}`);
}
