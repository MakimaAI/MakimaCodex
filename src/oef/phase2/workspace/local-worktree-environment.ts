import { arch, platform, release } from "node:os";
import { canonicalSha256 } from "../../phase1/core/contract/task-contract";

export class LocalWorktreeEnvironment {
  private readonly git: string;
  constructor(options: { git_executable?: string } = {}) { this.git = options.git_executable ?? "git"; }

  enforcement(): { filesystem: "OBSERVED"; network: "ADVISORY"; process: "OBSERVED"; sandbox: false } {
    return { filesystem: "OBSERVED", network: "ADVISORY", process: "OBSERVED", sandbox: false };
  }

  async prepare(input: { workspace_path: string; risk: "low" | "medium" | "high" | "critical" }): Promise<{
    provider: "local-worktree";
    workspace_path: string;
    os: string;
    architecture: string;
    tools: Record<string, string>;
    enforcement: ReturnType<LocalWorktreeEnvironment["enforcement"]>;
    fingerprint: string;
  }> {
    if (input.risk === "high" || input.risk === "critical") throw new Error("INSUFFICIENT_SANDBOX_ENFORCEMENT");
    const tools = {
      bun: Bun.version,
      node: process.version,
      git: probeVersion(this.git, ["--version"]),
    };
    const content = {
      provider: "local-worktree" as const,
      workspace_path: input.workspace_path,
      os: `${platform()}-${release()}`,
      architecture: arch(),
      tools,
      enforcement: this.enforcement(),
    };
    return { ...content, fingerprint: canonicalSha256(content) };
  }
}

function probeVersion(executable: string, args: string[]): string {
  try {
    const result = Bun.spawnSync([executable, ...args], { stdin: "ignore", stdout: "pipe", stderr: "pipe" });
    return result.exitCode === 0 ? new TextDecoder().decode(result.stdout).trim().slice(0, 500) : "unknown";
  } catch { return "unknown"; }
}
