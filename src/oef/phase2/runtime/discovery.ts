import type { RuntimeAdapter, RuntimeDetectionResult, RuntimeProbeExecutor, RuntimeProbeResult } from "./protocol";

export class SafeRuntimeProbeExecutor implements RuntimeProbeExecutor {
  private readonly timeoutMs: number;
  constructor(options: { timeoutMs: number }) {
    if (!Number.isInteger(options.timeoutMs) || options.timeoutMs <= 0 || options.timeoutMs > 60_000) {
      throw new Error("Runtime probe timeout must be between 1 and 60000 milliseconds");
    }
    this.timeoutMs = options.timeoutMs;
  }

  async run(executable: string, arguments_: readonly string[]): Promise<{ exit_code: number | null; stdout: string; stderr: string; timed_out: boolean }> {
    const child = Bun.spawn([executable, ...arguments_], {
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
      env: probeEnvironment(),
      windowsHide: true,
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<"timeout">(resolve => {
      timer = setTimeout(() => resolve("timeout"), this.timeoutMs);
    });
    const outcome = await Promise.race([child.exited.then(() => "exit" as const), timeout]);
    if (timer) clearTimeout(timer);
    if (outcome === "timeout") child.kill();
    const [stdout, stderr] = await Promise.all([
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return {
      exit_code: outcome === "timeout" ? null : child.exitCode,
      stdout: stdout.slice(0, 64_000),
      stderr: stderr.slice(0, 64_000),
      timed_out: outcome === "timeout",
    };
  }
}

function probeEnvironment(): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of ["PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) {
    const value = process.env[name];
    if (value) result[name] = value;
  }
  return result;
}

export interface RuntimeDiscoverySnapshot {
  runtime_id: string;
  adapter_id: string;
  detection: RuntimeDetectionResult;
  probe: RuntimeProbeResult;
}

export class LocalRuntimeDiscovery {
  private readonly probeExecutor: RuntimeProbeExecutor;
  constructor(options: { probeExecutor: RuntimeProbeExecutor }) { this.probeExecutor = options.probeExecutor; }

  async scan(adapters: readonly RuntimeAdapter[], options: { checkedAt?: string } = {}): Promise<RuntimeDiscoverySnapshot[]> {
    const checkedAt = options.checkedAt ?? new Date().toISOString();
    const snapshots: RuntimeDiscoverySnapshot[] = [];
    for (const adapter of adapters) {
      const detection = await adapter.detect({ environment_path: process.env.PATH ?? "", probe_executor: this.probeExecutor });
      const probe = await adapter.probe({ detection, checked_at: checkedAt });
      snapshots.push({
        runtime_id: adapter.manifest.runtime_id,
        adapter_id: adapter.manifest.adapter.id,
        detection,
        probe,
      });
    }
    return snapshots;
  }
}
