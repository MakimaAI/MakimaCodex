import type { SubagentBridgeStatus } from "./lifecycle";

const DEFAULT_TIMEOUT_MS = 12_000;
const DEFAULT_CACHE_TTL_MS = 1_000;

const unavailableStatus = (): SubagentBridgeStatus => ({
  installed: false,
  registered: false,
  enabled: false,
  tokenPresent: false,
  tokenSecure: null,
  marketplaceReady: false,
  mcpReady: false,
  ready: false,
  warnings: ["Subagent bridge status inspection is unavailable."],
});

interface IsolatedStatusOptions {
  workerUrl?: URL;
  timeoutMs?: number;
  cacheTtlMs?: number;
  now?: () => number;
}

let cached: { workerKey: string; expiresAt: number; status: SubagentBridgeStatus } | null = null;
let pending: { workerKey: string; promise: Promise<SubagentBridgeStatus> } | null = null;

function isBridgeStatus(value: unknown): value is SubagentBridgeStatus {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const status = value as Record<string, unknown>;
  return typeof status.installed === "boolean"
    && typeof status.registered === "boolean"
    && typeof status.enabled === "boolean"
    && typeof status.tokenPresent === "boolean"
    && (typeof status.tokenSecure === "boolean" || status.tokenSecure === null)
    && typeof status.marketplaceReady === "boolean"
    && typeof status.mcpReady === "boolean"
    && typeof status.ready === "boolean"
    && Array.isArray(status.warnings)
    && status.warnings.every(warning => typeof warning === "string");
}

function inspectInWorker(workerUrl: URL, timeoutMs: number): Promise<SubagentBridgeStatus> {
  return new Promise(resolve => {
    const worker = new Worker(workerUrl.href, { type: "module" });
    let settled = false;
    const finish = (status: SubagentBridgeStatus) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      worker.terminate();
      resolve(status);
    };
    const timeout = setTimeout(() => finish(unavailableStatus()), timeoutMs);
    worker.onmessage = event => {
      const payload = event.data as { ok?: unknown; status?: unknown };
      const candidate = payload?.ok === true ? payload.status : event.data;
      finish(isBridgeStatus(candidate) ? candidate : unavailableStatus());
    };
    worker.onerror = () => finish(unavailableStatus());
  });
}

/** Keep blocking Codex/PowerShell status probes off the proxy request thread. */
export async function inspectSubagentBridgeStatusIsolated(
  options: IsolatedStatusOptions = {},
): Promise<SubagentBridgeStatus> {
  const workerUrl = options.workerUrl ?? new URL("./status-worker.ts", import.meta.url);
  const workerKey = workerUrl.href;
  const now = options.now ?? Date.now;
  const cacheTtlMs = Math.max(0, options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS);
  const currentTime = now();
  if (cacheTtlMs > 0 && cached?.workerKey === workerKey && cached.expiresAt > currentTime) {
    return cached.status;
  }
  if (pending?.workerKey === workerKey) return pending.promise;

  const timeoutMs = Math.max(100, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const promise = inspectInWorker(workerUrl, timeoutMs).then(status => {
    if (cacheTtlMs > 0) cached = { workerKey, expiresAt: now() + cacheTtlMs, status };
    return status;
  }).finally(() => {
    if (pending?.promise === promise) pending = null;
  });
  pending = { workerKey, promise };
  return promise;
}

export function resetSubagentBridgeStatusCacheForTests(): void {
  cached = null;
  pending = null;
}
