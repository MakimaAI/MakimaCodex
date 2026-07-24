export interface DashboardPollingHost {
  isHidden: () => boolean;
  setTimeout: (callback: () => void, delayMs: number) => number;
  clearTimeout: (timerId: number) => void;
  addVisibilityListener: (listener: () => void) => void;
  removeVisibilityListener: (listener: () => void) => void;
}

interface DashboardPollingOptions {
  intervalMs: number;
  host: DashboardPollingHost;
  run: (signal: AbortSignal) => Promise<void>;
}

export function startDashboardPolling({ intervalMs, host, run }: DashboardPollingOptions): () => void {
  let stopped = false;
  let timerId: number | null = null;
  let controller: AbortController | null = null;

  const clearScheduledPoll = () => {
    if (timerId === null) return;
    host.clearTimeout(timerId);
    timerId = null;
  };

  const abortCurrentPoll = () => {
    const current = controller;
    controller = null;
    current?.abort();
  };

  const poll = () => {
    if (stopped || host.isHidden() || controller) return;
    const current = new AbortController();
    controller = current;
    void run(current.signal).catch(() => {}).finally(() => {
      if (controller !== current) return;
      controller = null;
      if (!stopped && !host.isHidden()) {
        timerId = host.setTimeout(() => {
          timerId = null;
          poll();
        }, intervalMs);
      }
    });
  };

  const onVisibilityChange = () => {
    clearScheduledPoll();
    if (host.isHidden()) {
      abortCurrentPoll();
      return;
    }
    poll();
  };

  host.addVisibilityListener(onVisibilityChange);
  poll();
  return () => {
    stopped = true;
    host.removeVisibilityListener(onVisibilityChange);
    clearScheduledPoll();
    abortCurrentPoll();
  };
}
