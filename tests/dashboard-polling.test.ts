import { expect, test } from "bun:test";
import { startDashboardPolling } from "../gui/src/dashboard-polling";

function deferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function fakePollingHost(initiallyHidden = false) {
  let hidden = initiallyHidden;
  let visibilityListener: (() => void) | null = null;
  let listenersAdded = 0;
  let listenersRemoved = 0;
  let nextTimerId = 1;
  const timers = new Map<number, { callback: () => void; delayMs: number }>();

  return {
    host: {
      isHidden: () => hidden,
      setTimeout(callback: () => void, delayMs: number) {
        const id = nextTimerId++;
        timers.set(id, { callback, delayMs });
        return id;
      },
      clearTimeout(id: number) { timers.delete(id); },
      addVisibilityListener(listener: () => void) {
        listenersAdded += 1;
        visibilityListener = listener;
      },
      removeVisibilityListener(listener: () => void) {
        if (visibilityListener === listener) {
          listenersRemoved += 1;
          visibilityListener = null;
        }
      },
    },
    timers,
    setHidden(next: boolean) {
      hidden = next;
      visibilityListener?.();
    },
    listenerCounts: () => ({ added: listenersAdded, removed: listenersRemoved }),
  };
}

test("Dashboard exposes a testable polling lifecycle seam", () => {
  expect(typeof startDashboardPolling).toBe("function");
});

test("Dashboard polling is single-flight and keeps the five-second cadence", async () => {
  const firstRun = deferred<void>();
  const signals: AbortSignal[] = [];
  const fake = fakePollingHost();

  const stop = startDashboardPolling({
    intervalMs: 5_000,
    host: fake.host,
    run: (signal: AbortSignal) => {
      signals.push(signal);
      return signals.length === 1 ? firstRun.promise : new Promise<void>(() => {});
    },
  });

  expect(signals).toHaveLength(1);
  expect(fake.timers.size).toBe(0);

  firstRun.resolve();
  await firstRun.promise;
  await Promise.resolve();

  expect([...fake.timers.values()].map(timer => timer.delayMs)).toEqual([5_000]);
  [...fake.timers.values()][0]!.callback();
  expect(signals).toHaveLength(2);

  stop();
});

test("Dashboard polling aborts on hide and refreshes immediately when visible", () => {
  const signals: AbortSignal[] = [];
  const fake = fakePollingHost();

  const stop = startDashboardPolling({
    intervalMs: 5_000,
    host: fake.host,
    run: (signal: AbortSignal) => {
      signals.push(signal);
      return new Promise<void>(() => {});
    },
  });

  expect(fake.listenerCounts()).toEqual({ added: 1, removed: 0 });
  expect(signals).toHaveLength(1);
  fake.setHidden(true);
  expect(signals[0]!.aborted).toBe(true);

  fake.setHidden(false);
  expect(signals).toHaveLength(2);
  expect(signals[1]!.aborted).toBe(false);

  stop();
  expect(signals[1]!.aborted).toBe(true);
  expect(fake.listenerCounts()).toEqual({ added: 1, removed: 1 });
});

test("Dashboard polling stays paused when mounted hidden", () => {
  const fake = fakePollingHost(true);
  let runs = 0;

  const stop = startDashboardPolling({
    intervalMs: 5_000,
    host: fake.host,
    run: async () => { runs += 1; },
  });

  expect(runs).toBe(0);
  expect(fake.timers.size).toBe(0);
  fake.setHidden(false);
  expect(runs).toBe(1);

  stop();
});

test("Dashboard main refresh is abortable and rejects stale commits", async () => {
  const source = await Bun.file("gui/src/pages/Dashboard.tsx").text();

  expect(source).toContain('import { startDashboardPolling, type DashboardPollingHost } from "../dashboard-polling";');
  expect(source).toContain("const dashboardRefreshEpochRef = useRef(0);");
  expect(source).toContain("const refreshEpoch = dashboardRefreshEpochRef.current;");
  expect(source).toContain("const canCommitRefresh = () =>");
  expect(source).toContain("intervalMs: 5_000");
  expect(source).toContain("run: fetchData");
  expect(source).toContain("fetch(`${apiBase}/healthz`, { signal })");
  expect(source).toContain("if (!canCommitRefresh()) return;");
  expect(source).not.toContain("setInterval(fetchData, 5000)");
});

test("Dashboard mutations fence refreshes for their full lifetime", async () => {
  const source = await Bun.file("gui/src/pages/Dashboard.tsx").text();

  expect(source).toContain("const dashboardMutationsInFlightRef = useRef(0);");
  expect(source).toContain("const beginDashboardMutation = () => {");
  expect(source).toContain("dashboardRefreshEpochRef.current += 1;");
  expect(source).toContain("dashboardMutationsInFlightRef.current === 0");
  expect(source.match(/const finishDashboardMutation = beginDashboardMutation\(\);/g)).toHaveLength(8);
  expect(source.match(/finishDashboardMutation\(\);/g)).toHaveLength(8);
});

test("Dashboard diagnostics and update polling share the cancellable lifecycle", async () => {
  const source = await Bun.file("gui/src/pages/Dashboard.tsx").text();

  expect(source.match(/return startDashboardPolling\(\{/g)).toHaveLength(3);
  expect(source).toContain("intervalMs: 30_000");
  expect(source).toContain("intervalMs: 1_500");
  expect(source).toContain("fetch(`${apiBase}/api/diagnostics/project-config`, { signal })");
  expect(source).toContain("cache: \"no-store\", signal");
  expect(source).not.toContain("setInterval(");
});
