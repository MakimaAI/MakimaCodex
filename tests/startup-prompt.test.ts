import { describe, expect, test } from "bun:test";

const root = new URL("../", import.meta.url);

async function readText(path: string): Promise<string> {
  return await Bun.file(new URL(path, root)).text();
}

describe("startup star prompt", () => {
  test("does not ship a package-manager postinstall lifecycle prompt", async () => {
    const pkg = JSON.parse(await readText("package.json")) as {
      scripts?: Record<string, string>;
      files?: string[];
    };

    expect(pkg.scripts?.postinstall).toBeUndefined();
    expect(pkg.files ?? []).not.toContain("scripts/postinstall.mjs");
  });

  test("ocx start waits for the interactive prompt before sync/injection", async () => {
    const cli = await readText("src/cli/index.ts");
    const promptIndex = cli.indexOf("await maybeShowStarPrompt()");
    const syncIndex = cli.indexOf("await syncModelsToCodex(port)");

    expect(cli).not.toContain("void maybeShowStarPrompt()");
    expect(promptIndex).toBeGreaterThan(-1);
    expect(syncIndex).toBeGreaterThan(-1);
    expect(promptIndex).toBeLessThan(syncIndex);
  });

  test("ocx init offers the Codex autostart shim by default", async () => {
    const init = await readText("src/cli/init.ts");

    expect(init).toContain("Install Codex autostart shim? [Y/n]");
    expect(init).toContain("installCodexShim");
  });

  test("ocx start probes for an orphaned live proxy even when the pid file is missing", async () => {
    const cli = await readText("src/cli/index.ts");
    const startIndex = cli.indexOf("async function handleStart");
    const pidIndex = cli.indexOf("const existingPid = readPid()", startIndex);
    const liveProbeIndex = cli.indexOf("const live = await findLiveProxy()", pidIndex);
    const pidGuardIndex = cli.indexOf("if (existingPid)", pidIndex);

    expect(pidIndex).toBeGreaterThan(startIndex);
    expect(liveProbeIndex).toBeGreaterThan(pidIndex);
    expect(pidGuardIndex).toBeGreaterThan(pidIndex);
    expect(liveProbeIndex).toBeLessThan(pidGuardIndex);
  });
});
