import { describe, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { LiveProxy } from "../src/server/proxy-liveness";
import { logoutOAuthProvider } from "../src/oauth/logout-cli";
import { saveConfig } from "../src/config";
import { getCredential, snapshotLoginFenceGeneration } from "../src/oauth/store";

type FenceAfterLogout = "intact" | "missing" | "unrelated-recreation" | "same-provider-recreation";

async function runNoProxyCrossProcessRace(fenceAfterLogout: FenceAfterLogout = "intact"): Promise<{
  exitCode: number;
  stderr: string;
  credentialAccess: string | null;
}> {
  const dir = mkdtempSync(join(tmpdir(), "ocx-cli-logout-fence-"));
  const readyPath = join(dir, "login-ready");
  const finishPath = join(dir, "finish-login");
  const fencePath = join(dir, "auth.login-fences.json");
  const previousHome = process.env.OPENCODEX_HOME;
  let child: ReturnType<typeof Bun.spawn> | undefined;
  process.env.OPENCODEX_HOME = dir;
  try {
    saveConfig({
      port: 10100,
      hostname: "127.0.0.1",
      defaultProvider: "xai",
      providers: {
        xai: { adapter: "openai-chat", baseUrl: "https://api.x.ai/v1", authMode: "oauth" },
      },
    });
    const childCode = `
      import { existsSync, writeFileSync } from "node:fs";
      import { OAUTH_PROVIDERS, runLogin } from "./src/oauth/index.ts";
      OAUTH_PROVIDERS.xai.login = async () => {
        writeFileSync(process.env.OCX_TEST_LOGIN_READY, "ready");
        while (!existsSync(process.env.OCX_TEST_FINISH_LOGIN)) await Bun.sleep(5);
        return {
          access: "late-cli-login",
          refresh: "late-cli-refresh",
          expires: Date.now() + 60_000,
          accountId: "cli-race-account",
        };
      };
      await runLogin("xai", {});
    `;
    child = Bun.spawn([process.execPath, "-e", childCode], {
      cwd: join(import.meta.dir, ".."),
      env: {
        ...process.env,
        OPENCODEX_HOME: dir,
        OCX_TEST_LOGIN_READY: readyPath,
        OCX_TEST_FINISH_LOGIN: finishPath,
      },
      stdout: "pipe",
      stderr: "pipe",
    });

    const readyDeadline = Date.now() + 5_000;
    while (!existsSync(readyPath) && Date.now() < readyDeadline) await Bun.sleep(10);
    expect(existsSync(readyPath)).toBe(true);

    expect(await logoutOAuthProvider("xai", {
      findLiveProxyImpl: async () => null,
    })).toBe("store");
    if (fenceAfterLogout !== "intact") unlinkSync(fencePath);
    if (fenceAfterLogout === "unrelated-recreation") {
      expect(await logoutOAuthProvider("anthropic", {
        findLiveProxyImpl: async () => null,
      })).toBe("store");
    } else if (fenceAfterLogout === "same-provider-recreation") {
      await snapshotLoginFenceGeneration("xai");
    }
    writeFileSync(finishPath, "finish");

    const exitCode = await child.exited;
    const stderr = await new Response(child.stderr).text();
    return {
      exitCode,
      stderr,
      credentialAccess: getCredential("xai")?.access ?? null,
    };
  } finally {
    child?.kill();
    if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
    else process.env.OPENCODEX_HOME = previousHome;
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("CLI OAuth logout", () => {
  test("routes logout through a live proxy so pending in-process login is fenced", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    let localRemovals = 0;
    const live: LiveProxy = { pid: 42, port: 12345, hostname: "::1" };

    const route = await logoutOAuthProvider(" XAI ", {
      findLiveProxyImpl: async () => live,
      fetchImpl: async (input, init) => {
        calls.push({ url: String(input), init });
        return Response.json({ success: true });
      },
      removeCredentialImpl: async () => {
        localRemovals += 1;
      },
      headersImpl: () => new Headers({ "X-OpenCodex-API-Key": "test-token" }),
    });

    expect(route).toBe("proxy");
    expect(localRemovals).toBe(0);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.url).toBe("http://[::1]:12345/api/oauth/logout?provider=xai");
    expect(calls[0]?.init?.method).toBe("POST");
    expect(new Headers(calls[0]?.init?.headers).get("X-OpenCodex-API-Key")).toBe("test-token");
  });

  test("removes the credential directly only when no proxy is running", async () => {
    const removed: string[] = [];

    const route = await logoutOAuthProvider("anthropic", {
      findLiveProxyImpl: async () => null,
      fetchImpl: async () => {
        throw new Error("must not fetch");
      },
      removeCredentialImpl: async provider => {
        removed.push(provider);
      },
    });

    expect(route).toBe("store");
    expect(removed).toEqual(["anthropic"]);
  });

  test("fails closed when the live proxy rejects logout", async () => {
    let localRemovals = 0;

    await expect(logoutOAuthProvider("xai", {
      findLiveProxyImpl: async () => ({ pid: 42, port: 12345 }),
      fetchImpl: async () => Response.json({ error: "logout rejected" }, { status: 503 }),
      removeCredentialImpl: async () => {
        localRemovals += 1;
      },
    })).rejects.toThrow("logout rejected");

    expect(localRemovals).toBe(0);
  });

  test("a no-proxy CLI logout fences a login that completes later in another process", async () => {
    const result = await runNoProxyCrossProcessRace();

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/login.*(fence|logout)|superseded/i);
    expect(result.credentialAccess).toBeNull();
  });

  test("a deleted fence file cannot turn a completed logout generation back into zero", async () => {
    const result = await runNoProxyCrossProcessRace("missing");

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/login.*fence|superseded/i);
    expect(result.credentialAccess).toBeNull();
  });

  test("an unrelated provider cannot recreate a fence that admits a pre-logout login", async () => {
    const result = await runNoProxyCrossProcessRace("unrelated-recreation");

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/login.*fence|superseded/i);
    expect(result.credentialAccess).toBeNull();
  });

  test("a new same-provider snapshot cannot admit a pre-logout login after fence recreation", async () => {
    const result = await runNoProxyCrossProcessRace("same-provider-recreation");

    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toMatch(/login.*fence|superseded/i);
    expect(result.credentialAccess).toBeNull();
  });
});
