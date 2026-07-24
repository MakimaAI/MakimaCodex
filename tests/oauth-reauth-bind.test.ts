import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { OAUTH_PROVIDERS, runLogin } from "../src/oauth";
import { getAccountCredential, getAccountSet, removeAccount, removeCredential, saveCredential } from "../src/oauth/store";
import type { OAuthController } from "../src/oauth/types";
import { handleManagementAPI } from "../src/server/management-api";
import type { OcxConfig } from "../src/types";

const TEST_DIR = join(import.meta.dir, ".tmp-oauth-reauth-bind");
const previousHome = process.env.OPENCODEX_HOME;

function config(): OcxConfig {
  return {
    port: 10100,
    defaultProvider: "openai",
    openaiProviderTierVersion: 2,
    providers: {
      openai: {
        adapter: "openai-responses",
        baseUrl: "https://chatgpt.com/backend-api/codex",
        authMode: "forward",
        codexAccountMode: "pool",
      },
      xai: {
        adapter: "openai-completions",
        baseUrl: "https://api.x.ai/v1",
        authMode: "oauth",
      },
    },
  };
}

beforeEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
  mkdirSync(TEST_DIR, { recursive: true });
  process.env.OPENCODEX_HOME = TEST_DIR;
});

afterEach(() => {
  if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
  else process.env.OPENCODEX_HOME = previousHome;
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe("OAuth account-scoped reauth", () => {
  test("POST /api/oauth/login rejects unknown accountId", async () => {
    const cfg = config();
    const req = new Request("http://localhost/api/oauth/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ provider: "xai", accountId: "missing-slot", reauth: true }),
    });
    const resp = await handleManagementAPI(req, new URL(req.url), cfg);
    expect(resp?.status).toBe(404);
    expect(await resp?.json()).toEqual({ error: "Unknown account for reauth" });
  });

  test("runLogin reauthAccountId refuses identity mismatch", async () => {
    await saveCredential("xai", {
      access: "a1",
      refresh: "r1",
      expires: Date.now() + 60_000,
      email: "slot-a@example.test",
      accountId: "acct-a",
    });
    const slotId = getAccountSet("xai")!.activeAccountId;
    const original = OAUTH_PROVIDERS.xai.login;
    OAUTH_PROVIDERS.xai.login = async () => ({
      access: "a2",
      refresh: "r2",
      expires: Date.now() + 60_000,
      email: "other@example.test",
      accountId: "acct-other",
    });
    try {
      await expect(runLogin("xai", {} as OAuthController, { reauthAccountId: slotId })).rejects.toThrow(
        /does not match the selected account/,
      );
    } finally {
      OAUTH_PROVIDERS.xai.login = original;
    }
    expect(getAccountCredential("xai", slotId)?.access).toBe("a1");
  });

  test("runLogin reauthAccountId refreshes the same slot on identity match", async () => {
    await saveCredential("xai", {
      access: "a1",
      refresh: "r1",
      expires: Date.now() + 60_000,
      email: "slot-a@example.test",
      accountId: "acct-a",
    });
    const slotId = getAccountSet("xai")!.activeAccountId;
    const original = OAUTH_PROVIDERS.xai.login;
    OAUTH_PROVIDERS.xai.login = async () => ({
      access: "a2",
      refresh: "r2",
      expires: Date.now() + 60_000,
      email: "slot-a@example.test",
      accountId: "acct-a",
    });
    try {
      await runLogin("xai", {} as OAuthController, { reauthAccountId: slotId });
    } finally {
      OAUTH_PROVIDERS.xai.login = original;
    }
    expect(getAccountCredential("xai", slotId)?.access).toBe("a2");
    expect(getAccountSet("xai")?.accounts).toHaveLength(1);
  });

  test("logout supersedes a pending reauth even when its non-active account remains", async () => {
    await saveCredential("xai", {
      access: "a1",
      refresh: "r1",
      expires: Date.now() + 60_000,
      email: "slot-a@example.test",
      accountId: "acct-a",
    });
    await saveCredential("xai", {
      access: "b1",
      refresh: "rb1",
      expires: Date.now() + 60_000,
      email: "slot-b@example.test",
      accountId: "acct-b",
    });
    const slotA = getAccountSet("xai")!.accounts.find(account => account.credential.accountId === "acct-a")!.id;
    let finishLogin!: () => void;
    let loginStarted!: () => void;
    const started = new Promise<void>(resolve => { loginStarted = resolve; });
    const finish = new Promise<void>(resolve => { finishLogin = resolve; });
    const original = OAUTH_PROVIDERS.xai.login;
    OAUTH_PROVIDERS.xai.login = async () => {
      loginStarted();
      await finish;
      return {
        access: "a2",
        refresh: "r2",
        expires: Date.now() + 60_000,
        email: "slot-a@example.test",
        accountId: "acct-a",
      };
    };
    try {
      const pending = runLogin("xai", {} as OAuthController, { reauthAccountId: slotA });
      await started;
      await removeCredential("xai"); // removes active B but must invalidate the pending reauth for A
      finishLogin();

      await expect(pending).rejects.toThrow(/login.*(fence|logout)|superseded/i);
    } finally {
      finishLogin?.();
      OAUTH_PROVIDERS.xai.login = original;
    }
    expect(getAccountCredential("xai", slotA)?.access).toBe("a1");
  });

  test("deleting the last account supersedes a pending login generation", async () => {
    await saveCredential("xai", {
      access: "existing",
      refresh: "existing-refresh",
      expires: Date.now() + 60_000,
      accountId: "existing-account",
    });
    const accountId = getAccountSet("xai")!.activeAccountId;
    let finishLogin!: () => void;
    let loginStarted!: () => void;
    const started = new Promise<void>(resolve => { loginStarted = resolve; });
    const finish = new Promise<void>(resolve => { finishLogin = resolve; });
    const original = OAUTH_PROVIDERS.xai.login;
    OAUTH_PROVIDERS.xai.login = async () => {
      loginStarted();
      await finish;
      return {
        access: "late",
        refresh: "late-refresh",
        expires: Date.now() + 60_000,
        accountId: "late-account",
      };
    };
    try {
      const pending = runLogin("xai", {} as OAuthController);
      await started;
      expect(await removeAccount("xai", accountId)).toBe(true);
      finishLogin();

      await expect(pending).rejects.toThrow(/login.*(fence|logout)|superseded/i);
    } finally {
      finishLogin?.();
      OAUTH_PROVIDERS.xai.login = original;
    }
    expect(getAccountSet("xai")).toBeNull();
  });

  test("deleting an account fences a pending login in another process", async () => {
    await saveCredential("xai", {
      access: "existing",
      refresh: "existing-refresh",
      expires: Date.now() + 60_000,
      accountId: "existing-account",
    });
    const accountId = getAccountSet("xai")!.activeAccountId;
    const readyPath = join(TEST_DIR, "cross-process-login-ready");
    const finishPath = join(TEST_DIR, "cross-process-login-finish");
    const childCode = `
      import { existsSync, writeFileSync } from "node:fs";
      import { OAUTH_PROVIDERS, runLogin } from "./src/oauth/index.ts";
      OAUTH_PROVIDERS.xai.login = async () => {
        writeFileSync(process.env.OCX_TEST_LOGIN_READY, "ready");
        while (!existsSync(process.env.OCX_TEST_FINISH_LOGIN)) await Bun.sleep(5);
        return {
          access: "late-account-login",
          refresh: "late-account-refresh",
          expires: Date.now() + 60_000,
          accountId: "late-account",
        };
      };
      await runLogin("xai", {});
    `;
    let child: ReturnType<typeof Bun.spawn> | undefined;
    try {
      child = Bun.spawn([process.execPath, "-e", childCode], {
        cwd: join(import.meta.dir, ".."),
        env: {
          ...process.env,
          OPENCODEX_HOME: TEST_DIR,
          OCX_TEST_LOGIN_READY: readyPath,
          OCX_TEST_FINISH_LOGIN: finishPath,
        },
        stdout: "pipe",
        stderr: "pipe",
      });

      const readyDeadline = Date.now() + 5_000;
      while (!existsSync(readyPath) && Date.now() < readyDeadline) await Bun.sleep(10);
      expect(existsSync(readyPath)).toBe(true);

      expect(await removeAccount("xai", accountId)).toBe(true);
      writeFileSync(finishPath, "finish");

      expect(await child.exited).not.toBe(0);
      expect(await new Response(child.stderr).text()).toMatch(/login.*(fence|logout)|superseded/i);
      expect(getAccountSet("xai")).toBeNull();
    } finally {
      child?.kill();
    }
  });

  test("management login passes reauthAccountId into startLoginFlow", async () => {
    const source = await Bun.file("src/server/management-api.ts").text();
    expect(source).toContain("reauthAccountId: accountId");
    expect(source).toContain("Unknown account for reauth");
  });
});
