import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { existsSync, mkdirSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  cancelLoginFlow,
  clearLoginState,
  getLoginStatus,
  OAUTH_PROVIDERS,
  startLoginFlow,
} from "../src/oauth";
import { saveConfig } from "../src/config";
import { getAuthStoreLockPath, getCredential, removeCredential, saveCredential } from "../src/oauth/store";
import { handleManagementAPI } from "../src/server/management-api";
import type { OAuthCredentials } from "../src/oauth/types";
import type { OcxConfig } from "../src/types";

const TEST_DIR = join(import.meta.dir, ".tmp-oauth-login-cancel-race");
const previousHome = process.env.OPENCODEX_HOME;
const originalXaiLogin = OAUTH_PROVIDERS.xai!.login;

function deferred<T>(): { promise: Promise<T>; resolve(value: T): void } {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(res => { resolve = res; });
  return { promise, resolve };
}

function credential(access: string): OAuthCredentials {
  return {
    access,
    refresh: `${access}-refresh`,
    expires: Date.now() + 60_000,
    accountId: "race-account",
  };
}

async function waitForBackgroundLogin(): Promise<void> {
  const deadline = Date.now() + 500;
  while (Date.now() < deadline) {
    const status = getLoginStatus("xai");
    if (getCredential("xai") || (status.done && status.error !== "Login cancelled")) return;
    await Bun.sleep(10);
  }
}

function testConfig(): OcxConfig {
  return {
    port: 10100,
    hostname: "127.0.0.1",
    defaultProvider: "xai",
    providers: {
      xai: { adapter: "openai-chat", baseUrl: "https://api.x.ai/v1", authMode: "oauth" },
    },
  };
}

describe("OAuth login cancellation persistence fence", () => {
  beforeEach(async () => {
    rmSync(TEST_DIR, { recursive: true, force: true });
    mkdirSync(TEST_DIR, { recursive: true });
    process.env.OPENCODEX_HOME = TEST_DIR;
    clearLoginState("xai");
    await removeCredential("xai");
    saveConfig(testConfig());
  });

  afterEach(async () => {
    OAUTH_PROVIDERS.xai!.login = originalXaiLogin;
    cancelLoginFlow("xai");
    clearLoginState("xai");
    if (existsSync(getAuthStoreLockPath())) unlinkSync(getAuthStoreLockPath());
    await removeCredential("xai");
    if (previousHome === undefined) delete process.env.OPENCODEX_HOME;
    else process.env.OPENCODEX_HOME = previousHome;
    if (existsSync(TEST_DIR)) rmSync(TEST_DIR, { recursive: true, force: true });
  });

  test("a provider that completes after cancel cannot persist credentials", async () => {
    const completed = deferred<OAuthCredentials>();
    OAUTH_PROVIDERS.xai!.login = async ctrl => {
      ctrl.onAuth?.({ url: "https://auth.example/authorize" });
      return completed.promise;
    };

    await startLoginFlow("xai", { forceLogin: true });
    expect(cancelLoginFlow("xai")).toBe(true);

    completed.resolve(credential("late-after-cancel"));
    await waitForBackgroundLogin();

    expect(getCredential("xai")).toBeNull();
    expect(getLoginStatus("xai")).toMatchObject({ done: true, error: "Login cancelled" });
  });

  test("logout invalidates a pending login before deleting credentials", async () => {
    await saveCredential("xai", credential("existing"));
    const completed = deferred<OAuthCredentials>();
    OAUTH_PROVIDERS.xai!.login = async ctrl => {
      ctrl.onAuth?.({ url: "https://auth.example/authorize" });
      return completed.promise;
    };

    await startLoginFlow("xai", { forceLogin: true });
    const request = new Request("http://127.0.0.1/api/oauth/logout?provider=xai", { method: "POST" });
    const response = await handleManagementAPI(request, new URL(request.url), testConfig());
    expect(response?.status).toBe(200);
    expect(getCredential("xai")).toBeNull();

    completed.resolve(credential("late-after-logout"));
    await waitForBackgroundLogin();

    expect(getCredential("xai")).toBeNull();
  });

  test("cancel rechecks the attempt while credential persistence waits for the store lock", async () => {
    const completed = deferred<OAuthCredentials>();
    OAUTH_PROVIDERS.xai!.login = async ctrl => {
      ctrl.onAuth?.({ url: "https://auth.example/authorize" });
      return completed.promise;
    };

    await startLoginFlow("xai", { forceLogin: true });
    writeFileSync(getAuthStoreLockPath(), JSON.stringify({
      version: 1,
      ownerId: "test-lock",
      pid: process.pid,
      createdAt: Date.now(),
    }));
    completed.resolve(credential("late-while-store-locked"));
    await Bun.sleep(50);

    expect(cancelLoginFlow("xai")).toBe(true);
    unlinkSync(getAuthStoreLockPath());
    await waitForBackgroundLogin();

    expect(getCredential("xai")).toBeNull();
  });

  test("credential persistence rechecks cancellation after mutation but before publishing", async () => {
    let checks = 0;

    await saveCredential("xai", credential("cancelled-before-publish"), () => {
      checks += 1;
      return checks === 1;
    });

    expect(checks).toBe(2);
    expect(getCredential("xai")).toBeNull();
  });
});
