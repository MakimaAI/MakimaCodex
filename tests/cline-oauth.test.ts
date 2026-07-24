import { afterEach, describe, expect, test } from "bun:test";
import {
  CLINE_API_BASE_URL,
  CLINE_WORKOS_CLIENT_ID,
  formatClineWorkOsAccessToken,
  loginCline,
  refreshClineToken,
} from "../src/oauth/cline";

const originalFetch = globalThis.fetch;
const originalSetTimeout = globalThis.setTimeout;

afterEach(() => {
  globalThis.fetch = originalFetch;
  globalThis.setTimeout = originalSetTimeout;
});

function captureSleeps(delays: number[]): void {
  globalThis.setTimeout = ((callback: TimerHandler, delay?: number, ...args: unknown[]) => {
    delays.push(Number(delay ?? 0));
    return originalSetTimeout(callback, 0, ...args);
  }) as typeof setTimeout;
}

describe("Cline OAuth", () => {
  test("formats WorkOS access tokens for Cline transport without double-prefixing", () => {
    expect(formatClineWorkOsAccessToken("cline-access")).toBe("workos:cline-access");
    expect(formatClineWorkOsAccessToken(" workos:cline-access ")).toBe("workos:cline-access");
    expect(formatClineWorkOsAccessToken("WORKOS:cline-access")).toBe("workos:cline-access");
  });

  test("logs in with the official WorkOS device flow and registers Cline credentials", async () => {
    captureSleeps([]);
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, init });
      if (url.endsWith("/user_management/authorize/device")) {
        return Response.json({
          device_code: "device-123",
          user_code: "ABCD-EFGH",
          verification_uri: "https://authenticate.workos.com/device",
          verification_uri_complete: "https://authenticate.workos.com/device?user_code=ABCD-EFGH",
          expires_in: 300,
          interval: 1,
        });
      }
      if (url.endsWith("/user_management/authenticate")) {
        return Response.json({
          access_token: "workos-access",
          refresh_token: "workos-refresh",
          token_type: "Bearer",
        });
      }
      if (url === `${CLINE_API_BASE_URL}/api/v1/auth/register`) {
        return Response.json({
          success: true,
          data: {
            accessToken: "cline-access",
            refreshToken: "cline-refresh",
            tokenType: "Bearer",
            expiresAt: "2030-01-02T03:04:05.000Z",
            userInfo: {
              clineUserId: "cline-user-42",
              email: "member@example.com",
              name: "Member",
              subject: "workos-user-42",
              accounts: ["personal"],
            },
          },
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    }) as typeof fetch;

    const auth: Array<{ url: string; instructions?: string }> = [];
    const credential = await loginCline({ onAuth: info => auth.push(info) });

    expect(auth).toEqual([{
      url: "https://authenticate.workos.com/device?user_code=ABCD-EFGH",
      instructions: "Enter this code in your browser: ABCD-EFGH",
    }]);
    expect(credential).toEqual({
      access: "cline-access",
      refresh: "cline-refresh",
      expires: Date.parse("2030-01-02T03:04:05.000Z"),
      accountId: "cline-user-42",
      email: "member@example.com",
    });
    expect(new URLSearchParams(String(requests[0]?.init?.body)).get("client_id")).toBe(CLINE_WORKOS_CLIENT_ID);
    expect(JSON.parse(String(requests[2]?.init?.body))).toEqual({
      accessToken: "workos-access",
      refreshToken: "workos-refresh",
    });
  });

  test("waits before the first device poll and applies the five-second slow_down increment", async () => {
    const delays: number[] = [];
    captureSleeps(delays);
    let pollCount = 0;

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/user_management/authorize/device")) {
        return Response.json({
          device_code: "device-paced",
          user_code: "PACE-CODE",
          verification_uri: "https://authenticate.workos.com/device",
          expires_in: 300,
          interval: 2,
        });
      }
      if (url.endsWith("/user_management/authenticate")) {
        pollCount += 1;
        if (pollCount === 1) return Response.json({ error: "slow_down" }, { status: 400 });
        if (pollCount === 2) return Response.json({ error: "authorization_pending" }, { status: 400 });
        return Response.json({ access_token: "workos-access", refresh_token: "workos-refresh" });
      }
      if (url === `${CLINE_API_BASE_URL}/api/v1/auth/register`) {
        return Response.json({
          success: true,
          data: {
            accessToken: "cline-access",
            refreshToken: "cline-refresh",
            expiresAt: "2030-01-02T03:04:05.000Z",
          },
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    }) as typeof fetch;

    await loginCline({});

    expect(pollCount).toBe(3);
    expect(delays).toEqual([2_000, 7_000, 7_000]);
  });

  test("removes the sleep abort listener after a completed poll wait", async () => {
    captureSleeps([]);
    const abort = new AbortController();
    const signal = abort.signal;
    const originalAdd = signal.addEventListener.bind(signal);
    const originalRemove = signal.removeEventListener.bind(signal);
    let activeAbortListeners = 0;
    signal.addEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: AddEventListenerOptions | boolean) => {
      if (type === "abort") activeAbortListeners += 1;
      originalAdd(type, listener, options);
    }) as typeof signal.addEventListener;
    signal.removeEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: EventListenerOptions | boolean) => {
      if (type === "abort") activeAbortListeners -= 1;
      originalRemove(type, listener, options);
    }) as typeof signal.removeEventListener;

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/user_management/authorize/device")) {
        return Response.json({
          device_code: "device-listener",
          user_code: "LISTENER",
          verification_uri: "https://authenticate.workos.com/device",
          expires_in: 300,
          interval: 1,
        });
      }
      if (url.endsWith("/user_management/authenticate")) {
        return Response.json({ access_token: "workos-access", refresh_token: "workos-refresh" });
      }
      if (url === `${CLINE_API_BASE_URL}/api/v1/auth/register`) {
        return Response.json({
          success: true,
          data: {
            accessToken: "cline-access",
            refreshToken: "cline-refresh",
            expiresAt: "2030-01-02T03:04:05.000Z",
          },
        });
      }
      throw new Error(`Unexpected request: ${url}`);
    }) as typeof fetch;

    await loginCline({ signal });

    expect(activeAbortListeners).toBe(0);
  });

  test("settles an aborting poll wait once when listener registration aborts reentrantly", async () => {
    const abort = new AbortController();
    const signal = abort.signal;
    const originalAdd = signal.addEventListener.bind(signal);
    const originalRemove = signal.removeEventListener.bind(signal);
    let removeCalls = 0;
    let armed = false;

    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/user_management/authorize/device")) {
        signal.addEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: AddEventListenerOptions | boolean) => {
          originalAdd(type, listener, options);
          if (type === "abort" && armed) abort.abort("reentrant-test");
        }) as typeof signal.addEventListener;
        signal.removeEventListener = ((type: string, listener: EventListenerOrEventListenerObject, options?: EventListenerOptions | boolean) => {
          if (type === "abort") removeCalls += 1;
          originalRemove(type, listener, options);
        }) as typeof signal.removeEventListener;
        armed = true;
        return Response.json({
          device_code: "device-reentrant",
          user_code: "REENTRANT",
          verification_uri: "https://authenticate.workos.com/device",
          expires_in: 300,
          interval: 1,
        });
      }
      throw new Error(`Unexpected request after cancellation: ${url}`);
    }) as typeof fetch;

    await expect(loginCline({ signal })).rejects.toThrow("Login cancelled");

    expect(removeCalls).toBe(1);
  });

  test("refreshes through the Cline API and preserves the old refresh token when omitted", async () => {
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      expect(String(input)).toBe(`${CLINE_API_BASE_URL}/api/v1/auth/refresh`);
      expect(JSON.parse(String(init?.body))).toEqual({
        refreshToken: "cline-refresh",
        grantType: "refresh_token",
      });
      return Response.json({
        success: true,
        data: {
          accessToken: "cline-access-2",
          tokenType: "Bearer",
          expiresAt: "2030-02-03T04:05:06.000Z",
          userInfo: {
            clineUserId: "cline-user-42",
            email: "member@example.com",
            name: "Member",
            subject: "workos-user-42",
            accounts: ["personal"],
          },
        },
      });
    }) as typeof fetch;

    await expect(refreshClineToken("cline-refresh")).resolves.toEqual({
      access: "cline-access-2",
      refresh: "cline-refresh",
      expires: Date.parse("2030-02-03T04:05:06.000Z"),
      accountId: "cline-user-42",
      email: "member@example.com",
    });
  });

  test("surfaces only an allowlisted terminal refresh code and never echoes the response body", async () => {
    globalThis.fetch = (async () => Response.json({
      error: "invalid_grant",
      message: "revoked credential secret-token-123",
    }, { status: 401 })) as typeof fetch;

    const error = await refreshClineToken("cline-refresh").catch(value => value as Error);
    expect(error.message).toContain("invalid_grant");
    expect(error.message).not.toContain("secret-token-123");
    expect(error.message).not.toContain("cline-refresh");
  });
});
