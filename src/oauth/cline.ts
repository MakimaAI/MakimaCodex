/** Cline account OAuth via the official WorkOS device flow. */
import type { OAuthController, OAuthCredentials } from "./types";

export const CLINE_API_BASE_URL = "https://api.cline.bot";
export const CLINE_WORKOS_CLIENT_ID = "client_01K3A541FN8TA3EPPHTD2325AR";

const WORKOS_API_BASE_URL = "https://api.workos.com";
const DEVICE_AUTH_PATH = "/user_management/authorize/device";
const DEVICE_TOKEN_PATH = "/user_management/authenticate";
const CLINE_REGISTER_PATH = "/api/v1/auth/register";
const CLINE_REFRESH_PATH = "/api/v1/auth/refresh";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_DEVICE_TTL_SECONDS = 300;
const DEFAULT_POLL_SECONDS = 5;
const TERMINAL_REFRESH_ERRORS = new Set(["invalid_grant", "access_denied", "expired_token", "revoked_token"]);

/** Cline's API expects WorkOS OAuth access tokens in its namespaced bearer-key form. */
export function formatClineWorkOsAccessToken(accessToken: string): string {
  const trimmed = accessToken.trim();
  return trimmed.toLowerCase().startsWith("workos:")
    ? `workos:${trimmed.slice("workos:".length)}`
    : `workos:${trimmed}`;
}

interface WorkOSDeviceResponse {
  device_code?: string;
  user_code?: string;
  verification_uri?: string;
  verification_uri_complete?: string;
  expires_in?: number;
  interval?: number;
  error?: string;
}

interface WorkOSTokenResponse {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  error?: string;
}

interface ClineUserInfo {
  clineUserId?: string | null;
  email?: string;
}

interface ClineTokenResponse {
  success?: boolean;
  data?: {
    accessToken?: string;
    refreshToken?: string;
    expiresAt?: string;
    userInfo?: ClineUserInfo;
  };
}

function requestSignal(signal?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(DEFAULT_TIMEOUT_MS);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("Login cancelled"));
    let settled = false;
    let timer: ReturnType<typeof setTimeout>;
    const onAbort = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      reject(new Error("Login cancelled"));
    };
    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    if (settled) return;
    signal?.addEventListener("abort", onAbort, { once: true });
    // Close the check/listener race if cancellation happened between the first
    // aborted check and listener registration.
    if (signal?.aborted) onAbort();
  });
}

function allowedVerificationUrl(raw: string): string {
  const parsed = new URL(raw);
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new Error("Cline device authorization returned an unsafe verification URL");
  }
  if (host !== "authenticate.workos.com" && !host.endsWith(".workos.com") && !host.endsWith(".cline.bot")) {
    throw new Error("Cline device authorization returned an unexpected verification host");
  }
  return parsed.toString();
}

function positiveSeconds(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback;
}

function parseClineCredential(payload: ClineTokenResponse, refreshFallback?: string): OAuthCredentials {
  const data = payload.data;
  if (!payload.success || !data?.accessToken || !data.expiresAt) {
    throw new Error("Cline token response missing required fields");
  }
  const refresh = data.refreshToken ?? refreshFallback;
  if (!refresh) throw new Error("Cline token response missing refresh token");
  const expires = Date.parse(data.expiresAt);
  if (!Number.isFinite(expires)) throw new Error("Cline token response has an invalid expiry");
  const accountId = data.userInfo?.clineUserId || undefined;
  const email = data.userInfo?.email?.trim().toLowerCase() || undefined;
  return {
    access: data.accessToken,
    refresh,
    expires,
    ...(accountId ? { accountId } : {}),
    ...(email ? { email } : {}),
  };
}

async function requestDeviceAuthorization(signal?: AbortSignal): Promise<{
  deviceCode: string;
  userCode: string;
  verificationUrl: string;
  expiresInSeconds: number;
  intervalSeconds: number;
}> {
  const response = await fetch(`${WORKOS_API_BASE_URL}${DEVICE_AUTH_PATH}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: CLINE_WORKOS_CLIENT_ID }),
    signal: requestSignal(signal),
  });
  const payload = (await response.json().catch(() => ({}))) as WorkOSDeviceResponse;
  if (!response.ok) throw new Error(`Cline device authorization failed (${response.status})`);
  if (!payload.device_code || !payload.user_code || !payload.verification_uri) {
    throw new Error("Cline device authorization response missing required fields");
  }
  return {
    deviceCode: payload.device_code,
    userCode: payload.user_code,
    verificationUrl: allowedVerificationUrl(payload.verification_uri_complete ?? payload.verification_uri),
    expiresInSeconds: positiveSeconds(payload.expires_in, DEFAULT_DEVICE_TTL_SECONDS),
    intervalSeconds: positiveSeconds(payload.interval, DEFAULT_POLL_SECONDS),
  };
}

async function pollWorkOSToken(
  deviceCode: string,
  expiresInSeconds: number,
  initialIntervalSeconds: number,
  ctrl: OAuthController,
): Promise<{ accessToken: string; refreshToken: string }> {
  const deadline = Date.now() + expiresInSeconds * 1000;
  let intervalSeconds = Math.max(1, initialIntervalSeconds);
  while (Date.now() <= deadline) {
    if (ctrl.signal?.aborted) throw new Error("Login cancelled");
    await sleep(intervalSeconds * 1000, ctrl.signal);
    if (Date.now() > deadline) break;
    const response = await fetch(`${WORKOS_API_BASE_URL}${DEVICE_TOKEN_PATH}`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
        device_code: deviceCode,
        client_id: CLINE_WORKOS_CLIENT_ID,
      }),
      signal: requestSignal(ctrl.signal),
    });
    const payload = (await response.json().catch(() => ({}))) as WorkOSTokenResponse;
    if (response.ok && payload.access_token && payload.refresh_token) {
      return { accessToken: payload.access_token, refreshToken: payload.refresh_token };
    }
    if (payload.error === "authorization_pending") {
      ctrl.onProgress?.("Waiting for browser authentication confirmation...");
      continue;
    }
    if (payload.error === "slow_down") {
      intervalSeconds += 5;
      ctrl.onProgress?.("Waiting for browser authentication confirmation...");
      continue;
    }
    if (payload.error === "access_denied") throw new Error("Cline device authorization denied");
    if (payload.error === "expired_token") throw new Error("Cline device authorization expired");
    throw new Error(`Cline device token request failed (${response.status})`);
  }
  throw new Error("Cline device authorization timed out");
}

async function registerClineToken(
  workos: { accessToken: string; refreshToken: string },
  signal?: AbortSignal,
): Promise<OAuthCredentials> {
  const response = await fetch(`${CLINE_API_BASE_URL}${CLINE_REGISTER_PATH}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(workos),
    signal: requestSignal(signal),
  });
  if (!response.ok) throw new Error(`Cline token registration failed (${response.status})`);
  return parseClineCredential((await response.json()) as ClineTokenResponse);
}

export async function loginCline(ctrl: OAuthController): Promise<OAuthCredentials> {
  const device = await requestDeviceAuthorization(ctrl.signal);
  ctrl.onAuth?.({
    url: device.verificationUrl,
    instructions: `Enter this code in your browser: ${device.userCode}`,
  });
  const workos = await pollWorkOSToken(
    device.deviceCode,
    device.expiresInSeconds,
    device.intervalSeconds,
    ctrl,
  );
  return registerClineToken(workos, ctrl.signal);
}

export async function refreshClineToken(refreshToken: string, signal?: AbortSignal): Promise<OAuthCredentials> {
  const response = await fetch(`${CLINE_API_BASE_URL}${CLINE_REFRESH_PATH}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken, grantType: "refresh_token" }),
    signal: requestSignal(signal),
  });
  const payload = await response.json().catch(() => ({})) as ClineTokenResponse & { error?: unknown };
  if (!response.ok) {
    const code = typeof payload.error === "string" && TERMINAL_REFRESH_ERRORS.has(payload.error)
      ? payload.error
      : undefined;
    throw new Error(code
      ? `Cline token refresh failed: ${code} (HTTP ${response.status})`
      : `Cline token refresh failed (${response.status})`);
  }
  return parseClineCredential(payload, refreshToken);
}
