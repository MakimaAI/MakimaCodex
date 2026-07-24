import { findLiveProxy, probeHostname, type LiveProxy } from "../server/proxy-liveness";
import { removeCredential } from "./store";
import { runningProxyUpdateHeaders } from "./login-cli";

interface LogoutOAuthProviderDeps {
  findLiveProxyImpl?: () => Promise<LiveProxy | null>;
  fetchImpl?: typeof fetch;
  removeCredentialImpl?: (provider: string) => Promise<void>;
  headersImpl?: () => HeadersInit;
}

export type OAuthLogoutRoute = "proxy" | "store";

/**
 * A live proxy owns an additional process-local AbortController fence, so route through it
 * when present. Without a proxy, removeCredential still advances the persisted provider
 * generation before removing credentials, fencing logins running in other CLI processes.
 */
export async function logoutOAuthProvider(
  provider: string,
  deps: LogoutOAuthProviderDeps = {},
): Promise<OAuthLogoutRoute> {
  const name = provider.trim().toLowerCase();
  const live = await (deps.findLiveProxyImpl ?? findLiveProxy)();
  if (!live) {
    await (deps.removeCredentialImpl ?? removeCredential)(name);
    return "store";
  }

  const baseUrl = `http://${probeHostname(live.hostname)}:${live.port}`;
  const response = await (deps.fetchImpl ?? fetch)(
    `${baseUrl}/api/oauth/logout?provider=${encodeURIComponent(name)}`,
    {
      method: "POST",
      headers: (deps.headersImpl ?? runningProxyUpdateHeaders)(),
      signal: AbortSignal.timeout(30_000),
    },
  );
  if (!response.ok) {
    const payload = (await response.json().catch(() => ({}))) as { error?: unknown };
    const detail = typeof payload.error === "string" && payload.error.trim()
      ? payload.error.trim()
      : `proxy returned HTTP ${response.status}`;
    throw new Error(`OAuth logout failed: ${detail}`);
  }
  return "proxy";
}
