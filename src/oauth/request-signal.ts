const OAUTH_REQUEST_TIMEOUT_MS = 30_000;

/** Bound every OAuth network call while preserving an earlier caller cancellation reason. */
export function oauthRequestSignal(parent?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(OAUTH_REQUEST_TIMEOUT_MS);
  return parent ? AbortSignal.any([parent, timeout]) : timeout;
}
