/**
 * Minimal EIP-6963 provider discovery for `TenzroClient.fromInjected()`.
 *
 * The browser extension installs `window.tenzro` and announces itself
 * via `eip6963:announceProvider` (the multi-wallet discovery standard
 * from EIP-6963 §Specification). This helper listens for the matching
 * announcement and returns the provider, with a typed
 * `TenzroNotInstalledError` for the not-installed case.
 *
 * The discovery code is inlined here rather than imported from a
 * separate `@tenzro/inject` package so the SDK has zero peer
 * dependencies — `npm install tenzro-sdk` is enough to opt into the
 * injected-provider path.
 */
export interface EIP1193Provider {
  request<T = unknown>(args: {
    method: string;
    params?: readonly unknown[] | Record<string, unknown>;
  }): Promise<T>;
}

export interface EIP6963ProviderInfo {
  readonly uuid: string;
  readonly name: string;
  readonly icon: string;
  readonly rdns: string;
}

export interface EIP6963ProviderDetail {
  readonly info: EIP6963ProviderInfo;
  readonly provider: EIP1193Provider;
}

interface EIP6963AnnounceProviderEvent extends Event {
  readonly detail: EIP6963ProviderDetail;
}

/**
 * Default `rdns` for the Tenzro browser-extension provider: the
 * reverse-DNS form of tenzro.com, the one Tenzro domain. The same value
 * as the extension's `installTenzroProvider({ rdns })` default, so the
 * provider it announces is the one this discovers.
 */
export const TENZRO_PROVIDER_RDNS = "com.tenzro.wallet";

/**
 * Listen for EIP-6963 announcements and resolve when a provider
 * matching `rdns` arrives. Defaults to the Tenzro extension's RDNS.
 *
 * Rejects with {@link TenzroNotInstalledError} if no matching
 * provider announces within `timeoutMs` (default 3000ms).
 */
export function discoverEip6963Provider(options?: {
  rdns?: string;
  timeoutMs?: number;
}): Promise<EIP6963ProviderDetail> {
  const wantRdns = options?.rdns ?? TENZRO_PROVIDER_RDNS;
  const timeoutMs = options?.timeoutMs ?? 3000;

  if (typeof window === "undefined") {
    return Promise.reject(
      new TenzroNotInstalledError("not running in a browser context"),
    );
  }

  return new Promise((resolve, reject) => {
    let settled = false;

    const onAnnounce = (rawEvent: Event) => {
      const event = rawEvent as EIP6963AnnounceProviderEvent;
      if (event.detail?.info?.rdns === wantRdns && !settled) {
        settled = true;
        window.removeEventListener("eip6963:announceProvider", onAnnounce);
        window.clearTimeout(timer);
        resolve(event.detail);
      }
    };

    window.addEventListener("eip6963:announceProvider", onAnnounce);

    // The deadline is set before the request goes out: a wallet answers
    // it synchronously, and its announcement clears the deadline.
    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      window.removeEventListener("eip6963:announceProvider", onAnnounce);
      reject(
        new TenzroNotInstalledError(
          `no EIP-6963 provider with rdns="${wantRdns}" announced within ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);

    // Per EIP-6963 §Specification, dApps signal readiness with this
    // event; already-installed wallets re-announce in response.
    window.dispatchEvent(new Event("eip6963:requestProvider"));
  });
}

/**
 * Thrown when a Tenzro provider is expected but not present in the page.
 *
 * Catch this in dApps to render an "Install Tenzro" CTA rather than
 * a generic error. The `code` field is also set to the literal string
 * `"TENZRO_NOT_INSTALLED"` for callers that prefer duck-typing over
 * `instanceof`.
 */
export class TenzroNotInstalledError extends Error {
  readonly code = "TENZRO_NOT_INSTALLED" as const;

  constructor(message: string) {
    super(message);
    this.name = "TenzroNotInstalledError";
  }
}
