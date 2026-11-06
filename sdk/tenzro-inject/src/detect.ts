/**
 * dApp-facing detection helpers for the Tenzro injected provider.
 *
 * The browser extension installs `window.tenzro` and announces itself via
 * three discovery mechanisms in parallel:
 *
 *   1. EIP-6963 — `eip6963:announceProvider` event (EVM façade)
 *   2. Wallet Standard — `wallet-standard:register-wallet` (SVM façade)
 *   3. `window.tenzro` — top-level multichain provider
 *
 * dApps should prefer EIP-6963 / Wallet Standard for their respective
 * surfaces, and fall back to `window.tenzro` only when explicitly opting
 * into the Tenzro multichain core (CAIP-25 sessions, native methods).
 */

import {
  EIP1193Provider,
  EIP6963AnnounceProviderEvent,
  EIP6963ProviderDetail,
  TENZRO_PROVIDER_RDNS,
  WalletStandardWallet,
} from "./types";

// ─── Top-level detection ─────────────────────────────────────────────────

/**
 * Public shape of `window.tenzro` — augmented at runtime by `inpage.ts`.
 *
 * Re-declared here (rather than imported) so the detect path can ship as
 * a standalone module without pulling in the in-page provider code.
 */
export interface TenzroWindowProvider extends EIP1193Provider {
  readonly isTenzro: true;
  readonly version: string;
  readonly chain: string;
  readonly evm: EIP1193Provider & { readonly isTenzro: true };
  readonly svm: unknown;
  readonly native: {
    request<T = unknown>(
      method: string,
      params?: readonly unknown[] | Record<string, unknown>,
    ): Promise<T>;
  };
  readonly multichain: {
    createSession(params: unknown): Promise<unknown>;
    revokeSession(sessionId?: string): Promise<void>;
    describeSession(sessionId?: string): Promise<unknown>;
    invokeMethod<T = unknown>(args: unknown): Promise<T>;
  };
}

declare global {
  interface Window {
    tenzro?: TenzroWindowProvider;
  }
}

/**
 * Synchronously read `window.tenzro` if the extension has already
 * installed it. Returns `undefined` if not present.
 *
 * Note: extensions install on `document_start`, but a dApp script that
 * runs *before* the content script's `<script>` tag has executed will
 * still see `undefined`. Prefer `waitForTenzro()` for race-free access.
 */
export function getTenzroProvider(): TenzroWindowProvider | undefined {
  if (typeof window === "undefined") return undefined;
  return window.tenzro;
}

/**
 * Resolve once the Tenzro provider is installed on `window.tenzro`.
 *
 * Polls every 50 ms up to `timeoutMs` (default 3000). Rejects with
 * `TenzroNotInstalledError` if the timeout elapses with no provider.
 *
 * Use this in dApps that load before the extension's content script
 * has had a chance to inject. The poll is cheap (one property read).
 */
export function waitForTenzroProvider(
  timeoutMs: number = 3000,
): Promise<TenzroWindowProvider> {
  if (typeof window === "undefined") {
    return Promise.reject(
      new TenzroNotInstalledError("not running in a browser context"),
    );
  }

  const existing = window.tenzro;
  if (existing) return Promise.resolve(existing);

  return new Promise((resolve, reject) => {
    const start = Date.now();
    const interval = window.setInterval(() => {
      if (window.tenzro) {
        window.clearInterval(interval);
        resolve(window.tenzro);
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        window.clearInterval(interval);
        reject(
          new TenzroNotInstalledError(
            `window.tenzro not present after ${timeoutMs}ms — extension may not be installed`,
          ),
        );
      }
    }, 50);
  });
}

// ─── EIP-6963 (EVM façade discovery) ─────────────────────────────────────

/**
 * Listen for EIP-6963 announcements and resolve when a provider matching
 * `rdns: com.tenzro.wallet` arrives — or any provider, if `rdns` is
 * unspecified.
 *
 * Side-effect-free apart from the request-provider dispatch: caller is
 * responsible for keeping the returned promise alive until resolution.
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

    // Per EIP-6963 §Specification, dApps signal readiness with this event;
    // already-installed wallets re-announce in response.
    window.dispatchEvent(new Event("eip6963:requestProvider"));
  });
}

/**
 * Collect *all* EIP-6963 providers currently announcing. Useful for
 * wallet-picker UIs that want to show the user every installed wallet
 * rather than auto-selecting Tenzro.
 *
 * Resolves after `windowMs` (default 500) — long enough for all
 * pre-installed wallets to respond to `eip6963:requestProvider`, short
 * enough not to block initial render.
 */
export function discoverAllEip6963Providers(
  windowMs: number = 500,
): Promise<readonly EIP6963ProviderDetail[]> {
  if (typeof window === "undefined") return Promise.resolve([]);

  return new Promise((resolve) => {
    const seen = new Map<string, EIP6963ProviderDetail>();

    const onAnnounce = (rawEvent: Event) => {
      const event = rawEvent as EIP6963AnnounceProviderEvent;
      const detail = event.detail;
      if (detail?.info?.uuid) {
        seen.set(detail.info.uuid, detail);
      }
    };

    window.addEventListener("eip6963:announceProvider", onAnnounce);
    window.dispatchEvent(new Event("eip6963:requestProvider"));

    window.setTimeout(() => {
      window.removeEventListener("eip6963:announceProvider", onAnnounce);
      resolve(Array.from(seen.values()));
    }, windowMs);
  });
}

// ─── Wallet Standard (SVM façade discovery) ──────────────────────────────

interface WalletStandardRegisterEvent extends CustomEvent {
  readonly detail: {
    register(callback: (wallet: WalletStandardWallet) => () => void): () => void;
  };
}

/**
 * Listen for Wallet-Standard `register-wallet` events and resolve when a
 * wallet matching `name` (default `"Tenzro"`) arrives.
 *
 * Wallet Standard is the SVM-side mirror of EIP-6963. Solana dApps
 * (`@wallet-standard/react`, `@solana/wallet-adapter`) plug into the
 * same event stream — this helper exists for non-React dApps that want
 * to talk to the Tenzro SVM façade directly.
 */
export function discoverWalletStandardWallet(options?: {
  name?: string;
  timeoutMs?: number;
}): Promise<WalletStandardWallet> {
  const wantName = options?.name ?? "Tenzro";
  const timeoutMs = options?.timeoutMs ?? 3000;

  if (typeof window === "undefined") {
    return Promise.reject(
      new TenzroNotInstalledError("not running in a browser context"),
    );
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let unsubscribe: (() => void) | undefined;

    const onRegister = (rawEvent: Event) => {
      const event = rawEvent as WalletStandardRegisterEvent;
      unsubscribe = event.detail.register((wallet) => {
        if (wallet.name === wantName && !settled) {
          settled = true;
          window.clearTimeout(timer);
          resolve(wallet);
        }
        return () => {}; // Wallet Standard requires an unregister callback
      });
    };

    window.addEventListener(
      "wallet-standard:register-wallet",
      onRegister as EventListener,
    );

    // Mirror of `eip6963:requestProvider` — Wallet Standard wallets
    // respond to `app-ready` by re-firing their `register-wallet` event.
    window.dispatchEvent(new Event("wallet-standard:app-ready"));

    const timer = window.setTimeout(() => {
      if (settled) return;
      settled = true;
      window.removeEventListener(
        "wallet-standard:register-wallet",
        onRegister as EventListener,
      );
      unsubscribe?.();
      reject(
        new TenzroNotInstalledError(
          `no Wallet-Standard wallet named "${wantName}" registered within ${timeoutMs}ms`,
        ),
      );
    }, timeoutMs);
  });
}

// ─── Errors ──────────────────────────────────────────────────────────────

/**
 * Thrown when a Tenzro provider is expected but not present in the page.
 *
 * Catch this in dApps to render an "Install Tenzro" CTA rather than a
 * generic error.
 */
export class TenzroNotInstalledError extends Error {
  readonly code = "TENZRO_NOT_INSTALLED" as const;

  constructor(message: string) {
    super(message);
    this.name = "TenzroNotInstalledError";
  }
}
