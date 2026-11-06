/**
 * The open wallet's window, opened from the page.
 *
 * Every request that needs the user's authority runs in the open wallet
 * (default https://wallet.tenzro.com), on its own origin, where the user's
 * passkey signs it. The page opens the window, sends one request, and gets
 * the answer by postMessage (protocol `tenzro-wallet/popup/v1`). The wallet
 * sees the page's real origin and shows it to the user; both sides check
 * origins exactly. The extension is never in this path and holds nothing.
 */

export const POPUP_PROTOCOL = "tenzro-wallet/popup/v1";
export const DEFAULT_WALLET_URL = "https://wallet.tenzro.com";

export class WalletWindowError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
    this.name = "WalletWindowError";
  }
}

let counter = 0;

/**
 * Opens the wallet window and sends `method` once it is ready. Call it from a
 * user action: browsers block windows opened without one.
 */
export function requestInWallet<T>(walletUrl: string, method: string, params: unknown, timeoutMs = 5 * 60_000): Promise<T> {
  const origin = new URL(walletUrl).origin;
  const popup = window.open(new URL("/approve", walletUrl).toString(), "tenzro-wallet", "popup,width=420,height=680");
  if (!popup) return Promise.reject(new WalletWindowError(4001, "the browser blocked the wallet window; ask again from a click"));
  const id = `${Date.now().toString(36)}-${++counter}`;
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("message", onMessage);
      window.clearInterval(poll);
      window.clearTimeout(timer);
      fn();
    };
    const onMessage = (e: MessageEvent) => {
      if (e.origin !== origin || e.source !== popup) return;
      const d = e.data as { protocol?: string; type?: string; id?: string; result?: T; error?: { code: number; message: string } };
      if (d?.protocol !== POPUP_PROTOCOL) return;
      if (d.type === "ready") {
        popup.postMessage({ protocol: POPUP_PROTOCOL, type: "request", id, method, params }, origin);
        return;
      }
      if (d.type === "response" && d.id === id) {
        finish(() => {
          if (d.error) reject(new WalletWindowError(d.error.code, d.error.message));
          else resolve(d.result as T);
        });
      }
    };
    window.addEventListener("message", onMessage);
    const poll = window.setInterval(() => {
      if (popup.closed) finish(() => reject(new WalletWindowError(4001, "the wallet window was closed")));
    }, 500);
    const timer = window.setTimeout(() => {
      finish(() => {
        popup.close();
        reject(new WalletWindowError(4001, "the request timed out"));
      });
    }, timeoutMs);
  });
}
