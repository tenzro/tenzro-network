/**
 * @tenzro/inject — public entry point.
 *
 * The package ships three consumable surfaces:
 *
 *   - `@tenzro/inject`         (this file) — re-exports the dApp-facing
 *                              detect helpers, the type definitions, and
 *                              the in-page provider installer for
 *                              extensions that bundle their own.
 *   - `@tenzro/inject/inpage`  — main-world script. Extensions ship this
 *                              as a separate file (see `inpage.ts`) and
 *                              inject it via a content-script `<script>`
 *                              tag.
 *   - `@tenzro/inject/detect`  — dApp-side detection helpers, isolated
 *                              from the in-page provider so dApp bundles
 *                              don't pull `installTenzroProvider` into
 *                              their JS.
 *
 * dApp authors should depend on `@tenzro/inject/detect`. Extension
 * authors building on top of this package import from `./inpage` and
 * the service-worker / content-script modules.
 */

export {
  // Top-level discovery
  getTenzroProvider,
  waitForTenzroProvider,
  // EIP-6963
  discoverEip6963Provider,
  discoverAllEip6963Providers,
  // Wallet Standard
  discoverWalletStandardWallet,
  // Errors
  TenzroNotInstalledError,
  // Types re-exported for convenience
  type TenzroWindowProvider,
} from "./detect";

// Re-export the canonical type definitions so consumers don't need a
// secondary `@tenzro/inject/types` import.
export {
  // EIP-1193
  type EIP1193RequestArguments,
  type EIP1193ProviderRpcError,
  type EIP1193EventName,
  type EIP1193Provider,
  RPC_ERROR_CODES,
  // EIP-6963
  type EIP6963ProviderInfo,
  type EIP6963ProviderDetail,
  type EIP6963AnnounceProviderEvent,
  // Wallet Standard
  type WalletStandardAccount,
  type WalletStandardWallet,
  // CAIP
  type CAIP25Scope,
  type CAIP25Scopes,
  type CAIP25CreateSessionParams,
  type CAIP25CreateSessionResult,
  type CAIP27InvokeParams,
  // Tenzro-specific
  TENZRO_SCOPES,
  SCOPE_METHODS,
  TENZRO_PROVIDER_RDNS,
  TENZRO_PROVIDER_NAME,
  DEFAULT_PLACEHOLDER_ICON,
} from "./types";

// What the extension serves, and what the open wallet signs instead.
export { KEY_METHODS, WALLET_METHODS, parseNetworkSettings, type NetworkSettings } from "./routing";
