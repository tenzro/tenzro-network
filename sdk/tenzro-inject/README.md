# @tenzro/inject

The official Tenzro injected provider for browser extensions and dApps. Installs `window.tenzro` and announces itself via EIP-6963 (EVM façade), Wallet Standard (SVM façade), and a CAIP-25/27 multichain core.

## What it gives you

A four-facet provider:

```ts
window.tenzro
  .request({ method, params })  // EIP-1193 — routes to native scope
  .evm                          // EIP-1193 + EIP-6963 — eth_*, personal_*, wallet_*
  .svm                          // Wallet Standard — solana_signTransaction, etc.
  .native                       // tenzro_* native verbs (TDIP, ERC-8004, ZK, VRF)
  .multichain                   // CAIP-25 createSession + CAIP-27 invokeMethod
```

Methods exposed per scope are listed in `SCOPE_METHODS` (`src/types.ts`).

## For dApp authors

Install the detect helpers and discover the Tenzro provider:

```ts
import { discoverEip6963Provider, waitForTenzroProvider } from "@tenzro/inject/detect";

// Option 1 — EIP-6963 (preferred for EVM-only dApps)
const detail = await discoverEip6963Provider();
const result = await detail.provider.request({ method: "eth_chainId" });

// Option 2 — full Tenzro provider (multichain)
const tenzro = await waitForTenzroProvider();
await tenzro.multichain.createSession({
  scopes: {
    "eip155:13380": { methods: ["eth_chainId", "eth_sendTransaction"], notifications: [] },
  },
});
const balance = await tenzro.native.request("tenzro_getBalance", [address]);
```

If the user hasn't installed Tenzro, both helpers reject with `TenzroNotInstalledError` after their timeout — render an "Install Tenzro" CTA.

`@tenzro/inject/detect` also exports `getTenzroProvider()` (synchronous, returns `undefined` when absent), `discoverAllEip6963Providers()` (every announcing wallet, for a picker UI), and `discoverWalletStandardWallet()` (the Wallet Standard / SVM façade).

### Call batches and permissions (ERC-5792, ERC-7715)

The EVM provider speaks the standard wallet-call methods, so libraries such as viem and wagmi work unchanged:

| Method | What it does |
|---|---|
| `wallet_getCapabilities` | `{ "<chainId>": { atomic: { status: "supported" }, paymasterService: { supported: false } } }`, answered without a window |
| `wallet_sendCalls` | Up to 16 calls (`to`, `value`, `data`) as one contract-call transaction from the user's account, approved once by their passkey in the open wallet. Every call applies or none does. The batch id is the transaction hash. |
| `wallet_getCallsStatus` | `100` while pending, `200` confirmed, `500` reverted, from the transaction's receipt; answered without a window |
| `wallet_showCallsStatus` | Shows the batch in the open wallet |
| `wallet_getSupportedExecutionPermissions` | `native-token-periodic` with the `expiry` rule |
| `wallet_requestExecutionPermissions` | Grants one of the user's agents (`to` is the agent's wallet address) a spend limit per hour (`periodDuration` 3600) or per day (86400), with an optional expiry, by updating the agent's Terms with the user's passkey approval. The Terms are recorded in consensus and every validator checks each of the agent's actions against them. The agent acts through its serving nodes, not through a delegation contract, so `delegationManager` is the zero address and `context` names the agent. |
| `wallet_revokeExecutionPermission` | Sets that agent's spend limits to zero |
| `wallet_getGrantedExecutionPermissions` | The spend limits the user's agents hold |

A sponsor cannot pay a call batch's fee: the network takes a transaction's fee from its sender, so `paymasterService` is not supported for batches.

## For extension authors

Bundle three entry points from this package:

| Entry | Purpose | Where it runs |
|---|---|---|
| `inpage.ts` | Installs `window.tenzro`, announces EIP-6963 + Wallet Standard | Page main world |
| `content-script.ts` | Injects `inpage.js`, bridges page ↔ service worker | Content script (isolated world) |
| `service-worker.ts` | Network discovery, CAIP-25 sessions, JSON-RPC routing | MV3 service worker |

Manifest V3 example:

```json
{
  "manifest_version": 3,
  "name": "Tenzro Wallet",
  "version": "0.1.0",
  "background": { "service_worker": "service-worker.js", "type": "module" },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content-script.js"],
    "run_at": "document_start"
  }],
  "web_accessible_resources": [{
    "resources": ["inpage.js"],
    "matches": ["<all_urls>"]
  }],
  "permissions": ["storage"]
}
```

The content script auto-injects `inpage.js` into the page's main world at `document_start` and opens a long-lived `chrome.runtime.connect()` port to the service worker. The service worker keeps CAIP-25 sessions (each confirmed by the user) and sends calls to the network's RPC operators. The network is the SDK's `DEFAULT_NETWORK` (the preview network's RPC endpoint and chain id) unless the extension stores another as `tenzro:network` (`{ seeds, chainId }`) in `chrome.storage.local` or calls `configureNetwork()`. A seed is only a way in: the worker discovers the staked `rpc` operators from those seeds with the SDK's `discoverEndpoints` (the discovery `connectToNetwork` runs), keeps the ones that report the chain id and agree on the chain's history, and fails over between them.

## Keys and authority

The extension holds no key and no credential of any kind: no browser-generated key, no token, no secret in storage. The user's authority comes only from their passkey, and the passkey signs only in the open wallet (`https://wallet.tenzro.com`, or `walletUrl` in `installTenzroProvider`):

- Reads and already-signed transactions (`tenzro_sendRawTransaction`, `eth_sendRawTransaction`) go to the network with no credential. Every operator serves them: reads are open, and a transaction carries its own passkey signature.
- Methods that need the user's approval (`tenzro_connect`, `tenzro_sendTransaction`, `tenzro_signSettlementPlan`, `tenzro_approveAgentTerms`, `tenzro_approveAgentAction`, `wallet_sendCalls`, `wallet_requestExecutionPermissions`, `wallet_revokeExecutionPermission`, and `eth_requestAccounts`, which connects) open the open wallet's window from the page. The wallet sees the page's real origin, shows the request, and the user's passkey signs it there.
- Raw signing methods (`eth_sign`, `personal_sign`, `eth_signTypedData*`, `eth_sendTransaction`, `solana_sign*`) are refused: they would need a key this extension does not hold.

Why this design and not an access token. The alternative was to have the passkey sign in to a node once and hold a short-lived access token for later calls. The node's access tokens are bound to a DPoP key the caller holds (RFC 9449); in a browser extension that key could only be a WebCrypto key generated in software, which the rule that keys live only in a passkey, TPM or Secure Enclave forbids. A token bound to nothing would be a bearer token: anyone who copied it from the extension could use it until it expired. Routing every approval through the open wallet means there is nothing in the extension to steal, and every write is approved by the passkey for exactly that write. The cost: an operator method that requires a signed-in caller (a node's own access policy) is not reachable through this provider, and each approval opens a wallet window, which a browser only allows from a user action such as a click.

## Multichain routing rules

- `tenzro:mainnet` / `tenzro:testnet` — only `tenzro_*` methods accepted.
- `eip155:<chain-id>` (`eip155:13380` on the preview network) — only `eth_*` / `personal_*` / `wallet_*` accepted.

The CAIP-2 `tenzro:` namespace is filed with `ChainAgnostic/namespaces` (`#184`); the reference documents are `tenzro/caip2.md`, `tenzro/caip10.md`, and `tenzro/caip19.md`.

## Build

```sh
npm install
npm run build
```

Outputs to `dist/`. The package's `exports` field maps six subpath imports — `@tenzro/inject`, `/inpage`, `/detect`, `/content-script`, `/service-worker`, `/types` — to their compiled equivalents.

## License

Apache-2.0
