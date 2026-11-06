# Changelog

## 0.2.0

First release.

- `window.tenzro` injected provider for browser extensions and dApps.
- CAIP-25/27 multichain core, an EIP-1193/EIP-6963 EVM facade and Wallet
  Standard registration.
- The extension holds no key: approvals open the open wallet's window, where
  the user's passkey signs; raw signing methods are refused.
- The service worker reaches the network through the RPC operators staked on
  chain, discovered with `discoverEndpoints` from the SDK's default network or
  one set with `configureNetwork` or `tenzro:network` in storage.
- Entry points: `.`, `inpage`, `detect`, `content-script`, `session-store`,
  `service-worker`, `routing`, `wallet-window` and `types`.
