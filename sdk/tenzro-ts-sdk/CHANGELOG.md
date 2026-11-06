# Changelog

## 0.9.0

First release.

### Added
- `NetworkPreset`, `PREVIEW_NETWORK`, `PREVIEW_CONFIG` and
  `TenzroClient.preview()`.
- `TypedTxClient.prepare(from, tx)`: a dry run that has the node encode the
  signing payload, checks it and returns the unsigned request and digest.
- `RpcCallError.isLightBuild`, for the light build's refusal of calls that
  need a local model.
- Typed results for the admin audit log, kill-switch receipts and pages,
  treasury accounts, ZK proofs and verification, TEE providers, finality and
  checkpoint certificates, provider stats and inference results.
- `examples/local-node.ts`.
- `connectToNetwork()` with no arguments reaches the network: it asks the seeds
  for the staked RPC operators on chain and keeps those that report the
  network chain id and agree on a checkpoint.
- One thin core and a package per capability: `@tenzro/core`,
  `@tenzro/payments`, `@tenzro/settlement`, `@tenzro/agents`, `@tenzro/bridge`,
  `@tenzro/inference` and `@tenzro/chain`; `tenzro-sdk` re-exports all of them
  with `TenzroClient`.
- `HardwareDpopProver` mints DPoP proofs with the hardware key.
- Every RPC the node serves has one binding, and every transaction type has a
  builder.
- Signing is hardware P-256 (TPM 2.0, Secure Enclave or passkey), with the
  optional ML-DSA-65 leg where the hardware holds one. Hardware keys load
  through the optional `@tenzro/device-key` package; without hardware the SDK
  refuses to sign.
- Payments follow the challenge and credential flow, with x402 v2 headers, the hybrid payer and the agent-channel payer.
- `web` exports the paying fetch client and the publisher gate.
- Offline verification of governance receipts.
- `getTerms` returns an agent's full Terms, the root that approved them, their
  status and spend against each limit.

### Network
- The default network is the preview network, `PREVIEW_NETWORK`: chain id
  13380, RPC `https://rpc.tenzro.com`, REST API `https://api.tenzro.com`, MCP
  `https://mcp.tenzro.com/mcp`, A2A `https://a2a.tenzro.com`, relay
  `https://relay.tenzro.com`. `connectToNetwork()`, `DEFAULT_NETWORK`,
  `NETWORK_CHAIN_ID` and `TenzroClient.fromInjected()` follow it, and
  `NETWORK_SEEDS` is `https://rpc.tenzro.com`.
