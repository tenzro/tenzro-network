# Changelog

## 0.9.0

First release.

### Added
- `network::NetworkPreset`, `network::PREVIEW_NETWORK` and
  `SdkConfig::preview()`.
- `TypedTxClient::prepare(from, &tx)` and `PreparedTransaction`: a dry run
  that has the node encode the signing payload, checks it and returns the
  unsigned request and digest.
- `SdkError::Node(NodeError)` carries the code, message and data of a JSON-RPC
  error the node answers with; `NodeError::is_light_build()`.
- `PageRequest` for event-log pages; typed admin audit log, kill-switch
  receipts, escrow pages, treasury accounts, ZK, TEE, finality and inference
  results.
- `examples/local_node.rs`.
- `network::connect_to_network(&NetworkOptions::default())` reaches the network
  through its staked RPC operators on chain.
- A thin core and one cargo feature per capability (`payments`, `settlement`,
  `agents`, `bridge`, `inference`, `chain`); `full`, the default, enables all.
- Typed requests for every RPC the node serves, and builders for every
  transaction type.
- Signing is hardware P-256 (TPM 2.0, Secure Enclave or passkey), with the
  optional ML-DSA-65 leg; without hardware the SDK refuses to sign.
- Payments follow the challenge and credential flow, with the x402 v2 paying
  client and the publisher gate (`tower` layer).
- Offline verification of governance receipts.
- `get_terms` returns an agent's full Terms, the root that approved them, their
  status and spend against each limit.

### Network
- The default network is the preview network, `network::PREVIEW_NETWORK`:
  chain id 133801, RPC `https://rpc.tenzro.com`, REST API
  `https://api.tenzro.com`, MCP `https://mcp.tenzro.com/mcp`, A2A
  `https://a2a.tenzro.com`, relay `https://relay.tenzro.com`.
  `NetworkOptions::default()` and `network::NETWORK_CHAIN_ID` follow it, and
  `NETWORK_SEEDS` is `https://rpc.tenzro.com`.
- `SdkConfigBuilder` without `chain_id` uses `network::NETWORK_CHAIN_ID`.
