# Changelog

## 0.9.0

First release.

### Added
- `MultimodalClient::transcribe_recording` (`tenzro_transcribeStream`): a
  whole recording through the streaming transcription, every event in order.
  `ConsensusClient::fleet_host_evidence` (`tenzro_fleetHostEvidence`).
  Both SDKs now bind the same node methods; the methods neither binds on
  purpose are listed in the README.
- `light` feature (preview, off by default): `TenzroClient::light_client`
  checks checkpoint certificates, epoch handovers, state values and identity
  keys and key histories from a trusted committee with the `tenzro-light`
  crate.
- `compute::ComputeClient` (`client.compute()`): typed compute bonds, compute
  claims and the observed price feed, and `rent`, which signs a `CreateEscrow`
  with stream release to a provider's bonded address (`RentRequest`). The
  compute bond reads moved here from `ProviderClient`.
- `network::NetworkPreset`, `network::PREVIEW_NETWORK` and
  `SdkConfig::preview()`.
- `TypedTxClient::prepare(from, &tx)` and `PreparedTransaction`: a dry run
  that has the node encode the signing payload, checks it and returns the
  unsigned request and digest.
- `SdkError::Node(NodeError)` carries the code, message and data of a JSON-RPC
  error the node answers with; `NodeError::is_light_build()`,
  `is_jurisdiction_unmet()` (-32024) and `is_below_settlement_floor()` (-32026,
  a charge below the micro-settlement floor).
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
  chain id 13380, RPC `https://rpc.tenzro.com`, REST API
  `https://api.tenzro.com`, MCP `https://mcp.tenzro.com/mcp`, A2A
  `https://a2a.tenzro.com`, relay `https://relay.tenzro.com`.
  `NetworkOptions::default()` and `network::NETWORK_CHAIN_ID` follow it, and
  `NETWORK_SEEDS` is `https://rpc.tenzro.com`.
- `SdkConfigBuilder` without `chain_id` uses `network::NETWORK_CHAIN_ID`.
