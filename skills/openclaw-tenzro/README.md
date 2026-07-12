# TenzroClaw

[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-123%20passed-brightgreen)]()

The official [OpenClaw](https://github.com/anthropics/openclaw) skill for interacting with [Tenzro Network](https://tenzro.com) — a full blockchain and multi-chain toolkit for AI agents.

## Overview

TenzroClaw gives AI agents direct access to the Tenzro blockchain and the ecosystem MCP servers (Solana, Ethereum, Canton, LayerZero, Chainlink, Li.Fi, plus external deBridge and 1inch) through a single Python script. Agents can create wallets, send transactions, manage identities, trade on marketplaces, deploy contracts, bridge tokens, swap on Jupiter, read Chainlink price feeds, run multi-modal AI inference, post AgentBonds, and more.

**Live testnet:** `https://rpc.tenzro.xyz`

## Quick Start

```bash
# Tenzro blockchain
python3 tools/tenzro_rpc.py node_status
python3 tools/tenzro_rpc.py create_wallet
python3 tools/tenzro_rpc.py register_identity human Alice
python3 tools/tenzro_rpc.py list_models
python3 tools/tenzro_rpc.py join Alice

# Solana
python3 tools/tenzro_rpc.py solana_get_slot
python3 tools/tenzro_rpc.py solana_get_tps
python3 tools/tenzro_rpc.py solana_resolve_domain toly.sol

# Ethereum
python3 tools/tenzro_rpc.py eth_get_gas_price_ext
python3 tools/tenzro_rpc.py eth_resolve_ens vitalik.eth
python3 tools/tenzro_rpc.py chainlink_get_price ETH/USD

# LayerZero
python3 tools/tenzro_rpc.py lz_list_chains
python3 tools/tenzro_rpc.py lz_list_dvns

# Chainlink
python3 tools/tenzro_rpc.py chainlink_list_feeds
python3 tools/tenzro_rpc.py ccip_get_supported_chains
```

## Installation

No installation required. Just clone and run:

```bash
git clone https://github.com/tenzro/TenzroClaw.git
cd TenzroClaw
python3 tools/tenzro_rpc.py --help
```

Optional: install `requests` for better HTTP handling (falls back to `urllib` if not available):

```bash
pip install requests
```

## Configuration

```bash
# Tenzro endpoints
export TENZRO_RPC_URL=https://rpc.tenzro.xyz
export TENZRO_API_URL=https://api.tenzro.xyz
export TENZRO_RPC_TIMEOUT=120

# Ecosystem MCP endpoints (optional — defaults to live testnet)
export SOLANA_MCP_URL=https://solana-mcp.tenzro.xyz/mcp
export ETHEREUM_MCP_URL=https://ethereum-mcp.tenzro.xyz/mcp
export LAYERZERO_MCP_URL=https://layerzero-mcp.tenzro.xyz/mcp
export CHAINLINK_MCP_URL=https://chainlink-mcp.tenzro.xyz/mcp
export CANTON_MCP_URL=https://canton-mcp.tenzro.xyz/mcp
export LIFI_MCP_URL=https://lifi-mcp.tenzro.xyz/mcp
```

## Capabilities

### Tenzro Blockchain

**Authentication (OAuth 2.1 + DPoP):** `onboard_human`, `onboard_delegated_agent`, `onboard_autonomous_agent` (each provisions a TDIP identity, FROST-Ed25519 threshold wallet, and access + refresh tokens), `refresh_token` (exchange refresh → fresh access token), `link_wallet_for_auth` (mint an auth session against an existing wallet), `revoke_jwt`, `revoke_did`. Tokens follow RFC 6749 + RFC 9449 — pass `dpop_jkt` (RFC 7638 thumbprint of the holder's Ed25519 key) to bind the token to a holder key.

**Wallet & Transactions:** `create_wallet` (chain-agnostic 2-of-3 FROST-Ed25519 (RFC 9591) threshold wallet — projects into EVM, SVM, and Canton via the pointer-token model, no `chain` parameter), `get_balance`, `send_transaction` (server-side `tenzro_signAndSendTransaction` with live nonce + gas-price lookup, accepts `value` or `amount` alias, rejects self-sends), `get_transaction` (returns `status: "pending"` while in-mempool, `"finalized"` once block-included), `list_accounts`

**Identity (TDIP):** `register_identity`, `resolve_did`, `set_username`, `resolve_username`, `import_identity`, `list_identities`

**AI Models & Inference:** `list_models`, `chat`, `inference_request`, `serve_model`, `stop_model`, `download_model`, `list_model_endpoints`, `get_provenance`. `serve_model` auto-clusters a model that exceeds one host — it reads the GGUF header for shape, discovers LAN members from gossiped `ClusterProfile` announcements, and runs a layer-wise pipeline; pass `force_cluster` to split even when it fits one host, `force_single` to pin it to one host, or `visibility="private"` to keep it local/LAN-only instead of gossiping it to the network. `list_model_endpoints` returns each service's `iroh_endpoint_id` (the serving node's iroh `EndpointId`, empty for local-only); cross-node inference routes to it over the `tenzro/infer` ALPN. `get_provenance` resolves the cached synthetic-content manifest (EU AI Act Art. 50(2)) for generated output by its `content_hash`.

**Multi-Modal Inference (17 wrappers across 7 modalities):**
- **Forecast** — `list_forecast_catalog`, `list_forecast_models`, `load_forecast_model`, `forecast` (TimesFM 2.5)
- **Vision** — `list_vision_catalog`, `vision_embed`, `vision_similarity` (CLIP, SigLIP2, DINOv3)
- **Text Embedding** — `list_text_embedding_catalog`, `text_embed` (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic)
- **Segmentation** — `list_segmentation_catalog`, `segment` (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM)
- **Detection** — `list_detection_catalog`, `detect` (RF-DETR, D-FINE)
- **Audio (ASR)** — `list_audio_catalog`, `transcribe` (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary)
- **Video** — `list_video_catalog`, `video_embed` (encoder scaffolding — catalog currently empty)

**Token Registry:** `create_token`, `list_tokens`, `get_token_info`, `get_token_balance`, `wrap_tnzo`, `cross_vm_transfer`, `deploy_contract`

**Task & Agent Marketplace:** `list_tasks`, `post_task`, `get_task`, `cancel_task`, `list_agent_templates`, `register_agent_template`, `spawn_agent_template`

**Staking & Governance:** `stake`, `unstake`, `list_proposals`, `vote`, `get_voting_power`, `register_provider`

**Settlement & Payments:** `settle`, `get_settlement`, `create_escrow`, `release_escrow`, `refund_escrow`, `get_escrow`, `prepaid_deposit`, `prepaid_withdraw`, `prepaid_balance`, `open_payment_channel`, `pay_mpp`, `pay_x402` — escrow `create`/`release`/`refund` are signed `CreateEscrow`/`ReleaseEscrow`/`RefundEscrow` transactions submitted via `tenzro_signAndSendTransaction` (consensus-mediated, payer-only authorization); `prepaid_*` fund, refund, and read the streaming balance that storage deals and compute rentals draw down per epoch

**x402 Bazaar (paid-resource discovery):** `x402_protocol_info`, `x402_register_resource`, `x402_discover_resources`, `x402_deregister_resource`, `x402_verify_offer`, `x402_payment_id`, `list_x402_schemes` — sellers register paid resources (listing id derived from `(seller_did, resource)`, so re-register is idempotent), buyers browse and verify offers before paying. Scheme adapters: `tenzro-hybrid` (default), `exact-eip3009`, `permit2`, `erc7710`.

**Bridge & Cross-Chain:** `bridge_tokens`, `bridge_quote`, `get_bridge_routes`, `list_bridge_adapters`. Adapter coverage spans LayerZero V2, Chainlink CCIP, deBridge DLN, Li.Fi aggregator, Wormhole NTT, Canton, Hyperlane V3 (sovereign Tenzro-validator-set ISM), Axelar GMP (Cosmos / Move / Stellar reach), and Babylon (Bitcoin staking finality-providers).

**Capital Intent (regulated capital allocation):** `capital_intent_open`, `capital_intent_quote`, `capital_intent_assign`, `capital_intent_execute`, `capital_intent_verify`, `capital_intent_compensate`, `capital_intent_settle`, `get_capital_intent`, `submit_reserve_attestation`, `get_reserve`, `attested_mint`.

**Multi-party Workflows (saga + AP2 / x402 / MPP mandate binding):** `workflow_open`, `workflow_step_execute`, `workflow_step_verify`, `workflow_step_compensate`, `workflow_finalize`, `workflow_mirror_to_canton`, `verify_did_envelope`, `get_workflow`, `get_workflow_saga`, `get_workflow_lifecycle`, `get_workflow_receipt`, `get_workflow_operational_metrics`, `list_workflows_by_creator`, `list_workflows_by_participant`, `list_workflows_by_status`, `list_workflow_receipts`.

**EVM Primitives (EIP-7702 / Permit2 / Secure-Mint):** `install_7702_delegation`, `get_7702_delegation`, `revoke_7702_delegation` (Pectra Type-4 delegation registry); `permit2_domain_separator`, `permit2_digest`, `permit2_verify_and_consume`, `permit2_nonce_used` (Permit2 `SignatureTransfer` with optional witness binding for ERC-7683 origin opens); `set_secure_mint_policy`, `get_secure_mint_policy`, `clear_secure_mint_policy`, `secure_mint_check`, `secure_mint_apply`, `secure_mint_record_burn`, `set_secure_mint_paused`, `set_global_issuance_pause` (per-token 1:1 reserve-attestation invariant for tokenized RWAs, token-keyed; fail-closed gate with freshness/heartbeat/velocity guards plus per-token + global issuance circuit breakers); `register_stable_asset`, `get_stable_asset`, `mint_stable_asset`, `redeem_stable_asset` (issuer-agnostic stable-unit issuance on the Secure-Mint reserve floor; register needs the `issuer` API-key scope).

**ERC-7683 Cross-Chain Intents:** `open_7683_order`, `get_7683_order`, `list_7683_orders`, `record_fill_7683`, `get_fill_7683`, `list_fills_7683`.

**CAIP Discovery:** `caip2`, `caip10`, `caip19` — Tenzro CAIP namespace identifiers (`ChainAgnostic/namespaces#184`). CAIP-2 reference is the lowercase hex of the first 16 bytes of the genesis block hash; CAIP-19 supports `slip44` (SLIP-44 coin index 1414421071), `token`, and `nft` asset namespaces.

**AgentBond & Insurance (Spec 9):** `post_agent_bond`, `increase_agent_bond`, `withdraw_agent_bond`, `get_agent_bond`, `list_agent_bonds`, `file_insurance_claim`, `get_insurance_claim`, `list_insurance_claims`, `get_insurance_pool`

**ERC-8004 Trustless Agents (cross-VM trio):** `register_8004_agent`, `lookup_8004_agent`, `submit_8004_feedback`, `request_8004_validation`, `submit_8004_validation`. Each `register_8004_agent` call fans out from one TDIP write to canonical EVM proxies (deployed at genesis), the QuantuLabs Anchor program on SVM, and the Tenzro-authored Canton package on DAML. `agentId` shape is per-backend: `uint256` on EVM, 32-byte Pubkey on SVM, 8-byte LE u64 on DAML.

**Network & Node:** `node_status`, `node_info`, `get_block_number`, `get_block`, `peer_count`, `syncing`

**Decentralized Storage:** `storage_store_object`, `storage_open_deal`, `storage_charge_epoch`, `storage_get_deal`, `storage_set_pricing`, `storage_status` — content-addressed objects on the data plane, byte-epoch deal billing gated by proof-of-retrievability.

**Compute Rental:** `compute_book_rental`, `compute_settle_epoch`, `compute_get_rental`, `compute_set_pricing`, `compute_status` — availability-proof-gated per-epoch settlement; a missed proof makes the renter whole from the provider's stake.

**Distributed MoE Serving:** `moe_shard_map`, `moe_plan_dispatch`, `moe_replication_policy`, `moe_catalog_shape` — expert-shard placement, top-k dispatch planning, and replication policy across providers.

**Tenzro Train Inspection:** `training_list_runs`, `training_get_run`, `training_get_receipt`, `training_get_sealed_manifest`, `get_trainer_daemon_status` — read-side view of decentralized training runs: run state per task, sealed receipts for finalized runs, Confidential-tier sealed-shard manifests, and the trainer auto-provisioning daemon's running state and live trainer count.

**Local Discovery & LAN Clustering:** `local_peers`, `node_reachability`, `node_profile`, `cluster_plan`, `cluster_preview` — same-segment peers via mDNS, the node's reachability tier, its hardware self-profile, and the layer-wise pipeline plan when a model needs more than one box. `cluster_preview` previews placement for a downloaded model from the node's live view (derives shape from the GGUF header, discovers LAN members) — no manual dimensions required; `cluster_plan` is the lower-level form taking explicit dimensions + a members list.

**Managed Databases:** `list_database_engines`, `create_database`, `get_database`, `list_databases`, `list_database_partitions`, `get_database_partition`, `issue_database_connection`, `database_query`, `authorize_database_read`, `rescale_database`, `drop_database` — an engine-agnostic protocol layer over persistent state. A node holds a thin stateless client to an operator-run engine (PostgreSQL / Qdrant / Valkey via URL config) or serves an embedded engine in-process (Lance / Tantivy); Milvus and Dgraph are catalog-only until a driver is linked. Placement is `local`, `lan_cluster`, or `network`; `database_query` bodies are per-engine dialects (SQL, vector search, full-text, command array).

**Cryptography:** `sign_message`, `verify_signature`, `encrypt_data`, `decrypt_data`, `derive_key`, `generate_keypair`, `hash_sha256`, `hash_keccak256`, `x25519_key_exchange`

**TEE Security:** `detect_tee`, `get_tee_attestation`, `verify_tee_attestation`, `seal_data`, `unseal_data`, `list_tee_providers`

### Ecosystem MCP Servers

**Solana (14 tools):** `solana_swap`, `solana_get_price`, `solana_stake`, `solana_get_yield`, `solana_get_balance`, `solana_get_token_accounts`, `solana_transfer`, `solana_get_token_info`, `solana_get_nft`, `solana_get_nfts_by_owner`, `solana_get_slot`, `solana_get_tps`, `solana_get_transaction`, `solana_resolve_domain`

**Ethereum (17 tools):** `eth_get_price_chainlink`, `eth_get_gas_price_ext`, `eth_estimate_gas_ext`, `eth_get_fee_history`, `eth_get_erc20_balance`, `eth_get_tx`, `eth_get_block_info`, `eth_get_receipt`, `eth_resolve_ens`, `eth_lookup_ens`, `eth_call_contract`, `eth_encode_function`, `eth_register_agent_8004`, `eth_lookup_agent_8004`, `eth_get_attestation`

**LayerZero (21 tools):** `lz_quote_fee`, `lz_send_message`, `lz_track_message`, `lz_get_message`, `lz_oft_quote`, `lz_oft_send`, `lz_oft_list`, `lz_encode_options`, `lz_transfer_quote`, `lz_transfer_build`, `lz_transfer_status`, `lz_transfer_chains`, `lz_transfer_tokens`, `lz_stargate_quote`, `lz_stargate_send`, `lz_get_deployments`, `lz_list_dvns`, `lz_get_messages_by_address`, `lz_list_chains`, `lz_get_chain_rpc`

**Chainlink (21 tools):** `ccip_get_fee`, `ccip_send_message`, `ccip_track_message`, `ccip_get_supported_chains`, `ccip_get_supported_tokens`, `ccip_get_lanes`, `ccip_get_token_pool`, `ccip_get_rate_limits`, `chainlink_get_price`, `chainlink_list_feeds`, `ds_get_report`, `ds_list_feeds`, `vrf_request_random`, `vrf_get_subscription`, `por_get_reserve`, `por_list_feeds`, `chainlink_check_upkeep`, `chainlink_get_upkeep_info`, `chainlink_estimate_functions_cost`, `chainlink_get_subscription`

**Canton (Canton 3.5+ JSON Ledger API)** — MCP-routed: `canton_submit_command`, `canton_list_contracts`, `canton_get_events`, `canton_get_transaction`, `canton_allocate_party`, `canton_list_parties`, `canton_grant_user_rights`, `canton_list_user_rights`, `canton_get_my_analytics`, `canton_list_api_key_analytics`, `canton_list_domains_ext`, `canton_get_health`, `canton_get_balance_ext`, `canton_transfer`, `canton_create_asset`, `canton_dvp_settle`, `canton_upload_dar`, `canton_get_fee_schedule`, `canton_reconnect_synchronizer`. **JSON-RPC wrappers** (route through `rpc.tenzro.xyz`, require a `canton`-scoped API key): `canton_health`, `canton_version`, `canton_list_packages`, `canton_get_my_user`, `canton_coin_balance`, `canton_connected_synchronizers`, `canton_upload_dar_rpc`, `canton_fee_schedule_rpc`, `canton_get_transaction_rpc`, `canton_allocate_party_rpc`, `canton_grant_user_rights`, `canton_list_user_rights`, `canton_get_my_analytics`, `canton_list_api_key_analytics`.

**Li.Fi (9 tools):** `lifi_get_quote`, `lifi_get_routes`, `lifi_get_status`, `lifi_get_chains`, `lifi_get_tokens`, `lifi_get_connections`, `lifi_get_tools`, `lifi_get_token_balance`, `lifi_execute_route`

See [SKILL.md](SKILL.md) for the complete reference with all commands and curl examples.

## Using with OpenClaw

```yaml
skills:
  - name: tenzroclaw
    source: github.com/tenzro/TenzroClaw
    tools:
      - tools/tenzro_rpc.py
```

## Tests

```bash
python3 -m unittest tools/test_tenzro_rpc.py -v
```

123 tests covering wallet, identity, verification, tokens, marketplace, staking, and more.

## Worked Examples

End-to-end runnable scripts against the live testnet:

```bash
# Task marketplace settlement cycle: post → quote → assign → complete,
# with on-chain TNZO transfer at completion and balance reconciliation.
python3 examples/agentic_workflow.py

# Multi-VM settlement: drives a native→evm transfer and asserts the
# pointer-model invariants across all four VM views (native, EVM
# wTNZO, SPL wTNZO, DAML holding).
python3 examples/multivm_settlement.py
```

Both scripts spawn fresh identities via `tenzro_joinAsMicroNode`, request faucet TNZO, then exercise real handlers — no fixtures.

## Architecture

```
Your Agent
    |
    |-- python3 tenzro_rpc.py <command> [args...]
    |
    v
tenzro_rpc.py
    |
    |-- JSON-RPC POST ---------> rpc.tenzro.xyz    (Tenzro blockchain)
    |-- HTTP POST/GET ---------> api.tenzro.xyz    (verification, faucet)
    |-- MCP Streamable HTTP ---> solana-mcp.tenzro.xyz   (Solana)
    |                         -> ethereum-mcp.tenzro.xyz (Ethereum)
    |                         -> canton-mcp.tenzro.xyz   (Canton)
    |                         -> layerzero-mcp.tenzro.xyz (LayerZero)
    |                         -> chainlink-mcp.tenzro.xyz (Chainlink)
    |                         -> lifi-mcp.tenzro.xyz     (Li.Fi)
    |
    v
Tenzro Network (decentralized) + External Chains
```

## Related

| Resource | URL |
|----------|-----|
| Tenzro Network | [tenzro.com](https://tenzro.com) |
| MCP Server | [github.com/tenzro/tenzro-mcp-server](https://github.com/tenzro/tenzro-mcp-server) |
| A2A Server | [github.com/tenzro/tenzro-a2a-server](https://github.com/tenzro/tenzro-a2a-server) |
| JSON-RPC | `https://rpc.tenzro.xyz` |
| Web API | `https://api.tenzro.xyz` |

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## License

Apache 2.0. See [LICENSE](LICENSE).
