# TenzroClaw

[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen)]()

The official [OpenClaw](https://github.com/anthropics/openclaw) skill for interacting with [Tenzro Network](https://tenzro.com) — a full blockchain and multi-chain toolkit for AI agents.

## Overview

TenzroClaw gives AI agents direct access to the Tenzro blockchain and 5 ecosystem chains (Solana, Ethereum, LayerZero, Chainlink, Canton) through a single Python script. Agents can create wallets, send transactions, manage identities, trade on marketplaces, deploy contracts, bridge tokens, swap on Jupiter, read Chainlink price feeds, and more.

**Live testnet:** `https://rpc.tenzro.network`

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
export TENZRO_RPC_URL=https://rpc.tenzro.network
export TENZRO_API_URL=https://api.tenzro.network
export TENZRO_RPC_TIMEOUT=120

# Ecosystem MCP endpoints (optional — defaults to live testnet)
export SOLANA_MCP_URL=https://solana-mcp.tenzro.network/mcp
export ETHEREUM_MCP_URL=https://ethereum-mcp.tenzro.network/mcp
export LAYERZERO_MCP_URL=https://layerzero-mcp.tenzro.network/mcp
export CHAINLINK_MCP_URL=https://chainlink-mcp.tenzro.network/mcp
export CANTON_MCP_URL=https://canton-mcp.tenzro.network/mcp
```

## Capabilities

### Tenzro Blockchain

**Authentication (OAuth 2.1 + DPoP):** `onboard_human`, `onboard_delegated_agent`, `onboard_autonomous_agent` (each provisions a TDIP identity, MPC wallet, and access + refresh tokens), `refresh_token` (exchange refresh → fresh access token), `link_wallet_for_auth` (mint an auth session against an existing wallet), `revoke_jwt`, `revoke_did`. Tokens follow RFC 6749 + RFC 9449 — pass `dpop_jkt` (RFC 7638 thumbprint of the holder's Ed25519 key) to bind the token to a holder key.

**Wallet & Transactions:** `create_wallet` (2-of-3 MPC, 32-byte address), `get_balance`, `send_transaction`, `list_accounts`

**Identity (TDIP):** `register_identity`, `resolve_did`, `set_username`, `resolve_username`, `import_identity`, `list_identities`

**AI Models & Inference:** `list_models`, `chat`, `inference_request`, `serve_model`, `stop_model`, `download_model`, `list_model_endpoints`

**Multi-Modal Inference (19 wrappers across 7 modalities):**
- **Forecast** — `list_forecast_catalog`, `list_forecast_models`, `load_forecast_model`, `forecast` (Chronos-2, Chronos-Bolt, TimesFM 2.5, Granite-TTM-r2)
- **Vision** — `list_vision_catalog`, `vision_embed`, `vision_similarity` (CLIP, SigLIP2, DINOv3)
- **Text Embedding** — `list_text_embedding_catalog`, `text_embed` (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic)
- **Segmentation** — `list_segmentation_catalog`, `segment` (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM)
- **Detection** — `list_detection_catalog`, `detect` (RF-DETR, D-FINE)
- **Audio (ASR)** — `list_audio_catalog`, `transcribe` (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary)
- **Video** — `list_video_catalog`, `video_embed` (encoder scaffolding — wave 1 catalog empty)

**Token Registry:** `create_token`, `list_tokens`, `get_token_info`, `get_token_balance`, `wrap_tnzo`, `cross_vm_transfer`, `deploy_contract`

**Task & Agent Marketplace:** `list_tasks`, `post_task`, `get_task`, `cancel_task`, `list_agent_templates`, `register_agent_template`, `spawn_agent_template`

**Staking & Governance:** `stake`, `unstake`, `list_proposals`, `vote`, `get_voting_power`, `register_provider`

**Settlement & Payments:** `settle`, `get_settlement`, `create_escrow`, `release_escrow`, `refund_escrow`, `get_escrow`, `open_payment_channel`, `pay_mpp`, `pay_x402` — escrow `create`/`release`/`refund` are signed `CreateEscrow`/`ReleaseEscrow`/`RefundEscrow` transactions submitted via `tenzro_signAndSendTransaction` (consensus-mediated, payer-only authorization)

**Bridge & Cross-Chain:** `bridge_tokens`, `bridge_quote`, `get_bridge_routes`, `list_bridge_adapters`

**Network & Node:** `node_status`, `node_info`, `get_block_number`, `get_block`, `peer_count`, `syncing`

**Cryptography:** `sign_message`, `verify_signature`, `encrypt_data`, `decrypt_data`, `derive_key`, `generate_keypair`, `hash_sha256`, `hash_keccak256`, `x25519_key_exchange`

**TEE Security:** `detect_tee`, `get_tee_attestation`, `verify_tee_attestation`, `seal_data`, `unseal_data`, `list_tee_providers`

### Ecosystem MCP Servers

**Solana (14 tools):** `solana_swap`, `solana_get_price`, `solana_stake`, `solana_get_yield`, `solana_get_balance`, `solana_get_token_accounts`, `solana_transfer`, `solana_get_token_info`, `solana_get_nft`, `solana_get_nfts_by_owner`, `solana_get_slot`, `solana_get_tps`, `solana_get_transaction`, `solana_resolve_domain`

**Ethereum (16 tools):** `eth_get_price_chainlink`, `eth_get_gas_price_ext`, `eth_estimate_gas_ext`, `eth_get_fee_history`, `eth_get_erc20_balance`, `eth_get_tx`, `eth_get_block_info`, `eth_get_receipt`, `eth_resolve_ens`, `eth_lookup_ens`, `eth_call_contract`, `eth_encode_function`, `eth_register_agent_8004`, `eth_lookup_agent_8004`, `eth_get_attestation`

**LayerZero (20 tools):** `lz_quote_fee`, `lz_send_message`, `lz_track_message`, `lz_get_message`, `lz_oft_quote`, `lz_oft_send`, `lz_oft_list`, `lz_encode_options`, `lz_transfer_quote`, `lz_transfer_build`, `lz_transfer_status`, `lz_transfer_chains`, `lz_transfer_tokens`, `lz_stargate_quote`, `lz_stargate_send`, `lz_get_deployments`, `lz_list_dvns`, `lz_get_messages_by_address`, `lz_list_chains`, `lz_get_chain_rpc`

**Chainlink (20 tools):** `ccip_get_fee`, `ccip_send_message`, `ccip_track_message`, `ccip_get_supported_chains`, `ccip_get_supported_tokens`, `ccip_get_lanes`, `ccip_get_token_pool`, `ccip_get_rate_limits`, `chainlink_get_price`, `chainlink_list_feeds`, `ds_get_report`, `ds_list_feeds`, `vrf_request_random`, `vrf_get_subscription`, `por_get_reserve`, `por_list_feeds`, `chainlink_check_upkeep`, `chainlink_get_upkeep_info`, `chainlink_estimate_functions_cost`, `chainlink_get_subscription`

**Canton (14 tools):** `canton_submit_command`, `canton_list_contracts`, `canton_get_events`, `canton_get_transaction`, `canton_allocate_party`, `canton_list_parties`, `canton_list_domains_ext`, `canton_get_health`, `canton_get_balance_ext`, `canton_transfer`, `canton_create_asset`, `canton_dvp_settle`, `canton_upload_dar`, `canton_get_fee_schedule`

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

47 tests covering wallet, identity, verification, tokens, marketplace, staking, and more.

## Architecture

```
Your Agent
    |
    |-- python3 tenzro_rpc.py <command> [args...]
    |
    v
tenzro_rpc.py
    |
    |-- JSON-RPC POST ---------> rpc.tenzro.network    (Tenzro blockchain)
    |-- HTTP POST/GET ---------> api.tenzro.network    (verification, faucet)
    |-- MCP Streamable HTTP ---> solana-mcp.tenzro.network   (Solana)
    |                         -> ethereum-mcp.tenzro.network (Ethereum)
    |                         -> layerzero-mcp.tenzro.network (LayerZero)
    |                         -> chainlink-mcp.tenzro.network (Chainlink)
    |                         -> canton-mcp.tenzro.network   (Canton)
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
| JSON-RPC | `https://rpc.tenzro.network` |
| Web API | `https://api.tenzro.network` |

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## License

Apache 2.0. See [LICENSE](LICENSE).
