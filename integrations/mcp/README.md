# Tenzro MCP Server

The official [Model Context Protocol](https://modelcontextprotocol.io) server for [Tenzro Network](https://tenzro.com) — giving AI agents direct access to blockchain operations, token management, cross-chain bridges, NFTs, identity, compliance, event streaming, and more.

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-2025--11--25-blue)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

## Overview

The Tenzro MCP server is an installable Python package that exposes blockchain and multi-modal AI tools across 19+ categories to any MCP-compatible AI agent (Claude, GPT, Cursor, Windsurf, etc.) via **stdio** or **Streamable HTTP** transport. Install with `pip install tenzro-mcp-server` and run locally, or connect directly to the live testnet endpoint. Agents can query balances, send transactions, mint NFTs, bridge tokens, check compliance, subscribe to events, run timeseries forecasts, embed images and text, segment and detect objects, transcribe audio, and interact with AI models — all through the standard MCP tool interface.

The companion Tenzro Rust node MCP server (`crates/tenzro-node/src/mcp/server.rs`) registers **414 tools** (Tenzro Ledger + multi-modal AI + AgentBond/insurance + agent memory) and is the authoritative tool inventory; this Python distributable exposes a comparable subset over stdio + Streamable HTTP.

**Testnet endpoint:** `https://mcp.tenzro.network/mcp`
**Local:** `http://localhost:3001/mcp`

## Installation

```bash
pip install tenzro-mcp-server
```

Or from source:

```bash
git clone https://github.com/tenzro/tenzro-network.git
cd integrations/mcp
pip install .
```

## Quick Start

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

**Option A: Connect to live testnet**

```json
{
  "mcpServers": {
    "tenzro": {
      "url": "https://mcp.tenzro.network/mcp"
    }
  }
}
```

**Option B: Run locally**

```json
{
  "mcpServers": {
    "tenzro": {
      "command": "tenzro-mcp-server"
    }
  }
}
```

### Claude Code

Add to your project's `.mcp.json`:

**Option A: Connect to live testnet**

```json
{
  "mcpServers": {
    "tenzro": {
      "type": "url",
      "url": "https://mcp.tenzro.network/mcp"
    }
  }
}
```

**Option B: Run locally**

```json
{
  "mcpServers": {
    "tenzro": {
      "type": "stdio",
      "command": "tenzro-mcp-server"
    }
  }
}
```

### Cursor / Windsurf / Other MCP Clients

**Option A: Connect to live testnet**
- **Name:** tenzro
- **Transport:** Streamable HTTP
- **URL:** `https://mcp.tenzro.network/mcp`

**Option B: Run locally**
- **Name:** tenzro
- **Command:** `tenzro-mcp-server`

Or with Streamable HTTP transport:
- **URL:** `http://localhost:3001/mcp`
- Start the server first: `tenzro-mcp-server --transport http --port 3001`

## Available Tools

The server exposes a Python subset across the categories below. The authoritative tool inventory lives on the Rust server (`crates/tenzro-node/src/mcp/server.rs`); consult that source for the complete list.

### Authentication (OAuth 2.1 + DPoP + AAP)

The Tenzro Agent Access Protocol (AAP) layers seven `aap_*` claims on top of OAuth 2.1, DPoP-bound JWTs (RFC 9449), and Rich Authorization Requests (RFC 9396).

- `onboard_human` — Provision a `did:tenzro:human:*` identity, FROST-Ed25519 threshold wallet, and access + refresh tokens (RFC 6749 + RFC 9449).
- `onboard_delegated_agent` — Issue an agent identity bound to a controller DID with a delegation scope.
- `onboard_autonomous_agent` — Issue a fully autonomous agent identity backed by a TNZO bond.
- `refresh_token` — Exchange a refresh token for a fresh access token (refresh tokens are not rotated in V1).
- `link_wallet_for_auth` — Mint a fresh access + refresh token pair against an existing FROST-Ed25519 threshold wallet.
- `revoke_jwt` / `revoke_did` — Revoke a single JWT by `jti` or cascade-invalidate every JWT minted under a DID.
- `oauth_discovery` — RFC 8414 Authorization Server Metadata discovery document.
- `exchange_token` — RFC 8693 OAuth 2.0 Token Exchange for delegated/impersonation flows.
- `introspect_token` — RFC 7662 OAuth 2.0 Token Introspection.

Pass `dpop_jkt` (RFC 7638 thumbprint of the holder's Ed25519 public key) to bind the issued token — every subsequent privileged call must then carry a fresh DPoP proof signed by the same key.

### Wallet & Balance (6 tools)

- `get_balance` — Get TNZO balance in wei
- `create_wallet` — Provision a chain-agnostic 2-of-3 FROST-Ed25519 (RFC 9591) threshold wallet (no seed phrase). Tenzro wallets are not per-chain — a single wallet projects into EVM, SVM, and Canton via the pointer-token model, so there is no `chain` parameter. Use `cross_vm_transfer` / `wrap_tnzo` for VM-specific operations and the bridge tools (`bridge_tokens`, deBridge, Wormhole, Li.Fi) for sends to external chains.
- `send_transaction` — Send TNZO transfer via server-side `tenzro_signAndSendTransaction` (live nonce + gas-price lookup; accepts `value` or `amount` alias; rejects self-sends with `cannot transfer to self`)
- `request_faucet` — Request 100 testnet TNZO (24h cooldown)
- `token_balance` — Get TNZO balance via token subsystem
- `total_supply` — Get total TNZO supply

### Node & Blocks (4 tools)

- `get_node_status` — Node health, block height, peers, uptime, role
- `get_block` — Get block by height with transactions
- `get_block_range` — Batch-fetch a contiguous range of blocks for catch-up sync (max 256/call; returns `nextHeight` + `moreAvailable` for pagination)
- `get_transaction` — Look up transaction by hash. Resolves from finalized storage first, then falls back to the consensus mempool: `status` is `"pending"` while in-mempool and `"finalized"` once block-included, so callers polling immediately after broadcast can distinguish "not yet finalized" from "unknown hash"

### Identity (5 tools)

- `register_identity` — Register human or machine DID via TDIP
- `resolve_did` — Resolve DID to identity info and delegation scope
- `set_delegation_scope` — Set spending limits and allowed operations for machine DID
- `set_username` — Set human-readable username for a DID
- `resolve_username` — Resolve username to DID

### Payments (8 tools)

- `create_payment_challenge` — Create MPP, x402, or native payment challenge
- `verify_payment` — Verify payment credential and settle on-chain
- `list_payment_protocols` — List supported payment protocols
- `list_x402_schemes` — Discover registered x402 scheme adapters (`exact`, `permit2`, plus any pluggable extensions)
- `settle_payment` — Execute immediate settlement
- `create_escrow` — Build & sign a `CreateEscrow` transaction (consensus-mediated, gas: 75,000). VM derives `escrow_id` and locks funds at a derived vault address.
- `release_escrow` — Build & sign a `ReleaseEscrow` transaction (payer-only, gas: 60,000)
- `refund_escrow` — Build & sign a `RefundEscrow` transaction (after expiry, payer-only, gas: 50,000)
- `get_escrow` — Read an escrow record by id (calls `tenzro_getEscrow`)
- `open_payment_channel` — Open micropayment channel
- `close_payment_channel` — Close payment channel with final balance

### AP2 v0.2 (Agent Payments Protocol)

- `ap2_sign_mandate` — Sign a `checkout` or `payment` mandate. The wallet bound to `signer_did` signs the canonical preimage with its Ed25519 key. Only AP2 v0.2 `"ed25519"` alg is supported.
- `ap2_verify_mandate` — Verify a single Verifiable Digital Credential (VDC) envelope (intent or cart mandate)
- `ap2_validate_mandate_pair` — Three-axis validation of an intent → cart mandate pair: AP2 mandate-level constraints + TDIP `DelegationScope` (`enforce_operation`) + runtime `SpendingPolicy` (`SpendingPolicySnapshot::check`)
- `ap2_protocol_info` — AP2 protocol metadata and supported features

### Stripe SPT (SharedPaymentToken)

- `spt_issue` — Issue a SharedPaymentToken bound to a principal/agent DID pair. The node-side `SptCeilingResolver` cross-checks the requested cap against the principal's `DelegationScope` and runtime `SpendingPolicy` before signing.
- `spt_verify` — Verify SPT signature, principal/agent DID activity, and remaining cap.

### ERC-8004 v0.6+ Trustless Agents Registry (cross-VM trio)

IdentityRegistry: `erc8004_encode_register` (no-arg overload), `erc8004_encode_register_with_uri` (`register(string)` overload), `erc8004_encode_register_with_metadata` (`register(string,(string,bytes)[])` overload), `erc8004_encode_get_agent`, `erc8004_decode_get_agent`, `erc8004_encode_set_agent_uri`, `erc8004_encode_set_agent_wallet`, `erc8004_encode_set_metadata`, `erc8004_encode_get_metadata`, `erc8004_decode_get_metadata`, `erc8004_encode_get_agent_uri`, `erc8004_encode_get_agent_wallet`.

ReputationRegistry: `erc8004_encode_feedback`, `erc8004_encode_get_feedback`, `erc8004_encode_get_feedback_count`, `erc8004_encode_revoke_feedback`, `erc8004_encode_is_feedback_revoked`, `erc8004_encode_append_response`, `erc8004_encode_get_feedback_responses`.

ValidationRegistry: `erc8004_encode_validation_request`, `erc8004_encode_validation_response`, `erc8004_encode_get_validation`.

The MCP encoder tools above produce **EVM** calldata, byte-identical to the native EVM precompiles `0x101a` / `0x101b` / `0x101c`. They target the canonical OpenZeppelin-ERC721 upgradeable proxies deployed at genesis at `tenzro_identity::erc8004::addresses::{IDENTITY_REGISTRY, REPUTATION_REGISTRY, VALIDATION_REGISTRY}`. Encoder tools accept `agent_id` as a JSON number, decimal string, or 0x-prefixed hex word (rejected if it exceeds `u64::MAX`).

The same registration semantics are mirrored to two non-EVM backends from a single TDIP `register_machine_with_fee` write — neither path is callable via MCP encoder tools (calldata is VM-native):

- **SVM mirror**: QuantuLabs Anchor program (`https://github.com/QuantuLabs/erc-8004-svm`). `tenzro-identity::erc8004_svm` builds Anchor-formatted instruction calldata; the node mirror buffers payloads under `erc8004_svm_pending_tx:` in RocksDB and indexes DID → 32-byte Pubkey under `erc8004_svm_did_index:`. Operator drains the queue to a Solana RPC.
- **DAML mirror**: Tenzro-authored Canton package at `vendor/erc8004-daml/daml/Tenzro/Erc8004/{Identity,Reputation,Validation}.daml`. `tenzro-identity::erc8004_daml` emits Canton Ledger JSON API v2 `submit-and-wait` commands as `serde_json::Value`; the node mirror buffers payloads under `erc8004_daml_pending_tx:` and indexes DID → 8-byte LE u64 agentId under `erc8004_daml_did_index:`. Opt-in: wired only when `NodeConfig.erc8004_daml` is present (package id = SHA-256 of compiled `.dar`, supplied by operator).

`agentId` is server-allocated by each backing registry (sequential `uint256` on EVM, 32-byte Pubkey on SVM, 8-byte LE u64 on DAML) — never derivable client-side.

### Identity (right-to-erasure)

- `forget_identity` — GDPR Article 17 right-to-erasure. Hard-deletes a `Revoked` DID from the registry and persistent storage. The DID must already be in `Revoked` status; call `revoke_identity` first and allow the cascading broadcaster to propagate.

### AI Models (10 tools)

- `list_models` — List available AI models
- `chat_completion` — Send chat completion request
- `list_model_endpoints` — List model service endpoints. Each endpoint carries `iroh_endpoint_id`, the hex iroh `EndpointId` of the serving node (empty for local-only services); cross-node inference routes to it over the `tenzro/infer` ALPN.
- `discover_models` — Discover models on network
- `download_model` — Download model from registry
- `serve_model` — Start serving a model. Auto-clusters when one host cannot hold the model: reads the GGUF header for layer count and hidden dimension, discovers LAN members from gossiped `ClusterProfile` announcements, and runs a layer-wise pipeline across them. Pass `force_single` to keep it on one host, or `cluster_members` to override discovery.
- `stop_model` — Stop serving a model
- `delete_model` — Delete a downloaded model
- `get_download_progress` — Check model download progress
- `list_providers` — List registered providers

### Multi-Modal AI (24 tools)

Per-modality `list_*_catalog`, `list_*_models`, `load_*_model`, `unload_*_model`, plus the modality verb. Catalogs draw from `OnnxForecastEntry`, `OnnxVisionEntry`, `OnnxTextEmbeddingEntry`, `OnnxSegmentationEntry`, `OnnxDetectionEntry`, `OnnxAudioEntry`, and `OnnxVideoEntry` in `tenzro-model`. License-tier gating (Permissive / Attribution / CommercialCustom / NonCommercial) is enforced at load time.

- **Forecast** — `list_forecast_catalog`, `list_forecast_models`, `load_forecast_model`, `unload_forecast_model`, `forecast` (TimesFM 2.5 200M)
- **Vision** — `list_vision_catalog`, `list_vision_models`, `load_vision_model`, `unload_vision_model`, `vision_embed`, `vision_similarity` (CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2)
- **Text Embedding** — `list_text_embedding_catalog`, `list_text_embedding_models`, `load_text_embedding_model`, `unload_text_embedding_model`, `text_embed` (Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0)
- **Segmentation** — `list_segmentation_catalog`, `list_segmentation_models`, `load_segmentation_model`, `unload_segmentation_model`, `segment` (SAM 3 / 3.1, SAM 2 base/large, EdgeSAM, MobileSAM)
- **Detection** — `list_detection_catalog`, `list_detection_models`, `load_detection_model`, `unload_detection_model`, `detect` (RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x)
- **Audio (ASR)** — `list_audio_catalog`, `list_audio_models`, `load_audio_model`, `unload_audio_model`, `transcribe` (Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash)
- **Video** — `list_video_catalog`, `list_video_models`, `load_video_model`, `unload_video_model`, `video_embed` (native catalog empty; pooled-vision fallback via DINOv3 / SigLIP2 / CLIP through `VisionFallbackVideoEncoder`)

### Staking & Governance (7 tools)

- `stake_tokens` — Stake TNZO as Validator, ModelProvider, or TeeProvider
- `unstake_tokens` — Unstake TNZO (initiates unbonding)
- `register_provider` — Register as network provider
- `get_provider_stats` — Get provider statistics
- `list_proposals` — List active governance proposals
- `vote_on_proposal` — Vote on a proposal (for/against/abstain)
- `get_voting_power` — Get voting power based on staked TNZO

### Bridge (5 tools)

- `bridge_tokens` — Bridge tokens via LayerZero, CCIP, or deBridge
- `get_bridge_routes` — Get available routes with fees and timing
- `list_bridge_adapters` — List bridge adapters
- `bridge_quote` — Get bridge fee quote
- `bridge_with_hook` — Bridge with post-delivery hook

### Tokens (7 tools)

- `create_token` — Create ERC-20 token via factory
- `get_token_info` — Look up token by symbol, address, or ID
- `list_tokens` — List registered tokens
- `deploy_contract` — Deploy bytecode to EVM/SVM/DAML
- `cross_vm_transfer` — Atomic cross-VM token transfer
- `wrap_tnzo` — Wrap native TNZO to VM representation
- `get_token_balance` — Get TNZO balance across all VMs

### Tasks (7 tools)

- `post_task` — Post task to marketplace
- `list_tasks` — List tasks by type or status
- `get_task` — Get task details
- `quote_task` — Submit price quote for a task
- `assign_task` — Assign task to agent
- `complete_task` — Mark task complete with result
- `cancel_task` — Cancel a task

### Agents (9 tools)

- `register_agent` — Register AI agent with capabilities
- `send_agent_message` — Send inter-agent message via A2A
- `spawn_agent` — Spawn child agent
- `create_swarm` — Create multi-agent swarm
- `get_swarm_status` — Get swarm status
- `terminate_swarm` — Terminate swarm
- `list_agents` — List all registered agents
- `get_agent_info` — Get agent details
- `deregister_agent` — Deregister an agent

### Agent Templates (7 tools)

- `register_agent_template` — Register reusable template
- `list_agent_templates` — List available templates
- `get_agent_template` — Get template details
- `search_agent_templates` — Search by name or description
- `spawn_from_template` — Spawn agent from template
- `rate_template` — Rate template (1-5 stars)
- `get_template_stats` — Get template usage stats

### NFTs (6 tools)

- `create_nft_collection` — Create ERC-721 or ERC-1155 collection
- `mint_nft` — Mint NFT in collection
- `transfer_nft` — Transfer NFT ownership
- `get_nft_info` — Query collection or token info
- `list_nft_collections` — List NFT collections
- `register_nft_pointer` — Register cross-VM NFT pointer

### Compliance (3 tools)

- `check_compliance` — Check if transfer is compliant
- `register_compliance` — Register compliance rules
- `freeze_address` — Freeze address for compliance

### Canton / DAML (Canton 3.5+ JSON Ledger API)

Reads:
- `canton_list_domains` — List Canton synchronization domains the node is configured against
- `canton_list_contracts` — Active-contracts query with `template_ids` filter (Canton 3.5+ requires a non-empty filter; the node attaches the resolved FQ party id automatically)
- `canton_list_parties` — `GET /v2/parties/known`
- `canton_list_packages` — `GET /v2/packages` — installed DAR package ids
- `canton_health` — combined `/livez` + `/readyz` + `/v2/version` probe
- `canton_version` — `GET /v2/version` — participant version + CIP feature flags (verified Canton 3.5.1)
- `canton_get_my_user` — Canton user record for the calling principal (CIP-26 User Management)
- `canton_coin_balance` — CIP-56 Canton Coin balance (sums every `Splice.Amulet:Amulet` contract the party signs)
- `canton_fee_schedule` — latest `Splice.AmuletRules:AmuletRules` active contract
- `canton_connected_synchronizers` — `GET /v2/state/connected-synchronizers` — currently-subscribed synchronizers with permission classes
- `canton_get_transaction` — `GET /v2/updates/transaction-tree-by-id/{hex}?requestingParties=...`
- `canton_get_events` — events for a specific contract id

Writes:
- `canton_submit_command` — DAML `create` / `exercise` via the JSON Ledger API submit-and-wait path. When the presenting API key carries a bound `canton_user_id`, the node forwards `actAs` as that user's `primaryParty`, scoping the submission to the tenant. Canton's AuthService enforces per-user CanActAs rights server-side.
- `canton_allocate_party` — `POST /v2/parties` — returns the fully-qualified party id `<hint>::<participant-hash>`
- `canton_grant_user_rights` — `POST /v2/users/{userId}/rights` — grant CanActAs / CanReadAs on a party to a tenant's user (CIP-26). Required before a newly-allocated party can be acted on.
- `canton_list_user_rights` — `GET /v2/users/{userId}/rights` — inspect what a tenant can act/read as.
- `canton_upload_dar` — DAR upload via `POST /v2/packages` with a single `Content-Type: application/octet-stream` header (Canton 3.5+ rejects duplicates). Legacy `/admin/packages/upload-dar` is NOT used — that's gRPC-only and not exposed on the Tenzro-operated DevNet.

Per-tenant analytics:
- `canton_get_my_analytics` — Subject self-read: per-tenant call counters for the API key configured on this client. Returns `{key_id, canton_user_id, calls_total, errors_total, calls_by_method, errors_by_method, first_seen_at, last_called_at}`.
- `canton_list_api_key_analytics` — Operator admin-read: every tenant's counters (admin-token-gated). Optional `key_id` filter.

### Verification (2 tools)

- `verify_zk_proof` — Verify Plonky3 STARK proof over the KoalaBear field; requires `circuit_id` ∈ {inference, settlement, identity} and 4-byte LE field-chunk public inputs
- `get_provenance` — Resolve the cached synthetic-content provenance manifest (EU AI Act Art. 50(2)) for AI-generated output by its 32-byte hex `content_hash`; errors when no manifest is cached for that hash

### Tenzro Train (1 tool)

- `get_trainer_daemon_status` — Report the node's trainer auto-provisioning daemon: running state, trainer DID, live trainer subprocess count, and concurrent-trainer ceiling

### Events (3 tools)

- `get_events` — Query historical events
- `subscribe_events` — Subscribe to real-time events
- `register_webhook` — Register webhook for notifications

### Join (1 tool)

- `join_as_participant` — Join network as MicroNode

### Skills Registry (5 tools)

- `list_skills` — List registered skills
- `register_skill` — Register new skill
- `search_skills` — Search by keyword or tag
- `get_skill` — Get skill details
- `use_skill` — Invoke a skill

### Tools Registry (5 tools)

- `list_registered_tools` — List registered MCP tools
- `register_tool` — Register MCP server endpoint
- `search_tools` — Search tools by keyword
- `get_tool_info` — Get tool details
- `use_registered_tool` — Invoke a registered tool

### Hardware (1 tool)

- `get_hardware_profile` — Detect hardware capabilities

### Usage (2 tools)

- `get_skill_usage` — Get skill usage statistics
- `get_tool_usage` — Get tool usage statistics

### Crypto (9 tools)

- `sign_message` — Sign message with Ed25519 or Secp256k1
- `verify_signature` — Verify signature
- `encrypt_data` — AES-256-GCM encryption
- `decrypt_data` — AES-256-GCM decryption
- `derive_key` — Derive child key from seed
- `generate_keypair` — Generate new keypair
- `hash_sha256` — Compute SHA-256 hash
- `hash_keccak256` — Compute Keccak-256 hash
- `x25519_key_exchange` — X25519 Diffie-Hellman key exchange

### TEE (6 tools)

- `detect_tee` — Detect available TEE hardware
- `get_tee_attestation` — Get TEE attestation quote
- `verify_tee_attestation_rpc` — Verify attestation quote
- `seal_data` — Seal data inside TEE enclave
- `unseal_data` — Unseal TEE-sealed data
- `list_tee_providers` — List registered TEE providers

### ZK (2 tools)

- `create_zk_proof` — Create a Plonky3 STARK proof over KoalaBear (`inference`, `settlement`, `identity` circuits)
- `list_zk_circuits` — List available ZK circuits

### Custody (9 tools)

- `create_mpc_wallet` — Create FROST-Ed25519 (RFC 9591) threshold wallet
- `export_keystore` — Export encrypted keystore
- `import_keystore` — Import from keystore
- `get_key_shares` — Get FROST-Ed25519 secret share configuration
- `rotate_keys` — Rotate FROST-Ed25519 secret shares
- `set_spending_limits` — Set daily and per-tx limits
- `get_spending_limits` — Get spending limits and usage
- `authorize_session` — Create time-limited session key
- `revoke_session` — Revoke active session key

### App (6 tools)

- `register_app` — Register app for custody services
- `create_user_wallet` — Create custodial wallet for app user
- `fund_user_wallet` — Fund user wallet from app treasury
- `list_user_wallets` — List app's user wallets
- `sponsor_transaction` — Sponsor transaction (app pays gas)
- `get_usage_stats` — Get app usage statistics

### Contract Encoding (2 tools)

- `encode_function` — ABI-encode smart contract function call
- `decode_result` — ABI-decode return data

### Streaming (2 tools)

- `chat_stream` — Stream chat completion token by token
- `subscribe_events_stream` — Subscribe to events via streaming

### AgentBond & Insurance (3 tools)

- `post_agent_bond` — Bond TNZO collateral against an autonomous agent DID (Spec 9)
- `get_agent_bond` — Look up the current bond and any open insurance claims
- `file_insurance_claim` — File a claim against an agent's bond

### deBridge Cross-Chain (5 tools)

- `debridge_search_tokens` — Search tokens on deBridge DLN
- `debridge_get_chains` — Get supported chains
- `debridge_get_instructions` — Get operational instructions
- `debridge_create_tx` — Create cross-chain transaction
- `debridge_same_chain_swap` — Execute same-chain swap

### Capital Intent (regulated capital allocation)

- `capital_intent_open` — Open a signed Capital Intent (capital-markets analog of an AP2 Intent Mandate)
- `capital_intent_quote` — Solver submits a bid against an opened intent
- `capital_intent_assign` — Auto-rank by ERC-8004 reputation, price, ETA
- `capital_intent_execute` — Execute a leg
- `capital_intent_verify` — Verify a step
- `capital_intent_compensate` — Roll back a step
- `capital_intent_settle` — Release escrow to the payee
- `get_capital_intent` — Read intent state
- `submit_reserve_attestation` — 1:1 backing attestation
- `get_reserve` — Read latest reserve attestation
- `attested_mint` — Token issuance gated by a fresh reserve attestation

### Multi-party workflows

- `workflow_open` — Declare a saga workflow with ordered steps
- `workflow_step_execute` — Transition step Pending → Executing (with optional per-step escrow)
- `workflow_step_verify` — Verify a step's outcome
- `workflow_step_compensate` — Roll back a step
- `workflow_finalize` — Emit on-chain WorkflowReceipt
- `workflow_mirror_to_canton` — Mirror to a Canton synchronizer for DAML reconciliation
- `verify_did_envelope` — Verify a DID-signed step payload
- `get_workflow`, `get_workflow_saga`, `get_workflow_lifecycle`, `get_workflow_receipt`, `get_workflow_operational_metrics`
- `list_workflows_by_creator`, `list_workflows_by_participant`, `list_workflows_by_status`, `list_workflow_receipts`

### EVM-side primitives (EIP-7702 / Permit2 / Secure-Mint)

- `install_7702_delegation`, `get_7702_delegation`, `revoke_7702_delegation` — Pectra Type-4 authority → target delegation registry
- `permit2_domain_separator`, `permit2_digest`, `permit2_verify_and_consume`, `permit2_nonce_used` — Permit2 SignatureTransfer (optional witness for ERC-7683 origin opens)
- `set_secure_mint_policy`, `get_secure_mint_policy`, `clear_secure_mint_policy`, `secure_mint_check`, `secure_mint_apply`, `secure_mint_record_burn`, `set_secure_mint_paused`, `set_global_issuance_pause` — per-token 1:1 reserve-attestation invariant for tokenized RWAs (token-keyed; fail-closed gate order with freshness/heartbeat/velocity guards; per-token + global issuance circuit breakers)

### Chain-agnostic discovery (CAIP)

- `caip2`, `caip10`, `caip19` — Canonical Tenzro CAIP identifiers per the submitted `tenzro` namespace spec (`ChainAgnostic/namespaces#184`). CAIP-2 reference is the lowercase hex of the first 16 bytes of the genesis block hash; CAIP-19 supports `slip44` / `token` / `nft` asset namespaces.

### ERC-7683 cross-chain intents

- `open_7683_order`, `get_7683_order`, `list_7683_orders` — Origin-side opener + reads
- `record_fill_7683`, `get_fill_7683`, `list_fills_7683` — Destination-side fill registry (idempotent)

### Decentralized Storage (6 tools)

- `storage_store_object` — Store an object with an erasure-coded redundancy scheme
- `storage_open_deal` — Open a streaming deal (renter pre-funds total epochs from deposit)
- `storage_charge_epoch` — Run one proof-of-retrievability-gated charge epoch
- `storage_get_deal` — Look up a storage deal by id
- `storage_set_pricing` — Set the byte-epoch pricing policy (fixed or network-dynamic)
- `storage_status` — Read this node's storage-provider status

### Compute Rental (5 tools)

- `compute_book_rental` — Book a rental (renter pre-funds total epochs from deposit)
- `compute_settle_epoch` — Settle one epoch, gated on the provider's availability proof
- `compute_get_rental` — Look up a compute rental by id
- `compute_set_pricing` — Set the per-epoch pricing policy (fixed or network-dynamic)
- `compute_status` — Read this node's compute-rental status

### Distributed MoE Serving (4 tools)

- `moe_shard_map` — Providers holding each (layer, expert), replication, hot / under-replicated experts, role counts
- `moe_plan_dispatch` — Build a dispatch plan from per-token top-k routing decisions
- `moe_replication_policy` — Read the governance-tuned replication policy
- `moe_catalog_shape` — Read the catalog-side MoE topology for a model

### Treasury Multisig (3 tools)

- `treasury_approve_withdrawal` — Approve a treasury withdrawal with a signed approval (Ed25519 or Secp256k1 over the `tenzro/treasury/withdrawal-approval` preimage)
- `treasury_execute_withdrawal` — Execute a withdrawal once approvals reach the threshold
- `treasury_get_pending_withdrawal` — Read a pending withdrawal: approvers, approvals, threshold

Treasury config mutations (add/remove withdrawer, threshold) are admin-token-gated RPCs reserved for the node operator and are not exposed as MCP tools.

### Local Discovery & LAN Clustering (4 tools)

- `local_peers` — Peers discovered on this node's local segment via mDNS
- `node_reachability` — Sustained connectivity tier (`direct` / `relay_only` / `unreachable`)
- `node_profile` — Hardware self-profile: build commit, CPU arch, OS, devices, derived serving capacity / backend / capability key
- `cluster_plan` — Deterministic layer-wise LAN cluster placement for a model across candidate members

## Ecosystem MCP Servers

In addition to the main Tenzro MCP server, the node runs specialized servers for direct blockchain interaction:

| Server | Port | Endpoint | Description |
|--------|------|----------|-------------|
| **Tenzro** | 3001 | `/mcp` | 414 tools — Tenzro Ledger + multi-modal AI (forecast, vision, text-embed, segmentation, detection, audio ASR, video) + AgentBond/insurance + agent memory |
| **Solana** | 3003 | `/mcp` | 14 tools — Jupiter swaps, SPL tokens, Metaplex NFTs, SNS, staking |
| **Ethereum** | 3004 | `/mcp` | 17 tools — Chainlink feeds, ENS, ERC-20, EAS, ERC-8004 |
| **Canton** | 3005 | `/mcp` | 15 tools — Canton 3.5+ JSON Ledger API (active-contracts queries with live offset + FQ party id, party / package / connected-synchronizer / version / health reads, CIP-56 Canton Coin balance, AmuletRules fee schedule, DAR upload via `/v2/packages`, submit-and-wait DAML commands, DvP settlement) |
| **LayerZero** | 3006 | `/mcp` | 21 tools — V2 messaging, OFT, Stargate V2, Value Transfer API |
| **Chainlink** | 3007 | `/mcp` | 21 tools — CCIP, data feeds, Data Streams, VRF v2.5, PoR, automation, Functions |
| **Li.Fi** | 3008 | `/mcp` | 9 tools — cross-chain aggregation, quotes, routes, status |

## Programmatic Usage

### TypeScript

```typescript
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const transport = new StreamableHTTPClientTransport(
  new URL("https://mcp.tenzro.network/mcp")
);
const client = new Client({ name: "my-app", version: "1.0.0" }, {});
await client.connect(transport);

// List all tools
const tools = await client.listTools();
console.log(`${tools.tools.length} tools available`);

// Check balance
const balance = await client.callTool({
  name: "get_balance",
  arguments: { address: "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68" },
});

// Mint an NFT
const nft = await client.callTool({
  name: "mint_nft",
  arguments: {
    collection_id: "0xabc...",
    to: "0x742d...",
    token_id: 1,
    uri: "ipfs://Qm...",
  },
});
```

### Python

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("https://mcp.tenzro.network/mcp") as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # List tools
        tools = await session.list_tools()
        print(f"{len(tools.tools)} tools available")

        # Check compliance before transfer
        compliance = await session.call_tool(
            "check_compliance",
            arguments={
                "token_id": "0xtoken...",
                "from": "0xsender...",
                "to": "0xrecipient...",
                "amount": "1000000",
            },
        )
```

### curl

```bash
# Initialize
curl -s -X POST https://mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1.0"}}}'

# List tools
curl -s -X POST https://mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# Call a tool
curl -s -X POST https://mcp.tenzro.network/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_node_status","arguments":{}}}'
```

## Running the Server

### stdio (Claude Desktop, Cursor)

```bash
tenzro-mcp-server
```

### Streamable HTTP

```bash
tenzro-mcp-server --transport http --port 3001
```

### Test the server

```bash
curl -s -X POST http://localhost:3001/mcp \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TENZRO_RPC_URL` | `https://rpc.tenzro.network` | Tenzro JSON-RPC endpoint |
| `TENZRO_API_URL` | `https://api.tenzro.network` | Tenzro Web API endpoint |

Command-line options:

| Flag | Default | Description |
|------|---------|-------------|
| `--transport` | `stdio` | Transport type (`stdio` or `http`) |
| `--port` | `3001` | HTTP server port (when using `http` transport) |
| `--host` | `0.0.0.0` | HTTP server bind address |

## Protocol Details

- **MCP Version:** 2025-11-25
- **Transport:** Streamable HTTP (stateless JSON mode)
- **Content Types:** `application/json`, `text/event-stream`
- **Framework:** [fastmcp](https://pypi.org/project/fastmcp/)

## Related

| Resource | URL |
|----------|-----|
| Tenzro Network | [tenzro.com](https://tenzro.com) |
| A2A Server | [github.com/tenzro/tenzro-network](https://github.com/tenzro/tenzro-network) |
| MCP Specification | [modelcontextprotocol.io](https://modelcontextprotocol.io) |

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## License

Apache 2.0. See [LICENSE](LICENSE).
