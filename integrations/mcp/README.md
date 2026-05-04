# Tenzro MCP Server

The official [Model Context Protocol](https://modelcontextprotocol.io) server for [Tenzro Network](https://tenzro.com) — giving AI agents direct access to blockchain operations, token management, cross-chain bridges, NFTs, identity, compliance, event streaming, and more.

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![MCP](https://img.shields.io/badge/MCP-2024--11--05-blue)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

## Overview

The Tenzro MCP server is an installable Python package that exposes blockchain and multi-modal AI tools across 19+ categories to any MCP-compatible AI agent (Claude, GPT, Cursor, Windsurf, etc.) via **stdio** or **Streamable HTTP** transport. Install with `pip install tenzro-mcp-server` and run locally, or connect directly to the live testnet endpoint. Agents can query balances, send transactions, mint NFTs, bridge tokens, check compliance, subscribe to events, run timeseries forecasts, embed images and text, segment and detect objects, transcribe audio, and interact with AI models — all through the standard MCP tool interface.

The companion Tenzro Rust node MCP server (`crates/tenzro-node/src/mcp/server.rs`) registers **193 tools** (169 base + 24 multi-modal AI) including the multi-modal AI tools described below.

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

## Available Tools (146)

The server provides **153 tools** across 18+ categories (count verified against `@mcp.tool` decorators in `tenzro_mcp_server/server.py`):

### Authentication (OAuth 2.1 + DPoP + AAP)

The Tenzro Agent Access Protocol (AAP) layers seven `aap_*` claims on top of OAuth 2.1, DPoP-bound JWTs (RFC 9449), and Rich Authorization Requests (RFC 9396).

- `onboard_human` — Provision a `did:tenzro:human:*` identity, MPC wallet, and access + refresh tokens (RFC 6749 + RFC 9449).
- `onboard_delegated_agent` — Issue an agent identity bound to a controller DID with a delegation scope.
- `onboard_autonomous_agent` — Issue a fully autonomous agent identity backed by a TNZO bond.
- `refresh_token` — Exchange a refresh token for a fresh access token (refresh tokens are not rotated in V1).
- `link_wallet_for_auth` — Mint a fresh access + refresh token pair against an existing MPC wallet.
- `revoke_jwt` / `revoke_did` — Revoke a single JWT by `jti` or cascade-invalidate every JWT minted under a DID.
- `oauth_discovery` — RFC 8414 Authorization Server Metadata discovery document.
- `exchange_token` — RFC 8693 OAuth 2.0 Token Exchange for delegated/impersonation flows.
- `introspect_token` — RFC 7662 OAuth 2.0 Token Introspection.

Pass `dpop_jkt` (RFC 7638 thumbprint of the holder's Ed25519 public key) to bind the issued token — every subsequent privileged call must then carry a fresh DPoP proof signed by the same key.

### Wallet & Balance (6 tools)

- `get_balance` — Get TNZO balance in wei
- `create_wallet` — Provision a chain-agnostic 2-of-3 Ed25519 MPC wallet (no seed phrase). Tenzro wallets are not per-chain — a single wallet projects into EVM, SVM, and Canton via the pointer-token model, so there is no `chain` parameter. Use `cross_vm_transfer` / `wrap_tnzo` for VM-specific operations and the bridge tools (`bridge_tokens`, deBridge, Wormhole, Li.Fi) for sends to external chains.
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

### AP2 (Agent Payments Protocol)

- `ap2_verify_mandate` — Verify a single Verifiable Digital Credential (VDC) envelope (intent or cart mandate)
- `ap2_validate_mandate_pair` — Three-axis validation of an intent → cart mandate pair: AP2 mandate-level constraints + TDIP `DelegationScope` (`enforce_operation`) + runtime `SpendingPolicy` (`SpendingPolicySnapshot::check`)
- `ap2_protocol_info` — AP2 protocol metadata and supported features

### AI Models (10 tools)

- `list_models` — List available AI models
- `chat_completion` — Send chat completion request
- `list_model_endpoints` — List model service endpoints
- `discover_models` — Discover models on network
- `download_model` — Download model from registry
- `serve_model` — Start serving a model
- `stop_model` — Stop serving a model
- `delete_model` — Delete a downloaded model
- `get_download_progress` — Check model download progress
- `list_providers` — List registered providers

### Multi-Modal AI (24 tools)

Per-modality `list_*_catalog`, `list_*_models`, `load_*_model`, `unload_*_model`, plus the modality verb. Catalogs draw from `OnnxForecastEntry`, `OnnxVisionEntry`, `OnnxTextEmbeddingEntry`, `OnnxSegmentationEntry`, `OnnxDetectionEntry`, `OnnxAudioEntry`, and `OnnxVideoEntry` in `tenzro-model`. License-tier gating (Permissive / Attribution / CommercialCustom / NonCommercial) is enforced at load time.

- **Forecast** — `list_forecast_catalog`, `list_forecast_models`, `load_forecast_model`, `unload_forecast_model`, `forecast` (Chronos-2, Chronos-Bolt small/base, TimesFM 2.5 200M, Granite-TTM-r2)
- **Vision** — `list_vision_catalog`, `list_vision_models`, `load_vision_model`, `unload_vision_model`, `vision_embed`, `vision_similarity` (CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2)
- **Text Embedding** — `list_text_embedding_catalog`, `list_text_embedding_models`, `load_text_embedding_model`, `unload_text_embedding_model`, `text_embed` (Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0)
- **Segmentation** — `list_segmentation_catalog`, `list_segmentation_models`, `load_segmentation_model`, `unload_segmentation_model`, `segment` (SAM 3 / 3.1, SAM 2 base/large, EdgeSAM, MobileSAM)
- **Detection** — `list_detection_catalog`, `list_detection_models`, `load_detection_model`, `unload_detection_model`, `detect` (RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x)
- **Audio (ASR)** — `list_audio_catalog`, `list_audio_models`, `load_audio_model`, `unload_audio_model`, `transcribe` (Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash)
- **Video** — `list_video_catalog`, `list_video_models`, `load_video_model`, `unload_video_model`, `video_embed` (encoder scaffolding only — wave 1 catalog empty)

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

### Canton (3 tools)

- `list_canton_domains` — List Canton synchronization domains
- `list_daml_contracts` — List active DAML contracts
- `submit_daml_command` — Submit DAML command

### Verification (1 tool)

- `verify_zk_proof` — Verify Plonky3 STARK proof over the KoalaBear field; requires `circuit_id` ∈ {inference, settlement, identity} and 4-byte LE field-chunk public inputs

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

- `create_mpc_wallet` — Create MPC threshold wallet
- `export_keystore` — Export encrypted keystore
- `import_keystore` — Import from keystore
- `get_key_shares` — Get MPC key share configuration
- `rotate_keys` — Rotate MPC key shares
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

### deBridge Cross-Chain (5 tools)

- `debridge_search_tokens` — Search tokens on deBridge DLN
- `debridge_get_chains` — Get supported chains
- `debridge_get_instructions` — Get operational instructions
- `debridge_create_tx` — Create cross-chain transaction
- `debridge_same_chain_swap` — Execute same-chain swap

## Ecosystem MCP Servers

In addition to the main Tenzro MCP server, the node runs specialized servers for direct blockchain interaction:

| Server | Port | Endpoint | Description |
|--------|------|----------|-------------|
| **Tenzro** | 3001 | `/mcp` | 191 tools for Tenzro Ledger + multi-modal AI operations |
| **Solana** | 3003 | `/mcp` | Jupiter swaps, SPL tokens, Metaplex NFTs, staking |
| **Ethereum** | 3004 | `/mcp` | Gas prices, ENS, ERC-20, EAS attestations, ERC-8004 |
| **Canton** | 3005 | `/mcp` | DAML contracts, CIP-56 tokens, DvP settlement |
| **LayerZero** | 3006 | `/mcp` | V2 messaging, OFT transfers, DVN configuration |
| **Chainlink** | 3007 | `/mcp` | CCIP, data feeds, VRF, automation, Functions |

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
