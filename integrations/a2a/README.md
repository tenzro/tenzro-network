# Tenzro A2A Server

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![A2A Protocol](https://img.shields.io/badge/A2A-0.2.0-blue)](https://a2a-protocol.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

Connect AI agents to Tenzro Network using Google's [Agent-to-Agent (A2A)](https://a2a-protocol.org) protocol.

## Overview

The Tenzro A2A server is an installable Python package that lets any A2A-compatible agent interact with the blockchain — query balances, send transactions, manage identities, spawn sub-agents, trade on marketplaces, deploy contracts, and more. Install with `pip install tenzro-a2a-server` and run locally, or connect directly to the live testnet endpoint.

**Live testnet:** `https://a2a.tenzro.network`
**Local:** `http://localhost:3002`

## Installation

```bash
pip install tenzro-a2a-server
```

Or from source:

```bash
git clone https://github.com/tenzro/tenzro-network.git
cd integrations/a2a
pip install .
```

## Endpoints

| Endpoint | URL | Description |
|----------|-----|-------------|
| Agent Card | `GET /.well-known/agent.json` | Agent capability discovery |
| A2A RPC | `POST /a2a` | JSON-RPC 2.0 task execution |
| A2A Stream | `POST /a2a/stream` | Server-Sent Events streaming |
| Health | `GET /health` | Health check |

> Note: the verification API at `api.tenzro.network` exposes `/verify/*`, `/health`, `/status`, and `/faucet` — no redundant `/api/` prefix (the subdomain already conveys it).

## Quick Start

### Discover capabilities

```bash
curl https://a2a.tenzro.network/.well-known/agent.json
```

### Send a task

```bash
curl -X POST https://a2a.tenzro.network/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{ "type": "text", "text": "What is my balance for address 0x1234...?" }]
      }
    },
    "id": 1
  }'
```

### Stream a response (SSE)

```bash
curl -X POST https://a2a.tenzro.network/a2a/stream \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{ "type": "text", "text": "Get the current block height" }]
      }
    },
    "id": 1
  }'
```

### Catch-up sync (block range)

A lagging client can ask the agent to batch-fetch historical blocks. The
handler dispatches to `tenzro_getBlockRange` and reports the
`nextHeight` / `moreAvailable` cursor so callers can paginate past pruning
gaps:

```bash
curl -X POST https://a2a.tenzro.network/a2a \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tasks/send",
    "params": {
      "message": {
        "role": "user",
        "parts": [{ "type": "text", "text": "block range 1000 1063" }]
      }
    },
    "id": 1
  }'
```

`status`/`health` queries also surface the live sync gap by comparing the
local tip against peer-reported network tips (gossiped on
`tenzro/status`).

## Agent Skills

The Tenzro A2A agent exposes skills covering blockchain, AI, identity, payments, lifecycle, bonds, capital markets, multi-party workflows, EVM primitives, cross-chain reach, BTC-secured staking, chain-agnostic discovery, Canton 3.5+ JSON Ledger API, decentralized storage, compute rental, distributed MoE serving, local discovery + LAN clustering, and agent orchestration. The Agent Card at `tenzro_a2a_server/agent_card.py` is the authoritative source for skill IDs and descriptions.

### Core Blockchain

| Skill | ID | Description |
|-------|-----|-------------|
| **Wallet Operations** | `wallet` | Create wallets, check balances, send TNZO transactions |
| **Token Management** | `token` | Create ERC-20 tokens, cross-VM transfers, wrap TNZO |
| **Smart Contracts** | `contract` | Deploy contracts to EVM, SVM, or DAML |
| **NFT Management** | `nft` | Create collections, mint, transfer, and query NFTs across VMs |
| **Staking & Providers** | `staking` | Stake TNZO, register as validator/provider |

### Identity & Payments

| Skill | ID | Description |
|-------|-----|-------------|
| **Identity Management** | `identity` | Register/resolve DIDs (TDIP), set usernames, GDPR Article 17 right-to-erasure (`forget_identity`) |
| **Settlement & Payments** | `settlement` | Micropayment channels, escrow, batch settlement |
| **AP2 Payments** | `ap2-payments` | AP2 v0.2 sign + verify + validate-pair (intent → cart) for agent-to-agent autonomous financial transactions, with three-axis ceiling enforcement (mandate constraints + TDIP DelegationScope + runtime SpendingPolicy) |
| **Stripe SPT** | `stripe-spt` | SharedPaymentToken issuance + verify with TDIP cap-resolver, AP2 cart-mandate cross-check, ERC-8004 ReputationRegistry cross-write on settled outcome, `granted_token.deactivated` webhook cascade into TDIP `apply_remote_revocation` |

### AI & Agents

| Skill | ID | Description |
|-------|-----|-------------|
| **AI Inference** | `inference` | Route inference to model providers, settle in TNZO |
| **Cortex Reasoning Workers** | `cortex` | Tenzro Cortex reasoning-tier inference via signed receipts (Fast/Standard/Deep budgets, MoE rdt-moe family, max_cost_wei cap) |
| **Forecast** | `forecast` | Timeseries forecasting via TimesFM 2.5 |
| **Vision** | `vision` | Image embedding/similarity via CLIP, SigLIP2, DINOv3 |
| **Text Embedding** | `text_embedding` | Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic |
| **Segmentation** | `segmentation` | SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM |
| **Detection** | `detection` | RF-DETR, D-FINE object detection |
| **Audio** | `audio` | ASR via Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary |
| **Video** | `video` | Frame-extraction + per-frame embedding via `VisionFallbackVideoEncoder` (pooled vision encoders) |
| **Agent Spawning** | `agent_spawning` | Spawn sub-agents with own DID and wallet (up to 50) |
| **Swarm Orchestration** | `swarm_orchestration` | Create agent swarms for parallel task execution |
| **Agent Lifecycle** | `lifecycle` | Driver of `Created → Active → Suspended → Terminated` state transitions, including parent→children spawn-tree audit |
| **AgentBond & Insurance** | `bond-insurance` | Post/withdraw TNZO collateral against autonomous agent DIDs and file insurance claims (Spec 9) |
| **Task Marketplace** | `task_marketplace` | Post/browse tasks with TNZO escrow payment |
| **Agent Marketplace** | `agent_marketplace` | Publish, discover, rate, and spawn agent templates |
| **ERC-8004 Trustless Agents** (v0.6+, cross-VM trio) | `erc8004` | Full surface across IdentityRegistry (register / register(string) / register(string,(string,bytes)[]) overloads, getAgent encode/decode, setAgentURI, setAgentWallet, setMetadata, getMetadata encode/decode, getAgentURI, getAgentWallet), ReputationRegistry (feedback, getFeedback, getFeedbackCount, revokeFeedback, isFeedbackRevoked, appendResponse, getFeedbackResponses), and ValidationRegistry (validationRequest, validationResponse, getValidation). EVM mirror writes against canonical OZ-ERC721 upgradeable proxies deployed at genesis (calldata byte-identical to native precompiles `0x101a` / `0x101b` / `0x101c`); SVM mirror via QuantuLabs Anchor program (`tenzro-identity::erc8004_svm`, buffered to `erc8004_svm_pending_tx:` — operator drains to a Solana RPC); DAML mirror via Tenzro-authored Canton package at `vendor/erc8004-daml/daml/Tenzro/Erc8004/` (Canton Ledger JSON API v2 `submit-and-wait` commands, buffered to `erc8004_daml_pending_tx:`). All three mirrors fan out from a single TDIP `register_machine_with_fee` call. `agentId` is server-allocated by each backing registry (sequential `uint256` on EVM, 32-byte Pubkey on SVM, 8-byte LE u64 on DAML). |

### Cross-Chain & Compliance

| Skill | ID | Description |
|-------|-----|-------------|
| **Cross-Chain Bridge** | `bridge` | Bridge tokens between Tenzro, Ethereum, Solana, Base via LayerZero/CCIP/deBridge |
| **Cross-Chain Token** | `crosschain` | ERC-7802 cross-chain token standard, mint/burn bridging |
| **Wormhole Cross-Chain** | `wormhole` | Wormhole messaging and token transfers (chain id lookup, VAA parsing, BridgeRouter integration) |
| **TNZO CCT Pool Registry** | `cct` | Chainlink CCT pool registry — LockRelease on Ethereum, BurnMint on Base/Arbitrum/Optimism/Solana |
| **Compliance & KYC** | `compliance` | ERC-3643 T-REX compliance, identity verification, KYC attestation |

### Verification & Onboarding

| Skill | ID | Description |
|-------|-----|-------------|
| **Proof Verification** | `verification` | Verify ZK proofs, TEE attestations, transaction signatures; look up the cached synthetic-content provenance manifest (EU AI Act Art. 50(2)) for AI-generated output by `content_hash` |
| **Event Streaming** | `events` | Subscribe to blockchain events via WebSocket, webhooks, gRPC |
| **Authentication (OAuth 2.1 + DPoP)** | `auth` | Onboard humans / delegated agents / autonomous agents (RFC 6749 + RFC 9449), refresh access tokens, link an existing wallet to an auth session, revoke JWTs/DIDs. Pass `dpop_jkt` (RFC 7638 thumbprint) to bind issued tokens to a holder key. |
| **Join as MicroNode** | `join` | Zero-install network participation with auto-provisioned DID + wallet |
| **Decentralized Storage** | `storage` | Content-addressed storage on the iroh data plane, billed per byte-epoch and held to a proof of retrievability — open/charge/look-up deals, set pricing, read provider status; one coverage budget shared with compute |
| **Compute Rental** | `compute` | Rent compute against stake, settled per epoch on an availability proof — book/settle/look-up rentals, set pricing, read provider status; shares the storage coverage budget |
| **Distributed MoE Serving** | `moe` | Decentralized expert-shard serving — shard map, top-k dispatch planning, replication policy, catalog topology, expert/gate weight loading into the local expert runtime, runtime status, and distributed layer forwards that fan hidden states out to expert holders and gather gate-weighted outputs |
| **Operability Inspection** | `operability` | Read-only surface for SREs and monitoring agents — Tenzro Train inspection (list runs, run state, sealed receipts, Confidential-tier sealed-shard manifests, trainer auto-provisioning daemon status), SLA fault-detector parameters and probes (list outstanding, issue liveness probe), and state-sync snapshot inspection (list, manifest by height, chunk fetch); validator-registry reads route through the validator-lifecycle skill |
| **Local Discovery & LAN Clustering** | `discovery` | mDNS local-segment peers, connectivity tier (`direct` / `relay_only` / `unreachable`), hardware self-profile, and deterministic layer-wise LAN cluster planning. Serving auto-triggers the cluster when a model exceeds one host: the node reads the GGUF header for shape, discovers members from gossiped `ClusterProfile` announcements, and runs a layer-wise pipeline — opt out with `force_single`. |

## A2A Methods

| Method | Description | Parameters |
|--------|-------------|------------|
| `tasks/send` | Send a message, create or continue a task | `message` (role, parts), `metadata` |
| `tasks/get` | Get task by ID | `id`, `historyLength` |
| `tasks/list` | List tasks | `contextId` (optional) |
| `tasks/cancel` | Cancel a running task | `id` |

## Message Routing

The agent routes messages based on natural language content:

| Keywords | Skill |
|----------|-------|
| `balance`, `wallet`, `send`, `transfer` | Wallet Operations |
| `block`, `height`, `transaction`, `block range`, `sync from`, `catch up` | Block/transaction queries (single block, transaction lookup, batch range for catch-up sync) |
| `identity`, `did`, `register`, `resolve`, `username` | Identity Management |
| `model`, `inference`, `ai`, `chat` | AI Inference |
| `forecast`, `timeseries`, `timesfm` | Forecast |
| `image embed`, `clip`, `siglip`, `dinov3`, `vision` | Vision |
| `text embed`, `embedding`, `qwen3-embedding`, `bge-m3`, `arctic` | Text Embedding |
| `segment`, `mask`, `sam` | Segmentation |
| `detect`, `bounding box`, `rf-detr`, `d-fine` | Detection |
| `transcribe`, `whisper`, `moonshine`, `parakeet`, `canary`, `asr` | Audio |
| `video embed` | Video |
| `payment`, `challenge`, `mpp`, `x402`, `ap2` | Payments |
| `stake`, `validator`, `provider` | Staking |
| `token`, `erc20`, `create token`, `wrap` | Token Management |
| `deploy`, `contract`, `bytecode` | Smart Contracts |
| `spawn`, `sub-agent`, `child agent` | Agent Spawning |
| `swarm`, `parallel`, `orchestrat` | Swarm Orchestration |
| `task`, `marketplace`, `post task`, `quote` | Task Marketplace |
| `template`, `agent marketplace`, `rating` | Agent Marketplace |
| `verify`, `proof`, `attestation`, `zk`, `provenance`, `synthetic` | Verification |
| `join`, `micronode`, `onboard` | Join as MicroNode |
| `nft`, `collection`, `mint`, `transfer nft` | NFT Management |
| `bridge`, `cross-chain`, `layerzero`, `ccip`, `debridge` | Cross-Chain Bridge |
| `compliance`, `kyc`, `t-rex`, `erc-3643`, `whitelist` | Compliance & KYC |
| `erc-7802`, `cross-chain token`, `crosschain` | Cross-Chain Token |
| `event`, `subscribe`, `webhook`, `stream`, `listen` | Event Streaming |
| `canton` | Cross-chain bridge |
| `status`, `health`, `node`, `peer`, `network` | Node status |
| `faucet`, `tokens` | Testnet faucet |

## Examples

See the `examples/` directory:

- [`typescript-client.ts`](examples/typescript-client.ts) — TypeScript A2A client
- [`python-client.py`](examples/python-client.py) — Python A2A client (zero deps)
- [`curl-examples.sh`](examples/curl-examples.sh) — cURL command examples

## Integration with AI Frameworks

### LangChain

```python
from langchain.tools import Tool
import requests

def tenzro_a2a(query: str) -> str:
    response = requests.post("https://a2a.tenzro.network/a2a", json={
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": query}]
            }
        },
        "id": 1
    })
    task = response.json().get("result", {})
    for msg in reversed(task.get("messages", [])):
        if msg.get("role") == "agent":
            return msg["parts"][0]["text"]
    return "No response"

tenzro_tool = Tool(
    name="TenzroBlockchain",
    func=tenzro_a2a,
    description="Interact with Tenzro Network — wallets, identities, payments, AI inference, agents, tokens, contracts"
)
```

### CrewAI

```python
from crewai.tools import tool
import requests

@tool("Tenzro Blockchain")
def tenzro_blockchain(query: str) -> str:
    """Interact with Tenzro Network — wallets, identities, AI inference, payments, agents, tokens, contracts, verification."""
    response = requests.post("https://a2a.tenzro.network/a2a", json={
        "jsonrpc": "2.0",
        "method": "tasks/send",
        "params": {
            "message": {
                "role": "user",
                "parts": [{"type": "text", "text": query}]
            }
        },
        "id": 1
    })
    task = response.json().get("result", {})
    for msg in reversed(task.get("messages", [])):
        if msg.get("role") == "agent":
            return msg["parts"][0]["text"]
    return "No response"
```

## Architecture

```
Your Agent                    Tenzro Node
    |                              |
    |-- GET /.well-known/agent.json -->  Agent Card
    |                              |
    |-- POST /a2a (tasks/send) ------->  Task Manager
    |                              |     |
    |                              |     v
    |                              |  Message Router
    |                              |  (wallet? identity? spawn? marketplace?)
    |                              |     |
    |                              |     v
    |                              |  Node Subsystems
    |                              |  (Storage, Identity, Wallet, Settlement,
    |                              |   Verification, Bridge, Model Registry,
    |                              |   Agent Runtime, Token Registry, VM...)
    |                              |     |
    |<-- A2aTask (completed) ------------|
```

## Combining A2A with MCP

| Protocol | Best For | Endpoint |
|----------|----------|----------|
| **A2A** (this) | Natural language task delegation | `a2a.tenzro.network/a2a` |
| **MCP** | Structured tool calls from Claude/Cursor | `mcp.tenzro.network/mcp` |
| **JSON-RPC** | Direct EVM-compatible RPC | `rpc.tenzro.network` |
| **Web API** | REST verification and status | `api.tenzro.network` |

## Running the Server

```bash
tenzro-a2a-server --port 3002
```

Or with a custom RPC endpoint:

```bash
TENZRO_RPC_URL=http://localhost:8545 tenzro-a2a-server --port 3002
```

### Test the server

```bash
curl http://localhost:3002/.well-known/agent.json
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TENZRO_RPC_URL` | `https://rpc.tenzro.network` | Tenzro JSON-RPC endpoint |
| `TENZRO_API_URL` | `https://api.tenzro.network` | Tenzro Web API endpoint |
| `TENZRO_A2A_BASE_URL` | `https://a2a.tenzro.network` | Base URL for Agent Card |

Command-line options:

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `3002` | HTTP server port |
| `--host` | `0.0.0.0` | HTTP server bind address |

## Related

| Resource | URL |
|----------|-----|
| Tenzro Network | [tenzro.com](https://tenzro.com) |
| MCP Server | [github.com/tenzro/tenzro-network](https://github.com/tenzro/tenzro-network) |
| A2A Protocol | [a2a-protocol.org](https://a2a-protocol.org) |

## Contact

- Website: [tenzro.com](https://tenzro.com)
- Engineering: [eng@tenzro.com](mailto:eng@tenzro.com)
- GitHub: [github.com/tenzro](https://github.com/tenzro)

## License

Apache 2.0. See [LICENSE](LICENSE).
