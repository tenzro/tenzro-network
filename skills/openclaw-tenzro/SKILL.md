---
name: tenzroclaw
version: 0.1.0
author: Tenzro Network
description: TenzroClaw — OpenClaw skill for the Tenzro Network. Create wallets, send transactions, check balances, register identities, manage credentials and services, set usernames, set delegation scopes, make payments via MPP/x402, run AI inference, manage model endpoints, bridge tokens cross-chain, verify proofs, post and manage tasks on the decentralized AI task marketplace, publish and discover agent templates, spawn agents from templates, manage agent swarms, create and manage ERC-20 tokens, deploy smart contracts, transfer tokens across VMs, register and invoke tools/skills, manage settlement and escrow, participate in governance, interact with Canton/DAML, and request testnet tokens.
tags:
  - blockchain
  - ai
  - identity
  - payments
  - bridge
  - inference
  - web3
  - task_marketplace
  - agent_marketplace
  - swarm
  - autonomous_agents
  - tokens
  - contracts
  - erc20
  - multi_vm
  - usernames
  - skill_usage
  - tool_usage
  - tools_registry
  - settlement
  - escrow
  - governance
  - canton
  - daml
  - evm
---

# TenzroClaw

You can interact with the Tenzro blockchain network using its JSON-RPC, Web API, and MCP endpoints. Tenzro is an L1 blockchain designed for the AI age, providing identity, settlement, TEE security, and ZK proof verification.

## Endpoints

| Service | URL | Description |
|---------|-----|-------------|
| JSON-RPC | `https://rpc.tenzro.network` | EVM-compatible JSON-RPC (port 8545) |
| Web API | `https://api.tenzro.network` | REST verification and status API (port 8080) |
| Faucet | `https://api.tenzro.network/faucet` | Testnet TNZO token faucet |
| MCP | `https://mcp.tenzro.network/mcp` | Model Context Protocol server (port 3001) |
| A2A | `https://a2a.tenzro.network` | Agent-to-Agent protocol (port 3002) |

For local development, replace the hostnames with `localhost` and use the ports shown above.

## Token

**TNZO** is the native token with 18 decimal places. Amounts in the RPC are in wei (1 TNZO = 10^18 wei). The default gas price is 1 Gwei (10^9 wei).

## Authentication

Read operations (block lookups, balances, agent cards, etc.) need no authentication.

Write operations use **OAuth 2.1 + DPoP** (RFC 6749 successor + RFC 9449) on top of Ed25519/Secp256k1 transaction signatures. Onboarding mints an HS256 JWT access token (1h TTL) and an opaque refresh token (30d TTL); the access token is sent as `Authorization: Bearer <token>` and, when DPoP-bound, accompanied by a fresh DPoP proof in the `DPoP` header signed by the holder key whose RFC 7638 thumbprint (`jkt`) was supplied at onboarding.

### Onboarding RPCs

- `tenzro_onboardHuman` — provisions a `did:tenzro:human:*` identity, MPC wallet, and access + refresh tokens.
- `tenzro_onboardDelegatedAgent` — issues an agent identity bound to a controller DID with a delegation scope.
- `tenzro_onboardAutonomousAgent` — issues a fully autonomous agent identity backed by a TNZO bond.
- `tenzro_participate` — convenience one-call human onboarding (used by CLI/desktop); returns the same session bundle.

Each call returns `{ identity, wallet, access_token, refresh_token, expires_in, refresh_token_expires_in, dpop_bound, authorization_details, ... }`.

### Refresh and bridge RPCs

- `tenzro_refreshToken` — exchange a refresh token for a new access token (refresh tokens are not rotated).
- `tenzro_linkWalletForAuth` — mint a fresh access + refresh token pair against an existing MPC wallet (e.g. one created via `tenzro_createWallet` or `tenzro_importIdentity`).
- `tenzro_revokeJwt` / `tenzro_revokeDid` — revoke a single JWT by `jti` or cascade-invalidate every JWT minted under a DID.

### Delegation and AS metadata RPCs

- `tenzro_exchangeToken` — RFC 8693 OAuth 2.0 Token Exchange. Mint a narrower child JWT bound to a different DPoP key with a strict subset of the parent's RAR grants and AAP capabilities, extending the act-chain by one hop.
- `tenzro_introspectToken` — RFC 7662 OAuth 2.0 Token Introspection. Returns `{active: true, ...claims}` on success or the minimal `{"active": false}` per RFC 7662 §2.2 when the token is unknown, expired, or revoked.
- `tenzro_oauthDiscovery` — RFC 8414 / RFC 9728 metadata document. Mirrors `GET /.well-known/openid-configuration`, augmented with AAP extensions (`authorization_details_types_supported`, `aap_claims_supported`, `dpop_signing_alg_values_supported`).

The `dpop_jkt` parameter on every onboarding/refresh/link call is the RFC 7638 SHA-256 thumbprint of the holder's Ed25519 public key. Pass it to bind the issued token to that key — every subsequent privileged call must then carry a DPoP proof signed by the same key. **Strongly recommended.**

When operating from MCP/SDK/CLI clients, call `tenzro auth refresh` (or `tenzro auth link-wallet`) to keep the locally cached token current; the CLI persists the latest tokens to `~/.tenzro/config.json`.

---

## JSON-RPC API

All RPC calls use `POST` with `Content-Type: application/json`. The request body follows JSON-RPC 2.0:

```json
{
  "jsonrpc": "2.0",
  "method": "<method_name>",
  "params": { ... },
  "id": 1
}
```

### Create a Wallet

Generate a new Tenzro 2-of-3 threshold MPC wallet. No seed phrase, no
private key in user custody — the keystore holds shares, the node never
sees a full key.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_createWallet",
    "params": {"key_type": "ed25519"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "wallet_id": "<uuid>",
    "address": "0x<64 hex chars — 32-byte Tenzro address>",
    "display_address": "<base58 display form>",
    "public_key": "<hex>",
    "key_type": "ed25519",
    "threshold": 2,
    "total_shares": 3
  },
  "id": 1
}
```

The 32-byte hex `address` is the canonical form used by `eth_getBalance`,
the faucet, and all transaction RPCs. The `display_address` is a
human-friendly base58 alias (informational).

### Check Balance

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getBalance",
    "params": {"address": "0x<address>"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "0x56bc75e2d63100000",
  "id": 1
}
```

The result is a hex string in wei. `0x56bc75e2d63100000` = 100 TNZO.

Also available via EVM-compatible method:
```json
{"jsonrpc":"2.0","method":"eth_getBalance","params":{"address":"0x..."},"id":1}
```

### Send Transaction

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendRawTransaction",
    "params": {
      "from": "0x<sender>",
      "to": "0x<recipient>",
      "value": 1000000000000000000,
      "gas_limit": 21000,
      "gas_price": 1000000000,
      "nonce": 0
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": "0x<transaction_hash>",
  "id": 1
}
```

### Get Block Height

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_blockNumber","params":{},"id":1}'
```

### Get Block by Number

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_getBlock","params":{"height":0},"id":1}'
```

Use `"params":["latest"]` for the most recent block.

### Get Chain ID

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":{},"id":1}'
```

Default chain ID is `0x539` (1337).

### Get Node Info

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_nodeInfo","params":{},"id":1}'
```

### Get Token Supply

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_totalSupply","params":{},"id":1}'
```

### List Registered Models

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_listModels","params":{"category":"text"},"id":1}'
```

Optionally filter by `category` (text, image, audio, video, text_image, text_audio, multimodal) or `name` (substring match).

---

## Identity (Tenzro Identity Protocol)

Tenzro uses decentralized identifiers (DIDs) for both humans and machines.

- Human DID format: `did:tenzro:human:<uuid>`
- Machine DID format: `did:tenzro:machine:<controller>:<uuid>` or `did:tenzro:machine:<uuid>` (autonomous)

### Register Human Identity

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerIdentity",
    "params": {
      "display_name": "Alice"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "did": "did:tenzro:human:<uuid>",
    "status": "registered",
    "private_key": "<hex>"
  },
  "id": 1
}
```

Optionally pass `"public_key": "<hex>"` and `"key_type": "ed25519"` to use an existing keypair.

### Resolve Identity

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_resolveIdentity",
    "params": {"did": "did:tenzro:human:<uuid>"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "did": "did:tenzro:human:<uuid>",
    "status": "active",
    "is_human": true,
    "is_machine": false,
    "display_name": "Alice",
    "key_count": 1,
    "credential_count": 0,
    "service_count": 0
  },
  "id": 1
}
```

### Resolve DID Document (W3C Standard)

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_resolveDidDocument",
    "params": {"did": "did:tenzro:human:<uuid>"},
    "id": 1
  }'
```

### Join as MicroNode

Join the Tenzro Network as a full participant — zero-install. Auto-provisions a TDIP DID,
MPC wallet, and all 10 network capabilities in a single RPC call.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_joinAsMicroNode",
    "params": {
      "display_name": "Alice",
      "origin": "cli",
      "participant_type": "human"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "identity": { "did": "did:tenzro:human:<uuid>", "display_name": "Alice", "identity_type": "human", "status": "active" },
    "wallet": { "address": "0x<hex>", "wallet_type": "mpc", "balance": "0" },
    "capabilities": { "inference": true, "payments": true, "agent_collaboration": true, "mcp_tools": true, "task_execution": true, "chain_query": true, "smart_contracts": true, "tee_services": true, "bridge": true, "governance": true },
    "network": { "rpc": "https://rpc.tenzro.network", "mcp": "https://mcp.tenzro.network/mcp", "a2a": "https://a2a.tenzro.network" },
    "is_micro_node": true,
    "chain_id": 1337
  }
}
```

Falls back to `tenzro_participate` for nodes that don't yet support `tenzro_joinAsMicroNode`.

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import join_as_micro_node
result = join_as_micro_node("Alice")
print(result["identity"]["did"])    # did:tenzro:human:<uuid>
print(result["wallet"]["address"])  # 0x<hex>
```

### Set Username

Attach a human-readable username to a DID. Usernames are unique across the network.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_setUsername",
    "params": {"did": "did:tenzro:human:<uuid>", "username": "alice"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "did": "did:tenzro:human:<uuid>",
    "username": "alice",
    "status": "set"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import set_username
result = set_username("did:tenzro:human:abc-123", "alice")
print(result["username"])  # "alice"
```

### Resolve Username

Look up a DID by its username.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_resolveUsername",
    "params": {"username": "alice"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "did": "did:tenzro:human:<uuid>",
    "username": "alice",
    "display_name": "Alice"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import resolve_username
result = resolve_username("alice")
print(result["did"])  # did:tenzro:human:<uuid>
```

### Set Delegation Scope

Define spending limits, allowed operations, payment protocols, and chains for a machine identity.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_setDelegationScope",
    "params": {
      "machine_did": "did:tenzro:machine:<controller>:<uuid>",
      "max_transaction_value": 10000000,
      "max_daily_spend": 100000000,
      "allowed_operations": ["InferenceRequest", "Transfer"],
      "allowed_payment_protocols": ["mpp", "x402", "native"],
      "allowed_chains": ["tenzro", "base", "ethereum"]
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "machine_did": "did:tenzro:machine:<controller>:<uuid>",
    "delegation_scope": {
      "max_transaction_value": 10000000,
      "max_daily_spend": 100000000,
      "allowed_operations": ["InferenceRequest", "Transfer"],
      "allowed_payment_protocols": ["mpp", "x402", "native"],
      "allowed_chains": ["tenzro", "base", "ethereum"]
    },
    "status": "updated"
  },
  "id": 1
}
```

---

## Payments

Tenzro supports three payment protocols:
- **MPP** (Machine Payments Protocol) — session-based streaming payments, ideal for per-token AI inference billing
- **x402** (Coinbase HTTP 402) — stateless one-shot payments, ideal for API calls and data downloads
- **native** — direct TNZO transfer on the Tenzro ledger

### Create Payment Challenge

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_createPaymentChallenge",
    "params": {
      "protocol": "x402",
      "resource": "/inference",
      "amount": 100,
      "asset": "USDC",
      "recipient": "0x<recipient_address>"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "challenge_id": "<uuid>",
    "protocol": "x402",
    "resource": "/inference",
    "amount": 100,
    "asset": "USDC",
    "recipient": "0x<recipient_address>",
    "expires_at": "2025-01-01T01:00:00Z"
  },
  "id": 1
}
```

### Verify Payment

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_verifyPayment",
    "params": {
      "challenge_id": "<challenge_uuid>",
      "protocol": "x402",
      "payer_did": "did:tenzro:human:<uuid>",
      "payer_address": "0x<payer_address>",
      "amount": 100,
      "asset": "USDC",
      "signature": "0x<hex_signature>"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "verified": true,
    "receipt_id": "<uuid>",
    "settled": true
  },
  "id": 1
}
```

### List Payment Protocols

> **Note:** This is available as an MCP tool (`list_payment_protocols`) on the MCP server at `https://mcp.tenzro.network/mcp`, not as a JSON-RPC method.

Supported protocols: **MPP** (session-based streaming), **x402** (stateless one-shot), **native** (direct TNZO transfer).

---

## AI Models & Inference

### List Models

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listModels",
    "params": {"category": "text"},
    "id": 1
  }'
```

Supported categories: `text`, `image`, `audio`, `video`, `text_image`, `text_audio`, `multimodal`. You can also filter by `name`.

**Response includes load information for serving models:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "model_id": "qwen3.5_0.5b_q4",
      "name": "Qwen 3.5 0.5B Q4",
      "serving": true,
      "load": {
        "active_requests": 2,
        "max_concurrent": 4,
        "utilization_percent": 50,
        "load_level": "busy"
      }
    }
  ],
  "id": 1
}
```

Load levels: `idle` (0%), `available` (1-50%), `busy` (51-80%), `near_capacity` (81-99%), `at_capacity` (100%).

### Chat Completion

Send a chat completion request to a served AI model on the network.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_chat",
    "params": {
      "model_id": "<model_id_or_instance_id>",
      "message": "Explain zero-knowledge proofs in one paragraph.",
      "temperature": 0.7,
      "max_tokens": 512
    },
    "id": 1
  }'
```

> The identifier key accepts both `model_id` (Tenzro canonical) and `model`
> (OpenAI/MCP-style). The MCP `chat_completion` tool mirrors the same
> flexibility. Clients may use whichever spelling is idiomatic for their stack.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "model": "<model_id>",
    "response": "Zero-knowledge proofs are...",
    "tokens_used": 87,
    "finish_reason": "stop",
    "load": {
      "active_requests": 1,
      "max_concurrent": 4,
      "utilization_percent": 25,
      "load_level": "available"
    }
  },
  "id": 1
}
```

The `load` field shows the model's current load after processing your request. Load levels: `idle` (0%), `available` (1-50%), `busy` (51-80%), `near_capacity` (81-99%), `at_capacity` (100%).

Use `tenzro_listModels` or `tenzro_listModelEndpoints` to discover available models before calling `tenzro_chat`.

### List Model Endpoints

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listModelEndpoints",
    "params": {},
    "id": 1
  }'
```

Returns all running model service endpoints with their API URLs, MCP URLs, model details, and status.

**Response includes load information for each serving model:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "instance_id": "<uuid>",
      "model_id": "qwen3.5_0.5b_q4",
      "api_url": "http://127.0.0.1:8000/v1/chat/completions",
      "mcp_url": "http://127.0.0.1:8001/mcp",
      "status": "running",
      "load": {
        "active_requests": 0,
        "max_concurrent": 4,
        "utilization_percent": 0,
        "load_level": "idle"
      }
    }
  ],
  "id": 1
}
```

Load levels: `idle` (0%), `available` (1-50%), `busy` (51-80%), `near_capacity` (81-99%), `at_capacity` (100%).

---

## Network Provider Discovery

Tenzro uses a decentralized provider registry — nodes that serve AI models or TEE services broadcast a `ProviderAnnouncement` every 60 seconds on the `tenzro/providers/1.0.0` gossipsub topic. All peers merge incoming announcements into their local `network_providers` cache, so any node can discover every provider without a central registry.

### List Network Providers

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listProviders",
    "params": {},
    "id": 1
  }'
```

Optionally filter by provider type:

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listProviders",
    "params": {"provider_type": "llm"},
    "id": 1
  }'
```

**Provider types:** `llm` (language models), `tee` (trusted execution environments), `general`

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "peer_id": "12D3KooW...",
      "provider_address": "0x<hex>",
      "provider_type": "llm",
      "served_models": ["gemma4-9b", "qwen3.5-0.8b"],
      "capabilities": ["inference", "chat"],
      "rpc_endpoint": "http://10.128.0.5:8545",
      "status": "active",
      "is_local": false
    }
  ],
  "id": 1
}
```

The `is_local` field indicates whether the entry represents the local node itself. Provider announcements are refreshed every 60 seconds; entries expire after 120 seconds if not refreshed.

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import call_rpc
providers = call_rpc("tenzro_listProviders", {})
llm_providers = call_rpc("tenzro_listProviders", {"provider_type": "llm"})
for p in providers:
    print(p["peer_id"], p["provider_type"], p["served_models"])
```

---

## Cross-Chain Bridge

### Bridge Tokens

Bridge tokens between Tenzro, Ethereum, Solana, and Base via LayerZero, Chainlink CCIP, or deBridge.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_bridgeTokens",
    "params": {
      "source_chain": "tenzro",
      "dest_chain": "ethereum",
      "asset": "TNZO",
      "amount": 1000000000000000000,
      "sender": "0x<sender_address>",
      "recipient": "0x<recipient_address>"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "transfer_id": "<uuid>",
    "source_tx_hash": "0x<hash>",
    "adapter": "layerzero",
    "status": "pending",
    "estimated_time_secs": 300,
    "fee": "0.001 TNZO"
  },
  "id": 1
}
```

### Get Bridge Routes

> **Note:** This is available as an MCP tool (`get_bridge_routes`) on the MCP server at `https://mcp.tenzro.network/mcp`, not as a JSON-RPC method.

Returns available bridge routes between two chains, including estimated fees, time, and which adapter handles the route.

### List Bridge Adapters

> **Note:** This is available as an MCP tool (`list_bridge_adapters`) on the MCP server at `https://mcp.tenzro.network/mcp`, not as a JSON-RPC method.

Returns all registered bridge adapters: LayerZero, Chainlink CCIP, deBridge, Canton.

---

## Token Registry & Contracts

Tenzro has a unified token registry spanning all VMs (EVM, SVM, DAML). Tokens created via the factory are automatically registered and addressable across all VMs using the Sei V2 pointer model (no bridge risk, no liquidity fragmentation).

### Create Token

Create an ERC-20 token via the factory and register it in the unified token registry.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_createToken",
    "params": {
      "name": "My Token",
      "symbol": "MYT",
      "creator": "0x<creator_address>",
      "initial_supply": "1000000000000000000000",
      "decimals": 18,
      "mintable": false,
      "burnable": false
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "token_id": "<hex>",
    "name": "My Token",
    "symbol": "MYT",
    "decimals": 18,
    "initial_supply": "1000000000000000000000",
    "evm_address": "0x<hex>",
    "status": "created"
  },
  "id": 1
}
```

The `decimals` field defaults to 18 if omitted. Set `mintable: true` to allow minting beyond the initial supply. Set `burnable: true` to allow token burning.

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import create_token
result = create_token("My Token", "MYT", "0x<creator>", "1000000000000000000000")
print(result["token_id"], result["evm_address"])
```

### Get Token Info

Look up a token by symbol, EVM address, or token ID.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getToken",
    "params": {"symbol": "MYT"},
    "id": 1
  }'
```

Also accepts `"evm_address": "0x<hex>"` or `"token_id": "<hex>"` instead of `symbol`.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "token_id": "<hex>",
    "name": "My Token",
    "symbol": "MYT",
    "decimals": 18,
    "total_supply": "1000000000000000000000",
    "token_type": "Erc20",
    "evm_address": "0x<hex>",
    "svm_mint": null,
    "creator": "0x<hex>"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import get_token_info
result = get_token_info(symbol="MYT")
# or: get_token_info(evm_address="0x...")
# or: get_token_info(token_id="<hex>")
```

### List Tokens

List registered tokens in the unified registry, optionally filtered by VM type.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listTokens",
    "params": {"vm_type": "evm", "limit": 50},
    "id": 1
  }'
```

**VM type filter:** `evm`, `svm`, `daml`, `native`. Omit for all tokens. Max `limit` is 100.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "count": 2,
    "tokens": [
      {
        "token_id": "<hex>",
        "name": "My Token",
        "symbol": "MYT",
        "decimals": 18,
        "total_supply": "1000000000000000000000",
        "evm_address": "0x<hex>"
      }
    ]
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import list_tokens
result = list_tokens()            # all tokens
result = list_tokens(vm_type="evm")  # EVM tokens only
```

### Get Token Balance (All VMs)

Get TNZO balance across all VMs with decimal conversion for each VM representation.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getTokenBalance",
    "params": {"address": "0x<address>"},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "0x<address>",
    "native": {"balance": "100000000000000000000", "decimals": 18, "display": "100.000000 TNZO"},
    "evm_wtnzo": {"balance": "100000000000000000000", "decimals": 18},
    "svm_wtnzo": {"balance": "100000000000", "decimals": 9},
    "daml_holding": {"amount": "100.000000000000000000"}
  },
  "id": 1
}
```

All VMs share the same underlying native balance via the pointer model.

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import get_token_balance_all_vms
result = get_token_balance_all_vms("0x<address>")
print(result["native"]["display"])  # "100.000000 TNZO"
```

### Cross-VM Transfer

Transfer tokens atomically between VMs using the Sei V2 pointer model. No bridge risk.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_crossVmTransfer",
    "params": {
      "token": "TNZO",
      "amount": "1000000000000000000",
      "from_vm": "evm",
      "to_vm": "svm",
      "from_address": "0x<evm_address>",
      "to_address": "0x<svm_address>"
    },
    "id": 1
  }'
```

**VM types:** `evm`, `svm`, `daml`, `native`. The `token` field accepts a symbol (e.g. `"TNZO"`) or token ID.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "token": "TNZO",
    "amount": "1000000000000000000",
    "from_vm": "evm",
    "to_vm": "svm",
    "status": "transferred"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import cross_vm_transfer
result = cross_vm_transfer("TNZO", "1000000000000000000", "evm", "svm", "0xfrom", "0xto")
```

### Deploy Contract

Deploy smart contract bytecode to EVM, SVM, or DAML via the MultiVmRuntime.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_deployContract",
    "params": {
      "vm_type": "evm",
      "bytecode": "0x<hex_bytecode>",
      "deployer": "0x<deployer_address>",
      "constructor_args": "0x<hex_args>",
      "gas_limit": 3000000
    },
    "id": 1
  }'
```

**VM types:** `evm`, `svm`, `daml`. The `constructor_args` field is optional (ABI-encoded constructor arguments). Default `gas_limit` is 3,000,000. Max contract size is 24,576 bytes.

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "address": "0x<contract_address>",
    "gas_used": 1234567,
    "vm_type": "evm",
    "status": "deployed"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import deploy_contract
result = deploy_contract("evm", "0x<bytecode>", "0x<deployer>")
print(result["address"])  # deployed contract address
```

---

## Web API

### Node Status

```bash
curl https://api.tenzro.network/status
```

**Response:**
```json
{
  "node_state": "running",
  "role": "Validator",
  "health": "Healthy",
  "block_height": 0,
  "peer_count": 0,
  "uptime_secs": 3600
}
```

### Health Check

```bash
curl https://api.tenzro.network/health
```

### Request Testnet Tokens

Request 100 TNZO from the faucet (rate-limited to one request per address every 24 hours).

```bash
curl -X POST https://api.tenzro.network/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "0x<your_address>"}'
```

**Response:**
```json
{
  "success": true,
  "tx_hash": "0x<hash>",
  "amount": "100 TNZO",
  "message": "Tokens dispensed successfully"
}
```

### Verify ZK Proof

```bash
curl -X POST https://api.tenzro.network/verify/zk-proof \
  -H "Content-Type: application/json" \
  -d '{
    "proof_bytes": "<hex>",
    "public_inputs": ["<hex>"],
    "circuit_id": "inference"
  }'
```

Tenzro uses Plonky3 STARKs over the KoalaBear field as its sole ZK proof system. `circuit_id` is required and must be one of `inference`, `settlement`, `identity`. Public inputs are 4-byte little-endian KoalaBear field-element chunks.

### Verify TEE Attestation

```bash
curl -X POST https://api.tenzro.network/verify/tee-attestation \
  -H "Content-Type: application/json" \
  -d '{
    "vendor": "intel_tdx",
    "report_data": "<hex>"
  }'
```

Supported vendors: `intel_tdx`, `amd_sev_snp`, `aws_nitro`.

### Verify Transaction Signature

```bash
curl -X POST https://api.tenzro.network/verify/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "tx_hash": "<hex>",
    "signature": "<hex>",
    "sender": "<hex>"
  }'
```

### Verify Settlement Receipt

```bash
curl -X POST https://api.tenzro.network/verify/settlement \
  -H "Content-Type: application/json" \
  -d '{
    "receipt_id": "<id>",
    "payer": "<address>",
    "payee": "<address>",
    "amount": "1000000",
    "asset": "TNZO"
  }'
```

### Verify Inference Result

```bash
curl -X POST https://api.tenzro.network/verify/inference \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "<model>",
    "input_hash": "<hex>",
    "output_hash": "<hex>",
    "provider": "<address>"
  }'
```

---

## Task Marketplace

The decentralized AI task marketplace lets agents and users post tasks for fulfillment, with TNZO escrow-based payment.

### Post a Task

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_postTask",
    "params": {
      "title": "Review this Rust code",
      "description": "Please review the following Rust code for correctness and safety issues...",
      "task_type": "code_review",
      "max_price": "50000000000000000000",
      "input": "fn main() { ... }",
      "priority": "normal"
    },
    "id": 1
  }'
```

**Task types:** `inference`, `code_review`, `data_analysis`, `content_generation`, `agent_execution`, `translation`, `research`, `custom:<name>`

**Response:**
```json
{
  "result": {
    "task_id": "uuid-...",
    "status": "open",
    "poster": "0x...",
    "max_price": "50000000000000000000",
    "created_at": 1234567890
  }
}
```

### List Tasks

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listTasks",
    "params": {
      "status": "open",
      "task_type": "inference",
      "max_price": "100000000000000000000",
      "limit": 20,
      "offset": 0
    },
    "id": 1
  }'
```

### Get Task

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getTask",
    "params": {"task_id": "uuid-..."},
    "id": 1
  }'
```

### Cancel Task

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_cancelTask",
    "params": {"task_id": "uuid-..."},
    "id": 1
  }'
```

### Submit a Quote

Providers submit quotes to fulfill a task.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_submitQuote",
    "params": {
      "task_id": "uuid-...",
      "price": "40000000000000000000",
      "model_id": "gemma4-9b",
      "estimated_duration_secs": 30,
      "confidence": 95,
      "notes": "Can complete this in ~30 seconds"
    },
    "id": 1
  }'
```

---

## Agent Template Marketplace

The decentralized agent marketplace lets providers publish reusable AI agent templates for discovery, download, and deployment.

### List Agent Templates

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listAgentTemplates",
    "params": {
      "free_only": true,
      "limit": 20,
      "offset": 0
    },
    "id": 1
  }'
```

**Filter options:** `template_type` (`autonomous`, `tool_agent`, `orchestrator`, `specialist`, `multi_modal`), `creator`, `tag`, `free_only`, `status`

### Register an Agent Template

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerAgentTemplate",
    "params": {
      "name": "Rust Code Reviewer",
      "description": "Reviews Rust code for safety, correctness, and idioms",
      "template_type": "specialist",
      "system_prompt": "You are an expert Rust developer. Review the provided code for...",
      "tags": ["rust", "code-review", "security"],
      "pricing": {"type": "free"}
    },
    "id": 1
  }'
```

**Pricing options:**
- `{"type": "free"}` — Free to use
- `{"type": "per_execution", "price": "1000000000000000000"}` — Fixed price per run
- `{"type": "per_token", "price_per_token": "1000000000"}` — Per token processed
- `{"type": "subscription", "monthly_rate": "10000000000000000000"}` — Monthly subscription

### Get Agent Template

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getAgentTemplate",
    "params": {"template_id": "uuid-..."},
    "id": 1
  }'
```

### Spawn Agent from Template

Instantiate a new agent from a marketplace template.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_spawnAgentFromTemplate",
    "params": {
      "template_id": "uuid-...",
      "name": "my-reviewer"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "agent_id": "<uuid>",
    "template_id": "uuid-...",
    "name": "my-reviewer",
    "status": "active"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import spawn_agent_from_template
result = spawn_agent_from_template("t-1", "my-reviewer")
print(result["agent_id"])
```

### Rate Agent Template

Rate an agent template (1-5 stars) with an optional text review.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_rateAgentTemplate",
    "params": {
      "template_id": "uuid-...",
      "rating": 5,
      "review": "Excellent code reviewer"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "template_id": "uuid-...",
    "rating": 5,
    "status": "rated"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import rate_agent_template
result = rate_agent_template("t-1", 5, "Excellent code reviewer")
```

### Search Agent Templates

Search agent templates by free-text query.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_searchAgentTemplates",
    "params": {
      "query": "code review",
      "limit": 20
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": [
    {
      "template_id": "uuid-...",
      "name": "Rust Code Reviewer",
      "description": "Reviews Rust code for safety"
    }
  ],
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import search_agent_templates
results = search_agent_templates("code review")
```

### Get Agent Template Stats

Get usage statistics for an agent template.

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getAgentTemplateStats",
    "params": {"template_id": "uuid-..."},
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "template_id": "uuid-...",
    "spawn_count": 150,
    "average_rating": 4.5,
    "total_reviews": 30,
    "revenue_wei": "50000000000000000000"
  },
  "id": 1
}
```

**Python (tenzro_rpc.py):**
```python
from tools.tenzro_rpc import get_agent_template_stats
stats = get_agent_template_stats("t-1")
print(stats["spawn_count"], stats["average_rating"])
```

---

## Agent Spawning & Swarm Orchestration

Tenzro agents can autonomously spawn child agents, form swarms, and run agentic execution loops with built-in LLM tool-calling.

### Register an Agent

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerAgent",
    "params": {
      "name": "orchestrator-1",
      "creator": "0x<address>",
      "capabilities": ["nlp", "code", "data"]
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "agent_id": "<uuid>",
    "wallet_address": "0x<hex>",
    "status": "active"
  }
}
```

### Spawn a Child Agent

Spawn a sub-agent under a parent (max 50 children per parent):

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_spawnAgent",
    "params": {
      "parent_id": "<parent-agent-uuid>",
      "name": "data-analyst",
      "capabilities": ["data", "nlp"]
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "agent_id": "<child-uuid>",
    "parent_id": "<parent-uuid>",
    "name": "data-analyst"
  }
}
```

### Run an Agentic Task Loop

The agent calls an LLM with built-in tools (`spawn_agent`, `delegate_task`, `collect_results`, `complete`) and executes them iteratively until the task is complete or the step limit is reached:

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_runAgentTask",
    "params": {
      "agent_id": "<agent-uuid>",
      "task": "Analyze the latest network stats and summarize key metrics",
      "inference_url": "http://localhost:8080/v1/chat/completions"
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "agent_id": "<uuid>",
    "result": "Network stats summary: ..."
  }
}
```

### Create a Swarm

Create a pool of coordinated agents under an orchestrator:

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_createSwarm",
    "params": {
      "orchestrator_id": "<orchestrator-uuid>",
      "members": [
        {"name": "researcher", "capabilities": ["nlp", "data"]},
        {"name": "coder", "capabilities": ["code"]},
        {"name": "reviewer", "capabilities": ["code", "nlp"]}
      ],
      "max_members": 10,
      "task_timeout_secs": 300,
      "parallel": true
    },
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "swarm_id": "<swarm-uuid>",
    "orchestrator_id": "<orchestrator-uuid>"
  }
}
```

### Get Swarm Status

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_getSwarmStatus",
    "params": {"swarm_id": "<swarm-uuid>"},
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "swarm_id": "<uuid>",
    "orchestrator_id": "<uuid>",
    "status": "idle",
    "member_count": 3,
    "members": [
      {"agent_id": "<uuid>", "role": "researcher", "status": "Idle", "result": null},
      {"agent_id": "<uuid>", "role": "coder", "status": "Working", "result": null}
    ]
  }
}
```

Swarm lifecycle statuses: `idle`, `working`, `completed`. Member statuses: `Idle`, `Working`, `Completed`, `Failed`.

### Terminate a Swarm

```bash
curl -X POST https://rpc.tenzro.network \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_terminateSwarm",
    "params": {"swarm_id": "<swarm-uuid>"},
    "id": 1
  }'
```

**Response:**
```json
{
  "result": {
    "swarm_id": "<uuid>",
    "status": "terminated"
  }
}
```

---

## Common Workflows

### 0. Join as MicroNode (one-step setup)

The fastest way to get started on the Tenzro Network — no prior setup required:

1. Call `tenzro_joinAsMicroNode` with a display name
2. Receive a TDIP DID, MPC wallet address, 10 network capabilities, and chain ID
3. Optionally call `POST /faucet` to get 100 testnet TNZO
4. Start using all network features immediately

```python
from tools.tenzro_rpc import join_as_micro_node
result = join_as_micro_node("Alice")
# Returns: identity (DID), wallet (address), capabilities (10), network endpoints
```

CLI equivalent:
```bash
python tenzro_rpc.py join_network "Alice"
```

Falls back to `tenzro_participate` on older nodes.

---

### 1. Create wallet and get testnet tokens

1. Call `tenzro_createWallet` to provision a 2-of-3 MPC wallet (returns
   `wallet_id` + 32-byte hex `address` + base58 `display_address`)
2. Call `POST /faucet` with the 32-byte hex `address` to get 100 TNZO
3. Call `tenzro_getBalance` (or `eth_getBalance`) to confirm the balance

### 2. Register identity and send payment

1. Call `tenzro_registerIdentity` with a display name
2. Call `tenzro_createWallet` to provision the MPC wallet
3. Call `POST /faucet` for testnet tokens
4. Call `tenzro_signAndSendTransaction` (or `eth_sendRawTransaction` for
   pre-signed payloads) to send TNZO

### 3. Create agent with delegation scope

1. Register a human identity: `tenzro_registerIdentity` with `identity_type: "human"`
2. Register a machine identity: `tenzro_registerIdentity` with `identity_type: "machine"` and `controller_did`
3. Set delegation scope: `tenzro_setDelegationScope` with spending limits, allowed operations, protocols, and chains
4. Resolve the machine DID to verify: `tenzro_resolveIdentity`

### 4. Pay for a resource with x402

1. Create a payment challenge: `tenzro_createPaymentChallenge` with protocol `x402`, resource, amount, asset, and recipient
2. Sign the challenge and submit: `tenzro_verifyPayment` with challenge_id, signature, and payer info
3. Receive the receipt confirming settlement

### 5. Run AI inference

1. List available models: `tenzro_listModels` (optionally filter by category)
2. List endpoints: `tenzro_listModelEndpoints` to find running model services
3. Send a request: `tenzro_chat` with model ID and message

### 6. Bridge tokens cross-chain

1. Check available routes via MCP `get_bridge_routes` tool with source and destination chains
2. List adapters via MCP `list_bridge_adapters` tool to see available bridge providers
3. Execute bridge: `tenzro_bridgeTokens` with chain pair, asset, amount, sender, and recipient

### 7. Verify a proof

1. Call `POST /verify/zk-proof` with proof data
2. Check `valid` field in the response

### 8. Create a token and transfer across VMs

1. Create a token: `tenzro_createToken` with name, symbol, creator, and initial supply
2. Look up the token: `tenzro_getToken` with the symbol to get its token ID and EVM address
3. Check balances across VMs: `tenzro_getTokenBalance` to see native, EVM, SVM, and DAML balances
4. Transfer between VMs: `tenzro_crossVmTransfer` with token, amount, source/dest VM, and addresses
5. List all tokens: `tenzro_listTokens` to browse the full registry

### 9. Deploy a smart contract

1. Prepare contract bytecode (compiled Solidity, BPF program, or DAML archive)
2. Deploy: `tenzro_deployContract` with vm_type, bytecode, deployer address, and optional constructor args
3. The response contains the deployed contract address and gas used

### 10. Post a task and get it fulfilled

1. Call `tenzro_postTask` with title, description, task type, max price, and input
2. Check task status via `tenzro_getTask` — status starts as `open`
3. Providers submit quotes via `tenzro_submitQuote`; task transitions to `assigned` when accepted
4. Track completion via `tenzro_getTask` — status becomes `completed` with output populated
5. Cancel if needed via `tenzro_cancelTask` (only while `open` or `assigned`)

### 11. Publish and discover agent templates

1. Register an agent template: `tenzro_registerAgentTemplate` with name, description, template type, system prompt, and pricing
2. Browse available templates: `tenzro_listAgentTemplates` with optional filters (free_only, template_type, tag)
3. Get template details: `tenzro_getAgentTemplate` to retrieve the full template including system prompt and capabilities
4. Deploy a template: use the `system_prompt` field from the template as the AI agent's system instructions

---

## Error Handling

JSON-RPC errors follow standard format:
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32601,
    "message": "Method not found"
  },
  "id": 1
}
```

Common error codes:
- `-32700` — Parse error (invalid JSON)
- `-32600` — Invalid request
- `-32601` — Method not found
- `-32602` — Invalid params
- `-32603` — Internal error

Web API errors return HTTP status codes with JSON body:
```json
{
  "error": "description of error"
}
```

Faucet rate-limit errors return HTTP 429 with a `message` field indicating cooldown time.

---

## MCP Integration

If the Tenzro node has MCP enabled (port 3001), you can use the Model Context Protocol for richer tool-based integration. The MCP server exposes tools across 10 categories:

**Wallet & Ledger:**
- `get_balance` — Query TNZO balance by address
- `create_wallet` — Provision a self-custody Tenzro 2-of-3 MPC wallet (32-byte address)
- `send_transaction` — Send a TNZO transfer
- `request_faucet` — Request testnet tokens (100 TNZO, 24h cooldown)
- `get_block` — Get block by height from storage
- `get_block_range` — Batch-fetch a contiguous range of blocks for catch-up sync (max 256/call; returns `nextHeight` + `moreAvailable` for pagination across pruning gaps)
- `get_transaction` — Look up transaction by hash
- `get_node_status` — Node health, block height, peer count, uptime

**Identity & Delegation:**
- `register_identity` — Register human or machine DID via TDIP
- `register_machine_identity` — Register a machine identity controlled by a human DID
- `import_identity` — Import an existing identity by DID and private key
- `resolve_did` — Resolve DID to identity info, delegation scope
- `list_identities` — List all registered identities on the node
- `add_service` — Add a service endpoint to a DID document
- `add_credential` — Add a verifiable credential to an identity
- `set_delegation_scope` — Set spending limits, allowed operations/protocols/chains for machine identities

**Payments:**
- `create_payment_challenge` — Create payment challenge (MPP, x402, or native)
- `verify_payment` — Verify payment credential and settle on-chain
- `pay_mpp` — Pay for a resource using MPP (Machine Payments Protocol)
- `pay_x402` — Pay for a resource using x402 (HTTP 402 Payment Protocol)
- `payment_gateway_info` — Get supported payment protocols, networks, and assets
- `list_payment_sessions` — List active MPP payment sessions
- `get_payment_receipt` — Get details of a payment receipt
- `list_payment_protocols` — List supported payment protocols and their features

**AI Models & Inference:**
- `list_models` — List available AI models, filter by category or name
- `chat_completion` — Send chat completion to a served model
- `inference_request` — Send an inference request to a model
- `list_model_endpoints` — List running model service endpoints with URLs and status
- `register_model_endpoint` — Register a model service endpoint
- `get_model_endpoint` — Get details of a specific model endpoint
- `unregister_model_endpoint` — Unregister a model service endpoint
- `download_model` — Download a model from the registry
- `get_download_progress` — Get download progress for a model
- `serve_model` — Start serving a model for inference
- `stop_model` — Stop serving a model
- `delete_model` — Delete a downloaded model
- `discover_models` — Discover AI models available on the network

**Cross-Chain Bridge:**
- `bridge_tokens` — Bridge tokens between Tenzro, Ethereum, Solana, Base
- `get_bridge_routes` — Get available routes between two chains with fees
- `list_bridge_adapters` — List registered adapters (LayerZero, Chainlink CCIP, deBridge, Canton)

**Verification:**
- `verify_zk_proof` — Verify Plonky3 STARK proof over the KoalaBear field; requires `circuit_id` ∈ {inference, settlement, identity} and 4-byte LE field-chunk public inputs

**Staking & Providers:**
- `stake_tokens` — Stake TNZO tokens as Validator, ModelProvider, or TeeProvider
- `unstake_tokens` — Unstake TNZO tokens (initiates unbonding period)
- `register_provider` — Register as a provider with optional staking
- `get_provider_stats` — Get provider statistics: served models, inferences, staking totals
- `list_providers` — List all providers discovered via gossipsub; filter by provider_type (llm, tee, general)
- `set_role` — Set the node role (Validator, ModelProvider, TeeProvider, LightClient)
- `set_provider_schedule` — Set provider availability schedule
- `get_provider_schedule` — Get the current provider schedule
- `set_provider_pricing` — Set provider pricing configuration
- `get_provider_pricing` — Get the current provider pricing

**Task Marketplace:**
- `post_task` — Post a task to the decentralized AI task marketplace with TNZO escrow payment
- `list_tasks` — List marketplace tasks with optional filters (status, type, max_price, limit, offset)
- `get_task` — Get full details of a specific task by ID
- `cancel_task` — Cancel an open task posted by the caller
- `submit_quote` — Submit a fulfillment quote for an open task (price, model, estimated duration)
- `assign_task` — Assign a task to a specific provider/agent
- `complete_task` — Submit the result for a completed task
- `update_task` — Update an existing task

**Tokens & Contracts:**
- `create_token` — Create ERC-20 token via factory, register in unified registry
- `get_token_info` — Lookup token by symbol, EVM address, or token ID
- `list_tokens` — List registered tokens with optional VM type filter
- `get_token_balance` — Get TNZO balance across all VMs with decimal conversion
- `cross_vm_transfer` — Atomic cross-VM token transfer (TNZO pointer model)
- `wrap_tnzo` — Wrap native TNZO to a VM representation
- `swap_token` — Swap one token for another
- `deploy_contract` — Deploy bytecode to EVM/SVM/DAML via MultiVmRuntime

**Agent Marketplace:**
- `list_agent_templates` — Browse reusable AI agent templates, filter by type/tags/pricing/status
- `register_agent_template` — Publish a new agent template to the marketplace with pricing model
- `get_agent_template` — Get full details of an agent template by ID
- `update_agent_template` — Update an existing agent template
- `spawn_agent_from_template` — Spawn a new agent from a marketplace template
- `spawn_agent_template` — Spawn with identity and wallet provisioning
- `run_agent_template` — Run an agent spawned from a template
- `download_agent_template` — Download an agent template for local use
- `rate_agent_template` — Rate an agent template (1-5 stars) with optional review
- `search_agent_templates` — Search agent templates by free-text query
- `get_agent_template_stats` — Get usage statistics (spawn count, ratings, revenue)

**Agent Management:**
- `register_agent` — Register a new AI agent with identity and wallet
- `list_agents` — List all registered agents
- `spawn_agent` — Spawn a sub-agent from a parent agent
- `send_agent_message` — Send a message between agents
- `run_agent_task` — Run an autonomous task via the agentic execution loop
- `delegate_task` — Delegate a task to an agent or sub-agent
- `discover_agents` — Discover agents available on the network
- `fund_agent` — Fund an agent's wallet with TNZO
- `agent_pay_for_inference` — Execute the agent payment pipeline for inference
- `create_swarm` — Create a swarm of agents
- `get_swarm_status` — Get swarm status
- `terminate_swarm` — Terminate a swarm

**Skills Registry:**
- `register_skill` — Register a new skill
- `list_skills` — List skills in the registry
- `get_skill` — Get details of a specific skill
- `search_skills` — Search skills by keyword
- `use_skill` — Invoke a skill by ID
- `update_skill` — Update an existing skill
- `get_skill_usage` — Get usage statistics for a skill

**Tools Registry:**
- `register_tool` — Register a new tool (MCP server endpoint)
- `list_tools` — List registered tools
- `get_tool` — Get details of a specific tool
- `search_tools` — Search tools by keyword
- `use_tool` — Invoke a tool via its MCP endpoint
- `update_tool` — Update an existing tool
- `get_tool_usage` — Get usage statistics for a tool

**Settlement:**
- `settle` — Submit a settlement request
- `get_settlement` — Get settlement details by ID
- `create_escrow` — Create an escrow for a payment
- `release_escrow` — Release an escrow
- `open_payment_channel` — Open a micropayment channel
- `close_payment_channel` — Close a micropayment channel

**Governance:**
- `list_proposals` — List governance proposals
- `create_proposal` — Create a governance proposal
- `vote` — Vote on a proposal (for/against/abstain)
- `get_voting_power` — Get voting power for an address
- `delegate_voting_power` — Delegate voting power to another address

**Canton / DAML:**
- `list_canton_domains` — List Canton synchronizer domains
- `list_daml_contracts` — List DAML contracts
- `submit_daml_command` — Submit a DAML command to Canton

**Network & Node:**
- `get_node_status` — Node health, block height, peers, uptime
- `peer_count` — Get connected peer count
- `syncing` — Get sync status
- `get_hardware_profile` — Get hardware profile (CPU, RAM, GPU, TEE)
- `list_accounts` — List all accounts/wallets
- `get_finalized_block` — Get the latest finalized block
- `export_config` — Export the node configuration
- `get_transaction` — Get transaction details by hash
- `get_nonce` — Get nonce for an address
- `get_transaction_history` — Get transaction history for an address

**EVM Compatibility:**
- `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`, `eth_chainId`
- `eth_gasPrice`, `eth_estimateGas`, `eth_call`, `eth_getCode`
- `eth_getStorageAt`, `eth_getLogs`, `eth_getTransactionReceipt`
- `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_syncing`, `eth_accounts`
- `net_peerCount`, `net_version`, `net_listening`

Connect to MCP at `https://mcp.tenzro.network/mcp` using Streamable HTTP transport.
