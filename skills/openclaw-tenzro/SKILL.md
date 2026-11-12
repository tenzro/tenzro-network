---
name: tenzroclaw
version: 0.1.0
author: Tenzro Network
description: TenzroClaw — OpenClaw skill for the Tenzro Network. Create wallets, send transactions, check balances, register identities, manage credentials and services, set delegation scopes, exercise GDPR Article 17 right-to-erasure (forget_identity), make payments via AP2 v0.2 (sign + verify + validate-pair), MPP, x402 v1, Stripe SPT (SharedPaymentToken), ERC-8004 (Jan 2026 revision) Trustless Agents Registry (22 surfaces across IdentityRegistry, ReputationRegistry, ValidationRegistry), run AI inference, manage model endpoints, bridge tokens cross-chain, verify proofs, read network duties, look up tokens across VMs, deploy smart contracts, transfer tokens across VMs, manage settlement and escrow, participate in governance, resolve a node's DID Document to every address it answers on, and discover and invoke any JSON-RPC method the node serves through the universal gateway.
tags:
  - blockchain
  - ai
  - identity
  - right_to_erasure
  - payments
  - ap2
  - stripe_spt
  - erc8004
  - bridge
  - inference
  - web3
  - autonomous_agents
  - tokens
  - contracts
  - multi_vm
  - settlement
  - escrow
  - governance
  - evm
  - file_storage
  - erasure_coding
  - rpc_gateway
  - node_addressing
---

# TenzroClaw

You can interact with the Tenzro blockchain network using its JSON-RPC, Web API, and MCP endpoints. Tenzro is a settlement layer designed for the AI age, providing identity, settlement, TEE security, and ZK proof verification.

## Endpoints

| Service  | URL                             | Description                                  |
| -------- | ------------------------------- | -------------------------------------------- |
| JSON-RPC | `https://rpc.tenzro.com`        | EVM-compatible JSON-RPC (port 8545)          |
| Web API  | `https://api.tenzro.com`        | REST verification and status API (port 8080) |
| MCP      | `https://mcp.tenzro.com/mcp`    | Model Context Protocol server (port 3001)    |
| A2A      | `https://a2a.tenzro.com`        | Agent-to-Agent protocol (port 3002)          |

For local development, replace the hostnames with `localhost` and use the ports shown above.

## Token

**TNZO** is the native token with 18 decimal places. Amounts in the RPC are in wei (1 TNZO = 10^18 wei). The default gas price is 1 Gwei (10^9 wei).

## Authentication

Read operations (block lookups, balances, agent cards, etc.) need no authentication.

Write operations use **OAuth 2.1 + DPoP** (RFC 6749 successor + RFC 9449) on top of Ed25519/Secp256k1 transaction signatures. Onboarding mints an ES256 JWT access token (1h TTL) and an opaque refresh token (30d TTL); the access token is sent as `Authorization: Bearer <token>` and, when DPoP-bound, accompanied by a fresh DPoP proof in the `DPoP` header signed by the holder key whose RFC 7638 thumbprint (`jkt`) was supplied at onboarding.

### Onboarding RPCs

- `tenzro_onboardHuman` — provisions a `did:tenzro:human:*` identity, hardware-bound wallet, and access + refresh tokens.
- `tenzro_onboardDelegatedAgent` — issues an agent identity bound to a controller DID with a delegation scope.
- `tenzro_onboardAutonomousAgent` — issues a fully autonomous agent identity backed by a TNZO bond.

Each call returns `{ identity, wallet, access_token, refresh_token, expires_in, refresh_token_expires_in, dpop_bound, authorization_details, ... }`.

### Refresh and bridge RPCs

- `tenzro_refreshToken` — exchange a refresh token for a new access token and a new refresh token. The request carries a DPoP proof from the key the refresh token is bound to and no access token; each refresh token is good for one exchange.
- `tenzro_revokeJwt` / `tenzro_revokeIdentity` — revoke a single JWT by `jti` or cascade-invalidate every JWT minted under a DID.

### Delegation and AS metadata RPCs

- `tenzro_exchangeToken` — RFC 8693 OAuth 2.0 Token Exchange. Mint a narrower child JWT bound to a different DPoP key with a strict subset of the parent's RAR grants and AAP capabilities, extending the act-chain by one hop.
- `tenzro_introspectToken` — RFC 7662 OAuth 2.0 Token Introspection. Returns `{active: true, ...claims}` on success or the minimal `{"active": false}` per RFC 7662 §2.2 when the token is unknown, expired, or revoked.
- `tenzro_oauthDiscovery` — RFC 8414 / RFC 9728 metadata document. Mirrors `GET /.well-known/openid-configuration`, augmented with AAP extensions (`authorization_details_types_supported`, `aap_claims_supported`, `dpop_signing_alg_values_supported`).

The `dpop_jkt` parameter on every onboarding/refresh/link call is the RFC 7638 SHA-256 thumbprint of the holder's Ed25519 public key. Pass it to bind the issued token to that key — every subsequent privileged call must then carry a DPoP proof signed by the same key. **Strongly recommended.**

When operating from MCP/SDK/CLI clients, call `tenzro auth refresh` to keep the locally cached token current; the CLI persists the latest tokens to `~/.tenzro/config.json`.

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

Create a wallet bound to a key held in your own hardware: a passkey for a
human, a TPM 2.0 or Secure Enclave for a machine. The private key never
leaves the device and the node never sees it.

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
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
    "key_type": "Ed25519",
    "threshold": 2,
    "total_shares": 3
  },
  "id": 1
}
```

The 32-byte hex `address` is the canonical form used by `eth_getBalance`
and all transaction RPCs. The `display_address` is a
human-friendly base58 alias (informational).

### Check Balance

```bash
curl -X POST https://rpc.tenzro.com \
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
{
  "jsonrpc": "2.0",
  "method": "eth_getBalance",
  "params": { "address": "0x..." },
  "id": 1
}
```

### Send Transaction

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_sendRawTransaction",
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
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_blockNumber","params":{},"id":1}'
```

### Get Block by Number

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_getBlock","params":{"height":0},"id":1}'
```

Use `"params":["latest"]` for the most recent block.

### Get Chain ID

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":{},"id":1}'
```

The answer is the chain id the network's genesis sets: `0x3444` (13380) on the preview network.

### Get Node Info

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_getNodeStatus","params":{},"id":1}'
```

### Get Token Supply

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_totalSupply","params":{},"id":1}'
```

### List Registered Models

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tenzro_listModels","params":{"category":"text"},"id":1}'
```

Optionally filter by `category` (text, image, audio, video, text_image, text_audio, multimodal) or `name` (substring match).

---

## Identity (Tenzro Identity Protocol)

Tenzro uses decentralized identifiers (DIDs) for both humans and machines.

- Human DID format: `did:tenzro:human:<uuid>`
- Machine DID format: `did:tenzro:machine:<controller>:<uuid>` or `did:tenzro:machine:<device-key-id>` (autonomous)

### Register Identity (human, machine, or autonomous)

`tenzro_registerIdentity` dispatches on the `identity_type` field. Three types are supported and each takes a different parameter shape.

#### Human

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerIdentity",
    "params": {
      "identity_type": "human",
      "display_name": "Alice"
    },
    "id": 1
  }'
```

`identity_type` defaults to `"human"` when omitted, so older callers passing only `display_name` continue to work. The DID is issued with prefix `did:tenzro:human:<uuid>`.

#### Machine (controlled — bound to a human DID)

Requires the controller's DID and a list of capabilities. An optional `delegation_scope` constrains spending and operations the machine may perform on the controller's behalf.

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerIdentity",
    "params": {
      "identity_type": "machine",
      "controller_did": "did:tenzro:human:<controller-uuid>",
      "capabilities": ["inference", "trading"],
      "delegation_scope": {
        "max_transaction_value": "1000000000000000000",
        "max_daily_spend":       "5000000000000000000",
        "allowed_operations":    ["transfer", "inference"],
        "allowed_payment_protocols": ["mpp", "x402"],
        "allowed_chains":        ["tenzro"]
      }
    },
    "id": 1
  }'
```

The DID is issued with prefix `did:tenzro:machine:<controller-uuid>:<uuid>`. Amount fields accept either decimal strings (recommended for values larger than 2⁶³) or numbers.

#### Autonomous (no controller)

Self-sovereign machine identity with no human owner. Capabilities required.

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_registerIdentity",
    "params": {
      "identity_type": "autonomous",
      "capabilities": ["inference"]
    },
    "id": 1
  }'
```

The DID is issued with prefix `did:tenzro:machine:<device-key-id>` (no controller segment).

#### Response (all types)

```json
{
  "jsonrpc": "2.0",
  "result": {
    "did": "did:tenzro:<type>:<uuid>",
    "identity_type": "<type>",
    "status": "registered"
  },
  "id": 1
}
```

For all three types, pass the public half of your hardware-held key as `"public_key": "<hex>"`; the node never generates or returns a private key.

### Resolve Identity

```bash
curl -X POST https://rpc.tenzro.com \
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
curl -X POST https://rpc.tenzro.com \
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
hardware-bound wallet, and all 10 network capabilities in a single RPC call.

```bash
curl -X POST https://rpc.tenzro.com \
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
    "identity": {
      "did": "did:tenzro:human:<uuid>",
      "display_name": "Alice",
      "identity_type": "micro_node",
      "status": "active"
    },
    "wallet": {
      "wallet_id": "<id>",
      "address": "0x<hex>",
      "public_key": "0x<hex>"
    },
    "capabilities": {
      "inference": true,
      "payments": true,
      "agent_collaboration": true,
      "mcp_tools": true,
      "task_execution": true,
      "chain_query": true,
      "smart_contracts": true,
      "tee_services": true,
      "bridge": true,
      "governance": true
    },
    "origin": "cli",
    "participant_type": "human",
    "role": "micro_node",
    "network": {
      "rpc": "https://rpc.tenzro.com",
      "mcp": "https://mcp.tenzro.com/mcp",
      "a2a": "https://a2a.tenzro.com"
    }
  },
  "id": 1
}
```


**Python (tenzro_rpc.py):**

```python
from tools.tenzro_rpc import join_as_micro_node
result = join_as_micro_node("Alice")
print(result["identity"]["did"])    # did:tenzro:human:<uuid>
print(result["wallet"]["address"])  # 0x<hex>
```

### Agent Terms

An agent's spending limits, allowed operations, payment protocols, counterparties and chains are its consensus Terms, approved by its root with a passkey or hardware key (`SetAgentTerms`). Read them, the root kind and the spend against them with `tenzro_getAgentTerms`.

### Create Payment Challenge

```bash
curl -X POST https://rpc.tenzro.com \
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
curl -X POST https://rpc.tenzro.com \
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

---

## AI Models & Inference

### List Models

```bash
curl -X POST https://rpc.tenzro.com \
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
curl -X POST https://rpc.tenzro.com \
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
curl -X POST https://rpc.tenzro.com \
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

Tenzro uses a decentralized provider registry — nodes that serve AI models or TEE services broadcast a `ProviderAnnouncement` every 60 seconds on the `tenzro/providers` gossip topic. All peers merge incoming announcements into their local `network_providers` cache, so any node can discover every provider without a central registry.

### List Network Providers

```bash
curl -X POST https://rpc.tenzro.com \
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
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listProviders",
    "params": {"provider_type": "ai"},
    "id": 1
  }'
```

**Provider types:** `ai` (every model class), `tee`, `storage`, `compute`, `general`

The listing comes a page at a time: `limit` (default 50, at most 200) and
`cursor` (the `next_cursor` of the page before). `next_cursor` is `null` on the
last page.

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": {
    "providers": [
      {
        "endpoint_id": "<iroh endpoint id, hex>",
        "provider_address": "0x<hex>",
        "provider_type": "ai",
        "served_models": ["gemma4-9b", "qwen3.5-0.8b"],
        "key_required_models": [],
        "capabilities": ["inference"],
        "status": "active",
        "region": "eu",
        "jurisdiction": "DE",
        "model_load": [],
        "load_as_of_ms": 1761400000000,
        "hardware_tier": "datacenter_gpu",
        "identity_anchor": "tpm",
        "source": "network"
      }
    ],
    "next_cursor": null
  },
  "id": 1
}
```

`source` is `local` for the node answering and `network` for a peer. Nodes that
serve delegated agents follow the model providers, by identity only
(`machine_did`, `operator_did`, `capabilities`, `live`). Provider announcements
are refreshed every 60 seconds; entries expire after 120 seconds if not
refreshed.

**Python (tenzro_rpc.py):**

```python
from tools.tenzro_rpc import call_rpc
page = call_rpc("tenzro_listProviders", {"provider_type": "ai", "limit": 50})
for p in page["providers"]:
    print(p["endpoint_id"], p["provider_type"], p["served_models"])
# page["next_cursor"], when set, is the cursor for the next page
```

---

## Cross-Chain Bridge

TNZO moves to and from other chains only over governed routes: a
CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana, IBC,
Bitcoin deposits and contract routes. Every route enforces committee attestations, a circuit
breaker, per-transfer and per-epoch caps, and the supply invariant.

### List Routes

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tenzro_listBridgeRoutes", "params": {}, "id": 1}'
```

Each route reports its caps, what it has minted this epoch, the TNZO locked
for it, what is outstanding on the other chain, and whether it is paused.

### Send TNZO Out

An outbound transfer is a `Bridge` transaction the holder's wallet signs
(`{"Bridge":{"op":{"outbound":{"target_chain","recipient","amount"}}}}`).
The amount locks in the route's vault and the route queues the outbound
message its committee attests on the other chain. `bridge_outbound` sends it

### Deliver an Inbound Transfer

Relayers submit the route committee's signed delivery as a `Bridge`
inbound transaction from their own wallet. The recipient is credited only
within the route's caps and outstanding supply, once.

---

## Token Registry & Contracts

A token is created by a `Token` transaction its issuer signs; the same
transaction type carries `mint`, `burn`, `transfer` and the issuer's
compliance controls. Tenzro has a unified token registry spanning all VMs (EVM, SVM). Tokens created via the factory are automatically registered and addressable across all VMs using the Sei V2 pointer model (no bridge risk, no liquidity fragmentation).

### Get Token Info

Look up a token by symbol, EVM address, or token ID.

```bash
curl -X POST https://rpc.tenzro.com \
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
    "tempo_address": null,
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
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tenzro_listTokens",
    "params": {"vm_type": "evm", "limit": 50},
    "id": 1
  }'
```

**VM type filter:** `evm`, `svm`, `native`. Omit for all tokens. Max `limit` is 100.

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
curl -X POST https://rpc.tenzro.com \
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
    "native": {
      "balance": "100000000000000000000",
      "decimals": 18,
      "display": "100.000000 TNZO"
    },
    "evm_wtnzo": { "balance": "100000000000000000000", "decimals": 18 },
    "svm_wtnzo": { "balance": "100000000000", "decimals": 9 }
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

### Calls across VMs

Every VM reads the same balance of a token, so nothing is wrapped or bridged
between VMs. A transfer, in one VM or across several, is one contract-call
transaction: an ordered list of calls, each naming its VM, the code it calls
and its calldata. Either every call takes effect or none does, and the gas is
the sum over the calls.

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -H "Authorization: DPoP <jwt>" -H "DPoP: <proof>" \
  -d '{
    "jsonrpc": "2.0",
    "params": {
      "from": "0x<address>",
      "to": "0x<address>",
      "value": 0,
      "gas_limit": 500000,
      "tx_type": {"ContractCall": {"calls": [
        {"vm": "evm", "to": [/* 20-byte ERC-20 contract */], "value": 0, "data": [/* transfer(address,uint256) */]},
        {"vm": "svm", "to": [/* 32-byte SPL Token program */], "value": 0, "data": [/* [n] [accounts] [instruction] */]}
      ]}}
    },
    "id": 1
  }'
```

The token interfaces are the EVM's ERC-20 and the SVM's SPL Token program
(`Transfer` for wTNZO, `TransferChecked` with the mint for any token).

### Deploy Contract

Deploy smart contract bytecode to EVM or SVM via the MultiVmRuntime.

A deployment is a `ContractDeploy` transaction the deployer signs on its own hardware, submitted with `tenzro_deployContract` (the same fields as `tenzro_sendRawTransaction`). The signature covers the code, the constructor arguments, the nonce, the chain and the sender; the contract is created when a block executes it, at the address its receipt reports. From the CLI:

```bash
tenzro contract deploy --bytecode 0x<hex_bytecode> --args 0x<hex_args>
```

**Response:** `{"tx_hash": "0x…", "status": "admitted"}`.

**Python (tenzro_rpc.py):** `deploy_contract(signed_tx)` submits a transaction signed elsewhere.

---

## Web API

### Node Status

```bash
curl https://api.tenzro.com/status
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
curl https://api.tenzro.com/health
```

### Verify ZK Proof

```bash
curl -X POST https://api.tenzro.com/verify/zk-proof \
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
curl -X POST https://api.tenzro.com/verify/tee-attestation \
  -H "Content-Type: application/json" \
  -d '{
    "vendor": "intel_tdx",
    "report_data": "<hex>"
  }'
```

Supported vendors: `intel_tdx`, `amd_sev_snp`, `aws_nitro`.

### Verify Transaction Signature

```bash
curl -X POST https://api.tenzro.com/verify/transaction \
  -H "Content-Type: application/json" \
  -d '{
    "tx_hash": "<hex>",
    "signature": "<hex>",
    "sender": "<hex>"
  }'
```

### Verify Settlement Receipt

```bash
curl -X POST https://api.tenzro.com/verify/settlement \
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
curl -X POST https://api.tenzro.com/verify/inference \
  -H "Content-Type: application/json" \
  -d '{
    "model_id": "<model>",
    "input_hash": "<hex>",
    "output_hash": "<hex>",
    "provider": "<address>"
  }'
```

---

## Network Duties

A duty is work the chain pays the first prover for: a route's settlement-lock reconciliation each epoch, or the install of a voided agent grant on another chain. Its reward sits in a keyless vault; the transaction that proves the work pays it. Task markets for agents and machines run in harnesses over escrows, not on chain.

```bash
curl -X POST https://rpc.tenzro.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "method": "tenzro_listDuties", "params": {}, "id": 1}'
```

---

## Common Workflows

### 0. Join as MicroNode (one-step setup)

The fastest way to get started on the Tenzro Network — no prior setup required:

1. Call `tenzro_joinAsMicroNode` with a display name
2. Receive a TDIP DID, hardware-bound wallet address, 10 network capabilities, and chain ID
3. Start using all network features immediately

```python
from tools.tenzro_rpc import join_as_micro_node
result = join_as_micro_node("Alice")
# Returns: identity (DID), wallet (address), capabilities (10), network endpoints
```

CLI equivalent:

```bash
python tenzro_rpc.py join_network "Alice"
```


---

### 1. Create a wallet and fund it

   `wallet_id` + 32-byte hex `address` + base58 `display_address`)
2. Fund the `address` with a transfer from an account that holds TNZO
3. Call `tenzro_getBalance` (or `eth_getBalance`) to confirm the balance

### 2. Register identity and send payment

1. Call `tenzro_registerIdentity` with a display name
3. Fund the wallet with a transfer from an account that holds TNZO
   sign both legs (Ed25519 + ML-DSA-65) locally and submit via
   `tenzro_sendRawTransaction` — the node never holds the secret

### 3. Create agent with delegation scope

1. Register a human identity: `tenzro_registerIdentity` with `identity_type: "human"`
2. Register a machine identity: `tenzro_registerIdentity` with `identity_type: "machine"` and `controller_did`
3. Approve the agent's Terms with the root's passkey (`SetAgentTerms`): spending limits, allowed operations, protocols, and chains
4. Resolve the machine DID to verify: `tenzro_resolveIdentity`

### 4. Pay for a resource

1. Create a payment challenge: `tenzro_createPaymentChallenge` with resource, amount, asset, and recipient
2. Sign the challenge and submit: `tenzro_verifyPayment` with challenge_id, signature, and payer info
3. Receive the receipt confirming settlement

### 5. Run AI inference

1. List available models: `tenzro_listModels` (optionally filter by category)
2. List endpoints: `tenzro_listModelEndpoints` to find running model services
3. Send a request: `tenzro_chat` with model ID and message

### 6. Send TNZO to another chain

1. Check the governed route: `tenzro_listBridgeRoutes` (caps, usage, supply, paused)
2. Send it: a `Bridge` outbound transaction the holder's wallet signs (`bridge_outbound`)

### 7. Verify a proof

1. Call `POST /verify/zk-proof` with proof data
2. Check `valid` field in the response

### 8. Create a token and transfer across VMs

1. Create a token: a `Token` create transaction the issuer signs
2. Look up the token: `tenzro_getToken` with the symbol to get its token ID and EVM address
3. Check balances across VMs: `tenzro_getTokenBalance` to see native, EVM and SVM balances
4. Transfer between VMs: a contract-call transaction whose calls use each VM's token interface
5. List all tokens: `tenzro_listTokens` to browse the full registry

### 9. Deploy a smart contract

1. Prepare EVM creation code (compiled Solidity)
2. Sign a `ContractDeploy` transaction with the deployer's hardware key and submit it with `tenzro_deployContract`
3. The response carries the transaction hash; the receipt reports the contract address once a block executes it

### 10. Pay for work on delivery

1. Agree the work in a task market a harness runs over the public RPC
2. Fund one escrow per milestone (`CreateEscrow` with a `reference` the harness gives), released by you or by the panel the task names
3. Check delivery evidence with `tenzro_verifyEvidence` before releasing

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

---

## MCP Integration

If the Tenzro node has MCP enabled (port 3001), you can use the Model Context Protocol for richer tool-based integration. The node's MCP server exposes tools including:

**Wallet & Ledger:**

- `get_balance` — Query TNZO balance by address
- `get_block` — Get block by height from storage
- `get_block_range` — Batch-fetch a contiguous range of blocks for catch-up sync (max 256/call; returns `nextHeight` + `moreAvailable` for pagination across pruning gaps)
- `get_transaction` — Look up transaction by hash
- `get_node_status` — Node health, block height, peer count, uptime

**Identity & Delegation:**

- `register_identity` — Register human or machine DID via TDIP
- `resolve_did` — Resolve DID to identity info, delegation scope

**Payments:**

- `create_payment_challenge` — Create payment challenge (MPP, x402, or native)
- `verify_payment` — Verify payment credential and settle on-chain

**AI Models & Inference:**

- `list_models` — List available AI models, filter by category or name
- `chat_by_intent` — Select and run in one call. Dispatch is pinned to the offer that was scored, so the price quoted is the price settled and the provider share goes to the address that offer named; the decision comes back under `route`
- `record_route_outcome` — Report how a routed call turned out (`resolved` / `escalated` / `failed`) so per-cluster error rates reflect what happened. In practice this carries `escalated`; the other two are recorded from the dispatch itself
- `route_difficulty_stats` — Read the cluster map and a model's per-cluster outcome counters. An operator diagnostic; `enabled` false means the node routes on declared metadata alone
- `list_model_endpoints` — List running model service endpoints with URLs and status
- `get_model_provenance` — Get a model's provenance by name (Hub repository or model id) or manifest root: its content-addressed manifests, the origins that observed each, and whether they agree (`verified`); optional `file` adds that file's Merkle inclusion proof
- `stop_model` — Stop serving a model
- `discover_models` — Discover AI models available on the network
- `get_router_metrics` — Read the inference router's live metrics: requests routed, hedges dispatched, hedges won, deadline-exceeded requests

**Cross-Chain Bridge:**

- `list_bridge_routes` — Every governed route with caps, usage and supply
- `get_bridge_route` — One route by transport and external chain
- `bridge_outbound` — Send TNZO out (holder-signed)

**Verification:**

- `verify_zk_proof` — Verify Plonky3 STARK proof over the KoalaBear field; requires `circuit_id` ∈ {inference, settlement, identity} and 4-byte LE field-chunk public inputs

**Staking & Providers:**

- `get_provider_stats` — Get provider statistics: served models, inferences, staking totals
- `list_providers` — List the providers discovered via gossip, a page at a time (`limit`, `cursor`); filter by provider_type (ai, tee, storage, compute, database, cloud, general). `ai` covers every model class — text, multimodal, image, video, audio.
- `set_provider_pricing` — Set provider pricing configuration
- `get_provider_pricing` — Get the current provider pricing

**Network Duties:**

- `list_duties` — Open network duties the chain pays the first prover for
- `get_duty` — One duty by id

**Tokens & Contracts:**

- `get_token_info` — Lookup token by symbol, EVM address, or token ID
- `list_tokens` — List registered tokens with optional VM type filter
- `get_token_balance` — Get TNZO balance across all VMs with decimal conversion
- `deploy_contract` — Submit a signed `ContractDeploy` transaction (EVM creation code)

**Settlement:**

- `create_escrow` — Create an escrow for a payment
- `release_escrow` — Release an escrow
- `open_payment_channel` — Open a micropayment channel
- `close_payment_channel` — Close a micropayment channel

**Governance:**

- `list_proposals` — List on-chain proposals, newest first (filter by kind)
- `governance_get` — Read a proposal, enacted policy or grant
- `get_voting_power` — Get the bonded stake an address votes with

**Network & Node:**

- `get_node_status` — Node health, block height, peers, uptime
- `get_transaction` — Get transaction details by hash

**EVM compatibility** (JSON-RPC methods on the RPC endpoint, not MCP tools):

- `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`, `eth_chainId`
- `eth_gasPrice`, `eth_estimateGas`, `eth_call`, `eth_getCode`
- `eth_getStorageAt`, `eth_getLogs`, `eth_getTransactionReceipt`
- `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_syncing`, `eth_accounts`
- `net_peerCount`, `net_version`, `net_listening`

Connect to MCP at `https://mcp.tenzro.com/mcp` using Streamable HTTP transport.
