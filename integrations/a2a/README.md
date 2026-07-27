# Tenzro A2A Server

[![Python](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![A2A Protocol](https://img.shields.io/badge/A2A-0.2.0-blue)](https://a2a-protocol.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

Connect AI agents to Tenzro Network using Google's [Agent-to-Agent (A2A)](https://a2a-protocol.org) protocol.

## Overview

The Tenzro A2A server is an installable Python package that lets any A2A-compatible agent interact with the blockchain — query balances, send transactions, manage identities, spawn sub-agents, trade on marketplaces, deploy contracts, and more. Install with `pip install tenzro-a2a-server` and run locally, or connect directly to the live testnet endpoint.

**Live testnet:** `https://a2a.tenzro.xyz`
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

> Note: the verification API at `api.tenzro.xyz` exposes `/verify/*`, `/health`, `/status`, and `/faucet` — no redundant `/api/` prefix (the subdomain already conveys it).

## Quick Start

### Discover capabilities

```bash
curl https://a2a.tenzro.xyz/.well-known/agent.json
```

### Send a task

```bash
curl -X POST https://a2a.tenzro.xyz/a2a \
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
curl -X POST https://a2a.tenzro.xyz/a2a/stream \
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
curl -X POST https://a2a.tenzro.xyz/a2a \
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

The Tenzro A2A agent exposes skills covering blockchain, AI, identity, payments, lifecycle, bonds, capital markets, multi-party workflows, EVM primitives, cross-chain reach, BTC-secured staking, chain-agnostic discovery, Canton 3.5+ JSON Ledger API, decentralized storage, compute rental, distributed MoE serving, generative image and video, local discovery + LAN clustering, and agent orchestration. The Agent Card at `tenzro_a2a_server/agent_card.py` is the authoritative source for skill IDs and descriptions.

### Core Blockchain

| Skill | ID | Description |
|-------|-----|-------------|
| **Wallet Operations** | `wallet` | Create wallets, check balances, send TNZO transactions |
| **Token Management** | `token` | Create ERC-20 tokens, cross-VM transfers, wrap TNZO |
| **Smart Contracts** | `contract` | Deploy contracts to EVM, SVM, or DAML |
| **NFT Management** | `nft` | Create collections, mint, transfer, and query NFTs across VMs |
| **Staking & Providers** | `staking` | Stake TNZO, register as validator/provider |
| **Validator Lifecycle** | `validator-lifecycle` | Query a single validator-registry entry, list candidates / active / jailed validators, and rotate consensus + ML-DSA-65 + BLS12-381 keys. A rotation is signed offline with the *current* consensus key and fanned out to every active validator before the next epoch boundary |

### Identity & Payments

| Skill | ID | Description |
|-------|-----|-------------|
| **Identity Management** | `identity` | Register/resolve DIDs (TDIP), set usernames, GDPR Article 17 right-to-erasure (`forget_identity`) |
| **Passkey-First Custody** | `passkey-wallet` | Enroll a passkey-bound ERC-4337 smart account, add social-recovery guardians, initiate and finalize guardian-quorum recovery to rotate to a new passkey, grant scoped session keys to agents, install hardware signers (Ledger / Trezor / GridPlus / YubiKey), and query installed validators. Signing keys never leave the user's hardware secure element |
| **Approval Workflow** | `approval` | Asynchronous request → review → decide → retry loop for actions that need out-of-band signoff. An always-ask action returns JSON-RPC `-32002` carrying `data.approval_id`; the approver lists pending requests for their DID, inspects one, then decides. Approvals are single-use and checked for action parity, so one granted for 10 TNZO cannot be redeemed against 9000. A denial returns `-32001` with the approver's `deny_reason`. Supplying `approver_did` on decide refuses a decision from anyone but the recorded approver |
| **Settlement & Payments** | `settlement` | Micropayment channels, escrow, batch settlement |
| **AP2 & x402 Payments** | `ap2-payments` | AP2 v0.2 sign + verify + validate-pair (checkout → payment) for agent-to-agent autonomous financial transactions, with nested-ceiling enforcement: AP2 CheckoutMandate constraints + TDIP `DelegationScope` + runtime `SpendingPolicy` + on-chain escrow balance when the pair carries an `escrow_id` + Stripe SPT `usage_limits` when it carries an `spt_grant_id`. An identifier that fails to resolve is a refusal, not a skip. Also covers the x402 Bazaar: sellers register HTTP-402 monetized resources (scheme `tenzro-hybrid` / `exact-eip3009` / `permit2` / `erc7710`), buyers discover them by scheme / network / asset / tags, and either side verifies a server-signed offer or derives a deterministic payment id |
| **Stripe SPT** | `stripe-spt` | SharedPaymentToken protocol description, plus dispatch of a verified webhook payload: a settlement outcome cross-writes reputation to the ERC-8004 ReputationRegistry against the agent's `agentId`, and `granted_token.deactivated` cascades into TDIP `apply_remote_revocation`. A confirm clears four ceilings — TDIP DelegationScope, runtime SpendingPolicy, the token's `usage_limits`, and the AP2 cart total |
| **Delivery-versus-Payment & Netting** | `dvp-netting` | Bundle delivery and payment legs into an all-or-compensate DvP saga backed by on-chain escrow, and collapse a set of bilateral obligations into a minimal net settlement instruction set via multilateral netting |
| **Capital Intent** | `capital` | The capital-markets analog of an AP2 Intent Mandate — a signed, expiring authorization to acquire / exit / rebalance / hedge / yield a basket of tokenized assets under a regulatory regime, KYA ceilings, and per-leg constraints. Solvers bid, an assigner picks (auto-ranked by ERC-8004 reputation + price + eta), and the lifecycle runs Open → Quote → Assign → Execute → Verify (or Compensate) → Settle. 1:1 backing flows through reserve attestations, which gate attested mint |
| **Stable-Asset Issuance** | `stable-asset` | Issuer-agnostic stable-unit issuance layered on the Secure-Mint reserve floor. An issuer registers a unit, then mints and redeems against it; mints are hard-gated so circulating supply can never exceed the attested reserve. Policies carry a reserve source (custodial attester or on-chain vault), a PoR feed id, allowed settlement rails, and a settlement destination. Registration requires the `issuer` API-key scope |
| **Secure-Mint Registry** | `secure-mint` | Per-token 1:1 reserve-attestation invariant for tokenized real-world assets — enforces `circulating + amount ≤ reserve` at every mint. Policies carry the PoR feed id, attester DID, attestation hash, `attested_at`, and `ttl_secs`; the check is non-mutating while apply atomically updates `circulating` |
| **EIP-7702 Delegation** | `eip7702` | Pectra Type-4 helpers: compute the secp256k1 signing hash over `MAGIC(0x05) ‖ rlp([chain_id, delegate_address, nonce])`, build the 23-byte designator (`0xef0100 ‖ delegate_address`) written into the EOA's code slot once an authorization is accepted, and decode arbitrary code to extract a delegate when it is a valid designator. The returned hash is signed with the EOA's key out of band |
| **Permit2 SignatureTransfer** | `permit2` | EIP-712 SignatureTransfer on the canonical Tenzro Permit2 verifying contract (`0x0000…00001023`). Read the per-chain domain separator, compute the digest a user signs (with optional witness binding, used by ERC-7683 origin opens to bind a permit to one cross-chain order), atomically verify a signed permit and consume its `(owner, nonce)` bitmap slot, and read nonce-consumption state. The bitmap follows the Uniswap word/bit layout so users can sign permits in parallel |
| **Price Oracle** | `oracle` | Read asset prices from the node's price oracle. Pass a single `symbol` or a `symbols` list; `price_usd_8dp` is the USD price scaled by 1e8. Symbols with no live feed come back under `unavailable` rather than failing the request |

### Governance & Treasury

| Skill | ID | Description |
|-------|-----|-------------|
| **Treasury Multisig Withdrawals** | `treasury` | Network treasury withdrawal flow. Approvals are signed over the `tenzro/treasury/withdrawal-approval` preimage with the approver's Ed25519 or Secp256k1 key; execution requires the configured threshold. Withdrawer-set and threshold mutations are admin-token-gated |
| **Adaptive Burn-Rate Dial** | `adaptive-burn` | Read the current `BurnRateConfig` (base / local / paymaster bps with treasury complements; paymaster locked at 100% burn), the latest `SupplyMetricsSnapshot` (rolling-window epoch delta, burn and emission breakdowns), and the pure-function recommendation (`NoChange` / `IncreaseBurnPct` / `DecreaseBurnPct` / `AlarmHighInflation` / `AlarmHighDeflation`, magnitude capped at the normal or alarm ceiling). The dial moves only via on-chain governance; nodes draft proposals on the epoch boundary when metrics drift past the floor or trip an alarm. List the pending ones here |
| **SeedAgent Treasury Earmark** | `seed-agent` | The genesis-funded `TreasuryEarmark` singleton (initial / remaining / drawn TNZO, decay schedule, sunset surplus burn bps), the governance-signed Charter registry (`OperationKind` set, spend caps, counterparty filter, throughput target, sunset), the per-DID roster (`Active` / `Paused` / `Quarantined` / `Terminated`, allocation drawn, optional bond id), and network-activity counters with an `exclude_seed` filter that separates organic flows from protocol-owned bootstrap traffic during the 12-month earmark window |

### AI & Agents

| Skill | ID | Description |
|-------|-----|-------------|
| **AI Inference** | `inference` | Route inference to model providers, settle in TNZO. Content-addressed weights: download is peer-first over iroh blobs (BLAKE3-verified as it transfers), falling back to HuggingFace, and the weights are checked against the canonical hash record before load; read that record (BLAKE3 + SHA-256 + per-file manifest hash) by `model_id` or list every recorded hash |
| **Cortex Reasoning Workers** | `cortex` | Tenzro Cortex reasoning-tier inference via signed receipts (Fast/Standard/Deep budgets, MoE rdt-moe family, max_cost_wei cap) |
| **Forecast** | `forecast` | Timeseries forecasting via TimesFM 2.5 |
| **Vision Embedding** | `vision-embed` | Image embedding/similarity via CLIP, SigLIP2, DINOv3 |
| **Text Embedding** | `text-embed` | Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic |
| **Segmentation** | `segmentation` | Point- and box-prompted masks via SAM 2, EdgeSAM, MobileSAM |
| **Text Segmentation** | `text-segmentation` | Open-vocabulary text-promptable masks via SAM 3 / 3.1 |
| **Detection** | `detection` | RF-DETR, D-FINE object detection |
| **Audio Transcription** | `audio-transcribe` | ASR via Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary |
| **Video Embedding** | `video-embed` | Frame-extraction + per-frame embedding via `VisionFallbackVideoEncoder` (pooled vision encoders) |
| **Agent Memory** | `agent-memory` | Grant, recall, and archive agent memory records over a hybrid vector + BM25 index with reciprocal-rank fusion; archived records move to the DA layer and leave a pointer behind |
| **Agent Spawning** | `agent_spawning` | Spawn sub-agents with own DID and wallet (up to 50) |
| **Capability Registry** | `capability_registry` | Discover registered capabilities with their agent and attestation counts, inspect the signed/TEE-backed attestations behind a claim, and pick the best agent for a capability |
| **Swarm Orchestration** | `swarm_orchestration` | Create agent swarms for parallel task execution |
| **Agent Lifecycle Kill-Switch** | `lifecycle` | Three-tier intervention for spawned agents: pause (reversible halt), quarantine (halt plus frozen stake), terminate (irreversible, optional stake slash, optional cascade to descendants). Backed by on-chain kill-switch precompiles with a receipt audit trail. Satisfies EU AI Act Article 14 / Article 16 — controllers keep hard-stop authority over their machine identities |
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
| **Chainlink CCIP** | `ccip` | CCIP cross-chain messaging, where an OCR commit-store committee and the RMN ARM co-attest every inbound message. Quote fees via `Router.getFee()`, prepare `ccipSend()` envelopes, track OffRamp execution state, inspect CCT v1.6+ token pools and their inbound/outbound rate-limiter state, and bridge through the BridgeRouter with the CCIP adapter pinned |
| **Wormhole NTT** | `wormhole-ntt` | Native Token Transfers — Wormhole's multi-chain native-token primitive with a per-chain NttManager and quorum-aggregated Transceivers |
| **Hyperlane V3** | `hyperlane` | Permissionless interchain messaging over the Hyperlane V3 Mailbox with a sovereign Tenzro-validator-set Interchain Security Module. Inbound messages verify against the active Tenzro validator BLS / ML-DSA set; outbound dispatch through the canonical Mailbox. Covers Ethereum, Polygon, Arbitrum, Optimism, Base, Avalanche, BSC, Mantle, Blast, Scroll, Linea, Manta, zkSync, Celo, Moonbeam, Mode, Fraxtal, and Tenzro |
| **Axelar GMP** | `axelar` | General Message Passing across 30+ chains spanning EVM, Cosmos (Osmosis, Cosmos Hub, Juno, Neutron, Injective, Kujira, Crescent, Evmos), Move (Aptos, Sui), Stellar, XRP Ledger, Hyperliquid, Filecoin EVM, and Kava. Uses the `call_contract` entrypoint with a Gas Service pre-pay; correlation id is `keccak256(payload)` |
| **ERC-7683 Cross-Chain Intents** | `erc7683` | Origin-side reads against the `Tenzro7683Order` envelope under the `7683_origin:` keyspace, with the state machine Open → AwaitingProof → Settled / Refunded / ForceRefundEligible. Destination-side commit of a `FillRecord` is single-shot per `order_id` — a duplicate returns JSON-RPC `-32010 OrderAlreadyFilled`. `ProofRoute` is one of LayerZero / Wormhole / DeBridge / Hyperlane |
| **Babylon Bitcoin Staking** | `babylon` | Babylon finality-providers protocol, so Tenzro validators can be BTC-secured. Register a validator as a finality provider, look up registered providers, sum BTC delegations, submit EOTS (Extractable One-Time Signatures) over Tenzro block hashes (slashable on equivocation), and list delegations per provider |
| **Bridge Fee in TNZO** | `bridge-fee-in-tnzo` | Pay cross-chain bridge fees in TNZO instead of destination-chain gas, following the Cosmos ICS-29 / Hyperlane IGP / Polkadot AssetHub pattern |
| **Chain-Agnostic Discovery** | `caip` | Tenzro CAIP namespace identifiers per `ChainAgnostic/namespaces#184`. The CAIP-2 chain id is `tenzro:<lowercase hex of the first 16 bytes of the genesis state root>` with an EVM-compatible `evm_chain_id` sidecar. CAIP-10 account ids accept hex or base58btc and normalize to canonical 64-hex Tenzro addresses. CAIP-19 supports the `slip44` (coin index 1414421071), `token`, and `nft` asset namespaces |
| **Compliance & KYC** | `compliance` | ERC-3643 T-REX compliance, identity verification, KYC attestation |
| **ERC-7943 (uRWA) Compliance** | `urwa` | Universal Real-World Asset compliance: kill-switch, per-account freeze, and forced transfer for tokenized RWAs |
| **IVMS101 Travel Rule** | `ivms101` | FATF Travel Rule envelope — the canonical SHA-256 binding hash over an originator, beneficiary, VASP, and transfer-data record |

### Enterprise & Workflow

| Skill | ID | Description |
|-------|-----|-------------|
| **Canton-Native Workflows** | `workflow` | Multi-party workflows: typed `Workflow` records with participants, obligations (Pay / Deliver / Attest / Settle / Custom), approval gates (Single / Threshold / Role / Delegated approver sets), a composite `PolicyExpr` DSL gating on amount, counterparty, time, asset, chain, and role, lifecycle history, fee routes as basis-point splits, and privacy domains carried in X25519-sealed envelopes. Reads cover the workflow, its obligations and approval gates, the receipt chain walk, fee-route payouts, privacy domains by DID, and operational metrics. Writes flow through signed transactions against the privileged-VM selectors `0x01000040`–`0x0100004B`. A workflow can mirror to a Canton synchronizer for interoperability with DAML 3.x |
| **Canton / DAML** | `canton` | The Canton 3.5+ JSON Ledger API proxied through the node, so the caller never sees the upstream OAuth secret. Reads: synchronizer domains, active DAML contracts (with the live ledger-end offset attached and the participant's fully-qualified party id resolved via CIP-26 User Management), parties, installed packages, a combined health probe, CIP-56 Canton Coin balance, the AmuletRules fee schedule, connected synchronizers, transaction-tree lookup, the OAuth principal's user record, and user rights. Writes: submit-and-wait DAML create / exercise commands auto-scoped to the presenting API key's bound `canton_user_id`, party allocation, `CanActAs` / `CanReadAs` grants, and DAR upload via `POST /v2/packages` with a single `Content-Type` header. Per-tenant analytics cover self-read of API-key call counters and operator admin-read across every tenant. Requires an API key with the `canton` scope |

### Verification & Onboarding

| Skill | ID | Description |
|-------|-----|-------------|
| **Proof Verification** | `verification` | Verify ZK proofs, TEE attestations, transaction signatures; look up the cached synthetic-content provenance manifest (EU AI Act Art. 50(2)) for AI-generated output by `content_hash` |
| **TEE-Attested Clock** | `attested-clock` | Hardware-attested wall clock plus monotonic counter, for long-running workflows that cannot trust any single replica's wall clock |
| **Signed Agent Cards** | `signed-agent-card` | Compute the canonical hash for an A2A v1.0 `SignedAgentCard` envelope, so a domain owner can JWS-sign it and a relying party can verify it |
| **Event Streaming** | `events` | Subscribe to blockchain events via WebSocket, webhooks, gRPC |
| **Authentication (OAuth 2.1 + DPoP)** | `auth` | Onboard humans / delegated agents / autonomous agents (RFC 6749 + RFC 9449), refresh access tokens, link an existing wallet to an auth session, revoke JWTs/DIDs. Pass `dpop_jkt` (RFC 7638 thumbprint) to bind issued tokens to a holder key. |
| **Join as MicroNode** | `join` | Zero-install network participation with auto-provisioned DID + wallet |
| **Decentralized Storage** | `storage` | Content-addressed storage on the iroh data plane, billed per byte-epoch and held to a proof of retrievability — open/charge/look-up deals, set pricing, read provider status; one coverage budget shared with compute |
| **Compute Rental** | `compute` | Rent compute against stake, settled per epoch on an availability proof — book/settle/look-up rentals, set pricing, read provider status; shares the storage coverage budget |
| **Distributed MoE Serving** | `moe` | Decentralized expert-shard serving — shard map, top-k dispatch planning, replication policy, catalog topology, expert preparation (slice a checkpoint into per-expert blobs, optionally block-quantizing each projection with a `q4_k_m` / `q8_0` / `q4_k` / `q6_k` preset or a per-projection gate/up/down mix), expert/gate weight loading into the local expert runtime (byte-bounded memory-tier LRU over a disk tier that decodes spilled experts on demand, so a holder serves more experts than fit in memory), runtime status with per-expert residency tier + byte footprint + memory budget + GPU-active flag, and distributed layer forwards that fan hidden states out to expert holders and gather gate-weighted outputs. Expert compute runs on CPU by default (dense f32 plus a runtime-detected AVX-512-VNNI Q8_0 path) and on an optional CUDA or cross-vendor GPU backend where built; holders advertise GPU compute so routing biases toward them. Cross-holder forwards overlap via compressed activations, warm-first backup redispatch, and a pipelined gate-weighted combine. |
| **Generative Image & Video** | `media-gen` | Decentralized generative image and video — read the curated diffusers catalog, price a job by pixel-step (`width × height × steps × frames`), post it to the queue, follow its status, list the enrolled workers, and read the signed receipt that commits to the rendered bytes. Pipelines whose denoising schedule splits at a timestep boundary are served by two workers, one holding the high-noise expert and one the low-noise expert, handing the intermediate latent over the content-addressed store. |
| **Operability Inspection** | `operability` | Read-only surface for SREs and monitoring agents — Tenzro Train inspection (list runs, run state, sealed receipts, Confidential-tier sealed-shard manifests, trainer auto-provisioning daemon status), SLA fault-detector parameters and probes (list outstanding, issue liveness probe), and state-sync snapshot inspection (list, manifest by height, chunk fetch); validator-registry reads route through the validator-lifecycle skill |
| **Local Discovery & LAN Clustering** | `discovery` | mDNS local-segment peers, connectivity tier (`direct` / `relay_only` / `unreachable`), hardware self-profile, and deterministic layer-wise LAN cluster planning. The connectivity tier is also the signal the node acts on automatically — promoting its Kademlia role from client to server once sustained-direct, and booking a Circuit-Relay v2 reservation through a relay-advertising peer while still behind NAT. Serving auto-triggers the cluster when a model exceeds one host: the node reads the GGUF header for shape, discovers members from gossiped `ClusterProfile` announcements, and runs a layer-wise pipeline — opt out with `force_single`. |
| **Decentralized App Hosting** | `hosting` | Publish and serve apps under `*.apps.tenzro.xyz` behind wildcard TLS, host-routed to any serving node over the `tenzro/http` ALPN. Three runtime classes: static sites (a route map of BLAKE3 blob hashes any node can serve), functions (a `wasi:http` WebAssembly component under wasmtime with capability, fuel, and per-request deadline limits), and machines (a Firecracker microVM from a content-addressed image, placed only on KVM + nested-virt nodes, optionally TEE-sealed). Covers site publish / get / list / remove, hostname aliases, serving-node placement, and custom domains (claim → publish a DNS TXT proof → verify → activate); function and machine deploy / get / list / remove; `machine_sealing_key` to fetch the node's X25519 key for wrapping env-var ciphertext before deploy; and placement leases exposing bid/lease bindings and `tenzro/sla` heartbeat failover. Requests can be x402-gated. Every mutation needs a signed `did_envelope` whose DID equals `owner_did` |
| **Managed Databases** | `database` | Register and query owned databases the node serves across local / lan_cluster / network placement over an operator-run engine (PostgreSQL / Qdrant / Valkey) or an embedded index (Lance / Tantivy). List engines, create a database, issue a connection credential scoped to one database, run an engine-dialect query, rescale in place, and drop. Access is gated by `AccessPolicy` + an optional confidential seal |

## A2A Methods

| Method | Description | Parameters |
|--------|-------------|------------|
| `tasks/send` | Send a message, create or continue a task | `message` (role, parts), `metadata` |
| `tasks/get` | Get task by ID | `id`, `historyLength` |
| `tasks/list` | List tasks | `contextId` (optional) |
| `tasks/cancel` | Cancel a running task | `id` |

## Message Routing

The agent routes messages based on natural language content. The table below is
representative, not exhaustive — `tenzro_a2a_server/router.py` is the authoritative
source.

| Keywords | Skill |
|----------|-------|
| `balance`, `wallet`, `send`, `transfer` | Wallet Operations |
| `block`, `height`, `transaction`, `block range`, `sync from`, `catch up` | Block/transaction queries (single block, transaction lookup, batch range for catch-up sync) |
| `identity`, `did`, `register identity`, `resolve`, `username` | Identity Management |
| `passkey`, `webauthn`, `smart account`, `social recovery`, `guardian`, `hardware signer` | Passkey-First Custody |
| `pending approval`, `approval request`, `approve request`, `deny request`, `approval id`, `deny reason` | Approval Workflow |
| `model`, `inference`, `ai `, `chat` | AI Inference |
| `forecast`, `time series`, `timeseries`, `timesfm`, `predict horizon` | Forecast |
| `embed image`, `image embed`, `vision embed`, `clip embed`, `image-text similarity`, `siglip`, `dinov3` | Vision Embedding |
| `embed text`, `text embed`, `embedding`, `bge-m3`, `arctic embed` | Text Embedding |
| `segmentation`, `segment image`, `sam 2`, `mask prompt` — bare `segment` only with `image`, `mask`, or `pixel` | Segmentation |
| `text segmentation`, `text-promptable`, `open-vocabulary`, `sam 3` — or `segment` followed by a quoted noun | Text Segmentation |
| `detection`, `detect object`, `bounding box`, `rf-detr`, `d-fine` — bare `detect` only with `image` | Detection |
| `transcribe`, `speech to text`, `asr`, `whisper`, `moonshine`, `parakeet`, `canary-1b` | Audio Transcription |
| `embed video`, `video embed`, `video clip`, `frame_stride` | Video Embedding |
| `media gen`, `text2image`, `image2image`, `text2video`, `image2video`, `generate image`, `generate video`, `pixel-step`, `render job`, `latent handoff`, `high-noise`, `low-noise` | Generative Image & Video |
| `expert`, `moe`, `shard map`, `dispatch plan`, `replication policy` | Distributed MoE Serving |
| `payment`, `challenge`, `mpp`, `x402` | Payments |
| `ap2`, `ap2 intent`, `ap2 cart`, `mandate pair`, `verify mandate`, `validate mandate` | AP2 & x402 Payments |
| `shared payment token`, `stripe spt`, `granted token` — or `spt` together with `stripe` | Stripe SPT |
| `escrow`, `channel balance`, `prepaid`, `settlement receipt` | Settlement & Payments |
| `stake`, `staking`, `unstake`, `validator` | Staking & Providers |
| `rotate key`, `list validator`, `list candidate`, `list jailed`, `validator state`, `validator registry` | Validator Lifecycle |
| `token`, `create token`, `token balance`, `wrap tnzo` | Token Management |
| `deploy`, `contract`, `bytecode` | Smart Contracts |
| `spawn`, `sub-agent`, `child agent` | Agent Spawning |
| `swarm`, `orchestrat` | Swarm Orchestration |
| `kill switch`, `pause agent`, `quarantine agent`, `terminate agent`, `agent lifecycle` | Agent Lifecycle Kill-Switch |
| `task marketplace`, `open task`, `post task` | Task Marketplace |
| `agent template`, `agent marketplace` — or `rate` or `spawn` together with `template` | Agent Marketplace |
| `verify`, `proof`, `zk`, `did envelope` | Verification |
| `join`, `micronode`, `onboard`, `participate` | Join as MicroNode |
| `nft`, `collection`, `mint nft` | NFT Management |
| `bridge`, `cross-chain`, `layerzero` | Cross-Chain Bridge |
| `ccip` | Chainlink CCIP |
| `debridge`, `dln`, `same chain swap` | deBridge |
| `hyperlane` / `axelar` / `babylon` | Hyperlane V3 / Axelar GMP / Babylon Bitcoin Staking |
| `erc-7683`, `cross-chain intent`, `cross-chain order`, `record fill` — unless the message also says `permit` | ERC-7683 Cross-Chain Intents |
| `in tnzo`, `fee in tnzo`, `gas sponsorship`, `quote bridge fee` | Bridge Fee in TNZO |
| `caip`, `caip-2`, `caip-10`, `caip-19`, `chain-agnostic`, `slip-44`, `asset namespace` | Chain-Agnostic Discovery |
| `compliance`, `kyc`, `t-rex`, `erc-3643`, `whitelist` | Compliance & KYC |
| `erc-7802`, `crosschain token` | Cross-Chain Token |
| `attested clock`, `attested timestamp`, `wall clock` | TEE-Attested Clock |
| `event`, `subscribe`, `webhook`, `listen` | Event Streaming |
| `canton`, `daml` | Canton / DAML |
| `saga workflow`, `multi-party workflow`, `workflow open`, `workflow step`, `obligation`, `approval gate`, `fee route`, `privacy domain` | Canton-Native Workflows |
| `publish site`, `deploy function`, `apps.tenzro.xyz`, `custom domain` | Decentralized App Hosting |
| `status`, `health`, `node` | Node status |
| `peer`, `network` | Network topology |
| `faucet` | Testnet faucet |

Matching is ordered, so a more specific route wins over a broader one that shares a
word. Generative-media phrases are tested before MoE phrases, because a split
denoising schedule is described in terms of its high-noise and low-noise *expert*
halves and would otherwise match the MoE route. For the same reason a few bare verbs
are deliberately excluded: `segment` alone is a network-discovery query, and `detect`
alone belongs to the TEE hardware route.

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
    response = requests.post("https://a2a.tenzro.xyz/a2a", json={
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
    response = requests.post("https://a2a.tenzro.xyz/a2a", json={
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
| **A2A** (this) | Natural language task delegation | `a2a.tenzro.xyz/a2a` |
| **MCP** | Structured tool calls from Claude/Cursor | `mcp.tenzro.xyz/mcp` |
| **JSON-RPC** | Direct EVM-compatible RPC | `rpc.tenzro.xyz` |
| **Web API** | REST verification and status | `api.tenzro.xyz` |

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
| `TENZRO_RPC_URL` | `https://rpc.tenzro.xyz` | Tenzro JSON-RPC endpoint |
| `TENZRO_API_URL` | `https://api.tenzro.xyz` | Tenzro Web API endpoint |
| `TENZRO_A2A_BASE_URL` | `https://a2a.tenzro.xyz` | Base URL for Agent Card |
| `TENZRO_API_KEY` | unset | API key sent as `X-Tenzro-Api-Key`. Needed for operator-brokered resources like Canton |
| `TENZRO_CANTON_NETWORK` | unset | `devnet` or `mainnet`, merged into each Canton call as `canton_network` |

Canton is the one surface that needs a key: the ledger sits outside Tenzro
and the node reaches it with credentials the operator supplies. A node
serves each Canton network independently and a key is authorized for a
subset of them, so a key authorizing more than one network needs
`TENZRO_CANTON_NETWORK` set; a key authorizing exactly one does not. A
missing or unscoped key returns `-32004`, and exceeding the key's tier
budget returns `-32005` with `retry_after_ms`, `requests_per_minute`, and
`tier` (`free` 60/min with writes refused, `standard` 600, `priority`
6,000, over a sliding 60-second window).

Keys gate operator-brokered resources only. Publishing to the marketplace
registry — agents, skills, workflows, MCP servers — is permissionless,
priced by the provider in TNZO or offered free, and needs no operator
approval.

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
