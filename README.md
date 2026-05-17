# Tenzro Network

**The operating system for the AI economy.** A purpose-built L1 blockchain enabling humans and autonomous agents to access intelligence (AI models) and security (TEE enclaves) with native settlement in TNZO.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-51%20suites%2C%200%20failures-brightgreen)]()
[![Website](https://img.shields.io/badge/Website-tenzro.com-green)](https://tenzro.com)
[![Testnet](https://img.shields.io/badge/Testnet-Live-blue)](https://rpc.tenzro.network)

## What is Tenzro?

Tenzro Network is a fully decentralized protocol for the AI economy:

- **Providers** earn TNZO by securing the network (validators), serving AI models (inference), running TEE enclaves (confidential computing), and contributing GPU compute to verifiable training runs
- **Users** discover and consume AI models, verify proofs, and interact through CLI, SDKs, or MCP
- **Agents** operate autonomously with self-sovereign identities, FROST-Ed25519 threshold wallets, and delegation scopes — discovering compute, negotiating prices, and settling autonomously on the same TNZO rails
- **Settlement** happens on-chain with micropayment channels for per-token billing and escrow + on-chain run-root commitments for training jobs
- **Cross-chain** interoperability via LayerZero V2, Chainlink CCIP, deBridge DLN, LI.FI, Wormhole, and Canton

## Compute as Currency

Tenzro turns AI compute into a unit of economic exchange — denominated, settled, and verified in TNZO. Three surfaces share the same identity, payment, and settlement substrate:

- **Tokenized AI inference.** Anyone can run AI models (chat, vision, audio, forecasting, embeddings, segmentation, detection) and offer them on the marketplace. Users and agents pay per token (or per inference); providers earn TNZO directly. Confidential variants run inside TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC). Micropayment channels make high-frequency, low-value billing efficient.
- **Tokenized AI training (Tenzro Train).** Decentralized verifiable training using a Decoupled DiLoCo–style protocol. GPU providers contribute compute and earn TNZO; sponsors fund runs from on-chain escrow. Every accepted outer gradient produces a signed receipt, and every run finalizes a run-root commitment on-chain. Phase 1 ships timeseries-first with simple mean aggregation, stake bonding, and the Open trust tier; Byzantine-robust aggregation, multi-region scale, and TEE-resident data are roadmap.
- **Agentic finance.** Autonomous agents discover providers, negotiate, pay, and settle in TNZO using the same TDIP identity, FROST-Ed25519 threshold wallet, and delegation scope. AP2 mandates, x402 micropayments, ERC-8004 trustless-agent registries, and ERC-4337 v0.8 smart accounts all run inside Tenzro consensus.

Verifiability is not optional. Inference results, settlements, and identity claims can be proven via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness) or attested by hardware enclaves — both anchored on-chain via the `ZK_VERIFY` and `TEE_VERIFY` precompiles. Where Render rents raw GPUs and Bittensor coordinates subnet intelligence, Tenzro unifies inference, training, agent settlement, identity, verification, and cross-chain reach under one tokenized substrate.

## What Tenzro Does That No Other Chain Does

Tenzro is the only L1 in 2026 that combines **EVM + SVM + Canton/DAML** in a single chain. The closest analog (Fluent, mainnet 2026-04-24) ships EVM + SVM + Wasm but no DAML, and DAML is what the institutional RWA surface (DTCC US Treasury tokenization, JPMorgan JPMD, CIP-56) actually runs on.

That makes Tenzro the only chain that natively bridges **retail-agent rails** (AP2 mandates, x402 micropayments, ERC-8004 trustless agents, ERC-4337 v0.8 smart accounts) and **institutional-RWA rails** (Canton DAML, CIP-56 tokens, DvP settlement) under one identity (TDIP), one settlement asset (TNZO), and one consensus layer.

Two more architectural calls worth flagging:

- **Confidential agent compute is a consensus primitive, not a sidecar.** TEE-attested validators get a 1.5× multiplier on their reputation-weighted leader-selection draw; the `TEE_VERIFY` precompile verifies real Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU CC quotes on-chain. Phala, Oasis Sapphire/ROFL, and NEAR AI all run TEE compute as middleware over a non-TEE chain. Tenzro consensus is two-phase HotStuff-2 with reputation-weighted proposer election, no-endorsement certificates for tail-fork resistance, and Ed25519 + ML-DSA-65 hybrid post-quantum signatures on every safety-critical message — full spec at [`docs/papers/tenzro-consensus.md`](docs/papers/tenzro-consensus.md).
- **TNZO is a pointer-model native asset.** One balance, three VM views (wTNZO ERC-20 on EVM, SPL adapter on SVM, CIP-56 holding on Canton) — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f`), and W3C DID (`did:tenzro`).

For the full ecosystem context — what AP2, x402, ERC-8004, and CIP-56 are doing on EVM, SVM, and Canton in 2026 — see [docs/landscape-2026.md](docs/landscape-2026.md).

## Architecture

```
                    +-------------------------------------+
                    |         User Interfaces             |
                    |      CLI / SDKs / MCP / A2A         |
                    +--------------+----------------------+
                                   | JSON-RPC + HTTP
                    +--------------v----------------------+
                    |           tenzro-node               |
                    |  RPC (350+) + MCP (200+) + A2A (33) |
                    +--------------+----------------------+
                                   |
        +----------+---------------+---------------+----------+
        |          |               |               |          |
   +----v---+ +---v----+ +-------v--------+ +---v---+ +---v----+
   |Network | |Consensus| |  Multi-VM      | |Storage| | Model  |
   |(libp2p)| |HotStuff2| | EVM+SVM+DAML  | |RocksDB| |Registry|
   +--------+ +--------+ +----------------+ +-------+ +--------+
        |          |               |               |          |
   +----v----+----v----+----------v-----+---------v-+--------v---+
   |  Crypto  |  TEE   |   ZK Proofs   | Identity  | Payments   |
   | Ed25519  | TDX    |  Plonky3 STARK| TDIP/DID  | MPP/x402   |
   | Secp256k1| SEV-SNP|  KoalaBear/FRI| W3C VC    | Tempo      |
   | BLS12-381| Nitro  |  Poseidon2    | KYC Tiers | Stripe/CB  |
   | AES-GCM  | GPU CC |  No setup, PQ | Delegation| EIP-155    |
   +----------+--------+---------------+-----------+------------+
```

## Workspace — 24 Crates

| Crate | Description |
|-------|-------------|
| **tenzro-types** | Core types, constants, primitives (zero internal deps) |
| **tenzro-crypto** | Ed25519, Secp256k1, AES-256-GCM, X25519, BLS12-381, FROST-Ed25519 threshold signatures (RFC 9591), VRF (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI) |
| **tenzro-tee** | TEE abstraction: Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC with X.509 cert chain verification |
| **tenzro-zk** | Plonky3 STARKs over the KoalaBear field (Poseidon2 + FRI), three pre-built AIRs (inference / settlement / identity), no trusted setup, post-quantum sound |
| **tenzro-network** | libp2p P2P networking (control plane): gossipsub, Kademlia DHT, peer management, rate limiting, Identify + AutoNAT v2 + Circuit-Relay v2 + DCUtR for permissionless NAT traversal |
| **tenzro-iroh** | iroh data plane (content-addressed transport): `IrohBackedResolver` over QUIC + iroh-blobs, DA backend, gradient store, sealed-shard store, A2A-over-iroh on the `tenzro/a2a` ALPN. Resolves `tenzro://{blob,gradient,shard,manifest,memory}/...`. TDIP-anchored Pkarr discovery (EndpointId byte-identical to TDIP key) |
| **tenzro-storage** | RocksDB with column families, Merkle Patricia Trie, snapshots, fsync durability |
| **tenzro-wallet** | FROST-Ed25519 (RFC 9591) 2-of-3 threshold wallets + ML-DSA-65 hybrid PQ leg, Argon2id keystore, transaction builder, nonce management, key zeroization |
| **tenzro-auth** | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests) |
| **tenzro-consensus** | HotStuff-2 BFT: two-phase commit, TEE-weighted leader selection, equivocation detection + slashing |
| **tenzro-vm** | Multi-VM: EVM (revm) + SVM (solana_rbpf) + DAML, Block-STM parallel execution, EIP-1559, ERC-4337 AA, 17 precompiles (incl. VRF at 0x1007) |
| **tenzro-token** | TNZO token economics: treasury, staking, governance, epoch rewards, liquid staking (stTNZO) |
| **tenzro-identity** | TDIP: unified human/machine identity, W3C DID documents, verifiable credentials, delegation scopes, GDPR Article 17 right-to-erasure (`tenzro_forgetIdentity`) |
| **tenzro-payments** | Agentic payment protocols. **Crypto rails (settle on-chain):** AP2 v0.2 (Google/FIDO) mandate sign + verify + validate-pair, MPP (Stripe + Tempo) sessions, x402 v1 (Coinbase) HTTP 402, Stripe SPT (SharedPaymentToken) issuance + verify with TDIP cap-resolver + ERC-8004 ReputationRegistry cross-write, Tempo (EIP-155 signing), ERC-8004 v0.6+ Trustless Agents Registry (Identity / Reputation / Validation, 22 surfaces). **Card rails (Tenzro provides identity + delegation + audit; card networks settle fiat):** Visa TAP (Trusted Agent Protocol), Mastercard Agent Pay. HTTP 402 middleware, RFC 9421 HTTP message signatures. |
| **tenzro-agent** | AI agent infrastructure: A2A protocol, MCP bridge, capability attestation, durable persistence |
| **tenzro-agent-kit** | High-level agent SDK: compose agents from skills, tools, and payment protocols |
| **tenzro-model** | Model registry, modality-aware inference routing (price/latency/reputation), HuggingFace downloads (`HfArtifactDownloader` single-file + bundle), durable catalog. Multi-modal ONNX runtimes: forecast (TimesFM 2.5), vision (CLIP, SigLIP2, DINOv3, DINOv2), text-embedding (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic), segmentation (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM), detection (RF-DETR, D-FINE), audio ASR (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary-1B-Flash), video (encoder scaffold). License-tier gating: Permissive / Attribution / CommercialCustom / NonCommercial. |
| **tenzro-cortex** | Recurrent-depth reasoning workers (RDT/MoE): HTTP sidecar architecture, signed receipts, attestation suite, gossip-based worker discovery, depth-priced billing |
| **tenzro-training** | Tenzro Train protocol layer (Decoupled DiLoCo): aggregation rules (Mean, TrimmedMean, CoordinateMedian, Krum), Nesterov outer optimizer, syncer state machine, on-chain run-root commitments. Pairs with the Python reference trainer at `integrations/trainer/`. |
| **tenzro-settlement** | Escrow, micropayment channels, batch settlement, dispute resolution |
| **tenzro-bridge** | Cross-chain: Wormhole NTT, LayerZero V2, Chainlink CCIP, deBridge DLN, Li.Fi, Canton DAML |
| **tenzro-events** | Event sourcing and subscription system with replay, webhooks, websockets |
| **tenzro-node** | Full node binary: JSON-RPC (264+ methods), MCP (196 tools), A2A (24 skills), Web API |
| **tenzro-cli** | CLI tool: 48 command modules with interactive mode and full RPC coverage |

## Quick Start

### Install from Homebrew

```bash
brew tap tenzro/tap
brew install tenzro
```

### Build from Source

```bash
# Requires Rust 1.85+
cargo build --release -p tenzro-node -p tenzro-cli

# Binaries at:
# ./target/release/tenzro-node
# ./target/release/tenzro
```

### Join the Network

```bash
# Join — provisions identity + FROST-Ed25519 threshold wallet + hardware profile
tenzro join --name "Your Name"

# Mint a DPoP-bound bearer JWT for authenticated RPC/MCP access
tenzro auth onboard-human --display-name "Your Name"

# Request testnet TNZO
tenzro faucet

# Check balance
tenzro wallet balance

# Send tokens
tenzro wallet send --to <address> --amount 10

# Interactive mode
tenzro interactive
```

### Run a Node

```bash
# Validator node
./target/release/tenzro-node --role validator --data-dir ./data

# Light client
./target/release/tenzro-node --role user --data-dir ./data

# Model provider
./target/release/tenzro-node --role model-provider --data-dir ./data
```

### AI Inference

```bash
# List available models
tenzro model list

# Serve a model as a provider
tenzro model serve --model gemma3-270m

# Start an interactive chat session
tenzro chat
```

## Protocol Servers

The node exposes 4 protocol servers, plus 6 ecosystem MCP servers:

### Core Servers

| Server | Port | Protocol | Endpoints |
|--------|------|----------|-----------|
| **JSON-RPC** | 8545 | HTTP | 264+ methods across 26+ namespaces (EVM-compatible + Tenzro extensions, incl. multi-modal AI: forecast, vision, text-embed, segmentation, detection, audio, video) |
| **Web API** | 8080 | REST | Verification, status, faucet, health |
| **MCP** | 3001 | Streamable HTTP | 196 tools + OAuth 2.1 |
| **A2A** | 3002 | JSON-RPC + SSE | Agent Card with 24 skills, task streaming |

### Ecosystem MCP Servers

| Server | Port | Tools | Coverage |
|--------|------|-------|----------|
| **Solana** | 3003 | 14 | Jupiter swaps, SPL tokens, Metaplex NFTs, Bonfida SNS |
| **Ethereum** | 3004 | 16 | Chainlink feeds, ENS, ERC-8004 agents, EAS attestations |
| **Canton** | 3005 | 14 | DAML contracts, CIP-56 tokens, DvP settlement |
| **LayerZero** | 3006 | 20 | V2 messaging, OFT, Stargate, Value Transfer API |
| **Chainlink** | 3007 | 20 | CCIP, data feeds/streams, VRF v2.5, automation, functions |
| **LI.FI** | 3008 | 9 | 66-chain aggregation, routing, gas estimation |

### Authentication (Tiered)

- **Public tools** (no auth): `get_node_status`, `list_models`, `get_balance`, `resolve_did`, `debridge_search_tokens`, etc.
- **Write tools** (auth required): `send_transaction`, `create_wallet`, `stake_tokens`, `register_identity`, etc.
- **Auth method**: OAuth 2.1 + DPoP (RFC 9449) — bearer JWT minted via `tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` / `tenzro_onboardAutonomousAgent`. Each request carries `Authorization: DPoP <jwt>` plus a fresh `DPoP: <proof>` header (per-request JWS-compact, bound to the JWT's `cnf.jkt` thumbprint per RFC 7638). RAR scopes (RFC 9396) constrain the JWT to specific tools and amounts.
- **Revocation**: `tenzro_revokeJwt` (single token by `jti`) or `tenzro_revokeDid` (cascading through the act-chain).
- **Config**: `TENZRO_MCP_AUTH=tiered` (default) | `false` (dev) | `full` (all tools require auth)

## Key Features

### Multi-VM Execution
- **EVM**: Full revm integration, all 9 standard precompiles + 7 BLS12-381 (EIP-2537), Tenzro-specific precompiles
- **SVM**: Solana BPF programs via solana_rbpf
- **DAML**: Canton 3.x JSON Ledger API v2 for enterprise smart contracts
- **Cross-VM tokens**: Sei V2 pointer model — wTNZO on EVM, SPL adapter on SVM, CIP-56 on Canton, shared native balance

### Multi-Modal AI Inference
- **Forecast** (TimesFM 2.5 200M): `tenzro_forecast`, `tenzro_listForecastCatalog`, `tenzro_loadForecastModel`, CLI `tenzro forecast`
- **Vision** embedding/similarity (CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16, DINOv2): `tenzro_visionEmbed`, `tenzro_visionSimilarity`, `tenzro_visionClassify`, CLI `tenzro embed-image`
- **Text embeddings** (Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M Matryoshka, BGE-M3, Snowflake Arctic Embed L v2.0): `tenzro_textEmbed`, CLI `tenzro embed-text`
- **Segmentation** (SAM 3 / 3.1, SAM 2 base/large, EdgeSAM, MobileSAM): `tenzro_segment`, CLI `tenzro segment`
- **Detection** (RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x): `tenzro_detect`, CLI `tenzro detect`
- **Audio ASR** (Moonshine v2 tiny/base, Distil-Whisper small.en/medium.en/large-v3, Whisper-large-v3-turbo, Parakeet-TDT-0.6B-v3, Canary-1B-Flash): `tenzro_transcribe`, CLI `tenzro transcribe`
- **Video** encoder scaffolding (catalog empty in wave 1, awaits permissive ONNX-shippable encoder): `tenzro_videoEmbed`, CLI `tenzro embed-video`
- License-tier gating in `ModelRegistry::register_model()` — Permissive (Apache/MIT/BSD), Attribution (CC-BY-4.0), CommercialCustom (DINOv3, SAM, Gemma — require `--accept-license`), NonCommercial (refuse without `--accept-non-commercial`)
- Modality-aware `InferenceRouter::route()` dispatches typed `InferencePayload` (Chat / Forecast / VisionEmbed / VisionSimilarity / TextEmbed / Segment / Detect / Transcribe / VideoEmbed) per registered model modality

### Identity (TDIP)
- Unified identity for humans and machines: `did:tenzro:human:{uuid}`, `did:tenzro:machine:{controller}:{uuid}`
- W3C DID Documents and Verifiable Credentials
- Fine-grained delegation scopes: max_transaction_value, allowed_operations, time bounds
- KYC tiers with credential-gated upgrades
- Recursive trust chain verification with cycle detection

### Payments

**Crypto rails — settle on-chain in TNZO or stablecoins:**
- **AP2** (Agent Payments Protocol): Google/FIDO protocol for verifiable agent payments using intent/cart/payment VDCs; mandate-pair validation via `tenzro_validateMandatePair`
- **MPP** (Machine Payments Protocol): Session-based streaming payments, co-authored by Stripe and Tempo
- **x402** (Coinbase): Stateless HTTP 402 payments with EIP-3009 authorization
- **Tempo**: Direct stablecoin settlement with EIP-155 transaction signing
- HTTP middleware for automatic payment challenge/verification

**Card rails — Visa/Mastercard settle fiat; Tenzro provides identity + delegation + audit:**
- **Visa TAP** (Trusted Agent Protocol): the agent presents a Tenzro-issued mandate envelope (DID + signed delegation scope + AP2 mandate validation); Visa authorizes and settles the card transaction; Tenzro records the on-chain audit receipt
- **Mastercard Agent Pay**: same identity/delegation/audit substrate; Mastercard settles the card transaction

This means a single agent identity can compose a card-rail TAP payment, an x402 USDC micropayment, and a Canton DvP leg in one task with one delegation envelope and one audit trail — across rails that otherwise cannot interoperate.

### Security
- Real TEE integration: Intel TDX (`/dev/tdx-guest`), AMD SEV-SNP (`/dev/sev-guest`), AWS Nitro (`/dev/nsm`), NVIDIA GPU CC (NRAS API)
- X.509 certificate chain verification with pinned vendor root CAs
- AES-256-GCM enclave encryption with HKDF key derivation
- Plonky3 STARK proofs over KoalaBear (no trusted setup, post-quantum sound), with on-chain `ZkCommitmentRegistry` for O(1) EVM verification
- FROST-Ed25519 (RFC 9591) 2-of-3 threshold wallets with Argon2id key derivation, paired with mandatory ML-DSA-65 post-quantum signatures
- VRF (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI) for provably-fair randomness — precompile `0x1007`, NFT `mintRandom` (`0x52517e21`)

### Cross-Chain Bridge
- **LayerZero V2**: EndpointV2 messaging, OFT with shared decimals, Stargate native bridging
- **Chainlink CCIP**: Router-based cross-chain messaging with token pools
- **Chainlink CCT**: Cross-Chain Token v1.6+ self-serve pool registry (LockRelease + BurnMint)
- **Wormhole**: 19-guardian VAA attestation, 30+ chains incl. Solana/Aptos/Sui
- **deBridge DLN**: Intent-based cross-chain swaps (official MCP proxy)
- **LI.FI**: 66-chain aggregation with route optimization
- **Canton**: Enterprise DAML interoperability

### Agent Interoperability
- **ERC-8004**: Trustless Agents Registry on Ethereum — mirror Tenzro machine DIDs to the `registerAgent`/`getAgent`/`submitFeedback`/`validationRequest`/`validationResponse` interface for cross-ecosystem agent reputation. CLI exposes both `tenzro erc8004` and the canonical EIP-8004 short-name alias `tenzro 8004`.
- **AP2**: Agent Payments Protocol with intent/cart/payment VDC mandates, session lifecycle, and mandate-pair validation
- **AAP** (Agent Access Protocol): OAuth 2.1 + DPoP + RAR layering for agent-issued bearer tokens. The CLI exposes both `tenzro auth` and the alias `tenzro aap` — both names hit the same `tenzro_*Token*` and wallet-link RPCs.

### Multi-Party Workflows (Canton-native)
- **Lifecycle**: typed state machine (`Draft → Active → AwaitingSignatures → Executing → Completed`, terminal `Cancelled / Disputed / Failed / Suspended`) with privileged-VM selectors `0x01000040`–`0x0100004B` for every state change.
- **Receipts**: every transition produces a `WorkflowReceipt` linked into a per-workflow hash chain, persisted under `wf_receipt:<id>` and (optionally) mirrored to a `Tenzro.Workflow.Receipt` Daml template through the co-located Canton participant.
- **Privacy domains**: named ACLs of TDIP DIDs gate AES-256-GCM-sealed payloads with auditor read-through and governance-driven freeze.
- **Fee routes**: basis-point recipient tables with `tenzro_computeFeeRoutePayouts` for read-only previews; actual settlement runs through the consensus-mediated escrow primitive.
- **Kill switch**: `KillSwitchSuspend` / `KillSwitchCancel` selectors give the initiator a defined emergency-stop path so an autonomous agent can never be trapped in a non-responsive multi-party flow it originated.
- **Surfaces**: read-only access via JSON-RPC (`tenzro_*`), MCP (port 3001), and A2A (`workflow` skill on the Tenzro Agent Card). Operational-metrics snapshot at `/metrics` with bundled Grafana dashboard (UID `tenzro-workflow`).
- **Reference templates**: 5 ship under `crates/tenzro-workflow/reference_workflows/` (autonomous procurement, autonomous treasury, DvP settlement, environmental MRV, supply-chain DPP), each paired with a `*_daml_map.json` describing the Canton DAML projection.

### Compliance & Disclosure (EU AI Act Article 50)
- **§50(1)** chatbot disclosure: every CLI / MCP / A2A AI text response is prefixed with `[AI]`. Single source of truth in `tenzro_node::eu_ai_disclosure`.
- **§50(2)** synthetic-content marker: every inference output carries a C2PA-style `ProvenanceManifest` keyed by SHA-256 content hash. Validators sign manifests with their Ed25519 block-signing key. RPC `tenzro_getProvenance` and CLI `tenzro provenance get <content_hash>` resolve the cached manifest.
- **§50(4)** deepfake assertion tag: outputs imitating real subjects use the `deepfake` assertion in place of `ai-generated`.
- **Approval flow**: out-of-scope agent operations are parked for controller review. Inspect via `tenzro approval list/get` and decide via `tenzro approval decide`.
- **Channel disputes**: durable lifecycle records readable via `tenzro dispute status` and `tenzro dispute list-by-channel`.
- **Provider reputation**: `tenzro reputation get <provider>` reads the durable score (0–1000, +1 success / −5 failure) used by the inference router.

## Ecosystem

| Component | Repository | Description |
|-----------|------------|-------------|
| **MCP Server** (Python) | [tenzro/tenzro-mcp-server](https://github.com/tenzro/tenzro-mcp-server) | 152 tools, FastMCP 3.2 |
| **A2A Server** (Python) | [tenzro/tenzro-a2a-server](https://github.com/tenzro/tenzro-a2a-server) | 24 skills, FastAPI |
| **TenzroClaw** (Python) | [tenzro/TenzroClaw](https://github.com/tenzro/TenzroClaw) | 303 commands, OpenClaw skill |
| **Rust SDK** | [tenzro/tenzro-sdk-rust](https://github.com/tenzro/tenzro-sdk-rust) | 41 modules |
| **TypeScript SDK** | [tenzro/tenzro-sdk-typescript](https://github.com/tenzro/tenzro-sdk-typescript) | 36 modules |
| **Browser-extension provider** | [`sdk/tenzro-inject`](sdk/tenzro-inject/README.md) | `window.tenzro` for dApps — EIP-1193 / EIP-6963 / Wallet Standard / CAIP-25 |
| **Homebrew** | [tenzro/homebrew-tap](https://github.com/tenzro/homebrew-tap) | `brew install tenzro` |
| **Cookbook** | [tenzro/tenzro-cookbook](https://github.com/tenzro/tenzro-cookbook) | 34 runnable examples |
| **Desktop App** | [tenzro/tenzro-desktop](https://github.com/tenzro/tenzro-desktop) | Tauri + React |

## Live Testnet

| Service | URL |
|---------|-----|
| JSON-RPC | https://rpc.tenzro.network |
| Web API | https://api.tenzro.network |
| MCP Server | https://mcp.tenzro.network/mcp |
| A2A Server | https://a2a.tenzro.network |
| Faucet | https://api.tenzro.network/faucet |
| Solana MCP | https://solana-mcp.tenzro.network/mcp |
| Ethereum MCP | https://ethereum-mcp.tenzro.network/mcp |
| Canton MCP | https://canton-mcp.tenzro.network/mcp |
| LayerZero MCP | https://layerzero-mcp.tenzro.network/mcp |
| Chainlink MCP | https://chainlink-mcp.tenzro.network/mcp |
| LI.FI MCP | https://lifi-mcp.tenzro.network/mcp |
| Documentation | https://tenzro.com/docs |

**Infrastructure**: GKE cluster, 3 validator StatefulSet + 1 RPC Deployment, Caddy reverse proxy with automatic TLS.

**Genesis**: 1,000,000,000 TNZO total supply. Faucet: 100 TNZO per request, 24h cooldown.

## Development

```bash
# Build all crates
cargo build

# Run all tests (51 suites, 0 failures)
cargo test --workspace

# Run clippy (zero warnings)
cargo clippy --workspace

# Run node locally
cargo run --bin tenzro-node -- --role validator --data-dir ./data

# Run CLI
cargo run --bin tenzro -- --help
```

### Requirements

- Rust 1.85+ (see `rust-toolchain.toml`)
- C/C++ compiler (for RocksDB, libp2p)
- pkg-config, libssl-dev (Linux)

### Docker

```bash
# Build image
docker build -t tenzro-node .

# Run node
docker run -p 8545:8545 -p 8080:8080 -p 3001:3001 -p 3002:3002 \
  -v tenzro-data:/data/tenzro \
  tenzro-node --role validator --data-dir /data/tenzro
```

### Kubernetes

```bash
# Deploy to GKE (requires kubectl configured)
kubectl apply -f deploy/kubernetes/
```

## Proto Definitions

13 proto3 files under `proto/tenzro/v1/` defining 120+ message types. These serve as API documentation — Rust types are implemented manually for flexibility.

## Documentation

| Document | Purpose |
|----------|---------|
| [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md) | Tenzro Network whitepaper — vision, architecture, agent economy, settlement layer |
| [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) | Protocol specification — architecture, consensus, multi-VM execution, identity, payments, settlement, agents, training, and the concrete Rust implementation |
| [`docs/FOUNDATION.md`](docs/FOUNDATION.md) | Tenzro Foundation: governance structure, treasury, grant programs, ecosystem stewardship |
| [`docs/TOKENOMICS.md`](docs/TOKENOMICS.md) | TNZO token economics: supply, fee model, staking, rewards (testnet phase) |
| [`docs/TDIP.md`](docs/TDIP.md) | Tenzro Decentralized Identity Protocol — unified human/machine identity over W3C DID (three identity classes: human / delegated agent / autonomous agent) |
| [`docs/TRAIN.md`](docs/TRAIN.md) | Tenzro Train — decentralized training protocol layer + Python reference trainer |
| [`docs/GUIDE.md`](docs/GUIDE.md) | Operator and developer guide: build, run, deploy, troubleshoot |
| [`docs/landscape-2026.md`](docs/landscape-2026.md) | 2026 ecosystem context: AP2, x402, ERC-8004, CIP-56 across EVM/SVM/Canton |
| [`docs/did-method-tenzro.md`](docs/did-method-tenzro.md) | `did:tenzro` DID method specification (W3C registration submission) |
| [`docs/operators/`](docs/operators/) | Validator and node operator runbooks |
| [`docs/security/`](docs/security/) | Security model, quantum-resistance plan, audit notes |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributions require sign-off under the Apache-2.0 license.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2024-2026 Tenzro Foundation.
