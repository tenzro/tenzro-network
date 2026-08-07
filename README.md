# Tenzro Network

**Tenzro is the open, distributed execution layer for AI.** Inference, agents, and workflows run across a network of independent nodes instead of one company's servers. Any machine can serve a model, rent out spare compute, and hold data — one stake covers every role, and TNZO settles all of it: consumers pay from their balance, providers earn into theirs. Underneath sit the substrate layers that make execution open — multi-VM settlement (EVM, SVM, Canton/DAML), cross-chain reach, one identity (TDIP), and one settlement asset (TNZO).

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-5%2C158%20passing-brightgreen)](<>)
[![Website](https://img.shields.io/badge/Website-tenzro.com-green)](https://tenzro.com)
[![Testnet](https://img.shields.io/badge/Testnet-Live-blue)](https://rpc.tenzro.xyz)

## What is Tenzro?

**The open, distributed execution layer for AI.** Tenzro is where inference happens, where agents act, and where workflows run — across a network of independent nodes rather than one company's servers. The thesis is straightforward: AI needs somewhere to run that no single provider controls. That means nodes anyone can join, a way to pay for what you use and earn for what you serve, and proofs anyone can check. Today inference and compute live behind opaque centralized APIs, identity is rebound at every protocol boundary, and value can't cross from EVM to Canton without giving up custody. Tenzro fixes this at the protocol layer.

- **Multi-role nodes**: one node, one stake, many roles. A node can serve AI models, rent out spare compute, and hold data at the same time — a single stake covers every role it takes on. Compute rental is availability-proof-gated and billed per epoch; storage is proof-of-retrievability-gated and billed per byte-epoch. In every case the consumer pays from their TNZO balance and the provider earns into theirs.
- **Decentralized AI + compute orchestration**: agents and humans discover and access AI inference (chat, vision, audio, forecasting, embeddings, segmentation, detection), rentable compute capacity, and TEE-backed confidential compute (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) through a single protocol-level marketplace with per-use billing, reputation scoring, and on-chain verifiability. Providers are sovereign — anyone can run a model, expose an endpoint, or contribute compute, and earn TNZO directly. The inference router (price / latency / reputation / weighted strategies) and the agent-spawning + swarm-orchestration primitives let agents compose multi-model, multi-provider workflows without trusting any one party.
- **Universal identity (TDIP)**: one DID for humans, delegated agents, and autonomous agents that works on EVM (via ERC-8004 mirror), SVM, Canton (CIP-26 user binding), AP2 mandates, x402 micropayments, and OAuth/DPoP — same identity, same delegation scope, same revocation surface.
- **Universal wallet (FROST-Ed25519 + ML-DSA-65 hybrid PQ)**: threshold-secured, hardware-attestable, and one balance shared across three VM views — wTNZO ERC-20 on EVM, SPL adapter on SVM, CIP-56 holding on Canton. No bridge risk, no liquidity fragmentation. Pointer-model native asset.
- **Universal settlement (TNZO)**: bridge fees, inference fees, escrow, micropayment channels, training-run grants, and cross-chain destination-native fees (via the Chainlink-backed bridge fee oracle) all denominated and accounted in TNZO.
- **Cross-chain reach as a wire primitive**: LayerZero V2, Chainlink CCIP, Chainlink CCT, Wormhole + NTT, deBridge DLN, LI.FI, Hyperlane V3, Axelar GMP, Babylon Bitcoin staking, and Canton — all behind one ERC-7683 envelope with `BridgeFeeHint`. Users sign once, solvers pick the bridge.
- **Multi-VM execution**: EVM (revm + 9 standard precompiles + 7 BLS12-381 EIP-2537 + 13 Tenzro precompiles) + SVM (solana-svm with SPL Token Program dispatch) + Canton 3.5+ DAML — every contract, every instruction, every command runs against the same identity, same wallet, same TNZO balance.
- **AI inference, generation, and training as protocol-level economic activity**: providers earn TNZO for serving models (chat, vision, audio, forecasting, embeddings, segmentation, detection), rendering diffusion image and video jobs (Tenzro Media Gen), running TEE enclaves, and contributing GPU compute to verifiable training runs (Tenzro Train). Inference results, settlements, and identity claims are verifiable on-chain via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness) or attested by hardware enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) — both anchored via `ZK_VERIFY` and `TEE_VERIFY` precompiles.
- **Humans as peer identity class**: HITL escalation, guardian-quorum recovery, AP2 cart/intent/payment mandates, and delegation scopes are wire primitives, not adapter-layer features.

Tenzro Network is also the reference implementation of the [Open Agent Network (OAN)](https://github.com/tenzro/open-agent-network) — the standards family (TNIP-001..022) for a hybrid human + agent coexisting network. OAN provides the governance framework; Tenzro Network is the working implementation. The wire stays open for other implementations.

## Compute as Currency

Tenzro turns AI compute into a unit of economic exchange — denominated, settled, and verified in TNZO. Four surfaces share the same identity, payment, and settlement substrate:

- **Tokenized AI inference.** Anyone can run AI models (chat, vision, audio, forecasting, embeddings, segmentation, detection) and offer them on the marketplace. Users and agents pay per token (or per inference); providers earn TNZO directly. Confidential variants run inside TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC). Micropayment channels make high-frequency, low-value billing efficient.
- **Tokenized AI training (Tenzro Train).** Decentralized verifiable training using a data-parallel protocol with decoupled outer synchronization. GPU providers contribute compute and earn TNZO; sponsors fund runs from on-chain escrow. Every accepted outer gradient produces a signed receipt, and every run finalizes a run-root commitment on-chain. Phase 1 covers timeseries first, with simple mean aggregation, stake bonding, and the Open trust tier; Byzantine-robust aggregation, multi-region scale, and TEE-resident data are roadmap.
- **Tokenized media generation (Tenzro Media Gen).** Diffusion image and video jobs are posted with a price ceiling, claimed by a worker, rendered, and settled against a signed receipt over what was produced. The work unit is the pixel-step (`width × height × steps × frames`). Models whose transformer is split into a high-noise and a low-noise expert render across two accelerators that could not each hold the whole model: exactly one intermediate latent crosses between the halves, and the payment divides by the share of the denoising schedule each half signed for.
- **Agentic finance.** Autonomous agents discover providers, negotiate, pay, and settle in TNZO using the same TDIP identity, FROST-Ed25519 threshold wallet, and delegation scope. AP2 mandates, x402 micropayments, ERC-8004 trustless-agent registries (mirrored across EVM, SVM, and DAML from a single TDIP write), and ERC-4337 v0.8 smart accounts all run inside Tenzro consensus.

Verifiability is not optional. Inference results, settlements, and identity claims can be proven via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness) or attested by hardware enclaves — both anchored on-chain via the `ZK_VERIFY` and `TEE_VERIFY` precompiles. Tenzro unifies inference, compute rental, storage, training, agent settlement, identity, verification, and cross-chain reach under one open execution layer — not raw GPU rental and not subnet coordination, but the full surface where AI runs.

## The Combination

Individually, the pieces exist elsewhere. What Tenzro composes into one network is the combination: verifiable AI inference and training, confidential compute, multi-modal serving, and agent settlement, all under one identity, one settlement asset, and one consensus layer.

Tenzro combines **EVM + SVM + Canton/DAML** in a single network — and DAML is the execution environment the institutional RWA surface (regulated tokenized treasuries, bank deposit tokens, CIP-56 settlement) is converging on. That breadth is the substrate; the execution layer for AI is what rides on top of it.

On that substrate, **retail-agent rails** (AP2 mandates, x402 micropayments, ERC-8004 trustless agents, ERC-4337 v0.8 smart accounts) and **institutional-RWA rails** (Canton DAML, CIP-56 tokens, DvP settlement) share one identity (TDIP), one settlement asset (TNZO), and one consensus layer.

Two more architectural calls worth flagging:

- **Confidential agent compute is a consensus primitive, not a sidecar.** TEE-attested validators get a 1.5× multiplier on their reputation-weighted leader-selection draw; the `TEE_VERIFY` precompile verifies real Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU CC quotes on-chain — attested execution is built into consensus, not bolted on as middleware over a non-TEE chain. Tenzro consensus is two-phase HotStuff-2 with reputation-weighted proposer election, no-endorsement certificates for tail-fork resistance, and Ed25519 + ML-DSA-65 hybrid post-quantum signatures on every safety-critical message.
- **TNZO is a pointer-model native asset.** One balance, three VM views (wTNZO ERC-20 on EVM, SPL adapter on SVM, CIP-56 holding on Canton) — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f`), and W3C DID (`did:tenzro`).

For the full architecture see [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md) and [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md).

## Architecture

```
                    +-------------------------------------+
                    |         User Interfaces             |
                    |      CLI / SDKs / MCP / A2A         |
                    +--------------+----------------------+
                                   | JSON-RPC + HTTP
                    +--------------v----------------------+
                    |           tenzro-node               |
                    |   RPC (855) + MCP (526) + A2A (41)  |
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

## Workspace — 32 Crates

| Crate                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **tenzro-types**            | Core types, constants, primitives (zero internal deps)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-crypto**           | Ed25519, Secp256k1, AES-256-GCM, X25519, BLS12-381, FROST-Ed25519 threshold signatures (RFC 9591), VRF (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **tenzro-tee**              | TEE abstraction: Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber Trust Authority with X.509 cert chain verification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-zk**               | Plonky3 STARKs over the KoalaBear field (Poseidon2 + FRI), four pre-built AIRs (inference / settlement / identity / pq-qc — the last giving a quorum certificate a succinct post-quantum leg, since ML-DSA-65 signatures do not aggregate the way BLS does), no trusted setup, post-quantum sound                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-network**          | libp2p P2P networking (control plane): gossipsub, Kademlia DHT, peer management, rate limiting, Identify + AutoNAT v2 + Circuit-Relay v2 + DCUtR for permissionless NAT traversal                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-iroh**             | iroh data plane (content-addressed transport): `IrohBackedResolver` over QUIC + iroh-blobs, DA backend, gradient store, sealed-shard store, A2A-over-iroh on the `tenzro/a2a` ALPN. Resolves `tenzro://{blob,gradient,shard,manifest,memory}/...`. TDIP-anchored Pkarr discovery (EndpointId byte-identical to TDIP key)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-storage**          | RocksDB with column families, Merkle Patricia Trie, snapshots, fsync durability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **tenzro-wallet**           | FROST-Ed25519 (RFC 9591) 2-of-3 threshold wallets + ML-DSA-65 hybrid PQ leg, Argon2id keystore, transaction builder, nonce management, key zeroization                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-keystore-unlock**  | Platform-agnostic `KeystoreUnlocker` trait for reproducing the wallet keystore password across restarts (`StaticUnlocker`, `EnvUnlocker`); no platform dependencies, so it sits in the public API of wallet/node without pulling in OS crates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **tenzro-device-key**       | Hardware-backed non-extractable P-256 device keys (macOS/iOS Secure Enclave, Touch ID / Face ID gated): biometric prehash signing and stable secret wrapping/unwrapping used to derive a persistent keystore password                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **tenzro-auth**             | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests), and WebAuthn attestation verification — what a device actually proved about the hardware holding its key, checked against pinned vendor roots rather than a platform account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-consensus**        | HotStuff-2 BFT: three-phase PREPARE → COMMIT → DECIDE, stake-weighted quorum with a 10% per-validator cap (consensus voting reserved for staked validators; service roles earn proof-of-service rewards), TEE-weighted leader selection (1.5×), equivocation detection + slashing, batch availability certificates so proposals order certificate hashes instead of transaction bodies, quorum-gated ZK commitment attestation (a `ZK_VERIFY` commitment is admitted only with a `2f+1`-stake-weight BLS certificate over independent re-verification)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-vm**               | Multi-VM: EVM (revm) + SVM (Anza `solana-svm` `TransactionBatchProcessor`, behind the `svm-full` feature) + DAML, Block-STM parallel execution, EIP-1559, ERC-4337 AA, ERC-7579 modular validators, **EIP-7702 Type-4 delegation registry**, **Permit2 SignatureTransfer + witness** (ERC-7683-ready gasless flows), **Secure-Mint precompile** (1:1 reserve-attestation invariant for tokenized assets), standard EVM + EIP-2537 BLS12-381 + Tenzro precompiles (TEE_VERIFY, ZK_VERIFY, VRF_VERIFY at 0x1007)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-token**            | TNZO token economics: treasury, staking, governance, epoch rewards, liquid staking (stTNZO)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| **tenzro-identity**         | TDIP: unified human/machine identity, W3C DID documents, verifiable credentials, delegation scopes, GDPR Article 17 right-to-erasure (`tenzro_forgetIdentity`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-payments**         | Agentic payment protocols. **Crypto rails (settle on-chain):** AP2 v0.2 (Google/FIDO) mandate sign + verify + validate-pair, MPP (Stripe + Tempo) sessions, x402 v1 (Coinbase) HTTP 402 with a resource bazaar (register / discover / deregister paid resources, offer verification, idempotent payment ids) across the tenzro-hybrid, exact-eip3009, permit2, and erc7710 schemes, Stripe SPT (SharedPaymentToken) issuance + verify with TDIP cap-resolver + ERC-8004 ReputationRegistry cross-write, Tempo (EIP-155 signing), ERC-8004 v0.6+ Trustless Agents Registry (Identity / Reputation / Validation, 22 surfaces). **Card rails (Tenzro provides identity + delegation + audit; card networks settle fiat):** Visa TAP (Trusted Agent Protocol), Mastercard Agent Pay. HTTP 402 middleware, RFC 9421 HTTP message signatures.                                                                                                                                                                                                                                                                                                                                             |
| **tenzro-agent**            | AI agent infrastructure: A2A protocol, MCP bridge, capability attestation, durable persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-agent-kit**        | High-level agent SDK: compose agents from skills, tools, and payment protocols                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-model**            | Model registry, modality-aware inference routing (price/latency/reputation), content-addressed peer-first model distribution (BLAKE3-hashed weights, `tenzro://blob/<hash>` URIs, `HfArtifactDownloader` fetches from peers over iroh blobs and falls back to HuggingFace; `ModelHashRegistry` first-recorder-wins + verify-before-load). Multi-gigabyte artifacts already on disk are published by reference (`publish_path` / `ImportMode::TryReference`) so a served model is not duplicated into the blob store. Durable catalog. Local inference via llama.cpp across every ggml backend (CUDA, ROCm, Metal, Vulkan, SYCL, OpenCL, WebGPU, MUSA, CANN, OpenVINO, zDNN, BLAS — one per build, CPU otherwise). Multi-modal ONNX runtimes: forecast (TimesFM 2.5), vision (CLIP, SigLIP2, DINOv3, DINOv2), text-embedding (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic), segmentation (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM), detection (RF-DETR, D-FINE), audio ASR (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary-1B-Flash), video (encoder scaffold). License-tier gating: Permissive / Attribution / CommercialCustom / NonCommercial. |
| **tenzro-cortex**           | Recurrent-depth reasoning workers (RDT/MoE): HTTP sidecar architecture, signed receipts, attestation suite, gossip-based worker discovery, depth-priced billing                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **tenzro-training**         | Tenzro Train protocol layer (data-parallel with decoupled outer synchronization): aggregation rules (Mean, LoraAlternating, TrimmedMean, CoordinateMedian, Krum), Nesterov outer optimizer with adaptive learning rate, blockwise Int8/Int4 gradient quantization, chunked top-k sparsification with a 2-bit codec and a local error-feedback accumulator for the dropped mass, streaming shard synchronization, pipeline trainer groups, syncer state machine, on-chain run-root commitments. Pairs with the Python reference trainer at `integrations/trainer/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| **tenzro-media-gen**        | Tenzro Media Gen protocol layer: diffusion job queue, worker registry, pixel-step pricing, split-expert claim and latent handoff, proportional payment division, three signed commitments (job id / handoff / receipt), content-addressed output store. Pairs with the Python reference worker at `integrations/media_gen/`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **tenzro-settlement**       | Escrow, micropayment channels, batch settlement, dispute resolution, and streaming rental escrow: time-based capacity rental with renter deposit + per-epoch streaming release gated on signed availability proof; provider stake collateralizes one-epoch exposure across active rentals, make-whole-from-stake on miss                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-storage-provider** | Decentralized storage over the iroh content-addressed transport: provider daemon (accept / serve objects), nonce-bound proof-of-retrievability challenges, systematic Reed-Solomon erasure coding (replication as the k=1 case), per-byte streaming metering gated on a passing retrievability proof (`ServiceType::Storage`), capability-gated retrieval (`AccessPolicy` + optional confidential seal)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **tenzro-cluster**          | Engine-agnostic local-network cluster substrate shared by model, storage, and database serving: reachability tiers, probed link-cost graph, deterministic nearest-neighbour ordering, and HRW rendezvous placement — every function is a deterministic function of measured inputs, so members converge on the same plan without a coordinator round                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **tenzro-database**         | Managed-database protocol layer (engine-agnostic, no driver): `DatabaseDescriptor`, placement across local / LAN-cluster / network tiers, engine catalog (PostgreSQL, Qdrant, Milvus, Valkey, Dgraph, Lance, Tantivy). Five engines have a driver (PostgreSQL / Qdrant / Valkey as thin stateless clients to an operator-run engine; Lance / Tantivy embedded in-process); Milvus and Dgraph are catalog-only until a driver is linked. Per-engine config validation, `AccessPolicy` + confidential seal, managed connection credentials, `tenzro/databases` gossip                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **tenzro-bridge**           | Cross-chain: Wormhole NTT (Guardian quorum verifier), LayerZero V2, Chainlink CCIP + CCT, deBridge DLN, Li.Fi, Canton DAML, Hyperlane V3 (sovereign Tenzro-ISM), Axelar GMP (Cosmos / Move / Stellar reach), Babylon Bitcoin staking                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **tenzro-events**           | Event sourcing and subscription system with replay, webhooks, websockets                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-workflow**         | Multi-party workflow runtime: orchestrates Canton DAML receipts, on-chain transaction selectors `0x01000040`–`0x0100004B`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **tenzro-wasm**             | WASI 0.2 component host for sandboxed agent skills and MCP tools: language-agnostic, capability-based, deterministic fuel metering, content-addressed component identity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-node**             | Full node binary: JSON-RPC (932 methods), MCP (535 tools), A2A (40 skills), Web API                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **tenzro-cli**              | CLI tool: 108 command modules with interactive mode and full RPC coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

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
# Guided setup — join the public network (consume, provide, or validate),
# create a local or sovereign network, or join an existing private network
tenzro setup

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
./target/release/tenzro-node --roles validator --data-dir ./data

# Light client
./target/release/tenzro-node --roles light --data-dir ./data

# One node serving inference and holding storage under one stake
./target/release/tenzro-node --roles ai,storage --data-dir ./data
```

### Run Your Own Network

```bash
# Bootstrap a self-contained network: validator keyset, schema-v3 genesis,
# service unit, and the exact join command for each peer
tenzro setup --path local --network-name lab

# Join an existing private network
tenzro setup --path private --genesis ./genesis.toml --bootstrap <multiaddr>
```

### Become a Provider

Bring your GPU, cluster, or data center and earn from network demand. With
a node running (`tenzro-node --roles ai`), one command handles everything:

```bash
tenzro join --provider
```

Hardware detection, wallet provisioning, faucet funding, the 1,000 TNZO
compute bond the model-provider rung requires, provider registration,
default pricing, and pulling + serving
the largest catalog model that fits your machine are all automatic. Your
capacity is advertised on the provider gossip topic and inference demand
routes to you, settling in TNZO per call.

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

| Server       | Port | Protocol        | Endpoints                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------ | ---- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **JSON-RPC** | 8545 | HTTP            | 932 methods across 31+ namespaces (EVM-compatible + Tenzro extensions, incl. multi-modal AI: forecast, vision, text-embed, segmentation, detection, audio, video; generative media; MoE sharded serving; LAN clustering; managed databases; app hosting: sites, functions, machines, leases; CAIP discovery; EIP-7702 delegation; Permit2; Secure-Mint; Capital Intent; Workflow). The same listener also serves the OpenAI-compatible HTTP routes `/v1/chat/completions`, `/v1/responses`, and the HTTP 402-gated `/api/paid/chat/completions` |
| **Web API**  | 8080 | REST            | Verification (`/verify/*`), `/status`, `/faucet`, `/health`, `/chat`, `/providers`, `/discovery/resources`, OAuth token/introspect/revoke, passkey wallet                                                                                                                                                                                                                                                                                                                                                                                       |
| **MCP**      | 3001 | Streamable HTTP | 535 tools + OAuth 2.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **A2A**      | 3002 | JSON-RPC + SSE  | Agent Card with 40 skills, task streaming                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

### Ecosystem MCP Servers

| Server        | Port | Tools | Coverage                                                                                 |
| ------------- | ---- | ----- | ---------------------------------------------------------------------------------------- |
| **Solana**    | 3003 | 14    | Jupiter swaps, SPL tokens, Metaplex NFTs, Bonfida SNS                                    |
| **Ethereum**  | 3004 | 17    | Chainlink feeds, ENS, ERC-8004 agents, EAS attestations                                  |
| **Canton**    | 3005 | 23    | DAML contracts, CIP-56 tokens, DvP settlement, user/party management, IDP administration |
| **LayerZero** | 3006 | 21    | V2 messaging, OFT, Stargate, Value Transfer API                                          |
| **Chainlink** | 3007 | 21    | CCIP, data feeds/streams, VRF v2.5, automation, functions                                |
| **LI.FI**     | 3008 | 9     | Cross-chain aggregation, routing, gas estimation                                         |

### Authentication (Tiered)

- **Public tools** (no auth): `get_node_status`, `list_models`, `get_balance`, `resolve_did`, `debridge_search_tokens`, etc.
- **Write tools** (auth required): `send_transaction`, `create_wallet`, `stake_tokens`, `register_identity`, etc.
- **Auth method**: OAuth 2.1 + DPoP (RFC 9449) — bearer JWT minted via `tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` / `tenzro_onboardAutonomousAgent`. Each request carries `Authorization: DPoP <jwt>` plus a fresh `DPoP: <proof>` header (per-request JWS-compact, bound to the JWT's `cnf.jkt` thumbprint per RFC 7638). RAR scopes (RFC 9396) constrain the JWT to specific tools and amounts.
- **API keys (operator-issued)**: `tnz_...` keys minted by the RPC operator via `tenzro_createApiKey` (admin-token-gated) and presented as `X-Tenzro-Api-Key`. Scopes gate methods that consult third-party paid resources: `canton` (Canton JSON Ledger API), `chainlink` (Ethereum mainnet RPC quota for Chainlink Data Feeds + bridge fee oracle + per-adapter sponsorship), `evm` / `svm` / `inference` / `tee` / `bridge` for operators who monetise those surfaces. Per-tenant counters in `CF_CANTON_ANALYTICS` + `CF_BRIDGE_ANALYTICS`. GCRA rate-limit on `chainlink`-scoped methods.
- **Revocation**: `tenzro_revokeJwt` (single token by `jti`) or `tenzro_revokeDid` (cascading through the act-chain).
- **Config**: `TENZRO_MCP_AUTH=tiered` (default) | `false` (dev) | `full` (all tools require auth)

## Key Features

### Multi-VM Execution — three VMs, one state machine

A chain that picks one VM forces every workload to fit that VM. Tenzro runs three and routes by transaction type. All three share the same state, the same gas token (TNZO), the same TDIP identity, and the same consensus.

- **EVM — liquidity and composability.** The Ethereum surface targets the broadest pool of existing contracts and tooling. Tenzro embeds revm with every standard precompile (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, EC_ADD, EC_MUL, EC_PAIRING, BLAKE2F) per the canonical EIPs, plus all seven BLS12-381 precompiles (EIP-2537) for native consensus-grade signature aggregation. Block-STM gives parallel transaction execution with MVCC concurrency control and automatic sequential fallback under contention. EIP-1559 dynamic fee market burns the base fee. Native primitives extend the EVM with protocol-aware precompiles: `TEE_VERIFY` (hardware attestation with vendor certificate-chain validation), `ZK_VERIFY` (O(1) commitment lookup against the on-chain Plonky3 registry), `VRF_VERIFY` (RFC 9381 ECVRF), `IBC_VERIFY` (IBC-Eureka light-client lookup), the Tenzro precompile slate (`TNZO_BRIDGE`, `TOKEN_FACTORY`, `CROSS_VM_BRIDGE`, `STAKING`, `GOVERNANCE`, `NFT_FACTORY`, `MODEL_INFERENCE`, `SETTLEMENT`, **global supply accounting** at `0x1021`, **module registry** at `0x1022`), ERC-4337 v0.8 account abstraction, EIP-7702 Type-4 delegation, Permit2 SignatureTransfer with witness binding, and ERC-7579 modular validator modules (social recovery / session keys / spending limits / WebAuthn passkey / TEE-bound).
- **SVM — throughput and latency.** The Solana surface targets workloads that need sub-second finality and high throughput — DEX routing, agent-to-agent micropayments, real-time settlement on a path. Tenzro embeds Anza's `solana-svm` `TransactionBatchProcessor` (behind the `svm-full` cargo feature) so Solana SBF programs run unmodified; without that feature the SPL Token adapter, the cross-VM native program, and PDA derivation still work while the SBF path returns `VmError::SvmFullFeatureRequired`. The SPL Token program maps onto the native unified token registry — a swap on SVM settles in the same balance space as a transfer on EVM. There is no bridging between the two VMs.
- **Canton DAML — privacy and institutional settlement.** Canton is where the institutional financial system already settles tokenized cash, money-market funds, bonds, equities, treasuries, and OTC derivatives. Tenzro speaks Canton 3.5+ JSON Ledger API v2 directly. CIP-56 Canton Coin holdings round-trip with TNZO; CIP-26 user management binds each tenant to its own party with `CanActAs` rights enforced server-side; DAR upload, party allocation, command submission, and active-contract queries are all available through the same node API surface as EVM and SVM calls. Canton's privacy model means the transaction body is visible only to its signatories; Tenzro provides the cross-VM orchestration and the public commitment.
- **Cross-VM token model — Sei V2 pointer.** TNZO has a single canonical native balance. The wTNZO ERC-20 pointer on the EVM side and the wTNZO SPL adapter on the SVM side share the same underlying balance — there is no bridge between them, no wrapped/unwrapped distinction, no liquidity fragmentation. Canton CIP-56 holdings round-trip through the Canton bridge adapter. From the application's perspective, a wallet has one TNZO balance regardless of which VM it last touched.
- **What this composes into.** An agent settling a DvP between a tokenized treasury (Canton) and a stablecoin payment (EVM) executes the whole thing as one workflow through one identity. An agent paying for a Solana DEX swap and posting a receipt on Tenzro consensus does it with one TNZO balance. Cross-VM coordination is a workflow primitive, not application code.

### Decentralized AI infrastructure

The protocol layer treats AI compute as a coordinated resource, not a centralized service.

**Tenzro does not ship models of its own.** Every model named anywhere in this README — Qwen, DeepSeek, GLM, Kimi, Gemma, MiniMax, FLUX, Wan, LTX, SAM, CLIP, Whisper and the rest — is a third-party checkpoint the network _supports_, not a first-party or proprietary one. The serving path is model-agnostic: `load_model` takes a GGUF path, and llama.cpp derives the architecture from the file's own metadata, so the `ModelArchitecture` enum is informational (for display and filtering) rather than an allowlist. A model with no catalog entry serves on documented defaults.

What the curated catalog buys you is metadata and convenience, not permission. Every one of its entries was chosen for being **ungated** — downloadable with no HuggingFace login — so a fresh node can fetch and serve without the operator holding an account.

**Per-model configuration is pluggable, not a single forced schema.** Models genuinely differ in what they need, and a lowest-common-denominator config would either fail the demanding ones or burden the simple ones. So a catalog entry is a set of optional, defaulted slots and a model declares only what actually applies to it: a multimodal projector (`mmproj`) only if it has one, a paired drafter and MTP kind only if it supports speculative decoding, a `MoeShape` only if it is sparse, a sampling `ServingProfile` where the defaults are wrong for that family, a `ReasoningPolicy` where the model has a thinking mode. Where a model's own chat template is broken upstream, `TemplateFix` names a vendored replacement — the catalog declares _which_ fix, the inference client supplies the file — rather than the runtime special-casing that model. Anything left unset falls back to a documented default, which is why an uncatalogued GGUF still serves. The same shape holds for generative media, where entries carry pixel-step pricing, split-expert boundaries and frame limits per pipeline; some models are served through authored configs pinned to a specific upstream version rather than a generic path.

**Being in the catalog is not a claim that a model has been verified end to end.** The registry is broader than what has been exercised on real hardware, and we do not imply otherwise. Testing is ongoing: when a model turns out to need something the generic path does not give it — a corrected chat template, different sampling defaults, a frame limit, a pinned upstream version — that becomes a new optional slot on the entry, added as needed to run _that_ model, and left unset for every model that does not need it. This is why the config surface is additive and per-model rather than a schema fixed up front: it grows in response to what real checkpoints actually turn out to require. If you hit a model that misbehaves, that is a gap to report, not a limit of the design.

**Gated models are supported; they carry their own credential.** Some of the strongest open checkpoints are gated: free to read about, but requiring per-account approval to fetch (the FLUX.2-dev and klein-base-9B lines are `gated: auto` on the Hub, and Llama's GGUFs likewise — which is the only reason Llama is not a default catalog entry). To use one, accept its terms on HuggingFace and give the node your own token: `HF_TOKEN`, or `HUGGING_FACE_HUB_TOKEN`, or the file `huggingface-cli login` already wrote to `~/.cache/huggingface/token` — all three are read, so an operator who logged in the ordinary way needs to do nothing else. The token is the operator's own credential for their own account: it is sent only to huggingface.co, never persisted by the node, and redacted out of logs. Without one, a gated fetch fails with a 401/403 and the error names the repository and the exact terms page to accept. `tenzro status` reports whether a token is present, because otherwise a missing credential surfaces only as an unexplained download failure.

- **Distributed Mixture-of-Experts serving.** MoE models (Qwen 3.5 122B-A10B / 397B-A17B, DeepSeek V3 / V4 Pro 1.6T-A49B / V4 Flash, GLM 5.1 / 5.2, Kimi K2 / K2.6 / K3 2.8T-A104B, MiniMax M3, Gemma 4 26B-A4B) serve in two modes. **Full-replica** when one provider's hardware fits the model. **Decentralized expert shards** when it doesn't — providers declare which experts they hold via `ProviderCapacity.moe_holdings`, and the dispatch planner aggregates per-token top-k routing decisions into per-holder batches dispatched directly over the holder's iroh QUIC endpoint. The shard view is a derived view over the existing provider registry — MoE providers are the same network providers that serve dense models. Replication is governance-tunable (default ≥ 2 holders per expert, up to 8 for popular experts). Typed pipeline roles: `Replica`, `Router`, `ExpertHolder`, `PrefillDecode`, `Prefill`, `Decode`. Execution runs in the node: `MoeExpertRuntime` hosts per-expert FFN weights (`ExpertFfn`) and gating networks (`GatingNetwork`) loaded from safetensors (local file or `tenzro://blob` URI over iroh-blobs); a forward pass gates locally, fans expert sub-batches out to holders over the `tenzro/moe` iroh ALPN (with HTTP fallback), and combines the weighted expert outputs. A holder can advertise more experts than fit in memory: the runtime keeps experts in a byte-bounded memory-tier LRU (budget auto-sized to 60% of `MemAvailable`, else 4 GiB) backed by a disk tier that spills raw safetensors and decodes them back on demand, and readahead promotes the disk-tier experts a forward is about to hit before the batch arrives. Residency (`Warm` memory / `Cold` disk) is read from the live tier state, so the shard map reflects what is actually loaded. The expert projection math (`Y = X·Wᵀ`) runs behind an `ExpertCompute` seam so the same forward path uses whatever hardware a holder has: a CPU `ndarray` path is always present (with a runtime-detected AVX-512-VNNI Q8_0 dot path on capable x86), while GPU backends compile only under cargo features (`moe-cuda` for cuBLAS grouped-GEMM on NVIDIA, `moe-wgpu` for a cross-vendor WGSL kernel; `moe-gpu` enables both) and never enter a default build — a holder advertises `moe_gpu` so the router biases expert placement toward GPU holders. Experts can be block-quantized to shrink both the stored blob and the bytes moved between holders — `Q8_0` (~1 byte/weight), `Q4_K` (~4.5 bpw), `Q6_K` (~6.6 bpw), with `ExpertQuantPlan::q4_k_m` (gate/up Q4_K, down Q6_K) as the balanced default, dequantized one row at a time. Cross-holder dispatch compresses activations to Q8_0 blocks when the hidden dim is a multiple of 32, redispatches to warm backup holders when one is slow or missing, and streams holder responses into a combiner that fails loudly if any expected contribution never lands. Planning RPCs: `tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`. Execution RPCs: `tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moePrepareExperts`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`. CLI: `tenzro moe {shard-map, plan-dispatch, replication-policy, catalog-shape, load-expert, load-gate, unload-expert, unload-gate, prepare-experts, status, forward}`.
- **LAN clustering — layer-wise pipeline parallelism.** When no single member fits a model, a set of machines on the same LAN serve it together as a pipeline: the model's layers are partitioned into contiguous stages, one stage per member, and only the boundary activation (`hidden_dim × dtype_bytes` per token, fp16) crosses the wire between adjacent stages. Placement is deterministic — VRAM-weighted largest-remainder layer assignment, greedy nearest-neighbour stage ordering, and a reachability gate that excludes members that cannot hold a data-plane link — with no model in the hot path. Members must share one runtime build commit (no wire-version negotiation); mixed backends across members are fine. RPC `tenzro_clusterPlan` returns the fit decision and, when a cluster forms, the ordered per-member layer stages. Serving auto-triggers the pipeline: `tenzro_serveModel` reads the GGUF header for the model shape, discovers members from gossiped `ClusterProfile` announcements, and runs the cluster when one host cannot hold the model — pass `force_single` to keep it on one host, or supply `cluster_members` to override discovery.
- **Local-first discovery and routing.** Nodes discover peers on their own LAN segment via mDNS (`tenzro_localPeers`) and publish a sustained connectivity tier — `direct` / `relay_only` / `unreachable` (`tenzro_nodeReachability`). The execution resolver prefers a local provider and falls back to the wider network only when none is reachable (prefer-local-with-fallback), so a request served by a machine on the same LAN never leaves it. Each node also exposes a hardware self-profile — runtime build commit, CPU architecture, OS, detected compute devices, and derived serving capacity / backend / capability key (`tenzro_nodeProfile`) — which feeds both single-box fit and cluster planning.
- **Multi-Token Prediction (MTP) speculative decoding.** The in-process runtime runs speculative decoding: the drafter proposes a block of candidate tokens, the target verifies them in one batched decode, and the accepted prefix advances the stream. Serving a model auto-loads its paired drafter — `tenzro_serveModel` reads the catalog `drafter_id`, loads it from disk or downloads it in the background, and reports the outcome in the serve response's `mtp` field. Declared for DeepSeek V3 (native, ~80% accept rate, ~1.8× decode), DeepSeek V4 Pro / Flash, GLM 5.2, Gemma 4 (all sizes), Qwen 3.5 (0.8B/2B/4B/9B/27B/35B-A3B/122B-A10B/397B-A17B), and Qwen 3.6 27B + 35B-A3B. Providers advertise drafter co-load via `ProviderCapacity.mtp_enabled`; the inference router filters MTP-eligible requests to MTP-capable providers when `draft_n` is set.
- **Vision-capable language models in-process.** A GGUF that carries a multimodal projector (`mmproj`) loads the projector alongside the language weights, so image attachments are encoded and interleaved into the prompt inside the same runtime rather than routed to a separate vision service. Catalog entries declare the projector via `MmprojSpec`; the path compiles under the `mtmd` cargo feature.
- **Difficulty-aware routing.** Model selection from declared metadata (parameter count, context window, capability tags) says nothing about whether a specific prompt needs the expensive model. Prompts are embedded and grouped by an online sequential k-means map that grows on demand — no training corpus, no offline fit — and each model accrues per-cluster outcome counters from real serving results, so its strength is a measured property per prompt neighbourhood. A newly registered model starts at a neutral prior with an optimism bonus so it stays explorable. Cluster map and counters persist in `CF_MODELS` and hydrate on startup.
- **Network model catalog.** Providers broadcast signed model offers on `tenzro/models` carrying modality, capabilities, context length, the provider's own price, a serving schedule, a TTL, and the serving address. The node verifies each announcement, pins the signing key per `(model_id, provider)` pair, and hands the unexpired set to intent routing — so routing scores every live offer on the network, not only what the local operator registered, and the settlement split follows the payee named in the winning offer.
- **Decentralized training — Tenzro Train.** A data-parallel protocol with decoupled outer synchronization. Rust protocol layer (`tenzro-training`) owns the syncer state machine, five aggregation rules (Mean / LoraAlternating / TrimmedMean / CoordinateMedian / Krum), Nesterov outer optimizer, fragment commitment, training receipts, and on-chain run-root commitments. Python reference trainer wraps PyTorch FSDP2 + Hivemind + safetensors for per-modality inner loops (transformers, native PyTorch, gluonts, timm). k-of-N witness committee with idempotent finalization and no-endorsement certificates handles multi-syncer coordination across regions. Communication efficiency: blockwise symmetric gradient quantization (Int8 4×, Int4 ~8× smaller than f32, byte-identical Rust/Python codecs), streaming synchronization (one parameter shard syncs per round, `active_shard = round % num_shards`), delayed application (round r's outer update applies during round r+1 so communication overlaps computation), adaptive outer learning rate scaled by pairwise cosine gradient agreement, and pipeline-parallel trainer groups for models too large for one trainer. Inner optimizer is selectable per task (`inner_optimizer`: `muon` / `adamw` / `sgd`) — Muon orthogonalizes 2D weight updates with Newton-Schulz iteration. Confidential tier uses HPKE RFC 9180 base-mode wrapping of per-shard data keys to enclave-resident trainers (data unsealed only inside the trainer's TEE). Three trust tiers: Open (Mean and LoraAlternating), Verified, Confidential.
- **Diffusion media generation — Tenzro Media Gen.** Image and video generation as a network resource, across four job kinds (`text2image`, `image2image`, `text2video`, `image2video`). Rust protocol layer (`tenzro-media-gen`) owns the job queue, worker registry, pixel-step pricing, payment division, the three signing preimages, and the content-addressed payload store; the Python reference worker (`integrations/media_gen/`, HuggingFace `diffusers`) owns the denoising loop and nothing else. The preconfigured catalog entries are third-party checkpoints — Qwen-Image and its four-step distillation, Qwen-Image-Edit, Z-Image-Turbo, FLUX.2-klein, the Wan 2.2 video family, LTX — none of them Tenzro's own. They are the pipelines that ship with metadata (pixel-step pricing shape, split-expert boundary, frame limits) already filled in; a worker advertises the pipelines it actually holds, so the set is a starting point rather than a boundary. Enrollment refuses a model whose license tier the operator has not accepted, and gated weights need the operator's own HuggingFace token as above. **Split-expert rendering** covers models whose transformer is a high-noise / low-noise expert pair — a fixed noise threshold (`t ≥ boundary_ratio × num_train_timesteps`) decides which expert owns a step, so one expert fits 48 GB where the whole model needs 80, exactly one intermediate latent crosses between the halves, and payment splits by `steps_completed / total_steps` taken from the signed handoff rather than either worker's later claim. Output, latent, and conditioning image are all addressed by `tenzro://blob/` and verified on read. RPCs under `tenzro_mediaGen_*`; CLI `tenzro media-gen {catalog, quote, post-job, get-job, get-receipt, fetch-output, enroll-worker, claim-job, publish-output, record-handoff, submit-receipt, fetch-latent}`.
- **Cortex.** Recurrent-depth-Transformer reasoning workers exposed as a separate compute lane — HTTP sidecar architecture, signed receipts, attestation suite, gossip-based worker discovery, depth-priced billing.
- **Confidential inference.** Model providers can wrap inference inside an Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC enclave; the result hash is signed with an enclave-bound key and the attestation chain verifies through `TEE_VERIFY` on-chain.

### Decentralized application hosting

Publish a static site, a server-side function, or an unmodified long-lived server to Tenzro nodes and serve it over the public internet — with no manual TLS, DNS, Caddy, or port setup. Three runtime classes share one deploy → discover → place → serve path:

- **Static sites and single-page apps.** A site is a signed route manifest mapping request paths to content-addressed blobs in the node's iroh store (`tenzro://blob/<hash>`). Content never touches the filesystem; a request path only indexes the route map. SPA fallback serves the index at 200 for non-asset paths (asset misses 404 directly so a missing bundle chunk is never masked). Responses carry an ETag (the blob hash) with `If-None-Match` 304 support. RPC `tenzro_siteDeploy` / CLI `tenzro site deploy`.
- **Functions.** A `wasi:http` component (WASI 0.2, hosted on wasmtime under the `wasi-skills` feature) that answers requests directly in a sandbox with capability-gated authority, deterministic fuel metering, and a per-request wall-clock deadline. RPC `tenzro_functionDeploy` / CLI `tenzro function deploy`.
- **Machines.** A resident process in a Firecracker microVM (under the `firecracker` feature, on operator nodes with KVM + nested-virt) for an unmodified Node / Python / Rust server. RPC `tenzro_machineDeploy` / CLI `tenzro machine deploy`.
- **Placement and economics.** A provider's advertised per-hour price is its bid; deploy discovers capable nodes, hard-filters by runtime class / CPU / RAM / disk / TEE / price ceiling, ranks region-first then cheapest, and leases the top-N distinct nodes — recorded as on-ledger `LeaseRecord`s readable via `tenzro_listLeases` / `tenzro_getLeasesForApp` (CLI `tenzro lease list` / `tenzro lease get`). Placement is best-effort: with no capable remote node, the app serves locally so deploy never fails. A 30s reconcile pass sweeps expired leases (provider-announcement TTL staleness is the liveness signal) and re-places replicas of silent nodes onto survivors, holding replica count stable. Deploy flags: `--replicas`, `--region-hint`, `--max-price-per-hour`.
- **Operator-configured edge.** Each operator configures the domain its edge serves apps under — there is no network-wide canonical host. A hostname alias rewrites an incoming request to the app's serving path; the edge forwards over the `tenzro/http` transport (one QUIC bi-stream per HTTP request) to a placed node and streams the response back. TLS at the edge is PQ-hybrid and provisioned automatically. Naming, placement, and mutations all require a signed envelope proving control of the owner DID.

See [`docs/HOSTING.md`](docs/HOSTING.md) for the full RPC and CLI surface.

### Tenant file storage

Multi-tenant object storage behind `/v1/files`, layered over the content-addressed storage provider rather than replacing it. The provider knows an object by the id the caller assigned and can rebuild its bytes from shards; what it deliberately does not know is that a given object is _Alice's `notes.txt`, uploaded on Tuesday_. That is application metadata, and pushing it down into the shard layer would mean every provider holding a shard also holds the filename and owner of the thing it is a fragment of. So the naming layer stays local to the node the tenant uploaded through, and the storage layer holds only bytes.

Uploads are erasure-coded into 4 data + 2 parity shards — surviving two simultaneous provider losses — and distributed across independent providers, with a streaming storage deal funding them. A `null` `deal_id` on the upload result means the bytes landed but nothing is paying to keep them.

Isolation is enforced per operation, and listing is the critical path: retrieve, content and delete each address one known id, so a missing ownership check there leaks one file to someone who already guessed its id, whereas `list` _enumerates_. A lookup for another tenant's file id is reported identically to one that does not exist. Deletion unlinks the reference and stops the deal; it does **not** erase shards, which expire only once the deal stops paying for them — so it must not be treated as redaction. RPCs `tenzro_uploadFile` / `tenzro_listFiles` / `tenzro_getFile` / `tenzro_deleteFile`; CLI `tenzro files {upload, list, get, download, delete, usage}`.

### Rented hardware sessions

When an operator rents out a node, the renter should be able to use the hardware directly, not only through the node's RPCs. The model is GCP OS Login + IAP and AWS SSM Session Manager — identity-scoped, short-lived, no inbound port, revocable at the source, and audited — not a handed-out root SSH key. Authorization and confinement live in the node; the transport is the `tenzro/shell` iroh ALPN.

Three factors gate a session, each answering a different question. A **service key**, provisioned by the operator or minted automatically when a rental deposit lands, establishes _which lease_ is being invoked — on its own it proves only that someone was given a string. A **passkey ceremony against the caller's Tenzro wallet** (the browser-launch flow the wallet already runs: the CLI prints a link, the user verifies in a browser, the CLI polls) makes the session attributable to a _person's wallet_ rather than to whoever holds the key. And **membership in the lease's authorized-wallet list** means a leaked key is not by itself usable.

The lease is also the scope: which accelerators, how many cores, how much memory, whether outbound egress is permitted (off by default — a rented shell is for compute, and the operator's local networks stay unreachable either way), the per-session wall-clock ceiling (capped at 12 hours), and the lease term. Omitting the accelerator list yields a CPU-only lease, because "all GPUs" is not a scope anyone chose. Revoking a lease kills every outstanding session grant against it. CLI `tenzro shell login` and `tenzro shell lease {open, revoke, list}`.

### 3D asset generation

Image-to-3D sits in the same job queue as image and video rather than beside it. The surrounding machinery — posting, claiming, content-addressed output, signed receipts, pixel-step settlement — is identical; only the loader and the artifact differ, and those are exactly what the catalog entry carries.

- **Kinds.** `MediaGenKind` gains `image23d` and `text23d`. The output is a GLB mesh with PBR materials, not frames, so nothing downstream tries to decode it as video.
- **Pluggable backend, nothing forced.** A media-gen entry declares its `backend`, defaulted to `diffusers`. That default is what keeps every existing pipeline byte-for-byte unchanged. `trellis2-4b` loads through Microsoft's own `trellis2` package, which is not a `diffusers` pipeline at all — pushing it through a shim, or pushing `diffusers` models through a new abstraction, would trade a working path for a uniform one. A worker missing a backend's package refuses enrolment for that entry rather than accepting the job and failing at claim time.
- **Priced on what it produces.** A 3D job is quoted on the voxel grid, not the conditioning image: `width`/`height` describe the _input photo_, so pricing on them would charge for the input and ignore the asset — two jobs from one photo at 512³ and 1536³ would cost the same while differing 27× in work. Charged on the grid face (`r²`), since generation cost tracks the sparse occupied surface rather than the empty interior, and against the same `per_pixel_step` rate so both settle through one path.

`tenzro model serve` and every pixel pipeline are untouched by any of this.

### Node capability surface

Two facilities cover the gap between what a node can do and what a caller can find.

- **Universal RPC gateway.** The node serves roughly 900 JSON-RPC methods and gains more each release, so any hand-maintained client list is perpetually behind — and the developer discovers the gap exactly when they need the method. `tenzro_listRpcMethods` returns the directory from the node itself, each entry carrying its gate class (admin token vs open) and the API-key scope it needs, so a caller can distinguish "I need a differently-scoped key" from "I need the operator's token" without provoking the error first; filter by namespace or substring, since unfiltered it is ~900 rows. Anything found can then be invoked by name. Authorization is unchanged: a gateway call passes the same admin-token gate, API-key scope gate, and default-deny classification as a direct request, reaching exactly what the presented credentials already allow. Exposed on the CLI (`tenzro rpc {methods, call}`), both SDKs, MCP, and A2A.
- **Model visibility — three tiers.** Who may call a model is a property of the model. `network` (the default) announces it on `tenzro/models` and makes it reachable by **any caller who pays** — no service key and no prior relationship, even on a node whose service-key gate is on. `gated` serves it to callers holding an API key whose policy the operator pre-agreed, and deliberately does _not_ announce it: the counterparties already know it is there, and gossiping it would advertise capacity to callers who cannot use it. `private` never leaves the box. CLI `tenzro model serve [--gated | --private]`. The published-model carve-out is narrow — an inference-method allowlist against a model currently served at `network`; a gated, private, or unknown model, or any other method, still needs the key.
- **Capability visibility.** What a node advertises is separable from what it can do. An operator can stop announcing individual capabilities — `ai`, `storage`, `database`, `hosting`, `rpc`, `tee`, `compute` — without unloading or disabling them, and resume later. Consensus is deliberately not hideable: a validator its peers cannot reach cannot vote. CLI `tenzro visibility {show, hide, publish}`.

### Multi-modal inference

The catalog spans seven ONNX runtimes plus the llama.cpp language path, all dispatched by the modality-aware `InferenceRouter::route()` against typed `InferencePayload` (Chat / Forecast / VisionEmbed / VisionSimilarity / TextEmbed / Segment / Detect / Transcribe / VideoEmbed). License tiers — Permissive (Apache/MIT/BSD), Attribution (CC-BY-4.0), CommercialCustom (DINOv3, SAM, Gemma — require `--accept-license`), NonCommercial (refuse without `--accept-non-commercial`) — gate registration. Forecast (TimesFM 2.5), Vision embedding (CLIP, SigLIP2, DINOv3, DINOv2), Text embedding (Qwen3-Embedding, EmbeddingGemma Matryoshka, BGE-M3, Snowflake Arctic), Segmentation (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM), Detection (RF-DETR, D-FINE), Audio ASR (Moonshine v2, Distil-Whisper, Whisper v3 turbo, Parakeet-TDT, Canary-1B-Flash), Video (vision-fallback encoder over uniformly-sampled frames). Each modality is exposed through JSON-RPC, MCP, A2A, and a CLI subcommand. All ONNX runtimes share one session builder that registers hardware execution providers before falling back to CPU — the `onnx-tensorrt` / `onnx-cuda` / `onnx-coreml` cargo features compile in the corresponding providers (default priority TensorRT → CUDA → CoreML), the `TENZRO_ONNX_EP` environment variable overrides the priority, and a failed provider registration falls through rather than erroring. Container image variants package the LLM-accelerated binary against a matching runtime: `Dockerfile.cuda` (NVIDIA CUDA — multi-arch, covering x86_64 and arm64 hosts such as Grace-Blackwell), `Dockerfile.rocm` (AMD ROCm), and `Dockerfile.vulkan` (cross-vendor Vulkan). The ONNX GPU execution providers ship only in the x86_64 CUDA image; on arm64 CUDA and under the ROCm and Vulkan images the ONNX modalities fall back to CPU while the llama.cpp language path stays GPU-accelerated. See `docs/AI.md` §2.7 for the full backend/image matrix.

### Identity (TDIP) — four classes

- `did:tenzro:human:{uuid}` — KYC tier, controlled machines, controller of any number of delegated agents.
- `did:tenzro:machine:{controller}:{uuid}` — delegated agent acting on behalf of a human, institution, or upstream machine. Carries a delegation scope (per-tx cap, daily cap, allowed operations / chains / payment protocols / counterparties, time bound).
- `did:tenzro:machine:{uuid}` — autonomous agent. Same wallet and A2A surface, no controller. Marks `is_seed_agent` for protocol-funded bootstrap agents.
- `did:tenzro:institution:{lei}:{uuid}` — legal entity anchored to its 20-character GLEIF Legal Entity Identifier (ISO 17442) with ISO 7064 Mod 97-10 check-digit validation at registration. Optional vLEI ACDC credential id binding, ISO 3166-1 alpha-2 country code, KYB tier. One legal entity can hold multiple institution identities (one per desk / fund / subsidiary) without re-issuing LEIs.

W3C DID Documents. W3C Verifiable Credentials with recursive trust-chain verification (cycle detection, depth bound, anchored to configured trust roots). KYC/KYB tier upgrades via credential. Cascading revocation. **Universal Resolver** at `/1.0/identifiers/{did}` (DIF spec) for any standards-compliant client. **KERI** Key Event Log for long-lived autonomous machine identities (inception, rotation, interaction events with pre-rotation commitments; SAID prefix `S` for SHA-256). **Sign-In With Tenzro** (SIWT) — EIP-4361-shaped message for off-chain service authentication.

### Payments

**Crypto rails — settle on-chain in TNZO or stablecoins:**

- **AP2** (Agent Payments Protocol): Google/FIDO protocol for verifiable agent payments using intent/cart/payment VDCs; mandate-pair validation via `tenzro_validateMandatePair`
- **MPP** (Machine Payments Protocol): Session-based streaming payments, co-authored by Stripe and Tempo
- **x402** (Coinbase): Stateless HTTP 402 payments with EIP-3009 authorization. The default facilitator is self-hosted — the operator runs the scheme's admission checks and settles through its own EVM signer rather than routing the signed authorization to a remote facilitator
- **Tempo**: Direct stablecoin settlement with EIP-155 transaction signing
- **App registry + developer-signed settlement**: a developer registers an app under their own DID and settles authorized charges against a payment-provider account they alone control. The developer signs each settlement authorization; the node routes the charge and records the outcome but never holds the payment-provider secret. RPCs `tenzro_registerApp` / `setAppStatus` / `getApp` / `listApps` / `settleAuthorized` / `getSettleAuthorizedOutcome`; SDK `AppClient` (Rust + TypeScript); CLI `tenzro app`
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

### Cross-Chain Bridge (16 production adapters)

- **LayerZero V2**: EndpointV2 messaging, OFT with shared decimals
- **Stargate V2 Hydra**: native USDC / USDT / WETH OFT bridging (separate adapter; LayerZero V2 underneath)
- **Chainlink CCIP**: Router-based cross-chain messaging with token pools
- **Chainlink CCT**: Cross-Chain Token v1.6+ self-serve pool registry (LockRelease + BurnMint)
- **Wormhole**: 19-guardian VAA attestation, 30+ chains incl. Solana/Aptos/Sui
- **Wormhole NTT**: Native Token Transfers with NttManager registry + multi-transceiver chain catalog (Wormhole / Axelar / LayerZero / custom)
- **deBridge DLN**: Intent-based cross-chain swaps (official MCP proxy)
- **LI.FI**: 66-chain aggregation with route optimization
- **Hyperlane V3**: messaging with sovereign Tenzro-validator-set ISM (`list_chains`, `quote_dispatch`, `dispatch`)
- **Axelar GMP**: Cosmos / Move / Stellar / XRPL reach
- **Babylon**: Bitcoin staking finality-providers + EOTS delegations
- **IBC-Eureka**: Tendermint light client compressed into SP1 plonk proofs for every Cosmos SDK chain. On-EVM `IBC_VERIFY` precompile at `0x1020` is an O(1) lookup against the off-EVM commitment registry.
- **BitVM2 / Clementine**: trust-minimised Bitcoin two-way peg with optimistic challenge protocol. Peg-in / peg-out lifecycle tracked on-chain; default 7-day settlement window.
- **Hyperbridge ISMP**: HTTP-shaped POST/GET messaging into Polkadot. Mint-control + per-asset rolling-window liquidity ceilings enforced at the message-ingest path.
- **NEAR Chain Signatures**: NEAR MPC produces secp256k1 / Ed25519 signatures for Bitcoin, Ethereum, Solana, TON, Stellar, Sui, Aptos, Dogecoin from a Tenzro account.
- **Canton**: Enterprise DAML interoperability

A unified `BridgeRouter` consults live fee quoting and returns a ranked set of routes by cost, speed, or reliability. Every adapter is fail-closed on inbound message verification (Guardian quorum for Wormhole, threshold validator set for Hyperlane + Axelar, ISMP proof for Hyperbridge, BitVM2 challenge protocol for Clementine). Per-adapter nonce trackers persist so replays are dropped across restarts. A **global supply accounting registry** at precompile `0x1021` is the single integrity log for Tenzro-issued tokens that move across rails — enforces monotone per-(asset, rail) sequence (replay guard), `Σ mints − Σ burns ≤ max_supply`, and no underflow on burn.

### Bridge Fee in TNZO + Chainlink-backed Fee Oracle

- **Single-token UX**: users pay one TNZO-denominated fee on the source chain; the destination-native fee is fronted by a per-adapter sponsorship pool.
- **Two oracle backings**: `GovernanceSetFeeOracle` (manual rate table, admin-token-gated via `tenzro_setBridgeFeeRate`) and `ChainlinkFeedFeeOracle` (live `eth_call` against `AggregatorV3Interface.latestRoundData()` with 30s in-memory cache + staleness + invalid-answer rejection).
- **Per-adapter sponsorship pools**: 8 deterministic vault addresses (SHA-256 over `"tenzro/bridge/sponsorship-vault" || adapter`, first 20 bytes), enumerable via `tenzro_listBridgeSponsorshipPools`.
- **ERC-7683 envelope unification**: `TenzroOrderData.bridge_fee_hint` lets a single user-signed order be filled by any bridge in the registered adapter set — solver picks the adapter, the TNZO ceiling bounds the destination-native commitment.
- **Operator-gated upstream cost**: the Ethereum mainnet RPC quota for Chainlink reads is operator-paid; methods are gated by API key with `chainlink` scope (same model as Canton). Per-tenant Compute Unit attribution in `CF_BRIDGE_ANALYTICS`. GCRA rate limiter (10 req/sec sustained, burst 100) with `-32005` retry envelope.

### Tokenization & Compliance

- **ERC-7943 (uRWA)**: real-world-asset compliance surface — token kill-switch (`tenzro_urwaTriggerKillSwitch`), freeze-tokens (`tenzro_urwaSetFrozenTokens`), forced-transfer (admin-token-gated).
- **IVMS101 v1.1.0**: FATF Travel Rule canonical envelope binding for KYC payloads on cross-border transfers.
- **Secure-Mint**: per-token 1:1 reserve-attestation invariant for tokenized RWAs.
- **TEE-attested timestamps**: saga step deadlines and obligation expiries carry a TEE-attested `wall_ms + monotonic_ns + tee_vendor` envelope with 30s drift tolerance.

### Agent Interoperability

- **ERC-8004**: Trustless Agents Registry on Ethereum — mirror Tenzro machine DIDs to the `registerAgent`/`getAgent`/`submitFeedback`/`validationRequest`/`validationResponse` interface for cross-ecosystem agent reputation. CLI exposes both `tenzro erc8004` and the canonical EIP-8004 short-name alias `tenzro 8004`.
- **AP2**: Agent Payments Protocol with intent/cart/payment VDC mandates, session lifecycle, and mandate-pair validation
- **AAP** (Agent Access Protocol): OAuth 2.1 + DPoP + RAR layering for agent-issued bearer tokens. The CLI exposes both `tenzro auth` and the alias `tenzro aap` — both names hit the same `tenzro_*Token*` and wallet-link RPCs.

### Multi-Party Workflows (VM-agnostic; Canton mirror optional)

The workflow runtime is its own state machine. It runs alongside (not inside) the VMs and carries its own typed lifecycle, per-step `execute / verify / compensate` handlers, on-chain receipts under privileged-VM transaction selectors, fee routes, kill switch, and privacy domains. **Canton mirroring is an optional projection** — a workflow can declare `canton_mirror: Some(...)` and the workflow dispatcher will write a `Tenzro.Workflow.Receipt` row through the co-located Canton participant for every step; a workflow with `canton_mirror: None` runs without Canton interaction. EVM contracts subscribe to workflow events through the standard event surface. SVM programs observe receipts through the unified token registry's event log.

- **Lifecycle**: typed state machine (`Draft → Active → AwaitingSignatures → Executing → Completed`, terminal `Cancelled / Disputed / Failed / Suspended`) with privileged-VM selectors `0x01000040`–`0x0100004B` for every state change.
- **Receipts**: every transition produces a `WorkflowReceipt` linked into a per-workflow hash chain, persisted under `wf_receipt:<id>` and (optionally) mirrored to a `Tenzro.Workflow.Receipt` Daml template through the co-located Canton participant.
- **Privacy domains**: named ACLs of TDIP DIDs gate AES-256-GCM-sealed payloads with auditor read-through and governance-driven freeze.
- **Fee routes**: basis-point recipient tables with `tenzro_computeFeeRoutePayouts` for read-only previews; actual settlement runs through the consensus-mediated escrow primitive.
- **Kill switch**: `KillSwitchSuspend` / `KillSwitchCancel` selectors give the initiator a defined emergency-stop path so an autonomous agent can never be trapped in a non-responsive multi-party flow it originated.
- **Surfaces**: read-only access via JSON-RPC (`tenzro_*`), MCP (port 3001), and A2A (`workflow` skill on the Tenzro Agent Card). Operational-metrics snapshot at `/metrics` with bundled Grafana dashboard (UID `tenzro-workflow`).
- **Reference templates**: 5 live under `crates/tenzro-workflow/reference_workflows/` (autonomous procurement, autonomous treasury, DvP settlement, environmental MRV, supply-chain DPP), each paired with a `*`*_daml_map.json` describing the optional Canton DAML projection.

### Compliance & Disclosure (EU AI Act Article 50)

- **§50(1)** chatbot disclosure: every CLI / MCP / A2A AI text response is prefixed with `[AI]`. Single source of truth in `tenzro_node::eu_ai_disclosure`.
- **§50(2)** synthetic-content marker: every inference output carries a C2PA-style `ContentProvenanceManifest` keyed by SHA-256 content hash. Validators sign manifests with their Ed25519 block-signing key. RPC `tenzro_getContentProvenance` and CLI `tenzro provenance get <content_hash>` resolve the cached manifest.
- **§50(4)** deepfake assertion tag: outputs imitating real subjects use the `deepfake` assertion in place of `ai-generated`.
- **Approval flow**: out-of-scope agent operations are parked for controller review. Inspect via `tenzro approval list/get` and decide via `tenzro approval decide`.
- **Channel disputes**: durable lifecycle records readable via `tenzro dispute status` and `tenzro dispute list-by-channel`.
- **Provider reputation**: `tenzro reputation get <provider>` reads the durable score (0–1000, +1 success / −5 failure) used by the inference router.

## Where a node keeps things

Everything Tenzro writes on a machine lives under one root: `$TENZRO_HOME`, or
`~/.tenzro` when unset. Model weights, the HuggingFace cache and dataset shards
are shared across every Tenzro process on the box — content-addressed and
read-only once written, so two nodes never hold separate copies of the same
weights. Chain state is per-instance under `instances/<name>/`, because RocksDB
cannot be shared: the second process to open the same directory fails on its
lock file.

```
$TENZRO_HOME
├── models/          shared — GGUF weights, ONNX bundles
├── hf/              shared — HuggingFace cache (exported to child processes)
├── trainer-cache/   shared — dataset shards, keyed by digest
└── instances/
    └── default/     RocksDB, keys, wallets, snapshots, iroh blobs
```

`--data-dir` still overrides the per-instance directory and `models_dir`
overrides the shared store, for operators who keep large data on separate
volumes. The container images set `TENZRO_HOME=/data/tenzro` so the model store
sits on the mounted volume rather than the ephemeral layer.

## Authorization model

Three layers, each answering a different question:

- **Admission** (`admission.rs`) — an optional operator-set service key gates
  the service surfaces. It has no consensus or gossip variant, so a gated node
  structurally cannot stop validating. A service key is a **rental credential**
  for this machine's raw resources — a confined shell, storage, memory, compute
  — carrying a `ServiceKeyGrant` with the surfaces it admits on and the term it
  expires at, bound to the `AccessLease` it was minted for. It is not a
  statement about what the node serves: **model serving answers to the model's
  own visibility, not to this gate.** A model published at `network` visibility
  is reachable by payment alone, on a gated node, because a peer that found the
  offer over gossip has no way to obtain a key. See
  [`docs/ACCESS.md`](docs/ACCESS.md).
- **Classification** (`rpc_gates.rs`) — every dispatched method is named in
  exactly one of `ADMIN_METHODS` (109) or `OPEN_METHODS` (823); a method in
  neither is refused before its handler runs. Tests read the dispatcher's own
  source, so adding an RPC without deciding its gate is a build failure rather
  than an audit finding.
- **Ownership** — methods acting on a tenant's resource require a signed DID
  envelope from that resource's owner, bound to the method name and to the
  call's parameters. The operator's admin token authenticates whoever runs the
  machine; it is the wrong gate for something belonging to somebody _using_ it,
  because accepting it would let a shared node's host mutate their tenants'
  resources.

`submitBlock`, `offerSnapshot` and `applySnapshotChunk` are not on the JSON-RPC
surface. They were peer traffic reachable over the user-facing port —
`submitBlock` pushed a caller-supplied block onto the finalized path, which by
contract has already been through consensus and therefore verifies nothing.
Blocks arrive over peer-authenticated gossip and block-sync; the inbound half of
state-sync is driven in-process. The read half (`listSnapshots`,
`getSnapshotManifest`, `getSnapshotChunk`) is what a syncing node calls on a
serving one and is unchanged.

## Ecosystem

| Component                      | Repository                                                                      | Description                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **MCP Server** (Python)        | [tenzro/tenzro-mcp-server](https://github.com/tenzro/tenzro-mcp-server)         | 360 tools, FastMCP 3.x                                                      |
| **A2A Server** (Python)        | [tenzro/tenzro-a2a-server](https://github.com/tenzro/tenzro-a2a-server)         | 75 skills, FastAPI                                                          |
| **TenzroClaw** (Python)        | [tenzro/TenzroClaw](https://github.com/tenzro/TenzroClaw)                       | 685 commands, OpenClaw skill                                                |
| **Rust SDK**                   | [tenzro/tenzro-sdk-rust](https://github.com/tenzro/tenzro-sdk-rust)             | 85 modules                                                                  |
| **TypeScript SDK**             | [tenzro/tenzro-sdk-typescript](https://github.com/tenzro/tenzro-sdk-typescript) | 92 modules                                                                  |
| **Browser-extension provider** | [`sdk/tenzro-inject`](sdk/tenzro-inject/README.md)                              | `window.tenzro` for dApps — EIP-1193 / EIP-6963 / Wallet Standard / CAIP-25 |
| **Homebrew**                   | [tenzro/homebrew-tap](https://github.com/tenzro/homebrew-tap)                   | `brew install tenzro`                                                       |
| **Cookbook**                   | [tenzro/tenzro-cookbook](https://github.com/tenzro/tenzro-cookbook)             | 34 runnable examples                                                        |
| **Desktop App**                | [tenzro/tenzro-desktop](https://github.com/tenzro/tenzro-desktop)               | Tauri + React                                                               |

## Live Testnet

| Service       | URL                                  |
| ------------- | ------------------------------------ |
| JSON-RPC      | https://rpc.tenzro.xyz               |
| Web API       | https://api.tenzro.xyz               |
| MCP Server    | https://mcp.tenzro.xyz/mcp           |
| A2A Server    | https://a2a.tenzro.xyz               |
| Faucet        | https://api.tenzro.xyz/faucet        |
| Solana MCP    | https://solana-mcp.tenzro.xyz/mcp    |
| Ethereum MCP  | https://ethereum-mcp.tenzro.xyz/mcp  |
| Canton MCP    | https://canton-mcp.tenzro.xyz/mcp    |
| LayerZero MCP | https://layerzero-mcp.tenzro.xyz/mcp |
| Chainlink MCP | https://chainlink-mcp.tenzro.xyz/mcp |
| LI.FI MCP     | https://lifi-mcp.tenzro.xyz/mcp      |
| Documentation | https://tenzro.com/docs              |

**Infrastructure**: The public endpoints on `tenzro.xyz` are operated by Tenzro Labs, the first reference RPC provider on the network. The RPC provider role is open — any operator that meets the validator bond can register their own endpoint and serve the same protocol surface. TLS at the edge is PQ-hybrid X25519MLKEM768. The repository is the reference implementation — anyone can run a node and join.

**Genesis**: 1,000,000,000 TNZO total supply. Faucet: 1,000 TNZO per request, 24h cooldown.

## Development

```bash
# Build all crates
cargo build

# Run all tests
cargo test --workspace

# Run clippy
cargo clippy --workspace

# Run node locally
cargo run --bin tenzro-node -- --roles validator --data-dir ./data

# Run CLI
cargo run --bin tenzro -- --help
```

### Requirements

- Rust 1.85+ (see `rust-toolchain.toml`)
- C/C++ compiler (for RocksDB, libp2p)
- `cmake` (for `llama-cpp-sys-2`)
- `protoc` — Protocol Buffers compiler ≥ 3.12 (required by `lance-encoding`, pulled in transitively via the agent-memory vector tier)
- `pkg-config`, `libssl-dev` (Linux)

Install `protoc`:

```bash
# macOS
brew install protobuf

# Debian / Ubuntu
sudo apt-get install -y protobuf-compiler

# Fedora / RHEL
sudo dnf install -y protobuf-compiler

# Arch
sudo pacman -S --needed protobuf

# Rust-only (no system package manager)
cargo install protoc-bin-vendored-cli
```

Verify with `protoc --version` (must print `libprotoc 3.12` or newer). See [`docs/GUIDE.md`](docs/GUIDE.md#2-toolchain-installation) for the full per-platform toolchain.

### Docker

```bash
# Build image
docker build -t tenzro-node .

# Run node
docker run -p 8545:8545 -p 8080:8080 -p 3001:3001 -p 3002:3002 \
  -v tenzro-data:/data/tenzro \
  tenzro-node --roles validator --data-dir /data/tenzro
```

### Deployment

The canonical deployment is Docker on a host with systemd. See [`deploy/validator-deployment.md`](deploy/validator-deployment.md) for the infrastructure-agnostic operator guide covering key management, networking, and upgrade procedures.

## Proto Definitions

13 proto3 files under `proto/tenzro/v1/` defining 120+ message types. These serve as API documentation — Rust types are implemented manually for flexibility.

## Documentation

| Document                                                           | Purpose                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md)                         | Tenzro Network whitepaper — vision, architecture, agent economy, settlement layer                                                                                                                                                                                                  |
| [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)                   | Protocol specification — architecture, consensus, multi-VM execution, identity, payments, settlement, agents, training, and the concrete Rust implementation                                                                                                                       |
| [`docs/ECONOMICS.md`](docs/ECONOMICS.md)                           | **Canonical**: who pays, who is paid, how much. Node economic modes, the revenue split, access tiers, settlement, provenance, machine identity                                                                                                                                                                       |
| [`docs/TOKENOMICS.md`](docs/TOKENOMICS.md)                         | TNZO token economics: supply, fee model, staking, rewards (testnet phase)                                                                                                                                                                                                          |
| [`docs/TDIP.md`](docs/TDIP.md)                                     | Tenzro Decentralized Identity Protocol — identity over W3C DID across human, delegated agent, autonomous agent and institution; machine anchors, device binding and hardware-bound passkeys, sessions, the wallet second-device rule, and machine ownership transfer |
| [`docs/AI.md`](docs/AI.md)                                         | Tenzro AI — decentralized inference (single-replica + sharded MoE + MTP + multi-modal), Cortex reasoning, confidential inference, Tenzro Train (data-parallel, decoupled outer synchronization) training, and Tenzro Media Gen (diffusion image and video, split-expert rendering) |
| [`docs/COMPUTE.md`](docs/COMPUTE.md)                               | Tenzro Compute — rentable compute capacity: per-epoch booking, availability-proof gate, streaming escrow, fixed or network-dynamic pricing, shared coverage with storage                                                                                                           |
| [`docs/STORAGE.md`](docs/STORAGE.md)                               | Tenzro Storage — decentralized content-addressed storage: byte-epoch billing, proof of retrievability, redundancy, and one stake shared with compute                                                                                                                               |
| [`docs/DATABASE.md`](docs/DATABASE.md)                             | Tenzro Database — managed-database protocol layer: engine catalog (PostgreSQL, Qdrant, Milvus, Valkey, Dgraph, Lance, Tantivy), placement across local / LAN-cluster / network tiers, access policy + confidential seal                                                            |
| [`docs/HOSTING.md`](docs/HOSTING.md)                               | Tenzro Hosting — static sites, functions, and machines on Tenzro nodes: content-addressed serving, `wasi:http` sandbox, Firecracker microVM, bid/lease placement, operator-configured edge with automatic TLS                                                                      |
| [`docs/ORCHESTRATION.md`](docs/ORCHESTRATION.md)                   | Intent orchestration — composing models, skills, tools, and agents behind an LLM planner with deterministic guardrails                                                                                                                                                             |
| [`docs/NETWORK.md`](docs/NETWORK.md)                               | Tenzro Network — decentralized networking: libp2p control plane (gossipsub topics, NAT traversal, validator-only topic authentication, request/response protocols) + iroh QUIC data plane (DA, model weights, gradients, sealed shards, agent memory, A2A + MCP ALPNs)             |
| [`docs/GUIDE.md`](docs/GUIDE.md)                                   | Operator and developer guide: build, run, deploy, troubleshoot                                                                                                                                                                                                                     |
| [`docs/did-method-tenzro.md`](docs/did-method-tenzro.md)           | `did:tenzro` DID method specification (W3C registration submission)                                                                                                                                                                                                                |
| [`deploy/validator-deployment.md`](deploy/validator-deployment.md) | Infrastructure-agnostic validator and node operator guide                                                                                                                                                                                                                          |
| [`docs/security/`](docs/security/)                                 | Security model, quantum-resistance plan, audit notes                                                                                                                                                                                                                               |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributions require sign-off under the Apache-2.0 license.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2024-2026 Tenzro Foundation.
