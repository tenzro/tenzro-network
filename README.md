# Tenzro Network

**Tenzro is an open network for the machine economy, built to grow itself.** Machines of every size, from small edge devices to the largest GPU servers, sell AI work through one identity model and one payment rail; agents and apps buy it. A small number of people run machines; most of the demand comes from agents and from people using AI through apps, who usually never see where the AI runs. Providers of compute, models, agents and apps are paid for the work they do, and users and agents get capable, affordable AI.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Website](https://img.shields.io/badge/Website-tenzro.com-green)](https://tenzro.com)
[![RPC](https://img.shields.io/badge/RPC-rpc.tenzro.com-blue)](https://rpc.tenzro.com)

## What is Tenzro?

The network has one job: to make a self-reinforcing loop turn. Demand from agents and apps pays providers; provider income draws more machines; more machines bring better prices, quality and availability; that draws more demand. Fees paid by real users carry the loop. Rewards only help it start: the rewards a settlement earns never exceed what it paid outside the trade.

**Every class of machine, one codebase.** A node is one `tenzro-node` source built in release variants, so each machine runs the variant it can serve and refuses roles it cannot ([docs/NODE.md](docs/NODE.md#node-tiers)):

| Tier | Machines | What it does |
|---|---|---|
| Edge (light build) | Small, embedded and edge devices: single-board computers (the Raspberry Pi is the reference device), Jetson-class modules, mini PCs, NAS boxes, gateways | Identity, payments, agents, RPC, storage and following the chain; forwards inference to providers on the network |
| Standard | CPU servers and workstations | Every role a CPU can serve, including models that fit it |
| GPU provider | Consumer GPUs to data-center accelerators | Inference, compute rental, confidential computing, sharded serving of models too large for one machine |
| Validator | Servers whose consensus key is held in a TPM 2.0 or Secure Enclave (in the machine, or in another machine's TPM through a key holder) that order blocks and sign checkpoints | Consensus, storage, relaying; bonded stake |

**Edge devices take part in the AI value chain.** Most AI is now used through model ladders: a cheap step routes, checks, filters or answers the easy cases, and a large model handles only what needs it. Tenzro is designed so that an edge device can be the cheap step: it hosts a deployable agent harness that orchestrates agents, small models and other nodes, and calls GPU providers for the hard part. One request then pays several parties from the caller's own budget: the author of the agent, the machine that orchestrated it, and the machine that ran the large model. Settlements carry the call chain (app, agent and tool) and pay each named party directly ([docs/AI.md](docs/AI.md#hybrid-jobs-edge-orchestration-and-model-ladders)). Because the design lets a device costing about a hundred dollars do paid work, more people can supply the network than where earning needs an expensive GPU.

**Where demand comes from.** Resellers and platforms that buy from providers and sell to developers with their own commission on top; consumer apps that buy AI for their own products; partners and their deployments; and developers calling the network directly. Every channel meets the same fees and rules; none has a protocol privilege. Users pay with what they already use: apps and platforms handle payment, and the network is reached through an OpenAI-compatible endpoint like any other model API.

**Built against farming and speculation.** Rewards follow paid, verified work only. Nothing is paid for holding tokens, for volume, for sign-ups or for engagement; there are no airdrops or points. A payer and a payee that share an identity root earn nothing from paying each other, and any group of parties acting together ends every settlement poorer than it started ([docs/TOKENOMICS.md](docs/TOKENOMICS.md#reward-calculation)).

**Decentralized step by step.** The network starts bootstrapped by its first operators and opens in phases: a preview, then a testnet, then the stages governance decides on the way to mainnet. Each step starts on measured evidence and an on-chain governance decision, never on a date. During the preview a new validator joins only once an enacted governance proposal has approved it (`validator.admission_approval`).

**TNZO keeps the network running.** It is the unit that prices and settles work on chain, that operators stake and are slashed in, and that pays the network's upkeep. It is not something a user has to hold: fees are set in USD terms and apps and platforms pay on their users' behalf.

**What the protocol provides underneath:**

- **Multi-role nodes**: one node, one stake, many roles. A node can serve AI models, rent out spare compute, and hold data at the same time — a single stake covers every role it takes on. Compute rental is availability-proof-gated and billed per epoch; storage is proof-of-retrievability-gated and billed per byte-epoch. In every case the consumer pays from their TNZO balance and the provider earns into theirs.
- **Decentralized AI + compute orchestration**: agents and humans discover and access AI inference (chat, vision, audio, forecasting, embeddings, segmentation, detection), rentable compute capacity, and TEE-backed confidential compute (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) through a single protocol-level marketplace with per-use billing, reputation scoring, and on-chain verifiability. Providers are sovereign — anyone can run a model, expose an endpoint, or contribute compute, and earn TNZO directly. The inference router (price / latency / reputation / weighted strategies) and the agent-spawning + swarm-orchestration primitives let agents compose multi-model, multi-provider workflows without trusting any one party.
- **Universal identity (TDIP)**: one DID for humans, delegated agents, and autonomous agents that works on EVM (via ERC-8004 mirror), SVM, AP2 mandates, x402 micropayments, and OAuth/DPoP — same identity, same delegation scope, same revocation surface.
- **Universal wallet (hardware key + ML-DSA-65 hybrid PQ)**: keys held only in passkeys, TPMs or Secure Enclaves, k-of-n hardware approval available, and one balance shared across VM views — wTNZO ERC-20 on EVM and an SPL adapter on SVM. No bridge risk, no liquidity fragmentation. Pointer-model native asset.
- **Universal settlement (TNZO)**: bridge fees, inference fees, escrow and escrow-backed payment channels, training-run grants, and cross-chain destination-native fees (via the Chainlink-backed bridge fee oracle) all denominated and accounted in TNZO.
- **One bridge path**: TNZO moves to other chains only over governed routes (a CCIP-compatible envelope for Ethereum, Base, Arbitrum and Solana; IBC for Cosmos chains; a deposit route for Bitcoin; bridge contracts on Sui, Aptos, Stellar and TON), all under one set of rules: committee attestations bound to chain, route, nonce and expiry; a circuit breaker; per-transfer and per-epoch caps; and an on-chain supply invariant. See [docs/BRIDGE.md](docs/BRIDGE.md).
- **Multi-VM execution**: EVM (revm + 9 standard precompiles + 7 BLS12-381 EIP-2537 + 13 Tenzro precompiles) + SVM (solana-svm with SPL Token Program dispatch) + the native runtime — every contract and every instruction runs against the same identity, same wallet, same TNZO balance.
- **AI inference and generation as protocol-level economic activity**: providers earn TNZO for serving models (chat, vision, audio, forecasting, embeddings, segmentation, detection), rendering diffusion image and video jobs (generative media), and running TEE enclaves. Inference results, settlements, and identity claims are verifiable on-chain via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness) or attested by hardware enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) — both anchored via `ZK_VERIFY` and `TEE_VERIFY` precompiles.
- **Humans as peer identity class**: HITL escalation, guardian-quorum recovery, AP2 cart/intent/payment mandates, and delegation scopes are wire primitives, not adapter-layer features.

Tenzro Network is also the reference implementation of the [Open Agent Network (OAN)](https://github.com/tenzro/open-agent-network) — the draft standards family (TNIP-001..022, pre-publication) for a hybrid human + agent coexisting network. OAN provides the governance framework; Tenzro Network is the working implementation. The wire stays open for other implementations.

## What runs on it

Four surfaces share the same identity, payment, and settlement substrate:

- **Tokenized AI inference.** Anyone can run AI models (chat, vision, audio, forecasting, embeddings, segmentation, detection) and offer them on the marketplace. Users and agents pay per token (or per inference); providers earn TNZO directly. Confidential variants run inside TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC). Micropayment channels make high-frequency, low-value billing efficient.
- **Generative media as a serving modality.** Image, video and audio renders run on a node's native engine, metered in pixel-steps (`width × height × steps × frames`) against its rate card and answered with a signed receipt over what was produced, so any provider holding the same weights can re-render and a disagreement is an inference fault.
- **Agentic finance.** Autonomous agents discover providers, negotiate, pay, and settle in TNZO using the same TDIP identity, hardware-rooted wallet, and delegation scope. AP2 mandates, x402 micropayments, ERC-8004 trustless-agent registries (mirrored across EVM and SVM from a single TDIP write), and ERC-4337 v0.8 smart accounts all run inside Tenzro consensus.

Verifiability is not optional. Inference results, settlements, and identity claims can be proven via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness) or attested by hardware enclaves — both anchored on-chain via the `ZK_VERIFY` and `TEE_VERIFY` precompiles. Tenzro unifies inference, compute rental, storage, training, agent settlement, identity, verification, and cross-chain reach under one open execution layer — not raw GPU rental and not subnet coordination, but the full surface where AI runs.

## The Combination

Individually, the pieces exist elsewhere. What Tenzro composes into one network is the combination: verifiable AI inference and training, confidential compute, multi-modal serving, and agent settlement, all under one identity, one settlement asset, and one consensus layer.

Tenzro combines **EVM + SVM** and its native runtime in a single network, with governed bridge routes to Ethereum, Solana, Bitcoin, Cosmos (IBC), Move chains, Stellar and TON. That breadth is the substrate; the execution layer for AI is what rides on top of it.

On that substrate, **agent rails** (AP2 mandates, x402 micropayments, ERC-8004 trustless agents, ERC-4337 v0.8 smart accounts) and **asset rails** (reserve-backed tokens, ERC-3643 compliance, cross-chain settlement) share one identity (TDIP), one settlement asset (TNZO), and one consensus layer.

Two more architectural calls worth flagging:

- **Confidential agent compute is a consensus primitive, not a sidecar.** The `TEE_VERIFY` precompile verifies real Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU CC quotes on-chain — attested execution is built into the chain, not bolted on as middleware. Attestation is a reputation signal only: nothing self-reported enters the leader schedule. Tenzro consensus is a signature-free DAG protocol over post-quantum authenticated channels (iroh ALPN `tenzro/consensus`), with no-vote certificates for tail-fork resistance and checkpoint certificates signed every 500 ms by hardware-held composite ML-DSA-65 + P-256 keys; the RPC reports `ordered` and `certified` finality, and bridges act on `certified`.

- **Agent work leaves evidence anyone can check.** Every tool call an agent makes through a node's MCP or A2A endpoint is a record the node signs with its hardware-certified session key and commits on chain each epoch. Evidence packs export with an EU AI Act profile (Art. 12 record-keeping, Art. 14 oversight) and verify offline from the genesis anchor alone (`tenzro agent audit evidence verify`). Trained models carry a provenance receipt over their on-chain training rounds (`tenzro provenance model`), and private weights are released only to environments whose TPM, TDX or SEV-SNP and NVIDIA GPU evidence meets the model owner's policy, each release recorded on chain. See [docs/AGENT_TRUST.md](docs/AGENT_TRUST.md) and [docs/AI.md](docs/AI.md#5-confidential-inference).
- **TNZO is a pointer-model native asset.** One balance, two VM views (wTNZO ERC-20 on EVM, SPL adapter on SVM) — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f`), and W3C DID (`did:tenzro`).

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
                    |   RPC (469) + MCP (429) + A2A         |
                    +--------------+----------------------+
                                   |
        +----------+---------------+---------------+----------+
        |          |               |               |          |
   +----v---+ +---v----+ +-------v--------+ +---v---+ +---v----+
   |Network | |Consensus| |  Multi-VM      | |Storage| | Model  |
   | (iroh) | |DAG + PQ | |   EVM+SVM     | |RocksDB| |Registry|
   +--------+ +--------+ +----------------+ +-------+ +--------+
        |          |               |               |          |
   +----v----+----v----+----------v-----+---------v-+--------v---+
   |  Crypto  |  TEE   |   ZK Proofs   | Identity  | Payments   |
   | Ed25519  | TDX    |  Plonky3 STARK| TDIP/DID  | MPP/x402   |
   | Secp256k1| SEV-SNP|  KoalaBear/FRI| W3C VC    | Tempo      |
   | ML-DSA-65| Nitro  |  Poseidon2    | KYC Tiers | Stripe/CB  |
   | AES-GCM  | GPU CC |  No setup, PQ | Delegation| EIP-155    |
   +----------+--------+---------------+-----------+------------+
```

## Workspace

| Crate                       | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **tenzro-types**            | Core types, constants, primitives (zero internal deps)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-crypto**           | Ed25519, Secp256k1, ML-DSA-65, ML-KEM-768, AES-256-GCM, X25519, P-256 / WebAuthn, VRF (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **tenzro-tee**              | TEE abstraction: Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber Trust Authority with X.509 cert chain verification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-zk**               | SHA3-256 preimage circuits (identity, settlement) proven in two independent Plonky3 systems (KoalaBear/SHA-256 and Goldilocks/BLAKE3, about 136 proven bits each), k-of-n acceptance, TEE-bound proofs, no trusted setup                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-network**          | Gossip messages, topics and validation, carried over iroh-gossip; peers are found through signed identity endpoint records and relays in `tenzro-iroh`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-iroh**             | iroh data plane (content-addressed transport): `IrohBackedResolver` over QUIC + iroh-blobs, DA backend, gradient store, sealed-shard store, A2A-over-iroh on the `tenzro/a2a` ALPN. Resolves `tenzro://{blob,gradient,shard,manifest,memory}/...`. TDIP-anchored Pkarr discovery (EndpointId byte-identical to TDIP key)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-storage**          | RocksDB with column families, unified binary state trie, snapshots, fsync durability                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| **tenzro-wallet**           | Hardware-rooted wallets (passkey / TPM / Secure Enclave signer + ML-DSA-65 hybrid PQ leg), keystore, transaction builder, nonce management, key zeroization                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-keystore-unlock**  | Platform-agnostic `KeystoreUnlocker` trait for reproducing the wallet keystore password across restarts from a hardware device key (Secure Enclave or TPM); no environment-variable or fixed-password implementation; no platform dependencies, so it sits in the public API of wallet/node without pulling in OS crates                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| **tenzro-device-key**       | Hardware-backed non-extractable P-256 device keys (TPM 2.0 on Linux, Secure Enclave on macOS/iOS): prehash signing, secret wrapping to the device, and Ed25519 / X25519 / ML-DSA-65 keys derived inside the hardware root on demand and wiped after use                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| **tenzro-auth**             | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests), and WebAuthn attestation verification — what a device actually proved about the hardware holding its key, checked against pinned vendor roots rather than a platform account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| **tenzro-consensus**        | Signature-free DAG ordering (reliable broadcast, leader commit on a quorum of references), stake apportioned into seats with a 10% per-validator weight cap, leader schedule weighted by seats × behavior and seeded from the committed prefix, 500 ms checkpoints signed by per-boot composite ML-DSA-65 + ECDSA-P256 session keys that hardware keys certify, compact STARK certificates and a per-epoch light client, PQ validator channels (X25519 + ML-KEM-768), epochs committing the next committee, checkpoint-equivocation evidence slashed on chain, recovery journal so a restarted validator resumes its epoch                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| **tenzro-vm**               | Multi-VM: EVM (revm) + SVM (Anza `solana-svm` `TransactionBatchProcessor`, behind the `svm-full` feature) + native runtime, Block-STM parallel execution, EIP-1559, ERC-4337 AA, ERC-7579 modular validators, **EIP-7702 Type-4 delegation registry**, **Permit2 SignatureTransfer + witness** (gasless flows), **reserve-backed token mints** (fresh attestations from bonded attestors, in consensus), standard EVM + EIP-2537 BLS12-381 + Tenzro precompiles (TEE_VERIFY, ZK_VERIFY, VRF_VERIFY at 0x1007)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-token**            | TNZO token economics: treasury, stake read models, governed policy, epoch rewards, vesting                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| **tenzro-identity**         | TDIP: unified human/machine identity, W3C DID documents, verifiable credentials, delegation scopes, GDPR Article 17 right-to-erasure (`tenzro_forgetIdentity`)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **tenzro-payments**         | Agentic payment protocols that settle on-chain: MPP (Stripe + Tempo) sessions, x402 HTTP 402 with node-signed offer verification and idempotent payment ids across the tenzro-hybrid, exact-eip3009, permit2, and erc7710 schemes, delivery-versus-payment, metering, receipt ledger and revenue split. HTTP 402 middleware, RFC 9421 HTTP message signatures. Card-network adapters run in harnesses over the public surface.                                                                                                                                                                                                                                                                                                                                             |
| **tenzro-model**            | Model registry, modality-aware inference routing (price/latency/reputation), content-addressed peer-first model distribution (BLAKE3-hashed weights, `tenzro://blob/<hash>` URIs, `HfArtifactDownloader` fetches from peers over iroh blobs and falls back to HuggingFace; every load checked against the catalog pins and the model's verified multi-origin manifest). Multi-gigabyte artifacts already on disk are published by reference (`publish_path` / `ImportMode::TryReference`) so a served model is not duplicated into the blob store. Durable catalog. Local inference via llama.cpp across every ggml backend (CUDA, ROCm, Metal, Vulkan, SYCL, OpenCL, WebGPU, MUSA, CANN, OpenVINO, zDNN, BLAS — one per build, CPU otherwise). Multi-modal ONNX runtimes: forecast (TimesFM 2.5), vision (CLIP, SigLIP2, DINOv3, DINOv2), text-embedding (Qwen3-Embedding, EmbeddingGemma, BGE-M3, Snowflake Arctic), segmentation (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM), detection (RF-DETR, D-FINE), audio ASR (Moonshine v2, Distil-Whisper, Whisper-v3-turbo, Parakeet-TDT, Canary-1B-Flash), video (encoder scaffold). License-tier gating: Permissive / Attribution / CommercialCustom / NonCommercial. |
| **tenzro-settlement**       | Escrow with payer-signed voucher claims (payment channels), hash-locked delivery-versus-payment claims, batch settlement, and streaming rental escrow: time-based capacity rental with renter deposit + per-epoch streaming release gated on signed availability proof; provider stake collateralizes one-epoch exposure across active rentals, make-whole-from-stake on miss                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-storage-provider** | Decentralized storage over the iroh content-addressed transport: provider daemon (accept / serve objects), nonce-bound proof-of-retrievability challenges, systematic Reed-Solomon erasure coding (replication as the k=1 case), per-byte streaming metering gated on a passing retrievability proof (`ServiceType::Storage`), capability-gated retrieval (`AccessPolicy` + optional confidential seal)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **tenzro-cluster**          | Engine-agnostic local-network cluster substrate shared by model, storage, and database serving: reachability tiers, probed link-cost graph, deterministic nearest-neighbour ordering, and HRW rendezvous placement — every function is a deterministic function of measured inputs, so members converge on the same plan without a coordinator round                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **tenzro-bridge**           | Bridge route framework (CCIP-compatible envelope for EVM + Solana), fee oracle, Chainlink feeds |
| **tenzro-events**           | The chain's event log (cursor-ordered, committed in block headers, provable against certified checkpoints), the node's live event bus                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| **tenzro-node**             | Full node binary: JSON-RPC, MCP, A2A, Web API                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| **tenzro-cli**              | CLI tool: command modules with interactive mode and full RPC coverage                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **tenzro-catalog** | The model catalog: signed, published model entries loaded at runtime, with each model's licence, engine, footprint and the hash of every file it downloads |
| **tenzro-trust** | Certifications, ratings, operator policies and model provenance: signed credentials with revocation, relying-party trust lists, accountable operator policies, content-addressed model manifests and ingest safety scanning |
| **tenzro-keygen** | A node's Ed25519, ML-DSA-65 and X25519 keys, derived on demand from its TPM or Secure Enclave |
| **tenzro-secure-enclave** | Apple Secure Enclave as a machine-identity root, the counterpart to TPM 2.0 |
| **tenzro-finality** | Checkpoint finality: the committee, session and certificate checks a light client runs |
| **tenzro-cert-stark** | Compact checkpoint certificates: one STARK for a quorum's ML-DSA-65 signatures |
| **tenzro-finality-prover** | Proves checkpoint finality as a quantum-safe STARK that light clients verify, with an optional Groth16 wrap for EVM chains |
| **tenzro-openshell** | OpenShell extensions backed by Tenzro: credentials minted under Terms, Terms-checked sandbox control, signed records, per-unit settlement, payments from the sandbox and host attestation |
| **tenzro-sim** | Deterministic network simulator: validators running the consensus core and the VM ledger under a simulated clock and network (not published) |
| **tenzro-econsim** | Economic simulation over the simulated ledger: populations, adversaries, sensitivity analysis and multi-year scenarios (not published) |
| **tenzro-settlement-fuzz** | Property-based fuzzing of settlement plan operations against the native executor (not published) |

## Quick Start

### Install

```bash
curl -fsSL https://downloads.tenzro.com/install.sh | sh     # Linux and macOS
irm https://downloads.tenzro.com/install.ps1 | iex          # Windows (PowerShell)
tenzro
```

The installer picks the build for the machine, verifies the release signature
and the archive's SHA-256 before it installs anything, needs no `sudo`, and puts
`tenzro` and `tenzro-node` in `~/.local/bin`. What it checks, what each first-run
screen looks like, and what to do on a machine without a TPM, a GPU or the
public network are in [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).
Verified on the 0.2.1 packages: the Windows MSI, the macOS package (arm64) and the Linux arm64 install script. Linux x86_64
and the `.deb` and `.rpm` packages have not been verified end to end. See
[docs/HARDWARE-COVERAGE.md](docs/HARDWARE-COVERAGE.md) for which platforms each
release archive is built and verified for.

### Verify a release yourself

Every release is a set of archives, a `SHA256SUMS` manifest and a signature
over it. Check both before you install by hand:

```bash
cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The key's fingerprint is `c88aaee70b3c0bf17a994bad44963a6a72359b2e1497df9a15a40ed099aeb72d`.
Full steps for Linux, macOS and Windows, and what the key does and does not
prove, are in [docs/VERIFY-DOWNLOAD.md](docs/VERIFY-DOWNLOAD.md).

### Build from Source

```bash
# Requires the Rust toolchain pinned in rust-toolchain.toml (rustup installs it)
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

# Join — provisions identity + hardware-rooted wallet + hardware profile
tenzro join --name "Your Name"

# Mint a DPoP-bound bearer JWT for authenticated RPC/MCP access
tenzro auth onboard-human --display-name "Your Name"

# Check balance
tenzro wallet balance

# Send tokens
tenzro wallet send <address> 10

# Interactive mode (run with no arguments in a terminal)
tenzro
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
# Bootstrap a self-contained network: validator keyset, schema-v1 genesis,
# service unit, and the exact join command for each peer
tenzro setup --path local --network-name lab

# Join an existing private network
tenzro setup --path private --genesis ./genesis.toml --bootstrap did:tenzro:machine:<id>
```

`tenzro setup --operator self` roots the machine in your passkey;
`--operator autonomous` roots it in the machine's own TPM 2.0 or, on Apple
hardware, its Secure Enclave. Either way the node's keys are derived inside
that hardware and never written to disk.

### Become a Validator

```bash
tenzro setup --mode validate
```

The wizard derives the validator keys inside the machine's TPM or Secure
Enclave, writes a service unit that starts the node with
`--validator-self-stake`, and prints the account that must hold the
self-stake (10,000 TNZO at genesis, governed as `stake.validator_tnzo`) plus
gas. Once that account is funded the node registers itself as a validator on
its next start, and the validator joins the active set at the next epoch
boundary. `tenzro validator get <account>` shows the registration.

The consensus key is held by hardware: the machine's own TPM 2.0 or Secure
Enclave, or the TPM of another machine the operator owns, reached through a
key holder (`--tpm-key-holder`, see [docs/NODE.md](docs/NODE.md#raspberry-pi-and-other-edge-devices)).
A passkey is never a consensus key; it authorises the operator.

Before it derives any key the wizard runs a preflight of the machine's
hardware root and prints each unmet prerequisite with the lines that fix it:
whether `/dev/tpmrm0` exists, whether this user may open it (the `tss`
group), whether the `tpm2-tools` the autonomous operator needs are installed,
and whether `tenzro-node` is on the machine. On Linux and Windows the TPM
keys are created once per machine by `tenzro-node tpm provision`; the wizard
offers to run it, and `--provision-tpm` runs it without asking. `tenzro join
--provider` prints the same checklist when its local node cannot be reached.

When the account does not hold the stake, the wizard says how much it needs
and offers three options in order: apply for a sponsorship grant
(`tenzro sponsor check`, `tenzro sponsor apply`), receive TNZO at the printed
account and run the same command again, or continue without a staked role
(`tenzro setup --mode consume`). `tenzro join --provider` shows the same screen
when the wallet is short of the compute bond. The need is recorded in
`~/.tenzro/config.json` and named by `tenzro sponsor status` until the account
holds it.

`tenzro setup --apply` goes the rest of the way: it installs the unit
(`sudo` on Linux for the systemd unit, a launch agent on macOS), starts the
node, and follows it until it has caught up with the network, printing
progress and, if the service fails, its log. Run interactively, the wizard asks
instead. `--apply` is not available for a new local network, whose genesis has
no founding validators until each one prints its entry.

`tenzro status --watch` is the live view afterwards: the node's state, chain
position, roles, validator registration, role bonds, sponsorship approval and
the one thing to do next, redrawn in place every two seconds (`--watch 5000`
for another interval, `--json` for line-delimited JSON).

Amounts on `tenzro stake` and `tenzro validator` commands are TNZO (`10000`
or `10000 TNZO`); wei needs its suffix (`250000000000000000wei`).

### Sponsorship

```bash
tenzro sponsor check     # does this machine and operator qualify, and what is missing
tenzro sponsor apply     # prepare the proposal a proposer files, and the grant you can file yourself
tenzro sponsor status    # approval record, what sponsorship has paid, proposals in flight
```

Sponsorship is paid by governance proposal ([docs/SPONSORSHIP-AND-GRANTS.md](docs/SPONSORSHIP-AND-GRANTS.md)).
`tenzro sponsor check` reads the node and reports each criterion the chain
enacts an approval on: a machine identity, a TPM endorsement that chains to a
recognized root, at least one verified-available hour, and the governed caps.

### Consensus, Keys and Access

- **Ordering.** Validators reliably broadcast one unsigned DAG vertex per
  round; a round leader commits once a quorum of the next round references
  it, and its causal history becomes one block. Batches are pushed to every
  validator before the vertices that introduce them.
- **Channels.** Validator links run over QUIC, upgraded by a handshake keyed
  by a hybrid X25519 + ML-KEM-768 exchange and signed by both sides' session
  keys; every frame carries a MAC.
- **Checkpoints.** About twice a second each validator signs a checkpoint
  over the blocks since the last one and the executed state. A quorum of
  signatures is a certificate anyone can verify against the epoch's
  committee (`tenzro_getCheckpointCertificate`, `tenzro_getCommittee`);
  signing two checkpoints with one index is slashable. A compact certificate
  replaces the quorum's ML-DSA-65 signatures with one STARK
  (`tenzro_getCompactCertificate`), and a light client follows these from
  genesis across epoch handovers (`tenzro_getEpochHandover`,
  `tenzro finality verify`).
- **Hardware-rooted keys and session keys.** A validator's identity key lives
  in its TPM 2.0 or Secure Enclave, in the machine or reached through a delegated key holder (never a passkey). Each boot and each epoch it
  certifies an in-memory session key (composite ML-DSA-65 + ECDSA-P256),
  which signs votes and handshakes; per-request artifacts such as inference
  receipts are signed by a session key that carries its certificate.
- **RPC access.** Every JSON-RPC method is classified as open (reads and a
  short list of permissionless writes), owner (the handler checks a proof
  from whoever owns what is changed: a signed DID envelope, an address
  signature, a passkey assertion or a scoped credential) or admin (the
  operator token). An unclassified method is refused before dispatch.

### Become a Provider

Bring your GPU, cluster, or data center and earn from network demand. With
a node running (`tenzro-node --roles ai`), one command handles everything:

```bash
tenzro join --provider
```

Hardware detection, wallet provisioning, the 1,000 TNZO
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
tenzro model serve gemma3-270m

# Start an interactive chat session
tenzro chat
```

## Protocol Servers

The node exposes 4 protocol servers, plus 6 ecosystem MCP servers:

### Core Servers

| Server       | Port | Protocol        | Endpoints                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------ | ---- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **JSON-RPC** | 8545 | HTTP            | Every served method (EVM-compatible + Tenzro extensions, incl. multi-modal AI: forecast, vision, text-embed, segmentation, detection, audio, video; generative media; MoE sharded serving; LAN clustering; managed databases; app hosting: sites, functions, machines, leases; CAIP discovery; EIP-7702 delegation; Permit2; Capital Intent; Workflow). The same listener also serves the OpenAI-compatible HTTP routes `/v1/chat/completions`, `/v1/responses`, and the HTTP 402-gated `/api/paid/chat/completions` |
| **Web API**  | 8080 | REST            | Verification (`/verify/*`), `/status`, `/health`, `/chat`, `/providers`, `/discovery/resources`, OAuth token/introspect/revoke, passkey wallet                                                                                                                                                                                                                                                                                                                                                                                       |
| **MCP**      | 3001 | Streamable HTTP | A tool for every served method (429 tools); revision 2026-07-28 only, opened with `server/discover`, no `initialize` and no session; OAuth 2.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| **A2A**      | 3002 | JSON-RPC + SSE  | Agent Card skills, task streaming                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

### Authentication (Tiered)

- **Public tools** (no auth): `get_node_status`, `list_models`, `get_balance`, `resolve_did`, etc.
- **Write tools** (auth required): `register_identity`, `transaction_signing_payload`, etc.; a transaction is signed on the holder's device and sent with `tenzro_sendRawTransaction`.
- **Auth method**: OAuth 2.1 + DPoP (RFC 9449) — bearer JWT minted via `tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` / `tenzro_onboardAutonomousAgent`. Each request carries `Authorization: DPoP <jwt>` plus a fresh `DPoP: <proof>` header (per-request JWS-compact, bound to the JWT's `cnf.jkt` thumbprint per RFC 7638). RAR scopes (RFC 9396) constrain the JWT to specific tools and amounts.
- **Node access**: one policy per node (`access.toml`) decides who may use each surface and method class; callers sign in with a passkey or hardware key for a DPoP-bound ES256 access token (`tenzro_accessChallenge`, `tenzro_issueAccessToken`). See [`docs/ACCESS.md`](docs/ACCESS.md).
- **Revocation**: `tenzro_revokeJwt` (single token by `jti`) or `tenzro_revokeIdentity` (a signed `RevokeIdentity` transaction; every node revokes the act-chain when it applies the block).
- **Config**: `TENZRO_MCP_AUTH=tiered` (default) | `false` (dev) | `full` (all tools require auth)

## Key Features

### Multi-VM Execution — two VMs and a native runtime, one state machine

A chain that picks one VM forces every workload to fit that VM. Tenzro runs the EVM, the SVM and its own native runtime and routes by transaction type. All share the same state, the same gas token (TNZO), the same TDIP identity, and the same consensus.

- **EVM — liquidity and composability.** The Ethereum surface targets the broadest pool of existing contracts and tooling. Tenzro embeds revm with every standard precompile (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, EC_ADD, EC_MUL, EC_PAIRING, BLAKE2F) per the canonical EIPs, plus all seven BLS12-381 precompiles (EIP-2537) for native consensus-grade signature aggregation. Block-STM gives parallel transaction execution with MVCC concurrency control and automatic sequential fallback under contention. EIP-1559 dynamic fee market burns the base fee. Native primitives extend the EVM with protocol-aware precompiles: `TEE_VERIFY` (hardware attestation with vendor certificate-chain validation), `ZK_VERIFY` (O(1) commitment lookup against the on-chain Plonky3 registry), `VRF_VERIFY` (RFC 9381 ECVRF), `IBC_VERIFY` (IBC-Eureka light-client lookup), the Tenzro precompile slate (`TNZO_BRIDGE`, `TOKEN_FACTORY`, `CROSS_VM_BRIDGE`, `STAKING`, `GOVERNANCE`, `NFT_FACTORY`, `MODEL_INFERENCE`, `SETTLEMENT`, **global supply accounting** at `0x1021`, **module registry** at `0x1022`), ERC-4337 v0.8 account abstraction, EIP-7702 Type-4 delegation, Permit2 SignatureTransfer with witness binding, and ERC-7579 modular validator modules (social recovery / session keys / spending limits / WebAuthn passkey / TEE-bound).
- **SVM — throughput and latency.** The Solana surface targets workloads that need sub-second finality and high throughput — DEX routing, agent-to-agent micropayments, real-time settlement on a path. Tenzro embeds Anza's `solana-svm` `TransactionBatchProcessor` (behind the `svm-full` cargo feature) so Solana SBF programs run unmodified; without that feature the SPL Token adapter, the cross-VM native program, and PDA derivation still work while the SBF path returns `VmError::SvmFullFeatureRequired`. The SPL Token program maps onto the native unified token registry — a swap on SVM settles in the same balance space as a transfer on EVM. There is no bridging between the two VMs.
- **Cross-VM token model — Sei V2 pointer.** TNZO has a single canonical native balance. The wTNZO ERC-20 pointer on the EVM side and the wTNZO SPL adapter on the SVM side share the same underlying balance — there is no bridge between them, no wrapped/unwrapped distinction, no liquidity fragmentation. From the application's perspective, a wallet has one TNZO balance regardless of which VM it last touched.
- **What this composes into.** An agent settling a delivery-versus-payment between a tokenized treasury and a stablecoin payment (EVM) executes the whole thing as one workflow through one identity. An agent paying for a Solana DEX swap and posting a receipt on Tenzro consensus does it with one TNZO balance. Cross-VM coordination is a workflow primitive, not application code.

### Decentralized AI infrastructure

The protocol layer treats AI compute as a coordinated resource, not a centralized service.

**Tenzro does not ship models of its own.** Every model named anywhere in this README — Qwen, DeepSeek, GLM, Kimi, Gemma, MiniMax, FLUX, Wan, LTX, SAM, CLIP, Whisper and the rest — is a third-party checkpoint the network _supports_, not a first-party or proprietary one. The serving path is model-agnostic: `load_model` takes a GGUF path, and llama.cpp derives the architecture from the file's own metadata, so the `ModelArchitecture` enum is informational (for display and filtering) rather than an allowlist. A model with no catalog entry serves on documented defaults.

**The model catalog is published data, not code.** Each model is a catalog entry — engine family, licence and licence tier, whether the weights are gated, and the SHA-256 of every file the model downloads, fixed to a commit of its origin — that a publisher signs with its own hardware key and publishes on the network. A node serves the entries signed by accounts bonded as catalog publishers with no upheld catalog fault; an operator may narrow that to the publishers its own catalog trust list names (`--catalog-trust-list <did>`). A newly published model is served without a rebuild or a restart, a file whose bytes do not match its entry's hash is refused, and two trusted publishers that describe one model differently get neither version served. See [docs/TRUST.md](docs/TRUST.md#model-catalog). The catalog buys you metadata and hash-pinned downloads, not permission.

**Per-model configuration is pluggable, not a single forced schema.** Models genuinely differ in what they need, and a lowest-common-denominator config would either fail the demanding ones or burden the simple ones. So a catalog entry is a set of optional, defaulted slots and a model declares only what actually applies to it: a multimodal projector (`mmproj`) only if it has one, a paired drafter and MTP kind only if it supports speculative decoding, a `MoeShape` only if it is sparse, a sampling `ServingProfile` where the defaults are wrong for that family, a `ReasoningPolicy` where the model has a thinking mode. Where a model's own chat template is broken upstream, `TemplateFix` names a vendored replacement — the catalog declares _which_ fix, the inference client supplies the file — rather than the runtime special-casing that model. Anything left unset falls back to a documented default, which is why an uncatalogued GGUF still serves. The same shape holds for generative media, where entries carry pixel-step pricing, split-expert boundaries and frame limits per pipeline; some models are served through authored configs pinned to a specific upstream version rather than a generic path.

**Being in the catalog is not a claim that a model has been verified end to end.** The registry is broader than what has been exercised on real hardware, and we do not imply otherwise. Testing is ongoing: when a model turns out to need something the generic path does not give it — a corrected chat template, different sampling defaults, a frame limit, a pinned upstream version — that becomes a new optional slot on the entry, added as needed to run _that_ model, and left unset for every model that does not need it. This is why the config surface is additive and per-model rather than a schema fixed up front: it grows in response to what real checkpoints actually turn out to require. If you hit a model that misbehaves, that is a gap to report, not a limit of the design.

**Gated models need no Hugging Face token.** Some strong open checkpoints are gated: their origin makes each user accept a licence before fetching them. Their catalog entries say so (`gated: true`) and name the licence. To use one, read the licence and accept it with `--accept-license <id>`. The node then fetches the weights from other nodes, by content hash, never from the origin, and keeps them only if they hash to the catalog's pins. Nodes pass gated weights only between themselves when both operators accepted the licence: each node's endpoint record, signed by its hardware key, lists the licences its operator accepted, and a provider refuses a request for licence-bound bytes from a node whose record does not list that licence. A node binds gated bytes to their licence in its blob store before they arrive, so it never serves them to anyone else. Without the acceptance, the fetch is refused before any byte moves, and the error names the flag.

- **Distributed Mixture-of-Experts serving.** MoE models (Qwen 3.5 122B-A10B / 397B-A17B, DeepSeek V3 / V4 Pro 1.6T-A49B / V4 Flash, GLM 5.1 / 5.2, Kimi K2 / K2.6 / K3 2.8T-A104B, MiniMax M3, Gemma 4 26B-A4B) serve in two modes. **Full-replica** when one provider's hardware fits the model. **Decentralized expert shards** when it doesn't — providers declare which experts they hold via `ProviderCapacity.moe_holdings`, and the dispatch planner aggregates per-token top-k routing decisions into per-holder batches dispatched directly over the holder's iroh QUIC endpoint. The shard view is a derived view over the existing provider registry — MoE providers are the same network providers that serve dense models. Replication is governance-tunable (default ≥ 2 holders per expert, up to 8 for popular experts). Typed pipeline roles: `Replica`, `Router`, `ExpertHolder`, `PrefillDecode`, `Prefill`, `Decode`. Execution runs in the node: `MoeExpertRuntime` hosts per-expert FFN weights (`ExpertFfn`) and gating networks (`GatingNetwork`) loaded from safetensors (local file or `tenzro://blob` URI over iroh-blobs); a forward pass gates locally, fans expert sub-batches out to holders over the `tenzro/moe` iroh ALPN (with HTTP fallback), and combines the weighted expert outputs. A holder can advertise more experts than fit in memory: the runtime keeps experts in a byte-bounded memory-tier LRU (budget auto-sized to 60% of `MemAvailable`, else 4 GiB) backed by a disk tier that spills raw safetensors and decodes them back on demand, and readahead promotes the disk-tier experts a forward is about to hit before the batch arrives. Residency (`Warm` memory / `Cold` disk) is read from the live tier state, so the shard map reflects what is actually loaded. The expert projection math (`Y = X·Wᵀ`) runs behind an `ExpertCompute` seam so the same forward path uses whatever hardware a holder has: a CPU `ndarray` path is always present (with a runtime-detected AVX-512-VNNI Q8_0 dot path on capable x86), while GPU backends compile only under cargo features (`moe-cuda` for cuBLAS grouped-GEMM on NVIDIA, `moe-wgpu` for a cross-vendor WGSL kernel; `moe-gpu` enables both) and never enter a default build — a holder advertises `moe_gpu` so the router biases expert placement toward GPU holders. Experts can be block-quantized to shrink both the stored blob and the bytes moved between holders — `Q8_0` (~1 byte/weight), `Q4_K` (~4.5 bpw), `Q6_K` (~6.6 bpw), with `ExpertQuantPlan::q4_k_m` (gate/up Q4_K, down Q6_K) as the balanced default, dequantized one row at a time. Cross-holder dispatch compresses activations to Q8_0 blocks when the hidden dim is a multiple of 32, redispatches to warm backup holders when one is slow or missing, and streams holder responses into a combiner that fails loudly if any expected contribution never lands. Planning RPCs: `tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`. Execution RPCs: `tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moePrepareExperts`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`. CLI: `tenzro moe {shard-map, plan-dispatch, replication-policy, catalog-shape, load-expert, load-gate, unload-expert, unload-gate, prepare-experts, status, forward}`.
- **Local discovery.** Cluster members find each other on their own LAN segment via mDNS, bound to their machine identities, and every node is reachable by its iroh endpoint directly or through the relays named in its signed endpoint record. Each node also exposes a hardware self-profile — runtime build commit, CPU architecture, OS, detected compute devices, and derived serving capacity / backend / capability key (`tenzro_nodeProfile`) — which feeds both single-box fit and cluster planning.
- **Multi-Token Prediction (MTP) speculative decoding.** The in-process runtime runs speculative decoding: the drafter proposes a block of candidate tokens, the target verifies them in one batched decode, and the accepted prefix advances the stream. Serving a model auto-loads its drafter — `tenzro_serveModel` reads the catalog `drafter_id`, loads it from disk or downloads it in the background, and reports the outcome in the serve response's `mtp` field. A model draws its candidates from one of two sources: a small **paired drafter** checkpoint, or a **native embedded MTP head** that self-drafts against the target's own hidden state (`drafter_id` unset, `mtp_kind: DraftMtp`) — no second checkpoint to fetch. Declared for DeepSeek V3 (native, ~80% accept rate, ~1.8× decode), DeepSeek V4 Pro / Flash, GLM 5.2, Gemma 4 (all sizes), Qwen 3.5 (0.8B/2B/4B/9B/27B/35B-A3B/122B-A10B/397B-A17B), Qwen 3.6 27B + 35B-A3B, and Qwen 3.8 27B (native embedded head). Providers advertise drafter co-load via `ProviderCapacity.mtp_enabled`; the inference router filters MTP-eligible requests to MTP-capable providers when `draft_n` is set.
- **Vision-capable language models in-process.** A GGUF that carries a multimodal projector (`mmproj`) loads the projector alongside the language weights, so image attachments are encoded and interleaved into the prompt inside the same runtime rather than routed to a separate vision service. Catalog entries declare the projector via `MmprojSpec`; the path compiles under the `mtmd` cargo feature.
- **Difficulty-aware routing.** Model selection from declared metadata (parameter count, context window, capability tags) says nothing about whether a specific prompt needs the expensive model. Prompts are embedded and grouped by an online sequential k-means map that grows on demand — no training corpus, no offline fit — and each model accrues per-cluster outcome counters from real serving results, so its strength is a measured property per prompt neighborhood. A newly registered model starts at a neutral prior with an optimism bonus so it stays explorable. Cluster map and counters persist in `CF_MODELS` and hydrate on startup.
- **Network model catalog.** Providers broadcast signed model offers on `tenzro/models` carrying modality, capabilities, context length, the provider's own price, a serving schedule, a TTL, and the serving address. The node verifies each announcement, pins the signing key per `(model_id, provider)` pair, and hands the unexpired set to intent routing — so routing scores every live offer on the network, not only what the local operator registered, and the settlement split follows the payee named in the winning offer.
- **Applications run in harnesses.** Markets (task markets, purchases with dispute panels), training jobs, reputation, hosting, workflows, agent templates and third-party connectors are not protocol features: a harness runs them over the public RPC, MCP, A2A and SDK surface, paying through escrows that carry its own reference. The chain keeps the primitives they need: escrows (signature, executor, hash lock, stream, committee release), settlement, the insurance pool, network duties the chain pays the first prover for (`tenzro_listDuties`), and evidence checks against chain state (`tenzro_verifyEvidence`).
- **Generative media.** Image, video, audio, 3D, action-policy and world-model renders as a model-serving modality. A node loads a catalog media model and renders it in process on the native Praecise diffusion engine; `tenzro_mediaGen_render` returns one seeded output with a signed receipt over its SHA-256 and perceptual fingerprint, so any provider holding the same weights can re-render it and an inference fault refunds the caller when they disagree. Renders are metered in pixel-steps against the node's rate card like every other modality. The preconfigured catalog entries are third-party checkpoints (Qwen-Image, Z-Image-Turbo, FLUX.2-klein, Janus-Pro, the Wan 2.2 video family, LTX, TRELLIS.2), none of them Tenzro's own. Job queues and worker pools are applications over this method. CLI `tenzro media-gen {catalog, render}`.
- **Confidential inference.** Model providers can wrap inference inside an Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC enclave; the result hash is signed with an enclave-bound key and the attestation chain verifies through `TEE_VERIFY` on-chain.

### Tenant file storage

Storage providers erasure-code objects across independent providers and are paid through storage claims. An OpenAI-shaped `/v1/files` for an application's tenants is an application a harness runs beside a provider, over the provider's `tenzro_storageStoreObject` and `tenzro_storageRetrieveObject`.

### 3D asset generation

Image-to-3D renders through the same method as image and video. The surrounding machinery (content-addressed output, signed receipts, metering) is identical; only the loader and the artifact differ, and those are exactly what the catalog entry carries.

- **Kinds.** `MediaGenKind` gains `image23d` and `text23d`. The output is a GLB mesh with PBR materials, not frames, so nothing downstream tries to decode it as video.
- **On the native engine.** `trellis2-4b` runs in process like every other media model: one reference image of the object on a transparent background in, a GLB with PBR textures out, built on the 512³ surface. Its DINOv3 image encoder is under Meta's DINOv3 License, so the entry is gated by that licence and the operator accepts `dinov3` before the node fetches it.
- **Checked like every render.** The receipt commits to the GLB's SHA-256 and a geometry fingerprint (the surface-area share of each cell of an 8³ grid over the asset's bounding cube), so another provider can re-render the seed and an inference fault refunds the caller when the shapes disagree.
- **Metered on what it produces.** A 3D render is metered on the voxel grid, not the conditioning image: `width`/`height` describe the _input photo_, so pricing on them would charge for the input and ignore the asset — two jobs from one photo at 512³ and 1536³ would cost the same while differing 27× in work. Charged on the grid face (`r²`), since generation cost tracks the sparse occupied surface rather than the empty interior, and against the same `per_pixel_step` rate so both settle through one path.

`tenzro model serve` and every pixel pipeline are untouched by any of this.

### Node capability surface

Two facilities cover the gap between what a node can do and what a caller can find.

- **Universal RPC gateway.** The node serves 469 JSON-RPC methods (see [docs/RPC.md](docs/RPC.md)) and gains more each release, so any hand-maintained client list is perpetually behind — and the developer discovers the gap exactly when they need the method. `tenzro_listRpcMethods` returns the directory from the node itself, each entry carrying its gate class (admin, owner, open or reserved) and the method class the access policy decides it under, so a caller can tell what it needs without provoking the error first; filter by namespace or substring, since unfiltered it is ~900 rows. Anything found can then be invoked by name. Authorization is unchanged: a gateway call passes the same access policy and default-deny classification as a direct request, reaching exactly what the presented access token already allows. Exposed on the CLI (`tenzro rpc {methods, call}`), both SDKs, MCP, and A2A.
- **Visibility — one setting per node, three values.** The operator sets `public`, `gated` or `private` once, and it applies to every resource the node offers (models of every type, compute, storage, databases, hosting, tools) unless a resource carries its own override. `public` announces the resource and makes it usable by **any caller who pays** the operator's per-use price (`0` is free) — no sign-in, as long as the node's access policy leaves `inference` open. `gated` announces it flagged as access-required and admits only callers the access policy names, with no pay-per-use path. `private` announces nothing and serves only the node's own callers; a private node still validates. CLI `tenzro visibility {show, set}` and `tenzro model serve [--public | --gated | --private]`. The model admission check applies after the access policy, on every inference route.

### Multi-modal inference

The catalog spans seven ONNX runtimes plus the llama.cpp language path, all dispatched by the modality-aware `InferenceRouter::route()` against typed `InferencePayload` (Chat / Forecast / VisionEmbed / VisionSimilarity / TextEmbed / Segment / Detect / Transcribe / VideoEmbed). License tiers — Permissive (Apache/MIT/BSD), Attribution (CC-BY-4.0), CommercialCustom (DINOv3, SAM, Gemma — require `--accept-license`), NonCommercial (refuse without `--accept-non-commercial`) — gate registration. A licence's commercial-use conditions (revenue thresholds, required authorizations, display duties, territory) are recorded with its catalog entry and returned as `license_conditions`; weights bound by several licences (a text encoder under its own terms beside the checkpoint's) take the most restrictive tier of them, every one must be accepted, and `license_conditions` lists each licence's conditions; every catalog row also carries `paid_serving`, false for a licence that restricts serving for pay, and such a model is only ever served free of charge. Forecast (TimesFM 2.5), Vision embedding (CLIP, SigLIP2, DINOv3, DINOv2), Text embedding (Qwen3-Embedding, EmbeddingGemma Matryoshka, BGE-M3, Snowflake Arctic), Segmentation (SAM 3 / 3.1, SAM 2, EdgeSAM, MobileSAM), Detection (RF-DETR, D-FINE), Audio ASR (Moonshine v2, Distil-Whisper, Whisper v3 turbo, Parakeet-TDT, Canary-1B-Flash), Video (frame-pooled vision encoder over uniformly-sampled frames). Each modality is exposed through JSON-RPC, MCP, A2A, and a CLI subcommand. All ONNX runtimes share one session builder whose execution providers follow the detected hardware: the `cuda` feature compiles in CUDA and TensorRT, every session on an NVIDIA machine registers them, and a provider that fails to register refuses the load rather than running on the CPU; `onnx-coreml` adds CoreML on Apple machines. Container image variants package the LLM-accelerated binary against a matching runtime: `Dockerfile.cuda` (NVIDIA CUDA — multi-arch, covering x86_64 and arm64 hosts such as Grace-Blackwell), `Dockerfile.rocm` (AMD ROCm), and `Dockerfile.vulkan` (cross-vendor Vulkan). The CUDA image carries the ONNX CUDA and TensorRT providers on both x86_64 and arm64; under the ROCm and Vulkan images the ONNX modalities run on the CPU while the llama.cpp language path is GPU-accelerated. See `docs/AI.md` §2.7 for the full backend/image matrix.

### Identity (TDIP) — four classes

- `did:tenzro:human:{uuid}` — KYC tier, controlled machines, controller of any number of delegated agents.
- `did:tenzro:machine:{controller}:{uuid}` — delegated agent acting on behalf of a human, institution, or upstream machine. Carries a delegation scope (per-tx cap, daily cap, allowed operations / chains / payment protocols / counterparties, time bound).
- `did:tenzro:machine:{uuid}` — autonomous agent. Same wallet and A2A surface, no controller.
- `did:tenzro:institution:{lei}:{uuid}` — legal entity anchored to its 20-character GLEIF Legal Entity Identifier (ISO 17442) with ISO 7064 Mod 97-10 check-digit validation at registration. Optional vLEI ACDC credential id binding, ISO 3166-1 alpha-2 country code, KYB tier. One legal entity can hold multiple institution identities (one per desk / fund / subsidiary) without re-issuing LEIs.

W3C DID Documents. W3C Verifiable Credentials with recursive trust-chain verification (cycle detection, depth bound, anchored to configured trust roots). KYC/KYB tier upgrades via credential. Cascading revocation. **Universal Resolver** at `/1.0/identifiers/{did}` (DIF spec) for any standards-compliant client. **KERI** Key Event Log for long-lived autonomous machine identities (inception, rotation, interaction events with pre-rotation commitments; SAID prefix `S` for SHA-256). **Sign-In With Tenzro** (SIWT) — EIP-4361-shaped message for off-chain service authentication.

### Payments

**Crypto rails — settle on-chain in TNZO or stablecoins:**

- **AP2** (Agent Payments Protocol): Google/FIDO protocol for verifiable agent payments using intent/cart/payment VDCs; mandate-pair validation via `tenzro_validateMandatePair`
- **MPP** (Machine Payments Protocol): Session-based streaming payments, co-authored by Stripe and Tempo
- **x402** (Coinbase): Stateless HTTP 402 payments with EIP-3009 authorization. The default facilitator is self-hosted — the operator runs the scheme's admission checks and settles through its own EVM signer rather than routing the signed authorization to a remote facilitator
- HTTP middleware for automatic payment challenge/verification

Card networks (Visa Trusted Agent Protocol, Mastercard Agent Pay) are adapters in harnesses: they carry an agent's Tenzro identity, delegation scope and audit receipts to the card network, which settles the card transaction.

### Security

- Real TEE integration: Intel TDX (`/dev/tdx-guest`), AMD SEV-SNP (`/dev/sev-guest`), AWS Nitro (`/dev/nsm`), NVIDIA GPU CC (NRAS API)
- X.509 certificate chain verification with pinned vendor root CAs
- AES-256-GCM enclave encryption with HKDF key derivation
- Plonky3 STARK proofs over KoalaBear (no trusted setup, post-quantum sound), with on-chain `ZkCommitmentRegistry` for O(1) EVM verification
- Wallet keys live only in passkeys, TPMs or Secure Enclaves; every account signs with its P-256 key and an ML-DSA-65 key together, and both legs are mandatory: an account with no ML-DSA-65 key enrolled signs nothing until it enrols one (the first transaction of a new sender is its enrolment), and identity registration is refused for hardware that has no ML-DSA-65 key. Multi-party approval is a k-of-n quorum of independent hardware keys
- Post-quantum validator consensus (composite ML-DSA-65 + P-256 checkpoint certificates, ML-KEM-768 consensus channels) and PQ-hybrid transport (X25519MLKEM768 key exchange). Stored records carry hybrid Ed25519 / ML-DSA-65 session signatures from the moment governance sets, endpoints authenticate with an ML-DSA-65 leg beside Ed25519, the randomness beacon takes hash-committed hardware secrets beside its VRF output once governance enables it, validators may hold ML-DSA-87 / P-384 consensus keys, and vouchers for channels on other chains can be signed with one-time hash-based keys. The classical parts: the P-256 leg of hardware keys (the pair is what protects), a few verifiers that check the ML-DSA-65 leg only when a key carries one (listed in [docs/PQ-AND-AI-SAFETY.md](docs/PQ-AND-AI-SAFETY.md)), EVM-standard transactions signed with secp256k1, Ed25519 session signatures before governance requires hybrid ones, the Ed25519 VRF on its own while commit-reveal is off, Ed25519 endpoint authentication with peers that bind no ML-DSA key, WebPKI certificates on transport, the Groth16 (BN254) wrapping of finality proofs for external chains, and the bridges' external-chain signatures
- VRF (RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI) for provably-fair randomness — precompile `0x1007`, NFT `mintRandom` (`0x52517e21`)

### Cross-Chain Bridge (one path: governed routes)

- **EVM** (Ethereum, Base, Arbitrum) and **Solana**: CCIP-compatible message envelope
- **Cosmos** chains: IBC (classic or v2)
- **Bitcoin**: deposit route
- **Sui**, **Aptos**, **Stellar** and **TON**: Tenzro's bridge contract on each chain

Every route obeys the same rules, enforced by the framework rather than any adapter: strict canonical decoding, committee (and on CCIP routes, independent blessing committee) attestations bound to this chain, the route, a nonce and an expiry; light-client proofs where a route requires one; a circuit breaker; per-transfer and per-epoch caps; and the supply invariant (what is outstanding on the other chain never exceeds the TNZO locked on Tenzro for that route). RPCs: `tenzro_listBridgeRoutes`, `tenzro_getBridgeRoute`, `tenzro_getBridgeOutbound`; transfers out are holder-signed `Bridge` transactions, and deliveries and light-client updates are `Bridge` transactions their relayer signs and pays for. See [docs/BRIDGE.md](docs/BRIDGE.md).


### Bridge Fee in TNZO

- **One rate pipeline**: each closed epoch, bonded validators report USD rates per symbol (`FeeRateSubmit`), each from at least two independent providers; the VM freezes each symbol's stake-weighted median once two thirds of stake has reported, moving at most the governed bound per epoch. Chainlink aggregators and signed Data Streams are inputs to a validator's report; a stream counts only under the signer set governance installs on chain (`SetRateStream` / `RemoveRateStream`).
- **Quotes from chain state**: `tenzro_quoteBridgeFeeInTnzo` converts a destination-native fee into TNZO at the committed rates, so every node quotes the same amount; it is refused while the destination's native asset is unpriced.

### Tokenization & Compliance

- **ERC-7943 (uRWA)**: real-world-asset compliance — the token issuer's halt, freeze and forced transfer are signed `Token` transactions; `tenzro_urwaIsKillSwitched` / `tenzro_urwaGetFrozenTokens` read them.
- **IVMS101 v1.1.0**: FATF Travel Rule canonical envelope binding for KYC payloads on cross-border transfers.
- **Reserve-backed tokens**: mints in consensus only against fresh reserve attestations from bonded attestors.
- **TEE-attested timestamps**: saga step deadlines and obligation expiries carry a TEE-attested `wall_ms + monotonic_ns + tee_vendor` envelope with 30s drift tolerance.

### Agent Interoperability

- **ERC-8004**: Trustless Agents Registry on Ethereum — mirror Tenzro machine DIDs to the `registerAgent`/`getAgent`/`submitFeedback`/`validationRequest`/`validationResponse` interface for cross-ecosystem agent reputation.
- **AAP** (Agent Access Protocol): OAuth 2.1 + DPoP + RAR layering for agent-issued bearer tokens. The CLI exposes it as `tenzro auth`.

### Compliance & Disclosure (EU AI Act Article 50)

- **§50(1)** chatbot disclosure: every CLI / MCP / A2A AI text response is prefixed with `[AI]`. Single source of truth in `tenzro_node::eu_ai_disclosure`.
- **§50(2)** synthetic-content marker: every inference output carries a C2PA-style `ContentProvenanceManifest` keyed by SHA-256 content hash. Validators sign manifests with their Ed25519 block-signing key. RPC `tenzro_getContentProvenance` and CLI `tenzro provenance get <content_hash>` resolve the cached manifest.
- **§50(4)** deepfake assertion tag: outputs imitating real subjects use the `deepfake` assertion in place of `ai-generated`.
- **Approval flow**: out-of-scope agent operations are parked for controller review. Inspect via `tenzro approval list/get` and decide via `tenzro approval decide`.
- **Channel disputes**: durable lifecycle records readable via `tenzro dispute status` and `tenzro dispute list-by-channel`.
- **Provider reputation**: `tenzro reputation get <provider>` reads the provider's standing (0–10000, from its serving bond and SLA verdicts) used by the inference router.

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
└── instances/
    └── default/     RocksDB, keys, wallets, snapshots, iroh blobs
```

`--data-dir` still overrides the per-instance directory and `models_dir`
overrides the shared store, for operators who keep large data on separate
volumes. The container images set `TENZRO_HOME=/data/tenzro` so the model store
sits on the mounted volume rather than the ephemeral layer.

## Authorization model

Three layers, each answering a different question:

- **Access policy** (`access.rs`) — one policy, `access.toml`, maps each
  service surface and method class to a rule: open, closed, paid, an allow
  list of DIDs and organizations, a KYA credential, consensus Terms, or a
  signed-in tier. Callers sign in with a passkey or a hardware key for a
  DPoP-bound access token; there is no shared secret. It has no consensus or
  gossip variant, so a closed node structurally cannot stop validating. **Model
  serving answers to the model's visibility on top of it**: a model at
  `public` visibility is reachable by payment alone, because a peer that found
  the offer over gossip has no way to sign in first. See
  [`docs/ACCESS.md`](docs/ACCESS.md).
- **Classification** (`rpc_gates.rs`) — every dispatched method is named in
  exactly one of `ADMIN_METHODS`, `OWNER_METHODS`, `OPEN_METHODS` or the
  reserved training names; a method in none is refused before its handler
  runs. Tests read the dispatcher's own
  source, so adding an RPC without deciding its gate is a build failure rather
  than an audit finding.
- **Ownership** — methods acting on a tenant's resource require a signed DID
  envelope from that resource's owner, bound to the method name and to the
  call's parameters. Node administration authenticates whoever runs the
  machine; it is the wrong gate for something belonging to somebody _using_ it,
  because accepting it would let a shared node's host mutate their tenants'
  resources.

`submitBlock`, `offerSnapshot` and `applySnapshotChunk` are not on the JSON-RPC
surface. They were peer traffic reachable over the user-facing port —
`submitBlock` pushed a caller-supplied block onto the finalized path, which by
contract has already been through consensus and therefore verifies nothing.
Blocks arrive over peer-authenticated gossip and block-sync. State sync runs over
iroh: a joining node asks a peer for a snapshot manifest on the
`tenzro/state-sync` ALPN and fetches the BLAKE3-verified buckets as blobs.
`listSnapshots` and `getSnapshotManifest` remain on JSON-RPC for inspection;
there is no chunk RPC.

## Ecosystem

| Component                      | Repository                                                                      | Description                                                                 |
| ------------------------------ | ------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| **TenzroClaw** (Python)        | [tenzro/TenzroClaw](https://github.com/tenzro/TenzroClaw)                       | OpenClaw skill                                                |
| **Rust SDK**                   | [`sdk/tenzro-sdk`](sdk/tenzro-sdk/README.md)                                 | Rust                                                                  |
| **TypeScript SDK**             | [`sdk/tenzro-ts-sdk`](sdk/tenzro-ts-sdk/README.md)                              | TypeScript                                                                  |
| **Browser-extension provider** | [`sdk/tenzro-inject`](sdk/tenzro-inject/README.md)                              | `window.tenzro` for dApps — EIP-1193 / EIP-6963 / Wallet Standard / CAIP-25 |
| **Desktop App**                | [`apps/tenzro-control`](apps/tenzro-control)                                     | Tauri + React          |

## Public endpoints

| Service       | URL                                  |
| ------------- | ------------------------------------ |
| JSON-RPC      | https://rpc.tenzro.com               |
| Web API       | https://api.tenzro.com               |
| MCP Server    | https://mcp.tenzro.com/mcp           |
| A2A Server    | https://a2a.tenzro.com               |
| Documentation | https://tenzro.com/docs              |

**Phases**: the network opens as a preview, then a testnet, then the stages governance decides on the way to mainnet. A preview chain can be reset and carries test tokens. Each phase change is an on-chain governance decision taken on measured results.

**Infrastructure**: The public endpoints on `tenzro.com` are served by a reference RPC provider on the network. Any machine can run a node, follow the chain and serve the roles its bond covers. The RPC provider role is a validator role: while `validator.admission_approval` is on (as it is during the preview), a new validator registers only once an enacted `ApproveValidators` proposal has named its account; governance turns the approval step off when it opens admission. TLS at the edge is PQ-hybrid X25519MLKEM768. The repository is the reference implementation.

**Genesis**: 1,000,000,000 TNZO total supply, allocated to the accounts genesis names.
A new wallet is funded by a transfer from a funded account; grants come from governance.
`tenzro join --provider` checks that the wallet holds the 1,000 TNZO bond before it posts it.

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

- Rust 1.99.1, pinned in `rust-toolchain.toml` (rustup installs it on first build)
- C/C++ compiler (for RocksDB, aws-lc-rs)
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

## Documentation

| Document                                                           | Purpose                                                                                                                                                                                                                                                                            |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`docs/CLI.md`](docs/CLI.md)                                       | Complete `tenzro` command reference — every group, subcommand and flag. Generated from the binary by `scripts/gen-cli-docs.sh`; a test fails when it and the CLI disagree |
| [`docs/WHITEPAPER.md`](docs/WHITEPAPER.md)                         | Tenzro Network whitepaper — vision, architecture, agent economy, settlement layer                                                                                                                                                                                                  |
| [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)                   | Protocol specification — architecture, consensus, multi-VM execution, identity, payments, settlement, agents, training, and the concrete Rust implementation                                                                                                                       |
| [`docs/ECONOMICS.md`](docs/ECONOMICS.md)                           | **Canonical**: who pays, who is paid, how much. Node economic modes, the revenue split, access tiers, settlement, provenance, machine identity                                                                                                                                                                       |
| [`docs/TOKENOMICS.md`](docs/TOKENOMICS.md)                         | TNZO token economics: supply, fee model, staking, rewards, treasury                                                                                                                                                                                                          |
| [`docs/TDIP.md`](docs/TDIP.md)                                     | Tenzro Decentralized Identity Protocol — identity over W3C DID across human, delegated agent, autonomous agent and institution; machine anchors, device binding and hardware-bound passkeys, sessions, the wallet second-device rule, and machine ownership transfer |
| [`docs/AI.md`](docs/AI.md)                                         | Tenzro AI — decentralized inference (single-replica + sharded MoE + MTP + multi-modal), confidential inference, and generative media (diffusion image and video) |
| [`docs/COMPUTE.md`](docs/COMPUTE.md)                               | Tenzro Compute — rentable compute capacity: per-epoch booking, availability-proof gate, streaming escrow, fixed or network-dynamic pricing, shared coverage with storage                                                                                                           |
| [`docs/STORAGE.md`](docs/STORAGE.md)                               | Tenzro Storage — decentralized content-addressed storage: byte-epoch billing, proof of retrievability, redundancy, and one stake shared with compute                                                                                                                               |
| [`docs/NETWORK.md`](docs/NETWORK.md)                               | Tenzro Network — decentralized networking: gossip topics over iroh-gossip, identity endpoint records + relays, point-to-point iroh ALPNs (DA, model weights, gradients, sealed shards, A2A + MCP)             |
| [`docs/GOVERNANCE_PARAMS.md`](docs/GOVERNANCE_PARAMS.md)           | Every governed parameter with its bounds and genesis value, the 32 proposal actions, status levers, guardian feature pause, jail and reinstatement |
| [`docs/PQ-AND-AI-SAFETY.md`](docs/PQ-AND-AI-SAFETY.md)             | What is post-quantum (ML-DSA-65 mandatory on accounts, hybrid ML-KEM-768 key wraps, X25519MLKEM768 transport), what stays classical and why, and how an agent is bounded |
| [`docs/SPONSORSHIP-AND-GRANTS.md`](docs/SPONSORSHIP-AND-GRANTS.md) | Sponsored validator bonds, running-cost sponsorship and grants: who is approved, how they are paid |
| [`docs/VERIFY-DOWNLOAD.md`](docs/VERIFY-DOWNLOAD.md)               | Verify a release download: SHA-256 manifest and cosign signatures |
| [`docs/RPC.md`](docs/RPC.md), [`docs/MCP.md`](docs/MCP.md), [`docs/NODE.md`](docs/NODE.md) | Generated references: every JSON-RPC method, every MCP tool (revision 2026-07-28) and every node flag |
| [`docs/KNOWN-RESIDUALS.md`](docs/KNOWN-RESIDUALS.md)               | Limits and open items stated plainly |
| [`docs/GUIDE.md`](docs/GUIDE.md)                                   | Operator and developer guide: build, run, deploy, troubleshoot                                                                                                                                                                                                                     |
| [`docs/did-method-tenzro.md`](docs/did-method-tenzro.md)           | `did:tenzro` DID method specification (W3C registration submission)                                                                                                                                                                                                                |
| [`deploy/validator-deployment.md`](deploy/validator-deployment.md) | Infrastructure-agnostic validator and node operator guide                                                                                                                                                                                                                          |
| [`docs/security/`](docs/security/)                                 | Threat model, security invariants, wallet custody                                                                                                                                                                                                                                  |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. All contributions require sign-off under the Apache-2.0 license.

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

Copyright 2024-2026 Tenzro Foundation.
