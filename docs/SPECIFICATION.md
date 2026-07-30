# Tenzro Network — Protocol Specification

## The Open, Distributed Execution Layer for AI

### Tenzro Ledger: A TEE-Native Network for Verifiable AI and Autonomous Agents

**Version 0.1.0 — March 2026**

---

## Abstract

**Tenzro Network** is the open, distributed execution layer for AI — a decentralized protocol where inference, agents, and workflows run across independently operated nodes rather than one provider's servers. The network provides three execution resources from those nodes: **intelligence** (AI models for inference), **compute** (rentable capacity by the epoch), and **storage** (content-addressed data held to a proof of retrievability), with **security** (TEE enclaves for key management, custody, and confidential computing) underwriting them. A single node can take on several of these roles against one stake: providers, validators, and nodes earn TNZO by securing the network, serving intelligence, renting out compute, holding data, and providing security. Consumers pay from their TNZO balance; providers earn into theirs.

**Tenzro Ledger** is the purpose-built network for humans and agents, providing verifiable, on-chain primitives for the AI age: **identity** (TDIP: Tenzro Decentralized Identity Protocol for humans and machines), **security** (TEE-weighted consensus with hardware attestations), **verification** (dual ZK + TEE proof systems), and **settlement** (micropayment channels, escrow, batch processing). All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

Built from the ground up around Trusted Execution Environments (TEEs) and zero-knowledge proofs, the Ledger provides hardware-rooted trust at every layer — TEE-attested validators receive a 1.5× multiplier on their reputation-weighted leader-selection draw, smart contracts execute within hardware enclaves, and all on-chain claims can be independently verified through cryptographic proofs or hardware attestations. The Ledger supports a multi-VM execution environment (EVM, SVM, Daml/Canton), an autonomous agent framework with self-sovereign identity and MPC wallet ownership, a multi-modal AI model marketplace covering text, vision, audio, and timeseries inference with per-token settlement, decentralized verifiable training (Tenzro Train, decoupled outer-aggregation with on-chain run-root commitments), diffusion image and video generation (Tenzro Media Gen, including split-expert rendering across two accelerators), recurrent-depth reasoning workers (Tenzro Cortex) priced by loop depth and bound to signed receipts, swarm orchestration for parallel agent execution, and cross-chain interoperability through Wormhole NTT, LayerZero V2, Chainlink CCIP, deBridge DLN, Li.Fi, and Canton. Multi-protocol payment support (MPP, x402, Tempo, Stripe SPT, AP2) enables HTTP 402-based machine payments with identity-bound delegation enforcement. Consensus is a two-phase HotStuff-2 BFT engine with 400ms block times, reputation-weighted proposer election, no-endorsement certificates for tail-fork resistance, and Ed25519 + ML-DSA-65 hybrid post-quantum signatures on every safety-critical message.

Tenzro is the open, distributed execution layer for AI. The execution surface — inference, agents, workflows — runs on a substrate where verifiable computation, confidential execution, rentable compute, decentralized storage, and agent-to-agent economic coordination are protocol-level primitives. Multi-role nodes, one stake covering every role, and per-epoch streaming settlement are what make that execution layer open and trustless. See [`COMPUTE.md`](COMPUTE.md) and [`STORAGE.md`](STORAGE.md) for the rentable-compute and storage surfaces.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [Consensus: HotStuff-2 BFT](#3-consensus-hotstuff-2-bft)
4. [Multi-VM Execution Layer](#4-multi-vm-execution-layer)
5. [Trusted Execution Environments](#5-trusted-execution-environments)
6. [Zero-Knowledge Proof System](#6-zero-knowledge-proof-system)
7. [Cryptographic Primitives](#7-cryptographic-primitives)
8. [TNZO Token Economics](#8-tnzo-token-economics)
9. [Settlement Layer](#9-settlement-layer)
10. [AI Model Marketplace](#10-ai-model-marketplace)
11. [Autonomous Agent Framework](#11-autonomous-agent-framework)
12. [Tenzro Decentralized Identity Protocol (TDIP)](#12-tenzro-decentralized-identity-protocol-tdip)
13. [Payment Protocols](#13-payment-protocols)
14. [Cross-Chain Bridge](#14-cross-chain-bridge)
15. [Self-Custody, Wallets, and Key Management](#15-self-custody-wallets-and-key-management)
16. [Peer-to-Peer Networking](#16-peer-to-peer-networking)
17. [Storage and State Management](#17-storage-and-state-management)
18. [Governance](#18-governance)
19. [Security Model](#19-security-model)
20. [Tenzro Train: Decentralized Verifiable Foundation-Model Training](#20-tenzro-train-decentralized-verifiable-foundation-model-training)
20a. [Tenzro Media Gen](#20a-tenzro-media-gen)
21. [Roadmap](#21-roadmap)

---

## 1. Introduction

### 1.1 The Problem

Existing blockchains were designed for financial transactions. They can transfer tokens and execute deterministic smart contracts, but they have no native understanding of computation, hardware trust, or autonomous software agents. As AI systems become economically significant actors — executing tasks, consuming resources, and generating value — this gap creates three categories of problems:

- **No verifiable computation.** Blockchains can record that a transaction occurred, but cannot verify that an off-chain computation (such as an inference, a training step, or a data transformation) was actually performed correctly by the claimed hardware running the claimed software. Existing approaches rely on staking and economic penalties, which are probabilistic at best and gameable at worst.
- **No hardware-rooted trust.** Smart contract execution is transparent by design — every validator sees every input. There is no mechanism for confidential computation where the chain itself enforces that data remains private while still producing verifiable results. Bolting TEE support onto an existing chain as a middleware layer forfeits the security guarantees that come from integrating hardware trust into consensus itself.
- **No agent-native primitives.** AI agents that need to discover services, negotiate prices, manage funds, and coordinate with other agents must do so through human-designed interfaces and custodial wallets. There is no chain where agents participate on the same footing as humans — with self-sovereign identity, their own key material, and the ability to transact autonomously within programmatic guardrails.

### 1.2 The Tenzro Solution

**Tenzro Network** is the protocol layer designed for the AI age. It provides two core capabilities to participants:

1. **Access to Intelligence:** A decentralized marketplace where providers serve AI models and users discover and consume inference through a chat interface (like ChatGPT/Claude). Settlements happen on-chain with micropayment channels for per-token billing.

2. **Access to Security:** Providers offer TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs) for confidential computation, key management, custody services, and verification. Users and agents can leverage hardware-rooted trust for sensitive operations.

Providers, validators, and nodes earn by:
- **Securing the network** (validator rewards and staking)
- **Providing intelligence** (per-inference fees from the AI marketplace)
- **Providing security** (fees for TEE enclave services)

**Tenzro Ledger** is the network that underpins the protocol. It treats hardware trust, verifiable computation, and autonomous agents as foundational primitives rather than application-layer add-ons:

- **TEE-native consensus.** Validators running inside Trusted Execution Environments receive a **1.5× multiplier** on their reputation-weighted leader-selection draw in the HotStuff-2 BFT consensus protocol. The multiplicative form (rather than a hard 2× boost) preserves the property that observed behaviour can fully overcome attestation: a TEE-attested but chronically-flaky validator is still dwarfed in draw probability by a non-TEE active validator. TEE attestations are verified on-chain and influence block validity.
- **Dual verification: ZK + TEE.** Every computation claim can be backed by a zero-knowledge proof (Plonky3 STARK over the KoalaBear field with FRI commitments), a TEE attestation, or both simultaneously through hybrid ZK-in-TEE execution. This provides two independent trust anchors — cryptographic (ZK) and hardware (TEE) — giving applications flexibility to choose their security/performance tradeoff. Plonky3 STARKs require no trusted setup and are post-quantum sound.
- **Multi-VM execution.** The Ledger supports EVM, SVM, and Daml smart contracts through a unified runtime. Applications are not limited to inference — any programmable logic can run on Tenzro, with the added capability of invoking TEE execution and ZK verification through native precompiles.
- **Agent-first design.** AI agents participate on the same footing as humans, with self-sovereign identity (DID-based via TDIP), MPC threshold wallets they control without custodians, capability-based permissions, and a native agent-to-agent (A2A) communication protocol. Agents can discover each other, negotiate services, and settle payments autonomously.
- **Native settlement primitives.** Micropayment channels, escrow contracts with programmable release conditions, and atomic batch settlement are built into the Ledger — not implemented as smart contracts on top of a generic VM. This enables sub-second settlement for high-frequency economic activity like per-token inference billing.

All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

### 1.3 What Tenzro Does That No Other Chain Does

By the start of 2026, agentic finance runs across three separate ecosystems, each with its own protocols, settlement primitives, and execution model:

- **EVM / agent-commerce surface.** ERC-8004 (Trustless Agents) reached mainnet on 2026-01-29. AP2 (Agent Payments Protocol) was donated by Google to the FIDO Alliance in April 2026 with 60+ partners (Adyen, AmEx, Mastercard, Stripe, OpenAI, Anthropic). x402 (Coinbase) reports ~$50M cumulative / ~$600M annualized micropayment volume. ERC-4337 v0.8 + EIP-7702 form the smart-account substrate. TEE-confidential agents are offered as middleware by Phala and Oasis (Sapphire/ROFL); NEAR AI offers TEE-attested agents as a platform feature.
- **SVM / Solana agent-trading surface.** Application-layer frameworks (ElizaOS, SendAI Solana Agent Kit, GOAT SDK) reach Jupiter, Drift, Mango, Metaplex, Bonfida, and SPL — but protocol-level identity, settlement, and consensus primitives for agents are inherited from Solana proper, not designed for them.
- **Canton / institutional-RWA surface.** Tokenized US Treasuries and several announced bank deposit tokens settle on Canton synchronizers under the CIP-56 token standard, which encodes DvP directly in the ledger model. Production institutional volume from autonomous agents on Canton is effectively zero.

A small set of L1s pursue multi-VM execution. **Fluent** (mainnet 2026-04-24) is the closest analog and runs EVM + SVM + WebAssembly — but does not include DAML, which is what the institutional RWA surface actually runs on. Sei v2 pioneered the EVM↔Wasm pointer-token model that Tenzro generalizes. Move-VM chains run a single execution environment and are not multi-VM in the EVM/SVM sense.

**Five things Tenzro does that no other chain in 2026 does:**

1. **Run EVM, SVM, and Canton/DAML in one chain.** `tenzro-vm` runs three executors (revm EVM, `solana-svm` SVM, Canton 3.5+ DAML) behind one runtime. Routing is at the transaction-type layer, not via cross-chain messaging. No 2026 chain combines all three.
2. **Bridge retail-agent and institutional-RWA rails under one identity.** A single TDIP DID can act on AP2/x402/ERC-8004/ERC-4337 (retail-agent) and Canton/CIP-56/DvP (institutional) with the same delegation scope, the same wallet, and the same on-chain settlement.
3. **Run the full agent-commerce stack natively, across crypto rails and card rails.** AP2 (`tenzro_validateMandatePair`), x402 with EIP-3009, MPP with Stripe Payment Intents — all settling on-chain in TNZO. For card rails (Visa Trusted Agent Protocol, Mastercard Agent Pay) where the money moves over the card network, Tenzro provides the layer the card networks do not: agent DID, signed delegation scope, AP2 mandate validation, and an on-chain audit receipt. ERC-8004 system precompiles at `0x101a/0x101b/0x101c` with byte-identical selectors to Ethereum, ERC-4337 v0.8 EntryPoint, A2A on port 3002, MCP via `rmcp` — all inside Tenzro consensus.
4. **Treat confidential agent compute as a consensus primitive, not a sidecar.** TEE-attested validators get a 1.5× multiplier on their reputation-weighted leader-selection draw. The `TEE_VERIFY` precompile verifies real Intel TDX (P-256 ECDSA over Quote\[0..632\]), AMD SEV-SNP, AWS Nitro (COSE_Sign1 ES384 per RFC 8152 §4.4), and NVIDIA GPU CC quotes on-chain with pinned vendor root CAs. ZK proofs are commitment-attested via `ZkCommitmentRegistry` for O(1) EVM verification.
5. **Settle agentic micropayments in a pointer-model native asset.** TNZO has one balance with three VM views — wTNZO ERC-20 at `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93` on EVM, SPL adapter on SVM, CIP-56 holdings on Canton. All three views read and write the same underlying account state — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f` — encodes ASCII T+0x80, N, Z, O), and W3C DID (`did:tenzro`).
6. **Coordinate capital allocation as a typed protocol standard.** The **Capital Intent** standard (`tenzro_capitalIntent*`) is the regulated-capital-markets analog of an AP2 Intent Mandate — a signed financial objective (acquire/exit/rebalance/hedge/yield) with reg-regime + KYC + ceilings, fulfilled by ERC-8004/KYA-ranked solver agents over ERC-7683/CCIP settlement, gated by `erc3643` compliance, and backed by attested-mint (`tenzro_attestedMint`) which enforces `supply ≤ attested reserves` as a 1:1 invariant. No other 2026 stack offers a capital-allocation intent.

What makes this work is the **combination**, not any single piece: AP2, x402, ERC-8004, ERC-4337, MCP, A2A, Plonky3, Poseidon2, FRI, KoalaBear, and TEE attestation are open standards adopted byte-for-byte rather than reinvented. The work is integrating them inside one consensus layer with one native asset and one identity surface.

For the full protocol-layer view, see [`WHITEPAPER.md`](WHITEPAPER.md).

### 1.4 Design Principles

1. **Hardware trust at the foundation.** TEE integration is not a sidecar — it influences validator selection, consensus weight, proof generation, and execution confidentiality. The Ledger is designed so that the strongest security guarantees emerge from hardware-attested participation.
2. **Cryptographic verifiability.** Claims about computation, identity, and payment are backed by mathematical proofs or hardware attestations, not economic penalties alone.
3. **General-purpose programmable network.** Tenzro Ledger is a programmable network, not an inference-specific subnet. AI model routing and settlement are built-in capabilities, but the Ledger supports arbitrary smart contract logic across three VM targets (EVM, SVM, Daml/Canton).
4. **Economic alignment.** Token economics incentivize honest behavior: validators earn block rewards and transaction fees (gas paid in TNZO) for securing the Ledger; providers earn per-inference fees and TEE service fees with the Network taking a commission that flows to the treasury; misbehavior is punished through stake slashing.
5. **Interoperability.** Multi-VM execution and cross-chain bridges (LayerZero, CCIP, deBridge, Canton) ensure Tenzro connects to existing ecosystems rather than requiring migration.

---

## 2. Architecture Overview

### 2.1 Tenzro Network and Tenzro Ledger

**Tenzro Network** is the overall protocol/platform designed for the AI age, enabling agents and autonomous systems to participate as economic actors in their own right. The Network provides:
- Access to **intelligence** (decentralized AI model marketplace)
- Access to **security** (TEE enclaves for custody, key management, confidential computing)

**Tenzro Ledger** is the network that provides the economic substrate for Tenzro Network. The Ledger offers purpose-built primitives for the AI age:
- **Identity:** TDIP (Tenzro Decentralized Identity Protocol) for unified human/machine identity
- **Security:** TEE-weighted consensus with hardware attestations
- **Verification:** Dual ZK + TEE proof systems
- **Settlement:** Micropayment channels, escrow, batch processing (all in TNZO)

**Revenue Model (Two-Tier Fee Structure):**

1. **Ledger Transaction Fees (Gas):** All on-chain transactions pay gas fees in TNZO to validators, securing the economic substrate. Uses EIP-1559 dynamic fee market.

2. **Network Commission Fees:** The Tenzro Network collects a 0.5% commission on AI provider inference payments and TEE provider service fees. This commission is distributed: 40% to treasury, 30% burned, 30% to stakers.

Providers/validators/nodes can earn from multiple sources:
- **Validators:** Block rewards + transaction fees (gas) for securing the Ledger
- **Model Providers:** Per-inference fees (minus 0.5% Network commission) for providing intelligence
- **TEE Providers:** Service fees (minus 0.5% Network commission) for providing security
- Nodes can serve multiple roles simultaneously (e.g., a validator can also be a Model Provider and/or TEE Provider)

### 2.2 System Architecture

```
                    +---------------------------------------+
                    |         User Interfaces                |
                    |   Desktop (Tauri+React) / CLI / SDKs   |
                    +------------------+--------------------+
                                       | JSON-RPC + HTTP
                    +------------------v--------------------+
                    |            tenzro-node                 |
                    |      RPC Server + Web Verify API       |
                    +------------------+--------------------+
                                       |
          +----------+---------+-------+-------+---------+----------+
          |          |         |               |         |          |
     +----v---+ +---v----+ +--v-----------+ +-v-----+ +-v------+ +-v------+
     |Network | |Consen- | |  Multi-VM    | |Storage| | Model  | | Agent  |
     |(libp2p)| |  sus   | | EVM+SVM+Daml| |RocksDB| |Registry| |Runtime |
     +--------+ +--------+ +--------------+ +-------+ +--------+ +--------+
          |          |         |               |         |          |
     +----v----------v---------v---------------v---------v----------v-------+
     |                    Supporting Infrastructure                          |
     |   Crypto - TEE - ZK - Wallet - Token - Settlement - Bridge            |
     |   Identity - Payments                                                |
     +----------------------------------------------------------------------+
```

### 2.3 Crate Architecture

The system is implemented as a Rust workspace of 32 crates plus SDKs, organized in a strict dependency hierarchy:

| Layer | Crate | Purpose |
|-------|-------|---------|
| Foundation | `tenzro-types` | Shared types, primitives, constants (zero internal dependencies) |
| Cryptography | `tenzro-crypto` | Ed25519, Secp256k1, AES-256-GCM, X25519, BLS12-381, FROST-Ed25519 threshold signing, VRF (RFC 9381) |
| Trust | `tenzro-tee` | TEE abstraction over Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber |
| Proofs | `tenzro-zk` | Plonky3 STARKs over KoalaBear (Poseidon2 + FRI), pre-built AIRs, hybrid ZK-in-TEE |
| Networking | `tenzro-network` | libp2p gossipsub, Kademlia DHT, peer management, Identify + AutoNAT v2 + Circuit-Relay v2 + DCUtR |
| iroh data plane | `tenzro-iroh` | QUIC-native content-addressed transport, DA backend, gradient store, sealed-shard store, A2A-over-iroh on `tenzro/a2a` ALPN |
| Storage | `tenzro-storage` | RocksDB, Merkle Patricia Trie, snapshots, fsync durability |
| Storage provider | `tenzro-storage-provider` | Paid decentralized storage: provider daemon, proof of retrievability, Reed-Solomon redundancy, per-byte-epoch metering |
| Databases | `tenzro-database` | Distributed database protocol: engine catalog (Postgres, Qdrant, Milvus, Dgraph, Valkey, embedded Lance and Tantivy), descriptors, partition placement, access control (engine-agnostic, links no driver) |
| Cluster substrate | `tenzro-cluster` | Engine-agnostic local-network cluster tier: reachability tiers, probed link-cost graph, nearest-neighbour ordering, rendezvous placement — shared by model layers, storage shards, and database partitions |
| Consensus | `tenzro-consensus` | HotStuff-2 BFT (three-phase PREPARE → COMMIT → DECIDE), epoch management, finality tracking, 1.5× TEE-weighted leader selection |
| Execution | `tenzro-vm` | Multi-VM runtime: EVM, SVM, Daml executors |
| Economics | `tenzro-token` | TNZO token, staking, rewards, treasury, governance |
| Wallets | `tenzro-wallet` | FROST-Ed25519 (RFC 9591) 2-of-3 threshold wallets + ML-DSA-65 hybrid, Argon2id keystore |
| Device keys | `tenzro-device-key` | Non-extractable P-256 keypairs in the platform secure element (macOS/iOS Secure Enclave, biometric-gated): prehash signing and ECIES secret wrapping |
| Keystore unlock | `tenzro-keystore-unlock` | Platform-agnostic source of the keystore password so wallets persist across restarts: device key, environment, file, or KMS |
| Authentication | `tenzro-auth` | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests) |
| Identity | `tenzro-identity` | TDIP: unified human/machine identity, W3C DID, verifiable credentials, delegation |
| Payments | `tenzro-payments` | Payment protocols: AP2, MPP (Stripe/Tempo), x402 (Coinbase), Tempo integration, Stripe SPT, ERC-8004 Trustless Agents Registry, Visa TAP, Mastercard Agent Pay |
| Agents | `tenzro-agent` | Agent runtime, lifecycle, A2A protocol, capability registry, swarm orchestration, durable persistence |
| Agent Kit | `tenzro-agent-kit` | High-level agent SDK: compose agents from skills, tools, payment protocols |
| AI Models | `tenzro-model` | Multi-modal model registry, llama.cpp LLM runtime, ONNX vision/text-embedding/segmentation/detection/audio/video runtimes, ONNX timeseries forecasting runtime, inference routing, pricing engine, durable catalog |
| Reasoning | `tenzro-cortex` | Recurrent-depth reasoning workers (RDT/MoE), HTTP sidecar architecture, signed receipts, attestation suite, gossip-based worker discovery |
| Training | `tenzro-training` | Decentralized training protocol: outer-gradient aggregation, fragment exchange, sync rounds, training receipts (Rust protocol layer; Python reference trainer for inner loop) |
| Media Gen | `tenzro-media-gen` | Generative-media protocol: diffusion job queue, worker registry, pixel-step pricing, split-expert payment division, signed handoffs and receipts (Rust protocol layer; Python reference worker for the denoising loop) |
| Settlement | `tenzro-settlement` | Escrow, micropayments, batch settlement, fee collection |
| Events | `tenzro-events` | Event sourcing and subscription system with replay, webhooks, websockets |
| Workflow | `tenzro-workflow` | Multi-party workflow runtime: orchestrates Canton DAML receipts, on-chain transaction selectors `0x01000040`–`0x0100004B` |
| Sandboxed skills | `tenzro-wasm` | WASI 0.2 component host for language-agnostic agent skills and MCP tools. Capability-based sandbox, deterministic fuel metering, content-addressed component identity, execution receipts |
| Bridge | `tenzro-bridge` | LayerZero V2, Chainlink CCIP + CCT, deBridge DLN, Li.Fi, Wormhole NTT (with Guardian quorum verifier), Canton, **Hyperlane V3** (sovereign Tenzro-ISM), **Axelar GMP** (Cosmos / Move / Stellar reach), **Babylon Bitcoin staking** (finality-providers protocol) |
| Node | `tenzro-node` | Full node binary, RPC server (855 methods), MCP (526 tools), A2A (40 skills), web API |
| CLI | `tenzro-cli` | Command-line interface (103 command modules) |
| SDK | `tenzro-sdk` | Rust SDK with builder-pattern configuration |
| TypeScript SDK | `tenzro-ts-sdk` | TypeScript SDK for browser and Node.js integration |

### 2.4 Node Roles

Participants in the Tenzro Network operate nodes in one of several roles. Nodes can serve multiple roles simultaneously (e.g., a validator can also be a Model Provider and/or TEE Provider, or a validator can additionally serve as an RPC Provider):

- **Validator.** Participates in HotStuff-2 consensus, proposes and votes on blocks, earns block rewards and priority fees (gas paid in TNZO). Each validator also runs a Canton participant node natively, connecting to one or more Canton synchronizers for Daml smart contract execution. **Three-tier model** detailed in §3.4a: Tier 1 (resource-only, unbonded), Tier 2 (staked, ≥ 10,000 TNZO), Tier 3 (RPC provider, ≥ 100,000 TNZO and implies Tier 2). All three tiers run the same protocol and sign the same QCs, but quorum weight is the validator's own bond, so a Tier 1 node that bonds nothing adds nothing to the tally. Tier 1 also carries no governance vote and no financial slashing exposure — there is no bond to slash. That is what makes open validator admission safe: participation is free, influence is not. Validators secure the Ledger.

- **RPC Provider.** A Tier 3 validator role. Serves public JSON-RPC + REST verification API. Sanctioned to mint scoped tenant API keys (`tenzro_createApiKey`), broker access to operator-held upstream credentials (Canton participants, AI provider keys, data feed subscriptions), and route cross-chain mint/burn flows. Requires ≥ 100,000 TNZO bonded (implies the Tier 2 minimum). Tenzro Labs operates the first RPC Provider at `rpc.tenzro.xyz`.

- **Model Provider.** Serves AI models for inference requests. Bonds **1,000 TNZO**; admission is permissionless above the bond, with no allowlist and no approval step. Earns a 1.1× reward multiplier per TOKENOMICS §9 and per-inference fees (paid in TNZO) settled through micropayment channels. The Network takes a 0.5% commission on provider earnings, which flows to the treasury. Model providers provide **intelligence** to the Network.

- **TEE Provider.** Operates hardware TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs, Intel Tiber) for confidential computation, key management, custody services, and attestation. Bonds **10,000 TNZO** — the second-largest rung on the ladder, reflecting that a false attestation compromises every party relying on it. Earns a 1.2× reward multiplier per TOKENOMICS §9 and fees for TEE services (paid in TNZO). The Network takes a 0.5% commission on provider earnings, which flows to the treasury. TEE providers provide **security** to the Network.

- **Storage Provider.** Stores and serves blockchain state, model weights, and historical data. Bonds **100 TNZO per terabyte pledged**, floored at 100 TNZO, so the bond tracks the capacity it collateralizes. Earns storage fees.

- **Compute Provider.** Rents accelerators for inference, training, and rendering. Bonds **per card by accelerator class** — 500 TNZO integrated, 1,000 consumer, 2,000 workstation, 5,000 datacentre — summed over everything pledged and floored at 500 TNZO. Earns time-based rental revenue.

- **Cloud Operator.** Hosts static sites, WASI HTTP functions, managed databases, and Firecracker machines. Bonds by the **highest service class offered**, each class a superset of the one below: 1,000 TNZO functions, 5,000 databases, 25,000 machines. Earns hosting fees.

- **Training Provider.** Participates in Tenzro Train distributed training runs as a trainer. Bonds **1,000 TNZO**, slashable for withholding training results. Witness committee membership is separate and restricted to Tier 2 staked validators.

- **Media Worker.** Renders Tenzro Media Gen diffusion jobs — image and video generation. **Open entry, no stake required.** Earns per-job fees (paid in TNZO) against the price ceiling the requester posted; the Network takes a 0.5% commission on worker earnings, which flows to the treasury. A worker enrolls the whole models it can hold and, separately, the individual experts of a split model — one half of a timestep-boundary expert pair fits accelerators that cannot hold the full model (§20a.4).

- **Light Client.** Verifies block headers and proofs without storing full state. Suitable for end-user devices.

- **Bootstrap Node.** Initial peer discovery endpoint for new nodes joining the network. Any node can serve this role; in practice the Tenzro Labs validator-0 serves as the canonical bootstrap seed, advertised via DNS (`bootstrap.tenzro.xyz`) and pkarr-relay.

- **Archive Node.** Stores complete historical state for analytics and indexing.

### 2.5 API Surface

The node exposes four API interfaces:

**JSON-RPC Server** (default `0.0.0.0:8545`):
Standard Ethereum-compatible JSON-RPC for transaction submission, state queries, and subscription management. Tenzro-specific methods include `tenzro_createAccount`, `tenzro_createWallet`, `tenzro_registerIdentity`, `tenzro_resolveIdentity`, `tenzro_resolveDidDocument`, and `tenzro_listModels`. The Capital Intent + backing surface adds `tenzro_capitalIntentOpen` / `Quote` / `Assign` / `Execute` / `Verify` / `Settle` / `Compensate`, `tenzro_getCapitalIntent`, and `tenzro_submitReserveAttestation` / `tenzro_attestedMint` / `tenzro_getReserve` (all mirrored as Rust + Python MCP tools, agent SDK methods, and `tenzro capital` CLI subcommands). The Workflow surface adds `tenzro_workflowOpen` / `StepExecute` / `StepVerify` / `StepCompensate` / `Finalize`, the durable reads `tenzro_get{Workflow,WorkflowSaga,WorkflowLifecycle,WorkflowReceipt,WorkflowOperationalMetrics}`, list-by-creator / -participant / -status, `tenzro_mirrorWorkflowToCanton`, and `tenzro_verifyDidEnvelope`. The ERC-7683 origin opener adds `tenzro_open7683Order` alongside the existing read + fill surface. The CAIP discovery surface adds `tenzro_caip2` / `tenzro_caip10` / `tenzro_caip19` returning canonical chain-agnostic identifiers per CASA. The EIP-7702 Type-4 delegation surface adds `tenzro_install7702Delegation` / `tenzro_get7702Delegation` / `tenzro_revoke7702Delegation` for authority → target registry mutations alongside the stateless helpers `tenzro_eip7702SigningHash` / `BuildDesignator` / `ParseDesignator` / `ProtocolInfo`. The Permit2 SignatureTransfer surface adds `tenzro_permit2DomainSeparator` / `tenzro_permit2Digest` (with optional witness binding for ERC-7683) / `tenzro_permit2VerifyAndConsume` / `tenzro_permit2NonceUsed`. The Secure-Mint surface adds `tenzro_setSecureMintPolicy` / `tenzro_getSecureMintPolicy` / `tenzro_clearSecureMintPolicy` / `tenzro_secureMintCheck` / `tenzro_secureMintApply` / `tenzro_secureMintRecordBurn` enforcing `circulating + amount ≤ reserve` for tokenized assets. The Stable-Asset issuance surface adds `tenzro_registerStableAsset` / `tenzro_getStableAsset` / `tenzro_mintStableAsset` / `tenzro_redeemStableAsset` — issuer-agnostic stable-unit policies layered on the Secure-Mint reserve floor, with registration gated by the `issuer` API-key scope. The ERC-7943 (uRWA) tokenized real-world-asset surface adds `tenzro_urwaIsKillSwitched` / `tenzro_urwaGetFrozenTokens` for the kill-switch + per-account freeze read paths backed by the in-EVM precompiles at `0x101a`, `0x101b`, `0x101c` (the four canonical selectors `forcedTransfer(0x33e4e1d3)` / `setFrozenTokens(0x57c52a45)` / `getFrozenTokens(0xe4d8156e)` / `killSwitch(0x1c70d7e6)` are byte-identical to the ERC-7943 reference implementation, so wallets that already speak uRWA dispatch against Tenzro without recompilation). The IVMS101 Travel Rule surface adds `tenzro_ivms101Hash` for binding an originator/beneficiary envelope to a payment receipt via canonical SHA-256 — the envelope itself stays off-chain (typically carried via the TRP open HTTPS protocol the EEA/UK CASP infrastructure standardises on), the receipt records only the binding hash + originating-VASP + beneficiary-VASP DID + asset CAIP-19 + amount-smallest-unit. The TEE-attested clock surface adds `tenzro_attestedClockNow` returning the canonical `AttestedTimestamp` envelope with wall_ms + monotonic_ns + tee_vendor metadata used by long-running workflow deadlines, AP2 mandate expiry, margin-call grace windows, and parametric-insurance trigger evaluation — the monotonic counter detects clock-rollback attacks regardless of any claimed wall_ms drift. The A2A v1.0 SignedAgentCard surface adds `tenzro_signedAgentCardCanonicalHash` so domain owners hash + JWS-sign their agent card (the A2A 2026 conformance bar) and relying parties re-verify the canonical hash to detect a hostile reverse-proxy rewrite of `url` / `skills` / `securitySchemes`. The delivery-versus-payment surface adds `tenzro_dvpOpenSaga` / `tenzro_dvpExecuteSaga` / `tenzro_dvpFinalizeSaga` for coupled multi-leg trades that all complete or all unwind, `tenzro_dvpGetSaga` / `tenzro_dvpListSagasByCreator` for reads, and the multilateral-netting pair `tenzro_nettingCompute` / `tenzro_nettingSettle` (with `tenzro_nettingGetBatch` / `tenzro_nettingListBatches`). The Wormhole NTT (Native Token Transfers) surface adds `tenzro_wormholeNttListChains` listing the registered Wormhole chain IDs + supported Transceiver kinds (Wormhole / Axelar / LayerZero / custom); the `NttInboundAttestation::has_quorum` primitive aggregates Transceiver attestations until the configured quorum is met, deduplicated by transceiver address. The bridge-fee-in-TNZO surface (the Cosmos ICS-29 Fee Middleware / Hyperlane IGP gas-oracle / Polkadot AssetHub asset-conversion pattern adapted for Tenzro) adds `tenzro_quoteBridgeFeeInTnzo` returning a TTL-bounded TNZO quote with monotonic-counter binding for a destination-native fee on any of the six registered bridge adapters, and `tenzro_listBridgeSponsorshipPools` enumerating the deterministic per-adapter sponsorship-pool vault addresses (computed as `SHA-256("tenzro/bridge/sponsorship-vault" || adapter_str)[..20]`) so users see exactly which vault their TNZO sponsorship debits land in. The price-oracle surface adds `tenzro_getPrice`, which takes a single `symbol` or a `symbols` list and returns `prices[]` (each `{symbol, price_usd_8dp, decimals, updated_at, feed_address}` where `price_usd_8dp` is the USD price as an integer scaled by 1e8) plus an `unavailable[]` list for symbols with no live feed — the call requires `bridge.prices.enabled` on the node. The AP2 mandate surface adds `tenzro_listMandates`, which takes a `controller_did` and returns the persisted intent/cart pairs authorized by that controller (each record carrying `mandate_id`, `payment_mandate_id`, the controller/agent/merchant DIDs, `max_amount` + `total_amount` as decimal strings, asset, chain, expiry, the `delegation_enforced` flag, and the stored checkout/payment VDCs).

`tenzro_createWallet` provisions a chain-agnostic 2-of-3 Ed25519 MPC wallet — there is no per-chain parameter. A single wallet projects into EVM, SVM, and Canton via the pointer-token model (§7), so apps do not select a chain at creation time. VM-specific operations are exposed through `tenzro_crossVmTransfer` and `tenzro_wrapTnzo`; transfers to external chains use `tenzro_bridgeTokens` (LayerZero V2), Chainlink CCIP, deBridge DLN, or Wormhole NTT.

Transaction submission goes through `tenzro_signAndSendTransaction` (server-custodial path — server-side MPC signing with live nonce and gas-price lookup; clients pass `from`, `to`, and `value` — `amount` is accepted as an alias) or `eth_sendRawTransaction` (self-custody / pre-signed path — the caller signs both legs locally and supplies `signature` (Ed25519), `public_key` (Ed25519), `pq_signature` (ML-DSA-65), `pq_public_key` (ML-DSA-65 verifying key), and the explicit `timestamp` matching their signed hash). On the raw-send path the node verifies the signing public key derives `from`, then verifies both the Ed25519 and ML-DSA-65 legs against `Transaction::hash()`; a bad signature or a missing leg returns `-32003`. `tenzro_signTransaction` returns `{signature, public_key, timestamp, tx_hash}` for offline submission. `tenzro_getTransaction` returns the transaction with `status: "pending"` while it sits in the consensus mempool and `status: "finalized"` once it has been included in a block, so callers polling immediately after broadcast distinguish "not yet finalized" from "unknown hash." Self-sends (`from == to`) are rejected with a `cannot transfer to self` validation error.

**Web Verification API** (default `0.0.0.0:8080`):

| Endpoint | Purpose |
|----------|---------|
| `POST /verify/zk-proof` | Verify a zero-knowledge proof |
| `POST /verify/tee-attestation` | Verify a TEE attestation report |
| `POST /verify/transaction` | Verify a transaction signature |
| `POST /verify/settlement` | Verify a settlement receipt |
| `POST /verify/inference` | Verify an inference result against its proof |
| `GET /verify/health` | Health check |
| `GET /health` | Health check (alias) |
| `GET /status` | Node status and metrics |
| `POST /faucet` | Request testnet TNZO tokens |
| `POST /facilitator/visa-tap/verify` | Recognize a signed agent request per Visa TAP (RFC 9421) |
| `GET /facilitator/visa-tap/supported` | Advertise the recognized signature format, domain, and agent tags |
| `POST /facilitator/x402/verify` | Verify an x402 payment payload against its requirements |
| `POST /facilitator/x402/settle` | Settle a verified x402 payment (operator's own EVM relayer for external-chain EIP-3009 / Permit2, or the consensus-mediated leg for native TNZO) |
| `GET /facilitator/x402/supported` | Advertise the x402 schemes and chains this facilitator settles |

**MCP Server** (default `0.0.0.0:3001`):
Model Context Protocol server using the `rmcp` crate with Streamable HTTP transport (protocol version `2025-11-25`). Exposes 526 tools spanning wallet, identity, payments (AP2 sign + verify, ERC-8004 v0.6+, Stripe SPT), inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), staking, tokens, NFTs, bridges, verification, agents, tasks, skills, tools, compliance, TEE, ZK, VRF, and event subscriptions, that any AI agent (Claude, GPT, etc.) can invoke. Representative groups:

| Group | Example Tools |
|-------|---------------|
| Wallet & Ledger | `get_balance`, `send_transaction`, `create_wallet`, `request_faucet` |
| Network & Blocks | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did`, `set_delegation_scope` |
| Payments | `create_payment_challenge`, `verify_payment`, `list_payment_protocols` |
| AI Models & Inference | `list_models`, `chat_completion`, `list_model_endpoints` |
| Cross-Chain Bridge | `bridge_tokens`, `get_bridge_routes`, `list_bridge_adapters` |
| Verification | `verify_zk_proof`, `verify_vrf_proof`, `generate_vrf_proof` |
| Staking & Providers | `stake_tokens`, `unstake_tokens`, `register_provider`, `get_provider_stats` |
| Tokens & Contracts | `create_token`, `deploy_contract`, `cross_vm_transfer`, `wrap_tnzo` |

Six additional MCP servers run alongside the main Tenzro server for ecosystem interaction: Solana (port 3003, 14 tools), Ethereum (port 3004, 17 tools), Canton (port 3005, 23 tools), LayerZero (port 3006, 21 tools), Chainlink (port 3007, 21 tools), and Li.Fi (port 3008, 9 tools).

**A2A Protocol Server** (default `0.0.0.0:3002`):
Agent-to-Agent protocol server implementing the Google A2A specification with JSON-RPC 2.0:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/agent.json` | Agent Card discovery (per A2A spec) |
| `POST /a2a` | JSON-RPC 2.0 dispatcher for task management |
| `POST /a2a/stream` | SSE streaming for real-time task updates |

JSON-RPC methods: `message/send`, `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel`. The Agent Card advertises 40 skills: `wallet`, `identity`, `inference`, `settlement`, `workflow-coordination`, `verification`, `staking`, `task_marketplace`, `agent_marketplace`, `agent_spawning`, `swarm_orchestration`, `token`, `contract`, `ap2-payments`, `join`, `nft`, `bridge`, `compliance`, `crosschain`, `events`, `erc8004`, `wormhole`, `cct`, `cortex`, `capability_registry`, `adaptive-burn`, `seed-agent`, `erc7683`, `iroh-transport`, `urwa`, `ivms101`, `attested-clock`, `signed-agent-card`, `wormhole-ntt`, `bridge-fee-in-tnzo`, `storage`, `compute`, `moe`, `media-gen`, `discovery`. Supports streaming responses via Server-Sent Events and multi-turn conversation history.

The Python distributable at `integrations/a2a/` publishes its own card with a wider skill set (70), including the per-modality inference skills (`forecast`, `vision-embed`, `text-embed`, `segmentation`, `text-segmentation`, `detection`, `audio-transcribe`, `video-embed`), `lifecycle`, `bond-insurance`, `auth`, `approval`, `agent-memory`, and `operability`. The two cards front the same JSON-RPC surface; the Python card groups it more finely.

---

## 3. Consensus: HotStuff-2 BFT

### 3.1 Overview

The Tenzro Ledger employs HotStuff-2, a leader-based Byzantine Fault Tolerant consensus protocol with linear message complexity. HotStuff-2 achieves consensus in two phases (as opposed to the three phases of original HotStuff), reducing latency while maintaining safety under partial synchrony. This consensus mechanism secures Tenzro Ledger.

### 3.2 Protocol Parameters

| Parameter | Default Value | Description |
|-----------|--------------|-------------|
| Block time | 400 ms | Target time between blocks |
| Max block size | 2 MB | Maximum serialized block size |
| Max transactions per block | 10,000 | Upper bound on transaction count |
| Max gas per block | 30,000,000 | Gas limit per block |
| View timeout | 2,000 ms | Timeout before view change |
| Min validators | 4 | Minimum validator set size |
| Epoch duration | 10,000 blocks | Blocks per epoch (~67 minutes at 400ms) |
| Mempool size limit | 100,000 | Maximum pending transactions |
| Transaction TTL | 600 seconds | Time-to-live for unconfirmed transactions |

### 3.3 Two-Phase Commit

The protocol proceeds in views, each led by a designated leader:

1. **PREPARE.** The leader proposes a block containing transactions selected from the mempool. Validators verify the block's validity and send signed prepare votes to the leader.

2. **COMMIT.** Upon collecting a quorum of prepare votes (2f+1 where f = floor((n-1)/3)), the leader forms a prepare certificate and broadcasts a commit message. Validators verify the certificate and send commit votes.

3. **DECIDE.** Upon collecting a quorum of commit votes, the leader forms a commit certificate. The block is finalized and appended to the chain. All validators execute the block's transactions and update state.

The quorum threshold follows classic BFT: for n validators, the protocol tolerates f = floor((n-1)/3) Byzantine faults, requiring 2f+1 votes for any decision. With 4 validators, this means 3 votes (tolerating 1 fault); with 7 validators, 5 votes (tolerating 2 faults); with 10 validators, 7 votes (tolerating 3 faults).

### 3.4 Optimistic Responsiveness

When `optimistic_responsiveness` is enabled (default), the protocol advances at network speed rather than waiting for fixed timeouts. If a quorum of honest validators respond before the view timeout, the protocol proceeds immediately. This allows block times below the configured 400ms target under favorable network conditions.

### 3.4a Three-Tier Validator Model

Validator participation follows a three-tier model. All three tiers run the same HotStuff-2 protocol and sign the same hybrid Ed25519 + ML-DSA-65 + BLS12-381 QCs; what differs is the block classes they're eligible to propose, their governance voting weight, their slashing exposure, and (Tier 3 only) their sanction to mint scoped tenant API keys.

**Tier 1 — Resource-only validator.** Open entry, no stake required. Eligibility is based on hardware profile (CPU, RAM, disk, bandwidth, IOPS thresholds), stability profile (probation uptime, no equivocation history, no slashed peers in operator history), optional TEE attestation, and geographic/network/jurisdictional diversity bonus. Earns priority fees on proposed blocks plus a base reward share (reputation-weighted, capped at base multiplier). No independent governance voting weight. **No financial slashing exposure** — misbehavior results in ejection from the set plus reputation collapse, but cannot be slashed because there is no bond. Excluded from leader election for high-trust block classes.

**Tier 2 — Staked validator.** Tier 1 eligibility plus ≥ 10,000 TNZO bonded self-stake. Earns priority fees + base + Tier 2 multiplier (up to 2× base) + stake-weighted share of commission. **Stake-weighted governance voting.** Slashing: 10% bond burn on equivocation; additional slashing on invalid TEE attestations, withholding training results, persistent SLA failures. Eligible for all block classes including high-trust. Eligible for high-trust roles: witness committee membership for training round finalization, high-value bridge node duties (Hyperlane ISM, Wormhole Guardian participation, threshold MPC bridge signer), AP2 high-value mandate validation, institutional Canton route operator.

**Tier 3 — RPC provider.** Tier 2 eligibility plus ≥ 100,000 TNZO bonded (implies the Tier 2 minimum — effective bond is 100k total, not 110k). Tier 3 implies Tier 2. Additionally **sanctioned to mint scoped tenant API keys** via `tenzro_createApiKey`, serve public JSON-RPC + REST verification API, broker tenant access to operator-held upstream credentials (Canton participants, AI provider keys, data feed subscriptions, banking rails), and route cross-chain mint/burn flows. Tier 3 earnings: Tier 2 earnings + tenant access fees + per-call fees + commission on routed flow. Tier 3 slashing: Tier 2 conditions + censoring tenant transactions, frontrunning, mishandled tenant secrets, billing fraud, persistent SLA failures.

Tier transitions are upgrades-only forward (1→2→3 by bonding more stake) or downgrades on stake withdrawal (3→2 below 100k while staying above 10k; 2→1 below 10k; 1→exit). All transitions take effect at the next epoch boundary. The TEE 1.5× multiplier on the leader-election draw applies to all three tiers.

Tenzro Labs operates the first Tier 3 RPC provider as validator-0 — the genesis seed bootstrap peer plus public RPC at `rpc.tenzro.xyz`. Tenzro Labs is the first Tier 3, not architecturally privileged; any other operator that bonds 100k can register their own Tier 3 endpoint, mint their own tenant API keys, and front their own upstream credential vault with the same protocol guarantees.

### 3.5 Reputation-Weighted Proposer Election

Tenzro's default proposer-election strategy is reputation-weighted. Each round draws the leader from a stake-weighted seeded distribution where per-validator weight is multiplied by an observed-behaviour tier and a TEE multiplier:

```
weight(v) = stake(v) × tier(v) × tee_multiplier(v) / 10000

tier(v):
  ACTIVE   = 1000   if v proposed ≥1 QC-certified block recently
                     and failed <10% of its proposer-window rounds
  INACTIVE = 10     if v voted but didn't propose
  FAILED   = 1      otherwise

tee_multiplier(v):
  15000 (1.5×) if v has a fresh valid TEE attestation in the current epoch
  10000 (1.0×) otherwise
```

The 1000× spread between ACTIVE and FAILED collapses a chronically-flaky validator's effective draw probability to ~0.1% within ~20 rounds. The leader-draw seed is anti-grinding (`SHA-256("TENZRO_LEADER_REPUTATION:" || epoch || round || prev_finalized_block_id)`), with `prev_finalized_block_id` fixed at least one full QC ago and the proposer-history window excluding the most recent 20 rounds. `ProposerElectionKind::RoundRobin` is retained for tests and replay benchmarks. A VRF primitive (ECVRF-EDWARDS25519-SHA512-TAI per RFC 9381 §5.4.1.1) is exposed to applications through EVM precompile `0x1007`, the NFT factory's `mintRandom` entry point, and the `tenzro_generateVrfProof` / `tenzro_verifyVrfProof` JSON-RPC methods.

### 3.6 No-Endorsement Certificates (Tail-Fork Resistance)

Tenzro closes the tail-fork attack class on 2-chain HotStuff with no-endorsement certificates (NECs). The leader at view *v* must either re-propose the high-tip from view *v−1*, or attach a valid NEC for view *v*. A NEC is an *f+1* aggregation of `NoEndorsementMsg`s, each attesting "I observed no QC at view v−1". *f+1* (not *2f+1*) is the correct threshold: with at most *f* Byzantine signers, *f+1* suffices to guarantee at least one truthful "no QC observed" attestation. Domain tag `TENZRO_NO_ENDORSEMENT:` distinct from the timeout and vote tags prevents cross-message replay. Full protocol specification with formal arguments and academic citations: [`docs/papers/tenzro-consensus.md`](papers/tenzro-consensus.md).

### 3.6.1 TEE-Weighted Validation

The TEE multiplier described above (1.5× on the reputation-adjusted weight) makes hardware-secured participation the economically rational default while never gating liveness. TEE attestations are verified at epoch boundaries when the validator set is reconstituted.

### 3.7 Epoch Management

The validator set is fixed within an epoch (default 10,000 blocks). At epoch boundaries:

1. Pending validator additions and removals are processed.
2. TEE attestations are re-verified for all validators.
3. The new validator set is committed to state.
4. Staking rewards for the completed epoch are calculated and distributed.
5. The epoch history (validator set, total stake, block range) is recorded.

### 3.7a Validator Lifecycle Primitives

Validators upgrade, rotate keys, and self-bootstrap without coordinated downtime. Four primitives, each independently composable:

**Chain compatibility check (`verify_chain_compat`).** On boot, the node compares the configured genesis (`chain_id` + computed `genesis_state_root`) against values persisted under `CF_METADATA`. Identical genesis resumes against the existing DB; drift fails loud with an actionable error. This is what allows in-place binary upgrades to preserve consensus history.

**Bootstrap discovery via DNS (`--bootstrap-dns`).** `_tenzro-boot._tcp.<zone>` SRV records advertise the active boot set; paired `_tenzro-id._tcp.<target>` TXT records carry libp2p peer IDs. Rotating a boot validator's identity is a zone edit, not a fleet-wide wrapper update. The pkarr relay handles iroh `EndpointId` resolution separately; the two surfaces are independent.

**Consensus key rotation (`tenzro_rotateValidatorKey`).** The validator proves ownership of the existing keys by signing the rotation payload under the *current* Ed25519 consensus key. The canonical preimage is `SHA-256("tenzro/rotate-validator-key" || address(32) || new_consensus(32) || new_pq(1952) || new_bls(48) || nonce_le(8))`. On the receiving node, `ValidatorRegistry::rotate_keys` updates the persisted entry in place and `EpochManager::add_pending_validator` upserts the new `ValidatorInfo`; the swap is atomic at the next epoch boundary with no split-key window. Cross-node propagation is operator-driven via a fan-out script until the consensus-mediated `RotateValidatorKey` typed transaction exists (post-mainnet roadmap).

**Snapshot-based auto-catchup.** Fresh validators with an empty data dir, `--bootstrap-dns` set, and a `[weak_subjectivity]` block in genesis auto-derive `state_sync_peer` from the first usable bootstrap multiaddr and `state_sync_anchor` from `weak_subjectivity.state_root_hex`. The existing `bootstrap_from_peer` flow then fetches snapshots, verifies the manifest's declared `state_root` bit-for-bit against the anchor, commits atomically, and tail-replays via gossipsub. Explicit `--state-sync-from` + `--state-sync-anchor` continue to take precedence when provided.

### 3.8 Finality

Blocks achieve finality when they receive a commit certificate (2f+1 commit votes). The `FinalityTracker` enforces sequential finalization — blocks must be finalized in height order. Once finalized, a block cannot be reverted. The finality tracker also supports fork choice: when multiple candidate blocks exist at the same height, the one with the most accumulated votes is selected.

---

## 4. Multi-VM Execution Layer

### 4.1 Architecture

The Tenzro Ledger's execution layer supports three virtual machines through a unified `MultiVmRuntime` that routes transactions to the appropriate executor based on the transaction's `VmType`:

- **EVM (Ethereum Virtual Machine).** Full EVM-compatible execution for Solidity and Vyper smart contracts.
- **SVM (Solana Virtual Machine).** Solana-compatible execution for programs written in Rust targeting the BPF instruction set.
- **Daml (Digital Asset Modeling Language).** Enterprise smart contract execution powered by Canton Network. Each Tenzro validator runs a Canton participant node natively, connecting to one or more Canton synchronizers (the Canton 3.5+ term for domains). Self-hosted participants expose the Ledger API on gRPC (port 5001 — `CommandService.SubmitAndWait`, `StateService.GetActiveContracts`, `UpdateService.GetUpdates`) and the Admin API on gRPC (port 5002 — `PackageService.UploadDar`). An operator may instead front its participant with the Canton 3.5+ JSON Ledger API v2 (`POST /v2/commands/submit-and-wait-for-transaction`, `POST /v2/state/active-contracts`, `POST /v2/packages`), gated by OAuth2 client credentials. External builders do not dial that participant directly: they present a Canton-scoped API key to the operator's node, the node resolves the key to a Canton user and mints the participant JWT server-side. A builder can therefore transact on Canton without running a participant and without ever holding participant credentials. Canton handles Daml contract lifecycle, sub-transaction privacy (parties only see events for contracts where they are stakeholders), and multi-synchronizer coordination through the Global Synchronizer. From the developer's perspective, Daml transactions are initiated through the same multi-VM interface as EVM and SVM calls.

#### 4.1.1 Why three VMs — and why this is not redundant

A reasonable objection to multi-VM L1s is that exposing several execution environments duplicates surface area without adding capability: every VM can already express any computable function, so a second VM only fragments tooling. That objection holds when the VMs target the same ecosystem — running two EVM dialects, or an EVM next to a re-implemented EVM, multiplies maintenance cost and developer confusion without enlarging the addressable application set.

Tenzro's three VMs are **complementary, not redundant**. Each anchors an ecosystem that the other two cannot import:

- **EVM** is the lingua franca of permissionless DeFi: ERC-20 / ERC-721 / ERC-4626 / ERC-4337 standards, Solidity tooling, Hardhat / Foundry / Remix, the audit ecosystem, billions of dollars of stablecoins denominated as ERC-20 contracts. A chain that wants to integrate with that liquidity must speak EVM bytecode, not "an EVM-compatible API."
- **SVM** is the only execution environment where high-throughput, parallel, account-isolated programs run today: Solana's program ecosystem (Jupiter, Pyth, Marinade, MagicEden, Drift, Phoenix) is written against `solana_program` and the SPL standard. Running these programs requires the actual BPF instruction set, the Solana account model, and SPL Token Program semantics — not a transpilation. SVM also gives Tenzro access to the parallel-execution scaling story for AI agent workloads where most transactions touch disjoint state.
- **Daml** (running on Canton) is the execution environment institutions are converging on for regulated assets — sub-transaction privacy, party-based authorization, atomic multi-domain settlement, and a six-year-plus production track record across global investment banks, market utilities, regional exchanges, and central-bank RTGS proofs-of-concept. No EVM-based privacy solution offers Daml's combination of privacy, finality, and regulatory acceptance for tokenized real-world assets.

The integration is unified: all three VMs read and write the same canonical TNZO balance through the pointer model (§4.9), share the same precompile-exposed primitives (TEE attestation, ZK verification, model inference, settlement), and dispatch through the same `MultiVmRuntime`. A single transaction can move TNZO from an EVM DeFi position into a Daml DvP settlement against a tokenized treasury, with the SVM side providing oracle inputs — without bridge risk, wrapping fees, or liquidity fragmentation.

Sei Network's April 2026 pivot to EVM-only — abandoning its earlier multi-VM ambitions — illustrates the alternative outcome: two redundant EVM-compatible surfaces (a CosmWasm dialect and an EVM) on a single chain proved to be developer-confusing and economically dominated by one side. Tenzro's three VMs avoid that failure mode because each ecosystem is genuinely non-substitutable: a DeFi protocol cannot be ported to Daml without losing its market, a Solana program cannot be ported to EVM without losing its parallelism guarantees, and a regulated-asset issuer cannot adopt EVM without losing privacy and party-based authorization. The complementarity is the point.

### 4.2 Execution Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Max gas limit | 30,000,000 | Maximum gas per transaction |
| Default gas limit | 10,000,000 | Default gas if unspecified |
| Min gas price | 1 Gwei (10^9 wei) | Minimum gas price |
| Max contract size | 24,576 bytes | EIP-170 contract size limit |
| Chain ID | 1337 | Tenzro Ledger chain identifier (live testnet) |
| Max call depth | 1,024 | Maximum nested call depth |

### 4.3 Precompile Registry

The VM provides precompiled contracts that expose native platform functionality to smart contracts:

- **TEE Precompile.** Verify TEE attestations, request enclave execution, and query TEE provider status.
- **ZK Precompile.** O(1) HashSet lookup against `ZkCommitmentRegistry`. Validators verify Plonky3 STARK proofs off-EVM and admit a 32-byte SHA-256 commitment only under a `2f+1` stake-weight quorum certificate (each co-signer re-verifies), then hold it challengeable for a fraud window; the precompile rejects unknown commitments.
- **Model Precompile.** Query the model registry, submit inference requests, and verify inference results.
- **Settlement Precompile.** Create escrows, open micropayment channels, and trigger settlement operations.

### 4.4 State Management

The `StateAdapter` provides a unified interface for VM executors to read and write state:

- **Account balances.** `get_balance(address)`, `set_balance(address, amount)`
- **Account nonces.** `get_nonce(address)`, `set_nonce(address, nonce)`
- **Contract storage.** `get_storage(address, key)`, `set_storage(address, key, value)`
- **Contract code.** `get_code(address)`, `set_code(address, bytecode)`
- **Transactional state.** `commit()` and `rollback()` for atomic state transitions.

### 4.5 Gas Oracle

The gas oracle provides gas price estimation based on recent block utilization. The `GasEstimator` analyzes the last N blocks to suggest gas prices at different priority levels (slow, standard, fast).

### 4.6 EIP-1559 Dynamic Fee Market

The Tenzro Ledger implements a full EIP-1559 fee market with dynamic base fee adjustment:

| Parameter | Value |
|-----------|-------|
| Target gas per block | 15,000,000 |
| Min base fee | 0.1 Gwei |
| Max base fee | 1,000 Gwei |
| Adjustment rate | ±12.5% per block |

**Mechanism:** The base fee adjusts up when blocks are above the target gas utilization and down when below. Base fee is burned (removed from circulation), creating deflationary pressure proportional to network usage. Users specify a `max_fee_per_gas` and `max_priority_fee_per_gas`; the priority fee goes to the block producer. The `FeeMarket` provides fee suggestions by urgency level (low, medium, high).

### 4.7 Block-STM Parallel Execution

The `BlockStmExecutor` implements optimistic parallel transaction execution using Software Transactional Memory:

- **MVCC (Multi-Version Concurrency Control):** Each transaction reads and writes to versioned state. Conflicts are detected by comparing read sets against concurrent write sets.
- **Conflict detection and re-execution:** When a conflict is detected, the conflicting transaction is re-executed with updated state. A configurable maximum re-execution count (default: 16) prevents infinite loops.
- **Automatic sequential fallback:** If the conflict rate exceeds 50%, the executor falls back to sequential execution for the remainder of the block, avoiding the overhead of repeated re-executions.
- **Metrics:** The executor tracks parallelism ratio, conflict count, re-execution count, and sequential fallback events.

### 4.8 Account Abstraction (ERC-4337 v0.8)

The Ledger implements ERC-4337 v0.8 account abstraction, enabling smart contract wallets. The v0.8 format carries deployment as `factory`/`factoryData` and sponsorship as `paymaster`/`paymasterVerificationGasLimit`/`paymasterPostOpGasLimit`/`paymasterData`, with PackedUserOperation support, EIP-712 typed data hashing, and a gas penalty threshold of 40,000:

- **EntryPoint contract.** Central singleton that validates and executes `UserOperation` bundles (max bundle size: 100).
- **SmartAccount.** Contract wallets with pluggable modules:
  - `SocialRecovery` — Multi-guardian key recovery
  - `SessionKey` — Time-limited session keys for dApps
  - `SpendingLimit` — Per-token/per-period spending caps
  - `Batching` — Atomic multi-call execution
- **AccountFactory.** Deterministic CREATE2 deployment of smart accounts from a salt and owner address.
- **Paymaster.** Gas sponsorship — third parties can pay gas on behalf of users, enabling gasless transactions.

### 4.8a EIP-7702 Type-4 Delegation

Tenzro implements EIP-7702 (Pectra, May 2025) as a protocol-level primitive in `tenzro-vm::eip7702`:

- **Signed authorization.** `Eip7702Authorization { chain_id, delegate_address, nonce, signature }` with preimage `MAGIC(0x05) || rlp([chain_id, address, nonce])` and recoverable secp256k1 `(r, s, y_parity)`. `chain_id == 0` is the cross-chain wildcard per the spec.
- **Delegation registry.** `DelegationRegistry::install(auth, expected_authority, current_chain_id, current_nonce)` recovers the authority via `recover_eoa_from_7702_signature`, verifies `(chain_id, nonce, authority)`, and records the authority → target pointer. `delegate_address == 0x0` revokes any active delegation.
- **Designator encoding.** The EIP-7702 23-byte `0xef0100 || target_address(20)` designator is detected by `is_delegation_designator` / `extract_delegation_target`; the EVM executor consults `resolve_target(account)` on a designator hit and runs the target's code in the authority's storage context.
- **RPC surface.** `tenzro_install7702Delegation`, `tenzro_get7702Delegation`, `tenzro_revoke7702Delegation`.

### 4.8b Permit2 SignatureTransfer

Tenzro implements Permit2 (Uniswap canonical) as a protocol-level primitive in `tenzro-vm::permit2`:

- **Typed data.** `TokenPermissions { token, amount }`, `PermitTransferFrom { permitted, spender, nonce, deadline }`, and `PermitTransferFromWitness { …, witness, witness_type_name, witness_type_string }` with deterministic typehashes per the spec; the witness path embeds the witness type-string inline so EIP-712 verifiers see the full struct shape.
- **Domain separator.** `domain_separator(chain_id, verifying_contract)` against the Tenzro canonical Permit2 address `0x0000…00001023`.
- **Nonce bitmap.** `Permit2NonceBitmap` matches Uniswap's word/bit layout (`nonce[..31]` is the word position, `nonce[31]` the bit position) so users can sign permits in parallel.
- **Witness path.** When an ERC-7683 origin opener wants gasless transfer-of-input, the witness is the order id and the signing flow folds together token-pull authorization and intent-signature into a single signature.
- **RPC surface.** `tenzro_permit2DomainSeparator`, `tenzro_permit2Digest`, `tenzro_permit2VerifyAndConsume`, `tenzro_permit2NonceUsed`.

### 4.8c Secure-Mint Registry

Tenzro implements the 1:1 reserve-attestation invariant for tokenized assets in `tenzro-vm::secure_mint`:

- **`SecureMintPolicy { asset_id, reserve, circulating, por_feed_id, attester_did, attestation_hash, attested_at, ttl_secs }`** — per-token policy. Tokens without a policy are unaffected.
- **`check_and_mint(token, amount, now)`** — atomic invariant `circulating + amount ≤ reserve` plus attestation-freshness check (`now − attested_at ≤ ttl_secs`).
- **`would_mint_succeed`** — read-only check.
- **`record_burn`** — saturating decrement on redemption.
- **`TokenizedEquityProfile`** — sidecar carrying CCT pool address, underlying CAIP-19, ISIN, CUSIP, per-share ratio (numerator, denominator), and the latest corporate-action event hash. Used by the unified token registry for tokenized-equity-class assets.
- **RPC surface.** `tenzro_setSecureMintPolicy`, `tenzro_getSecureMintPolicy`, `tenzro_clearSecureMintPolicy`, `tenzro_secureMintCheck`, `tenzro_secureMintApply`, `tenzro_secureMintRecordBurn`. EVM precompile slot reserved at `0x0000…00001024`.

### 4.8d Stable-Asset Issuance

Issuer-agnostic stable-unit issuance layered on the Secure-Mint reserve floor (`tenzro-vm::stable_controller` + the issuance registry). Tenzro provides the primitives; any issuer can register a unit and run it.

- **`StableAssetPolicy { issuer, unit_token, symbol, reserve_source, por_feed_id, allowed_rails, settlement_dst }`** — per-`(issuer, unit_token)` policy. `reserve_source` is either `{ kind: custodial, attester_did, asset_caip19 }` or `{ kind: on_chain_vault, vault, asset_caip19 }`.
- **Reserve floor.** Every mint is hard-gated by the Secure-Mint invariant installed on the same `unit_token`: a mint that would push circulating above the attested reserve is rejected. The stable-asset layer never relaxes that floor — it only governs issuance policy on top of it.
- **Issuer authorization.** `tenzro_registerStableAsset` requires an API key carrying the `issuer` scope; the read and mint/redeem paths follow the policy installed at registration.
- **Settlement rails.** `allowed_rails` is a closed set: `x402`, `ap2`, `mpp`, `visa_tap`, `mastercard`, `tempo`, `open_standard`, `native`. The `open_standard` rail covers consortium-governed units (e.g. OUSD); the unit settled is carried by the reserve `asset_caip19`, not the rail tag, so any Open Standard asset reuses the same rail.
- **Issuance controls.** Beyond the static reserve floor, a Secure-Mint policy carries operational guards: `heartbeat_secs` gates mint on a *live* proof-of-reserve attestation (distinct from `ttl_secs` staleness), `mint_window_cap` / `mint_window_secs` bound issuance velocity over a rolling window, and per-token (`paused`) plus global circuit breakers halt mint without clearing the policy. The mint path is fail-closed: any unverifiable condition rejects.
- **RPC surface.** `tenzro_registerStableAsset`, `tenzro_getStableAsset`, `tenzro_mintStableAsset`, `tenzro_redeemStableAsset`; Secure-Mint admin: `tenzro_setSecureMintPolicy`, `tenzro_getSecureMintPolicy`, `tenzro_clearSecureMintPolicy`, `tenzro_secureMintCheck`, `tenzro_secureMintApply`, `tenzro_secureMintRecordBurn`, `tenzro_setSecureMintPaused`, `tenzro_setGlobalIssuancePause` (the last four admin-token gated) — all mirrored as Rust + Python MCP tools, Rust + TypeScript SDK methods, A2A skills, and `tenzro stable-asset` / `tenzro secure-mint` CLI subcommands.

### 4.9 Cross-VM Token Architecture

The Tenzro Ledger implements a **Sei V2 pointer model** for cross-VM token representation. Instead of bridging or wrapping tokens between VMs (which introduces bridge risk and fragments liquidity), all VM representations point to the same underlying native balance managed by the `TnzoToken` layer. There is no lock-and-mint bridge — every VM surface reads and writes the same canonical balance.

**Architecture:**

```
                         ┌─────────────────┐
                         │   TnzoToken     │
                         │ (Native Balance) │
                         └───────┬─────────┘
                    ┌────────────┼────────────┐
                    │            │            │
              ┌─────▼─────┐ ┌───▼───┐ ┌──────▼──────┐
              │ wTNZO     │ │ wTNZO │ │ TNZO        │
              │ ERC-20    │ │ SPL   │ │ CIP-56      │
              │ Pointer   │ │Adapter│ │ Holding     │
              │ (EVM)     │ │ (SVM) │ │ (Canton)    │
              └───────────┘ └───────┘ └─────────────┘
```

**VM Representations:**

| VM | Representation | Decimals | Mechanism |
|----|---------------|----------|-----------|
| EVM | wTNZO ERC-20 pointer contract | 18 | Standard ERC-20 interface with approval storage; reads/writes native balance |
| SVM | wTNZO SPL token adapter | 9 | Maps SPL Token Program instructions to native TnzoToken; 9-decimal truncation (18 to 9); ATA derivation for associated token accounts |
| Canton | TNZO CIP-56 holding template | 18 (DAML Decimal) | Two-step transfer flow (create then accept/reject); party-to-address mapping; DAML Decimal string formatting |

**Decimal Conversion (SVM):**

Solana's SPL Token standard uses 9 decimals while TNZO uses 18. The SPL adapter performs deterministic truncation: the lower 9 decimal digits are dropped on deposit into SVM and zero-padded on withdrawal back to native. This means the smallest representable unit in SVM is 10^9 wei (1 Gwei-equivalent), which is sufficient for all practical token operations.

**Tenzro-Specific Precompile Addresses:**

In addition to the 9 standard EVM precompiles (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, BN254 EC operations, BLAKE2F) and 7 BLS12-381 precompiles (EIP-2537: G1ADD, G1MSM, G2ADD, G2MSM, PAIRING_CHECK, MAP_FP_TO_G1, MAP_FP2_TO_G2 at 0x0a-0x10 using the `blst` library), the VM exposes Tenzro-specific precompiles:

| Address | Precompile | Description |
|---------|-----------|-------------|
| `0x1001` | TNZO_BRIDGE | Cross-VM token transfers between EVM, SVM, and Canton |
| `0x1002` | TOKEN_FACTORY | Create and register new ERC-20 tokens in the unified registry |
| `0x1003` | CROSS_VM_BRIDGE | Atomic cross-VM token movement with balance verification |
| `0x1004` | STAKING | Stake/unstake TNZO and query staking state from smart contracts |
| `0x1005` | GOVERNANCE | Submit proposals and cast votes from smart contracts |

**Unified Token Registry:**

All tokens — native TNZO, user-created ERC-20s, SPL tokens, and CIP-56 holdings — are indexed in a single `DashMap`-backed `TokenRegistry` with RocksDB persistence (column family `CF_TOKENS`). Each token entry records its `TokenId` (deterministic SHA-256 of creator address and nonce), creator, symbol, decimals, total supply, and the set of VMs where it has pointer contracts deployed. This eliminates the fragmented token tracking that plagues multi-chain ecosystems.

**Token Factory:**

The `TOKEN_FACTORY` precompile at address `0x1002` enables any smart contract or user to create new tokens on the Tenzro Ledger. Created tokens are automatically registered in the unified token registry and can be deployed as pointer contracts across all three VMs. This enables ecosystem token creation (e.g., governance tokens for DAOs, reward tokens for applications) without requiring separate deployment and registration steps per VM.

### 4.9.1 Cross-VM Atomicity Invariant

The unified-balance design above produces a sharper guarantee than the multi-VM systems that wrap tokens or run separate keepers per VM. Concretely, for any block `B = [tx_1, …, tx_m]` containing a mix of EVM, SVM, and Daml transactions that touch shared TNZO balances, the post-block state is identical to the result of applying `tx_1, …, tx_m` sequentially against a single shared state tree. Each transaction either commits all of its state changes (across every VM it touches via the cross-VM bridge precompile `0x1003`) or reverts all of them. No intermediate state in which a balance has been debited on one VM but not credited on another is observable to any subsequent transaction or external reader.

In formal terms, block execution is **opaque (in the STM sense) and serializable**, with snapshot/rollback at the per-transaction boundary. The proof is one line: the dispatcher takes a snapshot of the shared state tree before every `Executor::execute(state, tx)` call and reverts to the snapshot if the receipt is a failure. Because the `TnzoToken` layer is the *only* shared resource across VMs, no side effects can leak between executors. This eliminates an entire class of bridge-style failure modes — there is no lock-mint-burn-release cycle, no multi-signature committee, and no optimistic challenge period — because there is no bridge.

When two transactions in the same block target the same balance from different VMs (for example, an EVM `transfer` via the wTNZO ERC-20 pointer and an SVM SPL transfer over the same source account), the conservative scheduler places them in different sequential batches: the write set of any cross-VM balance touch is statically determinable from the typed-transaction payload, so concurrent writes to the same balance are detected before parallel execution. The second transaction observes the post-image of the first; the conservation invariant `Σ balances_pre = Σ balances_post` holds for every block; and the three VM-native views (`balance(addr) via EVM == balance(addr) via SVM == balance(addr) via Daml`) agree post-block.

**References.** This is the standard cross-VM conservation invariant for a multi-VM ledger with shared identity and token state, together with the Block-STM deterministic-conflict-detection property. The same property is exercised across the full commit path in `crates/tenzro-vm/tests/cross_vm_atomicity.rs`.

---

## 5. Trusted Execution Environments

### 5.1 Overview

Tenzro supports hardware-based confidential computation through four TEE technologies:

| TEE | Provider | Use Case |
|-----|----------|----------|
| Intel TDX | `IntelTdxProvider` | Trust Domain Extensions for VM-level isolation |
| AMD SEV-SNP | `AmdSevSnpProvider` | Secure Encrypted Virtualization with Secure Nested Paging |
| AWS Nitro | `AwsNitroProvider` | AWS Nitro Enclaves for cloud-based isolation |
| NVIDIA GPU | `NvidiaGpuProvider` | NVIDIA Confidential Computing for GPU-accelerated AI workloads |

Each provider is gated behind a cargo feature flag (`intel-tdx`, `amd-sev-snp`, `aws-nitro`, `nvidia-gpu`) and implements a common `TeeProvider` trait.

### 5.6 NVIDIA GPU Confidential Computing

The `NvidiaGpuProvider` enables confidential AI inference on NVIDIA GPUs with hardware-rooted trust:

- **Supported architectures:** Hopper (H100/H200), Blackwell (B100/B200), and Ada Lovelace (L40S)
- **NRAS attestation:** Attestation reports are validated against the NVIDIA Remote Attestation Service (NRAS), with a maximum report age of 24 hours
- **GPU capabilities:** Each GPU reports its architecture, VRAM capacity, compute capability version, and driver version
- **Confidential inference:** Model weights and inputs remain encrypted in GPU memory; only the TEE enclave can access plaintext data

This is particularly important for Tenzro's AI model marketplace, where model providers can serve inference inside GPU TEEs, proving to consumers that their data and the model weights were processed confidentially.

### 5.2 Automatic Detection

The `detect_tee()` function probes the system for available TEE hardware in priority order: Intel TDX first, then AMD SEV-SNP, then AWS Nitro. The first available TEE is returned. Operators can also request a specific TEE via `detect_specific_tee(vendor)`.

### 5.3 Attestation

TEE attestation provides cryptographic evidence that code is running inside a genuine hardware enclave:

```
AttestationReport {
    vendor:       TeeVendor,           // IntelTdx | AmdSevSnp | AwsNitro
    quote:        Vec<u8>,             // Hardware-signed attestation quote
    measurement:  Vec<u8>,             // Code measurement / hash
    signature:    Vec<u8>,             // Vendor signature over the report
    vendor_data:  Vec<u8>,             // Vendor-specific auxiliary data
    timestamp:    Timestamp,           // When the attestation was generated
}
```

The `AttestationVerifier` validates reports by checking:
1. The quote structure matches the vendor's specification.
2. The measurement corresponds to the expected code.
3. The signature chains to the vendor's root of trust.
4. The timestamp is within an acceptable freshness window.

### 5.4 TEE Registry

The `TeeRegistry` maintains a network-wide directory of TEE providers with their capabilities and availability:

```
TeeCapacity {
    max_concurrent_jobs:   u32,
    active_jobs:           u32,
    total_cpu_cores:       u32,
    available_cpu_cores:   u32,
    supported_vendors:     Vec<TeeVendor>,
}
```

Providers register with the registry and periodically submit fresh attestation reports to maintain their active status.

### 5.5 Confidential Inference

When a user requests TEE-backed inference:

1. The user submits an inference request with `require_tee: true`.
2. The inference router selects a TEE-capable provider.
3. The model and input are loaded inside the TEE enclave.
4. Inference executes within the enclave's isolated memory.
5. The provider generates an attestation report binding the result to the model, input, and hardware.
6. The result and attestation are returned to the user.
7. Anyone can verify the attestation against the TEE vendor's root certificate.

---

## 6. Zero-Knowledge Proof System

### 6.1 Overview

Tenzro uses Plonky3 STARKs over the KoalaBear field (`p = 2^31 − 2^24 + 1`, two-adicity 24) with Poseidon2 hashing and FRI commitments. STARKs require **no trusted setup**, are **post-quantum sound** (relying only on collision-resistant hashing), and are well-matched to the AI workloads Tenzro verifies (matrix-multiply traces, hash chains over inference inputs/outputs). The Plonky3 git revision is pinned at `32079474b1d31d9221656ae774afb322d2597db0`. Testnet FRI parameters: `log_blowup = 1`, `num_queries = 64`, `query_pow = 16`, `commit_pow = 8`.

### 6.2 Pre-Built AIRs

Four domain-specific Algebraic Intermediate Representations (AIRs) are provided, each addressed by `circuit_id`:

**Identity Proof AIR (`circuit_id: "identity"`).** Proves knowledge of a private key corresponding to a public identity without revealing the key. Public inputs: public-key hash, capability commitment. Trace columns enforce hash-chain transitions over the private key, capabilities, and blinding factor using Poseidon2.

**Inference Verification AIR (`circuit_id: "inference"`).** Proves that an inference result was correctly computed from a given model and input. Public inputs: model hash, input hash, output hash. The trace binds model checksum, input checksum, and computed output checksum to the public hash digests via Poseidon2 round constraints.

**Settlement Proof AIR (`circuit_id: "settlement"`).** Proves that a settlement amount correctly reflects the agreed service terms. Public inputs: service hash, settlement hash, amount. The trace binds the private service proof and settlement details to the public commitments.

**Post-Quantum QC Aggregation AIR (`circuit_id: "pq-qc"`).** Compresses the ML-DSA-65 leg of a consensus quorum certificate into one STARK instead of N per-vote signatures. The AIR is parameterised by the validator-set size at runtime rather than by a const generic, so the same type serves N = 4 and N = 10,000 — the validator set is permissionless and unbounded. Trace layout is `2N + 1 + DIGEST_LEN` columns: a per-seat presence bitmap, a per-seat ML-DSA verification bit, the declared signer count, and the vote-message Poseidon2 digest. Public values are `[bitmap[0..N] | count | message_digest]`, with the bitmap exposed per bit so a relying party sees exactly which validator seats the certificate claims and can weight by stake without trusting an opaque popcount. Constraints enforce booleanity of both bit vectors, that a set presence bit forces its verification bit, that `count` equals the bitmap popcount, and that the trace digest matches the public digest.

This AIR carries `soundness_class: "advisory"` — the same posture as the identity and inference AIRs. The trace generator computes each verification bit off-circuit by calling native ML-DSA-65 verification and writes the boolean into the witness; the AIR binds the certificate's *structure* but does not evaluate the ML-DSA verification equation inside the circuit. A verifier that needs the post-quantum leg to be value-binding rather than advisory re-runs the N native verifications out of band. Per-vote post-quantum binding still exists on the individual votes.

### 6.3 Poseidon2 Hash

All AIRs use Poseidon2 over the KoalaBear field — the canonical Plonky3 algebraic hash. Poseidon2 is significantly more efficient inside STARK constraints than SHA-256/Keccak and avoids the round-count overhead of MiMC. The Poseidon2 instance is configured directly from Plonky3's `KoalaBearPoseidon2` reference implementation.

### 6.4 Hybrid ZK-in-TEE

Tenzro introduces a hybrid verification model that combines ZK proofs with TEE attestations:

1. A TEE enclave generates a Plonky3 STARK proof of correct computation.
2. The proof is accompanied by a TEE attestation binding it to the enclave.
3. Verifiers check both the mathematical proof and the hardware attestation.

This provides defense-in-depth: even if one trust assumption fails (e.g., an AIR constraint bug or a TEE side-channel), the other layer provides a fallback guarantee.

### 6.5 Commitment-Attestation Model

On-chain ZK verification uses a commitment-attestation pattern:

1. **Off-EVM verification.** Validators verify Plonky3 STARK proofs via `verify_proof_envelope(&Proof)` — a generic dispatcher that matches on `circuit_id` and routes to the corresponding AIR verifier.
2. **Proof publication.** The verifying node publishes the proof envelope to the DA layer and records the returned `tenzro://blob/<hash>` locator so any peer can fetch and independently re-verify it.
3. **Quorum co-signing.** A commitment is admitted to the `ZkCommitmentRegistry` only under a `2f+1` stake-weight quorum certificate: each co-signer independently re-runs `verify_proof_envelope` and BLS-signs the 32-byte commitment. The certificate is a 96-byte BLS12-381 aggregate plus a signer bitmap over the active validator set. The commitment hash is `SHA-256(circuit_id ‖ proof_bytes ‖ Σ(len_le(pi) ‖ pi))` with a 4-byte little-endian length prefix per public input.
4. **Fraud window.** Each attested commitment stays challengeable for `FRAUD_WINDOW_BLOCKS` (256) finalized blocks. Any staked party may file a fraud proof (`tenzro_fileZkFraudProof`): the node fetches the proof from its DA locator and re-runs the verifier deterministically. If it fails, the commitment is retracted and every co-signer named on the certificate is slashed for a consensus offence; if it re-verifies, the challenger's bond is forfeit.
5. **EVM precompile.** The `ZK_VERIFY` precompile is an O(1) HashSet lookup against the registry — smart contracts pay only a fixed cost to verify any STARK proof already admitted under quorum.

This separates expensive verification (off-EVM, parallelizable, run by validators as part of block production) from cheap on-EVM gating (constant-time membership check), and avoids embedding STARK verifier circuits inside the EVM. The quorum certificate plus fraud window replaces the trust assumption that any single verifying node was honest with an accountable `2f+1` co-signature that can be disproven and slashed.

### 6.6 Proof Wire Format

```
Proof {
    proof_bytes:    Vec<u8>,           // bincode-serialized p3_uni_stark::Proof
    public_inputs:  Vec<Vec<u8>>,      // each entry: 4-byte LE KoalaBear field-element chunks
    proof_type:     ProofType,         // Plonky3 (the only supported variant)
    circuit_id:     String,            // "inference" | "settlement" | "identity" | "pq-qc"
    created_at:     Timestamp,
    metadata:       ProofMetadata,     // Prover ID, proving time, custom fields
}
```

Public inputs are encoded as 4-byte little-endian KoalaBear field-element chunks, and the verifier reassembles them into field elements before checking AIR boundary constraints.

---

## 7. Cryptographic Primitives

### 7.1 Key Algorithms

| Algorithm | Purpose | Key Sizes |
|-----------|---------|-----------|
| Ed25519 | Transaction and message signatures, FROST threshold signing | 32-byte public key, 64-byte signature |
| Secp256k1 | Ethereum-compatible signatures, key derivation | 33-byte compressed public key |
| Secp256r1 (P-256) | WebAuthn / passkey signatures (Secure Enclave, StrongBox, TPM 2.0, Windows Hello), verified on-chain via the precompile at `0x100` | 64-byte uncompressed public key (`x ‖ y`), 64-byte raw signature (`r ‖ s`) |
| ML-DSA-65 (FIPS 204) | Post-quantum hybrid signature companion to Ed25519 | 1952-byte public key, 3309-byte signature |
| ML-KEM-768 (FIPS 203) | Post-quantum hybrid KEM companion to X25519 | 1184-byte public key, 1088-byte ciphertext |
| AES-256-GCM | Symmetric encryption for keystore and data at rest | 256-bit key, 96-bit nonce, 128-bit tag |
| X25519 | Elliptic-curve Diffie-Hellman key exchange | 32-byte public key |
| SHA-256 | General-purpose hashing, Merkle trees | 256-bit digest |
| Keccak-256 | Ethereum address derivation, storage keys | 256-bit digest |

### 7.2 Address Derivation

Addresses are 32-byte values derived from public keys:
- **Ed25519:** The raw 32-byte public key is truncated to 20 bytes, then zero-padded to 32 bytes.
- **Secp256k1:** Keccak-256 hash of the uncompressed public key, last 20 bytes, zero-padded to 32 bytes (Ethereum-compatible).

### 7.3 Threshold Signing

For threshold signatures over Ed25519, Tenzro uses **FROST** (Flexible Round-Optimized Schnorr Threshold signatures, [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)):

1. **Distributed Key Generation (DKG).** Two-round protocol where `n` participants jointly generate a single group public key without any party ever holding the corresponding secret. Each participant retains a key share.
2. **Threshold Signing.** Any `t`-of-`n` participants run a two-round signing protocol (commitment + response) to produce a single 64-byte Ed25519 signature indistinguishable from a single-key signature. No master key is ever reconstructed.
3. **Verification.** Resulting signatures verify against the group public key under the standard Ed25519 verifier — no protocol-specific verifier required.

This is a true threshold-MPC protocol: a compromised set of fewer than `t` participants learns nothing about the secret, and no party — including the signer that combines the round-2 outputs — ever sees the master key. The reference implementation is [`frost-ed25519`](https://github.com/ZcashFoundation/frost) maintained by the Zcash Foundation.

Older protocols (GG18, GG20, Lindell17) are explicitly out of scope: the TSSHOCK key-extraction attack (Verichains, 2023) and the BitForge / CVE-2023-33241 Paillier-modulus issue (Trail of Bits, Fireblocks, 2023) make them indefensible to deploy in 2026. CGGMP21/24 and DKLs23 are the equivalent picks if Tenzro adds secp256k1 multisig in the future.

### 7.4 Envelope Encryption

For data at rest (keystore files, cached keys), Tenzro uses envelope encryption:
1. A data encryption key (DEK) is generated randomly.
2. Data is encrypted with AES-256-GCM using the DEK.
3. The DEK is encrypted with a key encryption key (KEK) derived from the user's password via iterated SHA-256 (10,000 rounds).
4. The encrypted DEK, salt, nonce, and ciphertext are stored together.

---

## 8. TNZO Token Economics

> **Testnet phase.** All tokenomics parameters described in this section — supply, fee structure, commission splits, staking minimums, reward multipliers, slashing, unbonding periods, inflation, and burn rates — are configured for the Tenzro testnet phase. They are subject to revision before mainnet launch and will be finalized through the on-chain governance process.

### 8.1 Token Overview

| Property | Value |
|----------|-------|
| Symbol | TNZO |
| Decimals | 18 |
| Maximum Supply | 1,000,000,000 TNZO (1 billion) |
| Smallest Unit | 10^-18 TNZO |

The TNZO token serves three functions:
1. **Utility.** Payment for inference, settlement fees, and gas.
2. **Governance.** Voting power on network proposals proportional to staked balance.
3. **Security.** Staking collateral for validators and service providers.

### 8.2 Fee Structure

Tenzro operates two distinct fee collection mechanisms:

**1. Ledger Transaction Fees (Gas)**
- Paid in TNZO for all on-chain transactions (transfers, smart contract execution, etc.)
- Standard EIP-1559 fee market with dynamic base fee adjustment
- Flows directly to validators who produce and finalize blocks
- Provides economic security for Tenzro Ledger

**2. Network Commission Fees**
- 0.5% commission (50 basis points) on AI provider inference payments and TEE provider service fees
- Collected when users pay providers for intelligence (models) or security (TEE enclaves)
- Distributed as follows:

| Destination | Share | Purpose |
|-------------|-------|---------|
| Treasury | 40% | Network operations, grants, development |
| Burn | 30% | Deflationary pressure, reducing circulating supply |
| Stakers | 30% | Rewards for validators and service providers |

The network commission distribution parameters are governed by on-chain proposals and can be adjusted through governance votes.

### 8.3 Staking

Participants bond TNZO against a provider type. The ladder has nine rungs, each sized to the trust surface the role opens. It is defined in `tenzro-types/src/constants.rs` and applied by `ProviderType::required_stake`:

| Provider type | Bond | Scales with |
|---|---|---|
| RPC Provider | 100,000 TNZO | — |
| Validator | 10,000 TNZO | — |
| TEE Provider | 10,000 TNZO | — |
| Model Provider | 1,000 TNZO | — |
| Trainer | 1,000 TNZO | — |
| Syncer | 1,000 TNZO | — |
| Compute Provider | 500 TNZO floor | Accelerators pledged |
| Storage Provider | 100 TNZO floor | Terabytes pledged |
| Cloud Operator | 1,000 TNZO floor | Highest service class offered |

Three rungs scale with pledged capacity, so the bond tracks the exposure it collateralizes:

- **Compute Provider** — 1,000 TNZO per accelerator scaled by class (0.5× integrated, 1× consumer, 2× workstation, 5× datacentre), summed over everything pledged. One datacentre card plus one consumer card bonds 6,000 TNZO.
- **Storage Provider** — 100 TNZO per whole terabyte, so 50 TB bonds 5,000 TNZO.
- **Cloud Operator** — 1,000 TNZO functions, 5,000 databases, 25,000 machines. Classes are supersets: bonding for machines covers databases and functions.

Pledging no capacity to a scaling rung yields that rung's floor, never zero. The RPC Provider bond is the largest because a public endpoint brokers tenant traffic and upstream credentials, the largest trust surface any role holds. Every figure is governance-adjustable.

| Parameter | Value |
|-----------|-------|
| Unbonding period | 7 days (604,800,000 ms) |
| Slashing | Variable, based on offense severity |

**Reward multipliers:**

| Provider Type | Reward Multiplier | Description |
|--------------|-------------------|-------------|
| Validator | 1.0x | Block production and consensus |
| TEE Provider | 1.2x (20% bonus) | Hardware-attested confidential compute |
| Model Provider | 1.1x (10% bonus) | AI model serving |
| Storage Provider | 1.0x | Data storage and serving |
| Compute Provider | 1.0x | Accelerator rental |
| Cloud Operator | 1.0x | Hosted functions, databases, machines |

The elevated multiplier for TEE providers incentivizes investment in hardware-rooted trust infrastructure.

Consensus weight is separate from every bond above: only the validator bond carries finality weight, so bonding for any number of service rungs cannot move a quorum.

**Staking lifecycle:**
1. **Stake.** Lock TNZO against a provider type. Must meet minimum stake requirement.
2. **Active.** Stake is active; provider participates in the network and earns rewards.
3. **Unbonding.** Initiate unstake; stake is locked for the unbonding period.
4. **Withdrawn.** After unbonding completes, stake can be withdrawn.

**Slashing** reduces a provider's stake for provable misbehavior. Slash events are recorded with timestamp, amount, reason, and the address of the slashing authority. Slashed funds are burned, removing them from circulation. The consensus engine detects equivocation (double voting) via `EquivocationDetector` and triggers automatic slashing through a `SlashingCallback` trait — the node's `StakingSlashingCallback` bridges consensus detection to the `StakingManager`, slashing 10% of the validator's stake with full evidence logging. The complete pipeline is: detect equivocation in `VoteCollector` → collect evidence (conflicting votes) → invoke `SlashingCallback` → `StakingManager::slash()` → burn slashed tokens.

### 8.4 Reward Distribution

Rewards are **work-gated**, issued per epoch as minting-right coupons rather than paid on stake:

| Parameter | Value |
|-----------|-------|
| Epoch duration | 14,400 blocks (~1 day at 6s/block) |
| Reward model | Work-gated coupons on a declining annual schedule |
| Role buckets | Validator, Provider, Ecosystem |
| Claim liquid fraction | `liquid_bps` (remainder opens 12-month reward vesting) |

**Reward calculation for each closed epoch:**

```
year          = year_for(epoch)
epoch_rights  = declining_annual_schedule(year) / 365
(val_bps, prov_bps, eco_bps) = role_split_for(year)   // shifts infra → apps over years

For each role bucket:
  bucket_rights = epoch_rights * bucket_bps / 10000
  For each address with verified work in the bucket:
    work_share = address_work_weight / bucket_total_work_weight
    coupon     = bucket_rights * work_share            // an unclaimed minting right
```

Work weight is measured by the protocol — never self-reported. Validators earn on finalized-block and quorum-certificate participation; providers on metered proof-of-service (uptime- and reputation-scaled); the ecosystem bucket on contributions accepted through governance/foundation review (development, apps, tools). Rights left unmatched in a bucket, and coupons unclaimed within the claim window, are **permanently unminted** — supply only moves for work that was both done and claimed. Claiming a coupon mints the `liquid_bps` fraction immediately and opens a 12-month linear reward-vesting schedule for the remainder; a claim by a foundation-sponsored operator instead converts the full amount into operator-owned stake. Epoch reward metering is enforced sequential — epoch N is closed before N+1.

### 8.5 Treasury

The Network Treasury is a multi-asset vault that accumulates Network commission fees across all supported assets (TNZO, USDC, USDT, ETH, SOL, BTC):

- **Multi-signature withdrawal.** Treasury withdrawals require M-of-N approval from authorized withdrawers (configurable, e.g., 2-of-3).
- **Duplicate approval prevention.** Each withdrawer can approve a withdrawal only once.
- **Backing ratio.** The treasury publishes a `backing_ratio = treasury_value / tnzo_supply`, providing transparency into the network's economic health.
- **Fee sources.** The treasury receives 40% of the 0.5% Network commission on AI provider inference payments and TEE provider service fees. Ledger transaction fees (gas) flow directly to validators and do not pass through the treasury.

---

## 9. Settlement Layer

### 9.1 Overview

The settlement layer handles all economic transactions between participants. It supports three settlement modes designed for different use cases:

### 9.2 Immediate Settlement

For simple one-shot payments:

1. Consumer submits a `SettlementRequest` specifying payer, payee, amount, asset, and service proof.
2. The `SettlementEngine` verifies the consumer has sufficient balance.
3. For provider payments (AI inference or TEE services), a 0.5% Network commission is deducted and routed to the treasury. For direct peer-to-peer transfers, no commission is charged (only standard Ledger gas fees apply).
4. The net amount is credited to the payee.
5. A `SettlementReceipt` is generated with a unique receipt ID, status, and fee breakdown.

### 9.3 Escrow Settlement

Escrow is a **consensus-mediated on-chain primitive** — not a smart contract or
RPC convenience method. Funds are locked at a deterministically-derived vault
address by the Native VM; only the original signing payer can later release
funds to the payee or refund them to themselves.

```
EscrowAccount {
    escrow_id:          [u8; 32],          // SHA-256("tenzro/escrow/id" || payer || nonce_le)
    payer:              Address,
    payee:              Address,
    vault:              Address,           // Address(SHA-256("tenzro/escrow/vault" || escrow_id))
    amount:             u128,
    asset_id:           AssetId,
    created_at:         Timestamp,
    expires_at:         Timestamp,
    status:             EscrowStatus,      // Funded | Released | Refunded | Expired
    release_conditions: ReleaseConditions,
}
```

**Native-VM dispatch (4-byte selectors):**

| Selector       | Operation        | Gas    |
|----------------|------------------|--------|
| `0x01000010`   | CreateEscrow     | 75,000 |
| `0x01000011`   | ReleaseEscrow    | 60,000 |
| `0x01000012`   | RefundEscrow     | 50,000 |

**Release conditions:**
- `ProviderSignature` — Released when the provider signs a completion proof.
- `ConsumerSignature` — Released when the consumer confirms satisfaction.
- `BothSignatures` — Requires signatures from both parties (2 signatures minimum).
- `VerifierSignature` — Released by a third-party verifier or oracle.
- `Timeout` — Auto-released or refunded after a deadline.
- `Custom { condition }` — User-defined conditions.

**Authorization invariants (enforced by the VM):**
- `CreateEscrow.from` must equal the signing payer (verified at mempool admission). The VM never trusts a `payer` field in the payload.
- `ReleaseEscrow` is rejected unless `tx.from == escrow.payer`, the escrow is in `Funded` state, not expired, and the proof verifies against the recorded `release_conditions`.
- `RefundEscrow` is rejected unless `tx.from == escrow.payer` AND (the escrow is expired OR `release_conditions ∈ {Timeout, Custom}`).

**Escrow lifecycle:**
1. Payer constructs and signs a `CreateEscrow` typed transaction with payee, amount, asset, expiry, and release conditions.
2. The transaction is submitted via `tenzro_signAndSendTransaction` (server-side signing) or `eth_sendRawTransaction` (locally-signed). Mempool admission verifies the Ed25519 signature.
3. On block dispatch, the Native VM derives `escrow_id`, derives the vault address, debits the payer, credits the vault via a single auditable privileged-VM payout helper, persists the `EscrowAccount{Funded}` record to RocksDB `CF_SETTLEMENTS`, and emits a receipt log carrying `escrow_id`.
4. Provider delivers the service and assembles a `ServiceProof` matching the recorded `release_conditions`.
5. Payer signs and submits a `ReleaseEscrow` (vault → payee) or, after expiry, a `RefundEscrow` (vault → payer). The VM re-verifies authorization and the proof before payout.

**Persistence and hydration.** The `EscrowManager` writes through to RocksDB
`CF_SETTLEMENTS` under three prefixes — `escrow:<escrow_id>` for the full record,
`escrow_payer:<address_hex>` and `escrow_payee:<address_hex>` for index lookups
— using `KvStore::write_batch_sync` (fsync on commit). On node startup the manager
scans the `escrow:` prefix and rebuilds in-memory indices. Escrow state survives
restarts. Read RPCs `tenzro_getEscrow`, `tenzro_listEscrowsByPayer`, and
`tenzro_listEscrowsByPayee` query this index.

#### Delivery-versus-payment sagas

A single escrow settles one payer→payee leg. A delivery-versus-payment (DvP)
trade couples two or more legs that must all complete or all unwind — a
tokenized-treasury delivery against a stablecoin payment, a cross-VM swap, a
multi-party clearing step. The `SagaOrchestrator` runs these as compensating
transactions: each `SagaLeg` executes against an escrow, and if a later leg
fails or the deadline passes, the orchestrator compensates the already-executed
legs (refunding their escrows) rather than leaving a half-settled trade. The
state machine is `Open → Executing → Verifying → Finalized`, with
`Compensating → Compensated` and `Expired` as the unwind paths; `Finalized`,
`Compensated`, `Aborted`, and `Expired` are terminal. Every transition writes
through to `CF_SETTLEMENTS` and is idempotent under an in-flight guard, so a
retried or concurrently-driven step never double-refunds.

Open a saga with `tenzro_dvpOpenSaga`, drive it with `tenzro_dvpExecuteSaga`
and `tenzro_dvpFinalizeSaga`, and read state with `tenzro_dvpGetSaga` /
`tenzro_dvpListSagasByCreator`. A saga whose counterparty stalls does not pin
its escrows forever: validators run a periodic expiry sweep (every 300 s,
leader-gated) that compensates and expires any `Open`/`Executing` saga past its
deadline, releasing the locked funds without operator intervention.

#### Multilateral netting

`tenzro_nettingCompute` reduces a set of bilateral obligations to a minimal set
of net transfers before settlement, and `tenzro_nettingSettle` executes the
netted result atomically; `tenzro_nettingGetBatch` / `tenzro_nettingListBatches`
read the batch records. Netting cuts the on-chain settlement count for a
clearing round of mutually-offsetting obligations to the residual net positions.

### 9.4 Micropayment Channels

For high-frequency, low-value payments such as per-token inference billing:

```
MicropaymentChannel {
    channel_id:          String,
    payer:               Address,
    payee:               Address,
    deposit:             u128,
    spent:               u128,
    state:               ChannelState,     // nonce, payer_balance, payee_balance, signature
    asset_id:            AssetId,
    expires_at:          Timestamp,
    status:              ChannelStatus,    // Open | Closing | Closed | ForceClosed
    challenge_period_ms: i64,
}
```

**Channel lifecycle:**
1. **Open.** Consumer deposits funds into a channel, specifying the payee and expiration.
2. **Transact.** Off-chain state updates: each inference token increments `payee_balance` and decrements `payer_balance`, signed by both parties.
3. **Close.** Either party submits the latest state to the chain. A challenge period allows the counterparty to submit a later state.
4. **Settle.** After the challenge period, balances are distributed according to the final state.
5. **Force Close.** In case of dispute, either party can force-close with the latest signed state.

### 9.5 Batch Settlement

The `BatchProcessor` enables atomic multi-settlement operations: either all settlements in a batch succeed, or all are rolled back. This is essential for multi-party transactions where partial settlement would be inconsistent.

### 9.6 Native-TNZO On-Chain Settlement

When an HTTP 402 payment (x402 or MPP) settles in native TNZO, the balance move
is a **consensus-mediated on-chain transaction**, not an entry in the in-memory
settlement ledger. `PaymentGateway::verify_and_settle` invokes a settlement
callback that builds a system-key-signed `X402Settle` typed transaction (a
privileged Native-VM selector), admits it to the consensus mempool, and returns
the in-block transaction hash once it is included in a finalized block.

**Native-VM dispatch:**

| Selector       | Operation   | Gas    |
|----------------|-------------|--------|
| `0x01000024`   | X402Settle  | 40,000 |

The `X402Settle` payload carries `{ payer, payee, amount, payment_id }`. On block
dispatch the Native VM:

1. Charges gas from the system signer (`tx.from`).
2. Rejects the transaction if the `payment_id` marker already exists — a
   per-`payment_id` replay guard persisted under the system address in
   `CF_ACCOUNTS`, so a duplicated settlement callback cannot double-move balance.
3. Debits the payer (requires on-chain balance ≥ amount) and credits the payee,
   writing both through to `CF_ACCOUNTS` — the same backing store read by
   `eth_getBalance` and `token.balance_of`.
4. Sets the replay marker and increments the system signer's nonce.

**Authorization invariants (enforced by the VM):**
- The balance move is authorized by on-chain state and the system-key signature,
  never by a payee signature. The VM never trusts a beneficiary field to skip the
  payer-balance check.
- `payer ≠ payee`, `amount > 0`, and `1 ≤ payment_id length ≤ 128` are checked
  before any state change.

The receipt's `settlement_tx` field is the real in-block transaction hash. The
in-memory `SettlementEngine` remains receipt- and audit-only for native-TNZO
payments — it is never the balance authority. Payments whose asset settles on an
external chain follow the unchanged facilitator path (§13.6) and do not use this
selector.

### 9.7 Developer Settlement Authorization

For fiat checkout where a developer keeps custody of both the payment-processor
relationship and the funds, the app registry provides a non-custodial settlement
path. The developer charges the card on their own processor, then authorizes the
corresponding TNZO move from their own app wallet. No node holds a processor
secret and no node takes custody of developer funds; any node can execute a
signed authorization.

**App registry (on-chain, permissionless).** A developer registers an
`AppRecord` by signing a DID envelope with their own key. The record declares:

- `app_id` — network-unique identifier (1–128 bytes).
- `developer_did` — the owning DID.
- `app_wallet` — the developer's own TNZO treasury for this app. There is no
  pooled omnibus and no minting; settlement draws from this balance.
- `signing_pubkeys` — the Ed25519 keys allowed to authorize settlements, each
  with an optional `daily_limit_tnzo`.
- `margin_bps` — a pricing input the developer uses when setting the fiat price,
  bounded by `MAX_DEVELOPER_MARGIN_BPS` (2000 bps).
- `min_balance` — optional floor below which settlements are refused.

Registration is idempotent per `app_id` and every node hydrates the same registry
from `CF_SETTLEMENTS` (the `app:` prefix) on boot.

**Settlement authorization.** After the processor confirms a charge, the
developer's backend signs a `SettlementAuthorization`
`{ app_id, chain_id, payer_did, amount_tnzo, external_ref, nonce, expiry, key_id }`
with one of the app's enrolled keys and submits it. The node verifies the
signature against the enrolled key, checks the daily limit and expiry, and then:

1. Debits `amount_tnzo` from `app_wallet`.
2. Credits the payer `amount_tnzo − commission`.
3. Routes `commission = amount_tnzo * SETTLEMENT_AUTHORIZATION_COMMISSION_BPS /
   10000` (50 bps) to the treasury.

The call is idempotent per `(app_id, external_ref)` — a replay returns the
recorded outcome with `duplicate = true` rather than moving balance twice. Every
outcome is tagged with `app_id` for usage and revenue attribution without a
custodial per-user wallet.

**RPCs:** `tenzro_registerApp`, `tenzro_setAppStatus`, `tenzro_getApp`,
`tenzro_listApps`, `tenzro_settleAuthorized`, `tenzro_getSettleAuthorizedOutcome`.

---

## 10. AI Model Marketplace

### 10.1 Model Registry

The `ModelRegistry` maintains a decentralized catalog of available AI models, persisted via the storage layer (`CF_MODELS`) and rehydrated on node restart:

```
ModelInfo {
    model_id:      String,
    name:          String,
    description:   String,
    version:       String,
    category:      ModelCategory,    // LLM | ImageGen | Speech | Embedding | Custom
    modality:      ModelModality,    // Text | Image | Audio | Video | TextImage | TextAudio | Multimodal
    provider:      Address,
    price_per_token: u128,           // In TNZO per token
    min_stake:     u128,             // Required provider stake
    tee_required:  bool,
    supported_formats: Vec<String>,
    max_context_length: u64,
    parameters:    HashMap<String, String>,
}
```

The `modality` field is a typed enum with subset semantics: a `Multimodal` model satisfies any single-modality query, `TextImage` satisfies both Text and Image queries, and so on. This lets the router dispatch a vision-language request to either a dedicated vision-language model or a fully multimodal one without separate code paths.

Models are registered by providers who must meet the minimum stake requirement. The registry supports filtering by category, modality, and provider, and is durable across restarts so that the catalog survives provider churn.

### 10.2 Inference Routing

The `InferenceRouter` selects the optimal provider for each request based on configurable strategies:

| Strategy | Selection Criterion |
|----------|-------------------|
| Lowest Price | Provider offering the lowest per-token rate |
| Lowest Latency | Provider with the fastest historical response time |
| Highest Reputation | Provider with the best quality and uptime scores |
| Random | Uniform random selection (for load distribution) |
| Weighted Score | Composite score combining price, latency, and reputation |

**Circuit breaker.** Each provider connection is monitored with a circuit breaker (states: Closed, Open, Half-Open). After a configurable number of failures, the provider is temporarily removed from the routing pool and periodically retested.

### 10.3 Pricing

The `PricingEngine` calculates inference costs based on:
- Base per-token price set by the provider
- Model complexity multiplier
- TEE surcharge (if confidential inference is requested)
- Network congestion factor
- Stablecoin conversion rates for multi-asset payment

### 10.4 Provider Management

The `ProviderManager` tracks provider health and performance:

```
ProviderWithMetrics {
    provider:       InferenceProvider,
    total_requests: u64,
    successful:     u64,
    failed:         u64,
    avg_latency_ms: f64,
    last_health:    Timestamp,
    status:         ProviderStatus,    // Active | Inactive | Degraded | Banned
}
```

Providers that consistently fail health checks or deliver incorrect results are downgraded and eventually banned from the routing pool.

### 10.5 Model Downloads

The `DownloadManager` handles model weight distribution with:
- Progress tracking (bytes downloaded, total size, percentage, speed)
- Integrity verification via SHA-256 hash comparison
- Resumable downloads with chunk-based transfer

The HuggingFace Hub backend (`hf-hub`) is wired in by default; providers register a model by pointing at a HuggingFace repository and the node downloads the GGUF weights, ONNX exports, or safetensors archives directly.

### 10.6 Multi-Modal Inference Surface

The inference layer is intentionally not text-only. Three runtimes coexist behind a unified RPC surface:

**LLM runtime (llama.cpp / GGUF).** Decoder models — Llama, Qwen, Gemma, Mistral, Phi, etc. — load through `llama-cpp-2` (safe Rust bindings to llama.cpp). The runtime auto-detects model architecture from GGUF metadata and exposes both classic chat completion and a richer message shape (`ContentBlock`-typed multi-part messages) that supports image inputs, multi-turn conversations, and tool calling. Tool-call markers from common families (Qwen 3 `<tool_call>...</tool_call>`, Llama 3 JSON, generic JSON-in-tags) are parsed canonically and surfaced on the `ToolCall[]` field of the response. Streaming is implemented across the whole path (RPC → SSE → network forwarding) and preserves rich content blocks across hops.

**Vision encoder runtime (ONNX).** Foundation vision encoders — CLIP ViT-B/32, CLIP ViT-L/14, SigLIP base, SigLIP2 base, DINOv2 small/base/large — load through ONNX Runtime via the `onnx` cargo feature. The runtime decodes PNG/JPEG/WebP via the `image` crate, applies Lanczos3 resize, and runs CLIP-style or ImageNet normalization (configurable per registration). Output embeddings (`[1, D]` or `[1, 1, D]`) can be L2-normalized and fed into an in-process cosine-similarity helper for image-text retrieval. The catalog lists seven verified ungated models, all under MIT or Apache 2.0.

**Timeseries forecasting runtime (ONNX).** Foundation timeseries forecasters with a single-tensor input contract — TimesFM 2.5 — load through the same ONNX Runtime backend. The runtime accepts a univariate context window `[batch, context_len]` and returns either a point forecast `[batch, horizon]` or a quantile forecast `[batch, horizon, n_quantiles]`. Multi-input encoder-decoder forecasters (T5-based families with covariate and mask channels) plug in via per-family adapters. Inference is dispatched through `tokio::task::spawn_blocking` with a `parking_lot::Mutex` per session to satisfy ORT's non-concurrent contract.

The node exposes these through dedicated RPC namespaces: `tenzro_chat` (LLM, with classic and rich shapes), `tenzro_forecast` (timeseries), and vision-encoder methods that return raw embedding vectors. All three honor the same provider registration, pricing, routing, and settlement plumbing.

### 10.7 Hardware-Adaptive Runtime

The LLM runtime adapts to whatever compute is available on the provider's machine without code changes:

| Backend | Hardware | Activation |
|---------|----------|-----------|
| **Metal** | Apple Silicon GPU | Auto-linked on macOS ARM64 (no feature flag) |
| **CUDA** | NVIDIA datacenter (A100, H100, B200) and consumer (RTX 3090, 4090) | `--features cuda` |
| **ROCm** | AMD datacenter (MI300X) and consumer (RX 7900 XTX) | `--features rocm` |
| **Vulkan** | Cross-platform GPU (NVIDIA, AMD, Intel Arc, ARM Mali/Adreno) | `--features vulkan` |
| **CPU** | Always available; OpenMP-parallelized | Default fallback |

This means an ordinary laptop, a workstation with a single consumer GPU, and a multi-A100 server all participate in the same provider marketplace using the same binary; they just earn different volumes of inference traffic based on their measured throughput. The detected backend is published in the provider's hardware profile and visible to the routing layer.

Each provider publishes an advertised capacity in its gossip announcement — maximum concurrent requests, requests per second, batch size, and whether multi-token-prediction is enabled. `tenzro_listProviderCapacity` returns that advertised claim next to the throughput this node has actually observed for the provider: tokens per second, p95 latency, reputation (0–1000), and a reputation-discounted throughput figure that scales measured tokens/sec by the provider's trust score. Both the advertised and measured numbers are surfaced so consumers rank on observed behaviour rather than the claim alone. The same view is available through the `tenzro provider capacity` CLI command and the `list_provider_capacity` MCP tool.

#### Automatic hardware detection

Every node profiles its own hardware once at startup, with no operator configuration:

- **System memory** from `/proc/meminfo` on Linux and `sysctl hw.memsize` on macOS.
- **NVIDIA GPUs** via `nvidia-smi` (name, VRAM, compute capability per device) plus an NVLink probe (`nvidia-smi nvlink --status`) that distinguishes NVLink-connected multi-GPU machines from PCIe-only ones.
- **AMD GPUs** via `rocm-smi` (name, VRAM) paired with `rocminfo` gfx target discovery.
- **Apple Silicon** is treated as a unified-memory device: the GPU-usable budget is approximately three quarters of system RAM, matching the Metal working-set limit.

Probe failures degrade to coarser answers — a machine where `nvidia-smi` is absent simply reports no NVIDIA devices; it never errors. A `detected` flag records whether the profile came from a real probe: hardware claims are only ever produced by the node's own detection, never typed in by an operator.

Low-precision support is derived from the silicon, not declared: FP8 is inferred from NVIDIA compute capability ≥ 8.9 (Ada, Hopper) or AMD gfx94x/gfx95x/gfx12 targets, and FP4 from compute capability ≥ 10 (Blackwell) or gfx950 (CDNA4).

#### Hardware classes and routing

The detected profile collapses into a coarse `HardwareClass` — `Cpu`, `ConsumerGpu` (up to 24 GB VRAM), `DatacenterGpu` (25–96 GB), `MultiAccelerator` (above 96 GB), or `Unknown` when no probe ran. The class contributes a static weight to routing (0.2 / 0.5 / 0.8 / 1.0 respectively) alongside the dynamic observed metrics; `Unknown` providers get a neutral 0.5 and compete purely on measured throughput and reputation. Requests may carry a `min_hardware` hint in `InferenceParameters.custom` (`"consumer-gpu"`, `"datacenter-gpu"`, `"multi-accelerator"`) to set a hardware floor — a provider with no detected profile never satisfies an explicit floor, so the hint filters on verified capability only.

Routing also applies a memory-fit filter: when a model's registry entry carries a real weights size, providers whose detected memory budget cannot hold the model are excluded before scoring. The budget is system RAM plus discrete VRAM (llama.cpp splits a model across both pools), or unified memory alone on Apple Silicon. Providers with no detected profile pass the filter — absence of a claim is not treated as a negative claim.

#### VRAM-aware GPU offload

When a model loads, the runtime sizes the GPU offload from the detected profile and the model's own GGUF header:

- If the weights (with a 1.35× headroom factor for KV cache and compute buffers) fit in the GPU budget, all layers offload.
- If detection positively establishes that discrete VRAM cannot hold the full model, the runtime reads the layer count from the GGUF header and offloads the proportional number of layers, leaving the remainder on CPU.
- Unified-memory machines always take full offload — there is no separate VRAM pool to overflow.
- Cluster-scheduled loads skip the check entirely: the LAN placement planner has already guaranteed fit.

The result is that the same `tenzro model serve` command works on an 8 GB laptop and a 640 GB HGX node; the runtime picks the largest offload the hardware supports rather than failing or silently thrashing.

#### Served-model publication

Serving a GGUF model publishes it into the shared model registry with the real artifact hash: the node streams a SHA-256 over the weights file in the background and registers the model with that digest, catalog-derived size, context window, and architecture. Peers that later fetch the weights verify the downloaded bytes against this registry hash, so the digest is never synthetic — if hashing fails, the model is announced to the network but stays out of the registry rather than entering with a fabricated hash. Stopping a model (or failing to reload it at boot) flips the registry row to Inactive so routing stops considering it; re-serving reactivates it in place.

#### External serving engines

A provider can front an already-running OpenAI-compatible inference server — vLLM, SGLang, llama-server, or any compatible endpoint — instead of loading weights in the node process. `tenzro_serveModel` accepts `engine` (`vllm` | `sglang` | `llama-server` | `external`), `base_url`, an optional `upstream_model` (the name the engine was launched with, when it differs from the catalog id), and an optional `api_key` bearer token. Registration health-probes the engine so a misconfigured endpoint fails at serve time rather than at the first inference; chat and streaming requests are then mapped onto the engine's `/v1/chat/completions` API, including generation parameters and usage accounting from the engine's own token counts.

Externally-fronted models participate in routing, announcement, and settlement the same as in-process models, with two differences. The registry row carries a deterministic identity hash derived from the model id and engine URL rather than a weights digest — there is no local artifact for peers to fetch or verify. And the row's size is recorded as zero so the provider memory-fit filter does not apply: the weights live in the engine, whose health probe is the capacity signal. The binding persists across node restarts (including the bearer token, stored only in the operator's local database) and is re-probed at boot — a reachable engine re-registers automatically, an unreachable one is detached.

### 10.8 Verifiable Inference (TOPLOC Commitments)

Provenance signing (§10.6) attests to who served a response; a TOPLOC commitment attests to what the model computed. A request carrying `verifiable: true` (JSON-RPC `tenzro_chat`, the OpenAI-compatible surface, or `tenzro_inferenceRequest`) instructs the serving node to record the top-`k` raw logits (`k = 16`) at every generated decode step and persist the resulting commitment durably under its canonical SHA-256 hash. The response carries `{hash, k, steps}`; the full commitment is retrievable by hash.

**Verification is asymmetric.** A verifier holding the same model weights replays prompt + committed output token ids as a single prefill pass and compares per-step top-k logits — roughly two orders of magnitude cheaper than the original autoregressive decode. Providers that serve a quantization below their advertised precision, substitute a smaller model, or fabricate output produce logits that diverge from the commitment.

**Privacy.** The prompt is never stored with the commitment — the verifier supplies it at verification time. The commitment does contain the output token ids (the object of attestation), so requesting `verifiable` is an explicit opt-out of the gateway's completion-retention default for that response.

**Scope.** Commitments come from the local single-token (llama.cpp serial) decode path, non-streaming only: the SSE token channel carries no commitment and externally-fronted engines do not expose per-step logits. On the network path the flag is forwarded to the remote provider; its commitment object passes through the proxy verbatim, so a challenge is always anchored to the provider that served.

**Challenge lifecycle.** Any party may file a challenge against a stored commitment (`tenzro_fileInferenceChallenge`); the challenged model and provider are read from the stored envelope rather than caller input, so filings cannot misattribute. Filing draws a stake-weighted committee from the active validator set, seeded by the finalized-block hash so the draw is deterministic per dispute and grinding-resistant. The verdict is decided by the committee, not an operator, through a commit-reveal vote: each drawn member commits `H(verdict ‖ salt ‖ challenge_id ‖ voter)` (`tenzro_commitChallengeVote`) and later discloses `(verdict, salt)` (`tenzro_revealChallengeVote`), which must reproduce the commit. When committed stake reaches the `2f+1` threshold the challenge advances from the commit phase to the reveal phase. `tenzro_finalizeChallenge` tallies the revealed votes weighted by committee stake; a `2f+1` stake-weighted majority to uphold upholds the challenge, otherwise it is dismissed. Finalize is idempotent — a decided challenge returns its verdict unchanged — and a `force` flag closes a challenge that never reached an uphold quorum after the reveal window (the provider prevails). An upheld challenge fires the provider's existing penalty paths: routing reputation decrements through the failed-call path, and a failure is recorded against the provider's compute bond. No dedicated slashing primitive exists for inference challenges; the penalty economics reuse the reputation and bond machinery that also governs availability failures. Reputation increases only through settled payments, which prevents recovery via self-challenge. Commitments and challenges persist in `CF_CHALLENGES` and survive restarts; a node without durable storage disables the surface entirely.

### 10.9 Model Visibility and Sealed Distribution

Two independent primitives keep a model private: registry-level visibility and sealed weight distribution.

**Visibility.** Every serve registration carries a `ModelVisibility` value, `network` (default) or `private`. A `network` model is announced over gossip, heartbeats to the provider set, and participates in network inference routing. A `private` model does none of that: no announcement, no heartbeat, no presence in provider discovery — it serves only callers that reach the node directly. Visibility is set at registration (`tenzro_serveModel` `visibility` param; CLI `tenzro model serve --private`), persists with the serve record, and is enforced at the announcement and heartbeat paths rather than by filtering at query time.

**Sealed distribution.** Private weights move between nodes as encrypted shards under a signed manifest:

```
SealedModelManifest {
    model_id:       String,
    artifact_name:  String,
    owner_did:      String,
    model_hash:     Hash,                    // SHA-256 of the plaintext artifact
    total_bytes:    u64,
    shard_bytes:    u64,                     // plaintext shard size (256 MiB default)
    shards:         Vec<SealedModelShard>,   // index, sizes, ciphertext hash, tenzro://blob URI
    recipients:     Vec<SealedRecipient>,    // did, x25519_pubkey, wrapped key, optional attestation hash
    wrap_alg:       "x25519-envelope-aes-256-gcm",
    manifest_hash:  Hash,                    // domain-separated SHA-256 over the above
    signature:      Vec<u8>,                 // Ed25519 by the sealing node's announce key
    signer_pubkey:  Vec<u8>,
    created_at:     Timestamp,
}
```

The artifact is split into fixed-size shards, each encrypted with a nonce-prefixed AES-256-GCM content key generated for the seal. Ciphertext shards publish to the content-addressed blob store and are referenced by `tenzro://blob/<hash>` URI; each shard's ciphertext hash is domain-separated (`tenzro/model/sealed-shard ‖ model_id ‖ index`). The content key is wrapped once per recipient using X25519 ephemeral-static envelope encryption — the only wrap scheme the module produces or accepts. A recipient is a DID plus an X25519 public key and may carry an attestation report hash, binding the wrap target to a TEE identity the owner verified out-of-band (the same binding model as Confidential-tier training enrollment).

Unsealing verifies in this order: manifest signature, wrap algorithm, recipient match (DID and public key), per-shard ciphertext hashes as shards arrive, and finally the plaintext `model_hash` after reassembly — the decrypted artifact reaches model storage only when every check passes. Manifests persist in `CF_MODELS` and hydrate on restart; they carry no key material beyond wrapped ciphertexts and are safe to distribute over any channel.

Sealing and installing are operator actions gated by the node admin token (`tenzro_sealModel`, `tenzro_installSealedModel`). Discovery is open: `tenzro_getSealedModel`, `tenzro_listSealedModels`, and `tenzro_modelRecipientKey` (the node's X25519 recipient public key, generated at first start).

---

## 11. Autonomous Agent Framework

### 11.1 Overview

Tenzro provides a dedicated runtime for autonomous AI agents that can discover peers, negotiate services, execute tasks, and settle payments without human intervention.

### 11.2 Agent Identity

Each agent receives a self-sovereign identity upon registration:

```
AgentIdentity {
    agent_id:     String,           // Unique identifier
    name:         String,           // Human-readable name
    address:      Address,          // On-chain address (from auto-provisioned wallet)
    public_key:   Vec<u8>,          // Ed25519 public key
    created_at:   Timestamp,
    creator:      Address,          // Address that created this agent
    tee_backed:   bool,             // Whether identity is TEE-attested
}
```

The `AgentIdentityManager` handles registration, lifecycle management, and auto-provisions an MPC wallet for each agent, enabling agents to hold and transact TNZO autonomously.

### 11.3 Lifecycle State Machine

```
Created --> Active --> Suspended --> Active (resume)
                  |               |
                  +---> Terminated
                  |
Suspended ------> Terminated
```

State transitions are tracked with events broadcast to subscribers:
```
AgentLifecycleEvent {
    agent_id:    String,
    from_state:  AgentState,
    to_state:    AgentState,
    reason:      Option<String>,
    timestamp:   Timestamp,
}
```

**Health monitoring.** The runtime periodically checks agent heartbeats. Agents missing heartbeats beyond the configured interval (default: 30 seconds) are auto-suspended.

### 11.4 Capability Registry

Agents register capabilities describing what they can do:

| Capability | Description |
|-----------|-------------|
| `NaturalLanguageProcessing { languages }` | Text understanding and generation |
| `ComputerVision { formats }` | Image analysis and generation |
| `CodeGeneration { languages }` | Source code generation |
| `DataAnalysis { formats }` | Statistical analysis and visualization |
| `BlockchainInteraction { chains }` | On-chain operations |
| `SmartContractExecution` | Smart contract deployment and invocation |
| `ExternalAPIIntegration { apis }` | Integration with external services |
| `MultiAgentCoordination` | Orchestrating multi-agent workflows |
| `Custom { name, parameters }` | User-defined capabilities |

The `CapabilityRegistry` enables discovery: agents can query `find_agents_with_capability(capability)` or `find_agents_with_all_capabilities(capabilities)` to find peers. Capabilities can be **attested** (optionally TEE-backed) for cryptographic proof of ability.

The `find_best_agent(capability)` method selects the optimal agent, preferring TEE-backed attestations and more recent attestation timestamps.

### 11.5 Agent-to-Agent (A2A) Protocol

The A2A protocol enables structured inter-agent communication following the Google A2A specification. Each Tenzro node runs a full A2A protocol server (default port 3002):

**A2A Server Endpoints:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/agent.json` | GET | Agent Card discovery |
| `/a2a` | POST | JSON-RPC 2.0 dispatcher |
| `/a2a/stream` | POST | SSE streaming for task updates |

**Agent Card.** Each node publishes an Agent Card at `/.well-known/agent.json` per the A2A specification. The card advertises the node's capabilities, skills, supported input/output modes, authentication requirements, and protocol version (0.2.0). 40 skills are advertised covering core blockchain (wallet, token, contract, nft, staking), identity & payments (identity, settlement, ap2-payments, urwa, ivms101), AI & agents (inference, cortex, agent_spawning, swarm_orchestration, task_marketplace, agent_marketplace, capability_registry, erc8004, moe, media-gen), network resources (storage, compute, discovery, iroh-transport), cross-chain & compliance (bridge, crosschain, wormhole, wormhole-ntt, bridge-fee-in-tnzo, cct, erc7683, compliance), and verification & operations (verification, events, join, workflow-coordination, attested-clock, signed-agent-card, adaptive-burn, seed-agent).

**JSON-RPC Methods:**
- `message/send` / `tasks/send` — Send a message to create or continue a task
- `tasks/get` — Query task status (with optional history length limit)
- `tasks/list` — List tasks (optionally filtered by context ID)
- `tasks/cancel` — Cancel a running task

**Task lifecycle:**
```
Submitted → Working → Completed
                    → Failed
                    → Canceled (via tasks/cancel)
```

The `TaskManager` stores tasks in a concurrent `DashMap<String, A2aTask>`, with each task tracking its state, message history, and artifacts. The server routes user messages to appropriate node capabilities based on content analysis — wallet queries, block lookups, identity operations, faucet requests, model discovery, and network status.

**Streaming.** The `/a2a/stream` endpoint provides real-time task updates via Server-Sent Events (SSE). Clients receive `task` events as the task transitions through states, followed by a `done` sentinel when processing completes.

### 11.6 MCP Server

Each Tenzro node runs a Model Context Protocol (MCP) server (default port 3001) using the `rmcp` crate with Streamable HTTP transport. This exposes node capabilities as MCP tools that any MCP-compatible AI agent can invoke programmatically.

**Server configuration:**
- Protocol version: `2025-11-25`
- Transport: Streamable HTTP (endpoint: `/mcp`)
- Capabilities: Tools
- Server name: `tenzro`

**Available tools (526)** spanning wallet & ledger, network & blocks, identity & delegation (including right-to-erasure via `forget_identity`), payments (AP2 sign + verify, ERC-8004 v0.6+ Trustless Agents Registry, MPP, x402, Stripe SPT, Visa TAP, Mastercard Agent Pay), AI models & inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), cross-chain bridge, verification (ZK, VRF, attestations), staking & providers, tokens & contracts, NFTs, agents (spawning, swarms, marketplace), tasks (marketplace, quotes, completion), skills, tools, compliance & KYC, TEE, and event subscriptions. Representative samples:

| Group | Example Tools |
|-------|---------------|
| Wallet & Ledger | `get_balance`, `send_transaction`, `create_wallet`, `request_faucet` |
| Network & Blocks | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did`, `set_delegation_scope` |
| Payments | `create_payment_challenge`, `verify_payment`, `list_payment_protocols` |
| AI Models & Inference | `list_models`, `chat_completion`, `list_model_endpoints` |
| Cross-Chain Bridge | `bridge_tokens`, `get_bridge_routes`, `list_bridge_adapters` |
| Verification | `verify_zk_proof`, `verify_vrf_proof`, `generate_vrf_proof` |
| Staking & Providers | `stake_tokens`, `unstake_tokens`, `register_provider`, `get_provider_stats` |
| Tokens & Contracts | `create_token`, `deploy_contract`, `cross_vm_transfer`, `wrap_tnzo` |

All tool parameter schemas are generated via `schemars::JsonSchema` for automatic schema discovery by MCP clients. Tools delegate to the node's subsystems (`Arc<TenzroNode>`, `Arc<WebState>`) for actual data access and transaction submission.

**Ecosystem MCP servers.** Six additional Streamable HTTP servers run alongside the main Tenzro MCP server, each providing direct interaction with another network: Solana (port 3003, 14 tools — Jupiter swaps, SPL, Metaplex, Bonfida SNS), Ethereum (port 3004, 17 tools — Chainlink feeds, ENS, ERC-8004 agent registry, EAS), Canton (port 3005, 23 tools — DAML JSON Ledger API v2, CIP-56 transfers, DvP settlement, per-tenant IDP + user-rights management), LayerZero (port 3006, 21 tools — V2 messaging, OFT, Stargate V2, Value Transfer API), Chainlink (port 3007, 21 tools — CCIP, Data Feeds, Data Streams, VRF v2.5, Proof of Reserve, Automation, Functions), and Li.Fi (port 3008, 9 tools — cross-chain aggregation).

### 11.7 OpenClaw Skill Integration

An OpenClaw-compatible skill definition (`skills/openclaw-tenzro/SKILL.md`) allows OpenClaw agents to interact with the Tenzro blockchain. The skill provides structured instructions for:
- Connecting to Tenzro's JSON-RPC, Web API, MCP, and A2A endpoints
- Creating wallets and checking balances
- Sending transactions and requesting faucet tokens
- Registering and resolving identities
- Verifying proofs and checking node status

### 11.8 Agent Templates

Agent Templates are reusable, versioned blueprints for spawning autonomous agents without writing code. The network registers 18 reference templates covering common agentic patterns:

| Template | Type | Description |
|----------|------|-------------|
| Multi-Chain Portfolio Manager | Coordinator | Orchestrates portfolio rebalancing across multiple chains and DeFi protocols |
| Intelligent Payment Router | Specialist | Selects optimal payment protocol and routing path based on cost, speed, and chain availability |
| Cross-Chain Liquidity Aggregator | Custom | Autonomously sources and aggregates liquidity across bridge adapters and DEXs |
| Autonomous RWA Custodian | Custom | Manages real-world asset tokenization lifecycle with TEE-backed custody and compliance |
| Agentic Inference Marketplace | Coordinator | Discovers, benchmarks, and routes inference requests to optimal providers on behalf of other agents |
| Bridge Arbitrage Scanner | Specialist | Monitors price differentials across bridges and executes arbitrage trades |
| Canton Trade Settler | Specialist | Settles institutional trades on Canton synchronizers with DvP guarantees |
| MPP Payment Agent | Specialist | Handles MPP-protocol payment sessions for streaming and recurring charges |
| Model Inference Proxy | Worker | Routes inference requests to optimal model providers with fallback |
| Yield Rebalancer | Specialist | Rebalances yield positions across DeFi protocols based on APY and risk |
| Premium Alpha Advisor | Specialist | Provides premium analytics and trading signals to subscribers |
| Timeseries Forecaster | Worker | Forecast inference using TimesFM 2.5 |
| Audio Transcriber | Worker | Transcribes audio using Whisper, Distil-Whisper, Moonshine, Parakeet, Canary |
| Video Analyst | Worker | Analyzes video content with frame-level embeddings and multi-modal reasoning |
| Vision Indexer | Worker | Indexes image collections with CLIP, SigLIP2, DINOv3 embeddings |
| Timeseries Trainer | Specialist | Decentralized training participant for timeseries foundation models |
| Language Trainer | Specialist | Decentralized training participant for language models |
| Vision Trainer | Specialist | Decentralized training participant for vision foundation models |

Templates support six types: Assistant, Specialist, Worker, Coordinator, Validator, and Custom. Each template includes a unique `template_id`, version, creator DID, declared capabilities, runtime requirements, pricing model, and discovery examples.

### 11.9 Runtime Configuration

```
AgentRuntimeConfig {
    max_agents:              10,000,
    enable_tee_verification: false,   // (default; enable in production)
    heartbeat_interval:      30 seconds,
    max_message_queue_size:  1,000,
    default_resource_limits: ResourceLimits { ... },
}
```

---

## 12. Tenzro Decentralized Identity Protocol (TDIP)

### 12.1 Overview

Tenzro Decentralized Identity Protocol (TDIP) provides a unified decentralized identity system for the Tenzro Network. The protocol recognises **three identity classes** — humans, delegated agents (machines under a human controller), and autonomous agents (self-sovereign machines) — all under a single `did:tenzro:` namespace.

Every identity receives an auto-provisioned MPC wallet, a set of verifiable credentials, and W3C DID Document representation.

### 12.2 DID Formats

```
did:tenzro:human:{uuid}                    — Human identity (KYC-tiered)
did:tenzro:machine:{controller}:{uuid}     — Delegated agent (machine under a human controller)
did:tenzro:machine:{uuid}                  — Autonomous agent (self-sovereign machine, no controller)
```

### 12.3 Unified Identity Type

```
TenzroIdentity {
    did:            TenzroDid,
    public_keys:    Vec<PublicKeyInfo>,
    identity_data:  IdentityData,        // Human or Machine
    status:         IdentityStatus,      // Active | Suspended | Revoked
    wallet_address: Address,             // Auto-provisioned MPC wallet
    wallet_id:      String,
    credentials:    Vec<VerifiableCredential>,
    services:       Vec<ServiceEndpoint>,
    created_at:     DateTime,
    updated_at:     DateTime,
    metadata:       HashMap<String, String>,
}
```

**Human identity data:**
```
IdentityData::Human {
    display_name:       String,
    kyc_tier:           KycTier,         // Unverified | Basic | Enhanced | Full
    controlled_machines: Vec<String>,    // DIDs of machines this human controls
}
```

**Machine identity data:**
```
IdentityData::Machine {
    capabilities:      Vec<String>,      // e.g., "inference", "trading"
    delegation_scope:  DelegationScope,  // Permission boundaries
    controller_did:    Option<String>,   // Human controller (if any)
    reputation:        u32,              // 0-1000
    tenzro_agent_id:   Option<String>,   // Link to native agent runtime
}
```

### 12.4 KYC Tiers

| Tier | Level | Verification |
|------|-------|-------------|
| Unverified | 0 | No verification |
| Basic | 1 | Email verification |
| Enhanced | 2 | ID document verification |
| Full | 3 | Biometric + institutional verification |

KYC tiers are ordered — a tier comparison like `tier >= Enhanced` is supported for access control decisions.

### 12.5 Delegation Scopes

Human identities grant permissions to machine identities through delegation scopes:

```
DelegationScope {
    max_transaction_value:      Option<u128>,    // Per-transaction limit
    max_daily_spend:            Option<u128>,    // Daily aggregate limit
    allowed_operations:         Vec<String>,     // e.g., ["inference", "trade"]
    allowed_contracts:          Vec<Vec<u8>>,    // Smart contract allowlist
    time_bound:                 Option<TimeBound>, // not_before / not_after
    allowed_payment_protocols:  Vec<String>,     // e.g., ["mpp", "x402"]
    allowed_chains:             Vec<String>,     // e.g., ["tenzro", "tempo"]
}
```

An empty allowlist (e.g., empty `allowed_operations`) means all values are permitted. The `DelegationScope::unrestricted()` constructor creates a scope with no restrictions.

### 12.6 Verifiable Credentials

TDIP supports W3C Verifiable Credential-compatible credentials:
- Credentials are issued by one identity to another
- Machine identities can inherit credentials from their human controller
- Credential types include `KycVerification`, `ProviderAttestation`, `CapabilityProof`, and `Custom`
- Each credential carries a `CredentialProof` with issuer DID, signature, and issuance timestamp

### 12.7 Cascading Revocation

Revoking a human identity automatically revokes all machine identities controlled by that human. This prevents orphaned agents from operating after their controller is deactivated.

### 12.8 W3C DID Document Export

Every TDIP identity can be exported as a standard W3C DID Document for interoperability with external identity systems:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:tenzro:human:abc123",
  "verificationMethod": [...],
  "authentication": [...],
  "service": [...]
}
```

### 12.9 Right to Erasure (`tenzro_forgetIdentity`)

TDIP supports GDPR Article 17 right-to-erasure as a two-phase flow that respects the cascading-revocation invariant from §12.7:

1. **Revoke** — Call `tenzro_revokeIdentity` to mark the identity `Revoked`. The cascading revocation broadcaster propagates the status change to peers (cascading-revoke any controlled machines) and to dependent payment binders (Stripe SPT `granted_token.deactivated`, AP2 mandate cache).
2. **Forget** — Once propagation has settled, call `tenzro_forgetIdentity { did }` to hard-delete the identity from `CF_IDENTITIES` and the in-memory `IdentityRegistry`. The DID must already be in `Revoked` status; calling forget on an `Active` identity returns an error.

Forget is irreversible. The DID becomes unresolvable on this node; bound credentials and delegation scopes are dropped. Audit-trail receipts that referenced the DID remain — only the live identity record is erased. CLI: `tenzro identity forget <did>`. MCP tool: `forget_identity`.

---

## 13. Payment Protocols

### 13.1 Overview

Tenzro supports multiple agentic payment protocols across two settlement modes: **crypto rails**, where the chain settles the value, and **card rails**, where Visa or Mastercard settle the value while Tenzro provides the agent identity, delegation enforcement, and mandate audit trail. All protocols use the HTTP 402 Payment Required flow: a server issues a payment challenge, a client creates a payment credential, and the server verifies and settles.

The `tenzro-payments` crate implements all five with a unified `PaymentProtocol` trait and a `PaymentGateway` that routes across them.

### 13.2 Supported Protocols

#### Crypto rails — Tenzro settles the value

| Protocol | Origin | Use Case |
|----------|--------|----------|
| **AP2** (Agent Payments Protocol) | Google / FIDO Alliance | Intent / cart / payment VDC mandate sign + verify + validate-pair via `tenzro_ap2SignMandate`, `tenzro_ap2VerifyMandate`, `tenzro_ap2ValidateMandatePair` |
| **Stripe SPT** (SharedPaymentToken) | Stripe | Issued/granted token lifecycle via `StripeClient::{create_issued_token, retrieve_granted_token, revoke_issued_token, confirm_intent_with_spt}`; surface described by `tenzro_stripeSptProtocolInfo`; `granted_token.deactivated` cascades into TDIP `apply_remote_revocation` via `tenzro_processSptGrantedTokenDeactivated` |
| **ERC-8004** (Trustless Agents Registry) | Ethereum | Identity / Reputation / Validation registry surfaces — see §13.10 |
| **MPP** (Machine Payments Protocol) | Stripe / Tempo | Session-based machine payments with HTTP 402 |
| **x402** | Coinbase | Stateless HTTP 402 payments with EIP-3009 authorization |
| **Tempo** | Tempo Network | Stablecoin settlement via Tempo blockchain |
| **Direct** | Tenzro native | On-chain TNZO settlement |
| **Channel** | Tenzro native | Off-chain micropayment channels |

#### Card rails — Tenzro provides identity + delegation + audit; card networks settle fiat

For Visa Trusted Agent Protocol (TAP) and Mastercard Agent Pay, the money moves over the card network. The chain leg is not the money leg. Tenzro contributes the substrate that card networks do not provide at the protocol level: a verifiable agent DID, a signed delegation scope (max value, daily cap, allowed merchants/MCCs, time-bound), AP2 v0.2 CheckoutMandate + PaymentMandate validation before authorization, and an on-chain receipt for the agent's action. The agent presents the Tenzro-issued mandate envelope to the card-rail authorization API; the card network settles the fiat leg; Tenzro records the receipt. This means a single agent identity can compose a card-rail TAP payment, an x402 USDC micropayment, and a Canton DvP leg in one task with one delegation envelope and one audit trail.

| Protocol | Origin | Tenzro's Role |
|----------|--------|---------------|
| **Visa TAP** (Trusted Agent Protocol) | Visa | Agent DID + delegation + AP2 mandate validation + audit receipt; Visa settles fiat |
| **Mastercard Agent Pay** | Mastercard | Agent DID + delegation + AP2 mandate validation + audit receipt; Mastercard settles fiat |

Visa TAP's recognition role is served over HTTP as a facilitator on the web API. A resource server fronting a checkout or browse endpoint forwards the signed request fields to `POST /facilitator/visa-tap/verify`; the node runs the RFC 9421 recognition pipeline and answers whether the request came from a recognized agent and with what tag (`agent-browser-auth` / `agent-payer-auth`). `GET /facilitator/visa-tap/supported` advertises the recognized signature format, domain, and tags. Recognition is distinct from settlement — a recognized `agent-payer-auth` request settles through the payment gateway, not this endpoint.

### 13.3 Payment Flow

```
Client                          Server
  |                                |
  |  --- HTTP request ---------->  |
  |  <-- 402 PaymentChallenge ---  |
  |                                |
  |  (create PaymentCredential)    |
  |                                |
  |  --- request + credential -->  |
  |  (verify + settle)             |
  |  <-- 200 + PaymentReceipt --   |
```

### 13.4 AP2 (Agent Payments Protocol)

AP2 v0.2 (Google / FIDO Alliance) defines mandates carried as VDC-wrapped envelopes. Tenzro implements two, forming a parent/child pair:

- **CheckoutMandate** — signed by the principal. Authorizes an agent to spend up to `max_amount` of `asset`, optionally narrowed by `allowed_merchants`, `allowed_categories`, `accepted_chains`, `max_uses`, and a hard `expires_at`.
- **PaymentMandate** — signed by the agent. Commits to a specific cart (line items, `total_amount`, `merchant_did`, `chain`) under a named parent via `checkout_mandate_id`, optionally bound cryptographically by `checkout_hash` (SHA-256 of the parent CheckoutMandate VDC, AP2 v0.2 §6.2.3).

Tenzro provides three RPC surfaces:

- **`tenzro_ap2SignMandate { mandate_kind, mandate, signer_did }`** — `mandate_kind` is `"checkout"` or `"payment"`. The wallet bound to `signer_did` signs the canonical preimage with its Ed25519 key. Only AP2 v0.2 `"ed25519"` alg is supported.
- **`tenzro_ap2VerifyMandate { vdc }`** — verifies the Ed25519 signature against the signer DID's resolved verification method. Returns `{ valid, mandate_id, kind, signer_did, alg }`.
- **`tenzro_ap2ValidateMandatePair { checkout_vdc, payment_vdc, enforce_delegation }`** — verifies both signatures, checks the payment mandate's `checkout_mandate_id` (and `checkout_hash`, when present) resolves to the supplied checkout, and enforces **five nested ceilings** on the payment total, outermost first:
  1. `ap2_checkout_mandate` — the parent's `max_amount`, merchant/category/chain allow-lists, `max_uses`, and expiry.
  2. `tdip_delegation_scope` — `DelegationScope::enforce_operation` (max_transaction_value, allowed_operations, time_bound). Applied when `enforce_delegation` is true.
  3. `runtime_spending_policy` — `SpendingPolicy` (max_per_transaction, daily-spend window) resolved through `SpendingPolicyResolver`.
  4. `onchain_escrow` — when either mandate carries an `escrow_id`, the two must match and the escrow must cover the total.
  5. `stripe_spt_usage_limits` — when either mandate carries a `spt_grant_id`, the two must match and the granted token's remaining usage must admit the charge.

### 13.5 MPP (Machine Payments Protocol)

MPP, co-authored by Stripe and Tempo, provides session-based HTTP 402 payments:

- **MppChallenge** — Issued by the server with amount, asset, recipient, and chain
- **MppCredential** — Created by the client, signed with the payer's wallet
- **MppReceipt** — Returned after settlement with transaction reference
- **MppSession** — Tracks ongoing payment relationships between payer and payee
- **MppSessionManager** — Thread-safe session lifecycle management
- **MppPaymentServer** — HTTP handler that issues 402 responses
- **MppClient** — Client-side credential creation and submission

### 13.6 x402 (Coinbase)

x402 provides stateless HTTP 402 payments:

- **X402PaymentRequired** — 402 response header with payment requirements
- **X402PaymentPayload** — Payment data submitted by the client
- **X402Facilitator** — Coordinates between payer, payee, and settlement
- **X402PaymentServer** — HTTP handler for x402 flow
- **X402Client** — Client-side payment creation

**Payment schemes.** A resource declares one of three settlement schemes in its 402 challenge:

- **`exact`** — the base scheme: a single one-shot payment of a fixed amount per request.
- **`upto`** — usage-metered: the challenge names a per-request ceiling; the client authorizes up to that amount and the resource captures the actual metered cost (never above the ceiling) after serving. Fits token-metered inference and byte-metered reads where the final price is known only after the work runs.
- **`batch-settlement`** — off-chain accumulation: many small requests draw down a pre-funded channel and settle on-chain once at close, so per-call gas does not dominate a stream of micro-charges.

**Discovery (Bazaar).** A resource server advertises its priced endpoints so agents can find them without out-of-band configuration:

- `tenzro_x402RegisterResource { resource, scheme, price, asset, ... }` publishes a priced resource into the local Bazaar index.
- `tenzro_x402DiscoverResources { filter }` returns matching resources with their scheme and price. Each result carries `seller_reputation`, joined from the provider-reputation ledger by the listing's `pay_to` settlement address — the only score-up path on that ledger is a settled payment, so a seller cannot inflate its own ranking by re-listing. Results sort highest-reputation-first (unscored sellers last), freshest-first within the same score. An optional `minReputation` floor excludes listings below it (unscored sellers fail any floor).
- `tenzro_x402DeregisterResource { resource }` withdraws it.

**Idempotency and signed offers.** Each challenge carries a payment identifier and an offer signed by the resource server:

- `tenzro_x402PaymentId {}` mints a unique payment identifier; a client replaying the same identifier gets the first result, not a second charge.
- `tenzro_x402VerifyOffer { offer, signature }` verifies that a quoted price/scheme was actually issued by the resource server before the client authorizes payment.
- `tenzro_x402ProtocolInfo {}` reports the supported schemes and extensions.

**Settlement.** When the payment asset is native TNZO, settlement moves balance
on-chain through the consensus-mediated `X402Settle` path described in §9.6 — the
receipt's `settlement_tx` is the real in-block transaction hash. Payments in an
external-chain asset (USDC on Base, for example) settle on the chain where the
asset lives.

**Self-hosted EIP-3009 / Permit2 facilitation.** For external-chain USDC an
operator can verify and settle from its own EVM relayer rather than a remote
service. When the operator sets the `payments.x402_facilitator` config block
(external `evm_rpc_url`, `chain_id`, and a relayer key resolved from the config
field or the `TENZRO_X402_RELAYER_KEY` environment variable), the node builds a
local verifier that runs the eight exact/EVM checks against that RPC —
network / recipient / amount parity, the signed time window, EIP-712 signature
recovery, `authorizationState(from, nonce)` for nonce reuse, `balanceOf(from)`
for funding, and a `transferWithAuthorization` `eth_call` simulation — then
broadcasts the `transferWithAuthorization` meta-transaction through the
operator's relayer signer. The `settlement_tx` in the receipt is the real hash
on the external chain. This is the default when the block is configured;
the Coinbase CDP verifier remains an alternative route selected only when the
operator does not run a relayer. `tenzro_listX402Schemes` reports which is
active via `facilitator_mode` (`self-hosted` or `cdp`).

**Facilitator HTTP surface.** The `X402Facilitator` is mounted on the web API so a
resource server can forward a client's payment payload for verification and
settlement without embedding the flow itself: `POST /facilitator/x402/verify`
checks a payload against its requirements, `POST /facilitator/x402/settle`
executes the settlement (the operator's own relayer for external-chain EIP-3009 /
Permit2, or the consensus-mediated path for native TNZO), and
`GET /facilitator/x402/supported` advertises the schemes and chains the
facilitator settles.

### 13.7 Stripe SPT (SharedPaymentToken)

Stripe's SharedPaymentToken (SPT) is the token primitive that pairs with the MPP wire and Tempo settlement layers (the three layers of the Stripe agentic stack). Tenzro participates as a token issuer with TDIP-anchored cap enforcement:

- **Token lifecycle** — `StripeClient::create_issued_token` mints an issued token bound to a principal/agent DID pair with usage caps; `retrieve_granted_token` reads back the granted token Stripe returns to the agent; `confirm_intent_with_spt` confirms a Payment Intent against that granted token; `revoke_issued_token` tears it down. These live in `crates/tenzro-payments/src/mpp/stripe_spt.rs`.
- **`tenzro_stripeSptProtocolInfo`** — returns the SPT surface the node implements: client methods, the `SptStatus` lifecycle (`requires_action` → `active` → `used` / `deactivated`), and the ceiling model.
- **Four-ceiling enforcement** — a payment confirmed against an SPT must satisfy the principal's TDIP `DelegationScope`, the runtime `SpendingPolicy`, the SPT's own `usage_limits`, and — when the payment is carried by an AP2 mandate — the mandate's `total_amount`. The node-side `SptCeilingResolver` resolves `granted_token_id → SptCeilingSnapshot` for the check.
- **ERC-8004 ReputationRegistry cross-write** — `tenzro_processSptSettlementOutcome` writes a feedback entry to the ERC-8004 ReputationRegistry (precompile `0x101b`) keyed on the agent DID.
- **Webhook cascade** — `tenzro_processSptGrantedTokenDeactivated` dispatches Stripe's `granted_token.deactivated` webhook into TDIP `apply_remote_revocation`, which propagates the revocation to peers via the cascading-revocation broadcaster (§12.7).

### 13.8 Tempo Integration

Direct integration with the Tempo blockchain for stablecoin settlement:

- **TempoConfig** — Tempo network connection configuration
- **TempoBridgeAdapter** — Bridge adapter for cross-chain settlement to Tempo
- **Tip20Token** / **Tip20Balance** — TIP-20 stablecoin abstractions (USDC, USDT on Tempo)
- **TempoParticipant** — Direct participation in the Tempo network

### 13.9 Identity-Bound Payments

Payments are bound to TDIP identities through the `identity_binding` module. When a machine identity makes a payment, its delegation scope is enforced:

- Transaction value checked against `max_transaction_value`
- Payment protocol checked against `allowed_payment_protocols`
- Target chain checked against `allowed_chains`
- Daily spend accumulated and checked against `max_daily_spend`

### 13.10 ERC-8004 Trustless Agents Registry

ERC-8004 v0.6+ defines three on-chain registries (Identity, Reputation, Validation) for discovering and trusting agents across heterogeneous principal chains. Tenzro implements byte-identical selectors so the same calldata works against either the native Tenzro registry (precompiles `0x101a` / `0x101b` / `0x101c`) or the Ethereum mirror. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — it is server-allocated, never derivable client-side. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation for cross-system lookup.

**IdentityRegistry (12 surfaces):**

| RPC | Purpose |
|-----|---------|
| `tenzro_erc8004EncodeRegister {}` | Encode `register()` calldata (no-arg overload) |
| `tenzro_erc8004EncodeRegisterWithUri { agent_uri }` | Encode `register(string agentURI)` calldata |
| `tenzro_erc8004EncodeRegisterWithMetadata { agent_uri, metadata }` | Encode `register(string,(string,bytes)[])` calldata |
| `tenzro_erc8004EncodeGetAgent { agent_id }` / `tenzro_erc8004DecodeGetAgent { return_data }` | Read agent record |
| `tenzro_erc8004EncodeSetAgentURI { agent_id, metadata_uri }` | Update metadata URI |
| `tenzro_erc8004EncodeSetAgentWallet { agent_id, new_wallet, deadline, signature }` | Wallet rotation with EIP-712 signature |
| `tenzro_erc8004EncodeSetMetadata { agent_id, metadata_key, metadata_value }` | Per-key metadata write |
| `tenzro_erc8004EncodeGetMetadata { agent_id, metadata_key }` / `tenzro_erc8004DecodeGetMetadata { return_data }` | Per-key metadata read |
| `tenzro_erc8004EncodeGetAgentURI { agent_id }` / `tenzro_erc8004EncodeGetAgentWallet { agent_id }` | Convenience reads |

**ReputationRegistry (9 surfaces):**

| RPC | Purpose |
|-----|---------|
| `tenzro_erc8004EncodeFeedback { subject_agent_id, rating, context_uri, tag }` | Submit feedback (rating ∈ i8) |
| `tenzro_erc8004EncodeGetFeedback { feedback_id }` / `tenzro_erc8004EncodeGetFeedbackCount { subject_agent_id }` | Read feedback |
| `tenzro_erc8004EncodeRevokeFeedback { feedback_id }` / `tenzro_erc8004EncodeIsFeedbackRevoked { feedback_id }` | Revoke / check |
| `tenzro_erc8004EncodeAppendResponse { feedback_id, response_uri, response_hash }` / `tenzro_erc8004EncodeGetFeedbackResponses { feedback_id }` | Append + read responses |

**ValidationRegistry (3 surfaces):**

| RPC | Purpose |
|-----|---------|
| `tenzro_erc8004EncodeValidationRequest { validator_address, agent_id, request_uri, request_hash }` | Request validation |
| `tenzro_erc8004EncodeValidationResponse { agent_id, response_uri, response_hash }` | Submit validation result |
| `tenzro_erc8004EncodeGetValidation { validator_address, agent_id }` | Read validation record |

The Stripe SPT pipeline writes feedback entries into the ReputationRegistry on every settled outcome (paid / refunded / disputed), giving every Stripe-issued agent token a corresponding on-chain reputation footprint.

### 13.11 HTTP Middleware

The `tenzro-payments` crate provides axum middleware for automatic payment handling:
- Servers wrap their routes with payment middleware to auto-issue 402 challenges
- Clients use payment-aware HTTP clients that auto-create credentials

### 13.12 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `mpp` | Enabled | Machine Payments Protocol support |
| `x402` | Enabled | Coinbase x402 protocol support |
| `ap2` | Enabled | AP2 v0.2 sign + verify + validate-pair |
| `stripe-spt` | Enabled | Stripe SharedPaymentToken issuance + verify + cap-check |
| `erc8004` | Enabled | ERC-8004 v0.6+ Trustless Agents Registry encode/decode |
| `visa-tap` | Enabled | Visa Trusted Agent Protocol (TAP) — identity + delegation + audit layer for card-rail settlement |
| `mastercard-agent-pay` | Enabled | Mastercard Agent Pay SDK support |
| `tempo-bridge` | Disabled | Direct Tempo network settlement |

---

## 14. Cross-Chain Bridge

### 14.1 Overview

Tenzro connects to external blockchain ecosystems through bridge adapters that enable cross-chain asset transfers and message passing. Three adapters target public blockchain networks; a fourth provides enterprise connectivity to Canton synchronizers.

### 14.2 Public Blockchain Bridges

| Adapter | Protocol | Target Ecosystems |
|---------|----------|------------------|
| `LayerZeroAdapter` | LayerZero V2 | Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base |
| `ChainlinkCcipAdapter` | Chainlink CCIP | Ethereum, Polygon, Avalanche, Arbitrum, Optimism |
| `DeBridgeAdapter` | deBridge DLN | Ethereum, Solana, BNB Chain, Polygon, Arbitrum |

### 14.3 Bridge Router

The `BridgeRouter` selects the optimal adapter for each cross-chain operation based on:

| Strategy | Optimization Target |
|----------|-------------------|
| Cost | Minimize bridge fees |
| Speed | Minimize transfer time |
| Availability | Select adapter with highest uptime |

### 14.4 Message Format

All cross-chain messages use a standardized envelope:

```
BridgeMessage {
    message_id:     String,
    source_chain:   ChainId,
    dest_chain:     ChainId,
    sender:         Address,
    recipient:      Address,
    payload:        Vec<u8>,
    message_type:   BridgeMessageType,   // TokenTransfer | Message | ContractCall
    nonce:          u64,
    timestamp:      Timestamp,
}
```

Messages are wrapped in a `BridgeEnvelope` for transport:

```
BridgeEnvelope {
    message:    BridgeMessage,
    signatures: Vec<BridgeSignature>,
    proof:      Option<Vec<u8>>,
    adapter:    String,               // Which bridge adapter to use
    fee:        u128,
    status:     EnvelopeStatus,       // Pending | Sent | Confirmed | Failed
}
```

### 14.5 Replay Protection

Each bridge message includes a nonce and chain-specific identifiers. The bridge tracks processed message IDs in a `DashSet` to prevent replay attacks where the same message could be executed multiple times.

### 14.6 Canton Enterprise Integration

Tenzro nodes run Canton participant/validator processes natively, making every Tenzro validator a full participant in the Canton Network. Canton operates as a "network of networks" where participants connect to multiple synchronizers (formerly called "domains" in Canton 2.x) and contracts can be transferred between them atomically via a two-phase commit protocol coordinated by mediators.

Each Canton synchronizer consists of three components: a **Sequencer** (orders and timestamps messages), a **Mediator** (coordinates the two-phase commit confirmation protocol), and a **Topology Manager** (governs participant permissions, party-to-participant mappings, and package vetting). The **Global Synchronizer** is a public, permissionless synchronizer operated by Super Validators using BFT consensus, providing cross-synchronizer coordination for the entire Canton Network.

This architecture creates two distinct integration surfaces within Tenzro:

1. **VM execution (Section 4).** The `DamlExecutor` in `tenzro-vm` connects to the co-located Canton participant's Ledger API (gRPC, port 5001). Commands are submitted via `CommandService.SubmitAndWait`, active contracts are queried via `StateService.GetActiveContracts`, and transaction streams are consumed via `UpdateService.GetUpdates`. DAR packages are deployed through the Admin API (port 5002). Canton handles Daml contract lifecycle, sub-transaction privacy (parties only see events for contracts where they are stakeholders), and multi-synchronizer consensus. Results are translated back into Tenzro's unified `ExecutionResult` format. Because the Canton participant runs within the Tenzro node process, there is no external dependency — Daml execution is as native as EVM or SVM execution.

2. **Cross-synchronizer bridge (this section).** The `CantonAdapter` in `tenzro-bridge` enables asset transfers and message passing between Tenzro's Canton synchronizer and external Canton synchronizers operated by other institutions. Canton provides native cross-synchronizer atomicity through the Global Synchronizer, eliminating the need for traditional bridge mechanisms — transfers use Canton's two-phase commit protocol coordinated by the mediator. The adapter implements the same `BridgeAdapter` interface as the public blockchain bridges, allowing the bridge router to select Canton as a transfer path when the destination is an enterprise Canton deployment.

The `CantonAdapter` supports:
- Cross-synchronizer asset transfers via Daml Exercise commands, coordinated through the Global Synchronizer
- Synchronizer discovery and fee estimation (fees denominated in Canton Coin, the native utility token burned for Global Synchronizer usage)
- Daml contract creation and exercise via bridge messages
- Transfer status tracking with ~5 second finality (sequencer timestamp + mediator confirmation)

Canton topology is managed through topology transactions: `NamespaceDelegation`, `PartyToParticipant`, `OwnerToKeyMapping`, `VettedPackages`, and `ParticipantSynchronizerPermission`. Party identifiers follow the format `name::fingerprint` where the fingerprint is derived from the namespace's signing key.

By running Canton validators directly, Tenzro gains the enterprise-grade privacy and composability guarantees of the Canton Network — including sub-transaction privacy, need-to-know data sharing, atomic multi-synchronizer transfers, and regulatory-compliant smart contracts — without requiring users to interact with a separate ledger.

### 14.7 Multi-Party Workflows on Canton

The `tenzro-workflow` crate is a Canton-native multi-party workflow engine that turns a Tenzro chain transaction into a structured, multi-stakeholder process: a workflow has a typed lifecycle, a set of obligations distributed across counterparties, an approvals graph, fee routing, optional privacy domains, a kill-switch path, and a hash-chained audit receipt — all mirrored into Canton's Daml runtime through the same participant node used by §14.6.

#### 14.7.1 Workflow object model

A workflow is a `Workflow` value with the following fields:

| Field | Description |
|-------|-------------|
| `id` | `WorkflowId` derived from `SHA-256("tenzro/workflow/id" \|\| initiator \|\| nonce_le \|\| template_id)` |
| `template_id` | Reference to the workflow template (`AutonomousProcurement`, `BridgeArbitrage`, etc.) |
| `initiator_did` | TDIP DID of the workflow originator |
| `counterparties` | Ordered set of TDIP DIDs that must sign or act on the workflow |
| `obligations` | Per-counterparty `Obligation` records: `{ counterparty_did, action, deadline, status }` |
| `approvals` | `Approval` records gated by `policy_dsl` expressions (see §14.7.5) |
| `fee_route_id` | Optional reference to a `FeeRoute` used for settlement payouts |
| `privacy_domain_id` | Optional reference to a `PrivacyDomain` (see §14.7.4) |
| `state` | `WorkflowState`: `Draft → Active → AwaitingSignatures → Executing → Completed`, with terminal `Cancelled`, `Disputed`, `Failed`, `Suspended` |
| `signatures` | Map of `did → Signature` accumulating multi-party consent |

State transitions are validated by a fixed transition table; an invalid edge is rejected at the manager API surface, not silently coerced.

#### 14.7.2 Privileged-VM selectors

Workflow writes flow through signed transactions dispatched by the Native VM, not RPC, so they are consensus-mediated and replayable from block history. The privileged-VM selectors are:

| Selector | Operation | Description |
|----------|-----------|-------------|
| `0x01000040` | `CreateWorkflow` | Initialize a new workflow with template + counterparties |
| `0x01000041` | `SubmitSignature` | Add a signature to `AwaitingSignatures` workflow |
| `0x01000042` | `CompleteObligation` | Mark an obligation as fulfilled |
| `0x01000043` | `RecordApproval` | Record a policy-gated approval |
| `0x01000044` | `TransitionState` | Advance the state machine |
| `0x01000045` | `RegisterFeeRoute` | Register a recipient/share fee route |
| `0x01000046` | `RegisterPrivacyDomain` | Register a privacy domain with ACL |
| `0x01000047` | `MirrorToCanton` | Mirror a receipt to Canton via the participant node |
| `0x01000048` | `KillSwitchSuspend` | Suspend a workflow (initiator-only or governance-only) |
| `0x01000049` | `KillSwitchCancel` | Cancel a suspended workflow |
| `0x0100004A` | `OpenDispute` | Move a workflow into `Disputed` |
| `0x0100004B` | `ResolveDispute` | Close a dispute with payout direction |

All selectors enforce signer-vs-counterparty authorization at execution; an unauthorized signer returns a typed `WorkflowError::Unauthorized` instead of producing a partially-applied state.

#### 14.7.3 Canton receipt mirror

Every successful workflow state transition produces a `WorkflowReceipt`:

```
WorkflowReceipt {
  id: Hash,                        // SHA-256(canonical receipt bytes)
  workflow_id: WorkflowId,
  state_before: WorkflowState,
  state_after: WorkflowState,
  signer: Did,
  block_height: BlockHeight,
  prev_receipt: Hash,              // hash-chain link
  payload_envelope: ReceiptEnvelope, // inline summary or DA pointer
}
```

Receipts are persisted to RocksDB under `wf_receipt:<id>` (see §17) and the **chain head** is stored in the workflow's `WorkflowMeta.last_receipt`. The full receipt history is recovered by walking `prev_receipt` backwards from the head until `Hash::default()` (genesis). For audit, `tenzro_listWorkflowReceipts` walks up to `max` entries; receipts are not held in memory.

When a workflow is mirrored to Canton (selector `0x01000047`), the same receipt is projected into a `Tenzro.Workflow.Receipt` Daml template via the co-located participant's Ledger API. The Daml template carries the `ReceiptEnvelope` payload either inline (small payloads, defaults: settlement, kill-switch, lifecycle, governance) or as a `DaPointer` reference (large payloads, defaults: settlement-channel, inference, agent-message — see §17), and the originating Tenzro chain's `block_height + receipt_id` is recorded as the cross-ledger anchor. Canton's sub-transaction privacy ensures that only the workflow's stakeholders observe the mirrored receipt.

#### 14.7.4 Privacy domains

A `PrivacyDomain` is a named ACL of TDIP DIDs that gates encrypted payloads:

```
PrivacyDomain {
  id: PrivacyDomainId,
  initiator_did: Did,
  acl: BTreeSet<Did>,              // members + auditors
  auditors: BTreeSet<Did>,         // subset of acl with broader read scope
  frozen: bool,                    // governance-froze new sealings
  created_at: Timestamp,
}
```

Workflows that opt into a privacy domain seal their `Workflow.payload` and event payloads with a domain key shared among the ACL. The `seal/open` round-trip is symmetric AES-256-GCM with the domain key derived per the standard `tenzro-crypto` envelope-encryption flow (§7). Auditors inside the ACL can `open` payloads they were never explicit recipients of; non-members and non-auditors cannot. A frozen domain refuses new `seal` operations but permits existing payloads to continue being opened — the data-retention contract is preserved across governance-driven freezes.

#### 14.7.5 Policy DSL

Approvals on a workflow are gated by a small DSL evaluated against a `PolicyContext` containing `{ now, signer, counterparties, accumulated_amount_today, kyc_tiers, ... }`. Expressions evaluate to `PolicyOutcome::{ Allow, Deny, RequireApproval(approver_did) }`. Combinators:

- `amount_lte(N)` / `daily_amount_lte(N)` — numeric ceilings
- `counterparty_kyc_tier_gte(tier)` — KYC gating
- `time_window(start, end)` — wraps around midnight; supports business-hours
- `and(left, right)` — short-circuits on `Deny`; `RequireApproval` propagates if either branch requires
- `or(left, right)` — short-circuits on `Allow`; collapses to `RequireApproval` when no branch allows but at least one branch requires
- `not(inner)` — flips `Allow ⇄ Deny`; `RequireApproval` is a no-op under negation

The DSL is tree-shaped, terminating, and pure — it has no side effects and no I/O — which makes it safe to evaluate inside the Native VM during selector dispatch.

#### 14.7.6 Fee routing

A `FeeRoute` is a static recipient table:

```
FeeRoute {
  id: FeeRouteId,
  recipients: Vec<FeeRouteRecipient {
    recipient_did: Did,
    label: String,
    share_bps: u16,                // basis points; sum of all = 10_000
  }>,
}
```

`compute_fee_route_payouts(route, gross_wei: u128)` returns per-recipient payout amounts using basis-point splits with truncation; any rounding remainder is added to the last recipient so the sum of payouts equals the gross. The RPC `tenzro_computeFeeRoutePayouts` exposes this as a read-only preview; actual settlement payouts move through the consensus-mediated escrow primitive (§9), not the preview RPC.

#### 14.7.7 Kill switch

Two privileged-VM selectors, `KillSwitchSuspend` (`0x01000048`) and `KillSwitchCancel` (`0x01000049`), provide a defined emergency-stop path:

- **Suspend** moves the workflow into `Suspended`. It is callable by the initiator at any time and by governance-bound DIDs (per `IdentityRegistry::enforce_operation`) at any time.
- **Cancel** moves a `Suspended` workflow into terminal `Cancelled`. It is callable only by the initiator after the workflow has been suspended.

A suspended workflow rejects all writes except `KillSwitchCancel` and dispute selectors. The pair removes the only condition under which an autonomous agent could be trapped in a non-responsive multi-party flow it initiated.

#### 14.7.8 Operational metrics

`WorkflowRuntime::operational_metrics()` returns an `OperationalMetrics` snapshot computed by walking the in-memory workflow / obligation / approval indices once and partitioning by status. The snapshot is rendered by `OperationalMetrics::render_prometheus()` into the standard text exposition format with `# HELP` and `# TYPE` headers per metric and `BTreeMap` ordering for deterministic output. It is exposed through the node's `/metrics` endpoint and graphed by `deploy/monitoring/grafana-workflow-dashboard.json` (UID `tenzro-workflow`):

| Metric | Type | Labels |
|--------|------|--------|
| `tenzro_workflow_workflows_total` | gauge | `status` |
| `tenzro_workflow_obligations_total` | gauge | `status` |
| `tenzro_workflow_approvals_total` | gauge | `status` |
| `tenzro_workflow_signatures_collected_total` | counter | — |
| `tenzro_workflow_canton_mirrored_total` | counter | — |
| `tenzro_workflow_fee_routes_total` | gauge | — |
| `tenzro_workflow_privacy_domains_total` | gauge | — |

#### 14.7.9 RPC, MCP, and A2A surfaces

Read-only access is exposed across all three external surfaces:

- **JSON-RPC** (port 8545): `tenzro_getWorkflow`, `tenzro_getWorkflowLifecycle`, `tenzro_listWorkflowsByCreator`, `tenzro_listWorkflowsByParticipant`, `tenzro_listWorkflowsByStatus`, `tenzro_getObligation`, `tenzro_getApproval`, `tenzro_getWorkflowReceipt`, `tenzro_listWorkflowReceipts`, `tenzro_getFeeRoute`, `tenzro_listFeeRoutes`, `tenzro_computeFeeRoutePayouts`, `tenzro_getPrivacyDomain`, `tenzro_listPrivacyDomainsForDid`, `tenzro_getWorkflowOperationalMetrics`.
- **MCP** (port 3001): the same surface mirrored as `#[tool]`-defined methods on the main MCP server — `get_workflow`, `get_workflow_lifecycle`, `list_workflows_by_creator`, `list_workflows_by_participant`, `list_workflows_by_status`, `get_obligation`, `get_approval`, `get_workflow_receipt`, `list_workflow_receipts`, `get_fee_route`, `list_fee_routes`, `compute_fee_route_payouts`, `get_privacy_domain`, `list_privacy_domains_for_did`, `get_workflow_operational_metrics`.
- **A2A** (port 3002): the `workflow` skill on the Tenzro Agent Card surfaces all of the above through natural-language utterances, allowing peer agents to query workflow state, obligations, fee-route payouts, privacy domains, and Canton mirror status without bespoke RPC integration.

Writes never occur through these surfaces — every state-changing operation is a privileged-VM selector dispatched by a signed transaction submitted via `tenzro_signAndSendTransaction` or `eth_sendRawTransaction`, ensuring the Tenzro chain's full block history is the canonical workflow log.

#### 14.7.10 Reference templates

Five reference workflow templates live under `crates/tenzro-workflow/reference_workflows/`, each paired with a `*_daml_map.json` describing the Canton DAML projection:

| Template | Pattern |
|----------|---------|
| `autonomous_procurement` | Buyer/seller/auditor procurement on Canton with DvP |
| `autonomous_treasury` | Multi-sig treasury operations with policy-gated approvals |
| `dvp_settlement` | Delivery-vs-payment settlement on a Canton synchronizer |
| `environmental_mrv` | Environmental measurement / reporting / verification with auditor sign-off |
| `supply_chain_dpp` | Supply-chain digital product passport with multi-party attestations |

Each template defines its `WorkflowSpec` (counterparty roles, obligation set, approvals graph, fee route, privacy domain) and is instantiated at runtime via `tenzro-agent-kit`'s spawner. The agent-kit `reference_templates/` directory carries a separate set of agent templates (inference marketplace, RWA custodian, bridge arbitrage scanner, etc.) that may originate workflows but are not themselves workflow specs.

---

## 14a. Sandboxed Skills (WASI 0.2 Component Runtime)

The `tenzro-wasm` crate is the sandboxed runtime that executes community-supplied agent skills, MCP tools, and A2A skill components. It is not a transactional VM — execution stays on the EVM / SVM / DAML stack. The component runtime hosts application-layer code that needs untrusted-safe isolation.

### 14a.1 Component manifest

Every component carries a `ComponentManifest` declaring `id`, `version`, `content_hash_hex` (SHA-256 of the bytes), `runtime` (`wasi-component` / `agent-skill` / `mcp-tool`), `capabilities`, `deadline_ms`, and `fuel_limit`. The runtime re-hashes the bytes at registration and rejects manifests whose declared hash does not match.

### 14a.2 Capability model

`SkillCapabilities` declares the storage, network, environment, and `host_methods` a component requests. Defaults are deny-all. Storage uses the WASI 0.2 `preopens` model with explicit `(host_path, guest_path)` mounts. Network is gated by host allow-lists; HTTPS access is mediated via the `tenzro:net/https` host interface so the node can audit every URL. Host methods are an explicit allow-list — `wallet.read_balance`, `events.publish`, `inference.embed`, etc. — checked by the host's `HostInterface` policy.

### 14a.3 Fuel and deadlines

Wasmtime fuel metering counts WASM operations; epoch interruption enforces wall-clock deadlines. Two executions of the same component with the same input return identical fuel reports. Default deadline is 10s, default fuel budget is 50,000,000 units; both are overridable by the manifest.

### 14a.4 Execution receipts

`ExecutionReceipt { component_id, content_hash_hex, function, input_hash_hex, output_hash_hex, outcome, fuel: FuelReport, completed_at_ms }`. Outcome variants: `Success`, `Trapped`, `FuelExhausted`, `DeadlineExceeded`, `HostContractViolation`. Receipts chain into `ReceiptEnvelope` records (see §9 Settlement).

### 14a.5 Engine

`WasmEngine` wraps a process-wide Wasmtime `Engine` configured with component-model on, async support on, consume_fuel on, epoch-interruption on, Cranelift `Speed`, pooling allocator, parallel compilation. `wasm_reference_types` and `wasm_relaxed_simd` are explicitly off to keep behavior deterministic.

### 14a.6 Embed points

- `tenzro-agent-kit::executor` — alternative skill runtime when the template's manifest declares `runtime: agent-skill`. Behind the `wasi-skills` feature flag.
- `tenzro-node::mcp::wasm_tools::SandboxedToolRegistry` — sandboxed host for community MCP tools. Same feature flag.

### 14a.7 Public surface

```text
WasmEngine               process-wide Wasmtime engine
SkillRuntime             per-host runtime with component registry
ComponentManifest        declarative metadata
SkillCapabilities        sandbox grants
HostInterface (trait)    node-side dispatcher for `tenzro:*` calls
ExecutionReceipt         result of an invocation
```

---

## 15. Self-Custody, Wallets, and Key Management

Tenzro is a self-custodial network across all three identity classes — humans, delegated agents, and autonomous machines. No node, validator, or service provider holds the cryptographic material required to authorize a transaction on a user's behalf. Custody is rooted in hardware-backed keys on the user's own device (passkey in Secure Enclave / StrongBox / TPM 2.0 / Windows Hello), in a TEE-sealed key for autonomous machines (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA H100 CC), and — where threshold signing is desired — in a true MPC protocol (FROST-Ed25519, RFC 9591) where no party ever materializes the master key.

This section specifies the full surface: design principles, the six interlocking pillars (P-256 / WebAuthn, ERC-7579 modular validators, ERC-7484 module registry, ERC-7702 sponsored bootstrap, FROST-Ed25519 threshold signing, TEE-resident agent keys), hybrid post-quantum behavior across each, and the developer experience — both the opinionated "passkey wallet in three lines" SDK and the lower-level `Signer` / `Validator` / `KeyStorage` / `RecoveryGuardian` traits that custom wallet developers extend to build their own designs.

### 15.0 Design Principles

**1. Self-custody by default, on every identity class.** A human's wallet, a delegated agent's session key, and an autonomous machine's bootstrap key all derive from material that the user, controller, or TEE — not the node — exclusively holds. Server-custodial flows are not a supported configuration.

**2. Hardware-backed keys, never software keys, never seed phrases.** The default key for a human is a passkey in the platform authenticator (Apple Secure Enclave, Android StrongBox, Microsoft Pluton / Windows Hello, TPM 2.0). The default key for an autonomous machine is generated and sealed inside a remote-attestable TEE. Mnemonic seed phrases are not part of the recovery surface — recovery is performed through a guardian set on a smart account.

**3. Custody is enforced at signing time by code the model cannot influence.** For delegated and autonomous agents, every spending or operational ceiling — cap, scope, time-bound, allowed counterparty, allowed payment protocol — must be enforced cryptographically inside an ERC-7579 validator module that the EntryPoint consults during `validateUserOp`. Off-chain admission gates (`SpendingPolicyResolver`, `IdentityPaymentBinder`) remain as defense-in-depth, but a malicious node operator must not be able to accept an out-of-scope `UserOperation` from any agent.

**4. Two parallel developer paths.** The SDK exposes both a fully opinionated high-level surface (passkey wallet, three lines, biometric-gated, automatic cross-device fallback) and a fully unopinionated low-level surface (the `Signer` / `Validator` / `KeyStorage` traits) that custom wallet developers extend to build their own key-management designs (custom MPC topology, custom HSM integration, air-gapped flows, social-recovery topologies). The high-level API is a default implementation of the trait surface — there is no escape hatch and no internal-only API.

**5. Force biometric-capable authenticator, fall back to phone via QR.** The default UX rejects software-only authenticators. If the current device lacks a platform authenticator (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() === false`), the SDK MUST default to the FIDO **hybrid transport** (caBLE — QR + Bluetooth proximity) so that the desktop solicits the signature from the user's phone passkey without ever holding the key. This mirrors the pattern that converged across Coinbase Smart Wallet, Privy, and Daimo.

**6. Hybrid post-quantum at every layer that the standards permit.** Classical primitives are paired with their NIST FIPS 203/204 post-quantum companions: Ed25519 with ML-DSA-65 for signatures, X25519 with ML-KEM-768 for KEM. Where a standard is single-algorithm (P-256 inside a passkey, secp256k1 inside an EVM EOA), the classical algorithm is used as specified and the PQ companion lives in the on-chain validator metadata rather than in the device key — there is no production threshold ML-DSA in 2026, so threshold-PQ is deferred to a single-key-in-TEE design until the research matures.

**7. One custody model, no fallbacks.** The wallet surface has exactly one custody mode: self-custodial. There is no server-custodial configuration, no reconstruct-on-the-node key assembly, and no alternate provisioning path an operator can select.

### 15.1 Identity Classes and Custody Targets

| Class | Signing key | Storage | On-chain validator | Recovery | Bootstrap |
|---|---|---|---|---|---|
| **Human** | Hybrid Ed25519 + ML-DSA-65, materialized as 2-of-2: passkey P-256 device share (WebAuthn) + TEE share or guardian-quorum share | Passkey in Secure Enclave / StrongBox / Pluton / TPM 2.0; second share hardware-sealed in a TEE or held by a guardian set | ERC-7579 modular validator with WebAuthn + Ed25519 + (optional) TEE side-by-side, routed per UserOp | ERC-4337 v0.8 smart-account guardian set (3-of-5 default, time-locked) under hybrid PQ | Standard onboarding (`tenzro_participate`) registers the smart account, attaches the WebAuthn validator, and binds the TDIP identity |
| **Delegated agent** | Ed25519 (Tenzro-native) or P-256 (Coinbase-class) **session key** bound to the controller's primary identity | Same hardware-backed storage as the controller, scoped sub-credential | `DelegationScopeValidator` ERC-7579 module that consumes the TDIP `DelegationScope` on-chain — any `UserOp` outside scope returns ≠ magic value, so no signature is ever valid out-of-scope | Inherits the controller's recovery; revocation via per-DID monotonic epoch counter that invalidates all outstanding session keys | Controller spawns the agent and signs the delegation; agent receives a session key with cryptographically-bounded authority |
| **Autonomous machine** | Hybrid Ed25519 + ML-DSA-65 generated **inside the TEE** at bootstrap | Hardware-sealed (TDX / SEV-SNP / Nitro / H100 CC), never extractable | `TeeBoundValidator` requiring fresh remote attestation (≤24h freshness) on every `UserOp` | New attestation cycle = key rotation; `AgentBond` stake + insurance pool back accountability | ERC-7702 sponsored first transaction via the TNZO paymaster, gated on a valid TEE attestation — no prefunding required |

### 15.2 Pillar 1 — P-256 (secp256r1) Precompile

Modern platform authenticators use P-256 (secp256r1) exclusively. To verify WebAuthn signatures cheaply on-chain, Tenzro implements the [RIP-7212](https://github.com/ethereum/RIPs/blob/master/RIPS/rip-7212.md) precompile semantics with Ethereum mainnet ([EIP-7951](https://eips.ethereum.org/EIPS/eip-7951), live since the Fusaka activation on 2025-12-03) gas pricing for forward compatibility:

| Property | Value |
|---|---|
| Address | `0x0000000000000000000000000000000000000100` |
| Gas cost | **6,900** (matches EIP-7951 mainnet, not the 3,450 rollup variant) |
| Input length | 160 bytes — `hash(32) ‖ r(32) ‖ s(32) ‖ x(32) ‖ y(32)` |
| Output (success) | 32 bytes: `0x000…001` |
| Output (failure) | empty bytes — the precompile **never reverts** |
| Curve | secp256r1 (NIST P-256), uncompressed public key encoded as `x ‖ y` |

This is the second on-chain curve Tenzro supports natively (alongside secp256k1 for EVM compatibility) and unlocks every passkey-bound use case downstream — WebAuthn validators, session keys signed by the platform authenticator, and cross-chain delegation receipts that originated on a phone.

### 15.3 Pillar 2 — ERC-7579 Modular Smart Accounts

Every Tenzro smart account is built on the [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) modular interface so that authorization logic can be added, swapped, or revoked without redeploying the account. The account stores a registry of installed modules; for each `UserOperation`, the EntryPoint calls into the account's selected validator module:

```solidity
function validateUserOp(
    PackedUserOperation calldata userOp,
    bytes32 userOpHash
) external returns (uint256 validationData);
```

A `validationData` of `0` signals the signature and any time bounds are valid; non-zero packs an `ERC-4337` aggregator address, validity window, and failure flag. Module types defined by ERC-7579 are: `1 = Validator`, `2 = Executor`, `3 = Fallback`, `4 = Hook`. Tenzro implements four validator modules:

| Module | Purpose | Identity classes |
|---|---|---|
| `WebAuthnValidator` | Verifies a P-256 / WebAuthn signature against a registered passkey credential. Re-derives `clientDataJSON` hash + `authenticatorData` per the WebAuthn L3 spec, then dispatches to the `0x100` precompile. | Human |
| `Ed25519Validator` | Verifies a native Ed25519 signature against a registered public key. Used for FROST-aggregated signatures (which present as a single Ed25519 signature) and direct Ed25519 session keys. | Human, Delegated agent |
| `DelegationScopeValidator` | Consumes the TDIP `DelegationScope` and rejects any `UserOp` outside the cap / scope / time / counterparty / payment-protocol envelope **before** signature verification. Backed by a per-DID monotonic epoch counter for revocation. | Delegated agent |
| `TeeBoundValidator` | Requires a fresh (≤24h) remote-attestation quote (TDX, SEV-SNP, Nitro, or NVIDIA NRAS) signed by the TEE-resident keypair, verified against the pinned vendor root CA chain in `tenzro-tee`. | Autonomous machine |

Multiple validator modules can be installed side-by-side; the calldata of `userOp.signature` selects which validator runs (the first 4 bytes of the signature payload encode the validator selector, mirroring Rhinestone Nexus and Kernel v3 conventions).

### 15.4 Pillar 3 — ERC-7484 Module Registry

Validator modules — particularly third-party modules contributed by wallet developers — are looked up against the [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484) module registry, deployed as a singleton at the same address across all chains:

```
0x000000000069E2a187AEFFb852bF3cCdC95151B2
```

Tenzro mirrors this registry as a privileged-VM precompile so that a smart account can verify a module's attestation status without an out-of-VM call. Account installation flows reject modules without an attestation from a configured attester set (default: the account owner's chosen attesters; the network does not impose a global allowlist).

### 15.5 Pillar 4 — ERC-7702 Sponsored Bootstrap

Newly-spawned autonomous machines have a TEE-attested key but no TNZO. To let them act on their first transaction without prefunding, Tenzro implements [ERC-7702](https://eips.ethereum.org/EIPS/eip-7702) (live on Ethereum since the Pectra activation in May 2025):

| Property | Value |
|---|---|
| Transaction type | `0x04` |
| Authorization tuple | `[chain_id, address, nonce, y_parity, r, s]` |
| `chain_id == 0` | Permitted (per spec) for universal authorization across Tenzro's chains |
| Code slot value | `0xef0100 ‖ delegate_addr` (3-byte magic prefix `0xef0100`) |

The **TNZO paymaster** sponsors the gas for this first transaction iff the agent presents a valid TEE attestation that resolves to a registered ERC-8004 agent. The 7702-delegated EOA points at a TenzroSmartAccount with a `TeeBoundValidator` installed, so the agent is a smart account from its first action onward.

### 15.6 Pillar 5 — FROST-Ed25519 Threshold Signing

Where threshold signing is required (multi-device wallets, treasury policies, swarm-MPC across N TEE-attested agents), Tenzro uses **FROST** (Flexible Round-Optimized Schnorr Threshold signatures, [RFC 9591](https://datatracker.ietf.org/doc/rfc9591/)) over Ed25519. See §7.3 for the cryptographic specification. The protocol-level guarantees:

- **No party ever holds the master key.** DKG produces a single group public key and `n` shares; the secret behind the group key is never materialized — even at signing time, only round-2 outputs are aggregated.
- **Output is a standard 64-byte Ed25519 signature.** It verifies under the existing `Ed25519Validator` module with no protocol-specific verifier — every downstream consumer (RPC, MCP, A2A, EntryPoint) treats it as an ordinary signature.
- **t-of-n is configurable per account.** Default for human multi-device wallets is `2-of-3` (phone + laptop + guardian). Default for swarm-MPC across TEE agents is `(2/3)·n`.

The reference implementation is [`frost-ed25519`](https://github.com/ZcashFoundation/frost) maintained by the Zcash Foundation. Other FROST variants from the same crate family (`frost-secp256k1-tr` for Bitcoin Taproot) are available behind the same trait but out of scope for Tenzro Ledger.

PQ note: there is **no production threshold ML-DSA** in 2026 — Trilithium and similar constructions remain research (eprint 2025/675). For the PQ companion in a hybrid wallet, the `ML-DSA-65` key is held single-instance inside a TEE or HSM and signed alongside the FROST-Ed25519 aggregate. The hybrid signature thus verifies as `Ed25519(group) ∧ ML-DSA-65(tee)` — a downgrade attack on either layer fails.

### 15.7 Pillar 6 — TEE-Resident Agent Keys

For autonomous machines, the signing keypair is generated and sealed **inside** the TEE at bootstrap. Tenzro extends `tenzro-tee` with three operations:

| Operation | Behavior |
|---|---|
| `seal_agent_keypair(tee_session)` | Inside the enclave: generate Ed25519 + ML-DSA-65 hybrid keypair, derive the public key, seal the secret with the TEE's hardware-bound MKTME / VMSA / KMS / CC-memory key. The secret never leaves the TEE. |
| `attest_agent_key(tee_session, public_key)` | Produce a fresh remote-attestation quote that binds the agent's public key into the report data. Verified against the pinned vendor root CA chain (Intel PCS for TDX, AMD KDS for SEV-SNP, AWS for Nitro, NVIDIA NRAS for H100 CC). |
| `rotate_agent_key(tee_session)` | Generate a new sealed keypair and emit a fresh attestation; old key is wiped from the sealed store. Rotation is gated by the on-chain `TeeBoundValidator` requiring a ≤24h-fresh attestation. |

Bootstrap ties to ERC-8004: the agent registers in the IdentityRegistry at `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` (live mainnet 2026-01-29) — note that ERC-8004 assigns a sequential ERC-721 `tokenId` at registration, **not** a `keccak256` of the DID string. Tenzro's native ERC-8004 precompiles (`0x101a` / `0x101b` / `0x101c`) mirror this semantics so cross-registry calldata interop holds.

The closest production reference for TEE-resident agent identity is [Phala dstack](https://github.com/Dstack-TEE/dstack), donated to the Linux Foundation in 2025.

### 15.8 Hybrid Post-Quantum Behavior

| Layer | Classical | PQ companion | Notes |
|---|---|---|---|
| Native ledger transaction signing | Ed25519 | ML-DSA-65 (FIPS 204) | Both signatures attached; verifier requires both. Tenzro is ahead of industry — no production wallet carries a hybrid signature through its whole signing path as of mid-2026. |
| Passkey / WebAuthn | P-256 | (none on device) | Single-curve by spec. PQ companion lives in the on-chain validator metadata rather than the platform authenticator. |
| FROST threshold | Ed25519 (group sig) | ML-DSA-65 (single key in TEE/HSM) | No production threshold ML-DSA exists in 2026. Hybrid achieved by signing alongside the FROST aggregate, not over it. |
| TLS / RPC transport | X25519 | ML-KEM-768 (FIPS 203) | Already deployed in Caddy on the testnet. Hybrid by default for RPC, MCP, A2A. |

### 15.9 Recovery and Revocation

Recovery is performed at the smart-account layer, not by reconstructing key material:

- **Human accounts** install a `SocialRecovery` ERC-7579 module backed by a guardian set (default 3-of-5, time-locked 48 hours). Guardians can be other Tenzro identities, hardware tokens (YubiKey FIDO2), or third-party recovery services.
- **Delegated agent accounts** inherit recovery from the controller. Revocation is instant: the controller increments a per-DID monotonic epoch counter, and the `DelegationScopeValidator` rejects any session-key signature that does not match the current epoch.
- **Autonomous machine accounts** "rotate" by re-running the TEE attestation cycle; the `TeeBoundValidator`'s freshness window (≤24h) bounds the worst-case window of a stale or compromised key.

Cross-node revocation is broadcast over the existing TDIP `RevocationBroadcaster` channel and applied through `IdentityVerifier::apply_remote_revocation()` (see §12).

### 15.10 Developer Experience

The SDK exposes two parallel surfaces. **Both are public and supported.** The high-level surface is a default implementation built on top of the trait surface — there is no internal-only API.

#### 15.10.1 High-Level: Passkey Wallet in Three Lines

```ts
import { createPasskeyWallet, signWithPasskey } from "@tenzro/sdk";

const wallet = await createPasskeyWallet({ rpId: "keys.tenzro.xyz" });
const sig = await signWithPasskey(wallet, userOp);
```

```rust
use tenzro_sdk::passkey::{PasskeyWallet, PasskeyConfig};

let wallet = PasskeyWallet::create(PasskeyConfig::production("keys.tenzro.xyz")).await?;
let sig = wallet.sign_user_op(user_op).await?;
```

UX behavior the SDK enforces by default:

1. Calls `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`. If `false`, the SDK **must** request a cross-platform authenticator (`authenticatorAttachment: "cross-platform"`, `userVerification: "required"`) and render a QR for the FIDO hybrid transport (caBLE). It never silently falls back to a software key.
2. The WebAuthn ceremony is hosted on `keys.tenzro.xyz` so the resulting credential's RP ID is a stable registrable domain that survives URL redesigns and works across every Tenzro frontend.
3. The resulting P-256 public key is registered as the account's `WebAuthnValidator` module on first use (one transaction, gas-sponsored by the TNZO paymaster via ERC-7702).
4. Signing always raises a biometric prompt on the device that holds the passkey — Touch ID, Face ID, Windows Hello, Android biometric.

#### 15.10.2 Low-Level: Pluggable Trait Surface

Custom wallet developers extend the following traits to build their own designs (custom MPC topology, custom HSM integration, air-gapped flows, social-recovery topologies):

```rust
#[async_trait]
pub trait Signer: Send + Sync {
    fn describe(&self) -> SignerKind;
    async fn sign(&self, hash: [u8; 32], context: &SignContext) -> Result<Signature, SignerError>;
}

#[async_trait]
pub trait Validator: Send + Sync {
    fn module_address(&self) -> Address;
    fn module_type(&self) -> Erc7579ModuleType;
    async fn build_validator_data(&self, user_op: &PackedUserOperation) -> Result<Bytes, ValidatorError>;
}

#[async_trait]
pub trait KeyStorage: Send + Sync {
    async fn store(&self, key_id: &KeyId, blob: &[u8], policy: StoragePolicy) -> Result<(), StorageError>;
    async fn load(&self, key_id: &KeyId) -> Result<Vec<u8>, StorageError>;
    fn capabilities(&self) -> StorageCapabilities; // HardwareBacked, BiometricGated, Exportable, …
}

#[async_trait]
pub trait RecoveryGuardian: Send + Sync {
    async fn propose_recovery(&self, account: Address, new_owner: PublicKey) -> Result<RecoveryProposal, RecoveryError>;
    async fn approve_recovery(&self, proposal: &RecoveryProposal) -> Result<GuardianSignature, RecoveryError>;
    async fn execute_recovery(&self, proposal: RecoveryProposal, sigs: Vec<GuardianSignature>) -> Result<TxHash, RecoveryError>;
}

pub enum SignerKind {
    WebAuthn { credential_id: Vec<u8> },
    Ed25519,
    Frost { threshold: u16, total: u16 },
    Tee { backend: TeeBackend },
    Hsm { vendor: String },
    Custom(String),
}
```

The TypeScript SDK exposes a parallel surface (`Signer`, `Validator`, `KeyStorage`, `RecoveryGuardian`) so JS/TS wallets get the same extension points.

#### 15.10.3 Reference Compositions

The cookbook contains ready-made compositions covering the common topologies, each implementing the same traits:

| Composition | `Signer` | `KeyStorage` | `Validator` |
|---|---|---|---|
| `passkey-only` | WebAuthn | Platform authenticator | `WebAuthnValidator` |
| `passkey + tee` | WebAuthn (1 of 2) + TEE share (1 of 2) | Platform authenticator + TEE | `WebAuthnValidator` + `Ed25519Validator` (2-of-2 routing) |
| `frost-multi-device` | FROST-Ed25519 (2-of-3) | Per-device hardware-backed | `Ed25519Validator` (single aggregate) |
| `tee-only-agent` | TEE-resident Ed25519 + ML-DSA-65 | Hardware-sealed TEE | `TeeBoundValidator` |
| `delegated-session` | Ed25519 (session key) | Inherited from controller's storage | `DelegationScopeValidator` |
| `air-gapped` | Custom (off-machine signer) | None (key never on this host) | `Ed25519Validator` |

#### 15.10.4 Tauri Desktop Integration

The desktop application stores keys in the OS keychain via Rust-side commands — the Tauri WebView does **not** reliably reach the platform authenticator, so all WebAuthn ceremonies are dispatched from Rust:

| Platform | Backend | Hardware key location |
|---|---|---|
| macOS | `security-framework` with `kSecAttrTokenIDSecureEnclave` | Secure Enclave (T2 / Apple Silicon) |
| iOS | `security-framework` + LAContext biometric prompt | Secure Enclave |
| Android | JNI to `android.security.keystore.KeyGenParameterSpec` with `setIsStrongBoxBacked(true)` | StrongBox |
| Windows | `tss-esapi` 7.6 + Windows Hello | Pluton / TPM 2.0 |
| Linux | `tss-esapi` 7.6 (where TPM present); software-backed fallback rejected by default | TPM 2.0 |

WebAuthn ceremonies use [`webauthn-authenticator-rs`](https://crates.io/crates/webauthn-authenticator-rs); cross-device flows use the FIDO hybrid transport via the same crate's caBLE module. Tauri commands exposed: `device_create_passkey`, `device_sign_with_passkey`, `device_attest_key`, `device_start_cross_device_link`.

### 15.11 Onboarding

Tenzro provides a single onboarding flow that provisions a TDIP identity, a self-custodial smart account, and a hardware profile in one atomic operation.

**One-Click Participation (`tenzro_participate` RPC).** Provisions all three components:

1. The client device runs a WebAuthn passkey ceremony (or a FROST DKG across multiple devices, depending on the chosen composition). The private key material never leaves the device(s).
2. A TDIP DID is created (`did:tenzro:human:{uuid}`) and registered in the `IdentityRegistry`.
3. The identity is persisted to RocksDB (`CF_IDENTITIES`).
4. A TenzroSmartAccount is deployed via the AccountFactory (deterministic CREATE2 address) with the appropriate validator module installed (`WebAuthnValidator` for passkey, `Ed25519Validator` for FROST, `TeeBoundValidator` for TEE-only).
5. The host machine's hardware profile (CPU, RAM, GPU, TEE availability) is detected and attached to the identity metadata.

The response returns the DID, smart-account address, installed validator modules, and hardware profile.

**Import from Existing Key (`tenzro_importIdentity` RPC).** Users with existing Ed25519 / Secp256k1 / P-256 keys can register them as the initial validator on a freshly-deployed smart account. The imported key is treated as the seed for the validator module's credential — it is never copied to a server.

**Hardware Profile Detection.**

| Detected Property | Use |
|---|---|
| CPU model, cores, threads | Compute capacity for inference workloads |
| Total RAM | Memory-bound model support |
| GPU name, VRAM, architecture | GPU-accelerated inference and proving eligibility |
| TEE availability | TEE-attested validator eligibility (1.5× multiplier on reputation-weighted leader draw); enables `TeeBoundValidator` for autonomous-agent flows |
| Platform authenticator | Determines whether the client can host a passkey locally or must use cross-device QR (FIDO hybrid transport) |

**Client Interfaces.**

- **CLI:** `tenzro join --name "Alice"` (interactive passkey ceremony) or `tenzro wallet import 0x... --key-type ed25519` (import existing key as initial validator)
- **Desktop App:** Setup page on first launch with three composition tabs — "Passkey on this device" (default), "Multi-device (FROST)", "Import existing key"
- **JSON-RPC:** `tenzro_participate` and `tenzro_importIdentity`

The desktop application enforces an onboarding gate — Setup is shown before the Dashboard until a valid identity and smart account exist. On success, the user is taken to the Dashboard with their DID, smart-account address, installed validator modules, and hardware profile displayed.

### 15.12 Multi-Asset Support

Smart accounts natively track balances across the supported assets:

| Asset | Symbol | Type |
|---|---|---|
| Tenzro | TNZO | Native token |
| USD Coin | USDC | Stablecoin |
| Tether | USDT | Stablecoin |
| Ether | ETH | Cryptocurrency |
| Solana | SOL | Cryptocurrency |
| Bitcoin | BTC | Cryptocurrency |

---

## 16. Peer-to-Peer Networking

### 16.1 Protocol Stack

The networking layer is built on libp2p with the following protocols:

| Protocol | Purpose |
|----------|---------|
| Gossipsub | Pub/sub message propagation for blocks, transactions, consensus |
| Kademlia DHT | Peer discovery and content routing |
| Identify | Peer identification and capability exchange |
| Noise | Transport encryption |
| Yamux / Mplex | Stream multiplexing |

### 16.2 Gossipsub Topics

| Topic | Content |
|-------|---------|
| `tenzro/blocks` | Block propagation |
| `tenzro/transactions` | Transaction propagation |
| `tenzro/consensus` | Consensus messages (votes, proposals) |
| `tenzro/batches` | Batch bodies, availability acknowledgments/certificates, and body requests (availability-dissemination plane) |
| `tenzro/attestations` | TEE attestation reports |
| `tenzro/models` | Model registry updates |
| `tenzro/inference` | Inference requests and responses |
| `tenzro/status` | Node status and peer discovery |
| `tenzro/agents` | Agent-to-agent messages and task coordination |

### 16.3 Peer Management

The `PeerManager` tracks connected peers with metrics:

```
PeerMetrics {
    messages_sent:     u64,
    messages_received: u64,
    bytes_sent:        u64,
    bytes_received:    u64,
    latency_ms:        f64,
    last_seen:         Timestamp,
}
```

### 16.4 Rate Limiting

Network-level rate limiting prevents message flooding:
- Messages per peer are tracked on a sliding window.
- Peers exceeding the configured rate limit are throttled.
- Persistent offenders are temporarily disconnected.

### 16.5 Message Deduplication

Gossipsub messages are deduplicated using a time-bounded set of recently seen message IDs, preventing amplification attacks where the same message is propagated multiple times.

---

## 17. Storage and State Management

### 17.1 Backend

The storage layer uses RocksDB with column families for data isolation:

| Column Family | Content |
|---------------|---------|
| `CF_BLOCKS` | Block headers and bodies |
| `CF_STATE` | Account state and contract storage |
| `CF_ACCOUNTS` | Account metadata |
| `CF_TRANSACTIONS` | Transaction receipts and indices |
| `CF_METADATA` | Chain metadata (latest height, state root) |
| `CF_SNAPSHOTS` | State snapshot metadata |
| `CF_SETTLEMENTS` | Settlement receipts and escrow state |
| `CF_CHANNELS` | Micropayment channel state |
| `CF_CHALLENGES` | Payment challenges (MPP/x402) + TOPLOC inference commitments and challenge records |

### 17.2 Merkle Patricia Trie

State is organized in a Merkle Patricia Trie, providing:
- **O(log n) reads and writes** for account state.
- **State root hashing** for inclusion in block headers.
- **Merkle proofs** for light client state verification.

### 17.3 Snapshots

The storage layer supports state snapshots for fast sync:
- **Creation.** A consistent snapshot of the state trie at a given block height.
- **Compression.** Snapshots are compressed before storage and transfer.
- **Restoration.** New nodes can bootstrap from a snapshot rather than replaying all blocks.
- **Retention.** Configurable retention policy (default: 100 most recent snapshots).

### 17.4 Write Durability

Finalized blocks are written with `sync_writes: true`, ensuring data is flushed to persistent storage before acknowledgment. This prevents state corruption on power loss.

### 17.5 Storage Constants

| Parameter | Value |
|-----------|-------|
| Block cache size | 1 GB |
| Write buffer size | 256 MB |
| Snapshot retention | 100 |
| Bloom filter bits | 10 per key |

---

## 18. Governance

### 18.1 On-Chain Proposals

TNZO holders can create and vote on governance proposals:

```
GovernanceProposal {
    proposal_id:        String,
    title:              String,
    description:        String,
    proposer:           Address,
    proposal_type:      ProposalType,
    status:             ProposalStatus,    // Active | Passed | Failed | Executed
    votes_for:          u64,
    votes_against:      u64,
    total_voting_power: u64,
    voting_start:       Timestamp,
    voting_end:         Timestamp,
}
```

**Proposal types:**
- `ParameterChange` — Modify network parameters (fees, block size, etc.)
- `TreasurySpend` — Allocate treasury funds
- `ValidatorChange` — Add or remove validators
- `ProtocolUpgrade` — Upgrade network protocol
- `Custom { proposal_data }` — Arbitrary governance action

### 18.2 Quorum Requirements

| Parameter | Default |
|-----------|---------|
| Minimum participation | 20% (2,000 bps) of total supply |
| Minimum approval | 50% (5,000 bps) of votes cast |
| Minimum proposal stake | 10,000 TNZO |

A proposal passes if and only if:
1. Total votes (for + against) >= minimum participation threshold.
2. Votes for > votes against.
3. Approval rate >= minimum approval threshold.

### 18.3 Delegation

Token holders can delegate their voting power to another address:
- Delegation is per-address (all-or-nothing for a given delegator).
- Delegated power is added to the delegate's effective voting power.
- Delegations can be revoked at any time.
- Active delegations are checked at vote time.

### 18.4 Execution

Passed proposals enter an execution phase. The governance engine validates proposal status before execution and prevents double-execution. Parameter changes take effect at the next epoch boundary.

---

## 19. Security Model

### 19.1 Threat Model

Tenzro assumes:
- Up to f = floor((n-1)/3) Byzantine validators in the consensus set.
- Network partitions are temporary (partial synchrony model).
- TEE hardware is honest but may have side-channel leaks (defense-in-depth with ZK).
- At least 2 of 3 MPC key shares remain uncompromised for any given wallet.

### 19.2 Defense Layers

| Layer | Mechanism | Protects Against |
|-------|-----------|-----------------|
| Consensus | BFT quorum (2f+1) | Byzantine validators, equivocation |
| Cryptography | Ed25519 + Secp256k1 signatures | Forgery, impersonation |
| TEE | Hardware attestation | Tampered execution environments |
| ZK | Plonky3 STARK proofs | False computation claims |
| Economics | Stake slashing | Rational adversaries |
| Network | Message deduplication, rate limiting | Flooding, amplification |
| Storage | fsync, Merkle proofs | Data corruption, state forgery |
| Wallet | MPC threshold (2-of-3) | Single-point key compromise |

### 19.3 Slashing Conditions

Validators and providers can be slashed for:
- **Double voting (equivocation).** Signing conflicting blocks at the same view. The `EquivocationDetector` in `VoteCollector` automatically detects conflicting votes. When detected, the `SlashingCallback` trait triggers `StakingManager::slash()` with 10% of the validator's stake burned. Evidence (both conflicting votes) is preserved for accountability.
- **Downtime.** Missing heartbeats beyond the tolerance threshold.
- **Invalid proofs.** Submitting false attestation or ZK proof data.
- **Service failure.** Consistently failing inference requests as a model provider.

### 19.4 Arithmetic Safety

All token arithmetic uses `u128` for amounts with `checked_add`, `checked_sub`, `checked_mul`, and `saturating_*` variants to prevent overflow and underflow. The maximum supply (10^27 smallest units) fits comfortably within u128 (max ~3.4 * 10^38).

---

## 20. Tenzro Train: Decentralized Verifiable Foundation-Model Training

### 20.1 Overview

Tenzro Train is the protocol's foundation-model training service: a decentralized network of GPU providers who collaboratively train large models (timeseries, language, vision, multimodal) and earn TNZO for their compute. It is the training counterpart to the AI Model Marketplace (§10), which serves *inference* on already-trained models.

The design is **decoupled outer aggregation**: each trainer runs `H` inner SGD steps on its local data shard between communication rounds, then submits a single *outer gradient* (the parameter delta `Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`) to an elected syncer. The syncer aggregates outer gradients from `K`-of-`M` trainers per fragment, applies a Nesterov-momentum outer optimizer step, commits the result on-chain, and broadcasts the new starting weights for the next round. This compresses cross-trainer bandwidth by 100–500× relative to per-step all-reduce, which is what makes geographically distributed training over commodity links economically viable.

### 20.2 Trust Tiers

Sponsors select a trust tier at task posting; the tier determines what the trainer hardware must provide and how rewards scale.

| Tier | Trainer Hardware | Trust Source | Default Aggregation |
|---|---|---|---|
| **Open** (Phase 1 default) | Any GPU or CPU, no TEE required for training compute | Stake bonding + redundant fragment assignment + Mean aggregation across `K`-of-`M` | `Mean`, `LoraAlternating` |
| **Verified** | Trainer posts a per-round TEE attestation binding `{program_hash, shard_hash, model_hash, DID}` | Hardware attestation (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA CC) | Byzantine-robust (TrimmedMean / CoordinateMedian / Krum, Phase 2) |
| **Confidential** | TEE-resident training; data sealed to the enclave; host OS never sees cleartext | Hardware attestation + sealed datasets | Byzantine-robust (Phase 2) |

Per `AI.md` §7.3.3: training compute is TEE-optional in the Open tier; key custody and verification (the syncer's signing keys, the receipt commitment) are TEE-mandatory in *every* tier. Phase 1 covers the Open tier only — Verified and Confidential are wire-format-supported but not yet enforced by the syncer.

### 20.3 Architecture Split: Rust Protocol + Python Trainer

Tenzro Train is split across two layers, each owning what it does best:

**Rust protocol layer** (`crates/tenzro-training`, no tensor library dependency):
- Wire-format types, signature canonicalization, round/run state roots
- Byzantine-robust aggregation rules over `ndarray` views of safetensors-decoded payloads
- Nesterov-momentum outer optimizer
- Syncer state machine, RocksDB write-through persistence (`CF_TRAINING_RUNS`, `CF_TRAINING_RECEIPTS`)
- libp2p gossip topics: `tenzro/training` (trainer → syncer outer gradients) and `tenzro/training/syncer` (syncer → trainers post-step weights)
- VM precompile `0x1008` (`TRAINING_VERIFY`) for on-chain receipt verification
- JSON-RPC namespace `tenzro_training_*` (post / list / get / enroll / submit / finalize)
- TNZO escrow, per-trainer reward distribution, network commission (5%), receipt-as-NFT minting

**Python reference trainer** (`integrations/trainer/`, PyTorch FSDP2 + Hivemind + safetensors):
- Inner training loop (forward, backward, optimizer step) per modality
- Modality adapters: timeseries (TimesFM-class), language (Qwen 3 0.6B default, any catalog LM swappable via metadata), vision (ViT-class)
- Outer-gradient packaging: per-fragment safetensors blob + SHA-256
- Ed25519 signing of outer gradients (PyNaCl)
- JSON-RPC client to the local node (`enrollTrainer`, `submitOuterGradient`, `finalizeRound`)

The split lives in `AI.md` §7.1 and `crates/tenzro-training/src/lib.rs`. The boundary is the **outer gradient**: Python emits one safetensors blob per fragment + a 32-byte SHA-256 + a signed `OuterGradient` JSON; Rust never holds the raw tensor in memory and never executes a `forward()`. This keeps the protocol layer free of CUDA, ABI churn, and PyTorch version pinning, while letting the Python adapters track frontier model architectures without protocol changes.

### 20.4 Outer-Aggregation Protocol

A training run has the following lifecycle (`TrainingRunStatus` transitions in parentheses):

1. **Post.** Sponsor escrows TNZO and posts a `TrainingTaskSpec` via `tenzro_training_postTask` (→ `Pending`).
2. **Elect syncer.** A syncer is elected (Phase 1: deterministic from `task_id`; Phase 2: VRF-weighted by stake) and posts a TEE attestation (→ `Enrolling`).
3. **Enroll trainers.** Trainers call `tenzro_training_enrollTrainer`. Once `K` (the quorum) have enrolled, the run advances to `Training`.
4. **Per-round loop** for each `round ∈ 0..max_rounds`:
   1. Each trainer fetches its assigned shard, snapshots the current parameters `θ⁽⁰⁾`, runs `inner_steps` (`H`) SGD steps locally, computes `Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾`, and partitions the delta into `fragment_count` contiguous name-sorted buckets.
   2. Each fragment is safetensors-encoded and SHA-256'd. The trainer signs an `OuterGradient` over `tenzro/train/outer-gradient || task_id || round || fragment || trainer_did || sha256 || payload_bytes || inner_step_count || submitted_at` and submits via `tenzro_training_submitOuterGradient`.
   3. The syncer buffers submissions per `(round, fragment)`. Once a fragment reaches `K`-of-`M` accepted submissions (or the grace window `τ` elapses), it is eligible for aggregation.
   4. The Python syncer-side helper aggregates accepted fragment payloads via `AggregationRule::Mean` (Phase 1), applies a Nesterov outer step, computes the post-step parameter SHA-256 per fragment, and calls `tenzro_training_finalizeRound` with `{fragment → post_step_hash}`.
   5. The Rust syncer builds a `SyncRound` containing per-fragment `FragmentQuorumStatus` and the round's `state_root`, signs it, broadcasts on `tenzro/training/syncer`, and persists the new state root in `CF_TRAINING_RUNS`.
5. **Finalize.** When `current_round == max_rounds`, the syncer assembles a `TrainingReceipt` (capturing the verbatim task spec, all per-round state roots, the final model hash, per-trainer contribution counts and reward shares, the syncer's TEE attestation chain, and the run's Merkle `run_root`) and writes it to `CF_TRAINING_RECEIPTS` (→ `Completed`). The receipt is mintable as an NFT via the standard NFT factory at precompile `0x1006`.

#### 20.4.1 Training Objectives: Supervised and RL Post-Training (GRPO)

`TrainingTaskSpec.objective` selects what the inner loop optimizes. It is a serde externally-tagged enum:

- `"Supervised"` (default) — the H-step SGD loop over labeled shard batches described above.
- `{"RlPostTraining": {group_size, kl_coeff, clip_epsilon, max_new_tokens, temperature, reward_ref}}` — a GRPO (Group Relative Policy Optimization) inner loop, the pattern used by prime-rl and TRL's `GRPOTrainer`: no value model, no frozen reference copy.

Per RL inner step the trainer takes one prompt from its shard, samples `group_size` completions from the current policy at `temperature`, scores each with the sponsor-referenced reward callable, and computes group-relative advantages `(r − mean) / (std + ε)`. The loss per rollout is the clipped surrogate `min(ratio·A, clamp(ratio, 1−ε_clip, 1+ε_clip)·A)` averaged over tokens, plus a k3 KL penalty `exp(old − new) − (old − new) − 1` against the sampling-time policy (drift within the inner window is penalized without holding a second model in memory). A uniform-reward group yields zero advantages — no learning signal from that prompt, which is correct GRPO behavior.

`reward_ref` names the reward callable as `py:<module.path>:<callable>`, e.g. `py:my_rewards.math:score_completion`, with signature `(prompt: str, completion: str) -> float`. The Python trainer resolves it via `tenzro_trainer.rl.load_reward` at run start and fails fast if it does not resolve to a callable.

Admission is protocol-side: `tenzro_training_postTask` runs `validate_objective` (`crates/tenzro-training/src/runtime.rs`), which requires `Language` modality for `RlPostTraining` and rejects `group_size < 2`, non-finite or negative `kl_coeff`, `clip_epsilon` outside `(0, 1]`, `max_new_tokens == 0`, non-positive `temperature`, and an empty `reward_ref`.

The outer-gradient contract is unchanged: the RL loop returns the same `Δθ = θ⁽ᴴ⁾ − θ⁽⁰⁾` delta, so fragment partitioning, quantization, Open-tier activation commitments, and submission work verbatim. `loss_trajectory` carries the per-step GRPO losses (the loss half of the activation commitment) and `samples_processed` counts rollouts.

### 20.5 On-Chain Commitments

Every round seals a 32-byte `state_root` on-chain. Every run seals a 32-byte `run_root`. Both are domain-prefixed SHA-256 commitments deterministic across implementations:

- **`state_root`** (`crates/tenzro-training/src/commitments.rs::compute_state_root`):
  ```
  sha256(
    "tenzro/train/state-root"
    ‖ task_id_bytes
    ‖ round_be_u32
    ‖ for each fragment in sorted-by-id order:
        fragment_be_u32 ‖ accepted_be_u32 ‖ quorum_met_u8
        ‖ for each accepted_hash in trainer-DID-sorted order: hash_bytes
        ‖ post_step_hash_bytes
  )
  ```
- **`run_root`** (`compute_run_root`): a SHA-256 Merkle tree over the sequence of per-round `state_root`s, with Bitcoin-style duplicate-last for unbalanced layers and the per-node prefix `tenzro/train/run-root`. Length-1 returns the leaf directly; length-0 returns `Hash::zero()`.

The `run_root` is the single hash that anchors an entire training run, and it is what the receipt-NFT and any downstream verifier (e.g. the `0x1008` `TRAINING_VERIFY` precompile) check.

### 20.6 Aggregation Rules

`crates/tenzro-training/src/aggregation.rs` implements five aggregation rules over decoded fragment views; Phase 1 exposes `Mean` and `LoraAlternating` via tier policy.

| Rule | Robustness | Phase | Use Case |
|---|---|---|---|
| `Mean` | None (one Byzantine submitter pollutes the aggregate) | **1** | Open tier — trust comes from stake bonding |
| `LoraAlternating` | None (Open-tier, same admission as `Mean`) | **1** | LoRA/QLoRA adapter runs — the trainer freezes one low-rank factor per round so each round's delta is a single factor and per-coordinate mean is correct; reuses the mean aggregator |
| `TrimmedMean { alpha_bps }` | Up to `α%` Byzantine per coordinate | 2 | Verified tier — first-line Byzantine defense |
| `CoordinateMedian` | Up to `f < M/2` Byzantine learners | 2 | Verified tier when median is preferable |
| `Krum { f }` | Picks the gradient with lowest sum-of-distances to nearest neighbors; tolerates `f` Byzantine | 2 | High-stakes Verified / Confidential runs |

`Mean` and `LoraAlternating` admit at every tier. The Byzantine-robust rules (`TrimmedMean`, `CoordinateMedian`, `Krum`) are implemented and unit-tested in Phase 1 to lock the wire format and the math; they are dormant behind tier policy until Phase 2 lights up Verified.

For `LoraAlternating`, the naive per-coordinate mean of both LoRA factors would be wrong — the useful update is the product `B·A`, and `mean(Bᵢ·Aᵢ) ≠ (mean Bᵢ)·(mean Aᵢ)`. The trainer holds one factor fixed per round and syncs only the other, so within a round every contributor submits a delta on the same single factor and per-coordinate mean is exact.

### 20.7 Token Economics

Sponsors escrow TNZO at task posting. At receipt time:

- **Network commission** (default 5%) flows to the treasury (§8.5).
- **Per-trainer reward** is pro-rata to accepted contributions: a trainer's share of the post-commission pool equals `accepted_outer_gradients_for_trainer / total_accepted_outer_gradients_across_all_trainers`. Both numerator and denominator come from `TrainingReceipt::trainer_contributions`.
- **Syncer fee** is paid out from the same pool by way of a fixed slice (Phase 1: 1% of escrow before commission). The syncer's TEE attestation chain is bound into the receipt for audit.
- **Slashing.** Trainer stake (Phase 2) is slashed for: failure-to-submit beyond grace window `τ`; submitting a fragment whose `safetensors_hash` does not match the on-the-wire payload; submitting a forged signature. Syncer stake is slashed for: equivocation (two distinct `state_root`s for the same `(task_id, round)`); finalizing a round below quorum.

### 20.8 RPC Surface

The node exposes seven JSON-RPC methods under the `tenzro_training_*` namespace (see `crates/tenzro-node/src/rpc.rs`):

| Method | Caller | Purpose |
|---|---|---|
| `tenzro_training_postTask` | sponsor | Post a new training task; node validates spec, escrows TNZO, returns `task_id` |
| `tenzro_training_listRuns` | anyone | Discover active runs |
| `tenzro_training_getRun` | anyone | Fetch a single run's `TrainingRun` (status, current_round, state_roots, …) |
| `tenzro_training_getReceipt` | anyone | Fetch a finalized run's `TrainingReceipt` |
| `tenzro_training_enrollTrainer` | trainer | Register `trainer_did` against an `Enrolling` run |
| `tenzro_training_submitOuterGradient` | trainer | Submit one `OuterGradient` for the current round |
| `tenzro_training_finalizeRound` | syncer-side helper | Advance the run to `round + 1` given `post_step_hashes` |

JSON-RPC error codes follow the workspace convention: `-32602` for validation errors (unknown task, fragment out-of-range, payload-size mismatch, invalid signature), `-32011` for tier/quorum policy failures (attestation required, quorum not met), `-32603` for storage / aggregation / serialization internal errors.

### 20.9 CLI and Agent Kit

The CLI (`crates/tenzro-cli`) exposes a `train` command group with seven subcommands mirroring the RPC surface: `post-task`, `list-runs`, `get-run`, `get-receipt`, `enroll-trainer`, `submit-gradient`, `finalize-round`. Specs and gradients are loaded from JSON files; `post_step_hashes` is parsed as an inline JSON object.

Three reference agent templates are bootstrapped from `crates/tenzro-workflow/reference_workflows/` and registered on every node startup:

| Template | Modality | Min RAM | GPU | Platforms |
|---|---|---|---|---|
| `ref-timeseries-trainer-v1` | Timeseries | 16 GB | required | `linux-x86_64`, `linux-aarch64`, `macos-aarch64` |
| `ref-language-trainer-v1` | Language | 32 GB | required | `linux-x86_64`, `linux-aarch64` |
| `ref-vision-trainer-v1` | Vision | 24 GB | required | `linux-x86_64`, `linux-aarch64`, `macos-aarch64` |

Each template is a `specialist` `MultiVm`-backend agent with two allowed operations (`training_enroll`, `training_submit_gradient`) and a 30-day delegation scope. Spawning a template provisions a TDIP machine identity, an MPC wallet, and a delegation scope binding the agent to the configured operations and cap.

### 20.10 Python Reference Trainer

The Python package `integrations/trainer/` (PyPI name `tenzro-trainer`) implements the inner-loop side of the protocol. It is a runtime dependency of any node that wants to *participate* as a trainer, but the protocol layer (and the syncer state machine) function without it.

```
integrations/trainer/
├── pyproject.toml                        # Python ≥ 3.10, torch + safetensors + PyNaCl
├── tenzro_trainer/
│   ├── types.py                          # Wire-format mirrors of tenzro_types::training
│   ├── rpc_bridge.py                     # JSON-RPC 2.0 client (requests)
│   ├── gradient.py                       # Outer-gradient packaging + Ed25519 signing
│   ├── inner_loop.py                     # Generic H-step SGD driver (Supervised)
│   ├── rl.py                             # GRPO RL post-training inner loop
│   ├── adapters/
│   │   ├── timeseries.py                 # Phase 1 lead modality (TimesFM-class)
│   │   ├── language.py                   # Decoder-only LM adapter (Qwen 3 default,
│   │   │                                 #   catalog LM swappable) + rollout adapter
│   │   │                                 #   for RL post-training
│   │   └── vision.py                     # ViT adapter (timm)
│   └── cli.py                            # tenzro-trainer enroll | run | submit | finalize
└── tests/
    ├── test_types_roundtrip.py           # JSON wire format pinned (incl. objective)
    ├── test_fragment_partition.py        # Fragment partition algorithm pinned
    ├── test_rl_inner_loop.py             # GRPO loss/advantages/loop on a bandit policy
    └── test_signing.py                   # Ed25519 signature + canonical preimage pinned
```

The Python `OuterGradient.to_json()` produces the *exact* JSON shape the Rust syncer's `serde_json::from_value::<OuterGradient>()` accepts: `Hash` and `Address` as 32-element integer arrays (not hex strings); `Timestamp` as a bare `i64` (not an object); `Signature` as `{bytes: [...], public_key: [...]}`. The wire-format tests pin this contract.

### 20.11 Phase 1 Scope and Phase 2 Outlook

**Phase 1 covers:**
- Open tier with stake-bonded trust
- `Mean` and `LoraAlternating` aggregation
- Timeseries lead modality, with language and vision sharing the same plumbing
- Full Rust + Python training loop for the local case (single-node syncer + multiple trainers)
- On-chain commitments, receipt sealing, NFT-mintable receipts, RPC surface, CLI, agent kit templates
- Reference VM precompile (`0x1008`) for receipt verification

**Phase 2 lights up:**
- Verified and Confidential tiers (per-round TEE attestations bound to `program_hash`, `shard_hash`, `model_hash`, `DID`)
- Byzantine-robust aggregation (`TrimmedMean`, `CoordinateMedian`, `Krum`) gated by tier
- Trainer + syncer stake slashing for protocol violations (equivocation, payload mismatch, missed grace window)
- VRF-weighted syncer election (replacing Phase 1 deterministic election)
- Federated multi-syncer redundancy for very large runs

---

## 20a. Tenzro Media Gen

### 20a.1 Overview

Tenzro Media Gen is the protocol's generative-media service: diffusion image and video rendering as a network resource. A requester posts a job with a price ceiling; a worker claims it, renders it, publishes the output to the content-addressed store, and signs a receipt over what it produced. It is the generative counterpart to the AI Model Marketplace (§10) — the same TDIP identity, staking bond, reputation record, and TNZO settlement asset underwrite it, and a media worker is a provider registration carrying a different capability record.

Four job kinds, spelled on the wire as `text2image`, `image2image`, `text2video`, `image2video`. The image-conditioned kinds bind the conditioning image's SHA-256 into the job id, so a job commits to the exact bytes it was conditioned on. Video kinds carry a frame count and fps; image kinds reject both. Admission bounds are `MAX_MEDIA_GEN_DIMENSION = 8192`, `MAX_MEDIA_GEN_STEPS = 500`, `MAX_MEDIA_GEN_FRAMES = 3600`, `MAX_MEDIA_GEN_PROMPT_BYTES = 8192` (`crates/tenzro-types/src/media_gen.rs`).

### 20a.2 Architecture Split: Rust Protocol + Python Worker

The same split as Tenzro Train (§20.3), for the same reason.

**Rust protocol layer** (`crates/tenzro-media-gen`, no tensor library dependency): the job queue, the worker registry, the pricing function, the payment split, the three signing preimages, the output-store trait, RocksDB persistence, and the gossip envelope.

**Python reference worker** (`integrations/media_gen/`): the denoising loop and nothing else — pipeline construction, scheduler manipulation, VAE decode, video muxing, over HuggingFace `diffusers`. The worker never decides what a job is worth, who else is working on it, or whether its own receipt is acceptable.

`diffusers` carries a maintained implementation of every pipeline class in the catalog, including the timestep-boundary dispatch that split-expert rendering depends on. Reimplementing that in Rust would mean tracking upstream model releases in a second language for no protocol benefit.

### 20a.3 Model Catalog

Workers read the catalog at enrollment via `tenzro_mediaGen_listCatalog`. Each row names the HuggingFace repo, the `diffusers` pipeline class, the kinds it serves, default and maximum resolutions, default step count and guidance scale, frames and fps for video, a VRAM floor, and — for split models — the expert pair.

| ID | Repo | Kinds | Default w×h | Steps | VRAM | Expert pair |
|---|---|---|---|---|---|---|
| `qwen-image` | `Qwen/Qwen-Image` | text2image | 1328 × 1328 | 50 | 48 GB | — |
| `qwen-image-flash` | `nvidia/Qwen-Image-Flash` | text2image | 1024 × 1024 | 4 | 48 GB | — |
| `qwen-image-edit` | `Qwen/Qwen-Image-Edit-2511` | image2image | 1328 × 1328 | 40 | 48 GB | — |
| `z-image-turbo` | `Tongyi-MAI/Z-Image-Turbo` | text2image | 1024 × 1024 | 9 | 16 GB | — |
| `flux2-klein-4b` | `black-forest-labs/FLUX.2-klein-4B` | text2image, image2image | 1024 × 1024 | 4 | 12 GB | — |
| `wan2.2-t2v-a14b` | `Wan-AI/Wan2.2-T2V-A14B-Diffusers` | text2video | 1280 × 720 | 40 | 80 GB | 48 GB each |
| `wan2.2-i2v-a14b` | `Wan-AI/Wan2.2-I2V-A14B-Diffusers` | image2video | 1280 × 720 | 40 | 80 GB | 48 GB each |
| `wan2.2-ti2v-5b` | `Wan-AI/Wan2.2-TI2V-5B-Diffusers` | text2video, image2video | 1280 × 704 | 50 | 24 GB | — |

A row serving an image-conditioned kind resolves to a sibling pipeline class where the family provides one (`WanPipeline` → `WanImageToVideoPipeline`); a class that already covers image input keeps it.

`qwen-image-flash` is `qwen-image` distilled onto a four-step trajectory with guidance disabled: identical transformer, identical VRAM floor, one twelfth of the pixel-steps and so one twelfth of the quote. It is also the one row outside the permissive tier — the NVIDIA Open Model License classifies it `CommercialCustom`, so a worker declaring it must enroll on a node started with `--accept-license nvidia-open-model`. `tenzro_mediaGen_enrollWorker` rejects a capability naming a model the operator has not accepted, or one absent from the catalog. Enrollment is the enforcement point because the node never loads media-gen weights; the Python worker does.

### 20a.4 Split-Expert Rendering

Two model shapes are both called mixture-of-experts in the generative-media literature, and only one of them is a distribution primitive.

**Token-routed MoE** has a learned router selecting experts per token inside every forward pass. Splitting it across machines costs a round trip per layer per token. That is the shape the language-model dispatch planner addresses (`AI.md` §3); the media catalog does not carry it.

**Timestep-boundary expert pairs** are two transformers trained for different noise regimes — one for the high-noise prefix of the denoising schedule, one for the low-noise remainder. There is no learned router: a fixed noise threshold decides which expert owns a step. Exactly one intermediate latent crosses between the two halves, once per job. One expert needs 48 GB where the whole model needs 80, so two commodity accelerators render what one alone could not, and the coordination cost is a single blob transfer.

**The boundary is a noise level, not a step index.** A step belongs to the high-noise expert while:

```
t >= boundary_ratio × scheduler.config.num_train_timesteps
```

Timesteps descend through the schedule, so that set is always a prefix and one integer index splits it. `boundary_ratio` is a fraction of the scheduler's *training* timestep count — `0.875` of 1000 for Wan 2.2 A14B. A 40-step job and a 100-step job split at the same noise level and at different indices, which is why the protocol records `steps_completed` from the signed handoff rather than assuming a fixed fraction.

Both transformer slots are optional in the `diffusers` Wan pipeline, and every internal read falls back to the other slot when one is unset. A high-noise holder loads its expert into `transformer` and leaves `transformer_2` unset; a low-noise holder does the reverse and resumes with `scheduler.set_begin_index(boundary_index)`.

`MediaGenWorkerCapability` carries `supported_models` (models the worker serves whole) and `expert_holdings` (individual halves, for models it cannot). A worker with the VRAM for both halves lists the model in `supported_models` and still claims each half separately — the protocol makes no exception for co-location, which keeps the signed step counts and the payment split identical whether the halves run on one machine or two.

### 20a.5 Pricing and Payment Split

The work unit is the **pixel-step**: `width × height × steps × frames`, frames defaulting to 1 for image kinds (`crates/tenzro-media-gen/src/pricing.rs`). A quote is `base_fee + per_pixel_step × pixel_steps`, with `DEFAULT_BASE_FEE = 1 × 10¹⁵` attoTNZO and `DEFAULT_PER_PIXEL_STEP = 1 × 10⁹` attoTNZO. A job whose ceiling falls below the quote is rejected at admission rather than claimed and abandoned.

A non-split job pays the single worker the full `10_000` basis points. A split job pays proportionally to the schedule each half rendered:

```
high_bps = steps_completed × 10_000 / total_steps
low_bps  = 10_000 − high_bps
```

`steps_completed` comes from the signed handoff, not from either worker's later claim. Overstating a half would take a forged Ed25519 signature over the handoff preimage.

Settlement runs inside `tenzro_mediaGen_submitReceipt`, after the runtime has validated and sealed the receipt, so nothing is paid against a receipt the runtime would reject. The requester is debited `price_paid` and no more: the network commission (`NetworkCommissionRates::inference_commission_bps`, 500 bps) is carved out of that amount rather than added on top, matching the price the worker sealed and the requester was quoted against. `split_payout` divides the remainder by the basis points above; integer division leaves at most one attoTNZO per worker unallocated, and that dust falls to the last share so the parts sum exactly. The commission reaches the treasury at the derived `network_treasury_address()`, which an operator cannot redirect.

The whole debit is checked against the requester's balance before any of it moves, so a requester who cannot cover the job does not pay one expert and strand the other. A transfer that fails after that check leaves the job completed and short-paid rather than unwinding what already moved — the render happened and the receipt is valid, so the shortfall is the requester's to make good. Each unpayable leg is written as an unpaid marker in `CF_SETTLEMENTS` for retry and named in the JSON-RPC error (`-32023`). The response carries a `settlement` block (`price_paid`, `commission_wei`, one payout per assignment) that the CLI prints and the Python worker logs against its own DID.

### 20a.6 Commitments

Three SHA-256 preimages under three distinct domain tags (`crates/tenzro-media-gen/src/commitments.rs`). Distinct tags keep a handoff signature from being replayed as a receipt signature.

| Domain tag | Binds |
|---|---|
| `tenzro/media-gen/job-id` | requester DID and address, model ID, kind, every parameter, price ceiling, creation timestamp |
| `tenzro/media-gen/handoff` | job ID, handing-off worker DID and address, latent hash, latent byte length, `steps_completed`, handoff timestamp |
| `tenzro/media-gen/receipt` | job ID, the executed task spec, worker DID and address, output hash, output MIME, output byte length, seed used, generation time, price paid, completion timestamp |

Encoding rules: integers big-endian at their declared width, `Timestamp` as two's-complement i64 milliseconds, `f32` as the IEEE-754 big-endian bit pattern, variable-length fields prefixed with a big-endian u32 byte count, `Option` as a presence byte then the value. Raw 32-byte hashes embed bare; addresses are length-prefixed. The opaque `metadata` map is excluded from every preimage — a map has no canonical ordering across the Rust and Python JSON encoders, so binding it would make the digest encoder-dependent.

The job id is the digest of its own contents, so a spec carrying someone else's id still hashes to what it actually says. The Python worker recomputes the same three preimages; `integrations/media_gen/tests/` pins the field order against the same fixture values the Rust suite uses, so a preimage change on either side shows up as a digest change on one side only.

### 20a.7 Payload Store

Three payload kinds share one content-addressed store: the rendered output (receipt-committed), the intermediate latent on a split job (handoff-committed), and the requester's conditioning image (spec-committed). All three are addressed by `tenzro://blob/`, fetched over the node's iroh endpoint (§17), and verified on read.

`Hash` is SHA-256 — the canonical Tenzro hash, and what the commitments bind. iroh-blobs indexes by BLAKE3. `tenzro_mediaGen_publishOutput` therefore returns both: `output_hash` for the commitment and `locator` for the fetch. A worker publishing a latent records the SHA-256 in the handoff it signs; its partner fetches by locator and verifies the SHA-256 before resuming, so the transport's BLAKE3 verification and the protocol's hash check remain independent.

### 20a.8 Lifecycle and RPC Surface

```
postJob → claimJob → markRunning → render
                                    ├─ recordHandoff   (high-noise half of a split job)
                                    └─ submitReceipt   (whole job, or low-noise half)
```

`failJob` is terminal: a failed job does not requeue. A worker waiting on a split partner waits a bounded interval and then fails the job explicitly rather than abandoning it. `cancelJob` is the requester's path, valid until a worker has claimed. Job status is `pending` | `claimed` | `running` | `completed` | `failed` | `cancelled`; expert role is `high_noise` | `low_noise`.

Eighteen JSON-RPC methods under the `tenzro_mediaGen_` namespace:

| Group | Methods |
|---|---|
| Discovery | `listCatalog`, `quote`, `listWorkers` |
| Requester | `postJob`, `listJobs`, `getJob`, `cancelJob`, `getReceipt`, `fetchOutput`, `fetchInput` |
| Worker | `enrollWorker`, `claimJob`, `markRunning`, `failJob`, `publishOutput`, `recordHandoff`, `submitReceipt`, `fetchLatent` |

The same surface is reachable through the CLI (`tenzro media-gen …`), the MCP server, the A2A `media-gen` skill, and both SDKs. Job, worker, and receipt events broadcast on the `tenzro/media-gen` gossip topic. The Python worker's `tenzro-media-gen serve` drives the worker methods for an operator; the Rust CLI subcommands are the inspection and manual-recovery path.

---

## 21. Roadmap

### Phase 1: Core Infrastructure — **DONE**
- ~~Replace all stub implementations with production logic~~ — **DONE**: All core subsystems have real implementations
- ~~Integrate real EVM execution (revm) and SVM execution (solana-svm)~~ — **DONE**
- ~~Connect Daml executor to Canton participant nodes via Ledger API (gRPC, port 5001)~~ — **DONE**: tonic gRPC client
- ~~Implement bootstrap peer discovery and genesis block~~ — **DONE**: Kademlia DHT seeding + GenesisConfig
- ~~Complete TEE hardware integration (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)~~ — **DONE**: Device paths (`/dev/tdx-guest`, `/dev/sev-guest`, `/dev/nsm`, NVIDIA NRAS) with simulation fallback, X.509 cert chain verification
- ~~Implement EIP-1559 fee market~~ — **DONE**
- ~~Implement Block-STM parallel execution~~ — **DONE**
- ~~Implement ERC-4337 account abstraction~~ — **DONE**
- ~~Implement equivocation detection and slashing~~ — **DONE**: EquivocationDetector in VoteCollector, SlashingCallback bridges consensus → StakingManager::slash() (10% penalty)
- ~~Implement peer authentication~~ — **DONE**: ValidatorRegistry trait, validator-only gossipsub topics
- ~~Implement ZK trusted setup ceremony~~ — **OBSOLETED**: migrated to Plonky3 STARKs over KoalaBear; no trusted setup required

### Phase 2: Identity & Payments
- ~~Implement Tenzro Decentralized Identity Protocol (TDIP)~~ — **DONE**: three identity classes (human / delegated agent / autonomous agent), W3C DID, verifiable credentials, delegation scopes
- ~~Implement MPP and x402 payment protocols~~ — **DONE**: HTTP 402 challenge/credential/receipt flows
- ~~Implement Tempo network integration~~ — **DONE**: TempoBridgeAdapter, Tip20Token, TempoParticipant
- ~~Implement identity-bound payments~~ — **DONE**: delegation scope enforcement on payments
- Connect payment protocols to live settlement rails (Stripe MPP, Coinbase x402, Tempo network)

### Phase 3: Agent & Protocol Integration
- ~~Implement MCP server~~ — **DONE**: rmcp-based server on port 3001, Streamable HTTP transport, 526 tools
- ~~Implement A2A protocol server~~ — **DONE**: JSON-RPC 2.0 on port 3002, Agent Card discovery, SSE streaming, 40 skills
- ~~Implement ecosystem MCP servers~~ — **DONE**: Solana (3003), Ethereum (3004), Canton (3005), LayerZero (3006), Chainlink (3007), Li.Fi (3008)
- ~~Implement challenge store for payment protocols~~ — **DONE**: persistent challenge lookup for MPP and x402
- ~~Implement OpenClaw skill integration~~ — **DONE**: `skills/openclaw-tenzro/SKILL.md`
- ~~Implement NVIDIA GPU TEE provider~~ — **DONE**: Hopper/Blackwell/Ada Lovelace, NRAS attestation
- ~~Add GPU-accelerated ZK proving~~ — **DONE**: batch proof generation, Merkle aggregation, multi-level compression
- ~~Implement liquid staking (stTNZO)~~ — **DONE**: rebasing exchange rate, multi-validator delegation, 10% protocol fee

### Phase 4: Testnet Deployment
- ~~Deploy public testnet~~ — **DONE**: Tenzro Labs operates the initial public RPC and ecosystem endpoints on tenzro.xyz with PQ-hybrid TLS at the edge while the validator set decentralizes
- ~~Configure Caddy with auto-TLS for all subdomains~~ — **DONE**: Let's Encrypt certificates for 5 endpoints
- ~~Verify all endpoints live~~ — **DONE**: RPC, API, Faucet, MCP, A2A all operational
- Audit Plonky3 AIR constraint completeness against soundness analysis
- Launch model provider onboarding
- Enable micropayment channels for inference billing
- Deploy bridge to Ethereum testnet via LayerZero

### Phase 5: Ecosystem Growth
- Launch mainnet with full staking and governance
- SDK releases for Rust (33 methods), TypeScript (25 methods), and Python
- Desktop application general availability
- Enterprise Canton bridge for institutional AI
- Model marketplace with reputation and discovery

### Phase 6: Scale and Optimize
- Cross-shard execution for horizontal scaling
- Advanced routing algorithms (ML-based provider selection)
- Full audit and formal verification of critical paths
- Decentralized model storage via IPFS/Filecoin integration

---

## Appendix A: Supported Assets

| Asset ID | Symbol | Type | Decimals |
|----------|--------|------|----------|
| `tnzo` | TNZO | Native | 18 |
| `usdc` | USDC | Stablecoin | 6 |
| `usdt` | USDT | Stablecoin | 6 |
| `eth` | ETH | Cryptocurrency | 18 |
| `sol` | SOL | Cryptocurrency | 9 |
| `btc` | BTC | Cryptocurrency | 8 |

## Appendix B: Protocol Messages (Protobuf)

The network defines 120+ message types and 40+ RPC methods across 13 protobuf service definitions:

| Proto File | Content |
|-----------|---------|
| `types.proto` | Hash, Address, Signature, ChainId |
| `transaction.proto` | Transaction structures |
| `block.proto` | Block headers and bodies |
| `consensus.proto` | HotStuff-2 protocol messages |
| `network.proto` | P2P networking messages |
| `tee.proto` | TEE attestation types |
| `model.proto` | Model registry and inference |
| `settlement.proto` | Payment settlement |
| `agent.proto` | AI agent protocol |
| `governance.proto` | Proposals and voting |
| `bridge.proto` | Cross-chain messages |
| `canton.proto` | Canton/Daml 3.x integration (synchronizers, topology, Ledger API types) |
| `rpc.proto` | gRPC service definitions |

## Appendix C: Gossipsub Topic Reference

| Topic | Version | Direction |
|-------|---------|-----------|
| `tenzro/blocks` | 1.0.0 | Validators -> All |
| `tenzro/transactions` | 1.0.0 | Any -> Validators |
| `tenzro/consensus` | 1.0.0 | Validators <-> Validators |
| `tenzro/attestations` | 1.0.0 | TEE Providers -> All |
| `tenzro/models` | 1.0.0 | Model Providers -> All |
| `tenzro/inference` | 1.0.0 | Users <-> Providers |
| `tenzro/status` | 1.0.0 | All <-> All |
| `tenzro/agents` | 1.0.0 | Agents <-> Agents |
| `tenzro/batches` | 1.0.0 | Validators <-> Validators |

## Appendix D: Live Testnet Endpoints

Tenzro Labs operates the initial public endpoints on `tenzro.xyz` with PQ-hybrid TLS at the edge while the validator set decentralizes:

| Service | URL | Port | Protocol |
|---------|-----|------|----------|
| JSON-RPC | `https://rpc.tenzro.xyz` | 8545 | Ethereum-compatible JSON-RPC |
| Web API | `https://api.tenzro.xyz` | 8080 | REST (verify, status, faucet) |
| Faucet | `https://api.tenzro.xyz/faucet` | 8080 | POST with `{"address": "0x..."}` |
| MCP | `https://mcp.tenzro.xyz/mcp` | 3001 | Streamable HTTP (MCP protocol) |
| A2A | `https://a2a.tenzro.xyz` | 3002 | JSON-RPC 2.0 + SSE |
| Agent Card | `https://a2a.tenzro.xyz/.well-known/agent.json` | 3002 | GET (A2A discovery) |

**Testnet configuration:**
- Chain ID: 1337
- Faucet: 100 TNZO per request, 24-hour cooldown per address
- Docker image: `<your-registry>/tenzro-node:<tag>` (build from the repo `Dockerfile`)

---

**Tenzro Network** — AI-Native, Agentic, Tokenized Settlement Layer

**Tenzro Ledger** — Decentralized AI. Verifiable Inference. Permissionless Settlement.

*https://github.com/tenzro/tenzro-network*
