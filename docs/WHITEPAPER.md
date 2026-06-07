# Tenzro Network: AI-Native, Agentic, Tokenized Settlement Layer

## Tenzro Ledger: A TEE-Native Layer 1 for Verifiable AI and Autonomous Agents

**Version 0.1.0 — March 2026**

---

## Abstract

**Tenzro Network** is an AI-Native, Agentic, Tokenized Settlement Layer — a decentralized protocol designed for the AI age, where agents and autonomous systems are first-class participants alongside humans. It is the **reference implementation of the Open Agent Network (OAN)**, the protocol family (TNIP-001..022) for a hybrid human + agent coexisting network stewarded by the Tenzro Foundation. Tenzro Network is the first protocol where the full agent loop — discover model, discover skill, discover task, access resource, pay for it — is wire-level, not application-level, and it is fully usable today with the latest protocol support. The network provides two core capabilities: access to **intelligence** (AI models for inference) and access to **security** (TEE enclaves for key management, custody, and confidential computing). Providers, validators, and nodes earn by securing the network, providing intelligence (AI models), and providing security (TEE enclaves).

**Tenzro Ledger** is the purpose-built Layer 1 settlement layer for humans and agents, providing verifiable, on-chain primitives for the AI age: **identity** (TDIP: Tenzro Decentralized Identity Protocol for humans and machines), **security** (TEE-weighted consensus with hardware attestations), **verification** (dual ZK + TEE proof systems), and **settlement** (micropayment channels, escrow, batch processing). All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

Built from the ground up around Trusted Execution Environments (TEEs) and zero-knowledge proofs, the Ledger provides hardware-rooted trust at every layer — TEE-attested validators receive a 1.5× multiplier on their reputation-weighted leader-selection draw, smart contracts execute within hardware enclaves, and all on-chain claims can be independently verified through cryptographic proofs or hardware attestations. The Ledger supports a multi-VM execution environment (EVM, SVM, Daml/Canton), an autonomous agent framework with self-sovereign identity and MPC wallet ownership, a decentralized AI model marketplace with per-token settlement, decentralized verifiable training (Tenzro Train, Decoupled DiLoCo–style with on-chain run-root commitments), and cross-chain interoperability through Wormhole NTT, LayerZero V2, Chainlink CCIP, deBridge DLN, Li.Fi, and Canton. Multi-protocol payment support (MPP, x402, Tempo, Stripe SPT, AP2) enables HTTP 402-based machine payments with identity-bound delegation enforcement. Consensus is driven by a two-phase HotStuff-2 BFT engine with 400ms block times, reputation-weighted proposer election, no-endorsement certificates for tail-fork resistance, and Ed25519 + ML-DSA-65 hybrid post-quantum signatures on every safety-critical message.

Tenzro turns AI compute into a unit of economic exchange — denominated, settled, and verified in TNZO. The same identity, payment, and settlement substrate covers three surfaces: **tokenized AI inference** (per-token billing via micropayment channels), **tokenized AI training** (sponsor escrow + provider rewards + on-chain run-root commitments), and **agentic finance** (autonomous discovery, negotiation, payment, and settlement). Where Render rents raw GPUs and Bittensor coordinates subnet intelligence, Tenzro unifies inference, training, agent settlement, identity, verification, and cross-chain reach under one tokenized substrate. The Ledger is not solely an inference marketplace — it is a general-purpose L1 where verifiable computation, confidential execution, and agent-to-agent economic coordination are first-class primitives.

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
15. [Wallet and Key Management](#15-wallet-and-key-management)
16. [Peer-to-Peer Networking](#16-peer-to-peer-networking)
17. [Storage and State Management](#17-storage-and-state-management)
18. [Governance](#18-governance)
19. [Security Model](#19-security-model)
20. [Agent-Swarm Primitives](#20-agent-swarm-primitives)
21. [Roadmap](#21-roadmap)

---

## 1. Introduction

### 1.1 The Problem

Existing blockchains were designed for financial transactions. They can transfer tokens and execute deterministic smart contracts, but they have no native understanding of computation, hardware trust, or autonomous software agents. As AI systems become economically significant actors — executing tasks, consuming resources, and generating value — this gap creates three categories of problems:

- **No verifiable computation.** Blockchains can record that a transaction occurred, but cannot verify that an off-chain computation (such as an inference, a training step, or a data transformation) was actually performed correctly by the claimed hardware running the claimed software. Existing approaches rely on staking and economic penalties, which are probabilistic at best and gameable at worst.
- **No hardware-rooted trust.** Smart contract execution is transparent by design — every validator sees every input. There is no mechanism for confidential computation where the chain itself enforces that data remains private while still producing verifiable results. Bolting TEE support onto an existing chain as a middleware layer forfeits the security guarantees that come from integrating hardware trust into consensus itself.
- **No agent-native primitives.** AI agents that need to discover services, negotiate prices, manage funds, and coordinate with other agents must do so through human-designed interfaces and custodial wallets. There is no chain where agents are first-class participants with self-sovereign identity, their own key material, and the ability to transact autonomously within programmatic guardrails.

### 1.2 The Tenzro Solution

**Tenzro Network** is the protocol layer designed for the AI age, and the reference implementation of the **Open Agent Network (OAN)** — the standards family (TNIP-001..022) that defines the wire format for a hybrid human + agent coexisting network. OAN provides the full governance framework; Tenzro Network ships the working implementation. Specification and implementation evolve together, the wire stays open for other implementations, and conformance is demonstrated by the running network. The combined effect is the first protocol where an agent can discover a model, discover a skill, discover a task, access a resource, and pay for it through a single decentralized protocol surface — with one identity, one wallet, and one settlement substrate.

It provides two core capabilities to participants:

1. **Access to Intelligence:** A decentralized marketplace where providers serve AI models and users discover and consume inference through a chat interface (like ChatGPT/Claude). Settlements happen on-chain with micropayment channels for per-token billing.

2. **Access to Security:** Providers offer TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs) for confidential computation, key management, custody services, and verification. Users and agents can leverage hardware-rooted trust for sensitive operations.

Providers, validators, and nodes earn by:
- **Securing the network** (validator rewards and staking)
- **Providing intelligence** (per-inference fees from the AI marketplace)
- **Providing security** (fees for TEE enclave services)

**Tenzro Ledger** is the Layer 1 settlement layer that underpins the protocol. It treats hardware trust, verifiable computation, and autonomous agents as foundational primitives rather than application-layer add-ons:

- **TEE-native consensus.** Validators running inside Trusted Execution Environments receive a **1.5× multiplier** on their reputation-weighted leader-selection draw in the HotStuff-2 BFT consensus protocol. The multiplicative form (rather than a hard 2× boost) preserves the property that observed behaviour can fully overcome attestation: a TEE-attested but chronically-flaky validator is still dwarfed in draw probability by a non-TEE active validator. Hardware-secured participation becomes the economically rational default while never gating liveness. TEE attestations are verified on-chain and influence block validity.
- **Dual verification: ZK + TEE.** Every computation claim can be backed by a zero-knowledge proof (Plonky3 STARKs over the KoalaBear field with Poseidon2 + FRI commitments — transparent setup, post-quantum-conjectured soundness), a TEE attestation, or both simultaneously through hybrid ZK-in-TEE execution. This provides two independent trust anchors — cryptographic (ZK) and hardware (TEE) — giving applications flexibility to choose their security/performance tradeoff.
- **Multi-VM execution.** The Ledger supports EVM, SVM, and Daml smart contracts through a unified runtime. Applications are not limited to inference — any programmable logic can run on Tenzro, with the added capability of invoking TEE execution and ZK verification through native precompiles.
- **Agent-first design.** AI agents are first-class network participants with self-sovereign identity (DID-based via TDIP), MPC threshold wallets they control without custodians, capability-based permissions, and a native agent-to-agent (A2A) communication protocol. Agents can discover each other, negotiate services, and settle payments autonomously.
- **Native settlement primitives.** Micropayment channels, escrow contracts with programmable release conditions, and atomic batch settlement are built into the Ledger — not implemented as smart contracts on top of a generic VM. This enables sub-second settlement for high-frequency economic activity like per-token inference billing.

All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

### 1.3 Design Principles

1. **Hardware trust at the foundation.** TEE integration is not a sidecar — it influences validator selection, consensus weight, proof generation, and execution confidentiality. The Ledger is designed so that the strongest security guarantees emerge from hardware-attested participation.
2. **Cryptographic verifiability.** Claims about computation, identity, and payment are backed by mathematical proofs or hardware attestations, not economic penalties alone.
3. **General-purpose L1.** Tenzro Ledger is a programmable blockchain, not an inference-specific subnet. AI model routing and settlement are built-in capabilities, but the Ledger supports arbitrary smart contract logic across three VM targets (EVM, SVM, Daml/Canton).
4. **Economic alignment.** Token economics incentivize honest behavior: validators earn block rewards and transaction fees (gas paid in TNZO) for securing the Ledger; providers earn per-inference fees and TEE service fees with the Network taking a commission that flows to the treasury; misbehavior is punished through stake slashing.
5. **Interoperability.** Multi-VM execution and cross-chain bridges (LayerZero, CCIP, deBridge, Canton) ensure Tenzro connects to existing ecosystems rather than requiring migration.

### 1.4 Compute as Currency

Tenzro turns AI compute into a unit of economic exchange — denominated, settled, and verified in TNZO. Three surfaces share the same identity, payment, and settlement substrate, so a transaction that begins as an inference quote can become a training escrow, a cross-chain settlement, and an audit record without leaving the chain:

- **Tokenized AI inference.** Providers serve AI models (chat, vision, audio, forecasting, embeddings, segmentation, detection) on a permissionless marketplace. Users and agents pay per token (or per inference); providers earn TNZO directly with the Network taking a small commission. Confidential variants run inside TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC). Micropayment channels make high-frequency, low-value billing efficient — a per-token-priced Llama or TimesFM call settles off-chain inside a channel and finalizes on-chain at session close.
- **Tokenized AI training (Tenzro Train).** Decentralized verifiable training via a Decoupled DiLoCo–style protocol (§ Tenzro Train below). GPU providers contribute compute and earn TNZO rewards from a sponsor-funded escrow; every accepted outer gradient yields a signed receipt and every run finalizes a run-root commitment on-chain. Phase 1 is timeseries-first with simple mean aggregation, stake bonding, and the Open trust tier; Byzantine-robust aggregation (TrimmedMean / CoordinateMedian / Krum), multi-region scale, multi-modal beyond timeseries, and TEE-resident data are roadmap.
- **Agentic finance.** Autonomous agents discover providers, negotiate prices, pay, and settle in TNZO using the same TDIP identity, MPC wallet, and delegation scope. AP2 mandates, x402 micropayments, MPP sessions, ERC-8004 trustless-agent registries, and ERC-4337 v0.8 smart accounts all run inside Tenzro consensus rather than on top of a non-AI L1.

Verifiability is not optional. Inference results, settlements, and identity claims can be proven via Plonky3 STARKs over the KoalaBear field (transparent setup, post-quantum-conjectured soundness; AIRs in `tenzro-zk` cover inference, settlement, and identity) or attested by hardware enclaves — both anchored on-chain via the `ZK_VERIFY` and `TEE_VERIFY` precompiles, with `ZkCommitmentRegistry` providing O(1) on-EVM verification. Cross-chain reach is native: Wormhole NTT, LayerZero V2, Chainlink CCIP, deBridge DLN, Li.Fi, and Canton bridge adapters mean a TNZO settlement is not trapped on one chain. Where Render rents raw GPUs and Bittensor coordinates subnet intelligence, Tenzro unifies inference, training, agent settlement, identity, verification, and cross-chain reach under one tokenized substrate.

---

## 2. Architecture Overview

### 2.1 OAN, Tenzro Network, and Tenzro Ledger

Three entities, three roles. They are distinct, and the naming matters.

**Open Agent Network (OAN)** is the standards family for a hybrid human + agent coexisting network — the specification surface (TNIP-001..022) covering substrate primitives (Resolver, Skills, Mesh, Discover, Validation, Federation), composition layers (Handles, Compute, Memory, Credentials, Auth), and the identity tier (Identity, Delegation, Knowledge, Marketplace, Consensus, plus chain-specific bindings to Tenzro, Tempo, Canton, EVM, Solana, and x402). OAN is stewarded by the Tenzro Foundation and provides the full governance framework: specifications, conformance criteria, and reference implementation, all evolving together. The wire is open for any conformant implementation.

**Tenzro Network** is OAN's reference implementation — the overall protocol/platform designed for the AI age, enabling agents and autonomous systems to participate as first-class economic actors alongside humans. The Network provides:
- Access to **intelligence** (decentralized AI model marketplace)
- Access to **security** (TEE enclaves for custody, key management, confidential computing)

Tenzro Network is the first protocol where the full agent loop — discover model, discover skill, discover task, access resource, pay for it — is wire-level, not application-level. It is fully usable today with the latest protocol support, demonstrating conformance to every OAN layer end-to-end.

**Tenzro Ledger** is the Layer 1 blockchain that provides the settlement layer for the Network. The Ledger offers purpose-built primitives for the AI age:
- **Identity:** TDIP (Tenzro Decentralized Identity Protocol) for unified human/machine identity
- **Security:** TEE-weighted consensus with hardware attestations
- **Verification:** Dual ZK + TEE proof systems
- **Settlement:** Micropayment channels, escrow, batch processing (all in TNZO)

**Revenue Model (Two-Tier Fee Structure):**

1. **Ledger Transaction Fees (Gas):** All on-chain transactions pay gas fees in TNZO to validators, securing the L1 settlement layer. Uses EIP-1559 dynamic fee market.

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

The system is implemented as a Rust workspace of 23 crates plus two SDKs, organized in a strict dependency hierarchy:

| Layer | Crate | Purpose |
|-------|-------|---------|
| Foundation | `tenzro-types` | Shared types, primitives, constants (zero internal dependencies) |
| Cryptography | `tenzro-crypto` | Ed25519, Secp256k1, AES-256-GCM, X25519, MPC threshold signing, BLS12-381, VRF (RFC 9381 ECVRF) |
| Trust | `tenzro-tee` | TEE abstraction over Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC |
| Proofs | `tenzro-zk` | Plonky3 STARKs over KoalaBear (Poseidon2 + FRI), AIR circuits, hybrid ZK-in-TEE |
| Networking | `tenzro-network` | libp2p gossipsub, Kademlia DHT, peer management |
| Storage | `tenzro-storage` | RocksDB, Merkle Patricia Trie, snapshots, DA offload primitives |
| Consensus | `tenzro-consensus` | HotStuff-2 BFT, epoch management, finality tracking |
| Execution | `tenzro-vm` | Multi-VM runtime: EVM, SVM, Daml executors |
| Economics | `tenzro-token` | TNZO token, staking, rewards, treasury, governance, liquid staking, adaptive burn dial, SeedAgent earmark |
| Wallets | `tenzro-wallet` | MPC threshold wallets (2-of-3), encrypted keystore (Argon2id) |
| Identity | `tenzro-identity` | TDIP: unified human/machine identity, W3C DID, verifiable credentials, delegation, GDPR Article 17 right-to-erasure (`forget_identity`) |
| Payments | `tenzro-payments` | Payment protocols: AP2 v0.2 (sign + verify + validate-pair), MPP, x402 v1, Stripe SPT (SharedPaymentToken with TDIP cap-resolver + ERC-8004 ReputationRegistry cross-write + `granted_token.deactivated` webhook → TDIP cascade), ERC-8004 v0.6+ Trustless Agents Registry (22 surfaces), Tempo integration, Visa TAP, Mastercard Agent Pay |
| Agents | `tenzro-agent` | Agent runtime, lifecycle, A2A protocol, capability registry, runtime spending policy |
| Agent Kit | `tenzro-agent-kit` | Agent template/bootstrap/resolver/spawner kit |
| AI | `tenzro-model` | Model registry, inference routing (multi-modal), pricing engine, ONNX runtimes |
| Events | `tenzro-events` | Event bus, webhooks, WebSocket subscriptions, replay |
| Settlement | `tenzro-settlement` | On-chain escrow primitive, micropayments, batch settlement, fee collection |
| Bridge | `tenzro-bridge` | Wormhole NTT, LayerZero V2, Chainlink CCIP, deBridge DLN, Canton, Li.Fi |
| Auth | `tenzro-auth` | AuthEngine, AAP, DPoP, RAR for agent and wallet authorization |
| Cortex | `tenzro-cortex` | Cognitive primitives for agent reasoning |
| Training | `tenzro-training` | Decentralized training protocol layer (Rust) — pairs with Python reference trainer |
| Node | `tenzro-node` | Full node binary, RPC server, web verification API, MCP/A2A servers |
| CLI | `tenzro-cli` | Command-line interface |
| SDK | `tenzro-sdk` | Rust SDK with builder-pattern configuration |
| TypeScript SDK | `tenzro-ts-sdk` | TypeScript SDK for browser and Node.js integration |

### 2.4 Node Roles

Participants in the Tenzro Network operate nodes in one of several roles. Nodes can serve multiple roles simultaneously (e.g., a validator can also be a Model Provider and/or TEE Provider):

- **Validator.** Participates in consensus, proposes and votes on blocks, earns block rewards and transaction fees (gas paid in TNZO). Each validator also runs a Canton participant node natively, connecting to one or more Canton synchronizers for Daml smart contract execution. Requires a minimum stake of 1,000 TNZO. Validators secure the Ledger.

- **Model Provider.** Serves AI models for inference requests. Earns per-inference fees (paid in TNZO) settled through micropayment channels. The Network takes a 0.5% commission on provider earnings, which flows to the treasury. Model providers provide **intelligence** to the Network.

- **TEE Provider.** Operates hardware TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs) for confidential computation, key management, custody services, and attestation. Earns fees for TEE services (paid in TNZO). The Network takes a 0.5% commission on provider earnings, which flows to the treasury. TEE providers provide **security** to the Network.

- **Storage Provider.** Stores and serves blockchain state, model weights, and historical data. Earns storage fees.

- **Light Client.** Verifies block headers and proofs without storing full state. Suitable for end-user devices.

- **Bootstrap Node.** Initial peer discovery endpoint for new nodes joining the network.

- **Archive Node.** Stores complete historical state for analytics and indexing.

### 2.5 API Surface

The node exposes four API interfaces:

**JSON-RPC Server** (default `127.0.0.1:8545`):
Standard Ethereum-compatible JSON-RPC for transaction submission, state queries, and subscription management. Tenzro-specific methods include `tenzro_createAccount`, `tenzro_createWallet`, `tenzro_registerIdentity`, `tenzro_resolveIdentity`, `tenzro_resolveDidDocument`, and `tenzro_listModels`.

**Web Verification API** (default `0.0.0.0:8080`):

| Endpoint | Purpose |
|----------|---------|
| `POST /verify/zk-proof` | Verify a zero-knowledge proof |
| `POST /verify/tee-attestation` | Verify a TEE attestation report |
| `POST /verify/transaction` | Verify a transaction signature |
| `POST /verify/settlement` | Verify a settlement receipt |
| `POST /verify/inference` | Verify an inference result against its proof |
| `POST /verify/did-envelope` | Verify a DID-signed envelope |
| `GET /verify/health` | Health check |
| `GET /health` | Health check (alias) |
| `GET /status` | Node status and metrics |
| `POST /faucet` | Request testnet TNZO tokens |

**MCP Server** (default `0.0.0.0:3001`):
Model Context Protocol server using the `rmcp` crate with Streamable HTTP transport (protocol version `2025-11-25`). Exposes 331 Tenzro node capabilities as MCP tools — wallet, identity, payments, inference, multi-modal AI, staking, tokens, NFTs, bridges, verification, agents, tasks, skills, compliance, TEE, ZK, VRF, events, AgentBond + insurance, and more — that any MCP-compatible AI agent can invoke. Six additional ecosystem MCP servers run alongside on ports 3003–3008 (Solana, Ethereum, Canton, LayerZero, Chainlink, Li.Fi). See §11.6.

**A2A Protocol Server** (default `0.0.0.0:3002`):
Agent-to-Agent protocol server implementing the Google A2A specification with JSON-RPC 2.0:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/agent.json` | Agent Card discovery (per A2A spec) |
| `POST /a2a` | JSON-RPC 2.0 dispatcher for task management |
| `POST /a2a/stream` | SSE streaming for real-time task updates |

JSON-RPC methods: `message/send`, `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel`. The Agent Card advertises 24 skills covering wallet, identity, inference, cortex, settlement, verification, staking, task and agent marketplaces, agent spawning, swarm orchestration, lifecycle, bond-insurance, token, contract, AP2 payments, ERC-8004, Wormhole, CCT, join, NFT, bridge, compliance, cross-chain, and events. Supports streaming responses via Server-Sent Events and multi-turn conversation history.

---

## 3. Consensus: HotStuff-2 BFT

### 3.1 Overview

The Tenzro Ledger employs HotStuff-2, a leader-based Byzantine Fault Tolerant consensus protocol with linear message complexity. HotStuff-2 achieves consensus in two phases (as opposed to the three phases of original HotStuff), reducing latency while maintaining safety under partial synchrony. This consensus mechanism secures the L1 settlement layer.

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

### 3.5 Reputation-Weighted Proposer Election

Tenzro's default proposer-election strategy is reputation-weighted. Each round draws the leader from a stake-weighted seeded distribution where per-validator weight is multiplied by an observed-behaviour tier and a TEE multiplier:

```
weight(v) = stake(v) × tier(v) × tee_multiplier(v) / 10000

tier(v):
  ACTIVE_WEIGHT   = 1000   if v proposed ≥1 QC-certified block recently
                            and failed <10% of its proposer-window rounds
  INACTIVE_WEIGHT = 10     if v voted but didn't propose
  FAILED_WEIGHT   = 1      otherwise

tee_multiplier(v):
  15000 (1.5×) if v has a fresh valid TEE attestation in the current epoch
  10000 (1.0×) otherwise
```

The 1000× spread between ACTIVE and FAILED collapses a chronically-flaky validator's effective draw probability to ~0.1% within ~20 rounds, long before degradation propagates into chain-wide liveness loss. The multiplicative TEE form (rather than a hard 2× boost) preserves the property that observed behaviour fully overcomes attestation: a TEE-attested FAILED validator is still dwarfed by a non-TEE ACTIVE validator. The leader-draw seed is anti-grinding (`SHA-256("TENZRO_LEADER_REPUTATION:" || epoch || round || prev_finalized_block_id)`), with `prev_finalized_block_id` fixed at least one full QC ago and the proposer-history window excluding the most recent 20 rounds.

`ProposerElectionKind::RoundRobin` is retained for tests and replay benchmarks.

### 3.6 No-Endorsement Certificates (Tail-Fork Resistance)

Tenzro closes the tail-fork attack class on 2-chain HotStuff with no-endorsement certificates (NECs). The leader at view *v* must either re-propose the high-tip from view *v−1*, or attach a valid NEC for view *v*. A NEC is an *f+1* aggregation of `NoEndorsementMsg`s, each attesting "I observed no QC at view v−1". *f+1* (not *2f+1*) is the correct threshold: with at most *f* Byzantine signers, *f+1* suffices to guarantee at least one truthful "no QC observed" attestation. Domain tag `TENZRO_NO_ENDORSEMENT:` distinct from the timeout and vote tags prevents cross-message replay.

The full protocol specification with formal arguments and academic citations is at [`docs/papers/tenzro-consensus.md`](papers/tenzro-consensus.md).

### 3.7 Epoch Management

The validator set is fixed within an epoch (default 10,000 blocks). At epoch boundaries:

1. Pending validator additions and removals are processed.
2. TEE attestations are re-verified for all validators.
3. The new validator set is committed to state.
4. Staking rewards for the completed epoch are calculated and distributed.
5. The epoch history (validator set, total stake, block range) is recorded.

### 3.8 Finality

Blocks achieve finality when they receive a commit certificate (2f+1 commit votes). The `FinalityTracker` enforces sequential finalization — blocks must be finalized in height order. Once finalized, a block cannot be reverted. The finality tracker also supports fork choice: when multiple candidate blocks exist at the same height, the one with the most accumulated votes is selected.

---

## 4. Multi-VM Execution Layer

### 4.1 Architecture

The Tenzro Ledger's execution layer supports three virtual machines through a unified `MultiVmRuntime` that routes transactions to the appropriate executor based on the transaction's `VmType`:

- **EVM (Ethereum Virtual Machine).** Full EVM-compatible execution for Solidity and Vyper smart contracts.
- **SVM (Solana Virtual Machine).** Solana-compatible execution for programs written in Rust targeting the BPF instruction set.
- **Daml (Digital Asset Modeling Language).** Enterprise smart contract execution powered by Canton Network. Each Tenzro validator runs a Canton participant node natively, connecting to one or more Canton synchronizers (the Canton 3.5+ term for what were previously called "domains"). Self-hosted participants expose the Ledger API on gRPC (port 5001 — `CommandService.SubmitAndWait`, `StateService.GetActiveContracts`, `UpdateService.GetUpdates`) and the Admin API on gRPC (port 5002 — `PackageService.UploadDar`). The Tenzro-operated DevNet (`json.devnet.tenzro.network`) instead exposes the equivalent Canton 3.5+ JSON Ledger API v2 (`POST /v2/commands/submit-and-wait-for-transaction`, `POST /v2/state/active-contracts`, `POST /v2/packages`) gated by Auth0 client-credentials, so external builders can reach Canton without operating their own participant. Canton handles Daml contract lifecycle, sub-transaction privacy (parties only see events for contracts where they are stakeholders), and multi-synchronizer coordination through the Global Synchronizer. From the developer's perspective, Daml transactions are initiated through the same multi-VM interface as EVM and SVM calls.

### 4.2 Execution Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Max gas limit | 30,000,000 | Maximum gas per transaction |
| Default gas limit | 10,000,000 | Default gas if unspecified |
| Min gas price | 1 Gwei (10^9 wei) | Minimum gas price |
| Max contract size | 24,576 bytes | EIP-170 contract size limit |
| Default chain ID | 1337 | Development chain identifier |
| Max call depth | 1,024 | Maximum nested call depth |

### 4.3 Precompile Registry

The VM provides precompiled contracts that expose native platform functionality to smart contracts. In addition to the 9 standard EVM precompiles (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, BN254 EC operations, BLAKE2F per EIPs 196/197/198/1108/2565/152) and 7 BLS12-381 precompiles (EIP-2537 at 0x0a–0x10: G1ADD, G1MSM, G2ADD, G2MSM, PAIRING_CHECK, MAP_FP_TO_G1, MAP_FP2_TO_G2 via the `blst` library), the VM exposes Tenzro-specific precompiles:

| Address | Precompile | Description |
|---------|------------|-------------|
| `0x1001` | TNZO_BRIDGE | Cross-VM token transfers between EVM, SVM, and Canton |
| `0x1002` | TOKEN_FACTORY | Create and register new ERC-20 tokens in the unified registry |
| `0x1003` | CROSS_VM_BRIDGE | Atomic cross-VM token movement with balance verification |
| `0x1004` | STAKING | Stake/unstake TNZO and query staking state from smart contracts |
| `0x1005` | GOVERNANCE | Submit proposals and cast votes from smart contracts |
| `0x1006` | NFT_FACTORY | NFT creation and minting; `mintRandom()` (selector `0x52517e21`) consumes a verified VRF output to derive token_id and rarity tier |
| `0x1007` | VRF_VERIFY | RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI verifiable random function — reuses Ed25519 validator keys, low-order-key rejection, canonical-scalar rejection |
| `0x101a` | ERC8004_IDENTITY | ERC-8004 v0.6+ Trustless Agents — `register()` / `register(string)` / `register(string,(string,bytes)[])` / `getAgent` / `setAgentURI` / `setAgentWallet` (with EIP-712 signature) / `setMetadata` / `getMetadata` / `getAgentURI` / `getAgentWallet` for native Tenzro agent discovery. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — server-allocated, never derivable client-side. |
| `0x101b` | ERC8004_REPUTATION | ERC-8004 v0.6+ — `submitFeedback` / `getFeedback` / `getFeedbackCount` / `revokeFeedback` / `isFeedbackRevoked` / `appendResponse` / `getFeedbackResponses` for peer-to-peer agent reputation |
| `0x101c` | ERC8004_VALIDATION | ERC-8004 v0.6+ — `validationRequest` / `validationResponse` / `getValidation` for verifiable agent work attestation |

Selectors for the ERC-8004 trio are byte-identical to the canonical Ethereum mirror, so the same calldata works against either the native Tenzro registry or the Ethereum deployment.

Native verification precompiles also include:

- **TEE_VERIFY.** Verify TEE attestations (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC) with on-chain X.509 certificate chain validation.
- **ZK_VERIFY.** O(1) HashSet lookup against the on-chain `ZkCommitmentRegistry`. Plonky3 STARK proofs are verified off-EVM by validators who record 32-byte SHA-256 commitments via `compute_zk_commitment(circuit_id, proof_bytes, public_inputs)`; the precompile rejects unknown commitments.
- **Model Inference.** Query the model registry, submit inference requests, and verify inference results.
- **Settlement.** Create escrows, open micropayment channels, and trigger settlement operations.

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

The Ledger implements ERC-4337 v0.8 account abstraction, enabling smart contract wallets. The v0.8 format splits legacy `initCode` into `factory`/`factoryData` and legacy `paymasterAndData` into `paymaster`/`paymasterVerificationGasLimit`/`paymasterPostOpGasLimit`/`paymasterData`, with PackedUserOperation support, EIP-712 typed data hashing, and a gas penalty threshold of 40,000:

- **EntryPoint contract.** Central singleton that validates and executes `UserOperation` bundles (max bundle size: 100).
- **SmartAccount.** Contract wallets with pluggable modules:
  - `SocialRecovery` — Multi-guardian key recovery
  - `SessionKey` — Time-limited session keys for dApps
  - `SpendingLimit` — Per-token/per-period spending caps
  - `Batching` — Atomic multi-call execution
- **AccountFactory.** Deterministic CREATE2 deployment of smart accounts from a salt and owner address.
- **Paymaster.** Gas sponsorship — third parties can pay gas on behalf of users, enabling gasless transactions.

### 4.8a EIP-7702 Type-4 Delegation

EIP-7702 (Pectra, May 2025) lets an externally-owned account (EOA) borrow smart-contract code at its existing address by signing a `(chain_id, address, nonce)` authorization. Tenzro implements the protocol primitive in `tenzro-vm::eip7702`:

- **Signed authorization.** `Eip7702Authorization { chain_id, delegate_address, nonce, signature }` with the canonical preimage `MAGIC(0x05) || rlp([chain_id, address, nonce])` and recoverable secp256k1 signature `(r, s, y_parity)`.
- **Delegation registry.** `DelegationRegistry` records authority → target pointers atomically, accepts `chain_id == 0` as the cross-chain wildcard per the spec, refuses authority/declared mismatches, and treats `delegate_address == 0x0` as a revocation.
- **Designator encoding.** Per the EIP, the authority's on-chain code field becomes the 23-byte `0xef0100 || target_address(20)` designator; `is_delegation_designator` / `extract_delegation_target` detect and decode it. The EVM executor consults `resolve_target` when it encounters this magic prefix and runs the target's code in the authority's storage context.
- **RPC surface.** `tenzro_install7702Delegation`, `tenzro_get7702Delegation`, `tenzro_revoke7702Delegation` for relayers and wallets; the stateless `tenzro_eip7702SigningHash` / `tenzro_eip7702BuildDesignator` / `tenzro_eip7702ParseDesignator` / `tenzro_eip7702ProtocolInfo` helpers remain for offline signing flows.

### 4.8b Permit2 SignatureTransfer

Permit2 lets a token holder sign a one-shot authorization that any third party can use to pull a bounded amount of a token. Tenzro implements the protocol primitive in `tenzro-vm::permit2`:

- **EIP-712 typed data.** `TokenPermissions { token, amount }`, `PermitTransferFrom { permitted, spender, nonce, deadline }`, and `PermitTransferFromWitness { …, witness, witness_type_name, witness_type_string }` with deterministic typehashes that bind any witness type-string inline so EIP-712 verifiers render the full struct shape.
- **Domain separator.** Computed against the Tenzro canonical Permit2 verifying contract `0x0000…00001023` and the current chain id.
- **Nonce bitmap.** Per-owner 256-bit-per-word bitmap (`Permit2NonceBitmap`) — owners can sign multiple permits in parallel without serializing through a single counter, mirroring the Uniswap layout.
- **Witness path.** When the witness triple is supplied, the typehash is the witness-bearing form. This is what an ERC-7683 origin opener uses: the permit witness is the order id, so signing the permit also signs the cross-chain intent — one signature, end-to-end.
- **RPC surface.** `tenzro_permit2DomainSeparator`, `tenzro_permit2Digest`, `tenzro_permit2VerifyAndConsume`, `tenzro_permit2NonceUsed`.

### 4.8c Secure-Mint Registry

Tokenized RWAs require that the on-chain circulating supply never exceeds the off-chain attested reserve. Tenzro implements the protocol primitive in `tenzro-vm::secure_mint`:

- **Per-token policy.** `SecureMintPolicy { asset_id, reserve, circulating, por_feed_id, attester_did, attestation_hash, attested_at, ttl_secs }`. Tokens without a policy are pass-through; tokens with one are gated by `check_and_mint(token, amount, now)` which enforces both the `circulating + amount ≤ reserve` invariant and the attestation freshness window.
- **Tokenized-equity profile sidecar.** `TokenizedEquityProfile { cct_pool_address, por_feed_id, underlying_caip19, isin, cusip, per_share_ratio, last_corporate_action }` lets the unified token registry carry equity-class metadata alongside the Secure-Mint policy.
- **Burn accounting.** `record_burn` decrements circulating supply on redemption.
- **RPC surface.** `tenzro_setSecureMintPolicy`, `tenzro_getSecureMintPolicy`, `tenzro_clearSecureMintPolicy`, `tenzro_secureMintCheck`, `tenzro_secureMintApply`, `tenzro_secureMintRecordBurn`. EVM precompile slot reserved at `0x0000…00001024`.

This is the L1-level invariant the xStocks / BUIDL / tokenized-treasury class needs: a malicious issuer cannot mint above attested reserves, and stale attestations fail closed.

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

---

## 5. Trusted Execution Environments

### 5.1 Overview

Tenzro provides first-class support for hardware-based confidential computation through four TEE technologies:

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

Tenzro implements a Plonky3 STARK proof system over the **KoalaBear field** (`2^31 − 2^24 + 1`, two-adicity 24) with **Poseidon2** algebraic hashing and **FRI** polynomial commitments. The system is transparent (no trusted setup, no per-circuit proving key), post-quantum-conjectured sound, and produces proofs in the ~64–128 KB range that verify in ~5–20 ms on commodity hardware.

### 6.2 AIR Circuits

Three domain-specific AIRs (Algebraic Intermediate Representations) are provided as constraint polynomials over the KoalaBear field:

**Identity AIR.** Proves knowledge of a private key corresponding to a public identity without revealing the key.

**Inference AIR.** Proves that an inference result was correctly computed from a given model and input — public inputs are the model hash, input hash, and output hash.

**Settlement AIR.** Proves that a settlement amount correctly reflects the agreed service terms — public inputs are the service hash, settlement hash, and amount.

### 6.3 Pinned Testnet Configuration

The testnet uses a pinned FRI configuration: `log_blowup = 1`, `num_queries = 64`, `query_pow = 16`, `commit_pow = 8`. The Plonky3 source is pinned at git rev `32079474b1d31d9221656ae774afb322d2597db0`. These parameters are surfaced via `build_testnet_config()` and consumed by every prover and verifier in the workspace.

### 6.4 Hybrid ZK-in-TEE

Tenzro provides a hybrid verification model that combines Plonky3 proofs with TEE attestations:

1. A TEE enclave produces the AIR witness, runs the prover inside the enclave, and signs the result with its hardware-rooted Ed25519 key.
2. Verifiers check both the mathematical proof and the hardware attestation.

This provides defense-in-depth: even if one trust assumption fails (e.g., an AIR constraint bug or a TEE side-channel), the other layer provides a fallback guarantee. The pipeline is exposed via `tee_integration::{generate_tee_zk_proof, verify_tee_zk_proof, sign_tee_zk_proof, verify_tee_zk_signature}`.

### 6.5 Proof Lifecycle

```
Prove:    AIR + witness --> Plonky3 prover --> Proof envelope
Verify:   Proof envelope --> verify_proof_envelope(&Proof) --> bool
```

`tenzro_zk::verify_proof_envelope(&Proof)` is the single entry point used by web/MCP/RPC handlers and the settlement engine — it dispatches on `circuit_id` (`"inference" | "settlement" | "identity"`) and runs the right AIR's `Plonky3Verifier` against the pinned testnet config. Wire format:

```
Proof {
    proof_bytes:    Vec<u8>,           // bincode-serialized p3_uni_stark::Proof
    public_inputs:  Vec<Vec<u8>>,      // 4-byte LE chunks of KoalaBear field elements
    proof_type:     ProofType::Plonky3,
    circuit_id:     String,            // "inference" | "settlement" | "identity"
    created_at:     Timestamp,
    metadata:       ProofMetadata,
}
```

### 6.6 Commitment-Attestation Model

Validators run the full Plonky3 verifier off-EVM and record 32-byte SHA-256 commitments in the on-chain `ZkCommitmentRegistry`:

```
compute_zk_commitment(proof) = SHA-256(circuit_id ‖ proof_bytes ‖ Σ(len_le(pi) ‖ pi))
```

The EVM `ZK_VERIFY` precompile is then an O(1) HashSet lookup against that registry. This decouples expensive STARK verification from EVM gas costs while keeping the trust anchor on-chain.

---

## 7. Cryptographic Primitives

### 7.1 Key Algorithms

| Algorithm | Purpose | Key Sizes |
|-----------|---------|-----------|
| Ed25519 | Transaction and message signatures | 32-byte public key, 64-byte signature |
| Secp256k1 | Ethereum-compatible signatures, key derivation | 33-byte compressed public key |
| AES-256-GCM | Symmetric encryption for keystore and data at rest | 256-bit key, 96-bit nonce, 128-bit tag |
| X25519 | Elliptic-curve Diffie-Hellman key exchange | 32-byte public key |
| SHA-256 | General-purpose hashing, Merkle trees | 256-bit digest |
| Keccak-256 | Ethereum address derivation, storage keys | 256-bit digest |

### 7.2 Address Derivation

Addresses are 32-byte values derived from public keys:
- **Ed25519:** The raw 32-byte public key is truncated to 20 bytes, then zero-padded to 32 bytes.
- **Secp256k1:** Keccak-256 hash of the uncompressed public key, last 20 bytes, zero-padded to 32 bytes (Ethereum-compatible).

### 7.3 MPC Threshold Signing

The network implements multi-party computation for threshold signatures using Shamir's Secret Sharing over GF(256):

1. **Key Generation.** A secret key is split into `n` shares with a threshold of `t` (default: 2-of-3). Each share is distributed to a different custodian or device.
2. **Signing.** Any `t` shareholders produce partial signatures. These are combined using Lagrange interpolation to produce a valid full signature.
3. **Reconstruction.** The secret can be reconstructed from `t` shares using `reconstruct_secret()`, but this is only used for key recovery — normal operations use partial signature combination.

### 7.4 Envelope Encryption

For data at rest (keystore files, cached keys), Tenzro uses envelope encryption:
1. A data encryption key (DEK) is generated randomly.
2. Data is encrypted with AES-256-GCM using the DEK.
3. The DEK is encrypted with a key encryption key (KEK) derived from the user's password via iterated SHA-256 (10,000 rounds).
4. The encrypted DEK, salt, nonce, and ciphertext are stored together.

---

## 8. TNZO Token Economics

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
- Provides economic security for the L1 settlement layer

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

Participants stake TNZO to become validators or service providers:

| Parameter | Value |
|-----------|-------|
| Minimum stake | 1,000 TNZO |
| Unbonding period | 7 days (604,800,000 ms) |
| Slashing | Variable, based on offense severity |

**Provider types and staking:**

| Provider Type | Reward Multiplier | Description |
|--------------|-------------------|-------------|
| Validator | 1.0x | Block production and consensus |
| TEE Provider | 1.2x (20% bonus) | Hardware-attested confidential compute |
| Model Provider | 1.1x (10% bonus) | AI model serving |
| Storage Provider | 1.0x | Data storage and serving |

The elevated multiplier for TEE providers incentivizes investment in hardware-rooted trust infrastructure.

**Staking lifecycle:**
1. **Stake.** Lock TNZO against a provider type. Must meet minimum stake requirement.
2. **Active.** Stake is active; provider participates in the network and earns rewards.
3. **Unbonding.** Initiate unstake; stake is locked for the unbonding period.
4. **Withdrawn.** After unbonding completes, stake can be withdrawn.

**Slashing** reduces a provider's stake for provable misbehavior. Slash events are recorded with timestamp, amount, reason, and the address of the slashing authority. Slashed funds are burned, removing them from circulation. The consensus engine detects equivocation (double voting) via `EquivocationDetector` and triggers automatic slashing through a `SlashingCallback` trait — the node's `StakingSlashingCallback` bridges consensus detection to the `StakingManager`, slashing 10% of the validator's stake with full evidence logging. The complete pipeline is: detect equivocation in `VoteCollector` → collect evidence (conflicting votes) → invoke `SlashingCallback` → `StakingManager::slash()` → burn slashed tokens.

### 8.4 Reward Distribution

Rewards are calculated and distributed per epoch:

| Parameter | Value |
|-----------|-------|
| Epoch duration | 14,400 blocks (~1 day at 6s/block) |
| Base reward rate | 5% APY (500 basis points) |

**Reward calculation for each staker:**

```
epoch_budget = total_staked * (reward_rate / 10000) / 365

For each staker:
  stake_proportion = staker_amount / total_staked
  base_reward = epoch_budget * stake_proportion
  uptime_adjusted = base_reward * uptime_percentage
  final_reward = uptime_adjusted * provider_type_multiplier
```

Rewards accumulate as pending balances and must be explicitly claimed. Double-distribution is prevented by tracking which epochs have been distributed. Epoch reward calculations are enforced to be sequential — epoch N must be processed before epoch N+1.

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

For services requiring conditional release:

```
EscrowAccount {
    escrow_id:          String,
    payer:              Address,
    payee:              Address,
    amount:             u128,
    asset_id:           AssetId,
    created_at:         Timestamp,
    expires_at:         Timestamp,
    status:             EscrowStatus,     // Funded | Released | Refunded | Expired
    release_conditions: ReleaseConditions,
}
```

**Release conditions:**
- `ProviderSignature` — Released when the provider signs a completion proof.
- `ConsumerSignature` — Released when the consumer confirms satisfaction.
- `BothSignatures` — Requires signatures from both parties (2 signatures minimum).
- `VerifierSignature` — Released by a third-party verifier or oracle.
- `Timeout` — Auto-released or refunded after a deadline.
- `Custom { condition }` — User-defined conditions.

**Escrow lifecycle:**
1. Consumer creates escrow, locking funds from their balance.
2. Provider delivers the service and submits a `ServiceProof`.
3. The escrow engine verifies the proof against release conditions.
4. On success, funds are released to the payee. On failure or timeout, funds are refunded to the payer.
5. A background process periodically scans for expired escrows and auto-refunds them.

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

### 9.6 Capital Intent — agentic capital allocation

Above mechanical settlement sits the **Capital Intent** standard: the regulated-capital-markets analog of an AP2 Intent Mandate, and a primitive no other 2026 stack provides. A principal signs a financial *objective* — acquire, exit, rebalance, hedge, or yield — bounded by risk constraints (slippage, deadline, allowed venues/chains), a regulatory regime (Reg S / Reg D / MiFID II), a minimum KYC tier, and hard capital ceilings (AP2 mandate + delegation scope). Solver agents, ranked by ERC-8004 reputation and Know-Your-Agent identity, compete to fulfil it; fulfilment runs as a saga (execute → verify → compensate) over ERC-7683 / CCIP settlement legs, each gated by `erc3643` compliance and proven for best execution. Backing is enforced by **attested-mint**: a tokenized asset can only be minted while `supply ≤ attested reserves`, making 1:1 backing a protocol invariant rather than an issuer promise. Capital Intent thus binds Tenzro's identity, wallet, compliance, custody, and cross-chain rails into one coordination layer between autonomous agents and regulated tokenized money and assets. Wire surface: `tenzro_capitalIntent*` and `tenzro_submitReserveAttestation` / `tenzro_attestedMint` / `tenzro_getReserve`, mirrored across MCP, the agent SDK, and the `tenzro capital` CLI.

---

## 10. AI Model Marketplace

### 10.1 Model Registry

The `ModelRegistry` maintains a decentralized catalog of available AI models:

```
ModelInfo {
    model_id:      String,
    name:          String,
    description:   String,
    version:       String,
    category:      ModelCategory,    // LLM | ImageGen | Speech | Embedding | Custom
    modality:      ModelModality,    // Text | Image | Audio | Multimodal
    provider:      Address,
    price_per_token: u128,           // In TNZO per token
    min_stake:     u128,             // Required provider stake
    tee_required:  bool,
    supported_formats: Vec<String>,
    max_context_length: u64,
    parameters:    HashMap<String, String>,
}
```

Models are registered by providers, who must meet the minimum stake requirement. The registry supports filtering by category, modality, and provider.

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

The `HfArtifactDownloader` handles model weight distribution from HuggingFace Hub with two artifact modes:
- `ArtifactSpec::SingleFile { filename, extension }` — for GGUF / single-file ONNX
- `ArtifactSpec::Bundle { files, dir_name }` — for multi-file ONNX (encoder/decoder/joiner)

Tmp-dir-rename atomic finalization, progress tracking, integrity verification via SHA-256, and resumable chunk-based transfer.

### 10.6 Multi-Modal Inference Runtimes

Beyond chat / LLM serving, the network ships seven ONNX-backed inference runtimes — each with its own catalog and provider pool, dispatched by `InferenceRouter::route()` reading `model.modality` from the registry:

| Runtime | Catalog | Modality |
|---------|---------|----------|
| `TimeseriesRuntime` | TimesFM 2.5 | Forecast (`[1, ctx_len] -> [1, horizon]` or quantile output) |
| `VisionRuntime` | CLIP ViT-B/32 + L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16 | Image embed / similarity / classification |
| `TextEmbeddingRuntime` | Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M, BGE-M3, Snowflake Arctic Embed L v2.0 | Text embed (Matryoshka 768/512/256/128 supported) |
| `SegmentationRuntime` | SAM 3 / 3.1, SAM 2 base/large, EdgeSAM, MobileSAM | Two-pass encoder/decoder with point/box prompts |
| `DetectionRuntime` | RF-DETR n/s/m/b/l/2xl, D-FINE n/s/m/l/x | NMS-free DETR-family detection |
| `AudioRuntime` | Distil-Whisper, Whisper-large-v3-turbo, Moonshine v2, Parakeet-TDT-v3, Canary-1B-Flash | ASR (encoder/decoder/joiner bundles or single-encoder) |
| `VideoRuntime` | Wave-1 scaffold (frame extraction via ffmpeg + per-frame vision encoder fallback) | Video embed |

License-tier gating is enforced centrally in `ModelRegistry::register_model()` — `Permissive | Attribution | CommercialCustom | NonCommercial`. NonCommercial entries refuse to load without `--accept-non-commercial`; CommercialCustom (DINOv3, SAM, Gemma terms) require explicit `--accept-license <id>` per family.

The 24 multi-modal RPCs (`tenzro_listForecastCatalog`, `tenzro_forecast`, `tenzro_listVisionCatalog`, `tenzro_visionEmbed`, `tenzro_visionSimilarity`, `tenzro_visionClassify`, `tenzro_listTextEmbeddingCatalog`, `tenzro_textEmbed`, `tenzro_listSegmentationCatalog`, `tenzro_segment`, `tenzro_listDetectionCatalog`, `tenzro_detect`, `tenzro_listAudioCatalog`, `tenzro_transcribe`, `tenzro_listVideoCatalog`, `tenzro_videoEmbed`, plus per-modality `loadModel` / `unloadModel` / `listModels` triplets) are mirrored as 24 MCP tools and 7 A2A skills, with corresponding CLI commands (`forecast`, `embed-text`, `embed-image`, `segment`, `detect`, `transcribe`, `embed-video`).

---

## 11. Autonomous Agent Framework

### 11.1 Overview

Tenzro provides a first-class runtime for autonomous AI agents that can discover peers, negotiate services, execute tasks, and settle payments without human intervention.

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

**Agent Card.** Each node publishes an Agent Card at `/.well-known/agent.json` per the A2A specification. The card advertises the node's capabilities, skills, supported input/output modes, authentication requirements, and protocol version. The card advertises 24 skills (wallet, identity, inference, cortex, settlement, verification, staking, task and agent marketplaces, agent spawning, swarm orchestration, lifecycle, bond-insurance, token, contract, AP2 payments, ERC-8004, Wormhole, CCT, join, NFT, bridge, compliance, cross-chain, events).

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
- Protocol version: `2025-03-26`
- Transport: Streamable HTTP (endpoint: `/mcp`)
- Capabilities: Tools
- Server name: `tenzro`
- Total tools: 196 (169 base + 24 multi-modal AI + 3 AgentBond/insurance)

The base tool set covers wallet operations, identity and delegation, payments (MPP / x402 / native), AI inference, multi-modal AI (forecast, vision embed, text embed, segmentation, detection, ASR transcription, video embed), staking and providers, tokens and contracts, NFTs, cross-chain bridges, verification (ZK / TEE / VRF), agents and tasks, skills and tools, compliance, events, ERC-8004 trustless agents, AgentBond + insurance claims, and onboarding.

**Ecosystem MCP servers** run alongside the main Tenzro MCP server, each as an independent Streamable HTTP service:

| Server | Port | Purpose |
|--------|------|---------|
| Solana MCP | 3003 | Jupiter, SPL, Metaplex DAS, SNS |
| Ethereum MCP | 3004 | Chainlink feeds, ENS, ERC-8004, EAS |
| Canton MCP | 3005 | DAML JSON Ledger API v2, CIP-56, DvP |
| LayerZero MCP | 3006 | LayerZero V2 messaging, OFT, DVNs |
| Chainlink MCP | 3007 | CCIP, data feeds, automation, VRF, PoR |
| Li.Fi MCP | 3008 | Cross-chain aggregation across 130+ chains |

All ecosystem MCP servers are published in the MCP Registry and reachable at `network.tenzro/*` via DNS authentication. All tool parameter schemas are generated via `schemars::JsonSchema` for automatic schema discovery by MCP clients.

### 11.7 OpenClaw Skill Integration

An OpenClaw-compatible skill definition (`skills/openclaw-tenzro/SKILL.md`) allows OpenClaw agents to interact with the Tenzro blockchain. The skill provides structured instructions for:
- Connecting to Tenzro's JSON-RPC, Web API, MCP, and A2A endpoints
- Creating wallets and checking balances
- Sending transactions and requesting faucet tokens
- Registering and resolving identities
- Verifying proofs and checking node status

### 11.8 Agent Templates

Agent Templates are reusable, versioned blueprints for spawning autonomous agents without writing code. The network ships with 10 reference templates covering common agentic patterns:

| Template | Type | Description |
|----------|------|-------------|
| DeFi Trading Agent | Specialist | Automated trading across DEXs with risk management |
| Smart Contract Auditor | Specialist | Automated security analysis of smart contract code |
| Data Pipeline Processor | Worker | ETL and data transformation workflows |
| Customer Support Agent | Assistant | Conversational support with knowledge base integration |
| Content Moderation Agent | Validator | Automated content review and policy enforcement |
| Multi-Chain Portfolio Manager | Coordinator | Orchestrates portfolio rebalancing across multiple chains and DeFi protocols |
| Intelligent Payment Router | Specialist | Selects optimal payment protocol and routing path based on cost, speed, and chain availability |
| Cross-Chain Liquidity Aggregator | Custom | Autonomously sources and aggregates liquidity across bridge adapters and DEXs |
| Autonomous RWA Custodian | Custom | Manages real-world asset tokenization lifecycle with TEE-backed custody and compliance |
| Agentic Inference Marketplace | Coordinator | Discovers, benchmarks, and routes inference requests to optimal providers on behalf of other agents |

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

### 12.9 Right to Erasure

TDIP supports GDPR Article 17 right-to-erasure as a two-phase flow that respects the cascading-revocation invariant from §12.7. First, `tenzro_revokeIdentity` marks the identity `Revoked`; the cascading revocation broadcaster propagates the status change to peers (cascading-revoking any controlled machines) and to dependent payment binders (Stripe SPT `granted_token.deactivated`, AP2 mandate cache). Once propagation has settled, `tenzro_forgetIdentity { did }` hard-deletes the identity from `CF_IDENTITIES` and the in-memory `IdentityRegistry`. The DID must already be `Revoked`; calling forget on an `Active` identity returns an error. Forget is irreversible — the DID becomes unresolvable on this node, and bound credentials and delegation scopes are dropped. Audit-trail receipts that referenced the DID remain.

---

## 13. Payment Protocols

### 13.1 Overview

Tenzro supports multiple payment protocols for machine-to-machine and human-to-machine commerce. All protocols use the HTTP 402 Payment Required flow: a server issues a payment challenge, a client creates a payment credential, and the server verifies and settles.

The `tenzro-payments` crate implements multiple protocols with a unified `PaymentProtocol` trait and a `PaymentGateway` that routes across them.

### 13.2 Supported Protocols

| Protocol | Origin | Use Case |
|----------|--------|----------|
| **MPP** (Machine Payments Protocol) | Stripe / Tempo | Session-based machine payments with HTTP 402 |
| **x402** v1 | Coinbase | Stateless HTTP 402 payments |
| **AP2** v0.2 (Agent Payments Protocol) | Google / FIDO Alliance | Sign + verify + validate-pair of intent / cart / payment VDC mandates; three-layer ceiling (mandate constraints + DelegationScope + SpendingPolicy) for agent commerce |
| **Stripe SPT** (SharedPaymentToken) | Stripe | Token primitive paired with MPP wire + Tempo settlement; `tenzro_sptIssue` / `tenzro_sptVerify` with TDIP cap-resolver, AP2 cart-mandate cross-check, ERC-8004 ReputationRegistry cross-write on settled outcome, `granted_token.deactivated` webhook cascade into TDIP `apply_remote_revocation` |
| **ERC-8004** v0.6+ (Trustless Agents Registry) | Ethereum | Identity / Reputation / Validation registry — 22 surfaces, byte-identical calldata to native EVM precompiles `0x101a`/`0x101b`/`0x101c` |
| **Visa TAP** (Tokenized Agent Payments) | Visa | Card-network-settled agent transactions |
| **Mastercard Agent Pay** | Mastercard | Enterprise agent payment orchestration via Mastercard Agent Pay SDK |
| **Tempo** | Tempo Network | Stablecoin settlement via Tempo blockchain |
| **Direct** | Tenzro native | On-chain TNZO settlement |
| **Channel** | Tenzro native | Off-chain micropayment channels |

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

### 13.4 MPP (Machine Payments Protocol)

MPP, co-authored by Stripe and Tempo, provides session-based HTTP 402 payments:

- **MppChallenge** — Issued by the server with amount, asset, recipient, and chain
- **MppCredential** — Created by the client, signed with the payer's wallet
- **MppReceipt** — Returned after settlement with transaction reference
- **MppSession** — Tracks ongoing payment relationships between payer and payee
- **MppSessionManager** — Thread-safe session lifecycle management
- **MppPaymentServer** — HTTP handler that issues 402 responses
- **MppClient** — Client-side credential creation and submission

### 13.5 x402 (Coinbase)

x402 provides stateless HTTP 402 payments:

- **X402PaymentRequired** — 402 response header with payment requirements
- **X402PaymentPayload** — Payment data submitted by the client
- **X402Facilitator** — Coordinates between payer, payee, and settlement
- **X402PaymentServer** — HTTP handler for x402 flow
- **X402Client** — Client-side payment creation

### 13.6 Tempo Integration

Direct integration with the Tempo blockchain for stablecoin settlement:

- **TempoConfig** — Tempo network connection configuration
- **TempoBridgeAdapter** — Bridge adapter for cross-chain settlement to Tempo
- **Tip20Token** / **Tip20Balance** — TIP-20 stablecoin abstractions (USDC, USDT on Tempo)
- **TempoParticipant** — Direct participation in the Tempo network

### 13.7 Identity-Bound Payments

Payments are bound to TDIP identities through the `identity_binding` module. The `IdentityPaymentBinder` enforces a two-axis ceiling on every payment:

1. **Protocol-level `DelegationScope`** via `IdentityRegistry::enforce_operation` — `max_transaction_value`, `allowed_operations`, `allowed_payment_protocols`, `allowed_chains`, `time_bound`. This is the structural ceiling, set at identity registration and immutable except via cascading revocation.

2. **Runtime `SpendingPolicy`** via the pluggable `SpendingPolicyResolver` trait — `max_per_transaction`, `max_daily_spend`, `current_daily_spend`, `enabled`. This is the execution ceiling, mutable, and tracks rolling daily-spend windows.

Both ceilings must pass for the payment to settle. The runtime policy is registered per-machine-DID on `AgentRuntime` and consulted at payment time via the `AgentRuntimeSpendingPolicyResolver` bridge wired into `IdentityPaymentBinder` at node startup. Absent a resolver entry, the binder falls back to DelegationScope-only.

### 13.8 AP2 Mandate Sign + Verify + Validate

AP2 v0.2 surfaces three RPCs:

- **`tenzro_ap2SignMandate { mandate_kind, mandate, signer_did }`** — the wallet bound to `signer_did` signs the canonical preimage with its Ed25519 key. Mandate kinds: `checkout`, `payment`. Only AP2 v0.2 `"ed25519"` alg is supported.
- **`tenzro_ap2VerifyMandate { vdc }`** — verifies the Ed25519 signature against the signer DID's resolved verification method.
- **`tenzro_ap2ValidateMandatePair { intent_vdc, cart_vdc }`** — `Ap2Validator::validate_with_delegation_and_policy` enforces all three nested ceilings on the cart in one pass:
  1. AP2 v0.2 CheckoutMandate constraints (item set, max_amount).
  2. TDIP DelegationScope (`enforce_operation`).
  3. Runtime SpendingPolicy (`SpendingPolicySnapshot::check`).

The validate-pair surface is wired into the `tenzro_ap2ValidateMandatePair` RPC and exposed as the `ap2-payments` skill on the A2A server.

### 13.9 Stripe SPT (SharedPaymentToken)

Stripe SPT is the token primitive that pairs with the MPP wire and Tempo settlement layers (the three layers of the Stripe agentic stack). Tenzro participates as a token issuer with TDIP-anchored cap enforcement:

- `tenzro_sptIssue` signs an SPT bound to a principal/agent DID pair after `SptCeilingResolver` cross-checks the requested cap against the principal's `DelegationScope` and runtime `SpendingPolicy`.
- `tenzro_sptVerify` checks signature, principal/agent DID activity, and remaining cap.
- AP2 cart-mandate validation cross-checks `usage_limits ≥ cart_total` for SPT-backed carts.
- ERC-8004 `ReputationRegistry` cross-write on every settled outcome (paid / refunded / disputed) gives every Stripe-issued agent token a corresponding on-chain reputation footprint.
- The Stripe `granted_token.deactivated` webhook is dispatched into TDIP `apply_remote_revocation`, propagating the revocation to peers via the cascading-revocation broadcaster.

### 13.10 HTTP Middleware

The `tenzro-payments` crate provides axum middleware for automatic payment handling:
- Servers wrap their routes with payment middleware to auto-issue 402 challenges
- Clients use payment-aware HTTP clients that auto-create credentials

### 13.11 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `mpp` | Enabled | Machine Payments Protocol support |
| `x402` | Enabled | Coinbase x402 v1 protocol support |
| `ap2` | Enabled | AP2 v0.2 sign + verify + validate-pair |
| `stripe-spt` | Enabled | Stripe SharedPaymentToken issuance + verify + cap-check |
| `erc8004` | Enabled | ERC-8004 v0.6+ Trustless Agents Registry encode/decode |
| `visa-tap` | Enabled | Visa Tokenized Agent Payments support |
| `mastercard-agent-pay` | Enabled | Mastercard Agent Pay SDK support |
| `tempo-bridge` | Disabled | Direct Tempo network settlement |

---

## 14. Cross-Chain Bridge

### 14.1 Overview

Tenzro connects to external blockchain ecosystems through bridge adapters that enable cross-chain asset transfers and message passing. Public-network adapters target EVM, Solana, and other major chains; a Canton adapter provides enterprise connectivity to Canton synchronizers.

**Layered interop strategy:** Wormhole NTT is the canonical TNZO transfer path, LayerZero V2 with a mandatory Tenzro DVN handles arbitrary messaging, Chainlink CCIP with CCT (Cross-Chain Token) v1.6+ provides oracle-attested token movement, deBridge DLN serves intent-based filling, and Li.Fi aggregates over 130+ chains for best-execution routing. ERC-7683 cross-chain intents provide a chain-agnostic envelope above all of them.

### 14.2 Public Blockchain Bridges

| Adapter | Protocol | Target Ecosystems |
|---------|----------|------------------|
| `WormholeAdapter` | Wormhole Guardian VAAs / NTT (with on-Tenzro 13-of-19 Guardian-quorum verification, EOA receive_message signature path) | Canonical TNZO transfers across 30+ chains incl. Solana, EVM L1/L2s |
| `LayerZeroAdapter` | LayerZero V2 (mandatory Tenzro DVN) | Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base |
| `ChainlinkCcipAdapter` | Chainlink CCIP + CCT v1.6+ | Ethereum, Polygon, Avalanche, Arbitrum, Optimism (LockRelease + BurnMint pools) |
| `DeBridgeAdapter` | deBridge DLN | Ethereum, Solana, BNB Chain, Polygon, Arbitrum (intent-based filling) |
| `LiFiAdapter` | Li.Fi aggregator | 130+ chains via aggregated quote/route/status API |
| `HyperlaneAdapter` | Hyperlane V3 (sovereign Tenzro-validator-set ISM) | 18+ chains incl. EVM L1/L2s, Mantle, Blast, Scroll, Linea, zkSync, Manta, Mode, Fraxtal |
| `AxelarAdapter` | Axelar General Message Passing | 30+ chains incl. Cosmos (Osmosis, Cosmos Hub, Juno, Neutron, Injective), Move (Aptos, Sui), Stellar, XRP Ledger, Hyperliquid, Kava, Filecoin EVM |
| `BabylonAdapter` | Babylon Bitcoin staking (finality-providers protocol, EOTS signatures) | Bitcoin economic security for Tenzro validators |
| `CantonAdapter` | DAML 3.x + Global Synchronizer | Enterprise Canton synchronizers (CIP-56 holdings, two-phase commit) |

### 14.2a ERC-7683 Cross-Chain Intents

Tenzro implements the ERC-7683 cross-chain intent envelope natively in `tenzro-types::intent_7683`. User-signed `CrossChainOrder` / `GaslessCrossChainOrder` are resolved into `ResolvedCrossChainOrder` with chain-discriminated 32-byte recipients, fill instructions, and a `ProofRoute` (LayerZero / Wormhole / DeBridge / Hyperlane). Order state transitions through `Open → AwaitingProof → Settled / Refunded / ForceRefundEligible`. The on-chain envelope `Tenzro7683Order` persists in `CF_SETTLEMENTS` under a `7683_origin:` keyspace, with fill-side idempotency under `7683_dest:`.

CAIP-2 chain IDs: `TENZRO_MAINNET_CHAIN_ID = 0x10ED20`, `TENZRO_TESTNET_CHAIN_ID = 0x10ED21`.

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

The Canton execution surface from §14.6 is generalized into a Canton-native **multi-party workflow** primitive in `tenzro-workflow`. A workflow has a typed lifecycle (`Draft → Active → AwaitingSignatures → Executing → Completed`, with terminal `Cancelled / Disputed / Failed / Suspended`), a counterparty set, an obligations table, an approvals graph governed by a small policy DSL, an optional fee route, and an optional privacy domain. State changes flow exclusively through privileged-VM selectors `0x01000040`–`0x0100004B` dispatched by signed transactions, so the chain's block history is the canonical workflow log.

Each successful state transition produces a `WorkflowReceipt` carrying `state_before / state_after / signer / block_height / prev_receipt`. Receipts form a per-workflow hash chain anchored at `Hash::default()` and persisted under `wf_receipt:<id>`; the chain head is held in the workflow's `WorkflowMeta`. When a workflow opts into Canton mirroring, the same receipt is projected into a `Tenzro.Workflow.Receipt` Daml template through the co-located participant's Ledger API, with the `ReceiptEnvelope` embedded inline (small payloads) or referenced as a `DaPointer` (large payloads, per §17). Canton's sub-transaction privacy ensures only the workflow's stakeholders observe the mirrored receipt.

Two safety primitives sit on top of this core:

- **Privacy domains.** A `PrivacyDomain` is a named ACL of TDIP DIDs that gates encrypted payloads. Workflows that opt into a domain seal their `payload` and event payloads with a domain key shared among the ACL; AES-256-GCM symmetric envelope encryption (per §7) makes the seal/open round-trip symmetric. Auditors inside the ACL can open payloads they were never explicit recipients of. A frozen domain refuses new sealings while permitting existing payloads to continue being opened.
- **Kill switch.** Selectors `0x01000048` (suspend) and `0x01000049` (cancel) provide a defined emergency-stop path. The initiator can suspend at any time; suspended workflows reject all writes except cancel and dispute. The pair removes the only condition under which an autonomous agent could be trapped in a non-responsive multi-party flow it initiated.

A snapshot of operational health (workflow / obligation / approval counts by status, signatures collected, Canton mirrors, fee routes, privacy domains) is exposed via `WorkflowRuntime::operational_metrics()` and rendered to the node's `/metrics` Prometheus endpoint with `BTreeMap` ordering for deterministic output. The accompanying Grafana dashboard (`deploy/monitoring/grafana-workflow-dashboard.json`, UID `tenzro-workflow`) graphs all of the above.

Read access to workflows, obligations, approvals, receipts, fee routes, privacy domains, and operational metrics is mirrored across all three external surfaces: JSON-RPC (`tenzro_*` namespace), MCP (port 3001, as `#[tool]`-defined methods), and A2A (port 3002, as the `workflow` skill on the Tenzro Agent Card). Writes never occur through these surfaces — every state-changing operation is a signed privileged-VM selector.

Five reference workflow templates ship under `crates/tenzro-workflow/reference_workflows/` (autonomous procurement, autonomous treasury, DvP settlement, environmental MRV, supply-chain digital product passport), each paired with a `*_daml_map.json` describing the Canton DAML projection and defining its `WorkflowSpec` (counterparty roles, obligations, approvals graph, fee route, privacy domain) for instantiation by the agent-kit spawner.

---

## 14a. Sandboxed Skills (WASI 0.2 Component Runtime)

The `tenzro-wasm` crate is the sandboxed runtime that executes community-supplied agent skills, MCP tools, and A2A skill components on a Tenzro node. It is not a smart-contract VM — transactional execution stays on the EVM / SVM / DAML stack. The component runtime is the host for application-layer code that needs to run untrusted under capability-based isolation.

### 14a.1 Design

Components ship as WASI 0.2 `.wasm` files bundled with a `ComponentManifest` declaring identity, runtime ABI, capability requests, deadline, and fuel budget. The runtime validates the manifest's SHA-256 content hash against the bytes, admits the component to its registry, and instantiates it under Wasmtime fuel metering and epoch interruption. Components start with no filesystem access, no network access, no environment variables; capabilities are granted explicitly through the manifest's `capabilities` block.

### 14a.2 Capability surface

Components see two interface surfaces. The standard WASI 0.2 worlds (cli, http, sockets, filesystem, clocks, random) are gated by the manifest's `SkillCapabilities`. Tenzro-native interfaces exported under the `tenzro:*` namespace let a component call back into the node — read a configuration value, publish an event, request an inference, sign a payment under a delegated scope. The `HostInterface` trait the node implements is the single dispatch point for every `tenzro:*` call; per-method allow-lists and per-DID quotas are enforced before dispatch.

### 14a.3 Determinism

Wasmtime fuel metering counts WASM operations rather than wall-clock time, so two executions of the same component against the same input produce identical fuel reports regardless of the host's CPU speed. Epoch interruption enforces wall-clock deadlines on top of fuel budgets. Together they give the node a deterministic cost model the settlement engine can debit through `tenzro-payments`.

### 14a.4 Execution receipts

Every invocation returns an `ExecutionReceipt` carrying the component id, content hash, exported function name, SHA-256 of the input and output, outcome label (success, trapped, fuel-exhausted, deadline-exceeded, host-contract-violation), fuel report, and completion timestamp. Receipts chain into Tenzro `ReceiptEnvelope` records (see §9 Settlement) so a skill's execution history is durable and auditable end-to-end.

### 14a.5 Integration points

The `tenzro-agent-kit::executor` is the primary embedder. When a skill template's manifest declares `runtime: agent-skill`, the executor dispatches through `tenzro-wasm::SkillRuntime` instead of the native Rust or Python skill paths. The node's MCP server is the second embedder: community-submitted MCP tools ship as `.wasm` components and run in-process under capability checks instead of as separate HTTP processes. Both embedders are gated behind the `wasi-skills` feature flag.

### 14a.6 Why not a fourth VM

Tenzro's multi-VM strategy stays at EVM + SVM + DAML. Reach to CosmWasm-style chains, Move chains, and other WASM-VM-hosting ecosystems flows through the bridge layer, not through adding a fourth transactional VM. The `tenzro-wasm` runtime exclusively hosts application-layer code — skills and tools — not smart contracts.

---

## 15. Wallet and Key Management

### 15.1 MPC Wallets

Tenzro eliminates seed phrases through MPC threshold wallets:

| Parameter | Default |
|-----------|---------|
| Threshold | 2-of-3 |
| Key shares | 3 |
| Minimum threshold | 2 |

**Provisioning.** When a user or agent creates a wallet, the `WalletProvisioner` generates an Ed25519 keypair, splits the secret into 3 shares using Shamir's Secret Sharing, and returns the shares. No single share can reconstruct the key — any 2 of 3 are required.

### 15.2 Multi-Asset Support

Wallets natively track balances across supported assets:

| Asset | Symbol | Type |
|-------|--------|------|
| Tenzro | TNZO | Native token |
| USD Coin | USDC | Stablecoin |
| Tether | USDT | Stablecoin |
| Ether | ETH | Cryptocurrency |
| Solana | SOL | Cryptocurrency |
| Bitcoin | BTC | Cryptocurrency |

### 15.3 Encrypted Keystore

Key shares are stored in an encrypted keystore on disk:

1. A random 32-byte salt is generated.
2. An encryption key is derived from the user's password using **Argon2id** (memory-hard KDF resistant to GPU and ASIC attacks).
3. A `SymmetricKey` (AES-256-GCM) encrypts the serialized key shares.
4. The encrypted blob, salt, and nonce are written to `~/.tenzro/wallets/{wallet_id}.json`.
5. An in-memory cache (with configurable capacity) avoids repeated disk reads.

Password changes decrypt with the old password and re-encrypt with the new one atomically.

### 15.4 Transaction Signing

The `MessageSigner` coordinates threshold signing:

1. Collect key shares from available custodians (need >= threshold).
2. Each custodian produces a partial signature.
3. Partial signatures are combined into a full Ed25519 signature.
4. The resulting `SignedTransaction` can be submitted to the network.

### 15.5 Onboarding: Identity and Wallet Provisioning

Tenzro provides a unified onboarding flow that provisions a TDIP identity, an MPC wallet, and a hardware profile in a single atomic operation. This eliminates the multi-step setup typical of blockchain networks and ensures every participant has a verifiable on-chain identity from the moment they join.

**One-Click Participation (`tenzro_participate` RPC).**  A single JSON-RPC call provisions all three components:

1. An Ed25519 keypair is generated.
2. The secret key is split into 3 shares via Shamir's Secret Sharing (2-of-3 threshold).
3. A TDIP DID is created (`did:tenzro:human:{uuid}`) and registered in the `IdentityRegistry`.
4. The identity is persisted to RocksDB (`CF_IDENTITIES` column family).
5. The wallet address is derived from the public key and bound to the identity.
6. The host machine's hardware profile (CPU model, core count, RAM, GPUs) is detected and attached to the identity metadata.
7. The wallet key shares are encrypted with AES-256-GCM (key derived via Argon2id) and stored in the local keystore at `~/.tenzro/wallets/`.

The response returns the DID, wallet address, wallet threshold configuration, and hardware profile. The participant is immediately able to send transactions, request inference, and interact with the network.

**Import from Private Key (`tenzro_importIdentity` RPC).**  Users with existing Ed25519 or Secp256k1 private keys can import them instead of generating new ones:

1. The provided private key bytes are used to construct a `KeyPair`.
2. The public key and wallet address are derived from the imported key.
3. MPC key shares are generated from the imported key as the master secret.
4. The identity is registered on-chain with the same TDIP DID format.
5. Key shares are encrypted using the user-provided password (Argon2id + AES-256-GCM) and stored in the keystore.

This flow supports migration from other networks or key management systems while maintaining the same security guarantees as fresh key generation.

**Hardware Profile Detection.**  During onboarding, the node detects the participant's hardware capabilities:

| Detected Property | Use |
|-------------------|-----|
| CPU model, cores, threads | Compute capacity for inference workloads |
| Total RAM | Memory-bound model support |
| GPU name, VRAM, architecture | GPU-accelerated inference and proving eligibility |
| TEE availability | TEE-attested validator eligibility (1.5× multiplier on reputation-weighted leader draw) |

Hardware profiles are stored as identity metadata and used by the `InferenceRouter` to match inference requests to capable providers.

**Client Interfaces.**  Onboarding is accessible through all client interfaces:

- **CLI:** `tenzro-cli join --name "Alice"` (one-click) or `tenzro-cli wallet import 0x... --key-type ed25519` (import)
- **Desktop App:** Setup page shown on first launch with "Create New" and "Import Existing" tabs
- **JSON-RPC:** Direct calls to `tenzro_participate` or `tenzro_importIdentity`

The desktop application enforces an onboarding gate — the Setup page is displayed before the Dashboard until a valid identity and wallet exist. On successful onboarding, the user is redirected to the Dashboard with their DID, wallet address, and hardware profile displayed.

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
| `CF_CHALLENGES` | Payment challenge storage for MPP/x402 |

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
| ZK | Plonky3 STARKs over KoalaBear | False computation claims |
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

### 19.5 Post-Quantum Migration

Tenzro is migrating to NIST PQC standards in a flag-day cutover. The target end-state pairs Ed25519 + ML-DSA-65 (FIPS 204 hybrid signatures) and X25519 + ML-KEM-768 (FIPS 203 hybrid KEM) at the wire layer. Every signature and every key-exchange handshake will carry both a classical and a post-quantum component; verifiers reject unless both succeed. The Caddy reverse proxy in front of the testnet endpoints already serves PQ-hybrid TLS via X25519-MLKEM768. Plonky3 STARKs are post-quantum-conjectured-sound by construction.

---

## 20. Agent-Swarm Primitives

The Tenzro Ledger ships ten swarm-specific primitives that hold up under autonomous-agent traffic. Every primitive is keyed on the `controller_did` (the human or organization behind the agent), every fee/bond/slash/reward is denominated in TNZO, and every threshold is a governance-controlled parameter — not a hardcoded constant.

| # | Primitive | Purpose |
|---|---|---|
| 1 | **Kill-switch** | Authority graph (controller / DAO / regulator) able to halt an agent or class of agents within consensus latency, with typed receipt evidence. |
| 2 | **Per-DID flow control** | Mempool admission lanes keyed on `controller_did` — protects every other system from being overwhelmed by a single swarm. |
| 3 | **Dual-rail gas + paymaster burn quota** | Native TNZO gas rail plus stablecoin paymaster rail; paymasters burn TNZO from a treasury quota at 100% of paymaster_burn_bps. |
| 4 | **ERC-7683 settler** | Native cross-chain intent settlement surface (see §14.2a). Pure additive surface for the 88%+ of cross-chain intent volume that uses ERC-7683. |
| 5 | **Principal-chain receipts** | Typed liability chain on every settlement / lifecycle / kill-switch / bond receipt — surfaces the controller DID at every link. |
| 6 | **Hot-state local fee market** | Per-account fee escalation when swarms cluster on hot contracts. |
| 7 | **DA offload** | Receipts and inference payloads carry a `ReceiptEnvelope` that either inlines the payload or records a `DaPointer` to EigenDA / Celestia / Avail with a `commitment_kzg`. |
| 8 | **Adaptive burn governance dial** | `BurnRateConfig` + `SupplyTargets` + `BurnRateConfigManager` produce `BurnRateRecommendation` driving an auto-proposal generator; M2M volume is 100× human volume, calcified burn taper either drains or no-ops. |
| 9 | **AgentBond surety + insurance pool** | Slashable TNZO bond posted per autonomous agent. Slashed funds flow to an on-chain insurance pool that pays out on file-able claims. |
| 10 | **SeedAgent treasury earmark** | Treasury-funded protocol-owned agents to exercise the stack in months 0–12, with `Charter` / `SpendCaps` / `DecaySchedule` (100/100/100 → 75 → 50 → 25 → 0% over 12 months) and a `surplus_burn_bps` sunset disposition. |

These primitives compose through TDIP delegation scopes — every runtime check that bounds an agent (spending, kill-switch authority, bond release) reads from the existing `DelegationScope` and `IdentityRegistry::enforce_operation` path. The full specification set lives under `docs/architecture/agent-swarm/`.

---

## 21. Roadmap

### Phase 1: Core Infrastructure — **DONE**
- ~~Replace all stub implementations with production logic~~ — **DONE**: All core subsystems have real implementations
- ~~Integrate real EVM execution (revm) and SVM execution (rbpf)~~ — **DONE**
- ~~Connect Daml executor to Canton participant nodes via Ledger API (gRPC, port 5001)~~ — **DONE**: tonic gRPC client
- ~~Implement bootstrap peer discovery and genesis block~~ — **DONE**: Kademlia DHT seeding + GenesisConfig
- ~~Complete TEE hardware integration (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)~~ — **DONE**: Real hardware paths with simulation fallback, X.509 cert chain verification
- ~~Implement EIP-1559 fee market~~ — **DONE**
- ~~Implement Block-STM parallel execution~~ — **DONE**
- ~~Implement ERC-4337 account abstraction~~ — **DONE**
- ~~Implement equivocation detection and slashing~~ — **DONE**: EquivocationDetector in VoteCollector, SlashingCallback bridges consensus → StakingManager::slash() (10% penalty)
- ~~Implement peer authentication~~ — **DONE**: ValidatorRegistry trait, validator-only gossipsub topics
- ~~Ship Plonky3 STARK verifier and AIR circuits~~ — **DONE**: KoalaBear field, Poseidon2 + FRI, three AIRs (inference / settlement / identity), generic `verify_proof_envelope` dispatcher, on-chain `ZkCommitmentRegistry` + O(1) precompile

### Phase 2: Identity & Payments
- ~~Implement Tenzro Decentralized Identity Protocol (TDIP)~~ — **DONE**: three identity classes (human / delegated agent / autonomous agent), W3C DID, verifiable credentials, delegation scopes
- ~~Implement MPP and x402 payment protocols~~ — **DONE**: HTTP 402 challenge/credential/receipt flows
- ~~Implement Tempo network integration~~ — **DONE**: TempoBridgeAdapter, Tip20Token, TempoParticipant
- ~~Implement identity-bound payments~~ — **DONE**: delegation scope enforcement on payments
- Connect payment protocols to live settlement rails (Stripe MPP, Coinbase x402, Tempo network)

### Phase 3: Agent & Protocol Integration
- ~~Implement MCP server with 10 tools~~ — **DONE**: rmcp-based server on port 3001, Streamable HTTP transport
- ~~Implement A2A protocol server~~ — **DONE**: JSON-RPC 2.0 on port 3002, Agent Card discovery, SSE streaming, 5 skills
- ~~Implement challenge store for payment protocols~~ — **DONE**: persistent challenge lookup for MPP and x402
- ~~Implement OpenClaw skill integration~~ — **DONE**: `skills/openclaw-tenzro/SKILL.md`
- ~~Implement NVIDIA GPU TEE provider~~ — **DONE**: Hopper/Blackwell/Ada Lovelace, NRAS attestation
- ~~Add GPU-accelerated ZK proving~~ — **DONE**: batch proof generation, Merkle aggregation, multi-level compression
- ~~Implement liquid staking (stTNZO)~~ — **DONE**: rebasing exchange rate, multi-validator delegation, 10% protocol fee

### Phase 4: Testnet Deployment
- ~~Deploy public testnet~~ — **DONE**: Tenzro Labs operates the initial public RPC and ecosystem endpoints on tenzro.network with PQ-hybrid TLS at the edge while the validator set decentralizes
- ~~Configure Caddy with auto-TLS for all subdomains~~ — **DONE**: Let's Encrypt certificates for 5 endpoints
- ~~Verify all endpoints live~~ — **DONE**: RPC, API, Faucet, MCP, A2A all operational
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

## Appendix D: Live Testnet Endpoints

Tenzro Labs operates the initial public endpoints on `tenzro.network` with PQ-hybrid TLS at the edge while the validator set decentralizes:

| Service | URL | Port | Protocol |
|---------|-----|------|----------|
| JSON-RPC | `https://rpc.tenzro.network` | 8545 | Ethereum-compatible JSON-RPC |
| Web API | `https://api.tenzro.network` | 8080 | REST (verify, status, faucet) |
| Faucet | `https://api.tenzro.network/faucet` | 8080 | POST with `{"address": "0x..."}` |
| MCP | `https://mcp.tenzro.network/mcp` | 3001 | Streamable HTTP (MCP protocol) |
| A2A | `https://a2a.tenzro.network` | 3002 | JSON-RPC 2.0 + SSE |
| Agent Card | `https://a2a.tenzro.network/.well-known/agent.json` | 3002 | GET (A2A discovery) |
| Solana MCP | `https://solana-mcp.tenzro.network/mcp` | 3003 | Streamable HTTP |
| Ethereum MCP | `https://ethereum-mcp.tenzro.network/mcp` | 3004 | Streamable HTTP |
| Canton MCP | `https://canton-mcp.tenzro.network/mcp` | 3005 | Streamable HTTP |
| LayerZero MCP | `https://layerzero-mcp.tenzro.network/mcp` | 3006 | Streamable HTTP |
| Chainlink MCP | `https://chainlink-mcp.tenzro.network/mcp` | 3007 | Streamable HTTP |
| Li.Fi MCP | `https://lifi-mcp.tenzro.network/mcp` | 3008 | Streamable HTTP |

**Testnet configuration:**
- Chain ID: 1337
- Faucet: 100 TNZO per request, 24-hour cooldown per address
- Genesis: 1,000,000,000 TNZO total supply, 10,000,000 TNZO faucet allocation

---

**Tenzro Network** — AI-Native, Agentic, Tokenized Settlement Layer

**Tenzro Ledger** — Decentralized AI. Verifiable Inference. Permissionless Settlement.

*https://github.com/tenzro/tenzro-network*
