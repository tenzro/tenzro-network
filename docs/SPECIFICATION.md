# Tenzro Network — Protocol Specification

## The Open, Distributed Execution Layer for AI

### Tenzro Ledger: A TEE-Native Network for Verifiable AI and Autonomous Agents

**Version 0.1.0 — March 2026**

---

## Abstract

**Tenzro Network** is the open, distributed execution layer for AI — a decentralized protocol where inference, agents, and workflows run across independently operated nodes rather than one provider's servers. The network provides three execution resources from those nodes: **intelligence** (AI models for inference), **compute** (rentable capacity by the epoch), and **storage** (content-addressed data held to a proof of retrievability), with **security** (TEE enclaves for key management, custody, and confidential computing) underwriting them. A single node can take on several of these roles against one stake: providers, validators, and nodes earn TNZO by securing the network, serving intelligence, renting out compute, holding data, and providing security. Consumers pay from their TNZO balance; providers earn into theirs.

**Tenzro Ledger** is the purpose-built network for humans and agents, providing verifiable, on-chain primitives for the AI age: **identity** (TDIP: Tenzro Decentralized Identity Protocol for humans and machines), **security** (DAG consensus with hardware-held post-quantum checkpoint certificates and certified block import), **verification** (dual ZK + TEE proof systems), and **settlement** (micropayment channels, escrow, batch processing). All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

Built from the ground up around Trusted Execution Environments (TEEs) and zero-knowledge proofs, the Ledger provides hardware-rooted trust at every layer — smart contracts execute within hardware enclaves, and all on-chain claims can be independently verified through cryptographic proofs or hardware attestations. The Ledger supports a multi-VM execution environment (EVM, SVM and the native runtime), an autonomous agent framework with self-sovereign identity and permissionless wallet ownership (no custody held), a multi-modal AI model marketplace covering text, vision, audio, and timeseries inference with per-token settlement diffusion image and video generation, swarm orchestration for parallel agent execution, and cross-chain interoperability through governed bridge routes (a CCIP-compatible envelope for EVM chains and Solana). Multi-protocol payment support (MPP, x402, Tempo, Stripe SPT, AP2) enables HTTP 402-based machine payments with identity-bound delegation enforcement. Consensus is a signature-free DAG protocol over post-quantum authenticated channels, with no-vote certificates for tail-fork resistance and checkpoint certificates signed every 500 ms by session keys that hardware-held ML-DSA-65 + P-256 keys certify each epoch.

Tenzro is the open, distributed execution layer for AI. The execution surface — inference, agents, workflows — runs on a substrate where verifiable computation, confidential execution, rentable compute, decentralized storage, and agent-to-agent economic coordination are protocol-level primitives. Multi-role nodes, one stake covering every role, and per-epoch streaming settlement are what make that execution layer open and trustless. See [`COMPUTE.md`](COMPUTE.md) and [`STORAGE.md`](STORAGE.md) for the rentable-compute and storage surfaces.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Architecture Overview](#2-architecture-overview)
3. [Consensus](#3-consensus)
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
20. [Training](#20-training)
20a. [Generative Media](#20a-generative-media)

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

- **Hardware-rooted consensus.** Every validator's consensus key is a composite ML-DSA-65 + P-256 key: the P-256 leg lives in its TPM or Secure Enclave, and the ML-DSA-65 leg is derived on demand from that hardware for each use and never stored. TEE attestation is a reputation signal only: nothing self-reported enters the leader schedule.
- **Dual verification: ZK + TEE.** Identity and settlement claims can be backed by a zero-knowledge proof (Plonky3 STARKs in two independent configurations, KoalaBear/SHA-256 and Goldilocks/BLAKE3), a TEE attestation, or both through TEE-bound proofs. Inference claims are backed by TEE attestation; no circuit proves model inference. The STARKs need no trusted setup and rely only on hash functions.
- **Multi-VM execution.** The Ledger supports EVM and SVM smart contracts beside its native runtime through a unified runtime. Applications are not limited to inference — any programmable logic can run on Tenzro, with the added capability of invoking TEE execution and ZK verification through native precompiles.
- **Agent-first design.** AI agents participate on the same footing as humans, with self-sovereign identity (DID-based via TDIP), permissionless wallets they control directly — the signing key lives in the agent's own hardware and no custodian holds it, capability-based permissions, and a native agent-to-agent (A2A) communication protocol. Agents can discover each other, negotiate services, and settle payments autonomously.
- **Native settlement primitives.** Micropayment channels, escrow contracts with programmable release conditions, and atomic batch settlement are built into the Ledger — not implemented as smart contracts on top of a generic VM. This enables sub-second settlement for high-frequency economic activity like per-token inference billing.

All fees and settlements are denominated in **TNZO**, the governance token of the Tenzro Network protocol.

### 1.3 What Tenzro Does That No Other Chain Does

By the start of 2026, agentic finance runs across two separate ecosystems, each with its own protocols, settlement primitives, and execution model:

- **EVM / agent-commerce surface.** ERC-8004 (Trustless Agents) reached mainnet on 2026-01-29. AP2 (Agent Payments Protocol) was donated by Google to the FIDO Alliance in April 2026 with 60+ partners (Adyen, AmEx, Mastercard, Stripe, OpenAI, Anthropic). x402 (Coinbase) reports ~$50M cumulative / ~$600M annualized micropayment volume. ERC-4337 v0.8 + EIP-7702 form the smart-account substrate. TEE-confidential agents are offered as middleware by Phala and Oasis (Sapphire/ROFL); NEAR AI offers TEE-attested agents as a platform feature.
- **SVM / Solana agent-trading surface.** Application-layer frameworks (ElizaOS, SendAI Solana Agent Kit, GOAT SDK) reach Jupiter, Drift, Mango, Metaplex, Bonfida, and SPL — but protocol-level identity, settlement, and consensus primitives for agents are inherited from Solana proper, not designed for them.

A small set of L1s pursue multi-VM execution. **Fluent** (mainnet 2026-04-24) is the closest analog and runs EVM + SVM + WebAssembly. Sei v2 pioneered the EVM↔Wasm pointer-token model that Tenzro generalizes. Move-VM chains run a single execution environment and are not multi-VM in the EVM/SVM sense.

**Five things Tenzro does that no other chain in 2026 does:**

1. **Run EVM, SVM and a native runtime over one identity and one balance.** `tenzro-vm` runs three executors (revm EVM, `solana-svm` SVM, the native runtime) behind one runtime. Routing is at the transaction-type layer, not via cross-chain messaging.
2. **Carry agent rails across chains under one identity.** A single TDIP DID can act on AP2/x402/ERC-8004/ERC-4337 on Tenzro and, through governed bridge routes and settlement plans, on Ethereum, Solana, Bitcoin, Cosmos and Move chains, with the same delegation scope, the same wallet, and the same on-chain settlement.
3. **Run the full agent-commerce stack natively, across crypto rails and card rails.** AP2 mandates, x402 with EIP-3009, MPP with Stripe Payment Intents — all settling on-chain in TNZO. Card-network adapters run in harnesses and carry the layer the card networks do not have: agent DID, signed delegation scope, AP2 mandate validation, and an on-chain audit receipt. ERC-8004 system precompiles at `0x101a/0x101b/0x101c` with byte-identical selectors to Ethereum, ERC-4337 v0.8 EntryPoint, A2A on port 3002, MCP via `rmcp` — all inside Tenzro consensus.
4. **Treat confidential agent compute as a verifiable primitive, not a sidecar.** The `TEE_VERIFY` precompile verifies real Intel TDX (P-256 ECDSA over Quote\[0..632\]), AMD SEV-SNP, AWS Nitro (COSE_Sign1 ES384 per RFC 8152 §4.4), and NVIDIA GPU CC quotes on-chain with pinned vendor root CAs. ZK proofs are commitment-attested via `ZkCommitmentRegistry` for O(1) EVM verification.
5. **Settle agentic micropayments in a pointer-model native asset.** TNZO has one balance with two VM views — wTNZO ERC-20 at `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93` on EVM and an SPL adapter on SVM. Both views read and write the same underlying account state — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f` — encodes ASCII T+0x80, N, Z, O), and W3C DID (`did:tenzro`).

What makes this work is the **combination**, not any single piece: AP2, x402, ERC-8004, ERC-4337, MCP, A2A, Plonky3, FRI, SHA-3, and TEE attestation are open standards adopted byte-for-byte rather than reinvented. The work is integrating them inside one consensus layer with one native asset and one identity surface.

For the full protocol-layer view, see [`WHITEPAPER.md`](WHITEPAPER.md).

### 1.4 Design Principles

1. **Hardware trust at the foundation.** TEE integration is not a sidecar — it influences validator selection, consensus weight, proof generation, and execution confidentiality. The Ledger is designed so that the strongest security guarantees emerge from hardware-attested participation.
2. **Cryptographic verifiability.** Claims about computation, identity, and payment are backed by mathematical proofs or hardware attestations, not economic penalties alone.
3. **General-purpose programmable network.** Tenzro Ledger is a programmable network, not an inference-specific subnet. AI model routing and settlement are built-in capabilities, but the Ledger supports arbitrary smart contract logic across two VM targets (EVM, SVM) beside the native runtime.
4. **Economic alignment.** Token economics incentivize honest behavior: validators earn block rewards and transaction fees (gas paid in TNZO) for securing the Ledger; providers earn per-inference fees and TEE service fees with the Network taking a commission that flows to the treasury; misbehavior is punished through stake slashing.
5. **Interoperability.** Multi-VM execution and governed bridge routes (CCIP-compatible envelope, IBC, Bitcoin deposit, contract routes) ensure Tenzro connects to existing ecosystems rather than requiring migration.

---

## 2. Architecture Overview

### 2.1 Tenzro Network and Tenzro Ledger

**Tenzro Network** is the overall protocol/platform designed for the AI age, enabling agents and autonomous systems to participate as economic actors in their own right. The Network provides:
- Access to **intelligence** (decentralized AI model marketplace)
- Access to **security** (TEE enclaves for custody, key management, confidential computing)

**Tenzro Ledger** is the network that provides the economic substrate for Tenzro Network. The Ledger offers purpose-built primitives for the AI age:
- **Identity:** TDIP (Tenzro Decentralized Identity Protocol) for unified human/machine identity
- **Security:** DAG consensus with post-quantum checkpoint certificates; every imported block certified
- **Verification:** Dual ZK + TEE proof systems
- **Settlement:** Micropayment channels, escrow, batch processing (all in TNZO)

**Revenue Model (Two-Tier Fee Structure):**

1. **Ledger Transaction Fees (Gas):** All on-chain transactions pay gas fees in TNZO under an EIP-1559 dynamic fee market. The governed share of the base fee is burned (all of it by default); everything else a block collects, including priority fees, goes to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%).

2. **Network Commission Fees:** A settled service payment is divided once, by the serving node's economic mode — a private node keeps it, a public validating node pays 10% to the treasury, and a public node that does not validate pays 10% to the treasury and 10% to the RPC provider validating on its behalf. Every rate is governance-set. See [ECONOMICS.md](ECONOMICS.md) for the full model.

Providers/validators/nodes can earn from multiple sources:
- **Validators:** Reward coupons for consensus work and a base reward, both paid from the rewards pool, for securing the Ledger
- **Model Providers:** Per-inference fees (minus the network's share under the node's economic mode) for providing intelligence
- **TEE Providers:** Service fees (minus the network's share under the node's economic mode) for providing security
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
     | (iroh) | |  sus   | |   EVM+SVM   | |RocksDB| |Registry| |Runtime |
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
| Cryptography | `tenzro-crypto` | Ed25519, Secp256k1, AES-256-GCM, X25519, ML-DSA-65 / ML-KEM-768 (FIPS 203/204), VRF (RFC 9381) |
| Trust | `tenzro-tee` | TEE abstraction over Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber |
| Proofs | `tenzro-zk` | Plonky3 STARKs in two configurations (KoalaBear/SHA-256, Goldilocks/BLAKE3), SHA3-256 preimage circuits, k-of-n acceptance, TEE-bound proofs |
| Networking | `tenzro-network` | gossip messages, topics and validation over iroh-gossip |
| iroh data plane | `tenzro-iroh` | QUIC-native content-addressed transport, DA backend, gradient store, sealed-shard store, A2A-over-iroh on `tenzro/a2a` ALPN |
| Storage | `tenzro-storage` | RocksDB, unified binary state trie (block state root, proofs, snapshot buckets), fsync durability |
| Storage provider | `tenzro-storage-provider` | Paid decentralized storage: provider daemon, proof of retrievability, Reed-Solomon redundancy, per-byte-epoch metering |
| Cluster substrate | `tenzro-cluster` | Engine-agnostic local-network cluster tier: reachability tiers, probed link-cost graph, nearest-neighbour ordering, rendezvous placement — shared by model layers, storage shards, and database partitions |
| Consensus | `tenzro-consensus` | Signature-free DAG ordering, checkpoint certificates, epoch management, leader schedule from the committed prefix |
| Execution | `tenzro-vm` | Multi-VM runtime: EVM, SVM and native executors |
| Economics | `tenzro-token` | TNZO token, staking, rewards, treasury, governance |
| Wallets | `tenzro-wallet` | Permissionless hardware-key wallets (passkey for humans, TPM 2.0 / Secure Enclave for machines) + ML-DSA-65 hybrid, no custody held; Argon2id keystore for the wallets' public records |
| Device keys | `tenzro-device-key` | Non-extractable P-256 keypairs in the machine's hardware (TPM 2.0 on Linux and Windows, Secure Enclave on macOS/iOS): prehash signing, ECIES secret wrapping, and Ed25519 / X25519 / ML-DSA-65 keys derived on demand from a hardware root |
| Keystore unlock | `tenzro-keystore-unlock` | Platform-agnostic `KeystoreUnlocker` trait for the keystore password so wallets persist across restarts; the password comes from a hardware device key (Secure Enclave or TPM), and there is no environment-variable or fixed-password implementation |
| Authentication | `tenzro-auth` | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests) |
| Identity | `tenzro-identity` | TDIP: unified human/machine identity, W3C DID, verifiable credentials, delegation |
| Payments | `tenzro-payments` | Payment protocols: MPP, x402, RFC 9421 HTTP message signatures, delivery-versus-payment, metering and receipts |
| AI Models | `tenzro-model` | Multi-modal model registry, llama.cpp LLM runtime, ONNX vision/text-embedding/segmentation/detection/audio/video runtimes, ONNX timeseries forecasting runtime, inference routing, pricing engine, durable catalog |
| Settlement | `tenzro-settlement` | Escrow, micropayments, batch settlement, fee collection |
| Events | `tenzro-events` | The chain's event log (cursor-ordered, committed in block headers, provable against certified checkpoints), the node's live event bus, webhooks |
| Bridge | `tenzro-bridge` | Route framework (CCIP-compatible envelope for EVM + Solana), fee oracle, Chainlink feeds |
| Node | `tenzro-node` | Full node binary, RPC server, MCP, A2A, web API |
| CLI | `tenzro-cli` | Command-line interface (103 command modules) |
| SDK | `tenzro-sdk` | Rust SDK with builder-pattern configuration |
| TypeScript SDK | `tenzro-ts-sdk` | TypeScript SDK for browser and Node.js integration |

### 2.4 Node Roles

Participants in the Tenzro Network operate nodes in one of several roles. Nodes can serve multiple roles simultaneously (e.g., a validator can also be a Model Provider and/or TEE Provider, or a validator can additionally serve as an RPC Provider):

- **Validator.** Participates in consensus, proposes vertices and signs checkpoints, earns reward coupons for consensus work, paid from the rewards pool; priority fees go to the treasury, not to the proposer. **Three-tier model** detailed in §3.4a: Tier 1 (resource-only, unbonded), Tier 2 (staked, ≥ 10,000 TNZO), Tier 3 (RPC provider, ≥ 100,000 TNZO and implies Tier 2). All three tiers run the same protocol and sign the same QCs, but quorum weight is the validator's own bond, so a Tier 1 node that bonds nothing adds nothing to the tally. Tier 1 also carries no governance vote and no financial slashing exposure — there is no bond to slash. That is what makes open validator admission safe: participation is free, influence is not. Validators secure the Ledger.

- **RPC Provider.** A Tier 3 validator role. Serves public JSON-RPC + REST verification API. Sanctioned to broker access to operator-held upstream credentials, keyed by each tenant's DID, (AI provider keys, data feed subscriptions, external-chain RPC endpoints), and route cross-chain mint/burn flows. Requires ≥ 100,000 TNZO bonded (implies the Tier 2 minimum). The genesis configuration names the first RPC Provider, at `rpc.tenzro.com`.

- **Model Provider.** Serves AI models for inference requests. Bonds **1,000 TNZO**; admission is permissionless above the bond, with no allowlist and no approval step. Earns provider reward coupons by settled fees (TOKENOMICS §7) and per-inference fees (paid in TNZO) settled through micropayment channels. The network's share of provider earnings follows the node's economic mode and flows to the treasury (see [ECONOMICS.md](ECONOMICS.md)). Model providers provide **intelligence** to the Network.

- **TEE Provider.** Operates hardware TEE enclaves (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs, Intel Tiber) for confidential computation, key management, custody services, and attestation. Bonds **10,000 TNZO** — the second-largest rung on the ladder, reflecting that a false attestation compromises every party relying on it. Earns provider reward coupons by settled fees (TOKENOMICS §7) and fees for TEE services (paid in TNZO). The network's share of provider earnings follows the node's economic mode and flows to the treasury (see [ECONOMICS.md](ECONOMICS.md)). TEE providers provide **security** to the Network.

- **Storage Provider.** Stores and serves blockchain state, model weights, and historical data. Bonds **100 TNZO per terabyte pledged**, floored at 100 TNZO, so the bond tracks the capacity it collateralizes. Earns storage fees.

- **Compute Provider.** Rents accelerators for inference, training, and rendering. Bonds **per card by accelerator class** — 500 TNZO integrated, 1,000 consumer, 2,000 workstation, 5,000 datacentre — summed over everything pledged and floored at 500 TNZO. Earns time-based rental revenue.



- **Light Client.** Verifies block headers and proofs without storing full state. Suitable for end-user devices.

- **Bootstrap Node.** Initial peer discovery endpoint for new nodes joining the network. Any node can serve this role; a founding validator serves as the canonical bootstrap seed, advertised via DNS (`bootstrap.tenzro.com`) and pkarr-relay.

- **Archive Node.** Stores complete historical state for analytics and indexing.

### 2.5 API Surface

The node exposes four API interfaces:

**JSON-RPC Server** (default `0.0.0.0:8545`):

**Trust surface.** Certification, policy and provenance records are signed by their author's hardware key and re-verified by every node that applies them (`crates/tenzro-trust`; see `docs/TRUST.md`). `tenzro_submitTrustRecord` accepts a credential, a revocation, an issuer revocation, an operator policy, an origin attestation, a model manifest, or policy-violation evidence; the reads are `tenzro_verifyTrustCredential`, `tenzro_getTrustCredentials`, `tenzro_getStatusList`, `tenzro_getOperatorPolicy` and `tenzro_getModelProvenance`. The operator-local, disk-reading methods `tenzro_buildModelManifest` / `tenzro_verifyModelFiles` / `tenzro_scanModelFiles` / `tenzro_hostModel` are admin-gated. A model is named by the BLAKE3 Merkle root of its manifest (`tenzro:model:<root>`), an operator by its hardware-derived DID; credentials are W3C VC 2.0 documents with an `ecdsa-jcs-2019` Data Integrity proof and a Bitstring Status List entry, so expiry and revocation are part of validity.

**Web Verification API** (default `0.0.0.0:8080`):

| Endpoint | Purpose |
|----------|---------|
| `POST /verify/zk-proof` | Verify a zero-knowledge proof |
| `POST /verify/tee-attestation` | Verify a TEE attestation report |
| `POST /verify/transaction` | Verify a transaction signature |
| `POST /verify/settlement` | Verify a settlement receipt |
| `POST /verify/inference` | Verify an inference result against its proof |
| `GET /verify/health` | Health check |
| `GET /health` | Health check |
| `GET /status` | Node status and metrics |

**MCP Server** (default `0.0.0.0:3001`):
Model Context Protocol server using the `rmcp` crate with Streamable HTTP transport (protocol version `2026-07-28`). Exposes a tool for every served method, spanning wallet, identity, payments (x402, MPP, card rails), inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), stakes, tokens, governed bridge routes, verification, agents, tasks, TEE, ZK, VRF, and event subscriptions, that any AI agent (Claude, GPT, etc.) can invoke. Representative groups:

| Group | Example Tools |
|-------|---------------|
| Wallet & Ledger | `get_balance` |
| Network & Blocks | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did` |
| Payments | `create_payment_challenge`, `verify_payment` |
| AI Models & Inference | `list_models`, `list_model_endpoints` |
| Verification | `verify_zk_proof`, `verify_vrf_proof` |
| Stakes & Providers | `get_role_stakes`, `get_provider_stats` |
| Tokens & Contracts | `deploy_contract` |

**A2A Protocol Server** (default `0.0.0.0:3002`):
Agent-to-Agent protocol server implementing the Google A2A specification with JSON-RPC 2.0:

| Endpoint | Purpose |
|----------|---------|
| `GET /.well-known/agent-card.json` | Agent Card discovery, signed (detached JWS over the RFC 8785 form) |
| `POST /a2a` | JSON-RPC 2.0 dispatcher; `SendStreamingMessage` answers with SSE on the same route |

A2A 1.0 only: every request sends `A2A-Version: 1.0`. JSON-RPC methods: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`; mutations carry the Tenzro DID envelope. The Agent Card advertises 21 skills: `wallet`, `identity`, `inference`, `settlement`, `verification`, `staking`, `token`, `contract`, `join`, `bridge`, `compliance`, `events`, `adaptive-burn`, `iroh-transport`, `urwa`, `bridge-fee-in-tnzo`, `storage`, `compute`, `moe`, `media-gen`, `discovery`. Supports streaming responses via Server-Sent Events and multi-turn conversation history.


---

## 3. Consensus

### 3.1 Overview

The Tenzro Ledger orders transactions with a signature-free DAG protocol and makes the ordering transferable with checkpoint certificates. Validators exchange unsigned vertices over authenticated post-quantum channels; a reliable broadcast makes every honest validator deliver the same vertex or none; a leader commits once a quorum of the next round references it, which orders the DAG. Every 500 ms of ordered history, validators sign a checkpoint with an in-memory composite ML-DSA-65 + ECDSA-P256 session key that their hardware-held key certifies once per epoch (the certificate travels with every vote), and a quorum of signatures forms a certificate that anyone can verify. The design is described in [`architecture/consensus.md`](architecture/consensus.md).

### 3.2 Protocol Parameters

| Parameter | Default Value | Description |
|-----------|--------------|-------------|
| Leader timeout | 1,000 ms | Wait for a round leader before timing out |
| Checkpoint interval | 500 ms | Minimum segment time between checkpoints; votes are signed by a session key the hardware key certifies once per epoch |
| Seat budget | 1,000 | Seats stake is apportioned into |
| Epoch length | 7,200 checkpoints | About one hour at the checkpoint interval |
| Handover confirmations | 2 checkpoints | Checkpoints the old committee orders after the one ending its epoch |
| Batch interval | 50 ms | How often a validator cuts its mempool share into a batch |

### 3.3 Ordering

- **Seats.** Stake is apportioned into integer seats by largest remainder; every threshold is counted in seats (`n` seats, `f = (n-1)/3`, quorum `n - f`).
- **Vertices.** Each validator proposes one vertex per round, referencing a quorum of the previous round, introducing its batches and acknowledging others'. Vertices are delivered by a signature-free reliable broadcast (ECHO, VOTE, ACK, READY; two-step delivery on a large ECHO quorum).
- **Commit.** A round's leader vertex commits once the first proposals of the next round from a quorum of seats reference it; earlier leaders reachable from it commit first. A leader vertex that skips the previous leader counts only with a quorum of no-votes, which closes the tail-fork attack. Each committed leader orders its not yet ordered causal history into one block.
- **Batches.** A batch executes once its introduction and a quorum of acknowledgements are ordered.

### 3.4a Three-Tier Validator Model

Validator participation follows a three-tier model. All three tiers run the same protocol and sign checkpoints with the same hardware-held composite ML-DSA-65 + P-256 key; what differs is the block classes they're eligible to propose, their governance voting weight, their slashing exposure, and (Tier 3 only) their sanction to broker tenant access to external networks.

**Tier 1 — Resource-only validator.** Open entry, no stake required. Eligibility is based on hardware profile (CPU, RAM, disk, bandwidth, IOPS thresholds), stability profile (probation uptime, no equivocation history, no slashed peers in operator history), optional TEE attestation, and geographic/network/jurisdictional diversity bonus. Earns a base reward share (reputation-weighted, capped at base multiplier). No independent governance voting weight. **No financial slashing exposure** — misbehavior results in ejection from the set plus reputation collapse, but cannot be slashed because there is no bond. Excluded from leader election for high-trust block classes.

**Tier 2 — Staked validator.** Tier 1 eligibility plus ≥ 10,000 TNZO bonded self-stake. Earns validator-bucket rewards for the blocks it proposes and the checkpoints it signs, and the validator base rights funded from a share of each epoch's burn (transaction fees are burned, not paid to validators). **Stake-weighted governance voting.** Slashing: 5% bond burn on checkpoint equivocation (15% when correlated); additional slashing on invalid TEE attestations, withholding training results, persistent SLA failures. Eligible for all block classes including high-trust. Eligible for high-trust roles: witness committee membership for training round finalization, high-value bridge duties (bridge route committee membership), AP2 high-value mandate validation.

**Tier 3 — RPC provider.** Tier 2 eligibility plus ≥ 100,000 TNZO bonded (implies the Tier 2 minimum — effective bond is 100k total, not 110k). Tier 3 implies Tier 2. Additionally **sanctioned to broker tenant access** to external networks, serve public JSON-RPC + REST verification API, broker tenant access to operator-held upstream credentials (AI provider keys, data feed subscriptions, banking rails, external-chain RPC endpoints), and route cross-chain mint/burn flows. Tier 3 earnings: Tier 2 earnings plus what tenants pay it for access and calls, each such settlement recording RPC traffic provider work for its bonded RPC stake. Tier 3 slashing: Tier 2 conditions + censoring tenant transactions, frontrunning, mishandled tenant secrets, billing fraud, persistent SLA failures.

Tier transitions are upgrades-only forward (1→2→3 by bonding more stake) or downgrades on stake withdrawal (3→2 below 100k while staying above 10k; 2→1 below 10k; 1→exit). All transitions take effect at the next epoch boundary.

The genesis configuration names the first Tier 3 RPC provider as validator-0: the seed bootstrap peer plus public RPC at `rpc.tenzro.com`. It is not architecturally privileged; any other operator that bonds 100k can register their own Tier 3 endpoint, admit their own tenants, and front their own upstream credential vault with the same protocol guarantees.

### 3.5 Leader Schedule

The leader of each round is drawn from a distribution weighted by seats times observed behaviour (a validator whose leader slots commit keeps full weight; one that misses them drops to the floor). The schedule is a function of the committed prefix: it changes only at checkpoints and draws its seed from the ordering digest of the checkpoint two back, so no validator can grind it and every validator evaluates the commit rule against the same leader. No self-reported value, and no VRF or BLS key, enters the draw.

### 3.6 Checkpoints, Certificates and Accountability

A checkpoint commits the chain, the epoch, its index, the previous checkpoint, the height range, the blocks root, the state root at a lag of two blocks, the statement root and, at an epoch's end, the next committee's root. Each validator persists that it is about to sign before signing, so a crash cannot make it sign two checkpoints with one index. Two such signatures are complete evidence: a `ReportCheckpointEquivocation` transaction carrying them is verified by the VM and recorded once, and every node slashes the signer when it replays the log.

### 3.7 Epoch Management

The validator set is fixed within an epoch (default 10,000 blocks). At epoch boundaries:

1. Pending validator additions and removals are processed, within the churn budget: entrants and stake increases together draw on half the continuing stake; an entrant larger than what is left is phased in over several epochs, never admitted whole; decreases apply in full.
2. The validator registry completes pending exits in address order while their self-stake fits `staking.exit_churn_bps` (400, 4%) of the active set's self-stake, at least one every epoch; the rest wait, the same on every node.
3. The seated set is reconciled against the validator registry, including key changes.
4. The new validator set and the registry are committed to the state trie at the epoch's first block (`epoch` / `validator_registry` namespaces).
5. Reward coupons for the completed epoch's verified work are issued against the genesis-funded rewards pool; nothing is paid for stake alone and nothing is minted.
6. The epoch history (validator set, total stake, block range) is recorded.

### 3.7a Validator Lifecycle Primitives

Validators upgrade and self-bootstrap without coordinated downtime. Three primitives, each independently composable:

**Genesis match check (`verify_genesis_matches`).** On boot, the node compares the configured genesis (`chain_id` + computed `genesis_state_root`) against values persisted under `CF_METADATA`. Identical genesis resumes against the existing DB; drift fails loud with an actionable error. This is what allows in-place binary upgrades to preserve consensus history.

**Bootstrap by machine identity.** Boot entries (`--boot-nodes`, `TENZRO_BOOT_NODES`, `[iroh] boot`) are `did:tenzro:machine:<id>[@<relay url>]`; a network address is refused. Without explicit entries the genesis validators are the boot set: a validator's machine identity derives from the P-256 leg of its consensus key, and its genesis entry may name a relay. A machine's hardware key signs an endpoint record `{machine key, transport, endpoint key, relays, served relay URL, scope, sequence, issued, not_after}` (domain `tenzro/transport/endpoint-record`, lifetime 6 h, at most 24 h), verified against the claimed identity, the lifetime, the sequence held, and the dialled endpoint key. Records travel only on Tenzro's discovery network: every node stores, verifies and answers them on the `tenzro/discovery` ALPN and exchanges snapshots with the peers it knows. Relays are an operator role: a relay serves the iroh relay protocol and its operator's own record, and is admitted only when that record announces its URL.


**Verified state sync.** A fresh node with a weak-subjectivity checkpoint (a block hash at height `A`, from `--checkpoint-hash`/`--checkpoint-height` or genesis `[weak_subjectivity]`) restores the committed state at `S = A − STATE_ROOT_LAG` from peers over iroh (`--state-sync-from <ENDPOINT_ID>`, or the genesis validators' endpoints). It asks a peer for the manifest over the `tenzro/state-sync` ALPN, then checks the anchor chain `S ..= A` ends in the trusted block, that the manifest's bucket summaries fold to the root that block commits, and each bucket (4,096 in all, fetched and written one at a time as BLAKE3-verified blobs from whichever peer has them) against its summary before writing it. After the last bucket the node's own trie must reproduce the root. A sync that stops resumes by skipping committed buckets. Snapshots are produced only at epoch-start heights, so the epoch record and validator registry restore with the state.

**Admission by governance approval.** While the governed parameter `validator.admission_approval` is 1 (as during the preview), a new validator registers only from an account an enacted `ApproveValidators` proposal named; the same proposal type can withdraw an approval not yet used. Validators named at genesis and validators already registered are unaffected. Governance sets the parameter to 0 to open admission to any account with the bond.

### 3.8 Finality

The RPC reports two heights. **Ordered** is final for every honest validator: the commit rule never reverts it. **Certified** is covered by a checkpoint certificate: transferable, and accountable to the signers. Bridges act on certified. A follower executes a block only once a certificate it verifies covers it, the blocks rebuild the certified blocks root, and its own state root matches the certified one.

A certificate is also the portable proof of finality for a party that runs no Tenzro node: another chain, a bridge relayer, an auditor. `tenzro_getCheckpointCertificate` (optional `index`; the latest when omitted) returns the encoded certificate (the checkpoint: chain, genesis, epoch, height range, state root, plus a quorum of seat signatures) and the session certificates it names. With the epoch's committee (`tenzro_getCommittee`), `tenzro_consensus::checkpoint::Certificate::verify` checks it with no node in the loop: every signature is a composite ML-DSA-65 + ECDSA-P256 signature by a seat's per-boot session key, and each session key is certified by that seat's hardware key.

## 4. Multi-VM Execution Layer

### 4.1 Architecture

The Tenzro Ledger's execution layer supports two virtual machines beside its native runtime through a unified `MultiVmRuntime` that routes transactions to the appropriate executor based on the transaction's `VmType`:

- **EVM (Ethereum Virtual Machine).** Full EVM-compatible execution for Solidity and Vyper smart contracts.
- **SVM (Solana Virtual Machine).** Solana-compatible execution for programs written in Rust targeting the BPF instruction set.
- **Native runtime.** Tenzro's own transaction types (transfers, staking, governance, identity, settlement, agent operations) execute natively under `VmType::Tenzro`.

#### 4.1.1 Why two VMs — and why this is not redundant

A reasonable objection to multi-VM L1s is that exposing several execution environments duplicates surface area without adding capability: every VM can already express any computable function, so a second VM only fragments tooling. That objection holds when the VMs target the same ecosystem — running two EVM dialects, or an EVM next to a re-implemented EVM, multiplies maintenance cost and developer confusion without enlarging the addressable application set.

Tenzro's two VMs are **complementary, not redundant**. Each anchors an ecosystem that the other cannot import:

- **EVM** is the lingua franca of permissionless DeFi: ERC-20 / ERC-721 / ERC-4626 / ERC-4337 standards, Solidity tooling, Hardhat / Foundry / Remix, the audit ecosystem, billions of dollars of stablecoins denominated as ERC-20 contracts. A chain that wants to integrate with that liquidity must speak EVM bytecode, not "an EVM-compatible API."
- **SVM** is the only execution environment where high-throughput, parallel, account-isolated programs run today: Solana's program ecosystem (Jupiter, Pyth, Marinade, MagicEden, Drift, Phoenix) is written against `solana_program` and the SPL standard. Running these programs requires the actual BPF instruction set, the Solana account model, and SPL Token Program semantics — not a transpilation. SVM also gives Tenzro access to the parallel-execution scaling story for AI agent workloads where most transactions touch disjoint state.
The integration is unified: both VMs and the native runtime read and write the same canonical TNZO balance through the pointer model (§4.9), share the same precompile-exposed primitives (TEE attestation, ZK verification, model inference, settlement), and dispatch through the same `MultiVmRuntime`. A single transaction can move TNZO from an EVM DeFi position into an SVM program, with every call taking effect or none — without bridge risk, wrapping fees, or liquidity fragmentation.

Sei Network's April 2026 pivot to EVM-only — abandoning its earlier multi-VM ambitions — illustrates the alternative outcome: two redundant EVM-compatible surfaces (a CosmWasm dialect and an EVM) on a single chain proved to be developer-confusing and economically dominated by one side. Tenzro's two VMs avoid that failure mode because each ecosystem is genuinely non-substitutable: a DeFi protocol cannot be ported off the EVM without losing its market, and a Solana program cannot be ported to EVM without losing its parallelism guarantees. The complementarity is the point.

### 4.2 Execution Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Max gas limit | 30,000,000 | Maximum gas per transaction |
| Default gas limit | 10,000,000 | Default gas if unspecified |
| Min gas price | 1 Gwei (10^9 wei) | Minimum gas price |
| Max contract size | 24,576 bytes | EIP-170 contract size limit |
| Chain ID | `<chain-id>` | Set by each network's genesis (133801 on the preview network, 1337 on the local developer chain); custody approvals are bound to it |
| Max call depth | 1,024 | Maximum nested call depth |

### 4.3 Precompile Registry

The VM provides precompiled contracts that expose native platform functionality to smart contracts:

- **TEE Precompile.** Verify TEE attestations, request enclave execution, and query TEE provider status.
- **ZK Precompile.** O(1) HashSet lookup against `ZkCommitmentRegistry`. Plonky3 STARK proofs are verified off-EVM and a 32-byte SHA-256 commitment is admitted only by an executed transaction; the precompile rejects unknown commitments.
- **Model Precompile.** Query the model registry, submit inference requests, and verify inference results.
- **Settlement Precompile.** Create escrows and trigger settlement operations.

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

**Resource markets.** Gas covers four resources, each with its own USD base fee in consensus state moving by the same rule against its own per-block target: compute (the base fee above), state growth (entries a transaction creates, `fees.state_growth_target_per_block`), bandwidth (transaction bytes, `fees.bandwidth_target_per_block`) and proof verification (`fees.proof_target_per_block`). Every unit is gas, charged at the transaction's gas price; a unit of a resource whose own base fee is above compute's pays the difference on top, in TNZO at the rate in force, so congestion in one resource prices that resource alone. A sender that cannot pay the premium has its transaction undone like any failed one. `tenzro_getFeeMarket` returns every market's base fee and target.

### 4.7 Block-STM Parallel Execution

Every finalized block is executed by `tenzro_vm::parallel::execute_block`, called from the node's block loop. The result is defined to be identical to executing the block's transactions one after another: the same state, supply change, fee pool and per-transaction outcome.

- **Speculative execution with multi-version state:** worker threads execute transactions against a view that holds the writes of earlier transactions in block order. Each execution records what it read.
- **Validation and re-execution:** a transaction whose reads changed underneath it is aborted, its writes become estimates (later readers wait on them), and it runs again. Scheduling always takes the lowest pending task, so the process terminates once every transaction has a validated execution.
- **Commutative totals:** the fee pool and total supply are accumulated as per-transaction deltas rather than read as values, so they do not serialize every transaction behind the one before it.
- **Scope:** native (`VmType::Tenzro`) transactions run in parallel. EVM and SVM transactions run alone in their block position on the node's state, because the EVM executor needs the node adapter.
- **Contention signal:** each transaction's re-execution count feeds the hot-account fee market.

### 4.8 Accounts and Ethereum account abstraction

A Tenzro account is native: its keystore (linked passkeys, recovery signers, a pending recovery) is consensus state, every validator verifies the passkey assertion on each transaction, any linked device approves, and a sponsor may send a passkey-approved change and pay its fee. Agents act under Terms recorded on chain and re-checked by every validator. Nothing that moves value runs outside a block.

The EVM keeps Ethereum's account abstraction byte-exact, so Ethereum contracts and tooling behave the same on Tenzro:

- **ERC-4337 (EntryPoint v0.9).** `tenzro_vm::account_abstraction` holds the `PackedUserOperation` layout (`accountGasLimits` and `gasFees` as two 16-byte halves, `paymasterAndData` as paymaster, two 16-byte gas limits and data) and the user operation hash EntryPoint v0.9 computes: EIP-712 domain `ERC4337` version `1`, type `PackedUserOperation(...)`, the paymaster signature suffix (`signature ‖ uint16 length ‖ 0x22e325a297439656`) left out of the hash, and for an EIP-7702 account (`factory = 0x7702`) the init code hash replaced by `keccak256(delegate ‖ initCode[20:])`. Validation data is read with the v0.9 block-number range flag (top bit of both `validAfter` and `validUntil`). An EntryPoint and its accounts deployed in the EVM run in consensus like any other contract; the node runs no user operation mempool or bundler. The bundler methods (`eth_sendUserOperation`, `eth_estimateUserOperationGas`, `eth_getUserOperationByHash`, `eth_getUserOperationReceipt`, `eth_supportedEntryPoints`) are not served, because a user operation accepted that way executed outside consensus. A user operation reaches a deployed EntryPoint as an ordinary `handleOps` transaction from any account; a passkey account sends and pays for its own native transactions, and a sponsor can pay for its keystore changes.
- **ERC-7579.** `tenzro_vm::erc7579` lists the account, module and validator selectors (`execute` `0xe9ae5c53`, `installModule` `0x9517e29f`, `onInstall` `0x6d61fe70`, `validateUserOp` `0x97003203`, `isValidSignatureWithSender` `0xf551e2ee`, and the rest) and module types 1 to 4. `tenzro_vm::aa_execution` encodes and decodes `execute(bytes32 mode, bytes executionCalldata)`: call type `0x00` carries one call (`target ‖ value ‖ callData`), `0x01` a batch (`abi.encode(Execution[])`, at most 64 calls), default exec type only.
- **P-256.** `P256VERIFY` at `0x100` follows EIP-7951 (the RIP-7212 interface): 160-byte input `hash ‖ r ‖ s ‖ x ‖ y`, 6900 gas, 32-byte `1` on success and empty output otherwise; `r` and `s` must lie in `[1, n)`, the key must be on the curve and not the point at infinity, and `r` is compared modulo `n`.

Wallets expose the native account through the standard browser interfaces (see `sdk/tenzro-inject`): EIP-6963 discovery and EIP-1193 requests; ERC-5792 `wallet_sendCalls` as one atomic contract-call transaction (at most 16 calls) approved once by the passkey, with `atomic` reported as supported and the transaction hash as the batch id; ERC-7715 `native-token-periodic` permissions written into an agent's Terms as an hourly or daily spend limit with an optional expiry, checked by every validator on each agent action, with `delegationManager` the zero address because the agent's serving nodes redeem natively. A sponsor may send keystore changes and agent Terms carrying the passkey's approval and pay their fee; a call batch is paid by its sender, so `paymasterService` is unsupported for batches.

### 4.8a EIP-7702 Type-4 Delegation

Tenzro implements EIP-7702 through the standard type-4 transaction only:

- **Signed authorization.** `Eip7702Authorization { chain_id, delegate_address, nonce, signature }` with preimage `MAGIC(0x05) || rlp([chain_id, address, nonce])` and recoverable secp256k1 `(r, s, y_parity)`. `chain_id == 0` is the cross-chain wildcard per the spec.
- **One path.** A wallet signs a standard type-4 transaction and submits it with `eth_sendRawTransaction`; it executes as an `ExternalEvm` transaction, and its authorization list is applied in consensus: each authority is recovered, its chain id and nonce checked, and the designator written into its code. `delegate_address == 0x0` clears it.
- **Designator encoding.** The EIP-7702 23-byte `0xef0100 || target_address(20)` designator is detected by `is_delegation_designator` / `extract_delegation_target`; the EVM runs the target\'s code in the authority\'s storage context.
- **RPC surface.** `eth_sendRawTransaction` installs; `tenzro_get7702Delegation` reads the designator from the authority's code.
- **SDK builders.** The Rust (`tenzro_sdk::eip7702`) and TypeScript (`setCodeTransactionSigningHash`, `encodeSignedSetCodeTransaction`, `authorizationSigningHash`) builders produce the authorization digest, the transaction digest and the raw signed type-4 bytes from signatures an external wallet or hardware signer returns; they hold no key. Both reproduce `sdk/fixtures/eip7702/vectors.json`, a vector signed by an independent wallet library, which the node's decoder reads back to the same sender, hash and authority.

### 4.8b Permit2 SignatureTransfer

Tenzro implements Permit2 (Uniswap canonical) as a protocol-level primitive in `tenzro-vm::permit2`:

- **Typed data.** `TokenPermissions { token, amount }`, `PermitTransferFrom { permitted, spender, nonce, deadline }`, and `PermitTransferFromWitness { …, witness, witness_type_name, witness_type_string }` with deterministic typehashes per the spec; the witness path embeds the witness type-string inline so EIP-712 verifiers see the full struct shape.
- **Domain separator.** `domain_separator(chain_id, verifying_contract)` against the Tenzro canonical Permit2 address `0x0000…00001023`.
- **Nonce bitmap.** `Permit2NonceBitmap` matches Uniswap's word/bit layout (`nonce[..31]` is the word position, `nonce[31]` the bit position) so users can sign permits in parallel.
- **Witness path.** A permit may carry a 32-byte witness that binds it to an off-chain artifact, so one signature authorizes the token pull and commits to what it pays for.
- **RPC surface.** `tenzro_permit2VerifyAndConsume`, `tenzro_permit2NonceUsed`. The domain separator and the digest a user signs are computed client-side.

### 4.8c Reserve-Backed Minting

A token created with reserve backing (`reserve_backing: { min_attestor_stake_tnzo }`) mints only in consensus, through `TokenOp::Mint`, and only against reserve attestations:

- **Who attests.** Any account bonded as an attestor (the `attestor` role stake). An attestation names the attestor's identity and is signed with the hardware key that identity registered on chain; the bond that answers for it is that key's account's attestor stake.
- **How much stands behind a mint.** The attestor stake of the distinct accounts whose attestations a mint carries must together reach the token's `min_attestor_stake_tnzo`. The issuer chooses how much bonded stake a mint needs, never who provides it.
- **What each attestation says.** Every attestation covers the supply after the mint and is at most `token.reserve_attestation_max_age_secs` old.
- **Changing the backing.** `SetReserveBacking` queues behind the token's policy timelock, like a policy change, and applies with `ExecutePolicy`.

There is no node-local mint registry: no operator can set, pause or apply a reserve policy outside consensus.

### 4.9 Cross-VM Token Architecture

The Tenzro Ledger implements a **Sei V2 pointer model** for cross-VM token representation. Instead of bridging or wrapping tokens between VMs (which introduces bridge risk and fragments liquidity), all VM representations point to the same underlying native balance managed by the `TnzoToken` layer. There is no lock-and-mint bridge — every VM surface reads and writes the same canonical balance.

**Architecture:**

```
                         ┌─────────────────┐
                         │   TnzoToken     │
                         │ (Native Balance) │
                         └───────┬─────────┘
                    ┌────────────┴────────────┐
                    │                         │
              ┌─────▼─────┐               ┌───▼───┐
              │ wTNZO     │               │ wTNZO │
              │ ERC-20    │               │ SPL   │
              │ Pointer   │               │Adapter│
              │ (EVM)     │               │ (SVM) │
              └───────────┘               └───────┘
```

**VM Representations:**

| VM | Representation | Decimals | Mechanism |
|----|---------------|----------|-----------|
| EVM | wTNZO ERC-20 pointer contract | 18 | Standard ERC-20 interface with approval storage; reads/writes native balance |
| SVM | wTNZO SPL token adapter | 9 | Maps SPL Token Program instructions to native TnzoToken; 9-decimal truncation (18 to 9); ATA derivation for associated token accounts |

**Decimal Conversion (SVM):**

Solana's SPL Token standard uses 9 decimals while TNZO uses 18. The SPL adapter performs deterministic truncation: the lower 9 decimal digits are dropped on deposit into SVM and zero-padded on withdrawal back to native. This means the smallest representable unit in SVM is 10^9 wei (1 Gwei-equivalent), which is sufficient for all practical token operations.

**Tenzro-Specific Precompile Addresses:**

In addition to the 9 standard EVM precompiles (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, BN254 EC operations, BLAKE2F) and 7 BLS12-381 precompiles (EIP-2537: G1ADD, G1MSM, G2ADD, G2MSM, PAIRING_CHECK, MAP_FP_TO_G1, MAP_FP2_TO_G2 at 0x0a-0x10 using the `blst` library), the VM exposes Tenzro-specific precompiles:

| Address | Precompile | Description |
|---------|-----------|-------------|
| `0x1001` | TNZO_BRIDGE | Cross-VM token transfers between EVM and SVM |
| `0x1002` | TOKEN_FACTORY | Create and register new ERC-20 tokens in the unified registry |
| `0x1004` | STAKING | Stake/unstake TNZO and query staking state from smart contracts |
| `0x1005` | GOVERNANCE | Submit proposals and cast votes from smart contracts |

**Unified Token Registry:**

All tokens — native TNZO, user-created ERC-20s, and SPL tokens — are indexed in a single `DashMap`-backed `TokenRegistry` with RocksDB persistence (column family `CF_TOKENS`). Each token entry records its `TokenId` (deterministic SHA-256 of creator address and nonce), creator, symbol, decimals, total supply, and the set of VMs where it has pointer contracts deployed. This eliminates the fragmented token tracking that plagues multi-chain ecosystems.

**Token Factory:**

The `TOKEN_FACTORY` precompile at address `0x1002` enables any smart contract or user to create new tokens on the Tenzro Ledger. Created tokens are automatically registered in the unified token registry and can be deployed as pointer contracts across both VMs. This enables ecosystem token creation (e.g., governance tokens for DAOs, reward tokens for applications) without requiring separate deployment and registration steps per VM.

### 4.9.1 Cross-VM Atomicity Invariant

The unified-balance design above produces a sharper guarantee than the multi-VM systems that wrap tokens or run separate keepers per VM. Concretely, for any block `B = [tx_1, …, tx_m]` containing a mix of EVM, SVM, and native transactions that touch shared TNZO balances, the post-block state is identical to the result of applying `tx_1, …, tx_m` sequentially against a single shared state tree. Each transaction either commits all of its state changes (across every VM it touches via the cross-VM bridge precompile `0x1003`) or reverts all of them. No intermediate state in which a balance has been debited on one VM but not credited on another is observable to any subsequent transaction or external reader.

In formal terms, block execution is **opaque (in the STM sense) and serializable**, with snapshot/rollback at the per-transaction boundary. The proof is one line: the dispatcher takes a snapshot of the shared state tree before every `Executor::execute(state, tx)` call and reverts to the snapshot if the receipt is a failure. Because the `TnzoToken` layer is the *only* shared resource across VMs, no side effects can leak between executors. This eliminates an entire class of bridge-style failure modes — there is no lock-mint-burn-release cycle, no multi-signature committee, and no optimistic challenge period — because there is no bridge.

When two transactions in the same block target the same balance from different VMs (for example, an EVM `transfer` via the wTNZO ERC-20 pointer and an SVM SPL transfer over the same source account), the conservative scheduler places them in different sequential batches: the write set of any cross-VM balance touch is statically determinable from the typed-transaction payload, so concurrent writes to the same balance are detected before parallel execution. The second transaction observes the post-image of the first; the conservation invariant `Σ balances_pre = Σ balances_post` holds for every block; and the VM-native views (`balance(addr) via EVM == balance(addr) via SVM`) agree post-block.

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

`tenzro_tee::verify_report` validates a report by checking:
1. The report is signed by a key the vendor certified, and that certificate chains by signature to a pinned vendor root (with the vendor's TCB and revocation collateral).
2. The workload is not debuggable (and, for SEV-SNP, runs at VMPL 0).
3. The hardware-signed report data equals what the verifier asked for: a commitment to a single-use nonce the verifier issued, so freshness never rests on the report's own timestamp.
4. The launch measurement is in the attestation transparency log.

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

1. The user submits an inference request with `verification: "tee"`.
2. The inference router selects a provider that detected confidential compute. A provider that cannot meet the level refuses the request; it is never served at a lower level.
3. Inference executes inside the confidential VM the node runs in.
4. The provider signs a receipt binding the catalog model hash, the engine, its machine identity and the input and output commitments, and attaches an attestation report whose report data is a hash over those same fields and its signing key.
5. The result and receipt are returned to the user.
6. Anyone can verify the chain with `tenzro_verifyInferenceReceipt`: the report against the TEE vendor's roots, its report data against the receipt, its measurement against the attestation transparency log, and the receipt signature.

---

## 6. Zero-Knowledge Proof System

### 6.1 Overview

Tenzro proves hash-preimage statements with Plonky3 STARKs. Every statement can be proven in two independent configurations that share the statement and nothing else: KoalaBear (`2^31 − 2^24 + 1`) with a degree-8 challenge extension, SHA-256 Merkle trees and transcript, FRI at rate 1/16 with 60 queries; and Goldilocks (`2^64 − 2^32 + 1`) with a degree-5 extension, BLAKE3 Merkle trees and transcript, FRI at rate 1/32 with 48 queries. Both use a hiding PCS and a 16-bit query proof of work, and both reach about 136 bits of proven soundness (FRI in the Johnson-bound regime, no proximity conjecture). STARKs need no trusted setup and rely only on hash functions. The Plonky3 git revision is pinned at `32079474b1d31d9221656ae774afb322d2597db0`. Parameters, the soundness derivation and the hash rationale are in `docs/architecture/zk-proof-systems.md`.

### 6.2 Circuits

Both circuits prove `digest == SHA3-256(domain || witness)` for a 32-byte private witness, with the Keccak-f[1600] permutation evaluated in-circuit. Public inputs are the 32-byte `digest` and a 32-byte `binding` (a verifier challenge or request hash) that the Fiat-Shamir transcript absorbs, so a proof cannot be moved to a different binding.

**Identity (`circuit_id: "identity"`).** Knowledge of the 256-bit secret behind a published identity key commitment. The secret is proven by its holder (`tenzro zk prove`) and never sent to a node; node RPCs refuse identity proving.

**Settlement (`circuit_id: "settlement"`).** Knowledge of the 32-byte service result a customer committed to before paying. The settlement engine binds the proof to the request through `binding`.

There is no inference circuit: no circuit proves that a model produced an output. Inference integrity rests on TEE attestation and the challenge protocol. There is no post-quantum quorum-certificate circuit: certificates are BLS-only and per-vote ML-DSA binding is enforced natively.

### 6.3 Proof-system diversity

`verify_k_of_n(legs, k)` accepts a statement when proofs of it verify in at least `k` distinct proof systems, every supplied leg verifies, and all legs name the same statement. The node submits a statement for `ZK_VERIFY` attestation only when proofs verify in both systems, so a soundness failure confined to one field, hash or FRI parameter set cannot produce an attested forgery. The two systems share the Plonky3 uni-STARK protocol code; an independently implemented verifier would remove that common dependency.

### 6.4 Hybrid ZK-in-TEE

1. The enclave proves the statement.
2. The enclave produces an attestation whose signed report data is a digest over the circuit, proof system, public inputs and proof bytes.
3. Verifiers check the STARK, that the report data in the signed evidence equals that digest, and the attestation itself with the strict verifier (real hardware, not simulated, chained to a pinned vendor root).

The vendor attestation signature covers the proof, so an attestation cannot be attached to a different proof or statement. There is no separate enclave-held signing key.

### 6.5 Commitment-Attestation Model

On-chain ZK verification uses a commitment-attestation pattern:

1. **Off-EVM verification.** Validators verify Plonky3 STARK proofs via `verify_proof_envelope(&Proof)` — a generic dispatcher that matches on `circuit_id` and routes to the corresponding AIR verifier.
2. **Proof publication.** The verifying node publishes the proof envelope to the DA layer and records the returned `tenzro://blob/<hash>` locator so any peer can fetch and independently re-verify it.
3. **On-chain admission.** A commitment enters the `ZkCommitmentRegistry` only through an executed transaction, so every node admits the same commitments at the same height. A node's own verification (`tenzro_verifyZkProof`) changes no state. The commitment hash is `SHA-256(circuit_id ‖ proof_bytes ‖ Σ(len_le(pi) ‖ pi))` with a 4-byte little-endian length prefix per public input.
4. **EVM precompile.** The `ZK_VERIFY` precompile is an O(1) HashSet lookup against the registry — smart contracts pay only a fixed cost to verify any STARK proof already admitted on chain.

This separates expensive verification (off-EVM, parallelizable) from cheap on-EVM gating (constant-time membership check), and avoids embedding STARK verifier circuits inside the EVM.

### 6.6 Proof Wire Format

```
Proof {
    system:         ProofSystem,       // "koala-bear-sha256-fri" | "goldilocks-blake3-fri" | "halo2-ipa-pasta"
    proof_bytes:    Vec<u8>,           // bincode p3_uni_stark::Proof (Plonky3 systems) or Halo2 transcript
    public_inputs:  Vec<Vec<u8>>,      // [digest (32 bytes), binding (32 bytes)]
    circuit_id:     String,            // "identity" | "settlement"
    created_at:     Timestamp,
}
```

Public inputs are the same bytes in every proof system; each verifier splits them into 16-bit limbs of its own field. A verifier rejects a proof whose trace height differs from the circuit's.

---

## 7. Cryptographic Primitives

### 7.1 Key Algorithms

| Algorithm | Purpose | Key Sizes |
|-----------|---------|-----------|
| Ed25519 | Transaction and message signatures | 32-byte public key, 64-byte signature |
| Secp256k1 | Ethereum-compatible signatures, key derivation | 33-byte compressed public key |
| Secp256r1 (P-256) | WebAuthn / passkey signatures (Secure Enclave, StrongBox, TPM 2.0, Windows Hello), verified on-chain via the precompile at `0x100` | 64-byte uncompressed public key (`x ‖ y`), 64-byte raw signature (`r ‖ s`) |
| ML-DSA-65 (FIPS 204) | Post-quantum hybrid signature companion to Ed25519 | 1952-byte public key, 3309-byte signature |
| ML-KEM-768 (FIPS 203) | Post-quantum hybrid KEM companion to X25519 | 1184-byte public key, 1088-byte ciphertext |
| AES-256-GCM | Symmetric encryption for keystore and data at rest | 256-bit key, 96-bit nonce, 128-bit tag |
| X25519 | Elliptic-curve Diffie-Hellman key exchange | 32-byte public key |
| SHA-256 | General-purpose hashing, Merkle trees | 256-bit digest |
| Keccak-256 | Ethereum address derivation, storage keys | 256-bit digest |

### 7.2 Address Derivation

A ledger account is controlled by a composite key pair: a classical key (Ed25519, or secp256k1) and an ML-DSA-65 key. Its address commits to both:

```text
account = SHA-256("tenzro/account" || key_type || len(classical) || classical || ml_dsa_vk)[..20]
```

where `key_type` is `0` for Ed25519 and `1` for secp256k1. In the 32-byte account slot the 20-byte address is left-aligned and followed by 12 zero bytes. A transaction, an account-owner proof and a cross-VM transfer are accepted only from the account both of their public keys derive, so an ML-DSA key cannot be substituted after the address exists. The classical-only derivation (SHA-256 of an Ed25519 key, first 20 bytes; Keccak-256 of a secp256k1 key, last 20 bytes) still names peers, attesters and other classical-key identities, but it is not a ledger account.

### 7.3 Hybrid Signature Custody

Tenzro wallets do not split the signing key. Each identity's classical key is held whole in the holder's own hardware — a passkey (WebAuthn) authenticator for a human, a TPM 2.0 or Apple Secure Enclave for a machine — and the private half never leaves that hardware. There is no dealer, no share distribution, and no quorum reconstructed at signing time; the network holds nothing.

A single transaction carries a **hybrid** signature over two legs:

1. **Classical.** Ed25519 (or the P-256 WebAuthn assertion for a passkey), produced by the device key. Verifies under the standard verifier — no protocol-specific verifier required.
2. **Post-quantum.** ML-DSA-65 (FIPS 204), derived on demand from the same hardware root and signed alongside the classical leg.

The hybrid verifies as the conjunction of its legs, so a break of one algorithm does not forge a transaction. The post-quantum leg is mandatory: an account that has not enrolled an ML-DSA-65 key signs nothing until it does, and its first transaction is the enrolment (`AccountKeys`, `EnrollPqKey`), which carries the leg of the key being enrolled. The wallet, the CLI (`tenzro pq-hybrid enroll`, and automatically before the first transaction a new account sends) and the Rust and Python SDKs (`AccountKeysClient::send_enrolling`) enrol the hardware's key, so a new account is never left unable to send. Recovery is handled by a guardian set on the smart account (§15.9), not by holding a spare share.

### 7.4 Envelope Encryption

For data at rest (keystore files, cached keys), Tenzro uses envelope encryption:
1. A data encryption key (DEK) is generated randomly.
2. Data is encrypted with AES-256-GCM using the DEK.
3. The DEK is encrypted with a key encryption key (KEK) derived from the user's password via iterated SHA-256 (10,000 rounds).
4. The encrypted DEK, salt, nonce, and ciphertext are stored together.

---

## 8. TNZO Token Economics

> **Governed parameters.** Fees, splits, treasury legs, staking minimums, reward shares, slashing, unbonding periods and burn rates are governed parameters: genesis values, changed only by enacted proposal and only within the bounds compiled into the node ([GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md)). The network opens as a preview, then a testnet, then the stages governance decides on the way to mainnet; each phase may start from its own genesis values.

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
- The governed share of the base fee is burned (all of it by default); everything else a block collects, including priority fees, goes to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%).
- Validators are paid from the rewards pool (§8.4), not from gas

**2. Network Commission Fees**
- The network's share of AI provider inference payments and TEE provider service fees, set by the node's economic mode
- Collected when users pay providers for intelligence (models) or security (TEE enclaves)
- Divided once, by the serving node's economic mode (genesis values):

| Node mode | Operator | RPC provider | Treasury |
|-----------|----------|--------------|----------|
| Private | 100% | — | — |
| Public, validating | 90% | — | 10% |
| Public, not validating | 80% | 10% | 10% |

Nothing of the node revenue split is burned or paid to stakers. Separately, every on-chain settlement (escrow voucher, stream and hash-lock claims, compute and storage claim hours, x402) pays the governed settlement fee, `fees.settlement_fee_bps` (0.1% at genesis), half burned and half to the treasury. A payment to a bonded provider may also carry the governed treasury leg of its class of work (`fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps`, 0 at genesis, at most 5,000 bps), taken from the provider's credit after the fee. The insurance pool takes `fees.insurance_pool_bps` (10%) of every treasury-bound fee. What a settlement may earn in rewards is bounded by its fee plus its leg (TOKENOMICS §7).

The settlement split and the marketplace commission are one governance-set `EconomicPolicy` block, adjusted through on-chain proposals.

### 8.3 Staking

Participants bond TNZO per role, in consensus, with a `Stake` transaction (`bond`, `unbond`, `withdraw`; one stake per account per role, unbonding over a governed period). The role vocabulary is the node's `--roles` vocabulary (`NetworkRole`): `rpc`, `tee`, `ai`, `compute`, `storage`, `attestor`, `wallet`, `catalog` bond through `Stake`, the validator role through `RegisterValidator`, and `fullnode`, `light`, `edge`, `archive`, `bootstrap`, `micro` take no bond. A node refuses to boot with a bonded role its operator has not bonded. The ladder is defined in `tenzro-types/src/constants.rs` and applied by `NetworkRole::required_stake`:

| Role | Bond | Scales with |
|---|---|---|
| `rpc` | 100,000 TNZO | — |
| `validator` | 10,000 TNZO | — |
| `tee` | 10,000 TNZO | — |
| `ai` | 1,000 TNZO | — |
| `attestor` | 100,000 TNZO | — |
| `wallet` | 1,000 TNZO | — (declares its passkey domain) |
| `catalog` | 1,000 TNZO | — |
| `compute` | 500 TNZO floor | Accelerators pledged |
| `storage` | 100 TNZO floor | Terabytes pledged |

Two rungs scale with pledged capacity, so the bond tracks the exposure it collateralizes:

- **Compute Provider** — 1,000 TNZO per accelerator scaled by class (0.5× integrated, 1× consumer, 2× workstation, 5× datacentre), summed over everything pledged. One datacentre card plus one consumer card bonds 6,000 TNZO.
- **Storage Provider** — 100 TNZO per whole terabyte, so 50 TB bonds 5,000 TNZO.

Pledging no capacity to a scaling rung yields that rung's floor, never zero. The RPC Provider bond is the largest because a public endpoint brokers tenant traffic and upstream credentials, the largest trust surface any role holds. Every figure is governance-adjustable.

| Parameter | Value |
|-----------|-------|
| Unbonding period | 7 days (604,800,000 ms) |
| Slashing | Variable, based on offense severity |

**No reward multipliers.** Rewards are work-gated (§8.4) and nothing is paid on stake. Validators are paid for consensus votes and block proposals; providers of every type, TEE providers included, are paid by the fees their settlements recorded. No provider type carries a multiplier.

Consensus weight is separate from every bond above: only the validator bond carries finality weight, so bonding for any number of service rungs cannot move a quorum.

**Staking lifecycle:**
1. **Stake.** Lock TNZO against a provider type. Must meet minimum stake requirement.
2. **Active.** Stake is active; provider participates in the network and earns rewards.
3. **Unbonding.** Initiate unstake; stake is locked for the unbonding period.
4. **Withdrawn.** After unbonding completes, stake can be withdrawn.

**Slashing** reduces a provider's stake for provable misbehavior. Every slash is applied in consensus state by the transaction that carries its evidence, and the slashed TNZO moves into the insurance pool. Checkpoint equivocation (two signatures by one validator on different checkpoints with the same index) is proven by a `ReportCheckpointEquivocation` transaction that the VM verifies and records once; it slashes the signer's bond (genesis validators are bonded at genesis) by three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it (at least 5%, 15% for a validator that has offended before, at most the whole stake; earlier offenders are topped up when a later offence raises the rate), and every node then drops and jails the signer when it replays the log.

### 8.4 Reward Distribution

Rewards are **work-gated**, issued per epoch as coupons that claim a transfer out of the genesis-funded rewards pool rather than paid on stake. TNZO supply is fixed; nothing is minted:

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
    coupon     = bucket_rights * work_share            // an unclaimed claim on the pool
```

Work weight is measured by the protocol — never self-reported. Validators earn on finalized-block and quorum-certificate participation; providers on metered proof-of-service (uptime- and reputation-scaled); the ecosystem bucket on contributions accepted through governance/foundation review (development, apps, tools). Rights left unmatched in a bucket, and coupons unclaimed within the claim window, are **permanently unminted** — supply only moves for work that was both done and claimed. Claiming a coupon mints the `liquid_bps` fraction immediately and opens a 12-month linear reward-vesting schedule for the remainder. Epoch reward metering is enforced sequential — epoch N is closed before N+1.

### 8.5 Treasury

The Network Treasury is a multi-asset vault that accumulates Network commission fees across all supported assets (TNZO, USDC, USDT, ETH, SOL, BTC):

- **Keyless.** The treasury is `network_treasury_address`; no key, administrator or multisig withdraws from it. Only an enacted governance proposal moves its funds, after its timelock, during which Foundation stewards may veto or hold it (never spend).
- **Backing ratio.** The treasury publishes a `backing_ratio = treasury_value / tnzo_supply`, providing transparency into the network's economic health.
- **Fee sources.** The treasury receives its leg of the revenue split on service payments (§8.2), the unburned half of the on-chain settlement fee, and the block fees that are not burned (by default every priority fee), each less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%). No gas is paid to validators directly.

---

## 9. Settlement Layer

### 9.1 Overview

The settlement layer handles all economic transactions between participants. It supports three settlement modes designed for different use cases:

### 9.2 Immediate Settlement

For simple one-shot payments:

A one-shot payment is a one-leg settlement plan (or a payer-signed `PayerSettle`), executed by the VM:

1. The payer signs the authorization; the VM checks the balance and the payer's Terms caps.
2. The split engine (`tenzro_types::split::apply`) charges the protocol fee once on gross and divides the rest.
3. The payee is credited and a consensus `PaymentRecord` (and, for a plan, a per-leg receipt at `plr:`) is written.

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
    status:             EscrowStatus,      // Funded | Released | Refunded | Expired | Disputed
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
- `ProviderSignature` — Released by the provider, the payee, with the release transaction it signs from its own account (passkey or TPM-rooted).
- `ConsumerSignature` — Released by the consumer, the payer, with the release transaction it signs from its own account (passkey or TPM-rooted); no other account can release it, and no key carried in the proof counts.
- `BothSignatures` — Released once the payer and the payee have each sent a release transaction signed from their own accounts: the first is recorded as an approval, the second releases.
- `Timeout` — Auto-released or refunded after a deadline.
- `Custom { condition }` — User-defined conditions.

A third party that releases names itself in the escrow: an `Executor` escrow names its account, a `QuorumAttestation` escrow its committee. No key carried in a release proof stands for a party.

**Authorization invariants (enforced by the VM):**
- `CreateEscrow.from` must equal the signing payer (verified at mempool admission). The VM never trusts a `payer` field in the payload.
- `ReleaseEscrow` is rejected unless `tx.from` is the party the recorded `release_conditions` names (the payer; the payee for `ProviderSignature`; the payer or the named executor for `Executor`; either party, one transaction each, for `BothSignatures`; anyone with the committee's threshold for `QuorumAttestation`), the escrow is in `Funded` state and not expired.
- `RefundEscrow` is rejected unless `tx.from == escrow.payer` AND (the escrow is expired OR `release_conditions ∈ {Timeout, Custom}`).

**Escrow lifecycle:**
1. Payer constructs and signs a `CreateEscrow` typed transaction with payee, amount, asset, expiry, and release conditions.
3. On block dispatch, the Native VM derives `escrow_id`, derives the vault address, debits the payer, credits the vault via a single auditable privileged-VM payout helper, persists the `EscrowAccount{Funded}` record to RocksDB `CF_SETTLEMENTS`, and emits a receipt log carrying `escrow_id`.
4. Provider delivers the service.
5. The party the release conditions name signs and submits a `ReleaseEscrow` (vault → payee), or after expiry the payer submits a `RefundEscrow` (vault → payer). The VM re-verifies authorization before payout.

**Reads.** The escrow record lives only in VM state at `escrow:<escrow_id>`.
`tenzro_getEscrow` loads it from state; `tenzro_listEscrowsByPayer` and
`tenzro_listEscrowsByPayee` page the `EscrowCreated` event log (cursor paging)
and load each record from state.

#### Lock reconciliation

Every settlement lock on another network keeps a running hash and count over
what it records (each lock, release and refund). `SettlementPlan { op:
reconcile }` submits the entries since the last reconciliation with the
route's proof of the lock's checkpoint; folded from the stored hash they must
give the proven hash and count, or the transaction is refused. Each entry is
checked against its plan and decision; one that disagrees is stored as a
provable mismatch (`recon_mismatch:<route>:<position>`) and disables the
route. On an attested route the reconciliation also slashes the attestor
stake of the route's committee members into the insurance pool through the
one slash path, and the account a mismatch cost the leg's value claims it
with `PayInsuranceClaim { recon_mismatch }`. Reads: `tenzro_getReconciliation`,
`tenzro_listMismatches`; `tenzro_submitReconciliation` checks a submission and
returns the transaction to sign. See SETTLING_ACROSS_NETWORKS.

#### Netting in consensus

A plan whose legs are `netted` (one asset: TNZO or a carried asset a governed
route lists) commits when it opens. The protocol fee is charged on its gross
value at once, from collateral the opener posted on Tenzro
(`SettlementPlan { op: post_collateral | withdraw_collateral }`, one vault per
participant and asset), and the split rule's credits become the opener's
obligations to the recipients in the asset's open batch. An obligation is
admitted only while the opener's net debit in the batch stays within its
collateral, and collateral can be withdrawn only down to that net debit. A
delegated agent's collateral comes from its own wallet: each post and each
netted plan's action names its asset (none for TNZO) and states the amount
in it, which counts against that asset's per-payment and daily limits in the
terms and, at its USD value, against the wei caps, as every agent plan does.

When the batch's epoch (`settlement.netting_epoch_ms`, default one hour) ends,
block execution nets it with the deterministic greedy algorithm (net each
participant's position, match the largest debtor with the largest creditor)
and pays each net instruction from the debtor's collateral vault. A debtor
whose usable collateral no longer covers its net debit (an issuer froze or
took it) defaults: its collateral is divided over its instructions in
proportion by the split engine's largest-remainder rule, the default is
recorded at `ndef:<address>`, and it opens no netted plan again.

The batch record `nbat:<asset>:<seq>` keeps the canonical obligations, their
Merkle root, the instructions, what each paid and the defaults.
`tenzro_getNettingBatch {asset, seq?, participant?}` returns it with its
state-proof key and, for a participant, a gross-to-net statement: each
obligation it is party to with a Merkle path to the root, and the instructions
naming it; its gross position over the obligations equals its net over the
instructions.

### 9.4 Payment Channels

For high-frequency, low-value payments such as per-token inference billing, a
channel is an on-chain escrow plus cumulative vouchers:

1. **Open.** The payer funds an escrow with its own signed `CreateEscrow`
   transaction naming the payee and an expiry. The escrow id is
   `SHA-256("tenzro/escrow/id" || payer || nonce_le)`.
2. **Pay.** Each payment is a voucher `{escrow_id, cumulative_amount,
   public_key, signature}`: an Ed25519 signature by the payer over the
   `tenzro/escrow-voucher` preimage of chain id, escrow id and the running
   total. The payee accepts a voucher only after checking it against the
   escrow in consensus state, and only if it advances the total by at least
   the charge.
3. **Claim.** Anyone may submit `ClaimEscrow` (selector `0x01000013`) with up
   to 32 claims, each a voucher and the total claimed under it: what the
   payee's metering charged, at most the voucher's amount. The VM checks
   every voucher against its escrow's payer before moving anything and pays
   each escrow's payee the advance, all or nothing. A claim that does not
   advance past what was already claimed, or that exceeds its voucher,
   reverts. A voucher signed ahead of a call covers that call's ceiling; the
   headroom above what the calls cost is never claimed.
4. **Refund.** After expiry the payer refunds whatever was not claimed,
   the vouchers' headroom included.
   Claims after expiry are refused, so a claim can never race the refund.

No party depends on a node's memory for funds: the escrow and every claim
live in VM state. The same sessions back MPP `session` payments and the x402
`batch-settlement` scheme.

A hash-locked escrow (`ReleaseConditions::HashLock { hash }`) is paid to its
payee by `ClaimEscrowPreimage` (selector `0x01000014`) against a preimage of
the lock, which the transaction and its `EscrowPreimageRevealed` log publish.
This is the delivery-versus-payment primitive for HTTP 402: a seller that
encrypts a response under a key whose hash locks the buyer's escrow is paid
exactly when the key becomes public, and a lock nobody opens before expiry
leaves the funds for the payer's refund.

### 9.4a Escrow References and Streams

`CreateEscrow` (and an agent's `create_escrow` action) may carry a
`reference`: 32 opaque bytes the payer chooses, stored on the escrow and
appended to its `EscrowCreated` log (`escrow_id || payer || vault ||
reference`). The chain gives it no meaning; an application that opens
escrows (a task market, a session standby) uses it to find its escrows again
with `tenzro_getEscrow` and `tenzro_listEscrowsByPayer`.

A stream escrow (`ReleaseConditions::Stream { rate_per_epoch, epoch_ms }`)
opens with `CreateEscrow` like any other. It accrues `rate_per_epoch` for
every whole `epoch_ms` since funding, up to its amount and expiry; the payee
draws it with `ClaimEscrowStream`, the payer stops it with `RefundEscrow`
(accrued part to the payee, the rest back). A stream pays a positive rate, at
most its amount, over a positive epoch. A compute rental is a stream to the
provider's bonded address, paid by the validators' SLA verdicts: an epoch
judged unavailable is never paid out of the stream and stays with the
renter; an epoch not yet judged is paid once judged available, or once its
24-epoch attestation window closes with no verdict, and is paid when the
payer stops the stream.

### 9.4b Evidence Checks

`tenzro_verifyEvidence { items }` checks 1 to 16 evidence items against
chain state and returns, per item, its kind, the digest it checks to and
whether the chain verified it. An `audit` item (an audit or
attested-telemetry entry with its proof) must reach the epoch root its node
committed with `AgentAuditCommit`; a `terms` item must name an agent with
terms on chain (the digest of the terms in force is returned); a
`settlement` item must name a recorded HTTP-402 settlement; a `sensor_data`
item must carry the measuring device's signature over
`SHA-256("tenzro/sensor-reading" || len(did) || did || payload_digest ||
measured_at_ms)` under the key its identity registered; a `finality_proof`
item (journal and Groth16 seal) must verify against the governed finality
program, and checks to `SHA-256("tenzro/evidence/finality-proof" ||
checkpoint_digest || committee_root)`. A `document` (mandate, receipt,
evidence pack, delivery) is bound by its SHA-256 and never verified on
chain. An item state does not support is refused with the reason. The read
writes nothing: applications that pay on delivery (task markets, dispute
panels) call it before they release an escrow.

### 9.4c Network Duties

A duty is work the chain itself pays for, to the first sender whose proof
the chain verifies. Its reward sits in a keyless vault, `SHA-256(
"tenzro/duty/vault" || id)` unless the funder's own keyless account holds
it; the transaction that proves the work pays it and closes the duty, and a
duty closed unpaid returns its reward to the funder. Nobody awards a duty
and nothing in it is a fixed value:

| Duty | Funded by | Paid by |
|---|---|---|
| `reconciliation { route, epoch }` | the treasury, `settlement.reconciliation_reward` per route with a settlement lock, opened in the first block of each epoch and closed at the next | the first verified reconciliation of the route's lock in the epoch (see SETTLING_ACROSS_NETWORKS) |
| `grant_relay { agent_did, chain, seq }` | the grant's relay deposit (`agent.relay_deposit_utnzo.<family>`), opened when a grant on a chain that reports back is voided | the proven install of that void on the chain |

Reads: `tenzro_listDuties` (open duties, oldest first) and
`tenzro_getDuty { duty_id }`, with id `SHA-256("tenzro/duty/v1" || kind)`.

### 9.5 Batch Settlement

The `BatchProcessor` enables atomic multi-settlement operations: either all settlements in a batch succeed, or all are rolled back. This is essential for multi-party transactions where partial settlement would be inconsistent.

### 9.6 Native-TNZO On-Chain Settlement

When an HTTP 402 payment (x402 or MPP) settles in native TNZO, the balance move
is a consensus-mediated `PayerSettle` transaction authorized by the payer, not by
the node. The payer signs the canonical payment authorization: domain
`tenzro/payment-authorization`, then chain id, payment id (the challenge id),
payer, payee, ceiling and asset, length-prefixed. The node's ledger rail
submits the transaction carrying that authorization, waits until it executed
in a finalized block, and only then does the gateway issue a receipt.

**Native-VM dispatch:**

| Selector       | Operation   | Gas    |
|----------------|-------------|--------|
| `0x01000024`   | PayerSettle  | 40,000 |

The `PayerSettle` payload carries `{ payer, payee, amount, payment_id,
authorization }`, the authorization being `{ public_key, signature,
max_amount, asset }`. On dispatch the Native VM:

1. Verifies that the key controls the payer account, that the signature
   covers this chain, payment id, payer, payee, ceiling and asset, that the
   asset is TNZO and that `amount` does not exceed the signed ceiling.
2. Rejects the transaction if the `payment_id` marker already exists, so a
   payment settles once however many times it is submitted.
3. Charges gas to the submitter, debits the payer, pays any registered app
   margin, pays the network share (`HTTP_402_NETWORK_SHARE_BPS` = 10% of the
   amount after margin) to the network treasury and credits the payee.
4. Sets the replay marker.

Because the payer's signature is the authority, anyone may submit a
settlement; the submitter pays gas and gains nothing else. `payer ≠ payee`,
`amount > 0` and `1 ≤ payment_id length ≤ 128` are checked before any state
change. The receipt's `settlement_tx` is the executed transaction's hash. A
payer who cannot cover the amount gets an error, never a receipt, and
concurrent presentations of one credential settle once (the gateway claims
the challenge atomically). Payments in an external-chain asset settle through
their scheme (§13.6) and do not use this selector.

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

`HfArtifactDownloader` fetches model weights from peers over iroh blobs first and falls back to the Hugging Face Hub, reporting progress (bytes downloaded, total size, percentage). Every downloaded or served model is recorded as a content-addressed manifest in the trust ledger, and downloads and loads are checked against the SHA-256 in the model's catalog entry and the model's verified manifest. The catalog is published data: signed entries from the publishers the operator's catalog trust list recognises ([TRUST.md](TRUST.md#model-catalog)).

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

Each provider publishes an advertised capacity in its gossip announcement — maximum concurrent requests, requests per second, batch size, and whether multi-token-prediction is enabled. Consumers rank providers on the measured throughput their own node observes (usage and reputation), and read the advertised capacity from the service registry entry; no dedicated RPC returns the two side by side.

#### Automatic hardware detection

Every node profiles its own hardware once at startup, with no operator configuration:

- **System memory** from `/proc/meminfo` on Linux and `sysctl hw.memsize` on macOS.
- **NVIDIA GPUs** via `nvidia-smi` (name, VRAM, compute capability per device) plus an NVLink probe (`nvidia-smi nvlink --status`) that distinguishes NVLink-connected multi-GPU machines from PCIe-only ones.
- **AMD GPUs** via `rocm-smi` (name, VRAM) paired with `rocminfo` gfx target discovery.
- **Apple Silicon** is treated as a unified-memory device: the GPU-usable budget is approximately three quarters of system RAM, matching the Metal working-set limit.
- **Coherent CPU/GPU parts on Linux** are recognised structurally rather than by model name: a host with exactly one accelerator whose reported memory falls within an eighth of system RAM is holding one physical pool, and its memory is counted once. Parts whose device memory is a genuinely separate pool — including those bridged to host memory over a coherent interconnect — fall outside the test and keep the discrete accounting.

Probe failures degrade to coarser answers — a machine where `nvidia-smi` is absent simply reports no NVIDIA devices; it never errors. A `detected` flag records whether the profile came from a real probe: hardware claims are only ever produced by the node's own detection, never typed in by an operator.

Low-precision support is derived from the silicon, not declared: FP8 is inferred from NVIDIA compute capability ≥ 8.9 (Ada, Hopper) or AMD gfx94x/gfx95x/gfx12 targets, and FP4 from compute capability ≥ 10 (Blackwell) or gfx950 (CDNA4).

#### Hardware classes and routing

The detected profile collapses into a coarse `HardwareClass` — `Cpu`, `ConsumerGpu` (up to 24 GB VRAM), `DatacenterGpu` (25–96 GB, and above that band when the inventory holds a single device), `MultiAccelerator` (above 96 GB across more than one device), or `Unknown` when no probe ran. The class contributes a static weight to routing (0.2 / 0.5 / 0.8 / 1.0 respectively) alongside the dynamic observed metrics; `Unknown` providers get a neutral 0.5 and compete purely on measured throughput and reputation. Requests may carry a `min_hardware` hint in `InferenceParameters.custom` (`"consumer-gpu"`, `"datacenter-gpu"`, `"multi-accelerator"`) to set a hardware floor — a provider with no detected profile never satisfies an explicit floor, so the hint filters on verified capability only.

Routing also applies a memory-fit filter: when a model's registry entry carries a real weights size, providers whose detected memory budget cannot hold the model are excluded before scoring. The budget is system RAM plus discrete VRAM (llama.cpp splits a model across both pools), or the pool counted once on a unified-memory host. Providers with no detected profile pass the filter — absence of a claim is not treated as a negative claim.

#### VRAM-aware GPU offload

When a model loads, the runtime sizes the GPU offload from the detected profile and the model's own GGUF header:

- If the weights (with a 1.35× headroom factor for KV cache and compute buffers) fit in the GPU budget, all layers offload.
- If detection positively establishes that discrete VRAM cannot hold the full model, the runtime reads the layer count from the GGUF header and offloads the proportional number of layers, leaving the remainder on CPU.
- Unified-memory machines always take full offload — there is no separate VRAM pool to overflow.
- Cluster-scheduled loads skip the check entirely: the LAN placement planner has already guaranteed fit.

The result is that the same `tenzro model serve` command works on an 8 GB laptop and a 640 GB HGX node; the runtime picks the largest offload the hardware supports rather than failing or silently thrashing.

#### Served-model publication

Serving a GGUF model publishes it into the shared model registry with the real artifact hash: the node streams a SHA-256 over the weights file in the background and registers the model with that digest, catalog-derived size, context window, and architecture. Peers that later fetch the weights verify the downloaded bytes against this registry hash, so the digest is never synthetic — if hashing fails, the model is announced to the network but stays out of the registry rather than entering with a fabricated hash. Stopping a model (or failing to reload it at boot) flips the registry row to Inactive so routing stops considering it; re-serving reactivates it in place.

#### Native serving only

`tenzro_serveModel` loads a model into the node's own runtime; there is no path that binds a served model to an external inference server. It refuses a request carrying `engine`, `base_url`, `upstream_model` or `api_key` with `-32602` rather than ignoring the parameter, so a caller never believes a model is bound to an external server that the node is not using.

### 10.8 Verifiable Inference (TOPLOC Commitments)

Provenance signing (§10.6) attests to who served a response; a TOPLOC commitment attests to what the model computed. A request carrying `verifiable: true` (JSON-RPC `tenzro_chat`, the OpenAI-compatible surface, or `tenzro_inferenceRequest`) instructs the serving node to record the top-`k` raw logits (`k = 16`) at every generated decode step and persist the resulting commitment durably under its canonical SHA-256 hash. The response carries `{hash, k, steps}`; the full commitment is retrievable by hash.

**Verification is asymmetric.** A verifier holding the same model weights replays prompt + committed output token ids as a single prefill pass and compares per-step top-k logits — roughly two orders of magnitude cheaper than the original autoregressive decode. Providers that serve a quantization below their advertised precision, substitute a smaller model, or fabricate output produce logits that diverge from the commitment.

**Privacy.** The prompt is never stored with the commitment — the verifier supplies it at verification time. The commitment does contain the output token ids (the object of attestation), so requesting `verifiable` is an explicit opt-out of the gateway's completion-retention default for that response.

**Scope.** Commitments come from the local single-token (llama.cpp serial) decode path, non-streaming only: the SSE token channel carries no commitment and externally-fronted engines do not expose per-step logits. On the network path the flag is forwarded to the remote provider; its commitment object passes through the proxy verbatim, so a challenge is always anchored to the provider that served.

**Challenge lifecycle.** Any party may file a challenge against a stored commitment (`tenzro_fileInferenceChallenge`); the challenged model and provider are read from the stored envelope rather than caller input, so filings cannot misattribute. A commitment can be challenged once. Filing draws a stake-weighted committee (weighted sampling without replacement) from the active validator set, seeded by finalized-block entropy and the commitment hash, so the draw is deterministic per dispute and grinding-resistant; the provider's own consensus key is never seated, so a provider cannot decide its own dispute. Each seat records the validator's node key and its account address. The verdict is decided by the committee, not an operator, through a signed commit-reveal vote: each drawn member commits `H(verdict ‖ salt ‖ challenge_id ‖ voter)` (`tenzro_commitChallengeVote`) and later discloses `(verdict, salt)` (`tenzro_revealChallengeVote`), which must reproduce the commit. Both carry the seat's P-256 key and its signature under the `tenzro/inference/challenge-vote` context, made on the voter's own node by its hardware identity key with `tenzro_signChallengeVote` (admin-gated); the key must be the one the seat's account address commits to, and a vote without a valid seat signature is refused. The commit window and the reveal window are one hour each, and reveals open only when commits close (quorum reached or window elapsed). The quorum is `floor(2t/3) + 1` of the committee stake `t`. `tenzro_finalizeChallenge` upholds when revealed uphold stake reaches the quorum and dismisses when revealed dismiss stake does; with neither, the challenge stays open until the reveal window ends and is then dismissed (the provider prevails). Finalize is idempotent: a decided challenge returns its verdict unchanged. `tenzro_auditInferenceChallenge` lets anyone re-check a record: the draw, every signature and the tally. An upheld challenge fires the provider's existing penalty paths: routing reputation decrements through the failed-call path, and a failure is recorded against the provider's compute bond. No dedicated slashing primitive exists for inference challenges; the penalty economics reuse the reputation and bond machinery that also governs availability failures. Reputation increases only through settled payments, which prevents recovery via self-challenge. Commitments and challenges persist in `CF_CHALLENGES` and survive restarts; a node without durable storage disables the surface entirely.

### 10.9 Model Visibility and Sealed Distribution

Two independent primitives keep a model private: registry-level visibility and sealed weight distribution.

**Visibility.** A node has one `Visibility` — `public` (default), `gated` or `private` — that applies to every resource it offers, and a served model of any type may carry an override (`tenzro_serveModel` or `tenzro_load*Model` `visibility` param; CLI `tenzro model serve --public | --gated | --private`). With no override the model follows the node. A `public` model is announced over gossip, heartbeats to the provider set, participates in network inference routing, and is callable by anyone who pays the operator's per-use price. A `gated` model is announced the same way with `visibility = "gated"` (and listed in the provider heartbeat's `key_required_models`), and is callable only by callers the node's access policy names. A `private` model has no announcement, no heartbeat and no presence in provider discovery — it serves only this node's own callers. The override persists with the serve record; the node's visibility persists when set over `tenzro_setNodeVisibility`. Both are enforced at the announcement and heartbeat paths, read live each tick, rather than by filtering at query time.

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
    recipients:     Vec<SealedRecipient>,    // did, hybrid recipient_key (X25519 + ML-KEM-768), wrapped key, optional enclave measurement
    wrap_alg:       "x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm",
    manifest_hash:  Hash,                    // domain-separated SHA-256 over the above
    signature:      CompositeSignature,      // the sealing node's hardware identity key
    signer_pubkey:  Vec<u8>,
    created_at:     Timestamp,
}
```

The artifact is split into fixed-size shards, each encrypted with a nonce-prefixed AES-256-GCM content key generated for the seal. Ciphertext shards publish to the content-addressed blob store and are referenced by `tenzro://blob/<hash>` URI; each shard's ciphertext hash is domain-separated (`tenzro/model/sealed-shard ‖ model_id ‖ index`). The content key is wrapped once per recipient using hybrid X25519 + ML-KEM-768 envelope encryption (`x25519-mlkem768-hkdf-sha256-envelope-aes-256-gcm`) — the only wrap scheme the module produces or accepts; reading the content key needs both exchanges broken. A recipient is a DID plus a hybrid X25519 + ML-KEM-768 public key, and may carry `enclave_measurement_hex` — the measurement of the enclave the owner is willing to release the key to (the same binding model as Confidential-tier training enrollment).

Unsealing verifies in this order: manifest signature, wrap algorithm, recipient match (DID and public key), the pinned enclave measurement when the recipient carries one, per-shard ciphertext hashes as shards arrive, and finally the plaintext `model_hash` after reassembly — the decrypted artifact reaches model storage only when every check passes.

The measurement check is a gate, not a record. The installing node *is* the recipient — it holds the X25519 and ML-KEM-768 secret keys the manifest names — so it proves its own enclave: it generates a fresh report whose user data commits to `SHA-256("tenzro/model/sealed-recipient" ‖ did ‖ x25519_pubkey)`, verifies that report against a pinned vendor root (simulated reports are refused), confirms the returned report actually commits to that binding, and only then compares the measurement against the pinned one. No evidence comes from a caller, so there is nothing to replay. A node with no TEE provider produces no evidence and the install is refused rather than allowed through. Manifests persist in `CF_MODELS` and hydrate on restart; they carry no key material beyond wrapped ciphertexts and are safe to distribute over any channel.

Sealing and installing are operator actions for node administrators (`tenzro_sealModel`, `tenzro_installSealedModel`). Discovery is open: `tenzro_getSealedModel`, `tenzro_listSealedModels`, and `tenzro_modelRecipientKey` (the node's X25519 recipient public key, generated at first start).

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

The `AgentIdentityManager` handles registration, lifecycle management, and auto-provisions a permissionless wallet for each agent — the agent's classical key is held in its own TPM 2.0 / Secure Enclave, no custody held — enabling agents to hold and transact TNZO autonomously.

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
| `/.well-known/agent-card.json` | GET | Agent Card discovery (signed) |
| `/a2a` | POST | JSON-RPC 2.0 dispatcher (SSE for `SendStreamingMessage`) |

**Agent Card.** Each node publishes an A2A 1.0 Agent Card at `/.well-known/agent-card.json`, signed with a detached JWS by the operator wallet's bound signer; a node that cannot sign serves no card. The card advertises the node's capabilities, skills, supported input/output modes, authentication requirements, and protocol version 1.0. 21 skills are advertised: wallet, identity, inference, settlement, verification, staking, token, contract, join, bridge, compliance, events, adaptive-burn, iroh-transport, urwa, bridge-fee-in-tnzo, storage, compute, moe, media-gen and discovery.

**JSON-RPC Methods:**
- `SendMessage` / `SendStreamingMessage` — Send a message to create or continue a task
- `GetTask` — Query task status (with optional history length limit)
- `ListTasks` — List tasks (optionally filtered by context ID)
- `CancelTask` — Cancel a running task

**Task lifecycle:**
```
Submitted → Working → Completed
                    → Failed
                    → Canceled (via CancelTask)
```

The `TaskManager` stores tasks in a concurrent `DashMap<String, A2aTask>`, with each task tracking its state, message history, and artifacts. Tasks are held in memory and are lost when the node restarts. The server answers each task itself, from a read-only answer chosen by content analysis (wallet queries, block lookups, identity operations, model discovery, network status) or a typed `readEvents` read; it does not hand a task to another worker or provider. A2A is the node's front door and audit surface for agents, not a task marketplace: value moves only through signed transactions, and every call is recorded and signed by the node (see AGENT_TRUST.md).

**Streaming.** The `/a2a/stream` endpoint provides real-time task updates via Server-Sent Events (SSE). Clients receive `task` events as the task transitions through states, followed by a `done` sentinel when processing completes.

### 11.6 MCP Server

Each Tenzro node runs a Model Context Protocol (MCP) server (default port 3001) using the `rmcp` crate with Streamable HTTP transport. This exposes node capabilities as MCP tools that any MCP-compatible AI agent can invoke programmatically.

**Server configuration:**
- Protocol version: `2026-07-28` only; every request carries the revision's `_meta`, and `initialize` is not served
- Transport: Streamable HTTP (endpoint: `/mcp`), stateless: `server/discover`, per-request `_meta`, no sessions
- Capabilities: Tools and resources (with subscriptions)
- Authorization: OAuth 2.1 with a passkey login on `/authorize`, Client ID Metadata Documents, RFC 8707 audience-bound tokens and RFC 9207 `iss`
- Server name: `tenzro`

**Available tools (429)** spanning wallet & ledger, network & blocks, identity & delegation (including right-to-erasure via `forget_identity`), payments (AP2 sign + verify, ERC-8004 (Jan 2026 revision) Trustless Agents Registry, MPP, x402, Stripe SPT), AI models & inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), cross-chain bridge, verification (ZK, VRF, attestations), staking & providers, tokens & contracts, NFTs, agents (spawning, swarms, marketplace), tasks (marketplace, quotes, completion), skills, tools, compliance & KYC, TEE, and event subscriptions. Representative samples:

| Group | Example Tools |
|-------|---------------|
| Wallet & Ledger | `get_balance` |
| Network & Blocks | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did` |
| Payments | `create_payment_challenge`, `verify_payment` |
| AI Models & Inference | `list_models`, `list_model_endpoints` |
| Verification | `verify_zk_proof`, `verify_vrf_proof` |
| Stakes & Providers | `get_role_stakes`, `get_provider_stats` |
| Tokens & Contracts | `deploy_contract` |

All tool parameter schemas are generated via `schemars::JsonSchema` for automatic schema discovery by MCP clients. Tools delegate to the node's subsystems (`Arc<TenzroNode>`, `Arc<WebState>`) for actual data access and transaction submission.

### 11.7 OpenClaw Skill Integration

An OpenClaw-compatible skill definition (`skills/openclaw-tenzro/SKILL.md`) allows OpenClaw agents to interact with the Tenzro blockchain. The skill provides structured instructions for:
- Connecting to Tenzro's JSON-RPC, Web API, MCP, and A2A endpoints
- Creating wallets and checking balances
- Sending transactions
- Registering and resolving identities
- Verifying proofs and checking node status

### 11.8 Agent Templates

Agent Templates are reusable, versioned blueprints for spawning autonomous agents without writing code. Reference templates cover common agentic patterns:

| Template | Type | Description |
|----------|------|-------------|
| Multi-Chain Portfolio Manager | Coordinator | Orchestrates portfolio rebalancing across multiple chains and DeFi protocols |
| Intelligent Payment Router | Specialist | Selects optimal payment protocol and routing path based on cost, speed, and chain availability |
| Cross-Chain Liquidity Aggregator | Custom | Autonomously sources and aggregates liquidity across bridge adapters and DEXs |
| Autonomous RWA Custodian | Custom | Manages real-world asset tokenization lifecycle with TEE-backed custody and compliance |
| Agentic Inference Marketplace | Coordinator | Discovers, benchmarks, and routes inference requests to optimal providers on behalf of other agents |
| Bridge Arbitrage Scanner | Specialist | Monitors price differentials across bridges and executes arbitrage trades |
| MPP Payment Agent | Specialist | Handles MPP-protocol payment sessions for streaming and recurring charges |
| Model Inference Proxy | Worker | Routes inference requests to optimal model providers with fallback |
| Yield Rebalancer | Specialist | Rebalances yield positions across DeFi protocols based on APY and risk |
| Premium Alpha Advisor | Specialist | Provides premium analytics and trading signals to subscribers |
| Timeseries Forecaster | Worker | Forecast inference using TimesFM 2.5 |
| Audio Transcriber | Worker | Transcribes audio using Whisper, Distil-Whisper, Moonshine, Parakeet, Canary |
| Video Analyst | Worker | Analyzes video content with frame-level embeddings and multi-modal reasoning |
| Vision Indexer | Worker | Indexes image collections with CLIP, SigLIP2, DINOv3 embeddings |

Templates support six types: Assistant, Specialist, Worker, Coordinator, Validator, and Custom. Each template includes a unique `template_id`, version, creator DID, declared capabilities, runtime requirements, pricing model, and discovery examples.

### 11.8a Pre-approved Bounds and Credentials

- **Pre-approved bounds.** Terms may carry `auto_approve`, bounds the controller pre-approved for the agent's scope. A proposed scope stays within them when every limit is at or below the bound's, every list is within the bound's list, and every term the bounds do not name is no looser than in the current terms (`within_bounds`). Changing the terms on chain still takes the root's approval.
- **Organizations of agents** (members, roles, scope change requests and extra refusal rules) are not consensus state. They live in a harness over delegation terms: the harness decides who may ask for what, and every change it makes still lands as terms the agent's root approved.
- **Brokered credentials.** Terms may carry third-party secrets sealed by the controller to each serving node's hardware sealing key, each for one HTTPS host and header. The node's egress path opens the envelope with a key derived from its hardware for that one request and attaches the header; the agent never holds the secret, cannot set that header itself, and every attachment is in its audit trail.

### 11.8b Owned, Funded Agents

Every agent has an owner: a person (passkey) or an autonomous machine (TPM). Its identity and wallet hang off the owner's, so every action it takes is auditable through that lineage. The owner funds the agent's wallet, and the budget is the funding: a task can never spend more than was put in. Per-payment approval is optional and lives in the harness or wallet, not the protocol. The protocol controls the owner (the agent's controller) holds:

| Transaction | Effect |
|---|---|
| `PauseAgent` | The agent pays nothing while paused; inbound payments still arrive. A pause also suspends refills. |
| `ReclaimAgentFunds` | Moves the agent wallet's TNZO back to the controller: all of it, or a set amount. Works whatever the agent's state. |
| `SetAgentTopUp` | Allows refills from the controller's wallet within an allowance: the most moved per period, the period, the balance a refill brings the wallet up to, and an expiry; `None` cancels it. The expiry must fall within the governed `agent.topup_max_days` (90 at genesis). |
| `TopUpAgent` | Performs one refill within the allowance. Anyone may send it. |

Unusual-spending alerts, per-action approval prompts and anomaly detection are harness and wallet features built on the chain's signals (per-agent spend counters, Terms, an event per action).

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

Every identity receives an auto-provisioned permissionless wallet (its classical key held in the identity's own hardware — passkey for humans, TPM 2.0 / Secure Enclave for machines), a set of verifiable credentials, and W3C DID Document representation.

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
    wallet_address: Address,             // Auto-provisioned permissionless wallet
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

1. **Revoke** — Submit a signed `RevokeIdentity` transaction carrying the root's approval with `tenzro_revokeIdentity` (any account may send it). Once it lands every node marks the identity `Revoked` (cascading to the agents it delegated and the machines it controls), revokes the access tokens it issued to or through it, and dependent payment binders react (Stripe SPT `granted_token.deactivated`, AP2 mandate cache).
2. **Forget** — Once propagation has settled, call `tenzro_forgetIdentity { did }` to hard-delete the identity from `CF_IDENTITIES` and the in-memory `IdentityRegistry`. The DID must already be in `Revoked` status; calling forget on an `Active` identity returns an error.

Forget is irreversible. The DID becomes unresolvable on this node; bound credentials and delegation scopes are dropped. Audit-trail receipts that referenced the DID remain — only the live identity record is erased. CLI: `tenzro identity forget <did>`. MCP tool: `forget_identity`.

---

## 13. Payment Protocols

### 13.1 Overview

Tenzro supports agentic payment protocols whose value the chain settles. Card networks settle their own value through adapters in harnesses, using the agent identity, delegation enforcement and mandate audit trail the node serves. All protocols use the HTTP 402 Payment Required flow: a server issues a payment challenge, a client creates a payment credential, and the server verifies and settles.

The `tenzro-payments` crate implements all five with a unified `PaymentProtocol` trait and a `PaymentGateway` that routes across them.

### 13.2 Supported Protocols

#### Crypto rails — Tenzro settles the value

| Protocol | Origin | Use Case |
|----------|--------|----------|
| **ERC-8004** (Trustless Agents Registry) | Ethereum | Identity / Reputation / Validation registry surfaces — see §13.9 |
| **MPP** (Machine Payments Protocol) | Stripe / Tempo | Session-based machine payments with HTTP 402 |
| **x402** | x402 Foundation | HTTP 402 payments (wire version 2): payer-signed Tenzro credentials settled on the ledger, or EIP-3009 / Permit2 on the payer's EVM chain |
| **Tempo** | Tempo Network | Stablecoin settlement via Tempo blockchain |
| **Direct** | Tenzro native | On-chain TNZO settlement |
| **Channel** | Tenzro native | On-chain escrow plus cumulative payer-signed vouchers (§9.4) |

#### Card networks

Card networks (Visa Trusted Agent Protocol, Mastercard Agent Pay) settle over the card network, not on chain. Their adapters run in harnesses over the public surface: they present an agent's DID, delegation scope and audit receipts, all of which the node already serves.

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

Mandates are signed with ECDSA P-256 on the signer's own device: by the principal's passkey (a WebAuthn assertion whose challenge is `base64url(SHA-256(preimage))`, proof `passkey`) or by a P-256 key in a TPM or Secure Enclave (ES256 over the preimage, proof `es256`). A CheckoutMandate's `cnf` claim (`jwk` EC P-256 or `did`) names the key the agent must sign the PaymentMandate with; a human-not-present CheckoutMandate must carry one.

Tenzro provides these RPC surfaces:

  1. `ap2_checkout_mandate` — the parent's `max_amount`, merchant/category/chain allow-lists, `cnf` key binding, and expiry.
  2. `agent_terms` — the agent's consensus Terms (scope, per-transaction and per-period limits, counterparties, protocols), read from chain state.
  3. `onchain_escrow` — when either mandate carries an `escrow_id`, the two must match and the escrow must cover the total.
  4. `stripe_spt_usage_limits` — when either mandate carries a `spt_grant_id`, the two must match and the granted token's remaining usage must admit the charge.

A validated pair settles over the existing settlement rail: `tenzro_settle { provider, customer, amount, ap2: { checkout_vdc, payment_vdc } }` accepts the pair in place of the customer's bearer credential when the pair validates with delegation enforcement, the principal's DID controls `customer`, the merchant's DID controls `provider`, and `amount` equals the PaymentMandate total. Each PaymentMandate settles once, and a CheckoutMandate settles at most `max_uses` times; a replayed PaymentMandate or an exhausted CheckoutMandate is refused.

### 13.5 MPP (Machine Payments Protocol)

MPP, co-authored by Stripe and Tempo, provides session-based HTTP 402 payments:

- **MppChallenge** — Issued by the server with amount, asset, recipient, and chain
- **MppCredential** — Created by the client, signed with the payer's wallet
- **MppReceipt** — Returned after settlement with transaction reference
- **MppSession** — Tracks ongoing payment relationships between payer and payee
- **MppSessionManager** — Thread-safe session lifecycle management
- **MppPaymentServer** — HTTP handler that issues 402 responses
- **MppClient** — Client-side credential creation and submission

### 13.6 x402

x402 carries HTTP 402 payments in three headers (wire version 2), each a
base64 JSON body:

- **`PAYMENT-REQUIRED`** on the 402: `{x402Version: 2, error?, resource {url,
  description?, mimeType?}, accepts [{scheme, network, amount, asset, payTo,
  maxTimeoutSeconds, extra}], extensions?}`. A Tenzro node offers the network
  `tenzro:<chain id>` and names the challenge in `extra.challengeId`.
- **`PAYMENT-SIGNATURE`** on the retried request: `{x402Version, resource?,
  accepted, payload, extensions?}`. Under the Tenzro schemes the payload is
  the payer-signed Tenzro credential; under `exact-eip3009` / `permit2` it is
  the EIP-3009 authorization and its signature.
- **`PAYMENT-RESPONSE`** on the paid response: `{success, errorReason?,
  payer?, transaction, network, amount}`. For a ledger payment
  `transaction` is the Tenzro transaction the node saw executed before it
  served the response; anyone checks it with `eth_getTransactionReceipt`.

Every priced surface (the payment middleware, static sites, functions,
machines, Open databases and files) accepts a payment as `PAYMENT-SIGNATURE`,
`Authorization: Payment <base64url>` or `Payment-Credential`, and settles it
only for the resource, payee, price and asset it serves. An EVM payload is
verified against the requirement rebuilt from the challenge, never against the
option the buyer echoed.

Types: `X402PaymentRequired`, `X402PaymentRequirement`, `X402PaymentPayload`,
`X402SettlementResponse`, `X402PaymentServer`,
`X402Client` (`tenzro-payments::x402`).

**Schemes.**

- **`tenzro-hybrid`** — the exact-amount Tenzro scheme: one payment of the challenge amount, authorized by the payer's Ed25519 + ML-DSA-65 signature over the canonical payment authorization.
- **`exact-eip3009`** / **`permit2`** — exact payments on the payer's EVM chain (see below). **`erc7710`** verifies a delegation redemption but has no settlement leg, so a node does not serve a resource against it.
- **`upto`** — usage-metered: the payer signs a ceiling and the seller charges the metered actual beneath it after serving. When the seller named a `meter_key` on the challenge, the charge must carry a `usage_record` that key signed (units, quantities and unit prices, bound to the challenge, the payer and the ceiling), so the charge is exactly what the seller's meter attests.
- **`batch-settlement`** — many small requests are paid with cumulative vouchers on an escrow the payer funded (§9.4) and claimed on-chain in one transaction, so per-call gas does not dominate a stream of micro-charges.

**Idempotency and signed offers.** The challenge id is the payment's replay key on every rail: the payer signs it, the VM settles it once, and a retried credential gets the first receipt back. A node with a signer signs the offer on each challenge (commitment over resource, scheme, network, amount, asset, payTo and challengeId, carried in `extra.offerCommitment` / `offerSig` / `offerSigner`).

**Settlement.** When the payment asset is native TNZO, settlement moves balance
on-chain through the payer-authorized `PayerSettle` path described in §9.6.
Stablecoins settle between Bridge custodial wallets when the operator
configured the Bridge rail. Payments under `exact-eip3009` / `permit2` settle on
the payer's own EVM chain.

**EIP-3009 / Permit2 facilitation.** With the `payments.x402_facilitator` block
(`evm_rpc_url`, `chain_id`, `settlement_facilitator_url`) the node verifies
EIP-3009 payloads itself against that RPC — network, recipient and amount
parity, the signed time window, EIP-712 signature recovery,
`authorizationState(from, nonce)`, `balanceOf(from)` and a
`transferWithAuthorization` `eth_call` simulation. A node holds no EVM key, so
the broadcast goes through the settlement facilitator the operator names, and
the node then confirms on its own RPC that the returned transaction executed
successfully against the token contract with exactly the verified calldata; a
facilitator that reports a transaction that did not happen is caught there.
Without the block the node offers no EIP-3009 or Permit2 scheme: there is no
hosted default, and a block whose relayer signer is unavailable, or that names
neither a relayer signer nor a settlement facilitator, stops the node from
starting.

**The node's x402 facilitator.** A node serves verification and
settlement for other resource servers under `/facilitator/x402`:
`POST /verify`, `POST /settle` and `GET /supported`, in x402 v2 shapes. It
holds no funds. Tenzro-scheme payments (`tenzro-hybrid`, `upto`,
`batch-settlement`, `dvp`, `proven`, `plan`) end in consensus state; a payer
that names a DID is bound to the key that signed and held to its Terms, the
same check the node's own 402 gates make; EVM schemes go through the
scheme registry above. A2A tasks settle through the facilitator the
operator names in `payments.facilitator_url`, or through this one when none
is named. Travel Rule exchanges a VASP needs above its thresholds run
outside the node.

### 13.7 Stripe SPT (SharedPaymentToken)

Stripe's SharedPaymentToken (SPT) is the token primitive that pairs with the MPP wire and Tempo settlement layers (the three layers of the Stripe agentic stack). Tenzro participates as a token issuer with TDIP-anchored cap enforcement:

- **Token lifecycle** — `StripeClient::create_issued_token` mints an issued token bound to a principal/agent DID pair with usage caps; `retrieve_granted_token` reads back the granted token Stripe returns to the agent; `confirm_intent_with_spt` confirms a Payment Intent against that granted token; `revoke_issued_token` tears it down. These live in `crates/tenzro-payments/src/mpp/stripe_spt.rs`.
- **Ceilings** — a payment confirmed against an SPT must satisfy the agent's consensus Terms, the SPT's own `usage_limits`, and — when the payment is carried by an AP2 mandate — the mandate's `total_amount`. The node-side `SptCeilingResolver` resolves `granted_token_id → SptCeilingSnapshot` for the check.

### 13.8 Identity-Bound Payments

Payments are bound to TDIP identities through the `identity_binding` module. When a machine identity makes a payment, its delegation scope is enforced:

- Transaction value checked against `max_transaction_value`
- Payment protocol checked against `allowed_payment_protocols`
- Target chain checked against `allowed_chains`
- Daily spend accumulated and checked against `max_daily_spend`

### 13.9 ERC-8004 Trustless Agents Registry

ERC-8004 (Jan 2026 revision) defines three on-chain registries (Identity, Reputation, Validation) for discovering and trusting agents across heterogeneous principal chains. Tenzro implements byte-identical selectors so the same calldata works against either the native Tenzro registry (precompiles `0x101a` / `0x101b` / `0x101c`) or the Ethereum mirror. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — it is server-allocated, never derivable client-side. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation for cross-system lookup.

Calldata for the three registries is built client-side from the published selectors; the node serves no encoding RPCs.

### 13.10 HTTP Middleware

The `tenzro-payments` crate provides axum middleware for automatic payment handling:
- Servers wrap their routes with payment middleware to auto-issue 402 challenges
- Clients use payment-aware HTTP clients that auto-create credentials

### 13.11 Feature Flags

| Flag | Default | Description |
|------|---------|-------------|
| `mpp` | Enabled | Machine Payments Protocol support |
| `x402` | Enabled | Coinbase x402 protocol support |
| `ap2` | Enabled | AP2 v0.2 sign + verify + validate-pair |
| `stripe-spt` | Enabled | Stripe SharedPaymentToken issuance + verify + cap-check |
| `erc8004` | Enabled | ERC-8004 (Jan 2026 revision) Trustless Agents Registry encode/decode |

---

## 14. Cross-Chain Bridge

### 14.1 Overview

TNZO moves between Tenzro and external chains over one path: governed routes
in the route framework (`tenzro_bridge::route`). A route joins Tenzro to one
external chain over one transport.

| Transport | Chain family | Chains |
|-----------|--------------|--------|
| `ccip` | EVM | Ethereum, Base, Arbitrum, Optimism, BNB Chain, Avalanche C-Chain, Polygon PoS (CCIP-compatible envelope) |
| `ccip` | Solana | Solana (CCIP-compatible envelope) |
| `ibc` | Cosmos | CometBFT chains (ICS-20 packets; Tendermint light client, ICS-23 proofs) |
| `deposit` | Bitcoin | Bitcoin (deposits to a governed script; SPV header-chain client; inbound only) |
| `contract` | Sui, Aptos, Stellar | Tenzro's bridge contract (checkpoint, ledger-info and SCP light clients) |
| `contract` | TON | Tenzro's bridge contract (committee only, committee-only mint limits) |

### 14.2 Rules

Every route is installed by governance and every rule is enforced by the
framework: strict canonical decoding; committee (and on CCIP routes, an
independent blessing committee) signatures over a digest binding this chain's
id, the route, a nonce and an expiry; light-client proofs where a route
requires one; a circuit breaker; per-transfer and per-epoch caps; and the
supply invariant, by which the representation outstanding on the external
chain never exceeds the TNZO locked on Tenzro for the route.

### 14.3 Interfaces

| RPC | Purpose |
|-----|---------|
| `tenzro_listBridgeRoutes` / `tenzro_getBridgeRoute` | Routes with caps, epoch usage, supply, mode, placeholders and why a route cannot open |
| `tenzro_getBridgeOutbound` | An outbound record by sequence; for a Bitcoin route, the withdrawal and its per-input digests |
| `Bridge` outbound transaction | Holder-signed transfer out; locks TNZO in the route vault and queues the outbound message |
| `Bridge` inbound transaction | Committee-attested delivery in, signed and paid for by its relayer; credits the recipient |
| `tenzro_getBridgeCircuit` | Records that disable or pause a route |

Attested data messages (agent account reports inbound, settlement mirrors
outbound) use the same envelope and rules and move no TNZO.

## 15. Self-Custody, Wallets, and Key Management

Tenzro is a self-custodial network across all three identity classes — humans, delegated agents, and autonomous machines. No node, validator, or service provider holds the cryptographic material required to authorize a transaction on a user's behalf. Custody is rooted in hardware-backed keys on the user's own device (passkey in Secure Enclave / StrongBox / TPM 2.0 / Windows Hello) for humans, and in a TEE-sealed key for autonomous machines (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA H100 CC). The classical signing key never leaves the holder's hardware; no party — including the node — ever holds it.

This section specifies the full surface: design principles, the five interlocking pillars (P-256 / WebAuthn, ERC-7579 modular validators, ERC-7484 module registry, ERC-7702 sponsored bootstrap, TEE-resident agent keys), hybrid post-quantum behavior across each, and the developer experience — both the opinionated "passkey wallet in three lines" SDK and the lower-level `Signer` / `Validator` traits that custom wallet developers extend to build their own designs.

### 15.0 Design Principles

**1. Self-custody by default, on every identity class.** A human's wallet, a delegated agent's session key, and an autonomous machine's bootstrap key all derive from material that the user, controller, or TEE — not the node — exclusively holds. Server-custodial flows are not a supported configuration.

**2. Hardware-backed keys, never software keys, never seed phrases.** The default key for a human is a passkey in the platform authenticator (Apple Secure Enclave, Android StrongBox, Microsoft Pluton / Windows Hello, TPM 2.0). The default key for an autonomous machine is generated and sealed inside a remote-attestable TEE. Mnemonic seed phrases are not part of the recovery surface — recovery is performed through a guardian set on a smart account.

**3. Authority is consensus state the model cannot influence.** A delegated agent's every spending or operational ceiling (cap, scope, expiry, allowed counterparty, allowed payment protocol) is its consensus Terms, approved by its root's passkey or hardware key and checked by the VM on every `AgentAct` and by every payment entry point over the same chain state. No node keeps a second authority store, so a malicious node operator cannot widen an agent's authority.

**4. Two parallel developer paths.** The SDK exposes both a fully opinionated high-level surface (passkey wallet, three lines, biometric-gated, automatic cross-device fallback) and a fully unopinionated low-level surface (the `Signer` / `Validator` traits) that custom wallet developers extend to build their own key-management designs (custom HSM integration, hardware wallets, air-gapped flows, social-recovery topologies). The high-level API is a default implementation of the trait surface — there is no escape hatch and no internal-only API.

**5. Force biometric-capable authenticator, fall back to phone via QR.** The default UX rejects software-only authenticators. If the current device lacks a platform authenticator (`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable() === false`), the SDK MUST default to the FIDO **hybrid transport** (caBLE — QR + Bluetooth proximity) so that the desktop solicits the signature from the user's phone passkey without ever holding the key. This mirrors the pattern that converged across Coinbase Smart Wallet, Privy, and Daimo.

**6. Hybrid post-quantum at every layer that the standards permit.** Classical primitives are paired with their NIST FIPS 203/204 post-quantum companions: Ed25519 with ML-DSA-65 for signatures, X25519 with ML-KEM-768 for KEM. Where a standard is single-algorithm (P-256 inside a passkey, secp256k1 inside an EVM EOA), the classical algorithm is used as specified and the PQ companion lives in the on-chain validator metadata rather than in the device key — there is no production threshold ML-DSA in 2026, so threshold-PQ is deferred to a single-key-in-TEE design until the research matures.

**7. One custody model, no fallbacks.** The wallet surface has exactly one custody mode: self-custodial. There is no server-custodial configuration, no reconstruct-on-the-node key assembly, and no alternate provisioning path an operator can select.

### 15.1 Identity Classes and Custody Targets

| Class | Signing key | Storage | On-chain validator | Recovery | Bootstrap |
|---|---|---|---|---|---|
| **Delegated agent** | Ed25519 (Tenzro-native) or P-256 (Coinbase-class) **session key** bound to the controller's primary identity | Same hardware-backed storage as the controller, scoped sub-credential | `DelegationScopeValidator` ERC-7579 module that consumes the TDIP `DelegationScope` on-chain — any `UserOp` outside scope returns ≠ magic value, so no signature is ever valid out-of-scope | Inherits the controller's recovery; revocation via per-DID monotonic epoch counter that invalidates all outstanding session keys | Controller spawns the agent and signs the delegation; agent receives a session key with cryptographically-bounded authority |
| **Autonomous machine** | P-256 generated **inside the TPM 2.0 or Secure Enclave** of the machine; the machine DID is derived from that key | The TPM or Secure Enclave; the private half is never exported. A TEE is an execution environment, not a key store | Identity-key validator installed behind the `DelegationScopeValidator`, verifying the machine's own key on every `UserOp` | Re-register under a new hardware key; `AgentBond` stake + insurance pool back accountability | Funded by its controller or counterparty like any other account; there is no sponsored bootstrap |

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
| `Ed25519Validator` | Verifies a native Ed25519 signature against a registered public key. Used for the classical leg of hybrid signatures and for direct Ed25519 session keys. | Human, Delegated agent |
| `DelegationScopeValidator` | Consumes the TDIP `DelegationScope` and rejects any `UserOp` outside the cap / scope / time / counterparty / payment-protocol envelope **before** signature verification. Backed by a per-DID monotonic epoch counter for revocation. | Delegated agent |
| Identity-key validator | Verifies the `UserOp` signature against the public key of the TDIP identity that owns the account. | Autonomous machine |

Multiple validator modules can be installed side-by-side; the calldata of `userOp.signature` selects which validator runs (the first 4 bytes of the signature payload encode the validator selector, mirroring Rhinestone Nexus and Kernel v3 conventions).

### 15.4 Pillar 3 — ERC-7484 Module Registry

Validator modules — particularly third-party modules contributed by wallet developers — are looked up against the [ERC-7484](https://eips.ethereum.org/EIPS/eip-7484) module registry, deployed as a singleton at the same address across all chains:

```
0x000000000069E2a187AEFFb852bF3cCdC95151B2
```

Tenzro mirrors this registry as a privileged-VM precompile so that a smart account can verify a module's attestation status without an out-of-VM call. Account installation flows reject modules without an attestation from a configured attester set (default: the account owner's chosen attesters; the network does not impose a global allowlist).

### 15.5 Pillar 4 — ERC-7702 Sponsored Bootstrap

Tenzro implements [ERC-7702](https://eips.ethereum.org/EIPS/eip-7702) (live on Ethereum since the Pectra activation in May 2025) so an EOA can delegate its code to a smart account:

| Property | Value |
|---|---|
| Transaction type | `0x04` |
| Authorization tuple | `[chain_id, address, nonce, y_parity, r, s]` |
| `chain_id == 0` | Permitted (per spec) for universal authorization across Tenzro's chains |
| Code slot value | `0xef0100 ‖ delegate_addr` (3-byte magic prefix `0xef0100`) |

The 7702-delegated EOA points at a TenzroSmartAccount, so the account is a smart account from its first action onward. Gas is paid by the account or by a paymaster the account holder chooses; the network runs no attestation-gated sponsorship.

### 15.6 Pillar 5 — Hardware-Held Machine Keys

For autonomous machines, the signing key is created inside the machine's TPM 2.0 or Secure Enclave and never leaves it. The machine DID is derived from the attestation key, so a machine cannot claim a DID another key owns. TPM evidence (an AK quote over a node-issued nonce, activated against the EK) and TEE reports are reputation signals; neither is required to register, and neither holds a key.

Bootstrap ties to ERC-8004: the agent registers in the IdentityRegistry at `0x8004A169FB4a3325136EB29fA0ceB6D2e539a432` (live mainnet 2026-01-29) — note that ERC-8004 assigns a sequential ERC-721 `tokenId` at registration, **not** a `keccak256` of the DID string. Tenzro's native ERC-8004 precompiles (`0x101a` / `0x101b` / `0x101c`) mirror this semantics so cross-registry calldata interop holds.


### 15.8 Hybrid Post-Quantum Behavior

| Layer | Classical | PQ companion | Notes |
|---|---|---|---|
| Native ledger transaction signing | P-256 (hardware) | ML-DSA-65 (FIPS 204), mandatory | Both signatures are attached and the verifier requires both, against the key the account enrolled. An account with no key enrolled is refused until its enrolment transaction, which is verified against the key it enrols. Transactions in an external standard (EVM secp256k1) are verified by that standard and stay classical. |
| Passkey / WebAuthn | P-256 | (none on device) | Single-curve by spec. PQ companion lives in the on-chain validator metadata rather than the platform authenticator. |
| TLS / RPC transport | X25519 | ML-KEM-768 (FIPS 203) | X25519MLKEM768 offered first for RPC, MCP and A2A, with X25519 alone as the fallback. Certificates (WebPKI) are classical. |
| Node-to-node transport (iroh QUIC) | X25519 | ML-KEM-768 | Endpoints offer and accept only X25519MLKEM768: a peer offering a classical share alone, on a fresh or a resumed session, is refused, and a classical hint in a session store cannot make a node send one. Relay HTTPS, relay records and address lookup keep X25519 as a fallback for TLS terminators without the hybrid. |
| Endpoint authentication | Ed25519 (iroh TLS) | ML-DSA-65, mandatory: the machine's hardware ML-DSA key, bound to the endpoint record | On a connection each side signs the connection's TLS exporter with both hardware keys of its machine (P-256 and the ML-DSA-65 key its record binds), so a party relaying a forged Ed25519 handshake cannot pass the proofs on. A peer whose record carries no verified binding, or that has no hardware keys to prove with, is refused in both directions, and the A2A, MCP and MoE protocols are served only on their versioned ALPNs. Pins of each identity's hardware ML-DSA key are kept across restarts; a later record without the binding, or bound by another key, is refused. Block sync, state sync, gossip and blobs authenticate the endpoint by Ed25519 under the hybrid key exchange (see docs/PQ-AND-AI-SAFETY.md). |
| Validator consensus keys | ECDSA P-256 or P-384 | ML-DSA-65 or ML-DSA-87 | Composite `COMPSIG-MLDSA65-ECDSA-P256` (the default) or `COMPSIG-MLDSA87-ECDSA-P384`, both held in the TPM, selected by `consensus_key_scheme` in the node config. A registered validator rotates to the configured scheme on chain and signs with the new key from the epoch boundary that seats it, without a restart. |
| Validator machine identity | P-256 | ML-DSA-87 | A validator whose consensus key does not name its machine (ML-DSA-87 / P-384) registers its machine identity on chain, signed by both machine keys, so peers hold its endpoint records to the machine's ML-DSA key from the first record. Behind `staking.validator_machine_identity.status`. |
| Stored records (receipts, billing, SLA answers, availability attestations, tool-call records) | Ed25519 session signature | ML-DSA-65 session signature | Signed with session keys the hardware identity certifies. From `session.hybrid_records_from_ms` (governed; the highest value means never) a record without the hybrid signature is refused. Certificate checks are cached. |
| Randomness beacon | Ed25519 VRF | Hash commit-reveal of hardware-derived secrets | Once governance enables `beacon.commit_reveal.status`, each contribution commits to the validator's next 32-byte secret and reveals the last one, and the mix takes the revealed secret beside the VRF output, so the beacon stays unpredictable while the hash holds even if the VRF does not. The secrets derive from the hardware root, so nothing is stored. |
| Vouchers for channels on other chains | P-256 | WOTS+ one-time keys (SHA-256, Winternitz 16) under a Merkle root the channel commits to | Each voucher spends one leaf; verifying one costs about 600 SHA-256 evaluations and no elliptic-curve arithmetic. Keys derive from the hardware root, and the count of spent keys is flushed before a signature leaves the node, so no key signs twice. |
| Private model key release | X25519 | ML-KEM-768 | A model's content key is sealed to a key the attested environment made in memory for one release (`x25519-mlkem768-hkdf-sha256-aes-256-gcm`); reading it needs both exchanges broken. See [AI.md](AI.md#51-private-weights-attestation-bound-key-release). |
| Key wraps at rest (model content keys, the provider's content key held for its hardware, node credentials, session continuity, brokered agent credentials) | X25519 | ML-KEM-768 | Envelope version 2: the data key is sealed to a hybrid X25519 + ML-KEM-768 key derived on demand from the machine's hardware root (the two halves under separate derivations), by HKDF-SHA256 over both shared secrets, salted with a transcript of the recipient key, the sender's X25519 share and the ML-KEM-768 ciphertext, under a per-use context. A changed part of the envelope, or an exchange broken alone, does not open it. |

### 15.9 Recovery and Revocation

Recovery is performed at the smart-account layer, not by reconstructing key material:

- **Human accounts** install a `SocialRecovery` ERC-7579 module backed by a k-of-n quorum. Each member is an independent hardware-rooted key: a passkey (WebAuthn P-256 plus its ML-DSA-65 companion), a hardware wallet (secp256k1), or an Ed25519 + ML-DSA-65 composite key derived on demand from a member's hardware. Each member signs with its own device; no key is split, shared or dealt, and one key cannot hold two seats. The same module is the multi-party approval for any operation, not only recovery.
- **Delegated agent accounts** inherit recovery from the controller. Revocation is instant: the controller increments a per-DID monotonic epoch counter, and the `DelegationScopeValidator` rejects any session-key signature that does not match the current epoch.
- **Autonomous machine accounts** rotate by registering a new hardware key; the delegation scope that authorises the machine expires after 30 days unless renewed.

Identity revocation is a consensus transaction: a `RevokeIdentity` carrying the root's approval, re-verified by every validator and mirrored into every node's registry through `IdentityRegistry::revoke_from_chain()` (see §12).

### 15.10 Developer Experience

The SDK exposes two parallel surfaces. **Both are public and supported.** The high-level surface is a default implementation built on top of the trait surface — there is no internal-only API.

#### 15.10.1 High-Level: Passkey Wallet in Three Lines

```ts
import { createPasskeyWallet, signWithPasskey } from "@tenzro/sdk";

const wallet = await createPasskeyWallet({ rpId: "tenzro.com" });
const sig = await signWithPasskey(wallet, userOp);
```

```rust
use tenzro_sdk::passkey::{PasskeyWallet, PasskeyConfig};

let wallet = PasskeyWallet::create(PasskeyConfig::production("tenzro.com")).await?;
let sig = wallet.sign_user_op(user_op).await?;
```

UX behavior the SDK enforces by default:

1. Calls `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`. If `false`, the SDK **must** request a cross-platform authenticator (`authenticatorAttachment: "cross-platform"`, `userVerification: "required"`) and render a QR for the FIDO hybrid transport (caBLE). It never silently falls back to a software key.
2. The WebAuthn ceremony is hosted on `wallet.tenzro.com` with RP ID `tenzro.com`, a stable registrable domain that survives URL redesigns and works across every Tenzro frontend.
3. The resulting P-256 public key is registered as the account's `WebAuthnValidator` module on first use (one transaction).
4. Signing always raises a biometric prompt on the device that holds the passkey — Touch ID, Face ID, Windows Hello, Android biometric.

#### 15.10.2 Low-Level: Pluggable Trait Surface

Custom wallet developers extend the following traits to build their own designs (custom HSM integration, hardware wallets, air-gapped flows, social-recovery topologies):

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

pub enum SignerKind {
    WebAuthn { credential_id: Vec<u8> },
    Ed25519,
    Tee { backend: TeeBackend },
    Hsm { vendor: String },
    Custom(String),
}
```

The TypeScript SDK exposes a parallel surface (`Signer`, `Validator`) so JS/TS wallets get the same extension points. Where a key lives is the signer's own concern (the hardware signer holds it in the TPM or Secure Enclave, a passkey in its authenticator), and social recovery runs through the passkey custody RPCs.

#### 15.10.3 Reference Compositions

The cookbook contains ready-made compositions covering the common topologies, each implementing the same traits:

| Composition | `Signer` | Where the key lives | `Validator` |
|---|---|---|---|
| `passkey-only` | WebAuthn | Platform authenticator | `WebAuthnValidator` |
| `passkey + tee` | WebAuthn + TEE-held Ed25519, both required | Platform authenticator + TEE | `WebAuthnValidator` + `Ed25519Validator` (both must approve) |
| `hardware-agent` | P-256 held in the machine's TPM 2.0 or Secure Enclave | TPM or Secure Enclave | Identity-key validator |
| `delegated-session` | Ed25519 (session key) | Inherited from controller's storage | `DelegationScopeValidator` |
| `air-gapped` | Custom (off-machine signer) | None (key never on this host) | `Ed25519Validator` |

#### 15.10.4 Tauri Desktop Integration

The desktop application stores keys in the OS keychain via Rust-side commands — the Tauri WebView does **not** reliably reach the platform authenticator, so all WebAuthn ceremonies are dispatched from Rust:

| Platform | Backend | Hardware key location |
|---|---|---|
| macOS | `security-framework` with `kSecAttrTokenIDSecureEnclave` | Secure Enclave (T2 / Apple Silicon) |
| iOS | `security-framework` + LAContext biometric prompt | Secure Enclave |
| Android | JNI to `android.security.keystore.KeyGenParameterSpec` with `setIsStrongBoxBacked(true)` | StrongBox |
| Windows | TPM 2.0 commands over TPM Base Services; keys read from the persistent handles `tenzro-node tpm provision` makes, EK from 0x81010020 | Pluton / TPM 2.0 |
| Linux | TPM 2.0 commands over `/dev/tpmrm0`; the same persistent handles; no software fallback | TPM 2.0 |

WebAuthn ceremonies use [`webauthn-authenticator-rs`](https://crates.io/crates/webauthn-authenticator-rs); cross-device flows use the FIDO hybrid transport via the same crate's caBLE module. Tauri commands exposed: `device_create_passkey`, `device_sign_with_passkey`, `device_attest_key`, `device_start_cross_device_link`.

### 15.11 Onboarding

Tenzro provides a single onboarding flow that provisions a TDIP identity, a self-custodial smart account, and a hardware profile in one atomic operation.

**One-Click Participation.** Provisions all three components:

1. The client device runs a WebAuthn passkey ceremony (for a human) or creates a P-256 key inside its TPM 2.0 or Secure Enclave (for a machine). The private key material never leaves the device.
2. A TDIP DID is created (`did:tenzro:human:{uuid}`) and registered in the `IdentityRegistry`.
3. The identity is persisted to RocksDB (`CF_IDENTITIES`).
4. A TenzroSmartAccount is deployed via the AccountFactory (deterministic CREATE2 address) with the appropriate validator module installed (`WebAuthnValidator` for passkey, the identity-key validator for a machine).
5. The host machine's hardware profile (CPU, RAM, GPU, TEE availability) is detected and attached to the identity metadata.

The response returns the DID, smart-account address, installed validator modules, and hardware profile.

**Hardware Profile Detection.**

| Detected Property | Use |
|---|---|
| CPU model, cores, threads | Compute capacity for inference workloads |
| Total RAM | Memory-bound model support |
| GPU name, VRAM, architecture | GPU-accelerated inference and proving eligibility |
| TEE availability | TEE attestation as a validator reputation signal (it does not change the leader draw) |
| Platform authenticator | Determines whether the client can host a passkey locally or must use cross-device QR (FIDO hybrid transport) |

**Client Interfaces.**

- **CLI:** `tenzro join --name "Alice"` (interactive passkey ceremony) or `tenzro wallet import 0x... --key-type ed25519` (import existing key as initial validator)
- **Desktop App:** Setup page on first launch with two composition tabs — "Passkey on this device" (default) and "Import existing key"

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

The networking layer is built on iroh with the following protocols:

| Protocol | Purpose |
|----------|---------|
| Gossip (iroh-gossip, ALPN `tenzro/gossip` on the node's iroh endpoint) | Topic broadcast for blocks, transactions, certificates and announcements; each message is checked before it is passed on, and neighbours are scored on what they deliver |
| Identity endpoint records | Each machine signs the record naming its iroh endpoint and relays; knowing one Tenzro node is enough to learn the rest |
| Relays | Reach a node that cannot be dialed directly, admitted by their operators' signed records |
| Point-to-point ALPNs | Consensus, block sync, state sync, inference and other request/response protocols, each on its own ALPN |
| QUIC + TLS 1.3 (X25519MLKEM768) | Transport encryption and stream multiplexing |

### 16.2 Gossip Topics

| Topic | Content |
|-------|---------|
| `tenzro/blocks` | Block propagation |
| `tenzro/transactions` | Transaction propagation |
| `tenzro/certificates` | Checkpoint certificates, for followers (validators exchange consensus messages over the iroh ALPN `tenzro/consensus`, not gossip) |
| `tenzro/models` | Model registry updates |
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

Gossip messages are deduplicated using a time-bounded set of recently seen content hashes, preventing amplification attacks where the same message is propagated multiple times.

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
| `CF_METADATA` | Chain metadata (latest height), snapshot index, state-sync progress |
| `CF_SETTLEMENTS` | Settlement receipts and escrow state |
| `CF_CHANNELS` | Micropayment channel state |
| `CF_CHALLENGES` | Payment challenges (MPP/x402) + TOPLOC inference commitments and challenge records |

### 17.2 State Trie

The single state commitment is the unified binary state trie (17.3). It gives:
- **One root per height** over every committed column family, stamped into block headers (lagged by `STATE_ROOT_LAG`).
- **Inclusion and absence proofs** (`StateTrie::prove`, `verify_state_proof`) for light clients.
- **Incremental updates**: only the stems a block touches are rewritten; old versions stay provable until pruned.

### 17.3 Committed State and Snapshots

The state root in every block header is the root of a unified binary state trie (`tenzro_storage::StateTrie`) over every consensus-relevant column family (`COMMITTED_CFS`) plus the `epoch` and `validator_registry` namespaces. Keys are `SHA-256(namespace || key)` split into a 31-byte stem and a 1-byte slot; each stem's 256 slots hash to a stem commitment and stems form a binary tree with single-stem subtrees collapsed. Only the writes block execution makes are committed, captured by task- and thread-scoped hooks in the key-value store, so node-local writers cannot move the root. The trie is versioned by height: `root_at(h)` and `prove(h, namespace, key)` answer for any retained height, and `tenzro_getStateProof { namespace, key, height? }` returns a proof a light client checks with `verify_state_proof` against a certified header's state root (the header at `h + STATE_ROOT_LAG` commits the root of `h`).

Snapshots cut the trie at an epoch-start height into 4,096 buckets; each non-empty bucket is a BLAKE3 blob and the manifest lists every bucket's summary and blob hash plus the anchor chain. They are served over iroh and verified as described in 3.7a. Producer policy: `[snapshot] enabled`, `interval_blocks` (default 100,000), `retain_count` (default 2).

### 17.3a Data-Availability Retention

Every object a committee member certifies in the data-availability layer is recorded in consensus state (`DaRetention { Record { commitment, class, size_bytes } }`, from a bonded validator) with its class and an expiry fixed at the block time it is recorded: block-history segments are kept `storage.da_history_retention_seconds`, agent audit and telemetry `storage.audit_retention_seconds`, and neither may be governed below 183 days. Objects are bucketed by expiry day; at the start of every block, execution expires the objects of each bucket whose day has passed (at most 256 a block, continuing in the next), and every committee member then drops the slivers and certificate it holds. Only live objects count as stored. `tenzro_getDaObject` and `tenzro_getDaRetention` read the registry.

### 17.3b Event Indexes and Completeness

A block's event root commits, beside its events, the block's index: for every key a filter selects by (event kind, emitting contract, each topic at its position) one entry lists every event under the key and names the next key, starting from an empty key. One entry therefore proves either the full set of events under a key or that the block has none. A read with `completeness` carries, for every block it covered, the entries of its filter's keys with their paths and the block headers under certified checkpoints, plus proofs of the candidate events the filter rejects: the reader checks that nothing the filter selects was left out.

### 17.4 Write Durability

Finalized blocks are written with `sync_writes: true`, ensuring data is flushed to persistent storage before acknowledgment. This prevents state corruption on power loss.

### 17.5 Storage Constants

| Parameter | Value |
|-----------|-------|
| Block cache size | 1 GB |
| Write buffer size | 256 MB |
| Snapshot retention | 2 (`[snapshot] retain_count`) |
| Bloom filter bits | 10 per key |

---

## 18. Governance

Governance is stake-weighted voting on proposals that carry one typed action.
The network parameters, the proposal actions, the tracks and the guardian
brakes are described in `docs/GOVERNANCE_PARAMS.md`; this section states the
shape.

### 18.1 Proposals and Actions

A bonded account holding at least `governance.proposal_threshold_bps` of all
bonded stake can open a proposal. A proposal carries one `ProposalAction`.
The node accepts 32 actions in three domains: `network` (reversible by another
vote), `treasury` (moves value) and `sanction` (takes something from a named
party). They include `parameter_change`, `policy_update`, treasury grants and
sponsorship, bridge routes, guardian seats, `revoke_identity` and
`reinstate_validator`. The full table, with each action's domain, is in
`docs/GOVERNANCE_PARAMS.md`. Agents originate nothing unless a vote has moved
`governance.agent_phase` off 0.

### 18.2 Voting Rules

Every voting rule is itself a governed parameter (`governance.*`); the values
below are the genesis values.

| Rule | Genesis value |
|------|---------------|
| Quorum (`governance.quorum_bps`) | 3,334 bps of all bonded stake |
| Standard threshold (`governance.threshold_bps`) | 6,667 bps of participating stake |
| Expedited and security-fix threshold | 8,000 bps |
| Large spend (from 100,000 TNZO) | 7,500 bps of all eligible stake and a 14-day timelock |
| Voting period | 3 days; timelock 2 days |
| Minimum bond age to weigh in a vote | 7 days |

A proposal keeps the rules it opened under. A parameter change that only pauses
a feature runs on the expedited track.

### 18.3 Delegation

Token holders can delegate their voting power to another address. Delegation is
per-address; delegated power is added to the delegate's effective voting power,
delegations can be revoked at any time, and active delegations are checked at
vote time.

### 18.4 Execution and Brakes

A passed proposal waits out its timelock and is then executed; the engine
refuses a second execution. A parameter change is scheduled and applies at the
start of the next epoch, after a further grace window when it tightens a rule
(`governance.tightening_grace_epochs`).

Seated guardians (humans, `set_guardian`) can veto a queued proposal or pause
its enactment, and `governance.guardian_threshold` of them can pause one running
feature without a vote (`GovernanceFeaturePause`, at most
`governance.feature_pause_max_epochs`, then a cool-off). A guardian can only
stop an enabled feature; it cannot enable, resume or retire one, or change a
value.

---

## 19. Security Model

### 19.1 Threat Model

Tenzro assumes:
- Up to f = floor((n-1)/3) Byzantine validators in the consensus set.
- Network partitions are temporary (partial synchrony model).
- TEE hardware is honest but may have side-channel leaks (defense-in-depth with ZK).
- A wallet's hardware root (passkey authenticator, or the machine's TPM 2.0 / Secure Enclave) is not physically extracted; the classical key never leaves it.

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
| Wallet | Hardware-held key (passkey / TPM / Secure Enclave), never extractable; guardian-set recovery | Key theft, single-point compromise |

### 19.3 Slashing Conditions

Validators and providers can be slashed for:
- **Checkpoint equivocation.** Signing two different checkpoints with the same index. A `ReportCheckpointEquivocation` transaction carrying both signatures is verified by the VM and recorded once; the transaction slashes the signer into the insurance pool by three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it (at least 5%, 15% for a validator that has offended before, at most the whole stake; earlier offenders are topped up when a later offence raises the rate), and every node jails it when it replays the log. The evidence stays on chain.
- **Downtime.** Missing heartbeats beyond the tolerance threshold.
- **Invalid proofs.** Submitting false attestation or ZK proof data.
- **Service failure.** Consistently failing inference requests as a model provider.

### 19.4 Arithmetic Safety

All token arithmetic uses `u128` for amounts with `checked_add`, `checked_sub`, `checked_mul`, and `saturating_*` variants to prevent overflow and underflow. The maximum supply (10^27 smallest units) fits comfortably within u128 (max ~3.4 * 10^38).

---

## 20. Training

Training jobs run in harnesses, not in the protocol: a harness posts a job as a task whose rounds are milestones, each paid from an escrow when its round is delivered, and a trained model is served once it is published to the catalog like any other model.

A node trains as compute, like serving: `tenzro_trainRound` runs a deterministic supervised LoRA round in process on the node's CUDA device, metered in trained tokens and answered with a signed receipt and the machine's hardware-key attestation of the round's `result_digest`. The attestation is an ordinary `sensor_data` evidence item over the digest, checked by `tenzro_verifyEvidence` against the machine's registered identity key. A round replayed on a second machine of the same kernel class reaches the same digest, and a harness releases the round's milestone when both machines' attestations verify. Training adds no transaction type, consensus state or protocol parameter: the chain checks the evidence and holds the escrow as for any task.

## 20a. Generative Media

### 20a.1 Overview

Generative media (image, video, audio, 3D, action policies and world models) is a model-serving modality. A node loads a media model from the catalog (`tenzro_loadMediaModel`, operator only) and renders it in process on the native Praecise diffusion engine; it starts no media helper process. `tenzro_mediaGen_render` renders one seeded output, here or on a provider serving the model, and answers with what a signed inference receipt for the task `media` commits to: the output's MIME type, SHA-256 and length, its perceptual fingerprint, and the tolerance two renders must agree within. The output goes to the node's content store and is fetched by `output_blake3` with `tenzro_iroh_fetchBlob`.

A render is seeded, so another provider holding the same weights reproduces it up to numeric drift. Anyone holding the receipt can re-render through the same method and file an inference fault when the fingerprints disagree; an upheld fault refunds the caller from the provider's bond.

A render is metered like every other modality: its work units are priced against the node's rate card, collected from the caller, and recorded for the epoch's reward metering. The unit is the pixel-step, `width × height × steps × frames` (frames 1 for images); audio is metered on duration, 3D on its voxel grid, an action policy per action chunk, and a world model on simulated seconds, denoising steps and held session time (`tenzro_types::media_gen`).

### 20a.2 Model Catalog

The catalog is read through `tenzro_mediaGen_listCatalog`. Each row names the HuggingFace repo, the `diffusers` pipeline class, the kinds it serves, default and maximum resolutions, default step count and guidance scale, frames and fps for video, a VRAM floor, and — for split models — the expert pair.

| ID | Repo | Kinds | Default w×h | Steps | VRAM | Expert pair |
|---|---|---|---|---|---|---|
| `qwen-image` | `Qwen/Qwen-Image` | text2image | 1328 × 1328 | 50 | 48 GB | — |
| `qwen-image-flash` | `nvidia/Qwen-Image-Flash` | text2image | 1024 × 1024 | 4 | 48 GB | — |
| `qwen-image-edit` | `Qwen/Qwen-Image-Edit-2511` | image2image | 1328 × 1328 | 40 | 64 GB | — |
| `z-image-turbo` | `Tongyi-MAI/Z-Image-Turbo` | text2image | 1024 × 1024 | 9 | 16 GB | — |
| `flux2-klein-4b` | `black-forest-labs/FLUX.2-klein-4B` | text2image, image2image | 1024 × 1024 | 4 | 12 GB | — |
| `wan2.2-t2v-a14b` | `Wan-AI/Wan2.2-T2V-A14B-Diffusers` | text2video | 1280 × 720 | 40 | 80 GB | 48 GB each |
| `wan2.2-i2v-a14b` | `Wan-AI/Wan2.2-I2V-A14B-Diffusers` | image2video | 1280 × 720 | 40 | 80 GB | 48 GB each |
| `wan2.2-ti2v-5b` | `Wan-AI/Wan2.2-TI2V-5B-Diffusers` | text2video, image2video, world_model | 1280 × 704 | 50 | 48 GB | — |
| `matrix-game-3` | `Skywork/Matrix-Game-3.0` (requires the `wan2.2-ti2v-5b` text encoder, tokenizer, autoencoder and scheduler) | world_model | 1280 × 704 | 3 | 32 GB | — |

A row serving an image-conditioned kind resolves to a sibling pipeline class where the family provides one (`WanPipeline` → `WanImageToVideoPipeline`); a class that already covers image input keeps it.

`qwen-image-flash` is `qwen-image` distilled onto a four-step trajectory with guidance disabled: identical transformer, identical VRAM floor, one twelfth of the pixel-steps and so one twelfth of the metered work. It is also the one row outside the permissive tier — the NVIDIA Open Model License classifies it `CommercialCustom`, so a worker declaring it must enroll on a node started with `--accept-license nvidia-open-model`. Worker enrollment rejects a capability naming a model the operator has not accepted, or one absent from the catalog. The check runs when the node loads the model (`tenzro_loadMediaModel`).

### 20a.3 Split-Expert Models

Some video models pair two transformers trained for different noise regimes and switch between them once, at a fixed noise level (`t >= boundary_ratio × num_train_timesteps`). A node renders such a model only when it holds both experts; a catalog entry that splits the pair across two machines is refused by `tenzro_mediaGen_render`. Split-expert entries are `planned` until their pipeline is ported to the native engine.

### 20a.4 RPC Surface

| Method | What it does |
|---|---|
| `tenzro_mediaGen_listCatalog` | The media catalog |
| `tenzro_mediaGen_render` | One seeded render with a signed receipt |
| `tenzro_loadMediaModel`, `tenzro_unloadMediaModel` | Load or release a media model (operator only) |

The same surface is reachable through the CLI (`tenzro media-gen catalog | render`), the MCP tools, and the SDKs. Job queues, worker pools and quotes are applications built over these methods.

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
| `consensus.proto` | Consensus protocol messages |
| `network.proto` | P2P networking messages |
| `tee.proto` | TEE attestation types |
| `model.proto` | Model registry and inference |
| `settlement.proto` | Payment settlement |
| `agent.proto` | AI agent protocol |
| `governance.proto` | Proposals and voting |
| `bridge.proto` | Cross-chain messages |
| `rpc.proto` | gRPC service definitions |

## Appendix C: Gossip Topic Reference

| Topic | Direction |
|-------|-----------|
| `tenzro/blocks` | Validators -> All |
| `tenzro/transactions` | Any -> Validators |
| `tenzro/certificates` | Validators -> All |
| `tenzro/validators` | Validators -> All |
| `tenzro/models` | Model Providers -> All |
| `tenzro/status` | All <-> All |
| `tenzro/agents` | Agents <-> Agents |

## Appendix D: Public Endpoints

The public endpoints on `tenzro.com` use PQ-hybrid TLS at the edge:

| Service | URL | Port | Protocol |
|---------|-----|------|----------|
| JSON-RPC | `https://rpc.tenzro.com` | 8545 | Ethereum-compatible JSON-RPC |
| Web API | `https://api.tenzro.com` | 8080 | REST (verify, status) |
| MCP | `https://mcp.tenzro.com/mcp` | 3001 | Streamable HTTP (MCP protocol) |
| A2A | `https://a2a.tenzro.com` | 3002 | JSON-RPC 2.0 + SSE |
| Agent Card | `https://a2a.tenzro.com/.well-known/agent-card.json` | 3002 | GET (A2A discovery) |

**Network configuration:**
- Chain ID: set by each network's genesis (1337 on the developer chain).
- Phases: preview, then testnet, then the stages governance decides on the way to mainnet.
- TNZO is allocated at genesis and moves only by transfer; grants come from governance.
- Docker image: `<your-registry>/tenzro-node:<tag>` (build from the repo `Dockerfile`)

---

**Tenzro Network** — AI-Native, Agentic, Tokenized Settlement Layer

**Tenzro Ledger** — Decentralized AI. Verifiable Inference. Permissionless Settlement.

https://github.com/tenzro/tenzro-network
