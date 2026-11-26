# Tenzro Network — Protocol Specification

## The Open Settlement and Coordination Fabric for AI Work

### Tenzro Ledger: Settlement, Identity and Verification for AI Work and Autonomous Agents

**Version 0.2.2**

---

## Abstract

**Tenzro Network** is the demand and settlement layer for AI work: the open settlement and coordination fabric underneath operators, AI factories, GPU networks, model providers, agent platforms and payment schemes. It is not another AI or GPU provider and not a general-purpose chain. Operators keep their own machines and serving stacks; Tenzro brings agent and app demand to them, routes each call, and settles it per call against a receipt the serving machine signs. It settles compute of every kind, with AI inference, compute, storage and data as roles of the one network, and TEE attestation as a role that makes confidential work checkable. A node can take several roles from one account, each bonded separately; providers are paid for paid, verified work.

**Tenzro Ledger** is the settlement layer underneath, providing on-chain primitives for the machine economy: **identity** (TDIP: Tenzro Decentralized Identity Protocol for humans and machines, every key in a TPM, a Secure Enclave or a passkey), **security** (DAG consensus with hardware-held post-quantum checkpoint certificates and certified block import), **verification** (ZK proofs, TEE attestations and signed receipts), and **settlement** (escrow, payment channels, settlement plans). Network fees are priced in USD, the governed unit of account, and paid in TNZO at the in-network rate; payments settle in TNZO or in a stablecoin governance permits.

All on-chain claims can be independently verified through cryptographic proofs, hardware attestations or signed receipts. The Ledger runs EVM, SVM and its native runtime over one account and identity, so existing contracts, tokens and wallets settle against the same accounts; agents that always have an owner and act under consensus Terms; model serving of every modality with per-call settlement; and cross-chain settlement through governed bridge routes (a CCIP-compatible envelope for EVM chains and Solana, IBC, Bitcoin deposits and bridge contracts). x402, MPP, ACP and UCP map onto one payer-authorized settlement primitive, and AP2 mandates are verified statelessly against the paying agent's Terms. Consensus is a signature-free DAG protocol over post-quantum authenticated channels, with no-vote certificates for tail-fork resistance and checkpoint certificates signed every 500 ms by session keys that hardware-held ML-DSA-65 + P-256 keys certify each epoch.

See [`COMPUTE.md`](COMPUTE.md) and [`STORAGE.md`](STORAGE.md) for the rentable-compute and storage roles.

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
10. [AI Model Serving and Routing](#10-ai-model-serving-and-routing)
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
- **No hardware-rooted keys.** Accounts are usually controlled by software keys and seed phrases, and confidential work offers no evidence a third party can check against a vendor root.
- **No agent-native primitives.** AI agents that need to discover services, pay for them and coordinate with other agents must do so through human-designed interfaces and custodial wallets. There is no settlement layer where every agent answers to an accountable owner, spends only what that owner funded, and acts under limits every validator enforces.

### 1.2 The Tenzro Solution

**Tenzro Network** is the demand and settlement layer for AI work, underneath the operators, model providers, agent platforms and payment schemes that already exist. It provides these core capabilities to participants:

1. **AI inference:** Providers serve models of every modality on their own machines and publish rate cards per model and unit; the network sets no provider price. Each node routes the calls on its API to a provider by price, latency and standing read from chain, and each call settles against a receipt the serving machine signs, per call or through a payment channel.

2. **Compute and storage:** A node rents out capacity by the epoch, held to validator availability verdicts ([`COMPUTE.md`](COMPUTE.md)), and holds content-addressed data held to a proof of retrievability ([`STORAGE.md`](STORAGE.md)); each role carries its own bond.

3. **Confidential computing:** TEE providers run confidential workloads (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs) and return attestations anyone can verify against the vendor roots. A TEE is an execution environment, not a key store: keys live in TPMs, Secure Enclaves and passkeys.

Providers and validators earn by:

- **Securing the network** (reward coupons for consensus work, paid from the genesis-funded rewards pool)
- **Serving AI models** (per-call payments at the provider's own rate card)
- **Providing compute and storage** (per-hour rental fees and per-hour storage claims)
- **Providing TEE attestation and confidential computing** (fees for TEE services)

**Tenzro Ledger** is the settlement layer underneath. It treats hardware-rooted keys, verifiable work and accountable agents as foundational primitives rather than application-layer add-ons:

- **Hardware-rooted consensus.** Every validator's consensus key is a composite ML-DSA-65 + P-256 key: the P-256 leg lives in its TPM or Secure Enclave (its own, or another machine's TPM reached through a key holder), and the ML-DSA-65 leg is derived on demand from that hardware for each use and never stored. TEE attestation is a reputation signal only: nothing self-reported enters the leader schedule.
- **Dual verification: ZK + TEE.** Identity and settlement claims can be backed by a zero-knowledge proof (Plonky3 STARKs in two independent configurations, KoalaBear/SHA-256 and Goldilocks/BLAKE3), a TEE attestation, or both through TEE-bound proofs. Inference claims are backed by TEE attestation; no circuit proves model inference. The STARKs need no trusted setup and rely only on hash functions.
- **Multi-VM execution over one account.** The Ledger runs EVM and SVM contracts beside its native runtime through a unified runtime, so tokens, wallets and contracts from those ecosystems settle against the same accounts and identities. It is a settlement layer for AI work, not a general-purpose chain; TEE attestations and ZK proofs are verified through native precompiles.
- **Accountable agents.** Every agent has an owner: a person, whose key is a passkey, or a machine, whose key is in its TPM or Secure Enclave. An agent holds no key of its own: its account is keyless, funded by its owner, and it acts only under the Terms its owner granted, which every validator checks on each action. Agents reach each other over the agent-to-agent (A2A) protocol and pay through the same settlement primitives as everyone else.
- **Native settlement primitives.** Escrow with programmable release conditions, payment channels (an escrow plus cumulative payer-signed vouchers), settlement plans and batch claims are built into the Ledger, not implemented as smart contracts on top of a generic VM. This keeps per-call settlement of inference cheap and fast.

Network fees are priced in USD, the governed unit of account, and paid in TNZO at the in-network rate; payments settle in TNZO or in a stablecoin governance permits.

### 1.3 What Tenzro Provides

1. **EVM, SVM and a native runtime over one identity and one balance.** `tenzro-vm` runs three executors (revm EVM, `solana-svm` SVM, the native runtime) behind one runtime. Routing is at the transaction-type layer, not via cross-chain messaging.
2. **Agent rails across chains under one identity.** A single TDIP DID can act on AP2, x402, ERC-8004 and ERC-4337 on Tenzro and, through governed bridge routes and settlement plans, on Ethereum, Solana, Bitcoin, Cosmos and Move chains, under the same Terms, the same wallet and the same on-chain settlement. Approvals are bound to the chain id, so a signature for one chain never verifies on another.
3. **The agent-commerce stack over one settlement primitive.** x402 (Tenzro schemes and EVM schemes such as EIP-3009), MPP, ACP and UCP on the seller side, and AP2 mandates verified statelessly against the paying agent's Terms all map onto one payer-authorized settlement primitive. Card, bank and processor rails enter only as attested records from bonded attestors. The ERC-8004 registry contracts are part of genesis, with byte-identical selectors to Ethereum; the EVM keeps the ERC-4337 v0.9 encodings; A2A and MCP are served by every node.
4. **Confidential compute as a verifiable record.** The `TEE_VERIFY` precompile verifies Intel TDX (P-256 ECDSA over Quote\[0..632\]), AMD SEV-SNP and AWS Nitro (COSE_Sign1 ES384 per RFC 8152 §4.4) evidence against pinned vendor root CAs, with NVIDIA GPU evidence accepted alongside a verified CPU attestation. ZK proofs are commitment-attested via `ZkCommitmentRegistry` for O(1) EVM verification.
5. **One native asset with a view in each VM.** TNZO has one balance with two VM views: the wTNZO ERC-20 pointer precompile at `0x1001` on EVM and an SPL adapter on SVM. Both views read and write the same underlying account state, with no bridge between them. Registered upstream via CAIP-2 (`tenzro` namespace), SLIP-44 (`1414421071` / `0xd44e5a4f`, encoding ASCII T+0x80, N, Z, O), and W3C DID (`did:tenzro`).

AP2, x402, ERC-8004, ERC-4337, MCP, A2A, Plonky3, FRI, SHA-3 and TEE attestation are open standards adopted byte-for-byte rather than reinvented; the work is integrating them inside one consensus layer with one native asset and one identity surface.

For the full protocol-layer view, see [`WHITEPAPER.md`](WHITEPAPER.md).

### 1.4 Design Principles

1. **Hardware-rooted keys at the foundation.** Every key is rooted in a TPM, a Secure Enclave or a passkey, with no seed phrases and no private key stored in the clear. TEE attestation is verifiable evidence about a workload and a reputation signal; it is never custody and never changes validator selection or consensus weight.
2. **Cryptographic verifiability.** Claims about computation, identity, and payment are backed by mathematical proofs, hardware attestations or signed receipts, not economic penalties alone.
3. **Settlement for AI work, not a general-purpose chain.** Tenzro Ledger settles and coordinates AI work: model serving, compute, storage and data roles, agents and payments. It runs EVM and SVM beside the native runtime so existing contracts, tokens and wallets settle against the same accounts, not to be a venue for arbitrary applications. Markets, reputation scoring beyond the standing read from chain, trust lists, campaigns, workflows and training orchestration are harness and application code over the public surface.
4. **Economic alignment.** Rewards follow paid, verified work only: validators are paid from the genesis-funded rewards pool for consensus work, providers by the paid work their settlements record, and rewards never exceed what a settlement paid. Nothing is paid for holding, volume, engagement or sign-ups; there are no airdrops, points or yield. Misbehavior is punished through stake slashing.
5. **Interoperability.** Multi-VM execution and governed bridge routes (CCIP-compatible envelope, IBC, Bitcoin deposit, contract routes) ensure Tenzro connects to existing ecosystems rather than requiring migration.

---

## 2. Architecture Overview

### 2.1 Tenzro Network and Tenzro Ledger

**Tenzro Network** is the demand and settlement layer for AI work, where agents, apps and people pay the machines operators already run. The Network provides:

- **AI inference** (model serving of every modality, routed per call by price, latency and standing; providers set their own rate cards)
- **Compute and storage** (rentable capacity and content-addressed data, per [`COMPUTE.md`](COMPUTE.md) and [`STORAGE.md`](STORAGE.md))
- **Confidential computing** (TEE attestation that makes confidential work checkable)

**Tenzro Ledger** is the settlement layer underneath Tenzro Network. The Ledger offers purpose-built primitives for the machine economy:

- **Identity:** TDIP (Tenzro Decentralized Identity Protocol) for unified human/machine identity
- **Security:** DAG consensus with post-quantum checkpoint certificates; every imported block certified
- **Verification:** ZK proofs, TEE attestations and signed receipts
- **Settlement:** Escrow, payment channels, settlement plans and batch claims, in TNZO or a permitted stablecoin

**Revenue Model (Two-Tier Fee Structure):**

1. **Ledger Transaction Fees (Gas):** All on-chain transactions pay gas under an EIP-1559 dynamic fee market, priced in USD and paid in TNZO at the in-network rate. The governed share of the base fee is burned (all of it by default); everything else a block collects, including priority fees, goes to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%).

2. **Settlement fees:** A settled service payment is not divided by node mode: the payee receives it. The chain charges the governed settlement fee and any treasury leg on each on-chain settlement. See [ECONOMICS.md](ECONOMICS.md) for the full model.

Providers/validators/nodes can earn from multiple sources:

- **Validators:** Reward coupons for consensus work and a base reward, both paid from the rewards pool, for securing the Ledger
- **AI Providers:** Per-call payments at their own rate cards
- **TEE Providers:** Service fees for TEE attestation and confidential computing
- Nodes can serve multiple roles simultaneously (e.g., a validator can also be an AI Provider and/or TEE Provider), each bonded separately

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
     | (iroh) | |  sus   | |   EVM+SVM   | |RocksDB| |Registry| | Terms  |
     +--------+ +--------+ +--------------+ +-------+ +--------+ +--------+
          |          |         |               |         |          |
     +----v----------v---------v---------------v---------v----------v-------+
     |                    Supporting Infrastructure                          |
     |   Crypto - TEE - ZK - Wallet - Token - Settlement - Bridge            |
     |   Identity - Payments                                                |
     +----------------------------------------------------------------------+
```

### 2.3 Crate Architecture

The system is implemented as a Rust workspace of 37 crates plus SDKs, organized in a strict dependency hierarchy:

| Layer             | Crate                     | Purpose                                                                                                                                                                                                                                               |
| ----------------- | ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Foundation        | `tenzro-types`            | Shared types, primitives, constants (zero internal dependencies)                                                                                                                                                                                      |
| Cryptography      | `tenzro-crypto`           | Ed25519, Secp256k1, AES-256-GCM, X25519, ML-DSA-65 / ML-KEM-768 (FIPS 203/204), VRF (RFC 9381)                                                                                                                                                        |
| Trust             | `tenzro-tee`              | TEE abstraction over Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber                                                                                                                                                                    |
| Proofs            | `tenzro-zk`               | Plonky3 STARKs in two configurations (KoalaBear/SHA-256, Goldilocks/BLAKE3), SHA3-256 preimage circuits, k-of-n acceptance, TEE-bound proofs                                                                                                          |
| Networking        | `tenzro-network`          | gossip messages, topics and validation over iroh-gossip                                                                                                                                                                                               |
| iroh data plane   | `tenzro-iroh`             | QUIC-native content-addressed transport, DA backend, gradient store, sealed-shard store, A2A-over-iroh on `tenzro/a2a` ALPN                                                                                                                           |
| Storage           | `tenzro-storage`          | RocksDB, unified binary state trie (block state root, proofs, snapshot buckets), fsync durability                                                                                                                                                     |
| Storage provider  | `tenzro-storage-provider` | Paid decentralized storage: provider daemon, proof of retrievability, Reed-Solomon redundancy, hourly claim settlement                                                                                                                                  |
| Cluster substrate | `tenzro-cluster`          | Engine-agnostic local-network cluster tier: reachability tiers, probed link-cost graph, nearest-neighbour ordering, rendezvous placement — shared by model layers, storage shards, and database partitions                                            |
| Consensus         | `tenzro-consensus`        | Signature-free DAG ordering, checkpoint certificates, epoch management, leader schedule from the committed prefix                                                                                                                                     |
| Execution         | `tenzro-vm`               | Multi-VM runtime: EVM, SVM and native executors                                                                                                                                                                                                       |
| Economics         | `tenzro-token`            | TNZO token, staking, rewards, treasury, governance                                                                                                                                                                                                    |
| Wallets           | `tenzro-wallet`           | Permissionless hardware-key wallets (passkey for humans, TPM 2.0 / Secure Enclave for machines) + ML-DSA-65 hybrid, no custody held; Argon2id keystore for the wallets' public records                                                                |
| Device keys       | `tenzro-device-key`       | Non-extractable P-256 keypairs in the machine's hardware (TPM 2.0 on Linux and Windows, Secure Enclave on macOS): prehash signing, ECIES secret wrapping, and Ed25519 / X25519 / ML-DSA-65 keys derived on demand from a hardware root                |
| Keystore unlock   | `tenzro-keystore-unlock`  | Platform-agnostic `KeystoreUnlocker` trait for the keystore password so wallets persist across restarts; the password comes from a hardware device key (Secure Enclave or TPM), and there is no environment-variable or fixed-password implementation |
| Authentication    | `tenzro-auth`             | Authentication engine: AAP (Agent Authentication Protocol), DPoP, RAR (Rich Authorization Requests)                                                                                                                                                   |
| Identity          | `tenzro-identity`         | TDIP: unified human/machine identity, W3C DID, verifiable credentials, delegation                                                                                                                                                                     |
| Payments          | `tenzro-payments`         | Payment protocols: MPP, x402, RFC 9421 HTTP message signatures, delivery-versus-payment, metering and receipts                                                                                                                                        |
| AI Models         | `tenzro-model`            | Multi-modal model registry, llama.cpp LLM runtime, ONNX vision/text-embedding/segmentation/detection/audio/video runtimes, ONNX timeseries forecasting runtime, inference routing, rate-card pricing, durable catalog                                    |
| Settlement        | `tenzro-settlement`       | Escrow, micropayments, batch settlement, fee collection                                                                                                                                                                                               |
| Events            | `tenzro-events`           | The chain's event log (cursor-ordered, committed in block headers, provable against certified checkpoints), the node's live event bus, webhooks                                                                                                       |
| Bridge            | `tenzro-bridge`           | Route framework (CCIP-compatible envelope for EVM + Solana), fee oracle, Chainlink feeds                                                                                                                                                              |
| Node              | `tenzro-node`             | Full node binary, RPC server, MCP, A2A, web API                                                                                                                                                                                                       |
| CLI               | `tenzro-cli`              | Command-line interface (77 command modules)                                                                                                                                                                                                           |
| SDK               | `tenzro-sdk`              | Rust SDK with builder-pattern configuration                                                                                                                                                                                                           |
| TypeScript SDK    | `tenzro-ts-sdk`           | TypeScript SDK for browser and Node.js integration                                                                                                                                                                                                    |

### 2.4 Node Roles

Participants in the Tenzro Network operate nodes in one or more roles: validator, RPC, AI, compute, storage and security (TEE) providers, wallet providers, attestors, catalog publishers and edge relays. Each role a machine takes is bonded separately from the same account (§8.3); no single stake covers every role, and only the validator bond carries consensus weight. A node starts without a bonded role its operator has not bonded and logs the missing bond (an unbonded validator role refuses to start), and the light build refuses the `ai`, `compute` and `tee` roles.

- **Validator.** Participates in consensus, proposes vertices and signs checkpoints with a hardware-held key (its own TPM or Secure Enclave, or another machine's TPM through a key holder). Bonds **10,000 TNZO** with `RegisterValidator`. While the governed parameter `validator.admission_approval` is 1, as it is at genesis, an account registers only once an enacted `ApproveValidators` proposal has named it; governance opens admission by setting the parameter to 0 (§3.7a). Earns reward coupons for consensus work, paid from the rewards pool; priority fees go to the treasury, not to the proposer. A machine without the hardware follows the chain.

- **RPC Provider.** Serves public JSON-RPC and the REST verification API to tenants and earns for the traffic it serves. Bonds **100,000 TNZO** as its own role stake. It may broker access to operator-held upstream credentials, keyed by each tenant's DID (data feed subscriptions, external-chain RPC endpoints). The genesis configuration names the first RPC Provider, at `rpc.tenzro.com`.

- **AI Provider.** Serves AI models of every modality and publishes its own rate card per model and unit; the network sets no provider price. Bonds **1,000 TNZO**; admission is permissionless above the bond, with no allowlist and no approval step. Earns per-call payments, settled per call or through payment channels, and provider reward coupons by settled fees (TOKENOMICS §7). The network's share follows the node's economic mode and flows to the treasury (see [ECONOMICS.md](ECONOMICS.md)).

- **TEE Provider.** Runs confidential workloads in hardware TEEs (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU TEEs) and serves attestations, including hosted appraisal through Intel Tiber Trust Authority. Bonds **10,000 TNZO**, reflecting that a false attestation compromises every party relying on it. Earns fees for TEE services and provider reward coupons by settled fees (TOKENOMICS §7). A TEE is never a key store: no key is kept or derived inside one.

- **Storage Provider.** Stores and serves content-addressed data, model weights and historical data. Bonds **100 TNZO per terabyte pledged**, floored at 100 TNZO, so the bond tracks the capacity it collateralizes. Earns storage fees.

- **Compute Provider.** Rents accelerators for inference, training, and rendering. Bonds **per card by accelerator class** — 500 TNZO integrated, 1,000 consumer, 2,000 workstation, 5,000 datacentre — summed over everything pledged and floored at 500 TNZO. Earns time-based rental revenue.

- **Wallet Provider.** Serves passkey wallets on its own relying-party domain, declared in its bond (1,000 TNZO); validators confirm the domain names the bonding account. Wallets from unbonded domains still work; they are only not shown as staked.

- **Attestor.** Connects a payment rail (bank transfer, card, ISO 20022) under its own relationship and attests settlement legs and reserves on it. Bonds 100,000 TNZO; a payee's evidenced dispute slashes the bond.

- **Catalog Publisher.** Signs model catalog entries other nodes serve; its 1,000 TNZO bond answers for every entry it signs.

- **Edge Relay.** Terminates public TLS at a controlled DNS name, routes incoming requests to the node holding the content, and serves the iroh relay at the URL its bond publishes. Bonds 10,000 TNZO. It is a public front door, not a consensus participant.

- **Light Client.** Verifies block headers and proofs without storing full state.

- **Bootstrap Node.** Initial peer discovery endpoint for new nodes joining the network. Any node can serve this role; a founding validator serves as the canonical bootstrap seed, advertised through the pkarr relay; a node is booted by machine identity (`--boot-nodes did:tenzro:machine:<id>[@<relay url>]`).

- **Archive Node.** Stores complete historical state for analytics and indexing.

### 2.5 API Surface

The node exposes four API interfaces:

**JSON-RPC Server** (default `127.0.0.1:8545`):

**Trust surface.** Certification, policy and provenance records are signed by their author's hardware key and re-verified by every node that applies them (`crates/tenzro-trust`; see `docs/TRUST.md`). `tenzro_submitTrustRecord` accepts a credential, a revocation, an issuer revocation, an operator policy, an origin attestation, a model manifest, or policy-violation evidence; the reads are `tenzro_verifyTrustCredential`, `tenzro_getTrustCredentials`, `tenzro_getStatusList`, `tenzro_getOperatorPolicy` and `tenzro_getModelProvenance`. The operator-local, disk-reading methods `tenzro_buildModelManifest` / `tenzro_verifyModelFiles` / `tenzro_scanModelFiles` / `tenzro_hostModel` are admin-gated. A model is named by the BLAKE3 Merkle root of its manifest (`tenzro:model:<root>`), an operator by its hardware-derived DID; credentials are W3C VC 2.0 documents with an `ecdsa-jcs-2019` Data Integrity proof and a Bitstring Status List entry, so expiry and revocation are part of validity.

**Web Verification API** (default `127.0.0.1:8080`):

| Endpoint                       | Purpose                                      |
| ------------------------------ | -------------------------------------------- |
| `POST /verify/zk-proof`        | Verify a zero-knowledge proof                |
| `POST /verify/tee-attestation` | Verify a TEE attestation report              |
| `POST /verify/transaction`     | Verify a transaction signature               |
| `POST /verify/settlement`      | Verify a settlement receipt                  |
| `POST /verify/inference`       | Verify an inference result against its proof |
| `GET /verify/health`           | Health check                                 |
| `GET /health`                  | Health check                                 |
| `GET /status`                  | Node status and metrics                      |

**MCP Server** (default `127.0.0.1:3001`):
Model Context Protocol server using the `rmcp` crate with Streamable HTTP transport (protocol version `2026-07-28`). Exposes a tool for every served method, spanning wallet, identity, payments (x402, MPP, AP2), inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), stakes, tokens, governed bridge routes, verification, agents, tasks, TEE, ZK, VRF, and event subscriptions, that any MCP client can invoke. Representative groups:

| Group                 | Example Tools                                     |
| --------------------- | ------------------------------------------------- |
| Wallet & Ledger       | `get_balance`                                     |
| Network & Blocks      | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did`                |
| Payments              | `create_payment_challenge`, `verify_payment`      |
| AI Models & Inference | `list_models`, `list_model_endpoints`             |
| Verification          | `verify_zk_proof`, `verify_vrf_proof`             |
| Stakes & Providers    | `get_role_stakes`, `get_provider_stats`           |
| Tokens & Contracts    | `deploy_contract`                                 |

**A2A Protocol Server** (default `127.0.0.1:3002`):
Agent-to-Agent protocol server implementing the Google A2A specification with JSON-RPC 2.0:

| Endpoint                           | Purpose                                                                            |
| ---------------------------------- | ---------------------------------------------------------------------------------- |
| `GET /.well-known/agent-card.json` | Agent Card discovery, signed (detached JWS over the RFC 8785 form)                 |
| `POST /a2a`                        | JSON-RPC 2.0 dispatcher; `SendStreamingMessage` answers with SSE on the same route |

A2A 1.0 only: every request sends `A2A-Version: 1.0`. JSON-RPC methods: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`; every one carries the Tenzro DID envelope, and a task is read, continued or cancelled only by the DID that opened it. The Agent Card advertises up to 21 skills: `wallet`, `identity`, `inference`, `settlement`, `verification`, `staking`, `token`, `contract`, `join`, `bridge`, `compliance`, `events`, `adaptive-burn`, `iroh-transport`, `urwa`, `bridge-fee-in-tnzo`, `storage`, `compute`, `moe`, `media-gen`, `discovery`. A skill that needs something of the node is listed only while the node has it: `inference`, `moe` and `media-gen` on a node that serves models, `storage` and `compute` on a node serving those roles, `iroh-transport` when its iroh endpoint is bound. Supports streaming responses via Server-Sent Events and multi-turn conversation history.

---

## 3. Consensus

### 3.1 Overview

The Tenzro Ledger orders transactions with a signature-free DAG protocol and makes the ordering transferable with checkpoint certificates. Validators exchange unsigned vertices over authenticated post-quantum channels; a reliable broadcast makes every honest validator deliver the same vertex or none; a leader commits once a quorum of the next round references it, which orders the DAG. Every 500 ms of ordered history, validators sign a checkpoint with an in-memory composite ML-DSA-65 + ECDSA-P256 session key that their hardware-held key certifies once per epoch (the certificate travels with every vote), and a quorum of signatures forms a certificate that anyone can verify. The design is described in [`architecture/consensus.md`](architecture/consensus.md).

### 3.2 Protocol Parameters

| Parameter              | Default Value     | Description                                                                                                           |
| ---------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| Leader timeout         | 1,000 ms          | Wait for a round leader before timing out                                                                             |
| Checkpoint interval    | 500 ms            | Minimum segment time between checkpoints; votes are signed by a session key the hardware key certifies once per epoch |
| Seat budget            | 1,000             | Seats stake is apportioned into                                                                                       |
| Epoch length           | 7,200 checkpoints | One hour at the checkpoint interval                                                                                   |
| Handover confirmations | 2 checkpoints     | Checkpoints the old committee orders after the one ending its epoch                                                   |
| Batch interval         | 50 ms             | How often a validator cuts its mempool share into a batch                                                             |

### 3.3 Ordering

- **Seats.** Stake is apportioned into integer seats by largest remainder; every threshold is counted in seats (`n` seats, `f = (n-1)/3`, quorum `n - f`).
- **Vertices.** Each validator proposes one vertex per round, referencing a quorum of the previous round, introducing its batches and acknowledging others'. Vertices are delivered by a signature-free reliable broadcast (ECHO, VOTE, ACK, READY; two-step delivery on a large ECHO quorum).
- **Commit.** A round's leader vertex commits once the first proposals of the next round from a quorum of seats reference it; earlier leaders reachable from it commit first. A leader vertex that skips the previous leader counts only with a quorum of no-votes, which closes the tail-fork attack. Each committed leader orders its not yet ordered causal history into one block.
- **Batches.** A batch executes once its introduction and a quorum of acknowledgements are ordered.

### 3.4a Validator Bond and Admission

Every validator signs checkpoints with a hardware-held composite ML-DSA-65 + P-256 key and bonds at least **10,000 TNZO** of self-stake with `RegisterValidator`, carrying a proof of possession of that key. Quorum weight is the validator bond alone; bonds for service roles (RPC, AI, TEE, compute, storage and the rest) carry none. A node that bonds nothing can join, sync, gossip and follow the chain, but it does not vote.

Admission starts closed: while `validator.admission_approval` is 1 (its genesis value), a validator registers and sits on a committee only from the admitted set, the genesis validators and the accounts an enacted `ApproveValidators` proposal named (§3.7a). Governance opens admission to any account with the bond by setting the parameter to 0.

Validators earn validator-bucket reward coupons for the blocks they propose and the checkpoints they sign, and a base reward paid from the rewards pool (TOKENOMICS §7); transaction fees are not paid to validators. Slashing applies to checkpoint equivocation (§3.6, §19.3) and to the other evidenced faults listed in §19.3.

The RPC provider is a separate role with its own 100,000 TNZO bond (§2.4), not a validator tier. The genesis configuration names the first RPC provider, which also serves as the seed bootstrap peer and public RPC at `rpc.tenzro.com`. It is not architecturally privileged; any other operator that bonds the RPC role can register its own endpoint, admit its own tenants and front its own upstream credential vault under the same protocol rules.

### 3.5 Leader Schedule

The leader of each round is drawn from a distribution weighted by seats times observed behavior (a validator whose leader slots commit keeps full weight; one that misses them drops to the floor). The schedule is a function of the committed prefix: it changes only at checkpoints and draws its seed from the ordering digest of the checkpoint two back, so no validator can grind it and every validator evaluates the commit rule against the same leader. No self-reported value, and no VRF or BLS key, enters the draw.

### 3.6 Checkpoints, Certificates and Accountability

A checkpoint commits the chain, the epoch, its index, the previous checkpoint, the height range, the blocks root, the state root at a lag of two blocks, the statement root and, at an epoch's end, the next committee's root. Each validator persists that it is about to sign before signing, so a crash cannot make it sign two checkpoints with one index. Two such signatures are complete evidence: a `ReportCheckpointEquivocation` transaction carrying them is verified by the VM and recorded once, and every node slashes the signer when it replays the log.

### 3.7 Epoch Management

The validator set is fixed within an epoch (default 7,200 checkpoints). At epoch boundaries:

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

**Verified state sync.** A fresh node trusts a block at height `A`: a weak-subjectivity checkpoint when one is pinned (`--checkpoint-hash`/`--checkpoint-height` or genesis `[weak_subjectivity]`), and otherwise the anchor of a peer's newest snapshot over the `tenzro/state-sync/anchor` ALPN, taken only once the certification of the checkpoint covering it verifies from the genesis committee and the checkpoint's blocks root rebuilds from the block hashes sent with it. It restores the committed state at `S = A − STATE_ROOT_LAG` from peers over iroh (`--state-sync-from <ENDPOINT_ID>`, or the genesis validators' endpoints). It asks a peer for the manifest over the `tenzro/state-sync` ALPN, then checks the anchor chain `S ..= A` ends in the trusted block, that the manifest's bucket summaries fold to the root that block commits, and each bucket (4,096 in all, fetched and written one at a time as BLAKE3-verified blobs from whichever peer has them) against its summary before writing it. After the last bucket the node's own trie must reproduce the root. A sync that stops resumes by skipping committed buckets. Snapshots are produced only at epoch-start heights, so the epoch record and validator registry restore with the state; a usable join checkpoint is therefore `S + STATE_ROOT_LAG` for a snapshot `S` a serving node holds, and `tenzro_listSnapshots` gives it per snapshot (`checkpoint_height`, `checkpoint_hash`). The joining node asks each peer in turn and refuses to start when none holds the snapshot, rather than replaying blocks under a checkpoint join; a node whose store already holds chain state continues from its tip.

**Admission by governance approval.** While the governed parameter `validator.admission_approval` is 1, a validator registers and sits on a committee only from the admitted set: the genesis validators, which the genesis writes as approved, and the accounts an enacted `ApproveValidators` proposal named. The same proposal type with `approve` false takes an account off the set. Governance sets the parameter to 0 to open admission to any account with the bond, and back to 1 to close it, with no new genesis (`docs/operations/VALIDATOR-ADMISSION.md`).

### 3.8 Finality

The RPC reports two heights. **Ordered** is final for every honest validator: the commit rule never reverts it. **Certified** is covered by a checkpoint certificate: transferable, and accountable to the signers. Bridges act on certified. A follower executes a block only once a certificate it verifies covers it, the blocks rebuild the certified blocks root, and its own state root matches the certified one.

A certificate is also the portable proof of finality for a party that runs no Tenzro node: another chain, a bridge relayer, an auditor. `tenzro_getCheckpointCertificate` (optional `index`; the latest when omitted) returns the encoded certificate (the checkpoint: chain, genesis, epoch, height range, state root, plus a quorum of seat signatures) and the session certificates it names. With the epoch's committee (`tenzro_getCommittee`), `tenzro_consensus::checkpoint::Certificate::verify` checks it with no node in the loop: every signature is a composite ML-DSA-65 + ECDSA-P256 signature by a seat's per-boot session key, and each session key is certified by that seat's hardware key.

## 4. Multi-VM Execution Layer

### 4.1 Architecture

The Tenzro Ledger's execution layer supports two virtual machines beside its native runtime through a unified `MultiVmRuntime` that routes transactions to the appropriate executor based on the transaction's `VmType`:

- **EVM (Ethereum Virtual Machine).** Full EVM-compatible execution for Solidity and Vyper smart contracts.
- **SVM (Solana Virtual Machine).** Solana-compatible execution for programs written in Rust targeting the BPF instruction set.
- **Native runtime.** Tenzro's own transaction types (transfers, staking, governance, identity, settlement, agent operations) execute natively under `VmType::Tenzro`.

#### 4.1.1 Why two VMs

Tenzro is not a general-purpose chain; it runs the two VMs so that the tokens, wallets and contracts agents and apps already use can settle against the same accounts and identities as the native runtime. Each anchors an ecosystem the other cannot import:

- **EVM** carries the ERC-20 / ERC-721 / ERC-4626 / ERC-4337 standards, Solidity tooling (Hardhat, Foundry, Remix) and the stablecoins issued as ERC-20 contracts. Settling against them needs EVM bytecode, not an EVM-compatible API.
- **SVM** carries programs written against `solana_program` and the SPL standard. Running them needs the actual BPF instruction set, the Solana account model and SPL Token Program semantics, not a transpilation.

The integration is unified: both VMs and the native runtime read and write the same canonical TNZO balance through the pointer model (§4.9), share the same precompile-exposed primitives (TEE attestation and ZK verification), and dispatch through the same `MultiVmRuntime`. A single transaction can move TNZO from an EVM DeFi position into an SVM program, with every call taking effect or none — without bridge risk, wrapping fees, or liquidity fragmentation.

### 4.2 Execution Constants

| Constant          | Value             | Description                                                                                                                        |
| ----------------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Max gas limit     | 30,000,000        | Maximum gas per transaction                                                                                                        |
| Default gas limit | 10,000,000        | Default gas if unspecified                                                                                                         |
| Min gas price     | 1 Gwei (10^9 wei) | Minimum gas price                                                                                                                  |
| Max contract size | 24,576 bytes      | EIP-170 contract size limit                                                                                                        |
| Chain ID          | `<chain-id>`      | Set by each network's genesis (13380 on the preview network, 1337 on the local developer chain); custody approvals are bound to it |
| Max call depth    | 1,024             | Maximum nested call depth                                                                                                          |

### 4.3 Precompile Registry

The VM provides precompiled contracts that expose native platform functionality to smart contracts:

- **TEE_VERIFY (`0x1010`).** Strict verification of a TEE attestation report against pinned vendor roots; simulated reports are refused.
- **ZK_VERIFY (`0x1011`).** O(1) HashSet lookup against `ZkCommitmentRegistry`. Plonky3 STARK proofs are verified off-EVM and a 32-byte SHA-256 commitment is admitted only by an executed transaction; the precompile rejects unknown commitments.

There is no model-inference or settlement precompile: escrow and settlement are native transactions (§9). The full address table is in §4.9.

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

| Parameter            | Value            |
| -------------------- | ---------------- |
| Target gas per block | 15,000,000       |
| Min base fee         | 0.1 Gwei         |
| Max base fee         | 1,000 Gwei       |
| Adjustment rate      | ±12.5% per block |

**Mechanism:** The base fee adjusts up when blocks are above the target gas utilization and down when below. Base fee is burned (removed from circulation), creating deflationary pressure proportional to network usage. Users specify a `max_fee_per_gas` and `max_priority_fee_per_gas`; the priority fee goes to the treasury (§2.1). The `FeeMarket` provides fee suggestions by urgency level (low, medium, high).

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

Wallets expose the native account through the standard browser interfaces (see `sdk/tenzro-inject`): EIP-6963 discovery and EIP-1193 requests; ERC-5792 `wallet_sendCalls` as one atomic contract-call transaction approved once by the passkey, with `atomic` reported as supported and the transaction hash as the batch id; ERC-7715 `native-token-periodic` permissions written into an agent's Terms as an hourly or daily spend limit with an optional expiry, checked by every validator on each agent action, with `delegationManager` the zero address because the agent's serving nodes redeem natively. A sponsor may send keystore changes and agent Terms carrying the passkey's approval and pay their fee; a call batch is paid by its sender, so `paymasterService` is unsupported for batches.

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

The Tenzro Ledger implements a **pointer model** for cross-VM token representation. Instead of bridging or wrapping tokens between VMs (which introduces bridge risk and fragments liquidity), all VM representations point to the same underlying native balance managed by the `TnzoToken` layer. There is no lock-and-mint bridge — every VM surface reads and writes the same canonical balance.

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

| VM  | Representation                | Decimals | Mechanism                                                                                                                             |
| --- | ----------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| EVM | wTNZO ERC-20 pointer contract | 18       | Standard ERC-20 interface with approval storage; reads/writes native balance                                                          |
| SVM | wTNZO SPL token adapter       | 9        | Maps SPL Token Program instructions to native TnzoToken; 9-decimal truncation (18 to 9); ATA derivation for associated token accounts |

**Decimal Conversion (SVM):**

Solana's SPL Token standard uses 9 decimals while TNZO uses 18. The SPL adapter performs deterministic truncation: the lower 9 decimal digits are dropped on deposit into SVM and zero-padded on withdrawal back to native. This means the smallest representable unit in SVM is 10^9 wei (1 Gwei-equivalent), which is sufficient for all practical token operations.

**Tenzro-Specific Precompile Addresses:**

In addition to the 9 standard EVM precompiles (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, BN254 EC operations, BLAKE2F) and 7 BLS12-381 precompiles (EIP-2537: G1ADD, G1MSM, G2ADD, G2MSM, PAIRING_CHECK, MAP_FP_TO_G1, MAP_FP2_TO_G2 at 0x0a-0x10 using the `blst` library), the VM exposes Tenzro-specific precompiles:

| Address  | Precompile        | Description                                                                                        |
| -------- | ----------------- | -------------------------------------------------------------------------------------------------- |
| `0x0100` | P256VERIFY        | EIP-7951 secp256r1 signature verification, at its canonical Ethereum address                       |
| `0x1001` | wTNZO pointer     | ERC-20 interface over native TNZO                                                                  |
| `0x1002` | TOKEN_FACTORY     | Fungible tokens whose ledger lives in the precompile's storage, with the ERC-7943 (uRWA) functions |
| `0x1006` | NFT_FACTORY       | ERC-721 / ERC-1155 collections                                                                     |
| `0x1007` | VRF_VERIFY        | RFC 9381 ECVRF proof verification                                                                  |
| `0x1009` | RANDOMNESS_BEACON | Randomness derived from finalized chain state                                                      |
| `0x1010` | TEE_VERIFY        | Strict TEE attestation report verification                                                         |
| `0x1011` | ZK_VERIFY         | Lookup of ZK proof attestations recorded in state                                                  |

There are no staking, governance, settlement or model-inference precompiles.

**Unified Token Registry:**

All tokens — native TNZO, user-created ERC-20s, and SPL tokens — are indexed in a single `DashMap`-backed `TokenRegistry` with RocksDB persistence (column family `CF_TOKENS`). Each token entry records its `TokenId` (deterministic SHA-256 of creator address and nonce), creator, symbol, decimals, total supply, and the set of VMs where it has pointer contracts deployed. This eliminates the fragmented token tracking that plagues multi-chain ecosystems.

**Token Factory:**

The `TOKEN_FACTORY` precompile at address `0x1002` enables any smart contract or user to create new tokens on the Tenzro Ledger. Created tokens are automatically registered in the unified token registry and can be deployed as pointer contracts across both VMs. This enables ecosystem token creation (e.g., governance tokens for DAOs, reward tokens for applications) without requiring separate deployment and registration steps per VM.

### 4.9.1 Cross-VM Atomicity Invariant

The unified-balance design above produces a sharper guarantee than the multi-VM systems that wrap tokens or run separate keepers per VM. Concretely, for any block `B = [tx_1, …, tx_m]` containing a mix of EVM, SVM, and native transactions that touch shared TNZO balances, the post-block state is identical to the result of applying `tx_1, …, tx_m` sequentially against a single shared state tree. Each transaction either commits all of its state changes (across every VM it touches via the cross-VM bridge precompile `0x1003`) or reverts all of them. No intermediate state in which a balance has been debited on one VM but not credited on another is observable to any subsequent transaction or external reader.

In formal terms, block execution is **opaque (in the STM sense) and serializable**, with snapshot/rollback at the per-transaction boundary. The proof is one line: the dispatcher takes a snapshot of the shared state tree before every `Executor::execute(state, tx)` call and reverts to the snapshot if the receipt is a failure. Because the `TnzoToken` layer is the _only_ shared resource across VMs, no side effects can leak between executors. This eliminates an entire class of bridge-style failure modes — there is no lock-mint-burn-release cycle, no multi-signature committee, and no optimistic challenge period — because there is no bridge.

When two transactions in the same block target the same balance from different VMs (for example, an EVM `transfer` via the wTNZO ERC-20 pointer and an SVM SPL transfer over the same source account), the conservative scheduler places them in different sequential batches: the write set of any cross-VM balance touch is statically determinable from the typed-transaction payload, so concurrent writes to the same balance are detected before parallel execution. The second transaction observes the post-image of the first; the conservation invariant `Σ balances_pre = Σ balances_post` holds for every block; and the VM-native views (`balance(addr) via EVM == balance(addr) via SVM`) agree post-block.

**References.** This is the standard cross-VM conservation invariant for a multi-VM ledger with shared identity and token state, together with the Block-STM deterministic-conflict-detection property. The same property is exercised across the full commit path in `crates/tenzro-vm/tests/cross_vm_atomicity.rs`.

---

## 5. Trusted Execution Environments

### 5.1 Overview

Tenzro supports hardware-based confidential computation through four TEE technologies:

| TEE         | Provider            | Use Case                                                       |
| ----------- | ------------------- | -------------------------------------------------------------- |
| Intel TDX   | `IntelTdxProvider`  | Trust Domain Extensions for VM-level isolation                 |
| AMD SEV-SNP | `AmdSevSnpProvider` | Secure Encrypted Virtualization with Secure Nested Paging      |
| AWS Nitro   | `AwsNitroProvider`  | AWS Nitro Enclaves for cloud-based isolation                   |
| NVIDIA GPU  | `NvidiaGpuProvider` | NVIDIA Confidential Computing for GPU-accelerated AI workloads |

Each provider is gated behind a cargo feature flag (`intel-tdx`, `amd-sev-snp`, `aws-nitro`, `nvidia-gpu`) and implements a common `TeeProvider` trait.

### 5.6 NVIDIA GPU Confidential Computing

The `NvidiaGpuProvider` enables confidential AI inference on NVIDIA GPUs with hardware-rooted trust:

- **Supported architectures:** Hopper (H100/H200) and Blackwell (B100/B200)
- **NRAS attestation:** Attestation reports are validated against the NVIDIA Remote Attestation Service (NRAS); the token must carry `exp` and `iat` and be unexpired
- **GPU capabilities:** Each GPU reports its architecture, VRAM capacity, compute capability version, and driver version
- **Confidential inference:** Model weights and inputs remain encrypted in GPU memory; only the TEE enclave can access plaintext data

This matters for model serving: AI providers can serve inference inside GPU TEEs, proving to consumers that their data and the model weights were processed confidentially.

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

There is no inference circuit: no circuit proves that a model produced an output. Inference integrity rests on TEE attestation and the challenge protocol. There is no post-quantum quorum-certificate circuit: checkpoint certificates carry composite ML-DSA-65 + ECDSA-P256 signatures, verified natively.

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

| Algorithm             | Purpose                                                                                                                            | Key Sizes                                                                  |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Ed25519               | Transaction and message signatures                                                                                                 | 32-byte public key, 64-byte signature                                      |
| Secp256k1             | Ethereum-compatible signatures, key derivation                                                                                     | 33-byte compressed public key                                              |
| Secp256r1 (P-256)     | WebAuthn / passkey signatures (Secure Enclave, StrongBox, TPM 2.0, Windows Hello), verified on-chain via the precompile at `0x100` | 64-byte uncompressed public key (`x ‖ y`), 64-byte raw signature (`r ‖ s`) |
| ML-DSA-65 (FIPS 204)  | Post-quantum hybrid signature companion to Ed25519                                                                                 | 1952-byte public key, 3309-byte signature                                  |
| ML-KEM-768 (FIPS 203) | Post-quantum hybrid KEM companion to X25519                                                                                        | 1184-byte public key, 1088-byte ciphertext                                 |
| AES-256-GCM           | Symmetric encryption for keystore and data at rest                                                                                 | 256-bit key, 96-bit nonce, 128-bit tag                                     |
| X25519                | Elliptic-curve Diffie-Hellman key exchange                                                                                         | 32-byte public key                                                         |
| SHA-256               | General-purpose hashing, Merkle trees                                                                                              | 256-bit digest                                                             |
| Keccak-256            | Ethereum address derivation, storage keys                                                                                          | 256-bit digest                                                             |

### 7.2 Address Derivation

A ledger account is controlled by a composite key pair: a P-256 key held in hardware and an ML-DSA-65 key. Its address commits to the P-256 key only:

```text
account = SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[..20]
```

where `x ‖ y` is the 64-byte P-256 public key. In the 32-byte account slot the 20-byte address is left-aligned and followed by 12 zero bytes. A transaction, an account-owner proof and a cross-VM transfer are accepted only from the account their P-256 key derives; enrolling or rotating the ML-DSA-65 key never moves an account, and the first use binds the ML-DSA key to the signing key. The classical-only derivation (SHA-256 of an Ed25519 key, first 20 bytes; Keccak-256 of a secp256k1 key, last 20 bytes) still names peers, attesters and other classical-key identities, but it is not a ledger account.

### 7.3 Hybrid Signature Custody

Tenzro wallets do not split the signing key. Each identity's classical key is held whole in the holder's own hardware — a passkey (WebAuthn) authenticator for a human, a TPM 2.0 or Apple Secure Enclave for a machine — and the private half never leaves that hardware. There is no dealer, no share distribution, and no quorum reconstructed at signing time; the network holds nothing.

A single transaction carries a **hybrid** signature over two legs:

1. **Classical.** Ed25519 (or the P-256 WebAuthn assertion for a passkey), produced by the device key. Verifies under the standard verifier — no protocol-specific verifier required.
2. **Post-quantum.** ML-DSA-65 (FIPS 204), derived on demand from the same hardware root and signed alongside the classical leg.

The hybrid verifies as the conjunction of its legs, so a break of one algorithm does not forge a transaction. The post-quantum leg is mandatory: an account that has not enrolled an ML-DSA-65 key signs nothing until it does, and its first transaction is the enrolment (`AccountKeys`, `EnrollPqKey`), which carries the leg of the key being enrolled. The wallet, the CLI (`tenzro pq-hybrid enroll`, and automatically before the first transaction a new account sends) and the Rust and Python SDKs (`AccountKeysClient::send_enrolling`) enrol the hardware's key, so a new account is never left unable to send. Recovery is handled by the account's linked passkeys and recovery signers in its keystore (§15.6), not by holding a spare share.

### 7.4 Envelope Encryption

For data at rest (keystore files, cached keys), Tenzro uses envelope encryption:

1. A data encryption key (DEK) is generated randomly.
2. Data is encrypted with AES-256-GCM using the DEK.
3. The DEK is encrypted with a key encryption key (KEK) derived from the user's password via Argon2id (64 MB memory, 3 iterations, parallelism 4).
4. The encrypted DEK, salt, nonce, and ciphertext are stored together.

---

## 8. TNZO Token Economics

> **Governed parameters.** Fees, splits, treasury legs, staking minimums, reward shares, slashing, unbonding periods and burn rates are governed parameters: genesis values, changed only by enacted proposal and only within the bounds compiled into the node ([GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md)). The network opens as a preview, then a testnet, then the stages governance decides on the way to mainnet; each phase may start from its own genesis values.

### 8.1 Token Overview

| Property       | Value                          |
| -------------- | ------------------------------ |
| Symbol         | TNZO                           |
| Decimals       | 18                             |
| Maximum Supply | 1,000,000,000 TNZO (1 billion) |
| Smallest Unit  | 10^-18 TNZO                    |

TNZO supply is fixed at genesis. No TNZO is ever minted: rewards are released from a genesis-funded pool, and supply falls as fees are burned.

The TNZO token serves three functions:

1. **Utility.** Gas, network fees and settlement of paid work (payments may also settle in a stablecoin governance permits).
2. **Governance.** Voting power on network proposals proportional to staked balance.
3. **Security.** Staking collateral for validators and service providers.

### 8.2 Fee Structure

Tenzro operates two distinct fee collection mechanisms:

**1. Ledger Transaction Fees (Gas)**

- Priced in USD, the governed unit of account (USD at launch), and paid in TNZO at the in-network TNZO/USD rate (`fees.usd_rate_mode`: 0 uses the governance-set `fees.tnzo_usd_nano`, the preview's setting; 1 uses the stake-weighted median of validator rate reports within governed bands). Public market prices are never read on chain.
- Standard EIP-1559 fee market with dynamic base fee adjustment
- The governed share of the base fee is burned (all of it by default); everything else a block collects, including priority fees, goes to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%).
- Validators are paid from the rewards pool (§8.4), not from gas

**2. Network Commission Fees**

- The chain's settlement fee and treasury legs on payments to AI providers and TEE providers (below)
- Collected when callers pay providers at their own rate cards; the payee receives the payment, and node mode does not divide it

Every on-chain settlement (escrow voucher, stream and hash-lock claims, compute and storage claim hours, x402) pays the governed settlement fee, `fees.settlement_fee_bps` (0.1% at genesis), half burned and half to the treasury. A payment to a bonded provider may also carry the governed treasury leg of its class of work (`fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps`, 0 at genesis, at most 5,000 bps), taken from the provider's credit after the fee. The insurance pool takes `fees.insurance_pool_bps` (10%) of every treasury-bound fee. What a settlement may earn in rewards is bounded by its fee plus its leg (TOKENOMICS §7).

A payment in a stablecoin listed in the governed settlement-asset registry (enabled and on its peg) pays its settlement fee in that asset: the burn share goes to the treasury's stable holdings, and its TNZO equivalent is netted against the epoch's reward release and burned from the rewards pool, so supply falls as if the fee had been burned in TNZO. Gas is still paid in TNZO.

The default settlement asset and micro-settlement floor are one governance-set `EconomicPolicy` block, adjusted through on-chain proposals. There is no marketplace commission.

### 8.3 Staking

Participants bond TNZO per role, in consensus, with a `Stake` transaction (`bond`, `unbond`, `withdraw`; one stake per account per role, unbonding over a governed period). The role vocabulary is the node's `--roles` vocabulary (`NetworkRole`): `rpc`, `tee`, `ai`, `compute`, `storage`, `attestor`, `wallet`, `catalog`, `edge` bond through `Stake`, the validator role through `RegisterValidator`, and `fullnode`, `light`, `archive`, `bootstrap`, `micro` take no bond. A node comes up without a bonded role its operator has not bonded and logs the missing bond; an unbonded validator role refuses to boot. The ladder is defined in `tenzro-types/src/constants.rs` and applied by `NetworkRole::required_stake`:

| Role        | Bond           | Scales with                     |
| ----------- | -------------- | ------------------------------- |
| `rpc`       | 100,000 TNZO   | —                               |
| `validator` | 10,000 TNZO    | —                               |
| `tee`       | 10,000 TNZO    | —                               |
| `ai`        | 1,000 TNZO     | —                               |
| `attestor`  | 100,000 TNZO   | —                               |
| `wallet`    | 1,000 TNZO     | — (declares its passkey domain) |
| `catalog`   | 1,000 TNZO     | —                               |
| `edge`      | 10,000 TNZO    | — (edge relay)                  |
| `compute`   | 500 TNZO floor | Accelerators pledged            |
| `storage`   | 100 TNZO floor | Terabytes pledged               |

Two rungs scale with pledged capacity, so the bond tracks the exposure it collateralizes:

- **Compute Provider** — 1,000 TNZO per accelerator scaled by class (0.5× integrated, 1× consumer, 2× workstation, 5× datacentre), summed over everything pledged. One datacentre card plus one consumer card bonds 6,000 TNZO.
- **Storage Provider** — 100 TNZO per whole terabyte, so 50 TB bonds 5,000 TNZO.

Pledging no capacity to a scaling rung yields that rung's floor, never zero. The RPC Provider bond is among the largest (with the attestor bond) because a public endpoint brokers tenant traffic and upstream credentials, the largest trust surface any role holds. Every figure is governance-adjustable.

| Parameter        | Value                               |
| ---------------- | ----------------------------------- |
| Unbonding period | 7 days (604,800,000 ms)             |
| Slashing         | Variable, based on offense severity |

**No reward multipliers.** Rewards are work-gated (§8.4) and nothing is paid on stake. Validators are paid for consensus votes and block proposals; providers of every type, TEE providers included, are paid by the fees their settlements recorded. No provider type carries a multiplier.

Consensus weight is separate from every bond above: only the validator bond carries finality weight, so bonding for any number of service rungs cannot move a quorum.

**Staking lifecycle:**

1. **Stake.** Lock TNZO against a provider type. Must meet minimum stake requirement.
2. **Active.** Stake is active; the provider serves and is paid for the work it does.
3. **Unbonding.** Initiate unstake; stake is locked for the unbonding period.
4. **Withdrawn.** After unbonding completes, stake can be withdrawn.

**Slashing** reduces a provider's stake for provable misbehavior. Every slash is applied in consensus state by the transaction that carries its evidence, and the slashed TNZO moves into the insurance pool. Checkpoint equivocation (two signatures by one validator on different checkpoints with the same index) is proven by a `ReportCheckpointEquivocation` transaction that the VM verifies and records once; it slashes the signer's bond (genesis validators are bonded at genesis) by three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it (at least 5%, 15% for a validator that has offended before, at most the whole stake; earlier offenders are topped up when a later offence raises the rate), and every node then drops and jails the signer when it replays the log.

### 8.4 Reward Distribution

Rewards are **work-gated**, issued per epoch as coupons that claim a transfer out of the genesis-funded rewards pool rather than paid on stake. TNZO supply is fixed; nothing is minted:

| Parameter             | Value                                                  |
| --------------------- | ------------------------------------------------------ |
| Epoch duration        | 7,200 checkpoints at 500 ms (1 hour)                   |
| Reward model          | Work-gated coupons on a declining annual schedule      |
| Role buckets          | Validator, Provider, Ecosystem                         |
| Claim liquid fraction | `liquid_bps` (remainder opens 12-month reward vesting) |

**Reward calculation for each closed epoch:**

```
year          = year_for(epoch)
epoch_rights  = declining_annual_schedule(year) / epochs_per_year
(val_bps, prov_bps, eco_bps) = role_split_for(year)   // shifts infra → apps over years

For each role bucket:
  bucket_rights = epoch_rights * bucket_bps / 10000
  For each address with verified work in the bucket:
    work_share = address_work_weight / bucket_total_work_weight
    coupon     = bucket_rights * work_share            // an unclaimed claim on the pool
```

Work weight is measured by the protocol — never self-reported. Validators earn on finalized-block and quorum-certificate participation; providers on the paid work their settlements recorded (inference served, TEE sessions, RPC traffic, compute leases, storage served); the ecosystem bucket on settled usage a payer attributed to registered apps, agents and tools, never to the payee. Each settlement's reward weight is capped below what it paid in fees, parties that share an identity root earn nothing from paying each other, and nothing is paid for holding, volume, engagement or sign-ups. Rights left unmatched in a bucket, and coupons unclaimed within the claim window, lapse and stay in the pool — TNZO only leaves the pool for work that was both done and claimed. Claiming a coupon transfers the `liquid_bps` fraction from the pool immediately and opens a 12-month linear reward-vesting schedule for the remainder. Epoch reward metering is enforced sequential — epoch N is closed before N+1.

### 8.5 Treasury

The Network Treasury is a keyless vault that holds TNZO and the stable assets governance permits:

- **Keyless.** The treasury is `network_treasury_address`; no key, administrator or multisig withdraws from it. Only an enacted governance proposal moves its funds, after its timelock, during which the seated stewards may veto or hold it (never spend).
- **Fee sources.** The treasury receives its governed legs on service payments (§8.2), the unburned half of the on-chain settlement fee, and the block fees that are not burned (by default every priority fee), each less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%). No gas is paid to validators directly.

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

| Selector     | Operation     | Gas    |
| ------------ | ------------- | ------ |
| `0x01000010` | CreateEscrow  | 75,000 |
| `0x01000011` | ReleaseEscrow | 60,000 |
| `0x01000012` | RefundEscrow  | 50,000 |

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
2. On block dispatch, the Native VM derives `escrow_id`, derives the vault address, debits the payer, credits the vault via a single auditable privileged-VM payout helper, persists the `EscrowAccount{Funded}` record to RocksDB `CF_SETTLEMENTS`, and emits a receipt log carrying `escrow_id`.
3. Provider delivers the service.
4. The party the release conditions name signs and submits a `ReleaseEscrow` (vault → payee), or after expiry the payer submits a `RefundEscrow` (vault → payer). The VM re-verifies authorization before payout.

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

| Duty                                    | Funded by                                                                                                                                         | Paid by                                                                                           |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| `reconciliation { route, epoch }`       | the treasury, `settlement.reconciliation_reward` per route with a settlement lock, opened in the first block of each epoch and closed at the next | the first verified reconciliation of the route's lock in the epoch (see SETTLING_ACROSS_NETWORKS) |
| `grant_relay { agent_did, chain, seq }` | the grant's relay deposit (`agent.relay_deposit_utnzo.<family>`), opened when a grant on a chain that reports back is voided                      | the proven install of that void on the chain                                                      |

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

| Selector     | Operation   | Gas    |
| ------------ | ----------- | ------ |
| `0x01000024` | PayerSettle | 40,000 |

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

## 10. AI Model Serving and Routing

Model serving is a node role: a bonded AI provider serves models of every modality on its own hardware, through any supported engine behind one backend interface (no engine is privileged), and is paid per call through the settlement rails. Markets, listings, custom routing strategies and reputation scoring beyond the standing read from chain are harness and application code over the public surface.

### 10.1 Model Registry

The `ModelRegistry` keeps the catalog of models the network's providers serve, persisted via the storage layer (`CF_MODELS`) and rehydrated on node restart. Each entry (`tenzro_types::model::ModelInfo`) carries the model id, name, version and description, its `modality`, architecture, the provider's address, the model hash, its parameters, the provider's `RateCard`, its status, metadata, the resident artifact size and optional per-modality parameters (MoE, timeseries, vision, audio, video).

The `modality` field is a typed enum with subset semantics: a `Multimodal` model satisfies any single-modality query, `TextImage` satisfies both Text and Image queries, and so on. This lets the router dispatch a vision-language request to either a dedicated vision-language model or a fully multimodal one without separate code paths.

The registry supports filtering by modality and provider, and is durable across restarts so that the catalog survives provider churn.

### 10.2 Inference Routing

Each node routes the calls on its own API to a provider by price, latency and standing read from chain (§10.4), skips a silent or failed provider within seconds on signed heartbeats, hedges at most once and bills only the winner. A caller can filter by price, latency, location and verification level. The `InferenceRouter` strategies are:

| Strategy           | Selection Criterion                                         |
| ------------------ | ----------------------------------------------------------- |
| Lowest Price       | Provider whose rate card prices the call lowest             |
| Lowest Latency     | Provider with the fastest observed response time            |
| Highest Reputation | Provider with the highest standing read from chain          |
| Random             | Uniform random selection (for load distribution)            |
| Weighted Score     | Composite of price, latency and standing (the default)      |

Selection policy beyond these is a harness concern.

**Circuit breaker.** Each provider connection is monitored with a circuit breaker (states: Closed, Open, Half-Open). After a configurable number of failures, the provider is temporarily removed from the routing pool and periodically retested.

### 10.3 Pricing

Providers set their own prices: each publishes a `RateCard` per model, a price per metered unit (tokens, images, frames, seconds, pixel-steps and the other registered units) with a minimum charge, denominated in USD or TNZO. The network sets no provider price. A call is charged by `RateCard::charge_wei` over the units the serving machine metered, a USD card converting at the in-network TNZO/USD rate in force; the router, the settling node, the chain deciding a dispute and every SDK apply the same rule (`tenzro_model::pricing`).

### 10.4 Provider Management

The `ProviderManager` tracks provider health and performance (requests, failures, observed latency) and quarantines a provider after repeated stream failures. Routing standing comes from consensus state on each refresh: zero without a live serving bond, otherwise a governed bonded standing plus a governed availability standing scaled by the share of recent closed hours the validators' SLA verdicts found the provider available.

### 10.5 Model Downloads

`HfArtifactDownloader` fetches model weights from peers over iroh blobs first and falls back to the Hugging Face Hub, reporting progress (bytes downloaded, total size, percentage). Every downloaded or served model is recorded as a content-addressed manifest in the trust ledger, and downloads and loads are checked against the SHA-256 in the model's catalog entry and the model's verified manifest. The catalog is published data: signed entries from the publishers the operator's catalog trust list recognizes ([TRUST.md](TRUST.md#model-catalog)).

The HuggingFace Hub backend (`hf-hub`) is wired in by default; providers register a model by pointing at a HuggingFace repository and the node downloads the GGUF weights, ONNX exports, or safetensors archives directly.

### 10.6 Multi-Modal Inference Surface

The inference layer is intentionally not text-only. Three runtimes coexist behind a unified RPC surface:

**LLM runtime (llama.cpp / GGUF).** Decoder models — Llama, Qwen, Gemma, Mistral, Phi, etc. — load through `llama-cpp-2` (safe Rust bindings to llama.cpp). The runtime auto-detects model architecture from GGUF metadata and exposes both classic chat completion and a richer message shape (`ContentBlock`-typed multi-part messages) that supports image inputs, multi-turn conversations, and tool calling. Tool-call markers from common families (Qwen 3 `<tool_call>...</tool_call>`, Llama 3 JSON, generic JSON-in-tags) are parsed canonically and surfaced on the `ToolCall[]` field of the response. Streaming is implemented across the whole path (RPC → SSE → network forwarding) and preserves rich content blocks across hops.

**Vision encoder runtime (ONNX).** Foundation vision encoders — CLIP ViT-B/32, CLIP ViT-L/14, SigLIP base, SigLIP2 base, DINOv2 small/base/large — load through ONNX Runtime, built into the default `engine` feature. The runtime decodes PNG/JPEG/WebP via the `image` crate, applies Lanczos3 resize, and runs CLIP-style or ImageNet normalization (configurable per registration). Output embeddings (`[1, D]` or `[1, 1, D]`) can be L2-normalized and fed into an in-process cosine-similarity helper for image-text retrieval. The catalog lists seven verified ungated models, all under MIT or Apache 2.0.

**Timeseries forecasting runtime (ONNX).** Foundation timeseries forecasters with a single-tensor input contract — TimesFM 2.5 — load through the same ONNX Runtime backend. The runtime accepts a univariate context window `[batch, context_len]` and returns either a point forecast `[batch, horizon]` or a quantile forecast `[batch, horizon, n_quantiles]`. Multi-input encoder-decoder forecasters (T5-based families with covariate and mask channels) plug in via per-family adapters. Inference is dispatched through `tokio::task::spawn_blocking` with a `parking_lot::Mutex` per session to satisfy ORT's non-concurrent contract.

The node exposes these through dedicated RPC namespaces: `tenzro_chat` (LLM, with classic and rich shapes), `tenzro_forecast` (timeseries), and vision-encoder methods that return raw embedding vectors. All three honor the same provider registration, pricing, routing, and settlement plumbing.

### 10.7 Hardware-Adaptive Runtime

The LLM runtime adapts to whatever compute is available on the provider's machine without code changes:

| Backend    | Hardware                                                           | Activation          |
| ---------- | ------------------------------------------------------------------ | ------------------- |
| **Metal**  | Apple Silicon GPU                                                  | `--features metal`  |
| **CUDA**   | NVIDIA datacenter (A100, H100, B200) and consumer (RTX 3090, 4090) | `--features cuda`   |
| **ROCm**   | AMD datacenter (MI300X) and consumer (RX 7900 XTX)                 | `--features rocm`   |
| **Vulkan** | Cross-platform GPU (NVIDIA, AMD, Intel Arc, ARM Mali/Adreno)       | `--features vulkan` |
| **CPU**    | Always available; OpenMP-parallelized                              | Default fallback    |

This means an ordinary laptop, a workstation with a single consumer GPU, and a multi-A100 server all serve on the same network using the same binary; they just earn different volumes of inference traffic based on their measured throughput. The detected backend is published in the provider's hardware profile and visible to the routing layer.

Each provider publishes an advertised capacity in its gossip announcement — maximum concurrent requests, requests per second, batch size, and whether multi-token-prediction is enabled. Consumers rank providers on the measured throughput their own node observes (usage and reputation), and read the advertised capacity from the service registry entry; no dedicated RPC returns the two side by side.

#### Automatic hardware detection

Every node profiles its own hardware once at startup, with no operator configuration:

- **System memory** from `/proc/meminfo` on Linux and `sysctl hw.memsize` on macOS.
- **NVIDIA GPUs** via `nvidia-smi` (name, VRAM, compute capability per device) plus an NVLink probe (`nvidia-smi nvlink --status`) that distinguishes NVLink-connected multi-GPU machines from PCIe-only ones.
- **AMD GPUs** via `rocm-smi` (name, VRAM) paired with `rocminfo` gfx target discovery.
- **Apple Silicon** is treated as a unified-memory device.
- **Coherent CPU/GPU parts on Linux** are recognized structurally rather than by model name: a host with exactly one accelerator whose reported memory falls within an eighth of system RAM is holding one physical pool, and its memory is counted once. Parts whose device memory is a genuinely separate pool — including those bridged to host memory over a coherent interconnect — fall outside the test and keep the discrete accounting.

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

**Challenge lifecycle.** Any party may file a challenge against a commitment (`tenzro_fileInferenceChallenge`) with the provider's signed receipt and the inputs the receipt's `input_commitment` commits to; the challenged model and provider are read from the receipt rather than caller input, so filings cannot misattribute. A commitment can be challenged once. The filing node publishes the challenge on the gossip topic `tenzro/inference-challenges`; every validator takes it in after checking the receipt, the entropy block against its own chain and the committee draw, so every drawn seat learns it holds a seat. A seat fetches the inputs from the filing node, which serves them only to a seat that signs for them and deletes them when the challenge ends, re-executes them on its own node (`tenzro_reexecuteChallenge`), and may sign only the verdict it found. Filing draws a stake-weighted committee (weighted sampling without replacement) from the active validator set, seeded by finalized-block entropy and the commitment hash, so the draw is deterministic per dispute and grinding-resistant; the provider's own consensus key is never seated, so a provider cannot decide its own dispute. Each seat records the validator's node key and its account address. The verdict is decided by the committee, not an operator, through a signed commit-reveal vote: each drawn member commits `H(verdict ‖ salt ‖ challenge_id ‖ voter)` (`tenzro_commitChallengeVote`) and later discloses `(verdict, salt)` (`tenzro_revealChallengeVote`), which must reproduce the commit. Both carry the seat's P-256 key and its signature under the `tenzro/inference/challenge-vote` context, made on the voter's own node by its hardware identity key with `tenzro_signChallengeVote` (admin-gated); signed votes travel on the same topic, so every node holding the challenge applies them alike; the key must be the one the seat's account address commits to, and a vote without a valid seat signature is refused. The commit window and the reveal window are one hour each, and reveals open only when commits close (quorum reached or window elapsed). The quorum is `floor(2t/3) + 1` of the committee stake `t`. `tenzro_finalizeChallenge` upholds when revealed uphold stake reaches the quorum and dismisses when revealed dismiss stake does; with neither, the challenge stays open until the reveal window ends and is then dismissed (the provider prevails). Finalize is idempotent: a decided challenge returns its verdict unchanged. `tenzro_auditInferenceChallenge` lets anyone re-check a record: the draw, every signature and the tally. An upheld challenge fires the provider's existing penalty paths: routing reputation decrements through the failed-call path, and a failure is recorded against the provider's compute bond. No dedicated slashing primitive exists for inference challenges; the penalty economics reuse the reputation and bond machinery that also governs availability failures. Reputation increases only through settled payments, which prevents recovery via self-challenge. Commitments and challenges persist in `CF_CHALLENGES` and survive restarts; a node without durable storage disables the surface entirely.

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

The measurement check is a gate, not a record. The installing node is the recipient — it holds the X25519 and ML-KEM-768 secret keys the manifest names — so it proves its own enclave: it generates a fresh report whose user data commits to `SHA-256("tenzro/model/sealed-recipient" ‖ did ‖ x25519_pubkey)`, verifies that report against a pinned vendor root (simulated reports are refused), confirms the returned report actually commits to that binding, and only then compares the measurement against the pinned one. No evidence comes from a caller, so there is nothing to replay. A node with no TEE provider produces no evidence and the install is refused rather than allowed through. Manifests persist in `CF_MODELS` and hydrate on restart; they carry no key material beyond wrapped ciphertexts and are safe to distribute over any channel.

Sealing and installing are operator actions for node administrators (`tenzro_sealModel`, `tenzro_installSealedModel`). Discovery is open: `tenzro_getSealedModel`, `tenzro_listSealedModels`, and `tenzro_modelRecipientKey` (the node's X25519 recipient public key, generated at first start).

---

## 11. Agents

### 11.1 Overview

Agents run in harnesses and applications, not in the node. The protocol gives them an identity, a keyless account their owner funds, consensus Terms that bound what they may do, and the payment and settlement primitives every other account uses. Every agent has an owner, a person (passkey) or a machine (TPM or Secure Enclave), and no model-written code runs on a node.

### 11.2 Agent Identity

Each agent receives an identity upon registration, tied to its owner's:

```
AgentIdentity {
    agent_id:     String,           // Unique identifier
    address:      Address,          // On-chain address
    name:         String,           // Human-readable name
    version:      String,
    creator:      Address,          // Address that created this agent
}
```

Every agent has an owner: a person, whose key is a passkey, or an autonomous machine, whose key is in its TPM 2.0 or Secure Enclave. A delegated agent holds no key of its own: its account is keyless, funded by its owner, and it acts only under the Terms its owner's key granted, so it can never spend more than it was funded and every action traces back to the owner (onboarding: `tenzro_onboardAutonomousAgent`, `tenzro_onboardDelegatedAgent`; see [AGENT_ACCOUNTS.md](AGENT_ACCOUNTS.md)).

### 11.4 Capabilities

An agent's `Capability` (`tenzro_types::agent`) describes what it can do:

| Capability                                | Description                              |
| ----------------------------------------- | ---------------------------------------- |
| `NaturalLanguageProcessing { languages }` | Text understanding and generation        |
| `ComputerVision { formats }`              | Image analysis and generation            |
| `CodeGeneration { languages }`            | Source code generation                   |
| `DataAnalysis { formats }`                | Statistical analysis and visualization   |
| `BlockchainInteraction { chains }`        | On-chain operations                      |
| `SmartContractExecution`                  | Smart contract deployment and invocation |
| `ExternalAPIIntegration { apis }`         | Integration with external services       |
| `MultiAgentCoordination`                  | Orchestrating multi-agent workflows      |
| `Custom { name, parameters }`             | User-defined capabilities                |

### 11.5 Agent-to-Agent (A2A) Protocol

The A2A protocol enables structured inter-agent communication following the Google A2A specification. Each Tenzro node runs a full A2A protocol server (default port 3002):

**A2A Server Endpoints:**

| Endpoint                       | Method | Purpose                                                  |
| ------------------------------ | ------ | -------------------------------------------------------- |
| `/.well-known/agent-card.json` | GET    | Agent Card discovery (signed)                            |
| `/a2a`                         | POST   | JSON-RPC 2.0 dispatcher (SSE for `SendStreamingMessage`) |

**Agent Card.** Each node publishes an A2A 1.0 Agent Card at `/.well-known/agent-card.json`, signed with a detached JWS by the machine's identity key (TPM or Secure Enclave) under the machine DID that key derives; a node that cannot sign serves no card. The card advertises the node's capabilities, skills, supported input/output modes, authentication requirements, and protocol version 1.0. Up to 21 skills are advertised: wallet, identity, inference, settlement, verification, staking, token, contract, join, bridge, compliance, events, adaptive-burn, iroh-transport, urwa, bridge-fee-in-tnzo, storage, compute, moe, media-gen and discovery. The signature says who published the card, not what the node can do, so the node lists a skill only while it serves what the skill needs: the model skills (inference, moe, media-gen) while it runs with the model-serving role in a build that can run models, storage and compute while it runs with those roles, iroh-transport while its iroh endpoint is bound. A node runs with a bonded role only while it holds that role's bond, and the card is signed again when the list changes.

**JSON-RPC Methods:**

- `SendMessage` / `SendStreamingMessage` — Send a message to create or continue a task
- `GetTask` — Query one of the sender's own tasks (with optional history length limit); another DID's task reads as not found
- `ListTasks` — List the sender's own tasks (optionally filtered by context ID)
- `CancelTask` — Cancel a running task

**Task lifecycle:**

```
Submitted → Working → Completed
                    → Failed
                    → Canceled (via CancelTask)
```

The `TaskManager` stores tasks in a concurrent `DashMap<String, A2aTask>`, with each task tracking its state, message history, and artifacts. Every change to a task is written through to the node's store, and a restarted node takes its tasks back; a task that was still running when the node stopped is reported as failed, and one waiting for the caller's input stays open. Tasks do not accumulate without end. The `[a2a_tasks]` section of the node's configuration sets, each within bounds the node checks at start: `retention_secs` (default 86400, 60 to 2592000), after which a completed, failed or canceled task is removed; `input_deadline_secs` (default 3600, 60 to 604800), after which a task still waiting for its sender's input is failed; `max_per_principal` (default 256, 1 to 100000) and `max_total` (default 16384, 1 to 1000000), the most tasks one sender DID and the node hold; `max_history` (default 200, 2 to 10000), the most messages one task's history holds, past which a further message to that task is refused with -32051; `max_artifact_bytes` (default 1048576, 1024 to 67108864), the most bytes one task's artifacts hold, past which the task fails rather than keep part of an answer. A sender or node at its limit gives up its oldest finished task to make room; when every task it holds is still open, a new `SendMessage` is refused with error -32051. The server answers each task itself, from a read-only answer chosen by content analysis (wallet queries, block lookups, identity operations, model discovery, network status) or a typed `readEvents` read; it does not hand a task to another worker or provider. A2A is the node's front door and audit surface for agents, not a task marketplace: value moves only through signed transactions, and every call is recorded and signed by the node (see AGENT_TRUST.md).

**Streaming.** `SendStreamingMessage` on `/a2a` provides real-time task updates via Server-Sent Events (SSE). Clients receive the task as it transitions through states.

### 11.6 MCP Server

Each Tenzro node runs a Model Context Protocol (MCP) server (default port 3001) using the `rmcp` crate with Streamable HTTP transport. This exposes node capabilities as MCP tools that any MCP-compatible AI agent can invoke programmatically.

**Server configuration:**

- Protocol version: `2026-07-28` only; every request carries the revision's `_meta`, and `initialize` is not served
- Transport: Streamable HTTP (endpoint: `/mcp`), stateless: `server/discover`, per-request `_meta`, no sessions
- Capabilities: Tools and resources (with subscriptions)
- Authorization: OAuth 2.1 with a passkey login on `/authorize`, Client ID Metadata Documents, RFC 8707 audience-bound tokens and RFC 9207 `iss`
- Server name: `tenzro`

**Available tools**: a tool for every served method, spanning wallet & ledger, network & blocks, identity & delegation (including right-to-erasure via `forget_identity`), payments (AP2 mandate verification, ERC-8004 Trustless Agents Registry, MPP, x402), AI models & inference (multi-modal: forecast, vision, text-embed, segmentation, detection, audio ASR, video), cross-chain bridge, verification (ZK, VRF, attestations), staking & providers, tokens & contracts, NFTs, agent accounts and Terms, compliance, TEE, and event subscriptions. An opt-in compact mode exposes `search` plus `call`, so an agent loads only the methods it needs, under the same authorization and Terms. Representative samples:

| Group                 | Example Tools                                     |
| --------------------- | ------------------------------------------------- |
| Wallet & Ledger       | `get_balance`                                     |
| Network & Blocks      | `get_node_status`, `get_block`, `get_transaction` |
| Identity & Delegation | `register_identity`, `resolve_did`                |
| Payments              | `create_payment_challenge`, `verify_payment`      |
| AI Models & Inference | `list_models`, `list_model_endpoints`             |
| Verification          | `verify_zk_proof`, `verify_vrf_proof`             |
| Stakes & Providers    | `get_role_stakes`, `get_provider_stats`           |
| Tokens & Contracts    | `deploy_contract`                                 |

All tool parameter schemas are generated via `schemars::JsonSchema` for automatic schema discovery by MCP clients. Tools delegate to the node's subsystems (`Arc<TenzroNode>`, `Arc<WebState>`) for actual data access and transaction submission.

### 11.7 OpenClaw Skill Integration

An OpenClaw-compatible skill definition (`skills/openclaw-tenzro/SKILL.md`) allows OpenClaw agents to interact with the Tenzro blockchain. The skill provides structured instructions for:

- Connecting to Tenzro's JSON-RPC, Web API, MCP, and A2A endpoints
- Creating wallets and checking balances
- Sending transactions
- Registering and resolving identities
- Verifying proofs and checking node status

### 11.8a Pre-approved Bounds and Credentials

- **Pre-approved bounds.** Terms may carry `auto_approve`, bounds the controller pre-approved for the agent's scope. A proposed scope stays within them when every limit is at or below the bound's, every list is within the bound's list, and every term the bounds do not name is no looser than in the current terms (`within_bounds`). Changing the terms on chain still takes the root's approval.
- **Organizations of agents** (members, roles, scope change requests and extra refusal rules) are not consensus state. They live in a harness over delegation terms: the harness decides who may ask for what, and every change it makes still lands as terms the agent's root approved.
- **Brokered credentials.** Terms may carry third-party secrets sealed by the controller to each serving node's hardware sealing key, each for one HTTPS host and header. The node's egress path opens the envelope with a key derived from its hardware for that one request and attaches the header; the agent never holds the secret, cannot set that header itself, and every attachment is in its audit trail.

### 11.8b Owned, Funded Agents

Every agent has an owner: a person (passkey) or an autonomous machine (TPM). Its identity and wallet hang off the owner's, so every action it takes is auditable through that lineage. The owner funds the agent's wallet, and the budget is the funding: a task can never spend more than was put in. Per-payment approval is optional and lives in the harness or wallet, not the protocol. The protocol controls the owner (the agent's controller) holds:

| Transaction         | Effect                                                                                                                                                                                                                                                                   |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PauseAgent`        | The agent pays nothing while paused; inbound payments still arrive. A pause also suspends refills.                                                                                                                                                                       |
| `ReclaimAgentFunds` | Moves the agent wallet's TNZO back to the controller: all of it, or a set amount. Works whatever the agent's state.                                                                                                                                                      |
| `SetAgentTopUp`     | Allows refills from the controller's wallet within an allowance: the most moved per period, the period, the balance a refill brings the wallet up to, and an expiry; `None` cancels it. The expiry must fall within the governed `agent.topup_max_days` (90 at genesis). |
| `TopUpAgent`        | Performs one refill within the allowance. Anyone may send it.                                                                                                                                                                                                            |

Unusual-spending alerts, per-action approval prompts and anomaly detection are harness and wallet features built on the chain's signals (per-agent spend counters, Terms, an event per action).

---

## 12. Tenzro Decentralized Identity Protocol (TDIP)

### 12.1 Overview

Tenzro Decentralized Identity Protocol (TDIP) provides a unified decentralized identity system for the Tenzro Network. The protocol recognizes **three identity classes** — humans, delegated machines and agents (under a controller, which is a person or a hardware-rooted machine), and hardware-rooted machines (anchored by their own TPM or Secure Enclave, with no controller) — all under a single `did:tenzro:` namespace; institutions (`did:tenzro:institution:{lei}:{uuid}`) are also supported.

Every person and machine holds its key in hardware: a passkey for a person, a TPM 2.0 or Secure Enclave for a machine (or, for a Linux or macOS machine without one, another machine's TPM through the key holder). A delegated agent holds no key of its own: its account is keyless, funded by its owner, and it acts under the Terms its owner granted. Every identity has a set of verifiable credentials and a W3C DID Document representation.

### 12.2 DID Formats

```
did:tenzro:human:{uuid}                    — Human identity (KYC-tiered)
did:tenzro:machine:{controller}:{uuid}     — Delegated machine or agent (under a person or a hardware-rooted machine)
did:tenzro:machine:{uuid}                  — Hardware-rooted machine (anchored by its own TPM or Secure Enclave)
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

| Tier       | Level |
| ---------- | ----- |
| Unverified | 0     |
| Basic      | 1     |
| Enhanced   | 2     |
| Full       | 3     |

A tier is not a central registry entry: each relying party derives it from the W3C credentials its own trust list recognizes, issued by anyone (see [TRUST.md](TRUST.md)). KYC tiers are ordered — a tier comparison like `tier >= Enhanced` is supported for access control decisions.

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

An empty allowlist (e.g., empty `allowed_operations`) means all values are permitted. The scope is part of the identity record; the authority that decides what a delegated agent may spend is its consensus Terms (§11.8b, [AGENT_ACCOUNTS.md](AGENT_ACCOUNTS.md)), recorded with `SetAgentTerms` under its root's passkey or hardware-key approval and checked by every validator on each `AgentAct` and by every payment entry point. No node keeps a second authority store.

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

1. **Revoke** — Submit a signed `RevokeIdentity` transaction carrying the root's approval with `tenzro_revokeIdentity` (any account may send it). Once it lands every node marks the identity `Revoked` (cascading to the agents it delegated and the machines it controls), and revokes the access tokens it issued to or through it.
2. **Forget** — Once propagation has settled, call `tenzro_forgetIdentity { did }` to hard-delete the identity from `CF_IDENTITIES` and the in-memory `IdentityRegistry`. The DID must already be in `Revoked` status; calling forget on an `Active` identity returns an error.

Forget is irreversible. The DID becomes unresolvable on this node; bound credentials and delegation scopes are dropped. Audit-trail receipts that referenced the DID remain — only the live identity record is erased. CLI: `tenzro identity forget <did>`. MCP tool: `forget_identity`.

---

## 13. Payment Protocols

### 13.1 Overview

Tenzro supports agentic payment protocols whose value the chain settles. Each protocol is a mapping over the one payer-authorized settlement primitive, and a delegated agent pays only inside its consensus Terms whichever protocol it uses (`tenzro-payments::terms_gate`). Card, bank and processor rails enter only as attested records from bonded attestors (§2.4); they are labelled and capped apart from payments native to the ledger or proven from another chain. The HTTP 402 protocols share one flow: a server issues a payment challenge, a client creates a payment credential, and the server verifies and settles.

The `tenzro-payments` crate implements them behind a unified `PaymentProtocol` trait and a `PaymentGateway` that routes across them.

### 13.2 Supported Protocols

#### Crypto rails — Tenzro settles the value

| Protocol                                 | Origin          | Use Case                                                                                                                                  |
| ---------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| **ERC-8004** (Trustless Agents Registry) | Ethereum        | Identity / Reputation / Validation registry surfaces — see §13.8                                                                          |
| **MPP** (Machine Payments Protocol)      | Stripe / Tempo  | Session-based machine payments with HTTP 402                                                                                              |
| **x402**                                 | x402 Foundation | HTTP 402 payments (wire version 2): payer-signed Tenzro credentials settled on the ledger, or EIP-3009 / Permit2 on the payer's EVM chain |
| **ACP** (Agentic Commerce Protocol)      | Seller side     | Checkout sessions completed with an x402 payment payload (`/acp/checkout_sessions`)                                                       |
| **UCP** (Universal Commerce Protocol)    | Business side   | Checkout sessions with the AP2 mandates extension, completed through the Tenzro x402 handler (`/checkout-sessions`)                        |
| **Direct**                               | Tenzro native   | On-chain settlement in TNZO or a permitted stablecoin                                                                                     |
| **Channel**                              | Tenzro native   | On-chain escrow plus cumulative payer-signed vouchers (§9.4)                                                                              |

#### Card, bank and processor rails

These rails settle off chain. A payment on one enters the ledger only as an attested record from a bonded attestor that connected the rail under its own relationship; a payee's evidenced dispute slashes the attestor's bond.

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

AP2 v0.2 mandates are SD-JWT VCs (`dc+sd-jwt`, ES256), told apart by `vct`: a closed Checkout Mandate (`mandate.checkout.1`, one merchant-signed checkout), a closed Payment Mandate (`mandate.payment.1`, one payment for that checkout) and an open Payment Mandate (`mandate.payment.open.1`, constraints plus the agent key in `cnf`).

A mandate never grants authority. The paying agent's Terms decide every payment; a mandate can only narrow what the Terms already allow, and a payment that passes its mandates still has to pass the Terms. Verification is stateless: nothing is stored, and a constraint that could only be enforced by remembering earlier payments (`payment.budget`, `payment.agent_recurrence`) is refused, to be expressed instead as the Terms' period limits.

Who signs what: the merchant signs the checkout (ES256), and the closed Payment Mandate's `transaction_id` is the hash of that JWT; the closed Payment Mandate is signed by the agent's controller (the `controller_did` of its Terms), or, when an open Payment Mandate the controller signed is presented beside it, by the agent key that open mandate names in `cnf`; the open Payment Mandate is signed by the controller. Mandates ride in x402 payload `extensions` and in UCP's AP2 mandates extension, and are checked where the payment settles (`tenzro-payments::ap2`).

### 13.5 MPP (Machine Payments Protocol)

MPP, co-authored by Stripe and Tempo, provides session-based HTTP 402 payments:

- **MppChallenge** — Issued by the server with amount, asset, recipient, and chain
- **MppCredential** — Created by the client, signed with the payer's wallet
- **MppReceipt** — Returned after settlement with transaction reference
- **MppSession** — Tracks ongoing payment relationships between payer and payee
- **MppSessionManager** — Thread-safe session lifecycle management
- **MppPaymentServer** — HTTP handler that issues 402 responses

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
`Payment-Authorization: Payment <base64url>` (the header its challenge's `header` parameter asks for, so a client keeps its `Authorization` header for its own credentials), `Authorization: Payment <base64url>` or `Payment-Credential`, and settles it
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
A payment in a stablecoin governance listed in the settlement-asset
registry settles on the ledger in that asset (§8.2). Payments under `exact-eip3009` / `permit2` settle on
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

### 13.7 Terms-Bound Payments

A payer that is a delegated agent pays only inside its consensus Terms: the scope, the per-transaction and per-period limits, the counterparties and chains its root granted. The node implements the one `TermsGate` check over consensus state for every payment entry point; nothing else decides whether an agent may pay, and escrow-backed payment channels count against the same limits.

### 13.8 ERC-8004 Trustless Agents Registry

ERC-8004 (Jan 2026 revision) defines three on-chain registries (Identity, Reputation, Validation) for discovering and trusting agents across heterogeneous principal chains. Tenzro implements byte-identical selectors so the same calldata works against either the registry contracts on Tenzro (part of genesis, at the addresses of the upstream reference deployment) or any Ethereum deployment. `agentId` is a sequential `uint256` (1-indexed) allocated by the registry at `register*()` time — it is server-allocated, never derivable client-side. The TDIP `IdentityData::Machine.erc8004_agent_id` field captures the allocation for cross-system lookup.

Calldata for the three registries is built client-side from the published selectors; the node serves no encoding RPCs.

### 13.9 HTTP Middleware

The `tenzro-payments` crate provides axum middleware for automatic payment handling:

- Servers wrap their routes with payment middleware to auto-issue 402 challenges
- Clients use payment-aware HTTP clients that auto-create credentials

### 13.10 Feature Flags

| Flag   | Default | Description                       |
| ------ | ------- | --------------------------------- |
| `mpp`  | Enabled | Machine Payments Protocol support |
| `x402` | Enabled | Coinbase x402 protocol support    |

---

## 14. Cross-Chain Bridge

### 14.1 Overview

TNZO moves between Tenzro and external chains over one path: governed routes
in the route framework (`tenzro_bridge::route`). A route joins Tenzro to one
external chain over one transport.

| Transport  | Chain family        | Chains                                                                                                   |
| ---------- | ------------------- | -------------------------------------------------------------------------------------------------------- |
| `ccip`     | EVM                 | Ethereum, Base, Arbitrum, Optimism, BNB Chain, Avalanche C-Chain, Polygon PoS (CCIP-compatible envelope) |
| `ccip`     | Solana              | Solana (CCIP-compatible envelope)                                                                        |
| `ibc`      | Cosmos              | CometBFT chains (ICS-20 packets; Tendermint light client, ICS-23 proofs)                                 |
| `deposit`  | Bitcoin             | Bitcoin (deposits to a governed script; SPV header-chain client; inbound only)                           |
| `contract` | Sui, Aptos, Stellar | Tenzro's bridge contract (checkpoint, ledger-info and SCP light clients)                                 |
| `contract` | TON                 | Tenzro's bridge contract (committee only, committee-only mint limits)                                    |

### 14.2 Rules

Every route is installed by governance and every rule is enforced by the
framework: strict canonical decoding; committee (and on CCIP routes, an
independent blessing committee) signatures over a digest binding this chain's
id, the route, a nonce and an expiry; light-client proofs where a route
requires one; a circuit breaker; per-transfer and per-epoch caps; and the
supply invariant, by which the representation outstanding on the external
chain never exceeds the TNZO locked on Tenzro for the route.

### 14.3 Interfaces

| RPC                                                 | Purpose                                                                                       |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `tenzro_listBridgeRoutes` / `tenzro_getBridgeRoute` | Routes with caps, epoch usage, supply, mode, placeholders and why a route cannot open         |
| `tenzro_getBridgeOutbound`                          | An outbound record by sequence; for a Bitcoin route, the withdrawal and its per-input digests |
| `Bridge` outbound transaction                       | Holder-signed transfer out; locks TNZO in the route vault and queues the outbound message     |
| `Bridge` inbound transaction                        | Committee-attested delivery in, signed and paid for by its relayer; credits the recipient     |
| `tenzro_getBridgeCircuit`                           | Records that disable or pause a route                                                         |

Attested data messages (agent account reports inbound, settlement mirrors
outbound) use the same envelope and rules and move no TNZO.

## 15. Self-Custody, Wallets, and Key Management

Tenzro is self-custodial for every identity class. No node, validator, partner platform or service provider holds the material required to authorize a transaction on someone's behalf. Every key is rooted in a TPM, a Secure Enclave or a passkey; there are no seed phrases, and no private key is stored in the clear.

### 15.0 Design Principles

**1. Hardware-held keys, never software keys, never seed phrases.** A person's key is a passkey in a platform or roaming authenticator. A machine's key is generated inside its own TPM 2.0 or Secure Enclave. A Linux or macOS machine without one keeps its key in another machine's TPM through the key holder (`tenzro-node tpm serve` on the provider, `tenzro-node tpm key-holder` on the client, approved by a passkey grant; [NODE.md](NODE.md#raspberry-pi-and-other-edge-devices)); Windows cannot use the key holder, which needs a Unix socket. A TEE is an execution environment, not a key store: no key is kept or derived inside one.

**2. Custody lives in consensus.** A passkey account's keystore (linked passkeys, policy, recovery signers and any recovery in progress) is chain state, and every validator verifies the passkey assertion on each of the account's transactions against it (§4.8).

**3. Agents hold no key.** Every agent has an owner, a person (passkey) or a machine (TPM or Secure Enclave). The agent's account is keyless and funded by its owner, and every spending or operational ceiling (limits, scope, expiry, counterparties, payment protocols) is its consensus Terms, approved by its owner's passkey or hardware key and checked by the VM on every `AgentAct` and by every payment entry point over the same chain state. A serving node signs an agent's actions with a hardware key the owner named in the Terms; no node keeps a second authority store, so a node operator cannot widen an agent's authority.

**4. No software fallback.** A passkey signer never falls back to a software key, and a client without a platform authenticator uses the FIDO hybrid transport (QR plus Bluetooth proximity) so another device's passkey signs.

**5. Hybrid post-quantum at every layer the standards permit** (§15.5).

**6. One custody model.** There is no server-custodial configuration, no reconstruct-on-the-node key assembly, and no alternate provisioning path an operator can select. Partner platforms provide the experience, never custody of keys or funds.

### 15.1 Identity Classes and Keys

| Class               | Key                                                                                                | Recovery                                                                                  |
| ------------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Person**          | Passkey (P-256) with its hardware ML-DSA-65 companion where the device holds one                   | Any linked passkey, or the account's recovery signers after a wait during which the recovery can be cancelled |
| **Machine**         | P-256 inside its TPM 2.0 or Secure Enclave, ML-DSA-65 derived from the same root (or a key holder) | Re-register under a new hardware key                                                      |
| **Delegated agent** | None of its own; a keyless account its owner funds, acting under consensus Terms                   | Its owner reclaims funds (`ReclaimAgentFunds`), pauses it or revokes it                   |

### 15.2 P-256 (secp256r1) Precompile

Platform authenticators use P-256. Tenzro implements the EIP-7951 (RIP-7212 interface) precompile with mainnet gas pricing:

| Property         | Value                                                              |
| ---------------- | ------------------------------------------------------------------ |
| Address          | `0x0000000000000000000000000000000000000100`                       |
| Gas cost         | **6,900** (matches EIP-7951 mainnet, not the 3,450 rollup variant) |
| Input length     | 160 bytes — `hash(32) ‖ r(32) ‖ s(32) ‖ x(32) ‖ y(32)`             |
| Output (success) | 32 bytes: `0x000…001`                                              |
| Output (failure) | empty bytes — the precompile **never reverts**                     |
| Curve            | secp256r1 (NIST P-256), uncompressed public key encoded as `x ‖ y` |

### 15.3 Ethereum Account Abstraction in the EVM

The EVM keeps Ethereum's account abstraction byte-exact (§4.8): ERC-4337 v0.9 encodings, ERC-7579 module encodings, EIP-7702 type-4 delegation (§4.8a), and the ERC-7484 module registry address `0x000000000069E2a187AEFFb852bF3cCdC95151B2` pinned as the default attestation registry. The node serves no bundler: an EntryPoint deployed in the EVM is called with an ordinary transaction, and a passkey account sends and pays for its own native transactions.

### 15.4 Hardware-Held Machine Keys

For machines, the signing key is created inside the machine's TPM 2.0 or Secure Enclave and never leaves it; a Linux or macOS machine without one keeps the key in another machine's TPM through a key holder, and its identity root is reported as `tpm-delegated` ([NODE.md](NODE.md#raspberry-pi-and-other-edge-devices)). The machine DID is derived from the attestation key, so a machine cannot claim a DID another key owns. TPM evidence (an AK quote over a node-issued nonce, activated against the EK) and TEE reports are reputation signals; neither is required to register, and neither holds a key.

Tenzro's own ERC-8004 registry contracts (IdentityRegistry at `0x8004A818BFB912233c491871b3d84c89A494BD9e`) are part of genesis and follow the upstream semantics: ERC-8004 assigns a sequential ERC-721 `tokenId` at registration, not a `keccak256` of the DID string, so cross-registry calldata interop holds.

### 15.5 Hybrid Post-Quantum Behavior

| Layer                                                                                                                                                      | Classical                 | PQ companion                                                                            | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Native ledger transaction signing                                                                                                                          | P-256 (hardware)          | ML-DSA-65 (FIPS 204), mandatory                                                         | Both signatures are attached and the verifier requires both, against the key the account enrolled. An account with no key enrolled is refused until its enrolment transaction, which is verified against the key it enrols. Transactions in an external standard (EVM secp256k1) are verified by that standard and stay classical.                                                                                                                                                                                                                                                                                                                                                                                                 |
| Passkey / WebAuthn | P-256 | ML-DSA-65 enrolled for the P-256 key in chain state | The WebAuthn assertion is single-curve by spec. Where the device holds a hardware ML-DSA-65 key (the desktop app requires one), it is enrolled with `AccountKeys` and every signature must then carry that leg. |
| TLS / RPC transport                                                                                                                                        | X25519                    | ML-KEM-768 (FIPS 203)                                                                   | X25519MLKEM768 offered first for RPC, MCP and A2A, with X25519 alone as the fallback. Certificates (WebPKI) are classical.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Node-to-node transport (iroh QUIC)                                                                                                                         | X25519                    | ML-KEM-768                                                                              | Endpoints offer and accept only X25519MLKEM768: a peer offering a classical share alone, on a fresh or a resumed session, is refused, and a classical hint in a session store cannot make a node send one. Relay HTTPS, relay records and address lookup keep X25519 as a fallback for TLS terminators without the hybrid.                                                                                                                                                                                                                                                                                                                                                                                                         |
| Endpoint authentication                                                                                                                                    | Ed25519 (iroh TLS)        | ML-DSA-65, mandatory: the machine's hardware ML-DSA key, bound to the endpoint record   | On a connection each side signs the connection's TLS exporter with both hardware keys of its machine (P-256 and the ML-DSA-65 key its record binds), so a party relaying a forged Ed25519 handshake cannot pass the proofs on. A peer whose record carries no verified binding, or that has no hardware keys to prove with, is refused in both directions, and the A2A, MCP and MoE protocols are served only on their versioned ALPNs. Pins of each identity's hardware ML-DSA key are kept across restarts; a later record without the binding, or bound by another key, is refused. Block sync, state sync, gossip and blobs authenticate the endpoint by Ed25519 under the hybrid key exchange (see docs/PQ-AND-AI-SAFETY.md). |
| Validator consensus keys                                                                                                                                   | ECDSA P-256 or P-384      | ML-DSA-65 or ML-DSA-87                                                                  | Composite `COMPSIG-MLDSA65-ECDSA-P256` (the default) or `COMPSIG-MLDSA87-ECDSA-P384`, both held in the TPM (the second needs a TPM in the validator's own machine that implements ML-DSA and P-384; a key holder does not carry it), selected by `consensus_key_scheme` in the node config. A registered validator rotates to the configured scheme on chain and signs with the new key from the epoch boundary that seats it, without a restart.                                                                                                                                                                                                                                                                                  |
| Validator machine identity                                                                                                                                 | P-256                     | ML-DSA-87                                                                               | A validator whose consensus key does not name its machine (ML-DSA-87 / P-384) registers its machine identity on chain, signed by both machine keys, so peers hold its endpoint records to the machine's ML-DSA key from the first record. Behind `staking.validator_machine_identity.status`.                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Stored records (receipts, billing, SLA answers, availability attestations, tool-call records)                                                              | Ed25519 session signature | ML-DSA-65 session signature                                                             | Signed with session keys the hardware identity certifies. From `session.hybrid_records_from_ms` (governed; the highest value means never) a record without the hybrid signature is refused. Certificate checks are cached.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Randomness beacon                                                                                                                                          | Ed25519 VRF               | Hash commit-reveal of hardware-derived secrets                                          | Once governance enables `beacon.commit_reveal.status`, each contribution commits to the validator's next 32-byte secret and reveals the last one, and the mix takes the revealed secret beside the VRF output, so the beacon stays unpredictable while the hash holds even if the VRF does not. The secrets derive from the hardware root, so nothing is stored.                                                                                                                                                                                                                                                                                                                                                                   |
| Vouchers for channels on other chains                                                                                                                      | P-256                     | WOTS+ one-time keys (SHA-256, Winternitz 16) under a Merkle root the channel commits to | Each voucher spends one leaf; verifying one costs about 600 SHA-256 evaluations and no elliptic-curve arithmetic. Keys derive from the hardware root, and the count of spent keys is flushed before a signature leaves the node, so no key signs twice.                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Private model key release                                                                                                                                  | X25519                    | ML-KEM-768                                                                              | A model's content key is sealed to a key the attested environment made in memory for one release (`x25519-mlkem768-hkdf-sha256-aes-256-gcm`); reading it needs both exchanges broken. See [AI.md](AI.md#51-private-weights-attestation-bound-key-release).                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Key wraps at rest (model content keys, the provider's content key held for its hardware, node credentials, session continuity, brokered agent credentials) | X25519                    | ML-KEM-768                                                                              | Envelope version 2: the data key is sealed to a hybrid X25519 + ML-KEM-768 key derived on demand from the machine's hardware root (the two halves under separate derivations), by HKDF-SHA256 over both shared secrets, salted with a transcript of the recipient key, the sender's X25519 share and the ML-KEM-768 ciphertext, under a per-use context. A changed part of the envelope, or an exchange broken alone, does not open it.                                                                                                                                                                                                                                                                                            |

### 15.6 Recovery and Revocation

Recovery changes the keystore in consensus; no key material is reconstructed:

- **Person accounts** recover through any linked passkey, or through the account's recovery signers after a governed wait during which the recovery can be cancelled (by whom: [security/wallet-custody.md](security/wallet-custody.md)). Each recovery signer is an independent hardware-rooted key on its own device; no key is split, shared or dealt.
- **Delegated agents** answer to their owner: the owner pauses the agent (`PauseAgent`), returns its funds (`ReclaimAgentFunds`), changes its Terms or revokes it. After revocation nothing signed for the agent is paid on any operator's channel.
- **Machine accounts** rotate by registering a new hardware key.

Identity revocation is a consensus transaction: a `RevokeIdentity` carrying the root's approval, re-verified by every validator and mirrored into every node's registry through `IdentityRegistry::revoke_from_chain()` (see §12).

### 15.7 Developer Experience

The Rust and TypeScript SDKs build and sign transactions for an account whose keystore authorizes them, and never hold a key. The TypeScript SDK exposes a pluggable `Signer` interface (a signer signs a 32-byte digest with a passkey or a hardware key, and describes itself as WebAuthn, TPM or Secure Enclave backed, HSM or custom), so custom wallets, HSM integrations and air-gapped flows extend it without forking the SDK. The Rust SDK's passkey client (`PasskeyClient`) mirrors the node's passkey RPCs, and its keystore module encodes keystore changes and recovery approvals.

#### Desktop application

The desktop application runs passkey ceremonies in its Rust process, not the WebView, because the key lives in the platform's secure hardware and the cross-device ceremony needs Bluetooth and the CTAP2 stack:

| Platform | Hardware key location                                                                                                      |
| -------- | -------------------------------------------------------------------------------------------------------------------------- |
| macOS    | Secure Enclave                                                                                                             |
| Windows  | TPM 2.0 over TPM Base Services; keys read from the persistent handles `tenzro-node tpm provision` makes, EK from 0x81010020 |
| Linux    | TPM 2.0 over `/dev/tpmrm0`; the same persistent handles; no software fallback                                              |

A passkey is a pair of hardware keys under one label: a P-256 key the platform will not export and an ML-DSA-65 key for the post-quantum leg; hardware that cannot hold the ML-DSA-65 key is refused. Cross-device flows use the FIDO hybrid transport through `webauthn-authenticator-rs`. Tauri commands exposed: `device_create_passkey`, `device_sign_with_passkey`, `device_sign_hybrid_with_passkey`, `device_start_cross_device_link`, `device_complete_cross_device_link`, `device_cancel_cross_device_link`.

### 15.8 Onboarding

`tenzro_onboardHuman` provisions a human identity and its wallet from a passkey:

1. The client device runs a WebAuthn passkey ceremony; the private key never leaves the device.
2. The caller proves possession of the passkey and its ML-DSA-65 key over a custody challenge before anything is created.
3. A TDIP DID derived from the passkey (`did:tenzro:human:{id}`) is registered and persisted (`CF_IDENTITIES`), and its account derived; the keystore is the passkey alone until the account's first keystore change.
4. The response returns the identity, the wallet and a DPoP-bound access token.

A machine identity is rooted in a P-256 key created in its TPM 2.0 or Secure Enclave (or through a key holder). Clients: the CLI (`tenzro join`) and the desktop application's setup page.

---

## 16. Peer-to-Peer Networking

### 16.1 Protocol Stack

The networking layer is built on iroh with the following protocols:

| Protocol                                                               | Purpose                                                                                                                                                                  |
| ---------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Gossip (iroh-gossip, ALPN `tenzro/gossip` on the node's iroh endpoint) | Topic broadcast for blocks, transactions, certificates and announcements; each message is checked before it is passed on, and neighbours are scored on what they deliver |
| Identity endpoint records                                              | Each machine signs the record naming its iroh endpoint and relays; knowing one Tenzro node is enough to learn the rest                                                   |
| Relays                                                                 | Reach a node that cannot be dialed directly, admitted by their operators' signed records                                                                                 |
| Point-to-point ALPNs                                                   | Consensus, block sync, state sync, inference and other request/response protocols, each on its own ALPN                                                                  |
| QUIC + TLS 1.3 (X25519MLKEM768)                                        | Transport encryption and stream multiplexing                                                                                                                             |

### 16.2 Gossip Topics

| Topic                 | Content                                                                                                                           |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `tenzro/blocks`       | Block propagation                                                                                                                 |
| `tenzro/transactions` | Transaction propagation                                                                                                           |
| `tenzro/certificates` | Checkpoint certificates, for followers (validators exchange consensus messages over the iroh ALPN `tenzro/consensus`, not gossip) |
| `tenzro/models`       | Model registry updates                                                                                                            |
| `tenzro/status`       | Node status and peer discovery                                                                                                    |
| `tenzro/agents`       | Agent-to-agent messages and task coordination                                                                                     |

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

| Column Family     | Content                                                                            |
| ----------------- | ---------------------------------------------------------------------------------- |
| `CF_BLOCKS`       | Block headers and bodies                                                           |
| `CF_STATE`        | Account state and contract storage                                                 |
| `CF_ACCOUNTS`     | Account metadata                                                                   |
| `CF_TRANSACTIONS` | Transaction receipts and indices                                                   |
| `CF_METADATA`     | Chain metadata (latest height), snapshot index, state-sync progress                |
| `CF_SETTLEMENTS`  | Settlement receipts and escrow state                                               |
| `CF_CHANNELS`     | Micropayment channel state                                                         |
| `CF_CHALLENGES`   | Payment challenges (MPP/x402) + TOPLOC inference commitments and challenge records |

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

| Parameter                                          | Value                         |
| -------------------------------------------------- | ----------------------------- |
| Memory budget (block cache with memtables charged) | 512 MiB                       |
| Write buffer size                                  | 64 MB                         |
| Snapshot retention                                 | 2 (`[snapshot] retain_count`) |

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

| Rule                                            | Genesis value                                         |
| ----------------------------------------------- | ----------------------------------------------------- |
| Quorum (`governance.quorum_bps`)                | 3,334 bps of all bonded stake                         |
| Standard threshold (`governance.threshold_bps`) | 6,667 bps of participating stake                      |
| Expedited and security-fix threshold            | 8,000 bps                                             |
| Large spend (from 100,000 TNZO)                 | 7,500 bps of all eligible stake and a 14-day timelock |
| Voting period                                   | 3 days; timelock 2 days                               |
| Minimum bond age to weigh in a vote             | 7 days                                                |

A proposal keeps the rules it opened under. A parameter change that only pauses
a feature runs on the expedited track.

### 18.3 Execution and Brakes

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

| Layer        | Mechanism                                                                                    | Protects Against                   |
| ------------ | -------------------------------------------------------------------------------------------- | ---------------------------------- |
| Consensus    | BFT quorum (2f+1)                                                                            | Byzantine validators, equivocation |
| Cryptography | Ed25519 + Secp256k1 signatures                                                               | Forgery, impersonation             |
| TEE          | Hardware attestation                                                                         | Tampered execution environments    |
| ZK           | Plonky3 STARK proofs                                                                         | False computation claims           |
| Economics    | Stake slashing                                                                               | Rational adversaries               |
| Network      | Message deduplication, rate limiting                                                         | Flooding, amplification            |
| Storage      | fsync, Merkle proofs                                                                         | Data corruption, state forgery     |
| Wallet       | Hardware-held key (passkey / TPM / Secure Enclave), never extractable; keystore recovery signers | Key theft, single-point compromise |

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

Generative media (image, video, audio, 3D, action policies and world models) is a model-serving modality. A node loads a media model from the catalog (`tenzro_loadMediaModel`, operator only) and renders it in process on the open-source Praecise diffusion engine; it starts no media helper process. `tenzro_mediaGen_render` renders one seeded output, here or on a provider serving the model, and answers with what a signed inference receipt for the task `media` commits to: the output's MIME type, SHA-256 and length, its perceptual fingerprint, and the tolerance two renders must agree within. The output goes to the node's content store and is fetched by `output_blake3` with `tenzro_iroh_fetchBlob`.

A render is seeded, so another provider holding the same weights reproduces it up to numeric drift. Anyone holding the receipt can re-render through the same method and file an inference fault when the fingerprints disagree; an upheld fault refunds the caller from the provider's bond.

A render is metered like every other modality: its work units are priced against the node's rate card, collected from the caller, and recorded for the epoch's reward metering. The unit is the pixel-step, `width × height × steps × frames` (frames 1 for images); audio is metered on duration, 3D on its voxel grid, an action policy per action chunk, and a world model on simulated seconds, denoising steps and held session time (`tenzro_types::media_gen`).

### 20a.2 Model Catalog

The catalog is read through `tenzro_mediaGen_listCatalog`. Each row names the HuggingFace repo, the `diffusers` pipeline class, the kinds it serves, default and maximum resolutions, default step count and guidance scale, frames and fps for video, a VRAM floor, and — for split models — the expert pair.

| ID                 | Repo                                | Kinds                                | Default w×h | Steps | VRAM  | Expert pair |
| ------------------ | ----------------------------------- | ------------------------------------ | ----------- | ----- | ----- | ----------- |
| `qwen-image`       | `Qwen/Qwen-Image`                   | text2image                           | 1328 × 1328 | 50    | 48 GB | —           |
| `qwen-image-flash` | `nvidia/Qwen-Image-Flash`           | text2image                           | 1024 × 1024 | 4     | 48 GB | —           |
| `qwen-image-edit`  | `Qwen/Qwen-Image-Edit-2511`         | image2image                          | 1328 × 1328 | 40    | 64 GB | —           |
| `z-image-turbo`    | `Tongyi-MAI/Z-Image-Turbo`          | text2image                           | 1024 × 1024 | 9     | 16 GB | —           |
| `flux2-klein-4b`   | `black-forest-labs/FLUX.2-klein-4B` | text2image, image2image              | 1024 × 1024 | 4     | 12 GB | —           |
| `wan2.2-ti2v-5b`   | `Wan-AI/Wan2.2-TI2V-5B-Diffusers`   | text2video, image2video, world_model | 1280 × 704  | 50    | 48 GB | —           |

A row serving an image-conditioned kind resolves to a sibling pipeline class where the family provides one (`WanPipeline` → `WanImageToVideoPipeline`); a class that already covers image input keeps it.

`qwen-image-flash` is `qwen-image` distilled onto a four-step trajectory with guidance disabled: identical transformer, identical VRAM floor, one twelfth of the pixel-steps and so one twelfth of the metered work. It is also the one row outside the permissive tier — the NVIDIA Open Model License classifies it `CommercialCustom`, so a worker declaring it must enroll on a node started with `--accept-license nvidia-open-model`. Worker enrollment rejects a capability naming a model the operator has not accepted, or one absent from the catalog. The check runs when the node loads the model (`tenzro_loadMediaModel`).

### 20a.3 Split-Expert Models

Some video models pair two transformers trained for different noise regimes and switch between them once, at a fixed noise level (`t >= boundary_ratio × num_train_timesteps`). A node renders such a model only when it holds both experts; a catalog entry that splits the pair across two machines is refused by `tenzro_mediaGen_render`.

### 20a.4 RPC Surface

| Method                                             | What it does                                  |
| -------------------------------------------------- | --------------------------------------------- |
| `tenzro_mediaGen_listCatalog`                      | The media catalog                             |
| `tenzro_mediaGen_render`                           | One seeded render with a signed receipt       |
| `tenzro_loadMediaModel`, `tenzro_unloadMediaModel` | Load or release a media model (operator only) |

The same surface is reachable through the CLI (`tenzro media-gen catalog | render`), the MCP tools, and the SDKs. Job queues, worker pools and quotes are applications built over these methods.

---

## Appendix A: Wallet Assets

Assets the wallet tracks. A payment settles in an asset other than TNZO only when governance has installed it in the settlement-asset registry (`SetSettlementAsset`) and it is enabled and on its peg (§8.2).

| Asset ID | Symbol | Type           | Decimals |
| -------- | ------ | -------------- | -------- |
| `tnzo`   | TNZO   | Native         | 18       |
| `usdc`   | USDC   | Stablecoin     | 6        |
| `usdt`   | USDT   | Stablecoin     | 6        |
| `eth`    | ETH    | Cryptocurrency | 18       |
| `sol`    | SOL    | Cryptocurrency | 9        |
| `btc`    | BTC    | Cryptocurrency | 8        |

## Appendix B: Gossip Topic Reference

| Topic                 | Direction              |
| --------------------- | ---------------------- |
| `tenzro/blocks`       | Validators -> All      |
| `tenzro/transactions` | Any -> Validators      |
| `tenzro/certificates` | Validators -> All      |
| `tenzro/validators`   | Validators -> All      |
| `tenzro/models`       | Model Providers -> All |
| `tenzro/status`       | All <-> All            |
| `tenzro/agents`       | Agents <-> Agents      |

## Appendix C: Public Endpoints

The public endpoints on `tenzro.com` use PQ-hybrid TLS at the edge:

| Service    | URL                                                  | Port | Protocol                       |
| ---------- | ---------------------------------------------------- | ---- | ------------------------------ |
| JSON-RPC   | `https://rpc.tenzro.com`                             | 8545 | Ethereum-compatible JSON-RPC   |
| Web API    | `https://api.tenzro.com`                             | 8080 | REST (verify, status)          |
| MCP        | `https://mcp.tenzro.com/mcp`                         | 3001 | Streamable HTTP (MCP protocol) |
| A2A        | `https://a2a.tenzro.com`                             | 3002 | JSON-RPC 2.0 + SSE             |
| Agent Card | `https://a2a.tenzro.com/.well-known/agent-card.json` | 3002 | GET (A2A discovery)            |

**Network configuration:**

- Chain ID: set by each network's genesis (13380 for the network in `config/network/13380.toml`).
- Phases: preview, then testnet, then the stages governance decides on the way to mainnet.
- TNZO is allocated at genesis and moves only by transfer; grants come from governance.
- Docker image: `<your-registry>/tenzro-node:<tag>` (build from the repo `Dockerfile`)

---

**Tenzro Network** — the open settlement and coordination fabric for AI work

**Tenzro Ledger** — Verifiable work. Hardware-rooted identity. Per-call settlement.

https://github.com/tenzro/tenzro-network
