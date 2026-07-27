# Tenzro Network

## A coordination layer for the AI and agentic economy

**Version 1.0**

---

## Abstract

Tenzro Network is a coordination layer for the AI and agentic economy. It gives humans and autonomous agents a single identity, a single wallet, and one settlement substrate that spans networks, models, payment rails, and execution environments. Agents discover models and services, negotiate terms, conduct economic activity, and settle across ecosystems without juggling separate keys, gas tokens, or trust assumptions. Humans retain control through delegated authority, scoped credentials, and on-chain custody primitives.

Tenzro Ledger is the settlement substrate underneath. It runs three execution environments in one runtime — EVM for liquidity and the broadest DeFi surface, SVM for high-throughput low-latency execution, and Canton DAML for institutional, privacy-preserving multi-party workflows. Consensus is HotStuff-2 BFT with reputation-weighted proposer election; every safety-critical message carries an Ed25519 + ML-DSA-65 + BLS12-381 hybrid signature so the protocol remains sound under both classical and post-quantum adversaries.

Verifiability is built in. Plonky3 STARKs over the KoalaBear field cover inference, settlement, and identity claims; TEE attestations (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU Confidential Computing, Intel Tiber) anchor confidential execution; the two combine through a hybrid ZK-in-TEE path. Cross-chain reach is native through LayerZero V2, Chainlink CCIP and CCT, deBridge DLN, LI.FI, Wormhole, Hyperlane V3, Axelar GMP, Babylon Bitcoin staking, IBC-Eureka light client, BitVM2 / Clementine Bitcoin two-way peg, Hyperbridge ISMP, NEAR Chain Signatures, Stargate V2 Hydra, and Canton 3.5+. Payments span MPP, x402, Stripe Payment Intents, Tempo, Visa Tap, Mastercard Agent Pay, and AP2 mandates — all bound to a Tenzro Decentralized Identity (TDIP) and enforced at signing time through ERC-7579 modular validators.

AI infrastructure goes beyond model serving. The model catalog covers language, vision, audio, video, time-series, segmentation, detection, and text embeddings across permissively-licensed open-weight families (Qwen 3 / 3.5 / 3.6, Gemma 3 / 4, Mistral, DeepSeek V3 / V4, GLM 5 / 5.1 / 5.2, Kimi K2 / K2.6, MiniMax M1 / M3, Granite, Phi 3, gpt-oss, Nemotron). Mixture-of-Experts architectures serve in two modes: full-replica per provider (the default) and **decentralized expert-shard serving** in which providers declare the subset of experts they hold and a dispatch planner batches tokens per holder. Multi-Token Prediction is wired through every layer — catalog metadata, provider capacity advertisement, router selection, and the llama.cpp `--spec-type draft-mtp` invocation — so models with a jointly-trained MTP head (Gemma 4, Qwen 3.5/3.6, DeepSeek V3/V4, GLM 5.2) generate at the higher speculative-decoding throughput automatically. Generative image and video rendering is a separate service rather than another router modality, because a render job's cost is fully determined the moment it is posted: work is metered in pixel-steps (`width × height × steps × frames`), the requester's ceiling is checked at admission, and a diffusion model whose denoising schedule divides at a timestep boundary can be served by two accelerators that each hold one half, splitting payment by the step counts in a signed handoff.

TNZO is the governance, gas, staking, and settlement token. Fees flow to validators (consensus security), to model and TEE providers (intelligence and security services), and to the protocol treasury. Burn channels are demand-driven — base-fee burn under EIP-1559 plus a fraction of the network commission — so net supply tracks real usage rather than emission schedules.

This document describes what Tenzro is, why the design choices are what they are, and how the pieces compose into one coordination layer.

---

## Table of contents

1. [Vision](#1-vision)
2. [The 2026 trajectory](#2-the-2026-trajectory)
3. [Architecture](#3-architecture)
4. [Multi-VM execution](#4-multi-vm-execution)
5. [Consensus](#5-consensus)
6. [Identity and custody](#6-identity-and-custody)
7. [Payments and settlement](#7-payments-and-settlement)
8. [Cross-chain interoperability](#8-cross-chain-interoperability)
9. [AI infrastructure](#9-ai-infrastructure)
10. [Distributed training](#10-distributed-training)
11. [Confidential execution](#11-confidential-execution)
12. [Verification](#12-verification)
13. [Networking and storage](#13-networking-and-storage)
14. [Agent protocol surfaces](#14-agent-protocol-surfaces)
15. [Token economics](#15-token-economics)
16. [Governance](#16-governance)
17. [Security model](#17-security-model)
18. [What you can build](#18-what-you-can-build)

---

## 1. Vision

The economy is splitting into two kinds of participants: humans, who reason about goals and tradeoffs, and agents, who execute. Within five years the latter will conduct most discrete economic actions — fetch a quote, route a payment, settle a trade, train a model, query a registry, sign a receipt. The infrastructure that exists today was not built for them. Wallets assume a human at the keyboard. Chains assume a single VM. Payment rails assume a merchant relationship. Identity assumes a passport. Bridges assume liquidity is the only thing worth moving. Models live behind proprietary APIs whose terms of service forbid the things agents need to do.

Tenzro is the coordination layer for the AI and agentic economy — identity, execution, payment, and settlement in one place.

**One identity for humans and machines.** A single Tenzro Decentralized Identity (TDIP) covers human users, delegated agents acting on a human's behalf, and autonomous agents that own themselves. The same identity carries verifiable credentials, delegation scopes, KYC tier, and the wallet that signs every action. Move across Ethereum, Solana, Canton, and any of the supported destination chains without switching keys or wallets.

**Coordination across ecosystems.** An agent can fetch a yield quote on Arbitrum, settle a margin call on Canton, pay a Solana DEX for a swap, and post a receipt on Tenzro, all in one workflow, all from one wallet, all logged against one identity. Long-running workflows — multi-step trades, training runs, supply-chain settlements — run under the workflow runtime, which manages compensation, deadlines, and on-chain receipts.

**Self-owned AI.** Tenzro is the open infrastructure for self-owned AI: any open model, any size, on hardware you and your peers own. Open-weight models of every modality run on the network — language, vision, audio, video, time-series forecasting, segmentation, detection, embeddings. Providers serve their own hardware (consumer GPUs to data-center clusters, Apple Silicon to NVIDIA H200, AMD Instinct to Intel Gaudi) and earn per inference. Models too large for any single machine serve as distributed expert shards: providers hold the subset of experts they can fit, a dispatch planner batches tokens per holder, and settlement pays every holder for the work it verifiably did — so the largest open checkpoints run on pooled peer hardware instead of a hyperscale cluster. Users and agents pay per call, per token, or per session through the same settlement substrate.

**Distributed AI at protocol level.** Training is not centralized. Tenzro Train coordinates low-communication distributed training over heterogeneous compute, with on-chain run-root commitments, sponsor escrow, slashing for misbehavior, and confidential variants that keep training data sealed inside enclaves. Inference and training share the same identity and settlement plane.

**Human control through delegated authority.** Agents act under explicit delegation scopes — per-transaction caps, daily spending limits, allowed counterparties, allowed operations, time bounds. ERC-7579 modular validators enforce these at signing time, not after the fact. Session keys, social recovery, and hardware-bound passkeys let humans grant, restrict, rotate, and revoke agent authority without surrendering control of the underlying account.

**Settlement, not just messaging.** Where existing agent frameworks coordinate intent, Tenzro coordinates value. A protocol-level settlement substrate denominated in TNZO underwrites every economic action so an agent that promises to pay can be made to pay, and every receipt is verifiable on-chain.

The result is an open protocol where the AI economy can compose. No single vendor sits between agents and the resources they need.

---

## 2. The 2026 trajectory

Four forces are reshaping the protocol layer at once.

**Agents become economic actors.** Frontier AI labs have released tool-using agents capable of multi-step planning. Payment rails (Stripe MPP, Coinbase x402, Visa Tap, Mastercard Agent Pay) added HTTP 402-based machine-payment surfaces in 2025–2026. Standards bodies published trustless-agent identity (ERC-8004), agent-to-agent protocols (A2A), authorization mandates (AP2), and cross-chain intents (ERC-7683). Agents need to discover, transact, and settle without a human in the loop, and the rails for that arrived this cycle.

**Open-source intelligence catches up.** Open-weight models from Qwen, Gemma, Mistral, DeepSeek, Granite, and others now match or exceed the closed-source frontier on most public benchmarks. Inference moved from a handful of mega-providers to a long tail of operators running their own GPUs. Distributed low-communication training demonstrated that frontier-quality models can be trained across regions and operators rather than inside one data center. The bottleneck is no longer model quality — it is coordination.

**Regulation tightens.** The EU AI Act took effect in 2025 with Article 50 disclosure rules now binding. MiCA bound stablecoin and crypto-asset service providers in EEA jurisdictions. Travel rule enforcement extended to virtual asset service providers. Agent-driven payments require auditable receipts, mandate-bound authorization, and KYC-tier-bound delegation. Anything an institution can adopt has to make those legible at the protocol layer, not paper over them in app code.

**Institutional rails go on-chain.** Canton Network, with its CIP-26 user management and CIP-56 Canton Coin holdings, became the production substrate for tokenized real-world assets — money-market funds, treasuries, bonds, equities. Settlement is private, atomic, and party-scoped. Banks and asset managers settle DvP through Canton. Public chains do not have to replace this; they have to interoperate with it.

The chain that wins the agentic decade has to bring all four together — agent-native economic activity, open-source AI, regulatory legibility, institutional rails — under one identity, one wallet, one settlement substrate. That is what Tenzro is.

---

## 3. Architecture

Tenzro is built as a stack of focused crates that share a single state machine, a single consensus, and a single token. The pieces are designed to compose: the same TDIP identity authorizes a Solana swap and a Canton DvP; the same TEE attestation anchors a confidential inference and a sealed-shard training run; the same Plonky3 verifier validates inference, settlement, and identity proofs.

```
                  ┌─────────────────────────────────────────────────┐
                  │       User and agent surfaces                   │
                  │  Desktop · CLI · SDKs (Rust / TypeScript) ·     │
                  │  MCP servers · A2A agents · OpenClaw skills     │
                  └────────────────┬────────────────────────────────┘
                                   │  JSON-RPC · HTTP · QUIC · MCP · A2A
                  ┌────────────────▼────────────────────────────────┐
                  │              Tenzro Node                        │
                  │  Public RPC · Web verification API · MCP host · │
                  │  A2A host · iroh endpoint · gossip transport    │
                  └────────────────┬────────────────────────────────┘
                                   │
   ┌────────────┬─────────────┬────┴────┬──────────────┬─────────────────┐
   │            │             │         │              │                 │
   ▼            ▼             ▼         ▼              ▼                 ▼
┌──────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌─────────┐  ┌───────────────┐
│Multi │  │ HotStuff │  │ TEE +    │  │Storage │  │ Models  │  │ Identity      │
│VM    │  │ -2 BFT   │  │ ZK proof │  │RocksDB │  │+ Train  │  │ Wallet        │
│EVM + │  │+ hybrid  │  │ stack    │  │+ DA    │  │+ Cortex │  │ Custody       │
│SVM + │  │  sigs    │  │          │  │+ iroh  │  │         │  │ Delegation    │
│Canton│  │          │  │          │  │        │  │         │  │               │
└──────┘  └──────────┘  └──────────┘  └────────┘  └─────────┘  └───────────────┘
   │            │             │         │              │                 │
   └────────────┴─────────────┼─────────┴──────────────┴─────────────────┘
                              │
                  ┌───────────▼───────────┐
                  │   Settlement layer     │
                  │  TNZO escrow · channels│
                  │  Cross-chain bridges   │
                  │  Payment protocols     │
                  └───────────────────────┘
```

Every crate is reachable from one of three entry points: the JSON-RPC server on the node, the MCP server for tool-using agents, or the A2A server for agent-to-agent coordination. The CLI and both SDKs are thin clients over these. There is no separate enterprise edition or hosted variant — every operator runs the same binary on the same wire protocol.

---

## 4. Multi-VM execution

A single chain that picks one VM forces every workload to fit that VM. Tenzro runs three and routes by transaction type. Each VM is picked for what it does best, and all three share the same state, the same gas token, and the same identity.

### EVM — liquidity and composability

The Ethereum Virtual Machine surface targets the broadest pool of liquidity, tooling, and existing contracts. Tenzro implements every standard precompile (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, EC_ADD, EC_MUL, EC_PAIRING, BLAKE2F) per the canonical EIPs, plus all seven BLS12-381 precompiles (EIP-2537) for native consensus-grade signature aggregation. Block-STM gives parallel transaction execution with optimistic concurrency control and automatic fallback under contention. EIP-1559 dynamic fee market burns the base fee and rewards validators with the priority fee.

Native primitives extend the EVM with protocol-aware precompiles: `TEE_VERIFY` runs hardware attestation; `ZK_VERIFY` checks a Plonky3 STARK by O(1) commitment lookup against the on-chain registry; `MODEL_INFERENCE` and `SETTLEMENT` dispatch to the runtime; `STAKING`, `GOVERNANCE`, `TOKEN_FACTORY`, `NFT_FACTORY`, and `VRF_VERIFY` give Solidity contracts direct access to staking, on-chain proposals, ERC-20 issuance, NFT minting with verifiable randomness, and ECVRF. ERC-4337 v0.8 account abstraction, EIP-7702 delegation, and ERC-7579 modular validators are all implemented natively — smart accounts, session keys, social recovery, and spending limits work without any setup contract.

### SVM — throughput and latency

The Solana Virtual Machine surface targets workloads that need sub-second finality and high throughput — DEX routing, agent-to-agent micro-payments, real-time settlement on a path. Tenzro embeds the Solana BPF runtime so Solana programs run unmodified. The SPL Token program maps onto the native unified token registry so a swap on the SVM surface settles in the same balance space as a transfer on the EVM surface. There is no bridging between the two.

### Canton DAML — privacy and institutional settlement

Canton is where the institutional financial system already settles tokenized cash, money-market funds, bonds, equities, treasuries, and OTC derivatives. The Tenzro Canton adapter speaks the Canton 3.5+ JSON Ledger API v2 directly. CIP-56 Canton Coin holdings round-trip with TNZO; CIP-26 user management binds each tenant to its own party with `CanActAs` rights enforced server-side; DAR upload, party allocation, command submission, and active-contract queries are all available through the same node API surface as EVM and SVM calls.

The point is that an agent settling a DvP between a tokenized treasury (Canton) and a stablecoin payment (EVM) executes the whole thing as one workflow through one identity. Canton's privacy model means the transaction body is visible only to its signatories; Tenzro provides the cross-VM orchestration and the public commitment.

### Cross-VM token model

TNZO has a single canonical native balance. The wTNZO ERC-20 pointer on the EVM side and the wTNZO SPL adapter on the SVM side share the same underlying balance — there is no bridge between them, no wrapped/unwrapped distinction. Canton CIP-56 holdings round-trip through the bridge adapter. From the application's point of view, a wallet has one TNZO balance regardless of which VM it last touched.

---

## 5. Consensus

Tenzro Ledger uses HotStuff-2 BFT — three phases (PREPARE → COMMIT → DECIDE), linear O(n) communication per round, deterministic finality. Block target is 400 ms; finality follows within a small number of rounds under healthy network conditions. The chain ID is 1337.

### Hybrid post-quantum signatures

Every safety-critical message — vote, quorum certificate, finality cert, equivocation evidence — carries three signatures simultaneously:

- **Ed25519** for compatibility, speed, and broad library support
- **ML-DSA-65** (FIPS 204) for post-quantum soundness
- **BLS12-381** for O(1) signature aggregation in quorum certificates

A QC is a single 96-byte BLS aggregate plus a participation bitmap; the per-vote Ed25519 and ML-DSA-65 components let any verifier independently check each validator's claim if the aggregate is challenged. The genesis schema mandates all three pubkeys per validator. Loading any other shape against the production binary refuses to start.

### Reputation-weighted leader election

Leader selection is reputation-weighted rather than VRF-only. A validator's reputation is its historical block-production success times its TEE attestation multiplier (1.5× for hardware-attested validators) times a tip-following weight. The 1.5× multiplier is multiplicative, not additive: a chronically flaky TEE-attested validator is still dwarfed by a non-TEE active one. Hardware-secured participation becomes the economically rational default without ever gating liveness on TEE possession.

### Stake-weighted consensus, decoupled from service

Consensus and service are decoupled. Block finality is produced by a staked validator set whose voting power equals bonded TNZO: quorum certificates form at the smallest integer weight strictly above two-thirds (6,667 / 10,000 normalized), with a 10% per-validator cap and proportional redistribution, and the Byzantine bound `f` measured as a fraction of stake rather than a head-count of nodes. A node with zero stake carries zero finality weight, so unstaked participants cannot move a quorum — this is what lets service participation stay open without diluting consensus security.

Serving compute, storage, and security is a separate, open set of roles that earn through proof-of-service (pay-per-use, rental, and per-byte fees, section 15) and require no stake and no vote. One operator may both stake to validate and serve capacity, earning on both tracks. TEE attestation is an optional capability that adds a 1.5× leader-selection multiplier; it is never an admission or voting gate. High-trust block classes (training witness committees, high-value bridge duties, institutional settlement routes) restrict leader election to validators above a higher stake and reputation bar, but rest on the same stake-weighted 2/3 bound. The result lowers the barrier to *serving* the network while concentrating the economic security budget entirely in bonded stake.

### Slashing and tail-fork resistance

The consensus equivocation detector watches every vote stream for double-signs in the same view. When detected, the slashing callback bridges the consensus crate to the staking manager, burns 10% of the offender's stake, and preserves the evidence in audit storage. No-endorsement certificates handle tail-fork resistance: when a committee cannot assemble a quorum within the grace window, it builds a NEC and carries the prior state_root forward to the next view rather than stalling.

### Fast catch-up

A node that joins late receives the genesis, the most recent finalized block, the QC chain, and a state snapshot from a configured anchor peer. The weak-subjectivity anchor — either an `[weak_subjectivity]` block embedded in the genesis or an explicit `--state-sync-anchor` flag — is the trust gate: the snapshot's declared state_root must match the anchor bit-for-bit or the bootstrap aborts. New validators do not silently adopt a hostile fork.

### Stable validator lifecycle

Validators upgrade their binary in place. The deploy preserves the local chain DB across rolls, and on boot the node runs a chain-compatibility check (`verify_chain_compat`) that compares the configured genesis chain_id and computed state_root against what's persisted under `CF_METADATA`. Identical genesis loads existing state; drift fails loud with an actionable error.

Bootstrap peer discovery flows through DNS (`--bootstrap-dns`): `_tenzro-boot._tcp.<zone>` SRV records advertise the active boot set, paired with `_tenzro-id._tcp.<target>` TXT records carrying libp2p peer IDs. Rotating a boot validator's identity is a zone edit, not a fleet-wide wrapper update.

Consensus, ML-DSA-65, and BLS12-381 key rotation is operator-driven via the `tenzro_rotateValidatorKey` RPC. The rotating validator proves ownership of the existing keys by signing the rotation payload under the current Ed25519 consensus key. The new tuple is written to `EpochManager.pending_validators` and the swap is atomic at the next epoch boundary — no split-key window. Operators fan out the rotation to every active validator before the boundary using the provided script; the consensus-mediated typed-transaction variant is on the post-mainnet roadmap.

---

## 6. Identity and custody

The Tenzro Decentralized Identity Protocol (TDIP) defines a single identity model that covers humans, delegated agents, and autonomous agents. Every action on the network resolves to a TDIP DID; every payment, every signature, every credential ties back to it.

### Four identity classes

- **Human** — `did:tenzro:human:{uuid}`. Carries display name, KYC tier (Unverified / Basic / Enhanced / Full), and the set of machines the human controls. A human identity can issue verifiable credentials, can be the controller of any number of delegated agents, and signs with a passkey-bound MPC wallet.
- **Delegated agent** — `did:tenzro:machine:{controller}:{uuid}`. An agent acting on a human's behalf. Carries a delegation scope inherited from the controller — per-transaction value cap, daily spend cap, allowed operations, allowed chains, allowed payment protocols, time bound, allowed counterparties. The controller can revoke at any time; revocation cascades.
- **Autonomous agent** — `did:tenzro:machine:{uuid}`. An agent that owns itself. Same MPC wallet, same A2A surface, but no controller. Used for protocol-owned bootstrap agents and self-funded autonomous services. The `is_seed_agent` flag marks protocol-funded autonomous agents so organic-activity metrics can exclude bootstrap traffic.
- **Institution** — `did:tenzro:institution:{lei}:{uuid}`. A legal entity anchored to its GLEIF Legal Entity Identifier (ISO 17442). The 20-character LEI is validated with ISO 7064 Mod 97-10 check digits at registration and at every transaction that consults the identity. One legal entity can hold many institution identities (one per desk, fund, or subsidiary) without re-issuing LEIs — the trailing UUID disambiguates. Institutions carry a KYB tier, an optional vLEI ACDC credential id binding to the GLEIF vLEI Ecosystem Governance Framework, an ISO 3166-1 alpha-2 country code, and the set of machines the institution controls. KYB-Full institutions act as trust roots for tokenized RWA flows, can serve as Canton tenants, and can attest reserve under Secure-Mint.

DIDs resolve through standard W3C DID Documents. Verifiable Credentials carry KYC tier upgrades, attestations, and capability claims signed by trust roots. Trust chains traverse recursively with cycle detection, depth bound, and explicit anchoring to the configured trust roots.

A Universal Resolver-compatible HTTP surface (`/1.0/identifiers/{did}` and `/1.0/methods`) at the web verification API serves `did:tenzro:` and `did:pdis:` to any standards-compliant resolver driver — Vidos, Godiddy, the Spruce SDKs, browser wallet extensions — without a Tenzro-specific adapter. KERI compatibility is implemented for long-lived autonomous machine identities — every machine identity can publish a hash-chained Key Event Log with pre-rotation commitments so persistent control survives key compromise. Inception, rotation, and interaction events use a SAID prefix `S` (SHA-256, CESR code) and validate through the standard KERI rules.

### Sign-In With Tenzro

Off-chain services authenticate Tenzro identities through SIWT — an EIP-4361-shaped message that the wallet signs and the relying party verifies against the registered identity. The canonical message carries the requesting domain, the Tenzro address, a nonce, the chain id, an issued-at timestamp, optional expiration and not-before bounds, and the resources the signer authorizes. Verification is non-stateful — the relying party stores the issued nonce, dispatches the signed message, and checks the signature against the resolved DID Document. Existing SIWE parsers consume SIWT messages byte-for-byte.

### Wallets — passkey-first, MPC, post-quantum hybrid

The default Tenzro wallet is a passkey-bound MPC threshold wallet. Account creation is one tap (Touch ID / Face ID / Windows Hello / Android biometric) using FIDO2 / WebAuthn — no seed phrase to write down, no extension to install, no email to verify. Cross-device sign-in uses caBLE QR. The on-chain twin of the passkey is a P-256 WebAuthn validator module (ERC-7579) that verifies the assertion signature directly inside the account validation path.

Under the hood the wallet is a FROST-Ed25519 (or FROST-Secp256k1) 2-of-3 threshold split — one share on the user device, one share on the user's recovery factor (passkey-protected cloud), one share held by the protocol's MPC nodes. ML-DSA-65 is layered on every safety-critical signature, producing a post-quantum hybrid that satisfies both the classical and PQ verification paths simultaneously. Threshold signing also drives the cross-chain bridge side — DKLS23 t-of-n threshold ECDSA produces secp256k1 signatures for EVM destination chains without any single share ever holding the full key.

Two operational properties matter for production custody. **Pre-signing** caches DKLS23 round-1 output — which depends on the keyshare and a fresh randomness commitment but not on the message — so a signing request consumes a pre-computed tuple and immediately enters round 2, cutting the perceived signing latency by 30–40% for hot bridge flows. Each tuple is one-shot; re-use across two messages reveals the secret key, so the pool tracks per-tuple consumption and rotates on epoch change. **Proactive Key Refresh (PKR)** rotates shares on a governance-set cadence — default 24 hours of wall time or 100,000 signing instances per epoch, whichever comes first — so a long-running validator's keyshare exposure is bounded even if a single share holder is silently compromised. PKR preserves the group public key; clients see no change.

### Custody enforced at signing time

ERC-7579 modular validators enforce custody policy at the EntryPoint, not in application code. Three validator modules are deployed at genesis addresses:

- **Social recovery validator** — N-of-M guardian quorum using hybrid Ed25519 + ML-DSA-65 signatures. Guardians can be the human's other passkeys, trusted humans, or escrow services. Recovery requires the configured quorum and can replace the root key without changing the account address.
- **Session key validator** — short-lived Ed25519 keys with allowlists for call targets, 4-byte selectors, value ceilings, and time windows. Used by agents and dApps to act on the user's behalf for a bounded session without holding the root key.
- **Spending limit validator** — per-transaction value cap and rolling daily cap, enforced on every `validateUserOp`. The on-chain twin of the runtime delegation scope. Both must approve.

Combined validation is logical AND — every installed module must approve a user operation for the EntryPoint to accept it. Combined `validAfter = max(...)` and `validUntil = min_nonzero(...)`. Custody is not an off-chain check.

### Pluggable signers

For users and operators with existing key infrastructure, a `PluggableSigner` trait lets external wallet backends — HSMs, custodian APIs, hardware wallets, MPC services — drive Tenzro signing without modifying the wallet crate. The passkey-first default and the pluggable path coexist; both produce signatures the protocol verifies identically.

---

## 7. Payments and settlement

Payment is where agents and humans most need a unified surface. Tenzro supports every major HTTP 402-based machine-payment protocol natively, every protocol is bound to TDIP identity, and every settlement enforces both the protocol-layer delegation scope and the runtime spending policy.

### Protocols supported

- **MPP (Machine Payments Protocol)** — session-based streaming credential / receipt flow; deep integration with Stripe Payment Intents API, including HMAC-SHA256 webhook verification per RFC 2104.
- **x402** — stateless one-shot HTTP 402 payment, including the Coinbase CDP facilitator with EIP-3009 `transferWithAuthorization` calldata.
- **Tempo** — direct participation in the Tempo network for stablecoin settlement; EIP-155 secp256k1 transaction signing with RLP encoding and Keccak-256 hashing.
- **Stripe SPT (Shared Payment Token)** — Stripe's agentic-payment primitive; settlement outcome dispatched as ERC-8004 reputation feedback.
- **Visa Tap to Pay** — agent-tap-card flow bound to the TDIP wallet.
- **Mastercard Agent Pay** — Mastercard's agent-pay protocol surface.
- **AP2 (Agent Payments Protocol)** — Checkout/Payment mandate-pair validation with five-ceiling enforcement (AP2 CheckoutMandate cap + TDIP delegation scope + runtime SpendingPolicy + on-chain escrow + Stripe SPT usage limits).

Every payment surface uses the same `IdentityPaymentBinder` — the payer DID is bound, the delegation scope is checked via `IdentityRegistry::enforce_operation`, the runtime spending policy is checked via the `SpendingPolicyResolver` trait, and any AP2 mandate is validated against the parent CheckoutMandate constraints. Both ceilings must pass; either ceiling can refuse.

### Native settlement primitives

Tenzro implements settlement as a protocol primitive rather than a contract:

- **Escrow** — `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow` are typed transactions; funds lock at a deterministically-derived vault address with no private key; release and refund are authorized only by the payer; full RocksDB durability and hydration on restart.
- **Micropayment channels** — off-chain per-token billing with on-chain dispute resolution; signed channel updates carry the next state's canonical preimage `(nonce || payer_balance || payee_balance)`; channel close finalizes the latest signed state on-chain.
- **Batch settlement** — atomic settle-many over a list of payer/payee/amount tuples, with rollback on any single failure.
- **Reserve-bound minting** — Secure-Mint enforces `circulating + amount ≤ reserve` for tokenized assets; mint refuses if it would break the 1:1 invariant; reserve attestations are signed and time-bound.

### Capital intent and workflow

For longer-horizon economic activity, Tenzro provides two coordination primitives:

- **Capital intent** — open / quote / assign / execute / verify / compensate / settle lifecycle for intent-based capital flows (NAV calculation, bond pricing, treasury rebalancing).
- **Workflow** — long-running multi-step coordination with per-step execute / verify / compensate handlers, deadlines, on-chain receipts, and optional Canton mirroring of every step.

Both are surfaced through the same RPC namespace and consumed by reference agent templates in `tenzro-agent-kit`.

---

## 8. Cross-chain interoperability

A coordination layer is only as good as its reach. Tenzro carries fifteen bridge adapters plus three Chainlink data surfaces that cover the major ecosystems:

| Adapter | Reach | Primary use |
|---|---|---|
| LayerZero V2 | Every LayerZero-supported chain | Generic omnichain messaging, OFT transfers |
| Chainlink CCIP + CCT | Every CCIP-supported chain | Token transfers with the Cross-Chain Token standard |
| Chainlink Data Feeds | Every CCIP-supported chain | Price feeds (incl. AggregatorV3 reads) |
| Chainlink Data Streams | Equity, commodity, FX, crypto | Sub-second market data |
| Chainlink Proof of Reserve | Reserve-backed assets | Reserve attestations for Secure-Mint |
| deBridge DLN | Every DLN-supported chain | Intent-based cross-chain liquidity |
| LI.FI | 130+ chains | Cross-chain aggregation, route comparison |
| Wormhole + NTT | Every Wormhole-supported chain | Generic messaging, Native Token Transfers |
| Hyperlane V3 | 18+ chains incl. Tenzro | Sovereign Tenzro-validator-set ISM, generic messaging |
| Axelar GMP | 30+ chains incl. Cosmos, Move, Stellar, XRPL | Generic messaging, Cosmos / Sui / Aptos reach |
| Babylon | Bitcoin | BTC staking, finality providers for BTC-secured consensus |
| IBC-Eureka | Every Cosmos SDK chain | Tendermint light client compressed into SP1 plonk proofs |
| BitVM2 / Clementine | Bitcoin | Trust-minimised two-way peg with optimistic challenge protocol |
| Hyperbridge | Polkadot + ISMP chains | HTTP-shaped POST/GET cross-chain messaging |
| NEAR Chain Signatures | Bitcoin, Ethereum, Solana, TON, Stellar, Sui, Aptos, Dogecoin | NEAR MPC produces secp256k1 / Ed25519 signatures for the destination chain from a Tenzro account |
| Stargate V2 Hydra | Every LayerZero-supported chain | Native USDC / USDT / WETH single-signature OFT bridging |
| Canton 3.5+ | Canton Network synchronizers | Tokenized RWA, CIP-56 Canton Coin, DAML DvP |

Every adapter is fail-closed on inbound message verification. Wormhole VAAs are checked against the configured Guardian set with secp256k1 ECDSA recovery and the canonical signing digest. Hyperlane carries a sovereign Tenzro-validator-set ISM that verifies a k-of-n multisig over the canonical Mailbox encoding. Axelar carries a threshold validator set. All three use the same trailing ISM-metadata wire format (`body || u8 sig_count || sig_count * (addr20 || sig65)`). Nonce trackers persist per-adapter so replays are dropped across restarts.

A unified `BridgeRouter` picks a route given a source, destination, asset, and amount — by cost, by speed, or by reliability. The router consults live fee quoting (LayerZero `EndpointV2.quote()`, Chainlink `Router.getFee()`, deBridge order-creation API, Canton fee schedule pulled from the live Splice AmuletRules contract) and returns a ranked set of options the caller picks from. Every quote is fresh, every route is signable, every settlement is checkpointed.

ERC-7683 cross-chain intents close the loop. A user signs an open order on the source chain; a filler picks it up on the destination chain; the order ID is `SHA-256` over the canonical preimage and persisted in storage. Refund-eligible and force-refund states are tracked through the same lifecycle. ERC-7802 cross-chain token mint and burn extends the model to native cross-chain tokens.

The IBC-Eureka adapter delegates Tendermint header verification to the SP1 zkVM and consumes the resulting plonk proof to advance a stored ICS-07 consensus state. The 32-byte commitment (`SHA-256(tenzro/ibc-eureka/proof || client_id || height || root)`) is recorded in the on-chain IBC commitment registry; the EVM `IBC_VERIFY` precompile at `0x1020` is then an O(1) lookup. The same pattern — off-EVM verification, on-chain commitment, O(1) precompile lookup — runs for every Plonky3 STARK in the system.

Hyperbridge's adapter encodes the post-2026 hardening rules at the message-ingest path: admin transitions (governance-style payload typecodes) are inadmissible on the regular PostRequest path, and per-asset rolling-window mint ceilings reject any inbound transfer whose cumulative amount would exceed the configured per-window cap. Both rules fire before any payload is forwarded to the destination contract.

A **global supply accounting registry** at precompile `0x1021` is the single integrity log for Tenzro-issued tokens that move across rails. Every cross-rail mint/burn submits a signed delta carrying `(asset_id, rail, sequence, kind, amount, source_chain)`. The registry enforces three invariants: monotone-per-(asset, rail) sequence (replay guard), `Σ mints − Σ burns ≤ max_supply` (cap), and no underflow on burn. A misbehaving relayer or compromised rail is locally contained — the next delta is rejected at the registry, not on the rail.

---

## 9. AI infrastructure

Tenzro is built for open-source intelligence at every modality and every size. The model registry catalogs permissively-licensed open-weight models across seven runtimes, each operator picks which to serve, and the inference router matches users and agents to providers by price, latency, reputation, or weighted combination.

### Modalities

- **Language** — Qwen 2 / 3 / 3.5 / 3.6 (dense and MoE), Gemma 3 / 4 (incl. Gemma 4 26B-A4B MoE), Mistral (incl. Mistral Small 3.2), Phi 3 / 4, DeepSeek V3 (native MTP) and V4 Pro / Flash, GLM 5 / 5.1 / 5.2 (5.2 with native MTP), Kimi K2 / K2.5 / K2.6 / K2.7-Code, MiniMax M1 / M3, Granite, Granite-H, gpt-oss, Nemotron Nano. All run through the language runtime with full chat templates, streaming, and Anthropic-style SSE.
- **Vision embedding** — CLIP ViT-B/32 and L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16. Used for image search, similarity, and embedding pipelines.
- **Text embedding** — Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M (Matryoshka), BGE-M3, Snowflake Arctic Embed L v2.0, ModernBERT-embed base/large (8192-context RoPE encoder).
- **Segmentation** — point/box (SAM 2 base/large, EdgeSAM, MobileSAM) and text-promptable open-vocabulary (SAM 3 / 3.1).
- **Detection** — RF-DETR (nano through 2xl, 90-class COCO) and D-FINE (n/s/m/l/x, 80-class).
- **Audio (ASR)** — Moonshine v2, Distil-Whisper, Whisper-large-v3-turbo, NVIDIA Parakeet-TDT-0.6B-v3, Canary-1B-Flash.
- **Time-series forecasting** — TimesFM 2.5.
- **Video embedding** — vision-fallback encoder (CLIP / SigLIP2 / DINOv3 / ViT) over uniformly-sampled frames.

Every catalog entry carries a license tier (Permissive / Attribution / CommercialCustom / NonCommercial) enforced at registration time. The model registry refuses to load a non-commercial entry without explicit operator opt-in, and CommercialCustom entries require a per-family opt-in.

### Provider economics

A provider runs the node with `--roles ai`, registers under the model registry, and stakes TNZO bonded to their identity. Inference requests route to providers via the strategy the caller selects. Settlement is per-call or per-token through a micropayment channel; reputation tracks fast on success (latency only on HTTP 200), slow on failure (-5 per fault), and is gated to "settled-success only" on reputation gain so providers cannot game reputation without taking a real payment. Providers can also rent capacity for fixed terms backed by streaming escrow against their stake — see §15, *Capacity rental and escrow*.

### Heterogeneous hardware

The same provider binary runs on Apple Silicon, NVIDIA Ada / Hopper / Blackwell, AMD Instinct, Intel Gaudi, and CPU-only fallbacks. The runtime layer is ORT-backed for ONNX-shippable models and llama.cpp-backed for GGUF; the dispatch layer hides the difference. Small providers serve niche models; large providers run frontier models; the protocol does not pick winners.

### Chat surface

The language runtime is exposed five ways simultaneously:

- **JSON-RPC** `tenzro_chat` / `tenzro_chatStream`
- **OpenAI-compatible** `POST /v1/chat/completions` and `POST /v1/responses`, plus the HTTP-402-gated `POST /api/paid/chat/completions`
- **Anthropic-style SSE** `POST /chat-stream`
- **Web** `POST /chat` on the verification API
- **MCP** `chat_completion` tool, **A2A** `inference` skill, **CLI** `tenzro chat`

Agents pick whichever surface fits their framework; the model and provider are the same underneath.

### Mixture-of-Experts serving

MoE architectures activate a small subset of expert weights per token. The total parameter count can sit at 122B / 397B / 685B / 1.6T / 2.8T while the active path is only 10–104B — generation-time compute scales with the active path. Kimi K3 sets the current ceiling at 2.8T total over 896 routed experts, of which 104B is active per token. Tenzro serves MoE in two modes that share the same provider population.

The default mode is **full-replica per provider**: a provider whose hardware fits the entire model holds it and serves single-peer inference exactly like a dense model. This is the smaller-model path (Gemma 4 26B-A4B, Qwen 3.5 35B-A3B, Qwen 3.6 35B-A3B, Kimi K2.5, DeepSeek V3 on H200-class infrastructure).

The second mode is **decentralized expert-shard serving**: providers whose hardware cannot fit the full model declare the subset of experts they hold via `ProviderCapacity.moe_holdings`, and the network's MoE routers aggregate per-token top-k routing decisions into per-holder batches. Each batch carries the tokens whose top-k resolved to the same (expert, holder) tuple, dispatched directly over the holder's iroh QUIC endpoint (the data plane sits on the same content-addressed transport used for model weights, training gradients, and agent memory). The shard view is a derived view over the existing provider registry — the compute providers serving MoE shards are the same network providers that serve dense models, so the existing reputation, staking, billing, and TEE attestation primitives apply unchanged.

MoE pipeline roles are typed: `Replica`, `Router`, `ExpertHolder`, `PrefillDecode`, `Prefill`, `Decode`. A provider can declare more than one role; the router picks the matching role per request. Replication of each expert is governance-tunable — a default policy requires every active expert to be held by at least two distinct providers (so a single holder failure does not pause inference), with up to eight holders allowed for popular experts whose committed TPS exceeds the hot threshold.

Execution is carried by an expert-host runtime embedded in every node: holders load expert FFN weights and gating networks from safetensors payloads, and a distributed layer forward gates locally, dispatches per-holder batches (local execution, the holder's iroh QUIC endpoint on the `tenzro/moe` ALPN, or HTTP), and recombines per-token outputs weighted by the gate probabilities. Holder failures are absorbed inside the forward: each batch walks its planned holder set in warm-first order, and when every known holder for an expert fails, the affected (expert, token) pairs are replanned against a rebuilt shard view that excludes the failed providers — bounded rounds, with results already gathered kept in the combine, each failure recording a reputation penalty against that holder. A forward that still cannot cover every token fails closed by default; `allow_partial` instead renormalizes the gate weights over the experts that responded and reports the unserved pairs. Every holder meters its aggregate expert-forward throughput over a rolling minute and stamps it onto each advertised holding as `committed_tps`, so the planner ranks holders by observed serving capacity. So a holder can advertise more experts than fit in memory, the runtime keeps experts in a byte-bounded memory-tier LRU — the budget auto-sizes to 60% of the host's available memory, or 4 GiB where that reading is unavailable — over a disk tier that spills raw safetensors and decodes them back on demand; readahead promotes the disk-tier experts a forward is about to hit before its batch arrives. A holder's declared residency (`Warm` for memory-resident, `Cold` for disk-tier) is read from this live tier state rather than a static declaration.

The expert-shard view, the per-token-to-per-holder planner, the replication policy, and the execution runtime are surfaced through twelve RPCs (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`, `tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`) and through the Rust and TypeScript SDKs.

### Multi-Token Prediction

Speculative decoding lets a target model generate multiple tokens per inference step using a smaller drafter. **Multi-Token Prediction (MTP)** is the jointly-trained variant — an auxiliary head that shares hidden state with the target and produces tokens consistent with the target's distribution. The accept rate is materially higher than classical two-model speculative decoding because the drafter is not an independent model but the target's own auxiliary head.

Tenzro wires MTP from catalog to runtime. The catalog declares which entries pair with which drafter (`drafter_id`), which flavour of speculation they expect (`mtp_kind: DraftMtp` or `Generic`), and the recommended starting `draft_n` (the `--spec-draft-n-max` parameter). Provider capacity advertises whether the provider has the paired drafter co-loaded (`mtp_enabled: true`). The inference router filters MTP-eligible requests to MTP-capable providers when the request carries a `draft_n` hint and falls back to standard autoregressive providers otherwise. At the runtime the MTP variant of llama.cpp consumes the joint head and accepts the longest matching prefix on each step. Serving a model auto-loads its paired drafter: `tenzro_serveModel` reads the catalog `drafter_id`, loads the drafter from disk or downloads it in the background, and reports the outcome in the serve response — a drafter problem never fails the serve, and the drafter unloads with its target and is restored across restarts.

MTP is implemented for Gemma 4 (E2B / E4B / 12B / 26B-A4B / 31B), Qwen 3.5 (every size 0.8B–397B), Qwen 3.6 27B and 35B-A3B, DeepSeek V3 (native head, ~80% accept rate, ~1.8× decode throughput per upstream), DeepSeek V4 Pro / Flash, and GLM 5.2 (improved MTP layer). For models without a joint head, classical two-model speculative decoding (`MtpKind::Generic`) is wired through the same path.

### Generative image and video

Diffusion rendering is a different economic shape from token generation, so it is a distinct service rather than another modality on the inference router. A chat request is priced by tokens the model has not produced yet; a render request is priced by work that is fully determined the moment the job is posted. The unit is the **pixel-step** — `width × height × steps × frames` — so a four-step image and a fifty-step image at the same resolution are quoted for the work each actually takes. A requester posts a job with a price ceiling; the quote is checked against that ceiling at admission, not after a worker has claimed and abandoned it.

Four kinds are served: `text2image`, `image2image`, `text2video`, `image2video`. The image-conditioned kinds bind the conditioning image's hash into the job id, so a job commits to the exact bytes it was conditioned on. A worker claims a job, renders it, publishes the output to the content-addressed store, and signs a receipt over what it produced. Three signing preimages sit under three distinct domain tags — job id, handoff, receipt — so a signature from one stage cannot be replayed as another.

The catalog carries permissively-licensed open-weight families: Qwen-Image and its four-step distillation, Qwen-Image-Edit, Z-Image-Turbo, FLUX.2-Klein, and the Wan 2.2 text-to-video, image-to-video, and combined entries. Because the node never loads generative-media weights — the reference worker does — license terms are enforced at worker enrollment rather than at model load: a capability naming a model whose terms the operator did not accept is refused.

**Split-expert rendering** is what makes large video models reachable on commodity accelerators. Two model shapes are called mixture-of-experts in the generative-media literature and only one is a distribution primitive. Token-routed MoE has a learned router selecting experts inside every forward pass; splitting it across machines costs a round trip per layer per token, which is what the language-model dispatch planner above addresses. A **timestep-boundary expert pair** is different: two transformers of identical shape trained for different noise regimes, with a fixed noise threshold — not a learned router — deciding which expert owns a step. Timesteps descend through the schedule, so the high-noise expert's step set is always a prefix and one index splits it.

That structure means exactly one intermediate latent crosses between the two halves, once per job. One expert needs 48 GB where the whole model needs 80, so two commodity accelerators render what one could not, and the coordination cost is a single blob transfer rather than one per layer. The boundary is a fraction of the scheduler's *training* timestep count, not of the job's step count — a 40-step job and a 100-step job split at the same noise level and at different indices — so payment division reads the completed step count from the signed handoff rather than assuming a fixed fraction. A worker with the memory for both halves claims each half separately anyway; the protocol makes no exception for co-location, which keeps the signed step counts and the payment division identical whether the halves run on one machine or two.

As with distributed training, the protocol layer is Rust with no tensor library: the job queue, the worker registry, the pricing function, the payment split, the signing preimages, and the persistence. The denoising loop — pipeline construction, scheduler manipulation, VAE decode, video muxing — lives in a Python reference worker over HuggingFace `diffusers`, which renders and signs but never decides what a job is worth, who else is working on it, or whether its own receipt is acceptable.

---

## 10. Distributed training

Frontier-quality models can be trained across operators, regions, and hardware classes rather than inside one data center. Tenzro Train is the protocol layer that coordinates this.

### Design

Tenzro Train splits cleanly into two layers. The **Rust protocol layer** (`tenzro-training`) owns the syncer state machine, aggregation rules, outer-gradient ingestion, fragment commitment, training receipts, gossip topics, on-chain commitments, fraud-proof verification, and RPC. The **Python reference trainer** (`integrations/trainer/`) wraps PyTorch FSDP2, Hivemind, and safetensors; the per-modality inner training loops use the mainstream Python ecosystem (transformers, native PyTorch, gluonts, timm). The two communicate over JSON-RPC and the gossip topics.

Inner steps are PyTorch. Outer steps — gradient aggregation, state-root finalization, receipt emission — are Rust. The Rust crate has no tensor library dependency.

### Aggregation rules

Five aggregators are implemented: Mean (the Open trust tier default), LoraAlternating (the alternating-freeze rule for LoRA/QLoRA adapter runs), Trimmed Mean, Coordinate Median, and Krum (Byzantine-robust). The Open tier admits Mean and LoraAlternating; the Verified and Confidential tiers admit all five. Tier-policy admission is a pure function at enrollment time.

### Multi-syncer coordination

Real production decentralized training cannot run with a single syncer — a single point of trust and a single point of failure. Tenzro uses a k-of-N witness committee: a deterministic per-round selection function picks a committee of size `recommended_committee_size(N)` from the enrolled syncer set, using the chain entropy from the previous finalized block hash. Finalization is idempotent: redundant submissions from concurrent witnesses for the same `(round, state_root)` return Ok; conflicting `state_root`s return `ConflictingFinalize` for fork detection. No-endorsement certificates handle the case where the committee cannot assemble a quorum within the grace window.

### Confidential training

For training on sensitive data, the Confidential tier uses HPKE RFC 9180 base-mode wrapping of per-shard data keys to enclave-resident trainers. Each `SealedShardEnvelope` carries the ciphertext hash, wrapped data key, enclave pubkey, and enclave measurements; the manifest hash binds the full envelope set; trainer enrollment validates attestation, enclave pubkey, and measurement parity at sign-up. Data unsealed only inside the trainer's TEE.

### Modalities

Time-series (TimesFM-class), language (Qwen / Gemma / Mistral / Phi / DeepSeek / Granite), and vision (timm ViT) reference adapters all exist. Adapters are pluggable so additional modalities slot in without touching the protocol layer.

### Settlement

A training task posts a sponsor escrow in TNZO. Each accepted outer gradient yields a signed receipt. Run-root commitments land on-chain at finalization. The sponsor's escrow releases to participating trainers proportional to their contributions; misbehavior (invalid receipts, divergent state_roots, withholding) is slashed against the trainer's bond.

---

## 11. Confidential execution

Some computations have to remain confidential — model weights from a proprietary provider, training data covered by privacy regulation, key material that has to stay inside an enclave. Tenzro's TEE substrate covers five vendors uniformly.

### Supported TEEs

- **Intel TDX** — `/dev/tdx-guest` ioctl, TDREPORT → Quote pipeline, Intel PCS certificate chain, QE P-256 ECDSA quote signature verification.
- **AMD SEV-SNP** — `/dev/sev-guest` ioctl, AMD KDS VCEK certificate fetching, ARK → ASK → VCEK chain verification.
- **AWS Nitro Enclaves** — `/dev/nsm` device, CBOR attestation documents, AWS Nitro root CA chain, COSE_Sign1 ES384 verification per RFC 8152.
- **NVIDIA GPU Confidential Computing** — NVIDIA NRAS HTTP API attestation with JWT verification and SPDM-based measurements.
- **Intel Tiber Trust Authority** — hosted attestation via the ITA API with PS384/RS256 JWT verification against the pinned JWKS.

All five surface a unified `AttestationResult` so applications do not have to special-case the vendor. Enclave encryption is AES-256-GCM with HKDF-SHA256 key derivation per vendor; in production the key is sealed by hardware (MKTME / VMSA / KMS / CC memory).

### How TEE composes with the protocol

- **Validator participation** — TEE-attested validators get a 1.5× multiplicative weight on leader selection.
- **Confidential inference** — model provider runs the inference inside the enclave, returns a TEE-attested result hash, and signs it with a key sealed by the enclave.
- **Confidential training** — the sealed-shard pipeline above.
- **Sealed key custody** — bridge signers and protocol-side cryptographic operations can run with a TEE-sealed key the operator can never extract.
- **ZK-in-TEE** — the enclave generates the witness, runs the prover, and signs the commitment with a PQ-hybrid composite signer (classical + ML-DSA-65). Verifiers can check the ZK proof, the TEE attestation, or both.

---

## 12. Verification

Tenzro provides three independent ways to verify any claim made on the network: cryptographic (Plonky3 STARK), hardware (TEE attestation), or both at once (ZK-in-TEE). Each is anchored on-chain.

### Plonky3 STARKs over KoalaBear

The proof system is Plonky3 over the KoalaBear field (`2^31 − 2^24 + 1`, two-adicity 24). The hash is Poseidon2; the commitment scheme is FRI. The configuration (`log_blowup = 1`, `num_queries = 64`, `query_pow = 16`, `commit_pow = 8`) gives proofs in the 64–128 KB band that verify in ~5–20 ms on commodity hardware. Three AIRs are defined: inference, settlement, identity. The system is transparent — no trusted setup, no per-circuit CRS, no ceremony — and is post-quantum-conjectured sound.

A generic dispatcher (`verify_proof_envelope`) matches on `circuit_id` and runs the right AIR's verifier against the pinned testnet config. The EVM `ZK_VERIFY` precompile is O(1) — validators verify proofs off-chain and write 32-byte SHA-256 commitments into the on-chain `ZkCommitmentRegistry`. The precompile is a HashSet lookup against the registry.

### TEE attestation

Hardware attestation through any of the five supported vendors. Every attestation carries the vendor identifier, the chain of certificates (validated against the vendor root CA), the signed measurement set, and an enclave-bound public key. The `TEE_VERIFY` precompile is a real attestation check, not a stub. Attestations bind to an enclave-held signing key so subsequent signatures the enclave produces inherit the attestation's trust.

### Hybrid ZK-in-TEE

The enclave produces the witness, runs the prover inside the enclave, and signs the commitment with either a classical key (Ed25519 / secp256k1) or a PQ-hybrid composite signer (classical + ML-DSA-65). Cross-binding an externally-verified `AttestationResult` to a `TeeZkProof` lets a verifier rely on a third-party attestation appraisal (e.g. Intel Tiber) without coupling the ZK crate to any specific HTTP TEE client.

### What gets proved

- **Inference results** — model output committed to a chain identifier; verifiers can confirm a specific input produced a specific output under a specific model.
- **Settlements** — settlement amount, payer, payee, and resulting balance commitments are provable against the chain state root.
- **Identity claims** — credential possession, delegation scope membership, and trust-chain root anchoring are provable without revealing the underlying identity material.

---

## 13. Networking and storage

The Tenzro peer-to-peer layer runs on libp2p 0.56. Every node binds both TCP/9000 and QUIC/9000 by default — the universal transport set that lets cloud VMs, residential WiFi, mobile devices, and embedded boards reach the network through whichever transport NAT permits. Gossipsub carries blocks, transactions, consensus messages, attestations, training events, inference requests, agent messages, and SLA heartbeats. Kademlia DHT handles peer discovery; Identify gives observed-address discovery; AutoNAT v2 + Circuit Relay v2 + DCUtR give permissionless NAT traversal (hole punching for joiners behind home or corporate NAT).

Storage is RocksDB with column families per concern (blocks, state, accounts, transactions, identities, agents, models, providers, tokens, settlements, validator modules, agent memory, audit, API keys, MPC keyshares, training runs, training receipts, training manifests, bridge nonces, equivocation evidence, and more). Durable writes go through `write_batch_sync` with `fdatasync`. Block writes are atomic. Auto-repair handles WAL corruption on startup.

The DA layer abstracts behind a `DaBackend` trait. Receipts can be inline or off-loaded. The implemented backends are `InlineFallback` (safe pre-mainnet default, optional RocksDB-backed) and `IrohBlobs` over the iroh-blobs content-addressed transport. Iroh also carries the model-weight distribution path (peer-first with HuggingFace Hub fallback), the training gradient store, sealed-shard distribution, agent-memory archives, and the A2A / MCP transport — all on one shared QUIC endpoint per node, anchored to the node's TDIP key via Pkarr.

Snapshot bootstrap is cryptographically anchored — the joining node specifies a block hash it trusts; the snapshot must hash to that root or the bootstrap aborts.

---

## 14. Agent protocol surfaces

Tenzro exposes its capabilities through three concurrent surfaces, each picked for what it does best.

### JSON-RPC

The full RPC surface (700+ methods) covers blockchain, EVM-compat, accounts, token, models and inference (every modality), distributed MoE (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`), app hosting (sites, functions, machines, leases), settlement, escrow, agents, identity, network, governance, payments, AP2, staking, Canton (28 methods), marketplaces, bridges (40+ methods covering all fifteen adapters plus the unified router), NFT, compliance, events, TEE, ZK, VRF, skills, tools, capital intent, workflow, ERC-7683, Permit2, EIP-7702, Secure-Mint, adaptive burn, SeedAgent, agent memory, SIWT, KERI, Universal Resolver, Institution-LEI validation, IBC-Eureka, BitVM2, Hyperbridge, NEAR Chain Signatures, Stargate V2, MPC pre-sign and PKR observability, and global-supply registry. Every method authorizes through TDIP and binds to the caller's identity. Body and concurrency limits cap DoS surface.

### MCP (Model Context Protocol)

The MCP host serves 500+ tools to any MCP-compatible client. Beyond the main Tenzro MCP server, the node runs six ecosystem MCP servers for Solana, Ethereum, Canton, LayerZero, Chainlink, and LI.FI — each a complete tool surface for its target ecosystem (Solana Jupiter swaps + SPL transfers + SNS resolution; Ethereum Chainlink price feeds + ENS + ERC-8004 lookups + EAS attestations; Canton command submission + party allocation + DvP; LayerZero V2 send / quote / track + OFT + Stargate; Chainlink CCIP + Data Feeds + Data Streams + VRF + PoR + Automation + Functions; LI.FI quote / routes / status / chains / tokens / execute). All seven MCP servers honor graceful shutdown and carry concurrency + body-size limits.

### A2A (Agent-to-Agent)

The A2A host implements the Google A2A specification — `message/send`, `tasks/send`, `tasks/get`, `tasks/list`, `tasks/cancel` over JSON-RPC 2.0, with SSE streaming for long tasks. The Agent Card publishes 50+ skills covering wallet, identity, inference, distributed MoE, settlement, verification, staking, marketplaces, agent spawning, swarm orchestration, lifecycle, bond / insurance, token, contract, AP2, ERC-8004, Wormhole, CCT, auth, NFT, bridge, compliance, cross-chain, events, every multi-modal AI modality, workflow, Canton, agent memory, adaptive burn, SeedAgent, ERC-7683, capital intent, EIP-7702, Permit2, Secure-Mint, Hyperlane, Axelar, Babylon, IBC-Eureka, BitVM2, Hyperbridge, NEAR Chain Signatures, Stargate V2, CAIP, KERI, SIWT, Universal Resolver, Institution identity, MPC pre-sign / PKR, and operability.

Both MCP and A2A can also be carried over iroh's QUIC-native transport via dedicated ALPNs (`tenzro/a2a` and `tenzro/mcp`), so agents that prefer content-addressed peer transport over HTTP can connect peer-to-peer with no router in the middle.

### Agent kit and templates

`tenzro-agent-kit` is the agent template system. Reference templates — paid marketplace, intelligent payment router, MPP payment agent, autonomous RWA custodian, agentic inference marketplace, model inference proxy, bridge arbitrage scanner, multi-chain portfolio manager, yield rebalancer, cross-chain liquidity aggregator, Canton trade settler, agentic NAV calculator, agentic LC examiner, agentic treasury rebalancer, agentic margin call, agentic bond pricer RFQ, agentic best-execution router, DvP atomic-swap saga, and per-modality trainers — are ready-to-instantiate JSON manifests. Each manifest declares the execution backend, the delegation scope, the required tool tags, the required skill tags, and the ordered step set the agent walks at runtime.

The spawner instantiates an agent: provisions its TDIP identity, mints its MPC wallet, installs the delegation scope, populates the runtime spending policy, discovers the matching tools and skills, and registers it with the runtime. The kit charges a 5% creator commission on paid invocations and routes the rest to the template's creator wallet.

### WASM skill runtime and WIT registry

Sandboxed third-party skills run inside the `tenzro-wasm` host on WASI 0.2.9. The host serves Tenzro-specific imports (`ledger`, `signing`, `identity`) plus the standard WASI base (`io/streams`, `clocks`, `random`, `cli`) to component-model guests. Three packages pin the host/guest contract — `tenzro:skill@1.0.0` for generic skills, `tenzro:mcp-tool@1.0.0` for MCP tools, and `tenzro:a2a-skill@1.0.0` for A2A skills — each published as WIT files in the agent-kit registry. The host rejects guests whose declared package version drifts from what it advertises, so a sandboxed skill never loads against an incompatible host contract.

---

## 15. Token economics

TNZO is the network's gas, settlement, staking, and governance token. The maximum supply is 1,000,000,000 TNZO, denominated in 18 decimals.

### Three demand sources

- **Gas** — every transaction pays gas in TNZO under EIP-1559. The base fee is burned; the priority fee goes to validators and stakers.
- **Settlement** — every payment routed through Tenzro pays a network commission (currently 0.5%). The commission is split 40% treasury / 30% burn / 30% stakers.
- **Bonds** — providers (validators, model providers, TEE providers, trainers, bridge nodes, agents) bond TNZO. Misbehavior is slashed against the bond.

Every demand source grows with usage. Burn channels are demand-driven: more network activity means more burn means more deflationary pressure on circulating supply.

### Capacity rental and escrow

A consumer can reach provider capacity two ways: **pay-per-use** (metered per call or per token, paid after the unit is served) and **time-based rental** (reserving a provider's capacity for a fixed term — hourly through annual — at an agreed rate). Both settle in TNZO from the same consumer deposit and rest on the same provider stake.

Rental introduces a timing asymmetry pay-per-use does not have: the consumer is paying for future capacity. Paying upfront exposes the renter if the provider vanishes; paying at the end exposes the provider if the renter walks. Tenzro resolves this with **streaming escrow**. The renter funds an on-chain deposit; booking locks the term's value inside it; each settlement epoch a valid availability proof (heartbeat plus capacity attestation) unlocks that epoch's slice to the provider. A missed proof makes the renter whole *immediately from the provider's stake* — no dispute window — and repeated misses auto-terminate the rental. Neither party is ever exposed for more than one epoch.

The provider's stake does triple duty: it secures consensus, gates serving eligibility, and collateralizes every rental obligation. There is no separate per-rental bond. A provider may hold concurrent rentals only while `stake ≥ Σ(active per-epoch exposure)`; staking more is the market knob on serving capacity. Each epoch's release pays the standard 0.5% commission, and the batch of usage and availability receipts is Merkle-rooted on-chain and crossed to Canton for audit — the money settles per-transaction, the evidence anchors as periodic roots.

### Adaptive burn dial

A governance-controlled adaptive burn dial lets the protocol adjust the burn fraction in response to circulating supply targets. The dial reads rolling-window supply metrics (epoch deltas, basis-point change vs. target), computes a recommendation under bounded magnitude caps, and can be triggered automatically by the supply-target alarms or manually by a governance proposal. The paymaster burn fraction is locked at 100% so paymaster-sponsored gas does not create a back-door inflation path.

### SeedAgent treasury allocation

The bootstrap phase of any agentic protocol faces a chicken-and-egg problem — no organic agents exist yet, so the protocol has to seed activity to demonstrate the rails work. SeedAgents are protocol-funded autonomous agents that exercise inference, settlement, marketplace, bridge, and dispute surfaces during the first year. They draw from a governance-bonded treasury earmark with a decay schedule (100% months 0–2, 75% months 3–5, 50% months 6–8, 25% months 9–11, 0% from month 12). The `is_seed_agent` flag lets every analytics surface cleanly separate protocol-owned bootstrap activity from organic. After sunset, any unused earmark is burned.

### Staking

Validators, model providers, TEE providers, and storage providers stake TNZO. Stake bonds the operator to honest behavior — equivocation slashes 10% of stake, withholding training results slashes against the training bond, and rampant inference failures slash through the reputation system. Liquid staking (stTNZO) is available — a rebasing token tracking the staked principal plus accrued rewards minus the 10% protocol fee. Unbonding is seven days.

### Governance vote weighting

Stake-weighted with quadratic dampening on the upper end so a single very large staker cannot dominate. Verified credentials give a bonus weight (KYC-Full carries more weight than KYC-Basic on votes that involve treasury disbursements or constitutional changes). Delegate-voting is supported: a staker can delegate their voting weight without delegating their stake.

### Bridge fee sponsorship

Bridges can be expensive for small payments. Tenzro supports bridge-fee sponsorship pools that subsidize cross-chain settlements for end users (and for agents) in exchange for protocol-level commission on the underlying flow. Operators contribute to the pool; routes that are eligible draw from it automatically.

A complete economic specification is in `docs/TOKENOMICS.md`.

---

## 16. Governance

Governance is on-chain through the governance engine. Anyone with the minimum proposal bond can submit a proposal; proposals enter a voting window during which staked TNZO and stTNZO holders cast votes; passing proposals execute through the governance executor.

Proposals fall into three classes:

- **Parameter changes** — staking minimums, network commission rate, burn-channel splits, EIP-1559 parameters, model registry policy.
- **Treasury disbursements** — grants, ecosystem incentives, audits, infrastructure.
- **Code upgrades** — binary upgrades roll across the fleet under operator coordination once the on-chain proposal passes.

The governance executor mints and burns through the staking and token managers, never directly through privileged keys.

Specific parameter dials — adaptive burn fraction, SeedAgent treasury sweep, bridge fee schedule, KYC-tier upgrade endorsements — are scoped to a specific proposal class with tighter or looser timelock per the risk profile. Constitutional changes (chain ID, consensus algorithm, genesis-schema shape) require supermajority and a long timelock.

---

## 17. Security model

The threat model assumes:

- A subset of validators (up to but not including the BFT bound) is Byzantine.
- A subset of bridges may be compromised or quorum-busted on the other side.
- TEE attestations may be temporarily forged by hardware exploits; the protocol must remain safe without unique reliance on any one vendor.
- Adversaries have classical and conjectured quantum compute.
- Payment counterparties may be hostile; some are sanctioned; some attempt double-spend or front-run.

Mitigations:

- **BFT consensus.** HotStuff-2 safety holds under up to (n−1)/3 Byzantine validators.
- **Equivocation detection + slashing.** Double-signing burns 10% of stake.
- **Hybrid signatures.** Ed25519 + ML-DSA-65 + BLS12-381 means an attacker has to defeat all three to forge a vote.
- **TEE-independent operation.** A node can run without any TEE and remain a full participant; TEE only gives a draw-weight multiplier.
- **Fail-closed inbound bridge verification.** Every adapter verifies inbound outer-envelopes against its configured trust source (Guardian set, validator multisig, threshold validator set, Canton synchronizer).
- **Custody at signing time.** ERC-7579 validators enforce spending limits, session-key allowlists, and recovery quorum at `validateUserOp`. Off-chain spending policy is defense in depth, not the primary control.
- **Anchored snapshot bootstrap.** Joining nodes specify a block hash they trust; the protocol refuses to bootstrap from a mismatched snapshot.
- **Permission-scoped admin surfaces.** Privileged operations (cross-chain mint/burn, bridge authorization, compliance freeze, secure-mint policy mutation, delegation-scope tweaks, Canton operator surfaces) gate on the operator admin token. Tenant API keys cannot escalate.
- **Reserve-bound minting.** Tokenized assets cannot mint past their attested reserve.

External security audits cover crypto, consensus, VM, bridge, and TEE. Cross-validator behavior is monitored via Prometheus / Grafana; equivocation alerts page on-call.

---

## 18. What you can build

The same Tenzro stack underwrites a wide range of applications.

**Agentic finance.** An agent runs on the user's behalf with a scoped delegation. It scans yield across Aave-class money markets on Arbitrum, swaps stables through a Solana DEX, settles a margin call on a Canton-tokenized treasury, and posts an audit receipt on Tenzro. The user retains the right to revoke at any time and the per-day spend cap holds across every leg of the workflow.

**Tokenized RWA settlement.** An institutional asset manager mints a tokenized money-market fund on Canton, books a sale through the JSON Ledger API, settles payment on the EVM surface (Permit2 + EIP-7702), and emits an on-chain NAV receipt with a Plonky3 proof of the underlying calculation. Privacy holds — only the counterparties see the trade body — while the public commitment is verifiable.

**Open-source inference at scale.** A provider runs a heterogeneous fleet (a few H200s, a few Apple Silicon nodes, a few Hopper-class consumer GPUs) serving Qwen, Gemma, Mistral, and TimesFM at the same time. Users pay per call, providers settle per-token, reputation gates routing decisions, and the network commission funds protocol development and burns.

**Generative media rendering.** A studio posts a batch of text-to-video jobs with a per-job TNZO ceiling and no chosen provider. Workers holding Wan 2.2 claim them; because that model's denoising schedule divides at a timestep boundary, two 48 GB accelerators can split a model that needs 80 — one renders while the noise level is high, hands over a single intermediate latent, and the other finishes. Payment divides by the step counts in the signed handoff. The studio verifies each output against the content hash in its receipt before paying, and fetches the bytes peer-to-peer rather than from a vendor endpoint.

**Distributed training.** A coalition of operators sponsors a TimesFM-class forecast training run with a TNZO escrow. Trainers across regions contribute outer gradients; the syncer committee aggregates and finalizes; the run-root commits on-chain; receipts release escrow proportional to contribution. Misbehavior is slashed.

**Cross-chain agent commerce.** An agent registered on the Tenzro marketplace fulfills inference, swap, bridge, and settlement requests across ten ecosystems through one identity. Payments arrive in TNZO, stablecoins, or Canton Coin and route into the agent's wallet. ERC-8004 reputation feedback gates discoverability.

**Gated RPC provider.** An operator runs a public RPC endpoint for a specific class of network resources — Canton institutional settlement, regulated cross-chain routes, KYC-tier-gated services, admin-gated mint and burn. They mint scoped API keys for tenant developers, manage per-tenant party allocation, identity-provider provisioning, and per-tenant analytics. Tenants present the API key (and where required, their own JWT from the per-tenant identity provider) on every call; the operator's RPC endpoint forwards as the tenant's bound party. The operator earns from tenant subscription, per-call fees, and commission on the underlying flow.

**Confidential computing services.** A custodian runs a TEE provider that holds tokenized RWA keys behind sealed-key custody. Customers attest the enclave, post requests sealed against the enclave pubkey, and receive signed receipts. The protocol enforces SLA via the bond posted by the provider.

**Agent-to-agent commerce.** Two agents discover each other through the A2A directory; one offers a forecast service, the other consumes it. They negotiate price, settle through MPP, and post a receipt. Neither has a controller in the loop. Both are TDIP-registered so the audit trail is full.

These are not hypotheticals — every primitive named above is present in the current Tenzro Network release. The combination of identity, custody, multi-VM execution, cross-chain reach, AI infrastructure, distributed training, confidential execution, verification, and protocol-level settlement is what makes the agentic economy buildable on one substrate.

---

## Glossary

- **A2A** — Agent-to-Agent protocol; the Google specification for inter-agent JSON-RPC with optional SSE.
- **AP2** — Agent Payments Protocol; checkout / payment mandate validation for agent-initiated payments.
- **BLS12-381** — Pairing-friendly elliptic curve used for signature aggregation.
- **BitVM2 / Clementine** — Trust-minimised two-way Bitcoin peg with optimistic challenge protocol.
- **Canton** — A privacy-preserving distributed ledger for institutional financial settlement, DAML-based.
- **DKLS23** — Threshold ECDSA signing protocol (Doerner-Kondi-Lee-Shelat 2023).
- **EIP-1559** — Ethereum fee-market upgrade with base-fee burn.
- **EIP-2537** — BLS12-381 precompiles.
- **EIP-4361** — Sign-In with Ethereum message format; the SIWT canonical form follows the same shape.
- **EIP-7702** — Set-code transaction type that lets EOAs temporarily delegate to contract code.
- **ERC-4337** — Account abstraction via the EntryPoint and UserOperation.
- **ERC-7579** — Modular smart-account validator standard.
- **ERC-7683** — Cross-chain intent settlement standard.
- **ERC-7802** — Cross-chain native-token mint and burn.
- **ERC-8004** — Trustless agent identity registry.
- **GLEIF** — Global Legal Entity Identifier Foundation; issues LEIs under ISO 17442.
- **HotStuff-2** — Three-phase BFT consensus algorithm with linear communication.
- **HPKE** — Hybrid Public Key Encryption per RFC 9180.
- **IBC-Eureka** — IBC over an SP1-compressed Tendermint light client.
- **ISMP** — Interoperable State Machine Protocol; the HTTP-shaped cross-chain message surface Hyperbridge serves.
- **KERI** — Key Event Receipt Infrastructure; self-certifying identifiers with hash-chained key event logs and pre-rotation.
- **KoalaBear** — A 32-bit prime field optimized for STARK provers.
- **LEI** — Legal Entity Identifier; 20-character ISO 17442 code anchored to a legal entity in the GLEIF registry.
- **MCP** — Model Context Protocol; a JSON-RPC tool-discovery surface for agent runtimes.
- **ML-DSA-65** — Module-Lattice Digital Signature Algorithm, FIPS 204; the post-quantum signature standard.
- **MoE** — Mixture-of-Experts; a transformer architecture that activates a small subset of expert FFNs per token.
- **MPP** — Machine Payments Protocol; session-based HTTP 402 payment with credential / receipt.
- **MTP** — Multi-Token Prediction; speculative decoding using a jointly-trained head sharing hidden state with the target.
- **Pixel-step** — The work unit for generative media rendering: `width × height × steps × frames`, with `frames = 1` for image jobs.
- **PKR** — Proactive Key Refresh; periodic rotation of DKLS23 keyshares that preserves the group public key.
- **Plonky3** — Recursive STARK prover over the KoalaBear field.
- **SIWT** — Sign-In With Tenzro; an EIP-4361-shaped message that off-chain services use to authenticate Tenzro identities.
- **SP1** — Succinct's general-purpose zkVM used by IBC-Eureka to compress Tendermint header verification into a plonk proof.
- **Stargate V2 Hydra** — LayerZero V2 OFT-based native USDC / USDT / WETH bridging.
- **TDIP** — Tenzro Decentralized Identity Protocol.
- **TEE** — Trusted Execution Environment.
- **TNZO** — The native token of Tenzro Network.
- **Universal Resolver** — DIF's standard HTTP API for resolving DIDs of any method; Tenzro serves `did:tenzro:` and `did:pdis:` through it.
- **vLEI** — Verifiable LEI; a GLEIF-issued ACDC credential cryptographically binding to an institution's LEI.
- **WIT** — WebAssembly Interface Type; the IDL pinning the host/guest contract for `tenzro-wasm` skills.
- **x402** — Stateless HTTP 402 payment protocol.

---

**License: Apache-2.0.**
