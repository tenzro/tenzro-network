# Tenzro Network

## An open network for the machine economy

**Version 1.1**

---

## Abstract

Tenzro Network is an open network for the machine economy, built to grow itself. Machines of every class, from small embedded and edge devices to the largest GPU servers, sell AI work under one identity model and one payment rail, and agents and apps buy it. A small number of people operate machines; most of the demand comes from agents, and from people using AI through apps who rarely care where it runs. Providers of compute, models, agents and apps are paid for verified work, and users and agents get capable AI at a fair price. The economy's job is a loop that reinforces itself: demand pays providers, provider income draws more supply, more supply improves price, quality and availability, and that draws more demand. Fees from real use carry the loop; rewards only help it start and never exceed what a settlement paid outside the trade.

The network gives humans and autonomous agents a single identity, a single wallet, and one settlement substrate that spans networks, models, payment rails, and execution environments. Agents discover models and services, negotiate terms, conduct economic activity, and settle across ecosystems without juggling separate keys, gas tokens, or trust assumptions. Humans retain control through delegated authority, scoped credentials, and on-chain custody primitives.

Tenzro Ledger is the settlement substrate underneath. It runs three execution environments in one runtime — EVM for liquidity and the broadest DeFi surface, SVM for high-throughput low-latency execution, and its native runtime for the protocol's own transactions. Consensus is a signature-free DAG protocol over post-quantum channels, with checkpoints certified by hardware-held composite ML-DSA-65 + P-256 keys, so finality remains sound under both classical and post-quantum adversaries.

Verifiability is built in. Plonky3 STARKs cover settlement and identity claims; TEE attestations (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU Confidential Computing, Intel Tiber) anchor confidential execution; the two combine through a hybrid ZK-in-TEE path. Cross-chain reach runs over one bridge path, governed routes under one set of rules (a CCIP-compatible envelope for EVM chains and Solana, IBC for Cosmos chains, a deposit route for Bitcoin, and bridge contracts on Sui, Aptos, Stellar and TON). Payments span MPP, x402, Stripe Payment Intents, Tempo, Visa Tap, Mastercard Agent Pay, and AP2 mandates — all bound to a Tenzro Decentralized Identity (TDIP) and enforced at signing time through ERC-7579 modular validators.

AI infrastructure goes beyond model serving. The model catalog covers language, vision, audio, video, time-series, segmentation, detection, and text embeddings across permissively-licensed open-weight families (Qwen 3 / 3.5 / 3.6, Gemma 3 / 4, Mistral, DeepSeek V3 / V4, GLM 5 / 5.1 / 5.2, Kimi K2 / K2.6 / K3, MiniMax M1 / M3, Granite, Phi 3, gpt-oss, Nemotron). Mixture-of-Experts architectures serve in two modes: full-replica per provider (the default) and **decentralized expert-shard serving** in which providers declare the subset of experts they hold and a dispatch planner batches tokens per holder. Multi-Token Prediction is wired through every layer — catalog metadata, provider capacity advertisement, router selection, and the llama.cpp `--spec-type draft-mtp` invocation — so models with a jointly-trained MTP head (Gemma 4, Qwen 3.5/3.6, DeepSeek V3/V4, GLM 5.2) generate at the higher speculative-decoding throughput automatically. Generative image and video rendering is a separate service rather than another router modality, because a render job's cost is fully determined the moment it is posted: work is metered in pixel-steps (`width × height × steps × frames`), the requester's ceiling is checked at admission, and a diffusion model whose denoising schedule divides at a timestep boundary can be served by two accelerators that each hold one half, splitting payment by the step counts in a signed handoff.

TNZO is the economic unit that keeps the network running: it prices and settles work on chain, it is what operators stake and are slashed in, and it pays the network's upkeep through fees and the treasury. Users do not need to hold it: fees are set in USD terms, and apps and platforms pay on their users' behalf in what those users already use. Every on-chain settlement pays a governed fee (10 basis points of the value settled at genesis, half burned, half to the treasury), each class of provider work can carry a governed treasury leg, and rewards are bounded by what each settlement paid outside the trade, so farming and self-dealing lose money at every level.

Decentralization is progressive. The network is bootstrapped by its first operators and opens in phases (a preview, then a testnet, then the stages governance decides on the way to mainnet); each step starts on measured evidence and an on-chain governance decision, never on a date.

This document describes what Tenzro is, why the design choices are what they are, and how the pieces compose.

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
10. [Applications on the network](#10-applications-on-the-network)
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

The economy is gaining a new kind of participant. Agents already fetch quotes, call tools, route payments and commission other agents, and the share of economic actions they carry out keeps growing. Most of the AI they use, and most of the AI people use, reaches them through apps that pick a model on price, latency and reliability. The machines that can serve that demand range from a single-board computer on a shelf to racks of data-center GPUs. What is missing is one open economy in which all of those machines can sell their work, all of those buyers can pay for it, and no single company sits in between.

Tenzro is that economy: an open network for the machine economy that grows itself.

**A few operators, demand from everywhere.** The network does not need everyone to run a node. A comparatively small number of people operate machines. Demand comes from agents, from apps and platforms that serve end users, from partners, and from developers calling models directly. The network is reached the way any model API is reached, through an OpenAI-compatible endpoint, so an end user never has to know it is there.

**Every class of machine.** One codebase builds release variants for every class of hardware, and each tier does the work it is good at:

- **Edge and light nodes**: small, embedded and edge devices (single-board computers with the Raspberry Pi as the reference device, Jetson-class modules, mini PCs, NAS boxes, gateways). They run identity, payments, agents and chain following today; the design gives them orchestration: hosting agent harnesses, running small local models, and routing work to other nodes.
- **Standard nodes**: CPU servers and workstations, which serve every role a CPU can.
- **GPU providers**: consumer GPUs to data-center accelerators, serving models, renting compute, running confidential workloads, and sharding models too large for any one machine.
- **Validators**: bonded machines with hardware-held keys that order transactions and certify checkpoints.

**Edge devices in the AI value chain.** Modern AI is used through model ladders: a cheap step routes, filters, checks or answers the easy cases, and an expensive model handles the rest. Tenzro is designed so that cheap hardware can be that step. An edge device hosts a deployable agent harness; the harness orchestrates agents, small models and other nodes, and calls GPU providers only for what needs a large model. Such a hybrid job pays every party that did work from the caller's own budget: the provider of the agent, the provider of the orchestration, and the provider that ran the model. Networks whose providers must own expensive GPUs limit who can take part; a tier of devices that cost about a hundred dollars widens it, while earnings still follow paid demand. Settlement names the app, agent and tool behind a payment and pays each payee directly (section 9).

**Earnings from work, never from presence.** Providers of compute, models, agents and apps earn for paid, verified work. Nothing pays for holding tokens, volume, sign-ups or engagement, and parties that share an identity root earn nothing from paying each other. The rules hold at every level, from a single settlement to the network's reward buckets (section 15).

**One identity for humans and machines.** A single Tenzro Decentralized Identity (TDIP) covers human users, delegated agents acting on a human's behalf, and autonomous agents that own themselves. The same identity carries verifiable credentials, delegation scopes, KYC tier, and the wallet that signs every action. Move across Ethereum, Solana, Bitcoin, Cosmos chains, and any of the supported destination chains without switching keys or wallets.

**Coordination across ecosystems.** An agent can fetch a lending quote on Arbitrum, settle a margin call on Ethereum, pay a Solana DEX for a swap, and post a receipt on Tenzro, all in one workflow, all from one wallet, all logged against one identity. Long-running workflows — multi-step trades, supply-chain settlements — run in harnesses over the public RPC, MCP, A2A and SDK surface, paying through escrows.

**Open models on owned hardware.** Any open model, any size, runs on hardware its operators own. Open-weight models of every modality run on the network — language, vision, audio, video, time-series forecasting, segmentation, detection, embeddings. Providers serve their own hardware (consumer GPUs to data-center clusters, Apple Silicon to NVIDIA H200, AMD Instinct) and earn per inference. Models too large for any single machine serve as distributed expert shards: providers hold the subset of experts they can fit, a dispatch planner batches tokens per holder, and settlement pays every holder for the work it verifiably did — so the largest open checkpoints run on pooled peer hardware instead of a hyperscale cluster. Users and agents pay per call, per token, or per session through the same settlement substrate.

**Distributed AI at protocol level.** Inference runs across independent providers on one identity and settlement plane.

**Human control through delegated authority.** Agents act under explicit delegation scopes — per-transaction caps, daily spending limits, allowed counterparties, allowed operations, time bounds. ERC-7579 modular validators enforce these at signing time, not after the fact. Session keys, social recovery, and hardware-bound passkeys let humans grant, restrict, rotate, and revoke agent authority without surrendering control of the underlying account.

**Settlement, not just messaging.** Where existing agent frameworks coordinate intent, Tenzro coordinates value. A protocol-level settlement substrate denominated in TNZO underwrites every economic action so an agent that promises to pay can be made to pay, and every receipt is verifiable on-chain.

The result is an open protocol where the AI economy can compose. No single vendor sits between agents and the resources they need.

---

## 2. The 2026 trajectory

Four forces are reshaping the protocol layer at once.

**Agents become economic actors.** Leading AI labs have released tool-using agents capable of multi-step planning. Payment rails (Stripe MPP, Coinbase x402, Visa Tap, Mastercard Agent Pay) added HTTP 402-based machine-payment surfaces in 2025–2026. Standards bodies published trustless-agent identity (ERC-8004), agent-to-agent protocols (A2A), authorization mandates (AP2), and cross-chain intents (ERC-7683). Agents need to discover, transact, and settle without a human in the loop, and the rails for that arrived this cycle.

**Open-source intelligence catches up.** Open-weight models from Qwen, Gemma, Mistral, DeepSeek, Granite, and others now match or exceed closed-source models on most public benchmarks. Inference moved from a handful of mega-providers to a long tail of operators running their own GPUs. Distributed low-communication training demonstrated that frontier-quality models can be trained across regions and operators rather than inside one data center. The bottleneck is no longer model quality — it is coordination.

**Regulation tightens.** The EU AI Act took effect in 2025 with Article 50 disclosure rules now binding. MiCA bound stablecoin and crypto-asset service providers in EEA jurisdictions. Travel rule enforcement extended to virtual asset service providers. Agent-driven payments require auditable receipts, mandate-bound authorization, and KYC-tier-bound delegation. Anything an institution can adopt has to make those legible at the protocol layer, not paper over them in app code.

The chain that wins the agentic decade has to bring these together — agent-native economic activity, open-source AI, regulatory legibility — under one identity, one wallet, one settlement substrate. That is what Tenzro is.

---

## 3. Architecture

Tenzro is built as a stack of focused crates that share a single state machine, a single consensus, and a single token. The pieces are designed to compose: the same TDIP identity authorizes a Solana swap and an EVM settlement; the same TEE attestation anchors a confidential inference; the same verifiers validate settlement and identity proofs.

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
│Multi │  │ DAG BFT  │  │ TEE +    │  │Storage │  │ Models  │  │ Identity      │
│VM    │  │ + PQ     │  │ ZK proof │  │RocksDB │  │+ Media  │  │ Wallet        │
│EVM + │  │ checkpt  │  │ stack    │  │+ DA    │  │         │  │ Custody       │
│SVM + │  │  certs   │  │          │  │+ iroh  │  │         │  │ Delegation    │
│native│  │          │  │          │  │        │  │         │  │               │
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

A single chain that picks one VM forces every workload to fit that VM. Tenzro runs the EVM, the SVM and its native runtime and routes by transaction type. Each is picked for what it does best, and all share the same state, the same gas token, and the same identity.

### EVM — liquidity and composability

The Ethereum Virtual Machine surface targets the broadest pool of liquidity, tooling, and existing contracts. Tenzro implements every standard precompile (ecRecover, SHA-256, RIPEMD-160, Identity, ModExp, EC_ADD, EC_MUL, EC_PAIRING, BLAKE2F) per the canonical EIPs, plus all seven BLS12-381 precompiles (EIP-2537) for native consensus-grade signature aggregation. Block-STM gives parallel transaction execution with optimistic concurrency control and automatic fallback under contention. EIP-1559 dynamic fee market burns the governed share of the base fee (all of it by default) and pays no fee to the block proposer; the rest goes to the treasury (section 15).

Native primitives extend the EVM with protocol-aware precompiles: `TEE_VERIFY` (`0x1010`) runs strict hardware attestation verification and refuses simulated reports; `ZK_VERIFY` (`0x1011`) answers whether a proof commitment was attested in consensus state; `RANDOMNESS_BEACON` (`0x1009`) returns deterministic per-request randomness derived from finalized block hashes; the wTNZO pointer (`0x1001`), `TOKEN_FACTORY` (`0x1002`), `NFT_FACTORY` (`0x1006`) and `VRF_VERIFY` (`0x1007`) give Solidity contracts direct access to native TNZO, ERC-20 issuance, NFT minting with verifiable randomness, and ECVRF. All of them run inside real transactions with the calling frame's `msg.sender`, `msg.value` and static flag, and every write goes through the EVM journal. ERC-4337 v0.9 account abstraction, EIP-7702 delegation, and ERC-7579 modular validators are all implemented natively — smart accounts, session keys, social recovery, and spending limits work without any setup contract.

### SVM — throughput and latency

The Solana Virtual Machine surface targets workloads that need sub-second finality and high throughput — DEX routing, agent-to-agent micro-payments, real-time settlement on a path. Tenzro embeds the Solana BPF runtime so Solana programs run unmodified. The SPL Token program maps onto the native unified token registry so a swap on the SVM surface settles in the same balance space as a transfer on the EVM surface. There is no bridging between the two.

### Cross-VM token model

TNZO has a single canonical native balance. The wTNZO ERC-20 pointer on the EVM side and the wTNZO SPL adapter on the SVM side share the same underlying balance — there is no bridge between them, no wrapped/unwrapped distinction. One transaction may call the EVM and the SVM in order, all-or-nothing. From the application's point of view, a wallet has one TNZO balance regardless of which VM it last touched.

---

## 5. Consensus

Tenzro Ledger orders transactions with a signature-free DAG protocol and makes the ordering transferable with post-quantum checkpoint certificates. The design is described in [`architecture/consensus.md`](architecture/consensus.md); its latency and throughput are measured by the proof-gate runs of the network emulator in `tenzro-consensus`, not asserted here. Each network's genesis sets its chain ID; the preview network's is 13380.

### Ordering

Validators talk over authenticated post-quantum channels on the node's iroh endpoint (ALPN `tenzro/consensus`): an X25519 + ML-KEM-768 handshake that both sides sign with their hardware keys, then a MAC on every frame. Nothing inside a frame is signed. Each validator proposes one vertex per round; a reliable broadcast makes every honest validator deliver the same vertex or none. A round's leader vertex commits once the next round's first proposals from a quorum of seats reference it, with no-vote certificates closing the tail-fork attack, and each committed leader orders its causal history into one block.

### Hardware-held post-quantum checkpoints

Every 500 ms of ordered history, validators sign a checkpoint (height range, blocks root, lagged state root, statement root, and at an epoch's end the next committee's root) with an in-memory composite ML-DSA-65 + ECDSA-P256 session key, which their hardware key (P-256 held in the Secure Enclave or TPM, ML-DSA-65 derived from it for each signature) certifies once per epoch; every vote carries that certificate, so it is attributable to the hardware key. There is no software validator key; a machine without the hardware follows the chain. A quorum of signatures is a certificate anyone can check. The RPC reports two finality heights: `ordered`, final for every honest validator, and `certified`, covered by a certificate; bridges act on `certified`.

### Leader schedule

Stake is apportioned into seats, with no one-seat floor, so splitting stake across validators buys no weight. The leader of each round is drawn by seats times observed behavior, from a seed taken from the committed prefix, so no validator can grind it. No VRF or BLS key and no self-reported value (including TEE attestation, which is a reputation signal only) enters the draw.

### Stake-weighted consensus, decoupled from service

Consensus and service are decoupled. Block finality is produced by a staked validator set whose voting power equals the bonded validator stake: checkpoint certificates form at a quorum of n − f seats (f = (n − 1) / 3), with stake apportioned into seats under a 10% per-validator cap, and the Byzantine bound `f` measured as a fraction of stake rather than a head-count of nodes. Only the validator bond carries finality weight. Service bonds — model, TEE, compute, storage, rail attestor, wallet provider, catalog publisher — carry none, so bonding for any number of service rungs cannot move a quorum.

Serving compute, storage, and security is a separate set of roles that earn through proof-of-service (pay-per-use, rental, and per-byte fees, section 15). Every rung bonds TNZO, but no service rung votes. The bond is what a defrauded counterparty is made whole from: invalid TEE attestations, upheld inference-verification challenges, and persistent SLA failure all slash against it. Admission stays permissionless — anyone who posts the bond and meets the resource profile may serve, with no allowlist and no committee. Compute and storage bonds scale with the capacity pledged, so a bond tracks the exposure it collateralizes rather than a flat fee (section 15). One operator may both validate and serve capacity, earning on both tracks. TEE attestation is an optional capability and a reputation signal; it never changes leader selection and is never an admission or voting gate. High-trust block classes (high-value bridge duties, institutional settlement routes) restrict leader election to validators above a higher stake and reputation bar, but rest on the same stake-weighted 2/3 bound. The result keeps the economic security budget concentrated entirely in validator-bonded stake while every service obligation carries its own collateral.

### Slashing and tail-fork resistance

A validator persists that it is about to sign a checkpoint before signing, so a crash cannot make it sign two with one index. Two signatures on different checkpoints with the same index are complete evidence: a `ReportCheckpointEquivocation` transaction carrying them is verified by the VM and recorded once; it slashes the signer by three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it (at least 5%, 15% for a validator that has offended before, at most the whole stake; earlier offenders are topped up when a later offence raises the rate), into the insurance pool, and every node jails the signer when it replays the log. Tail forks are closed by the commit rule itself: a leader vertex that skips the previous leader counts only with a quorum of no-votes.

### Catch-up and recovery

A node that joins late restores the committed state from peers over iroh, anchored to a weak-subjectivity checkpoint: a block hash it trusts, from a `[weak_subjectivity]` block in the genesis or the `--checkpoint-hash` / `--checkpoint-height` flags. The snapshot's anchor chain must end in that block, every anchor block's body must match its header, the manifest's bucket summaries must fold to the state root that block commits, and each bucket must rebuild its summary before it is written; after the last bucket the node's own trie must reproduce the root. New validators do not silently adopt a hostile fork. From there a follower imports a block only once a certificate it verifies covers it, the blocks rebuild the certified blocks root, and its own state root matches the certified one; block sync runs over the iroh ALPN `tenzro/block-sync` from committee members' endpoints. A validator that restarts rebuilds its consensus state from a recovery journal it writes before sending anything, and resumes its epoch.

### Stable validator lifecycle

Validators upgrade their binary in place. The deploy preserves the local chain DB across rolls, and on boot the node runs a genesis match check (`verify_genesis_matches`) that compares the configured genesis chain_id and computed state_root against what's persisted under `CF_METADATA`. Identical genesis loads existing state; drift fails loud with an actionable error.

Nodes join by machine identity. A boot entry is `did:tenzro:machine:<id>[@<relay url>]`, never a network address; the genesis validators are the default boot set, their identities derived from their consensus keys. Each machine's hardware key signs a short-lived endpoint record naming its per-boot iroh endpoint and the relays it is reachable through. Records travel on Tenzro's own discovery network, stored and answered by every node, so any known node identity is a way in. Relaying is an operator role announced by identity, and no relay or discovery host is built in.

Epochs end at a checkpoint that commits the next committee, derived by every node from the same executed state; the old committee orders two more checkpoints and hands over. New validators register with `RegisterValidator`, carrying a proof of possession of their hardware key, and are seated at an epoch boundary. Genesis validator entries are printed on each machine by `tenzro-node validator-entry`.

---

## 6. Identity and custody

The Tenzro Decentralized Identity Protocol (TDIP) defines a single identity model that covers humans, delegated agents, and autonomous agents. Every action on the network resolves to a TDIP DID; every payment, every signature, every credential ties back to it.

### Four identity classes

- **Human** — `did:tenzro:human:{uuid}`. Carries display name, KYC tier (Unverified / Basic / Enhanced / Full), and the set of machines the human controls. A human identity can issue verifiable credentials, can be the controller of any number of delegated agents, and signs with a passkey-bound permissionless wallet — no custody is held on its behalf.
- **Delegated agent** — `did:tenzro:machine:{controller}:{uuid}`. An agent acting on a human's behalf. Carries a delegation scope inherited from the controller — per-transaction value cap, daily spend cap, allowed operations, allowed chains, allowed payment protocols, time bound, allowed counterparties. The controller can revoke at any time; revocation cascades.
- **Autonomous agent** — `did:tenzro:machine:{uuid}`. An agent that owns itself. Same permissionless wallet — the signing key lives in its own TPM or Secure Enclave — same A2A surface, but no controller. Used for self-funded autonomous services.
- **Institution** — `did:tenzro:institution:{lei}:{uuid}`. A legal entity anchored to its GLEIF Legal Entity Identifier (ISO 17442). The 20-character LEI is validated with ISO 7064 Mod 97-10 check digits at registration and at every transaction that consults the identity. One legal entity can hold many institution identities (one per desk, fund, or subsidiary) without re-issuing LEIs — the trailing UUID disambiguates. Institutions carry a KYB tier, an optional vLEI ACDC credential id binding to the GLEIF vLEI Ecosystem Governance Framework, an ISO 3166-1 alpha-2 country code, and the set of machines the institution controls. KYB-Full institutions act as trust roots for tokenized RWA flows, and, bonded as attestors, can attest the reserves behind reserve-backed tokens.

DIDs resolve through standard W3C DID Documents. Certifications, ratings and KYC are W3C VC 2.0 credentials any issuer signs with its hardware-derived DID; no issuer is privileged by the network, and each relying party names the issuers it recognizes in its own trust list (see [TRUST.md](TRUST.md)).

A Universal Resolver-compatible HTTP surface (`/1.0/identifiers/{did}` and `/1.0/methods`) at the web verification API serves `did:tenzro:` and `did:pdis:` to any standards-compliant resolver driver — Vidos, Godiddy, the Spruce SDKs, browser wallet extensions — without a Tenzro-specific adapter. KERI compatibility is implemented for long-lived autonomous machine identities — every machine identity can publish a hash-chained Key Event Log with pre-rotation commitments so persistent control survives key compromise. Inception, rotation, and interaction events use a SAID prefix `S` (SHA-256, CESR code) and validate through the standard KERI rules.

### Sign-In With Tenzro

Off-chain services authenticate Tenzro identities through SIWT — an EIP-4361-shaped message that the wallet signs and the relying party verifies against the registered identity. The canonical message carries the requesting domain, the Tenzro address, a nonce, the chain id, an issued-at timestamp, optional expiration and not-before bounds, and the resources the signer authorizes. Verification is non-stateful — the relying party stores the issued nonce, dispatches the signed message, and checks the signature against the resolved DID Document. Existing SIWE parsers consume SIWT messages byte-for-byte.

### Wallets — passkey-first, permissionless, post-quantum hybrid

The default Tenzro wallet is a passkey-bound permissionless wallet — no custodian, no gatekeeper, and no share of the key held anywhere off the user's own hardware. Account creation is one tap (Touch ID / Face ID / Windows Hello / Android biometric) using FIDO2 / WebAuthn on a single device — no seed phrase to write down, no extension to install, no email to verify, and no second share-holder to enrol before the wallet exists. Cross-device sign-in uses caBLE QR, which is also the pairing path for an optional guardian device (see “Devices bound to an identity” below). The on-chain twin of the passkey is a P-256 WebAuthn validator module (ERC-7579) that verifies the assertion signature directly inside the account validation path — though a passkey counts as hardware-bound only once its attestation has been verified against a pinned vendor root, not merely because it came from a platform authenticator.

Under the hood the classical signing key is held in the identity's own hardware — a passkey-backed platform authenticator for a human, a TPM 2.0 or Secure Enclave for a machine — and it never leaves the device. The network holds no share of it; the hardware root is the wallet. ML-DSA-65 is layered on every safety-critical signature, producing a post-quantum hybrid that satisfies both the classical and PQ verification paths simultaneously against that single hardware-held key. The cross-chain bridge holds no shared or enclave-held key: each route is attested by a committee drawn from bonded attestors, every member signing with the bridge signing key it declared when it bonded, and a destination contract accepts a delivery once a threshold of those members has signed. No key is kept or derived inside a TEE.

Production custody rests on three live mechanisms rather than any protocol-held key material. The signing key is hardware-held and sealed to its root, so a stolen disk or a container escape yields ciphertext, not a usable key. Recovery runs through a guardian set — the social-recovery validator can replace the root key without changing the account address (below). And every user operation is gated by ERC-7579 policy modules at the EntryPoint, so custody is enforced on-chain at signing time, not by an off-chain quorum.

### What anchors a machine identity

A machine identity has to be answerable to something other than itself. An
identity that answers only to itself is a self-issued claim — indistinguishable
from ten thousand more minted by the same script — so Tenzro admits a machine
only under one of two anchors, and there is no third:

- **Delegated** — a human or an institution registered the machine and remains
  accountable for it. The controller's own identity is the anchor.
- **Hardware-rooted** — nobody delegated it, and an **attestable** root of trust
  stands in the delegating party's place: a TPM endorsement key, a Secure Enclave,
  a SEV-SNP VCEK, an SGX/TDX provisioning id, a StrongBox or QFPROM key, an
  ATECC608 or SE050 element, an ESP32 digital-signature peripheral.

The distinction that carries the weight is **attestable versus merely per-unit**.
Identifier sources are graded in three tiers. `Model` sources (Arm `MIDR_EL1`,
x86 CPUID) name a design, not a unit. `Fused` sources (Intel and AMD PPIN, Apple
ECID, Allwinner SID, Rockchip OTP, Raspberry Pi serial, SMBIOS UUID) are per-unit
but *readable* — anything running on the machine can read them and anything
anywhere can then claim them. Only `Attestable` sources prove possession without
disclosing a secret, and only those anchor a machine nobody delegated. Accepting
a fused serial would make the anchor rule cosmetic.

**Accelerator identifiers are never identity.** A GPU is the most-swapped
component in a machine; rooting identity in one makes the identity follow the
card out of the chassis. No source in the graded set names a GPU, and a test
fails the build if one is ever added.

A machine that holds its own signing key **seals it to that hardware root**
rather than writing a keyfile. A key in a file is copyable by anything that can
read it — a backup, a stolen disk, a container escape, a misapplied `chmod` — and
copying it makes you the machine, with no human to notice. The blob on disk is
ciphertext under the TPM's storage hierarchy; a host that cannot seal is refused
rather than degraded to plaintext. This is the anchor rule seen from the other
side: the machines allowed to speak for themselves are exactly the machines able
to seal the key they speak with.

**Ownership moves on whatever anchors the machine.** A delegated machine
transfers on its controller's authority; a hardware-rooted machine transfers on
proof of its root. The two are not interchangeable — holding the hardware cannot
take a machine that has an accountable party, because that is a compromise rather
than an acquisition. Ownership replaces rather than accumulates, and every
authorisation is time-bounded so it cannot be replayed against a machine that has
since changed hands.

### Devices bound to an identity

A Tenzro identity links devices the way a platform account links them — except
the link is not a platform account. **No Apple, Google or Microsoft sign-in is an
identity authority here.** What the network trusts is a signature from
vendor-placed hardware over a challenge Tenzro chose, verified against a root the
operator pinned and matched by AAGUID through the FIDO Metadata Service.

A device counts as **hardware-bound** only when both hold: the credential cannot
be replicated off the device, and an attestation says its key lives in a TEE or
secure element. Neither implies the other. A WebAuthn credential advertising
backup-eligibility is disqualified outright — a credential that *may* sync proves
control of a cloud account, not possession of a device — and this is checked
before anything else, because a credential claiming to be device-bound while
admitting it is syncable is describing two different things. Where the
certificate chain cannot be verified the grade is *degraded* rather than the
parse failing, so an operator who has pinned no roots gets an honest
`chain_verified: false` instead of a silent pass.

For a phone there is no readable per-unit serial to collect — Apple and Google
removed them from application reach years ago, deliberately. The attested
credential key *is* the device identity, which is why the attestation and not the
serial is what gets checked.

**A wallet is created behind a single device; a guardian is added, not required.**
The machine the user is already on is enough to create the wallet — its hardware
root holds the key from the first tap. What one device cannot do is survive its own
loss: a wallet held behind one device alone is lost with that device, and two
passkeys on one laptop are two ways into one box that a single failure takes
together. So the interface treats a second hardware-bound device — a phone, another
machine — as the recovery guardian to bind next, not as a share the wallet waits on
to exist. The readiness check names that gap and its remedy, so an interface says
"scan the pairing QR code with your phone to add recovery" rather than blocking
creation.

Sessions name the **bound device** that authorised them, not merely the identity.
A session recording only that a user is signed in cannot be revoked when they
lose a phone without signing them out everywhere, including from the laptop still
in their hands. Unbinding a device therefore ends exactly the sessions it granted,
and both happen in one action — removing the device while leaving its sessions
live would preserve the very access the user is trying to cut off.

### Custody enforced in consensus

Custody rules live in consensus state, not in application code or a contract a wallet chooses to call:

- **Keystore.** A passkey account's keystore (its linked passkeys, recovery signers and any pending recovery) is chain state. Every validator verifies the passkey assertion on each of the account's transactions against it; any linked device approves, and recovery by the account's recovery signers completes only after a wait any passkey can cancel.
- **Agent Terms.** A delegated agent acts within Terms recorded on chain: per-transaction, hourly and daily spend limits, allowed operations, counterparties and chains, and an expiry. Every validator checks each of the agent's actions against them.
- **Owned, funded agents.** Every agent has an owner: a person (passkey) or an autonomous machine (TPM). The owner funds the agent's wallet, and the budget is the funding: a task can never spend more than was put in. The owner can pause an agent, after which it pays nothing (`PauseAgent`); return its unspent funds at any time, whatever its state (`ReclaimAgentFunds`); and allow refills from the owner's wallet within an allowance (`SetAgentTopUp`, then `TopUpAgent`, which anyone may send). An allowance always expires, within the governed `agent.topup_max_days` (90 at genesis), and a pause suspends refills.
- **Sponsored changes.** A sponsor can send a keystore change or an agent's Terms with the passkey's approval inside and pay the fee; the approval, not the sender, is what authorizes it.

### Pluggable signers

For users and operators with existing key infrastructure, a `PluggableSigner` trait lets external wallet backends — hardware wallets (Ledger, Trezor, GridPlus Lattice1, YubiKey) and HSMs — drive Tenzro signing without modifying the wallet crate. The passkey-first default and the pluggable path coexist; both produce signatures the protocol verifies identically.

---

## 7. Payments and settlement

Payment is where agents and humans most need a unified surface. Tenzro supports every major HTTP 402-based machine-payment protocol natively, every protocol is bound to TDIP identity, and every settlement enforces both the protocol-layer delegation scope and the runtime spending policy.

### Protocols supported

- **MPP (Machine Payments Protocol)** — session-based streaming credential / receipt flow; deep integration with Stripe Payment Intents API, including HMAC-SHA256 webhook verification per RFC 2104.
- **x402** — stateless one-shot HTTP 402 payment, including the Coinbase CDP facilitator with EIP-3009 `transferWithAuthorization` calldata.
- **Stripe SPT (Shared Payment Token)** — Stripe's agentic-payment primitive; settlement outcome dispatched as ERC-8004 reputation feedback.
- **AP2 (Agent Payments Protocol)** — Checkout/Payment mandate-pair validation with nested checks (AP2 CheckoutMandate cap + the agent's consensus Terms + on-chain escrow + Stripe SPT usage limits).

Every payment surface asks the same check: a delegated agent pays only inside its consensus Terms (scope, per-transaction and per-period limits, counterparties, protocols), read from chain state, and any AP2 mandate is validated against the parent CheckoutMandate constraints. Either can refuse.

### Native settlement primitives

Tenzro implements settlement as a protocol primitive rather than a contract:

- **Escrow** — `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow` are typed transactions; funds lock at a deterministically-derived vault address with no private key; release and refund are authorized only by the payer; full RocksDB durability and hydration on restart.
- **Payment channels** — per-token billing against an escrow the payer funds on the ledger; the payer signs cumulative vouchers off-chain and the payee claims the advance with `ClaimEscrow`; the unclaimed remainder is refunded only after expiry.
- **Batch claims** — one `ClaimEscrow` transaction claims from several escrows and applies all claims or none; `ClaimEscrowPreimage` pays a hash-locked escrow against the lock's preimage.
- **Reserve-bound minting** — a reserve-backed token mints in consensus only against signed, time-bound reserve attestations covering the supply after the mint, from bonded attestors whose stake together meets the token's backing; any bonded attestor may attest.

### Who is paying, and on what terms

Three access tiers describe how a party reaches a node's resources. They are
distinct relationships, not tiers of the same subscription:

- **User** — a human, agent or machine paying **on demand** for what it uses.
  No prior relationship, no credential to issue: a public node is reachable by
  payment alone.
- **Subscriber** — a developer, user or machine that subscribes to resources on
  a node and reaches them signed in, with an **access token** for a DID the
  operator's access policy names.
- **Renter** — a party that locks up funds or pays upfront for **raw resources**
  (compute, storage, memory, security), bounded by the rental's own term.

The node operator is the admin: they write the access policy that decides who
may use each surface, and the terms of every rental. A **private** node — one
connected to the network but not advertising itself — is reachable only as
that policy admits, which is what makes "private" a statement about discovery
rather than about connectivity.

Kept deliberately separate from all of this: an **RPC provider selling scoped
access to external networks** (other chains) to its own tenants bills
those tenants directly, the way any blockchain RPC provider does. That revenue is
the provider's own and never touches the settlement split — conflating the two
would double-count a node's RPC-provider leg against a business the split has no
claim on.

### Metering is per unit, and every modality has units

Billing meters the unit the work is actually done in, and **Tenzro is not an LLM
network**. Language models are one modality among many: vision, image, video,
world models, timeseries, embeddings, audio, segmentation and detection all
serve on the same rails, and each has its own natural billable dimension —
tokens, images, frames, seconds, samples, or embedded items. A single billable-units
type carries all of them, so the meter, the receipt and the settlement path do
not branch per modality and a new modality does not need a new payment surface.

Per-unit metering is what makes agentic microtransactions viable: an agent
consuming a stream pays for exactly the units it consumed rather than a rounded
session. x402 carries this natively. Alongside the exact scheme, a **ceiling
scheme** lets a buyer sign a maximum while the seller settles the actual amount
consumed — the shape agentic streaming needs, since neither side knows the final
count when the request starts — and a batch-settlement scheme amortises many
small charges into one on-chain settlement so the settlement cost does not
dominate the payment. Charges below a governance-set floor accumulate instead of
settling individually.

### Paying in what you hold, being paid in what you chose

Humans, machines and agents all pay the same way, and they may pay in a
stablecoin or another accepted asset rather than being forced to acquire TNZO
first. The network takes TNZO by default, with a governance-settable override;
an operator may instead elect to keep the inbound asset. What is not permitted is
silently crediting a payee an asset they did not choose — a payee who declared
TNZO receives TNZO or the payment is **refused**, because handing them something
else would be a substitution nobody agreed to. The preference belongs to the
payee and is authorized by their own identity key, not by an administrator of the
node hosting them, so a shared node's operator cannot change how their tenants
get paid.

### Funding an agent across the fiat boundary

Tenzro is **not a licensed provider**. KYC, fiat
acceptance, card issuance and network settlement are each performed by a
licensed party that already does them well. What Tenzro adds is the layer none
of them occupy: a portable agent identity with enforceable delegation, so the
same agent can be funded through one provider, spend through another, and settle
on-network under one set of ceilings. The provider list is a registry of
integrations rather than a shortlist to pick a winner from, and an operator can
integrate one Tenzro has never heard of without a protocol change.

Funding has a **direction**, and the two halves are not alternatives: an inbound
orchestrator turns fiat into stablecoin an agent can spend, while an outbound
issuer lets an agent spend an existing balance at merchants that never handle
stablecoins. A network with only the first has agents that can be paid but
cannot buy. **Custody** is recorded separately from the provider, because it
decides who can lose the money and does not follow from the provider's name — a
custodial orchestrator holds the keys, while a non-custodial issuer underwrites
against collateral in a contract the customer owns and can exit at any time.

Crucially, **funding never widens a delegation scope**. Both the funding
source's cap and the identity's scope ceiling are checked and the narrower one
binds, so an agent that could not spend an amount before it was funded still
cannot afterwards. Without that, the on-ramp would be a hole straight through
every control the identity layer enforces.

The card networks sit at a different layer and are integrated there. Visa's
stablecoin settlement program settles with issuers and acquirers — banks and
fintechs — not with merchants directly, which places it one layer below anything
Tenzro touches. Visa and Mastercard instead expose agent identity and mandate
surfaces, and both authenticate over Web Bot Auth.

### The same settlement, on several chains at once

A settler may want one book or several. A settlement can be recorded on the
Tenzro Ledger alone, or fanned out in parallel across EVM chains, Solana,
Stellar, the XRP Ledger and anywhere else the bridge adapters reach.

What makes that useful rather than decorative is **durability**. A preview or
testnet chain can be reset. Writing a Tenzro reference onto another
chain produces a record that is only interpretable by asking Tenzro what the
reference meant — so when Tenzro's state is gone, the settler holds a hash of
nothing. A self-contained mirror instead embeds the canonical settlement bytes,
and stays readable and verifiable with no Tenzro node in existence. That is the
form that survives a reset or a mainnet cutover, and the protocol reports
whether a given settlement has one rather than leaving a settler to assume it.

Mirrors are independent. No two-phase commit exists across chains that do not
know about each other, so a congested or reorganising chain never rolls back a
settlement that already committed elsewhere; partial success is reported
honestly, and a mirror that did not land never enters the record.

### Which rail a payment settles on

An agentic economy metered per token produces charges spanning six orders of
magnitude, and no single chain is correct across that range. **Supporting x402
is not the same as being able to carry a micropayment**: Base speaks x402
fluently and still cannot carry a one-cent charge without roughly 10% overhead.
A rail chosen on protocol support alone loses money on every metered call.

So every rail Tenzro settles on carries an indicative fee floor, and the router
picks the cheapest one that both carries the payee's declared asset and is worth
using at that size — settlement may cost at most 1% of the payment by default.
Stellar and the XRP Ledger anchor the cheap end, which is what makes per-token
metering a real settlement path rather than an accounting fiction. Ethereum L1
sits at the far end deliberately: it is settlement for size rather than
frequency, and should never win a micropayment race.

The decision has exactly four outcomes, kept distinct because they imply
different remedies: **accumulate** (below the micro-settlement floor — hold it
in a channel), **primary** (the Tenzro Ledger), **secondary** (the cheapest rail
carrying the payee's asset), and **no viable rail** (clears the floor, but
nothing carries that asset at that size). The floor binds before the asset
preference: a dust charge does not become movable because the payee would like
it in USDC.

### Agents that other people's infrastructure can verify

A TDIP DID proves an agent's identity *to Tenzro*, and proves nothing to a
merchant behind a CDN, because nothing outside this network resolves
`did:tenzro:`. The web converged on a different format for that question —
HTTP Message Signatures under the Web Bot Auth profile — and both card networks
build their agent identity on it: Visa's Trusted Agent Protocol and
Mastercard's Agent Pay authenticate over it, and Cloudflare, AWS WAF, Vercel,
Shopify and Akamai verify it at the edge.

Tenzro agents sign every outbound HTTP request with an RFC 9421 HTTP Message
Signature. The key is the agent's P-256 key in its serving machine's TPM, the
one its controller approved by passkey in the agent's on-chain terms, so no
software copy of it exists. The signature covers the request line, the body
digest, the agent's DID and the approval digest of the terms it acts under. A
merchant off the network resolves the key id from chain state, which also says
who the agent's root identity is, which terms are in force and whether the
agent has been revoked or quarantined, and verifies the request without
trusting any directory operator (see [AGENT_TRUST.md](AGENT_TRUST.md#signed-agent-requests)).

### Tenzro is the accounting layer, not only the payment layer

An edge gateway can meter a request and take payment for it. What it cannot do
is answer afterwards, to somebody who trusts neither party, which party consumed
what, under whose authority, and whether the payment that cleared corresponds to
the work that happened. Cloudflare, shipping exactly that over x402, states the
limit plainly: payment proves budget, not trust.

Every interaction on Tenzro produces one record binding the consuming identity,
the resource, the **specific authority** that permitted it — a delegation, an
AP2 mandate, an x402 payment, a credential — and where the charge landed:
settled, folded into a channel, **accrued** below the micro-settlement floor, or
free. That last distinction is one a settlement hash alone cannot make, and
accrual is precisely the state a deferred x402 scheme needs and x402 has nowhere
to record.

A web fetch, an inference, a storage read and a marketplace invocation share one
record and one content address, so an audit is a lookup rather than a
reconciliation across per-surface logs. Verification compares content addresses
rather than signatures, so a counterparty can recompute the digest offline and
reach the same conclusion without trusting the node that served it.

### Provenance is the record, not a log

Identity and wallet together are the provenance trail for every resource and
network interaction: **who or what, when, how, and how much** — for on-demand
access, for rentals, and for subscriptions alike. Every metered interaction
carries that record whether or not it was chargeable, so an unbilled interaction
is still accounted for rather than invisible.

Everything settles on the Tenzro Ledger. Tenzro is its own settlement layer and
treats other chains as **secondary** ones: a settlement may additionally be
mirrored onto an EVM chain, an SVM chain, or across a bridge, and each
mirror is recorded against the primary settlement rather than replacing it.

### Longer-horizon coordination

Multi-step coordination (intent lifecycles, sagas with per-step compensation,
treasury and pricing workflows) runs in harnesses over the public RPC, MCP and
A2A surface. The protocol keeps what those steps settle against: escrow,
settlement plans and their receipts.

---

## 8. Cross-chain interoperability

A coordination layer is only as good as its reach, and a bridge is only as safe as the rules it cannot skip. Tenzro has one bridge path: governed routes in the route framework. A route joins Tenzro to one external chain over one transport.

| Transport | Reach | Primary use |
|---|---|---|
| CCIP-compatible envelope | Ethereum, Base, Arbitrum, Solana | TNZO transfers and attested data messages |
| IBC (classic or v2) | Cosmos SDK chains on CometBFT | ICS-20 token transfers |
| Deposit route | Bitcoin | Inbound deposits to a governed script |
| Tenzro bridge contract | Sui, Aptos, Stellar, TON | TNZO transfers and settlement legs |

Every rule is enforced by the framework rather than by an adapter. Deliveries are decoded strictly: a truncated, non-canonical or over-long payload is refused. The route committee, and on CCIP routes an independent blessing committee, sign a digest that binds this chain's id, the route, a nonce and an expiry, so a signature made for one use verifies for no other and a nonce is accepted once. A route that requires a light-client proof admits nothing without one. A circuit breaker, tripped by validators holding two thirds of stake or by governance, stops a route in both directions. Per-transfer and per-epoch caps bound what any route can move, and the supply invariant holds for every route: the representation outstanding on the external chain never exceeds the TNZO locked on Tenzro for it.

Sending TNZO out requires the holder's own signature; the node locks the amount for the route and builds the message that lets the other chain release the same amount. Coming back, the recipient is credited only within the route's caps and outstanding supply.

Chainlink Data Feeds, Data Streams and Proof of Reserve are read directly for prices and reserve attestations; they are not a bridge.

Intent and solver markets are not part of the protocol. They run in a harness over the public surface: a solver posts a generic bond, payment settles through escrow, and a failed fill goes through the protocol's generic disputes and slashing. ERC-7802 cross-chain token mint and burn extends the model to native cross-chain tokens.

---

## 9. AI infrastructure

Tenzro is built for open-source intelligence at every modality and every size. The model registry catalogs permissively-licensed open-weight models across seven runtimes, each operator picks which to serve, and the inference router matches users and agents to providers by price, latency, reputation, or weighted combination.

### Modalities

- **Language** — Qwen 2 / 3 / 3.5 / 3.6 (dense and MoE), Gemma 3 / 4 (incl. Gemma 4 26B-A4B MoE), Mistral (incl. Mistral Small 3.2), Phi 3 / 4, DeepSeek V3 (native MTP) and V4 Pro / Flash, GLM 5 / 5.1 / 5.2 (5.2 with native MTP), Kimi K2 / K2.5 / K2.6 / K2.7-Code / K3, MiniMax M1 / M3, Granite, Granite-H, gpt-oss, Nemotron Nano. All run through the language runtime with full chat templates, streaming, and Anthropic-style SSE.
- **Vision embedding** — CLIP ViT-B/32 and L/14, SigLIP2 base/large/so400m, DINOv3 vits16/vitb16/vitl16. Used for image search, similarity, and embedding pipelines.
- **Text embedding** — Qwen3-Embedding 0.6B/4B/8B, EmbeddingGemma-300M (Matryoshka), BGE-M3, Snowflake Arctic Embed L v2.0, ModernBERT-embed base/large (8192-context RoPE encoder).
- **Segmentation** — point/box (SAM 2 base/large, EdgeSAM, MobileSAM) and text-promptable open-vocabulary (SAM 3 / 3.1).
- **Detection** — RF-DETR (nano through 2xl, 90-class COCO) and D-FINE (n/s/m/l/x, 80-class).
- **Audio (ASR)** — Moonshine v2, Distil-Whisper, Whisper-large-v3-turbo, NVIDIA Parakeet-TDT-0.6B-v3, Canary-1B-Flash.
- **Time-series forecasting** — TimesFM 2.5.
- **Video embedding** — frame-pooled vision encoder (CLIP / SigLIP2 / DINOv3 / ViT) over uniformly-sampled frames.

Every catalog entry carries a license tier (Permissive / Attribution / CommercialCustom / NonCommercial) enforced at registration time. The model registry refuses to load a non-commercial entry without explicit operator opt-in, and CommercialCustom entries require a per-family opt-in.

### Provider economics

A provider runs the node with `--roles ai`, registers under the model registry, and posts the 1,000 TNZO model-provider bond against their identity. Inference requests route to providers via the strategy the caller selects. Settlement is per-call or per-token through a payment channel (an escrow with payer-signed vouchers); routing standing is read from consensus state: zero without a live serving bond, otherwise a governed bonded standing plus a governed availability standing from the validators' SLA verdicts over the last closed hours. Providers can also rent capacity for fixed terms backed by streaming escrow against their stake — see §15, *Capacity rental and escrow*.

### Heterogeneous hardware

The same provider binary runs on Apple Silicon, NVIDIA Ada / Hopper / Blackwell, AMD Instinct, and CPU-only fallbacks. The runtime layer is ORT-backed for ONNX-shippable models and llama.cpp-backed for GGUF; the dispatch layer hides the difference. Small providers serve niche models; large providers run frontier models; the protocol does not pick winners.

### Node tiers and release variants

One `tenzro-node` source builds for every class of machine. The `inference` cargo feature carries the model engines and is on by default; the light build leaves it out (`--no-default-features`), keeps identity (including a remote-TPM client for a machine with no TPM of its own), payments, agents, RPC, MCP, A2A, storage and chain following, forwards inference calls to providers on the network, and refuses the `ai`, `compute` and `tee` roles at startup. `scripts/build-tier.sh` builds the variants: `edge` (the light build, optionally tuned for one processor and optimized for size), `validator` (the light build under the release profile) and `provider` (the standard build with a GPU backend). At run time `--tier auto|edge|validator|provider` sizes the store, buffers and threads to the machine. Measured on an aarch64 host, the light build is 86.8 MB stripped (62.2 MB size-optimized) against 132.4 MB for the standard build, and a light node held 130 to 210 MiB resident while idle. The full table is in [NODE.md](NODE.md#node-tiers).

### Hybrid jobs: edge orchestration and model ladders

A request rarely needs the largest model for every step. Routing, classification, retrieval, extraction, masking of old tool output, policy and budget checks, and output verification are cheap; generation by a frontier model is not. Tenzro is designed so the cheap steps run near the caller, on an edge device, and the expensive step runs on a GPU provider, all inside one paid request:

- An **agent provider** publishes a harness: the deterministic orchestration of an agent or a swarm (plan, tools, routing, state, budget).
- An **orchestration provider**, typically an edge device, hosts the harness, runs its small local models and fans calls out to other nodes.
- A **model provider** runs the large model when the harness escalates.

Each party is paid from the caller's signed budget for its own part. The design rule is that a caller never pays more through the network than through the best direct path to the same model, so edge orchestration earns from the cost it saves and the work it does, not from a markup.

What exists today: the light build that runs on edge devices; payments that name the call chain behind them (`CallAttribution`: the app, the agent and the tool, each a registered identity, signed by the payer) and pay each named party directly; payment split rules that divide one payment between several payees; agent wallets funded and capped by their owners; and verifiable inference and render receipts (section 12).

### Chat surface

The language runtime is exposed five ways simultaneously:

- **JSON-RPC** `tenzro_chat`
- **OpenAI-compatible** `POST /v1/chat/completions` and `POST /v1/responses`
- **Web** `POST /chat` on the verification API
- **MCP** `chat` tool, **A2A** `inference` skill, **CLI** `tenzro chat`

Agents pick whichever surface fits their framework; the model and provider are the same underneath.

### Mixture-of-Experts serving

MoE architectures activate a small subset of expert weights per token. The total parameter count can sit at 122B / 397B / 685B / 1.6T / 2.8T while the active path is only 10–104B — generation-time compute scales with the active path. Kimi K3 sets the current ceiling at 2.8T total over 896 routed experts, of which 104B is active per token. Tenzro serves MoE in two modes that share the same provider population.

The default mode is **full-replica per provider**: a provider whose hardware fits the entire model holds it and serves single-peer inference exactly like a dense model. This is the smaller-model path (Gemma 4 26B-A4B, Qwen 3.5 35B-A3B, Qwen 3.6 35B-A3B, Kimi K2.5, DeepSeek V3 on H200-class infrastructure).

The second mode is **decentralized expert-shard serving**: providers whose hardware cannot fit the full model declare the subset of experts they hold via `ProviderCapacity.moe_holdings`, and the network's MoE routers aggregate per-token top-k routing decisions into per-holder batches. Each batch carries the tokens whose top-k resolved to the same (expert, holder) tuple, dispatched directly over the holder's iroh QUIC endpoint (the data plane sits on the same content-addressed transport used for model weights and agent memory). The shard view is a derived view over the existing provider registry — the compute providers serving MoE shards are the same network providers that serve dense models, so the existing reputation, staking, billing, and TEE attestation primitives apply unchanged.

MoE pipeline roles are typed: `Replica`, `Router`, `ExpertHolder`, `PrefillDecode`, `Prefill`, `Decode`. A provider can declare more than one role; the router picks the matching role per request. Replication of each expert is governance-tunable — a default policy requires every active expert to be held by at least two distinct providers (so a single holder failure does not pause inference), with up to eight holders allowed for popular experts whose committed TPS exceeds the hot threshold.

Execution is carried by an expert-host runtime embedded in every node: holders load expert FFN weights and gating networks from safetensors payloads, and a distributed layer forward gates locally, dispatches per-holder batches (local execution, the holder's iroh QUIC endpoint on the `tenzro/moe` ALPN, or HTTP), and recombines per-token outputs weighted by the gate probabilities. Holder failures are absorbed inside the forward: each batch walks its planned holder set in warm-first order, and when every known holder for an expert fails, the affected (expert, token) pairs are replanned against a rebuilt shard view that excludes the failed providers — bounded rounds, with results already gathered kept in the combine, each failure recording a reputation penalty against that holder. A forward that still cannot cover every token fails closed by default; `allow_partial` instead renormalizes the gate weights over the experts that responded and reports the unserved pairs. Every holder meters its aggregate expert-forward throughput over a rolling minute and stamps it onto each advertised holding as `committed_tps`, so the planner ranks holders by observed serving capacity. So a holder can advertise more experts than fit in memory, the runtime keeps experts in a byte-bounded memory-tier LRU — the budget auto-sizes to 60% of the host's available memory, or 4 GiB where that reading is unavailable — over a disk tier that spills raw safetensors and decodes them back on demand; readahead promotes the disk-tier experts a forward is about to hit before its batch arrives. A holder's declared residency (`Warm` for memory-resident, `Cold` for disk-tier) is read from this live tier state rather than a static declaration.

The expert-shard view, the per-token-to-per-holder planner, the replication policy, and the execution runtime are surfaced through sixteen RPCs (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`, `tenzro_moeExpertLoad`, `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`, `tenzro_moeExpertStatus`, `tenzro_moeRoute`, `tenzro_moeExecute`, `tenzro_moeForward`, `tenzro_moePrepareExperts`, `tenzro_moePrepareStatus`, `tenzro_moeListReceipts`, `tenzro_moeDisputeReceipt`) and through the Rust and TypeScript SDKs.

### Multi-Token Prediction

Speculative decoding lets a target model generate multiple tokens per inference step using a smaller drafter. **Multi-Token Prediction (MTP)** is the jointly-trained variant — an auxiliary head that shares hidden state with the target and produces tokens consistent with the target's distribution. The accept rate is materially higher than classical two-model speculative decoding because the drafter is not an independent model but the target's own auxiliary head.

Tenzro wires MTP from catalog to runtime. The catalog declares which entries pair with which drafter (`drafter_id`), which flavour of speculation they expect (`mtp_kind: DraftMtp` or `Generic`), and the recommended starting `draft_n` (the `--spec-draft-n-max` parameter). Provider capacity advertises whether the provider has the paired drafter co-loaded (`mtp_enabled: true`). The inference router filters MTP-eligible requests to MTP-capable providers when the request carries a `draft_n` hint and falls back to standard autoregressive providers otherwise. At the runtime the MTP variant of llama.cpp consumes the joint head and accepts the longest matching prefix on each step. Serving a model auto-loads its paired drafter: `tenzro_serveModel` reads the catalog `drafter_id`, loads the drafter from disk or downloads it in the background, and reports the outcome in the serve response — a drafter problem never fails the serve, and the drafter unloads with its target and is restored across restarts.

MTP is implemented for Gemma 4 (E2B / E4B / 12B / 26B-A4B / 31B), Qwen 3.5 (every size 0.8B–397B), Qwen 3.6 27B and 35B-A3B, DeepSeek V3 (native head, ~80% accept rate, ~1.8× decode throughput per upstream), DeepSeek V4 Pro / Flash, and GLM 5.2 (improved MTP layer). For models without a joint head, classical two-model speculative decoding (`MtpKind::Generic`) is wired through the same path.

### Generative image and video

Generative media is served like every other modality: a node loads a media model from the catalog and renders it in process on its native diffusion engine. A render is seeded, so any provider holding the same weights reproduces it up to numeric drift, and its signed receipt commits to the output's SHA-256 and a perceptual fingerprint with the tolerance two renders must agree within. A re-render on another provider that disagrees beyond that tolerance is an inference fault, refunding the caller from the provider's bond.

The kinds served are `text2image`, `image2image`, `text2video`, `image2video`, `text2audio`, 3D, action policies and world models. A render is metered in pixel-steps (`width × height × steps × frames`, with duration, voxel and world-model equivalents) against the node's rate card, the same way tokens are.

The catalog carries permissively-licensed open-weight families: Qwen-Image and its four-step distillation, Qwen-Image-Edit, Z-Image-Turbo, FLUX.2-Klein, and the Wan 2.2 text-to-video, image-to-video, and combined entries. Job queues, worker pools and quotes for media are applications built over the render method.

---

## 10. Applications on the network

The protocol is kept light by design. It does consensus, identity, tokens, staking and roles, settlement, bridges, governance and model serving. Applications such as training and task markets are built on its public interfaces (the public RPC, MCP, A2A, the SDKs, escrow and events) with no privileged access to a node, so anyone can build or run them. Developers and the community can build, fork, swap or run their own training and task tooling without waiting for a protocol change or a governance vote.

A training run, for example, is a task whose rounds are milestones: each round is paid from an escrow carrying the round's `reference`, released by the sponsor or by a threshold of the run's named panel once the round is delivered, and a trained model is served once it is published to the catalog like any other model. A task market works the same way, with one escrow per milestone and stream escrows for rentals.

---

## 11. Confidential execution

Some computations have to remain confidential — model weights from a proprietary provider, training data covered by privacy regulation, key material that has to stay inside an enclave. Tenzro's TEE substrate covers five vendors uniformly.

### Supported TEEs

- **Intel TDX** — `/dev/tdx-guest` ioctl, TDREPORT → Quote pipeline, Intel PCS certificate chain, QE P-256 ECDSA quote signature verification.
- **AMD SEV-SNP** — `/dev/sev-guest` ioctl, AMD KDS VCEK certificate fetching, ARK → ASK → VCEK chain verification.
- **AWS Nitro Enclaves** — `/dev/nsm` device, CBOR attestation documents, AWS Nitro root CA chain, COSE_Sign1 ES384 verification per RFC 8152.
- **NVIDIA GPU Confidential Computing** — NVIDIA NRAS HTTP API attestation with JWT verification and SPDM-based measurements.
- **Intel Tiber Trust Authority** — hosted attestation via the ITA API with PS384/RS256 JWT verification against the pinned JWKS.

All five surface a unified `AttestationResult` so applications do not have to special-case the vendor.

### How TEE composes with the protocol

- **Validator participation** — TEE attestation is a reputation signal for validators; it does not change leader selection.
- **Confidential inference** — model provider runs the inference inside the enclave, returns a TEE-attested result hash, and signs it with a key sealed by the enclave.
- **Attested key release** — a private model's content key is wrapped to an environment's release key only after its attestation passes the model's policy and the chain records the release; no key is kept or derived inside a TEE.
- **ZK-in-TEE** — the enclave generates the witness, runs the prover, and signs the commitment with a PQ-hybrid composite signer (classical + ML-DSA-65). Verifiers can check the ZK proof, the TEE attestation, or both.

---

## 12. Verification

Tenzro provides three independent ways to verify any claim made on the network: cryptographic (Plonky3 STARK), hardware (TEE attestation), or both at once (ZK-in-TEE). Each is anchored on-chain.

### Plonky3 STARKs in two configurations

Two circuits are defined, identity and settlement. Both prove knowledge of a 32-byte witness whose SHA3-256 under a per-circuit domain is a public digest, with Keccak-f evaluated in-circuit and a 32-byte binding absorbed into the transcript. Every statement can be proven in two Plonky3 configurations that share nothing but the statement and the protocol code: KoalaBear with a degree-8 extension, SHA-256 commitments and FRI at rate 1/16; and Goldilocks with a degree-5 extension, BLAKE3 commitments and FRI at rate 1/32. Both use a hiding PCS and reach about 136 bits of proven soundness (Johnson-bound FRI analysis, no proximity conjecture). The node admits a statement for attestation only when it verifies in both. The system is transparent: no trusted setup, no per-circuit CRS, no ceremony. No circuit proves model inference.

A generic dispatcher (`verify_proof_envelope`) matches on `circuit_id` and the proof's system and runs the pinned verifier. The EVM `ZK_VERIFY` precompile is O(1) — validators verify proofs off-chain and write 32-byte SHA-256 commitments into the on-chain `ZkCommitmentRegistry`. The precompile is a HashSet lookup against the registry.

### TEE attestation

Hardware attestation through any of the five supported vendors. Every attestation carries the vendor identifier, the chain of certificates (validated against the vendor root CA), the signed measurement set, and an enclave-bound public key. The `TEE_VERIFY` precompile is a real attestation check, not a stub. Attestations bind to an enclave-held signing key so subsequent signatures the enclave produces inherit the attestation's trust.

### Hybrid ZK-in-TEE

The enclave produces the witness, runs the prover inside the enclave, and signs the commitment with either a classical key (Ed25519 / secp256k1) or a PQ-hybrid composite signer (classical + ML-DSA-65). Cross-binding an externally-verified `AttestationResult` to a `TeeZkProof` lets a verifier rely on a third-party attestation appraisal (e.g. Intel Tiber) without coupling the ZK crate to any specific HTTP TEE client.

### What gets proved

- **Inference results** — no circuit proves model inference; results are checked through signed inference receipts and TEE attestation.
- **Settlements** — settlement amount, payer, payee, and resulting balance commitments are provable against the chain state root.
- **Identity claims** — credential possession, delegation scope membership, and trust-chain root anchoring are provable without revealing the underlying identity material.

---

## 13. Networking and storage

The Tenzro peer-to-peer layer runs on iroh. Every node runs one QUIC endpoint whose key its machine vouches for in a signed endpoint record, so cloud VMs, residential WiFi, mobile devices, and embedded boards reach each other directly or through the relays named in those records. Topic gossip runs on iroh-gossip over each node's iroh endpoint and carries blocks, transactions, checkpoint certificates, validator endpoint announcements, agent messages, and SLA heartbeats; every message is checked before a node passes it on, and consensus itself runs on direct validator channels, not gossip. Peers are found through those signed endpoint records, exchanged only between Tenzro nodes; point-to-point protocols run on their own ALPNs over the same endpoint.

Storage is RocksDB with column families per concern (blocks, state, accounts, transactions, identities, agents, models, providers, tokens, settlements, validator modules, agent memory, audit, bridge nonces, equivocation evidence, and more). Durable writes go through `write_batch_sync` with `fdatasync`. Block writes are atomic. Auto-repair handles WAL corruption on startup.

The DA layer abstracts behind a `DaBackend` trait. Receipts can be inline or off-loaded. The implemented backends are `Inline` (safe pre-mainnet default, optional RocksDB-backed) and `IrohBlobs` over the iroh-blobs content-addressed transport. Iroh also carries the model-weight distribution path (peer-first with HuggingFace Hub fallback), agent-memory archives, and the A2A / MCP transport — all on one shared QUIC endpoint per node, anchored to the node's TDIP key.

Snapshot bootstrap is cryptographically anchored — the joining node specifies a block hash it trusts; the snapshot must hash to that root or the bootstrap aborts.

---

## 14. Agent protocol surfaces

Tenzro exposes its capabilities through three concurrent surfaces, each picked for what it does best.

### JSON-RPC

The RPC surface covers blockchain reads, EVM-compatible methods, accounts, tokens, models and inference (every modality), distributed MoE (`tenzro_moeShardMap`, `tenzro_moePlanDispatch`, `tenzro_moeReplicationPolicy`, `tenzro_moeCatalogShape`), settlement and escrow, agent terms and bonds, identity and DID resolution, network, governance, payments (MPP, x402), staking, settlement mirroring, bridges, events and event proofs, TEE and ZK attestation, VRF proof verification, Permit2, EIP-7702, and supply metrics. Each method carries an access class, and body, concurrency and per-address rate limits cap DoS surface. Hosting, markets, routers and other applications are not part of the node's RPC surface; they run in harness modules and call it.

### MCP (Model Context Protocol)

The node's MCP server exposes its tools to any MCP-compatible client over Streamable HTTP and over the `tenzro/mcp` ALPN on the node's iroh endpoint, where each stream is a full MCP session. It speaks MCP revision 2026-07-28 statelessly, with the revision's per-request metadata on every request. The node runs this one MCP server; tooling for other chains and services is left to harness modules and third-party connectors.

### A2A (Agent-to-Agent)

The A2A host implements A2A 1.0 — `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask` over JSON-RPC 2.0 with the `A2A-Version: 1.0` header, SSE streaming for long tasks, and a signed agent card at `/.well-known/agent-card.json`. The Agent Card publishes skills covering wallet, identity, inference, media generation, distributed MoE, settlement, verification, staking, token, contract, bridge, bridge-fee-in-TNZO, compliance, uRWA, storage, compute, discovery, iroh transport, events, join, and adaptive burn.

Both MCP and A2A can also be carried over iroh's QUIC-native transport via dedicated ALPNs (`tenzro/a2a` and `tenzro/mcp`), so agents that prefer content-addressed peer transport over HTTP can connect peer-to-peer with no router in the middle.

### Agent kit and templates

Agents are built in harnesses: an agent kit holds an agent to
the Terms its root signed, pays through the node's payment surface, and ships
templates (payments, inference, robotics, a dashboard) that create the agent,
its Terms and its wallet under a person's or a machine's identity. The kit
uses only the public surface; no node holds an agent's keys or runs its code.

---

## 15. Token economics

TNZO is the network's gas, settlement, staking, and governance token. The maximum supply is 1,000,000,000 TNZO, denominated in 18 decimals.

### Three demand sources

- **Gas** — every transaction pays gas in TNZO under EIP-1559. The governed share of the base fee is burned (all of it by default); the rest of the block's fees, including the priority part, goes to the treasury less the insurance pool's governed share. No gas is paid to the block proposer.
- **On-chain settlement fee** — every settlement the chain carries out pays `fees.settlement_fee_bps` of the value it pays out (10 basis points at genesis, never below the governed USD minimum); `fees.settlement_fee_burn_bps` of it is burned (half at genesis) and the rest goes to the treasury. A payment to a bonded provider can also carry a governed treasury leg for its class of work (`fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps`, 0 at genesis, at most 5,000 basis points), taken from the provider's credit so the buyer's price does not change.
- **Node revenue split** — a service payment a node collects is divided **exactly once**, by the node's economic mode, and nothing downstream takes a further cut. A **private** node — connected but not advertising itself, reached as its operator's access policy admits — keeps the whole payment: nobody discovered it and no validator was engaged on the caller's behalf. A **public validating** node pays 10% to the treasury. A **public node that does not validate** pays 10% to the treasury and 10% to the RPC provider validating on its behalf, that leg coming out of the operator's share because the node is buying validation it does not perform. The operator majority is enforced at construction rather than by convention, and every rate is one governance-set `EconomicPolicy` block rather than a constant. The treasury account is derived and keyless and spent only by governance; because the payee is configuration rather than code, changing it needs no code change. See [ECONOMICS.md](ECONOMICS.md) for the full model.
- **Bonds** — every participating role bonds TNZO across a ten-rung ladder (validator, RPC operator, rail attestor, TEE provider, edge operator, model provider, compute provider, storage provider, wallet provider, catalog publisher), each amount set by governance, with compute and storage bonds scaling with the capacity pledged. Misbehavior is slashed against the bond.

Every demand source grows with usage, not with holding.

### Rewards follow paid work

Rewards are paid from a finite, genesis-funded pool, never minted, and only for verified work. Provider work is recorded per class when a bonded provider is paid: `InferenceServed`, `TeeSession`, `RpcTraffic`, `ComputeLease` and `StorageServed`; settled usage attributed to registered apps, agents and tools records `AppUsage` for their creators; validators record consensus votes and block proposals. What one settlement may earn is bounded by what it paid outside the trade (the settlement fee plus its treasury leg): the provider weight, the activity weight of the attributed creators and the governed creator royalty (`fees.creator_royalty_fee_bps`, 0 at genesis) together stay at or below 9,000 basis points of that cost. Any group of parties acting together therefore ends each settlement at least a tenth of its outside cost poorer, and parties that share an identity root earn nothing at all from paying each other. Nothing is paid for holding, volume, sign-ups or engagement; there are no airdrops or points.

### Capacity rental and escrow

A consumer can reach provider capacity two ways: **pay-per-use** (metered per call or per token, paid after the unit is served) and **time-based rental** (reserving a provider's capacity for a fixed term — hourly through annual — at an agreed rate). Both settle in TNZO from the same consumer deposit and rest on the same provider stake.

Rental introduces a timing asymmetry pay-per-use does not have: the consumer is paying for future capacity. Paying upfront exposes the renter if the provider vanishes; paying at the end exposes the provider if the renter walks. A rental is therefore a **stream escrow** with a duration and an SLA instead of deliverables: the renter locks the agreed price to the provider's bonded address, and it releases one epoch at a time to the end of the term. Either side may stop it at an epoch boundary; neither is exposed for more than one epoch.

Availability is judged by the validators, not by either party: they probe every bonded provider and freeze a verdict per epoch once two thirds of bonded stake agree. An unavailable verdict slashes the provider's compute bond into the insurance pool, and the renter claims that epoch back from the pool with the verdict as evidence. Consensus weight is not part of this — that comes only from the separate validator bond.

### Network duties

Chain work that anyone may carry out is paid as a network duty: the chain holds the reward, pays it to the first sender whose proof it verifies, and returns any unpaid remainder to the funder at expiry. Settlement reconciliation is one: each epoch the treasury funds a duty for every bridge route with a settlement lock, at the governed `settlement.reconciliation_reward`. Every reward and bond amount here is a governed parameter that changes only through an enacted proposal.

### Adaptive burn dial

A governance-controlled adaptive burn dial lets the protocol adjust the burn fraction in response to circulating supply targets. The dial reads rolling-window supply metrics (epoch deltas, basis-point change vs. target), computes a recommendation under bounded magnitude caps, and can be triggered automatically by the supply-target alarms or manually by a governance proposal. The paymaster burn fraction is locked at 100% so paymaster-sponsored gas does not create a back-door inflation path.

### Bootstrap activity

The network is bootstrapped by its first operators, who run it until it is stable; decentralization then opens at measured milestones, never on a date. Usage that the operators' own projects or related parties bring pays the normal fees and earns no extra rewards: payer and payee on one identity root earn nothing, and any other group is held to the outside-cost bound above. The protocol runs no bootstrap agents of its own and sets no treasury aside for them. Agent templates that exercise the network live in a harness over the public surface; the agents they run are ordinary identities funded by governed treasury grants, act under delegation terms like any other agent, and their activity is counted by the same rules as everyone else's.

### Staking

Every role bonds TNZO. The bond ties the operator to honest behavior — an equivocation slashes the validator's stake by an amount that grows with how much stake equivocated with it (at least 5%), and rampant inference failures slash through the reputation system.

| Role | Bond |
|---|---|
| Validator | 10,000 TNZO |
| RPC operator | 100,000 TNZO |
| TEE provider | 10,000 TNZO |
| Model provider | 1,000 TNZO |
| Compute provider | scales with the accelerators pledged, floor 500 TNZO |
| Storage provider | 100 TNZO per terabyte pledged, floor 100 TNZO |

Two rungs scale with capacity, so the bond tracks the exposure it collateralizes:

- **Compute** — 5,000 TNZO per datacentre card, 2,000 per workstation card, 1,000 per consumer card, 500 per integrated accelerator, summed over everything pledged. A provider offering one datacentre card and one consumer card bonds 6,000 TNZO.
- **Storage** — 100 TNZO per terabyte, so a 50 TB provider bonds 5,000 TNZO.

Pledging no capacity to a scaling rung yields that rung's floor, never zero — bonding is never free. The RPC operator bond is among the largest on the ladder (with the rail attestor's) because a public RPC endpoint brokers tenant traffic and upstream chain access, which is the largest trust surface any role holds; it subsumes the validator bond, since an RPC operator is a validator that additionally serves public RPC.

Below the ladder, a node can join, sync, gossip, relay, and run consensus without bonding anything. Quorum weight is the validator's own bond, so bonding nothing contributes nothing to a quorum; there is no governance vote and no slashing exposure, since there is no bond to slash. Admission stays open without making influence free.

Bonded stake is not tokenized: there is no liquid staking token. The unbonding window and every bond figure are governance-adjustable.

### Governance vote weighting

Stake-weighted with quadratic dampening on the upper end so a single very large staker cannot dominate. Verified credentials give a bonus weight (KYC-Full carries more weight than KYC-Basic on votes that involve treasury disbursements or constitutional changes). Delegate-voting is supported: a staker can delegate their voting weight without delegating their stake.

### Bridge fee sponsorship

Bridges can be expensive for small payments. Tenzro supports bridge-fee sponsorship pools that subsidize cross-chain settlements for end users (and for agents) in exchange for protocol-level commission on the underlying flow. Operators contribute to the pool; routes that are eligible draw from it automatically.

A complete economic specification is in `docs/TOKENOMICS.md`.

---

## 16. Governance

Governance is on-chain through the governance engine. Anyone with the minimum proposal bond can submit a proposal; proposals enter a voting window during which staked TNZO holders cast votes; passing proposals execute through the governance executor.

**Prices are a fixed, governed tariff; governance is the lever.** Day to day, fees and rates do not float with demand. Governance changes them by enacted proposal, each parameter only within the hard bounds compiled into the node and, for a tightening change, after its timelock and grace window. Every governed parameter, its genesis value and its bounds are listed in [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md).

**Phases are governance decisions.** The network opens as a preview, then a testnet, then the stages governance decides on the way to mainnet. Each step, and each lift of a launch limit, starts on measured evidence (an unplanned-halt-free run, executed upgrades and slashes, security review, measured economics) and an enacted proposal, never on a date. During the preview, `validator.admission_approval` is 1: a new validator registers only from an account an enacted `ApproveValidators` proposal named, and the proposal can withdraw an approval not yet used. Validators named at genesis and ones already registered are unaffected, and governance opens admission by setting the parameter to 0.

Proposals fall into three classes:

- **Parameter changes** — staking minimums, settlement fee and treasury legs, validator admission, the `EconomicPolicy` block (settlement split, default settlement asset and micro-settlement floor), burn-channel splits, EIP-1559 parameters, model registry policy.
- **Treasury disbursements** — grants, ecosystem incentives, audits, infrastructure.
- **Code upgrades** — binary upgrades roll across the fleet under operator coordination once the on-chain proposal passes.

The governance executor moves and burns TNZO through the staking and token managers, never directly through privileged keys. It cannot mint TNZO: the supply is fixed at genesis.

Specific parameter dials — adaptive burn fraction, bridge fee schedule, KYC-tier upgrade endorsements — are scoped to a specific proposal class with tighter or looser timelock per the risk profile. Constitutional changes (chain ID, consensus algorithm, genesis-schema shape) require supermajority and a long timelock.

---

## 17. Security model

The threat model assumes:

- A subset of validators (up to but not including the BFT bound) is Byzantine.
- A subset of bridges may be compromised or quorum-busted on the other side.
- TEE attestations may be temporarily forged by hardware exploits; the protocol must remain safe without unique reliance on any one vendor.
- Adversaries have classical and conjectured quantum compute.
- Payment counterparties may be hostile; some are sanctioned; some attempt double-spend or front-run.

Mitigations:

- **BFT consensus.** Safety holds under up to (n−1)/3 Byzantine seats.
- **Equivocation evidence + slashing.** Signing two checkpoints with one index is proven on chain and slashed.
- **Composite signatures.** A checkpoint signature is ML-DSA-65 and P-256 together, held in hardware; forging one needs both broken and the key extracted.
- **TEE-independent operation.** A node can run without any TEE and remain a full participant; TEE attestation is a reputation signal only.
- **Fail-closed inbound bridge verification.** Every adapter verifies inbound outer-envelopes against its configured trust source (Guardian set, validator multisig, threshold validator set, light client).
- **Custody in consensus.** The account keystore and agent Terms are chain state; every validator checks passkey approvals, recovery and agent spending against them. Off-chain spending policy is defense in depth, not the primary control.
- **Approvals bound to one chain.** The digest a passkey or TPM root signs for a custody operation (agent terms, step-ups, identity revocation, DID services, root ballots, cluster membership) carries the chain id, so an approval collected on one Tenzro network never verifies on another.
- **Anchored snapshot bootstrap.** Joining nodes specify a block hash they trust; the protocol refuses to bootstrap from a mismatched snapshot.
- **Default-deny RPC surface.** Every dispatched JSON-RPC method is classified as admin, owner-proved or open, and a method in none is refused before its handler runs. A test reads the dispatcher's own source and fails while any arm is unclassified, so adding a method without deciding its gate makes it unreachable rather than public. This inverts an earlier allowlist whose default-open direction had already shipped thirteen unauthenticated methods. Privileged operations (cross-chain mint/burn, bridge authorization, compliance freeze, delegation-scope tweaks) are for node administrators only, checked against the operator DID and the administrators the access policy names; no policy rule grants them.
- **One access policy per node.** An operator decides who may use each service surface (JSON-RPC, MCP, A2A, the OpenAI-compatible API, files, the web gateway and iroh) and each method class, in one file. Callers sign in with a passkey or a hardware key for a short-lived, DPoP-bound access token signed by the node's hardware-rooted key; no shared secret exists. The policy covers the service surface only: it has no representation for consensus or gossip, so a closed node structurally cannot stop validating.
- **Reserve-bound minting.** Tokenized assets cannot mint past their attested reserve.

External security audits cover crypto, consensus, VM, bridge, and TEE. Cross-validator behavior is monitored via Prometheus / Grafana; equivocation alerts page on-call.

---

## 18. What you can build

The same Tenzro stack underwrites a wide range of applications.

**Agentic finance.** An agent runs on the user's behalf with a scoped delegation. It compares lending rates across Aave-class money markets on Arbitrum, swaps stables through a Solana DEX, settles a margin call on a tokenized treasury on Ethereum, and posts an audit receipt on Tenzro. The user retains the right to revoke at any time and the per-day spend cap holds across every leg of the workflow.

**Tokenized RWA settlement.** An institutional asset manager issues a reserve-backed tokenized money-market fund on Tenzro, settles payment on the EVM surface (Permit2 + EIP-7702) against a delivery leg on another chain through a settlement plan, and emits an on-chain NAV receipt. The public commitment is verifiable.

**Open-source inference at scale.** A provider runs a heterogeneous fleet (a few H200s, a few Apple Silicon nodes, a few Hopper-class consumer GPUs) serving Qwen, Gemma, Mistral, and TimesFM at the same time. Users pay per call, providers settle per-token, a router application in a harness module picks providers from their bonds and SLA standing, and the treasury leg of each settlement funds protocol development.

**Generative media rendering.** A studio's job-queue application, running in a harness module, posts a batch of text-to-video jobs with a per-job TNZO ceiling and no chosen provider. Workers holding Wan 2.2 claim them; because that model's denoising schedule divides at a timestep boundary, two 48 GB accelerators can split a model that needs 80 — one renders while the noise level is high, hands over a single intermediate latent, and the other finishes. Payment divides by the step counts in the signed handoff. The studio verifies each output against the content hash in its receipt before paying, and fetches the bytes peer-to-peer rather than from a vendor endpoint.

**Cross-chain agent commerce.** An agent with a Tenzro identity fulfills inference, bridge, and settlement requests under its consensus Terms, through one identity. Payments arrive in TNZO or stablecoins and settle into the agent's account. The marketplace that lists the agent and the reputation that ranks it are applications in harness modules, built on the public surfaces and the ERC-8004 registrations the network mirrors.

**Gated RPC provider.** An operator runs a public RPC endpoint for a specific class of network resources — regulated cross-chain routes, KYC-tier-gated services, admin-gated mint and burn. They admit tenant developers by DID, broker each tenant's upstream credentials keyed by that DID, and keep per-tenant analytics. Tenants sign in with their own passkey or hardware key on every session; the operator's RPC endpoint forwards as the tenant's bound party. The operator earns from tenant subscription, per-call fees, and commission on the underlying flow.

**Confidential computing services.** A custodian runs a TEE provider that holds tokenized RWA keys behind sealed-key custody. Customers attest the enclave, post requests sealed against the enclave pubkey, and receive signed receipts. The protocol enforces SLA via the bond posted by the provider.

**Agent-to-agent commerce.** Two agents discover each other through the A2A directory; one offers a forecast service, the other consumes it. They negotiate price, settle through MPP, and post a receipt. Neither has a controller in the loop. Both are TDIP-registered so the audit trail is full.

These are not hypotheticals — every primitive named above is present in the current Tenzro Network release. The combination of identity, custody, multi-VM execution, cross-chain reach, AI infrastructure, confidential execution, verification, and protocol-level settlement is what makes the agentic economy buildable on one substrate.

---

## Glossary

- **A2A** — Agent-to-Agent protocol; the Google specification for inter-agent JSON-RPC with optional SSE.
- **AP2** — Agent Payments Protocol; checkout / payment mandate validation for agent-initiated payments.
- **BLS12-381** — Pairing-friendly elliptic curve exposed to EVM contracts through the EIP-2537 precompiles.
- **EIP-1559** — Ethereum fee-market upgrade with base-fee burn.
- **EIP-2537** — BLS12-381 precompiles.
- **EIP-4361** — Sign-In with Ethereum message format; the SIWT canonical form follows the same shape.
- **EIP-6963** — Discovery of the wallets injected into a page.
- **EIP-7702** — Set-code transaction type that lets an EOA delegate to contract code until it sets another delegation.
- **EIP-7951** — The P-256 signature verification precompile at `0x100`.
- **ERC-4337** — Account abstraction via the EntryPoint and UserOperation.
- **ERC-5792** — Wallet call batches (`wallet_sendCalls`) and capability discovery.
- **ERC-7579** — Modular smart-account standard.
- **ERC-7715** — Wallet permission requests (`wallet_requestExecutionPermissions`).
- **ERC-8004** — Trustless agent identity registry.
- **GLEIF** — Global Legal Entity Identifier Foundation; issues LEIs under ISO 17442.
- **HPKE** — Hybrid Public Key Encryption per RFC 9180.
- **IBC-Eureka** — the IBC v2 protocol (classic IBC and v2 are both bridge routes).
- **KERI** — Key Event Receipt Infrastructure; self-certifying identifiers with hash-chained key event logs and pre-rotation.
- **KoalaBear** — The 31-bit prime field `2^31 − 2^24 + 1`, one of the two STARK base fields Tenzro uses (the other is Goldilocks).
- **LEI** — Legal Entity Identifier; 20-character ISO 17442 code anchored to a legal entity in the GLEIF registry.
- **MCP** — Model Context Protocol; a JSON-RPC tool-discovery surface for agent runtimes.
- **ML-DSA-65** — Module-Lattice Digital Signature Algorithm, FIPS 204; the post-quantum signature standard.
- **MoE** — Mixture-of-Experts; a transformer architecture that activates a small subset of expert FFNs per token.
- **MPP** — Machine Payments Protocol; session-based HTTP 402 payment with credential / receipt.
- **MTP** — Multi-Token Prediction; speculative decoding using a jointly-trained head sharing hidden state with the target.
- **Pixel-step** — The work unit for generative media rendering: `width × height × steps × frames`, with `frames = 1` for image jobs.
- **Plonky3** — The STARK toolkit Tenzro's proof systems are built on.
- **SIWT** — Sign-In With Tenzro; an EIP-4361-shaped message that off-chain services use to authenticate Tenzro identities.
- **TDIP** — Tenzro Decentralized Identity Protocol.
- **TEE** — Trusted Execution Environment.
- **TNZO** — The native token of Tenzro Network.
- **Universal Resolver** — DIF's standard HTTP API for resolving DIDs of any method; Tenzro serves `did:tenzro:` and `did:pdis:` through it.
- **vLEI** — Verifiable LEI; a GLEIF-issued ACDC credential cryptographically binding to an institution's LEI.
- **x402** — Stateless HTTP 402 payment protocol.

---

**License: Apache-2.0.**
