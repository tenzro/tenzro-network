# The 2026 Agentic-Finance Landscape

**Last updated:** 2026-05-02

This document describes the agentic-finance ecosystem as it stands at the start
of 2026 — the protocols, settlement primitives, and execution models in active
production across EVM, SVM, and Canton — and explains what Tenzro does in that
context. It is descriptive, not promotional. Every claim is cross-checkable
against code in this repository or against cited external standards and
registries.

---

## 1. The 2026 landscape

Three distinct ecosystems make up the agentic-finance surface at the start of
2026. Each has its own protocols, settlement primitives, and execution model.

### 1.1 EVM / agent-commerce surface

The Ethereum and EVM-compatible chains have, over 2025–2026, picked up a
deliberate stack for agentic commerce:

- **ERC-8004 (Trustless Agents)** — registry triple (Identity / Reputation /
  Validation) reached mainnet on **2026-01-29**. Standardizes how on-chain
  agents register, accumulate peer feedback, and request/submit work
  attestations.
- **AP2 (Agent Payments Protocol)** — Google-led, donated to the FIDO Alliance
  in **April 2026**, with 60+ partners (Adyen, American Express, Mastercard,
  Stripe, OpenAI, Anthropic, etc.). Verifiable Digital Credentials for
  intent / cart / payment mandates.
- **x402 (Coinbase)** — HTTP 402 micropayment protocol. Public traction figures
  in 2026 cite ~$50M cumulative volume / ~$600M annualized run-rate (with
  ~$28k/day from on-chain audited flows).
- **ERC-4337 v0.8 + EIP-7702** — account abstraction, paymasters, batched
  operations as the substrate for agent-controlled smart accounts.
- **TEE-confidential agents** — Phala and Oasis (Sapphire / ROFL) provide
  agent-scoped TEE execution as a **sidecar** to existing chains; NEAR AI
  positions TEE-attested agents as a platform feature.

### 1.2 SVM / Solana agent-trading surface

Solana's agent ecosystem is dominated by a small set of frameworks plus the
native DEX/lending venues:

- **ElizaOS, SendAI Solana Agent Kit, GOAT SDK** — application-layer agent
  frameworks. They reach Solana primitives (Jupiter swaps, Drift/Mango
  derivatives, Metaplex NFTs, Bonfida SNS, SPL tokens) but do **not** define
  consensus, identity, or settlement primitives at the L1 layer.
- **Settlement and identity** are inherited from Solana proper. Agent identity
  is mostly off-chain or framework-specific.

### 1.3 Canton / institutional-RWA surface

Canton is the institutional ledger family used for tokenized real-world
assets and regulated securities settlement:

- **DTCC US Treasury tokenization** (2025) — Canton synchronizers used for
  collateral movement.
- **JPMorgan JPMD deposit token** (announced 2025) on Canton.
- **CIP-56 token standard** — the institutional fungible-token interface for
  Canton.
- **DvP and atomic settlement** between asset and cash legs are first-class
  Canton primitives.
- One project named `AgenticLedger` exists on Canton for autonomous-agent
  use cases, but **production institutional volume from autonomous agents is
  effectively zero** at the start of 2026.

### 1.4 Cross-cutting: multi-VM L1s

A small set of L1s pursue multi-VM execution:

- **Fluent** (mainnet **2026-04-24**) — EVM + SVM + WebAssembly. **No DAML.**
  Targets developer ergonomics, not regulated settlement.
- **Sei v2** — Cosmos SDK with EVM compatibility and an SVM-style parallel
  execution path; pioneer of the "pointer" token model that Tenzro adopts.
- **Aptos / Sui** — Move-VM L1s with high throughput; not multi-VM in the
  EVM/SVM sense.

No L1 in 2026 combines EVM **and** SVM **and** Canton/DAML in a single chain.

---

## 2. What Tenzro does in this context

Five things Tenzro does that no other chain in 2026 does.

### 2.1 Runs EVM, SVM, and Canton/DAML in one chain

Tenzro's `tenzro-vm` crate runs three executors behind one runtime:
`EvmExecutor` (revm), `SvmExecutor` (`solana_rbpf`), and `DamlExecutor`
(Canton 3.x JSON Ledger API v2). Multi-VM routing happens at the
transaction-type layer, not via cross-chain messaging.

Fluent's mainnet is the closest analog and ships EVM + SVM + Wasm — but
without DAML, which is what the institutional RWA surface (DTCC, JPMD,
CIP-56) is actually built on. A developer or agent on Tenzro can reach
DeFi (EVM), high-throughput agent ops (SVM), and regulated tokenized-asset
settlement (Canton) without leaving the chain.

### 2.2 Bridges retail-agent and institutional-RWA rails under one identity

The two agentic-finance surfaces — retail agent commerce (AP2 / x402 /
ERC-8004 / ERC-4337) and institutional RWA settlement (Canton / CIP-56 /
DvP) — currently live on different chains, with no shared identity, no
shared settlement, and no shared agent framework.

Tenzro implements both natively:

- **Retail-agent rails:** AP2 mandate validation (`tenzro_validateMandatePair`),
  x402 with EIP-3009, MPP with Stripe Payment Intents, ERC-8004 system
  precompiles at `0x101a / 0x101b / 0x101c` with byte-identical selectors to
  the Ethereum mirror, ERC-4337 v0.8 EntryPoint with split gas fields, EIP-7702.
- **Institutional rails:** Canton DAML executor, CIP-56 token templates with
  party↔address mapping, DvP-style two-step transfer flow, DTCC/JPMD-style
  fee schedule integration via `bridge::CantonAdapter`.

A single agent identity (a TDIP DID) can act on both surfaces with the same
delegation scope, the same wallet, and the same on-chain settlement.

### 2.3 Runs the full agent-commerce stack natively, not bolted on

The 2026 retail-agent stack was assembled from independent projects across
multiple ecosystems. Tenzro implements each as a first-class primitive:

| Layer | Standard | Tenzro implementation |
|-------|----------|-----------------------|
| Agent identity | ERC-8004 | `tenzro-identity::erc8004` selectors + `did:tenzro:machine:` DIDs |
| Agent payments | AP2 (Google → FIDO) | `tenzro-payments::ap2`, `tenzro_validateMandatePair`, intent/cart/payment VDCs |
| Micropayments | x402 (Coinbase) | `tenzro-payments::x402`, EIP-3009 calldata, CDP facilitator |
| Streaming payments | MPP (Stripe/Tempo) | `tenzro-payments::mpp`, Payment Intents API, HMAC webhook |
| Smart accounts | ERC-4337 v0.8 + EIP-7702 | `tenzro-vm` EntryPoint, paymasters, smart accounts |
| Agent comms | Google A2A | A2A server on port 3002, 31 skills |
| Tool comms | MCP (Anthropic) | `rmcp` Streamable HTTP, 193 tools, plus 6 ecosystem MCP servers |

The agent-commerce stack runs **inside** Tenzro consensus, with TNZO as the
settlement asset, instead of being assembled from off-chain SaaS.

### 2.4 Treats confidential agent compute as a consensus primitive

Phala and Oasis ship TEE-confidential agents as middleware over an existing
non-TEE chain. NEAR AI exposes TEE-attested agents as a platform feature
above the consensus layer.

In Tenzro the TEE primitive is at the consensus layer:

- TEE-attested validators get a **1.5× multiplier** on their reputation-weighted
  leader-selection draw in HotStuff-2 (`tenzro-consensus`).
- The `TEE_VERIFY` precompile verifies real Intel TDX (P-256 ECDSA over
  Quote\[0..632\]), AMD SEV-SNP, AWS Nitro (COSE_Sign1 ES384 per RFC 8152
  §4.4), and NVIDIA GPU CC attestations on-chain, with pinned vendor root
  CAs (`tenzro-tee`).
- ZK proofs are **commitment-attested**: validators verify Plonky3 STARKs
  off-EVM and record SHA-256 commitments in `ZkCommitmentRegistry`. The EVM
  `ZK_VERIFY` precompile becomes an O(1) HashSet lookup
  (`tenzro-vm::precompiles::zk_verify`).

The combination — TEE-weighted consensus + on-chain attestation precompile +
hybrid ZK-in-TEE — is not present in any other 2026 L1.

### 2.5 Settles agentic micropayments in a pointer-model native asset

x402 and most agentic-payment volume in 2026 is denominated in USDC, which
exists on each chain as a deployed ERC-20 (or SPL token). Bridging USDC
between EVM and SVM ecosystems requires real cross-chain transfers and burns
liquidity at the boundary.

TNZO uses a **Sei-V2-style pointer model** at the protocol level:

- One native balance, three VM views: wTNZO ERC-20 at
  `0x7a4bcb13a6b2b384c284b5caa6e5ef3126527f93` on EVM, an SPL adapter on
  SVM, and CIP-56 holdings on Canton.
- All three views read and write the **same** underlying account state in
  `tenzro-token`.
- Cross-VM transfers are atomic and zero-bridge.

For an agent paying micropayments across the multi-VM surface, this means
no liquidity fragmentation, no bridge wait, and no per-chain redeployment.

The asset itself is registered upstream:

- **CAIP-2 `tenzro` namespace** — `ChainAgnostic/namespaces#184` (filed 2026-05-02).
- **SLIP-44 `1414421071` (`0xd44e5a4f`, ASCII T+0x80, N, Z, O)** —
  `satoshilabs/slips#2015` (filed 2026-05-02).
- **`did:tenzro` DID method** — `w3c/did-extensions#705` (filed 2026-05-02).

---

## 3. What Tenzro borrows from the broader stack

A fair chunk of the 2026 stack is interoperable by design. Tenzro adopts
upstream standards rather than reinventing them — and that matters for
ecosystem reach.

- **AP2, x402, ERC-8004, ERC-4337, EIP-7702** are open standards. Tenzro's
  implementation interoperates byte-for-byte with the Ethereum mirror.
- **MCP and A2A** are protocol-level standards from Anthropic and Google.
  Tenzro ships first-class servers but does not own the protocol.
- **Plonky3, Poseidon2, FRI, KoalaBear** are open cryptography, not
  Tenzro-specific.
- **TEE attestation** uses vendor-issued certificates (Intel PCS, AMD KDS,
  AWS Nitro root, NVIDIA NRAS) — Tenzro verifies, does not produce.
- **Pointer-model tokens** are an idea pioneered by Sei v2; Tenzro extends
  the pattern from EVM↔Wasm to EVM↔SVM↔Canton.

What's specific to Tenzro is the **combination**, not any single piece.

---

## 4. What it would take to match this stack from scratch

To match the Tenzro stack from scratch, another chain would need to ship,
in one consensus layer:

1. A working DAML/Canton executor inside the L1 runtime (not via an
   external Canton synchronizer-as-bridge).
2. A working SVM executor alongside it (the pieces exist, but no chain has
   merged them with DAML).
3. TEE attestation precompiles for **all four** vendor stacks (Intel, AMD,
   AWS, NVIDIA), with pinned root-CA chains and signature verification on
   the actual quote bytes.
4. A consensus layer that gives TEE-attested validators measurable weight
   advantage.
5. A native asset registered across CAIP-2, SLIP-44, and W3C DID — on
   ledgers that already host the asset.
6. AP2 / x402 / ERC-8004 / ERC-4337 / MCP / A2A all wired to that native
   asset and to a TDIP-shaped agent identity.

That is the surface area of the 21-crate workspace and the live testnet
at `rpc.tenzro.network` / `mcp.tenzro.network` / `a2a.tenzro.network`.

---

## 5. What this means for builders, providers, and partners

- **EVM-native dApps and DeFi protocols** — Tenzro is a deployment target
  with first-class EVM, plus SVM and Canton ports of the same liquidity
  via the pointer model.
- **Solana-native agent frameworks (ElizaOS, SendAI, GOAT)** — Tenzro is
  reachable through `tenzro-solana-mcp`, the SVM executor, and the SPL
  adapter; agent identity persists across the EVM ↔ SVM boundary.
- **Canton institutional partners (DTCC, banks, CIP-56 issuers)** — Tenzro
  validators run a Canton participant natively; CIP-56 templates and DvP
  flows are first-class.
- **AI inference and TEE providers** — Tenzro is the only chain where
  TEE-attested participation is rewarded at the consensus layer, and where
  inference settlement runs on the same asset that pays gas.
- **Wallet vendors (MetaMask, Phantom, Wallet Standard)** — TNZO is
  reachable via EIP-6963 (`network.tenzro.wallet`), CAIP-25 provider
  authorization, and the Wallet Standard exposed by `sdk/tenzro-inject`.

---

## 6. References (live and verifiable)

- `crates/tenzro-vm/src/precompiles/erc8004.rs` — ERC-8004 system precompiles
- `crates/tenzro-payments/src/ap2/` — AP2 mandate validation
- `crates/tenzro-payments/src/x402/` — x402 facilitator
- `crates/tenzro-tee/src/attestation.rs` — TDX/SEV-SNP/Nitro/NVIDIA verification
- `crates/tenzro-consensus/src/leader.rs` — TEE-weighted leader selection
- `crates/tenzro-vm/src/precompiles/zk_verify.rs` — ZK commitment lookup
- `crates/tenzro-token/src/pointer.rs` — TNZO pointer model
- `docs/caip2-namespace/tenzro/` — CAIP-2 / 10 / 19 / 25 specs
- `docs/did-method-tenzro.md` — `did:tenzro` method specification

---

## Maintenance

This document is point-in-time as of 2026-05-02. Review and refresh
quarterly, or whenever:

- A new multi-VM L1 ships with DAML support (would invalidate §2.1).
- Phala / Oasis / NEAR AI moves TEE attestation into L1 consensus
  (would weaken §2.4).
- AP2, x402, or ERC-8004 are adopted natively by another chain at the
  consensus layer (would weaken §2.3).

Updates land in this file first; the SPECIFICATION, FOUNDATION, and README
sections that summarize the 2026 context cite this file as the canonical
reference.
