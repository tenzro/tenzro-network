# Tenzro Foundation

## Charter for the Stewardship of Tenzro Network, Tenzro Ledger, and the TNZO Economy

**Version 1.0 — Draft, May 2026**

> **Pre-formation status.** The Tenzro Foundation has not yet been constituted. This document is a forward-looking charter that describes how the Foundation will operate once formed. Until the Foundation is established, stewardship of the protocol, ledger, and TNZO economy is provided collectively by **Tenzro Labs** (the founding development team) and **community contributors** working in the open against this charter. The Foundation will be constituted after testnet maturity and before mainnet launch — see [§3 Pre-Formation Stewardship and Foundation Formation](#3-pre-formation-stewardship-and-foundation-formation).

> **Testnet phase.** All economic parameters in this document — TNZO supply, fees, commission splits, staking minimums, reward multipliers, slashing, unbonding, inflation, burn rates — are configured for the Tenzro testnet phase. They are subject to revision before mainnet launch and will be finalized through on-chain governance.

---

## Table of Contents

1. [Purpose and Mission](#1-purpose-and-mission)
2. [Scope of Stewardship](#2-scope-of-stewardship)
3. [Pre-Formation Stewardship and Foundation Formation](#3-pre-formation-stewardship-and-foundation-formation)
4. [Foundation Structure (Post-Formation)](#4-foundation-structure-post-formation)
5. [TNZO Token Economy](#5-tnzo-token-economy)
6. [Treasury Management](#6-treasury-management)
7. [Governance Framework](#7-governance-framework)
8. [Staking and Validator Operations](#8-staking-and-validator-operations)
9. [Fee Structure and Revenue Flows](#9-fee-structure-and-revenue-flows)
10. [Liquid Staking (stTNZO)](#10-liquid-staking-sttnzo)
11. [Network Security and Slashing](#11-network-security-and-slashing)
12. [Identity and Access](#12-identity-and-access)
13. [Cross-Chain Bridge Oversight](#13-cross-chain-bridge-oversight)
14. [Infrastructure Operations](#14-infrastructure-operations)
15. [Progressive Decentralization](#15-progressive-decentralization)
16. [Code of Conduct](#16-code-of-conduct)
17. [Conflicts of Interest](#17-conflicts-of-interest)
18. [Sunset and Dissolution](#18-sunset-and-dissolution)
19. [Amendments](#19-amendments)

---

## 1. Purpose and Mission

The Tenzro Foundation will exist to steward the long-term health, security, and decentralization of the Tenzro Network, the Tenzro Ledger, and the TNZO token economy. The Foundation is not — and will never be — an owner of the network. It is a temporary custodian of integrity during the transition from a founding team to fully decentralized, community-governed protocol operation. The Foundation's most important success metric is the rate at which it transfers authority away from itself.

### 1.1 Mission Statement

To steward, but not own, a decentralized protocol for the AI age, where humans and autonomous agents can access intelligence (AI models) and security (TEE enclaves) through a permissionless, verifiable, and economically self-sustaining network — and to dissolve into the network once it no longer needs a custodian.

### 1.2 Core Principles

1. **Decentralization is the goal, not a feature.** Every Foundation decision should move authority from the Foundation toward on-chain governance. The Foundation measures itself by what it gives away.
2. **Credible neutrality.** The Foundation does not pick winners among ecosystem participants, validators, providers, or applications. It maintains and improves the protocol; the market and governance decide everything else.
3. **Open participation.** Anyone can run a node, become a provider, contribute code, or participate in governance. No permissioned access, no special-treatment lanes.
4. **Economic sustainability.** The network must generate sufficient fee revenue to sustain itself without perpetual token issuance or external funding from the Foundation.
5. **Hardware-rooted trust.** TEE-attested participants receive measurable economic advantages, making hardware security the rational default — but never the gatekeeper for participation.
6. **Transparency.** Treasury operations, governance decisions, protocol changes, and the Foundation's own activities are visible on-chain or in publicly published reports.
7. **Time-bounded authority.** Every Foundation power has a published path to revocation. The Foundation Council veto sunsets. Foundation-operated infrastructure transitions to the community. The Foundation itself plans for its own dissolution.

### 1.3 What Tenzro Does in the 2026 Ecosystem

The Foundation's stewardship is grounded in a specific architectural stance. By the start of 2026, agentic finance runs across three separate ecosystems — EVM-side agent commerce (ERC-8004 mainnet 2026-01-29, AP2 donated to FIDO in April 2026, x402 at ~$600M annualized), SVM-side agent trading (ElizaOS, SendAI, GOAT), and Canton-side institutional RWA (tokenized treasuries, bank deposit tokens, CIP-56 settlement) — each with its own protocols, settlement primitives, and execution model. No protocol in 2026 combines EVM + SVM + Canton/DAML in one chain.

Tenzro does. Five things follow:

1. **One chain spans EVM, SVM, and Canton/DAML.** `tenzro-vm` runs three executors behind one runtime, so DeFi, agent trading, and regulated tokenized-asset settlement happen on one ledger.
2. **One identity spans retail-agent and institutional-RWA rails.** A single TDIP DID acts on AP2/x402/ERC-8004/ERC-4337 (retail-agent) and on Canton/CIP-56/DvP (institutional) with the same delegation scope, wallet, and on-chain settlement.
3. **The agent-commerce stack is native.** AP2, x402, MPP, ERC-8004, ERC-4337 v0.8, A2A, and MCP run inside Tenzro consensus and settle in TNZO.
4. **Confidential agent compute is a consensus primitive.** TEE-attested validators get a 1.5× multiplier on their reputation-weighted leader-selection draw in HotStuff-2; on-chain `TEE_VERIFY` covers Intel TDX, AMD SEV-SNP, AWS Nitro, and NVIDIA GPU CC.
5. **The native asset uses a pointer model.** TNZO has one balance and three VM views — no bridge risk, no liquidity fragmentation. Registered upstream via CAIP-2, SLIP-44 (`1414421071` / `0xd44e5a4f`), and W3C DID (`did:tenzro`).

The Foundation's role is to steward this stack into community ownership without trading away the architectural decisions that make it cohere.

---

## 2. Scope of Stewardship

The Foundation, once constituted, will be responsible for three distinct but interconnected systems. **Until the Foundation is formed, these responsibilities are carried by Tenzro Labs and community contributors as described in §3.**

### 2.1 Tenzro Network (Protocol Layer)

The decentralized protocol enabling AI inference marketplace, TEE services, and agent autonomy:

- Protocol specification and reference implementation (26 Rust crates)
- Client applications (desktop app, CLI, SDKs)
- Provider onboarding and marketplace health
- Payment protocol integrations (MPP, x402, AP2, Tempo)
- Agent framework and A2A/MCP protocol standards
- Multi-party workflow engine on Canton (privileged-VM selectors, hash-chained receipts, kill switch, fee routing, privacy domains)

### 2.2 Tenzro Ledger

The purpose-built network providing settlement infrastructure:

- Consensus protocol (HotStuff-2 BFT)
- Multi-VM execution environment (EVM, SVM, DAML/Canton)
- On-chain identity system (TDIP)
- Cryptographic infrastructure (Ed25519, Secp256k1, BLS12-381, Plonky3 STARKs over KoalaBear)
- Storage and state management (RocksDB, Merkle Patricia Trie)
- P2P networking (libp2p gossipsub, Kademlia)

### 2.3 TNZO Economy

The token economy that aligns incentives across all participants:

- Token supply and distribution schedule
- Treasury management and grant allocation
- Staking parameters and reward distribution
- Fee structure and burn mechanics
- Liquid staking protocol (stTNZO)
- Cross-chain bridge security

---

## 3. Pre-Formation Stewardship and Foundation Formation

### 3.1 Why Pre-Formation

The Tenzro Foundation will not be constituted until the network has demonstrated technical viability on testnet and is ready to transition toward mainnet. Forming a foundation prematurely creates governance overhead before the protocol is mature enough to govern; forming it too late leaves the protocol without a credible neutral steward when external commitments (audits, listings, bridge integrations, regulator engagement) start to require one. The Foundation's planned formation window is **between testnet maturity and mainnet launch**.

### 3.2 Current Stewards (Pre-Formation)

Until the Foundation is constituted, stewardship is provided by:

- **Tenzro Labs** — the founding development team that built the reference implementation, operates the testnet, and is the primary contributor to the protocol codebase.
- **Community contributors** — independent developers, validators, providers, researchers, and users who contribute code, documentation, infrastructure, and governance input under the same open-source license (Apache-2.0) as Tenzro Labs.

Pre-formation stewardship operates against this charter as a guiding document, but legal authority over Tenzro Labs' work product, trademarks, and operational infrastructure rests with Tenzro Labs until those rights are transferred to the Foundation upon formation.

### 3.3 Pre-Formation Decision-Making

During pre-formation, decisions follow this hierarchy:

1. **Reversible technical changes** — code, configuration, documentation: any contributor can propose; review by Tenzro Labs maintainers per the contribution policy in `CONTRIBUTING.md`.
2. **Network parameter changes on testnet** — proposed publicly with rationale; ratified by Tenzro Labs after a comment period of at least 7 days.
3. **Irreversible or economically significant decisions** — token distribution mechanics, mainnet genesis, validator set, treasury allocation: deferred to the Foundation Council post-formation, except where mainnet-blocking.

Tenzro Labs commits to operating transparently during pre-formation: publishing roadmap updates, maintaining open issue trackers, holding public design discussions, and publishing a quarterly stewardship report covering the same items the Foundation will report on once formed.

### 3.4 Formation Triggers

The Foundation will be constituted when **all** of the following conditions are met:

- Testnet has operated continuously for at least 6 months with no critical security incidents.
- External security audits of consensus, cryptography, VM, and bridge subsystems are complete with all critical and high findings resolved.
- A jurisdiction has been selected for the Foundation legal entity.
- Founding Foundation Council members have been identified, drawing from Tenzro Labs leadership, independent industry contributors, and at least one externally elected community representative.
- A draft transition document has been published describing the transfer of trademarks, code copyrights (where assigned), domain names, infrastructure operating responsibility, and treasury allocation from Tenzro Labs to the Foundation.

The transition document will be published for public comment for at least 30 days before formation completes.

### 3.5 At Formation

Upon formation, the Foundation:

1. Assumes ownership of the `tenzro` GitHub organization, `tenzro.xyz` and `tenzro.com` domains, and the Tenzro trademark.
2. Receives the Foundation treasury allocation per §5 / §6 from the genesis distribution.
3. Appoints initial Council, Technical Committee, and Treasury Committee members per §4.
4. Publishes its founding documents (articles of incorporation, bylaws, conflicts policy) on-chain or via permanent storage with on-chain hash anchoring.
5. Begins operating against this charter as the authoritative version, superseding pre-formation arrangements.

Tenzro Labs continues to exist as a contributing organization but does not retain special authority over the protocol once the Foundation is formed.

---

## 4. Foundation Structure (Post-Formation)

This section describes the structure the Foundation will take once constituted. It is informational during pre-formation.

### 4.1 Governing Bodies

#### Foundation Council

The Foundation Council will hold ultimate authority during the pre-decentralization phase. Responsibilities:

- Approve treasury withdrawals exceeding 1,000,000 TNZO
- Ratify protocol upgrades before on-chain governance is fully operational
- Appoint and remove multisig signers
- Set initial network parameters
- Manage Foundation legal entity and compliance

The Council will have between 5 and 9 members, with terms staggered to ensure continuity. At least one Council seat will be filled by community election from the formation date onward.

#### Technical Committee

Responsible for protocol development and security:

- Review and merge protocol changes
- Coordinate security audits
- Maintain the Plonky3 STARK proof system (KoalaBear field, FRI parameters, AIR constraint sets) — no trusted setup required, but parameter changes are governance-gated
- Maintain the reference node implementation
- Oversee testnet and mainnet deployments

#### Treasury Committee

Responsible for financial operations:

- Execute multisig treasury withdrawals
- Review and recommend grant proposals
- Publish quarterly treasury reports
- Manage Foundation operational budget
- Oversee token distribution schedule compliance

### 4.2 Multisig Operations

Treasury withdrawals require M-of-N multisig approval:

| Operation | Threshold | Signers |
|-----------|-----------|---------|
| Operational expenses (< 100,000 TNZO) | 2-of-5 | Treasury Committee |
| Grant disbursement (< 1,000,000 TNZO) | 3-of-5 | Treasury Committee |
| Large allocation (>= 1,000,000 TNZO) | 4-of-7 | Foundation Council + Treasury Committee |
| Emergency security response | 2-of-5 | Technical Committee |

Rules enforced by the on-chain `NetworkTreasury` contract:

- Each signer can approve a withdrawal exactly once
- Threshold must be less than or equal to the number of authorized signers
- Withdrawals execute atomically upon reaching threshold
- Pending approvals are cleared after execution
- The treasury enforces the invariant: `collected = balance + distributed`

---

## 5. TNZO Token Economy

> All parameters in this section are testnet-phase configurations; final mainnet values will be set through the on-chain governance process described in §7.

### 5.1 Token Specification

| Parameter | Value |
|-----------|-------|
| Token name | Tenzro Network Token |
| Symbol | TNZO |
| Decimals | 18 |
| Maximum supply | 1,000,000,000 TNZO |
| Smallest unit | 10^-18 TNZO |
| Supply model | Fixed cap; no protocol mint authority beyond the genesis distribution |

### 5.2 Token Utility

TNZO serves four functions within the network:

1. **Transaction fees (gas).** All on-chain transactions on the Tenzro Ledger require TNZO for gas, following an EIP-1559 dynamic fee market with base fee adjustment (±12.5% per block), fee burning, and priority fee tipping.
2. **Settlement currency.** AI inference payments, TEE service fees, and escrow settlements are denominated in TNZO. Micropayment channels enable per-token billing for streaming inference.
3. **Staking and validation.** Validators and providers stake TNZO to participate in consensus and earn rewards. TEE-attested validators receive a 1.5× multiplier on their reputation-weighted leader-selection draw, creating strong economic incentives for hardware-secured participation.
4. **Governance.** TNZO holders vote on protocol proposals, treasury grants, parameter changes, and protocol upgrades. Voting power is stake-weighted with delegation support.

### 5.3 Initial Token Distribution

There is no team allocation and no investor allocation. Tenzro Network is community-owned from day one. The genesis distribution funds the participants that produce value on the network and the long-term incentive pools that pay future participants for future contributions.

| Allocation | Percentage | Amount | Purpose |
|------------|-----------|--------|---------|
| Community | 35% | 350,000,000 TNZO | Airdrops, incentive programs, ecosystem growth |
| Treasury | 25% | 250,000,000 TNZO | Network treasury and grants |
| Ecosystem and contributor incentives | 20% | 200,000,000 TNZO | Reward pool for work-gated coupons, contributor and developer grants, operator sponsorship |
| Provider incentives | 15% | 150,000,000 TNZO | TEE, compute, and model provider rewards |
| Liquidity | 5% | 50,000,000 TNZO | DEX and CEX liquidity provisioning |

There are no privileged token-holder classes and no lock-ups for special parties, because there are no special parties. Every TNZO holder is holding because they earned it from the network or bought it from another participant who did.

### 5.4 No Reserved or Vesting Allocations

Because there is no team allocation and no investor allocation:

- There is no investor unlock cliff and no quarterly vesting events that release a wave of supply onto the market.
- There is no team unlock schedule. Contributors who build the protocol receive grants the same way ecosystem builders do — through governance-approved disbursements from the public treasury, on terms the community can see.
- There is no early-backer carry.

The protocol operates a vesting primitive, but it applies only to earned distributions, not to reserved allocations: reward claims vest over 12 months, foundation grants vest over 6 months, and long-term contributor grants use a 12-month cliff followed by 36-month linear release. Vesting attaches to what participants earn, not to a pre-allocated founder or investor tranche.

### 5.5 Supply Dynamics

Supply is fixed at the genesis cap. There is no protocol-level mint authority beyond the genesis distribution:

- Rewards are paid from the ecosystem and contributor incentive pool seeded at genesis, not minted. Reward minting is work-gated (see §8.3): per-epoch minting rights are issued pro-rata against verified work, and unmatched or unclaimed rights are never minted.
- Fee burning (30% of all network commission fees, plus the EIP-1559 base fee) creates deflationary pressure.
- Because there is no emission schedule, net supply trends deflationary as usage grows: burn tracks real activity while the reward pool is a fixed genesis allocation that draws down only against verified work.

The Foundation monitors the effective burn rate and the draw-down of the incentive pool and may propose parameter adjustments through governance if the supply trajectory warrants.

---

## 6. Treasury Management

### 6.1 Revenue Sources

The Network Treasury accumulates funds from three sources:

1. **Network commission fees.** 40% of the 0.5% commission collected on AI inference and TEE service payments flows to the treasury.
2. **Initial allocation.** 250,000,000 TNZO from the genesis distribution.
3. **Protocol revenue.** Any additional revenue from Foundation-operated services (testnet faucets, bridge relayers, bootstrap nodes) during the pre-decentralization phase.

### 6.2 Treasury Composition

The treasury supports multi-asset balances:

| Asset | Symbol | Type |
|-------|--------|------|
| Tenzro | TNZO | Native token |
| USD Coin | USDC | Stablecoin |
| Tether | USDT | Stablecoin |
| Ether | ETH | Cryptocurrency |
| Solana | SOL | Cryptocurrency |
| Bitcoin | BTC | Cryptocurrency |

Non-TNZO assets may accumulate through bridge operations, cross-chain settlements, or strategic reserves.

### 6.3 Grant Program

The Foundation operates a grant program funded from the treasury allocation. Grants support protocol development, ecosystem tooling, security audits, and community initiatives.

**Grant parameters:**

| Parameter | Value |
|-----------|-------|
| Maximum single grant | 1,000,000 TNZO |
| Minimum proposal stake | 10,000 TNZO |
| Grant approval quorum | 50% of votes cast |

**Grant process:**

1. Applicant submits a `TreasuryGrant` proposal on-chain with a stake of at least 10,000 TNZO.
2. The proposal enters a 7-day voting period.
3. TNZO holders vote For, Against, or Abstain with stake-weighted voting power.
4. If the proposal meets quorum (20% participation) and achieves majority approval (>50%), it passes.
5. The Treasury Committee executes the disbursement via multisig.
6. Milestone-based grants release funds incrementally upon deliverable verification.

### 6.4 Treasury Reporting

The Foundation publishes quarterly treasury reports including:

- Opening and closing balances (all assets)
- Fee revenue collected (with breakdown by source)
- Grants disbursed (with recipient and purpose)
- Operational expenses
- Tokens burned
- Supply audit confirmation (`collected = balance + distributed`)

During pre-formation, Tenzro Labs publishes equivalent stewardship reports covering the same line items.

### 6.5 Reserve Policy

The Foundation maintains a minimum treasury reserve:

- Operating reserve: 12 months of projected operational expenses in TNZO and stablecoins
- Security reserve: sufficient TNZO to respond to emergency slashing events or bridge exploits
- The Foundation does not engage in speculative trading of treasury assets

---

## 7. Governance Framework

### 7.1 On-Chain Governance

All governance actions are executed through on-chain proposals voted on by TNZO holders. The `GovernanceEngine` enforces proposal lifecycle, quorum rules, and execution constraints.

### 7.2 Proposal Types

| Type | Description | Example |
|------|-------------|---------|
| ParameterChange | Modify network parameters | Adjust fee rate, block size, staking minimum |
| TreasuryGrant | Allocate treasury funds to a recipient | Fund a development grant or security audit |
| ProtocolUpgrade | Upgrade the network protocol | Deploy new consensus logic, VM changes |
| ValidatorChange | Add or remove validators | Onboard new validator set members |
| Custom | Arbitrary governance action | Ratify a policy, approve a partnership |

### 7.3 Proposal Lifecycle

```
Submitted → Active (voting open) → Passed / Failed → Executed
```

1. **Submission.** A proposer stakes a minimum of 10,000 TNZO and submits the proposal with title, description, type, and execution data.
2. **Voting period.** Default 7 days. TNZO holders vote with stake-weighted power.
3. **Quorum check.** The proposal passes only if all conditions are met:
   - Total votes (for + against) ≥ 20% of total staked supply
   - Votes for > votes against
   - Approval rate ≥ 50% of votes cast
   - Absolute minimum of 1,000 TNZO in total voting power
4. **Execution.** Passed proposals are executed on-chain. Parameter changes take effect at the next epoch boundary. Double-execution is prevented by the protocol.

### 7.4 Voting Mechanics

**Stake-weighted voting.** Each TNZO staked grants one unit of voting power. Voting power is verified against the `StakingManager` — a voter cannot claim more power than their actual staked balance.

**Delegation.** Token holders can delegate their voting power to another address without transferring tokens. Effective voting power = base staked amount + delegated power from others. Delegation is revocable at any time.

**Vote types:**

| Vote | Effect |
|------|--------|
| For | Counts toward approval |
| Against | Counts against approval |
| Abstain | Counts toward quorum but not approval ratio |

### 7.5 Foundation Veto (Pre-Decentralization)

During the pre-decentralization phase, the Foundation Council retains a time-limited veto on governance proposals that would:

- Compromise network security (e.g., removing slashing for equivocation)
- Violate legal or regulatory requirements
- Modify the Foundation's own governance parameters before the scheduled handoff

The veto power is explicitly revoked as part of the progressive decentralization plan (see §15). The Foundation commits to publishing a rationale for every veto exercised. A veto without published rationale within 7 days is considered withdrawn.

---

## 8. Staking and Validator Operations

> All staking parameters are testnet-phase values, subject to revision through governance before mainnet.

### 8.1 Staking Parameters

| Parameter | Value |
|-----------|-------|
| Validator minimum stake | 10,000 TNZO |
| TEE provider minimum stake | 1,000 TNZO |
| Model provider minimum stake | 500 TNZO |
| Storage provider minimum stake | 500 TNZO |
| Unbonding period | 7 days |
| Reward model | Work-gated coupons on a declining annual schedule |
| Epoch duration | 14,400 blocks (~1 day at 6-second block target) |

### 8.2 Provider Types and Reward Multipliers

Different provider roles receive different reward multipliers reflecting their contribution to the network:

| Provider Type | Multiplier | Rationale |
|---------------|-----------|-----------|
| Validator | 1.0× | Baseline consensus participation |
| TEE Provider | 1.2× | Hardware-secured enclaves add trust guarantees |
| Model Provider | 1.1× | AI inference capacity increases network utility |
| Storage Provider | 1.0× | Data availability and state persistence |

TEE-attested validators additionally receive a 1.5× multiplier on their reputation-weighted leader-selection draw in HotStuff-2, creating a compounding incentive for hardware-secured participation. The multiplicative form preserves the property that observed behaviour fully overcomes attestation — a TEE-attested but flaky validator is dwarfed by a non-TEE validator with a clean recent track record.

### 8.3 Reward Calculation

Rewards are **work-gated**. Each epoch's minting rights are earned by verified work done in that epoch — not by holding stake — and are issued as minting-right coupons across three role buckets (Validator, Provider, Ecosystem):

```
year          = year_for(epoch)
epoch_rights  = declining_annual_schedule(year) / 365
(val_bps, prov_bps, eco_bps) = role_split_for(year)   // shifts infrastructure → apps over years

For each role bucket:
  bucket_rights = epoch_rights × bucket_bps / 10,000
  For each address with verified work in the bucket:
    work_share = address_work_weight / bucket_total_work_weight
    coupon     = bucket_rights × work_share            // an unclaimed minting right
```

Work weight is measured by the protocol, never self-reported: validators earn on finalized-block and quorum-certificate participation, providers on metered proof-of-service (uptime- and reputation-scaled), and the **Ecosystem bucket on contributions accepted through foundation/governance review** — this is the rail by which development, applications, and tooling earn TNZO on the same work-gated basis as validation and service. An accepted proposal records ecosystem work weight for the contributor's address, which then earns coupons in that epoch's ecosystem bucket.

**Distribution rules:**

- Epochs are metered sequentially (epoch N closed before N+1)
- Rights left unmatched in a bucket are permanently unminted (no leftover leaks into supply)
- Coupons unclaimed within the claim window expire unminted
- Claiming mints the liquid fraction immediately and opens a 12-month reward-vesting schedule for the remainder; a sponsored operator's claim converts the full amount to owned stake

### 8.4 Validator Responsibilities

Validators who stake TNZO and participate in consensus are expected to:

- Maintain ≥ 99% uptime (reward is proportional to uptime)
- Run the reference node implementation at the current protocol version
- Process transactions honestly and participate in HotStuff-2 voting rounds
- Respond to view change requests within protocol timeouts
- Submit TEE attestations (if TEE-equipped) for enhanced consensus weight

---

## 9. Fee Structure and Revenue Flows

### 9.1 Two-Tier Fee System

The Tenzro economy operates two distinct fee mechanisms:

#### Tier 1: Ledger Transaction Fees (Gas)

All on-chain transactions pay gas fees in TNZO. The fee market follows EIP-1559:

| Parameter | Value |
|-----------|-------|
| Target gas per block | 15,000,000 |
| Maximum gas per block | 30,000,000 |
| Minimum base fee | 0.1 Gwei |
| Maximum base fee | 1,000 Gwei |
| Base fee adjustment | ±12.5% per block |

Gas fees flow directly to the block-producing validator. The base fee portion is burned; the priority fee (tip) is retained by the validator.

#### Tier 2: Network Commission Fees

The Tenzro Network collects a 0.5% commission on payments between users and providers for AI inference and TEE services. This fee does not apply to direct peer-to-peer transfers.

| Parameter | Value |
|-----------|-------|
| Commission rate | 0.5% (50 basis points) |
| Minimum settlement | 1,000 smallest units |
| Maximum batch size | 100 settlements |

### 9.2 Commission Fee Distribution

| Recipient | Share | Purpose |
|-----------|-------|---------|
| Treasury | 40% | Protocol development, grants, operations |
| Burn | 30% | Deflationary supply pressure |
| Stakers | 30% | Additional staking rewards |

The fee split must always sum to 100%. Changes require a governance `ParameterChange` proposal.

### 9.3 Revenue Flow

```
User pays Provider for inference/TEE service
         |
         v
    Full amount debited from user
         |
    +----+----+
    |         |
    v         v
 0.5% fee    99.5% to provider
    |
    +--------+--------+
    |        |        |
    v        v        v
  40%      30%      30%
Treasury   Burn    Stakers
```

---

## 10. Liquid Staking (stTNZO)

### 10.1 Overview

The liquid staking protocol allows TNZO holders to stake while retaining liquidity through the stTNZO derivative token. stTNZO represents a claim on staked TNZO plus accumulated rewards.

### 10.2 Parameters

| Parameter | Value |
|-----------|-------|
| Token symbol | stTNZO |
| Decimals | 18 |
| Protocol fee | 10% of rewards (1,000 basis points) |
| Minimum deposit | 0.1 TNZO |
| Maximum total deposits | Unlimited (configurable) |
| Unbonding period | 7 days |
| Maximum validators | 50 |
| Initial exchange rate | 1:1 (stTNZO:TNZO) |

### 10.3 Exchange Rate Mechanics

```
exchange_rate = total_underlying_wei / total_sttnzo_supply
```

As staking rewards accrue, the underlying TNZO increases while the stTNZO supply remains constant, causing the exchange rate to rise.

### 10.4 Operations

- **Deposit:** User deposits TNZO and receives stTNZO at the current exchange rate.
- **Withdrawal request:** User burns stTNZO and enters a 7-day unbonding period. The TNZO amount is calculated at the exchange rate at request time.
- **Claim:** After unbonding, the user can claim their TNZO.
- **Transfer:** stTNZO is freely transferable.

### 10.5 Protocol Fee

The 10% protocol fee on staking rewards accrues to the Foundation treasury and funds protocol development and liquid-staking infrastructure maintenance. The fee is adjustable through governance and must remain within bounds that keep the effective yield competitive with direct staking.

---

## 11. Network Security and Slashing

### 11.1 Slashable Offenses

| Offense | Description | Penalty |
|---------|-------------|---------|
| Equivocation | Voting for multiple conflicting blocks in the same view (detected automatically) | 10% of staked amount |
| Downtime | Extended periods of unavailability during consensus | Variable (governance-determined) |
| Invalid proofs | Submitting fraudulent ZK proofs or TEE attestations | Variable (governance-determined) |
| Service failure | Provider fails to deliver contracted inference or TEE services | Variable (governance-determined) |

### 11.2 Slashing Mechanics

**Equivocation Detection.** The consensus layer's `EquivocationDetector` monitors all votes. When a validator signs conflicting votes at the same height/view, the detector:

1. Captures cryptographic evidence (both conflicting vote messages with signatures)
2. Triggers the `SlashingCallback` trait with the validator's address and evidence
3. The callback invokes `StakingManager::slash()` with a 10% penalty

**Slash Execution.** When a slash is executed:

1. The staker's bonded amount is reduced by the slash penalty.
2. The slash event is recorded on-chain with timestamp, reason, validator address, amount, and cryptographic evidence.
3. Any active unbonding period is reset.
4. If remaining stake falls below the role's minimum, the staker is forced into unbonding.
5. Slashed tokens are burned.

### 11.3 Foundation Role in Slashing

Equivocation slashing is fully automated — the consensus protocol detects double-voting, preserves evidence, and enforces the 10% penalty via the `SlashingCallback` bridge to `StakingManager`.

During the pre-decentralization phase, the Foundation Technical Committee retains authority for non-equivocation offenses:

- Initiate slash proposals for downtime, invalid proofs, or service failure
- Coordinate emergency slashing in response to active attacks
- Propose changes to slashing parameters through governance

Post-decentralization, all slashing types will be fully automated through the consensus protocol and on-chain evidence submission.

---

## 12. Identity and Access

### 12.1 TDIP (Tenzro Decentralized Identity Protocol)

Every participant on the Tenzro Network receives a TDIP identity, which is the foundational access credential for all network operations.

**DID formats:**

| Type | Format | Description |
|------|--------|-------------|
| Human | `did:tenzro:human:{uuid}` | Individual participant |
| Controlled machine | `did:tenzro:machine:{controller}:{uuid}` | Agent controlled by a human |
| Autonomous machine | `did:tenzro:machine:{uuid}` | Self-sovereign agent |

### 12.2 KYC Tiers

The Foundation may establish KYC requirements for certain operations:

| Tier | Level | Verification | Capabilities |
|------|-------|-------------|--------------|
| Unverified | 0 | None | Basic transactions, inference requests |
| Basic | 1 | Email | Standard operations, small grants |
| Enhanced | 2 | ID document | Large transactions, provider registration |
| Full | 3 | Biometric + institutional | Validator operations, large treasury grants |

KYC tier requirements for specific operations are set through governance. The Foundation operates or contracts KYC verification services during the pre-decentralization phase.

### 12.3 Cascading Revocation

Revoking a human identity automatically revokes all machine identities controlled by that human. This prevents orphaned agents from operating after their controller is deactivated. The Foundation may initiate identity revocation in cases of fraud, regulatory requirement, or demonstrated malicious activity, with the same published-rationale requirement that applies to vetoes.

---

## 13. Cross-Chain Bridge Oversight

### 13.1 Supported Bridges

The Tenzro Network supports cross-chain interoperability through six adapters:

| Bridge | Chains | Protocol |
|--------|--------|----------|
| Wormhole NTT | Ethereum, Solana, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base | Native Token Transfers (primary for TNZO) |
| LayerZero V2 | Ethereum, Arbitrum, Optimism, Polygon, BSC, Avalanche, Base | Omnichain messaging (mandatory Tenzro DVN) |
| Chainlink CCIP | Ethereum, Polygon, Avalanche, Arbitrum, Optimism | Cross-chain interoperability |
| deBridge DLN | Ethereum, Solana, BNB Chain, Polygon, Arbitrum | Intent-based transfers |
| Li.Fi | 130+ chains | Aggregator (best-route routing) |
| Canton | Enterprise Canton synchronizers | DAML/Canton enterprise |

### 13.2 Bridge Security

The Foundation is responsible for bridge security during the pre-decentralization phase:

- **Replay protection.** Nonce and message ID tracking prevent duplicate message delivery.
- **Message deduplication.** Token transfers are tracked to prevent replay attacks.
- **Relayer operation.** The Foundation operates bridge relayers for supported chains.
- **Incident response.** The Foundation can pause bridge operations in response to detected exploits.

### 13.3 Bridge Governance

Changes to bridge configurations are subject to governance proposals. Emergency bridge pauses by the Foundation Technical Committee are permitted without governance approval, with a mandatory post-incident report and governance ratification within 7 days.

---

## 14. Infrastructure Operations

### 14.1 Testnet

The Foundation (during pre-formation: Tenzro Labs) operates the public testnet. Public endpoints:

| Service | Endpoint |
|---------|----------|
| JSON-RPC | `rpc.tenzro.xyz` |
| Web API | `api.tenzro.xyz` |
| Faucet | `api.tenzro.xyz/faucet` |
| MCP Server | `mcp.tenzro.xyz` |
| A2A Server | `a2a.tenzro.xyz` |
| P2P | port 9000 (TCP + QUIC) |

Infrastructure layout (cloud, registry, fleet topology) is operator-specific; the Foundation's deployment is one of many possible. For the IaC-agnostic operator guide, see [`deploy/validator-deployment.md`](../deploy/validator-deployment.md).

### 14.2 Testnet Faucet

The testnet faucet distributes test TNZO for development purposes. Testnet tokens have no economic value and cannot be exchanged for mainnet tokens.

### 14.3 Bootstrap Nodes

The Foundation operates initial bootstrap nodes for peer discovery. As the network grows, the Foundation transitions to community-operated bootstrap nodes per the metrics in §15.

### 14.4 Software Releases

The Foundation is responsible for:

- Tagging and publishing releases of the reference node implementation
- Maintaining the Cargo workspace and dependency integrity
- Publishing desktop application binaries (macOS, Linux, Windows)
- Publishing CLI binaries and container images
- Coordinating protocol upgrade deployments

### 14.5 Security Audits

The Foundation commissions external security audits:

- Pre-mainnet audit of all 26 crates
- Annual audit of consensus and cryptographic subsystems
- Bridge adapter audits before enabling cross-chain transfers
- Smart contract / precompile audits before VM activation

Audit reports are published publicly. Critical and high findings are resolved before the audit is considered complete; medium and low findings are tracked publicly until closed.

---

## 15. Progressive Decentralization

The Foundation exists to bootstrap the network. Its authority is explicitly temporary. The progressive decentralization plan transfers control from the Foundation to on-chain governance in stages.

### 15.1 Phase 1: Foundation Governance (Initial)

- Foundation Council has veto power over governance proposals (with published rationale requirement)
- Foundation operates testnet infrastructure and bootstrap nodes
- Treasury multisig controlled by Foundation-appointed signers
- Protocol upgrades require Foundation Technical Committee approval
- Foundation sets initial network parameters

### 15.2 Phase 2: Shared Governance

Triggered when the network reaches sufficient decentralization metrics (validator count, stake distribution, geographic diversity):

- Foundation veto limited to security-critical proposals only
- Treasury multisig expanded to include elected community members
- Governance quorum reduced as participation increases
- Community-elected Technical Committee members join protocol review
- Foundation begins transferring bootstrap node operation to community

### 15.3 Phase 3: Community Governance

Triggered when on-chain governance has demonstrated sustained, representative participation:

- Foundation veto power revoked
- Treasury multisig fully community-controlled
- Protocol upgrades governed entirely by on-chain proposals
- Foundation retains only legal entity obligations and trademark stewardship
- Foundation Council transitions to advisory role

### 15.4 Decentralization Metrics

The Foundation tracks and publishes the following metrics quarterly:

| Metric | Phase 2 Target | Phase 3 Target |
|--------|---------------|---------------|
| Active validators | ≥ 50 | ≥ 200 |
| Nakamoto coefficient | ≥ 10 | ≥ 30 |
| Unique staking addresses | ≥ 1,000 | ≥ 10,000 |
| Governance participation (avg) | ≥ 10% of staked supply | ≥ 20% of staked supply |
| Geographic regions (validators) | ≥ 5 | ≥ 15 |
| Non-Foundation stake | ≥ 60% | ≥ 90% |
| Client diversity | ≥ 2 independent implementations | ≥ 3 independent implementations |

### 15.5 Irrevocability

The transition to Phase 3 is irreversible. Once the Foundation veto is revoked on-chain, it cannot be reinstated by any party. The governance contract enforces this constraint at the protocol level.

---

## 16. Code of Conduct

The Foundation, its bodies, contributors, and all participants in Foundation-operated forums and infrastructure adhere to a published Code of Conduct based on the Contributor Covenant. The Code of Conduct will be maintained at `CODE_OF_CONDUCT.md` in the primary protocol repository, and applies to:

- All Foundation Council, Technical Committee, and Treasury Committee proceedings
- All public communication channels operated by the Foundation
- All contributions to the reference implementation, documentation, and SDKs
- All Foundation-organized events

Violations are reported to the Foundation Council (post-formation) or to Tenzro Labs maintainers (pre-formation) and are handled per the published enforcement procedure. Enforcement actions affecting Foundation officers are subject to additional review by an independent ethics committee once Phase 2 begins.

---

## 17. Conflicts of Interest

### 17.1 Disclosure

All Foundation Council, Technical Committee, and Treasury Committee members disclose:

- Direct or indirect TNZO holdings exceeding 0.1% of supply
- Equity, advisory, or director positions in entities that contract with or compete with the Foundation, validators, providers, or bridge counterparties
- Other material financial relationships that could reasonably affect Foundation decisions

Disclosures are updated annually and upon any material change, and are published publicly.

### 17.2 Recusal

Foundation officers recuse themselves from votes, reviews, or decisions where they have a material conflict. Recusals are recorded in the meeting minutes and published with the decision.

### 17.3 Trading Restrictions

Foundation officers and senior Tenzro Labs personnel are subject to trading restrictions on TNZO and related assets:

- Blackout periods around protocol upgrades, treasury actions, and audit publication
- Pre-clearance requirements for trades exceeding defined thresholds
- Prohibition on trading on material non-public information

The full trading policy is published with the Foundation's founding documents.

### 17.4 Procurement

Foundation contracts with vendors, auditors, and grant recipients are awarded through documented selection processes. Contracts with parties connected to Foundation officers require disclosure and approval by uninvolved Council members.

---

## 18. Sunset and Dissolution

### 18.1 Sunset Principle

The Foundation is designed to dissolve. The endgame is a protocol that operates without a Foundation — governed by on-chain processes, secured by economically rational validators, and developed by an open contributor base. Every Foundation power has a defined path to revocation under §15.

### 18.2 Triggering Conditions

The Foundation Council may initiate dissolution when **all** of the following are met:

- Phase 3 (Community Governance) has been active for at least 24 months
- All Phase 3 decentralization metrics are sustained
- Multiple independent client implementations exist with non-trivial validator share
- A community-governed successor structure exists for any residual Foundation responsibilities (legal entity obligations, trademark stewardship, audit coordination)
- Treasury holdings (if any remain) have a documented disposition plan ratified by on-chain governance

### 18.3 Dissolution Process

Dissolution proceeds via:

1. A dissolution proposal published for at least 90 days of public comment
2. An on-chain governance vote requiring 40% participation and 75% approval
3. Transfer of remaining treasury holdings to the community as directed by the proposal (typically: protocol-controlled treasury, public-goods funding mechanism, or pro-rata distribution)
4. Transfer or open-licensing of trademarks and domain names per the proposal
5. Filing of legal entity dissolution in the Foundation's jurisdiction
6. A final dissolution report published on-chain

### 18.4 No Re-Establishment

Once dissolved, the Foundation cannot be re-established under the same name or with the same authority by any successor. Future stewardship structures, if needed, must be created through community governance under different identities.

---

## 19. Amendments

This charter is a living document. Amendments follow the same governance process as protocol changes:

- **Pre-formation:** Tenzro Labs may amend with published rationale and a 14-day public comment period before the amendment takes effect.
- **During Phase 1 (post-formation):** Foundation Council may amend with published rationale.
- **During Phase 2:** Amendments require both Foundation Council approval and a governance proposal passing with standard quorum.
- **During Phase 3:** Amendments require a governance proposal with enhanced quorum (30% participation, 66% approval).

All amendments are versioned, timestamped, and published on-chain (or, pre-formation, in the protocol repository with on-chain hash anchoring at the next available opportunity).

Sections governing dissolution (§18) require Phase 3 governance with the enhanced quorum threshold to amend at any time, regardless of phase.

---

## Appendix A: Key Protocol Constants (Testnet Phase)

| Constant | Value | Source |
|----------|-------|--------|
| TNZO decimals | 18 | tenzro-types |
| Maximum supply | 1,000,000,000 TNZO | tenzro-token |
| Supply model | Fixed cap; no mint authority beyond genesis | tenzro-token |
| Network commission | 0.5% | tenzro-settlement |
| Fee split: Treasury | 40% | tenzro-token |
| Fee split: Burn | 30% | tenzro-token |
| Fee split: Stakers | 30% | tenzro-token |
| Validator min stake | 10,000 TNZO | tenzro-token |
| TEE provider min stake | 1,000 TNZO | tenzro-token |
| Model provider min stake | 500 TNZO | tenzro-token |
| Storage provider min stake | 500 TNZO | tenzro-token |
| Unbonding period | 7 days | tenzro-token |
| Reward model | Work-gated coupons, declining schedule | tenzro-token |
| Epoch duration | 14,400 blocks (~1 day at 6-second block target) | tenzro-token |
| Governance min stake | 10,000 TNZO | tenzro-token |
| Governance quorum | 20% participation | tenzro-token |
| Governance approval | 50% of votes | tenzro-token |
| Governance voting period | 7 days | tenzro-token |
| Liquid staking fee | 10% of rewards | tenzro-token |
| stTNZO min deposit | 0.1 TNZO | tenzro-token |
| stTNZO unbonding | 7 days | tenzro-token |
| stTNZO max validators | 50 | tenzro-token |
| EIP-1559 target gas | 15,000,000 | tenzro-vm |
| EIP-1559 max gas | 30,000,000 | tenzro-vm |
| EIP-1559 min base fee | 0.1 Gwei | tenzro-vm |
| EIP-1559 max base fee | 1,000 Gwei | tenzro-vm |
| Default chain ID | 1337 | tenzro-vm |
| Max contract size | 24,576 bytes | tenzro-vm |
| Max call depth | 1,024 | tenzro-vm |
| TEE multiplier on leader draw | 1.5× | tenzro-consensus |
| HotStuff-2 phases | PREPARE, COMMIT (two-phase) | tenzro-consensus |
| Block time | 400ms | tenzro-consensus |
| Keystore encryption | Argon2id + AES-256-GCM | tenzro-wallet |
| MPC threshold | 2-of-3 | tenzro-wallet |
| Max settlement batch | 100 | tenzro-settlement |

## Appendix B: Token Distribution Addresses

*To be published at Token Generation Event. All allocation addresses will be verifiable on-chain.*

## Appendix C: Foundation Legal Entity

*To be established at Foundation formation, between testnet maturity and mainnet launch. The Foundation will be constituted as a non-profit entity in a jurisdiction that provides legal clarity for blockchain protocol stewardship. Until then, Tenzro Labs and community contributors operate against this charter as described in §3.*
