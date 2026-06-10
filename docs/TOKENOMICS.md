# TNZO Token Economics

## Version 1.0

TNZO is the gas, settlement, staking, and governance token of Tenzro Network. The supply is fixed at one billion. The model is designed for the agentic decade: demand is multi-sourced (gas, settlement, bonds, governance), burn channels track real usage rather than emission schedules, providers and validators earn from real economic activity rather than speculative yield, and human users retain control over agent spending through scope and policy primitives that are part of the protocol layer.

This document specifies the economic model, the rationale behind each parameter choice, and how the pieces compose into a sustainable system through and after the bootstrap phase.

---

## Table of contents

1. [Why TNZO](#1-why-tnzo)
2. [Supply and decimals](#2-supply-and-decimals)
3. [Demand sources](#3-demand-sources)
4. [Fee architecture](#4-fee-architecture)
5. [Burn channels and net supply](#5-burn-channels-and-net-supply)
6. [Adaptive burn dial](#6-adaptive-burn-dial)
7. [Staking](#7-staking)
8. [Liquid staking](#8-liquid-staking)
9. [Provider economies](#9-provider-economies)
10. [Bonds and slashing](#10-bonds-and-slashing)
11. [Bridge fee model](#11-bridge-fee-model)
12. [Treasury](#12-treasury)
13. [SeedAgent bootstrap allocation](#13-seedagent-bootstrap-allocation)
14. [Agent-economy specific surfaces](#14-agent-economy-specific-surfaces)
15. [Distributed training economics](#15-distributed-training-economics)
16. [Governance economics](#16-governance-economics)
17. [Sustainability](#17-sustainability)
18. [Where the agentic decade is going](#18-where-the-agentic-decade-is-going)

---

## 1. Why TNZO

TNZO is the primary utility token of Tenzro Network. It is the single asset every participant — humans, agents, machines — uses to pay transaction fees, access network resources, and vote in governance. The point of the design is simple: a participant on Tenzro does not have to juggle a dozen tokens to get things done. One token covers every protocol-layer action.

- **Gas.** Every transaction pays gas in TNZO. No separate fee token.
- **Resource access.** Resources on Tenzro are everything participants can offer or consume — agents, skills, data, workflows, models, compute, apps, tools, TEE attestation, storage, distributed training participation, micropayment channels, cross-chain messages, marketplace templates. Every paid resource settles its protocol-layer commission in TNZO. Counterparties can still settle the underlying payment in any asset they agree on (stablecoins, native chain assets, off-chain rails); TNZO is the protocol's denominator.
- **Governance.** Voting weight is TNZO-stake-weighted. A single asset is the basis for proposal bonds, voting, delegation, and constitutional decisions.
- **Bonds and security.** Validators, providers (model, TEE, storage, compute, data, training), bridge nodes, marketplace agents, and template creators bond TNZO. The bond aligns the participant with honest behavior; misbehavior is slashed.

TNZO does not replace user-facing stablecoins. AP2 cart settlements, x402 USDC flows, Tempo stablecoin transfers, Stripe Payment Intents, and Canton CIP-56 Canton Coin holdings all flow in their own assets. TNZO is the protocol-layer denominator that makes the rails work: gas, network commission, bond, and governance vote.

---

## 2. Supply and distribution

### Parameters

| Parameter | Value | Notes |
|---|---|---|
| Token name | TNZO | |
| Symbol | TNZO | |
| Decimals | 18 | u128 arithmetic throughout |
| Maximum supply | 1,000,000,000 TNZO | Fixed cap |
| Smallest unit | 10⁻¹⁸ TNZO | One wei-equivalent |
| Chain ID | 1337 | |
| Circuit-breaker maximum outflow | 1% of max supply per circuit-breaker window | Defense in depth on emergency operations |

Supply is fixed. There is no protocol-level mint authority beyond the genesis distribution; staking rewards are paid out of the rewards pool seeded at genesis (see section 7), not minted.

### Distribution model

**There is no team allocation and no investor allocation.** Tenzro Network is community-owned from day one. The genesis distribution funds the participants that produce value on the network and the long-term incentive pools that pay future participants for future contributions.

**The way to earn TNZO is to contribute value to the network.** This is open-ended by design. The protocol does not enumerate every legitimate path to earnings, and the list below is examples rather than a closed set — anyone finding a new way to create value for the network can earn from that activity. Representative paths include:

| Path | How value flows back as TNZO |
|---|---|
| Running a validator | Run a node that meets the resource profile (hardware, bandwidth, uptime, optional TEE attestation) and participate in HotStuff-2 consensus. Two tiers: resource-only validators earn priority fees and a base reward share with no stake required; staked validators bond TNZO on top of meeting the profile and earn higher reward multipliers, full leader-election eligibility, and governance weight (section 7) |
| Serving compute or hardware | Run a model provider, TEE provider, storage provider, distributed-training participant, or any other resource-serving role; earn per-call / per-token / per-service / per-attestation / per-byte fees, plus the provider class reward multiplier on staking rewards |
| Operating an RPC provider | Run a public or gated RPC endpoint that brokers access to network resources (Canton, regulated bridge routes, KYC-tier-gated services, admin-gated cross-chain mint/burn). Mint scoped API keys for tenants, manage per-tenant party allocation and identity-provider provisioning, expose per-tenant analytics; earn from tenant access fees, per-call fees, and commission on the underlying flow routed through your endpoint |
| Building and running apps on Tenzro | Ship an application that drives transactions through the network — settlements, payments, inference billing, marketplace flows; earn from the underlying activity (provider fees, marketplace commissions, agent template invocations, AP2 / MPP / x402 settlement flow your app routes) |
| Running agents that do useful work | Deploy autonomous or delegated agents that fulfill inference requests, payment routing, cross-chain settlement, capital intent, or any other paid service; earn per fulfilled task plus reputation-driven routing share |
| Building tools, skills, and integrations | Ship MCP tools, A2A skills, agent templates, libraries, SDKs, bridges, oracle integrations, payment-rail adapters, and other ecosystem components; earn template invocation commissions, tool / skill usage fees, and ecosystem grants |
| Data and content contributions | Contribute to skills, tools, model catalogs, training datasets, knowledge bases, reference data, or any other public resource the network consumes; earn through usage fees and governance-approved contribution rewards |
| Protocol and infrastructure work | Build the protocol itself, audit code, ship core integrations, write documentation, run security research, operate public infrastructure; receive grants from the public treasury through the Tenzro Foundation's governance-approved allocation process |
| Community participation | Participate in governance votes, contribute to community channels and learning resources, file useful bug reports, refer new participants; receive community incentive allocations, faucet allocations, marketplace rewards, and governance-approved incentives |

Beyond the above, the Tenzro Foundation runs a public, governance-controlled grant program. Grants fund work the community proposes and the network rewards — research, ecosystem development, public-good infrastructure, regional onboarding, education, security audits, integrations, and anything else governance approves as serving the network. The grant pool sits in the public treasury (section 12); allocation is on-chain and auditable.

There are no privileged token-holder classes. There are no lock-ups for special parties because there are no special parties. Every TNZO holder is holding because they earned it from the network or bought it from another participant who did.

### Circulating supply

Circulating supply at any point is the genesis distribution that has actually been claimed, plus net staking rewards paid, minus the cumulative burn from all five burn channels (section 5). The full supply does not enter circulation at genesis; participation-class allocations unlock as participants earn them (run a validator → earn validator rewards; serve inference → earn provider settlement; build a template → earn invocation commissions).

The treasury (40% of all network commission) accumulates a public, on-chain balance that governance disburses through grants and ecosystem incentives. Treasury holdings are not circulating; they enter circulation only when governance approves a specific disbursement.

### No reserved or vesting allocations

Because there is no team allocation and no investor allocation:

- There is no investor unlock cliff. There are no quarterly vesting events that release a wave of supply onto the market.
- There is no team unlock schedule. Contributors who build the protocol receive grants in the same way ecosystem builders do — through governance-approved disbursements from the public treasury, on terms the community can see.
- There is no early-backer carry. Anyone holding TNZO at any point in time is holding it because they earned it from the network or bought it from another participant who did.

This is the simplest possible alignment: every token holder has either contributed value to the network or has bought into a system where everyone else has.

---

## 3. Demand sources

A token's market behavior reflects the structure of its demand. TNZO has four orthogonal sources:

**Gas.** Every transaction on Tenzro Ledger — every EVM call, every SVM instruction, every Canton-routed command, every identity operation, every governance vote, every cross-chain message — pays gas in TNZO. EIP-1559 sets a dynamic base fee that adjusts ±12.5% per block to target half the block gas limit. The base fee is burned (see section 5). The priority fee goes to validators and stakers.

**Settlement commission.** Every payment routed through Tenzro's settlement layer (inference billing, TEE service payment, agent-to-agent settlement, AP2 cart, MPP receipt, x402 verification, micropayment channel close) pays a 0.5% network commission. The commission is split 40% treasury / 30% burn / 30% stakers.

**Bonds.** Every provider class bonds TNZO. Validators, model providers, TEE providers, storage providers, training participants, bridge nodes, marketplace agents — all bond. The bond aligns the provider with honest behavior. Misbehavior is slashed against the bond.

**Governance.** Voting weight is stake-weighted (see section 16). Proposers post a proposal bond; voters lock TNZO for the voting window.

Each demand source grows with usage rather than with speculation. The economic model favors networks where real activity (transactions, settlements, services, governance participation) produces real demand for TNZO.

---

## 4. Fee architecture

Tenzro implements two tiers of fees: gas (infrastructure layer) and network commission (service layer). The two are deliberately independent because they meter different things.

### Tier 1 — Gas fees (EIP-1559)

| Parameter | Value |
|---|---|
| Max gas per block | 30,000,000 |
| Target gas per block | 15,000,000 (50% of max) |
| Initial base fee | 1 Gwei (10⁹ wei-equivalent) |
| Min base fee | 0.1 Gwei |
| Max base fee | 1,000 Gwei |
| Elasticity multiplier | 2× |
| Base fee change rate | ±12.5% per block (denominator 8) |
| Max contract code size | 24,576 bytes |
| Max call depth | 1,024 |

Base fee adjustment formula:

```
if gas_used > target:
    delta = (base_fee × (gas_used − target)) / target / 8
    next_base_fee = base_fee + max(delta, 1)
else:
    delta = (base_fee × (target − gas_used)) / target / 8
    next_base_fee = base_fee − delta

next_base_fee = clamp(next_base_fee, min_base_fee, max_base_fee)
```

Fee split:

- **Base fee → burn.** Removed from circulating supply.
- **Priority fee → validators and stakers.** Tips for inclusion priority.

Priority fee suggestions by urgency:

| Urgency | Priority fee |
|---|---|
| Low | 10% of base fee |
| Medium | 20% of base fee |
| High | 50% of base fee |
| Urgent | 100% of base fee |

### Tier 2 — Network commission

| Parameter | Value |
|---|---|
| Network commission rate | 0.5% (50 basis points) |
| Treasury share | 40% (4,000 bps of commission) |
| Burn share | 30% (3,000 bps of commission) |
| Staker share | 30% (3,000 bps of commission) |
| Minimum settlement amount | 1,000 base units (dust protection) |
| Max batch size | 100 settlements per atomic batch |

Settlement fee formula:

```
network_fee     = (amount × 50) / 10,000          // 0.5%
provider_amount = amount − network_fee
treasury_amount = (network_fee × 4,000) / 10,000  // 40% of fee → 0.2% of amount
burn_amount     = (network_fee × 3,000) / 10,000  // 30% of fee → 0.15% of amount
staker_amount   = (network_fee × 3,000) / 10,000  // 30% of fee → 0.15% of amount
```

The 0.5% rate is set low to maximize adoption. Comparable take rates: traditional cloud (5–30%), centralized payment processors (2–4%), centralized model APIs (varies), traditional brokerages (basis points to percent). Governance can adjust the network commission rate upward as the network matures, with timelock-bounded magnitude caps.

### Why two tiers

Gas fees self-regulate via EIP-1559 to track infrastructure demand. Commission fees track service-layer activity. The two grow independently:

- A network running heavy DeFi but no inference burns gas heavily but accrues little commission.
- A network running heavy inference but no on-chain trades accrues heavy commission but burns less gas.
- A network running both — the steady state — does both.

The two-tier design diversifies revenue and reduces the dependence on any single demand source.

---

## 5. Burn channels and net supply

Tenzro has two independent demand-driven burn channels. Net supply change is the algebraic sum:

```
Net supply change per epoch =
    + staking rewards paid             (inflationary, capped at 5% APY)
    − base-fee burn                     (deflationary, EIP-1559)
    − commission burn                   (deflationary, 0.15% of all settled volume)
    − paymaster burn                    (deflationary, 100% of paymaster fees)
    − slashing burn                     (deflationary, 10% of slashed bond)
    − SeedAgent surplus burn            (deflationary, sunset disposition)
```

### Base-fee burn

Every block burns `base_fee × gas_used`. The default burn fraction is 100% — under EIP-1559, the entire base fee is removed from circulation. The base fee tracks network congestion: more activity, more burn.

### Commission burn

30% of every network commission is burned. Concretely: 0.15% of every settled amount is burned. For a network running on inference, training settlement, agent-to-agent commerce, micropayment channels, and bridge flows, commission burn is the second deflationary channel — it tracks service-layer demand independently of on-chain congestion.

### Paymaster burn

ERC-4337 paymasters can sponsor user gas. Tenzro paymasters burn 100% of the paymaster fee. This is structurally fixed (the paymaster burn fraction is locked at 100% so that sponsored gas does not become an inflation back-door).

### Slashing burn

Slashed stake is burned, not redistributed. 10% of an equivocator's stake disappears from circulating supply at the moment of slashing. Burning rather than redistributing keeps slashing purely punitive (avoiding the moral-hazard problem where slashing benefits the surviving validators).

### SeedAgent surplus burn

Any unused SeedAgent earmark at sunset is burned (see section 13).

### Combined dynamics

Whether net supply is inflationary or deflationary in any given epoch is a function of network usage:

- **Low-activity epoch.** Base-fee burn is small; commission burn is small; staking rewards still pay out; net inflationary.
- **Steady-state epoch.** Base-fee burn and commission burn together typically offset staking rewards.
- **High-activity epoch.** Both burn channels accelerate; net deflationary.

The model deliberately does not target a fixed inflation rate. The protocol does not need to issue tokens to subsidize participation; participation is funded by real network use.

---

## 6. Adaptive burn dial

Tenzro carries a governance-controlled adaptive burn dial that lets the protocol adjust burn fractions in response to circulating-supply targets.

### Configuration

The `BurnRateConfig` carries three independently-adjustable burn fractions:

| Parameter | Default | Adjustable |
|---|---|---|
| `base_fee_burn_bps` | 10,000 (100% of base fee burned) | Yes, by governance |
| `local_fee_burn_bps` | 10,000 (100% of local fee burned) | Yes, by governance |
| `paymaster_burn_bps` | 10,000 (100% of paymaster fee burned) | No, locked at 100% |

### Supply targets

A `SupplyTargets` configuration sets:

- A rolling-window length (in epochs)
- A neutral band (basis points around zero net supply change)
- An inflation alarm threshold and a deflation alarm threshold
- A target annual supply change in basis points
- Magnitude caps (normal and alarm)
- A fast-track timelock for alarm-triggered adjustments

### Recommendation engine

A pure transfer function `compute_recommendation(metrics, targets)` reads the latest supply metrics snapshot and emits one of:

- `NoChange` — within the neutral band
- `IncreaseBurnPct(bps)` — net supply tracking above target
- `DecreaseBurnPct(bps)` — net supply tracking below target
- `AlarmHighInflation(bps)` — net supply above the alarm threshold; fast-track adjustment
- `AlarmHighDeflation(bps)` — net supply below the alarm threshold; fast-track adjustment
- `Disabled` — adaptive burn is off; no recommendation

Magnitude is bounded by the configured caps. Recommendations are auto-proposed for governance vote and execute through the standard governance timelock.

### Why this matters

A fixed burn fraction works well at one usage band. As the network grows, the burn rate that produces sustainable net supply changes. The adaptive dial lets the protocol respond to actual on-chain conditions rather than guessing the right fraction at launch.

---

## 7. Staking and validator participation

Validators secure the network through HotStuff-2 consensus. Tenzro uses a two-tier validator model: eligibility is open to anyone meeting the resource profile, and staking is optional but unlocks additional benefits.

### Tier 1 — Resource-only validators

Open entry, no stake required. Eligibility is based on:

- **Hardware profile.** CPU cores, memory, disk, bandwidth, and storage IOPS thresholds checked at admission. Continuous monitoring confirms the validator continues to meet the profile during operation.
- **Stability profile.** Demonstrated uptime over a probation window, no equivocation history, no slashed peers in the operator's history.
- **TEE attestation (optional).** Hardware attestation through any supported vendor (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber). Not required, but attested validators receive the 1.5× multiplier on their leader-selection draw.
- **Geographic and network diversity.** The protocol's admission process favors validators that add geographic, ISP, or jurisdictional diversity to the existing set.

Resource-only validators are full participants in the BFT set: they vote in HotStuff-2 PREPARE / COMMIT / DECIDE, they propose blocks when elected, and they sign quorum certificates with hybrid Ed25519 + ML-DSA-65 + BLS12-381 signatures.

**Earnings.** Priority fees on blocks they propose, plus a base reward share. The base reward share scales with reputation (uptime, block-production success, no-equivocation history) and the provider class multiplier. Resource-only validators cap at a base reward multiplier and are excluded from leader election for the highest-trust block classes (e.g., blocks that include large-value institutional settlement or training round finalization) — those require staked tier validators.

**No slashing exposure.** Without bonded stake, a misbehaving resource-only validator can be removed from the set and have their reputation collapse, but cannot be financially slashed. This is the trade-off for open entry: the protocol's economic security on high-value blocks depends on the staked tier (below).

### Tier 2 — Staked validators

Resource-only eligibility plus bonded TNZO. Staked validators get:

- **Full leader-election eligibility** across every block class.
- **Higher reward multiplier** on top of the resource-only base.
- **Governance weight** — voting weight is stake-weighted (section 16). Resource-only validators do not have governance voting weight independent of their staking.
- **Slashing exposure** as the cost of higher trust: 10% bond burn on equivocation, additional slashing on withholding training results, invalid TEE attestations, or persistent SLA failures.

Stake also makes the validator eligible for high-trust roles:

- Witness committee membership for training round finalization (`tenzro-training`)
- High-value bridge node duties (Hyperlane Tenzro-set ISM, Wormhole Guardian-quorum participation when configured, threshold MPC bridge signer)
- AP2 high-value mandate validation surface
- Institutional Canton route operator

The TEE attestation multiplier (1.5×) is multiplicative and applies to both tiers. A staked TEE-attested validator has the highest combined leader-election draw probability.

### Parameters

| Parameter | Value | Source |
|---|---|---|
| Default minimum stake | 1,000 TNZO | `tenzro-token/staking.rs` |
| Default unbonding period | 7 days | `tenzro-token/staking.rs` |
| Base reward rate | 5% APY (500 bps) | `tenzro-token/rewards.rs` |
| Epoch duration | 14,400 blocks (~1 day at 6-second block target) | `tenzro-token/rewards.rs` |
| Epochs per year | 365 | |
| Equivocation slash | 10% of stake | `tenzro-consensus + tenzro-token` |
| TEE-attested validator multiplier | 1.5× on leader-selection draw | `tenzro-consensus` |
| Resource-only base reward share | Reputation-weighted base | Governance-set |
| Staked validator multiplier on base | Up to 2× the resource-only base, plus stake-weighted share of commission | Governance-set |

The minimum stake, unbonding period, resource profile thresholds, and reward share between tiers are governance-adjustable.

### Reward calculation

```
epoch_budget = (total_staked × reward_rate_bps / 10,000) / epochs_per_year
epoch_budget = min(epoch_budget, reward_pool_available)

For each staker:
    stake_proportion = stake_amount / total_staked
    base_reward      = epoch_budget × stake_proportion
    qos_adjusted     = base_reward × uptime_multiplier      // 0.0 to 1.0
    final_reward     = qos_adjusted × provider_multiplier   // 1.0× to 1.2×
```

### Provider reward multipliers

| Provider class | Multiplier | Rationale |
|---|---|---|
| Validator | 1.0× | Baseline — secures consensus |
| Model provider | 1.1× | Operational cost (GPU, bandwidth) |
| TEE provider | 1.2× | Capital cost (confidential hardware) |
| Storage provider | 1.0× | Baseline |

### Quality of service

The `uptime_multiplier` (0.0 to 1.0) scales rewards by actual contribution: a 95% uptime validator earns 95% of the potential reward, a 50% uptime validator earns 50%, zero uptime means zero reward. Reputation tracking (separate from stake) further influences proposer-election probability through reputation-weighted leader selection.

### Slashing

Equivocation is detected by the consensus equivocation detector watching every vote stream. When a double-sign is detected, the slashing callback burns 10% of the offender's stake and preserves the evidence in audit storage. Slashing automatically resets unbonding and can push stake below minimum, forcing the offender into involuntary unbonding.

Other slashable conditions follow per-class rules:

- **Downtime** — extended offline periods trigger graceful unbonding before slashing where possible.
- **Invalid TEE attestations** — TEE providers submitting forged attestations are slashed against their bond.
- **Inference failure** — model providers returning consistently incorrect inference results are slashed through reputation-driven mechanisms (see section 9).
- **Training misbehavior** — trainers submitting invalid outer gradients or withholding finalizations are slashed against the training bond.

### Burning vs. redistributing

Slashed TNZO is burned. This keeps slashing purely punitive — surviving validators do not benefit from a peer's loss, eliminating the moral-hazard incentive to encourage slashing events.

---

## 8. Liquid staking

Liquid staking lets users earn staking rewards while preserving liquidity. The stTNZO token is a rebasing representation of staked TNZO plus accrued rewards minus the protocol fee.

| Parameter | Value |
|---|---|
| Token | stTNZO |
| Decimals | 18 (matches TNZO) |
| Initial exchange rate | 1:1 |
| Protocol fee | 10% of staking rewards (1,000 bps) |
| Minimum deposit | 0.1 TNZO |
| Maximum total deposits | Unlimited (operator-configurable cap) |
| Unbonding period | 7 days (matches native staking) |
| Maximum validator diversification | 50 validators per pool |

### Exchange rate

Rebasing model. The exchange rate increases as the underlying staked TNZO accrues rewards:

```
exchange_rate = (total_underlying_wei × 10¹⁸) / total_sttnzo_supply
```

Overflow-safe computation uses quotient/remainder decomposition to handle u128 arithmetic on values that have both been multiplied by 10¹⁸:

```
quotient    = total_underlying / total_sttnzo_supply
remainder   = total_underlying % total_sttnzo_supply
exchange_rate = quotient × 10¹⁸ + (remainder × 10¹⁸) / total_sttnzo_supply
```

### Mint and redeem

- **Deposit TNZO → mint stTNZO** at the current exchange rate.
- **Burn stTNZO → withdraw TNZO** at the current exchange rate, subject to the 7-day unbonding.

### Multi-validator diversification

A liquid staking pool spreads its stake across up to 50 validators. Allocation is configurable per pool (proportional, weighted, or governance-set). Diversification reduces the risk that any one validator's slashing event materially impacts pool participants.

### Protocol fee

10% of accrued staking rewards goes to the protocol; the other 90% accrues to stTNZO holders via the rising exchange rate. The protocol fee is the operator's compensation for running the pool, validator selection, and slashing management.

---

## 9. Provider economies

Tenzro has multiple provider classes, each with its own micro-economy.

### Model providers

A model provider:

- Stakes TNZO (min stake configurable; see section 7).
- Registers in the model registry with one or more model identifiers, modalities, and pricing.
- Serves inference requests routed by the inference router (price, latency, reputation, or weighted strategy).
- Earns per call or per token (the unit depends on modality).
- Is rate-limited by their reputation score (250–1000 range).

Reputation is asymmetric: success on settled payment increments reputation by +1 (capped at 1,000); failure decrements by -5 (floored at 0). The split between "successful HTTP 200" and "settled payment" matters: HTTP 200 alone updates latency only. Reputation gain is gated to settled-payment-only so providers cannot game reputation without taking a real payment.

Reputation is durable. RocksDB persists per-provider reputation; restarts do not reset it.

### TEE providers

A TEE provider:

- Stakes TNZO (min stake configurable).
- Registers as a TEE provider with vendor (TDX / SEV-SNP / Nitro / NVIDIA GPU / Intel Tiber) and supported services.
- Generates attestations on demand for confidential inference, sealed key custody, or other confidential workloads.
- Earns per attestation or per service-second.
- Receives the 1.2× provider reward multiplier on staking rewards (reflects higher capital cost of confidential hardware).

### Validators

A validator:

- Stakes TNZO (min stake configurable).
- Joins the validator set through the epoch admission process (anyone with bonded stake can join at the next epoch).
- Participates in HotStuff-2 consensus.
- Earns priority fees and the staker share of network commission.
- TEE-attested validators get the 1.5× leader-selection multiplier.

### Storage providers

A storage provider:

- Stakes TNZO.
- Serves snapshot / DA / blob requests.
- Earns through DA pricing and snapshot-bootstrap fees.

### Marketplace template creators

A creator who publishes an agent template:

- Earns a 5% commission on paid invocations of their template.
- Earnings settle to the template's `creator_wallet` address atomically with the agent invocation.
- Template usage is tracked through `invocation_count` and `total_revenue` on-chain.

### Skill and tool creators

Skill and tool authors register entries in the skill / tool registries. Discovery is permissionless; usage is settled through the same micropayment substrate.

---

## 10. Bonds and slashing

Every provider class carries a bond. The bond size is proportional to the economic damage the provider could cause if they misbehave.

| Class | Bond size guideline | Slashing event |
|---|---|---|
| Validator stake | Min 1,000 TNZO (governance-set) | Equivocation: 10% |
| Model provider | Stake + AgentBond (per agent) | Persistent inference failure: reputation collapse + bond withholding |
| TEE provider | Stake | Forged attestation: bond slash |
| Training participant | Per-task escrow | Invalid outer gradient / withholding: per-task slash |
| Bridge node | Per-bridge configurable | Quorum dishonesty: bond slash |
| Agent (marketplace) | AgentBond | Insurance claim payout: bond withholding |

### AgentBond and insurance

For agent-marketplace transactions, agents post AgentBonds. If a user files an insurance claim alleging non-performance (the agent took payment but failed to deliver the service), the claim is adjudicated by the dispute resolution process. Approved claims pay out from the agent's bond. The agent's reputation reflects the outcome.

This protects users entering into agent-to-agent commerce without requiring per-transaction escrow on every interaction.

---

## 11. Bridge fee model

Cross-chain settlement has direct costs (gas on the source chain, fees on the destination chain, oracle/relayer compensation) and protocol-layer costs (the bridge router, fee oracle, monitor).

### Fee structure per route

For each bridge adapter, the fee is the sum of:

- **Source-chain gas** — paid in the source chain's native asset.
- **Destination-chain gas** — paid by the relayer/keeper.
- **Adapter-specific fee** — LayerZero DVN fee, CCIP fee, deBridge order fee, Wormhole relayer fee, etc.
- **Tenzro protocol fee** — a configurable basis-point fee on the routed amount.

The protocol fee is split per the standard commission split: 40% treasury / 30% burn / 30% stakers.

### Fee quoting

All adapters expose live fee quoting via the unified `BridgeRouter`. Callers request quotes for a desired route and receive a fresh quote per adapter, with the protocol fee already factored in. Quotes have a TTL; stale quotes are rejected.

### Fee sponsorship pools

Operators can contribute to bridge-fee sponsorship pools that subsidize cross-chain settlements for end users and agents on configured routes. Sponsorship pools are funded by:

- Operator contributions in TNZO.
- A configurable cut of the network commission routed through subsidized routes (capped to prevent runaway sponsorship).
- Treasury grants approved by governance.

Eligible flows draw automatically from the sponsorship pool when invoked through the standard bridge router. Sponsorship is logged on-chain and exposed via analytics.

### Fee oracle

A per-adapter fee oracle tracks recent fee observations and feeds the router with reasonable defaults when live quoting is unavailable (network partition, adapter outage). The oracle is also used by the adaptive burn dial input layer when estimating bridge-related supply impacts.

---

## 12. Treasury

The Tenzro Network Treasury accumulates 40% of all network commission, plus governance-approved transfers, plus genesis-allocated treasury holdings. The treasury is multisig-controlled and on-chain.

### Inflows

- **Settlement commission share** — 40% of all 0.5% network commissions across inference, training, settlement, bridge, marketplace, and agent-to-agent commerce.
- **Bridge protocol fees** — share of cross-chain settlement protocol fees (40% to treasury per the standard split).
- **Liquid staking protocol fee** — 10% of stTNZO pool rewards.
- **Marketplace commissions** — 5% of paid agent template invocations.
- **Slashing recovery** — note: slashed bond is burned, not deposited to treasury. The treasury does not benefit from slashing events.
- **Governance-directed transfers** — explicit grants or reallocations.

### Outflows

Multisig-controlled. Categories include:

- Protocol development grants (audits, core engineering, research)
- Ecosystem incentives (developer grants, bug bounties)
- Infrastructure (test environments, monitoring, on-call)
- Insurance fund seed and replenishment
- SeedAgent treasury earmark (see section 13)
- Bridge fee sponsorship pool contributions
- Operational costs (legal, compliance)

### On-chain transparency

All treasury inflows and outflows are on-chain and queryable. Multisig signers and signature thresholds are public. Audit trail is permanent.

---

## 13. SeedAgent bootstrap allocation

Every agentic protocol faces a bootstrap problem: no organic agents exist yet, so the protocol has to seed activity to demonstrate the rails work and to give early adopters something to interact with. SeedAgents are protocol-funded autonomous agents that exercise inference, settlement, marketplace, bridge, capital intent, and dispute surfaces during the first year of mainnet.

### Earmark

The SeedAgent earmark is a TNZO allocation from the genesis distribution, governance-controlled, with:

- An `enabled` master switch (off by default; turned on by governance proposal).
- A monthly decay schedule (default: 100% in months 0–2, 75% in months 3–5, 50% in months 6–8, 25% in months 9–11, 0% from month 12).
- A `surplus_burn_bps` parameter governing what happens to unused earmark at sunset (default: 100%; sunset disposition is burn).

### Charters

A SeedAgent operates under a governance-signed Charter that declares:

- The operation kinds the agent is allowed to perform (inference consumer, task marketplace consumer, template instantiator, bridge user, settlement probe, ERC-7683 probe, dispute filer).
- Spend caps (per operation, per day, per month).
- Target throughput.
- Counterparty filter (notably: `deny_other_seed_agents` to ensure SeedAgents do not transact with each other, so the network's organic-activity metrics remain meaningful).
- Sunset date.
- Enabled flag.

### Identity marker

Every SeedAgent identity is registered with the `is_seed_agent` flag set on its TDIP record. Every analytics surface (model usage, settlement volume, bridge flows, marketplace invocations, network activity) excludes SeedAgent activity in its organic-only views.

### Lifecycle

- **Active.** Charter-bounded operation.
- **Paused.** Charter at sunset enters Paused — agent stops initiating new operations, completes in-flight.
- **Quarantined.** A grace period before termination.
- **Terminated.** Agent identity revoked, residual bond unlocked, charter closed.

### Why this matters

SeedAgents make Tenzro work the day it launches. They demonstrate every protocol surface in real time. Their activity is loud about being protocol-funded — operators reading network analytics know what fraction of activity is organic. After 12 months they sunset and unused earmark burns, completing the bootstrap-to-organic transition.

---

## 14. Agent-economy specific surfaces

The agentic economy has a few specific economic surfaces that do not exist in human-only systems.

### Triple-ceiling enforcement on agent payments

Every agent payment passes through three independent ceiling checks:

1. **AP2 mandate constraints** — the mandate itself (signed by the user) declares an item set and a max amount; the payment cannot exceed either.
2. **Delegation scope (protocol layer)** — the agent's TDIP delegation scope declares per-transaction value cap, daily spend cap, allowed operations, allowed chains, allowed payment protocols, time bound. Enforced by `IdentityRegistry::enforce_operation`.
3. **Runtime spending policy** — the runtime `SpendingPolicy` tracks rolling daily spend per machine DID; per-transaction and daily-window caps enforced by `SpendingPolicySnapshot::check`.

All three must pass. The agent payment is refused if any single ceiling fails. The user retains the right to override via signing a new mandate or via the controller's revocation surface.

### ERC-7579 on-chain custody enforcement

The on-chain twin of the delegation scope is the spending limit validator module. Smart accounts use both — the on-chain validator enforces the limit at `validateUserOp`, the off-chain runtime spending policy reinforces it before the user operation is even dispatched. Custody is enforced at signing time, not as a defensive afterthought.

### Mandate-receipt binding

Every settlement receipt can be bound to the off-chain mandate that authorized it. The `MandateRef` carries the mandate protocol (`ap2-cart`, `ap2-intent`, `ap2-payment`, `x402`, `mpp`, `stripe-spt`, `visa-tap`, `mastercard-agent-pay`, `capital-intent`, `workflow-step`), the mandate hash, the issuer DID, the optional mandate URI, and the expiration. The audit loop intent → settlement is closed: every settlement reveals which mandate authorized it.

### Capital intent fee model

Capital intent lifecycle operations (open / quote / assign / execute / verify / compensate / settle) pay gas per operation plus network commission on the underlying settlement. There is no per-intent protocol surcharge; the system is priced on the actual flows it executes.

### Workflow fee model

Workflows pay gas per step plus a commission on the underlying value movement. Per-step compensate handlers do not pay commission on the rollback; commission is on net value transferred, not gross.

### Agent memory storage

Per-agent memory persistence (grant / recall / archive) is metered in storage units. Archived records pay an archive-write fee to the DA backend; recall is free reading. The fee model encourages archiving stale memory to DA so the on-chain index stays small.

---

## 15. Distributed training economics

Distributed training is its own micro-economy with its own incentive structure.

### Sponsor escrow

A training task posts a sponsor escrow in TNZO. The escrow funds:

- Per-step rewards to trainers who submit valid outer gradients accepted by the syncer.
- A finalization reward to the witness committee that produces the run-root commitment.
- A protocol commission (40% treasury / 30% burn / 30% stakers per the standard split).

### Trainer rewards

Trainers are paid proportional to their accepted outer-gradient count, weighted by their contribution to the inner training loop. Misbehavior (invalid gradients, divergent state_roots, withholding) slashes against the trainer's bond.

### Tier-policy

Three trust tiers:

- **Open** — anyone can train; only Mean aggregation; lowest sponsor barrier; default bond.
- **Verified** — trainers must hold a verified credential; all four aggregators (Mean / TrimmedMean / CoordinateMedian / Krum) admitted; higher bond.
- **Confidential** — training data is sealed (HPKE RFC 9180 wrapped); trainer must run inside an attested enclave; highest bond.

The sponsor picks the tier; the tier sets aggregation policy and trainer requirements.

### Witness committee rewards

The witness committee that finalizes a round earns a fraction of the round's sponsor disbursement. Membership rotates each round via deterministic per-round selection using the previous finalized block hash as entropy. Committee size scales with the syncer set.

### Forfeit on dishonest finalization

Conflicting `state_root` finalization attempts surface `ConflictingFinalize`. The witness that produced the conflicting submission forfeits its committee reward and is slashed against its bond.

---

## 16. Governance economics

Governance is on-chain, stake-weighted, and constitutionally bounded.

### Proposal classes

| Class | Bond | Voting window | Timelock | Quorum |
|---|---|---|---|---|
| Parameter change | Low | Standard | Standard | Simple majority |
| Treasury disbursement | Low | Standard | Standard | Simple majority |
| Code upgrade | Medium | Standard | Standard | Supermajority (2/3) |
| Adaptive burn (normal) | Low | Short | Short | Simple majority |
| Adaptive burn (alarm) | Low | Short | Fast-track | Simple majority |
| Constitutional | High | Long | Long | Supermajority (2/3) |
| SeedAgent charter | Medium | Standard | Standard | Simple majority |
| Bridge authorization | Medium | Standard | Standard | Simple majority |
| Network commission rate | Low | Standard | Standard | Simple majority |

### Voting weight

Stake-weighted with quadratic dampening on the upper end so any single very large staker cannot dominate. KYC-tier bonus weights apply to treasury and constitutional proposals (KYC-Full carries more weight than KYC-Basic, recognizing that constitutional decisions have higher counterparty-trust requirements). Delegate voting is supported: a staker can delegate voting weight without delegating stake.

### Vote economics

Voters lock TNZO for the voting window. There is no slashing for voting against the eventual outcome; voting is exclusively about preference revelation, not commitment. Proposal bonds are returned to the proposer if the proposal passes; forfeited (burned) if the proposal fails.

### Executor

The governance executor mints, burns, transfers from treasury, and adjusts parameters by calling into the relevant subsystems' privileged surfaces. The executor itself has no off-protocol authority; it can only do what the on-chain proposal authorizes.

---

## 17. Sustainability

A token economy is sustainable when participation is funded by real network use rather than emission schedules.

### Steady-state check

For TNZO to be sustainable at steady state, the inflationary forces (staking rewards, ecosystem incentives) must be offset by the deflationary forces (base-fee burn, commission burn, paymaster burn, slashing burn).

The model has no fixed emission schedule. Staking rewards are paid out of a finite rewards pool (genesis-allocated, governance-replenishable from treasury) at a rate the protocol can sustain given current activity. If activity is low, the rate is constrained; if activity is high, the rate is generous.

The burn channels grow with usage:

- **Heavy DeFi activity** → high base-fee burn.
- **Heavy inference / settlement activity** → high commission burn.
- **High paymaster sponsorship** → high paymaster burn.

The adaptive burn dial (section 6) gives governance a finer instrument to keep net supply tracking on target even as the activity mix changes.

### Break-even target

At a hypothetical 30% staking ratio (300M TNZO staked) earning 5% APY:

- Annual staking rewards paid: 15M TNZO
- Required annual burn to offset: 15M TNZO
- At Ethereum-class utilization (15M gas/block at 30 Gwei base fee), gas burn alone produces a fraction of this; commission burn at moderate usage closes the gap.

Once commission throughput crosses a threshold, net supply is deflationary. The threshold depends on the gas burn baseline and the commission throughput; both grow with the network, and so does the offset.

### Demand independence

Demand for TNZO does not require speculative appreciation to function. Every gas user, every settlement participant, every staker, every voter, every provider needs TNZO to do their work. The token's role is functional, not promotional.

### Treasury runway

The treasury accumulates 40% of all commission flows plus other inflows (section 12). As long as the network is being used, the treasury runway extends. If treasury inflows exceed planned outflows, governance can adjust either the inflow rate (lower commission), the outflow rate (more grants), or both. The treasury does not depend on token sales or external financing.

---

## 18. Simulations

The model is verified through closed-form analysis and scenario simulation across the failure modes that have broken comparable systems. The simulations test whether net supply, staking equilibrium, fee market, treasury runway, and SeedAgent sunset all behave correctly under realistic and adversarial activity profiles. Every parameter used here matches the on-chain defaults; the equations are reproducible from the constants in sections 2 through 7.

### 18.1 Net supply across activity regimes

Define the per-epoch (one-day) supply equation:

```
ΔS_epoch = R_stake − B_basefee − B_commission − B_paymaster − B_slash − B_seedagent_surplus
```

Where:

- `R_stake` = epoch staking reward paid = `(S_staked × r_apy) / 365`
- `B_basefee` = `Σ (base_fee_block × gas_used_block)` over all blocks in the epoch, multiplied by `base_fee_burn_bps / 10,000`
- `B_commission` = `0.30 × 0.005 × V_settlement_epoch`
- `B_paymaster` = `1.00 × F_paymaster_epoch`
- `B_slash` = sum of slashed bonds (typically zero in honest operation)
- `B_seedagent_surplus` = nonzero only at SeedAgent sunset

Setting parameters from sections 4 and 7 (`base_fee_burn_bps = 10,000`, `r_apy = 0.05`, commission burn share = 30%). All quantities below are denominated in TNZO; settlement volume is in TNZO (not in USD-equivalent) so the burn math is price-independent.

Gas burn baseline: assume an average base fee `b_avg` across the epoch and a total gas used per epoch `G_epoch`. With a 6-second block target and 14,400 blocks/epoch, `G_epoch = blocks_per_epoch × avg_gas_per_block`. Default `b_avg` track-rate is 1 Gwei (≈ 10⁻⁹ TNZO/gas) at the EIP-1559 floor; sustained congestion drives `b_avg` upward through the ±12.5% adjustment.

Commission burn: `B_commission = 0.30 × 0.005 × V_settlement_TNZO_per_epoch = 0.0015 × V_TNZO`.

| Regime | `S_staked` (TNZO) | Avg block gas | `b_avg` | Gas burn (TNZO/day) | Settlement vol (TNZO/day) | Commission burn (TNZO/day) | `R_stake` (TNZO/day) | ΔS/day | Annualized |
|---|---|---|---|---|---|---|---|---|---|
| Low (bootstrap) | 100M | 1M | 1 Gwei | 14.4 | 100K | 150 | 13,699 | +13,535 | +4.94% / yr |
| Moderate | 200M | 5M | 5 Gwei | 360 | 5M | 7,500 | 27,397 | +19,537 | +3.57% / yr |
| Breakeven | 300M | 10M | 10 Gwei | 1,440 | 25M | 37,500 | 41,096 | +2,156 | +0.26% / yr |
| Steady-state | 300M | 15M | 30 Gwei | 6,480 | 50M | 75,000 | 41,096 | −40,384 | −4.91% / yr |
| Heavy | 400M | 20M | 100 Gwei | 28,800 | 200M | 300,000 | 54,795 | −273,995 | −25.0% / yr |
| Peak agentic | 500M | 25M | 200 Gwei | 72,000 | 500M | 750,000 | 68,493 | −753,507 | −55.0% / yr |

Two observations:

- The model is mildly inflationary in early-stage operation (under 4-5% APY net inflation at the lowest activity levels). This is the price of paying staking rewards before commission throughput catches up.
- At a moderate steady-state — 50M TNZO of settlement volume per day with 15M gas per block at 30 Gwei — net supply already contracts at ~5% APY. At heavy agentic-economy activity the contraction is much faster.

**Reality check on settlement volume.** Is "50M TNZO/day" realistic? With the network's expected activity surfaces — inference billing, training settlement, agent commerce, micropayment channels, bridge routing, marketplace invocations, AP2 / x402 / MPP payments, capital intent flows — a per-user-per-day settlement footprint in the tens to hundreds of TNZO across a base of moderate users reaches this magnitude long before mainstream adoption. At a hypothetical 1M active agents on the network each producing 50 TNZO/day in settled commerce, the daily volume is 50M TNZO. The agentic-economy projection where most discrete economic actions are agent-driven puts daily volumes orders of magnitude above this.

**Stress check — permanent stagnation.** If the network is permanently stuck at the "Low" regime, annual net inflation tops out at ~5%. After ten years, cumulative inflation is ~63% (compounded); supply approaches but never reaches the 1B cap because the rewards pool is finite (paid out of the genesis-allocated pool, not minted; see section 7). The protocol does not face a runaway-emission failure mode even in worst-case stagnation. The bounded rewards pool plus the natural ramp from bootstrap to organic activity ensures the inflation phase is transient.

**Stress check — runaway deflation.** At "Peak agentic" rate, supply contracts at ~55% annually. The adaptive burn dial (section 6) gives governance an instrument to throttle this — lowering `base_fee_burn_bps` from the 100% default to e.g. 50% halves the burn-channel contribution. Extreme deflation also pushes up real fees, which dampens demand on its own. The protocol can tune through this; there is no failure mode here, only a parameter to manage.

### 18.2 Staking equilibrium

Define the staking participation function: `participation_rate = f(real_yield, opportunity_cost)`.

Real yield to a staker:

```
real_yield = (r_apy × type_multiplier × qos_multiplier) − protocol_fee
           + staker_share_of_commission
           − expected_slash_rate
```

Plugging in defaults (`r_apy = 5%`, validator `type_multiplier = 1.0`, QoS = 1.0, no protocol fee on native staking, expected slash rate ≈ 0 under honest operation, staker share of commission at moderate activity ≈ 0.5% APY):

- Validator real yield: **≈ 5.5% APY**
- TEE provider real yield: **≈ 6.5% APY** (1.2× multiplier)
- Model provider real yield: **≈ 6.0% APY** (1.1× multiplier)
- stTNZO holder real yield: **≈ 4.95% APY** (90% pass-through after 10% protocol fee)

**Equilibrium check against 2026 baselines.**

| Network | Nominal APY | Inflation drag | Approximate real yield |
|---|---|---|---|
| Ethereum (staking) | 2.8–3.8% | ~0.2% (mild) | 2.6–3.6% |
| Solana (native) | 6–8% | ~5–6% | 0–3% |
| Cosmos (ATOM) | 10–14% (some sources 15–20%) | ~10% | 0–8% |
| Polkadot (DOT) | 7–12% | varies by era | 4–8% |
| 2026 T-bills | ~4–5% | n/a (fiat baseline) | 4–5% |
| **Tenzro (validator)** | **5.0–5.5% nominal** | **Net deflationary at moderate activity** | **5.0–7.0% real** |

At 5.0–5.5% nominal with potential native-burn deflation at moderate-to-high activity (regimes from 18.1), Tenzro's real yield is competitive with or exceeds every major proof-of-stake network on a real-yield basis. The structural advantage is the absence of an emission schedule — staking rewards come from a finite genesis-allocated pool and burn channels track real usage, so real yield rises rather than falls as the network grows.

**Stress check — yield collapse.** If real yield drops below ~3% APY (e.g., rewards pool depletes or commission revenue stalls), participation falls. The security budget falls. At what participation level does the network become Byzantine-vulnerable?

HotStuff-2 BFT requires `> 2/3` of validator-weight honest. Tenzro's two-tier validator model splits this budget:

- **High-value blocks** (training round finalization, institutional settlement, high-value bridge messages, Canton DvP) are restricted to staked validators only. The 2/3 safety bound on these blocks is measured on staked weight. An attacker breaking liveness or safety on a high-value block must acquire and bond the required share of *staked* TNZO at market price.
- **Standard blocks** are open to both tiers. The 2/3 safety bound is measured on combined validator-weight (staked + resource-only). An attacker can theoretically break liveness on standard blocks by running enough resource-only nodes to control 1/3 of validator weight, but admission gates (hardware profile, stability profile, geographic diversity) and per-block staked weight requirements bound this.

For the high-value block path, the cost to mount an attack is the cost to acquire and bond the required share of currently-staked TNZO at market price.

| Staking participation | Honest stake (TNZO) | Attacker cost to break liveness (>1/3 of staked) | Attacker cost to break safety (>2/3 of staked) |
|---|---|---|---|
| 10% | 100M | >33M TNZO + market impact + slashing exposure | >67M TNZO + market impact + slashing exposure |
| 20% | 200M | >67M TNZO | >133M TNZO |
| 30% | 300M | >100M TNZO | >200M TNZO |
| 50% | 500M | >167M TNZO | >333M TNZO |

The attacker also faces (a) the slashing risk on every validator they operate (10% bond burn per equivocation; correlated attacks compound), (b) market impact on accumulating the position, and (c) the cost of running the additional infrastructure. Real attacker cost is meaningfully above the headline TNZO figure.

Staking participation below ~10% (i.e., when 33M TNZO is enough to break liveness) is a security-budget signal that triggers governance intervention: raise the reward rate temporarily, raise the commission share to stakers, fund a participation incentive, or pause non-essential treasury outflows to redirect to staker rewards. The adaptive burn dial alone is insufficient at this end — direct governance intervention is the lever.

**Stress check — slashing spiral.** A single equivocation slashes 10% of one offender's stake. The largest realistic single-event burn from slashing is bounded by `0.10 × (largest single validator's stake)`. With even distribution and 100 validators, this is ≤ `0.001 × S_staked`. A correlated multi-validator equivocation event (worst case, all 100 validators slashed simultaneously) is bounded at `0.10 × S_staked`. The protocol does not face a spiral failure mode — slashed stake is burned, not redistributed, so there is no positive feedback loop where surviving validators benefit from peers' slashing.

### 18.3 Fee market stability

Define the EIP-1559 fixed point. Given `target_gas = 15M`, `gas_used_block`, and base fee `b`:

```
b_{t+1} = b_t × (1 + (gas_used − target) / (target × 8))
```

With clamps `b ∈ [0.1 Gwei, 1000 Gwei]`. The fixed point is `b* such that gas_used(b*) = target`, i.e., the base fee where demand matches the 50%-utilization target.

**Stress check — empty blocks.** If demand goes to zero, `b_{t+1} = b_t × 7/8`. After 10 blocks at zero demand, `b → 0.263 × b_0`; after 17 blocks, `b → 0.094 × b_0`, hitting the 0.1 Gwei floor from a 1 Gwei starting base fee. The fee market does not get stuck at a high base fee during demand droughts.

**Stress check — sustained congestion.** If demand stays at `2× target` (full blocks), `b_{t+1} = b_t × 9/8`. After 10 blocks, `b → 3.25 × b_0`; after 25 blocks, `b → 11.4 × b_0`; converges to the 1000 Gwei ceiling from a 1 Gwei starting base fee in ~58 blocks of sustained full-block demand. Up and down adjustments are symmetric in their fixed-point ratio per block (12.5% absolute), which means the time to fully respond to a demand shock is bounded and predictable.

**Stress check — adversarial spamming.** An attacker can artificially inflate `gas_used` by spamming valid transactions. Under EIP-1559, each spam transaction also pays its own gas at the elevated base fee, which is burned. The attacker pays the protocol per-block to drive the fee up, and the elevated fee both deters legitimate users and accelerates burn. Spamming is self-defeating economically unless the attacker's goal is to deny service rather than to game economics — in which case the attacker is simply purchasing block space at market rate, which is the design.

### 18.4 Treasury runway

Define treasury solvency:

```
T_{t+1} = T_t + I_t − O_t

where:
  I_t = 0.40 × commission flow + bridge protocol fee share + liquid-staking protocol fee + marketplace commissions
  O_t = grants + ecosystem incentives + infrastructure + insurance fund + SeedAgent earmark + sponsorship contributions + operational
```

For the network to fund itself indefinitely from real demand:

```
I_steady_state ≥ O_steady_state
```

**Solvency check at the steady-state settlement volume** (from 18.1, 50M TNZO/day = 18.25B TNZO/year):

- Annual treasury inflow from commission: `0.40 × 0.005 × 18.25B TNZO` = **36.5M TNZO/year**
- Plus liquid-staking protocol fees on stTNZO pools: ~`0.10 × 0.05 × S_staked_in_liquid_pools` (variable; bounded by stTNZO TVL)
- Plus marketplace commissions at moderate marketplace volume: ~1–10% of treasury inflow
- Plus bridge protocol fees and other commission flows

At steady-state activity, treasury inflow at ~36.5M TNZO/year (~3.65% of max supply per year) is ample to fund grants, audits, insurance, infrastructure, and a sponsorship pool without depleting the genesis allocation. Below steady-state activity, the treasury must rely on its genesis-allocated initial balance to extend runway; governance can throttle outflows during the bootstrap phase to preserve runway until commission throughput ramps up.

**Stress check — bootstrap runway.** Treasury inflows during the first 12 months will be modest. The SeedAgent earmark explicitly funds protocol activity during this window so that commission inflows ramp up before the bootstrap balance depletes. The earmark sunset is timed to coincide with the projected organic-activity ramp.

### 18.5 SeedAgent sunset disposition

Define the SeedAgent earmark draw schedule (defaults from section 13):

| Months | Draw rate |
|---|---|
| 0–2 | 100% of monthly entitlement |
| 3–5 | 75% |
| 6–8 | 50% |
| 9–11 | 25% |
| 12+ | 0% (sunset, surplus burns) |

**Total SeedAgent draw bounded at:**

```
T_draw_total = E × (3 × 1.00 + 3 × 0.75 + 3 × 0.50 + 3 × 0.25) / 12
            = E × 0.625
```

Where `E` is the annual entitlement. At sunset, the unused fraction (37.5% by default) plus any unspent in-period reserve is burned. The protocol does not retain a residual SeedAgent allocation past month 12.

**Stress check — extension by governance.** If organic activity is below the projected ramp at month 12, governance can vote to extend SeedAgent operation. The amount available for extension is bounded by what the treasury can fund, not by the original earmark. This forces the trade-off explicit (extending SeedAgent draws on treasury, not on a pre-allocated reserve).

**Stress check — premature sunset.** If organic activity exceeds projection by month 6, the charter can sunset early; the surplus disposition (burn) still applies. The protocol does not retain unused bootstrap capacity for any other purpose.

### 18.6 Bridge sponsorship sustainability

Bridge fee sponsorship draws from a configurable pool. Sustainability requires:

```
S_pool_inflow ≥ S_pool_outflow_to_sponsored_routes
```

Where pool inflow comes from operator contributions, a configurable cut of network commission on subsidized routes, and treasury grants. The cap on commission share is governance-set; the default cap prevents runaway sponsorship.

**Stress check — sponsorship drain.** If sponsored routes are gamed (users routing through them solely to extract subsidies), the cap on commission share auto-throttles. Persistent gaming triggers governance to lower the cap, raise the eligibility threshold, or shut down sponsorship for a specific route.

### 18.7 Failure mode coverage

The simulations above cover the failure modes that have broken comparable systems in 2022–2025:

| Failure mode | Tenzro mitigation | Tested in |
|---|---|---|
| Runaway emission | No emission schedule; rewards from finite genesis pool | 18.1 |
| Insufficient burn | Two demand-driven channels + adaptive dial | 18.1, 18.3 |
| Staking yield collapse → security degradation | Adaptive reward rate + governance lever | 18.2 |
| Slashing cascade | Slashed stake is burned, not redistributed; no positive feedback | 18.2 |
| Fee market lock-up at high base fee | Symmetric ±12.5% adjustment + ceiling | 18.3 |
| Adversarial gas spamming | Self-paid via the same base-fee burn | 18.3 |
| Treasury depletion | Diversified inflows; governance throttles outflows | 18.4 |
| Bootstrap funding cliff | SeedAgent earmark + adaptive disbursement | 18.4, 18.5 |
| Sponsorship pool drain | Governance-set commission share cap | 18.6 |
| Investor / team unlock cliffs | No team or investor allocation; no cliffs exist | 2 |

The model is conservatively parameterized — every assumption used to verify it errs on the side of pessimism (low activity, no organic ramp, adversarial staking participation, sustained congestion). The default parameters survive every simulation; the governance dials are available to retune any of them if real-world activity diverges from these projections.

---

## 19. Where the agentic decade is going

The model above is designed for where the AI and agentic economy is going, not where it has been.

**Agents do most discrete economic actions.** By the late 2020s, autonomous agents — frontier-LLM-driven, tool-using, identity-bound — will conduct the majority of routine economic transactions: quote requests, payment routing, on-chain settlement, identity verification, micro-credentialing. The protocol that wins this period is the one that gives agents a complete substrate. Tenzro's TDIP, MPC wallets, AP2 mandates, ERC-7579 custody, MCP/A2A surfaces, and protocol-level settlement are designed for that world.

**Settlement converges on identity-bound payment.** Stablecoins, payment processors, card networks, agent-pay standards, and on-chain micropayments are all converging on the same model: a counterparty identity (KYC where required), a signed mandate (authorization scope), a settled receipt (audit). MPP, x402, Tempo, Visa Tap, Mastercard Agent Pay, Stripe SPT, and AP2 all express this pattern. Tenzro implements every major variant natively so an agent can serve any payment surface its counterparty needs.

**Open-source AI is the default.** By late 2026, open-weight models from Qwen, Gemma, Mistral, DeepSeek, Granite, and others match or exceed closed frontier models on most benchmarks. Inference moves from a small number of hyperscaler APIs to a long tail of operators serving their own GPUs. Tenzro's permissionless model marketplace, multi-modality runtimes, and provider economy are built for this distribution.

**Distributed training is production.** DiLoCo / Decoupled DiLoCo / OpenDiLoCo / INTELLECT-1/2/3 / Hermes 4 have demonstrated that frontier-quality models can be trained across regions and across operators. The protocol layer that wins is the one that provides cross-operator coordination — sponsor escrow, witness committees, on-chain run-root commitments, sealed-shard confidential training. Tenzro Train is built for this.

**Institutional rails go on-chain.** Canton Network is settling tokenized money-market funds, treasuries, bonds, and equities for major asset managers. Banks settle DvP through Canton. Public chains do not have to replace this; they have to interoperate. Tenzro's Canton 3.5+ adapter — JSON Ledger API v2, CIP-26 user management, CIP-56 Canton Coin holdings, party-scoped privacy, multi-tenant isolation — is the bridge between institutional rails and the public agentic economy.

**Cross-chain becomes intent-driven.** ERC-7683 cross-chain intents, deBridge DLN, LayerZero V2, and CCIP CCT are coalescing on an intent-driven model: the user signs what they want; the network finds the cheapest, fastest, or most-reliable path. Tenzro's unified `BridgeRouter` is built for this.

**Regulation requires legibility.** EU AI Act Article 50 binds AI disclosure. MiCA binds stablecoin and crypto-asset service providers. Travel rule enforcement extends to virtual asset service providers. Protocols that move into 2027 without auditable identity, mandate-bound authorization, KYC-tier-bound delegation, on-chain receipts, and operator-grade analytics will not be usable by institutional counterparties. Tenzro's TDIP credential system, AP2 validation, ERC-7579 enforcement, settlement receipts with mandate binding, and per-tenant analytics are built for this regulatory shape.

**Post-quantum becomes table stakes.** NIST standardized ML-DSA in 2024; CNSA 2.0 mandates PQ-hybrid signatures across federal infrastructure by the late 2020s; major TLS deployments shipped X25519MLKEM768 in 2024–2025. Protocols that store value or sign attestations for the long term need PQ-hybrid throughout. Tenzro's Ed25519 + ML-DSA-65 hybrid signatures on every safety-critical message, X25519 + ML-KEM-768 key exchange, and PQ-hybrid wallet primitives are built for this.

The TNZO economic model is built around these forward trajectories. Demand sources scale with the agentic economy. Burn channels scale with real usage. Bonds align providers with the value they secure. Governance dials let the protocol respond to where the world is going.

That is what TNZO is for.

---

**License: Apache-2.0.**
