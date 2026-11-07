# TNZO Token Economics

## Version 1.2

TNZO is the economic unit that keeps Tenzro Network running. It prices and settles work on chain, it is the stake operators bond and are slashed in, it pays gas, and it funds the network's upkeep through fees and the treasury. The supply is fixed at one billion TNZO, all allocated at genesis. Nothing mints TNZO after genesis and there is no inflation: rewards are paid from a pool genesis already funded, and burns only reduce the supply.

Tenzro is an open network for the machine economy: machines from small edge devices to the largest GPU servers sell AI work, and agents and apps buy it. The token model serves that economy rather than the other way round. Providers, validators and creators are paid for paid, verified work and for nothing else; nothing is paid for holding, volume, sign-ups or engagement. End users do not need to hold TNZO: protocol fees are set in USD terms, and the apps and platforms that serve users pay on their behalf, in what those users already use.

This document specifies the economic model, the rationale behind each parameter, and how the pieces compose, from the bootstrap through progressive decentralization. It states rules and governed parameters; it makes no forecast of any return.

---

## Table of contents

1. [Why TNZO](#1-why-tnzo)
2. [Supply and decimals](#2-supply-and-decimals)
3. [Demand sources](#3-demand-sources)
4. [Fee architecture](#4-fee-architecture)
5. [Burn channels and net supply](#5-burn-channels-and-net-supply)
6. [Adaptive burn dial](#6-adaptive-burn-dial)
7. [Staking](#7-staking)
8. [Bonded stake is not tokenized](#8-bonded-stake-is-not-tokenized)
9. [Provider economies](#9-provider-economies)
10. [Bonds and slashing](#10-bonds-and-slashing)
11. [Bridge fee model](#11-bridge-fee-model)
12. [Treasury](#12-treasury)
13. [Bootstrap activity](#13-bootstrap-activity)
13c. [Grants and funding proposals](#13c-grants-and-funding-proposals)
13d. [Vesting](#13d-vesting)
14. [Agent-economy specific surfaces](#14-agent-economy-specific-surfaces)
15. [Network duties](#15-network-duties)
15b. [Economic security](#15b-economic-security)
16. [Governance economics](#16-governance-economics)
17. [Sustainability](#17-sustainability)
18. [Where the agentic decade is going](#18-where-the-agentic-decade-is-going)

---

## 1. Why TNZO

TNZO is the primary utility token of Tenzro Network. It is the single asset every participant — humans, agents, machines — uses to pay transaction fees, access network resources, and vote in governance. The point of the design is simple: a participant on Tenzro does not have to juggle a dozen tokens to get things done. One token covers every protocol-layer action.

- **Gas.** Every transaction pays gas in TNZO. No separate fee token.
- **Resource access.** Resources on Tenzro are everything participants can offer or consume — agents, skills, data, workflows, models, compute, apps, tools, TEE attestation, storage, generative image and video rendering, micropayment channels, cross-chain messages, marketplace templates. Every paid resource settles its protocol-layer commission in TNZO. Counterparties can still settle the underlying payment in any asset they agree on (stablecoins, native chain assets, off-chain rails); TNZO is the protocol's denominator.
- **Governance.** Voting weight is TNZO-stake-weighted. A single asset is the basis for proposal bonds, voting, delegation, and constitutional decisions.
- **Bonds and security.** Validators, providers (model, TEE, storage, compute, data), bridge nodes, marketplace agents, and template creators bond TNZO. The bond aligns the participant with honest behavior; misbehavior is slashed.

Users and apps are not asked to carry the token. Fees can be covered at the application layer: a platform or app that buys AI for its users pays the network's charges itself and prices the service to them on its own terms, so a user does not need TNZO just to use it; protocol fees are set in micro-USD and charged in TNZO at the rate in force (see [ECONOMICS.md](ECONOMICS.md)), so the network's charges do not drift with the token.

TNZO does not replace user-facing stablecoins. AP2 cart settlements, x402 USDC flows, Tempo stablecoin transfers, and Stripe Payment Intents all flow in their own assets. TNZO is the protocol-layer denominator that makes the rails work: gas, the network's share of a settled payment, bond, and governance vote.

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
| Chain ID | set by each network's genesis | 13380 on the preview network; `eth_chainId` returns it |
| Network-rewards pool | 400,000,000 TNZO | Genesis-funded account; rewards are transfers out of it |

Supply is fixed. Genesis allocates exactly the maximum supply: the accounts it names, including the network-rewards pool account (`tenzro_token::rewards_pool_address()`, 400M TNZO); genesis refuses a configuration whose allocations do not add up to 1,000,000,000 TNZO (`tnzo::check_genesis_supply`). There is no protocol-level mint authority beyond the genesis distribution: reward claims and vesting releases are transfers out of the pool and the vesting escrow account (see section 7), not mints. The only thing that changes total supply after genesis is burning (section 5), plus bridge mint and burn of tokens that crossed chains.

There is no transfer circuit breaker on TNZO. A node-local, wall-clock breaker would be incompatible with deterministic execution, so none exists.

Every block is held to a value rule: the balances each transaction touches change by exactly its fee plus whatever it declares it burned, and the whole block's balance changes net to its recorded supply change. A block that fails this is not committed. See [ECONOMICS.md](ECONOMICS.md#value-conservation).

### Distribution model

**There is no team allocation and no investor allocation.** Genesis funds the network-rewards pool, which pays future participants for future work, and the accounts genesis names; every genesis account and amount is public.

**The way to earn TNZO is to contribute value to the network.** This is open-ended by design. The protocol does not enumerate every legitimate path to earnings, and the list below is examples rather than a closed set — anyone finding a new way to create value for the network can earn from that activity. Representative paths include:

| Path | How value flows back as TNZO |
|---|---|
| Running a validator | Bond 10,000 TNZO and run a node that meets the resource profile (hardware, bandwidth, uptime, optional TEE attestation) to order blocks and sign checkpoints with a hardware-held consensus key. Voting power is stake-weighted; earn priority fees, leader-election rewards, and governance weight. Optional TEE attestation is a reputation signal and does not change leader selection. Only validators carry consensus weight; the service roles in the next row bond for their own rung without voting (section 7) |
| Serving compute or hardware | Bond for a service rung — model provider, TEE provider, compute provider, storage provider, rail attestor, wallet provider or catalog publisher — and earn per-call / per-token / per-service / per-attestation / per-byte fees, plus the provider class reward multiplier on staking rewards. Compute and storage bonds scale with the capacity pledged (section 7) |
| Operating an RPC provider | Run a public or gated RPC endpoint that brokers access to network resources (external chains, regulated bridge routes, KYC-tier-gated services, admin-gated cross-chain mint/burn). Admit tenants by DID in the node's access policy, broker their upstream credentials keyed by DID, expose per-tenant analytics; earn from tenant access fees, per-call fees, and commission on the underlying flow routed through your endpoint |
| Building and running apps on Tenzro | Run an application that drives transactions through the network — settlements, payments, inference billing, marketplace flows; earn from the underlying activity (provider fees, marketplace commissions, agent template invocations, AP2 / MPP / x402 settlement flow your app routes) |
| Running agents that do useful work | Deploy autonomous or delegated agents that fulfill inference requests, payment routing, cross-chain settlement, capital intent, or any other paid service; earn per fulfilled task plus reputation-driven routing share |
| Building tools, skills, and integrations | Publish MCP tools, A2A skills, agent templates, libraries, SDKs, bridges, oracle integrations, payment-rail adapters, and other ecosystem components; earn template invocation commissions and tool / skill usage fees; ecosystem grants are a separate, governance-approved program (below) |
| Data and content contributions | Contribute to skills, tools, model catalogs, training datasets, knowledge bases, reference data, or any other public resource the network consumes; earn through usage fees, or through governance-approved contribution grants (below) |
| Protocol and infrastructure work | Build the protocol itself, audit code, write core integrations, write documentation, run security research, operate public infrastructure; receive grants from the public treasury through the Tenzro Foundation's governance-approved allocation process |
| Community participation | Participate in governance votes, contribute to community channels and learning resources, file useful bug reports; work of this kind is paid only through governance-approved grants, milestone-based or retroactive, for verified work. There are no airdrops, points, referral, engagement or volume rewards |

Beyond the above, the Tenzro Foundation runs a public, governance-controlled grant program. Grants are separate from network rewards. Network rewards pay only for verified work on the network, out of the genesis-funded rewards pool (section 7). Grants come from the public treasury, never from the rewards pool, and fund work governance approves — research, ecosystem development, public-good infrastructure, regional onboarding, education, security audits, integrations, and anything else governance approves as serving the network. The grant pool sits in the public treasury (section 12); allocation is on-chain and auditable.

There are no privileged token-holder classes and no lock-ups for special parties, because there are no special parties.

### Circulating supply

Circulating supply at any point is the genesis distribution outside the rewards pool and the treasury, plus rewards paid out of the pool, minus the cumulative burn (section 5). The full supply does not enter circulation at genesis; participation-class allocations unlock as participants earn them (run a validator → earn validator rewards; serve inference → earn provider settlement; build a template → earn invocation commissions).

The treasury (the treasury part of each settlement fee, and the governed treasury leg of provider payments where governance sets one) accumulates a public, on-chain balance that governance disburses through grants and ecosystem incentives. Treasury holdings are not circulating; they enter circulation only when governance approves a specific disbursement.

### No reserved or vesting allocations

Because there is no team allocation and no investor allocation:

- There is no investor unlock cliff. There are no quarterly vesting events that release a large block of supply onto the market.
- There is no team unlock schedule. Founders, team members and other contributors who build the protocol receive grants for measurable contributions through the same governance-controlled grant program and framework available to every contributor: governance-approved disbursements from the public treasury, on terms the community can see.
- There is no early-backer carry.

The way to receive TNZO from the network is to do work it pays for.

---

## 3. Demand sources

TNZO is needed for four things, each of which grows with use of the network:

**Gas.** Every transaction on Tenzro Ledger — every EVM call, every SVM instruction, every identity operation, every governance vote, every cross-chain message — pays gas in TNZO. EIP-1559 sets a dynamic base fee that adjusts ±12.5% per block to target half the block gas limit. The governed share of the base fee is burned (100% by default) and everything else a block collects in fees, including the priority part, is credited to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%) (see section 4). No gas is paid to the block proposer.

**On-chain settlement fee.** Every settlement the chain carries out pays `fees.settlement_fee_bps` of the value it pays out (10 bps at genesis, never below the governed USD minimum), half of it burned at genesis (`fees.settlement_fee_burn_bps`) and the rest to the treasury. A payment to a bonded provider may also carry the governed treasury leg of its class of work (section 7), 0 at genesis.

**Node revenue split.** Every payment routed through Tenzro's settlement layer (inference billing, TEE service payment, agent-to-agent settlement, AP2 cart, MPP receipt, x402 verification, micropayment channel close) is divided once, by the node's economic mode: a private node keeps it, a public validating node shares 10% with the treasury, and a public node that does not validate pays 10% to the treasury and 10% to the RPC provider validating on its behalf. See [ECONOMICS.md](ECONOMICS.md).

**Bonds.** Every provider class bonds TNZO. Validators, model providers, TEE providers, storage providers, bridge nodes, marketplace agents — all bond. The bond aligns the provider with honest behavior. Misbehavior is slashed against the bond.

**Governance.** Voting weight is stake-weighted (see section 16). Proposers post a proposal bond; voters lock TNZO for the voting window.

Each source grows with usage: transactions, settlements, services and governance participation.

---

## 4. Fee architecture

Tenzro implements two tiers of fees: gas (infrastructure layer) and the network's share of a settled service payment (service layer). The two are deliberately independent because they meter different things.

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

The base fee of each block is consensus state: it is computed from the parent block's base fee and gas used when the parent settles its fees, and stored in state (`tenzro_vm::ledger::block_base_fee`). A transaction whose gas price is below the block's base fee is not executed. The node's fee quotes (`eth_gasPrice`, `eth_feeHistory`) read the value the last block stored.

Fee split, per block, from the fees actually paid:

- Every fee a transaction pays is credited to the block's fee pool as it is paid.
- **Base fee → burn.** At the end of the block, the base-fee burn dial `base_fee_burn_bps` (set only by an enacted adaptive-burn governance policy, default 10,000) of the base-fee part of what was collected is burned: removed from the pool and from total supply.
- **Everything else → treasury.** The rest of the pool, including the priority part, is credited to the treasury, less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%). Validators are paid from the rewards pool (section 7), not from tips.

Priority fee suggestions by urgency:

| Urgency | Priority fee |
|---|---|
| Low | 10% of base fee |
| Medium | 20% of base fee |
| High | 50% of base fee |
| Urgent | 100% of base fee |

### Tier 2 — Network commission

The network's share of a service payment is **not a separate fee taken on top of
the split** — it *is* the non-operator part of the split. There is one division,
made once, described in full in [ECONOMICS.md](ECONOMICS.md).

| Mode | Operator | RPC provider | Treasury |
|---|---:|---:|---:|
| Private (not advertised) | 100% | — | — |
| Public, validating | 90% | — | 10% |
| Public, not validating | 80% | 10% | 10% |

```
// The complete division. Nothing downstream takes a further cut — the
// settlement engine's own network fee is zero on this path.
treasury_amount     = (amount × treasury_bps) / 10,000
rpc_provider_amount = (amount × rpc_provider_bps) / 10,000   // delegated mode only
operator_amount     = amount − treasury_amount − rpc_provider_amount
```

The operator's share is computed by subtraction, so the shares sum to exactly
the payment and the rounding dust reaches the majority party rather than
vanishing.

Every rate is governance-settable as one `EconomicPolicy` block, and the
operator must always hold a strict majority — enforced at construction, and
enforced against governance too. Comparable take rates: traditional cloud
(5–30%), centralized payment processors (2–4%), traditional brokerages (basis
points to percent).

**Historical note.** Earlier revisions of this document described a flat 0.5%
commission re-split 40% treasury / 30% burn / 30% stakers. That re-split was
never wired to any live path, and the rate actually charged on inference was
5%. Both are gone: there is now one division, and it is the one in the table
above.

### Why two tiers

Gas fees self-regulate via EIP-1559 to track infrastructure demand. Commission fees track service-layer activity. The two grow independently:

- A network running heavy DeFi but no inference burns gas heavily but accrues little commission.
- A network running heavy inference but no on-chain trades accrues heavy commission but burns less gas.
- A network running both — the steady state — does both.

The two-tier design diversifies revenue and reduces the dependence on any single demand source.

---

## 5. Burn channels and net supply

Tenzro's burn channels are demand-driven — each one tracks real usage rather
than a schedule. Net supply change is the algebraic sum:

```
Net supply change per epoch =
    − base-fee burn                     (EIP-1559 base fee, governed share, settled in-block)
    − settlement-fee burn               (fees.settlement_fee_burn_bps of each on-chain settlement fee)
    − local-fee burn                    (gas paid in a local asset; not wired in execution yet)
    − paymaster burn                    (100% of paymaster fees; not wired in execution yet)
```

Rewards are not a term: they are transfers out of the genesis-funded rewards pool, so they move supply between accounts without changing it. Supply can only fall after genesis.

The on-chain settlement fee burns its governed share: every settlement the chain
carries out pays `fees.settlement_fee_bps` of the value it pays out (10 bps at
genesis) and burns `fees.settlement_fee_burn_bps` of that fee (half at
genesis); the rest goes to the treasury. Each settling transaction declares
what it burns, and the block value rule checks it.

The node revenue split is not a burn channel. A service payment a node collects
is divided once between the operator, the treasury and, where the node does not
validate, the RPC provider validating on its behalf; nothing in that division is
destroyed. Nor are the per-class treasury legs: they accumulate in the treasury
as a balance governance can disburse.

### Base-fee burn

Every block burns the governed share of the base fee it collected: `base_fee_burn_bps` × Σ `min(gas_price, base_fee) × gas_used` over its transactions. The default share is 100%. The base fee tracks network congestion: more activity, more burn.

The movement happens inside block execution, in consensus state (`tenzro_vm::ledger`):

1. Each transaction's fee (`gas_price × gas_used`, charged whether it succeeds or reverts) is credited to the block's fee pool account as it is paid.
2. At the end of the block the pool is emptied: the burn share is removed from the pool and from total supply, the rest is credited to the treasury, and the next block's base fee is written to state.
3. The block is then checked: the net change across every balance it wrote must equal the supply change it recorded. A block that fails is refused.

Because the figures come from the fees actually paid, and are applied by every node while executing the same block, the treasury balance and total supply cannot drift from what payers were charged or between nodes. Earlier revisions derived the split from a node-local fee-market counter that re-anchored on every restart; that path is gone.

### Local-fee burn

Gas paid in a local asset rather than TNZO burns under its own governance dial
(`local_fee_burn_bps`, genesis 100%). It is adjusted only by explicit governance
proposal, never by the auto-adjuster, so a route that lets callers pay in a
non-TNZO asset cannot quietly stop consuming supply.

### Paymaster burn

ERC-4337 paymasters can sponsor user gas. Tenzro paymasters burn 100% of the paymaster fee. This is structurally fixed (the paymaster burn fraction is locked at 100% so that sponsored gas cannot move TNZO without paying for it).

### Combined dynamics

Total supply is fixed and only falls. How circulating supply moves in any given epoch is a function of network usage:

- **Low-activity epoch.** Base-fee burn is small; rewards pay out of the pool; total supply is nearly flat and circulating supply grows by what the pool paid.
- **High-activity epoch.** Sustained congestion drives the base fee up through the ±12.5% adjustment; burn accelerates, and total supply falls.

Total supply never rises after genesis. Provider and ecosystem payouts are additionally pegged to the verified service revenue they settled (section 7), so the pool pays out in proportion to paid-for service, while burn tracks paid-for block space.

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
- `AlarmHighInflation(bps)` — circulating supply growing faster than the alarm threshold (pool payouts outpacing burn; total supply still never rises); fast-track adjustment
- `AlarmHighDeflation(bps)` — net supply below the alarm threshold; fast-track adjustment
- `Disabled` — adaptive burn is off; no recommendation

Magnitude is bounded by the configured caps. The engine only recommends. Every validator runs the auto-proposal generator: when the recommendation clears the minimum magnitude it drafts an `AdaptiveBurnConfigUpdate` governance proposal (on the expedited track for an alarm, debounced so proposals do not overlap) and submits it from the validator's own account. Nothing changes until the network votes it through. Once enacted, the policy record in consensus state is the only input block execution reads for the burn share: at the end of every block the fee settlement (the EIP-1559-style base-fee market) burns `base_fee_burn_bps` of the base-fee revenue and credits the rest to the treasury. There is no second parameter that sets it.

### Why this matters

A fixed burn fraction works well at one usage band. As the network grows, the burn rate that produces sustainable net supply changes. The adaptive dial lets the protocol respond to actual on-chain conditions rather than guessing the right fraction at launch.

---

## 7. Consensus, staking, and service roles

Tenzro decouples **consensus weight** from **service capacity**. Block finality is produced by a staked validator set running DAG consensus with stake-weighted checkpoint certificates. Serving intelligence, security, compute, storage, and hosted services is a separate set of roles that earn through proof-of-service. Every role bonds TNZO, but only validators carry finality weight and governance weight. A single operator can do both: bond to validate *and* bond to serve capacity, earning on both tracks at once.

Bonding is what puts a participant at risk for the work it claims to do, so it is universal across the ladder — nine rungs, each with its own bond sized to the trust surface it opens. Bonding is never free: a role that pledges no capacity still posts the floor for its rung. What differs between rungs is the size of the bond and what misbehavior costs, not whether a bond exists. Nothing about bonding requires a TEE, and nothing about a TEE substitutes for a bond.

### The stake ladder

| Role | Bond | Scales with |
|---|---|---|
| RPC operator | 100,000 TNZO | — |
| Rail attestor | 100,000 TNZO | — |
| Validator | 10,000 TNZO | — |
| TEE provider | 10,000 TNZO | — |
| Model provider | 1,000 TNZO | — |
| Wallet provider | 1,000 TNZO | — (declares its passkey domain) |
| Catalog publisher | 1,000 TNZO | — |
| Compute provider | 500 TNZO floor | Accelerators pledged |
| Storage provider | 100 TNZO floor | Terabytes pledged |

A **wallet provider** bonds for the relying-party domain its passkeys are bound to. Validators fetch `https://<domain>/.well-known/tenzro-provider` each probe round and attest whether it names the bonding account; a frozen verdict that it does marks the domain as served by a staked provider, and an unavailable verdict takes the SLA penalty from the bond. Wallets from unbonded domains still work; they are only not shown as staked.

The RPC operator carries the largest bond on the ladder because it holds the largest trust surface: it admits tenants to its node by DID, brokers upstream chain access under its own credentials, and fronts gated resources for parties that never touch the protocol directly. The RPC bond subsumes the validator bond: an RPC operator is a validator that additionally serves public RPC.

Below the ladder sits unbonded participation. A node can join, sync, gossip, relay, and run consensus without posting anything, because it claims no work and takes no counterparty risk. Its quorum weight is its own bond, so bonding nothing contributes nothing to a quorum; it gets no governance vote and has no slashing exposure, since there is no bond to slash. That is what keeps admission open without making influence free.

**Compute providers** bond per card, at 1,000 TNZO scaled by the accelerator class: integrated 500, consumer 1,000, workstation 2,000, datacentre 5,000. A provider pledging one datacentre card and one consumer card bonds 6,000 TNZO. The floor is 500 TNZO.

**Storage providers** bond 100 TNZO per whole terabyte pledged, floored at 100 TNZO.


The ladder is defined in `tenzro-types/src/constants.rs` and applied by `NetworkRole::required_stake`; the bond itself is a `Stake` transaction per account per role, held in consensus. Every bond figure is governance-adjustable.

**A new bond keeps its USD value.** A new or raised bond, and a validator joining the set, must meet each amount above raised in proportion when TNZO trades below `stake.bond_floor_rate_nano_usd` (0.10 USD at genesis), valued at the safety rate (the lower of the fee rate and the lowest median of the last day). After a 95% fall, entering costs twenty times the TNZO, so a crash does not make Sybil entry cheap; a rise never lowers the amounts. Bonds already in place keep serving at the TNZO amounts. `tenzro_getRoleStakes` reports both as `required` and `entry_required`.

### Consensus is stake-weighted

The validator set orders and certifies blocks. Bonded stake is apportioned into integer seats (1,000 by default, largest remainder, no one-seat floor), and every threshold is counted in seats: `n` seats, `f = (n - 1) / 3`, quorum `n - f`. To prevent any single validator from dominating, per-validator weight is capped at 10% with the excess redistributed proportionally across the remaining set before seats are apportioned. The Byzantine fault bound `f` is measured as a **fraction of stake**, not a head-count of nodes, and all threshold math is integer to avoid floating-point edge cases.

A consequence of stake-weighting: a node with zero stake carries zero finality weight. There is no head-count vote to capture — adding unstaked nodes cannot move a quorum. This is what makes open service participation safe alongside a bonded consensus set.

Validators sign checkpoints with a hardware-held composite ML-DSA-65 + P-256 key, propose a vertex every round, and are exposed to slashing:

- **Stake requirement.** Bonded TNZO above the governance-set minimum.
- **Slashing exposure.** Checkpoint equivocation costs three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it, at least 5% (15% for a validator that has offended before) and at most the whole stake, paid into the insurance pool; additional slashing on invalid TEE attestations, or persistent SLA failures.
- **Leader election** across every block class, including the highest-trust classes (large-value institutional settlement).
- **Governance weight**, stake-weighted (section 16).
- **High-trust role eligibility:** high-value bridge duties (Hyperlane Tenzro-set ISM, Wormhole Guardian-quorum when configured, a seat on a bridge route committee drawn from bonded attestors); AP2 high-value mandate validation.

**TEE is an optional capability, not a gate.** Hardware attestation through any supported vendor (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU CC, Intel Tiber) is a reputation signal. It never changes the leader-selection draw, which is seats times observed behavior only.

### Service roles are bonded but carry no consensus weight

Service providers bond for their rung and earn through proof-of-service. They do not vote in consensus and do not finalize blocks:

- **Admission is permissionless but bonded.** Registration requires an active bond at or above the rung's requirement. There is no allowlist and no operator approval step — post the bond, meet the resource profile, and serve.
- **Admission profile.** Hardware thresholds (CPU, memory, disk, bandwidth, storage IOPS) checked at registration, continuous monitoring during operation, and a stability/uptime probation window. The protocol favors operators that add geographic, ISP, or jurisdictional diversity.
- **Earnings.** Pay-per-use inference fees, time-based rental revenue, and storage/bandwidth fees, settled per the mechanisms in section 9. A reputation-weighted reward share scales with uptime, successful service, and the provider-class and TEE-capability multipliers.
- **Bond at risk.** A misbehaving provider loses reputation, is ejected from the serving set, and is exposed to slashing against its bond (every serving role's `Stake` bond is probed under `did:tenzro:role:<role>:<account hex>`, and an unavailable SLA verdict takes the governed penalty from it into the insurance pool) — invalid TEE attestations, upheld inference-verification challenges, and persistent SLA failure all cut into it. Payers are additionally protected by escrow and streaming settlement (section 9), so the bond backs correctness while escrow backs delivery.
- **Capacity and bond move together.** A compute or storage provider that grows its pledged capacity raises its bond to match. Serving beyond what the bond covers is not admissible.

The clean line: **finality weight lives with validators; service capacity lives with bonded providers; escrow bridges the trust gap for paid service.**

### Parameters

| Parameter | Value | Source |
|---|---|---|
| RPC operator bond | 100,000 TNZO | `tenzro-types/constants.rs` |
| Validator bond | 10,000 TNZO | `tenzro-types/constants.rs` |
| TEE provider bond | 10,000 TNZO | `tenzro-types/constants.rs` |
| Model provider / wallet provider bond | 1,000 TNZO | `tenzro-types/constants.rs` |
| Compute provider bond | 1,000 TNZO per accelerator × class multiplier (0.5× integrated, 1× consumer, 2× workstation, 5× datacentre), 500 TNZO floor | `tenzro-types/constants.rs` |
| Storage provider bond | 100 TNZO per terabyte, 100 TNZO floor | `tenzro-types/constants.rs` |
| Compute bond minimum | 100 TNZO at genesis, `compute_bond.min_tnzo` | `tenzro-vm/native/mod.rs` |
| Validator unbonding period | 7 days: `ExitValidator` moves the bond to unbonding (no longer stake, still slashable); a second `ExitValidator` after 7 days pays it out | `tenzro-vm/native/staking.rs` |
| Reward model | Work-gated coupons on a declining annual schedule, paid from the genesis rewards pool; provider and ecosystem buckets capped at `revenue_peg_bps` (default and most 10,000) of the work weight they recorded, each settlement's weight at most a share of the fee it paid outside the trade | `tenzro-token/rewards.rs` |
| Epoch duration | 14,400 blocks (~1 day at 6-second block target) | `tenzro-token/rewards.rs` |
| Epochs per year | 365 | |
| Reward claim liquid fraction | `liquid_bps` (remainder opens 12-month reward vesting) | `tenzro-token/rewards.rs` |
| Equivocation slash | `min(100%, max(5%, 3 × correlated bonded share))` of bonded and unbonding stake, 15% floor for a repeat offender, correlation window 16 checkpoints, earlier offenders topped up; applied in-block by the evidence transaction, into the insurance pool | `tenzro-types/constants.rs`, `tenzro-vm/native/staking.rs` |
| Consensus quorum threshold | `n - f` of `n` seats, `f = (n - 1) / 3` | `tenzro-consensus/committee.rs` |
| Per-validator weight cap | 10% of active set, excess redistributed proportionally | `tenzro-consensus` |
| Service-provider reward share | Reputation-weighted, proof-of-service | Governance-set |

Every bond on the ladder, the unbonding period, resource profile thresholds, quorum/cap parameters, and reward shares are governance-adjustable.

### Reward calculation

Rewards are **work-gated**: an epoch's payout rights are earned by verified work done in that epoch, not by holding stake. Every payout is a transfer out of the genesis-funded rewards pool; nothing is minted. There is no stake-proportional payout. Nothing a participant self-reports can create reward-eligible work — every unit of work weight is measured by the protocol (finalized blocks and quorum-certificate participation for validators, metered proof-of-service for providers, on-chain-recorded contribution acceptance for the ecosystem bucket).

The engine (`tenzro-token/rewards.rs`) closes each epoch by issuing **reward coupons** rather than paying balances directly:

```
For each closed epoch:
    year          = year_for(epoch)
    annual_rights = declining_annual_schedule(year)       // fixed release from the pool, no minting
    epoch_rights  = annual_rights / epochs_per_year       // one year of block time / genesis epoch length
    (val_bps, prov_bps, eco_bps) = role_split_for(year)   // shifts infra → apps over years

    For each role bucket (Validator, Provider, Ecosystem):
        share         = epoch_rights × bucket_bps / 10,000
        bucket_rights = share                                        // Validator
        bucket_rights = min(share, bucket_work_weight × revenue_peg_bps / 10,000)
                                                                     // Provider, Ecosystem
        For each address with verified work in the bucket:
            work_share = address_work_weight / bucket_total_work_weight
            coupon     = bucket_rights × work_share        // an unclaimed payout right
```

Provider and ecosystem work weight is each settlement's own reward ceiling, so the peg means a bucket pays out at most `revenue_peg_bps` (at most 10,000) of it: a provider with little paid work earns little, whatever the calendar allows.

What a settlement may earn is bounded by what it paid **outside the trade**: the TNZO protocol fee (burned, and paid to the treasury and the insurance pool) plus the treasury leg of its provider class, where governance sets one (`fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps`, 0 at genesis, taken from the provider's credit so the buyer's price is unchanged). Out of that outside cost:

| Share | Parameter (genesis) | Paid to |
|---|---|---|
| Provider weight | `mint.provider_reward_cost_bps` (4,000), and never above what the provider was paid | The payee, when its bond or stake makes the payment provider work |
| Activity weight | `fees.activity_reward_fee_bps` (5,000), split evenly | The apps, agents and tools the payer attributed the settlement to, never the payee |
| Creator royalty | `fees.creator_royalty_fee_bps` (0), paid in TNZO out of the treasury part of the fee and leg | The same attributed creators |

Governance keeps the three together at or below 9,000 bps (`MAX_SETTLEMENT_REWARD_BPS`), so every settlement leaves at least a tenth of its outside cost with parties outside it. Nothing is earned by a party that shares an identity root with the payer or the payee (roots are followed through agent controllers), or when the payer or payee is unregistered. Issuance out of the pool is tied to metered, paid service; burn is tied to paid block space (section 5).

**Why self-dealing loses.** Let one settlement move value `V`, pay fee `F` and treasury leg `L`, so the outside cost is `C = F + L`. A coupon never exceeds the weight it was matched to, and the buckets pay at most their recorded weight, so the most the parties can receive back is `(p + a + r)·C` with `p + a + r ≤ 0.9`. A payer, provider and creator acting together (one root, or any number of colluding roots) therefore end at least `0.1·C` poorer per settlement, before gas and before the 75% of each claim that vests over twelve months. At the genesis rate (10 bps fee, no leg) that is at least 1 bp of the value moved. Both sides of the inequality are TNZO amounts recorded by the same settlement, so it holds whatever TNZO trades at and whatever rate the fee oracle holds; the oracle only sets the least fee, which is charged in TNZO before any weight is computed.

**Provider classes.** Provider work is recorded per class, all in the provider bucket and paid pro rata to weight, so a unit of outside cost earns the same whatever the class:

| Class | Recorded when | Backed by |
|---|---|---|
| `InferenceServed` | A plan's payee reports it (`ReportSettledWork`); a voucher, x402 payment or escrow release paid to the account that posted a compute bond | The settlement plan or the escrow; the compute bond |
| `TeeSession` | The same payments (or a reported plan) to an account with a bonded TEE provider stake | The TEE provider stake |
| `RpcTraffic` | The same payments (or a reported plan) to an account with a bonded RPC operator stake | The RPC operator stake |
| `ComputeLease` | A stream claim paid to the account that posted the compute bond; an hour of a compute claim judged available | The compute bond and its frozen SLA verdict |
| `StorageServed` | An hour of a storage claim judged available, which needs a possession proof of the stored object | The bond or storage stake and its frozen SLA verdict |

Compute and storage claim hours pay the settlement fee like every other on-chain settlement. A payment to an account that holds none of these bonds earns no provider weight.

**Call-chain attribution.** A settlement plan (`PlanOp::Open.attribution`) and an escrow voucher (`EscrowVoucher.attribution`) may name up to three hops of the call chain that led to the payment: `app_did`, `agent_did` and `tool_did`. Each must be a registered, unrevoked identity, or the plan or voucher is refused. The payer's signature covers the attribution (a voucher signs its usual preimage followed by the attribution's bytes), so a payee cannot attribute a payment to itself or to a party of its choosing.

A coupon is a bounded, per-address right to be paid from the pool, not a balance. Rights left unmatched (a bucket with capacity because insufficient verified work or revenue was recorded) and coupons unclaimed within the claim window **lapse and stay in the pool**. Tokens leave the pool only for work that was both done and claimed.

### Declining schedule and role split

Annual payout rights decline year over year on a fixed schedule over the fixed pool; the network never runs an open-ended emission. A controller scales the schedule between `mint.min_mult_bps` (0.5x) and `mint.max_mult_bps` (1x): it never issues more than the schedule. It moves at most `mint.adj_bps_per_year` (25% of 1x) a year against the **security ratio** (section 15b): up while slashable stake covers less than `security.min_ratio_bps` of what one attack can take out over the bridges, down once it covers more. Within each year, the role split (`role_split_for_year`) shifts weight from infrastructure buckets (validator, provider) toward the ecosystem bucket over time, so that as the base layer matures, a growing share of payout rights flows to application and tooling contributions rather than raw capacity.

### Role buckets and what counts as work

| Bucket | Work weight is | Measured by |
|---|---|---|
| Validator | Finalized-block participation and quorum-certificate signing | Consensus records — no self-report |
| Provider | Settled provider work: inference, TEE sessions, RPC traffic, compute leases, storage served | Settlements paid to a bonded provider, each weighted by the outside cost it paid |
| Ecosystem | Settled usage attributed to registered apps, agents and tools | The payer-signed attribution on a plan or voucher, weighted by the outside cost it paid |

The ecosystem bucket is how TNZO rewards flow to apps, agents and tools: the settlements their users pay for and attribute to them record ecosystem work weight for the attributed creators, which then earns coupons in that epoch's ecosystem bucket. Contributions the network funds outside settled usage go through treasury grants (section 12), not this bucket. This keeps "earn TNZO by building" on the same work-gated rail as validation and service, with no path for self-reported work to mint.

### Claiming, vesting, and quality of service

Reward accounting is consensus state: every finalized block credits its proposer and closes the epochs before its own, so every node derives the same coupons from the same chain. Providers record settled fees with a `report_settled_work` funding transaction citing the leg receipts of committed settlement plans that credited them and that another party paid, each plan counted once at its provider weight. Claiming a coupon (a `claim_rewards` funding transaction, signed by the earner) splits the payout: a liquid fraction (`liquid_bps`) is transferred from the rewards pool immediately, and the remainder moves from the pool into the vesting escrow account under a **12-month linear reward-vesting schedule** (no cliff); a `release_vesting` funding transaction pays vested amounts out of that escrow. This aligns rewarded participants with the network over a year rather than paying fully liquid up front. Provider and validator work weight is itself quality-scaled — uptime and reputation reduce the measured work weight before coupons are issued, so a low-availability operator earns proportionally fewer rights.

### Slashing

Every slash is a consensus transaction, and every slashed TNZO goes to the network insurance pool, which pays harmed parties on evidence held in chain state.

Equivocation is signing two different checkpoints with one index; every validator detects it among the checkpoint votes it collects, and anyone can find it in two conflicting certificates. The on-chain penalty is applied by a `ReportCheckpointEquivocation` transaction carrying both signed checkpoints: the VM verifies them against the validator's registered composite key and slashes three times the share of bonded stake held by every validator that equivocated within 16 checkpoints of it, at least 5% (15% for a validator that has offended before) and at most the whole stake of its bonded and unbonding stake from the staking vault into the insurance pool in that block. The penalty is proportional to the stake that equivocated together: an isolated fault, usually a misconfigured failover, costs 5%, while a third of bonded stake equivocating at once, the threshold an attack on finality needs, costs every one of them everything. When a later offence in the window raises the rate, earlier offenders are topped up to it, so the outcome does not depend on the order the evidence lands in. Because an exiting validator's bond sits in unbonding for 7 days, still in the vault, exiting does not escape a slash for an offence found in that window.

Other slashable conditions, each through its own consensus evidence:

- **Unavailability** — validators probe providers and attest each epoch's outcome (`SlaAttest`); once two thirds of bonded stake have attested, a verdict that the provider was unavailable takes the governed `sla.unavailable.penalty_gwei` from its compute bond. A renter whose stream paid that provider for the epoch claims the epoch's accrual from the pool with the verdict as evidence.
- **Inference faults** — an upheld `InferenceFault` refunds the requester from the provider's compute bond and takes a penalty of `inference.optimistic.penalty_payment_bps` of what the requester paid (default 20x), at least `inference.optimistic.penalty_floor_micro_usd` (default 10 cents) in TNZO at the rate in force. Governance holds the multiple at or above the inverse of the least sampling share, so a substituted answer loses more in expectation than it saves, whatever the TNZO price.
- **Training faults** — a trainer commits a signed receipt for each round (`TrainingProof`: starting checkpoint, shard commitment, hyperparameters, step count, resulting checkpoint and step log, bound to the round's milestone escrow). Anyone may challenge it within `training.challenge_window_ms` (the shorter `training.tee_challenge_window_ms` when the receipt carries an accepted TEE attestation) by posting `training.challenge_bond_gwei`. Validators replay `training.sample_steps` steps drawn from the randomness beacon, the first and last always among them, and compare within `training.tolerance_ppm`. Upheld by two thirds of bonded stake, the trainer's compute bond pays `training.challenger_reward_gwei` to the challenger and `training.penalty_gwei` to the insurance pool, the milestone returns to its payer, and the challenger's bond comes back less `training.challenge_fee_bps`. A dismissed challenge's bond, less the fee, goes to the trainer. The milestone is released only after the window closes with no challenge pending and none upheld.
- **Policy violations** — a receipt contradicting the operator's own published policy, once validators holding two thirds of bonded stake have proved it (`AgentAuditFlag` with a `PolicyViolation` finding), takes the governed penalty from the operator's compute bond.
- **Agent faults** — validator-verified quarantines and the controller's own `TerminateAgent` slash the agent bond. A paused or quarantined agent's bond is frozen: it cannot be withdrawn until the pause ends or the quarantine is lifted.

### Redistributing, not burning

Slashed TNZO funds the insurance pool rather than being burned, so a slash compensates the parties a fault harmed. Surviving validators and the reporter do not receive it, which keeps the moral-hazard incentive to encourage slashing events out. The pool pays only on evidence chain state already holds (below), capped by the governed `insurance.max_claim_bps` and `insurance.max_claim_tnzo`; governance sets those parameters and the pool's fee share, and nobody holds a key to the pool. A slash changes no supply: it moves TNZO from the staking vault to the pool.

---

## 8. Bonded stake is not tokenized

There is no liquid staking token. A bond lives in consensus state, per role, under the bonding account: it is added with a signed `Stake` transaction, earns through the work it backs, is slashed into the insurance pool, and leaves only after the governed unbonding window. A bond cannot be transferred or wrapped while it secures the network.

## 9. Provider economies

Tenzro has multiple provider classes, each with its own micro-economy.

### Model providers

A model provider:

- Stakes TNZO (min stake configurable; see section 7).
- Registers in the model registry with one or more model identifiers, modalities, and pricing.
- Serves inference requests routed by the inference router (price, latency, reputation, or weighted strategy).
- Earns in either of two billing modes (see "Capacity rental and reservation" below): **pay-per-use** (per call or per token, the unit depends on modality) for on-demand consumption, or **time-based rental** (a stream escrow to the provider, paid per epoch) when a consumer reserves dedicated capacity.
- Is rate-limited by their reputation score (250–1000 range).

Reputation is asymmetric: success on settled payment increments reputation by +1 (capped at 1,000); failure decrements by -5 (floored at 0). The split between "successful HTTP 200" and "settled payment" matters: HTTP 200 alone updates latency only. Reputation gain is gated to settled-payment-only so providers cannot game reputation without taking a real payment.

Reputation is durable. RocksDB persists per-provider reputation; restarts do not reset it.

### TEE providers

A TEE provider:

- Stakes TNZO (min stake configurable).
- Registers as a TEE provider with vendor (TDX / SEV-SNP / Nitro / NVIDIA GPU / Intel Tiber) and supported services.
- Generates attestations on demand for confidential inference, sealed key custody, or other confidential workloads.
- Earns per attestation or per service-second.
- Earns provider reward coupons in proportion to the settled TEE-session fees it is paid, on the same terms as every other provider. There is no TEE-specific reward multiplier, and nothing is paid on stake.

### Validators

A validator:

- Stakes TNZO (min stake configurable).
- Joins the validator set through the epoch admission process: with bonded stake it joins at the next epoch, and while `validator.admission_approval` is 1 (as during the preview) only from an account an enacted `ApproveValidators` proposal named.
- Participates in consensus: proposes vertices and signs checkpoints with its hardware key.
- Earns reward coupons for the consensus work actually performed, and a base reward while it records consensus work (section 18.2). Priority fees go to the treasury, not to the proposer (section 4).

### How a settled service payment divides

One payment funds the party that did the work and the network that made it
findable and settleable. How it divides follows from what the node actually
does — there is no setting an operator can change to be paid more.

| Mode | Condition | Operator | RPC provider | Treasury |
|---|---|---:|---:|---:|
| Private | The node's visibility is `private` | 100% | — | — |
| Public, validating | Advertised, and the node validates | 90% | — | 10% |
| Public, delegated | Advertised, and the node does not validate | 80% | 10% | 10% |

**A private node keeps the payment.** It is connected to the network but not
advertising itself; its resources are reached as the operator's access policy
admits. Nobody discovered it and no validator was engaged on the
caller's behalf, so there is no network share to take. Ledger gas is still owed
on any transaction it settles — a separate stream, not a commission.

**The RPC provider's leg pays for validation, not for brokerage.** A node that
advertises but does not validate still needs its users' transactions validated,
and whoever does that work is owed for it. The difference between the two public
schedules is exactly that leg. A node in this mode that cannot name its RPC
provider is refused at settlement rather than having that share quietly
redirected.

Separately, an RPC provider selling access to **external networks they broker**
(chains beyond Tenzro) bills their own tenants on their own
terms, the way every other chain's RPC operators do. That revenue never touches
this split — charging in both places would be charging twice for two different
things.

The operator's majority is enforced at construction, not merely documented, and
the shares sum to exactly the payment with rounding dust going to the operator
by subtraction rather than a further multiplication.

The treasury account is derived (`SHA-256("tenzro/treasury")`), keyless, and spent only by governance; the payee is configuration rather than a constant.

### Storage providers

A storage provider:

- Stakes TNZO.
- Serves snapshot / DA / blob requests.
- Earns through DA pricing and snapshot-bootstrap fees.

### Media providers

A provider serving media models earns like any other AI provider: each render is metered in pixel-steps (`width × height × steps × frames`, with duration, voxel and world-model equivalents) against its rate card, and pays the same network share on earnings, per the node's economic mode. A node loads only catalog models whose licence terms the operator accepted.

### Marketplace template creators

A creator who publishes an agent template is paid by whoever invokes it, at the price the creator sets. When the payer attributes the payment to the template's agent or tool DID, the creator also earns that settlement's activity weight and any creator royalty (section 7). There is no marketplace commission on top, and no on-chain path that settles a creator share to a template's `creator_wallet` by itself: a creator share is a line of the payment's split rule, set by the payer and payee.

### Skill and tool creators

Skill and tool authors register entries in the skill / tool registries. Discovery is permissionless; usage is settled through the same micropayment substrate.

### Capacity rental and reservation

A consumer can reach a provider's capacity two ways. **Pay-per-use** meters consumption after the fact (above). **Time-based rental** reserves capacity for a term: a rental is a stream escrow to the provider's bonded address, paid per epoch while the validators find the provider available (see [COMPUTE.md](COMPUTE.md)).

- **Matching.** Renter and provider agree a price for the term wherever they meet: directly, or in any market built on the network's public interfaces.
- **Settlement streams.** The renter opens a stream escrow with `CreateEscrow` to the provider's bonded address, locking the price as a stream accruing `ceil(price / epochs)` per one-hour market epoch until the deadline. The provider draws what has accrued with `ClaimEscrowStream`; either side stops it with `RefundEscrow`, which pays the accrued part and returns the rest. Neither side is ever exposed for more than one epoch. A stream escrow opens only as a rental award.
- **SLA, not self-report.** Validators probe every bonded provider and freeze a verdict per epoch once two thirds of bonded stake agree. An unavailable verdict slashes the provider's compute bond (`sla.unavailable.penalty_gwei`) into the insurance pool, and the renter's stream never pays for that epoch: it stays with the renter, so there is no loss to claim, and one party on both sides of a stream gains nothing. The provider's compute bond is the rental's collateral; there is no per-rental bond.
- **Settlement fee.** Each stream draw divides by the node's economic mode like any settled payment (§4).

---

## 10. Bonds and slashing

Every provider class carries a bond. The bond size is proportional to the economic damage the provider could cause if they misbehave.

| Class | Bond size guideline | Slashing event |
|---|---|---|
| Validator stake | Min 10,000 TNZO (governance-set, `stake.validator_tnzo`) | Equivocation: correlation-scaled, 5% to 100%, into the insurance pool |
| Model provider | Stake + AgentBond (per agent) | Persistent inference failure: reputation collapse + bond withholding; unavailable SLA epoch: compute-bond slash into the insurance pool, which pays the renter that epoch (§9, *Capacity rental and reservation*) |
| TEE provider | Stake | Forged attestation: bond slash |
| Bridge node | Per-bridge configurable | Quorum dishonesty: bond slash |
| Agent (marketplace) | AgentBond | Kill-switch termination, validator finding: slash into the insurance pool |

### AgentBond and the insurance pool

Agents post AgentBonds. Every slash of an agent bond goes into the network insurance pool: a kill-switch termination, a validator finding that quarantines the agent (the whole bond), and the penalty an upheld inference fault takes from a provider's compute bond. The pool also takes `fees.insurance_pool_bps` of the fee revenue bound for the treasury, from block fees and from settlement fees.

The pool pays a claim (`PayInsuranceClaim`) only on evidence chain state already holds of a loss a bonded party caused, to the party the evidence names, once per evidence:

- a frozen SLA verdict that judged a provider unavailable in an epoch the claimant's streaming escrow paid it for;
- a reconciliation mismatch of an attested route's settlement lock that cost the claimant a leg's value (a release without the plan's commit costs its payer, a refund after it costs its payee). The reconciliation that stores it slashes `settlement.attestor_slash_bps` of the attestor stake of every member of the route's committees into the pool (see SETTLING_ACROSS_NETWORKS, Reconciliation).

A metered-charge dispute is repaid from the meter's bond alone, up to what the payer provably settled above what the meter could charge: a meter and its payer can be one party, so the pool never covers a meter. A payer should not let a meter charge more than its bond covers.

A claim pays the proven loss, capped at `insurance.max_claim_bps` of the pool and `insurance.max_claim_tnzo`. There is no claim filing, adjudication vote or approval step: the verified evidence on chain is the adjudication. Reads: `tenzro_getInsurancePoolBalance`, `tenzro_listInsuranceClaims`, `tenzro_getInsuranceClaim`.

---

## 11. Bridge fee model

Cross-chain settlement has direct costs (gas on the source chain, fees on the destination chain, oracle/relayer compensation) and protocol-layer costs (the bridge router, fee oracle, monitor).

### Fee structure per route

For each bridge adapter, the fee is the sum of:

- **Source-chain gas** — paid in the source chain's native asset.
- **Destination-chain gas** — paid by the relayer/keeper.
- **Adapter-specific fee** — LayerZero DVN fee, CCIP fee, deBridge order fee, Wormhole relayer fee, etc.
- **Tenzro protocol fee** — a configurable basis-point fee on the routed amount.

The protocol fee routes to the treasury leg of the standard revenue split (see [ECONOMICS.md](ECONOMICS.md)).

### Fee quoting

All adapters expose live fee quoting via the unified `BridgeRouter`. Callers request quotes for a desired route and receive a fresh quote per adapter, with the protocol fee already factored in. Quotes have a TTL; stale quotes are rejected.

### Fee sponsorship pools

Operators can contribute to bridge-fee sponsorship pools that subsidize cross-chain settlements for end users and agents on configured routes. Sponsorship pools are funded by:

- Operator contributions in TNZO.
- A configurable cut of the treasury leg accrued on subsidized routes (capped to prevent runaway sponsorship).
- Treasury grants approved by governance.

Eligible flows draw automatically from the sponsorship pool when invoked through the standard bridge router. Sponsorship is logged on-chain and exposed via analytics.

### Fee oracle

A per-adapter fee oracle tracks recent fee observations and feeds the router with reasonable defaults when live quoting is unavailable (network partition, adapter outage). The oracle is also used by the adaptive burn dial input layer when estimating bridge-related supply impacts.

---

## 12. Treasury

The Tenzro Network Treasury accumulates the treasury leg of every settlement split, plus governance-approved transfers, plus genesis-allocated treasury holdings. The treasury is on-chain and every outflow is approved through governance.

### Inflows

- **Settlement fee share** — the part of each on-chain settlement fee that is not burned (half at genesis).
- **Treasury legs** — the governed per-class treasury leg of provider payments (`fees.treasury_leg_{inference,tee,rpc,compute,storage}_bps`, 0 at genesis, at most 5,000 bps each), less any creator royalty paid out of it.
- **Node revenue split share** — the treasury part of a service payment a public node divides (section 9).
- **Block fees** — the block fees that are not burned.
- **Bridge protocol fees** — share of cross-chain settlement protocol fees.
- Each inflow above goes to the treasury less the insurance pool's governed share (`fees.insurance_pool_bps`). There is no marketplace commission.
- **Slashing recovery** — none: slashed bond goes to the insurance pool, not the treasury. The treasury does not benefit from slashing events.
- **Governance-directed transfers** — explicit grants or reallocations.

### Outflows

Approved through governance. Categories include:

- Protocol development grants (audits, core engineering, research)
- Ecosystem incentives (developer grants, bug bounties)
- Infrastructure (test environments, monitoring, on-call)
- Insurance fund seed and replenishment
- Bridge fee sponsorship pool contributions
- Operational costs (legal, compliance)
- Network duties, such as settlement reconciliation each epoch (see section 15)

### On-chain transparency

All treasury inflows and outflows are on-chain and queryable. The treasury is keyless: its address is derived as SHA-256 of `tenzro/treasury`, and no key, administrator or multisig can withdraw from it. Funds move only through an enacted governance proposal, after its timelock. Audit trail is permanent.

---

## 13. Bootstrap activity

The network is bootstrapped: its first operators run it until it is stable, and decentralization opens at measured milestones (security of the bonded stake, independence of operators, uptime), never on a date. The network opens as a preview, then a testnet, then the stages governance decides on the way to mainnet; each step and each lift of a launch limit is an enacted governance proposal. During the preview a new validator registers only from an account an enacted `ApproveValidators` proposal named (`validator.admission_approval` = 1).

Bootstrap demand is held to the same rules as any other. Usage brought by the operators' own projects or related parties pays the normal tariff and fees, earns no extra rewards (payer and payee on one root earn nothing; other groups are held to the outside-cost bound of section 7), and is reported apart from unrelated demand, never as organic growth.

The protocol keeps no bootstrap allocation, earmark or protocol-owned agent registry. Agent templates that exercise inference, settlement, bridges and the other surfaces live in a harness over the public surface. The agents they run are ordinary identities: they are funded by governed treasury grants (section 13c), act under delegation terms, and their activity is counted by the same rules as any other identity's. What bootstrap activity costs is therefore visible in the treasury's grant records and stops when governance stops granting.

---

## 13c. Grants and funding proposals

The treasury is spent only by on-chain governance, and anyone can ask.

- **Requests with a zero balance.** Any registered identity (a person's passkey DID, an agent acting under its delegation, or a machine's hardware-derived DID) files a `Funding` request whose gas the treasury pays. A request is a grant (`tenzro funding request-grant --amount <wei> --category research --link <url>`), or a tranche release. Spam is bounded by identity instead of money: one open request per root identity (an agent's requests count against its controller), `funding.requests_per_window` requests per `funding.request_window_ms` network-wide, and size limits. Bonded validators vote under the ordinary governance rules.
- **Grants in tranches.** A grant may be split into tranches that sum to its amount. The first tranche is paid when the grant enacts; each later tranche is paid only when its own release request passes, and only once. A rejected request pays nothing.

The read surface is open: `tenzro_getProposal` and `tenzro_getGrant` (`tenzro funding show ...`).
---

## 13d. Vesting

The protocol has a single vesting primitive (`tenzro-token/vesting.rs`) used wherever TNZO is committed to a future release curve rather than paid liquid. All schedules are linear after any cliff, overflow-safe over 18-decimal u128 amounts, and expose an `outstanding()` view; `release` pays out the vested-but-unreleased portion at a given time.

| Kind | Cliff | Duration | Used for |
|---|---|---|---|
| Reward | None | 12 months linear | The non-liquid fraction of a claimed reward coupon |
| Grant | None | 6 months linear | Treasury grants enacted with `vesting: grant` |
| Contributor | 12 months | 36 months linear after cliff | Treasury grants enacted with `vesting: contributor` (long-term contributors) |

Reward vesting is opened automatically at claim time (section 7) and needs no operator action. Grant and contributor schedules are opened only by an enacted `TreasuryGrant` proposal: its `vesting` field is `liquid` (paid to the recipient's balance), `grant` or `contributor`, and each tranche vests on its own schedule from when it is paid. No operator or foundation key can open one. Vesting keeps rewarded participants, funded projects, and long-term contributors aligned with the network over the release window instead of taking a fully-liquid position up front.

---

## 14. Agent-economy specific surfaces

The agentic economy has a few specific economic surfaces that do not exist in human-only systems.

### Nested-ceiling enforcement on agent payments

An agent payment passes through up to four checks, outermost first:

1. **AP2 checkout mandate** — the mandate itself (signed by the principal) declares an item set, a max amount, and optional merchant / category / chain allow-lists; the payment cannot exceed or fall outside any of them.
2. **The agent's consensus Terms** — the per-transaction cap, per-period caps, allowed operations, chains, payment protocols and counterparties, and expiry its root approved; spend is counted in consensus state.
3. **On-chain escrow** — when the mandate pair carries an `escrow_id`, the pre-locked escrow balance bounds the payment. An `escrow_id` that fails to resolve is a hard refusal, never a skip.
4. **Stripe SPT usage limits** — when the mandate pair carries a `spt_grant_id`, the granted token's `usage_limits.max_amount` and currency bound the payment. An unresolvable `spt_grant_id` is likewise a hard refusal.

Ceilings 1–3 apply to every agent payment; 4 and 5 apply when the mandate pair commits to an escrow or an SPT. Every applicable ceiling must pass — the payment is refused if any single one fails. The principal retains the right to override by signing a new mandate or through the controller's revocation surface.

### ERC-7579 on-chain custody enforcement

The on-chain twin of the delegation scope is the spending limit validator module. Smart accounts use both — the on-chain validator enforces the limit at `validateUserOp`, the off-chain runtime spending policy reinforces it before the user operation is even dispatched. Custody is enforced at signing time, not as a defensive afterthought.

### Mandate-receipt binding

Every settlement receipt can be bound to the off-chain mandate that authorized it. The `MandateRef` carries the mandate protocol (`ap2-checkout`, `ap2-payment`, `x402`, `mpp`, `stripe-spt`, `capital-intent`, `workflow-step`), the mandate hash, the issuer DID, the optional mandate URI, and the expiration. The audit loop authorization → settlement is closed: every settlement reveals which mandate authorized it.

### Capital intent fee model

Capital intent lifecycle operations (open / quote / assign / execute / verify / compensate / settle) pay gas per operation plus the network's share of the underlying settlement. There is no per-intent protocol surcharge; the system is priced on the actual flows it executes.

### Workflow fee model

Workflows pay gas per step plus a commission on the underlying value movement. Per-step compensate handlers do not pay commission on the rollback; commission is on net value transferred, not gross.

---

## 15. Network duties

A network duty is chain work that anyone may carry out. The chain holds the reward in a keyless vault, pays it to the first sender whose proof it verifies, and then closes the duty; an unpaid remainder returns to the funder when the duty expires. Duties are read with `tenzro_getDuty` and `tenzro_listDuties`.

- **Settlement reconciliation.** Each epoch the chain opens one duty for every bridge route with a settlement lock, funded by the treasury at the governed `settlement.reconciliation_reward` (1 TNZO at genesis). The duty pays whoever submits the entries the lock recorded since the last reconciliation with a proof of the lock's checkpoint. An entry that disagrees with Tenzro's plan is stored as a mismatch and disables the route.
- **Voided-grant relay.** Funded from the relay deposit of the grant, not the treasury.

The reward, like every other economic value in this document, is a governed parameter: it changes only through an enacted proposal.

---

## 15b. Economic security

On-chain value is protected by every node checking every block. What a coalition that signs conflicting histories can carry off is what leaves over the bridges before it is stopped, and that is bounded by the network-wide outflow caps (`tenzro_getBridgeOutflow`). The chain ties those caps to bonded stake in two ways, both valued at the safety rate:

- **Security ratio** = `security.attack_stake_bps` (a third) of bonded stake, divided by `security.attack_window_epochs` (a day of hourly epochs) times every effective outflow cap valued in TNZO. A proposal that raises any outflow cap, or switches the fee rate to validator mode, is refused unless the ratio stays at least `security.min_ratio_bps` (1.5) after it. Lowering a cap is never gated. A unit validators have not priced leaves the ratio unknown, which refuses every raise and counts as below the minimum for issuance.
- **Stake-backed caps.** Each epoch the caps of units other than TNZO shrink pro rata so that, with TNZO's own cap, they let out at most two thirds of bonded stake divided by `1 + bridge.security_gamma_bps` (gamma = 1) in one epoch. A crash in the TNZO price shrinks them at once, without a vote; gamma = 1 leaves room for a fall of half inside one safety window. The cap in force is the lower of the governed cap and this one.
- **Over-cap exits queue.** An exit the cap in force cannot carry this epoch is not refused: it waits in the exit queue, and anyone may release it once an epoch has room. It queues while the exits already waiting in its unit come to less than `bridge.queue_max_epochs` (24) epochs of the cap, so it leaves within about a day; past that the exit is refused and may be sent later. The sender can withdraw a queued exit at any time.

The genesis caps are sized from genesis stake: 21 validators of 10,000 TNZO put 70,000 TNZO at risk, which at k = 1.5 over a day covers about 1,945 TNZO an hour, split equally by USD at 0.10 USD per TNZO across TNZO (648), USDC (64.82) and OUSD (64.82). Caps rise only as stake grows.

## 16. Governance economics

Governance is on-chain: proposals, votes, enactment and vetoes are transactions every validator executes, and there is no other path by which network policy changes.

### Tracks

| Track | Voting window | Timelock | Quorum (of bonded stake) | Threshold (of participating stake) | Used for |
|---|---|---|---|---|---|
| Standard | 3 days | 2 days | 1/3 | 2/3 | Everything |
| Expedited | 6 hours | 4 hours | 1/3 | 4/5 | A burn-dial change answering a supply alarm, and nothing else |

Guardians hold negative powers only. Governance guardians veto a passed proposal during its timelock; protocol guardians pause enactment (voting and proposing continue). Either power takes `governance.guardian_threshold` distinct seated guardians of the role (default 2), a pause lifts by itself after `governance.max_pause_ms` (default 72 hours), and a new pause waits `governance.pause_cooloff_ms` (default 7 days) after the last one ended. A guardian is a human identity seated by an enacted `SetGuardian` proposal (or at genesis) for a term of at most `governance.guardian_max_term_ms` (default one year), and unseated by `RemoveGuardian` or when the term ends. Every seat names an independent key root (a passkey sync provider or a device-bound credential); two live seats of one role never share one. Foundation steward seats (role `steward`) may veto a queued treasury or expedited proposal, or hold treasury and expedited enactment for at most `governance.max_pause_ms`; they hold no power after `governance.steward_sunset_ms`, at most `governance.steward_max_seats` are live, and governance may only lower either value. No guardian action moves funds, sets a parameter or enacts a proposal. Actions fall into three domains: `Network` (parameters, economic policy, burn dial, supply targets, protocol upgrades; another vote can reverse them), `Treasury` (grants, tranches, recoveries; value moves and cannot be voted back) and `Sanction` (revoking an identity, seating or unseating a guardian). An agent may originate only the domains the governed agent phase permits.

### Who proposes and who votes

Opening a proposal takes bonded stake; voting weight is bonded stake. A funding request (a grant or a tranche release) can be filed by any registered identity with a zero balance as a `Funding` transaction whose gas the treasury pays; it then goes to the same vote.

### Enactment

A passed proposal is enacted by a `GovernanceExecute` transaction once its timelock has run. Treasury actions move balances in consensus state. A `policy_update` records the change in consensus state (`tenzro_getPolicy`) and logs it, and every node applies it to the subsystem it names: the economic policy, the burn dial and its supply targets, or a protocol upgrade. A protocol upgrade enacts only once validators holding `upgrade.readiness_bps` of bonded stake (default 67%) have sent `UpgradeReady` with a TPM quote of its binary, and activates `upgrade.activation_delay_blocks` after the enacting block; a node running another binary stops executing blocks at that height. The burn dial's generator only drafts: a validator submits its draft as a proposal and the network decides.

---

## 17. Sustainability

The network is sustainable when the fees real users pay cover what it costs to run, without rewards doing that work. Rewards exist to help the loop start (demand pays providers, provider income draws supply, supply improves price and availability, which draws demand) and are built so they can never pay more than the work behind them paid.

### What carries the network

- **Fees, not new tokens.** Network revenue comes from the on-chain settlement fee, the per-class treasury legs, and block fees. Rewards come out of a finite, genesis-funded pool on a declining schedule; nothing is minted, and unmatched or unclaimed rights stay in the pool.
- **Rewards bounded by outside cost.** A settlement's rewards are at most 9,000 bps of what it paid outside the trade (section 7). The reward pool can help a working loop start; it cannot pay anyone to trade with themselves.
- **Prices in USD terms.** Fees are set in micro-USD and charged in TNZO at the rate in force, so the network's charges follow the cost of the work rather than the token. AI prices fall quickly year on year; fees that are a share of value, plus governed USD minimums, keep pace where fixed per-token charges would not.
- **A visible take.** Every charge is a governed parameter with hard bounds (section 16 and [GOVERNANCE_PARAMS.md](GOVERNANCE_PARAMS.md)), and every payment it applies to settles on chain.

### How it is judged

Break-even and independence are measured on demand from parties unrelated to the providers serving it: related-party usage pays the tariff but counts neither toward rewards beyond the outside-cost bound nor toward the measures that decide whether the network pays its way. The per-class treasury legs start at 0 and are set by governance within their bounds; until fees cover running costs, the bootstrap carries the difference.

### Supply

Total supply only falls after genesis: burns (the governed share of base fees, of settlement fees, and paymaster fees) remove TNZO, and rewards move existing TNZO out of the pool. Whether circulating supply rises or falls in a period depends on usage and on how much verified work claims rewards; this document does not forecast it. The adaptive burn dial (section 6) gives governance an instrument to adjust the burn within bounds.

### Treasury runway

The treasury receives the part of each on-chain settlement fee that is not burned, the governed treasury legs, the treasury part of a public node's revenue split, and the block fees that are not burned, each less the insurance pool's governed share (`fees.insurance_pool_bps`, default 10%), plus other inflows (section 12). Outflows are capped per proposal and per period. The treasury does not depend on token sales.

---

## 18. Simulations

The model is verified through closed-form analysis and scenario simulation across the failure modes that have broken comparable systems. The simulations test whether net supply, staking equilibrium, fee market, and treasury runway all behave correctly under realistic and adversarial activity profiles. Every parameter used here matches the on-chain defaults; the equations are reproducible from the constants in sections 2 through 7.

### 18.1 Net supply

Define the per-epoch (one-day) change in circulating supply:

```
ΔS_epoch = R_paid − B_basefee − B_settlement − B_paymaster
```

Where:

- `R_paid` = TNZO paid out of the rewards pool in the epoch: claimed coupons' liquid part and vesting releases. It is bounded above by the epoch's share of the declining schedule (section 7: 60M TNZO in schedule year 0, falling 15% a year to a 10M floor, scaled by the controller between 0.5x and 1x), and below that by verified work: a provider or ecosystem bucket pays at most the reward weight its settlements recorded, and unclaimed coupons lapse into the pool.
- `B_basefee` = `Σ (base_fee_block × gas_used_block)` over the epoch's blocks, times `base_fee_burn_bps / 10,000`.
- `B_settlement` = the burned share of the epoch's on-chain settlement fees (`fees.settlement_fee_burn_bps`, half at genesis).
- `B_paymaster` = the paymaster burn (100% of paymaster-sponsored fees; not wired in execution yet, section 5).

Pool payouts move TNZO that genesis already allocated; they do not raise total supply. Total supply falls by every burn. Both sides are recorded on chain each block, and the block value rule (section 2) refuses a block whose balance changes do not match them.

**Settlement volume and rewards.** A settlement's reward weight is at most 9,000 bps of its outside cost, so for every unit of reward weight a settlement records it paid at least 1.11 units in fee and leg, half of the fee burned at genesis. Growth in rewarded settlement therefore grows the burn with it.

### 18.2 Staking equilibrium

Nothing is paid on stake. A bond earns only through the work it backs, and the protocol sets no target return. What a validator is paid in an epoch is:

```
validator_pay = stable cover + coupon share of the validator bucket + base reward
                + verified-availability reward

stable cover     = validator.base_cost_usd_month for the epoch, paid in stable settlement
                   assets from the validator cover reserve, which only
                   validator.stable_cover_fee_share_bps of the stable fees paid settlements
                   left the treasury fills, up to validator.stable_cover_target_months
validator bucket = min(epoch release × mint.validator_share_bps / (sum of the three shares),
                       mint.revenue_peg_bps of the epoch's paid weight: the reward ceilings
                       of the paid settlements it recorded)
epoch release    = annual release / epochs per year
annual release   = max(mint.base_tnzo_per_year × (1 − mint.decay_bps_per_year)^year,
                       mint.floor_tnzo_per_year) × controller multiplier
coupon share     = the validator's consensus work units (checkpoint votes, block proposals)
                   / all validators' consensus work units in the epoch
base reward      = the part of validator.base_cost_usd_month the stable cover left unpaid,
                   at the TNZO/USD rate in force, at most validator.base_cap_tnzo_month,
                   per validator with recorded consensus work; all bases together at most
                   fees.validator_burn_share_bps of the epoch's burned fees
```

An epoch with no paid settlement issues validators nothing: consensus is paid from what paid usage brings in, in stable assets first, and never from pool releases that no paid work matched. A validator also earns the verified-availability reward when two thirds of bonded stake attest it answered unpredictable challenges, signed by its TPM-endorsed machine identity; an unavailable verdict slashes its bond instead. No validator attests its own availability.

At genesis, the pool's release schedule is at most 60M TNZO in schedule year 0, falling 15% a year to a 10M TNZO floor; the shares are 45% validators, 40% providers and 15% apps; validators' running cost is 1,500 USD a month, paid first from a stable cover reserve that only stable settlement fees fill (all of the treasury's kept stable fees until it holds 12 months of cost), then as a base reward, capped at 20,000 TNZO a month, from at most 25% of the epoch's burn. The base is the operator's: each validator coupon records its base part, and a claim pays that part at `rewards.base_liquid_bps` (genesis 100% liquid) before the rest is split into its liquid and vesting shares. Every payment comes out of the finite rewards pool. The controller multiplier stays between `mint.min_mult_bps` (0.5x) and `mint.max_mult_bps` (1x). Providers and apps are paid by the fees their settlements recorded, never above each settlement's own reward ceiling. Every value above is governance-set.

What a validator is paid therefore depends on the work it does, the number of validators sharing the bucket and the burn. Nothing is paid for holding or bonding TNZO alone. This document does not forecast payouts.

**Stress check — falling validator stake.** If validators leave, the bonded stake that secures consensus falls. At what point does the network become Byzantine-vulnerable?

Consensus requires more than two-thirds of seats honest, and in Tenzro consensus weight comes only from the validator bond — service bonds carry zero finality weight (section 7). Because consensus weight is decoupled from service capacity, the security budget is exactly the validator-bonded supply; bonding for any number of service rungs cannot move a quorum. With `n` seats, fault bound `f = (n - 1) / 3` and quorum `n - f` (section 7), an attacker holding more than one third of validator-bonded stake can halt finality, and can also sign conflicting checkpoints that each reach a quorum. More than one third of bonded stake is therefore enough to break either liveness or safety. The attacker must acquire and bond that share at market price, and it is all slashable.

High-trust block classes (institutional settlement, high-value bridge messages, cross-chain delivery-versus-payment) further restrict *leader election* to validators above a higher stake and reputation bar, raising the bonded position an attacker needs to target them, but the underlying one-third fault bound is the same.

The rule: the stake an attacker must bond to break liveness or safety is more than one third of all validator-bonded stake. With `B` TNZO bonded to validators, that is more than `B / 3`. The protocol measures the same quantity: `security.attack_stake_bps` (default 3,334, one third) is the share of bonded stake a safety fault puts at risk, used in the security ratio (section 15b).

The attacker also faces (a) the slashing risk on every validator they operate (an equivocation costs at least 5% of the bond, and a coordinated one by a third of bonded stake costs all of it), (b) market impact on accumulating the position, and (c) the cost of running the additional infrastructure. Real attacker cost is meaningfully above the headline TNZO figure.

The protocol responds through the security ratio (slashable stake over what one attack can take out over the bridges). While the ratio is below `security.min_ratio_bps` (default 1.5x), the issuance controller raises its multiplier toward `mint.max_mult_bps`, and a raise of any bridge outflow cap is refused. Governance can also lower bridge outflow caps or change the validator base reward. The adaptive burn dial alone is insufficient at this end.

**Stress check — slashing spiral.** An isolated equivocation slashes 5% of one offender's stake; only a correlated event can take more, and it takes more only from the stake that equivocated. Slashed stake moves to the insurance pool, not to surviving validators or the reporter, so there is no positive feedback loop where anyone profits from a peer's slash, and it pays out only against proven losses under governed caps.

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
  I_t = (treasury leg of settled service payments
         + (1 − fees.settlement_fee_burn_bps) × on-chain settlement fees
         + unburned block fees) × (1 − fees.insurance_pool_bps)
         + other inflows (section 12)
  O_t = grants + ecosystem incentives + infrastructure + insurance fund + sponsorship contributions + operational
```

For the network to fund itself indefinitely from real demand:

```
I_steady_state ≥ O_steady_state
```

**Treasury rates at genesis:**

- Treasury part of a public node's revenue split: 10% of the payment at genesis (`EconomicPolicy`), less the insurance share.
- Per-class treasury legs of provider payments: 0 at genesis (`fees.treasury_leg_*_bps`), set by governance within 0 to 5,000 bps.
- On-chain settlement fee: 0.1% of the value settled (`fees.settlement_fee_bps` = 10), of which half is burned and half goes to the treasury, less the insurance share: 0.045% of the value settled.
- Block fees: the base fee is burned by default; priority fees go to the treasury, less the insurance share.

How much settlement volume is service payments and how much is other on-chain settlement is not fixed by the protocol, so this document gives the rates and not a yearly figure. At steady-state activity, inflows grow with settled volume and are what funds grants, audits, insurance, infrastructure, and other outflows without depleting the genesis allocation. Below steady-state activity, the treasury must rely on its genesis-allocated initial balance to extend runway; governance can throttle outflows during the bootstrap phase to preserve runway until commission throughput ramps up.

**Stress check — bootstrap runway.** Treasury inflows during the first 12 months will be modest. Grants that fund bootstrap activity draw on the treasury like any other grant and are bounded by the same per-proposal and per-period outflow caps, so governance can scale them to the runway.

### 18.5 Bootstrap funding

There is no bootstrap earmark to draw down or burn at a sunset. Bootstrap activity is paid for by governed treasury grants, each enacted by its own vote, released in tranches where the grant says so, and bounded by the treasury outflow caps. If organic activity ramps slower than projected, governance grants more from what the treasury holds; if it ramps faster, governance stops granting. Nothing is pre-allocated, so nothing is left over.

### 18.6 Bridge sponsorship sustainability

Bridge fee sponsorship draws from a configurable pool. Sustainability requires:

```
S_pool_inflow ≥ S_pool_outflow_to_sponsored_routes
```

Where pool inflow comes from operator contributions, a configurable cut of the treasury leg on subsidized routes, and treasury grants. The cap on commission share is governance-set; the default cap prevents runaway sponsorship.

**Stress check — sponsorship drain.** If sponsored routes are gamed (users routing through them solely to extract subsidies), the cap on commission share auto-throttles. Persistent gaming triggers governance to lower the cap, raise the eligibility threshold, or shut down sponsorship for a specific route.

### 18.7 Failure mode coverage

The simulations above cover the failure modes that have broken comparable systems in 2022–2025:

| Failure mode | Tenzro mitigation | Tested in |
|---|---|---|
| Runaway issuance | Fixed supply, nothing minted after genesis; rewards from the finite genesis pool | 18.1 |
| Insufficient burn | Two demand-driven channels + adaptive dial | 18.1, 18.3 |
| Falling validator stake → security degradation | Pool release controller on the security ratio + governance lever | 18.2 |
| Slashing cascade | Correlation-scaled penalty touches only the offenders; slashed stake funds the insurance pool, never surviving validators; no positive feedback | 18.2 |
| Fee market lock-up at high base fee | Symmetric ±12.5% adjustment + ceiling | 18.3 |
| Adversarial gas spamming | Self-paid via the same base-fee burn | 18.3 |
| Treasury depletion | Diversified inflows; governance throttles outflows | 18.4 |
| Bootstrap funding cliff | Governed treasury grants under outflow caps | 18.4, 18.5 |
| Sponsorship pool drain | Governance-set commission share cap | 18.6 |
| Investor / team unlock cliffs | No team or investor allocation; no cliffs exist | 2 |

The model is conservatively parameterized — every assumption used to verify it errs on the side of pessimism (low activity, no organic ramp, adversarial staking participation, sustained congestion). The default parameters survive every simulation; the governance dials are available to retune any of them if real-world activity diverges from these projections.

---

## 19. Where the agentic decade is going

The model above is designed for where the AI and agentic economy is going, not where it has been.

**Agents do most discrete economic actions.** By the late 2020s, autonomous agents — LLM-driven, tool-using, identity-bound — will conduct the majority of routine economic transactions: quote requests, payment routing, on-chain settlement, identity verification, micro-credentialing. The protocol that wins this period is the one that gives agents a complete substrate. Tenzro's TDIP, hardware-bound wallets, AP2 mandates, ERC-7579 custody, MCP/A2A surfaces, and protocol-level settlement are designed for that world.

**Settlement converges on identity-bound payment.** Stablecoins, payment processors, card networks, agent-pay standards, and on-chain micropayments are all converging on the same model: a counterparty identity (KYC where required), a signed mandate (authorization scope), a settled receipt (audit). MPP, x402, Tempo, Visa Tap, Mastercard Agent Pay, Stripe SPT, and AP2 all express this pattern. Tenzro implements every major variant natively so an agent can serve any payment surface its counterparty needs.

**Open-source AI is the default.** By late 2026, open-weight models from Qwen, Gemma, Mistral, DeepSeek, Granite, and others match or exceed closed models on most benchmarks. Inference moves from a small number of hyperscaler APIs to a long tail of operators serving their own GPUs. Tenzro's permissionless model marketplace, multi-modality runtimes, and provider economy are built for this distribution.

**Distributed training is production.** Data-parallel training with decoupled outer synchronization has demonstrated that large models can be trained across regions and across operators. Coordinating such runs across operators needs sponsor escrow, round milestones and checkable evidence. On Tenzro these are built on the network's public interfaces (escrows carrying a reference, quorum release, evidence verification), so anyone can run, fork or replace the training tooling.

**Cross-chain becomes intent-driven.** ERC-7683 cross-chain intents, deBridge DLN, LayerZero V2, and CCIP CCT are coalescing on an intent-driven model: the user signs what they want; the network finds the cheapest, fastest, or most-reliable path. Tenzro's unified `BridgeRouter` is built for this.

**Regulation requires legibility.** EU AI Act Article 50 binds AI disclosure. MiCA binds stablecoin and crypto-asset service providers. Travel rule enforcement extends to virtual asset service providers. Protocols that move into 2027 without auditable identity, mandate-bound authorization, KYC-tier-bound delegation, on-chain receipts, and operator-grade analytics will not be usable by institutional counterparties. Tenzro's TDIP credential system, AP2 validation, ERC-7579 enforcement, settlement receipts with mandate binding, and per-tenant analytics are built for this regulatory shape.

**Post-quantum becomes table stakes.** NIST standardized ML-DSA in 2024; CNSA 2.0 mandates PQ-hybrid signatures across federal infrastructure by the late 2020s; major TLS deployments enabled X25519MLKEM768 in 2024–2025. Protocols that store value or sign attestations for the long term need PQ-hybrid throughout. Tenzro's Ed25519 + ML-DSA-65 hybrid signatures on every safety-critical message, X25519 + ML-KEM-768 key exchange, and PQ-hybrid wallet primitives are built for this.

The TNZO economic model is built around these forward trajectories. Demand sources scale with the agentic economy. Burn channels scale with real usage. Bonds align providers with the value they secure. Governance dials let the protocol respond to where the world is going.

That is what TNZO is for.

---

**License: Apache-2.0.**
