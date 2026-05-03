# TNZO Tokenomics: Designed for the AI and Agentic Era

**Tenzro Network | March 2026**

---

## Executive Summary

The TNZO token is the economic primitive of Tenzro Network -- a purpose-built L1 for the AI age where humans and autonomous agents access intelligence (AI models) and security (TEE enclaves) and settle all value exchange on the Tenzro Ledger. This document details the TNZO token economics, situates them in the 2026 token-economy landscape, and provides a sustainability framework ensuring the protocol can fund itself indefinitely from real demand rather than inflationary subsidies.

The 2026 AI-native protocol landscape has reached an inflection point. Protocols that tied their tokenomics to real compute demand (Bittensor's flow-based emissions, Render's burn-mint equilibrium, io.net's Incentive Dynamic Engine, Akash's BME) are surviving. Those relying on speculative staking yields and unsustainable inflation are struggling. Tenzro's architecture positions it well: a two-tier fee model (gas + network commission) with dual burn mechanisms creates natural deflationary pressure that scales with adoption. The key is ensuring every TNZO burned or staked corresponds to real demand for intelligence or security.

---

## Table of Contents

1. [TNZO Token Fundamentals](#1-tnzo-token-fundamentals)
2. [The Two-Tier Fee Architecture](#2-the-two-tier-fee-architecture)
3. [Burn Mechanisms and Deflationary Dynamics](#3-burn-mechanisms-and-deflationary-dynamics)
4. [Staking Economics](#4-staking-economics)
5. [Liquid Staking (stTNZO)](#5-liquid-staking-sttnzo)
6. [Treasury and Revenue Model](#6-treasury-and-revenue-model)
7. [Agent-Native Payments (MPP + x402)](#7-agent-native-payments-mpp--x402)
8. [Micropayment Channels](#8-micropayment-channels)
9. [Cross-Chain Settlement](#9-cross-chain-settlement)
10. [The 2026 Token-Economy Landscape](#10-the-2026-token-economy-landscape)
11. [Sustainability Analysis](#11-sustainability-analysis)
12. [Supply and Distribution](#12-supply-and-distribution)
13. [Governance Economics](#13-governance-economics)
14. [What Tenzro Does Differently in Token Economics](#14-what-tenzro-does-differently-in-token-economics)
15. [Strategic Recommendations](#15-strategic-recommendations)

---

## 1. TNZO Token Fundamentals

| Parameter | Value |
|-----------|-------|
| Token name | TNZO |
| Decimals | 18 |
| Maximum supply | 1,000,000,000 (1 billion) |
| Smallest unit | 1 wei-equivalent (10^-18 TNZO) |
| Precision | u128 (overflow-safe arithmetic) |
| Chain ID | 1337 (Tenzro Ledger) |

### Four Utility Functions

1. **Gas** -- Pay transaction fees on the Tenzro Ledger (EIP-1559 dynamic pricing)
2. **Settlement** -- Settle payments for AI inference, TEE services, and agent operations
3. **Staking** -- Stake to validate, provide models, operate TEE enclaves, or store data
4. **Governance** -- Vote on protocol parameters, treasury grants, and upgrades

### Why a Native Token (Not Just Stablecoins)

AI-native protocols face a fundamental design choice: settle in stablecoins or native tokens. Tenzro uses TNZO as the settlement layer with stablecoin support because:

- **Burn mechanics require a native token.** EIP-1559 base fee burns and commission burns create deflationary pressure only if there is a burnable native asset. Stablecoin-only protocols cannot create this reflexive demand loop.
- **Staking security requires alignment.** Validators, model providers, and TEE providers must have economic skin-in-the-game denominated in the asset they secure. Stablecoin staking lacks this alignment.
- **Governance weight requires non-pegged value.** Governance votes weighted by staked TNZO create real cost to attacking governance. Stablecoin-weighted governance can be trivially Sybil-attacked.
- **Stablecoins remain supported** for user-facing pricing (MPP sessions, x402 payments), bridged via tenzro-payments. Providers receive TNZO rewards regardless of the user's payment denomination.

---

## 2. The Two-Tier Fee Architecture

Tenzro implements a two-tier fee system that separates infrastructure security (gas) from service-layer value capture (network commission). This is architecturally distinct from single-fee protocols and draws from the most sustainable models in the 2026 landscape.

### Tier 1: Gas Fees (EIP-1559)

Gas fees secure the Tenzro Ledger itself. Every transaction -- transfers, smart contract calls, identity registration, governance votes -- pays gas.

| Parameter | Value | Source |
|-----------|-------|--------|
| Max gas per block | 30,000,000 | `tenzro-vm/eip1559.rs` |
| Target gas per block | 15,000,000 (50% of max) | `tenzro-vm/eip1559.rs` |
| Initial base fee | 1 Gwei (10^9 wei) | `tenzro-vm/eip1559.rs` |
| Min base fee | 0.1 Gwei | `tenzro-vm/eip1559.rs` |
| Max base fee | 1,000 Gwei | `tenzro-vm/eip1559.rs` |
| Elasticity multiplier | 2x | `tenzro-vm/eip1559.rs` |
| Base fee change rate | 12.5% per block (denominator 8) | `tenzro-vm/eip1559.rs` |

**Base fee adjustment formula:**

```
if gas_used > target:
    fee_delta = (base_fee * (gas_used - target)) / target / 8
    next_base_fee = base_fee + max(fee_delta, 1)
else:
    fee_delta = (base_fee * (target - gas_used)) / target / 8
    next_base_fee = base_fee - fee_delta

next_base_fee = clamp(next_base_fee, 0.1 Gwei, 1000 Gwei)
```

**Fee split:**
- **Base fee** --> BURNED (removed from total supply permanently)
- **Priority fee** --> Validators and stakers (tips for inclusion priority)

**Priority fee suggestions by urgency:**

| Urgency | Priority Fee |
|---------|-------------|
| Low | 10% of base fee |
| Medium | 20% of base fee |
| High | 50% of base fee |
| Urgent | 100% of base fee |

### Tier 2: Network Commission (0.5%)

The network commission captures value from AI inference, TEE services, and any settlement processed through the Tenzro Ledger. This is the primary revenue engine for the protocol.

| Parameter | Value | Source |
|-----------|-------|--------|
| Network fee rate | 0.5% (50 basis points) | `tenzro-settlement/engine.rs` |
| Min settlement amount | 1,000 units (dust protection) | `tenzro-settlement/engine.rs` |
| Max batch size | 100 settlements per batch | `tenzro-settlement/engine.rs` |

**Settlement fee formula:**

```
network_fee = (amount * 50) / 10,000
provider_receives = amount - network_fee

Example: 10,000 TNZO inference payment
  Network fee: 50 TNZO (0.5%)
  Provider receives: 9,950 TNZO
```

**Commission distribution (40/30/30):**

| Destination | Share | Purpose |
|-------------|-------|---------|
| Treasury | 40% (4,000 bps) | Protocol development, grants, operations |
| Burn | 30% (3,000 bps) | Permanent supply reduction |
| Stakers | 30% (3,000 bps) | Reward active network participants |

This split is enforced on-chain and must sum to exactly 10,000 basis points.

### Why Two Tiers

Single-fee protocols face a dilemma: set fees too low and validators are underpaid; set them too high and users leave. Tenzro's two-tier system resolves this:

- **Gas fees** self-regulate via EIP-1559 to reflect infrastructure demand
- **Commission fees** are fixed at 0.5%, competitive with centralized alternatives
- **Validators earn from gas tips**, independent of service-layer activity
- **Providers earn from settlements**, independent of on-chain congestion
- **The protocol earns from both**, creating diversified revenue

Comparable take rates in the 2026 landscape: Akash proposed 20% (currently 1-2%), Apple 30%, Uber 23%. Tenzro's 0.5% is deliberately low to maximize adoption during growth, with governance able to adjust upward as the network matures.

---

## 3. Burn Mechanisms and Deflationary Dynamics

Tenzro has two independent burn channels. This is a structural advantage over single-burn protocols.

### Burn Channel 1: EIP-1559 Gas Base Fee

Every block burns `base_fee * gas_used`. This is the primary, demand-driven deflationary mechanism.

```
burn_per_block = base_fee * gas_used
```

- **Self-regulating:** Burns more when network is congested, less when idle
- **No cap:** Supply can decrease below initial issuance
- **Unlimited:** Tracks accumulated `total_burned` counter

At Ethereum-like utilization (15M gas/block at 30 gwei base fee), this burns approximately 450 TNZO per block. The block budget below assumes a sustained network-average effective burn-per-block which factors in idle blocks; at peak load with 400ms blocks the rate is substantially higher.

### Burn Channel 2: Network Commission Burn (30%)

30% of all network commission fees are burned:

```
commission_burn = (settlement_amount * 50 / 10,000) * 3,000 / 10,000
               = settlement_amount * 0.15 / 100
               = 0.015% of all settled volume
```

### Combined Deflationary Formula

```
Annual Net Supply Change =
    Staking Rewards (inflationary)
  - EIP-1559 Gas Burns (deflationary)
  - Commission Burns (deflationary)

Break-even condition:
  Staking Rewards = Gas Burns + Commission Burns
```

### Deflationary Threshold

With 5% APY staking rewards on a hypothetical 30% staking ratio (300M TNZO staked):

```
Annual staking inflation: 300M * 5% = 15M TNZO

Required annual burn to offset:
  Gas burns: ~6.5M TNZO (at Ethereum-like utilization)
  Commission burns: requires ~56.7B TNZO settled volume per year
    (56.7B * 0.015% = ~8.5M TNZO burned)

Total burns needed: 15M TNZO --> achievable at moderate utilization
```

This means TNZO can become net-deflationary at moderate network usage. The key insight: both burn channels scale independently with different types of demand (transactions vs. service payments), providing diversified deflationary pressure.

---

## 4. Staking Economics

### Staking Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Minimum stake | 1,000 TNZO | `tenzro-token/staking.rs` |
| Unbonding period | 7 days (604,800,000 ms) | `tenzro-token/staking.rs` |
| Base reward rate | 5% APY (500 bps) | `tenzro-token/rewards.rs` |
| Epoch duration | 14,400 blocks (~1 day at 6s/block) | `tenzro-token/rewards.rs` |
| Epochs per year | 365 | `tenzro-token/rewards.rs` |

### Provider Types and Reward Multipliers

| Provider Type | Multiplier | Rationale |
|---------------|-----------|-----------|
| Validator | 1.0x | Baseline -- secures consensus |
| TEE Provider | 1.2x | Higher capital cost (confidential hardware) |
| Model Provider | 1.1x | Higher operational cost (GPU, bandwidth) |
| Storage Provider | 1.0x | Baseline -- stores ledger state |

### Reward Calculation

```
1. epoch_budget = (total_staked * reward_rate_bps / 10,000) / epochs_per_year
2. epoch_budget = min(epoch_budget, reward_pool)  // Cap by available pool
3. For each staker:
     stake_proportion = stake_amount / total_staked
     base_reward = epoch_budget * stake_proportion
     adjusted_reward = base_reward * uptime_multiplier  // 0.0 to 1.0
     final_reward = adjusted_reward * type_multiplier   // 1.0x to 1.2x
```

### Quality-of-Service (QoS) Based Rewards

The `uptime_multiplier` (0.0 to 1.0) ensures rewards flow to active, reliable providers rather than passive stakers. This aligns with the 2026 industry shift toward QoS-based emissions:

- **Bittensor** shifted to flow-based emissions (net TAO inflows, not price)
- **Nosana** proposed NNP-001 (usage-driven, not yield-driven)
- **Grass** introduced QoS thresholds (100+ hours uptime per epoch, latency metrics)
- **io.net** launched IDE (stable USD-targeted payouts tied to actual GPU utilization)

Tenzro's uptime multiplier achieves the same goal: a validator with 95% uptime earns 95% of their potential reward; one with 50% uptime earns 50%. Zero uptime = zero rewards.

### Slashing

Slashing is fully implemented with automatic equivocation detection and enforcement. When a slash is executed, the unbonding period is reset and stake can be reduced below minimum, forcing the provider into unbonding:

- **Equivocation** -- Double-signing or conflicting votes (detected via `EquivocationDetector` in consensus, 10% stake penalty)
- **Downtime** -- Extended offline periods
- **Invalid proofs** -- TEE providers submitting false attestations
- **Service failure** -- Model providers returning incorrect inference results

The consensus layer's `EquivocationDetector` monitors all votes for conflicting signatures in the same view. When equivocation is detected, the `SlashingCallback` trait bridges to `StakingManager::slash()` which automatically enforces the penalty and preserves evidence on-chain.

Slashed TNZO is burned, not redistributed -- ensuring slashing is punitive rather than redistributive.

---

## 5. Liquid Staking (stTNZO)

Liquid staking allows staked TNZO to remain economically productive. The stTNZO token represents a claim on staked TNZO plus accrued rewards.

### Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Token | stTNZO | `tenzro-token/liquid_staking.rs` |
| Decimals | 18 | Same as TNZO |
| Initial exchange rate | 1:1 | `tenzro-token/liquid_staking.rs` |
| Protocol fee | 10% of rewards (1,000 bps) | `tenzro-token/liquid_staking.rs` |
| Minimum deposit | 0.1 TNZO | `tenzro-token/liquid_staking.rs` |
| Maximum total deposits | Unlimited (default) | `tenzro-token/liquid_staking.rs` |
| Unbonding period | 7 days | Matches native staking |
| Max validators | 50 | Diversification limit |

### Exchange Rate Mechanics

stTNZO uses a rebasing model where the exchange rate increases as staking rewards accrue:

```
exchange_rate = (total_underlying_tnzo * 10^18) / total_sttnzo_supply

// Overflow-safe calculation (u128):
quotient = underlying / supply
remainder = underlying % supply
exchange_rate = quotient * 10^18 + (remainder * 10^18 / supply)
```

When rewards arrive:

```
protocol_fee = reward_amount * 1,000 / 10,000    // 10%
staker_share = reward_amount - protocol_fee       // 90%

total_underlying_tnzo += staker_share
// stTNZO supply unchanged --> exchange rate increases
// Each stTNZO now redeemable for more TNZO
```

### Why 10% Protocol Fee

The 10% protocol fee on liquid staking rewards funds protocol development from real yield, not token sales. This is structurally similar to how AO Computer funds development from deposited asset yield rather than pre-mine.

At 300M TNZO staked at 5% APY:
- Annual rewards: 15M TNZO
- Protocol fee (10%): 1.5M TNZO
- Staker yield: 13.5M TNZO (effective 4.5% APY)

This creates a sustainable revenue stream that grows with staking participation.

---

## 6. Treasury and Revenue Model

### Revenue Sources

The treasury collects from three independent channels:

1. **Commission share (40% of 0.5% network fee):**
   ```
   treasury_income = settled_volume * 0.5% * 40% = settled_volume * 0.2%
   ```

2. **Liquid staking protocol fee (10% of staking rewards):**
   ```
   treasury_income = total_staked * 5% APY * 10%
   ```

3. **Gas priority fees** (when validators route tips through treasury for redistribution)

### Treasury Operations

| Parameter | Value | Source |
|-----------|-------|--------|
| Multisig threshold | Configurable M-of-N | `tenzro-token/treasury.rs` |
| Max grant per proposal | Governance-determined | `tenzro-token/governance.rs` |
| Multi-asset support | TNZO, USDC, USDT, ETH, SOL, BTC | `tenzro-token/treasury.rs` |
| Supply invariant | collected = current_balance + distributed | `tenzro-token/treasury.rs` |

### Treasury Sustainability Model

```
Annual Treasury Revenue (at various utilization levels):

Low utilization ($10M settled/year):
  Commission share: $10M * 0.2% = $20K
  Staking fee: 50M staked * 5% * 10% = 250K TNZO
  Total: $20K + 250K TNZO

Medium utilization ($1B settled/year):
  Commission share: $1B * 0.2% = $2M
  Staking fee: 200M staked * 5% * 10% = 1M TNZO
  Total: $2M + 1M TNZO

High utilization ($100B settled/year):
  Commission share: $100B * 0.2% = $200M
  Staking fee: 400M staked * 5% * 10% = 2M TNZO
  Total: $200M + 2M TNZO
```

The treasury is self-funding at medium utilization. No reliance on token sales or inflationary grants.

---

## 7. Agent-Native Payments (MPP + x402)

The AI agent economy requires machines to pay machines without human intermediation. Tenzro natively supports both dominant machine payment protocols:

### Machine Payments Protocol (MPP)

Co-authored by Stripe and Tempo, MPP is the session-based payment protocol for autonomous AI agents.

**How it works on Tenzro:**
1. Agent requests a resource (inference, TEE attestation)
2. Tenzro node returns HTTP 402 with `MppChallenge` (amount, currency, expiry)
3. Agent creates `MppCredential` (payment proof, signed by wallet)
4. Node verifies credential, settles on-chain, returns `MppReceipt`
5. Session continues with pre-funded balance for subsequent requests

**2026 adoption:** 100+ services in Tempo Payment Directory. Partners include Visa, Anthropic, OpenAI, Mastercard, Shopify. MPP functions like "OAuth for payments."

### x402 Protocol

Coinbase's stateless, per-request payment protocol for HTTP APIs.

**How it works on Tenzro:**
1. Agent requests a resource
2. Server returns 402 `PaymentRequired` header
3. Agent creates `X402PaymentPayload` (signed by wallet)
4. Server verifies (locally or via facilitator), serves resource

**2026 adoption:** 15M+ transactions across projects. Multi-network: EVM (Base, Polygon), Solana, Avalanche, Sui, Near. Free tier: 1,000 tx/month via Coinbase facilitator.

### Tenzro's Integration

Tenzro's `tenzro-payments` crate implements both MPP and x402 with:
- `PaymentGateway` for multi-protocol routing
- Identity binding via TIP (Tenzro Identity Protocol) with delegation scope enforcement
- HTTP middleware for automatic challenge/verification
- Settlement on Tenzro Ledger with 0.5% network commission

This means any AI agent with a Tenzro identity and MPC wallet can autonomously pay for inference, TEE services, or any HTTP 402-protected resource -- without human intervention.

---

## 8. Micropayment Channels

For high-frequency, low-value transactions (per-token billing, streaming inference), Tenzro implements off-chain micropayment channels with on-chain settlement.

### Channel Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Challenge period | 24 hours | `tenzro-settlement/micropayments.rs` |
| Dispute timeout | 24 hours | `tenzro-settlement/micropayments.rs` |
| State nonce | Incremental (replay protection) | `tenzro-settlement/micropayments.rs` |
| Signature | Ed25519 (cryptographic verification) | `tenzro-settlement/micropayments.rs` |

### Channel Lifecycle

```
1. OPEN: Customer deposits TNZO into channel
   channel.deposit = N TNZO
   channel.spent = 0

2. USE: Off-chain state updates per micropayment
   new_spent = channel.spent + payment
   payer_balance = deposit - new_spent
   payee_balance = new_spent
   State signed by payer (Ed25519)

3. CLOSE: Initiate cooperative or unilateral close
   24-hour challenge period begins
   Newer state (higher nonce) can challenge

4. SETTLE: After challenge period
   Customer refunded: payer_balance
   Provider paid: payee_balance
   0.5% network commission on total spent
```

### Per-Token Billing

This enables per-token billing for AI inference:
- User opens channel with 100 TNZO deposit
- Each generated token costs 0.001 TNZO (off-chain state update)
- After generating 50,000 tokens (50 TNZO spent), user closes channel
- Settlement: 50 TNZO to provider (minus 0.5% commission), 50 TNZO refunded

No gas cost per token -- only on channel open and close.

---

## 9. Cross-Chain Settlement

Tenzro bridges connect the ledger to other chains for asset movement and cross-chain agent payments.

### Bridge Adapters

| Adapter | Protocol | Use Case |
|---------|----------|----------|
| LayerZero V2 | Omnichain messaging | EVM chain interop |
| Chainlink CCIP | Cross-chain messaging | Institutional, high-value |
| deBridge DLN | Intent-based, no locked liquidity | Fast, competitive |
| Canton/DAML | Enterprise ledger | Regulated environments |

### Cross-Chain Agent Payment Flow

1. Agent on Ethereum wants to pay for inference on Tenzro
2. Agent bridges USDC to Tenzro via deBridge (fast, intent-based)
3. USDC converted to TNZO on Tenzro DEX or used directly via stablecoin settlement
4. Inference settled on Tenzro Ledger (0.5% commission collected)
5. Provider receives payment in TNZO or stablecoin

This is consistent with the 2026 trend: deBridge launched MCP integration (February 2026) enabling AI agents and developer tools (Claude, Copilot) to execute cross-chain operations directly.

---

## 9.5 Cross-VM Token Architecture

While Section 9 covers cross-chain settlement (moving assets between Tenzro and external chains), this section addresses cross-VM interoperability within the Tenzro Ledger itself. The Ledger supports three VMs (EVM, SVM, Canton/DAML), and TNZO must be usable across all three without fragmentation.

### The Pointer Model (No Bridge Risk)

Tenzro adopts the **Sei V2 pointer model**: each VM has a lightweight representation (wTNZO on EVM, wTNZO SPL on SVM, TNZO CIP-56 on Canton) that points to the same underlying native balance. There is no lock-and-mint bridge between VMs. When a user interacts with wTNZO on EVM, the ERC-20 pointer contract reads and writes the user's canonical native balance in the `TnzoToken` layer directly.

**Implications for tokenomics:**
- **Zero liquidity fragmentation.** The entire TNZO supply is unified. There are no separate "EVM TNZO" and "SVM TNZO" pools that could trade at different prices or require arbitrage.
- **No bridge risk.** Cross-VM transfers are atomic balance updates, not bridge messages. There is no attack surface for bridge exploits (the leading source of DeFi losses in 2024-2025).
- **Single source of truth for supply.** `total_supply()`, burn accounting, and treasury calculations always reflect the true unified supply, regardless of which VM surface was used.

### TNZO Representation Across VMs

| VM | Token | Decimals | Interface |
|----|-------|----------|-----------|
| EVM | wTNZO (ERC-20 pointer) | 18 | Standard ERC-20 (`transfer`, `approve`, `transferFrom`) with approval storage |
| SVM | wTNZO (SPL adapter) | 9 | SPL Token Program instruction mapping; associated token account (ATA) derivation |
| Canton | TNZO (CIP-56 holding) | 18 (DAML Decimal) | Two-step transfer: create transfer proposal, then accept or reject |

**Decimal conversion (SVM).** Solana SPL tokens use 9 decimals vs TNZO's 18. The adapter truncates the lower 9 digits on deposit to SVM and zero-pads on withdrawal. The smallest representable unit in SVM is therefore 10^9 wei (1 Gwei-equivalent), which is sufficient for all practical operations including micropayments.

### Cross-VM Transfer Gas Costs

Cross-VM transfers invoke the `CROSS_VM_BRIDGE` precompile at address `0x1003`. Because these are internal balance updates (not cross-chain bridge messages), gas costs are predictable and low:

| Operation | Estimated Gas | Description |
|-----------|-------------|-------------|
| EVM to SVM transfer | ~50,000 | Balance debit + SPL adapter credit + decimal conversion |
| EVM to Canton transfer | ~60,000 | Balance debit + CIP-56 holding creation + party mapping |
| SVM to EVM transfer | ~50,000 | SPL adapter debit + decimal expansion + balance credit |
| Token wrap (`TNZO_BRIDGE` at `0x1001`) | ~30,000 | No-op in pointer model (balance is already unified) |

The `wrap` operation is effectively a no-op in the pointer model -- calling it returns the user's existing balance in the target VM representation without any actual token movement. It exists for API compatibility with protocols that expect an explicit wrap step.

### Token Factory for Ecosystem Tokens

The `TOKEN_FACTORY` precompile at address `0x1002` enables permissionless token creation on the Tenzro Ledger. Any user or smart contract can create a new ERC-20 token that is automatically registered in the unified token registry (`CF_TOKENS` column family in RocksDB).

**Token creation parameters:**
- `TokenId`: Deterministic SHA-256 hash of creator address and nonce (no collisions)
- Decimals: Configurable (default 18)
- Initial supply: Set at creation, minted to creator
- Cross-VM deployment: Created tokens can be deployed as pointer contracts across all three VMs

**Economic impact:** The token factory lowers the barrier for ecosystem token creation (DAO governance tokens, application reward tokens, loyalty points), all of which generate gas fees on the Tenzro Ledger and increase network utilization, feeding the EIP-1559 burn mechanism.

---

## 10. The 2026 Token-Economy Landscape

### Protocol Comparison Matrix

| Protocol | Supply | Fee Model | Burn Mechanism | Staking | Agent Payments | Status |
|----------|--------|-----------|---------------|---------|----------------|--------|
| **TNZO (Tenzro)** | 1B | 2-tier (gas + 0.5% commission) | EIP-1559 + 30% commission burn | QoS-weighted, 5% APY | MPP + x402 native | Pre-alpha |
| **TAO (Bittensor)** | 21M | Subnet emissions | None (flow-based allocation) | Subnet staking | None | Live (post-halving) |
| **RENDER** | 644.2M | BME (burn-mint) | User payments burned | Node operator rewards | None | Live |
| **AO (Arweave)** | 21M | Fair launch yield | None | Asset bridging | None | Mainnet Feb 2026 |
| **AKT (Akash)** | 388M | BME (March 2026) | Burn AKT to mint ACT | PoS (Cosmos) | None | Live |
| **IO (io.net)** | 800M | IDE (Q2 2026) | 50%+ revenue burned | Supplier + staker | None | Live |
| **SENT (Sentient)** | 34.36B | Stake-to-access | None | Access gating | GRID agents | Pre-launch |
| **VANA** | 120M | Data purchase burn | DLP token burn on purchase | DataDAO staking | None | Live |
| **SAHARA** | 10B | Per-inference | Auto fee split | PoS | Sorin agents | Pre-mainnet |
| **GRASS** | 1B | QoS-based | None | Router staking | None | Live |
| **NOS (Nosana)** | 100M | Usage-driven (NNP-001) | None | Up to 40% APY | None | Live |

### Key Findings from 2026 Research

**1. Burn-Mint Equilibrium (BME) is the dominant sustainable model**

Render pioneered BME in December 2023. By March 2026, Akash adopted it (mainnet March 23, 2026) and io.net is launching IDE (a BME variant) in Q2 2026. The pattern: users burn tokens for services, providers receive minted tokens for work. If demand exceeds issuance, the token becomes deflationary.

*How Tenzro handles this:* Tenzro's dual-burn model (EIP-1559 + commission burn) reaches the same deflationary outcome through a different mechanism. Rather than explicit burn-mint cycles, Tenzro burns from two independent channels. This decouples infrastructure demand (gas) from service demand (commissions), so a slowdown in either does not collapse the burn.

**2. Flow-based emissions replace price-based emissions**

Bittensor's "Taoflow" (November 2025) shifted subnet emissions from being price-based to flow-based -- measuring net TAO inflows (staking minus unstaking). Subnets with negative net flows receive zero emissions. This combats wash trading and pump-and-dump dynamics.

*How Tenzro handles this:* Tenzro's QoS-weighted rewards (uptime multiplier) reach a similar goal. Providers that go offline or perform poorly see rewards decrease toward zero, while active providers earn full rewards.

**3. Stable provider economics are essential**

io.net's IDE targets USD-equivalent payouts to GPU providers regardless of token price volatility. Two vault system (Reward Vault + Fee Vault) buffers against demand shocks and price crashes.

*How Tenzro handles this:* Tenzro's MPP integration enables stablecoin-denominated sessions (users pay in USDC, providers receive TNZO equivalent). The settlement engine handles conversion. This provides price stability for providers without requiring protocol-level vaults.

**4. HTTP 402 payments are becoming the standard for machine-to-machine commerce**

MPP (Stripe + Tempo) has 100+ services and partnerships with Visa, Mastercard, and Shopify. x402 (Coinbase + Cloudflare) has 15M+ transactions across projects. Both operate on the HTTP 402 response code.

*How Tenzro handles this:* Tenzro carries native MPP and x402 support in its payment layer (`tenzro-payments`), so HTTP 402 challenge / credential / receipt flows are part of the chain's request path rather than a wallet plugin or middleware bolted on top.

**5. High staking APY is unsustainable**

Nosana offers up to 40% staking APY -- this is clearly unsustainable without proportional demand growth. Sentient's 2% annual emission is more conservative. The successful range in 2026 appears to be 2-8% APY.

*How Tenzro handles this:* Tenzro's 5% APY sits in the sustainable middle range, and the QoS multiplier ensures it is earned through active contribution rather than passive holding.

**6. Community-first allocation correlates with sustainability**

AO Computer (0% pre-mine), Bittensor (fair launch), and Sentient (65.55% community) demonstrate stronger long-term economics than protocols with heavy VC/team allocations and short vesting.

*How Tenzro handles this:* Tenzro targets 35-40% community allocation. This sits in a reasonable range; pushing toward 40-45% would further strengthen community alignment and is open to governance.

---

## 11. Sustainability Analysis

### The Sustainability Equation

A protocol is economically sustainable when its burn rate and fee revenue can fund operations indefinitely without relying on token sales from treasury reserves.

```
Sustainable when:
  Annual Burns >= Annual Inflation
  AND
  Treasury Revenue >= Annual Operating Cost
```

### Scenario Modeling

**Assumptions:**
- 30% staking ratio (300M TNZO staked)
- 5% APY staking rewards
- 400ms blocks (~78.8M blocks/year theoretical maximum; scenarios below assume realistic average load, not peak)

#### Scenario A: Low Adoption (Year 1-2)

```
Annual settled volume: $50M
Annual transactions: 1M (avg 5,000 gas, base fee 1 gwei)

Inflation:
  Staking rewards: 300M * 5% = 15M TNZO

Burns:
  EIP-1559 gas: 5,000 * 1 gwei * 1M = 0.005 TNZO/year (negligible)
  Commission: $50M * 0.015% = ~$7,500 in TNZO

Net: INFLATIONARY (-14.99M TNZO/year, ~1.5% of supply)

Treasury revenue: $50M * 0.2% = $100K + staking fee
Status: Requires supplementary funding from initial allocation
```

**Mitigation:** This is expected and acceptable in early growth. The 25% treasury allocation provides runway. Bittensor, Render, and AO all subsidized early growth from allocations.

#### Scenario B: Medium Adoption (Year 3-4)

```
Annual settled volume: $5B
Annual transactions: 50M (avg 15,000 gas, base fee 5 gwei)

Inflation:
  Staking rewards: 300M * 5% = 15M TNZO

Burns:
  EIP-1559 gas: 15,000 * 5 gwei * 50M = 3.75M TNZO/year
  Commission: $5B * 0.015% = $750K in TNZO (~1.5M TNZO at $0.50)

Net: SLIGHTLY INFLATIONARY (-9.75M TNZO/year, ~0.98%)

Treasury revenue: $5B * 0.2% = $10M + 1M TNZO staking fee
Status: Treasury self-sustaining, approaching deflationary break-even
```

#### Scenario C: High Adoption (Year 5+)

```
Annual settled volume: $100B
Annual transactions: 500M (avg 15,000 gas, base fee 30 gwei)

Inflation:
  Staking rewards: 400M * 5% = 20M TNZO

Burns:
  EIP-1559 gas: 15,000 * 30 gwei * 500M = 225M TNZO/year
  Commission: $100B * 0.015% = $15M in TNZO

Net: STRONGLY DEFLATIONARY (+205M TNZO burned net)
Effective annual supply reduction: ~20.5%

Treasury revenue: $100B * 0.2% = $200M + staking fee
Status: Fully self-sustaining, significant deflationary pressure
```

### Comparison to Proven Models

| Protocol | Break-even Status | Revenue Model |
|----------|-------------------|---------------|
| Ethereum | Net deflationary since EIP-1559 + merge | Gas burns > PoS issuance |
| Render | Not yet deflationary | BME burns < Year 1 emissions |
| Akash | Too early (BME launched March 2026) | $8-12K/day compute revenue |
| io.net | IDE targeting 50%+ burn | $20M+ in leases since launch |
| **Tenzro** | Break-even at ~$5B annual settled volume | Dual-burn + commission revenue |

---

## 12. Supply and Distribution

### Token Allocation

| Allocation | Percentage | Amount | Vesting |
|------------|-----------|--------|---------|
| Community | 35% | 350M | Phased distribution over epochs |
| Treasury | 25% | 250M | Multisig-controlled, governance grants |
| Provider Incentives | 15% | 150M | Reward pool for staking/operations |
| Team | 10% | 100M | 4-year vest, 1-year cliff |
| Investors | 10% | 100M | 4-year vest, 1-year cliff |
| Liquidity | 5% | 50M | DEX liquidity, exchange listings |

### Comparison to Peer Allocations

| Protocol | Community | Team | Investors | Notes |
|----------|-----------|------|-----------|-------|
| AO | 100% | 0% | 0% | Pure fair launch |
| Bittensor | ~100% | 0% | 0% | Fair launch (mining) |
| Sentient | 65.55% | 22% | 12.45% | 6-year team vest |
| Vana | 44%+ | N/A | N/A | Community rewards |
| SaharaAI | 64%+ | N/A | N/A | Ecosystem growth |
| **Tenzro** | **35%** | **10%** | **10%** | 4-year vest, 1-year cliff |

Tenzro's 35% community allocation is on the lower end of 2026 norms. The 25% treasury effectively serves community purposes (grants, ecosystem development), bringing effective community + ecosystem allocation to 60%.

### Inflation Schedule

| Phase | Inflation Source | Rate | Mechanism |
|-------|-----------------|------|-----------|
| Year 1-2 | Staking rewards from Provider Incentives pool | ~5% on staked | Fixed pool, not new mint |
| Year 3+ | Staking rewards (if pool depleted, governance votes on inflation) | Governance-determined | Requires proposal, quorum, vote |
| Steady state | Targeted 2% max | Governance cap | Burns expected to offset |

The initial Provider Incentives pool (150M TNZO) funds staking rewards without minting new tokens for approximately 10 years at 5% APY on 300M staked TNZO (15M/year from pool). This is a critical design choice: early rewards come from allocation, not inflation, preventing the dilution spiral that plagues many protocols.

---

## 13. Governance Economics

### Governance Parameters

| Parameter | Value | Source |
|-----------|-------|--------|
| Min proposal stake | 10,000 TNZO | `tenzro-token/governance.rs` |
| Voting duration | 7 days (configurable per proposal) | `tenzro-token/governance.rs` |
| Quorum | 20% of total supply | Governance config |
| Approval threshold | Simple majority (votes_for > votes_against) | `tenzro-token/governance.rs` |
| Vote delegation | Supported (cascading aggregation) | `tenzro-token/governance.rs` |

### Proposal Types

1. **ParameterChange** -- Adjust protocol constants (fee rates, staking params, gas limits)
2. **TreasuryGrant** -- Fund ecosystem development from treasury
3. **ProtocolUpgrade** -- Approve code changes and hard forks
4. **ValidatorChange** -- Add or remove validators from the active set

### Sybil Resistance

Governance voting power is verified against actual staked balance, not self-reported. This prevents the vulnerability identified in the production audit where `vote()` accepted `voting_power` as an unverified parameter.

### Economic Cost of Governance Attack

To control governance (>50% of voting power), an attacker would need to stake >50% of the voting supply. At a 30% staking ratio and $1 TNZO price, this requires ~$150M in TNZO -- plus the attacker faces 7-day unbonding risk and slashing exposure. This makes governance attacks economically irrational at scale.

---

## 14. What Tenzro Does Differently in Token Economics

### 1. Burns From Two Independent Channels

Tenzro burns TNZO from two demand sources at once: an EIP-1559 base-fee burn on every transaction (infrastructure demand) and a 30% burn of the 0.5% network commission on AI inference and TEE service payments (service demand). Render, Akash, and io.net each run a single burn-mint channel; Tenzro runs two, so a slowdown in either does not collapse the deflationary pressure.

### 2. Settles Agent Payments Natively in HTTP 402

The MPP and x402 protocols live inside `tenzro-payments` and are reachable from the chain's RPC, MCP, and A2A surfaces. The chain itself speaks HTTP 402 challenge / credential / receipt — agents do not need a wallet plugin or middleware to participate. Most AI-token protocols (Bittensor, Render, Akash, io.net) do not have a native agent-payment standard; the chains that do typically wire it through the application layer.

### 3. Treats Hardware-Attested Compute as a Consensus Primitive

HotStuff-2 BFT gives TEE-attested validators 2x leader-selection weight, and the EVM exposes `TEE_VERIFY` as a precompile that consumes real Intel TDX, AMD SEV-SNP, AWS Nitro, or NVIDIA GPU CC quotes. This puts confidential agent compute in the trust path of consensus rather than next to it as a sidecar.

### 4. Runs EVM, SVM, and Canton/DAML in the Same Chain

The Multi-VM runtime executes Solidity, Solana BPF, and DAML contracts under one settlement layer. Akash, io.net, and Render each settle on a single VM (Cosmos / Solana / Solana respectively); Tenzro can settle agent-economy flow on the same chain that holds enterprise RWA contracts.

### 5. Auto-Provisions Identity, Wallet, and Payment Capability in One RPC

`tenzro_participate` returns a TDIP DID, an MPC threshold wallet, a hardware profile, and the protocol bindings needed for MPP / x402 / native settlement in a single round-trip. The identity stack (`tenzro-identity`), wallet stack (`tenzro-wallet`), and payment stack (`tenzro-payments`) are integrated rather than offered as three independent products.

### 6. Publishes Its Foundational Protocols as Public Standards

Tenzro's identity (TDIP), token (CAIP-2 `tenzro` namespace, SLIP-44 1414421071, W3C `did:tenzro`), and payment surfaces (MPP, x402, ERC-8004, AP2) are filed upstream so other chains and tools can resolve and verify Tenzro entities without bespoke integration. The aim is the same role ERC-20 / ERC-721 played for DeFi: shared protocol primitives the rest of the ecosystem can build on.

### 7. Has a Live Testnet With Production-Quality Implementations

The Tenzro testnet is live on GCP (`tenzro-infra` project) with the following infrastructure:

- **3 validators** (StatefulSet) running HotStuff-2 consensus on GKE
- **1 RPC node** (Deployment) serving public JSON-RPC at `https://rpc.tenzro.network` (Chain ID: 1337)
- **Caddy reverse proxy** with TLS termination (external IP: 35.224.150.186)
- **6-node GKE cluster** (5x e2-medium validators + 1x e2-small RPC) in us-central1-a
- **Docker images** built via Cloud Build and stored in Artifact Registry (145.7MB)
- **Active P2P networking** with libp2p peer discovery (Kademlia DHT), gossipsub messaging, and peer reputation tracking

The core infrastructure crates are production-quality implementations (testnet-ready):

| Layer | Crate | Implementation |
|-------|-------|---------------|
| Cryptography | tenzro-crypto | FROST MPC (Shamir SSS over GF(256)), BLS12-381 via `blst`, Ed25519 via `ed25519-dalek`, Secp256k1 via `k256`, Argon2id KDF, AES-256-GCM |
| Storage | tenzro-storage | RocksDB with 15+ column families, Merkle Patricia Trie with proof generation |
| Consensus | tenzro-consensus | HotStuff-2 BFT with PREPARE/COMMIT/DECIDE, TEE-weighted leader selection, epoch management, equivocation detection with automatic slashing |
| VM Execution | tenzro-vm | EVM via `revm`, SVM via `solana_rbpf`, Block-STM parallel execution, EIP-1559 fee market, ERC-4337 account abstraction |
| Wallet | tenzro-wallet | Argon2id + AES-256-GCM encrypted keystore, MPC threshold signing |
| Identity | tenzro-identity | W3C DID Documents, verifiable credentials, delegation scopes, cascading revocation |
| Token Economics | tenzro-token | TNZO 18-decimal arithmetic, staking/slashing (with equivocation detection), stTNZO liquid staking, governance, treasury with multisig |
| Networking | tenzro-network | libp2p with gossipsub topics, Kademlia DHT, peer manager |

The token, in other words, runs on a working consensus engine and VM execution layer today rather than ahead of one.

---

## 15. Strategic Recommendations

Based on the 2026 token-economy landscape (§10) and the sustainability modeling above, the following recommendations keep TNZO tokenomics sustainable and well-fitted to the AI and agentic era:

### R1: Implement Adaptive Commission Rate

The current 0.5% flat commission rate should become adaptive based on network utilization:

```
if utilization > 80%: commission = 0.5% (current)
if utilization < 20%: commission = 0.25% (attract volume)
if utilization > 95%: commission = 1.0% (premium pricing)
```

This follows the EIP-1559 philosophy of dynamic pricing applied to the service layer.

### R2: Add Inference Burn (BME Enhancement)

Beyond the existing commission burn, implement a direct burn on inference settlement:

```
When user pays for AI inference:
  1. 0.5% network commission (existing)
  2. Of the provider payment: X% burned, (100-X)% to provider

  X = governance-determined burn rate (suggested: 1-2%)
```

This creates a third burn channel directly tied to AI compute demand, making TNZO more strongly deflationary as inference volume grows.

### R3: Provider Stabilization Vault

Adopt io.net's vault concept to buffer provider payouts during TNZO price volatility:

```
Reward Vault: 5% of treasury reserved for provider payout stabilization
Fee Vault: 5% of treasury reserved for price crash cushion

When TNZO price drops >30% in 7 days:
  Provider payouts supplemented from Reward Vault
  to maintain USD-equivalent earnings
```

This prevents provider churn during market downturns -- the primary failure mode for DePIN protocols.

### R4: Increase Community Allocation

Current 35% community allocation is below the 2026 norm (AO 100%, Sentient 65.55%, Vana 44%, SaharaAI 64%). Consider:

- Move 5% from Liquidity (5% --> 2%) and Investor (10% --> 8%) to Community (35% --> 40%)
- Or implement a community mining program where running a Tenzro node earns TNZO from the Provider Incentives pool (similar to Bittensor subnet mining)

### R5: Implement Epoch-Based Emission Reduction

Rather than fixed 5% APY forever, implement automatic emission reduction:

```
Year 1-2: 5% APY (bootstrap)
Year 3-4: 4% APY (if burn_rate > 50% of issuance)
Year 5-6: 3% APY (if burn_rate > 75% of issuance)
Year 7+:  2% APY (steady state, matching Sentient's 2% cap)

Trigger: Governance can accelerate or delay based on network metrics
```

This follows the pattern of Bittensor (halving), io.net (disinflationary from 8%), and ICP (targeting <3% by end 2026).

### R6: Publish Real-Time Economics Dashboard

Following Render (stats.renderfoundation.com) and io.net ($20M+ leases tracked publicly), publish:

- TNZO burned vs. minted (daily, cumulative)
- Inference requests settled per day
- TEE attestations verified per day
- Provider uptime and QoS scores
- Treasury balance and revenue breakdown
- stTNZO exchange rate history
- Micropayment channel volume

Real usage metrics build credibility. Protocols that publish metrics (Render, io.net, Akash) attract more serious participants than those that don't.

### R7: Agent-First Fee Design

Design fee structures specifically for autonomous agents:

```
Human user: Standard pricing (gas + 0.5% commission)
Agent (TDIP-verified): Reduced commission (0.3%) for high-volume
Agent-to-agent: Micropayment channel preferred (no per-tx gas)
Batch settlement: Volume discount (0.25% for >1000 settlements/day)
```

This recognizes that in the agentic era, the majority of transactions will be machine-to-machine. Competitive pricing for agents drives volume, and volume drives burns.

### R8: Governance-Controlled Parameters

The following parameters should be adjustable via governance proposals:

| Parameter | Current | Governance Range |
|-----------|---------|-----------------|
| Network commission | 0.5% | 0.1% - 2.0% |
| Commission burn share | 30% | 20% - 50% |
| Treasury share | 40% | 20% - 50% |
| Staker share | 30% | 20% - 50% |
| Min stake | 1,000 TNZO | 100 - 100,000 TNZO |
| Staking APY | 5% | 1% - 10% |
| Liquid staking fee | 10% | 5% - 20% |
| Unbonding period | 7 days | 3 - 28 days |

This allows the protocol to adapt to market conditions without hard forks.

---

## Appendix A: Key Protocol Constants

| Constant | Value | Crate |
|----------|-------|-------|
| ONE_TNZO | 10^18 | tenzro-token |
| MAX_SUPPLY | 1,000,000,000 TNZO | tenzro-token |
| NETWORK_FEE_BPS | 50 | tenzro-settlement |
| TREASURY_SHARE_BPS | 4,000 | tenzro-token |
| BURN_SHARE_BPS | 3,000 | tenzro-token |
| STAKER_SHARE_BPS | 3,000 | tenzro-token |
| MIN_STAKE | 1,000 TNZO | tenzro-token |
| UNBONDING_PERIOD | 604,800,000 ms (7 days) | tenzro-token |
| REWARD_RATE_BPS | 500 (5% APY) | tenzro-token |
| EPOCH_DURATION | 14,400 blocks | tenzro-token |
| STTNZO_PROTOCOL_FEE | 1,000 bps (10%) | tenzro-token |
| MIN_DEPOSIT_STTNZO | 0.1 TNZO | tenzro-token |
| MAX_GAS_LIMIT | 30,000,000 | tenzro-vm |
| TARGET_GAS | 15,000,000 | tenzro-vm |
| INITIAL_BASE_FEE | 1 Gwei | tenzro-vm |
| MIN_BASE_FEE | 0.1 Gwei | tenzro-vm |
| MAX_BASE_FEE | 1,000 Gwei | tenzro-vm |
| CHALLENGE_PERIOD | 86,400,000 ms (24 hours) | tenzro-settlement |
| MIN_SETTLEMENT | 1,000 units | tenzro-settlement |
| MAX_BATCH_SIZE | 100 | tenzro-settlement |
| MIN_PROPOSAL_STAKE | 10,000 TNZO | tenzro-token |

## Appendix B: Fee Flow Diagram

```
                         User/Agent Pays for Service
                                    |
                    ________________|________________
                   |                                 |
            Gas Transaction                   Service Payment
            (EIP-1559)                        (AI/TEE/Agent)
                   |                                 |
           ________|________                   ______|______
          |                 |                 |             |
     Base Fee          Priority Fee      0.5% Network   99.5% to
     BURNED            to Validators     Commission     Provider
                                              |
                                    __________|__________
                                   |          |          |
                                 40%        30%        30%
                               Treasury    BURNED    Stakers
                                   |
                          _________|_________
                         |                   |
                    Grants/Ops          Protocol Dev
                    (governance)        (liquid staking
                                         fee: 10%)

                    BURN CHANNELS:
                    1. EIP-1559 base fee (demand-driven, unlimited)
                    2. 30% of network commission (0.015% of settled volume)
                    3. Slashed stake (punitive, event-driven)
```

## Appendix C: Where TNZO Sits on Three Axes

```
                     Low Fee <-----------> High Fee
                        |                     |
    Tenzro (0.5%) ------+                     |
    Akash (1-2%) -------+                     |
                        |                     |
                        |            Akash proposed (20%) +
                        |            Apple (30%) ---------+

                    Passive Staking <-----> QoS-Based
                        |                     |
    Nosana (40% APY) ---+                     |
                        |                     |
    Tenzro (5% + QoS) ---------+              |
    Sentient (2%) ------+------+              |
                        |      |              |
                        | Bittensor (flow) ---+
                        | io.net (IDE) -------+
                        | Grass (QoS) --------+

                    Single Burn <----------> Multi Burn
                        |                     |
    Render (BME) -------+                     |
    Akash (BME) --------+                     |
    io.net (IDE) -------+                     |
                        |                     |
                        |     Tenzro (EIP-1559 + commission + slash) +
```

---

*This document is versioned with the Tenzro Network codebase. All parameters reference implementation in `crates/tenzro-token`, `crates/tenzro-settlement`, `crates/tenzro-vm`, and `crates/tenzro-payments`. Governance can adjust any parameter listed in Appendix A via on-chain proposal.*
