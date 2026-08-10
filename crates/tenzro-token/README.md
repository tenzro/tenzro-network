# tenzro-token

TNZO token economics for the Tenzro Network, including staking, governance, treasury, rewards, and liquid staking.

## Overview

`tenzro-token` implements the economic layer of the Tenzro Network. The crate provides the TNZO native token (18-decimal precision), staking mechanisms for validators and providers, on-chain governance, treasury management, reward distribution, and liquid staking (stTNZO) for capital efficiency.

## Modules

- `tnzo` - TNZO token implementation with 18-decimal precision
- `staking` - Validator and provider staking with slashing
- `governance` - On-chain proposal creation and voting
- `treasury` - Multi-asset treasury with multisig withdrawals
- `rewards` - Epoch-based reward distribution
- `fee_distribution` - Fee routing and distribution logic
- `liquid_staking` - stTNZO liquid staking pool with rebasing exchange rate
- `cross_vm` - Cross-VM token operations (wTNZO pointer model)
- `registry` - Unified token registry across VMs
- `erc7802` - Cross-chain token manager (ERC-7802)
- `erc3643` - Compliance registry (ERC-3643)
- `adaptive_burn` - Governance dial over EIP-1559 burn fractions and supply targets
- `seed_agent` - SeedAgent treasury earmark, charter registry, monthly decay schedule
- `bond` - AgentBond stake registry and insurance claim pool
- `burn_quota` - Per-epoch burn quota accounting
- `error` - Error types

## Key Features

- **TNZO Token**: 18-decimal native token for gas, settlement, staking, and governance
- **Staking**: Validator and provider staking with minimum stake requirements, unbonding periods, and slashing (10% penalty on equivocation)
- **Governance**: On-chain proposals with weighted voting based on staked tokens
- **Treasury**: Multi-asset fee accumulation with multisig withdrawal controls
- **Rewards**: Epoch-based reward distribution to validators, providers, and stakers
- **Liquid Staking (stTNZO)**:
  - Rebasing exchange rate tracking staking rewards
  - Multi-validator delegation for diversification
  - Protocol fee (default 10%, configurable via DEFAULT_PROTOCOL_FEE_BPS = 1000 basis points)
  - 7-day unbonding period (604,800 seconds)
  - Overflow-safe u128 arithmetic with quotient/remainder decomposition
- **Cross-VM Token Architecture**: Sei V2 pointer model with wTNZO ERC-20, SPL adapter, CIP-56 DAML template
- **Adaptive burn governance dial**: `BurnRateConfig` (base/local/paymaster bps with paymaster locked at 100%), `SupplyTargets` (rolling-window epochs, neutral band, alarms, magnitude caps, fast-track timelock), `SupplyMetricsSnapshot`, and `BurnRateConfigManager` write-through to `CF_TOKENS` under `burn_rate:current` / `burn_targets:current` / `burn_metrics:latest`. Pure transfer function `compute_recommendation(metrics, targets) -> BurnRateRecommendation` returns `RecommendationAction::{Disabled, NoChange, IncreaseBurnPct, DecreaseBurnPct, AlarmHighInflation, AlarmHighDeflation}` with magnitude bps capped at `magnitude_cap_normal_bps` (default 200) or `magnitude_cap_alarm_bps` (default 100). Surfaced via `tenzro_getBurnRateConfig`, `tenzro_getSupplyMetrics`, `tenzro_getBurnRateRecommendation`, `tenzro_listAdaptiveBurnProposals`.
- **SeedAgent treasury earmark**: `TreasuryEarmark` singleton (genesis-funded TNZO allocation, decay schedule, `enabled` master switch, `surplus_burn_bps` sunset disposition), `Charter` (governance-signed mandate enumerating `OperationKind::{InferenceConsumer, TaskMarketplaceConsumer, TemplateInstantiator, BridgeUser, SettlementProbe, Settler7683Probe, DisputeFiler}`, `SpendCaps`, `TargetThroughput`, `CounterpartyFilter`, sunset, enabled flag), `DecaySchedule` (default 100/100/100 months 0-2 → 75 months 3-5 → 50 months 6-8 → 25 months 9-11 → 0 from month 12), `SeedAgentRecord` (per-DID provisioning state with `SeedAgentStatus::{Active, Paused, Quarantined, Terminated}`), and `SeedAgentEarmarkManager` write-through to `CF_TOKENS` under `seed_earmark:singleton` / `seed_charter:<id>` / `seed_agent:<did>`. Surfaced via `tenzro_getTreasuryEarmark`, `tenzro_getSeedAgentCharter`, `tenzro_listSeedAgentCharters`, `tenzro_listSeedAgents`, `tenzro_getNetworkActivity`.
- **RocksDB Persistence**: Token supply, staking state, balances, adaptive-burn dial, SeedAgent registry, and AgentBond stakes backed by CF_ACCOUNTS / CF_TOKENS

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| Default network fee | 0.5% | Network commission on AI/TEE payments |
| Community allocation | 35-40% | Community token allocation |
| stTNZO decimals | 18 | Liquid staking token decimals |
| Liquid staking protocol fee | 10% (1000 bps) | Protocol fee on staking rewards |
| Unbonding period | 7 days (604,800 sec) | Time to wait before withdrawal |

## Usage

### Token Operations

```rust
use tenzro_token::tnzo::TnzoToken;

let token = TnzoToken::new()?;

// Check balance
let balance = token.balance_of(&address)?;

// Transfer tokens
token.transfer(from, to, amount)?;
```

### Staking

```rust
use tenzro_token::staking::StakingManager;

let min_stake = 1_000_000_000_000_000_000_000; // 1000 TNZO
let staking = StakingManager::new(min_stake);

// Stake tokens
staking.stake(validator_address, amount)?;

// Unstake (initiates unbonding period)
staking.unstake(validator_address, amount)?;

// Withdraw after unbonding period
staking.withdraw(validator_address)?;

// Slash misbehaving validator (10% penalty)
staking.slash(validator_address, slash_amount, reason)?;
```

### Governance

```rust
use tenzro_token::governance::{GovernanceEngine, Proposal, ProposalType};

let governance = GovernanceEngine::new();

// Create proposal
let proposal = Proposal {
    proposal_type: ProposalType::ParameterChange,
    title: "Increase minimum stake".to_string(),
    description: "Proposal to increase min stake to 2000 TNZO".to_string(),
    proposer: proposer_address,
    ..Default::default()
};
let proposal_id = governance.create_proposal(proposal)?;

// Vote (voting power = staked tokens)
governance.vote(proposal_id, voter_address, voting_power, true)?;

// Execute if passed
if governance.has_passed(proposal_id)? {
    governance.execute(proposal_id)?;
}
```

### Liquid Staking

```rust
use tenzro_token::liquid_staking::LiquidStakingPool;

let pool = LiquidStakingPool::new(
    "stTNZO".to_string(),
    1000, // 10% protocol fee (basis points)
    604_800, // 7 day unbonding
)?;

// Deposit TNZO, receive stTNZO
let st_tnzo_minted = pool.deposit(depositor, tnzo_amount)?;

// Request withdrawal (initiates unbonding)
let withdrawal_id = pool.request_withdrawal(user, st_tnzo_amount)?;

// Complete withdrawal after unbonding period
let tnzo_returned = pool.complete_withdrawal(withdrawal_id)?;

// Check exchange rate (stTNZO:TNZO)
let rate = pool.exchange_rate()?;
```

### Treasury

```rust
use tenzro_token::treasury::NetworkTreasury;

let required_approvals = 3;
let treasury = NetworkTreasury::new(treasury_address, required_approvals);

// Propose withdrawal
let withdrawal_id = treasury.propose_withdrawal(
    asset,
    amount,
    recipient,
    proposer
)?;

// Approvers vote
treasury.approve_withdrawal(withdrawal_id, approver1)?;
treasury.approve_withdrawal(withdrawal_id, approver2)?;
treasury.approve_withdrawal(withdrawal_id, approver3)?;

// Execute when threshold reached
treasury.execute_withdrawal(withdrawal_id)?;
```

## Testing

Run tests with:

```bash
cargo test -p tenzro-token
```

Unit tests cover the treasury, staking, governance, rewards, vesting, and liquid-staking paths.

## Production Status

Components:
- RocksDB-persisted token supply and balances via CF_ACCOUNTS
- Stake-weighted governance with real voting power tracking
- Multisig treasury with approval threshold enforcement
- Liquid staking with overflow-safe u128 arithmetic
- Adaptive burn dial with read-only RPC surface, write-through persistence, EIP-1559 fee-market consumer, `AutoProposalGenerator`, and `SupplyMetricsSnapshot` aggregator (base-fee burn + slash inflow) wired through the governance executor
- SeedAgent treasury earmark with read-only RPC surface, write-through persistence, off-chain `SeedAgentDaemon` (6h poll + monthly refill + charter-sunset pause + leader-gate), governance-executor mutation paths, monthly decay enforcement at refill, sunset wind-down sweep (Paused → Quarantined → Terminated → surplus disposal), and the `tenzro/seed-agents` gossipsub topic

## Dependencies

- `tenzro-types` - Core types
- `tenzro-storage` - RocksDB persistence
- `tokio` - Async runtime
- `dashmap` - Concurrent hash maps
- `parking_lot` - High-performance locks

## License

Apache-2.0.
