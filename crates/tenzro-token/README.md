# tenzro-token

TNZO token economics for the Tenzro Network: read models of balances, stakes and the treasury, rewards, vesting, and the governed economic policy.

## Overview

`tenzro-token` implements the economic layer of the Tenzro Network. The crate provides the TNZO native token (18-decimal precision), read models of the stakes and bonds that consensus enforces, the network-policy state that on-chain governance (in `tenzro-vm`) changes, the treasury read model, reward distribution and vesting. There is no liquid staking token.

## Modules

- `tnzo` - native TNZO balance read model (18-decimal precision)
- `treasury` - fee-accounting read model of the keyless network treasury
- `rewards` - work-gated reward distribution
- `fee_distribution` - fee routing and distribution
- `vesting` - vesting schedules for non-fee TNZO flows
- `economic_policy` - the live, governance-settable economic policy
- `validator_registry` - permissionless validator registry and active-set membership
- `cross_vm` - cross-VM token types and decimal conversion (native 18-decimal to SPL 9-decimal)
- `registry` - token metadata index over consensus state
- `adaptive_burn` - governance dial over EIP-1559 burn fractions and supply targets
- `bond` - AgentBond constants and addresses
- `error` - error types

## Key Features

- **TNZO Token**: 18-decimal native token for gas, settlement, staking, and governance. TNZO moves only in block execution.
- **Stakes and slashing**: bonded per role with a signed `Stake` transaction and enforced in consensus (`tenzro-vm` native executors); this crate keeps read models only.
- **Treasury**: keyless; only an enacted governance proposal moves its funds.
- **Rewards**: work-gated epoch reward distribution to validators and providers.
- **Cross-VM tokens**: one native balance seen from the EVM and SVM, with safe decimal conversion.
- **Adaptive burn governance dial**: `BurnRateConfig` (base and local fee burn bps), `SupplyTargets` (rolling-window epochs, neutral band, alarms, magnitude caps, whether alarm proposals take governance's expedited track), `SupplyMetricsSnapshot`, and `BurnRateConfigManager` write-through to `CF_TOKENS` under `burn_rate:current` / `burn_targets:current` / `burn_metrics:latest`. Pure transfer function `compute_recommendation(metrics, targets) -> BurnRateRecommendation` returns `RecommendationAction::{Disabled, NoChange, IncreaseBurnPct, DecreaseBurnPct, AlarmHighInflation, AlarmHighDeflation}` with magnitude bps capped at `magnitude_cap_normal_bps` (default 200) or `magnitude_cap_alarm_bps` (default 100). Surfaced via `tenzro_getBurnRateConfig`, `tenzro_getSupplyMetrics`, `tenzro_getBurnRateRecommendation`; burn-dial proposals are `policy_update` proposals listed by `tenzro_listProposals`.
- **RocksDB Persistence**: Token supply, staking state, balances, adaptive-burn dial, and AgentBond stakes backed by CF_ACCOUNTS / CF_TOKENS

## Parameters

Fees, fee splits, stake amounts and unbonding windows are governed network parameters (`economic_policy` and the consensus parameter set), not crate constants.

## Usage

### Token Operations

```rust
use tenzro_token::tnzo::{RocksDbBackend, TnzoToken};

// The native balances as block execution left them. TNZO moves only in
// block execution, so the read model has no writer.
let token = TnzoToken::new(Arc::new(RocksDbBackend::new(store)));
let balance = token.balance_of(&address);
```

### Stakes

Stakes, bonds and slashes live in consensus (`tenzro-vm` native executors):
an account bonds stake per role with a signed `Stake` transaction, and every
slash funds the insurance pool. This crate holds only read models of the
agent and compute bonds, filled by replaying the chain's logs.

### Treasury

The treasury is the keyless `network_treasury_address` in consensus state.
No key, administrator or multisig withdraws from it: only an enacted governance
proposal (a treasury grant, tranche or recovery) moves
its funds, after the proposal's timelock and any Foundation steward veto
window. `NetworkTreasury` here is a fee-accounting read model.

## Testing

Run tests with:

```bash
cargo test -p tenzro-token
```

Unit tests cover the treasury, rewards, vesting and adaptive-burn paths.

## Production Status

Components:
- RocksDB-persisted token supply and balances via CF_ACCOUNTS
- Keyless treasury read model; withdrawals only by enacted governance
- Adaptive burn dial with read-only RPC surface, write-through persistence, EIP-1559 fee-market consumer, `AutoProposalGenerator` (its drafts go to on-chain governance), and `SupplyMetricsSnapshot` aggregator (base-fee burn + slash inflow)

## Dependencies

- `tenzro-types` - Core types
- `tenzro-storage` - RocksDB persistence
- `tokio` - Async runtime
- `dashmap` - Concurrent hash maps
- `parking_lot` - High-performance locks

## License

Apache-2.0.
