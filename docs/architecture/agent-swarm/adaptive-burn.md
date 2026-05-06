# Adaptive Burn Governance

**Status:** Drafting (2026-05-04)
**Phase:** 3 (mainnet hardening)
**Touches:** `tenzro-token` (treasury, burn taper), `tenzro-vm` (EIP-1559 burn dial), `tenzro-model` (UsageTracker integration), `tenzro-node` (governance executor)

## Context

Tenzro genesis: 1 billion TNZO total supply. EIP-1559 base fee burn is the deflationary force. Inflation: staking rewards distributed to validators and providers per epoch. The intersection of these two — net supply curve — assumes a transaction volume profile typical of human-driven L1s.

Agent swarms break that assumption in both directions:

- **High M2M volume.** If autonomous agents drive 100× human volume, EIP-1559 burns at 100× the modeled rate. Supply turns sharply deflationary. Validators paid in TNZO see real-yield-in-TNZO grow, but TNZO itself becomes scarcer than the staking allocation assumed. Worst case: governance loses the ability to fund providers and treasury operations because the float is gone.

- **Low M2M volume after hype cycle.** If swarms underdeliver, burn is anemic, inflation dominates, supply expands faster than demand. Token value pressure.

Either failure mode is bad. Both can happen at different points in the same year. Static burn-rate multipliers calcify the problem.

The data to detect either condition exists in `UsageTracker` (already wired to `InferenceRouter` and the per-account fee market): we know transaction count, gas burned, fee distribution per epoch. What's missing is a feedback loop that adjusts the global burn taper based on those signals.

## Decision

A governance-controlled adaptive burn rate that:

1. Reads observed metrics each epoch from `UsageTracker` and the EIP-1559 burn ledger.
2. Computes a recommended burn-rate adjustment per a published transfer function.
3. Applies the recommendation **after a governance ratification window** — not automatically. The function is the proposal; governance is still the executor.
4. Caps adjustments per-epoch to bound volatility.

The token retains EIP-1559 in form; the **base fee burn fraction** becomes a governance-tunable dial that adapts to observed volume.

## Architecture

### Signal: NetSupplyDelta

Per epoch:

```
NetSupplyDelta(e) =
    + StakingRewards(e)
    + TreasuryEmissions(e)              // governance-approved spends from treasury
    - BaseFeeBurn(e)                    // EIP-1559 base fee burned
    - LocalFeeBurn(e)                   // Spec 6 local fees burned
    - PaymasterBurn(e)                  // Spec 3 USDC-paid → TNZO-burned
    - SlashedAndBurned(e)               // portion of slashes that burns vs goes to treasury
```

`NetSupplyDelta > 0` = inflationary epoch. `< 0` = deflationary. `= 0` = neutral.

We don't compute this from a price/value perspective — the chain has no oracle of "fair value" — only from circulating supply mechanics.

### Targets

Governance sets per-epoch and rolling-window targets:

```
SupplyTargets {
    epoch_neutral_band_pct:    f64,    // |NetSupplyDelta / Supply| < this → no action
    rolling_window_epochs:     u32,    // smoothing
    inflation_alarm_pct:       f64,    // sustained >this over window → alarm
    deflation_alarm_pct:       f64,    // sustained <this over window → alarm
    target_annual_supply_pct:  f64,    // long-run target (e.g., -1% to +2% / year)
}
```

Genesis defaults (governance-tunable):
- `epoch_neutral_band`: ±0.005% per epoch
- `rolling_window`: 90 epochs (~30 days at 8h epochs)
- `inflation_alarm`: +5% annualized
- `deflation_alarm`: −5% annualized
- `target_annual_supply`: 0% to +1% (slight inflation, paying providers from emission)

### Transfer function

The function `BurnTaperRecommendation(observations) → (action, magnitude)`:

```
input:
    rolling_supply_delta_pct   // annualized
    base_fee_burn_share         // BaseFeeBurn / NetSupplyDelta absolute denom
    paymaster_burn_share
    local_fee_burn_share
    target_annual_supply_pct

output:
    action: "no_change" | "decrease_burn_pct" | "increase_burn_pct" | "alarm"
    magnitude_bps:  i32   // proposed delta to base_fee_burn_pct, ±200bps max per epoch
```

Logic (informal):

```
delta = rolling_supply_delta_pct - target_annual_supply_pct

if |delta| < epoch_neutral_band:
    return ("no_change", 0)

if delta > inflation_alarm:
    return ("alarm", "high_inflation")

if delta < -deflation_alarm:
    return ("alarm", "high_deflation")

# steady-state proportional adjustment
# inflationary → burn more → increase burn pct
# deflationary → burn less → decrease burn pct
magnitude = min(200, abs(delta) * gain)
direction = "increase_burn_pct" if delta > 0 else "decrease_burn_pct"
return (direction, magnitude * sign(delta))
```

`gain` is governance-tunable, default 50bps-per-1%-deviation. A 4% over-target deviation produces a 200bps proposed change (capped). The cap is the per-epoch volatility bound.

### Burn-rate dial

Today EIP-1559 burns 100% of base fee. We make this a governance dial:

```
BurnRateConfig {
    base_fee_burn_pct:        u16,   // 0..10000 bps. genesis: 10000 (100%)
    base_fee_treasury_pct:    u16,   // = 10000 - base_fee_burn_pct
    local_fee_burn_pct:       u16,   // genesis: 10000
    paymaster_burn_pct:       u16,   // genesis: 10000 (always burn TNZO from paymaster quota)
}
```

Constraint: each pair sums to 10000 (100%). Treasury receives the non-burn share.

The transfer function operates primarily on `base_fee_burn_pct` because that's the dominant burn flow. Local-fee and paymaster splits move only by explicit governance proposals, not by the auto-adjuster — they're smaller streams and fiddling with them adds noise.

### Governance pipeline

```
   epoch boundary
        │
        ▼
   ┌────────────────────────┐
   │ AdaptiveBurnObserver   │   computes NetSupplyDelta, calls transfer function
   └─────────┬──────────────┘
             │ recommendation
             ▼
   ┌────────────────────────┐
   │ AutoProposalGenerator  │   if magnitude > threshold, drafts a typed governance proposal
   └─────────┬──────────────┘
             │ proposal_id
             ▼
   ┌────────────────────────┐
   │ Governance              │   normal voting + timelock
   │ - quorum: simple majority │
   │ - timelock: 24h         │
   └─────────┬──────────────┘
             │ if passes
             ▼
   ┌────────────────────────┐
   │ BurnRateConfigUpdate   │   applied at next epoch boundary
   └────────────────────────┘
```

Key property: **the adjustment is NOT automatic.** The observer drafts a proposal; governance still has to ratify. The adjuster proposes; the chain disposes.

This is conservative on purpose — burn-rate autonomous loops have a history of being gamed (whoever controls the signal controls the dial). Governance-with-fast-track gets the responsiveness without the manipulability.

### Fast-track for alarm states

When the recommendation is `("alarm", reason)`:

- Auto-generates a proposal with **shortened 6h timelock** instead of 24h.
- Quorum drops to *participation* threshold (governance can act on what shows up rather than waiting for full quorum).
- Magnitude in alarm proposals is capped tighter (100bps, not 200bps) — alarm doesn't justify a big move, just a fast small one.

Alarm fast-track is itself a governance-tunable parameter. Disabling it falls back to ordinary 24h timelock.

### Anti-manipulation

The transfer function reads only on-chain state. There are several manipulable inputs:

- **Wash transactions** to inflate burn → trigger `decrease_burn_pct` proposals.
- **Provider stake manipulation** to spike rewards → trigger `increase_burn_pct` proposals.

Mitigations:
- **`UsageTracker` is per-controller-DID, not per-tx.** A wash farmer needs many controllers to evade. Each controller costs Verified-lane stake. The flow-control spec (Spec 2) puts a cost floor on wash volume.
- **Rolling window** smooths short-term spikes. A wash burst across 30 days is expensive.
- **Governance is in the loop.** A wash-driven recommendation that's clearly aberrant gets voted down.
- **Sanity check in the function:** if `rolling_supply_delta_pct` exceeds `2 × inflation_alarm` or `2 × deflation_alarm`, output `"alarm"` only — never auto-adjust on extreme readings.

### RPC surface

```
tenzro_getSupplyMetrics
    → {
        circulating_supply: u128,
        epoch_supply_delta: i128,
        rolling_window_supply_delta_pct: f64,
        target_annual_supply_pct: f64,
        burn_breakdown: { base_fee, local_fee, paymaster, slash },
        emission_breakdown: { staking_rewards, treasury_emissions },
      }

tenzro_getBurnRateConfig
    → { base_fee_burn_pct, base_fee_treasury_pct, local_fee_burn_pct, paymaster_burn_pct }

tenzro_getBurnRateRecommendation
    → { action, magnitude_bps, basis: SupplyMetricsSnapshot }

tenzro_listAdaptiveBurnProposals { window? }
    → [{ proposal_id, generated_at, action, magnitude_bps, status }]
```

CLI: `tenzro node supply-metrics`, `tenzro governance burn-rate`.

MCP: `get_supply_metrics`, `get_burn_rate_config` tools.

### Governance dial visibility

The current `BurnRateConfig` is part of the public chain state (CF_METADATA `burn_rate:current`). Wallets and dapps can read it to display "X% of fees burned" in their UI without guessing. Updates are typed events on a dedicated topic: `tenzro/burn-rate-changed`.

## Interaction with existing systems

- **`UsageTracker`** already has the volume signals (Inference, transfers, channel updates). We add aggregate views per epoch.
- **EIP-1559 base fee burn** is the dominant flow being adjusted. Existing path stays; the dial just gates the burn vs treasury split.
- **Local fee market (Spec 6)** burns are aggregated into the supply signal but adjusted independently (their split has its own dial).
- **Dual-rail gas (Spec 3)** paymaster burns are aggregated. The paymaster flow is "swap USDC for TNZO and burn" — that burn is real and should always be 100% (lowering the paymaster burn pct would mean USDC-paid gas stops eating TNZO supply, defeating the purpose). Function never recommends adjusting paymaster_burn_pct.
- **Slashing (Spec 1, Spec 9)** has its own slash-share-burn dial; not touched by this adjuster.
- **DA offload (Spec 7)** receipts don't change burn behavior; offloading is gas-neutral.

## PQ posture

Pure governance + on-chain math. No new signature surface.

## Governance dials

| Parameter | Genesis default | Notes |
|---|---|---|
| `enabled` | true | Master kill switch |
| `epoch_neutral_band_pct` | 0.005% | per-epoch |
| `rolling_window_epochs` | 90 | ~30 days |
| `inflation_alarm_pct` | 5% annualized | |
| `deflation_alarm_pct` | 5% annualized | |
| `target_annual_supply_pct` | 0–1% | range |
| `gain` | 50 bps per 1% deviation | |
| `magnitude_cap_normal_bps` | 200 | per epoch |
| `magnitude_cap_alarm_bps` | 100 | per alarm proposal |
| `auto_proposal_min_magnitude_bps` | 25 | below: skip generation |
| `alarm_fast_track_enabled` | true | |
| `alarm_timelock_hours` | 6 | vs 24 normal |
| `base_fee_burn_pct` | 10000 (100%) | initial value |
| `local_fee_burn_pct` | 10000 | |
| `paymaster_burn_pct` | 10000 (locked at 100%) | function never adjusts |

## Verification

1. **Neutral epoch:** epoch supply delta within neutral band — recommendation `no_change`, no proposal generated.
2. **Mild deflation:** rolling −2% annualized — recommendation `decrease_burn_pct` magnitude ~100bps, proposal generated, governance ratifies.
3. **Mild inflation:** rolling +2% annualized — `increase_burn_pct`, ratifies.
4. **Alarm threshold:** rolling −7% — `("alarm", "high_deflation")`, fast-track proposal with 6h timelock and 100bps cap.
5. **Extreme reading:** rolling −12% (2× alarm) — output forced to `alarm`, not auto-adjust.
6. **Magnitude cap:** would-be magnitude 400bps — capped to 200 (normal) or 100 (alarm).
7. **Ratification path:** auto-generated proposal goes through normal voting + timelock; rejection leaves config unchanged.
8. **Wash-detection robustness:** simulated wash trader inflates burn over 1 epoch — 90-epoch rolling window absorbs spike, no recommendation triggered.

## Out of scope

- **Bonding curve / market-maker.** Tenzro has no protocol-owned AMM for TNZO/USD. Adding one to "stabilize" supply is a different debate — out.
- **PI controller / RL-tuned gain.** Gain is a constant. PI/PID controllers are tunable later if simple proportional proves insufficient.
- **Per-application burn dials.** Apps that want to burn extra TNZO (e.g., as a sink for in-app activity) build their own contract burn paths. The adapter doesn't see them; their burn shows up as supply reduction in metrics. Apps don't get to override the chain-level dial.
- **Cross-chain TNZO supply.** TNZO bridged out via NTT is out of circulating supply on Tenzro and in circulation elsewhere. NetSupplyDelta computes Tenzro-side circulating; the foreign-side mirrors are visible via NTT manager state but don't enter this calc. This is correct — burns on Tenzro affect Tenzro supply; foreign supply is the bridge's accounting problem.
