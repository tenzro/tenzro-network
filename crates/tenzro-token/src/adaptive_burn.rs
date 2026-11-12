//! Adaptive burn governance dial.
//!
//! The design
//! describes an epoch observer that reads `UsageTracker` and the EIP-1559
//! burn ledger, computes a recommended adjustment to the protocol's
//! `base_fee_burn_pct` dial via a published transfer function, and
//! auto-drafts a typed governance proposal to apply it (with a fast-track
//! timelock when the recommendation is an alarm).
//!
//! This module lands the protocol-side primitives:
//!
//! - [`BurnRateConfig`] — the governance dials (base fee burn / treasury
//!   split, local fee burn). Persisted as a singleton in
//!   `CF_TOKENS/burn_rate:current`. Wallets, dapps, and the EIP-1559 fee
//!   market read this to decide where each TNZO base-fee chunk goes.
//! - [`SupplyTargets`] — governance-tunable target band, rolling window,
//!   alarm thresholds, gain. Persisted as a singleton in
//!   `CF_TOKENS/burn_targets:current`.
//! - [`SupplyMetricsSnapshot`] — observed metrics for an epoch (or rolling
//!   window). Persisted under `burn_metrics:latest`. The node's epoch
//!   observer aggregates burn flows (base fee, local fee) and any supply
//!   added into this shape at every epoch boundary. TNZO supply is fixed at
//!   genesis and the ledger refuses a block that adds to it, so supply only
//!   falls (by what fees burn) or holds; rewards are paid from the
//!   genesis-funded pool and leave total supply unchanged.
//! - [`compute_recommendation`] — the pure transfer function. Reads a
//!   snapshot + targets + gain, returns a [`BurnRateRecommendation`] with
//!   action and magnitude. Same input → same output, deterministic.
//! - [`BurnRateConfigManager`] — write-through manager mirroring
//!   the other token managers' pattern. Constructed in-memory for tests, with
//!   `Arc<dyn KvStore>` for production. Hydrates on construction.
//!
//! - [`AutoProposalGenerator`] — polls the recommendation and drafts a
//!   typed governance proposal when the dial should move. Spawned by the
//!   node alongside the governance executor.
//!
//! Block execution never reads this manager: `tenzro_vm::ledger::settle_block`
//! reads `base_fee_burn_bps` from the enacted `AdaptiveBurnConfigUpdate`
//! policy in consensus state at the end of every block, so only a governance
//! vote moves the burn-vs-treasury split of collected base fees. This manager
//! is the node's reflection of that enacted policy.
//!
//! Per-controller-DID wash-detection mitigation lives in the per-DID flow
//! control crate; this module reads aggregate metrics only.

use crate::error::{Result, TokenError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{CF_TOKENS, KvStore, WriteOp};
use tenzro_types::primitives::{BlockHeight, Timestamp};
use tracing::{debug, info};

// ---------- Storage keys -----------------------------------------------------

/// Singleton key for the live `BurnRateConfig` under `CF_TOKENS`.
pub const BURN_RATE_CONFIG_KEY: &[u8] = b"burn_rate:current";

/// Singleton key for the live `SupplyTargets` under `CF_TOKENS`.
pub const SUPPLY_TARGETS_KEY: &[u8] = b"burn_targets:current";

/// Singleton key for the latest `SupplyMetricsSnapshot` under `CF_TOKENS`.
pub const SUPPLY_METRICS_KEY: &[u8] = b"burn_metrics:latest";

// ---------- Genesis defaults (mirror adaptive-burn.md §"Governance dials") ---

/// Genesis: 100% of base fee is burned (0% to treasury).
pub const DEFAULT_BASE_FEE_BURN_BPS: u16 = 10_000;
/// Genesis: 100% of local fees are burned.
pub const DEFAULT_LOCAL_FEE_BURN_BPS: u16 = 10_000;

/// Genesis neutral band: 0.005% of supply per epoch (5bps).
pub const DEFAULT_NEUTRAL_BAND_BPS: u16 = 5;
/// Genesis rolling window: 90 epochs (~30 days at 8h epochs).
pub const DEFAULT_ROLLING_WINDOW_EPOCHS: u32 = 90;
/// Genesis supply-increase alarm: +5% annualized = 500 bps. The ledger
/// refuses any increase, so a reading above zero means a faulty observer or
/// ledger.
pub const DEFAULT_INFLATION_ALARM_BPS: u16 = 500;
/// Genesis deflation alarm: -5% annualized = 500 bps (magnitude).
pub const DEFAULT_DEFLATION_ALARM_BPS: u16 = 500;
/// Genesis target: a flat supply. TNZO supply is fixed at genesis, so the
/// target is never above zero: fees may burn, nothing mints.
pub const DEFAULT_TARGET_ANNUAL_SUPPLY_BPS: i32 = 0;
/// Genesis gain: 50bps adjustment per 1% deviation from target.
pub const DEFAULT_GAIN_BPS_PER_PCT: u16 = 50;
/// Genesis cap on per-epoch normal magnitude: 200 bps.
pub const DEFAULT_MAGNITUDE_CAP_NORMAL_BPS: u16 = 200;
/// Genesis cap on alarm-state magnitude: 100 bps (smaller, faster).
pub const DEFAULT_MAGNITUDE_CAP_ALARM_BPS: u16 = 100;
/// Genesis floor below which auto-proposals are skipped: 25 bps.
pub const DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS: u16 = 25;
/// Genesis: alarm proposals go on governance's expedited track.
pub const DEFAULT_ALARM_FAST_TRACK_ENABLED: bool = true;

// ---------- Types ------------------------------------------------------------

/// Live burn-rate dials. Each pair `*_burn_bps + *_treasury_bps` must sum to
/// 10_000 — the burn share is what's destroyed; the treasury share is what
/// flows to `NetworkTreasury`. Surfaces only the burn shares (the
/// treasury share is the complement) to keep the wire shape compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnRateConfig {
    /// 0..10_000. Genesis: 10_000 (100%). The transfer function adjusts
    /// this primarily.
    pub base_fee_burn_bps: u16,
    /// 0..10_000. Genesis: 10_000 (100%). Adjusted only by explicit
    /// governance proposals, never by the auto-adjuster.
    pub local_fee_burn_bps: u16,
}

impl Default for BurnRateConfig {
    fn default() -> Self {
        Self {
            base_fee_burn_bps: DEFAULT_BASE_FEE_BURN_BPS,
            local_fee_burn_bps: DEFAULT_LOCAL_FEE_BURN_BPS,
        }
    }
}

/// The burn/treasury split of a single fee amount (`burn + treasury == amount`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeSplit {
    /// Amount destroyed (burned).
    pub burn: u128,
    /// Amount routed to `NetworkTreasury`.
    pub treasury: u128,
}

impl FeeSplit {
    /// `burn + treasury`.
    pub fn total(&self) -> u128 {
        self.burn.saturating_add(self.treasury)
    }
}

/// Split `amount` by `burn_bps`: `burn = floor(amount * bps / 10_000)`, and
/// `treasury = amount - burn` so the two always sum to `amount` exactly — any
/// rounding dust goes to the treasury rather than being lost.
fn split_amount(amount: u128, burn_bps: u16) -> FeeSplit {
    let bps = burn_bps.min(10_000) as u128;
    let burn = amount.saturating_mul(bps) / 10_000;
    FeeSplit {
        burn,
        treasury: amount.saturating_sub(burn),
    }
}

impl BurnRateConfig {
    /// Split a base-fee amount into (burn, treasury) per `base_fee_burn_bps`.
    pub fn split_base_fee(&self, amount: u128) -> FeeSplit {
        split_amount(amount, self.base_fee_burn_bps)
    }
    /// Split a local-fee amount per `local_fee_burn_bps`.
    pub fn split_local_fee(&self, amount: u128) -> FeeSplit {
        split_amount(amount, self.local_fee_burn_bps)
    }

    /// Treasury share of base fee = 10_000 - burn share.
    pub fn base_fee_treasury_bps(&self) -> u16 {
        10_000_u16.saturating_sub(self.base_fee_burn_bps)
    }
    /// Treasury share of local fee = 10_000 - burn share.
    pub fn local_fee_treasury_bps(&self) -> u16 {
        10_000_u16.saturating_sub(self.local_fee_burn_bps)
    }

    /// Apply a delta (in bps, positive = increase burn) to `base_fee_burn_bps`.
    /// Clamps to `[0, 10_000]`. Returns the new config; does not mutate.
    pub fn with_base_fee_burn_delta(self, delta_bps: i32) -> Self {
        let new = (self.base_fee_burn_bps as i32 + delta_bps).clamp(0, 10_000) as u16;
        Self {
            base_fee_burn_bps: new,
            ..self
        }
    }

    /// Validate that all bps values are in `[0, 10_000]`.
    pub fn validate(&self) -> Result<()> {
        for (name, bps) in [
            ("base_fee_burn_bps", self.base_fee_burn_bps),
            ("local_fee_burn_bps", self.local_fee_burn_bps),
        ] {
            if bps > 10_000 {
                return Err(TokenError::InvalidParameter(format!(
                    "{} {} > 10000",
                    name, bps
                )));
            }
        }
        Ok(())
    }
}

/// Governance-tunable supply targets. All bps values are basis points
/// (1bps = 0.01%); `target_annual_supply_bps` is signed because the target
/// can be negative (supply falling by what fees burn). It is never above
/// zero: TNZO supply is fixed at genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupplyTargets {
    /// Master kill switch. When `false` the function returns
    /// [`RecommendationAction::Disabled`] regardless of metrics.
    pub enabled: bool,
    /// `|epoch_supply_delta / supply| < this` → no action.
    pub epoch_neutral_band_bps: u16,
    /// Smoothing window in epochs.
    pub rolling_window_epochs: u32,
    /// Sustained supply increase `> this` over window → alarm. The ledger
    /// refuses any increase, so this fires only on a fault.
    pub inflation_alarm_bps: u16,
    /// Sustained `< -this` over window → alarm. Stored as magnitude.
    pub deflation_alarm_bps: u16,
    /// Long-run target for net supply change, annualized: zero (flat) or
    /// negative (falling by what fees burn). Never positive.
    pub target_annual_supply_bps: i32,
    /// Gain on the proportional adjustment, in bps-per-1%-deviation.
    pub gain_bps_per_pct: u16,
    /// Per-epoch volatility cap on normal-state magnitude.
    pub magnitude_cap_normal_bps: u16,
    /// Per-alarm-proposal magnitude cap (smaller than normal cap by spec).
    pub magnitude_cap_alarm_bps: u16,
    /// Floor below which `compute_recommendation` skips proposal generation.
    pub auto_proposal_min_magnitude_bps: u16,
    /// True iff alarm proposals go on governance's expedited track: a
    /// shorter voting window and timelock, at a higher approval threshold.
    pub alarm_fast_track_enabled: bool,
}

impl Default for SupplyTargets {
    fn default() -> Self {
        Self {
            enabled: true,
            epoch_neutral_band_bps: DEFAULT_NEUTRAL_BAND_BPS,
            rolling_window_epochs: DEFAULT_ROLLING_WINDOW_EPOCHS,
            inflation_alarm_bps: DEFAULT_INFLATION_ALARM_BPS,
            deflation_alarm_bps: DEFAULT_DEFLATION_ALARM_BPS,
            target_annual_supply_bps: DEFAULT_TARGET_ANNUAL_SUPPLY_BPS,
            gain_bps_per_pct: DEFAULT_GAIN_BPS_PER_PCT,
            magnitude_cap_normal_bps: DEFAULT_MAGNITUDE_CAP_NORMAL_BPS,
            magnitude_cap_alarm_bps: DEFAULT_MAGNITUDE_CAP_ALARM_BPS,
            auto_proposal_min_magnitude_bps: DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS,
            alarm_fast_track_enabled: DEFAULT_ALARM_FAST_TRACK_ENABLED,
        }
    }
}

/// Breakdown of an epoch's burns. Sum becomes `BaseFeeBurn + LocalFeeBurn`
/// in the NetSupplyDelta formula; slashes are not burned, they
/// fund the insurance pool. Amounts are TNZO base units (1e18).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnBreakdown {
    pub base_fee: u128,
    pub local_fee: u128,
}

impl BurnBreakdown {
    pub fn total(&self) -> u128 {
        self.base_fee.saturating_add(self.local_fee)
    }
}

/// Supply an epoch added: the increasing side of the net supply change.
/// TNZO supply is fixed at genesis and the ledger refuses a block that adds
/// to it, so both figures read zero; rewards paid from the genesis-funded
/// pool move existing TNZO and are not counted here. The type and field
/// names are kept for readers of the stored snapshot and the RPC.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmissionBreakdown {
    /// Supply added at the epoch boundary.
    pub staking_rewards: u128,
    /// Supply added to the treasury; nothing writes it.
    pub treasury_emissions: u128,
}

impl EmissionBreakdown {
    pub fn total(&self) -> u128 {
        self.staking_rewards.saturating_add(self.treasury_emissions)
    }
}

/// Snapshot of supply mechanics for one epoch (or the latest rolling window
/// summary). Written by the epoch observer; read by the transfer function
/// and the `tenzro_getSupplyMetrics` RPC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupplyMetricsSnapshot {
    /// Block height at which this snapshot was taken.
    pub block_height: BlockHeight,
    /// Wall-clock timestamp of the snapshot.
    pub captured_at: Timestamp,
    /// Total TNZO in circulation at snapshot time.
    pub circulating_supply: u128,
    /// `Σ(supply added) - Σ(burns)` for the epoch. Signed: negative = the
    /// epoch burned TNZO. Stored as i128; with a fixed supply it is never
    /// positive.
    pub epoch_supply_delta: i128,
    /// Annualized rolling-window supply delta as a signed bps value.
    /// Same denominator as `target_annual_supply_bps` so they're directly
    /// comparable.
    pub rolling_window_supply_delta_bps: i32,
    pub burn_breakdown: BurnBreakdown,
    pub emission_breakdown: EmissionBreakdown,
}

/// What the transfer function recommends doing this epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationAction {
    /// Adjuster disabled by governance — no action.
    Disabled,
    /// Within the neutral band — no action.
    NoChange,
    /// Supply above target — proposal to raise `base_fee_burn_bps`.
    IncreaseBurnPct,
    /// Deflationary deviation — proposal to lower `base_fee_burn_bps`.
    DecreaseBurnPct,
    /// Supply increase exceeded the alarm threshold (or 2× extreme); the
    /// ledger refuses any increase, so this means a fault — fast-
    /// track proposal with shortened timelock.
    AlarmHighInflation,
    /// Reading exceeded deflation alarm threshold (or 2× extreme).
    AlarmHighDeflation,
}

impl RecommendationAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecommendationAction::Disabled => "disabled",
            RecommendationAction::NoChange => "no_change",
            RecommendationAction::IncreaseBurnPct => "increase_burn_pct",
            RecommendationAction::DecreaseBurnPct => "decrease_burn_pct",
            RecommendationAction::AlarmHighInflation => "alarm_high_inflation",
            RecommendationAction::AlarmHighDeflation => "alarm_high_deflation",
        }
    }

    /// True iff this action represents an alarm condition.
    pub fn is_alarm(&self) -> bool {
        matches!(
            self,
            RecommendationAction::AlarmHighInflation | RecommendationAction::AlarmHighDeflation
        )
    }
}

/// Output of `compute_recommendation`. `magnitude_bps` is signed: positive =
/// raise burn pct, negative = lower it. For alarm/no-change/disabled the
/// magnitude is 0 (the alarm itself is the signal — the magnitude of the
/// resulting proposal is set by the auto-proposal generator using
/// `magnitude_cap_alarm_bps`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRateRecommendation {
    pub action: RecommendationAction,
    pub magnitude_bps: i32,
    /// True iff `|magnitude_bps| >= auto_proposal_min_magnitude_bps`. The
    /// auto-proposal generator skips proposals below this floor.
    pub above_proposal_floor: bool,
    /// Echo of the `rolling_window_supply_delta_bps - target` deviation
    /// the function read. Signed.
    pub deviation_bps: i32,
}

// ---------- Pure transfer function -------------------------------------------

/// Compute the burn-rate recommendation for the current epoch.
///
/// Pure function: same `(metrics, targets)` input → same output.
///
/// Logic:
/// 1. If `targets.enabled == false` → `Disabled`.
/// 2. Compute `delta = rolling_supply_delta_bps - target_annual_supply_bps`.
/// 3. Sanity check: if `rolling_supply_delta_bps > 2 × inflation_alarm_bps`
///    or `> 2 × deflation_alarm_bps` → output alarm only, never auto-adjust.
/// 4. If `|delta_per_epoch_equivalent| < neutral_band_bps` → `NoChange`.
///    Convert the annualized delta to per-epoch by dividing by
///    `rolling_window_epochs` (the band is per-epoch in spec).
/// 5. If sustained `delta > inflation_alarm_bps` → `AlarmHighInflation`.
/// 6. If sustained `delta < -deflation_alarm_bps` → `AlarmHighDeflation`.
/// 7. Otherwise: proportional adjustment, capped by `magnitude_cap_normal_bps`.
pub fn compute_recommendation(
    metrics: &SupplyMetricsSnapshot,
    targets: &SupplyTargets,
) -> BurnRateRecommendation {
    if !targets.enabled {
        return BurnRateRecommendation {
            action: RecommendationAction::Disabled,
            magnitude_bps: 0,
            above_proposal_floor: false,
            deviation_bps: 0,
        };
    }

    let rolling = metrics.rolling_window_supply_delta_bps;
    let target = targets.target_annual_supply_bps;
    let deviation = rolling.saturating_sub(target);

    // Step 3: extreme reading sanity check. Forces alarm before any
    // proportional adjustment runs.
    let extreme_increase = (targets.inflation_alarm_bps as i32).saturating_mul(2);
    let extreme_deflation = (targets.deflation_alarm_bps as i32).saturating_mul(2);
    if rolling > extreme_increase {
        return BurnRateRecommendation {
            action: RecommendationAction::AlarmHighInflation,
            magnitude_bps: 0,
            above_proposal_floor: true,
            deviation_bps: deviation,
        };
    }
    if rolling < -extreme_deflation {
        return BurnRateRecommendation {
            action: RecommendationAction::AlarmHighDeflation,
            magnitude_bps: 0,
            above_proposal_floor: true,
            deviation_bps: deviation,
        };
    }

    // Step 4: neutral band. The band is defined per-epoch; the rolling
    // delta is annualized, so divide by window length to get the per-epoch
    // equivalent.
    let window = targets.rolling_window_epochs.max(1) as i32;
    let per_epoch_deviation = deviation / window;
    let band = targets.epoch_neutral_band_bps as i32;
    if per_epoch_deviation.abs() < band {
        return BurnRateRecommendation {
            action: RecommendationAction::NoChange,
            magnitude_bps: 0,
            above_proposal_floor: false,
            deviation_bps: deviation,
        };
    }

    // Steps 5-6: alarm thresholds on the annualized delta.
    if rolling > targets.inflation_alarm_bps as i32 {
        return BurnRateRecommendation {
            action: RecommendationAction::AlarmHighInflation,
            magnitude_bps: 0,
            above_proposal_floor: true,
            deviation_bps: deviation,
        };
    }
    if rolling < -(targets.deflation_alarm_bps as i32) {
        return BurnRateRecommendation {
            action: RecommendationAction::AlarmHighDeflation,
            magnitude_bps: 0,
            above_proposal_floor: true,
            deviation_bps: deviation,
        };
    }

    // Step 7: proportional adjustment. `gain_bps_per_pct` is in bps-per-1%-
    // deviation. `deviation` is already in bps. So:
    //     magnitude = (|deviation| / 100) * gain_bps_per_pct
    let abs_dev = deviation.unsigned_abs();
    let raw_magnitude = (abs_dev as u64 * targets.gain_bps_per_pct as u64 / 100) as i32;
    let cap = targets.magnitude_cap_normal_bps as i32;
    let capped = raw_magnitude.min(cap);

    // Sign convention: supply above target (deviation > 0) → increase burn
    // pct (magnitude positive). Below target → decrease burn pct (negative).
    let (action, magnitude) = if deviation > 0 {
        (RecommendationAction::IncreaseBurnPct, capped)
    } else {
        (RecommendationAction::DecreaseBurnPct, -capped)
    };

    let above_floor = magnitude.unsigned_abs() >= targets.auto_proposal_min_magnitude_bps as u32;

    BurnRateRecommendation {
        action,
        magnitude_bps: magnitude,
        above_proposal_floor: above_floor,
        deviation_bps: deviation,
    }
}

// ---------- Manager ----------------------------------------------------------

/// Manages the singleton `BurnRateConfig`, `SupplyTargets`, and latest
/// `SupplyMetricsSnapshot` records. Mirrors the other token managers' shape:
/// `parking_lot::RwLock` over the live state with optional write-through to
/// `CF_TOKENS`.
pub struct BurnRateConfigManager {
    config: parking_lot::RwLock<BurnRateConfig>,
    targets: parking_lot::RwLock<SupplyTargets>,
    metrics: parking_lot::RwLock<SupplyMetricsSnapshot>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for BurnRateConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BurnRateConfigManager {
    /// In-memory manager seeded with genesis defaults.
    pub fn new() -> Self {
        Self {
            config: parking_lot::RwLock::new(BurnRateConfig::default()),
            targets: parking_lot::RwLock::new(SupplyTargets::default()),
            metrics: parking_lot::RwLock::new(SupplyMetricsSnapshot::default()),
            storage: None,
        }
    }

    /// Construct with RocksDB write-through. Hydrates all three singletons
    /// from `CF_TOKENS`. If a key is absent the manager initializes with
    /// the corresponding `Default::default()` and persists it so subsequent
    /// reads are consistent across restarts.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mgr = Self {
            config: parking_lot::RwLock::new(BurnRateConfig::default()),
            targets: parking_lot::RwLock::new(SupplyTargets::default()),
            metrics: parking_lot::RwLock::new(SupplyMetricsSnapshot::default()),
            storage: Some(storage),
        };
        mgr.hydrate_from_storage()?;
        Ok(mgr)
    }

    /// Read a snapshot of the current burn-rate config.
    pub fn config(&self) -> BurnRateConfig {
        *self.config.read()
    }

    /// Read a snapshot of the current supply targets.
    pub fn targets(&self) -> SupplyTargets {
        *self.targets.read()
    }

    /// Read the latest persisted supply metrics snapshot.
    pub fn latest_metrics(&self) -> SupplyMetricsSnapshot {
        self.metrics.read().clone()
    }

    /// Apply a governance-ratified update to the burn-rate config.
    /// Validates the new config and persists immediately. Used by the
    /// governance executor when an adaptive-burn proposal passes.
    pub fn apply_config(&self, new_config: BurnRateConfig) -> Result<()> {
        new_config.validate()?;
        *self.config.write() = new_config;
        self.persist_config(&new_config)?;
        info!(
            base_fee_burn_bps = new_config.base_fee_burn_bps,
            local_fee_burn_bps = new_config.local_fee_burn_bps,
            "BurnRateConfig updated"
        );
        Ok(())
    }

    /// Apply a governance-ratified update to supply targets. A target above
    /// zero is refused: TNZO supply is fixed at genesis.
    pub fn apply_targets(&self, new_targets: SupplyTargets) -> Result<()> {
        if new_targets.epoch_neutral_band_bps > 10_000 || new_targets.gain_bps_per_pct > 10_000 {
            return Err(TokenError::InvalidParameter(
                "epoch_neutral_band_bps / gain_bps_per_pct must be <= 10000".into(),
            ));
        }
        if new_targets.target_annual_supply_bps > 0 {
            return Err(TokenError::InvalidParameter(format!(
                "target_annual_supply_bps is {}; TNZO supply is fixed, so the target is at most 0",
                new_targets.target_annual_supply_bps
            )));
        }
        *self.targets.write() = new_targets;
        self.persist_targets(&new_targets)?;
        info!("SupplyTargets updated");
        Ok(())
    }

    /// Record the latest supply metrics snapshot (called by the epoch
    /// observer after aggregating UsageTracker + burn-ledger data).
    pub fn record_metrics(&self, snapshot: SupplyMetricsSnapshot) -> Result<()> {
        *self.metrics.write() = snapshot.clone();
        self.persist_metrics(&snapshot)?;
        debug!(
            block_height = snapshot.block_height.0,
            epoch_supply_delta = snapshot.epoch_supply_delta,
            rolling_bps = snapshot.rolling_window_supply_delta_bps,
            "SupplyMetricsSnapshot recorded"
        );
        Ok(())
    }

    /// Compute the current burn-rate recommendation from the latest
    /// persisted metrics + targets. Pure read; does not mutate state and
    /// does not draft a proposal.
    pub fn current_recommendation(&self) -> BurnRateRecommendation {
        let metrics = self.metrics.read().clone();
        let targets = *self.targets.read();
        compute_recommendation(&metrics, &targets)
    }

    fn hydrate_from_storage(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return Ok(()),
        };

        // BurnRateConfig
        match storage
            .get(CF_TOKENS, BURN_RATE_CONFIG_KEY)
            .map_err(|e| TokenError::StorageError(format!("get burn rate config: {}", e)))?
        {
            Some(value) => {
                let cfg: BurnRateConfig = serde_json::from_slice(&value).map_err(|e| {
                    TokenError::StorageError(format!("decode burn rate config: {}", e))
                })?;
                cfg.validate()?;
                *self.config.write() = cfg;
                info!(
                    base_fee_burn_bps = cfg.base_fee_burn_bps,
                    "BurnRateConfig hydrated from storage"
                );
            }
            None => {
                let genesis = *self.config.read();
                self.persist_config(&genesis)?;
                info!("BurnRateConfig initialized from genesis defaults");
            }
        }

        // SupplyTargets
        match storage
            .get(CF_TOKENS, SUPPLY_TARGETS_KEY)
            .map_err(|e| TokenError::StorageError(format!("get supply targets: {}", e)))?
        {
            Some(value) => {
                let mut t: SupplyTargets = serde_json::from_slice(&value).map_err(|e| {
                    TokenError::StorageError(format!("decode supply targets: {}", e))
                })?;
                // A target persisted above zero, such as the earlier rising
                // default, is held flat: TNZO supply is fixed.
                if t.target_annual_supply_bps > 0 {
                    t.target_annual_supply_bps = 0;
                    self.persist_targets(&t)?;
                    info!("Stored supply target was above zero; held at 0");
                }
                *self.targets.write() = t;
                info!("SupplyTargets hydrated from storage");
            }
            None => {
                let genesis = *self.targets.read();
                self.persist_targets(&genesis)?;
                info!("SupplyTargets initialized from genesis defaults");
            }
        }

        // SupplyMetricsSnapshot — absence is fine; observer hasn't run yet.
        if let Some(value) = storage
            .get(CF_TOKENS, SUPPLY_METRICS_KEY)
            .map_err(|e| TokenError::StorageError(format!("get supply metrics: {}", e)))?
        {
            let m: SupplyMetricsSnapshot = serde_json::from_slice(&value)
                .map_err(|e| TokenError::StorageError(format!("decode supply metrics: {}", e)))?;
            *self.metrics.write() = m;
            info!("SupplyMetricsSnapshot hydrated from storage");
        }

        Ok(())
    }

    fn persist_config(&self, cfg: &BurnRateConfig) -> Result<()> {
        if let Some(storage) = &self.storage {
            let value = serde_json::to_vec(cfg)
                .map_err(|e| TokenError::StorageError(format!("encode burn rate config: {}", e)))?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: BURN_RATE_CONFIG_KEY.to_vec(),
                    value,
                }])
                .map_err(|e| {
                    TokenError::StorageError(format!("persist burn rate config: {}", e))
                })?;
        }
        Ok(())
    }

    fn persist_targets(&self, t: &SupplyTargets) -> Result<()> {
        if let Some(storage) = &self.storage {
            let value = serde_json::to_vec(t)
                .map_err(|e| TokenError::StorageError(format!("encode supply targets: {}", e)))?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: SUPPLY_TARGETS_KEY.to_vec(),
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist supply targets: {}", e)))?;
        }
        Ok(())
    }

    fn persist_metrics(&self, m: &SupplyMetricsSnapshot) -> Result<()> {
        if let Some(storage) = &self.storage {
            let value = serde_json::to_vec(m)
                .map_err(|e| TokenError::StorageError(format!("encode supply metrics: {}", e)))?;
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: SUPPLY_METRICS_KEY.to_vec(),
                    value,
                }])
                .map_err(|e| TokenError::StorageError(format!("persist supply metrics: {}", e)))?;
        }
        Ok(())
    }
}

// ---------- Auto-proposal generator -----------------------------------------

/// Default poll interval for the auto-proposal generator: 8 hours, matching
/// the genesis epoch boundary in `adaptive-burn.md`.
pub const DEFAULT_AUTO_PROPOSAL_POLL_INTERVAL_SECS: u64 = 8 * 60 * 60;

/// Default debounce between auto-proposals: 24 hours. The generator will not
/// emit a second proposal within this window even if metrics keep drifting,
/// to prevent flooding governance with overlapping `AdaptiveBurnConfigUpdate`
/// votes.
pub const DEFAULT_AUTO_PROPOSAL_DEBOUNCE_SECS: u64 = 24 * 60 * 60;

/// Configuration for [`AutoProposalGenerator`].
#[derive(Debug, Clone, Copy)]
pub struct AutoProposalGeneratorConfig {
    /// How often the generator polls `current_recommendation()`. Defaults to
    /// the epoch period (8h).
    pub poll_interval_secs: u64,
    /// Minimum elapsed time between two consecutive drafts. Defaults to 24h,
    /// independent of how long the resulting vote takes.
    pub debounce_secs: u64,
}

impl Default for AutoProposalGeneratorConfig {
    fn default() -> Self {
        Self {
            poll_interval_secs: DEFAULT_AUTO_PROPOSAL_POLL_INTERVAL_SECS,
            debounce_secs: DEFAULT_AUTO_PROPOSAL_DEBOUNCE_SECS,
        }
    }
}

/// A policy change the generator wants put to an on-chain governance vote.
/// The node turns it into a `GovernancePropose` transaction signed by its
/// validator key; the network votes on it like any other proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDraft {
    /// The change to vote on.
    pub update: tenzro_types::token::PolicyUpdate,
    /// Why, recorded on-chain with the proposal.
    pub memo: String,
    /// Whether it goes on the expedited track (alarm states only).
    pub expedited: bool,
}

/// Watches the [`BurnRateConfigManager`] recommendation and drafts
/// [`tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate`]
/// proposals for on-chain governance:
///
/// 1. Periodically reads `manager.current_recommendation()`.
/// 2. If the recommendation clears the proposal floor, or is an alarm, sends
///    a [`PolicyDraft`] to the node, which submits it as a governance
///    proposal. Nothing changes until the network votes it through.
/// 3. Respects a debounce window to avoid flooding governance.
///
/// Alarm states use `magnitude_cap_alarm_bps` for magnitude (the
/// recommendation itself carries `magnitude_bps = 0` for alarms: the alarm is
/// the signal, the size is set by the alarm cap) and go on the expedited
/// track when `alarm_fast_track_enabled` is set.
pub struct AutoProposalGenerator {
    manager: Arc<BurnRateConfigManager>,
    drafts: tokio::sync::mpsc::UnboundedSender<PolicyDraft>,
    config: AutoProposalGeneratorConfig,
    last_issued_at: parking_lot::Mutex<Option<std::time::Instant>>,
}

impl AutoProposalGenerator {
    pub fn new(
        manager: Arc<BurnRateConfigManager>,
        drafts: tokio::sync::mpsc::UnboundedSender<PolicyDraft>,
    ) -> Self {
        Self::with_config(manager, drafts, AutoProposalGeneratorConfig::default())
    }

    pub fn with_config(
        manager: Arc<BurnRateConfigManager>,
        drafts: tokio::sync::mpsc::UnboundedSender<PolicyDraft>,
        config: AutoProposalGeneratorConfig,
    ) -> Self {
        Self {
            manager,
            drafts,
            config,
            last_issued_at: parking_lot::Mutex::new(None),
        }
    }

    /// Spawn the background loop. The returned `JoinHandle` lives for the
    /// process lifetime; callers may drop it.
    pub fn spawn(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let poll = std::time::Duration::from_secs(self.config.poll_interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate fire so metrics have a chance to be observed.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if let Err(e) = self.tick_once() {
                    tracing::warn!(error = %e, "AutoProposalGenerator: tick_once failed");
                }
            }
        })
    }

    /// One iteration: read the recommendation and draft a proposal if it
    /// calls for one. Returns the draft sent, if any.
    pub fn tick_once(&self) -> Result<Option<PolicyDraft>> {
        let recommendation = self.manager.current_recommendation();
        if !self.should_propose(&recommendation) {
            return Ok(None);
        }

        {
            let last = self.last_issued_at.lock();
            if let Some(t) = *last {
                let elapsed = t.elapsed();
                if elapsed.as_secs() < self.config.debounce_secs {
                    debug!(
                        elapsed_secs = elapsed.as_secs(),
                        debounce_secs = self.config.debounce_secs,
                        "AutoProposalGenerator: within debounce window, skipping"
                    );
                    return Ok(None);
                }
            }
        }

        let targets = self.manager.targets();
        let current = self.manager.config();
        let proposed = self.compute_proposed_config(&current, &targets, &recommendation);

        // Validate before drafting so the network never votes on something
        // enactment would refuse.
        proposed.validate()?;

        let expedited = recommendation.action.is_alarm() && targets.alarm_fast_track_enabled;
        let memo = format!(
            "Adaptive burn: {action}. Deviation {deviation} bps, magnitude {magnitude} bps. \
             base_fee_burn_bps {cur} -> {prop}.",
            action = recommendation.action.as_str(),
            deviation = recommendation.deviation_bps,
            magnitude = recommendation.magnitude_bps,
            cur = current.base_fee_burn_bps,
            prop = proposed.base_fee_burn_bps,
        );
        let draft = PolicyDraft {
            update: tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps: proposed.base_fee_burn_bps,
                local_fee_burn_bps: proposed.local_fee_burn_bps,
            },
            memo,
            expedited,
        };

        self.drafts.send(draft.clone()).map_err(|_| {
            TokenError::InvalidParameter(
                "the governance submitter is gone; the draft was not sent".to_string(),
            )
        })?;
        *self.last_issued_at.lock() = Some(std::time::Instant::now());

        info!(
            action = recommendation.action.as_str(),
            current_bps = current.base_fee_burn_bps,
            proposed_bps = proposed.base_fee_burn_bps,
            expedited,
            "AutoProposalGenerator: drafted adaptive burn proposal"
        );

        Ok(Some(draft))
    }

    fn should_propose(&self, rec: &BurnRateRecommendation) -> bool {
        match rec.action {
            RecommendationAction::Disabled | RecommendationAction::NoChange => false,
            RecommendationAction::IncreaseBurnPct | RecommendationAction::DecreaseBurnPct => {
                rec.above_proposal_floor
            }
            RecommendationAction::AlarmHighInflation | RecommendationAction::AlarmHighDeflation => {
                true
            }
        }
    }

    fn compute_proposed_config(
        &self,
        current: &BurnRateConfig,
        targets: &SupplyTargets,
        rec: &BurnRateRecommendation,
    ) -> BurnRateConfig {
        // For alarms the recommendation magnitude is 0: pull the per-alarm
        // cap from targets. Sign comes from which alarm fired.
        let delta = match rec.action {
            RecommendationAction::AlarmHighInflation => targets.magnitude_cap_alarm_bps as i32,
            RecommendationAction::AlarmHighDeflation => -(targets.magnitude_cap_alarm_bps as i32),
            _ => rec.magnitude_bps,
        };
        current.with_base_fee_burn_delta(delta)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_split_is_exact_with_dust_to_treasury() {
        // Genesis = 100% burn.
        let c = BurnRateConfig::default();
        let s = c.split_base_fee(1_000);
        assert_eq!((s.burn, s.treasury), (1_000, 0));
        assert_eq!(s.total(), 1_000);

        // 50/50 on an odd amount: floor to burn, remainder (dust) to treasury.
        let c2 = BurnRateConfig {
            base_fee_burn_bps: 5_000,
            ..Default::default()
        };
        let s2 = c2.split_base_fee(1_001);
        assert_eq!((s2.burn, s2.treasury), (500, 501));
        assert_eq!(s2.total(), 1_001);

        // 0% burn → everything to treasury.
        let c3 = BurnRateConfig {
            base_fee_burn_bps: 0,
            ..Default::default()
        };
        let s3 = c3.split_base_fee(777);
        assert_eq!((s3.burn, s3.treasury), (0, 777));

        // Local fees use their own dial (genesis 100% burn).
        assert_eq!(
            c.split_local_fee(42),
            FeeSplit {
                burn: 42,
                treasury: 0
            }
        );
    }

    fn metrics_with_rolling(bps: i32) -> SupplyMetricsSnapshot {
        SupplyMetricsSnapshot {
            rolling_window_supply_delta_bps: bps,
            ..SupplyMetricsSnapshot::default()
        }
    }

    #[test]
    fn defaults_are_consistent() {
        let cfg = BurnRateConfig::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.base_fee_burn_bps, 10_000);
        assert_eq!(cfg.base_fee_treasury_bps(), 0);
    }

    #[test]
    fn config_with_delta_clamps() {
        let cfg = BurnRateConfig::default();
        let lower = cfg.with_base_fee_burn_delta(-200);
        assert_eq!(lower.base_fee_burn_bps, 9_800);
        let raise = cfg.with_base_fee_burn_delta(500);
        // Already at 10_000, can't go higher.
        assert_eq!(raise.base_fee_burn_bps, 10_000);
        let big_drop = cfg.with_base_fee_burn_delta(-20_000);
        assert_eq!(big_drop.base_fee_burn_bps, 0);
    }

    #[test]
    fn disabled_short_circuits() {
        let targets = SupplyTargets {
            enabled: false,
            ..SupplyTargets::default()
        };
        let m = metrics_with_rolling(1_000);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::Disabled);
        assert_eq!(r.magnitude_bps, 0);
    }

    #[test]
    fn neutral_band_returns_no_change() {
        // Target = 0bps. Rolling = 0bps. Deviation = 0. Per-epoch = 0.
        // Band = 5bps → no change.
        let targets = SupplyTargets::default();
        let m = metrics_with_rolling(0);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::NoChange);
        assert_eq!(r.deviation_bps, 0);
    }

    #[test]
    fn supply_above_target_recommends_increase_burn() {
        // Target = 0bps. Rolling = +150bps. Deviation = +150bps.
        // Per-epoch = 150/90 ≈ 1bps < band (5bps) → no change actually.
        // To trigger proportional, we need deviation > band * window =
        // 5 * 90 = 450. So set rolling = 450 → deviation = 450. Per-epoch
        // = 5 = band; abs(per_epoch_deviation) < band fails (not strict
        // greater, but `< band` is the band-inside condition). 5 is NOT
        // less than 5 → falls through to proportional path.
        let targets = SupplyTargets::default();
        let m = metrics_with_rolling(450);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::IncreaseBurnPct);
        assert!(r.magnitude_bps > 0);
        // |dev| = 450bps = 4.5% deviation. gain = 50 bps/pct → 225bps raw,
        // capped to magnitude_cap_normal (200).
        assert_eq!(r.magnitude_bps, 200);
        assert!(r.above_proposal_floor);
    }

    #[test]
    fn supply_below_target_recommends_decrease_burn() {
        let targets = SupplyTargets::default();
        // rolling = -450bps. Target = 0bps. Deviation = -450bps. Per-epoch
        // = -5 (passes band check at boundary). Within deflation alarm
        // magnitude (500). Proportional path.
        let m = metrics_with_rolling(-450);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::DecreaseBurnPct);
        assert!(r.magnitude_bps < 0);
        assert_eq!(r.magnitude_bps, -200);
    }

    #[test]
    fn alarm_on_a_supply_increase() {
        let targets = SupplyTargets::default();
        // Increase alarm = 500. Rolling = 700 → above alarm but below
        // 2× extreme (1000). Action = AlarmHighInflation.
        let m = metrics_with_rolling(700);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::AlarmHighInflation);
        assert_eq!(r.magnitude_bps, 0);
        assert!(r.action.is_alarm());
    }

    #[test]
    fn alarm_high_deflation() {
        let targets = SupplyTargets::default();
        let m = metrics_with_rolling(-700);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::AlarmHighDeflation);
        assert_eq!(r.magnitude_bps, 0);
    }

    #[test]
    fn extreme_reading_forces_alarm_only() {
        let targets = SupplyTargets::default();
        // 2× alarm = 1000. Rolling = 1500 → forced alarm, no proportional.
        let m = metrics_with_rolling(1500);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::AlarmHighInflation);
        assert_eq!(r.magnitude_bps, 0);
    }

    /// TNZO supply is fixed: the genesis target adds nothing, and the
    /// manager refuses a target above zero however it arrives.
    #[test]
    fn the_supply_target_is_never_above_zero() {
        assert!(SupplyTargets::default().target_annual_supply_bps <= 0);
        let mgr = BurnRateConfigManager::new();
        for target in [1, 50, i32::MAX] {
            let t = SupplyTargets {
                target_annual_supply_bps: target,
                ..SupplyTargets::default()
            };
            assert!(mgr.apply_targets(t).is_err(), "target {target} accepted");
        }
        assert!(mgr.targets().target_annual_supply_bps <= 0);
        let falling = SupplyTargets {
            target_annual_supply_bps: -25,
            ..SupplyTargets::default()
        };
        mgr.apply_targets(falling).unwrap();
        assert_eq!(mgr.targets().target_annual_supply_bps, -25);
    }

    /// A node that persisted the earlier rising default hydrates it as flat.
    #[test]
    fn a_stored_rising_target_hydrates_as_flat() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let stored = SupplyTargets {
            target_annual_supply_bps: 50,
            ..SupplyTargets::default()
        };
        store
            .put(
                CF_TOKENS,
                SUPPLY_TARGETS_KEY,
                &serde_json::to_vec(&stored).unwrap(),
            )
            .unwrap();
        let mgr = BurnRateConfigManager::with_storage(store).unwrap();
        assert_eq!(mgr.targets().target_annual_supply_bps, 0);
    }

    #[test]
    fn manager_apply_config_persists() {
        let mgr = BurnRateConfigManager::new();
        let updated = BurnRateConfig {
            base_fee_burn_bps: 9_500,
            ..BurnRateConfig::default()
        };
        mgr.apply_config(updated).unwrap();
        assert_eq!(mgr.config().base_fee_burn_bps, 9_500);
    }

    #[test]
    fn record_metrics_round_trips_through_recommendation() {
        let mgr = BurnRateConfigManager::new();
        mgr.record_metrics(metrics_with_rolling(500)).unwrap();
        let r = mgr.current_recommendation();
        assert_eq!(r.action, RecommendationAction::IncreaseBurnPct);
    }

    #[test]
    fn breakdown_totals() {
        let b = BurnBreakdown {
            base_fee: 100,
            local_fee: 50,
        };
        assert_eq!(b.total(), 150);
        let e = EmissionBreakdown {
            staking_rewards: 200,
            treasury_emissions: 100,
        };
        assert_eq!(e.total(), 300);
    }

    #[test]
    fn proposal_floor_skips_small_magnitudes() {
        // Construct targets with a high floor so any small magnitude is
        // skipped, AND a tight rolling window so the per-epoch band check
        // doesn't swallow modest deviations.
        let targets = SupplyTargets {
            auto_proposal_min_magnitude_bps: 500, // require >= 500 bps
            rolling_window_epochs: 1,             // per-epoch == annualized for the band check
            ..SupplyTargets::default()
        };
        // rolling=400, target=0 → deviation=400bps=4%. Below alarm (500).
        // gain=50/pct → raw magnitude=200bps, capped at 200. Below floor 500.
        let m = metrics_with_rolling(400);
        let r = compute_recommendation(&m, &targets);
        assert_eq!(r.action, RecommendationAction::IncreaseBurnPct);
        assert_eq!(r.magnitude_bps, 200);
        assert!(!r.above_proposal_floor);
    }

    // ---- AutoProposalGenerator tests --------------------------------------

    type Drafts = tokio::sync::mpsc::UnboundedReceiver<PolicyDraft>;

    fn make_auto_gen() -> (
        Arc<BurnRateConfigManager>,
        Drafts,
        Arc<AutoProposalGenerator>,
    ) {
        let manager = Arc::new(BurnRateConfigManager::new());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let generator = Arc::new(AutoProposalGenerator::new(manager.clone(), tx));
        (manager, rx, generator)
    }

    fn drain(rx: &mut Drafts) -> Vec<PolicyDraft> {
        let mut out = Vec::new();
        while let Ok(d) = rx.try_recv() {
            out.push(d);
        }
        out
    }

    fn proposed_base_bps(draft: &PolicyDraft) -> u16 {
        match draft.update {
            tenzro_types::token::PolicyUpdate::AdaptiveBurnConfigUpdate {
                base_fee_burn_bps,
                ..
            } => base_fee_burn_bps,
            ref other => panic!("unexpected draft {other:?}"),
        }
    }

    #[test]
    fn auto_gen_skips_no_change() {
        let (mgr, mut rx, generator) = make_auto_gen();
        // metrics with rolling=0 → deviation = -50 → per-epoch tiny, NoChange.
        mgr.record_metrics(metrics_with_rolling(0)).unwrap();
        assert!(generator.tick_once().unwrap().is_none());
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn auto_gen_skips_disabled() {
        let (mgr, mut rx, generator) = make_auto_gen();
        let disabled = SupplyTargets {
            enabled: false,
            ..SupplyTargets::default()
        };
        mgr.apply_targets(disabled).unwrap();
        mgr.record_metrics(metrics_with_rolling(10_000)).unwrap();
        assert!(generator.tick_once().unwrap().is_none());
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn auto_gen_skips_below_floor() {
        let (mgr, mut rx, generator) = make_auto_gen();
        // Floor=500, rolling=450 → magnitude=200 → below floor.
        let targets = SupplyTargets {
            auto_proposal_min_magnitude_bps: 500,
            rolling_window_epochs: 1,
            ..SupplyTargets::default()
        };
        mgr.apply_targets(targets).unwrap();
        mgr.record_metrics(metrics_with_rolling(450)).unwrap();
        assert!(generator.tick_once().unwrap().is_none());
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn auto_gen_drafts_increase_burn_proposal_on_the_standard_track() {
        let (mgr, mut rx, generator) = make_auto_gen();
        let low_burn = BurnRateConfig {
            base_fee_burn_bps: 5_000,
            ..BurnRateConfig::default()
        };
        mgr.apply_config(low_burn).unwrap();
        // gain=50/pct, rolling=450 → magnitude=225, capped at 200 → above
        // default floor 25.
        let targets = SupplyTargets {
            rolling_window_epochs: 1,
            ..SupplyTargets::default()
        };
        mgr.apply_targets(targets).unwrap();
        mgr.record_metrics(metrics_with_rolling(450)).unwrap();
        let draft = generator.tick_once().unwrap().expect("a draft");
        assert!(!draft.expedited);
        assert_eq!(proposed_base_bps(&draft), 5_200);
        assert_eq!(drain(&mut rx), vec![draft]);
        // Drafting changes nothing: only an enacted vote does.
        assert_eq!(mgr.config().base_fee_burn_bps, 5_000);
    }

    #[test]
    fn auto_gen_alarm_is_expedited_and_uses_alarm_cap_magnitude() {
        let (mgr, mut rx, generator) = make_auto_gen();
        let low_burn = BurnRateConfig {
            base_fee_burn_bps: 5_000,
            ..BurnRateConfig::default()
        };
        mgr.apply_config(low_burn).unwrap();
        // rolling=600 → exceeds inflation_alarm_bps=500 → AlarmHighInflation.
        // (A supply increase the ledger refuses; the alarm is the fault path.)
        mgr.record_metrics(metrics_with_rolling(600)).unwrap();
        let draft = generator.tick_once().unwrap().expect("a draft");
        assert!(draft.expedited);
        assert_eq!(
            proposed_base_bps(&draft),
            5_000 + DEFAULT_MAGNITUDE_CAP_ALARM_BPS
        );
        assert_eq!(drain(&mut rx).len(), 1);
    }

    #[test]
    fn auto_gen_alarm_without_fast_track_uses_the_standard_track() {
        let (mgr, _rx, generator) = make_auto_gen();
        mgr.apply_targets(SupplyTargets {
            alarm_fast_track_enabled: false,
            ..SupplyTargets::default()
        })
        .unwrap();
        mgr.record_metrics(metrics_with_rolling(600)).unwrap();
        let draft = generator.tick_once().unwrap().expect("a draft");
        assert!(!draft.expedited);
    }

    #[test]
    fn auto_gen_alarm_decrease_clamps_at_zero() {
        let (mgr, mut rx, generator) = make_auto_gen();
        // Start at 50 bps; alarm-deflation wants to push it negative.
        let low_burn = BurnRateConfig {
            base_fee_burn_bps: 50,
            ..BurnRateConfig::default()
        };
        mgr.apply_config(low_burn).unwrap();
        mgr.record_metrics(metrics_with_rolling(-600)).unwrap();
        let draft = generator.tick_once().unwrap().expect("a draft");
        assert_eq!(proposed_base_bps(&draft), 0);
        assert_eq!(drain(&mut rx).len(), 1);
    }

    #[test]
    fn auto_gen_respects_debounce() {
        let (mgr, mut rx, generator) = make_auto_gen();
        let targets = SupplyTargets {
            rolling_window_epochs: 1,
            ..SupplyTargets::default()
        };
        mgr.apply_targets(targets).unwrap();
        mgr.record_metrics(metrics_with_rolling(450)).unwrap();
        assert!(generator.tick_once().unwrap().is_some());
        // Second tick within the 24h debounce is skipped.
        assert!(generator.tick_once().unwrap().is_none());
        assert_eq!(drain(&mut rx).len(), 1);
    }

    #[test]
    fn auto_gen_fails_loudly_when_nobody_submits() {
        let (mgr, rx, generator) = make_auto_gen();
        drop(rx);
        mgr.record_metrics(metrics_with_rolling(600)).unwrap();
        assert!(generator.tick_once().is_err());
        // A failed send is not a draft: the next tick tries again.
        assert!(generator.tick_once().is_err());
    }
}
