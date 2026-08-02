//! StableController — per-issuer leaky-PI peg / buffer controller.
//!
//! Implements the stabilization layer for a tiered hybrid stable asset:
//! a hard RWA/fiat reserve floor (enforced by
//! [`crate::secure_mint::SecureMintRegistry`]) with an AI-tuned crypto
//! buffer above it. This controller manages only the buffer and supply
//! *within the floor's headroom* — it can authorize a supply delta but the
//! SecureMint invariant is the hard gate, so a misbehaving controller can
//! degrade capital efficiency, never mint an unbacked unit.
//!
//! # Mechanism
//!
//! The peg loop is a proportional + leaky-integral controller over the
//! error between market price and target. The derivative term is
//! deliberately omitted: in an economic setting it amplifies price noise
//! and becomes an attack vector. The integral *leak* provides anti-windup.
//! All math is integer-only and basis-point / Q18-scaled, matching the
//! EIP-1559 controller already in this crate (`eip1559.rs`).
//!
//! The buffer/risk loop uses dual-threshold liquidation (warn band →
//! rebalance, trip band → partial close) with a gap between bands to
//! prevent hysteresis oscillation.
//!
//! ```text
//!   error e = market_price - target          (signed, Q18)
//!   integral I = leak(I_prev) + e            (leaky accumulator)
//!   control u = Kp*e + Ki*I                  (signed control signal)
//!   supply_delta = clamp(u -> supply space, floor_headroom)
//! ```

use serde::{Deserialize, Serialize};

/// Q18 fixed-point scale (1e18 = 1.0). Prices and the integral are tracked
/// in this scale.
pub const Q18: i128 = 1_000_000_000_000_000_000;

/// Per-issuer controller configuration. Gains are basis points applied to
/// the Q18 error so an issuer tunes responsiveness without floats.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StableControllerConfig {
    /// Target price in Q18 (typically `1e18` for a USD-pegged unit).
    pub target_q18: i128,
    /// Proportional gain, basis points of the Q18 error. e.g. 5000 = 0.5.
    pub kp_bps: i128,
    /// Integral gain, basis points of the leaky-integral term.
    pub ki_bps: i128,
    /// Integral leak, basis points retained each epoch (anti-windup).
    /// 10_000 = no leak (pure integral); 9_000 = retain 90% per epoch.
    pub leak_bps: i128,
    /// Maximum |supply_delta| per epoch, as basis points of current
    /// circulating-above-floor. Bounds how fast the controller can move.
    pub max_supply_step_bps: i128,
    /// Target buffer ratio in basis points (buffer / circulating-above-
    /// floor). e.g. 12_000 = 120% buffer target.
    pub target_buffer_bps: i128,
    /// Warn band lower bound (bps). Below this → rebalance.
    pub warn_buffer_bps: i128,
    /// Liquidation trip lower bound (bps). Below this → partial close.
    /// Must be < `warn_buffer_bps`; the gap prevents oscillation.
    pub trip_buffer_bps: i128,
}

impl Default for StableControllerConfig {
    fn default() -> Self {
        // Conservative defaults: gentle P, mild leaky-I, 5% max step/epoch,
        // 120% buffer target with warn at 110% and trip at 105%, expressed
        // relative to the 100% floor.
        Self {
            target_q18: Q18,
            kp_bps: 5_000,             // 0.5
            ki_bps: 500,               // 0.05
            leak_bps: 9_000,           // retain 90% of the integral each epoch
            max_supply_step_bps: 500,  // 5%
            target_buffer_bps: 12_000, // 120%
            warn_buffer_bps: 11_000,   // 110%
            trip_buffer_bps: 10_500,   // 105%
        }
    }
}

impl StableControllerConfig {
    /// Reject configs that would oscillate or misbehave.
    pub fn validate(&self) -> Result<(), String> {
        if self.target_q18 <= 0 {
            return Err("target_q18 must be positive".into());
        }
        if !(0..=10_000).contains(&self.leak_bps) {
            return Err("leak_bps must be in 0..=10_000".into());
        }
        if self.trip_buffer_bps >= self.warn_buffer_bps {
            return Err(
                "trip_buffer_bps must be < warn_buffer_bps (band gap prevents hysteresis)".into(),
            );
        }
        if self.max_supply_step_bps < 0 {
            return Err("max_supply_step_bps must be non-negative".into());
        }
        Ok(())
    }
}

/// Where the buffer currently sits relative to the configured bands.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskBand {
    /// At or above target — healthy.
    Healthy,
    /// Between warn and target — fine, no action.
    Adequate,
    /// In the warn band — rebalance toward target.
    Warn,
    /// Below the trip line — partial close / de-risk.
    Trip,
}

/// What to do with the buffer this epoch.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BufferAction {
    /// Hold — buffer within tolerance.
    Hold,
    /// Add collateral toward `target_buffer_bps`.
    Rebalance,
    /// Reduce exposure / partial-close positions (trip band).
    PartialClose,
}

/// The controller's decision for one epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StableControllerOutput {
    /// Signed supply change in unit smallest-units. Positive = mint
    /// (subject to the SecureMint floor gate), negative = burn. Already
    /// clamped to `max_supply_step_bps` and to the supplied floor headroom.
    pub supply_delta: i128,
    /// Current buffer ratio in bps (buffer / circulating-above-floor).
    pub buffer_ratio_bps: i128,
    /// Risk band the buffer is in.
    pub band: RiskBand,
    /// Recommended buffer action.
    pub buffer_action: BufferAction,
    /// The control signal `u` (Q18) for diagnostics.
    pub control_signal_q18: i128,
}

/// Per-issuer controller state. Holds only the leaky-integral accumulator;
/// everything else is supplied per epoch so callers can persist the small
/// state and reconstruct deterministically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StableController {
    config: StableControllerConfig,
    /// Leaky-integral accumulator (Q18).
    integral_q18: i128,
}

impl StableController {
    pub fn new(config: StableControllerConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            integral_q18: 0,
        })
    }

    pub fn config(&self) -> &StableControllerConfig {
        &self.config
    }

    pub fn integral_q18(&self) -> i128 {
        self.integral_q18
    }

    /// Run one control epoch.
    ///
    /// * `market_price_q18` — observed market price of the unit (Q18). The
    ///   caller is responsible for EMA-smoothing this upstream, exactly as
    ///   the EIP-1559 controller consumes smoothed utilization.
    /// * `circulating_above_floor` — supply above the hard reserve floor,
    ///   the base the supply step is sized against.
    /// * `buffer_value` — current crypto-buffer value, same unit as
    ///   circulating, for the ratio.
    /// * `floor_headroom` — max additional units the SecureMint floor would
    ///   permit minting right now (`reserve - circulating`). The mint side
    ///   of `supply_delta` is hard-clamped to this; the controller never
    ///   proposes crossing the floor.
    pub fn step(
        &mut self,
        market_price_q18: i128,
        circulating_above_floor: u128,
        buffer_value: u128,
        floor_headroom: u128,
    ) -> StableControllerOutput {
        // --- peg loop (leaky-PI, no derivative) ---
        let e = market_price_q18 - self.config.target_q18; // signed Q18 error
        // I = leak * I_prev + e
        self.integral_q18 = mul_bps(self.integral_q18, self.config.leak_bps) + e;
        // u = Kp*e + Ki*I  (bps gains over Q18 terms)
        let u = mul_bps(e, self.config.kp_bps) + mul_bps(self.integral_q18, self.config.ki_bps);

        // Map the control signal to a supply step. A positive market price
        // above target means the unit is "too expensive" → expand supply to
        // push price down; below target → contract. The sign of the step
        // tracks the sign of `u`. Magnitude is proportional to |u| relative
        // to target, capped by max_supply_step_bps of the circulating base.
        let base = circulating_above_floor as i128;
        let max_step = (base * self.config.max_supply_step_bps) / 10_000;
        // |step| = base * min(|u|/target, max_supply_step_bps) — i.e. scale
        // |u|/target into a bps-of-base move, then clamp.
        let u_frac_bps = if self.config.target_q18 != 0 {
            (u.abs() * 10_000) / self.config.target_q18
        } else {
            0
        };
        let raw_mag = (base * u_frac_bps) / 10_000;
        let mag = raw_mag.clamp(0, max_step.max(0));
        let mut supply_delta = if u >= 0 { mag } else { -mag };

        // Hard floor gate on the mint side: never propose minting beyond
        // what the reserve permits. Burns (negative) are always allowed.
        if supply_delta > 0 {
            // Saturate the cast: a headroom above i128::MAX would wrap to a
            // negative bound and spuriously force a burn.
            let headroom_i128 = i128::try_from(floor_headroom).unwrap_or(i128::MAX);
            supply_delta = supply_delta.min(headroom_i128);
        }

        // --- buffer / risk loop (dual-threshold) ---
        let buffer_ratio_bps = if base > 0 {
            (buffer_value as i128 * 10_000) / base
        } else {
            // No circulating-above-floor → buffer ratio is vacuously healthy.
            self.config.target_buffer_bps
        };
        let (band, buffer_action) = if buffer_ratio_bps < self.config.trip_buffer_bps {
            (RiskBand::Trip, BufferAction::PartialClose)
        } else if buffer_ratio_bps < self.config.warn_buffer_bps {
            (RiskBand::Warn, BufferAction::Rebalance)
        } else if buffer_ratio_bps < self.config.target_buffer_bps {
            (RiskBand::Adequate, BufferAction::Hold)
        } else {
            (RiskBand::Healthy, BufferAction::Hold)
        };

        StableControllerOutput {
            supply_delta,
            buffer_ratio_bps,
            band,
            buffer_action,
            control_signal_q18: u,
        }
    }
}

/// `x * bps / 10_000`, signed, saturating. Integer-only.
fn mul_bps(x: i128, bps: i128) -> i128 {
    x.saturating_mul(bps) / 10_000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> StableControllerConfig {
        StableControllerConfig::default()
    }

    #[test]
    fn validate_rejects_inverted_bands() {
        let mut c = cfg();
        c.trip_buffer_bps = c.warn_buffer_bps; // not strictly less
        assert!(c.validate().is_err());
    }

    #[test]
    fn at_peg_no_supply_move() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        let out = ctrl.step(Q18, 1_000_000, 1_200_000, u128::MAX);
        assert_eq!(out.supply_delta, 0);
        assert_eq!(out.band, RiskBand::Healthy);
    }

    #[test]
    fn above_peg_expands_supply() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        // Market 2% above target → controller mints to push price down.
        let market = Q18 + (Q18 * 2 / 100);
        let out = ctrl.step(market, 1_000_000, 1_200_000, u128::MAX);
        assert!(
            out.supply_delta > 0,
            "expected expansion, got {}",
            out.supply_delta
        );
        // Clamped to 5% of 1_000_000 = 50_000.
        assert!(out.supply_delta <= 50_000);
    }

    #[test]
    fn below_peg_contracts_supply() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        let market = Q18 - (Q18 * 2 / 100);
        let out = ctrl.step(market, 1_000_000, 1_200_000, u128::MAX);
        assert!(
            out.supply_delta < 0,
            "expected contraction, got {}",
            out.supply_delta
        );
    }

    #[test]
    fn mint_clamped_to_floor_headroom() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        let market = Q18 + (Q18 * 50 / 100); // big deviation
        // Only 1_000 units of headroom under the reserve floor.
        let out = ctrl.step(market, 1_000_000, 1_200_000, 1_000);
        assert!(out.supply_delta > 0);
        assert!(
            out.supply_delta <= 1_000,
            "must not cross floor: {}",
            out.supply_delta
        );
    }

    #[test]
    fn burn_not_limited_by_floor_headroom() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        let market = Q18 - (Q18 * 20 / 100);
        // Zero headroom must not block a burn (negative delta).
        let out = ctrl.step(market, 1_000_000, 1_200_000, 0);
        assert!(out.supply_delta < 0);
    }

    #[test]
    fn warn_band_triggers_rebalance() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        // buffer 108% < warn 110% but >= trip 105%.
        let out = ctrl.step(Q18, 1_000_000, 1_080_000, u128::MAX);
        assert_eq!(out.band, RiskBand::Warn);
        assert_eq!(out.buffer_action, BufferAction::Rebalance);
    }

    #[test]
    fn trip_band_triggers_partial_close() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        // buffer 100% < trip 105%.
        let out = ctrl.step(Q18, 1_000_000, 1_000_000, u128::MAX);
        assert_eq!(out.band, RiskBand::Trip);
        assert_eq!(out.buffer_action, BufferAction::PartialClose);
    }

    #[test]
    fn integral_leaks_toward_zero_at_peg() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        // Build up integral with a sustained deviation.
        let market = Q18 + (Q18 / 100);
        for _ in 0..5 {
            ctrl.step(market, 1_000_000, 1_200_000, u128::MAX);
        }
        let built = ctrl.integral_q18();
        assert!(built > 0);
        // Return to peg: error 0 each epoch, integral should decay via leak.
        for _ in 0..20 {
            ctrl.step(Q18, 1_000_000, 1_200_000, u128::MAX);
        }
        assert!(ctrl.integral_q18() < built, "integral should leak down");
    }

    #[test]
    fn zero_circulating_is_vacuously_healthy() {
        let mut ctrl = StableController::new(cfg()).unwrap();
        let out = ctrl.step(Q18, 0, 0, u128::MAX);
        assert_eq!(out.supply_delta, 0);
        assert_eq!(out.band, RiskBand::Healthy);
    }
}
