//! Economic security: slashable stake against what can leave over the
//! bridges.
//!
//! On-chain value is protected by every node checking every block. What a
//! coalition that signs conflicting histories can carry off is what leaves
//! over the bridges before it is stopped, and that is bounded by the
//! network-wide outflow caps. Two rules tie those caps to bonded stake:
//!
//! - **Stake-backed caps.** Each epoch the caps of units other than TNZO
//!   shrink, pro rata, so that what they let out in one epoch is worth at
//!   most two thirds of bonded stake divided by `1 + bridge.security_gamma_bps`,
//!   valued at the safety rate. A crash in the TNZO price shrinks them at
//!   once, without a vote. TNZO's own cap is counted against the same
//!   budget first.
//! - **Security ratio.** `attack_stake_bps` of bonded stake, against
//!   `security.attack_window_epochs` epochs of every effective cap valued in
//!   TNZO at the safety rate. A raise of any outflow cap, and the switch of
//!   the fee rate to validator mode, are refused unless the ratio stays at
//!   least `security.min_ratio_bps` after it; lowering a cap is never gated.
//!   The issuance controller moves the mint multiplier against the same
//!   ratio.
//!
//! The effective cap of a unit is the lower of its governed cap and its
//! stake-backed cap; the ratio and every exit read the effective caps. A
//! unit validators have not priced keeps its governed cap, makes the ratio
//! unknown, and so refuses every cap raise.

use revm::primitives::U256;
use tenzro_types::bridge_route::{NetworkOutflowLimits, OutflowCap, TNZO_UNIT, representation_id};

use super::*;

/// Governed key: least ratio of slashable stake to extractable value, bps.
pub const MIN_RATIO_PARAM: &str = "security.min_ratio_bps";
/// Governed key: share of bonded stake a safety fault puts at risk, bps.
pub const ATTACK_STAKE_PARAM: &str = "security.attack_stake_bps";
/// Governed key: epochs an attack drains the outflow caps before it is
/// stopped.
pub const ATTACK_WINDOW_PARAM: &str = "security.attack_window_epochs";
/// Governed key: margin the stake-backed caps keep for a price fall inside
/// one safety window, bps (10,000 = a fall of half).
pub const GAMMA_PARAM: &str = "bridge.security_gamma_bps";
/// Governed key: most epochs of a unit's effective cap the exit queue may
/// hold; an exit over the cap queues only while the queue is shorter.
pub const QUEUE_MAX_EPOCHS_PARAM: &str = "bridge.queue_max_epochs";

/// Genesis value of [`MIN_RATIO_PARAM`]: k = 1.5.
pub const DEFAULT_MIN_RATIO_BPS: u64 = 15_000;
/// Genesis value of [`ATTACK_STAKE_PARAM`]: a third, the stake accountable
/// safety puts at risk.
pub const DEFAULT_ATTACK_STAKE_BPS: u64 = 3_334;
/// Genesis value of [`ATTACK_WINDOW_PARAM`]: a day.
pub const DEFAULT_ATTACK_WINDOW_EPOCHS: u64 = 24;
/// Genesis value of [`GAMMA_PARAM`]: gamma = 1.
pub const DEFAULT_GAMMA_BPS: u64 = 10_000;
/// Genesis value of [`QUEUE_MAX_EPOCHS_PARAM`]: a day.
pub const DEFAULT_QUEUE_MAX_EPOCHS: u64 = 24;

fn mul_div(a: u128, b: u128, c: u128) -> u128 {
    if c == 0 {
        return u128::MAX;
    }
    u128::try_from(U256::from(a) * U256::from(b) / U256::from(c)).unwrap_or(u128::MAX)
}

/// Decimals of the token `unit` names: a deposit route's native asset, or
/// the representation of a listed asset once the ledger holds it.
fn unit_decimals(state: &dyn VmState, unit: &str) -> Option<u8> {
    if let Some(d) = super::bridge::deposit_asset_of_unit(unit) {
        return Some(d.decimals);
    }
    crate::token_ledger::read_token(state, &representation_id(unit)).map(|r| r.decimals)
}

/// TNZO wei worth `amount` smallest units of `unit` at the safety rate;
/// `None` when validators have not priced it.
pub fn unit_value_tnzo(state: &dyn VmState, unit: &str, amount: u128) -> Option<u128> {
    if unit == TNZO_UNIT {
        return Some(amount);
    }
    let decimals = unit_decimals(state, unit)?;
    economy::amount_in_tnzo_at(state, unit, decimals, amount, economy::safety_rate(state))
}

/// What the stake-backed caps let out in one epoch, TNZO wei: two thirds
/// of bonded stake over `1 + gamma`.
pub fn stake_backed_budget(state: &dyn VmState) -> u128 {
    let two_thirds = mul_div(total_bonded_stake(state), 2, 3);
    let gamma = u128::from(network_param(state, GAMMA_PARAM));
    mul_div(two_thirds, 10_000, 10_000u128.saturating_add(gamma))
}

/// The caps in force: each governed cap, the caps of units other than
/// TNZO cut pro rata so that, with TNZO's cap, they fit the stake-backed
/// budget. A unit validators have not priced keeps its governed cap.
pub fn effective_outflow_limits(
    state: &dyn VmState,
    governed: &NetworkOutflowLimits,
) -> NetworkOutflowLimits {
    let budget = stake_backed_budget(state);
    let tnzo = governed.per_epoch(TNZO_UNIT).unwrap_or(0);
    let room = budget.saturating_sub(tnzo);
    let values: Vec<Option<u128>> = governed
        .caps
        .iter()
        .map(|c| {
            (c.unit != TNZO_UNIT)
                .then(|| unit_value_tnzo(state, &c.unit, c.per_epoch))
                .flatten()
        })
        .collect();
    let total = values
        .iter()
        .flatten()
        .fold(0u128, |a, v| a.saturating_add(*v));
    if total <= room {
        return governed.clone();
    }
    NetworkOutflowLimits {
        caps: governed
            .caps
            .iter()
            .zip(&values)
            .map(|(c, v)| OutflowCap {
                unit: c.unit.clone(),
                per_epoch: match v {
                    Some(_) => mul_div(c.per_epoch, room, total),
                    None => c.per_epoch,
                },
            })
            .collect(),
    }
}

/// The outflow caps exits are held to now: the effective caps of the
/// governed limits, if any are set.
pub fn outflow_limits_in_force(state: &dyn VmState) -> Option<NetworkOutflowLimits> {
    super::read_bridge_outflow_limits(state).map(|l| effective_outflow_limits(state, &l))
}

/// TNZO wei a safety fault puts at risk: `attack_stake_bps` of bonded stake.
pub fn stake_at_risk_tnzo(state: &dyn VmState) -> u128 {
    mul_div(
        total_bonded_stake(state),
        u128::from(network_param(state, ATTACK_STAKE_PARAM).min(10_000)),
        10_000,
    )
}

/// TNZO wei one attack can take out under `limits`: the attack window times
/// every effective cap, valued at the safety rate. `None` when a unit is
/// unpriced.
pub fn extractable_tnzo(state: &dyn VmState, limits: &NetworkOutflowLimits) -> Option<u128> {
    let window = u128::from(network_param(state, ATTACK_WINDOW_PARAM).max(1));
    let per_epoch = effective_outflow_limits(state, limits)
        .caps
        .iter()
        .try_fold(0u128, |a, c| {
            Some(a.saturating_add(unit_value_tnzo(state, &c.unit, c.per_epoch)?))
        })?;
    Some(per_epoch.saturating_mul(window))
}

/// The ratio of slashable to extractable value, bps, given `slashable` and
/// `extractable`: `u64::MAX` when nothing can leave.
pub fn ratio_bps_of(slashable: u128, extractable: u128) -> u64 {
    if extractable == 0 {
        return u64::MAX;
    }
    // Exact while slashable stake is below 10^34 wei, far above any supply;
    // above it, rounded down to whole multiples, never overflowing.
    let bps = match slashable.checked_mul(10_000) {
        Some(n) => n / extractable,
        None => (slashable / extractable).saturating_mul(10_000),
    };
    u64::try_from(bps).unwrap_or(u64::MAX)
}

/// The security ratio under `limits`, bps; `None` when a unit is unpriced.
pub fn ratio_bps_under(state: &dyn VmState, limits: &NetworkOutflowLimits) -> Option<u64> {
    Some(ratio_bps_of(
        stake_at_risk_tnzo(state),
        extractable_tnzo(state, limits)?,
    ))
}

/// The security ratio under the caps set, bps. With no caps set nothing
/// leaves, so the ratio is `u64::MAX`.
pub fn ratio_bps(state: &dyn VmState) -> Option<u64> {
    match super::read_bridge_outflow_limits(state) {
        Some(limits) => ratio_bps_under(state, &limits),
        None => Some(u64::MAX),
    }
}

/// Refuse `what` unless the security ratio under `limits` is at least
/// `security.min_ratio_bps`.
pub fn require_secure(
    state: &dyn VmState,
    limits: &NetworkOutflowLimits,
    what: &str,
) -> Result<()> {
    let k = network_param(state, MIN_RATIO_PARAM);
    match ratio_bps_under(state, limits) {
        Some(r) if r >= k => Ok(()),
        Some(r) => Err(VmError::InvalidTransaction(format!(
            "{what} refused: slashable stake would cover {r} bps of what one attack can take \
             out over the bridges, under the {k} bps security.min_ratio_bps"
        ))),
        None => Err(VmError::InvalidTransaction(format!(
            "{what} refused: an outflow unit has no validator rate, so the security ratio is unknown"
        ))),
    }
}

/// Whether `new` raises any cap of `current`; a unit added counts as a
/// raise.
pub fn raises_any(current: &NetworkOutflowLimits, new: &NetworkOutflowLimits) -> bool {
    new.caps.iter().any(|c| {
        current
            .per_epoch(&c.unit)
            .is_none_or(|now| c.per_epoch > now)
    })
}

/// Refuse a parameter change the security ratio does not allow: switching
/// the fee rate to validator mode needs the ratio at least k under the caps
/// set.
pub fn param_change_allowed(
    state: &dyn VmState,
    key: &str,
    current: u64,
    value: u64,
) -> Result<()> {
    // Re-arming validator mode after the dispersion breaker fell back is a
    // switch to validator mode like any other.
    if key == economy::RATE_MODE_PARAM
        && value == 1
        && (current == 0
            || economy::rate_breaker(state, economy::FEE_SYMBOL)
                .tripped_epoch
                .is_some())
    {
        let limits = super::read_bridge_outflow_limits(state).unwrap_or_default();
        if limits.caps.is_empty() {
            return Ok(());
        }
        return require_secure(state, &limits, "switching the fee rate to validator mode");
    }
    Ok(())
}

/// The security read-out: the ratio, its inputs and the stake-backed budget.
pub fn report(state: &dyn VmState) -> serde_json::Value {
    let limits = super::read_bridge_outflow_limits(state);
    let extractable = limits.as_ref().map(|l| extractable_tnzo(state, l));
    serde_json::json!({
        "ratio_bps": ratio_bps(state),
        "min_ratio_bps": network_param(state, MIN_RATIO_PARAM),
        "stake_at_risk_tnzo": stake_at_risk_tnzo(state).to_string(),
        "extractable_tnzo": extractable.flatten().map(|v| v.to_string()),
        "attack_window_epochs": network_param(state, ATTACK_WINDOW_PARAM),
        "stake_backed_budget_tnzo": stake_backed_budget(state).to_string(),
        "gamma_bps": network_param(state, GAMMA_PARAM),
        "safety_rate_nano_usd": economy::safety_rate(state).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;
    use tenzro_types::constants::ONE_TNZO;

    fn cap(unit: &str, per_epoch: u128) -> OutflowCap {
        OutflowCap {
            unit: unit.into(),
            per_epoch,
        }
    }

    /// Whole TNZO and micro-USD of USDC and OUSD.
    fn caps3(tnzo: u128, usdc: u128, ousd: u128) -> NetworkOutflowLimits {
        NetworkOutflowLimits {
            caps: vec![
                cap(TNZO_UNIT, tnzo * ONE_TNZO),
                cap("USDC", usdc),
                cap("OUSD", ousd),
            ],
        }
    }

    fn caps(tnzo: u128, usdc: u128) -> NetworkOutflowLimits {
        NetworkOutflowLimits {
            caps: vec![
                cap(TNZO_UNIT, tnzo * ONE_TNZO),
                cap("USDC", usdc * 1_000_000),
            ],
        }
    }

    /// 21 validators of 10,000 TNZO; USDC and OUSD listed with 6 decimals
    /// and priced at one dollar; TNZO at `tnzo_nano_usd`.
    fn network(tnzo_nano_usd: u128) -> StateAdapter {
        let mut state = StateAdapter::new();
        staking::add_bond(&mut state, &[1; 32], 210_000 * ONE_TNZO, 0).unwrap();
        let mut ch = Vec::new();
        for unit in ["USDC", "OUSD"] {
            bridge::issue_representation(
                &mut state,
                &representation_id(unit),
                unit,
                unit,
                6,
                &[9; 32],
                1,
                0,
                &mut ch,
            )
            .unwrap();
            economy::write_symbol_rate_for_tests(&mut state, unit, 1, 1_000_000_000);
        }
        economy::write_rate_for_tests(&mut state, 1, tnzo_nano_usd, tnzo_nano_usd);
        state
    }

    #[test]
    fn the_genesis_caps_are_backed_at_the_genesis_rate() {
        let state = network(100_000_000);
        // 648 TNZO, 64.82 USDC and 64.82 OUSD (648.2 TNZO each at 0.10) an
        // hour: about 1,945 TNZO in all.
        let l = caps3(648, 64_820_000, 64_820_000);
        let r = ratio_bps_under(&state, &l).unwrap();
        assert!(r >= DEFAULT_MIN_RATIO_BPS, "{r}");
        assert!(r < DEFAULT_MIN_RATIO_BPS + 50, "{r}");
        // A cap raise past the backing is refused; within it, allowed.
        assert!(require_secure(&state, &caps(25_000, 10_000), "raise").is_err());
        assert!(require_secure(&state, &l, "raise").is_ok());
    }

    #[test]
    fn a_crash_shrinks_foreign_caps_at_once_and_leaves_tnzo_alone() {
        // Budget: 2/3 x 210,000 / 2 = 70,000 TNZO an epoch.
        let governed = caps(10_000, 5_000);
        let calm = network(100_000_000);
        assert_eq!(stake_backed_budget(&calm), 70_000 * ONE_TNZO);
        assert_eq!(effective_outflow_limits(&calm, &governed), governed);
        // TNZO falls to a hundredth: 5,000 USDC is 5M TNZO, room is 60,000.
        let crashed = network(1_000_000);
        let eff = effective_outflow_limits(&crashed, &governed);
        assert_eq!(eff.per_epoch(TNZO_UNIT), governed.per_epoch(TNZO_UNIT));
        assert_eq!(eff.per_epoch("USDC"), Some(60 * 1_000_000));
        // Its value fits the budget left after TNZO's cap.
        let left = unit_value_tnzo(&crashed, "USDC", eff.per_epoch("USDC").unwrap()).unwrap();
        assert!(left <= 60_000 * ONE_TNZO);
    }

    #[test]
    fn an_unpriced_unit_keeps_its_cap_and_leaves_the_ratio_unknown() {
        let state = network(1_000_000);
        let mut l = caps(10_000, 5_000);
        l.caps.push(cap("EURC", 1));
        assert_eq!(
            effective_outflow_limits(&state, &l).per_epoch("EURC"),
            Some(1)
        );
        assert_eq!(ratio_bps_under(&state, &l), None);
        assert!(require_secure(&state, &l, "raise").is_err());
    }

    #[test]
    fn a_raise_is_any_higher_cap_or_any_new_unit() {
        let now = caps(10, 10);
        assert!(!raises_any(&now, &now));
        assert!(!raises_any(&now, &caps(5, 10)));
        assert!(raises_any(&now, &caps(11, 10)));
        let mut more = now.clone();
        more.caps.push(cap("OUSD", 1));
        assert!(raises_any(&now, &more));
    }

    #[test]
    fn validator_rate_mode_needs_the_ratio() {
        let mut state = network(100_000_000);
        let mut ch = Vec::new();
        funding::write_json(
            &mut state,
            BRIDGE_OUTFLOW_LIMITS_KEY,
            &caps(25_000, 10_000),
            &mut ch,
        )
        .unwrap();
        assert!(param_change_allowed(&state, economy::RATE_MODE_PARAM, 0, 1).is_err());
        assert!(param_change_allowed(&state, economy::RATE_MODE_PARAM, 1, 0).is_ok());
        funding::write_json(
            &mut state,
            BRIDGE_OUTFLOW_LIMITS_KEY,
            &caps(100, 10),
            &mut ch,
        )
        .unwrap();
        assert!(param_change_allowed(&state, economy::RATE_MODE_PARAM, 0, 1).is_ok());
    }

    #[test]
    fn nothing_leaving_is_an_unbounded_ratio() {
        assert_eq!(ratio_bps_of(1, 0), u64::MAX);
        assert_eq!(ratio_bps_of(u128::MAX, 1), u64::MAX);
        assert_eq!(ratio_bps_of(3, 2), 15_000);
        assert_eq!(ratio_bps(&StateAdapter::new()), Some(u64::MAX));
    }
}
