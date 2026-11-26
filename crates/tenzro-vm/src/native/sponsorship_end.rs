//! Running-cost sponsorship as a top-up that ends on paid usage.
//!
//! Once [`GATE`] is in force, a running-cost sponsorship (in TNZO or in a
//! stable asset) is refused, when proposed and when enacted, while the
//! trailing paid usage carries the validator set: the value settled between
//! distinct registered roots over the last [`WINDOW_PARAM`] closed reward
//! epochs, at the fee rate in force, at or above [`PER_VALIDATOR_PARAM`] a
//! day for each validator the last closed epoch's cover counted. It pays
//! again by itself when usage falls back under that.

use super::*;

/// Gate of the usage trigger.
pub const GATE: &str = "feature.sponsorship_usage_end.activation_epoch";

/// Governed key: paid usage a day, whole USD, per validator at which
/// running-cost sponsorship ends.
pub const PER_VALIDATOR_PARAM: &str =
    "feature.sponsorship_usage_end.paid_usage_usd_day_per_validator";

/// Governed key: closed reward epochs the trailing paid usage is counted
/// over.
pub const WINDOW_PARAM: &str = "feature.sponsorship_usage_end.window_epochs";

/// Trailing paid usage against the threshold that ends sponsorship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UsageTrigger {
    /// Trailing paid usage, micro-USD a day.
    pub usd_e6_day: u128,
    /// Where sponsorship ends, micro-USD a day.
    pub threshold_usd_e6_day: u128,
    /// Closed reward epochs counted.
    pub window: u64,
    /// Whether usage carries the set, so sponsorship has ended.
    pub ended: bool,
}

/// The trigger as the chain stands, or `None` while [`GATE`] is dormant or
/// no reward epoch has closed.
pub fn usage_trigger(state: &dyn VmState) -> Option<UsageTrigger> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return None;
    }
    let last = super::rewards::read_reward_state(state)
        .ok()?
        .last_closed_epoch?;
    let per_year = super::rewards::read_reward_schedule(state)
        .ok()?
        .epochs_per_year
        .max(1);
    let window = network_param(state, WINDOW_PARAM).max(1);
    let first = last.saturating_sub(window - 1);
    let counted = last - first + 1;
    let wei: u128 = (first..=last)
        .map(|e| super::economy::read_epoch_activity(state, e).organic_value)
        .fold(0, u128::saturating_add);
    let rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let per_epoch_e6 = super::settlement_asset::tnzo_value_e6(wei, rate) / u128::from(counted);
    let usd_e6_day = per_epoch_e6.saturating_mul(u128::from(per_year)) / 365;
    let validators = u128::from(super::validator_cover::read_cover(state, last).validators);
    let threshold_usd_e6_day = u128::from(network_param(state, PER_VALIDATOR_PARAM))
        .saturating_mul(1_000_000)
        .saturating_mul(validators);
    Some(UsageTrigger {
        usd_e6_day,
        threshold_usd_e6_day,
        window: counted,
        ended: validators > 0 && usd_e6_day >= threshold_usd_e6_day,
    })
}

/// Refuse a running-cost sponsorship while paid usage carries the set.
pub(super) fn require_sponsorship_open(state: &dyn VmState) -> Result<()> {
    match usage_trigger(state) {
        Some(t) if t.ended => Err(super::funding::refuse(format!(
            "paid usage carries the validator set (USD {} a day over the last {} epochs, \
             USD {} at which running-cost sponsorship ends), so it has ended; it resumes if \
             usage falls back",
            t.usd_e6_day / 1_000_000,
            t.window,
            t.threshold_usd_e6_day / 1_000_000
        ))),
        _ => Ok(()),
    }
}
