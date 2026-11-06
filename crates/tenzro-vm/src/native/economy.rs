//! Network economy in consensus state.
//!
//! - **USD-priced fees.** Gas is priced in USD and paid by burning the
//!   equivalent TNZO at the TNZO/USD rate chain state holds. The rate has two
//!   explicit modes, chosen by governance (`fees.usd_rate_mode`): in mode 0 it
//!   is the governance-set `fees.tnzo_usd_nano`; in mode 1 it is the
//!   stake-weighted median of the rates bonded validators seal and then open
//!   each epoch, each report the median of at least
//!   `fees.usd_rate_min_sources` independent sources;
//!   it moves only into the band between the stake-weighted
//!   `fees.usd_rate_quantile_low_bps` and `fees.usd_rate_quantile_high_bps`
//!   quantiles of the reports, rising at most `fees.usd_rate_max_change_bps`
//!   and falling at most `fees.usd_rate_max_fall_bps` per epoch, and holds
//!   while
//!   `fees.usd_rate_frozen` is set. The market rate starts from the
//!   governance rate, so switching modes never jumps. Prices outside the
//!   chain are evidence for governance, never an input.
//! - **Safe fallback.** Missing, late or outvoted reports never move the
//!   rate and never price fees at zero: fees go on at the last frozen rate.
//!   An epoch whose reports reach too little stake, or that governance
//!   holds, logs `FeeRateHeld`; once no median newer than
//!   `fees.usd_rate_max_age_epochs` has set the rate, [`rate_age`] reports
//!   it as held, so the read surface shows the fallback whether or not any
//!   report arrives.
//! - **Dispersion breaker.** An epoch whose reports spread wider than
//!   `fees.usd_rate_breaker_spread_bps` between the band quantiles, or whose
//!   TNZO median sits further than `fees.usd_rate_breaker_gap_bps` from the
//!   governance rate, holds the rate instead of moving it. After
//!   `fees.usd_rate_breaker_epochs` such epochs in a row the TNZO rate falls
//!   back to the governance rate, and stays there until governance sets
//!   `fees.usd_rate_mode` to 1 again. Disagreement between sources turns
//!   into a hold, never a move.
//! - **Unopened reports.** A validator that seals rates for an epoch and
//!   never opens them forfeits `fees.usd_rate_unopened_slash_bps` of its
//!   validator bond to the insurance pool when the epoch is tallied, so
//!   sealing and then withholding an unwelcome report costs stake.
//! - **Posted fees.** Identity registration, verification and inference
//!   settlement each pay a governed USD price per use, converted at the rate
//!   in force and burned in full. Nothing is prepaid: there is no credit that
//!   could be bought at one rate and spent at another.
//! - **Settlement fee.** Every on-chain settlement (escrow voucher, stream and
//!   hash-lock claims, x402) pays `fees.settlement_fee_bps` of the settled
//!   value, `fees.settlement_fee_burn_bps` of it burned and the rest to the
//!   treasury.
//! - **Activity.** Each settlement is counted in its reward epoch's
//!   [`EpochActivity`]. The apps, agents and tools the payer attributed it to
//!   earn ecosystem reward weight equal to `fees.activity_reward_fee_bps` of
//!   the fee that settlement paid, split evenly, and a royalty of
//!   `fees.creator_royalty_fee_bps` of the fee out of its treasury part. Its
//!   payee earns none of either; a payee whose bond or stake makes the
//!   payment provider work earns provider weight instead. Nothing is earned
//!   by a party that shares a root identity with the payer or the payee, or
//!   when either is unregistered. Provider weight, activity weight and
//!   royalty together stay within
//!   [`tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS`] of the fee and each
//!   bucket pays at most its recorded weight, so trading with oneself across
//!   identities always costs more than it earns.
//! - **Agent bonds.** A delegated agent's bond must cover a governed share
//!   (`agent_bond.spend_bps`) of its spend ceiling; a validator finding that
//!   quarantines the agent slashes the whole bond into the insurance pool.
//!
//! Records, all under `SYSTEM_ADDRESS`:
//! - `fxr_commit:<epoch>` — sealed rate reports; `fxr_symbols:<epoch>` —
//!   symbols opened; `fxr_pending` — epochs not yet tallied;
//!   `fxr_pruned_below` — the first epoch whose reports are still kept;
//!   `fxr_medians_pruned:<SYMBOL>` — the first epoch whose frozen median of
//!   the symbol is still kept.
//! - `fxr_sub:<SYMBOL>:<epoch>` / `fxr:<SYMBOL>:<epoch>` — opened rate
//!   reports and the frozen median, per symbol.
//! - `fxr_live:<SYMBOL>` — the rate currently in force for a symbol.
//! - `fxr_breaker:<SYMBOL>` — the dispersion breaker's [`RateBreaker`].
//! - `econ_epoch:<epoch 16-hex>` — an epoch's [`EpochActivity`], deleted
//!   with the epoch's other reward records once its claim window has passed.
//! - `econ_payer:<root>` — the last epoch a root paid in.
//! - `econ_fee:<root DID>` — settlement fees that root paid in the last
//!   epoch it paid in, the treasury excepted.
//!
//! Sealed and opened reports of a market epoch are deleted once the epoch is
//! tallied and its opening hour has passed. Frozen medians are kept for
//! [`KEPT_MEDIAN_EPOCHS`] behind the symbol's rate in force.

use serde::{Deserialize, Serialize};

use super::funding::{delete_record, read_json, refuse, write_json};
use super::*;

/// Selector of a validator's USD rate report.
pub const SELECTOR_FEE_RATE_SUBMIT: [u8; 4] = [0x01, 0x00, 0x00, 0x2c];
/// Gas for a rate report.
pub const GAS_FEE_RATE_SUBMIT: u64 = 40_000;
/// Most quotes one report may carry, across its symbols.
pub const MAX_RATE_QUOTES: usize = 64;
/// Fewest independent sources governance may require a symbol's rate in
/// one report to quote, and the genesis value of [`RATE_MIN_SOURCES_PARAM`].
pub const MIN_RATE_SOURCES: usize = 2;
/// Most independent sources governance may require per symbol.
pub const MAX_RATE_MIN_SOURCES: u64 = 16;
/// Log topic when an epoch's rate is frozen.
pub const FEE_RATE_FINALIZED_TOPIC: &[u8] = b"FeeRateFinalized";

/// Governed: 0 = the governance rate is in force, 1 = the validator median.
pub const RATE_MODE_PARAM: &str = "fees.usd_rate_mode";
/// Governed: the TNZO/USD rate in governance mode, nano-USD per TNZO.
pub const GOVERNANCE_RATE_PARAM: &str = "fees.tnzo_usd_nano";
/// Governed: most the market rate rises per epoch, bps.
pub const RATE_MAX_CHANGE_PARAM: &str = "fees.usd_rate_max_change_bps";
/// Governed key: most the market rate falls per epoch, bps. Falls follow a
/// crash faster than rises follow a pump: a rate that stays high after the
/// market fell overstates every USD value the chain checks.
pub const RATE_MAX_FALL_PARAM: &str = "fees.usd_rate_max_fall_bps";
/// Governed key: epochs of frozen medians the safety rate looks back over.
pub const SAFETY_RATE_WINDOW_PARAM: &str = "fees.safety_rate_window_epochs";
/// Governed key: share of bonded stake, bps, that must open its sealed rates
/// for an epoch's median to count.
pub const RATE_QUORUM_PARAM: &str = "fees.usd_rate_quorum_bps";
/// Governed key: low stake-weighted quantile of the reports, bps; the rate
/// moves only into the band between it and the high quantile.
pub const RATE_QUANTILE_LOW_PARAM: &str = "fees.usd_rate_quantile_low_bps";
/// Governed key: high stake-weighted quantile of the reports, bps.
pub const RATE_QUANTILE_HIGH_PARAM: &str = "fees.usd_rate_quantile_high_bps";
/// Governed key: 1 holds the validator rate where it is (a challenge or a
/// lost quorum); medians are still recorded.
pub const RATE_FROZEN_PARAM: &str = "fees.usd_rate_frozen";
/// Governed: epochs in a row short of the quorum, with a majority still
/// reporting, that the rate in force may sit further than
/// [`RATE_STALE_GAP_PARAM`] from their median before it moves toward that
/// median at the per-epoch bound.
pub const RATE_STALE_EPOCHS_PARAM: &str = "fees.usd_rate_stale_epochs";
/// Governed: gap between the rate in force and an epoch's median, bps of
/// the median, that counts the epoch as stale.
pub const RATE_STALE_GAP_PARAM: &str = "fees.usd_rate_stale_gap_bps";
/// Governed: share of bonded stake, bps, that must open its rates for an
/// epoch short of the quorum to count toward staleness and, once stale, to
/// move the rate toward its median. Never below a majority.
pub const RATE_STALE_QUORUM_PARAM: &str = "fees.usd_rate_stale_quorum_bps";
/// Governed: settlement fee, bps of settled value.
pub const SETTLEMENT_FEE_PARAM: &str = "fees.settlement_fee_bps";
/// Governed: most a settlement earns in activity rewards, bps of the
/// settlement fee it paid.
pub const ACTIVITY_REWARD_FEE_PARAM: &str = "fees.activity_reward_fee_bps";
/// Governed: share of the settlement fee burned, bps; the rest goes to the
/// treasury.
pub const SETTLEMENT_FEE_BURN_PARAM: &str = "fees.settlement_fee_burn_bps";
/// Governed: a delegated agent's bond, bps of its spend ceiling.
pub const AGENT_BOND_PARAM: &str = "agent_bond.spend_bps";
/// The least fee one settlement pays, micro-USD (converted at the live
/// rate, never above the settled value).
pub const MIN_SETTLEMENT_FEE_PARAM: &str = "fees.min_settlement_fee_micro_usd";

/// Genesis rate mode: governance.
pub const DEFAULT_RATE_MODE: u64 = 0;
/// Genesis governance rate: 0.10 USD per TNZO.
pub const DEFAULT_TNZO_USD_NANO: u64 = 100_000_000;
/// Genesis per-epoch (hourly) bound on a rise: 1%.
pub const DEFAULT_RATE_MAX_CHANGE_BPS: u64 = 100;
/// Genesis per-epoch (hourly) bound on a fall: 5%.
pub const DEFAULT_RATE_MAX_FALL_BPS: u64 = 500;
/// Genesis safety window: a day of hourly epochs.
pub const DEFAULT_SAFETY_RATE_WINDOW_EPOCHS: u64 = 24;
/// Most epochs governance may set the safety window to: a week of hourly
/// epochs.
pub const MAX_SAFETY_RATE_WINDOW_EPOCHS: u64 = 168;
/// Epochs of frozen medians kept behind a symbol's rate in force: the
/// longest window any reader looks back over, the safety window or the
/// treasury's volume window, at its governed maximum. Older medians are
/// deleted.
pub const KEPT_MEDIAN_EPOCHS: u64 = {
    let volume = super::treasury_reserve::MAX_VOLUME_WINDOW_EPOCHS;
    if volume > MAX_SAFETY_RATE_WINDOW_EPOCHS {
        volume
    } else {
        MAX_SAFETY_RATE_WINDOW_EPOCHS
    }
};
/// Two thirds of bonded stake opens an epoch's median.
pub const DEFAULT_RATE_QUORUM_BPS: u64 = 6_666;
/// The band between the one-third and two-thirds quantiles.
pub const DEFAULT_RATE_QUANTILE_LOW_BPS: u64 = 3_334;
/// High end of the band.
pub const DEFAULT_RATE_QUANTILE_HIGH_BPS: u64 = 6_666;
/// Genesis values of the staleness parameters: six hourly epochs, 3%, a
/// majority of stake.
pub const DEFAULT_RATE_STALE_EPOCHS: u64 = 6;
pub const DEFAULT_RATE_STALE_GAP_BPS: u64 = 300;
pub const DEFAULT_RATE_STALE_QUORUM_BPS: u64 = 5_001;
/// Governed: epochs the validator rate may go without a newer frozen median
/// before it is reported as held, counted from the epoch whose reports set
/// it. Fees go on at the held rate.
pub const RATE_MAX_AGE_PARAM: &str = "fees.usd_rate_max_age_epochs";
/// Genesis maximum age: a day of hourly epochs.
pub const DEFAULT_RATE_MAX_AGE_EPOCHS: u64 = 24;
/// Log topic when an epoch's reports leave the rate where it is because
/// too little stake opened them or governance holds the rate.
pub const FEE_RATE_HELD_TOPIC: &[u8] = b"FeeRateHeld";
/// Governed: fewest independent sources one report must quote for each
/// symbol. A report quoting fewer is refused when it is opened, and an
/// opened report below the value in force when its epoch is tallied is not
/// counted.
pub const RATE_MIN_SOURCES_PARAM: &str = "fees.usd_rate_min_sources";
/// Governed: widest spread between the low and high stake-weighted quantiles
/// of an epoch's reports, bps of the low quantile, before the epoch holds the
/// rate instead of moving it.
pub const RATE_BREAKER_SPREAD_PARAM: &str = "fees.usd_rate_breaker_spread_bps";
/// Governed: widest gap between an epoch's TNZO median and the governance
/// rate, bps of the governance rate, before the epoch holds the rate.
pub const RATE_BREAKER_GAP_PARAM: &str = "fees.usd_rate_breaker_gap_bps";
/// Governed: epochs in a row that breach the spread or the gap before the
/// TNZO rate falls back to the governance rate.
pub const RATE_BREAKER_EPOCHS_PARAM: &str = "fees.usd_rate_breaker_epochs";
/// Governed: bps of its validator bond a validator forfeits to the insurance
/// pool for each epoch it sealed rates for and never opened.
pub const RATE_UNOPENED_SLASH_PARAM: &str = "fees.usd_rate_unopened_slash_bps";
/// Genesis spread bound: 5%. Validators reading independent venues agree
/// far closer than this; a wider spread means a source is broken or moved.
pub const DEFAULT_RATE_BREAKER_SPREAD_BPS: u64 = 500;
/// Genesis gap bound: half the governance rate.
pub const DEFAULT_RATE_BREAKER_GAP_BPS: u64 = 5_000;
/// Genesis breach count before the fallback: three hourly epochs.
pub const DEFAULT_RATE_BREAKER_EPOCHS: u64 = 3;
/// Genesis forfeit for an unopened report: 0.1% of the validator bond.
pub const DEFAULT_RATE_UNOPENED_SLASH_BPS: u64 = 10;
/// Log topic when the dispersion breaker puts the governance rate in force.
pub const FEE_RATE_BREAKER_TOPIC: &[u8] = b"FeeRateBreakerTripped";
/// Log topic when a validator forfeits stake for a report it never opened.
pub const FEE_RATE_UNOPENED_TOPIC: &[u8] = b"FeeRateUnopened";

/// Governed key: share of an HTTP-402 payment settled off chain
/// (delivery-versus-payment and fiat rails) offered to the network treasury,
/// bps of the amount left after the developer margin.
pub const HTTP402_NETWORK_SHARE_PARAM: &str = "fees.http402_network_share_bps";

/// Governed key: most a developer may add on top of a network cost as its
/// own margin on an HTTP-402 payment, bps.
pub const MAX_DEVELOPER_MARGIN_PARAM: &str = "fees.max_developer_margin_bps";
/// Genesis settlement fee: 0.1%.
pub const DEFAULT_SETTLEMENT_FEE_BPS: u64 = tenzro_types::fees::DEFAULT_SETTLEMENT_FEE_BPS as u64;
/// Genesis activity reward cap: half the settlement fee.
pub const DEFAULT_ACTIVITY_REWARD_FEE_BPS: u64 = 5_000;
/// Highest activity reward cap governance may set: below the whole fee, so
/// a settlement always costs more than it earns.
pub const MAX_ACTIVITY_REWARD_FEE_BPS: u64 = 9_000;
/// Genesis settlement fee burn share: half; the other half to the treasury.
pub const DEFAULT_SETTLEMENT_FEE_BURN_BPS: u64 = 5_000;
/// Governed: royalty a settlement pays the apps, agents and tools its payer
/// attributed it to, bps of its fee. It is paid out of the fee's treasury
/// part, so the payer pays no more for it, and with the provider and
/// activity rewards it stays within
/// [`tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS`] of the fee.
pub const CREATOR_ROYALTY_FEE_PARAM: &str = "fees.creator_royalty_fee_bps";
/// Genesis creator royalty: none.
pub const DEFAULT_CREATOR_ROYALTY_FEE_BPS: u64 = 0;
/// Governed: the treasury leg of a settled inference payment, bps of what
/// the payee is credited after the settlement fee.
pub const TREASURY_LEG_INFERENCE_PARAM: &str = "fees.treasury_leg_inference_bps";
/// Governed: the treasury leg of a settled TEE session payment.
pub const TREASURY_LEG_TEE_PARAM: &str = "fees.treasury_leg_tee_bps";
/// Governed: the treasury leg of a settled RPC traffic payment.
pub const TREASURY_LEG_RPC_PARAM: &str = "fees.treasury_leg_rpc_bps";
/// Governed: the treasury leg of a settled compute lease payment.
pub const TREASURY_LEG_COMPUTE_PARAM: &str = "fees.treasury_leg_compute_bps";
/// Governed: the treasury leg of a settled storage payment.
pub const TREASURY_LEG_STORAGE_PARAM: &str = "fees.treasury_leg_storage_bps";
/// Genesis treasury leg of every provider class: none.
pub const DEFAULT_TREASURY_LEG_BPS: u64 = 0;
/// Highest treasury leg governance may set for a class.
pub const MAX_TREASURY_LEG_BPS: u64 = 5_000;

/// The governed treasury leg of a payment of `class` provider work, bps of
/// what the payee is credited after the settlement fee. Zero for anything
/// that is not provider work.
pub fn treasury_leg_bps(state: &dyn VmState, class: tenzro_token::rewards::WorkClass) -> u64 {
    use tenzro_token::rewards::WorkClass;
    let key = match class {
        WorkClass::InferenceServed => TREASURY_LEG_INFERENCE_PARAM,
        WorkClass::TeeSession => TREASURY_LEG_TEE_PARAM,
        WorkClass::RpcTraffic => TREASURY_LEG_RPC_PARAM,
        WorkClass::ComputeLease => TREASURY_LEG_COMPUTE_PARAM,
        WorkClass::StorageServed => TREASURY_LEG_STORAGE_PARAM,
        WorkClass::ConsensusVote | WorkClass::BlockProposal | WorkClass::AppUsage => return 0,
    };
    network_param(state, key).min(MAX_TREASURY_LEG_BPS)
}
/// Genesis agent bond: 10% of the spend ceiling.
pub const DEFAULT_AGENT_BOND_BPS: u64 = 1_000;
/// Genesis least settlement fee: one micro-USD.
pub const DEFAULT_MIN_SETTLEMENT_FEE_MICRO_USD: u64 = 1;
pub(super) const ATTO_PER_MICRO_USD: u128 = 1_000_000_000_000;

const NANO_PER_USD: u128 = 1_000_000_000;
/// The symbol whose rate prices fees.
pub const FEE_SYMBOL: &str = "TNZO";

// ---------------------------------------------------------------------------
// TNZO/USD rate
// ---------------------------------------------------------------------------

/// The market rate in force, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveRate {
    /// Nano-USD per TNZO, decimal.
    pub rate_nano_usd: String,
    /// Epoch whose median set it.
    pub epoch: u64,
    /// Consecutive epochs short of the quorum whose median sat further from
    /// the rate in force than the staleness gap.
    #[serde(default)]
    pub stale_epochs: u64,
}

/// The rate chain state prices fees at, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeRate {
    /// Nano-USD per TNZO.
    pub rate_nano_usd: u128,
    /// `governance` or `validators`.
    pub mode: String,
    /// Epoch whose median set it, in validator mode once one has.
    pub epoch: Option<u64>,
    /// Most the market rate rises per epoch, bps.
    pub max_change_bps: u64,
    /// Most the market rate falls per epoch, bps.
    pub max_fall_bps: u64,
}

fn governance_rate(state: &dyn VmState) -> u128 {
    u128::from(network_param(state, GOVERNANCE_RATE_PARAM).max(1))
}

fn live_key(symbol: &str) -> String {
    format!("fxr_live:{symbol}")
}

/// The dispersion breaker of a symbol, as stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateBreaker {
    /// Tallied epochs in a row whose reports breached the spread or gap bound.
    pub breached_epochs: u64,
    /// Epoch whose tally tripped the breaker. While set, the governance rate
    /// is in force whatever `fees.usd_rate_mode` says.
    #[serde(default)]
    pub tripped_epoch: Option<u64>,
}

fn breaker_key(symbol: &str) -> String {
    format!("fxr_breaker:{symbol}")
}

/// The dispersion breaker of `symbol`.
pub fn rate_breaker(state: &dyn VmState, symbol: &str) -> RateBreaker {
    read_json(state, &breaker_key(symbol)).unwrap_or_default()
}

/// Whether the validator TNZO rate is in force: governance chose mode 1 and
/// the dispersion breaker has not put the governance rate back in force.
pub fn validator_rate_in_force(state: &dyn VmState) -> bool {
    network_param(state, RATE_MODE_PARAM) == 1
        && rate_breaker(state, FEE_SYMBOL).tripped_epoch.is_none()
}

/// Clears the TNZO breaker: governance has set `fees.usd_rate_mode` to 1.
pub(super) fn rearm_rate_breaker(state: &mut dyn VmState, changes: &mut Vec<StateChange>) {
    delete_record(state, &breaker_key(FEE_SYMBOL), changes);
}

/// Whether reports spanning `low` to `high` spread wider than `bound_bps` of
/// `low`.
fn dispersed(low: u128, high: u128, bound_bps: u64) -> bool {
    let (lo, hi) = (low.min(high), high.max(low));
    (hi - lo).saturating_mul(10_000) > lo.saturating_mul(u128::from(bound_bps))
}

/// Whether `median` sits further than `bound_bps` of `governed` from it.
fn far_from_governed(median: u128, governed: u128, bound_bps: u64) -> bool {
    median.abs_diff(governed).saturating_mul(10_000)
        > governed.saturating_mul(u128::from(bound_bps))
}

fn live_rate(state: &dyn VmState, symbol: &str) -> Option<(u128, u64)> {
    let r: LiveRate = read_json(state, &live_key(symbol))?;
    Some((r.rate_nano_usd.parse().ok().filter(|v| *v > 0)?, r.epoch))
}

/// Symbol under which validators report, with their rates, the TNZO the
/// market traded over the last day, in nano-TNZO. It goes through the same
/// sealed reports, sources, quorum and band as every rate.
pub const VOLUME_SYMBOL: &str = "TNZOVOL";

/// TNZO the market traded over a day, wei, as the validators' volume reports
/// observed it at its lowest over the last `window` market epochs: each
/// epoch's report counts at the lower of its frozen median and the banded
/// value in force, and the lowest of them counts, so a sale sized from it
/// does not outrun a market whose volume has since fallen. Zero with no
/// report, or with none from the last `max_age` market epochs before
/// `market_epoch`.
pub fn observed_daily_volume(
    state: &dyn VmState,
    market_epoch: u64,
    max_age: u64,
    window: u64,
) -> u128 {
    let Some((_, latest)) = live_rate(state, VOLUME_SYMBOL) else {
        return 0;
    };
    if latest.saturating_add(max_age) < market_epoch {
        return 0;
    }
    let window = window.clamp(1, super::treasury_reserve::MAX_VOLUME_WINDOW_EPOCHS);
    let from = latest.saturating_sub(window - 1);
    let mut low: Option<u128> = None;
    for epoch in from..=latest {
        let Some(r) = read_committed_rate(state, VOLUME_SYMBOL, epoch) else {
            continue;
        };
        let (Ok(median), Ok(applied)) = (
            r.median_nano_usd.parse::<u128>(),
            r.applied_nano_usd.parse::<u128>(),
        ) else {
            continue;
        };
        let v = median.min(applied);
        low = Some(low.map_or(v, |l| l.min(v)));
    }
    low.unwrap_or(0).saturating_mul(1_000_000_000)
}

/// Writes a frozen TNZO median and the rate it applied, in validator mode,
/// as the tally leaves them, for tests elsewhere.
#[cfg(test)]
pub(crate) fn write_rate_for_tests(
    state: &mut dyn VmState,
    epoch: u64,
    median_nano_usd: u128,
    applied_nano_usd: u128,
) {
    let mut ch = Vec::new();
    super::set_genesis_param(state, RATE_MODE_PARAM, 1);
    let record = CommittedFeeRate {
        median_nano_usd: median_nano_usd.to_string(),
        applied_nano_usd: applied_nano_usd.to_string(),
        submitters: 3,
        stake: "1".into(),
    };
    write_json(
        state,
        &format!("fxr:{FEE_SYMBOL}:{epoch}"),
        &record,
        &mut ch,
    )
    .unwrap();
    let live = LiveRate {
        rate_nano_usd: applied_nano_usd.to_string(),
        epoch,
        stale_epochs: 0,
    };
    write_json(state, &live_key(FEE_SYMBOL), &live, &mut ch).unwrap();
}

/// Writes `symbol`'s frozen rate for `epoch`, for tests elsewhere.
#[cfg(test)]
pub(crate) fn write_symbol_rate_for_tests(
    state: &mut dyn VmState,
    symbol: &str,
    epoch: u64,
    nano_usd: u128,
) {
    let mut ch = Vec::new();
    let live = LiveRate {
        rate_nano_usd: nano_usd.to_string(),
        epoch,
        stale_epochs: 0,
    };
    write_json(state, &live_key(symbol), &live, &mut ch).unwrap();
}

/// Writes a volume report as the tally leaves it, for tests elsewhere.
#[cfg(test)]
pub(crate) fn write_volume_for_tests(state: &mut dyn VmState, epoch: u64, nano_tnzo: u128) {
    let mut ch = Vec::new();
    let live = LiveRate {
        rate_nano_usd: nano_tnzo.to_string(),
        epoch,
        stale_epochs: 0,
    };
    write_json(state, &live_key(VOLUME_SYMBOL), &live, &mut ch).unwrap();
    let record = CommittedFeeRate {
        median_nano_usd: nano_tnzo.to_string(),
        applied_nano_usd: nano_tnzo.to_string(),
        submitters: 3,
        stake: "1".into(),
    };
    write_json(
        state,
        &format!("fxr:{VOLUME_SYMBOL}:{epoch}"),
        &record,
        &mut ch,
    )
    .unwrap();
}

/// The TNZO/USD rate in force.
pub fn read_fee_rate(state: &dyn VmState) -> FeeRate {
    let max_change_bps = network_param(state, RATE_MAX_CHANGE_PARAM);
    let max_fall_bps = network_param(state, RATE_MAX_FALL_PARAM);
    if validator_rate_in_force(state) {
        // Validator mode starts from the governance rate until the first
        // epoch's median is frozen; every later move is bounded from there.
        let (rate, epoch) = match live_rate(state, FEE_SYMBOL) {
            Some((r, e)) => (r, Some(e)),
            None => (governance_rate(state), None),
        };
        FeeRate {
            rate_nano_usd: rate,
            mode: "validators".into(),
            epoch,
            max_change_bps,
            max_fall_bps,
        }
    } else {
        FeeRate {
            rate_nano_usd: governance_rate(state),
            mode: "governance".into(),
            epoch: None,
            max_change_bps,
            max_fall_bps,
        }
    }
}

/// How old a rate in force is, and whether fees are held at it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateAge {
    /// Epochs since the epoch whose reports set the rate; `None` when no
    /// validator median has set it.
    pub age_epochs: Option<u64>,
    /// `fees.usd_rate_max_age_epochs`.
    pub max_age_epochs: u64,
    /// The rate is validator-reported and no median newer than the maximum
    /// age has set it (or none ever has): fees are priced at the last good
    /// rate, which stays where it is until reports resume.
    pub held: bool,
}

/// Age of the `symbol` rate in force at chain calendar time `now_ms`. The
/// governance rate is never held: governance sets it directly.
pub fn rate_age(state: &dyn VmState, symbol: &str, now_ms: i64) -> RateAge {
    let max_age_epochs = network_param(state, RATE_MAX_AGE_PARAM);
    let symbol = normalize_symbol(symbol).unwrap_or_default();
    let governed = symbol == FEE_SYMBOL && !validator_rate_in_force(state);
    let set_at = if governed {
        None
    } else {
        live_record(state, &symbol).map(|l| l.1)
    };
    age_of(
        governed,
        set_at,
        (now_ms.max(0) / MARKET_EPOCH_MS) as u64,
        max_age_epochs,
    )
}

fn age_of(governed: bool, set_at: Option<u64>, now_epoch: u64, max_age_epochs: u64) -> RateAge {
    let age_epochs = set_at.map(|e| now_epoch.saturating_sub(e));
    RateAge {
        age_epochs,
        max_age_epochs,
        held: !governed && age_epochs.is_none_or(|a| a > max_age_epochs),
    }
}

/// The TNZO/USD rate safety checks value stake and caps at, nano-USD per
/// TNZO: the lower of the rate in force and the lowest frozen median of the
/// last `fees.safety_rate_window_epochs` epochs up to the one that set it.
/// A crash shows in the medians at once, while the rate in force follows
/// it at most `fees.usd_rate_max_fall_bps` an epoch, so a check never
/// trusts stake or collateral to be worth more than the market recently
/// said. Payments keep the rate in force.
pub fn safety_rate(state: &dyn VmState) -> u128 {
    let r = read_fee_rate(state);
    let Some(last) = r.epoch else {
        return r.rate_nano_usd;
    };
    let window =
        network_param(state, SAFETY_RATE_WINDOW_PARAM).clamp(1, MAX_SAFETY_RATE_WINDOW_EPOCHS);
    (last.saturating_sub(window - 1)..=last)
        .filter_map(|e| read_committed_rate(state, FEE_SYMBOL, e))
        .filter_map(|c| c.median_nano_usd.parse::<u128>().ok())
        .filter(|m| *m > 0)
        .fold(r.rate_nano_usd, u128::min)
}

/// The validator-median USD rate in force for `symbol` (nano-USD per whole
/// unit) and the epoch that set it. TNZO answers with the fee rate in
/// force; any other symbol answers only once validators have frozen one.
pub fn read_symbol_rate(state: &dyn VmState, symbol: &str) -> Option<(u128, Option<u64>)> {
    let symbol = normalize_symbol(symbol).ok()?;
    if symbol == FEE_SYMBOL {
        let r = read_fee_rate(state);
        return Some((r.rate_nano_usd, r.epoch));
    }
    live_rate(state, &symbol).map(|(r, e)| (r, Some(e)))
}

/// TNZO base units worth `amount` smallest units of `symbol` (with
/// `decimals` decimals) at the rates in force, rounded up. `None` when
/// validators have not priced `symbol`.
pub fn amount_in_tnzo(
    state: &dyn VmState,
    symbol: &str,
    decimals: u8,
    amount: u128,
) -> Option<u128> {
    amount_in_tnzo_at(
        state,
        symbol,
        decimals,
        amount,
        read_fee_rate(state).rate_nano_usd,
    )
}

/// [`amount_in_tnzo`] with TNZO valued at `tnzo_nano_usd` instead of the
/// rate in force: safety checks pass the safety rate.
pub fn amount_in_tnzo_at(
    state: &dyn VmState,
    symbol: &str,
    decimals: u8,
    amount: u128,
    tnzo_nano_usd: u128,
) -> Option<u128> {
    use revm::primitives::U256;
    if decimals > 36 {
        return None;
    }
    let (sym, _) = read_symbol_rate(state, symbol)?;
    let tnzo = tnzo_nano_usd.max(1);
    let num = U256::from(amount)
        .checked_mul(U256::from(sym))?
        .checked_mul(U256::from(10u128.pow(18)))?;
    let den = U256::from(10u128)
        .checked_pow(U256::from(decimals))?
        .checked_mul(U256::from(tnzo))?;
    let q = num.div_ceil(den);
    u128::try_from(q).ok()
}

/// The governed signer set of the rate stream `feed_id`, if installed.
pub fn read_rate_stream(
    state: &dyn VmState,
    feed_id: &[u8; 32],
) -> Option<tenzro_types::RateStreamSigners> {
    read_json(
        state,
        &tenzro_types::RateStreamSigners::storage_key(feed_id),
    )
}

/// The governed Proof-of-Reserve feed of `asset_id`, if installed.
pub fn read_reserve_feed(state: &dyn VmState, asset_id: &str) -> Option<tenzro_types::ReserveFeed> {
    read_json(state, &tenzro_types::ReserveFeed::storage_key(asset_id))
}

/// TNZO base units that pay `atto_usd` at the rate in force, rounded up so a
/// non-zero price never rounds to free.
pub fn usd_to_wei(state: &dyn VmState, atto_usd: u128) -> u128 {
    if atto_usd == 0 {
        return 0;
    }
    let rate = read_fee_rate(state).rate_nano_usd.max(1);
    atto_usd.saturating_mul(NANO_PER_USD).div_ceil(rate)
}

#[derive(Debug, Clone, Deserialize)]
struct RateQuote {
    symbol: String,
    source: String,
    rate_nano_usd: String,
}

#[derive(Debug, Clone, Deserialize)]
struct FeeRateSubmitPayload {
    epoch: u64,
    commitment: String,
    #[serde(default)]
    reveal: Option<RevealPayload>,
}

#[derive(Debug, Clone, Deserialize)]
struct RevealPayload {
    quotes: Vec<RateQuote>,
    salt: String,
}

/// One validator's sealed report for an epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateCommit {
    validator: String,
    commitment: String,
    stake: String,
    #[serde(default)]
    opened: bool,
    /// Its stake was taken for never opening the report.
    #[serde(default)]
    forfeited: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RateSubmission {
    validator: String,
    rate: String,
    stake: String,
    sources: Vec<String>,
}

/// A frozen epoch rate, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommittedFeeRate {
    /// Stake-weighted median of the reports, nano-USD per unit.
    pub median_nano_usd: String,
    /// The median bounded by the per-epoch change limit: what took effect.
    pub applied_nano_usd: String,
    /// Validators it was computed from.
    pub submitters: usize,
    /// Their combined stake.
    pub stake: String,
}

/// The frozen `symbol` rate for `epoch`, if validators have reported it.
pub fn read_committed_rate(
    state: &dyn VmState,
    symbol: &str,
    epoch: u64,
) -> Option<CommittedFeeRate> {
    let symbol = normalize_symbol(symbol).ok()?;
    read_json(state, &format!("fxr:{symbol}:{epoch}"))
}

/// A symbol as rates are keyed: 2 to 12 upper-case letters and digits.
pub fn normalize_symbol(symbol: &str) -> Result<String> {
    let s = symbol.trim().to_ascii_uppercase();
    if s.len() < 2 || s.len() > 12 || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(refuse(format!(
            "rate symbol {symbol:?} is not 2 to 12 letters or digits"
        )));
    }
    Ok(s)
}

/// One symbol's rate in a report: the median of its quotes (the lower
/// middle for an even count), refused unless at least `min_sources`
/// distinct sources quote it.
fn report_rate(quotes: &[&RateQuote], min_sources: usize) -> Result<(u128, Vec<String>)> {
    let mut sources: Vec<String> = Vec::with_capacity(quotes.len());
    let mut rates = Vec::with_capacity(quotes.len());
    for q in quotes {
        let source = q.source.trim().to_ascii_lowercase();
        if source.is_empty() || source.len() > 64 {
            return Err(refuse("a rate source is named in 1 to 64 characters"));
        }
        if sources.contains(&source) {
            return Err(refuse(format!(
                "source {source} is quoted twice for one symbol"
            )));
        }
        let rate: u128 = q
            .rate_nano_usd
            .parse()
            .ok()
            .filter(|r| *r > 0)
            .ok_or_else(|| refuse("rate_nano_usd must be a positive integer"))?;
        sources.push(source);
        rates.push(rate);
    }
    if sources.len() < min_sources.max(MIN_RATE_SOURCES) {
        return Err(refuse(format!(
            "a symbol's rate needs at least {} independent sources",
            min_sources.max(MIN_RATE_SOURCES)
        )));
    }
    rates.sort_unstable();
    Ok((rates[(rates.len() - 1) / 2], sources))
}

/// A report's quotes grouped by symbol, each group checked.
fn report_rates(
    quotes: &[RateQuote],
    min_sources: usize,
) -> Result<Vec<(String, u128, Vec<String>)>> {
    if quotes.len() > MAX_RATE_QUOTES {
        return Err(refuse(format!(
            "a rate report carries at most {MAX_RATE_QUOTES} quotes"
        )));
    }
    let mut by: std::collections::BTreeMap<String, Vec<&RateQuote>> = Default::default();
    for q in quotes {
        by.entry(normalize_symbol(&q.symbol)?).or_default().push(q);
    }
    if by.is_empty() {
        return Err(refuse("a rate report quotes at least one symbol"));
    }
    by.into_iter()
        .map(|(symbol, qs)| {
            let (rate, sources) = report_rate(&qs, min_sources)?;
            Ok((symbol, rate, sources))
        })
        .collect()
}

/// `median` reached from `prior` rising at most `max_rise_bps` and falling
/// at most `max_fall_bps` of `prior`.
fn bounded(prior: u128, median: u128, max_rise_bps: u64, max_fall_bps: u64) -> u128 {
    let step = |bps: u64| prior.saturating_mul(u128::from(bps.min(10_000))) / 10_000;
    median.clamp(
        prior.saturating_sub(step(max_fall_bps)).max(1),
        prior.saturating_add(step(max_rise_bps)),
    )
}

/// The stake-weighted `q_bps` quantile of `rows` (rate, validator, stake):
/// the lowest rate at or below which reports holding `q_bps` of the stake lie.
fn stake_weighted_quantile(rows: &mut [(u128, String, u128)], q_bps: u64) -> Option<u128> {
    rows.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let total = rows.iter().fold(0u128, |a, r| a.saturating_add(r.2));
    if total == 0 {
        return None;
    }
    let q = u128::from(q_bps.min(10_000));
    let mut cum = 0u128;
    for (rate, _, stake) in rows.iter() {
        cum = cum.saturating_add(*stake);
        if cum.saturating_mul(10_000) >= total.saturating_mul(q) {
            return Some(*rate);
        }
    }
    rows.last().map(|r| r.0)
}

/// The next rate: `prior` moved only into the band between the low and high
/// stake-weighted quantiles of the reports, then up by at most
/// `max_rise_bps` or down by at most `max_fall_bps` of `prior`. Reporters
/// holding less than the low quantile's share can stop the rate moving but
/// never move it; honest agreement moves it fully.
fn banded(prior: u128, low: u128, high: u128, max_rise_bps: u64, max_fall_bps: u64) -> u128 {
    bounded(
        prior,
        prior.clamp(low.min(high), high.max(low)),
        max_rise_bps,
        max_fall_bps,
    )
}

fn commits_key(epoch: u64) -> String {
    format!("fxr_commit:{epoch}")
}

fn opened_symbols_key(epoch: u64) -> String {
    format!("fxr_symbols:{epoch}")
}

const PENDING_RATE_EPOCHS_KEY: &str = "fxr_pending";

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| refuse(format!("{what} is not hex")))?;
    b.try_into()
        .map_err(|_| refuse(format!("{what} is not 32 bytes")))
}

/// One validator's sealed rates for the epoch that just closed, and the
/// opening of its sealed rates for the epoch before.
///
/// Rates for epoch `e` are sealed while epoch `e + 1` runs and opened while
/// `e + 2` runs, so every report is fixed before any is seen. When `e + 2`
/// ends (or every validator that sealed has opened), each symbol's
/// stake-weighted median of the opened rates is recorded if the stake that
/// opened it reaches `fees.usd_rate_quorum_bps` of bonded stake. The rate in
/// force then moves only into the band between the low and high quantiles
/// of the opened rates, up at most `fees.usd_rate_max_change_bps` and down
/// at most `fees.usd_rate_max_fall_bps` of itself, and not at all while `fees.usd_rate_frozen` is set. Outlying reports are
/// never slashed: under a majority cartel the honest reporters are the
/// outliers. TNZO's rate prices fees; the others
/// price amounts named in other assets (a destination chain's native fee).
pub(super) fn submit_rate(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    let p: FeeRateSubmitPayload = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("Invalid FeeRateSubmit payload: {e}")))?;
    let now_epoch = (now_ms.max(0) / MARKET_EPOCH_MS) as u64;
    if p.epoch + 1 != now_epoch {
        return Err(refuse(format!(
            "rates for epoch {} are sealed only during epoch {} (current {now_epoch})",
            p.epoch,
            p.epoch + 1
        )));
    }
    let stake = bonded_stake_of(state, from);
    if stake == 0 {
        return Err(refuse("only accounts with bonded stake may report rates"));
    }
    let commitment = parse_hex32(&p.commitment, "commitment")?;
    let me = hex::encode(from);
    let mut changes = Vec::new();
    let mut logs = Vec::new();

    // Epochs whose opening hour has ended are tallied first.
    let pending: Vec<u64> = read_json(state, PENDING_RATE_EPOCHS_KEY).unwrap_or_default();
    let (due, mut keep): (Vec<u64>, Vec<u64>) = pending.iter().partition(|e| **e + 2 < now_epoch);
    for e in due {
        tally_rates(state, e, &mut changes, &mut logs)?;
    }
    prune_rate_epochs(state, now_epoch, &pending, &mut changes)?;

    // Seal this epoch.
    let ck = commits_key(p.epoch);
    let mut commits: Vec<RateCommit> = read_json(state, &ck).unwrap_or_default();
    if commits.iter().any(|c| c.validator == me) {
        return Err(refuse(format!(
            "this validator already sealed its rates for epoch {}",
            p.epoch
        )));
    }
    commits.push(RateCommit {
        validator: me.clone(),
        commitment: hex::encode(commitment),
        stake: stake.to_string(),
        opened: false,
        forfeited: false,
    });
    write_json(state, &ck, &commits, &mut changes)?;
    if !keep.contains(&p.epoch) {
        keep.push(p.epoch);
    }

    // Open the epoch before. Opening an epoch this validator has no seal
    // for (its sealing report did not land) opens nothing, and the seal
    // made now still stands: a missed hour costs that hour's report, not
    // every report after it.
    let reveal = match p.reveal {
        Some(r) => {
            let prev = p
                .epoch
                .checked_sub(1)
                .ok_or_else(|| refuse("epoch 0 has no earlier sealed rates to open"))?;
            let prior: Vec<RateCommit> = read_json(state, &commits_key(prev)).unwrap_or_default();
            prior.iter().any(|c| c.validator == me).then_some(r)
        }
        None => None,
    };
    if let Some(r) = reveal {
        let prev = p.epoch - 1;
        let pk = commits_key(prev);
        let mut prior: Vec<RateCommit> = read_json(state, &pk).unwrap_or_default();
        let Some(mine) = prior.iter_mut().find(|c| c.validator == me) else {
            return Err(refuse(format!(
                "this validator sealed no rates for epoch {prev}"
            )));
        };
        if mine.opened {
            return Err(refuse(format!(
                "this validator already opened its rates for epoch {prev}"
            )));
        }
        let salt = parse_hex32(&r.salt, "salt")?;
        let mut parsed = Vec::with_capacity(r.quotes.len());
        for q in &r.quotes {
            let rate: u128 = q
                .rate_nano_usd
                .parse()
                .map_err(|_| refuse("rate_nano_usd must be a positive integer"))?;
            parsed.push((q.symbol.as_str(), q.source.as_str(), rate));
        }
        let expect = tenzro_types::fee_rate_commitment(from, prev, &salt, parsed);
        if hex::encode(expect) != mine.commitment {
            return Err(refuse(format!(
                "the opened rates do not match the rates sealed for epoch {prev}"
            )));
        }
        mine.opened = true;
        let sealed_stake = mine.stake.clone();
        let all_opened = prior.iter().all(|c| c.opened);
        write_json(state, &pk, &prior, &mut changes)?;
        let sk = opened_symbols_key(prev);
        let mut symbols: Vec<String> = read_json(state, &sk).unwrap_or_default();
        for (symbol, rate, sources) in report_rates(&r.quotes, min_rate_sources(state))? {
            let subs_key = format!("fxr_sub:{symbol}:{prev}");
            let mut subs: Vec<RateSubmission> = read_json(state, &subs_key).unwrap_or_default();
            subs.push(RateSubmission {
                validator: me.clone(),
                rate: rate.to_string(),
                stake: sealed_stake.clone(),
                sources,
            });
            write_json(state, &subs_key, &subs, &mut changes)?;
            if !symbols.contains(&symbol) {
                symbols.push(symbol);
            }
        }
        write_json(state, &sk, &symbols, &mut changes)?;
        if all_opened && keep.contains(&prev) {
            tally_rates(state, prev, &mut changes, &mut logs)?;
            keep.retain(|e| *e != prev);
        }
    }
    keep.sort_unstable();
    if keep != pending {
        write_json(state, PENDING_RATE_EPOCHS_KEY, &keep, &mut changes)?;
    }
    Ok((changes, logs))
}

/// `fees.usd_rate_min_sources` in force.
fn min_rate_sources(state: &dyn VmState) -> usize {
    network_param(state, RATE_MIN_SOURCES_PARAM)
        .clamp(MIN_RATE_SOURCES as u64, MAX_RATE_MIN_SOURCES) as usize
}

/// Key of the first market epoch whose sealed and opened reports are kept.
const RATE_PRUNED_BELOW_KEY: &str = "fxr_pruned_below";

/// Most market epochs one report deletes the reports of, so a chain that
/// starts deleting late catches up over several reports at a bounded cost.
const MAX_RATE_PRUNED_EPOCHS: u64 = 64;

/// Deletes the sealed reports, opened symbols and opened reports of every
/// market epoch `e` with `e + 2 < now_epoch`. Epoch `e` is sealed during
/// `e + 1` and opened during `e + 2`; once that hour has passed it is
/// tallied (the caller tallies every such epoch still pending first), and
/// nothing reads its reports again. The frozen medians stay. A chain that
/// had never deleted starts from its oldest pending epoch.
fn prune_rate_epochs(
    state: &mut dyn VmState,
    now_epoch: u64,
    pending: &[u64],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let end = now_epoch.saturating_sub(2);
    let kept: Option<u64> = read_json(state, RATE_PRUNED_BELOW_KEY);
    let from = kept.unwrap_or_else(|| pending.iter().copied().fold(end, u64::min));
    let to = end
        .min(from.saturating_add(MAX_RATE_PRUNED_EPOCHS))
        .max(from);
    for e in from..to {
        let symbols: Vec<String> = read_json(state, &opened_symbols_key(e)).unwrap_or_default();
        for symbol in symbols {
            delete_record(state, &format!("fxr_sub:{symbol}:{e}"), changes);
        }
        delete_record(state, &opened_symbols_key(e), changes);
        delete_record(state, &commits_key(e), changes);
    }
    // Recorded from the first report on, nothing due or not: without it every
    // report started again at its own cutoff and nothing was ever deleted.
    if kept != Some(to) {
        write_json(state, RATE_PRUNED_BELOW_KEY, &to, changes)?;
    }
    Ok(())
}

/// Deletes the frozen medians of `symbol` more than [`KEPT_MEDIAN_EPOCHS`]
/// behind `live`, the epoch of its rate in force, at most
/// [`MAX_RATE_PRUNED_EPOCHS`] epochs a call. Every reader looks back from
/// the rate in force over a governed window capped below that. A symbol's
/// first median starts the count where nothing older can exist.
fn prune_medians(
    state: &mut dyn VmState,
    symbol: &str,
    live: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let key = format!("fxr_medians_pruned:{symbol}");
    let end = live.saturating_add(1).saturating_sub(KEPT_MEDIAN_EPOCHS);
    let from: u64 = read_json(state, &key).unwrap_or(end);
    let to = end.min(from.saturating_add(MAX_RATE_PRUNED_EPOCHS));
    for e in from..to {
        delete_record(state, &format!("fxr:{symbol}:{e}"), changes);
    }
    if read_json::<u64>(state, &key) != Some(to.max(from)) {
        write_json(state, &key, &to.max(from), changes)?;
    }
    Ok(())
}

/// Freeze each opened symbol's median for `epoch` and move its rate in force.
fn tally_rates(
    state: &mut dyn VmState,
    epoch: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let total = total_bonded_stake(state);
    let quorum = u128::from(network_param(state, RATE_QUORUM_PARAM).min(10_000));
    let stale_quorum = u128::from(
        network_param(state, RATE_STALE_QUORUM_PARAM).clamp(DEFAULT_RATE_STALE_QUORUM_BPS, 10_000),
    );
    let rules = RateRules {
        max_change_bps: network_param(state, RATE_MAX_CHANGE_PARAM),
        max_fall_bps: network_param(state, RATE_MAX_FALL_PARAM),
        stale_epochs: network_param(state, RATE_STALE_EPOCHS_PARAM).max(1),
        stale_gap_bps: network_param(state, RATE_STALE_GAP_PARAM),
        frozen: network_param(state, RATE_FROZEN_PARAM) == 1,
    };
    let q_low = network_param(state, RATE_QUANTILE_LOW_PARAM);
    let q_high = network_param(state, RATE_QUANTILE_HIGH_PARAM);
    let min_sources = min_rate_sources(state);
    let spread_bound = network_param(state, RATE_BREAKER_SPREAD_PARAM);
    let gap_bound = network_param(state, RATE_BREAKER_GAP_PARAM);
    let breaker_epochs = network_param(state, RATE_BREAKER_EPOCHS_PARAM).max(1);
    let symbols: Vec<String> = read_json(state, &opened_symbols_key(epoch)).unwrap_or_default();
    for symbol in symbols {
        let final_key = format!("fxr:{symbol}:{epoch}");
        if state
            .get_storage(&SYSTEM_ADDRESS, final_key.as_bytes())
            .is_some_and(|b| !b.is_empty())
        {
            continue;
        }
        let subs: Vec<RateSubmission> =
            read_json(state, &format!("fxr_sub:{symbol}:{epoch}")).unwrap_or_default();
        let mut rows: Vec<(u128, String, u128)> = subs
            .iter()
            .filter(|s| s.sources.len() >= min_sources)
            .filter_map(|s| {
                Some((
                    s.rate.parse().ok()?,
                    s.validator.clone(),
                    s.stake.parse().ok()?,
                ))
            })
            .collect();
        let opened = rows.iter().fold(0u128, |a, r| a.saturating_add(r.2));
        if total == 0 || opened.saturating_mul(10_000) < total.saturating_mul(stale_quorum) {
            logs.push(held_log(
                state,
                &symbol,
                epoch,
                "below_quorum",
                opened,
                total,
            )?);
            continue;
        }
        let full = opened.saturating_mul(10_000) >= total.saturating_mul(quorum);
        let (Some(median), Some(low), Some(high)) = (
            stake_weighted_quantile(&mut rows, 5_000),
            stake_weighted_quantile(&mut rows, q_low),
            stake_weighted_quantile(&mut rows, q_high),
        ) else {
            continue;
        };
        let live = live_record(state, &symbol);
        let prior = match &live {
            Some(l) => Some(l.0),
            None if symbol == FEE_SYMBOL => Some(governance_rate(state)),
            // A symbol's first frozen median has nothing to move from.
            None => None,
        };
        let breach = dispersed(low, high, spread_bound)
            || (symbol == FEE_SYMBOL
                && far_from_governed(median, governance_rate(state), gap_bound));
        if symbol == FEE_SYMBOL
            && let Some(log) = count_breach(state, epoch, breach, breaker_epochs, changes)?
        {
            logs.push(log);
        }
        // Dispersed reports never set a symbol's first rate either.
        if breach && prior.is_none() {
            logs.push(held_log(
                state,
                &symbol,
                epoch,
                "dispersion",
                opened,
                total,
            )?);
            continue;
        }
        let rules = RateRules {
            frozen: rules.frozen || breach,
            ..rules
        };
        let Some((applied, stale_epochs)) = next_rate(
            prior,
            live.as_ref().map_or(0, |l| l.2),
            Tally {
                median,
                low,
                high,
                full,
            },
            &rules,
        ) else {
            continue;
        };
        if rules.frozen {
            logs.push(held_log(
                state,
                &symbol,
                epoch,
                if breach {
                    "dispersion"
                } else {
                    "governance_hold"
                },
                opened,
                total,
            )?);
        }
        let record = CommittedFeeRate {
            median_nano_usd: median.to_string(),
            applied_nano_usd: applied.to_string(),
            submitters: rows.len(),
            stake: opened.to_string(),
        };
        write_json(state, &final_key, &record, changes)?;
        if live.as_ref().is_none_or(|l| epoch > l.1) {
            let next = LiveRate {
                rate_nano_usd: applied.to_string(),
                epoch,
                stale_epochs,
            };
            write_json(state, &live_key(&symbol), &next, changes)?;
            prune_medians(state, &symbol, epoch, changes)?;
            super::settlement_asset::observe_rate(state, &symbol, epoch, applied, changes, logs)?;
        }
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![FEE_RATE_FINALIZED_TOPIC.to_vec()],
            serde_json::to_vec(&serde_json::json!({
                "symbol": symbol,
                "epoch": epoch,
                "median_nano_usd": record.median_nano_usd,
                "applied_nano_usd": record.applied_nano_usd,
                "quorum": full,
                "stale_epochs": stale_epochs,
            }))
            .map_err(|e| VmError::Internal(format!("encode rate log: {e}")))?,
        ));
    }
    forfeit_unopened(state, epoch, changes, logs)
}

/// Counts a tallied TNZO epoch on the dispersion breaker: a breach adds one,
/// a clean epoch starts the count again. The count reaching `trip_after`
/// puts the governance rate in force and returns the `FeeRateBreakerTripped`
/// log. A tripped breaker stays tripped until governance re-arms mode 1.
fn count_breach(
    state: &mut dyn VmState,
    epoch: u64,
    breach: bool,
    trip_after: u64,
    changes: &mut Vec<StateChange>,
) -> Result<Option<Log>> {
    let mut b = rate_breaker(state, FEE_SYMBOL);
    if b.tripped_epoch.is_some() {
        return Ok(None);
    }
    let before = b.clone();
    b.breached_epochs = if breach {
        b.breached_epochs.saturating_add(1)
    } else {
        0
    };
    let tripped = b.breached_epochs >= trip_after;
    if tripped {
        b.tripped_epoch = Some(epoch);
    }
    if b != before {
        write_json(state, &breaker_key(FEE_SYMBOL), &b, changes)?;
    }
    if !tripped {
        return Ok(None);
    }
    let data = serde_json::to_vec(&serde_json::json!({
        "symbol": FEE_SYMBOL,
        "epoch": epoch,
        "breached_epochs": b.breached_epochs,
        "rate_nano_usd": governance_rate(state).to_string(),
    }))
    .map_err(|e| VmError::Internal(format!("encode rate log: {e}")))?;
    Ok(Some(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![FEE_RATE_BREAKER_TOPIC.to_vec()],
        data,
    )))
}

/// Takes `fees.usd_rate_unopened_slash_bps` of the validator bond of every
/// validator that sealed rates for `epoch` and never opened them, into the
/// insurance pool, once. Called when the epoch is tallied, after its opening
/// hour has passed.
fn forfeit_unopened(
    state: &mut dyn VmState,
    epoch: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let key = commits_key(epoch);
    let mut commits: Vec<RateCommit> = read_json(state, &key).unwrap_or_default();
    if commits.iter().all(|c| c.opened || c.forfeited) {
        return Ok(());
    }
    let bps = network_param(state, RATE_UNOPENED_SLASH_PARAM).min(10_000) as u16;
    for c in commits.iter_mut().filter(|c| !c.opened && !c.forfeited) {
        c.forfeited = true;
        let Ok(addr) = hex::decode(&c.validator) else {
            continue;
        };
        let taken = super::staking::slash_to_insurance(
            state,
            &addr,
            super::staking::SlashedStake::Validator,
            bps,
            changes,
        )?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![FEE_RATE_UNOPENED_TOPIC.to_vec()],
            serde_json::to_vec(&serde_json::json!({
                "validator": c.validator,
                "epoch": epoch,
                "forfeited": taken.to_string(),
            }))
            .map_err(|e| VmError::Internal(format!("encode rate log: {e}")))?,
        ));
    }
    write_json(state, &key, &commits, changes)?;
    Ok(())
}

/// The `FeeRateHeld` log of an epoch that leaves `symbol`'s rate where it
/// is, with the rate fees go on at.
fn held_log(
    state: &dyn VmState,
    symbol: &str,
    epoch: u64,
    reason: &str,
    opened: u128,
    total: u128,
) -> Result<Log> {
    let in_force = live_record(state, symbol)
        .map(|l| l.0)
        .or_else(|| (symbol == FEE_SYMBOL).then(|| governance_rate(state)));
    let data = serde_json::to_vec(&serde_json::json!({
        "symbol": symbol,
        "epoch": epoch,
        "reason": reason,
        "rate_nano_usd": in_force.map(|r| r.to_string()),
        "opened_stake": opened.to_string(),
        "bonded_stake": total.to_string(),
    }))
    .map_err(|e| VmError::Internal(format!("encode rate log: {e}")))?;
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![FEE_RATE_HELD_TOPIC.to_vec()],
        data,
    ))
}

/// The rate in force for `symbol` as stored: rate, epoch, stale epochs.
fn live_record(state: &dyn VmState, symbol: &str) -> Option<(u128, u64, u64)> {
    let r: LiveRate = read_json(state, &live_key(symbol))?;
    Some((
        r.rate_nano_usd.parse().ok().filter(|v| *v > 0)?,
        r.epoch,
        r.stale_epochs,
    ))
}

/// The governed values one tally runs on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RateRules {
    pub max_change_bps: u64,
    pub max_fall_bps: u64,
    pub stale_epochs: u64,
    pub stale_gap_bps: u64,
    pub frozen: bool,
}

/// One epoch's opened reports: the stake-weighted median and band edges,
/// and whether the stake that opened them reached the quorum.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tally {
    pub median: u128,
    pub low: u128,
    pub high: u128,
    pub full: bool,
}

/// The next rate in force, and the stale-epoch count after this epoch.
///
/// With the quorum, the rate moves only into the band between the low and
/// high quantiles, at most the per-epoch bound: a group holding no more
/// than a third of the stake can neither move it nor hold it, and a group
/// short of two thirds cannot move it. Short of the quorum the band is not
/// formed and the rate stays; but when at least the staleness quorum (a
/// majority) still opened and their median sits further than the
/// staleness gap from the rate for `stale_epochs` epochs in a row, the
/// rate moves toward that median at the per-epoch bound. Withholding
/// reports therefore freezes the rate for the window at most, and only the
/// stake that reports moves it. A governance hold keeps the rate where it
/// is. `None` when there is no rate to move and this epoch cannot set the
/// first one.
pub(crate) fn next_rate(
    prior: Option<u128>,
    stale: u64,
    t: Tally,
    rules: &RateRules,
) -> Option<(u128, u64)> {
    let Some(prior) = prior else {
        return t.full.then_some((t.median, 0));
    };
    if rules.frozen {
        return Some((prior, stale));
    }
    if t.full {
        return Some((
            banded(
                prior,
                t.low,
                t.high,
                rules.max_change_bps,
                rules.max_fall_bps,
            ),
            0,
        ));
    }
    let gap = prior.abs_diff(t.median);
    let far = gap.saturating_mul(10_000) > t.median.saturating_mul(u128::from(rules.stale_gap_bps));
    let stale = if far { stale.saturating_add(1) } else { 0 };
    if stale >= rules.stale_epochs {
        Some((
            bounded(prior, t.median, rules.max_change_bps, rules.max_fall_bps),
            stale,
        ))
    } else {
        Some((prior, stale))
    }
}

// ---------------------------------------------------------------------------
// Posted fees
// ---------------------------------------------------------------------------

/// Governed key: USD price of registering an identity, and of revoking one
/// on its root's authority, micro-USD.
pub const IDENTITY_FEE_PARAM: &str = "fees.identity_register_micro_usd";
/// Governed key: USD price of one proof attestation (verification),
/// micro-USD.
pub const VERIFY_FEE_PARAM: &str = "fees.verify_micro_usd";
/// Governed key: USD price of one inference or compute stream settlement,
/// micro-USD, paid by the provider claiming it.
pub const INFERENCE_FEE_PARAM: &str = "fees.inference_settle_micro_usd";
/// Genesis identity registration price: one cent.
pub const DEFAULT_IDENTITY_FEE_MICRO_USD: u64 = 10_000;
/// Genesis verification price: a tenth of a cent.
pub const DEFAULT_VERIFY_FEE_MICRO_USD: u64 = 1_000;
/// Genesis inference settlement price: a hundredth of a cent.
pub const DEFAULT_INFERENCE_FEE_MICRO_USD: u64 = 100;

/// The governed USD price key of a native call, if it has one.
pub fn posted_fee_param(selector: [u8; 4]) -> Option<&'static str> {
    match selector {
        SELECTOR_IDENTITY_REGISTER
        | SELECTOR_IDENTITY_REVOKE
        | SELECTOR_ATTACH_MACHINE_ATTESTATION => Some(IDENTITY_FEE_PARAM),
        SELECTOR_ZK_ATTEST => Some(VERIFY_FEE_PARAM),
        SELECTOR_ESCROW_STREAM_CLAIM => Some(INFERENCE_FEE_PARAM),
        _ => None,
    }
}

/// The posted fee a native call pays, in TNZO base units at the rate in
/// force; zero for calls without one.
pub fn posted_fee(state: &dyn VmState, selector: [u8; 4]) -> u128 {
    posted_fee_param(selector).map_or(0, |key| {
        usd_to_wei(
            state,
            u128::from(network_param(state, key)).saturating_mul(ATTO_PER_MICRO_USD),
        )
    })
}

/// Take a succeeded call's posted fee from its sender and burn it.
pub(super) fn charge_posted_fee(
    state: &mut dyn VmState,
    payer: &[u8],
    fee: u128,
    mut result: ExecutionResult,
) -> Result<ExecutionResult> {
    let old = state.get_balance(payer);
    if old < fee {
        return Err(refuse(format!(
            "this call's posted fee of {fee} wei is more than the sender holds"
        )));
    }
    let new = old - fee;
    state.set_balance(payer, new);
    result.state_changes.push(StateChange::new(
        payer.to_vec(),
        b"balance".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some(new.to_le_bytes().to_vec()),
    ));
    record_burn(state, fee)?;
    Ok(result.with_burn(fee))
}

// ---------------------------------------------------------------------------
// Provider bonds sized to live exposure
// ---------------------------------------------------------------------------

/// Governed key: least ratio of a bonded provider's compute bond to the TNZO
/// it holds in open escrows, bps. 0 turns the check off.
pub const VAR_RATIO_PARAM: &str = "compute_bond.var_ratio_bps";

/// Governed key: least TNZO, in gwei, one escrow toward a bonded provider
/// may lock.
pub const MIN_ESCROW_PARAM: &str = "compute_bond.min_escrow_gwei";

/// Genesis value of [`MIN_ESCROW_PARAM`]: 0.1 TNZO.
pub const DEFAULT_MIN_ESCROW_GWEI: u64 = 100_000_000;
/// Genesis ratio: the bond covers 1.1 times what the provider could take.
pub const DEFAULT_VAR_RATIO_BPS: u64 = 11_000;

fn exposure_key(did: &str) -> String {
    format!("var_escrows:{did}")
}

/// TNZO a provider holds in open escrows, and the ids of those escrows.
///
/// Past its expiry an escrow holds the provider only to what it accrued and
/// has not been claimed (a stream's served hours); one that holds it to
/// nothing leaves the list.
pub fn provider_exposure(
    state: &dyn VmState,
    provider_did: &str,
    now_ms: i64,
) -> (u128, Vec<String>) {
    let ids: Vec<String> = read_json(state, &exposure_key(provider_did)).unwrap_or_default();
    let mut open = Vec::with_capacity(ids.len());
    let mut total = 0u128;
    for id in ids {
        let Some(raw) = hex::decode(&id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        if let Ok((_, _, e)) = read_escrow_record(state, &raw)
            && e.status == tenzro_settlement::escrow::EscrowStatus::Funded
        {
            let held = if now_ms > e.expires_at.0 {
                super::payment_settlement::stream_due(state, &e, now_ms, true).unwrap_or(0)
            } else {
                e.amount.saturating_sub(e.claimed)
            };
            if held == 0 && now_ms > e.expires_at.0 {
                continue;
            }
            total = total.saturating_add(held);
            open.push(id);
        }
    }
    (total, open)
}

/// Refuse a TNZO escrow toward a bonded provider when the provider's live
/// exposure, the new escrow included, would exceed its bond divided by
/// `compute_bond.var_ratio_bps` (0: never); otherwise index the escrow, so
/// an hour judged unavailable can be repaid from the bond. Payees without
/// a compute bond are not providers and are not checked.
pub(super) fn check_provider_exposure(
    state: &mut dyn VmState,
    payee: &Address,
    asset: &tenzro_types::AssetId,
    amount: u128,
    escrow_id: &[u8; 32],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let ratio = u128::from(network_param(state, VAR_RATIO_PARAM));
    if *asset != tenzro_types::AssetId::tnzo() {
        return Ok(());
    }
    let Some(did) = identity_did_of(state, payee.as_bytes()) else {
        return Ok(());
    };
    // Only a bond the payee posted itself makes it a provider here, so a
    // bond posted in another's name cannot block payments to it.
    let Some(bond) = compute_bond(state, &did)
        .filter(|b| b.provider_address.trim_start_matches("0x") == hex::encode(payee.as_bytes()))
    else {
        return Ok(());
    };
    // Each open escrow is at least the governed minimum and all of them fit
    // under the bond, so the list a provider's bond can carry stays short.
    let min = u128::from(network_param(state, MIN_ESCROW_PARAM)).saturating_mul(1_000_000_000);
    if amount < min {
        return Err(refuse(format!(
            "an escrow toward bonded provider {did} locks at least {min} wei; this one locks {amount}"
        )));
    }
    let (live, mut open) = provider_exposure(state, &did, now_ms);
    let exposure = live.saturating_add(amount);
    let need = exposure.saturating_mul(ratio) / 10_000;
    let have = if bond.is_eligible() {
        bond.effective_amount()
    } else {
        0
    };
    if ratio > 0 && have < need {
        return Err(refuse(format!(
            "provider {did} bonds {have} wei against {exposure} wei of open escrows; \
             {need} wei is needed"
        )));
    }
    open.push(hex::encode(escrow_id));
    write_json(state, &exposure_key(&did), &open, changes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Settlement fee and activity
// ---------------------------------------------------------------------------

/// One reward epoch's settlement activity, as stored and read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochActivity {
    /// Value settled, wei.
    #[serde(with = "u128_string")]
    pub settled_value: u128,
    /// Settlement transactions.
    pub settlements: u64,
    /// Payments they carried (vouchers for a session claim, one otherwise).
    pub payments: u64,
    /// Distinct root identities that paid.
    pub unique_payers: u64,
    /// Value between distinct registered roots: what earns activity
    /// rewards.
    #[serde(with = "u128_string")]
    pub organic_value: u128,
    /// Value between accounts sharing a root, or with an unregistered side.
    #[serde(with = "u128_string")]
    pub unattributed_value: u128,
    /// Settlement fees charged, wei.
    #[serde(with = "u128_string")]
    pub settlement_fees: u128,
    /// TNZO burned in the epoch: base fees, settlement fees and bonds.
    #[serde(with = "u128_string")]
    pub burned: u128,
    /// Settlement fees paid by registered roots other than the treasury:
    /// the total fee-weighted distributions share out.
    #[serde(with = "u128_string", default)]
    pub attributed_fees: u128,
    /// TNZO equivalent of the burn shares of settlement fees collected in
    /// other assets, booked at the rates in force: netted against the
    /// epoch's issuance when it closes.
    #[serde(with = "u128_string", default)]
    pub burn_eq: u128,
}

mod u128_string {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u128, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

pub(super) fn activity_key(epoch: u64) -> String {
    format!("econ_epoch:{epoch:016x}")
}

fn fees_paid_key(root: &str) -> String {
    format!("econ_fee:{root}")
}

fn payer_key(root: &str) -> String {
    format!("econ_payer:{root}")
}

/// Settlement fees a root paid in the last reward epoch it paid in.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FeesPaid {
    epoch: u64,
    fees: String,
}

/// Settlement fees root identity `root` paid in reward epoch `epoch`, while
/// that is the last epoch it paid in; zero for any other epoch.
pub fn read_fees_paid(state: &dyn VmState, epoch: u64, root: &str) -> u128 {
    read_json::<FeesPaid>(state, &fees_paid_key(root))
        .filter(|f| f.epoch == epoch)
        .and_then(|f| f.fees.parse().ok())
        .unwrap_or(0)
}

/// Deletes the activity of reward epoch `epoch`.
pub(super) fn prune_epoch(state: &mut dyn VmState, epoch: u64, changes: &mut Vec<StateChange>) {
    delete_record(state, &activity_key(epoch), changes);
    super::burn_netting::prune_epoch(state, epoch, changes);
}

/// The reward epoch now in progress.
pub fn read_current_epoch(state: &dyn VmState) -> u64 {
    current_epoch(state).unwrap_or(0)
}

/// The activity recorded for reward epoch `epoch`.
pub fn read_epoch_activity(state: &dyn VmState, epoch: u64) -> EpochActivity {
    read_json(state, &activity_key(epoch)).unwrap_or_default()
}

fn current_epoch(state: &dyn VmState) -> Result<u64> {
    Ok(rewards::read_reward_state(state)?.current_epoch)
}

fn update_activity(
    state: &mut dyn VmState,
    changes: &mut Vec<StateChange>,
    f: impl FnOnce(&mut EpochActivity),
) -> Result<u64> {
    let epoch = current_epoch(state)?;
    let mut a = read_epoch_activity(state, epoch);
    f(&mut a);
    write_json(state, &activity_key(epoch), &a, changes)?;
    Ok(epoch)
}

/// Test seam: prices TNZO at 1e21 nano-USD so one base unit counts as one
/// micro-unit of account, for tests written with spend limits in base units.
#[cfg(test)]
pub(crate) fn count_wei_as_units_for_tests(state: &mut dyn VmState) {
    write_rate_for_tests(
        state,
        0,
        1_000_000_000_000_000_000_000,
        1_000_000_000_000_000_000_000,
    );
}

/// Test seam: books `burned` and `burn_eq` in the current epoch's record.
#[cfg(test)]
pub(crate) fn book_for_tests(state: &mut dyn VmState, burned: u128, burn_eq: u128) {
    update_activity(state, &mut Vec::new(), |a| {
        a.burned = a.burned.saturating_add(burned);
        a.burn_eq = a.burn_eq.saturating_add(burn_eq);
    })
    .unwrap();
}

/// Adds TNZO burned outside a settlement (base fees, slashed bonds) to the
/// current epoch's record.
pub fn record_burn(state: &mut dyn VmState, burned: u128) -> Result<()> {
    if burned == 0 {
        return Ok(());
    }
    let mut changes = Vec::new();
    update_activity(state, &mut changes, |a| {
        a.burned = a.burned.saturating_add(burned)
    })?;
    Ok(())
}

/// The root identity behind an account: a delegated identity's controller,
/// otherwise the identity itself. `None` for an unregistered account.
fn root_of(state: &dyn VmState, addr: &[u8]) -> Option<String> {
    let did = identity_did_of(state, addr)?;
    let root = match did.strip_prefix("did:tenzro:machine:") {
        Some(rest) => match rest.split_once(':') {
            Some((controller, _)) => controller.to_string(),
            None => rest.to_string(),
        },
        None => did
            .strip_prefix("did:tenzro:human:")
            .map(str::to_string)
            .unwrap_or_else(|| did.clone()),
    };
    Some(root)
}

/// What one settlement earns beyond the value it moves, from who it pays and
/// who the payer attributed it to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct Earning {
    /// The provider work the payee earns at settlement, from the bond or
    /// stake it holds. A plan's payees report theirs instead.
    pub provider: Option<tenzro_token::rewards::WorkClass>,
    /// The agent that paid from its wallet, if one did.
    pub payer_agent: Option<String>,
    /// The call chain the payer attributed the settlement to.
    pub attribution: Option<tenzro_types::settlement::CallAttribution>,
    /// The payment already paid the network its HTTP-402 share in a separate
    /// escrow, so it pays no settlement fee: one payment pays one network fee.
    pub network_share_paid: bool,
}

/// What a settled payout leaves the payee, and what it burned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Payout {
    /// Credit due to the payee: the value less the settlement fee and the
    /// treasury leg.
    pub credit: u128,
    /// The fee's burn share; the caller declares it on its result.
    pub burned: u128,
    /// The treasury leg of the payee's work class, paid beside the fee.
    pub treasury_leg: u128,
}

/// The fee the network takes from a settlement of `value` under the
/// governed settlement rate.
pub fn settlement_fee(state: &dyn VmState, value: u128) -> u128 {
    tenzro_types::split::fee_allocation(value, &fee_params(state)).fee
}

/// Fee parameters that charge nothing, for a payment that paid the network
/// its share another way.
pub(super) const NO_FEE: tenzro_types::split::FeeParams = tenzro_types::split::FeeParams {
    fee_bps: 0,
    min_fee: 0,
    burn_bps: 0,
    insurance_bps: 0,
};

/// The governed fee parameters the split engine reads: the settlement rate,
/// the least fee (converted from micro-USD at the live rate), the burn share
/// and the insurance pool's share.
pub fn fee_params(state: &dyn VmState) -> tenzro_types::split::FeeParams {
    let min_micro_usd = network_param(state, MIN_SETTLEMENT_FEE_PARAM);
    tenzro_types::split::FeeParams {
        fee_bps: network_param(state, SETTLEMENT_FEE_PARAM).min(10_000) as u16,
        min_fee: usd_to_wei(
            state,
            u128::from(min_micro_usd).saturating_mul(ATTO_PER_MICRO_USD),
        ),
        burn_bps: network_param(state, SETTLEMENT_FEE_BURN_PARAM).min(10_000) as u16,
        insurance_bps: super::insurance::fee_share_bps(state),
    }
}

/// Credit a settlement fee's treasury and insurance parts and note the pool
/// credit. The burn part is not credited anywhere.
pub(super) fn credit_fee(
    state: &mut dyn VmState,
    fee: &tenzro_types::split::FeeAllocation,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for (account, amount) in [
        (derive_treasury_address(), fee.treasury),
        (super::insurance::pool_address(), fee.insurance),
    ] {
        if amount == 0 {
            continue;
        }
        let t = account.as_bytes().to_vec();
        let old = state.get_balance(&t);
        let new = old.saturating_add(amount);
        state.set_balance(&t, new);
        changes.push(StateChange::new(
            t,
            b"balance".to_vec(),
            Some(old.to_le_bytes().to_vec()),
            Some(new.to_le_bytes().to_vec()),
        ));
    }
    super::insurance::note_credit(
        state,
        fee.insurance,
        super::insurance::PoolSource::Fees,
        changes,
    )?;
    super::treasury_reserve::note_revenue(state, fee.treasury, changes)
}

/// Charge the settlement fee on `value` moving from `payer` to `payee`, and,
/// when the payment is provider work, the treasury leg of its class on what
/// is left; credit the treasury, and record the value in the epoch's
/// activity and what the settlement earns.
pub(super) fn settle_payout(
    state: &mut dyn VmState,
    payer: &[u8],
    payee: &[u8],
    value: u128,
    earning: &Earning,
    changes: &mut Vec<StateChange>,
) -> Result<Payout> {
    let params = if earning.network_share_paid {
        NO_FEE
    } else {
        fee_params(state)
    };
    let fee = tenzro_types::split::fee_allocation(value, &params);
    let leg = earning.provider.map_or(0, |class| {
        tenzro_types::split::bps_of(value - fee.fee, u128::from(treasury_leg_bps(state, class)))
    });
    record_fee(state, payer, payee, value, &fee, leg, earning, changes)?;
    Ok(Payout {
        credit: value - fee.fee - leg,
        burned: fee.burn,
        treasury_leg: leg,
    })
}

/// Account for one settlement of `value` from `payer` to `payee` whose fee
/// the split engine computed and which paid the treasury `leg` beside it:
/// credit the fee's parts and the leg less the royalty, pay the royalty, and
/// record the value in the epoch's activity, the fee in the payer root's
/// paid fees, and what the settlement earns its provider and the creators it
/// is attributed to. What a settlement may earn is bounded by what it paid
/// outside the trade: the fee and the leg.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_fee(
    state: &mut dyn VmState,
    payer: &[u8],
    payee: &[u8],
    value: u128,
    alloc: &tenzro_types::split::FeeAllocation,
    leg: u128,
    earning: &Earning,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    record_fee_in(
        state,
        payer,
        payee,
        value,
        alloc,
        leg,
        earning,
        Collect::Tnzo,
        changes,
    )
    .map(|_| ())
}

/// A settlement fee collected in the token the payment moved: the parts in
/// the token's smallest unit, paid from `from`.
pub(super) struct InKind<'a> {
    /// The token.
    pub token: &'a [u8; 32],
    /// The account the parts are paid from.
    pub from: &'a [u8],
    /// The fee's parts, in the token.
    pub alloc: &'a tenzro_types::split::FeeAllocation,
    /// The treasury leg, in the token.
    pub leg: u128,
    /// The burn share's TNZO equivalent, booked for the epoch.
    pub burn_eq: u128,
    /// Block time, ms.
    pub now_ms: i64,
}

/// Where a settlement fee's parts are paid.
pub(super) enum Collect<'a> {
    /// Already taken out of TNZO by the caller: the treasury and insurance
    /// parts are credited in TNZO and the burn part leaves supply.
    Tnzo,
    /// Paid in the payment's token: treasury, insurance and royalties in
    /// the token, and the burn part to the treasury's stable holdings with
    /// its TNZO equivalent booked for the epoch.
    InKind(InKind<'a>),
}

/// [`record_fee`] with the fee collected as `collect` says. `value`,
/// `alloc` and `leg` are in TNZO base units (for a fee in kind, their TNZO
/// equivalents), and are what activity and reward weight are counted in.
/// Returns what the treasury kept of a fee in kind, in the token, after
/// royalties; zero for TNZO.
#[allow(clippy::too_many_arguments)]
pub(super) fn record_fee_in(
    state: &mut dyn VmState,
    payer: &[u8],
    payee: &[u8],
    value: u128,
    alloc: &tenzro_types::split::FeeAllocation,
    leg: u128,
    earning: &Earning,
    collect: Collect<'_>,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let fee = alloc.fee;
    let outside = fee.saturating_add(leg);
    let payer_root = root_of(state, payer);
    // Roots followed through agent controllers: an agent paying for its
    // controller, or its controller's other agents, is not a second party.
    let payer_did = earning
        .payer_agent
        .clone()
        .or_else(|| identity_did_of(state, payer));
    let payee_did = identity_did_of(state, payee);
    let roots = match (&payer_did, &payee_did) {
        (Some(a), Some(b)) => Some((
            rewards::root_identity(state, a),
            rewards::root_identity(state, b),
        )),
        _ => None,
    };
    let organic = payer != payee && matches!(&roots, Some((a, b)) if a != b);
    let (provider_bps, activity_bps, royalty_bps) = rewards::settlement_reward_shares(state);
    let creators = match &roots {
        Some(excluded) if organic => attributed_creators(state, payer, payee, excluded, earning),
        _ => Vec::new(),
    };
    let n = creators.len() as u128;
    let royalty_of = |fee: u128, treasury: u128, leg: u128| -> u128 {
        tenzro_types::split::bps_of(fee.saturating_add(leg), u128::from(royalty_bps))
            .min(treasury.saturating_add(leg))
            .checked_div(n)
            .unwrap_or(0)
    };
    let (royalty_each, in_kind_royalty, kept_in_kind) = match &collect {
        Collect::Tnzo => {
            let royalty_each = royalty_of(alloc.fee, alloc.treasury, leg);
            let mut kept = *alloc;
            kept.treasury = alloc.treasury.saturating_add(leg) - royalty_each * n;
            credit_fee(state, &kept, changes)?;
            (royalty_each, 0, 0)
        }
        Collect::InKind(k) => {
            let royalty_each = royalty_of(k.alloc.fee, k.alloc.treasury, k.leg);
            let kept = k.alloc.treasury + k.leg - royalty_each * n;
            let to_treasury = kept + k.alloc.burn;
            // Revenue and the pool's fee credits are counted at their TNZO
            // equivalents: the share of the fee each part is, applied to the
            // fee's equivalent. The burn share stands for burned TNZO and is
            // not revenue.
            let eq_of = |part: u128| {
                alloc
                    .fee
                    .saturating_mul(part)
                    .checked_div(k.alloc.fee)
                    .unwrap_or(0)
            };
            super::payment_settlement::move_asset(
                state,
                k.token,
                k.from,
                derive_treasury_address().as_bytes(),
                to_treasury,
                k.now_ms,
                changes,
            )?;
            super::payment_settlement::move_asset(
                state,
                k.token,
                k.from,
                super::insurance::pool_address().as_bytes(),
                k.alloc.insurance,
                k.now_ms,
                changes,
            )?;
            super::insurance::note_credit(
                state,
                eq_of(k.alloc.insurance),
                super::insurance::PoolSource::Fees,
                changes,
            )?;
            super::treasury_reserve::note_revenue(state, eq_of(kept), changes)?;
            super::validator_cover::note_stable_fee(state, k.token, kept, changes)?;
            (0, royalty_each, kept)
        }
    };
    let (burned_now, burn_eq) = match &collect {
        Collect::Tnzo => (alloc.burn, 0),
        Collect::InKind(k) => (0, k.burn_eq),
    };
    let epoch = current_epoch(state)?;
    let new_payer = match &payer_root {
        Some(root) => {
            let key = payer_key(root);
            let seen = read_json::<u64>(state, &key) == Some(epoch);
            if !seen {
                write_json(state, &key, &epoch, changes)?;
            }
            !seen
        }
        None => false,
    };
    // The fee a registered root paid, for fee-weighted distributions. The
    // treasury never accrues it.
    let fee_root = if fee > 0 && payer != derive_treasury_address().as_bytes() {
        identity_did_of(state, payer).map(|did| crate::funding::root_did(&did))
    } else {
        None
    };
    if let Some(root) = &fee_root {
        let prior = read_fees_paid(state, epoch, root);
        let paid = FeesPaid {
            epoch,
            fees: prior.saturating_add(fee).to_string(),
        };
        write_json(state, &fees_paid_key(root), &paid, changes)?;
    }
    update_activity(state, changes, |a| {
        a.settled_value = a.settled_value.saturating_add(value);
        a.settlement_fees = a.settlement_fees.saturating_add(fee);
        if fee_root.is_some() {
            a.attributed_fees = a.attributed_fees.saturating_add(fee);
        }
        a.burned = a.burned.saturating_add(burned_now);
        a.burn_eq = a.burn_eq.saturating_add(burn_eq);
        if new_payer {
            a.unique_payers += 1;
        }
        if organic {
            a.organic_value = a.organic_value.saturating_add(value);
        } else {
            a.unattributed_value = a.unattributed_value.saturating_add(value);
        }
    })?;
    // Provider work needs two parties told apart: a payer and a payee that
    // are both registered under different roots.
    if organic && let (Some(class), Some(payee_at)) = (earning.provider, Address::from_bytes(payee))
    {
        let weight =
            tenzro_token::rewards::provider_work_weight(value - outside, outside, provider_bps);
        rewards::record_settled_work(state, payee_at, class, weight, changes)?;
    }
    let activity_each = tenzro_types::split::bps_of(outside, u128::from(activity_bps)) / n.max(1);
    for creator in creators {
        if royalty_each > 0 {
            credit_balance(state, creator.as_bytes(), royalty_each, changes)?;
        }
        if let Collect::InKind(k) = &collect
            && in_kind_royalty > 0
        {
            super::payment_settlement::move_asset(
                state,
                k.token,
                k.from,
                creator.as_bytes(),
                in_kind_royalty,
                k.now_ms,
                changes,
            )?;
        }
        rewards::record_settled_work(
            state,
            creator,
            tenzro_token::rewards::WorkClass::AppUsage,
            activity_each,
            changes,
        )?;
    }
    Ok(kept_in_kind)
}

/// The accounts of the apps, agents and tools `earning` attributes a
/// settlement to that may earn from it: each a registered, unrevoked
/// identity whose root is neither of `roots` (the payer's and the payee's),
/// each account once.
fn attributed_creators(
    state: &dyn VmState,
    payer: &[u8],
    payee: &[u8],
    roots: &(String, String),
    earning: &Earning,
) -> Vec<Address> {
    let Some(attribution) = &earning.attribution else {
        return Vec::new();
    };
    let mut out: Vec<Address> = Vec::new();
    for did in attribution.dids() {
        let root = rewards::root_identity(state, did);
        if root == roots.0 || root == roots.1 {
            continue;
        }
        let Some(account) = registered_account(state, did) else {
            continue;
        };
        if account.as_bytes() != payer && account.as_bytes() != payee && !out.contains(&account) {
            out.push(account);
        }
    }
    out
}

/// The account a registered, unrevoked identity was registered with.
pub(super) fn registered_account(state: &dyn VmState, did: &str) -> Option<Address> {
    if state
        .get_storage(&SYSTEM_ADDRESS, &super::identity_revocation_key(did))
        .is_some_and(|b| !b.is_empty())
    {
        return None;
    }
    state
        .get_storage(&SYSTEM_ADDRESS, &super::identity_storage_key(did))
        .filter(|b| !b.is_empty())
        .and_then(|b| {
            serde_json::from_slice::<tenzro_types::identity::RegisterIdentityPayload>(&b).ok()
        })
        .map(|r| r.wallet_address)
}

fn credit_balance(
    state: &mut dyn VmState,
    account: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let old = state.get_balance(account);
    let new = old
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
    state.set_balance(account, new);
    changes.push(StateChange::new(
        account.to_vec(),
        b"balance".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some(new.to_le_bytes().to_vec()),
    ));
    Ok(())
}

/// Count one settlement transaction carrying `payments` payments.
pub(super) fn count_settlement(
    state: &mut dyn VmState,
    payments: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    update_activity(state, changes, |a| {
        a.settlements += 1;
        a.payments = a.payments.saturating_add(payments);
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegated-agent bonds
// ---------------------------------------------------------------------------

/// The bond, wei, an agent with spend ceiling `spend` (wei) must hold:
/// `agent_bond.spend_bps` of the ceiling.
pub fn required_agent_bond(state: &dyn VmState, spend: u128) -> u128 {
    let bps = u128::from(network_param(state, AGENT_BOND_PARAM).min(10_000));
    (spend / 10_000)
        .saturating_mul(bps)
        .saturating_add(spend % 10_000 * bps / 10_000)
}

/// The spend ceiling that sizes an agent's bond, micro-units of account: its
/// daily ceiling, else its per-transaction ceiling. `None` when the terms
/// set neither.
pub fn agent_spend_ceiling(terms: &tenzro_types::agent_terms::AgentTerms) -> Option<u128> {
    let scope = &terms.delegation_scope;
    scope
        .max_daily_spend
        .as_deref()
        .or(scope.max_transaction_value.as_deref())
        .and_then(|v| v.parse().ok())
}

/// Refused unless `agent_did`'s bond covers what its terms require.
pub fn check_agent_bond(
    state: &dyn VmState,
    agent_did: &str,
    terms: &tenzro_types::agent_terms::AgentTerms,
) -> std::result::Result<(), String> {
    let ceiling = agent_spend_ceiling(terms)
        .ok_or_else(|| "the terms need a spend ceiling to size the agent's bond".to_string())?;
    let spend = usd_to_wei(state, ceiling.saturating_mul(ATTO_PER_MICRO_USD));
    let required = required_agent_bond(state, spend);
    let held = state.get_balance(derive_bond_vault_address(agent_did).as_bytes());
    if held < required {
        return Err(format!(
            "{agent_did} holds a bond of {held} wei; a spend ceiling of {ceiling} micro-units ({spend} wei at the rate in force) needs {required}"
        ));
    }
    Ok(())
}

/// An agent bond as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentBond {
    pub agent_did: String,
    pub controller_did: String,
    /// Wei the bond holds.
    pub amount: u128,
    /// `Active`, `Cooldown`, `Slashed`, `Returned` or `Burned`.
    pub state: String,
    /// When a withdrawal's cooldown ends, ms.
    pub cooldown_until_ms: Option<i64>,
    /// The bond vault, hex.
    pub vault: String,
}

impl AgentBond {
    /// Whether the bond counts for lane promotion and resolver eligibility.
    pub fn is_active(&self) -> bool {
        self.state == "Active"
    }
}

fn bond_controller_key(controller_did: &str) -> String {
    format!("bond_controller:{controller_did}")
}

/// Record `agent_did` under its controller's bond index, once.
pub(super) fn index_bond_controller(
    state: &mut dyn VmState,
    controller_did: &str,
    agent_did: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let key = bond_controller_key(controller_did);
    let mut agents: Vec<String> = read_json(state, &key).unwrap_or_default();
    if !agents.iter().any(|a| a == agent_did) {
        agents.push(agent_did.to_string());
        write_json(state, &key, &agents, changes)?;
    }
    Ok(())
}

/// `agent_did`'s bond record, in any lifecycle state.
pub fn agent_bond(state: &dyn VmState, agent_did: &str) -> Option<AgentBond> {
    let marker = read_json::<serde_json::Value>(state, &bond_storage_key(agent_did))?;
    let op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let lifecycle = match op {
        "Posted" | "Increased" | "PartiallySlashed" => "Active",
        "WithdrawInitiated" => "Cooldown",
        "Slashed" => "Slashed",
        "Returned" => "Returned",
        "Burned" => "Burned",
        _ => return None,
    };
    Some(AgentBond {
        agent_did: agent_did.to_string(),
        controller_did: marker
            .get("controller_did")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        amount: marker
            .get("amount")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        state: lifecycle.to_string(),
        cooldown_until_ms: marker.get("cooldown_until_ms").and_then(|v| v.as_i64()),
        vault: hex::encode(derive_bond_vault_address(agent_did).as_bytes()),
    })
}

/// Every bond `controller_did` posted, in posting order.
pub fn agent_bonds_of_controller(state: &dyn VmState, controller_did: &str) -> Vec<AgentBond> {
    read_json::<Vec<String>>(state, &bond_controller_key(controller_did))
        .unwrap_or_default()
        .iter()
        .filter_map(|agent| agent_bond(state, agent))
        .collect()
}

/// What `agent_did`'s bond holds on chain, if it has a live one.
pub fn agent_bond_amount(state: &dyn VmState, agent_did: &str) -> Option<u128> {
    let marker = read_json::<serde_json::Value>(state, &bond_storage_key(agent_did))?;
    if matches!(
        marker.get("op").and_then(|v| v.as_str()),
        Some("Slashed" | "Returned" | "Burned")
    ) {
        return None;
    }
    marker
        .get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
}

/// A provider's compute bond as consensus state holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeBond {
    pub provider_did: String,
    /// The payout address that funded the vault, hex.
    pub provider_address: String,
    /// Wei the bond holds.
    pub amount: u128,
    /// `Active`, `Cooldown`, `Slashed` or `Returned`.
    pub status: String,
    /// When a withdrawal's cooldown ends, ms.
    pub cooldown_until_ms: Option<i64>,
    /// The bond vault, hex.
    pub vault: String,
    /// Whether it holds the governed compute bond minimum in force.
    pub meets_minimum: bool,
}

impl ComputeBond {
    /// Whether the bond backs its provider: active, not cooling down, and at
    /// least the governed minimum.
    pub fn is_eligible(&self) -> bool {
        self.status == "Active" && self.meets_minimum
    }

    /// What the bond backs: its amount while active, else zero.
    pub fn effective_amount(&self) -> u128 {
        if self.is_eligible() { self.amount } else { 0 }
    }
}

const COMPUTE_BOND_INDEX_KEY: &str = "compute_bond_index";

/// Record `provider_did` in the index of every compute bond ever posted, once.
pub(super) fn index_compute_bond(
    state: &mut dyn VmState,
    provider_did: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut providers: Vec<String> = read_json(state, COMPUTE_BOND_INDEX_KEY).unwrap_or_default();
    if !providers.iter().any(|p| p == provider_did) {
        providers.push(provider_did.to_string());
        write_json(state, COMPUTE_BOND_INDEX_KEY, &providers, changes)?;
    }
    Ok(())
}

/// `provider_did`'s compute bond, in any lifecycle state.
pub fn compute_bond(state: &dyn VmState, provider_did: &str) -> Option<ComputeBond> {
    let marker = read_json::<serde_json::Value>(state, &compute_bond_storage_key(provider_did))?;
    let status = match marker.get("op").and_then(|v| v.as_str()).unwrap_or("") {
        "Posted" | "Increased" | "PartiallySlashed" => "Active",
        "WithdrawInitiated" => "Cooldown",
        "Slashed" => "Slashed",
        "Returned" => "Returned",
        _ => return None,
    };
    let text = |k: &str| {
        marker
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let amount: u128 = text("amount").parse().unwrap_or(0);
    Some(ComputeBond {
        provider_did: provider_did.to_string(),
        provider_address: text("provider_address"),
        amount,
        status: status.to_string(),
        cooldown_until_ms: marker.get("cooldown_until_ms").and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse().ok())
                .or_else(|| v.as_i64())
        }),
        vault: hex::encode(derive_compute_bond_vault_address(provider_did).as_bytes()),
        meets_minimum: amount >= super::compute_bond_min(state),
    })
}

/// Every compute bond on chain, in posting order.
pub fn compute_bonds(state: &dyn VmState) -> Vec<ComputeBond> {
    read_json::<Vec<String>>(state, COMPUTE_BOND_INDEX_KEY)
        .unwrap_or_default()
        .iter()
        .filter_map(|did| compute_bond(state, did))
        .collect()
}

/// Slash `bps` of `agent_did`'s bond into the insurance pool, keeping the
/// bond's residual floor: a bond left below it is taken whole and ends
/// `Slashed`. A bond already terminal, or none, slashes nothing. Emits the
/// `BondSlashed` log the node mirrors into its bond index. Returns the
/// amount taken.
pub fn slash_agent_bond(
    state: &mut dyn VmState,
    agent_did: &str,
    bps: u16,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<u128> {
    if bps == 0 {
        return Ok(0);
    }
    let key = bond_storage_key(agent_did);
    let Some(mut marker) = read_json::<serde_json::Value>(state, &key) else {
        return Ok(0);
    };
    let op = marker.get("op").and_then(|v| v.as_str()).unwrap_or("");
    if matches!(op, "Slashed" | "Returned" | "Burned") {
        return Ok(0);
    }
    let prior: u128 = marker
        .get("amount")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| VmError::Internal("bond marker missing amount".to_string()))?;
    let slashed = compute_slash_amount(prior, bps, bond_min_residual(state));
    if slashed == 0 {
        return Ok(0);
    }
    let vault = derive_bond_vault_address(agent_did).as_bytes().to_vec();
    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    let held = state.get_balance(&vault);
    let taken = slashed.min(held);
    state.set_balance(&vault, held - taken);
    let pool_held = state.get_balance(&pool);
    let pool_new = pool_held
        .checked_add(taken)
        .ok_or_else(|| VmError::Internal("InsurancePool balance overflow".to_string()))?;
    state.set_balance(&pool, pool_new);
    changes.push(StateChange::new(
        vault,
        b"balance".to_vec(),
        Some(held.to_le_bytes().to_vec()),
        Some((held - taken).to_le_bytes().to_vec()),
    ));
    changes.push(StateChange::new(
        pool,
        b"balance".to_vec(),
        Some(pool_held.to_le_bytes().to_vec()),
        Some(pool_new.to_le_bytes().to_vec()),
    ));
    let remaining = prior.saturating_sub(slashed);
    let terminal = remaining < bond_min_residual(state);
    marker["amount"] = serde_json::Value::String(if terminal { 0 } else { remaining }.to_string());
    marker["op"] = serde_json::Value::String(
        if terminal {
            "Slashed"
        } else {
            "PartiallySlashed"
        }
        .to_string(),
    );
    write_json(state, &key, &marker, changes)?;
    super::insurance::note_credit(state, taken, super::insurance::PoolSource::Slash, changes)?;
    // agent_did_len(4) || agent_did || controller_did_len(4) || controller_did
    // || slashed(16) || bps(2) || terminal(1)
    let controller = marker
        .get("controller_did")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let mut data = Vec::with_capacity(4 + agent_did.len() + 4 + controller.len() + 19);
    data.extend_from_slice(&(agent_did.len() as u32).to_le_bytes());
    data.extend_from_slice(agent_did.as_bytes());
    data.extend_from_slice(&(controller.len() as u32).to_le_bytes());
    data.extend_from_slice(controller.as_bytes());
    data.extend_from_slice(&taken.to_le_bytes());
    data.extend_from_slice(&bps.to_le_bytes());
    data.push(u8::from(terminal));
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![b"BondSlashed".to_vec()],
        data,
    ));
    Ok(taken)
}

#[cfg(test)]
#[path = "provider_economy_tests.rs"]
mod provider_economy_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn q(source: &str, rate: u128) -> RateQuote {
        RateQuote {
            symbol: "TNZO".into(),
            source: source.into(),
            rate_nano_usd: rate.to_string(),
        }
    }

    #[test]
    fn a_report_needs_two_distinct_sources() {
        assert!(report_rates(&[q("a", 5)], MIN_RATE_SOURCES).is_err());
        assert!(report_rates(&[q("a", 5), q("A", 6)], MIN_RATE_SOURCES).is_err());
        assert_eq!(
            report_rates(&[q("a", 5), q("b", 9), q("c", 7)], MIN_RATE_SOURCES).unwrap()[0].1,
            7
        );
    }

    #[test]
    fn each_symbol_needs_its_own_two_sources() {
        let mut eth = q("a", 3_000);
        eth.symbol = "eth".into();
        // TNZO is quoted twice but ETH only once: the report is refused.
        assert!(report_rates(&[q("a", 5), q("b", 6), eth.clone()], MIN_RATE_SOURCES).is_err());
        let mut eth2 = q("b", 3_100);
        eth2.symbol = "ETH".into();
        let r = report_rates(&[q("a", 5), q("b", 6), eth, eth2], MIN_RATE_SOURCES).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, "ETH");
        assert_eq!(r[0].1, 3_000);
        assert!(normalize_symbol("e").is_err());
        assert!(normalize_symbol("ETH/USD").is_err());
    }

    #[test]
    fn the_rate_moves_at_most_the_bound() {
        assert_eq!(bounded(1_000, 2_000, 1_000, 1_000), 1_100);
        assert_eq!(bounded(1_000, 10, 1_000, 1_000), 900);
        assert_eq!(bounded(1_000, 1_050, 1_000, 1_000), 1_050);
    }

    #[test]
    fn a_fall_is_followed_five_times_faster_than_a_rise() {
        let (rise, fall) = (DEFAULT_RATE_MAX_CHANGE_BPS, DEFAULT_RATE_MAX_FALL_BPS);
        assert_eq!(bounded(1_000_000, 10_000_000, rise, fall), 1_010_000);
        assert_eq!(bounded(1_000_000, 50_000, rise, fall), 950_000);
        // A 95% fall in one day: at 5% an hour the rate in force is within
        // 30% of the market after the day; at 1% an hour it would still be
        // more than 15 times too high.
        let (mut fast, mut slow) = (1_000_000u128, 1_000_000u128);
        for _ in 0..24 {
            fast = bounded(fast, 50_000, rise, fall);
            slow = bounded(slow, 50_000, rise, rise);
        }
        assert!(fast < 300_000, "{fast}");
        assert!(slow > 750_000, "{slow}");
        // After 59 hours the fall is fully followed.
        for _ in 24..59 {
            fast = bounded(fast, 50_000, rise, fall);
        }
        assert_eq!(fast, 50_000);
    }

    #[test]
    fn the_safety_rate_is_the_lowest_recent_median_or_the_rate_in_force() {
        let mut state = crate::StateAdapter::new();
        // Governance mode: the governance rate.
        assert_eq!(safety_rate(&state), u128::from(DEFAULT_TNZO_USD_NANO));
        // The market fell 95% at epoch 10; the rate in force walks down.
        write_rate_for_tests(&mut state, 9, 100_000_000, 100_000_000);
        write_rate_for_tests(&mut state, 10, 5_000_000, 95_000_000);
        assert_eq!(read_fee_rate(&state).rate_nano_usd, 95_000_000);
        assert_eq!(safety_rate(&state), 5_000_000);
        // A rebound in the medians does not lift it while the low one is
        // inside the window.
        write_rate_for_tests(&mut state, 33, 100_000_000, 60_000_000);
        assert_eq!(safety_rate(&state), 5_000_000);
        write_rate_for_tests(&mut state, 34, 100_000_000, 60_600_000);
        assert_eq!(safety_rate(&state), 60_600_000, "epoch 10 left the window");
        crate::native::set_genesis_param(&mut state, SAFETY_RATE_WINDOW_PARAM, 168);
        assert_eq!(safety_rate(&state), 5_000_000);
    }

    fn rows(r: &[(u128, u128)]) -> Vec<(u128, String, u128)> {
        r.iter()
            .enumerate()
            .map(|(i, (rate, stake))| (*rate, format!("v{i}"), *stake))
            .collect()
    }

    #[test]
    fn a_cartel_below_two_thirds_cannot_move_the_rate() {
        for cartel in [34u128, 52, 66] {
            let mut r = rows(&[(1_000, 100 - cartel), (10_000, cartel)]);
            let lo = stake_weighted_quantile(&mut r, 3_334).unwrap();
            let hi = stake_weighted_quantile(&mut r, 6_667).unwrap();
            assert_eq!(banded(1_000, lo, hi, 100, 100), 1_000, "cartel {cartel}%");
        }
        // Above two thirds it moves, by the hourly bound at most.
        let mut r = rows(&[(1_000, 30), (10_000, 70)]);
        let lo = stake_weighted_quantile(&mut r, 3_334).unwrap();
        let hi = stake_weighted_quantile(&mut r, 6_667).unwrap();
        assert_eq!(banded(1_000, lo, hi, 100, 100), 1_010);
    }

    #[test]
    fn honest_agreement_moves_the_rate_within_the_bound() {
        let mut r = rows(&[(1_050, 33), (1_060, 33), (1_040, 34)]);
        let lo = stake_weighted_quantile(&mut r, 3_334).unwrap();
        let hi = stake_weighted_quantile(&mut r, 6_667).unwrap();
        assert_eq!(banded(1_000, lo, hi, 1_000, 1_000), 1_040);
        assert_eq!(banded(1_000, lo, hi, 100, 500), 1_010);
        // A rate already inside the band stays.
        assert_eq!(banded(1_045, lo, hi, 100, 500), 1_045);
    }

    fn rules() -> RateRules {
        RateRules {
            max_change_bps: 100,
            max_fall_bps: 500,
            stale_epochs: 6,
            stale_gap_bps: 300,
            frozen: false,
        }
    }

    #[test]
    fn exactly_a_third_holding_one_edge_neither_holds_nor_moves_the_rate() {
        // Twenty-one equal stakes: seven report just under the rate in
        // force after the market fell, fourteen report the market.
        let mut rows: Vec<(u128, String, u128)> = (0..21)
            .map(|i| (if i < 7 { 990 } else { 800 }, format!("v{i}"), 1))
            .collect();
        let lo = stake_weighted_quantile(&mut rows, DEFAULT_RATE_QUANTILE_LOW_BPS).unwrap();
        let hi = stake_weighted_quantile(&mut rows, DEFAULT_RATE_QUANTILE_HIGH_BPS).unwrap();
        assert_eq!((lo, hi), (800, 800));
        // And the band holds a stale rate when a majority short of two
        // thirds disagrees with the rest: the staleness rule does not
        // apply with the quorum.
        let t = Tally {
            median: 10_000,
            low: 1_000,
            high: 10_000,
            full: true,
        };
        assert_eq!(next_rate(Some(1_000), 99, t, &rules()), Some((1_000, 0)));
    }

    #[test]
    fn a_missed_quorum_freezes_the_rate_only_for_the_staleness_window() {
        let r = rules();
        let (mut rate, mut stale) = (1_000u128, 0);
        for i in 0..30 {
            let t = Tally {
                median: 800,
                low: 0,
                high: 0,
                full: false,
            };
            let (next, s) = next_rate(Some(rate), stale, t, &r).unwrap();
            if i < 5 {
                assert_eq!(next, 1_000);
            }
            rate = next;
            stale = s;
        }
        assert!(rate < 850, "{rate}");
        // A rate already near the median is not stale.
        assert_eq!(
            next_rate(
                Some(810),
                5,
                Tally {
                    median: 800,
                    low: 0,
                    high: 0,
                    full: false
                },
                &r
            ),
            Some((810, 0))
        );
    }

    #[test]
    fn a_governance_hold_keeps_the_rate_and_no_first_rate_comes_from_a_minority() {
        let mut r = rules();
        let t = Tally {
            median: 800,
            low: 800,
            high: 800,
            full: false,
        };
        assert_eq!(next_rate(None, 0, t, &r), None);
        r.frozen = true;
        assert_eq!(next_rate(Some(1_000), 9, t, &r), Some((1_000, 9)));
    }

    #[test]
    fn a_commitment_binds_the_validator_epoch_salt_and_quotes() {
        let salt = [7u8; 32];
        let q = [("TNZO", "a", 100u128), ("TNZO", "b", 101)];
        let c = tenzro_types::fee_rate_commitment(b"v1", 5, &salt, q);
        assert_eq!(c, tenzro_types::fee_rate_commitment(b"v1", 5, &salt, q));
        assert_ne!(c, tenzro_types::fee_rate_commitment(b"v2", 5, &salt, q));
        assert_ne!(c, tenzro_types::fee_rate_commitment(b"v1", 6, &salt, q));
        assert_ne!(
            c,
            tenzro_types::fee_rate_commitment(b"v1", 5, &[8u8; 32], q)
        );
        let q2 = [("TNZO", "a", 100u128), ("TNZO", "b", 102)];
        assert_ne!(c, tenzro_types::fee_rate_commitment(b"v1", 5, &salt, q2));
    }

    fn rate_state(total: u128) -> crate::StateAdapter {
        let mut st = crate::StateAdapter::new();
        st.set_storage(
            &SYSTEM_ADDRESS,
            b"staking_total_bonded",
            total.to_le_bytes().to_vec(),
        );
        set_genesis_param(&mut st, RATE_MODE_PARAM, 1);
        // The governance rate sits where these tests' markets trade, so the
        // dispersion breaker's gap bound is not what they exercise.
        set_genesis_param(&mut st, GOVERNANCE_RATE_PARAM, 1_000);
        st
    }

    fn put(st: &mut crate::StateAdapter, key: &str, v: serde_json::Value) {
        st.set_storage(
            &SYSTEM_ADDRESS,
            key.as_bytes(),
            serde_json::to_vec(&v).unwrap(),
        );
    }

    fn opened(st: &mut crate::StateAdapter, epoch: u64, reports: &[(u128, u128)]) {
        put(
            st,
            &format!("fxr_symbols:{epoch}"),
            serde_json::json!(["TNZO"]),
        );
        let subs: Vec<_> = reports
            .iter()
            .enumerate()
            .map(|(i, (rate, stake))| {
                serde_json::json!({
                    "validator": format!("v{i}"),
                    "rate": rate.to_string(),
                    "stake": stake.to_string(),
                    "sources": ["a", "b"],
                })
            })
            .collect();
        put(
            st,
            &format!("fxr_sub:TNZO:{epoch}"),
            serde_json::json!(subs),
        );
    }

    fn live(st: &mut crate::StateAdapter, rate: u128, epoch: u64) {
        put(
            st,
            &live_key(FEE_SYMBOL),
            serde_json::json!({ "rate_nano_usd": rate.to_string(), "epoch": epoch }),
        );
    }

    /// A frozen stable rate steps the breaker of the asset priced under it:
    /// three epochs off the peg suspend it.
    #[test]
    fn a_frozen_stable_rate_steps_its_assets_peg_breaker() {
        use crate::native::settlement_asset as sa;
        let mut st = rate_state(100);
        let id = [0x5c; 32];
        let entry = tenzro_types::settlement_asset::SettlementAsset::new(
            &format!("0x{}", hex::encode(id)),
            "USDC",
            "USD",
            6,
        );
        sa::install_for_test(&mut st, &entry);
        let mut logs = Vec::new();
        for (e, rate) in [
            (0u64, 1_000_000_000u128),
            (1, 950_000_000),
            (2, 950_000_000),
            (3, 950_000_000),
        ] {
            put(
                &mut st,
                &format!("fxr_symbols:{e}"),
                serde_json::json!(["USDC"]),
            );
            put(
                &mut st,
                &format!("fxr_sub:USDC:{e}"),
                serde_json::json!([{ "validator": "v0", "rate": rate.to_string(), "stake": "100", "sources": ["a", "b"] }]),
            );
            logs.extend(tally(&mut st, e));
        }
        let b = sa::read_breaker(&st, &id);
        assert!(b.suspended, "{b:?}");
        assert_eq!(b.since_epoch, Some(3));
        assert!(topics(&logs).contains(&sa::ASSET_SUSPENDED_TOPIC.to_vec()));
    }

    fn tally(st: &mut crate::StateAdapter, epoch: u64) -> Vec<Log> {
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        tally_rates(st, epoch, &mut changes, &mut logs).unwrap();
        logs
    }

    fn topics(logs: &[Log]) -> Vec<Vec<u8>> {
        logs.iter().flat_map(|l| l.topics.clone()).collect()
    }

    /// Frozen medians more than the longest governed lookback behind the rate
    /// in force are deleted, the ones a reader may still look at stay, and
    /// a window set above its governed maximum reads no further back.
    #[test]
    fn medians_older_than_the_longest_lookback_are_deleted() {
        let mut st = rate_state(100);
        let last = KEPT_MEDIAN_EPOCHS + 40;
        for e in 0..=last {
            opened(&mut st, e, &[(1_000, 100)]);
            tally(&mut st, e);
        }
        assert_eq!(read_fee_rate(&st).epoch, Some(last));
        let kept_from = last + 1 - KEPT_MEDIAN_EPOCHS;
        for e in 0..kept_from {
            assert!(
                read_committed_rate(&st, FEE_SYMBOL, e).is_none(),
                "median {e}"
            );
        }
        for e in kept_from..=last {
            assert!(
                read_committed_rate(&st, FEE_SYMBOL, e).is_some(),
                "median {e}"
            );
        }
        set_genesis_param(&mut st, SAFETY_RATE_WINDOW_PARAM, 10 * KEPT_MEDIAN_EPOCHS);
        assert_eq!(safety_rate(&st), 1_000);
    }

    /// The sealed and opened reports of a tallied epoch whose opening hour
    /// has passed are deleted, the frozen median stays, and the two epochs
    /// still being sealed or opened keep theirs.
    #[test]
    fn reports_of_a_tallied_epoch_are_deleted_and_its_median_kept() {
        let mut st = rate_state(100);
        for e in 0..10u64 {
            opened(&mut st, e, &[(1_000, 100)]);
            put(&mut st, &format!("fxr_commit:{e}"), serde_json::json!([]));
            tally(&mut st, e);
        }
        let mut changes = Vec::new();
        prune_rate_epochs(&mut st, 10, &[0], &mut changes).unwrap();
        for e in 0..8u64 {
            for key in [
                format!("fxr_commit:{e}"),
                format!("fxr_symbols:{e}"),
                format!("fxr_sub:TNZO:{e}"),
            ] {
                assert_eq!(
                    st.get_storage(&SYSTEM_ADDRESS, key.as_bytes()),
                    None,
                    "{key}"
                );
            }
            assert!(read_committed_rate(&st, FEE_SYMBOL, e).is_some());
        }
        for e in 8..10u64 {
            assert!(read_json::<Vec<String>>(&st, &format!("fxr_symbols:{e}")).is_some());
            assert!(read_json::<serde_json::Value>(&st, &format!("fxr_sub:TNZO:{e}")).is_some());
        }
        // The next report goes on from where this one stopped.
        prune_rate_epochs(&mut st, 11, &[], &mut changes).unwrap();
        assert_eq!(st.get_storage(&SYSTEM_ADDRESS, b"fxr_symbols:8"), None);
        assert!(read_json::<Vec<String>>(&st, "fxr_symbols:9").is_some());
    }

    /// Reports arriving hour by hour, each with only the previous epoch
    /// pending, as on a running chain: every hour deletes what has passed.
    #[test]
    fn reports_are_deleted_as_the_hours_pass() {
        let mut st = rate_state(100);
        let mut changes = Vec::new();
        for now in 0..12u64 {
            opened(&mut st, now, &[(1_000, 100)]);
            put(&mut st, &format!("fxr_commit:{now}"), serde_json::json!([]));
            prune_rate_epochs(&mut st, now, &[now.saturating_sub(1)], &mut changes).unwrap();
        }
        for e in 0..9u64 {
            for key in [format!("fxr_commit:{e}"), format!("fxr_symbols:{e}")] {
                assert_eq!(
                    st.get_storage(&SYSTEM_ADDRESS, key.as_bytes()),
                    None,
                    "{key}"
                );
            }
        }
        assert!(read_json::<Vec<String>>(&st, "fxr_symbols:9").is_some());
    }

    fn opened_with_sources(
        st: &mut crate::StateAdapter,
        epoch: u64,
        reports: &[(u128, u128)],
        sources: &[&str],
    ) {
        opened(st, epoch, reports);
        let key = format!("fxr_sub:TNZO:{epoch}");
        let mut subs: Vec<serde_json::Value> = read_json(st, &key).unwrap();
        for s in &mut subs {
            s["sources"] = serde_json::json!(sources);
        }
        put(st, &key, serde_json::json!(subs));
    }

    fn held_reasons(logs: &[Log]) -> Vec<String> {
        logs.iter()
            .filter(|l| l.topics.first().is_some_and(|t| t == FEE_RATE_HELD_TOPIC))
            .map(|l| {
                let v: serde_json::Value = serde_json::from_slice(&l.data).unwrap();
                v["reason"].as_str().unwrap().to_string()
            })
            .collect()
    }

    /// Governance sets how many independent sources a report needs: a report
    /// quoting fewer is refused when opened, and one opened under a lower
    /// count is not counted once the count is raised.
    #[test]
    fn a_report_below_the_governed_source_count_is_refused_and_not_counted() {
        assert!(report_rates(&[q("a", 5), q("b", 6)], 3).is_err());
        assert!(report_rates(&[q("a", 5), q("b", 6), q("c", 7)], 3).is_ok());
        // Below the floor counts as the floor.
        assert!(report_rates(&[q("a", 5)], 1).is_err());

        let mut st = rate_state(300);
        set_genesis_param(&mut st, GOVERNANCE_RATE_PARAM, 1_000);
        live(&mut st, 1_000, 10);
        opened_with_sources(
            &mut st,
            11,
            &[(1_005, 100), (1_005, 100), (1_005, 100)],
            &["a", "b"],
        );
        set_genesis_param(&mut st, RATE_MIN_SOURCES_PARAM, 3);
        let logs = tally(&mut st, 11);
        assert_eq!(held_reasons(&logs), vec!["below_quorum".to_string()]);
        assert!(read_committed_rate(&st, FEE_SYMBOL, 11).is_none());

        opened_with_sources(
            &mut st,
            12,
            &[(1_005, 100), (1_005, 100), (1_005, 100)],
            &["a", "b", "c"],
        );
        tally(&mut st, 12);
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_005);
    }

    /// Reports that disagree beyond the governed spread hold the rate where
    /// it is instead of moving it into their band, and say why.
    #[test]
    fn dispersed_reports_hold_the_rate_instead_of_moving_it() {
        let mut st = rate_state(400);
        set_genesis_param(&mut st, GOVERNANCE_RATE_PARAM, 1_000);
        live(&mut st, 1_000, 10);
        // Low quantile 1,150, high 1,300: a 13% spread, above the 5% bound.
        // Without the breaker the rate would rise one step, to 1,010.
        opened(
            &mut st,
            11,
            &[(1_100, 100), (1_150, 100), (1_300, 100), (1_400, 100)],
        );
        let logs = tally(&mut st, 11);
        assert_eq!(held_reasons(&logs), vec!["dispersion".to_string()]);
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_000);
        let frozen = read_committed_rate(&st, FEE_SYMBOL, 11).unwrap();
        assert_eq!(frozen.applied_nano_usd, "1000");
        assert_eq!(rate_breaker(&st, FEE_SYMBOL).breached_epochs, 1);

        // Within the spread the same rise goes through and the count resets.
        set_genesis_param(&mut st, RATE_BREAKER_SPREAD_PARAM, 2_000);
        opened(
            &mut st,
            12,
            &[(1_100, 100), (1_150, 100), (1_300, 100), (1_400, 100)],
        );
        let logs = tally(&mut st, 12);
        assert!(held_reasons(&logs).is_empty());
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_010);
        assert_eq!(rate_breaker(&st, FEE_SYMBOL).breached_epochs, 0);
    }

    /// A pumped or broken venue that drags every report together far from
    /// the governance rate never moves the rate: after the governed number of
    /// such epochs in a row the governance rate is in force, and it stays in
    /// force until governance sets validator mode again.
    #[test]
    fn the_rate_falls_back_to_the_governance_rate_after_the_breach_epochs() {
        let mut st = rate_state(300);
        set_genesis_param(&mut st, GOVERNANCE_RATE_PARAM, 1_000);
        live(&mut st, 1_400, 10);
        let pumped = [(1_600, 100), (1_600, 100), (1_600, 100)];
        // Breach, breach, clean, breach: the count starts again.
        opened(&mut st, 11, &pumped);
        tally(&mut st, 11);
        opened(&mut st, 12, &pumped);
        tally(&mut st, 12);
        opened(&mut st, 13, &[(1_400, 100), (1_400, 100), (1_400, 100)]);
        tally(&mut st, 13);
        assert_eq!(rate_breaker(&st, FEE_SYMBOL).breached_epochs, 0);
        for e in 14..16 {
            opened(&mut st, e, &pumped);
            tally(&mut st, e);
            assert_eq!(read_fee_rate(&st).mode, "validators");
            assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_400);
        }
        opened(&mut st, 16, &pumped);
        let logs = tally(&mut st, 16);
        assert!(topics(&logs).contains(&FEE_RATE_BREAKER_TOPIC.to_vec()));
        let r = read_fee_rate(&st);
        assert_eq!((r.mode.as_str(), r.rate_nano_usd), ("governance", 1_000));
        assert!(!rate_age(&st, FEE_SYMBOL, 17 * MARKET_EPOCH_MS).held);
        assert_eq!(rate_breaker(&st, FEE_SYMBOL).tripped_epoch, Some(16));

        // Clean epochs do not re-arm it; governance does.
        opened(&mut st, 17, &[(1_400, 100), (1_400, 100), (1_400, 100)]);
        tally(&mut st, 17);
        assert_eq!(read_fee_rate(&st).mode, "governance");
        let mut changes = Vec::new();
        rearm_rate_breaker(&mut st, &mut changes);
        assert_eq!(read_fee_rate(&st).mode, "validators");
        assert_eq!(rate_breaker(&st, FEE_SYMBOL), RateBreaker::default());
    }

    /// A validator that seals its rates and never opens them forfeits the
    /// governed share of its bond to the insurance pool when the epoch is
    /// tallied, once; a validator that opened loses nothing.
    #[test]
    fn a_sealed_report_never_opened_forfeits_stake_to_the_insurance_pool() {
        const TNZO: u128 = 1_000_000_000_000_000_000;
        let mut st = crate::StateAdapter::new();
        set_genesis_param(&mut st, RATE_MODE_PARAM, 1);
        let (quiet, honest) = ([7u8; 32], [8u8; 32]);
        for who in [quiet, honest] {
            super::super::staking::add_bond(&mut st, &who, 10_000 * TNZO, 0).unwrap();
        }
        let vault = st.get_balance(&STAKING_VAULT_ADDRESS);
        st.set_balance(&STAKING_VAULT_ADDRESS, vault + 20_000 * TNZO);
        let pool = derive_insurance_pool_address().as_bytes().to_vec();
        let pool_before = st.get_balance(&pool);
        put(
            &mut st,
            &commits_key(11),
            serde_json::json!([
                { "validator": hex::encode(quiet), "commitment": "00", "stake": "1", "opened": false },
                { "validator": hex::encode(honest), "commitment": "00", "stake": "1", "opened": true },
            ]),
        );
        let logs = tally(&mut st, 11);
        assert_eq!(topics(&logs), vec![FEE_RATE_UNOPENED_TOPIC.to_vec()]);
        let forfeit = 10_000 * TNZO * u128::from(DEFAULT_RATE_UNOPENED_SLASH_BPS) / 10_000;
        assert_eq!(bonded_stake_of(&st, &quiet), 10_000 * TNZO - forfeit);
        assert_eq!(bonded_stake_of(&st, &honest), 10_000 * TNZO);
        assert_eq!(st.get_balance(&pool), pool_before + forfeit);
        // Tallying the epoch again takes nothing more.
        assert!(tally(&mut st, 11).is_empty());
        assert_eq!(bonded_stake_of(&st, &quiet), 10_000 * TNZO - forfeit);
    }

    #[test]
    fn missing_reports_hold_fees_at_the_last_good_rate_and_say_so() {
        // One validator of three opens: below the staleness quorum.
        let mut st = rate_state(300);
        live(&mut st, 1_000, 10);
        let before = usd_to_wei(&st, 1_000_000_000_000);
        opened(&mut st, 11, &[(50, 100)]);
        let logs = tally(&mut st, 11);
        assert_eq!(topics(&logs), vec![FEE_RATE_HELD_TOPIC.to_vec()]);
        let held: serde_json::Value = serde_json::from_slice(&logs[0].data).unwrap();
        assert_eq!(held["reason"], "below_quorum");
        assert_eq!(held["rate_nano_usd"], "1000");
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_000);
        assert_eq!(usd_to_wei(&st, 1_000_000_000_000), before);
        assert!(read_committed_rate(&st, FEE_SYMBOL, 11).is_none());
    }

    #[test]
    fn a_rate_past_its_maximum_age_is_reported_held_and_not_moved() {
        let mut st = rate_state(300);
        live(&mut st, 1_000, 10);
        let at = |epoch: u64| epoch as i64 * MARKET_EPOCH_MS + 1;
        let max = DEFAULT_RATE_MAX_AGE_EPOCHS;
        let fresh = rate_age(&st, FEE_SYMBOL, at(10 + max));
        assert_eq!(fresh.age_epochs, Some(max));
        assert!(!fresh.held);
        let stale = rate_age(&st, FEE_SYMBOL, at(11 + max));
        assert!(stale.held);
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_000);
        // The limit is governed.
        set_genesis_param(&mut st, RATE_MAX_AGE_PARAM, max + 5);
        assert!(!rate_age(&st, FEE_SYMBOL, at(11 + max)).held);
        // The governance rate is never held; a validator rate never set is.
        set_genesis_param(&mut st, RATE_MODE_PARAM, 0);
        assert!(!rate_age(&st, FEE_SYMBOL, at(1_000)).held);
        assert!(rate_age(&rate_state(300), FEE_SYMBOL, at(1)).held);
        assert!(rate_age(&st, "ETH", at(1)).held);
    }

    #[test]
    fn a_manipulated_rate_moves_at_most_the_bound_or_not_at_all() {
        // A third of stake reporting ten times the market moves nothing.
        let mut st = rate_state(300);
        // The step cap alone is under test: the governance rate and the gap
        // bound leave the dispersion breaker out of it.
        set_genesis_param(&mut st, GOVERNANCE_RATE_PARAM, 5_000);
        set_genesis_param(&mut st, RATE_BREAKER_GAP_PARAM, 50_000);
        live(&mut st, 1_000, 10);
        opened(&mut st, 11, &[(10_000, 100), (1_000, 100), (1_000, 100)]);
        tally(&mut st, 11);
        assert_eq!(read_fee_rate(&st).rate_nano_usd, 1_000);
        // Every report agreeing on ten times the market moves the bound only.
        opened(&mut st, 12, &[(10_000, 100), (10_000, 100), (10_000, 100)]);
        tally(&mut st, 12);
        let bound = 1_000 + 1_000 * u128::from(DEFAULT_RATE_MAX_CHANGE_BPS) / 10_000;
        assert_eq!(read_fee_rate(&st).rate_nano_usd, bound);
        // A governance hold keeps it there and says so.
        set_genesis_param(&mut st, RATE_FROZEN_PARAM, 1);
        opened(&mut st, 13, &[(10_000, 100), (10_000, 100), (10_000, 100)]);
        let logs = tally(&mut st, 13);
        assert!(topics(&logs).contains(&FEE_RATE_HELD_TOPIC.to_vec()));
        assert_eq!(read_fee_rate(&st).rate_nano_usd, bound);
    }

    #[test]
    fn a_rate_is_held_exactly_from_one_past_its_maximum_age() {
        assert!(!age_of(false, Some(5), 7, 2).held);
        assert!(age_of(false, Some(5), 8, 2).held);
        assert!(age_of(false, None, 0, 2).held);
        assert!(!age_of(true, None, 99, 2).held);
        // A median frozen for a later epoch than now is never negative age.
        assert_eq!(age_of(false, Some(9), 3, 2).age_epochs, Some(0));
    }
}
