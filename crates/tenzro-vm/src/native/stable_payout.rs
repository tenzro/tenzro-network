//! Payouts in an approved stable asset, sized in US dollars.
//!
//! The treasury holds stable assets as well as TNZO. Sponsorship and grants
//! may be paid in one, so a falling TNZO price does not shrink what a
//! verified hour or a milestone is worth. Nothing about the gate changes:
//! the recipient is an approved operator or grantee, the payment is backed by
//! verified hours or a milestone, and it counts against governed yearly caps
//! and the treasury outflow limit. Only the unit differs:
//!
//! - The asset is an enabled, priced, on-peg USD entry of the governed
//!   settlement registry ([`super::settlement_asset::permitted`]), so a
//!   depegged or suspended asset pays nothing.
//! - The caps (`*_usd` parameters, whole dollars) and the per-hour value
//!   (micro-dollars) are zero at genesis.
//! - The outflow limit is the governed treasury limit (per proposal and per
//!   period, in basis points) applied to the value of the treasury's stable
//!   holdings, so the TNZO limit and the stable limit are independent.
//! - The asset moves from the treasury's balance to the recipient. Nothing
//!   is issued and no token supply changes.
//!
//! A payment may ask for the governed per-proposal exception
//! (`treasury.proposal_outflow_exception_bps`, zero at genesis): headroom
//! above the period limit for that one payment, still inside the yearly USD
//! caps and the per-proposal limit.

use serde::{Deserialize, Serialize};

use super::funding::{bps_of, read_json, refuse, write_json};
use super::payout_gates::{
    PER_VERIFIED_EPOCH_USD_PARAM, PayoutKind, Unit, check_grant_caps, check_sponsorship_caps,
    commit_in_unit, consume_hours, plan_hours, require_approved_grantee, require_approved_operator,
};
use super::settlement_asset;
use super::{derive_treasury_address, network_param};
use crate::error::Result;
use crate::governance::{
    MAX_PERIOD_OUTFLOW_PARAM, MAX_PROPOSAL_OUTFLOW_PARAM, OUTFLOW_PERIOD_PARAM,
};
use crate::token_ledger;
use crate::traits::VmState;
use crate::types::{Log, StateChange};
use tenzro_types::primitives::Address;

/// Governed key: extra basis points of the period's opening stable value one
/// flagged payment may use above the period limit. Zero at genesis.
pub const PROPOSAL_EXCEPTION_PARAM: &str = "treasury.proposal_outflow_exception_bps";

const PERIOD_KEY: &str = "treasury_stable_outflow_period";

/// A settlement asset and the rate it prices at now.
pub struct Priced {
    pub token: [u8; 32],
    pub token_id: String,
    pub rate_nano_usd: u128,
    pub decimals: u8,
}

impl Priced {
    /// What `amount` smallest units are worth, micro-dollars, rounded up.
    pub fn usd_e6(&self, amount: u128) -> u128 {
        settlement_asset::value_e6_up(amount, self.rate_nano_usd, self.decimals)
    }
}

/// The settlement asset `token_id` names, when it may pay out now: a USD
/// entry that is enabled, priced, on its peg and not suspended.
pub fn price(state: &dyn VmState, token_id: &str) -> Result<Priced> {
    let token = crate::governance::parse_token_id(token_id).map_err(|e| refuse(e.to_string()))?;
    let permitted = settlement_asset::permitted(state, &token)?;
    if permitted.asset.currency != tenzro_types::settlement_asset::NUMERAIRE {
        return Err(refuse(format!(
            "{} is pegged to {}; only a USD stable asset pays sponsorship and grants",
            permitted.asset.symbol, permitted.asset.currency
        )));
    }
    Ok(Priced {
        token,
        token_id: token_id.to_ascii_lowercase(),
        rate_nano_usd: permitted.rate_nano_usd,
        decimals: permitted.asset.decimals,
    })
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
struct StablePeriod {
    started_ms: i64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    opening_e6: u128,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    paid_e6: u128,
}

/// The treasury's stable holdings, micro-dollars at the rates in force.
pub fn treasury_stable_value(state: &dyn VmState) -> u128 {
    settlement_asset::holdings_value_e6(state, derive_treasury_address().as_bytes())
}

fn period(state: &dyn VmState, now_ms: i64) -> StablePeriod {
    let length = network_param(state, OUTFLOW_PERIOD_PARAM) as i64;
    match read_json::<StablePeriod>(state, PERIOD_KEY) {
        Some(p) if now_ms < p.started_ms.saturating_add(length) => p,
        _ => StablePeriod {
            started_ms: now_ms,
            opening_e6: treasury_stable_value(state),
            paid_e6: 0,
        },
    }
}

/// What one enacting proposal may commit: at most the governed share of the
/// treasury's stable holdings.
pub fn commit_stable(state: &dyn VmState, committed_e6: u128) -> Result<()> {
    let cap = bps_of(
        treasury_stable_value(state),
        network_param(state, MAX_PROPOSAL_OUTFLOW_PARAM),
    );
    if committed_e6 > cap {
        return Err(refuse(format!(
            "a proposal may pay at most {cap} micro-dollars from the treasury's stable holdings; \
             this one commits {committed_e6}"
        )));
    }
    Ok(())
}

/// Count `usd_e6` against the stable outflow period. `exception` adds the
/// governed headroom for this payment only.
pub fn record_stable(
    state: &mut dyn VmState,
    usd_e6: u128,
    exception: bool,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut p = period(state, now_ms);
    let mut cap = bps_of(p.opening_e6, network_param(state, MAX_PERIOD_OUTFLOW_PARAM));
    if exception {
        cap = cap.saturating_add(bps_of(
            p.opening_e6,
            network_param(state, PROPOSAL_EXCEPTION_PARAM),
        ));
    }
    let paid = p.paid_e6.saturating_add(usd_e6);
    if paid > cap {
        return Err(refuse(format!(
            "the treasury may pay out {cap} micro-dollars of stable assets in this outflow period \
             and has paid {}; {usd_e6} more is over the limit{}",
            p.paid_e6,
            if exception {
                ""
            } else {
                " (a payment may ask for the governed per-proposal exception)"
            }
        )));
    }
    p.paid_e6 = paid;
    write_json(state, PERIOD_KEY, &p, changes)?;
    Ok(())
}

/// Move `amount` of `token` from the treasury to `to`. Moves existing
/// balance only.
fn transfer_out(
    state: &mut dyn VmState,
    token: &[u8; 32],
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let moved = token_ledger::transfer(
        state,
        token,
        derive_treasury_address().as_bytes(),
        to,
        amount,
        now_ms,
    )?
    .ok_or_else(|| refuse("the treasury holds less of the asset than the payment"))?;
    changes.extend(moved);
    Ok(())
}

fn per_hour_usd(state: &dyn VmState) -> u128 {
    u128::from(network_param(state, PER_VERIFIED_EPOCH_USD_PARAM))
}

/// Submission check for a stable running-cost sponsorship.
pub fn check_sponsorship(
    state: &dyn VmState,
    operator: &[u8],
    from: u64,
    to: u64,
    token_id: &str,
    amount: u128,
) -> Result<()> {
    let priced = price(state, token_id)?;
    plan_hours(
        state,
        operator,
        from,
        to,
        priced.usd_e6(amount),
        per_hour_usd(state),
        PER_VERIFIED_EPOCH_USD_PARAM,
    )
    .map(|_| ())
}

/// Enact a stable running-cost sponsorship.
#[allow(clippy::too_many_arguments)]
pub(super) fn sponsor_stable(
    state: &mut dyn VmState,
    proposal_id: &str,
    operator: &Address,
    from: u64,
    to: u64,
    token_id: &str,
    amount: u128,
    exception: bool,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let priced = price(state, token_id)?;
    let usd = priced.usd_e6(amount);
    let plan = plan_hours(
        state,
        operator.as_bytes(),
        from,
        to,
        usd,
        per_hour_usd(state),
        PER_VERIFIED_EPOCH_USD_PARAM,
    )?;
    let class = require_approved_operator(state, operator.as_bytes())?.class;
    let view = check_sponsorship_caps(state, Unit::Usd, operator.as_bytes(), usd, now_ms)?;
    commit_stable(state, usd)?;
    record_stable(state, usd, exception, now_ms, changes)?;
    transfer_out(
        state,
        &priced.token,
        operator.as_bytes(),
        amount,
        now_ms,
        changes,
    )?;
    consume_hours(state, &plan, proposal_id, changes);
    let basis = format!(
        "{} verified-available hours of {} in epochs {from} to {to}",
        plan.hours.len(),
        plan.did
    );
    commit_in_unit(
        state,
        view,
        PayoutKind::RunningCost,
        operator.as_bytes(),
        class.label(),
        amount,
        usd,
        &priced.token_id,
        proposal_id,
        &basis,
        now_ms,
        changes,
        logs,
    )
}

/// Submission check for a stable grant: the asset pays out now.
pub fn check_grant_asset(state: &dyn VmState, token_id: &str) -> Result<()> {
    price(state, token_id).map(|_| ())
}

/// Commit a stable grant's whole amount against the per-proposal limit.
pub(super) fn commit_grant(state: &dyn VmState, token_id: &str, amount: u128) -> Result<()> {
    let priced = price(state, token_id)?;
    commit_stable(state, priced.usd_e6(amount))
}

/// Pay one stable grant payment to an approved grantee against a milestone.
#[allow(clippy::too_many_arguments)]
pub(super) fn pay_grant_stable(
    state: &mut dyn VmState,
    proposal_id: &str,
    recipient: &Address,
    token_id: &str,
    amount: u128,
    milestone: &str,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let approval = require_approved_grantee(state, recipient.as_bytes())?;
    let priced = price(state, token_id)?;
    let usd = priced.usd_e6(amount);
    let view = check_grant_caps(state, Unit::Usd, recipient.as_bytes(), usd, now_ms)?;
    record_stable(state, usd, false, now_ms, changes)?;
    transfer_out(
        state,
        &priced.token,
        recipient.as_bytes(),
        amount,
        now_ms,
        changes,
    )?;
    commit_in_unit(
        state,
        view,
        PayoutKind::Grant,
        recipient.as_bytes(),
        approval.class.label(),
        amount,
        usd,
        &priced.token_id,
        proposal_id,
        milestone,
        now_ms,
        changes,
        logs,
    )
}

/// What a remote payout is worth, micro-dollars: the amount moved and the
/// relayer refund, both leave the treasury's account.
fn remote_usd(priced: &Priced, remote: &tenzro_types::remote_grant::RemoteAction) -> u128 {
    priced
        .usd_e6(remote.amount)
        .saturating_add(priced.usd_e6(remote.relay_refund))
}

/// Submission check for a treasury remote action: one that moves value
/// names an approved operator paid against verified hours.
pub fn check_remote(
    state: &dyn VmState,
    remote: &tenzro_types::remote_grant::RemoteAction,
    payout: Option<&crate::governance::RemotePayout>,
) -> Result<()> {
    let moves_value = remote.amount > 0 || remote.relay_refund > 0;
    match (moves_value, payout) {
        (false, _) => Ok(()),
        (true, None) => Err(refuse(
            "a treasury remote action that moves value names the approved operator it pays",
        )),
        (true, Some(p)) => {
            let priced = price(state, &p.priced_by)?;
            plan_hours(
                state,
                p.payee.as_bytes(),
                p.from_epoch,
                p.to_epoch,
                remote_usd(&priced, remote),
                per_hour_usd(state),
                PER_VERIFIED_EPOCH_USD_PARAM,
            )
            .map(|_| ())
        }
    }
}

/// Enact the payout side of a treasury remote action, before its grant is
/// written. A remote action that moves nothing pays nothing.
#[allow(clippy::too_many_arguments)]
pub(super) fn pay_remote(
    state: &mut dyn VmState,
    proposal_id: &str,
    remote: &tenzro_types::remote_grant::RemoteAction,
    payout: Option<&crate::governance::RemotePayout>,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if remote.amount == 0 && remote.relay_refund == 0 {
        return Ok(());
    }
    let p = payout.ok_or_else(|| {
        refuse("a treasury remote action that moves value names the approved operator it pays")
    })?;
    let priced = price(state, &p.priced_by)?;
    let usd = remote_usd(&priced, remote);
    let plan = plan_hours(
        state,
        p.payee.as_bytes(),
        p.from_epoch,
        p.to_epoch,
        usd,
        per_hour_usd(state),
        PER_VERIFIED_EPOCH_USD_PARAM,
    )?;
    let class = require_approved_operator(state, p.payee.as_bytes())?.class;
    let view = check_sponsorship_caps(state, Unit::Usd, p.payee.as_bytes(), usd, now_ms)?;
    commit_stable(state, usd)?;
    record_stable(state, usd, false, now_ms, changes)?;
    consume_hours(state, &plan, proposal_id, changes);
    let basis = format!(
        "{} verified-available hours of {} in epochs {} to {}, paid on another chain",
        plan.hours.len(),
        plan.did,
        p.from_epoch,
        p.to_epoch
    );
    commit_in_unit(
        state,
        view,
        PayoutKind::RemoteRunningCost,
        p.payee.as_bytes(),
        class.label(),
        remote.amount.saturating_add(remote.relay_refund),
        usd,
        &priced.token_id,
        proposal_id,
        &basis,
        now_ms,
        changes,
        logs,
    )
}
