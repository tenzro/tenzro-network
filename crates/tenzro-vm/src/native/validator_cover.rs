//! Validators' running cost, paid first from the stable fees that paid usage
//! settles.
//!
//! - Booking. Every settlement fee the treasury keeps in a stable settlement
//!   asset is booked against that asset ([`note_stable_fee`]) until the next
//!   reward epoch closes.
//! - Fill. When a reward epoch closes, `validator.stable_cover_fee_share_bps`
//!   of what was booked since the last close moves from the treasury into the
//!   cover reserve, a keyless vault, while the reserve holds less than
//!   `validator.stable_cover_target_months` months of the active set's running
//!   cost. Nothing else fills it: no rewards pool, no grant, no mint.
//! - Pay. Each validator with consensus work in the closing epoch is owed one
//!   epoch of `validator.base_cost_usd_month`. The reserve pays it in the
//!   assets it holds that may settle (registered, priced, on peg and not
//!   suspended by the peg breaker), as far as they go, every validator the
//!   same. What it cannot pay is the epoch's shortfall: logged, and left to
//!   the base reward, the governed share of the burn the same paid usage
//!   produced ([`super::rewards::validator_base_rights`], which pays only
//!   the uncovered part). An asset that may not settle pays nothing and is
//!   kept; nothing falls back to another asset or to the rewards pool.
//!
//! An empty reserve, an epoch without stable fees or a set without active
//! validators pays nothing and waits: nothing is refused, nothing goes
//! negative, no block is held up.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenzro_types::primitives::u128_serde;

use super::funding::{read_json, write_json};
use super::settlement_asset::{listed_ids, permitted, units_for_e6, value_e6};
use super::*;

/// Governed: share of the stable settlement fees the treasury keeps that
/// fills the cover reserve, bps.
pub const FEE_SHARE_PARAM: &str = "validator.stable_cover_fee_share_bps";
/// Governed: months of the active set's running cost the cover reserve
/// fills up to.
pub const TARGET_MONTHS_PARAM: &str = "validator.stable_cover_target_months";

pub const DEFAULT_FEE_SHARE_BPS: u64 = 10_000;
pub const DEFAULT_TARGET_MONTHS: u64 = 12;

const VAULT_DOMAIN: &[u8] = b"tenzro/validator/stable-cover-reserve";
const BOOKED_KEY: &str = "validator_cover_booked";

/// Topic of the log an epoch's cover emits.
pub const COVER_TOPIC: &[u8] = b"ValidatorCostCovered";

/// The cover reserve: a keyless vault only this module moves.
pub fn reserve_address() -> Address {
    let digest = Sha256::digest(VAULT_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// What one epoch's cover owed and paid, micro-USD.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochCover {
    /// Validators with consensus work in the epoch.
    pub validators: u64,
    /// Running cost owed, all validators together.
    #[serde(with = "u128_serde")]
    pub need_e6: u128,
    /// Paid out of the reserve.
    #[serde(with = "u128_serde")]
    pub paid_e6: u128,
    /// Moved from the treasury's stable fees into the reserve.
    #[serde(with = "u128_serde")]
    pub filled_e6: u128,
}

fn cover_key(epoch: u64) -> String {
    format!("validator_cover_epoch:{epoch:016x}")
}

/// The cover recorded for `epoch`; zeros before it closed.
pub fn read_cover(state: &dyn VmState, epoch: u64) -> EpochCover {
    read_json(state, &cover_key(epoch)).unwrap_or_default()
}

/// Stable fees booked since the last close, units by token id hex.
fn read_booked(state: &dyn VmState) -> BTreeMap<String, String> {
    read_json(state, BOOKED_KEY).unwrap_or_default()
}

/// Books `units` of `token` the treasury just kept as a settlement fee.
pub(super) fn note_stable_fee(
    state: &mut dyn VmState,
    token: &[u8; 32],
    units: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if units == 0 || *token == crate::token_ledger::tnzo_id() {
        return Ok(());
    }
    let mut booked = read_booked(state);
    let e = booked
        .entry(hex::encode(token))
        .or_insert_with(|| "0".into());
    let now: u128 = e.parse().unwrap_or(0);
    *e = now.saturating_add(units).to_string();
    write_json(state, BOOKED_KEY, &booked, changes)?;
    Ok(())
}

/// One validator's running cost for one epoch of `epochs_per_year`, micro-USD.
pub fn cost_each_e6(state: &dyn VmState, epochs_per_year: u64) -> u128 {
    u128::from(network_param(
        state,
        super::rewards::VALIDATOR_BASE_COST_PARAM,
    ))
    .saturating_mul(1_000_000)
    .saturating_mul(12)
        / u128::from(epochs_per_year.max(1))
}

/// What `account` holds in assets that may settle, with each asset's rate
/// and decimals, largest value first.
fn settleable(state: &dyn VmState, account: &[u8]) -> Vec<([u8; 32], u128, u128, u8)> {
    let mut v: Vec<([u8; 32], u128, u128, u8)> = listed_ids(state)
        .into_iter()
        .filter_map(|id| {
            let held = crate::token_ledger::balance(state, &id, account);
            if held == 0 {
                return None;
            }
            let p = permitted(state, &id).ok()?;
            Some((id, held, p.rate_nano_usd, p.asset.decimals))
        })
        .collect();
    v.sort_by(|a, b| {
        value_e6(b.1, b.2, b.3)
            .cmp(&value_e6(a.1, a.2, a.3))
            .then(a.0.cmp(&b.0))
    });
    v
}

/// Fills the reserve from the fees booked since the last close and pays the
/// running cost of `validators` for the closing `epoch` (see the module
/// header). Returns what it recorded.
pub(super) fn cover_epoch(
    state: &mut dyn VmState,
    epoch: u64,
    validators: &[Address],
    epochs_per_year: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<EpochCover> {
    let treasury = derive_treasury_address();
    let reserve = reserve_address();
    let n = validators.len() as u128;
    let each = cost_each_e6(state, epochs_per_year);
    let mut cover = EpochCover {
        validators: n as u64,
        need_e6: each.saturating_mul(n),
        ..EpochCover::default()
    };

    // Fill, while under target, from the fees booked.
    let booked = read_booked(state);
    if !booked.is_empty() {
        write_json(
            state,
            BOOKED_KEY,
            &BTreeMap::<String, String>::new(),
            changes,
        )?;
    }
    let share = u128::from(network_param(state, FEE_SHARE_PARAM).min(10_000));
    let months_per_year = 12u128;
    let target = each
        .saturating_mul(n.max(1))
        .saturating_mul(u128::from(epochs_per_year.max(1)))
        / months_per_year
        * u128::from(network_param(state, TARGET_MONTHS_PARAM));
    let mut held_e6: u128 = settleable(state, reserve.as_bytes())
        .iter()
        .map(|(_, h, r, d)| value_e6(*h, *r, *d))
        .fold(0, u128::saturating_add);
    for (hex_id, units) in &booked {
        let Some(id) = hex::decode(hex_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue;
        };
        let Ok(p) = permitted(state, &id) else {
            continue; // Not settleable now: the treasury keeps it.
        };
        let room = target.saturating_sub(held_e6);
        if room == 0 {
            break;
        }
        let want = units.parse::<u128>().unwrap_or(0).saturating_mul(share) / 10_000;
        let in_treasury = crate::token_ledger::balance(state, &id, treasury.as_bytes());
        let room_units = units_for_e6(room, p.rate_nano_usd, p.asset.decimals);
        let moved = want.min(in_treasury).min(room_units);
        if moved == 0 {
            continue;
        }
        super::payment_settlement::move_asset(
            state,
            &id,
            treasury.as_bytes(),
            reserve.as_bytes(),
            moved,
            now_ms,
            changes,
        )?;
        let v = value_e6(moved, p.rate_nano_usd, p.asset.decimals);
        held_e6 = held_e6.saturating_add(v);
        cover.filled_e6 = cover.filled_e6.saturating_add(v);
    }

    // Pay, every validator the same, as far as the reserve goes.
    if n > 0 && each > 0 {
        let pay_each = each.min(held_e6 / n);
        if pay_each > 0 {
            for v in validators {
                let mut left = pay_each;
                for (id, held, rate, dec) in settleable(state, reserve.as_bytes()) {
                    if left == 0 {
                        break;
                    }
                    let worth = value_e6(held, rate, dec);
                    let take_e6 = left.min(worth);
                    let units = units_for_e6(take_e6, rate, dec).min(held);
                    super::payment_settlement::move_asset(
                        state,
                        &id,
                        reserve.as_bytes(),
                        v.as_bytes(),
                        units,
                        now_ms,
                        changes,
                    )?;
                    left = left.saturating_sub(take_e6);
                    cover.paid_e6 = cover.paid_e6.saturating_add(take_e6);
                }
            }
        }
    }
    write_json(state, &cover_key(epoch), &cover, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![COVER_TOPIC.to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "epoch": epoch,
            "validators": cover.validators,
            "need_e6": cover.need_e6.to_string(),
            "paid_e6": cover.paid_e6.to_string(),
            "shortfall_e6": cover.need_e6.saturating_sub(cover.paid_e6).to_string(),
            "filled_e6": cover.filled_e6.to_string(),
        }))
        .map_err(|e| VmError::Internal(format!("encode validator cover log: {e}")))?,
    ));
    Ok(cover)
}

/// Share of the running cost `cover` left unpaid, as (numerator,
/// denominator): the part the base reward may still pay.
pub fn uncovered(cover: &EpochCover) -> (u128, u128) {
    if cover.need_e6 == 0 {
        (1, 1)
    } else {
        (cover.need_e6.saturating_sub(cover.paid_e6), cover.need_e6)
    }
}
