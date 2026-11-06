//! Payout in a settlement asset the payee prefers.
//!
//! A payee lists, on chain, the settlement assets it accepts being paid out
//! in (`PaymentOp::SetPayoutAssets`). A payment that arrives in a stable
//! asset is paid out to it in one of them: the arrival asset itself when
//! listed and no other listed asset sits further over its treasury share
//! target, otherwise the listed asset the treasury holds most over its
//! `max_treasury_share_bps` target, swapped from the treasury's stable
//! holdings. The treasury takes the arrival asset in exchange.
//!
//! Swaps are not filled first-come. A payment that needs one leaves the
//! payee's credit in the payout escrow and joins the epoch's book; when the
//! epoch closes, every request in the book is filled pro-rata: the epoch cap
//! is shared in proportion to the value each request asked for, then each
//! arrival asset's room under its exposure ceiling and each payout asset's
//! treasury holding in proportion to what was asked of them. No request's
//! place in the epoch changes what it gets. What a request is not filled is
//! carried into the next epoch's fill for up to
//! `fees.payout_swap_carry_epochs`, then paid to the payee in the asset it
//! arrived in; a payee that lists the arrival asset is paid the remainder in
//! it at once.
//!
//! A swap pays the lower of the par amount and the amount at the two
//! validator rates, less `fees.payout_swap_spread_bps`, so the treasury
//! never pays out more value than it receives at the rates in force. No
//! swap runs when either asset may not settle (disabled, unpriced or off its
//! peg), past what the treasury holds, past the arrival asset's
//! `max_exposure_bps` of the treasury's whole value, or past
//! `fees.payout_swap_max_units_epoch` of value swapped in an epoch. When the
//! payout cannot be made in any listed asset and the arrival asset is not
//! listed, the payment is refused and says why; nothing is paid out in an
//! asset the payee did not list. TNZO arrivals and TNZO payouts are not
//! swapped.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::funding::{read_json, write_json};
use super::settlement_asset::{Permitted, holdings_tnzo_eq, permitted, tnzo_eq, value_e6};
use super::*;

/// Governed key: spread a payout swap keeps for the treasury, bps.
pub const SPREAD_PARAM: &str = "fees.payout_swap_spread_bps";
/// Genesis value of [`SPREAD_PARAM`].
pub const DEFAULT_SPREAD_BPS: u64 = 15;
/// Greatest value of [`SPREAD_PARAM`].
pub const MAX_SPREAD_BPS: u64 = 100;
/// Governed key: most value swapped for payouts in one epoch, whole units of
/// account.
pub const EPOCH_CAP_PARAM: &str = "fees.payout_swap_max_units_epoch";
/// Genesis value of [`EPOCH_CAP_PARAM`].
pub const DEFAULT_EPOCH_CAP_UNITS: u64 = 100_000;
/// Greatest value of [`EPOCH_CAP_PARAM`].
pub const MAX_EPOCH_CAP_UNITS: u64 = 100_000_000;
/// Most payout assets one payee lists.
pub const MAX_PAYOUT_ASSETS: usize = 8;
/// Governed key: epochs an unfilled payout swap request is carried into
/// later fills before its remainder is paid in the asset it arrived in.
pub const CARRY_PARAM: &str = "fees.payout_swap_carry_epochs";
/// Genesis value of [`CARRY_PARAM`].
pub const DEFAULT_CARRY_EPOCHS: u64 = 24;
/// Greatest value of [`CARRY_PARAM`].
pub const MAX_CARRY_EPOCHS: u64 = 720;
/// Most requests the swap book holds; a payout that would pass it is paid
/// as if no swap were possible.
pub const MAX_BOOK_REQUESTS: usize = 4_096;
/// Topic of the log an epoch's swap fill emits.
pub const PAYOUT_SWAPS_FILLED_TOPIC: &[u8] = b"PayoutSwapsFilled";

const BOOK_KEY: &str = "payout_swap_book";
const ESCROW_DOMAIN: &[u8] = b"tenzro/payout-swap-escrow/v1";

/// The keyless account a queued payout's credit waits in.
pub fn escrow_address() -> Address {
    let digest = Sha256::digest(ESCROW_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// A payout waiting for its epoch's swap fill.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwapRequest {
    /// The payee, hex.
    pub payee: String,
    /// The asset the payment arrived in, hex token id.
    pub arrival: String,
    /// What of the arrival asset waits in the escrow, smallest units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub credit: u128,
    /// The epoch the payment was made in.
    pub epoch: u64,
}

/// The requests waiting for a fill, in the order they were made (which
/// no fill depends on).
pub fn read_book(state: &dyn VmState) -> Vec<SwapRequest> {
    read_json(state, BOOK_KEY).unwrap_or_default()
}

fn pref_key(payee: &[u8]) -> String {
    format!("payout_assets:{}", hex::encode(payee))
}

/// The settlement assets `payee` accepts being paid out in, in its order.
/// Empty: it keeps what arrives.
pub fn read_payout_assets(state: &dyn VmState, payee: &[u8]) -> Vec<[u8; 32]> {
    read_json::<Vec<String>>(state, &pref_key(payee))
        .unwrap_or_default()
        .iter()
        .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
        .collect()
}

/// Sets the payout assets `payee` accepts: at most [`MAX_PAYOUT_ASSETS`]
/// distinct tokens, each with a settlement asset entry. An empty list
/// clears the preference.
pub(super) fn set_payout_assets(
    state: &mut dyn VmState,
    payee: &[u8],
    assets: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if assets.len() > MAX_PAYOUT_ASSETS {
        return Err(VmError::InvalidTransaction(format!(
            "a payee lists at most {MAX_PAYOUT_ASSETS} payout assets"
        )));
    }
    let mut ids: Vec<String> = Vec::with_capacity(assets.len());
    for a in assets {
        let id: [u8; 32] = a
            .strip_prefix("0x")
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "payout asset {a:?} is not 0x and 64 hex digits"
                ))
            })?;
        if super::settlement_asset::read_settlement_asset(state, &id).is_none() {
            return Err(VmError::InvalidTransaction(format!(
                "payout asset {a} is not a settlement asset"
            )));
        }
        let h = hex::encode(id);
        if ids.contains(&h) {
            return Err(VmError::InvalidTransaction(format!(
                "payout asset {a} is listed twice"
            )));
        }
        ids.push(h);
    }
    write_json(state, &pref_key(payee), &ids, changes)?;
    Ok(())
}

fn scale(amount: u128, from_decimals: u8, to_decimals: u8, up: bool) -> u128 {
    use revm::primitives::U256;
    let p = |d: u8| U256::from(10u8).pow(U256::from(d));
    let num = U256::from(amount) * p(to_decimals);
    let den = p(from_decimals);
    let q = if up { num.div_ceil(den) } else { num / den };
    u128::try_from(q).unwrap_or(u128::MAX)
}

/// What a swap of `amount` of `from` pays out in `to`, smallest units: the
/// lower of the par amount (assets on one currency) and the amount at the
/// two validator rates, rounded down, less the spread, rounded up.
pub fn quote_out(state: &dyn VmState, from: &Permitted, to: &Permitted, amount: u128) -> u128 {
    use revm::primitives::U256;
    let (fd, td) = (from.asset.decimals, to.asset.decimals);
    let num =
        U256::from(amount) * U256::from(from.rate_nano_usd) * U256::from(10u8).pow(U256::from(td));
    let den = U256::from(to.rate_nano_usd.max(1)) * U256::from(10u8).pow(U256::from(fd));
    let at_rates = u128::try_from(num / den).unwrap_or(u128::MAX);
    let gross = if from.asset.currency == to.asset.currency {
        at_rates.min(scale(amount, fd, td, false))
    } else {
        at_rates
    };
    let spread = u128::from(network_param(state, SPREAD_PARAM).min(MAX_SPREAD_BPS));
    let cut = U256::from(gross) * U256::from(spread);
    let cut = u128::try_from(cut.div_ceil(U256::from(10_000u32))).unwrap_or(u128::MAX);
    gross.saturating_sub(cut)
}

/// How far the treasury's holding of `token` sits over its share target,
/// bps of the treasury's stable holdings (negative when under).
fn over_target_bps(state: &dyn VmState, token: &[u8; 32], p: &Permitted, total: u128) -> i128 {
    if total == 0 {
        return -i128::from(p.asset.max_treasury_share_bps as u32);
    }
    let held = crate::token_ledger::balance(state, token, derive_treasury_address().as_bytes());
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let eq = tnzo_eq(held, p.rate_nano_usd, p.asset.decimals, tnzo_rate, false);
    let share = eq.saturating_mul(10_000) / total;
    i128::try_from(share).unwrap_or(i128::MAX) - i128::from(p.asset.max_treasury_share_bps as u32)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Swapped {
    epoch: u64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    value_e6: u128,
}

const SWAPPED_KEY: &str = "payout_swapped";

/// The last fill: the epoch it closed and the value it swapped,
/// micro-units.
pub fn read_last_fill(state: &dyn VmState) -> Option<(u64, u128)> {
    read_json::<Swapped>(state, SWAPPED_KEY).map(|s| (s.epoch, s.value_e6))
}

/// Why `to` cannot pay out `credit` of `arrival` now, if it cannot; the
/// amount it pays otherwise.
fn swap_out(
    state: &dyn VmState,
    arrival: &Permitted,
    credit: u128,
    to_token: &[u8; 32],
) -> std::result::Result<u128, String> {
    let to = permitted(state, to_token).map_err(|e| e.to_string())?;
    let out = quote_out(state, arrival, &to, credit);
    let held = crate::token_ledger::balance(state, to_token, derive_treasury_address().as_bytes());
    if out > held {
        return Err(format!(
            "the treasury holds {held} of {}; the payout is {out}",
            to.asset.symbol
        ));
    }
    let arrival_token = arrival
        .asset
        .token_bytes()
        .ok_or_else(|| "the arrival asset names no 32-byte token".to_string())?;
    super::settlement_asset::check_exposure(state, &arrival_token, arrival, credit)
        .map_err(|e| e.to_string())?;
    Ok(out)
}

/// Candidates other than the arrival asset that the payee lists and that
/// may settle now, most over target first, the payee's order breaking ties;
/// only those over target when the payee also takes the arrival asset.
fn candidates(
    state: &dyn VmState,
    arrival_token: &[u8; 32],
    prefs: &[[u8; 32]],
    total: u128,
) -> Vec<([u8; 32], Permitted)> {
    let keep = prefs.contains(arrival_token);
    let mut ranked: Vec<(i128, usize, [u8; 32], Permitted)> = prefs
        .iter()
        .enumerate()
        .filter(|(_, t)| *t != arrival_token)
        .filter_map(|(i, t)| {
            let p = permitted(state, t).ok()?;
            Some((over_target_bps(state, t, &p, total), i, *t, p))
        })
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    ranked
        .into_iter()
        .filter(|r| !keep || r.0 > 0)
        .map(|r| (r.2, r.3))
        .collect()
}

fn mul_div(x: u128, num: u128, den: u128) -> u128 {
    use revm::primitives::U256;
    if den == 0 || num >= den {
        return x;
    }
    u128::try_from(U256::from(x) * U256::from(num) / U256::from(den)).unwrap_or(u128::MAX)
}

/// Smallest units of `p`'s asset worth `eq` TNZO base units at the rates
/// in force, rounded down.
fn units_for_tnzo_eq(state: &dyn VmState, p: &Permitted, eq: u128) -> u128 {
    use revm::primitives::U256;
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let num =
        U256::from(eq) * U256::from(tnzo_rate) * U256::from(10u8).pow(U256::from(p.asset.decimals));
    let den = U256::from(p.rate_nano_usd.max(1)) * U256::from(10u8).pow(U256::from(18u8));
    u128::try_from(num / den).unwrap_or(u128::MAX)
}

/// How much more of `p`'s asset the treasury may take in before it makes up
/// its exposure ceiling of the treasury's whole value. A swap pays out as
/// much value as it takes in, so the whole value is taken as it stands.
fn exposure_room(state: &dyn VmState, token: &[u8; 32], p: &Permitted) -> u128 {
    let treasury = derive_treasury_address();
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let held = crate::token_ledger::balance(state, token, treasury.as_bytes());
    let held_eq = tnzo_eq(held, p.rate_nano_usd, p.asset.decimals, tnzo_rate, true);
    let total = state
        .get_balance(treasury.as_bytes())
        .saturating_add(holdings_tnzo_eq(state, treasury.as_bytes()));
    let ceiling_eq = total.saturating_mul(u128::from(p.asset.max_exposure_bps)) / 10_000;
    units_for_tnzo_eq(state, p, ceiling_eq.saturating_sub(held_eq))
}

struct Planned {
    req: SwapRequest,
    payee: Vec<u8>,
    arrival: [u8; 32],
    keep: bool,
    /// The arrival asset and the payout asset, when a swap can run.
    legs: Option<(Permitted, [u8; 32], Permitted)>,
    fill: u128,
    out: u128,
}

/// Fills every request made in or before the closed `epoch`, pro-rata (see
/// the module header), pays each payee its swapped part and, by the carry
/// rule, its remainder, and logs the fill.
pub(super) fn fill_epoch(
    state: &mut dyn VmState,
    epoch: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let book = read_book(state);
    let (due, mut later): (Vec<SwapRequest>, Vec<SwapRequest>) =
        book.into_iter().partition(|r| r.epoch <= epoch);
    if due.is_empty() {
        return Ok(());
    }
    let treasury = derive_treasury_address();
    let total = holdings_tnzo_eq(state, treasury.as_bytes());
    let mut plans: Vec<Planned> = due
        .into_iter()
        .filter_map(|req| {
            let payee = hex::decode(&req.payee).ok()?;
            let arrival: [u8; 32] = hex::decode(&req.arrival).ok()?.try_into().ok()?;
            let prefs = read_payout_assets(state, &payee);
            let keep = prefs.contains(&arrival);
            let legs = permitted(state, &arrival).ok().and_then(|a| {
                let (t, p) = candidates(state, &arrival, &prefs, total)
                    .into_iter()
                    .next()?;
                Some((a, t, p))
            });
            Some(Planned {
                req,
                payee,
                arrival,
                keep,
                legs,
                fill: 0,
                out: 0,
            })
        })
        .collect();

    // The epoch cap, shared by the value each request asked for.
    let cap = u128::from(network_param(state, EPOCH_CAP_PARAM).min(MAX_EPOCH_CAP_UNITS))
        .saturating_mul(1_000_000);
    let worth = |p: &Planned| {
        p.legs.as_ref().map_or(0, |(a, _, _)| {
            value_e6(p.req.credit, a.rate_nano_usd, a.asset.decimals)
        })
    };
    let requested: u128 = plans.iter().map(worth).fold(0, u128::saturating_add);
    for p in plans.iter_mut() {
        if p.legs.is_some() {
            p.fill = mul_div(p.req.credit, cap, requested);
        }
    }
    // Each arrival asset's room under its exposure ceiling, shared by what
    // was asked of it.
    let mut arrivals: Vec<[u8; 32]> = plans
        .iter()
        .filter(|p| p.legs.is_some())
        .map(|p| p.arrival)
        .collect();
    arrivals.sort();
    arrivals.dedup();
    for a in arrivals {
        let asked: u128 = plans
            .iter()
            .filter(|p| p.arrival == a)
            .map(|p| p.fill)
            .sum();
        let Some(ap) = plans
            .iter()
            .find(|p| p.arrival == a)
            .and_then(|p| p.legs.as_ref().map(|l| l.0.clone()))
        else {
            continue;
        };
        let room = exposure_room(state, &a, &ap);
        for p in plans.iter_mut().filter(|p| p.arrival == a) {
            p.fill = mul_div(p.fill, room, asked);
        }
    }
    // Each payout asset's treasury holding, shared by what was asked of it.
    for p in plans.iter_mut() {
        if let Some((a, _, t)) = &p.legs {
            p.out = quote_out(state, a, t, p.fill);
        }
    }
    let mut targets: Vec<[u8; 32]> = plans
        .iter()
        .filter_map(|p| p.legs.as_ref().map(|l| l.1))
        .collect();
    targets.sort();
    targets.dedup();
    for t in targets {
        let asked: u128 = plans
            .iter()
            .filter(|p| p.legs.as_ref().is_some_and(|l| l.1 == t))
            .map(|p| p.out)
            .sum();
        let held = crate::token_ledger::balance(state, &t, treasury.as_bytes());
        if asked <= held {
            continue;
        }
        for p in plans
            .iter_mut()
            .filter(|p| p.legs.as_ref().is_some_and(|l| l.1 == t))
        {
            p.fill = mul_div(p.fill, held, asked);
            let (a, _, tp) = p.legs.as_ref().expect("a planned swap");
            p.out = quote_out(state, a, tp, p.fill);
        }
    }

    let carry = network_param(state, CARRY_PARAM).clamp(1, MAX_CARRY_EPOCHS);
    let escrow = escrow_address();
    let mut filled = 0u128;
    for p in plans {
        let mut left = p.req.credit;
        if let Some((a, t, _)) = &p.legs {
            let held = crate::token_ledger::balance(state, t, treasury.as_bytes());
            if p.fill > 0 && p.out > 0 && p.out <= held {
                super::payment_settlement::move_asset(
                    state,
                    &p.arrival,
                    escrow.as_bytes(),
                    treasury.as_bytes(),
                    p.fill,
                    now_ms,
                    changes,
                )?;
                super::payment_settlement::move_asset(
                    state,
                    t,
                    treasury.as_bytes(),
                    &p.payee,
                    p.out,
                    now_ms,
                    changes,
                )?;
                super::payment_settlement::apply_split(state, t, &p.payee, p.out, now_ms, changes)?;
                filled = filled.saturating_add(value_e6(p.fill, a.rate_nano_usd, a.asset.decimals));
                left -= p.fill;
            }
        }
        if left == 0 {
            continue;
        }
        if p.keep || epoch.saturating_sub(p.req.epoch).saturating_add(1) >= carry {
            super::payment_settlement::move_asset(
                state,
                &p.arrival,
                escrow.as_bytes(),
                &p.payee,
                left,
                now_ms,
                changes,
            )?;
            super::payment_settlement::apply_split(
                state, &p.arrival, &p.payee, left, now_ms, changes,
            )?;
        } else {
            later.push(SwapRequest {
                credit: left,
                ..p.req
            });
        }
    }
    write_json(state, BOOK_KEY, &later, changes)?;
    write_json(
        state,
        SWAPPED_KEY,
        &Swapped {
            epoch,
            value_e6: filled,
        },
        changes,
    )?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![PAYOUT_SWAPS_FILLED_TOPIC.to_vec()],
        serde_json::to_vec(&serde_json::json!({
            "epoch": epoch,
            "requested_e6": requested.to_string(),
            "cap_e6": cap.to_string(),
            "filled_e6": filled.to_string(),
            "carried": later.len(),
        }))
        .map_err(|e| VmError::Internal(format!("encode swap fill log: {e}")))?,
    ));
    Ok(())
}

/// Pays `payee`'s `credit` of `arrival_token`, already credited to it, out
/// in the asset its preference and the treasury's share targets choose.
/// When a swap is wanted and some listed asset could pay it now, the credit
/// moves to the payout escrow and joins the epoch's book, filled when the
/// epoch closes; the payee then holds nothing of it yet. Returns the asset
/// and amount the payee holds of the payout now.
pub(super) fn pay_out(
    state: &mut dyn VmState,
    arrival_token: &[u8; 32],
    arrival: &Permitted,
    payee: &[u8],
    credit: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<([u8; 32], u128)> {
    let prefs = read_payout_assets(state, payee);
    if prefs.is_empty() || credit == 0 {
        return Ok((*arrival_token, credit));
    }
    let keep = prefs.contains(arrival_token);
    let total = holdings_tnzo_eq(state, derive_treasury_address().as_bytes());
    let mut why = Vec::new();
    let mut book = read_book(state);
    let feasible = book.len() < MAX_BOOK_REQUESTS
        && candidates(state, arrival_token, &prefs, total)
            .iter()
            .any(|(t, _)| match swap_out(state, arrival, credit, t) {
                Ok(_) => true,
                Err(e) => {
                    why.push(e);
                    false
                }
            });
    if feasible {
        super::payment_settlement::move_asset(
            state,
            arrival_token,
            payee,
            escrow_address().as_bytes(),
            credit,
            now_ms,
            changes,
        )?;
        book.push(SwapRequest {
            payee: hex::encode(payee),
            arrival: hex::encode(arrival_token),
            credit,
            epoch: super::economy::read_current_epoch(state),
        });
        write_json(state, BOOK_KEY, &book, changes)?;
        return Ok((*arrival_token, 0));
    }
    if keep {
        return Ok((*arrival_token, credit));
    }
    if book.len() >= MAX_BOOK_REQUESTS {
        why.push(format!(
            "the payout swap book holds its most of {MAX_BOOK_REQUESTS} requests"
        ));
    }
    for t in &prefs {
        if let Err(e) = permitted(state, t) {
            why.push(e.to_string());
        }
    }
    Err(VmError::InvalidTransaction(format!(
        "the payee accepts no payout this payment can make: {}",
        why.join("; ")
    )))
}
