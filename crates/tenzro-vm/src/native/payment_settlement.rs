//! Payer-authorized settlement: HTTP-402 payment authorizations, escrow
//! voucher claims, and the payment records every settlement writes.
//!
//! A payment is authorized by the payer's own signature over a canonical
//! preimage defined in `tenzro_types::payment_authorization`, checked here
//! against the account being debited: the payer's P-256 key must name that
//! account, and the ML-DSA-65 leg is checked against the key the account has
//! enrolled in state, never one the record carries. A delegated agent has no key of its own:
//! it pays through an `AgentAct` held to its terms, and its vouchers are
//! signed by a serving node its terms assign, with that node's hardware key
//! for the agent. The submitting account pays gas and has no other
//! authority, so settlement can be submitted by anyone.
//!
//! Every payment, native, proven on another chain or attested on another
//! rail, leaves one record at `pay:<pay_ref>` binding the request, the
//! payee's quote, the amount and the delivery receipts.

use tenzro_settlement::escrow::{EscrowAccount, EscrowStatus};
use tenzro_types::payment_authorization::{
    EscrowClaim, EscrowVoucher, PaymentAuthorization, PaymentBinding, agent_voucher_digest,
    asset_token_id, escrow_voucher_preimage, pay_ref,
};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    AttestedPayment, MAX_RECEIPTS_PER_PAYMENT, PaymentOp, PaymentRecord, RecordClass,
    payee_split_key, payment_record_key, validate_standing_split,
};
use tenzro_types::split::{FeeParams, SplitRule};

use super::{
    NativeExecutor, SYSTEM_ADDRESS, derive_vault_address, deterministic_now_ms, escrow_storage_key,
};
pub mod netting;
pub mod plan;
pub mod recon;

use crate::error::{Result, VmError};
use crate::gas::GasMeter;
use crate::traits::VmState;
use crate::types::{ExecutionResult, Log, StateChange, VmTransaction};

/// Gas for a voucher claim: a signature check, an escrow record rewrite and
/// a vault-to-payee move per voucher.
pub(super) const GAS_ESCROW_CLAIM_PER_VOUCHER: u64 = 55_000;

/// Gas for a hash-lock claim: a hash, an escrow record rewrite and a
/// vault-to-payee move.
pub(super) const GAS_ESCROW_PREIMAGE_CLAIM: u64 = 50_000;

/// Gas for a stream claim: an escrow record rewrite and a vault-to-payee
/// move.
pub(super) const GAS_ESCROW_STREAM_CLAIM: u64 = 45_000;

/// What a streaming escrow owes its payee at `now_ms` beyond what it has
/// paid: `rate_per_epoch` for every whole epoch elapsed since it was funded,
/// up to its expiry and its amount. `None` for an escrow that is not a
/// stream.
///
/// A stream paying a provider that posted a compute bond is paid by the SLA
/// verdicts validators freeze for each market epoch: an hour judged
/// unavailable is never paid and stays the payer's, so a renter is not
/// harmed by an hour it did not get and has nothing to claim back. An hour
/// not yet judged is paid once judged available, or once its attestation
/// window has closed with no verdict; with `undecided_paid` (the stream is
/// being stopped) it is paid now, so a payer cannot stop a stream to avoid
/// paying for hours it was served.
///
/// Hours already settled into a claim are not read again: the stream's
/// cursor (see [`stream_progress`]) holds how far it was judged and how
/// much of that was withheld.
pub(super) fn stream_due(
    state: &dyn VmState,
    escrow: &EscrowAccount,
    now_ms: i64,
    undecided_paid: bool,
) -> Option<u128> {
    stream_progress(state, escrow, now_ms, undecided_paid).map(|(due, _)| due)
}

/// Where a stream's judging stands: the time up to which every hour has
/// been judged, and the milliseconds of it withheld.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct StreamCursor {
    pub judged_ms: i64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub withheld_ms: u128,
}

pub(super) fn stream_cursor_key(escrow_id: &[u8; 32]) -> String {
    format!("stream_cursor:{}", hex::encode(escrow_id))
}

fn escrow_id_of(escrow: &EscrowAccount) -> Option<[u8; 32]> {
    hex::decode(&escrow.escrow_id).ok()?.try_into().ok()
}

/// [`stream_due`], with the cursor a claim records so its next claim starts
/// where this one stopped.
pub(super) fn stream_progress(
    state: &dyn VmState,
    escrow: &EscrowAccount,
    now_ms: i64,
    undecided_paid: bool,
) -> Option<(u128, StreamCursor)> {
    let tenzro_types::settlement::ReleaseConditions::Stream {
        rate_per_epoch,
        epoch_ms,
    } = escrow.release_conditions
    else {
        return None;
    };
    let created = escrow.created_at.0;
    let mut until = now_ms.min(escrow.expires_at.0);
    let cursor: StreamCursor = escrow_id_of(escrow)
        .and_then(|id| super::funding::read_json(state, &stream_cursor_key(&id)))
        .unwrap_or_default();
    let mut withheld_ms: u128 = cursor.withheld_ms;
    let mut judged = cursor.judged_ms;
    if let Some(did) = sla_provider(state, &escrow.payee) {
        let now_epoch = (now_ms.max(0) / super::MARKET_EPOCH_MS) as u64;
        let lower = created.max(cursor.judged_ms);
        let mut epoch = (lower.max(0) / super::MARKET_EPOCH_MS) as u64;
        while (epoch as i64).saturating_mul(super::MARKET_EPOCH_MS) < until {
            let start = (epoch as i64).saturating_mul(super::MARKET_EPOCH_MS);
            let end = start.saturating_add(super::MARKET_EPOCH_MS);
            match super::read_sla_verdict(state, &did, epoch) {
                Some(v) if v.available => {}
                Some(_) => {
                    withheld_ms += (end.min(until) - start.max(lower)).max(0) as u128;
                }
                None if undecided_paid || epoch + super::MARKET_SUBMIT_WINDOW < now_epoch => {}
                None => {
                    until = start.max(lower);
                    break;
                }
            }
            epoch += 1;
        }
        judged = judged.max(until);
    }
    let elapsed = until.saturating_sub(created).max(0) as u64;
    let epochs = elapsed / epoch_ms.max(1);
    let withheld = rate_per_epoch.saturating_mul(withheld_ms) / u128::from(epoch_ms.max(1));
    let accrued = rate_per_epoch
        .saturating_mul(u128::from(epochs))
        .saturating_sub(withheld)
        .min(escrow.amount);
    Some((
        accrued.saturating_sub(escrow.claimed),
        StreamCursor {
            judged_ms: judged,
            withheld_ms,
        },
    ))
}

/// The compute-bonded provider a stream pays, when its payee posted the
/// bond itself.
fn sla_provider(state: &dyn VmState, payee: &Address) -> Option<String> {
    let did = super::identity_did_of(state, payee.as_bytes())?;
    super::economy::compute_bond(state, &did)
        .filter(|b| b.provider_address.trim_start_matches("0x") == hex::encode(payee.as_bytes()))
        .map(|_| did)
}

/// Longest preimage a hash-lock claim reveals.
const MAX_PREIMAGE_LEN: usize = 64;

use tenzro_types::payment_authorization::MAX_VOUCHERS_PER_CLAIM;

/// Check a payer's authorization of an HTTP-402 settlement.
///
/// The keys must derive `payer`, the signature must cover this chain, this
/// payment id, this payer and payee, the signed ceiling and asset, and what
/// the payment buys (request, quote and USD price), and the settled
/// `amount` must not exceed the ceiling. A payment priced in USD and
/// settled in TNZO converts at the rate in force and must stay within the
/// ceiling.
/// The part of a signed `amount` a declared leg of `margin_bps` takes: the
/// leg is on top of the price, so it is `amount * bps / (10_000 + bps)` and
/// the rest is the payee's price. `None` on overflow.
pub fn declared_leg(amount: u128, margin_bps: u32) -> Option<u128> {
    Some(amount.checked_mul(u128::from(margin_bps))? / (10_000u128 + u128::from(margin_bps)))
}

/// The amount a payer signs for a `price` with a declared leg of
/// `margin_bps` on top: the least amount whose remainder after the leg
/// ([`declared_leg`]) is at least `price`. `None` on overflow.
pub fn amount_with_leg(price: u128, margin_bps: u32) -> Option<u128> {
    let total = price.checked_mul(10_000u128 + u128::from(margin_bps))?;
    Some(total.div_ceil(10_000))
}

/// The parts of a signed `amount` that declared legs of `bps` each take,
/// all on top of one price: leg `i` is `amount * bps[i] / (10_000 + sum)`,
/// rounded down, and the rest is the payee's price. With one leg it is
/// [`declared_leg`]. `None` on overflow.
pub fn declared_legs(amount: u128, bps: &[u32]) -> Option<Vec<u128>> {
    let total = bps
        .iter()
        .try_fold(0u128, |a, b| a.checked_add(u128::from(*b)))?;
    let den = 10_000u128.checked_add(total)?;
    bps.iter()
        .map(|b| Some(amount.checked_mul(u128::from(*b))? / den))
        .collect()
}

/// Governed key: most reseller legs one payment carries.
pub const MAX_RESELLER_LEGS_PARAM: &str = "payments.max_reseller_legs";
/// Genesis value of [`MAX_RESELLER_LEGS_PARAM`].
pub const DEFAULT_MAX_RESELLER_LEGS: u64 = 4;
/// Greatest value of [`MAX_RESELLER_LEGS_PARAM`].
pub const MAX_MAX_RESELLER_LEGS: u64 = 16;

pub fn verify_payment_authorization(
    state: &dyn VmState,
    chain_id: u64,
    payment_id: &str,
    payer: &Address,
    payee: &Address,
    amount: u128,
    auth: &PaymentAuthorization,
    now_ms: u64,
) -> Result<()> {
    asset_token_id(&auth.asset).map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
    let (key, rp_id) =
        crate::keystore::account_signing_key(state, &auth.public_key, payer.as_bytes(), now_ms)
            .map_err(|e| {
                VmError::InvalidTransaction(format!("PayerSettle authorization key: {e}"))
            })?;
    if amount > auth.max_amount {
        return Err(VmError::InvalidTransaction(format!(
            "PayerSettle amount {} exceeds the payer's authorized ceiling {}",
            amount, auth.max_amount
        )));
    }
    let message =
        tenzro_types::payment_authorization::payment_authorization_preimage_with_resellers(
            chain_id,
            payment_id,
            payer,
            payee,
            auth.max_amount,
            &auth.asset,
            &auth.binding,
            &auth.resellers,
        );
    crate::keystore::verify_for_relying_party(
        rp_id.as_deref(),
        &key,
        tenzro_crypto::composite::SignatureContext::PaymentAuthorization,
        &message,
        &auth.signature,
        tenzro_crypto::composite::PqPolicy::Required,
    )
    .map(|_| ())
    .map_err(|e| VmError::InvalidTransaction(format!("signature does not verify: {e}")))
}

/// TNZO base units worth `usd_e6` USD micro-units at the rate in force.
pub fn usd_e6_to_wei(state: &dyn VmState, usd_e6: u64) -> u128 {
    super::economy::usd_to_wei(state, u128::from(usd_e6).saturating_mul(1_000_000_000_000))
}

/// The share of `usd_e6` that `part` of `whole` carries, rounded up so a
/// non-zero share is never free.
fn usd_share(usd_e6: u64, part: u128, whole: u128) -> u64 {
    if whole == 0 || part >= whole {
        return usd_e6;
    }
    let share = u128::from(usd_e6).saturating_mul(part).div_ceil(whole);
    u64::try_from(share).unwrap_or(u64::MAX)
}

/// The token an asset string names: TNZO, or a token the ledger holds.
pub(super) fn asset_token(state: &dyn VmState, asset: &str) -> Result<[u8; 32]> {
    match asset_token_id(asset).map_err(|e| VmError::InvalidTransaction(e.to_string()))? {
        None => Ok(crate::token_ledger::tnzo_id()),
        Some(id) if crate::token_ledger::read_token(state, &id).is_some() => Ok(id),
        Some(_) => Err(VmError::InvalidTransaction(format!(
            "{asset} is not a token on this ledger"
        ))),
    }
}

fn tnzo_change(account: &[u8], old: u128, new: u128) -> StateChange {
    StateChange::new(
        account.to_vec(),
        b"balance".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some(new.to_le_bytes().to_vec()),
    )
}

/// Move `amount` of `token` from `from` to `to`; TNZO moves in the native
/// balance map, any other token through the token ledger with its issuer's
/// policy applied.
pub(super) fn move_asset(
    state: &mut dyn VmState,
    token: &[u8; 32],
    from: &[u8],
    to: &[u8],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    if *token == crate::token_ledger::tnzo_id() {
        let from_old = state.get_balance(from);
        if from_old < amount {
            return Err(VmError::InsufficientBalance {
                required: amount,
                available: from_old,
            });
        }
        state.set_balance(from, from_old - amount);
        changes.push(tnzo_change(from, from_old, from_old - amount));
        let to_old = state.get_balance(to);
        let to_new = to_old
            .checked_add(amount)
            .ok_or_else(|| VmError::Internal("balance overflow".to_string()))?;
        state.set_balance(to, to_new);
        changes.push(tnzo_change(to, to_old, to_new));
        return Ok(());
    }
    let moved = crate::token_ledger::transfer(state, token, from, to, amount, now_ms)?.ok_or_else(
        || VmError::InvalidTransaction(format!("the sender holds less than {amount} of the token")),
    )?;
    changes.extend(moved);
    Ok(())
}

/// What one settlement moved.
pub(super) struct Settled {
    /// What the network took out of the amount, in the payment's asset:
    /// the settlement fee and the treasury leg.
    pub fee: u128,
    /// TNZO burned out of the fee.
    pub burned: u128,
    /// The treasury leg of the payee's work class, inside `fee`.
    pub treasury_leg: u128,
    /// `fee`'s worth in TNZO base units, rounded down.
    pub fee_tnzo_eq: u128,
    /// TNZO base units booked as burned for a fee collected in another
    /// asset, rounded up; zero for TNZO.
    pub burn_eq: u128,
    /// What the payment was worth, micro-units of account.
    pub value_e6: u128,
    /// The epoch whose median set the TNZO rate used.
    pub rate_epoch: Option<u64>,
    /// The token the payee was paid out in, when a payout swap paid it in
    /// another asset than the payment's.
    pub payout_token: Option<[u8; 32]>,
    /// What the treasury kept of a fee collected in kind, in the token.
    pub treasury_kept: u128,
}

/// Pay `amount` of `token` from `from` to `payee` and charge the settlement
/// fee out of the amount, in the same asset. For TNZO the burn share is
/// burned. For any other token the token must be a permitted settlement
/// asset on its peg; the payment is valued at its validator rate, never
/// below the signed `usd_e6`, the fee is charged on that value in the
/// token, the treasury, insurance and burn shares are paid to the treasury
/// and the insurance pool in the token, and the burn share's TNZO
/// equivalent is booked for the epoch. The payee's TNZO is never touched.
/// `payer` is who the value is attributed to (the escrow's payer when
/// `from` is its vault); `earning` is what the settlement earns beyond it.
#[allow(clippy::too_many_arguments)]
pub(super) fn settle_asset(
    state: &mut dyn VmState,
    token: &[u8; 32],
    from: &[u8],
    payer: &[u8],
    payee: &[u8],
    amount: u128,
    usd_e6: u64,
    now_ms: i64,
    earning: &super::economy::Earning,
    changes: &mut Vec<StateChange>,
) -> Result<Settled> {
    if *token == crate::token_ledger::tnzo_id() {
        let from_old = state.get_balance(from);
        if from_old < amount {
            return Err(VmError::InsufficientBalance {
                required: amount,
                available: from_old,
            });
        }
        state.set_balance(from, from_old - amount);
        changes.push(tnzo_change(from, from_old, from_old - amount));
        let payout = super::economy::settle_payout(state, payer, payee, amount, earning, changes)?;
        let old = state.get_balance(payee);
        let new = old
            .checked_add(payout.credit)
            .ok_or_else(|| VmError::Internal("payee balance overflow".to_string()))?;
        state.set_balance(payee, new);
        changes.push(tnzo_change(payee, old, new));
        apply_split(state, token, payee, payout.credit, now_ms, changes)?;
        let rate = super::economy::read_fee_rate(state);
        let fee = amount - payout.credit;
        return Ok(Settled {
            fee,
            burned: payout.burned,
            treasury_leg: payout.treasury_leg,
            fee_tnzo_eq: fee,
            burn_eq: 0,
            value_e6: super::settlement_asset::tnzo_value_e6(amount, rate.rate_nano_usd)
                .max(u128::from(usd_e6)),
            rate_epoch: rate.epoch,
            payout_token: None,
            treasury_kept: 0,
        });
    }
    settle_in_kind(
        state, token, from, payer, payee, amount, usd_e6, now_ms, earning, changes,
    )
}

/// [`settle_asset`] for a token other than TNZO.
#[allow(clippy::too_many_arguments)]
fn settle_in_kind(
    state: &mut dyn VmState,
    token: &[u8; 32],
    from: &[u8],
    payer: &[u8],
    payee: &[u8],
    amount: u128,
    usd_e6: u64,
    now_ms: i64,
    earning: &super::economy::Earning,
    changes: &mut Vec<StateChange>,
) -> Result<Settled> {
    use super::settlement_asset::{tnzo_eq, units_for_e6, value_e6};
    let permitted = super::settlement_asset::permitted(state, token)?;
    let rate = permitted.rate_nano_usd;
    let decimals = permitted.asset.decimals;
    let signed = u128::from(usd_e6);
    let worth = value_e6(amount, rate, decimals).max(signed);
    // The fee base is the amount, raised to what the signed price is worth
    // in the token when that is more: a low signed price never lowers it.
    let gross = amount.max(units_for_e6(signed, rate, decimals));
    let params = if earning.network_share_paid {
        super::economy::NO_FEE
    } else {
        in_kind_fee_params(state, &permitted)
    };
    let alloc = tenzro_types::split::fee_allocation(gross, &params);
    let leg = earning.provider.map_or(0, |class| {
        tenzro_types::split::bps_of(
            amount.saturating_sub(alloc.fee),
            u128::from(super::economy::treasury_leg_bps(state, class)),
        )
    });
    let outside = alloc.fee.saturating_add(leg);
    if outside > amount {
        return Err(VmError::InvalidTransaction(format!(
            "the settlement fee {} and treasury leg {leg} exceed the {amount} paid",
            alloc.fee
        )));
    }
    super::settlement_asset::admit_inflow(state, token, &permitted, worth, changes)?;
    let credit = amount - outside;
    move_asset(state, token, from, payee, credit, now_ms, changes)?;
    let chain_rate = super::economy::read_fee_rate(state);
    let eq = |x: u128, up: bool| tnzo_eq(x, rate, decimals, chain_rate.rate_nano_usd, up);
    let (burn_eq, treasury_kept) = collect_in_kind(
        state, token, &permitted, from, payer, payee, amount, &alloc, leg, earning, now_ms, changes,
    )?;
    let (paid_in, paid) =
        super::payout_swap::pay_out(state, token, &permitted, payee, credit, now_ms, changes)?;
    if paid > 0 {
        apply_split(state, &paid_in, payee, paid, now_ms, changes)?;
    }
    Ok(Settled {
        payout_token: (paid_in != *token).then_some(paid_in),
        treasury_kept,
        fee: outside,
        burned: 0,
        treasury_leg: leg,
        fee_tnzo_eq: eq(outside, false),
        burn_eq,
        value_e6: worth,
        rate_epoch: chain_rate.epoch,
    })
}

/// The settlement fee parameters for a fee collected in `permitted`'s
/// asset: the governed rate and shares, with the least fee converted from
/// micro-units of account to the asset at its rate, rounded up.
pub(super) fn in_kind_fee_params(
    state: &dyn VmState,
    permitted: &super::settlement_asset::Permitted,
) -> tenzro_types::split::FeeParams {
    let mut params = super::economy::fee_params(state);
    params.min_fee = super::settlement_asset::units_for_e6(
        u128::from(super::network_param(
            state,
            super::economy::MIN_SETTLEMENT_FEE_PARAM,
        )),
        permitted.rate_nano_usd,
        permitted.asset.decimals,
    );
    params
}

/// Pays a settlement fee collected in `token` from `from`: the treasury
/// and insurance shares and the treasury leg in the token, the burn share
/// to the treasury's stable holdings, and records the settlement of
/// `amount` in the epoch's activity at its TNZO equivalent. Returns the
/// burn share's TNZO equivalent, rounded up, which is booked for the epoch,
/// and what the treasury kept of the fee in the token.
#[allow(clippy::too_many_arguments)]
pub(super) fn collect_in_kind(
    state: &mut dyn VmState,
    token: &[u8; 32],
    permitted: &super::settlement_asset::Permitted,
    from: &[u8],
    payer: &[u8],
    payee: &[u8],
    amount: u128,
    alloc: &tenzro_types::split::FeeAllocation,
    leg: u128,
    earning: &super::economy::Earning,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<(u128, u128)> {
    let chain_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let eq = |x: u128, up: bool| {
        super::settlement_asset::tnzo_eq(
            x,
            permitted.rate_nano_usd,
            permitted.asset.decimals,
            chain_rate,
            up,
        )
    };
    let burn_eq = eq(alloc.burn, true);
    let fee_eq = eq(alloc.fee, false);
    let alloc_eq = tenzro_types::split::FeeAllocation {
        fee: fee_eq,
        burn: burn_eq.min(fee_eq),
        treasury: eq(alloc.treasury, false),
        insurance: eq(alloc.insurance, false),
    };
    let kept = super::economy::record_fee_in(
        state,
        payer,
        payee,
        eq(amount, false),
        &alloc_eq,
        eq(leg, false),
        earning,
        super::economy::Collect::InKind(super::economy::InKind {
            token,
            from,
            alloc,
            leg,
            burn_eq,
            now_ms,
        }),
        changes,
    )?;
    Ok((burn_eq, kept))
}

/// The receipt fields of a payment settled on the ledger in `asset`.
fn native_receipt(asset: &str, settled: &Settled) -> tenzro_types::settlement::SettledReceipt {
    tenzro_types::settlement::SettledReceipt {
        fee_asset: asset.to_string(),
        fee_tnzo_eq: settled.fee_tnzo_eq,
        burn_eq: settled.burn_eq,
        rate_epoch: settled.rate_epoch,
        unit: super::settlement_asset::unit_of_account(),
        value_units: settled.value_e6,
        payout_asset: settled
            .payout_token
            .map_or_else(|| asset.to_string(), |t| format!("0x{}", hex::encode(t))),
        legs: Vec::new(),
    }
}

/// The receipt fields of a payment made off the ledger (proven or
/// attested): no fee on Tenzro, valued at its signed USD price, its one leg
/// the payee's.
fn external_receipt(
    state: &dyn VmState,
    asset: &str,
    usd_e6: u64,
    payee: &Address,
    amount: u128,
) -> tenzro_types::settlement::SettledReceipt {
    tenzro_types::settlement::SettledReceipt {
        fee_asset: asset.to_string(),
        fee_tnzo_eq: 0,
        burn_eq: 0,
        rate_epoch: super::economy::read_fee_rate(state).epoch,
        unit: super::settlement_asset::unit_of_account(),
        value_units: u128::from(usd_e6),
        payout_asset: asset.to_string(),
        legs: vec![tenzro_types::settlement::ReceiptLeg {
            role: "operator".into(),
            account: hex::encode(payee.as_bytes()),
            amount,
            fee: 0,
            commission_bps: None,
        }],
    }
}

/// The standing split rule `payee` set, if any.
pub fn read_split(state: &dyn VmState, payee: &[u8]) -> Option<SplitRule> {
    let payee = <[u8; 32]>::try_from(payee).ok()?;
    state
        .get_storage(
            &SYSTEM_ADDRESS,
            payee_split_key(&Address::new(payee)).as_bytes(),
        )
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
}

/// The fee was charged once on the payment; the standing rule divides what
/// the payee was credited.
const CHARGED: FeeParams = FeeParams {
    fee_bps: 0,
    min_fee: 0,
    burn_bps: 0,
    insurance_bps: 0,
};

/// Divide `credited` with `payee`'s standing split rule, passing every
/// other recipient its line in the same asset and execution.
pub(super) fn apply_split(
    state: &mut dyn VmState,
    token: &[u8; 32],
    payee: &[u8],
    credited: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let account = <[u8; 32]>::try_from(payee)
        .map(Address::new)
        .map_err(|_| VmError::InvalidTransaction("a payee is a 32-byte account".to_string()))?;
    let Some(rule) = read_split(state, payee) else {
        return Ok(());
    };
    let to = plan::recipients(state, &rule, &account)?;
    let allocation = tenzro_types::split::apply(credited, &rule, &CHARGED, 0)
        .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
    for (recipient, credit) in to.iter().zip(&allocation.credits) {
        if *credit > 0 && recipient.as_bytes() != payee {
            move_asset(
                state,
                token,
                payee,
                recipient.as_bytes(),
                *credit,
                now_ms,
                changes,
            )?;
        }
    }
    Ok(())
}

/// Pay `payout` of an escrow's asset from its vault to `to` (its payee, or
/// one leg of a split), with the settlement fee charged as
/// [`settle_asset`] does on the payout's share of the escrow's USD price.
pub(super) fn pay_from_vault(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    escrow: &EscrowAccount,
    to: &[u8],
    payout: u128,
    now_ms: i64,
    earning: &super::economy::Earning,
    changes: &mut Vec<StateChange>,
) -> Result<Settled> {
    let token = asset_token(state, escrow.asset_id.as_str())?;
    let vault = derive_vault_address(escrow_id).as_bytes().to_vec();
    settle_asset(
        state,
        &token,
        &vault,
        escrow.payer.as_bytes(),
        to,
        payout,
        usd_share(escrow.usd_e6, payout, escrow.amount),
        now_ms,
        earning,
        changes,
    )
}

/// What a payment out of an escrow to `payee` earns: provider work from the
/// payee's bond or stake (a compute lease for a stream), the paying agent
/// when an agent's wallet funded it, and the call chain a voucher names.
pub(super) fn escrow_earning(
    state: &dyn VmState,
    payee: &[u8],
    stream: bool,
    voucher: Option<&EscrowVoucher>,
) -> super::economy::Earning {
    super::economy::Earning {
        provider: super::rewards::provider_class(state, payee, stream),
        payer_agent: voucher.and_then(|v| v.agent.as_ref().map(|a| a.agent_did.clone())),
        attribution: voucher.and_then(|v| v.attribution.clone()),
        network_share_paid: false,
    }
}

/// Storage key of the hash-locked escrow `payer` funded to the network
/// treasury under `lock`: the network's share of a sealed delivery.
fn network_share_lock_key(payer: &Address, lock: &[u8; 32]) -> String {
    format!(
        "network_share_lock:{}:{}",
        hex::encode(payer.as_bytes()),
        hex::encode(lock)
    )
}

/// Note a new hash-locked escrow to the network treasury, so the payout of
/// the seller's escrow under the same lock knows the network was paid its
/// share.
pub(super) fn note_network_share_lock(
    state: &mut dyn VmState,
    escrow_id: &[u8; 32],
    escrow: &EscrowAccount,
    changes: &mut Vec<StateChange>,
) {
    let tenzro_types::settlement::ReleaseConditions::HashLock { hash } = &escrow.release_conditions
    else {
        return;
    };
    if escrow.payee != tenzro_types::network_treasury_address() {
        return;
    }
    let key = network_share_lock_key(&escrow.payer, hash);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), escrow_id.to_vec());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(escrow_id.to_vec()),
    ));
}

/// Whether the payout of hash-locked `escrow` under `lock` already paid the
/// network: its payer locked an escrow of the same asset to the network
/// treasury under the same lock, still funded or paid out, holding at least
/// the governed HTTP-402 network share of both escrows together. A network
/// escrow exempts one payout; the note of it is spent here.
fn spend_network_share(
    state: &mut dyn VmState,
    escrow: &EscrowAccount,
    lock: &[u8; 32],
    changes: &mut Vec<StateChange>,
) -> bool {
    let treasury = tenzro_types::network_treasury_address();
    if escrow.payee == treasury {
        return false;
    }
    let key = network_share_lock_key(&escrow.payer, lock);
    let Some(noted) = state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .filter(|b| b.len() == 32)
    else {
        return false;
    };
    let Some(network) = state
        .get_storage(
            &SYSTEM_ADDRESS,
            escrow_storage_key(&hex::encode(&noted)).as_bytes(),
        )
        .and_then(|b| serde_json::from_slice::<EscrowAccount>(&b).ok())
    else {
        return false;
    };
    let share_bps = super::network_param(state, super::economy::HTTP402_NETWORK_SHARE_PARAM);
    let price = escrow.amount.saturating_add(network.amount);
    let share = price.saturating_mul(u128::from(share_bps.min(10_000))) / 10_000;
    let same_lock = matches!(
        &network.release_conditions,
        tenzro_types::settlement::ReleaseConditions::HashLock { hash } if hash == lock
    );
    let paid = network.payer == escrow.payer
        && network.payee == treasury
        && network.asset_id == escrow.asset_id
        && same_lock
        && matches!(
            network.status,
            EscrowStatus::Funded | EscrowStatus::Released
        )
        && share > 0
        && network.amount >= share;
    if paid {
        state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), Vec::new());
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            key.into_bytes(),
            Some(noted),
            None,
        ));
    }
    paid
}

/// The record at `pay_ref`.
pub fn read_payment(state: &dyn VmState, pay_ref: &[u8; 32]) -> Option<PaymentRecord> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, payment_record_key(pay_ref).as_bytes())?;
    serde_json::from_slice(&blob).ok()
}

fn payment_id_key(payment_id: &str) -> String {
    format!("pay_id:{payment_id}")
}

/// The record a payment id settled, when one did. A payment id is settled
/// at most once on this chain.
pub fn read_payment_by_id(state: &dyn VmState, payment_id: &str) -> Option<PaymentRecord> {
    let blob = state.get_storage(&SYSTEM_ADDRESS, payment_id_key(payment_id).as_bytes())?;
    let pay_ref: [u8; 32] = hex::decode(blob).ok()?.try_into().ok()?;
    read_payment(state, &pay_ref)
}

/// Record a native payment of `amount` from `payer` to `payee` under
/// `payment_id` without moving any balance.
#[cfg(test)]
pub(crate) fn record_settled(
    state: &mut dyn VmState,
    payment_id: &str,
    payer: &[u8],
    payee: [u8; 32],
    amount: u128,
) {
    let binding = PaymentBinding {
        request_digest: [1; 32],
        ..Default::default()
    };
    let payee = Address::new(payee);
    let mut changes = Vec::new();
    let reference = claim_reference(
        state,
        1,
        &payee,
        &binding,
        payment_id,
        Origin::Native,
        &mut changes,
    )
    .unwrap();
    let record = PaymentRecord {
        pay_ref: hex::encode(reference),
        class: RecordClass::Native,
        payer: hex::encode(payer),
        payee,
        asset: "TNZO".into(),
        amount,
        fee: 0,
        settled: Default::default(),
        binding,
        nonce: payment_id.into(),
        agent_did: None,
        source: None,
        attestor: None,
        receipts: Vec::new(),
        refunded: 0,
        recorded_at_ms: 0,
    };
    write_record(state, &record, &mut changes).unwrap();
}

/// Topic of the log a payee's payout asset change emits; data is the payee.
pub const PAYOUT_ASSETS_SET_TOPIC: &[u8] = b"PayoutAssetsSet";

/// Topic of the log a payee's split change emits; data is the payee.
pub const PAYEE_SPLIT_SET_TOPIC: &[u8] = b"PayeeSplitSet";

/// Topic of the log a recorded payment emits; data is `pay_ref(32) ||
/// class(1)`.
pub const PAYMENT_RECORDED_TOPIC: &[u8] = b"PaymentRecorded";

fn write_record(
    state: &mut dyn VmState,
    record: &PaymentRecord,
    changes: &mut Vec<StateChange>,
) -> Result<Log> {
    let pay_ref: [u8; 32] = hex::decode(&record.pay_ref)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| VmError::Internal("a payment reference is 32 bytes".to_string()))?;
    let key = payment_record_key(&pay_ref);
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let blob = serde_json::to_vec(record)
        .map_err(|e| VmError::Internal(format!("encode payment record: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        old,
        Some(blob),
    ));
    let class = match record.class {
        RecordClass::Native => 0u8,
        RecordClass::Proven => 1,
        RecordClass::Attested => 2,
    };
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![PAYMENT_RECORDED_TOPIC.to_vec()],
        [pay_ref.as_slice(), &[class]].concat(),
    ))
}

/// Where a recorded payment was made, which namespaces its nonce: a native
/// payment's id is unique on this chain, while a nonce from another chain
/// or rail is unique only under its source and attestor, so nobody can
/// claim a native payment's reference by stating a payment elsewhere.
enum Origin<'a> {
    Native,
    Proven(&'a str),
    Attested(&'a [u8]),
}

/// Open a new record for `payee`, `binding` and `nonce`: refuse a
/// reference already recorded and, for a native payment, an id already
/// settled, and index the id.
fn claim_reference(
    state: &mut dyn VmState,
    chain_id: u64,
    payee: &Address,
    binding: &PaymentBinding,
    nonce: &str,
    origin: Origin<'_>,
    changes: &mut Vec<StateChange>,
) -> Result<[u8; 32]> {
    if nonce.is_empty() || nonce.len() > 128 {
        return Err(VmError::InvalidTransaction(
            "a payment id is 1 to 128 bytes".to_string(),
        ));
    }
    if binding.request_digest == [0; 32] {
        return Err(VmError::InvalidTransaction(
            "a payment names the request it pays for".to_string(),
        ));
    }
    let scoped = match origin {
        Origin::Native => nonce.to_string(),
        Origin::Proven(chain) => format!("proven:{chain}:{nonce}"),
        Origin::Attested(attestor) => format!("attested:{}:{nonce}", hex::encode(attestor)),
    };
    let reference = pay_ref(chain_id, payee, binding, &scoped);
    if read_payment(state, &reference).is_some() {
        return Err(VmError::InvalidTransaction(format!(
            "payment {nonce} is already recorded"
        )));
    }
    if matches!(origin, Origin::Native) {
        let id_key = payment_id_key(nonce);
        if state
            .get_storage(&SYSTEM_ADDRESS, id_key.as_bytes())
            .is_some()
        {
            return Err(VmError::InvalidTransaction(format!(
                "payment {nonce} is already settled"
            )));
        }
        let value = hex::encode(reference).into_bytes();
        state.set_storage(&SYSTEM_ADDRESS, id_key.as_bytes(), value.clone());
        changes.push(StateChange::new(
            SYSTEM_ADDRESS.to_vec(),
            id_key.into_bytes(),
            None,
            Some(value),
        ));
    }
    Ok(reference)
}

/// A payment settled on the Tenzro Ledger.
pub(super) struct NativePayment<'a> {
    /// The account debited.
    pub payer: &'a Address,
    /// The account paid.
    pub payee: &'a Address,
    /// `TNZO` or a token id.
    pub asset: &'a str,
    /// Amount, in the asset's smallest unit, margin included.
    pub amount: u128,
    /// What it pays for.
    pub binding: PaymentBinding,
    /// The payment id.
    pub nonce: &'a str,
    /// The delegated agent paying, when one is.
    pub agent_did: Option<&'a str>,
    /// The account that submitted the payment and fronted its gas, when it
    /// is not the payer.
    pub relayer: Option<Relayer<'a>>,
    /// The reseller commissions the payer signed, each its own leg on top of
    /// the payee's price.
    pub resellers: &'a [tenzro_types::payment_authorization::ResellerLeg],
}

/// An account that submitted a payment for its payer and paid its gas.
pub(super) struct Relayer<'a> {
    /// The account.
    pub account: &'a [u8],
    /// The gas it was charged, TNZO base units.
    pub gas_wei: u128,
}

/// Governed key: most a relayer is reimbursed of a payment's gas, in bps of
/// what the treasury kept of the payment's fee in kind.
pub const RELAY_REIMBURSE_PARAM: &str = "fees.relay_reimburse_max_bps";
/// Genesis value of [`RELAY_REIMBURSE_PARAM`]: all of the treasury share.
pub const DEFAULT_RELAY_REIMBURSE_BPS: u64 = 10_000;

/// What [`settle_native`] did.
pub(super) struct NativeOutcome {
    /// The record written.
    pub record: PaymentRecord,
    /// The developer margin paid to the app wallet.
    pub margin: u128,
    /// TNZO burned.
    pub burned: u128,
    /// The treasury leg paid beside the settlement fee.
    pub treasury_leg: u128,
    /// What the relayer was reimbursed of its gas, in the payment's token.
    /// Only the settlement tests read it.
    #[cfg(test)]
    pub reimbursed: u128,
    /// The record's log.
    pub log: Log,
}

/// Settle `p` and write its record: the developer margin the payer signed
/// in the binding goes to the app wallet it signed, the rest to the payee
/// less the settlement fee. A USD-priced TNZO
/// payment must also stay within what its USD price buys at the rate in
/// force, so a payee cannot settle more TNZO than the quote was worth.
pub(super) fn settle_native(
    state: &mut dyn VmState,
    chain_id: u64,
    now_ms: i64,
    p: &NativePayment<'_>,
    changes: &mut Vec<StateChange>,
) -> Result<NativeOutcome> {
    if p.amount == 0 {
        return Err(VmError::InvalidTransaction(
            "a payment moves a non-zero amount".to_string(),
        ));
    }
    if p.payer == p.payee {
        return Err(VmError::InvalidTransaction(
            "payer and payee must differ".to_string(),
        ));
    }
    let token = asset_token(state, p.asset)?;
    let tnzo = token == crate::token_ledger::tnzo_id();
    if tnzo && p.binding.usd_e6 > 0 {
        let worth = usd_e6_to_wei(state, p.binding.usd_e6);
        if p.amount > worth {
            return Err(VmError::InvalidTransaction(format!(
                "{} TNZO exceeds the {} the USD price buys at the rate in force",
                p.amount, worth
            )));
        }
    }
    check_resellers(state, p)?;
    // The signed margin and every reseller commission are carved out of the
    // amount, each on top of the payee's price; the margin within its cap.
    let margin_bps = match &p.binding.app_margin {
        Some(m) => {
            let cap = super::network_param(state, super::economy::MAX_DEVELOPER_MARGIN_PARAM);
            if u64::from(m.margin_bps) > cap {
                return Err(VmError::InvalidTransaction(format!(
                    "the developer margin {} bps exceeds the cap {}",
                    m.margin_bps, cap
                )));
            }
            m.margin_bps
        }
        None => 0,
    };
    let mut bps = vec![margin_bps];
    bps.extend(p.resellers.iter().map(|r| r.commission_bps));
    let parts = declared_legs(p.amount, &bps)
        .ok_or_else(|| VmError::Internal("leg overflow".to_string()))?;
    let margin = parts[0];
    let commissions = &parts[1..];
    let reference = claim_reference(
        state,
        chain_id,
        p.payee,
        &p.binding,
        p.nonce,
        Origin::Native,
        changes,
    )?;
    if let Some(m) = &p.binding.app_margin {
        move_asset(
            state,
            &token,
            p.payer.as_bytes(),
            m.app_wallet.as_bytes(),
            margin,
            now_ms,
            changes,
        )?;
    }
    let network_cost = p.amount - margin - commissions.iter().sum::<u128>();
    // Each reseller leg settles as its own payment of its commission, paying
    // the settlement fee at the governed rate and earning no reward weight.
    let mut legs = Vec::with_capacity(p.resellers.len() + 2);
    let mut resold = Vec::with_capacity(p.resellers.len());
    for (r, amount) in p.resellers.iter().zip(commissions) {
        let leg = settle_asset(
            state,
            &token,
            p.payer.as_bytes(),
            p.payer.as_bytes(),
            r.reseller.as_bytes(),
            *amount,
            usd_share(p.binding.usd_e6, *amount, p.amount),
            now_ms,
            &super::economy::Earning {
                payer_agent: p.agent_did.map(str::to_string),
                ..Default::default()
            },
            changes,
        )?;
        resold.push(tenzro_types::settlement::ReceiptLeg {
            role: "reseller".into(),
            account: hex::encode(r.reseller.as_bytes()),
            amount: *amount,
            fee: leg.fee,
            commission_bps: Some(r.commission_bps),
        });
        legs.push(leg);
    }
    let earning = super::economy::Earning {
        provider: super::rewards::provider_class(&*state, p.payee.as_bytes(), false),
        payer_agent: p.agent_did.map(str::to_string),
        attribution: None,
        network_share_paid: false,
    };
    let operator = settle_asset(
        state,
        &token,
        p.payer.as_bytes(),
        p.payer.as_bytes(),
        p.payee.as_bytes(),
        network_cost,
        usd_share(p.binding.usd_e6, network_cost, p.amount),
        now_ms,
        &earning,
        changes,
    )?;
    let mut receipt_legs = vec![tenzro_types::settlement::ReceiptLeg {
        role: "operator".into(),
        account: hex::encode(p.payee.as_bytes()),
        amount: network_cost,
        fee: operator.fee,
        commission_bps: None,
    }];
    receipt_legs.extend(resold);
    if let Some(m) = &p.binding.app_margin {
        receipt_legs.push(tenzro_types::settlement::ReceiptLeg {
            role: "platform".into(),
            account: hex::encode(m.app_wallet.as_bytes()),
            amount: margin,
            fee: 0,
            commission_bps: None,
        });
    }
    let settled = legs.iter().fold(operator, |mut total, leg| {
        total.fee += leg.fee;
        total.burned += leg.burned;
        total.fee_tnzo_eq += leg.fee_tnzo_eq;
        total.burn_eq += leg.burn_eq;
        total.value_e6 += leg.value_e6;
        total.treasury_kept += leg.treasury_kept;
        total
    });
    super::economy::count_settlement(state, 1, changes)?;
    // The reimbursement is paid either way; only the settlement tests read
    // the amount back.
    #[cfg_attr(not(test), allow(unused_variables))]
    let reimbursed = match &p.relayer {
        Some(r) if !tnzo && r.account != p.payer.as_bytes() => {
            reimburse_relayer(state, &token, r, settled.treasury_kept, now_ms, changes)?
        }
        _ => 0,
    };
    let record = PaymentRecord {
        pay_ref: hex::encode(reference),
        class: RecordClass::Native,
        payer: hex::encode(p.payer.as_bytes()),
        payee: *p.payee,
        asset: p.asset.to_string(),
        amount: p.amount,
        fee: settled.fee,
        settled: tenzro_types::settlement::SettledReceipt {
            legs: receipt_legs,
            ..native_receipt(p.asset, &settled)
        },
        binding: p.binding,
        nonce: p.nonce.to_string(),
        agent_did: p.agent_did.map(str::to_string),
        source: None,
        attestor: None,
        receipts: Vec::new(),
        refunded: 0,
        recorded_at_ms: now_ms,
    };
    let log = write_record(state, &record, changes)?;
    Ok(NativeOutcome {
        record,
        margin,
        burned: settled.burned,
        treasury_leg: settled.treasury_leg,
        #[cfg(test)]
        reimbursed,
        log,
    })
}

/// Refuses reseller legs the payment may not carry: more than the governed
/// number, a reseller named twice, a commission of nothing, or commissions
/// past the cap the paying agent's terms set.
fn check_resellers(state: &dyn VmState, p: &NativePayment<'_>) -> Result<()> {
    if p.resellers.is_empty() {
        return Ok(());
    }
    let max = super::network_param(state, MAX_RESELLER_LEGS_PARAM).min(MAX_MAX_RESELLER_LEGS);
    if p.resellers.len() as u64 > max {
        return Err(VmError::InvalidTransaction(format!(
            "a payment carries at most {max} reseller legs"
        )));
    }
    let mut seen = std::collections::HashSet::new();
    for r in p.resellers {
        if r.commission_bps == 0 {
            return Err(VmError::InvalidTransaction(
                "a reseller leg names a commission".to_string(),
            ));
        }
        if !seen.insert(r.reseller) {
            return Err(VmError::InvalidTransaction(
                "a reseller is named twice on one payment".to_string(),
            ));
        }
    }
    if let Some(did) = p.agent_did
        && let Some(cap) = super::agent_terms::read_agent_terms(state, did)
            .and_then(|t| t.terms.delegation_scope.max_commission_bps)
    {
        let total: u64 = p
            .resellers
            .iter()
            .map(|r| u64::from(r.commission_bps))
            .sum();
        if total > u64::from(cap) {
            return Err(VmError::InvalidTransaction(format!(
                "the reseller commissions {total} bps exceed the buyer's cap of {cap} bps"
            )));
        }
    }
    Ok(())
}

/// Reimburses `relayer` the gas it fronted for a payment in `token`, in the
/// token, from what the treasury kept of the payment's fee: at most the
/// gas at the two rates in force, rounded down, and at most
/// `fees.relay_reimburse_max_bps` of `treasury_kept`.
fn reimburse_relayer(
    state: &mut dyn VmState,
    token: &[u8; 32],
    relayer: &Relayer<'_>,
    treasury_kept: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    use revm::primitives::U256;
    let p = super::settlement_asset::permitted(state, token)?;
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let num = U256::from(relayer.gas_wei)
        .checked_mul(U256::from(tnzo_rate))
        .and_then(|v| v.checked_mul(U256::from(10u8).pow(U256::from(p.asset.decimals))));
    let den = U256::from(10u8).pow(U256::from(18u8)) * U256::from(p.rate_nano_usd.max(1));
    let gas_value = num.map_or(u128::MAX, |n| u128::try_from(n / den).unwrap_or(u128::MAX));
    let share = tenzro_types::split::bps_of(
        treasury_kept,
        u128::from(super::network_param(state, RELAY_REIMBURSE_PARAM).min(10_000)),
    );
    let amount = gas_value.min(share);
    move_asset(
        state,
        token,
        super::derive_treasury_address().as_bytes(),
        relayer.account,
        amount,
        now_ms,
        changes,
    )?;
    Ok(amount)
}

/// Governed key: whether payments attested on rails outside any chain are
/// recorded (1) or refused (0).
pub const ATTESTED_ENABLED_PARAM: &str = "payments.attested_enabled";
/// Genesis value of [`ATTESTED_ENABLED_PARAM`]: on, labelled and capped.
pub const DEFAULT_ATTESTED_ENABLED: u64 = 1;
/// Governed key: most one attested payment may be worth, USD micro-units.
pub const ATTESTED_CAP_PARAM: &str = "payments.attested_cap_usd_e6";
/// Genesis value of [`ATTESTED_CAP_PARAM`]: 10,000 USD.
pub const DEFAULT_ATTESTED_CAP_USD_E6: u64 = 10_000_000_000;
/// Governed key: how far ahead of block time an agent voucher may be
/// dated, ms.
pub const VOUCHER_FRESHNESS_PARAM: &str = "payments.voucher_freshness_ms";
/// Genesis value of [`VOUCHER_FRESHNESS_PARAM`]: 60 seconds.
pub const DEFAULT_VOUCHER_FRESHNESS_MS: u64 = 60_000;

/// Gas for a payment record operation.
pub const GAS_PAYMENT_OP: u64 = 40_000;

/// Apply a [`PaymentOp`] submitted by `from`.
pub(super) fn apply_payment_op(
    state: &mut dyn VmState,
    chain_id: u64,
    now_ms: i64,
    from: &[u8],
    op: &PaymentOp,
    changes: &mut Vec<StateChange>,
) -> Result<Log> {
    match op {
        PaymentOp::Receipt { receipt } => {
            let mut record = read_payment(state, &receipt.pay_ref).ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no payment is recorded at {}",
                    hex::encode(receipt.pay_ref)
                ))
            })?;
            if record.payee.as_bytes() != from {
                return Err(VmError::InvalidTransaction(
                    "only the payee lists receipts on its payment".to_string(),
                ));
            }
            // A served level is what the chain attests for the payee, never
            // what the payee says.
            if let Some(stamp) = &receipt.hardware {
                super::hardware_level::check_stamp(state, from, stamp, now_ms)?;
            }
            let digest = hex::encode(receipt.digest());
            if record.receipts.contains(&digest) {
                return Err(VmError::InvalidTransaction(
                    "the receipt is already listed".to_string(),
                ));
            }
            if record.receipts.len() >= MAX_RECEIPTS_PER_PAYMENT {
                return Err(VmError::InvalidTransaction(format!(
                    "a payment lists at most {MAX_RECEIPTS_PER_PAYMENT} receipts"
                )));
            }
            record.receipts.push(digest);
            write_record(state, &record, changes)
        }
        PaymentOp::Proven {
            agent_did,
            chain,
            delivery,
        } => {
            let paid = super::remote_grant::proven_payment(
                state, chain_id, now_ms, agent_did, chain, delivery, changes,
            )?;
            let reference = claim_reference(
                state,
                chain_id,
                &paid.payee,
                &paid.binding,
                &paid.nonce,
                Origin::Proven(&paid.route_chain),
                changes,
            )?;
            let record = PaymentRecord {
                pay_ref: hex::encode(reference),
                class: RecordClass::Proven,
                payer: paid.payer,
                payee: paid.payee,
                settled: external_receipt(
                    &*state,
                    &paid.asset,
                    paid.binding.usd_e6,
                    &paid.payee,
                    paid.amount,
                ),
                asset: paid.asset,
                amount: paid.amount,
                fee: 0,
                binding: paid.binding,
                nonce: paid.nonce,
                agent_did: Some(agent_did.clone()),
                source: Some(paid.route_chain),
                attestor: None,
                receipts: Vec::new(),
                refunded: 0,
                recorded_at_ms: now_ms,
            };
            write_record(state, &record, changes)
        }
        PaymentOp::SetSplit { rule } => {
            let payee = <[u8; 32]>::try_from(from).map(Address::new).map_err(|_| {
                VmError::InvalidTransaction("a payee is a 32-byte account".to_string())
            })?;
            let key = payee_split_key(&payee);
            let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
            let blob = match rule {
                None => Vec::new(),
                Some(rule) => {
                    validate_standing_split(rule).map_err(VmError::InvalidTransaction)?;
                    // Every recipient must resolve now, so the rule cannot
                    // stop the payee's payments later by naming no one.
                    plan::recipients(state, rule, &payee)?;
                    serde_json::to_vec(rule)
                        .map_err(|e| VmError::Internal(format!("encode split: {e}")))?
                }
            };
            state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), blob.clone());
            changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                key.into_bytes(),
                old,
                Some(blob),
            ));
            Ok(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![PAYEE_SPLIT_SET_TOPIC.to_vec()],
                payee.as_bytes().to_vec(),
            ))
        }
        PaymentOp::SetPayoutAssets { assets } => {
            super::payout_swap::set_payout_assets(state, from, assets, changes)?;
            Ok(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![PAYOUT_ASSETS_SET_TOPIC.to_vec()],
                from.to_vec(),
            ))
        }
        PaymentOp::Refund { pay_ref, amount } => {
            let mut record = read_payment(state, pay_ref).ok_or_else(|| {
                VmError::InvalidTransaction(format!(
                    "no payment is recorded at {}",
                    hex::encode(pay_ref)
                ))
            })?;
            if record.payee.as_bytes() != from {
                return Err(VmError::InvalidTransaction(
                    "only the payee refunds its payment".to_string(),
                ));
            }
            if record.class != RecordClass::Native {
                return Err(VmError::InvalidTransaction(
                    "only a payment settled on this ledger is refunded here".to_string(),
                ));
            }
            let left = record.amount - record.refunded;
            if *amount > left {
                return Err(VmError::InvalidTransaction(format!(
                    "{left} of the payment is left to refund"
                )));
            }
            let payer = hex::decode(&record.payer)
                .map_err(|_| VmError::Internal("a native record's payer is not hex".to_string()))?;
            let token = asset_token(state, &record.asset)?;
            move_asset(state, &token, from, &payer, *amount, now_ms, changes)?;
            record.refunded += *amount;
            write_record(state, &record, changes)
        }
        PaymentOp::Attested { payment } => {
            record_attested(state, chain_id, now_ms, from, payment, changes)
        }
    }
}

fn record_attested(
    state: &mut dyn VmState,
    chain_id: u64,
    now_ms: i64,
    from: &[u8],
    payment: &AttestedPayment,
    changes: &mut Vec<StateChange>,
) -> Result<Log> {
    if super::network_param(state, ATTESTED_ENABLED_PARAM) == 0 {
        return Err(VmError::InvalidTransaction(
            "attested payments are disabled".to_string(),
        ));
    }
    if !super::role_bonded(state, from, tenzro_types::network::NetworkRole::Attestor) {
        return Err(VmError::InvalidTransaction(
            "an attested payment is recorded by a bonded attestor".to_string(),
        ));
    }
    let cap = super::network_param(state, ATTESTED_CAP_PARAM);
    if payment.binding.usd_e6 == 0 || payment.binding.usd_e6 > cap {
        return Err(VmError::InvalidTransaction(format!(
            "an attested payment is priced in USD, 1 to {cap} micro-units"
        )));
    }
    let reference = claim_reference(
        state,
        chain_id,
        &payment.payee,
        &payment.binding,
        &payment.nonce,
        Origin::Attested(from),
        changes,
    )?;
    let record = PaymentRecord {
        pay_ref: hex::encode(reference),
        class: RecordClass::Attested,
        payer: payment.payer.clone(),
        payee: payment.payee,
        asset: payment.asset.clone(),
        amount: payment.amount,
        fee: 0,
        settled: external_receipt(
            &*state,
            &payment.asset,
            payment.binding.usd_e6,
            &payment.payee,
            payment.amount,
        ),
        binding: payment.binding,
        nonce: payment.nonce.clone(),
        agent_did: None,
        source: Some(payment.rail.clone()),
        attestor: Some(hex::encode(from)),
        receipts: Vec::new(),
        refunded: 0,
        recorded_at_ms: now_ms,
    };
    write_record(state, &record, changes)
}

/// The escrow record `escrow_id`, as the VM holds it.
///
/// Read by the node to decide whether a voucher it is offered can be claimed.
pub fn read_escrow(state: &dyn VmState, escrow_id: &[u8; 32]) -> Option<EscrowAccount> {
    let key = escrow_storage_key(&hex::encode(escrow_id));
    let blob = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes())?;
    serde_json::from_slice(&blob).ok()
}

/// A voucher checked against its escrow, ready to pay out.
struct CheckedClaim {
    escrow: EscrowAccount,
    escrow_blob: Vec<u8>,
    storage_key: String,
    payout: u128,
}

/// Check `voucher` and a claim of `amount` in total under it: the voucher
/// must cover the amount, and the amount must advance the escrow.
fn check_voucher(
    chain_id: u64,
    now_ms: i64,
    voucher: &EscrowVoucher,
    amount: u128,
    state: &dyn VmState,
) -> Result<CheckedClaim> {
    let escrow_id_hex = hex::encode(voucher.escrow_id);
    let storage_key = escrow_storage_key(&escrow_id_hex);
    let escrow_blob = state
        .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
        .ok_or_else(|| VmError::InvalidTransaction(format!("Escrow {escrow_id_hex} not found")))?;
    let escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
        VmError::Internal(format!(
            "Failed to decode escrow record {escrow_id_hex}: {e}"
        ))
    })?;
    if escrow.status != EscrowStatus::Funded {
        return Err(VmError::InvalidTransaction(format!(
            "Escrow {escrow_id_hex} is not claimable ({:?})",
            escrow.status
        )));
    }
    // A claim after expiry would race the payer's refund of the remainder.
    if now_ms > escrow.expires_at.0 {
        return Err(VmError::InvalidTransaction(format!(
            "Escrow {escrow_id_hex} has expired; its remainder belongs to the payer"
        )));
    }
    if voucher.cumulative_amount > escrow.amount {
        return Err(VmError::InvalidTransaction(format!(
            "voucher for {} exceeds escrow {escrow_id_hex} holding {}",
            voucher.cumulative_amount, escrow.amount
        )));
    }
    if amount > voucher.cumulative_amount {
        return Err(VmError::InvalidTransaction(format!(
            "a claim of {amount} exceeds its voucher for {} on escrow {escrow_id_hex}",
            voucher.cumulative_amount
        )));
    }
    if amount <= escrow.claimed {
        return Err(VmError::InvalidTransaction(format!(
            "a claim of {amount} does not advance escrow {escrow_id_hex} past {} already claimed",
            escrow.claimed
        )));
    }
    if let Some(a) = &voucher.attribution {
        check_attribution(state, a)?;
    }
    match &voucher.agent {
        None => {
            let (key, rp_id) = crate::keystore::account_signing_key(
                state,
                &voucher.public_key,
                escrow.payer.as_bytes(),
                now_ms.max(0) as u64,
            )
            .map_err(|e| {
                VmError::InvalidTransaction(format!(
                    "voucher key for the payer of escrow {escrow_id_hex}: {e}"
                ))
            })?;
            let message = tenzro_types::payment_authorization::attributed_voucher_preimage(
                escrow_voucher_preimage(
                    chain_id,
                    &voucher.escrow_id,
                    voucher.cumulative_amount,
                    &voucher.binding,
                ),
                voucher.attribution.as_ref(),
            );
            crate::keystore::verify_for_relying_party(
                rp_id.as_deref(),
                &key,
                tenzro_crypto::composite::SignatureContext::EscrowVoucher,
                &message,
                &voucher.signature,
                tenzro_crypto::composite::PqPolicy::Required,
            )
            .map_err(|e| {
                VmError::InvalidTransaction(format!("voucher signature does not verify: {e}"))
            })?;
        }
        Some(signer) => check_agent_voucher(state, chain_id, now_ms, &escrow, voucher, signer)?,
    }
    let payout = amount - escrow.claimed;
    Ok(CheckedClaim {
        escrow,
        escrow_blob,
        storage_key,
        payout,
    })
}

/// Refuse an attribution that is malformed or names a DID that is not a
/// registered, unrevoked identity.
pub(super) fn check_attribution(
    state: &dyn VmState,
    attribution: &tenzro_types::settlement::CallAttribution,
) -> Result<()> {
    attribution.check().map_err(VmError::InvalidTransaction)?;
    for did in attribution.dids() {
        if super::economy::registered_account(state, did).is_none() {
            return Err(VmError::InvalidTransaction(format!(
                "attributed {did} is not a registered identity"
            )));
        }
    }
    Ok(())
}

/// Whether the ledger would honour `voucher` at `now_ms`, and what it would
/// pay: the check a payee makes before accepting a voucher off the ledger,
/// the same one `ClaimEscrow` makes. A voucher on an agent's escrow is
/// checked against the agent's terms.
pub fn check_escrow_voucher(
    state: &dyn VmState,
    chain_id: u64,
    now_ms: i64,
    voucher: &EscrowVoucher,
) -> Result<u128> {
    check_voucher(chain_id, now_ms, voucher, voucher.cumulative_amount, state).map(|c| c.payout)
}

/// Check a voucher a serving node signed for an agent: the escrow's payer
/// is the agent's wallet, the node is assigned in the agent's current terms
/// and signed with its key for the agent, and the voucher was signed before
/// the terms expired and before any revocation or quarantine, and not
/// dated ahead of block time by more than the governed freshness window.
/// The lock itself was held to the terms when the agent opened it.
fn check_agent_voucher(
    state: &dyn VmState,
    chain_id: u64,
    now_ms: i64,
    escrow: &EscrowAccount,
    voucher: &EscrowVoucher,
    signer: &tenzro_types::payment_authorization::AgentVoucherSigner,
) -> Result<()> {
    let refuse = |m: String| VmError::InvalidTransaction(m);
    // The node's raw P-256 signature, and its ML-DSA-65 signature when the
    // agent requires that leg.
    let (node_signature, node_pq) = match (&voucher.signature.classical, &voucher.signature.pq) {
        (tenzro_crypto::composite::ClassicalProof::Raw { signature }, pq)
            if voucher.public_key.is_empty() =>
        {
            (signature.clone(), pq.clone())
        }
        _ => {
            return Err(refuse(
                "an agent voucher carries the node's raw signature".to_string(),
            ));
        }
    };
    if escrow.payer.as_bytes() != tenzro_types::agent_terms::agent_wallet(&signer.agent_did) {
        return Err(refuse(format!(
            "escrow {} is not funded by {}'s wallet",
            escrow.escrow_id, signer.agent_did
        )));
    }
    let stored =
        super::agent_terms::read_agent_terms(state, &signer.agent_did).ok_or_else(|| {
            refuse(format!(
                "{} has no approved terms on chain",
                signer.agent_did
            ))
        })?;
    let freshness = super::network_param(state, VOUCHER_FRESHNESS_PARAM);
    if signer.as_of_ms > (now_ms.max(0) as u64).saturating_add(freshness) {
        return Err(refuse(
            "the voucher is dated ahead of block time".to_string(),
        ));
    }
    if stored
        .terms
        .expires_at_ms
        .is_some_and(|at| signer.as_of_ms >= at)
    {
        return Err(refuse(
            "the voucher was signed after the agent's terms expired".to_string(),
        ));
    }
    let quarantine = super::agent_audit::read_agent_quarantine(state, &signer.agent_did);
    if let Some(q) = &quarantine
        && signer.as_of_ms >= q.at_ms.max(0) as u64
    {
        return Err(refuse(format!(
            "the voucher was signed after {} was {}",
            signer.agent_did,
            if q.revoked { "revoked" } else { "quarantined" }
        )));
    }
    // The node dates its own signature, so once the agent has lost its
    // standing a date before that moment proves nothing by itself: past
    // then, a voucher pays only while its date is within the freshness
    // window of block time, which closes one window after the agent lapsed.
    let lapsed_at = [
        stored.terms.expires_at_ms,
        quarantine.as_ref().map(|q| q.at_ms.max(0) as u64),
    ]
    .into_iter()
    .flatten()
    .min();
    let now = now_ms.max(0) as u64;
    if lapsed_at.is_some_and(|at| now >= at) && signer.as_of_ms.saturating_add(freshness) < now {
        return Err(refuse(format!(
            "{} no longer acts, and the voucher is older than the freshness window",
            signer.agent_did
        )));
    }
    let digest = tenzro_types::payment_authorization::attributed_agent_voucher_digest(
        agent_voucher_digest(
            chain_id,
            &voucher.escrow_id,
            voucher.cumulative_amount,
            &voucher.binding,
            signer,
        ),
        voucher.attribution.as_ref(),
    );
    super::agent_terms::verify_node_signature(
        &stored.terms,
        &signer.machine_did,
        &digest,
        &node_signature,
    )
    .map_err(refuse)?;
    super::agent_terms::verify_node_pq_leg(
        state,
        &signer.agent_did,
        &signer.machine_did,
        &digest,
        node_pq.as_deref(),
    )
    .map_err(refuse)
}

#[derive(serde::Deserialize)]
struct ClaimEscrowPayload {
    claims: Vec<EscrowClaim>,
}

impl NativeExecutor {
    /// Handle a `ClaimEscrow` native transaction.
    ///
    /// Every voucher is checked before any balance moves, so the claim is
    /// all-or-nothing: a batch of legs either all pay out or none does.
    pub(super) async fn execute_escrow_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        crate::invariant_monitor::require_unfrozen(
            state,
            crate::invariant_monitor::GuardedModule::PaymentChannel,
        )?;
        let payload: ClaimEscrowPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid ClaimEscrow payload: {e}"))
        })?;
        if payload.claims.is_empty() || payload.claims.len() > MAX_VOUCHERS_PER_CLAIM {
            return Err(VmError::InvalidTransaction(format!(
                "ClaimEscrow carries 1..={MAX_VOUCHERS_PER_CLAIM} claims, got {}",
                payload.claims.len()
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for c in &payload.claims {
            if !seen.insert(c.voucher.escrow_id) {
                return Err(VmError::InvalidTransaction(format!(
                    "ClaimEscrow names escrow {} twice",
                    hex::encode(c.voucher.escrow_id)
                )));
            }
        }
        let gas = GAS_ESCROW_CLAIM_PER_VOUCHER.saturating_mul(payload.claims.len() as u64);
        gas_meter.consume(gas)?;

        let now_ms = deterministic_now_ms(tx);
        let checked = payload
            .claims
            .iter()
            .map(|c| check_voucher(tx.chain_id, now_ms, &c.voucher, c.amount, &*state))
            .collect::<Result<Vec<_>>>()?;

        let gas_cost = tx.gas_price.saturating_mul(gas as u128);
        let caller_balance = state.get_balance(&tx.from);
        if caller_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: caller_balance,
            });
        }
        let new_caller_balance = caller_balance - gas_cost;
        state.set_balance(&tx.from, new_caller_balance);

        let mut state_changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(caller_balance.to_le_bytes().to_vec()),
            Some(new_caller_balance.to_le_bytes().to_vec()),
        )];
        let mut logs = Vec::with_capacity(checked.len());
        let mut burned = 0u128;
        super::economy::count_settlement(state, payload.claims.len() as u64, &mut state_changes)?;

        for (leg, claim) in payload.claims.iter().zip(checked) {
            let voucher = &leg.voucher;
            let CheckedClaim {
                mut escrow,
                escrow_blob,
                storage_key,
                payout,
            } = claim;
            let earning = escrow_earning(&*state, escrow.payee.as_bytes(), false, Some(voucher));
            let settled = pay_from_vault(
                state,
                &voucher.escrow_id,
                &escrow,
                escrow.payee.as_bytes(),
                payout,
                now_ms,
                &earning,
                &mut state_changes,
            )?;
            burned = burned.saturating_add(settled.burned);
            let payee_bytes = escrow.payee.as_bytes().to_vec();

            escrow.claimed = leg.amount;
            if escrow.claimed == escrow.amount {
                escrow.status = EscrowStatus::Released;
            }
            let new_blob = serde_json::to_vec(&escrow)
                .map_err(|e| VmError::Internal(format!("Failed to serialize escrow: {e}")))?;
            state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), new_blob.clone());
            super::record_escrow_owed(
                state,
                crate::invariant_monitor::GuardedModule::PaymentChannel,
                &escrow,
            )?;

            state_changes.push(StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(escrow_blob),
                Some(new_blob),
            ));
            // escrow_id(32) || payee(32) || payout(16) || claimed total(16)
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![b"EscrowClaimed".to_vec()],
                [
                    voucher.escrow_id.as_slice(),
                    payee_bytes.as_slice(),
                    &payout.to_le_bytes(),
                    &leg.amount.to_le_bytes(),
                ]
                .concat(),
            ));
        }

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        state_changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));

        Ok(
            ExecutionResult::success(gas_meter.final_used(), Vec::new(), logs, state_changes)
                .with_burn(burned),
        )
    }

    /// Handle a `ClaimEscrowPreimage` native transaction: pay a hash-locked
    /// escrow's remainder to its payee against the preimage of its lock, and
    /// publish the preimage in the log.
    ///
    /// The lock makes the payment and the revelation one event: the payee is
    /// paid only by publishing the preimage, and a lock nobody opens before
    /// expiry leaves the funds for the payer's refund. Any account may submit
    /// it; the money can only go to the escrow's payee.
    pub(super) async fn execute_escrow_preimage_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        crate::invariant_monitor::require_unfrozen(
            state,
            crate::invariant_monitor::GuardedModule::PaymentChannel,
        )?;
        use sha2::{Digest, Sha256};
        gas_meter.consume(GAS_ESCROW_PREIMAGE_CLAIM)?;
        let payload: PreimageClaimPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid ClaimEscrowPreimage payload: {e}"))
        })?;
        if payload.preimage.is_empty() || payload.preimage.len() > MAX_PREIMAGE_LEN {
            return Err(VmError::InvalidTransaction(format!(
                "a preimage is 1..={MAX_PREIMAGE_LEN} bytes, got {}",
                payload.preimage.len()
            )));
        }
        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {escrow_id_hex} not found"))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!(
                "Failed to decode escrow record {escrow_id_hex}: {e}"
            ))
        })?;
        let tenzro_types::settlement::ReleaseConditions::HashLock { hash } =
            escrow.release_conditions.clone()
        else {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {escrow_id_hex} is not hash-locked"
            )));
        };
        if escrow.status != EscrowStatus::Funded {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {escrow_id_hex} is not claimable ({:?})",
                escrow.status
            )));
        }
        if deterministic_now_ms(tx) > escrow.expires_at.0 {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {escrow_id_hex} has expired; its remainder belongs to the payer"
            )));
        }
        let digest: [u8; 32] = Sha256::digest(&payload.preimage).into();
        if digest != hash {
            return Err(VmError::InvalidTransaction(format!(
                "the preimage does not open the lock of escrow {escrow_id_hex}"
            )));
        }

        let gas_cost = tx
            .gas_price
            .saturating_mul(GAS_ESCROW_PREIMAGE_CLAIM as u128);
        let caller_balance = state.get_balance(&tx.from);
        if caller_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: caller_balance,
            });
        }
        state.set_balance(&tx.from, caller_balance - gas_cost);

        let payout = escrow.amount - escrow.claimed;
        let mut fee_changes = Vec::new();
        let mut earning = escrow_earning(&*state, escrow.payee.as_bytes(), false, None);
        // A hash-locked escrow to the treasury is the network share itself.
        earning.network_share_paid = escrow.payee == tenzro_types::network_treasury_address()
            || spend_network_share(state, &escrow, &hash, &mut fee_changes);
        let settled = pay_from_vault(
            state,
            &payload.escrow_id,
            &escrow,
            escrow.payee.as_bytes(),
            payout,
            deterministic_now_ms(tx),
            &earning,
            &mut fee_changes,
        )?;
        super::economy::count_settlement(state, 1, &mut fee_changes)?;
        let payee_bytes = escrow.payee.as_bytes().to_vec();

        escrow.claimed = escrow.amount;
        escrow.status = EscrowStatus::Released;
        let new_blob = serde_json::to_vec(&escrow)
            .map_err(|e| VmError::Internal(format!("Failed to serialize escrow: {e}")))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), new_blob.clone());
        super::record_escrow_owed(
            state,
            crate::invariant_monitor::GuardedModule::PaymentChannel,
            &escrow,
        )?;

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(caller_balance.to_le_bytes().to_vec()),
                Some((caller_balance - gas_cost).to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(escrow_blob),
                Some(new_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        state_changes.extend(fee_changes);
        // escrow_id(32) || payee(32) || payout(16) || preimage
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"EscrowPreimageRevealed".to_vec()],
            [
                payload.escrow_id.as_slice(),
                payee_bytes.as_slice(),
                &payout.to_le_bytes(),
                &payload.preimage,
            ]
            .concat(),
        );
        Ok(
            ExecutionResult::success(gas_meter.final_used(), Vec::new(), vec![log], state_changes)
                .with_burn(settled.burned),
        )
    }

    /// Handle a `ClaimEscrowStream` native transaction: pay a streaming
    /// escrow's accrued, unpaid part to its payee. Any account may submit it;
    /// the money can only go to the payee, and only as fast as the stream
    /// accrues.
    pub(super) async fn execute_escrow_stream_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        crate::invariant_monitor::require_unfrozen(
            state,
            crate::invariant_monitor::GuardedModule::PaymentChannel,
        )?;
        gas_meter.consume(GAS_ESCROW_STREAM_CLAIM)?;
        let payload: StreamClaimPayload = serde_json::from_slice(&tx.data[4..]).map_err(|e| {
            VmError::InvalidTransaction(format!("Invalid ClaimEscrowStream payload: {e}"))
        })?;
        let escrow_id_hex = hex::encode(payload.escrow_id);
        let storage_key = escrow_storage_key(&escrow_id_hex);
        let escrow_blob = state
            .get_storage(&SYSTEM_ADDRESS, storage_key.as_bytes())
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {escrow_id_hex} not found"))
            })?;
        let mut escrow: EscrowAccount = serde_json::from_slice(&escrow_blob).map_err(|e| {
            VmError::Internal(format!(
                "Failed to decode escrow record {escrow_id_hex}: {e}"
            ))
        })?;
        if escrow.status != EscrowStatus::Funded {
            return Err(VmError::InvalidTransaction(format!(
                "Escrow {escrow_id_hex} is not claimable ({:?})",
                escrow.status
            )));
        }
        let (due, cursor) = stream_progress(&*state, &escrow, deterministic_now_ms(tx), false)
            .ok_or_else(|| {
                VmError::InvalidTransaction(format!("Escrow {escrow_id_hex} is not a stream"))
            })?;
        if due == 0 {
            return Err(VmError::InvalidTransaction(format!(
                "stream {escrow_id_hex} has accrued nothing unpaid"
            )));
        }

        let gas_cost = tx.gas_price.saturating_mul(GAS_ESCROW_STREAM_CLAIM as u128);
        let caller_balance = state.get_balance(&tx.from);
        if caller_balance < gas_cost {
            return Err(VmError::InsufficientBalance {
                required: gas_cost,
                available: caller_balance,
            });
        }
        state.set_balance(&tx.from, caller_balance - gas_cost);

        let mut fee_changes = Vec::new();
        let earning = escrow_earning(&*state, escrow.payee.as_bytes(), true, None);
        let settled = pay_from_vault(
            state,
            &payload.escrow_id,
            &escrow,
            escrow.payee.as_bytes(),
            due,
            deterministic_now_ms(tx),
            &earning,
            &mut fee_changes,
        )?;
        super::economy::count_settlement(state, 1, &mut fee_changes)?;
        let payee_bytes = escrow.payee.as_bytes().to_vec();

        escrow.claimed += due;
        if escrow.claimed == escrow.amount {
            escrow.status = EscrowStatus::Released;
        }
        let new_blob = serde_json::to_vec(&escrow)
            .map_err(|e| VmError::Internal(format!("Failed to serialize escrow: {e}")))?;
        state.set_storage(&SYSTEM_ADDRESS, storage_key.as_bytes(), new_blob.clone());
        super::record_escrow_owed(
            state,
            crate::invariant_monitor::GuardedModule::PaymentChannel,
            &escrow,
        )?;
        // The hours this claim judged are not read again.
        super::funding::write_json(
            state,
            &stream_cursor_key(&payload.escrow_id),
            &cursor,
            &mut fee_changes,
        )?;

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(caller_balance.to_le_bytes().to_vec()),
                Some((caller_balance - gas_cost).to_le_bytes().to_vec()),
            ),
            StateChange::new(
                SYSTEM_ADDRESS.to_vec(),
                storage_key.as_bytes().to_vec(),
                Some(escrow_blob),
                Some(new_blob),
            ),
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(old_nonce.to_le_bytes().to_vec()),
                Some((old_nonce + 1).to_le_bytes().to_vec()),
            ),
        ];
        state_changes.extend(fee_changes);
        // escrow_id(32) || payee(32) || paid(16) || claimed_total(16)
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![b"EscrowStreamed".to_vec()],
            [
                payload.escrow_id.as_slice(),
                payee_bytes.as_slice(),
                &due.to_le_bytes(),
                &escrow.claimed.to_le_bytes(),
            ]
            .concat(),
        );
        Ok(
            ExecutionResult::success(gas_meter.final_used(), Vec::new(), vec![log], state_changes)
                .with_burn(settled.burned),
        )
    }
}

#[derive(serde::Deserialize)]
struct PreimageClaimPayload {
    escrow_id: [u8; 32],
    preimage: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct StreamClaimPayload {
    escrow_id: [u8; 32],
}

#[cfg(test)]
#[path = "machine_payment_tests.rs"]
mod machine_payment_tests;
