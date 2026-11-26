//! A validator bond bought with a stable settlement asset.
//!
//! Once [`GATE`] is in force, an account pays a stable settlement asset to
//! the treasury with a native call
//! ([`tenzro_native_ops::bond_with_stable::BondWithStableOp`]) and the
//! treasury pays TNZO for it straight into the account's validator bond in
//! the staking vault. The TNZO never reaches a free balance: it leaves the
//! bond only by the validator exit, after the governed unbonding period,
//! like any other bond.
//!
//! The price is the asset's value at the higher of the TNZO rate in force
//! and the safety rate, less [`SPREAD_PARAM`], so the treasury never pays
//! more TNZO than either rate says the stable is worth. A purchase is
//! refused below the caller's `min_tnzo`, when the asset may not settle,
//! when the treasury would then hold more of the asset than its exposure
//! ceiling, past what the treasury holds, and past [`CAP_PARAM`] of TNZO in
//! one epoch, which is zero at genesis.
//!
//! The treasury exchanging TNZO for stable assets distributes TNZO: setting
//! [`GATE`] or raising [`CAP_PARAM`] above zero is the owner's decision.
//!
//! Records, under `SYSTEM_ADDRESS`: `bond_onramp_epoch:{epoch}` — TNZO paid
//! into bonds in that epoch.

use super::funding::{read_json, refuse, write_json};
use super::*;

/// Gate of the on-ramp. Switching it on is the owner's decision.
pub const GATE: &str = "feature.bond_onramp.activation_epoch";

/// Governed key: most TNZO, whole, the on-ramp pays into bonds in one epoch.
pub const CAP_PARAM: &str = "treasury.onramp_max_tnzo_epoch";

/// Governed key: what the on-ramp keeps of a purchase's value, bps.
pub const SPREAD_PARAM: &str = "fees.onramp_spread_bps";

pub use tenzro_native_ops::SELECTOR_BOND_WITH_STABLE;

/// Gas for one purchase.
pub const GAS_BOND_WITH_STABLE: u64 = 60_000;

/// Topic of the log a purchase emits.
pub const BOND_BOUGHT_TOPIC: &[u8] = b"BondBoughtWithStable";

fn epoch_key(epoch: u64) -> String {
    format!("bond_onramp_epoch:{epoch}")
}

/// TNZO the on-ramp paid into bonds in `epoch`.
pub fn paid_in_epoch(state: &dyn VmState, epoch: u64) -> u128 {
    read_json::<String>(state, &epoch_key(epoch))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// TNZO, base units, `units` of `p`'s asset buy now, after the spread.
pub fn quote(state: &dyn VmState, p: &super::settlement_asset::Permitted, units: u128) -> u128 {
    let rate = super::economy::read_fee_rate(state)
        .rate_nano_usd
        .max(super::economy::safety_rate(state));
    let worth =
        super::settlement_asset::tnzo_eq(units, p.rate_nano_usd, p.asset.decimals, rate, false);
    let spread = network_param(state, SPREAD_PARAM).min(10_000);
    worth - super::funding::bps_of(worth, spread)
}

/// Buy a validator bond for `from` with the payload's stable asset.
pub(super) fn apply(
    state: &mut dyn VmState,
    from: &[u8],
    payload: &[u8],
    now_ms: i64,
) -> Result<(Vec<StateChange>, Vec<Log>)> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Err(refuse("the bond on-ramp is not in force on this chain"));
    }
    let op: tenzro_native_ops::bond_with_stable::BondWithStableOp = serde_json::from_slice(payload)
        .map_err(|e| refuse(format!("Invalid bond purchase payload: {e}")))?;
    op.validate().map_err(refuse)?;
    let token: [u8; 32] = op
        .asset
        .as_slice()
        .try_into()
        .map_err(|_| refuse("a bond purchase names a 32-byte token id"))?;
    let p = super::settlement_asset::permitted(state, &token)?;
    super::settlement_asset::check_exposure(state, &token, &p, op.units)?;
    let tnzo = quote(state, &p, op.units);
    if tnzo == 0 || tnzo < op.min_tnzo {
        return Err(refuse(format!(
            "{} of {} buy {tnzo} TNZO base units, under the {} asked for",
            op.units, p.asset.symbol, op.min_tnzo
        )));
    }
    let epoch = params_epoch(state);
    let paid = paid_in_epoch(state, epoch).saturating_add(tnzo);
    let cap = u128::from(network_param(state, CAP_PARAM))
        .saturating_mul(tenzro_types::constants::ONE_TNZO);
    if paid > cap {
        return Err(refuse(format!(
            "the bond on-ramp pays at most {} TNZO into bonds an epoch, and this purchase would \
             pass it",
            cap / tenzro_types::constants::ONE_TNZO
        )));
    }
    let treasury = derive_treasury_address();
    let vault = super::staking::staking_vault_address();
    let mut changes = Vec::new();
    super::payment_settlement::move_asset(
        state,
        &token,
        from,
        treasury.as_bytes(),
        op.units,
        now_ms,
        &mut changes,
    )?;
    super::funding::move_balance(state, treasury.as_bytes(), &vault, tnzo, &mut changes)?;
    super::staking::add_bond(state, from, tnzo, now_ms)?;
    write_json(state, &epoch_key(epoch), &paid.to_string(), &mut changes)?;
    let data = serde_json::to_vec(&serde_json::json!({
        "account": hex::encode(from),
        "asset": hex::encode(token),
        "units": op.units.to_string(),
        "tnzo": tnzo.to_string(),
    }))
    .map_err(|e| VmError::Internal(format!("encode bond purchase log: {e}")))?;
    Ok((
        changes,
        vec![Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![BOND_BOUGHT_TOPIC.to_vec()],
            data,
        )],
    ))
}
