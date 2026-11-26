//! Standby reservations: capacity on a model a buyer pays for by the hour
//! whether or not it calls.
//!
//! The price is the operator's standby fee per hour (`[standby]
//! fee_per_hour`, announced as `standby_fee_per_hour`). A buyer reserves by
//! opening a stream escrow to the operator's account whose reference is
//! [`reservation_digest`] of the model, at a rate covering the fee and an
//! amount covering it to the escrow's expiry. The operator claims the stream
//! as it accrues, called or not, and the buyer may stop it at any time; the
//! claim settles on the ledger like any stream, fee and treasury leg
//! included, so this node keeps no charge book.
//!
//! A request names the escrow in `reservation`. When the escrow is funded,
//! pays this node for this model, and was opened by the signed-in caller's
//! own account, the request is admitted on the never-shed interactive path
//! with [`RESERVED_WEIGHT`] in the fair share, ahead of every unreserved
//! caller, `spot` or not.

use serde_json::Value;
use tenzro_settlement::{EscrowAccount, EscrowStatus};
use tenzro_types::settlement::ReleaseConditions;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Fair-share weight of a reserved caller: four times a signed-in one.
pub const RESERVED_WEIGHT: u32 = 8;

/// The reference a reservation escrow for `model_id` carries.
pub fn reservation_digest(model_id: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(b"tenzro/standby-reservation/v1");
    h.update(model_id.as_bytes());
    h.finalize().into()
}

/// Whether `escrow` funds standby at `fee_per_hour` for `payee_hex` under
/// `reference` from `now_ms` to its expiry: funded, paying that account,
/// carrying that reference, a stream at a rate covering the fee, holding
/// enough to pay it every hour left. The reason when it does not.
pub(crate) fn funds_standby(
    escrow: &EscrowAccount,
    payee_hex: &str,
    reference: [u8; 32],
    fee_per_hour: u128,
    now_ms: u64,
) -> Result<(), &'static str> {
    if escrow.status != EscrowStatus::Funded {
        return Err("the escrow is not funded");
    }
    if !hex::encode(escrow.payee.as_bytes())
        .eq_ignore_ascii_case(payee_hex.trim_start_matches("0x"))
    {
        return Err("the escrow pays another account");
    }
    if escrow.reference != Some(reference) {
        return Err("the escrow is for something else");
    }
    let ReleaseConditions::Stream {
        rate_per_epoch,
        epoch_ms,
    } = escrow.release_conditions
    else {
        return Err("standby is paid by a stream escrow");
    };
    let per_hour = rate_per_epoch.saturating_mul(3_600_000) / u128::from(epoch_ms.max(1));
    if per_hour < fee_per_hour {
        return Err("the stream pays less than the standby fee");
    }
    let expires = u64::try_from(escrow.expires_at.0).unwrap_or(0);
    let hours = expires.saturating_sub(now_ms).div_ceil(3_600_000);
    if hours == 0 {
        return Err("the escrow has expired");
    }
    let left = escrow.amount.saturating_sub(escrow.claimed);
    if left < fee_per_hour.saturating_mul(hours as u128) {
        return Err("the escrow does not cover the standby fee to its expiry");
    }
    Ok(())
}

fn refuse(why: impl std::fmt::Display) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: format!("reservation refused: {why}"),
        data: None,
    }
}

/// Whether a request for `model_id` holds a reservation: `None` when it names
/// none, the reserved caller when it names one this node honours, an error
/// when it names one this node does not.
pub(crate) fn reserved_caller(
    node: &TenzroNode,
    params: &Value,
    model_id: &str,
    caller_did: Option<&str>,
) -> Result<Option<tenzro_model::traffic::Caller>, JsonRpcError> {
    let Some(named) = params.get("reservation") else {
        return Ok(None);
    };
    let id = named
        .as_str()
        .and_then(|h| hex::decode(h.trim_start_matches("0x")).ok())
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| refuse("'reservation' is a 32-byte escrow id in hex"))?;
    let fee = node.config().standby.fee_per_hour;
    if fee == 0 {
        return Err(refuse("this node sells no standby"));
    }
    let did = caller_did.ok_or_else(|| refuse("a reservation is used signed in"))?;
    let payee = node
        .payee_hex()
        .ok_or_else(|| refuse("this node has no payee account"))?;
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| refuse("this node reads no chain state"))?;
    let escrow =
        tenzro_vm::native::read_escrow(&chain, &id).ok_or_else(|| refuse("no such escrow"))?;
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
    funds_standby(&escrow, &payee, reservation_digest(model_id), fee, now).map_err(refuse)?;
    if tenzro_vm::native::identity_did_of(&chain, escrow.payer.as_bytes()).as_deref() != Some(did) {
        return Err(refuse("the escrow was opened by another account"));
    }
    Ok(Some(tenzro_model::traffic::Caller::new(
        did.to_string(),
        RESERVED_WEIGHT,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::{Address, Timestamp};

    const H: u64 = 3_600_000;

    fn escrow(payee: Address, rate_per_hour: u128, amount: u128, expires: u64) -> EscrowAccount {
        let mut e = EscrowAccount::new(
            Address::new([1; 32]),
            payee,
            amount,
            tenzro_types::AssetId::tnzo(),
            Timestamp(expires as i64),
            ReleaseConditions::Stream {
                rate_per_epoch: rate_per_hour,
                epoch_ms: H,
            },
        );
        e.status = EscrowStatus::Funded;
        e.reference = Some(reservation_digest("m"));
        e
    }

    #[test]
    fn a_reservation_must_fund_this_model_at_the_fee_to_its_expiry() {
        let payee = Address::new([2; 32]);
        let me = hex::encode(payee.as_bytes());
        let ok = escrow(payee, 10, 30, 3 * H);
        assert_eq!(
            funds_standby(&ok, &me, reservation_digest("m"), 10, 0),
            Ok(())
        );
        assert_eq!(
            funds_standby(&ok, &me, reservation_digest("other"), 10, 0),
            Err("the escrow is for something else")
        );
        assert_eq!(
            funds_standby(&ok, &hex::encode([3; 32]), reservation_digest("m"), 10, 0),
            Err("the escrow pays another account")
        );
        assert_eq!(
            funds_standby(&ok, &me, reservation_digest("m"), 11, 0),
            Err("the stream pays less than the standby fee")
        );
        let short = escrow(payee, 10, 29, 3 * H);
        assert_eq!(
            funds_standby(&short, &me, reservation_digest("m"), 10, 0),
            Err("the escrow does not cover the standby fee to its expiry")
        );
        assert_eq!(
            funds_standby(&ok, &me, reservation_digest("m"), 10, 3 * H),
            Err("the escrow has expired")
        );
        let mut refunded = ok.clone();
        refunded.status = EscrowStatus::Refunded;
        assert_eq!(
            funds_standby(&refunded, &me, reservation_digest("m"), 10, 0),
            Err("the escrow is not funded")
        );
    }

    #[test]
    fn the_reservation_reference_names_the_model() {
        assert_ne!(reservation_digest("a"), reservation_digest("b"));
        assert_eq!(reservation_digest("a"), reservation_digest("a"));
    }
}
