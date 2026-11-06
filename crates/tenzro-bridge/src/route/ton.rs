//! TON: the bridge contract's external messages, proven by the TON light
//! client ([`super::ton_light_client`]).
//!
//! A transfer to Tenzro is an external outbound message of Tenzro's bridge
//! contract on the basechain. The delivery's body names its source and
//! logical time and carries the message body's bits, the transfer record of
//! [`super::move_event`] written big-endian (as on Stellar):
//!
//! ```text
//! workchain   i8 (0)     the contract's workchain
//! address     32 bytes   the contract's account id: the route's `ramp`
//! created_lt  u64        the message's logical time
//! record      168 bytes  sequence, selectors, sender, token, endpoint,
//!                        recipient, amount
//! ```
//!
//! The contract is TNZO's TEP-74 jetton master: it emits the record when it
//! burns jettons sent to it for Tenzro (the sender is the jetton owner), and
//! executes an outbound record by minting jettons to the recipient. A jetton
//! amount is below 2^120, so larger records are refused both ways.
//!
//! Outbound transfers are the record, which the contract executes.
//!
//! A delivery carries, as its proof, the masterchain block's finalization
//! and the Merkle proofs down to the message ([`super::ton_light_client`]);
//! the light client re-encodes the proven message in the layout above and
//! admits the delivery only if it is the delivered body. A masterchain
//! block is final once finalized, which takes one block.

use super::canonical::{Reader, Writer};
use super::move_event::{MoveTransfer, message_id};
use super::stellar::encode_record;
use super::{BridgeRoute, BridgeRouteAdapter, ChainFamily, RouteAdapter, RouteMessage};
use crate::error::{BridgeError, Result};

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("ton message: {}", what.into()))
}

/// Largest amount a TEP-74 jetton carries (`VarUInteger 16`, 120 bits).
pub const MAX_JETTON_AMOUNT: u128 = (1 << 120) - 1;

fn within_jetton_range(t: MoveTransfer) -> Result<MoveTransfer> {
    if t.amount > MAX_JETTON_AMOUNT {
        return Err(bad("the amount exceeds a jetton amount"));
    }
    Ok(t)
}

fn read_record(r: &mut Reader<'_>) -> Result<MoveTransfer> {
    within_jetton_range(MoveTransfer {
        sequence: r.u64_be()?,
        source_selector: r.u64_be()?,
        dest_selector: r.u64_be()?,
        sender: r.array()?,
        token: r.array()?,
        endpoint: r.array()?,
        recipient: r.array()?,
        amount: r.u128_be()?,
    })
}

/// A delivered TON message, in the body encoding.
pub fn encode_message(address: &[u8; 32], created_lt: u64, record: &MoveTransfer) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(0)
        .raw(address)
        .u64_be(created_lt)
        .raw(&encode_record(record));
    w.into_bytes()
}

/// The TON adapter. See the module docs.
pub struct TonAdapter;

impl RouteAdapter for TonAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Contract
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Ton
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let workchain = r.u8()?;
        let address: [u8; 32] = r.array()?;
        let created_lt = r.u64_be()?;
        let t = read_record(r)?;
        if workchain != 0 || address != route.ramp {
            return Err(bad(
                "not sent by the route's bridge contract on the basechain",
            ));
        }
        if created_lt == 0 {
            return Err(bad("a message needs its logical time"));
        }
        Ok(t.inbound(ChainFamily::Ton, &encode_message(&address, created_lt, &t)))
    }

    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>> {
        Ok(encode_record(&within_jetton_range(
            MoveTransfer::outbound(route, msg)?,
        )?))
    }

    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let t = read_record(r)?;
        let mut m = t.read_back(route)?;
        m.message_id = message_id(ChainFamily::Ton, &encode_record(&t));
        Ok(m)
    }

    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]> {
        MoveTransfer::outbound(route, msg).map(|t| message_id(ChainFamily::Ton, &encode_record(&t)))
    }

    fn finality_depth(&self, _route: &BridgeRoute) -> Result<u64> {
        Ok(1)
    }
}
