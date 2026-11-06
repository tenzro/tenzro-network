//! Transfers and messages over governed bridge routes, as consensus
//! transactions.
//!
//! Every write the route framework makes (a delivery's nonce, the epoch mint
//! total, a route's supply record, an outbound sequence, a light client's
//! head) happens inside block execution, so every node applies the same
//! accounting and the credits and debits it implies.

use serde::{Deserialize, Serialize};

use crate::bridge_route::BridgeRouteAdapter;
use crate::payment_authorization::hex_bytes;

/// Upper bound on a delivery, update or payload carried in one operation.
pub const MAX_BRIDGE_PAYLOAD_LEN: usize = 256 * 1024;

/// One operation on a governed bridge route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeOp {
    /// Admit a delivery a relayer brings from `source_chain` and credit the
    /// Tenzro account it names. Any account may submit it: the delivery is
    /// admitted only under every rule of the route.
    Inbound {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain the delivery comes from.
        source_chain: String,
        /// The delivery as the route's transport encodes it.
        #[serde(with = "hex_bytes")]
        delivery: Vec<u8>,
    },
    /// Lock `amount` TNZO of the sender's on the route to `target_chain`, and
    /// queue the message authorising the same amount to `recipient` there.
    /// Over a deposit route the sender's deposit asset is retired instead,
    /// and the message is the withdrawal paying `recipient` (an output
    /// script) from the route's deposits.
    Outbound {
        /// External chain the value goes to.
        target_chain: String,
        /// Recipient account on the external chain.
        #[serde(with = "hex_bytes")]
        recipient: Vec<u8>,
        /// Base units: TNZO, the deposit asset over a deposit route, or
        /// the carried asset named by `asset`.
        #[serde(with = "crate::primitives::u128_serde")]
        amount: u128,
        /// A carried asset's symbol (`USDC`): its representation is burned
        /// here and the route's vault releases the token there. `None`
        /// moves TNZO (or the deposit asset over a deposit route).
        #[serde(default)]
        asset: Option<String>,
    },
    /// Move a route's light client forward with an update its external chain
    /// signed, or bootstrap it from the route's anchor. Any account may
    /// submit it: the update carries its own proof.
    LightClientUpdate {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain the light client follows.
        source_chain: String,
        /// The update as the light client encodes it.
        #[serde(with = "hex_bytes")]
        update: Vec<u8>,
    },
    /// Publish an attested data message from `source_chain` in the
    /// transaction's log, once per delivery. A native consumer the message
    /// is meant for (an order's fill proof, an agent account report) may
    /// still act on it once afterwards.
    AdmitMessage {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain the message comes from.
        source_chain: String,
        /// The delivery as the route's transport encodes it.
        #[serde(with = "hex_bytes")]
        delivery: Vec<u8>,
    },
    /// Queue a data message from the sender to `target_chain`.
    SendMessage {
        /// External chain the message goes to.
        target_chain: String,
        /// Message body.
        #[serde(with = "hex_bytes")]
        payload: Vec<u8>,
    },
    /// Apply an IBC message a relayer brings from the Cosmos chain of the
    /// IBC route to `source_chain`. Any account may submit it: it carries its
    /// own proof against the route's light client.
    Ibc {
        /// External chain of the IBC route.
        source_chain: String,
        /// The message.
        msg: IbcMsg,
    },
    /// Draw the committees of the route to `source_chain` from the accounts
    /// bonded as attestors with a bridge signing key, weighted by stake, with
    /// the randomness beacon. Any account may submit it while the route's
    /// committees are undrawn, once their term has ended, or once an
    /// equivocation broke them.
    DrawCommittee {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain of the route.
        source_chain: String,
    },
    /// Prove that `member` of the route's committees signed two different
    /// deliveries with one nonce. Its attestor stake is slashed, and the
    /// route carries no traffic until its committees are drawn again.
    ReportEquivocation {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain of the route.
        source_chain: String,
        /// The member's signing address.
        #[serde(with = "hex_bytes")]
        member: Vec<u8>,
        /// One delivery the member signed.
        #[serde(with = "hex_bytes")]
        first: Vec<u8>,
        /// Another delivery with the same nonce the member signed.
        #[serde(with = "hex_bytes")]
        second: Vec<u8>,
    },
    /// Send a queued exit once its delay has passed. Anyone may release it;
    /// it then leaves as an immediate exit would, against the limits in
    /// force now.
    ReleaseExit {
        /// The exit's id.
        id: u64,
    },
    /// Cancel a queued exit and return its value to the sender: the sender
    /// at any time, a seated guardian during its delay, or anyone once a
    /// committee member of its route has been proven to equivocate since it
    /// was queued.
    CancelExit {
        /// The exit's id.
        id: u64,
    },
    /// Prove that a member of the route's verifier committee `signed_by_set`
    /// signed a handover to a committee this chain did not draw: a set index
    /// not above its own, or members, threshold or expiry other than the
    /// committee drawn under that index. Its attestor stake is slashed, and
    /// if it sits on the route's committees they are drawn again.
    ReportWrongHandover {
        /// Transport of the route.
        adapter: BridgeRouteAdapter,
        /// External chain of the route.
        source_chain: String,
        /// The committee the signer sat on.
        signed_by_set: u32,
        /// The committee the handover names.
        set_index: u32,
        /// The handover's member addresses, 20 bytes each, in order.
        #[serde(with = "hex_bytes")]
        members: Vec<u8>,
        /// The handover's threshold.
        threshold: u32,
        /// The handover's expiry, Unix seconds.
        expires_at_secs: u64,
        /// The member's 65-byte signature over the handover digest.
        #[serde(with = "hex_bytes")]
        signature: Vec<u8>,
    },
}

/// An IBC message from a Cosmos chain to Tenzro. Each carries a proof of the
/// Cosmos chain's IBC store at a height its route's light client verified
/// (the encoding is `tenzro_bridge::route::tendermint::EntryProof`); every
/// identifier comes from the route's settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IbcMsg {
    /// Classic: the Cosmos chain's connection end towards Tenzro is `INIT`;
    /// Tenzro's end opens as `TRYOPEN`.
    ConnectionOpenTry {
        /// Proof of the Cosmos connection end.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
    /// Classic: the Cosmos chain's connection end is `OPEN`; so is Tenzro's.
    ConnectionOpenConfirm {
        /// Proof of the Cosmos connection end.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
    /// Classic: the Cosmos chain's transfer channel end is `INIT`; Tenzro's
    /// end opens as `TRYOPEN`.
    ChannelOpenTry {
        /// Proof of the Cosmos channel end.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
    /// Classic: the Cosmos chain's channel end is `OPEN`; so is Tenzro's.
    ChannelOpenConfirm {
        /// Proof of the Cosmos channel end.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
    /// The Cosmos chain acknowledged outbound packet `sequence`. An error
    /// acknowledgement refunds its sender.
    Acknowledge {
        /// The packet's sequence.
        sequence: u64,
        /// The acknowledgement the Cosmos chain wrote.
        #[serde(with = "hex_bytes")]
        acknowledgement: Vec<u8>,
        /// Proof of the acknowledgement's commitment.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
    /// Outbound packet `sequence` timed out unreceived; its sender is
    /// refunded.
    Timeout {
        /// The packet's sequence.
        sequence: u64,
        /// Proof that the Cosmos chain holds no receipt of it, at a height
        /// past its timeout.
        #[serde(with = "hex_bytes")]
        proof: Vec<u8>,
    },
}

impl IbcMsg {
    /// The proof the message carries.
    pub fn proof(&self) -> &[u8] {
        match self {
            Self::ConnectionOpenTry { proof }
            | Self::ConnectionOpenConfirm { proof }
            | Self::ChannelOpenTry { proof }
            | Self::ChannelOpenConfirm { proof }
            | Self::Acknowledge { proof, .. }
            | Self::Timeout { proof, .. } => proof,
        }
    }

    /// The message kind, as clients name it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ConnectionOpenTry { .. } => "connection_open_try",
            Self::ConnectionOpenConfirm { .. } => "connection_open_confirm",
            Self::ChannelOpenTry { .. } => "channel_open_try",
            Self::ChannelOpenConfirm { .. } => "channel_open_confirm",
            Self::Acknowledge { .. } => "acknowledge",
            Self::Timeout { .. } => "timeout",
        }
    }
}

impl BridgeOp {
    /// Shape checks that need no state.
    pub fn validate(&self) -> Result<(), &'static str> {
        let (chain, bytes): (&String, &[u8]) = match self {
            Self::ReleaseExit { .. } | Self::CancelExit { .. } => return Ok(()),
            Self::DrawCommittee { source_chain, .. } => (source_chain, b"draw".as_slice()),
            Self::ReportWrongHandover {
                source_chain,
                members,
                signature,
                ..
            } => {
                if signature.len() != 65 {
                    return Err("a handover signature is 65 bytes");
                }
                if members.is_empty() || members.len() % 20 != 0 || members.len() > 20 * 255 {
                    return Err("a handover names 1 to 255 20-byte member addresses");
                }
                (source_chain, signature.as_slice())
            }
            Self::ReportEquivocation {
                source_chain,
                member,
                first,
                second,
                ..
            } => {
                if member.len() != 20 {
                    return Err("a committee member is a 20-byte address");
                }
                if first.is_empty()
                    || second.is_empty()
                    || first.len() + second.len() > MAX_BRIDGE_PAYLOAD_LEN
                {
                    return Err("an equivocation carries two deliveries within 256 KiB");
                }
                (source_chain, first.as_slice())
            }
            Self::Inbound {
                source_chain,
                delivery,
                ..
            }
            | Self::AdmitMessage {
                source_chain,
                delivery,
                ..
            } => (source_chain, delivery),
            Self::Outbound {
                target_chain,
                recipient,
                amount,
                asset,
            } => {
                if *amount == 0 {
                    return Err("an outbound transfer moves a positive amount");
                }
                if asset.as_ref().is_some_and(|a| {
                    a.is_empty()
                        || a.len() > crate::bridge_route::MAX_ASSET_SYMBOL_LEN
                        || !a.bytes().all(|b| b.is_ascii_alphanumeric())
                }) {
                    return Err("an asset symbol is 1..=12 ASCII letters or digits");
                }
                (target_chain, recipient)
            }
            Self::LightClientUpdate {
                source_chain,
                update,
                ..
            } => (source_chain, update),
            Self::SendMessage {
                target_chain,
                payload,
            } => (target_chain, payload),
            Self::Ibc { source_chain, msg } => {
                if let IbcMsg::Acknowledge {
                    acknowledgement, ..
                } = msg
                    && (acknowledgement.is_empty() || acknowledgement.len() > 1024)
                {
                    return Err("an acknowledgement is 1 byte to 1 KiB");
                }
                (source_chain, msg.proof())
            }
        };
        if chain.is_empty() || chain.len() > crate::bridge_route::MAX_CHAIN_NAME_LEN {
            return Err("a chain name is 1 to 64 bytes");
        }
        if bytes.is_empty() || bytes.len() > MAX_BRIDGE_PAYLOAD_LEN {
            return Err("a delivery, recipient, update or payload is 1 byte to 256 KiB");
        }
        Ok(())
    }

    /// Bytes the operation carries, for gas.
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Inbound { delivery, .. } | Self::AdmitMessage { delivery, .. } => delivery.len(),
            Self::Outbound { recipient, .. } => recipient.len(),
            Self::LightClientUpdate { update, .. } => update.len(),
            Self::SendMessage { payload, .. } => payload.len(),
            Self::DrawCommittee { .. } | Self::ReleaseExit { .. } | Self::CancelExit { .. } => 0,
            Self::ReportEquivocation { first, second, .. } => first.len() + second.len(),
            Self::ReportWrongHandover {
                members, signature, ..
            } => members.len() + signature.len(),
            Self::Ibc { msg, .. } => match msg {
                IbcMsg::Acknowledge {
                    acknowledgement,
                    proof,
                    ..
                } => acknowledgement.len() + proof.len(),
                other => other.proof().len(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_or_oversized_payload_is_refused() {
        let op = BridgeOp::Inbound {
            adapter: BridgeRouteAdapter::Ccip,
            source_chain: "ethereum".into(),
            delivery: vec![],
        };
        assert!(op.validate().is_err());
        let op = BridgeOp::SendMessage {
            target_chain: "ethereum".into(),
            payload: vec![0; MAX_BRIDGE_PAYLOAD_LEN + 1],
        };
        assert!(op.validate().is_err());
        let op = BridgeOp::Outbound {
            target_chain: "ethereum".into(),
            recipient: vec![1; 20],
            amount: 0,
            asset: None,
        };
        assert!(op.validate().is_err());
    }

    #[test]
    fn an_operation_round_trips_through_json() {
        let op = BridgeOp::Outbound {
            target_chain: "ethereum".into(),
            recipient: vec![0xAB; 20],
            amount: 5,
            asset: Some("USDC".into()),
        };
        let back: BridgeOp = serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
        assert_eq!(back, op);
        assert!(op.validate().is_ok());
    }
}
