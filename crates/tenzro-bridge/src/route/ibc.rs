//! The IBC adapter: ICS-20 fungible-token packets between Tenzro and a
//! Cosmos chain, over IBC classic or IBC v2 as the route's settings
//! ([`IbcRoute`]) declare.
//!
//! A packet is the same in both versions, and so is how it is committed and
//! proven; only what it travels on differs. In IBC classic its ends are a
//! port and a channel on each chain, the channel opened by the handshakes
//! [`super::ibc_core`] keeps; in IBC v2 its ends are a port and the light
//! client each chain holds of the other, and the payload names its version
//! (`ics20-1`) and encoding (`application/json`).
//!
//! A delivery's body is one packet, written field by field:
//!
//! ```text
//! sequence                 u64 big-endian
//! source_port              u16 length + ASCII
//! source_channel           u16 length + ASCII   the channel (classic) or client (v2)
//! destination_port         u16 length + ASCII
//! destination_channel      u16 length + ASCII   the channel (classic) or client (v2)
//! data                     u32 length + bytes   ICS-20 packet data (JSON)
//! timeout_revision_number  u64 big-endian       zero in v2
//! timeout_revision_height  u64 big-endian       zero in v2
//! timeout_timestamp        u64 big-endian       Unix nanoseconds (classic), seconds (v2)
//! ```
//!
//! The data is the ICS-20 `FungibleTokenPacketData` exactly as the transfer
//! module writes it for the version: in classic, compact JSON with the keys
//! `amount`, `denom`, `memo`, `receiver` and `sender` in that order; in v2,
//! compact JSON with `denom`, `amount`, `sender`, `receiver` and, when it is
//! not empty, `memo`. Any other spelling of the same values is refused.
//!
//! The commitment the sending chain stores, and its key, follow the version:
//! classic stores the SHA-256 of the timeout and the data's hash under the
//! ICS-24 path `commitments/ports/{port}/channels/{channel}/sequences/{n}`;
//! v2 stores the SHA-256 over the destination client, the timeout and the
//! payload's hash under `{client} 0x01 {n}`. Receipts and acknowledgements
//! sit beside them ([`receipt_key`], [`ack_key`]).
//!
//! On the route, `peer` and `local_endpoint` are the SHA-256 of the Cosmos
//! chain's and Tenzro's end (`transfer/{id}`), `ramp` is the ASCII name of the
//! store in the Cosmos chain's multistore that holds IBC state (`ibc`), and
//! `remote_token` is the SHA-256 of TNZO's denomination trace on the Cosmos
//! chain, `transfer/{id}/atnzo` for the Cosmos end.
//!
//! **Inbound** packets return TNZO: their denomination must be that trace,
//! and they may time out only by timestamp. The message id is the packet
//! commitment the Cosmos chain stored, which the route's Tendermint light
//! client proves ([`super::tendermint`]). **Outbound** packets send `atnzo`
//! from Tenzro's end and time out the route's `packet_timeout_secs` after
//! they are sent; [`super::ibc_core`] builds and commits them.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::canonical::{Reader, Writer};
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, IbcRoute, IbcVersion, RouteAdapter, RouteMessage,
};
use crate::error::{BridgeError, Result};
use tenzro_types::bridge_route::IBC_TRANSFER_PORT;

/// TNZO's base denomination on IBC (one unit is 10^-18 TNZO).
pub const IBC_TNZO_DENOM: &str = "atnzo";

/// Largest ICS-20 packet data accepted.
pub const MAX_PACKET_DATA: usize = 4 * 1024;

/// The ICS-20 version a v2 payload names.
pub const ICS20_VERSION: &str = "ics20-1";

/// The encoding a v2 payload names.
pub const ICS20_ENCODING: &str = "application/json";

/// The acknowledgement of a packet the transfer module accepted, in both
/// versions.
pub const SUCCESS_ACK: &[u8] = br#"{"result":"AQ=="}"#;

/// Longest port identifier (ICS-24).
const MAX_PORT_LEN: usize = 128;

/// Longest sender or receiver string.
const MAX_ACCOUNT_LEN: usize = 128;

/// Longest acknowledgement accepted.
pub const MAX_ACK_LEN: usize = 1024;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("IBC packet: {}", what.into()))
}

/// ICS-24 identifier characters.
fn identifier(s: &str, min: usize, max: usize) -> Result<()> {
    let ok = (min..=max).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_+#[]<>".contains(&b));
    if ok {
        Ok(())
    } else {
        Err(bad(format!("'{s}' is not an ICS-24 identifier")))
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// One IBC packet. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The IBC version the packet travels (not part of its encoding: the
    /// route declares it).
    pub version: IbcVersion,
    /// The packet's sequence.
    pub sequence: u64,
    /// Port on the sending chain.
    pub source_port: String,
    /// Channel (classic) or client (v2) on the sending chain.
    pub source_channel: String,
    /// Port on the receiving chain.
    pub destination_port: String,
    /// Channel (classic) or client (v2) on the receiving chain.
    pub destination_channel: String,
    /// Application data.
    pub data: Vec<u8>,
    /// Timeout height, revision number (classic only).
    pub timeout_revision_number: u64,
    /// Timeout height, revision height (classic only).
    pub timeout_revision_height: u64,
    /// Timeout: Unix nanoseconds (classic) or seconds (v2).
    pub timeout_timestamp: u64,
}

impl Packet {
    /// The body encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(self.sequence)
            .be_str(&self.source_port)
            .be_str(&self.source_channel)
            .be_str(&self.destination_port)
            .be_str(&self.destination_channel)
            .be_bytes(&self.data)
            .u64_be(self.timeout_revision_number)
            .u64_be(self.timeout_revision_height)
            .u64_be(self.timeout_timestamp);
        w.into_bytes()
    }

    /// Read one packet of `version`.
    pub fn read(r: &mut Reader<'_>, version: IbcVersion) -> Result<Self> {
        let p = Self {
            version,
            sequence: r.u64_be()?,
            source_port: r.be_str(MAX_PORT_LEN)?,
            source_channel: r.be_str(64)?,
            destination_port: r.be_str(MAX_PORT_LEN)?,
            destination_channel: r.be_str(64)?,
            data: r.be_bytes(MAX_PACKET_DATA)?.to_vec(),
            timeout_revision_number: r.u64_be()?,
            timeout_revision_height: r.u64_be()?,
            timeout_timestamp: r.u64_be()?,
        };
        identifier(&p.source_port, 2, MAX_PORT_LEN)?;
        identifier(&p.destination_port, 2, MAX_PORT_LEN)?;
        let id_min = match version {
            IbcVersion::Classic => 8,
            IbcVersion::V2 => 9,
        };
        identifier(&p.source_channel, id_min, 64)?;
        identifier(&p.destination_channel, id_min, 64)?;
        if p.sequence == 0 {
            return Err(bad("sequence 0"));
        }
        match version {
            IbcVersion::Classic => {
                if p.timeout_timestamp == 0 && p.timeout_revision_height == 0 {
                    return Err(bad("a packet needs a timeout"));
                }
            }
            IbcVersion::V2 => {
                if p.timeout_timestamp == 0
                    || p.timeout_revision_number != 0
                    || p.timeout_revision_height != 0
                {
                    return Err(bad("a v2 packet times out by timestamp only"));
                }
            }
        }
        Ok(p)
    }

    /// Decode a complete body of `version`.
    pub fn decode(body: &[u8], version: IbcVersion) -> Result<Self> {
        let mut r = Reader::new(body);
        let p = Self::read(&mut r, version)?;
        r.finish()?;
        Ok(p)
    }

    /// The packet's timestamp timeout in Unix nanoseconds; `i128::MAX` for a
    /// classic packet that times out by height only.
    pub fn timeout_ns(&self) -> i128 {
        match (self.version, self.timeout_timestamp) {
            (IbcVersion::Classic, 0) => i128::MAX,
            (IbcVersion::Classic, ts) => i128::from(ts),
            (IbcVersion::V2, ts) => i128::from(ts) * 1_000_000_000,
        }
    }

    /// The commitment the sending chain stores for the packet.
    pub fn commitment(&self) -> [u8; 32] {
        match self.version {
            IbcVersion::Classic => sha256(&[
                &self.timeout_timestamp.to_be_bytes(),
                &self.timeout_revision_number.to_be_bytes(),
                &self.timeout_revision_height.to_be_bytes(),
                &sha256(&[&self.data]),
            ]),
            IbcVersion::V2 => {
                let payload = sha256(&[
                    &sha256(&[self.source_port.as_bytes()]),
                    &sha256(&[self.destination_port.as_bytes()]),
                    &sha256(&[ICS20_VERSION.as_bytes()]),
                    &sha256(&[ICS20_ENCODING.as_bytes()]),
                    &sha256(&[&self.data]),
                ]);
                sha256(&[
                    &[2],
                    &sha256(&[self.destination_channel.as_bytes()]),
                    &sha256(&[&self.timeout_timestamp.to_be_bytes()]),
                    &sha256(&[&payload]),
                ])
            }
        }
    }

    /// The key the sending chain stores the commitment under.
    pub fn commitment_key(&self) -> Vec<u8> {
        packet_key(
            self.version,
            "commitments",
            1,
            &self.source_port,
            &self.source_channel,
            self.sequence,
        )
    }
}

fn packet_key(
    version: IbcVersion,
    kind: &str,
    v2_prefix: u8,
    port: &str,
    id: &str,
    sequence: u64,
) -> Vec<u8> {
    match version {
        IbcVersion::Classic => {
            format!("{kind}/ports/{port}/channels/{id}/sequences/{sequence}").into_bytes()
        }
        IbcVersion::V2 => {
            let mut k = id.as_bytes().to_vec();
            k.push(v2_prefix);
            k.extend_from_slice(&sequence.to_be_bytes());
            k
        }
    }
}

/// Where the receiving chain records that it received packet `sequence` at
/// its end `(port, id)`.
pub fn receipt_key(version: IbcVersion, port: &str, id: &str, sequence: u64) -> Vec<u8> {
    packet_key(version, "receipts", 2, port, id, sequence)
}

/// The value of a receipt.
pub fn receipt_value(version: IbcVersion) -> Vec<u8> {
    match version {
        IbcVersion::Classic => vec![1],
        IbcVersion::V2 => vec![2],
    }
}

/// Where the receiving chain commits its acknowledgement of packet
/// `sequence` at its end `(port, id)`.
pub fn ack_key(version: IbcVersion, port: &str, id: &str, sequence: u64) -> Vec<u8> {
    packet_key(version, "acks", 3, port, id, sequence)
}

/// The commitment of an acknowledgement (one payload in v2).
pub fn ack_commitment(version: IbcVersion, ack: &[u8]) -> [u8; 32] {
    match version {
        IbcVersion::Classic => sha256(&[ack]),
        IbcVersion::V2 => sha256(&[&[2], &sha256(&[ack])]),
    }
}

/// Whether `ack` is a well-formed acknowledgement that the receiving chain
/// refused the packet: `{"error":"..."}` in classic, the universal error
/// acknowledgement in v2.
pub fn is_error_ack(version: IbcVersion, ack: &[u8]) -> bool {
    match version {
        IbcVersion::Classic => serde_json::from_slice::<serde_json::Value>(ack).is_ok_and(|v| {
            v.as_object()
                .is_some_and(|o| o.len() == 1 && o.get("error").is_some_and(|e| e.is_string()))
        }),
        IbcVersion::V2 => ack == sha256(&[b"UNIVERSAL_ERROR_ACKNOWLEDGEMENT"]),
    }
}

/// ICS-20 packet data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FungibleTokenPacketData {
    /// Decimal amount.
    pub amount: String,
    /// Denomination trace.
    pub denom: String,
    /// Free-form memo, ignored here.
    pub memo: String,
    /// Recipient on the receiving chain.
    pub receiver: String,
    /// Sender on the sending chain.
    pub sender: String,
}

impl FungibleTokenPacketData {
    /// The transfer module's JSON for `version`.
    pub fn encode(&self, version: IbcVersion) -> Vec<u8> {
        match version {
            IbcVersion::Classic => serde_json::to_vec(self).expect("strings serialize"),
            IbcVersion::V2 => {
                let s = |v: &str| serde_json::to_string(v).expect("strings serialize");
                let memo = if self.memo.is_empty() {
                    String::new()
                } else {
                    format!(r#","memo":{}"#, s(&self.memo))
                };
                format!(
                    r#"{{"denom":{},"amount":{},"sender":{},"receiver":{}{memo}}}"#,
                    s(&self.denom),
                    s(&self.amount),
                    s(&self.sender),
                    s(&self.receiver)
                )
                .into_bytes()
            }
        }
    }

    /// Parse packet data of `version`, refusing any spelling but the
    /// transfer module's.
    pub fn decode(data: &[u8], version: IbcVersion) -> Result<Self> {
        let d: Self = match version {
            IbcVersion::Classic => {
                serde_json::from_slice(data).map_err(|e| bad(format!("data: {e}")))?
            }
            IbcVersion::V2 => {
                let v: serde_json::Map<String, serde_json::Value> =
                    serde_json::from_slice(data).map_err(|e| bad(format!("data: {e}")))?;
                let field = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
                Self {
                    amount: field("amount").ok_or_else(|| bad("data has no amount"))?,
                    denom: field("denom").ok_or_else(|| bad("data has no denom"))?,
                    memo: field("memo").unwrap_or_default(),
                    receiver: field("receiver").ok_or_else(|| bad("data has no receiver"))?,
                    sender: field("sender").ok_or_else(|| bad("data has no sender"))?,
                }
            }
        };
        if d.encode(version) != data {
            return Err(bad("data is not in the transfer module's canonical form"));
        }
        if d.sender.is_empty()
            || d.sender.len() > MAX_ACCOUNT_LEN
            || d.receiver.is_empty()
            || d.receiver.len() > MAX_ACCOUNT_LEN
        {
            return Err(bad("sender and receiver must be 1 to 128 bytes"));
        }
        Ok(d)
    }

    /// The amount, a positive decimal without leading zeros.
    pub fn amount(&self) -> Result<u128> {
        let a = &self.amount;
        if a.is_empty() || !a.bytes().all(|b| b.is_ascii_digit()) || a.starts_with('0') {
            return Err(bad(format!("amount '{a}' is not a positive decimal")));
        }
        a.parse::<u128>()
            .map_err(|_| bad("amount does not fit in 128 bits"))
    }
}

/// The IBC settings of `route`.
pub fn settings(route: &BridgeRoute) -> Result<&IbcRoute> {
    route
        .ibc
        .as_ref()
        .ok_or_else(|| bad("the route has no IBC settings"))
}

/// The Tenzro account a packet's sender or receiver string names.
pub fn tenzro_account(s: &str) -> Result<Vec<u8>> {
    let hex_part = s
        .strip_prefix("0x")
        .filter(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| bad("receiver must be a 0x-prefixed lowercase 32-byte Tenzro account"))?;
    hex::decode(hex_part).map_err(|_| bad("receiver is not hex"))
}

fn printable(b: &[u8]) -> Result<String> {
    if b.is_empty() || b.len() > MAX_ACCOUNT_LEN || !b.iter().all(|c| c.is_ascii_graphic()) {
        return Err(bad(
            "a Cosmos account must be 1 to 128 printable ASCII bytes",
        ));
    }
    Ok(String::from_utf8(b.to_vec()).expect("ASCII"))
}

/// The packet sending `msg` from Tenzro over `route`, timing out at
/// `timeout_secs` (Unix seconds).
pub fn outbound_packet(
    route: &BridgeRoute,
    msg: &RouteMessage,
    timeout_secs: u64,
) -> Result<Packet> {
    let ibc = settings(route)?;
    let sender: [u8; 32] = msg
        .sender
        .as_slice()
        .try_into()
        .map_err(|_| bad("the Tenzro sender must be a 32-byte account"))?;
    let data = FungibleTokenPacketData {
        amount: msg.amount.to_string(),
        denom: IBC_TNZO_DENOM.to_string(),
        memo: String::new(),
        receiver: printable(&msg.receiver)?,
        sender: format!("0x{}", hex::encode(sender)),
    };
    Ok(Packet {
        version: ibc.version,
        sequence: msg.sequence,
        source_port: IBC_TRANSFER_PORT.into(),
        source_channel: ibc.tenzro_packet_id(&route.source_chain),
        destination_port: IBC_TRANSFER_PORT.into(),
        destination_channel: ibc.counterparty_packet_id().to_string(),
        data: data.encode(ibc.version),
        timeout_revision_number: 0,
        timeout_revision_height: 0,
        timeout_timestamp: match ibc.version {
            IbcVersion::Classic => timeout_secs
                .checked_mul(1_000_000_000)
                .ok_or_else(|| bad("timeout out of range"))?,
            IbcVersion::V2 => timeout_secs,
        },
    })
}

/// The transfer an outbound packet of `route` carries: the packet must be
/// Tenzro's, from the route's end to the Cosmos chain's, sending `atnzo`.
pub fn outbound_message(route: &BridgeRoute, p: &Packet) -> Result<RouteMessage> {
    let ibc = settings(route)?;
    if p.version != ibc.version
        || p.source_port != IBC_TRANSFER_PORT
        || p.source_channel != ibc.tenzro_packet_id(&route.source_chain)
        || p.destination_port != IBC_TRANSFER_PORT
        || p.destination_channel != ibc.counterparty_packet_id()
    {
        return Err(bad("the packet is not one of the route's outbound packets"));
    }
    let data = FungibleTokenPacketData::decode(&p.data, p.version)?;
    if data.denom != IBC_TNZO_DENOM {
        return Err(bad("an outbound packet sends atnzo"));
    }
    Ok(RouteMessage {
        message_id: p.commitment(),
        source_selector: route.local_selector,
        dest_selector: route.source_chain_id,
        sequence: p.sequence,
        sender: tenzro_account(&data.sender)?,
        amount: data.amount()?,
        receiver: data.receiver.into_bytes(),
        token_pool: route.local_endpoint,
        token: route.remote_token,
    })
}

/// The IBC adapter. See the module docs.
pub struct IbcAdapter;

impl RouteAdapter for IbcAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Ibc
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Cosmos
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let ibc = settings(route)?;
        let p = Packet::read(r, ibc.version)?;
        if p.source_port != IBC_TRANSFER_PORT || p.source_channel != ibc.counterparty_packet_id() {
            return Err(bad(
                "packet was not sent from the route's end on the Cosmos chain",
            ));
        }
        if p.destination_port != IBC_TRANSFER_PORT
            || p.destination_channel != ibc.tenzro_packet_id(&route.source_chain)
        {
            return Err(bad("packet is not addressed to the route's end on Tenzro"));
        }
        if p.timeout_revision_number != 0 || p.timeout_revision_height != 0 {
            return Err(bad("a packet to Tenzro may time out only by timestamp"));
        }
        let data = FungibleTokenPacketData::decode(&p.data, ibc.version)?;
        let trace = ibc.tnzo_trace();
        if data.denom != trace || Sha256::digest(trace.as_bytes()).as_slice() != route.remote_token
        {
            return Err(bad(format!(
                "denomination '{}' is not returning TNZO",
                data.denom
            )));
        }
        Ok(RouteMessage {
            message_id: p.commitment(),
            source_selector: route.source_chain_id,
            dest_selector: route.local_selector,
            sequence: p.sequence,
            sender: data.sender.as_bytes().to_vec(),
            receiver: tenzro_account(&data.receiver)?,
            token_pool: IbcRoute::end_hash(&p.source_channel),
            token: IbcRoute::end_hash(&p.destination_channel),
            amount: data.amount()?,
        })
    }

    fn encode_outbound(&self, _route: &BridgeRoute, _msg: &RouteMessage) -> Result<Vec<u8>> {
        Err(bad(
            "an outbound packet is built with its timeout by the IBC layer",
        ))
    }

    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        outbound_message(route, &Packet::read(r, settings(route)?.version)?)
    }

    fn outbound_message_id(&self, _route: &BridgeRoute, _msg: &RouteMessage) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    /// CometBFT finalizes a block when it is committed.
    fn finality_depth(&self, _route: &BridgeRoute) -> Result<u64> {
        Ok(0)
    }
}
