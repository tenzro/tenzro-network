//! Tenzro's side of IBC: its IBC store, the classic handshakes, and the
//! lifecycle of the packets it sends, all in route state, so they are part
//! of consensus.
//!
//! **The store.** Every entry a Cosmos chain verifies about Tenzro lives in
//! route state under [`store_key`]`(path)`: `ibc/` followed by the hex of the
//! ICS-24 path (classic) or key (v2). The Cosmos chain's light client of
//! Tenzro proves the path `[b"ibc", path]` (Tenzro's commitment prefix is
//! `ibc`) as that route-state entry under a Tenzro state root. The store
//! holds Tenzro's connection and channel ends (classic), the commitments of
//! the packets Tenzro sent, and the receipts and acknowledgements of the
//! packets it received.
//!
//! **Handshakes (classic).** The Cosmos chain opens each handshake (its
//! `ConnOpenInit` and `ChanOpenInit` name Tenzro's identifiers, which the
//! route derives from its chain name), and Tenzro answers:
//!
//! - `connection_open_try`: the Cosmos chain's connection end is `INIT`
//!   towards Tenzro's client; Tenzro writes its end `TRYOPEN`.
//! - `connection_open_confirm`: the Cosmos end is `OPEN`; Tenzro's becomes
//!   `OPEN`.
//! - `channel_open_try` and `channel_open_confirm`: the same for the
//!   unordered `transfer` channel (`ics20-1`) on that connection.
//!
//! Each step is proven against the route's Tendermint light client
//! ([`super::tendermint::verify_store_entry`]), and every end is checked
//! against the identifiers the route's settings name. An IBC v2 route has
//! no handshake: its counterparty is the client the route's settings name.
//!
//! **Packets.** A packet Tenzro sends is committed in the store and times
//! out the route's `packet_timeout_secs` later. It settles once:
//!
//! - `acknowledge`: the Cosmos chain committed an acknowledgement of it.
//!   A success acknowledgement leaves the TNZO on the Cosmos chain; an error
//!   acknowledgement refunds the sender.
//! - `timeout`: at a height whose block time is past the packet's timeout,
//!   the Cosmos chain holds no receipt of it. The sender is refunded.
//!
//! Settling replaces the commitment with [`DELIVERED`] or [`REFUNDED`], so a
//! packet settles once, its outcome stays readable, and the Cosmos chain can
//! no longer prove it was sent. A packet
//! Tenzro receives writes its receipt and its success acknowledgement.

use tenzro_types::bridge_route::IBC_TRANSFER_PORT;
use tenzro_types::bridge_transfer::IbcMsg;

use super::ibc::{
    FungibleTokenPacketData, ICS20_VERSION, Packet, SUCCESS_ACK, ack_commitment, ack_key,
    is_error_ack, outbound_message, outbound_packet, receipt_key, receipt_value, settings,
    tenzro_account,
};
use super::state::{self, RouteState};
use super::tendermint::verify_store_entry;
use super::{BridgeRoute, IbcRoute, IbcVersion, OutboundTransfer, RouteMessage};
use crate::error::{BridgeError, Result};

/// Tenzro's commitment prefix, as a Cosmos chain's connection names it.
pub const COMMITMENT_PREFIX: &[u8] = b"ibc";

/// The value a delivered packet's commitment is replaced with.
pub const DELIVERED: [u8; 1] = [0];

/// The value a refunded packet's commitment is replaced with (an error
/// acknowledgement or a timeout).
pub const REFUNDED: [u8; 1] = [1];

/// The connection version both chains run (`1`, ordered and unordered
/// channels).
const CONNECTION_VERSION: (&str, [&str; 2]) = ("1", ["ORDER_ORDERED", "ORDER_UNORDERED"]);

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("IBC: {}", what.into()))
}

/// The route-state key of the IBC store entry at `path`.
pub fn store_key(path: &[u8]) -> String {
    format!("ibc/{}", hex::encode(path))
}

fn get(state: &dyn RouteState, path: &[u8]) -> Option<Vec<u8>> {
    state.get(&store_key(path))
}

/// The ICS-24 path of a connection end.
pub fn connection_path(id: &str) -> Vec<u8> {
    format!("connections/{id}").into_bytes()
}

/// The ICS-24 path of a channel end on the transfer port.
pub fn channel_path(id: &str) -> Vec<u8> {
    format!("channelEnds/ports/{IBC_TRANSFER_PORT}/channels/{id}").into_bytes()
}

// ---- protobuf, as the Cosmos chain marshals these messages ----

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn field_bytes(out: &mut Vec<u8>, field: u64, b: &[u8]) {
    varint(out, (field << 3) | 2);
    varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn field_str(out: &mut Vec<u8>, field: u64, s: &str) {
    if !s.is_empty() {
        field_bytes(out, field, s.as_bytes());
    }
}

fn field_uint(out: &mut Vec<u8>, field: u64, v: u64) {
    if v != 0 {
        varint(out, field << 3);
        varint(out, v);
    }
}

/// A handshake state (`ibc.core.connection.v1.State`, and the channel's
/// states with the same numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndState {
    /// `INIT`.
    Init = 1,
    /// `TRYOPEN`.
    TryOpen = 2,
    /// `OPEN`.
    Open = 3,
}

/// `ibc.core.connection.v1.ConnectionEnd`, with the connection version,
/// no delay, and the counterparty's commitment prefix `ibc`.
pub fn connection_end(
    state: EndState,
    client_id: &str,
    counterparty_client_id: &str,
    counterparty_connection_id: &str,
) -> Vec<u8> {
    let mut version = Vec::new();
    field_str(&mut version, 1, CONNECTION_VERSION.0);
    for feature in CONNECTION_VERSION.1 {
        field_str(&mut version, 2, feature);
    }
    let mut prefix = Vec::new();
    field_bytes(&mut prefix, 1, COMMITMENT_PREFIX);
    let mut counterparty = Vec::new();
    field_str(&mut counterparty, 1, counterparty_client_id);
    field_str(&mut counterparty, 2, counterparty_connection_id);
    field_bytes(&mut counterparty, 3, &prefix);
    let mut out = Vec::new();
    field_str(&mut out, 1, client_id);
    field_bytes(&mut out, 2, &version);
    field_uint(&mut out, 3, state as u64);
    field_bytes(&mut out, 4, &counterparty);
    out
}

/// `ibc.core.channel.v1.Channel`: an unordered `ics20-1` channel on the
/// transfer port with one connection hop.
pub fn channel_end(
    state: EndState,
    counterparty_channel_id: &str,
    connection_hop: &str,
) -> Vec<u8> {
    let mut counterparty = Vec::new();
    field_str(&mut counterparty, 1, IBC_TRANSFER_PORT);
    field_str(&mut counterparty, 2, counterparty_channel_id);
    let mut out = Vec::new();
    field_uint(&mut out, 1, state as u64);
    // ORDER_UNORDERED.
    field_uint(&mut out, 2, 1);
    field_bytes(&mut out, 3, &counterparty);
    field_str(&mut out, 4, connection_hop);
    field_str(&mut out, 5, ICS20_VERSION);
    out
}

/// Tenzro's identifiers and the Cosmos chain's, for a classic route.
struct Classic<'a> {
    client: String,
    connection: String,
    channel: String,
    cp_client: &'a str,
    cp_connection: &'a str,
    cp_channel: &'a str,
}

fn classic<'a>(route: &BridgeRoute, ibc: &'a IbcRoute) -> Result<Classic<'a>> {
    match (
        ibc.version,
        &ibc.counterparty_connection_id,
        &ibc.counterparty_channel_id,
    ) {
        (IbcVersion::Classic, Some(cp_connection), Some(cp_channel)) => Ok(Classic {
            client: IbcRoute::tenzro_client_id(&route.source_chain),
            connection: IbcRoute::tenzro_connection_id(&route.source_chain),
            channel: IbcRoute::tenzro_channel_id(&route.source_chain),
            cp_client: &ibc.counterparty_client_id,
            cp_connection,
            cp_channel,
        }),
        _ => Err(refuse(
            "an IBC v2 route has no connection or channel handshake",
        )),
    }
}

/// Packets travel the route: always over v2, and over classic once Tenzro's
/// channel end is open.
pub fn check_open(state: &dyn RouteState, route: &BridgeRoute) -> Result<()> {
    let ibc = settings(route)?;
    if ibc.version == IbcVersion::V2 {
        return Ok(());
    }
    let c = classic(route, ibc)?;
    if get(state, &channel_path(&c.channel))
        != Some(channel_end(EndState::Open, c.cp_channel, &c.connection))
    {
        return Err(refuse(format!("channel {} is not open", c.channel)));
    }
    Ok(())
}

/// The outbound packet for `transfer` with `sequence`, the transfer it
/// carries, and the store write committing it.
pub fn send_packet(
    state: &dyn RouteState,
    route: &BridgeRoute,
    sequence: u64,
    transfer: &OutboundTransfer,
) -> Result<(RouteMessage, Vec<u8>, (String, Vec<u8>))> {
    check_open(state, route)?;
    let ibc = settings(route)?;
    let timeout = u64::try_from(state.now_ms() / 1000)
        .map_err(|_| refuse("the clock is before 1970"))?
        .checked_add(ibc.packet_timeout_secs)
        .ok_or_else(|| refuse("timeout out of range"))?;
    let mut message = RouteMessage {
        message_id: [0u8; 32],
        source_selector: route.local_selector,
        dest_selector: route.source_chain_id,
        sequence,
        sender: transfer.sender.clone(),
        receiver: transfer.recipient.clone(),
        token_pool: route.local_endpoint,
        token: route.remote_token,
        amount: transfer.amount,
    };
    let packet = outbound_packet(route, &message, timeout)?;
    message.message_id = packet.commitment();
    let bytes = packet.encode();
    if outbound_message(route, &Packet::decode(&bytes, ibc.version)?)? != message {
        return Err(refuse("the outbound packet does not read back as built"));
    }
    let commit = (
        store_key(&packet.commitment_key()),
        packet.commitment().to_vec(),
    );
    Ok((message, bytes, commit))
}

/// The store writes for a packet Tenzro received with `sequence`: its
/// receipt and its success acknowledgement.
pub fn received_writes(route: &BridgeRoute, sequence: u64) -> Result<Vec<(String, Vec<u8>)>> {
    let ibc = settings(route)?;
    let id = ibc.tenzro_packet_id(&route.source_chain);
    Ok(vec![
        (
            store_key(&receipt_key(ibc.version, IBC_TRANSFER_PORT, &id, sequence)),
            receipt_value(ibc.version),
        ),
        (
            store_key(&ack_key(ibc.version, IBC_TRANSFER_PORT, &id, sequence)),
            ack_commitment(ibc.version, SUCCESS_ACK).to_vec(),
        ),
    ])
}

/// What an IBC message did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IbcOutcome {
    /// The message kind, as the transaction log names it.
    pub kind: &'static str,
    /// The store path written.
    pub path: Vec<u8>,
    /// For a settled packet, its sequence.
    pub sequence: Option<u64>,
    /// For a refunded packet, the Tenzro account refunded and the amount.
    pub refund: Option<([u8; 32], u128)>,
}

/// Apply a relayer's IBC message on `route`: one handshake step or the
/// settlement of an outbound packet, each on its proof against the route's
/// light client.
pub fn handle(state: &mut dyn RouteState, route: &BridgeRoute, msg: &IbcMsg) -> Result<IbcOutcome> {
    let ibc = settings(route)?;
    match msg {
        IbcMsg::ConnectionOpenTry { proof } => {
            let c = classic(route, ibc)?;
            let path = connection_path(&c.connection);
            if get(state, &path).is_some() {
                return Err(refuse(format!(
                    "connection {} already exists",
                    c.connection
                )));
            }
            let theirs = connection_end(EndState::Init, c.cp_client, &c.client, "");
            verify_store_entry(
                state,
                route,
                &connection_path(c.cp_connection),
                Some(&theirs),
                proof,
            )?;
            let ours = connection_end(EndState::TryOpen, &c.client, c.cp_client, c.cp_connection);
            state.apply(vec![(store_key(&path), ours)])?;
            Ok(IbcOutcome {
                kind: "connection_open_try",
                path,
                sequence: None,
                refund: None,
            })
        }
        IbcMsg::ConnectionOpenConfirm { proof } => {
            let c = classic(route, ibc)?;
            let path = connection_path(&c.connection);
            if get(state, &path)
                != Some(connection_end(
                    EndState::TryOpen,
                    &c.client,
                    c.cp_client,
                    c.cp_connection,
                ))
            {
                return Err(refuse(format!(
                    "connection {} is not TRYOPEN",
                    c.connection
                )));
            }
            let theirs = connection_end(EndState::Open, c.cp_client, &c.client, &c.connection);
            verify_store_entry(
                state,
                route,
                &connection_path(c.cp_connection),
                Some(&theirs),
                proof,
            )?;
            let ours = connection_end(EndState::Open, &c.client, c.cp_client, c.cp_connection);
            state.apply(vec![(store_key(&path), ours)])?;
            Ok(IbcOutcome {
                kind: "connection_open_confirm",
                path,
                sequence: None,
                refund: None,
            })
        }
        IbcMsg::ChannelOpenTry { proof } => {
            let c = classic(route, ibc)?;
            if get(state, &connection_path(&c.connection))
                != Some(connection_end(
                    EndState::Open,
                    &c.client,
                    c.cp_client,
                    c.cp_connection,
                ))
            {
                return Err(refuse(format!("connection {} is not open", c.connection)));
            }
            let path = channel_path(&c.channel);
            if get(state, &path).is_some() {
                return Err(refuse(format!("channel {} already exists", c.channel)));
            }
            let theirs = channel_end(EndState::Init, "", c.cp_connection);
            verify_store_entry(
                state,
                route,
                &channel_path(c.cp_channel),
                Some(&theirs),
                proof,
            )?;
            let ours = channel_end(EndState::TryOpen, c.cp_channel, &c.connection);
            state.apply(vec![(store_key(&path), ours)])?;
            Ok(IbcOutcome {
                kind: "channel_open_try",
                path,
                sequence: None,
                refund: None,
            })
        }
        IbcMsg::ChannelOpenConfirm { proof } => {
            let c = classic(route, ibc)?;
            let path = channel_path(&c.channel);
            if get(state, &path)
                != Some(channel_end(EndState::TryOpen, c.cp_channel, &c.connection))
            {
                return Err(refuse(format!("channel {} is not TRYOPEN", c.channel)));
            }
            let theirs = channel_end(EndState::Open, &c.channel, c.cp_connection);
            verify_store_entry(
                state,
                route,
                &channel_path(c.cp_channel),
                Some(&theirs),
                proof,
            )?;
            let ours = channel_end(EndState::Open, c.cp_channel, &c.connection);
            state.apply(vec![(store_key(&path), ours)])?;
            Ok(IbcOutcome {
                kind: "channel_open_confirm",
                path,
                sequence: None,
                refund: None,
            })
        }
        IbcMsg::Acknowledge {
            sequence,
            acknowledgement,
            proof,
        } => {
            let (packet, path) = pending(state, route, ibc, *sequence)?;
            let key = ack_key(
                ibc.version,
                IBC_TRANSFER_PORT,
                ibc.counterparty_packet_id(),
                *sequence,
            );
            verify_store_entry(
                state,
                route,
                &key,
                Some(&ack_commitment(ibc.version, acknowledgement)),
                proof,
            )?;
            let refund = if acknowledgement.as_slice() == SUCCESS_ACK {
                None
            } else if is_error_ack(ibc.version, acknowledgement) {
                Some(refund_of(route, &packet)?)
            } else {
                return Err(refuse(
                    "the acknowledgement is neither a success nor an error acknowledgement",
                ));
            };
            settle(state, route, &path, refund)?;
            Ok(IbcOutcome {
                kind: "acknowledge",
                path,
                sequence: Some(*sequence),
                refund,
            })
        }
        IbcMsg::Timeout { sequence, proof } => {
            let (packet, path) = pending(state, route, ibc, *sequence)?;
            let key = receipt_key(
                ibc.version,
                IBC_TRANSFER_PORT,
                ibc.counterparty_packet_id(),
                *sequence,
            );
            let proof_time_ns = verify_store_entry(state, route, &key, None, proof)?;
            if proof_time_ns < packet.timeout_ns() {
                return Err(refuse("the proof's block is before the packet's timeout"));
            }
            let refund = Some(refund_of(route, &packet)?);
            settle(state, route, &path, refund)?;
            Ok(IbcOutcome {
                kind: "timeout",
                path,
                sequence: Some(*sequence),
                refund,
            })
        }
    }
}

/// Outbound packet `sequence` and its commitment path, while it is unsettled.
fn pending(
    state: &dyn RouteState,
    route: &BridgeRoute,
    ibc: &IbcRoute,
    sequence: u64,
) -> Result<(Packet, Vec<u8>)> {
    let bytes = state
        .get(&state::outbound_key(route, sequence))
        .ok_or_else(|| refuse(format!("no outbound packet {sequence}")))?;
    let packet = Packet::decode(&bytes, ibc.version)?;
    let path = packet.commitment_key();
    if get(state, &path).as_deref() != Some(packet.commitment().as_slice()) {
        return Err(refuse(format!("packet {sequence} is already settled")));
    }
    Ok((packet, path))
}

fn refund_of(route: &BridgeRoute, packet: &Packet) -> Result<([u8; 32], u128)> {
    let data = FungibleTokenPacketData::decode(&packet.data, packet.version)?;
    let sender: [u8; 32] = tenzro_account(&data.sender)?
        .try_into()
        .map_err(|_| refuse("the sender is not a 32-byte account"))?;
    let message = outbound_message(route, packet)?;
    Ok((sender, message.amount))
}

/// Mark the packet at `path` settled and, for a refund, return its amount
/// from the route's outstanding supply.
fn settle(
    state: &mut dyn RouteState,
    route: &BridgeRoute,
    path: &[u8],
    refund: Option<([u8; 32], u128)>,
) -> Result<()> {
    let marker = if refund.is_some() {
        REFUNDED
    } else {
        DELIVERED
    };
    let mut writes = vec![(store_key(path), marker.to_vec())];
    if let Some((_, amount)) = refund {
        let supply = state::read_supply(state, route).release(amount, route)?;
        writes.push((state::supply_key(route), supply.encode()));
    }
    state.apply(writes)
}

/// The state of a route's IBC store, for reading back over RPC.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IbcStatus {
    /// `classic` or `v2`.
    pub version: &'static str,
    /// Tenzro's light client of the route's chain.
    pub client_id: String,
    /// Tenzro's identifier packets name for its end.
    pub packet_id: String,
    /// Classic: Tenzro's connection end and its state.
    pub connection: Option<(String, Option<&'static str>)>,
    /// Classic: Tenzro's channel end and its state.
    pub channel: Option<(String, Option<&'static str>)>,
}

fn end_state<F: Fn(EndState) -> Vec<u8>>(value: Option<Vec<u8>>, end: F) -> Option<&'static str> {
    let value = value?;
    [
        (EndState::Init, "INIT"),
        (EndState::TryOpen, "TRYOPEN"),
        (EndState::Open, "OPEN"),
    ]
    .into_iter()
    .find(|(s, _)| end(*s) == value)
    .map(|(_, name)| name)
}

/// Where `route`'s IBC handshakes stand.
pub fn status(state: &dyn RouteState, route: &BridgeRoute) -> Result<IbcStatus> {
    let ibc = settings(route)?;
    let (connection, channel) = match classic(route, ibc) {
        Ok(c) => (
            Some((
                c.connection.clone(),
                end_state(get(state, &connection_path(&c.connection)), |s| {
                    connection_end(s, &c.client, c.cp_client, c.cp_connection)
                }),
            )),
            Some((
                c.channel.clone(),
                end_state(get(state, &channel_path(&c.channel)), |s| {
                    channel_end(s, c.cp_channel, &c.connection)
                }),
            )),
        ),
        Err(_) => (None, None),
    };
    Ok(IbcStatus {
        version: ibc.version.as_str(),
        client_id: IbcRoute::tenzro_client_id(&route.source_chain),
        packet_id: ibc.tenzro_packet_id(&route.source_chain),
        connection,
        channel,
    })
}

/// Where an outbound packet stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketState {
    /// Sent, neither acknowledged nor timed out.
    Pending,
    /// Acknowledged with success: the Cosmos chain credited the receiver.
    Delivered,
    /// Acknowledged with an error, or timed out: the sender was refunded.
    Refunded,
}

impl PacketState {
    /// The name RPC reads give it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Refunded => "refunded",
        }
    }
}

/// An outbound packet: where it stands, who sent it, how much it carried,
/// and its commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketOutcome {
    /// Where it stands.
    pub state: PacketState,
    /// The Tenzro account that sent it.
    pub sender: [u8; 32],
    /// What it carried, base units.
    pub amount: u128,
    /// The packet commitment it was sent under.
    pub commitment: [u8; 32],
}

/// Outbound packet `sequence` of `route`, and where it stands.
pub fn packet_outcome(
    state: &dyn RouteState,
    route: &BridgeRoute,
    sequence: u64,
) -> Result<PacketOutcome> {
    let ibc = settings(route)?;
    let bytes = state
        .get(&state::outbound_key(route, sequence))
        .ok_or_else(|| refuse(format!("no outbound packet {sequence}")))?;
    let packet = Packet::decode(&bytes, ibc.version)?;
    let (sender, amount) = refund_of(route, &packet)?;
    let commitment = packet.commitment();
    let state = match get(state, &packet.commitment_key()) {
        Some(v) if v == commitment => PacketState::Pending,
        Some(v) if v == DELIVERED => PacketState::Delivered,
        Some(v) if v == REFUNDED => PacketState::Refunded,
        _ => return Err(refuse(format!("packet {sequence} has no commitment"))),
    };
    Ok(PacketOutcome {
        state,
        sender,
        amount,
        commitment,
    })
}

/// Where outbound packet `sequence` of `route` stands: `pending`, then
/// `delivered` or `refunded`.
pub fn packet_status(
    state: &dyn RouteState,
    route: &BridgeRoute,
    sequence: u64,
) -> Result<&'static str> {
    packet_outcome(state, route, sequence).map(|o| o.state.as_str())
}
