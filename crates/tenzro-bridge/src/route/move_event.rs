//! What Tenzro's bridge module on a Move chain (Sui, Aptos) emits and
//! accepts, in BCS.
//!
//! The module is `bridge`, published at the route's `ramp`. A transfer to
//! Tenzro emits the event `<ramp>::bridge::TransferOut`; a transfer from
//! Tenzro is executed from a `TransferIn` record. Both are the same fixed
//! BCS struct:
//!
//! ```text
//! sequence         u64      per-route transfer number
//! source_selector  u64      the sending chain's identifier on the route
//! dest_selector    u64      the receiving chain's identifier on the route
//! sender           address  the account that sent it (32 bytes)
//! token            address  inbound: the representation burned (the route's
//!                           `peer`); outbound: the representation to mint
//!                           (the route's `remote_token`)
//! endpoint         address  inbound: the Tenzro endpoint (the route's
//!                           `local_endpoint`); outbound: the module's
//!                           address (the route's `ramp`)
//! recipient        address  the account credited (32 bytes)
//! amount           u128     in TNZO's smallest unit
//! ```
//!
//! The message id is the Keccak-256 of a domain tag, the chain family and
//! the record.

use sha3::{Digest, Keccak256};

use super::canonical::{Reader, Writer};
use super::{BridgeRoute, ChainFamily, RouteMessage};
use crate::error::{BridgeError, Result};

/// The bridge module's name.
pub const MODULE: &str = "bridge";

/// The event a transfer to Tenzro emits.
pub const TRANSFER_OUT: &str = "TransferOut";

/// Deepest type tag accepted.
const MAX_TYPE_DEPTH: usize = 8;

/// Longest Move identifier accepted.
const MAX_IDENTIFIER: usize = 128;

/// Most type arguments accepted at one level.
const MAX_TYPE_ARGS: usize = 16;

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("Move event: {}", what.into()))
}

/// A Move identifier: a BCS string of ASCII letters, digits and `_`.
pub fn read_identifier(r: &mut Reader<'_>) -> Result<String> {
    let b = r.bcs_bytes(MAX_IDENTIFIER)?;
    if b.is_empty() || !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_') {
        return Err(bad("an identifier must be ASCII letters, digits or '_'"));
    }
    Ok(String::from_utf8(b.to_vec()).expect("ASCII"))
}

/// A Move struct tag: address, module, name, type arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructTag {
    pub address: [u8; 32],
    pub module: String,
    pub name: String,
    /// Number of type arguments; their contents are skipped.
    pub type_args: usize,
}

impl StructTag {
    /// Read a struct tag (inside a type tag, nested to `depth`).
    pub fn read(r: &mut Reader<'_>, depth: usize) -> Result<Self> {
        if depth > MAX_TYPE_DEPTH {
            return Err(bad("type nested too deep"));
        }
        let address = r.array()?;
        let module = read_identifier(r)?;
        let name = read_identifier(r)?;
        let type_args = r.uleb128(MAX_TYPE_ARGS)?;
        for _ in 0..type_args {
            skip_type_tag(r, depth + 1)?;
        }
        Ok(Self {
            address,
            module,
            name,
            type_args,
        })
    }

    /// Write a struct tag without type arguments.
    pub fn write(&self, w: &mut Writer) {
        w.raw(&self.address)
            .bcs_bytes(self.module.as_bytes())
            .bcs_bytes(self.name.as_bytes())
            .uleb128(0);
    }

    /// Whether this is `<ramp>::bridge::TransferOut` with no type arguments.
    pub fn is_transfer_out(&self, ramp: &[u8; 32]) -> bool {
        self.address == *ramp
            && self.module == MODULE
            && self.name == TRANSFER_OUT
            && self.type_args == 0
    }
}

/// Skip one Move type tag.
pub fn skip_type_tag(r: &mut Reader<'_>, depth: usize) -> Result<()> {
    if depth > MAX_TYPE_DEPTH {
        return Err(bad("type nested too deep"));
    }
    match r.uleb128(10)? {
        // bool, u8, u64, u128, address, signer, u16, u32, u256
        0..=5 | 8..=10 => Ok(()),
        // vector<T>
        6 => skip_type_tag(r, depth + 1),
        // struct
        7 => StructTag::read(r, depth + 1).map(|_| ()),
        _ => unreachable!("uleb128 bounded to 10"),
    }
}

/// A type tag that must be a struct.
pub fn read_struct_type_tag(r: &mut Reader<'_>) -> Result<StructTag> {
    if r.uleb128(10)? != 7 {
        return Err(bad("the event type is not a struct"));
    }
    StructTag::read(r, 1)
}

/// The record a transfer carries in either direction. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveTransfer {
    pub sequence: u64,
    pub source_selector: u64,
    pub dest_selector: u64,
    pub sender: [u8; 32],
    pub token: [u8; 32],
    pub endpoint: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u128,
}

impl MoveTransfer {
    /// BCS encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_le(self.sequence)
            .u64_le(self.source_selector)
            .u64_le(self.dest_selector)
            .raw(&self.sender)
            .raw(&self.token)
            .raw(&self.endpoint)
            .raw(&self.recipient)
            .u128_le(self.amount);
        w.into_bytes()
    }

    /// Read the record.
    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            sequence: r.u64_le()?,
            source_selector: r.u64_le()?,
            dest_selector: r.u64_le()?,
            sender: r.array()?,
            token: r.array()?,
            endpoint: r.array()?,
            recipient: r.array()?,
            amount: r.u128_le()?,
        })
    }

    /// Decode a complete record.
    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let t = Self::read(&mut r)?;
        r.finish()?;
        Ok(t)
    }

    /// The inbound route message this record carries.
    pub fn inbound(&self, family: ChainFamily, body: &[u8]) -> RouteMessage {
        RouteMessage {
            message_id: message_id(family, body),
            source_selector: self.source_selector,
            dest_selector: self.dest_selector,
            sequence: self.sequence,
            sender: self.sender.to_vec(),
            receiver: self.recipient.to_vec(),
            token_pool: self.token,
            token: self.endpoint,
            amount: self.amount,
        }
    }

    /// The outbound record for `msg` on `route`.
    pub fn outbound(route: &BridgeRoute, msg: &RouteMessage) -> Result<Self> {
        let account = |b: &[u8], what: &str| -> Result<[u8; 32]> {
            b.try_into()
                .map_err(|_| bad(format!("the {what} must be a 32-byte account")))
        };
        Ok(Self {
            sequence: msg.sequence,
            source_selector: msg.source_selector,
            dest_selector: msg.dest_selector,
            sender: account(&msg.sender, "sender")?,
            token: msg.token,
            endpoint: route.ramp,
            recipient: account(&msg.receiver, "recipient")?,
            amount: msg.amount,
        })
    }

    /// The route message an outbound record reads back as.
    pub fn read_back(&self, route: &BridgeRoute) -> Result<RouteMessage> {
        if self.endpoint != route.ramp {
            return Err(bad("the outbound record names another module"));
        }
        Ok(RouteMessage {
            message_id: message_id(route.family, &self.encode()),
            source_selector: self.source_selector,
            dest_selector: self.dest_selector,
            sequence: self.sequence,
            sender: self.sender.to_vec(),
            receiver: self.recipient.to_vec(),
            token_pool: route.local_endpoint,
            token: self.token,
            amount: self.amount,
        })
    }
}

/// Keccak-256 of the contract-message domain, the family and `body`.
pub fn message_id(family: ChainFamily, body: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"tenzro/bridge/contract-message/");
    h.update(family.as_str().as_bytes());
    h.update(body);
    h.finalize().into()
}
