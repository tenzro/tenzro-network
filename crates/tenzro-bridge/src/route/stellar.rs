//! Stellar: the bridge contract's events, proven from ledgers the governed
//! validator quorum externalized through SCP.
//!
//! **Messages.** A delivery's body is one Soroban `ContractEvent` in XDR. It
//! must be a contract event of the contract at the route's `ramp`, with the
//! single topic `Symbol("transfer_out")` and as data the bytes of the
//! transfer record, the fields of [`super::move_event`] written big-endian:
//!
//! ```text
//! sequence u64, source_selector u64, dest_selector u64, sender 32,
//! token 32, endpoint 32, recipient 32, amount u128
//! ```
//!
//! Outbound transfers are that record, which the contract executes. An
//! externalized ledger is final, so the finality depth is 0.
//!
//! **Light client.** The route's anchor names the network, a set of
//! validator node keys and a threshold. Ledger N is accepted when at least
//! the threshold of those validators signed an SCP `EXTERNALIZE` statement
//! for slot N + 1 with one and the same value: that value's transaction set
//! names ledger N's header hash as its previous ledger. Each signature is
//! Ed25519 over the network id, the SCP envelope type and the statement.
//!
//! A message proof carries those statements, the transaction set, ledger
//! N's header, its transaction result set (whose hash the header names), the
//! transaction's and the operation's positions, and the
//! `InvokeHostFunctionSuccessPreImage` (return value and events) whose hash
//! the operation's success result is, with the event's position. Every
//! result in the set and every event in the preimage is parsed in full, so
//! a position always names a real result and a real event.
//!
//! The quorum is set by governance; it moves only when governance replaces
//! the route's anchor, so the client has no updates.
//!
//! Encodings (big-endian):
//!
//! ```text
//! proof = count:u8 { envelope:bytes } tx_set:bytes header:bytes results:bytes
//!         tx_index:u32 op_index:u32 preimage:bytes event_index:u32
//! ```

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::attestation::{MAX_PROOF_LEN, body_hash};
use super::canonical::{Reader, Writer};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::move_event::{MoveTransfer, message_id};
use super::state::RouteState;
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, LightClientAnchor, LightClientKind, RouteAdapter,
    RouteMessage,
};
use crate::error::{BridgeError, Result};

/// The topic of a transfer event.
pub const TRANSFER_OUT_TOPIC: &str = "transfer_out";

const ENVELOPE_TYPE_SCP: u32 = 1;
const SCP_ST_EXTERNALIZE: u32 = 2;
const CONTRACT_EVENT: u32 = 1;
const INVOKE_HOST_FUNCTION: i32 = 24;
const RECORD_LEN: usize = 8 * 3 + 32 * 4 + 16;
const MAX_DEPTH: usize = 16;
const MAX_ITEMS: usize = 1 << 16;
const MAX_OPAQUE: usize = 256 * 1024;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("stellar light client: {}", what.into()))
}

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("stellar event: {}", what.into()))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

// ---- XDR ----

struct Xdr<'a, 'b>(&'b mut Reader<'a>);

impl<'a> Xdr<'a, '_> {
    fn u32(&mut self) -> Result<u32> {
        self.0.u32_be()
    }
    fn i32(&mut self) -> Result<i32> {
        Ok(self.0.u32_be()? as i32)
    }
    fn u64(&mut self) -> Result<u64> {
        self.0.u64_be()
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.0.take(n).map(|_| ())
    }
    fn hash(&mut self) -> Result<[u8; 32]> {
        self.0.array()
    }
    fn bool(&mut self) -> Result<bool> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(refuse("a boolean other than 0 or 1")),
        }
    }
    /// Variable-length opaque or string, zero-padded to four bytes.
    fn opaque(&mut self, max: usize) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(refuse(format!("an XDR field of {len} bytes exceeds {max}")));
        }
        let data = self.0.take(len)?;
        let pad = (4 - len % 4) % 4;
        if self.0.take(pad)?.iter().any(|b| *b != 0) {
            return Err(refuse("non-zero XDR padding"));
        }
        Ok(data)
    }
    fn count(&mut self, max: usize) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(refuse(format!("{n} items exceed {max}")));
        }
        Ok(n)
    }
    /// An `ExtensionPoint` or other `union switch (int v) { case 0: void }`.
    fn empty_ext(&mut self) -> Result<()> {
        if self.u32()? != 0 {
            return Err(refuse("an unknown extension"));
        }
        Ok(())
    }
    /// A `PublicKey` / `AccountID` / `NodeID`.
    fn public_key(&mut self) -> Result<[u8; 32]> {
        if self.u32()? != 0 {
            return Err(refuse("a public key that is not Ed25519"));
        }
        self.hash()
    }
    fn asset(&mut self) -> Result<()> {
        match self.u32()? {
            0 => Ok(()),
            1 => {
                self.skip(4)?;
                self.public_key().map(|_| ())
            }
            2 => {
                self.skip(12)?;
                self.public_key().map(|_| ())
            }
            t => Err(refuse(format!("unknown asset type {t}"))),
        }
    }
}

fn write_opaque(w: &mut Writer, b: &[u8]) {
    w.u32_be(b.len() as u32).raw(b);
    for _ in 0..(4 - b.len() % 4) % 4 {
        w.u8(0);
    }
}

/// Skip one `SCVal`.
fn skip_scval(x: &mut Xdr<'_, '_>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(refuse("an SCVal nested too deep"));
    }
    match x.u32()? {
        0 => x.bool().map(|_| ()),
        1 | 20 => Ok(()),
        2 => {
            if x.u32()? > 9 {
                return Err(refuse("unknown SCError type"));
            }
            x.skip(4)
        }
        3 | 4 => x.skip(4),
        5..=8 | 21 => x.skip(8),
        9 | 10 => x.skip(16),
        11 | 12 => x.skip(32),
        13 | 14 => x.opaque(MAX_OPAQUE).map(|_| ()),
        15 => x.opaque(32).map(|_| ()),
        16 => {
            if x.bool()? {
                for _ in 0..x.count(MAX_ITEMS)? {
                    skip_scval(x, depth + 1)?;
                }
            }
            Ok(())
        }
        17 => skip_scmap(x, depth),
        18 => skip_scaddress(x),
        19 => {
            match x.u32()? {
                0 => x.skip(32)?,
                1 => {}
                t => return Err(refuse(format!("unknown contract executable {t}"))),
            }
            skip_scmap(x, depth)
        }
        t => Err(refuse(format!("unknown SCVal type {t}"))),
    }
}

/// Skip an optional `SCMap`.
fn skip_scmap(x: &mut Xdr<'_, '_>, depth: usize) -> Result<()> {
    if x.bool()? {
        for _ in 0..x.count(MAX_ITEMS)? {
            skip_scval(x, depth + 1)?;
            skip_scval(x, depth + 1)?;
        }
    }
    Ok(())
}

fn skip_scaddress(x: &mut Xdr<'_, '_>) -> Result<()> {
    match x.u32()? {
        0 => x.public_key().map(|_| ()),
        1 | 4 => x.skip(32),
        2 => x.skip(8 + 32),
        3 => {
            if x.u32()? != 0 {
                return Err(refuse("unknown claimable balance id type"));
            }
            x.skip(32)
        }
        t => Err(refuse(format!("unknown SCAddress type {t}"))),
    }
}

// ---- events ----

/// The contract and data of a transfer event, after checking its shape.
fn read_transfer_event(r: &mut Reader<'_>) -> Result<([u8; 32], Vec<u8>)> {
    let mut x = Xdr(r);
    x.empty_ext()?;
    if !x.bool()? {
        return Err(bad("an event without a contract"));
    }
    let contract = x.hash()?;
    if x.u32()? != CONTRACT_EVENT {
        return Err(bad("not a contract event"));
    }
    if x.u32()? != 0 {
        return Err(bad("unknown event body version"));
    }
    if x.count(1)? != 1 || x.u32()? != 15 || x.opaque(32)? != TRANSFER_OUT_TOPIC.as_bytes() {
        return Err(bad("the topics are not [transfer_out]"));
    }
    if x.u32()? != 13 {
        return Err(bad("the data is not bytes"));
    }
    let data = x.opaque(RECORD_LEN)?.to_vec();
    Ok((contract, data))
}

/// Skip one `ContractEvent` of any shape.
fn skip_event(x: &mut Xdr<'_, '_>) -> Result<()> {
    x.empty_ext()?;
    if x.bool()? {
        x.skip(32)?;
    }
    if x.u32()? > 2 {
        return Err(refuse("unknown event type"));
    }
    if x.u32()? != 0 {
        return Err(refuse("unknown event body version"));
    }
    for _ in 0..x.count(MAX_ITEMS)? {
        skip_scval(x, 0)?;
    }
    skip_scval(x, 0)
}

/// Topic 0 of the settlement lock's `Locked` event.
pub const LOCKED_TOPIC: &str = "locked";
/// The settlement lock's checkpoint event topic.
pub const ACCUMULATOR_TOPIC: &str = "accumulator";

/// An `SCAddress` that is an account key or a contract id, as 32 bytes.
fn read_lock_address(x: &mut Xdr<'_, '_>) -> Result<[u8; 32]> {
    if x.u32()? != 18 {
        return Err(bad("a Locked field is not an address"));
    }
    match x.u32()? {
        0 => x.public_key(),
        1 => x.hash(),
        _ => Err(bad("a Locked address is neither an account nor a contract")),
    }
}

/// The emitting contract and the settlement lock's record in an event: its
/// `Locked` event (topics `[locked, plan_id, leg_id]`, data `[index: u32,
/// payer, recipient, token, amount: i128, escape_at: u64]`) or its
/// `Accumulator` checkpoint (topics `[accumulator]`, data `[count: u64, acc:
/// bytes]`).
pub fn lock_record(event: &[u8]) -> Result<([u8; 32], super::receipt_proof::LockRecord)> {
    let mut r = Reader::new(event);
    let mut x = Xdr(&mut r);
    x.empty_ext()?;
    if !x.bool()? {
        return Err(bad("an event without a contract"));
    }
    let contract = x.hash()?;
    if x.u32()? != CONTRACT_EVENT || x.u32()? != 0 {
        return Err(bad("not a contract event"));
    }
    let topics = x.count(3)?;
    if x.u32()? != 15 {
        return Err(bad("the first topic is not a symbol"));
    }
    let topic = x.opaque(32)?;
    if topics == 1 && topic == ACCUMULATOR_TOPIC.as_bytes() {
        if x.u32()? != 16 || !x.bool()? || x.count(2)? != 2 || x.u32()? != 5 {
            return Err(bad("the data is not [count: u64, acc]"));
        }
        let count = x.u64()?;
        if x.u32()? != 13 {
            return Err(bad("the accumulator is not bytes"));
        }
        let acc =
            <[u8; 32]>::try_from(x.opaque(32)?).map_err(|_| bad("the accumulator is 32 bytes"))?;
        r.finish()?;
        let cp = super::receipt_proof::LockCheckpoint { count, acc };
        return Ok((contract, super::receipt_proof::LockRecord::Checkpoint(cp)));
    }
    if topics != 3 || topic != LOCKED_TOPIC.as_bytes() {
        return Err(bad(
            "the topics are not [locked, plan_id, leg_id] or [accumulator]",
        ));
    }
    let id = |x: &mut Xdr<'_, '_>| -> Result<[u8; 32]> {
        if x.u32()? != 13 {
            return Err(bad("a Locked id is not bytes"));
        }
        <[u8; 32]>::try_from(x.opaque(32)?).map_err(|_| bad("a Locked id is 32 bytes"))
    };
    let plan_id = id(&mut x)?;
    let leg_id = id(&mut x)?;
    if x.u32()? != 16 || !x.bool()? || x.count(6)? != 6 {
        return Err(bad("the data is not a vector of six fields"));
    }
    if x.u32()? != 3 {
        return Err(bad("the index is not a u32"));
    }
    let index = u8::try_from(x.u32()?).map_err(|_| bad("the index is above 255"))?;
    let payer = read_lock_address(&mut x)?;
    let recipient = read_lock_address(&mut x)?;
    let asset = read_lock_address(&mut x)?;
    if x.u32()? != 10 {
        return Err(bad("the amount is not an i128"));
    }
    let hi = x.u64()?;
    let lo = x.u64()?;
    if hi >> 63 != 0 {
        return Err(bad("a negative amount"));
    }
    let amount = (u128::from(hi) << 64) | u128::from(lo);
    if x.u32()? != 5 {
        return Err(bad("the escape time is not a u64"));
    }
    let escape_at_ms = x.u64()?.saturating_mul(1000);
    r.finish()?;
    let ev = super::receipt_proof::LockEvent {
        plan_id,
        leg_id,
        index,
        payer,
        recipient,
        asset,
        amount,
        escape_at_ms,
    };
    Ok((contract, super::receipt_proof::LockRecord::Locked(ev)))
}

/// The transfer record in its big-endian form.
pub fn encode_record(t: &MoveTransfer) -> Vec<u8> {
    let mut w = Writer::new();
    w.u64_be(t.sequence)
        .u64_be(t.source_selector)
        .u64_be(t.dest_selector)
        .raw(&t.sender)
        .raw(&t.token)
        .raw(&t.endpoint)
        .raw(&t.recipient)
        .u128_be(t.amount);
    w.into_bytes()
}

fn read_record(r: &mut Reader<'_>) -> Result<MoveTransfer> {
    Ok(MoveTransfer {
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

/// A transfer event of `contract` carrying `record`, in XDR.
pub fn transfer_event(contract: &[u8; 32], record: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32_be(0)
        .u32_be(1)
        .raw(contract)
        .u32_be(CONTRACT_EVENT)
        .u32_be(0)
        .u32_be(1)
        .u32_be(15);
    write_opaque(&mut w, TRANSFER_OUT_TOPIC.as_bytes());
    w.u32_be(13);
    write_opaque(&mut w, record);
    w.into_bytes()
}

/// The Stellar adapter. See the module docs.
pub struct StellarAdapter;

impl RouteAdapter for StellarAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Contract
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Stellar
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let (contract, data) = read_transfer_event(r)?;
        if contract != route.ramp {
            return Err(bad("emitted by another contract"));
        }
        let mut dr = Reader::new(&data);
        let t = read_record(&mut dr)?;
        dr.finish()?;
        Ok(t.inbound(ChainFamily::Stellar, &data))
    }

    fn encode_outbound(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<Vec<u8>> {
        Ok(encode_record(&MoveTransfer::outbound(route, msg)?))
    }

    fn decode_outbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        let t = read_record(r)?;
        let mut m = t.read_back(route)?;
        m.message_id = message_id(ChainFamily::Stellar, &encode_record(&t));
        Ok(m)
    }

    fn outbound_message_id(&self, route: &BridgeRoute, msg: &RouteMessage) -> Result<[u8; 32]> {
        MoveTransfer::outbound(route, msg)
            .map(|t| message_id(ChainFamily::Stellar, &encode_record(&t)))
    }

    fn finality_depth(&self, _route: &BridgeRoute) -> Result<u64> {
        Ok(0)
    }
}

// ---- SCP, headers and results ----

/// An externalize statement: its signer, slot and value.
struct Externalize<'a> {
    node: [u8; 32],
    slot: u64,
    value: &'a [u8],
}

/// Parse and check one SCP envelope under `network_id`.
fn read_envelope<'a>(b: &'a [u8], network_id: &[u8; 32]) -> Result<Externalize<'a>> {
    let mut r = Reader::new(b);
    let mut x = Xdr(&mut r);
    let node = x.public_key()?;
    let slot = x.u64()?;
    if x.u32()? != SCP_ST_EXTERNALIZE {
        return Err(refuse("not an EXTERNALIZE statement"));
    }
    let _counter = x.u32()?;
    let value = x.opaque(1024)?;
    let _n_h = x.u32()?;
    let _quorum_set_hash = x.hash()?;
    let statement_end = x.0.position();
    let signature: [u8; 64] = x
        .opaque(64)?
        .try_into()
        .map_err(|_| refuse("an Ed25519 signature is 64 bytes"))?;
    r.finish()?;
    let mut signed = network_id.to_vec();
    signed.extend_from_slice(&ENVELOPE_TYPE_SCP.to_be_bytes());
    signed.extend_from_slice(&b[..statement_end]);
    VerifyingKey::from_bytes(&node)
        .map_err(|_| refuse("a node key is not a curve point"))?
        .verify_strict(&signed, &Signature::from_bytes(&signature))
        .map_err(|_| refuse("an SCP signature does not verify"))?;
    Ok(Externalize { node, slot, value })
}

/// The transaction set hash a `StellarValue` names.
fn value_tx_set_hash(value: &[u8]) -> Result<[u8; 32]> {
    let mut r = Reader::new(value);
    let mut x = Xdr(&mut r);
    let h = read_stellar_value(&mut x)?;
    r.finish()?;
    Ok(h)
}

fn read_stellar_value(x: &mut Xdr<'_, '_>) -> Result<[u8; 32]> {
    let tx_set_hash = x.hash()?;
    let _close_time = x.u64()?;
    for _ in 0..x.count(6)? {
        x.opaque(128)?;
    }
    match x.u32()? {
        0 => {}
        1 => {
            x.public_key()?;
            x.opaque(64)?;
        }
        t => return Err(refuse(format!("unknown StellarValue type {t}"))),
    }
    Ok(tx_set_hash)
}

/// From a ledger header: its sequence and result set hash.
fn read_header(b: &[u8]) -> Result<(u32, [u8; 32])> {
    let mut r = Reader::new(b);
    let mut x = Xdr(&mut r);
    let _version = x.u32()?;
    let _previous = x.hash()?;
    read_stellar_value(&mut x)?;
    let results_hash = x.hash()?;
    let _bucket_list = x.hash()?;
    let seq = x.u32()?;
    x.skip(8 + 8 + 4 + 8 + 4 + 4 + 4 + 4 * 32)?;
    match x.u32()? {
        0 => {}
        1 => {
            x.u32()?;
            x.empty_ext()?;
        }
        t => return Err(refuse(format!("unknown header extension {t}"))),
    }
    r.finish()?;
    Ok((seq, results_hash))
}

fn skip_claim_atom(x: &mut Xdr<'_, '_>) -> Result<()> {
    match x.u32()? {
        0 => x.skip(32 + 8)?,
        1 => {
            x.public_key()?;
            x.skip(8)?;
        }
        2 => x.skip(32)?,
        t => return Err(refuse(format!("unknown claim atom {t}"))),
    }
    x.asset()?;
    x.skip(8)?;
    x.asset()?;
    x.skip(8)
}

fn skip_offer_success(x: &mut Xdr<'_, '_>) -> Result<()> {
    for _ in 0..x.count(MAX_ITEMS)? {
        skip_claim_atom(x)?;
    }
    match x.u32()? {
        0 | 1 => {
            x.public_key()?;
            x.skip(8)?;
            x.asset()?;
            x.asset()?;
            x.skip(8 + 8 + 4)?;
            x.empty_ext()
        }
        2 => Ok(()),
        t => Err(refuse(format!("unknown offer effect {t}"))),
    }
}

fn skip_path_payment_success(x: &mut Xdr<'_, '_>) -> Result<()> {
    for _ in 0..x.count(MAX_ITEMS)? {
        skip_claim_atom(x)?;
    }
    x.public_key()?;
    x.asset()?;
    x.skip(8)
}

/// Read one `OperationResult`; for a successful host function invocation,
/// return its success hash.
fn read_op_result(x: &mut Xdr<'_, '_>) -> Result<Option<[u8; 32]>> {
    match x.i32()? {
        0 => {}
        -6..=-1 => return Ok(None),
        c => return Err(refuse(format!("unknown operation result code {c}"))),
    }
    let op = x.i32()?;
    let code = x.i32()?;
    match (op, code) {
        (2 | 13, 0) => skip_path_payment_success(x)?,
        (2 | 13, -9) => x.asset()?,
        (3 | 4 | 12, 0) => skip_offer_success(x)?,
        (8, 0) => x.skip(8)?,
        (9, 0) => {
            for _ in 0..x.count(MAX_ITEMS)? {
                x.public_key()?;
                x.skip(8)?;
            }
        }
        (14, 0) => {
            if x.u32()? != 0 {
                return Err(refuse("unknown claimable balance id type"));
            }
            x.skip(32)?;
        }
        (INVOKE_HOST_FUNCTION, 0) => return Ok(Some(x.hash()?)),
        (0..=26, _) => {}
        (t, _) => return Err(refuse(format!("unknown operation type {t}"))),
    }
    Ok(None)
}

/// Read the operation results of a transaction result (`txSUCCESS` or
/// `txFAILED`), recording success hashes; `None` for other codes.
fn read_op_results(x: &mut Xdr<'_, '_>) -> Result<Vec<Option<[u8; 32]>>> {
    (0..x.count(1000)?).map(|_| read_op_result(x)).collect()
}

/// Read a transaction result set; for each transaction, whether it
/// succeeded and its operations' success hashes.
fn read_results(b: &[u8]) -> Result<Vec<(bool, Vec<Option<[u8; 32]>>)>> {
    let mut r = Reader::new(b);
    let mut x = Xdr(&mut r);
    let n = x.count(MAX_ITEMS)?;
    let mut out = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let _tx_hash = x.hash()?;
        let _fee = x.u64()?;
        let entry = match x.i32()? {
            0 => (true, read_op_results(&mut x)?),
            -1 => (false, read_op_results(&mut x)?),
            outer @ (1 | -13) => {
                let _inner_hash = x.hash()?;
                let _inner_fee = x.u64()?;
                let inner = match x.i32()? {
                    0 => (outer == 1, read_op_results(&mut x)?),
                    -1 => (false, read_op_results(&mut x)?),
                    -17..=-2 => (false, Vec::new()),
                    c => return Err(refuse(format!("unknown inner result code {c}"))),
                };
                x.empty_ext()?;
                inner
            }
            -17..=-2 => (false, Vec::new()),
            c => return Err(refuse(format!("unknown result code {c}"))),
        };
        x.empty_ext()?;
        out.push(entry);
    }
    r.finish()?;
    Ok(out)
}

/// The byte span of event `index` in a success preimage.
fn preimage_event_span(b: &[u8], index: usize) -> Result<(usize, usize)> {
    let mut r = Reader::new(b);
    let mut x = Xdr(&mut r);
    skip_scval(&mut x, 0)?;
    let n = x.count(MAX_ITEMS)?;
    let mut span = None;
    for i in 0..n {
        let start = x.0.position();
        skip_event(&mut x)?;
        if i == index {
            span = Some((start, x.0.position()));
        }
    }
    r.finish()?;
    span.ok_or_else(|| refuse("no event at that position"))
}

// ---- the client ----

fn quorum(anchor: &LightClientAnchor) -> Result<(&[u8; 32], &[[u8; 32]], usize)> {
    match anchor {
        LightClientAnchor::StellarScp {
            network_id,
            validators,
            threshold,
        } => Ok((network_id, validators, *threshold as usize)),
        _ => Err(refuse("the route's anchor is not a Stellar anchor")),
    }
}

/// The XDR of the contract event `proof` shows in a ledger the anchor's
/// quorum externalized: the quorum's statements, the transaction set, the
/// ledger header and results, the invocation's success preimage, and the
/// event's position.
fn proven_event(anchor: &LightClientAnchor, proof: &[u8]) -> Result<Vec<u8>> {
    let (network_id, validators, threshold) = quorum(anchor)?;
    let mut r = Reader::new(proof);
    let n = r.u8()? as usize;
    let mut envelopes = Vec::with_capacity(n);
    for _ in 0..n {
        envelopes.push(r.be_bytes(4096)?);
    }
    let tx_set = r.be_bytes(MAX_PROOF_LEN)?;
    let header = r.be_bytes(4096)?;
    let results = r.be_bytes(MAX_PROOF_LEN)?;
    let tx_index = r.u32_be()? as usize;
    let op_index = r.u32_be()? as usize;
    let preimage = r.be_bytes(MAX_PROOF_LEN)?;
    let event_index = r.u32_be()? as usize;
    r.finish()?;

    let (seq, results_hash) = read_header(header)?;
    let mut signers = std::collections::HashSet::new();
    let mut value: Option<&[u8]> = None;
    for e in &envelopes {
        let ext = read_envelope(e, network_id)?;
        if ext.slot != u64::from(seq) + 1 {
            return Err(refuse("a statement for another slot"));
        }
        if *value.get_or_insert(ext.value) != ext.value {
            return Err(refuse("statements externalize different values"));
        }
        if validators.contains(&ext.node) {
            signers.insert(ext.node);
        }
    }
    if signers.len() < threshold {
        return Err(refuse(format!(
            "{} of the quorum's validators externalized; {threshold} required",
            signers.len()
        )));
    }
    let value = value.ok_or_else(|| refuse("no statements"))?;
    if value_tx_set_hash(value)? != sha256(tx_set) {
        return Err(refuse("the transaction set is not the externalized one"));
    }
    let mut tr = Reader::new(tx_set);
    let mut tx = Xdr(&mut tr);
    if tx.u32()? != 1 || tx.hash()? != sha256(header) {
        return Err(refuse("the transaction set does not follow this ledger"));
    }
    if sha256(results) != results_hash {
        return Err(refuse("the results are not the ledger's"));
    }
    let (succeeded, ops) = read_results(results)?
        .into_iter()
        .nth(tx_index)
        .ok_or_else(|| refuse("no transaction at that position"))?;
    let success = ops
        .get(op_index)
        .copied()
        .flatten()
        .filter(|_| succeeded)
        .ok_or_else(|| refuse("not a successful host function invocation"))?;
    if sha256(preimage) != success {
        return Err(refuse("the events are not the invocation's"));
    }
    let (start, end) = preimage_event_span(preimage, event_index)?;
    Ok(preimage[start..end].to_vec())
}

/// The Stellar SCP light client. It keeps no state of its own.
#[derive(Debug, Default)]
pub struct StellarLightClient;

impl LightClientVerifier for StellarLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::StellarScp
    }

    fn proven_lock_record(
        &self,
        _state: &dyn RouteState,
        _route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        let (contract, record) = lock_record(&proven_event(anchor, proof)?)?;
        if contract != *lock {
            return Err(refuse("the event is not the route's settlement lock's"));
        }
        Ok(record)
    }

    fn verify(
        &self,
        _state: &dyn RouteState,
        _route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        if body_hash(&proven_event(anchor, proof)?) != *body {
            return Err(refuse(
                "the event at that position is not the delivered one",
            ));
        }
        Ok(())
    }

    fn advance(
        &self,
        _state: &mut dyn RouteState,
        _route: &BridgeRoute,
        _anchor: &LightClientAnchor,
        _update: &[u8],
    ) -> Result<LightClientHead> {
        Err(refuse(
            "the quorum is governed: it changes only with the route's anchor",
        ))
    }

    /// The client follows no chain of its own: each proof stands on the
    /// governed quorum.
    fn head(
        &self,
        _state: &dyn RouteState,
        _route: &BridgeRoute,
        _anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        None
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Validators that externalize synthetic ledgers, for route tests.

    use ed25519_dalek::{Signer, SigningKey};

    use super::*;

    pub const NETWORK: [u8; 32] = [0x5e; 32];

    pub fn validators(seed: u8, n: usize) -> Vec<SigningKey> {
        (0..n)
            .map(|i| SigningKey::from_bytes(&[seed.wrapping_add(i as u8); 32]))
            .collect()
    }

    pub fn envelope(k: &SigningKey, slot: u64, value: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(0)
            .raw(&k.verifying_key().to_bytes())
            .u64_be(slot)
            .u32_be(SCP_ST_EXTERNALIZE)
            .u32_be(1);
        write_opaque(&mut w, value);
        w.u32_be(1).raw(&[0x9a; 32]);
        let statement = w.into_bytes();
        let mut signed = NETWORK.to_vec();
        signed.extend_from_slice(&ENVELOPE_TYPE_SCP.to_be_bytes());
        signed.extend_from_slice(&statement);
        let mut w = Writer::new();
        w.raw(&statement);
        write_opaque(&mut w, &k.sign(&signed).to_bytes());
        w.into_bytes()
    }

    fn stellar_value(w: &mut Writer, tx_set_hash: &[u8; 32]) {
        w.raw(tx_set_hash).u64_be(1_800_000_000).u32_be(0).u32_be(0);
    }

    pub fn stellar_value_bytes(tx_set_hash: &[u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        stellar_value(&mut w, tx_set_hash);
        w.into_bytes()
    }

    pub fn header(seq: u32, results_hash: [u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(22).raw(&[0x01; 32]);
        stellar_value(&mut w, &[0x02; 32]);
        w.raw(&results_hash)
            .raw(&[0x03; 32])
            .u32_be(seq)
            .raw(&[0u8; 8 + 8 + 4 + 8 + 4 + 4 + 4 + 4 * 32])
            .u32_be(0);
        w.into_bytes()
    }

    pub fn tx_set(previous: [u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(1).raw(&previous).u32_be(0);
        w.into_bytes()
    }

    /// A success preimage: a void return value and `events`.
    pub fn preimage(events: &[Vec<u8>]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(1).u32_be(events.len() as u32);
        for e in events {
            w.raw(e);
        }
        w.into_bytes()
    }

    /// A diagnostic-style event of another contract, with nested values.
    pub fn noise_event() -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(0)
            .u32_be(1)
            .raw(&[0x0b; 32])
            .u32_be(CONTRACT_EVENT)
            .u32_be(0)
            .u32_be(2);
        w.u32_be(15);
        write_opaque(&mut w, b"mint");
        w.u32_be(18).u32_be(0).u32_be(0).raw(&[0x0c; 32]);
        w.u32_be(16)
            .u32_be(1)
            .u32_be(2)
            .u32_be(10)
            .raw(&[0u8; 16])
            .u32_be(14);
        write_opaque(&mut w, b"memo text");
        w.into_bytes()
    }

    /// A result set: a payment, a failed transaction, and an invocation
    /// whose second operation's success hash is `success`.
    pub fn results(success: [u8; 32]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(3);
        // A successful payment.
        w.raw(&[0x10; 32])
            .u64_be(100)
            .u32_be(0)
            .u32_be(1)
            .u32_be(0)
            .u32_be(1)
            .u32_be(0)
            .u32_be(0);
        // A failed transaction.
        w.raw(&[0x11; 32])
            .u64_be(100)
            .u32_be(-5i32 as u32)
            .u32_be(0);
        // A fee-bumped invocation: a path payment, then the host function.
        w.raw(&[0x12; 32])
            .u64_be(300)
            .u32_be(1)
            .raw(&[0x13; 32])
            .u64_be(200)
            .u32_be(0)
            .u32_be(2);
        w.u32_be(0)
            .u32_be(2)
            .u32_be(0)
            .u32_be(0)
            .u32_be(0)
            .raw(&[0x14; 32])
            .u32_be(0)
            .u64_be(5);
        w.u32_be(0).u32_be(24).u32_be(0).raw(&success);
        w.u32_be(0).u32_be(0);
        w.into_bytes()
    }

    pub struct Proof<'a> {
        pub envelopes: &'a [Vec<u8>],
        pub tx_set: &'a [u8],
        pub header: &'a [u8],
        pub results: &'a [u8],
        pub tx_index: u32,
        pub op_index: u32,
        pub preimage: &'a [u8],
        pub event_index: u32,
    }

    impl Proof<'_> {
        pub fn encode(&self) -> Vec<u8> {
            let mut w = Writer::new();
            w.u8(self.envelopes.len() as u8);
            for e in self.envelopes {
                w.be_bytes(e);
            }
            w.be_bytes(self.tx_set)
                .be_bytes(self.header)
                .be_bytes(self.results)
                .u32_be(self.tx_index)
                .u32_be(self.op_index)
                .be_bytes(self.preimage)
                .u32_be(self.event_index);
            w.into_bytes()
        }
    }
}

#[cfg(test)]
mod mainnet_tests {
    use serde_json::Value;
    use sha2::{Digest, Sha256};

    use super::super::test_support::MemState;
    use super::super::{BridgeRouteAdapter, ChainFamily, MintRateLimit, VerifierQuorum};
    use super::*;

    /// Recorded from Stellar mainnet: a ledger's header, its transaction
    /// results and one Soroban invocation's return value and events (from a
    /// public RPC node's ledger metadata), and the next ledger's transaction
    /// set and the SCP externalize statements for it (from SDF's history
    /// archive).
    const MAINNET: &str = include_str!("../../tests/fixtures/stellar_mainnet.json");

    /// The Ed25519 key of a `G...` account id.
    fn strkey(s: &str) -> [u8; 32] {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut bits = 0u64;
        let mut n = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            bits = (bits << 5) | ALPHABET.iter().position(|a| *a == c).unwrap() as u64;
            n += 5;
            if n >= 8 {
                n -= 8;
                out.push((bits >> n) as u8);
            }
        }
        assert_eq!(out[0], 6 << 3, "an account id");
        out[1..33].try_into().unwrap()
    }

    #[test]
    fn a_mainnet_soroban_event_is_proven_by_the_quorums_externalize_statements() {
        let f: Value = serde_json::from_str(MAINNET).unwrap();
        let h = |k: &str| hex::decode(f[k].as_str().unwrap()).unwrap();
        let network_id: [u8; 32] =
            Sha256::digest(f["network_passphrase"].as_str().unwrap().as_bytes()).into();
        let mut validators: Vec<[u8; 32]> = f["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| strkey(n.as_str().unwrap()))
            .collect();
        validators.sort();
        validators.dedup();
        let n = validators.len();
        let anchor = LightClientAnchor::StellarScp {
            network_id,
            validators: validators.clone(),
            threshold: (2 * n / 3 + 1) as u32,
        };
        let route = BridgeRoute {
            adapter: BridgeRouteAdapter::Contract,
            family: ChainFamily::Stellar,
            source_chain: "stellar".into(),
            source_chain_id: 1,
            local_selector: 2,
            peer: [1; 32],
            ramp: [2; 32],
            local_endpoint: [3; 32],
            remote_token: [4; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: vec![],
                threshold: 0,
            },
            blessing: None,
            light_client: Some(anchor.clone()),
            mint_limit: MintRateLimit {
                per_mint: 1,
                per_epoch: 1,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: None,
            ibc: None,
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        };
        let proof = |envelopes: &[Vec<u8>]| {
            let mut w = Writer::new();
            w.u8(envelopes.len() as u8);
            for e in envelopes {
                w.be_bytes(e);
            }
            w.be_bytes(&h("tx_set"))
                .be_bytes(&h("header"))
                .be_bytes(&h("results"));
            w.u32_be(f["tx_index"].as_u64().unwrap() as u32)
                .u32_be(f["op_index"].as_u64().unwrap() as u32);
            w.be_bytes(&h("preimage"))
                .u32_be(f["event_index"].as_u64().unwrap() as u32);
            w.into_bytes()
        };
        let envelopes: Vec<Vec<u8>> = f["envelopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| hex::decode(e.as_str().unwrap()).unwrap())
            .collect();
        let event = h("event");
        let lc = StellarLightClient;
        let s = MemState::default();
        lc.verify(&s, &route, &anchor, &body_hash(&event), &proof(&envelopes))
            .unwrap();

        // Fewer statements than the threshold, a forged statement, or another
        // event: refused.
        assert!(
            lc.verify(
                &s,
                &route,
                &anchor,
                &body_hash(&event),
                &proof(&envelopes[..n / 2])
            )
            .is_err()
        );
        let mut forged = envelopes.clone();
        let last = forged[0].len() - 1;
        forged[0][last] ^= 1;
        assert!(
            lc.verify(&s, &route, &anchor, &body_hash(&event), &proof(&forged))
                .is_err()
        );
        assert!(
            lc.verify(
                &s,
                &route,
                &anchor,
                &body_hash(&h("header")),
                &proof(&envelopes)
            )
            .is_err()
        );
    }
}
