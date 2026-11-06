//! Bitcoin: deposits to a governed output script, proven by SPV.
//!
//! A deposit is a Bitcoin transaction with exactly one output paying the
//! route's deposit script (the output script of the governed deposit
//! descriptor, whose SHA-256 is the route's `peer`) and exactly one
//! `OP_RETURN` output naming the Tenzro account to credit:
//!
//! ```text
//! OP_RETURN PUSH(36) "TNZO" account:32
//! ```
//!
//! The delivery's body names the transaction and where it was mined:
//!
//! ```text
//! height    u64 big-endian    the block's height
//! index     u32 big-endian    the transaction's position in the block
//! tx        u32 length + the transaction without witness data
//! ```
//!
//! The message id is the transaction id, the sequence is
//! `height * 2^20 + index`, and the amount is the deposit output's value in
//! satoshis. On Tenzro a deposit route's supply record counts the bitcoin
//! held under the descriptor (`locked`) against the representation credited
//! on Tenzro (`bridged`); a deposit raises both by the same amount.
//!
//! The route's light client ([`BitcoinLightClient`]) proves the deposit: it
//! follows the header chain with the most cumulative work from a governed
//! header at a difficulty-adjustment boundary, checking each header's proof
//! of work and its target under the mainnet retarget rule, and accepts a
//! deposit whose transaction a Merkle branch places in a block of that
//! chain with at least the governed number of confirmations.
//!
//! The deposit descriptor is `tr(NUMS, multi_a(threshold, signers...))`
//! ([`super::bitcoin_spend`]); its output script's SHA-256 is the route's
//! `peer`. Tenzro tracks every output it holds: a deposit adds its output, a
//! withdrawal (an outbound transfer) spends the oldest outputs in a
//! transaction derived from consensus state alone and returns its change.
//! Bitcoin cannot check a Tenzro proof, so a withdrawal is completed by
//! `threshold` of the signers signing that transaction; that they sign no
//! other spend is the trust that remains.
//!
//! Light-client encodings, fixed-layout and big-endian unless noted:
//!
//! ```text
//! update = 0x00 header:80                                     (bootstrap)
//!        | 0x01 parent_height:u64 count:u16 { header:80 }     (extend or reorganise)
//! proof  = header:80 count:u8 { sibling:32 }
//! ```
//!
//! Headers are Bitcoin's own 80-byte serialization (little-endian fields).

use ethnum::U256;
use sha2::{Digest, Sha256};

use super::attestation::body_hash;
use super::bitcoin_spend::{DepositDescriptor, Utxo};
use super::canonical::{Reader, Writer};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::state::RouteState;
use super::{
    BridgeRoute, BridgeRouteAdapter, ChainFamily, LightClientAnchor, LightClientKind, RouteAdapter,
    RouteMessage,
};
use crate::error::{BridgeError, Result};

/// The `OP_RETURN` tag that marks a Tenzro deposit.
pub const DEPOSIT_TAG: &[u8; 4] = b"TNZO";

/// Largest transaction a deposit may be.
pub const MAX_TX_LEN: usize = 60 * 1024;

/// Most headers one update may carry.
pub const MAX_HEADERS_PER_UPDATE: usize = 2016;

/// Blocks per difficulty period.
pub const RETARGET_INTERVAL: u64 = 2016;

/// The period's intended duration, in seconds.
const TARGET_TIMESPAN: u64 = 14 * 24 * 60 * 60;

/// Mainnet proof-of-work limit, as compact bits.
const POW_LIMIT_BITS: u32 = 0x1d00_ffff;

/// Transactions per block the sequence encoding allows.
const INDEX_BITS: u32 = 20;

/// Deepest Merkle branch accepted.
const MAX_BRANCH: usize = 32;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::TransferFailed(format!("bitcoin: {}", what.into()))
}

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("bitcoin deposit: {}", what.into()))
}

/// Double SHA-256.
pub fn sha256d(b: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(b)).into()
}

fn compact_size(r: &mut Reader<'_>, max: usize) -> Result<usize> {
    let first = r.u8()?;
    let (v, min) = match first {
        0xfd => (u64::from(u16::from_le_bytes(r.array()?)), 0xfd),
        0xfe => (u64::from(u32::from_le_bytes(r.array()?)), 0x1_0000),
        0xff => (r.u64_le()?, 0x1_0000_0000),
        b => (u64::from(b), 0),
    };
    if v < min {
        return Err(bad("non-minimal compact size"));
    }
    if v > max as u64 {
        return Err(bad(format!("count {v} exceeds {max}")));
    }
    Ok(v as usize)
}

fn write_compact_size(w: &mut Writer, v: usize) {
    match v {
        0..=0xfc => {
            w.u8(v as u8);
        }
        0xfd..=0xffff => {
            w.u8(0xfd).raw(&(v as u16).to_le_bytes());
        }
        _ => {
            w.u8(0xfe).u32_le(v as u32);
        }
    }
}

/// A transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxIn {
    pub prevout: [u8; 36],
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

/// A transaction output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOut {
    pub value: u64,
    pub script: Vec<u8>,
}

/// A transaction without witness data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
}

impl Transaction {
    /// Bitcoin's serialization without witness data.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_le(self.version);
        write_compact_size(&mut w, self.inputs.len());
        for i in &self.inputs {
            w.raw(&i.prevout);
            write_compact_size(&mut w, i.script_sig.len());
            w.raw(&i.script_sig).u32_le(i.sequence);
        }
        write_compact_size(&mut w, self.outputs.len());
        for o in &self.outputs {
            w.u64_le(o.value);
            write_compact_size(&mut w, o.script.len());
            w.raw(&o.script);
        }
        w.u32_le(self.lock_time);
        w.into_bytes()
    }

    /// Parse a complete transaction without witness data.
    pub fn decode(tx: &[u8]) -> Result<Self> {
        let mut r = Reader::new(tx);
        let version = r.u32_le()?;
        let n = compact_size(&mut r, MAX_TX_LEN / 41)?;
        if n == 0 {
            return Err(bad("a transaction without inputs (or with witness data)"));
        }
        let mut inputs = Vec::with_capacity(n);
        for _ in 0..n {
            let prevout = r.array()?;
            let len = compact_size(&mut r, MAX_TX_LEN)?;
            inputs.push(TxIn {
                prevout,
                script_sig: r.take(len)?.to_vec(),
                sequence: r.u32_le()?,
            });
        }
        let n = compact_size(&mut r, MAX_TX_LEN / 9)?;
        let mut outputs = Vec::with_capacity(n);
        for _ in 0..n {
            let value = r.u64_le()?;
            let len = compact_size(&mut r, MAX_TX_LEN)?;
            outputs.push(TxOut {
                value,
                script: r.take(len)?.to_vec(),
            });
        }
        let lock_time = r.u32_le()?;
        r.finish()?;
        Ok(Self {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

/// The `OP_RETURN` script that names `account` as the deposit's recipient.
pub fn deposit_marker(account: &[u8; 32]) -> Vec<u8> {
    let mut s = vec![0x6a, 36];
    s.extend_from_slice(DEPOSIT_TAG);
    s.extend_from_slice(account);
    s
}

/// A deposit as a delivery carries it. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deposit {
    pub height: u64,
    pub index: u32,
    pub tx: Vec<u8>,
}

impl Deposit {
    /// The body encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u64_be(self.height).u32_be(self.index).be_bytes(&self.tx);
        w.into_bytes()
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let d = Self {
            height: r.u64_be()?,
            index: r.u32_be()?,
            tx: r.be_bytes(MAX_TX_LEN)?.to_vec(),
        };
        if d.index >= 1 << INDEX_BITS || d.height >= 1 << (64 - INDEX_BITS) {
            return Err(bad("height or index out of range"));
        }
        // A 64-byte transaction could pass for an inner Merkle node.
        if d.tx.len() == 64 {
            return Err(bad("a 64-byte transaction"));
        }
        Ok(d)
    }

    /// The transaction id.
    pub fn txid(&self) -> [u8; 32] {
        sha256d(&self.tx)
    }

    /// The route sequence this deposit takes.
    pub fn sequence(&self) -> u64 {
        (self.height << INDEX_BITS) | u64::from(self.index)
    }
}

/// A Bitcoin transaction the route's light client proves mined: the
/// transaction, its id, and the height and time of its block.
#[derive(Debug, Clone)]
pub struct ProvenPayment {
    pub tx: Transaction,
    pub txid: [u8; 32],
    pub height: u64,
    pub block_time: u32,
}

/// Check `proof` (the deposit encoding of the transaction, its block header
/// and Merkle branch) against the light client `anchor` started: the
/// transaction is in a block of the client's best chain with at least the
/// route's confirmations. Returns the encoded transaction and what it proves.
fn prove_inclusion<'p>(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    proof: &'p [u8],
) -> Result<(&'p [u8], ProvenPayment)> {
    let a = anchor_parts(anchor)?;
    let (tip_height, _) =
        tip(state, route, anchor)?.ok_or_else(|| refuse("not bootstrapped from the anchor"))?;
    let mut r = Reader::new(proof);
    let deposit_bytes = r.be_bytes(MAX_TX_LEN + 16)?;
    let header = BlockHeader::read(&mut r)?;
    let n = r.u8()? as usize;
    if n > MAX_BRANCH {
        return Err(refuse("Merkle branch too deep"));
    }
    let mut branch = Vec::with_capacity(n);
    for _ in 0..n {
        branch.push(r.array::<32>()?);
    }
    r.finish()?;
    let mut dr = Reader::new(deposit_bytes);
    let deposit = Deposit::read(&mut dr)?;
    dr.finish()?;
    let tx = Transaction::decode(&deposit.tx)?;
    if u64::from(deposit.index) >> n != 0 {
        return Err(refuse("the index does not fit the branch"));
    }
    let txid = deposit.txid();
    let mut node = txid;
    for (level, sibling) in branch.iter().enumerate() {
        // Bitcoin pairs the last node of an odd level with itself, so the
        // same branch would also reach the root from the position after it,
        // which holds no transaction. A node is only ever its own sibling as
        // the left one, which keeps one position, and so one route
        // sequence, per transaction.
        if deposit.index >> level & 1 == 1 && *sibling == node {
            return Err(refuse(
                "the position is a duplicated Merkle node, not a transaction",
            ));
        }
        node = if deposit.index >> level & 1 == 0 {
            sha256d(&[node, *sibling].concat())
        } else {
            sha256d(&[*sibling, node].concat())
        };
    }
    if node != header.merkle_root {
        return Err(refuse("the transaction is not in the block"));
    }
    let on_best_chain = deposit.height <= tip_height
        && record(state, route, anchor, deposit.height)?
            .is_some_and(|rec| rec.hash == header.hash());
    if !on_best_chain {
        return Err(refuse("the block is not on the client's best chain"));
    }
    let depth = tip_height - deposit.height + 1;
    if depth < a.confirmations {
        return Err(refuse(format!(
            "the transaction has {depth} confirmations; the route requires {}",
            a.confirmations
        )));
    }
    Ok((
        deposit_bytes,
        ProvenPayment {
            tx,
            txid,
            height: deposit.height,
            block_time: header.time,
        },
    ))
}

/// A payment on the Bitcoin route's chain, proven by its light client: what
/// a fill of an order paying out on Bitcoin rests on.
pub fn prove_payment(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    proof: &[u8],
) -> Result<ProvenPayment> {
    prove_inclusion(state, route, anchor, proof).map(|(_, p)| p)
}

/// The Bitcoin adapter. See the module docs.
pub struct BitcoinAdapter;

impl RouteAdapter for BitcoinAdapter {
    fn transport(&self) -> BridgeRouteAdapter {
        BridgeRouteAdapter::Deposit
    }

    fn family(&self) -> ChainFamily {
        ChainFamily::Bitcoin
    }

    fn decode_inbound(&self, route: &BridgeRoute, r: &mut Reader<'_>) -> Result<RouteMessage> {
        route_descriptor(route)?;
        let d = Deposit::read(r)?;
        let tx = Transaction::decode(&d.tx)?;
        let mut deposits = tx
            .outputs
            .iter()
            .filter(|o| <[u8; 32]>::from(Sha256::digest(&o.script)) == route.peer);
        let (Some(deposit), None) = (deposits.next(), deposits.next()) else {
            return Err(bad("exactly one output must pay the deposit script"));
        };
        let mut markers = tx
            .outputs
            .iter()
            .filter(|o| o.script.first() == Some(&0x6a));
        let (Some(marker), None) = (markers.next(), markers.next()) else {
            return Err(bad("exactly one OP_RETURN output must name the recipient"));
        };
        let account: [u8; 32] = match marker.script.as_slice() {
            [0x6a, 36, tag @ ..] if tag.len() == 36 && &tag[..4] == DEPOSIT_TAG => {
                tag[4..].try_into().expect("32 bytes")
            }
            _ => return Err(bad("the OP_RETURN output is not a Tenzro deposit marker")),
        };
        if marker.value != 0 || deposit.value == 0 {
            return Err(bad("the marker carries value or the deposit carries none"));
        }
        Ok(RouteMessage {
            message_id: d.txid(),
            source_selector: route.source_chain_id,
            dest_selector: route.local_selector,
            sequence: d.sequence(),
            sender: tx.inputs[0].prevout.to_vec(),
            receiver: account.to_vec(),
            token_pool: route.peer,
            token: route.local_endpoint,
            amount: u128::from(deposit.value),
        })
    }

    fn encode_outbound(&self, _route: &BridgeRoute, _msg: &RouteMessage) -> Result<Vec<u8>> {
        Err(refuse(
            "a withdrawal is planned from the descriptor's outputs, not encoded from a message",
        ))
    }

    fn decode_outbound(&self, _route: &BridgeRoute, _r: &mut Reader<'_>) -> Result<RouteMessage> {
        Err(refuse(
            "a withdrawal is planned from the descriptor's outputs, not encoded from a message",
        ))
    }

    fn outbound_message_id(&self, _route: &BridgeRoute, _msg: &RouteMessage) -> Result<[u8; 32]> {
        Ok([0u8; 32])
    }

    fn finality_depth(&self, route: &BridgeRoute) -> Result<u64> {
        match &route.light_client {
            Some(LightClientAnchor::BitcoinHeaders { confirmations, .. }) => {
                Ok(u64::from(*confirmations))
            }
            _ => Err(refuse("a deposit route needs its header-chain anchor")),
        }
    }
}

// ---- the header chain ----

/// A block header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub prev: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl BlockHeader {
    /// The 80-byte serialization.
    pub fn encode(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    fn read(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            version: r.u32_le()?,
            prev: r.array()?,
            merkle_root: r.array()?,
            time: r.u32_le()?,
            bits: r.u32_le()?,
            nonce: r.u32_le()?,
        })
    }

    /// The block hash (internal byte order).
    pub fn hash(&self) -> [u8; 32] {
        sha256d(&self.encode())
    }
}

/// The target a compact `bits` value encodes, refusing negative or
/// overflowing encodings.
pub fn target(bits: u32) -> Result<U256> {
    let size = bits >> 24;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 {
        return Err(refuse("a negative or zero target"));
    }
    if size <= 3 {
        return Ok(U256::from(mantissa >> (8 * (3 - size))));
    }
    let shift = 8 * (size - 3);
    if 32 - mantissa.leading_zeros() + shift > 256 {
        return Err(refuse("a target over 256 bits"));
    }
    Ok(U256::from(mantissa) << shift)
}

/// The compact encoding of `target`.
pub fn compact(target: U256) -> u32 {
    let mut size = (256 - target.leading_zeros()).div_ceil(8);
    let mut c = if size <= 3 {
        target.as_u32() << (8 * (3 - size))
    } else {
        (target >> (8 * (size - 3))).as_u32()
    };
    if c & 0x0080_0000 != 0 {
        c >>= 8;
        size += 1;
    }
    c | (size << 24)
}

/// The work a header of `bits` adds: 2^256 / (target + 1).
fn work(bits: u32) -> Result<u128> {
    let t = target(bits)?;
    let w = (!t / (t + 1)) + 1;
    u128::try_from(w).map_err(|_| refuse("work out of range"))
}

/// What the client keeps for each header on its best chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    hash: [u8; 32],
    chainwork: u128,
    bits: u32,
    time: u32,
}

impl Record {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(&self.hash)
            .u128_be(self.chainwork)
            .u32_be(self.bits)
            .u32_be(self.time);
        w.into_bytes()
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let rec = Self {
            hash: r.array()?,
            chainwork: r.u128_be()?,
            bits: r.u32_be()?,
            time: r.u32_be()?,
        };
        r.finish()?;
        Ok(rec)
    }
}

struct Anchor {
    trusted_height: u64,
    trusted_header_hash: [u8; 32],
    confirmations: u64,
    deposit_script: Vec<u8>,
}

fn anchor_parts(anchor: &LightClientAnchor) -> Result<Anchor> {
    match anchor {
        LightClientAnchor::BitcoinHeaders {
            trusted_height,
            trusted_header_hash,
            confirmations,
            signers,
            threshold,
            ..
        } => Ok(Anchor {
            trusted_height: *trusted_height,
            trusted_header_hash: *trusted_header_hash,
            confirmations: u64::from(*confirmations),
            deposit_script: DepositDescriptor {
                signers: signers.clone(),
                threshold: *threshold,
            }
            .script_pubkey()?,
        }),
        _ => Err(refuse("the route's anchor is not a Bitcoin header anchor")),
    }
}

/// Where route state keeps the outputs the route's descriptor holds.
pub fn utxo_set_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    format!("{}:utxos", anchor.store_key(route))
}

/// The outputs the route's descriptor holds, oldest first.
pub fn read_utxos(state: &dyn RouteState, route: &BridgeRoute) -> Result<Vec<Utxo>> {
    let anchor = route
        .light_client
        .as_ref()
        .ok_or_else(|| refuse("a deposit route needs its header-chain anchor"))?;
    match state.get(&utxo_set_key(route, anchor)) {
        Some(b) => super::bitcoin_spend::decode_utxos(&b),
        None => Ok(Vec::new()),
    }
}

/// The output a deposit (a delivery body) pays the route's descriptor.
pub fn deposit_utxo(route: &BridgeRoute, body: &[u8]) -> Result<Utxo> {
    let mut r = Reader::new(body);
    let d = Deposit::read(&mut r)?;
    r.finish()?;
    let tx = Transaction::decode(&d.tx)?;
    let (vout, out) = tx
        .outputs
        .iter()
        .enumerate()
        .find(|(_, o)| <[u8; 32]>::from(Sha256::digest(&o.script)) == route.peer)
        .ok_or_else(|| bad("no output pays the deposit script"))?;
    Ok(Utxo {
        txid: d.txid(),
        vout: vout as u32,
        value: out.value,
    })
}

/// The route's deposit descriptor and its withdrawal fee rate, refused
/// unless the route's `peer` is the SHA-256 of the descriptor's output
/// script.
pub fn route_descriptor(route: &BridgeRoute) -> Result<(DepositDescriptor, u64)> {
    let Some(LightClientAnchor::BitcoinHeaders {
        signers,
        threshold,
        fee_rate,
        ..
    }) = &route.light_client
    else {
        return Err(refuse("a deposit route needs its header-chain anchor"));
    };
    let desc = DepositDescriptor {
        signers: signers.clone(),
        threshold: *threshold,
    };
    if <[u8; 32]>::from(Sha256::digest(desc.script_pubkey()?)) != route.peer {
        return Err(refuse(
            "the route's peer is not the hash of its deposit descriptor's script",
        ));
    }
    Ok((desc, *fee_rate))
}

fn prefix(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    anchor.store_key(route)
}

fn record_key(route: &BridgeRoute, anchor: &LightClientAnchor, height: u64) -> String {
    format!("{}:h:{height:020}", prefix(route, anchor))
}

fn tip_key(route: &BridgeRoute, anchor: &LightClientAnchor) -> String {
    prefix(route, anchor)
}

fn record(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    height: u64,
) -> Result<Option<Record>> {
    state
        .get(&record_key(route, anchor, height))
        .map(|b| Record::decode(&b))
        .transpose()
}

fn tip(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
) -> Result<Option<(u64, Record)>> {
    let Some(b) = state.get(&tip_key(route, anchor)) else {
        return Ok(None);
    };
    let height = u64::from_be_bytes(b.try_into().map_err(|_| refuse("tip record"))?);
    let rec = record(state, route, anchor, height)?.ok_or_else(|| refuse("tip record missing"))?;
    Ok(Some((height, rec)))
}

/// The bits a header at `height` must carry, given its parent.
fn expected_bits(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
    pending: &[(u64, Record)],
    height: u64,
    parent: &Record,
) -> Result<u32> {
    if !height.is_multiple_of(RETARGET_INTERVAL) {
        return Ok(parent.bits);
    }
    let first_height = height - RETARGET_INTERVAL;
    let first = match pending.iter().find(|(h, _)| *h == first_height) {
        Some((_, r)) => *r,
        None => record(state, route, anchor, first_height)?
            .ok_or_else(|| refuse("the period's first header is not known"))?,
    };
    let span = u64::from(parent.time.saturating_sub(first.time))
        .clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);
    let limit = target(POW_LIMIT_BITS)?;
    let new = (target(parent.bits)? * U256::from(span) / U256::from(TARGET_TIMESPAN)).min(limit);
    Ok(compact(new))
}

/// The Bitcoin header-chain light client. Its state lives in route state.
#[derive(Debug, Default)]
pub struct BitcoinLightClient;

impl LightClientVerifier for BitcoinLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::BitcoinHeaders
    }

    fn proven_lock_record(
        &self,
        _state: &dyn RouteState,
        _route: &BridgeRoute,
        _anchor: &LightClientAnchor,
        _lock: &[u8; 32],
        _proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        Err(refuse(
            "a Bitcoin leg is locked in a script and proven by its funding payment, not by a contract event",
        ))
    }

    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        let a = anchor_parts(anchor)?;
        let (deposit_bytes, payment) = prove_inclusion(state, route, anchor, proof)?;
        if body_hash(deposit_bytes) != *body {
            return Err(refuse("the proof is for another deposit"));
        }
        if !payment
            .tx
            .outputs
            .iter()
            .any(|o| o.script == a.deposit_script)
        {
            return Err(refuse(
                "the transaction pays no output to the deposit script",
            ));
        }
        Ok(())
    }

    fn advance(
        &self,
        state: &mut dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        update: &[u8],
    ) -> Result<LightClientHead> {
        let a = anchor_parts(anchor)?;
        let mut r = Reader::new(update);
        let mut writes = Vec::new();
        let tip_height = match r.u8()? {
            0 => {
                let header = BlockHeader::read(&mut r)?;
                r.finish()?;
                if header.hash() != a.trusted_header_hash {
                    return Err(refuse("the bootstrap header is not the anchor's"));
                }
                if tip(state, route, anchor)?.is_some() {
                    return Err(refuse("already bootstrapped"));
                }
                let rec = Record {
                    hash: header.hash(),
                    chainwork: work(header.bits)?,
                    bits: header.bits,
                    time: header.time,
                };
                writes.push((record_key(route, anchor, a.trusted_height), rec.encode()));
                a.trusted_height
            }
            1 => {
                let parent_height = r.u64_be()?;
                let n = r.u16_be()? as usize;
                if n == 0 || n > MAX_HEADERS_PER_UPDATE {
                    return Err(refuse(format!("an update of {n} headers")));
                }
                let (best_height, best) = tip(state, route, anchor)?
                    .ok_or_else(|| refuse("not bootstrapped from the anchor"))?;
                if parent_height < a.trusted_height || parent_height > best_height {
                    return Err(refuse("the update does not build on the client's chain"));
                }
                let mut parent = record(state, route, anchor, parent_height)?
                    .ok_or_else(|| refuse("the parent header is not known"))?;
                let mut pending: Vec<(u64, Record)> = Vec::with_capacity(n);
                for i in 0..n {
                    let header = BlockHeader::read(&mut r)?;
                    let height = parent_height + 1 + i as u64;
                    if header.prev != parent.hash {
                        return Err(refuse(format!(
                            "header {height} does not build on its parent"
                        )));
                    }
                    if header.bits
                        != expected_bits(state, route, anchor, &pending, height, &parent)?
                    {
                        return Err(refuse(format!(
                            "header {height} has the wrong difficulty target"
                        )));
                    }
                    let hash = header.hash();
                    if U256::from_le_bytes(hash) > target(header.bits)? {
                        return Err(refuse(format!("header {height} lacks the proof of work")));
                    }
                    let rec = Record {
                        hash,
                        chainwork: parent
                            .chainwork
                            .checked_add(work(header.bits)?)
                            .ok_or_else(|| refuse("chainwork overflow"))?,
                        bits: header.bits,
                        time: header.time,
                    };
                    pending.push((height, rec));
                    parent = rec;
                }
                r.finish()?;
                if parent.chainwork <= best.chainwork {
                    return Err(refuse(
                        "the update has no more work than the client's chain",
                    ));
                }
                for (h, rec) in &pending {
                    writes.push((record_key(route, anchor, *h), rec.encode()));
                }
                parent_height + n as u64
            }
            t => return Err(refuse(format!("unknown update tag {t}"))),
        };
        writes.push((tip_key(route, anchor), tip_height.to_be_bytes().to_vec()));
        state.apply(writes)?;
        Ok(head(tip_height, a.confirmations))
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        let a = anchor_parts(anchor).ok()?;
        let (h, _) = tip(state, route, anchor).ok()??;
        Some(head(h, a.confirmations))
    }
}

/// `finalized` is the highest block with the route's confirmations; `period`
/// is the chain tip.
fn head(tip_height: u64, confirmations: u64) -> LightClientHead {
    LightClientHead {
        kind: "bitcoin_headers",
        finalized: (tip_height + 1).saturating_sub(confirmations),
        period: tip_height,
        next_known: false,
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    //! Mined headers and Merkle branches, for route tests.

    use super::*;

    /// Mine a header on `prev`.
    pub fn mine(prev: [u8; 32], merkle_root: [u8; 32], time: u32, bits: u32) -> BlockHeader {
        let t = target(bits).unwrap();
        let mut h = BlockHeader {
            version: 0x2000_0000,
            prev,
            merkle_root,
            time,
            bits,
            nonce: 0,
        };
        while U256::from_le_bytes(h.hash()) > t {
            h.nonce += 1;
        }
        h
    }

    /// The Merkle root of `txids` and the branch for `index`.
    pub fn merkle(txids: &[[u8; 32]], index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
        let mut layer = txids.to_vec();
        let mut idx = index;
        let mut branch = Vec::new();
        while layer.len() > 1 {
            if layer.len() % 2 == 1 {
                layer.push(*layer.last().unwrap());
            }
            branch.push(layer[idx ^ 1]);
            layer = layer
                .chunks(2)
                .map(|p| sha256d(&[p[0], p[1]].concat()))
                .collect();
            idx /= 2;
        }
        (layer[0], branch)
    }

    pub fn bootstrap(h: &BlockHeader) -> Vec<u8> {
        let mut out = vec![0];
        out.extend_from_slice(&h.encode());
        out
    }

    pub fn extend(parent_height: u64, headers: &[BlockHeader]) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1).u64_be(parent_height).u16_be(headers.len() as u16);
        for h in headers {
            w.raw(&h.encode());
        }
        w.into_bytes()
    }

    pub fn proof(deposit: &Deposit, header: &BlockHeader, branch: &[[u8; 32]]) -> Vec<u8> {
        let mut w = Writer::new();
        w.be_bytes(&deposit.encode())
            .raw(&header.encode())
            .u8(branch.len() as u8);
        for s in branch {
            w.raw(s);
        }
        w.into_bytes()
    }
}
