//! TON light client: masterchain blocks finalized by the validator set,
//! followed from key block to key block.
//!
//! The light client starts from a governed key block (its seqno and root
//! hash) and takes the validator set from that block's configuration
//! (parameter 34) through a Merkle proof of the block. The masterchain
//! validators are the set's first `main` members. A masterchain block is
//! final once validators holding more than two thirds of their weight
//! signed a finalize vote for the consensus candidate that names it:
//!
//! ```text
//! signed   = consensus.dataToSign session_id (consensus.simplex.finalizeVote
//!              (consensus.candidateId slot sha256(candidate)))
//! candidate = consensus.candidateHashData(Ordinary|Empty) block:tonNode.blockIdExt ...
//! ```
//!
//! - **Bootstrap** (`0x00 | proof`): a Merkle proof of the anchor key block
//!   whose configuration holds the validator set.
//! - **Handover** (`0x01 | finalization | proof`): the next key block,
//!   finalized by the current set, whose previous key block is the current
//!   one; its configuration's set becomes current.
//! - **Message**: a masterchain block finalized by the current set (and
//!   not past the next key block), a Merkle proof of it down to the shard
//!   descriptor of the basechain shard that holds the route's bridge
//!   contract, Merkle proofs of that shard's blocks from the one the
//!   descriptor names back to the one holding the transaction, and in that
//!   block the transaction of the bridge contract whose external outbound
//!   message carries exactly the delivered transfer record.
//!
//! Encodings, big-endian unless noted:
//!
//! ```text
//! finalization  session_id:32 slot:u32 candidate:u16-len bytes count:u16 { index:u16 signature:64 }
//! update        0x00 boc:u32-len | 0x01 finalization boc:u32-len
//! proof         finalization masterchain_boc:u32-len count:u8 { shard_boc:u32-len } lt:u64 index:u16
//! store         key_seqno:u32 key_root:32 set [ 0x00 | 0x01 prev_seqno:u32 prev_root:32 set ]
//! set           count:u16 { pubkey:32 weight:u64 }
//! ```

use std::sync::Arc;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use super::canonical::{Reader, Writer};
use super::light_client::{LightClientHead, LightClientVerifier};
use super::move_event::MoveTransfer;
use super::state::RouteState;
use super::ton::encode_message;
use super::ton_cell::{
    Aug, Cell, Slice, bits_of, bits_of_uint, dict_all, dict_get, parse_boc, proven_tree,
};
use super::{BridgeRoute, LightClientAnchor, LightClientKind};
use crate::error::{BridgeError, Result};

/// The masterchain's workchain.
pub const MASTERCHAIN: i32 = -1;
/// The masterchain's one shard.
pub const MASTERCHAIN_SHARD: u64 = 0x8000_0000_0000_0000;
/// Most shard blocks a message proof may walk back.
pub const MAX_SHARD_CHAIN: usize = 16;
/// Largest bag of cells a proof may carry.
pub const MAX_BOC: usize = 1 << 21;

const TL_DATA_TO_SIGN: u32 = 0xa8e3_3df8;
const TL_FINALIZE_VOTE: u32 = 0x40a7_e105;
const TL_CANDIDATE_ID: u32 = 0xb691_cd3f;
const TL_CANDIDATE_ORDINARY: u32 = 0xe8f9_bcdc;
const TL_CANDIDATE_EMPTY: u32 = 0x72b4_d933;

const TAG_BLOCK: u64 = 0x11ef_55aa;
const TAG_BLOCK_INFO: u64 = 0x9bc7_a987;
const TAG_BLOCK_EXTRA: u64 = 0x4a33_f6fd;
const TAG_MC_EXTRA: u64 = 0xcca5;
const TAG_ED25519: u64 = 0x8e81_278a;

fn refuse(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("ton light client: {}", what.into()))
}

/// A block id as the consensus names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockId {
    pub workchain: i32,
    pub shard: u64,
    pub seqno: u32,
    pub root_hash: [u8; 32],
    pub file_hash: [u8; 32],
}

/// The masterchain validators of a key block's set, in index order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    pub validators: Vec<([u8; 32], u64)>,
}

impl ValidatorSet {
    fn total(&self) -> u128 {
        self.validators.iter().map(|(_, w)| u128::from(*w)).sum()
    }
}

/// What validators signed to finalize a masterchain block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalization {
    pub session_id: [u8; 32],
    pub slot: u32,
    /// The TL `consensus.CandidateHashData` naming the block.
    pub candidate: Vec<u8>,
    /// Each signer's index in the masterchain set, and its signature.
    pub signatures: Vec<(u16, [u8; 64])>,
}

fn tl_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = if b.len() < 254 {
        vec![b.len() as u8]
    } else {
        let mut v = vec![254];
        v.extend_from_slice(&(b.len() as u32).to_le_bytes()[..3]);
        v
    };
    out.extend_from_slice(b);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

impl Finalization {
    pub fn write(&self, w: &mut Writer) {
        w.raw(&self.session_id).u32_be(self.slot);
        w.u16_be(self.candidate.len() as u16).raw(&self.candidate);
        w.u16_be(self.signatures.len() as u16);
        for (i, s) in &self.signatures {
            w.u16_be(*i).raw(s);
        }
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Self> {
        let session_id = r.array()?;
        let slot = r.u32_be()?;
        let n = r.u16_be()? as usize;
        let candidate = r.take(n)?.to_vec();
        let count = r.u16_be()? as usize;
        let signatures = (0..count)
            .map(|_| Ok((r.u16_be()?, r.array()?)))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            session_id,
            slot,
            candidate,
            signatures,
        })
    }

    /// The block the candidate names.
    pub fn block(&self) -> Result<BlockId> {
        let c = &self.candidate;
        if c.len() < 84 {
            return Err(refuse("a candidate too short to name a block"));
        }
        let ctor = u32::from_le_bytes(c[..4].try_into().expect("4 bytes"));
        if ctor != TL_CANDIDATE_ORDINARY && ctor != TL_CANDIDATE_EMPTY {
            return Err(refuse("not a candidate of a block"));
        }
        Ok(BlockId {
            workchain: i32::from_le_bytes(c[4..8].try_into().expect("4 bytes")),
            shard: u64::from_le_bytes(c[8..16].try_into().expect("8 bytes")),
            seqno: u32::from_le_bytes(c[16..20].try_into().expect("4 bytes")),
            root_hash: c[20..52].try_into().expect("32 bytes"),
            file_hash: c[52..84].try_into().expect("32 bytes"),
        })
    }

    /// The bytes each finalize vote signs.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut vote = TL_FINALIZE_VOTE.to_le_bytes().to_vec();
        vote.extend_from_slice(&TL_CANDIDATE_ID.to_le_bytes());
        vote.extend_from_slice(&self.slot.to_le_bytes());
        vote.extend_from_slice(&Sha256::digest(&self.candidate));
        let mut m = TL_DATA_TO_SIGN.to_le_bytes().to_vec();
        m.extend_from_slice(&self.session_id);
        m.extend_from_slice(&tl_bytes(&vote));
        m
    }

    /// The masterchain block this finalizes, once validators of `set`
    /// holding more than two thirds of its weight signed it.
    pub fn verify(&self, set: &ValidatorSet) -> Result<BlockId> {
        let block = self.block()?;
        if block.workchain != MASTERCHAIN || block.shard != MASTERCHAIN_SHARD {
            return Err(refuse("the candidate is not a masterchain block"));
        }
        let message = self.signed_message();
        let mut seen = vec![false; set.validators.len()];
        let mut weight: u128 = 0;
        for (i, sig) in &self.signatures {
            let i = *i as usize;
            let (key, w) = set
                .validators
                .get(i)
                .ok_or_else(|| refuse("a signer outside the validator set"))?;
            if std::mem::replace(&mut seen[i], true) {
                return Err(refuse("a validator signed twice"));
            }
            let vk = VerifyingKey::from_bytes(key)
                .map_err(|_| refuse("a validator key does not decode"))?;
            vk.verify(&message, &Signature::from_bytes(sig))
                .map_err(|_| refuse(format!("validator {i}'s signature does not verify")))?;
            weight += u128::from(*w);
        }
        if weight * 3 <= set.total() * 2 {
            return Err(refuse(
                "validators holding more than two thirds of the weight did not sign",
            ));
        }
        Ok(block)
    }
}

/// What a block's header says that the light client needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockInfo {
    pub not_master: bool,
    pub key_block: bool,
    pub after_merge: bool,
    pub seq_no: u32,
    pub workchain: i32,
    pub prev_key_block_seqno: u32,
    /// The previous block's seqno and root hash (none after a merge).
    pub prev: Option<(u32, [u8; 32])>,
}

fn block_refs(block: &Arc<Cell>) -> Result<Slice> {
    let mut s = block.parse()?;
    if s.uint(32)? != TAG_BLOCK {
        return Err(refuse("not a block"));
    }
    s.skip(32)?;
    Ok(s)
}

/// Read a block's header.
pub fn block_info(block: &Arc<Cell>) -> Result<BlockInfo> {
    let mut b = block_refs(block)?;
    let mut s = b.ref_slice()?;
    if s.uint(32)? != TAG_BLOCK_INFO {
        return Err(refuse("not a block header"));
    }
    s.skip(32)?;
    let not_master = s.bit()?;
    let after_merge = s.bit()?;
    s.skip(4)?;
    let key_block = s.bit()?;
    let vert_seqno_incr = s.bit()?;
    let flags = s.uint(8)?;
    let seq_no = s.uint(32)? as u32;
    s.skip(32)?;
    if s.uint(2)? != 0 {
        return Err(refuse("a malformed shard id"));
    }
    s.skip(6)?;
    let workchain = s.int(32)? as i32;
    s.skip(64 + 32 + 64 + 64 + 32 + 32 + 32)?;
    let prev_key_block_seqno = s.uint(32)? as u32;
    if flags & 1 == 1 {
        s.skip(8 + 32 + 64)?;
    }
    if not_master {
        s.reference()?;
    }
    let prev = if after_merge {
        None
    } else {
        let mut p = s.ref_slice()?;
        p.skip(64)?;
        let seq = p.uint(32)? as u32;
        Some((seq, p.bytes::<32>()?))
    };
    let _ = vert_seqno_incr;
    Ok(BlockInfo {
        not_master,
        key_block,
        after_merge,
        seq_no,
        workchain,
        prev_key_block_seqno,
        prev,
    })
}

/// A block's `BlockExtra`, after its three descriptor references.
fn block_extra(block: &Arc<Cell>) -> Result<Slice> {
    let mut b = block_refs(block)?;
    b.reference()?;
    b.reference()?;
    b.reference()?;
    let mut e = b.ref_slice()?;
    if e.uint(32)? != TAG_BLOCK_EXTRA {
        return Err(refuse("not a block extra"));
    }
    Ok(e)
}

/// A masterchain block's `McBlockExtra`, just after its `key_block` bit,
/// and that bit.
fn mc_extra(block: &Arc<Cell>) -> Result<(Slice, bool)> {
    let mut e = block_extra(block)?;
    e.reference()?;
    e.reference()?;
    e.reference()?;
    e.skip(512)?;
    if !e.bit()? {
        return Err(refuse("a masterchain block without its masterchain extra"));
    }
    let mut m = e.ref_slice()?;
    if m.uint(16)? != TAG_MC_EXTRA {
        return Err(refuse("not a masterchain extra"));
    }
    let key = m.bit()?;
    Ok((m, key))
}

/// The validator set (configuration parameter 34) a key block carries.
pub fn key_block_validators(block: &Arc<Cell>) -> Result<ValidatorSet> {
    let (mut m, key) = mc_extra(block)?;
    if !key {
        return Err(refuse("not a key block"));
    }
    if m.bit()? {
        m.reference()?;
    }
    if m.bit()? {
        m.reference()?;
    }
    m.skip_currency()?;
    m.skip_currency()?;
    m.reference()?;
    m.skip(256)?;
    let config = m.ref_slice()?;
    let mut param = dict_get(config, 32, &bits_of_uint(34, 32), Aug::None)?
        .ok_or_else(|| refuse("the configuration has no validator set"))?;
    parse_validator_set(&param.reference()?)
}

/// Parse a `ValidatorSet` and keep its masterchain members.
pub fn parse_validator_set(cell: &Arc<Cell>) -> Result<ValidatorSet> {
    let mut s = cell.parse()?;
    let tag = s.uint(8)?;
    s.skip(64)?;
    let total = s.uint(16)? as usize;
    let main = s.uint(16)? as usize;
    let list = match tag {
        0x11 => s,
        0x12 => {
            s.skip(64)?;
            if !s.bit()? {
                return Err(refuse("an empty validator set"));
            }
            s.ref_slice()?
        }
        _ => return Err(refuse("not a validator set")),
    };
    if main == 0 || main > total {
        return Err(refuse("a validator set with no masterchain members"));
    }
    let entries = dict_all(list, 16)?;
    if entries.len() != total {
        return Err(refuse("the validator list does not hold `total` members"));
    }
    let mut validators = Vec::with_capacity(main);
    for (i, (key, mut v)) in entries.into_iter().take(main).enumerate() {
        if key != bits_of_uint(i as u64, 16) {
            return Err(refuse("the validator list is not indexed 0..total"));
        }
        let t = v.uint(8)?;
        if (t != 0x53 && t != 0x73) || v.uint(32)? != TAG_ED25519 {
            return Err(refuse("a validator without an Ed25519 key"));
        }
        let key = v.bytes::<32>()?;
        let weight = v.uint(64)?;
        validators.push((key, weight));
    }
    Ok(ValidatorSet { validators })
}

/// The descriptor (seqno, root hash) of the shard of `workchain` that holds
/// `account`, from a masterchain block's shard hashes.
pub fn shard_descr(
    mc_block: &Arc<Cell>,
    workchain: i32,
    account: &[u8; 32],
) -> Result<(u32, [u8; 32])> {
    let (mut m, _) = mc_extra(mc_block)?;
    if !m.bit()? {
        return Err(refuse("a masterchain block without shard hashes"));
    }
    let hashes = m.ref_slice()?;
    let mut tree = dict_get(
        hashes,
        32,
        &bits_of_uint(workchain as u32 as u64, 32),
        Aug::None,
    )?
    .ok_or_else(|| refuse("the masterchain block names no shard of that workchain"))?
    .ref_slice()?;
    let bits = bits_of(account);
    let mut depth = 0;
    while tree.bit()? {
        let left = tree.reference()?;
        let right = tree.reference()?;
        tree = if bits[depth] { right } else { left }.parse()?;
        depth += 1;
        if depth > 60 {
            return Err(refuse("a shard tree deeper than 60"));
        }
    }
    let tag = tree.uint(4)?;
    if tag != 0xa && tag != 0xb {
        return Err(refuse("not a shard descriptor"));
    }
    let seq_no = tree.uint(32)? as u32;
    tree.skip(32 + 64 + 64)?;
    Ok((seq_no, tree.bytes::<32>()?))
}

/// The external outbound message `index` of the transaction at `lt` of
/// `account` in a shard block: its creation logical time and its body.
pub fn account_out_message(
    block: &Arc<Cell>,
    account: &[u8; 32],
    lt: u64,
    index: u16,
) -> Result<(u64, Slice)> {
    let mut e = block_extra(block)?;
    e.reference()?;
    e.reference()?;
    let mut blocks = e.ref_slice()?;
    if !blocks.bit()? {
        return Err(refuse("the block holds no account blocks"));
    }
    let root = blocks.ref_slice()?;
    let mut acc = dict_get(root, 256, &bits_of(account), Aug::Currency)?
        .ok_or_else(|| refuse("the block holds no transaction of the account"))?;
    if acc.uint(4)? != 0x5 || acc.bytes::<32>()? != *account {
        return Err(refuse("a malformed account block"));
    }
    let mut tx = dict_get(acc, 64, &bits_of_uint(lt, 64), Aug::Currency)?
        .ok_or_else(|| refuse("the account has no transaction at that logical time"))?
        .ref_slice()?;
    if tx.uint(4)? != 0b0111 || tx.bytes::<32>()? != *account || tx.uint(64)? != lt {
        return Err(refuse("a malformed transaction"));
    }
    let mut msgs = tx.ref_slice()?;
    if msgs.bit()? {
        msgs.reference()?;
    }
    if !msgs.bit()? {
        return Err(refuse("the transaction sent no message"));
    }
    let out = msgs.ref_slice()?;
    let mut m = dict_get(out, 15, &bits_of_uint(u64::from(index), 15), Aug::None)?
        .ok_or_else(|| refuse("the transaction has no message at that index"))?
        .ref_slice()?;
    if m.uint(2)? != 0b11 {
        return Err(refuse("not an external outbound message"));
    }
    if m.uint(2)? != 0b10 || m.bit()? {
        return Err(refuse("the message's source is not a standard address"));
    }
    let wc = m.int(8)? as i32;
    if wc != 0 || m.bytes::<32>()? != *account {
        return Err(refuse("the message was not sent by the account"));
    }
    match m.uint(2)? {
        0b00 => {}
        0b01 => {
            let len = m.uint(9)? as usize;
            m.skip(len)?;
        }
        _ => return Err(refuse("a malformed external destination")),
    }
    let created_lt = m.uint(64)?;
    m.skip(32)?;
    if m.bit()? {
        return Err(refuse("a message carrying a state init"));
    }
    let body = if m.bit()? { m.ref_slice()? } else { m };
    Ok((created_lt, body))
}

/// Read the transfer record the bridge contract writes as a message body:
/// sequence, selectors, sender, token and endpoint in the body cell, then
/// recipient and amount in its one reference.
pub fn read_record(mut body: Slice) -> Result<MoveTransfer> {
    if body.remaining() != 960 || body.refs_left() != 1 {
        return Err(refuse("the message body is not a transfer record"));
    }
    let sequence = body.uint(64)?;
    let source_selector = body.uint(64)?;
    let dest_selector = body.uint(64)?;
    let sender = body.bytes()?;
    let token = body.bytes()?;
    let endpoint = body.bytes()?;
    let mut tail = body.ref_slice()?;
    if tail.remaining() != 384 || tail.refs_left() != 0 {
        return Err(refuse("the message body is not a transfer record"));
    }
    let recipient = tail.bytes()?;
    let amount = (u128::from(tail.uint(64)?) << 64) | u128::from(tail.uint(64)?);
    Ok(MoveTransfer {
        sequence,
        source_selector,
        dest_selector,
        sender,
        token,
        endpoint,
        recipient,
        amount,
    })
}

/// The light client's state: the current key block and its set, and the one
/// before it, whose epoch's messages are still proven after a handover.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Store {
    key_seqno: u32,
    key_root: [u8; 32],
    set: ValidatorSet,
    prev: Option<(u32, [u8; 32], ValidatorSet)>,
}

fn write_set(w: &mut Writer, set: &ValidatorSet) {
    w.u16_be(set.validators.len() as u16);
    for (k, wt) in &set.validators {
        w.raw(k).u64_be(*wt);
    }
}

fn read_set(r: &mut Reader<'_>) -> Result<ValidatorSet> {
    let n = r.u16_be()? as usize;
    let validators = (0..n)
        .map(|_| Ok((r.array()?, r.u64_be()?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(ValidatorSet { validators })
}

impl Store {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(self.key_seqno).raw(&self.key_root);
        write_set(&mut w, &self.set);
        match &self.prev {
            None => {
                w.u8(0);
            }
            Some((seqno, root, set)) => {
                w.u8(1).u32_be(*seqno).raw(root);
                write_set(&mut w, set);
            }
        }
        w.into_bytes()
    }

    fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b);
        let key_seqno = r.u32_be()?;
        let key_root = r.array()?;
        let set = read_set(&mut r)?;
        let prev = match r.u8()? {
            0 => None,
            1 => Some((r.u32_be()?, r.array()?, read_set(&mut r)?)),
            _ => return Err(refuse("a malformed light client store")),
        };
        r.finish()?;
        Ok(Self {
            key_seqno,
            key_root,
            set,
            prev,
        })
    }
}

fn load(
    state: &dyn RouteState,
    route: &BridgeRoute,
    anchor: &LightClientAnchor,
) -> Result<Option<Store>> {
    state
        .get(&anchor.store_key(route))
        .map(|b| Store::decode(&b))
        .transpose()
}

fn read_boc(r: &mut Reader<'_>) -> Result<Arc<Cell>> {
    let n = r.u32_be()? as usize;
    if n > MAX_BOC {
        return Err(refuse("a proof too large"));
    }
    let mut roots = parse_boc(r.take(n)?)?;
    if roots.len() != 1 {
        return Err(refuse("a proof has one root"));
    }
    Ok(roots.remove(0))
}

fn anchor_parts(anchor: &LightClientAnchor) -> Result<(u32, [u8; 32])> {
    match anchor {
        LightClientAnchor::TonKeyBlock {
            trusted_seqno,
            trusted_root_hash,
        } => Ok((*trusted_seqno, *trusted_root_hash)),
        _ => Err(refuse("the route's anchor is not a TON key block")),
    }
}

/// The external outbound message a message proof proves: its creation
/// logical time and body, from a masterchain block the light client's set
/// finalized, down through the shard that holds `account`.
pub fn proven_message(
    store_bytes: &[u8],
    account: &[u8; 32],
    proof: &[u8],
) -> Result<(u64, Slice)> {
    let store = Store::decode(store_bytes)?;
    let mut r = Reader::new(proof);
    let fin = Finalization::read(&mut r)?;
    // A block finalized by the current set is of the current epoch; one
    // finalized by the previous set is of the epoch that ended at the
    // current key block, so a transfer still undelivered when the set
    // changed can be proven.
    let (id, key_seqno, before) = match fin.verify(&store.set) {
        Ok(id) => (id, store.key_seqno, None),
        Err(current) => match &store.prev {
            Some((seqno, _, set)) => (
                fin.verify(set).map_err(|_| current)?,
                *seqno,
                Some(store.key_seqno),
            ),
            None => return Err(current),
        },
    };
    let mc = proven_tree(&read_boc(&mut r)?, &id.root_hash)?;
    let info = block_info(&mc)?;
    if info.not_master || info.seq_no != id.seqno {
        return Err(refuse(
            "the proof is not of the finalized masterchain block",
        ));
    }
    let under_key =
        info.prev_key_block_seqno == key_seqno || (info.key_block && info.seq_no == key_seqno);
    if !under_key || before.is_some_and(|next| info.seq_no >= next) {
        return Err(refuse(
            "the block is not under the light client's key block; relay the handover first",
        ));
    }
    let (seq_no, root) = shard_descr(&mc, 0, account)?;
    let count = r.u8()? as usize;
    if count == 0 || count > MAX_SHARD_CHAIN {
        return Err(refuse("a message proof walks 1 to 16 shard blocks"));
    }
    let mut want = (seq_no, root);
    let mut shard = None;
    for _ in 0..count {
        let tree = proven_tree(&read_boc(&mut r)?, &want.1)?;
        let info = block_info(&tree)?;
        if !info.not_master || info.workchain != 0 || info.seq_no != want.0 {
            return Err(refuse("a shard block is not the one its successor names"));
        }
        if let Some(prev) = info.prev {
            want = prev;
        }
        shard = Some(tree);
    }
    let lt = r.u64_be()?;
    let index = r.u16_be()?;
    r.finish()?;
    account_out_message(&shard.expect("at least one"), account, lt, index)
}

/// Tag of the settlement lock's `Locked` log.
pub const LOG_LOCKED: u64 = 0x61;
/// Tag of the settlement lock's `Accumulator` checkpoint log.
pub const LOG_ACCUMULATOR: u64 = 0x64;

/// Read the settlement lock's log: its `Locked` log, or its `Accumulator`
/// checkpoint: tag (8), count (64), acc (256).
pub fn read_lock_record(body: Slice) -> Result<super::receipt_proof::LockRecord> {
    let mut b = body.clone();
    if b.remaining() == 8 + 64 + 256 && b.refs_left() == 0 && b.uint(8)? == LOG_ACCUMULATOR {
        let count = b.uint(64)?;
        let acc = b.bytes()?;
        return Ok(super::receipt_proof::LockRecord::Checkpoint(
            super::receipt_proof::LockCheckpoint { count, acc },
        ));
    }
    read_lock_log(body).map(super::receipt_proof::LockRecord::Locked)
}

/// Read the settlement lock's `Locked` log: tag (8), plan_id (256), leg_id
/// (256), index (8), payer (256), and in a reference recipient (256), amount
/// (coins), escape_at (64, seconds), asset (256, the jetton master, 0 for TON).
pub fn read_lock_log(mut body: Slice) -> Result<super::receipt_proof::LockEvent> {
    if body.remaining() != 8 + 256 * 3 + 8 || body.refs_left() != 1 || body.uint(8)? != LOG_LOCKED {
        return Err(refuse("the message is not a Locked log"));
    }
    let plan_id = body.bytes()?;
    let leg_id = body.bytes()?;
    let index = body.uint(8)? as u8;
    let payer = body.bytes()?;
    let mut tail = body.ref_slice()?;
    let recipient = tail.bytes()?;
    let len = tail.uint(4)? as usize;
    let mut amount = 0u128;
    for _ in 0..len {
        amount = (amount << 8) | u128::from(tail.uint(8)?);
    }
    let escape_at_ms = tail.uint(64)?.saturating_mul(1000);
    let asset = tail.bytes()?;
    if tail.remaining() != 0 || tail.refs_left() != 0 {
        return Err(refuse("the message is not a Locked log"));
    }
    Ok(super::receipt_proof::LockEvent {
        plan_id,
        leg_id,
        index,
        payer,
        recipient,
        asset,
        amount,
        escape_at_ms,
    })
}

/// The TON light client. See the module docs.
#[derive(Default)]
pub struct TonLightClient;

impl LightClientVerifier for TonLightClient {
    fn kind(&self) -> LightClientKind {
        LightClientKind::TonValidators
    }

    fn proven_lock_record(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        lock: &[u8; 32],
        proof: &[u8],
    ) -> Result<super::receipt_proof::LockRecord> {
        anchor_parts(anchor)?;
        let store = state
            .get(&anchor.store_key(route))
            .ok_or_else(|| refuse("not bootstrapped from the route's anchor"))?;
        let (_, body) = proven_message(&store, lock, proof)?;
        read_lock_record(body)
    }

    fn verify(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
        body_hash: &[u8; 32],
        proof: &[u8],
    ) -> Result<()> {
        anchor_parts(anchor)?;
        let store = state
            .get(&anchor.store_key(route))
            .ok_or_else(|| refuse("not bootstrapped from the route's anchor"))?;
        let (created_lt, body) = proven_message(&store, &route.ramp, proof)?;
        let record = read_record(body)?;
        let delivered = encode_message(&route.ramp, created_lt, &record);
        if <[u8; 32]>::from(Keccak256::digest(&delivered)) != *body_hash {
            return Err(refuse("the proven message is not the delivered body"));
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
        let (trusted_seqno, trusted_root) = anchor_parts(anchor)?;
        let existing = load(state, route, anchor)?;
        let mut r = Reader::new(update);
        let store = match r.u8()? {
            0 => {
                if existing.is_some() {
                    return Err(refuse("already bootstrapped from this anchor"));
                }
                let block = proven_tree(&read_boc(&mut r)?, &trusted_root)?;
                r.finish()?;
                let info = block_info(&block)?;
                if info.not_master || !info.key_block || info.seq_no != trusted_seqno {
                    return Err(refuse("the bootstrap is not the anchor's key block"));
                }
                Store {
                    key_seqno: trusted_seqno,
                    key_root: trusted_root,
                    set: key_block_validators(&block)?,
                    prev: None,
                }
            }
            1 => {
                let current =
                    existing.ok_or_else(|| refuse("not bootstrapped from the route's anchor"))?;
                let fin = Finalization::read(&mut r)?;
                let id = fin.verify(&current.set)?;
                let block = proven_tree(&read_boc(&mut r)?, &id.root_hash)?;
                r.finish()?;
                let info = block_info(&block)?;
                if info.not_master
                    || !info.key_block
                    || info.seq_no != id.seqno
                    || info.prev_key_block_seqno != current.key_seqno
                {
                    return Err(refuse(
                        "the handover is not the key block after the current one",
                    ));
                }
                Store {
                    key_seqno: id.seqno,
                    key_root: id.root_hash,
                    set: key_block_validators(&block)?,
                    prev: Some((current.key_seqno, current.key_root, current.set)),
                }
            }
            _ => return Err(refuse("unknown update kind")),
        };
        state.apply(vec![(anchor.store_key(route), store.encode())])?;
        Ok(head(&store))
    }

    fn head(
        &self,
        state: &dyn RouteState,
        route: &BridgeRoute,
        anchor: &LightClientAnchor,
    ) -> Option<LightClientHead> {
        load(state, route, anchor).ok().flatten().map(|s| head(&s))
    }
}

fn head(s: &Store) -> LightClientHead {
    LightClientHead {
        kind: "ton_validators",
        finalized: u64::from(s.key_seqno),
        period: u64::from(s.key_seqno),
        next_known: false,
    }
}

/// Building updates and proofs from full blocks, as a relayer does: each
/// proof keeps exactly the cells the light client reads.
pub mod relay {
    use std::sync::Arc;

    use serde_json::Value;

    use super::super::canonical::Writer;
    use super::super::ton_cell::{Cell, merkle_proof, parse_boc, record_reads, serialize_boc};
    use super::*;

    fn root(boc: &[u8]) -> Result<Arc<Cell>> {
        parse_boc(boc)?
            .into_iter()
            .next()
            .ok_or_else(|| refuse("an empty bag of cells"))
    }

    fn proof_of<T>(
        block: &Arc<Cell>,
        read: impl FnOnce(&Arc<Cell>) -> Result<T>,
    ) -> Result<(T, Vec<u8>)> {
        let (out, reads) = record_reads(|| read(block));
        let out = out?;
        Ok((out, serialize_boc(&merkle_proof(block, &reads)?)))
    }

    fn put_boc(w: &mut Writer, boc: &[u8]) {
        w.u32_be(boc.len() as u32).raw(boc);
    }

    /// A finalization from the signatures a node serves for a masterchain
    /// block (`getMasterchainBlockSignatures`: `session_id`, `slot`,
    /// `candidate` and the signatures by `node_id_short`), with each signer
    /// placed by its index in `set`.
    pub fn finalization(response: &Value, set: &ValidatorSet) -> Result<Finalization> {
        use base64::Engine as _;
        let b64 = |v: &Value| {
            v.as_str()
                .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok())
                .ok_or_else(|| refuse("a signature field is not base64"))
        };
        let d = response.get("result").unwrap_or(response);
        let ids: Vec<[u8; 32]> = set
            .validators
            .iter()
            .map(|(k, _)| {
                let mut h = Sha256::new();
                h.update(0x4813_b4c6u32.to_le_bytes());
                h.update(k);
                h.finalize().into()
            })
            .collect();
        let mut signatures = Vec::new();
        for s in d["signatures"].as_array().cloned().unwrap_or_default() {
            let node = b64(&s["node_id_short"])?;
            let Some(i) = ids.iter().position(|id| id.as_slice() == node.as_slice()) else {
                continue;
            };
            let sig: [u8; 64] = b64(&s["signature"])?
                .try_into()
                .map_err(|_| refuse("a signature is 64 bytes"))?;
            signatures.push((i as u16, sig));
        }
        Ok(Finalization {
            session_id: b64(&d["session_id"])?
                .try_into()
                .map_err(|_| refuse("a session id is 32 bytes"))?,
            slot: d["slot"].as_u64().ok_or_else(|| refuse("no slot"))? as u32,
            candidate: b64(&d["candidate"])?,
            signatures,
        })
    }

    /// The bootstrap update from the anchor key block (its full bag of cells).
    pub fn bootstrap(key_block: &[u8]) -> Result<Vec<u8>> {
        let block = root(key_block)?;
        let (_, proof) = proof_of(&block, |b| {
            block_info(b)?;
            key_block_validators(b)
        })?;
        let mut w = Writer::new();
        w.u8(0);
        put_boc(&mut w, &proof);
        Ok(w.into_bytes())
    }

    /// The handover update to the next key block.
    pub fn handover(fin: &Finalization, key_block: &[u8]) -> Result<Vec<u8>> {
        let block = root(key_block)?;
        let (_, proof) = proof_of(&block, |b| {
            block_info(b)?;
            key_block_validators(b)
        })?;
        let mut w = Writer::new();
        w.u8(1);
        fin.write(&mut w);
        put_boc(&mut w, &proof);
        Ok(w.into_bytes())
    }

    /// A message proof for the external message `index` of `account`'s
    /// transaction at `lt`: the finalized masterchain block, and the shard
    /// blocks from the one it names back to the one holding the transaction
    /// (full bags of cells, newest first).
    pub fn message_proof(
        fin: &Finalization,
        mc_block: &[u8],
        shard_blocks: &[Vec<u8>],
        account: &[u8; 32],
        lt: u64,
        index: u16,
    ) -> Result<Vec<u8>> {
        let mc = root(mc_block)?;
        let (_, mc_proof) = proof_of(&mc, |b| {
            block_info(b)?;
            shard_descr(b, 0, account)
        })?;
        let mut w = Writer::new();
        fin.write(&mut w);
        put_boc(&mut w, &mc_proof);
        w.u8(shard_blocks.len() as u8);
        for (i, boc) in shard_blocks.iter().enumerate() {
            let block = root(boc)?;
            let last = i + 1 == shard_blocks.len();
            let (_, proof) = proof_of(&block, |b| {
                block_info(b)?;
                if last {
                    // The body is read as the route reads it, so the proof
                    // keeps every cell of a transfer record or a lock log.
                    let (_, body) = account_out_message(b, account, lt, index)?;
                    let _ = read_record(body.clone());
                    let _ = read_lock_record(body);
                }
                Ok(())
            })?;
            put_boc(&mut w, &proof);
        }
        w.u64_be(lt).u16_be(index);
        Ok(w.into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::super::test_support::MemState;
    use super::super::ton_cell::parse_boc;
    use super::super::{BridgeRouteAdapter, ChainFamily, MintRateLimit, VerifierQuorum};
    use super::*;

    /// Recorded from TON mainnet: two consecutive key blocks, a masterchain
    /// block under the second, the basechain shard block it names, and the
    /// finalize signatures of the second key block and of the masterchain
    /// block, as public nodes serve them.
    const MAINNET: &str = include_str!("../../tests/fixtures/ton/mainnet.json");

    fn hexb(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// `(workchain,shard,seqno,root_hash,file_hash)`.
    fn id_of(v: &Value) -> (u32, [u8; 32]) {
        let s = v.as_str().unwrap().trim_matches(|c| c == '(' || c == ')');
        let parts: Vec<&str> = s.split(',').collect();
        (
            parts[2].parse().unwrap(),
            hex::decode(parts[3]).unwrap().try_into().unwrap(),
        )
    }

    fn root(boc: &[u8]) -> Arc<Cell> {
        parse_boc(boc).unwrap().remove(0)
    }

    fn route(account: [u8; 32], anchor: LightClientAnchor) -> BridgeRoute {
        BridgeRoute {
            adapter: BridgeRouteAdapter::Contract,
            family: ChainFamily::Ton,
            source_chain: "ton".into(),
            source_chain_id: 1,
            local_selector: 2,
            peer: [1; 32],
            ramp: account,
            local_endpoint: [2; 32],
            remote_token: [3; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: vec![],
                threshold: 0,
            },
            blessing: None,
            light_client: Some(anchor),
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
        }
    }

    /// A message of the epoch that just ended is still proven after the
    /// next key block's handover: transfers left undelivered when the set
    /// changed are not stranded.
    #[test]
    fn a_message_of_the_ended_epoch_is_proven_after_a_handover() {
        let f: Value = serde_json::from_str(MAINNET).unwrap();
        let k = hexb(&f["key_block"]["boc"]);
        let k0 = hexb(&f["previous_key_block"]["boc"]);
        let mc = hexb(&f["masterchain_block"]["boc"]);
        let shard = hexb(&f["shard_block"]["boc"]);
        let (k_seqno, k_root) = id_of(&f["key_block"]["id"]);
        let account: [u8; 32] = hexb(&f["account_id"]).try_into().unwrap();
        let lt = f["lt"].as_u64().unwrap();
        let set = key_block_validators(&root(&k)).unwrap();
        let next_set = key_block_validators(&root(&k0)).unwrap();
        let fin_b = relay::finalization(&f["masterchain_block"]["signatures"], &set).unwrap();
        let shard_root = root(&shard);
        let index = (0..64u16)
            .find(|i| account_out_message(&shard_root, &account, lt, *i).is_ok())
            .expect("the transaction sent an external message");
        let proof = relay::message_proof(
            &fin_b,
            &mc,
            std::slice::from_ref(&shard),
            &account,
            lt,
            index,
        )
        .unwrap();
        // The client has since followed the next key block, whose set is
        // another.
        let store = Store {
            key_seqno: block_info(&root(&mc)).unwrap().seq_no + 1,
            key_root: [9; 32],
            set: next_set,
            prev: Some((k_seqno, k_root, set)),
        }
        .encode();
        proven_message(&store, &account, &proof).expect("the ended epoch's message");
    }

    #[test]
    fn mainnet_key_blocks_are_followed_and_a_message_is_proven_through_its_shard() {
        let f: Value = serde_json::from_str(MAINNET).unwrap();
        let k0 = hexb(&f["previous_key_block"]["boc"]);
        let k = hexb(&f["key_block"]["boc"]);
        let mc = hexb(&f["masterchain_block"]["boc"]);
        let shard = hexb(&f["shard_block"]["boc"]);
        let (k0_seqno, k0_root) = id_of(&f["previous_key_block"]["id"]);
        let (k_seqno, k_root) = id_of(&f["key_block"]["id"]);
        let account: [u8; 32] = hexb(&f["account_id"]).try_into().unwrap();
        let lt = f["lt"].as_u64().unwrap();

        // The full blocks hash to the ids the network names them by.
        assert_eq!(root(&k0).hash(0), k0_root);
        assert_eq!(root(&k).hash(0), k_root);

        let anchor = LightClientAnchor::TonKeyBlock {
            trusted_seqno: k0_seqno,
            trusted_root_hash: k0_root,
        };
        let route = route(account, anchor.clone());
        let lc = TonLightClient;
        let mut state = MemState::default();

        // A bootstrap from another block than the anchor is refused.
        assert!(
            lc.advance(&mut state, &route, &anchor, &relay::bootstrap(&k).unwrap())
                .is_err()
        );
        let head = lc
            .advance(&mut state, &route, &anchor, &relay::bootstrap(&k0).unwrap())
            .unwrap();
        assert_eq!(head.finalized, u64::from(k0_seqno));

        // The next key block, finalized by the first one's validators.
        let set0 = key_block_validators(&root(&k0)).unwrap();
        let fin_k = relay::finalization(&f["key_block"]["signatures"], &set0).unwrap();
        assert_eq!(fin_k.block().unwrap().root_hash, k_root);
        let mut thin = fin_k.clone();
        thin.signatures.truncate(thin.signatures.len() / 2);
        assert!(
            lc.advance(
                &mut state,
                &route,
                &anchor,
                &relay::handover(&thin, &k).unwrap()
            )
            .is_err()
        );
        let mut forged = fin_k.clone();
        forged.signatures[0].1[5] ^= 1;
        assert!(
            lc.advance(
                &mut state,
                &route,
                &anchor,
                &relay::handover(&forged, &k).unwrap()
            )
            .is_err()
        );
        let head = lc
            .advance(
                &mut state,
                &route,
                &anchor,
                &relay::handover(&fin_k, &k).unwrap(),
            )
            .unwrap();
        assert_eq!(head.finalized, u64::from(k_seqno));

        // A message of the account, in the basechain shard block the
        // finalized masterchain block names.
        let set = key_block_validators(&root(&k)).unwrap();
        let fin_b = relay::finalization(&f["masterchain_block"]["signatures"], &set).unwrap();
        let shard_root = root(&shard);
        let index = (0..64u16)
            .find(|i| account_out_message(&shard_root, &account, lt, *i).is_ok())
            .expect("the transaction sent an external message");
        let proof = relay::message_proof(
            &fin_b,
            &mc,
            std::slice::from_ref(&shard),
            &account,
            lt,
            index,
        )
        .unwrap();
        let store = state.get(&anchor.store_key(&route)).unwrap();
        let (created_lt, body) = proven_message(&store, &account, &proof).unwrap();
        assert!(created_lt > lt);
        // The proof prunes what the route does not read, so the body is the
        // same cell by its level-0 hash.
        assert_eq!(
            body.cell().hash(0),
            account_out_message(&shard_root, &account, lt, index)
                .unwrap()
                .1
                .cell()
                .hash(0)
        );

        // It is not a bridge transfer record, so no delivery rests on it.
        let err = lc
            .verify(&state, &route, &anchor, &[0; 32], &proof)
            .unwrap_err();
        assert!(err.to_string().contains("not a transfer record"), "{err}");

        // Another account, a forged signature, or a tampered proof: refused.
        assert!(proven_message(&store, &[0x55; 32], &proof).is_err());
        let mut bad_fin = fin_b.clone();
        bad_fin.signatures[1].1[0] ^= 1;
        let bad = relay::message_proof(
            &bad_fin,
            &mc,
            std::slice::from_ref(&shard),
            &account,
            lt,
            index,
        )
        .unwrap();
        assert!(proven_message(&store, &account, &bad).is_err());
        for at in [200, proof.len() / 2, proof.len() - 20] {
            let mut t = proof.clone();
            t[at] ^= 1;
            assert!(proven_message(&store, &account, &t).is_err(), "byte {at}");
        }
    }
}
