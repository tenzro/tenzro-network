//! Proofs that an Ethereum block's receipts contain a log.
//!
//! A block's receipts sit in a Merkle-Patricia trie keyed by the RLP of the
//! transaction index, whose root the execution payload carries
//! (`receipts_root`). [`verify_log`] walks a proof of one receipt from that
//! root, requires the transaction to have succeeded, and returns the log at
//! the requested index. Every node and value is decoded strictly: anything
//! that is not exactly canonical RLP is refused, and the proof may hold no
//! node the walk does not use.

use rlp::Rlp;
use sha3::{Digest, Keccak256};

use crate::error::{BridgeError, Result};

/// Most nodes a receipt proof may hold.
pub const MAX_PROOF_NODES: usize = 64;

/// One log of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptLog {
    /// The emitting contract.
    pub address: [u8; 20],
    /// The topics, in order.
    pub topics: Vec<[u8; 32]>,
    /// The non-indexed data.
    pub data: Vec<u8>,
}

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("receipt proof: {}", what.into()))
}

fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

/// An RLP item that spans `bytes` exactly.
fn whole(bytes: &[u8]) -> Result<Rlp<'_>> {
    let r = Rlp::new(bytes);
    let info = r.payload_info().map_err(|e| bad(format!("rlp: {e}")))?;
    if info.header_len + info.value_len != bytes.len() {
        return Err(bad("trailing bytes after an RLP item"));
    }
    Ok(r)
}

fn item<'a>(r: &Rlp<'a>, i: usize) -> Result<Rlp<'a>> {
    r.at(i).map_err(|e| bad(format!("rlp: {e}")))
}

fn data<'a>(r: &Rlp<'a>) -> Result<&'a [u8]> {
    if !r.is_data() {
        return Err(bad("expected an RLP string"));
    }
    r.data().map_err(|e| bad(format!("rlp: {e}")))
}

fn count(r: &Rlp<'_>) -> Result<usize> {
    if !r.is_list() {
        return Err(bad("expected an RLP list"));
    }
    r.item_count().map_err(|e| bad(format!("rlp: {e}")))
}

/// The trie key of transaction `index`: the nibbles of its RLP encoding.
pub fn receipt_key(index: u32) -> Vec<u8> {
    tenzro_types::eth_receipt::receipt_key(u64::from(index))
}

/// Decode a hex-prefix encoded path into (is_leaf, nibbles).
fn hex_prefix(path: &[u8]) -> Result<(bool, Vec<u8>)> {
    let (&first, rest) = path.split_first().ok_or_else(|| bad("empty node path"))?;
    let flag = first >> 4;
    let is_leaf = match flag {
        0 | 1 => false,
        2 | 3 => true,
        _ => return Err(bad("bad hex-prefix flag")),
    };
    let mut nibbles = Vec::with_capacity(rest.len() * 2 + 1);
    if flag & 1 == 1 {
        nibbles.push(first & 0x0f);
    } else if first & 0x0f != 0 {
        return Err(bad("non-zero padding in an even hex-prefix path"));
    }
    for b in rest {
        nibbles.push(b >> 4);
        nibbles.push(b & 0x0f);
    }
    Ok((is_leaf, nibbles))
}

/// What a trie node points to next.
enum Next<'a> {
    Hash([u8; 32]),
    Inline(&'a [u8]),
}

fn child<'a>(r: &Rlp<'a>) -> Result<Next<'a>> {
    if r.is_list() {
        let raw = r.as_raw();
        if raw.len() >= 32 {
            return Err(bad("an inline child must be shorter than 32 bytes"));
        }
        return Ok(Next::Inline(raw));
    }
    let d = data(r)?;
    match d.len() {
        32 => Ok(Next::Hash(d.try_into().expect("length checked"))),
        0 => Err(bad("the key is absent from the trie")),
        _ => Err(bad(
            "a child reference is neither a hash nor an inline node",
        )),
    }
}

/// Walk `proof` from `root` along `key` (nibbles) and return the value.
pub fn verify_trie_value(root: &[u8; 32], key: &[u8], proof: &[Vec<u8>]) -> Result<Vec<u8>> {
    if proof.len() > MAX_PROOF_NODES {
        return Err(bad("too many proof nodes"));
    }
    let mut next = Next::Hash(*root);
    let mut used = 0usize;
    let mut rest = key;
    loop {
        let node: &[u8] = match next {
            Next::Hash(h) => {
                let n = proof
                    .get(used)
                    .ok_or_else(|| bad("proof ends before the value"))?;
                if keccak(n) != h {
                    return Err(bad(format!("node {used} does not hash to its reference")));
                }
                used += 1;
                n
            }
            Next::Inline(raw) => raw,
        };
        let r = whole(node)?;
        match count(&r)? {
            17 => match rest.split_first() {
                None => {
                    let v = data(&item(&r, 16)?)?;
                    if v.is_empty() {
                        return Err(bad("the key is absent from the trie"));
                    }
                    return finish(v, used, proof.len());
                }
                Some((&nibble, tail)) => {
                    next = child(&item(&r, nibble as usize)?)?;
                    rest = tail;
                }
            },
            2 => {
                let (is_leaf, path) = hex_prefix(data(&item(&r, 0)?)?)?;
                if is_leaf {
                    if path != rest {
                        return Err(bad("the key is absent from the trie"));
                    }
                    return finish(data(&item(&r, 1)?)?, used, proof.len());
                }
                if path.is_empty() || !rest.starts_with(&path) {
                    return Err(bad("the key is absent from the trie"));
                }
                rest = &rest[path.len()..];
                next = child(&item(&r, 1)?)?;
            }
            _ => return Err(bad("a trie node is neither a branch nor a two-item node")),
        }
    }
}

fn finish(value: &[u8], used: usize, total: usize) -> Result<Vec<u8>> {
    if used != total {
        return Err(bad("the proof carries nodes the walk does not use"));
    }
    Ok(value.to_vec())
}

/// Decode a consensus receipt (typed or legacy), require that its
/// transaction succeeded, and return its logs.
pub fn successful_receipt_logs(receipt: &[u8]) -> Result<Vec<ReceiptLog>> {
    let body = match receipt.first() {
        Some(&t) if t < 0x7f => &receipt[1..],
        Some(_) => receipt,
        None => return Err(bad("empty receipt")),
    };
    let r = whole(body)?;
    if count(&r)? != 4 {
        return Err(bad("a receipt has four fields"));
    }
    let status = data(&item(&r, 0)?)?;
    if status != [1u8] {
        return Err(bad("the transaction did not succeed"));
    }
    let logs = item(&r, 3)?;
    let n = count(&logs)?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let log = item(&logs, i)?;
        if count(&log)? != 3 {
            return Err(bad("a log has three fields"));
        }
        let address: [u8; 20] = data(&item(&log, 0)?)?
            .try_into()
            .map_err(|_| bad("a log address is 20 bytes"))?;
        let t = item(&log, 1)?;
        let mut topics = Vec::new();
        for j in 0..count(&t)? {
            topics.push(
                data(&item(&t, j)?)?
                    .try_into()
                    .map_err(|_| bad("a topic is 32 bytes"))?,
            );
        }
        if topics.len() > 4 {
            return Err(bad("a log has at most four topics"));
        }
        out.push(ReceiptLog {
            address,
            topics,
            data: data(&item(&log, 2)?)?.to_vec(),
        });
    }
    Ok(out)
}

/// The log at `log_index` of the successful receipt of transaction
/// `tx_index`, proven against `receipts_root`.
pub fn verify_log(
    receipts_root: &[u8; 32],
    tx_index: u32,
    log_index: u32,
    proof: &[Vec<u8>],
) -> Result<ReceiptLog> {
    let receipt = verify_trie_value(receipts_root, &receipt_key(tx_index), proof)?;
    successful_receipt_logs(&receipt)?
        .into_iter()
        .nth(log_index as usize)
        .ok_or_else(|| bad("the receipt has no log at that index"))
}

/// A settlement lock's `Locked` event in family-neutral form: one leg of a
/// Tenzro plan locked on another chain. Every chain family's lock emits the
/// same fields; each family's decoder below reads its own encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockEvent {
    /// The plan.
    pub plan_id: [u8; 32],
    /// The leg's id, `leg_id(plan_id, index)`.
    pub leg_id: [u8; 32],
    /// The leg's index in the plan.
    pub index: u8,
    /// Who locked, left-padded to 32 bytes.
    pub payer: [u8; 32],
    /// Who a commit pays, left-padded to 32 bytes.
    pub recipient: [u8; 32],
    /// The asset, left-padded to 32 bytes; all zero for the native coin.
    pub asset: [u8; 32],
    /// Amount in the asset's smallest unit.
    pub amount: u128,
    /// Unix time (ms) from which the payer may reclaim an undecided leg.
    pub escape_at_ms: u64,
}

/// Length of [`LockEvent::encode`].
pub const LOCK_EVENT_LEN: usize = 32 * 5 + 1 + 16 + 8;

impl LockEvent {
    /// Canonical encoding, the body a route committee attests when the route
    /// has no light client: `plan_id || leg_id || index (1) || payer ||
    /// recipient || asset || amount (16, big endian) || escape_at_ms (8,
    /// big endian)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LOCK_EVENT_LEN);
        out.extend_from_slice(&self.plan_id);
        out.extend_from_slice(&self.leg_id);
        out.push(self.index);
        out.extend_from_slice(&self.payer);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.asset);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out.extend_from_slice(&self.escape_at_ms.to_be_bytes());
        out
    }

    /// Strict inverse of [`LockEvent::encode`].
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != LOCK_EVENT_LEN {
            return Err(bad(format!(
                "a lock event is {LOCK_EVENT_LEN} bytes, got {}",
                b.len()
            )));
        }
        let w = |at: usize| -> [u8; 32] { b[at..at + 32].try_into().expect("32 bytes") };
        Ok(Self {
            plan_id: w(0),
            leg_id: w(32),
            index: b[64],
            payer: w(65),
            recipient: w(97),
            asset: w(129),
            amount: u128::from_be_bytes(b[161..177].try_into().expect("16 bytes")),
            escape_at_ms: u64::from_be_bytes(b[177..185].try_into().expect("8 bytes")),
        })
    }
}

/// A settlement lock's reconciliation checkpoint: how many entries it has
/// recorded (locks, releases, refunds) and the running hash over them,
/// [`tenzro_types::settlement::recon_step`] folded from zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockCheckpoint {
    /// Entries recorded.
    pub count: u64,
    /// The running hash after them.
    pub acc: [u8; 32],
}

/// Length of [`LockCheckpoint::encode`].
pub const LOCK_CHECKPOINT_LEN: usize = 8 + 32;

impl LockCheckpoint {
    /// Canonical encoding, the body a route committee attests: `count (8,
    /// big endian) || acc`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LOCK_CHECKPOINT_LEN);
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.acc);
        out
    }

    /// Strict inverse of [`LockCheckpoint::encode`].
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != LOCK_CHECKPOINT_LEN {
            return Err(bad(format!(
                "a lock checkpoint is {LOCK_CHECKPOINT_LEN} bytes, got {}",
                b.len()
            )));
        }
        Ok(Self {
            count: u64::from_be_bytes(b[..8].try_into().expect("8 bytes")),
            acc: b[8..].try_into().expect("32 bytes"),
        })
    }
}

/// What a proof of a settlement lock's event shows: one leg's lock, or the
/// lock's reconciliation checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockRecord {
    /// A leg was locked.
    Locked(LockEvent),
    /// The lock's running reconciliation hash.
    Checkpoint(LockCheckpoint),
}

impl LockRecord {
    /// Decode an attested body: a lock event or a checkpoint, told apart by
    /// their fixed lengths.
    pub fn decode(b: &[u8]) -> Result<Self> {
        match b.len() {
            LOCK_EVENT_LEN => LockEvent::decode(b).map(Self::Locked),
            LOCK_CHECKPOINT_LEN => LockCheckpoint::decode(b).map(Self::Checkpoint),
            n => Err(bad(format!(
                "a lock record is {LOCK_EVENT_LEN} (event) or {LOCK_CHECKPOINT_LEN} (checkpoint) bytes, got {n}"
            ))),
        }
    }

    /// The canonical encoding [`LockRecord::decode`] reads.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Locked(e) => e.encode(),
            Self::Checkpoint(c) => c.encode(),
        }
    }
}

/// Topic 0 of the EVM lock's `Accumulator` event.
pub fn evm_accumulator_topic() -> [u8; 32] {
    keccak(b"Accumulator(uint64,bytes32)")
}

/// Read a proven EVM lock log: its `Locked` event or its `Accumulator(uint64
/// count, bytes32 acc)` checkpoint. The emitter is checked by the caller.
pub fn evm_lock_record(log: &ReceiptLog) -> Result<LockRecord> {
    if log.topics.first() != Some(&evm_accumulator_topic()) {
        return evm_lock_event(log).map(LockRecord::Locked);
    }
    if log.topics.len() != 1 || log.data.len() != 2 * 32 {
        return Err(bad(
            "an Accumulator event carries two words and no indexed field",
        ));
    }
    if log.data[..24].iter().any(|b| *b != 0) {
        return Err(bad("an Accumulator count is out of range"));
    }
    Ok(LockRecord::Checkpoint(LockCheckpoint {
        count: u64::from_be_bytes(log.data[24..32].try_into().expect("8 bytes")),
        acc: log.data[32..].try_into().expect("32 bytes"),
    }))
}

/// Topic 0 of the EVM lock's `Locked` event.
pub fn evm_locked_topic() -> [u8; 32] {
    keccak(b"Locked(bytes32,bytes32,uint8,address,address,address,uint256,uint64)")
}

/// Read the EVM lock's `Locked(bytes32 indexed planId, bytes32 indexed
/// legId, uint8 index, address payer, address recipient, address token,
/// uint256 amount, uint64 escapeAt)` from a proven log. The emitter is
/// checked by the caller.
pub fn evm_lock_event(log: &ReceiptLog) -> Result<LockEvent> {
    if log.topics.len() != 3 || log.topics[0] != evm_locked_topic() {
        return Err(bad("the log is not a Locked event"));
    }
    if log.data.len() != 6 * 32 {
        return Err(bad("a Locked event carries six words"));
    }
    let word =
        |i: usize| -> [u8; 32] { log.data[i * 32..(i + 1) * 32].try_into().expect("32 bytes") };
    let small = |w: [u8; 32], bytes: usize| -> Result<[u8; 32]> {
        if w[..32 - bytes].iter().any(|b| *b != 0) {
            return Err(bad("a Locked event field is out of range"));
        }
        Ok(w)
    };
    let index = small(word(0), 1)?[31];
    let amount = small(word(4), 16)?;
    let escape = small(word(5), 8)?;
    Ok(LockEvent {
        plan_id: log.topics[1],
        leg_id: log.topics[2],
        index,
        payer: small(word(1), 20)?,
        recipient: small(word(2), 20)?,
        asset: small(word(3), 20)?,
        amount: u128::from_be_bytes(amount[16..].try_into().expect("16 bytes")),
        escape_at_ms: u64::from_be_bytes(escape[24..].try_into().expect("8 bytes"))
            .saturating_mul(1000),
    })
}

/// Read a Move (Aptos or Sui) settlement lock's `Locked { plan_id: vector<u8>, leg_id:
/// vector<u8>, index: u8, payer: address, recipient: address, asset:
/// address, amount: u64, escape_at_ms: u64 }` from its BCS event data.
pub fn move_lock_event(data: &[u8]) -> Result<LockEvent> {
    let mut r = super::canonical::Reader::new(data);
    let id = |r: &mut super::canonical::Reader<'_>| -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(r.bcs_bytes(32)?).map_err(|_| bad("a Locked id is 32 bytes"))
    };
    let plan_id = id(&mut r)?;
    let leg_id = id(&mut r)?;
    let ev = LockEvent {
        plan_id,
        leg_id,
        index: r.u8()?,
        payer: r.array()?,
        recipient: r.array()?,
        asset: r.array()?,
        amount: u128::from(r.u64_le()?),
        escape_at_ms: r.u64_le()?,
    };
    r.finish()?;
    Ok(ev)
}

/// Read a Move (Aptos or Sui) settlement lock's event named `name`: its
/// `Locked` event, or its `Accumulator { count: u64, acc: vector<u8> }`
/// checkpoint.
pub fn move_lock_record(name: &str, data: &[u8]) -> Result<LockRecord> {
    match name {
        "Locked" => move_lock_event(data).map(LockRecord::Locked),
        "Accumulator" => {
            let mut r = super::canonical::Reader::new(data);
            let count = r.u64_le()?;
            let acc = <[u8; 32]>::try_from(r.bcs_bytes(32)?)
                .map_err(|_| bad("an Accumulator hash is 32 bytes"))?;
            r.finish()?;
            Ok(LockRecord::Checkpoint(LockCheckpoint { count, acc }))
        }
        _ => Err(bad(
            "the event is neither a Locked nor an Accumulator event",
        )),
    }
}

/// A receipts trie, built by a relayer from every receipt of a block to
/// prove one of them.
pub use tenzro_types::eth_receipt::trie;

/// A receipt as `eth_getBlockReceipts` returns it, in its consensus
/// encoding: the transaction type byte (for typed transactions) followed by
/// the RLP of status, cumulative gas used, logs bloom and logs.
pub fn receipt_from_json(v: &serde_json::Value) -> Result<Vec<u8>> {
    let text = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .ok_or_else(|| bad(format!("receipt has no '{k}'")))
    };
    let bytes = |s: &str, what: &str| {
        hex::decode(s.trim_start_matches("0x")).map_err(|_| bad(format!("{what} is not hex")))
    };
    let quantity = |s: &str, what: &str| {
        u64::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|_| bad(format!("{what} is not a quantity")))
    };
    let ty = quantity(text("type")?, "type")?;
    let status = quantity(text("status")?, "status")?;
    let gas = quantity(text("cumulativeGasUsed")?, "cumulativeGasUsed")?;
    let bloom = bytes(text("logsBloom")?, "logsBloom")?;
    let logs = v
        .get("logs")
        .and_then(|l| l.as_array())
        .ok_or_else(|| bad("receipt has no logs"))?;
    let mut s = rlp::RlpStream::new_list(4);
    if status == 1 {
        s.append(&1u8);
    } else {
        s.append_empty_data();
    }
    s.append(&gas);
    s.append(&bloom);
    s.begin_list(logs.len());
    for log in logs {
        let field = |k: &str| log.get(k).ok_or_else(|| bad(format!("log has no '{k}'")));
        let topics = field("topics")?
            .as_array()
            .ok_or_else(|| bad("topics is not a list"))?;
        s.begin_list(3);
        s.append(&bytes(
            field("address")?.as_str().unwrap_or_default(),
            "address",
        )?);
        s.begin_list(topics.len());
        for t in topics {
            s.append(&bytes(t.as_str().unwrap_or_default(), "topic")?);
        }
        s.append(&bytes(field("data")?.as_str().unwrap_or_default(), "data")?);
    }
    let body = s.out().to_vec();
    let ty = u8::try_from(ty).map_err(|_| bad("type out of range"))?;
    Ok(if ty == 0 {
        body
    } else {
        [vec![ty], body].concat()
    })
}

#[cfg(test)]
mod tests {
    use rlp::RlpStream;

    use super::*;

    pub(crate) fn receipt(status: u8, logs: &[ReceiptLog]) -> Vec<u8> {
        let mut s = RlpStream::new_list(4);
        if status == 1 {
            s.append(&1u8);
        } else {
            s.append_empty_data();
        }
        s.append(&21_000u64);
        s.append(&vec![0u8; 256]);
        s.begin_list(logs.len());
        for l in logs {
            s.begin_list(3);
            s.append(&l.address.to_vec());
            s.begin_list(l.topics.len());
            for t in &l.topics {
                s.append(&t.to_vec());
            }
            s.append(&l.data);
        }
        let mut out = vec![2u8];
        out.extend_from_slice(&s.out());
        out
    }

    fn log(n: u8) -> ReceiptLog {
        ReceiptLog {
            address: [n; 20],
            topics: vec![[n; 32], [n + 1; 32]],
            data: vec![n; 40],
        }
    }

    fn trie_of(receipts: &[Vec<u8>], at: u32) -> ([u8; 32], Vec<Vec<u8>>) {
        let entries: Vec<_> = receipts
            .iter()
            .enumerate()
            .map(|(i, r)| (receipt_key(i as u32), r.clone()))
            .collect();
        trie::build(&entries, &receipt_key(at))
    }

    fn sample_lock() -> LockEvent {
        LockEvent {
            plan_id: [1; 32],
            leg_id: [2; 32],
            index: 3,
            payer: [4; 32],
            recipient: [5; 32],
            asset: [6; 32],
            amount: u128::MAX - 7,
            escape_at_ms: 1_801_209_600_000,
        }
    }

    #[test]
    fn a_lock_event_round_trips_and_refuses_other_lengths() {
        let ev = sample_lock();
        let bytes = ev.encode();
        assert_eq!(bytes.len(), LOCK_EVENT_LEN);
        assert_eq!(LockEvent::decode(&bytes).unwrap(), ev);
        assert!(LockEvent::decode(&bytes[1..]).is_err());
        let mut long = bytes.clone();
        long.push(0);
        assert!(LockEvent::decode(&long).is_err());
    }

    /// The shared vector: the log the EVM lock emits in its forge test.
    #[test]
    fn the_evm_locked_log_decodes_to_the_shared_vector() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sdk/fixtures/settlement_lock/locked_event.json"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let h32 = |k: &str| -> [u8; 32] {
            hex::decode(v[k].as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap()
        };
        let pad = |k: &str| -> [u8; 32] {
            let b = hex::decode(v[k].as_str().unwrap().trim_start_matches("0x")).unwrap();
            let mut w = [0u8; 32];
            w[32 - b.len()..].copy_from_slice(&b);
            w
        };
        let log = ReceiptLog {
            address: [9; 20],
            topics: vec![evm_locked_topic(), h32("plan_id"), h32("leg_id")],
            data: hex::decode(v["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        };
        let ev = evm_lock_event(&log).unwrap();
        assert_eq!(ev.plan_id, h32("plan_id"));
        assert_eq!(ev.leg_id, h32("leg_id"));
        assert_eq!(u64::from(ev.index), v["index"].as_u64().unwrap());
        assert_eq!(ev.payer, pad("payer"));
        assert_eq!(ev.recipient, pad("recipient"));
        assert_eq!(ev.asset, [0; 32]);
        assert_eq!(ev.amount, u128::from(v["amount"].as_u64().unwrap()));
        assert_eq!(ev.escape_at_ms, v["escape_at"].as_u64().unwrap() * 1000);

        let mut other = log.clone();
        other.topics[0][0] ^= 1;
        assert!(evm_lock_event(&other).is_err(), "another event");
        let mut wide = log.clone();
        wide.data[32] = 1;
        assert!(evm_lock_event(&wide).is_err(), "an index above u8");
        let mut short = log;
        short.data.pop();
        assert!(evm_lock_event(&short).is_err());
    }

    #[test]
    fn an_evm_lock_log_is_its_lock_or_its_checkpoint() {
        // Accumulator(uint64 count, bytes32 acc): two words, no indexed field.
        let acc = [0xac; 32];
        let mut data = vec![0u8; 24];
        data.extend_from_slice(&6u64.to_be_bytes());
        data.extend_from_slice(&acc);
        let log = ReceiptLog {
            address: [7; 20],
            topics: vec![evm_accumulator_topic()],
            data,
        };
        assert_eq!(
            evm_lock_record(&log).unwrap(),
            LockRecord::Checkpoint(LockCheckpoint { count: 6, acc })
        );
        let mut wide = log.clone();
        wide.data[0] = 1;
        assert!(evm_lock_record(&wide).is_err(), "a count above u64");
        let mut indexed = log.clone();
        indexed.topics.push([0; 32]);
        assert!(evm_lock_record(&indexed).is_err());
        let mut short = log;
        short.data.pop();
        assert!(evm_lock_record(&short).is_err());
        // Anything else is read as a Locked event.
        let other = ReceiptLog {
            address: [7; 20],
            topics: vec![[9; 32]],
            data: Vec::new(),
        };
        assert!(evm_lock_record(&other).is_err());

        let cp = LockCheckpoint { count: 6, acc };
        assert_eq!(
            LockRecord::decode(&cp.encode()).unwrap(),
            LockRecord::Checkpoint(cp)
        );
        assert!(LockRecord::decode(&[0; 41]).is_err());
    }

    #[test]
    fn a_log_of_a_successful_receipt_is_proven() {
        let receipts: Vec<_> = (0..20u8)
            .map(|i| receipt(1, &[log(i), log(i + 50)]))
            .collect();
        for at in [0u32, 1, 7, 16, 19] {
            let (root, proof) = trie_of(&receipts, at);
            let got = verify_log(&root, at, 1, &proof).unwrap();
            assert_eq!(got, log(at as u8 + 50));
        }
    }

    #[test]
    fn a_failed_transaction_or_a_wrong_proof_is_refused() {
        let mut receipts: Vec<_> = (0..5u8).map(|i| receipt(1, &[log(i)])).collect();
        receipts[3] = receipt(0, &[log(3)]);
        let (root, proof) = trie_of(&receipts, 3);
        assert!(verify_log(&root, 3, 0, &proof).is_err(), "failed tx");

        let (root, proof) = trie_of(&receipts, 2);
        verify_log(&root, 2, 0, &proof).unwrap();
        assert!(verify_log(&root, 1, 0, &proof).is_err(), "other index");
        assert!(verify_log(&root, 2, 1, &proof).is_err(), "no such log");
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert!(verify_log(&wrong_root, 2, 0, &proof).is_err());
        let mut extra = proof.clone();
        extra.push(vec![0xc0]);
        assert!(verify_log(&root, 2, 0, &extra).is_err(), "unused node");
        let mut tampered = proof.clone();
        let last = tampered.len() - 1;
        let n = tampered[last].len();
        tampered[last][n - 1] ^= 1;
        assert!(verify_log(&root, 2, 0, &tampered).is_err());
    }
}
