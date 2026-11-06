//! SSZ hash tree roots of a beacon block body, from the Beacon API's JSON.
//!
//! A message proof carries the branch from a block's `receipts_root` up to
//! its body root. Building it needs the root of every other body field, so a
//! relayer merkleizes the whole body as the beacon node serves it
//! (`/eth/v2/beacon/blocks/{block_id}`, Electra and Fulu layout) and checks
//! the result against the block header's `body_root` before using it.

use ethnum::U256;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};

fn bad(what: impl Into<String>) -> BridgeError {
    BridgeError::InvalidParameter(format!("beacon block body: {}", what.into()))
}

fn hash(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// `zero[d]`: the root of a depth-`d` tree of zero chunks.
fn zero_hashes() -> [[u8; 32]; 64] {
    let mut z = [[0u8; 32]; 64];
    for d in 1..64 {
        z[d] = hash(&z[d - 1], &z[d - 1]);
    }
    z
}

/// The depth of a tree with room for `limit` chunks.
fn depth(limit: usize) -> usize {
    limit.max(1).next_power_of_two().trailing_zeros() as usize
}

/// Merkleize `chunks` into a tree with room for `limit` chunks.
fn merkleize(chunks: &[[u8; 32]], limit: usize) -> Result<[u8; 32]> {
    if chunks.len() > limit.max(1) {
        return Err(bad("more elements than the type allows"));
    }
    let zero = zero_hashes();
    let mut layer: Vec<[u8; 32]> = chunks.to_vec();
    for z in zero.iter().take(depth(limit)) {
        if layer.is_empty() {
            layer.push(*z);
        }
        if layer.len() % 2 == 1 {
            layer.push(*z);
        }
        layer = layer.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
    }
    Ok(layer.first().copied().unwrap_or(zero[0]))
}

/// Every branch node, leaf to root, of `index` among `leaves` in a tree of
/// `depth` levels.
pub(crate) fn branch(leaves: &[[u8; 32]], index: usize, depth: usize) -> Vec<[u8; 32]> {
    let zero = zero_hashes();
    let mut layer = leaves.to_vec();
    let mut i = index;
    let mut out = Vec::with_capacity(depth);
    for z in zero.iter().take(depth) {
        if layer.len() % 2 == 1 {
            layer.push(*z);
        }
        out.push(layer.get(i ^ 1).copied().unwrap_or(*z));
        layer = layer.chunks(2).map(|p| hash(&p[0], &p[1])).collect();
        i /= 2;
    }
    out
}

fn mix_in_length(root: [u8; 32], len: usize) -> [u8; 32] {
    let mut l = [0u8; 32];
    l[..8].copy_from_slice(&(len as u64).to_le_bytes());
    hash(&root, &l)
}

fn pack(bytes: &[u8]) -> Vec<[u8; 32]> {
    bytes
        .chunks(32)
        .map(|c| {
            let mut chunk = [0u8; 32];
            chunk[..c.len()].copy_from_slice(c);
            chunk
        })
        .collect()
}

/// The SSZ types a beacon block body is made of.
#[derive(Clone, Copy)]
enum Ty {
    Uint64,
    Uint256,
    /// `ByteVector[n]`.
    Bytes(usize),
    /// `ByteList[limit]`.
    ByteList(usize),
    Bitvector(usize),
    Bitlist(usize),
    List(&'static Ty, usize),
    Vector(&'static Ty, usize),
    Container(&'static [(&'static str, Ty)]),
}

const BYTES32: Ty = Ty::Bytes(32);
const SIGNATURE: Ty = Ty::Bytes(96);
const PUBKEY: Ty = Ty::Bytes(48);
const ADDRESS: Ty = Ty::Bytes(20);

const BEACON_BLOCK_HEADER: Ty = Ty::Container(&[
    ("slot", Ty::Uint64),
    ("proposer_index", Ty::Uint64),
    ("parent_root", BYTES32),
    ("state_root", BYTES32),
    ("body_root", BYTES32),
]);
const SIGNED_BEACON_BLOCK_HEADER: Ty =
    Ty::Container(&[("message", BEACON_BLOCK_HEADER), ("signature", SIGNATURE)]);
const PROPOSER_SLASHING: Ty = Ty::Container(&[
    ("signed_header_1", SIGNED_BEACON_BLOCK_HEADER),
    ("signed_header_2", SIGNED_BEACON_BLOCK_HEADER),
]);
const CHECKPOINT: Ty = Ty::Container(&[("epoch", Ty::Uint64), ("root", BYTES32)]);
const ATTESTATION_DATA: Ty = Ty::Container(&[
    ("slot", Ty::Uint64),
    ("index", Ty::Uint64),
    ("beacon_block_root", BYTES32),
    ("source", CHECKPOINT),
    ("target", CHECKPOINT),
]);
/// `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT`.
const MAX_ATTESTERS: usize = 2048 * 64;
const INDEXED_ATTESTATION: Ty = Ty::Container(&[
    ("attesting_indices", Ty::List(&Ty::Uint64, MAX_ATTESTERS)),
    ("data", ATTESTATION_DATA),
    ("signature", SIGNATURE),
]);
const ATTESTER_SLASHING: Ty = Ty::Container(&[
    ("attestation_1", INDEXED_ATTESTATION),
    ("attestation_2", INDEXED_ATTESTATION),
]);
const ATTESTATION: Ty = Ty::Container(&[
    ("aggregation_bits", Ty::Bitlist(MAX_ATTESTERS)),
    ("data", ATTESTATION_DATA),
    ("signature", SIGNATURE),
    ("committee_bits", Ty::Bitvector(64)),
]);
const DEPOSIT_DATA: Ty = Ty::Container(&[
    ("pubkey", PUBKEY),
    ("withdrawal_credentials", BYTES32),
    ("amount", Ty::Uint64),
    ("signature", SIGNATURE),
]);
const DEPOSIT: Ty = Ty::Container(&[("proof", Ty::Vector(&BYTES32, 33)), ("data", DEPOSIT_DATA)]);
const VOLUNTARY_EXIT: Ty = Ty::Container(&[("epoch", Ty::Uint64), ("validator_index", Ty::Uint64)]);
const SIGNED_VOLUNTARY_EXIT: Ty =
    Ty::Container(&[("message", VOLUNTARY_EXIT), ("signature", SIGNATURE)]);
const ETH1_DATA: Ty = Ty::Container(&[
    ("deposit_root", BYTES32),
    ("deposit_count", Ty::Uint64),
    ("block_hash", BYTES32),
]);
const SYNC_AGGREGATE: Ty = Ty::Container(&[
    ("sync_committee_bits", Ty::Bitvector(512)),
    ("sync_committee_signature", SIGNATURE),
]);
const WITHDRAWAL: Ty = Ty::Container(&[
    ("index", Ty::Uint64),
    ("validator_index", Ty::Uint64),
    ("address", ADDRESS),
    ("amount", Ty::Uint64),
]);
const TRANSACTION: Ty = Ty::ByteList(1 << 30);
/// The execution payload's fields, in order; `receipts_root` is the fourth.
const EXECUTION_PAYLOAD_FIELDS: &[(&str, Ty)] = &[
    ("parent_hash", BYTES32),
    ("fee_recipient", ADDRESS),
    ("state_root", BYTES32),
    ("receipts_root", BYTES32),
    ("logs_bloom", Ty::Bytes(256)),
    ("prev_randao", BYTES32),
    ("block_number", Ty::Uint64),
    ("gas_limit", Ty::Uint64),
    ("gas_used", Ty::Uint64),
    ("timestamp", Ty::Uint64),
    ("extra_data", Ty::ByteList(32)),
    ("base_fee_per_gas", Ty::Uint256),
    ("block_hash", BYTES32),
    ("transactions", Ty::List(&TRANSACTION, 1 << 20)),
    ("withdrawals", Ty::List(&WITHDRAWAL, 16)),
    ("blob_gas_used", Ty::Uint64),
    ("excess_blob_gas", Ty::Uint64),
];
const BLS_TO_EXECUTION_CHANGE: Ty = Ty::Container(&[
    ("validator_index", Ty::Uint64),
    ("from_bls_pubkey", PUBKEY),
    ("to_execution_address", ADDRESS),
]);
const SIGNED_BLS_TO_EXECUTION_CHANGE: Ty = Ty::Container(&[
    ("message", BLS_TO_EXECUTION_CHANGE),
    ("signature", SIGNATURE),
]);
const DEPOSIT_REQUEST: Ty = Ty::Container(&[
    ("pubkey", PUBKEY),
    ("withdrawal_credentials", BYTES32),
    ("amount", Ty::Uint64),
    ("signature", SIGNATURE),
    ("index", Ty::Uint64),
]);
const WITHDRAWAL_REQUEST: Ty = Ty::Container(&[
    ("source_address", ADDRESS),
    ("validator_pubkey", PUBKEY),
    ("amount", Ty::Uint64),
]);
const CONSOLIDATION_REQUEST: Ty = Ty::Container(&[
    ("source_address", ADDRESS),
    ("source_pubkey", PUBKEY),
    ("target_pubkey", PUBKEY),
]);
const EXECUTION_REQUESTS: Ty = Ty::Container(&[
    ("deposits", Ty::List(&DEPOSIT_REQUEST, 8192)),
    ("withdrawals", Ty::List(&WITHDRAWAL_REQUEST, 16)),
    ("consolidations", Ty::List(&CONSOLIDATION_REQUEST, 2)),
]);
/// The body's fields, in order; `execution_payload` is the tenth.
const BODY_FIELDS: &[(&str, Ty)] = &[
    ("randao_reveal", SIGNATURE),
    ("eth1_data", ETH1_DATA),
    ("graffiti", BYTES32),
    ("proposer_slashings", Ty::List(&PROPOSER_SLASHING, 16)),
    ("attester_slashings", Ty::List(&ATTESTER_SLASHING, 1)),
    ("attestations", Ty::List(&ATTESTATION, 8)),
    ("deposits", Ty::List(&DEPOSIT, 16)),
    ("voluntary_exits", Ty::List(&SIGNED_VOLUNTARY_EXIT, 16)),
    ("sync_aggregate", SYNC_AGGREGATE),
    ("execution_payload", Ty::Container(EXECUTION_PAYLOAD_FIELDS)),
    (
        "bls_to_execution_changes",
        Ty::List(&SIGNED_BLS_TO_EXECUTION_CHANGE, 16),
    ),
    ("blob_kzg_commitments", Ty::List(&Ty::Bytes(48), 4096)),
    ("execution_requests", EXECUTION_REQUESTS),
];

const PAYLOAD_INDEX: usize = 9;
const RECEIPTS_ROOT_INDEX: usize = 3;

fn hex(v: &Value, what: &str) -> Result<Vec<u8>> {
    let s = v
        .as_str()
        .ok_or_else(|| bad(format!("{what} is not a string")))?;
    hex::decode(s.trim_start_matches("0x")).map_err(|_| bad(format!("{what} is not hex")))
}

fn uint(v: &Value, what: &str) -> Result<U256> {
    let s = v
        .as_str()
        .map(str::to_string)
        .or_else(|| v.as_u64().map(|n| n.to_string()));
    s.and_then(|s| U256::from_str_radix(&s, 10).ok())
        .ok_or_else(|| bad(format!("{what} is not a decimal number")))
}

fn items<'a>(v: &'a Value, what: &str) -> Result<&'a Vec<Value>> {
    v.as_array()
        .ok_or_else(|| bad(format!("{what} is not a list")))
}

fn root(ty: &Ty, v: &Value, what: &str) -> Result<[u8; 32]> {
    match *ty {
        Ty::Uint64 => {
            let n = uint(v, what)?;
            if n > U256::from(u64::MAX) {
                return Err(bad(format!("{what} exceeds 64 bits")));
            }
            let mut chunk = [0u8; 32];
            chunk[..8].copy_from_slice(&n.as_u64().to_le_bytes());
            Ok(chunk)
        }
        Ty::Uint256 => Ok(uint(v, what)?.to_le_bytes()),
        Ty::Bytes(n) => {
            let b = hex(v, what)?;
            if b.len() != n {
                return Err(bad(format!("{what} is {} bytes, expected {n}", b.len())));
            }
            merkleize(&pack(&b), n.div_ceil(32))
        }
        Ty::ByteList(limit) => {
            let b = hex(v, what)?;
            if b.len() > limit {
                return Err(bad(format!("{what} is longer than {limit} bytes")));
            }
            Ok(mix_in_length(
                merkleize(&pack(&b), limit.div_ceil(32))?,
                b.len(),
            ))
        }
        Ty::Bitvector(bits) => {
            let b = hex(v, what)?;
            if b.len() != bits.div_ceil(8) {
                return Err(bad(format!("{what} is not {bits} bits")));
            }
            merkleize(&pack(&b), bits.div_ceil(256))
        }
        Ty::Bitlist(limit) => {
            let mut b = hex(v, what)?;
            let last = *b
                .last()
                .ok_or_else(|| bad(format!("{what} has no length bit")))?;
            if last == 0 {
                return Err(bad(format!("{what} has no length bit")));
            }
            let top = 7 - last.leading_zeros() as usize;
            let len = (b.len() - 1) * 8 + top;
            if len > limit {
                return Err(bad(format!("{what} is longer than {limit} bits")));
            }
            let n = b.len();
            b[n - 1] ^= 1 << top;
            if b[n - 1] == 0 {
                b.pop();
            }
            Ok(mix_in_length(
                merkleize(&pack(&b), limit.div_ceil(256))?,
                len,
            ))
        }
        Ty::List(elem, limit) => {
            let list = items(v, what)?;
            let (chunks, chunk_limit) = match *elem {
                Ty::Uint64 => {
                    let mut bytes = Vec::with_capacity(list.len() * 8);
                    for x in list {
                        bytes.extend_from_slice(&root(&Ty::Uint64, x, what)?[..8]);
                    }
                    (pack(&bytes), (limit * 8).div_ceil(32))
                }
                _ => (
                    list.iter()
                        .map(|x| root(elem, x, what))
                        .collect::<Result<Vec<_>>>()?,
                    limit,
                ),
            };
            if list.len() > limit {
                return Err(bad(format!("{what} has more than {limit} elements")));
            }
            Ok(mix_in_length(merkleize(&chunks, chunk_limit)?, list.len()))
        }
        Ty::Vector(elem, n) => {
            let list = items(v, what)?;
            if list.len() != n {
                return Err(bad(format!(
                    "{what} has {} elements, expected {n}",
                    list.len()
                )));
            }
            let chunks = list
                .iter()
                .map(|x| root(elem, x, what))
                .collect::<Result<Vec<_>>>()?;
            merkleize(&chunks, n)
        }
        Ty::Container(fields) => {
            let chunks = field_roots(fields, v)?;
            merkleize(&chunks, fields.len())
        }
    }
}

fn field_roots(fields: &[(&str, Ty)], v: &Value) -> Result<Vec<[u8; 32]>> {
    fields
        .iter()
        .map(|(name, ty)| {
            let f = v
                .get(*name)
                .ok_or_else(|| bad(format!("missing '{name}'")))?;
            root(ty, f, name)
        })
        .collect()
}

/// A body's root, its execution payload's `receipts_root`, and the branch
/// from that `receipts_root` to the body root (payload levels first).
pub struct ReceiptsBranch {
    /// The body's hash tree root.
    pub body_root: [u8; 32],
    /// The execution payload's `receipts_root`.
    pub receipts_root: [u8; 32],
    /// The nine branch nodes, leaf to root.
    pub branch: Vec<[u8; 32]>,
}

/// Merkleize `body` (a block's `message.body` as JSON) and prove its
/// `receipts_root`.
pub fn receipts_branch(body: &Value) -> Result<ReceiptsBranch> {
    let payload = body
        .get("execution_payload")
        .ok_or_else(|| bad("missing 'execution_payload'"))?;
    let payload_leaves = field_roots(EXECUTION_PAYLOAD_FIELDS, payload)?;
    let body_leaves = field_roots(BODY_FIELDS, body)?;
    let mut branch = branch(
        &payload_leaves,
        RECEIPTS_ROOT_INDEX,
        depth(EXECUTION_PAYLOAD_FIELDS.len()),
    );
    branch.extend(self::branch(
        &body_leaves,
        PAYLOAD_INDEX,
        depth(BODY_FIELDS.len()),
    ));
    Ok(ReceiptsBranch {
        body_root: merkleize(&body_leaves, BODY_FIELDS.len())?,
        receipts_root: payload_leaves[RECEIPTS_ROOT_INDEX],
        branch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkleization_matches_the_ssz_rules_on_small_cases() {
        // One chunk is its own root; two chunks hash together; an empty
        // list of room four is the depth-two zero root mixed with zero.
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(merkleize(&[a], 1).unwrap(), a);
        assert_eq!(merkleize(&[a, b], 2).unwrap(), hash(&a, &b));
        let z = zero_hashes();
        assert_eq!(merkleize(&[], 4).unwrap(), z[2]);
        assert_eq!(
            mix_in_length(merkleize(&[], 4).unwrap(), 0),
            hash(&z[2], &[0u8; 32])
        );
        assert!(merkleize(&[a, b, a], 2).is_err());
        // A branch reproduces the root it was taken from.
        let leaves: Vec<[u8; 32]> = (0..13u8).map(|i| [i; 32]).collect();
        let root = merkleize(&leaves, 16).unwrap();
        let br = branch(&leaves, 9, 4);
        let mut node = leaves[9];
        let mut i = 9;
        for s in &br {
            node = if i % 2 == 0 {
                hash(&node, s)
            } else {
                hash(s, &node)
            };
            i /= 2;
        }
        assert_eq!(node, root);
    }

    #[test]
    fn a_bitlist_drops_its_length_bit() {
        // Three bits set and the length bit: 0b1111 = length 3.
        let with = root(&Ty::Bitlist(8), &Value::String("0x0f".into()), "bits").unwrap();
        assert_eq!(
            with,
            mix_in_length(merkleize(&pack(&[0x07]), 1).unwrap(), 3)
        );
        assert!(root(&Ty::Bitlist(8), &Value::String("0x00".into()), "bits").is_err());
    }
}
