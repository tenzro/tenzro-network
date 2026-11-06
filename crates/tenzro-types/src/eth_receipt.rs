//! Ethereum receipts and the receipts trie (Yellow Paper section 4.3.1,
//! EIP-2718).
//!
//! A receipt's consensus encoding is the RLP of `[status, cumulativeGasUsed,
//! logsBloom, logs]`, prefixed by the transaction type byte when the
//! transaction is typed (type 0 is the bare RLP). A block's receipts sit in
//! a Merkle-Patricia trie keyed by the RLP of each transaction's index; its
//! root is the block's `receiptsRoot`.

use rlp::RlpStream;
use sha3::{Digest, Keccak256};

use crate::block::LogsBloom;
use crate::primitives::Hash;

fn keccak(b: &[u8]) -> [u8; 32] {
    Keccak256::digest(b).into()
}

/// The root of a trie with no entries: Keccak-256 of the RLP empty string.
pub const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

/// The trie key of transaction `index`: the nibbles of its RLP encoding.
pub fn receipt_key(index: u64) -> Vec<u8> {
    let encoded = rlp::encode(&index);
    encoded.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// One log of a receipt: the emitting address, its topics and its data.
pub struct ReceiptLogRef<'a> {
    /// The emitting contract.
    pub address: &'a [u8],
    /// The topics, in order.
    pub topics: &'a [&'a [u8]],
    /// The non-indexed data.
    pub data: &'a [u8],
}

/// The consensus encoding of a receipt.
pub fn encode_receipt<'a>(
    tx_type: u8,
    success: bool,
    cumulative_gas_used: u64,
    logs: impl IntoIterator<Item = ReceiptLogRef<'a>> + Clone,
) -> Vec<u8> {
    let mut bloom = LogsBloom::default();
    let mut count = 0usize;
    for l in logs.clone() {
        bloom.accrue_log(l.address, l.topics);
        count += 1;
    }
    let mut s = RlpStream::new_list(4);
    if success {
        s.append(&1u8);
    } else {
        s.append_empty_data();
    }
    s.append(&cumulative_gas_used);
    s.append(&bloom.0.as_slice());
    s.begin_list(count);
    for l in logs {
        s.begin_list(3);
        s.append(&l.address);
        s.begin_list(l.topics.len());
        for t in l.topics {
            s.append(t);
        }
        s.append(&l.data);
    }
    let body = s.out().to_vec();
    if tx_type == 0 {
        body
    } else {
        [vec![tx_type], body].concat()
    }
}

/// The receipts root of a block: the root of the trie over `receipts`, each
/// a transaction index and its encoded receipt. When two receipts share an
/// index the later one stands.
pub fn receipts_root(receipts: impl IntoIterator<Item = (u64, Vec<u8>)>) -> Hash {
    let entries: std::collections::BTreeMap<Vec<u8>, Vec<u8>> = receipts
        .into_iter()
        .map(|(i, r)| (receipt_key(i), r))
        .collect();
    let entries: Vec<(Vec<u8>, Vec<u8>)> = entries.into_iter().collect();
    Hash::new(trie::root(&entries))
}

/// A Merkle-Patricia trie built over every entry at once, for a root and
/// the proof of one value.
pub mod trie {
    use rlp::RlpStream;

    use super::{EMPTY_TRIE_ROOT, keccak};

    fn hp(nibbles: &[u8], leaf: bool) -> Vec<u8> {
        let flag = if leaf { 2u8 } else { 0 };
        let mut out = Vec::new();
        let rest = if nibbles.len() % 2 == 1 {
            out.push(((flag | 1) << 4) | nibbles[0]);
            &nibbles[1..]
        } else {
            out.push(flag << 4);
            nibbles
        };
        for p in rest.chunks(2) {
            out.push((p[0] << 4) | p[1]);
        }
        out
    }

    /// Encode the node over `entries` (keys relative to this node, none a
    /// prefix of another). When `target` lies under it, every hashed node on
    /// its path is pushed to `path`, deepest first.
    fn node(
        entries: &[(Vec<u8>, Vec<u8>)],
        target: Option<&[u8]>,
        path: &mut Vec<Vec<u8>>,
    ) -> Vec<u8> {
        if entries.len() == 1 {
            let mut s = RlpStream::new_list(2);
            s.append(&hp(&entries[0].0, true));
            s.append(&entries[0].1);
            return s.out().to_vec();
        }
        let common = (0..)
            .take_while(|&i| {
                entries
                    .iter()
                    .all(|(k, _)| k.len() > i && k[i] == entries[0].0[i])
            })
            .count();
        if common > 0 {
            let rest: Vec<_> = entries
                .iter()
                .map(|(k, v)| (k[common..].to_vec(), v.clone()))
                .collect();
            let sub = target.map(|t| &t[common..]);
            let child = node(&rest, sub, path);
            let mut s = RlpStream::new_list(2);
            s.append(&hp(&entries[0].0[..common], false));
            reference(&mut s, child, sub.is_some(), path);
            return s.out().to_vec();
        }
        let mut s = RlpStream::new_list(17);
        for n in 0..16u8 {
            let sub: Vec<_> = entries
                .iter()
                .filter(|(k, _)| k.first() == Some(&n))
                .map(|(k, v)| (k[1..].to_vec(), v.clone()))
                .collect();
            if sub.is_empty() {
                s.append_empty_data();
                continue;
            }
            let t = target.filter(|t| t.first() == Some(&n)).map(|t| &t[1..]);
            let child = node(&sub, t, path);
            reference(&mut s, child, t.is_some(), path);
        }
        s.append_empty_data();
        s.out().to_vec()
    }

    fn reference(s: &mut RlpStream, child: Vec<u8>, on_path: bool, path: &mut Vec<Vec<u8>>) {
        if child.len() >= 32 {
            s.append(&keccak(&child).to_vec());
            if on_path {
                path.push(child);
            }
        } else {
            s.append_raw(&child, 1);
        }
    }

    /// The root of a trie over `entries` (nibble keys).
    pub fn root(entries: &[(Vec<u8>, Vec<u8>)]) -> [u8; 32] {
        if entries.is_empty() {
            return EMPTY_TRIE_ROOT;
        }
        keccak(&node(entries, None, &mut Vec::new()))
    }

    /// The root of a trie over `entries` (nibble keys) and the proof of the
    /// value under `key`.
    pub fn build(entries: &[(Vec<u8>, Vec<u8>)], key: &[u8]) -> ([u8; 32], Vec<Vec<u8>>) {
        if entries.is_empty() {
            return (EMPTY_TRIE_ROOT, Vec::new());
        }
        let mut path = Vec::new();
        let root = node(entries, Some(key), &mut path);
        path.push(root.clone());
        path.reverse();
        (keccak(&root), path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_empty_trie_root_is_keccak_of_the_empty_string() {
        assert_eq!(keccak(&rlp::encode(&"")), EMPTY_TRIE_ROOT);
        assert_eq!(receipts_root(std::iter::empty()).0, EMPTY_TRIE_ROOT);
    }

    /// A trie of one entry is a single leaf whose path is all of rlp(0).
    #[test]
    fn one_receipt_is_a_leaf_under_rlp_zero() {
        let r = encode_receipt(2, true, 21_000, std::iter::empty());
        assert_eq!(r[0], 2);
        let mut leaf = RlpStream::new_list(2);
        leaf.append(&vec![0x20u8, 0x80]);
        leaf.append(&r);
        assert_eq!(receipts_root([(0, r)]).0, keccak(&leaf.out()));
    }

    #[test]
    fn index_order_does_not_change_the_root() {
        let rs: Vec<(u64, Vec<u8>)> = (0..200u64)
            .map(|i| {
                (
                    i,
                    encode_receipt((i % 3) as u8, i % 2 == 0, i * 21_000, std::iter::empty()),
                )
            })
            .collect();
        let mut rev = rs.clone();
        rev.reverse();
        assert_eq!(receipts_root(rs), receipts_root(rev));
    }
}
