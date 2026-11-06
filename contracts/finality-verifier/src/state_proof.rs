// SPDX-License-Identifier: Apache-2.0
//! Tenzro state proofs, checked under a state root: the rules of Tenzro's
//! state trie (SHA-256 throughout). An entry `(namespace, key)` has a 32-byte
//! tree key whose first 31 bytes are its stem (a path of 248 bits) and whose
//! last byte selects one of 256 value slots; a proof is the sibling hashes
//! down that path and where the path ends.
//!
//! Proofs travel in a fixed binary form: the path length (u16, big-endian),
//! the sibling hashes, then the terminal: 0 for an empty subtree, 1 and the
//! other stem (31 bytes) and its slots root, or 2 and the eight slot
//! siblings.

use sha2::{Digest, Sha256};

const STEM_LEN: usize = 31;
const STEM_BITS: usize = STEM_LEN * 8;
const EMPTY: [u8; 32] = [0u8; 32];
const TREE_KEY_DOMAIN: &[u8] = b"tenzro.state-trie.key";

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The tree key of `(namespace, key)`.
pub fn tree_key(namespace: &str, key: &[u8]) -> [u8; 32] {
    sha(&[TREE_KEY_DOMAIN, &(namespace.len() as u16).to_le_bytes(), namespace.as_bytes(), key])
}

/// The tree key of VM system storage slot `prefix || id_hex`, where
/// `id_hex` is the lowercase hex of `id`: the committed key is
/// `storage:<system account hex>:<hex of the slot>`.
pub fn system_slot_tree_key(prefix: &[u8], id: &[u8; 32]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut id_hex = [0u8; 64];
    for (i, byte) in id.iter().enumerate() {
        id_hex[2 * i] = HEX[(byte >> 4) as usize];
        id_hex[2 * i + 1] = HEX[(byte & 15) as usize];
    }
    let mut h = Sha256::new();
    h.update(TREE_KEY_DOMAIN);
    h.update(5u16.to_le_bytes());
    h.update(b"state");
    h.update(b"storage:");
    h.update([b'f'; 40]);
    h.update(b":");
    for part in [prefix, id_hex.as_slice()] {
        for byte in part {
            h.update([HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
        }
    }
    h.finalize().into()
}

fn slot_pair(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    if *l == EMPTY && *r == EMPTY {
        return EMPTY;
    }
    sha(&[&[0x03], l, r])
}

fn bit(stem: &[u8], depth: usize) -> u8 {
    (stem[depth / 8] >> (7 - (depth % 8))) & 1
}

fn word(b: &[u8], at: usize) -> Option<[u8; 32]> {
    b.get(at..at + 32)?.try_into().ok()
}

/// Whether, under `root`, the entry with tree key `tk` holds `value`
/// (`Some`) or is absent (`None`), by the encoded proof `proof`.
pub fn verify_at(root: &[u8; 32], tk: &[u8; 32], value: Option<&[u8]>, proof: &[u8]) -> bool {
    let Some(len) = proof.get(..2) else { return false };
    let depth = u16::from_be_bytes([len[0], len[1]]) as usize;
    if depth > STEM_BITS {
        return false;
    }
    let terminal_at = 2 + 32 * depth;
    let Some(&tag) = proof.get(terminal_at) else { return false };
    let body = &proof[terminal_at + 1..];
    let stem = &tk[..STEM_LEN];
    let slot = tk[STEM_LEN];
    let mut acc = match tag {
        0 if body.is_empty() => {
            if value.is_some() {
                return false;
            }
            EMPTY
        }
        1 if body.len() == STEM_LEN + 32 => {
            let other = &body[..STEM_LEN];
            if value.is_some() || other == stem || !(0..depth).all(|d| bit(other, d) == bit(stem, d)) {
                return false;
            }
            sha(&[&[0x02], other, &body[STEM_LEN..]])
        }
        2 if body.len() == 32 * 8 => {
            let mut s = value.map(|v| sha(&[&[0x00], v])).unwrap_or(EMPTY);
            let mut index = slot as usize;
            for i in 0..8 {
                let sib = word(body, 32 * i).expect("length checked");
                s = if index & 1 == 0 { slot_pair(&s, &sib) } else { slot_pair(&sib, &s) };
                index >>= 1;
            }
            if s == EMPTY {
                return false;
            }
            sha(&[&[0x02], stem, &s])
        }
        _ => return false,
    };
    for d in (0..depth).rev() {
        let sib = word(proof, 2 + 32 * d).expect("length checked");
        acc = if bit(stem, d) == 0 { sha(&[&[0x01], &acc, &sib]) } else { sha(&[&[0x01], &sib, &acc]) };
    }
    &acc == root
}

/// [`verify_at`] for the entry `(namespace, key)`.
pub fn verify(root: &[u8; 32], namespace: &str, key: &[u8], value: Option<&[u8]>, proof: &[u8]) -> bool {
    verify_at(root, &tree_key(namespace, key), value, proof)
}
