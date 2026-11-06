//! Hash rules of the state trie. Pure functions, shared by the trie, the
//! proof verifier and the snapshot verifier, so all three agree by
//! construction.
//!
//! Layout: every committed entry `(namespace, key)` gets a 32-byte tree key.
//! Its first 31 bytes are the stem, a path of 248 bits through a binary trie;
//! its last byte selects one of 256 value slots under that stem.
//!
//! - An empty subtree hashes to 32 zero bytes.
//! - A value slot holds `H(0x00 || value)`, or zero when unset.
//! - The 256 slots of a stem merkleize pairwise: `H(0x03 || l || r)`, except
//!   that two zero children give zero.
//! - A stem node hashes as `H(0x02 || stem || slots_root)`.
//! - An interior node hashes as `H(0x01 || left || right)`.
//! - A subtree holding exactly one stem hashes to that stem node's hash,
//!   wherever it sits: the stem is placed at the shallowest depth where it is
//!   alone, and no interior node has one empty child and one stem child.
//!
//! `H` is the hash scheme the trie holds at the version being hashed
//! ([`HashScheme`]), passed to every function here; tree keys are SHA-256
//! under every scheme, so a key's path never moves.

use sha2::{Digest, Sha256};
use tenzro_types::hash_scheme::HashScheme;

/// Length of a stem in bytes.
pub const STEM_LEN: usize = 31;
/// Number of path bits in a stem.
pub const STEM_BITS: usize = STEM_LEN * 8;

/// A 31-byte stem.
pub type Stem = [u8; STEM_LEN];

/// The hash of an empty subtree.
pub const EMPTY: [u8; 32] = [0u8; 32];

const TREE_KEY_DOMAIN: &[u8] = b"tenzro.state-trie.key";
const LEAF_TAG: u8 = 0x00;
const INTERNAL_TAG: u8 = 0x01;
const STEM_TAG: u8 = 0x02;
const SLOT_PAIR_TAG: u8 = 0x03;

/// The tree key of a committed entry.
pub fn tree_key(namespace: &str, key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TREE_KEY_DOMAIN);
    h.update((namespace.len() as u16).to_le_bytes());
    h.update(namespace.as_bytes());
    h.update(key);
    h.finalize().into()
}

/// Splits a tree key into its stem and value slot.
pub fn split_tree_key(tree_key: &[u8; 32]) -> (Stem, u8) {
    let mut stem = [0u8; STEM_LEN];
    stem.copy_from_slice(&tree_key[..STEM_LEN]);
    (stem, tree_key[STEM_LEN])
}

/// Joins a stem and a value slot back into a tree key.
pub fn join_tree_key(stem: &Stem, slot: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..STEM_LEN].copy_from_slice(stem);
    out[STEM_LEN] = slot;
    out
}

/// Bit `depth` of a stem, most significant bit first.
pub fn stem_bit(stem: &Stem, depth: usize) -> u8 {
    (stem[depth / 8] >> (7 - (depth % 8))) & 1
}

/// Whether two stems agree on their first `depth` bits.
pub fn shares_prefix(a: &Stem, b: &Stem, depth: usize) -> bool {
    (0..depth).all(|d| stem_bit(a, d) == stem_bit(b, d))
}

fn h(scheme: HashScheme, parts: &[&[u8]]) -> [u8; 32] {
    scheme.digest(&parts.concat())
}

/// The slot hash of a value.
pub fn leaf_hash(scheme: HashScheme, value: &[u8]) -> [u8; 32] {
    h(scheme, &[&[LEAF_TAG], value])
}

fn slot_pair(scheme: HashScheme, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if *left == EMPTY && *right == EMPTY {
        return EMPTY;
    }
    h(scheme, &[&[SLOT_PAIR_TAG], left, right])
}

/// Root of a stem's 256 value slots, given the occupied ones.
pub fn slots_root<'a>(
    scheme: HashScheme,
    slots: impl IntoIterator<Item = (u8, &'a [u8; 32])>,
) -> [u8; 32] {
    let mut level = vec![EMPTY; 256];
    for (i, h) in slots {
        level[i as usize] = *h;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| slot_pair(scheme, &pair[0], &pair[1]))
            .collect();
    }
    level[0]
}

/// The eight sibling hashes on the path from slot `slot` to the slots root,
/// bottom-up.
pub fn slot_siblings<'a>(
    scheme: HashScheme,
    slots: impl IntoIterator<Item = (u8, &'a [u8; 32])>,
    slot: u8,
) -> [[u8; 32]; 8] {
    let mut level = vec![EMPTY; 256];
    for (i, h) in slots {
        level[i as usize] = *h;
    }
    let mut out = [EMPTY; 8];
    let mut index = slot as usize;
    for sibling in out.iter_mut() {
        *sibling = level[index ^ 1];
        level = level
            .chunks(2)
            .map(|pair| slot_pair(scheme, &pair[0], &pair[1]))
            .collect();
        index >>= 1;
    }
    out
}

/// Recomputes a slots root from one slot's hash and its bottom-up siblings.
pub fn slots_root_from_path(
    scheme: HashScheme,
    slot: u8,
    slot_hash: [u8; 32],
    siblings: &[[u8; 32]; 8],
) -> [u8; 32] {
    let mut acc = slot_hash;
    let mut index = slot as usize;
    for sibling in siblings {
        acc = if index & 1 == 0 {
            slot_pair(scheme, &acc, sibling)
        } else {
            slot_pair(scheme, sibling, &acc)
        };
        index >>= 1;
    }
    acc
}

/// Hash of a stem node.
pub fn stem_hash(scheme: HashScheme, stem: &Stem, slots_root: &[u8; 32]) -> [u8; 32] {
    h(scheme, &[&[STEM_TAG], stem, slots_root])
}

/// Hash of an interior node.
pub fn internal_hash(scheme: HashScheme, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    h(scheme, &[&[INTERNAL_TAG], left, right])
}

/// What a subtree holds, which decides how it combines with its sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Subtree {
    /// No stems.
    Empty,
    /// Exactly one stem; the hash is that stem node's hash.
    Single([u8; 32]),
    /// Two or more stems; the hash is an interior node's hash.
    Multi([u8; 32]),
}

impl Subtree {
    /// The subtree's hash.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            Subtree::Empty => EMPTY,
            Subtree::Single(h) | Subtree::Multi(h) => *h,
        }
    }
}

/// Combines two sibling subtrees into their parent, applying the rule that a
/// single stem is carried up unchanged.
pub fn combine(scheme: HashScheme, left: Subtree, right: Subtree) -> Subtree {
    match (left, right) {
        (Subtree::Empty, Subtree::Empty) => Subtree::Empty,
        (Subtree::Single(h), Subtree::Empty) | (Subtree::Empty, Subtree::Single(h)) => {
            Subtree::Single(h)
        }
        (l, r) => Subtree::Multi(internal_hash(scheme, &l.hash(), &r.hash())),
    }
}

/// Builds the subtree rooted at `depth` from its stems, each with its slots
/// root. `stems` must be sorted, distinct, and share their first `depth` bits.
pub fn build_subtree(scheme: HashScheme, depth: usize, stems: &[(Stem, [u8; 32])]) -> Subtree {
    match stems {
        [] => Subtree::Empty,
        [(stem, slots)] => Subtree::Single(stem_hash(scheme, stem, slots)),
        _ => {
            // Sorted stems put every 0-bit before every 1-bit at this depth.
            let split = stems.partition_point(|(s, _)| stem_bit(s, depth) == 0);
            combine(
                scheme,
                build_subtree(scheme, depth + 1, &stems[..split]),
                build_subtree(scheme, depth + 1, &stems[split..]),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_path_recomputes_the_slots_root() {
        for s in [HashScheme::Sha256, HashScheme::Sha3_256] {
            let a = leaf_hash(s, b"a");
            let b = leaf_hash(s, b"b");
            let slots = [(3u8, &a), (200u8, &b)];
            let root = slots_root(s, slots);
            for (slot, h) in [(3u8, a), (200u8, b)] {
                let sib = slot_siblings(s, slots, slot);
                assert_eq!(slots_root_from_path(s, slot, h, &sib), root);
            }
            // An unset slot proves absence the same way.
            let sib = slot_siblings(s, slots, 7);
            assert_eq!(slots_root_from_path(s, 7, EMPTY, &sib), root);
        }
    }

    /// Two threads hashing under two schemes at once each get their own
    /// scheme's hashes: the scheme is a parameter, not ambient state.
    #[test]
    fn concurrent_hashing_under_two_schemes_does_not_mix() {
        let expect = |s: HashScheme| {
            let stems = [
                ([1u8; STEM_LEN], [2u8; 32]),
                ([0x80u8; STEM_LEN], [3u8; 32]),
            ];
            build_subtree(s, 0, &stems).hash()
        };
        let (a, b) = (expect(HashScheme::Sha256), expect(HashScheme::Sha3_256));
        assert_ne!(a, b);
        std::thread::scope(|t| {
            for _ in 0..4 {
                t.spawn(|| {
                    for _ in 0..200 {
                        assert_eq!(expect(HashScheme::Sha256), a);
                    }
                });
                t.spawn(|| {
                    for _ in 0..200 {
                        assert_eq!(expect(HashScheme::Sha3_256), b);
                    }
                });
            }
        });
    }

    #[test]
    fn a_single_stem_passes_through_any_depth() {
        let h = HashScheme::Sha256;
        let s = [0xAAu8; STEM_LEN];
        let slots = slots_root(h, [(0u8, &leaf_hash(h, b"x"))]);
        assert_eq!(
            build_subtree(h, 0, &[(s, slots)]),
            build_subtree(h, 17, &[(s, slots)])
        );
        assert_eq!(
            combine(h, Subtree::Single(stem_hash(h, &s, &slots)), Subtree::Empty),
            Subtree::Single(stem_hash(h, &s, &slots))
        );
    }
}
