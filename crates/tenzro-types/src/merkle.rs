//! The binary Merkle tree every chain commitment uses: BLAKE3 with
//! domain-separated leaves (`0x00`) and inner nodes (`0x01`), an odd node at
//! the end of a level promoted unchanged, and a fixed root for no leaves.
//!
//! Checkpoints commit block hashes with it, and block headers commit their
//! events with it, so one inclusion path format proves both.

use serde::{Deserialize, Serialize};

/// A 32-byte tree node.
pub type Node = [u8; 32];

/// Root of a tree with no leaves.
pub fn empty_root() -> Node {
    *blake3::hash(b"tenzro/consensus/merkle/empty").as_bytes()
}

fn hash_leaf(leaf: &Node) -> Node {
    let mut h = blake3::Hasher::new();
    h.update(&[0u8]);
    h.update(leaf);
    h.finalize().into()
}

fn hash_pair(left: &Node, right: &Node) -> Node {
    let mut h = blake3::Hasher::new();
    h.update(&[1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn next_level(level: &[Node]) -> Vec<Node> {
    level
        .chunks(2)
        .map(|pair| {
            if pair.len() == 2 {
                hash_pair(&pair[0], &pair[1])
            } else {
                pair[0]
            }
        })
        .collect()
}

/// Merkle root over `leaves`.
pub fn merkle_root(leaves: &[Node]) -> Node {
    if leaves.is_empty() {
        return empty_root();
    }
    let mut level: Vec<Node> = leaves.iter().map(hash_leaf).collect();
    while level.len() > 1 {
        level = next_level(&level);
    }
    level[0]
}

/// One step up an inclusion path: the sibling at that level and which side
/// it sits on. A level where the node was promoted has no step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStep {
    /// The sibling node.
    pub sibling: Node,
    /// Whether the sibling is the left child.
    pub left: bool,
}

/// The inclusion path of `leaves[index]`, or `None` when `index` is out of
/// range.
pub fn merkle_path(leaves: &[Node], index: usize) -> Option<Vec<PathStep>> {
    if index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Node> = leaves.iter().map(hash_leaf).collect();
    let mut i = index;
    let mut path = Vec::new();
    while level.len() > 1 {
        if i % 2 == 1 {
            path.push(PathStep {
                sibling: level[i - 1],
                left: true,
            });
        } else if i + 1 < level.len() {
            path.push(PathStep {
                sibling: level[i + 1],
                left: false,
            });
        }
        level = next_level(&level);
        i /= 2;
    }
    Some(path)
}

/// The root `leaf` reaches along `path`.
pub fn root_from_path(leaf: &Node, path: &[PathStep]) -> Node {
    path.iter().fold(hash_leaf(leaf), |acc, step| {
        if step.left {
            hash_pair(&step.sibling, &acc)
        } else {
            hash_pair(&acc, &step.sibling)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_leaf_proves_into_the_root() {
        for n in 1..=9usize {
            let leaves: Vec<Node> = (0..n as u8).map(|i| [i; 32]).collect();
            let root = merkle_root(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let path = merkle_path(&leaves, i).unwrap();
                assert_eq!(root_from_path(leaf, &path), root, "n={n} i={i}");
                let mut other = *leaf;
                other[0] ^= 1;
                assert_ne!(root_from_path(&other, &path), root);
            }
            assert!(merkle_path(&leaves, n).is_none());
        }
    }
}
