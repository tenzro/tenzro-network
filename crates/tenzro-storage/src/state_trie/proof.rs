//! State proofs and their verifier.
//!
//! A proof shows that, under a given state root, a committed entry
//! `(namespace, key)` holds a given value, or holds nothing. The verifier is a
//! pure function over the root, the entry and the proof, with no storage, so a
//! light client that trusts a root (from a verified block header) can check an
//! agent bond, a delegation record or a balance without trusting whoever served
//! the proof.

use super::hashing::{
    EMPTY, STEM_BITS, Stem, internal_hash, leaf_hash, shares_prefix, slots_root_from_path,
    split_tree_key, stem_bit, stem_hash, tree_key,
};
use serde::{Deserialize, Serialize};
use tenzro_types::hash_scheme::HashScheme;

/// Where a proof's path through the trie ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofTerminal {
    /// The path ends in an empty subtree: the entry is absent.
    Empty,
    /// The path ends at a different stem: the entry is absent.
    OtherStem {
        /// The stem found where the entry's stem would be.
        stem: Stem,
        /// That stem's slots root.
        slots_root: [u8; 32],
    },
    /// The path ends at the entry's own stem. The slot holds the value's hash
    /// when the entry is present and zero when it is absent.
    Stem {
        /// Sibling hashes from the entry's slot up to the slots root.
        slot_siblings: [[u8; 32]; 8],
    },
}

/// A proof for one committed entry under one state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateProof {
    /// Sibling hashes on the path from the root down, one per interior node.
    pub siblings: Vec<[u8; 32]>,
    /// Where the path ends.
    pub terminal: ProofTerminal,
}

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// The path is longer than a stem has bits.
    #[error("proof path of {0} levels is longer than a stem")]
    TooDeep(usize),
    /// The proof says the entry is absent but a value was claimed, or the
    /// reverse.
    #[error("proof shape does not match the claimed presence of a value")]
    PresenceMismatch,
    /// The stem found at the end of the path could not sit there.
    #[error("the stem at the end of the path is not on the entry's path")]
    StemOffPath,
    /// The proof reconstructs a different root.
    #[error("proof reconstructs root {computed}, expected {expected}")]
    RootMismatch {
        /// Root the proof reconstructs, hex.
        computed: String,
        /// Root the caller trusts, hex.
        expected: String,
    },
}

impl StateProof {
    /// The fixed binary form other chains decode: the path length (u16,
    /// big-endian), the sibling hashes, then the terminal: 0 for an empty
    /// subtree, 1 and the other stem and its slots root, or 2 and the eight
    /// slot siblings.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 32 * self.siblings.len() + 1 + 32 * 8);
        out.extend_from_slice(&(self.siblings.len() as u16).to_be_bytes());
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        match &self.terminal {
            ProofTerminal::Empty => out.push(0),
            ProofTerminal::OtherStem { stem, slots_root } => {
                out.push(1);
                out.extend_from_slice(stem);
                out.extend_from_slice(slots_root);
            }
            ProofTerminal::Stem { slot_siblings } => {
                out.push(2);
                for s in slot_siblings {
                    out.extend_from_slice(s);
                }
            }
        }
        out
    }
}

/// Verifies that under `root`, committed under the node hash `scheme`, the
/// entry `(namespace, key)` holds `value` (`Some`) or is absent (`None`).
pub fn verify_state_proof(
    scheme: HashScheme,
    root: &[u8; 32],
    namespace: &str,
    key: &[u8],
    value: Option<&[u8]>,
    proof: &StateProof,
) -> Result<(), ProofError> {
    let depth = proof.siblings.len();
    if depth > STEM_BITS {
        return Err(ProofError::TooDeep(depth));
    }
    let (stem, slot) = split_tree_key(&tree_key(namespace, key));

    let mut acc = match &proof.terminal {
        ProofTerminal::Empty => {
            if value.is_some() {
                return Err(ProofError::PresenceMismatch);
            }
            EMPTY
        }
        ProofTerminal::OtherStem {
            stem: other,
            slots_root,
        } => {
            if value.is_some() {
                return Err(ProofError::PresenceMismatch);
            }
            if *other == stem || !shares_prefix(other, &stem, depth) {
                return Err(ProofError::StemOffPath);
            }
            stem_hash(scheme, other, slots_root)
        }
        ProofTerminal::Stem { slot_siblings } => {
            let slot_hash = value.map(|v| leaf_hash(scheme, v)).unwrap_or(EMPTY);
            let slots = slots_root_from_path(scheme, slot, slot_hash, slot_siblings);
            if slots == EMPTY {
                // A stem node always holds at least one value.
                return Err(ProofError::PresenceMismatch);
            }
            stem_hash(scheme, &stem, &slots)
        }
    };

    for d in (0..depth).rev() {
        let sibling = &proof.siblings[d];
        acc = if stem_bit(&stem, d) == 0 {
            internal_hash(scheme, &acc, sibling)
        } else {
            internal_hash(scheme, sibling, &acc)
        };
    }

    if &acc != root {
        return Err(ProofError::RootMismatch {
            computed: hex::encode(acc),
            expected: hex::encode(root),
        });
    }
    Ok(())
}
