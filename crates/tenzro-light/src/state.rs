//! Checking a value a node read from state against a certified checkpoint.

use tenzro_finality::checkpoint::Checkpoint;
use tenzro_state_proof::{StateProof, verify_state_proof};
use tenzro_types::hash_scheme::{HashScheme, STATE_TRIE_HASH_SCHEMES};

use crate::error::{LightError, Result};

/// What a node claims one committed entry holds, and its proof.
#[derive(Debug, Clone, Copy)]
pub struct StateClaim<'a> {
    /// Height of the state the proof is against.
    pub height: u64,
    /// Hash scheme of the state trie at that height.
    pub scheme: HashScheme,
    /// State namespace of the entry.
    pub namespace: &'a str,
    /// Key of the entry.
    pub key: &'a [u8],
    /// The value, or `None` when the entry is claimed absent.
    pub value: Option<&'a [u8]>,
    /// The proof.
    pub proof: &'a StateProof,
}

/// Checks `claim` against the state root `checkpoint` certifies: the proof
/// is for the height that root is of, and it reconstructs the root.
///
/// The scheme comes from the node with the proof and is held to the schemes
/// the trie can hash with. That table has one entry, so a reply naming any
/// other scheme is refused. A second entry takes effect at the first block
/// of a protocol version, which a checkpoint does not name: when one is
/// added, the height it starts at must reach the client from a certified
/// source, not from the node's reply.
pub fn verify_state(checkpoint: &Checkpoint, claim: &StateClaim<'_>) -> Result<()> {
    if claim.height != checkpoint.state_height {
        return Err(LightError::HeightMismatch {
            want: checkpoint.state_height,
            got: claim.height,
        });
    }
    if !STATE_TRIE_HASH_SCHEMES
        .iter()
        .any(|(_, s)| *s == claim.scheme)
    {
        return Err(LightError::UnknownScheme);
    }
    verify_state_proof(
        claim.scheme,
        &checkpoint.state_root,
        claim.namespace,
        claim.key,
        claim.value,
        claim.proof,
    )?;
    Ok(())
}
