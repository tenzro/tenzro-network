//! The Merkle tree over a batch of messages, and the proof that one message
//! is in it. The batch root is what the identity key signs in hardware (see
//! [`crate::batch_signer`]).

use sha2::{Digest, Sha256};

use crate::delegation::{DelegationError, DelegationResult, Reader};

const BATCH_PROOF_VERSION: u8 = 1;
const MAX_PATH: usize = 40;

/// Domain of a batch leaf.
pub const BATCH_LEAF_DOMAIN: &[u8] = b"tenzro/session-batch/leaf/v1";

fn leaf_hash(message: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(BATCH_LEAF_DOMAIN);
    h.update((message.len() as u64).to_be_bytes());
    h.update(message);
    h.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two below `n` (`n >= 2`).
fn split(n: u64) -> u64 {
    1u64 << (63 - (n - 1).leading_zeros())
}

fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.len() == 1 {
        return leaves[0];
    }
    let k = split(leaves.len() as u64) as usize;
    node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
}

fn path_of(leaves: &[[u8; 32]], index: usize, out: &mut Vec<[u8; 32]>) {
    if leaves.len() == 1 {
        return;
    }
    let k = split(leaves.len() as u64) as usize;
    if index < k {
        path_of(&leaves[..k], index, out);
        out.push(root_of(&leaves[k..]));
    } else {
        path_of(&leaves[k..], index - k, out);
        out.push(root_of(&leaves[..k]));
    }
}

fn fold(index: u64, count: u64, leaf: [u8; 32], path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if count == 1 {
        return path.is_empty().then_some(leaf);
    }
    let k = split(count);
    let (top, rest) = path.split_last()?;
    if index < k {
        Some(node_hash(&fold(index, k, leaf, rest)?, top))
    } else {
        Some(node_hash(top, &fold(index - k, count - k, leaf, rest)?))
    }
}

/// The root and a proof for each of `messages`, in order. No signature.
pub fn batch_members(messages: &[&[u8]]) -> ([u8; 32], Vec<BatchProof>) {
    let leaves: Vec<[u8; 32]> = messages.iter().map(|m| leaf_hash(m)).collect();
    let root = root_of(&leaves);
    let count = leaves.len() as u32;
    let proofs = (0..leaves.len())
        .map(|i| {
            let mut path = Vec::new();
            path_of(&leaves, i, &mut path);
            BatchProof {
                index: i as u32,
                count,
                path,
            }
        })
        .collect();
    (root, proofs)
}

/// Proof that one message is in a signed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchProof {
    pub index: u32,
    pub count: u32,
    pub path: Vec<[u8; 32]>,
}

impl BatchProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![BATCH_PROOF_VERSION];
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.push(self.path.len() as u8);
        for h in &self.path {
            out.extend_from_slice(h);
        }
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> DelegationResult<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != BATCH_PROOF_VERSION {
            return Err(DelegationError::Malformed("unknown batch proof version"));
        }
        let index = u32::from_be_bytes(r.arr::<4>()?);
        let count = u32::from_be_bytes(r.arr::<4>()?);
        let n = r.u8()? as usize;
        if n > MAX_PATH {
            return Err(DelegationError::Malformed("batch path too long"));
        }
        let mut path = Vec::with_capacity(n);
        for _ in 0..n {
            path.push(r.arr::<32>()?);
        }
        r.done()?;
        Ok(Self { index, count, path })
    }

    /// The batch root this proof leads to for `message`, or `None` when the
    /// proof does not fit its own index and count.
    pub fn root_for(&self, message: &[u8]) -> Option<[u8; 32]> {
        if self.count == 0 || self.index >= self.count {
            return None;
        }
        fold(
            u64::from(self.index),
            u64::from(self.count),
            leaf_hash(message),
            &self.path,
        )
    }
}
