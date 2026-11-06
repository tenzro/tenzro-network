//! Provable data possession: succinct challenges that a provider still holds
//! the shards it is paid to store.
//!
//! Each shard is cut into [`CHUNK_SIZE`]-byte chunks and committed as a
//! Merkle root when the object is stored ([`chunk_commitment`], recorded on
//! the object's [`ShardRef`]). A challenge is a fresh random nonce; the nonce
//! alone determines which `(shard, chunk)` positions must be proven
//! ([`sample_positions`]), so neither side chooses them and the provider
//! cannot know them in advance. The answer is, per position, the chunk bytes
//! and their Merkle path — a few kilobytes whatever the object size. The
//! verifier checks each path against the committed root and never downloads a
//! shard.
//!
//! A provider that has kept only a fraction `f` of a shard's chunks survives
//! `s` samples on that shard with probability about `f^s`, so a handful of
//! samples per epoch makes discarding data a losing bet.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, StorageProviderError};
use crate::provider::{ObjectDescriptor, ShardRef};

/// Chunk size the per-shard Merkle tree is built over.
pub const CHUNK_SIZE: usize = 1024;

type Hash = [u8; 32];

fn leaf(index: u64, chunk: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(index.to_be_bytes());
    h.update(chunk);
    h.finalize().into()
}

fn node(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn chunk_leaves(shard: &[u8]) -> Vec<Hash> {
    if shard.is_empty() {
        return vec![leaf(0, &[])];
    }
    shard
        .chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(i, c)| leaf(i as u64, c))
        .collect()
}

/// Levels of the tree bottom-up; an odd node is paired with itself.
fn levels(leaves: Vec<Hash>) -> Vec<Vec<Hash>> {
    let mut out = vec![leaves];
    while out.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let prev = out.last().expect("non-empty");
        let next = prev
            .chunks(2)
            .map(|p| node(&p[0], p.get(1).unwrap_or(&p[0])))
            .collect();
        out.push(next);
    }
    out
}

/// The Merkle root over a shard's chunks and the chunk count, as recorded on
/// its [`ShardRef`].
pub fn chunk_commitment(shard: &[u8]) -> (String, u64) {
    let leaves = chunk_leaves(shard);
    let count = leaves.len() as u64;
    let tree = levels(leaves);
    let root = tree.last().expect("root")[0];
    (hex::encode(root), count)
}

fn path(tree: &[Vec<Hash>], mut index: usize) -> Vec<Hash> {
    let mut out = Vec::new();
    for level in &tree[..tree.len() - 1] {
        let sibling = index ^ 1;
        out.push(*level.get(sibling).unwrap_or(&level[index]));
        index >>= 1;
    }
    out
}

fn root_from(mut h: Hash, mut index: u64, path: &[Hash]) -> Hash {
    for s in path {
        h = if index & 1 == 0 {
            node(&h, s)
        } else {
            node(s, &h)
        };
        index >>= 1;
    }
    h
}

/// A possession challenge for one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdpChallenge {
    /// Object challenged.
    pub object_id: String,
    /// Fresh random nonce; selects the positions to prove.
    pub nonce: [u8; 32],
    /// How many positions to prove.
    pub samples: usize,
}

/// One proven chunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdpItem {
    /// Shard index.
    pub shard: usize,
    /// Chunk index within the shard.
    pub chunk: u64,
    /// The chunk bytes.
    pub bytes: Vec<u8>,
    /// Merkle path from the chunk to the shard's committed root.
    pub path: Vec<[u8; 32]>,
}

/// The provider's answer to a [`PdpChallenge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdpProof {
    /// Object the proof is for.
    pub object_id: String,
    /// One item per sampled position, in sample order.
    pub items: Vec<PdpItem>,
}

/// Draw a fresh challenge with `samples` positions.
pub fn new_pdp_challenge(object_id: &str, samples: usize) -> PdpChallenge {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    PdpChallenge {
        object_id: object_id.to_string(),
        nonce,
        samples: samples.max(1),
    }
}

/// The `(shard, chunk)` positions a challenge requires, derived from its nonce
/// and the object's committed shard layout. Deterministic, so prover and
/// verifier agree without exchanging the list.
pub fn sample_positions(challenge: &PdpChallenge, shards: &[ShardRef]) -> Vec<(usize, u64)> {
    if shards.is_empty() {
        return Vec::new();
    }
    (0..challenge.samples as u64)
        .map(|i| {
            let mut h = Sha256::new();
            h.update(b"tenzro/pdp-sample");
            h.update(challenge.nonce);
            h.update(i.to_be_bytes());
            let d: Hash = h.finalize().into();
            let a = u64::from_be_bytes(d[..8].try_into().expect("8 bytes"));
            let b = u64::from_be_bytes(d[8..16].try_into().expect("8 bytes"));
            let shard = &shards[(a % shards.len() as u64) as usize];
            (shard.index, b % shard.chunk_count.max(1))
        })
        .collect()
}

/// Answer a challenge from the shards the provider holds. `fetch_shard`
/// returns a shard's bytes by index; a provider that no longer has one cannot
/// answer for it.
pub fn prove<F>(
    challenge: &PdpChallenge,
    shards: &[ShardRef],
    mut fetch_shard: F,
) -> Result<PdpProof>
where
    F: FnMut(usize) -> Result<Vec<u8>>,
{
    let mut items = Vec::new();
    let mut trees: std::collections::HashMap<usize, (Vec<u8>, Vec<Vec<Hash>>)> =
        std::collections::HashMap::new();
    for (shard, chunk) in sample_positions(challenge, shards) {
        if let std::collections::hash_map::Entry::Vacant(e) = trees.entry(shard) {
            let bytes = fetch_shard(shard)?;
            let tree = levels(chunk_leaves(&bytes));
            e.insert((bytes, tree));
        }
        let (bytes, tree) = &trees[&shard];
        let start = (chunk as usize) * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(bytes.len());
        items.push(PdpItem {
            shard,
            chunk,
            bytes: bytes.get(start..end).unwrap_or(&[]).to_vec(),
            path: path(tree, chunk as usize),
        });
    }
    Ok(PdpProof {
        object_id: challenge.object_id.clone(),
        items,
    })
}

fn fail(object_id: &str, reason: String) -> StorageProviderError {
    StorageProviderError::ChallengeFailed {
        object_id: object_id.to_string(),
        reason,
    }
}

/// Check a proof against the object's committed chunk roots. Needs only the
/// descriptor and the proof.
pub fn verify(
    descriptor: &ObjectDescriptor,
    challenge: &PdpChallenge,
    proof: &PdpProof,
) -> Result<()> {
    let id = &challenge.object_id;
    if proof.object_id != *id || descriptor.object_id != *id {
        return Err(fail(id, "proof is for another object".into()));
    }
    let positions = sample_positions(challenge, &descriptor.shards);
    if proof.items.len() != positions.len() {
        return Err(fail(
            id,
            format!(
                "expected {} items, got {}",
                positions.len(),
                proof.items.len()
            ),
        ));
    }
    for (item, (shard, chunk)) in proof.items.iter().zip(positions) {
        if item.shard != shard || item.chunk != chunk {
            return Err(fail(
                id,
                "proof answers positions that were not asked".into(),
            ));
        }
        if item.bytes.len() > CHUNK_SIZE {
            return Err(fail(id, "chunk longer than the chunk size".into()));
        }
        let sref = descriptor
            .shards
            .iter()
            .find(|s| s.index == shard)
            .ok_or_else(|| fail(id, format!("no shard {shard}")))?;
        let root = root_from(leaf(chunk, &item.bytes), chunk, &item.path);
        if hex::encode(root) != sref.chunk_root {
            return Err(fail(
                id,
                format!("shard {shard} chunk {chunk} does not match its commitment"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redundancy::RedundancyScheme;
    use tenzro_types::access_policy::AccessPolicy;

    fn object(shards: &[Vec<u8>]) -> ObjectDescriptor {
        ObjectDescriptor {
            object_id: "obj".into(),
            owner_hex: "00".into(),
            size_bytes: shards.iter().map(|s| s.len() as u64).sum(),
            scheme: RedundancyScheme::erasure(2, 2).unwrap(),
            shards: shards
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    let (chunk_root, chunk_count) = chunk_commitment(s);
                    ShardRef {
                        index: i,
                        uri: format!("tenzro://blob/{i}"),
                        commitment: String::new(),
                        chunk_root,
                        chunk_count,
                    }
                })
                .collect(),
            access_policy: AccessPolicy::OwnerOnly {
                owner_did: "did:tenzro:human:owner".into(),
            },
            confidential: None,
        }
    }

    fn shards() -> Vec<Vec<u8>> {
        (0..4u8)
            .map(|i| {
                (0..5000u32)
                    .map(|b| (b as u8).wrapping_mul(31).wrapping_add(i))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn an_honest_provider_passes_and_the_proof_is_small() {
        let data = shards();
        let d = object(&data);
        for _ in 0..20 {
            let c = new_pdp_challenge("obj", 8);
            let p = prove(&c, &d.shards, |i| Ok(data[i].clone())).unwrap();
            verify(&d, &c, &p).unwrap();
            let size: usize = p
                .items
                .iter()
                .map(|i| i.bytes.len() + 32 * i.path.len())
                .sum();
            assert!(
                size < 8 * (CHUNK_SIZE + 32 * 8),
                "proof is bounded by samples, not data"
            );
        }
    }

    #[test]
    fn a_provider_missing_data_fails() {
        let data = shards();
        let d = object(&data);
        // The provider kept shard 2 only partly: the tail was zeroed.
        let mut damaged = data.clone();
        for b in damaged[2][1024..].iter_mut() {
            *b = 0;
        }
        let mut failures = 0;
        for _ in 0..40 {
            let c = new_pdp_challenge("obj", 8);
            let p = prove(&c, &d.shards, |i| Ok(damaged[i].clone())).unwrap();
            if verify(&d, &c, &p).is_err() {
                failures += 1;
            }
        }
        assert!(
            failures > 30,
            "lost data must be caught almost every epoch ({failures}/40)"
        );
    }

    #[test]
    fn a_proof_for_a_different_nonce_is_refused() {
        let data = shards();
        let d = object(&data);
        let old = new_pdp_challenge("obj", 8);
        let replay = prove(&old, &d.shards, |i| Ok(data[i].clone())).unwrap();
        let fresh = new_pdp_challenge("obj", 8);
        assert!(verify(&d, &fresh, &replay).is_err());
    }

    #[test]
    fn forged_chunk_bytes_are_refused() {
        let data = shards();
        let d = object(&data);
        let c = new_pdp_challenge("obj", 4);
        let mut p = prove(&c, &d.shards, |i| Ok(data[i].clone())).unwrap();
        p.items[0].bytes[0] ^= 0xff;
        assert!(verify(&d, &c, &p).is_err());
    }
}
