//! Provable data possession, the pure part: what a provider commits to when
//! it stores an object, what a challenge asks, what a proof answers and how a
//! proof is checked. A verifier needs nothing else, so consensus code checks
//! a proof with this module alone; making a proof, which reads the shards, is
//! the storage provider's.
//!
//! Each shard is cut into [`CHUNK_SIZE`]-byte chunks and committed as a
//! Merkle root when the object is stored ([`chunk_commitment`], recorded on
//! the object's [`ShardRef`]). A challenge is a nonce; the nonce alone
//! determines which `(shard, chunk)` positions must be proven
//! ([`sample_positions`]), so neither side chooses them and the provider
//! cannot know them in advance. The answer is, per position, the chunk bytes
//! and their Merkle path — a few kilobytes whatever the object size. The
//! verifier checks each path against the committed root and never downloads a
//! shard.
//!
//! A provider that has kept only a fraction `f` of a shard's chunks survives
//! `s` samples on that shard with probability about `f^s`, so a handful of
//! samples per epoch makes discarding data a losing bet.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Chunk size the per-shard Merkle tree is built over.
pub const CHUNK_SIZE: usize = 1024;

type Hash = [u8; 32];

/// A reference to one stored shard: where to fetch it and how to verify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRef {
    /// Index in `0..n` among the object's shards.
    pub index: usize,
    /// Content-addressed URI the shard bytes were published under.
    pub uri: String,
    /// Hex SHA-256 commitment of the shard bytes.
    pub commitment: String,
    /// Hex Merkle root over the shard's [`CHUNK_SIZE`] chunks; possession
    /// challenges are checked against it.
    pub chunk_root: String,
    /// Number of chunks under `chunk_root`.
    pub chunk_count: u64,
}

/// The leading fields of a stored object's descriptor: the shards a storage
/// claim commits to. A claim carries the whole descriptor's bincode bytes, but
/// bincode cannot read the whole descriptor back, since its access policy is
/// an internally tagged enum and its seal is left out when absent; these
/// fields come first and read back.
#[derive(Debug, Clone, Deserialize)]
pub struct DescriptorShards {
    /// Application-level object identifier (caller-assigned, unique per owner).
    pub object_id: String,
    /// Owner address bytes (hex) — the renter who pays for this object.
    pub owner_hex: String,
    /// True original byte length, used to strip erasure padding on rebuild.
    pub size_bytes: u64,
    /// Data shards of the redundancy scheme the shards were encoded under.
    pub data_shards: usize,
    /// Parity shards of that scheme.
    pub parity_shards: usize,
    /// One entry per shard, in shard-index order (`0..n`).
    pub shards: Vec<ShardRef>,
}

/// A possession challenge for one object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PdpChallenge {
    /// Object challenged.
    pub object_id: String,
    /// Nonce that selects the positions to prove.
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

/// Why a proof does not answer its challenge.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("possession challenge failed for {object_id}: {reason}")]
pub struct PdpError {
    /// Object challenged.
    pub object_id: String,
    /// What did not match.
    pub reason: String,
}

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

/// The Merkle tree over one shard's chunks, levels bottom-up; an odd node is
/// paired with itself.
pub struct ChunkTree(Vec<Vec<Hash>>);

impl ChunkTree {
    /// The tree over `shard`'s chunks.
    pub fn of(shard: &[u8]) -> Self {
        let leaves = if shard.is_empty() {
            vec![leaf(0, &[])]
        } else {
            shard
                .chunks(CHUNK_SIZE)
                .enumerate()
                .map(|(i, c)| leaf(i as u64, c))
                .collect()
        };
        let mut levels = vec![leaves];
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let prev = levels.last().expect("non-empty");
            let next = prev
                .chunks(2)
                .map(|p| node(&p[0], p.get(1).unwrap_or(&p[0])))
                .collect();
            levels.push(next);
        }
        Self(levels)
    }

    /// The Merkle path from chunk `index` to the root.
    pub fn path(&self, mut index: usize) -> Vec<Hash> {
        let mut out = Vec::new();
        for level in &self.0[..self.0.len() - 1] {
            let sibling = index ^ 1;
            out.push(*level.get(sibling).unwrap_or(&level[index]));
            index >>= 1;
        }
        out
    }
}

/// The Merkle root over a shard's chunks and the chunk count, as recorded on
/// its [`ShardRef`].
pub fn chunk_commitment(shard: &[u8]) -> (String, u64) {
    let tree = ChunkTree::of(shard);
    let count = tree.0[0].len() as u64;
    (hex::encode(tree.0.last().expect("root")[0]), count)
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

/// Check a proof against the committed chunk roots of `shards`, the shards
/// of the object `object_id`. Needs only those and the proof.
pub fn verify(
    object_id: &str,
    shards: &[ShardRef],
    challenge: &PdpChallenge,
    proof: &PdpProof,
) -> Result<(), PdpError> {
    let id = &challenge.object_id;
    let fail = |reason: String| PdpError {
        object_id: id.clone(),
        reason,
    };
    if proof.object_id != *id || object_id != id {
        return Err(fail("proof is for another object".into()));
    }
    let positions = sample_positions(challenge, shards);
    if proof.items.len() != positions.len() {
        return Err(fail(format!(
            "expected {} items, got {}",
            positions.len(),
            proof.items.len()
        )));
    }
    for (item, (shard, chunk)) in proof.items.iter().zip(positions) {
        if item.shard != shard || item.chunk != chunk {
            return Err(fail("proof answers positions that were not asked".into()));
        }
        if item.bytes.len() > CHUNK_SIZE {
            return Err(fail("chunk longer than the chunk size".into()));
        }
        let sref = shards
            .iter()
            .find(|s| s.index == shard)
            .ok_or_else(|| fail(format!("no shard {shard}")))?;
        let root = root_from(leaf(chunk, &item.bytes), chunk, &item.path);
        if hex::encode(root) != sref.chunk_root {
            return Err(fail(format!(
                "shard {shard} chunk {chunk} does not match its commitment"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A shard set and an honest proof for `challenge`, made with this module alone.
    fn answer(challenge: &PdpChallenge, data: &[Vec<u8>]) -> (Vec<ShardRef>, PdpProof) {
        let shards: Vec<ShardRef> = data
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let (chunk_root, chunk_count) = chunk_commitment(bytes);
                ShardRef {
                    index,
                    uri: String::new(),
                    commitment: String::new(),
                    chunk_root,
                    chunk_count,
                }
            })
            .collect();
        let items = sample_positions(challenge, &shards)
            .into_iter()
            .map(|(shard, chunk)| {
                let start = chunk as usize * CHUNK_SIZE;
                let bytes = &data[shard];
                PdpItem {
                    shard,
                    chunk,
                    bytes: bytes[start..(start + CHUNK_SIZE).min(bytes.len())].to_vec(),
                    path: ChunkTree::of(bytes).path(chunk as usize),
                }
            })
            .collect();
        let proof = PdpProof {
            object_id: challenge.object_id.clone(),
            items,
        };
        (shards, proof)
    }

    #[test]
    fn a_proof_is_checked_with_this_module_alone() {
        let data: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 3 * CHUNK_SIZE + 17]).collect();
        let challenge = PdpChallenge {
            object_id: "obj".into(),
            nonce: [7; 32],
            samples: 8,
        };
        let (shards, proof) = answer(&challenge, &data);
        verify("obj", &shards, &challenge, &proof).unwrap();
        let mut forged = proof.clone();
        forged.items[0].bytes[0] ^= 0xff;
        assert!(verify("obj", &shards, &challenge, &forged).is_err());
        let other = PdpChallenge {
            nonce: [8; 32],
            ..challenge.clone()
        };
        assert!(verify("obj", &shards, &other, &proof).is_err());
        assert!(verify("another", &shards, &challenge, &proof).is_err());
    }

    #[test]
    fn the_descriptor_prefix_reads_back_from_the_layout_a_claim_commits() {
        #[derive(Serialize)]
        struct Scheme {
            data_shards: usize,
            parity_shards: usize,
        }
        #[derive(Serialize)]
        struct Committed {
            object_id: String,
            owner_hex: String,
            size_bytes: u64,
            scheme: Scheme,
            shards: Vec<ShardRef>,
            trailing: String,
        }
        let (shards, _) = answer(
            &PdpChallenge {
                object_id: "obj".into(),
                nonce: [1; 32],
                samples: 1,
            },
            &[vec![1; 10]],
        );
        let bytes = bincode::serialize(&Committed {
            object_id: "obj".into(),
            owner_hex: "ab".into(),
            size_bytes: 10,
            scheme: Scheme {
                data_shards: 2,
                parity_shards: 1,
            },
            shards,
            trailing: "the rest of the descriptor".into(),
        })
        .unwrap();
        let read: DescriptorShards = bincode::deserialize(&bytes).unwrap();
        assert_eq!((read.data_shards, read.parity_shards), (2, 1));
        assert_eq!(read.shards.len(), 1);
        assert_eq!(read.object_id, "obj");
    }
}
