//! Provable data possession, the provider's part: drawing a challenge and
//! answering one from the shards it holds. What a challenge, a proof and a
//! shard commitment are, and how a proof is checked, live in
//! [`tenzro_storage::pdp`], so consensus code verifies a proof without this
//! crate.

use rand::RngCore;
use tenzro_storage::pdp::ChunkTree;
pub use tenzro_storage::pdp::{
    CHUNK_SIZE, DescriptorShards, PdpChallenge, PdpError, PdpItem, PdpProof, ShardRef,
    chunk_commitment, sample_positions, verify,
};

use crate::error::Result;

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
    let mut trees: std::collections::HashMap<usize, (Vec<u8>, ChunkTree)> =
        std::collections::HashMap::new();
    for (shard, chunk) in sample_positions(challenge, shards) {
        if let std::collections::hash_map::Entry::Vacant(e) = trees.entry(shard) {
            let bytes = fetch_shard(shard)?;
            let tree = ChunkTree::of(&bytes);
            e.insert((bytes, tree));
        }
        let (bytes, tree) = &trees[&shard];
        let start = (chunk as usize) * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(bytes.len());
        items.push(PdpItem {
            shard,
            chunk,
            bytes: bytes.get(start..end).unwrap_or(&[]).to_vec(),
            path: tree.path(chunk as usize),
        });
    }
    Ok(PdpProof {
        object_id: challenge.object_id.clone(),
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::ObjectDescriptor;
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
            verify(&d.object_id, &d.shards, &c, &p).unwrap();
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
            if verify(&d.object_id, &d.shards, &c, &p).is_err() {
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
        assert!(verify(&d.object_id, &d.shards, &fresh, &replay).is_err());
    }

    #[test]
    fn forged_chunk_bytes_are_refused() {
        let data = shards();
        let d = object(&data);
        let c = new_pdp_challenge("obj", 4);
        let mut p = prove(&c, &d.shards, |i| Ok(data[i].clone())).unwrap();
        p.items[0].bytes[0] ^= 0xff;
        assert!(verify(&d.object_id, &d.shards, &c, &p).is_err());
    }
}
