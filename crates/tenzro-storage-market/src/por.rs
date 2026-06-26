//! Proof of retrievability (D2): spot-check challenges that a provider still
//! holds the shards it was paid to store.
//!
//! # Why challenges, not just commitments
//!
//! The per-shard SHA-256 commitment in an [`ObjectDescriptor`] proves *what*
//! the bytes should be, but a provider could discard them and still know the
//! commitment. A retrievability challenge proves the provider can *produce* the
//! bytes *now*: the verifier draws a fresh random nonce, names a random subset
//! of shard indices, and demands `SHA-256(nonce || shard_bytes)` for each. The
//! nonce makes precomputation useless — the only way to answer is to hash the
//! actual bytes the provider is holding at challenge time.
//!
//! # Verification
//!
//! Two trust models are supported:
//!
//! - **Independent recompute (trustless).** The verifier fetches the challenged
//!   shards over the transport itself, recomputes the expected response, and
//!   compares. Used when the verifier has transport access — it proves the
//!   bytes are genuinely retrievable from the network, not just that the
//!   provider replied.
//! - **Commitment witness.** When the verifier cannot fetch but holds the
//!   descriptor's commitments, it can still reject any response that is
//!   structurally impossible. This is weaker (it cannot by itself prove
//!   possession) and is only a pre-filter before escalating to a transport
//!   fetch.
//!
//! A failed challenge is the signal the settlement/consensus layer uses to slot
//! a storage provider for a make-whole slash, mirroring the rental miss path in
//! `tenzro-settlement`.

use crate::error::{Result, StorageMarketError};
use crate::provider::ObjectDescriptor;
use bytes::Bytes;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_iroh::{IrohResolver, TenzroUri};

/// A retrievability challenge: prove possession of the named shards *now*.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Object whose shards are being challenged.
    pub object_id: String,
    /// Random 32-byte nonce; defeats precomputed responses.
    pub nonce: [u8; 32],
    /// Shard indices the provider must prove possession of.
    pub shard_indices: Vec<usize>,
}

/// A provider's response: one digest per challenged shard, in the same order
/// as [`Challenge::shard_indices`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// Object the response is for.
    pub object_id: String,
    /// `SHA-256(nonce || shard_bytes)` per challenged shard.
    pub digests: Vec<[u8; 32]>,
}

/// Computes the canonical challenge digest `SHA-256(nonce || shard_bytes)`.
pub fn challenge_digest(nonce: &[u8; 32], shard_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(shard_bytes);
    hasher.finalize().into()
}

/// Draws a fresh challenge over a random subset of an object's shards.
///
/// `sample_size` is clamped to the object's shard count. A challenge always
/// covers at least one shard. Indices are distinct.
pub fn new_challenge(descriptor: &ObjectDescriptor, sample_size: usize) -> Challenge {
    let n = descriptor.shard_count();
    let take = sample_size.clamp(1, n.max(1));

    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce);

    // Sample `take` distinct indices from 0..n by partial Fisher-Yates.
    let mut pool: Vec<usize> = (0..n).collect();
    for i in 0..take.min(n) {
        let j = rng.gen_range(i..n);
        pool.swap(i, j);
    }
    let mut shard_indices: Vec<usize> = pool.into_iter().take(take.min(n)).collect();
    shard_indices.sort_unstable();

    Challenge {
        object_id: descriptor.object_id.clone(),
        nonce,
        shard_indices,
    }
}

/// Answers a challenge by hashing the bytes the prover currently holds.
///
/// `fetch_shard` returns the bytes for a given shard index, or an error if the
/// prover no longer has them. A prover that has lost a challenged shard cannot
/// produce a valid digest and the resulting response will fail verification.
pub fn answer_challenge<F>(challenge: &Challenge, mut fetch_shard: F) -> Result<ChallengeResponse>
where
    F: FnMut(usize) -> Result<Vec<u8>>,
{
    let mut digests = Vec::with_capacity(challenge.shard_indices.len());
    for &idx in &challenge.shard_indices {
        let bytes = fetch_shard(idx)?;
        digests.push(challenge_digest(&challenge.nonce, &bytes));
    }
    Ok(ChallengeResponse {
        object_id: challenge.object_id.clone(),
        digests,
    })
}

/// Verifies a challenge response by independently fetching the challenged
/// shards over the transport and recomputing the expected digests.
///
/// This is the trustless path: it proves the shards are genuinely retrievable
/// from the network *and* that the provider's response matches. Any shard that
/// cannot be fetched, fails its commitment, or whose recomputed digest differs
/// from the response fails the whole challenge.
pub async fn verify_challenge(
    descriptor: &ObjectDescriptor,
    challenge: &Challenge,
    response: &ChallengeResponse,
    resolver: &Arc<dyn IrohResolver>,
) -> Result<()> {
    if response.object_id != challenge.object_id {
        return Err(StorageMarketError::ChallengeFailed {
            object_id: challenge.object_id.clone(),
            reason: "response object_id does not match challenge".to_string(),
        });
    }
    if response.digests.len() != challenge.shard_indices.len() {
        return Err(StorageMarketError::ChallengeFailed {
            object_id: challenge.object_id.clone(),
            reason: format!(
                "expected {} digests, got {}",
                challenge.shard_indices.len(),
                response.digests.len()
            ),
        });
    }

    for (pos, &idx) in challenge.shard_indices.iter().enumerate() {
        let sref = descriptor
            .shards
            .iter()
            .find(|s| s.index == idx)
            .ok_or_else(|| StorageMarketError::ShardNotFound {
                object_id: challenge.object_id.clone(),
                shard_index: idx,
            })?;

        let uri: TenzroUri =
            sref.uri.parse().map_err(|e| StorageMarketError::ChallengeFailed {
                object_id: challenge.object_id.clone(),
                reason: format!("shard {} has unparseable URI: {}", idx, e),
            })?;

        let bytes: Bytes =
            resolver
                .fetch_bytes(&uri)
                .await
                .map_err(|e| StorageMarketError::ChallengeFailed {
                    object_id: challenge.object_id.clone(),
                    reason: format!("shard {} not retrievable: {}", idx, e),
                })?;

        // Bytes must match their stored commitment (no silent corruption).
        if crate::redundancy::Shard::commit(&bytes) != sref.commitment {
            return Err(StorageMarketError::ChallengeFailed {
                object_id: challenge.object_id.clone(),
                reason: format!("shard {} bytes fail commitment", idx),
            });
        }

        let expected = challenge_digest(&challenge.nonce, &bytes);
        if expected != response.digests[pos] {
            return Err(StorageMarketError::ChallengeFailed {
                object_id: challenge.object_id.clone(),
                reason: format!("shard {} digest mismatch", idx),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::StorageProvider;
    use crate::redundancy::RedundancyScheme;
    use std::collections::HashMap;
    use tenzro_iroh::{IrohBackedResolver, IrohResolver};

    async fn stored() -> (Arc<dyn IrohResolver>, ObjectDescriptor, HashMap<usize, Vec<u8>>) {
        let resolver: Arc<dyn IrohResolver> = IrohBackedResolver::bind_in_memory().await.unwrap();
        let provider = StorageProvider::new(resolver.clone());
        let scheme = RedundancyScheme::erasure(4, 2).unwrap();
        let data = b"proof of retrievability target object with enough bytes".to_vec();
        let desc = provider
            .store_object("por-obj", "abcd", &data, scheme)
            .await
            .unwrap();

        // Build a local shard-bytes map so the honest prover can answer by
        // index (simulating a provider that still holds its shards).
        let mut held = HashMap::new();
        for sref in &desc.shards {
            let uri: TenzroUri = sref.uri.parse().unwrap();
            let bytes = resolver.fetch_bytes(&uri).await.unwrap().to_vec();
            held.insert(sref.index, bytes);
        }
        (resolver, desc, held)
    }

    #[tokio::test]
    async fn honest_provider_passes_challenge() {
        let (resolver, desc, held) = stored().await;
        let challenge = new_challenge(&desc, 3);
        let response =
            answer_challenge(&challenge, |idx| Ok(held.get(&idx).cloned().unwrap())).unwrap();
        verify_challenge(&desc, &challenge, &response, &resolver)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn lying_provider_fails_challenge() {
        let (resolver, desc, _held) = stored().await;
        let challenge = new_challenge(&desc, 2);
        // Prover answers with garbage bytes it does not actually hold.
        let response =
            answer_challenge(&challenge, |_idx| Ok(vec![0u8; 16])).unwrap();
        let err = verify_challenge(&desc, &challenge, &response, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageMarketError::ChallengeFailed { .. }));
    }

    #[tokio::test]
    async fn wrong_digest_count_is_rejected() {
        let (resolver, desc, _held) = stored().await;
        let challenge = new_challenge(&desc, 3);
        let response = ChallengeResponse {
            object_id: challenge.object_id.clone(),
            digests: vec![[0u8; 32]], // too few
        };
        let err = verify_challenge(&desc, &challenge, &response, &resolver)
            .await
            .unwrap_err();
        assert!(matches!(err, StorageMarketError::ChallengeFailed { .. }));
    }

    #[test]
    fn challenge_samples_distinct_indices_within_bounds() {
        let desc = ObjectDescriptor {
            object_id: "x".to_string(),
            owner_hex: "00".to_string(),
            size_bytes: 10,
            scheme: RedundancyScheme::erasure(4, 2).unwrap(),
            shards: (0..6)
                .map(|i| crate::provider::ShardRef {
                    index: i,
                    uri: format!("tenzro://blob/{:064x}", i),
                    commitment: String::new(),
                })
                .collect(),
        };
        let c = new_challenge(&desc, 100); // oversized sample clamps to n
        assert_eq!(c.shard_indices.len(), 6);
        let mut sorted = c.shard_indices.clone();
        sorted.dedup();
        assert_eq!(sorted.len(), 6, "indices must be distinct");
        assert!(c.shard_indices.iter().all(|&i| i < 6));
    }
}
