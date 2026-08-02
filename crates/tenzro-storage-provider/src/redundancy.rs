//! Erasure coding and replication for stored objects (D3).
//!
//! An object is split into `k` **data shards** plus `m` **parity shards**
//! (`n = k + m` total) using systematic Reed-Solomon over GF(2^8). Any `k` of
//! the `n` shards reconstruct the object, so the system tolerates the loss of
//! up to `m` shards (whole providers going offline) without data loss. This is
//! strictly more space-efficient than `n`-way replication for the same fault
//! tolerance: `m`-of-`n` erasure coding survives `m` failures at `n/k`
//! overhead, whereas surviving `m` failures by replication costs `m+1` full
//! copies.
//!
//! Plain replication (multiple full copies of every shard) remains available as
//! the `k = 1` degenerate case: one data shard plus `m` parity shards over
//! GF(2^8) are byte-identical copies, so `RedundancyScheme::replicated(copies)`
//! is just sugar over the same encoder.
//!
//! # Shard layout
//!
//! Reed-Solomon requires every shard to be the same length. The object is
//! zero-padded up to a multiple of `k`, split into `k` equal data shards, and
//! the original byte length is recorded in [`ObjectDescriptor::size_bytes`] so
//! the trailing padding is stripped on reconstruction. Each shard carries a
//! SHA-256 commitment so a single corrupted shard is detectable before it
//! poisons a reconstruction.

use crate::error::{Result, StorageProviderError};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How an object is spread across shards for fault tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedundancyScheme {
    /// Number of data shards (`k`). Reconstructing the object needs any `k`
    /// shards out of `data_shards + parity_shards`.
    pub data_shards: usize,
    /// Number of parity shards (`m`). The object survives up to `m` shard
    /// losses.
    pub parity_shards: usize,
}

impl RedundancyScheme {
    /// Erasure-coded scheme: `data` data shards + `parity` parity shards.
    pub fn erasure(data: usize, parity: usize) -> Result<Self> {
        if data == 0 {
            return Err(StorageProviderError::InvalidRedundancy(
                "data_shards must be >= 1".to_string(),
            ));
        }
        if parity == 0 {
            return Err(StorageProviderError::InvalidRedundancy(
                "parity_shards must be >= 1".to_string(),
            ));
        }
        Ok(Self {
            data_shards: data,
            parity_shards: parity,
        })
    }

    /// Pure replication: `copies` total identical copies of the object. Modeled
    /// as `k = 1` data shard plus `copies - 1` parity shards, all byte-identical
    /// over GF(2^8).
    pub fn replicated(copies: usize) -> Result<Self> {
        if copies < 2 {
            return Err(StorageProviderError::InvalidRedundancy(
                "replication needs at least 2 copies".to_string(),
            ));
        }
        Ok(Self {
            data_shards: 1,
            parity_shards: copies - 1,
        })
    }

    /// Total shard count `n = k + m`.
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Maximum number of shard losses the object can survive (`m`).
    pub fn fault_tolerance(&self) -> usize {
        self.parity_shards
    }
}

/// One erasure shard: its position, bytes, and integrity commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shard {
    /// Index in `0..n`. Indices `0..k` are data shards; `k..n` are parity.
    pub index: usize,
    /// Shard bytes (all shards of an object share one length).
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, hex-encoded — the per-shard integrity commitment.
    pub commitment: String,
}

impl Shard {
    /// Computes the hex SHA-256 commitment over `bytes`.
    pub fn commit(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// True if the shard's bytes still match its recorded commitment.
    pub fn verify(&self) -> bool {
        Self::commit(&self.bytes) == self.commitment
    }
}

/// Splits `data` into `scheme.total_shards()` shards under a systematic
/// Reed-Solomon code. The first `k` shards are the (zero-padded) data; the
/// remaining `m` are parity. Each shard is committed with SHA-256.
pub fn encode(data: &[u8], scheme: RedundancyScheme) -> Result<Vec<Shard>> {
    let k = scheme.data_shards;
    let m = scheme.parity_shards;

    let rs = ReedSolomon::new(k, m).map_err(|e| StorageProviderError::Erasure(e.to_string()))?;

    // Each data shard holds ceil(len / k) bytes; pad the final shard with zeros.
    // A zero-length object still produces non-empty shards (1 byte each) so the
    // encoder has something to work on; size_bytes records the true length.
    let shard_len = data.len().div_ceil(k).max(1);

    let mut shards: Vec<Vec<u8>> = Vec::with_capacity(k + m);
    for i in 0..k {
        let start = i * shard_len;
        let mut shard = vec![0u8; shard_len];
        if start < data.len() {
            let end = (start + shard_len).min(data.len());
            shard[..end - start].copy_from_slice(&data[start..end]);
        }
        shards.push(shard);
    }
    // Parity shards start zeroed; encode() fills them.
    for _ in 0..m {
        shards.push(vec![0u8; shard_len]);
    }

    rs.encode(&mut shards)
        .map_err(|e| StorageProviderError::Erasure(e.to_string()))?;

    Ok(shards
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let commitment = Shard::commit(&bytes);
            Shard {
                index,
                bytes,
                commitment,
            }
        })
        .collect())
}

/// Reconstructs the original object from a subset of shards.
///
/// `present` carries whatever shards survived (in any order). Each shard's
/// commitment is verified first; a shard whose bytes do not match its
/// commitment is discarded as corrupt rather than trusted. If at least `k`
/// valid, distinct-index shards remain, the object is reconstructed and
/// truncated to `original_len`. Otherwise returns [`StorageProviderError::InsufficientShards`].
pub fn reconstruct(
    present: &[Shard],
    scheme: RedundancyScheme,
    original_len: usize,
    object_id: &str,
) -> Result<Vec<u8>> {
    let k = scheme.data_shards;
    let m = scheme.parity_shards;
    let n = k + m;

    let rs = ReedSolomon::new(k, m).map_err(|e| StorageProviderError::Erasure(e.to_string()))?;

    // Build the sparse shard vector the decoder expects: Some(bytes) for a
    // verified present shard, None for a hole. Corrupt shards become holes.
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut valid = 0usize;
    for shard in present {
        if shard.index >= n {
            continue;
        }
        if !shard.verify() {
            // Corrupt shard: treat as missing so it cannot poison the decode.
            continue;
        }
        if slots[shard.index].is_none() {
            slots[shard.index] = Some(shard.bytes.clone());
            valid += 1;
        }
    }

    if valid < k {
        return Err(StorageProviderError::InsufficientShards {
            object_id: object_id.to_string(),
            have: valid,
            need: k,
        });
    }

    rs.reconstruct(&mut slots)
        .map_err(|e| StorageProviderError::Erasure(e.to_string()))?;

    // Concatenate the k data shards and strip padding.
    let mut out = Vec::with_capacity(k * slots[0].as_ref().map_or(0, |s| s.len()));
    for slot in slots.iter().take(k) {
        let bytes = slot.as_ref().ok_or_else(|| {
            StorageProviderError::Erasure("data shard still missing after reconstruct".to_string())
        })?;
        out.extend_from_slice(bytes);
    }
    out.truncate(original_len);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erasure_round_trips_exactly() {
        let scheme = RedundancyScheme::erasure(4, 2).unwrap();
        let data = b"the quick brown fox jumps over the lazy dog repeatedly".to_vec();
        let shards = encode(&data, scheme).unwrap();
        assert_eq!(shards.len(), 6);
        let back = reconstruct(&shards, scheme, data.len(), "obj1").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn survives_up_to_m_losses() {
        let scheme = RedundancyScheme::erasure(4, 2).unwrap();
        let data = vec![7u8; 1000];
        let shards = encode(&data, scheme).unwrap();
        // Drop 2 shards (== m): still reconstructs.
        let surviving: Vec<Shard> = shards
            .into_iter()
            .filter(|s| s.index != 1 && s.index != 4)
            .collect();
        assert_eq!(surviving.len(), 4);
        let back = reconstruct(&surviving, scheme, data.len(), "obj2").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn fails_past_m_losses() {
        let scheme = RedundancyScheme::erasure(4, 2).unwrap();
        let data = vec![3u8; 500];
        let shards = encode(&data, scheme).unwrap();
        // Drop 3 shards (> m): cannot reconstruct.
        let surviving: Vec<Shard> = shards.into_iter().take(3).collect();
        let err = reconstruct(&surviving, scheme, data.len(), "obj3").unwrap_err();
        assert!(matches!(
            err,
            StorageProviderError::InsufficientShards {
                have: 3,
                need: 4,
                ..
            }
        ));
    }

    #[test]
    fn corrupt_shard_is_discarded_not_trusted() {
        let scheme = RedundancyScheme::erasure(4, 2).unwrap();
        let data = vec![9u8; 800];
        let mut shards = encode(&data, scheme).unwrap();
        // Corrupt one data shard's bytes without updating its commitment.
        shards[0].bytes[0] ^= 0xFF;
        // 5 other valid shards remain (4 needed) → reconstruct still succeeds,
        // and the corrupt shard is treated as a hole rather than trusted.
        let back = reconstruct(&shards, scheme, data.len(), "obj4").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn replication_is_k1_erasure() {
        let scheme = RedundancyScheme::replicated(3).unwrap();
        assert_eq!(scheme.data_shards, 1);
        assert_eq!(scheme.parity_shards, 2);
        assert_eq!(scheme.total_shards(), 3);
        let data = b"replicated payload".to_vec();
        let shards = encode(&data, scheme).unwrap();
        // Each shard is a full copy of the (padded) object.
        for s in &shards {
            assert_eq!(&s.bytes[..data.len()], &data[..]);
        }
        // Any single surviving copy reconstructs.
        let one = vec![shards[2].clone()];
        let back = reconstruct(&one, scheme, data.len(), "obj5").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn zero_length_object_round_trips() {
        let scheme = RedundancyScheme::erasure(3, 2).unwrap();
        let data: Vec<u8> = Vec::new();
        let shards = encode(&data, scheme).unwrap();
        let back = reconstruct(&shards, scheme, 0, "empty").unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn rejects_zero_data_shards() {
        assert!(RedundancyScheme::erasure(0, 2).is_err());
        assert!(RedundancyScheme::erasure(4, 0).is_err());
        assert!(RedundancyScheme::replicated(1).is_err());
    }
}
