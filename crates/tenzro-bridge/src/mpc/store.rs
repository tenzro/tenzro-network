//! TEE-sealed keyshare storage abstraction (`CF_MPC_KEYSHARES`).
//!
//! Every DKLS23 party holds one keyshare per `(group_id, epoch)`. Shares are
//! never persisted in plaintext: each party's local enclave seals the
//! `Party<C>` payload (via `tenzro_tee::SealedSecp256k1Key`-style envelope)
//! before write-through to RocksDB under the `CF_MPC_KEYSHARES` column
//! family.
//!
//! The on-disk record is the [`KeyshareEnvelope`] — sealed ciphertext plus
//! the public coordinates (group key, party index, parameters, group epoch)
//! that the runtime needs to *route* a session without unsealing. Unsealing
//! happens lazily, only when the party joins an active signing or refresh
//! round.
//!
//! ## Storage key layout (`CF_MPC_KEYSHARES`)
//!
//! ```text
//! "mpc/keyshare/<group_id_hex>/<epoch_le_u64_hex>"  →  bincode(KeyshareEnvelope)
//! "mpc/keyshare/by_group/<group_id_hex>"            →  Vec<u64> (epoch index)
//! ```
//!
//! Two indexes so the runtime can:
//! - look up "the current share for group G at epoch E" in one read, and
//! - enumerate all epochs ever held for group G during recovery/audit.
//!
//! The trait `KeyshareStore` is the surface; the concrete RocksDB impl lands
//! in task #17 alongside DKG wiring.

use serde::{Deserialize, Serialize};
use tenzro_types::Hash;

use crate::mpc::setup::MpcParameters;

// `CF_MPC_KEYSHARES` is owned by `tenzro-storage` (registered with the
// RocksDB ColumnFamilyDescriptor list there). Re-exported here for
// callers that import from the bridge crate.
pub use tenzro_storage::CF_MPC_KEYSHARES;

/// Domain-separation tag for `GroupId` derivation. `GroupId` identifies the
/// signing committee + group public key independently of any individual
/// session. Re-keys (refresh) preserve the same `GroupId` but increment the
/// epoch.
///
/// ```text
/// GroupId = SHA-256(
///     "tenzro/mpc/group"
///  || group_public_key_sec1_compressed (33 bytes for secp256k1)
///  || sorted_participant_dids (utf-8, NUL-separated, ascending)
///  || threshold_byte
///  || total_parties_byte
/// )
/// ```
pub const GROUP_DOMAIN_TAG: &[u8] = b"tenzro/mpc/group";

/// 32-byte identifier of a DKLS23 signing group (group public key +
/// participant set + threshold shape). Stable across epoch boundaries — only
/// the share material rotates on refresh.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GroupId(pub [u8; 32]);

impl GroupId {
    /// View as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Hex view for log lines and storage keys.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId({})", self.to_hex())
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// On-disk sealed keyshare record. The `sealed_payload` is opaque ciphertext
/// produced by the local TEE provider (`tenzro_tee`); only this party's
/// enclave can unseal it. Public fields are persisted in the clear so the
/// runtime can route messages and resume sessions without unsealing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyshareEnvelope {
    /// Group this envelope belongs to.
    pub group_id: GroupId,
    /// Monotonic epoch counter — incremented by `refresh`/`re_key`. Older
    /// envelopes are retained for late-message rollback during the refresh
    /// transition window.
    pub epoch: u64,
    /// 1-based party index within the group (DKLS23 convention).
    pub party_index: u8,
    /// Threshold shape stamped at write time so a reader can fail fast on
    /// stale `(t, n)` mismatches.
    pub parameters: MpcParameters,
    /// SEC1-compressed group public key (secp256k1 → 33 bytes). Plaintext for
    /// fast routing and address derivation.
    pub group_public_key_compressed: Vec<u8>,
    /// Hash of the unsealed share material — used for tamper detection on
    /// unseal (the enclave compares `sha256(plaintext) == share_hash`).
    pub share_hash: Hash,
    /// Sealed share payload. Opaque to all but this party's enclave.
    pub sealed_payload: Vec<u8>,
    /// Unix-ms timestamp of envelope creation.
    pub created_at_ms: i64,
}

/// Errors returned by [`KeyshareStore`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum KeyshareError {
    /// No envelope persisted for the requested `(group_id, epoch)`.
    #[error("keyshare not found for group {group} epoch {epoch}")]
    NotFound { group: String, epoch: u64 },
    /// Two distinct envelopes claim the same `(group_id, epoch)` slot. Refuses
    /// to silently overwrite — manual operator resolution required.
    #[error("conflicting keyshare envelope at group {group} epoch {epoch}")]
    Conflict { group: String, epoch: u64 },
    /// Underlying storage failure (rocksdb / serde).
    #[error("keyshare store backend error: {0}")]
    Backend(String),
}

/// Read/write surface for sealed MPC keyshares. The concrete RocksDB-backed
/// implementation lands in task #17 (`tenzro_node`).
#[async_trait::async_trait]
pub trait KeyshareStore: Send + Sync {
    /// Persist a freshly-sealed envelope. Returns `Err(Conflict)` if a
    /// distinct envelope already occupies the `(group_id, epoch)` slot;
    /// re-insertion of a byte-identical envelope is idempotent.
    async fn insert(&self, envelope: KeyshareEnvelope) -> Result<(), KeyshareError>;

    /// Fetch the envelope for `(group_id, epoch)` if persisted.
    async fn get(&self, group_id: &GroupId, epoch: u64) -> Result<KeyshareEnvelope, KeyshareError>;

    /// Latest envelope for `group_id`. Equivalent to `get(group_id, max_epoch)`
    /// but performed in a single read against the secondary index.
    async fn latest(&self, group_id: &GroupId) -> Result<KeyshareEnvelope, KeyshareError>;

    /// All epochs the store retains for `group_id`, ascending. Used during
    /// rollback windows and for operator inspection.
    async fn list_epochs(&self, group_id: &GroupId) -> Result<Vec<u64>, KeyshareError>;

    /// Prune envelopes older than `keep_last_n` for `group_id`. Returns the
    /// number of envelopes removed. Safe to call after refresh quorum is
    /// observed for the new epoch.
    async fn prune(&self, group_id: &GroupId, keep_last_n: usize) -> Result<usize, KeyshareError>;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mpc::setup::MpcCurve;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    /// In-memory [`KeyshareStore`] used by cross-module tests in
    /// [`crate::mpc::keygen`]. Behaves as a clone-able handle around a
    /// shared `Arc<Mutex<...>>` so the producer (the session driver) and
    /// the assertion site can share the same backing map.
    #[derive(Clone, Default)]
    pub struct MemKeyshareStore {
        inner: Arc<Mutex<BTreeMap<(GroupId, u64), KeyshareEnvelope>>>,
    }

    #[async_trait::async_trait]
    impl KeyshareStore for MemKeyshareStore {
        async fn insert(&self, envelope: KeyshareEnvelope) -> Result<(), KeyshareError> {
            let mut g = self.inner.lock().await;
            let key = (envelope.group_id, envelope.epoch);
            if let Some(existing) = g.get(&key)
                && existing != &envelope
            {
                return Err(KeyshareError::Conflict {
                    group: envelope.group_id.to_hex(),
                    epoch: envelope.epoch,
                });
            }
            g.insert(key, envelope);
            Ok(())
        }

        async fn get(
            &self,
            group_id: &GroupId,
            epoch: u64,
        ) -> Result<KeyshareEnvelope, KeyshareError> {
            self.inner
                .lock()
                .await
                .get(&(*group_id, epoch))
                .cloned()
                .ok_or(KeyshareError::NotFound {
                    group: group_id.to_hex(),
                    epoch,
                })
        }

        async fn latest(&self, group_id: &GroupId) -> Result<KeyshareEnvelope, KeyshareError> {
            let g = self.inner.lock().await;
            g.iter()
                .rev()
                .find_map(|((gid, _), env)| {
                    if gid == group_id {
                        Some(env.clone())
                    } else {
                        None
                    }
                })
                .ok_or(KeyshareError::NotFound {
                    group: group_id.to_hex(),
                    epoch: 0,
                })
        }

        async fn list_epochs(&self, group_id: &GroupId) -> Result<Vec<u64>, KeyshareError> {
            let g = self.inner.lock().await;
            let mut out: Vec<u64> = g
                .keys()
                .filter_map(|(gid, ep)| if gid == group_id { Some(*ep) } else { None })
                .collect();
            out.sort_unstable();
            Ok(out)
        }

        async fn prune(
            &self,
            group_id: &GroupId,
            keep_last_n: usize,
        ) -> Result<usize, KeyshareError> {
            let mut g = self.inner.lock().await;
            let mut epochs: Vec<u64> = g
                .keys()
                .filter_map(|(gid, ep)| if gid == group_id { Some(*ep) } else { None })
                .collect();
            epochs.sort_unstable();
            if epochs.len() <= keep_last_n {
                return Ok(0);
            }
            let drop_count = epochs.len() - keep_last_n;
            let to_drop: Vec<u64> = epochs.iter().take(drop_count).copied().collect();
            for ep in &to_drop {
                g.remove(&(*group_id, *ep));
            }
            Ok(to_drop.len())
        }
    }

    fn sample_group_id() -> GroupId {
        let mut hasher = Sha256::new();
        hasher.update(GROUP_DOMAIN_TAG);
        hasher.update([0u8; 33]); // dummy SEC1-compressed point
        hasher.update(b"did:tenzro:machine:p1\0did:tenzro:machine:p2\0did:tenzro:machine:p3");
        hasher.update([2u8, 3u8]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        GroupId(out)
    }

    #[test]
    fn group_id_hex_roundtrip() {
        let g = sample_group_id();
        assert_eq!(g.to_hex().len(), 64);
        assert_eq!(format!("{}", g), g.to_hex());
    }

    #[test]
    fn envelope_serdes() {
        let env = KeyshareEnvelope {
            group_id: sample_group_id(),
            epoch: 7,
            party_index: 1,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            share_hash: Hash::from_bytes(&[5u8; 32]).unwrap(),
            sealed_payload: vec![1, 2, 3, 4],
            created_at_ms: 1_700_000_000_000,
        };
        let encoded = serde_json::to_vec(&env).unwrap();
        let decoded: KeyshareEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(env, decoded);
    }
}
