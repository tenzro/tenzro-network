//! RocksDB-backed [`KeyshareStore`] implementation.
//!
//! Persists DKLS23 [`KeyshareEnvelope`] records under `CF_MPC_KEYSHARES` using
//! the exact key layout documented in `tenzro_bridge::mpc::store`:
//!
//! ```text
//! "mpc/keyshare/<group_id_hex>/<epoch_le_u64_hex>" → bincode(KeyshareEnvelope)
//! "mpc/keyshare/by_group/<group_id_hex>"           → bincode(Vec<u64>)  (epoch index)
//! ```
//!
//! The store is the seam between the bridge crate's session driver (which
//! holds an [`Arc<dyn KeyshareStore>`]) and the node-owned `Arc<RocksDbStore>`
//! — the bridge crate must not depend on tenzro-storage's RocksDB types, so
//! the concrete impl lives here.
//!
//! Conflict semantics match the trait contract: re-inserting a byte-identical
//! envelope is idempotent; a distinct envelope at the same `(group_id, epoch)`
//! returns [`KeyshareError::Conflict`] without overwriting.

use std::sync::Arc;

use tenzro_bridge::mpc::store::{GroupId, KeyshareEnvelope, KeyshareError, KeyshareStore};
use tenzro_storage::{CF_MPC_KEYSHARES, KvStore};

/// Per-envelope key: `mpc/keyshare/<group_hex>/<epoch_le_u64_hex>`.
fn envelope_key(group_id: &GroupId, epoch: u64) -> Vec<u8> {
    format!(
        "mpc/keyshare/{}/{}",
        group_id.to_hex(),
        hex::encode(epoch.to_le_bytes())
    )
    .into_bytes()
}

/// Per-group epoch index key: `mpc/keyshare/by_group/<group_hex>`.
fn epoch_index_key(group_id: &GroupId) -> Vec<u8> {
    format!("mpc/keyshare/by_group/{}", group_id.to_hex()).into_bytes()
}

/// RocksDB-backed [`KeyshareStore`].
#[derive(Clone)]
pub struct NodeKeyshareStore {
    storage: Arc<dyn KvStore>,
}

impl NodeKeyshareStore {
    /// Wrap a shared [`KvStore`] (typically the node's `Arc<RocksDbStore>`).
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    /// Read the epoch index for `group_id` (ascending, no duplicates). Returns
    /// an empty vector when no envelopes have been written for the group.
    fn read_epoch_index(&self, group_id: &GroupId) -> Result<Vec<u64>, KeyshareError> {
        let key = epoch_index_key(group_id);
        match self
            .storage
            .get(CF_MPC_KEYSHARES, &key)
            .map_err(|e| KeyshareError::Backend(e.to_string()))?
        {
            Some(bytes) => bincode::deserialize::<Vec<u64>>(&bytes)
                .map_err(|e| KeyshareError::Backend(format!("epoch index decode: {}", e))),
            None => Ok(Vec::new()),
        }
    }

    /// Write the epoch index for `group_id`.
    fn write_epoch_index(&self, group_id: &GroupId, epochs: &[u64]) -> Result<(), KeyshareError> {
        let key = epoch_index_key(group_id);
        let bytes = bincode::serialize(epochs)
            .map_err(|e| KeyshareError::Backend(format!("epoch index encode: {}", e)))?;
        self.storage
            .put(CF_MPC_KEYSHARES, &key, &bytes)
            .map_err(|e| KeyshareError::Backend(e.to_string()))
    }
}

#[async_trait::async_trait]
impl KeyshareStore for NodeKeyshareStore {
    async fn insert(&self, envelope: KeyshareEnvelope) -> Result<(), KeyshareError> {
        let key = envelope_key(&envelope.group_id, envelope.epoch);

        // Conflict check: same key + different bytes ⇒ Conflict; same bytes
        // ⇒ idempotent ok.
        let existing = self
            .storage
            .get(CF_MPC_KEYSHARES, &key)
            .map_err(|e| KeyshareError::Backend(e.to_string()))?;
        let serialized = bincode::serialize(&envelope)
            .map_err(|e| KeyshareError::Backend(format!("envelope encode: {}", e)))?;

        if let Some(existing_bytes) = existing {
            if existing_bytes != serialized {
                return Err(KeyshareError::Conflict {
                    group: envelope.group_id.to_hex(),
                    epoch: envelope.epoch,
                });
            }
            // Idempotent: byte-identical record already persisted.
            return Ok(());
        }

        self.storage
            .put(CF_MPC_KEYSHARES, &key, &serialized)
            .map_err(|e| KeyshareError::Backend(e.to_string()))?;

        // Maintain the secondary epoch index, ascending + deduplicated.
        let mut epochs = self.read_epoch_index(&envelope.group_id)?;
        if !epochs.contains(&envelope.epoch) {
            epochs.push(envelope.epoch);
            epochs.sort_unstable();
            self.write_epoch_index(&envelope.group_id, &epochs)?;
        }

        Ok(())
    }

    async fn get(&self, group_id: &GroupId, epoch: u64) -> Result<KeyshareEnvelope, KeyshareError> {
        let key = envelope_key(group_id, epoch);
        let bytes = self
            .storage
            .get(CF_MPC_KEYSHARES, &key)
            .map_err(|e| KeyshareError::Backend(e.to_string()))?
            .ok_or(KeyshareError::NotFound {
                group: group_id.to_hex(),
                epoch,
            })?;
        bincode::deserialize(&bytes)
            .map_err(|e| KeyshareError::Backend(format!("envelope decode: {}", e)))
    }

    async fn latest(&self, group_id: &GroupId) -> Result<KeyshareEnvelope, KeyshareError> {
        let epochs = self.read_epoch_index(group_id)?;
        let latest_epoch = epochs.last().copied().ok_or(KeyshareError::NotFound {
            group: group_id.to_hex(),
            epoch: 0,
        })?;
        self.get(group_id, latest_epoch).await
    }

    async fn list_epochs(&self, group_id: &GroupId) -> Result<Vec<u64>, KeyshareError> {
        self.read_epoch_index(group_id)
    }

    async fn prune(&self, group_id: &GroupId, keep_last_n: usize) -> Result<usize, KeyshareError> {
        let epochs = self.read_epoch_index(group_id)?;
        if epochs.len() <= keep_last_n {
            return Ok(0);
        }
        let drop_count = epochs.len() - keep_last_n;
        let (to_drop, keep) = epochs.split_at(drop_count);
        for ep in to_drop {
            let key = envelope_key(group_id, *ep);
            self.storage
                .delete(CF_MPC_KEYSHARES, &key)
                .map_err(|e| KeyshareError::Backend(e.to_string()))?;
        }
        self.write_epoch_index(group_id, keep)?;
        Ok(drop_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_bridge::mpc::setup::{MpcCurve, MpcParameters};
    use tenzro_storage::MemoryStore;
    use tenzro_types::Hash;

    fn sample_envelope(group: GroupId, epoch: u64, party: u8) -> KeyshareEnvelope {
        KeyshareEnvelope {
            group_id: group,
            epoch,
            party_index: party,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: vec![0x02; 33],
            share_hash: Hash::from_bytes(&[1u8; 32]).unwrap(),
            sealed_payload: vec![party, 0xAA, 0xBB],
            created_at_ms: 1_700_000_000_000,
        }
    }

    fn store() -> NodeKeyshareStore {
        NodeKeyshareStore::new(Arc::new(MemoryStore::new()))
    }

    #[tokio::test]
    async fn insert_and_get_roundtrip() {
        let s = store();
        let g = GroupId([7u8; 32]);
        let env = sample_envelope(g, 1, 1);
        s.insert(env.clone()).await.unwrap();
        let got = s.get(&g, 1).await.unwrap();
        assert_eq!(got, env);
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let s = store();
        let g = GroupId([7u8; 32]);
        let err = s.get(&g, 99).await.unwrap_err();
        assert!(matches!(err, KeyshareError::NotFound { .. }));
    }

    #[tokio::test]
    async fn insert_idempotent_for_same_bytes() {
        let s = store();
        let g = GroupId([7u8; 32]);
        let env = sample_envelope(g, 1, 1);
        s.insert(env.clone()).await.unwrap();
        // Same bytes a second time = ok, not conflict.
        s.insert(env.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn insert_conflict_on_different_bytes() {
        let s = store();
        let g = GroupId([7u8; 32]);
        s.insert(sample_envelope(g, 1, 1)).await.unwrap();
        // Different party_index ⇒ different bytes ⇒ Conflict.
        let err = s.insert(sample_envelope(g, 1, 2)).await.unwrap_err();
        assert!(matches!(err, KeyshareError::Conflict { .. }));
    }

    #[tokio::test]
    async fn list_epochs_ascending() {
        let s = store();
        let g = GroupId([7u8; 32]);
        s.insert(sample_envelope(g, 3, 1)).await.unwrap();
        s.insert(sample_envelope(g, 1, 1)).await.unwrap();
        s.insert(sample_envelope(g, 2, 1)).await.unwrap();
        assert_eq!(s.list_epochs(&g).await.unwrap(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn latest_returns_highest_epoch() {
        let s = store();
        let g = GroupId([7u8; 32]);
        s.insert(sample_envelope(g, 1, 1)).await.unwrap();
        s.insert(sample_envelope(g, 5, 1)).await.unwrap();
        s.insert(sample_envelope(g, 3, 1)).await.unwrap();
        let latest = s.latest(&g).await.unwrap();
        assert_eq!(latest.epoch, 5);
    }

    #[tokio::test]
    async fn prune_keeps_last_n() {
        let s = store();
        let g = GroupId([7u8; 32]);
        for ep in 1..=5 {
            s.insert(sample_envelope(g, ep, 1)).await.unwrap();
        }
        let dropped = s.prune(&g, 2).await.unwrap();
        assert_eq!(dropped, 3);
        assert_eq!(s.list_epochs(&g).await.unwrap(), vec![4, 5]);
        // Pruned envelopes are gone.
        assert!(matches!(
            s.get(&g, 1).await.unwrap_err(),
            KeyshareError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn prune_noop_when_below_keep_last_n() {
        let s = store();
        let g = GroupId([7u8; 32]);
        s.insert(sample_envelope(g, 1, 1)).await.unwrap();
        s.insert(sample_envelope(g, 2, 1)).await.unwrap();
        assert_eq!(s.prune(&g, 5).await.unwrap(), 0);
        assert_eq!(s.list_epochs(&g).await.unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn group_isolation_in_epoch_index() {
        let s = store();
        let g1 = GroupId([1u8; 32]);
        let g2 = GroupId([2u8; 32]);
        s.insert(sample_envelope(g1, 1, 1)).await.unwrap();
        s.insert(sample_envelope(g2, 7, 1)).await.unwrap();
        assert_eq!(s.list_epochs(&g1).await.unwrap(), vec![1]);
        assert_eq!(s.list_epochs(&g2).await.unwrap(), vec![7]);
    }
}
