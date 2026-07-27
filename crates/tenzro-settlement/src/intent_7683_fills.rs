//! ERC-7683 destination-side fill registry — the idempotency guard that
//! enforces "an order is filled at most once on Tenzro".
//!
//! # Why this exists
//!
//! Per the 7683 spec and `docs/architecture/agent-swarm/erc-7683-settler.md`,
//! the destination settler must reject a second `fill(originData)` call whose
//! decoded `orderId` already maps to a recorded fill. Without this guard a
//! solver could re-submit a previously-filled order to drain its own balance
//! into a different recipient, or two solvers could race to fill the same
//! order, leaving one out of pocket and the user double-paid.
//!
//! The registry is the source of truth for "has this order been filled here
//! already?" Persistence under `CF_SETTLEMENTS / 7683_dest:<order_id>`
//! survives restarts so the guard is durable across the destination
//! settler's lifetime.
//!
//! # Manager role
//!
//! [`Spec4FillRegistry`] is a denormalized query cache + write-through
//! persistence layer. The actual fund movement (pulling outputs from the
//! solver's balance and crediting the recipient) happens in the destination
//! settler precompile against the VM state. This registry only records that
//! the fill happened — which is enough for the idempotency guard.
//!
//! # Persistence layout
//!
//! | Prefix                   | Value                       |
//! |--------------------------|-----------------------------|
//! | `7683_dest:<order_id>`   | `FillRecord` (JSON)         |
//!
//! The key uses the raw 32-byte `Hash` bytes after the prefix — built via
//! [`tenzro_types::intent_7683::fill_storage_key`]. No secondary indices —
//! lookup-by-order-id is the only access pattern (the spec is single-shot,
//! so there's nothing to list except by full-prefix scan for audit).

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use serde_json;
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_SETTLEMENTS};
use tenzro_types::intent_7683::{
    fill_storage_key, FillRecord, FILL_KEY_PREFIX,
};
use tenzro_types::primitives::Hash;
use tracing::{info, warn};

/// Destination-side fill registry for ERC-7683 orders.
///
/// Records the first successful `fill(originData)` per `order_id` and
/// refuses subsequent fills with [`SettlementError::OrderAlreadyFilled`].
/// Optionally write-through to RocksDB so the guard survives restart.
pub struct Spec4FillRegistry {
    fills: DashMap<Hash, FillRecord>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for Spec4FillRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Spec4FillRegistry")
            .field("fills", &self.fills.len())
            .field(
                "storage",
                &self.storage.as_ref().map(|_| "Some(Arc<dyn KvStore>)"),
            )
            .finish()
    }
}

impl Default for Spec4FillRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Spec4FillRegistry {
    /// In-memory registry with no persistence. Useful for tests and for
    /// nodes that don't want fill state to survive restart (none in
    /// production — every validator/RPC carries persistent CF_SETTLEMENTS).
    pub fn new() -> Self {
        Self {
            fills: DashMap::new(),
            storage: None,
        }
    }

    /// Persistent registry. On construction, scans
    /// `CF_SETTLEMENTS / 7683_dest:` and rebuilds the in-memory map so the
    /// idempotency guard is hot from the first request after startup.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let reg = Self {
            fills: DashMap::new(),
            storage: Some(storage),
        };
        reg.hydrate();
        reg
    }

    /// Rebuild the in-memory map from `CF_SETTLEMENTS`. Best-effort:
    /// individual deserialization failures are logged and skipped so a
    /// single corrupt record cannot block startup.
    fn hydrate(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        let keys = match storage.get_keys_with_prefix(CF_SETTLEMENTS, FILL_KEY_PREFIX) {
            Ok(keys) => keys,
            Err(e) => {
                warn!(
                    "Failed to scan CF_SETTLEMENTS for 7683 fill hydration: {}",
                    e
                );
                return;
            }
        };

        let mut hydrated = 0usize;
        for key_bytes in &keys {
            match storage.get(CF_SETTLEMENTS, key_bytes) {
                Ok(Some(data)) => match serde_json::from_slice::<FillRecord>(&data) {
                    Ok(record) => {
                        self.fills.insert(record.order_id, record);
                        hydrated += 1;
                    }
                    Err(e) => {
                        warn!(
                            "Failed to deserialize 7683 FillRecord at key {:?}: {}",
                            String::from_utf8_lossy(key_bytes),
                            e
                        );
                    }
                },
                Ok(None) => {}
                Err(e) => warn!(
                    "Storage read failure during Spec4FillRegistry hydration: {}",
                    e
                ),
            }
        }

        if hydrated > 0 {
            info!(
                "Hydrated {} ERC-7683 fill record(s) from RocksDB CF_SETTLEMENTS",
                hydrated
            );
        }
    }

    /// Record a destination-side fill. Idempotency:
    ///
    /// - Returns `Ok(())` and persists the record if `order_id` is unseen.
    /// - Returns [`SettlementError::OrderAlreadyFilled`] without mutation
    ///   if a record for `order_id` already exists, regardless of whether
    ///   the duplicate's other fields match.
    ///
    /// The check uses [`DashMap::entry`] so concurrent calls for the same
    /// `order_id` race exactly once: the first wins, subsequent ones see
    /// the populated entry and bail out. The persistence write happens
    /// before the entry is unlocked so an observer that sees `fills[id]`
    /// in memory can rely on the record being durable on disk.
    pub fn record_fill(&self, record: FillRecord) -> Result<()> {
        let order_id = record.order_id;

        // Use entry API to make the check-and-insert atomic w.r.t. other
        // concurrent record_fill calls for the same order_id.
        match self.fills.entry(order_id) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(SettlementError::OrderAlreadyFilled(hex::encode(
                    order_id.as_bytes(),
                )))
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                // Persist BEFORE inserting into the in-memory map. If the
                // disk write fails we leave no in-memory trace — the next
                // attempt will see the slot vacant and try again. That's
                // safer than committing in-memory and silently losing the
                // record on restart.
                if let Some(storage) = &self.storage {
                    let bytes = serde_json::to_vec(&record).map_err(|e| {
                        SettlementError::StorageError(format!(
                            "serialize 7683 FillRecord: {}",
                            e
                        ))
                    })?;
                    let ops = vec![WriteOp::Put {
                        cf: CF_SETTLEMENTS.to_string(),
                        key: fill_storage_key(&order_id),
                        value: bytes,
                    }];
                    storage
                        .write_batch_sync(ops)
                        .map_err(|e| SettlementError::StorageError(e.to_string()))?;
                }

                let filler = record.filler;
                slot.insert(record);
                info!(
                    "Recorded ERC-7683 fill {} by {}",
                    hex::encode(order_id.as_bytes()),
                    filler
                );
                Ok(())
            }
        }
    }

    /// Look up the recorded fill for `order_id`, if any. `None` means the
    /// order has not been filled on this destination — callers must not
    /// interpret `None` as "not filled anywhere" (the order may be filled
    /// on a different chain).
    pub fn get_fill(&self, order_id: &Hash) -> Option<FillRecord> {
        self.fills.get(order_id).map(|r| r.value().clone())
    }

    /// True if a fill record exists for `order_id`. Lighter than
    /// [`Self::get_fill`] when callers only need the boolean.
    pub fn is_filled(&self, order_id: &Hash) -> bool {
        self.fills.contains_key(order_id)
    }

    /// Snapshot of all recorded fills. Order is not guaranteed (DashMap
    /// iteration is unordered). For pagination, callers should sort by
    /// `filled_at` themselves; this registry does not maintain a
    /// time-ordered index.
    pub fn list_fills(&self) -> Vec<FillRecord> {
        self.fills.iter().map(|r| r.value().clone()).collect()
    }

    /// Number of recorded fills.
    pub fn len(&self) -> usize {
        self.fills.len()
    }

    /// True if no fills are recorded.
    pub fn is_empty(&self) -> bool {
        self.fills.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::intent_7683::{Output, ProofRoute};
    use tenzro_types::primitives::{Address, Timestamp};

    fn sample_record(order_id: Hash, filler_byte: u8) -> FillRecord {
        FillRecord {
            order_id,
            origin_chain_id: 11155111, // Sepolia EIP-155
            origin_settler: Address::new([0xA1; 32]),
            filler: Address::new([filler_byte; 32]),
            recipient: [0xCC; 32],
            outputs: vec![Output {
                token: vec![0xDD; 20],
                amount: {
                    let mut a = [0u8; 32];
                    a[24..].copy_from_slice(&1_000_000u64.to_be_bytes());
                    a
                },
                recipient: [0xCC; 32],
                chain_id: 11155111,
            }],
            fill_tx_hash: Hash::new([0xEE; 32]),
            filled_at: Timestamp::new(1_700_000_000_000),
            proof_route: ProofRoute::LayerZero,
        }
    }

    #[test]
    fn first_fill_succeeds() {
        let reg = Spec4FillRegistry::new();
        let order_id = Hash::new([0x11; 32]);
        let record = sample_record(order_id, 0x22);

        let result = reg.record_fill(record.clone());
        assert!(result.is_ok(), "first fill must succeed: {:?}", result);
        assert!(reg.is_filled(&order_id));
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn second_fill_same_order_id_rejected() {
        let reg = Spec4FillRegistry::new();
        let order_id = Hash::new([0x11; 32]);
        let first = sample_record(order_id, 0x22);
        let second = sample_record(order_id, 0x33); // different filler

        reg.record_fill(first.clone()).expect("first fill ok");

        let result = reg.record_fill(second);
        let err = result.expect_err("second fill must be rejected");
        match err {
            SettlementError::OrderAlreadyFilled(id_hex) => {
                assert_eq!(id_hex, hex::encode(order_id.as_bytes()));
            }
            other => panic!("expected OrderAlreadyFilled, got {:?}", other),
        }

        // Original record must still be the one in the registry — the
        // duplicate must not overwrite.
        let stored = reg.get_fill(&order_id).expect("first fill still there");
        assert_eq!(stored.filler, first.filler);
        assert_eq!(reg.len(), 1, "registry size unchanged");
    }

    #[test]
    fn distinct_order_ids_both_recorded() {
        let reg = Spec4FillRegistry::new();
        let id_a = Hash::new([0x11; 32]);
        let id_b = Hash::new([0x12; 32]);
        reg.record_fill(sample_record(id_a, 0x22)).unwrap();
        reg.record_fill(sample_record(id_b, 0x23)).unwrap();
        assert_eq!(reg.len(), 2);
        assert!(reg.is_filled(&id_a));
        assert!(reg.is_filled(&id_b));
    }

    #[test]
    fn get_fill_unknown_returns_none() {
        let reg = Spec4FillRegistry::new();
        assert!(reg.get_fill(&Hash::new([0x99; 32])).is_none());
        assert!(!reg.is_filled(&Hash::new([0x99; 32])));
    }

    #[test]
    fn list_fills_returns_all_recorded() {
        let reg = Spec4FillRegistry::new();
        let id_a = Hash::new([0x11; 32]);
        let id_b = Hash::new([0x12; 32]);
        let id_c = Hash::new([0x13; 32]);
        reg.record_fill(sample_record(id_a, 0x22)).unwrap();
        reg.record_fill(sample_record(id_b, 0x23)).unwrap();
        reg.record_fill(sample_record(id_c, 0x24)).unwrap();

        let mut listed: Vec<Hash> = reg.list_fills().into_iter().map(|r| r.order_id).collect();
        listed.sort_by_key(|h| h.as_bytes()[0]);
        assert_eq!(listed, vec![id_a, id_b, id_c]);
    }

    #[test]
    fn concurrent_record_fill_same_id_only_one_wins() {
        use std::sync::Barrier;
        use std::thread;

        let reg = Arc::new(Spec4FillRegistry::new());
        let order_id = Hash::new([0x11; 32]);
        let barrier = Arc::new(Barrier::new(8));

        let handles: Vec<_> = (0..8)
            .map(|i| {
                let reg = reg.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    reg.record_fill(sample_record(order_id, i as u8))
                })
            })
            .collect();

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok_count = results.iter().filter(|r| r.is_ok()).count();
        let err_count = results
            .iter()
            .filter(|r| matches!(r, Err(SettlementError::OrderAlreadyFilled(_))))
            .count();
        assert_eq!(ok_count, 1, "exactly one fill must win");
        assert_eq!(err_count, 7, "the other seven must hit OrderAlreadyFilled");
        assert_eq!(reg.len(), 1);
    }
}

#[cfg(test)]
mod persistence_tests {
    //! Persistence-mode tests use the RocksDB-backed `KvStore` so the
    //! write-through and hydration paths are both exercised, not just the
    //! in-memory DashMap. Each test gets its own tempdir.
    use super::*;
    use tempfile::TempDir;
    use tenzro_storage::RocksDbStore;
    use tenzro_types::intent_7683::{Output, ProofRoute};
    use tenzro_types::primitives::{Address, Timestamp};

    fn open_kv(tmp: &TempDir) -> Arc<dyn KvStore> {
        Arc::new(RocksDbStore::open_default(tmp.path()).expect("open RocksDB"))
    }

    fn sample_record(order_id: Hash, filler_byte: u8) -> FillRecord {
        FillRecord {
            order_id,
            origin_chain_id: 11155111,
            origin_settler: Address::new([0xA1; 32]),
            filler: Address::new([filler_byte; 32]),
            recipient: [0xCC; 32],
            outputs: vec![Output {
                token: vec![0xDD; 20],
                amount: {
                    let mut a = [0u8; 32];
                    a[24..].copy_from_slice(&1_000_000u64.to_be_bytes());
                    a
                },
                recipient: [0xCC; 32],
                chain_id: 11155111,
            }],
            fill_tx_hash: Hash::new([0xEE; 32]),
            filled_at: Timestamp::new(1_700_000_000_000),
            proof_route: ProofRoute::LayerZero,
        }
    }

    #[test]
    fn record_then_hydrate_preserves_state() {
        let tmp = TempDir::new().unwrap();
        let order_id = Hash::new([0x42; 32]);

        // First lifetime: write the record, drop the registry.
        {
            let kv = open_kv(&tmp);
            let reg = Spec4FillRegistry::with_storage(kv);
            reg.record_fill(sample_record(order_id, 0x77))
                .expect("first fill ok");
            assert_eq!(reg.len(), 1);
        }

        // Second lifetime: open a fresh registry against the same KvStore.
        {
            let kv = open_kv(&tmp);
            let reg = Spec4FillRegistry::with_storage(kv);
            assert_eq!(reg.len(), 1, "hydration must restore the fill");
            let restored = reg.get_fill(&order_id).expect("fill rehydrated");
            assert_eq!(restored.filler, Address::new([0x77; 32]));
        }
    }

    #[test]
    fn duplicate_after_restart_still_rejected() {
        let tmp = TempDir::new().unwrap();
        let order_id = Hash::new([0x42; 32]);

        {
            let kv = open_kv(&tmp);
            let reg = Spec4FillRegistry::with_storage(kv);
            reg.record_fill(sample_record(order_id, 0x77)).unwrap();
        }

        // Reopen and try to fill the same order again.
        let kv = open_kv(&tmp);
        let reg = Spec4FillRegistry::with_storage(kv);
        let err = reg
            .record_fill(sample_record(order_id, 0x88))
            .expect_err("duplicate after restart must still be rejected");
        match err {
            SettlementError::OrderAlreadyFilled(_) => {}
            other => panic!("expected OrderAlreadyFilled, got {:?}", other),
        }
    }
}
