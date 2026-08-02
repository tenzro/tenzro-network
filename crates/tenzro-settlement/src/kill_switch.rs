//! Kill-switch receipt store (Agent-Swarm Spec 1).
//!
//! `KillSwitchStore` is a denormalized query cache + persistent index for
//! `KillSwitchReceipt`s, mirroring the [`EscrowManager`] pattern. It is
//! **not** the source of truth for kill-switch state — that lives in the VM
//! state at `killswitch:<receipt_id>` under `SYSTEM_ADDRESS`, written by
//! the Native VM precompile during transaction execution. This store is
//! populated by the node-side post-execute scan in `event_loop.rs`, which
//! reads VM `Log`s with topics `KillSwitchPause` / `KillSwitchQuarantine`
//! / `KillSwitchTerminate`, rebuilds the canonical `KillSwitchReceipt`
//! with the real `frozen_at_block` value, and calls
//! [`KillSwitchStore::record`].
//!
//! # Persistence layout (CF_SETTLEMENTS)
//!
//! | Prefix                            | Value                                   |
//! |-----------------------------------|-----------------------------------------|
//! | `killswitch:<receipt_id_hex>`     | `KillSwitchReceipt` (JSON)              |
//! | `killswitch_agent:<did>:<ts>`     | receipt id (hex string, JSON-encoded)   |
//! | `killswitch_controller:<did>:<ts>`| receipt id (hex string, JSON-encoded)   |
//!
//! The agent and controller indices are written under composite keys that
//! sort lexicographically by timestamp suffix (zero-padded 20-digit decimal
//! milliseconds), so a `get_keys_with_prefix(killswitch_agent:<did>:)` scan
//! returns receipts for that agent in chronological order.
//!
//! # Consumers
//!
//! - `tenzro_listKillSwitchByAgent` / `tenzro_listKillSwitchByController`
//!   RPC handlers read from the per-DID indices.
//! - `IdentityPaymentBinder` and `StakingManager` consult the agent
//!   lifecycle FSM (not this store) at policy-enforcement time. This store
//!   is the audit log; the FSM is the active state.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_SETTLEMENTS, KvStore, WriteOp};
use tenzro_types::kill_switch::KillSwitchReceipt;
use tracing::{debug, info, warn};

use crate::error::{Result, SettlementError};

/// Storage key prefix for `KillSwitchReceipt` records.
const KILLSWITCH_KEY_PREFIX: &[u8] = b"killswitch:";
/// Per-agent index prefix: `killswitch_agent:<agent_did>:<ts_dec_padded>`.
const KILLSWITCH_AGENT_KEY_PREFIX: &[u8] = b"killswitch_agent:";
/// Per-controller index prefix: `killswitch_controller:<did>:<ts_dec_padded>`.
const KILLSWITCH_CONTROLLER_KEY_PREFIX: &[u8] = b"killswitch_controller:";

/// Width of the zero-padded timestamp suffix used in index keys (20 digits
/// is enough for `i64::MAX` in milliseconds, ~292 million years).
const TS_PAD_WIDTH: usize = 20;

/// Persistent + in-memory store of `KillSwitchReceipt`s.
pub struct KillSwitchStore {
    /// Receipt id (hex) → receipt.
    receipts: DashMap<String, KillSwitchReceipt>,
    /// agent_did → receipt ids (insertion order).
    by_agent: DashMap<String, Vec<String>>,
    /// controller_did → receipt ids (insertion order).
    by_controller: DashMap<String, Vec<String>>,
    /// Optional persistent storage backend.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for KillSwitchStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KillSwitchStore")
            .field("receipts", &self.receipts.len())
            .field("by_agent", &self.by_agent.len())
            .field("by_controller", &self.by_controller.len())
            .field(
                "storage",
                &self.storage.as_ref().map(|_| "Some(Arc<dyn KvStore>)"),
            )
            .finish()
    }
}

impl KillSwitchStore {
    /// In-memory-only store (tests).
    pub fn new() -> Self {
        Self {
            receipts: DashMap::new(),
            by_agent: DashMap::new(),
            by_controller: DashMap::new(),
            storage: None,
        }
    }

    /// Persistent store backed by `CF_SETTLEMENTS`. Hydrates indices from
    /// disk on construction.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let store = Self {
            receipts: DashMap::new(),
            by_agent: DashMap::new(),
            by_controller: DashMap::new(),
            storage: Some(storage),
        };
        store.hydrate();
        store
    }

    /// Record a kill-switch receipt: writes the receipt blob and both
    /// per-DID index entries atomically via `write_batch_sync`. Idempotent
    /// — re-recording the same receipt id is a no-op (the deterministic
    /// id derivation in the VM ensures no collision across distinct
    /// actions).
    pub fn record(&self, receipt: KillSwitchReceipt) -> Result<()> {
        let id = receipt.receipt_id.clone();
        if self.receipts.contains_key(&id) {
            debug!(
                "KillSwitchStore::record skipped: receipt {} already present",
                id
            );
            return Ok(());
        }

        let agent_did = receipt.agent_did.clone();
        let controller_did = receipt.controller_did.clone();
        let ts_millis = receipt.timestamp.0;

        // Update in-memory state first.
        self.by_agent
            .entry(agent_did.clone())
            .or_default()
            .push(id.clone());
        self.by_controller
            .entry(controller_did.clone())
            .or_default()
            .push(id.clone());
        self.receipts.insert(id.clone(), receipt.clone());

        // Persist atomically.
        if let Some(storage) = &self.storage {
            let blob = serde_json::to_vec(&receipt).map_err(|e| {
                SettlementError::StorageError(format!("serialize KillSwitchReceipt {}: {}", id, e))
            })?;
            let id_blob = serde_json::to_vec(&id).map_err(|e| {
                SettlementError::StorageError(format!(
                    "serialize index value for receipt {}: {}",
                    id, e
                ))
            })?;

            let ops = vec![
                WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: Self::receipt_key(&id),
                    value: blob,
                },
                WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: Self::agent_index_key(&agent_did, ts_millis),
                    value: id_blob.clone(),
                },
                WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: Self::controller_index_key(&controller_did, ts_millis),
                    value: id_blob,
                },
            ];

            storage.write_batch_sync(ops).map_err(|e| {
                SettlementError::StorageError(format!("write_batch_sync for receipt {}: {}", id, e))
            })?;
        }

        info!(
            "Recorded kill-switch receipt {} ({} of {})",
            id,
            receipt.action.as_str(),
            agent_did
        );
        Ok(())
    }

    /// Look up a receipt by its hex receipt id.
    pub fn get(&self, receipt_id: &str) -> Option<KillSwitchReceipt> {
        self.receipts.get(receipt_id).map(|e| e.value().clone())
    }

    /// All receipts targeting `agent_did`, in insertion (chronological) order.
    pub fn list_by_agent(&self, agent_did: &str) -> Vec<KillSwitchReceipt> {
        self.by_agent
            .get(agent_did)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.receipts.get(id).map(|e| e.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// All receipts authored by `controller_did`.
    pub fn list_by_controller(&self, controller_did: &str) -> Vec<KillSwitchReceipt> {
        self.by_controller
            .get(controller_did)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.receipts.get(id).map(|e| e.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Total number of recorded receipts (used for /metrics).
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.receipts.is_empty()
    }

    // ---- Key derivation -----------------------------------------------------

    fn receipt_key(receipt_id_hex: &str) -> Vec<u8> {
        [KILLSWITCH_KEY_PREFIX, receipt_id_hex.as_bytes()].concat()
    }

    fn agent_index_key(agent_did: &str, ts_millis: i64) -> Vec<u8> {
        Self::index_key(KILLSWITCH_AGENT_KEY_PREFIX, agent_did, ts_millis)
    }

    fn controller_index_key(controller_did: &str, ts_millis: i64) -> Vec<u8> {
        Self::index_key(KILLSWITCH_CONTROLLER_KEY_PREFIX, controller_did, ts_millis)
    }

    fn index_key(prefix: &[u8], did: &str, ts_millis: i64) -> Vec<u8> {
        // Pad ts to 20 decimal digits so lexicographic order matches
        // numeric order. Negative timestamps would never occur here
        // (Timestamp is always a wall-clock millis since epoch).
        let ts_padded = format!("{:0>width$}", ts_millis.max(0), width = TS_PAD_WIDTH);
        let mut out = Vec::with_capacity(prefix.len() + did.len() + 1 + ts_padded.len());
        out.extend_from_slice(prefix);
        out.extend_from_slice(did.as_bytes());
        out.push(b':');
        out.extend_from_slice(ts_padded.as_bytes());
        out
    }

    // ---- Hydration ----------------------------------------------------------

    fn hydrate(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        // Load receipts.
        let keys = match storage.get_keys_with_prefix(CF_SETTLEMENTS, KILLSWITCH_KEY_PREFIX) {
            Ok(k) => k,
            Err(e) => {
                warn!(
                    "Failed to scan CF_SETTLEMENTS for kill-switch hydration: {}",
                    e
                );
                return;
            }
        };

        let mut hydrated = 0usize;
        // Receipts come back in lexicographic order on receipt_id (hex), which
        // is unordered relative to time. We reconstruct in-memory indices
        // from each receipt's own (agent_did, controller_did, timestamp).
        // To preserve chronological order in the per-DID Vecs, accumulate
        // (timestamp, id) pairs first, sort, then push.
        let mut by_agent_tmp: std::collections::HashMap<String, Vec<(i64, String)>> =
            std::collections::HashMap::new();
        let mut by_controller_tmp: std::collections::HashMap<String, Vec<(i64, String)>> =
            std::collections::HashMap::new();

        for key in &keys {
            // Filter out the per-DID index entries that share the same
            // base prefix bytes for some DIDs. (`killswitch:` is a strict
            // prefix of `killswitch_agent:` is FALSE — they diverge at byte
            // 11. So `get_keys_with_prefix(b"killswitch:")` returns only
            // exact matches. No filter needed.)
            match storage.get(CF_SETTLEMENTS, key) {
                Ok(Some(data)) => match serde_json::from_slice::<KillSwitchReceipt>(&data) {
                    Ok(receipt) => {
                        by_agent_tmp
                            .entry(receipt.agent_did.clone())
                            .or_default()
                            .push((receipt.timestamp.0, receipt.receipt_id.clone()));
                        by_controller_tmp
                            .entry(receipt.controller_did.clone())
                            .or_default()
                            .push((receipt.timestamp.0, receipt.receipt_id.clone()));
                        self.receipts.insert(receipt.receipt_id.clone(), receipt);
                        hydrated += 1;
                    }
                    Err(e) => {
                        let key_str = std::str::from_utf8(key).unwrap_or("<binary>");
                        warn!(
                            "Failed to deserialize kill-switch receipt at key {}: {}",
                            key_str, e
                        );
                    }
                },
                Ok(None) => {}
                Err(e) => warn!(
                    "Storage read failure during KillSwitchStore hydration: {}",
                    e
                ),
            }
        }

        // Sort per-DID buckets chronologically and seed in-memory indices.
        for (did, mut entries) in by_agent_tmp {
            entries.sort_by_key(|(ts, _)| *ts);
            self.by_agent
                .insert(did, entries.into_iter().map(|(_, id)| id).collect());
        }
        for (did, mut entries) in by_controller_tmp {
            entries.sort_by_key(|(ts, _)| *ts);
            self.by_controller
                .insert(did, entries.into_iter().map(|(_, id)| id).collect());
        }

        if hydrated > 0 {
            info!(
                "Hydrated {} kill-switch receipt(s) from RocksDB CF_SETTLEMENTS",
                hydrated
            );
        }
    }
}

impl Default for KillSwitchStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable summary of the store, exposed via `/metrics` and the
/// `tenzro_killSwitchStats` RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillSwitchStats {
    pub total_receipts: usize,
    pub agents_acted_on: usize,
    pub controllers_active: usize,
}

impl KillSwitchStore {
    pub fn stats(&self) -> KillSwitchStats {
        KillSwitchStats {
            total_receipts: self.receipts.len(),
            agents_acted_on: self.by_agent.len(),
            controllers_active: self.by_controller.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::kill_switch::KillSwitchAction;
    use tenzro_types::primitives::{BlockHeight, Timestamp};

    fn mk_receipt(
        id: &str,
        action: KillSwitchAction,
        agent: &str,
        controller: &str,
        ts: i64,
    ) -> KillSwitchReceipt {
        KillSwitchReceipt {
            receipt_id: id.to_string(),
            action,
            agent_did: agent.to_string(),
            controller_did: controller.to_string(),
            reason_code: 1,
            reason_text: None,
            evidence_hash: None,
            slash_bps: None,
            cascade: None,
            pause_until: None,
            frozen_at_block: BlockHeight::new(1),
            timestamp: Timestamp::new(ts),
        }
    }

    #[test]
    fn record_and_lookup_in_memory() {
        let store = KillSwitchStore::new();
        let r = mk_receipt(
            "aa",
            KillSwitchAction::Pause,
            "did:tenzro:machine:a",
            "did:tenzro:human:b",
            100,
        );
        store.record(r.clone()).unwrap();

        assert_eq!(store.get("aa"), Some(r.clone()));
        assert_eq!(store.list_by_agent("did:tenzro:machine:a").len(), 1);
        assert_eq!(store.list_by_controller("did:tenzro:human:b").len(), 1);
        assert!(store.list_by_agent("did:tenzro:machine:other").is_empty());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn record_is_idempotent() {
        let store = KillSwitchStore::new();
        let r = mk_receipt("dup", KillSwitchAction::Quarantine, "a", "b", 1);
        store.record(r.clone()).unwrap();
        store.record(r.clone()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.list_by_agent("a").len(), 1);
    }

    #[test]
    fn list_by_agent_preserves_insertion_order() {
        let store = KillSwitchStore::new();
        let r1 = mk_receipt("01", KillSwitchAction::Pause, "agent", "ctrl", 100);
        let r2 = mk_receipt("02", KillSwitchAction::Quarantine, "agent", "ctrl", 200);
        let r3 = mk_receipt("03", KillSwitchAction::Terminate, "agent", "ctrl", 300);
        store.record(r1).unwrap();
        store.record(r2).unwrap();
        store.record(r3).unwrap();

        let list = store.list_by_agent("agent");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].receipt_id, "01");
        assert_eq!(list[1].receipt_id, "02");
        assert_eq!(list[2].receipt_id, "03");
    }

    #[test]
    fn stats_reflect_current_state() {
        let store = KillSwitchStore::new();
        store
            .record(mk_receipt("a1", KillSwitchAction::Pause, "ag1", "c1", 1))
            .unwrap();
        store
            .record(mk_receipt("a2", KillSwitchAction::Pause, "ag2", "c1", 2))
            .unwrap();
        store
            .record(mk_receipt(
                "a3",
                KillSwitchAction::Quarantine,
                "ag1",
                "c2",
                3,
            ))
            .unwrap();
        let s = store.stats();
        assert_eq!(s.total_receipts, 3);
        assert_eq!(s.agents_acted_on, 2);
        assert_eq!(s.controllers_active, 2);
    }
}
