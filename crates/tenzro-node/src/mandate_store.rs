//! RocksDB-backed store for validated AP2 mandates.
//!
//! When [`handle_ap2_validate_mandate_pair`] cross-validates a
//! CheckoutMandate against its child PaymentMandate, the validated pair is
//! recorded here so a principal can later enumerate the mandates issued
//! under their DID via `tenzro_listMandates`. The store keeps the full
//! signed VDCs plus a projected summary (controller/agent DID, description,
//! amount, asset, expiry) so listing is a cheap index walk that never
//! re-parses signatures.
//!
//! Rows live in `CF_SETTLEMENTS` alongside the rest of the payment-domain
//! state (channels, escrow, receipts, x402 idempotency):
//!
//! - `mandate:<mandate_id>` → [`MandateRecord`] (the canonical row)
//! - `mandate_by_controller:<controller_did>:<mandate_id>` → empty reverse
//!   index so `list_by_controller` avoids a full-table scan.
//!
//! The reverse index is rebuilt in-memory on hydration from the canonical
//! rows (same approach as `BondManager::by_controller`), so only the
//! canonical rows are the source of truth on disk.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_SETTLEMENTS, KvStore, WriteOp};

/// Storage key prefix for the canonical [`MandateRecord`] rows.
pub const MANDATE_KEY_PREFIX: &[u8] = b"mandate:";
/// Storage key prefix for the `controller_did → mandate_id` reverse index.
pub const MANDATE_BY_CONTROLLER_PREFIX: &[u8] = b"mandate_by_controller:";

/// A validated AP2 mandate pair, persisted for principal-scoped listing.
///
/// The `checkout_vdc` / `payment_vdc` fields hold the full signed VDCs (as
/// JSON) exactly as they were validated, so a relying party can re-verify
/// them independently. The scalar fields are the projection used for cheap
/// list rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MandateRecord {
    /// CheckoutMandate ID — the primary key of this record.
    pub mandate_id: String,
    /// Child PaymentMandate ID.
    pub payment_mandate_id: String,
    /// Principal DID (the controller) — the CheckoutMandate `principal_did`.
    pub controller_did: String,
    /// Agent DID the mandate delegates to.
    pub agent_did: String,
    /// Merchant DID from the PaymentMandate.
    pub merchant_did: String,
    /// Human-readable intent from the CheckoutMandate.
    pub description: String,
    /// Upper bound on authorized spend, smallest unit of `asset`.
    pub max_amount: u128,
    /// Actual committed cart total from the PaymentMandate.
    pub total_amount: u128,
    /// Asset / currency (e.g. `"USD"`, `"USDC"`, `"TNZO"`).
    pub asset: String,
    /// Settlement chain / rail from the PaymentMandate.
    pub chain: String,
    /// CheckoutMandate expiry (RFC 3339).
    pub expires_at: String,
    /// Whether TDIP delegation enforcement was applied at validation time.
    pub delegation_enforced: bool,
    /// Wall-clock time the mandate pair was validated + recorded (ms since epoch).
    pub validated_at_ms: u64,
    /// Full signed CheckoutMandate VDC, for independent re-verification.
    pub checkout_vdc: serde_json::Value,
    /// Full signed PaymentMandate VDC, for independent re-verification.
    pub payment_vdc: serde_json::Value,
}

/// In-memory cache + RocksDB write-through for validated AP2 mandates.
///
/// Construction:
/// - [`MandateStore::new`] — pure in-memory (tests, light client).
/// - [`MandateStore::with_storage`] — write-through + hydrated from disk.
pub struct MandateStore {
    /// `mandate_id -> MandateRecord`.
    mandates: DashMap<String, MandateRecord>,
    /// `controller_did -> Vec<mandate_id>` reverse index.
    by_controller: DashMap<String, Vec<String>>,
    /// Optional persistence backend — when set, every write calls
    /// `write_batch_sync` for fsync durability.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for MandateStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MandateStore")
            .field("mandates", &self.mandates.len())
            .finish()
    }
}

impl Default for MandateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MandateStore {
    /// Pure in-memory store. Use [`with_storage`] for persistence.
    pub fn new() -> Self {
        Self {
            mandates: DashMap::new(),
            by_controller: DashMap::new(),
            storage: None,
        }
    }

    /// Write-through store hydrated from `CF_SETTLEMENTS/mandate:`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> anyhow::Result<Self> {
        let store = Self {
            mandates: DashMap::new(),
            by_controller: DashMap::new(),
            storage: Some(storage),
        };
        store.hydrate()?;
        Ok(store)
    }

    fn hydrate(&self) -> anyhow::Result<()> {
        let storage = match &self.storage {
            Some(s) => s.clone(),
            None => return Ok(()),
        };
        let mut count = 0usize;
        for (_key, value) in storage.scan_prefix(CF_SETTLEMENTS, MANDATE_KEY_PREFIX)? {
            let record: MandateRecord = serde_json::from_slice(&value)?;
            self.by_controller
                .entry(record.controller_did.clone())
                .or_default()
                .push(record.mandate_id.clone());
            self.mandates.insert(record.mandate_id.clone(), record);
            count += 1;
        }
        tracing::info!(mandate_count = count, "MandateStore hydrated from storage");
        Ok(())
    }

    /// Record a validated mandate pair. Idempotent on `mandate_id`: a
    /// second validation of the same CheckoutMandate overwrites the row
    /// (the VDCs are immutable, so this is a no-op refresh of the
    /// `validated_at_ms` timestamp).
    pub fn record(&self, record: MandateRecord) -> anyhow::Result<()> {
        let is_new = !self.mandates.contains_key(&record.mandate_id);
        if let Some(storage) = &self.storage {
            let mut ops = Vec::with_capacity(2);
            let mut key = MANDATE_KEY_PREFIX.to_vec();
            key.extend_from_slice(record.mandate_id.as_bytes());
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key,
                value: serde_json::to_vec(&record)?,
            });
            if is_new {
                let mut idx = MANDATE_BY_CONTROLLER_PREFIX.to_vec();
                idx.extend_from_slice(record.controller_did.as_bytes());
                idx.push(b':');
                idx.extend_from_slice(record.mandate_id.as_bytes());
                ops.push(WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: idx,
                    value: Vec::new(),
                });
            }
            storage.write_batch_sync(ops)?;
        }
        if is_new {
            self.by_controller
                .entry(record.controller_did.clone())
                .or_default()
                .push(record.mandate_id.clone());
        }
        self.mandates.insert(record.mandate_id.clone(), record);
        Ok(())
    }

    /// Fetch a single mandate by its CheckoutMandate ID.
    pub fn get(&self, mandate_id: &str) -> Option<MandateRecord> {
        self.mandates.get(mandate_id).map(|r| r.clone())
    }

    /// Enumerate every recorded mandate whose principal is `controller_did`.
    /// Ordered newest-first by `validated_at_ms`.
    pub fn list_by_controller(&self, controller_did: &str) -> Vec<MandateRecord> {
        let ids = match self.by_controller.get(controller_did) {
            Some(r) => r.clone(),
            None => return Vec::new(),
        };
        let mut out: Vec<MandateRecord> = ids
            .into_iter()
            .filter_map(|id| self.mandates.get(&id).map(|r| r.clone()))
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.validated_at_ms));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, controller: &str, validated_at_ms: u64) -> MandateRecord {
        MandateRecord {
            mandate_id: id.to_string(),
            payment_mandate_id: format!("{id}-pay"),
            controller_did: controller.to_string(),
            agent_did: "did:tenzro:machine:a".to_string(),
            merchant_did: "did:tenzro:machine:m".to_string(),
            description: "book flights".to_string(),
            max_amount: 600,
            total_amount: 500,
            asset: "USD".to_string(),
            chain: "tenzro".to_string(),
            expires_at: "2026-08-01T00:00:00Z".to_string(),
            delegation_enforced: true,
            validated_at_ms,
            checkout_vdc: serde_json::json!({"kind": "checkout"}),
            payment_vdc: serde_json::json!({"kind": "payment"}),
        }
    }

    #[test]
    fn record_and_get() {
        let s = MandateStore::new();
        s.record(rec("m1", "did:tenzro:human:c", 100)).unwrap();
        assert_eq!(s.get("m1").unwrap().controller_did, "did:tenzro:human:c");
        assert!(s.get("missing").is_none());
    }

    #[test]
    fn list_by_controller_newest_first() {
        let s = MandateStore::new();
        s.record(rec("m1", "c", 100)).unwrap();
        s.record(rec("m2", "c", 300)).unwrap();
        s.record(rec("m3", "c", 200)).unwrap();
        s.record(rec("other", "d", 400)).unwrap();
        let list = s.list_by_controller("c");
        let ids: Vec<_> = list.iter().map(|r| r.mandate_id.as_str()).collect();
        assert_eq!(ids, vec!["m2", "m3", "m1"]);
        assert_eq!(s.list_by_controller("d").len(), 1);
        assert!(s.list_by_controller("none").is_empty());
    }

    #[test]
    fn re_record_is_idempotent_on_index() {
        let s = MandateStore::new();
        s.record(rec("m1", "c", 100)).unwrap();
        s.record(rec("m1", "c", 500)).unwrap();
        // Only one index entry, updated timestamp.
        assert_eq!(s.list_by_controller("c").len(), 1);
        assert_eq!(s.get("m1").unwrap().validated_at_ms, 500);
    }
}
