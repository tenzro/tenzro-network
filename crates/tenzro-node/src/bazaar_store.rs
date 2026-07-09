//! RocksDB-backed [`ResourceCatalogStore`] for the x402 Bazaar.
//!
//! Persists [`X402ResourceListing`] records under `CF_SETTLEMENTS` keyed by
//! `bazaar:<listing_id>`, alongside the other payment-domain state (channels,
//! escrow, receipts). The concrete RocksDB impl lives here so the payments
//! crate stays free of tenzro-storage's RocksDB types.

use std::sync::Arc;

use tenzro_payments::x402::{ResourceCatalogStore, X402ResourceListing};
use tenzro_payments::{PaymentError, Result as PaymentResult};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};

/// Key prefix for Bazaar listings within `CF_SETTLEMENTS`.
const BAZAAR_PREFIX: &str = "bazaar:";

fn listing_key(listing_id: &str) -> Vec<u8> {
    format!("{}{}", BAZAAR_PREFIX, listing_id).into_bytes()
}

/// RocksDB-backed [`ResourceCatalogStore`].
pub struct NodeResourceCatalogStore {
    storage: Arc<dyn KvStore>,
}

impl std::fmt::Debug for NodeResourceCatalogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeResourceCatalogStore").finish()
    }
}

impl NodeResourceCatalogStore {
    /// Wrap a shared [`KvStore`] (typically the node's `Arc<RocksDbStore>`).
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }
}

impl ResourceCatalogStore for NodeResourceCatalogStore {
    fn put(&self, listing: &X402ResourceListing) -> PaymentResult<()> {
        let bytes = serde_json::to_vec(listing)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        self.storage
            .put(CF_SETTLEMENTS, &listing_key(&listing.listing_id), &bytes)
            .map_err(|e| PaymentError::SettlementError(format!("bazaar put: {e}")))
    }

    fn remove(&self, listing_id: &str) -> PaymentResult<bool> {
        let key = listing_key(listing_id);
        let existed = self
            .storage
            .get(CF_SETTLEMENTS, &key)
            .map_err(|e| PaymentError::SettlementError(format!("bazaar get: {e}")))?
            .is_some();
        if existed {
            self.storage
                .delete(CF_SETTLEMENTS, &key)
                .map_err(|e| PaymentError::SettlementError(format!("bazaar delete: {e}")))?;
        }
        Ok(existed)
    }

    fn load_all(&self) -> PaymentResult<Vec<X402ResourceListing>> {
        let keys = self
            .storage
            .get_keys_with_prefix(CF_SETTLEMENTS, BAZAAR_PREFIX.as_bytes())
            .map_err(|e| PaymentError::SettlementError(format!("bazaar scan: {e}")))?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(bytes) = self
                .storage
                .get(CF_SETTLEMENTS, &key)
                .map_err(|e| PaymentError::SettlementError(format!("bazaar get: {e}")))?
            {
                let listing: X402ResourceListing = serde_json::from_slice(&bytes)
                    .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
                out.push(listing);
            }
        }
        Ok(out)
    }
}
