//! RocksDB-backed [`ResourceCatalogStore`] for the x402 Bazaar, plus the
//! node-side [`SellerReputationResolver`] bridging discovery to the
//! provider-reputation ledger.
//!
//! Persists [`X402ResourceListing`] records under `CF_SETTLEMENTS` keyed by
//! `bazaar:<listing_id>`, alongside the other payment-domain state (channels,
//! escrow, receipts). The concrete RocksDB impl lives here so the payments
//! crate stays free of tenzro-storage's RocksDB types.

use std::sync::Arc;

use tenzro_model::ProviderManager;
use tenzro_payments::x402::{ResourceCatalogStore, SellerReputationResolver, X402ResourceListing};
use tenzro_payments::{PaymentError, Result as PaymentResult};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::primitives::Address;

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

/// [`SellerReputationResolver`] over the node's [`ProviderManager`].
///
/// Joins a listing to the provider-reputation ledger by its `pay_to`
/// settlement address: the same address a provider registered under is the
/// address its x402 listings settle to, and the only score-up path on that
/// ledger is a settled payment (`record_settled_success`). A pay-to address
/// with no provider record resolves to `None` — unscored, not zero.
pub struct ProviderReputationResolver {
    provider_manager: Arc<ProviderManager>,
}

impl std::fmt::Debug for ProviderReputationResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderReputationResolver").finish()
    }
}

impl ProviderReputationResolver {
    /// Wrap the node's shared [`ProviderManager`].
    pub fn new(provider_manager: Arc<ProviderManager>) -> Self {
        Self { provider_manager }
    }
}

/// Parse a hex pay-to address (with or without `0x`, 20-byte EVM-style or
/// 32-byte native) into a left-zero-padded 32-byte [`Address`].
fn parse_pay_to_address(pay_to: &str) -> Option<Address> {
    let hex_str = pay_to.strip_prefix("0x").unwrap_or(pay_to);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.is_empty() || bytes.len() > 32 {
        return None;
    }
    let mut buf = [0u8; 32];
    buf[32 - bytes.len()..].copy_from_slice(&bytes);
    Some(Address(buf))
}

impl SellerReputationResolver for ProviderReputationResolver {
    fn reputation(&self, _seller_did: &str, pay_to: &str) -> Option<u64> {
        let address = parse_pay_to_address(pay_to)?;
        self.provider_manager.get_reputation(&address)
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
