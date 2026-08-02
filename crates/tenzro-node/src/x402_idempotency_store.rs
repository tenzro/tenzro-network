//! RocksDB-backed [`IdempotencyStore`] for x402 payment identifiers.
//!
//! Persists [`PaymentReceipt`] records under `CF_SETTLEMENTS` keyed by
//! `x402_idem:<payment_id>`, alongside the other payment-domain state
//! (channels, escrow, receipts, bazaar listings). The concrete RocksDB impl
//! lives here so the payments crate stays free of tenzro-storage's RocksDB
//! types.

use std::sync::Arc;

use tenzro_payments::types::PaymentReceipt;
use tenzro_payments::x402::IdempotencyStore;
use tenzro_payments::{PaymentError, Result as PaymentResult};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};

/// Key prefix for x402 idempotency rows within `CF_SETTLEMENTS`.
const IDEM_PREFIX: &str = "x402_idem:";

fn idem_key(payment_id: &str) -> Vec<u8> {
    format!("{}{}", IDEM_PREFIX, payment_id).into_bytes()
}

/// RocksDB-backed [`IdempotencyStore`].
pub struct NodeIdempotencyStore {
    storage: Arc<dyn KvStore>,
}

impl std::fmt::Debug for NodeIdempotencyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdempotencyStore").finish()
    }
}

impl NodeIdempotencyStore {
    /// Wrap a shared [`KvStore`] (typically the node's `Arc<RocksDbStore>`).
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }
}

impl IdempotencyStore for NodeIdempotencyStore {
    fn put(&self, payment_id: &str, receipt: &PaymentReceipt) -> PaymentResult<()> {
        let bytes = serde_json::to_vec(receipt)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        self.storage
            .put(CF_SETTLEMENTS, &idem_key(payment_id), &bytes)
            .map_err(|e| PaymentError::SettlementError(format!("x402 idem put: {e}")))
    }

    fn load_all(&self) -> PaymentResult<Vec<(String, PaymentReceipt)>> {
        let keys = self
            .storage
            .get_keys_with_prefix(CF_SETTLEMENTS, IDEM_PREFIX.as_bytes())
            .map_err(|e| PaymentError::SettlementError(format!("x402 idem scan: {e}")))?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let payment_id = String::from_utf8_lossy(&key)
                .strip_prefix(IDEM_PREFIX)
                .unwrap_or_default()
                .to_string();
            if payment_id.is_empty() {
                continue;
            }
            if let Some(bytes) = self
                .storage
                .get(CF_SETTLEMENTS, &key)
                .map_err(|e| PaymentError::SettlementError(format!("x402 idem get: {e}")))?
            {
                let receipt: PaymentReceipt = serde_json::from_slice(&bytes)
                    .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
                out.push((payment_id, receipt));
            }
        }
        Ok(out)
    }
}
