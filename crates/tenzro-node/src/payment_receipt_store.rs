//! RocksDB-backed [`ReceiptStore`] for receipts of settled payment
//! challenges.
//!
//! Persists [`PaymentReceipt`] records under `CF_SETTLEMENTS` keyed by
//! `payment_receipt:<challenge_id>`, so a payer retrying a settled credential
//! gets its receipt back after a restart. The concrete RocksDB impl lives here
//! so the payments crate stays free of tenzro-storage's RocksDB types.

use std::sync::Arc;

use tenzro_payments::types::PaymentReceipt;
use tenzro_payments::{PaymentError, ReceiptStore, Result as PaymentResult};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};

/// Key prefix for receipt rows within `CF_SETTLEMENTS`.
const RECEIPT_PREFIX: &str = "payment_receipt:";

fn receipt_key(challenge_id: &str) -> Vec<u8> {
    format!("{RECEIPT_PREFIX}{challenge_id}").into_bytes()
}

/// RocksDB-backed [`ReceiptStore`].
pub struct NodeReceiptStore {
    storage: Arc<dyn KvStore>,
}

impl std::fmt::Debug for NodeReceiptStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeReceiptStore").finish()
    }
}

impl NodeReceiptStore {
    /// Wrap a shared [`KvStore`] (typically the node's `Arc<RocksDbStore>`).
    pub fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }
}

impl ReceiptStore for NodeReceiptStore {
    fn put(&self, challenge_id: &str, receipt: &PaymentReceipt) -> PaymentResult<()> {
        let bytes = serde_json::to_vec(receipt)
            .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
        self.storage
            .put(CF_SETTLEMENTS, &receipt_key(challenge_id), &bytes)
            .map_err(|e| PaymentError::SettlementError(format!("receipt put: {e}")))
    }

    fn load_all(&self) -> PaymentResult<Vec<(String, PaymentReceipt)>> {
        let keys = self
            .storage
            .get_keys_with_prefix(CF_SETTLEMENTS, RECEIPT_PREFIX.as_bytes())
            .map_err(|e| PaymentError::SettlementError(format!("receipt scan: {e}")))?;
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            let challenge_id = String::from_utf8_lossy(&key)
                .strip_prefix(RECEIPT_PREFIX)
                .unwrap_or_default()
                .to_string();
            if challenge_id.is_empty() {
                continue;
            }
            if let Some(bytes) = self
                .storage
                .get(CF_SETTLEMENTS, &key)
                .map_err(|e| PaymentError::SettlementError(format!("receipt get: {e}")))?
            {
                let receipt: PaymentReceipt = serde_json::from_slice(&bytes)
                    .map_err(|e| PaymentError::SerializationError(e.to_string()))?;
                out.push((challenge_id, receipt));
            }
        }
        Ok(out)
    }
}
