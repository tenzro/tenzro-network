//! Receipts of settled challenges.
//!
//! Once a challenge is settled it is consumed and can never be claimed again.
//! The ledger keeps its receipt, keyed by challenge id, so a payer that
//! retries the same credential (a lost response, a timeout) gets the receipt
//! back instead of an error, and a different credential for the same
//! challenge is recognised as a replay.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use crate::error::Result;
use crate::types::PaymentReceipt;

/// Durable backing for the receipt ledger.
pub trait ReceiptStore: Send + Sync + std::fmt::Debug {
    /// Persist the receipt recorded against `challenge_id`.
    fn put(&self, challenge_id: &str, receipt: &PaymentReceipt) -> Result<()>;
    /// Load every `(challenge_id, receipt)` row (used to hydrate on boot).
    fn load_all(&self) -> Result<Vec<(String, PaymentReceipt)>>;
}

/// Settled-challenge receipts, first writer wins.
#[derive(Debug, Default)]
pub struct ReceiptLedger {
    index: RwLock<HashMap<String, PaymentReceipt>>,
    store: Option<Arc<dyn ReceiptStore>>,
}

impl ReceiptLedger {
    /// In-memory ledger with no durable backing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ledger backed by `store`, hydrated from whatever it already holds.
    pub fn with_store(store: Arc<dyn ReceiptStore>) -> Result<Self> {
        let index = store.load_all()?.into_iter().collect();
        Ok(Self {
            index: RwLock::new(index),
            store: Some(store),
        })
    }

    /// The receipt already recorded for `challenge_id`, if any.
    pub fn get(&self, challenge_id: &str) -> Option<PaymentReceipt> {
        self.index.read().get(challenge_id).cloned()
    }

    /// Record `receipt` for `challenge_id`. Keeps the first receipt if one is
    /// already recorded and returns whichever receipt the ledger now holds.
    pub fn record(&self, challenge_id: &str, receipt: PaymentReceipt) -> Result<PaymentReceipt> {
        let mut idx = self.index.write();
        if let Some(existing) = idx.get(challenge_id) {
            return Ok(existing.clone());
        }
        if let Some(store) = &self.store {
            store.put(challenge_id, &receipt)?;
        }
        idx.insert(challenge_id.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Number of receipts recorded.
    pub fn len(&self) -> usize {
        self.index.read().len()
    }

    /// Whether the ledger holds no receipts.
    pub fn is_empty(&self) -> bool {
        self.index.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn receipt(id: &str) -> PaymentReceipt {
        PaymentReceipt {
            receipt_id: id.to_string(),
            protocol: "x402".to_string(),
            challenge_id: "ch".to_string(),
            credential_id: "cr".to_string(),
            amount: 1,
            asset: "TNZO".to_string(),
            settlement_tx: None,
            chain: "tenzro".to_string(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                "did:tenzro:human:bob".to_string(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        }
    }

    #[derive(Debug, Default)]
    struct MemStore {
        rows: RwLock<HashMap<String, PaymentReceipt>>,
    }

    impl ReceiptStore for MemStore {
        fn put(&self, id: &str, receipt: &PaymentReceipt) -> Result<()> {
            self.rows.write().insert(id.to_string(), receipt.clone());
            Ok(())
        }
        fn load_all(&self) -> Result<Vec<(String, PaymentReceipt)>> {
            Ok(self
                .rows
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        }
    }

    #[test]
    fn the_first_receipt_wins_and_survives_restart() {
        let store = Arc::new(MemStore::default());
        {
            let ledger = ReceiptLedger::with_store(store.clone()).unwrap();
            ledger.record("ch-1", receipt("r1")).unwrap();
            let kept = ledger.record("ch-1", receipt("r2")).unwrap();
            assert_eq!(kept.receipt_id, "r1");
        }
        let hydrated = ReceiptLedger::with_store(store).unwrap();
        assert_eq!(hydrated.get("ch-1").unwrap().receipt_id, "r1");
    }
}
