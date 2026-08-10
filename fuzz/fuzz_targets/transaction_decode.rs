//! Fuzzes transaction deserialization and canonical hashing — the
//! preimage every signature on the network binds to (chain_id || from
//! || to || nonce || gas || timestamp || tx_type || memo ||
//! pq_public_key), plus the structural checks in
//! `SignedTransaction::validate` (ML-DSA-65 length gates, non-zero
//! addresses, data-size limits).
//!
//! Property: arbitrary JSON must never panic the decoder, the hasher,
//! or the validator.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tenzro_types::transaction::{SignedTransaction, Transaction};

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = serde_json::from_slice::<Transaction>(data) {
        let _ = tx.hash();
    }
    if let Ok(signed) = serde_json::from_slice::<SignedTransaction>(data) {
        let _ = signed.validate();
    }
});
