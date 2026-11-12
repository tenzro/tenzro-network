//! Hybrid-signed senders for tests that submit transactions to a node.
//!
//! The ML-DSA-65 leg is required of every account, so a sender needs an
//! ML-DSA-65 key enrolled in chain state before its first transaction. These
//! signers come from seeds whose ML-DSA-65 key `TestHybridSigner::hybrid_pq_key`
//! can name, and `enroll` records that key the way an enrolment does.

// Each test crate that includes this module uses only part of it.
#![allow(dead_code)]

use serde_json::Value;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_node::TenzroNode;

/// A hybrid signer from a seed that differs between calls.
pub fn fresh_signer() -> TestHybridSigner {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    TestHybridSigner::hybrid((nanos.wrapping_add(n.wrapping_mul(97)) % 255) as u8 + 1)
}

/// Record the ML-DSA-65 key of `signer` as enrolled for its P-256 key.
pub fn enroll(node: &TenzroNode, signer: &TestHybridSigner) {
    use tenzro_crypto::composite::HybridSigner as _;
    let key = signer.public_key();
    let pq = key
        .pq
        .clone()
        .expect("a hybrid signer has an ML-DSA-65 key");
    let storage = node.storage().expect("node storage").clone();
    let mut state = tenzro_vm::StateAdapter::with_storage(storage);
    tenzro_vm::account_keys::set_enrolled_pq_key(&mut state, &key.p256, pq, &mut Vec::new());
    state.commit().expect("commit enrolled key");
}

/// Record the enrolled key of the sender whose request `params` carry its
/// P-256 `public_key`.
pub fn enroll_sender(node: &TenzroNode, params: &Value) {
    let p256 = hex::decode(
        params["public_key"]
            .as_str()
            .expect("params carry a public_key")
            .trim_start_matches("0x"),
    )
    .expect("public_key is hex");
    let pq = TestHybridSigner::hybrid_pq_key(&p256).expect("a signer from fresh_signer");
    let storage = node.storage().expect("node storage").clone();
    let mut state = tenzro_vm::StateAdapter::with_storage(storage);
    tenzro_vm::account_keys::set_enrolled_pq_key(&mut state, &p256, pq, &mut Vec::new());
    state.commit().expect("commit enrolled key");
}
