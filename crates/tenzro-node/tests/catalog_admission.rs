//! A node serves a published model only from a publisher chain state stands
//! behind. Each test is one attack on the catalog a node assembles: an entry
//! from a publisher with no bond, an entry edited after it was signed, one
//! signed by a key that is not the publisher's, and one from a publisher whose
//! identity was revoked. Its own process: the catalog is installed
//! process-wide.

use std::collections::BTreeSet;
use std::sync::Arc;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use serde_json::{Value, json};
use tenzro_node::catalog_sync::CatalogSync;
use tenzro_trust::TrustLedger;
use tenzro_trust::catalog::CatalogRecord;
use tenzro_trust::proof::{ProofRequest, attach_hardware, machine_did, options, signing_digest};

/// A publisher's key, standing in for its TPM.
struct Publisher(SigningKey);

impl Publisher {
    fn new(seed: u8) -> Self {
        Self(SigningKey::from_slice(&[seed; 32]).unwrap())
    }
    fn sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out.copy_from_slice(self.0.verifying_key().to_sec1_point(false).as_bytes());
        out
    }
    fn did(&self) -> String {
        machine_did(&self.sec1())
    }
    fn account(&self) -> [u8; 32] {
        tenzro_crypto::composite::account_slot(&self.sec1()[1..])
    }
    fn sign(&self, doc: Value) -> Value {
        let opts = options(&ProofRequest {
            signer_did: self.did(),
            public_key_sec1: self.sec1(),
            purpose: "assertionMethod".into(),
            created: "2026-11-01T00:00:00Z".into(),
            rp_id: None,
        });
        let digest = signing_digest(&doc, &opts);
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(&digest).unwrap();
        attach_hardware(doc, opts, &sig.to_bytes().into())
    }
    /// This publisher's signed entry for `model`.
    fn entry(&self, model: &str) -> Value {
        self.sign(CatalogRecord::unsigned(
            &self.did(),
            model,
            1,
            Some(&body(model)),
        ))
    }
}

fn body(id: &str) -> Value {
    json!({"model": {"engine": "gguf", "spec": {"id": id, "temperature": 0.7}}, "gated": false})
}

/// A catalog over `ledger` whose chain admits only `bonded` accounts and
/// treats `revoked` DIDs as revoked.
fn sync(ledger: Arc<TrustLedger>, bonded: Vec<[u8; 32]>, revoked: Vec<String>) -> CatalogSync {
    CatalogSync::new(
        ledger,
        Vec::new(),
        Arc::new(move |account: &[u8; 32], _digest: &str| bonded.contains(account)),
        Arc::new(move |did: &str| revoked.iter().any(|r| r == did)),
        tenzro_model::CatalogCell::default(),
    )
}

fn publishers(s: &CatalogSync) -> BTreeSet<String> {
    s.refresh().publishers.into_iter().collect()
}

#[test]
fn a_publisher_without_a_bond_is_not_served() {
    let bonded = Publisher::new(11);
    let unbonded = Publisher::new(12);
    let ledger = Arc::new(TrustLedger::new());
    ledger
        .apply(&bonded.entry("acme-a"))
        .expect("a signed entry");
    ledger
        .apply(&unbonded.entry("acme-b"))
        .expect("a signed entry");
    let s = sync(ledger, vec![bonded.account()], Vec::new());
    assert_eq!(publishers(&s), BTreeSet::from([bonded.did()]));
}

#[test]
fn an_edited_or_forged_entry_never_reaches_the_catalog() {
    let publisher = Publisher::new(13);
    let impostor = Publisher::new(14);
    let ledger = Arc::new(TrustLedger::new());
    let mut edited = publisher.entry("acme-c");
    edited["entry"]["gated"] = json!(true);
    assert!(
        ledger.apply(&edited).is_err(),
        "an entry edited after signing"
    );
    let forged = impostor.sign(CatalogRecord::unsigned(
        &publisher.did(),
        "acme-c",
        1,
        Some(&body("acme-c")),
    ));
    assert!(
        ledger.apply(&forged).is_err(),
        "an entry signed by another key"
    );
    let mut unsigned =
        CatalogRecord::unsigned(&publisher.did(), "acme-c", 1, Some(&body("acme-c")));
    unsigned["proof"] = json!({});
    assert!(ledger.apply(&unsigned).is_err(), "an unsigned entry");
    // Even with both keys bonded, nothing was admitted to serve.
    let s = sync(
        ledger,
        vec![publisher.account(), impostor.account()],
        Vec::new(),
    );
    assert!(publishers(&s).is_empty());
}

#[test]
fn a_revoked_publisher_drops_out() {
    let publisher = Publisher::new(15);
    let ledger = Arc::new(TrustLedger::new());
    ledger
        .apply(&publisher.entry("acme-d"))
        .expect("a signed entry");
    let live = sync(ledger.clone(), vec![publisher.account()], Vec::new());
    assert_eq!(publishers(&live), BTreeSet::from([publisher.did()]));
    let revoked = sync(ledger, vec![publisher.account()], vec![publisher.did()]);
    assert!(publishers(&revoked).is_empty());
}
