//! x402 signed-offer + payment-identifier idempotency.
//!
//! Two x402 extensions live here, both pure and transport-agnostic:
//!
//! 1. **Signed offer.** Stock x402 returns an unsigned `X402PaymentRequired`
//!    in the 402 body — a buyer has no way to prove *which* offer it paid
//!    against if the seller later disputes the price. Tenzro binds a 32-byte
//!    domain-separated SHA-256 commitment over the canonical
//!    [`X402PaymentRequirement`] and has the server Ed25519-sign that
//!    commitment. The signature travels in `requirement.extra["offerSig"]`
//!    (+ `offerCommitment` + `offerSigner`) so a stock client ignores it and
//!    a Tenzro-aware buyer verifies the offer before paying. Mirrors the
//!    receipt-commitment pattern in [`crate::x402::receipt`].
//!
//! 2. **Payment identifier.** An idempotency key `pay_<hex>` derived
//!    deterministically from `(offer_commitment, payer_did)`. A buyer that
//!    retries a settlement with the same identifier gets the *prior* receipt
//!    back instead of paying twice. The [`IdempotencyLedger`] holds an
//!    in-memory index plus a pluggable durable [`IdempotencyStore`] so the
//!    guarantee survives node restart.
//!
//! # Domain separation
//!
//! Per the project rule against version segments in Tenzro-owned strings, the
//! SHA-256 domain tags are the literals `"tenzro/x402/offer"` and
//! `"tenzro/x402/payment-id"` — no `/v1`, no `1.0.0`. Schema revisions are
//! flag-day cutovers under the same tag.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PaymentError, Result};
use crate::types::PaymentReceipt;
use crate::x402::payment_required::X402PaymentRequirement;

/// Domain-separation tag for the offer commitment.
pub const X402_OFFER_DOMAIN: &str = "tenzro/x402/offer";

/// Domain-separation tag for the payment identifier.
pub const X402_PAYMENT_ID_DOMAIN: &str = "tenzro/x402/payment-id";

/// `extra` key carrying the hex-encoded offer commitment.
pub const OFFER_COMMITMENT_KEY: &str = "offerCommitment";
/// `extra` key carrying the hex-encoded Ed25519 offer signature.
pub const OFFER_SIG_KEY: &str = "offerSig";
/// `extra` key carrying the hex-encoded Ed25519 signer public key.
pub const OFFER_SIGNER_KEY: &str = "offerSigner";

/// Length of the offer commitment (SHA-256).
pub const X402_OFFER_COMMITMENT_LEN: usize = 32;

/// Compute the 32-byte offer commitment over the canonical
/// [`X402PaymentRequirement`].
///
/// The commitment binds exactly the price-determining fields a buyer relies
/// on: scheme, network, price ceiling, asset, pay-to, resource, and the
/// challenge expiry (so a stale offer can't be replayed after it lapses).
/// `description`, `mimeType`, `outputSchema`, and `extra` are advisory and
/// deliberately excluded — a seller may fix a typo in the description without
/// invalidating an in-flight payment.
///
/// Every field is length-prefixed with a 4-byte little-endian length so a
/// `/` in the resource path can never be confused with a field boundary.
pub fn compute_offer_commitment(
    requirement: &X402PaymentRequirement,
) -> [u8; X402_OFFER_COMMITMENT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(X402_OFFER_DOMAIN.as_bytes());
    // expires_at is bound as its RFC-3339 string so the commitment is stable
    // across serialization round-trips.
    let expires = requirement.expires_at.to_rfc3339();
    for field in [
        requirement.scheme.as_str(),
        requirement.network.as_str(),
        requirement.max_amount_required.as_str(),
        requirement.asset.as_str(),
        requirement.pay_to.as_str(),
        requirement.resource.as_str(),
        expires.as_str(),
    ] {
        let bytes = field.as_bytes();
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; X402_OFFER_COMMITMENT_LEN];
    out.copy_from_slice(&digest);
    out
}

/// A server-signed offer: the offer commitment, the Ed25519 signature over
/// it, and the signer's public key. All hex-encoded (no `0x` prefix).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignedOffer {
    /// Hex-encoded 32-byte offer commitment.
    pub offer_commitment: String,
    /// Hex-encoded Ed25519 signature over the commitment bytes.
    pub offer_sig: String,
    /// Hex-encoded Ed25519 verifying key of the seller/facilitator.
    pub offer_signer: String,
}

impl SignedOffer {
    /// Sign `requirement` with the server's Ed25519 signer, returning the
    /// signed-offer triple. The signature is over the raw 32-byte commitment.
    pub fn sign(
        requirement: &X402PaymentRequirement,
        signer: &tenzro_crypto::signatures::Ed25519SignerImpl,
    ) -> Result<Self> {
        use tenzro_crypto::signatures::Signer;
        let commitment = compute_offer_commitment(requirement);
        let sig = signer
            .sign(&commitment)
            .map_err(|e| PaymentError::CryptoError(format!("offer sign failed: {e}")))?;
        Ok(Self {
            offer_commitment: hex::encode(commitment),
            offer_sig: hex::encode(sig.as_bytes()),
            offer_signer: hex::encode(signer.public_key().as_bytes()),
        })
    }

    /// Verify the offer signature against `requirement`.
    ///
    /// Recomputes the commitment from the requirement (so a tampered price or
    /// pay-to address invalidates the signature), checks it matches the
    /// carried commitment, then verifies the Ed25519 signature under the
    /// carried signer key.
    pub fn verify(&self, requirement: &X402PaymentRequirement) -> Result<()> {
        let expected = compute_offer_commitment(requirement);
        let carried = hex::decode(&self.offer_commitment)
            .map_err(|e| PaymentError::VerificationFailed(format!("bad offer commitment hex: {e}")))?;
        if carried != expected {
            return Err(PaymentError::VerificationFailed(
                "offer commitment does not match requirement".to_string(),
            ));
        }
        let sig_bytes = hex::decode(&self.offer_sig)
            .map_err(|e| PaymentError::VerificationFailed(format!("bad offer sig hex: {e}")))?;
        let key_bytes = hex::decode(&self.offer_signer)
            .map_err(|e| PaymentError::VerificationFailed(format!("bad offer signer hex: {e}")))?;
        let public_key =
            tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, key_bytes);
        let signature =
            tenzro_crypto::Signature::new(tenzro_crypto::KeyType::Ed25519, sig_bytes);
        // `verify` returns Ok(()) only for a valid signature; any error (bad
        // key, bad signature, mismatch) becomes a VerificationFailed.
        tenzro_crypto::signatures::verify(&public_key, &expected, &signature)
            .map_err(|e| PaymentError::VerificationFailed(format!("offer signature invalid: {e}")))?;
        Ok(())
    }

    /// Attach this signed offer to a requirement's `extra` object under the
    /// `offerCommitment` / `offerSig` / `offerSigner` keys, preserving any
    /// existing scheme-specific `extra`.
    pub fn attach_to(&self, requirement: &mut X402PaymentRequirement) {
        let obj = match &mut requirement.extra {
            serde_json::Value::Object(m) => m,
            other => {
                *other = serde_json::Value::Object(serde_json::Map::new());
                other.as_object_mut().expect("just set object")
            }
        };
        obj.insert(
            OFFER_COMMITMENT_KEY.to_string(),
            serde_json::Value::String(self.offer_commitment.clone()),
        );
        obj.insert(
            OFFER_SIG_KEY.to_string(),
            serde_json::Value::String(self.offer_sig.clone()),
        );
        obj.insert(
            OFFER_SIGNER_KEY.to_string(),
            serde_json::Value::String(self.offer_signer.clone()),
        );
    }

    /// Extract a signed offer from a requirement's `extra`, if all three keys
    /// are present and string-typed.
    pub fn extract_from(requirement: &X402PaymentRequirement) -> Option<Self> {
        let obj = requirement.extra.as_object()?;
        let s = |k: &str| obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string());
        Some(Self {
            offer_commitment: s(OFFER_COMMITMENT_KEY)?,
            offer_sig: s(OFFER_SIG_KEY)?,
            offer_signer: s(OFFER_SIGNER_KEY)?,
        })
    }
}

/// Derive the `pay_<hex>` payment identifier for a `(offer, payer)` pair.
///
/// Deterministic: the same offer commitment + payer always yields the same
/// identifier, which is what makes settlement idempotent. Domain-separated so
/// it can never collide with an offer commitment.
pub fn derive_payment_id(offer_commitment: &[u8; X402_OFFER_COMMITMENT_LEN], payer_did: &str) -> String {
    let mut h = Sha256::new();
    h.update(X402_PAYMENT_ID_DOMAIN.as_bytes());
    h.update(offer_commitment);
    let payer = payer_did.as_bytes();
    h.update((payer.len() as u32).to_le_bytes());
    h.update(payer);
    format!("pay_{}", hex::encode(h.finalize()))
}

/// Whether `s` is a structurally-valid payment identifier (`pay_` + 64 hex).
pub fn is_payment_id(s: &str) -> bool {
    let Some(hex_part) = s.strip_prefix("pay_") else {
        return false;
    };
    hex_part.len() == X402_OFFER_COMMITMENT_LEN * 2
        && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Durable backing for the idempotency ledger. The node injects a
/// RocksDB-backed store so replay protection survives restart.
pub trait IdempotencyStore: Send + Sync + std::fmt::Debug {
    /// Persist the receipt recorded against `payment_id`.
    fn put(&self, payment_id: &str, receipt: &PaymentReceipt) -> Result<()>;
    /// Load every `(payment_id, receipt)` row (used to hydrate on boot).
    fn load_all(&self) -> Result<Vec<(String, PaymentReceipt)>>;
}

/// Idempotency ledger for x402 payment identifiers.
///
/// A settlement flow calls [`IdempotencyLedger::get`] before charging; if a
/// receipt already exists for that `payment_id`, it is returned and the charge
/// is skipped. After a successful settlement the flow calls
/// [`IdempotencyLedger::record`] to bind the identifier to its receipt.
#[derive(Debug)]
pub struct IdempotencyLedger {
    index: RwLock<HashMap<String, PaymentReceipt>>,
    store: Option<Arc<dyn IdempotencyStore>>,
}

impl Default for IdempotencyLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl IdempotencyLedger {
    /// In-memory ledger with no durable backing.
    pub fn new() -> Self {
        Self {
            index: RwLock::new(HashMap::new()),
            store: None,
        }
    }

    /// Ledger backed by `store`, hydrated from whatever it already holds.
    pub fn with_store(store: Arc<dyn IdempotencyStore>) -> Result<Self> {
        let existing = store.load_all()?;
        let mut index = HashMap::with_capacity(existing.len());
        for (id, receipt) in existing {
            index.insert(id, receipt);
        }
        Ok(Self {
            index: RwLock::new(index),
            store: Some(store),
        })
    }

    /// Return the receipt already bound to `payment_id`, if any.
    pub fn get(&self, payment_id: &str) -> Option<PaymentReceipt> {
        self.index.read().get(payment_id).cloned()
    }

    /// Bind `payment_id` to `receipt`. Idempotent: recording the same
    /// identifier twice keeps the *first* receipt (the settled one) and
    /// returns it, so a racing double-settle can't overwrite the record.
    /// Returns the receipt now held for the identifier.
    pub fn record(&self, payment_id: &str, receipt: PaymentReceipt) -> Result<PaymentReceipt> {
        if !is_payment_id(payment_id) {
            return Err(PaymentError::CredentialError(format!(
                "malformed payment identifier: {payment_id}"
            )));
        }
        {
            let idx = self.index.read();
            if let Some(existing) = idx.get(payment_id) {
                return Ok(existing.clone());
            }
        }
        let mut idx = self.index.write();
        // Re-check under the write lock in case a concurrent writer won.
        if let Some(existing) = idx.get(payment_id) {
            return Ok(existing.clone());
        }
        if let Some(store) = &self.store {
            store.put(payment_id, &receipt)?;
        }
        idx.insert(payment_id.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Number of identifiers recorded.
    pub fn len(&self) -> usize {
        self.index.read().len()
    }

    /// Whether the ledger holds no identifiers.
    pub fn is_empty(&self) -> bool {
        self.index.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn requirement() -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            "tenzro-hybrid",
            "eip155:1337",
            "1000",
            "0xrecipient",
            "USDC",
            "https://api.tenzro.network/paid/resource",
            "Test resource",
            "application/json",
            300,
        )
    }

    fn receipt(id: &str, amount: u128) -> PaymentReceipt {
        PaymentReceipt {
            receipt_id: id.to_string(),
            protocol: "x402".to_string(),
            challenge_id: "ch".to_string(),
            credential_id: "cr".to_string(),
            amount,
            asset: "USDC".to_string(),
            settlement_tx: None,
            chain: "tenzro-evm".to_string(),
            settled_at: Utc::now(),
            principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                "did:tenzro:human:bob".to_string(),
                tenzro_types::primitives::BlockHeight::new(0),
            ),
            extra: HashMap::new(),
        }
    }

    #[test]
    fn offer_commitment_is_deterministic() {
        let r = requirement();
        assert_eq!(compute_offer_commitment(&r), compute_offer_commitment(&r));
    }

    #[test]
    fn offer_commitment_moves_when_price_or_payto_changes() {
        let base = compute_offer_commitment(&requirement());

        let mut r = requirement();
        r.max_amount_required = "1001".to_string();
        assert_ne!(compute_offer_commitment(&r), base);

        let mut r = requirement();
        r.pay_to = "0xother".to_string();
        assert_ne!(compute_offer_commitment(&r), base);

        // Description is advisory — must NOT move the commitment.
        let mut r = requirement();
        r.description = "totally different copy".to_string();
        assert_eq!(compute_offer_commitment(&r), base);
    }

    #[test]
    fn sign_and_verify_round_trips() {
        let kp = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519).unwrap();
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let r = requirement();
        let signed = SignedOffer::sign(&r, &signer).unwrap();
        assert!(signed.verify(&r).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_price() {
        let kp = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519).unwrap();
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let r = requirement();
        let signed = SignedOffer::sign(&r, &signer).unwrap();

        let mut tampered = r.clone();
        tampered.max_amount_required = "1".to_string();
        assert!(matches!(
            signed.verify(&tampered).unwrap_err(),
            PaymentError::VerificationFailed(_)
        ));
    }

    #[test]
    fn attach_and_extract_round_trips_and_preserves_scheme_extra() {
        let kp = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519).unwrap();
        let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(kp).unwrap();
        let mut r = requirement().with_extra(serde_json::json!({ "permit2Nonce": "0x7" }));
        let signed = SignedOffer::sign(&r, &signer).unwrap();
        signed.attach_to(&mut r);

        // Scheme-specific extra survives the attach.
        assert_eq!(r.extra["permit2Nonce"], serde_json::json!("0x7"));
        let extracted = SignedOffer::extract_from(&r).unwrap();
        assert_eq!(extracted, signed);
        assert!(extracted.verify(&r).is_ok());
    }

    #[test]
    fn payment_id_is_deterministic_and_payer_scoped() {
        let c = compute_offer_commitment(&requirement());
        let a = derive_payment_id(&c, "did:tenzro:human:alice");
        let a2 = derive_payment_id(&c, "did:tenzro:human:alice");
        let b = derive_payment_id(&c, "did:tenzro:human:bob");
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(is_payment_id(&a));
    }

    #[test]
    fn is_payment_id_rejects_malformed() {
        assert!(!is_payment_id("pay_short"));
        assert!(!is_payment_id("nope_0000000000000000000000000000000000000000000000000000000000000000"));
        assert!(!is_payment_id(&format!("pay_{}", "z".repeat(64))));
    }

    #[test]
    fn ledger_returns_prior_receipt_on_replay() {
        let c = compute_offer_commitment(&requirement());
        let pid = derive_payment_id(&c, "did:tenzro:human:alice");
        let ledger = IdempotencyLedger::new();
        assert!(ledger.get(&pid).is_none());

        let first = ledger.record(&pid, receipt("r1", 1000)).unwrap();
        assert_eq!(first.receipt_id, "r1");

        // A racing second settle records a *different* receipt id but must get
        // the first one back — no double charge.
        let second = ledger.record(&pid, receipt("r2", 1000)).unwrap();
        assert_eq!(second.receipt_id, "r1");
        assert_eq!(ledger.get(&pid).unwrap().receipt_id, "r1");
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_malformed_id() {
        let ledger = IdempotencyLedger::new();
        assert!(matches!(
            ledger.record("bogus", receipt("r", 1)).unwrap_err(),
            PaymentError::CredentialError(_)
        ));
    }

    #[derive(Debug, Default)]
    struct MemStore {
        rows: RwLock<HashMap<String, PaymentReceipt>>,
    }
    impl IdempotencyStore for MemStore {
        fn put(&self, payment_id: &str, receipt: &PaymentReceipt) -> Result<()> {
            self.rows.write().insert(payment_id.to_string(), receipt.clone());
            Ok(())
        }
        fn load_all(&self) -> Result<Vec<(String, PaymentReceipt)>> {
            Ok(self.rows.read().iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        }
    }

    #[test]
    fn store_backed_ledger_writes_through_and_hydrates() {
        let c = compute_offer_commitment(&requirement());
        let pid = derive_payment_id(&c, "did:tenzro:human:alice");
        let store = Arc::new(MemStore::default());
        {
            let ledger = IdempotencyLedger::with_store(store.clone()).unwrap();
            ledger.record(&pid, receipt("r1", 1000)).unwrap();
            assert_eq!(store.rows.read().len(), 1);
        }
        let ledger2 = IdempotencyLedger::with_store(store.clone()).unwrap();
        assert_eq!(ledger2.len(), 1);
        assert_eq!(ledger2.get(&pid).unwrap().receipt_id, "r1");
    }
}
