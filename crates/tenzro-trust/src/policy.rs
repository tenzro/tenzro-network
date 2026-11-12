//! Operator policies and provable violations.
//!
//! An operator publishes what it serves and what it refuses as a document
//! signed by its hardware key. The policy also names the keys the operator
//! signs inference receipts with, which binds those keys to the operator's
//! DID. Nobody but the operator decides what the policy says; the network
//! only holds operators to it.
//!
//! Two clauses are checkable from a receipt alone, and a receipt that
//! contradicts one of them is proof of a violation anyone can recompute:
//!
//! - `serves.models`: the receipt names a model the policy does not list.
//! - `jurisdictions`: the receipt's jurisdiction claim is outside the ones
//!   the policy declares.
//!
//! The other clauses (refused content categories, data retention) are
//! declarations a relying party can filter on; judging a breach of them needs
//! people, not a signature check, so they are never slashed automatically.
//!
//! A policy is in force from its `validFrom` until the `validFrom` of the
//! operator's next sequence number, and never after its `validUntil`.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tenzro_types::model::JurisdictionReceipt;

use crate::credential::Credential;
use crate::requirements::{TrustRequirements, Verdict};
use crate::{Result, TrustError, has_type, invalid, str_field, time_field, verify_signed_by};

pub const POLICY_TYPE: &str = "TenzroOperatorPolicy";
pub const VIOLATION_TYPE: &str = "TenzroPolicyViolation";
/// Longest validity of one policy document.
pub const MAX_POLICY_DAYS: i64 = 366;

/// The algorithm of every receipt key: a node's hardware identity key, P-256
/// with an ML-DSA-65 leg when its hardware holds one.
pub const RECEIPT_KEY_ALGORITHM: &str = "p256";

/// A key the operator's nodes sign inference receipts under: a node's
/// hardware identity key, which certifies the node's session keys.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReceiptKey {
    /// [`RECEIPT_KEY_ALGORITHM`].
    pub algorithm: String,
    /// Hex P-256 point, `x || y` (64 bytes).
    pub public_key: String,
    /// Hex ML-DSA-65 verifying key, when the identity has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// Hex of the bincode-encoded composite signature by this key over
    /// [`receipt_key_binding`] for the operator, under
    /// [`SignatureContext::ReceiptKeyBinding`], so only the holder of a key
    /// can bind it to an operator.
    ///
    /// [`SignatureContext::ReceiptKeyBinding`]: tenzro_crypto::composite::SignatureContext::ReceiptKeyBinding
    pub binding: String,
}

impl ReceiptKey {
    /// Bind `identity` to `operator` with the identity's own signature.
    pub fn bind(
        identity: &dyn tenzro_crypto::composite::HybridSigner,
        operator: &str,
    ) -> tenzro_crypto::Result<Self> {
        use tenzro_crypto::composite::SignatureContext;
        let key = identity.public_key();
        let signature = identity.sign(
            SignatureContext::ReceiptKeyBinding,
            &receipt_key_binding(operator),
        )?;
        let binding = bincode::serialize(&signature)
            .map_err(|e| tenzro_crypto::CryptoError::InvalidSignature(e.to_string()))?;
        Ok(Self {
            algorithm: RECEIPT_KEY_ALGORITHM.to_string(),
            public_key: hex::encode(&key.p256),
            pq_public_key: key.pq.as_ref().map(hex::encode),
            binding: hex::encode(binding),
        })
    }

    /// The composite key this entry names, when it is well formed.
    pub fn composite_key(&self) -> Option<tenzro_crypto::composite::CompositePublicKey> {
        if self.algorithm != RECEIPT_KEY_ALGORITHM {
            return None;
        }
        let p256 = hex::decode(&self.public_key).ok()?;
        let pq = match &self.pq_public_key {
            Some(pq) => Some(hex::decode(pq).ok()?),
            None => None,
        };
        tenzro_crypto::composite::CompositePublicKey::new(p256, pq).ok()
    }

    /// Whether the key signed a binding to `operator`.
    fn binds(&self, operator: &str) -> bool {
        use tenzro_crypto::composite::{
            CompositeSignature, PqPolicy, SignatureContext, verify_composite,
        };
        let (Some(key), Ok(bytes)) = (self.composite_key(), hex::decode(&self.binding)) else {
            return false;
        };
        let Ok(signature) = bincode::deserialize::<CompositeSignature>(&bytes) else {
            return false;
        };
        verify_composite(
            &key,
            SignatureContext::ReceiptKeyBinding,
            &receipt_key_binding(operator),
            &signature,
            PqPolicy::WhenPresent,
        )
        .is_ok()
    }
}

/// The message a receipt key signs to bind itself to `operator`.
pub fn receipt_key_binding(operator: &str) -> Vec<u8> {
    operator.as_bytes().to_vec()
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Serves {
    /// The model ids this operator serves; `None` means it does not restrict
    /// itself to a list.
    #[serde(default)]
    pub models: Option<BTreeSet<String>>,
    /// Credentials every model it serves holds, from issuers it names.
    #[serde(default)]
    pub trust: TrustRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Refuses {
    /// Content categories the operator declares it refuses, in its own terms.
    #[serde(default)]
    pub categories: Vec<String>,
    /// Refuse model files in formats that execute code when loaded.
    #[serde(default)]
    pub unsafe_formats: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DataPractice {
    #[serde(default)]
    pub retention_days: Option<u32>,
    #[serde(default)]
    pub trains_on_inputs: bool,
}

/// An operator's signed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPolicy {
    pub digest: String,
    pub operator: String,
    pub sequence: u64,
    pub valid_from: chrono::DateTime<chrono::Utc>,
    pub valid_until: chrono::DateTime<chrono::Utc>,
    pub proof_created: chrono::DateTime<chrono::Utc>,
    pub receipt_keys: BTreeSet<ReceiptKey>,
    pub serves: Serves,
    /// Country codes or blocs; `None` means no territorial restriction.
    pub jurisdictions: Option<BTreeSet<String>>,
    pub refuses: Refuses,
    pub data: DataPractice,
    pub document: Value,
}

/// The policy body before signing.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PolicyTerms {
    #[serde(default)]
    pub receipt_keys: Vec<ReceiptKey>,
    #[serde(default)]
    pub serves: Serves,
    #[serde(default)]
    pub jurisdictions: Option<BTreeSet<String>>,
    #[serde(default)]
    pub refuses: Refuses,
    #[serde(default)]
    pub data: DataPractice,
}

impl OperatorPolicy {
    pub fn unsigned(
        operator: &str,
        sequence: u64,
        valid_from: chrono::DateTime<chrono::Utc>,
        valid_until: chrono::DateTime<chrono::Utc>,
        terms: &PolicyTerms,
    ) -> Value {
        let fmt =
            |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        json!({
            "type": [POLICY_TYPE],
            "operator": operator,
            "sequence": sequence,
            "validFrom": fmt(valid_from),
            "validUntil": fmt(valid_until),
            "receiptKeys": terms.receipt_keys,
            "serves": terms.serves,
            "jurisdictions": terms.jurisdictions,
            "refuses": terms.refuses,
            "data": terms.data,
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, POLICY_TYPE) {
            return Err(invalid(format!("not a {POLICY_TYPE}")));
        }
        let operator = str_field(document, "/operator")?.to_string();
        let proof = verify_signed_by(document, &operator)?;
        let sequence = document
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("sequence must be an unsigned integer"))?;
        let valid_from = time_field(document, "/validFrom")?;
        let valid_until = time_field(document, "/validUntil")?;
        if valid_until <= valid_from
            || valid_until - valid_from > chrono::Duration::days(MAX_POLICY_DAYS)
        {
            return Err(invalid(format!(
                "a policy is valid for between 1 second and {MAX_POLICY_DAYS} days"
            )));
        }
        if valid_from < proof.created {
            return Err(invalid("a policy cannot take effect before it was signed"));
        }
        let field = |name: &str| document.get(name).cloned().unwrap_or(Value::Null);
        let receipt_keys: BTreeSet<ReceiptKey> = serde_json::from_value(field("receiptKeys"))
            .map_err(|e| invalid(format!("receiptKeys: {e}")))?;
        for k in &receipt_keys {
            let lowercase = k.public_key == k.public_key.to_lowercase()
                && k.pq_public_key
                    .as_ref()
                    .is_none_or(|pq| *pq == pq.to_lowercase());
            if k.composite_key().is_none() || !lowercase {
                return Err(invalid(
                    "a receipt key is a lowercase hex p256 key (x || y, 64 bytes), with its ML-DSA-65 key when it has one",
                ));
            }
            if !k.binds(&operator) {
                return Err(invalid(format!(
                    "receipt key {} is not bound to {operator} by its own signature",
                    k.public_key
                )));
            }
        }
        let serves: Serves =
            serde_json::from_value(field("serves")).map_err(|e| invalid(format!("serves: {e}")))?;
        serves.trust.validate()?;
        let jurisdictions: Option<BTreeSet<String>> =
            serde_json::from_value(field("jurisdictions"))
                .map_err(|e| invalid(format!("jurisdictions: {e}")))?;
        if let Some(j) = &jurisdictions
            && (j.is_empty()
                || j.iter().any(|c| {
                    c.len() < 2 || c.len() > 8 || !c.bytes().all(|b| b.is_ascii_uppercase())
                }))
        {
            return Err(invalid(
                "jurisdictions are upper-case country codes or bloc names",
            ));
        }
        let refuses: Refuses = serde_json::from_value(field("refuses"))
            .map_err(|e| invalid(format!("refuses: {e}")))?;
        let data: DataPractice =
            serde_json::from_value(field("data")).map_err(|e| invalid(format!("data: {e}")))?;
        Ok(OperatorPolicy {
            digest: crate::record_digest(document),
            operator,
            sequence,
            valid_from,
            valid_until,
            proof_created: proof.created,
            receipt_keys,
            serves,
            jurisdictions,
            refuses,
            data,
            document: document.clone(),
        })
    }

    /// Whether the operator's policy lets it serve `model_id`, given the
    /// credentials currently valid for that model's manifest.
    pub fn admit_model<'a>(
        &self,
        model_id: &str,
        model_subject: Option<&crate::credential::Subject>,
        valid: impl IntoIterator<Item = &'a Credential>,
    ) -> std::result::Result<(), PolicyRefusal> {
        if let Some(models) = &self.serves.models
            && !models.contains(model_id)
        {
            return Err(PolicyRefusal::NotServed(model_id.to_string()));
        }
        if self.serves.trust.require.is_empty() {
            return Ok(());
        }
        let Some(subject) = model_subject else {
            return Err(PolicyRefusal::NoManifest(model_id.to_string()));
        };
        let verdict: Verdict = self.serves.trust.evaluate(subject, valid);
        if verdict.passed {
            Ok(())
        } else {
            Err(PolicyRefusal::MissingCredentials(verdict.unmet))
        }
    }

    /// Whether the policy names the identity whose P-256 point is
    /// `public_key` as one of its receipt keys.
    pub fn signs_with(&self, public_key: &[u8]) -> bool {
        let hex_key = hex::encode(public_key);
        self.receipt_keys.iter().any(|k| k.public_key == hex_key)
    }
}

/// Why an operator's own policy refuses a model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyRefusal {
    #[error("the operator's policy does not serve {0}")]
    NotServed(String),
    #[error("the operator's policy requires credentials for {0}, which has no manifest")]
    NoManifest(String),
    #[error("the operator's policy requires credentials the model does not hold: {0:?}")]
    MissingCredentials(Vec<String>),
}

/// Which clause a receipt contradicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Clause {
    #[serde(rename = "serves.models")]
    ServesModels,
    #[serde(rename = "jurisdictions")]
    Jurisdictions,
}

/// A violation that verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenViolation {
    /// Hex SHA-256 over the policy digest and the receipt preimage: one
    /// receipt proves one violation of one policy, however it is packaged.
    pub id: String,
    pub operator: String,
    pub policy: String,
    pub policy_sequence: u64,
    pub clause: Clause,
    pub detail: String,
    pub receipt_signed_at_ms: i64,
}

/// The evidence document a challenger submits.
pub fn violation_evidence(policy: &Value, receipt: &JurisdictionReceipt, clause: Clause) -> Value {
    json!({
        "type": VIOLATION_TYPE,
        "policy": policy,
        "receipt": { "kind": "jurisdiction", "body": receipt },
        "clause": clause,
    })
}

/// The receipt's batch signature covers its canonical preimage and was made
/// by the key it names (`signer_public_key`).
fn verify_receipt(r: &JurisdictionReceipt) -> bool {
    let Ok(at_ms) = u64::try_from(r.signed_at.as_millis()) else {
        return false;
    };
    let (Some(raw), Ok(identity)) = (
        r.batched.as_deref(),
        tenzro_crypto::composite::CompositePublicKey::new(
            r.signer_public_key.clone(),
            r.signer_pq_key.clone(),
        ),
    ) else {
        return false;
    };
    let Ok(sig) = serde_json::from_slice::<tenzro_crypto::batch::BatchedSignature>(raw) else {
        return false;
    };
    tenzro_crypto::batch::RecordSignature::batched(sig)
        .verify_record_at(&identity, &r.canonical_preimage(), at_ms)
        .is_ok()
}

/// Verify violation `evidence`. `history` is every policy the operator has
/// published (any order); it decides which policy was in force when the
/// receipt was signed, so a policy the operator later replaced still binds
/// the receipts signed under it, and a newer one cannot excuse them.
pub fn verify_violation(evidence: &Value, history: &[OperatorPolicy]) -> Result<ProvenViolation> {
    if evidence.get("type").and_then(Value::as_str) != Some(VIOLATION_TYPE) {
        return Err(invalid(format!("not a {VIOLATION_TYPE}")));
    }
    let policy =
        OperatorPolicy::parse(evidence.get("policy").ok_or_else(|| invalid("no policy"))?)?;
    if evidence.pointer("/receipt/kind").and_then(Value::as_str) != Some("jurisdiction") {
        return Err(invalid("the receipt kind must be jurisdiction"));
    }
    let receipt: JurisdictionReceipt = serde_json::from_value(
        evidence
            .pointer("/receipt/body")
            .cloned()
            .unwrap_or(Value::Null),
    )
    .map_err(|e| invalid(format!("receipt: {e}")))?;
    let clause: Clause =
        serde_json::from_value(evidence.get("clause").cloned().unwrap_or(Value::Null))
            .map_err(|e| invalid(format!("clause: {e}")))?;

    if !verify_receipt(&receipt) {
        return Err(invalid("the receipt signature does not verify"));
    }
    let named = policy
        .receipt_keys
        .iter()
        .filter_map(ReceiptKey::composite_key)
        .any(|k| k.p256 == receipt.signer_public_key && k.pq == receipt.signer_pq_key);
    if !named {
        return Err(invalid(
            "the receipt was not signed by a key the policy names",
        ));
    }
    let signed_ms = receipt.signed_at.as_millis();
    let signed_at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(signed_ms)
        .ok_or_else(|| invalid("receipt time is out of range"))?;
    if signed_at < policy.valid_from || signed_at > policy.valid_until {
        return Err(TrustError::Stale(
            "the receipt was not signed while this policy was valid".into(),
        ));
    }
    let superseded = history.iter().any(|p| {
        p.operator == policy.operator && p.sequence > policy.sequence && p.valid_from <= signed_at
    });
    if superseded {
        return Err(TrustError::Stale(
            "a later policy was in force when the receipt was signed".into(),
        ));
    }

    let detail = match clause {
        Clause::ServesModels => {
            let models = policy
                .serves
                .models
                .as_ref()
                .ok_or_else(|| invalid("the policy does not restrict the models it serves"))?;
            if models.contains(&receipt.model_id) {
                return Err(invalid(format!(
                    "{} is a model the policy serves",
                    receipt.model_id
                )));
            }
            format!("served {} which the policy does not list", receipt.model_id)
        }
        Clause::Jurisdictions => {
            let allowed = policy
                .jurisdictions
                .as_ref()
                .ok_or_else(|| invalid("the policy declares no jurisdictions"))?;
            let j = &receipt.jurisdiction;
            if allowed.contains(&j.country) || j.blocs.iter().any(|b| allowed.contains(b)) {
                return Err(invalid(format!(
                    "{} is inside the declared jurisdictions",
                    j.country
                )));
            }
            format!("served from {} outside {:?}", j.country, allowed)
        }
    };
    let id = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/trust/violation");
        h.update(policy.digest.as_bytes());
        h.update(receipt.canonical_preimage());
        hex::encode(h.finalize())
    };
    Ok(ProvenViolation {
        id,
        operator: policy.operator.clone(),
        policy: policy.digest.clone(),
        policy_sequence: policy.sequence,
        clause,
        detail,
        receipt_signed_at_ms: signed_ms,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::credential::tests::t;
    use crate::proof::testkit::TestKey;
    use tenzro_crypto::composite::HybridSigner as _;
    use tenzro_types::model::JurisdictionClaim;
    use tenzro_types::primitives::{Address, Hash, Timestamp};

    /// A serving node's hardware identity stand-in and its record signer.
    pub(crate) struct ReceiptSigner(
        pub std::sync::Arc<tenzro_crypto::composite::testing::TestHybridSigner>,
        tenzro_crypto::batch::ImmediateRecordSigner,
    );

    impl ReceiptSigner {
        pub(crate) fn new() -> Self {
            let id =
                std::sync::Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::random());
            let session = tenzro_crypto::batch::ImmediateRecordSigner::new(id.clone());
            Self(id, session)
        }
        pub(crate) fn key_for(&self, operator: &str) -> ReceiptKey {
            ReceiptKey::bind(self.0.as_ref(), operator).unwrap()
        }
        pub(crate) fn receipt(
            &self,
            model_id: &str,
            country: &str,
            at: &str,
        ) -> JurisdictionReceipt {
            let mut r = JurisdictionReceipt {
                request_hash: Hash([1u8; 32]),
                response_hash: Hash([2u8; 32]),
                model_id: model_id.into(),
                provider: Address([3u8; 32]),
                jurisdiction: JurisdictionClaim {
                    country: country.into(),
                    blocs: vec![],
                    attestation_hash: None,
                    declared_at: Timestamp::new(0),
                },
                signed_at: Timestamp::new(t(at).timestamp_millis()),
                signer_public_key: self.0.public_key().p256.clone(),
                signer_pq_key: self.0.public_key().pq.clone(),
                batched: None,
            };
            let signed =
                tenzro_crypto::batch::RecordSigner::sign_record(&self.1, &r.canonical_preimage())
                    .unwrap();
            r.batched = Some(serde_json::to_vec(&signed.batched).unwrap());
            r
        }
    }

    pub(crate) fn policy_doc(
        op: &TestKey,
        seq: u64,
        from: &str,
        keys: &[&ReceiptSigner],
        models: &[&str],
        jur: Option<&[&str]>,
    ) -> Value {
        let terms = PolicyTerms {
            receipt_keys: keys.iter().map(|k| k.key_for(&op.did())).collect(),
            serves: Serves {
                models: Some(models.iter().map(|m| m.to_string()).collect()),
                trust: TrustRequirements::default(),
            },
            jurisdictions: jur.map(|j| j.iter().map(|c| c.to_string()).collect()),
            refuses: Refuses::default(),
            data: DataPractice::default(),
        };
        op.sign_at(
            OperatorPolicy::unsigned(
                &op.did(),
                seq,
                t(from),
                t(from) + chrono::Duration::days(300),
                &terms,
            ),
            from,
        )
    }

    #[test]
    fn serving_an_unlisted_model_is_a_proven_violation() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let doc = policy_doc(
            &op,
            1,
            "2026-01-01T00:00:00Z",
            &[&rs],
            &["qwen3.5-0.8b"],
            None,
        );
        let policy = OperatorPolicy::parse(&doc).unwrap();
        let bad = rs.receipt("uncensored-70b", "DE", "2026-02-01T00:00:00Z");
        let v = verify_violation(
            &violation_evidence(&doc, &bad, Clause::ServesModels),
            std::slice::from_ref(&policy),
        )
        .unwrap();
        assert_eq!(v.operator, op.did());

        let fine = rs.receipt("qwen3.5-0.8b", "DE", "2026-02-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&doc, &fine, Clause::ServesModels),
                &[policy]
            )
            .is_err()
        );
    }

    #[test]
    fn serving_outside_the_declared_jurisdictions_is_a_proven_violation() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let doc = policy_doc(
            &op,
            1,
            "2026-01-01T00:00:00Z",
            &[&rs],
            &["m"],
            Some(&["EU", "CH"]),
        );
        let policy = OperatorPolicy::parse(&doc).unwrap();
        let out = rs.receipt("m", "US", "2026-02-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&doc, &out, Clause::Jurisdictions),
                std::slice::from_ref(&policy)
            )
            .is_ok()
        );
        let inside = rs.receipt("m", "CH", "2026-02-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&doc, &inside, Clause::Jurisdictions),
                &[policy]
            )
            .is_err()
        );
    }

    #[test]
    fn a_receipt_from_a_key_the_policy_does_not_name_proves_nothing() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let framer = ReceiptSigner::new();
        let doc = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        let policy = OperatorPolicy::parse(&doc).unwrap();
        let framed = framer.receipt("forbidden", "DE", "2026-02-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&doc, &framed, Clause::ServesModels),
                &[policy]
            )
            .is_err()
        );
    }

    #[test]
    fn a_receipt_key_cannot_be_claimed_without_its_own_signature() {
        let op = TestKey::new(1);
        let victim = TestKey::new(2);
        let rs = ReceiptSigner::new();
        // The key signed a binding to the victim, not to this operator.
        let terms = PolicyTerms {
            receipt_keys: vec![rs.key_for(&victim.did())],
            ..PolicyTerms::default()
        };
        let doc = op.sign_at(
            OperatorPolicy::unsigned(
                &op.did(),
                1,
                t("2026-01-01T00:00:00Z"),
                t("2026-06-01T00:00:00Z"),
                &terms,
            ),
            "2026-01-01T00:00:00Z",
        );
        assert!(OperatorPolicy::parse(&doc).is_err());
    }

    #[test]
    fn a_tampered_receipt_proves_nothing() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let doc = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        let policy = OperatorPolicy::parse(&doc).unwrap();
        let mut r = rs.receipt("m", "DE", "2026-02-01T00:00:00Z");
        r.model_id = "forbidden".into();
        assert!(
            verify_violation(
                &violation_evidence(&doc, &r, Clause::ServesModels),
                &[policy]
            )
            .is_err()
        );
    }

    #[test]
    fn a_session_key_the_named_key_did_not_certify_proves_nothing() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let framer = ReceiptSigner::new();
        let doc = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        let policy = OperatorPolicy::parse(&doc).unwrap();
        // The framer's own session signs a receipt that names the operator's key.
        let mut r = framer.receipt("forbidden", "DE", "2026-02-01T00:00:00Z");
        r.signer_public_key = rs.0.public_key().p256.clone();
        r.signer_pq_key = rs.0.public_key().pq.clone();
        assert!(
            verify_violation(
                &violation_evidence(&doc, &r, Clause::ServesModels),
                &[policy]
            )
            .is_err()
        );
    }

    #[test]
    fn a_later_policy_excuses_only_later_receipts() {
        let op = TestKey::new(1);
        let rs = ReceiptSigner::new();
        let v1 = policy_doc(&op, 1, "2026-01-01T00:00:00Z", &[&rs], &["m"], None);
        let v2 = policy_doc(&op, 2, "2026-03-01T00:00:00Z", &[&rs], &["m", "n"], None);
        let hist = vec![
            OperatorPolicy::parse(&v1).unwrap(),
            OperatorPolicy::parse(&v2).unwrap(),
        ];
        let before = rs.receipt("n", "DE", "2026-02-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&v1, &before, Clause::ServesModels),
                &hist
            )
            .is_ok()
        );
        let after = rs.receipt("n", "DE", "2026-04-01T00:00:00Z");
        assert!(
            verify_violation(
                &violation_evidence(&v1, &after, Clause::ServesModels),
                &hist
            )
            .is_err()
        );
    }

    #[test]
    fn a_policy_cannot_be_back_dated_before_its_signature() {
        let op = TestKey::new(1);
        let terms = PolicyTerms::default();
        let doc = op.sign_at(
            OperatorPolicy::unsigned(
                &op.did(),
                1,
                t("2026-01-01T00:00:00Z"),
                t("2026-06-01T00:00:00Z"),
                &terms,
            ),
            "2026-02-01T00:00:00Z",
        );
        assert!(OperatorPolicy::parse(&doc).is_err());
    }

    #[test]
    fn admission_refuses_models_the_policy_does_not_serve() {
        let op = TestKey::new(1);
        let policy = OperatorPolicy::parse(&policy_doc(
            &op,
            1,
            "2026-01-01T00:00:00Z",
            &[],
            &["m"],
            None,
        ))
        .unwrap();
        assert!(policy.admit_model("m", None, []).is_ok());
        assert_eq!(
            policy.admit_model("x", None, []),
            Err(PolicyRefusal::NotServed("x".into()))
        );
    }
}
