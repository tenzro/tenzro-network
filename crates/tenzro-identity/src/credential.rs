//! Verifiable credentials for the Tenzro Decentralized Identity Protocol
//!
//! Implements W3C Verifiable Credentials compatible credential types
//! that can be issued to identities and inherited by machine identities
//! from their human controllers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Credential types supported by the Tenzro Decentralized Identity Protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum TenzroCredentialType {
    /// KYC attestation credential
    KycAttestation,
    /// Age verification credential
    AgeVerification,
    /// Residency proof credential
    ResidencyProof,
    /// Accredited investor status
    AccreditedInvestor,
    /// Institutional membership credential
    InstitutionalMember,
    /// Payment protocol authorization
    PaymentAuthorization,
    /// Model provider credential
    ModelProvider,
    /// TEE operator credential
    TeeOperator,
    /// Custom credential type
    Custom(String),
}

impl TenzroCredentialType {
    /// Returns the type name as a string
    pub fn type_name(&self) -> &str {
        match self {
            Self::KycAttestation => "KycAttestation",
            Self::AgeVerification => "AgeVerification",
            Self::ResidencyProof => "ResidencyProof",
            Self::AccreditedInvestor => "AccreditedInvestor",
            Self::InstitutionalMember => "InstitutionalMember",
            Self::PaymentAuthorization => "PaymentAuthorization",
            Self::ModelProvider => "ModelProvider",
            Self::TeeOperator => "TeeOperator",
            Self::Custom(name) => name,
        }
    }
}

/// Cryptographic proof attached to a verifiable credential
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialProof {
    /// Proof type (e.g., "Ed25519Signature2020", "EcdsaSecp256k1Signature2019")
    pub proof_type: String,
    /// When the proof was created
    pub created: DateTime<Utc>,
    /// DID of the proof creator
    pub verification_method: String,
    /// Purpose of the proof (e.g., "assertionMethod", "authentication")
    pub proof_purpose: String,
    /// The proof value (signature bytes)
    pub proof_value: Vec<u8>,
}

impl CredentialProof {
    /// Creates a new credential proof
    pub fn new(
        proof_type: impl Into<String>,
        verification_method: impl Into<String>,
        proof_value: Vec<u8>,
    ) -> Self {
        Self {
            proof_type: proof_type.into(),
            created: Utc::now(),
            verification_method: verification_method.into(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value,
        }
    }

    /// Verifies the proof signature against a message and issuer public key
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed (typically the credential bytes)
    /// * `issuer_pubkey` - The issuer's public key for verification (raw
    ///   classical key bytes for Ed25519/Secp256k1; ML-DSA-65 verifying key
    ///   bytes for `MlDsa65Signature2026`).
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if signature is valid, `Ok(false)` if invalid,
    /// or an error if the proof type is unsupported.
    ///
    /// # Hybrid credentials
    ///
    /// Hybrid credentials use [`CredentialProof::verify_hybrid`] instead —
    /// the `proof_value` field of a hybrid credential is the
    /// bincode-serialized [`tenzro_crypto::composite::CompositeSignature`]
    /// rather than a raw classical signature, so the legacy `verify()` path
    /// would mis-interpret the bytes. Classical-only Ed25519 / Secp256k1
    /// credentials still verify here unchanged.
    pub fn verify(&self, message: &[u8], issuer_pubkey: &[u8]) -> crate::error::Result<bool> {
        use tenzro_crypto::{KeyType, PublicKey, Signature};

        match self.proof_type.as_str() {
            "Ed25519Signature2020" | "Ed25519" => {
                // Verify Ed25519 signature
                if issuer_pubkey.len() != 32 {
                    return Err(crate::error::IdentityError::VerificationFailed(format!(
                        "Invalid Ed25519 public key length: expected 32, got {}",
                        issuer_pubkey.len()
                    )));
                }

                if self.proof_value.len() != 64 {
                    return Err(crate::error::IdentityError::VerificationFailed(format!(
                        "Invalid Ed25519 signature length: expected 64, got {}",
                        self.proof_value.len()
                    )));
                }

                // Construct PublicKey and Signature objects
                let pubkey = PublicKey::new(KeyType::Ed25519, issuer_pubkey.to_vec());
                let signature = Signature::new(KeyType::Ed25519, self.proof_value.clone());

                // Use tenzro_crypto verify function
                match tenzro_crypto::signatures::verify(&pubkey, message, &signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            "EcdsaSecp256k1Signature2019" | "Secp256k1" => {
                // Secp256k1 verification
                let pubkey = PublicKey::new(KeyType::Secp256k1, issuer_pubkey.to_vec());
                let signature = Signature::new(KeyType::Secp256k1, self.proof_value.clone());

                match tenzro_crypto::signatures::verify(&pubkey, message, &signature) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            "MlDsa65Signature2026" | "ML-DSA-65" => {
                // Pure post-quantum signature. Forward compat for the post-2030
                // pure-PQ era; today, hybrid credentials use the hybrid path.
                use tenzro_crypto::pq::{ML_DSA_65_VK_LEN, ml_dsa_verify};
                if issuer_pubkey.len() != ML_DSA_65_VK_LEN {
                    return Err(crate::error::IdentityError::VerificationFailed(format!(
                        "Invalid ML-DSA-65 verifying key length: expected {}, got {}",
                        ML_DSA_65_VK_LEN,
                        issuer_pubkey.len()
                    )));
                }
                match ml_dsa_verify(issuer_pubkey, message, &self.proof_value) {
                    Ok(()) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
            other => Err(crate::error::IdentityError::VerificationFailed(format!(
                "Unsupported proof type: {}",
                other
            ))),
        }
    }

    /// Verify a hybrid credential proof.
    ///
    /// Used when `proof_type == "HybridEd25519MlDsa65Signature2026"` and
    /// `proof_value` is the `bincode`-serialized
    /// [`tenzro_crypto::composite::CompositeSignature`] of `message`. Both
    /// the classical and post-quantum legs must validate against the
    /// supplied composite public key — there is no downgrade path.
    ///
    /// Returns `Ok(true)` if the credential is hybrid-typed and both legs
    /// verify, `Ok(false)` if the signature does not validate, or an error
    /// if the proof type is not the hybrid variant.
    pub fn verify_hybrid(
        &self,
        message: &[u8],
        issuer_pubkey: &tenzro_crypto::composite::CompositePublicKey,
    ) -> crate::error::Result<bool> {
        use tenzro_crypto::composite::{
            CompositeSignature, HybridVerifier, StandardHybridVerifier,
        };

        if self.proof_type != "HybridEd25519MlDsa65Signature2026" {
            return Err(crate::error::IdentityError::VerificationFailed(format!(
                "expected HybridEd25519MlDsa65Signature2026 proof type, got {}",
                self.proof_type
            )));
        }

        let sig: CompositeSignature = match bincode::deserialize(&self.proof_value) {
            Ok(s) => s,
            Err(e) => {
                return Err(crate::error::IdentityError::VerificationFailed(format!(
                    "could not decode hybrid signature: {}",
                    e
                )));
            }
        };

        let verifier = StandardHybridVerifier::new(issuer_pubkey.clone());
        match verifier.verify(message, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}

/// Builds a [`CredentialProof`] using a hybrid (Ed25519 + ML-DSA-65) signer.
///
/// `verification_method` is the W3C DID URL identifying the issuer key (e.g.
/// `did:tenzro:human:alice#pq-key-1`). The `proof_type` is set to
/// `"HybridEd25519MlDsa65Signature2026"`, the `proof_value` is the
/// `bincode`-serialized [`tenzro_crypto::composite::CompositeSignature`]
/// over `message`, and both legs of the resulting signature are required
/// at verification time.
pub fn sign_credential_hybrid(
    signer: &dyn tenzro_crypto::composite::HybridSigner,
    message: &[u8],
    verification_method: impl Into<String>,
) -> crate::error::Result<CredentialProof> {
    let composite = signer.sign(message).map_err(|e| {
        crate::error::IdentityError::CryptoError(format!("hybrid credential sign failed: {}", e))
    })?;
    let bytes = bincode::serialize(&composite).map_err(|e| {
        crate::error::IdentityError::SerializationError(format!(
            "failed to encode composite signature: {}",
            e
        ))
    })?;
    Ok(CredentialProof::new(
        "HybridEd25519MlDsa65Signature2026",
        verification_method,
        bytes,
    ))
}

/// A verifiable credential compatible with W3C VC Data Model
///
/// These credentials can be issued to human identities and inherited
/// by their controlled machine identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    /// Credential context (W3C VC context URIs)
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Unique credential identifier
    pub id: String,
    /// Credential types (always includes "VerifiableCredential")
    #[serde(rename = "type")]
    pub credential_type: Vec<String>,
    /// Tenzro-specific credential type
    pub tenzro_type: TenzroCredentialType,
    /// DID of the credential issuer
    pub issuer: String,
    /// When the credential was issued
    pub issuance_date: DateTime<Utc>,
    /// Optional expiration date
    pub expiration_date: Option<DateTime<Utc>>,
    /// Credential subject (the entity the credential is about)
    pub credential_subject: CredentialSubject,
    /// Cryptographic proof
    pub proof: Option<CredentialProof>,
}

/// The subject of a verifiable credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSubject {
    /// DID of the subject
    pub id: String,
    /// Claims about the subject
    pub claims: HashMap<String, serde_json::Value>,
}

/// Canonical JSON: recursively emits object keys in sorted order.
///
/// Independent of `serde_json`'s `preserve_order` feature, so the byte string
/// a signer produces does not depend on which other crates share the build.
/// See [`CredentialSubject::canonical_bytes`].
fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_default(),
        Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", parts.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(&map[*k])
                    )
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

impl CredentialSubject {
    /// Canonical byte form of the subject used as the proof message.
    ///
    /// Emits every object key in sorted order — `HashMap` iteration order is
    /// process-random, and a proof signed in one process must verify in
    /// another. Every signer and verifier of a credential proof MUST use these
    /// bytes.
    ///
    /// The sort is done explicitly rather than by round-tripping through
    /// `serde_json::Value`. That round-trip only sorts when `serde_json`'s
    /// `preserve_order` feature is **off**: with it on, `Map` is an `IndexMap`
    /// that keeps insertion order and the round-trip is a no-op.
    ///
    /// That feature is not ours to control. Cargo unifies features across a
    /// build, and `revm` (via `jmespath_community`) and the `lance` stack both
    /// enable `serde_json/preserve_order` — so whether this function sorted
    /// depended on which *other* crates happened to be in the build graph.
    /// Building `tenzro-identity` alone sorted; building it alongside
    /// `tenzro-vm` did not. Two nodes compiled with different feature sets
    /// would therefore derive different signing preimages for the same
    /// credential and be unable to verify each other's proofs.
    pub fn canonical_bytes(&self) -> crate::error::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        Ok(canonical_json(&value).into_bytes())
    }
}

impl VerifiableCredential {
    /// Creates a new verifiable credential
    pub fn new(
        tenzro_type: TenzroCredentialType,
        issuer: impl Into<String>,
        subject_did: impl Into<String>,
    ) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://identity.tenzro.com/credentials/v1".to_string(),
            ],
            id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            credential_type: vec![
                "VerifiableCredential".to_string(),
                format!("Tenzro{}", tenzro_type.type_name()),
            ],
            tenzro_type,
            issuer: issuer.into(),
            issuance_date: Utc::now(),
            expiration_date: None,
            credential_subject: CredentialSubject {
                id: subject_did.into(),
                claims: HashMap::new(),
            },
            proof: None,
        }
    }

    /// Sets an expiration date
    pub fn with_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration_date = Some(expiration);
        self
    }

    /// Adds a claim to the credential subject
    pub fn with_claim(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.credential_subject.claims.insert(key.into(), value);
        self
    }

    /// Attaches a proof to the credential
    pub fn with_proof(mut self, proof: CredentialProof) -> Self {
        self.proof = Some(proof);
        self
    }

    /// Returns true if the credential has not expired
    pub fn is_valid(&self) -> bool {
        match self.expiration_date {
            Some(exp) => Utc::now() < exp,
            None => true,
        }
    }

    /// Returns true if the credential has a proof attached
    pub fn is_signed(&self) -> bool {
        self.proof.is_some()
    }

    /// Verifies the credential's cryptographic proof
    ///
    /// # Arguments
    ///
    /// * `issuer_pubkey` - The issuer's public key (typically looked up from registry)
    ///
    /// # Returns
    ///
    /// Returns `Ok(true)` if the credential is valid and the signature verifies,
    /// `Ok(false)` if the credential is expired or signature is invalid,
    /// or an error if verification cannot be performed.
    pub fn verify_proof(&self, issuer_pubkey: &[u8]) -> crate::error::Result<bool> {
        // Check if credential is expired
        if !self.is_valid() {
            return Ok(false);
        }

        // Check if proof exists
        let proof = match &self.proof {
            Some(p) => p,
            None => {
                return Err(crate::error::IdentityError::CredentialError(
                    "No proof attached to credential".to_string(),
                ));
            }
        };

        // Canonical message from the credential (excluding proof): the
        // sorted-key JSON of the credential subject and claims.
        let message = self.credential_subject.canonical_bytes()?;

        proof.verify(&message, issuer_pubkey)
    }

    /// Verify a hybrid credential proof against an issuer's
    /// composite public key.
    ///
    /// The credential must carry a proof whose `proof_type` is
    /// `"HybridEd25519MlDsa65Signature2026"` and whose `proof_value` is a
    /// bincode-serialized [`tenzro_crypto::composite::CompositeSignature`]
    /// over [`CredentialSubject::canonical_bytes`]. Both legs of
    /// the composite signature are required.
    pub fn verify_proof_hybrid(
        &self,
        issuer_pubkey: &tenzro_crypto::composite::CompositePublicKey,
    ) -> crate::error::Result<bool> {
        if !self.is_valid() {
            return Ok(false);
        }

        let proof = match &self.proof {
            Some(p) => p,
            None => {
                return Err(crate::error::IdentityError::CredentialError(
                    "No proof attached to credential".to_string(),
                ));
            }
        };

        let message = self.credential_subject.canonical_bytes()?;
        proof.verify_hybrid(&message, issuer_pubkey)
    }

    /// Sign this credential with a hybrid (Ed25519 + ML-DSA-65) signer,
    /// attaching a `CredentialProof` of type
    /// `"HybridEd25519MlDsa65Signature2026"` whose `proof_value` is the
    /// bincode-serialized composite signature over the credential subject.
    pub fn sign_hybrid(
        mut self,
        signer: &dyn tenzro_crypto::composite::HybridSigner,
        verification_method: impl Into<String>,
    ) -> crate::error::Result<Self> {
        let message = self.credential_subject.canonical_bytes()?;
        let proof = sign_credential_hybrid(signer, &message, verification_method)?;
        self.proof = Some(proof);
        Ok(self)
    }
}

/// Schema definition for credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSchema {
    /// Unique schema identifier
    pub schema_id: String,
    /// Human-readable schema name
    pub name: String,
    /// Schema version
    pub version: String,
    /// Required fields in this credential type
    pub required_fields: Vec<String>,
    /// Optional fields in this credential type
    pub optional_fields: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_credential() {
        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer-id",
            "did:tenzro:human:subject-id",
        );

        assert!(cred.is_valid());
        assert!(!cred.is_signed());
        assert!(
            cred.context
                .contains(&"https://www.w3.org/2018/credentials/v1".to_string())
        );
        assert_eq!(cred.issuer, "did:tenzro:human:issuer-id");
        assert_eq!(cred.credential_subject.id, "did:tenzro:human:subject-id");
    }

    #[test]
    fn test_credential_with_claims() {
        let cred = VerifiableCredential::new(
            TenzroCredentialType::AccreditedInvestor,
            "did:tenzro:human:issuer",
            "did:tenzro:human:alice",
        )
        .with_claim("status", serde_json::Value::String("verified".to_string()))
        .with_claim("tier", serde_json::json!(3));

        assert_eq!(cred.credential_subject.claims.len(), 2);
        assert_eq!(
            cred.credential_subject.claims.get("status"),
            Some(&serde_json::Value::String("verified".to_string()))
        );
    }

    #[test]
    fn test_credential_expiration() {
        let expired =
            VerifiableCredential::new(TenzroCredentialType::AgeVerification, "issuer", "subject")
                .with_expiration(Utc::now() - chrono::Duration::days(1));

        assert!(!expired.is_valid());

        let valid =
            VerifiableCredential::new(TenzroCredentialType::AgeVerification, "issuer", "subject")
                .with_expiration(Utc::now() + chrono::Duration::days(365));

        assert!(valid.is_valid());
    }

    #[test]
    fn test_credential_with_proof() {
        let proof = CredentialProof::new(
            "Ed25519Signature2020",
            "did:tenzro:human:issuer#key-1",
            vec![1, 2, 3, 4],
        );

        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            "did:tenzro:human:subject",
        )
        .with_proof(proof);

        assert!(cred.is_signed());
    }

    #[test]
    fn test_credential_type_name() {
        assert_eq!(
            TenzroCredentialType::KycAttestation.type_name(),
            "KycAttestation"
        );
        assert_eq!(
            TenzroCredentialType::ModelProvider.type_name(),
            "ModelProvider"
        );
        assert_eq!(
            TenzroCredentialType::Custom("MyType".to_string()).type_name(),
            "MyType"
        );
    }

    #[test]
    fn test_credential_proof_verification() {
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
        use tenzro_crypto::{KeyPair, KeyType};

        // Generate a keypair for the issuer
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        // Create a message to sign
        let message = b"test credential data";

        // Sign the message
        let signature = signer.sign(message).unwrap();

        // Create a proof
        let proof = CredentialProof::new(
            "Ed25519Signature2020",
            "did:tenzro:human:issuer#key-1",
            signature.to_bytes(),
        );

        // Verify the proof
        let result = proof
            .verify(message, signer.public_key().as_bytes())
            .unwrap();
        assert!(result, "Valid signature should verify");

        // Test with wrong message
        let wrong_message = b"wrong message";
        let result = proof
            .verify(wrong_message, signer.public_key().as_bytes())
            .unwrap();
        assert!(!result, "Invalid signature should not verify");
    }

    #[test]
    fn test_verifiable_credential_proof_verification() {
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
        use tenzro_crypto::{KeyPair, KeyType};

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        let mut cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            "did:tenzro:human:subject",
        );

        // Create the message to sign (credential subject)
        let message = cred.credential_subject.canonical_bytes().unwrap();
        let signature = signer.sign(&message).unwrap();

        // Attach the proof
        let proof = CredentialProof::new(
            "Ed25519Signature2020",
            "did:tenzro:human:issuer#key-1",
            signature.to_bytes(),
        );
        cred = cred.with_proof(proof);

        // Verify the credential
        let result = cred.verify_proof(signer.public_key().as_bytes()).unwrap();
        assert!(result, "Valid credential should verify");

        // Test with wrong public key
        let wrong_keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let result = cred
            .verify_proof(wrong_keypair.public_key().as_bytes())
            .unwrap();
        assert!(!result, "Credential with wrong key should not verify");
    }

    #[test]
    fn test_hybrid_credential_sign_and_verify_roundtrip() {
        use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_crypto::signatures::Ed25519SignerImpl;
        use tenzro_crypto::{KeyPair, KeyType};

        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate());
        let issuer_pk = signer.public_key().clone();

        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            "did:tenzro:human:subject",
        )
        .sign_hybrid(&signer, "did:tenzro:human:issuer#pq-key-1")
        .unwrap();

        assert!(cred.is_signed());
        let proof = cred.proof.as_ref().unwrap();
        assert_eq!(proof.proof_type, "HybridEd25519MlDsa65Signature2026");
        assert_eq!(
            proof.verification_method,
            "did:tenzro:human:issuer#pq-key-1"
        );

        // Both legs verify under the issuer's composite public key.
        assert!(cred.verify_proof_hybrid(&issuer_pk).unwrap());

        // Wrong key: must not verify.
        let wrong = InMemoryHybridSigner::new(
            Box::new(Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap()),
            MlDsaSigningKey::generate(),
        );
        assert!(!cred.verify_proof_hybrid(wrong.public_key()).unwrap());
    }

    #[test]
    fn test_hybrid_credential_rejects_legacy_verify_path() {
        // The hybrid proof_value is a serialized CompositeSignature, not a
        // bare 64-byte Ed25519 signature; the legacy verify() path must
        // refuse it cleanly rather than silently accepting garbage.
        use tenzro_crypto::composite::{HybridSigner, InMemoryHybridSigner};
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_crypto::signatures::Ed25519SignerImpl;
        use tenzro_crypto::{KeyPair, KeyType};

        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        let signer = InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate());

        let cred = VerifiableCredential::new(
            TenzroCredentialType::KycAttestation,
            "did:tenzro:human:issuer",
            "did:tenzro:human:subject",
        )
        .sign_hybrid(&signer, "did:tenzro:human:issuer#pq-key-1")
        .unwrap();

        let classical_bytes = signer.public_key().classical.as_bytes().to_vec();
        let err = cred.verify_proof(&classical_bytes).unwrap_err();
        match err {
            crate::error::IdentityError::VerificationFailed(msg) => {
                assert!(
                    msg.contains("HybridEd25519MlDsa65Signature2026")
                        || msg.contains("Unsupported")
                );
            }
            other => panic!("expected VerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_expired_credential_fails_verification() {
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
        use tenzro_crypto::{KeyPair, KeyType};

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();

        let mut cred =
            VerifiableCredential::new(TenzroCredentialType::AgeVerification, "issuer", "subject")
                .with_expiration(Utc::now() - chrono::Duration::days(1));

        // Sign it
        let message = cred.credential_subject.canonical_bytes().unwrap();
        let signature = signer.sign(&message).unwrap();
        cred = cred.with_proof(CredentialProof::new(
            "Ed25519",
            "issuer#key-1",
            signature.to_bytes(),
        ));

        // Expired credential should fail verification
        let result = cred.verify_proof(signer.public_key().as_bytes()).unwrap();
        assert!(!result, "Expired credential should not verify");
    }
}
