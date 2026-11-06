//! W3C Data Integrity proofs (`ecdsa-jcs-2019`) made by a hardware key.
//!
//! A document the node publishes (its DID Document, a credential it issues)
//! is signed by a P-256 key held in this machine's TPM or Secure Enclave
//! through [`tenzro_device_key::signer`]. The proof follows the
//! `ecdsa-jcs-2019` cryptosuite: the document without its `proof` and the
//! proof options are each canonicalised with JSON Canonicalization (RFC 8785)
//! and hashed with SHA-256, and the key signs `hash(options) || hash(doc)`.
//! The signature is raw `r || s`, multibase base58btc (`z...`).
//!
//! A relay or cache that edits one byte of the document, or moves the proof
//! onto another document, breaks the signature.
//!
//! The canonical form, the signing digest and the JWK encoding are
//! `tenzro-trust`'s, the same ones every trust record uses; this module adds
//! only signing with a named verification method and verifying under a key
//! the caller supplies.

use serde_json::{Map, Value};
use tenzro_device_key::HardwareSigner;

use tenzro_trust::proof::{CRYPTOSUITE, PROOF_TYPE};

pub use tenzro_trust::proof::{p256_from_jwk, p256_jwk};

/// Attach a proof by `signer` to `document`, naming `verification_method`
/// as the key that made it.
pub fn sign(
    mut document: Value,
    signer: &dyn HardwareSigner,
    verification_method: &str,
    proof_purpose: &str,
    created: &str,
) -> tenzro_device_key::Result<Value> {
    if let Value::Object(map) = &mut document {
        map.remove("proof");
    }
    let options = serde_json::json!({
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method,
        "proofPurpose": proof_purpose,
        "created": created,
    });
    let digest = tenzro_trust::proof::signing_digest(&document, &options);
    let signature = signer.sign_prehash(&digest)?;
    let mut proof = options;
    proof["proofValue"] = Value::String(format!("z{}", bs58::encode(signature).into_string()));
    if let Value::Object(map) = &mut document {
        map.insert("proof".into(), proof);
    }
    Ok(document)
}

/// Why a proof was refused.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("the document carries no proof")]
    Missing,
    #[error("the proof is not a {PROOF_TYPE} with cryptosuite {CRYPTOSUITE}")]
    UnsupportedSuite,
    #[error("the proof is malformed")]
    Malformed,
    #[error("the proof does not verify under the named key")]
    BadSignature,
    /// The signature is good but the key is not the document subject's, so
    /// the proof says only that somebody signed, not that this DID did.
    #[error("the document's DID does not derive from the key that signed it")]
    NotTheSubjectsKey,
}

/// Verify `document`'s proof under `public_key_sec1`, returning the proof's
/// `verificationMethod`.
pub fn verify(document: &Value, public_key_sec1: &[u8]) -> Result<String, ProofError> {
    let mut body = document.clone();
    let proof = match &mut body {
        Value::Object(map) => map.remove("proof").ok_or(ProofError::Missing)?,
        _ => return Err(ProofError::Missing),
    };
    let proof = proof.as_object().ok_or(ProofError::Malformed)?;
    if proof.get("type").and_then(Value::as_str) != Some(PROOF_TYPE)
        || proof.get("cryptosuite").and_then(Value::as_str) != Some(CRYPTOSUITE)
    {
        return Err(ProofError::UnsupportedSuite);
    }
    let value = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .and_then(|v| v.strip_prefix('z'))
        .and_then(|v| bs58::decode(v).into_vec().ok())
        .ok_or(ProofError::Malformed)?;
    let method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or(ProofError::Malformed)?
        .to_string();
    let mut options: Map<String, Value> = proof.clone();
    options.remove("proofValue");
    let digest = tenzro_trust::proof::signing_digest(&body, &Value::Object(options));
    if !tenzro_device_key::signer::verify_p256_prehash(public_key_sec1, &digest, &value) {
        return Err(ProofError::BadSignature);
    }
    Ok(method)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use tenzro_device_key::{DeviceSignature, HardwareBackend};

    /// Test-only stand-in for a TPM key.
    pub(crate) struct TestSigner(pub SigningKey);

    impl HardwareSigner for TestSigner {
        fn backend(&self) -> HardwareBackend {
            HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "test"
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            let mut out = [0u8; 65];
            out.copy_from_slice(self.0.verifying_key().to_sec1_point(false).as_bytes());
            Ok(out)
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<DeviceSignature> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    pub(crate) fn test_signer(seed: u8) -> TestSigner {
        TestSigner(SigningKey::from_slice(&[seed; 32]).unwrap())
    }

    #[test]
    fn a_signed_document_verifies_and_any_edit_breaks_it() {
        let s = test_signer(3);
        let pk = s.public_key_sec1().unwrap();
        let doc =
            serde_json::json!({"id": "did:tenzro:machine:x", "service": [{"url": "https://a"}]});
        let signed = sign(
            doc,
            &s,
            "did:tenzro:machine:x#hw",
            "assertionMethod",
            "2026-09-23T00:00:00Z",
        )
        .unwrap();
        assert_eq!(verify(&signed, &pk).unwrap(), "did:tenzro:machine:x#hw");

        let mut edited = signed.clone();
        edited["service"][0]["url"] = "https://evil".into();
        assert_eq!(verify(&edited, &pk), Err(ProofError::BadSignature));

        let mut moved = signed.clone();
        moved["proof"]["proofPurpose"] = "authentication".into();
        assert_eq!(verify(&moved, &pk), Err(ProofError::BadSignature));

        let other = test_signer(4).public_key_sec1().unwrap();
        assert_eq!(verify(&signed, &other), Err(ProofError::BadSignature));
    }
}
