//! Data Integrity proofs (`ecdsa-jcs-2019`) over trust documents.
//!
//! Every trust document (a credential, a revocation, an
//! operator policy, a model manifest, an origin attestation) is signed the
//! same way. The document without its `proof` and the proof options are each
//! canonicalised with RFC 8785 and hashed with SHA-256; the signer signs
//! `SHA-256(options) || SHA-256(document)` with a P-256 key.
//!
//! The signer's public key travels inside the proof options as
//! `publicKeyJwk`, and the `verificationMethod` is `<signer DID>#hardware-key`.
//! The DID must be the one that key derives, so a verifier needs no DID
//! resolution and no directory: the key proves the signature and the
//! derivation proves whose key it is.
//!
//! P-256 is the one curve a TPM 2.0, an Apple Secure Enclave and a passkey
//! all hold. A TPM or Secure Enclave signs the digest directly (the
//! `hardware` form). A passkey only produces WebAuthn assertions, so the
//! `webauthn` form carries the assertion: the client data's challenge is the
//! digest, and the signature covers `authenticatorData || SHA-256(clientDataJSON)`.
//! Both forms need the key's owner to act on their own hardware; nothing here
//! ever sees a private key.

use base64::Engine;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::jcs::canonical_json;

/// The proof type and cryptosuite every trust document uses.
pub const PROOF_TYPE: &str = "DataIntegrityProof";
pub const CRYPTOSUITE: &str = "ecdsa-jcs-2019";
/// Fragment naming the signing key inside the signer's DID.
pub const KEY_FRAGMENT: &str = "#hardware-key";

const WEBAUTHN_FIELDS: [&str; 2] = ["authenticatorData", "clientDataJSON"];

/// Authenticator data flag bits (WebAuthn Level 3, section 6.1).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;

fn b64url() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// The uncompressed SEC1 P-256 public key as a JWK.
pub fn p256_jwk(public_key_sec1: &[u8; 65]) -> Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url().encode(&public_key_sec1[1..33]),
        "y": b64url().encode(&public_key_sec1[33..65]),
    })
}

/// The uncompressed SEC1 key a P-256 JWK names.
pub fn p256_from_jwk(jwk: &Value) -> Option<[u8; 65]> {
    if jwk.get("kty")?.as_str()? != "EC" || jwk.get("crv")?.as_str()? != "P-256" {
        return None;
    }
    let x = b64url().decode(jwk.get("x")?.as_str()?).ok()?;
    let y = b64url().decode(jwk.get("y")?.as_str()?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&x);
    out[33..].copy_from_slice(&y);
    Some(out)
}

/// The machine DID a TPM or Secure Enclave key derives.
pub fn machine_did(public_key_sec1: &[u8; 65]) -> String {
    tenzro_identity::TenzroDid::from_device_key(public_key_sec1)
        .map(|d| d.to_string())
        .unwrap_or_default()
}

/// The human DID a passkey derives (from the key's `x || y`).
pub fn human_did(public_key_sec1: &[u8; 65]) -> String {
    tenzro_identity::TenzroDid::from_passkey(&public_key_sec1[1..]).to_string()
}

/// Whether `did` is one of the DIDs `public_key_sec1` derives.
pub fn key_derives_did(did: &str, public_key_sec1: &[u8; 65]) -> bool {
    !did.is_empty() && (did == machine_did(public_key_sec1) || did == human_did(public_key_sec1))
}

/// What a signer states in a proof before signing.
#[derive(Debug, Clone)]
pub struct ProofRequest {
    pub signer_did: String,
    pub public_key_sec1: [u8; 65],
    pub purpose: String,
    /// RFC 3339 creation time.
    pub created: String,
    /// The WebAuthn relying party ID, for a passkey signer.
    pub rp_id: Option<String>,
}

/// The proof options a signer commits to.
pub fn options(req: &ProofRequest) -> Value {
    let mut opts = serde_json::json!({
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": format!("{}{}", req.signer_did, KEY_FRAGMENT),
        "proofPurpose": req.purpose,
        "created": req.created,
        "publicKeyJwk": p256_jwk(&req.public_key_sec1),
    });
    if let Some(rp) = &req.rp_id {
        opts["rpId"] = Value::String(rp.clone());
    }
    opts
}

/// `document` without its `proof`.
pub fn unsigned_body(document: &Value) -> Value {
    let mut body = document.clone();
    if let Value::Object(map) = &mut body {
        map.remove("proof");
    }
    body
}

/// The 32 bytes a signer signs: `SHA-256(SHA-256(options) || SHA-256(document))`,
/// with the document taken without its `proof`. A hardware key signs this as
/// a prehash; a passkey receives it as the WebAuthn challenge.
pub fn signing_digest(document: &Value, options: &Value) -> [u8; 32] {
    let mut input = Sha256::digest(canonical_json(options)).to_vec();
    input.extend_from_slice(&Sha256::digest(canonical_json(&unsigned_body(document))));
    Sha256::digest(&input).into()
}

fn attach(mut document: Value, mut proof: Value) -> Value {
    if let Value::Object(map) = &mut document {
        map.remove("proof");
        if let Some(p) = proof.as_object_mut() {
            p.retain(|_, v| !v.is_null());
        }
        map.insert("proof".into(), proof);
    }
    document
}

/// Attach a hardware-key signature (raw `r || s`) made over
/// [`signing_digest`].
pub fn attach_hardware(document: Value, options: Value, signature_rs: &[u8; 64]) -> Value {
    let mut proof = options;
    proof["proofValue"] = Value::String(format!("z{}", bs58::encode(signature_rs).into_string()));
    attach(document, proof)
}

/// Attach a passkey assertion. `signature_rs` is the assertion signature
/// converted to raw `r || s`. A passkey signs in the holder's browser or
/// authenticator app, which assembles this form itself.
#[cfg(test)]
pub(crate) fn attach_webauthn(
    document: Value,
    options: Value,
    signature_rs: &[u8; 64],
    authenticator_data: &[u8],
    client_data_json: &[u8],
) -> Value {
    let mut proof = options;
    proof["proofValue"] = Value::String(format!("z{}", bs58::encode(signature_rs).into_string()));
    proof["authenticatorData"] = Value::String(b64url().encode(authenticator_data));
    proof["clientDataJSON"] = Value::String(b64url().encode(client_data_json));
    attach(document, proof)
}

/// Why a proof was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("the document carries no proof")]
    Missing,
    #[error("the proof is not a {PROOF_TYPE} with cryptosuite {CRYPTOSUITE}")]
    UnsupportedSuite,
    #[error("the proof is malformed: {0}")]
    Malformed(&'static str),
    #[error("the signer DID is not derived from the signing key")]
    KeyNotBound,
    #[error("the passkey assertion is not acceptable: {0}")]
    WebAuthn(&'static str),
    #[error("the signature does not verify under the signing key")]
    BadSignature,
}

/// A proof that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProof {
    pub signer_did: String,
    pub public_key_sec1: [u8; 65],
    pub purpose: String,
    pub created: chrono::DateTime<chrono::Utc>,
}

fn verify_p256_prehash(public_key_sec1: &[u8; 65], digest: &[u8; 32], signature_rs: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let Ok(vk) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_slice(signature_rs) else {
        return false;
    };
    let sig = sig.normalize_s();
    vk.verify_prehash(digest, &sig).is_ok()
}

/// Verify `document`'s proof and return who signed it.
pub fn verify(document: &Value) -> Result<VerifiedProof, ProofError> {
    let proof = document
        .get("proof")
        .and_then(Value::as_object)
        .ok_or(ProofError::Missing)?;
    if proof.get("type").and_then(Value::as_str) != Some(PROOF_TYPE)
        || proof.get("cryptosuite").and_then(Value::as_str) != Some(CRYPTOSUITE)
    {
        return Err(ProofError::UnsupportedSuite);
    }
    let public_key = proof
        .get("publicKeyJwk")
        .and_then(p256_from_jwk)
        .ok_or(ProofError::Malformed("publicKeyJwk is not a P-256 JWK"))?;
    let method = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or(ProofError::Malformed("no verificationMethod"))?;
    let signer_did = method
        .strip_suffix(KEY_FRAGMENT)
        .ok_or(ProofError::Malformed(
            "verificationMethod does not name the hardware key",
        ))?;
    if !key_derives_did(signer_did, &public_key) {
        return Err(ProofError::KeyNotBound);
    }
    let purpose = proof
        .get("proofPurpose")
        .and_then(Value::as_str)
        .ok_or(ProofError::Malformed("no proofPurpose"))?
        .to_string();
    let created = proof
        .get("created")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&chrono::Utc))
        .ok_or(ProofError::Malformed("created is not an RFC 3339 time"))?;
    let signature = proof
        .get("proofValue")
        .and_then(Value::as_str)
        .and_then(|v| v.strip_prefix('z'))
        .and_then(|v| bs58::decode(v).into_vec().ok())
        .filter(|s| s.len() == 64)
        .ok_or(ProofError::Malformed(
            "proofValue is not a multibase r||s signature",
        ))?;

    let mut options: Map<String, Value> = proof.clone();
    options.remove("proofValue");
    for f in WEBAUTHN_FIELDS {
        options.remove(f);
    }
    let rp_id = options
        .get("rpId")
        .and_then(Value::as_str)
        .map(str::to_string);
    let digest = signing_digest(document, &Value::Object(options));

    let is_webauthn = WEBAUTHN_FIELDS.iter().any(|f| proof.contains_key(*f));
    let signed_ok = if is_webauthn {
        let rp_id = rp_id.ok_or(ProofError::WebAuthn("a passkey proof must name its rpId"))?;
        let auth_data = proof
            .get("authenticatorData")
            .and_then(Value::as_str)
            .and_then(|s| b64url().decode(s).ok())
            .ok_or(ProofError::WebAuthn("authenticatorData is not base64url"))?;
        let client_data = proof
            .get("clientDataJSON")
            .and_then(Value::as_str)
            .and_then(|s| b64url().decode(s).ok())
            .ok_or(ProofError::WebAuthn("clientDataJSON is not base64url"))?;
        if auth_data.len() < 37 {
            return Err(ProofError::WebAuthn("authenticatorData is too short"));
        }
        if auth_data[..32] != Sha256::digest(rp_id.as_bytes())[..] {
            return Err(ProofError::WebAuthn(
                "the assertion was made for another relying party",
            ));
        }
        let flags = auth_data[32];
        if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
            return Err(ProofError::WebAuthn("the passkey did not verify its user"));
        }
        if flags & FLAG_BE != 0 {
            return Err(ProofError::WebAuthn(
                "a synced passkey cannot sign trust documents",
            ));
        }
        let cd: Value = serde_json::from_slice(&client_data)
            .map_err(|_| ProofError::WebAuthn("clientDataJSON is not JSON"))?;
        if cd.get("type").and_then(Value::as_str) != Some("webauthn.get") {
            return Err(ProofError::WebAuthn("clientDataJSON is not an assertion"));
        }
        if cd.get("challenge").and_then(Value::as_str) != Some(b64url().encode(digest).as_str()) {
            return Err(ProofError::BadSignature);
        }
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let prehash: [u8; 32] = Sha256::digest(&signed).into();
        verify_p256_prehash(&public_key, &prehash, &signature)
    } else {
        verify_p256_prehash(&public_key, &digest, &signature)
    };
    if !signed_ok {
        return Err(ProofError::BadSignature);
    }
    Ok(VerifiedProof {
        signer_did: signer_did.to_string(),
        public_key_sec1: public_key,
        purpose,
        created,
    })
}

#[cfg(test)]
pub(crate) mod testkit {
    //! Test stand-ins for a TPM key and a passkey. Tests only: a real signer
    //! is a hardware key the node or the user's device holds.
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    pub(crate) struct TestKey(pub SigningKey);

    impl TestKey {
        pub(crate) fn new(seed: u8) -> Self {
            Self(SigningKey::from_slice(&[seed; 32]).unwrap())
        }
        pub(crate) fn sec1(&self) -> [u8; 65] {
            let mut out = [0u8; 65];
            out.copy_from_slice(self.0.verifying_key().to_sec1_point(false).as_bytes());
            out
        }
        pub(crate) fn did(&self) -> String {
            machine_did(&self.sec1())
        }
        pub(crate) fn sign_prehash(&self, digest: &[u8; 32]) -> [u8; 64] {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.to_bytes());
            out
        }
        /// Sign `doc` as this machine key, dated `created`.
        pub(crate) fn sign_at(&self, doc: Value, created: &str) -> Value {
            let opts = options(&ProofRequest {
                signer_did: self.did(),
                public_key_sec1: self.sec1(),
                purpose: "assertionMethod".into(),
                created: created.into(),
                rp_id: None,
            });
            let digest = signing_digest(&doc, &opts);
            attach_hardware(doc, opts, &self.sign_prehash(&digest))
        }
        pub(crate) fn sign(&self, doc: Value) -> Value {
            self.sign_at(doc, "2026-09-24T00:00:00Z")
        }
        /// Sign `doc` as a passkey on `rp_id` with the given authenticator flags.
        pub(crate) fn sign_passkey(&self, doc: Value, rp_id: &str, flags: u8) -> Value {
            let opts = options(&ProofRequest {
                signer_did: human_did(&self.sec1()),
                public_key_sec1: self.sec1(),
                purpose: "assertionMethod".into(),
                created: "2026-09-24T00:00:00Z".into(),
                rp_id: Some(rp_id.into()),
            });
            let digest = signing_digest(&doc, &opts);
            let client_data = serde_json::to_vec(&serde_json::json!({
                "type": "webauthn.get",
                "challenge": b64url().encode(digest),
                "origin": format!("https://{rp_id}"),
            }))
            .unwrap();
            let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            auth_data.push(flags);
            auth_data.extend_from_slice(&1u32.to_be_bytes());
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&client_data));
            let prehash: [u8; 32] = Sha256::digest(&signed).into();
            let sig = self.sign_prehash(&prehash);
            attach_webauthn(doc, opts, &sig, &auth_data, &client_data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::TestKey;
    use super::*;

    #[test]
    fn a_hardware_signed_document_verifies_and_names_its_signer() {
        let k = TestKey::new(3);
        let doc = serde_json::json!({"type": ["TenzroTrustList"], "owner": k.did()});
        let signed = k.sign(doc);
        let v = verify(&signed).unwrap();
        assert_eq!(v.signer_did, k.did());
        assert_eq!(v.public_key_sec1, k.sec1());
    }

    #[test]
    fn any_edit_to_the_document_or_the_proof_breaks_it() {
        let k = TestKey::new(3);
        let signed = k.sign(serde_json::json!({"a": 1, "b": ["x"]}));

        let mut edited = signed.clone();
        edited["b"][0] = "y".into();
        assert_eq!(verify(&edited), Err(ProofError::BadSignature));

        let mut repurposed = signed.clone();
        repurposed["proof"]["proofPurpose"] = "authentication".into();
        assert_eq!(verify(&repurposed), Err(ProofError::BadSignature));

        let mut redated = signed.clone();
        redated["proof"]["created"] = "2020-01-01T00:00:00Z".into();
        assert_eq!(verify(&redated), Err(ProofError::BadSignature));
    }

    #[test]
    fn a_key_swapped_in_under_the_same_did_is_refused() {
        let k = TestKey::new(3);
        let other = TestKey::new(4);
        let mut signed = k.sign(serde_json::json!({"a": 1}));
        signed["proof"]["publicKeyJwk"] = p256_jwk(&other.sec1());
        assert_eq!(verify(&signed), Err(ProofError::KeyNotBound));
    }

    #[test]
    fn a_did_the_key_does_not_derive_is_refused() {
        let k = TestKey::new(3);
        let mut signed = k.sign(serde_json::json!({"a": 1}));
        signed["proof"]["verificationMethod"] =
            format!("{}{}", TestKey::new(9).did(), KEY_FRAGMENT).into();
        assert_eq!(verify(&signed), Err(ProofError::KeyNotBound));
    }

    #[test]
    fn a_passkey_assertion_verifies_as_the_human_did() {
        let k = TestKey::new(5);
        let signed = k.sign_passkey(
            serde_json::json!({"a": 1}),
            "auditor.example",
            FLAG_UP | FLAG_UV,
        );
        let v = verify(&signed).unwrap();
        assert_eq!(v.signer_did, human_did(&k.sec1()));
    }

    #[test]
    fn a_passkey_without_user_verification_or_a_synced_one_is_refused() {
        let k = TestKey::new(5);
        let no_uv = k.sign_passkey(serde_json::json!({"a": 1}), "auditor.example", FLAG_UP);
        assert!(matches!(verify(&no_uv), Err(ProofError::WebAuthn(_))));
        let synced = k.sign_passkey(
            serde_json::json!({"a": 1}),
            "auditor.example",
            FLAG_UP | FLAG_UV | FLAG_BE,
        );
        assert!(matches!(verify(&synced), Err(ProofError::WebAuthn(_))));
    }

    #[test]
    fn a_passkey_assertion_moved_to_another_document_is_refused() {
        let k = TestKey::new(5);
        let signed = k.sign_passkey(
            serde_json::json!({"a": 1}),
            "auditor.example",
            FLAG_UP | FLAG_UV,
        );
        let mut moved = signed.clone();
        moved["a"] = 2.into();
        assert_eq!(verify(&moved), Err(ProofError::BadSignature));
        let mut other_rp = signed;
        other_rp["proof"]["rpId"] = "evil.example".into();
        assert!(verify(&other_rp).is_err());
    }

    #[test]
    fn jwk_round_trips() {
        let pk = TestKey::new(7).sec1();
        assert_eq!(p256_from_jwk(&p256_jwk(&pk)).unwrap(), pk);
    }
}
