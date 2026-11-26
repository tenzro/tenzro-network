//! The client side of signing in to a node: the RFC 9449 DPoP key a client
//! holds, the per-request proofs it signs with it, and the challenge exchange
//! that turns a hardware key's signature into an access token.
//!
//! Both the `tenzro` CLI (`tenzro access sign-in`) and the node binary's own
//! administrative subcommands (`tenzro-node graceful-exit`) sign in this way.
//! Neither depends on how the other reaches the node: [`sign_in`] takes the
//! JSON-RPC call as a function, and [`authorization`] gives the two headers an
//! authenticated request carries.
//!
//! # DPoP
//!
//! The key is P-256, created inside and held by the machine's TPM or Secure
//! Enclave, or derived by the key holder that holds the machine's keys
//! ([`KeyHolderDpopKey`]); it never exists outside the chip, so nothing on
//! disk or in memory can be copied to mint proofs elsewhere. The proof is a
//! compact JWS signed ES256:
//!
//! ```text
//! header  = {"typ":"dpop+jwt","alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":…,"y":…}}
//! payload = {"htm":…,"htu":…,"iat":…,"jti":…[,"ath":…]}
//! ```
//!
//! A proof commits to the method and URL it is for, carries a `jti` the node
//! caches against replay, and is accepted only within ±60s of its `iat`, so it
//! is minted per request. `ath` is `base64url(SHA-256(access_token))` and is
//! present whenever a token is presented: without it a proof would authorise
//! any call the holder ever makes, not this one.
//!
//! The `jkt` is the RFC 7638 thumbprint over the canonical member set
//! `{"crv","kty","x","y"}`, byte-for-byte what [`crate::DpopProof::compute_jkt`]
//! recomputes on the node.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_device_key::HardwareSigner;

/// Label of a client's DPoP key in the TPM or Secure Enclave.
pub const DPOP_KEY_LABEL: &str = "tenzro/cli/dpop";

/// Why a client could not sign in or prove a request.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// A hardware key could not be read or could not sign.
    #[error("hardware key: {0}")]
    Key(String),
    /// The node refused a call, or could not be reached.
    #[error("{0}")]
    Call(String),
    /// The node's answer lacked what the exchange needs.
    #[error("sign-in answer: {0}")]
    Answer(String),
}

/// A client's DPoP signing key.
pub struct DpopKey {
    signer: Box<dyn HardwareSigner>,
}

impl DpopKey {
    /// The DPoP key held by `signer`.
    pub fn new(signer: Box<dyn HardwareSigner>) -> Self {
        Self { signer }
    }

    /// The public key as a JWK, in RFC 7638 canonical form: sorted members,
    /// no whitespace.
    pub fn jwk(&self) -> Result<String, ClientError> {
        let pk = self
            .signer
            .public_key_sec1()
            .map_err(|e| ClientError::Key(format!("read DPoP public key: {e}")))?;
        Ok(jwk_for(&pk))
    }

    /// RFC 7638 SHA-256 thumbprint of the JWK, base64url unpadded.
    pub fn jkt(&self) -> Result<String, ClientError> {
        Ok(B64.encode(Sha256::digest(self.jwk()?.as_bytes())))
    }

    /// Sign a proof for one request.
    ///
    /// `htu` is normalised to origin + path: the node strips the query before
    /// comparing, so a proof carrying one would never match.
    pub fn proof(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String, ClientError> {
        let signing_input = signing_input(&self.jwk()?, htm, htu, access_token);
        let sig = self
            .signer
            .sign(signing_input.as_bytes())
            .map_err(|e| ClientError::Key(format!("sign DPoP proof: {e}")))?;
        Ok(format!("{signing_input}.{}", B64.encode(sig)))
    }
}

/// The DPoP key of a machine whose keys are in another machine's TPM: a
/// P-256 key the key holder derives from that TPM's root under
/// [`DPOP_KEY_LABEL`]. The key holder signs a TPM-resident key only over
/// messages in a Tenzro domain, which a JWS signing input never is; a
/// derived key is confined by its label instead, and this label is used for
/// nothing but DPoP proofs. The private key stays with the key holder.
pub struct KeyHolderDpopKey {
    root: tenzro_device_key::derive::DerivationRoot,
}

impl KeyHolderDpopKey {
    /// The key holder's DPoP key, through the derivation root this process
    /// reaches it by.
    pub fn open() -> Result<Self, ClientError> {
        let root = tenzro_device_key::derive::DerivationRoot::open_or_create()
            .map_err(|e| ClientError::Key(format!("no DPoP key through the key holder: {e}")))?;
        Ok(Self { root })
    }
}

impl HardwareSigner for KeyHolderDpopKey {
    fn backend(&self) -> tenzro_device_key::HardwareBackend {
        tenzro_device_key::HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        DPOP_KEY_LABEL
    }
    fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
        let xy = self.root.p256_public(DPOP_KEY_LABEL)?;
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..].copy_from_slice(&xy);
        Ok(out)
    }
    fn sign_prehash(
        &self,
        digest: &[u8; 32],
    ) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
        self.root.p256_sign_prehash(DPOP_KEY_LABEL, digest)
    }
}

/// What a node issued on sign-in.
#[derive(Debug, Clone)]
pub struct SignedIn {
    /// The DID the token speaks for.
    pub did: String,
    /// The DPoP-bound access token.
    pub access_token: String,
    /// Seconds until it expires.
    pub expires_in: u64,
    /// The method classes the node's policy grants the DID.
    pub classes: Value,
}

/// Sign in as the hardware key `identity` holds, binding the token to `dpop`.
///
/// Asks the node for a challenge (`tenzro_accessChallenge`) naming the key's
/// machine DID and the DPoP key's thumbprint, has the hardware key sign the
/// device message it returns, and answers it (`tenzro_issueAccessToken`).
/// `call` makes one JSON-RPC call to the node.
pub async fn sign_in<C, F>(
    call: C,
    identity: &dyn HardwareSigner,
    dpop: &DpopKey,
) -> Result<SignedIn, ClientError>
where
    C: Fn(&'static str, Value) -> F,
    F: std::future::Future<Output = Result<Value, String>>,
{
    let jkt = dpop.jkt()?;
    let public_key = identity
        .public_key_sec1()
        .map_err(|e| ClientError::Key(e.to_string()))?;
    let did = tenzro_types::did_derivation::machine_did(&public_key);
    let challenge = call(
        "tenzro_accessChallenge",
        json!({ "did": did, "dpop_jkt": jkt }),
    )
    .await
    .map_err(|e| ClientError::Call(format!("asking for a sign-in challenge: {e}")))?;
    let message = challenge["device_message"]
        .as_str()
        .ok_or_else(|| ClientError::Answer("no device_message".into()))?;
    let message = hex::decode(message)
        .map_err(|_| ClientError::Answer("device_message is not hex".into()))?;
    let signature = identity
        .sign(&message)
        .map_err(|e| ClientError::Key(format!("signing the challenge: {e}")))?;
    let issued = call(
        "tenzro_issueAccessToken",
        json!({
            "challenge_id": challenge["challenge_id"],
            "proof": {
                "kind": "device",
                "public_key": hex::encode(public_key),
                "signature": hex::encode(signature),
            },
        }),
    )
    .await
    .map_err(|e| ClientError::Call(format!("answering the sign-in challenge: {e}")))?;
    let access_token = issued["access_token"]
        .as_str()
        .ok_or_else(|| ClientError::Answer("no access_token".into()))?
        .to_string();
    Ok(SignedIn {
        did,
        access_token,
        expires_in: issued["expires_in"].as_u64().unwrap_or(0),
        classes: issued["classes"].clone(),
    })
}

/// The `Authorization` and `DPoP` headers of a POST to `url` presenting
/// `access_token`, with a fresh proof from `dpop`.
pub fn authorization(
    access_token: &str,
    dpop: &DpopKey,
    url: &str,
) -> Result<[(&'static str, String); 2], ClientError> {
    Ok([
        ("Authorization", format!("DPoP {access_token}")),
        ("DPoP", dpop.proof("POST", url, Some(access_token))?),
    ])
}

fn jwk_for(pk: &[u8; 65]) -> String {
    format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        B64.encode(&pk[1..33]),
        B64.encode(&pk[33..65])
    )
}

/// `base64url(header).base64url(payload)` for one request.
fn signing_input(jwk: &str, htm: &str, htu: &str, access_token: Option<&str>) -> String {
    let header = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}"#);
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let jti = uuid::Uuid::new_v4().to_string();
    let mut payload = format!(
        r#"{{"htm":"{}","htu":"{}","iat":{},"jti":"{}""#,
        htm.to_uppercase(),
        normalize_htu(htu),
        iat,
        jti,
    );
    if let Some(token) = access_token.filter(|t| !t.is_empty()) {
        payload.push_str(&format!(
            r#","ath":"{}""#,
            B64.encode(Sha256::digest(token.as_bytes()))
        ));
    }
    payload.push('}');
    format!("{}.{}", B64.encode(&header), B64.encode(&payload))
}

/// Origin + path, query and fragment removed: the form the node compares
/// against.
///
/// The path is preserved exactly, including a bare trailing `/`. The node
/// derives its expected `htu` from the request URI it actually received, and
/// for a call to the root that is `http://host:port/` *with* the slash, so
/// trimming it produces a proof that is refused with an `htu mismatch`. A URL
/// given without any path gets one added for the same reason.
fn normalize_htu(url: &str) -> String {
    let cut = url.find(['?', '#']).unwrap_or(url.len());
    let base = &url[..cut];

    // Does a path component exist at all? Look past `scheme://`.
    let after_scheme = base.find("://").map(|i| i + 3).unwrap_or(0);
    if base[after_scheme..].contains('/') {
        base.to_string()
    } else {
        format!("{base}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    /// Test-only stand-in for the TPM key.
    struct TestKey(SigningKey);

    impl HardwareSigner for TestKey {
        fn backend(&self) -> tenzro_device_key::HardwareBackend {
            tenzro_device_key::HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "test"
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            let mut out = [0u8; 65];
            out.copy_from_slice(self.0.verifying_key().to_sec1_point(false).as_bytes());
            Ok(out)
        }
        fn sign_prehash(
            &self,
            digest: &[u8; 32],
        ) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    fn key() -> DpopKey {
        DpopKey::new(Box::new(TestKey(
            SigningKey::from_slice(&[9u8; 32]).unwrap(),
        )))
    }

    /// The proof verifies through the node's own DPoP verifier and binds the
    /// same thumbprint the client reports.
    #[test]
    fn a_proof_verifies_with_the_nodes_verifier() {
        let k = key();
        let proof = k.proof("post", "http://127.0.0.1:8545/", None).unwrap();
        let (p, signed, sig) = crate::DpopProof::parse_with_signed_input(&proof).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let v = p
            .verify("POST", "http://127.0.0.1:8545/", now, &signed, &sig)
            .unwrap();
        assert_eq!(v.jkt, k.jkt().unwrap());
    }

    /// The key a key holder derives for DPoP signs proofs the node's
    /// verifier accepts, and its thumbprint is stable across opens.
    #[test]
    fn a_key_holder_derived_key_signs_proofs_the_node_accepts() {
        let open = || {
            DpopKey::new(Box::new(KeyHolderDpopKey {
                root: tenzro_device_key::derive::DerivationRoot::for_tests([5u8; 32]),
            }))
        };
        let k = open();
        let proof = k
            .proof("POST", "http://127.0.0.1:8545/", Some("t"))
            .unwrap();
        let (p, signed, sig) = crate::DpopProof::parse_with_signed_input(&proof).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let v = p
            .verify("POST", "http://127.0.0.1:8545/", now, &signed, &sig)
            .unwrap();
        assert_eq!(v.jkt, k.jkt().unwrap());
        assert_eq!(open().jkt().unwrap(), k.jkt().unwrap());
    }

    /// Presenting a token without binding the proof to it would leave the
    /// proof good for any other token the holder has.
    #[test]
    fn ath_is_present_and_is_the_token_digest() {
        let k = key();
        let token = "header.payload.sig";
        let proof = k.proof("POST", "http://n/", Some(token)).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(proof.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert_eq!(
            payload["ath"].as_str().unwrap(),
            B64.encode(Sha256::digest(token.as_bytes()))
        );
        let bare = k.proof("POST", "http://n/", Some("")).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(bare.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert!(payload.get("ath").is_none());
    }

    /// The node compares against the URI it received, so the path must survive
    /// verbatim — including the root slash.
    #[test]
    fn htu_drops_the_query_but_keeps_the_path() {
        assert_eq!(normalize_htu("http://n:8545/?x=1"), "http://n:8545/");
        assert_eq!(normalize_htu("http://n:8545/rpc#frag"), "http://n:8545/rpc");
        assert_eq!(normalize_htu("http://n:8545/rpc"), "http://n:8545/rpc");
        assert_eq!(normalize_htu("http://n:8545"), "http://n:8545/");
        assert_eq!(normalize_htu("http://n:8545?x=1"), "http://n:8545/");
    }

    /// Two proofs for the same request must differ, or the node's replay cache
    /// would reject the second.
    #[test]
    fn each_proof_carries_a_fresh_jti() {
        let k = key();
        let jti = |p: String| -> String {
            let payload: serde_json::Value =
                serde_json::from_slice(&B64.decode(p.split('.').nth(1).unwrap()).unwrap()).unwrap();
            payload["jti"].as_str().unwrap().to_string()
        };
        assert_ne!(
            jti(k.proof("POST", "http://n/", None).unwrap()),
            jti(k.proof("POST", "http://n/", None).unwrap())
        );
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// A proof is for one request. The node binds method and URL precisely so one
    /// cannot be replayed as another, and this is the assertion that keeps the
    /// client from quietly minting something broader than it claims.
    #[test]
    fn a_proof_does_not_authorise_a_different_request() {
        let key = key();

        let proof = key
            .proof("POST", "http://127.0.0.1:8545", None)
            .expect("mint");
        let (parsed, signed_input, signature) =
            crate::DpopProof::parse_with_signed_input(&proof).expect("parse");

        assert!(
            parsed
                .verify(
                    "GET",
                    "http://127.0.0.1:8545",
                    now(),
                    &signed_input,
                    &signature
                )
                .is_err(),
            "a proof minted for POST must not verify for GET"
        );
        assert!(
            parsed
                .verify(
                    "POST",
                    "http://127.0.0.1:9999",
                    now(),
                    &signed_input,
                    &signature
                )
                .is_err(),
            "a proof minted for one URL must not verify for another"
        );
    }

    /// Tampering with the payload must invalidate the signature — otherwise the
    /// signing input is not covering what we think it covers.
    #[test]
    fn an_altered_proof_fails_verification() {
        let key = key();

        let proof = key
            .proof("POST", "http://127.0.0.1:8545", None)
            .expect("mint");
        let (parsed, signed_input, mut signature) =
            crate::DpopProof::parse_with_signed_input(&proof).expect("parse");

        signature[0] ^= 0xff;
        assert!(
            parsed
                .verify(
                    "POST",
                    "http://127.0.0.1:8545",
                    now(),
                    &signed_input,
                    &signature
                )
                .is_err(),
            "a corrupted signature must not verify"
        );
    }

    /// The client strips query strings because the node compares against
    /// origin+path. A proof minted from a URL carrying one still has to verify.
    #[test]
    fn a_url_with_a_query_still_produces_a_matching_proof() {
        let key = key();

        let proof = key
            .proof("POST", "http://127.0.0.1:8545/?trace=1", None)
            .expect("mint");
        let (parsed, signed_input, signature) =
            crate::DpopProof::parse_with_signed_input(&proof).expect("parse");

        parsed
            .verify(
                "POST",
                "http://127.0.0.1:8545/",
                now(),
                &signed_input,
                &signature,
            )
            .expect("query-stripped htu matches what the node compares");
    }

    /// The exchange: the challenge names the key's machine DID and the DPoP
    /// key's thumbprint, the answer carries the device signature over the
    /// node's message, and the token comes back with its lifetime.
    #[tokio::test]
    async fn sign_in_answers_the_challenge_with_the_hardware_key() {
        let identity = TestKey(SigningKey::from_slice(&[7u8; 32]).unwrap());
        let dpop = key();
        let did = tenzro_types::did_derivation::machine_did(&identity.public_key_sec1().unwrap());
        let jkt = dpop.jkt().unwrap();
        let seen = std::sync::Mutex::new(Vec::new());
        let signed = sign_in(
            |method, params| {
                seen.lock().unwrap().push((method, params.clone()));
                async move {
                    Ok(match method {
                        "tenzro_accessChallenge" => {
                            json!({ "challenge_id": "c1", "device_message": hex::encode(b"msg") })
                        }
                        _ => json!({ "access_token": "tok", "expires_in": 900, "classes": ["admin"] }),
                    })
                }
            },
            &identity,
            &dpop,
        )
        .await
        .unwrap();
        assert_eq!(signed.did, did);
        assert_eq!(signed.access_token, "tok");
        assert_eq!(signed.expires_in, 900);
        let seen = seen.into_inner().unwrap();
        assert_eq!(seen[0].1["did"], did.as_str());
        assert_eq!(seen[0].1["dpop_jkt"], jkt.as_str());
        assert_eq!(seen[1].1["challenge_id"], "c1");
        let signature = hex::decode(seen[1].1["proof"]["signature"].as_str().unwrap()).unwrap();
        assert_eq!(signature, identity.sign(b"msg").unwrap().to_vec());
    }
}
