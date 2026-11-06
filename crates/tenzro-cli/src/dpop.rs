//! Client-side RFC 9449 DPoP: the key this CLI holds, and the per-request
//! proofs it signs with it.
//!
//! # Why this exists
//!
//! Every signing RPC on a node is DPoP-bound. `tenzro auth link-wallet` and
//! `tenzro auth refresh` already accept a `--dpop-jkt` and will bind an access
//! token to a client-held key — but nothing on this side *held* a key or
//! *minted* a proof, so the bound half of the flow was unreachable. The RPC
//! client forwarded a `TENZRO_DPOP_PROOF` environment variable and left the
//! caller to produce its contents.
//!
//! Which cannot work for more than one call. A proof commits to the method and
//! URL it is for, carries a `jti` the node caches against replay, and is
//! accepted only within ±60s of its `iat`. A proof is therefore a per-request
//! artifact, not a credential to export — so this mints one per call rather
//! than asking anyone to paste one.
//!
//! # Shape
//!
//! The key is P-256, created inside and held by this machine's TPM or Secure
//! Enclave (`tenzro_device_key::signer`); it never exists outside the chip, so
//! nothing on disk or in memory can be copied to mint proofs elsewhere. The
//! proof is a compact JWS signed ES256:
//!
//! ```text
//! header  = {"typ":"dpop+jwt","alg":"ES256","jwk":{"crv":"P-256","kty":"EC","x":…,"y":…}}
//! payload = {"htm":…,"htu":…,"iat":…,"jti":…[,"ath":…]}
//! ```
//!
//! `ath` is `base64url(SHA-256(access_token))` and is present whenever a token
//! is being presented — the node requires it on access-token requests, and
//! omitting it is the difference between a proof that authorises this call and
//! one that authorises any call the holder ever makes.
//!
//! The `jkt` is the RFC 7638 thumbprint over the canonical member set
//! `{"crv","kty","x","y"}`, byte-for-byte what
//! `tenzro_auth::DpopProof::compute_jkt` recomputes on the other side. It is
//! the value `--dpop-jkt` wants.

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest, Sha256};
use tenzro_device_key::HardwareSigner;

/// Label of this client's DPoP key in the TPM or Secure Enclave.
const DPOP_KEY_LABEL: &str = "tenzro/cli/dpop";

/// The client's DPoP signing key.
pub struct DpopKey {
    signer: Box<dyn HardwareSigner>,
}

impl DpopKey {
    /// The DPoP key for this machine, created in its TPM or Secure Enclave on
    /// first use. Fails closed on a machine with neither: a DPoP key
    /// authorises signing requests, and a key held anywhere else could be
    /// copied.
    ///
    /// Opened once per process and kept: a command that then selects a
    /// hardware key namespace (`access sign-in --key-namespace`) still proves
    /// with this client's own key, which the token it is issued binds.
    pub fn load_or_create() -> Result<&'static Self> {
        static KEY: std::sync::Mutex<Option<&'static DpopKey>> = std::sync::Mutex::new(None);
        let mut slot = KEY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(key) = *slot {
            return Ok(key);
        }
        let signer = tenzro_device_key::signer::open_or_create(DPOP_KEY_LABEL)
            .map_err(|e| anyhow::anyhow!("no hardware key for DPoP: {e}"))?;
        let key: &'static Self = Box::leak(Box::new(Self { signer }));
        *slot = Some(key);
        Ok(key)
    }

    /// Same as [`Self::load_or_create`]; the key lives in the chip, so opening
    /// and creating are one operation.
    pub fn load() -> Result<&'static Self> {
        Self::load_or_create()
    }

    /// Whether this machine can hold a DPoP key at all.
    pub fn exists() -> bool {
        tenzro_device_key::signer::platform_backend().is_some()
    }

    /// The public key as a JWK, in RFC 7638 canonical form — sorted members,
    /// no whitespace.
    pub fn jwk(&self) -> Result<String> {
        let pk = self
            .signer
            .public_key_sec1()
            .map_err(|e| anyhow::anyhow!("read DPoP public key: {e}"))?;
        Ok(jwk_for(&pk))
    }

    /// RFC 7638 SHA-256 thumbprint of the JWK, base64url unpadded.
    pub fn jkt(&self) -> Result<String> {
        Ok(B64.encode(Sha256::digest(self.jwk()?.as_bytes())))
    }

    /// Sign a proof for one request.
    ///
    /// `htu` is normalised to origin + path: the node strips the query before
    /// comparing, so a proof carrying one would never match.
    pub fn proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> Result<String> {
        let signing_input = signing_input(&self.jwk()?, htm, htu, access_token);
        let sig = self
            .signer
            .sign(signing_input.as_bytes())
            .map_err(|e| anyhow::anyhow!("sign DPoP proof: {e}"))?;
        Ok(format!("{signing_input}.{}", B64.encode(sig)))
    }
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

/// Origin + path, query and fragment removed — the form the node compares
/// against.
///
/// The path is preserved exactly, including a bare trailing `/`. The node
/// derives its expected `htu` from the request URI it actually received, and
/// for a call to the root that is `http://host:port/` *with* the slash — so
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
        DpopKey {
            signer: Box::new(TestKey(SigningKey::from_slice(&[9u8; 32]).unwrap())),
        }
    }

    /// The proof verifies through the node's own DPoP verifier and binds the
    /// same thumbprint the client reports.
    #[test]
    fn a_proof_verifies_with_the_nodes_verifier() {
        let k = key();
        let proof = k.proof("post", "http://127.0.0.1:8545/", None).unwrap();
        let (p, signed, sig) = tenzro_auth::DpopProof::parse_with_signed_input(&proof).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let v = p
            .verify("POST", "http://127.0.0.1:8545/", now, &signed, &sig)
            .unwrap();
        assert_eq!(v.jkt, k.jkt().unwrap());
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
            tenzro_auth::DpopProof::parse_with_signed_input(&proof).expect("parse");

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
            tenzro_auth::DpopProof::parse_with_signed_input(&proof).expect("parse");

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
            tenzro_auth::DpopProof::parse_with_signed_input(&proof).expect("parse");

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
}
