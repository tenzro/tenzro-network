//! RFC 9449 DPoP (Demonstrating Proof of Possession) header parsing &
//! verification.
//!
//! A DPoP proof is a compact JWS in the `DPoP` HTTP header, signed by
//! the holder's private key over `(htm, htu, iat, jti[, ath])`:
//!
//! ```text
//! header  = { typ: "dpop+jwt", alg: "EdDSA", jwk: <holder pubkey JWK> }
//! payload = { htm: "POST", htu: "https://rpc.tenzro.xyz/", iat: <unix>,
//!             jti: <random>, ath: base64url(SHA-256(access_token)) }
//! ```
//!
//! On every protected request the engine:
//!
//! 1. Parses the DPoP header into [`DpopProof`].
//! 2. Verifies the embedded JWK's SHA-256 thumbprint matches the
//!    JWT's `cnf.jkt` (binding token ↔ key).
//! 3. Verifies the proof signature against the embedded JWK.
//! 4. Verifies `htm` matches the HTTP method, `htu` matches the request
//!    URL (origin+path, query stripped), and `iat` is within ±60s.
//! 5. Verifies `jti` has not been seen recently (replay protection via
//!    a `dashmap` cache keyed by `(jti, exp_window)`).
//! 6. (For access-token requests, not /token) verifies
//!    `ath = base64url(SHA-256(access_token))`.
//!
//! Result: [`DpopVerification`] with the verified `jkt` thumbprint that
//! the engine can compare against the token's `cnf` claim.

use crate::error::{AuthError, Result};
use serde::{Deserialize, Serialize};

/// Maximum permitted clock skew between holder and verifier, in seconds.
/// Per RFC 9449 §11.1, implementations should accept at least ±5s; we
/// allow ±60s to tolerate slow RTT and modest clock drift on agent
/// hardware.
pub const DPOP_MAX_CLOCK_SKEW_SECS: i64 = 60;

/// Window after which a `jti` may be evicted from the replay cache.
/// Set to `2 * DPOP_MAX_CLOCK_SKEW_SECS` so a replayed proof falling
/// inside the verifier's accept window is always caught.
pub const DPOP_REPLAY_CACHE_TTL_SECS: u64 = 120;

/// A parsed and validated DPoP proof.
///
/// Fields are public for downstream debugging and audit-log
/// serialization; the engine never mutates one after construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpopProof {
    /// HTTP method the proof binds to, uppercase ("GET", "POST", …).
    pub htm: String,

    /// Target URI the proof binds to (origin + path, query stripped).
    pub htu: String,

    /// Issued-at, Unix seconds.
    pub iat: i64,

    /// Unique identifier — used for replay detection.
    pub jti: String,

    /// Optional access-token hash (`base64url(SHA-256(access_token))`).
    /// Required when the proof accompanies an existing access token,
    /// absent when the proof is sent to the /token endpoint to obtain
    /// a new token.
    pub ath: Option<String>,

    /// Holder's public key, encoded as a JWK (e.g., `{"kty":"OKP",
    /// "crv":"Ed25519","x":"<base64url>"}`). The thumbprint of this JWK
    /// is what binds the proof to the token's `cnf.jkt`.
    pub jwk_json: String,
}

/// Result of [`DpopProof::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopVerification {
    /// SHA-256 thumbprint of the embedded JWK, base64url-encoded.
    /// Compare against [`crate::Cnf::jkt`] to confirm the proof matches
    /// the token.
    pub jkt: String,

    /// Replay-cache key — the engine inserts this on success and
    /// rejects duplicates within [`DPOP_REPLAY_CACHE_TTL_SECS`].
    pub jti: String,

    /// `iat` echoed for audit logging.
    pub iat: i64,
}

impl DpopProof {
    /// Compute the canonical RFC 7638 JWK thumbprint over an
    /// already-parsed JWK JSON object. Returns
    /// `base64url-no-pad(SHA-256(canonical))`.
    ///
    /// "Canonical" per RFC 7638 §3 means the lexicographically-sorted
    /// subset of required members serialized with no whitespace.
    /// For Ed25519 keys (`OKP` with `crv=Ed25519`) the required set is
    /// `{crv, kty, x}`; for `EC` keys it is `{crv, kty, x, y}`; for
    /// `RSA` it is `{e, kty, n}`. We support `OKP/Ed25519` only in V1.
    pub fn compute_jkt(jwk_json: &str) -> Result<String> {
        let v: serde_json::Value = serde_json::from_str(jwk_json)
            .map_err(|e| AuthError::InvalidDpop(format!("malformed JWK: {}", e)))?;

        let kty = v.get("kty").and_then(|x| x.as_str()).ok_or_else(|| {
            AuthError::InvalidDpop("JWK missing 'kty'".into())
        })?;
        let crv = v.get("crv").and_then(|x| x.as_str()).ok_or_else(|| {
            AuthError::InvalidDpop("JWK missing 'crv'".into())
        })?;
        let x = v.get("x").and_then(|x| x.as_str()).ok_or_else(|| {
            AuthError::InvalidDpop("JWK missing 'x'".into())
        })?;

        if kty != "OKP" || crv != "Ed25519" {
            return Err(AuthError::InvalidDpop(format!(
                "unsupported JWK kty/crv: {}/{} (V1 only supports OKP/Ed25519)",
                kty, crv
            )));
        }

        // RFC 7638 canonical form: sorted required members, no whitespace.
        let canonical = format!(r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#, crv, kty, x);

        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(canonical.as_bytes());
        Ok(base64_url_no_pad(&digest))
    }

    /// Parse a `DPoP` header value into a `DpopProof` *and* return the
    /// raw `(signed_input, signature)` byte pair needed by
    /// [`DpopProof::verify`] / [`crate::AuthEngine::validate_jwt`].
    ///
    /// `signed_input` is the ASCII bytes of `<header_b64>.<payload_b64>`
    /// (the JWS Signing Input per RFC 7515 §5.1); `signature` is the
    /// base64url-decoded third segment. Returning them here means the
    /// caller doesn't have to re-parse the header value to get the bytes
    /// the verifier needs.
    pub fn parse_with_signed_input(header_value: &str) -> Result<(Self, Vec<u8>, Vec<u8>)> {
        let parts: Vec<&str> = header_value.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP JWS must have exactly 3 parts, got {}",
                parts.len()
            )));
        }
        let signed_input = format!("{}.{}", parts[0], parts[1]).into_bytes();
        let signature = base64_url_decode(parts[2])?;
        let proof = Self::parse(header_value)?;
        Ok((proof, signed_input, signature))
    }

    /// Parse a `DPoP` header value (a compact JWS string of the form
    /// `<base64url-header>.<base64url-payload>.<base64url-sig>`) into a
    /// `DpopProof`. This *does not* verify the signature or any
    /// time/replay invariants — that is [`DpopProof::verify`]'s job.
    /// Most callers want [`DpopProof::parse_with_signed_input`] so they
    /// also get the bytes needed for verification.
    pub fn parse(header_value: &str) -> Result<Self> {
        let parts: Vec<&str> = header_value.split('.').collect();
        if parts.len() != 3 {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP JWS must have exactly 3 parts, got {}",
                parts.len()
            )));
        }

        let header_bytes = base64_url_decode(parts[0])?;
        let payload_bytes = base64_url_decode(parts[1])?;

        let header: serde_json::Value = serde_json::from_slice(&header_bytes)
            .map_err(|e| AuthError::InvalidDpop(format!("malformed JWS header: {}", e)))?;
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| AuthError::InvalidDpop(format!("malformed JWS payload: {}", e)))?;

        // Header invariants per RFC 9449 §4.2.
        let typ = header.get("typ").and_then(|v| v.as_str()).unwrap_or("");
        if typ != "dpop+jwt" {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP typ must be 'dpop+jwt', got '{}'",
                typ
            )));
        }
        let alg = header.get("alg").and_then(|v| v.as_str()).unwrap_or("");
        if alg != "EdDSA" {
            return Err(AuthError::InvalidDpop(format!(
                "V1 only supports alg=EdDSA, got '{}'",
                alg
            )));
        }
        let jwk = header.get("jwk").ok_or_else(|| {
            AuthError::InvalidDpop("DPoP header missing 'jwk'".into())
        })?;
        let jwk_json = serde_json::to_string(jwk)?;

        // Payload invariants.
        let htm = payload
            .get("htm")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidDpop("DPoP missing 'htm'".into()))?
            .to_string();
        let htu = payload
            .get("htu")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidDpop("DPoP missing 'htu'".into()))?
            .to_string();
        let iat = payload
            .get("iat")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| AuthError::InvalidDpop("DPoP missing 'iat'".into()))?;
        let jti = payload
            .get("jti")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidDpop("DPoP missing 'jti'".into()))?
            .to_string();
        let ath = payload
            .get("ath")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(DpopProof {
            htm,
            htu,
            iat,
            jti,
            ath,
            jwk_json,
        })
    }

    /// Verify the proof against the request context.
    ///
    /// Caller is responsible for replay-cache lookup using the returned
    /// [`DpopVerification::jti`]; this function does not own the cache.
    /// Caller is also responsible for confirming
    /// [`DpopVerification::jkt`] matches the bound token's `cnf.jkt`.
    pub fn verify(
        &self,
        expected_htm: &str,
        expected_htu: &str,
        now_unix: i64,
        signed_input: &[u8],
        signature: &[u8],
    ) -> Result<DpopVerification> {
        if !self.htm.eq_ignore_ascii_case(expected_htm) {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP htm mismatch: proof={}, request={}",
                self.htm, expected_htm
            )));
        }
        if self.htu != expected_htu {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP htu mismatch: proof={}, request={}",
                self.htu, expected_htu
            )));
        }
        let skew = (now_unix - self.iat).abs();
        if skew > DPOP_MAX_CLOCK_SKEW_SECS {
            return Err(AuthError::InvalidDpop(format!(
                "DPoP iat outside accepted window: skew={}s, max={}s",
                skew, DPOP_MAX_CLOCK_SKEW_SECS
            )));
        }

        // Verify Ed25519 signature using the embedded JWK.
        let jwk: serde_json::Value = serde_json::from_str(&self.jwk_json)?;
        let x_b64 = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::InvalidDpop("JWK missing 'x'".into()))?;
        let pubkey_bytes = base64_url_decode(x_b64)?;
        if pubkey_bytes.len() != 32 {
            return Err(AuthError::InvalidDpop(format!(
                "Ed25519 public key must be 32 bytes, got {}",
                pubkey_bytes.len()
            )));
        }
        let pk_array: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidDpop("public key length mismatch".into()))?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| AuthError::InvalidDpop(format!("invalid Ed25519 public key: {}", e)))?;

        if signature.len() != 64 {
            return Err(AuthError::InvalidDpop(format!(
                "Ed25519 signature must be 64 bytes, got {}",
                signature.len()
            )));
        }
        let sig_array: [u8; 64] = signature
            .try_into()
            .map_err(|_| AuthError::InvalidDpop("signature length mismatch".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);

        use ed25519_dalek::Verifier;
        pk.verify(signed_input, &sig)
            .map_err(|e| AuthError::InvalidDpop(format!("Ed25519 verification failed: {}", e)))?;

        let jkt = Self::compute_jkt(&self.jwk_json)?;

        Ok(DpopVerification {
            jkt,
            jti: self.jti.clone(),
            iat: self.iat,
        })
    }
}

/// Base64url-decode without padding (RFC 7515 §2).
fn base64_url_decode(s: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AuthError::InvalidDpop(format!("base64url decode: {}", e)))
}

/// Base64url-encode without padding (RFC 7515 §2).
fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jkt_thumbprint_is_stable_for_canonical_jwk() {
        // RFC 7638 §3.1 worked example for an EC key (we only do
        // OKP/Ed25519 in V1, so use a synthetic Ed25519 JWK).
        let jwk = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
        let jkt = DpopProof::compute_jkt(jwk).unwrap();
        // Stable output — recompute from canonical form.
        // Canonical = `{"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
        // (sorted required members, no whitespace).
        assert!(!jkt.is_empty());
        // Idempotent: same input → same output.
        let jkt2 = DpopProof::compute_jkt(jwk).unwrap();
        assert_eq!(jkt, jkt2);
    }

    #[test]
    fn rejects_non_ed25519_jwk() {
        let jwk = r#"{"kty":"EC","crv":"P-256","x":"f","y":"g"}"#;
        let err = DpopProof::compute_jkt(jwk).unwrap_err();
        assert!(matches!(err, AuthError::InvalidDpop(_)));
    }

    #[test]
    fn parse_rejects_wrong_typ() {
        // Build a fake JWS with typ=jwt instead of dpop+jwt.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"jwt","alg":"EdDSA","jwk":{}}"#);
        let payload = URL_SAFE_NO_PAD.encode(br#"{"htm":"POST","htu":"x","iat":0,"jti":"a"}"#);
        let sig = URL_SAFE_NO_PAD.encode(b"sig");
        let jws = format!("{}.{}.{}", header, payload, sig);
        let err = DpopProof::parse(&jws).unwrap_err();
        assert!(matches!(err, AuthError::InvalidDpop(_)));
    }
}
