//! ML-DSA-65 (FIPS 204) wallet signing endpoints.
//!
//! Exposed at `/wallet/mldsa/*` on the public Web API (port 8080,
//! `api.tenzro.xyz`). Used by Tenzro-aware wallets — through the
//! Tenzro SDKs — to obtain post-quantum signatures over arbitrary
//! preimage bytes.
//!
//! ## Mode
//!
//! Testnet runs in **`tee-only`** mode: the node is the sole holder of
//! the ML-DSA-65 signing material, sealed (in production) by a TEE.
//! Threshold ML-DSA awaits NIST IR 8214B; the wallet's
//! `MlDsaCoordinator.capabilities()` returns `tee-only` and never calls
//! the threshold methods. We therefore mount only the two endpoints
//! the wallet actually exercises in `tee-only` mode:
//!
//! | Endpoint | Method | Purpose |
//! |----------|--------|---------|
//! | `/wallet/mldsa/capabilities` | GET | Discovery — returns `{mode}` |
//! | `/wallet/mldsa/sign` | POST | Sign a preimage; returns 3309-byte sig |
//!
//! The four threshold endpoints (`start-round`, `commit`, `respond`,
//! `finalize`) are **deliberately not mounted**: per the project's
//! "no dead code" rule, we don't pre-mount routes that only exist to
//! return 503. A wallet that mistakenly hits one of them gets a 404
//! from axum, which is a clean signal.
//!
//! ## Auth
//!
//! Both endpoints require:
//! - `Authorization: DPoP <jwt>` (RFC 9449)
//! - `DPoP: <proof>` over `(method, full_uri)`
//! - `claims.aap_capabilities` includes action `wallet.mldsa.sign`
//!
//! The capability check is centralized in
//! [`super::oauth::validate_wallet_auth`].
//!
//! ## Key material
//!
//! `(did, surface_key)` deterministically maps to an ML-DSA-65 seed via
//! `seed = SHA-256("tenzro/wallet/mldsa" || did || surface_key)`.
//! This is the **testnet stub** — it gives reproducible test
//! signatures without a live TEE keystore. The production
//! implementation will replace [`derive_signing_key`] with a TEE-sealed
//! lookup, leaving the wire shape unchanged.
//!
//! ## Wire format
//!
//! All bytes are base64url, no padding (RFC 4648 §5). Field naming
//! follows the project-wide snake_case convention with the `_b64`
//! suffix on byte fields, matching the wallet's
//! `MlDsaCoordinator.sign()` request body.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tenzro_crypto::pq::{MlDsaSigningKey, ML_DSA_65_SEED_LEN, ML_DSA_65_SIG_LEN};

use super::error::WalletApiError;
use super::handlers::WebState;
use super::oauth::{full_request_uri, validate_wallet_auth};

/// Capability action enforced on every `/wallet/mldsa/*` request.
const REQUIRED_ACTION: &str = "wallet.mldsa.sign";

/// Domain-separation tag for the deterministic seed-derivation stub.
/// Distinct from any other Tenzro HKDF/SHA tag so a `(did, surface_key)`
/// pair never collides with another protocol's secret-derivation.
const SEED_DOMAIN_TAG: &[u8] = b"tenzro/wallet/mldsa";

// ---------------------------------------------------------------------------
// GET /wallet/mldsa/capabilities
// ---------------------------------------------------------------------------

/// Response body for the discovery endpoint.
///
/// `mode` is always `tee-only` for testnet. `public_key_b64` is absent:
/// the wallet binds its public key at *pairing time*, not via this
/// discovery endpoint. A future threshold mode may set
/// `mode = "threshold"` and surface threshold-coordination metadata in
/// new fields.
#[derive(Debug, Serialize)]
pub struct MlDsaCapabilities {
    /// `"tee-only"` on testnet. Threshold ML-DSA waits on NIST IR 8214B.
    pub mode: &'static str,
}

/// `GET /wallet/mldsa/capabilities`
pub async fn capabilities_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let full_uri = full_request_uri(&headers, "/wallet/mldsa/capabilities");
    if let Err(resp) =
        validate_wallet_auth(&state, &headers, "GET", &full_uri, REQUIRED_ACTION).await
    {
        return resp;
    }

    Json(MlDsaCapabilities { mode: "tee-only" }).into_response()
}

// ---------------------------------------------------------------------------
// POST /wallet/mldsa/sign
// ---------------------------------------------------------------------------

/// Sign-request body. Mirrors the wallet kernel's
/// `MlDsaCoordinator.sign()` payload one-for-one.
#[derive(Debug, Deserialize)]
pub struct MlDsaSignRequest {
    /// Bearer DID — must match the validated JWT's `sub` claim. The
    /// server rejects sign requests where the body's `did` does not
    /// equal the bearer subject so a holder of one DID's token cannot
    /// trigger signatures for another DID's surface key.
    pub did: String,

    /// Wallet-defined identifier for the surface (e.g. `"vault.0"`,
    /// `"agent.x"`). Combined with `did` to derive the signing key.
    pub surface_key: String,

    /// Preimage bytes to sign, base64url, no padding.
    pub preimage_b64: String,

    /// Optional caller-supplied purpose string for audit logging. Not
    /// included in the signed message.
    #[serde(default)]
    pub purpose: Option<String>,
}

/// Sign-response body — the FIPS-204 §4 Table 2 3309-byte ML-DSA-65
/// signature, base64url no-pad.
#[derive(Debug, Serialize)]
pub struct MlDsaSignResponse {
    /// 3309-byte signature, base64url no-pad. Decode + length-check at
    /// 3309 before passing to the verifier.
    pub signature_b64: String,
}

/// Generic JSON error body for sign-time client errors. We do NOT use
/// the OAuth error shape here because these are not OAuth errors — the
/// caller is already authenticated; what failed was the request body
/// itself (e.g., malformed base64). 4xx with a stable `error` code +
/// human description.
fn wallet_error(status: StatusCode, code: &'static str, description: &str) -> WalletApiError {
    WalletApiError::new(status, code, description.to_string())
}

/// `POST /wallet/mldsa/sign`
pub async fn sign_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<MlDsaSignRequest>,
) -> Response {
    let full_uri = full_request_uri(&headers, "/wallet/mldsa/sign");
    let claims =
        match validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await {
            Ok(c) => c,
            Err(resp) => return resp,
        };

    // The body's `did` MUST match the bearer subject. Otherwise a
    // holder of one DID's token could trigger a sign against another
    // DID's keyed surface (the deterministic key derivation reads from
    // `body.did`, so a mismatch produces a real ML-DSA-65 signature
    // against the wrong key — which is observable but still unwanted
    // because the caller can route the wrong-key signature to a verifier
    // configured for the wrong public key and trigger a denial of
    // service). Reject up front.
    if claims.sub != body.did {
        return wallet_error(
            StatusCode::FORBIDDEN,
            "did_subject_mismatch",
            &format!(
                "request body did '{}' does not match bearer subject '{}'",
                body.did, claims.sub
            ),
        )
        .into_response();
    }

    // Decode preimage. Empty preimage is allowed (FIPS 204 accepts
    // zero-length messages); length cap is enforced by axum's request
    // body limit (2 MB) layered above the router.
    let preimage = match URL_SAFE_NO_PAD.decode(body.preimage_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return wallet_error(
                StatusCode::BAD_REQUEST,
                "invalid_preimage_b64",
                &format!("preimage_b64 must be base64url no-pad: {}", e),
            )
            .into_response();
        }
    };

    // Derive the deterministic test-stub signing key. Production
    // replaces this with TEE-sealed keystore lookup keyed by
    // (controller_did, surface_key).
    let signing_key = match derive_signing_key(&body.did, &body.surface_key) {
        Ok(k) => k,
        Err(e) => return e.into_response(),
    };

    // Sign — `MlDsaSigningKey::sign` re-derives the expanded key from
    // the 32-byte seed each call (~ms), keeping resident secret state
    // small.
    let signature = signing_key.sign(&preimage);
    debug_assert_eq!(
        signature.len(),
        ML_DSA_65_SIG_LEN,
        "ml-dsa-65 signature must be {} bytes per FIPS 204",
        ML_DSA_65_SIG_LEN
    );

    if let Some(purpose) = &body.purpose {
        tracing::debug!(
            did = %body.did,
            surface_key = %body.surface_key,
            purpose = %purpose,
            "ml-dsa-65 sign issued"
        );
    }

    Json(MlDsaSignResponse {
        signature_b64: URL_SAFE_NO_PAD.encode(&signature),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/// Deterministic mapping: `(did, surface_key)` → ML-DSA-65 signing key.
///
/// `seed = SHA-256(SEED_DOMAIN_TAG || did_utf8 || 0x00 || surface_key_utf8)`
///
/// The `0x00` separator prevents `(did="ab", surface_key="cd")` from
/// colliding with `(did="abcd", surface_key="")`. The derived key is
/// a real FIPS 204 ML-DSA-65 signing key — `MlDsaSigningKey::sign`
/// produces canonical 3309-byte signatures that any FIPS 204 verifier
/// accepts.
///
/// Authorisation is by DPoP+JWT: the bearer of the (DID, JWT) tuple
/// can sign with this DID's surface keys. The bearer↔DID check is
/// enforced in the request handler.
fn derive_signing_key(did: &str, surface_key: &str) -> Result<MlDsaSigningKey, WalletApiError> {
    let mut hasher = Sha256::new();
    hasher.update(SEED_DOMAIN_TAG);
    hasher.update(did.as_bytes());
    hasher.update([0x00]);
    hasher.update(surface_key.as_bytes());
    let seed = hasher.finalize();
    debug_assert_eq!(seed.len(), ML_DSA_65_SEED_LEN);

    MlDsaSigningKey::from_seed(&seed).map_err(|e| {
        // Should be unreachable — SHA-256 always yields 32 bytes which
        // matches ML_DSA_65_SEED_LEN. If the `pq` constants ever drift,
        // surface a 500 rather than panicking.
        wallet_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "key_derivation_failed",
            &format!("ml-dsa-65 key derivation failed: {}", e),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::ml_dsa_verify;

    #[test]
    fn deterministic_seed_yields_stable_key() {
        let k1 = derive_signing_key("did:tenzro:human:alice", "vault.0").unwrap();
        let k2 = derive_signing_key("did:tenzro:human:alice", "vault.0").unwrap();
        assert_eq!(k1.verifying_key_bytes(), k2.verifying_key_bytes());
    }

    #[test]
    fn distinct_inputs_yield_distinct_keys() {
        let k1 = derive_signing_key("did:tenzro:human:alice", "vault.0").unwrap();
        let k2 = derive_signing_key("did:tenzro:human:alice", "vault.1").unwrap();
        let k3 = derive_signing_key("did:tenzro:human:bob", "vault.0").unwrap();
        assert_ne!(k1.verifying_key_bytes(), k2.verifying_key_bytes());
        assert_ne!(k1.verifying_key_bytes(), k3.verifying_key_bytes());
    }

    #[test]
    fn separator_prevents_concat_collision() {
        // Without the 0x00 separator, ("ab", "cd") and ("abcd", "") would
        // produce identical seeds.
        let k1 = derive_signing_key("ab", "cd").unwrap();
        let k2 = derive_signing_key("abcd", "").unwrap();
        assert_ne!(k1.verifying_key_bytes(), k2.verifying_key_bytes());
    }

    #[test]
    fn signature_verifies_against_derived_vk() {
        let key = derive_signing_key("did:tenzro:human:alice", "vault.0").unwrap();
        let msg = b"transaction preimage bytes";
        let sig = key.sign(msg);
        assert_eq!(sig.len(), ML_DSA_65_SIG_LEN);
        ml_dsa_verify(key.verifying_key_bytes(), msg, &sig).unwrap();
    }

    #[test]
    fn signature_fails_on_tampered_preimage() {
        let key = derive_signing_key("did:tenzro:human:alice", "vault.0").unwrap();
        let sig = key.sign(b"original");
        assert!(ml_dsa_verify(key.verifying_key_bytes(), b"tampered", &sig).is_err());
    }
}
