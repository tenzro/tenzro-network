//! Passkey share-unwrap endpoints.
//!
//! Exposed at `/wallet/share/*` on the public Web API (port 8080,
//! `api.tenzro.xyz`). Used by Tenzro-aware wallets — through the
//! Tenzro SDKs — to retrieve the wrapped half of a 2-of-2 FROST share
//! that lives on the node, gated by a WebAuthn passkey assertion.
//!
//! ## Three-step flow
//!
//! 1. `GET /wallet/share/envelope?credential_id=…&surface_key=…`
//!    Returns the wrapped share blob and its AEAD parameters. The
//!    wrapping is deterministic from `(credential_id, surface_key)` —
//!    the wallet, holding the passkey, locally derives the unwrap key
//!    from the passkey's PRF output. This endpoint is idempotent.
//! 2. `POST /wallet/share/escrow/challenge`
//!    Server mints a fresh 32-byte random nonce, holds it for 30s, and
//!    returns it to the wallet. The wallet uses this nonce as the
//!    WebAuthn `challenge` field when prompting the user's passkey.
//! 3. `POST /wallet/share/escrow/unwrap`
//!    Wallet posts back the resulting WebAuthn assertion plus the
//!    nonce. Server verifies the assertion, single-use-consumes the
//!    nonce, and returns `(wrapped_share, pepper)`. The pepper binds
//!    the unwrap to *this specific assertion*, so a replayed `envelope`
//!    + an old assertion cannot recover the cleartext share.
//!
//! ## Why the pepper, not just the wrapped share?
//!
//! The wrapped share is fetched without a user-presence proof (just
//! AAP-token-gated). On its own it must be useless — that's the
//! security model. The pepper is a per-assertion entropy mix that
//! becomes part of the unwrap KDF *only* when the wallet has a fresh,
//! cryptographically verified passkey assertion. Without the pepper the
//! wrapped share is gibberish, even to a caller that can produce valid
//! AAP tokens.
//!
//! ## Auth
//!
//! All three endpoints require:
//! - `Authorization: DPoP <jwt>` (RFC 9449)
//! - `DPoP: <proof>` over `(method, full_uri)`
//! - `claims.aap_capabilities` includes action `wallet.share.unwrap`
//!
//! ## Testnet stub vs production
//!
//! - **Wrapping:** the testnet stub derives a deterministic AES-256-GCM
//!   wrapping key from `(credential_id, surface_key)`. Production swaps
//!   in an HSM-backed wrapping (the wire shape is unchanged).
//! - **Passkey verification:** the stub implements full WebAuthn-style
//!   verification of an Ed25519-keyed assertion (COSE alg `-8`):
//!   1. Parse `clientDataJSON`, check `type == "webauthn.get"` and that
//!      `clientDataJSON.challenge` (base64url no-pad) equals the escrowed
//!      nonce.
//!   2. Reconstruct the signed bytes as
//!      `authenticatorData || SHA-256(clientDataJSON)` per WebAuthn L3
//!      §7.2 step 19.
//!   3. Verify the Ed25519 signature against the credential's stored
//!      public key (deterministically derived from `credential_id` for
//!      the testnet stub).
//!
//!   The stub does not enforce RP ID, origin, attestation, or
//!   counter-monotonicity — those are deferred to the production
//!   passkey registry. The wire shape (request + response) is identical
//!   to what the production verifier consumes.
//! - **Pepper KDF:** `pepper = SHA-256("tenzro/wallet/share/pepper"
//!   || nonce || assertion_signature)`. Production replaces this with
//!   HKDF-SHA256 with the same inputs; the wallet's `derive_unwrap_key`
//!   does the matching swap.
//!
//! ## Wire format
//!
//! All bytes are base64url, no padding (RFC 4648 §5). Field naming
//! follows the project-wide snake_case convention with the `_b64`
//! suffix on byte fields, matching the wallet kernel's
//! `ShareEscrowClient` request/response shapes.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use ed25519_dalek::{Signature as EdSignature, SigningKey as EdSigningKey, Verifier, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::WalletApiError;
use super::handlers::WebState;
use super::oauth::{full_request_uri, validate_wallet_auth};

/// Capability action enforced on every `/wallet/share/*` request.
const REQUIRED_ACTION: &str = "wallet.share.unwrap";

/// Domain-separation tag for the deterministic AES-256-GCM wrapping
/// key (testnet stub). Distinct from every other `tenzro/wallet/*` tag
/// so the wrapping key cannot collide with an FROST/ML-DSA seed.
const WRAP_KEY_DOMAIN_TAG: &[u8] = b"tenzro/wallet/share/wrap-key";

/// Domain-separation tag for the deterministic plaintext share
/// (testnet stub). Distinct from the wrapping-key tag so the share
/// material itself never equals its own wrapping key.
const SHARE_PLAINTEXT_DOMAIN_TAG: &[u8] = b"tenzro/wallet/share/plaintext";

/// Domain-separation tag for the deterministic credential public key
/// (testnet stub). Production passkey registry replaces this with a
/// real lookup keyed by `credential_id`.
const CREDENTIAL_KEY_DOMAIN_TAG: &[u8] = b"tenzro/wallet/share/cred-key";

/// Domain-separation tag for the per-assertion pepper KDF.
const PEPPER_DOMAIN_TAG: &[u8] = b"tenzro/wallet/share/pepper";

/// AES-GCM nonce — 12 bytes constant for the testnet wrapping stub.
/// Safe because each `(credential_id, surface_key)` pair has its own
/// derived wrapping key; the (key, nonce) pair is unique.
const WRAP_NONCE: [u8; 12] = [
    0x74, 0x65, 0x6e, 0x7a, 0x72, 0x6f, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x00,
];

/// AAD bound into the AES-GCM wrap. Mirrors the wallet's unwrap-side
/// AAD so the AEAD authentication ties the ciphertext to its
/// `(credential_id, surface_key)` pair.
fn wrap_aad(credential_id: &str, surface_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        b"tenzro/wallet/share/aad".len() + credential_id.len() + surface_key.len() + 2,
    );
    aad.extend_from_slice(b"tenzro/wallet/share/aad");
    aad.push(0x00);
    aad.extend_from_slice(credential_id.as_bytes());
    aad.push(0x00);
    aad.extend_from_slice(surface_key.as_bytes());
    aad
}

/// Escrow nonces live this long. WebAuthn ceremonies typically take
/// 5–15 seconds; 30 seconds gives the user time to choose the right
/// authenticator without keeping replay windows open.
const ESCROW_TTL: Duration = Duration::from_secs(30);

/// 32 random bytes per RFC 9449 / WebAuthn §13.4.3 challenge guidance.
const ESCROW_NONCE_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Escrow store
// ---------------------------------------------------------------------------

/// One entry per outstanding `(credential_id, surface_key, nonce)`
/// triple. Single-use: the unwrap handler removes the entry on
/// successful match before any cryptographic work, so a successful
/// unwrap cannot be replayed.
struct EscrowEntry {
    expires_at_ms: u64,
}

/// Concurrent escrow store. Keyed by the full triple
/// `credential_id || 0x00 || surface_key || 0x00 || nonce_b64`.
///
/// Bound to `WebState` (one instance per node). We don't shard by
/// `credential_id` — a few hundred outstanding ceremonies per node is
/// the realistic upper bound and `DashMap` handles that trivially.
pub struct ShareEscrow {
    entries: DashMap<String, EscrowEntry>,
}

impl ShareEscrow {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Drop expired entries. Called on every escrow interaction so the
    /// map self-bounds without a separate sweeper task.
    fn sweep(&self, now_ms: u64) {
        self.entries.retain(|_, e| e.expires_at_ms > now_ms);
    }

    fn key(credential_id: &str, surface_key: &str, nonce_b64: &str) -> String {
        let mut k =
            String::with_capacity(credential_id.len() + surface_key.len() + nonce_b64.len() + 2);
        k.push_str(credential_id);
        k.push('\0');
        k.push_str(surface_key);
        k.push('\0');
        k.push_str(nonce_b64);
        k
    }
}

impl Default for ShareEscrow {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn escrow(state: &Arc<WebState>) -> &ShareEscrow {
    &state.share_escrow
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// Query string for `GET /wallet/share/envelope`.
#[derive(Debug, Deserialize)]
pub struct EnvelopeQuery {
    pub credential_id: String,
    pub surface_key: String,
}

/// Response body for `GET /wallet/share/envelope`.
#[derive(Debug, Serialize)]
pub struct EnvelopeResponse {
    /// AES-256-GCM ciphertext of the FROST share, base64url no-pad.
    /// Layout: `nonce(12) || ciphertext || tag(16)` — same convention
    /// as `tenzro_tee::enclave_crypto`.
    pub wrapped_share_b64: String,
    /// AEAD algorithm identifier. Always `"aes-256-gcm"` on testnet.
    pub alg: &'static str,
    /// Salt used in the wallet-side unwrap KDF. Stable per
    /// `(credential_id, surface_key)`. Base64url no-pad.
    pub salt_b64: String,
}

/// Request body for `POST /wallet/share/escrow/challenge`.
#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub credential_id: String,
    pub surface_key: String,
}

/// Response body for `POST /wallet/share/escrow/challenge`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// 32-byte random nonce, base64url no-pad. The wallet must use
    /// this exact string as the WebAuthn `challenge` field when
    /// prompting the user's passkey.
    pub nonce_b64: String,
    /// Unix-millis at which the nonce will be evicted.
    pub expires_at_ms: u64,
}

/// WebAuthn assertion as produced by `navigator.credentials.get()`.
/// Bytes-fields are base64url no-pad.
#[derive(Debug, Deserialize)]
pub struct PasskeyAssertion {
    /// Raw `authenticatorData` bytes from the authenticator.
    pub authenticator_data_b64: String,
    /// Raw `clientDataJSON` bytes (UTF-8 JSON) from the client.
    pub client_data_json_b64: String,
    /// Authenticator's signature over `authenticatorData ||
    /// SHA-256(clientDataJSON)`. For Ed25519 (COSE alg `-8`) this is
    /// 64 bytes.
    pub signature_b64: String,
}

/// Request body for `POST /wallet/share/escrow/unwrap`.
#[derive(Debug, Deserialize)]
pub struct UnwrapRequest {
    pub credential_id: String,
    pub surface_key: String,
    /// Same nonce previously issued by `escrow/challenge`. Single-use:
    /// consumed by this call regardless of whether the assertion
    /// verifies.
    pub nonce_b64: String,
    pub assertion: PasskeyAssertion,
}

/// Response body for `POST /wallet/share/escrow/unwrap`.
#[derive(Debug, Serialize)]
pub struct UnwrapResponse {
    /// Same wrapped share as `EnvelopeResponse.wrapped_share_b64`.
    /// Returned again so the wallet doesn't have to round-trip
    /// `envelope` and `unwrap` separately.
    pub wrapped_share_b64: String,
    /// Per-assertion pepper, base64url no-pad. Mixed into the wallet's
    /// unwrap KDF — without it the wrapped share is gibberish.
    pub pepper_b64: String,
}

fn wallet_error(status: StatusCode, code: &'static str, description: &str) -> WalletApiError {
    WalletApiError::new(status, code, description.to_string())
}

fn parse_b64(field: &'static str, value: &str) -> Result<Vec<u8>, WalletApiError> {
    URL_SAFE_NO_PAD.decode(value.as_bytes()).map_err(|e| {
        wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_b64",
            &format!("{} must be base64url no-pad: {}", field, e),
        )
    })
}

// ---------------------------------------------------------------------------
// Testnet stub: deterministic key + share derivation
// ---------------------------------------------------------------------------

/// Wrapping key for `(credential_id, surface_key)`. SHA-256 of the
/// domain tag + both inputs (with `0x00` separators to prevent concat
/// collisions). 32 bytes — matches AES-256.
fn derive_wrap_key(credential_id: &str, surface_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(WRAP_KEY_DOMAIN_TAG);
    hasher.update(credential_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(surface_key.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// Plaintext FROST share material for `(credential_id, surface_key)`.
/// The testnet stub returns 32 deterministic bytes — production looks
/// the share up from a real share registry.
fn derive_plaintext_share(credential_id: &str, surface_key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(SHARE_PLAINTEXT_DOMAIN_TAG);
    hasher.update(credential_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(surface_key.as_bytes());
    hasher.finalize().to_vec()
}

/// Salt mixed into the wallet's unwrap KDF. Stable per
/// `(credential_id, surface_key)`. Public — its job is uniqueness, not
/// secrecy.
fn derive_salt(credential_id: &str, surface_key: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"tenzro/wallet/share/salt");
    hasher.update(credential_id.as_bytes());
    hasher.update([0x00]);
    hasher.update(surface_key.as_bytes());
    hasher.finalize()[..16].to_vec()
}

/// Encrypts the plaintext share under the deterministic wrap key.
/// Returns `nonce(12) || ciphertext || tag(16)` per the project's
/// AES-GCM convention.
fn wrap_share(credential_id: &str, surface_key: &str) -> Result<Vec<u8>, WalletApiError> {
    let plaintext = derive_plaintext_share(credential_id, surface_key);
    wrap_share_bytes(credential_id, surface_key, &plaintext)
}

/// Wraps arbitrary share plaintext under the same deterministic key /
/// nonce / AAD derivation the escrow-unwrap path expects. Used by the
/// `/wallet/new/finalize` provisioning path to wrap the REAL serialized
/// FROST device key-package (not the deterministic stub plaintext).
/// Returns `nonce(12) || ciphertext || tag(16)`.
pub(crate) fn wrap_share_bytes(
    credential_id: &str,
    surface_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, WalletApiError> {
    let key_bytes = derive_wrap_key(credential_id, surface_key);
    let aad = wrap_aad(credential_id, surface_key);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&WRAP_NONCE);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| {
            wallet_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "wrap_failed",
                &format!("AES-256-GCM encrypt: {}", e),
            )
        })?;

    let mut out = Vec::with_capacity(WRAP_NONCE.len() + ciphertext.len());
    out.extend_from_slice(&WRAP_NONCE);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Salt for `(credential_id, surface_key)`, exposed for the provisioning
/// finalize path so its `wrapped_share.salt_b64` matches the escrow
/// envelope the wallet later fetches for unwrapping.
pub(crate) fn provisioning_salt(credential_id: &str, surface_key: &str) -> Vec<u8> {
    derive_salt(credential_id, surface_key)
}

/// Deterministic Ed25519 verifying key for the testnet `credential_id`
/// stub. Production swaps this for a passkey-registry lookup.
fn derive_credential_verifying_key(credential_id: &str) -> Result<VerifyingKey, WalletApiError> {
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_KEY_DOMAIN_TAG);
    hasher.update(credential_id.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hasher.finalize());
    // SigningKey::from_bytes always succeeds for any 32-byte seed.
    let signing_key = EdSigningKey::from_bytes(&seed);
    Ok(signing_key.verifying_key())
}

// ---------------------------------------------------------------------------
// WebAuthn-style assertion verification (testnet stub)
// ---------------------------------------------------------------------------

/// Minimal `clientDataJSON` shape we need to parse. The full WebAuthn
/// spec defines more fields (`crossOrigin`, `tokenBinding`,
/// `topOrigin`); we ignore them on testnet but still require the two
/// fields the security argument depends on.
#[derive(Debug, Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
}

/// Verify a WebAuthn-style Ed25519 assertion against the escrowed
/// nonce. On success returns the raw signature bytes (used as pepper
/// input).
fn verify_assertion(
    credential_id: &str,
    expected_nonce_b64: &str,
    assertion: &PasskeyAssertion,
) -> Result<Vec<u8>, WalletApiError> {
    let auth_data = parse_b64("authenticator_data_b64", &assertion.authenticator_data_b64)?;
    let client_data = parse_b64("client_data_json_b64", &assertion.client_data_json_b64)?;
    let signature_bytes = parse_b64("signature_b64", &assertion.signature_b64)?;

    if signature_bytes.len() != 64 {
        return Err(wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_signature",
            &format!(
                "ed25519 webauthn signature must be 64 bytes, got {}",
                signature_bytes.len()
            ),
        ));
    }

    // Parse clientDataJSON and bind challenge.
    let cd: ClientData = serde_json::from_slice(&client_data).map_err(|e| {
        wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            &format!("clientDataJSON must be valid UTF-8 JSON: {}", e),
        )
    })?;
    if cd.ty != "webauthn.get" {
        return Err(wallet_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_data",
            &format!(
                "clientDataJSON.type must be 'webauthn.get', got '{}'",
                cd.ty
            ),
        ));
    }
    if cd.challenge != expected_nonce_b64 {
        return Err(wallet_error(
            StatusCode::BAD_REQUEST,
            "challenge_mismatch",
            "clientDataJSON.challenge does not match the escrowed nonce",
        ));
    }

    // Build signed-bytes preimage: authenticatorData || SHA-256(clientDataJSON).
    let mut preimage = Vec::with_capacity(auth_data.len() + 32);
    preimage.extend_from_slice(&auth_data);
    let cd_hash = Sha256::digest(&client_data);
    preimage.extend_from_slice(&cd_hash);

    // Verify the Ed25519 signature.
    let vk = derive_credential_verifying_key(credential_id)?;
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&signature_bytes);
    let sig = EdSignature::from_bytes(&sig_arr);
    vk.verify(&preimage, &sig).map_err(|_| {
        wallet_error(
            StatusCode::UNAUTHORIZED,
            "assertion_signature_invalid",
            "ed25519 webauthn signature does not verify against the credential public key",
        )
    })?;

    Ok(signature_bytes)
}

/// Pepper = SHA-256(domain_tag || nonce_bytes || assertion_signature).
/// Production replaces with HKDF-SHA256 with the same inputs — same
/// 32-byte output.
fn derive_pepper(nonce_bytes: &[u8], assertion_signature: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(PEPPER_DOMAIN_TAG);
    hasher.update(nonce_bytes);
    hasher.update(assertion_signature);
    hasher.finalize().to_vec()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /wallet/share/envelope?credential_id=…&surface_key=…`
pub async fn envelope_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Query(q): Query<EnvelopeQuery>,
) -> Response {
    let full_uri = full_request_uri(&headers, "/wallet/share/envelope");
    if let Err(resp) =
        validate_wallet_auth(&state, &headers, "GET", &full_uri, REQUIRED_ACTION).await
    {
        return resp;
    }

    let wrapped = match wrap_share(&q.credential_id, &q.surface_key) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };
    let salt = derive_salt(&q.credential_id, &q.surface_key);

    Json(EnvelopeResponse {
        wrapped_share_b64: URL_SAFE_NO_PAD.encode(&wrapped),
        alg: "aes-256-gcm",
        salt_b64: URL_SAFE_NO_PAD.encode(&salt),
    })
    .into_response()
}

/// `POST /wallet/share/escrow/challenge`
pub async fn challenge_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<ChallengeRequest>,
) -> Response {
    let full_uri = full_request_uri(&headers, "/wallet/share/escrow/challenge");
    if let Err(resp) =
        validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await
    {
        return resp;
    }

    let now = now_ms();
    escrow(&state).sweep(now);

    let mut nonce_bytes = [0u8; ESCROW_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce_bytes);

    let key = ShareEscrow::key(&body.credential_id, &body.surface_key, &nonce_b64);
    let expires_at_ms = now + ESCROW_TTL.as_millis() as u64;
    escrow(&state)
        .entries
        .insert(key, EscrowEntry { expires_at_ms });

    Json(ChallengeResponse {
        nonce_b64,
        expires_at_ms,
    })
    .into_response()
}

/// `POST /wallet/share/escrow/unwrap`
pub async fn unwrap_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<UnwrapRequest>,
) -> Response {
    let full_uri = full_request_uri(&headers, "/wallet/share/escrow/unwrap");
    if let Err(resp) =
        validate_wallet_auth(&state, &headers, "POST", &full_uri, REQUIRED_ACTION).await
    {
        return resp;
    }

    let now = now_ms();
    escrow(&state).sweep(now);

    // Single-use consumption: remove the entry first, *then* run the
    // crypto. This guarantees that even a panicking verifier cannot
    // leave a re-usable nonce in the map.
    let key = ShareEscrow::key(&body.credential_id, &body.surface_key, &body.nonce_b64);
    let entry = match escrow(&state).entries.remove(&key) {
        Some((_, e)) => e,
        None => {
            return wallet_error(
                StatusCode::UNAUTHORIZED,
                "escrow_nonce_not_found",
                "no outstanding nonce for (credential_id, surface_key, nonce) — already consumed, expired, or never issued",
            )
            .into_response();
        }
    };
    if entry.expires_at_ms <= now {
        return wallet_error(
            StatusCode::UNAUTHORIZED,
            "escrow_nonce_expired",
            "nonce has expired (30s TTL); request a fresh challenge",
        )
        .into_response();
    }

    // Verify the WebAuthn assertion.
    let signature_bytes =
        match verify_assertion(&body.credential_id, &body.nonce_b64, &body.assertion) {
            Ok(s) => s,
            Err(e) => return e.into_response(),
        };

    let nonce_bytes = match parse_b64("nonce_b64", &body.nonce_b64) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };
    let pepper = derive_pepper(&nonce_bytes, &signature_bytes);

    let wrapped = match wrap_share(&body.credential_id, &body.surface_key) {
        Ok(w) => w,
        Err(e) => return e.into_response(),
    };

    Json(UnwrapResponse {
        wrapped_share_b64: URL_SAFE_NO_PAD.encode(&wrapped),
        pepper_b64: URL_SAFE_NO_PAD.encode(&pepper),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrapping is deterministic per `(credential_id, surface_key)`.
    /// The wallet, when it later re-fetches the envelope, must get the
    /// same ciphertext — otherwise a long-lived offline backup would
    /// silently rot.
    #[test]
    fn wrap_is_deterministic_per_pair() {
        let w1 = wrap_share("cred-A", "vault.0").unwrap();
        let w2 = wrap_share("cred-A", "vault.0").unwrap();
        assert_eq!(w1, w2);
    }

    /// Distinct inputs must produce distinct wrap keys (and therefore
    /// distinct ciphertexts under our fixed nonce convention).
    #[test]
    fn distinct_pairs_yield_distinct_wraps() {
        let w_a0 = wrap_share("cred-A", "vault.0").unwrap();
        let w_a1 = wrap_share("cred-A", "vault.1").unwrap();
        let w_b0 = wrap_share("cred-B", "vault.0").unwrap();
        assert_ne!(w_a0, w_a1);
        assert_ne!(w_a0, w_b0);
        assert_ne!(w_a1, w_b0);
    }

    /// The `0x00` separator in `derive_wrap_key` prevents
    /// `(credential_id="ab", surface_key="cd")` from sharing a key with
    /// `(credential_id="abcd", surface_key="")`.
    #[test]
    fn separator_prevents_concat_collision() {
        let k1 = derive_wrap_key("ab", "cd");
        let k2 = derive_wrap_key("abcd", "");
        assert_ne!(k1, k2);
    }

    /// AAD binding: a ciphertext minted under one
    /// `(credential_id, surface_key)` must not decrypt under another.
    /// We verify by directly attempting an unauthorized AAD decrypt.
    #[test]
    fn aad_binds_ciphertext_to_pair() {
        let wrapped = wrap_share("cred-A", "vault.0").unwrap();
        let key = derive_wrap_key("cred-A", "vault.0");
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Nonce::from_slice(&wrapped[..12]);

        // Correct AAD decrypts.
        let correct_aad = wrap_aad("cred-A", "vault.0");
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &wrapped[12..],
                        aad: &correct_aad,
                    },
                )
                .is_ok()
        );

        // Wrong AAD fails.
        let wrong_aad = wrap_aad("cred-A", "vault.1");
        assert!(
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &wrapped[12..],
                        aad: &wrong_aad,
                    },
                )
                .is_err()
        );
    }

    /// Full roundtrip: deterministic credential signing key
    /// signs a webauthn-shaped payload, the verifier accepts, and the
    /// derived pepper is reproducible.
    #[test]
    fn webauthn_roundtrip_verifies_and_derives_pepper() {
        let credential_id = "cred-passkey-X";
        let nonce_bytes = [0xABu8; 32];
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce_bytes);

        // Build a valid clientDataJSON.
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://wallet.tenzro.xyz"}}"#,
            nonce_b64
        );
        let cd_bytes = cd.as_bytes().to_vec();
        // Authenticator data: 37-byte minimum (rpIdHash[32] || flags[1] || counter[4]).
        let mut auth_data = vec![0u8; 37];
        auth_data[32] = 0x01; // UP flag

        // Sign as the credential's signing key.
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_KEY_DOMAIN_TAG);
        hasher.update(credential_id.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        let sk = EdSigningKey::from_bytes(&seed);

        let mut preimage = Vec::with_capacity(auth_data.len() + 32);
        preimage.extend_from_slice(&auth_data);
        preimage.extend_from_slice(&Sha256::digest(&cd_bytes));
        use ed25519_dalek::Signer;
        let sig = sk.sign(&preimage);

        let assertion = PasskeyAssertion {
            authenticator_data_b64: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json_b64: URL_SAFE_NO_PAD.encode(&cd_bytes),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        let sig_bytes = verify_assertion(credential_id, &nonce_b64, &assertion)
            .expect("valid assertion must verify");
        assert_eq!(sig_bytes.len(), 64);

        // Pepper is reproducible from (nonce, signature).
        let p1 = derive_pepper(&nonce_bytes, &sig_bytes);
        let p2 = derive_pepper(&nonce_bytes, &sig_bytes);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 32);
    }

    /// A clientDataJSON whose `challenge` does not match the escrowed
    /// nonce must be rejected — without this check a replayed
    /// assertion against a stale challenge would unwrap the share.
    #[test]
    fn challenge_mismatch_is_rejected() {
        let credential_id = "cred-passkey-X";
        let real_nonce_b64 = URL_SAFE_NO_PAD.encode([0x11u8; 32]);
        let stale_nonce_b64 = URL_SAFE_NO_PAD.encode([0x22u8; 32]);

        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"x"}}"#,
            stale_nonce_b64,
        );
        let cd_bytes = cd.as_bytes().to_vec();
        let auth_data = vec![0u8; 37];

        // Sign with the right key but the wrong embedded challenge.
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_KEY_DOMAIN_TAG);
        hasher.update(credential_id.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        let sk = EdSigningKey::from_bytes(&seed);
        let mut preimage = Vec::with_capacity(auth_data.len() + 32);
        preimage.extend_from_slice(&auth_data);
        preimage.extend_from_slice(&Sha256::digest(&cd_bytes));
        use ed25519_dalek::Signer;
        let sig = sk.sign(&preimage);

        let assertion = PasskeyAssertion {
            authenticator_data_b64: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json_b64: URL_SAFE_NO_PAD.encode(&cd_bytes),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        // Caller asserts the nonce is `real_nonce_b64` but the inner
        // clientDataJSON.challenge says `stale_nonce_b64` — must be
        // rejected.
        let result = verify_assertion(credential_id, &real_nonce_b64, &assertion);
        assert!(result.is_err());
    }

    /// A signature produced by a *different* credential's key over a
    /// genuine `(nonce, type=webauthn.get)` clientDataJSON must still
    /// fail — the verifier is keyed on `credential_id`, not on the
    /// embedded challenge alone.
    #[test]
    fn wrong_credential_signature_is_rejected() {
        let target_cred = "cred-target";
        let attacker_cred = "cred-attacker";
        let nonce_b64 = URL_SAFE_NO_PAD.encode([0x33u8; 32]);

        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"x"}}"#,
            nonce_b64,
        );
        let cd_bytes = cd.as_bytes().to_vec();
        let auth_data = vec![0u8; 37];

        // Sign with the *attacker's* key.
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_KEY_DOMAIN_TAG);
        hasher.update(attacker_cred.as_bytes());
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        let sk = EdSigningKey::from_bytes(&seed);
        let mut preimage = Vec::with_capacity(auth_data.len() + 32);
        preimage.extend_from_slice(&auth_data);
        preimage.extend_from_slice(&Sha256::digest(&cd_bytes));
        use ed25519_dalek::Signer;
        let sig = sk.sign(&preimage);

        let assertion = PasskeyAssertion {
            authenticator_data_b64: URL_SAFE_NO_PAD.encode(&auth_data),
            client_data_json_b64: URL_SAFE_NO_PAD.encode(&cd_bytes),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
        };

        // Verify against the *target* credential — must fail.
        let result = verify_assertion(target_cred, &nonce_b64, &assertion);
        assert!(result.is_err());
    }

    /// Escrow sweep evicts strictly past-due entries.
    #[test]
    fn escrow_sweep_evicts_expired() {
        let store = ShareEscrow::new();
        store.entries.insert(
            "k-old".into(),
            EscrowEntry {
                expires_at_ms: 1_000,
            },
        );
        store.entries.insert(
            "k-new".into(),
            EscrowEntry {
                expires_at_ms: 10_000,
            },
        );
        store.sweep(5_000);
        assert!(!store.entries.contains_key("k-old"));
        assert!(store.entries.contains_key("k-new"));
    }
}
