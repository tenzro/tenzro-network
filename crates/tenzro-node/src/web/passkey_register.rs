//! Passkey credential enrolment: `POST /wallet/passkey/register`.
//!
//! Exposed on the public Web API. A Tenzro-aware wallet enrols the public key
//! its WebAuthn authenticator produced at registration; every later assertion
//! is checked against what is stored here (see `passkey_registry`). The passkey
//! credential gates the permissionless wallet — the classical key is hardware
//! held and no assertion is accepted for a credential this node never saw.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use super::error::WalletApiError;
use super::handlers::WebState;
use super::oauth::{full_request_uri, validate_wallet_auth};

const REGISTER_ACTION: &str = "wallet.passkey.register";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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

fn default_require_uv() -> bool {
    true
}

/// The public key is the one the authenticator produced at registration —
/// taken from the WebAuthn attestation by the client. Registration is the only
/// moment this node learns it; every later assertion is checked against what is
/// stored here.
#[derive(Debug, Deserialize)]
pub struct PasskeyRegisterRequest {
    /// Authenticator-chosen credential id, as it will appear in assertions.
    pub credential_id: String,
    /// Raw public key: 32 bytes for Ed25519, or the 64-byte `(x, y)` pair for
    /// ES256. Base64url, no padding.
    pub public_key_b64: String,
    /// `"ed25519"` (COSE -8) or `"es256"` (COSE -7).
    pub algorithm: String,
    /// Relying-party id the credential was created for.
    pub rp_id: String,
    /// Exact origin permitted to present this credential.
    pub origin: String,
    /// Whether assertions must carry the User Verified flag. Defaults to true:
    /// this credential gates the wallet, so a stolen unlocked device should not
    /// be enough.
    #[serde(default = "default_require_uv")]
    pub require_user_verification: bool,
}

/// What was enrolled.
#[derive(Debug, Serialize)]
pub struct PasskeyRegisterResponse {
    /// The credential id now on file.
    pub credential_id: String,
    /// Number of credentials this node holds.
    pub registered_count: usize,
}

/// `POST /wallet/passkey/register` — enrol a passkey credential.
///
/// Without this there is no way to register a credential at all, and every
/// assertion would fail as unknown. Verification checks each assertion against
/// the key the authenticator registered here — nothing is derived from the
/// credential id, which is public, so a seen credential id cannot be used to
/// mint assertions that verify.
///
/// A credential id may be enrolled once. Re-registering is refused rather than
/// overwritten: silently replacing the key a credential authenticates against
/// is the same attack by another route.
pub async fn passkey_register_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
    Json(body): Json<PasskeyRegisterRequest>,
) -> Response {
    use super::passkey_registry::{CoseAlgorithm, PasskeyCredential};

    let full_uri = full_request_uri(&headers, "/wallet/passkey/register");
    if let Err(resp) =
        validate_wallet_auth(&state, &headers, "POST", &full_uri, REGISTER_ACTION).await
    {
        return resp;
    }

    let algorithm = match body.algorithm.to_ascii_lowercase().as_str() {
        "ed25519" | "eddsa" => CoseAlgorithm::Ed25519,
        "es256" | "p256" => CoseAlgorithm::Es256,
        other => {
            return wallet_error(
                StatusCode::BAD_REQUEST,
                "unsupported_algorithm",
                &format!("algorithm must be ed25519 or es256, got {other}"),
            )
            .into_response();
        }
    };

    let public_key = match parse_b64("public_key_b64", &body.public_key_b64) {
        Ok(b) => b,
        Err(e) => return e.into_response(),
    };

    if body.rp_id.trim().is_empty() || body.origin.trim().is_empty() {
        return wallet_error(
            StatusCode::BAD_REQUEST,
            "missing_binding",
            "rp_id and origin are required — without them an assertion made for \
             another site would be accepted here",
        )
        .into_response();
    }

    let credential = PasskeyCredential {
        credential_id: body.credential_id.clone(),
        public_key,
        algorithm,
        rp_id: body.rp_id,
        origin: body.origin,
        // Starts at zero: many platform authenticators never keep a counter,
        // and a stored zero disables the replay check rather than locking the
        // credential out. The first assertion that reports a real counter
        // begins enforcing monotonicity.
        sign_count: 0,
        require_user_verification: body.require_user_verification,
        created_at: now_ms() / 1000,
    };

    match state.passkey_registry.register(credential) {
        Ok(()) => Json(PasskeyRegisterResponse {
            credential_id: body.credential_id,
            registered_count: state.passkey_registry.len(),
        })
        .into_response(),
        Err(e) => {
            use super::passkey_registry::PasskeyError;
            let (status, code) = match e {
                PasskeyError::DuplicateCredential(_) => {
                    (StatusCode::CONFLICT, "credential_already_registered")
                }
                PasskeyError::BadKeyLength { .. } => (StatusCode::BAD_REQUEST, "bad_key_length"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "registration_failed"),
            };
            wallet_error(status, code, &e.to_string()).into_response()
        }
    }
}
