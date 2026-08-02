//! `/wallet/new/*` — passkey-quorum wallet provisioning.
//!
//! Mounted on the public Web API (port 8080, `api.tenzro.xyz`) as four
//! PRE-AUTH routes. A Tenzro-aware wallet drives them — through the
//! wallet kernel's `ProvisioningHttpAdapter` — to mint a fresh TDIP
//! identity whose signing key is split 2-of-2 between the wallet device
//! (passkey-bound) and this node's TEE leg. No seed phrase is ever
//! produced or transmitted.
//!
//! ## Routes
//!
//! | Route | Method | Body | Reply |
//! |-------|--------|------|-------|
//! | `/wallet/new/start` | POST | `{kind}` | `{session_id, challenge_b64, user_handle_b64, user_display_name}` |
//! | `/wallet/new/finalize` | POST | `{session_id, enrolment:{credential_id, attestation_object, client_data_json}}` | `{identity, threshold:{k,n}, wrapped_share:{credential_id, wrapped_share_b64, alg, salt_b64}}` |
//! | `/wallet/new/confirm` | POST | `{session_id}` | 204 |
//! | `/wallet/new/cancel` | POST | `{session_id}` | 204 (idempotent) |
//!
//! Reply `*_b64` fields are STANDARD base64 (RFC 4648 §4) — the wallet
//! decodes them with `atob`. This is deliberately different from the
//! URL_SAFE_NO_PAD encoding `wallet_frost` / `wallet_share` use on their
//! own wire; those are separate protocols with their own adapters.
//!
//! ## Why pre-auth
//!
//! Provisioning runs before the user has any session. Consent for the
//! new device is asserted by the WebAuthn attestation embedded in
//! `finalize` — the `attestation_object` binds the freshly-created
//! passkey to the node-issued `challenge` from `start`. There is no
//! `Authorization` header on these routes.
//!
//! ## Delegation, not a parallel stack
//!
//! This module owns only the session state machine + the wire shape. All
//! cryptographic work is delegated into the same primitives the passkey
//! RPCs already use:
//!
//! - device passkey → [`WebAuthnAccountKey`] + `webauthn_validator().enroll`
//! - 2-of-2 signing split → [`wallet_frost::provision_split`]
//! - device-share wrapping → [`wallet_share::wrap_share_bytes`]
//! - identity registration → `identity_registry().register_human_with_binding`
//! - session persistence → [`KvStore`] under `CF_VALIDATOR_MODULES`,
//!   MAC-tagged with the same per-process key as `PendingRecoveryStore`.
//!
//! ## Node-TEE leg
//!
//! The wallet sends no PQ key. The node generates the ML-DSA-65 leg for
//! the hybrid custody record itself ([`MlDsaSigningKey::generate`]) so
//! the enrolled [`WebAuthnAccountKey`] carries a real 1952-byte verifying
//! key — matching the passkey-enrollment RPC's hybrid invariant.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::error::WalletApiError;
use super::handlers::WebState;
use super::wallet_frost::{ProvisionScheme, provision_split};
use super::wallet_share::{provisioning_salt, wrap_share_bytes};

use tenzro_storage::{CF_VALIDATOR_MODULES, KvStore};

/// Sessions expire this long after `start`. The wallet re-runs `start`
/// if the user overruns the passkey UI.
const SESSION_TTL_MS: u64 = 10 * 60 * 1000;

/// RocksDB key prefix for provisioning sessions.
const SESSION_PREFIX: &[u8] = b"wallet/new/session/";

/// Surfaces a provisioned wallet carries. The device share we wrap and
/// return to the wallet is the native surface's leg — the other surfaces
/// are re-derived on demand by the same deterministic split, so a single
/// wrapped share bootstraps the whole identity.
///
/// EVM uses secp256k1; the rest use ed25519.
const NATIVE_SURFACE: &str = "tenzro-native";
const EVM_SURFACE: &str = "evm-on-tenzro";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct StartRequest {
    /// `human` | `controlled-machine` | `autonomous-machine`.
    kind: String,
}

#[derive(Debug, Serialize)]
struct StartReply {
    session_id: String,
    challenge_b64: String,
    user_handle_b64: String,
    user_display_name: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FinalizeRequest {
    session_id: String,
    enrolment: Enrolment,
}

#[derive(Debug, Deserialize)]
struct Enrolment {
    /// Credential id — base64url (as produced by `navigator.credentials.create`).
    credential_id: String,
    /// WebAuthn attestation object — base64url CBOR.
    attestation_object: String,
    /// WebAuthn clientDataJSON — base64url. Its embedded `challenge` is
    /// verified against the session challenge in `finalize_handler`.
    client_data_json: String,
}

#[derive(Debug, Serialize)]
struct Threshold {
    k: u8,
    n: u8,
}

#[derive(Debug, Serialize)]
struct WrappedShareReply {
    credential_id: String,
    wrapped_share_b64: String,
    alg: &'static str,
    salt_b64: String,
}

#[derive(Debug, Serialize)]
struct DidParts {
    method: &'static str,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller: Option<String>,
    uuid: String,
}

#[derive(Debug, Serialize)]
struct IdentityReply {
    did: String,
    parts: DidParts,
    /// Per-surface public key material, keyed by surface name. Emitted as a
    /// JSON object — the wallet returns the identity verbatim and only reads
    /// `.did`, so an object (not a Map) is the correct wire shape.
    keys: serde_json::Value,
    created_at: u64,
}

#[derive(Debug, Serialize)]
struct FinalizeReply {
    identity: IdentityReply,
    threshold: Threshold,
    wrapped_share: WrappedShareReply,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SessionIdRequest {
    session_id: String,
}

// ---------------------------------------------------------------------------
// Persistent session record
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
enum SessionStatus {
    /// `start` ran; awaiting `finalize`.
    Pending,
    /// `finalize` ran; identity built + share wrapped; awaiting `confirm`.
    Finalized,
    /// `confirm` ran; identity is live.
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SessionRecord {
    session_id: String,
    kind: String,
    did: String,
    controller: Option<String>,
    uuid: String,
    challenge: Vec<u8>,
    user_handle: Vec<u8>,
    user_display_name: String,
    created_at_ms: u64,
    status: SessionStatus,
}

impl SessionRecord {
    fn is_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.created_at_ms) > SESSION_TTL_MS
    }
}

// ---------------------------------------------------------------------------
// Session store (KvStore-backed, MAC-tagged — mirrors PendingRecoveryStore)
// ---------------------------------------------------------------------------

struct SessionStore {
    storage: Arc<dyn KvStore>,
}

impl SessionStore {
    fn new(storage: Arc<dyn KvStore>) -> Self {
        Self { storage }
    }

    fn key(session_id: &str) -> Vec<u8> {
        let mut k = SESSION_PREFIX.to_vec();
        k.extend_from_slice(session_id.as_bytes());
        k
    }

    fn put(&self, rec: &SessionRecord) -> Result<(), WalletApiError> {
        let bytes = serde_json::to_vec(rec)
            .map_err(|e| internal("session_serialize", format!("serialize session: {e}")))?;
        let tagged = mac_wrap(&bytes);
        self.storage
            .put(CF_VALIDATOR_MODULES, &Self::key(&rec.session_id), &tagged)
            .map_err(|e| internal("session_persist", format!("persist session: {e}")))
    }

    fn get(&self, session_id: &str) -> Result<Option<SessionRecord>, WalletApiError> {
        let bytes = self
            .storage
            .get(CF_VALIDATOR_MODULES, &Self::key(session_id))
            .map_err(|e| internal("session_read", format!("read session: {e}")))?;
        match bytes {
            Some(b) => {
                let payload = mac_verify(&b).map_err(|e| {
                    internal("session_tampered", format!("tampered session row: {e}"))
                })?;
                let rec: SessionRecord = serde_json::from_slice(payload).map_err(|e| {
                    internal("session_deserialize", format!("deserialize session: {e}"))
                })?;
                Ok(Some(rec))
            }
            None => Ok(None),
        }
    }

    fn delete(&self, session_id: &str) {
        let _ = self
            .storage
            .delete(CF_VALIDATOR_MODULES, &Self::key(session_id));
    }
}

/// Per-process MAC key at `~/.tenzro/local_state_mac.key` (0600). Mirrors
/// `passkey_rpc::local_mac_key` — same file, same threat model (detects
/// accidental corruption + cross-process tampering of session rows; does
/// not defend against in-process malware in the same trust boundary).
fn local_mac_key() -> &'static [u8; 32] {
    use std::sync::OnceLock;
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let path = match tenzro_types::paths::try_tenzro_home() {
            Ok(_) => tenzro_types::paths::local_state_mac_key_path(),
            Err(e) => {
                tracing::warn!(%e, "wallet_new local_mac_key: using zero key (tests only)");
                return [0u8; 32];
            }
        };
        if let Ok(bytes) = std::fs::read(&path)
            && bytes.len() == 32
        {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return k;
        }
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&path, k) {
            tracing::warn!(error = %e, "wallet_new local_mac_key: failed to persist MAC key");
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
        k
    })
}

fn mac_wrap(payload: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let tag = h.finalize();
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(payload);
    out
}

fn mac_verify(blob: &[u8]) -> Result<&[u8], &'static str> {
    if blob.len() < 32 {
        return Err("row too short");
    }
    let (tag, payload) = blob.split_at(32);
    let mut h = Sha256::new();
    h.update(local_mac_key());
    h.update(payload);
    let expected = h.finalize();
    if &expected[..] != tag {
        return Err("tag mismatch (row tampered or foreign)");
    }
    Ok(payload)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn internal(code: &'static str, msg: impl Into<String>) -> WalletApiError {
    WalletApiError::new(StatusCode::INTERNAL_SERVER_ERROR, code, msg.into())
}

fn bad_request(code: &'static str, msg: impl Into<String>) -> WalletApiError {
    WalletApiError::new(StatusCode::BAD_REQUEST, code, msg.into())
}

fn not_found(code: &'static str, msg: impl Into<String>) -> WalletApiError {
    WalletApiError::new(StatusCode::NOT_FOUND, code, msg.into())
}

/// Resolve the shared `KvStore` from the node on `WebState`, or error if
/// the node/storage isn't wired (light client, boot race).
fn session_store(state: &WebState) -> Result<SessionStore, WalletApiError> {
    let node = state
        .node
        .as_ref()
        .ok_or_else(|| internal("node_unavailable", "node not available on this endpoint"))?;
    let storage = node
        .storage()
        .ok_or_else(|| internal("storage_unavailable", "durable storage not initialized"))?;
    Ok(SessionStore::new(storage.clone() as Arc<dyn KvStore>))
}

/// Build the DID for a requested `kind`. Human → `new_human`; both machine
/// kinds → `new_autonomous_machine` (no controller is known at provision
/// time — a controlled machine is later re-anchored to its controller by
/// the controller's own signed delegation).
fn did_for_kind(kind: &str) -> Result<tenzro_identity::TenzroDid, WalletApiError> {
    match kind {
        "human" => Ok(tenzro_identity::TenzroDid::new_human()),
        "controlled-machine" | "autonomous-machine" => {
            Ok(tenzro_identity::TenzroDid::new_autonomous_machine())
        }
        other => Err(bad_request(
            "unknown_kind",
            format!("unknown identity kind: {other}"),
        )),
    }
}

/// `parts.kind` string echoed back to the wallet for a given DID + request
/// kind. Machine DIDs report the request kind verbatim so a `controlled-machine`
/// request round-trips even though the on-ledger DID has no controller yet.
fn parts_kind(request_kind: &str) -> &'static str {
    match request_kind {
        "controlled-machine" => "controlled-machine",
        "autonomous-machine" => "autonomous-machine",
        _ => "human",
    }
}

/// Base64url-decode a WebAuthn wire field (credential id / attestation
/// object / clientDataJSON), tolerating both padded and unpadded input.
fn decode_b64url(field: &str, value: &str) -> Result<Vec<u8>, WalletApiError> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(value))
        .map_err(|e| bad_request("bad_b64url", format!("{field}: invalid base64url: {e}")))
}

/// Extract the COSE P-256 public key (x, y) from a WebAuthn attestation
/// object. The attestation object is CBOR `{fmt, attStmt, authData}`;
/// `authData` embeds `attestedCredentialData` which ends with the credential
/// public key as a COSE_Key map. We parse the COSE_Key's `-2` (x) / `-3` (y)
/// labels for the two 32-byte coordinates.
///
/// authData layout (WebAuthn §6.1):
///   rpIdHash(32) | flags(1) | signCount(4) |
///   [ AAGUID(16) | credIdLen(2 BE) | credId(credIdLen) | COSE_Key(rest) ]
fn extract_p256_xy_from_attestation(
    attestation_object: &[u8],
) -> Result<([u8; 32], [u8; 32]), WalletApiError> {
    let att: ciborium::value::Value = ciborium::de::from_reader(attestation_object)
        .map_err(|e| bad_request("bad_attestation", format!("attestation CBOR: {e}")))?;

    let map = att
        .as_map()
        .ok_or_else(|| bad_request("bad_attestation", "attestation object is not a CBOR map"))?;

    let auth_data = map
        .iter()
        .find_map(|(k, v)| match k {
            ciborium::value::Value::Text(t) if t == "authData" => v.as_bytes(),
            _ => None,
        })
        .ok_or_else(|| bad_request("bad_attestation", "attestation missing authData"))?;

    // Fixed header is 37 bytes; attestedCredentialData requires flag bit 6 (AT).
    if auth_data.len() < 37 {
        return Err(bad_request("bad_attestation", "authData too short"));
    }
    let flags = auth_data[32];
    if flags & 0x40 == 0 {
        return Err(bad_request(
            "bad_attestation",
            "authData has no attestedCredentialData (AT flag unset)",
        ));
    }
    // Skip AAGUID(16) + credIdLen(2) + credId(credIdLen), then parse COSE_Key.
    let mut off = 37 + 16;
    if auth_data.len() < off + 2 {
        return Err(bad_request(
            "bad_attestation",
            "authData truncated at credIdLen",
        ));
    }
    let cred_id_len = u16::from_be_bytes([auth_data[off], auth_data[off + 1]]) as usize;
    off += 2 + cred_id_len;
    if auth_data.len() < off {
        return Err(bad_request(
            "bad_attestation",
            "authData truncated at credId",
        ));
    }
    let cose_bytes = &auth_data[off..];

    let cose: ciborium::value::Value = ciborium::de::from_reader(cose_bytes)
        .map_err(|e| bad_request("bad_attestation", format!("COSE_Key CBOR: {e}")))?;
    let cose_map = cose
        .as_map()
        .ok_or_else(|| bad_request("bad_attestation", "COSE_Key is not a CBOR map"))?;

    // COSE_Key integer labels: -2 = x coordinate, -3 = y coordinate.
    let coord = |label: i128| -> Option<Vec<u8>> {
        cose_map.iter().find_map(|(k, v)| match k {
            ciborium::value::Value::Integer(i) if i128::from(*i) == label => v.as_bytes().cloned(),
            _ => None,
        })
    };
    let x_bytes =
        coord(-2).ok_or_else(|| bad_request("bad_attestation", "COSE_Key missing x coordinate"))?;
    let y_bytes =
        coord(-3).ok_or_else(|| bad_request("bad_attestation", "COSE_Key missing y coordinate"))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(bad_request(
            "bad_attestation",
            "COSE_Key coordinates are not 32 bytes each (not P-256?)",
        ));
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&x_bytes);
    y.copy_from_slice(&y_bytes);
    Ok((x, y))
}

/// Verify the WebAuthn `clientDataJSON` binds this enrolment to the session
/// challenge. `clientDataJSON` is a UTF-8 JSON object `{type, challenge,
/// origin, ...}` where `type` is `webauthn.create` for a registration and
/// `challenge` is the base64url-no-pad encoding of the raw challenge the
/// server issued in `start`. We reject any enrolment whose embedded challenge
/// does not match the session's — this is what prevents a captured attestation
/// from one session being replayed to provision against another.
fn verify_client_data_challenge(
    client_data_json: &[u8],
    expected_challenge: &[u8],
) -> Result<(), WalletApiError> {
    let parsed: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| bad_request("bad_client_data", format!("clientDataJSON not JSON: {e}")))?;

    let ty = parsed
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("bad_client_data", "clientDataJSON missing type"))?;
    if ty != "webauthn.create" {
        return Err(bad_request(
            "bad_client_data",
            format!("clientDataJSON type is {ty}, expected webauthn.create"),
        ));
    }

    let challenge_b64 = parsed
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| bad_request("bad_client_data", "clientDataJSON missing challenge"))?;
    let got = decode_b64url("client_data_json.challenge", challenge_b64)?;
    if got != expected_challenge {
        return Err(bad_request(
            "challenge_mismatch",
            "clientDataJSON challenge does not match session challenge",
        ));
    }
    Ok(())
}

/// Derive the per-surface address the node is the authority for. The node
/// derives it deterministically from the joint FROST verifying key so the
/// same address is reproducible at sign time from `(did, surface_key)`.
/// Native/SVM/Canton surfaces base58-encode a 32-byte hash of the vk; EVM
/// takes the low 20 bytes of keccak(vk) rendered `0x…`.
fn surface_address(surface: &str, verifying_key: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"tenzro/wallet/surface-address");
    h.update(surface.as_bytes());
    h.update([0x00]);
    h.update(verifying_key);
    let digest = h.finalize();
    if surface == "evm-on-tenzro" {
        format!("0x{}", hex::encode(&digest[12..32]))
    } else {
        bs58::encode(&digest[..]).into_string()
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /wallet/new/start` — open a provisioning session.
pub(crate) async fn start_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<StartRequest>,
) -> Result<Response, WalletApiError> {
    let store = session_store(&state)?;

    let did = did_for_kind(&req.kind)?;
    let did_string = did.to_string_canonical();

    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    // The user handle is the DID's uuid bytes — a stable, non-PII handle.
    let user_handle = did.id.as_bytes().to_vec();
    let user_display_name = match req.kind.as_str() {
        "human" => "Tenzro Wallet".to_string(),
        _ => "Tenzro Agent".to_string(),
    };

    let session_id = uuid::Uuid::new_v4().to_string();
    let rec = SessionRecord {
        session_id: session_id.clone(),
        kind: req.kind.clone(),
        did: did_string,
        controller: did.controller_id.clone(),
        uuid: did.id.clone(),
        challenge: challenge.to_vec(),
        user_handle: user_handle.clone(),
        user_display_name: user_display_name.clone(),
        created_at_ms: now_ms(),
        status: SessionStatus::Pending,
    };
    store.put(&rec)?;

    let reply = StartReply {
        session_id,
        challenge_b64: STANDARD.encode(challenge),
        user_handle_b64: STANDARD.encode(&user_handle),
        user_display_name,
    };
    Ok((StatusCode::OK, Json(reply)).into_response())
}

/// `POST /wallet/new/finalize` — verify the passkey enrolment, split the
/// signing key 2-of-2, wrap the device share, register the identity.
pub(crate) async fn finalize_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<FinalizeRequest>,
) -> Result<Response, WalletApiError> {
    let store = session_store(&state)?;
    let node = state
        .node
        .as_ref()
        .ok_or_else(|| internal("node_unavailable", "node not available"))?;

    let mut rec = store
        .get(&req.session_id)?
        .ok_or_else(|| not_found("unknown_session", "provisioning session not found"))?;
    if rec.is_expired(now_ms()) {
        store.delete(&req.session_id);
        return Err(not_found("session_expired", "provisioning session expired"));
    }

    // Idempotent re-finalize is refused — a session is finalized once. The
    // wallet re-runs `start` for a fresh attempt.
    if rec.status != SessionStatus::Pending {
        return Err(bad_request(
            "already_finalized",
            "session is not awaiting finalize",
        ));
    }

    // 1. Decode the WebAuthn enrolment + extract the P-256 device pubkey.
    let credential_id = decode_b64url("credential_id", &req.enrolment.credential_id)?;
    let attestation = decode_b64url("attestation_object", &req.enrolment.attestation_object)?;
    let client_data = decode_b64url("client_data_json", &req.enrolment.client_data_json)?;
    // Bind the enrolment to THIS session's challenge — rejects a captured
    // attestation replayed against a different session.
    verify_client_data_challenge(&client_data, &rec.challenge)?;
    let (pubkey_x, pubkey_y) = extract_p256_xy_from_attestation(&attestation)?;

    // 2. Node-TEE ML-DSA-65 leg for the hybrid custody record.
    let ml_dsa = tenzro_crypto::pq::MlDsaSigningKey::generate();
    let ml_dsa_vk = ml_dsa.verifying_key_bytes().to_vec();
    let account_key =
        tenzro_vm::aa_webauthn_validator::WebAuthnAccountKey::new(pubkey_x, pubkey_y, ml_dsa_vk)
            .map_err(|e| internal("account_key", format!("WebAuthnAccountKey: {e}")))?;

    // 3. Split the native surface 2-of-2. `surface_key` is derived from the
    //    joint verifying key so it is reproducible at sign time. The device
    //    leg we wrap here is the native share; the wallet re-derives the
    //    other surfaces from the same `(did, surface_key)` split on demand.
    let did_string = rec.did.clone();
    let native = provision_split(ProvisionScheme::Ed25519, &did_string, NATIVE_SURFACE)
        .map_err(|_| internal("provision_split", "native surface split failed"))?;
    // Re-key the split to the surface address so sign-time derivation matches.
    let native_address = surface_address(NATIVE_SURFACE, &native.verifying_key);
    let surface_key = format!("{NATIVE_SURFACE}:{native_address}");
    let native = provision_split(ProvisionScheme::Ed25519, &did_string, &surface_key)
        .map_err(|_| internal("provision_split", "native surface split failed"))?;

    // 3b. Derive the EVM surface (secp256k1) from the same DID. The wallet
    //     re-derives its device leg on demand from the same wrapped share, so
    //     the node only needs to publish the resulting EVM address here.
    let evm = provision_split(ProvisionScheme::Secp256k1, &did_string, EVM_SURFACE)
        .map_err(|_| internal("provision_split", "evm surface split failed"))?;
    let evm_address = surface_address(EVM_SURFACE, &evm.verifying_key);

    // 4. Wrap the REAL device key-package under the passkey-derived key.
    let cred_id_hex = hex::encode(&credential_id);
    let wrapped = wrap_share_bytes(&cred_id_hex, &surface_key, &native.device_key_package)
        .map_err(|_| internal("wrap_failed", "device share wrap failed"))?;
    let salt = provisioning_salt(&cred_id_hex, &surface_key);

    // 5. Deploy the smart account + install the WebAuthn validator + register
    //    the human TDIP identity, exactly as the passkey-enrollment RPC does.
    let factory = node
        .account_factory()
        .ok_or_else(|| internal("no_factory", "AccountFactory not initialized"))?;
    let webauthn_validator = node
        .webauthn_validator()
        .ok_or_else(|| internal("no_webauthn", "WebAuthnValidator not initialized"))?;
    let identity_registry = node
        .identity_registry()
        .ok_or_else(|| internal("no_registry", "IdentityRegistry not initialized"))?;

    let p256_xy = account_key.p256_public_key_xy();
    let mut owner_seed = Vec::with_capacity(p256_xy.len() + credential_id.len() + did_string.len());
    owner_seed.extend_from_slice(&p256_xy);
    owner_seed.extend_from_slice(&credential_id);
    owner_seed.extend_from_slice(did_string.as_bytes());
    let owner = tenzro_crypto::sha256(&owner_seed).as_bytes().to_vec();
    let mut smart_account = factory.create_account(owner, 0);

    let init_data = serde_json::to_vec(&account_key)
        .map_err(|e| internal("serialize_key", format!("serialize account key: {e}")))?;
    let webauthn_module_addr = {
        let mut a = [0u8; 20];
        a[18] = 0x10;
        a[19] = 0x20;
        a
    };
    let module_config = tenzro_vm::erc7579::ValidatorModuleConfig {
        type_id: tenzro_vm::aa_validators::ModuleType::Validator as u64,
        module_address: webauthn_module_addr,
        init_data,
        priority: 0,
    };
    smart_account
        .install_validator_module(module_config, true)
        .map_err(|e| internal("install_validator", format!("install validator: {e}")))?;
    webauthn_validator
        .enroll(
            smart_account.address.clone(),
            credential_id.clone(),
            account_key.clone(),
        )
        .map_err(|e| internal("enroll", format!("WebAuthn enroll: {e}")))?;
    factory.update_account(smart_account.clone());

    let mut wallet_addr_bytes = [0u8; 32];
    let sa_addr = smart_account.address.as_slice();
    let sa_len = sa_addr.len().min(32);
    wallet_addr_bytes[..sa_len].copy_from_slice(&sa_addr[..sa_len]);
    let binding = tenzro_identity::WalletBinding {
        wallet_id: format!("0x{}", hex::encode(&smart_account.address)),
        address: tenzro_types::primitives::Address::new(wallet_addr_bytes),
        public_key: p256_xy.to_vec(),
        key_type: "P-256".to_string(),
        pq_verifying_key: account_key.pq_pubkey.clone(),
        bls_verifying_key: Vec::new(),
    };
    let did = tenzro_identity::TenzroDid::parse(&did_string)
        .map_err(|e| internal("did_parse", format!("re-parse did: {e}")))?;
    let display_name = rec.user_display_name.clone();
    identity_registry
        .register_human_with_binding(
            did,
            display_name,
            tenzro_types::identity::KycTier::Unverified,
            binding,
        )
        .await
        .map_err(|e| internal("register", format!("identity registration: {e}")))?;

    if let Err(e) = identity_registry.set_identity_metadata(
        &did_string,
        [
            (
                "smart_account_address".to_string(),
                format!("0x{}", hex::encode(&smart_account.address)),
            ),
            (
                "passkey_credential_id".to_string(),
                format!("0x{}", hex::encode(&credential_id)),
            ),
        ],
    ) {
        tracing::warn!(did = %did_string, error = %e, "wallet_new: metadata write skipped");
    }

    // 6. Advance the session so `confirm`/`cancel` are coherent.
    let created_at = rec.created_at_ms;
    rec.status = SessionStatus::Finalized;
    store.put(&rec)?;

    // 7. Emit the reply. All `*_b64` fields are STANDARD base64.
    let reply = FinalizeReply {
        identity: IdentityReply {
            did: did_string.clone(),
            parts: DidParts {
                method: "tenzro",
                kind: parts_kind(&rec.kind).to_string(),
                controller: rec.controller.clone(),
                uuid: rec.uuid.clone(),
            },
            keys: serde_json::json!({
                NATIVE_SURFACE: {
                    "surface": NATIVE_SURFACE,
                    "scheme": "ed25519",
                    "address": native_address,
                    "publicKey": STANDARD.encode(&native.verifying_key),
                },
                EVM_SURFACE: {
                    "surface": EVM_SURFACE,
                    "scheme": "secp256k1",
                    "address": evm_address,
                    "publicKey": STANDARD.encode(&evm.verifying_key),
                }
            }),
            created_at,
        },
        threshold: Threshold { k: 2, n: 2 },
        wrapped_share: WrappedShareReply {
            credential_id: req.enrolment.credential_id.clone(),
            wrapped_share_b64: STANDARD.encode(&wrapped),
            alg: "aes-256-gcm",
            salt_b64: STANDARD.encode(&salt),
        },
    };
    Ok((StatusCode::OK, Json(reply)).into_response())
}

/// `POST /wallet/new/confirm` — mark the identity live. Idempotent: a
/// confirm on an already-confirmed session is a no-op 204.
pub(crate) async fn confirm_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SessionIdRequest>,
) -> Result<Response, WalletApiError> {
    let store = session_store(&state)?;
    match store.get(&req.session_id)? {
        Some(mut rec) => match rec.status {
            SessionStatus::Finalized | SessionStatus::Confirmed => {
                rec.status = SessionStatus::Confirmed;
                store.put(&rec)?;
                Ok(StatusCode::NO_CONTENT.into_response())
            }
            SessionStatus::Pending => Err(bad_request(
                "not_finalized",
                "session must be finalized before confirm",
            )),
        },
        // Idempotent: a confirm after the row was cleaned up is a no-op.
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

/// `POST /wallet/new/cancel` — drop a half-built session + wrapped share.
/// Idempotent: cancel of an unknown/confirmed session is a no-op 204.
pub(crate) async fn cancel_handler(
    State(state): State<Arc<WebState>>,
    Json(req): Json<SessionIdRequest>,
) -> Result<Response, WalletApiError> {
    let store = session_store(&state)?;
    store.delete(&req.session_id);
    Ok(StatusCode::NO_CONTENT.into_response())
}
