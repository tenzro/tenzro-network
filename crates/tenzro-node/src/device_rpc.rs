//! Devices bound to an identity, and the sessions they authorise.
//!
//! The store behind `tenzro_bindDevice` / `tenzro_listBoundDevices` /
//! `tenzro_revokeBoundDevice` / `tenzro_walletReadiness`, and the machine
//! ownership transfer that shares its authority model.
//!
//! # Why binding is a separate record from the passkey enrollment
//!
//! The smart-account enrollment records *which credential may sign*. This
//! records *what the credential proved about the hardware holding it* — the
//! attestation format, the protection tier, whether the chain reached a pinned
//! root, and the backup flags. The first is an authorisation; the second is
//! evidence, and only the second can answer "is this a device or an account".
//!
//! Keeping them separate also means a deployment that has not configured vendor
//! roots still enrolls passkeys normally; those devices simply do not grade as
//! hardware-bound, and the wallet gate says so rather than silently passing.
//!
//! # Who may change the device list
//!
//! Every mutation here answers a node-issued, single-use custody challenge
//! (`tenzro_createCustodyChallenge`) that names the exact change. Node
//! administration only reaches the method; it authorises nothing by itself.
//!
//! - Binding the first device: the registered credential key must be the key
//!   the identity DID derives from.
//! - Binding another device, or unbinding one: a user-verified assertion from
//!   a device already bound to the identity.
//! - Moving a delegated machine: a user-verified assertion from a device bound
//!   to the current controller.
//! - Moving a machine nobody delegated: a signature by the machine's own
//!   registered key.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_storage::{CF_IDENTITIES, KvStore};
use tenzro_types::device_binding::{
    BindingPolicy, BoundDevice, DeviceSession, WalletReadiness, custody_counts,
    revoke_sessions_for_device, wallet_readiness,
};

use crate::node::TenzroNode;
use crate::passkey_rpc::CustodyOperation;
use crate::rpc::JsonRpcError;

/// A WebAuthn assertion (`navigator.credentials.get()`) from a bound device.
/// Every field is standard base64.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceAssertion {
    /// Hex credential id of the bound device that made the assertion.
    pub credential_id: String,
    pub authenticator_data_b64: String,
    pub client_data_json_b64: String,
    /// DER or raw `r || s` ECDSA signature.
    pub signature_b64: String,
}

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32003,
        message: message.into(),
        data: None,
    }
}

fn b64(field: &str, value: &str) -> Result<Vec<u8>, JsonRpcError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| invalid(format!("{field} is not valid base64: {e}")))
}

/// Spend the custody challenge for exactly this change, returning the digest
/// the ceremony must have signed.
fn consume_challenge(
    node: &Arc<TenzroNode>,
    challenge_id: &str,
    account: &str,
    operation: CustodyOperation,
    target: &str,
) -> Result<[u8; 32], JsonRpcError> {
    node.custody_challenges()
        .consume(
            challenge_id,
            account.as_bytes(),
            operation,
            target.as_bytes(),
        )
        .map_err(refused)
}

/// Check a registration's `clientDataJSON` is a creation ceremony over
/// `challenge` on this node's origin, and return its hash.
fn registration_client_data_hash(
    client_data_json: &[u8],
    challenge: &[u8; 32],
    rp_id: &str,
) -> Result<[u8; 32], JsonRpcError> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let client: Value = serde_json::from_slice(client_data_json)
        .map_err(|e| invalid(format!("clientDataJSON is not JSON: {e}")))?;
    if client.get("type").and_then(Value::as_str) != Some("webauthn.create") {
        return Err(invalid(
            "clientDataJSON is not from a registration ceremony",
        ));
    }
    if client.get("crossOrigin").and_then(Value::as_bool) == Some(true) {
        return Err(refused(
            "a registration made inside a cross-origin frame is refused",
        ));
    }
    // Any page under the RP ID's domain can run a registration ceremony
    // for it; only the relying party's own origin binds a device.
    if client.get("origin").and_then(Value::as_str) != Some(format!("https://{rp_id}").as_str()) {
        return Err(refused(format!(
            "a registration made on another origin than https://{rp_id} is refused"
        )));
    }
    let presented = client
        .get("challenge")
        .and_then(Value::as_str)
        .and_then(|c| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .ok()
        })
        .ok_or_else(|| invalid("clientDataJSON carries no challenge"))?;
    if presented.as_slice() != challenge.as_slice() {
        return Err(refused("the registration answers a different challenge"));
    }
    Ok(Sha256::digest(client_data_json).into())
}

/// Verify a user-verified assertion from a device bound to `identity_did`
/// over `challenge`, advance that device's signature counter, and return it.
fn require_bound_device_assertion(
    node: &Arc<TenzroNode>,
    identity_did: &str,
    challenge: &[u8; 32],
    assertion: &DeviceAssertion,
) -> Result<BoundDevice, JsonRpcError> {
    use tenzro_device_key::signer::{
        PasskeyAuthorization, PasskeyController, verify_authorization,
    };
    let store = storage(node)?;
    let key = device_key(identity_did, &assertion.credential_id);
    let raw = store
        .get(CF_IDENTITIES, &key)
        .map_err(|e| internal("read device", e))?
        .ok_or_else(|| {
            refused(format!(
                "credential {} is not a device bound to {identity_did}",
                assertion.credential_id
            ))
        })?;
    let mut device: BoundDevice =
        serde_json::from_slice(&raw).map_err(|e| internal("decode device", e))?;
    let authz = PasskeyAuthorization {
        authenticator_data: b64("authenticator_data_b64", &assertion.authenticator_data_b64)?,
        client_data_json: b64("client_data_json_b64", &assertion.client_data_json_b64)?,
        signature: b64("signature_b64", &assertion.signature_b64)?,
    };
    let controller = PasskeyController {
        public_key_sec1: device.public_key_sec1.clone(),
        rp_id: node.http_surface().webauthn_rp_id().to_string(),
    };
    verify_authorization(&controller, challenge, &authz)
        .map_err(|e| refused(format!("device assertion refused: {e}")))?;
    let counter: [u8; 4] = authz.authenticator_data[33..37]
        .try_into()
        .map_err(|_| invalid("authenticatorData has no signature counter"))?;
    device
        .advance_sign_count(u32::from_be_bytes(counter))
        .map_err(|seen| {
            refused(format!(
                "signature counter {seen} did not advance past {}; the credential may have \
                 been cloned",
                device.sign_count
            ))
        })?;
    store
        .put(
            CF_IDENTITIES,
            &key,
            &serde_json::to_vec(&device).map_err(|e| internal("encode device", e))?,
        )
        .map_err(|e| internal("persist device", e))?;
    Ok(device)
}

/// Whether `signature` over `digest` verifies under an identity's first
/// registered key (Ed25519 or P-256).
fn identity_key_signed(
    public_keys: &[tenzro_identity::PublicKeyInfo],
    digest: &[u8; 32],
    signature: &[u8],
) -> bool {
    let Some(key) = public_keys.first() else {
        return false;
    };
    match key.key_type.as_str() {
        "Ed25519" => {
            let (Ok(pk), Ok(sig)) = (
                <[u8; 32]>::try_from(key.public_key.as_slice()),
                <[u8; 64]>::try_from(signature),
            ) else {
                return false;
            };
            ed25519_dalek::VerifyingKey::from_bytes(&pk)
                .map(|vk| {
                    vk.verify_strict(digest, &ed25519_dalek::Signature::from_bytes(&sig))
                        .is_ok()
                })
                .unwrap_or(false)
        }
        "P-256" => {
            tenzro_device_key::signer::verify_p256_prehash(&key.public_key, digest, signature)
        }
        _ => false,
    }
}

/// Key prefix for a bound device, under `CF_IDENTITIES`.
const DEVICE_PREFIX: &str = "bound_device:";
/// Key prefix for a device-authorised session.
const SESSION_PREFIX: &str = "device_session:";

fn device_key(identity_did: &str, credential_id: &str) -> Vec<u8> {
    format!("{DEVICE_PREFIX}{identity_did}:{credential_id}").into_bytes()
}

fn session_key(identity_did: &str, session_id: &str) -> Vec<u8> {
    format!("{SESSION_PREFIX}{identity_did}:{session_id}").into_bytes()
}

fn storage(node: &Arc<TenzroNode>) -> Result<Arc<dyn KvStore>, JsonRpcError> {
    node.storage()
        .map(|s| s.clone() as Arc<dyn KvStore>)
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "Storage not initialized".to_string(),
            data: None,
        })
}

fn internal(what: &str, e: impl std::fmt::Display) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: format!("{what}: {e}"),
        data: None,
    }
}

/// Every device bound to `identity_did`.
pub(crate) fn list_devices(
    node: &Arc<TenzroNode>,
    identity_did: &str,
) -> Result<Vec<BoundDevice>, JsonRpcError> {
    let store = storage(node)?;
    let prefix = format!("{DEVICE_PREFIX}{identity_did}:");
    let rows = store
        .scan_prefix(CF_IDENTITIES, prefix.as_bytes())
        .map_err(|e| internal("read bound devices", e))?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<BoundDevice>(&v).ok())
        .collect())
}

/// Every session recorded for `identity_did`, live or not.
fn list_sessions(
    node: &Arc<TenzroNode>,
    identity_did: &str,
) -> Result<Vec<DeviceSession>, JsonRpcError> {
    let store = storage(node)?;
    let prefix = format!("{SESSION_PREFIX}{identity_did}:");
    let rows = store
        .scan_prefix(CF_IDENTITIES, prefix.as_bytes())
        .map_err(|e| internal("read sessions", e))?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_slice::<DeviceSession>(&v).ok())
        .collect())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// tenzro_bindDevice
// ---------------------------------------------------------------------------

/// Bind a device to an identity from a WebAuthn registration.
#[derive(Debug, Deserialize)]
pub struct BindDeviceRequest {
    /// Identity the device will authenticate as.
    pub identity_did: String,
    /// Operator-facing label — "work phone".
    pub label: String,
    /// Base64 (standard, padded) WebAuthn attestation object from
    /// `navigator.credentials.create()`.
    pub attestation_object_b64: String,
    /// Base64 `clientDataJSON` from the same ceremony. Its challenge must be
    /// the digest of `challenge_id`.
    pub client_data_json_b64: String,
    /// From `tenzro_createCustodyChallenge` with operation `bind_device`,
    /// account = hex of the identity DID, target = hex of the label.
    pub challenge_id: String,
    /// Required once the identity has a bound device: an assertion from one
    /// of them over the same challenge.
    #[serde(default)]
    pub authorization: Option<DeviceAssertion>,
}

#[derive(Debug, Serialize)]
pub struct BindDeviceResponse {
    pub credential_id: String,
    pub identity_did: String,
    /// Whether this device's key is in hardware and cannot be replicated.
    pub hardware_bound: bool,
    pub attestation_format: String,
    pub key_protection: String,
    pub aaguid: String,
    pub backup_eligible: bool,
    /// Devices bound to this identity after this call.
    pub device_count: usize,
    /// How many independent roots of control those devices amount to.
    pub independent_roots: usize,
    /// Whether a wallet may now be created, and why not if not.
    pub wallet_ready: bool,
    pub wallet_blocker: Option<String>,
}

/// `tenzro_bindDevice` — record what a registration proved about a device.
///
/// The attestation is verified and graded against the vendor roots this node
/// pins; nothing the client asserts about its own hardware is taken on trust.
/// The registration must be user-verified and made on this node's relying
/// party, and the caller must hold the identity (see the module docs).
/// A device that does not meet [`BindingPolicy`] is **refused**, so the device
/// list never contains something the wallet gate would later have to
/// second-guess.
pub(crate) async fn handle_bind_device(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use sha2::{Digest, Sha256};

    let req: BindDeviceRequest = crate::passkey_rpc::parse_params(params)?;
    if req.identity_did.trim().is_empty() {
        return Err(invalid("identity_did is required"));
    }

    let challenge = consume_challenge(
        node,
        &req.challenge_id,
        &req.identity_did,
        CustodyOperation::BindDevice,
        &req.label,
    )?;
    let attestation = b64("attestation_object_b64", &req.attestation_object_b64)?;
    let client_data = b64("client_data_json_b64", &req.client_data_json_b64)?;
    let client_data_hash = registration_client_data_hash(
        &client_data,
        &challenge,
        node.http_surface().webauthn_rp_id(),
    )?;

    let facts = tenzro_auth::parse_attestation(
        &attestation,
        &client_data_hash,
        &node.webauthn_trusted_roots(),
        now_ms() / 1000,
    )
    .map_err(|e| invalid(e.to_string()))?;

    let rp_id_hash: [u8; 32] =
        Sha256::digest(node.http_surface().webauthn_rp_id().as_bytes()).into();
    if facts.rp_id_hash != rp_id_hash {
        return Err(refused(
            "the credential was registered for a different relying party",
        ));
    }
    if !facts.user_present || !facts.user_verified {
        return Err(refused(
            "binding a device requires user verification (biometric or PIN) during registration",
        ));
    }
    let tenzro_auth::CredentialKey::P256(public_key) = facts.credential_key.clone() else {
        return Err(invalid("a bound device must hold a P-256 credential"));
    };

    // Whoever binds a device must already hold the identity: its root key for
    // the first device, one of its devices after that.
    let existing = list_devices(node, &req.identity_did)?;
    if existing.is_empty() {
        // A human DID derives from the raw x||y point; the other forms from the
        // SEC1 encoding. Both name this same key.
        let roots_identity =
            tenzro_types::did_derivation::did_derives_from_key(&req.identity_did, &public_key[1..])
                || tenzro_types::did_derivation::did_derives_from_key(
                    &req.identity_did,
                    &public_key,
                );
        if !roots_identity {
            return Err(refused(format!(
                "{} has no bound device, and this credential is not the key it derives from; \
                 the first device must be the identity's own passkey",
                req.identity_did
            )));
        }
    } else {
        let assertion = req.authorization.as_ref().ok_or_else(|| {
            refused(
                "this identity already has bound devices: authorise the new one with an \
                 assertion from one of them",
            )
        })?;
        require_bound_device_assertion(node, &req.identity_did, &challenge, assertion)?;
    }

    if facts.credential_id.is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "the registration carried no credential id — a device cannot be bound \
                      without one"
                .to_string(),
            data: None,
        });
    }

    let credential_id = hex::encode(&facts.credential_id);
    let device = BoundDevice {
        credential_id: credential_id.clone(),
        identity_did: req.identity_did.clone(),
        label: req.label.clone(),
        public_key_sec1: public_key.to_vec(),
        aaguid: facts.aaguid,
        backup_eligible: facts.backup_eligible,
        backed_up: facts.backed_up,
        attestation: facts.evidence.clone(),
        sign_count: facts.sign_count,
        bound_at_ms: now_ms(),
    };

    // Refused here rather than stored and filtered later: a device list that
    // contains entries the wallet gate silently ignores is a list an operator
    // will misread.
    BindingPolicy::default()
        .admit(&device)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: e.to_string(),
            data: Some(serde_json::json!({
                "attestation_format": device.attestation.format.as_str(),
                "key_protection": device.attestation.protection.as_str(),
                "chain_verified": device.attestation.chain_verified,
                "backup_eligible": device.backup_eligible,
            })),
        })?;

    let store = storage(node)?;
    store
        .put(
            CF_IDENTITIES,
            &device_key(&req.identity_did, &credential_id),
            &serde_json::to_vec(&device).map_err(|e| internal("encode device", e))?,
        )
        .map_err(|e| internal("persist device", e))?;

    let devices = list_devices(node, &req.identity_did)?;
    let readiness = wallet_readiness(&devices, &req.identity_did, None);
    let (_, independent_roots) = custody_counts(&devices, &req.identity_did);

    serde_json::to_value(BindDeviceResponse {
        credential_id,
        identity_did: req.identity_did,
        hardware_bound: device.is_hardware_bound(),
        attestation_format: device.attestation.format.as_str().to_string(),
        key_protection: device.attestation.protection.as_str().to_string(),
        aaguid: device.aaguid.to_hex(),
        backup_eligible: device.backup_eligible,
        device_count: devices.len(),
        independent_roots,
        wallet_ready: readiness.is_ok(),
        wallet_blocker: readiness.err().map(|e| e.to_string()),
    })
    .map_err(|e| internal("encode response", e))
}

// ---------------------------------------------------------------------------
// tenzro_listBoundDevices
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ListBoundDevicesRequest {
    pub identity_did: String,
}

/// `tenzro_listBoundDevices` — the devices that can authenticate as an identity.
pub(crate) async fn handle_list_bound_devices(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ListBoundDevicesRequest = crate::passkey_rpc::parse_params(params)?;
    let devices = list_devices(node, &req.identity_did)?;
    let readiness = wallet_readiness(&devices, &req.identity_did, None);

    Ok(serde_json::json!({
        "identity_did": req.identity_did,
        "count": devices.len(),
        "independent_roots": custody_counts(&devices, &req.identity_did).1,
        "hardware_bound_count": devices.iter().filter(|d| d.is_hardware_bound()).count(),
        "wallet_ready": readiness.is_ok(),
        "wallet_blocker": readiness.err().map(|e| e.to_string()),
        "devices": devices.iter().map(|d| serde_json::json!({
            "credential_id": d.credential_id,
            "label": d.label,
            "aaguid": d.aaguid.to_hex(),
            "hardware_bound": d.is_hardware_bound(),
            "attestation_format": d.attestation.format.as_str(),
            "key_protection": d.attestation.protection.as_str(),
            "chain_verified": d.attestation.chain_verified,
            "backup_eligible": d.backup_eligible,
            "backed_up": d.backed_up,
            "sign_count": d.sign_count,
            "sign_count_meaningful": d.sign_count_is_meaningful(),
            "bound_at_ms": d.bound_at_ms,
        })).collect::<Vec<_>>(),
    }))
}

// ---------------------------------------------------------------------------
// tenzro_revokeBoundDevice
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RevokeBoundDeviceRequest {
    pub identity_did: String,
    pub credential_id: String,
    /// From `tenzro_createCustodyChallenge` with operation `revoke_device`,
    /// account = hex of the identity DID, target = hex of the credential id.
    pub challenge_id: String,
    /// An assertion over that challenge from any device bound to the
    /// identity, including the one being revoked.
    pub authorization: DeviceAssertion,
}

/// `tenzro_revokeBoundDevice` — unbind a device and end the sessions it granted.
///
/// The two happen together, and that is the point: removing the device without
/// ending its sessions would leave a lost phone's access live, which is the
/// exact situation the user is trying to fix.
pub(crate) async fn handle_revoke_bound_device(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: RevokeBoundDeviceRequest = crate::passkey_rpc::parse_params(params)?;
    let challenge = consume_challenge(
        node,
        &req.challenge_id,
        &req.identity_did,
        CustodyOperation::RevokeDevice,
        &req.credential_id,
    )?;
    require_bound_device_assertion(node, &req.identity_did, &challenge, &req.authorization)?;
    let store = storage(node)?;

    let key = device_key(&req.identity_did, &req.credential_id);
    let existed = store
        .get(CF_IDENTITIES, &key)
        .map_err(|e| internal("read device", e))?
        .is_some();
    if existed {
        store
            .delete(CF_IDENTITIES, &key)
            .map_err(|e| internal("delete device", e))?;
    }

    let mut sessions = list_sessions(node, &req.identity_did)?;
    let ended = revoke_sessions_for_device(&mut sessions, &req.credential_id);
    for s in sessions.iter().filter(|s| s.revoked) {
        store
            .put(
                CF_IDENTITIES,
                &session_key(&req.identity_did, &s.session_id),
                &serde_json::to_vec(s).map_err(|e| internal("encode session", e))?,
            )
            .map_err(|e| internal("persist session", e))?;
    }

    let remaining = list_devices(node, &req.identity_did)?;
    Ok(serde_json::json!({
        "identity_did": req.identity_did,
        "credential_id": req.credential_id,
        "removed": existed,
        "sessions_ended": ended,
        "devices_remaining": remaining.len(),
        "independent_roots": custody_counts(&remaining, &req.identity_did).1,
        "wallet_ready": wallet_readiness(&remaining, &req.identity_did, None).is_ok(),
    }))
}

// ---------------------------------------------------------------------------
// tenzro_walletReadiness
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct WalletReadinessRequest {
    pub identity_did: String,
    /// Credential id of the device asking, when it is one of the bound ones.
    /// Supplying it is what lets the check notice that every bound device is
    /// this same machine.
    #[serde(default)]
    pub this_device_credential_id: Option<String>,
}

/// `tenzro_walletReadiness` — whether a wallet may be created, and why not.
///
/// Read before offering wallet creation, so the user is told what to do
/// ("scan the pairing QR with your phone") rather than shown a button that
/// fails.
pub(crate) async fn handle_wallet_readiness(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: WalletReadinessRequest = crate::passkey_rpc::parse_params(params)?;
    let devices = list_devices(node, &req.identity_did)?;
    let readiness = wallet_readiness(
        &devices,
        &req.identity_did,
        req.this_device_credential_id.as_deref(),
    );

    let (ready, blocker, remedy) = match &readiness {
        Ok(()) => (true, None, None),
        Err(e) => (
            false,
            Some(e.to_string()),
            Some(match e {
                WalletReadiness::NeedsSecondDevice { .. }
                | WalletReadiness::NeedsSeparateDevice => "bind_second_device",
                WalletReadiness::NeedsIndependentRoot { .. } => "bind_independent_device",
            }),
        ),
    };
    let (bound, independent_roots) = custody_counts(&devices, &req.identity_did);

    Ok(serde_json::json!({
        "identity_did": req.identity_did,
        "ready": ready,
        "blocker": blocker,
        "remedy": remedy,
        "bound_devices": bound,
        "independent_roots": independent_roots,
        "hardware_bound_devices": devices.iter().filter(|d| d.is_hardware_bound()).count(),
    }))
}

// ---------------------------------------------------------------------------
// tenzro_transferMachineOwnership
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TransferOwnershipRequest {
    pub machine_did: String,
    pub new_owner_did: String,
    /// `controller` or `machine_key`.
    pub authority: String,
    /// The controlling DID, for a controller-authorised transfer.
    #[serde(default)]
    pub controller_did: Option<String>,
    /// From `tenzro_createCustodyChallenge` with operation
    /// `transfer_machine_ownership`, account = hex of the machine DID,
    /// target = hex of the new owner DID.
    pub challenge_id: String,
    /// Controller transfer: an assertion over the challenge from a device
    /// bound to the controller.
    #[serde(default)]
    pub authorization: Option<DeviceAssertion>,
    /// Hardware-root transfer: the machine's own registered key's signature
    /// over the challenge digest, hex.
    #[serde(default)]
    pub machine_signature_hex: Option<String>,
    /// Validity window in milliseconds from now. Bounded so an authorisation
    /// cannot be replayed later against a machine that has changed hands.
    #[serde(default = "default_ttl_ms")]
    pub ttl_ms: u64,
}

fn default_ttl_ms() -> u64 {
    5 * 60 * 1000
}

/// `tenzro_transferMachineOwnership` — move a machine to another identity.
///
/// The authority required is whatever anchors the machine, and the two are not
/// interchangeable: a delegated machine moves on its controller's authority, a
/// hardware-rooted one on a signature by the machine's own key. Holding the
/// hardware cannot take a machine that has an accountable party.
pub(crate) async fn handle_transfer_machine_ownership(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_identity::identity::{
        IdentityData, MachineAnchor, OwnershipTransfer, TransferAuthority,
    };

    let req: TransferOwnershipRequest = crate::passkey_rpc::parse_params(params)?;
    let registry = node.identity_registry().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Identity registry not initialized".to_string(),
        data: None,
    })?;

    let identity = registry
        .resolve(&req.machine_did)
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("cannot resolve {}: {e}", req.machine_did),
            data: None,
        })?;

    // Reconstruct the machine's current anchor from its record.
    let current = match &identity.identity_data {
        IdentityData::Machine { controller_did, .. } => match controller_did {
            Some(did) => MachineAnchor::Delegated {
                controller_did: did.clone(),
            },
            None => MachineAnchor::SelfKeyed,
        },
        _ => {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("{} is not a machine identity", req.machine_did),
                data: None,
            });
        }
    };

    let challenge = consume_challenge(
        node,
        &req.challenge_id,
        &req.machine_did,
        CustodyOperation::TransferMachineOwnership,
        &req.new_owner_did,
    )?;

    let authority = match req.authority.as_str() {
        "controller" => {
            let controller_did = req.controller_did.clone().ok_or_else(|| {
                invalid("controller_did is required for a controller-authorised transfer")
            })?;
            let assertion = req.authorization.as_ref().ok_or_else(|| {
                refused("a controller-authorised transfer needs an assertion from the controller's device")
            })?;
            require_bound_device_assertion(node, &controller_did, &challenge, assertion)?;
            TransferAuthority::Controller { controller_did }
        }
        "machine_key" => {
            let signature = req
                .machine_signature_hex
                .as_deref()
                .map(|h| hex::decode(h.trim_start_matches("0x")))
                .transpose()
                .map_err(|e| invalid(format!("machine_signature_hex is not hex: {e}")))?
                .ok_or_else(|| {
                    refused("a hardware-authorised transfer needs the machine's own signature")
                })?;
            if !identity_key_signed(&identity.public_keys, &challenge, &signature) {
                return Err(refused(
                    "the machine signature does not verify under the machine's registered key",
                ));
            }
            TransferAuthority::MachineKey
        }
        other => {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("authority must be 'controller' or 'machine_key', got '{other}'"),
                data: None,
            });
        }
    };

    let transfer = OwnershipTransfer {
        machine_did: req.machine_did.clone(),
        new_owner_did: req.new_owner_did.clone(),
        authority,
        expires_at_ms: now_ms().saturating_add(req.ttl_ms),
    };

    let next = transfer
        .authorize(&current, now_ms())
        .map_err(|e| JsonRpcError {
            code: -32003,
            message: e.to_string(),
            data: None,
        })?;

    let new_controller = next.controller_did().unwrap_or_default().to_string();
    registry
        .set_machine_controller(&req.machine_did, &new_controller)
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("ownership transfer could not be recorded: {e}"),
            data: None,
        })?;
    crate::machine_access::machine_owner_changed(node, &req.machine_did);

    Ok(serde_json::json!({
        "machine_did": req.machine_did,
        "previous_owner": current.controller_did(),
        "new_owner": new_controller,
        "authorised_by": req.authority,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire shape every surface sends. `parse_params` deserializes the
    /// params value directly, so a one-element array — the other convention in
    /// this codebase — would be rejected. Pinning the shape here catches a
    /// client that wraps its params before a user does.
    #[test]
    fn requests_deserialize_from_a_bare_object() {
        let r: ListBoundDevicesRequest =
            serde_json::from_value(serde_json::json!({"identity_did": "did:tenzro:alice"}))
                .unwrap();
        assert_eq!(r.identity_did, "did:tenzro:alice");

        let r: RevokeBoundDeviceRequest = serde_json::from_value(serde_json::json!({
            "identity_did": "did:tenzro:alice",
            "credential_id": "cred-1",
            "challenge_id": "c",
            "authorization": assertion_json(),
        }))
        .unwrap();
        assert_eq!(r.credential_id, "cred-1");
    }

    #[test]
    fn an_array_wrapped_param_is_rejected_rather_than_silently_accepted() {
        let wrapped = serde_json::json!([{"identity_did": "did:tenzro:alice"}]);
        assert!(serde_json::from_value::<ListBoundDevicesRequest>(wrapped).is_err());
    }

    #[test]
    fn wallet_readiness_this_device_is_optional() {
        // Callers that cannot name the device they are on still get an answer;
        // they just lose the "every bound device is this same machine" check.
        let r: WalletReadinessRequest =
            serde_json::from_value(serde_json::json!({"identity_did": "did:tenzro:alice"}))
                .unwrap();
        assert!(r.this_device_credential_id.is_none());

        let r: WalletReadinessRequest = serde_json::from_value(serde_json::json!({
            "identity_did": "did:tenzro:alice",
            "this_device_credential_id": "cred-1",
        }))
        .unwrap();
        assert_eq!(r.this_device_credential_id.as_deref(), Some("cred-1"));
    }

    #[test]
    fn transfer_defaults_to_a_bounded_authorisation_window() {
        // Omitting ttl_ms must not mean "valid forever" — an authorisation that
        // never expires could be replayed against a machine that has since
        // changed hands.
        let r: TransferOwnershipRequest = serde_json::from_value(serde_json::json!({
            "machine_did": "did:tenzro:machine",
            "new_owner_did": "did:tenzro:bob",
            "authority": "controller",
            "controller_did": "did:tenzro:alice",
            "challenge_id": "c",
            "authorization": assertion_json(),
        }))
        .unwrap();
        assert_eq!(r.ttl_ms, default_ttl_ms());
        assert!(r.ttl_ms > 0);
        assert!(r.machine_signature_hex.is_none());
    }

    fn assertion_json() -> Value {
        serde_json::json!({
            "credential_id": "cred-1",
            "authenticator_data_b64": "",
            "client_data_json_b64": "",
            "signature_b64": "",
        })
    }

    /// Revoking without an assertion is not a request the node can parse,
    /// so node administration alone cannot unbind a device.
    #[test]
    fn revoking_requires_a_device_assertion() {
        let r = serde_json::from_value::<RevokeBoundDeviceRequest>(serde_json::json!({
            "identity_did": "did:tenzro:alice",
            "credential_id": "cred-1",
            "challenge_id": "c",
        }));
        assert!(r.is_err());
    }

    fn client_data(kind: &str, challenge: &[u8], cross_origin: bool) -> Vec<u8> {
        use base64::Engine;
        serde_json::to_vec(&serde_json::json!({
            "type": kind,
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": "https://node.example.org",
            "crossOrigin": cross_origin,
        }))
        .unwrap()
    }

    #[test]
    fn registration_client_data_must_answer_the_issued_challenge() {
        let challenge = [9u8; 32];
        assert!(
            registration_client_data_hash(
                &client_data("webauthn.create", &challenge, false),
                &challenge,
                "node.example.org"
            )
            .is_ok()
        );
        for bad in [
            client_data("webauthn.get", &challenge, false),
            client_data("webauthn.create", &[8u8; 32], false),
            client_data("webauthn.create", &challenge, true),
            b"not json".to_vec(),
        ] {
            assert!(registration_client_data_hash(&bad, &challenge, "node.example.org").is_err());
        }
        // The same ceremony run by a page on a sibling origin binds nothing.
        assert!(
            registration_client_data_hash(
                &client_data("webauthn.create", &challenge, false),
                &challenge,
                "example.org"
            )
            .is_err()
        );
    }

    fn machine(key_type: &str, public_key: Vec<u8>) -> Vec<tenzro_identity::PublicKeyInfo> {
        vec![tenzro_identity::PublicKeyInfo {
            key_id: "key-1".into(),
            key_type: key_type.into(),
            public_key,
            purposes: vec![],
        }]
    }

    /// A hardware-root transfer is authorised by the machine's own key, not
    /// by knowing its (public) hardware root.
    #[test]
    fn only_the_machines_own_key_authorises_a_hardware_root_transfer() {
        use ed25519_dalek::Signer;
        let digest = [5u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let m = machine("Ed25519", sk.verifying_key().to_bytes().to_vec());
        let good = sk.sign(&digest).to_bytes();
        assert!(identity_key_signed(&m, &digest, &good));
        assert!(!identity_key_signed(&m, &[6u8; 32], &good));
        let other = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32])
            .sign(&digest)
            .to_bytes();
        assert!(!identity_key_signed(&m, &digest, &other));
        assert!(!identity_key_signed(
            &machine("X25519", vec![0; 32]),
            &digest,
            &good
        ));
        assert!(!identity_key_signed(
            &machine("Ed25519", vec![]),
            &digest,
            &good
        ));
    }

    #[test]
    fn transfer_accepts_the_hardware_root_authority_without_a_controller() {
        // A machine nobody delegated is moved on its own signature. The two
        // authorities are not interchangeable, so this shape must parse
        // without a controller_did.
        let r: TransferOwnershipRequest = serde_json::from_value(serde_json::json!({
            "machine_did": "did:tenzro:machine",
            "new_owner_did": "did:tenzro:bob",
            "authority": "machine_key",
            "challenge_id": "c",
            "machine_signature_hex": "aabb",
        }))
        .unwrap();
        assert_eq!(r.authority, "machine_key");
        assert!(r.controller_did.is_none());
        assert_eq!(r.machine_signature_hex.as_deref(), Some("aabb"));
    }

    /// Storage keys must be injective across identities: one identity's device
    /// row may never be read or overwritten through another's key.
    #[test]
    fn device_and_session_keys_are_scoped_per_identity() {
        assert_ne!(
            device_key("did:tenzro:alice", "cred-1"),
            device_key("did:tenzro:bob", "cred-1")
        );
        assert_ne!(
            session_key("did:tenzro:alice", "s-1"),
            session_key("did:tenzro:bob", "s-1")
        );
        // Devices and sessions live in distinct keyspaces.
        assert_ne!(device_key("a", "x"), session_key("a", "x"));
        assert!(
            String::from_utf8(device_key("a", "x"))
                .unwrap()
                .starts_with(DEVICE_PREFIX)
        );
        assert!(
            String::from_utf8(session_key("a", "x"))
                .unwrap()
                .starts_with(SESSION_PREFIX)
        );
    }

    #[test]
    fn a_missing_params_value_is_an_invalid_params_error_not_a_panic() {
        let e = crate::passkey_rpc::parse_params::<ListBoundDevicesRequest>(None).unwrap_err();
        assert_eq!(e.code, -32602);
    }
}
