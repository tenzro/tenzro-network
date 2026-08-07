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

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tenzro_storage::{CF_IDENTITIES, KvStore};
use tenzro_types::device_binding::{
    BindingPolicy, BoundDevice, DeviceSession, WalletReadiness, revoke_sessions_for_device,
    wallet_readiness,
};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

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
    /// Operator-facing label — "Alva's iPhone".
    pub label: String,
    /// Base64 (standard, padded) WebAuthn attestation object from
    /// `navigator.credentials.create()`.
    pub attestation_object_b64: String,
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
    /// Whether a wallet may now be created, and why not if not.
    pub wallet_ready: bool,
    pub wallet_blocker: Option<String>,
}

/// `tenzro_bindDevice` — record what a registration proved about a device.
///
/// The attestation is parsed and graded against the vendor roots this node
/// pins; nothing the client asserts about its own hardware is taken on trust.
/// A device that does not meet [`BindingPolicy`] is **refused**, so the device
/// list never contains something the wallet gate would later have to
/// second-guess.
pub(crate) async fn handle_bind_device(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use base64::Engine;

    let req: BindDeviceRequest = crate::passkey_rpc::parse_params(params)?;
    if req.identity_did.trim().is_empty() {
        return Err(JsonRpcError {
            code: -32602,
            message: "identity_did is required".to_string(),
            data: None,
        });
    }

    let attestation = base64::engine::general_purpose::STANDARD
        .decode(req.attestation_object_b64.trim())
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("attestation_object_b64 is not valid base64: {e}"),
            data: None,
        })?;

    let facts = tenzro_auth::parse_attestation(&attestation, &node.webauthn_trusted_roots())
        .map_err(|e| JsonRpcError {
            code: -32602,
            message: e.to_string(),
            data: None,
        })?;

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

    serde_json::to_value(BindDeviceResponse {
        credential_id,
        identity_did: req.identity_did,
        hardware_bound: device.is_hardware_bound(),
        attestation_format: device.attestation.format.as_str().to_string(),
        key_protection: device.attestation.protection.as_str().to_string(),
        aaguid: device.aaguid.to_hex(),
        backup_eligible: device.backup_eligible,
        device_count: devices.len(),
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
                WalletReadiness::NoHardwareBoundDevice => "bind_hardware_bound_device",
            }),
        ),
    };

    Ok(serde_json::json!({
        "identity_did": req.identity_did,
        "ready": ready,
        "blocker": blocker,
        "remedy": remedy,
        "bound_devices": devices.len(),
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
    /// `controller` or `hardware_root`.
    pub authority: String,
    /// The controlling DID, for a controller-authorised transfer.
    #[serde(default)]
    pub controller_did: Option<String>,
    /// The machine root proven, for a hardware-authorised transfer.
    #[serde(default)]
    pub hardware_root_hex: Option<String>,
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
/// hardware-rooted one on proof of its root. Holding the hardware cannot take a
/// machine that has an accountable party.
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
            None => MachineAnchor::HardwareRooted {
                hardware_root_hex: identity
                    .metadata
                    .get("hardware_root")
                    .cloned()
                    .unwrap_or_default(),
                sources: identity
                    .metadata
                    .get("hardware_root_sources")
                    .map(|s| s.split(',').map(|p| p.trim().to_string()).collect())
                    .unwrap_or_default(),
            },
        },
        _ => {
            return Err(JsonRpcError {
                code: -32602,
                message: format!("{} is not a machine identity", req.machine_did),
                data: None,
            });
        }
    };

    let authority = match req.authority.as_str() {
        "controller" => TransferAuthority::Controller {
            controller_did: req.controller_did.clone().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "controller_did is required for a controller-authorised transfer"
                    .to_string(),
                data: None,
            })?,
        },
        "hardware_root" => TransferAuthority::HardwareRoot {
            hardware_root_hex: req.hardware_root_hex.clone().ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "hardware_root_hex is required for a hardware-authorised transfer"
                    .to_string(),
                data: None,
            })?,
        },
        other => {
            return Err(JsonRpcError {
                code: -32602,
                message: format!(
                    "authority must be 'controller' or 'hardware_root', got '{other}'"
                ),
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
        }))
        .unwrap();
        assert_eq!(r.ttl_ms, default_ttl_ms());
        assert!(r.ttl_ms > 0);
        assert!(r.hardware_root_hex.is_none());
    }

    #[test]
    fn transfer_accepts_the_hardware_root_authority_without_a_controller() {
        // A machine nobody delegated is moved by whoever proves the hardware
        // root. The two authorities are not interchangeable, so this shape must
        // parse without a controller_did.
        let r: TransferOwnershipRequest = serde_json::from_value(serde_json::json!({
            "machine_did": "did:tenzro:machine",
            "new_owner_did": "did:tenzro:bob",
            "authority": "hardware_root",
            "hardware_root_hex": "aabb",
        }))
        .unwrap();
        assert_eq!(r.authority, "hardware_root");
        assert!(r.controller_did.is_none());
        assert_eq!(r.hardware_root_hex.as_deref(), Some("aabb"));
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
