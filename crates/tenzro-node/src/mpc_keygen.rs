//! DKLS23 distributed key generation orchestration over the node's MPC
//! relay — the keyshare establishment surface for the threshold bridge
//! signer.
//!
//! `NodeThresholdSigner` signs with keyshares read from
//! `CF_MPC_KEYSHARES`, but those shares have to be created by a DKG run
//! first. This module exposes the operator RPCs that drive that run:
//!
//! - `tenzro_mpcKeygen` — start a DKG session on this node. Every
//!   participant's operator calls the same RPC on their own node with an
//!   identical parameter set (same participant list, threshold, finalized
//!   block hash, and session nonce — the `InstanceId` is derived from
//!   those inputs and must be byte-identical across parties, otherwise
//!   each side rejects the other's rounds with `InstanceIdMismatch`).
//!   The session runs in a background task; the RPC returns the derived
//!   instance id immediately.
//! - `tenzro_mpcKeygenStatus` — poll a session by instance id (or list
//!   all sessions). On completion the record carries the derived
//!   `group_id`, SEC1-compressed group public key, local party index,
//!   and EVM address — exactly the fields the operator pastes into
//!   `BridgeAdapterConfig.mpc_threshold` before restarting the node.
//!
//! Both RPCs are admin-token-gated: creating a signing group and reading
//! DKG orchestration state are operator-only.
//!
//! # DID → PeerId routing
//!
//! The MPC relay is fail-closed: without an installed `MpcDidResolver`,
//! outbound sends error and inbound rounds are rejected as
//! `UnknownSender`. `tenzro_mpcKeygen` therefore takes explicit
//! `peer_bindings` (participant DID → libp2p PeerId) supplied by the
//! operator, builds an [`MpcDidPeerRegistry`], and installs it on the
//! network service before the session starts. The local DID is bound to
//! the local PeerId automatically.
//!
//! # Relay-inbox handoff
//!
//! `NetworkService::subscribe_mpc_relay` supports a single subscriber —
//! the [`NetworkMpcSurface`] built here replaces any surface previously
//! subscribed (e.g. by a configured threshold bridge signer). That is the
//! intended operational order: DKG runs first, the operator then writes
//! the output into the adapter config and restarts the node, which
//! re-subscribes the signing surface.

use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use libp2p::PeerId;
use serde::Serialize;
use serde_json::{Value, json};
use tracing::{info, warn};

use tenzro_bridge::mpc::keygen::{KeygenConfig, KeygenSession};
use tenzro_bridge::mpc::libp2p_relay::{MpcLibp2pRelay, MpcLibp2pSurface};
use tenzro_bridge::mpc::sealing::TeeKeyshareSealer;
use tenzro_bridge::mpc::setup::{InstanceId, MpcCurve, MpcParameters, SESSION_NONCE_LEN};
use tenzro_network::NetworkService;
use tenzro_types::Hash;

use crate::mpc_libp2p_adapter::{MpcDidPeerRegistry, NetworkMpcSurface};
use crate::mpc_threshold_signer::{SealerHandle, StoreHandle};
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Per-session DKG state tracked on the node. Cloned into RPC responses;
/// the background task overwrites the registry entry on completion.
#[derive(Clone, Serialize)]
pub struct KeygenSessionRecord {
    /// Hex instance id — the registry key and poll handle.
    pub instance_id: String,
    /// `running` | `completed` | `failed`.
    pub status: String,
    pub local_did: String,
    /// Canonical (sorted-ascending) participant list.
    pub participant_dids: Vec<String>,
    pub threshold: u8,
    pub total_parties: u8,
    /// 1-based DKLS23 party index of this node.
    pub local_party_index: u8,
    pub started_at_ms: u64,
    pub finished_at_ms: Option<u64>,
    /// Derived group id (hex) — set on completion.
    pub group_id: Option<String>,
    /// SEC1-compressed secp256k1 group public key (hex) — set on completion.
    pub group_public_key: Option<String>,
    /// Keyshare epoch (always 0 for fresh DKG) — set on completion.
    pub epoch: Option<u64>,
    /// EVM (EIP-55) address derived from the group key — set on completion.
    pub address: Option<String>,
    /// Failure detail — set when `status == "failed"`.
    pub error: Option<String>,
}

/// Registry of DKG sessions keyed by hex instance id. Held on
/// [`TenzroNode`]; in-flight orchestration state only — the durable
/// artifact of a successful run is the sealed `KeyshareEnvelope` in
/// `CF_MPC_KEYSHARES`.
pub type KeygenSessionRegistry = DashMap<String, KeygenSessionRecord>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn invalid_params(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn internal(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

/// Decode a hex parameter into a fixed-size array with a descriptive error.
fn decode_hex_32(p: &Value, key: &str) -> Result<[u8; 32], JsonRpcError> {
    let s = p
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params(format!("missing '{}' (64-char hex string)", key)))?;
    let bytes = hex::decode(s.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("'{}' hex decode failed: {}", key, e)))?;
    if bytes.len() != 32 {
        return Err(invalid_params(format!(
            "'{}' decoded to {} bytes, expected 32",
            key,
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `tenzro_mpcKeygen` — start a DKLS23 DKG session (admin-token-gated).
///
/// Params:
/// ```json
/// {
///   "local_did": "did:tenzro:machine:...",
///   "participant_dids": ["did:...", "did:...", "did:..."],
///   "threshold": 2,
///   "finalized_block_hash": "<64-hex>",
///   "session_nonce": "<64-hex>",
///   "peer_bindings": { "did:...": "12D3Koo...", "did:...": "12D3Koo..." }
/// }
/// ```
///
/// `finalized_block_hash` and `session_nonce` must be identical on every
/// participant node — the coordinator picks a recently finalized block
/// hash plus a fresh random 32-byte nonce and distributes both to the
/// other operators out of band. `total_parties` is
/// `participant_dids.len()`; `peer_bindings` must cover every remote
/// participant.
pub(crate) async fn handle_mpc_keygen(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| invalid_params("missing params object"))?;

    // -------- Parse + normalize participants --------------------------
    let local_did = p
        .get("local_did")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_params("missing 'local_did'"))?
        .to_string();
    let mut participant_dids: Vec<String> = p
        .get("participant_dids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| invalid_params("missing 'participant_dids' (array of DID strings)"))?
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| {
                    invalid_params("'participant_dids' entries must be non-empty strings")
                })
        })
        .collect::<Result<_, _>>()?;
    // Canonical ordering: GroupId + party indices depend on it, and every
    // party must sort identically — do it here so operators can pass the
    // list in any order.
    participant_dids.sort();
    participant_dids.dedup();
    let total_parties = participant_dids.len();
    if !participant_dids.iter().any(|d| d == &local_did) {
        return Err(invalid_params(
            "'local_did' must appear in 'participant_dids'",
        ));
    }

    let threshold = p
        .get("threshold")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid_params("missing 'threshold'"))?;
    if threshold > u8::MAX as u64 || total_parties > u8::MAX as usize {
        return Err(invalid_params("threshold / participant count out of range"));
    }
    let parameters = MpcParameters::new(MpcCurve::Secp256k1, threshold as u8, total_parties as u8)
        .ok_or_else(|| {
            invalid_params(format!(
                "invalid MpcParameters threshold={} total_parties={} (need 2 <= t <= n <= 32)",
                threshold, total_parties
            ))
        })?;

    // -------- Instance id: must agree byte-for-byte across parties ----
    let block_hash_bytes = decode_hex_32(&p, "finalized_block_hash")?;
    let nonce: [u8; SESSION_NONCE_LEN] = decode_hex_32(&p, "session_nonce")?;
    let finalized_block_hash = Hash::new(block_hash_bytes);
    // message_hash is zero for DKG — there is no payload to anchor.
    let instance_id = InstanceId::derive(&finalized_block_hash, &[0u8; 32], &nonce);
    let instance_hex = instance_id.to_hex();

    // Idempotency: re-posting the same session parameters returns the
    // existing record instead of double-subscribing the relay.
    if let Some(existing) = node.mpc_keygen_sessions().get(&instance_hex) {
        return serde_json::to_value(existing.value())
            .map_err(|e| internal(format!("serialize: {}", e)));
    }

    // -------- Prerequisites -------------------------------------------
    let storage = node
        .storage()
        .cloned()
        .ok_or_else(|| internal("storage not initialized"))?;
    let network = node
        .network()
        .cloned()
        .ok_or_else(|| internal("network not initialized"))?;

    // -------- DID → PeerId routing ------------------------------------
    let local_peer_id = network
        .local_peer_id()
        .await
        .map_err(|e| internal(format!("local peer id unavailable: {}", e)))?;
    let registry = MpcDidPeerRegistry::new();
    registry.insert_self(local_did.clone(), local_peer_id);
    let bindings = p
        .get("peer_bindings")
        .and_then(|v| v.as_object())
        .ok_or_else(|| invalid_params("missing 'peer_bindings' (object: DID -> PeerId)"))?;
    for (did, peer_val) in bindings {
        if did == &local_did {
            continue; // self-binding already installed from the live PeerId
        }
        let peer_str = peer_val
            .as_str()
            .ok_or_else(|| invalid_params(format!("peer_bindings['{}'] must be a string", did)))?;
        let peer_id = PeerId::from_str(peer_str).map_err(|e| {
            invalid_params(format!(
                "peer_bindings['{}'] PeerId parse failed: {}",
                did, e
            ))
        })?;
        registry.insert(did.clone(), peer_id);
    }
    for did in &participant_dids {
        if did != &local_did && !bindings.contains_key(did) {
            return Err(invalid_params(format!(
                "peer_bindings missing entry for remote participant '{}'",
                did
            )));
        }
    }
    network
        .set_mpc_did_resolver(Arc::new(registry))
        .await
        .map_err(|e| internal(format!("installing MPC DID resolver failed: {}", e)))?;

    // -------- Runtime dependencies (mirrors the signer construction) --
    let keyshare_store = Arc::new(crate::mpc_keyshare_store::NodeKeyshareStore::new(storage));
    // Production-posture sealer: TEE-rooted IKM. Fails closed off-hardware
    // (no-simulation policy) — same rule as the signing path.
    let sealer: Arc<dyn tenzro_bridge::mpc::sealing::KeyshareSealer> =
        match TeeKeyshareSealer::derive_auto().await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                return Err(internal(format!(
                    "TEE keyshare sealer unavailable: {} (no raw-IKM fallback)",
                    e
                )));
            }
        };
    let surface: Arc<dyn MpcLibp2pSurface> = match NetworkMpcSurface::new(network).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            return Err(internal(format!(
                "network MPC surface subscription failed: {}",
                e
            )));
        }
    };
    let relay = MpcLibp2pRelay::new(surface);

    // -------- Session --------------------------------------------------
    let cfg = KeygenConfig {
        instance_id,
        parameters,
        participant_dids: participant_dids.clone(),
        local_did: local_did.clone(),
    };
    let local_party_index = cfg
        .local_party_index()
        .map_err(|e| invalid_params(format!("keygen config: {}", e)))?;
    let session = KeygenSession::new(
        cfg,
        relay,
        SealerHandle { inner: sealer },
        StoreHandle {
            inner: keyshare_store,
        },
    )
    .map_err(|e| invalid_params(format!("keygen config: {}", e)))?;

    let record = KeygenSessionRecord {
        instance_id: instance_hex.clone(),
        status: "running".to_string(),
        local_did,
        participant_dids,
        threshold: threshold as u8,
        total_parties: total_parties as u8,
        local_party_index,
        started_at_ms: now_ms(),
        finished_at_ms: None,
        group_id: None,
        group_public_key: None,
        epoch: None,
        address: None,
        error: None,
    };
    node.mpc_keygen_sessions()
        .insert(instance_hex.clone(), record.clone());

    let sessions = node.mpc_keygen_sessions().clone();
    let task_instance = instance_hex.clone();
    tokio::spawn(async move {
        let outcome = session.run().await;
        if let Some(mut entry) = sessions.get_mut(&task_instance) {
            entry.finished_at_ms = Some(now_ms());
            match outcome {
                Ok(output) => {
                    info!(
                        "MPC DKG {} completed: group_id={} address={}",
                        task_instance,
                        output.group_id.to_hex(),
                        output.address
                    );
                    entry.status = "completed".to_string();
                    entry.group_id = Some(output.group_id.to_hex());
                    entry.group_public_key = Some(hex::encode(&output.group_public_key_compressed));
                    entry.epoch = Some(output.epoch);
                    entry.address = Some(output.address);
                }
                Err(e) => {
                    warn!("MPC DKG {} failed: {}", task_instance, e);
                    entry.status = "failed".to_string();
                    entry.error = Some(e.to_string());
                }
            }
        }
    });

    serde_json::to_value(&record).map_err(|e| internal(format!("serialize: {}", e)))
}

/// `tenzro_mpcKeygenStatus` — poll DKG session state (admin-token-gated).
///
/// With `{"instance_id": "<hex>"}` returns that session's record
/// (`-32404` when unknown); without params returns all tracked sessions.
pub(crate) async fn handle_mpc_keygen_status(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let instance_id = params
        .as_ref()
        .and_then(|p| p.get("instance_id"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    match instance_id {
        Some(id) => match node.mpc_keygen_sessions().get(&id) {
            Some(record) => serde_json::to_value(record.value())
                .map_err(|e| internal(format!("serialize: {}", e))),
            None => Err(JsonRpcError {
                code: -32404,
                message: format!("no DKG session with instance_id {}", id),
                data: None,
            }),
        },
        None => {
            let mut sessions: Vec<KeygenSessionRecord> = node
                .mpc_keygen_sessions()
                .iter()
                .map(|e| e.value().clone())
                .collect();
            sessions.sort_by_key(|s| s.started_at_ms);
            Ok(json!({ "sessions": sessions }))
        }
    }
}
