//! In-process JSON-RPC bridge to the embedded node, plus the local
//! catalog / on-disk model helpers the onboarding flow reads.
//!
//! Every call here is a plain function dispatch inside this process.
//! There is no HTTP listener, no localhost port, no auth header
//! crossing a network boundary. The node still applies the same gates
//! it applies over HTTP — `dispatch_embedded` runs the identical
//! admin-token → API-key → method pipeline — so being embedded buys
//! convenience, not privilege.

use serde::Deserialize;
use serde_json::Value;

use crate::state::AppState;

/// Arguments of the webview's generic console call. The webview names a
/// method and its params and nothing else: it cannot supply or receive a
/// credential, so a script running in it can reach only what an
/// unauthenticated caller could.
#[derive(Debug, Deserialize)]
pub struct RpcCallArgs {
    /// JSON-RPC method name (e.g. `"tenzro_getNodeStatus"`).
    pub method: String,
    /// Method params. Positional (`[...]`) and named (`{...}`) both
    /// work — the node's dispatcher normalises them.
    #[serde(default)]
    pub params: Value,
}

/// Read-only node methods the webview may call through the generic
/// console. Every mutation Control performs goes through a named command
/// in `commands.rs`, which attaches the admin token on the Rust side; the
/// webview never holds it and cannot widen this list.
pub const CONSOLE_METHODS: &[&str] = &[
    "tenzro_getNodeStatus",
    "tenzro_getNodeStatus",
    "tenzro_nodeProfile",
    "tenzro_blockNumber",
    "tenzro_peerCount",
    "tenzro_syncing",
    "tenzro_getNetworkStats",
    "tenzro_getBalance",
    "tenzro_getBlock",
    "tenzro_getTransaction",
    "tenzro_listModels",
    "tenzro_listModelEndpoints",
    "tenzro_getHardwareProfile",
    "tenzro_slaVerdict",
    "tenzro_getTreasuryPayouts",
    "tenzro_getSponsoredBond",
    "tenzro_listProposals",
];

/// Whether the webview console may call `method`.
pub fn console_allows(method: &str) -> bool {
    CONSOLE_METHODS.contains(&method)
}

/// The webview's console call: an allowlisted read-only method, dispatched
/// with no credential. Returns the full JSON-RPC 2.0 envelope so the
/// console can show a method-level error as the node reported it.
pub async fn console_call(args: RpcCallArgs, state: &AppState) -> Result<Value, String> {
    if !console_allows(&args.method) {
        return Err(format!(
            "{} is not available from this window; the console serves read-only methods only",
            args.method
        ));
    }
    dispatch(&args.method, args.params, Default::default(), state).await
}

/// Dispatch one JSON-RPC call against the embedded node. Returns the
/// full JSON-RPC 2.0 envelope, errors included, so the caller can
/// distinguish a transport failure (this `Err`) from a method-level
/// error (an `error` member inside the `Ok`).
async fn dispatch(
    method: &str,
    params: Value,
    auth: tenzro_node::EmbeddedAuth,
    state: &AppState,
) -> Result<Value, String> {
    let node = running_node(state).await?;
    Ok(envelope(&node, method, params, auth).await)
}

async fn running_node(state: &AppState) -> Result<std::sync::Arc<tenzro_node::TenzroNode>, String> {
    let guard = state.node.read().await;
    guard
        .as_ref()
        .map(|h| h.node())
        .ok_or_else(|| "node is not running yet".to_string())
}

async fn envelope(
    node: &std::sync::Arc<tenzro_node::TenzroNode>,
    method: &str,
    params: Value,
    auth: tenzro_node::EmbeddedAuth,
) -> Value {
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });
    tenzro_node::dispatch_embedded(node, request, auth).await
}

/// One unprivileged call against `node`, unwrapped to its `result`.
pub async fn call_node(
    node: &std::sync::Arc<tenzro_node::TenzroNode>,
    method: &str,
    params: Value,
) -> Result<Value, String> {
    unwrap_envelope(envelope(node, method, params, Default::default()).await, method)
}

/// Dispatch and unwrap: returns the `result` member, or the `error`
/// message as an `Err`. Most internal callers want this shape rather
/// than picking the envelope apart themselves.
pub async fn rpc_result(
    method: &str,
    params: Value,
    state: &AppState,
) -> Result<Value, String> {
    let resp = dispatch(method, params, Default::default(), state).await?;
    unwrap_envelope(resp, method)
}

/// Same as [`rpc_result`] but as the node's operator, for the node-scoped
/// mutations Control performs on the user's behalf (role changes, provider
/// registration, pricing). The embedded node runs with this machine's DID
/// as its `operator_did`, so a DPoP-bound access token issued to that DID
/// carries the operator's classes. Only named commands call this; the
/// token never crosses into the webview.
pub async fn rpc_result_admin(
    method: &str,
    params: Value,
    state: &AppState,
) -> Result<Value, String> {
    let node = running_node(state).await?;
    let token = operator_token(&node).await?;
    let auth = operator::authorize(&token)?;
    unwrap_envelope(envelope(&node, method, params, auth).await, method)
}

/// The cached operator access token, refreshed a minute before it lapses.
static OPERATOR_TOKEN: tokio::sync::Mutex<Option<(String, std::time::Instant)>> =
    tokio::sync::Mutex::const_new(None);

async fn operator_token(node: &std::sync::Arc<tenzro_node::TenzroNode>) -> Result<String, String> {
    let mut cached = OPERATOR_TOKEN.lock().await;
    if let Some((token, until)) = cached.as_ref() {
        if std::time::Instant::now() < *until {
            return Ok(token.clone());
        }
    }
    let (token, expires_in) = operator::sign_in(node).await?;
    let lifetime = std::time::Duration::from_secs(expires_in.saturating_sub(60));
    *cached = Some((token.clone(), std::time::Instant::now() + lifetime));
    Ok(token)
}

/// Operator sign-in against the embedded node: the machine's hardware
/// identity key answers an access challenge, and a hardware DPoP key binds
/// the token it earns to this process.
mod operator {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tenzro_device_key::signer::HardwareSigner;

    /// Hardware label of Control's DPoP key.
    const DPOP_KEY_LABEL: &str = "tenzro/control/dpop";
    /// The `htu` of an in-process call; the node compares it verbatim.
    const EMBEDDED_HTU: &str = "embedded:///";
    const HTM: &str = "POST";

    fn dpop_key() -> Result<Box<dyn HardwareSigner>, String> {
        tenzro_device_key::signer::open_or_create(DPOP_KEY_LABEL)
            .map_err(|e| format!("no hardware key for DPoP: {e}"))
    }

    pub(super) async fn sign_in(
        node: &std::sync::Arc<tenzro_node::TenzroNode>,
    ) -> Result<(String, u64), String> {
        let key = tenzro_device_key::signer::open_or_create(
            tenzro_types::did_derivation::MACHINE_KEY_LABEL,
        )
        .map_err(|e| format!("machine identity key: {e}"))?;
        let public_key = key
            .public_key_sec1()
            .map_err(|e| format!("machine identity key: {e}"))?;
        let did = tenzro_types::did_derivation::machine_did(&public_key);
        let dpop = dpop_key()?;
        let jkt = jkt(&jwk(dpop.as_ref())?);

        let challenge = super::call_node(
            node,
            "tenzro_accessChallenge",
            json!({ "did": did, "dpop_jkt": jkt }),
        )
        .await?;
        let digest = challenge["device_digest"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .ok_or("access challenge carries no device_digest")?;
        let signature = key
            .sign(&digest)
            .map_err(|e| format!("signing the access challenge: {e}"))?;

        let issued = super::call_node(
            node,
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
        .await?;
        let token = issued["access_token"]
            .as_str()
            .ok_or("sign-in returned no access_token")?
            .to_string();
        Ok((token, issued["expires_in"].as_u64().unwrap_or(0)))
    }

    /// The headers of one operator call: the token and a fresh proof for it.
    pub(super) fn authorize(token: &str) -> Result<tenzro_node::EmbeddedAuth, String> {
        let key = dpop_key()?;
        let input = signing_input(&jwk(key.as_ref())?, token);
        let sig = key
            .sign(input.as_bytes())
            .map_err(|e| format!("signing the DPoP proof: {e}"))?;
        Ok(tenzro_node::EmbeddedAuth {
            authorization: Some(format!("DPoP {token}")),
            dpop: Some(format!("{input}.{}", B64.encode(sig))),
            http_method: Some(HTM.to_string()),
            http_uri: Some(EMBEDDED_HTU.to_string()),
            ..Default::default()
        })
    }

    /// The public key as an RFC 7638 canonical JWK.
    fn jwk(key: &dyn HardwareSigner) -> Result<String, String> {
        let pk = key
            .public_key_sec1()
            .map_err(|e| format!("DPoP public key: {e}"))?;
        Ok(format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            B64.encode(&pk[1..33]),
            B64.encode(&pk[33..65])
        ))
    }

    fn jkt(jwk: &str) -> String {
        B64.encode(Sha256::digest(jwk.as_bytes()))
    }

    /// `base64url(header).base64url(payload)` of a proof bound to `token`.
    fn signing_input(jwk: &str, token: &str) -> String {
        let header = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}"#);
        let iat = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let payload = format!(
            r#"{{"htm":"{HTM}","htu":"{EMBEDDED_HTU}","iat":{iat},"jti":"{}","ath":"{}"}}"#,
            uuid::Uuid::new_v4(),
            B64.encode(Sha256::digest(token.as_bytes()))
        );
        format!("{}.{}", B64.encode(header), B64.encode(payload))
    }
}

fn unwrap_envelope(resp: Value, method: &str) -> Result<Value, String> {
    if let Some(err) = resp.get("error") {
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown RPC error");
        return Err(format!("{}: {}", method, msg));
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/* --------------------------------------------------------------------- */
/* hardware                                                               */
/* --------------------------------------------------------------------- */

/// Host hardware profile. Cheap probe (sysinfo plus a few platform
/// reads), returned uncached so an eGPU attached at runtime shows up.
pub fn hardware_profile() -> Value {
    let p = crate::hardware::HardwareProfile::detect();
    serde_json::json!({
        "ram_gb": p.ram_gb,
        "physical_cores": p.physical_cores,
        "gpu_class": format!("{:?}", p.gpu_class).to_lowercase(),
        "free_disk_gb": p.free_disk_gb,
    })
}

/// What this machine can offer the network, and the headroom behind
/// each offer. Derived in Rust so the onboarding UI never re-implements
/// hardware policy in TypeScript — a second copy would drift from the
/// node's own role-admission gate.
pub fn capability_readout() -> Value {
    let readout = crate::hardware::HardwareProfile::detect().readout();
    serde_json::to_value(readout).unwrap_or(Value::Null)
}

/* --------------------------------------------------------------------- */
/* local model catalogue                                                  */
/* --------------------------------------------------------------------- */

/// Directory the node's downloader writes GGUFs into.
///
/// The shared machine-wide store, which is the same directory
/// `NodeConfig::effective_models_dir()` resolves to, so the catalogue and the embedded
/// node's downloads agree on what is present.
pub fn models_dir() -> Result<std::path::PathBuf, String> {
    tenzro_types::paths::try_tenzro_home()
        .map(|_| tenzro_types::paths::models_dir())
        .map_err(|e| e.to_string())
}

/// The catalogue's relative path for an entry. Sharded entries carry a
/// `subdir/first-shard.gguf` filename; flat entries carry a bare file
/// name; a few carry nothing and fall back to `<id>.gguf`.
pub fn download_rel_path(entry: &tenzro_model::catalog::HfModelEntry) -> String {
    if entry.download_filename.is_empty() {
        format!("{}.gguf", entry.id)
    } else {
        entry.download_filename.clone()
    }
}

/// Bytes an entry occupies on disk, and whether it is present at all.
/// Handles both layouts: a flat GGUF, or a subdirectory of shards that
/// must be totalled.
pub fn on_disk(entry: &tenzro_model::catalog::HfModelEntry) -> (bool, u64, Option<String>) {
    let Ok(dir) = models_dir() else {
        return (false, 0, None);
    };
    let rel = download_rel_path(entry);
    let path = dir.join(&rel);

    if path.exists() {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        return (true, size, Some(path.display().to_string()));
    }

    if rel.contains('/') {
        if let Some(subdir) = path.parent() {
            if subdir.exists() {
                let mut total = 0u64;
                if let Ok(rd) = std::fs::read_dir(subdir) {
                    for e in rd.flatten() {
                        if e.path().extension().and_then(|s| s.to_str()) == Some("gguf") {
                            total += e.metadata().map(|m| m.len()).unwrap_or(0);
                        }
                    }
                }
                if total > 0 {
                    return (true, total, Some(subdir.display().to_string()));
                }
            }
        }
    }

    (false, 0, None)
}

/// Is this model currently resident in the node's inference runtime?
async fn is_loaded(state: &AppState, id: &str) -> bool {
    let node = {
        let guard = state.node.read().await;
        match guard.as_ref() {
            Some(h) => h.node(),
            None => return false,
        }
    };
    node.model_runtime_arc()
        .map(|rt| rt.list_loaded().iter().any(|m| m == id))
        .unwrap_or(false)
}

/// Catalogue metadata merged with on-disk facts for one model. Returns
/// `null` for an id the catalogue doesn't know.
pub async fn model_details(id: String, state: &AppState) -> Result<Value, String> {
    let Some(entry) = tenzro_model::catalog::get_model_by_id(&id) else {
        return Ok(Value::Null);
    };

    let (downloaded, on_disk_bytes, on_disk_path) = on_disk(&entry);
    let dir = models_dir()?;

    let mmproj_path = entry
        .mmproj
        .as_ref()
        .map(|_| dir.join(format!("{}.mmproj.gguf", entry.id)));
    let mmproj_present = mmproj_path.as_ref().map(|p| p.exists()).unwrap_or(false);
    let mmproj_bytes = mmproj_path
        .as_ref()
        .filter(|p| p.exists())
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .unwrap_or(0);

    let moe = entry.moe.map(|m| {
        serde_json::json!({
            "num_experts": m.num_experts,
            "experts_per_token": m.experts_per_token,
            "shared_experts": m.shared_experts,
        })
    });

    Ok(serde_json::json!({
        "id": entry.id,
        "name": entry.name,
        "family": entry.family,
        "description": entry.description,
        "license": tenzro_model::catalog::entry(&entry.id).map(|e| e.licence.name),
        "hf_repo": entry.hf_repo,
        "parameters": entry.parameters,
        "architecture": entry.architecture,
        "context_length": entry.context_length,
        "quantization": entry.quantization,
        "min_ram_gb": entry.min_ram_gb,
        "catalog_size_bytes": entry.size_bytes,
        "moe": moe,
        "mmproj_required": entry.mmproj.is_some(),
        "local": {
            "downloaded": downloaded,
            "on_disk_bytes": on_disk_bytes,
            "on_disk_path": on_disk_path,
            "download_filename": download_rel_path(&entry),
            "mmproj_present": mmproj_present,
            "mmproj_bytes": mmproj_bytes,
            "loaded": is_loaded(state, &entry.id).await,
        },
    }))
}

/// Delete a downloaded model to reclaim disk. Refuses while the model
/// is loaded — unloading first is the caller's job, because a live
/// serving slot pointing at a deleted file is a far worse failure than
/// an explicit refusal. Returns the bytes freed.
pub async fn offload_model(id: String, state: &AppState) -> Result<u64, String> {
    let entry = tenzro_model::catalog::get_model_by_id(&id)
        .ok_or_else(|| format!("unknown model id: {}", id))?;

    if is_loaded(state, &id).await {
        return Err(
            "model is currently being served — stop serving it first, then retry".to_string(),
        );
    }

    let dir = models_dir()?;
    let rel = download_rel_path(&entry);
    let main_path = dir.join(&rel);
    let mut freed: u64 = 0;

    if rel.contains('/') {
        if let Some(subdir) = main_path.parent() {
            if subdir.exists() && subdir != dir {
                if let Ok(rd) = std::fs::read_dir(subdir) {
                    for e in rd.flatten() {
                        freed += e.metadata().map(|m| m.len()).unwrap_or(0);
                    }
                }
                std::fs::remove_dir_all(subdir)
                    .map_err(|e| format!("failed to remove {}: {}", subdir.display(), e))?;
            }
        }
    } else if main_path.exists() {
        freed += std::fs::metadata(&main_path).map(|m| m.len()).unwrap_or(0);
        std::fs::remove_file(&main_path)
            .map_err(|e| format!("failed to remove {}: {}", main_path.display(), e))?;
    }

    if entry.mmproj.is_some() {
        let p = dir.join(format!("{}.mmproj.gguf", entry.id));
        if p.exists() {
            freed += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let _ = std::fs::remove_file(&p);
        }
    }

    for suffix in [".tmp", ".partial", ".download", ".gguf.tmp"] {
        let p = dir.join(format!("{}{}", entry.id, suffix));
        if p.exists() {
            freed += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let _ = std::fs::remove_file(&p);
        }
    }

    tracing::info!(model_id = %id, freed_bytes = freed, "removed model from disk");
    Ok(freed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_serves_the_read_methods_the_ui_uses() {
        assert!(console_allows("tenzro_getNodeStatus"));
        assert!(console_allows("tenzro_listModelEndpoints"));
    }

    #[test]
    fn console_serves_the_sponsorship_reads() {
        for method in [
            "tenzro_slaVerdict",
            "tenzro_getTreasuryPayouts",
            "tenzro_getSponsoredBond",
            "tenzro_listProposals",
        ] {
            assert!(console_allows(method), "{method} is a read the Dashboard needs");
        }
    }

    #[test]
    fn console_refuses_mutations_and_operator_methods() {
        for method in [
            "tenzro_issueAccessToken",
            "tenzro_setRole",
            "tenzro_sendRawTransaction",
            "tenzro_addMachineAccess",
            "tenzro_shutdown",
            "tenzro_serveModel",
            "",
        ] {
            assert!(!console_allows(method), "{method} must not pass the console");
        }
    }

    #[test]
    fn console_args_cannot_carry_a_credential() {
        // A webview that sends a credential has it dropped at the IPC
        // boundary: the argument type has no field for it.
        let args: RpcCallArgs = serde_json::from_value(serde_json::json!({
            "method": "tenzro_getNodeStatus",
            "params": {},
            "authorization": "DPoP stolen",
            "api_key": "tnz_stolen",
        }))
        .unwrap();
        assert_eq!(args.method, "tenzro_getNodeStatus");
        assert!(!format!("{args:?}").contains("stolen"));
    }
}
