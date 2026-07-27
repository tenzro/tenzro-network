//! Sandboxed execution for bundled marketplace skills.
//!
//! Registry admission is permissionless, so a published skill is
//! untrusted code from an unknown author. The sandbox — not the registry
//! — is what a caller relies on: a skill that supplies a content-addressed
//! bundle runs as a WASI 0.2 component with no filesystem, no network,
//! no environment, under a fuel budget and an epoch deadline, and the
//! invocation returns the receipt recording what the guest consumed.
//!
//! A bundle carries two digests. The `tenzro://blob/<blake3>` locator is
//! verified by iroh-blobs on transfer; the SHA-256 is the digest the
//! publisher declared and the one a caller pins through
//! `expected_sha256`. Both are checked before the guest runs, so the
//! bytes that execute are the bytes the registry row names.
//!
//! The guest contract is the `tenzro:skill/skill@1.0.0` interface: one
//! `invoke` export taking a JSON request string and returning a JSON
//! response string.

use std::sync::Arc;

use serde_json::Value;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Export the skill contract resolves inside `tenzro:skill/skill@1.0.0`.
#[cfg(feature = "wasi-skills")]
pub(crate) const SKILL_EXPORT: &str = "invoke";

/// Fetch, verify, and run a skill's bundle in the component sandbox.
///
/// `invocation_id` scopes the registration so concurrent calls against
/// the same skill never contend for one registry entry; the receipt
/// carries the content hash, which is the identity that matters.
#[cfg(feature = "wasi-skills")]
pub(crate) async fn execute_bundle(
    node: &Arc<TenzroNode>,
    skill: &tenzro_types::SkillDefinition,
    invocation_id: &str,
    input: &Value,
    caller_did: Option<String>,
) -> std::result::Result<Value, JsonRpcError> {
    use sha2::{Digest, Sha256};
    use tenzro_iroh::IrohResolver as _;

    let bundle = skill.bundle.as_ref().ok_or_else(|| JsonRpcError {
        code: -32603,
        message: format!("Skill '{}' publishes no bundle", skill.skill_id),
        data: None,
    })?;
    bundle.validate().map_err(|e| JsonRpcError {
        code: -32006,
        message: format!("Malformed bundle on skill '{}': {e}", skill.skill_id),
        data: None,
    })?;

    let resolver = node.iroh_resolver.clone().ok_or_else(|| JsonRpcError {
        code: -32004,
        message: "iroh transport not bound on this node — bundle bytes are unreachable".to_string(),
        data: None,
    })?;
    let uri = tenzro_types::tenzro_uri::TenzroUri::parse(&bundle.uri).map_err(|e| JsonRpcError {
        code: -32006,
        message: format!("Bundle URI '{}' does not parse: {e}", bundle.uri),
        data: None,
    })?;
    let bundle_bytes = resolver.fetch_bytes(&uri).await.map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("Fetching bundle {}: {e}", bundle.uri),
        data: None,
    })?;

    // iroh-blobs already verified BLAKE3 on read. The publisher's SHA-256
    // is the digest a caller pins, so it is checked here against the bytes
    // that are about to execute rather than trusted from the row.
    let content_hash_hex = hex::encode(Sha256::digest(&bundle_bytes));
    let declared = bundle.sha256.to_ascii_lowercase();
    if content_hash_hex != declared {
        return Err(JsonRpcError {
            code: -32006,
            message: format!(
                "Bundle bytes hash {content_hash_hex}, registry row declares {declared}"
            ),
            data: Some(serde_json::json!({
                "skill_id": skill.skill_id,
                "bundle_uri": bundle.uri,
                "declared_sha256": declared,
                "actual_sha256": content_hash_hex,
            })),
        });
    }

    // Capabilities are denied outright: publisher code gets pure compute
    // over the JSON it is handed. An operator grants more only by hosting
    // the skill behind an endpoint they control.
    let component_id = format!("skill:{}:{}", skill.skill_id, invocation_id);
    let manifest = tenzro_wasm::ComponentManifest {
        id: component_id.clone(),
        version: skill.version.clone(),
        content_hash_hex: content_hash_hex.clone(),
        runtime: tenzro_wasm::ComponentRuntime::AgentSkill,
        capabilities: tenzro_wasm::SkillCapabilities::deny_all(),
        deadline_ms: None,
        fuel_limit: None,
        description: Some(skill.description.clone()),
        creator_did: Some(skill.creator_did.clone()),
    };

    let input_bytes = bytes::Bytes::from(serde_json::to_vec(input).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("'input' is not serializable: {e}"),
        data: None,
    })?);

    let sandbox = node.sandboxed_tools();
    sandbox.register(manifest, bundle_bytes).map_err(|e| JsonRpcError {
        code: -32006,
        message: format!("Bundle rejected by the sandbox: {e}"),
        data: None,
    })?;
    let outcome = sandbox
        .invoke(&component_id, SKILL_EXPORT, input_bytes, caller_did)
        .await;
    sandbox.unregister(&component_id);

    let (output, receipt) = outcome.map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("Skill '{}' failed in the sandbox: {e}", skill.skill_id),
        data: Some(serde_json::json!({
            "skill_id": skill.skill_id,
            "content_hash": content_hash_hex,
        })),
    })?;
    let output_value = serde_json::from_slice::<Value>(output.as_ref())
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(output.as_ref()).into_owned()));

    Ok(serde_json::json!({
        "output": output_value,
        "sandbox": {
            "content_hash": content_hash_hex,
            "bundle_uri": bundle.uri,
            "receipt": receipt,
        }
    }))
}

/// Without the `wasi-skills` feature the node links no component engine,
/// so a bundled skill reports the sandbox as unavailable rather than
/// running the bytes unsandboxed.
#[cfg(not(feature = "wasi-skills"))]
pub(crate) async fn execute_bundle(
    _node: &Arc<TenzroNode>,
    _skill: &tenzro_types::SkillDefinition,
    _invocation_id: &str,
    _input: &Value,
    _caller_did: Option<String>,
) -> std::result::Result<Value, JsonRpcError> {
    Err(JsonRpcError {
        code: -32603,
        message: "This node was built without the component sandbox (wasi-skills), so bundled \
                  skills cannot run here"
            .to_string(),
        data: None,
    })
}
