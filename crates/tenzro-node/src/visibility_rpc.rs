//! Operator control over what this node advertises.
//!
//! See [`tenzro_types::node_visibility`] for the model. This is the surface an
//! operator drives it from, plus the persistence that makes a choice survive a
//! restart — a node that came back advertising capabilities its operator had
//! hidden would be worse than one that never offered the switch.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_storage::{CF_METADATA, KvStore};
use tenzro_types::node_visibility::{Capability, NodeVisibility, Visibility};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Where the policy is persisted.
const VISIBILITY_KEY: &[u8] = b"node_visibility";

/// Load the persisted policy, or the default when there is none.
///
/// An unreadable row falls back to the default *and warns*, rather than
/// failing startup: a node that will not boot because it cannot parse a
/// discovery preference has turned a cosmetic problem into an outage.
pub fn load(storage: &Arc<dyn KvStore>) -> NodeVisibility {
    match storage.get(CF_METADATA, VISIBILITY_KEY) {
        Ok(Some(bytes)) => match serde_json::from_slice::<NodeVisibility>(&bytes) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "Unreadable node-visibility policy; defaulting to public");
                NodeVisibility::default()
            }
        },
        _ => NodeVisibility::default(),
    }
}

/// Persist the policy.
fn store(node: &Arc<TenzroNode>, policy: &NodeVisibility) {
    let Some(storage) = node.storage() else {
        return;
    };
    match serde_json::to_vec(policy) {
        Ok(bytes) => {
            if let Err(e) = storage.put(CF_METADATA, VISIBILITY_KEY, &bytes) {
                tracing::warn!(error = %e, "Could not persist the node-visibility policy");
            }
        }
        Err(e) => tracing::warn!(error = %e, "Could not serialize the node-visibility policy"),
    }
}

/// Render the policy for a caller.
fn render(policy: &NodeVisibility) -> Value {
    let capabilities: Vec<Value> = policy
        .all()
        .into_iter()
        .map(|(c, v)| {
            json!({
                "capability": c.as_str(),
                "visibility": v.as_str(),
                "advertised": v.is_advertised(),
                "can_be_private": c.can_be_private(),
            })
        })
        .collect();
    json!({
        "capabilities": capabilities,
        "has_private_capabilities": policy.has_private_capabilities(),
        // Said on every response rather than left to documentation. The
        // failure mode this guards against is an operator marking something
        // private and believing it is therefore protected.
        "note": "Visibility controls discovery, not access. A private capability is not \
                 announced to peers, but anyone who learns this node's address and holds the \
                 required credential can still use it. Access control is the API-key scopes, \
                 the service-key admission gate, and per-resource access policies.",
    })
}

/// `tenzro_nodeVisibility` — what this node advertises.
pub(crate) async fn handle_node_visibility(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    Ok(render(&node.visibility()))
}

/// `tenzro_setNodeVisibility` — change what this node advertises.
///
/// Params: either `{capability, visibility}` for one capability, or
/// `{preset: "public" | "private"}` for all of them at once. Admin-gated: this
/// is the operator's own machine policy, not a tenant's.
pub(crate) async fn handle_set_node_visibility(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing params: expected {capability, visibility} or {preset}".to_string(),
        data: None,
    })?;

    let mut policy = node.visibility();

    if let Some(preset) = p.get("preset").and_then(|v| v.as_str()) {
        policy = match preset {
            "public" => NodeVisibility::public(),
            // `private` hides everything that can be hidden; consensus stays
            // advertised because a validator its peers cannot reach cannot
            // vote. Applying it silently would be the wrong kind of quiet.
            "private" => NodeVisibility::private(),
            other => {
                return Err(JsonRpcError {
                    code: -32602,
                    message: format!("Unknown preset '{other}' (public|private)"),
                    data: None,
                });
            }
        };
    } else {
        let capability = p
            .get("capability")
            .and_then(|v| v.as_str())
            .and_then(Capability::parse)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: format!(
                    "Missing or unknown 'capability'. Expected one of: {}",
                    Capability::ALL
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                data: None,
            })?;
        let visibility = p
            .get("visibility")
            .and_then(|v| v.as_str())
            .and_then(Visibility::parse)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing or unknown 'visibility' (network|private)".to_string(),
                data: None,
            })?;
        policy
            .set(capability, visibility)
            .map_err(|e| JsonRpcError {
                code: -32602,
                message: e.to_string(),
                data: None,
            })?;
    }

    *node.node_visibility.write() = policy.clone();
    store(node, &policy);
    tracing::info!(
        private = policy.has_private_capabilities(),
        "Node visibility updated"
    );
    Ok(render(&policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rendered_policy_lists_every_capability() {
        // An operator's view must show the whole picture, not only the
        // entries someone happened to change.
        let rendered = render(&NodeVisibility::public());
        let caps = rendered["capabilities"].as_array().expect("array");
        assert_eq!(caps.len(), Capability::ALL.len());
        assert!(caps.iter().all(|c| c["advertised"] == true));
        assert_eq!(rendered["has_private_capabilities"], false);
    }

    #[test]
    fn the_private_preset_leaves_consensus_advertised() {
        let rendered = render(&NodeVisibility::private());
        let caps = rendered["capabilities"].as_array().expect("array");
        let validator = caps
            .iter()
            .find(|c| c["capability"] == "validator")
            .expect("validator listed");
        assert_eq!(
            validator["advertised"], true,
            "a hidden validator cannot be reached by peers, so it cannot vote"
        );
        assert_eq!(validator["can_be_private"], false);
        let ai = caps.iter().find(|c| c["capability"] == "ai").unwrap();
        assert_eq!(ai["advertised"], false);
    }

    #[test]
    fn every_response_says_that_privacy_is_not_access_control() {
        // The failure mode being guarded against is an operator marking
        // something private and believing it is therefore protected.
        for policy in [NodeVisibility::public(), NodeVisibility::private()] {
            let note = render(&policy)["note"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            assert!(note.contains("discovery, not access"), "{note}");
        }
    }
}
