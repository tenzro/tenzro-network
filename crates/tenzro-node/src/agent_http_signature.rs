//! HTTP message signatures on the requests agents send, and the key
//! directory that lets a server off the network verify them.
//!
//! When an agent's request leaves this node and this machine serves the
//! agent under its on-chain terms, the request is signed with the agent's
//! key on this machine: the TPM-held P-256 key its controller approved in
//! those terms. The signature names the agent and the approval digest of the
//! terms it acts under (see `tenzro_payments::rfc9421::agent`).
//!
//! `tenzro_resolveAgentKey` answers, from chain state, what a verifier needs
//! to check such a request: the key behind a `keyid`, the agent and root it
//! belongs to, the terms in force and whether the agent is revoked or
//! quarantined. The same state renders the agent's Web Bot Auth key
//! directory, served at `/.well-known/http-message-signatures-directory`:
//! every node serves the same keys, and a revoked agent's directory is empty
//! from the next block on.

use std::sync::Arc;

use serde_json::Value;
use tenzro_payments::rfc9421::agent::{AgentKeyResolution, sign_agent_request};
use tenzro_payments::rfc9421::{HttpSigner, RequestParts};
use tenzro_vm::traits::VmState;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// The agent's TPM key on this machine, behind the RFC 9421 signer seam.
struct AgentKey(Box<dyn tenzro_device_key::HardwareSigner>);

impl HttpSigner for AgentKey {
    fn sign(&self, base: &[u8]) -> tenzro_payments::Result<Vec<u8>> {
        self.0
            .sign(base)
            .map(|s| s.to_vec())
            .map_err(|e| tenzro_payments::PaymentError::Rfc9421Error(format!("agent key: {e}")))
    }
}

/// The public origin this node's operator published, under which the
/// directory named in each signed request is served.
static DIRECTORY_ORIGIN: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Record the operator-published origin the directory is served under.
pub(crate) fn set_directory_origin(origin: Option<String>) {
    let _ = DIRECTORY_ORIGIN.set(origin);
}

/// Every key the terms of `agent_did` assign, as chain state holds them now.
pub(crate) fn resolutions(chain: &dyn VmState, agent_did: &str) -> Vec<AgentKeyResolution> {
    let Some(stored) = tenzro_vm::native::read_agent_terms(chain, agent_did) else {
        return Vec::new();
    };
    stored
        .terms
        .serving_nodes
        .iter()
        .filter_map(|n| resolve(chain, agent_did, &n.dpop_jkt))
        .collect()
}

/// The agent's key directory at the current height.
pub(crate) fn directory(chain: &dyn VmState, agent_did: &str) -> Result<Value, String> {
    tenzro_payments::rfc9421::agent::directory(
        &resolutions(chain, agent_did),
        crate::calendar::now_ms(),
    )
    .map_err(|e| e.to_string())
}

/// What a verifier needs about the key `keyid` of `agent_did`, read from
/// chain state. `None` when the agent's terms name no serving node with
/// that key.
pub(crate) fn resolve(
    chain: &dyn VmState,
    agent_did: &str,
    keyid: &str,
) -> Option<AgentKeyResolution> {
    let stored = tenzro_vm::native::read_agent_terms(chain, agent_did)?;
    let node = stored
        .terms
        .serving_nodes
        .iter()
        .find(|n| n.dpop_jkt == keyid)?;
    let status = tenzro_vm::native::read_agent_quarantine(chain, agent_did);
    Some(AgentKeyResolution {
        agent_did: agent_did.to_string(),
        root: tenzro_vm::funding::root_did(agent_did),
        keyid: keyid.to_string(),
        public_key: node.dpop_public_key.clone(),
        machine_did: node.machine_did.clone(),
        key_certification: node.key_certification.clone(),
        mandate: stored.approval_digest.clone(),
        terms_version: stored.version,
        expires_at_ms: stored.terms.expires_at_ms,
        revoked: status.as_ref().is_some_and(|q| q.revoked),
        quarantined: status.as_ref().is_some_and(|q| !q.revoked),
    })
}

/// Sign `request` for `agent_did` when this machine serves the agent under
/// its terms. Requests for an identity with no terms, or terms this machine
/// does not serve, are returned as they are; a machine that serves the agent
/// but cannot sign refuses the request rather than send it unsigned.
pub(crate) async fn sign_for_agent(
    chain: Option<tenzro_vm::StateAdapter>,
    agent_did: &str,
    mut request: reqwest::Request,
) -> Result<reqwest::Request, String> {
    let Some(stored) = chain
        .as_ref()
        .and_then(|c| tenzro_vm::native::read_agent_terms(c, agent_did))
    else {
        return Ok(request);
    };
    let Ok((_, _, machine_did)) = crate::agent_delegation::this_machine() else {
        return Ok(request);
    };
    let Some(node) = stored.terms.serving_node(&machine_did).cloned() else {
        return Ok(request);
    };
    let url = request.url().clone();
    let authority = match url.port() {
        Some(port) => format!("{}:{port}", url.host_str().unwrap_or_default()),
        None => url.host_str().unwrap_or_default().to_string(),
    };
    let parts = RequestParts::for_request(request.method().as_str(), authority, url.path())
        .with_query(url.query().unwrap_or_default())
        .with_scheme(url.scheme());
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .map(<[u8]>::to_vec);
    let origin = DIRECTORY_ORIGIN
        .get()
        .cloned()
        .flatten()
        .ok_or("the agent's requests name a key directory: publish external_rpc_addr")?;
    let directory_url = tenzro_payments::rfc9421::agent::directory_url(&origin, agent_did);
    let agent = agent_did.to_string();
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let nonce = hex::encode(uuid::Uuid::new_v4().as_bytes());
    let headers = tokio::task::spawn_blocking(move || {
        let label = crate::agent_delegation::key_label(&agent, &machine_did);
        let key = tenzro_device_key::signer::open_or_create(&label)
            .map_err(|e| format!("agent key: {e}"))?;
        let sec1 = key
            .public_key_sec1()
            .map_err(|e| format!("agent key: {e}"))?;
        if crate::agent_delegation::jkt_of(&sec1[1..])? != node.dpop_jkt {
            return Err(
                "this machine's key for the agent is not the one its terms approve".to_string(),
            );
        }
        sign_agent_request(
            parts,
            body.as_deref(),
            &agent,
            &stored.approval_digest,
            &node.dpop_jkt,
            &directory_url,
            created,
            &nonce,
            &AgentKey(key),
        )
        .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    for (name, value) in headers {
        let name =
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|e| e.to_string())?;
        let value = reqwest::header::HeaderValue::from_str(&value).map_err(|e| e.to_string())?;
        request.headers_mut().insert(name, value);
    }
    Ok(request)
}

fn bad(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_resolveAgentKey { agent_did, keyid }`.
pub(crate) async fn handle_resolve(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.ok_or_else(|| bad("Missing params"))?;
    let field = |name: &str| {
        params
            .get(name)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| bad(format!("Missing '{name}'")))
    };
    let agent_did = field("agent_did")?;
    let keyid = field("keyid")?;
    let chain = crate::rpc::chain_state_of(node).ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "this node holds no chain state".into(),
        data: None,
    })?;
    let resolution = resolve(&chain, agent_did, keyid).ok_or_else(|| JsonRpcError {
        code: -32004,
        message: format!("{agent_did} has no key {keyid} in its terms"),
        data: None,
    })?;
    serde_json::to_value(resolution).map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
    })
}

/// `GET /.well-known/http-message-signatures-directory?agent=<did>`.
pub(crate) async fn serve_directory(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some(agent) = q.get("agent").filter(|a| !a.is_empty()) else {
        return (axum::http::StatusCode::BAD_REQUEST, "agent is required").into_response();
    };
    let Some(chain) = crate::rpc::chain_state_of(&node) else {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "no chain state",
        )
            .into_response();
    };
    match directory(&chain, agent) {
        Ok(doc) => (
            axum::http::StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    tenzro_payments::rfc9421::agent::DIRECTORY_MEDIA_TYPE,
                ),
                // Revocation empties the directory from the next block, so a
                // verifier never holds it longer than a block.
                (axum::http::header::CACHE_CONTROL, "max-age=1"),
            ],
            doc.to_string(),
        )
            .into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use tenzro_payments::rfc9421::agent::verify_agent_request;
    use tenzro_types::agent_terms::{AgentTerms, ServingNode, TermsScope};
    use tenzro_vm::native::{AgentQuarantine, SYSTEM_ADDRESS, StoredAgentTerms};

    const AGENT: &str = "did:tenzro:machine:alice:shopper";

    struct SoftKey(SigningKey);

    impl HttpSigner for SoftKey {
        fn sign(&self, base: &[u8]) -> tenzro_payments::Result<Vec<u8>> {
            let sig: Signature = self.0.sign(base);
            Ok(sig.to_bytes().to_vec())
        }
    }

    fn put<T: serde::Serialize>(chain: &mut tenzro_vm::StateAdapter, slot: &str, v: &T) {
        chain.set_storage(
            &SYSTEM_ADDRESS,
            slot.as_bytes(),
            serde_json::to_vec(v).unwrap(),
        );
    }

    /// A request signed with the key the agent's on-chain terms approve
    /// verifies against the directory read; once the controller revokes the
    /// agent, the same request is refused.
    #[test]
    fn a_merchant_verifies_an_agent_request_from_chain_state_alone() {
        let key = SigningKey::from_slice(&[5u8; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let xy = &point.as_bytes()[1..];
        let jkt = crate::agent_delegation::jkt_of(xy).unwrap();
        let terms = AgentTerms {
            controller_did: "did:tenzro:human:alice".into(),
            agent_name: "shopper".into(),
            delegation_scope: TermsScope::default(),
            capabilities: vec![],
            serving_nodes: vec![ServingNode {
                machine_did: "did:tenzro:machine:m1".into(),
                operator_did: "did:tenzro:human:op".into(),
                dpop_public_key: hex::encode(xy),
                dpop_jkt: jkt.clone(),
                key_certification: String::new(),
                sealing_public_key: String::new(),
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        let mut chain = tenzro_vm::StateAdapter::new();
        let stored = StoredAgentTerms {
            terms,
            root: tenzro_types::agent_terms::RootKind::Passkey,
            version: 3,
            approval_digest: "beef".into(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        };
        put(
            &mut chain,
            &tenzro_vm::native::agent_terms::terms_key(AGENT),
            &stored,
        );

        assert!(resolve(&chain, AGENT, "not-a-key").is_none());
        let res = resolve(&chain, AGENT, &jkt).unwrap();
        assert_eq!(
            (res.root.as_str(), res.terms_version, res.mandate.as_str()),
            ("did:tenzro:human:alice", 3, "beef")
        );

        let parts = RequestParts::for_request("POST", "shop.example", "/buy").with_query("sku=1");
        let body = b"{\"qty\":1}";
        let now = 2_000_000_000;
        let headers = sign_agent_request(
            parts.clone(),
            Some(body),
            AGENT,
            "beef",
            &jkt,
            &tenzro_payments::rfc9421::agent::directory_url("https://node.example", AGENT),
            now,
            "n",
            &SoftKey(key),
        )
        .unwrap();
        let signed = headers
            .into_iter()
            .fold(parts, |p, (k, v)| p.with_header(k, v));
        verify_agent_request(&signed, Some(body), &res, now).unwrap();

        // The directory is the terms' keys, each under the thumbprint the
        // signature names as its keyid.
        let live = directory(&chain, AGENT).unwrap();
        assert_eq!(live["keys"].as_array().unwrap().len(), 1);
        assert_eq!(live["keys"][0]["kid"], jkt.as_str());
        assert_eq!(
            directory(&chain, "did:tenzro:machine:nobody").unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            0
        );

        let revoked = AgentQuarantine {
            controller_did: "did:tenzro:human:alice".into(),
            by: "aa".into(),
            reason_code: 0,
            evidence_hash: None,
            at_ms: 1,
            revoked: true,
        };
        put(
            &mut chain,
            &tenzro_vm::native::agent_audit::quarantine_key(AGENT),
            &revoked,
        );
        let res = resolve(&chain, AGENT, &jkt).unwrap();
        assert!(res.revoked);
        assert!(verify_agent_request(&signed, Some(body), &res, now).is_err());
        // Revoked: the directory every node serves is empty.
        assert_eq!(
            directory(&chain, AGENT).unwrap()["keys"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
    }
}
