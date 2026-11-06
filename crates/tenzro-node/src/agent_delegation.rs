//! Agent delegation: a controller approves an agent's terms with a custody
//! challenge, and only a new approval changes them.
//!
//! Three custody operations:
//!
//! - `delegate_agent` creates the agent. `account` is the controller's smart
//!   account and `target` the hash of the agent's completed terms.
//! - `update_agent_terms` replaces the terms of an existing agent; its DID
//!   does not change. `target` is the hash of the new completed terms, with
//!   the credential rotation flag appended.
//! - `revoke_identity` revokes the agent (or, signed by a root for itself,
//!   the root and every agent it delegated). `target` is
//!   `tenzro_types::identity::revocation_target(did, reason)`. The revocation
//!   is a `RevokeIdentity` transaction every validator re-verifies, so every
//!   node refuses the agent's actions from then on.
//!
//! The terms name the nodes that serve the agent. Each serving node holds its
//! own P-256 key for the agent in its TPM, re-created from a label derived
//! from the agent and the machine, and its TPM certifies the key with
//! `TPM2_Certify`. The node issuing the challenge collects each key and
//! certification over the `tenzro/agent-key` transport before it computes
//! the target, so the controller approves the exact keys that may act.
//!
//! Approved terms go on chain with the controller's passkey assertion, which
//! every validator re-verifies. Each action the agent takes is signed by the
//! one serving node that computed it, after that node checked it against the
//! terms; the VM checks it again at execution and its verdict is final.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tenzro_iroh::{ALPN_AGENT_KEY, ALPN_AGENT_TOKEN, EndpointId, Reply, RequestHandler};

pub use tenzro_types::agent_terms::{AgentAction, AgentTerms, ServingNode, TermsScope};

use crate::node::TenzroNode;
use crate::passkey_rpc::{
    CUSTODY_CHALLENGE_TTL_SECS, CreateCustodyChallengeRequest, CustodyAuthorization,
    CustodyOperation, decode_hex, require_account_control_detailed,
};
use crate::rpc::JsonRpcError;

/// Capability a node announces when it serves delegated agents.
pub const AGENT_SERVING_CAPABILITY: &str = "agent_serving";

/// Domain of a serving node's statement about its agent key.
const KEY_CERT_DOMAIN: &[u8] = b"tenzro/agent-key/v1";

/// Domain of the label a serving node derives its agent key from.
const KEY_LABEL_DOMAIN: &[u8] = b"tenzro/agent-dpop";

/// How long the issuing node waits for a serving node.
const PEER_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on a peer's answer.
const MAX_PEER_ANSWER: usize = 64 * 1024;

/// Upper bound on serving nodes in one agent's terms.
const MAX_SERVING_NODES: usize = 16;

/// Upper bound on entries in each list of the terms.
const MAX_LIST_ENTRIES: usize = 64;

/// Upper bound on one list entry, bytes.
const MAX_ENTRY_LEN: usize = 128;

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32001,
        message: message.into(),
        data: None,
    }
}

fn failed(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: message.into(),
        data: None,
    }
}

fn outside(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32003,
        message: message.into(),
        data: None,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_amount(field: &str, value: &Option<String>) -> Result<Option<u128>, JsonRpcError> {
    tenzro_types::agent_terms::parse_amount(value.as_deref())
        .map_err(|e| invalid(format!("{field}: {e}")))
}

fn check_list(field: &str, items: &[String]) -> Result<(), JsonRpcError> {
    if items.len() > MAX_LIST_ENTRIES {
        return Err(invalid(format!(
            "{field} holds at most {MAX_LIST_ENTRIES} entries"
        )));
    }
    if items
        .iter()
        .any(|i| i.is_empty() || i.len() > MAX_ENTRY_LEN)
    {
        return Err(invalid(format!(
            "each {field} entry must be 1 to {MAX_ENTRY_LEN} bytes"
        )));
    }
    Ok(())
}

/// Node-side checks on terms, beyond what hashing them needs.
trait TermsCheck {
    fn check_shape(&self) -> Result<(), JsonRpcError>;
    fn check_completed(
        &self,
        state: &dyn tenzro_vm::traits::VmState,
        agent_did: &str,
    ) -> Result<(), JsonRpcError>;
    fn metadata(&self, approval: &[u8; 32]) -> HashMap<String, String>;
    fn public_serving_nodes(&self) -> Value;
}

impl TermsCheck for AgentTerms {
    /// Refuse terms that are malformed, whatever their serving nodes say.
    fn check_shape(&self) -> Result<(), JsonRpcError> {
        if self.controller_did.is_empty() {
            return Err(invalid("controller_did is required"));
        }
        if !tenzro_identity::did::is_valid_agent_name(&self.agent_name) {
            return Err(invalid(
                "agent_name must be 1 to 64 characters of a-z, 0-9, '-', '_' or '.'",
            ));
        }
        let s = &self.delegation_scope;
        parse_amount("max_transaction_value", &s.max_transaction_value)?;
        parse_amount("max_daily_spend", &s.max_daily_spend)?;
        parse_amount("max_hourly_spend", &s.max_hourly_spend)?;
        parse_amount("step_up_above", &s.step_up_above)?;
        parse_amount("tainted_value_limit", &s.tainted_value_limit)?;
        parse_amount("cosign_above", &s.cosign_above)?;
        if let Some(ttl) = s.remote_grant_ttl_ms
            && (ttl == 0 || ttl > tenzro_types::agent_terms::MAX_REMOTE_GRANT_TTL_MS)
        {
            return Err(invalid("remote_grant_ttl_ms is 1 to 86400000"));
        }
        let mut assets = std::collections::HashSet::new();
        for l in &s.remote_limits {
            if l.caip19.is_empty() || l.caip19.len() > 256 || !assets.insert(l.caip19.as_str()) {
                return Err(invalid(
                    "remote_limits name each asset once, by its CAIP-19 id",
                ));
            }
            match parse_amount("remote_limits.max_per_day", &Some(l.max_per_day.clone()))? {
                Some(v) if v > 0 => {}
                _ => return Err(invalid("remote_limits.max_per_day is a positive amount")),
            }
        }
        if !s.remote_limits.is_empty() && s.max_daily_spend.is_none() {
            return Err(invalid(
                "remote_limits need max_daily_spend, the rate grants are counted at",
            ));
        }
        if let Some([start, end]) = s.allowed_hours_utc
            && (start > 23 || end > 23 || start == end)
        {
            return Err(invalid(
                "allowed_hours_utc is [start, end): two different UTC hours from 0 to 23",
            ));
        }
        check_list("allowed_operations", &s.allowed_operations)?;
        check_list("allowed_payment_protocols", &s.allowed_payment_protocols)?;
        check_list("allowed_chains", &s.allowed_chains)?;
        check_list("allowed_models", &s.allowed_models)?;
        check_list("allowed_counterparties", &s.allowed_counterparties)?;
        let token_id =
            |t: &str| hex::decode(t.trim_start_matches("0x")).is_ok_and(|b| b.len() == 32);
        if let Some(k) = &s.counterparty_kyc
            && (!(1..=3).contains(&k.min_tier) || !token_id(&k.registry))
        {
            return Err(invalid(
                "counterparty_kyc names a tier from 1 to 3 and a 32-byte registry token id",
            ));
        }
        if s.asset_limits
            .iter()
            .any(|l| l.min_counterparty_kyc_tier > 3)
        {
            return Err(invalid(
                "an asset limit's min_counterparty_kyc_tier is 0 to 3",
            ));
        }
        if s.max_split_fee_bps.is_some_and(|b| b > 10_000) {
            return Err(invalid("max_split_fee_bps is 0 to 10000"));
        }
        check_list("capabilities", &self.capabilities)?;
        if self.serving_nodes.is_empty() || self.serving_nodes.len() > MAX_SERVING_NODES {
            return Err(invalid(format!(
                "serving_nodes must name 1 to {MAX_SERVING_NODES} nodes"
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for n in &self.serving_nodes {
            if n.machine_did.is_empty() || n.operator_did.is_empty() {
                return Err(invalid(
                    "each serving node names its machine_did and operator_did",
                ));
            }
            if !seen.insert(n.machine_did.as_str()) {
                return Err(invalid(format!(
                    "serving node {} is listed twice",
                    n.machine_did
                )));
            }
        }
        if self.min_distinct_operators == 0 {
            return Err(invalid("min_distinct_operators must be at least 1"));
        }
        let operators: std::collections::HashSet<&str> = self
            .serving_nodes
            .iter()
            .map(|n| n.operator_did.as_str())
            .collect();
        if (operators.len() as u32) < self.min_distinct_operators {
            return Err(invalid(format!(
                "the serving nodes span {} distinct operators; the terms require {}",
                operators.len(),
                self.min_distinct_operators
            )));
        }
        if let Some(at) = self.expires_at_ms
            && at <= now_ms()
        {
            return Err(invalid("expires_at_ms is in the past"));
        }
        Ok(())
    }

    /// Refuse terms whose serving-node keys are missing or not certified.
    fn check_completed(
        &self,
        state: &dyn tenzro_vm::traits::VmState,
        agent_did: &str,
    ) -> Result<(), JsonRpcError> {
        for n in &self.serving_nodes {
            verify_certification(state, agent_did, n).map_err(|e| {
                invalid(format!(
                    "serving node {} in delegation is not complete: {e}; send the delegation \
                     the challenge returned, unchanged",
                    n.machine_did
                ))
            })?;
        }
        Ok(())
    }

    fn metadata(&self, approval: &[u8; 32]) -> HashMap<String, String> {
        HashMap::from([
            ("agent_name".to_string(), self.agent_name.clone()),
            (
                "agent_terms".to_string(),
                serde_json::to_string(self).unwrap_or_default(),
            ),
            ("agent_terms_approval".to_string(), hex::encode(approval)),
        ])
    }

    fn public_serving_nodes(&self) -> Value {
        Value::Array(
            self.serving_nodes
                .iter()
                .map(|n| {
                    serde_json::json!({
                        "machine_did": n.machine_did,
                        "operator_did": n.operator_did,
                        "dpop_jkt": n.dpop_jkt,
                    })
                })
                .collect(),
        )
    }
}

// ---------------------------------------------------------------------------
// Serving-node keys and their TPM certification.
// ---------------------------------------------------------------------------

/// What the issuing node asks a serving node for.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentKeyRequest {
    /// The agent the key is for.
    pub agent_did: String,
    /// The agent's controller.
    pub controller_did: String,
    /// The agent's name.
    pub agent_name: String,
}

fn cert_message(agent_did: &str, machine_did: &str, operator_did: &str, key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(256);
    m.extend_from_slice(KEY_CERT_DOMAIN);
    for part in [
        agent_did.as_bytes(),
        machine_did.as_bytes(),
        operator_did.as_bytes(),
        key,
    ] {
        m.extend_from_slice(&(part.len() as u32).to_be_bytes());
        m.extend_from_slice(part);
    }
    m
}

pub(crate) fn jkt_of(xy: &[u8]) -> Result<String, String> {
    if xy.len() != 64 {
        return Err("the key is not a 64-byte P-256 point".to_string());
    }
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let jwk = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64.encode(&xy[..32]),
        "y": b64.encode(&xy[32..]),
    });
    tenzro_auth::DpopProof::compute_jkt(&jwk.to_string()).map_err(|e| e.to_string())
}

fn take_part<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    if input.len() < 4 {
        return Err("key_certification is truncated".to_string());
    }
    let n = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if input.len() < 4 + n {
        return Err("key_certification is truncated".to_string());
    }
    let (v, rest) = input[4..].split_at(n);
    *input = rest;
    Ok(v)
}

/// Check a serving node's key: its TPM certified it with `TPM2_Certify`
/// over this agent, this machine, this operator and this key, and the
/// machine identity named in the entry vouches for that TPM's attestation
/// key. The thumbprint must be the key's.
///
/// The attestation key is trusted only as the key of a machine admitted on
/// chain with a quote by it, whose endorsement certificate chains to a TPM
/// manufacturer root governance recognises. A certification by any other
/// key, however well formed, proves nothing about where the key lives.
pub fn verify_certification(
    state: &dyn tenzro_vm::traits::VmState,
    agent_did: &str,
    n: &ServingNode,
) -> Result<(), String> {
    use tenzro_device_key::key_certification::{KeyCertification, verify};
    let key = hex::decode(&n.dpop_public_key).map_err(|_| "dpop_public_key is not hex")?;
    if jkt_of(&key)? != n.dpop_jkt {
        return Err("dpop_jkt is not the thumbprint of dpop_public_key".to_string());
    }
    let bytes = hex::decode(&n.key_certification).map_err(|_| "key_certification is not hex")?;
    let (tpm, mut rest) = KeyCertification::from_bytes(&bytes)?;
    let machine_key = take_part(&mut rest)?;
    let machine_sig = take_part(&mut rest)?;
    if !rest.is_empty() {
        return Err("key_certification has trailing bytes".to_string());
    }
    if tenzro_types::did_derivation::machine_did(machine_key) != n.machine_did {
        return Err("key_certification is bound by another machine".to_string());
    }
    let msg = cert_message(agent_did, &n.machine_did, &n.operator_did, &key);
    let extra: [u8; 32] = Sha256::digest(&msg).into();
    let attestation_key = admitted_attestation_key(state, &n.machine_did, &tpm.ak_public)?;
    verify(&tpm, &key, &extra, &attestation_key).map_err(|e| format!("TPM certification: {e}"))?;
    let mut binding = msg;
    binding.extend_from_slice(&tpm.ak_name()?);
    if !tenzro_device_key::signer::verify_p256(machine_key, &binding, machine_sig) {
        return Err("the machine does not vouch for the certifying TPM".to_string());
    }
    Ok(())
}

/// The attestation key `ak_public` names, when it is the key of a TPM the
/// chain admitted: admitted under the serving machine's own identity
/// `machine_did` (a machine root that recorded its TPM's attestation), or as
/// the autonomous machine the attestation key roots. Either identity carries
/// a quote by the key that binds it, and that TPM's endorsement certificate
/// chains to a recognised manufacturer root.
fn admitted_attestation_key(
    state: &dyn tenzro_vm::traits::VmState,
    machine_did: &str,
    ak_public: &[u8],
) -> Result<[u8; 65], String> {
    let claimed = tenzro_device_key::tpm_wire::parse_public(ak_public)
        .ok()
        .and_then(|ak| ak.p256_sec1())
        .ok_or("the certifying key is not a P-256 attestation key")?;
    let admitted_under_root = tenzro_vm::native::funding::machine_attestation(state, machine_did)
        .ok()
        .and_then(|att| tenzro_tee::tpm_attest::attestation_key_sec1(&att.evidence).ok())
        == Some(claimed);
    let did = if admitted_under_root {
        machine_did.to_string()
    } else {
        tenzro_tee::tpm_attest::machine_did_for_attestation_key(&claimed)
    };
    let admitted = tenzro_vm::native::funding::machine_attestation(state, &did)
        .map_err(|e| format!("the certifying TPM is not an admitted machine: {e}"))?;
    let admitted_key = tenzro_tee::tpm_attest::attestation_key_sec1(&admitted.evidence)
        .map_err(|e| format!("{did}'s admitted attestation key: {e}"))?;
    if admitted_key != claimed {
        return Err(format!("{did} was admitted with another attestation key"));
    }
    tenzro_vm::native::machine_endorsed(state, &did, now_ms() as i64)
        .map_err(|e| format!("the certifying TPM has no recognised endorsement: {e}"))?;
    Ok(admitted_key)
}

pub(crate) fn key_label(agent_did: &str, machine_did: &str) -> String {
    let digest = Sha256::new()
        .chain_update(KEY_LABEL_DOMAIN)
        .chain_update((agent_did.len() as u32).to_be_bytes())
        .chain_update(agent_did.as_bytes())
        .chain_update(machine_did.as_bytes())
        .finalize();
    format!("tenzro-agent-{}", hex::encode(&digest[..16]))
}

/// This node's ML-DSA-65 key for `agent_did`, derived from `root` under
/// the agent's key label, with its proof of possession: what the controller
/// puts on chain when it requires the agent's ML-DSA leg.
pub(crate) fn agent_node_pq_key_from(
    root: &tenzro_device_key::DerivationRoot,
    agent_did: &str,
    machine_did: &str,
) -> Result<tenzro_types::account_signature::AgentNodePqKey, String> {
    let label = key_label(agent_did, machine_did);
    let ml_dsa_public_key = root
        .ml_dsa65_public(&label)
        .map_err(|e| format!("agent ML-DSA key: {e}"))?;
    let possession = root
        .ml_dsa65_sign(
            &label,
            tenzro_types::account_signature::AGENT_NODE_PQ_POSSESSION_CONTEXT,
            &tenzro_types::account_signature::agent_node_pq_possession_message(
                agent_did,
                machine_did,
                &ml_dsa_public_key,
            ),
        )
        .map_err(|e| format!("agent ML-DSA key: {e}"))?;
    Ok(tenzro_types::account_signature::AgentNodePqKey {
        machine_did: machine_did.to_string(),
        ml_dsa_public_key,
        possession,
    })
}

/// This node's ML-DSA-65 signature for `agent_did` over `digest`, by the key
/// [`agent_node_pq_key_from`] names.
pub(crate) fn agent_node_pq_sign(
    root: &tenzro_device_key::DerivationRoot,
    agent_did: &str,
    machine_did: &str,
    digest: &[u8; 32],
) -> Result<Vec<u8>, String> {
    root.ml_dsa65_sign(
        &key_label(agent_did, machine_did),
        tenzro_types::account_signature::AGENT_NODE_PQ_CONTEXT,
        digest,
    )
    .map_err(|e| format!("agent ML-DSA key: {e}"))
}

/// This machine's derivation root.
fn pq_root() -> Result<tenzro_device_key::DerivationRoot, String> {
    let root = tenzro_device_key::DerivationRoot::open_or_create()
        .map_err(|e| format!("derivation root: {e}"))?;
    Ok(root)
}

/// This node's ML-DSA-65 signature for `agent_did` over `digest`, when the
/// agent's wallet requires the ML-DSA leg in `chain`; `None` otherwise.
pub(crate) async fn agent_pq_leg(
    chain: &dyn tenzro_vm::VmState,
    agent_did: &str,
    machine_did: &str,
    digest: [u8; 32],
) -> Result<Option<Vec<u8>>, String> {
    let wallet = tenzro_types::agent_terms::agent_wallet(agent_did);
    if !tenzro_vm::account_keys::pq_required(chain, &wallet) {
        return Ok(None);
    }
    let (agent, machine) = (agent_did.to_string(), machine_did.to_string());
    tokio::task::spawn_blocking(move || {
        agent_node_pq_sign(&pq_root()?, &agent, &machine, &digest).map(Some)
    })
    .await
    .map_err(|e| e.to_string())?
}

/// `tenzro_agentNodePqKey { agent_did }`: this node's ML-DSA-65 key for the
/// agent with its proof of possession, for the controller to put on chain
/// in `AccountKeysOp::RequireAgentPqLeg`.
pub(crate) async fn handle_agent_node_pq_key(params: Option<Value>) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let agent_did = params
        .get("agent_did")
        .and_then(Value::as_str)
        .ok_or_else(|| outside("agent_did is required"))?
        .to_string();
    let (_, _, machine_did) = this_machine().map_err(failed)?;
    let key = tokio::task::spawn_blocking(move || {
        agent_node_pq_key_from(&pq_root()?, &agent_did, &machine_did)
    })
    .await
    .map_err(|e| failed(e.to_string()))?
    .map_err(failed)?;
    serde_json::to_value(key).map_err(|e| failed(e.to_string()))
}

pub(crate) fn this_machine() -> Result<
    (
        &'static dyn tenzro_device_key::HardwareSigner,
        [u8; 65],
        String,
    ),
    String,
> {
    let machine = crate::identity_bootstrap::machine_signer()
        .ok_or("this machine has no TPM 2.0 identity")?;
    let machine_key = machine
        .public_key_sec1()
        .map_err(|e| format!("machine key: {e}"))?;
    let machine_did = tenzro_types::did_derivation::machine_did(&machine_key);
    Ok((machine, machine_key, machine_did))
}

/// Answer an agent-key request from this machine's TPM. Blocking.
///
/// The key is a TPM primary derived from a label over the agent and this
/// machine, so it is the same key after a restart and it never leaves the
/// chip. The TPM certifies it; a machine that cannot produce that
/// certification refuses to serve.
pub fn answer_key_request(
    operator_did: Option<&str>,
    sealing_public_key: Option<tenzro_crypto::hybrid_seal::HybridPublicKey>,
    req: &AgentKeyRequest,
) -> Result<ServingNode, String> {
    let operator_did = operator_did.ok_or("this node has no operator identity")?;
    let (machine, machine_key, machine_did) = this_machine()?;
    let label = key_label(&req.agent_did, &machine_did);
    // The certification's statement covers the key itself, so the key is
    // derived first; creating a TPM primary is deterministic in the label.
    let agent_key =
        tenzro_device_key::signer::open_or_create(&label).map_err(|e| format!("agent key: {e}"))?;
    let sec1 = agent_key
        .public_key_sec1()
        .map_err(|e| format!("agent key: {e}"))?;
    let xy = &sec1[1..];
    let msg = cert_message(&req.agent_did, &machine_did, operator_did, xy);
    let extra: [u8; 32] = Sha256::digest(&msg).into();
    let (certified_xy, tpm) =
        tenzro_device_key::key_certification::certify_local_key(&label, &extra)?;
    if certified_xy.as_slice() != xy {
        return Err("the TPM certified a different key".to_string());
    }
    let mut binding = msg;
    binding.extend_from_slice(&tpm.ak_name()?);
    let machine_sig = machine
        .sign(&binding)
        .map_err(|e| format!("machine key refused to sign: {e}"))?;
    let mut cert = tpm.to_bytes();
    for part in [machine_key.as_slice(), machine_sig.as_slice()] {
        cert.extend_from_slice(&(part.len() as u32).to_be_bytes());
        cert.extend_from_slice(part);
    }
    Ok(ServingNode {
        machine_did,
        operator_did: operator_did.to_string(),
        dpop_public_key: hex::encode(xy),
        dpop_jkt: jkt_of(xy)?,
        key_certification: hex::encode(cert),
        sealing_public_key: sealing_public_key
            .map(|k| hex::encode(k.encode()))
            .unwrap_or_default(),
    })
}

/// Serves agent-key requests on this node's endpoint.
#[derive(Debug)]
pub struct AgentKeyServer {
    operator_did: Option<String>,
    sealing_public_key: Option<tenzro_crypto::hybrid_seal::HybridPublicKey>,
}

impl AgentKeyServer {
    /// A server answering as `operator_did`'s node, publishing the key the
    /// agent's brokered credentials are sealed to.
    pub fn new(
        operator_did: Option<String>,
        sealing_public_key: Option<tenzro_crypto::hybrid_seal::HybridPublicKey>,
    ) -> Self {
        Self {
            operator_did,
            sealing_public_key,
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for AgentKeyServer {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let req: AgentKeyRequest = match serde_json::from_slice(&request) {
            Ok(r) => r,
            Err(e) => return Reply::full(400, format!("malformed agent-key request: {e}")),
        };
        let operator = self.operator_did.clone();
        let sealing = self.sealing_public_key.clone();
        match tokio::task::spawn_blocking(move || {
            answer_key_request(operator.as_deref(), sealing, &req)
        })
        .await
        {
            Ok(Ok(answer)) => match serde_json::to_vec(&answer) {
                Ok(body) => Reply::full(200, body),
                Err(e) => Reply::full(500, format!("encode answer: {e}")),
            },
            Ok(Err(e)) => Reply::full(403, e),
            Err(e) => Reply::full(500, format!("agent-key task failed: {e}")),
        }
    }
}

/// Send `body` to the node `machine_did` on `alpn` and return its answer.
async fn ask_peer(
    node: &Arc<TenzroNode>,
    machine_did: &str,
    alpn: &'static [u8],
    body: Vec<u8>,
) -> Result<Bytes, String> {
    let transport = node
        .identity_transport
        .as_ref()
        .ok_or("this node resolves no machine identities")?;
    let record = transport
        .store()
        .lookup(machine_did)
        .ok_or("its endpoint record has not reached this node")?;
    let addr =
        tenzro_iroh::identity_transport::endpoint_addr(&record).map_err(|e| e.to_string())?;
    let resolver = node
        .iroh_resolver()
        .ok_or("this node has no transport endpoint")?;
    let call = async {
        let response = tenzro_iroh::request(resolver.endpoint(), addr, alpn, &body).await?;
        let ok = response.is_success();
        let bytes = response.bytes(MAX_PEER_ANSWER).await?;
        Ok::<_, tenzro_iroh::IrohError>((ok, bytes))
    };
    let (ok, bytes) = tokio::time::timeout(PEER_TIMEOUT, call)
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.to_string())?;
    if !ok {
        return Err(String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(bytes)
}

fn is_this_machine(machine_did: &str) -> bool {
    crate::identity_bootstrap::machine_did().as_deref() == Some(machine_did)
}

/// Collect one serving node's key and certification: from this machine's
/// own TPM when the entry names it, otherwise over the transport.
async fn fetch_key(
    node: &Arc<TenzroNode>,
    req: &AgentKeyRequest,
    machine_did: &str,
) -> Result<ServingNode, JsonRpcError> {
    let refuse = |why: String| failed(format!("serving node {machine_did} did not answer: {why}"));
    if is_this_machine(machine_did) {
        if !node.config().serves_agents() {
            return Err(refuse(
                "this node does not serve delegated agents".to_string(),
            ));
        }
        let operator = node.operator_did();
        let sealing = node.machine_sealing_public_key().ok();
        let r = req.clone();
        return tokio::task::spawn_blocking(move || {
            answer_key_request(operator.as_deref(), sealing, &r)
        })
        .await
        .map_err(|e| refuse(e.to_string()))?
        .map_err(refuse);
    }
    let body = serde_json::to_vec(req).map_err(|e| refuse(e.to_string()))?;
    let bytes = ask_peer(node, machine_did, ALPN_AGENT_KEY, body)
        .await
        .map_err(refuse)?;
    serde_json::from_slice(&bytes).map_err(|e| refuse(format!("malformed answer: {e}")))
}

// ---------------------------------------------------------------------------
// Per-node tokens.
// ---------------------------------------------------------------------------

/// A token delivered to a serving node, bound to its key for one agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentTokenDelivery {
    /// The agent.
    pub agent_did: String,
    /// The serving node the token is for.
    pub machine_did: String,
    /// DPoP-bound access token; `cnf.jkt` is the node's key for the agent.
    pub access_token: String,
    /// Seconds until it expires.
    pub expires_in: u64,
}

fn delivered() -> &'static parking_lot::Mutex<HashMap<String, AgentTokenDelivery>> {
    static TOKENS: OnceLock<parking_lot::Mutex<HashMap<String, AgentTokenDelivery>>> =
        OnceLock::new();
    TOKENS.get_or_init(Default::default)
}

/// The token this node holds for serving `agent_did`, if one was delivered.
pub fn delivered_token(agent_did: &str) -> Option<AgentTokenDelivery> {
    delivered().lock().get(agent_did).cloned()
}

/// The `cnf.jkt` claim of a JWT, read without verifying it: the caller
/// checks it against a key it holds, and the issuing node verifies the
/// token whenever it is presented.
fn token_jkt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v.get("cnf")?.get("jkt")?.as_str().map(str::to_string)
}

/// Accept a token for an agent this node serves: it must name this machine
/// and be bound to this machine's own key for the agent.
fn accept_token(delivery: AgentTokenDelivery) -> Result<(), String> {
    let (_, _, machine_did) = this_machine()?;
    if delivery.machine_did != machine_did {
        return Err("the token is for another machine".to_string());
    }
    let key =
        tenzro_device_key::signer::open_or_create(&key_label(&delivery.agent_did, &machine_did))
            .map_err(|e| format!("agent key: {e}"))?;
    let sec1 = key
        .public_key_sec1()
        .map_err(|e| format!("agent key: {e}"))?;
    if token_jkt(&delivery.access_token) != Some(jkt_of(&sec1[1..])?) {
        return Err("the token is not bound to this machine's key for the agent".to_string());
    }
    delivered()
        .lock()
        .insert(delivery.agent_did.clone(), delivery);
    Ok(())
}

/// Receives the tokens bound to this node's agent keys.
#[derive(Debug)]
pub struct AgentTokenServer;

#[async_trait::async_trait]
impl RequestHandler for AgentTokenServer {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let delivery: AgentTokenDelivery = match serde_json::from_slice(&request) {
            Ok(d) => d,
            Err(e) => return Reply::full(400, format!("malformed agent token: {e}")),
        };
        match tokio::task::spawn_blocking(move || accept_token(delivery)).await {
            Ok(Ok(())) => Reply::full(200, "accepted"),
            Ok(Err(e)) => Reply::full(403, e),
            Err(e) => Reply::full(500, format!("agent-token task failed: {e}")),
        }
    }
}

/// Mint a DPoP-bound token for each serving node, bound to that node's key
/// for the agent, and deliver it to the node. Never returned to the caller.
async fn deliver_tokens(node: &Arc<TenzroNode>, agent_did: &str, terms: &AgentTerms) -> Value {
    let s = &terms.delegation_scope;
    let envelope = crate::rpc::delegated_agent_envelope(
        s.max_transaction_value
            .as_deref()
            .and_then(|v| v.parse().ok()),
        s.max_daily_spend.as_deref().and_then(|v| v.parse().ok()),
        &s.allowed_operations,
    );
    let ttl = terms
        .expires_at_ms
        .map(|at| at.saturating_sub(now_ms()) / 1000)
        .filter(|t| *t > 0);
    let mut out = Vec::new();
    for n in &terms.serving_nodes {
        let result = async {
            let token = crate::rpc::mint_onboarding_jwt(
                node,
                agent_did,
                &terms.controller_did,
                Some(&n.dpop_jkt),
                envelope.clone(),
                ttl,
            )
            .map_err(|e| e.message)?;
            let delivery = AgentTokenDelivery {
                agent_did: agent_did.to_string(),
                machine_did: n.machine_did.clone(),
                access_token: token,
                expires_in: crate::rpc::effective_ttl_secs(node, ttl),
            };
            if is_this_machine(&n.machine_did) {
                return tokio::task::spawn_blocking(move || accept_token(delivery))
                    .await
                    .map_err(|e| e.to_string())?;
            }
            let body = serde_json::to_vec(&delivery).map_err(|e| e.to_string())?;
            ask_peer(node, &n.machine_did, ALPN_AGENT_TOKEN, body)
                .await
                .map(|_| ())
        }
        .await;
        out.push(match result {
            Ok(()) => serde_json::json!({ "machine_did": n.machine_did, "delivered": true }),
            Err(e) => {
                serde_json::json!({ "machine_did": n.machine_did, "delivered": false, "error": e })
            }
        });
    }
    Value::Array(out)
}

// ---------------------------------------------------------------------------
// Controller, agent and chain state.
// ---------------------------------------------------------------------------

/// The controller's smart account, which their passkey is enrolled on.
/// The root's identity and the account its approvals name: a human's smart
/// account, or the ledger account an autonomous machine's registered hardware
/// key names.
fn controller_account(
    node: &Arc<TenzroNode>,
    controller_did: &str,
) -> Result<(tenzro_identity::TenzroIdentity, Vec<u8>), JsonRpcError> {
    let no_account = || {
        refused(format!(
            "controller {controller_did} is not an active human with a passkey account or an \
             autonomous machine registered on chain"
        ))
    };
    let registry = node
        .identity_registry()
        .ok_or_else(|| failed("Identity registry not initialized"))?;
    let identity = registry.resolve(controller_did).map_err(|_| no_account())?;
    if identity.status != tenzro_identity::IdentityStatus::Active {
        return Err(no_account());
    }
    let account = match tenzro_types::agent_terms::RootKind::of(controller_did) {
        Some(tenzro_types::agent_terms::RootKind::Passkey) if identity.is_human() => identity
            .metadata
            .get("smart_account_address")
            .ok_or_else(no_account)
            .and_then(|a| decode_hex(a))?,
        Some(tenzro_types::agent_terms::RootKind::Machine) if identity.is_machine() => {
            let chain = crate::rpc::chain_state_of(node)
                .ok_or_else(|| failed("chain state unavailable"))?;
            let xy =
                tenzro_vm::native::machine_root_key(&chain, controller_did).map_err(refused)?;
            tenzro_crypto::composite::account_slot(&xy).to_vec()
        }
        _ => return Err(no_account()),
    };
    Ok((identity, account))
}

/// The agent's DID: derived from the controller's identity and the name.
fn agent_did_of(
    controller: &tenzro_identity::TenzroIdentity,
    agent_name: &str,
) -> Result<String, JsonRpcError> {
    tenzro_identity::TenzroDid::delegated_agent(&controller.did.id, agent_name)
        .map(|d| d.to_string())
        .map_err(|e| invalid(e.to_string()))
}

fn existing_agent(node: &Arc<TenzroNode>, did: &str) -> Option<tenzro_identity::TenzroIdentity> {
    node.identity_registry()?.resolve(did).ok()
}

/// A machine root's approval of a custody challenge: its hardware composite
/// signature over the challenge digest under the account-owner context.
#[derive(Debug, Deserialize)]
struct MachineRootAuthorization {
    challenge_id: String,
    signature: tenzro_crypto::composite::CompositeSignature,
}

/// The root's approval of `op` over `target` on `account`, from the
/// `authorization` in `params`: a passkey's custody assertion for a human
/// root, a hardware signature for a machine root. The node consumes the
/// challenge it issued, then verifies the approval exactly as validators do
/// ([`tenzro_vm::native::verify_root_approval`]), so terms it submits are
/// never refused on chain for their approval.
async fn approve_as_root(
    node: &Arc<TenzroNode>,
    controller_did: &str,
    account: &[u8],
    op: CustodyOperation,
    target: &[u8],
    params: &Value,
) -> Result<tenzro_types::agent_terms::AgentTermsApproval, JsonRpcError> {
    use tenzro_crypto::composite::{ClassicalProof, CompositeSignature};
    use tenzro_types::agent_terms::{AgentTermsApproval, RootKind};
    let approval = match RootKind::of(controller_did) {
        Some(RootKind::Passkey) => {
            let auth = parse_authorization(params)?;
            let a = require_account_control_detailed(node, account, op, target, Some(auth)).await?;
            AgentTermsApproval {
                account: account.to_vec(),
                nonce: a.nonce,
                root_public_key: a.passkey_xy.to_vec(),
                signature: CompositeSignature {
                    classical: ClassicalProof::WebAuthn {
                        authenticator_data: a.assertion.authenticator_data,
                        client_data_json: a.assertion.client_data_json,
                        signature: a.assertion.signature,
                    },
                    pq: a.ml_dsa_signature,
                },
            }
        }
        Some(RootKind::Machine) => {
            let raw = params.get("authorization").cloned().ok_or_else(|| {
                refused("authorization is required: the machine root's hardware signature")
            })?;
            let auth: MachineRootAuthorization =
                serde_json::from_value(raw).map_err(|e| invalid(format!("authorization: {e}")))?;
            let chain = crate::rpc::chain_state_of(node)
                .ok_or_else(|| failed("chain state unavailable"))?;
            let xy =
                tenzro_vm::native::machine_root_key(&chain, controller_did).map_err(refused)?;
            let (_, nonce) = node
                .custody_challenges()
                .consume_with_nonce(&auth.challenge_id, account, op, target)
                .map_err(refused)?;
            AgentTermsApproval {
                account: account.to_vec(),
                nonce,
                root_public_key: xy,
                signature: auth.signature,
            }
        }
        None => return Err(refused(format!("{controller_did} cannot root an agent"))),
    };
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| failed("chain state unavailable"))?;
    tenzro_vm::native::verify_root_approval(
        &chain,
        controller_did,
        op.tag(),
        target,
        &approval,
        now_ms(),
    )
    .map_err(refused)?;
    Ok(approval)
}

/// Record approved terms in chain state, where every node enforces them.
async fn record_terms_on_chain(
    node: &Arc<TenzroNode>,
    terms: &AgentTerms,
    rotate: Option<bool>,
    approval: tenzro_types::agent_terms::AgentTermsApproval,
) -> Result<Value, JsonRpcError> {
    let tx = tenzro_types::TransactionType::SetAgentTerms {
        terms: terms.clone(),
        rotate,
        approval,
    };
    let r = crate::rpc::submit_as_validator(node, tx, 200_000).await?;
    // The chain is what decides whether the Terms hold (the agent's bond, the approval, the scope). Nothing is
    // registered or delivered for Terms it refused: an agent left without Terms could be neither created again
    // nor changed.
    if let (Some(submitter), Some(hash)) = (node.ledger_submitter(), r["tx_hash"].as_str())
        && let crate::payment_rails::Inclusion::Executed(receipt) =
            submitter.await_inclusion(hash, TERMS_WAIT).await
        && !receipt.success
    {
        return Err(refused(format!(
            "the chain refused the Terms: {}",
            receipt
                .revert_reason
                .unwrap_or_else(|| "the transaction reverted".to_string())
        )));
    }
    Ok(r["tx_hash"].clone())
}

/// How long a delegation waits for its Terms transaction to execute before it
/// answers.
const TERMS_WAIT: Duration = Duration::from_secs(60);

/// `tenzro_createCustodyChallenge` for `delegate_agent` and
/// `update_agent_terms`: complete the terms and issue the challenge over
/// their hash. With `device_public_key`, the challenge is for a machine
/// delegated under the controller, which serves as its own single node.
pub(crate) async fn create_challenge(
    node: &Arc<TenzroNode>,
    req: CreateCustodyChallengeRequest,
) -> Result<Value, JsonRpcError> {
    let op = req.operation;
    if req.target_hex.as_deref().is_some_and(|t| !t.is_empty()) {
        return Err(invalid(format!(
            "target_hex must be absent for {op:?}: the node computes the target from delegation"
        )));
    }
    if let Some(device_key) = req.device_public_key.as_deref() {
        return create_machine_challenge(node, &req, device_key);
    }
    let mut terms = req
        .delegation
        .clone()
        .ok_or_else(|| invalid(format!("{op:?} requires delegation: the agent's terms")))?;
    terms.check_shape()?;
    let (controller, account) = controller_account(node, &terms.controller_did)?;
    check_account_matches(req.account_address.as_deref(), &account)?;
    let agent_did = agent_did_of(&controller, &terms.agent_name)?;
    let rotate = match op {
        CustodyOperation::DelegateAgent => {
            if req.agent_did.is_some() || req.rotate_tokens {
                return Err(invalid(
                    "agent_did and rotate_tokens apply only to update_agent_terms",
                ));
            }
            if existing_agent(node, &agent_did).is_some() {
                return Err(failed(format!(
                    "agent {} already exists under this controller",
                    terms.agent_name
                )));
            }
            None
        }
        _ => {
            let given = req
                .agent_did
                .as_deref()
                .ok_or_else(|| invalid("update_agent_terms requires agent_did"))?;
            if given != agent_did {
                return Err(invalid(format!(
                    "{given} is not the agent {} under {}; an agent's name and controller do \
                     not change",
                    terms.agent_name, terms.controller_did
                )));
            }
            check_updatable(node, &agent_did, &terms.controller_did)?;
            Some(req.rotate_tokens)
        }
    };

    let key_req = AgentKeyRequest {
        agent_did: agent_did.clone(),
        controller_did: terms.controller_did.clone(),
        agent_name: terms.agent_name.clone(),
    };
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| failed("chain state unavailable"))?;
    for entry in terms.serving_nodes.iter_mut() {
        let answer = fetch_key(node, &key_req, &entry.machine_did).await?;
        if answer.machine_did != entry.machine_did || answer.operator_did != entry.operator_did {
            return Err(failed(format!(
                "serving node {} answered as {} operated by {}, not operated by {}",
                entry.machine_did, answer.machine_did, answer.operator_did, entry.operator_did
            )));
        }
        verify_certification(&chain, &agent_did, &answer).map_err(|e| {
            failed(format!(
                "serving node {} answered with a key its TPM does not certify: {e}",
                entry.machine_did
            ))
        })?;
        *entry = answer;
    }

    issue_challenge(node, &account, op, &terms, rotate, &agent_did)
}

fn check_account_matches(given: Option<&str>, account: &[u8]) -> Result<(), JsonRpcError> {
    if let Some(given) = given
        && decode_hex(given)? != account
    {
        return Err(invalid(format!(
            "account_address must be the controller's smart account 0x{}",
            hex::encode(account)
        )));
    }
    Ok(())
}

fn issue_challenge(
    node: &Arc<TenzroNode>,
    account: &[u8],
    op: CustodyOperation,
    terms: &AgentTerms,
    rotate: Option<bool>,
    agent_did: &str,
) -> Result<Value, JsonRpcError> {
    let target = terms.target(rotate);
    let (challenge_id, digest, nonce) = node
        .custody_challenges()
        .issue(account, op, &target)
        .map_err(failed)?;
    let mut out = serde_json::json!({
        "challenge_id": challenge_id,
        "challenge_hex": format!("0x{}", hex::encode(digest)),
        "webauthn_challenge": crate::passkey_rpc::custody_webauthn_challenge(&digest),
        "account_address": format!("0x{}", hex::encode(account)),
        "operation": op,
        "target_hex": format!("0x{}", hex::encode(target)),
        "nonce_hex": format!("0x{}", hex::encode(nonce)),
        "chain_id": node.custody_challenges().chain_id(),
        "expires_in_secs": CUSTODY_CHALLENGE_TTL_SECS,
        "agent_did": agent_did,
        "delegation": terms,
    });
    if let Some(rotate) = rotate {
        out["rotate_tokens"] = Value::Bool(rotate);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Machine delegation: a machine with its own hardware key, approved by the
// controller through the same custody challenge.
// ---------------------------------------------------------------------------

fn amount_string(v: Option<&Value>) -> Option<String> {
    let v = v?;
    v.as_str()
        .and_then(|s| s.parse::<u128>().ok())
        .or_else(|| v.as_u64().map(u128::from))
        .map(|n| n.to_string())
}

fn count(v: Option<&Value>) -> Option<u32> {
    v.and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

fn string_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// The terms a controller approves for a machine: the machine is the
/// agent's single serving node, its hardware key the node key.
fn machine_terms(
    controller_did: &str,
    machine_id: &str,
    device_public_key: &[u8],
    scope: &Value,
    capabilities: Vec<String>,
) -> AgentTerms {
    AgentTerms {
        controller_did: controller_did.to_string(),
        agent_name: machine_id.to_string(),
        delegation_scope: TermsScope {
            max_transaction_value: amount_string(scope.get("max_transaction_value")),
            max_daily_spend: amount_string(scope.get("max_daily_spend")),
            allowed_operations: string_list(scope.get("allowed_operations")),
            allowed_payment_protocols: string_list(scope.get("allowed_payment_protocols")),
            allowed_chains: string_list(scope.get("allowed_chains")),
            allowed_models: string_list(scope.get("allowed_models")),
            allowed_counterparties: string_list(scope.get("allowed_counterparties")),
            asset_limits: scope
                .get("asset_limits")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            max_hourly_spend: amount_string(scope.get("max_hourly_spend")),
            max_actions_per_hour: count(scope.get("max_actions_per_hour")),
            max_actions_per_day: count(scope.get("max_actions_per_day")),
            allowed_hours_utc: scope
                .get("allowed_hours_utc")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            step_up_above: amount_string(scope.get("step_up_above")),
            step_up_new_counterparty: scope
                .get("step_up_new_counterparty")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            tainted_value_limit: amount_string(scope.get("tainted_value_limit")),
            remote_grant_ttl_ms: scope.get("remote_grant_ttl_ms").and_then(Value::as_u64),
            remote_limits: scope
                .get("remote_limits")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
            cosign_above: amount_string(scope.get("cosign_above")),
            governance: scope
                .get("governance")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            counterparty_kyc: scope
                .get("counterparty_kyc")
                .and_then(|v| serde_json::from_value(v.clone()).ok()),
            max_split_fee_bps: scope
                .get("max_split_fee_bps")
                .and_then(Value::as_u64)
                .map(|v| v.min(u64::from(u16::MAX)) as u16),
            max_commission_bps: scope
                .get("max_commission_bps")
                .and_then(Value::as_u64)
                .map(|v| v.min(u64::from(u32::MAX)) as u32),
            tool_pins: scope
                .get("tool_pins")
                .and_then(|v| serde_json::from_value(v.clone()).ok())
                .unwrap_or_default(),
        },
        capabilities,
        serving_nodes: vec![ServingNode {
            machine_did: tenzro_types::did_derivation::machine_did(device_public_key),
            operator_did: controller_did.to_string(),
            dpop_public_key: hex::encode(device_public_key),
            dpop_jkt: String::new(),
            key_certification: String::new(),
            sealing_public_key: String::new(),
        }],
        min_distinct_operators: 1,
        expires_at_ms: None,
        trifecta_exception: scope
            .get("trifecta_exception")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        auto_approve: None,
        credentials: Vec::new(),
    }
}

fn create_machine_challenge(
    node: &Arc<TenzroNode>,
    req: &CreateCustodyChallengeRequest,
    device_key_hex: &str,
) -> Result<Value, JsonRpcError> {
    if req.operation != CustodyOperation::DelegateAgent {
        return Err(invalid("device_public_key applies only to delegate_agent"));
    }
    let device_key = decode_hex(device_key_hex)?;
    let d = req
        .delegation
        .as_ref()
        .ok_or_else(|| invalid("delegate_agent requires delegation: the machine's terms"))?;
    let machine_id = req
        .machine_id
        .as_deref()
        .ok_or_else(|| invalid("a machine delegation names machine_id"))?;
    let scope = serde_json::to_value(&d.delegation_scope).unwrap_or(Value::Null);
    let terms = machine_terms(
        &d.controller_did,
        machine_id,
        &device_key,
        &scope,
        d.capabilities.clone(),
    );
    let (_, account) = controller_account(node, &terms.controller_did)?;
    check_account_matches(req.account_address.as_deref(), &account)?;
    let machine_did = terms.serving_nodes[0].machine_did.clone();
    issue_challenge(
        node,
        &account,
        CustodyOperation::DelegateAgent,
        &terms,
        None,
        &machine_did,
    )
}

/// The controller's consent to registering a machine under it: the root's
/// approval, over a `delegate_agent` challenge, of the machine's
/// terms with its hardware key as the single serving node.
pub(crate) async fn require_account_control_for_machine(
    node: &Arc<TenzroNode>,
    params: &Value,
    controller_did: &str,
    machine_id: &str,
    device_public_key: &[u8],
) -> Result<(), JsonRpcError> {
    let scope = params
        .get("delegation_scope")
        .cloned()
        .unwrap_or(Value::Null);
    let terms = machine_terms(
        controller_did,
        machine_id,
        device_public_key,
        &scope,
        string_list(params.get("capabilities")),
    );
    let (_, account) = controller_account(node, controller_did)?;
    approve_as_root(
        node,
        controller_did,
        &account,
        CustodyOperation::DelegateAgent,
        &terms.target(None),
        params,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Onboard, update, revoke.
// ---------------------------------------------------------------------------

/// Refuse a terms change on an agent that is gone, revoked, or controlled by
/// someone else.
fn check_updatable(
    node: &Arc<TenzroNode>,
    agent_did: &str,
    controller_did: &str,
) -> Result<tenzro_identity::TenzroIdentity, JsonRpcError> {
    let agent = existing_agent(node, agent_did)
        .ok_or_else(|| invalid(format!("{agent_did} is not a registered agent")))?;
    if agent.controller_did() != Some(controller_did) {
        return Err(refused(format!(
            "{agent_did} is not controlled by {controller_did}"
        )));
    }
    if agent.status != tenzro_identity::IdentityStatus::Active
        || node.agent_audit().is_revoked(agent_did)
    {
        return Err(refused(format!(
            "{agent_did} is revoked; its terms cannot change"
        )));
    }
    Ok(agent)
}

fn parse_terms(params: &Value) -> Result<AgentTerms, JsonRpcError> {
    let raw = params
        .get("delegation")
        .cloned()
        .ok_or_else(|| invalid("delegation is required: the terms the challenge returned"))?;
    serde_json::from_value(raw).map_err(|e| invalid(format!("delegation: {e}")))
}

fn parse_authorization(params: &Value) -> Result<CustodyAuthorization, JsonRpcError> {
    let raw = params
        .get("authorization")
        .cloned()
        .ok_or_else(|| refused("authorization is required: the controller's passkey approval"))?;
    serde_json::from_value(raw).map_err(|e| invalid(format!("authorization: {e}")))
}

/// Withdraw every live access token `agent_did` holds on this node. Returns
/// how many. The agent signs in again under whatever its Terms now allow.
fn revoke_agent_tokens(node: &Arc<TenzroNode>, agent_did: &str) -> usize {
    let Some(engine) = node.auth_engine() else {
        return 0;
    };
    let Ok(live) = engine.live_tokens(chrono::Utc::now().timestamp() as u64) else {
        return 0;
    };
    live.into_iter()
        .filter(|t| t.bearer_did == agent_did)
        .filter(|t| {
            engine
                .revoke_token(&t.jti, "agent credentials rotated or revoked")
                .is_ok()
        })
        .count()
}

/// `tenzro_onboardDelegatedAgent` with a passkey approval: the controller's
/// `authorization` over the completed `delegation`.
pub(crate) async fn onboard(node: &Arc<TenzroNode>, params: &Value) -> Result<Value, JsonRpcError> {
    let terms = parse_terms(params)?;
    terms.check_shape()?;
    let (controller, account) = controller_account(node, &terms.controller_did)?;
    let agent_did = agent_did_of(&controller, &terms.agent_name)?;
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| failed("chain state unavailable"))?;
    terms.check_completed(&chain, &agent_did)?;
    if existing_agent(node, &agent_did).is_some() {
        return Err(failed(format!(
            "agent {} already exists under this controller",
            terms.agent_name
        )));
    }
    let target = terms.target(None);
    let approval = approve_as_root(
        node,
        &terms.controller_did,
        &account,
        CustodyOperation::DelegateAgent,
        &target,
        params,
    )
    .await?;
    let digest = tenzro_types::agent_terms::custody_challenge_digest(
        node.chain_id(),
        &approval.account,
        CustodyOperation::DelegateAgent.tag(),
        &target,
        &approval.nonce,
    );
    let chain_tx = record_terms_on_chain(node, &terms, None, approval).await?;

    let registry = node
        .identity_registry()
        .ok_or_else(|| failed("Identity registry not initialized"))?;
    let identity = registry
        .register_delegated_agent(
            &terms.controller_did,
            &terms.agent_name,
            terms.capabilities.clone(),
            terms.metadata(&digest),
        )
        .map_err(|e| failed(format!("agent registration failed: {e}")))?;
    crate::rpc::persist_identity(node, &identity)?;
    let did = identity.did_string();
    let tokens = deliver_tokens(node, &did, &terms).await;

    Ok(serde_json::json!({
        "identity": {
            "did": did,
            "identity_type": "machine",
            "controller_did": terms.controller_did,
            "capabilities": terms.capabilities,
            "status": format!("{}", identity.status),
        },
        "wallet": {
            "wallet_id": identity.wallet_id,
            "address": format!("0x{}", hex::encode(identity.wallet_address.as_bytes())),
        },
        "serving_nodes": terms.public_serving_nodes(),
        "min_distinct_operators": terms.min_distinct_operators,
        "expires_at_ms": terms.expires_at_ms,
        "terms_tx": chain_tx,
        "token_delivery": tokens,
    }))
}

/// `tenzro_updateAgentTerms`: replace an agent's terms with the controller's
/// passkey approval of the new completed terms.
pub(crate) async fn handle_update_agent_terms(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let agent_did = params
        .get("agent_did")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("agent_did is required"))?
        .to_string();
    let rotate = params
        .get("rotate_tokens")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let terms = parse_terms(&params)?;
    terms.check_shape()?;
    let (controller, account) = controller_account(node, &terms.controller_did)?;
    if agent_did_of(&controller, &terms.agent_name)? != agent_did {
        return Err(invalid(format!(
            "{agent_did} is not the agent {} under {}",
            terms.agent_name, terms.controller_did
        )));
    }
    check_updatable(node, &agent_did, &terms.controller_did)?;
    let chain =
        crate::rpc::chain_state_of(node).ok_or_else(|| failed("chain state unavailable"))?;
    terms.check_completed(&chain, &agent_did)?;
    let target = terms.target(Some(rotate));
    let approval = approve_as_root(
        node,
        &terms.controller_did,
        &account,
        CustodyOperation::UpdateAgentTerms,
        &target,
        &params,
    )
    .await?;
    let digest = tenzro_types::agent_terms::custody_challenge_digest(
        node.chain_id(),
        &approval.account,
        CustodyOperation::UpdateAgentTerms.tag(),
        &target,
        &approval.nonce,
    );
    let chain_tx = record_terms_on_chain(node, &terms, Some(rotate), approval).await?;

    let registry = node
        .identity_registry()
        .ok_or_else(|| failed("Identity registry not initialized"))?;
    let identity = registry
        .update_delegated_agent(
            &agent_did,
            terms.capabilities.clone(),
            terms.metadata(&digest),
        )
        .map_err(|e| failed(format!("terms update failed: {e}")))?;
    crate::rpc::persist_identity(node, &identity)?;
    let tokens = deliver_tokens(node, &agent_did, &terms).await;

    let mut out = serde_json::json!({
        "agent_did": agent_did,
        "delegation": terms,
        "terms_tx": chain_tx,
        "token_delivery": tokens,
    });
    if rotate {
        out["tokens_revoked"] = Value::from(revoke_agent_tokens(node, &agent_did));
    }
    Ok(out)
}

/// Forget the access token this node delivered for serving `agent_did`,
/// once consensus has revoked it. Chain state is what every node enforces;
/// this only stops this node handing the agent's token out.
pub(crate) fn forget_delivered_tokens(agent_did: &str) {
    delivered().lock().remove(agent_did);
}

// ---------------------------------------------------------------------------
// Enforcement on the serving node.
// ---------------------------------------------------------------------------

fn chain_terms(
    node: &Arc<TenzroNode>,
    agent_did: &str,
) -> Option<(tenzro_vm::StateAdapter, tenzro_vm::native::StoredAgentTerms)> {
    let chain = crate::rpc::chain_state_of(node)?;
    let terms = tenzro_vm::native::read_agent_terms(&chain, agent_did)?;
    Some((chain, terms))
}

/// The Terms delegated agent `agent_did` acts under, for its audit record:
/// its name, the controller at their root and what that root rests on, the
/// Terms version and the approval digest. `None` for a DID with no Terms on
/// chain.
pub(crate) fn delegation_facts(
    node: &Arc<TenzroNode>,
    agent_did: &str,
) -> Option<crate::admin_audit::Delegation> {
    let (_, stored) = chain_terms(node, agent_did)?;
    Some(crate::admin_audit::Delegation {
        agent_name: stored.terms.agent_name.clone(),
        controller_did: stored.terms.controller_did.clone(),
        root_kind: match stored.root {
            tenzro_types::agent_terms::RootKind::Passkey => "passkey",
            tenzro_types::agent_terms::RootKind::Machine => "machine",
        }
        .to_string(),
        terms_version: stored.version,
        approval_digest: stored.approval_digest.clone(),
        chain: Vec::new(),
    })
}

/// Whether `public_key` is the key a serving machine holds for delegated agent
/// `did` under the agent's approved Terms, and `dpop_jkt` (the key a sign-in
/// binds its token to) is that same key. The agent runtime on that machine
/// signs in as the agent with it; nothing else can, since the key never leaves
/// the machine's TPM.
pub(crate) fn is_serving_key(
    node: &Arc<TenzroNode>,
    did: &str,
    public_key: &[u8],
    dpop_jkt: &str,
) -> bool {
    chain_terms(node, did)
        .is_some_and(|(_, stored)| serving_key_listed(&stored.terms, public_key, dpop_jkt))
}

fn serving_key_listed(terms: &AgentTerms, public_key: &[u8], dpop_jkt: &str) -> bool {
    let xy = match public_key {
        [0x04, xy @ ..] if xy.len() == 64 => xy,
        xy if xy.len() == 64 => xy,
        _ => return false,
    };
    let Ok(jkt) = jkt_of(xy) else {
        return false;
    };
    jkt == dpop_jkt
        && terms
            .serving_nodes
            .iter()
            .any(|n| n.dpop_jkt == jkt && hex::decode(&n.dpop_public_key).is_ok_and(|k| k == xy))
}

/// The server name a delegated agent's terms pin this node's own MCP tools
/// under.
pub const NODE_TOOL_SERVER: &str = "tenzro-node";

/// For a tool call by `did`: when it is a delegated agent whose terms pin
/// tools, the tool must be pinned and still describe itself as it did when
/// the terms were approved.
pub(crate) fn check_agent_tool(
    node: &Arc<TenzroNode>,
    did: &str,
    server: &str,
    name: &str,
    description: &str,
    input_schema: &Value,
) -> Result<(), String> {
    let Some((_, stored)) = chain_terms(node, did) else {
        return Ok(());
    };
    stored
        .terms
        .delegation_scope
        .check_tool(server, name, description, input_schema)
}

/// For a token presented by `bearer_did`: when it is a delegated agent with
/// terms on chain, the token must be bound to a serving node the current
/// terms assign, the terms must not have expired, and the request must carry
/// a typed intent the terms allow.
pub(crate) fn check_agent_token(
    node: &Arc<TenzroNode>,
    bearer_did: &str,
    jkt: Option<&str>,
    intent: Option<&tenzro_auth::AuthorityRequest>,
) -> Result<(), String> {
    let Some((chain, stored)) = chain_terms(node, bearer_did) else {
        return Ok(());
    };
    tenzro_vm::native::check_agent_status(
        &chain,
        bearer_did,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )?;
    if stored.terms.expires_at_ms.is_some_and(|at| now_ms() >= at) {
        return Err("outside the agent's approved terms: expiry".to_string());
    }
    let assigned = jkt.is_some_and(|j| stored.terms.serving_nodes.iter().any(|n| n.dpop_jkt == j));
    if !assigned {
        return Err(
            "outside the agent's approved terms: serving node (the token is not bound to a node \
             the terms assign)"
                .to_string(),
        );
    }
    crate::agent_guardrails::check_bearer_intent(node, bearer_did, intent)
}

/// For a request made with a delegated agent's DPoP-bound access token: the
/// agent must be
/// live and within its terms, and the request must be a typed proposal the
/// terms allow.
pub(crate) fn check_agent_key_request(
    node: &Arc<TenzroNode>,
    subject: &str,
    method: &str,
    params: Option<&Value>,
) -> Result<(), String> {
    let Some((chain, stored)) = chain_terms(node, subject) else {
        return Ok(());
    };
    tenzro_vm::native::check_agent_status(
        &chain,
        subject,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )?;
    if stored.terms.expires_at_ms.is_some_and(|at| now_ms() >= at) {
        return Err("outside the agent's approved terms: expiry".to_string());
    }
    if crate::event_index::EVENT_METHODS.contains(&method) {
        check_event_filter(&stored.terms.delegation_scope, params)?;
        return crate::agent_guardrails::check_operation(
            node,
            subject,
            crate::event_index::SUBSCRIBE_OPERATION,
            None,
        );
    }
    crate::agent_guardrails::check_agent(node, subject)?;
    match crate::agent_guardrails::keyed_proposal(method, params)? {
        crate::agent_guardrails::Proposal::Operation { operation, model } => {
            if model.is_none() && !stored.terms.delegation_scope.allowed_models.is_empty() {
                return Err("outside the agent's approved terms: model".to_string());
            }
            crate::agent_guardrails::check_operation(node, subject, operation, model)
        }
        _ => Ok(()),
    }
}

/// For an event read signed by `did` (over A2A, where the request carries a
/// signed DID envelope rather than an access token): when `did` is a delegated
/// agent with terms on chain, it must be live, unexpired, reading with a
/// filter [`check_event_filter`] accepts, and its terms must allow the
/// subscription operation.
pub(crate) fn check_agent_event_read(
    node: &Arc<TenzroNode>,
    did: &str,
    params: &Value,
) -> Result<(), String> {
    let Some((chain, stored)) = chain_terms(node, did) else {
        return Ok(());
    };
    tenzro_vm::native::check_agent_status(
        &chain,
        did,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )?;
    if stored.terms.expires_at_ms.is_some_and(|at| now_ms() >= at) {
        return Err("outside the agent's approved terms: expiry".to_string());
    }
    check_event_filter(&stored.terms.delegation_scope, Some(params))?;
    crate::agent_guardrails::check_operation(
        node,
        did,
        crate::event_index::SUBSCRIBE_OPERATION,
        None,
    )
}

/// When an agent's terms name counterparties, it reads only the logs of
/// those contracts: its event filter must name addresses, each of them one
/// the terms list. Whether the terms allow reading at all is the operation
/// check every agent action passes.
pub(crate) fn check_event_filter(
    scope: &tenzro_types::agent_terms::TermsScope,
    params: Option<&Value>,
) -> Result<(), String> {
    if scope.allowed_counterparties.is_empty() {
        return Ok(());
    }
    let p = params.map(|p| crate::rpc::unwrap_param_object(Some(p.clone())));
    let addresses: Vec<String> = p
        .as_ref()
        .and_then(|p| p.get("filter"))
        .and_then(|f| f.get("addresses"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim_start_matches("0x").to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let listed = |a: &str| {
        scope.allowed_counterparties.iter().any(|c| {
            let c = c.trim_start_matches("0x").to_ascii_lowercase();
            c == a || c.ends_with(a)
        })
    };
    if addresses.is_empty() || !addresses.iter().all(|a| listed(a)) {
        return Err("outside the agent's approved terms: counterparty (the event filter must name only listed addresses)"
            .to_string());
    }
    Ok(())
}

/// The delegated agent a request acts for: the DID its access token proved.
pub(crate) fn acting_agent(caller: Option<&str>) -> Result<String, JsonRpcError> {
    caller.map(str::to_string).ok_or_else(|| {
        refused("an agent acts with its access token: sign in with tenzro_issueAccessToken")
    })
}

/// `tenzro_agentAct`: one action by a delegated agent, requested with the
/// agent's access token. This node must be one of the agent's serving nodes. It
/// checks the action against the terms in chain state, signs it with its
/// TPM key for the agent only when it is within them, and submits it; the
/// VM checks it again at execution.
pub(crate) async fn handle_agent_act(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let agent_did = acting_agent(caller)?;
    let params = crate::rpc::unwrap_param_object(params);
    let (chain, _) = chain_terms(node, &agent_did)
        .ok_or_else(|| outside(format!("{agent_did} has no approved terms on chain")))?;
    let (_, _, machine_did) = this_machine().map_err(failed)?;
    let action = AgentAction {
        asset: params
            .get("asset")
            .and_then(Value::as_str)
            .map(str::to_string),
        usd_e6: params.get("usd_e6").and_then(Value::as_u64).unwrap_or(0),
        payment: params
            .get("payment")
            .cloned()
            .map(serde_json::from_value::<tenzro_types::agent_terms::AgentPayment>)
            .transpose()
            .map_err(|e| invalid(format!("payment: {e}")))?,
        agent_did: agent_did.clone(),
        machine_did: machine_did.clone(),
        operation: params
            .get("operation")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("operation is required"))?
            .to_string(),
        counterparty: params
            .get("counterparty")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_start_matches("0x")
            .to_string(),
        amount: amount_string(params.get("amount"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        chain: params
            .get("chain")
            .and_then(Value::as_str)
            .unwrap_or("tenzro")
            .to_string(),
        payment_protocol: params
            .get("payment_protocol")
            .and_then(Value::as_str)
            .map(str::to_string),
        model: params
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        calls: match params.get("calls") {
            Some(v) => {
                serde_json::from_value(v.clone()).map_err(|e| invalid(format!("calls: {e}")))?
            }
            None => Vec::new(),
        },
        escrow: params
            .get("escrow")
            .cloned()
            .map(serde_json::from_value::<tenzro_types::agent_terms::AgentEscrow>)
            .transpose()
            .map_err(|e| invalid(format!("escrow: {e}")))?,
        remote_grant: params
            .get("remote_grant")
            .cloned()
            .map(serde_json::from_value::<tenzro_types::remote_grant::RemoteGrantRequest>)
            .transpose()
            .map_err(|e| invalid(format!("remote_grant: {e}")))?,
        ballot: params
            .get("ballot")
            .cloned()
            .map(serde_json::from_value::<tenzro_types::agent_terms::AgentBallot>)
            .transpose()
            .map_err(|e| invalid(format!("ballot: {e}")))?,
        veto_signal: params
            .get("veto_signal")
            .and_then(Value::as_str)
            .map(|p| p.trim_start_matches("0x").to_ascii_lowercase()),
        nonce: tenzro_vm::native::read_agent_act_nonce(&chain, &agent_did),
        // The agent may declare its own arguments tainted; it can never
        // clear a label this node holds.
        tainted: crate::agent_guardrails::is_tainted(&agent_did)
            || params
                .get("tainted")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        step_up: params.get("step_up").map(parse_step_up).transpose()?,
    };
    // A grant counts against the daily spend at the share its budget uses.
    let mut action = action;
    if let Some(grant) = &action.remote_grant
        && let Some(stored) = tenzro_vm::native::read_agent_terms(&chain, &agent_did)
    {
        action.amount =
            tenzro_vm::native::remote_grant::grant_equivalent(&stored, &grant.caip19, grant.budget)
                .map_err(outside)?;
    }
    act_signed(node, &chain, action).await
}

/// Check `action` against its agent's terms in `chain`, sign it with this
/// node's key for the agent, and submit it as an `AgentAct`. The VM checks
/// it again when it executes.
pub(crate) async fn act_signed(
    node: &Arc<TenzroNode>,
    chain: &tenzro_vm::StateAdapter,
    action: AgentAction,
) -> Result<Value, JsonRpcError> {
    let agent_did = action.agent_did.clone();
    let machine_did = action.machine_did.clone();
    if let Err(why) = tenzro_vm::native::check_agent_act(chain, &action, None, now_ms()) {
        tracing::warn!(target: "agent_delegation", agent = %agent_did, reason = %why, "action refused before signing");
        let mut err = outside(why.clone());
        if why.contains(tenzro_types::agent_terms::STEP_UP_REQUIRED) {
            err.data = Some(step_up_challenge(node.chain_id(), &action));
        }
        return Err(err);
    }
    let label = key_label(&agent_did, &machine_did);
    let digest = action.digest();
    let signature = tokio::task::spawn_blocking(move || {
        tenzro_device_key::signer::open_or_create(&label)
            .and_then(|k| k.sign_prehash(&digest))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| failed(e.to_string()))?
    .map_err(|e| failed(format!("agent key: {e}")))?;
    // The ML-DSA-65 signature follows the P-256 one when the agent's wallet
    // requires that leg.
    let mut signature = signature.to_vec();
    if let Some(pq) = agent_pq_leg(chain, &agent_did, &machine_did, digest)
        .await
        .map_err(failed)?
    {
        signature.extend_from_slice(&pq);
    }
    let tx = tenzro_types::TransactionType::AgentAct {
        action: action.clone(),
        signature,
    };
    let r = crate::rpc::submit_as_validator(node, tx, 100_000).await?;
    // A created escrow's id derives from the payer (the agent's wallet)
    // and the action nonce.
    let escrow_id = match &action.escrow {
        Some(tenzro_types::agent_terms::AgentEscrow::Create { .. }) => {
            Some(hex::encode(tenzro_vm::native::derive_escrow_id(
                &tenzro_types::Address::new(tenzro_types::agent_terms::agent_wallet(&agent_did)),
                action.nonce,
            )))
        }
        _ => None,
    };
    // A payment's record is keyed by its reference.
    let pay_ref = action.payment.as_ref().and_then(|p| {
        let payee = tenzro_types::Address::from_hex(&action.counterparty).ok()?;
        let binding = tenzro_types::payment_authorization::PaymentBinding {
            request_digest: p.request_digest,
            quote_digest: p.quote_digest,
            usd_e6: action.usd_e6,
            app_margin: None,
        };
        Some(hex::encode(tenzro_types::payment_authorization::pay_ref(
            node.payment_gateway()?.chain_id(),
            &payee,
            &binding,
            &p.payment_id,
        )))
    });
    Ok(serde_json::json!({
        "agent_did": agent_did,
        "machine_did": machine_did,
        "nonce": action.nonce,
        "escrow_id": escrow_id,
        "pay_ref": pay_ref,
        "tx_hash": r["tx_hash"],
    }))
}

/// `tenzro_signRemoteAction`: this serving node's signature over one action
/// of the agent's account on another chain, after checking the action
/// against the live grant there and the agent's terms. An action above the
/// grant's cosign threshold needs this from two serving nodes of distinct
/// operators; each signs on its own check.
pub(crate) async fn handle_sign_remote_action(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::remote_grant::{RemoteAction, act_digest, target_leaf};
    let agent_did = acting_agent(caller)?;
    let params = crate::rpc::unwrap_param_object(params);
    let caip2 = params
        .get("chain")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("chain is required"))?
        .to_string();
    let nonce = params
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("nonce (the account's next action nonce) is required"))?;
    let action: RemoteAction = serde_json::from_value(
        params
            .get("action")
            .cloned()
            .ok_or_else(|| invalid("action is required"))?,
    )
    .map_err(|e| invalid(format!("action: {e}")))?;
    let (chain, stored) = chain_terms(node, &agent_did)
        .ok_or_else(|| outside(format!("{agent_did} has no approved terms on chain")))?;
    tenzro_vm::native::check_agent_status(
        &chain,
        &agent_did,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )
    .map_err(outside)?;
    let (_, _, machine_did) = this_machine().map_err(failed)?;
    if stored.terms.serving_node(&machine_did).is_none() {
        return Err(outside("this node does not serve the agent"));
    }
    let grant = tenzro_vm::native::remote_grant::read_grant(&chain, &agent_did, &caip2)
        .ok_or_else(|| outside(format!("{agent_did} holds no grant on {caip2}")))?;
    grant.admits(&action, now_ms()).map_err(outside)?;
    if grant.targets_root != [0u8; 32] {
        let issue = tenzro_vm::native::remote_grant::read_grant_issue(
            &chain, &agent_did, &caip2, grant.seq,
        )
        .ok_or_else(|| failed("the grant's issue is not recorded"))?;
        let leaf = target_leaf(&action.target, &action.selector);
        if !issue
            .targets
            .iter()
            .any(|t| target_leaf(&t.target, &t.selector) == leaf)
        {
            return Err(outside("the grant does not allow that target"));
        }
    } else {
        let allowed = &stored.terms.delegation_scope.allowed_counterparties;
        let target = hex::encode(&action.target);
        if !allowed.is_empty()
            && !allowed
                .iter()
                .any(|c| c.trim_start_matches("0x").eq_ignore_ascii_case(&target))
        {
            return Err(outside("outside the agent's approved terms: counterparty"));
        }
    }
    let digest = act_digest(&grant.chain, &grant.account, grant.seq, nonce, &action);
    // TVM's P256_CHKSIGNU verifies over the SHA-256 of the 32-byte digest.
    let signed: [u8; 32] = match tenzro_types::omni_account::Family::of(&caip2) {
        Some(tenzro_types::omni_account::Family::Tvm) => Sha256::digest(digest).into(),
        _ => digest,
    };
    let label = key_label(&agent_did, &machine_did);
    let raw = tokio::task::spawn_blocking(move || {
        tenzro_device_key::signer::open_or_create(&label)
            .and_then(|k| k.sign_prehash(&signed))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| failed(e.to_string()))?
    .map_err(failed)?;
    // Accounts accept only the low-S form of a signature.
    let signature = p256::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| failed(format!("the node key produced a malformed signature: {e}")))?
        .normalize_s();
    let node_entry = stored.terms.serving_node(&machine_did).expect("checked");
    Ok(serde_json::json!({
        "agent_did": agent_did,
        "chain": caip2,
        "seq": grant.seq,
        "nonce": nonce,
        "digest": hex::encode(digest),
        "signature": hex::encode(signature.to_bytes()),
        "public_key": format!("04{}", node_entry.dpop_public_key),
        "operator_did": node_entry.operator_did,
        "machine_did": machine_did,
        "needs_cosign": action.amount > grant.cosign_above,
    }))
}

/// `tenzro_signRemoteChannelVoucher`: as the calling agent, this serving
/// node signs a voucher paying `cumulative` on channel `channel_id` of the
/// agent's account on `chain`. The account pays it only up to the channel's
/// deposit, which counted against the grant when the channel opened, and
/// only while the grant is not void; the node signs only while the agent is
/// live and it is assigned in the agent's terms.
///
/// With `scheme: "hash"` the voucher is signed with the channel's next
/// one-time hash-based key instead (see [`crate::hash_vouchers`]), for a
/// channel contract that verifies those; with `keys_only: true` as well,
/// nothing is signed and the answer is the keys the channel commits to when
/// it opens.
pub(crate) async fn handle_sign_remote_channel_voucher(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    use tenzro_types::remote_grant::channel_voucher_digest;
    let agent_did = acting_agent(caller)?;
    let params = crate::rpc::unwrap_param_object(params);
    let caip2 = params
        .get("chain")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("chain is required"))?
        .to_string();
    let channel_id = params
        .get("channel_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("channel_id is required"))?;
    let hash_scheme = match params.get("scheme").and_then(Value::as_str) {
        None | Some("p256") => false,
        Some("hash") => true,
        Some(other) => return Err(invalid(format!("unknown voucher scheme {other}"))),
    };
    let keys_only = hash_scheme && params.get("keys_only").and_then(Value::as_bool) == Some(true);
    let cumulative: u128 = if keys_only {
        0
    } else {
        params
            .get("cumulative_amount")
            .and_then(Value::as_str)
            .and_then(|s| s.parse().ok())
            .filter(|c| *c > 0)
            .ok_or_else(|| invalid("cumulative_amount must be a positive decimal u128 string"))?
    };
    let (chain, stored) = chain_terms(node, &agent_did)
        .ok_or_else(|| outside(format!("{agent_did} has no approved terms on chain")))?;
    tenzro_vm::native::check_agent_status(
        &chain,
        &agent_did,
        chrono::Utc::now().timestamp_millis().max(0) as u64,
    )
    .map_err(outside)?;
    let (_, _, machine_did) = this_machine().map_err(failed)?;
    let node_entry = stored
        .terms
        .serving_node(&machine_did)
        .ok_or_else(|| outside("this node does not serve the agent"))?
        .clone();
    let grant = tenzro_vm::native::remote_grant::read_grant(&chain, &agent_did, &caip2)
        .ok_or_else(|| outside(format!("{agent_did} holds no grant on {caip2}")))?;
    if grant.void {
        return Err(outside(format!("{agent_did}'s grant on {caip2} is void")));
    }
    let digest = channel_voucher_digest(&grant.chain, &grant.account, channel_id, cumulative);
    if hash_scheme {
        let label = crate::hash_vouchers::label(&agent_did, &machine_did, &caip2, channel_id);
        let data_dir = node.config().data_dir.clone();
        let (keys, signature) = tokio::task::spawn_blocking(move || {
            let root =
                tenzro_device_key::DerivationRoot::open_or_create().map_err(|e| e.to_string())?;
            let tree = crate::hash_vouchers::tree(&root, &label)?;
            if keys_only {
                return Ok::<_, String>((tree.keys(), None));
            }
            crate::hash_vouchers::sign(&tree, &data_dir, &label, &digest)
                .map(|(keys, sig)| (keys, Some(sig)))
        })
        .await
        .map_err(|e| failed(e.to_string()))?
        .map_err(failed)?;
        let mut answer = serde_json::json!({
            "agent_did": agent_did,
            "chain": caip2,
            "channel_id": channel_id,
            "voucher_keys": crate::hash_vouchers::keys_json(&keys),
            "operator_did": node_entry.operator_did,
            "machine_did": machine_did,
        });
        if let Some(sig) = signature {
            answer["cumulative_amount"] = Value::String(cumulative.to_string());
            answer["digest"] = Value::String(hex::encode(digest));
            answer["leaf"] = Value::from(sig.leaf);
            answer["signature"] = Value::String(hex::encode(sig.to_bytes()));
        }
        return Ok(answer);
    }
    let label = key_label(&agent_did, &machine_did);
    let raw = tokio::task::spawn_blocking(move || {
        tenzro_device_key::signer::open_or_create(&label)
            .and_then(|k| k.sign_prehash(&digest))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| failed(e.to_string()))?
    .map_err(failed)?;
    let signature = p256::ecdsa::Signature::from_slice(&raw)
        .map_err(|e| failed(format!("the node key produced a malformed signature: {e}")))?
        .normalize_s();
    Ok(serde_json::json!({
        "agent_did": agent_did,
        "chain": caip2,
        "channel_id": channel_id,
        "cumulative_amount": cumulative.to_string(),
        "digest": hex::encode(digest),
        "signature": hex::encode(signature.to_bytes()),
        "public_key": format!("04{}", node_entry.dpop_public_key),
        "operator_did": node_entry.operator_did,
        "machine_did": machine_did,
    }))
}

/// The root's step-up approval of one action, as `tenzro_agentAct` takes
/// it: `account`, `nonce` and `root_public_key` hex, and the composite
/// `signature` (a passkey assertion in WebAuthn form for a human root, the
/// TPM or Secure Enclave signature in raw form for a machine root).
fn parse_step_up(v: &Value) -> Result<tenzro_types::agent_terms::AgentTermsApproval, JsonRpcError> {
    let field = |name: &str| -> Result<Vec<u8>, JsonRpcError> {
        decode_hex(
            v.get(name)
                .and_then(Value::as_str)
                .ok_or_else(|| invalid(format!("step_up.{name} is required")))?,
        )
    };
    let nonce: [u8; 16] = field("nonce")?
        .try_into()
        .map_err(|_| invalid("step_up.nonce is 16 bytes"))?;
    let signature = serde_json::from_value(
        v.get("signature")
            .cloned()
            .ok_or_else(|| invalid("step_up.signature is required"))?,
    )
    .map_err(|e| invalid(format!("step_up.signature: {e}")))?;
    Ok(tenzro_types::agent_terms::AgentTermsApproval {
        account: field("account")?,
        nonce,
        root_public_key: field("root_public_key")?,
        signature,
    })
}

/// What the root signs to approve `action` when its terms hold it for
/// step-up: the custody challenge for `agent_step_up` over the action's
/// digest. A passkey signs `webauthn_challenge`; a TPM or Secure Enclave
/// signs `challenge_hex` under the account-owner context. The agent sends the
/// action again, unchanged, with the approval as `step_up`. The data carries
/// the whole held action as `action` (every field its digest covers: the
/// serving machine, the taint flag, the amount, the counterparty, the calls),
/// so a wallet can show what it approves and recompute `target` from it
/// without the agent passing the action separately. The challenge is bound
/// to the network `chain_id`.
fn step_up_challenge(chain_id: u64, action: &AgentAction) -> Value {
    let account = tenzro_types::agent_terms::agent_wallet(&action.agent_did);
    let nonce: [u8; 16] = rand::random();
    let target = action.digest();
    let challenge = tenzro_types::agent_terms::custody_challenge_digest(
        chain_id,
        &account,
        tenzro_types::agent_terms::OP_AGENT_STEP_UP,
        &target,
        &nonce,
    );
    serde_json::json!({
        "step_up": {
            "controller_operation": "agent_step_up",
            "account": hex::encode(account),
            "nonce": hex::encode(nonce),
            "target": hex::encode(target),
            "chain_id": chain_id,
            "challenge_hex": hex::encode(challenge),
            "webauthn_challenge": crate::passkey_rpc::custody_webauthn_challenge(&challenge),
            "action_nonce": action.nonce,
            "action": AgentAction { step_up: None, ..action.clone() },
        }
    })
}

// ---------------------------------------------------------------------------
// Discovery.
// ---------------------------------------------------------------------------

/// Whether `machine_did` was judged available in the last closed epoch.
fn live(chain: Option<&tenzro_vm::StateAdapter>, machine_did: &str) -> bool {
    let Some(chain) = chain else {
        return false;
    };
    let epoch = (now_ms() as i64 / tenzro_vm::native::MARKET_EPOCH_MS).saturating_sub(1) as u64;
    tenzro_vm::native::read_sla_verdict(chain, machine_did, epoch).is_some_and(|v| v.available)
}

/// Discovery entries for nodes that serve delegated agents: this node when
/// it serves them, and every announced node that does. Identities only; no
/// addresses.
pub(crate) fn serving_provider_entries(node: &Arc<TenzroNode>) -> Vec<Value> {
    let chain = crate::rpc::chain_state_of(node);
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    if node.config().serves_agents()
        && let (Some(machine_did), Some(operator_did)) = (
            crate::identity_bootstrap::machine_did(),
            node.operator_did(),
        )
    {
        seen.insert(machine_did.clone());
        out.push(serde_json::json!({
            "machine_did": machine_did,
            "operator_did": operator_did,
            "capabilities": [AGENT_SERVING_CAPABILITY],
            "live": live(chain.as_ref(), &machine_did),
        }));
    }
    for entry in node.network_providers_snapshot() {
        let a = &entry.announcement;
        if !a.capabilities.iter().any(|c| c == AGENT_SERVING_CAPABILITY) {
            continue;
        }
        let (machine_did, Some(operator_did)) = (&a.machine_did, &a.operator_did) else {
            continue;
        };
        if !seen.insert(machine_did.clone()) {
            continue;
        }
        out.push(serde_json::json!({
            "machine_did": machine_did,
            "operator_did": operator_did,
            "capabilities": a.capabilities,
            "live": live(chain.as_ref(), machine_did),
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key a node derives for an agent proves itself the way the chain
    /// checks it, and the node's signatures for the agent verify under it,
    /// as the VM verifies an action's or voucher's ML-DSA leg.
    #[test]
    fn a_nodes_ml_dsa_key_for_an_agent_proves_itself_and_signs_its_actions() {
        use tenzro_types::account_signature::{
            AGENT_NODE_PQ_CONTEXT, AGENT_NODE_PQ_POSSESSION_CONTEXT,
            agent_node_pq_possession_message,
        };
        let root = tenzro_device_key::DerivationRoot::for_tests([3; 32]);
        let agent = "did:tenzro:agent:buyer";
        let machine = "did:tenzro:machine:serving";
        let key = agent_node_pq_key_from(&root, agent, machine).unwrap();
        assert_eq!(key.machine_did, machine);
        tenzro_crypto::pq::ml_dsa_verify(
            &key.ml_dsa_public_key,
            AGENT_NODE_PQ_POSSESSION_CONTEXT,
            &agent_node_pq_possession_message(agent, machine, &key.ml_dsa_public_key),
            &key.possession,
        )
        .unwrap();
        let digest = [0x42; 32];
        let sig = agent_node_pq_sign(&root, agent, machine, &digest).unwrap();
        tenzro_crypto::pq::ml_dsa_verify(
            &key.ml_dsa_public_key,
            AGENT_NODE_PQ_CONTEXT,
            &digest,
            &sig,
        )
        .unwrap();
        // Another agent gets another key.
        let other = agent_node_pq_key_from(&root, "did:tenzro:agent:seller", machine).unwrap();
        assert_ne!(other.ml_dsa_public_key, key.ml_dsa_public_key);
    }

    fn terms() -> AgentTerms {
        AgentTerms {
            controller_did: "did:tenzro:human:abc".into(),
            agent_name: "buyer-1".into(),
            delegation_scope: TermsScope {
                max_transaction_value: Some("1000".into()),
                allowed_operations: vec!["transfer".into()],
                allowed_chains: vec!["tenzro".into()],
                ..Default::default()
            },
            capabilities: vec!["inference".into()],
            serving_nodes: vec![ServingNode {
                machine_did: "did:tenzro:machine:m1".into(),
                operator_did: "did:tenzro:human:op".into(),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        }
    }

    #[test]
    fn only_the_serving_key_the_terms_name_signs_in_as_the_agent() {
        let key = |b: u8| -> Vec<u8> {
            let k = tenzro_crypto::p256::P256KeyPair::from_secret_bytes(&[b; 32]).unwrap();
            k.public_key_bytes().to_vec()
        };
        let (served, other) = (key(7), key(9));
        let mut t = terms();
        t.serving_nodes[0].dpop_public_key = hex::encode(&served);
        t.serving_nodes[0].dpop_jkt = jkt_of(&served).unwrap();
        let jkt = jkt_of(&served).unwrap();
        assert!(serving_key_listed(&t, &served, &jkt));
        let sec1 = [&[0x04u8][..], &served].concat();
        assert!(
            serving_key_listed(&t, &sec1, &jkt),
            "the SEC1 form of the same key"
        );
        // Another key, or the right key with a token bound to another key, is refused.
        assert!(!serving_key_listed(&t, &other, &jkt_of(&other).unwrap()));
        assert!(!serving_key_listed(&t, &served, &jkt_of(&other).unwrap()));
        // A Terms entry whose thumbprint does not match its key names no key.
        t.serving_nodes[0].dpop_jkt = jkt_of(&other).unwrap();
        assert!(!serving_key_listed(&t, &served, &jkt));
        assert!(
            !serving_key_listed(&terms(), &served, &jkt),
            "no key in the Terms"
        );
    }

    #[test]
    fn any_change_to_the_terms_changes_the_target() {
        let base = terms();
        let t = base.target(None);
        let mut raised = base.clone();
        raised.delegation_scope.max_transaction_value = Some("1001".into());
        assert_ne!(t, raised.target(None));
        let mut models = base.clone();
        models.delegation_scope.allowed_models = vec!["m".into()];
        assert_ne!(t, models.target(None));
        assert_ne!(base.target(Some(false)), base.target(Some(true)));
        assert_ne!(t, base.target(Some(false)));
    }

    #[test]
    fn non_canonical_amounts_are_refused() {
        let mut t = terms();
        t.delegation_scope.max_transaction_value = Some("01000".into());
        assert!(t.check_shape().is_err());
    }

    #[test]
    fn too_few_operators_are_refused() {
        let mut t = terms();
        t.min_distinct_operators = 2;
        assert!(t.check_shape().is_err());
    }

    /// A serving node whose whole certification was made in software: an
    /// "attestation key" claiming every TPM attribute certifies the agent
    /// key, and a software machine key vouches for it.
    fn software_certified_node(agent_did: &str) -> ServingNode {
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use tenzro_device_key::tpm_wire::*;
        let point = |k: &SigningKey| -> Vec<u8> {
            k.verifying_key().to_sec1_point(false).as_bytes()[1..].to_vec()
        };
        let public = |attributes: u32, k: &SigningKey| -> Vec<u8> {
            let p = point(k);
            let mut w = Writer::new();
            w.u16(TPM2_ALG_ECC)
                .u16(TPM2_ALG_SHA256)
                .u32(attributes)
                .tpm2b(&[]);
            w.u16(TPM2_ALG_NULL)
                .u16(TPM2_ALG_ECDSA)
                .u16(TPM2_ALG_SHA256);
            w.u16(TPM2_ECC_NIST_P256).u16(TPM2_ALG_NULL);
            w.tpm2b(&p[..32]).tpm2b(&p[32..]);
            w.finish()
        };
        let ak = SigningKey::from_slice(&[11u8; 32]).unwrap();
        let agent_key = SigningKey::from_slice(&[12u8; 32]).unwrap();
        let machine = SigningKey::from_slice(&[13u8; 32]).unwrap();
        let machine_sec1 = machine
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let machine_did = tenzro_types::did_derivation::machine_did(&machine_sec1);
        let operator_did = "did:tenzro:human:op".to_string();
        let key = point(&agent_key);

        let ak_public = public(ATTESTATION_KEY_ATTRIBUTES, &ak);
        let key_public = public(
            TPMA_OBJECT_FIXEDTPM
                | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN
                | TPMA_OBJECT_USERWITHAUTH
                | TPMA_OBJECT_SIGN_ENCRYPT,
            &agent_key,
        );
        let ak_name = parse_public(&ak_public).unwrap().name().unwrap();
        let key_name = parse_public(&key_public).unwrap().name().unwrap();
        let msg = cert_message(agent_did, &machine_did, &operator_did, &key);
        let extra: [u8; 32] = Sha256::digest(&msg).into();
        let mut a = Writer::new();
        a.u32(TPM2_GENERATED_VALUE).u16(TPM2_ST_ATTEST_CERTIFY);
        a.tpm2b(&endorsement_primary_qualified_name(&ak_name))
            .tpm2b(&extra);
        a.bytes(&1u64.to_be_bytes())
            .u32(0)
            .u32(0)
            .u8(1)
            .bytes(&1u64.to_be_bytes());
        a.tpm2b(&key_name).tpm2b(&key_name);
        let attest = a.finish();
        let digest: [u8; 32] = Sha256::digest(&attest).into();
        let sig: p256::ecdsa::Signature = ak.sign_prehash(&digest).unwrap();
        let tpm = tenzro_device_key::key_certification::KeyCertification {
            ak_public,
            key_public,
            attest,
            signature: sig.to_bytes().to_vec(),
        };
        let mut binding = msg;
        binding.extend_from_slice(&ak_name);
        let machine_sig: p256::ecdsa::Signature = machine.sign(&binding);
        let mut cert = tpm.to_bytes();
        for part in [machine_sec1.as_slice(), machine_sig.to_bytes().as_slice()] {
            cert.extend_from_slice(&(part.len() as u32).to_be_bytes());
            cert.extend_from_slice(part);
        }
        ServingNode {
            machine_did,
            operator_did,
            dpop_public_key: hex::encode(&key),
            dpop_jkt: jkt_of(&key).unwrap(),
            key_certification: hex::encode(cert),
            ..Default::default()
        }
    }

    #[test]
    fn a_certification_by_an_unadmitted_attestation_key_is_refused() {
        let agent = "did:tenzro:agent:x";
        let n = software_certified_node(agent);
        let state = tenzro_vm::StateAdapter::new();
        let err = verify_certification(&state, agent, &n).unwrap_err();
        assert!(err.contains("not an admitted machine"), "{err}");
    }

    /// Records machine root `did` (controller `key`) in `state`, with `tpm`'s
    /// attestation when given, and the test manufacturer root.
    fn admit_root(
        state: &mut tenzro_vm::StateAdapter,
        did: &str,
        key: &[u8],
        tpm: Option<&tenzro_tee::tpm_attest::tests::SoftTpm>,
    ) {
        use tenzro_tee::tpm_attest::tests::{evidence, pem};
        use tenzro_vm::traits::VmState;
        let sys = tenzro_vm::native::SYSTEM_ADDRESS;
        let mut metadata = std::collections::BTreeMap::new();
        if let Some(tpm) = tpm {
            let nonce = [7u8; 32];
            let challenge = tenzro_tee::tpm_attest::admission_challenge(did, key, &nonce);
            let (ev, root) = evidence(tpm, &challenge);
            let att = tenzro_tee::tpm_attest::MachineAttestation {
                evidence: ev,
                nonce: nonce.to_vec(),
                activated: true,
            };
            metadata.insert(
                tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
                serde_json::to_string(&att).unwrap(),
            );
            state.set_storage(
                &sys,
                tenzro_vm::native::funding::ENDORSEMENT_ROOTS_KEY.as_bytes(),
                serde_json::to_vec(&vec![pem(&root)]).unwrap(),
            );
        }
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: "machine".into(),
            display_name: "machine root".into(),
            controller_pubkey: key.to_vec(),
            key_type: "P-256".into(),
            wallet_id: String::new(),
            wallet_address: tenzro_types::primitives::Address::new([9u8; 32]),
            pq_verifying_key: Vec::new(),
            metadata,
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &sys,
            format!("identity:{did}").as_bytes(),
            serde_json::to_vec(&record).unwrap(),
        );
    }

    fn machine_key() -> Vec<u8> {
        p256::ecdsa::SigningKey::from_slice(&[13u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec()
    }

    /// A validator that also serves agents: its TPM is admitted once, under
    /// its machine DID, and the key that TPM certifies is accepted.
    #[test]
    fn a_tpm_admitted_under_the_machine_root_certifies_its_serving_key() {
        let agent = "did:tenzro:agent:x";
        let n = software_certified_node(agent);
        let mut state = tenzro_vm::StateAdapter::new();
        // The certification's attestation key is [11; 32], SoftTpm::new(10)'s.
        let tpm = tenzro_tee::tpm_attest::tests::SoftTpm::new(10);
        admit_root(&mut state, &n.machine_did, &machine_key(), Some(&tpm));
        verify_certification(&state, agent, &n).unwrap();
    }

    /// A machine root registered without its TPM's attestation attaches it
    /// with an `AttachMachineAttestation` transaction; from then on the key
    /// that TPM certifies is accepted under the machine DID.
    #[test]
    fn after_attaching_its_attestation_a_root_certifies_its_serving_key() {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        use tenzro_crypto::composite::{SignatureContext, signing_digest};
        use tenzro_vm::traits::VmState;
        let agent = "did:tenzro:agent:x";
        let n = software_certified_node(agent);
        let mut state = tenzro_vm::StateAdapter::new();
        admit_root(&mut state, &n.machine_did, &machine_key(), None);
        verify_certification(&state, agent, &n).unwrap_err();

        // The certification's attestation key is SoftTpm::new(10)'s.
        let tpm = tenzro_tee::tpm_attest::tests::SoftTpm::new(10);
        let (_, root) = tenzro_tee::tpm_attest::tests::evidence(&tpm, &[0; 32]);
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::funding::ENDORSEMENT_ROOTS_KEY.as_bytes(),
            serde_json::to_vec(&vec![tenzro_tee::tpm_attest::tests::pem(&root)]).unwrap(),
        );
        let wallet = [9u8; 32];
        let nonce = tenzro_types::identity::attach_attestation_nonce(
            &n.machine_did,
            &wallet,
            state.get_nonce(&wallet),
        );
        let challenge =
            tenzro_tee::tpm_attest::admission_challenge(&n.machine_did, &machine_key(), &nonce);
        let (ev, _) = tenzro_tee::tpm_attest::tests::evidence(&tpm, &challenge);
        let att = tenzro_tee::tpm_attest::MachineAttestation {
            evidence: ev,
            nonce: nonce.to_vec(),
            activated: true,
        };
        let attestation = serde_json::to_string(&att).unwrap();
        let statement =
            tenzro_types::identity::attach_attestation_statement(&n.machine_did, &attestation);
        let identity_key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        let sig: p256::ecdsa::Signature = identity_key
            .sign_prehash(&signing_digest(
                SignatureContext::IdentityRegistration,
                &statement,
            ))
            .unwrap();
        let op = tenzro_types::identity::AttachMachineAttestationOp {
            did: n.machine_did.clone(),
            attestation,
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: sig.to_bytes().to_vec(),
                },
            ),
        };
        tenzro_vm::native::machine_attestation::attach(
            &mut state,
            &wallet,
            &serde_json::to_vec(&op).unwrap(),
        )
        .unwrap();
        verify_certification(&state, agent, &n).unwrap();
    }

    /// A machine root registered without its TPM's attestation admits no TPM.
    #[test]
    fn a_machine_root_without_tpm_attestation_certifies_nothing() {
        let agent = "did:tenzro:agent:x";
        let n = software_certified_node(agent);
        let mut state = tenzro_vm::StateAdapter::new();
        admit_root(&mut state, &n.machine_did, &machine_key(), None);
        let err = verify_certification(&state, agent, &n).unwrap_err();
        assert!(err.contains("not an admitted machine"), "{err}");
    }

    /// A root that attested another TPM does not admit this certification's.
    #[test]
    fn a_tpm_the_root_did_not_attest_is_refused() {
        let agent = "did:tenzro:agent:x";
        let n = software_certified_node(agent);
        let mut state = tenzro_vm::StateAdapter::new();
        let other = tenzro_tee::tpm_attest::tests::SoftTpm::new(40);
        admit_root(&mut state, &n.machine_did, &machine_key(), Some(&other));
        let err = verify_certification(&state, agent, &n).unwrap_err();
        assert!(err.contains("not an admitted machine"), "{err}");
    }

    #[test]
    fn an_uncertified_serving_node_is_refused() {
        let t = terms();
        let state = tenzro_vm::StateAdapter::new();
        assert!(
            t.check_completed(&state, "did:tenzro:machine:abc:x")
                .is_err()
        );
    }

    /// A refused action's step-up data carries the whole held action, so a
    /// wallet can show it and recompute the digest it approves.
    #[test]
    fn the_step_up_data_carries_the_held_action() {
        let action = AgentAction {
            asset: None,
            usd_e6: 7,
            payment: None,
            agent_did: "did:tenzro:agent:x".into(),
            machine_did: "did:tenzro:machine:serving".into(),
            operation: "pay".into(),
            counterparty: "0xabc".into(),
            amount: 1_000,
            chain: "tenzro".into(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: 3,
            tainted: true,
            step_up: None,
            escrow: None,
        };
        let data = step_up_challenge(13380, &action);
        let held: AgentAction =
            serde_json::from_value(data["step_up"]["action"].clone()).expect("the held action");
        assert_eq!(held, action);
        assert_eq!(
            data["step_up"]["action"]["machine_did"],
            "did:tenzro:machine:serving"
        );
        assert_eq!(data["step_up"]["action"]["tainted"], true);
        assert_eq!(data["step_up"]["target"], hex::encode(held.digest()));
        let nonce: [u8; 16] = hex::decode(data["step_up"]["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            data["step_up"]["challenge_hex"],
            hex::encode(tenzro_types::agent_terms::custody_challenge_digest(
                13380,
                &tenzro_types::agent_terms::agent_wallet(&action.agent_did),
                tenzro_types::agent_terms::OP_AGENT_STEP_UP,
                &held.digest(),
                &nonce,
            ))
        );
    }

    #[test]
    fn an_out_of_scope_event_subscription_is_refused() {
        let mut t = terms();
        let read = |t: &AgentTerms| {
            let action = AgentAction {
                asset: None,
                usd_e6: 0,
                payment: None,
                agent_did: "did:tenzro:agent:x".into(),
                machine_did: String::new(),
                operation: crate::event_index::SUBSCRIBE_OPERATION.into(),
                counterparty: String::new(),
                amount: 0,
                chain: String::new(),
                payment_protocol: None,
                model: None,
                calls: Vec::new(),
                remote_grant: None,
                ballot: None,
                veto_signal: None,
                nonce: 0,
                tainted: false,
                step_up: None,
                escrow: None,
            };
            tenzro_types::agent_terms::check_scope(t, &action, 10)
        };
        assert_eq!(
            read(&t),
            Err("operation"),
            "terms that do not allow reading events"
        );
        t.delegation_scope
            .allowed_operations
            .push("subscribe_events".into());
        assert_eq!(read(&t), Ok(()));

        let filter = |addrs: &[&str]| serde_json::json!({ "filter": { "addresses": addrs } });
        let mut scope = t.delegation_scope;
        check_event_filter(&scope, Some(&filter(&[]))).unwrap();
        let listed = "0x".to_string() + &"ab".repeat(20);
        let other = "0x".to_string() + &"cd".repeat(20);
        scope.allowed_counterparties = vec![listed.clone()];
        assert!(
            check_event_filter(&scope, Some(&filter(&[]))).is_err(),
            "an unrestricted filter"
        );
        assert!(
            check_event_filter(&scope, Some(&filter(&[&other]))).is_err(),
            "an unlisted address"
        );
        assert!(
            check_event_filter(&scope, Some(&filter(&[&listed, &other]))).is_err(),
            "one unlisted address"
        );
        check_event_filter(&scope, Some(&filter(&[&listed]))).unwrap();
    }
}
