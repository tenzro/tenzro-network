//! OpenShell sandboxes on Tenzro: the Terms a sandbox's agent is delegated
//! under, the provider credential the gateway attaches, and the signed
//! records of what the Tenzro extensions decided, verified offline.
//!
//! Terms are held by Tenzro and approved by the controller's passkey. The
//! policy's `tenzro` network middleware takes no config: it only routes the
//! sandbox's traffic through the extensions, which read the agent's Terms
//! from Tenzro on every decision.
//!
//! Every decision is a tenzro-types agent audit entry, signed by a session
//! key that the serving node's hardware identity certified. An entry is
//! `{"body": <hex of the entry JSON>, "signature": <hex of the
//! SessionSignature JSON>}`; entries of one session are numbered from 0,
//! each chained to the leaf hash of the one before, and the session's root
//! is the MMR root of their leaf hashes. A session is named by
//! SHA-256("tenzro/openshell/session/v1" || 0x00 || gateway || 0x00 || name),
//! the name being a sandbox, or the agent's DID for its model calls.

use std::collections::HashSet;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::auth::{AuthClient, DelegatedAgent};
use crate::error::{SdkError, SdkResult};
use crate::passkey_client::CustodyChallengeResponse;
use crate::wallet::{COMPOSITE_LABEL_MLDSA65_P256, composite_message_representative};

const SESSION_DOMAIN: &[u8] = b"tenzro/openshell/session/v1\0";
const CERTIFICATE_CONTEXT: &[u8] = b"tenzro/session/certificate";
const HYBRID_SESSION_CONTEXT: &[u8] = b"tenzro/session/ml-dsa-65";
const ML_DSA_65_VK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;

/// The middleware name the Tenzro supervisor middleware registers under.
pub const OPENSHELL_TENZRO_MIDDLEWARE: &str = "tenzro";

/// The payment rails a sandbox may use, as Terms name them.
pub const OPENSHELL_PAYMENT_PROTOCOLS: [&str; 3] = ["x402", "mpp", "ap2"];

/// The sandbox annotation that names the agent a sandbox runs.
pub const OPENSHELL_AGENT_ANNOTATION: &str = "tenzro.agent";

/// The response header that carries the signed record of a model call.
pub const OPENSHELL_RECEIPT_HEADER: &str = "x-tenzro-receipt";

fn refuse<T>(msg: impl Into<String>) -> SdkResult<T> {
    Err(SdkError::InvalidParameter(msg.into()))
}

/// Who the Terms are for and where the agent is served.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenShellTermsOptions {
    /// The controller whose passkey approves the Terms.
    pub controller_did: String,
    /// The agent's name.
    pub agent_name: String,
    /// The serving nodes, `[{machine_did, operator_did}]`.
    pub serving_nodes: Vec<Value>,
    /// Capabilities the agent declares.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Distinct operators the serving nodes must span.
    #[serde(default)]
    pub min_distinct_operators: Option<u32>,
    /// Clock for the expiry, ms; now when omitted.
    #[serde(default)]
    pub now_ms: Option<u64>,
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn canonical_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'))
}

fn decimal_le(a: &str, b: &str) -> bool {
    (a.len(), a) <= (b.len(), b)
}

/// The Terms to ask Tenzro for, from an explicit `grant`, checked against
/// the sandbox `policy` (both as data): the policy routes through exactly one
/// `tenzro` middleware, which carries no config and does not fail open, and
/// every payment service is an endpoint of its network policy. Refuses open
/// limits or payees, rails Terms do not know and wildcard models. Every
/// sandbox may be created and reach its endpoints; policy changes
/// (`policy_changes`), tool calls (`tools`), inference (`models`) and
/// payments (`payments`) are granted only when asked for.
pub fn openshell_terms(
    policy: &Value,
    grant: &Value,
    options: &OpenShellTermsOptions,
) -> SdkResult<Value> {
    let mws: Vec<&Value> = policy["network_middlewares"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
        .filter(|m| m["middleware"].as_str() == Some(OPENSHELL_TENZRO_MIDDLEWARE))
        .collect();
    let mw = match mws.as_slice() {
        [] => return refuse("the policy has no tenzro middleware"),
        [mw] => *mw,
        _ => return refuse("the policy names the tenzro middleware twice"),
    };
    if mw.get("config").is_some() {
        return refuse("the tenzro middleware takes no config: Terms stay on Tenzro");
    }
    if mw
        .get("on_error")
        .is_some_and(|e| e.as_str() != Some("fail_closed"))
    {
        return refuse("the tenzro middleware must fail closed");
    }
    let models = strings(&grant["models"]);
    if models.iter().any(|m| m.is_empty() || m.contains('*')) {
        return refuse("models must be named");
    }
    let pay = &grant["payments"];
    let protocols: Vec<String> = strings(&pay["protocols"])
        .into_iter()
        .map(|p| p.to_lowercase())
        .collect();
    for p in &protocols {
        if !OPENSHELL_PAYMENT_PROTOCOLS.contains(&p.as_str()) {
            return refuse(format!(
                "payment protocol {p} is not one of {}",
                OPENSHELL_PAYMENT_PROTOCOLS.join(", ")
            ));
        }
    }
    let mut payees = Vec::new();
    if !protocols.is_empty() && pay["any_payee"] != Value::Bool(true) {
        payees = strings(&pay["payees"]);
        if payees.is_empty() {
            return refuse("name the payees or set any_payee");
        }
        for a in &payees {
            let ok = a.len() == 42
                && a.starts_with("0x")
                && a[2..].bytes().all(|b| b.is_ascii_hexdigit());
            if !ok {
                return refuse(format!("payee {a} is not a 20-byte hex address"));
            }
        }
        payees = payees.iter().map(|a| a.to_lowercase()).collect();
    }
    let services = strings(&pay["services"]);
    if !services.is_empty() && protocols.is_empty() {
        return refuse("payment services need a payment rail");
    }
    let mut hosts = HashSet::new();
    if let Some(nps) = policy["network_policies"].as_object() {
        for np in nps.values() {
            for ep in np["endpoints"].as_array().into_iter().flatten() {
                if let Some(h) = ep["host"].as_str() {
                    hosts.insert(h.to_lowercase());
                }
            }
        }
    }
    for s in &services {
        if !hosts.contains(&s.to_lowercase()) {
            return refuse(format!(
                "payment service {s} is not an endpoint of the network policy"
            ));
        }
    }
    let mut limits = Vec::new();
    for k in ["max_transaction_value", "max_daily_spend"] {
        match grant[k].as_str() {
            Some(v) if canonical_decimal(v) => limits.push(v.to_string()),
            _ => return refuse(format!("{k} is not a canonical decimal")),
        }
    }
    if !decimal_le(&limits[0], &limits[1]) {
        return refuse("max_transaction_value is above max_daily_spend");
    }
    let secs = match grant["expires_in_secs"].as_u64() {
        Some(s) if s > 0 => s,
        _ => return refuse("expires_in_secs must be a positive whole number"),
    };
    let mut operations = vec!["sandbox", "fetch"];
    if grant["policy_changes"] == Value::Bool(true) {
        operations.push("sandbox.policy");
    }
    if grant["tools"] == Value::Bool(true) {
        operations.push("tool");
    }
    if !models.is_empty() {
        operations.push("inference");
    }
    if !protocols.is_empty() {
        operations.push("pay");
    }
    let chains = match grant["chains"].as_array() {
        Some(_) => strings(&grant["chains"]),
        None => vec!["tenzro".to_string()],
    };
    let now_ms = options.now_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    });
    let mut terms = json!({
        "controller_did": options.controller_did,
        "agent_name": options.agent_name,
        "delegation_scope": {
            "max_transaction_value": limits[0],
            "max_daily_spend": limits[1],
            "allowed_operations": operations,
            "allowed_payment_protocols": protocols,
            "allowed_chains": chains,
            "allowed_models": models,
            "allowed_counterparties": payees,
        },
        "capabilities": options.capabilities,
        "serving_nodes": options.serving_nodes,
        "expires_at_ms": now_ms + secs * 1000,
    });
    if let Some(m) = options.min_distinct_operators {
        terms["min_distinct_operators"] = json!(m);
    }
    Ok(terms)
}

/// The session id of `name` (a sandbox, or an agent DID) on `gateway`, hex.
pub fn openshell_session_id(gateway: &str, name: &str) -> String {
    let mut h = Sha256::new();
    h.update(SESSION_DOMAIN);
    h.update(gateway.as_bytes());
    h.update([0u8]);
    h.update(name.as_bytes());
    hex::encode(h.finalize())
}

/// The provider record and annotation a sandbox for the agent is created
/// with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenShellCredential {
    /// The delegated agent.
    pub agent_did: String,
    /// The provider record: its one credential, `TENZRO_AGENT_TOKEN`, is the
    /// agent's DID. The Tenzro credential driver mints a short-lived token
    /// from it on every resolve; neither reaches the sandbox's environment.
    pub provider: Value,
    /// The sandbox annotation naming the agent.
    pub annotation: Value,
    /// The node's answer to the delegation.
    pub delegated: DelegatedAgent,
}

/// Delegate the sandbox's agent under the Terms `grant` asks for, approved
/// by the controller's passkey (`authorize`), and return the provider record
/// and annotation its sandbox is created with.
pub async fn mint_openshell_credential<F, Fut, A>(
    auth: &AuthClient,
    account_address: &str,
    policy: &Value,
    grant: &Value,
    options: &OpenShellTermsOptions,
    authorize: F,
) -> SdkResult<OpenShellCredential>
where
    F: FnOnce(CustodyChallengeResponse) -> Fut,
    Fut: std::future::Future<Output = SdkResult<A>>,
    A: Serialize,
{
    let terms = openshell_terms(policy, grant, options)?;
    let delegated = auth
        .delegate_agent(account_address, terms, authorize)
        .await?;
    let Some(did) = delegated.identity["did"].as_str().map(str::to_string) else {
        return refuse("the node returned no agent DID");
    };
    Ok(OpenShellCredential {
        provider: json!({
            "name": "tenzro",
            "type": "tenzro",
            "credentials": { "TENZRO_AGENT_TOKEN": did },
        }),
        annotation: json!({ OPENSHELL_AGENT_ANNOTATION: did }),
        agent_did: did,
        delegated,
    })
}

/// A signed agent audit entry as stored and disclosed: hex of the signed
/// JSON and of its session signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenShellSignedEntry {
    /// The entry's JSON, exactly as signed, hex.
    pub body: String,
    /// The session signature's JSON, hex.
    pub signature: String,
}

/// The hardware identity that certifies the session keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenShellIdentity {
    /// P-256 `x || y`, hex.
    pub p256: String,
    /// The ML-DSA-65 key, hex, when the identity has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

/// Verifier options.
#[derive(Debug, Clone)]
pub struct OpenShellVerifyOptions {
    /// The serving node's hardware identity.
    pub identity: OpenShellIdentity,
    /// The moment hybrid records are in force, ms (chain state): an entry
    /// made at or after it must carry a hybrid session signature. `None`
    /// while not in force.
    pub hybrid_records_from_ms: Option<u64>,
    /// The session the entries must belong to, hex.
    pub session_id: Option<String>,
}

/// Entries from JSON Lines (one signed entry per line) or a JSON array.
pub fn parse_openshell_entries(text: &str) -> SdkResult<Vec<OpenShellSignedEntry>> {
    let t = text.trim();
    let rows: Vec<Value> = if t.starts_with('[') {
        serde_json::from_str(t)?
    } else {
        t.lines()
            .filter(|l| !l.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?
    };
    rows.into_iter()
        .enumerate()
        .map(
            |(i, r)| match (r["body"].as_str(), r["signature"].as_str()) {
                (Some(body), Some(signature)) => Ok(OpenShellSignedEntry {
                    body: body.to_string(),
                    signature: signature.to_string(),
                }),
                _ => refuse(format!("entry {i} is not a signed entry")),
            },
        )
        .collect()
}

/// One verified entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenShellRecord {
    /// The session, hex.
    pub session_id: String,
    /// Position in the session.
    pub seq: u64,
    /// When it was recorded, ms.
    pub at_ms: u64,
    /// The agent that acted.
    pub agent: String,
    /// `egress`, `tool_call`, `spend`, `model_call`, `grant_use`, ...
    pub kind: String,
    /// What it acted on.
    pub action: String,
    /// `{"status": "allowed"}` or `{"status": "refused", "reason": ...}`.
    pub outcome: Value,
    /// SHA-256 of the action's arguments, hex.
    pub detail: String,
    /// The payment or settlement it is linked to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_tx: Option<String>,
    /// The host binding the serving node verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// For a tool call: the serving node and the surface (`openshell`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<Value>,
    /// Its leaf hash in the session's MMR, hex.
    pub leaf: String,
    /// Whether a hybrid (Ed25519 + ML-DSA-65) session key signed it.
    pub hybrid: bool,
}

/// A session every entry of which verified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedOpenShellSession {
    /// The session, hex.
    pub session_id: String,
    /// The agent.
    pub agent: String,
    /// Entries.
    pub count: u64,
    /// The MMR root over every entry, hex.
    pub root: String,
    /// The entries, in order.
    pub entries: Vec<OpenShellRecord>,
}

fn unhex(s: &str, what: &str) -> SdkResult<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|_| SdkError::InvalidParameter(format!("{what} is not hex")))
}

fn byte_array(v: &Value, what: &str) -> SdkResult<Vec<u8>> {
    let Some(a) = v.as_array() else {
        return refuse(format!("{what} is not a byte array"));
    };
    a.iter()
        .map(|x| match x.as_u64() {
            Some(b) if b <= 255 => Ok(b as u8),
            _ => refuse(format!("{what} is not a byte array")),
        })
        .collect()
}

fn put(m: &mut Vec<u8>, bytes: &[u8]) {
    m.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    m.extend_from_slice(bytes);
}

fn ml_dsa_verify(vk: &[u8], ctx: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    if vk.len() != ML_DSA_65_VK_LEN || sig.len() != ML_DSA_65_SIG_LEN {
        return false;
    }
    let mut vk_arr: EncodedVerifyingKey<MlDsa65> = Default::default();
    let dst: &mut [u8] = vk_arr.as_mut();
    dst.copy_from_slice(vk);
    let key = VerifyingKey::<MlDsa65>::decode(&vk_arr);
    let mut sig_arr: EncodedSignature<MlDsa65> = Default::default();
    let dst: &mut [u8] = sig_arr.as_mut();
    dst.copy_from_slice(sig);
    let Some(sig) = Signature::<MlDsa65>::decode(&sig_arr) else {
        return false;
    };
    key.verify_with_context(msg, ctx, &sig)
}

fn p256_signature(sig: &[u8]) -> SdkResult<p256::ecdsa::Signature> {
    if sig.len() == 64 {
        p256::ecdsa::Signature::from_slice(sig)
    } else {
        p256::ecdsa::Signature::from_der(sig)
    }
    .map_err(|_| SdkError::InvalidParameter("the P-256 leg is neither raw r || s nor DER".into()))
}

fn verify_composite(identity: &OpenShellIdentity, message: &[u8], sig: &Value) -> SdkResult<bool> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    let classical = &sig["classical"];
    let (Some("raw"), Some(raw)) = (classical["form"].as_str(), classical["signature"].as_str())
    else {
        return refuse("the certificate's P-256 leg is not a raw hardware signature");
    };
    let m = composite_message_representative(CERTIFICATE_CONTEXT, message);
    let xy = unhex(&identity.p256, "the identity's P-256 key")?;
    if xy.len() != 64 {
        return refuse("the identity's P-256 key is not x || y");
    }
    let key =
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&[&[4u8][..], &xy].concat()).map_err(|_| {
            SdkError::InvalidParameter("the identity's P-256 key is not on the curve".into())
        })?;
    let digest: [u8; 32] = Sha256::digest(&m).into();
    if key
        .verify_prehash(&digest, &p256_signature(&unhex(raw, "the P-256 leg")?)?)
        .is_err()
    {
        return Ok(false);
    }
    let pq = match sig["pq"].as_str() {
        Some(h) => Some(unhex(h, "the ML-DSA-65 leg")?),
        None => None,
    };
    let enrolled = match &identity.pq {
        Some(h) => Some(unhex(h, "the identity's ML-DSA-65 key")?),
        None => None,
    };
    match (pq, enrolled) {
        (Some(_), None) => refuse("ML-DSA-65 leg present for an identity with no ML-DSA-65 key"),
        (None, Some(_)) => Ok(false),
        (Some(pq), Some(vk)) => Ok(ml_dsa_verify(&vk, COMPOSITE_LABEL_MLDSA65_P256, &m, &pq)),
        (None, None) => Ok(true),
    }
}

fn ed25519_verify(key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let (Ok(key), Ok(sig)) = (<[u8; 32]>::try_from(key), <[u8; 64]>::try_from(sig)) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) else {
        return false;
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
        .is_ok()
}

fn verify_session_key(key: &Value, message: &[u8], sig: &Value) -> SdkResult<bool> {
    let k = byte_array(&key["bytes"], "the session key")?;
    let s = byte_array(&sig["bytes"], "the session signature")?;
    Ok(match (key["key_type"].as_str(), sig["key_type"].as_str()) {
        (Some("Ed25519"), Some("Ed25519")) => ed25519_verify(&k, message, &s),
        (Some("Ed25519MlDsa65"), Some("Ed25519MlDsa65")) => {
            k.len() == 32 + ML_DSA_65_VK_LEN
                && s.len() > 64
                && ed25519_verify(&k[..32], message, &s[..64])
                && ml_dsa_verify(&k[32..], HYBRID_SESSION_CONTEXT, message, &s[64..])
        }
        _ => false,
    })
}

/// Check one session signature over `body` made at `at_ms`: the identity
/// certified the session key, the certificate was valid at `at_ms`, the
/// session key signed `body`, and a record made once hybrid records are in
/// force carries a hybrid session key. Returns whether the session key is
/// hybrid.
pub fn verify_openshell_signature(
    body: &[u8],
    signature: &[u8],
    at_ms: u64,
    identity: &OpenShellIdentity,
    hybrid_records_from_ms: Option<u64>,
) -> SdkResult<bool> {
    let s: Value = serde_json::from_slice(signature).map_err(|_| {
        SdkError::InvalidParameter("the signature is not a session signature".into())
    })?;
    let cert = &s["certificate"];
    let key = &cert["session_key"];
    let tag = match key["key_type"].as_str() {
        Some("Ed25519") => 0u8,
        Some("Ed25519MlDsa65") => 2u8,
        _ => return refuse("a session key must be Ed25519 or Ed25519 with ML-DSA-65"),
    };
    let hybrid = tag == 2;
    if hybrid_records_from_ms.is_some_and(|from| at_ms >= from) && !hybrid {
        return refuse(format!(
            "a record made at {at_ms} ms needs a hybrid session signature"
        ));
    }
    let Some(not_after) = cert["not_after_ms"].as_u64() else {
        return refuse("the certificate names no expiry");
    };
    if at_ms > not_after {
        return refuse(format!(
            "the session certificate expired at {not_after} ms, before {at_ms} ms"
        ));
    }
    let p256 = unhex(&identity.p256, "the identity's P-256 key")?;
    let mut m = Vec::new();
    put(&mut m, &p256);
    match &identity.pq {
        Some(pq) => {
            m.push(1);
            put(&mut m, &unhex(pq, "the identity's ML-DSA-65 key")?);
        }
        None => m.push(0),
    }
    m.push(tag);
    put(&mut m, &byte_array(&key["bytes"], "the session key")?);
    m.extend_from_slice(&not_after.to_le_bytes());
    if !verify_composite(identity, &m, &cert["signature"])? {
        return refuse("the session certificate does not verify under the identity");
    }
    if !verify_session_key(key, body, &s["signature"])? {
        return refuse("the session signature does not verify");
    }
    Ok(hybrid)
}

fn leaf_hash(body: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update((body.len() as u64).to_le_bytes());
    h.update(body);
    h.update(signature);
    h.finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn strip(s: &str) -> String {
    s.strip_prefix("0x").unwrap_or(s).to_lowercase()
}

fn record(e: &Value, i: usize, leaf: String, hybrid: bool) -> SdkResult<OpenShellRecord> {
    let text = |k: &str| {
        e[k].as_str()
            .map(str::to_string)
            .ok_or_else(|| SdkError::InvalidParameter(format!("entry {i} has no {k}")))
    };
    Ok(OpenShellRecord {
        session_id: strip(&text("session_id")?),
        seq: e["seq"]
            .as_u64()
            .ok_or_else(|| SdkError::InvalidParameter(format!("entry {i} has no seq")))?,
        at_ms: e["at_ms"]
            .as_u64()
            .ok_or_else(|| SdkError::InvalidParameter(format!("entry {i} has no at_ms")))?,
        agent: text("agent")?,
        kind: text("kind")?,
        action: text("action")?,
        outcome: e["outcome"].clone(),
        detail: text("detail")?,
        linked_tx: e["linked_tx"].as_str().map(str::to_string),
        image: e["image"].as_str().map(str::to_string),
        call: e.get("call").cloned(),
        leaf,
        hybrid,
    })
}

fn decode(body: &[u8], i: usize) -> SdkResult<Value> {
    serde_json::from_slice(body)
        .map_err(|_| SdkError::InvalidParameter(format!("entry {i} is not an agent audit entry")))
}

/// Verify a session from its entries alone, as the extensions' own verifier
/// does: every entry signed under a session key the identity certified,
/// numbered from 0 with no gap, of one session and one agent, each chained to
/// the leaf hash of the entry before it. Returns the entries and the MMR
/// root.
pub fn verify_openshell_session(
    entries: &[OpenShellSignedEntry],
    opts: &OpenShellVerifyOptions,
) -> SdkResult<VerifiedOpenShellSession> {
    if entries.is_empty() {
        return refuse("the session has no entries");
    }
    let mut session = opts.session_id.as_deref().map(strip);
    let mut agent: Option<String> = None;
    let mut prev = [0u8; 32];
    let mut peaks: Vec<(u32, [u8; 32])> = Vec::new();
    let mut out = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        let body = unhex(&entry.body, "an entry body")?;
        let signature = unhex(&entry.signature, "an entry signature")?;
        let e = decode(&body, i)?;
        let at_ms = e["at_ms"].as_u64().unwrap_or(u64::MAX);
        let hybrid = verify_openshell_signature(
            &body,
            &signature,
            at_ms,
            &opts.identity,
            opts.hybrid_records_from_ms,
        )
        .map_err(|err| SdkError::InvalidParameter(format!("entry {i}: {err}")))?;
        let r = record(&e, i, String::new(), hybrid)?;
        if r.seq != i as u64 {
            return refuse(format!("entry {i} is numbered {}", r.seq));
        }
        if e["prev"].as_str().map(strip) != Some(hex::encode(prev)) {
            return refuse(format!("entry {i} does not chain to the entry before it"));
        }
        if *session.get_or_insert_with(|| r.session_id.clone()) != r.session_id {
            return refuse(format!("entry {i} names another session"));
        }
        if *agent.get_or_insert_with(|| r.agent.clone()) != r.agent {
            return refuse(format!("entry {i} names another agent"));
        }
        let leaf = leaf_hash(&body, &signature);
        prev = leaf;
        let (mut h, mut node) = (0u32, leaf);
        while let Some(&(ph, left)) = peaks.last() {
            if ph != h {
                break;
            }
            peaks.pop();
            node = node_hash(&left, &node);
            h += 1;
        }
        peaks.push((h, node));
        out.push(OpenShellRecord {
            leaf: hex::encode(leaf),
            ..r
        });
    }
    let root = match peaks.split_last() {
        None => [0u8; 32],
        Some((last, rest)) => rest
            .iter()
            .rev()
            .fold(last.1, |acc, p| node_hash(&p.1, &acc)),
    };
    Ok(VerifiedOpenShellSession {
        session_id: session.unwrap_or_default(),
        agent: agent.unwrap_or_default(),
        count: out.len() as u64,
        root: hex::encode(root),
        entries: out,
    })
}

/// Verify the signed record a model call returns in `x-tenzro-receipt`
/// (base64url of the signed entry's JSON): its signature only, as one entry
/// of the agent's session.
pub fn verify_openshell_receipt(
    header: &str,
    identity: &OpenShellIdentity,
    hybrid_records_from_ms: Option<u64>,
) -> SdkResult<OpenShellRecord> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header.trim().trim_end_matches('='))
        .map_err(|_| SdkError::InvalidParameter("the receipt is not base64url".into()))?;
    let entry: OpenShellSignedEntry = serde_json::from_slice(&raw)?;
    let body = unhex(&entry.body, "the receipt body")?;
    let signature = unhex(&entry.signature, "the receipt signature")?;
    let e = decode(&body, 0)?;
    let at_ms = e["at_ms"].as_u64().unwrap_or(u64::MAX);
    let hybrid =
        verify_openshell_signature(&body, &signature, at_ms, identity, hybrid_records_from_ms)?;
    record(&e, 0, hex::encode(leaf_hash(&body, &signature)), hybrid)
}

/// A payment the agent made, or was refused, in a session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenShellPayment {
    /// The entry's position.
    pub seq: u64,
    /// When, ms.
    pub at_ms: u64,
    /// `x402`, `mpp`, `ap2`, or `inference` for a model call's charge.
    pub rail: String,
    /// The service URL for a payment, the model for an inference charge.
    pub target: String,
    /// The decision.
    pub outcome: Value,
    /// The payment or settlement it is linked to; `None` when refused.
    pub linked_tx: Option<String>,
}

/// The payments of a verified session, in order: every `spend` entry
/// (action "<rail> <url>") and every model call that names the settlement
/// of its charge.
pub fn openshell_payments(session: &VerifiedOpenShellSession) -> SdkResult<Vec<OpenShellPayment>> {
    let mut out = Vec::new();
    for e in &session.entries {
        let (rail, target) = match e.kind.as_str() {
            "spend" => match e.action.split_once(' ') {
                Some((rail, target)) if !rail.is_empty() => (rail.to_string(), target.to_string()),
                _ => return refuse(format!("entry {} names no payment rail", e.seq)),
            },
            "model_call" if e.linked_tx.is_some() => ("inference".to_string(), e.action.clone()),
            _ => continue,
        };
        out.push(OpenShellPayment {
            seq: e.seq,
            at_ms: e.at_ms,
            rail,
            target,
            outcome: e.outcome.clone(),
            linked_tx: e.linked_tx.clone(),
        });
    }
    Ok(out)
}
