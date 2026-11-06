//! The record of every privileged call this node serves.
//!
//! Every call to an admin-class method (the operator DID or a policy admin,
//! see [`crate::rpc_gates::ADMIN_METHODS`]) leaves a record of who made it,
//! from where, with which credential, what it asked for and what came of it,
//! whether the gate admitted it or refused it. So does a sign-in by an
//! administrator, and a privileged action the node takes on its own (the
//! surge planner loading and unloading models).
//!
//! # What a record holds
//!
//! - **When and where:** the time, this node's machine DID and its chain id.
//! - **What:** the method, the surface it arrived on, and a digest of its
//!   parameters: a SHA-256 of the whole and a short list of non-secret key
//!   fields (model id, DID, role and the like). Payloads are never stored.
//! - **Who:** the DID the access token proved, its identity root, whether it
//!   is the operator or a policy admin, the credential it signed in with
//!   (passkey, hardware key, a delegated agent's serving key), the token's
//!   fingerprint, id and DPoP key thumbprint (never the token), and for a
//!   delegated agent the Terms it acts under and the human or machine at
//!   their root.
//! - **From where:** the transport, the TCP peer, the client address, the
//!   `X-Forwarded-For` chain only when the peer is a configured trusted
//!   proxy, the client machine's name and login when a configured local
//!   identity service knows the address, the iroh endpoint id of an overlay
//!   peer, the user agent, the client header, and a request id.
//! - **Decision and result:** admitted or refused (with the refusal), and for
//!   an admitted call a second record with its result (success or the error
//!   code) and how long it ran.
//!
//! # Tamper evidence
//!
//! Records are appended, one JSON line each, to `audit/admin-audit.jsonl` in
//! the data directory and synced to disk before the call runs. Each carries
//! the hash of the record before it, so an edit, an insertion or a deletion
//! anywhere breaks the chain. Every `checkpoint_every` records, and when a
//! segment rotates, the node signs the head of the chain with its hardware
//! identity key (TPM or Secure Enclave, through
//! [`TenzroNode::identity_signer`]); the checkpoint is itself a record in the
//! chain. Each record is also logged at INFO with its sequence number and
//! hash, so the journal holds an independent copy of the head. A segment past
//! `rotate_bytes` is renamed to `admin-audit.<last seq>.jsonl` and the chain
//! continues into a new file; nothing here deletes a segment.
//!
//! # Fail closed
//!
//! The admission record is written before the call runs. When it cannot be
//! written the call is refused with [`AUDIT_UNAVAILABLE`]: a privileged
//! action never happens without its record.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use tenzro_crypto::composite::{
    CompositePublicKey, CompositeSignature, HybridSigner, PqPolicy, SignatureContext,
};
use tenzro_types::node_access::Surface;

use crate::egress_guard::Cidr;
use crate::node::TenzroNode;
use crate::rpc::{AuthContext, JsonRpcError, JsonRpcRequest, JsonRpcResponse};

/// Directory under the data directory that holds the log.
pub const AUDIT_DIR: &str = "audit";
/// The segment being written.
pub const ACTIVE_SEGMENT: &str = "admin-audit.jsonl";
/// JSON-RPC error code for a privileged call refused because its record
/// could not be written.
pub const AUDIT_UNAVAILABLE: i32 = -32040;

const SEGMENT_PREFIX: &str = "admin-audit.";
const SEGMENT_SUFFIX: &str = ".jsonl";
const HASH_DOMAIN: &[u8] = b"tenzro/node/admin-audit/v1";
const CHECKPOINT_DOMAIN: &[u8] = b"tenzro/node/admin-audit-checkpoint/v1";
const FINGERPRINT_DOMAIN: &[u8] = b"tenzro/node/token-fingerprint/v1";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
/// Longest header value or reason kept in a record.
const MAX_TEXT: usize = 200;
/// Longest parameter value kept as a key field.
const MAX_FIELD: usize = 96;
/// Records a listing returns when it names no limit, and at most.
const DEFAULT_LIST: usize = 100;
const MAX_LIST: usize = 1000;

/// Parameter keys whose values are kept in a record. Everything else is in
/// the digest only, so a secret in a parameter never reaches the log.
const KEY_FIELDS: &[&str] = &[
    "address",
    "agent_did",
    "chain",
    "class",
    "cluster_did",
    "did",
    "draining",
    "jti",
    "machine_did",
    "method",
    "model",
    "model_id",
    "name",
    "new_owner_did",
    "operation",
    "role",
    "seq",
    "surface",
    "version",
    "visibility",
];

/// Operator settings for administrative access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminConfig {
    /// Networks (addresses or CIDR ranges) administrative calls are accepted
    /// from, compared against the client address. Empty accepts any network
    /// and logs a warning for every administrative call from off this
    /// machine. In-process calls are always accepted; iroh overlay calls are
    /// refused once a list is set, since they carry no address.
    #[serde(default)]
    pub networks: Vec<String>,
    /// Methods outside the admin class to record as well.
    #[serde(default)]
    pub audit_also: Vec<String>,
    /// Admin-class methods not to record (reads an operator polls often).
    #[serde(default)]
    pub audit_skip: Vec<String>,
    /// Size at which the active segment is closed and a new one started.
    #[serde(default = "default_rotate_bytes")]
    pub audit_rotate_bytes: u64,
    /// Records between signed checkpoints.
    #[serde(default = "default_checkpoint_every")]
    pub audit_checkpoint_every: u64,
    /// A local identity service asked which machine and login a client
    /// address belongs to, such as an overlay network's local identity
    /// service. Absent records no peer identity.
    #[serde(default)]
    pub peer_identity: Option<PeerIdentityConfig>,
}

/// A local identity service on a Unix socket. The node sends it
/// `GET <request>` over HTTP/1.0, with `{addr}` in `request` replaced by the
/// client's address and port, and reads the machine name and login from the
/// JSON answer at the two JSON pointers. A service that does not answer
/// within half a second, or answers anything but 200 with JSON, records no
/// peer identity for that call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentityConfig {
    /// The service's Unix socket.
    pub socket: PathBuf,
    /// The request path and query; must contain `{addr}`.
    #[serde(default = "default_identity_request")]
    pub request: String,
    /// The `Host` header the service expects.
    #[serde(default = "default_identity_host")]
    pub host: String,
    /// JSON pointer to the machine name in the answer.
    #[serde(default = "default_identity_machine_field")]
    pub machine_field: String,
    /// JSON pointer to the login in the answer.
    #[serde(default = "default_identity_login_field")]
    pub login_field: String,
    /// Client networks (addresses or CIDR ranges) to ask about. Empty asks
    /// about every client address off this machine.
    #[serde(default)]
    pub networks: Vec<String>,
}

fn default_identity_request() -> String {
    "/whois?addr={addr}".to_string()
}

fn default_identity_host() -> String {
    "localhost".to_string()
}

fn default_identity_machine_field() -> String {
    "/machine".to_string()
}

fn default_identity_login_field() -> String {
    "/login".to_string()
}

fn default_rotate_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_checkpoint_every() -> u64 {
    64
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            networks: Vec::new(),
            audit_also: Vec::new(),
            audit_skip: Vec::new(),
            audit_rotate_bytes: default_rotate_bytes(),
            audit_checkpoint_every: default_checkpoint_every(),
            peer_identity: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// How a call reached the node.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// The JSON-RPC listener and the REST gateway on it.
    Http,
    /// The MCP server.
    Mcp,
    /// A frame over the iroh overlay.
    Iroh,
    /// A caller in this process (the embedded client, the desktop app).
    #[default]
    InProcess,
    /// The node acting on its own.
    Node,
}

/// A client machine, as the configured local identity service names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentity {
    /// The client machine's name.
    pub machine: Option<String>,
    /// The login the client machine is registered to.
    pub login: Option<String>,
}

/// Where a call came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// The transport.
    pub transport: Transport,
    /// The TCP peer, address and port.
    pub peer: Option<String>,
    /// The client address: the peer, or the first untrusted hop of a trusted
    /// proxy's `X-Forwarded-For`.
    pub client_ip: Option<String>,
    /// The `X-Forwarded-For` chain, present only when the peer is a trusted
    /// proxy.
    pub forwarded_for: Option<Vec<String>>,
    /// The client machine and its login, when the configured local identity
    /// service knows the client address.
    pub peer_identity: Option<PeerIdentity>,
    /// The iroh endpoint id of an overlay peer.
    pub overlay_peer: Option<String>,
    /// The `User-Agent` header.
    pub user_agent: Option<String>,
    /// The `X-Tenzro-Client` header: client name and version.
    pub client: Option<String>,
}

/// The credential a caller proved itself with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Credential {
    /// An access token from a passkey sign-in.
    Passkey,
    /// An access token from a hardware-key (TPM or Secure Enclave) sign-in.
    HardwareKey,
    /// An access token from a delegated agent's serving key, under its Terms.
    DelegatedAgentKey,
    /// An access token whose sign-in this process did not see (issued before
    /// a restart); the sign-in record names it by fingerprint.
    AccessToken,
    /// No credential, or one that did not verify.
    #[default]
    None,
    /// The node itself.
    Node,
}

/// The access token a call carried, by reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenRef {
    /// Truncated SHA-256 of the token, domain-separated. Identifies the token
    /// without revealing it.
    pub fingerprint: String,
    /// The token's id, when it verified.
    pub jti: Option<String>,
    /// Thumbprint of the DPoP key the token is bound to.
    pub dpop_jkt: Option<String>,
    /// Expiry, Unix seconds.
    pub expires_at: Option<u64>,
}

/// The Terms a delegated agent acts under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// The agent's name under its controller.
    pub agent_name: String,
    /// The human or machine at the root of the delegation.
    pub controller_did: String,
    /// What the root's authority rests on: `passkey` or `machine`.
    pub root_kind: String,
    /// The Terms version in force.
    pub terms_version: u64,
    /// Digest of the custody challenge the root approved, which identifies
    /// the approval.
    pub approval_digest: String,
    /// The token's delegation chain, root first, when it carries one.
    pub chain: Vec<String>,
}

/// Who made a call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// The DID the access token proved.
    pub did: Option<String>,
    /// What the DID is rooted in: `passkey` (a human), `machine`, or `None`
    /// for any other DID.
    pub root: Option<String>,
    /// `operator` or `policy_admin` when the DID administers this node.
    pub role: Option<String>,
    /// The credential.
    pub credential: Credential,
    /// The token, by reference.
    pub token: Option<TokenRef>,
    /// The Terms, for a delegated agent.
    pub delegation: Option<Delegation>,
    /// The node component that acted, for an action the node took itself.
    pub actor: Option<String>,
}

/// What a call asked for, without its payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamsDigest {
    /// SHA-256 of the parameters as received, hex.
    pub sha256: String,
    /// The non-secret key fields, by name.
    pub fields: BTreeMap<String, String>,
}

/// The gate's decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Decision {
    /// Admitted; the call runs once this record is on disk.
    Admitted,
    /// Refused before it ran.
    Refused {
        /// The JSON-RPC error code the caller received.
        code: i32,
        /// The refusal.
        reason: String,
    },
}

/// A privileged call, as the gate saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    /// This node's id for the request.
    pub request_id: String,
    /// The `X-Request-Id` header, when sent.
    pub client_request_id: Option<String>,
    /// The JSON-RPC id, as text.
    pub jsonrpc_id: Option<String>,
    /// The method.
    pub method: String,
    /// The access-policy surface it was decided under.
    pub surface: Option<String>,
    /// The parameters, as a digest.
    pub params: ParamsDigest,
    /// Who.
    pub principal: Principal,
    /// From where.
    pub source: Source,
    /// The gate's decision.
    pub decision: Decision,
}

/// How an admitted call ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    /// It succeeded.
    Ok,
    /// It returned an error.
    Error {
        /// The JSON-RPC error code.
        code: i32,
    },
}

/// The result of an admitted call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completion {
    /// The request, as its admission record names it.
    pub request_id: String,
    /// Sequence number of the admission record.
    pub call_seq: u64,
    /// The method, repeated so a filter by method finds both records.
    pub method: String,
    /// How it ended.
    pub outcome: Outcome,
    /// How long the call ran.
    pub elapsed_ms: u64,
}

/// A sign-in by a DID that administers this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignIn {
    /// The DID that signed in.
    pub did: String,
    /// `operator` or `policy_admin`.
    pub role: Option<String>,
    /// The credential it signed in with.
    pub credential: Credential,
    /// The token issued, by reference.
    pub token: TokenRef,
    /// From where.
    pub source: Source,
}

/// A signed statement of the chain's head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Sequence number of the record it covers.
    pub covers_seq: u64,
    /// Hash of that record.
    pub covers_hash: String,
    /// The identity key that signed, when one did.
    pub signer: Option<CompositePublicKey>,
    /// The signature over [`checkpoint_message`], when the node holds a
    /// hardware identity key.
    pub signature: Option<CompositeSignature>,
}

/// The log opened by a starting node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    /// The node version.
    pub version: String,
    /// The last line of the log could not be read (a write cut short), and
    /// this record continues the chain from the last record that could.
    pub after_unreadable_line: bool,
}

/// One entry of the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "snake_case",
    tag = "kind",
    content = "data",
    deny_unknown_fields
)]
pub enum Entry {
    /// A privileged call and the gate's decision.
    Call(Call),
    /// The result of an admitted call.
    Completion(Completion),
    /// An administrator signed in.
    SignIn(SignIn),
    /// A signed checkpoint.
    Checkpoint(Checkpoint),
    /// The node started and opened the log.
    Opened(Opened),
}

/// A record: its place in the chain and its entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// Position in the chain, from 0.
    pub seq: u64,
    /// Hash of the record before it.
    pub prev: String,
    /// When, RFC 3339 UTC with milliseconds.
    pub at: String,
    /// This node's machine DID, when its identity key is open.
    pub node: Option<String>,
    /// The chain id.
    pub chain_id: u64,
    /// The entry.
    pub entry: Entry,
}

/// A line of the log: a record and its hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Line {
    /// The record.
    pub record: Record,
    /// SHA-256 over the domain and the record's JSON, hex.
    pub hash: String,
}

/// The hash a record is chained by.
pub fn record_hash(record: &Record) -> Result<String, String> {
    let body = serde_json::to_vec(record).map_err(|e| format!("encode record: {e}"))?;
    let mut h = Sha256::new();
    h.update(HASH_DOMAIN);
    h.update(&body);
    Ok(hex::encode(h.finalize()))
}

/// The bytes a checkpoint signs: domain, node, chain id, sequence number
/// and hash, each length-prefixed or fixed-width so no two checkpoints share
/// a message.
pub fn checkpoint_message(node: Option<&str>, chain_id: u64, seq: u64, hash: &str) -> Vec<u8> {
    let node = node.unwrap_or_default().as_bytes();
    let mut m = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + node.len() + 8 + 8 + 8 + 64);
    m.extend_from_slice(CHECKPOINT_DOMAIN);
    m.extend_from_slice(&(node.len() as u64).to_be_bytes());
    m.extend_from_slice(node);
    m.extend_from_slice(&chain_id.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(hash.as_bytes());
    m
}

/// A token's fingerprint, from an `Authorization` header value or a bare
/// token: the first 16 bytes of a domain-separated SHA-256, hex.
pub fn token_fingerprint(authorization: &str) -> Option<String> {
    let a = authorization.trim();
    let token = a
        .split_once(' ')
        .filter(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("dpop") || scheme.eq_ignore_ascii_case("bearer")
        })
        .map(|(_, t)| t.trim())
        .unwrap_or(a);
    if token.is_empty() {
        return None;
    }
    let mut h = Sha256::new();
    h.update(FINGERPRINT_DOMAIN);
    h.update(token.as_bytes());
    Some(hex::encode(&h.finalize()[..16]))
}

/// The digest of a call's parameters.
pub fn params_digest(params: Option<&Value>) -> ParamsDigest {
    let bytes = params
        .map(|p| serde_json::to_vec(p).unwrap_or_default())
        .unwrap_or_default();
    let mut fields = BTreeMap::new();
    let object = match params {
        Some(Value::Object(o)) => Some(o),
        Some(Value::Array(a)) => match a.as_slice() {
            [Value::Object(o)] => Some(o),
            _ => None,
        },
        _ => None,
    };
    if let Some(o) = object {
        for key in KEY_FIELDS {
            let text = match o.get(*key) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                Some(Value::Bool(b)) => b.to_string(),
                _ => continue,
            };
            if text.len() <= MAX_FIELD {
                fields.insert((*key).to_string(), clip(&text));
            }
        }
    }
    ParamsDigest {
        sha256: hex::encode(Sha256::digest(&bytes)),
        fields,
    }
}

/// `s` as printable ASCII, at most [`MAX_TEXT`] characters.
fn clip(s: &str) -> String {
    s.chars()
        .take(MAX_TEXT)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

// ---------------------------------------------------------------------------
// Request origin
// ---------------------------------------------------------------------------

/// What the transport knows about a request, before any gate runs.
#[derive(Debug, Clone, Default)]
pub struct Origin {
    /// The transport.
    pub transport: Transport,
    /// The TCP peer.
    pub peer: Option<SocketAddr>,
    /// The client address.
    pub client_ip: Option<IpAddr>,
    /// The trusted proxy chain.
    pub forwarded_for: Option<Vec<IpAddr>>,
    /// The overlay peer's endpoint id.
    pub overlay_peer: Option<String>,
    /// `User-Agent`.
    pub user_agent: Option<String>,
    /// `X-Tenzro-Client`.
    pub client: Option<String>,
    /// `X-Request-Id`.
    pub client_request_id: Option<String>,
    /// Fingerprint of the `Authorization` header's token.
    pub token_fingerprint: Option<String>,
}

impl Origin {
    /// A request that arrived over the iroh overlay from `peer`.
    pub fn overlay(peer: String) -> Self {
        Self {
            transport: Transport::Iroh,
            overlay_peer: Some(peer),
            ..Self::default()
        }
    }

    /// An HTTP request from `peer` with `headers`, on `transport`.
    pub fn http(
        surface: &crate::http_surface::SurfacePolicy,
        transport: Transport,
        peer: Option<SocketAddr>,
        headers: &axum::http::HeaderMap,
    ) -> Self {
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(clip)
                .filter(|s| !s.is_empty())
        };
        Self {
            transport,
            peer,
            client_ip: peer.map(|p| surface.client_ip(p, headers)),
            forwarded_for: peer.and_then(|p| surface.forwarded_chain(p, headers)),
            overlay_peer: None,
            user_agent: header("user-agent"),
            client: header("x-tenzro-client"),
            client_request_id: header("x-request-id"),
            token_fingerprint: headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(token_fingerprint),
        }
    }
}

tokio::task_local! {
    static ORIGIN: Origin;
}

/// Run `f` as the handling of a request from `origin`.
pub async fn with_origin<F: std::future::Future>(origin: Origin, f: F) -> F::Output {
    ORIGIN.scope(origin, f).await
}

/// The origin of the request being handled; an in-process caller when no
/// transport named one.
pub fn current_origin() -> Origin {
    ORIGIN.try_with(Clone::clone).unwrap_or_default()
}

/// Middleware recording the origin of each request on an HTTP listener.
pub async fn capture_http(
    axum::extract::State((node, transport)): axum::extract::State<(Arc<TenzroNode>, Transport)>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let peer = req
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let origin = Origin::http(node.http_surface(), transport, peer, req.headers());
    with_origin(origin, next.run(req)).await
}

/// The configured local identity service, checked at open.
#[derive(Debug, Clone)]
struct PeerIdentityResolver {
    socket: PathBuf,
    request: String,
    host: String,
    machine_field: String,
    login_field: String,
    networks: Vec<Cidr>,
}

impl PeerIdentityResolver {
    fn from_config(cfg: &PeerIdentityConfig) -> Result<Self, String> {
        if !cfg.request.starts_with('/') || !cfg.request.contains("{addr}") {
            return Err(format!(
                "admin peer_identity request {:?} must start with / and contain {{addr}}",
                cfg.request
            ));
        }
        for (name, v) in [
            ("request", &cfg.request),
            ("host", &cfg.host),
            ("machine_field", &cfg.machine_field),
            ("login_field", &cfg.login_field),
        ] {
            if v.is_empty() || v.chars().any(|c| c.is_control() || c == ' ') {
                return Err(format!(
                    "admin peer_identity {name} must be non-empty, with no spaces or control characters"
                ));
            }
        }
        for (name, v) in [
            ("machine_field", &cfg.machine_field),
            ("login_field", &cfg.login_field),
        ] {
            if !v.starts_with('/') {
                return Err(format!(
                    "admin peer_identity {name} {v:?} must be a JSON pointer (start with /)"
                ));
            }
        }
        let networks = cfg
            .networks
            .iter()
            .map(|s| Cidr::parse(s).map_err(|e| format!("admin peer_identity networks: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            socket: cfg.socket.clone(),
            request: cfg.request.clone(),
            host: cfg.host.clone(),
            machine_field: cfg.machine_field.clone(),
            login_field: cfg.login_field.clone(),
            networks,
        })
    }

    /// Whether the service is asked about `ip`: an address in its networks,
    /// or with none set, any address off this machine.
    fn asks_about(&self, ip: IpAddr) -> bool {
        if self.networks.is_empty() {
            !ip.to_canonical().is_loopback()
        } else {
            self.networks.iter().any(|n| n.contains(ip))
        }
    }

    /// Ask the service who `addr` is. `None` when it does not answer within
    /// half a second or answers something unreadable.
    #[cfg(unix)]
    async fn lookup(&self, addr: SocketAddr) -> Option<PeerIdentity> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ask = async {
            let mut stream = tokio::net::UnixStream::connect(&self.socket).await.ok()?;
            let path = self.request.replace("{addr}", &addr.to_string());
            let request = format!("GET {path} HTTP/1.0\r\nHost: {}\r\n\r\n", self.host);
            stream.write_all(request.as_bytes()).await.ok()?;
            let mut body = Vec::new();
            stream.take(256 * 1024).read_to_end(&mut body).await.ok()?;
            let at = body.windows(4).position(|w| w == b"\r\n\r\n")?;
            let head = String::from_utf8_lossy(&body[..at]);
            if !head.starts_with("HTTP/1.") || !head.split(' ').nth(1).is_some_and(|c| c == "200") {
                return None;
            }
            let v: Value = serde_json::from_slice(&body[at + 4..]).ok()?;
            let text = |p: &str| v.pointer(p).and_then(Value::as_str).map(clip);
            Some(PeerIdentity {
                machine: text(&self.machine_field),
                login: text(&self.login_field),
            })
        };
        tokio::time::timeout(std::time::Duration::from_millis(500), ask)
            .await
            .ok()
            .flatten()
    }

    #[cfg(not(unix))]
    async fn lookup(&self, _addr: SocketAddr) -> Option<PeerIdentity> {
        None
    }
}

// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

/// The head of the chain, as this process last wrote it.
#[derive(Debug)]
struct Head {
    /// The next record's sequence number.
    next_seq: u64,
    /// Hash of the last record.
    hash: String,
    /// Records since the last checkpoint.
    since_checkpoint: u64,
}

/// What [`AdminAudit::verify`] found.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verification {
    /// True when the chain is whole, every checkpoint verifies, and the log
    /// ends where this node last wrote.
    pub ok: bool,
    /// Records read.
    pub records: u64,
    /// Segments read, oldest first.
    pub segments: Vec<String>,
    /// First and last sequence numbers read.
    pub first_seq: Option<u64>,
    /// See `first_seq`.
    pub last_seq: Option<u64>,
    /// Hash of the last record read.
    pub head_hash: Option<String>,
    /// Checkpoints read.
    pub checkpoints: u64,
    /// Checkpoints whose signature verified under this node's identity key.
    pub signed_checkpoints: u64,
    /// Checkpoints written without a signature (no identity key, or the
    /// hardware refused).
    pub unsigned_checkpoints: u64,
    /// Everything that is wrong, one sentence each.
    pub problems: Vec<String>,
}

/// A listing filter.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    /// Only records about this method.
    pub method: Option<String>,
    /// Only records whose principal is this DID.
    pub principal: Option<String>,
    /// Only records at or after this time (Unix ms).
    pub since_ms: Option<i64>,
    /// Only records before this time (Unix ms).
    pub until_ms: Option<i64>,
    /// At most this many, the most recent.
    pub limit: usize,
}

/// The node's administrative audit log.
pub struct AdminAudit {
    dir: PathBuf,
    rotate_bytes: u64,
    checkpoint_every: u64,
    also: BTreeSet<String>,
    skip: BTreeSet<String>,
    networks: Vec<Cidr>,
    peer_identity: Option<PeerIdentityResolver>,
    chain_id: u64,
    head: Mutex<Head>,
    counters: Mutex<BTreeMap<(String, &'static str), u64>>,
    sign_ins: Mutex<HashMap<String, (Credential, u64)>>,
}

impl std::fmt::Debug for AdminAudit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminAudit")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

/// Sequence number a rotated segment's name carries.
fn segment_seq(name: &str) -> Option<u64> {
    name.strip_prefix(SEGMENT_PREFIX)?
        .strip_suffix(SEGMENT_SUFFIX)?
        .parse()
        .ok()
}

impl AdminAudit {
    /// The log in `data_dir`, under `cfg`, for chain `chain_id`. Writes an
    /// [`Opened`] record, so a directory this process cannot write refuses
    /// here rather than at the first administrative call.
    pub fn open(data_dir: &Path, cfg: &AdminConfig, chain_id: u64) -> Result<Self, String> {
        let networks = cfg
            .networks
            .iter()
            .map(|s| Cidr::parse(s).map_err(|e| format!("admin networks: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        for m in &cfg.audit_skip {
            if crate::rpc_gates::gate_class(m) != Some(crate::rpc_gates::GateClass::Admin) {
                return Err(format!(
                    "admin audit_skip names {m}, which is not an admin-class method"
                ));
            }
        }
        for m in &cfg.audit_also {
            if !crate::rpc_gates::is_known_method(m) {
                return Err(format!(
                    "admin audit_also names {m}, which this node does not serve"
                ));
            }
        }
        let peer_identity = cfg
            .peer_identity
            .as_ref()
            .map(PeerIdentityResolver::from_config)
            .transpose()?;
        let dir = data_dir.join(AUDIT_DIR);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let audit = Self {
            dir,
            rotate_bytes: cfg.audit_rotate_bytes.max(4096),
            checkpoint_every: cfg.audit_checkpoint_every.max(1),
            also: cfg.audit_also.iter().cloned().collect(),
            skip: cfg.audit_skip.iter().cloned().collect(),
            networks,
            peer_identity,
            chain_id,
            head: Mutex::new(Head {
                next_seq: 0,
                hash: GENESIS_HASH.to_string(),
                since_checkpoint: 0,
            }),
            counters: Mutex::new(BTreeMap::new()),
            sign_ins: Mutex::new(HashMap::new()),
        };
        let unreadable = audit.recover_head()?;
        audit.append(
            Entry::Opened(Opened {
                version: env!("CARGO_PKG_VERSION").to_string(),
                after_unreadable_line: unreadable,
            }),
            None,
        )?;
        if unreadable {
            error!(
                dir = %audit.dir.display(),
                "the last line of the administrative audit log could not be read; the chain \
                 continues from the last record that could. Run `tenzro access audit-verify`."
            );
        }
        if audit.networks.is_empty() {
            warn!(
                "administrative calls are accepted from any network; set [admin] networks \
                 (for example 127.0.0.1/32 and the operators' private network) to restrict them"
            );
        }
        Ok(audit)
    }

    /// Whether calls to `method` are recorded.
    pub fn audits(&self, method: &str) -> bool {
        self.also.contains(method)
            || (crate::rpc_gates::gate_class(method) == Some(crate::rpc_gates::GateClass::Admin)
                && !self.skip.contains(method))
    }

    /// Why an administrative call from `origin` is refused by the network
    /// restriction, if it is.
    pub fn source_refusal(&self, origin: &Origin) -> Option<String> {
        let ip = origin.client_ip;
        if self.networks.is_empty() {
            if let Some(ip) = ip
                && !ip.is_loopback()
            {
                warn!(
                    client_ip = %ip,
                    "administrative call from off this machine with no [admin] networks set"
                );
            }
            return None;
        }
        match (origin.transport, ip) {
            (Transport::InProcess | Transport::Node, _) => None,
            (_, Some(ip)) if self.networks.iter().any(|n| n.contains(ip)) => None,
            (_, Some(ip)) => Some(format!(
                "administrative calls are not accepted from {ip}; this node accepts them from \
                 its [admin] networks only"
            )),
            (_, None) => Some(
                "administrative calls are not accepted over this transport; this node accepts \
                 them from its [admin] networks only"
                    .to_string(),
            ),
        }
    }

    /// The source of a call from `origin`, asking the configured local
    /// identity service who the client address belongs to.
    pub async fn source_of(&self, origin: &Origin) -> Source {
        let peer_identity = match (&self.peer_identity, origin.client_ip) {
            (Some(resolver), Some(ip)) if resolver.asks_about(ip) => {
                let port = origin
                    .peer
                    .filter(|p| p.ip().to_canonical() == ip)
                    .map_or(1, |p| p.port());
                resolver.lookup(SocketAddr::new(ip, port)).await
            }
            _ => None,
        };
        Source {
            transport: origin.transport,
            peer: origin.peer.map(|p| p.to_string()),
            client_ip: origin.client_ip.map(|ip| ip.to_string()),
            forwarded_for: origin
                .forwarded_for
                .as_ref()
                .map(|c| c.iter().map(ToString::to_string).collect()),
            peer_identity,
            overlay_peer: origin.overlay_peer.clone(),
            user_agent: origin.user_agent.clone(),
            client: origin.client.clone(),
        }
    }

    /// Remember how the token with `fingerprint` was signed in for, until
    /// `expires_at` (Unix seconds).
    pub fn note_sign_in(&self, fingerprint: &str, credential: Credential, expires_at: u64) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let mut s = self.sign_ins.lock();
        s.retain(|_, (_, exp)| *exp > now);
        s.insert(fingerprint.to_string(), (credential, expires_at));
    }

    /// How the token with `fingerprint` was signed in for, if this process
    /// issued it.
    pub fn sign_in_credential(&self, fingerprint: &str) -> Option<Credential> {
        self.sign_ins.lock().get(fingerprint).map(|(c, _)| *c)
    }

    fn active_path(&self) -> PathBuf {
        self.dir.join(ACTIVE_SEGMENT)
    }

    /// Segments oldest first: the rotated ones by their last sequence
    /// number, then the active one.
    fn segments(&self) -> Result<Vec<PathBuf>, String> {
        let mut rotated: Vec<(u64, PathBuf)> = std::fs::read_dir(&self.dir)
            .map_err(|e| format!("{}: {e}", self.dir.display()))?
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                segment_seq(&name).map(|s| (s, e.path()))
            })
            .collect();
        rotated.sort();
        let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
        let active = self.active_path();
        if active.exists() {
            out.push(active);
        }
        Ok(out)
    }

    /// Set the head from the newest readable record on disk. Returns whether
    /// the last line could not be read.
    fn recover_head(&self) -> Result<bool, String> {
        let segments = self.segments()?;
        for path in segments.iter().rev() {
            let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let mut last: Option<Line> = None;
            let mut last_unreadable = false;
            for raw in std::io::BufReader::new(file).lines() {
                let raw = raw.map_err(|e| format!("{}: {e}", path.display()))?;
                if raw.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<Line>(&raw) {
                    Ok(line) => {
                        last = Some(line);
                        last_unreadable = false;
                    }
                    Err(_) => last_unreadable = true,
                }
            }
            if let Some(line) = last {
                let mut head = self.head.lock();
                head.next_seq = line.record.seq + 1;
                head.hash = line.hash;
                head.since_checkpoint = 0;
                return Ok(last_unreadable);
            }
            if last_unreadable {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Append one line to the active segment and sync it.
    fn write_line(&self, line: &Line) -> Result<(), String> {
        let mut text = serde_json::to_string(line).map_err(|e| format!("encode record: {e}"))?;
        text.push('\n');
        let path = self.active_path();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        // A line cut short by a crash is followed by a newline so the next
        // record starts on a line of its own.
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len > 0 {
            let mut tail = [0u8; 1];
            use std::io::{Read, Seek, SeekFrom};
            let mut reader =
                std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            reader
                .seek(SeekFrom::Start(len - 1))
                .and_then(|_| reader.read_exact(&mut tail))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            if tail[0] != b'\n' {
                text.insert(0, '\n');
            }
        }
        file.write_all(text.as_bytes())
            .and_then(|_| file.sync_data())
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Chain `entry` onto the head and write it.
    fn write_entry(&self, head: &mut Head, entry: Entry) -> Result<(u64, String), String> {
        let record = Record {
            seq: head.next_seq,
            prev: head.hash.clone(),
            at: now_rfc3339(),
            node: crate::identity_bootstrap::opened_machine_did(),
            chain_id: self.chain_id,
            entry,
        };
        let hash = record_hash(&record)?;
        let seq = record.seq;
        self.write_line(&Line {
            record,
            hash: hash.clone(),
        })?;
        head.next_seq = seq + 1;
        head.hash = hash.clone();
        head.since_checkpoint += 1;
        Ok((seq, hash))
    }

    /// Write a checkpoint over the head, signed by `signer` when given.
    fn write_checkpoint(
        &self,
        head: &mut Head,
        signer: Option<&dyn HybridSigner>,
    ) -> Result<(), String> {
        let covers_seq = head.next_seq.saturating_sub(1);
        let covers_hash = head.hash.clone();
        let node = crate::identity_bootstrap::opened_machine_did();
        let message = checkpoint_message(node.as_deref(), self.chain_id, covers_seq, &covers_hash);
        let (signer_key, signature) = match signer {
            Some(s) => match s.sign(SignatureContext::AdminAuditCheckpoint, &message) {
                Ok(sig) => (Some(s.public_key().clone()), Some(sig)),
                Err(e) => {
                    warn!(error = %e, "the identity key refused to sign an audit checkpoint");
                    (None, None)
                }
            },
            None => (None, None),
        };
        let signed = signature.is_some();
        let (seq, hash) = self.write_entry(
            head,
            Entry::Checkpoint(Checkpoint {
                covers_seq,
                covers_hash,
                signer: signer_key,
                signature,
            }),
        )?;
        head.since_checkpoint = 0;
        info!(target: "tenzro::admin_audit", seq, hash = %hash, covers_seq, signed, "audit checkpoint");
        Ok(())
    }

    /// Close the active segment when it has grown past the rotation size:
    /// checkpoint it and rename it after its last record.
    fn rotate_if_due(
        &self,
        head: &mut Head,
        signer: Option<&dyn HybridSigner>,
    ) -> Result<(), String> {
        let path = self.active_path();
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < self.rotate_bytes {
            return Ok(());
        }
        self.write_checkpoint(head, signer)?;
        let last = head.next_seq.saturating_sub(1);
        let to = self
            .dir
            .join(format!("{SEGMENT_PREFIX}{last:020}{SEGMENT_SUFFIX}"));
        std::fs::rename(&path, &to).map_err(|e| format!("rotate {}: {e}", path.display()))?;
        info!(target: "tenzro::admin_audit", segment = %to.display(), "audit segment closed");
        Ok(())
    }

    /// Append `entry` and, when due, a checkpoint signed by `signer`.
    /// Returns the entry's sequence number and hash.
    pub fn append(
        &self,
        entry: Entry,
        signer: Option<&dyn HybridSigner>,
    ) -> Result<(u64, String), String> {
        let mut head = self.head.lock();
        self.rotate_if_due(&mut head, signer)?;
        let written = self.write_entry(&mut head, entry)?;
        if head.since_checkpoint >= self.checkpoint_every {
            // The entry is on disk; a checkpoint that fails to write is
            // reported and retried after the next record.
            if let Err(e) = self.write_checkpoint(&mut head, signer) {
                error!(error = %e, "could not write an audit checkpoint");
            }
        }
        Ok(written)
    }

    fn count(&self, method: &str, outcome: &'static str) {
        *self
            .counters
            .lock()
            .entry((method.to_string(), outcome))
            .or_insert(0) += 1;
    }

    /// Record a call; logs it at INFO and counts it. A refusal is counted as
    /// `refused`.
    pub fn record_call(
        &self,
        call: Call,
        signer: Option<&dyn HybridSigner>,
    ) -> Result<u64, String> {
        let method = call.method.clone();
        let refused = matches!(call.decision, Decision::Refused { .. });
        let summary = (
            call.principal.did.clone().unwrap_or_else(|| "-".into()),
            call.principal.credential,
            call.principal.role.clone().unwrap_or_else(|| "-".into()),
            call.source.client_ip.clone().unwrap_or_else(|| "-".into()),
            call.source.transport,
            call.source
                .peer_identity
                .as_ref()
                .and_then(|p| p.machine.clone()),
            call.request_id.clone(),
        );
        let reason = match &call.decision {
            Decision::Refused { reason, .. } => Some(reason.clone()),
            Decision::Admitted => None,
        };
        let result = self.append(Entry::Call(call), signer);
        match &result {
            Ok((seq, hash)) => info!(
                target: "tenzro::admin_audit",
                seq,
                hash = %hash,
                method = %method,
                principal = %summary.0,
                credential = ?summary.1,
                role = %summary.2,
                client_ip = %summary.3,
                transport = ?summary.4,
                peer_machine = ?summary.5,
                request_id = %summary.6,
                refused = ?reason,
                "administrative call"
            ),
            Err(e) => error!(
                method = %method,
                principal = %summary.0,
                client_ip = %summary.3,
                error = %e,
                "could not record an administrative call"
            ),
        }
        if refused {
            self.count(&method, "refused");
        } else if result.is_err() {
            self.count(&method, "audit_failed");
        }
        result.map(|(seq, _)| seq)
    }

    /// Record how an admitted call ended, and count it.
    pub fn record_completion(&self, completion: Completion, signer: Option<&dyn HybridSigner>) {
        let method = completion.method.clone();
        let outcome = match completion.outcome {
            Outcome::Ok => "ok",
            Outcome::Error { .. } => "error",
        };
        self.count(&method, outcome);
        let request_id = completion.request_id.clone();
        match self.append(Entry::Completion(completion), signer) {
            Ok((seq, hash)) => info!(
                target: "tenzro::admin_audit",
                seq,
                hash = %hash,
                method = %method,
                request_id = %request_id,
                outcome,
                "administrative call finished"
            ),
            Err(e) => error!(
                method = %method,
                request_id = %request_id,
                error = %e,
                "could not record how an administrative call ended; its admission record stands"
            ),
        }
    }

    /// Every readable line of every segment, oldest first.
    fn read_all(&self) -> Result<Vec<Line>, String> {
        let mut out = Vec::new();
        for path in self.segments()? {
            let file =
                std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            for raw in std::io::BufReader::new(file).lines() {
                let raw = raw.map_err(|e| format!("{}: {e}", path.display()))?;
                if let Ok(line) = serde_json::from_str::<Line>(&raw) {
                    out.push(line);
                }
            }
        }
        Ok(out)
    }

    /// The records `filter` selects, oldest first.
    pub fn list(&self, filter: &Filter) -> Result<Vec<Line>, String> {
        let at_ms = |l: &Line| {
            chrono::DateTime::parse_from_rfc3339(&l.record.at)
                .map(|t| t.timestamp_millis())
                .unwrap_or(0)
        };
        let mut picked: Vec<Line> = self
            .read_all()?
            .into_iter()
            .filter(|l| {
                let (method, did) = match &l.record.entry {
                    Entry::Call(c) => (Some(c.method.as_str()), c.principal.did.as_deref()),
                    Entry::Completion(c) => (Some(c.method.as_str()), None),
                    Entry::SignIn(s) => (Some("tenzro_issueAccessToken"), Some(s.did.as_str())),
                    Entry::Checkpoint(_) | Entry::Opened(_) => (None, None),
                };
                filter.method.as_deref().is_none_or(|m| method == Some(m))
                    && filter.principal.as_deref().is_none_or(|p| did == Some(p))
                    && filter.since_ms.is_none_or(|s| at_ms(l) >= s)
                    && filter.until_ms.is_none_or(|u| at_ms(l) < u)
            })
            .collect();
        let limit = if filter.limit == 0 {
            DEFAULT_LIST
        } else {
            filter.limit.min(MAX_LIST)
        };
        if picked.len() > limit {
            picked.drain(..picked.len() - limit);
        }
        Ok(picked)
    }

    /// Check the whole log: every line reads, every hash matches its record,
    /// every record names the hash of the one before it with the next
    /// sequence number, every checkpoint covers a record in the chain and
    /// its signature verifies (under `identity`, this node's identity key,
    /// when given), and the log ends where this process last wrote.
    pub fn verify(&self, identity: Option<&CompositePublicKey>) -> Verification {
        let mut v = Verification::default();
        let segments = match self.segments() {
            Ok(s) => s,
            Err(e) => {
                v.problems.push(e);
                return v;
            }
        };
        let mut prev: Option<(u64, String)> = None;
        let mut hashes: HashMap<u64, String> = HashMap::new();
        for path in &segments {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            v.segments.push(name.clone());
            let file = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(e) => {
                    v.problems.push(format!("{name}: {e}"));
                    continue;
                }
            };
            for (n, raw) in std::io::BufReader::new(file).lines().enumerate() {
                let raw = match raw {
                    Ok(r) => r,
                    Err(e) => {
                        v.problems.push(format!("{name} line {}: {e}", n + 1));
                        continue;
                    }
                };
                if raw.trim().is_empty() {
                    continue;
                }
                let line: Line = match serde_json::from_str(&raw) {
                    Ok(l) => l,
                    Err(_) => {
                        v.problems
                            .push(format!("{name} line {} cannot be read as a record", n + 1));
                        continue;
                    }
                };
                let seq = line.record.seq;
                v.records += 1;
                match record_hash(&line.record) {
                    Ok(h) if h == line.hash => {}
                    _ => v.problems.push(format!(
                        "record {seq} does not match its hash: it was altered"
                    )),
                }
                match &prev {
                    None => {
                        v.first_seq = Some(seq);
                        if seq != 0 {
                            v.problems.push(format!(
                                "the log starts at record {seq}: records before it are not here"
                            ));
                        } else if line.record.prev != GENESIS_HASH {
                            v.problems
                                .push("record 0 does not start the chain".to_string());
                        }
                    }
                    Some((pseq, phash)) => {
                        if seq != pseq + 1 {
                            v.problems.push(if seq > pseq + 1 {
                                format!("records {} to {} are missing", pseq + 1, seq - 1)
                            } else {
                                format!("record {seq} follows record {pseq}: out of order")
                            });
                        } else if &line.record.prev != phash {
                            v.problems.push(format!(
                                "record {seq} does not follow record {pseq}: a record between \
                                 them was removed or altered"
                            ));
                        }
                    }
                }
                if let Entry::Checkpoint(cp) = &line.record.entry {
                    v.checkpoints += 1;
                    if hashes.get(&cp.covers_seq) != Some(&cp.covers_hash) {
                        v.problems.push(format!(
                            "checkpoint {seq} covers record {} as it is not in the log",
                            cp.covers_seq
                        ));
                    }
                    match (&cp.signer, &cp.signature) {
                        (Some(key), Some(sig)) => {
                            let message = checkpoint_message(
                                line.record.node.as_deref(),
                                line.record.chain_id,
                                cp.covers_seq,
                                &cp.covers_hash,
                            );
                            let verified = tenzro_crypto::composite::verify_composite(
                                key,
                                SignatureContext::AdminAuditCheckpoint,
                                &message,
                                sig,
                                PqPolicy::WhenPresent,
                            )
                            .is_ok();
                            if !verified {
                                v.problems
                                    .push(format!("checkpoint {seq}'s signature does not verify"));
                            } else if identity.is_some_and(|id| id != key) {
                                v.problems.push(format!(
                                    "checkpoint {seq} was signed by a key that is not this \
                                     node's identity key"
                                ));
                            } else {
                                v.signed_checkpoints += 1;
                            }
                        }
                        _ => v.unsigned_checkpoints += 1,
                    }
                }
                hashes.insert(seq, line.hash.clone());
                prev = Some((seq, line.hash));
            }
        }
        if let Some((seq, hash)) = &prev {
            v.last_seq = Some(*seq);
            v.head_hash = Some(hash.clone());
        }
        let head = self.head.lock();
        let written = head.next_seq.checked_sub(1);
        if written.is_some() && (written != v.last_seq || Some(&head.hash) != v.head_hash.as_ref())
        {
            v.problems.push(format!(
                "the log ends at record {} but this node wrote up to record {} ({}): records at \
                 the end were removed or replaced",
                v.last_seq.map_or("none".to_string(), |s| s.to_string()),
                written.unwrap_or_default(),
                head.hash
            ));
        }
        v.ok = v.problems.is_empty();
        v
    }

    /// The administrative-action counter in Prometheus text format.
    pub fn encode_prometheus(&self, out: &mut String) {
        out.push_str(
            "# HELP tenzro_admin_actions_total Administrative calls by method and outcome \
             (refused, ok, error, audit_failed)\n",
        );
        out.push_str("# TYPE tenzro_admin_actions_total counter\n");
        for ((method, outcome), n) in self.counters.lock().iter() {
            out.push_str(&format!(
                "tenzro_admin_actions_total{{method=\"{method}\",outcome=\"{outcome}\"}} {n}\n"
            ));
        }
        out.push('\n');
    }
}

// ---------------------------------------------------------------------------
// Principal
// ---------------------------------------------------------------------------

/// `operator` or `policy_admin` for a DID that administers `node`.
pub(crate) fn role_of(node: &TenzroNode, did: &str) -> Option<String> {
    if node.config().operator_did.as_deref() == Some(did) {
        Some("operator".to_string())
    } else if node.access().policy().admins.iter().any(|a| a == did) {
        Some("policy_admin".to_string())
    } else {
        None
    }
}

fn root_of(did: &str) -> Option<String> {
    tenzro_types::agent_terms::RootKind::of(did).map(|k| match k {
        tenzro_types::agent_terms::RootKind::Passkey => "passkey".to_string(),
        tenzro_types::agent_terms::RootKind::Machine => "machine".to_string(),
    })
}

/// The principal behind `claims`, the verified token a call carried, whose
/// `Authorization` value had `fingerprint`.
pub(crate) fn principal_of(
    node: &Arc<TenzroNode>,
    claims: Option<&tenzro_auth::AuthClaims>,
    fingerprint: Option<String>,
) -> Principal {
    let Some(claims) = claims else {
        return Principal {
            token: fingerprint.map(|f| TokenRef {
                fingerprint: f,
                jti: None,
                dpop_jkt: None,
                expires_at: None,
            }),
            ..Principal::default()
        };
    };
    let did = claims.sub.clone();
    let delegation = crate::agent_delegation::delegation_facts(node, &did).map(|d| Delegation {
        chain: claims
            .aap_delegation
            .as_ref()
            .map(|a| a.chain.clone())
            .unwrap_or_default(),
        ..d
    });
    let credential = fingerprint
        .as_deref()
        .and_then(|f| node.admin_audit().sign_in_credential(f))
        .unwrap_or(if delegation.is_some() {
            Credential::DelegatedAgentKey
        } else {
            Credential::AccessToken
        });
    Principal {
        root: root_of(&did),
        role: role_of(node, &did),
        credential,
        token: fingerprint.map(|f| TokenRef {
            fingerprint: f,
            jti: Some(claims.jti.clone()),
            dpop_jkt: claims.cnf.as_ref().map(|c| c.jkt.clone()),
            expires_at: Some(claims.exp),
        }),
        delegation,
        actor: None,
        did: Some(did),
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn answer(id: Value, code: i32, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code,
            message,
            data: None,
        }),
    }
}

/// The identity key checkpoints are signed with.
fn signer_of(node: &TenzroNode) -> Option<&dyn HybridSigner> {
    node.identity_signer().map(|s| s.as_ref())
}

/// Admit and run one call to a recorded method.
///
/// `claims` is the caller's verified access token as the transport resolved
/// it (or the error verifying it). The access policy and an agent's Terms
/// decide as they do for any call, then the network restriction; a refusal
/// is recorded and answered. An admitted call is recorded before it runs and
/// refused when that record cannot be written; its result is recorded after.
pub(crate) async fn run_audited(
    node: &Arc<TenzroNode>,
    surface: Surface,
    request: JsonRpcRequest,
    auth: &AuthContext,
    claims: Result<Option<tenzro_auth::AuthClaims>, JsonRpcError>,
) -> JsonRpcResponse {
    run_audited_with(
        node,
        surface,
        request,
        auth,
        claims,
        |request, did| async move {
            crate::rpc::handle_request(node, request, auth, did.as_deref()).await
        },
    )
    .await
}

/// [`run_audited`], running an admitted call with `dispatch` (the request and
/// the caller's DID).
async fn run_audited_with<F, Fut>(
    node: &Arc<TenzroNode>,
    surface: Surface,
    request: JsonRpcRequest,
    auth: &AuthContext,
    claims: Result<Option<tenzro_auth::AuthClaims>, JsonRpcError>,
    dispatch: F,
) -> JsonRpcResponse
where
    F: FnOnce(JsonRpcRequest, Option<String>) -> Fut,
    Fut: std::future::Future<Output = JsonRpcResponse>,
{
    let audit = node.admin_audit();
    let origin = current_origin();
    let started = std::time::Instant::now();
    let fingerprint = auth
        .authorization
        .as_deref()
        .and_then(token_fingerprint)
        .or_else(|| origin.token_fingerprint.clone());
    let source = audit.source_of(&origin).await;
    let mut call = Call {
        request_id: uuid::Uuid::new_v4().simple().to_string(),
        client_request_id: origin.client_request_id.clone(),
        jsonrpc_id: (!request.id.is_null()).then(|| clip(&request.id.to_string())),
        method: request.method.clone(),
        surface: Some(surface.as_str().to_string()),
        params: params_digest(request.params.as_ref()),
        principal: Principal::default(),
        source,
        decision: Decision::Admitted,
    };
    let refuse = |mut call: Call, error: JsonRpcError, id: Value| {
        call.decision = Decision::Refused {
            code: error.code,
            reason: clip(&error.message),
        };
        // A refusal stands whether or not its record is written.
        let _ = audit.record_call(call, signer_of(node));
        JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    };

    let claims = match claims {
        Ok(c) => c,
        Err(e) => {
            call.principal = principal_of(node, None, fingerprint);
            return refuse(call, e, request.id);
        }
    };
    call.principal = principal_of(node, claims.as_ref(), fingerprint);
    let caller = crate::access::Caller {
        did: claims.as_ref().map(|c| c.sub.clone()),
        ip: None,
    };
    let caller = match crate::access::admit(
        node,
        surface,
        &request.method,
        request.params.as_ref(),
        caller,
    ) {
        Ok(c) => c,
        Err(e) => return refuse(call, e, request.id),
    };
    if let Some(e) =
        crate::rpc::inference_admission_refusal(node, surface, &request, caller.did.as_deref())
    {
        return refuse(call, e, request.id);
    }
    if let Some(why) = audit.source_refusal(&origin) {
        return refuse(
            call,
            JsonRpcError {
                code: -32004,
                message: why,
                data: None,
            },
            request.id,
        );
    }

    let request_id = call.request_id.clone();
    let method = request.method.clone();
    let call_seq = match audit.record_call(call, signer_of(node)) {
        Ok(seq) => seq,
        Err(_) => {
            return answer(
                request.id,
                AUDIT_UNAVAILABLE,
                "this node cannot write its administrative audit log, so it refuses \
                 administrative calls until it can"
                    .to_string(),
            );
        }
    };
    let response = dispatch(request, caller.did).await;
    audit.record_completion(
        Completion {
            request_id,
            call_seq,
            method,
            outcome: match &response.error {
                None => Outcome::Ok,
                Some(e) => Outcome::Error { code: e.code },
            },
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        signer_of(node),
    );
    response
}

/// Record a privileged action `actor`, a component of the node, is about to
/// take: `method` with `params`. Returns what [`record_node_completion`]
/// needs, or the error writing the record, in which case the action must not
/// be taken.
pub(crate) fn record_node_action(
    node: &TenzroNode,
    actor: &str,
    method: &str,
    params: &Value,
) -> Result<(String, u64), String> {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let seq = node.admin_audit().record_call(
        Call {
            request_id: request_id.clone(),
            client_request_id: None,
            jsonrpc_id: None,
            method: method.to_string(),
            surface: None,
            params: params_digest(Some(params)),
            principal: Principal {
                did: crate::identity_bootstrap::opened_machine_did(),
                root: Some("machine".to_string()),
                credential: Credential::Node,
                actor: Some(actor.to_string()),
                ..Principal::default()
            },
            source: Source {
                transport: Transport::Node,
                ..Source::default()
            },
            decision: Decision::Admitted,
        },
        signer_of(node),
    )?;
    Ok((request_id, seq))
}

/// Record how an action [`record_node_action`] recorded ended.
pub(crate) fn record_node_completion(
    node: &TenzroNode,
    (request_id, call_seq): (String, u64),
    method: &str,
    result: &Result<Value, JsonRpcError>,
    started: std::time::Instant,
) {
    node.admin_audit().record_completion(
        Completion {
            request_id,
            call_seq,
            method: method.to_string(),
            outcome: match result {
                Ok(_) => Outcome::Ok,
                Err(e) => Outcome::Error { code: e.code },
            },
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        signer_of(node),
    );
}

/// Record an administrator's sign-in: `did` received `token`, signed in
/// with `credential`, expiring at `expires_at` (Unix seconds). Every sign-in
/// is remembered so later calls with the token name the credential; one by
/// a DID that administers this node is also written to the log, and when
/// that cannot be written the sign-in is refused.
pub(crate) async fn record_sign_in(
    node: &Arc<TenzroNode>,
    did: &str,
    token: &str,
    dpop_jkt: &str,
    credential: Credential,
    expires_at: u64,
) -> Result<(), JsonRpcError> {
    let audit = node.admin_audit();
    let Some(fingerprint) = token_fingerprint(token) else {
        return Ok(());
    };
    audit.note_sign_in(&fingerprint, credential, expires_at);
    let Some(role) = role_of(node, did) else {
        return Ok(());
    };
    let source = audit.source_of(&current_origin()).await;
    audit
        .append(
            Entry::SignIn(SignIn {
                did: did.to_string(),
                role: Some(role.clone()),
                credential,
                token: TokenRef {
                    fingerprint,
                    jti: None,
                    dpop_jkt: Some(dpop_jkt.to_string()),
                    expires_at: Some(expires_at),
                },
                source: source.clone(),
            }),
            signer_of(node),
        )
        .map(|(seq, hash)| {
            info!(
                target: "tenzro::admin_audit",
                seq,
                hash = %hash,
                did,
                role = %role,
                credential = ?credential,
                client_ip = %source.client_ip.as_deref().unwrap_or("-"),
                transport = ?source.transport,
                "administrator signed in"
            );
        })
        .map_err(|e| {
            error!(did, error = %e, "could not record an administrator's sign-in");
            JsonRpcError {
                code: AUDIT_UNAVAILABLE,
                message: "this node cannot write its administrative audit log, so it does not \
                          sign administrators in until it can"
                    .to_string(),
                data: None,
            }
        })
}

// ---------------------------------------------------------------------------
// RPC
// ---------------------------------------------------------------------------

fn time_param(v: Option<&Value>) -> Result<Option<i64>, JsonRpcError> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => Ok(n.as_i64()),
        Some(Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| Some(t.timestamp_millis()))
            .map_err(|_| JsonRpcError {
                code: -32602,
                message: format!("{s} is not an RFC 3339 time or Unix milliseconds"),
                data: None,
            }),
        Some(_) => Err(JsonRpcError {
            code: -32602,
            message: "a time is an RFC 3339 string or Unix milliseconds".to_string(),
            data: None,
        }),
    }
}

fn first_param(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(mut a)) if !a.is_empty() => a.swap_remove(0),
        Some(v @ Value::Object(_)) => v,
        _ => json!({}),
    }
}

/// `tenzro_listAdminAudit { method?, principal?, since?, until?, limit? }`:
/// the most recent records the filter selects, oldest first. Times are RFC
/// 3339 or Unix milliseconds; `limit` defaults to 100, at most 1000.
pub(crate) async fn handle_list(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = first_param(params);
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::to_string);
    let filter = Filter {
        method: text("method"),
        principal: text("principal"),
        since_ms: time_param(p.get("since"))?,
        until_ms: time_param(p.get("until"))?,
        limit: p.get("limit").and_then(Value::as_u64).unwrap_or(0) as usize,
    };
    let records = node.admin_audit().list(&filter).map_err(|e| JsonRpcError {
        code: -32603,
        message: e,
        data: None,
    })?;
    Ok(json!({ "count": records.len(), "records": records }))
}

/// `tenzro_verifyAdminAudit`: check the chain, the checkpoints (against this
/// node's identity key) and that the log ends where the node last wrote.
pub(crate) async fn handle_verify(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let identity = node.identity_signer().map(|s| s.public_key().clone());
    serde_json::to_value(node.admin_audit().verify(identity.as_ref())).map_err(|e| JsonRpcError {
        code: -32603,
        message: e.to_string(),
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn open(dir: &Path, cfg: &AdminConfig) -> AdminAudit {
        AdminAudit::open(dir, cfg, 1337).expect("open audit log")
    }

    fn cfg() -> AdminConfig {
        AdminConfig {
            peer_identity: None,
            ..AdminConfig::default()
        }
    }

    fn call(method: &str, did: &str) -> Call {
        Call {
            request_id: "r".into(),
            client_request_id: None,
            jsonrpc_id: Some("1".into()),
            method: method.into(),
            surface: Some("rpc".into()),
            params: params_digest(Some(&json!({ "model_id": "m" }))),
            principal: Principal {
                did: Some(did.into()),
                credential: Credential::HardwareKey,
                ..Principal::default()
            },
            source: Source {
                transport: Transport::Http,
                client_ip: Some("127.0.0.1".into()),
                ..Source::default()
            },
            decision: Decision::Admitted,
        }
    }

    fn lines(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join(AUDIT_DIR).join(ACTIVE_SEGMENT))
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn rewrite(dir: &Path, lines: &[String]) {
        std::fs::write(
            dir.join(AUDIT_DIR).join(ACTIVE_SEGMENT),
            lines.join("\n") + "\n",
        )
        .unwrap();
    }

    #[test]
    fn a_whole_log_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        for i in 0..5 {
            audit
                .record_call(call("tenzro_stopModel", &format!("did:{i}")), None)
                .unwrap();
        }
        let v = audit.verify(None);
        assert!(v.ok, "{:?}", v.problems);
        assert_eq!(v.records, 6);
        assert_eq!(v.first_seq, Some(0));
        assert_eq!(v.last_seq, Some(5));
    }

    #[test]
    fn an_edited_record_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        audit
            .record_call(call("tenzro_stopModel", "did:a"), None)
            .unwrap();
        audit
            .record_call(call("tenzro_serveModel", "did:a"), None)
            .unwrap();
        let mut l = lines(dir.path());
        l[1] = l[1].replace("did:a", "did:b");
        rewrite(dir.path(), &l);
        let v = audit.verify(None);
        assert!(!v.ok);
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("record 1") && p.contains("altered")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn an_edit_that_rehashes_its_record_still_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        audit
            .record_call(call("tenzro_stopModel", "did:a"), None)
            .unwrap();
        audit
            .record_call(call("tenzro_serveModel", "did:a"), None)
            .unwrap();
        let mut l = lines(dir.path());
        let mut line: Line = serde_json::from_str(&l[1]).unwrap();
        if let Entry::Call(c) = &mut line.record.entry {
            c.principal.did = Some("did:b".into());
        }
        line.hash = record_hash(&line.record).unwrap();
        l[1] = serde_json::to_string(&line).unwrap();
        rewrite(dir.path(), &l);
        let v = audit.verify(None);
        assert!(!v.ok);
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("does not follow record 1")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn a_deleted_record_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        for _ in 0..3 {
            audit
                .record_call(call("tenzro_stopModel", "did:a"), None)
                .unwrap();
        }
        let mut l = lines(dir.path());
        l.remove(2);
        rewrite(dir.path(), &l);
        let v = audit.verify(None);
        assert!(!v.ok);
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("records 2 to 2 are missing")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn records_removed_from_the_end_are_detected() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        for _ in 0..3 {
            audit
                .record_call(call("tenzro_stopModel", "did:a"), None)
                .unwrap();
        }
        let mut l = lines(dir.path());
        l.pop();
        rewrite(dir.path(), &l);
        let v = audit.verify(None);
        assert!(!v.ok);
        assert!(
            v.problems.iter().any(|p| p.contains("records at the end")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn a_signed_checkpoint_verifies_and_a_forged_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let config = AdminConfig {
            audit_checkpoint_every: 2,
            ..cfg()
        };
        let audit = open(dir.path(), &config);
        let signer = TestHybridSigner::hybrid(3);
        for _ in 0..4 {
            audit
                .record_call(
                    call("tenzro_stopModel", "did:a"),
                    Some(&signer as &dyn HybridSigner),
                )
                .unwrap();
        }
        let v = audit.verify(Some(HybridSigner::public_key(&signer)));
        assert!(v.ok, "{:?}", v.problems);
        assert!(v.signed_checkpoints >= 2, "{v:?}");
        assert_eq!(v.unsigned_checkpoints, 0);

        // The same log checked against another node's key.
        let other = TestHybridSigner::p256_only(4);
        let v = audit.verify(Some(HybridSigner::public_key(&other)));
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("not this node's identity key")),
            "{:?}",
            v.problems
        );

        // A checkpoint whose covered hash is changed and re-hashed no longer
        // verifies.
        let mut l = lines(dir.path());
        let at = l
            .iter()
            .position(|s| s.contains("\"kind\":\"checkpoint\""))
            .unwrap();
        let mut line: Line = serde_json::from_str(&l[at]).unwrap();
        if let Entry::Checkpoint(cp) = &mut line.record.entry {
            cp.covers_hash = GENESIS_HASH.to_string();
        }
        line.hash = record_hash(&line.record).unwrap();
        l[at] = serde_json::to_string(&line).unwrap();
        rewrite(dir.path(), &l);
        let v = audit.verify(Some(HybridSigner::public_key(&signer)));
        assert!(
            v.problems
                .iter()
                .any(|p| p.contains("signature does not verify")),
            "{:?}",
            v.problems
        );
    }

    #[test]
    fn the_chain_continues_across_a_restart_and_a_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let config = AdminConfig {
            audit_rotate_bytes: 4096,
            ..cfg()
        };
        {
            let audit = open(dir.path(), &config);
            for _ in 0..20 {
                audit
                    .record_call(call("tenzro_stopModel", "did:a"), None)
                    .unwrap();
            }
        }
        let audit = open(dir.path(), &config);
        audit
            .record_call(call("tenzro_stopModel", "did:a"), None)
            .unwrap();
        let v = audit.verify(None);
        assert!(v.ok, "{:?}", v.problems);
        assert!(v.segments.len() > 1, "{:?}", v.segments);
        assert_eq!(v.first_seq, Some(0));
    }

    #[test]
    fn a_line_cut_short_is_reported_and_the_chain_continues() {
        let dir = tempfile::tempdir().unwrap();
        {
            let audit = open(dir.path(), &cfg());
            audit
                .record_call(call("tenzro_stopModel", "did:a"), None)
                .unwrap();
        }
        let path = dir.path().join(AUDIT_DIR).join(ACTIVE_SEGMENT);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"{\"record\":{\"seq\":2").unwrap();
        drop(f);
        let audit = open(dir.path(), &cfg());
        audit
            .record_call(call("tenzro_stopModel", "did:a"), None)
            .unwrap();
        let v = audit.verify(None);
        assert_eq!(v.problems.len(), 1, "{:?}", v.problems);
        assert!(v.problems[0].contains("cannot be read"));
        assert_eq!(v.last_seq, Some(3));
    }

    #[test]
    fn a_write_failure_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let audit = open(dir.path(), &cfg());
        let path = dir.path().join(AUDIT_DIR).join(ACTIVE_SEGMENT);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(
            audit
                .record_call(call("tenzro_stopModel", "did:a"), None)
                .is_err()
        );
        let mut prom = String::new();
        audit.encode_prometheus(&mut prom);
        assert!(prom.contains(
            "tenzro_admin_actions_total{method=\"tenzro_stopModel\",outcome=\"audit_failed\"} 1"
        ));
    }

    #[test]
    fn only_key_fields_are_kept_from_params() {
        let d = params_digest(Some(&json!([{
            "model_id": "gemma",
            "private_key": "secret",
            "password": "secret",
            "visibility": "public",
            "nested": { "model_id": "x" }
        }])));
        assert_eq!(d.fields.get("model_id").map(String::as_str), Some("gemma"));
        assert_eq!(
            d.fields.get("visibility").map(String::as_str),
            Some("public")
        );
        assert_eq!(d.fields.len(), 2);
        assert_eq!(d.sha256.len(), 64);
    }

    #[test]
    fn a_fingerprint_never_contains_the_token() {
        let token = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJkaWQ6dGVuenJvOmh1bWFuOmEifQ.c2ln";
        let f = token_fingerprint(&format!("DPoP {token}")).unwrap();
        assert_eq!(f.len(), 32);
        assert_eq!(Some(f.clone()), token_fingerprint(token));
        assert!(!token.contains(&f) && !f.contains("eyJ"));
    }

    #[test]
    fn audit_skip_must_name_an_admin_method() {
        let dir = tempfile::tempdir().unwrap();
        let bad = AdminConfig {
            audit_skip: vec!["tenzro_blockNumber".into()],
            ..cfg()
        };
        assert!(AdminAudit::open(dir.path(), &bad, 1).is_err());
        let ok = AdminConfig {
            audit_skip: vec!["tenzro_gossipStats".into()],
            audit_also: vec!["tenzro_blockNumber".into()],
            ..cfg()
        };
        let audit = AdminAudit::open(dir.path(), &ok, 1).unwrap();
        assert!(!audit.audits("tenzro_gossipStats"));
        assert!(audit.audits("tenzro_blockNumber"));
        assert!(audit.audits("tenzro_stopModel"));
        assert!(!audit.audits("tenzro_getBalance"));
    }

    // ---- Through the gate ----------------------------------------------

    const OPERATOR: &str = "did:tenzro:human:operator";
    const TOKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJvcGVyYXRvciJ9.c2lnbmF0dXJl";

    async fn node_with(admin: AdminConfig) -> (Arc<TenzroNode>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let config = crate::config::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            operator_did: Some(OPERATOR.to_string()),
            admin,
            ..crate::config::NodeConfig::default()
        };
        (Arc::new(TenzroNode::new(config).await.unwrap()), tmp)
    }

    fn claims(did: &str) -> tenzro_auth::AuthClaims {
        tenzro_auth::AuthClaims {
            sub: did.to_string(),
            iss: "node".into(),
            aud: "rpc".into(),
            iat: 0,
            nbf: 0,
            exp: 4_000_000_000,
            jti: "jti-1".into(),
            cnf: Some(tenzro_auth::Cnf {
                jkt: "dpop-thumbprint".into(),
            }),
            controller_did: did.to_string(),
            authorization_details: tenzro_auth::AuthorizationDetails::empty(),
            aap_agent: None,
            aap_task: None,
            aap_capabilities: None,
            aap_delegation: None,
            aap_context: None,
            aap_audit: None,
        }
    }

    fn auth() -> AuthContext {
        AuthContext {
            authorization: Some(format!("DPoP {TOKEN}")),
            dpop: None,
            http_method: "POST".into(),
            http_uri: "http://127.0.0.1:8545/".into(),
        }
    }

    fn request(method: &str) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params: Some(json!({ "model_id": "gemma-3", "secret": "do-not-log" })),
            id: json!(7),
        }
    }

    fn from_cli() -> Origin {
        Origin {
            transport: Transport::Http,
            peer: Some("127.0.0.1:53000".parse().unwrap()),
            client_ip: Some("127.0.0.1".parse().unwrap()),
            user_agent: Some("tenzro-cli/0.4.0".into()),
            client_request_id: Some("req-42".into()),
            ..Origin::default()
        }
    }

    fn ok(id: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id,
            result: Some(json!(true)),
            error: None,
        }
    }

    /// Run `method` through the audited gate as `who`, from `origin`, with a
    /// dispatcher that only notes it ran.
    async fn gated(
        node: &Arc<TenzroNode>,
        method: &str,
        who: Result<Option<tenzro_auth::AuthClaims>, JsonRpcError>,
        origin: Origin,
        ran: &std::sync::atomic::AtomicBool,
    ) -> JsonRpcResponse {
        with_origin(
            origin,
            run_audited_with(node, Surface::Rpc, request(method), &auth(), who, |r, _| {
                ran.store(true, std::sync::atomic::Ordering::SeqCst);
                async move { ok(r.id) }
            }),
        )
        .await
    }

    fn calls(node: &TenzroNode, method: &str) -> Vec<Call> {
        node.admin_audit()
            .list(&Filter {
                method: Some(method.into()),
                limit: MAX_LIST,
                ..Filter::default()
            })
            .unwrap()
            .into_iter()
            .filter_map(|l| match l.record.entry {
                Entry::Call(c) => Some(c),
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn every_admin_method_writes_one_record_naming_the_caller_and_source() {
        let (node, _tmp) = node_with(cfg()).await;
        let ran = std::sync::atomic::AtomicBool::new(false);
        for method in crate::rpc_gates::ADMIN_METHODS {
            assert!(node.admin_audit().audits(method), "{method}");
            let r = gated(&node, method, Ok(Some(claims(OPERATOR))), from_cli(), &ran).await;
            assert!(
                r.error.is_none(),
                "{method}: {:?}",
                r.error.map(|e| e.message)
            );
            let c = calls(&node, method);
            assert_eq!(c.len(), 1, "{method}");
            let c = &c[0];
            assert_eq!(c.decision, Decision::Admitted);
            assert_eq!(c.principal.did.as_deref(), Some(OPERATOR));
            assert_eq!(c.principal.role.as_deref(), Some("operator"));
            assert_eq!(c.principal.root.as_deref(), Some("passkey"));
            assert_eq!(c.source.client_ip.as_deref(), Some("127.0.0.1"));
            assert_eq!(c.source.peer.as_deref(), Some("127.0.0.1:53000"));
            assert_eq!(c.source.transport, Transport::Http);
            assert_eq!(c.source.user_agent.as_deref(), Some("tenzro-cli/0.4.0"));
            assert_eq!(c.client_request_id.as_deref(), Some("req-42"));
            assert_eq!(
                c.params.fields.get("model_id").map(String::as_str),
                Some("gemma-3")
            );
            assert!(!c.params.fields.contains_key("secret"));
            let done: Vec<Completion> = node
                .admin_audit()
                .list(&Filter {
                    method: Some((*method).into()),
                    ..Filter::default()
                })
                .unwrap()
                .into_iter()
                .filter_map(|l| match l.record.entry {
                    Entry::Completion(d) => Some(d),
                    _ => None,
                })
                .collect();
            assert_eq!(done.len(), 1, "{method}");
            assert_eq!(done[0].request_id, c.request_id);
            assert_eq!(done[0].outcome, Outcome::Ok);
        }
        assert!(node.admin_audit().verify(None).ok);
    }

    #[tokio::test]
    async fn a_refused_call_is_recorded_as_refused_and_does_not_run() {
        let (node, _tmp) = node_with(cfg()).await;
        let ran = std::sync::atomic::AtomicBool::new(false);
        let r = gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims("did:tenzro:human:stranger"))),
            from_cli(),
            &ran,
        )
        .await;
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(-32004));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        let c = calls(&node, "tenzro_stopModel");
        assert_eq!(c.len(), 1);
        assert!(matches!(
            &c[0].decision,
            Decision::Refused { code: -32004, .. }
        ));
        assert_eq!(
            c[0].principal.did.as_deref(),
            Some("did:tenzro:human:stranger")
        );
        assert_eq!(c[0].principal.role, None);

        // A token that does not verify is refused with no principal, and
        // still named by its fingerprint.
        let r = gated(
            &node,
            "tenzro_stopModel",
            Err(JsonRpcError {
                code: -32001,
                message: "JWT validation failed".into(),
                data: None,
            }),
            from_cli(),
            &ran,
        )
        .await;
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(-32001));
        let c = calls(&node, "tenzro_stopModel");
        assert_eq!(c.len(), 2);
        assert_eq!(c[1].principal.did, None);
        assert_eq!(
            c[1].principal.token.as_ref().map(|t| t.fingerprint.clone()),
            token_fingerprint(TOKEN)
        );
        let mut prom = String::new();
        node.admin_audit().encode_prometheus(&mut prom);
        assert!(prom.contains(
            "tenzro_admin_actions_total{method=\"tenzro_stopModel\",outcome=\"refused\"} 2"
        ));
    }

    #[tokio::test]
    async fn a_token_is_recorded_by_fingerprint_and_never_itself() {
        let (node, tmp) = node_with(cfg()).await;
        let ran = std::sync::atomic::AtomicBool::new(false);
        node.admin_audit().note_sign_in(
            &token_fingerprint(TOKEN).unwrap(),
            Credential::Passkey,
            4_000_000_000,
        );
        gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims(OPERATOR))),
            from_cli(),
            &ran,
        )
        .await;
        let c = calls(&node, "tenzro_stopModel");
        let token = c[0].principal.token.clone().unwrap();
        assert_eq!(Some(token.fingerprint), token_fingerprint(TOKEN));
        assert_eq!(token.jti.as_deref(), Some("jti-1"));
        assert_eq!(token.dpop_jkt.as_deref(), Some("dpop-thumbprint"));
        assert_eq!(c[0].principal.credential, Credential::Passkey);
        let on_disk =
            std::fs::read_to_string(tmp.path().join(AUDIT_DIR).join(ACTIVE_SEGMENT)).unwrap();
        assert!(!on_disk.contains(TOKEN));
        assert!(!on_disk.contains("eyJzdWIiOiJvcGVyYXRvciJ9"));
        assert!(!on_disk.contains("do-not-log"));
    }

    #[tokio::test]
    async fn a_forged_forwarding_header_from_an_untrusted_peer_is_ignored() {
        let (node, _tmp) = node_with(cfg()).await;
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "10.9.8.7".parse().unwrap());
        let peer: SocketAddr = "203.0.113.5:4100".parse().unwrap();
        let origin = Origin::http(node.http_surface(), Transport::Http, Some(peer), &headers);
        assert_eq!(origin.client_ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(origin.forwarded_for, None);
        let ran = std::sync::atomic::AtomicBool::new(false);
        gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims(OPERATOR))),
            origin,
            &ran,
        )
        .await;
        let c = calls(&node, "tenzro_stopModel");
        assert_eq!(c[0].source.client_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(c[0].source.forwarded_for, None);

        // Behind a configured proxy the chain is kept and the client is the
        // first hop the proxy did not add.
        let config = crate::config::NodeConfig {
            http_surface: crate::http_surface::HttpSurfaceConfig {
                trusted_proxies: vec!["203.0.113.5".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let behind = crate::http_surface::SurfacePolicy::from_config(&config, None).unwrap();
        let origin = Origin::http(&behind, Transport::Http, Some(peer), &headers);
        assert_eq!(origin.client_ip, Some("10.9.8.7".parse().unwrap()));
        assert_eq!(
            origin.forwarded_for,
            Some(vec!["10.9.8.7".parse().unwrap()])
        );
    }

    #[tokio::test]
    async fn an_admin_call_whose_record_cannot_be_written_is_refused() {
        let (node, tmp) = node_with(cfg()).await;
        let path = tmp.path().join(AUDIT_DIR).join(ACTIVE_SEGMENT);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let ran = std::sync::atomic::AtomicBool::new(false);
        let r = gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims(OPERATOR))),
            from_cli(),
            &ran,
        )
        .await;
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(AUDIT_UNAVAILABLE));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn the_network_restriction_refuses_and_records_a_call_from_elsewhere() {
        let (node, _tmp) = node_with(AdminConfig {
            networks: vec!["127.0.0.0/8".into()],
            ..cfg()
        })
        .await;
        let ran = std::sync::atomic::AtomicBool::new(false);
        let away = Origin {
            transport: Transport::Http,
            client_ip: Some("198.51.100.20".parse().unwrap()),
            ..Origin::default()
        };
        let r = gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims(OPERATOR))),
            away,
            &ran,
        )
        .await;
        assert_eq!(r.error.as_ref().map(|e| e.code), Some(-32004));
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        let r = gated(
            &node,
            "tenzro_stopModel",
            Ok(Some(claims(OPERATOR))),
            from_cli(),
            &ran,
        )
        .await;
        assert!(r.error.is_none());
        let c = calls(&node, "tenzro_stopModel");
        assert!(matches!(c[0].decision, Decision::Refused { .. }));
        assert_eq!(c[1].decision, Decision::Admitted);
    }

    #[test]
    fn the_network_restriction_admits_listed_networks_only() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AdminAudit::open(
            dir.path(),
            &AdminConfig {
                networks: vec!["127.0.0.1/32".into(), "10.0.0.0/8".into()],
                ..cfg()
            },
            1,
        )
        .unwrap();
        let from = |ip: &str| Origin {
            transport: Transport::Http,
            client_ip: Some(ip.parse().unwrap()),
            ..Origin::default()
        };
        assert!(audit.source_refusal(&from("127.0.0.1")).is_none());
        assert!(audit.source_refusal(&from("10.20.30.40")).is_none());
        assert!(audit.source_refusal(&from("203.0.113.7")).is_some());
        assert!(
            audit
                .source_refusal(&Origin::overlay("peer".into()))
                .is_some()
        );
        assert!(audit.source_refusal(&Origin::default()).is_none());
    }

    /// A local identity service on a Unix socket that answers every request
    /// with `status` and `body`, and hands back each request it read.
    #[cfg(unix)]
    fn identity_service(
        dir: &Path,
        status: &'static str,
        body: &'static str,
    ) -> (PathBuf, tokio::sync::mpsc::UnboundedReceiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let socket = dir.join("identity.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = tx.send(String::from_utf8_lossy(&buf).into_owned());
                let answer =
                    format!("HTTP/1.0 {status}\r\nContent-Type: application/json\r\n\r\n{body}");
                let _ = stream.write_all(answer.as_bytes()).await;
            }
        });
        (socket, rx)
    }

    fn identity_cfg(socket: PathBuf) -> PeerIdentityConfig {
        PeerIdentityConfig {
            socket,
            request: default_identity_request(),
            host: default_identity_host(),
            machine_field: default_identity_machine_field(),
            login_field: default_identity_login_field(),
            networks: Vec::new(),
        }
    }

    fn from_peer(peer: &str) -> Origin {
        let peer: SocketAddr = peer.parse().unwrap();
        Origin {
            transport: Transport::Http,
            peer: Some(peer),
            client_ip: Some(peer.ip()),
            ..Origin::default()
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_source_names_the_machine_and_login_the_identity_service_reports() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, mut asked) = identity_service(
            dir.path(),
            "200 OK",
            r#"{"machine":"ops-laptop","login":"operator@example.com"}"#,
        );
        let audit = open(
            dir.path(),
            &AdminConfig {
                peer_identity: Some(identity_cfg(socket)),
                ..cfg()
            },
        );
        let source = audit.source_of(&from_peer("10.1.2.3:41000")).await;
        assert_eq!(
            source.peer_identity,
            Some(PeerIdentity {
                machine: Some("ops-laptop".into()),
                login: Some("operator@example.com".into()),
            })
        );
        let request = asked.recv().await.unwrap();
        assert!(request.starts_with("GET /whois?addr=10.1.2.3:41000 HTTP/1.0\r\n"));
        assert!(request.contains("\r\nHost: localhost\r\n"));

        // A loopback client is not asked about.
        let local = audit.source_of(&from_peer("127.0.0.1:41000")).await;
        assert_eq!(local.peer_identity, None);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_request_host_and_fields_follow_the_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, mut asked) = identity_service(
            dir.path(),
            "200 OK",
            r#"{"Peer":{"Name":"build-7"},"Owner":{"Email":"ops@example.com"}}"#,
        );
        let audit = open(
            dir.path(),
            &AdminConfig {
                peer_identity: Some(PeerIdentityConfig {
                    request: "/v1/peer?ip={addr}".into(),
                    host: "identity.local".into(),
                    machine_field: "/Peer/Name".into(),
                    login_field: "/Owner/Email".into(),
                    networks: vec!["10.0.0.0/8".into()],
                    ..identity_cfg(socket)
                }),
                ..cfg()
            },
        );
        let source = audit.source_of(&from_peer("10.9.9.9:5000")).await;
        assert_eq!(
            source.peer_identity,
            Some(PeerIdentity {
                machine: Some("build-7".into()),
                login: Some("ops@example.com".into()),
            })
        );
        let request = asked.recv().await.unwrap();
        assert!(request.starts_with("GET /v1/peer?ip=10.9.9.9:5000 HTTP/1.0\r\n"));
        assert!(request.contains("\r\nHost: identity.local\r\n"));

        // Outside the configured networks the service is not asked.
        let away = audit.source_of(&from_peer("198.51.100.4:5000")).await;
        assert_eq!(away.peer_identity, None);
        assert!(asked.try_recv().is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_identity_service_that_refuses_or_is_absent_records_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _asked) = identity_service(dir.path(), "404 Not Found", "{}");
        let audit = open(
            dir.path(),
            &AdminConfig {
                peer_identity: Some(identity_cfg(socket)),
                ..cfg()
            },
        );
        let source = audit.source_of(&from_peer("10.1.2.3:41000")).await;
        assert_eq!(source.peer_identity, None);
        assert_eq!(source.client_ip.as_deref(), Some("10.1.2.3"));

        let gone = tempfile::tempdir().unwrap();
        let audit = open(
            gone.path(),
            &AdminConfig {
                peer_identity: Some(identity_cfg(gone.path().join("missing.sock"))),
                ..cfg()
            },
        );
        let source = audit.source_of(&from_peer("10.1.2.3:41000")).await;
        assert_eq!(source.peer_identity, None);
    }

    #[test]
    fn a_malformed_identity_service_configuration_is_refused_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("identity.sock");
        for bad in [
            PeerIdentityConfig {
                request: "/whois".into(),
                ..identity_cfg(socket.clone())
            },
            PeerIdentityConfig {
                host: "a\r\nX-Injected: 1".into(),
                ..identity_cfg(socket.clone())
            },
            PeerIdentityConfig {
                machine_field: "machine".into(),
                ..identity_cfg(socket.clone())
            },
            PeerIdentityConfig {
                networks: vec!["not-a-network".into()],
                ..identity_cfg(socket.clone())
            },
        ] {
            let r = AdminAudit::open(
                dir.path(),
                &AdminConfig {
                    peer_identity: Some(bad.clone()),
                    ..cfg()
                },
                1,
            );
            assert!(r.is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn the_identity_service_is_configured_under_admin() {
        let cfg: AdminConfig = toml::from_str(
            r#"
            [peer_identity]
            socket = "/run/identity.sock"
            networks = ["10.0.0.0/8"]
            "#,
        )
        .unwrap();
        let p = cfg.peer_identity.unwrap();
        assert_eq!(p.socket, PathBuf::from("/run/identity.sock"));
        assert_eq!(p.request, "/whois?addr={addr}");
        assert_eq!(p.machine_field, "/machine");
        assert!(
            toml::from_str::<AdminConfig>("[peer_identity]\nsocket = \"/s\"\nport = 1\n").is_err()
        );
    }
}
