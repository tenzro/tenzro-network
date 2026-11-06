//! Delegated TPM: a machine with no TPM signs through a machine that has one.
//!
//! Provider side ([`serve`]): `tenzro-node tpm serve --config <file>` runs on
//! a machine with a TPM. It signs, with a key that never leaves that TPM, for
//! the clients the file enrols, under the key label enrolled for each, for
//! messages that begin with an allowed domain prefix, within a per-minute
//! limit; every request is logged. Its own transport key is derived from its
//! TPM and never written anywhere.
//!
//! A client is enrolled by the operator's passkey, not by a transport key: the
//! file names the passkey's public key, its relying party and the key label.
//! Every request carries a [`TransportGrant`]: a WebAuthn assertion, made with
//! user verification by that passkey, naming the transport endpoint the
//! request arrives from, the key label and the time the grant ends. The
//! provider refuses a request with no grant, an expired grant, a grant longer
//! than it allows, a grant for another endpoint or label, or one no enrolled
//! passkey signed.
//!
//! Client side ([`RemoteConfig`], [`install`], [`open`]): the TPM-less machine
//! holds no signing key and no transport key. A separate key holder
//! (`tenzro-node tpm key-holder`, see [`crate::tpm_key_holder`]) makes the
//! transport key at its own start, keeps it in locked memory only, holds the
//! grant, and carries the node's requests to the provider over a local socket.
//! The node can restart freely; a new key holder (after a reboot) has a new
//! transport key and needs a new grant.

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_device_key::derive::DerivationRoot;
use tenzro_device_key::remote::{
    Audit, Grant, KeyStore, Policy, Provider, RemoteDeriveClient, RemoteTpmSigner, Transport,
};
use tenzro_device_key::{DeviceKeyError, HardwareSigner};
use tenzro_iroh::TpmSignServer;
use tracing::{info, warn};

use crate::error::{NodeError, Result};

/// Domain of the statement a passkey signs to grant a transport endpoint.
pub const GRANT_DOMAIN: &[u8] = b"tenzro/tpm-transport-grant/v1";

/// The label under which a provider derives its own transport key from its
/// TPM.
pub const PROVIDER_TRANSPORT_LABEL: &str = "tenzro/tpm-provider/transport";

/// Marks a request that carries a grant ahead of the signing request.
const GRANTED_MAGIC: &[u8; 4] = b"TZG1";

/// Largest grant a request may carry.
const MAX_GRANT_BYTES: usize = 16 * 1024;

/// Where a TPM-less machine reaches its key holder.
#[derive(Debug, Clone)]
pub struct RemoteConfig {
    /// The key label enrolled for this machine at the provider.
    pub label: String,
    /// The key holder's local socket.
    pub key_holder: PathBuf,
}

/// Parses `<64 hex endpoint id>@<ip:port>[,<ip:port>...]`, or several of them
/// separated by `;` (the first is the primary).
pub fn parse_providers(
    spec: &str,
) -> std::result::Result<Vec<([u8; 32], Vec<SocketAddr>)>, String> {
    let all = spec
        .split(';')
        .map(|one| parse_provider(one.trim()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if all.is_empty() {
        return Err("no provider".into());
    }
    Ok(all)
}

/// Parses one `<64 hex endpoint id>@<ip:port>[,<ip:port>...]`.
pub fn parse_provider(spec: &str) -> std::result::Result<([u8; 32], Vec<SocketAddr>), String> {
    let (id, addrs) = spec
        .split_once('@')
        .ok_or("expected <endpoint id>@<ip:port>")?;
    let id: [u8; 32] = hex::decode(id)
        .map_err(|e| format!("endpoint id: {e}"))?
        .try_into()
        .map_err(|_| "endpoint id is not 32 bytes".to_string())?;
    let addrs = addrs
        .split(',')
        .map(|a| a.parse::<SocketAddr>().map_err(|e| format!("{a}: {e}")))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((id, addrs))
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

/// A passkey's permission for one transport endpoint to use one key label
/// until `not_after_ms`. The assertion fields are base64url, as a WebAuthn
/// `get()` ceremony returns them, over the challenge [`grant_challenge`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportGrant {
    /// The granted transport endpoint id, hex.
    pub endpoint_id: String,
    /// The key label the endpoint may use.
    pub label: String,
    /// When the grant ends, milliseconds since the Unix epoch.
    pub not_after_ms: u64,
    /// The passkey's credential id, base64url.
    pub credential_id: String,
    /// `authenticatorData`, base64url.
    pub authenticator_data: String,
    /// `clientDataJSON`, base64url.
    pub client_data_json: String,
    /// The assertion signature, base64url.
    pub signature: String,
}

/// The 32 bytes a passkey signs (as its WebAuthn challenge) to grant
/// `endpoint` the key `label` until `not_after_ms`.
pub fn grant_challenge(endpoint: &[u8; 32], label: &str, not_after_ms: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(GRANT_DOMAIN);
    h.update(endpoint);
    h.update((label.len() as u32).to_be_bytes());
    h.update(label.as_bytes());
    h.update(not_after_ms.to_be_bytes());
    h.finalize().into()
}

/// One passkey the provider's operator enrolled, and the key label a grant
/// from it opens.
#[derive(Debug, Clone)]
pub struct EnrolledPasskey {
    /// The passkey's P-256 public key, `x || y`.
    pub public_key_xy: Vec<u8>,
    /// The WebAuthn relying party the passkey belongs to.
    pub rp_id: String,
    /// The key label a grant from this passkey opens.
    pub label: String,
    /// Whether this client may also use keys derived from the provider's
    /// root.
    pub derived: bool,
}

impl EnrolledPasskey {
    /// The identity the provider's policy and rate limit know this client
    /// by: the same for every grant the passkey makes, whatever endpoint it
    /// names.
    pub fn client_id(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"tenzro/tpm-transport-client/v1");
        h.update(&self.public_key_xy);
        h.update(self.label.as_bytes());
        h.finalize().to_vec()
    }
}

/// A signing request with the grant that authorizes it in front.
pub fn wrap_request(grant: &[u8], request: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + grant.len() + request.len());
    out.extend_from_slice(GRANTED_MAGIC);
    out.extend_from_slice(&(grant.len() as u32).to_be_bytes());
    out.extend_from_slice(grant);
    out.extend_from_slice(request);
    out
}

fn unwrap_request(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let rest = bytes.strip_prefix(GRANTED_MAGIC.as_slice())?;
    let (len, rest) = rest.split_first_chunk::<4>()?;
    let len = u32::from_be_bytes(*len) as usize;
    if len > MAX_GRANT_BYTES || rest.len() < len {
        return None;
    }
    Some(rest.split_at(len))
}

/// Checks `grant` for a request that arrived from transport endpoint
/// `client` at `now_ms`, and returns the enrolment it opens.
pub fn check_grant<'a>(
    enrolled: &'a [EnrolledPasskey],
    max_grant_ms: u64,
    client: &[u8; 32],
    grant: &TransportGrant,
    now_ms: u64,
) -> std::result::Result<&'a EnrolledPasskey, String> {
    if grant.endpoint_id != hex::encode(client) {
        return Err("the grant names another transport endpoint".into());
    }
    if now_ms >= grant.not_after_ms {
        return Err("the grant has expired".into());
    }
    if grant.not_after_ms - now_ms > max_grant_ms {
        return Err("the grant runs longer than this provider allows".into());
    }
    let b64 = |what: &str, v: &str| {
        URL_SAFE_NO_PAD
            .decode(v.trim_end_matches('='))
            .map_err(|_| format!("{what} is not base64url"))
    };
    let assertion = tenzro_crypto::webauthn::WebAuthnAssertion {
        authenticator_data: b64("authenticator_data", &grant.authenticator_data)?,
        client_data_json: b64("client_data_json", &grant.client_data_json)?,
        signature: b64("signature", &grant.signature)?,
        user_handle: None,
    };
    let challenge =
        URL_SAFE_NO_PAD.encode(grant_challenge(client, &grant.label, grant.not_after_ms));
    enrolled
        .iter()
        .filter(|e| e.label == grant.label)
        .find(|e| {
            tenzro_crypto::webauthn::verify_webauthn_assertion_require_uv(
                &assertion,
                &e.public_key_xy,
                &challenge,
                &tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain {
                    rp_id: e.rp_id.clone(),
                    related_origins: Vec::new(),
                },
                tenzro_crypto::webauthn::WebAuthnCeremonyType::Get,
            )
            .is_ok()
        })
        .ok_or_else(|| "no enrolled passkey granted this endpoint that key".to_string())
}

/// A [`Provider`] that serves only requests carrying a valid grant.
pub struct GrantedProvider<K: KeyStore, A: Audit> {
    provider: Provider<K, A>,
    enrolled: Vec<EnrolledPasskey>,
    max_grant_ms: u64,
}

impl<K: KeyStore, A: Audit> GrantedProvider<K, A> {
    /// A provider for the clients `enrolled`, accepting grants of at most
    /// `max_grant_ms`. The policy's client map is built from the enrolment.
    pub fn new(
        keys: K,
        audit: A,
        mut policy: Policy,
        enrolled: Vec<EnrolledPasskey>,
        max_grant_ms: u64,
    ) -> Self {
        policy.clients = enrolled
            .iter()
            .map(|e| {
                (
                    e.client_id(),
                    Grant {
                        label: e.label.clone(),
                        derived: e.derived,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        Self {
            provider: Provider::new(keys, audit, policy),
            enrolled,
            max_grant_ms,
        }
    }

    /// Lets granted clients that are enrolled for it use derived keys.
    pub fn with_derivation(
        mut self,
        root: Arc<dyn tenzro_device_key::derive::RemoteDerive>,
    ) -> Self {
        self.provider = self.provider.with_derivation(root);
        self
    }

    /// Lets granted clients that may use derived keys have batch roots
    /// signed by the identity key `versions` names.
    pub fn with_identity_versions(
        mut self,
        versions: Arc<dyn tenzro_device_key::delegation::IssuerVersions>,
    ) -> Self {
        self.provider = self.provider.with_identity_versions(versions);
        self
    }

    /// Sets how the provider's TPM command queue behaves.
    pub fn with_queue(mut self, params: tenzro_device_key::tpm_queue::QueueParams) -> Self {
        self.provider = self.provider.with_queue(params);
        self
    }

    /// Answers one request that arrived from transport endpoint `client`.
    pub fn handle(&self, client: &[u8; 32], request: &[u8], now_ms: u64) -> Vec<u8> {
        let refuse = |why: &str| {
            warn!(client = %hex::encode(&client[..8]), why, "tpm-sign refused");
            tenzro_device_key::remote::refusal(why)
        };
        let Some((grant, inner)) = unwrap_request(request) else {
            return refuse("the request carries no grant");
        };
        let grant: TransportGrant = match serde_json::from_slice(grant) {
            Ok(g) => g,
            Err(_) => return refuse("the grant is malformed"),
        };
        match check_grant(&self.enrolled, self.max_grant_ms, client, &grant, now_ms) {
            // A delegation issued under this grant ends with it.
            Ok(enrolment) => {
                self.provider
                    .handle_capped(&enrolment.client_id(), inner, Some(grant.not_after_ms))
            }
            Err(why) => refuse(&why),
        }
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Carries a request to the provider through the local key holder.
#[derive(Debug, Clone)]
pub struct HolderTransport {
    socket: PathBuf,
}

impl HolderTransport {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl Transport for HolderTransport {
    fn call(&self, request: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
        holder_call(&self.socket, request)
            .map_err(|e| DeviceKeyError::Tpm(format!("remote TPM: {e}")))
    }
}

#[cfg(unix)]
fn holder_call(socket: &Path, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
    crate::tpm_key_holder::request(socket, crate::tpm_key_holder::OP_CALL, request)
}

#[cfg(not(unix))]
fn holder_call(_socket: &Path, _request: &[u8]) -> std::result::Result<Vec<u8>, String> {
    Err("the TPM key holder needs a Unix socket, which this platform does not have".into())
}

/// From now on every hardware key and every derived key this process asks
/// for lives in the providers' TPM: `{label}/{key label}` there.
pub fn install(config: &RemoteConfig) -> Result<()> {
    let grant = config.label.clone();
    let socket = config.key_holder.clone();
    tenzro_device_key::signer::use_remote_signers(Box::new(move |label| {
        let signer = RemoteTpmSigner::open(
            HolderTransport::new(socket.clone()),
            &format!("{grant}/{label}"),
        )?;
        Ok(Box::new(signer) as Box<dyn HardwareSigner>)
    }))
    .map_err(|e| NodeError::Config(e.to_string()))?;
    tenzro_device_key::derive::use_remote_root(Arc::new(RemoteDeriveClient::new(
        HolderTransport::new(config.key_holder.clone()),
        &config.label,
    )))
    .map_err(|e| NodeError::Config(e.to_string()))
}

/// Opens this machine's identity key at the providers.
pub fn open(config: &RemoteConfig) -> tenzro_device_key::Result<RemoteTpmSigner<HolderTransport>> {
    RemoteTpmSigner::open(
        HolderTransport::new(config.key_holder.clone()),
        &config.label,
    )
}

// ---------------------------------------------------------------------------
// Provider side
// ---------------------------------------------------------------------------

/// The provider file.
#[derive(Debug, Deserialize)]
pub struct ProviderFile {
    /// Refused when present: the provider's transport key is derived from
    /// its TPM and never kept in a file.
    #[serde(default)]
    pub secret_key_file: Option<toml::Value>,
    /// A message is signed only if it begins with one of these.
    #[serde(default = "default_prefixes")]
    pub allowed_prefixes: Vec<String>,
    /// Signatures per client per minute.
    #[serde(default = "default_rate")]
    pub per_minute: u32,
    /// A derived key's sub-label must begin with one of these.
    #[serde(default = "default_prefixes_tenzro_slash")]
    pub derived_prefixes: Vec<String>,
    /// The longest grant accepted, in hours.
    #[serde(default = "default_max_grant_hours")]
    pub max_grant_hours: u64,
    /// The addresses the provider listens on. Loopback only when absent:
    /// name a private-network (VPN) or LAN address here to serve machines beyond this one.
    #[serde(default)]
    pub listen: Vec<SocketAddr>,
    /// Enrolled clients.
    pub clients: Vec<ClientEntry>,
    /// TPM commands allowed to wait behind the one running; a request past
    /// this is refused with a retry hint.
    #[serde(default = "default_queue_waiting")]
    pub tpm_queue_max_waiting: usize,
    /// The longest a request waits for its turn at the TPM, in seconds.
    #[serde(default = "default_queue_wait_secs")]
    pub tpm_queue_max_wait_secs: u64,
    /// Retries of a TPM command the chip reported as temporarily unable.
    #[serde(default = "default_queue_retries")]
    pub tpm_retries: u32,
    /// The pause before the first retry, in milliseconds; it doubles.
    #[serde(default = "default_backoff_base_ms")]
    pub tpm_backoff_base_ms: u64,
    /// The longest pause between retries, in milliseconds.
    #[serde(default = "default_backoff_cap_ms")]
    pub tpm_backoff_cap_ms: u64,
    /// The identities this provider signs batch roots for, and the key
    /// version and key label each currently has. The identity's on-chain key
    /// update changes this file; the provider reads it on every request.
    /// Absent: no batch roots are signed.
    #[serde(default)]
    pub issuer_file: Option<PathBuf>,
}

fn default_queue_waiting() -> usize {
    64
}
fn default_queue_wait_secs() -> u64 {
    120
}
fn default_queue_retries() -> u32 {
    3
}
fn default_backoff_base_ms() -> u64 {
    200
}
fn default_backoff_cap_ms() -> u64 {
    5_000
}
/// The identities a provider signs batch roots for, read from a file the
/// identity's key update rewrites:
/// `{"identities": {"<did>": {"version": 2, "label": "<sub-label>"}}}`.
pub struct FileIssuerVersions {
    path: PathBuf,
}

#[derive(Deserialize)]
struct IssuerEntry {
    version: u64,
    label: String,
}

#[derive(Deserialize)]
struct IssuerFile {
    identities: HashMap<String, IssuerEntry>,
}

impl FileIssuerVersions {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl tenzro_device_key::delegation::IssuerVersions for FileIssuerVersions {
    fn current(
        &self,
        identity: &str,
    ) -> tenzro_device_key::delegation::DelegationResult<(u64, String)> {
        use tenzro_device_key::delegation::DelegationError;
        let text = std::fs::read_to_string(&self.path).map_err(|e| {
            DelegationError::UnknownIdentity(format!("{}: {e}", self.path.display()))
        })?;
        let file: IssuerFile = serde_json::from_str(&text).map_err(|e| {
            DelegationError::UnknownIdentity(format!("{}: {e}", self.path.display()))
        })?;
        file.identities
            .get(identity)
            .map(|e| (e.version, e.label.clone()))
            .ok_or_else(|| DelegationError::UnknownIdentity(identity.to_string()))
    }
}

/// One enrolled client: the operator passkey whose grants open a key label.
#[derive(Debug, Deserialize)]
pub struct ClientEntry {
    /// The passkey's P-256 public key, hex `x || y` (or SEC1 uncompressed).
    pub passkey_public_key: String,
    /// The passkey's WebAuthn relying party id.
    pub rp_id: String,
    /// The key label a grant from this passkey opens.
    pub label: String,
    /// Whether this client may also use keys derived from the provider's
    /// root (validator, VRF, sealing and access-token keys).
    #[serde(default)]
    pub derived: bool,
}

fn default_prefixes() -> Vec<String> {
    vec![
        "tenzro".to_string(),
        // The composite signature representative every hybrid signature
        // begins with.
        "CompositeAlgorithmSignatures2025".to_string(),
    ]
}

fn default_rate() -> u32 {
    60
}

fn default_prefixes_tenzro_slash() -> Vec<String> {
    vec!["tenzro/".to_string()]
}

fn default_max_grant_hours() -> u64 {
    24 * 30
}

/// The enrolment a provider file declares.
pub fn enrolled_passkeys(config: &ProviderFile) -> Result<Vec<EnrolledPasskey>> {
    config
        .clients
        .iter()
        .map(|c| {
            let raw = hex::decode(c.passkey_public_key.trim_start_matches("0x"))
                .map_err(|e| NodeError::Config(format!("passkey_public_key: {e}")))?;
            let xy = match raw.len() {
                64 => raw,
                65 if raw[0] == 0x04 => raw[1..].to_vec(),
                _ => {
                    return Err(NodeError::Config(
                        "passkey_public_key is not a P-256 key (x || y, 64 bytes)".into(),
                    ));
                }
            };
            if c.rp_id.is_empty() || c.label.is_empty() {
                return Err(NodeError::Config(
                    "every client needs an rp_id and a label".into(),
                ));
            }
            Ok(EnrolledPasskey {
                public_key_xy: xy,
                rp_id: c.rp_id.clone(),
                label: c.label.clone(),
                derived: c.derived,
            })
        })
        .collect()
}

pub(crate) struct OpenKeys;

impl KeyStore for OpenKeys {
    fn open(&self, label: &str) -> tenzro_device_key::Result<Box<dyn HardwareSigner>> {
        tenzro_device_key::signer::open_or_create(label)
    }
}

struct TracingAudit;

impl Audit for TracingAudit {
    fn record(&self, client: &[u8], kind: &str, outcome: &str) {
        let client = hex::encode(&client[..client.len().min(8)]);
        if outcome == "ok" {
            info!(%client, kind, "tpm-sign");
        } else {
            warn!(%client, kind, outcome, "tpm-sign");
        }
    }
}

struct Service(Arc<GrantedProvider<OpenKeys, TracingAudit>>);

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("tpm-sign provider")
    }
}

/// Milliseconds since the Unix epoch.
pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[async_trait]
impl TpmSignServer for Service {
    async fn serve(&self, client: [u8; 32], request: Vec<u8>) -> Vec<u8> {
        let provider = self.0.clone();
        // The TPM is slow and blocking.
        tokio::task::spawn_blocking(move || provider.handle(&client, &request, now_ms()))
            .await
            .unwrap_or_default()
    }
}

/// Runs the provider until the process ends.
pub async fn serve(file: &Path) -> Result<()> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    let config: ProviderFile =
        toml::from_str(&text).map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    if config.secret_key_file.is_some() {
        return Err(NodeError::Config(format!(
            "{}: secret_key_file is no longer read: the provider's transport key is derived \
             from its TPM. Remove the line.",
            file.display()
        )));
    }
    let enrolled = enrolled_passkeys(&config)?;
    let policy = Policy {
        clients: HashMap::new(),
        allowed_prefixes: config
            .allowed_prefixes
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect(),
        allow_prehash: false,
        per_minute: config.per_minute,
        derived_prefixes: config.derived_prefixes.clone(),
    };
    let root = Arc::new(
        DerivationRoot::open_or_create()
            .map_err(|e| NodeError::Config(format!("the derivation root: {e}")))?,
    );
    let secret = root
        .endpoint_secret(PROVIDER_TRANSPORT_LABEL)
        .map_err(|e| NodeError::Config(format!("the provider transport key: {e}")))?;
    let mut provider = GrantedProvider::new(
        OpenKeys,
        TracingAudit,
        policy,
        enrolled,
        config.max_grant_hours.saturating_mul(3_600_000),
    );
    provider = provider.with_queue(tenzro_device_key::tpm_queue::QueueParams {
        max_waiting: config.tpm_queue_max_waiting,
        max_wait_ms: config.tpm_queue_max_wait_secs.saturating_mul(1000),
        retries: config.tpm_retries,
        backoff_base_ms: config.tpm_backoff_base_ms,
        backoff_cap_ms: config.tpm_backoff_cap_ms,
    });
    if config.clients.iter().any(|c| c.derived) {
        provider = provider.with_derivation(root.clone());
        if let Some(issuers) = &config.issuer_file {
            provider = provider.with_identity_versions(Arc::new(FileIssuerVersions::new(issuers)));
        }
    }
    let provider = Arc::new(provider);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(tenzro_iroh::serve_tpm_sign(
        *secret,
        Arc::new(Service(provider)),
        config.listen.clone(),
        ready_tx,
    ));
    let addr = ready_rx
        .await
        .map_err(|_| NodeError::Other("the provider endpoint did not start".into()))?;
    println!(
        "tpm provider ready: endpoint {} enrolled {} client(s)\n{addr:?}",
        hex::encode(tenzro_iroh::endpoint_id_of(&secret)),
        config.clients.len()
    );
    match server.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(NodeError::Other(e.to_string())),
        Err(e) => Err(NodeError::Other(e.to_string())),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    /// An operator passkey for tests.
    pub(crate) struct TestPasskey {
        key: SigningKey,
        pub rp_id: String,
    }

    impl TestPasskey {
        pub(crate) fn new(seed: u8) -> Self {
            Self {
                key: SigningKey::from_slice(&[seed; 32]).unwrap(),
                rp_id: "operator.example".into(),
            }
        }

        pub(crate) fn enrolment(&self, label: &str) -> EnrolledPasskey {
            EnrolledPasskey {
                public_key_xy: self.key.verifying_key().to_sec1_point(false).as_bytes()[1..]
                    .to_vec(),
                rp_id: self.rp_id.clone(),
                label: label.into(),
                derived: false,
            }
        }

        /// A grant for `endpoint`, made with user verification.
        pub(crate) fn grant(
            &self,
            endpoint: &[u8; 32],
            label: &str,
            not_after_ms: u64,
        ) -> TransportGrant {
            let challenge = grant_challenge(endpoint, label, not_after_ms);
            let cdj = serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": format!("https://{}", self.rp_id),
            })
            .to_string()
            .into_bytes();
            let mut ad = Sha256::digest(self.rp_id.as_bytes()).to_vec();
            ad.push(0x05);
            ad.extend_from_slice(&[0, 0, 0, 1]);
            let hash = tenzro_crypto::webauthn::webauthn_signed_hash(&ad, &cdj);
            let sig: p256::ecdsa::Signature = self.key.sign_prehash(&hash).unwrap();
            TransportGrant {
                endpoint_id: hex::encode(endpoint),
                label: label.into(),
                not_after_ms,
                credential_id: URL_SAFE_NO_PAD.encode(b"cred"),
                authenticator_data: URL_SAFE_NO_PAD.encode(&ad),
                client_data_json: URL_SAFE_NO_PAD.encode(&cdj),
                signature: URL_SAFE_NO_PAD.encode(sig.to_bytes()),
            }
        }
    }

    const HOUR: u64 = 3_600_000;

    #[test]
    fn a_grant_from_the_enrolled_passkey_for_this_endpoint_is_accepted() {
        let pk = TestPasskey::new(3);
        let enrolled = vec![pk.enrolment("pi-1")];
        let endpoint = [9u8; 32];
        let grant = pk.grant(&endpoint, "pi-1", 10 * HOUR);
        let e = check_grant(&enrolled, 24 * HOUR, &endpoint, &grant, HOUR).unwrap();
        assert_eq!(e.label, "pi-1");
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let pk = TestPasskey::new(3);
        let enrolled = vec![pk.enrolment("pi-1")];
        let endpoint = [9u8; 32];
        let grant = pk.grant(&endpoint, "pi-1", 10 * HOUR);
        let err = check_grant(&enrolled, 24 * HOUR, &endpoint, &grant, 10 * HOUR).unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn a_grant_for_another_endpoint_label_or_passkey_is_refused() {
        let pk = TestPasskey::new(3);
        let other = TestPasskey::new(4);
        let enrolled = vec![pk.enrolment("pi-1")];
        let endpoint = [9u8; 32];
        let grant = pk.grant(&endpoint, "pi-1", 10 * HOUR);
        assert!(check_grant(&enrolled, 24 * HOUR, &[8u8; 32], &grant, HOUR).is_err());
        let mut relabelled = grant.clone();
        relabelled.label = "pi-2".into();
        assert!(check_grant(&enrolled, 24 * HOUR, &endpoint, &relabelled, HOUR).is_err());
        let forged = other.grant(&endpoint, "pi-1", 10 * HOUR);
        assert!(check_grant(&enrolled, 24 * HOUR, &endpoint, &forged, HOUR).is_err());
        let too_long = pk.grant(&endpoint, "pi-1", 100 * HOUR);
        assert!(check_grant(&enrolled, 24 * HOUR, &endpoint, &too_long, HOUR).is_err());
    }

    #[test]
    fn a_provider_file_with_a_key_file_or_a_bad_passkey_is_refused() {
        let file: ProviderFile = toml::from_str(
            "clients = [{ passkey_public_key = \"00\", rp_id = \"x\", label = \"pi-1\" }]",
        )
        .unwrap();
        assert!(enrolled_passkeys(&file).is_err());
        let with_key: ProviderFile =
            toml::from_str("secret_key_file = \"/var/lib/k\"\nclients = []").unwrap();
        assert!(with_key.secret_key_file.is_some());
    }
}
