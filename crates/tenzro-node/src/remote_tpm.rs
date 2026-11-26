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
use tenzro_device_key::HardwareSigner;
use tenzro_device_key::derive::DerivationRoot;
use tenzro_device_key::remote::{Audit, Grant, KeyStore, Policy, Provider, RemoteTpmSigner};
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

/// The grant in a passkey's assertion: the `PublicKeyCredential` JSON a
/// browser's `navigator.credentials.get` returns (`toJSON()`), over the
/// challenge [`grant_challenge`] made for `endpoint`, `label` and
/// `not_after_ms`. Refused when the assertion answers another challenge or
/// is not an assertion; the provider checks the signature.
pub fn grant_from_assertion(
    assertion: &str,
    endpoint: &[u8; 32],
    label: &str,
    not_after_ms: u64,
) -> std::result::Result<TransportGrant, String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let json: serde_json::Value =
        serde_json::from_str(assertion).map_err(|e| format!("the assertion is not JSON: {e}"))?;
    let text = |v: Option<&serde_json::Value>, name: &str| {
        v.and_then(|v| v.as_str())
            .map(|s| s.trim_end_matches('=').to_string())
            .ok_or_else(|| format!("the assertion has no {name}"))
    };
    let response = json.get("response");
    let credential_id = text(json.get("rawId").or_else(|| json.get("id")), "rawId")?;
    let authenticator_data = text(
        response.and_then(|r| r.get("authenticatorData")),
        "response.authenticatorData",
    )?;
    let client_data_json = text(
        response.and_then(|r| r.get("clientDataJSON")),
        "response.clientDataJSON",
    )?;
    let signature = text(
        response.and_then(|r| r.get("signature")),
        "response.signature",
    )?;
    let client: serde_json::Value = b64
        .decode(&client_data_json)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or("the assertion's clientDataJSON is not base64url JSON")?;
    if client.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err("this is not a passkey assertion (webauthn.get)".into());
    }
    let challenge = b64.encode(grant_challenge(endpoint, label, not_after_ms));
    if client.get("challenge").and_then(|v| v.as_str()) != Some(challenge.as_str()) {
        return Err(
            "the assertion answers another challenge: sign the one this command printed".into(),
        );
    }
    Ok(TransportGrant {
        endpoint_id: hex::encode(endpoint),
        label: label.to_string(),
        not_after_ms,
        credential_id,
        authenticator_data,
        client_data_json,
        signature,
    })
}

/// The line the operator runs in a browser on the relying party's own page
/// to sign `challenge` with their passkey; it prints the assertion to paste.
pub fn assertion_snippet(challenge: &[u8; 32], rp_id: &str) -> String {
    use base64::Engine as _;
    let c = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge);
    format!(
        "navigator.credentials.get({{publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(\
         {{challenge: \"{c}\", rpId: \"{rp_id}\", userVerification: \"required\"}})}})\
         .then(c => console.log(JSON.stringify(c.toJSON())))"
    )
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
    let for_label: Vec<&EnrolledPasskey> =
        enrolled.iter().filter(|e| e.label == grant.label).collect();
    for_label
        .iter()
        .copied()
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
        .ok_or_else(|| {
            if for_label.is_empty() {
                return format!(
                    "no passkey is enrolled for '{}': enrol one for that label on this provider first",
                    grant.label
                );
            }
            let enrolled_keys = for_label
                .iter()
                .map(|e| enrolled_fingerprint(e))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "the passkey that signed is not the one enrolled for '{}' (enrolled passkey {enrolled_keys}): sign the grant with that passkey",
                grant.label
            )
        })
}

/// The first eight hex characters of the SHA-256 of an enrolled passkey's
/// public key: enough for its holder to tell which of their passkeys is meant.
fn enrolled_fingerprint(e: &EnrolledPasskey) -> String {
    hex::encode(&Sha256::digest(&e.public_key_xy)[..4])
}

/// A [`Provider`] that serves only requests carrying a valid grant.
pub struct GrantedProvider<K: KeyStore, A: Audit> {
    provider: Provider<K, A>,
    enrolled: std::sync::RwLock<Vec<EnrolledPasskey>>,
    max_grant_ms: u64,
    /// Whether a derivation root is attached (decided at start).
    derivation: bool,
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
            enrolled: std::sync::RwLock::new(enrolled),
            max_grant_ms,
            derivation: false,
        }
    }

    /// Replaces the enrolled clients while the provider runs. Clients
    /// kept keep their rate window and any request in flight; a removed
    /// client is refused from the next request on. Refused, with nothing
    /// changed, if the new list needs derived keys the provider was not
    /// started with: that needs a restart.
    pub fn reload_clients(
        &self,
        enrolled: Vec<EnrolledPasskey>,
    ) -> std::result::Result<(), String> {
        if !self.derivation && enrolled.iter().any(|e| e.derived) {
            return Err(
                "a client uses derived keys but the provider started without a derivation root: \
                 restart the provider"
                    .into(),
            );
        }
        let clients = enrolled
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
        self.provider.replace_clients(clients);
        *self.enrolled.write().expect("enrolled") = enrolled;
        Ok(())
    }

    /// Lets granted clients that are enrolled for it use derived keys.
    pub fn with_derivation(
        mut self,
        root: Arc<dyn tenzro_device_key::derive::RemoteDerive>,
    ) -> Self {
        self.provider = self.provider.with_derivation(root);
        self.derivation = true;
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

    /// Has this machine's TPM attest for the keys it holds for the client
    /// enrolled under `label`.
    pub fn with_attestor(
        mut self,
        label: &str,
        attestor: Arc<dyn tenzro_device_key::remote::Attestor>,
    ) -> Self {
        self.provider = self.provider.with_attestor(label, attestor);
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
        let checked = {
            let enrolled = self.enrolled.read().expect("enrolled");
            check_grant(&enrolled, self.max_grant_ms, client, &grant, now_ms)
                .map(|enrolment| enrolment.client_id())
        };
        match checked {
            // A delegation issued under this grant ends with it.
            Ok(id) => self
                .provider
                .handle_capped(&id, inner, Some(grant.not_after_ms)),
            Err(why) => refuse(&why),
        }
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

pub use tenzro_device_key::remote::HolderTransport;

/// From now on every hardware key and every derived key this process asks
/// for lives in the providers' TPM: `{label}/{key label}` there.
pub fn install(config: &RemoteConfig) -> Result<()> {
    tenzro_device_key::remote::use_key_holder(&config.label, &config.key_holder)
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
    /// Requests of any kind per client per minute that may wait for the
    /// TPM: key opens and public halves as well as signatures.
    #[serde(default = "default_request_rate")]
    pub requests_per_minute: u32,
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
    /// The label of the one client whose machine identity this machine's
    /// TPM answers for on chain: the provider attests for that client's
    /// keys and for no other. A TPM is admitted under one identity, so a
    /// provider whose TPM backs its own machine's identity leaves this out,
    /// and its clients register without a TPM attestation.
    #[serde(default)]
    pub attests_for: Option<String>,
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

/// Twice the signature rate: a client opens its keys and reads their public
/// halves besides signing.
fn default_request_rate() -> u32 {
    2 * default_rate()
}

fn default_prefixes_tenzro_slash() -> Vec<String> {
    vec!["tenzro/".to_string()]
}

fn default_max_grant_hours() -> u64 {
    24 * 30
}

/// The enrolment a provider file declares. One label may have several
/// passkeys (the operator's devices); one passkey enrolled twice for the same
/// label is refused.
pub fn enrolled_passkeys(config: &ProviderFile) -> Result<Vec<EnrolledPasskey>> {
    let enrolled = config
        .clients
        .iter()
        .map(enrolled_passkey)
        .collect::<Result<Vec<_>>>()?;
    let mut seen = std::collections::HashSet::new();
    if let Some(e) = enrolled
        .iter()
        .find(|e| !seen.insert((e.label.as_str(), e.public_key_xy.as_slice())))
    {
        return Err(NodeError::Config(format!(
            "one passkey is enrolled twice for the key label {:?}",
            e.label
        )));
    }
    Ok(enrolled)
}

/// One client entry, checked.
pub fn enrolled_passkey(c: &ClientEntry) -> Result<EnrolledPasskey> {
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
    if p256::PublicKey::from_sec1_bytes(&[&[0x04][..], &xy].concat()).is_err() {
        return Err(NodeError::Config(
            "passkey_public_key is not a point on P-256".into(),
        ));
    }
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

/// Re-reads the `[[clients]]` of `file` into a running provider. Only the
/// client list changes; on any error the provider keeps the list it has.
pub fn reload_clients_from_file<K: KeyStore, A: Audit>(
    file: &Path,
    provider: &GrantedProvider<K, A>,
) -> Result<usize> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    let config: ProviderFile =
        toml::from_str(&text).map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    let enrolled = enrolled_passkeys(&config)?;
    let n = enrolled.len();
    provider
        .reload_clients(enrolled)
        .map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    Ok(n)
}

/// Where a running provider records its process id: beside its file.
#[cfg(unix)]
pub fn pid_file_for(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(".pid");
    PathBuf::from(name)
}

/// The process id a running provider keeps in its pid file for as long as it
/// runs.
#[cfg(unix)]
struct PidFile(PathBuf);

#[cfg(unix)]
impl PidFile {
    fn write(file: &Path) -> Self {
        let path = pid_file_for(file);
        if let Err(e) = std::fs::write(&path, std::process::id().to_string()) {
            warn!(error = %e, file = %path.display(), "tpm provider: pid file not written, enrolments will not reload it by themselves");
        }
        Self(path)
    }
}

#[cfg(unix)]
impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A client to add to a provider file.
pub struct NewClient<'a> {
    pub passkey_public_key: &'a str,
    pub rp_id: &'a str,
    pub label: &'a str,
    pub derived: bool,
}

/// Adds `client` to the `[[clients]]` of `file`. The file is checked as a
/// whole before it is replaced, so a refused client leaves it untouched.
/// Returns how many clients the file enrols now.
pub fn enrol_client(file: &Path, client: &NewClient<'_>) -> Result<usize> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    let key = client.passkey_public_key.trim();
    let mut next = text.clone();
    if !next.ends_with('\n') {
        next.push('\n');
    }
    next.push_str(&format!(
        "\n[[clients]]\npasskey_public_key = {key:?}\nrp_id = {:?}\nlabel = {:?}\nderived = {}\n",
        client.rp_id, client.label, client.derived
    ));
    let config: ProviderFile =
        toml::from_str(&next).map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    let enrolled = enrolled_passkeys(&config)?;
    let dup = enrolled
        .iter()
        .filter(|c| c.label == client.label && c.rp_id == client.rp_id)
        .count();
    if dup > 1 {
        return Err(NodeError::Config(format!(
            "{}: a client for label {:?} and relying party {:?} is already enrolled",
            file.display(),
            client.label,
            client.rp_id
        )));
    }
    let tmp = file.with_extension("enrol.tmp");
    std::fs::write(&tmp, &next)
        .and_then(|()| std::fs::rename(&tmp, file))
        .map_err(|e| NodeError::Config(format!("{}: {e}", file.display())))?;
    Ok(enrolled.len())
}

/// What became of a running provider after its file changed.
#[derive(Debug, PartialEq, Eq)]
pub enum Reload {
    /// The provider with this process id was told to re-read its file.
    Signalled(u32),
    /// No provider is running from this file: the client is enrolled and
    /// takes effect when one starts.
    NotRunning,
}

/// Tells the provider running from `file`, if there is one, to re-read its
/// client list.
#[cfg(unix)]
pub fn reload_running(file: &Path) -> Result<Reload> {
    let pid_file = pid_file_for(file);
    let Ok(text) = std::fs::read_to_string(&pid_file) else {
        return Ok(Reload::NotRunning);
    };
    let Ok(pid) = text.trim().parse::<i32>() else {
        return Ok(Reload::NotRunning);
    };
    // SAFETY: kill(2) takes plain integers and touches no memory.
    if unsafe { libc::kill(pid, 0) } != 0 {
        return Ok(Reload::NotRunning);
    }
    // SAFETY: as above.
    if unsafe { libc::kill(pid, libc::SIGHUP) } != 0 {
        return Err(NodeError::Config(format!(
            "the provider (process {pid}) could not be told to reload: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(Reload::Signalled(pid as u32))
}

/// A provider on this platform is not signalled: it reads its file when it
/// starts.
#[cfg(not(unix))]
pub fn reload_running(_file: &Path) -> Result<Reload> {
    Ok(Reload::NotRunning)
}

/// How often a running provider looks at its file for a changed client list.
const CLIENTS_FILE_LOOK_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

/// What tells a changed file from an unchanged one: its modification time
/// and length. `None` while the file cannot be read.
fn file_stamp(file: &Path) -> Option<(std::time::SystemTime, u64)> {
    let meta = std::fs::metadata(file).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

/// Re-reads the client list whenever `file` changes (`tenzro-node tpm clients`
/// writes it), on every platform; a list the provider would refuse leaves the
/// running one in place.
fn watch_clients_file<K: KeyStore + 'static, A: Audit + 'static>(
    file: std::path::PathBuf,
    provider: Arc<GrantedProvider<K, A>>,
) {
    tokio::spawn(async move {
        let mut seen = file_stamp(&file);
        let mut every = tokio::time::interval(CLIENTS_FILE_LOOK_EVERY);
        loop {
            every.tick().await;
            let now = file_stamp(&file);
            if now.is_none() || now == seen {
                continue;
            }
            seen = now;
            match reload_clients_from_file(&file, &provider) {
                Ok(n) => info!(
                    clients = n,
                    "tpm provider: the file changed, client list reloaded"
                ),
                Err(e) => {
                    warn!(error = %e, "tpm provider: the file changed, reload refused, client list unchanged")
                }
            }
        }
    });
}

/// Runs the provider until the process ends. A change to `file`, or SIGHUP,
/// re-reads the client list without interrupting any client.
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
        requests_per_minute: config.requests_per_minute,
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
    if let Some(label) = &config.attests_for {
        if !config.clients.iter().any(|c| &c.label == label) {
            return Err(NodeError::Config(format!(
                "{}: attests_for names {label}, which no client is enrolled under",
                file.display()
            )));
        }
        #[cfg(any(target_os = "linux", windows))]
        {
            provider = provider.with_attestor(
                label,
                Arc::new(tenzro_tee::holder_attest::HolderAttestor(
                    tenzro_tee::holder_attest::LocalTpm,
                )),
            );
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        return Err(NodeError::Config(format!(
            "{}: attests_for needs a TPM 2.0, which this platform has none of",
            file.display()
        )));
    }
    if config.clients.iter().any(|c| c.derived) {
        provider = provider.with_derivation(root.clone());
        if let Some(issuers) = &config.issuer_file {
            provider = provider.with_identity_versions(Arc::new(FileIssuerVersions::new(issuers)));
        }
    }
    let provider = Arc::new(provider);
    watch_clients_file(file.to_path_buf(), provider.clone());
    #[cfg(unix)]
    let _pid;
    #[cfg(unix)]
    {
        // Recorded only once SIGHUP is handled: a signal sent before that would end it.
        let provider = provider.clone();
        let file = file.to_path_buf();
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
            Ok(mut hup) => {
                _pid = Some(PidFile::write(&file));
                tokio::spawn(async move {
                    while hup.recv().await.is_some() {
                        match reload_clients_from_file(&file, &provider) {
                            Ok(n) => info!(clients = n, "tpm provider: client list reloaded"),
                            Err(e) => {
                                warn!(error = %e, "tpm provider: reload refused, client list unchanged")
                            }
                        }
                    }
                });
            }
            Err(e) => warn!(error = %e, "tpm provider: SIGHUP reload unavailable"),
        }
    }
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
            let origin = format!("https://{}", self.rp_id);
            self.grant_from(&origin, endpoint, label, not_after_ms)
        }

        /// [`TestPasskey::grant`] as a client at `origin` reports it.
        fn grant_from(
            &self,
            origin: &str,
            endpoint: &[u8; 32],
            label: &str,
            not_after_ms: u64,
        ) -> TransportGrant {
            let challenge = grant_challenge(endpoint, label, not_after_ms);
            let cdj = serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": origin,
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
    fn a_grant_made_in_an_android_app_is_refused() {
        // A grant answers to the relying party its enrolment records and to
        // no related origins, so no app origin opens one.
        let pk = TestPasskey::new(3);
        let enrolled = vec![pk.enrolment("pi-1")];
        let endpoint = [9u8; 32];
        let app = format!("android:apk-key-hash:{}", "A".repeat(43));
        let grant = pk.grant_from(&app, &endpoint, "pi-1", 10 * HOUR);
        assert!(check_grant(&enrolled, 24 * HOUR, &endpoint, &grant, HOUR).is_err());
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
    fn a_passkey_not_enrolled_for_the_label_is_refused_by_the_label() {
        let enrolled = vec![TestPasskey::new(3).enrolment("pi-1")];
        let endpoint = [9u8; 32];
        let forged = TestPasskey::new(4).grant(&endpoint, "pi-1", 10 * HOUR);
        let why = match check_grant(&enrolled, 24 * HOUR, &endpoint, &forged, HOUR) {
            Err(why) => why.to_string(),
            Ok(_) => panic!("a passkey that is not enrolled was accepted"),
        };
        assert!(why.contains("not the one enrolled for 'pi-1'"), "{why}");
        assert!(
            why.contains(&enrolled_fingerprint(&enrolled[0])),
            "the refusal names the enrolled passkey: {why}"
        );
        assert!(
            !why.contains(&hex::encode(
                &Sha256::digest(&TestPasskey::new(4).enrolment("pi-1").public_key_xy)[..4]
            )),
            "{why}"
        );

        let none = match check_grant(&[], 24 * HOUR, &endpoint, &forged, HOUR) {
            Err(why) => why,
            Ok(_) => panic!("a grant with nothing enrolled was accepted"),
        };
        assert!(none.contains("no passkey is enrolled for 'pi-1'"), "{none}");
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

    fn provider_file(dir: &Path, passkey: &TestPasskey) -> PathBuf {
        let file = dir.join("provider.toml");
        let first = passkey.enrolment("pi-1");
        std::fs::write(
            &file,
            format!(
                "[[clients]]\npasskey_public_key = \"{}\"\nrp_id = \"{}\"\nlabel = \"pi-1\"\n",
                hex::encode(first.public_key_xy),
                first.rp_id
            ),
        )
        .unwrap();
        file
    }

    #[test]
    fn a_new_device_is_added_to_the_file_and_a_refused_one_leaves_it_alone() {
        let dir = tempfile::tempdir().unwrap();
        let passkey = TestPasskey::new(5);
        let file = provider_file(dir.path(), &passkey);
        let second = TestPasskey::new(6).enrolment("pi-2");
        let key = hex::encode(second.public_key_xy);
        let client = NewClient {
            passkey_public_key: &key,
            rp_id: &second.rp_id,
            label: "pi-2",
            derived: false,
        };
        assert_eq!(enrol_client(&file, &client).unwrap(), 2);
        let text = std::fs::read_to_string(&file).unwrap();
        let config: ProviderFile = toml::from_str(&text).unwrap();
        assert_eq!(enrolled_passkeys(&config).unwrap().len(), 2);

        // The same device and label again, and a key that is no P-256 key.
        let before = std::fs::read_to_string(&file).unwrap();
        assert!(enrol_client(&file, &client).is_err());
        let bad = NewClient {
            passkey_public_key: "abcd",
            ..client
        };
        assert!(enrol_client(&file, &bad).is_err());
        assert_eq!(std::fs::read_to_string(&file).unwrap(), before);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_running_provider_is_told_to_reload_and_a_stopped_one_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = provider_file(dir.path(), &TestPasskey::new(5));
        assert_eq!(reload_running(&file).unwrap(), Reload::NotRunning);

        // A stale pid file: the process it names has ended.
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let gone_pid = gone.id();
        gone.wait().unwrap();
        std::fs::write(pid_file_for(&file), gone_pid.to_string()).unwrap();
        assert_eq!(reload_running(&file).unwrap(), Reload::NotRunning);

        // This process handles SIGHUP the way the provider does.
        let mut hup =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        let pid = PidFile::write(&file);
        assert_eq!(
            reload_running(&file).unwrap(),
            Reload::Signalled(std::process::id())
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), hup.recv())
            .await
            .expect("the signal arrives")
            .expect("the handler is open");
        drop(pid);
        assert!(
            !pid_file_for(&file).exists(),
            "a stopped provider leaves no pid file"
        );
    }
}

#[cfg(test)]
mod assertion_tests {
    use super::*;

    fn assertion(kind: &str, challenge: &[u8]) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let client = serde_json::json!({
            "type": kind, "challenge": b64.encode(challenge), "origin": "https://control.tenzro.com",
        });
        serde_json::json!({
            "id": "Y3JlZA", "rawId": "Y3JlZA", "type": "public-key",
            "response": {
                "authenticatorData": "YXV0aA",
                "clientDataJSON": b64.encode(client.to_string()),
                "signature": "c2ln",
            },
        })
        .to_string()
    }

    #[test]
    fn a_browser_assertion_over_the_printed_challenge_is_the_grant() {
        let endpoint = [7u8; 32];
        let challenge = grant_challenge(&endpoint, "pi-hall", 1_800_000_000_000);
        let grant = grant_from_assertion(
            &assertion("webauthn.get", &challenge),
            &endpoint,
            "pi-hall",
            1_800_000_000_000,
        )
        .unwrap();
        assert_eq!(grant.endpoint_id, hex::encode(endpoint));
        assert_eq!(grant.credential_id, "Y3JlZA");
        assert_eq!(grant.authenticator_data, "YXV0aA");
        assert_eq!(grant.signature, "c2ln");
        assert_eq!(grant.not_after_ms, 1_800_000_000_000);
    }

    #[test]
    fn an_assertion_for_another_grant_or_ceremony_is_refused() {
        let endpoint = [7u8; 32];
        let challenge = grant_challenge(&endpoint, "pi-hall", 1);
        // Another label, end or endpoint gives another challenge.
        assert!(
            grant_from_assertion(
                &assertion("webauthn.get", &challenge),
                &endpoint,
                "other",
                1
            )
            .is_err()
        );
        assert!(
            grant_from_assertion(
                &assertion("webauthn.get", &challenge),
                &endpoint,
                "pi-hall",
                2
            )
            .is_err()
        );
        assert!(
            grant_from_assertion(
                &assertion("webauthn.get", &challenge),
                &[8; 32],
                "pi-hall",
                1
            )
            .is_err()
        );
        assert!(
            grant_from_assertion(
                &assertion("webauthn.create", &challenge),
                &endpoint,
                "pi-hall",
                1
            )
            .is_err()
        );
        assert!(grant_from_assertion("{}", &endpoint, "pi-hall", 1).is_err());
    }

    #[test]
    fn the_snippet_signs_the_challenge_for_the_relying_party() {
        let s = assertion_snippet(&[0u8; 32], "control.tenzro.com");
        assert!(s.contains("rpId: \"control.tenzro.com\""));
        assert!(s.contains(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32])));
        assert!(s.contains("toJSON()"));
    }
}
