//! A hardware key held by another machine's TPM.
//!
//! A machine with no TPM of its own signs through a machine the same operator
//! owns: the key never leaves that machine's TPM, and the TPM-less machine
//! holds no key at all, only the right to ask. Three parts:
//!
//! - [`RemoteTpmSigner`] is a [`HardwareSigner`] whose signatures come from a
//!   [`Provider`] over a [`Transport`]. It checks every signature against the
//!   provider's public key before returning it, so a faulty or hostile
//!   provider cannot hand back anything that does not verify.
//! - [`Provider`] answers requests on the machine that owns the TPM. It signs
//!   only for enrolled clients, only under the key label enrolled for that
//!   client, only for messages that begin with a domain prefix the operator
//!   allowed, and not faster than the client's rate limit. It signs a message,
//!   never a caller-supplied digest, unless the operator turns that on.
//! - [`Transport`] carries one request and its answer. The client's identity
//!   is whatever the transport authenticated (a pinned public key), never a
//!   field of the request.
//!
//! The wire format is fixed and versioned; changing it changes
//! [`WIRE_VERSION`], and an unknown version is refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::batch_signer::{RootSignature, RootSigner};
use crate::delegation::{
    Clock, DelegationError, DelegationResult, IssuerVersions, SystemClock, issuer_publics,
};
use crate::derive::RemoteDerive;
use crate::signer::{HardwareBackend, HardwareSigner, verify_p256, verify_p256_prehash};
use crate::tpm_queue::{QueueParams, TpmQueue, is_transient};
use crate::{DeviceKeyError, DeviceSignature, Result};

/// The version of the request and answer encoding.
pub const WIRE_VERSION: u8 = 1;

/// The longest message a provider signs.
pub const MAX_MESSAGE: usize = 64 * 1024;

const KIND_PUBLIC_KEY: u8 = 1;
const KIND_SIGN: u8 = 2;
const KIND_SIGN_PREHASH: u8 = 3;

// Derived-key operations (see [`crate::derive`]); the request's body is
// `[sub-label length][sub-label][arguments]`.
const KIND_ED_PUBLIC: u8 = 10;
const KIND_ED_SIGN: u8 = 11;
const KIND_VRF_PROVE: u8 = 12;
const KIND_X_PUBLIC: u8 = 13;
const KIND_X_AGREE: u8 = 14;
const KIND_MLDSA_PUBLIC: u8 = 15;
const KIND_MLDSA_SIGN: u8 = 16;
const KIND_P256_PUBLIC: u8 = 17;
const KIND_P256_SIGN: u8 = 18;
const KIND_KEM_PUBLIC: u8 = 19;
const KIND_KEM_DECAPSULATE: u8 = 20;

/// A provider's hardware signs the Merkle root of a batch (see [`crate::batch_signer`]).
const KIND_SIGN_ROOT: u8 = 22;

const STATUS_OK: u8 = 0;
const STATUS_REFUSED: u8 = 1;
const STATUS_ERROR: u8 = 2;

/// Carries one request to a provider and returns its answer.
pub trait Transport: Send + Sync {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>>;
}

fn remote(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Tpm(format!("remote TPM: {}", msg.into()))
}

fn encode_request(kind: u8, label: &str, body: &[u8]) -> Result<Vec<u8>> {
    let label = label.as_bytes();
    if label.len() > 255 || body.len() > MAX_MESSAGE {
        return Err(remote("request too large"));
    }
    let mut out = Vec::with_capacity(7 + label.len() + body.len());
    out.push(WIRE_VERSION);
    out.push(kind);
    out.push(label.len() as u8);
    out.extend_from_slice(label);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

struct Request<'a> {
    kind: u8,
    label: &'a str,
    body: &'a [u8],
}

fn decode_request(bytes: &[u8]) -> std::result::Result<Request<'_>, &'static str> {
    if bytes.len() < 3 {
        return Err("short request");
    }
    if bytes[0] != WIRE_VERSION {
        return Err("unknown wire version");
    }
    let kind = bytes[1];
    let label_len = bytes[2] as usize;
    let rest = &bytes[3..];
    if rest.len() < label_len + 4 {
        return Err("short request");
    }
    let label = std::str::from_utf8(&rest[..label_len]).map_err(|_| "label is not UTF-8")?;
    let rest = &rest[label_len..];
    let body_len = u32::from_be_bytes(rest[..4].try_into().expect("four bytes")) as usize;
    let body = &rest[4..];
    if body.len() != body_len || body_len > MAX_MESSAGE {
        return Err("body length does not match");
    }
    Ok(Request { kind, label, body })
}

/// A refusal answer, for a layer in front of [`Provider::handle`] that
/// refuses a request before the provider sees it.
pub fn refusal(why: &str) -> Vec<u8> {
    answer(STATUS_REFUSED, why.as_bytes())
}

/// If `answer` is a refusal because the provider's TPM line is full or the
/// wait ran out, how many milliseconds the provider says to wait.
pub fn busy_retry_after(answer: &[u8]) -> Option<u64> {
    if answer.len() < 6 || answer[0] != WIRE_VERSION || answer[1] != STATUS_REFUSED {
        return None;
    }
    let text = std::str::from_utf8(&answer[6..]).ok()?;
    if !text.starts_with(crate::tpm_queue::BUSY_PREFIX) {
        return None;
    }
    let tail = text.rsplit("retry in ").next()?;
    tail.split(' ').next()?.parse().ok()
}

fn answer(status: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + body.len());
    out.push(WIRE_VERSION);
    out.push(status);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn decode_answer(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.len() < 6 || bytes[0] != WIRE_VERSION {
        return Err(remote("malformed answer"));
    }
    let len = u32::from_be_bytes(bytes[2..6].try_into().expect("four bytes")) as usize;
    if bytes.len() != 6 + len {
        return Err(remote("answer length does not match"));
    }
    let body = &bytes[6..];
    match bytes[1] {
        STATUS_OK => Ok(body.to_vec()),
        STATUS_REFUSED => Err(remote(format!(
            "the provider refused: {}",
            String::from_utf8_lossy(body)
        ))),
        _ => Err(remote(format!(
            "the provider failed: {}",
            String::from_utf8_lossy(body)
        ))),
    }
}

/// Several providers for one client, tried in order. The one that answered
/// last is tried first, so a healthy backup is not left for a primary that is
/// down on every request. Which provider answers does not change who the
/// client is: [`RemoteTpmSigner`] and [`RemoteDeriveClient`] check every
/// signature against the public key they were opened with, so a provider
/// holding a different key is refused, never silently taken for the same
/// machine.
pub struct FailoverTransport<T: Transport> {
    transports: Vec<T>,
    last_good: std::sync::atomic::AtomicUsize,
}

impl<T: Transport> FailoverTransport<T> {
    /// `transports` in order of preference; at least one.
    pub fn new(transports: Vec<T>) -> Self {
        assert!(
            !transports.is_empty(),
            "a failover transport needs a provider"
        );
        Self {
            transports,
            last_good: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl<T: Transport> Transport for FailoverTransport<T> {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
        use std::sync::atomic::Ordering;
        let n = self.transports.len();
        let start = self.last_good.load(Ordering::Acquire) % n;
        let mut failures = Vec::new();
        for i in 0..n {
            let at = (start + i) % n;
            match self.transports[at].call(request) {
                Ok(answer) => {
                    self.last_good.store(at, Ordering::Release);
                    return Ok(answer);
                }
                Err(e) => failures.push(format!("provider {at}: {e}")),
            }
        }
        Err(remote(format!(
            "no provider answered ({})",
            failures.join("; ")
        )))
    }
}

/// What a client holds: the provider's key for its label, reached over a
/// transport.
pub struct RemoteTpmSigner<T: Transport> {
    transport: T,
    label: String,
    public_key: [u8; 65],
}

impl<T: Transport> RemoteTpmSigner<T> {
    /// Opens the provider's key `label` and learns its public key.
    pub fn open(transport: T, label: &str) -> Result<Self> {
        let request = encode_request(KIND_PUBLIC_KEY, label, &[])?;
        let body = decode_answer(&transport.call(&request)?)?;
        let public_key: [u8; 65] = body
            .try_into()
            .map_err(|_| remote("public key is not 65 bytes"))?;
        if public_key[0] != 0x04 {
            return Err(remote("public key is not an uncompressed SEC1 point"));
        }
        Ok(Self {
            transport,
            label: label.to_string(),
            public_key,
        })
    }
}

impl<T: Transport> HardwareSigner for RemoteTpmSigner<T> {
    fn backend(&self) -> HardwareBackend {
        HardwareBackend::RemoteTpm
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn public_key_sec1(&self) -> Result<[u8; 65]> {
        Ok(self.public_key)
    }

    fn sign(&self, message: &[u8]) -> Result<DeviceSignature> {
        let request = encode_request(KIND_SIGN, &self.label, message)?;
        let sig: DeviceSignature = decode_answer(&self.transport.call(&request)?)?
            .try_into()
            .map_err(|_| remote("signature is not 64 bytes"))?;
        if !verify_p256(&self.public_key, message, &sig) {
            return Err(remote(
                "the signature does not verify under the provider's key",
            ));
        }
        Ok(sig)
    }

    fn sign_prehash(&self, digest: &[u8; 32]) -> Result<DeviceSignature> {
        let request = encode_request(KIND_SIGN_PREHASH, &self.label, digest)?;
        let sig: DeviceSignature = decode_answer(&self.transport.call(&request)?)?
            .try_into()
            .map_err(|_| remote("signature is not 64 bytes"))?;
        if !verify_p256_prehash(&self.public_key, digest, &sig) {
            return Err(remote(
                "the signature does not verify under the provider's key",
            ));
        }
        Ok(sig)
    }
}

/// One enrolled client: the key label it may use.
#[derive(Clone, Debug)]
pub struct Grant {
    pub label: String,
    /// Whether this client may also use keys derived from the provider's
    /// root, under `{label}/{sub-label}`.
    pub derived: bool,
}

/// Whether `message` begins with the domain `prefix`, either directly or as
/// the first length-prefixed field (a 4-byte big-endian length, then the
/// bytes), which is how records name the domain they are signed under.
fn in_domain(message: &[u8], prefix: &[u8]) -> bool {
    if message.starts_with(prefix) {
        return true;
    }
    let Some((len, rest)) = message.split_first_chunk::<4>() else {
        return false;
    };
    let len = u32::from_be_bytes(*len) as usize;
    len <= 255 && rest.len() >= len && rest.starts_with(prefix)
}

/// What a provider will do.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Enrolled clients, keyed by the identity the transport authenticated.
    pub clients: HashMap<Vec<u8>, Grant>,
    /// A message is signed only if it begins with one of these.
    pub allowed_prefixes: Vec<Vec<u8>>,
    /// Whether a caller-supplied digest is signed. Off unless the operator
    /// turns it on: a digest hides what is being signed.
    pub allow_prehash: bool,
    /// Signatures per client per minute.
    pub per_minute: u32,
    /// A derived key's sub-label must begin with one of these.
    pub derived_prefixes: Vec<String>,
}

/// Records what a provider signed, refused and for whom.
pub trait Audit: Send + Sync {
    fn record(&self, client: &[u8], kind: &str, outcome: &str);
}

/// Opens the provider's hardware key for a label.
pub trait KeyStore: Send + Sync {
    fn open(&self, label: &str) -> Result<Box<dyn HardwareSigner>>;
}

/// Answers requests on the machine that owns the TPM.
pub struct Provider<K: KeyStore, A: Audit> {
    keys: K,
    audit: A,
    policy: Policy,
    /// The enrolled clients. Starts as `policy.clients`; [`Self::replace_clients`]
    /// swaps it while the provider runs, so enrolling a device needs no restart.
    clients: RwLock<HashMap<Vec<u8>, Grant>>,
    derive: Option<Arc<dyn RemoteDerive>>,
    window: Mutex<HashMap<Vec<u8>, (Instant, u32)>>,
    /// One TPM command at a time; the rest wait in a bounded line.
    queue: TpmQueue,
    issuance: Option<Issuance>,
    clock: Arc<dyn Clock>,
}

/// What a provider needs to sign batch roots for an identity.
struct Issuance {
    versions: Arc<dyn IssuerVersions>,
    publics: Mutex<HashMap<String, ([u8; 32], Vec<u8>)>>,
}

impl<K: KeyStore, A: Audit> Provider<K, A> {
    pub fn new(keys: K, audit: A, policy: Policy) -> Self {
        Self {
            keys,
            audit,
            clients: RwLock::new(policy.clients.clone()),
            policy,
            derive: None,
            window: Mutex::new(HashMap::new()),
            queue: TpmQueue::new(QueueParams::default()),
            issuance: None,
            clock: Arc::new(SystemClock),
        }
    }

    /// Sets how the TPM command queue behaves.
    pub fn with_queue(mut self, params: QueueParams) -> Self {
        self.queue = TpmQueue::new(params);
        self
    }

    /// Lets enrolled clients with derived keys have batch roots signed by
    /// the identity key `versions` names. Needs a derivation root.
    pub fn with_identity_versions(mut self, versions: Arc<dyn IssuerVersions>) -> Self {
        self.issuance = Some(Issuance {
            versions,
            publics: Mutex::new(HashMap::new()),
        });
        self
    }

    /// Replaces the clock delegations are dated by.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Requests waiting for the TPM.
    pub fn queue_waiting(&self) -> usize {
        self.queue.waiting()
    }

    /// Lets enrolled clients that are granted it use keys derived from
    /// `root`, operation by operation.
    pub fn with_derivation(mut self, root: Arc<dyn RemoteDerive>) -> Self {
        self.derive = Some(root);
        self
    }

    /// Replaces the enrolled clients. Requests already running finish under
    /// the grant they were admitted with; rate windows, the TPM queue and
    /// everything else are untouched, so a client present before and after
    /// notices nothing.
    pub fn replace_clients(&self, clients: HashMap<Vec<u8>, Grant>) {
        *self.clients.write().expect("clients") = clients;
    }

    fn within_rate(&self, client: &[u8]) -> bool {
        let mut window = self.window.lock().expect("rate window");
        let now = Instant::now();
        let slot = window.entry(client.to_vec()).or_insert((now, 0));
        if now.duration_since(slot.0) >= Duration::from_secs(60) {
            *slot = (now, 0);
        }
        if slot.1 >= self.policy.per_minute {
            return false;
        }
        slot.1 += 1;
        true
    }

    /// Answers one request from `client`, the identity the transport
    /// authenticated.
    pub fn handle(&self, client: &[u8], request: &[u8]) -> Vec<u8> {
        self.handle_capped(client, request, None)
    }

    /// Like [`Self::handle`], and a delegation issued by this call ends no
    /// later than `not_after_cap_ms`, the end of the grant the request
    /// arrived under.
    pub fn handle_capped(
        &self,
        client: &[u8],
        request: &[u8],
        not_after_cap_ms: Option<u64>,
    ) -> Vec<u8> {
        let refuse = |kind: &str, why: &str| {
            self.audit.record(client, kind, &format!("refused: {why}"));
            answer(STATUS_REFUSED, why.as_bytes())
        };
        let req = match decode_request(request) {
            Ok(r) => r,
            Err(why) => return refuse("malformed", why),
        };
        let kind = match req.kind {
            KIND_PUBLIC_KEY => "public-key",
            KIND_SIGN => "sign",
            KIND_SIGN_PREHASH => "sign-prehash",
            KIND_ED_PUBLIC..=KIND_P256_SIGN => "derived",
            KIND_SIGN_ROOT => "sign-root",
            _ => return refuse("unknown", "unknown request kind"),
        };
        let Some(grant) = self.clients.read().expect("clients").get(client).cloned() else {
            return refuse(kind, "client is not enrolled");
        };
        let own = req.label == grant.label
            || req
                .label
                .strip_prefix(grant.label.as_str())
                .is_some_and(|rest| rest.starts_with('/'));
        if !own {
            return refuse(kind, "client may not use that key");
        }
        // Everything below reaches the TPM: one command at a time, in order,
        // the rest waiting a bounded time in a bounded line.
        let run = self.queue.run(
            || self.after_policy(client, kind, &grant, &req, not_after_cap_ms),
            |e: &DeviceKeyError| is_transient(&e.to_string()),
        );
        match run {
            Ok(Ok(answer)) => answer,
            Ok(Err(e)) => {
                self.audit.record(client, kind, &format!("error: {e}"));
                answer(STATUS_ERROR, e.to_string().as_bytes())
            }
            Err(busy) => refuse(kind, &busy.to_string()),
        }
    }

    /// The part of a request that touches the TPM. `Err` only for a TPM
    /// failure the queue may retry.
    fn after_policy(
        &self,
        client: &[u8],
        kind: &str,
        grant: &Grant,
        req: &Request<'_>,
        _not_after_cap_ms: Option<u64>,
    ) -> Result<Vec<u8>> {
        let refuse = |kind: &str, why: &str| {
            self.audit.record(client, kind, &format!("refused: {why}"));
            answer(STATUS_REFUSED, why.as_bytes())
        };
        if req.kind == KIND_SIGN_ROOT {
            return self.handle_sign_root(client, grant, req);
        }
        if (KIND_ED_PUBLIC..=KIND_P256_SIGN).contains(&req.kind) {
            return Ok(self.handle_derived(client, grant, req));
        }
        Ok(self.base_request(client, kind, req, &refuse))
    }

    fn base_request(
        &self,
        client: &[u8],
        kind: &str,
        req: &Request<'_>,
        refuse: &dyn Fn(&str, &str) -> Vec<u8>,
    ) -> Vec<u8> {
        let signer = match self.keys.open(req.label) {
            Ok(s) => s,
            Err(e) => {
                self.audit.record(client, kind, &format!("error: {e}"));
                return answer(STATUS_ERROR, e.to_string().as_bytes());
            }
        };
        match req.kind {
            KIND_PUBLIC_KEY => match signer.public_key_sec1() {
                Ok(pk) => {
                    self.audit.record(client, kind, "ok");
                    answer(STATUS_OK, &pk)
                }
                Err(e) => answer(STATUS_ERROR, e.to_string().as_bytes()),
            },
            KIND_SIGN => {
                if !self
                    .policy
                    .allowed_prefixes
                    .iter()
                    .any(|p| in_domain(req.body, p))
                {
                    return refuse(kind, "message does not begin with an allowed domain");
                }
                if !self.within_rate(client) {
                    return refuse(kind, "rate limit");
                }
                match signer.sign(req.body) {
                    Ok(sig) => {
                        self.audit.record(client, kind, "ok");
                        answer(STATUS_OK, &sig)
                    }
                    Err(e) => {
                        self.audit.record(client, kind, &format!("error: {e}"));
                        answer(STATUS_ERROR, e.to_string().as_bytes())
                    }
                }
            }
            _ => {
                if !self.policy.allow_prehash {
                    return refuse(kind, "signing a bare digest is not enabled");
                }
                let Ok(digest) = <[u8; 32]>::try_from(req.body) else {
                    return refuse(kind, "digest is not 32 bytes");
                };
                if !self.within_rate(client) {
                    return refuse(kind, "rate limit");
                }
                match signer.sign_prehash(&digest) {
                    Ok(sig) => {
                        self.audit.record(client, kind, "ok");
                        answer(STATUS_OK, &sig)
                    }
                    Err(e) => answer(STATUS_ERROR, e.to_string().as_bytes()),
                }
            }
        }
    }
}

impl<K: KeyStore, A: Audit> Provider<K, A> {
    /// Signs a batch root with the identity key. The request carries the
    /// identity, the root and the count; the provider adds its own time and
    /// the identity key version it holds, so it never signs caller-chosen
    /// bytes.
    fn handle_sign_root(&self, client: &[u8], grant: &Grant, req: &Request<'_>) -> Result<Vec<u8>> {
        let refuse = |why: &str| {
            self.audit
                .record(client, "sign-root", &format!("refused: {why}"));
            answer(STATUS_REFUSED, why.as_bytes())
        };
        if !grant.derived {
            return Ok(refuse("derived keys are not enabled for this client"));
        }
        let (Some(root_key), Some(issuance)) = (&self.derive, &self.issuance) else {
            return Ok(refuse("this provider signs no batches"));
        };
        let request = match SignRootRequest::from_bytes(req.body) {
            Ok(r) => r,
            Err(e) => return Ok(refuse(&e.to_string())),
        };
        if request.count == 0 {
            return Ok(refuse("an empty batch"));
        }
        let (version, sub) = match issuance.versions.current(&request.identity) {
            Ok(v) => v,
            Err(e) => return Ok(refuse(&e.to_string())),
        };
        if !self
            .policy
            .derived_prefixes
            .iter()
            .any(|p| sub.starts_with(p.as_str()))
        {
            return Ok(refuse("the identity key is not in an allowed domain"));
        }
        if !self.within_rate(client) {
            return Ok(refuse("rate limit"));
        }
        let label = format!("{}/{}", grant.label, sub);
        let (ed, ml) = {
            let cached = issuance
                .publics
                .lock()
                .expect("publics")
                .get(&label)
                .cloned();
            match cached {
                Some(p) => p,
                None => {
                    let p = issuer_publics(root_key.as_ref(), &label)?;
                    issuance
                        .publics
                        .lock()
                        .expect("publics")
                        .insert(label.clone(), p.clone());
                    p
                }
            }
        };
        let mut sig = RootSignature {
            identity: request.identity,
            issuer_version: version,
            issuer_ed25519: ed,
            issuer_ml_dsa: ml,
            signed_at_ms: self.clock.now_ms(),
            count: request.count,
            root: request.root,
            ed_signature: [0; 64],
            ml_dsa_signature: Vec::new(),
        };
        let statement = sig.statement();
        sig.ed_signature = root_key.ed25519_sign(&label, &statement)?;
        sig.ml_dsa_signature =
            root_key.ml_dsa65_sign(&label, tenzro_crypto::pq::context::BATCH_ROOT, &statement)?;
        self.audit.record(client, "sign-root", "ok");
        Ok(answer(STATUS_OK, &sig.to_bytes()))
    }
}

/// What a requesting machine sends to have a batch root signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignRootRequest {
    pub identity: String,
    pub root: [u8; 32],
    pub count: u32,
}

impl SignRootRequest {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.identity.len() as u32).to_be_bytes());
        out.extend_from_slice(self.identity.as_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.count.to_be_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> DelegationResult<Self> {
        let mut r = crate::delegation::Reader(bytes);
        let identity = std::str::from_utf8(r.lp_raw(256)?)
            .map_err(|_| DelegationError::Malformed("identity is not UTF-8"))?
            .to_string();
        let root = r.arr::<32>()?;
        let count = u32::from_be_bytes(r.arr::<4>()?);
        r.done()?;
        Ok(Self {
            identity,
            root,
            count,
        })
    }
}

/// A [`RootSigner`] whose hardware is a provider's TPM, reached over a
/// [`Transport`]. Holds no key.
pub struct RemoteRootSigner<T: Transport> {
    transport: T,
    label: String,
    identity: String,
}

impl<T: Transport> RemoteRootSigner<T> {
    pub fn new(transport: T, label: &str, identity: &str) -> Self {
        Self {
            transport,
            label: label.to_string(),
            identity: identity.to_string(),
        }
    }
}

impl<T: Transport> RootSigner for RemoteRootSigner<T> {
    fn sign_root(
        &self,
        root: &[u8; 32],
        count: u32,
        _now_ms: u64,
    ) -> DelegationResult<RootSignature> {
        let body = SignRootRequest {
            identity: self.identity.clone(),
            root: *root,
            count,
        }
        .to_bytes();
        let request = encode_request(KIND_SIGN_ROOT, &self.label, &body)
            .map_err(|e| DelegationError::Provider(e.to_string()))?;
        let answer = self
            .transport
            .call(&request)
            .map_err(|e| DelegationError::Provider(e.to_string()))?;
        let bytes = decode_answer(&answer).map_err(|e| DelegationError::Provider(e.to_string()))?;
        let sig = RootSignature::from_bytes(&bytes)?;
        if sig.identity != self.identity || sig.root != *root || sig.count != count {
            return Err(DelegationError::Provider(
                "the provider signed another batch".into(),
            ));
        }
        sig.verify_signatures()?;
        Ok(sig)
    }
}

impl<K: KeyStore, A: Audit> Provider<K, A> {
    fn handle_derived(&self, client: &[u8], grant: &Grant, req: &Request<'_>) -> Vec<u8> {
        let refuse = |why: &str| {
            self.audit
                .record(client, "derived", &format!("refused: {why}"));
            answer(STATUS_REFUSED, why.as_bytes())
        };
        if !grant.derived {
            return refuse("derived keys are not enabled for this client");
        }
        let Some(root) = &self.derive else {
            return refuse("this provider has no derivation root");
        };
        let Some((&sub_len, rest)) = req.body.split_first() else {
            return refuse("short derived request");
        };
        let sub_len = sub_len as usize;
        if rest.len() < sub_len {
            return refuse("short derived request");
        }
        let (sub, args) = rest.split_at(sub_len);
        let Ok(sub) = std::str::from_utf8(sub) else {
            return refuse("sub-label is not UTF-8");
        };
        if !self
            .policy
            .derived_prefixes
            .iter()
            .any(|p| sub.starts_with(p.as_str()))
        {
            return refuse("sub-label is not in an allowed domain");
        }
        let signs = matches!(
            req.kind,
            KIND_ED_SIGN
                | KIND_VRF_PROVE
                | KIND_X_AGREE
                | KIND_MLDSA_SIGN
                | KIND_P256_SIGN
                | KIND_KEM_DECAPSULATE
        );
        if signs && !self.within_rate(client) {
            return refuse("rate limit");
        }
        let label = format!("{}/{}", grant.label, sub);
        let result: Result<Vec<u8>> = match req.kind {
            KIND_ED_PUBLIC => root.ed25519_public(&label).map(|k| k.to_vec()),
            KIND_ED_SIGN => root.ed25519_sign(&label, args).map(|s| s.to_vec()),
            KIND_VRF_PROVE => root.vrf_prove(&label, args).map(|p| p.0.to_vec()),
            KIND_X_PUBLIC => root.x25519_public(&label).map(|k| k.to_vec()),
            KIND_X_AGREE => match <[u8; 32]>::try_from(args) {
                Ok(peer) => root.x25519_agree(&label, &peer).map(|s| s.to_vec()),
                Err(_) => return refuse("peer key is not 32 bytes"),
            },
            KIND_MLDSA_PUBLIC => root.ml_dsa65_public(&label),
            KIND_KEM_PUBLIC => root.ml_kem768_public(&label),
            KIND_KEM_DECAPSULATE => root.ml_kem768_decapsulate(&label, args).map(|s| s.to_vec()),
            KIND_MLDSA_SIGN => {
                let Some((&ctx_len, rest)) = args.split_first() else {
                    return refuse("short ML-DSA request");
                };
                if rest.len() < ctx_len as usize {
                    return refuse("short ML-DSA request");
                }
                let (ctx, message) = rest.split_at(ctx_len as usize);
                root.ml_dsa65_sign(&label, ctx, message)
            }
            KIND_P256_PUBLIC => root.p256_public(&label).map(|k| k.to_vec()),
            KIND_P256_SIGN => match <[u8; 32]>::try_from(args) {
                Ok(hash) => root.p256_sign_prehash(&label, &hash).map(|s| s.to_vec()),
                Err(_) => return refuse("hash is not 32 bytes"),
            },
            _ => return refuse("unknown request kind"),
        };
        match result {
            Ok(bytes) => {
                self.audit.record(client, "derived", "ok");
                answer(STATUS_OK, &bytes)
            }
            Err(e) => {
                self.audit.record(client, "derived", &format!("error: {e}"));
                answer(STATUS_ERROR, e.to_string().as_bytes())
            }
        }
    }
}

/// Node keys (validator, VRF, sealing, access-token) derived and used in the
/// provider's TPM, asked for operation by operation.
pub struct RemoteDeriveClient<T: Transport> {
    transport: T,
    label: String,
    publics: Mutex<HashMap<(u8, String), Vec<u8>>>,
}

impl<T: Transport> RemoteDeriveClient<T> {
    pub fn new(transport: T, label: &str) -> Self {
        Self {
            transport,
            label: label.to_string(),
            publics: Mutex::new(HashMap::new()),
        }
    }

    fn ask(&self, kind: u8, sub: &str, args: &[u8]) -> Result<Vec<u8>> {
        if sub.len() > 255 {
            return Err(remote("sub-label too long"));
        }
        let mut body = Vec::with_capacity(1 + sub.len() + args.len());
        body.push(sub.len() as u8);
        body.extend_from_slice(sub.as_bytes());
        body.extend_from_slice(args);
        let request = encode_request(kind, &self.label, &body)?;
        decode_answer(&self.transport.call(&request)?)
    }

    fn public(&self, kind: u8, sub: &str) -> Result<Vec<u8>> {
        let key = (kind, sub.to_string());
        if let Some(p) = self.publics.lock().expect("publics").get(&key) {
            return Ok(p.clone());
        }
        let p = self.ask(kind, sub, &[])?;
        self.publics.lock().expect("publics").insert(key, p.clone());
        Ok(p)
    }
}

fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| remote(format!("{what} is not {N} bytes")))
}

impl<T: Transport> RemoteDerive for RemoteDeriveClient<T> {
    fn ed25519_public(&self, label: &str) -> Result<[u8; 32]> {
        fixed(self.public(KIND_ED_PUBLIC, label)?, "Ed25519 key")
    }

    fn ed25519_sign(&self, label: &str, message: &[u8]) -> Result<[u8; 64]> {
        let public = self.ed25519_public(label)?;
        let sig: [u8; 64] = fixed(self.ask(KIND_ED_SIGN, label, message)?, "signature")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public)
            .map_err(|e| remote(format!("Ed25519 key: {e}")))?;
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| {
                remote("the Ed25519 signature does not verify under the provider's key")
            })?;
        Ok(sig)
    }

    fn vrf_prove(&self, label: &str, alpha: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof> {
        Ok(tenzro_crypto::vrf::VrfProof(fixed(
            self.ask(KIND_VRF_PROVE, label, alpha)?,
            "VRF proof",
        )?))
    }

    fn x25519_public(&self, label: &str) -> Result<[u8; 32]> {
        fixed(self.public(KIND_X_PUBLIC, label)?, "X25519 key")
    }

    fn x25519_agree(&self, label: &str, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let mut raw = self.ask(KIND_X_AGREE, label, peer)?;
        let out: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| remote("agreement is not 32 bytes"))?;
        zeroize::Zeroize::zeroize(&mut raw);
        Ok(Zeroizing::new(out))
    }

    fn ml_dsa65_public(&self, label: &str) -> Result<Vec<u8>> {
        self.public(KIND_MLDSA_PUBLIC, label)
    }

    fn ml_kem768_public(&self, label: &str) -> Result<Vec<u8>> {
        self.public(KIND_KEM_PUBLIC, label)
    }

    fn ml_kem768_decapsulate(&self, label: &str, ciphertext: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut raw = self.ask(KIND_KEM_DECAPSULATE, label, ciphertext)?;
        let out: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| remote("decapsulation is not 32 bytes"))?;
        zeroize::Zeroize::zeroize(&mut raw);
        Ok(Zeroizing::new(out))
    }

    fn ml_dsa65_sign(&self, label: &str, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if ctx.len() > 255 {
            return Err(remote("context too long"));
        }
        let mut args = Vec::with_capacity(1 + ctx.len() + message.len());
        args.push(ctx.len() as u8);
        args.extend_from_slice(ctx);
        args.extend_from_slice(message);
        self.ask(KIND_MLDSA_SIGN, label, &args)
    }

    fn p256_public(&self, label: &str) -> Result<[u8; 64]> {
        fixed(self.public(KIND_P256_PUBLIC, label)?, "P-256 key")
    }

    fn p256_sign_prehash(&self, label: &str, hash: &[u8; 32]) -> Result<[u8; 64]> {
        let public = self.p256_public(label)?;
        let sig: [u8; 64] = fixed(self.ask(KIND_P256_SIGN, label, hash)?, "signature")?;
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..].copy_from_slice(&public);
        if !verify_p256_prehash(&sec1, hash, &sig) {
            return Err(remote(
                "the P-256 signature does not verify under the provider's key",
            ));
        }
        Ok(sig)
    }
}

// ---------------------------------------------------------------------------
// The key holder's local socket
// ---------------------------------------------------------------------------
//
// A node, and any other process on the machine that signs for it (the CLI's
// `validator register-machine`), reaches the provider through the key
// holder's local socket. The client side of that socket lives here so the
// node and the CLI share one implementation; the holder itself (the server)
// is `tenzro-node tpm key-holder`.

/// The key holder operation that carries a signing request to the provider.
pub const HOLDER_OP_CALL: u8 = 1;

const HOLDER_STATUS_OK: u8 = 0;

/// Largest frame either side of the holder socket sends.
const HOLDER_MAX_FRAME: usize = 1 << 20;

/// Longest one holder operation may take: the holder's own request timeout
/// (20 s) with room for its retries.
const HOLDER_TIMEOUT: Duration = Duration::from_secs(60);

/// Sends one operation to the key holder at `socket` and returns its answer.
#[cfg(unix)]
pub fn holder_request(
    socket: &std::path::Path,
    op: u8,
    payload: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).map_err(|e| {
        format!(
            "the key holder at {} is not reachable: {e}",
            socket.display()
        )
    })?;
    let timeout = Some(HOLDER_TIMEOUT);
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|e| format!("key holder socket: {e}"))?;
    let mut out = vec![op];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    stream
        .write_all(&out)
        .map_err(|e| format!("key holder socket: {e}"))?;
    let mut head = [0u8; 5];
    stream
        .read_exact(&mut head)
        .map_err(|e| format!("the key holder did not answer: {e}"))?;
    let len = u32::from_be_bytes(head[1..5].try_into().expect("four bytes")) as usize;
    if len > HOLDER_MAX_FRAME {
        return Err("the key holder's answer is too large".into());
    }
    let mut body = vec![0u8; len];
    stream
        .read_exact(&mut body)
        .map_err(|e| format!("the key holder did not answer: {e}"))?;
    match head[0] {
        HOLDER_STATUS_OK => Ok(body),
        _ => Err(String::from_utf8_lossy(&body).into_owned()),
    }
}

/// Sends one operation to the key holder at `socket` and returns its answer.
#[cfg(not(unix))]
pub fn holder_request(
    _socket: &std::path::Path,
    _op: u8,
    _payload: &[u8],
) -> std::result::Result<Vec<u8>, String> {
    Err("the TPM key holder needs a Unix socket, which this platform does not have".into())
}

/// Carries a request to the provider through the local key holder.
#[derive(Debug, Clone)]
pub struct HolderTransport {
    socket: std::path::PathBuf,
}

impl HolderTransport {
    pub fn new(socket: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl Transport for HolderTransport {
    fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
        holder_request(&self.socket, HOLDER_OP_CALL, request)
            .map_err(|e| DeviceKeyError::Tpm(format!("remote TPM: {e}")))
    }
}

/// From now on every hardware key and every derived key this process asks
/// for lives in the providers' TPM, reached through the key holder at
/// `socket`: `{grant_label}/{key label}` there. Set once per process, before
/// any key use.
pub fn use_key_holder(grant_label: &str, socket: &std::path::Path) -> Result<()> {
    let grant = grant_label.to_string();
    let path = socket.to_path_buf();
    crate::signer::use_remote_signers(Box::new(move |label| {
        let signer = RemoteTpmSigner::open(
            HolderTransport::new(path.clone()),
            &format!("{grant}/{label}"),
        )?;
        Ok(Box::new(signer) as Box<dyn HardwareSigner>)
    }))?;
    crate::derive::use_remote_root(Arc::new(RemoteDeriveClient::new(
        HolderTransport::new(socket),
        grant_label,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::tests::SoftwareTestSigner;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    struct Keys(SigningKey);
    impl KeyStore for Keys {
        fn open(&self, label: &str) -> Result<Box<dyn HardwareSigner>> {
            if label == "pi-1" || label.starts_with("pi-1/") {
                Ok(Box::new(SoftwareTestSigner(self.0.clone())))
            } else {
                Err(DeviceKeyError::NotFound(label.into()))
            }
        }
    }

    #[derive(Default)]
    struct Log(Mutex<Vec<String>>);
    impl Audit for Arc<Log> {
        fn record(&self, _client: &[u8], kind: &str, outcome: &str) {
            self.0.lock().unwrap().push(format!("{kind}: {outcome}"));
        }
    }

    struct Loop<K: KeyStore, A: Audit> {
        provider: Provider<K, A>,
        client: Vec<u8>,
    }
    impl<K: KeyStore, A: Audit> Transport for Loop<K, A> {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
            Ok(self.provider.handle(&self.client, request))
        }
    }

    fn policy(client: &[u8], prehash: bool, per_minute: u32) -> Policy {
        Policy {
            clients: HashMap::from([(
                client.to_vec(),
                Grant {
                    label: "pi-1".into(),
                    derived: true,
                },
            )]),
            allowed_prefixes: vec![b"tenzro/".to_vec()],
            allow_prehash: prehash,
            per_minute,
            derived_prefixes: vec!["tenzro/".to_string()],
        }
    }

    fn setup(
        client: &[u8],
        enrolled: &[u8],
        prehash: bool,
        per_minute: u32,
    ) -> (Loop<Keys, Arc<Log>>, Arc<Log>) {
        let log = Arc::new(Log::default());
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        (
            Loop {
                provider: Provider::new(
                    Keys(key),
                    log.clone(),
                    policy(enrolled, prehash, per_minute),
                ),
                client: client.to_vec(),
            },
            log,
        )
    }

    #[test]
    fn an_enrolled_client_signs_through_the_provider_and_the_signature_verifies() {
        let (t, log) = setup(b"pi", b"pi", false, 10);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        assert_eq!(signer.backend(), HardwareBackend::RemoteTpm);
        let sig = signer.sign(b"tenzro/session/1 hello").unwrap();
        assert!(verify_p256(
            &signer.public_key_sec1().unwrap(),
            b"tenzro/session/1 hello",
            &sig
        ));
        assert!(log.0.lock().unwrap().iter().any(|l| l == "sign: ok"));
    }

    #[test]
    fn a_client_that_is_not_enrolled_gets_nothing() {
        let (t, log) = setup(b"stranger", b"pi", false, 10);
        let err = RemoteTpmSigner::open(t, "pi-1").err().expect("refused");
        assert!(err.to_string().contains("not enrolled"), "{err}");
        assert!(log.0.lock().unwrap()[0].contains("refused"));
    }

    #[test]
    fn a_client_may_not_use_another_clients_key() {
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let err = RemoteTpmSigner::open(t, "pi-2").err().expect("refused");
        assert!(err.to_string().contains("may not use that key"), "{err}");
    }

    #[test]
    fn a_message_outside_the_allowed_domains_is_not_signed() {
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        let err = signer.sign(b"transfer all funds").unwrap_err();
        assert!(err.to_string().contains("allowed domain"), "{err}");
    }

    #[test]
    fn a_message_naming_its_domain_as_a_length_prefixed_field_is_signed() {
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        let domain = b"tenzro/transport/endpoint-record";
        let mut message = (domain.len() as u32).to_be_bytes().to_vec();
        message.extend_from_slice(domain);
        message.extend_from_slice(b"rest of the record");
        assert!(signer.sign(&message).is_ok());
        let mut other = 5u32.to_be_bytes().to_vec();
        other.extend_from_slice(b"other and more");
        assert!(signer.sign(&other).is_err());
    }

    #[test]
    fn a_bare_digest_is_refused_unless_the_operator_allows_it() {
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        let err = signer.sign_prehash(&[1u8; 32]).unwrap_err();
        assert!(err.to_string().contains("bare digest"), "{err}");

        let (t, _) = setup(b"pi", b"pi", true, 10);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        assert!(signer.sign_prehash(&[1u8; 32]).is_ok());
    }

    #[test]
    fn signing_is_rate_limited_per_client() {
        let (t, _) = setup(b"pi", b"pi", false, 2);
        let signer = RemoteTpmSigner::open(t, "pi-1").unwrap();
        assert!(signer.sign(b"tenzro/a").is_ok());
        assert!(signer.sign(b"tenzro/b").is_ok());
        let err = signer.sign(b"tenzro/c").unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{err}");
    }

    #[test]
    fn a_provider_that_returns_a_signature_that_does_not_verify_is_refused_by_the_client() {
        struct Liar(Loop<Keys, Arc<Log>>);
        impl Transport for Liar {
            fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
                let mut a = self.0.call(request)?;
                if request[1] == KIND_SIGN {
                    let n = a.len();
                    a[n - 1] ^= 1;
                }
                Ok(a)
            }
        }
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let signer = RemoteTpmSigner::open(Liar(t), "pi-1").unwrap();
        let err = signer.sign(b"tenzro/x").unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn an_unknown_wire_version_is_refused() {
        let (t, _) = setup(b"pi", b"pi", false, 10);
        let mut request = encode_request(KIND_PUBLIC_KEY, "pi-1", &[]).unwrap();
        request[0] = 9;
        let answer = t.call(&request).unwrap();
        assert_eq!(answer[1], STATUS_REFUSED);
    }

    /// A derivation root standing in for the TPM's: keys from a hash of the
    /// label, and a record of the labels it was asked for.
    #[derive(Default)]
    struct FakeRoot(Mutex<Vec<String>>);

    impl FakeRoot {
        fn seed(&self, label: &str) -> [u8; 32] {
            self.0.lock().unwrap().push(label.to_string());
            Sha256::digest(label.as_bytes()).into()
        }
    }

    impl RemoteDerive for Arc<FakeRoot> {
        fn ed25519_public(&self, label: &str) -> Result<[u8; 32]> {
            Ok(ed25519_dalek::SigningKey::from_bytes(&self.seed(label))
                .verifying_key()
                .to_bytes())
        }
        fn ed25519_sign(&self, label: &str, message: &[u8]) -> Result<[u8; 64]> {
            use ed25519_dalek::Signer;
            Ok(ed25519_dalek::SigningKey::from_bytes(&self.seed(label))
                .sign(message)
                .to_bytes())
        }
        fn vrf_prove(&self, label: &str, _: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof> {
            self.seed(label);
            Ok(tenzro_crypto::vrf::VrfProof([7u8; 80]))
        }
        fn x25519_public(&self, label: &str) -> Result<[u8; 32]> {
            Ok(self.seed(label))
        }
        fn x25519_agree(&self, label: &str, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
            self.seed(label);
            Ok(Zeroizing::new(*peer))
        }
        fn ml_dsa65_public(&self, label: &str) -> Result<Vec<u8>> {
            Ok(self.seed(label).to_vec())
        }
        fn ml_kem768_public(&self, label: &str) -> Result<Vec<u8>> {
            Ok(self.seed(label).to_vec())
        }
        fn ml_kem768_decapsulate(&self, label: &str, _: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            Ok(Zeroizing::new(self.seed(label)))
        }
        fn ml_dsa65_sign(&self, label: &str, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
            self.seed(label);
            Ok([ctx, message].concat())
        }
        fn p256_public(&self, label: &str) -> Result<[u8; 64]> {
            let k = SigningKey::from_slice(&self.seed(label)).unwrap();
            let point = k.verifying_key().to_sec1_point(false);
            Ok(point.as_bytes()[1..].try_into().unwrap())
        }
        fn p256_sign_prehash(&self, label: &str, hash: &[u8; 32]) -> Result<[u8; 64]> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let k = SigningKey::from_slice(&self.seed(label)).unwrap();
            let sig: p256::ecdsa::Signature = k.sign_prehash(hash).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    fn derived_setup(
        client: &[u8],
        derived: bool,
    ) -> (RemoteDeriveClient<Loop<Keys, Arc<Log>>>, Arc<FakeRoot>) {
        let root = Arc::new(FakeRoot::default());
        let log = Arc::new(Log::default());
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let mut p = policy(b"pi", false, 60);
        p.clients.get_mut(b"pi".as_slice()).unwrap().derived = derived;
        let transport = Loop {
            provider: Provider::new(Keys(key), log, p).with_derivation(Arc::new(root.clone())),
            client: client.to_vec(),
        };
        (RemoteDeriveClient::new(transport, "pi-1"), root)
    }

    #[test]
    fn derived_keys_are_used_in_the_provider_under_the_clients_namespace() {
        let (client, root) = derived_setup(b"pi", true);
        let message = b"hello";
        let sig = client
            .ed25519_sign("tenzro/validator/ed25519", message)
            .unwrap();
        assert_eq!(sig.len(), 64);
        let hash = [3u8; 32];
        assert!(client.p256_sign_prehash("tenzro/access", &hash).is_ok());
        assert_eq!(
            client.ml_dsa65_sign("tenzro/v/ml", b"ctx", b"msg").unwrap(),
            b"ctxmsg"
        );
        assert_eq!(
            *client.x25519_agree("tenzro/seal", &[9u8; 32]).unwrap(),
            [9u8; 32]
        );
        assert_eq!(client.vrf_prove("tenzro/vrf", b"a").unwrap().0, [7u8; 80]);
        let seen = root.0.lock().unwrap();
        assert!(
            seen.iter().all(|l| l.starts_with("pi-1/tenzro/")),
            "{seen:?}"
        );
    }

    #[test]
    fn a_client_not_granted_derived_keys_is_refused() {
        let (client, _) = derived_setup(b"pi", false);
        let err = client
            .ed25519_public("tenzro/validator/ed25519")
            .unwrap_err();
        assert!(err.to_string().contains("not enabled"), "{err}");
    }

    #[test]
    fn a_derived_sub_label_outside_the_allowed_domain_is_refused() {
        let (client, root) = derived_setup(b"pi", true);
        let err = client.ed25519_sign("other/label", b"m").unwrap_err();
        assert!(err.to_string().contains("allowed domain"), "{err}");
        assert!(root.0.lock().unwrap().is_empty());
    }

    #[test]
    fn a_derived_signature_that_does_not_verify_is_refused_by_the_client() {
        struct Liar(Loop<Keys, Arc<Log>>);
        impl Transport for Liar {
            fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
                let mut a = self.0.call(request)?;
                if request[1] == KIND_ED_SIGN {
                    let n = a.len();
                    a[n - 1] ^= 1;
                }
                Ok(a)
            }
        }
        let root = Arc::new(FakeRoot::default());
        let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let t = Loop {
            provider: Provider::new(
                Keys(key),
                Arc::new(Log::default()),
                policy(b"pi", false, 60),
            )
            .with_derivation(Arc::new(root)),
            client: b"pi".to_vec(),
        };
        let client = RemoteDeriveClient::new(Liar(t), "pi-1");
        let err = client
            .ed25519_sign("tenzro/validator/ed25519", b"m")
            .unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    /// Answers for a provider that is up, or fails when it is down; counts calls.
    struct Flaky<T: Transport> {
        inner: T,
        up: std::sync::atomic::AtomicBool,
        calls: std::sync::atomic::AtomicU32,
    }
    impl<T: Transport> Transport for Flaky<T> {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
            use std::sync::atomic::Ordering;
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.up.load(Ordering::SeqCst) {
                self.inner.call(request)
            } else {
                Err(remote("down"))
            }
        }
    }
    fn flaky(t: Loop<Keys, Arc<Log>>, up: bool) -> Flaky<Loop<Keys, Arc<Log>>> {
        Flaky {
            inner: t,
            up: std::sync::atomic::AtomicBool::new(up),
            calls: std::sync::atomic::AtomicU32::new(0),
        }
    }

    #[test]
    fn a_backup_provider_with_the_same_key_takes_over_and_stays_taken() {
        use std::sync::atomic::Ordering;
        // Two providers holding the same key (a duplicated key): one down, one up.
        let (a, _) = setup(b"pi", b"pi", false, 100);
        let (b, _) = setup(b"pi", b"pi", false, 100);
        let (a, b) = (flaky(a, true), flaky(b, true));
        let f = FailoverTransport::new(vec![a, b]);
        let signer = RemoteTpmSigner::open(f, "pi-1").unwrap();
        assert!(signer.sign(b"tenzro/one").is_ok());
        signer.transport.transports[0]
            .up
            .store(false, Ordering::SeqCst);
        assert!(signer.sign(b"tenzro/two").is_ok(), "the backup answers");
        let first_calls = signer.transport.transports[0].calls.load(Ordering::SeqCst);
        assert!(signer.sign(b"tenzro/three").is_ok());
        assert_eq!(
            signer.transport.transports[0].calls.load(Ordering::SeqCst),
            first_calls,
            "the backup is tried first once it has answered"
        );
    }

    #[test]
    fn a_backup_provider_holding_a_different_key_is_refused_not_taken_for_the_machine() {
        use std::sync::atomic::Ordering;
        let (a, _) = setup(b"pi", b"pi", false, 100);
        // The backup's TPM holds another key under the same label.
        let log = Arc::new(Log::default());
        let other = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let b = Loop {
            provider: Provider::new(Keys(other), log, policy(b"pi", false, 100)),
            client: b"pi".to_vec(),
        };
        let f = FailoverTransport::new(vec![flaky(a, true), flaky(b, true)]);
        let signer = RemoteTpmSigner::open(f, "pi-1").unwrap();
        assert!(signer.sign(b"tenzro/one").is_ok());
        signer.transport.transports[0]
            .up
            .store(false, Ordering::SeqCst);
        let err = signer.sign(b"tenzro/two").unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");
    }

    #[test]
    fn with_no_provider_up_the_error_names_every_one() {
        use std::sync::atomic::Ordering;
        let (a, _) = setup(b"pi", b"pi", false, 100);
        let (b, _) = setup(b"pi", b"pi", false, 100);
        let (a, b) = (flaky(a, true), flaky(b, true));
        let f = FailoverTransport::new(vec![a, b]);
        let signer = RemoteTpmSigner::open(f, "pi-1").unwrap();
        for t in &signer.transport.transports {
            t.up.store(false, Ordering::SeqCst);
        }
        let err = signer.sign(b"tenzro/x").unwrap_err().to_string();
        assert!(
            err.contains("provider 0") && err.contains("provider 1"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod delegation_tests {
    use super::*;
    use crate::delegation::tests::{Chain, ChainRoot, IDENTITY, ManualClock, VERIFY};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct NoKeys;
    impl KeyStore for NoKeys {
        fn open(&self, label: &str) -> Result<Box<dyn HardwareSigner>> {
            Err(DeviceKeyError::NotFound(label.into()))
        }
    }
    struct Silent;
    impl Audit for Silent {
        fn record(&self, _: &[u8], _: &str, _: &str) {}
    }

    /// A TPM that takes `cost` per command and records how many commands run
    /// at once.
    struct SlowRoot {
        inner: ChainRoot,
        cost: Duration,
        running: AtomicUsize,
        peak: AtomicUsize,
        ops: AtomicUsize,
        fail_first: AtomicUsize,
    }
    impl SlowRoot {
        fn new(chain: &Arc<Chain>, cost_ms: u64) -> Arc<Self> {
            Arc::new(Self {
                inner: ChainRoot(chain.clone()),
                cost: Duration::from_millis(cost_ms),
                running: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
                ops: AtomicUsize::new(0),
                fail_first: AtomicUsize::new(0),
            })
        }
        fn command<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.peak.fetch_max(now, Ordering::SeqCst);
            self.ops.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.cost);
            self.running.fetch_sub(1, Ordering::SeqCst);
            if self
                .fail_first
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(DeviceKeyError::Tpm("TPM_RC_RETRY".into()));
            }
            f()
        }
    }
    impl RemoteDerive for SlowRoot {
        fn ed25519_public(&self, l: &str) -> Result<[u8; 32]> {
            self.command(|| self.inner.ed25519_public(l))
        }
        fn ed25519_sign(&self, l: &str, m: &[u8]) -> Result<[u8; 64]> {
            self.command(|| self.inner.ed25519_sign(l, m))
        }
        fn vrf_prove(&self, l: &str, a: &[u8]) -> Result<tenzro_crypto::vrf::VrfProof> {
            self.inner.vrf_prove(l, a)
        }
        fn x25519_public(&self, l: &str) -> Result<[u8; 32]> {
            self.inner.x25519_public(l)
        }
        fn x25519_agree(&self, l: &str, p: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
            self.inner.x25519_agree(l, p)
        }
        fn ml_dsa65_public(&self, l: &str) -> Result<Vec<u8>> {
            self.command(|| self.inner.ml_dsa65_public(l))
        }
        fn ml_kem768_public(&self, l: &str) -> Result<Vec<u8>> {
            self.inner.ml_kem768_public(l)
        }
        fn ml_kem768_decapsulate(&self, l: &str, c: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
            self.inner.ml_kem768_decapsulate(l, c)
        }
        fn ml_dsa65_sign(&self, l: &str, c: &[u8], m: &[u8]) -> Result<Vec<u8>> {
            self.command(|| self.inner.ml_dsa65_sign(l, c, m))
        }
        fn p256_public(&self, l: &str) -> Result<[u8; 64]> {
            self.inner.p256_public(l)
        }
        fn p256_sign_prehash(&self, l: &str, h: &[u8; 32]) -> Result<[u8; 64]> {
            self.inner.p256_sign_prehash(l, h)
        }
    }

    const CLIENT: &[u8] = b"pi-client";

    struct Loop {
        provider: Arc<Provider<NoKeys, Silent>>,
        client: Vec<u8>,
        cap: Option<u64>,
    }
    impl Transport for Loop {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
            Ok(self.provider.handle_capped(&self.client, request, self.cap))
        }
    }

    fn provider(
        chain: &Arc<Chain>,
        root: Arc<SlowRoot>,
        clock: Arc<ManualClock>,
        queue: QueueParams,
        derived: bool,
    ) -> Arc<Provider<NoKeys, Silent>> {
        let policy = Policy {
            clients: HashMap::from([(
                CLIENT.to_vec(),
                Grant {
                    label: "pi-1".into(),
                    derived,
                },
            )]),
            allowed_prefixes: vec![],
            allow_prehash: false,
            per_minute: 100_000,
            derived_prefixes: vec!["tenzro/test/".into()],
        };
        Arc::new(
            Provider::new(NoKeys, Silent, policy)
                .with_derivation(root)
                .with_queue(queue)
                .with_identity_versions(chain.clone())
                .with_clock(clock),
        )
    }

    fn rig(
        cost_ms: u64,
        queue: QueueParams,
    ) -> (
        Arc<Chain>,
        Arc<ManualClock>,
        Arc<SlowRoot>,
        Arc<Provider<NoKeys, Silent>>,
    ) {
        let chain = Chain::new();
        let clock = Arc::new(ManualClock(std::sync::atomic::AtomicU64::new(1_000_000)));
        let root = SlowRoot::new(&chain, cost_ms);
        let p = provider(&chain, root.clone(), clock.clone(), queue, true);
        (chain, clock, root, p)
    }

    fn root_signer(p: &Arc<Provider<NoKeys, Silent>>) -> RemoteRootSigner<Loop> {
        RemoteRootSigner::new(
            Loop {
                provider: p.clone(),
                client: CLIENT.to_vec(),
                cap: None,
            },
            "pi-1",
            IDENTITY,
        )
    }

    #[test]
    fn a_burst_of_50_root_signatures_queues_through_one_tpm_and_all_pass() {
        let (_chain, _clock, root, p) = rig(8, QueueParams::default());
        let threads: Vec<_> = (0..50u8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || root_signer(&p).sign_root(&[i; 32], 1, 0).map(|_| ()))
            })
            .collect();
        for t in threads {
            t.join().unwrap().unwrap();
        }
        assert_eq!(
            root.peak.load(Ordering::SeqCst),
            1,
            "one TPM command at a time"
        );
        assert!(root.ops.load(Ordering::SeqCst) >= 50 * 2);
        assert_eq!(p.queue_waiting(), 0);
    }

    #[test]
    fn a_full_queue_is_refused_with_a_reason_and_the_rest_still_pass() {
        let queue = QueueParams {
            max_waiting: 2,
            ..QueueParams::default()
        };
        let (_chain, _clock, _root, p) = rig(80, queue);
        // Warm the public-key cache so each request is two commands.
        root_signer(&p).sign_root(&[0; 32], 1, 0).unwrap();
        let threads: Vec<_> = (0..12u8)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || root_signer(&p).sign_root(&[i; 32], 1, 0).map(|_| ()))
            })
            .collect();
        let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let busy = results
            .iter()
            .filter(|r| {
                matches!(r, Err(crate::delegation::DelegationError::Provider(m)) if m.contains("tpm busy: the queue is full"))
            })
            .count();
        assert!(ok >= 1 && busy >= 1, "ok {ok} busy {busy}");
        assert_eq!(ok + busy, 12, "every request was served or refused clearly");
    }

    #[test]
    fn a_temporary_tpm_error_is_retried_with_a_pause_and_the_root_still_signs() {
        let q = QueueParams {
            backoff_base_ms: 10,
            ..QueueParams::default()
        };
        let (_chain, _clock, root, p) = rig(1, q);
        root.fail_first.store(2, Ordering::SeqCst);
        root_signer(&p).sign_root(&[9; 32], 1, 0).unwrap();
    }

    #[test]
    fn a_provider_signs_a_batch_root_and_a_remote_signer_batches_through_it() {
        use crate::batch_signer::{BatchParams, Batcher};
        let (chain, clock, _root, p) = rig(0, QueueParams::default());
        let signer = RemoteRootSigner::new(
            Loop {
                provider: p.clone(),
                client: CLIENT.to_vec(),
                cap: None,
            },
            "pi-1",
            IDENTITY,
        );
        let mut b = Batcher::new(
            signer,
            BatchParams {
                max_batch: 3,
                flush_interval_ms: 1_000,
            },
        )
        .unwrap();
        let now = clock.0.load(Ordering::SeqCst);
        b.submit(b"a".to_vec(), now).unwrap();
        b.submit(b"b".to_vec(), now).unwrap();
        let f = b.submit(b"c".to_vec(), now).unwrap().expect("full");
        for (m, msg) in f.members.iter().zip([b"a", b"b", b"c"]) {
            m.verify(msg, chain.as_ref(), now, VERIFY).unwrap();
        }
    }

    #[test]
    fn a_provider_refuses_a_root_for_a_client_without_derived_keys_or_an_empty_batch() {
        use crate::batch_signer::RootSigner;
        let (_chain, clock, root, _p) = rig(0, QueueParams::default());
        let chain = Chain::new();
        let p = provider(&chain, root, clock, QueueParams::default(), false);
        let signer = RemoteRootSigner::new(
            Loop {
                provider: p,
                client: CLIENT.to_vec(),
                cap: None,
            },
            "pi-1",
            IDENTITY,
        );
        assert!(signer.sign_root(&[1; 32], 1, 0).is_err());
        let (_c, _k, _r, p2) = rig(0, QueueParams::default());
        let signer = RemoteRootSigner::new(
            Loop {
                provider: p2,
                client: CLIENT.to_vec(),
                cap: None,
            },
            "pi-1",
            IDENTITY,
        );
        assert!(signer.sign_root(&[1; 32], 0, 0).is_err());
        let other = RemoteRootSigner::new(
            Loop {
                provider: rig(0, QueueParams::default()).3,
                client: b"stranger".to_vec(),
                cap: None,
            },
            "pi-1",
            IDENTITY,
        );
        assert!(other.sign_root(&[1; 32], 1, 0).is_err());
    }
}

/// Guard: two clients of one provider asking for the consensus key get
/// two different keys, because the node asks for `{grant}/{label}` and the
/// provider opens exactly that label.
#[cfg(test)]
mod consensus_label_tests {
    use super::*;
    use crate::signer::tests::SoftwareTestSigner;
    use p256::ecdsa::SigningKey;
    use sha2::{Digest, Sha256};

    /// The consensus key label every node uses.
    const CONSENSUS: &str = "tenzro/consensus/validator";

    /// A provider key store whose key depends on the label it is asked for,
    /// as a TPM's does.
    struct PerLabel;
    impl KeyStore for PerLabel {
        fn open(&self, label: &str) -> Result<Box<dyn HardwareSigner>> {
            let seed: [u8; 32] = Sha256::digest(label.as_bytes()).into();
            Ok(Box::new(SoftwareTestSigner(
                SigningKey::from_slice(&seed).unwrap(),
            )))
        }
    }

    struct Quiet;
    impl Audit for Quiet {
        fn record(&self, _: &[u8], _: &str, _: &str) {}
    }

    struct As<'a>(&'a Provider<PerLabel, Quiet>, &'static [u8]);
    impl Transport for As<'_> {
        fn call(&self, request: &[u8]) -> Result<Vec<u8>> {
            Ok(self.0.handle(self.1, request))
        }
    }

    fn provider() -> Provider<PerLabel, Quiet> {
        let grant = |label: &str| Grant {
            label: label.into(),
            derived: false,
        };
        Provider::new(
            PerLabel,
            Quiet,
            Policy {
                clients: HashMap::from([
                    (b"pi".to_vec(), grant("pi")),
                    (b"tpm-host".to_vec(), grant("tpm-host")),
                ]),
                allowed_prefixes: vec![b"tenzro/".to_vec()],
                allow_prehash: false,
                per_minute: 60,
                derived_prefixes: vec!["tenzro/".to_string()],
            },
        )
    }

    /// What `remote_tpm::install` asks for: `{grant}/{label}`.
    fn consensus_key(p: &Provider<PerLabel, Quiet>, client: &'static [u8], grant: &str) -> Vec<u8> {
        RemoteTpmSigner::open(As(p, client), &format!("{grant}/{CONSENSUS}"))
            .expect("the client opens its own consensus key")
            .public_key_sec1()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn two_clients_of_one_provider_get_two_consensus_keys() {
        let p = provider();
        assert_ne!(
            consensus_key(&p, b"pi", "pi"),
            consensus_key(&p, b"tpm-host", "tpm-host")
        );
    }

    #[test]
    fn no_client_may_ask_for_the_shared_literal_consensus_label() {
        let p = provider();
        for client in [b"pi".as_slice(), b"tpm-host".as_slice()] {
            let t = As(&p, if client == b"pi" { b"pi" } else { b"tpm-host" });
            let err = RemoteTpmSigner::open(t, CONSENSUS).err().expect("refused");
            assert!(err.to_string().contains("may not use that key"), "{err}");
        }
    }
}
