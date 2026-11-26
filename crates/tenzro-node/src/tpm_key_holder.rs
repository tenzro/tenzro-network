//! The key holder of a machine with no TPM.
//!
//! `tenzro-node tpm key-holder` runs beside the node as its own service. At
//! start it makes the machine's transport key for this boot, keeps it in
//! locked memory, never writes it anywhere, and listens on a local socket
//! that only the users it names may use (checked by the peer's credentials).
//! The operator's passkey grants that transport key a key label at the
//! provider for a limited time ([`crate::remote_tpm::TransportGrant`]); the
//! holder keeps the grant and carries each of the node's signing requests to
//! the provider with it. The node keeps nothing: it restarts against the same
//! holder and the same grant. A new holder, after a reboot, has a new
//! transport key, which no earlier grant names.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};
use zeroize::Zeroize;

use tenzro_device_key::remote::busy_retry_after;
pub use tenzro_device_key::remote::holder_id;

use crate::remote_tpm::{TransportGrant, now_ms, wrap_request};

/// Carry a signing request to the provider.
pub const OP_CALL: u8 = tenzro_device_key::remote::HOLDER_OP_CALL;
/// The holder's transport endpoint id and the end of its grant.
pub const OP_ID: u8 = tenzro_device_key::remote::HOLDER_OP_ID;
/// Install a grant.
pub const OP_GRANT: u8 = 3;

const STATUS_OK: u8 = 0;
const STATUS_ERR: u8 = 1;

/// Retries of a request the provider refused because its TPM line is full,
/// unless the holder is told otherwise.
pub const DEFAULT_BUSY_RETRIES: u32 = 5;

/// Largest frame either side sends.
const MAX_FRAME: usize = 1 << 20;

/// How long one request to a provider may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The transport key, in memory locked against swapping and wiped on drop.
struct LockedKey {
    bytes: Box<[u8; 32]>,
    locked: bool,
}

impl LockedKey {
    fn generate() -> std::result::Result<Self, String> {
        let mut bytes = Box::new([0u8; 32]);
        let locked = lock(bytes.as_mut_ptr(), 32);
        getrandom_0_4::fill(bytes.as_mut_slice())
            .map_err(|e| format!("the operating system gave no randomness: {e}"))?;
        Ok(Self { bytes, locked })
    }
}

impl Drop for LockedKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            unlock(self.bytes.as_mut_ptr(), 32);
        }
    }
}

#[cfg(unix)]
fn lock(ptr: *mut u8, len: usize) -> bool {
    // SAFETY: `ptr` points to `len` bytes owned by a live Box.
    let rc = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
    if rc != 0 {
        warn!(
            error = %std::io::Error::last_os_error(),
            "the transport key could not be locked in memory; raise RLIMIT_MEMLOCK to keep it out of swap"
        );
    }
    rc == 0
}

#[cfg(unix)]
fn unlock(ptr: *mut u8, len: usize) {
    // SAFETY: `ptr` points to `len` bytes owned by a live Box, locked earlier.
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

/// Where the holder sends a granted request.
#[async_trait]
pub trait Upstream: Send + Sync {
    /// Sends `request` to a provider, authenticated as the endpoint of
    /// `secret`, and returns its answer.
    async fn call(&self, secret: &[u8; 32], request: &[u8])
    -> std::result::Result<Vec<u8>, String>;
}

/// A set of providers: the first, then each backup, staying with the last
/// one that answered. No provider is special; the set is whatever the
/// operator enrols.
pub struct FailoverUpstream {
    members: Vec<Arc<dyn Upstream>>,
    current: AtomicUsize,
}

impl FailoverUpstream {
    pub fn new(members: Vec<Arc<dyn Upstream>>) -> Self {
        Self {
            members,
            current: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Upstream for FailoverUpstream {
    async fn call(
        &self,
        secret: &[u8; 32],
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        let n = self.members.len();
        let start = self.current.load(Ordering::Relaxed);
        let mut last = "no provider is configured".to_string();
        for i in 0..n {
            let at = (start + i) % n;
            match self.members[at].call(secret, request).await {
                Ok(answer) => {
                    self.current.store(at, Ordering::Relaxed);
                    return Ok(answer);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

/// One provider, over iroh.
struct IrohProvider {
    id: [u8; 32],
    addrs: Vec<SocketAddr>,
    timeout: Duration,
}

#[async_trait]
impl Upstream for IrohProvider {
    async fn call(
        &self,
        secret: &[u8; 32],
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        match tokio::time::timeout(
            self.timeout,
            tenzro_iroh::tpm_sign_request_once(*secret, self.id, &self.addrs, request),
        )
        .await
        {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("the provider did not answer".to_string()),
        }
    }
}

/// The providers, over iroh, with failover between them.
pub struct IrohUpstream {
    providers: Vec<([u8; 32], Vec<SocketAddr>)>,
    inner: FailoverUpstream,
}

impl IrohUpstream {
    fn build(providers: &[([u8; 32], Vec<SocketAddr>)], timeout: Duration) -> FailoverUpstream {
        FailoverUpstream::new(
            providers
                .iter()
                .map(|(id, addrs)| {
                    Arc::new(IrohProvider {
                        id: *id,
                        addrs: addrs.clone(),
                        timeout,
                    }) as Arc<dyn Upstream>
                })
                .collect(),
        )
    }

    pub fn new(providers: Vec<([u8; 32], Vec<SocketAddr>)>) -> Self {
        let inner = Self::build(&providers, REQUEST_TIMEOUT);
        Self { providers, inner }
    }

    /// How long one request to a provider may take, including its wait for
    /// a turn at the provider's TPM.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.inner = Self::build(&self.providers, timeout);
        self
    }
}

#[async_trait]
impl Upstream for IrohUpstream {
    async fn call(
        &self,
        secret: &[u8; 32],
        request: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        self.inner.call(secret, request).await
    }
}

/// The key holder's state: this boot's transport key and its grant.
pub struct Holder {
    key: LockedKey,
    grant: RwLock<Option<(TransportGrant, Vec<u8>)>>,
    upstream: Arc<dyn Upstream>,
    busy_retries: u32,
}

impl Holder {
    /// How many times a request the provider refused as busy is retried.
    pub fn with_busy_retries(mut self, retries: u32) -> Self {
        self.busy_retries = retries;
        self
    }

    /// A holder with a transport key made now, for this boot only.
    pub fn new(upstream: Arc<dyn Upstream>) -> std::result::Result<Self, String> {
        Ok(Self {
            key: LockedKey::generate()?,
            grant: RwLock::new(None),
            upstream,
            busy_retries: DEFAULT_BUSY_RETRIES,
        })
    }

    /// The transport endpoint id a grant must name.
    pub fn endpoint_id(&self) -> [u8; 32] {
        tenzro_iroh::endpoint_id_of(&self.key.bytes)
    }

    /// When the installed grant ends, if one is installed.
    pub fn grant_not_after_ms(&self) -> Option<u64> {
        self.grant.read().as_ref().map(|(g, _)| g.not_after_ms)
    }

    /// Installs `grant` for later requests. The provider is what checks the
    /// passkey; this refuses only a grant that cannot be for this holder.
    pub fn install_grant(&self, grant: &[u8]) -> std::result::Result<(), String> {
        let parsed: TransportGrant =
            serde_json::from_slice(grant).map_err(|e| format!("the grant is malformed: {e}"))?;
        if parsed.endpoint_id != hex::encode(self.endpoint_id()) {
            return Err("the grant names another transport endpoint than this key holder's".into());
        }
        if parsed.not_after_ms <= now_ms() {
            return Err("the grant has already expired".into());
        }
        *self.grant.write() = Some((parsed, grant.to_vec()));
        Ok(())
    }

    /// Carries one signing request to the provider with the grant.
    pub async fn call(&self, request: &[u8]) -> std::result::Result<Vec<u8>, String> {
        let wrapped = {
            let grant = self.grant.read();
            let Some((g, bytes)) = grant.as_ref() else {
                return Err(
                    "no grant is installed: run `tenzro-node tpm grant-request`, approve it with \
                     the operator passkey, then `tenzro-node tpm grant-install`"
                        .into(),
                );
            };
            if g.not_after_ms <= now_ms() {
                return Err("the grant has expired: install a new one".into());
            }
            wrap_request(bytes, request)
        };
        let retries = self.busy_retries;
        let mut attempt = 0;
        loop {
            let answer = self.upstream.call(&self.key.bytes, &wrapped).await?;
            // A provider whose TPM line is full says so and how long to
            // wait; the holder waits that long and asks again.
            match busy_retry_after(&answer) {
                Some(ms) if attempt < retries => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(ms.clamp(50, 30_000))).await;
                }
                _ => return Ok(answer),
            }
        }
    }

    async fn answer(
        self: &Arc<Self>,
        op: u8,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, String> {
        match op {
            OP_CALL => self.call(payload).await,
            OP_ID => {
                let mut out = self.endpoint_id().to_vec();
                out.extend_from_slice(&self.grant_not_after_ms().unwrap_or(0).to_be_bytes());
                Ok(out)
            }
            OP_GRANT => {
                self.install_grant(payload)?;
                Ok(Vec::new())
            }
            _ => Err("unknown operation".into()),
        }
    }
}

/// Serves `holder` on the Unix socket at `socket` until the process ends.
/// Only this process's own user and `allowed_uids` may connect.
pub async fn serve(
    holder: Arc<Holder>,
    socket: &Path,
    allowed_uids: Vec<u32>,
) -> std::io::Result<()> {
    if socket.exists() {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("a key holder already serves {}", socket.display()),
            ));
        }
        std::fs::remove_file(socket)?;
    }
    let listener = tokio::net::UnixListener::bind(socket)?;
    {
        use std::os::unix::fs::PermissionsExt;
        // The peer-credential check below is the gate; the file mode only
        // lets the named users reach it.
        let mode = if allowed_uids.is_empty() {
            0o600
        } else {
            0o666
        };
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(mode))?;
    }
    // SAFETY: geteuid has no preconditions.
    let own = unsafe { libc::geteuid() };
    info!(
        socket = %socket.display(),
        endpoint = %hex::encode(holder.endpoint_id()),
        "tpm key holder ready"
    );
    loop {
        let (mut stream, _) = listener.accept().await?;
        let uid = match stream.peer_cred() {
            Ok(c) => c.uid(),
            Err(e) => {
                warn!(error = %e, "key holder: peer credentials unavailable; connection dropped");
                continue;
            }
        };
        // A user this holder does not serve is told so in the answer to its
        // request, so the caller reads why and not a closed connection.
        let refused = (uid != own && !allowed_uids.contains(&uid)).then(|| {
            warn!(
                uid,
                "key holder: connection from a user it does not serve; refused"
            );
            format!("this key holder serves user {own} and does not answer user {uid}")
        });
        let holder = holder.clone();
        tokio::spawn(async move {
            let mut head = [0u8; 5];
            if stream.read_exact(&mut head).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes(head[1..5].try_into().expect("four bytes")) as usize;
            if len > MAX_FRAME {
                return;
            }
            let mut payload = vec![0u8; len];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            let answer = match refused {
                Some(why) => Err(why),
                None => holder.answer(head[0], &payload).await,
            };
            let (status, body) = match answer {
                Ok(b) => (STATUS_OK, b),
                Err(e) => (STATUS_ERR, e.into_bytes()),
            };
            let mut out = vec![status];
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(&body);
            let _ = stream.write_all(&out).await;
        });
    }
}

/// Sends one operation to the key holder at `socket` and returns its answer.
pub fn request(socket: &Path, op: u8, payload: &[u8]) -> std::result::Result<Vec<u8>, String> {
    tenzro_device_key::remote::holder_request(socket, op, payload)
}

/// Why a node cannot use its key holder yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Wanted {
    /// No key holder answers at the socket.
    Holder(String),
    /// The key holder there holds no grant that still stands.
    Grant(String),
}

impl Wanted {
    pub fn reason(&self) -> &str {
        match self {
            Wanted::Holder(r) | Wanted::Grant(r) => r,
        }
    }
}

/// Why a node cannot use its key holder yet, if it cannot: none answers at
/// `socket`, or the one there holds no grant that still stands at `now_ms`.
pub fn grant_wanted(socket: &Path, now_ms: u64) -> Option<Wanted> {
    match holder_id(socket) {
        Err(e) => Some(Wanted::Holder(format!(
            "no key holder answers at {}: {e}",
            socket.display()
        ))),
        Ok((_, None)) => Some(Wanted::Grant(
            "the key holder has no grant: run `tenzro-node tpm grant-request`, approve it with \
             the operator passkey, then `tenzro-node tpm grant-install`"
                .into(),
        )),
        Ok((_, Some(end))) if end <= now_ms => Some(Wanted::Grant(
            "the key holder's grant has expired: run `tenzro-node tpm grant-request`, approve \
             it with the operator passkey, then `tenzro-node tpm grant-install`"
                .into(),
        )),
        Ok(_) => None,
    }
}

/// How a node waits for its key holder and the holder's grant.
#[derive(Debug, Clone, Copy)]
pub struct GrantWait {
    /// How often it looks again.
    pub step: Duration,
    /// How often it repeats what it waits for.
    pub remind: Duration,
    /// How long it waits for a key holder to answer at all before it refuses.
    pub holder: Duration,
}

/// Returns once the key holder at `socket` holds a grant that stands,
/// looking again every `wait.step`. A node started before its operator
/// approved the grant (after a reboot of the machine, the key holder starts
/// without one) waits here and goes on by itself when the grant is
/// installed; what it waits for is logged when it changes and repeated every
/// `wait.remind`. A key holder that starts after the node is waited for up
/// to `wait.holder`; when none has answered by then, the error names the
/// socket.
pub async fn await_grant(socket: &Path, wait: GrantWait) -> std::result::Result<(), String> {
    let began = std::time::Instant::now();
    let mut said: Option<(String, std::time::Instant)> = None;
    // Once a key holder has answered, a restart of it is waited out without limit.
    let mut answered = false;
    loop {
        let Some(wanted) = ask(socket).await else {
            if said.is_some() {
                info!("the key holder's grant is installed; starting");
            }
            return Ok(());
        };
        answered |= matches!(wanted, Wanted::Grant(_));
        if !answered && began.elapsed() >= wait.holder {
            return Err(format!(
                "{} (waited {} s for a key holder to answer)",
                wanted.reason(),
                wait.holder.as_secs()
            ));
        }
        let reason = wanted.reason().to_owned();
        if said
            .as_ref()
            .is_none_or(|(r, at)| *r != reason || at.elapsed() >= wait.remind)
        {
            warn!("waiting for the key grant: {reason}");
            said = Some((reason, std::time::Instant::now()));
        }
        tokio::time::sleep(wait.step).await;
    }
}

/// [`grant_wanted`] at the current time, off the runtime's own threads: the
/// request blocks on the socket.
async fn ask(socket: &Path) -> Option<Wanted> {
    let at = socket.to_path_buf();
    tokio::task::spawn_blocking(move || grant_wanted(&at, now_ms()))
        .await
        .unwrap_or_else(|e| {
            Some(Wanted::Holder(format!(
                "the key holder could not be asked: {e}"
            )))
        })
}

/// What a running node waits for from its key holder: nothing while its
/// grant stands.
#[derive(Debug, Clone, Default)]
pub struct GrantState(Arc<RwLock<Option<String>>>);

impl GrantState {
    /// Why the node cannot sign now, when it cannot.
    pub fn waiting_for(&self) -> Option<String> {
        self.0.read().clone()
    }

    /// The state as the node's status reports it.
    pub fn json(&self) -> serde_json::Value {
        match self.waiting_for() {
            None => serde_json::json!({ "state": "granted" }),
            Some(reason) => serde_json::json!({
                "state": "waiting for the operator's approval",
                "reason": reason,
            }),
        }
    }
}

static RUNNING_GRANT: std::sync::OnceLock<GrantState> = std::sync::OnceLock::new();

/// The grant state of this process's node, once it watches one.
pub fn running_grant() -> Option<&'static GrantState> {
    RUNNING_GRANT.get()
}

/// Watches the grant of the running node's key holder at `socket` for the
/// life of the process, so that [`running_grant`] reports it.
pub fn watch_running_grant(socket: std::path::PathBuf, wait: GrantWait) {
    let state = RUNNING_GRANT.get_or_init(GrantState::default).clone();
    tokio::spawn(async move { watch_grant(&socket, wait, state).await });
}

/// Looks at the key holder at `socket` every `wait.step` and keeps `state`
/// current. A grant that expires or is lost while the node runs (a key
/// holder restarted after a reboot holds none) leaves the node running and
/// waiting for the operator's approval, said when it changes and every
/// `wait.remind`; signing resumes by itself once a grant is installed.
pub async fn watch_grant(socket: &Path, wait: GrantWait, state: GrantState) {
    let mut said: Option<(String, std::time::Instant)> = None;
    loop {
        tokio::time::sleep(wait.step).await;
        let Some(wanted) = ask(socket).await else {
            if state.0.write().take().is_some() {
                info!("the key holder's grant is installed; the node signs again");
            }
            said = None;
            continue;
        };
        let reason = wanted.reason().to_owned();
        *state.0.write() = Some(reason.clone());
        if said
            .as_ref()
            .is_none_or(|(r, at)| *r != reason || at.elapsed() >= wait.remind)
        {
            warn!(
                "waiting for the operator's approval: {reason}. The node keeps running and \
                 signs again once a grant is installed"
            );
            said = Some((reason, std::time::Instant::now()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_tpm::tests::TestPasskey;
    use crate::remote_tpm::{GrantedProvider, HolderTransport, RemoteConfig};
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use std::path::PathBuf;
    use tenzro_device_key::remote::{Audit, KeyStore, Policy, RemoteTpmSigner};
    use tenzro_device_key::{DeviceSignature, HardwareBackend, HardwareSigner};

    struct TestSigner(SigningKey);
    impl HardwareSigner for TestSigner {
        fn backend(&self) -> HardwareBackend {
            HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            "pi-1"
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            Ok(self
                .0
                .verifying_key()
                .to_sec1_point(false)
                .as_bytes()
                .try_into()
                .unwrap())
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<DeviceSignature> {
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            let mut out = [0u8; 64];
            out.copy_from_slice(&sig.to_bytes());
            Ok(out)
        }
    }

    struct TestKeys;
    impl KeyStore for TestKeys {
        fn open(&self, _label: &str) -> tenzro_device_key::Result<Box<dyn HardwareSigner>> {
            Ok(Box::new(TestSigner(
                SigningKey::from_slice(&[7u8; 32]).unwrap(),
            )))
        }
    }

    struct NoAudit;
    impl Audit for NoAudit {
        fn record(&self, _client: &[u8], _kind: &str, _outcome: &str) {}
    }

    /// The provider, reached in process as the endpoint the holder's key
    /// stands for.
    struct InProcess(GrantedProvider<TestKeys, NoAudit>);
    #[async_trait]
    impl Upstream for InProcess {
        async fn call(
            &self,
            secret: &[u8; 32],
            request: &[u8],
        ) -> std::result::Result<Vec<u8>, String> {
            Ok(self
                .0
                .handle(&tenzro_iroh::endpoint_id_of(secret), request, now_ms()))
        }
    }

    const HOUR: u64 = 3_600_000;

    fn provider(pk: &TestPasskey) -> Arc<InProcess> {
        let policy = Policy {
            clients: Default::default(),
            allowed_prefixes: vec![b"tenzro/".to_vec()],
            allow_prehash: false,
            // No test here is about the rate limit (the tests of the
            // provider cover it), and one signs as fast as it can for the
            // length of a reload.
            per_minute: u32::MAX,
            requests_per_minute: u32::MAX,
            derived_prefixes: vec!["tenzro/".into()],
        };
        Arc::new(InProcess(GrantedProvider::new(
            TestKeys,
            NoAudit,
            policy,
            vec![pk.enrolment("pi-1")],
            24 * HOUR,
        )))
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tzholder-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A key holder serving at a fresh socket, as after a boot.
    async fn boot(upstream: Arc<dyn Upstream>) -> (Arc<Holder>, PathBuf, PathBuf) {
        let d = dir();
        let socket = d.join("holder.sock");
        let holder = Arc::new(Holder::new(upstream).unwrap());
        let (h, s) = (holder.clone(), socket.clone());
        tokio::spawn(async move { serve(h, &s, Vec::new()).await });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (holder, socket, d)
    }

    fn node(socket: &Path) -> RemoteConfig {
        RemoteConfig {
            label: "pi-1".into(),
            key_holder: socket.to_path_buf(),
        }
    }

    /// The node's side, as a fresh process opening its key.
    async fn node_signs(config: RemoteConfig) -> tenzro_device_key::Result<DeviceSignature> {
        tokio::task::spawn_blocking(move || {
            let signer = crate::remote_tpm::open(&config)?;
            signer.sign(b"tenzro/test/1 hello")
        })
        .await
        .unwrap()
    }

    fn install(pk: &TestPasskey, socket: &Path, endpoint: &[u8; 32], not_after: u64) {
        let grant = serde_json::to_vec(&pk.grant(endpoint, "pi-1", not_after)).unwrap();
        request(socket, OP_GRANT, &grant).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn no_transport_key_file_is_ever_written() {
        let pk = TestPasskey::new(3);
        let (holder, socket, d) = boot(provider(&pk)).await;
        install(&pk, &socket, &holder.endpoint_id(), now_ms() + HOUR);
        node_signs(node(&socket)).await.unwrap();
        let written: Vec<_> = std::fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(written, vec![std::ffi::OsString::from("holder.sock")]);
        assert!(!Path::new("tpm-client.key").exists());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_provider_refuses_a_client_without_a_valid_grant() {
        let pk = TestPasskey::new(3);
        let upstream = provider(&pk);
        let (holder, socket, _d) = boot(upstream.clone()).await;
        let err = node_signs(node(&socket)).await.unwrap_err();
        assert!(err.to_string().contains("no grant"), "{err}");
        // A request that reaches the provider without a grant, or with one
        // a different passkey made, is refused there.
        let bare = upstream
            .0
            .handle(&holder.endpoint_id(), b"anything", now_ms());
        assert_eq!(bare[1], 1, "refused");
        let stranger = TestPasskey::new(4);
        install(&stranger, &socket, &holder.endpoint_id(), now_ms() + HOUR);
        let err = node_signs(node(&socket)).await.unwrap_err();
        assert!(
            err.to_string().contains("not the one enrolled for 'pi-1'"),
            "{err}"
        );
    }

    /// A node started before the grant is approved waits, and goes on by
    /// itself once the grant is installed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_waits_for_the_grant_and_goes_on_once_it_is_installed() {
        let pk = TestPasskey::new(3);
        let (holder, socket, _d) = boot(provider(&pk)).await;
        assert!(
            grant_wanted(&socket, now_ms())
                .unwrap()
                .reason()
                .contains("has no grant")
        );
        // A holder that answers is waited on past the bound for one that does not.
        let waiting = {
            let socket = socket.clone();
            tokio::spawn(
                async move { await_grant(&socket, quick(Duration::from_millis(50))).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(!waiting.is_finished(), "started without a grant");

        install(&pk, &socket, &holder.endpoint_id(), now_ms() + HOUR);
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("goes on once the grant is installed")
            .unwrap()
            .unwrap();
        assert_eq!(grant_wanted(&socket, now_ms()), None);
        assert!(
            grant_wanted(&socket, now_ms() + 2 * HOUR)
                .unwrap()
                .reason()
                .contains("expired")
        );
    }

    /// A grant that runs out while the node runs leaves it waiting for the
    /// operator's approval, which its status names; a new grant ends the wait.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_running_node_whose_grant_expires_waits_and_resumes() {
        let pk = TestPasskey::new(3);
        let (holder, socket, _d) = boot(provider(&pk)).await;
        install(&pk, &socket, &holder.endpoint_id(), now_ms() + 400);
        let state = GrantState::default();
        let watch = {
            let (socket, state) = (socket.clone(), state.clone());
            tokio::spawn(async move { watch_grant(&socket, quick(Duration::ZERO), state).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(state.waiting_for(), None, "the grant still stands");
        assert_eq!(state.json()["state"], "granted");

        let waiting = async {
            while state.waiting_for().is_none() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("an expired grant is noticed");
        assert!(state.waiting_for().unwrap().contains("expired"));
        assert_eq!(state.json()["state"], "waiting for the operator's approval");
        assert!(!watch.is_finished(), "the node keeps running");

        install(&pk, &socket, &holder.endpoint_id(), now_ms() + HOUR);
        let resumed = async {
            while state.waiting_for().is_some() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), resumed)
            .await
            .expect("a new grant ends the wait");
        watch.abort();
    }

    fn quick(holder: Duration) -> GrantWait {
        GrantWait {
            step: Duration::from_millis(20),
            remind: Duration::from_secs(60),
            holder,
        }
    }

    /// No key holder at the socket is named as such, and is waited for only
    /// up to the bound: then the node refuses, naming the socket.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_missing_key_holder_is_named_and_refused_after_the_wait() {
        let socket = std::env::temp_dir().join(format!("absent-{}.sock", std::process::id()));
        let wanted = grant_wanted(&socket, 0).unwrap();
        assert!(matches!(wanted, Wanted::Holder(_)), "{wanted:?}");
        assert!(
            wanted.reason().contains("no key holder answers"),
            "{wanted:?}"
        );
        let err = tokio::time::timeout(
            Duration::from_secs(5),
            await_grant(&socket, quick(Duration::from_millis(100))),
        )
        .await
        .expect("refuses once the wait is over")
        .unwrap_err();
        assert!(err.contains(&socket.display().to_string()), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_expired_grant_is_refused() {
        let pk = TestPasskey::new(3);
        let (holder, socket, _d) = boot(provider(&pk)).await;
        let grant =
            serde_json::to_vec(&pk.grant(&holder.endpoint_id(), "pi-1", now_ms() - 1)).unwrap();
        assert!(
            request(&socket, OP_GRANT, &grant)
                .unwrap_err()
                .contains("expired")
        );
        // One that ends while installed stops working when it ends. The window
        // is wide enough that the first signature lands inside it on a host
        // busy with the rest of the suite, and the wait outlasts it.
        install(&pk, &socket, &holder.endpoint_id(), now_ms() + 3_000);
        node_signs(node(&socket)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(3_200)).await;
        let err = node_signs(node(&socket)).await.unwrap_err();
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_node_restart_keeps_working_without_a_new_grant() {
        let pk = TestPasskey::new(3);
        let (holder, socket, _d) = boot(provider(&pk)).await;
        install(&pk, &socket, &holder.endpoint_id(), now_ms() + HOUR);
        let first = node_signs(node(&socket)).await.unwrap();
        // A restarted node is a new process with nothing kept: it opens its
        // key again through the same holder.
        let second = node_signs(node(&socket)).await.unwrap();
        assert_eq!(first.len(), second.len());
        let signer = tokio::task::spawn_blocking({
            let socket = socket.clone();
            move || {
                RemoteTpmSigner::open(HolderTransport::new(socket), "pi-1")
                    .unwrap()
                    .public_key_sec1()
                    .unwrap()
            }
        })
        .await
        .unwrap();
        assert_eq!(signer[0], 0x04);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_new_boot_needs_a_new_grant() {
        let pk = TestPasskey::new(3);
        let upstream = provider(&pk);
        let (old, old_socket, _d1) = boot(upstream.clone()).await;
        let grant = pk.grant(&old.endpoint_id(), "pi-1", now_ms() + HOUR);
        let bytes = serde_json::to_vec(&grant).unwrap();
        request(&old_socket, OP_GRANT, &bytes).unwrap();
        node_signs(node(&old_socket)).await.unwrap();

        let (new, socket, _d2) = boot(upstream.clone()).await;
        assert_ne!(new.endpoint_id(), old.endpoint_id());
        // The old grant names the old endpoint: the new holder will not
        // take it, and the provider refuses it from the new endpoint.
        assert!(request(&socket, OP_GRANT, &bytes).is_err());
        let replayed = upstream.0.handle(
            &new.endpoint_id(),
            &crate::remote_tpm::wrap_request(&bytes, b"x"),
            now_ms(),
        );
        assert_eq!(replayed[1], 1, "refused");
        assert!(node_signs(node(&socket)).await.is_err());
        install(&pk, &socket, &new.endpoint_id(), now_ms() + HOUR);
        node_signs(node(&socket)).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_holder_reports_its_endpoint_and_grant() {
        let pk = TestPasskey::new(3);
        let (holder, socket, _d) = boot(provider(&pk)).await;
        let socket2 = socket.clone();
        let (id, grant) = tokio::task::spawn_blocking(move || holder_id(&socket2).unwrap())
            .await
            .unwrap();
        assert_eq!(id, holder.endpoint_id());
        assert!(grant.is_none());
    }

    fn node_for(socket: &Path, label: &str) -> RemoteConfig {
        RemoteConfig {
            label: label.into(),
            key_holder: socket.to_path_buf(),
        }
    }

    /// Onboarding a second device must not interrupt the first.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_added_by_reload_works_and_the_signing_client_is_never_interrupted() {
        let pk = TestPasskey::new(3);
        let upstream = provider(&pk);
        // The first device: already granted and signing.
        let (a, a_sock, _d1) = boot(upstream.clone()).await;
        install(&pk, &a_sock, &a.endpoint_id(), now_ms() + HOUR);
        node_signs(node(&a_sock)).await.unwrap();

        // The new device's holder asks for a grant under a label the provider
        // has not enrolled yet: refused. This is the state in which, today,
        // only a provider restart helps.
        let (b, b_sock, _d2) = boot(upstream.clone()).await;
        let grant2 =
            serde_json::to_vec(&pk.grant(&b.endpoint_id(), "pi-2", now_ms() + HOUR)).unwrap();
        request(&b_sock, OP_GRANT, &grant2).unwrap();
        let err = node_signs(node_for(&b_sock, "pi-2")).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("no passkey is enrolled for 'pi-2'"),
            "{err}"
        );

        // The first device keeps signing, continuously, across the reload.
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let signing = {
            let (stop, sock) = (stop.clone(), a_sock.clone());
            tokio::spawn(async move {
                let mut n = 0u32;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    node_signs(node(&sock))
                        .await
                        .expect("tpm-host sign interrupted");
                    n += 1;
                }
                n
            })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        upstream
            .0
            .reload_clients(vec![pk.enrolment("pi-1"), pk.enrolment("pi-2")])
            .unwrap();
        // The new device signs with no provider restart, while the first device signs.
        node_signs(node_for(&b_sock, "pi-2")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let signed = signing.await.unwrap();
        assert!(
            signed > 1,
            "tpm-host signed {signed} times across the reload"
        );
        // The first device still uses the grant it installed before: no re-grant.
        node_signs(node(&a_sock)).await.unwrap();
        // The new device cannot use the first device's label.
        assert!(node_signs(node_for(&b_sock, "pi-1")).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_reload_can_remove_a_client_and_refuses_what_needs_a_restart() {
        let pk = TestPasskey::new(3);
        let upstream = provider(&pk);
        let (a, a_sock, _d) = boot(upstream.clone()).await;
        install(&pk, &a_sock, &a.endpoint_id(), now_ms() + HOUR);
        node_signs(node(&a_sock)).await.unwrap();
        // A list needing derived keys the provider has no root for: refused,
        // nothing changes.
        let mut derived = pk.enrolment("pi-1");
        derived.derived = true;
        assert!(upstream.0.reload_clients(vec![derived]).is_err());
        node_signs(node(&a_sock)).await.unwrap();
        // Removing the client takes effect at once.
        upstream.0.reload_clients(Vec::new()).unwrap();
        assert!(node_signs(node(&a_sock)).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_bad_provider_file_leaves_the_running_list_alone() {
        let pk = TestPasskey::new(3);
        let upstream = provider(&pk);
        let (a, a_sock, d) = boot(upstream.clone()).await;
        install(&pk, &a_sock, &a.endpoint_id(), now_ms() + HOUR);
        let file = d.join("provider.toml");
        let entry = |label: &str| {
            format!(
                "{{ passkey_public_key = \"{}\", rp_id = \"{}\", label = \"{label}\" }}",
                hex::encode(&pk.enrolment("x").public_key_xy),
                pk.rp_id
            )
        };
        std::fs::write(&file, "clients = [ not toml").unwrap();
        assert!(crate::remote_tpm::reload_clients_from_file(&file, &upstream.0).is_err());
        node_signs(node(&a_sock)).await.unwrap();
        std::fs::write(
            &file,
            "clients = [{ passkey_public_key = \"00\", rp_id = \"x\", label = \"y\" }]",
        )
        .unwrap();
        assert!(crate::remote_tpm::reload_clients_from_file(&file, &upstream.0).is_err());
        node_signs(node(&a_sock)).await.unwrap();
        std::fs::write(
            &file,
            format!("clients = [{}, {}]", entry("pi-1"), entry("pi-2")),
        )
        .unwrap();
        assert_eq!(
            crate::remote_tpm::reload_clients_from_file(&file, &upstream.0).unwrap(),
            2
        );
        node_signs(node(&a_sock)).await.unwrap();
    }
}
