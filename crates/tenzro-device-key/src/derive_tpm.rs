//! The TPM derivation root: a keyed-hash key the TPM generated, usable only
//! through a policy that a key in the same TPM authorises by signing.
//!
//! # Why not a primary
//!
//! A TPM primary key is a function of the hierarchy seed and a public
//! template, so any process that can open the TPM recreates it and computes
//! whatever it computes. This root is instead created with `TPM2_Create`: the
//! TPM draws its HMAC key at random (`sensitiveDataOrigin`), wraps it under a
//! storage parent that never leaves the chip (`fixedTPM`, `fixedParent`), and
//! marks it usable only through its `authPolicy` (`userWithAuth` clear).
//!
//! # Who can use it
//!
//! Three things are needed together:
//! 1. this machine's TPM;
//! 2. the wrapped blob, `derive-root.tpm` in the device-key directory
//!    (`TENZRO_DEVICE_KEY_DIR`, else `~/.local/state/tenzro/device-keys`),
//!    written `0600` in a `0700` directory. It is ciphertext under the
//!    chip's storage parent and useless anywhere else;
//! 3. the authorising key: a restricted P-256 signing key the TPM generated
//!    in its endorsement hierarchy, at a persistent handle (the node's
//!    attestation key by default, [`set_authorization_handle`] to name
//!    another). The root's `authPolicy` is `TPM2_PolicySigned` by that key's
//!    name with [`ROOT_POLICY_REF`], so every use needs a fresh signature by
//!    that key over the session's `nonceTPM` with an expiration of
//!    [`ROOT_POLICY_EXPIRATION`] seconds: a signature authorises one session
//!    only and lapses even within it. The same policy first requires
//!    `TPM2_PolicyPCR` on [`ROOT_PCR`] (PCR 7, the secure-boot state) holding
//!    the value it held when the root was made, so a machine booted into
//!    another secure-boot state cannot use the root even with the TPM and the
//!    blob. A change of that state (secure boot turned off, other boot
//!    authorities) makes the root unusable: its derived keys are then
//!    replaced, as on a new machine.
//!
//! Before the root is used, the authorising key is checked against the TPM's
//! endorsement key: the endorsement key is made again as a transient primary
//! from the TCG template (no persistent handle is read or used), a secret is
//! encrypted to it for the authorising key's name (`TPM2_MakeCredential`),
//! and only that key in that TPM can recover it (`TPM2_ActivateCredential`).
//! No secret is stored anywhere: the authorisation is the key's signature,
//! made inside the chip.
//!
//! The boundary is the TPM device itself: a process that can open the TPM and
//! has the blob can have the authorising key sign and use the root. The root's
//! public area is checked on every load, so a blob replaced with a key someone
//! chose, or one usable without the policy, is refused.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use zeroize::Zeroizing;

use crate::tpm_wire::{self, PublicArea, WireError};
use crate::{DeviceKeyError, Result};

/// File name of the wrapped root in the device-key directory.
pub const ROOT_FILE: &str = "derive-root.tpm";

/// The `policyRef` the authorising key signs, naming what it authorises.
pub const ROOT_POLICY_REF: &[u8] = b"tenzro/device-key/tpm-root";

/// Seconds a signed authorisation stays valid after its session started. It
/// is sent negative, so the TPM issues no ticket that could be replayed.
pub const ROOT_POLICY_EXPIRATION: i32 = 30;

/// The PCR the root is bound to: PCR 7, the secure-boot state (the
/// secure-boot policy and the authorities that verified the boot). The root
/// is usable only while it holds the value it held when the root was made.
pub const ROOT_PCR: u8 = 7;

/// The root's `authPolicy`: `TPM2_PolicyPCR` on [`ROOT_PCR`] holding the value
/// that hashes to `pcr_digest`, then `TPM2_PolicySigned` by the key named
/// `auth_name` with [`ROOT_POLICY_REF`].
pub fn root_policy(auth_name: &[u8], pcr_digest: &[u8; 32]) -> [u8; 32] {
    let pcr = tpm_wire::policy_pcr_update(&[0u8; 32], ROOT_PCR, pcr_digest);
    tpm_wire::policy_signed_update(&pcr, auth_name, ROOT_POLICY_REF)
}

const BLOB_MAGIC: &[u8] = b"tenzro/device-key/tpm-derive-root/signed\n";

static AUTHORIZATION_HANDLE: OnceLock<u32> = OnceLock::new();

/// Name the persistent handle of the key that authorises the root. Set once,
/// before the root is first opened; the default is the node's attestation
/// key ([`tpm_wire::NODE_ATTESTATION_HANDLE`]).
///
/// # Errors
/// A handle outside the persistent range, or a second, different setting.
pub fn set_authorization_handle(handle: u32) -> Result<()> {
    if handle >> 24 != 0x81 {
        return Err(tpm_err(format!(
            "0x{handle:08x} is not a persistent TPM handle (0x81xxxxxx)"
        )));
    }
    let set = *AUTHORIZATION_HANDLE.get_or_init(|| handle);
    if set != handle {
        return Err(tpm_err(format!(
            "the root's authorising key is already 0x{set:08x}"
        )));
    }
    Ok(())
}

fn authorization_handle() -> u32 {
    *AUTHORIZATION_HANDLE.get_or_init(|| tpm_wire::NODE_ATTESTATION_HANDLE)
}

fn tpm_err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

fn wire(what: &str) -> impl Fn(WireError) -> DeviceKeyError + '_ {
    move |e| tpm_err(format!("{what}: {e}"))
}

pub(crate) use crate::tpm_provision::TpmTransport;

type Opener = Box<dyn Fn() -> Result<Box<dyn TpmTransport>> + Send + Sync>;

fn os_random<const N: usize>() -> Result<[u8; N]> {
    use rand::RngCore;
    let mut b = [0u8; N];
    rand::rngs::OsRng
        .try_fill_bytes(&mut b)
        .map_err(|e| tpm_err(format!("OS RNG: {e}")))?;
    Ok(b)
}

/// A connection with every transient handle it created flushed on drop, so
/// nothing is left in the chip's few object slots on any path.
struct Session {
    t: Box<dyn TpmTransport>,
    handles: Vec<u32>,
}

impl Session {
    fn cmd(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        self.t.submit(command)
    }

    /// The storage parent: the node's persistent storage root, made by
    /// provisioning and never created here.
    fn parent(&mut self) -> Result<u32> {
        let resp = self.cmd(&tpm_wire::read_public_command(
            tpm_wire::NODE_STORAGE_ROOT_HANDLE,
        ))?;
        let public = tpm_wire::parse_read_public_response(&resp).map_err(|e| {
            tpm_err(format!(
                "the TPM storage root 0x{:08x} cannot be read ({e}); run `tenzro-node tpm provision` once on \
                 this machine",
                tpm_wire::NODE_STORAGE_ROOT_HANDLE
            ))
        })?;
        if public.attributes != tpm_wire::STORAGE_PARENT_ATTRIBUTES {
            return Err(tpm_err(format!(
                "TPM handle 0x{:08x} is not a storage root",
                tpm_wire::NODE_STORAGE_ROOT_HANDLE
            )));
        }
        Ok(tpm_wire::NODE_STORAGE_ROOT_HANDLE)
    }

    /// A policy session and its `nonceTPM`.
    fn policy_session(&mut self) -> Result<(u32, Vec<u8>)> {
        let nonce = os_random::<16>()?;
        let resp = self.cmd(&tpm_wire::start_policy_session_command(&nonce))?;
        tpm_wire::parse_start_auth_session_nonce(&resp).map_err(wire("starting a policy session"))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        while let Some(h) = self.handles.pop() {
            let _ = self.t.submit(&tpm_wire::flush_context_command(h));
        }
    }
}

/// The authorising key at `handle`, checked: a restricted P-256 ECDSA signing
/// key the TPM generated, certified by this TPM's endorsement key. Returns its
/// name, which the root's policy binds.
fn certified_authorizer(s: &mut Session, handle: u32) -> Result<Vec<u8>> {
    let resp = s.cmd(&tpm_wire::read_public_command(handle))?;
    let ak = tpm_wire::parse_read_public_response(&resp).map_err(|e| {
        tpm_err(format!(
            "the root's authorising key 0x{handle:08x} cannot be read ({e}); run `tenzro-node tpm \
             provision` once on this machine"
        ))
    })?;
    check_authorizer(&ak, handle)?;
    let name = ak.name().map_err(wire("the authorising key's name"))?;

    // This TPM's endorsement key, made again from the TCG template.
    let (ek, ek_public) = crate::tpm_provision::transient_endorsement_key(&mut *s.t)?;
    s.handles.push(ek);
    let secret = Zeroizing::new(os_random::<32>()?);
    let credential = crate::credential::make_credential(&ek_public, &name, &secret[..])?;
    let (session, _) = s.policy_session()?;
    let resp = s.cmd(&tpm_wire::policy_secret_endorsement_command(session))?;
    tpm_wire::response_body(&resp).map_err(wire("authorising the endorsement key"))?;
    let resp = s.cmd(&tpm_wire::activate_credential_command(
        handle,
        ek,
        session,
        &credential.blob,
        &credential.encrypted_secret,
    ))?;
    let released = Zeroizing::new(tpm_wire::parse_activate_credential_response(&resp).map_err(
        |e| {
            tpm_err(format!(
                "the root's authorising key 0x{handle:08x} is not certified by this TPM's \
                 endorsement key ({e})"
            ))
        },
    )?);
    {
        use subtle::ConstantTimeEq;
        if released.len() != secret.len() || !bool::from(released[..].ct_eq(&secret[..])) {
            return Err(tpm_err(format!(
                "the root's authorising key 0x{handle:08x} did not recover the endorsement \
                 key's credential"
            )));
        }
    }
    Ok(name)
}

fn check_authorizer(ak: &PublicArea, handle: u32) -> Result<()> {
    if ak.attributes != tpm_wire::ATTESTATION_KEY_ATTRIBUTES
        || ak.name_alg != tpm_wire::TPM2_ALG_SHA256
        || ak.p256_sec1().is_none()
    {
        return Err(tpm_err(format!(
            "TPM handle 0x{handle:08x} is not a restricted P-256 signing key the TPM generated"
        )));
    }
    Ok(())
}

/// Refuse any root that is not a TPM-generated HMAC key bound to `policy`.
fn check_public(public: &[u8], policy: &[u8; 32]) -> Result<()> {
    let p = tpm_wire::parse_keyedhash_public(public).map_err(wire("TPM root public area"))?;
    if p.name_alg != tpm_wire::TPM2_ALG_SHA256
        || p.attributes != tpm_wire::POLICY_HMAC_KEY_ATTRIBUTES
        || p.auth_policy != policy
        || p.scheme != tpm_wire::TPM2_ALG_HMAC
        || p.scheme_hash != tpm_wire::TPM2_ALG_SHA256
    {
        return Err(tpm_err(
            "the stored TPM root is not a TPM-generated HMAC key bound to this machine's \
             authorising key and its current secure-boot state (PCR 7); refusing it",
        ));
    }
    Ok(())
}

fn encode_blob(private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut out = BLOB_MAGIC.to_vec();
    out.extend_from_slice(&(private.len() as u16).to_be_bytes());
    out.extend_from_slice(private);
    out.extend_from_slice(&(public.len() as u16).to_be_bytes());
    out.extend_from_slice(public);
    out
}

fn decode_blob(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let bad = || tpm_err("the stored TPM root blob is malformed");
    let rest = bytes.strip_prefix(BLOB_MAGIC).ok_or_else(bad)?;
    let mut r = tpm_wire::Reader::new(rest);
    let private = r.tpm2b().map_err(|_| bad())?.to_vec();
    let public = r.tpm2b().map_err(|_| bad())?.to_vec();
    if r.remaining() != 0 {
        return Err(bad());
    }
    Ok((private, public))
}

/// The TPM derivation root. Holds the wrapped blob and the authorising key's
/// handle; no output is kept.
pub(crate) struct TpmRoot {
    private: Vec<u8>,
    public: Vec<u8>,
    authorizer: u32,
    open: Opener,
    /// The root loaded in the TPM, kept for the life of this value so a
    /// derivation costs one policy session, one signature and one HMAC.
    /// Transient only: flushed on drop, and by the kernel resource manager
    /// when the process exits.
    loaded: Mutex<Option<Loaded>>,
    /// Paces loading the root again after a load failed, so a TPM that is
    /// not answering is not asked for the same load over and over.
    reload: Mutex<crate::retry::RetryGate>,
}

/// A connection with the storage parent and the root loaded in it.
struct Loaded {
    s: Session,
    key: u32,
}

/// Why one attempt at a TPM operation failed.
enum Attempt {
    /// The loaded objects are gone (the TPM was reset, or the connection
    /// broke), so loading them again may succeed.
    Lost(DeviceKeyError),
    Failed(DeviceKeyError),
}

/// A command failed outright. A TPM that did not answer has not lost the
/// root: loading it again would queue behind the stuck command, so that is a
/// plain failure, not a loss.
fn lost(e: DeviceKeyError) -> Attempt {
    if crate::tpm_exec::is_stall(&e) {
        Attempt::Failed(e)
    } else {
        Attempt::Lost(e)
    }
}

/// Classify a response-parsing failure.
fn step<T>(what: &str, r: std::result::Result<T, WireError>) -> std::result::Result<T, Attempt> {
    r.map_err(|e| match e {
        WireError::ResponseCode(c) if tpm_wire::handle_lost(c) => Attempt::Lost(wire(what)(e)),
        e => Attempt::Failed(wire(what)(e)),
    })
}

impl TpmRoot {
    /// The root for this machine: the kernel TPM resource manager (Linux) or
    /// TPM Base Services (Windows), the
    /// default blob location and the configured authorising key.
    #[cfg(any(target_os = "linux", windows))]
    pub(crate) fn open_or_create_on_device() -> Result<Self> {
        if !crate::backend_tpm::available() {
            return Err(tpm_err(
                "this machine has no usable TPM 2.0 (the kernel resource manager or TPM Base Services), so it has no derivation root",
            ));
        }
        let open: Opener = Box::new(|| {
            crate::backend_tpm::TpmDevice::open().map(|d| Box::new(d) as Box<dyn TpmTransport>)
        });
        Self::open_or_create(
            &crate::tpm_provision::default_dir()?.join(ROOT_FILE),
            authorization_handle(),
            open,
        )
    }

    fn open_or_create(path: &Path, authorizer: u32, open: Opener) -> Result<Self> {
        let policy = {
            let mut s = Session {
                t: open()?,
                handles: Vec::new(),
            };
            let name = certified_authorizer(&mut s, authorizer)?;
            let resp = s.cmd(&tpm_wire::pcr_read_command(ROOT_PCR))?;
            let value = tpm_wire::parse_pcr_read_response(&resp)
                .map_err(wire("reading the secure-boot state (PCR 7)"))?;
            root_policy(&name, &tpm_wire::pcr_digest(&value))
        };
        let io = |e: std::io::Error| tpm_err(format!("TPM root {}: {e}", path.display()));
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let bytes = Self::create(&policy, &open)?;
                if let Some(dir) = path.parent() {
                    crate::tpm_provision::create_private_dir(dir).map_err(io)?;
                }
                if crate::tpm_provision::write_new(path, &bytes).map_err(io)? {
                    bytes
                } else {
                    std::fs::read(path).map_err(io)?
                }
            }
            Err(e) => return Err(io(e)),
        };
        let (private, public) = decode_blob(&bytes)?;
        check_public(&public, &policy)?;
        Ok(Self {
            private,
            public,
            authorizer,
            open,
            loaded: Mutex::new(None),
            reload: Mutex::new(crate::retry::RetryGate::new(
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(30),
            )),
        })
    }

    /// Have the TPM generate a new root bound to `policy` and return its
    /// encoded blob.
    fn create(policy: &[u8; 32], open: &Opener) -> Result<Vec<u8>> {
        let mut s = Session {
            t: open()?,
            handles: Vec::new(),
        };
        let parent = s.parent()?;
        let template = tpm_wire::policy_hmac_key_template(policy);
        let resp = s.cmd(&tpm_wire::create_command(parent, &[], &template))?;
        let (private, public) =
            tpm_wire::parse_create_response(&resp).map_err(wire("creating the TPM root"))?;
        check_public(&public, policy)?;
        Ok(encode_blob(&private, &public))
    }

    /// HMAC `data` with the root. The root is loaded on first use and kept;
    /// if the TPM has lost it (a TPM reset, a broken connection) it is
    /// loaded again once and the operation retried.
    pub(crate) fn hmac(&self, data: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        let mut reloaded = false;
        loop {
            if loaded.is_none() {
                let mut gate = self.reload.lock().unwrap_or_else(|e| e.into_inner());
                if let Err(wait) = gate.check(std::time::Instant::now()) {
                    return Err(tpm_err(format!(
                        "the TPM did not load the derivation root ({} failed loads); next try in {:.1}s",
                        gate.failures(),
                        wait.as_secs_f64()
                    )));
                }
                match self.load() {
                    Ok(l) => {
                        gate.succeeded();
                        *loaded = Some(l);
                    }
                    Err(e) => {
                        gate.failed(std::time::Instant::now());
                        return Err(e);
                    }
                }
            }
            let l = loaded.as_mut().expect("loaded above");
            match Self::hmac_once(l, self.authorizer, data) {
                Ok(mac) => return Ok(mac),
                Err(Attempt::Lost(e)) if !reloaded => {
                    tracing::warn!(
                        "the TPM no longer holds the derivation root ({e}); loading it again"
                    );
                    *loaded = None;
                    reloaded = true;
                }
                Err(Attempt::Lost(e)) => {
                    *loaded = None;
                    return Err(e);
                }
                Err(Attempt::Failed(e)) => return Err(e),
            }
        }
    }

    /// Open a connection and load the root under the storage parent.
    fn load(&self) -> Result<Loaded> {
        let mut s = Session {
            t: (self.open)()?,
            handles: Vec::new(),
        };
        let parent = s.parent()?;
        let resp = s.cmd(&tpm_wire::load_command(parent, &self.private, &self.public))?;
        let key = tpm_wire::parse_load_response(&resp).map_err(wire("loading the TPM root"))?;
        s.handles.push(key);
        Ok(Loaded { s, key })
    }

    /// The authorising key's signature over a policy session's `nonceTPM`,
    /// the expiration and [`ROOT_POLICY_REF`], made inside the TPM.
    fn authorize(
        l: &mut Loaded,
        authorizer: u32,
        nonce_tpm: &[u8],
        expiration: i32,
    ) -> std::result::Result<[u8; 64], Attempt> {
        let message = tpm_wire::policy_signed_message(nonce_tpm, expiration, ROOT_POLICY_REF);
        let resp =
            l.s.cmd(&tpm_wire::hash_command(
                &message,
                tpm_wire::TPM2_RH_ENDORSEMENT,
            ))
            .map_err(lost)?;
        let (digest, ticket) = step(
            "hashing the authorisation",
            tpm_wire::parse_hash_response(&resp),
        )?;
        let resp =
            l.s.cmd(&tpm_wire::sign_validated_command(
                authorizer, &digest, &ticket,
            ))
            .map_err(lost)?;
        step(
            "signing the authorisation",
            tpm_wire::parse_sign_response(&resp),
        )
    }

    fn hmac_once(
        l: &mut Loaded,
        authorizer: u32,
        data: &[u8],
    ) -> std::result::Result<Zeroizing<[u8; 32]>, Attempt> {
        let (mut session, mut nonce_tpm) = l.s.policy_session().map_err(lost)?;
        // A message starting with TPM_GENERATED_VALUE gets no hash ticket, so a
        // nonce that begins with it is replaced.
        while nonce_tpm.starts_with(&tpm_wire::TPM2_GENERATED_VALUE.to_be_bytes()) {
            let _ = l.s.t.submit(&tpm_wire::flush_context_command(session));
            (session, nonce_tpm) = l.s.policy_session().map_err(lost)?;
        }
        let mut run = || {
            let resp =
                l.s.cmd(&tpm_wire::policy_pcr_command(session, &[], ROOT_PCR))
                    .map_err(lost)?;
            step("TPM2_PolicyPCR", tpm_wire::response_body(&resp).map(|_| ()))?;
            let expiration = -ROOT_POLICY_EXPIRATION;
            let signature = Self::authorize(l, authorizer, &nonce_tpm, expiration)?;
            let resp =
                l.s.cmd(&tpm_wire::policy_signed_command(
                    authorizer,
                    session,
                    &nonce_tpm,
                    ROOT_POLICY_REF,
                    expiration,
                    &signature,
                ))
                .map_err(lost)?;
            step(
                "TPM2_PolicySigned",
                tpm_wire::response_body(&resp).map(|_| ()),
            )?;
            let resp =
                l.s.cmd(&tpm_wire::hmac_command(l.key, session, &[], data))
                    .map_err(lost)?;
            step("TPM root HMAC", tpm_wire::parse_hmac_response(&resp))
        };
        let out = run();
        // A completed HMAC closes the session, since it was not continued;
        // any other outcome leaves it open.
        if out.is_err() {
            let _ = l.s.t.submit(&tpm_wire::flush_context_command(session));
        }
        out.map(Zeroizing::new)
    }
}

#[cfg(test)]
mod tests {
    //! The ignored TPM tests run against one of two TPMs:
    //!
    //! - a real chip through the kernel resource manager: set
    //!   `TENZRO_TEST_TPM=/dev/tpmrm0` and run as any user that can open it;
    //! - the TCG reference TPM simulator (`tpm2-simulator` from
    //!   ms-tpm-20-ref) over its TCP protocol: start it and set
    //!   `TENZRO_TEST_TPM_SIM=<host>:<command port>` (the platform port is the
    //!   next one).
    //!
    //! Then run `cargo test -p tenzro-device-key -- --ignored --test-threads=1`.
    //!
    //! Every object the tests create is transient and flushed. Each test reads
    //! the chip's persistent handles, NV indices and transient objects before
    //! and after it runs and fails if any of them changed, so a run can never
    //! add, evict or overwrite a key that was on the chip before it.

    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::path::PathBuf;
    use std::process::Command;

    const SEND_COMMAND: u32 = 8;
    const SESSION_END: u32 = 20;
    const POWER_ON: u32 = 1;
    const POWER_OFF: u32 = 2;
    const NV_ON: u32 = 11;

    /// The simulator's TCP framing, standing in for `/dev/tpmrm0`.
    struct Mssim(TcpStream);

    impl Mssim {
        fn connect(addr: &str) -> Result<Self> {
            TcpStream::connect(addr)
                .map(Self)
                .map_err(|e| tpm_err(format!("TPM simulator {addr}: {e}")))
        }
    }

    fn read_u32(s: &mut TcpStream) -> Result<u32> {
        let mut b = [0u8; 4];
        s.read_exact(&mut b)
            .map_err(|e| tpm_err(format!("simulator read: {e}")))?;
        Ok(u32::from_be_bytes(b))
    }

    impl TpmTransport for Mssim {
        fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let mut frame = SEND_COMMAND.to_be_bytes().to_vec();
            frame.push(0); // locality
            frame.extend_from_slice(&(command.len() as u32).to_be_bytes());
            frame.extend_from_slice(command);
            self.0
                .write_all(&frame)
                .map_err(|e| tpm_err(format!("simulator write: {e}")))?;
            let len = read_u32(&mut self.0)? as usize;
            let mut resp = vec![0u8; len];
            self.0
                .read_exact(&mut resp)
                .map_err(|e| tpm_err(format!("simulator read: {e}")))?;
            read_u32(&mut self.0)?; // acknowledgement
            Ok(resp)
        }
    }

    impl Drop for Mssim {
        fn drop(&mut self) {
            let _ = self.0.write_all(&SESSION_END.to_be_bytes());
        }
    }

    /// swtpm's TCP command channel: raw commands, raw responses.
    struct SwtpmChannel(TcpStream);

    impl TpmTransport for SwtpmChannel {
        fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            let io = |e: std::io::Error| tpm_err(format!("swtpm: {e}"));
            self.0.write_all(command).map_err(io)?;
            let mut head = [0u8; 10];
            self.0.read_exact(&mut head).map_err(io)?;
            let size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;
            let mut rest = vec![0u8; size.saturating_sub(10)];
            self.0.read_exact(&mut rest).map_err(io)?;
            Ok([head.as_slice(), &rest].concat())
        }
    }

    /// The TPM the ignored tests run against.
    #[derive(Clone)]
    enum Target {
        /// A real chip at this device path.
        Device(String),
        /// The simulator at `<host>:<command port>`.
        Sim(String),
        /// A software TPM (`swtpm socket --server type=tcp`) at
        /// `<host>:<port>`, on a private test network.
        Swtpm(String),
    }

    impl Target {
        fn from_env() -> Option<Self> {
            match std::env::var("TENZRO_TEST_TPM") {
                Ok(device) => Some(Self::Device(device)),
                Err(_) => match std::env::var("TENZRO_TEST_TPM_SIM") {
                    Ok(a) => Some(Self::Sim(a)),
                    Err(_) => std::env::var("TENZRO_TEST_SWTPM").ok().map(Self::Swtpm),
                },
            }
        }

        /// Set this target in a child process's environment.
        fn export(&self, cmd: &mut Command) {
            match self {
                Self::Device(d) => cmd
                    .env("TENZRO_TEST_TPM", d)
                    .env_remove("TENZRO_TEST_TPM_SIM"),
                Self::Sim(a) => cmd
                    .env("TENZRO_TEST_TPM_SIM", a)
                    .env_remove("TENZRO_TEST_TPM"),
                Self::Swtpm(a) => cmd
                    .env("TENZRO_TEST_SWTPM", a)
                    .env_remove("TENZRO_TEST_TPM")
                    .env_remove("TENZRO_TEST_TPM_SIM"),
            };
        }
    }

    fn target() -> Target {
        Target::from_env().expect("TENZRO_TEST_TPM, TENZRO_TEST_TPM_SIM or TENZRO_TEST_SWTPM")
    }

    #[cfg(target_os = "linux")]
    fn device_opener(device: &str) -> Opener {
        assert_eq!(
            device,
            crate::backend_tpm::DEVICE,
            "TENZRO_TEST_TPM must name the device this crate opens"
        );
        Box::new(|| {
            crate::backend_tpm::TpmDevice::open().map(|d| Box::new(d) as Box<dyn TpmTransport>)
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn device_opener(device: &str) -> Opener {
        let device = device.to_string();
        Box::new(move || {
            Err(tpm_err(format!(
                "{device}: this platform has no TPM device transport"
            )))
        })
    }

    const TPM2_CAP_HANDLES: u32 = 1;

    /// Every handle the chip lists in the transient, persistent and NV ranges.
    /// Behind the kernel resource manager the transient range is this
    /// connection's own, so it is empty; on the simulator it is chip-wide.
    fn chip_handles(t: &Target) -> Vec<u32> {
        let mut out = Vec::new();
        let mut tpm = opener(t)().unwrap();
        for range in [0x8000_0000u32, 0x8100_0000, 0x0100_0000] {
            let mut next = range;
            loop {
                let mut b = tpm_wire::Writer::new();
                b.u32(TPM2_CAP_HANDLES).u32(next).u32(64);
                let body = b.finish();
                let mut cmd = tpm_wire::Writer::new();
                cmd.u16(tpm_wire::TPM2_ST_NO_SESSIONS)
                    .u32(10 + body.len() as u32)
                    .u32(tpm_wire::TPM2_CC_GET_CAPABILITY)
                    .bytes(&body);
                let resp = tpm.submit(&cmd.finish()).unwrap();
                let mut r = tpm_wire::response_body(&resp).unwrap();
                let more = r.u8().unwrap();
                assert_eq!(r.u32().unwrap(), TPM2_CAP_HANDLES);
                let count = r.u32().unwrap();
                let mut last = None;
                for _ in 0..count {
                    let h = r.u32().unwrap();
                    if h >> 24 == range >> 24 {
                        out.push(h);
                        last = Some(h);
                    }
                }
                match (more, last) {
                    (1, Some(h)) => next = h + 1,
                    _ => break,
                }
            }
        }
        out
    }

    /// Run `test` against the target, failing if the chip's handles differ
    /// afterwards, whether the test passed or not.
    fn guarded(test: impl FnOnce(&Target)) {
        let t = target();
        boot(&t);
        // The storage root is persistent and made by provisioning; idempotent.
        crate::tpm_provision::provision_with(
            &mut *opener(&t)().unwrap(),
            crate::tpm_provision::IDENTITY_KEY_LABEL,
        )
        .unwrap();
        let before = chip_handles(&t);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(&t)));
        let after = chip_handles(&t);
        let show = |v: &[u32]| {
            v.iter()
                .map(|h| format!("0x{h:08x}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        eprintln!("TPM handles before: [{}]", show(&before));
        eprintln!("TPM handles after:  [{}]", show(&after));
        assert_eq!(before, after, "the test changed the TPM's handles");
        if let Err(p) = outcome {
            std::panic::resume_unwind(p);
        }
    }

    fn platform(addr: &str, signals: &[u32]) {
        let (host, port) = addr.rsplit_once(':').unwrap();
        let port: u16 = port.parse().unwrap();
        let mut p = TcpStream::connect(format!("{host}:{}", port + 1)).unwrap();
        for s in signals {
            p.write_all(&s.to_be_bytes()).unwrap();
            read_u32(&mut p).unwrap();
        }
        let _ = p.write_all(&SESSION_END.to_be_bytes());
    }

    /// Power the simulator on and start it; idempotent. A real chip is
    /// already running.
    fn boot(t: &Target) {
        let Target::Sim(addr) = t else { return };
        platform(addr, &[POWER_ON, NV_ON]);
        let startup = [0x80, 0x01, 0, 0, 0, 12, 0, 0, 0x01, 0x44, 0, 0];
        let resp = Mssim::connect(addr).unwrap().submit(&startup).unwrap();
        let code = u32::from_be_bytes(resp[6..10].try_into().unwrap());
        assert!(code == 0 || code == 0x100, "TPM2_Startup: 0x{code:x}");
    }

    fn opener(t: &Target) -> Opener {
        match t {
            Target::Device(device) => device_opener(device),
            Target::Sim(addr) => {
                let addr = addr.clone();
                Box::new(move || {
                    Mssim::connect(&addr).map(|m| Box::new(m) as Box<dyn TpmTransport>)
                })
            }
            Target::Swtpm(addr) => {
                let addr = addr.clone();
                Box::new(move || {
                    TcpStream::connect(&addr)
                        .map(|s| Box::new(SwtpmChannel(s)) as Box<dyn TpmTransport>)
                        .map_err(|e| tpm_err(format!("swtpm {addr}: {e}")))
                })
            }
        }
    }

    /// The authorising key the tests bind roots to: the attestation key
    /// provisioning made.
    const AK: u32 = tpm_wire::NODE_ATTESTATION_HANDLE;

    /// A root blob location in a fresh directory that is removed on drop.
    struct TempBlob(PathBuf);

    impl TempBlob {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("tenzro-derive-tpm-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn path(&self) -> PathBuf {
            self.0.join(ROOT_FILE)
        }
    }

    impl Drop for TempBlob {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn policy() -> [u8; 32] {
        root_policy(&[0x00, 0x0b, 7, 7, 7], &[3u8; 32])
    }

    #[test]
    fn the_policy_binds_the_authorising_key_the_boot_state_and_the_reference() {
        let p = policy();
        assert_ne!(
            p,
            root_policy(&[0x00, 0x0b, 7, 7, 8], &[3u8; 32]),
            "another key"
        );
        assert_ne!(
            p,
            root_policy(&[0x00, 0x0b, 7, 7, 7], &[4u8; 32]),
            "another boot state"
        );
        let signed_only =
            tpm_wire::policy_signed_update(&[0u8; 32], &[0x00, 0x0b, 7, 7, 7], ROOT_POLICY_REF);
        assert_ne!(p, signed_only, "the PCR term is part of the policy");
        let other_ref = tpm_wire::policy_signed_update(
            &tpm_wire::policy_pcr_update(&[0u8; 32], ROOT_PCR, &[3u8; 32]),
            &[0x00, 0x0b, 7, 7, 7],
            b"other",
        );
        assert_ne!(p, other_ref, "another policy reference");
        let t = tpm_wire::policy_hmac_key_template(&p);
        let k = tpm_wire::parse_keyedhash_public(&t).unwrap();
        assert_eq!(k.attributes & tpm_wire::TPMA_OBJECT_USERWITHAUTH, 0);
        assert_ne!(k.attributes & tpm_wire::TPMA_OBJECT_SENSITIVEDATAORIGIN, 0);
        assert_ne!(k.attributes & tpm_wire::TPMA_OBJECT_FIXEDTPM, 0);
        assert!(check_public(&t, &p).is_ok());
        // a root bound to another key or another boot state is refused
        assert!(check_public(&t, &root_policy(&[1], &[3u8; 32])).is_err());
        assert!(check_public(&t, &root_policy(&[0x00, 0x0b, 7, 7, 7], &[5u8; 32])).is_err());
    }

    /// The password-authorised root is gone: its policy digest, the
    /// published PolicyAuthValue digest, opens nothing, and a blob in the old
    /// format is refused.
    #[test]
    fn the_password_policy_and_its_blobs_are_refused() {
        let password = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update([0u8; 32]);
            h.update(0x0000_016Bu32.to_be_bytes());
            let d: [u8; 32] = h.finalize().into();
            d
        };
        assert_eq!(
            hex(&password),
            "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"
        );
        assert!(check_public(&tpm_wire::policy_hmac_key_template(&password), &policy()).is_err());
        let mut old = b"tenzro/device-key/tpm-derive-root\n".to_vec();
        old.extend_from_slice(&[0, 1, 9, 0, 1, 9]);
        assert!(decode_blob(&old).is_err());
    }

    #[test]
    fn a_root_usable_without_the_policy_is_refused() {
        let p = policy();
        let mut t = tpm_wire::policy_hmac_key_template(&p);
        // attributes live at offset 4..8 of TPMT_PUBLIC
        let attrs = tpm_wire::POLICY_HMAC_KEY_ATTRIBUTES | tpm_wire::TPMA_OBJECT_USERWITHAUTH;
        t[4..8].copy_from_slice(&attrs.to_be_bytes());
        assert!(check_public(&t, &p).is_err());
        let chosen =
            tpm_wire::POLICY_HMAC_KEY_ATTRIBUTES & !tpm_wire::TPMA_OBJECT_SENSITIVEDATAORIGIN;
        let mut t = tpm_wire::policy_hmac_key_template(&p);
        t[4..8].copy_from_slice(&chosen.to_be_bytes());
        assert!(check_public(&t, &p).is_err());
        assert!(check_public(&tpm_wire::policy_hmac_key_template(&[0u8; 32]), &p).is_err());
    }

    #[test]
    fn a_blob_round_trips_and_garbage_is_refused() {
        let enc = encode_blob(&[1, 2, 3], &[4, 5]);
        assert_eq!(decode_blob(&enc).unwrap(), (vec![1, 2, 3], vec![4, 5]));
        assert!(decode_blob(&enc[1..]).is_err());
        let mut long = enc.clone();
        long.push(0);
        assert!(decode_blob(&long).is_err());
    }

    #[test]
    fn the_authorising_handle_is_persistent_and_set_once() {
        assert!(set_authorization_handle(0x8000_0001).is_err());
        set_authorization_handle(tpm_wire::NODE_ATTESTATION_HANDLE).unwrap();
        set_authorization_handle(tpm_wire::NODE_ATTESTATION_HANDLE).unwrap();
        assert!(set_authorization_handle(0x8101_8002).is_err());
    }

    fn derive_hex(root: &TpmRoot, label: &str) -> String {
        hex(&root.hmac(&crate::derive::hardware_input(label)).unwrap()[..])
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_the_root_is_deterministic_per_label_and_separates_labels() {
        guarded(|t| {
            let blob = TempBlob::new("det");
            let root = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            let a1 = derive_hex(&root, "tenzro/test/a");
            let a2 = derive_hex(&root, "tenzro/test/a");
            let b = derive_hex(&root, "tenzro/test/b");
            assert_eq!(a1, a2);
            assert_ne!(a1, b);
            // Reopening the stored blob gives the same root.
            let again = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            assert_eq!(derive_hex(&again, "tenzro/test/a"), a1);
            // A second root on the same chip is an unrelated key.
            let blob2 = TempBlob::new("det2");
            let other = TpmRoot::open_or_create(&blob2.path(), AK, opener(t)).unwrap();
            assert_ne!(derive_hex(&other, "tenzro/test/a"), a1);
        });
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_every_key_kind_derives_through_the_tpm_root() {
        guarded(every_key_kind_derives);
    }

    fn every_key_kind_derives(t: &Target) {
        let blob = TempBlob::new("kinds");
        let path = blob.path();
        let open = || {
            crate::derive::DerivationRoot::from_tpm_root(
                TpmRoot::open_or_create(&path, AK, opener(t)).unwrap(),
            )
        };
        let (r1, r2) = (open(), open());
        assert_eq!(r1.backend(), crate::derive::DeriveBackend::Tpm);
        let l = "tenzro/test/kinds";
        let e = |r: &crate::derive::DerivationRoot| r.with_ed25519(l, |k| k.public_key()).unwrap();
        let x = |r: &crate::derive::DerivationRoot| r.with_x25519(l, |k| k.public_key()).unwrap();
        let m =
            |r: &crate::derive::DerivationRoot| r.with_ml_dsa65(l, |k| k.verifying_key()).unwrap();
        assert_eq!(e(&r1), e(&r2));
        assert_eq!(x(&r1), x(&r2));
        assert_eq!(m(&r1), m(&r2));
        let other = r1
            .with_ed25519("tenzro/test/other", |k| k.public_key())
            .unwrap();
        assert_ne!(other, e(&r1));
    }

    /// Power-cycling needs the simulator's platform port; a real chip's
    /// restart is a reboot.
    #[test]
    #[ignore = "needs the TPM simulator (TENZRO_TEST_TPM_SIM)"]
    fn sim_the_root_survives_a_tpm_restart() {
        guarded(|t| {
            let Target::Sim(addr) = t else {
                panic!("power-cycling needs TENZRO_TEST_TPM_SIM");
            };
            let blob = TempBlob::new("restart");
            let root = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            let before = derive_hex(&root, "tenzro/test/restart");
            platform(addr, &[POWER_OFF]);
            boot(t);
            assert_eq!(derive_hex(&root, "tenzro/test/restart"), before);
        });
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_a_substituted_root_is_refused() {
        guarded(a_substituted_root_is_refused);
    }

    fn a_substituted_root_is_refused(t: &Target) {
        // A keyed-hash key whose bytes the substituter chose and which a
        // plain password opens: the TPM will load it, so only the public-area
        // check stands between it and every derived key.
        let mut s = Session {
            t: opener(t)().unwrap(),
            handles: Vec::new(),
        };
        let parent = s.parent().unwrap();
        let attrs = (tpm_wire::POLICY_HMAC_KEY_ATTRIBUTES
            & !tpm_wire::TPMA_OBJECT_SENSITIVEDATAORIGIN)
            | tpm_wire::TPMA_OBJECT_USERWITHAUTH;
        let mut template = tpm_wire::policy_hmac_key_template(&[0u8; 32]);
        template[4..8].copy_from_slice(&attrs.to_be_bytes());
        let mut b = tpm_wire::Writer::new();
        b.u32(parent);
        b.u32(9).u32(tpm_wire::TPM2_RS_PW).u16(0).u8(0).u16(0);
        let mut sensitive = tpm_wire::Writer::new();
        sensitive.tpm2b(&[]).tpm2b(&[0x42; 32]);
        b.tpm2b(&sensitive.finish())
            .tpm2b(&template)
            .tpm2b(&[])
            .u32(0);
        let body = b.finish();
        let mut cmd = tpm_wire::Writer::new();
        cmd.u16(tpm_wire::TPM2_ST_SESSIONS)
            .u32(10 + body.len() as u32)
            .u32(tpm_wire::TPM2_CC_CREATE)
            .bytes(&body);
        let (private, public) =
            tpm_wire::parse_create_response(&s.cmd(&cmd.finish()).unwrap()).unwrap();
        drop(s);

        let blob = TempBlob::new("swap");
        let path = blob.path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, encode_blob(&private, &public)).unwrap();
        let err = TpmRoot::open_or_create(&path, AK, opener(t))
            .err()
            .expect("refused");
        assert!(err.to_string().contains("refusing it"), "{err}");
    }

    /// A signature by `key` over `nonce`, `expiration` and the root's policy
    /// reference, made in the TPM.
    fn signed_by(s: &mut Session, key: u32, nonce: &[u8], expiration: i32) -> [u8; 64] {
        let m = tpm_wire::policy_signed_message(nonce, expiration, ROOT_POLICY_REF);
        let (digest, ticket) = tpm_wire::parse_hash_response(
            &s.cmd(&tpm_wire::hash_command(&m, tpm_wire::TPM2_RH_ENDORSEMENT))
                .unwrap(),
        )
        .unwrap();
        tpm_wire::parse_sign_response(
            &s.cmd(&tpm_wire::sign_validated_command(key, &digest, &ticket))
                .unwrap(),
        )
        .unwrap()
    }

    /// One HMAC by the root at `key` in `session`, as the TPM answers it.
    fn hmac_in(
        s: &mut Session,
        key: u32,
        session: u32,
    ) -> std::result::Result<[u8; 32], WireError> {
        tpm_wire::parse_hmac_response(
            &s.cmd(&tpm_wire::hmac_command(
                key,
                session,
                &[],
                b"tenzro/test/policy",
            ))
            .unwrap(),
        )
    }

    fn policy_signed(
        s: &mut Session,
        key: u32,
        session: u32,
        nonce: &[u8],
        expiration: i32,
        sig: &[u8; 64],
    ) -> std::result::Result<(), WireError> {
        tpm_wire::response_body(
            &s.cmd(&tpm_wire::policy_signed_command(
                key,
                session,
                nonce,
                ROOT_POLICY_REF,
                expiration,
                sig,
            ))
            .unwrap(),
        )
        .map(|_| ())
    }

    /// The boot-state term of the root's policy, on the PCR's current value.
    fn pcr_term(s: &mut Session, session: u32) {
        tpm_wire::response_body(
            &s.cmd(&tpm_wire::policy_pcr_command(session, &[], ROOT_PCR))
                .unwrap(),
        )
        .unwrap();
    }

    /// `TPM2_PCR_Extend` of the root's PCR, on a private TPM only.
    fn extend_root_pcr(s: &mut Session) {
        let mut b = tpm_wire::Writer::new();
        b.u32(u32::from(ROOT_PCR));
        b.u32(9).u32(tpm_wire::TPM2_RS_PW).u16(0).u8(0).u16(0);
        b.u32(1).u16(tpm_wire::TPM2_ALG_SHA256).bytes(&[0x5a; 32]);
        let body = b.finish();
        let mut cmd = tpm_wire::Writer::new();
        cmd.u16(tpm_wire::TPM2_ST_SESSIONS)
            .u32(10 + body.len() as u32)
            .u32(0x0000_0182)
            .bytes(&body);
        tpm_wire::response_body(&s.cmd(&cmd.finish()).unwrap()).unwrap();
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_the_root_opens_only_in_the_boot_state_it_was_bound_to() {
        guarded(|t| {
            let mut s = Session {
                t: opener(t)().unwrap(),
                handles: Vec::new(),
            };
            let name = certified_authorizer(&mut s, AK).unwrap();
            let value = tpm_wire::parse_pcr_read_response(
                &s.cmd(&tpm_wire::pcr_read_command(ROOT_PCR)).unwrap(),
            )
            .unwrap();
            let now = tpm_wire::pcr_digest(&value);
            let mut other = value.clone();
            other[0] ^= 1;
            let elsewhere = tpm_wire::pcr_digest(&other);

            // the right boot state unlocks
            let blob = TempBlob::new("pcr-right");
            let root = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            derive_hex(&root, "tenzro/test/pcr");

            // a root bound to another PCR 7 value: the TPM refuses its use here
            let open = opener(t);
            let wrong = TpmRoot::create(&root_policy(&name, &elsewhere), &open).unwrap();
            let (private, public) = decode_blob(&wrong).unwrap();
            let parent = s.parent().unwrap();
            let key = tpm_wire::parse_load_response(
                &s.cmd(&tpm_wire::load_command(parent, &private, &public))
                    .unwrap(),
            )
            .unwrap();
            s.handles.push(key);
            let (session, nonce) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            let sig = signed_by(&mut s, AK, &nonce, -ROOT_POLICY_EXPIRATION);
            policy_signed(&mut s, AK, session, &nonce, -ROOT_POLICY_EXPIRATION, &sig).unwrap();
            assert!(
                matches!(
                    hmac_in(&mut s, key, session),
                    Err(WireError::ResponseCode(_))
                ),
                "wrong PCR value"
            );
            let _ = s.cmd(&tpm_wire::flush_context_command(session));
            // and the TPM refuses the PCR term outright when told to expect that value
            let (session, _) = s.policy_session().unwrap();
            let resp = s
                .cmd(&tpm_wire::policy_pcr_command(session, &elsewhere, ROOT_PCR))
                .unwrap();
            assert!(
                tpm_wire::response_body(&resp).is_err(),
                "expected another PCR value"
            );
            let _ = s.cmd(&tpm_wire::flush_context_command(session));
            // a stored root from another boot state is refused before use
            let moved = TempBlob::new("pcr-moved");
            std::fs::create_dir_all(moved.path().parent().unwrap()).unwrap();
            std::fs::write(moved.path(), &wrong).unwrap();
            let err = TpmRoot::open_or_create(&moved.path(), AK, opener(t))
                .err()
                .expect("refused");
            assert!(err.to_string().contains("secure-boot state"), "{err}");
            assert_ne!(now, elsewhere);

            // On a private TPM the boot state can really change: extend PCR 7 and the
            // root made before it no longer opens.
            if std::env::var("TENZRO_TEST_TPM_PRIVATE").as_deref() == Ok("1") {
                extend_root_pcr(&mut s);
                let err = root
                    .hmac(&crate::derive::hardware_input("tenzro/test/pcr"))
                    .expect_err("refused after the boot state changed");
                assert!(err.to_string().contains("TPM"), "{err}");
                println!("PCR 7 extended on the private TPM: the root is refused");
            }
        });
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_the_root_opens_only_for_a_fresh_signature_by_its_key() {
        guarded(|t| {
            let blob = TempBlob::new("signed");
            let root = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            // the right key, through the root's own path
            derive_hex(&root, "tenzro/test/signed");

            let mut s = Session {
                t: opener(t)().unwrap(),
                handles: Vec::new(),
            };
            let parent = s.parent().unwrap();
            let key = tpm_wire::parse_load_response(
                &s.cmd(&tpm_wire::load_command(parent, &root.private, &root.public))
                    .unwrap(),
            )
            .unwrap();
            s.handles.push(key);
            let refused = |r: std::result::Result<[u8; 32], WireError>, what: &str| {
                assert!(
                    matches!(r, Err(WireError::ResponseCode(_))),
                    "{what}: {r:?}"
                );
            };

            // the right key, by hand: the positive control for the refusals below
            let (session, nonce) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            let sig = signed_by(&mut s, AK, &nonce, -ROOT_POLICY_EXPIRATION);
            policy_signed(&mut s, AK, session, &nonce, -ROOT_POLICY_EXPIRATION, &sig).unwrap();
            hmac_in(&mut s, key, session).unwrap();

            // no key: a policy session nothing signed
            let (session, _) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            refused(hmac_in(&mut s, key, session), "no signature");
            let _ = s.cmd(&tpm_wire::flush_context_command(session));

            // a different TPM key, signing the same way
            let other = tpm_wire::parse_create_primary_response(
                &s.cmd(&tpm_wire::create_primary_command(
                    &tpm_wire::ecc_p256_template(
                        tpm_wire::KeyRole::Attestation,
                        "tenzro/test/other-authoriser",
                    ),
                ))
                .unwrap(),
            )
            .unwrap()
            .0;
            s.handles.push(other);
            let (session, nonce) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            let sig = signed_by(&mut s, other, &nonce, -ROOT_POLICY_EXPIRATION);
            policy_signed(
                &mut s,
                other,
                session,
                &nonce,
                -ROOT_POLICY_EXPIRATION,
                &sig,
            )
            .unwrap();
            refused(hmac_in(&mut s, key, session), "another key");
            let _ = s.cmd(&tpm_wire::flush_context_command(session));

            // a replay: a signature made for one session presented to another
            let (first, first_nonce) = s.policy_session().unwrap();
            let old = signed_by(&mut s, AK, &first_nonce, -ROOT_POLICY_EXPIRATION);
            let _ = s.cmd(&tpm_wire::flush_context_command(first));
            let (session, nonce) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            assert!(
                policy_signed(
                    &mut s,
                    AK,
                    session,
                    &first_nonce,
                    -ROOT_POLICY_EXPIRATION,
                    &old
                )
                .is_err(),
                "the old nonce is not this session's"
            );
            assert!(
                policy_signed(&mut s, AK, session, &nonce, -ROOT_POLICY_EXPIRATION, &old).is_err(),
                "the old signature does not cover this nonce"
            );
            refused(hmac_in(&mut s, key, session), "replay");
            let _ = s.cmd(&tpm_wire::flush_context_command(session));

            // an expired authorisation
            let (session, nonce) = s.policy_session().unwrap();
            pcr_term(&mut s, session);
            let sig = signed_by(&mut s, AK, &nonce, -1);
            std::thread::sleep(std::time::Duration::from_millis(2_500));
            assert!(
                policy_signed(&mut s, AK, session, &nonce, -1, &sig).is_err(),
                "expired"
            );
            refused(hmac_in(&mut s, key, session), "expired");
            let _ = s.cmd(&tpm_wire::flush_context_command(session));
        });
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_a_key_that_is_not_a_restricted_endorsement_signer_is_refused() {
        guarded(|t| {
            let mut s = Session {
                t: opener(t)().unwrap(),
                handles: Vec::new(),
            };
            // an unrestricted signing key may sign anything, so it cannot authorise
            let resp = s
                .cmd(&tpm_wire::create_primary_command(
                    &tpm_wire::ecc_p256_template(
                        tpm_wire::KeyRole::Signing,
                        "tenzro/test/unrestricted",
                    ),
                ))
                .unwrap();
            let k = tpm_wire::parse_create_primary_response(&resp).unwrap().0;
            s.handles.push(k);
            let err = certified_authorizer(&mut s, k).expect_err("refused");
            assert!(err.to_string().contains("restricted P-256"), "{err}");
            // the attestation key is certified by this TPM's endorsement key
            certified_authorizer(&mut s, AK).unwrap();
        });
    }

    /// Runs in a second process spawned by
    /// [`tpm_a_second_process_needs_the_signing_key_and_the_blob`].
    #[test]
    #[ignore = "helper: spawned as a second process"]
    fn probe() {
        let (Ok(mode), Some(t)) = (std::env::var("TENZRO_TEST_PROBE"), Target::from_env()) else {
            return;
        };
        let t = &t;
        let path = PathBuf::from(std::env::var("TENZRO_TEST_PROBE_BLOB").unwrap());
        let data = crate::derive::hardware_input("tenzro/test/probe");
        let outcome: std::result::Result<String, String> = match mode.as_str() {
            // Same blob, same chip, the authorising key signs.
            "signed" => TpmRoot::open_or_create(&path, AK, opener(t))
                .and_then(|r| r.hmac(&data))
                .map(|m| hex(&m[..]))
                .map_err(|e| e.to_string()),
            // Same blob, same chip, a plain password session instead of the policy.
            "password-session" => {
                let bytes = std::fs::read(&path).unwrap();
                let (private, public) = decode_blob(&bytes).unwrap();
                let mut s = Session {
                    t: opener(t)().unwrap(),
                    handles: Vec::new(),
                };
                let parent = s.parent().unwrap();
                let key = tpm_wire::parse_load_response(
                    &s.cmd(&tpm_wire::load_command(parent, &private, &public))
                        .unwrap(),
                )
                .unwrap();
                s.handles.push(key);
                let resp = s
                    .cmd(&tpm_wire::hmac_command(
                        key,
                        tpm_wire::TPM2_RS_PW,
                        &[],
                        &data,
                    ))
                    .unwrap();
                tpm_wire::parse_hmac_response(&resp)
                    .map(|m| hex(&m))
                    .map_err(|e| e.to_string())
            }
            // No blob: rebuild a key from public values alone, as a primary
            // with the root's template, and MAC the same input.
            "recreate-primary" => {
                let mut s = Session {
                    t: opener(t)().unwrap(),
                    handles: Vec::new(),
                };
                let mut template = tpm_wire::policy_hmac_key_template(&[0u8; 32]);
                let attrs =
                    tpm_wire::POLICY_HMAC_KEY_ATTRIBUTES | tpm_wire::TPMA_OBJECT_USERWITHAUTH;
                template[4..8].copy_from_slice(&attrs.to_be_bytes());
                let resp = s.cmd(&tpm_wire::create_primary_command(&template)).unwrap();
                let mut r = tpm_wire::response_body(&resp).unwrap();
                let key = r.u32().unwrap();
                s.handles.push(key);
                let resp = s
                    .cmd(&tpm_wire::hmac_command(
                        key,
                        tpm_wire::TPM2_RS_PW,
                        &[],
                        &data,
                    ))
                    .unwrap();
                tpm_wire::parse_hmac_response(&resp)
                    .map(|m| hex(&m))
                    .map_err(|e| e.to_string())
            }
            other => panic!("unknown probe mode {other}"),
        };
        match outcome {
            Ok(h) => println!("PROBE-OK {h}"),
            Err(e) => println!("PROBE-ERR {e}"),
        }
    }

    fn run_probe(mode: &str, blob: &Path, t: &Target) -> String {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args([
            "--ignored",
            "--exact",
            "derive_tpm::tests::probe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("TENZRO_TEST_PROBE", mode)
        .env("TENZRO_TEST_PROBE_BLOB", blob);
        t.export(&mut cmd);
        let out = cmd.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // The harness prints the test name on the same line as the output.
        stdout
            .lines()
            .find_map(|l| l.find("PROBE-").map(|i| l[i..].trim().to_string()))
            .unwrap_or_else(|| panic!("probe {mode} printed no result: {stdout}"))
    }

    /// The root's boundary is the TPM device: a second process on the same
    /// chip with the blob opens it through the authorising key's signature,
    /// and nothing short of that signature does.
    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_a_second_process_needs_the_signing_key_and_the_blob() {
        guarded(|t| {
            let blob = TempBlob::new("probe");
            let path = blob.path();
            let root = TpmRoot::open_or_create(&path, AK, opener(t)).unwrap();
            let ours = derive_hex(&root, "tenzro/test/probe");
            assert_eq!(run_probe("signed", &path, t), format!("PROBE-OK {ours}"));
            let r = run_probe("password-session", &path, t);
            assert!(
                r.starts_with("PROBE-ERR") && r.contains("TPM refused"),
                "{r}"
            );
            // A key rebuilt from public values computes, but not our output.
            let r = run_probe("recreate-primary", &path, t);
            assert!(r.starts_with("PROBE-OK "), "recreate-primary: {r}");
            assert_ne!(r, format!("PROBE-OK {ours}"));
        });
    }

    /// A transport that counts the root loads made through it.
    struct Counting(
        Box<dyn TpmTransport>,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
    );

    impl TpmTransport for Counting {
        fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
            if command.get(6..10) == Some(&tpm_wire::TPM2_CC_LOAD.to_be_bytes()[..]) {
                self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            self.0.submit(command)
        }
    }

    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_the_root_is_loaded_once_and_again_after_it_is_lost() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        guarded(|t| {
            let blob = TempBlob::new("kept");
            let loads = std::sync::Arc::new(AtomicUsize::new(0));
            let (inner, counted) = (opener(t), loads.clone());
            let open: Opener = Box::new(move || {
                inner().map(|x| Box::new(Counting(x, counted.clone())) as Box<dyn TpmTransport>)
            });
            let root = TpmRoot::open_or_create(&blob.path(), AK, open).unwrap();
            let first = derive_hex(&root, "tenzro/test/kept");
            for _ in 0..4 {
                assert_eq!(derive_hex(&root, "tenzro/test/kept"), first);
            }
            assert_eq!(loads.load(SeqCst), 1, "the root is loaded once");

            // The root disappears from the TPM: the next derivation loads it
            // again and gives the same output.
            {
                let mut g = root.loaded.lock().unwrap();
                let l = g.as_mut().unwrap();
                let key = l.key;
                let resp = l.s.t.submit(&tpm_wire::flush_context_command(key)).unwrap();
                tpm_wire::response_body(&resp).unwrap();
                l.s.handles.retain(|h| *h != key);
            }
            assert_eq!(derive_hex(&root, "tenzro/test/kept"), first);
            assert_eq!(loads.load(SeqCst), 2, "loaded again once");
        });
    }

    /// The device path end to end on this machine's own TPM: run with
    /// `TENZRO_TEST_TPM=/dev/tpmrm0` and `TENZRO_DEVICE_KEY_DIR` set to a
    /// throwaway directory.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs TENZRO_TEST_TPM and a throwaway TENZRO_DEVICE_KEY_DIR"]
    fn device_the_root_opens_through_the_configured_key() {
        guarded(|_| {
            assert!(
                std::env::var_os("TENZRO_DEVICE_KEY_DIR").is_some(),
                "no TENZRO_DEVICE_KEY_DIR"
            );
            let l = "tenzro/test/device";
            let derive = || {
                crate::derive::DerivationRoot::open_or_create()
                    .and_then(|r| r.with_ed25519(l, |k| k.public_key()))
            };
            let a = derive().unwrap();
            assert_eq!(derive().unwrap(), a);
            println!("DEVICE ed25519 {}", hex(&a));
        });
    }

    /// Wall-clock time of one derivation plus one use of the derived key, for
    /// each key kind. `TENZRO_TEST_TPM_RUNS` sets the sample count (default
    /// 200); the result is printed as `LATENCY <kind> ...` lines.
    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM or TENZRO_TEST_TPM_SIM)"]
    fn tpm_latency_of_one_derivation_and_use_per_key_kind() {
        guarded(|t| {
            let runs: usize = std::env::var("TENZRO_TEST_TPM_RUNS")
                .map(|v| v.parse().unwrap())
                .unwrap_or(200);
            let blob = TempBlob::new("latency");
            let tpm_root = TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap();
            let root = crate::derive::DerivationRoot::from_tpm_root(
                TpmRoot::open_or_create(&blob.path(), AK, opener(t)).unwrap(),
            );
            let l = "tenzro/test/latency";
            let msg = b"tenzro latency probe";
            let peer = root
                .with_x25519("tenzro/test/peer", |k| k.public_key())
                .unwrap();
            let time = |kind: &str, op: &dyn Fn()| {
                let mut ms: Vec<f64> = (0..runs)
                    .map(|_| {
                        let start = std::time::Instant::now();
                        op();
                        start.elapsed().as_secs_f64() * 1e3
                    })
                    .collect();
                ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
                let rank = |p: f64| ms[((p * runs as f64).ceil() as usize).max(1) - 1];
                println!(
                    "LATENCY {kind} runs={runs} p50={:.2}ms p99={:.2}ms min={:.2}ms max={:.2}ms",
                    rank(0.50),
                    rank(0.99),
                    ms[0],
                    ms[runs - 1]
                );
            };
            time("tpm-hmac-only", &|| {
                derive_hex(&tpm_root, l);
            });
            time("ed25519-derive+sign", &|| {
                root.with_ed25519(l, |k| k.sign(msg)).unwrap();
            });
            time("x25519-derive+dh", &|| {
                root.with_x25519(l, |k| k.diffie_hellman(&peer).unwrap())
                    .unwrap();
            });
            time("ml-dsa-65-derive+sign", &|| {
                root.with_ml_dsa65(l, |k| k.sign(b"tenzro/test", msg))
                    .unwrap();
            });
        });
    }
}
