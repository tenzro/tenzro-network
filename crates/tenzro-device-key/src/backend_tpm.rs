//! TPM 2.0 backend for [`crate::DeviceKey`], on Linux over the kernel
//! resource manager at `/dev/tpmrm0` (never the raw `/dev/tpm0`) and on
//! Windows over TPM Base Services. Both carry the same command bytes and
//! keep the same keys at the same handles; only the channel differs.
//!
//! The command bytes come from [`crate::tpm_wire`]; this module only moves
//! them to and from the TPM, and every command it sends runs on the one
//! TPM thread of [`crate::tpm_exec`]: serialized, bounded by a deadline, and
//! rate-limited for signing.
//!
//! # Keys are provisioned once, then only read and loaded
//!
//! No primary key is created while a node runs. `tenzro-node tpm provision`
//! ([`crate::tpm_provision`]) creates, once per machine, the endorsement
//! hierarchy primaries the node needs and makes them persistent:
//!
//! - the node identity key, at [`tpm_wire::NODE_IDENTITY_HANDLE`] (or the
//!   namespace's own slot), read with `TPM2_ReadPublic` and used in place;
//! - the storage root, at [`tpm_wire::NODE_STORAGE_ROOT_HANDLE`], the parent
//!   of every other labelled key.
//!
//! The endorsement key itself is read from its TCG persistent handle
//! ([`tpm_wire::EK_ECC_PERSISTENT_HANDLE`]), never recreated.
//!
//! Primaries are a deterministic function of the endorsement seed (which
//! never leaves the chip) and the template, so provisioning again after a
//! reinstall or a `TPM2_Clear` gives back the same identity and the same
//! storage root. Every other labelled key is a child of the storage root,
//! generated inside the TPM by `TPM2_Create`; its TPM-wrapped blob is kept in
//! the device-key directory and is useless on any other chip. A key is
//! loaded once per process and kept: an operation then costs one command.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use zeroize::Zeroizing;

use crate::hpke::{KemId, extract_and_expand, key_schedule_base};
use crate::tpm_exec::{self, Class};
use crate::tpm_provision::{
    IDENTITY_KEY_LABEL, IdentitySlot, NOT_PROVISIONED, default_dir, find_identity_slot,
    read_public, write_new,
};
use crate::tpm_wire::{self, KeyRole, PublicArea, WireError};
use crate::{DeviceKey, DeviceKeyError, DevicePublicKey, DeviceSignature, Result};

/// The Linux resource manager this backend talks to.
#[cfg(target_os = "linux")]
pub(crate) const DEVICE: &str = "/dev/tpmrm0";

/// HPKE `info` for [`DeviceKey::wrap_secret`] on this backend.
const WRAP_INFO: &[u8] = b"tenzro-device-key/backend_tpm/wrap_secret/v1";

/// Largest response any command here can produce. TPM responses are bounded
/// by `TPM_PT_MAX_RESPONSE_SIZE`: 4096 on chips without ML-DSA, more on a
/// chip that signs ML-DSA-87, whose signature alone is 4627 bytes.
const MAX_RESPONSE: usize = 8192;

/// Header of a child key blob file.
const CHILD_MAGIC: &[u8] = b"tenzro/device-key/tpm-child\n";

fn tpm_err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Enclave(msg.into())
}

fn wire(e: WireError) -> DeviceKeyError {
    tpm_err(e.to_string())
}

fn command_name(command: &[u8]) -> String {
    match tpm_wire::command_code(command) {
        Some(cc) => format!("TPM command 0x{cc:03x}"),
        None => "TPM command".into(),
    }
}

/// One open channel to the TPM: a descriptor on the Linux resource manager.
#[cfg(target_os = "linux")]
mod channel {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};

    use super::{DEVICE, MAX_RESPONSE, tpm_err};
    use crate::Result;

    pub(crate) struct Channel(File);

    impl Channel {
        pub(crate) fn open() -> Result<Self> {
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(DEVICE)
                .map(Self)
                .map_err(|e| tpm_err(format!("open {DEVICE}: {e}")))
        }

        /// Send one command and read its whole response.
        pub(crate) fn exchange(&self, command: &[u8]) -> Result<Vec<u8>> {
            let mut f = &self.0;
            f.write_all(command)
                .map_err(|e| tpm_err(format!("write {DEVICE}: {e}")))?;
            let mut buf = vec![0u8; MAX_RESPONSE];
            let n = f
                .read(&mut buf)
                .map_err(|e| tpm_err(format!("read {DEVICE}: {e}")))?;
            buf.truncate(n);
            Ok(buf)
        }

        /// A channel to nowhere, for tests that never send.
        #[cfg(test)]
        pub(crate) fn detached() -> Self {
            Self(File::open("/dev/null").unwrap())
        }
    }
}

/// One open channel to the TPM: a TPM Base Services context.
#[cfg(windows)]
mod channel {
    use std::ffi::c_void;
    use std::ptr;

    use windows_sys::Win32::System::TpmBaseServices::{
        TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
        TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_SUCCESS, Tbsi_Context_Create,
        Tbsip_Context_Close, Tbsip_Submit_Command,
    };

    use super::{MAX_RESPONSE, tpm_err};
    use crate::Result;

    pub(crate) struct Channel(*mut c_void);

    // SAFETY: a TBS context is a process-wide handle, not bound to the thread
    // that opened it, and every command on it runs on the one TPM thread of
    // `tpm_exec`, so it is never used from two threads at once.
    unsafe impl Send for Channel {}
    unsafe impl Sync for Channel {}

    impl Channel {
        pub(crate) fn open() -> Result<Self> {
            let params = TBS_CONTEXT_PARAMS2 {
                version: 2, // TPM_VERSION_20
                Anonymous: TBS_CONTEXT_PARAMS2_0 {
                    asUINT32: 0b100, // includeTpm20 = 1
                },
            };
            let mut handle: *mut c_void = ptr::null_mut();
            // SAFETY: `params` lives on the stack for the call's duration and
            // is passed as the narrower `TBS_CONTEXT_PARAMS` the FFI signature
            // declares; both start with the same `version: u32` field, which
            // TBS reads before anything past it. `handle` is a valid
            // out-pointer.
            let rc = unsafe {
                Tbsi_Context_Create(
                    &params as *const TBS_CONTEXT_PARAMS2 as *const TBS_CONTEXT_PARAMS,
                    &mut handle,
                )
            };
            if rc != TBS_SUCCESS || handle.is_null() {
                return Err(tpm_err(format!("Tbsi_Context_Create failed: 0x{rc:08X}")));
            }
            Ok(Self(handle))
        }

        /// Send one command and read its whole response.
        pub(crate) fn exchange(&self, command: &[u8]) -> Result<Vec<u8>> {
            let mut result = vec![0u8; MAX_RESPONSE];
            let mut result_len = result.len() as u32;
            // SAFETY: `self.0` is a live context from a successful `open()`;
            // `command` and `result` are valid for their stated lengths for
            // the call's duration; `result_len` is a valid in/out length.
            let rc = unsafe {
                Tbsip_Submit_Command(
                    self.0,
                    TBS_COMMAND_LOCALITY_ZERO,
                    TBS_COMMAND_PRIORITY_NORMAL,
                    command.as_ptr(),
                    command.len() as u32,
                    result.as_mut_ptr(),
                    &mut result_len,
                )
            };
            if rc != TBS_SUCCESS {
                return Err(tpm_err(format!("Tbsip_Submit_Command failed: 0x{rc:08X}")));
            }
            result.truncate(result_len as usize);
            Ok(result)
        }
    }

    impl Drop for Channel {
        /// Closing the context makes TBS flush the transient objects it holds.
        fn drop(&mut self) {
            // SAFETY: `self.0` is a context this value solely owns, from a
            // successful `open()`.
            unsafe {
                Tbsip_Context_Close(self.0);
            }
        }
    }
}

use channel::Channel;

/// One open channel to the TPM. Opening, every command and closing run on
/// the TPM thread.
pub struct TpmDevice(Arc<Channel>);

impl TpmDevice {
    pub fn open() -> Result<Self> {
        tpm_exec::global()
            .run("open the TPM", Class::Other, Channel::open)
            .map(|c| Self(Arc::new(c)))
    }

    /// Send one command and read its whole response.
    pub fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        let c = self.0.clone();
        let cmd = command.to_vec();
        tpm_exec::global().run(&command_name(command), Class::of(command), move || {
            c.exchange(&cmd)
        })
    }

    /// Free a transient object without waiting for the TPM to answer.
    fn flush_detached(&self, handle: u32) {
        let c = self.0.clone();
        tpm_exec::global().detach(move || {
            let _ = c.exchange(&tpm_wire::flush_context_command(handle));
        });
    }

    pub fn sign(&mut self, handle: u32, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let resp = self.submit(&tpm_wire::sign_command(handle, digest))?;
        tpm_wire::parse_sign_response(&resp).map_err(wire)
    }

    /// Whether the TPM implements ECC curve `curve` (`TPM_CAP_ECC_CURVES`).
    pub fn supports_ecc_curve(&mut self, curve: u16) -> Result<bool> {
        let resp = self.submit(&tpm_wire::get_ecc_curve_command(curve))?;
        tpm_wire::parse_ecc_curve_supported(&resp, curve).map_err(wire)
    }

    /// ECDSA-P384 with the key at `handle` over a SHA-384 digest.
    pub fn sign_p384(&mut self, handle: u32, digest: &[u8; 48]) -> Result<[u8; 96]> {
        let resp = self.submit(&tpm_wire::sign_p384_command(handle, digest))?;
        tpm_wire::parse_sign_p384_response(&resp).map_err(wire)
    }

    /// Pure ML-DSA with the key at `handle` over `message` with the FIPS 204
    /// context `ctx`, by `TPM2_SignSequenceStart` and
    /// `TPM2_SignSequenceComplete`. A sequence the TPM did not complete is
    /// flushed.
    pub fn ml_dsa_sign(&mut self, handle: u32, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let resp = self.submit(&tpm_wire::sign_sequence_start_command(handle, ctx))?;
        let sequence = tpm_wire::parse_sign_sequence_start_response(&resp).map_err(wire)?;
        let done = self
            .submit(&tpm_wire::sign_sequence_complete_command(
                sequence, handle, message,
            ))
            .and_then(|resp| tpm_wire::parse_ml_dsa_signature_response(&resp).map_err(wire));
        if done.is_err() {
            self.flush_detached(sequence);
        }
        done
    }

    /// Whether the TPM implements algorithm `alg` (`TPM_CAP_ALGS`).
    pub fn supports_algorithm(&mut self, alg: u16) -> Result<bool> {
        let resp = self.submit(&tpm_wire::get_algorithm_command(alg))?;
        tpm_wire::parse_algorithm_supported(&resp, alg).map_err(wire)
    }

    pub fn read_public(&mut self, handle: u32) -> Result<PublicArea> {
        let resp = self.submit(&tpm_wire::read_public_command(handle))?;
        tpm_wire::parse_read_public_response(&resp).map_err(wire)
    }

    /// Read a whole NV index in chunks the chip will accept.
    pub fn nv_read_all(&mut self, index: u32) -> Result<Vec<u8>> {
        let size = tpm_wire::parse_nv_read_public_response(
            &self.submit(&tpm_wire::nv_read_public_command(index))?,
        )
        .map_err(wire)?;
        const CHUNK: u16 = 512;
        let mut out = Vec::with_capacity(size as usize);
        let mut offset = 0u16;
        while offset < size {
            let n = CHUNK.min(size - offset);
            let resp = self.submit(&tpm_wire::nv_read_command(index, n, offset))?;
            let chunk = tpm_wire::parse_nv_read_response(&resp).map_err(wire)?;
            if chunk.is_empty() {
                return Err(tpm_err("NV read returned no data"));
            }
            offset += chunk.len() as u16;
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// Certify with the attestation key `ak` that `object` is loaded in
    /// this TPM, over `qualifying_data`.
    pub fn certify(
        &mut self,
        object: u32,
        ak: u32,
        qualifying_data: &[u8],
    ) -> Result<(Vec<u8>, [u8; 64])> {
        let resp = self.submit(&tpm_wire::certify_command(object, ak, qualifying_data))?;
        tpm_wire::parse_certify_response(&resp).map_err(wire)
    }

    pub fn quote(&mut self, ak: u32, nonce: &[u8], pcrs: &[u8; 3]) -> Result<(Vec<u8>, [u8; 64])> {
        let resp = self.submit(&tpm_wire::quote_command(ak, nonce, pcrs))?;
        tpm_wire::parse_quote_response(&resp).map_err(wire)
    }

    /// Recover a credential a verifier encrypted to this TPM's endorsement
    /// key `ek` (loaded at `ek_handle`) for the attestation key `ak`.
    ///
    /// The endorsement key is authorised the way its template says: a
    /// high-range EK (`userWithAuth`) takes the empty password, a low-range
    /// one the PolicySecret(TPM_RH_ENDORSEMENT) policy it carries.
    pub fn activate_credential(
        &mut self,
        ak: u32,
        ek_handle: u32,
        ek: &PublicArea,
        credential_blob: &[u8],
        encrypted_secret: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let command = if ek.attributes & tpm_wire::TPMA_OBJECT_USERWITHAUTH != 0 {
            tpm_wire::activate_credential_password_command(
                ak,
                ek_handle,
                credential_blob,
                encrypted_secret,
            )
        } else if ek.auth_policy == tpm_wire::EK_POLICY {
            let mut nonce = [0u8; 16];
            getrandom_fill(&mut nonce)?;
            let session = tpm_wire::parse_start_auth_session_response(
                &self.submit(&tpm_wire::start_policy_session_command(&nonce))?,
            )
            .map_err(wire)?;
            let resp = self.submit(&tpm_wire::policy_secret_endorsement_command(session))?;
            tpm_wire::response_body(&resp).map_err(wire)?;
            tpm_wire::activate_credential_command(
                ak,
                ek_handle,
                session,
                credential_blob,
                encrypted_secret,
            )
        } else {
            return Err(tpm_err(
                "the endorsement key takes neither the empty password nor the TCG EK policy",
            ));
        };
        let resp = self.submit(&command)?;
        tpm_wire::parse_activate_credential_response(&resp)
            .map(Zeroizing::new)
            .map_err(wire)
    }

    fn ecdh(&mut self, handle: u32, peer_x: &[u8; 32], peer_y: &[u8; 32]) -> Result<[u8; 32]> {
        let resp = self.submit(&tpm_wire::ecdh_zgen_command(handle, peer_x, peer_y))?;
        tpm_wire::parse_ecdh_zgen_response(&resp).map_err(wire)
    }

    /// Generate a child of the storage root inside the TPM; returns its
    /// wrapped private part and its public area.
    fn create_child(&mut self, template: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let resp = self.submit(&tpm_wire::create_command(
            tpm_wire::NODE_STORAGE_ROOT_HANDLE,
            &[],
            template,
        ))?;
        tpm_wire::parse_create_response(&resp).map_err(storage_root_missing)
    }

    /// Load a child of the storage root; returns its transient handle.
    fn load_child(&mut self, private: &[u8], public: &[u8]) -> Result<u32> {
        let resp = self.submit(&tpm_wire::load_command(
            tpm_wire::NODE_STORAGE_ROOT_HANDLE,
            private,
            public,
        ))?;
        tpm_wire::parse_load_response(&resp).map_err(storage_root_missing)
    }
}

impl Drop for TpmDevice {
    /// Closing the channel makes the resource manager flush what it holds,
    /// which needs the chip: done on the TPM thread, never waited for.
    fn drop(&mut self) {
        let c = self.0.clone();
        tpm_exec::global().detach(move || drop(c));
    }
}

/// A failure naming the storage root, which is missing until provisioned.
fn storage_root_missing(e: WireError) -> DeviceKeyError {
    match e {
        WireError::ResponseCode(code) if tpm_wire::handle_lost(code) => tpm_err(format!(
            "the TPM storage root 0x{:08x} is missing ({e}); {NOT_PROVISIONED}",
            tpm_wire::NODE_STORAGE_ROOT_HANDLE
        )),
        e => wire(e),
    }
}

fn getrandom_fill(buf: &mut [u8]) -> Result<()> {
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(|e| tpm_err(format!("OS RNG: {e}")))
}

/// Whether the resource manager is present and answers. Probed once per
/// process, outside the TPM thread: the probe sends no command, so it runs
/// before the process sets its TPM limits and leaves them unset.
pub fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| Channel::open().is_ok())
}

fn raw_point(p: &PublicArea) -> Result<DevicePublicKey> {
    let sec1 = p
        .p256_sec1()
        .ok_or_else(|| tpm_err("TPM returned a non-P-256 key"))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&sec1[1..]);
    Ok(out)
}

/// Whether `label` (already namespaced) is this process's identity key.
fn is_identity(label: &str) -> bool {
    label == crate::namespaced(IDENTITY_KEY_LABEL)
}

fn role_tag(role: KeyRole) -> &'static str {
    match role {
        KeyRole::Signing => "sign",
        KeyRole::Attestation => "attest",
        KeyRole::Agreement => "agree",
    }
}

fn child_path(label: &str, role: KeyRole) -> Result<PathBuf> {
    let id = hex::encode(&tpm_wire::label_unique(label)[..16]);
    Ok(default_dir()?.join(format!("{id}.{}.tpmkey", role_tag(role))))
}

fn encode_child(private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut out = CHILD_MAGIC.to_vec();
    for part in [private, public] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

fn decode_child(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let bad = || tpm_err("TPM key blob is malformed");
    let mut rest = bytes.strip_prefix(CHILD_MAGIC).ok_or_else(bad)?;
    let mut part = || -> Result<Vec<u8>> {
        let len = rest.get(..4).ok_or_else(bad)?;
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let body = rest.get(4..4 + len).ok_or_else(bad)?.to_vec();
        rest = &rest[4 + len..];
        Ok(body)
    };
    let private = part()?;
    let public = part()?;
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok((private, public))
}

/// A key in use: a descriptor and the key's handle in it. A loaded child is
/// transient and flushed on drop; the persistent identity is never flushed.
struct Kept {
    dev: TpmDevice,
    handle: u32,
    public: PublicArea,
    transient: bool,
}

impl Drop for Kept {
    fn drop(&mut self) {
        if self.transient {
            self.dev.flush_detached(self.handle);
        }
    }
}

type Loader = fn(&str, KeyRole) -> Result<Kept>;

/// Bring the key for `label` and `role` into use: read the persistent
/// identity, or load the child blob under the storage root.
fn load(label: &str, role: KeyRole) -> Result<Kept> {
    let mut dev = TpmDevice::open()?;
    if is_identity(label) && role == KeyRole::Signing {
        let found = find_identity_slot(label, |h| read_public(&mut dev, h)).map_err(|e| {
            tpm_err(format!(
                "the node identity key cannot be read ({e}); {NOT_PROVISIONED}"
            ))
        })?;
        let IdentitySlot::Held(handle, public) = found else {
            return Err(tpm_err(format!(
                "this machine's TPM holds no identity key for this namespace; {NOT_PROVISIONED}"
            )));
        };
        tracing::info!(
            handle = format_args!("0x{handle:08x}"),
            "read the node identity from its persistent TPM handle"
        );
        return Ok(Kept {
            dev,
            handle,
            public,
            transient: false,
        });
    }
    let path = child_path(label, role)?;
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(DeviceKeyError::NotFound(label.to_string()));
        }
        Err(e) => return Err(tpm_err(format!("TPM key {}: {e}", path.display()))),
    };
    let (private, public_raw) = decode_child(&bytes)?;
    let public = tpm_wire::parse_public(&public_raw).map_err(wire)?;
    if public.attributes != role.attributes() || public.p256_sec1().is_none() {
        return Err(tpm_err(format!(
            "TPM key {} is not a P-256 key of its role",
            path.display()
        )));
    }
    let handle = dev.load_child(&private, &public_raw)?;
    Ok(Kept {
        dev,
        handle,
        public,
        transient: true,
    })
}

/// Generate the child keys for `label` and keep their blobs. Racing
/// creators agree on whichever blob reached the disk first.
fn create_children(label: &str) -> Result<()> {
    let dir = default_dir()?;
    let io = |e: std::io::Error| tpm_err(format!("TPM key directory {}: {e}", dir.display()));
    crate::tpm_provision::create_private_dir(&dir).map_err(io)?;
    let mut dev = TpmDevice::open()?;
    for role in [KeyRole::Signing, KeyRole::Agreement] {
        let path = child_path(label, role)?;
        if path.exists() {
            continue;
        }
        let (private, public) = dev.create_child(&tpm_wire::ecc_p256_template(role, label))?;
        write_new(&path, &encode_child(&private, &public)).map_err(io)?;
    }
    Ok(())
}

/// One labelled key, shared by every opener in the process.
struct Shared {
    label: String,
    load: Loader,
    signing: Mutex<Option<Kept>>,
    agreement: Mutex<Option<Kept>>,
}

impl Shared {
    fn new(label: &str, load: Loader) -> Self {
        Self {
            label: label.to_string(),
            load,
            signing: Mutex::new(None),
            agreement: Mutex::new(None),
        }
    }

    /// Run `op` on the key for `role`, bringing it into use first when it is
    /// not yet. When `op` fails on a kept key with a TPM-side error, the key
    /// is brought into use again once and `op` retried: the TPM may have lost
    /// a loaded child (a reset, a broken connection). A timeout, a stalled
    /// TPM or a rate limit is returned as is.
    fn with_key<R>(
        &self,
        role: KeyRole,
        op: impl Fn(&mut TpmDevice, u32, &PublicArea) -> Result<R>,
    ) -> Result<R> {
        let slot = if role == KeyRole::Signing {
            &self.signing
        } else {
            &self.agreement
        };
        let mut kept = slot.lock().unwrap_or_else(|e| e.into_inner());
        let mut fresh = false;
        loop {
            if kept.is_none() {
                *kept = Some((self.load)(&self.label, role)?);
                fresh = true;
            }
            let k = kept.as_mut().expect("kept above");
            match op(&mut k.dev, k.handle, &k.public) {
                Ok(r) => return Ok(r),
                Err(e @ DeviceKeyError::Tpm(_)) => return Err(e),
                Err(e) if fresh => {
                    *kept = None;
                    return Err(e);
                }
                Err(_) => *kept = None,
            }
        }
    }
}

/// Every key this process has opened, by namespaced label.
fn registry() -> &'static Mutex<HashMap<String, Arc<Shared>>> {
    static KEYS: OnceLock<Mutex<HashMap<String, Arc<Shared>>>> = OnceLock::new();
    KEYS.get_or_init(Default::default)
}

fn shared(label: &str, load: Loader) -> Arc<Shared> {
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(label.to_string())
        .or_insert_with(|| Arc::new(Shared::new(label, load)))
        .clone()
}

/// One labelled TPM-resident P-256 key.
pub struct TpmKey(Arc<Shared>);

impl DeviceKey for TpmKey {
    fn label(&self) -> &str {
        &self.0.label
    }

    fn public_key(&self) -> Result<DevicePublicKey> {
        self.0
            .with_key(KeyRole::Signing, |_, _, public| raw_point(public))
    }

    fn sign_prehash(&self, hash: &[u8; 32]) -> Result<DeviceSignature> {
        self.0
            .with_key(KeyRole::Signing, |dev, handle, _| dev.sign(handle, hash))
    }

    fn wrap_secret(&self, secret: &[u8]) -> Result<Vec<u8>> {
        if secret.is_empty() {
            return Err(tpm_err("wrap_secret: empty secret"));
        }
        let pk_r = self.0.with_key(KeyRole::Agreement, |_, _, public| {
            public
                .p256_sec1()
                .ok_or_else(|| tpm_err("agreement key is not P-256"))
        })?;

        let eph = <p256::ecdh::EphemeralSecret as p256::elliptic_curve::Generate>::generate();
        let enc = eph.public_key().to_sec1_bytes().to_vec();
        let pk_point = p256::PublicKey::from_sec1_bytes(&pk_r)
            .map_err(|_| tpm_err("wrap_secret: malformed recipient key"))?;
        let dh = eph.diffie_hellman(&pk_point);

        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(&enc);
        kem_context.extend_from_slice(&pk_r);
        let shared = extract_and_expand(
            KemId::DhkemP256,
            dh.raw_secret_bytes().as_slice(),
            &kem_context,
        )
        .map_err(|e| tpm_err(format!("wrap_secret: {e}")))?;
        let (key, nonce) = key_schedule_base(KemId::DhkemP256, &shared, WRAP_INFO)
            .map_err(|e| tpm_err(format!("wrap_secret: {e}")))?;
        let ct = ChaCha20Poly1305::new((&*key).into())
            .encrypt(
                (&*nonce).into(),
                Payload {
                    msg: secret,
                    aad: &enc,
                },
            )
            .map_err(|_| tpm_err("wrap_secret: AEAD seal failed"))?;

        let mut out = enc;
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn unwrap_secret(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if ciphertext.len() <= 65 || ciphertext[0] != 0x04 {
            return Err(tpm_err("unwrap_secret: malformed ciphertext"));
        }
        let (enc, ct) = ciphertext.split_at(65);
        let mut peer_x = [0u8; 32];
        let mut peer_y = [0u8; 32];
        peer_x.copy_from_slice(&enc[1..33]);
        peer_y.copy_from_slice(&enc[33..65]);

        let (pk_r, z) = self.0.with_key(KeyRole::Agreement, |dev, handle, public| {
            let pk_r = public
                .p256_sec1()
                .ok_or_else(|| tpm_err("agreement key is not P-256"))?;
            Ok((pk_r, Zeroizing::new(dev.ecdh(handle, &peer_x, &peer_y)?)))
        })?;

        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        let shared = extract_and_expand(KemId::DhkemP256, z.as_slice(), &kem_context)
            .map_err(|e| tpm_err(format!("unwrap_secret: {e}")))?;
        let (key, nonce) = key_schedule_base(KemId::DhkemP256, &shared, WRAP_INFO)
            .map_err(|e| tpm_err(format!("unwrap_secret: {e}")))?;
        ChaCha20Poly1305::new((&*key).into())
            .decrypt((&*nonce).into(), Payload { msg: ct, aad: enc })
            .map(Zeroizing::new)
            .map_err(|_| tpm_err("unwrap_secret: AEAD open failed (tampered or wrong key)"))
    }
}

fn check_label(label: &str) -> Result<()> {
    if label.is_empty() {
        return Err(tpm_err("device key label must not be empty"));
    }
    Ok(())
}

/// Open the labelled key. A key this process already opened is returned
/// without touching the TPM; otherwise the identity must be provisioned, and
/// any other key must have its blob.
pub fn open(label: &str) -> Result<Box<dyn DeviceKey>> {
    opened(label).map(|k| Box::new(TpmKey(k)) as Box<dyn DeviceKey>)
}

fn opened(label: &str) -> Result<Arc<Shared>> {
    check_label(label)?;
    if !available() {
        return Err(DeviceKeyError::NotFound(label.to_string()));
    }
    if let Some(k) = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(label)
    {
        return Ok(k.clone());
    }
    if !is_identity(label) && !child_path(label, KeyRole::Signing)?.exists() {
        return Err(DeviceKeyError::NotFound(label.to_string()));
    }
    let key = shared(label, load);
    // Brings the key into use now, so a missing identity or an unloadable
    // blob is reported here rather than at the first signature.
    key.with_key(KeyRole::Signing, |_, _, _| Ok(()))?;
    Ok(key)
}

/// Run `op` on the signing key labelled `label` (under this process's key
/// namespace), in the descriptor that holds it.
pub(crate) fn with_signing_key<R>(
    label: &str,
    op: impl Fn(&mut TpmDevice, u32, &PublicArea) -> Result<R>,
) -> Result<R> {
    opened(&crate::namespaced(label))?.with_key(KeyRole::Signing, op)
}

/// Create the labelled key: generate its children under the storage root.
/// The identity key is never created here; it is provisioned.
pub fn create(label: &str) -> Result<Box<dyn DeviceKey>> {
    check_label(label)?;
    if is_identity(label) {
        return open(label).map_err(|e| {
            tpm_err(format!(
                "the node identity key is not available ({e}); {NOT_PROVISIONED}"
            ))
        });
    }
    create_children(label)?;
    open(label)
}

/// Delete the labelled key's blobs. The identity is retired by no longer
/// provisioning it, never deleted here.
pub fn delete(label: &str) -> Result<()> {
    check_label(label)?;
    if is_identity(label) {
        return Ok(());
    }
    registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(label);
    for role in [KeyRole::Signing, KeyRole::Agreement] {
        match std::fs::remove_file(child_path(label, role)?) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(tpm_err(format!("delete TPM key {label}: {e}"))),
        }
    }
    Ok(())
}

// --- Keys of one kind each: P-384 signing and ML-DSA. ------------------------

/// The kind of a single-key child of the storage root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildKind {
    /// ECDSA over NIST P-384 with SHA-384.
    P384Signing,
    /// Pure ML-DSA of a `TPMI_MLDSA_PARAMETER_SET`.
    MlDsa(u16),
}

impl ChildKind {
    fn tag(self) -> String {
        match self {
            Self::P384Signing => "p384".into(),
            Self::MlDsa(set) => format!("mldsa{set}"),
        }
    }

    fn template(self, label: &str) -> Vec<u8> {
        match self {
            Self::P384Signing => tpm_wire::ecc_p384_signing_template(label),
            Self::MlDsa(set) => tpm_wire::ml_dsa_template(set),
        }
    }

    fn holds(self, p: &PublicArea) -> bool {
        p.attributes == tpm_wire::SIGNING_KEY_ATTRIBUTES
            && match self {
                Self::P384Signing => p.p384_sec1().is_some(),
                Self::MlDsa(set) => matches!(
                    &p.key,
                    tpm_wire::PublicKey::MlDsa {
                        parameter_set,
                        allow_external_mu: false,
                        ..
                    } if *parameter_set == set
                ),
            }
    }

    /// Refuses, naming what is missing, on a TPM that does not implement
    /// this kind of key.
    fn require(self, dev: &mut TpmDevice) -> Result<()> {
        match self {
            Self::P384Signing => {
                if !dev.supports_ecc_curve(tpm_wire::TPM2_ECC_NIST_P384)? {
                    return Err(tpm_err("this TPM does not implement the NIST P-384 curve"));
                }
                if !dev.supports_algorithm(tpm_wire::TPM2_ALG_SHA384)? {
                    return Err(tpm_err("this TPM does not implement SHA-384"));
                }
            }
            Self::MlDsa(_) => {
                if !dev.supports_algorithm(tpm_wire::TPM2_ALG_MLDSA)? {
                    return Err(tpm_err(
                        "this TPM does not implement ML-DSA (TPM 2.0 library v1.85 or later is required)",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn kind_path(label: &str, kind: ChildKind) -> Result<PathBuf> {
    let id = hex::encode(&tpm_wire::label_unique(label)[..16]);
    Ok(default_dir()?.join(format!("{id}.{}.tpmkey", kind.tag())))
}

/// One labelled key of one [`ChildKind`], generated inside the TPM as a
/// child of the storage root. Its TPM-wrapped blob is kept in the device-key
/// directory and is useless on any other chip; the private key never leaves
/// the TPM.
pub struct TpmChildKey {
    label: String,
    kind: ChildKind,
    kept: Mutex<Option<Kept>>,
}

impl TpmChildKey {
    /// Opens the key `label` (under this process's key namespace) of `kind`,
    /// generating it inside the TPM on first use. A TPM that does not
    /// implement `kind` is refused before anything is created.
    pub fn open_or_create(label: &str, kind: ChildKind) -> Result<Self> {
        check_label(label)?;
        if !available() {
            return Err(tpm_err("this machine has no usable TPM"));
        }
        let label = crate::namespaced(label).into_owned();
        let path = kind_path(&label, kind)?;
        let mut dev = TpmDevice::open()?;
        kind.require(&mut dev)?;
        if !path.exists() {
            let dir = default_dir()?;
            let io =
                |e: std::io::Error| tpm_err(format!("TPM key directory {}: {e}", dir.display()));
            crate::tpm_provision::create_private_dir(&dir).map_err(io)?;
            let (private, public) = dev.create_child(&kind.template(&label))?;
            write_new(&path, &encode_child(&private, &public)).map_err(io)?;
        }
        drop(dev);
        let key = Self {
            label,
            kind,
            kept: Mutex::new(None),
        };
        key.with(|_, _, _| Ok(()))?;
        Ok(key)
    }

    /// The namespaced label.
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn kind(&self) -> ChildKind {
        self.kind
    }

    fn load(&self) -> Result<Kept> {
        let path = kind_path(&self.label, self.kind)?;
        let bytes = std::fs::read(&path)
            .map_err(|e| tpm_err(format!("TPM key {}: {e}", path.display())))?;
        let (private, public_raw) = decode_child(&bytes)?;
        let public = tpm_wire::parse_public(&public_raw).map_err(wire)?;
        if !self.kind.holds(&public) {
            return Err(tpm_err(format!(
                "TPM key {} is not a {:?} key",
                path.display(),
                self.kind
            )));
        }
        let mut dev = TpmDevice::open()?;
        let handle = dev.load_child(&private, &public_raw)?;
        Ok(Kept {
            dev,
            handle,
            public,
            transient: true,
        })
    }

    /// Run `op` on the loaded key, loading it first when it is not, and once
    /// more when the TPM lost it, as `Shared::with_key` does.
    fn with<R>(&self, op: impl Fn(&mut TpmDevice, u32, &PublicArea) -> Result<R>) -> Result<R> {
        let mut kept = self.kept.lock().unwrap_or_else(|e| e.into_inner());
        let mut fresh = false;
        loop {
            if kept.is_none() {
                *kept = Some(self.load()?);
                fresh = true;
            }
            let k = kept.as_mut().expect("kept above");
            match op(&mut k.dev, k.handle, &k.public) {
                Ok(r) => return Ok(r),
                Err(e @ DeviceKeyError::Tpm(_)) => return Err(e),
                Err(e) if fresh => {
                    *kept = None;
                    return Err(e);
                }
                Err(_) => *kept = None,
            }
        }
    }

    /// Uncompressed SEC1 point of a P-384 key (97 bytes).
    pub fn p384_sec1(&self) -> Result<[u8; 97]> {
        self.with(|_, _, p| {
            p.p384_sec1()
                .ok_or_else(|| tpm_err("the key is not a P-384 key"))
        })
    }

    /// ECDSA-P384 over a caller-computed SHA-384 digest, raw `r || s`.
    pub fn sign_p384_prehash(&self, digest: &[u8; 48]) -> Result<[u8; 96]> {
        if self.kind != ChildKind::P384Signing {
            return Err(tpm_err("the key is not a P-384 key"));
        }
        self.with(|dev, handle, _| dev.sign_p384(handle, digest))
    }

    /// The ML-DSA verifying key the TPM generated.
    pub fn ml_dsa_public(&self) -> Result<Vec<u8>> {
        self.with(|_, _, p| match &p.key {
            tpm_wire::PublicKey::MlDsa { key, .. } => Ok(key.clone()),
            _ => Err(tpm_err("the key is not an ML-DSA key")),
        })
    }

    /// An ML-DSA signature over `message` with the FIPS 204 context `ctx`,
    /// made inside the TPM.
    pub fn ml_dsa_sign(&self, ctx: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        if !matches!(self.kind, ChildKind::MlDsa(_)) {
            return Err(tpm_err("the key is not an ML-DSA key"));
        }
        if ctx.len() > 255 {
            return Err(tpm_err("an ML-DSA context is at most 255 bytes"));
        }
        if message.len() > tpm_wire::TPM2_MAX_BUFFER {
            return Err(tpm_err(format!(
                "the TPM signs an ML-DSA message of at most {} bytes",
                tpm_wire::TPM2_MAX_BUFFER
            )));
        }
        self.with(|dev, handle, _| dev.ml_dsa_sign(handle, ctx, message))
    }

    /// Delete the key's blob; the TPM holds nothing else of it.
    pub fn delete(label: &str, kind: ChildKind) -> Result<()> {
        check_label(label)?;
        match std::fs::remove_file(kind_path(&crate::namespaced(label), kind)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(tpm_err(format!("delete TPM key {label}: {e}"))),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn empty_label_is_refused() {
        assert!(open("").is_err());
        assert!(create("").is_err());
    }

    #[test]
    fn a_child_blob_round_trips_and_garbage_is_refused() {
        let blob = encode_child(b"private", b"public");
        assert_eq!(
            decode_child(&blob).unwrap(),
            (b"private".to_vec(), b"public".to_vec())
        );
        assert!(decode_child(&blob[..blob.len() - 1]).is_err());
        assert!(decode_child(b"not a blob").is_err());
    }

    static LOADS: AtomicUsize = AtomicUsize::new(0);
    static OTHER_LOADS: AtomicUsize = AtomicUsize::new(0);

    fn counting_load(label: &str, role: KeyRole) -> Result<Kept> {
        LOADS.fetch_add(1, Ordering::SeqCst);
        fake_kept(label, role)
    }

    fn other_load(label: &str, role: KeyRole) -> Result<Kept> {
        OTHER_LOADS.fetch_add(1, Ordering::SeqCst);
        fake_kept(label, role)
    }

    fn fake_kept(label: &str, role: KeyRole) -> Result<Kept> {
        let template = tpm_wire::ecc_p256_template(role, label);
        Ok(Kept {
            dev: TpmDevice(Arc::new(Channel::detached())),
            handle: tpm_wire::NODE_IDENTITY_HANDLE,
            public: tpm_wire::parse_public(&template).unwrap(),
            transient: false,
        })
    }

    /// The identity is brought into use once per process: every opener and
    /// every later use reads the kept key, never the TPM again.
    #[test]
    fn the_identity_is_loaded_exactly_once_per_process() {
        let label = "tenzro-test-identity-once";
        let a = TpmKey(shared(label, counting_load));
        let b = TpmKey(shared(label, counting_load));
        assert!(Arc::ptr_eq(&a.0, &b.0), "openers share one key");
        for key in [&a, &b, &a] {
            for _ in 0..5 {
                key.0
                    .with_key(KeyRole::Signing, |_, handle, _| Ok(handle))
                    .unwrap();
            }
        }
        assert_eq!(LOADS.load(Ordering::SeqCst), 1);
    }

    /// A timeout or rate limit is returned, not retried by reloading the key.
    #[test]
    fn an_executor_error_is_not_retried() {
        let key = TpmKey(shared("tenzro-test-no-retry", other_load));
        let calls = AtomicUsize::new(0);
        key.0.with_key(KeyRole::Signing, |_, _, _| Ok(())).unwrap();
        let err = key
            .0
            .with_key::<()>(KeyRole::Signing, |_, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(DeviceKeyError::Tpm("timed out".into()))
            })
            .unwrap_err();
        assert!(matches!(err, DeviceKeyError::Tpm(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(OTHER_LOADS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn identity_slots_are_bound_to_their_label() {
        assert_eq!(
            tpm_wire::node_identity_handle(IDENTITY_KEY_LABEL, false),
            tpm_wire::NODE_IDENTITY_HANDLE
        );
        let ns = format!("node-b/{IDENTITY_KEY_LABEL}");
        let h = tpm_wire::node_identity_handle(&ns, true);
        assert!(h > tpm_wire::NODE_IDENTITY_HANDLE && h <= tpm_wire::NODE_IDENTITY_HANDLE + 255);
        let p = tpm_wire::parse_public(&tpm_wire::identity_template(&ns)).unwrap();
        assert!(is_identity_key_template(&p, &ns));
        assert!(!is_identity_key_template(&p, IDENTITY_KEY_LABEL));
    }

    /// [`crate::tpm_provision::is_identity_key`] without the point check: a template carries no point.
    fn is_identity_key_template(p: &PublicArea, label: &str) -> bool {
        p.attributes == KeyRole::Signing.attributes()
            && p.auth_policy == tpm_wire::label_unique(label)
    }

    /// Runs only where a provisioned TPM is reachable; on a host without
    /// one it checks that absence is reported rather than papered over.
    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM): opens and creates keys on the host TPM"]
    fn signs_and_verifies_on_real_hardware_if_present() {
        if !available() {
            assert!(open("tenzro-test").is_err());
            return;
        }
        let dir = std::env::temp_dir().join(format!("tenzro-tpm-test-{}", std::process::id()));
        // SAFETY: the test sets the variable before any key is opened.
        unsafe { std::env::set_var("TENZRO_DEVICE_KEY_DIR", &dir) };
        let key = match create("tenzro-test-sign") {
            Ok(k) => k,
            Err(e) => {
                assert!(e.to_string().contains("provision"), "{e}");
                return;
            }
        };
        let pk = key.public_key().unwrap();
        let digest: [u8; 32] = Sha256::digest(b"m").into();
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&pk);
        for _ in 0..3 {
            let sig = key.sign_prehash(&digest).unwrap();
            assert!(crate::signer::verify_p256_prehash(&sec1, &digest, &sig));
        }
        assert_eq!(open("tenzro-test-sign").unwrap().public_key().unwrap(), pk);
        let other = create("tenzro-test-other").unwrap().public_key().unwrap();
        assert_ne!(pk, other, "two labels must give two keys");
        delete("tenzro-test-sign").unwrap();
        delete("tenzro-test-other").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn hardware_test_dir() {
        let dir = std::env::temp_dir().join(format!("tenzro-tpm-kinds-{}", std::process::id()));
        // SAFETY: set before any key of these tests is opened; the hardware
        // tests run one at a time.
        unsafe { std::env::set_var("TENZRO_DEVICE_KEY_DIR", &dir) };
    }

    /// A P-384 key is generated in this machine's TPM, signs, verifies and is
    /// the same key when opened again. A TPM without P-384 is refused naming
    /// the curve, and no key is created.
    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM): opens and creates keys on the host TPM"]
    fn a_p384_key_is_held_and_used_in_the_tpm() {
        use sha2::Sha384;
        let kind = ChildKind::P384Signing;
        if !available() {
            assert!(TpmChildKey::open_or_create("tenzro-test-p384", kind).is_err());
            return;
        }
        hardware_test_dir();
        let has_p384 = TpmDevice::open()
            .and_then(|mut d| d.supports_ecc_curve(tpm_wire::TPM2_ECC_NIST_P384))
            .unwrap();
        let key = match TpmChildKey::open_or_create("tenzro-test-p384", kind) {
            Ok(k) => k,
            Err(e) => {
                if has_p384 {
                    assert!(e.to_string().contains("provision"), "{e}");
                } else {
                    assert!(e.to_string().contains("P-384"), "{e}");
                    let path = kind_path(&crate::namespaced("tenzro-test-p384"), kind).unwrap();
                    assert!(!path.exists());
                }
                return;
            }
        };
        assert!(has_p384);
        let pk = key.p384_sec1().unwrap();
        let digest: [u8; 48] = Sha384::digest(b"m").into();
        for _ in 0..3 {
            let sig = key.sign_p384_prehash(&digest).unwrap();
            assert!(crate::signer::verify_p384_prehash(&pk, &digest, &sig));
            let other: [u8; 48] = Sha384::digest(b"n").into();
            assert!(!crate::signer::verify_p384_prehash(&pk, &other, &sig));
        }
        let again = TpmChildKey::open_or_create("tenzro-test-p384", kind).unwrap();
        assert_eq!(again.p384_sec1().unwrap(), pk);
        let other = TpmChildKey::open_or_create("tenzro-test-p384-other", kind).unwrap();
        assert_ne!(
            other.p384_sec1().unwrap(),
            pk,
            "two labels must give two keys"
        );
        assert!(key.ml_dsa_sign(b"", b"m").is_err());
        TpmChildKey::delete("tenzro-test-p384", kind).unwrap();
        TpmChildKey::delete("tenzro-test-p384-other", kind).unwrap();
    }

    /// An ML-DSA-65 or ML-DSA-87 key is made only by a TPM that implements
    /// ML-DSA, and then signs inside it; any other TPM is refused, naming
    /// ML-DSA, and no key is created.
    #[test]
    #[ignore = "needs a TPM (TENZRO_TEST_TPM): opens and creates keys on the host TPM"]
    fn an_ml_dsa_key_is_made_only_by_a_tpm_that_implements_ml_dsa() {
        use tenzro_types::signature_scheme::SignatureScheme;
        if !available() {
            let kind = ChildKind::MlDsa(tpm_wire::TPM2_MLDSA_87);
            assert!(TpmChildKey::open_or_create("tenzro-test-mldsa", kind).is_err());
            return;
        }
        hardware_test_dir();
        let has_ml_dsa = TpmDevice::open()
            .and_then(|mut d| d.supports_algorithm(tpm_wire::TPM2_ALG_MLDSA))
            .unwrap();
        for (set, scheme) in [
            (tpm_wire::TPM2_MLDSA_65, SignatureScheme::MlDsa65P256),
            (tpm_wire::TPM2_MLDSA_87, SignatureScheme::MlDsa87P384),
        ] {
            let kind = ChildKind::MlDsa(set);
            let label = format!("tenzro-test-mldsa-{set}");
            let opened = TpmChildKey::open_or_create(&label, kind);
            if !has_ml_dsa {
                let e = opened.err().expect("a TPM without ML-DSA is refused");
                assert!(e.to_string().contains("does not implement ML-DSA"), "{e}");
                assert!(
                    !kind_path(&crate::namespaced(&label), kind)
                        .unwrap()
                        .exists()
                );
                continue;
            }
            let key = opened.unwrap();
            let vk = key.ml_dsa_public().unwrap();
            assert_eq!(vk.len(), scheme.ml_dsa_public_key_len());
            let sig = key.ml_dsa_sign(scheme.label(), b"message").unwrap();
            assert_eq!(sig.len(), scheme.ml_dsa_signature_len());
            tenzro_crypto::pq::ml_dsa_verify_scheme(scheme, &vk, scheme.label(), b"message", &sig)
                .unwrap();
            assert!(
                tenzro_crypto::pq::ml_dsa_verify_scheme(
                    scheme,
                    &vk,
                    scheme.label(),
                    b"other",
                    &sig
                )
                .is_err()
            );
            TpmChildKey::delete(&label, kind).unwrap();
        }
    }
}
