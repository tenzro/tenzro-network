//! One-time TPM provisioning, run by `tenzro-node tpm provision`.
//!
//! This is the only code that creates a primary key. It creates the node's
//! endorsement-hierarchy primaries and makes each persistent with
//! `TPM2_EvictControl`:
//!
//! | handle                                   | key                         |
//! |------------------------------------------|-----------------------------|
//! | [`tpm_wire::NODE_STORAGE_ROOT_HANDLE`]   | storage root (child parent) |
//! | [`tpm_wire::NODE_ATTESTATION_HANDLE`]    | machine attestation key     |
//! | [`tpm_wire::NODE_IDENTITY_HANDLE`] or a namespace's slot ([`find_identity_slot`]) | node identity key |
//! | the [`tpm_wire::EK_PROFILES`] handle of the first certified EK | endorsement key |
//!
//! The endorsement key is the one the TPM's manufacturer certified: of the
//! TCG EK kinds this TPM holds a certificate for (ECC P-256, RSA-2048, ECC
//! P-384, RSA-3072, in that order), the first whose key is already at its
//! handle, or can be recreated from its TCG template, checked against the
//! certificate, and made persistent at a free handle. Machine attestation
//! reads it there.
//!
//! A primary is a function of the endorsement seed and its template, so
//! provisioning is idempotent: a slot already holding the expected key is
//! left alone, and a slot holding any other key is never overwritten. A key
//! namespace's identity starts at the slot its label hashes to and, when
//! another label's key holds that one, takes the next free slot after it;
//! the key's `authPolicy` binds its label, so it is found again the same
//! way. The node itself only reads these handles ([`check`] at start-up)
//! and never creates them.

use crate::tpm_wire::{self, KeyRole, PublicArea, WireError};
use crate::{DeviceKeyError, Result};

/// Something that carries TPM command buffers to a TPM.
pub(crate) trait TpmTransport: Send {
    fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(any(target_os = "linux", windows))]
impl TpmTransport for crate::backend_tpm::TpmDevice {
    fn submit(&mut self, command: &[u8]) -> Result<Vec<u8>> {
        crate::backend_tpm::TpmDevice::submit(self, command)
    }
}

/// Label of the storage root's template.
pub(crate) const STORAGE_ROOT_LABEL: &str = "tenzro/device-key/derive-parent";

pub(crate) use crate::IDENTITY_KEY_LABEL;

pub(crate) const NOT_PROVISIONED: &str =
    "run `tenzro-node tpm provision` once on this machine to create its persistent TPM keys";

/// Where the identity key of a label is, or may go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentitySlot {
    /// The slot holds this label's identity key.
    Held(u32, PublicArea),
    /// No slot holds it; this one is the first free one on its way.
    Free(u32),
    /// No slot holds it and none is free.
    Full,
}

/// Finds the identity key `label` (already namespaced) with `read`, which
/// reads a persistent handle (`None` when nothing is there). The default
/// identity has its own slot. A namespace's identity is looked for from the
/// slot its label hashes to, then each next slot of the 255, wrapping: the
/// first holding this label's key is it, and otherwise the first free one
/// is where it goes. A slot holding another label's key is passed over,
/// never taken.
pub(crate) fn find_identity_slot(
    label: &str,
    mut read: impl FnMut(u32) -> Result<Option<PublicArea>>,
) -> Result<IdentitySlot> {
    let namespaced = label != IDENTITY_KEY_LABEL;
    let first = tpm_wire::node_identity_handle(label, namespaced);
    if !namespaced {
        return Ok(match read(first)? {
            Some(p) if is_identity_key(&p, label) => IdentitySlot::Held(first, p),
            Some(_) => IdentitySlot::Full,
            None => IdentitySlot::Free(first),
        });
    }
    let base = tpm_wire::NODE_IDENTITY_HANDLE + 1;
    let start = first - base;
    let mut free = None;
    for i in 0..tpm_wire::NAMESPACE_IDENTITY_SLOTS {
        let handle = base + (start + i) % tpm_wire::NAMESPACE_IDENTITY_SLOTS;
        match read(handle)? {
            Some(p) if is_identity_key(&p, label) => return Ok(IdentitySlot::Held(handle, p)),
            Some(_) => {}
            None => {
                free.get_or_insert(handle);
            }
        }
    }
    Ok(free.map_or(IdentitySlot::Full, IdentitySlot::Free))
}

/// Whether `p` is the identity key for `label`: a P-256 signing key whose
/// `authPolicy` binds the label.
pub(crate) fn is_identity_key(p: &PublicArea, label: &str) -> bool {
    p.attributes == KeyRole::Signing.attributes()
        && p.auth_policy == tpm_wire::label_unique(label)
        && p.p256_sec1().is_some()
}

/// What provisioning found or did for one slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The slot already held the expected key.
    Present,
    /// The key was created and made persistent now.
    Created,
}

/// The outcome of [`provision`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub storage_root: (u32, Slot),
    pub attestation: (u32, Slot),
    pub identity: (u32, Slot),
    /// The manufacturer-certified endorsement key made persistent for
    /// machine attestation, if the TPM holds a certificate for one.
    pub endorsement_key: Option<EndorsementSlot>,
    /// Whether an (uncertified) ECC endorsement key is at
    /// [`tpm_wire::EK_ECC_PERSISTENT_HANDLE`], what attestation falls back
    /// to when no certified one is.
    pub uncertified_endorsement_key: bool,
}

/// Where the certified endorsement key is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndorsementSlot {
    pub handle: u32,
    /// The EK kind, e.g. "ECC P-384 (H-3)".
    pub kind: &'static str,
    pub slot: Slot,
}

fn err(msg: impl Into<String>) -> DeviceKeyError {
    DeviceKeyError::Tpm(msg.into())
}

fn wire(what: &'static str) -> impl Fn(WireError) -> DeviceKeyError {
    move |e| err(format!("{what}: {e}"))
}

pub(crate) fn read_public(t: &mut dyn TpmTransport, handle: u32) -> Result<Option<PublicArea>> {
    match tpm_wire::parse_read_public_response(&t.submit(&tpm_wire::read_public_command(handle))?) {
        Ok(p) => Ok(Some(p)),
        Err(WireError::ResponseCode(code)) if tpm_wire::handle_lost(code) => Ok(None),
        Err(e) => Err(err(format!("read TPM handle 0x{handle:08x}: {e}"))),
    }
}

/// Create the primary for `template` and make it persistent at `handle`,
/// unless `handle` already holds that same key.
fn persist_primary(t: &mut dyn TpmTransport, template: &[u8], handle: u32) -> Result<Slot> {
    let resp = t.submit(&tpm_wire::create_primary_command(template))?;
    let (transient, public) =
        tpm_wire::parse_create_primary_response(&resp).map_err(wire("create primary"))?;
    let outcome = (|| match read_public(t, handle)? {
        Some(held) if held.key == public.key && held.attributes == public.attributes => {
            Ok(Slot::Present)
        }
        Some(_) => Err(err(format!(
            "TPM handle 0x{handle:08x} already holds a different key; evict it first if it is not in use"
        ))),
        None => {
            let resp = t.submit(&tpm_wire::evict_control_command(transient, handle))?;
            tpm_wire::response_body(&resp).map_err(wire("make the key persistent"))?;
            Ok(Slot::Created)
        }
    })();
    let _ = t.submit(&tpm_wire::flush_context_command(transient));
    outcome
}

/// Provision the persistent node keys through `t`, for the identity key
/// labelled `identity_label` (already namespaced).
pub(crate) fn provision_with(t: &mut dyn TpmTransport, identity_label: &str) -> Result<Report> {
    let storage_root = persist_primary(
        t,
        &tpm_wire::storage_parent_template(STORAGE_ROOT_LABEL),
        tpm_wire::NODE_STORAGE_ROOT_HANDLE,
    )?;
    let attestation = persist_primary(
        t,
        &tpm_wire::ecc_p256_template(
            KeyRole::Attestation,
            crate::key_certification::ATTESTATION_KEY_LABEL,
        ),
        tpm_wire::NODE_ATTESTATION_HANDLE,
    )?;
    let identity_handle = match find_identity_slot(identity_label, |h| read_public(t, h))? {
        IdentitySlot::Held(h, _) | IdentitySlot::Free(h) => h,
        IdentitySlot::Full if identity_label == IDENTITY_KEY_LABEL => {
            return Err(err(format!(
                "TPM handle 0x{:08x} already holds a different key; evict it first if it is not in use",
                tpm_wire::NODE_IDENTITY_HANDLE
            )));
        }
        IdentitySlot::Full => {
            return Err(err(format!(
                "every one of the {} namespace identity slots holds another key; evict one that is not in use",
                tpm_wire::NAMESPACE_IDENTITY_SLOTS
            )));
        }
    };
    let identity = persist_primary(
        t,
        &tpm_wire::identity_template(identity_label),
        identity_handle,
    )?;
    let endorsement_key = provision_endorsement_key(t)?;
    let uncertified_endorsement_key = read_public(t, tpm_wire::EK_ECC_PERSISTENT_HANDLE)?.is_some();
    Ok(Report {
        storage_root: (tpm_wire::NODE_STORAGE_ROOT_HANDLE, storage_root),
        attestation: (tpm_wire::NODE_ATTESTATION_HANDLE, attestation),
        identity: (identity_handle, identity),
        endorsement_key,
        uncertified_endorsement_key,
    })
}

/// Read a whole NV index; `None` when the TPM has no such index.
fn nv_read_all(t: &mut dyn TpmTransport, index: u32) -> Result<Option<Vec<u8>>> {
    let Ok(size) = tpm_wire::parse_nv_read_public_response(
        &t.submit(&tpm_wire::nv_read_public_command(index))?,
    ) else {
        return Ok(None);
    };
    const CHUNK: u16 = 512;
    let mut out = Vec::with_capacity(size as usize);
    while (out.len() as u16) < size {
        let offset = out.len() as u16;
        let resp = t.submit(&tpm_wire::nv_read_command(
            index,
            CHUNK.min(size - offset),
            offset,
        ))?;
        let chunk =
            tpm_wire::parse_nv_read_response(&resp).map_err(wire("read the EK certificate"))?;
        if chunk.is_empty() {
            return Err(err("NV read returned no data"));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
}

/// Whether the DER certificate `cert` carries `key`'s public key: its ECC
/// point (uncompressed) or RSA modulus appears in the certificate. This only
/// picks which endorsement key to keep; every verifier checks the
/// certificate's key against the EK exactly, and its chain by signature.
fn key_in_certificate(key: &PublicArea, cert: &[u8]) -> bool {
    let bytes: Vec<u8> = match &key.key {
        tpm_wire::PublicKey::Rsa { modulus, .. } => modulus.clone(),
        _ => match (key.p256_sec1(), key.p384_sec1()) {
            (Some(p), _) => p.to_vec(),
            (_, Some(p)) => p.to_vec(),
            _ => return false,
        },
    };
    bytes.len() >= 64 && cert.windows(bytes.len()).any(|w| w == bytes.as_slice())
}

/// Make the manufacturer-certified endorsement key persistent (see the
/// module documentation for which one).
fn provision_endorsement_key(t: &mut dyn TpmTransport) -> Result<Option<EndorsementSlot>> {
    let mut certificate = |t: &mut dyn TpmTransport, index| nv_read_all(t, index);
    choose_endorsement_key(
        t,
        &mut certificate,
        &mut |t, handle| read_public(t, handle),
        &mut |t, profile, cert| {
            let resp = t.submit(&tpm_wire::create_primary_command(&(profile.template)()))?;
            let (transient, public) = tpm_wire::parse_create_primary_response(&resp)
                .map_err(wire("recreate the endorsement key"))?;
            let outcome = if key_in_certificate(&public, cert) {
                let resp = t.submit(&tpm_wire::evict_control_command(
                    transient,
                    profile.persistent,
                ))?;
                tpm_wire::response_body(&resp)
                    .map(|_| true)
                    .map_err(wire("make the endorsement key persistent"))
            } else {
                Ok(false)
            };
            let _ = t.submit(&tpm_wire::flush_context_command(transient));
            outcome
        },
    )
}

type CertReader<'a> = dyn FnMut(&mut dyn TpmTransport, u32) -> Result<Option<Vec<u8>>> + 'a;
type HandleReader<'a> = dyn FnMut(&mut dyn TpmTransport, u32) -> Result<Option<PublicArea>> + 'a;
type Persister<'a> =
    dyn FnMut(&mut dyn TpmTransport, &tpm_wire::EkProfile, &[u8]) -> Result<bool> + 'a;

/// The selection behind [`provision_endorsement_key`], over its three TPM
/// operations: the first EK kind with a certificate whose key is at its
/// handle, or whose handle is free and whose recreated key the certificate
/// carries (then persisted). A handle holding any other key is never
/// overwritten; that kind is passed over.
fn choose_endorsement_key(
    t: &mut dyn TpmTransport,
    certificate: &mut CertReader<'_>,
    held: &mut HandleReader<'_>,
    persist: &mut Persister<'_>,
) -> Result<Option<EndorsementSlot>> {
    for profile in tpm_wire::EK_PROFILES {
        let Some(cert) = certificate(t, profile.cert_index)?.filter(|c| !c.is_empty()) else {
            continue;
        };
        let found = |slot| EndorsementSlot {
            handle: profile.persistent,
            kind: profile.name,
            slot,
        };
        match held(t, profile.persistent)? {
            Some(key) if key_in_certificate(&key, &cert) => return Ok(Some(found(Slot::Present))),
            Some(_) => continue,
            None => {
                if persist(t, &profile, &cert)? {
                    return Ok(Some(found(Slot::Created)));
                }
            }
        }
    }
    Ok(None)
}

/// Check through `t` that every persistent node key is in place, naming the
/// first one that is not.
pub(crate) fn check_with(t: &mut dyn TpmTransport, identity_label: &str) -> Result<()> {
    let missing = |what: &str, handle: u32| {
        err(format!(
            "this machine's TPM has no {what} at 0x{handle:08x}; {}",
            NOT_PROVISIONED
        ))
    };
    let root = tpm_wire::NODE_STORAGE_ROOT_HANDLE;
    match read_public(t, root)? {
        Some(p) if p.attributes == tpm_wire::STORAGE_PARENT_ATTRIBUTES => {}
        _ => return Err(missing("storage root", root)),
    }
    let ak = tpm_wire::NODE_ATTESTATION_HANDLE;
    match read_public(t, ak)? {
        Some(p) if p.attributes == tpm_wire::ATTESTATION_KEY_ATTRIBUTES => {}
        _ => return Err(missing("attestation key", ak)),
    }
    match find_identity_slot(identity_label, |h| read_public(t, h))? {
        IdentitySlot::Held(..) => Ok(()),
        _ => Err(missing(
            "node identity key",
            tpm_wire::node_identity_handle(identity_label, identity_label != IDENTITY_KEY_LABEL),
        )),
    }
}

/// The device-key directory: `TENZRO_DEVICE_KEY_DIR`, else the user's
/// local state directory.
#[cfg(any(target_os = "linux", windows))]
pub(crate) fn default_dir() -> Result<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(d) = std::env::var_os("TENZRO_DEVICE_KEY_DIR") {
        return Ok(PathBuf::from(d));
    }
    #[cfg(target_os = "linux")]
    let base = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state"));
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    base.map(|b| b.join("tenzro").join("device-keys"))
        .ok_or_else(|| {
            err("no TENZRO_DEVICE_KEY_DIR and no user state directory: nowhere to keep TPM keys")
        })
}

/// Create `dir` and its parents, readable by this user only.
pub(crate) fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// Write `bytes` to `path` only if nothing is there yet, atomically: a
/// concurrent creator either wins or finds the finished file.
pub(crate) fn write_new(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<bool> {
    use std::io::Write;
    // Unique per call, not only per process: two threads of one process
    // creating the same file must not write the same partial file.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let partial = path.with_extension(format!(
        "partial.{}.{}",
        std::process::id(),
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let mut f = o.open(&partial)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    let linked = std::fs::hard_link(&partial, path);
    let _ = std::fs::remove_file(&partial);
    match linked {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e),
    }
}

/// Provision this machine's TPM for the node (under this process's key
/// namespace). Idempotent.
#[cfg(any(target_os = "linux", windows))]
pub fn provision() -> Result<Report> {
    let mut dev = crate::backend_tpm::TpmDevice::open()?;
    provision_with(&mut dev, &crate::namespaced(IDENTITY_KEY_LABEL))
}

/// Refuse to run a node on a TPM that has not been provisioned. A machine
/// without a TPM passes: it has no hardware identity either way.
#[cfg(any(target_os = "linux", windows))]
pub fn check() -> Result<()> {
    if !crate::backend_tpm::available() {
        return Ok(());
    }
    let mut dev = crate::backend_tpm::TpmDevice::open()?;
    check_with(&mut dev, &crate::namespaced(IDENTITY_KEY_LABEL))
}

/// This TPM's endorsement key, made as a transient primary from the TCG
/// template: the key the manufacturer certified, without reading or using
/// any persistent handle. The caller flushes the returned handle.
pub(crate) fn transient_endorsement_key(
    t: &mut dyn TpmTransport,
) -> Result<(u32, tpm_wire::PublicArea)> {
    let resp = t.submit(&tpm_wire::create_primary_command(
        &tpm_wire::ek_ecc_template(),
    ))?;
    tpm_wire::parse_create_primary_response(&resp)
        .map_err(|e| DeviceKeyError::Enclave(format!("recreating the endorsement key: {e}")))
}

#[cfg(test)]
mod tests {
    use super::{IdentitySlot, find_identity_slot, is_identity_key};
    use crate::tpm_wire::{self, PublicArea};
    use std::collections::HashMap;

    /// Threads of one process creating the same file at once: exactly one
    /// creates it, the rest find it finished, and none fails.
    #[test]
    fn concurrent_creators_of_one_file_do_not_collide() {
        let dir = std::env::temp_dir().join(format!("tenzro-write-new-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        super::create_private_dir(&dir).unwrap();
        let path = dir.join("file.bin");
        let wins: usize = std::thread::scope(|s| {
            let handles: Vec<_> = (0..16u8)
                .map(|i| {
                    let path = path.clone();
                    s.spawn(move || super::write_new(&path, &[i; 64]).unwrap())
                })
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum()
        });
        assert_eq!(wins, 1, "one creator wins");
        assert_eq!(std::fs::read(&path).unwrap().len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An identity key of `label` as the TPM would hold it: its template
    /// with a point.
    fn identity_key(label: &str) -> PublicArea {
        let mut p = tpm_wire::parse_public(&tpm_wire::identity_template(label)).unwrap();
        if let tpm_wire::PublicKey::EccP256 { x, y, .. } = &mut p.key {
            *x = [1; 32];
            *y = [2; 32];
        }
        assert!(is_identity_key(&p, label));
        p
    }

    /// Two namespaces whose labels hash to the same slot.
    fn colliding_labels() -> (String, String) {
        let mut seen: HashMap<u32, String> = HashMap::new();
        for i in 0.. {
            let label = format!("cl-run-{i}/{}", crate::IDENTITY_KEY_LABEL);
            let slot = tpm_wire::node_identity_handle(&label, true);
            if let Some(other) = seen.insert(slot, label.clone()) {
                return (other, label);
            }
        }
        unreachable!()
    }

    /// A namespace whose slot another namespace's key holds takes the next
    /// free slot, which it is then found at; the other key is untouched.
    #[test]
    fn a_namespace_whose_slot_is_taken_goes_to_the_next_free_one() {
        let (first, second) = colliding_labels();
        let home = tpm_wire::node_identity_handle(&first, true);
        assert_eq!(home, tpm_wire::node_identity_handle(&second, true));
        let mut tpm: HashMap<u32, PublicArea> = HashMap::new();
        tpm.insert(home, identity_key(&first));
        let read = |tpm: &HashMap<u32, PublicArea>| {
            let tpm = tpm.clone();
            move |h: u32| Ok(tpm.get(&h).cloned())
        };
        let IdentitySlot::Free(slot) = find_identity_slot(&second, read(&tpm)).unwrap() else {
            panic!("the second namespace gets a free slot")
        };
        assert_ne!(slot, home, "never the slot another key holds");
        tpm.insert(slot, identity_key(&second));
        assert_eq!(
            find_identity_slot(&second, read(&tpm)).unwrap(),
            IdentitySlot::Held(slot, identity_key(&second))
        );
        assert_eq!(
            find_identity_slot(&first, read(&tpm)).unwrap(),
            IdentitySlot::Held(home, identity_key(&first))
        );
    }

    /// Probing wraps past the last slot, and a TPM whose every namespace
    /// slot holds another key has no room, rather than a slot to overwrite.
    #[test]
    fn probing_wraps_and_a_full_tpm_is_refused() {
        let label = format!("cl-wrap/{}", crate::IDENTITY_KEY_LABEL);
        let base = tpm_wire::NODE_IDENTITY_HANDLE + 1;
        let other = identity_key(&format!("cl-other/{}", crate::IDENTITY_KEY_LABEL));
        let mut tpm: HashMap<u32, PublicArea> = (0..tpm_wire::NAMESPACE_IDENTITY_SLOTS)
            .map(|i| (base + i, other.clone()))
            .collect();
        assert_eq!(
            find_identity_slot(&label, |h| Ok(tpm.get(&h).cloned())).unwrap(),
            IdentitySlot::Full
        );
        tpm.remove(&base);
        assert_eq!(
            find_identity_slot(&label, |h| Ok(tpm.get(&h).cloned())).unwrap(),
            IdentitySlot::Free(base)
        );
    }

    /// A transport that is never used: the selection is driven through the
    /// closures alone.
    struct NoTpm;
    impl super::TpmTransport for NoTpm {
        fn submit(&mut self, _: &[u8]) -> crate::Result<Vec<u8>> {
            unreachable!("the selection test sends no command")
        }
    }

    fn ek_with_point(template: Vec<u8>, point: &[u8]) -> PublicArea {
        let mut p = tpm_wire::parse_public(&template).unwrap();
        match &mut p.key {
            tpm_wire::PublicKey::EccP256 { x, y, .. } => {
                x.copy_from_slice(&point[1..33]);
                y.copy_from_slice(&point[33..65]);
            }
            tpm_wire::PublicKey::EccP384 { x, y, .. } => {
                x.copy_from_slice(&point[1..49]);
                y.copy_from_slice(&point[49..97]);
            }
            tpm_wire::PublicKey::Rsa { modulus, .. } => *modulus = point.to_vec(),
            tpm_wire::PublicKey::MlDsa { .. } => unreachable!("endorsement keys are ECC or RSA"),
        }
        p
    }

    /// A TPM that holds certificates for RSA-2048 and P-384 EKs, an
    /// unrelated key at the RSA EK handle. The RSA handle is left alone and
    /// the P-384 EK is made persistent at its own handle.
    #[test]
    fn the_first_certified_ek_with_a_free_or_matching_handle_is_kept() {
        use super::{EndorsementSlot, Slot, choose_endorsement_key};
        let p384_point = [[4u8].as_slice(), &[7u8; 96]].concat();
        let rsa_modulus = vec![9u8; 256];
        let p384_cert = [b"cert-p384:".as_slice(), &p384_point, b"-end"].concat();
        let rsa_cert = [b"cert-rsa:".as_slice(), &rsa_modulus, b"-end"].concat();
        let certs: HashMap<u32, Vec<u8>> = [
            (tpm_wire::EK_CERT_NV_RSA, rsa_cert),
            (tpm_wire::EK_CERT_NV_ECC_P384, p384_cert),
        ]
        .into();
        let unrelated = identity_key(crate::IDENTITY_KEY_LABEL);
        let mut handles: HashMap<u32, PublicArea> =
            [(tpm_wire::EK_RSA_PERSISTENT_HANDLE, unrelated.clone())].into();
        let recreated = |template: Vec<u8>| -> PublicArea {
            match tpm_wire::parse_public(&template).unwrap().key {
                tpm_wire::PublicKey::EccP384 { .. } => ek_with_point(template, &p384_point),
                _ => ek_with_point(template, &[[4u8].as_slice(), &[1u8; 64]].concat()),
            }
        };
        let mut persisted = Vec::new();
        let run = |handles: &mut HashMap<u32, PublicArea>, persisted: &mut Vec<u32>| {
            let snapshot = handles.clone();
            choose_endorsement_key(
                &mut NoTpm,
                &mut |_, i| Ok(certs.get(&i).cloned()),
                &mut |_, h| Ok(snapshot.get(&h).cloned()),
                &mut |_, profile, cert| {
                    let key = recreated((profile.template)());
                    let ok = super::key_in_certificate(&key, cert);
                    if ok {
                        persisted.push(profile.persistent);
                        handles.insert(profile.persistent, key);
                    }
                    Ok(ok)
                },
            )
            .unwrap()
        };
        assert_eq!(
            run(&mut handles, &mut persisted),
            Some(EndorsementSlot {
                handle: tpm_wire::EK_ECC_P384_PERSISTENT_HANDLE,
                kind: "ECC P-384 (H-3)",
                slot: Slot::Created,
            })
        );
        assert_eq!(persisted, vec![tpm_wire::EK_ECC_P384_PERSISTENT_HANDLE]);
        assert_eq!(handles[&tpm_wire::EK_RSA_PERSISTENT_HANDLE], unrelated);
        // Provisioning again finds it in place.
        assert_eq!(
            run(&mut handles, &mut persisted).map(|s| s.slot),
            Some(Slot::Present)
        );
        assert_eq!(persisted.len(), 1);
    }

    /// A TPM with no EK certificate gets no endorsement key from provisioning.
    #[test]
    fn no_certificate_no_endorsement_key() {
        let got = super::choose_endorsement_key(
            &mut NoTpm,
            &mut |_, _| Ok(None),
            &mut |_, _| Ok(None),
            &mut |_, _, _| unreachable!("nothing to persist"),
        )
        .unwrap();
        assert_eq!(got, None);
    }

    /// The certified EK templates recreate the keys this TPM's manufacturer
    /// certified. Runs only against a real TPM (`--ignored`), creates
    /// transient primaries and flushes them; persists nothing. Kinds named in
    /// `TENZRO_TEST_EK_KINDS` (comma-separated `p256,rsa2048,p384,rsa3072`)
    /// are checked, the others skipped: an RSA primary takes the TPM seconds.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    #[ignore]
    fn ek_templates_match_this_tpms_certificates() {
        let kinds = std::env::var("TENZRO_TEST_EK_KINDS").unwrap_or_else(|_| "p384".into());
        let mut dev = crate::backend_tpm::TpmDevice::open().unwrap();
        let mut checked = 0;
        for (kind, profile) in ["p256", "rsa2048", "p384", "rsa3072"]
            .into_iter()
            .zip(tpm_wire::EK_PROFILES)
        {
            if !kinds.split(',').any(|k| k == kind) {
                continue;
            }
            let Some(cert) = super::nv_read_all(&mut dev, profile.cert_index).unwrap() else {
                eprintln!("{kind}: no certificate on this TPM");
                continue;
            };
            let resp = dev
                .submit(&tpm_wire::create_primary_command(&(profile.template)()))
                .unwrap();
            let (handle, public) = tpm_wire::parse_create_primary_response(&resp).unwrap();
            let _ = dev.submit(&tpm_wire::flush_context_command(handle));
            assert!(
                super::key_in_certificate(&public, &cert),
                "{kind}: the template does not recreate the certified key"
            );
            eprintln!("{kind}: template recreates the certified key");
            checked += 1;
        }
        assert!(
            checked > 0,
            "no certified EK of the requested kinds on this TPM"
        );
    }

    /// swtpm's TCP command channel (`swtpm socket --server type=tcp`).
    struct Swtpm(std::net::TcpStream);

    impl super::TpmTransport for Swtpm {
        fn submit(&mut self, command: &[u8]) -> crate::Result<Vec<u8>> {
            use std::io::{Read, Write};
            let io = |e: std::io::Error| crate::DeviceKeyError::Tpm(format!("swtpm: {e}"));
            self.0.write_all(command).map_err(io)?;
            let mut head = [0u8; 10];
            self.0.read_exact(&mut head).map_err(io)?;
            let size = u32::from_be_bytes([head[2], head[3], head[4], head[5]]) as usize;
            let mut rest = vec![0u8; size.saturating_sub(10)];
            self.0.read_exact(&mut rest).map_err(io)?;
            Ok([head.as_slice(), &rest].concat())
        }
    }

    /// `TPM2_ActivateCredential` with the node's attestation key and the
    /// endorsement key at `ek_handle`, authorised as its template says.
    fn activate(
        t: &mut dyn super::TpmTransport,
        ek: &PublicArea,
        ek_handle: u32,
        cred: &crate::credential::Credential,
    ) -> crate::Result<Vec<u8>> {
        let ak = tpm_wire::NODE_ATTESTATION_HANDLE;
        let command = if ek.attributes & tpm_wire::TPMA_OBJECT_USERWITHAUTH != 0 {
            tpm_wire::activate_credential_password_command(
                ak,
                ek_handle,
                &cred.blob,
                &cred.encrypted_secret,
            )
        } else {
            let session = tpm_wire::parse_start_auth_session_response(
                &t.submit(&tpm_wire::start_policy_session_command(&[7; 16]))?,
            )
            .map_err(super::wire("policy session"))?;
            tpm_wire::response_body(
                &t.submit(&tpm_wire::policy_secret_endorsement_command(session))?,
            )
            .map_err(super::wire("PolicySecret"))?;
            tpm_wire::activate_credential_command(
                ak,
                ek_handle,
                session,
                &cred.blob,
                &cred.encrypted_secret,
            )
        };
        tpm_wire::parse_activate_credential_response(&t.submit(&command)?)
            .map_err(super::wire("ActivateCredential"))
    }

    /// `ek` with its key replaced by a different one of the same kind: an
    /// endorsement key no TPM here holds.
    fn another_ek_like(ek: &PublicArea) -> PublicArea {
        use rand::SeedableRng;
        use rsa::traits::PublicKeyParts;
        let (unique, held_len): (Vec<Vec<u8>>, usize) = match &ek.key {
            tpm_wire::PublicKey::EccP256 { .. } => {
                let p = p256::SecretKey::from_slice(&[0x31; 32])
                    .unwrap()
                    .public_key()
                    .to_sec1_bytes();
                (vec![p[1..33].to_vec(), p[33..].to_vec()], 68)
            }
            tpm_wire::PublicKey::EccP384 { .. } => {
                let p = p384::SecretKey::from_slice(&[0x31; 48])
                    .unwrap()
                    .public_key()
                    .to_sec1_bytes();
                (vec![p[1..49].to_vec(), p[49..].to_vec()], 100)
            }
            tpm_wire::PublicKey::Rsa { modulus, .. } => {
                let mut rng = rand::rngs::StdRng::seed_from_u64(31);
                let k = rsa::RsaPrivateKey::new(&mut rng, modulus.len() * 8).unwrap();
                (vec![k.n().to_bytes_be()], 2 + modulus.len())
            }
            tpm_wire::PublicKey::MlDsa { .. } => unreachable!("endorsement keys are ECC or RSA"),
        };
        let mut w = tpm_wire::Writer::new();
        for u in &unique {
            w.tpm2b(u);
        }
        let head = &ek.raw[..ek.raw.len() - held_len];
        tpm_wire::parse_public(&[head, &w.finish()].concat()).unwrap()
    }

    /// Admission against swtpm, for the one certified endorsement key kind a
    /// test script set up (scripts/testnet/swtpm-ek-admission.sh; PRIVATE
    /// TEST ONLY). Provisioning must find and keep that EK, and the TPM must
    /// release a credential encrypted to it only to the attestation key it
    /// names, and never one encrypted to another EK of the same kind. Writes
    /// the EK's `TPMT_PUBLIC` and certificate for the chain check.
    #[test]
    #[ignore]
    fn swtpm_admission_for_its_endorsement_key() {
        let addr = std::env::var("TENZRO_TEST_SWTPM").expect("TENZRO_TEST_SWTPM=host:port");
        let kind = std::env::var("TENZRO_TEST_SWTPM_EK").expect("TENZRO_TEST_SWTPM_EK=<EK kind>");
        let out = std::path::PathBuf::from(std::env::var("TENZRO_TEST_SWTPM_OUT").unwrap());
        let mut t = Swtpm(std::net::TcpStream::connect(addr).unwrap());
        let report = super::provision_with(&mut t, crate::IDENTITY_KEY_LABEL).unwrap();
        let slot = report
            .endorsement_key
            .expect("provisioning keeps a certified EK");
        assert_eq!(slot.kind, kind);
        eprintln!("{kind}: kept at 0x{:08x} ({:?})", slot.handle, slot.slot);
        let ek = super::read_public(&mut t, slot.handle).unwrap().unwrap();
        let profile = tpm_wire::EK_PROFILES
            .iter()
            .find(|p| p.name == kind)
            .unwrap();
        let cert = super::nv_read_all(&mut t, profile.cert_index)
            .unwrap()
            .unwrap();
        assert!(super::key_in_certificate(&ek, &cert));

        let ak = super::read_public(&mut t, tpm_wire::NODE_ATTESTATION_HANDLE)
            .unwrap()
            .unwrap();
        let secret = [0x5A; 32];
        let cred = crate::credential::make_credential(&ek, &ak.name().unwrap(), &secret).unwrap();
        assert_eq!(activate(&mut t, &ek, slot.handle, &cred).unwrap(), secret);
        eprintln!("{kind}: the TPM released the credential to the attestation key");

        // Bound to the attestation key's name: made for another object, the
        // TPM refuses it.
        let root = super::read_public(&mut t, tpm_wire::NODE_STORAGE_ROOT_HANDLE)
            .unwrap()
            .unwrap();
        let elsewhere =
            crate::credential::make_credential(&ek, &root.name().unwrap(), &secret).unwrap();
        assert!(activate(&mut t, &ek, slot.handle, &elsewhere).is_err());
        // Encrypted to an endorsement key this TPM does not hold: refused.
        let other = another_ek_like(&ek);
        assert_ne!(other.raw, ek.raw);
        let foreign =
            crate::credential::make_credential(&other, &ak.name().unwrap(), &secret).unwrap();
        assert!(activate(&mut t, &ek, slot.handle, &foreign).is_err());
        eprintln!("{kind}: credentials for another object or another EK are refused");

        std::fs::write(out.join("ek_public.bin"), &ek.raw).unwrap();
        std::fs::write(out.join("ek_cert.der"), &cert).unwrap();
    }

    /// Source files that may build a `TPM2_CreatePrimary` command outside
    /// their tests: the wire encoder and this module.
    const ALLOWED: &[&str] = &["tpm_wire.rs", "tpm_provision.rs"];

    /// The part of a source file outside its `#[cfg(test)] mod tests`.
    fn non_test(src: &str) -> &str {
        src.find("#[cfg(test)]\nmod tests")
            .map_or(src, |i| &src[..i])
    }

    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                rust_files(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// No code path creates a primary key outside provisioning, in this
    /// crate or in any crate of the workspace that sends TPM commands.
    #[test]
    fn no_code_path_creates_a_primary_outside_provisioning() {
        let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let mut files = Vec::new();
        for c in std::fs::read_dir(crates).unwrap() {
            let src = c.unwrap().path().join("src");
            if src.is_dir() {
                rust_files(&src, &mut files);
            }
        }
        assert!(files.len() > 100, "the workspace sources were not found");
        let mut offenders = Vec::new();
        for f in &files {
            let name = f.file_name().unwrap().to_str().unwrap();
            let in_this_crate = f.starts_with(env!("CARGO_MANIFEST_DIR"));
            if in_this_crate && ALLOWED.contains(&name) {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let body = non_test(&src);
            for needle in [
                "create_primary",
                "TPM2_CC_CREATE_PRIMARY",
                "Command::new(\"tpm2_createprimary\")",
                ".primary(KeyRole",
            ] {
                if body.contains(needle) {
                    offenders.push(format!("{} ({needle})", f.display()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "primary keys created outside provisioning: {offenders:#?}"
        );
    }
}
