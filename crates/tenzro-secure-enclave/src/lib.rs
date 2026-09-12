//! Apple Secure Enclave as a **machine-identity** root.
//!
//! # Where this sits
//!
//! Tenzro keeps three concerns apart, and this crate is deliberately only the
//! second one:
//!
//! | Concern | Root | Crate |
//! |---|---|---|
//! | **Human** identity | passkeys | `tenzro-auth` / WebAuthn |
//! | **Machine** identity | TPM 2.0, or the Secure Enclave on Apple | `tenzro-tee`'s TPM code, **this crate** |
//! | **Network** security | TEE attestation (SEV-SNP, TDX, Nitro, GPU CC) | `tenzro-tee` |
//!
//! A TEE, a TPM and the Secure Enclave are **not** the same thing and this crate
//! does not pretend otherwise. A TEE attests that a *workload* runs unmodified
//! on trusted silicon; a TPM and the SEP attest that a *machine* holds a key
//! nobody can copy. Folding Apple support into the TEE crate would have implied
//! an equivalence that does not exist — hence a separate entity.
//!
//! # What the Secure Enclave gives, precisely
//!
//! A persistent, non-extractable P-256 key bound to this machine's SEP, with
//! **no Apple Developer Program membership, no provisioning profile and no
//! entitlements** — see [`tenzro_device_key`] for the measurements behind that
//! claim. That is what makes an Apple node permissionless.
//!
//! # ⚠ Where it is weaker than a TPM
//!
//! The SEP has **no PCRs and issues no quote**. A TPM seals to measured-boot
//! state, so unsealing says something about the boot chain; the enclave says
//! only "this key is non-extractable on this machine". There is no attestation
//! path at all, not merely a weaker one.
//!
//! [`MachineRootKind`] exists so that distinction is *recorded* rather than
//! inferred. Anything that stores how a node is rooted must not write an
//! enclave-rooted node down as TPM-attested: "there is a hardware root" and
//! "the root carries a measured-boot claim" are different statements, and
//! conflating them puts a false assurance claim into whatever keeps it.

use zeroize::Zeroizing;

pub mod error;
pub use error::{Error, Result};

/// Which hardware produced a machine-identity root.
///
/// Recorded, never inferred — see the crate docs on why the distinction has to
/// survive into whatever stores it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum MachineRootKind {
    /// TPM 2.0. Sealed to the platform; no measured-image binding, but quotes
    /// are available.
    Tpm,
    /// Apple Secure Enclave. **No measured-image binding and no quote.**
    /// Non-extractability is the entire guarantee.
    SecureEnclave,
}

impl MachineRootKind {
    /// Whether this root can produce an attestation quote.
    ///
    /// False for [`Self::SecureEnclave`] — there is nothing to quote. A caller
    /// that needs a quote must not silently accept an enclave-rooted node.
    pub fn can_quote(self) -> bool {
        matches!(self, Self::Tpm)
    }

    /// Neither root binds the measured image; both seal to the machine. Present
    /// so callers do not have to remember which of the two properties the SEP
    /// lacks — it lacks both, the TPM lacks one.
    pub fn binds_measured_image(self) -> bool {
        false
    }
}

/// Label under which this machine's root is sealed.
const MACHINE_ROOT_LABEL: &str = "tenzro-machine-root";

/// Whether this machine has a usable Secure Enclave.
///
/// False on every non-Apple target, so a caller can probe unconditionally.
pub fn available() -> bool {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        tenzro_device_key::backend_se::available()
    }
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        false
    }
}

/// A stable per-machine secret only this Secure Enclave can recover.
///
/// Generated once from the OS CSPRNG and immediately sealed; thereafter
/// unsealed. The bytes never exist on disk in the clear, so copying the disk
/// yields a blob no other machine's SEP will open — machine-*bound*, not merely
/// machine-*resident*.
///
/// The secret is read back rather than returned from the generating call, so
/// the very first invocation exercises the same path every later one takes. A
/// seal that silently failed to persist would otherwise surface only after a
/// reboot, by which point the key derived from it is already in use.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn machine_root_ikm() -> Result<Zeroizing<Vec<u8>>> {
    use sha2::Digest;
    use tenzro_device_key::SealedSecret;
    use tenzro_device_key::envelope::RecoveryKey;

    let path = tenzro_types::paths::tenzro_home()
        .join("machine-root")
        .join("root.env");
    let sealed = SealedSecret::new(MACHINE_ROOT_LABEL, &path);

    if !sealed.exists() {
        use rand::RngCore;
        let mut secret = Zeroizing::new(vec![0u8; 32]);
        rand::thread_rng().fill_bytes(&mut secret);

        // The envelope refuses a single recipient by construction, so the root
        // needs a second. It is derived from the enclave's own signing key:
        // this is deliberately NOT a human recovery path. A machine root is
        // machine-bound by definition and is not meant to survive the machine —
        // inventing a recovery code the operator was never given would be worse
        // than none, because it would look like redundancy while providing it
        // only to the same enclave that already holds the primary.
        let ident = enclave_identity()?;
        let mut ikm = [0u8; 32];
        ikm.copy_from_slice(&sha2::Sha256::digest(ident)[..]);
        let companion = RecoveryKey::from_ikm(&ikm).map_err(|e| Error::Enclave(e.to_string()))?;

        sealed
            .enrol(&secret, companion.recipient(), false)
            .map_err(|e| Error::Enclave(format!("seal machine root: {e}")))?;
    }

    let out = sealed
        .open()
        .map_err(|e| Error::Enclave(format!("unseal machine root: {e}")))?;
    Ok(Zeroizing::new(out.to_vec()))
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn machine_root_ikm() -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::Unavailable(
        "the Secure Enclave machine root is only available on macOS and iOS".into(),
    ))
}

/// This machine's enclave signing public key, creating the key on first use.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn enclave_identity() -> Result<[u8; 64]> {
    match tenzro_device_key::backend_se::identity(MACHINE_ROOT_LABEL) {
        Ok(i) => Ok(i.signing),
        Err(_) => {
            // `false`: a machine root must be usable by a headless node, so it
            // is never gated behind user presence. There is nobody to answer a
            // Touch ID prompt on a server.
            tenzro_device_key::backend_se::create_with_presence(MACHINE_ROOT_LABEL, false)
                .map_err(|e| Error::Enclave(format!("create machine key: {e}")))?;
            tenzro_device_key::backend_se::identity(MACHINE_ROOT_LABEL)
                .map(|i| i.signing)
                .map_err(|e| Error::Enclave(format!("read machine identity: {e}")))
        }
    }
}

/// Which root this machine would use, if any.
pub fn machine_root_kind() -> Option<MachineRootKind> {
    available().then_some(MachineRootKind::SecureEnclave)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The enclave must never claim capabilities it does not have. This is the
    /// guard against an enclave-rooted node being recorded as TPM-attested.
    #[test]
    fn kind_reports_honest_capabilities() {
        assert!(!MachineRootKind::SecureEnclave.can_quote());
        assert!(!MachineRootKind::SecureEnclave.binds_measured_image());
        assert!(MachineRootKind::Tpm.can_quote());
        assert!(!MachineRootKind::Tpm.binds_measured_image());
    }

    /// `available()` must answer on every platform, not just Apple, so callers
    /// can probe unconditionally.
    #[test]
    fn availability_is_answerable_everywhere() {
        let a = available();
        assert_eq!(a, machine_root_kind().is_some());
    }

    /// Before this crate an Apple machine had no machine-identity root at all.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn apple_hardware_has_a_machine_root() {
        assert!(available(), "this Mac reports no Secure Enclave");
        assert_eq!(machine_root_kind(), Some(MachineRootKind::SecureEnclave));
    }

    /// A root that changes between calls is not a root — anything that recorded
    /// the derived public key would be left pointing at material nobody holds.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn machine_root_is_stable_across_calls() {
        let a = machine_root_ikm().expect("first read");
        let b = machine_root_ikm().expect("second read");
        assert_eq!(&a[..], &b[..], "machine root changed between calls");
        assert_eq!(a.len(), 32);
        assert!(a.iter().any(|x| *x != 0), "root must not be all zeroes");
    }

    /// On a non-Apple host the call must fail as Unavailable rather than
    /// fabricate a root — a fabricated one would seal against a placeholder.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn non_apple_refuses_rather_than_fabricates() {
        assert!(matches!(machine_root_ikm(), Err(Error::Unavailable(_))));
    }
}
