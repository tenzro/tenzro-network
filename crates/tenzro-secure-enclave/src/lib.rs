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
//! | **Machine** identity | TPM 2.0, or the Secure Enclave on Apple | `tenzro-device-key`, `tenzro-tee`'s TPM modules, **this crate** |
//! | **Confidential compute** | TEE attestation (SEV-SNP, TDX, Nitro, GPU CC) | `tenzro-tee` |
//!
//! `tenzro-tee` is the confidential-compute crate — secure inference, secure
//! training, ZK proving, and the attestation that makes them checkable. It is
//! not a custody layer. The TPM modules inside it are machine-root code that
//! predates the crates now responsible for that, and they are noted as such
//! where they sit.
//!
//! A TEE, a TPM and the Secure Enclave are **not** the same thing and this crate
//! does not pretend otherwise. A TEE attests that a *workload* runs unmodified
//! on trusted silicon; a TPM and the SEP attest that a *machine* holds a key
//! nobody can copy. Folding Apple support into the TEE crate would have implied
//! an equivalence that does not exist — hence a separate entity.
//!
//! # What the Secure Enclave gives, precisely
//!
//! A persistent, non-extractable P-256 key bound to this machine's SEP, reached
//! through CryptoKit so there are no keychain items to manage.
//!
//! This section used to say that came with **no Apple Developer Program
//! membership, no provisioning profile and no entitlements**, and that this is
//! what makes an Apple node permissionless. That is not Apple's position. DTS
//! (developer forums 786171) states the rule for the Secure Enclave itself
//! rather than for one framework: *"Access to the SE is the same as access to
//! the data protection keychain. In short: you need an App ID that's authorised
//! by a profile, and you need to be running in a user context."* An unsigned
//! build creating and reopening an SE key — measured, on an M2 — is incidental
//! success in unsupported territory that may stop at an OS update or a
//! signing-identity change. See [`tenzro_device_key`], which carries the full
//! correction and the four constraints behind it.
//!
//! Where macOS signing gets in the way, the machine has no hardware key it can
//! rely on, and it does not hold keys at all.
//!
//! # Where it is weaker than a TPM
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

/// Label of this machine's enclave key. The same key signs for the machine
/// and receives secrets sealed to it.
#[cfg(any(target_os = "macos", target_os = "ios"))]
const MACHINE_KEY_LABEL: &str = "tenzro-machine-key";

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

/// This machine's enclave signing public key (raw `x || y`), creating the key
/// on first use.
///
/// This is the machine's identity: a machine DID is derived from it, so the
/// identifier is a function of a key only this enclave holds, not of a stored
/// random value. The key is never gated behind user presence, because a
/// headless node has nobody to answer a Touch ID prompt.
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn machine_identity_key() -> Result<[u8; 64]> {
    open_or_create(&Enclave)
}

/// The enclave operations [`machine_identity_key`] needs.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
trait MachineKeyStore {
    /// The machine key's signing public key.
    fn identity(&self) -> std::result::Result<[u8; 64], Lookup>;
    /// Create the machine key.
    fn create(&self) -> std::result::Result<(), String>;
}

/// Why the machine key could not be read.
#[derive(Debug)]
#[cfg(any(target_os = "macos", target_os = "ios", test))]
enum Lookup {
    /// There is no machine key yet.
    Missing,
    /// The enclave did not answer: refused access, an OS or signing change,
    /// or any other failure. The key may well exist.
    Failed(String),
}

/// Read the machine key, creating it only when the enclave says there is
/// none. Any other failure is returned: creating a key then would hand the
/// machine a new identity while its existing one is merely unreachable.
#[cfg(any(target_os = "macos", target_os = "ios", test))]
fn open_or_create(store: &dyn MachineKeyStore) -> Result<[u8; 64]> {
    match store.identity() {
        Ok(key) => Ok(key),
        Err(Lookup::Failed(e)) => Err(Error::Enclave(format!("read machine identity: {e}"))),
        Err(Lookup::Missing) => {
            store
                .create()
                .map_err(|e| Error::Enclave(format!("create machine key: {e}")))?;
            store.identity().map_err(|e| {
                Error::Enclave(format!("read machine identity after creating it: {e:?}"))
            })
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
struct Enclave;

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl MachineKeyStore for Enclave {
    fn identity(&self) -> std::result::Result<[u8; 64], Lookup> {
        use tenzro_device_key::DeviceKeyError;
        tenzro_device_key::backend_se::identity(MACHINE_KEY_LABEL)
            .map(|i| i.signing)
            .map_err(|e| match e {
                DeviceKeyError::NotFound(_) => Lookup::Missing,
                other => Lookup::Failed(other.to_string()),
            })
    }

    fn create(&self) -> std::result::Result<(), String> {
        tenzro_device_key::backend_se::create_with_presence(MACHINE_KEY_LABEL, false)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn machine_identity_key() -> Result<[u8; 64]> {
    Err(Error::Unavailable(
        "the Secure Enclave is only available on macOS and iOS".into(),
    ))
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

    /// The identity key must not change between calls, or the DID derived from
    /// it would move.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn machine_identity_is_stable_across_calls() {
        let a = machine_identity_key().expect("first read");
        let b = machine_identity_key().expect("second read");
        assert_eq!(a, b, "machine identity key changed between calls");
    }

    /// A store whose key exists but cannot be read right now, or that has no
    /// key yet.
    struct Fake {
        key: Option<[u8; 64]>,
        refuse_reads: bool,
        created: std::cell::Cell<bool>,
    }

    impl MachineKeyStore for Fake {
        fn identity(&self) -> std::result::Result<[u8; 64], Lookup> {
            if self.refuse_reads {
                return Err(Lookup::Failed("access denied".into()));
            }
            match (self.key, self.created.get()) {
                (Some(k), _) => Ok(k),
                (None, true) => Ok([9u8; 64]),
                (None, false) => Err(Lookup::Missing),
            }
        }
        fn create(&self) -> std::result::Result<(), String> {
            self.created.set(true);
            Ok(())
        }
    }

    #[test]
    fn an_unreadable_key_is_an_error_not_a_new_identity() {
        let store = Fake {
            key: Some([1u8; 64]),
            refuse_reads: true,
            created: std::cell::Cell::new(false),
        };
        assert!(matches!(open_or_create(&store), Err(Error::Enclave(_))));
        assert!(
            !store.created.get(),
            "a key was created over an unreadable one"
        );
    }

    #[test]
    fn only_a_missing_key_is_created() {
        let missing = Fake {
            key: None,
            refuse_reads: false,
            created: std::cell::Cell::new(false),
        };
        assert_eq!(open_or_create(&missing).unwrap(), [9u8; 64]);
        assert!(missing.created.get());
        let present = Fake {
            key: Some([1u8; 64]),
            refuse_reads: false,
            created: std::cell::Cell::new(false),
        };
        assert_eq!(open_or_create(&present).unwrap(), [1u8; 64]);
        assert!(!present.created.get());
    }

    /// Off Apple hardware every call fails as Unavailable rather than invent a
    /// key.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    #[test]
    fn non_apple_refuses_rather_than_fabricates() {
        assert!(matches!(machine_identity_key(), Err(Error::Unavailable(_))));
    }
}
