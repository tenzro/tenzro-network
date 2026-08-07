//! Devices bound to a Tenzro identity, and what makes that binding worth
//! anything.
//!
//! A Tenzro identity links devices the way an Apple ID does — a phone, a
//! laptop, a machine — and each bound device can authenticate as that identity.
//! Unlike an Apple ID, the link is not a platform account. **Nothing here
//! trusts Apple, Google or Microsoft as an identity provider.** What is trusted
//! is a WebAuthn attestation: a signature, from a key the vendor put in
//! hardware, over a challenge we chose, verifiable against a vendor root we
//! pin. The platform is a conduit, not an authority.
//!
//! # A synced passkey is not a hardware-bound one
//!
//! WebAuthn's backup-eligibility bit (`BE`) says whether a credential *may* be
//! synced. `BE=0` means it cannot leave the device it was made on; `BE=1` means
//! the platform's password manager may replicate it to every device the user's
//! cloud account touches — at which point the credential proves control of an
//! *account*, not possession of a *device*.
//!
//! But `BE=0` alone is not proof of hardware either: it is a claim made by the
//! same software making every other claim. A software authenticator can report
//! `BE=0` truthfully and still keep the private key in a file. `BE` narrows
//! what a credential *is*; only [`AttestationEvidence`] establishes what
//! protects it.
//!
//! So the rule this module encodes has two halves, and both are required:
//!
//! 1. `BE=0` — the credential cannot be replicated off the device.
//! 2. An attestation, verified to a pinned vendor root, saying the key lives in
//!    a secure element or TEE.
//!
//! `BE=0 ∧ BS=1` is refused outright: a credential that cannot be backed up
//! cannot report itself as backed up, so a device claiming both is either
//! broken or lying, and neither is something to bind an identity to.
//!
//! # Phones do not expose serial numbers, and should not
//!
//! For a machine, [`crate::machine_id`] reads chipset and processor
//! identifiers. For a phone there is deliberately no equivalent: Apple and
//! Google both removed per-unit identifiers from application reach precisely so
//! that apps could not fingerprint users across installs.
//!
//! That is not a gap. **For a phone, the device identity *is* the attested
//! credential key** — a per-credential keypair the secure element generated and
//! will not export, whose attestation says which hardware holds it. It
//! identifies the device better than a serial would, because a serial can be
//! read and repeated by anything that has seen it once, while possession of the
//! key can only be demonstrated by the device that holds it.
//!
//! The [`Aaguid`] identifies the authenticator's *make and model*, and is
//! therefore [`crate::machine_id::IdentifierGrade::Model`]-grade: every Pixel 9
//! reports the same one. It is what policy is written against ("StrongBox-class
//! authenticators only"); it is never identity.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A device's authenticator make and model, as a WebAuthn AAGUID.
///
/// 128 bits, chosen by the vendor to be identical across substantially
/// identical authenticators — so it names a *model*, never a unit. Present only
/// in the registration attestation, never in a later assertion, which is why it
/// has to be captured when the device is bound and stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Aaguid(pub [u8; 16]);

impl Aaguid {
    /// The all-zero AAGUID.
    ///
    /// Reported by authenticators that decline to identify their model, which
    /// several platform providers have historically done for privacy. It means
    /// **unknown**, not *suspicious* — treating it as an alarm would reject a
    /// large share of legitimate platform authenticators.
    pub const ZERO: Aaguid = Aaguid([0u8; 16]);

    /// Whether the authenticator declined to name its model.
    pub fn is_unknown(&self) -> bool {
        *self == Aaguid::ZERO
    }

    /// Lowercase hex, for lookup against the FIDO Metadata Service.
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Display for Aaguid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// How well a device protects the key it authenticates with.
///
/// Ordered weakest to strongest so a policy can express a floor and `max()`
/// picks the best available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// The key is in software. It can be copied, and anything that copies it
    /// becomes the device.
    Software,
    /// The key is in a Trusted Execution Environment — Android TEE, a
    /// TrustZone-backed keystore. Isolated from the OS, but sharing the
    /// application processor.
    TrustedEnvironment,
    /// The key is in a discrete secure element with its own processor: Android
    /// StrongBox, an Apple Secure Enclave, a TPM, a security key.
    SecureElement,
}

impl KeyProtection {
    /// Whether a key at this level resists an attacker who owns the OS.
    ///
    /// This is the question that decides whether binding the device means
    /// anything: a software key on a rooted phone is readable, so the binding
    /// proves only that someone once had the file.
    pub fn is_hardware_backed(&self) -> bool {
        matches!(
            self,
            KeyProtection::TrustedEnvironment | KeyProtection::SecureElement
        )
    }

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            KeyProtection::Software => "software",
            KeyProtection::TrustedEnvironment => "trusted_environment",
            KeyProtection::SecureElement => "secure_element",
        }
    }
}

impl fmt::Display for KeyProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The WebAuthn attestation statement format a device presented.
///
/// Each is a different vendor's way of saying the same thing, and each chains
/// to a different pinned root. Modelled explicitly so a verifier cannot treat
/// an unverifiable format as though it had been verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationFormat {
    /// Android Keystore attestation. The certificate's KeyDescription extension
    /// carries the security level and the verified-boot state, chaining to the
    /// Google hardware attestation root.
    AndroidKey,
    /// Apple's anonymous attestation, from the Secure Enclave, chaining to the
    /// Apple root.
    Apple,
    /// TPM attestation — Windows Hello and any discrete TPM — carrying an
    /// attestation identity key certified by the TPM vendor.
    Tpm,
    /// The generic FIDO format. A security key or platform authenticator whose
    /// attestation certificate chains to a vendor root published in the FIDO
    /// Metadata Service.
    Packed,
    /// No attestation was supplied. The credential may still be perfectly good;
    /// nothing about the hardware holding it has been established.
    None,
}

impl AttestationFormat {
    /// Whether this format can carry a hardware claim at all.
    ///
    /// [`AttestationFormat::None`] cannot, which is why a device presenting it
    /// can be bound but never counted as hardware-bound.
    pub fn can_attest_hardware(&self) -> bool {
        !matches!(self, AttestationFormat::None)
    }

    /// Stable wire form, matching the WebAuthn `fmt` field.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttestationFormat::AndroidKey => "android-key",
            AttestationFormat::Apple => "apple",
            AttestationFormat::Tpm => "tpm",
            AttestationFormat::Packed => "packed",
            AttestationFormat::None => "none",
        }
    }

    /// Parse the WebAuthn `fmt` field. An unrecognised format is refused rather
    /// than mapped to `None`: silently downgrading an unknown attestation to
    /// "no attestation" would let a future format be accepted unverified.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "android-key" => Some(AttestationFormat::AndroidKey),
            "apple" => Some(AttestationFormat::Apple),
            "tpm" => Some(AttestationFormat::Tpm),
            "packed" => Some(AttestationFormat::Packed),
            "none" => Some(AttestationFormat::None),
            _ => None,
        }
    }
}

impl fmt::Display for AttestationFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a verified attestation established about the device.
///
/// Constructed only by a verifier that has actually checked the certificate
/// chain to a pinned root — the fields are what it concluded, not what the
/// device claimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationEvidence {
    /// The statement format that was verified.
    pub format: AttestationFormat,
    /// Where the credential's private key lives.
    pub protection: KeyProtection,
    /// Whether the attestation chain terminated at a root we pin — via the FIDO
    /// Metadata Service for `packed`, or the vendor root for the platform
    /// formats.
    ///
    /// `false` means the chain was present but did not verify, which is
    /// **weaker than absent**: something tried to look attested and failed.
    pub chain_verified: bool,
    /// For Android: whether the device reported a verified boot chain.
    ///
    /// `None` where the format does not carry it. Android's own guidance is
    /// that the software-enforced half of a KeyDescription is only trustworthy
    /// while the bootloader is locked, so an unverified boot state devalues
    /// everything the platform (rather than the secure hardware) asserted.
    pub verified_boot: Option<bool>,
}

impl AttestationEvidence {
    /// Whether this evidence supports treating the device as hardware-bound.
    ///
    /// All three of: a format that can carry a hardware claim, a chain that
    /// actually verified, and a protection level that resists an attacker who
    /// owns the OS. An unverified chain fails even when the claimed protection
    /// is `SecureElement` — an unchecked claim of a secure element is just a
    /// claim.
    pub fn proves_hardware(&self) -> bool {
        self.format.can_attest_hardware()
            && self.chain_verified
            && self.protection.is_hardware_backed()
    }
}

/// Why a device could not be bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingError {
    /// The credential may be replicated to other devices, so possessing it
    /// proves control of an account rather than of this device.
    Syncable,
    /// `BE=0` with `BS=1`: a credential that cannot be backed up reported that
    /// it is backed up.
    ContradictoryBackupFlags,
    /// No attestation, or one that did not verify to a pinned root.
    NotHardwareBacked {
        /// What the evidence actually showed.
        protection: KeyProtection,
        /// Whether a chain was presented and failed, as opposed to absent.
        chain_verified: bool,
    },
    /// The device reported an unlocked bootloader.
    BootChainUnverified,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syncable => write!(
                f,
                "this passkey is synced to a cloud account, so holding it proves control of that \
                 account rather than possession of this device. Create a device-bound passkey \
                 instead — on Android that is a StrongBox/TEE key, on Windows a Hello credential, \
                 or use a hardware security key"
            ),
            Self::ContradictoryBackupFlags => write!(
                f,
                "this authenticator reported that the credential cannot be backed up and that it \
                 is backed up. One of those is false, and an authenticator that misreports its \
                 own state is not one to bind an identity to"
            ),
            Self::NotHardwareBacked {
                protection,
                chain_verified,
            } => {
                if *chain_verified {
                    write!(
                        f,
                        "this device's passkey is protected at the '{protection}' level, which an \
                         attacker who controls the operating system can read. Binding it would \
                         prove only that someone once had the key file"
                    )
                } else {
                    write!(
                        f,
                        "this device's attestation did not verify against a known vendor root, so \
                         nothing has been established about the hardware holding its key. Tenzro \
                         verifies the hardware itself rather than trusting the platform account \
                         it came from"
                    )
                }
            }
            Self::BootChainUnverified => write!(
                f,
                "this device reported an unlocked bootloader, so the operating system making its \
                 claims cannot be trusted to make them honestly"
            ),
        }
    }
}

impl std::error::Error for BindingError {}

/// A device linked to a Tenzro identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundDevice {
    /// WebAuthn credential id, base64url — the handle this device is known by.
    pub credential_id: String,
    /// The identity this device can authenticate as.
    pub identity_did: String,
    /// Operator-facing label: "Alva's iPhone", "spark-0".
    pub label: String,
    /// Authenticator make and model. Model-grade, never identity.
    pub aaguid: Aaguid,
    /// Whether the credential may be replicated off this device. `false` is
    /// required for a hardware binding.
    pub backup_eligible: bool,
    /// Whether it is currently replicated. Can change over the credential's
    /// life, and is watched: a flip to backed-up means what was a device
    /// binding has become an account binding.
    pub backed_up: bool,
    /// What a verifier established about the hardware.
    pub attestation: AttestationEvidence,
    /// Signature counter from the last assertion.
    ///
    /// Meaningful **only** for a device-bound credential. Synced passkeys hold
    /// it at zero permanently, so clone detection built on it locks out exactly
    /// the users whose credentials are hardest to clone.
    pub sign_count: u32,
    /// When this device was bound, in milliseconds since the Unix epoch.
    pub bound_at_ms: u64,
}

impl BoundDevice {
    /// Whether this device's key is held in hardware that resists an attacker
    /// owning the OS, and cannot be replicated elsewhere.
    pub fn is_hardware_bound(&self) -> bool {
        !self.backup_eligible && self.attestation.proves_hardware()
    }

    /// Whether the signature counter is a usable clone signal for this device.
    ///
    /// Only for device-bound credentials, and only once the authenticator has
    /// actually moved it: a counter pinned at zero is an authenticator that
    /// does not implement it, not evidence of anything.
    pub fn sign_count_is_meaningful(&self) -> bool {
        !self.backup_eligible && self.sign_count > 0
    }

    /// Accept a new signature counter from an assertion.
    ///
    /// A counter that fails to advance on a device that was advancing it is the
    /// documented signal of a cloned credential. Returns `Err` with the
    /// offending value so the caller can refuse the assertion; the device is
    /// left untouched.
    pub fn advance_sign_count(&mut self, observed: u32) -> Result<(), u32> {
        if self.sign_count_is_meaningful() && observed <= self.sign_count {
            return Err(observed);
        }
        self.sign_count = observed;
        Ok(())
    }
}

/// What a relying party demands of a device before binding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingPolicy {
    /// Refuse credentials that may sync to a cloud account.
    pub require_device_bound: bool,
    /// The weakest key protection accepted.
    pub minimum_protection: KeyProtection,
    /// Refuse a device reporting an unlocked bootloader.
    pub require_verified_boot: bool,
}

impl Default for BindingPolicy {
    /// What binding a device to a Tenzro identity requires.
    ///
    /// Device-bound and hardware-backed, because the point of binding a device
    /// is that the device — not an account someone may have phished — is what
    /// authenticates. Verified boot is *not* required by default: it is absent
    /// on every non-Android format, so demanding it would reject every iPhone
    /// and every security key.
    fn default() -> Self {
        Self {
            require_device_bound: true,
            minimum_protection: KeyProtection::TrustedEnvironment,
            require_verified_boot: false,
        }
    }
}

impl BindingPolicy {
    /// Adjudicate a device against this policy.
    ///
    /// # Errors
    ///
    /// The first unmet requirement, so the message a user sees names one thing
    /// to fix rather than a list.
    pub fn admit(&self, device: &BoundDevice) -> Result<(), BindingError> {
        // Checked before anything else, and regardless of policy: an
        // authenticator that contradicts itself has disqualified its own
        // evidence, so there is nothing left to evaluate.
        if !device.backup_eligible && device.backed_up {
            return Err(BindingError::ContradictoryBackupFlags);
        }
        if self.require_device_bound && device.backup_eligible {
            return Err(BindingError::Syncable);
        }
        if device.attestation.protection < self.minimum_protection
            || !device.attestation.chain_verified
            || !device.attestation.format.can_attest_hardware()
        {
            return Err(BindingError::NotHardwareBacked {
                protection: device.attestation.protection,
                chain_verified: device.attestation.chain_verified,
            });
        }
        if self.require_verified_boot && device.attestation.verified_boot == Some(false) {
            return Err(BindingError::BootChainUnverified);
        }
        Ok(())
    }
}

/// An authenticated session: this identity, signed in from this bound device.
///
/// Distinct from the short-lived browser *ceremony* session that mints it. A
/// ceremony session is a ten-minute capability for completing one WebAuthn
/// exchange; this is the credential the user then carries.
///
/// # Every session names the device that authorised it
///
/// Not merely the identity. A session that recorded only "alice is signed in"
/// could not be revoked when Alice loses the phone that created it — you would
/// have to sign her out everywhere, including from the laptop still in her
/// hands. Naming the device makes "sign this phone out" expressible, and makes
/// unbinding a device sufficient to kill exactly the access it granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSession {
    /// Opaque session identifier.
    pub session_id: String,
    /// The identity this session acts as.
    pub identity_did: String,
    /// The bound device that authenticated it. The join key that makes
    /// device revocation and session revocation the same action.
    pub credential_id: String,
    /// When it was issued, in milliseconds since the Unix epoch.
    pub issued_at_ms: u64,
    /// When it stops being valid, regardless of anything else.
    pub expires_at_ms: u64,
    /// Whether it was explicitly ended before expiry.
    pub revoked: bool,
}

impl DeviceSession {
    /// Whether this session may still be used at `now_ms`.
    ///
    /// Expiry and revocation are checked together and neither is inferred from
    /// the other: a revoked session inside its window and an expired session
    /// never revoked are both unusable, and a caller that checked only one
    /// would honour the other.
    pub fn is_active(&self, now_ms: u64) -> bool {
        !self.revoked && now_ms < self.expires_at_ms
    }

    /// End this session now.
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// Whether this session was authorised by `credential_id`.
    pub fn was_authorised_by(&self, credential_id: &str) -> bool {
        self.credential_id == credential_id
    }
}

/// Revoke every session a device authorised, returning how many were ended.
///
/// The invariant that makes unbinding a device meaningful: a device whose
/// binding is gone must not leave live sessions behind, or "I lost my phone,
/// remove it" would remove the ability to sign in again while leaving the
/// thief's existing session working.
///
/// Already-revoked sessions are not counted again, so the return value is the
/// number of sessions this call actually ended.
pub fn revoke_sessions_for_device(sessions: &mut [DeviceSession], credential_id: &str) -> usize {
    sessions
        .iter_mut()
        .filter(|s| s.was_authorised_by(credential_id) && !s.revoked)
        .map(|s| s.revoke())
        .count()
}

/// The sessions of `identity_did` that may still be used at `now_ms`.
pub fn active_sessions<'a>(
    sessions: &'a [DeviceSession],
    identity_did: &str,
    now_ms: u64,
) -> Vec<&'a DeviceSession> {
    sessions
        .iter()
        .filter(|s| s.identity_did == identity_did && s.is_active(now_ms))
        .collect()
}

/// Why an identity may not yet create a wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletReadiness {
    /// Fewer than two devices are bound.
    NeedsSecondDevice {
        /// How many hardware-bound devices the identity currently has.
        bound: usize,
    },
    /// Two or more devices are bound, but they are all the machine the wallet
    /// would be created on.
    NeedsSeparateDevice,
    /// A device is bound, but not to hardware that can protect a key.
    NoHardwareBoundDevice,
}

impl fmt::Display for WalletReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // These are read by a user, so they are assembled from explicit
            // concatenated literals: a wrapped single literal folds its source
            // indentation into the message itself.
            Self::NeedsSecondDevice { bound } => write!(
                f,
                "a wallet needs a second device before it can be created — {bound} bound so far. \
                 This machine is the first. Scan the pairing QR code with your phone and \
                 authenticate with your passkey to bind it as the second"
            ),
            Self::NeedsSeparateDevice => write!(
                f,
                "every bound device is this same machine. The second device has to be a genuinely \
                 separate one — a phone, or another machine — or losing this one loses the wallet \
                 with it. Scan the pairing QR code with your phone and authenticate with your \
                 passkey"
            ),
            Self::NoHardwareBoundDevice => write!(
                f,
                "no bound device holds its key in hardware, so nothing here can protect a wallet. \
                 Bind a device whose passkey is device-bound and hardware-backed"
            ),
        }
    }
}

impl std::error::Error for WalletReadiness {}

/// Whether `identity_did` may create a wallet yet.
///
/// # Why a second device is required
///
/// A wallet held behind a single device is lost with that device. The first
/// device is the machine the user is already on — it was captured when they
/// started — so the requirement in practice is: bind a phone (or another
/// machine) before there is anything to lose.
///
/// The second device must be *separate*, not merely a second credential. Two
/// passkeys on one laptop are two ways into one box, and a laptop that dies
/// takes both. `this_machine_credential_id` names the credential belonging to
/// the machine asking, so a device that is only that machine again does not
/// count toward the requirement.
///
/// Only hardware-bound devices count. A syncable or software-backed credential
/// would make the second factor an account rather than a device, which is the
/// thing [`BindingPolicy`] exists to prevent.
///
/// # Errors
///
/// The specific reason, so the message names the one thing to do next.
pub fn wallet_readiness(
    devices: &[BoundDevice],
    identity_did: &str,
    this_machine_credential_id: Option<&str>,
) -> Result<(), WalletReadiness> {
    let mine: Vec<&BoundDevice> = devices
        .iter()
        .filter(|d| d.identity_did == identity_did)
        .collect();

    let hardware: Vec<&BoundDevice> = mine
        .iter()
        .copied()
        .filter(|d| d.is_hardware_bound())
        .collect();

    if hardware.is_empty() {
        return Err(WalletReadiness::NoHardwareBoundDevice);
    }
    if hardware.len() < 2 {
        return Err(WalletReadiness::NeedsSecondDevice {
            bound: hardware.len(),
        });
    }
    // Two or more, but they must not all be the machine asking.
    if let Some(this_machine) = this_machine_credential_id
        && hardware.iter().all(|d| d.credential_id == this_machine)
    {
        return Err(WalletReadiness::NeedsSeparateDevice);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(
        format: AttestationFormat,
        protection: KeyProtection,
        chain_verified: bool,
    ) -> AttestationEvidence {
        AttestationEvidence {
            format,
            protection,
            chain_verified,
            verified_boot: None,
        }
    }

    fn device(backup_eligible: bool, attestation: AttestationEvidence) -> BoundDevice {
        BoundDevice {
            credential_id: "cred".into(),
            identity_did: "did:tenzro:human:alice".into(),
            label: "Alice's phone".into(),
            aaguid: Aaguid([7u8; 16]),
            backup_eligible,
            backed_up: false,
            attestation,
            sign_count: 0,
            bound_at_ms: 1_700_000_000_000,
        }
    }

    /// The headline rule: a synced passkey proves control of a cloud account,
    /// not possession of a device.
    #[test]
    fn a_synced_passkey_cannot_be_hardware_bound() {
        let d = device(
            true,
            evidence(AttestationFormat::Apple, KeyProtection::SecureElement, true),
        );
        assert!(!d.is_hardware_bound());
        let err = BindingPolicy::default().admit(&d).expect_err("must refuse");
        assert!(matches!(err, BindingError::Syncable));
        assert!(err.to_string().contains("cloud account"), "{err}");
    }

    /// `BE=0` narrows what a credential is; it does not establish what protects
    /// it. A software authenticator can report `BE=0` truthfully.
    #[test]
    fn device_bound_alone_is_not_hardware_bound() {
        let d = device(
            false,
            evidence(AttestationFormat::Packed, KeyProtection::Software, true),
        );
        assert!(!d.is_hardware_bound());
        assert!(matches!(
            BindingPolicy::default().admit(&d),
            Err(BindingError::NotHardwareBacked { .. })
        ));
    }

    /// An unchecked claim of a secure element is just a claim.
    #[test]
    fn an_unverified_chain_fails_even_claiming_a_secure_element() {
        let d = device(
            false,
            evidence(
                AttestationFormat::AndroidKey,
                KeyProtection::SecureElement,
                false,
            ),
        );
        assert!(!d.is_hardware_bound());
        let err = BindingPolicy::default().admit(&d).expect_err("must refuse");
        // The message must say Tenzro checked the hardware rather than trusting
        // the platform the credential arrived from.
        assert!(err.to_string().contains("vendor root"), "{err}");
    }

    /// No attestation means nothing was established, however good the device
    /// might actually be.
    #[test]
    fn absent_attestation_never_counts_as_hardware() {
        let d = device(
            false,
            evidence(AttestationFormat::None, KeyProtection::SecureElement, true),
        );
        assert!(!d.is_hardware_bound());
        assert!(BindingPolicy::default().admit(&d).is_err());
    }

    #[test]
    fn a_device_bound_attested_secure_element_is_admitted() {
        for format in [
            AttestationFormat::AndroidKey,
            AttestationFormat::Apple,
            AttestationFormat::Tpm,
            AttestationFormat::Packed,
        ] {
            let d = device(false, evidence(format, KeyProtection::SecureElement, true));
            assert!(d.is_hardware_bound(), "{format} should bind");
            BindingPolicy::default().admit(&d).expect("admitted");
        }
    }

    /// An authenticator that contradicts itself has disqualified its own
    /// evidence — checked before anything else.
    #[test]
    fn contradictory_backup_flags_are_refused_first() {
        let mut d = device(
            false,
            evidence(AttestationFormat::Apple, KeyProtection::SecureElement, true),
        );
        d.backed_up = true;
        let err = BindingPolicy::default().admit(&d).expect_err("must refuse");
        assert!(matches!(err, BindingError::ContradictoryBackupFlags));
    }

    /// Android's software-enforced claims are only worth anything while the
    /// bootloader is locked.
    #[test]
    fn an_unlocked_bootloader_is_refused_when_the_policy_asks() {
        let mut d = device(
            false,
            evidence(
                AttestationFormat::AndroidKey,
                KeyProtection::SecureElement,
                true,
            ),
        );
        d.attestation.verified_boot = Some(false);

        // Default policy does not demand it — requiring it would reject every
        // iPhone and every security key, none of which report it.
        BindingPolicy::default().admit(&d).expect("default admits");

        let strict = BindingPolicy {
            require_verified_boot: true,
            ..BindingPolicy::default()
        };
        assert!(matches!(
            strict.admit(&d),
            Err(BindingError::BootChainUnverified)
        ));
    }

    /// Counter-based clone detection locks out synced-passkey users first,
    /// because their counter is permanently zero.
    #[test]
    fn the_sign_counter_is_only_a_signal_for_device_bound_credentials() {
        let mut synced = device(
            true,
            evidence(AttestationFormat::Apple, KeyProtection::SecureElement, true),
        );
        assert!(!synced.sign_count_is_meaningful());
        // A synced credential reporting zero forever must not be refused.
        synced.advance_sign_count(0).expect("no clone signal here");

        let mut bound = device(
            false,
            evidence(AttestationFormat::Tpm, KeyProtection::SecureElement, true),
        );
        bound.advance_sign_count(5).expect("first observation");
        assert!(bound.sign_count_is_meaningful());
        bound.advance_sign_count(6).expect("advancing is fine");
        // A counter that goes backwards is the documented clone signal.
        assert_eq!(bound.advance_sign_count(6), Err(6));
        assert_eq!(bound.sign_count, 6, "a refused assertion changes nothing");
    }

    /// A zero AAGUID is "unknown", not "suspicious" — several platform
    /// providers report it for privacy, and alarming on it would reject them.
    #[test]
    fn an_unknown_aaguid_does_not_block_binding() {
        let mut d = device(
            false,
            evidence(AttestationFormat::Apple, KeyProtection::SecureElement, true),
        );
        d.aaguid = Aaguid::ZERO;
        assert!(d.aaguid.is_unknown());
        BindingPolicy::default().admit(&d).expect("still admitted");
    }

    /// Protection levels order weakest to strongest so a policy floor works and
    /// `max()` picks the best available.
    #[test]
    fn protection_levels_are_ordered_and_only_the_top_two_are_hardware() {
        assert!(KeyProtection::Software < KeyProtection::TrustedEnvironment);
        assert!(KeyProtection::TrustedEnvironment < KeyProtection::SecureElement);
        assert!(!KeyProtection::Software.is_hardware_backed());
        assert!(KeyProtection::TrustedEnvironment.is_hardware_backed());
        assert!(KeyProtection::SecureElement.is_hardware_backed());
    }

    /// An unrecognised format must not be silently downgraded to "none", which
    /// would let a future format through unverified.
    #[test]
    fn wire_forms_round_trip_and_unknown_formats_are_refused() {
        for format in [
            AttestationFormat::AndroidKey,
            AttestationFormat::Apple,
            AttestationFormat::Tpm,
            AttestationFormat::Packed,
            AttestationFormat::None,
        ] {
            assert_eq!(AttestationFormat::parse(format.as_str()), Some(format));
        }
        assert_eq!(AttestationFormat::parse("android-safetynet"), None);
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn session(id: &str, credential_id: &str, expires_at_ms: u64) -> DeviceSession {
        DeviceSession {
            session_id: id.into(),
            identity_did: "did:tenzro:human:alice".into(),
            credential_id: credential_id.into(),
            issued_at_ms: 1_000,
            expires_at_ms,
            revoked: false,
        }
    }

    /// Expiry and revocation are independent reasons a session is unusable, and
    /// a caller checking only one would honour the other.
    #[test]
    fn a_session_needs_both_an_unexpired_window_and_no_revocation() {
        let live = session("s1", "cred-a", 5_000);
        assert!(live.is_active(4_999));
        assert!(!live.is_active(5_000), "expiry is exclusive");

        let mut revoked = session("s2", "cred-a", 5_000);
        revoked.revoke();
        assert!(!revoked.is_active(1_500), "revoked inside its window");
    }

    /// The invariant that makes "I lost my phone" work: removing the device
    /// must end the access it granted, not just the ability to sign in again.
    #[test]
    fn unbinding_a_device_ends_exactly_its_own_sessions() {
        let mut sessions = vec![
            session("phone-1", "cred-phone", 9_000),
            session("phone-2", "cred-phone", 9_000),
            session("laptop-1", "cred-laptop", 9_000),
        ];

        let ended = revoke_sessions_for_device(&mut sessions, "cred-phone");
        assert_eq!(ended, 2);

        let live = active_sessions(&sessions, "did:tenzro:human:alice", 1_500);
        assert_eq!(live.len(), 1, "the laptop in her hands stays signed in");
        assert_eq!(live[0].session_id, "laptop-1");
    }

    /// The count is what this call ended, so a repeated revoke does not inflate
    /// it and an operator reading the number is not misled.
    #[test]
    fn revoking_twice_reports_no_further_sessions_ended() {
        let mut sessions = vec![session("s1", "cred-a", 9_000)];
        assert_eq!(revoke_sessions_for_device(&mut sessions, "cred-a"), 1);
        assert_eq!(revoke_sessions_for_device(&mut sessions, "cred-a"), 0);
    }

    #[test]
    fn one_identitys_sessions_are_not_anothers() {
        let mut theirs = session("s2", "cred-b", 9_000);
        theirs.identity_did = "did:tenzro:agent:bob".into();
        let sessions = vec![session("s1", "cred-a", 9_000), theirs];

        assert_eq!(
            active_sessions(&sessions, "did:tenzro:human:alice", 1_500).len(),
            1
        );
        assert_eq!(
            active_sessions(&sessions, "did:tenzro:agent:bob", 1_500).len(),
            1
        );
    }

    #[test]
    fn an_expired_session_is_not_reported_active() {
        let sessions = vec![session("s1", "cred-a", 2_000)];
        assert!(active_sessions(&sessions, "did:tenzro:human:alice", 2_001).is_empty());
    }
}

#[cfg(test)]
mod wallet_gate_tests {
    use super::*;

    fn hardware_device(credential_id: &str) -> BoundDevice {
        BoundDevice {
            credential_id: credential_id.into(),
            identity_did: "did:tenzro:human:alice".into(),
            label: credential_id.into(),
            aaguid: Aaguid([1u8; 16]),
            backup_eligible: false,
            backed_up: false,
            attestation: AttestationEvidence {
                format: AttestationFormat::Apple,
                protection: KeyProtection::SecureElement,
                chain_verified: true,
                verified_boot: None,
            },
            sign_count: 0,
            bound_at_ms: 1_700_000_000_000,
        }
    }

    const ALICE: &str = "did:tenzro:human:alice";

    /// The machine the user is on is the first device. On its own it is not
    /// enough: a wallet behind one device is lost with that device.
    #[test]
    fn the_machine_alone_cannot_create_a_wallet() {
        let devices = vec![hardware_device("machine")];
        let err = wallet_readiness(&devices, ALICE, Some("machine")).expect_err("must refuse");
        assert_eq!(err, WalletReadiness::NeedsSecondDevice { bound: 1 });
        assert!(err.to_string().contains("QR code"), "{err}");
        assert!(err.to_string().contains("passkey"), "{err}");
    }

    /// A phone bound alongside the machine is what the requirement is for.
    #[test]
    fn a_phone_bound_alongside_the_machine_unlocks_wallet_creation() {
        let devices = vec![hardware_device("machine"), hardware_device("phone")];
        wallet_readiness(&devices, ALICE, Some("machine")).expect("two separate devices");
    }

    /// Two credentials on one laptop are two ways into one box, and the box
    /// dying takes both.
    #[test]
    fn a_second_credential_on_the_same_machine_does_not_count() {
        let devices = vec![hardware_device("machine"), hardware_device("machine")];
        let err = wallet_readiness(&devices, ALICE, Some("machine")).expect_err("must refuse");
        assert_eq!(err, WalletReadiness::NeedsSeparateDevice);
        assert!(err.to_string().contains("separate"), "{err}");
    }

    /// A synced passkey makes the second factor an account, not a device.
    #[test]
    fn a_synced_second_device_does_not_satisfy_the_requirement() {
        let mut phone = hardware_device("phone");
        phone.backup_eligible = true;
        let devices = vec![hardware_device("machine"), phone];
        assert_eq!(
            wallet_readiness(&devices, ALICE, Some("machine")),
            Err(WalletReadiness::NeedsSecondDevice { bound: 1 })
        );
    }

    #[test]
    fn a_software_only_device_cannot_protect_a_wallet_at_all() {
        let mut machine = hardware_device("machine");
        machine.attestation.protection = KeyProtection::Software;
        let err = wallet_readiness(&[machine], ALICE, Some("machine")).expect_err("must refuse");
        assert_eq!(err, WalletReadiness::NoHardwareBoundDevice);
    }

    /// Another identity's devices are not this identity's second factor.
    #[test]
    fn devices_bound_to_someone_else_do_not_count() {
        let mut bobs = hardware_device("bobs-phone");
        bobs.identity_did = "did:tenzro:human:bob".into();
        let devices = vec![hardware_device("machine"), bobs];
        assert_eq!(
            wallet_readiness(&devices, ALICE, Some("machine")),
            Err(WalletReadiness::NeedsSecondDevice { bound: 1 })
        );
    }

    /// Many devices may bind, and each of them authenticates.
    #[test]
    fn an_identity_may_bind_many_devices() {
        let devices = vec![
            hardware_device("machine"),
            hardware_device("phone"),
            hardware_device("tablet"),
            hardware_device("security-key"),
        ];
        wallet_readiness(&devices, ALICE, Some("machine")).expect("all bind, all authenticate");
    }
}
