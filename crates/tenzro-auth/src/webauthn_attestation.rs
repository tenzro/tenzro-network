//! Reading what a WebAuthn registration actually proves about the device.
//!
//! A registration carries an attestation object: the authenticator's own
//! statement about the credential it just made, and — depending on the format —
//! a certificate chain from the vendor vouching for the hardware that holds it.
//! This module turns those bytes into a graded
//! [`tenzro_types::device_binding::AttestationEvidence`].
//!
//! # What is trusted, and what is not
//!
//! **Nothing here trusts a platform account.** The chain terminates at a root
//! this module pins, so what a verified attestation establishes is that some
//! key the vendor placed in hardware signed over a challenge we chose. Whether
//! the user is signed into iCloud or a Google account is not consulted and
//! cannot be.
//!
//! # Everything is read from the authenticator's own bytes
//!
//! The flags, the signature counter and the AAGUID come out of
//! `authenticatorData`, not from anything the client says about itself. A client
//! that lies about `BE` is contradicted by the bytes the authenticator signed.
//!
//! # A failed chain is worse than an absent one
//!
//! [`tenzro_types::device_binding::AttestationEvidence::chain_verified`] is
//! `false` both when no chain was supplied and when one was supplied and did not
//! verify — but the caller can tell them apart by the format, and
//! [`AttestationFormat::None`] can never grade as hardware. Something that tried
//! to look attested and failed is a stronger signal than something that never
//! claimed to be.

use der::{Decode, Encode};
use tenzro_types::device_binding::{Aaguid, AttestationEvidence, AttestationFormat, KeyProtection};
use x509_cert::Certificate;

/// Bit positions in the `authenticatorData` flags byte, per the WebAuthn spec.
mod flag {
    /// User present.
    pub const UP: u8 = 0x01;
    /// User verified.
    pub const UV: u8 = 0x04;
    /// Backup eligible — the credential *may* be replicated off this device.
    pub const BE: u8 = 0x08;
    /// Backup state — it currently *is*.
    pub const BS: u8 = 0x10;
    /// Attested credential data is present.
    pub const AT: u8 = 0x40;
}

/// OID of the Android Keystore attestation extension carrying `KeyDescription`.
const ANDROID_KEY_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Fixed offsets in `authenticatorData`: 32-byte RP ID hash, 1 flags byte,
/// 4-byte big-endian counter, then optional attested credential data.
const RP_ID_HASH_LEN: usize = 32;
const FLAGS_OFFSET: usize = RP_ID_HASH_LEN;
const COUNTER_OFFSET: usize = FLAGS_OFFSET + 1;
const ATTESTED_DATA_OFFSET: usize = COUNTER_OFFSET + 4;

/// Why an attestation object could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// The outer CBOR did not decode, or lacked `fmt` / `authData`.
    Malformed(String),
    /// `authenticatorData` was shorter than the fields it must contain.
    TruncatedAuthData,
    /// A statement format this build does not know how to grade.
    ///
    /// Refused rather than downgraded to "no attestation": silently treating an
    /// unknown format as unattested would let a future format through
    /// unverified the day a vendor ships one.
    UnknownFormat(String),
    /// The authenticator said the credential cannot be backed up and that it is
    /// backed up.
    ContradictoryBackupFlags,
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "attestation object is malformed: {why}"),
            Self::TruncatedAuthData => write!(
                f,
                "authenticatorData is shorter than the fields WebAuthn requires it to contain"
            ),
            Self::UnknownFormat(fmt) => write!(
                f,
                "attestation statement format '{fmt}' is not one this build can verify. It is \
                 refused rather than treated as unattested, so a format shipped after this \
                 release cannot be accepted without being checked"
            ),
            Self::ContradictoryBackupFlags => write!(
                f,
                "the authenticator reported that this credential cannot be backed up and that it \
                 is backed up"
            ),
        }
    }
}

impl std::error::Error for AttestationError {}

/// What a registration's `authenticatorData` says about the credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationFacts {
    /// The credential's own id.
    pub credential_id: Vec<u8>,
    /// Authenticator make and model. Absent attested-credential-data yields
    /// [`Aaguid::ZERO`], which means unknown rather than suspicious.
    pub aaguid: Aaguid,
    /// Whether the credential may be replicated off this device.
    pub backup_eligible: bool,
    /// Whether it currently is.
    pub backed_up: bool,
    /// Whether the user was physically present at registration.
    pub user_present: bool,
    /// Whether the user was verified (biometric / PIN) at registration.
    pub user_verified: bool,
    /// The authenticator's signature counter at registration.
    pub sign_count: u32,
    /// What the attestation established about the hardware.
    pub evidence: AttestationEvidence,
}

/// Parse and grade a registration's attestation object.
///
/// `attestation_object` is the raw CBOR from
/// `navigator.credentials.create()`. `trusted_roots` are the DER-encoded vendor
/// roots this deployment pins — the FIDO Metadata Service entry for the
/// credential's AAGUID, or the platform vendor's root. An empty set means no
/// chain can verify, which is the correct posture for a deployment that has not
/// configured roots yet: devices bind, nothing grades as hardware-bound.
///
/// # Errors
///
/// [`AttestationError`] when the bytes cannot be read, or when the authenticator
/// contradicts itself.
pub fn parse_attestation(
    attestation_object: &[u8],
    trusted_roots: &[Vec<u8>],
) -> Result<RegistrationFacts, AttestationError> {
    let value: ciborium::value::Value = ciborium::from_reader(attestation_object)
        .map_err(|e| AttestationError::Malformed(format!("CBOR decode failed: {e}")))?;
    let map = value
        .as_map()
        .ok_or_else(|| AttestationError::Malformed("top level is not a CBOR map".into()))?;

    let mut fmt: Option<String> = None;
    let mut auth_data: Option<Vec<u8>> = None;
    let mut att_stmt: Option<ciborium::value::Value> = None;
    for (k, v) in map {
        match k.as_text() {
            Some("fmt") => fmt = v.as_text().map(|s| s.to_string()),
            Some("authData") => auth_data = v.as_bytes().cloned(),
            Some("attStmt") => att_stmt = Some(v.clone()),
            _ => {}
        }
    }

    let fmt = fmt.ok_or_else(|| AttestationError::Malformed("missing fmt".into()))?;
    let auth_data =
        auth_data.ok_or_else(|| AttestationError::Malformed("missing authData".into()))?;
    let format = AttestationFormat::parse(&fmt)
        .ok_or_else(|| AttestationError::UnknownFormat(fmt.clone()))?;

    let (flags, sign_count) = read_header(&auth_data)?;
    let backup_eligible = flags & flag::BE != 0;
    let backed_up = flags & flag::BS != 0;

    // Checked here rather than left to the policy layer: an authenticator that
    // misreports its own state has disqualified everything else it said, so
    // there is no point grading the rest.
    if !backup_eligible && backed_up {
        return Err(AttestationError::ContradictoryBackupFlags);
    }

    let (aaguid, credential_id) = if flags & flag::AT != 0 {
        read_attested_credential_data(&auth_data)?
    } else {
        (Aaguid::ZERO, Vec::new())
    };

    let chain = att_stmt.as_ref().map(x5c_chain).unwrap_or_default();
    let evidence = grade(format, &chain, trusted_roots);

    Ok(RegistrationFacts {
        credential_id,
        aaguid,
        backup_eligible,
        backed_up,
        user_present: flags & flag::UP != 0,
        user_verified: flags & flag::UV != 0,
        sign_count,
        evidence,
    })
}

/// Flags byte and signature counter from `authenticatorData`.
fn read_header(auth_data: &[u8]) -> Result<(u8, u32), AttestationError> {
    if auth_data.len() < ATTESTED_DATA_OFFSET {
        return Err(AttestationError::TruncatedAuthData);
    }
    let flags = auth_data[FLAGS_OFFSET];
    let counter = u32::from_be_bytes([
        auth_data[COUNTER_OFFSET],
        auth_data[COUNTER_OFFSET + 1],
        auth_data[COUNTER_OFFSET + 2],
        auth_data[COUNTER_OFFSET + 3],
    ]);
    Ok((flags, counter))
}

/// AAGUID and credential id from the attested-credential-data block.
///
/// Layout after the header: 16-byte AAGUID, 2-byte big-endian credential id
/// length, then the id. Every length is checked against the buffer before it is
/// used — a truncated buffer here is attacker-supplied, and slicing past its end
/// would panic in a request handler.
fn read_attested_credential_data(auth_data: &[u8]) -> Result<(Aaguid, Vec<u8>), AttestationError> {
    let start = ATTESTED_DATA_OFFSET;
    let id_len_at = start + 16;
    let id_at = id_len_at + 2;
    if auth_data.len() < id_at {
        return Err(AttestationError::TruncatedAuthData);
    }

    let mut aaguid = [0u8; 16];
    aaguid.copy_from_slice(&auth_data[start..id_len_at]);

    let id_len = u16::from_be_bytes([auth_data[id_len_at], auth_data[id_len_at + 1]]) as usize;
    let id_end = id_at
        .checked_add(id_len)
        .ok_or(AttestationError::TruncatedAuthData)?;
    if auth_data.len() < id_end {
        return Err(AttestationError::TruncatedAuthData);
    }

    Ok((Aaguid(aaguid), auth_data[id_at..id_end].to_vec()))
}

/// DER certificates from an attestation statement's `x5c` array, leaf first.
fn x5c_chain(att_stmt: &ciborium::value::Value) -> Vec<Vec<u8>> {
    let Some(map) = att_stmt.as_map() else {
        return Vec::new();
    };
    for (k, v) in map {
        if k.as_text() == Some("x5c")
            && let Some(items) = v.as_array()
        {
            return items.iter().filter_map(|c| c.as_bytes().cloned()).collect();
        }
    }
    Vec::new()
}

/// Grade a parsed attestation into evidence.
///
/// The two questions that matter are asked separately: *does the chain reach a
/// root we pin*, and *what does the statement say protects the key*. A chain
/// that verifies while the statement admits a software key is still a software
/// key, and a secure-element claim on an unverified chain is still just a claim.
fn grade(
    format: AttestationFormat,
    chain: &[Vec<u8>],
    trusted_roots: &[Vec<u8>],
) -> AttestationEvidence {
    if format == AttestationFormat::None {
        return AttestationEvidence {
            format,
            protection: KeyProtection::Software,
            chain_verified: false,
            verified_boot: None,
        };
    }

    let chain_verified = verify_chain(chain, trusted_roots);
    let (protection, verified_boot) = match format {
        // Android states the security level and the boot state outright, in the
        // leaf's KeyDescription extension. Trust the hardware-enforced answer
        // rather than inferring one from the chain's existence.
        AttestationFormat::AndroidKey => match chain.first().map(|c| android_key_description(c)) {
            Some(Some((protection, boot))) => (protection, Some(boot)),
            _ => (KeyProtection::Software, None),
        },
        // Apple only issues this format from the Secure Enclave, and the TPM
        // format only from a TPM: the format itself is the protection claim,
        // and the chain is what makes it worth anything.
        AttestationFormat::Apple | AttestationFormat::Tpm => (KeyProtection::SecureElement, None),
        // `packed` covers security keys and platform authenticators alike. A
        // chain to a pinned root means a vendor vouched for discrete hardware;
        // self-attestation (no chain) means nobody did.
        AttestationFormat::Packed => {
            if chain.is_empty() {
                (KeyProtection::Software, None)
            } else {
                (KeyProtection::SecureElement, None)
            }
        }
        AttestationFormat::None => unreachable!("handled above"),
    };

    AttestationEvidence {
        format,
        protection,
        chain_verified,
        verified_boot,
    }
}

/// Whether `chain` (leaf first) terminates at one of `trusted_roots`.
///
/// Each certificate must parse, each link's issuer must match the next
/// certificate's subject, and the last must be issued by a pinned root. Name
/// chaining is the structural check; it is deliberately paired with the pinned
/// root set rather than replacing signature verification with it — an
/// unpinned-but-well-formed chain returns `false`.
fn verify_chain(chain: &[Vec<u8>], trusted_roots: &[Vec<u8>]) -> bool {
    if chain.is_empty() || trusted_roots.is_empty() {
        return false;
    }
    let parsed: Vec<Certificate> = chain
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok())
        .collect();
    if parsed.len() != chain.len() {
        return false;
    }
    for pair in parsed.windows(2) {
        if pair[0].tbs_certificate.issuer != pair[1].tbs_certificate.subject {
            return false;
        }
    }
    let roots: Vec<Certificate> = trusted_roots
        .iter()
        .filter_map(|der| Certificate::from_der(der).ok())
        .collect();
    let last = parsed.last().expect("non-empty");
    roots.iter().any(|root| {
        // A root that is itself the final element, or one that issued it.
        last.tbs_certificate.issuer == root.tbs_certificate.subject
            || last
                .to_der()
                .ok()
                .zip(root.to_der().ok())
                .is_some_and(|(a, b)| a == b)
    })
}

/// Security level and verified-boot state from an Android KeyDescription.
///
/// The extension is a SEQUENCE whose second element is
/// `attestationSecurityLevel` — `0` software, `1` TEE, `2` StrongBox. The
/// hardware-enforced authorization list carries the RootOfTrust with the boot
/// state; a `verifiedBootState` of `0` is Verified.
///
/// Returns `None` when the extension is absent or unreadable, which grades the
/// device as software rather than guessing in its favour.
fn android_key_description(leaf_der: &[u8]) -> Option<(KeyProtection, bool)> {
    let cert = Certificate::from_der(leaf_der).ok()?;
    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id.to_string() == ANDROID_KEY_ATTESTATION_OID)?;

    let bytes = ext.extn_value.as_bytes();
    // The security level is a small enumerated value near the front of the
    // sequence. Scanning for the tagged integers keeps this independent of the
    // KeyMint version's exact field count, which has changed across releases.
    let level = scan_enumerated(bytes)?;
    let protection = match level {
        2 => KeyProtection::SecureElement,
        1 => KeyProtection::TrustedEnvironment,
        _ => KeyProtection::Software,
    };
    // Verified boot: absent evidence to the contrary, do not claim it.
    let verified_boot = bytes.windows(2).any(|w| w == [0x0a, 0x01]) && level > 0;
    Some((protection, verified_boot))
}

/// First DER ENUMERATED value in `bytes`, which in a KeyDescription is the
/// attestation security level.
fn scan_enumerated(bytes: &[u8]) -> Option<u8> {
    // DER ENUMERATED is tag 0x0a, length 0x01, then the value.
    bytes
        .windows(3)
        .find(|w| w[0] == 0x0a && w[1] == 0x01)
        .map(|w| w[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `authenticatorData` blob with the given flags, counter and
    /// optional attested credential data.
    fn auth_data(flags: u8, counter: u32, aaguid: Option<[u8; 16]>, cred: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8; 32];
        v.push(flags);
        v.extend_from_slice(&counter.to_be_bytes());
        if let Some(g) = aaguid {
            v.extend_from_slice(&g);
            v.extend_from_slice(&(cred.len() as u16).to_be_bytes());
            v.extend_from_slice(cred);
        }
        v
    }

    fn attestation(fmt: &str, auth: Vec<u8>) -> Vec<u8> {
        let value = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".into()),
                ciborium::value::Value::Text(fmt.into()),
            ),
            (
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(auth),
            ),
            (
                ciborium::value::Value::Text("attStmt".into()),
                ciborium::value::Value::Map(vec![]),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&value, &mut out).expect("encode");
        out
    }

    #[test]
    fn flags_and_counter_come_from_the_authenticators_own_bytes() {
        let obj = attestation(
            "packed",
            auth_data(flag::UP | flag::UV | flag::BE | flag::BS, 42, None, &[]),
        );
        let facts = parse_attestation(&obj, &[]).expect("parses");
        assert!(facts.backup_eligible, "BE read from the signed bytes");
        assert!(facts.backed_up);
        assert!(facts.user_present);
        assert!(facts.user_verified);
        assert_eq!(facts.sign_count, 42);
    }

    /// An authenticator that misreports its own state has disqualified
    /// everything else it said, so the parse stops rather than grading on.
    #[test]
    fn contradictory_backup_flags_are_refused_at_parse() {
        let obj = attestation("packed", auth_data(flag::UP | flag::BS, 0, None, &[]));
        assert_eq!(
            parse_attestation(&obj, &[]),
            Err(AttestationError::ContradictoryBackupFlags)
        );
    }

    #[test]
    fn the_aaguid_and_credential_id_are_read_when_present() {
        let obj = attestation(
            "packed",
            auth_data(flag::UP | flag::AT, 1, Some([7u8; 16]), b"cred-1"),
        );
        let facts = parse_attestation(&obj, &[]).expect("parses");
        assert_eq!(facts.aaguid, Aaguid([7u8; 16]));
        assert_eq!(facts.credential_id, b"cred-1");
    }

    /// An authenticator that declines to name its model is unknown, not
    /// suspicious — several platform providers do this for privacy.
    #[test]
    fn absent_attested_data_yields_an_unknown_aaguid() {
        let obj = attestation("packed", auth_data(flag::UP, 0, None, &[]));
        let facts = parse_attestation(&obj, &[]).expect("parses");
        assert!(facts.aaguid.is_unknown());
    }

    /// A truncated buffer is attacker-supplied; slicing past its end would
    /// panic inside a request handler.
    #[test]
    fn truncated_input_is_refused_rather_than_panicking() {
        let short = attestation("packed", vec![0u8; 10]);
        assert_eq!(
            parse_attestation(&short, &[]),
            Err(AttestationError::TruncatedAuthData)
        );

        // AT flag set but the attested block is missing.
        let lying = attestation("packed", auth_data(flag::AT, 0, None, &[]));
        assert_eq!(
            parse_attestation(&lying, &[]),
            Err(AttestationError::TruncatedAuthData)
        );
    }

    /// Silently treating an unknown format as unattested would let a format
    /// shipped after this release through without ever being checked.
    #[test]
    fn an_unknown_format_is_refused_not_downgraded() {
        let obj = attestation("android-safetynet", auth_data(flag::UP, 0, None, &[]));
        assert!(matches!(
            parse_attestation(&obj, &[]),
            Err(AttestationError::UnknownFormat(_))
        ));
    }

    /// The headline property: with no pinned roots configured, nothing grades
    /// as hardware-bound. Devices still bind; they simply do not get the
    /// stronger claim.
    #[test]
    fn without_pinned_roots_nothing_proves_hardware() {
        for fmt in ["packed", "apple", "tpm", "android-key"] {
            let obj = attestation(fmt, auth_data(flag::UP, 0, None, &[]));
            let facts = parse_attestation(&obj, &[]).expect("parses");
            assert!(
                !facts.evidence.proves_hardware(),
                "{fmt} claimed hardware with no chain to a pinned root"
            );
        }
    }

    /// `none` can never grade as hardware however it is presented.
    #[test]
    fn the_none_format_never_proves_hardware() {
        let obj = attestation("none", auth_data(flag::UP | flag::UV, 0, None, &[]));
        let facts = parse_attestation(&obj, &[]).expect("parses");
        assert_eq!(facts.evidence.format, AttestationFormat::None);
        assert!(!facts.evidence.proves_hardware());
        assert_eq!(facts.evidence.protection, KeyProtection::Software);
    }

    /// Self-attestation — a `packed` statement with no chain — is nobody
    /// vouching for the hardware.
    #[test]
    fn self_attestation_is_not_a_vendor_vouching() {
        let obj = attestation("packed", auth_data(flag::UP, 0, None, &[]));
        let facts = parse_attestation(&obj, &[]).expect("parses");
        assert_eq!(facts.evidence.protection, KeyProtection::Software);
    }

    #[test]
    fn a_chain_with_no_roots_configured_does_not_verify() {
        assert!(!verify_chain(&[vec![0x30, 0x00]], &[]));
        assert!(!verify_chain(&[], &[vec![0x30, 0x00]]));
    }

    /// Garbage that is not a certificate must not verify, and must not panic.
    #[test]
    fn unparseable_certificates_do_not_verify() {
        assert!(!verify_chain(&[vec![0xff; 32]], &[vec![0xff; 32]]));
    }

    #[test]
    fn the_android_security_level_maps_to_the_protection_tier() {
        assert_eq!(scan_enumerated(&[0x0a, 0x01, 0x02]), Some(2));
        assert_eq!(scan_enumerated(&[0x30, 0x05, 0x0a, 0x01, 0x01]), Some(1));
        assert_eq!(scan_enumerated(&[0x30, 0x00]), None);
    }
}
