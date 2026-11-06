//! AMD SEV-SNP attestation report verification.
//!
//! The report is signed (ECDSA P-384, SHA-384) by the chip's VCEK. The VCEK is
//! trusted only because:
//!
//! - it chains by signature VCEK -> ASK -> ARK, and the ARK is one of AMD's
//!   roots pinned in [`crate::certs`];
//! - its hardware-id extension equals the report's `CHIP_ID`, so a VCEK from
//!   another chip cannot vouch for this report. A report signed by a VLEK
//!   instead (`SIGNER_INFO` bit 2) is issued to a cloud provider for a fleet
//!   rather than to one chip, so it carries no hardware id and its `CHIP_ID`
//!   must be zero; `MASK_CHIP_KEY` is refused outright, since it detaches the
//!   report from any chip;
//! - its TCB extensions equal the report's `REPORTED_TCB`, so a VCEK issued at
//!   an older, patched-out TCB cannot vouch for a report claiming a newer one
//!   (or the reverse).
//!
//! On top of the signature: the guest policy's debug bit must be clear, the
//! report must come from VMPL 0 (the guest's most privileged level, not a
//! lower level a compromised guest kernel controls), the guest must not permit
//! a migration agent (`MIGRATE_MA`, or `AUTHOR_KEY_EN` in `SIGNER_INFO`) —
//! otherwise its state can be moved after the report is signed — and
//! `REPORT_DATA` must be the verifier's challenge. When the evidence carries AMD's CRL for the ASK,
//! the VCEK is checked against it.
//!
//! Evidence layout in an [`AttestationReport`]: `attestation_data` is the
//! 1184-byte report, `certificates` is `[VCEK, ASK]` in DER, and an optional
//! DER CRL is carried hex-encoded under [`CRL_KEY`].

use std::collections::BTreeMap;

use sha2::{Digest, Sha384};
use tenzro_types::tee::{AttestationReport, Measurement, TeeVendor};

use super::{VerifiedAttestation, VerifyPolicy, ct_eq, fail};
use crate::error::Result;
use crate::x509::{self, Cert};

/// Metadata key for an optional hex DER CRL issued by the ASK.
pub const CRL_KEY: &str = "snp_crl";

const REPORT_LEN: usize = 1184;
const SIGNED_LEN: usize = 0x2A0;
const OFF_VERSION: usize = 0x000;
const OFF_POLICY: usize = 0x008;
const OFF_VMPL: usize = 0x030;
const OFF_SIG_ALGO: usize = 0x034;
const OFF_REPORT_DATA: usize = 0x050;
const OFF_MEASUREMENT: usize = 0x090;
const OFF_HOST_DATA: usize = 0x0C0;
const OFF_REPORTED_TCB: usize = 0x180;
const OFF_CHIP_ID: usize = 0x1A0;
/// `SIGNER_INFO`: which key signed, and whether the guest may be migrated.
const OFF_SIGNER_INFO: usize = 0x048;
const OFF_SIG_R: usize = 0x2A0;
const OFF_SIG_S: usize = 0x2E8;

/// Guest policy bit that allows the hypervisor to debug the guest.
const POLICY_DEBUG: u64 = 1 << 19;
/// Guest policy bit permitting association with a migration agent.
const POLICY_MIGRATE_MA: u64 = 1 << 18;
/// `SIGNER_INFO` bit 2: the report was signed by a VLEK rather than a VCEK.
const SIGNING_KEY_VLEK: u32 = 1 << 2;
/// `SIGNER_INFO` bit 0: the guest is associated with a migration agent.
const SIGNER_INFO_AUTHOR_KEY_EN: u32 = 1;
/// `SIGNER_INFO` bit 1: the guest has a migration agent.
const SIGNER_INFO_MASK_CHIP_KEY: u32 = 1 << 1;
/// ECDSA P-384 with SHA-384, the only signature algorithm reports use.
const SIG_ALGO_ECDSA_P384_SHA384: u32 = 1;

const OID_HWID: &str = "1.3.6.1.4.1.3704.1.4";
const OID_BL_SPL: &str = "1.3.6.1.4.1.3704.1.3.1";
const OID_TEE_SPL: &str = "1.3.6.1.4.1.3704.1.3.2";
const OID_SNP_SPL: &str = "1.3.6.1.4.1.3704.1.3.3";
const OID_UCODE_SPL: &str = "1.3.6.1.4.1.3704.1.3.8";

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// AMD's ARKs, parsed once per call. These are the only SEV-SNP roots.
///
/// Milan and Genoa. Turin is not among them, so a Turin host is refused here
/// rather than checked against a root that did not issue its chain — see
/// [`crate::certs::get_amd_ark_for_product`].
fn amd_roots() -> Result<Vec<Cert>> {
    [
        crate::certs::AMD_ARK_MILAN_PEM,
        crate::certs::AMD_ARK_GENOA_PEM,
    ]
    .iter()
    .map(|pem| x509::parse_pem_chain(pem).map(|mut v| v.remove(0)))
    .collect()
}

/// Compare a VCEK extension value with the bytes the report states, accepting
/// the encodings AMD uses: raw bytes, a DER OCTET STRING, or a DER INTEGER.
fn extension_equals(value: &[u8], expected: &[u8]) -> bool {
    match value.first() {
        Some(0x04) if value.len() >= 2 && value[1] as usize == value.len() - 2 => {
            value[2..] == *expected
        }
        Some(0x02) if value.len() >= 3 && value[1] as usize == value.len() - 2 => {
            // A single-byte SPL is encoded as INTEGER, possibly with a leading
            // zero to keep it positive.
            let digits = &value[2..];
            let digits = if digits.len() > 1 && digits[0] == 0 {
                &digits[1..]
            } else {
                digits
            };
            digits == expected
        }
        _ => value == expected,
    }
}

pub fn verify(report: &AttestationReport, policy: &VerifyPolicy) -> Result<VerifiedAttestation> {
    let crl = report
        .metadata
        .get(CRL_KEY)
        .map(|h| hex::decode(h).map_err(|e| fail(format!("SNP CRL hex: {e}"))))
        .transpose()?;
    verify_with_roots(
        &report.attestation_data,
        &report.certificates,
        crl.as_deref(),
        &amd_roots()?,
        policy,
    )
}

/// Verify a raw report with its `[VCEK, ASK]` chain against `roots`.
pub fn verify_with_roots(
    raw: &[u8],
    chain_der: &[Vec<u8>],
    crl: Option<&[u8]>,
    roots: &[Cert],
    policy: &VerifyPolicy,
) -> Result<VerifiedAttestation> {
    if raw.len() != REPORT_LEN {
        return Err(fail(format!(
            "SNP report is {} bytes, not {REPORT_LEN}",
            raw.len()
        )));
    }
    let version = u32_at(raw, OFF_VERSION);
    if !(2..=5).contains(&version) {
        return Err(fail(format!("unsupported SNP report version {version}")));
    }
    if u32_at(raw, OFF_SIG_ALGO) != SIG_ALGO_ECDSA_P384_SHA384 {
        return Err(fail("SNP report is not signed with ECDSA P-384"));
    }

    let chain: Vec<Cert> = chain_der
        .iter()
        .map(|d| x509::parse(d))
        .collect::<Result<_>>()?;
    let vcek = chain
        .first()
        .ok_or_else(|| fail("SNP evidence carries no VCEK"))?;
    x509::verify_chain(&chain, roots, policy.now)?;
    if let Some(crl) = crl {
        let ask = chain
            .get(1)
            .ok_or_else(|| fail("a CRL needs the ASK to check it"))?;
        x509::check_not_revoked(vcek, crl, ask, policy.now)?;
    }

    // Which key signed decides what the chain proves. A VCEK is issued to one
    // chip and its hardware-id extension is what binds the report to that
    // chip. A VLEK is issued to a cloud provider for a whole fleet, so it
    // carries no hardware id and a report signed by one says "some chip of
    // this provider's", not "this chip". Checking a VLEK-signed report as
    // though it were VCEK-signed would fail on the missing extension; not
    // checking at all would let a VLEK stand in for a chip-bound claim.
    let signer_info = u32_at(raw, OFF_SIGNER_INFO);
    let signed_by_vlek = signer_info & SIGNING_KEY_VLEK != 0;
    if signer_info & SIGNER_INFO_MASK_CHIP_KEY != 0 {
        return Err(fail(
            "SNP report was produced with MASK_CHIP_KEY, so it is not bound to a chip",
        ));
    }
    let chip_id = &raw[OFF_CHIP_ID..OFF_CHIP_ID + 64];
    if signed_by_vlek {
        // A VLEK-signed report's CHIP_ID is zeroed by the firmware. A
        // non-zero one means the evidence does not match how it was signed.
        if chip_id.iter().any(|b| *b != 0) {
            return Err(fail("a VLEK-signed report must not carry a chip id"));
        }
    } else {
        let hwid = vcek
            .extension(OID_HWID)
            .ok_or_else(|| fail("VCEK has no hardware-id extension"))?;
        if !extension_equals(hwid, chip_id) {
            return Err(fail("VCEK was issued for a different chip"));
        }
    }
    let tcb = u64_at(raw, OFF_REPORTED_TCB).to_le_bytes();
    for (oid, byte, name) in [
        (OID_BL_SPL, tcb[0], "bootloader"),
        (OID_TEE_SPL, tcb[1], "TEE"),
        (OID_SNP_SPL, tcb[6], "SNP"),
        (OID_UCODE_SPL, tcb[7], "microcode"),
    ] {
        let v = vcek
            .extension(oid)
            .ok_or_else(|| fail(format!("VCEK has no {name} TCB extension")))?;
        if !extension_equals(v, &[byte]) {
            return Err(fail(format!("VCEK {name} TCB does not match the report")));
        }
    }

    // r and s are little-endian in 72-byte fields; P-384 uses the low 48.
    let mut sig = [0u8; 96];
    for (i, b) in raw[OFF_SIG_R..OFF_SIG_R + 48].iter().rev().enumerate() {
        sig[i] = *b;
    }
    for (i, b) in raw[OFF_SIG_S..OFF_SIG_S + 48].iter().rev().enumerate() {
        sig[48 + i] = *b;
    }
    let digest = Sha384::digest(&raw[..SIGNED_LEN]);
    x509::verify_ecdsa_prehash(&vcek.spki_der, &digest, &sig)
        .map_err(|_| fail("SNP report signature does not verify under the VCEK"))?;

    let guest_policy = u64_at(raw, OFF_POLICY);
    if guest_policy & POLICY_DEBUG != 0 {
        return Err(fail("SNP guest policy allows debugging"));
    }
    // A guest that may be associated with a migration agent can have its
    // state moved by that agent, so the measurement this report vouches for
    // is not necessarily the state still running. The attestation would stay
    // valid across a migration it says nothing about.
    if guest_policy & POLICY_MIGRATE_MA != 0 || signer_info & SIGNER_INFO_AUTHOR_KEY_EN != 0 {
        return Err(fail(
            "SNP guest permits a migration agent, so the report does not bind the running state",
        ));
    }
    if u32_at(raw, OFF_VMPL) != 0 {
        return Err(fail("SNP report was not requested at VMPL 0"));
    }
    let report_data = &raw[OFF_REPORT_DATA..OFF_REPORT_DATA + 64];
    if !ct_eq(report_data, &policy.expected_user_data) {
        return Err(fail("SNP report data does not answer this challenge"));
    }

    let measurement = raw[OFF_MEASUREMENT..OFF_MEASUREMENT + 48].to_vec();
    let mut details = BTreeMap::new();
    details.insert("policy".into(), format!("0x{guest_policy:x}"));
    details.insert(
        "host_data".into(),
        hex::encode(&raw[OFF_HOST_DATA..OFF_HOST_DATA + 32]),
    );
    details.insert("reported_tcb".into(), hex::encode(tcb));
    Ok(VerifiedAttestation {
        vendor: TeeVendor::AmdSevSnp,
        measurements: vec![Measurement {
            index: 0,
            algorithm: "SHA384".into(),
            value: measurement.clone(),
            register: "MEASUREMENT".into(),
            description: None,
        }],
        measurement,
        user_data: report_data.to_vec(),
        tcb_status: "VcekMatchesReportedTcb".into(),
        platform_id: chip_id.to_vec(),
        details,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    //! Reports here are built to the SEV-SNP ABI layout and signed with a
    //! P-384 key whose certificate a test CA issues, with AMD's extensions.
    //! The pinned AMD chain itself is checked separately against the real
    //! Milan ARK and ASK.

    use super::*;
    use crate::x509::testca;
    use p384::ecdsa::signature::hazmat::PrehashSigner;
    use spki::EncodePublicKey;

    pub(crate) const NOW: u64 = 1_800_000_000;

    pub(crate) fn vcek_key() -> p384::ecdsa::SigningKey {
        p384::ecdsa::SigningKey::from_slice(&[0x33; 48]).unwrap()
    }

    fn der_int(v: u8) -> Vec<u8> {
        if v >= 0x80 {
            vec![0x02, 0x02, 0x00, v]
        } else {
            vec![0x02, 0x01, v]
        }
    }

    pub(crate) fn chain(chip: [u8; 64], tcb: [u8; 8]) -> (Cert, Vec<Vec<u8>>) {
        let ark_k = testca::key(50);
        let ask_k = testca::key(51);
        let ark = testca::issue("ARK-Test", &ark_k, "ARK-Test", &ark_k, true, 1);
        let ask = testca::issue("SEV-Test", &ask_k, "ARK-Test", &ark_k, true, 2);
        let mut hwid = vec![0x04, 0x40];
        hwid.extend_from_slice(&chip);
        let spki = vcek_key().verifying_key().to_public_key_der().unwrap();
        let vcek = testca::issue_with_spki(
            "SEV-VCEK",
            spki.as_bytes(),
            "SEV-Test",
            &ask_k,
            false,
            3,
            (1_000_000_000, 4_000_000_000),
            &[
                (OID_HWID, hwid),
                (OID_BL_SPL, der_int(tcb[0])),
                (OID_TEE_SPL, der_int(tcb[1])),
                (OID_SNP_SPL, der_int(tcb[6])),
                (OID_UCODE_SPL, der_int(tcb[7])),
            ],
        );
        (x509::parse(&ark).unwrap(), vec![vcek, ask])
    }

    pub(crate) fn report(
        report_data: &[u8; 64],
        policy: u64,
        vmpl: u32,
        chip: [u8; 64],
        tcb: [u8; 8],
    ) -> Vec<u8> {
        report_signed(report_data, policy, vmpl, chip, tcb, 0)
    }

    pub(crate) fn report_signed(
        report_data: &[u8; 64],
        policy: u64,
        vmpl: u32,
        chip: [u8; 64],
        tcb: [u8; 8],
        signer_info: u32,
    ) -> Vec<u8> {
        let mut r = vec![0u8; REPORT_LEN];
        r[OFF_SIGNER_INFO..OFF_SIGNER_INFO + 4].copy_from_slice(&signer_info.to_le_bytes());
        r[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&3u32.to_le_bytes());
        r[OFF_POLICY..OFF_POLICY + 8].copy_from_slice(&policy.to_le_bytes());
        r[OFF_VMPL..OFF_VMPL + 4].copy_from_slice(&vmpl.to_le_bytes());
        r[OFF_SIG_ALGO..OFF_SIG_ALGO + 4].copy_from_slice(&1u32.to_le_bytes());
        r[OFF_REPORT_DATA..OFF_REPORT_DATA + 64].copy_from_slice(report_data);
        r[OFF_MEASUREMENT..OFF_MEASUREMENT + 48].copy_from_slice(&[0x5A; 48]);
        r[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8].copy_from_slice(&tcb);
        r[OFF_CHIP_ID..OFF_CHIP_ID + 64].copy_from_slice(&chip);
        sign(&mut r, &vcek_key());
        r
    }

    fn sign(r: &mut [u8], key: &p384::ecdsa::SigningKey) {
        let digest = Sha384::digest(&r[..SIGNED_LEN]);
        let sig: p384::ecdsa::Signature = key.sign_prehash(&digest).unwrap();
        let b = sig.to_bytes();
        for i in 0..48 {
            r[OFF_SIG_R + i] = b[47 - i];
            r[OFF_SIG_S + i] = b[95 - i];
        }
    }

    const CHIP: [u8; 64] = [0xC1; 64];
    const TCB: [u8; 8] = [3, 0, 0, 0, 0, 0, 14, 209];

    fn policy() -> VerifyPolicy {
        VerifyPolicy {
            now: NOW,
            expected_user_data: vec![7; 64],
            max_age_secs: 600,
            nvidia_jwks: None,
        }
    }

    #[test]
    fn a_genuine_report_verifies() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report(&[7; 64], 0x30000, 0, CHIP, TCB);
        let v = verify_with_roots(&r, &chain, None, &[ark], &policy()).unwrap();
        assert_eq!(v.platform_id, CHIP.to_vec());
        assert_eq!(v.measurement, vec![0x5A; 48]);
    }

    #[test]
    fn a_report_signed_by_an_attacker_key_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let mut r = report(&[7; 64], 0x30000, 0, CHIP, TCB);
        sign(
            &mut r,
            &p384::ecdsa::SigningKey::from_slice(&[0x44; 48]).unwrap(),
        );
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    #[test]
    fn a_vcek_for_another_chip_is_refused() {
        let (ark, chain) = chain([0xD2; 64], TCB);
        let r = report(&[7; 64], 0x30000, 0, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    #[test]
    fn a_vcek_at_another_tcb_is_refused() {
        let (ark, chain) = chain(CHIP, [3, 0, 0, 0, 0, 0, 13, 209]);
        let r = report(&[7; 64], 0x30000, 0, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    #[test]
    fn a_debuggable_guest_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report(&[7; 64], 0x30000 | POLICY_DEBUG, 0, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    #[test]
    fn a_report_from_a_lower_vmpl_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report(&[7; 64], 0x30000, 2, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    /// A guest that may be handed to a migration agent can have its state
    /// moved after the report is signed, so the report stops describing what
    /// is running while still verifying.
    #[test]
    fn a_migratable_guest_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report(&[7; 64], 0x30000 | POLICY_MIGRATE_MA, 0, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());

        let (ark, certs) = self::chain(CHIP, TCB);
        let r = report_signed(&[7; 64], 0x30000, 0, CHIP, TCB, SIGNER_INFO_AUTHOR_KEY_EN);
        assert!(verify_with_roots(&r, &certs, None, &[ark], &policy()).is_err());
    }

    /// `MASK_CHIP_KEY` detaches the report from the chip entirely, so nothing
    /// is left for the certificate to bind it to.
    #[test]
    fn a_masked_chip_key_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report_signed(&[7; 64], 0x30000, 0, CHIP, TCB, SIGNER_INFO_MASK_CHIP_KEY);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    /// A VLEK is issued to a provider for a fleet, so it has no hardware id
    /// and its report must not claim a chip. Checking the chip extension on
    /// one would reject every legitimate VLEK report; skipping the check
    /// without noticing the key type would let a fleet key answer a
    /// chip-bound question.
    #[test]
    fn a_vlek_signed_report_carries_no_chip_id() {
        // A VLEK-signed report that still names a chip is refused.
        let (ark, chain) = chain(CHIP, TCB);
        let r = report_signed(&[7; 64], 0x30000, 0, CHIP, TCB, SIGNING_KEY_VLEK);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());

        // With a zero chip id it verifies, and the certificate needs no
        // hardware-id extension.
        let ark_k = testca::key(60);
        let ask_k = testca::key(61);
        let ark_der = testca::issue("ARK-Test", &ark_k, "ARK-Test", &ark_k, true, 1);
        let ask = testca::issue("SEV-Test", &ask_k, "ARK-Test", &ark_k, true, 2);
        let spki = vcek_key().verifying_key().to_public_key_der().unwrap();
        let vlek = testca::issue_with_spki(
            "SEV-VLEK",
            spki.as_bytes(),
            "SEV-Test",
            &ask_k,
            false,
            3,
            (1_000_000_000, 4_000_000_000),
            &[
                (OID_BL_SPL, der_int(TCB[0])),
                (OID_TEE_SPL, der_int(TCB[1])),
                (OID_SNP_SPL, der_int(TCB[6])),
                (OID_UCODE_SPL, der_int(TCB[7])),
            ],
        );
        let r = report_signed(&[7; 64], 0x30000, 0, [0u8; 64], TCB, SIGNING_KEY_VLEK);
        let v = verify_with_roots(
            &r,
            &[vlek, ask],
            None,
            &[x509::parse(&ark_der).unwrap()],
            &policy(),
        )
        .unwrap();
        assert_eq!(v.platform_id, vec![0u8; 64]);
    }

    #[test]
    fn a_report_answering_another_challenge_is_refused() {
        let (ark, chain) = chain(CHIP, TCB);
        let r = report(&[8; 64], 0x30000, 0, CHIP, TCB);
        assert!(verify_with_roots(&r, &chain, None, &[ark], &policy()).is_err());
    }

    #[test]
    fn a_chain_to_an_unpinned_root_is_refused_by_the_production_path() {
        let (_ark, chain) = chain(CHIP, TCB);
        let report = AttestationReport {
            vendor: TeeVendor::AmdSevSnp,
            attestation_data: super::tests::report(&[7; 64], 0x30000, 0, CHIP, TCB),
            certificates: chain,
            ..Default::default()
        };
        assert!(verify(&report, &policy()).is_err());
    }

    #[test]
    fn the_pinned_milan_ask_is_signed_by_the_pinned_milan_ark() {
        let ark = x509::parse_pem_chain(crate::certs::AMD_ARK_MILAN_PEM).unwrap();
        let ask = x509::parse_pem_chain(crate::certs::AMD_ASK_MILAN_PEM).unwrap();
        let now = ask[0].not_before + 1;
        assert_eq!(x509::verify_chain(&ask, &ark, now).unwrap(), 0);
        let genoa = x509::parse_pem_chain(crate::certs::AMD_ARK_GENOA_PEM).unwrap();
        assert!(x509::verify_chain(&ask, &genoa, now).is_err());
    }
}
