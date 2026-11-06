//! An NVIDIA GPU's own proof of identity: its per-device certificate chain
//! to NVIDIA's published device identity root, and an SPDM measurement
//! report the device signed over a verifier's nonce.
//!
//! Every NVIDIA GPU that supports attestation (Hopper onward) carries a
//! device identity key provisioned at manufacture and certified by NVIDIA
//! (the `GSP BROM` certificate, issued through a provisioner CA under the
//! `NVIDIA Device Identity CA` root), and an alias key for its firmware
//! certified by that device key. Asked for measurements with a requester
//! nonce, the device answers an SPDM `GET_MEASUREMENTS` with a response
//! signed by the alias key over the whole exchange: the request (with the
//! nonce) and the response. Verifying the signature, the chain and the nonce
//! shows a genuine NVIDIA device answered this nonce now. The root is the
//! one NVIDIA publishes for offline verification; no NVIDIA service is
//! asked anything.
//!
//! [`check_reference_values`] compares the report's measurements with the
//! reference values NVIDIA publishes for its firmware and drivers. Revocation,
//! which NVIDIA publishes by OCSP, is an online question asked apart from
//! verification ([`crate::ocsp`]). Confidential-compute mode is not required.
//!
//! Wire layout (DMTF DSP0274, SPDM 1.1 and 1.2): the request is
//! `version, 0xE0, param1, param2, nonce[32], slot_id`; the response is
//! `version, 0x60, param1, param2, number_of_blocks, record_length (u24 LE),
//! record, nonce[32], opaque_length (u16 LE), opaque, signature`. The
//! signature is ECDSA, raw `r || s` on the alias key's curve (P-384 on every
//! NVIDIA device), over SHA-384 of the request and the response up to the
//! signature.

use sha2::{Digest, Sha256, Sha384};

use crate::error::{Result, TeeError};
use crate::x509::{self, Cert};

fn fail(msg: impl Into<String>) -> TeeError {
    TeeError::AttestationVerificationFailed(msg.into())
}

const GET_MEASUREMENTS: u8 = 0xE0;
const MEASUREMENTS: u8 = 0x60;
const REQUEST_LEN: usize = 37;
/// Most bytes a report may carry.
pub const MAX_REPORT_BYTES: usize = 0x2000;
/// Most certificates a device chain may carry.
pub const MAX_CHAIN_CERTS: usize = 8;

/// What a verified device report shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGpuDevice {
    /// SHA-256 of the device identity certificate's public key, hex: the
    /// certificate directly above the firmware alias certificate, provisioned
    /// once per chip. One device is one GPU, whatever firmware it runs.
    pub device_id: String,
    /// Subject of the alias certificate that signed the report (DER).
    pub signer_subject: Vec<u8>,
}

/// Verify that `report` (SPDM request then response, as NVML returns it) was
/// signed by the device whose certificate chain is `chain` (leaf first),
/// that the chain ends at one of `roots` at unix time `now`, and that the
/// request carried `nonce`.
pub fn verify_device_report(
    report: &[u8],
    chain: &[Cert],
    roots: &[Cert],
    now: u64,
    nonce: &[u8; 32],
) -> Result<VerifiedGpuDevice> {
    if report.len() > MAX_REPORT_BYTES {
        return Err(fail(
            "the device report is longer than any SPDM report NVML returns",
        ));
    }
    if chain.len() < 2 || chain.len() > MAX_CHAIN_CERTS {
        return Err(fail(
            "a device chain has the alias certificate, the device certificate and their issuers",
        ));
    }
    let request = report
        .get(..REQUEST_LEN)
        .ok_or_else(|| fail("the report is shorter than a GET_MEASUREMENTS request"))?;
    let version = request[0];
    if !(0x11..=0x12).contains(&version) {
        return Err(fail(format!(
            "SPDM version {version:#04x} is not 1.1 or 1.2"
        )));
    }
    if request[1] != GET_MEASUREMENTS || request[2] & 0x01 == 0 {
        return Err(fail("the request is not a signed GET_MEASUREMENTS"));
    }
    if &request[4..36] != nonce {
        return Err(fail("the device answered another nonce"));
    }
    let response = &report[REQUEST_LEN..];
    if response.len() < 8 || response[0] != version || response[1] != MEASUREMENTS {
        return Err(fail(
            "the response is not MEASUREMENTS of the request's version",
        ));
    }
    let record_len = u32::from_le_bytes([response[5], response[6], response[7], 0]) as usize;
    let opaque_at = 8 + record_len + 32;
    let opaque_len = response
        .get(opaque_at..opaque_at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
        .ok_or_else(|| fail("the response is truncated before its opaque data"))?;
    let signature_at = REQUEST_LEN + opaque_at + 2 + opaque_len;
    let leaf = &chain[0];
    // Raw `r || s`: twice the field size of the alias key's curve.
    let signature_len = match leaf.public_key_bits()?.len() {
        65 => 64,
        97 => 96,
        _ => return Err(fail("the alias key is not an ECDSA P-256 or P-384 key")),
    };
    if report.len() != signature_at + signature_len {
        return Err(fail(
            "the response does not end with one signature by the alias key",
        ));
    }
    x509::verify_chain(chain, roots, now)?;
    let digest = Sha384::digest(&report[..signature_at]);
    x509::verify_ecdsa_prehash(&leaf.spki_der, &digest, &report[signature_at..])
        .map_err(|e| fail(format!("the report signature does not verify: {e}")))?;
    Ok(VerifiedGpuDevice {
        device_id: hex::encode(Sha256::digest(&chain[1].spki_der)),
        signer_subject: leaf.subject_der.clone(),
    })
}

/// This machine's first NVIDIA GPU, through NVML: its report over `nonce`
/// and the certificate chain of the alias key that signed it (DER, alias
/// first). No library, no GPU, or a GPU that does not attest is an error.
#[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
pub fn collect_local(nonce: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
    let nvml = crate::nvml::Nvml::open()?;
    let device = nvml.device_by_index(0)?;
    let evidence = nvml.cc_attestation_report(device, nonce)?;
    let chains = nvml.cc_certificate_chains(device)?;
    if chains.attestation_cert_chain.is_empty() {
        return Err(fail("NVML returned no attestation certificate chain"));
    }
    Ok((evidence.report, chains.attestation_cert_chain))
}

/// The measurement blocks of a report, in order: each block's index and its
/// DMTF measurement value. Only the layout is checked here; the signature is
/// [`verify_device_report`]'s.
pub fn measurements(report: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    let response = report
        .get(REQUEST_LEN..)
        .filter(|r| r.len() >= 8 && r[1] == MEASUREMENTS)
        .ok_or_else(|| fail("the report carries no MEASUREMENTS response"))?;
    let count = response[4] as usize;
    let record_len = u32::from_le_bytes([response[5], response[6], response[7], 0]) as usize;
    let mut record = response
        .get(8..8 + record_len)
        .ok_or_else(|| fail("the measurement record is truncated"))?;
    let mut blocks: Vec<(u8, Vec<u8>)> = Vec::with_capacity(count);
    while !record.is_empty() {
        let truncated = || fail("a measurement block is truncated");
        let header = record.get(..4).ok_or_else(truncated)?;
        let (index, spec) = (header[0], header[1]);
        let size = u16::from_le_bytes([header[2], header[3]]) as usize;
        let measurement = record.get(4..4 + size).ok_or_else(truncated)?;
        // DMTF measurement: value type, value size (u16 LE), value.
        if spec & 0x01 == 0 || size < 3 {
            return Err(fail(format!(
                "measurement {index} is not a DMTF measurement"
            )));
        }
        if u16::from_le_bytes([measurement[1], measurement[2]]) as usize + 3 != size {
            return Err(fail(format!("measurement {index} does not fill its block")));
        }
        if blocks.iter().any(|(i, _)| *i == index) {
            return Err(fail(format!("measurement {index} appears twice")));
        }
        blocks.push((index, measurement[3..].to_vec()));
        record = &record[4 + size..];
    }
    if blocks.len() != count {
        return Err(fail(
            "the record holds another number of blocks than the response declares",
        ));
    }
    Ok(blocks)
}

/// Check a report's measurements against reference values, `(index,
/// accepted values)`: every listed index must be measured with one of its
/// accepted values. Indices left out are those NVIDIA marks inactive and are
/// not compared. No references match nothing.
pub fn check_reference_values(report: &[u8], references: &[(u8, Vec<Vec<u8>>)]) -> Result<()> {
    if references.is_empty() {
        return Err(fail("no GPU reference values are recognised"));
    }
    let measured = measurements(report)?;
    for (index, allowed) in references {
        let value = measured
            .iter()
            .find(|(i, _)| i == index)
            .map(|(_, v)| v)
            .ok_or_else(|| fail(format!("measurement {index} is missing from the report")))?;
        if !allowed.iter().any(|a| a == value) {
            return Err(fail(format!(
                "measurement {index} matches none of its reference values"
            )));
        }
    }
    Ok(())
}

/// Split concatenated DER certificates, or parse PEM text, into a chain.
pub fn parse_chain(bytes: &[u8]) -> Result<Vec<Cert>> {
    if bytes.starts_with(b"-----BEGIN") {
        let text = std::str::from_utf8(bytes).map_err(|_| fail("PEM chain is not UTF-8"))?;
        return x509::parse_pem_chain(text);
    }
    crate::tpm_attest::split_der(bytes)
        .iter()
        .map(|der| x509::parse(der))
        .collect()
}

/// A device made in software for tests of what consumes verified devices:
/// a root, a device certificate and an alias certificate (P-256), and
/// reports signed by the alias key in the SPDM layout NVIDIA devices use.
#[cfg(any(test, feature = "test-ca"))]
pub mod testgpu {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use sha2::{Digest, Sha384};

    use crate::x509::testca::{issue, key};

    /// The one measurement a software device reports: its index and value.
    pub const MEASUREMENT: (u8, [u8; 4]) = (1, [0xAA, 0xBB, 0xCC, 0xDD]);

    /// A software device: its chain (DER, alias first, then the device and
    /// root certificates), the root (PEM), and the alias key.
    pub struct SoftGpu {
        pub chain: Vec<u8>,
        pub root_pem: String,
        alias: p256::ecdsa::SigningKey,
    }

    impl SoftGpu {
        /// The device of `seed`, under the root of `root_seed`.
        pub fn new(seed: u8, root_seed: u8) -> Self {
            let root = key(root_seed);
            let device = key(seed);
            let alias = key(seed.wrapping_add(1));
            let root_der = issue("Test GPU Root", &root, "Test GPU Root", &root, true, 1);
            let device_der = issue(
                "Test GPU Device",
                &device,
                "Test GPU Root",
                &root,
                true,
                seed,
            );
            let alias_der = issue(
                "Test GPU Alias",
                &alias,
                "Test GPU Device",
                &device,
                false,
                seed,
            );
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&root_der);
            Self {
                chain: [alias_der, device_der, root_der].concat(),
                root_pem: format!(
                    "-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n"
                ),
                alias,
            }
        }

        /// A signed `GET_MEASUREMENTS` exchange over `nonce`, one
        /// measurement block, with opaque data.
        pub fn report(&self, nonce: &[u8; 32]) -> Vec<u8> {
            let mut r = vec![0x11, 0xE0, 0x01, 0xFF];
            r.extend_from_slice(nonce);
            r.push(0);
            let (index, value) = MEASUREMENT;
            let mut record = vec![index, 0x01, 7, 0, 0x01, 4, 0];
            record.extend_from_slice(&value);
            r.extend_from_slice(&[0x11, 0x60, 0x00, 0x00, 1]);
            r.extend_from_slice(&(record.len() as u32).to_le_bytes()[..3]);
            r.extend_from_slice(&record);
            r.extend_from_slice(&[0x5A; 32]);
            r.extend_from_slice(&3u16.to_le_bytes());
            r.extend_from_slice(&[1, 2, 3]);
            let digest = Sha384::digest(&r);
            let sig: p256::ecdsa::Signature = self.alias.sign_prehash(&digest).unwrap();
            r.extend_from_slice(&sig.to_bytes());
            r
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // NVIDIA's published sample from its open-source verifier
    // (github.com/NVIDIA/nvtrust, guest_tools/gpu_verifiers/local_gpu_verifier,
    // Apache-2.0): an H100's report and certificate chain, and the device
    // identity root its verifier ships.
    const REPORT_HEX: &str = include_str!("../testdata/nvidia/hopper_attestation_report.hex");
    const CHAIN_PEM: &str = include_str!("../testdata/nvidia/hopper_cert_chain.crt");
    const ROOT_PEM: &str = include_str!("../testdata/nvidia/device_identity_ca.crt");
    /// The requester nonce the sample was taken with.
    const NONCE: &str = "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    /// 2026-10-25.
    const NOW: u64 = 1_792_886_400;

    fn sample() -> (Vec<u8>, Vec<Cert>, Vec<Cert>, [u8; 32]) {
        (
            hex::decode(REPORT_HEX.trim()).unwrap(),
            parse_chain(CHAIN_PEM.as_bytes()).unwrap(),
            x509::parse_pem_chain(ROOT_PEM).unwrap(),
            hex::decode(NONCE).unwrap().try_into().unwrap(),
        )
    }

    #[test]
    fn nvidias_sample_h100_report_verifies_against_the_published_root() {
        let (report, chain, roots, nonce) = sample();
        let device = verify_device_report(&report, &chain, &roots, NOW, &nonce).unwrap();
        assert_eq!(device.device_id.len(), 64);
        // The DER chain NVML hands back verifies the same way.
        let der: Vec<u8> = chain.iter().flat_map(|c| c.der.clone()).collect();
        let again = parse_chain(&der).unwrap();
        assert_eq!(
            verify_device_report(&report, &again, &roots, NOW, &nonce).unwrap(),
            device
        );
    }

    #[test]
    fn another_nonce_a_changed_byte_or_a_short_report_is_refused() {
        let (report, chain, roots, nonce) = sample();
        let mut other = nonce;
        other[0] ^= 1;
        assert!(verify_device_report(&report, &chain, &roots, NOW, &other).is_err());
        for at in [5, 60, report.len() - 200, report.len() - 1] {
            let mut changed = report.clone();
            changed[at] ^= 1;
            assert!(verify_device_report(&changed, &chain, &roots, NOW, &nonce).is_err());
        }
        assert!(
            verify_device_report(&report[..report.len() - 1], &chain, &roots, NOW, &nonce).is_err()
        );
        assert!(verify_device_report(&report[..30], &chain, &roots, NOW, &nonce).is_err());
    }

    #[test]
    fn a_chain_to_another_root_or_without_the_device_certificate_is_refused() {
        let (report, chain, roots, nonce) = sample();
        // A self-signed root that is not NVIDIA's.
        let foreign_key = x509::testca::key(9);
        let foreign = vec![
            x509::parse(&x509::testca::issue(
                "NVIDIA Device Identity CA",
                &foreign_key,
                "NVIDIA Device Identity CA",
                &foreign_key,
                true,
                1,
            ))
            .unwrap(),
        ];
        assert!(verify_device_report(&report, &chain, &foreign, NOW, &nonce).is_err());
        assert!(verify_device_report(&report, &chain[..1], &roots, NOW, &nonce).is_err());
        // The device chain without the alias certificate that signed.
        assert!(verify_device_report(&report, &chain[1..], &roots, NOW, &nonce).is_err());
        assert!(verify_device_report(&report, &chain, &roots, 1_600_000_000, &nonce).is_err());
    }

    #[test]
    fn the_sample_report_matches_its_own_measurements_and_no_other_value() {
        let (report, ..) = sample();
        let measured = measurements(&report).unwrap();
        assert!(measured.len() > 1, "{measured:?}");
        let references: Vec<(u8, Vec<Vec<u8>>)> = measured
            .iter()
            .map(|(i, v)| (*i, vec![v.clone()]))
            .collect();
        check_reference_values(&report, &references).unwrap();
        // One listed index is enough; the rest are not compared.
        check_reference_values(&report, &references[..1]).unwrap();
        let mut changed = references.clone();
        changed[0].1[0][0] ^= 1;
        assert!(check_reference_values(&report, &changed).is_err());
        // Another accepted value beside the measured one still matches.
        changed[0].1.push(measured[0].1.clone());
        check_reference_values(&report, &changed).unwrap();
        let mut unmeasured = references.clone();
        unmeasured.push((0xFE, vec![vec![0; 48]]));
        assert!(check_reference_values(&report, &unmeasured).is_err());
        assert!(check_reference_values(&report, &[]).is_err());
        assert!(measurements(&report[..60]).is_err());
    }

    /// This machine's GPU answers a fresh nonce with a report that verifies
    /// against NVIDIA's published root. Run where an NVIDIA GPU is:
    /// `cargo test -p tenzro-tee this_machines_gpu -- --ignored`.
    #[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
    #[test]
    #[ignore = "needs an NVIDIA GPU and its driver"]
    fn this_machines_gpu_answers_a_fresh_nonce() {
        let nonce: [u8; 32] = rand::random();
        let (report, chain) = collect_local(&nonce).unwrap();
        let chain = parse_chain(&chain).unwrap();
        let roots = x509::parse_pem_chain(ROOT_PEM).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let device = verify_device_report(&report, &chain, &roots, now, &nonce).unwrap();
        let measured = measurements(&report).unwrap();
        eprintln!(
            "device {} answered with {} measurements",
            device.device_id,
            measured.len()
        );
    }

    #[test]
    fn a_software_device_reports_its_one_measurement() {
        let gpu = testgpu::SoftGpu::new(0x21, 0x20);
        let (index, value) = testgpu::MEASUREMENT;
        assert_eq!(
            measurements(&gpu.report(&[7; 32])).unwrap(),
            vec![(index, value.to_vec())]
        );
    }

    #[test]
    fn a_software_device_verifies_under_its_own_root_only() {
        let gpu = testgpu::SoftGpu::new(0x21, 0x20);
        let chain = parse_chain(&gpu.chain).unwrap();
        let root = x509::parse_pem_chain(&gpu.root_pem).unwrap();
        let report = gpu.report(&[7; 32]);
        verify_device_report(&report, &chain, &root, NOW, &[7; 32]).unwrap();
        let (_, _, nvidia, _) = sample();
        assert!(verify_device_report(&report, &chain, &nvidia, NOW, &[7; 32]).is_err());
    }
}
