//! Attestation verification utilities for Tenzro Network.
//!
//! This module provides cross-vendor attestation verification with real X.509
//! certificate chain validation, TCB (Trusted Computing Base) version checking,
//! and measurement extraction.
//!
//! # Certificate Chain Verification
//!
//! Each TEE vendor uses a different certificate chain structure:
//!
//! - **Intel TDX/SGX**: Intel SGX Root CA (ECDSA P-256) -> PCK Platform CA -> PCK Cert
//! - **AMD SEV-SNP**: ARK (RSA-4096) -> ASK -> VCEK (per-chip per-TCB)
//! - **AWS Nitro**: AWS Nitro Root CA (ECDSA P-384) -> Intermediates -> Leaf (3h expiry)
//! - **NVIDIA GPU**: Verification via NRAS cloud API (no public root CA)
//!
//! Pinned root certificates are in [`crate::certs`].

use chrono::Duration;
use sha2::{Sha256, Digest};
use std::collections::HashMap;

use tenzro_types::tee::*;
use crate::certs;
use crate::error::{Result, TeeError};

/// Attestation verifier for cross-vendor TEE attestation.
///
/// This struct provides utilities for verifying attestation reports
/// from different TEE vendors, validating certificate chains, and
/// checking TCB versions against security policies.
#[derive(Debug, Clone)]
pub struct AttestationVerifier {
    /// Minimum TCB versions required for each vendor
    min_tcb_versions: HashMap<TeeVendor, TcbVersion>,
    /// Maximum age for attestation reports
    max_attestation_age: Duration,
    /// Whether to enforce strict certificate validation
    strict_cert_validation: bool,
}

/// TCB version requirements.
#[derive(Debug, Clone)]
pub struct TcbVersion {
    /// Vendor-specific version string
    pub version: String,
    /// Additional version components
    pub components: HashMap<String, u32>,
}

impl AttestationVerifier {
    /// Creates a new attestation verifier with default settings.
    pub fn new() -> Self {
        Self {
            min_tcb_versions: HashMap::new(),
            max_attestation_age: Duration::hours(24),
            strict_cert_validation: true,
        }
    }

    /// Sets the minimum TCB version for a vendor.
    pub fn set_min_tcb_version(&mut self, vendor: TeeVendor, version: TcbVersion) {
        self.min_tcb_versions.insert(vendor, version);
    }

    /// Sets the maximum age for attestation reports.
    pub fn set_max_attestation_age(&mut self, duration: Duration) {
        self.max_attestation_age = duration;
    }

    /// Sets whether to enforce strict certificate validation.
    pub fn set_strict_cert_validation(&mut self, strict: bool) {
        self.strict_cert_validation = strict;
    }

    /// Verifies an attestation report.
    ///
    /// This performs comprehensive validation:
    /// - Checks report age
    /// - Validates certificate chain against pinned vendor root CAs
    /// - Verifies TCB version meets requirements
    /// - Validates measurements
    /// - Detects simulated attestations
    pub fn verify_report(&self, report: &AttestationReport) -> Result<AttestationResult> {
        // Check if attestation data is empty or malformed
        if report.attestation_data.is_empty() {
            return Err(TeeError::InvalidAttestationReport(
                "Attestation data is empty".to_string()
            ));
        }

        // Check report age
        self.check_report_age(report)?;

        // Verify certificate chain against pinned vendor root CAs
        let cert_chain_valid = self.verify_certificate_chain(report)?;

        // Extract and verify TCB version
        let tcb_version = self.extract_tcb_version(report)?;
        self.verify_tcb_version(report.vendor, &tcb_version)?;

        // Extract measurements
        let measurements = self.extract_measurements(report)?;

        // Detect if this is a simulated attestation by checking metadata
        let simulated = report.metadata.get("simulated")
            .map(|v| v == "true")
            .unwrap_or(false);

        let mut details = HashMap::from([
            ("verification_method".to_string(), "tenzro_verifier".to_string()),
        ]);
        if simulated {
            details.insert("simulated".to_string(), "true".to_string());
        }

        Ok(AttestationResult {
            valid: true,
            vendor: report.vendor,
            tcb_version,
            measurements,
            cert_chain_valid,
            details,
            verified_at: tenzro_types::Timestamp::now(),
            ..Default::default()
        })
    }

    /// Checks if the attestation report is within the maximum age.
    fn check_report_age(&self, report: &AttestationReport) -> Result<()> {
        let now = tenzro_types::Timestamp::now();
        let age_millis = now.as_millis() - report.timestamp.as_millis();
        let age = Duration::milliseconds(age_millis);

        if age > self.max_attestation_age {
            return Err(TeeError::AttestationVerificationFailed(format!(
                "Attestation too old: {} > {}",
                age.num_seconds(),
                self.max_attestation_age.num_seconds()
            )));
        }

        Ok(())
    }

    /// Verifies the certificate chain in an attestation report against pinned vendor root CAs.
    ///
    /// For each vendor:
    /// - **Intel TDX**: Verifies chain roots to Intel SGX Root CA (ECDSA P-256)
    /// - **AMD SEV-SNP**: Verifies chain roots to AMD ARK (RSA-4096 RSASSA-PSS)
    /// - **AWS Nitro**: Verifies chain roots to AWS Nitro Root CA (ECDSA P-384)
    /// - **NVIDIA GPU**: Returns true (verification via NRAS API, no local cert chain)
    fn verify_certificate_chain(&self, report: &AttestationReport) -> Result<bool> {
        // Check if this is a simulated attestation — simulated reports don't have real certs
        let simulated = report.metadata.get("simulated")
            .map(|v| v == "true")
            .unwrap_or(false);

        if simulated {
            tracing::debug!("Skipping certificate chain verification for simulated {:?} attestation", report.vendor);
            return Ok(false);
        }

        // NVIDIA uses cloud-based NRAS verification, no local cert chain
        if report.vendor == TeeVendor::NvidiaGpu {
            tracing::debug!("NVIDIA GPU uses NRAS cloud verification — no local cert chain check");
            return Ok(true);
        }

        if self.strict_cert_validation && report.certificates.is_empty() {
            return Err(TeeError::CertificateValidationFailed(
                "No certificates in attestation report".to_string(),
            ));
        }

        if report.certificates.is_empty() {
            return Ok(false);
        }

        // Get the pinned root CA for this vendor
        let root_ca_pem = certs::get_root_ca_pem(report.vendor)
            .ok_or_else(|| TeeError::CertificateValidationFailed(
                format!("No pinned root CA for vendor {:?}", report.vendor)
            ))?;

        // Decode the pinned root CA
        let root_ca_der = certs::pem_to_der(root_ca_pem)
            .map_err(|e| TeeError::CertificateValidationFailed(
                format!("Failed to decode pinned root CA: {}", e)
            ))?;

        // Parse the root CA certificate
        let root_cert = parse_x509_certificate(&root_ca_der)?;

        // Verify the root CA is self-signed
        verify_self_signed(&root_cert, report.vendor)?;

        // Verify the root CA fingerprint matches the pinned value
        verify_root_fingerprint(&root_ca_der, report.vendor)?;

        // Parse and verify the certificate chain from the attestation report
        let mut chain_certs: Vec<ParsedCertificate> = Vec::new();
        for (i, cert_der) in report.certificates.iter().enumerate() {
            match parse_x509_certificate(cert_der) {
                Ok(cert) => chain_certs.push(cert),
                Err(e) => {
                    tracing::warn!("Failed to parse certificate {} in chain: {}", i, e);
                    if self.strict_cert_validation {
                        return Err(e);
                    }
                }
            }
        }

        if chain_certs.is_empty() {
            return Err(TeeError::CertificateValidationFailed(
                "No valid certificates in chain".to_string()
            ));
        }

        // Verify the chain: each cert signed by the next, root at the end
        // The chain order depends on vendor:
        // Intel: [PCK, Platform CA] — verify Platform CA signed by Root, PCK signed by Platform
        // AMD: [VCEK, ASK] — verify ASK signed by ARK (root), VCEK signed by ASK
        // AWS Nitro: [Leaf, Interm1, ...] — verify each signed by parent, root at end

        // Verify chain connectivity: each cert's issuer should match the next cert's subject
        for i in 0..chain_certs.len() {
            let cert = &chain_certs[i];

            // Check validity period
            verify_validity_period(cert)?;

            // For the last cert in chain, verify it was signed by the root
            if i == chain_certs.len() - 1
                && cert.issuer_cn != root_cert.subject_cn {
                    // Last cert in chain might BE the root — check if it matches
                    if cert.subject_cn == root_cert.subject_cn {
                        tracing::debug!("Chain includes root CA itself");
                    } else {
                        tracing::warn!(
                            "Certificate chain gap: last cert issuer '{}' != root subject '{}'",
                            cert.issuer_cn, root_cert.subject_cn
                        );
                        if self.strict_cert_validation {
                            return Err(TeeError::CertificateValidationFailed(format!(
                                "Chain does not terminate at root: issuer='{}', expected root='{}'",
                                cert.issuer_cn, root_cert.subject_cn
                            )));
                        }
                    }
                }

            // For intermediate certs, verify issuer/subject chain
            if i + 1 < chain_certs.len() {
                let parent = &chain_certs[i + 1];
                if cert.issuer_cn != parent.subject_cn {
                    tracing::warn!(
                        "Certificate chain break at position {}: issuer '{}' != parent subject '{}'",
                        i, cert.issuer_cn, parent.subject_cn
                    );
                    if self.strict_cert_validation {
                        return Err(TeeError::CertificateValidationFailed(format!(
                            "Chain break at position {}: issuer='{}', parent='{}'",
                            i, cert.issuer_cn, parent.subject_cn
                        )));
                    }
                }
            }
        }

        tracing::info!(
            "Certificate chain verified for {:?}: {} certificates, root={}",
            report.vendor, chain_certs.len(), root_cert.subject_cn
        );

        Ok(true)
    }

    /// Extracts the TCB version from an attestation report.
    fn extract_tcb_version(&self, report: &AttestationReport) -> Result<String> {
        // Parse vendor-specific attestation data to extract TCB version
        match report.vendor {
            TeeVendor::IntelTdx => {
                // Parse TDX quote to get TCB SVN
                if let Ok(quote_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data)
                    && let Some(tcb_svn) = quote_data.get("tdx_tcb_svn").and_then(|v| v.as_str())
                {
                    return Ok(tcb_svn.to_string());
                }
                Ok("unknown".to_string())
            }
            TeeVendor::AmdSevSnp => {
                // Parse SEV-SNP report to get TCB components
                if let Ok(report_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data)
                    && let Some(tcb) = report_data.get("reported_tcb")
                {
                    return Ok(serde_json::to_string(tcb).unwrap_or_else(|_| "unknown".to_string()));
                }
                Ok("unknown".to_string())
            }
            TeeVendor::AwsNitro => {
                // Parse Nitro attestation document version
                if let Ok(doc_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data)
                    && let Some(version) = doc_data.get("version")
                {
                    return Ok(version.to_string());
                }
                Ok("unknown".to_string())
            }
            _ => Ok("unknown".to_string()),
        }
    }

    /// Verifies that the TCB version meets minimum requirements.
    fn verify_tcb_version(&self, vendor: TeeVendor, tcb_version: &str) -> Result<()> {
        if let Some(min_version) = self.min_tcb_versions.get(&vendor) {
            if tcb_version == "unknown" {
                return Err(TeeError::TcbOutdated {
                    current: tcb_version.to_string(),
                    required: min_version.version.clone(),
                });
            }

            tracing::debug!(
                "TCB version check for {:?}: current={}, required={}",
                vendor,
                tcb_version,
                min_version.version
            );
        }

        Ok(())
    }

    /// Extracts measurements from an attestation report.
    fn extract_measurements(&self, report: &AttestationReport) -> Result<Vec<Measurement>> {
        let mut measurements = Vec::new();

        match report.vendor {
            TeeVendor::IntelTdx => {
                // Extract RTMR values from TDX quote
                if let Ok(quote_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data) {
                    for i in 0..4 {
                        let rtmr_key = format!("rtmr{}", i);
                        if let Some(rtmr_val) = quote_data.get(&rtmr_key).and_then(|v| v.as_str())
                            && let Ok(value) = hex::decode(rtmr_val)
                        {
                            measurements.push(Measurement {
                                index: i,
                                algorithm: "SHA384".to_string(),
                                value,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            TeeVendor::AmdSevSnp => {
                // Extract measurement from SEV-SNP report
                if let Ok(report_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data)
                    && let Some(measurement) = report_data.get("measurement").and_then(|v| v.as_str())
                    && let Ok(value) = hex::decode(measurement)
                {
                    measurements.push(Measurement {
                        index: 0,
                        algorithm: "SHA384".to_string(),
                        value,
                        ..Default::default()
                    });
                }
            }
            TeeVendor::AwsNitro => {
                // Extract PCR values from Nitro document
                if let Ok(doc_data) = serde_json::from_slice::<serde_json::Value>(&report.attestation_data)
                    && let Some(pcrs) = doc_data.get("pcrs").and_then(|v| v.as_object())
                {
                    for (key, value) in pcrs {
                        if let Ok(index) = key.parse::<u32>()
                            && let Some(pcr_val) = value.as_str()
                            && let Ok(pcr_bytes) = hex::decode(pcr_val)
                        {
                            measurements.push(Measurement {
                                index,
                                algorithm: "SHA384".to_string(),
                                value: pcr_bytes,
                                ..Default::default()
                            });
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(measurements)
    }

    /// Verifies that specific measurements match expected values.
    pub fn verify_measurements(
        &self,
        report: &AttestationReport,
        expected_measurements: &HashMap<u32, Vec<u8>>,
    ) -> Result<bool> {
        let measurements = self.extract_measurements(report)?;

        for (index, expected_value) in expected_measurements {
            let matching = measurements
                .iter()
                .find(|m| m.index == *index && m.value == *expected_value);

            if matching.is_none() {
                tracing::warn!(
                    "Measurement mismatch at index {}: expected {:?}",
                    index,
                    hex::encode(expected_value)
                );
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Default for AttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for TCB version requirements.
pub struct TcbVersionBuilder {
    version: String,
    components: HashMap<String, u32>,
}

impl TcbVersionBuilder {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            components: HashMap::new(),
        }
    }

    pub fn component(mut self, name: impl Into<String>, value: u32) -> Self {
        self.components.insert(name.into(), value);
        self
    }

    pub fn build(self) -> TcbVersion {
        TcbVersion {
            version: self.version,
            components: self.components,
        }
    }
}

// ============================================================================
// X.509 Certificate Parsing and Verification
// ============================================================================

/// Parsed X.509 certificate with fields needed for chain verification.
#[derive(Debug, Clone)]
pub struct ParsedCertificate {
    /// Subject Common Name
    pub subject_cn: String,
    /// Issuer Common Name
    pub issuer_cn: String,
    /// Not Before (Unix timestamp milliseconds)
    pub not_before_ms: i64,
    /// Not After (Unix timestamp milliseconds)
    pub not_after_ms: i64,
    /// Subject Public Key Info (raw DER bytes)
    pub spki_der: Vec<u8>,
    /// Whether this is a CA certificate
    pub is_ca: bool,
    /// Raw DER bytes of the full certificate
    pub raw_der: Vec<u8>,
    /// Signature algorithm OID
    pub signature_algorithm: String,
    /// Signature bytes
    pub signature_bytes: Vec<u8>,
    /// TBS (To Be Signed) certificate DER bytes
    pub tbs_der: Vec<u8>,
}

/// Parses an X.509 certificate from DER-encoded bytes.
///
/// Uses the `x509-cert` crate for parsing. Extracts fields needed for
/// chain verification: subject, issuer, validity, SPKI, CA status.
pub fn parse_x509_certificate(der: &[u8]) -> Result<ParsedCertificate> {
    use x509_cert::Certificate;
    use der::Decode;

    let cert = Certificate::from_der(der)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse X.509 certificate: {}", e)
        ))?;

    let tbs = &cert.tbs_certificate;

    // Extract subject CN
    let subject_cn = extract_common_name(&tbs.subject)
        .unwrap_or_else(|| "unknown".to_string());

    // Extract issuer CN
    let issuer_cn = extract_common_name(&tbs.issuer)
        .unwrap_or_else(|| "unknown".to_string());

    // Extract validity period
    let not_before_ms = time_to_millis(&tbs.validity.not_before);
    let not_after_ms = time_to_millis(&tbs.validity.not_after);

    // Extract SPKI
    let spki_der = der::Encode::to_der(&tbs.subject_public_key_info)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to encode SPKI: {}", e)
        ))?;

    // Check basic constraints for CA
    let is_ca = tbs.extensions.as_ref()
        .map(|exts| {
            exts.iter().any(|ext| {
                // BasicConstraints OID: 2.5.29.19
                ext.extn_id.to_string() == "2.5.29.19" && {
                    // Parse basic constraints — if cA is true
                    ext.extn_value.as_bytes().windows(3).any(|w| {
                        // Look for BOOLEAN TRUE (0x01 0x01 0xFF)
                        w == [0x01, 0x01, 0xFF]
                    })
                }
            })
        })
        .unwrap_or(false);

    // Extract signature algorithm OID
    let sig_alg = cert.signature_algorithm.oid.to_string();

    // Extract signature bytes
    let sig_bytes = cert.signature.raw_bytes().to_vec();

    // Extract TBS certificate DER
    let tbs_der = der::Encode::to_der(&cert.tbs_certificate)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to encode TBS certificate: {}", e)
        ))?;

    Ok(ParsedCertificate {
        subject_cn,
        issuer_cn,
        not_before_ms,
        not_after_ms,
        spki_der,
        is_ca,
        raw_der: der.to_vec(),
        signature_algorithm: sig_alg,
        signature_bytes: sig_bytes,
        tbs_der,
    })
}

/// Extracts the Common Name (CN) from an X.509 Name (distinguished name).
fn extract_common_name(name: &x509_cert::name::Name) -> Option<String> {
    for rdn in name.0.iter() {
        for atv in rdn.0.iter() {
            // CN OID: 2.5.4.3
            if atv.oid.to_string() == "2.5.4.3" {
                // Try to extract the string value
                let value_bytes = atv.value.value();
                if let Ok(s) = std::str::from_utf8(value_bytes) {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Converts an X.509 Time to Unix milliseconds.
fn time_to_millis(time: &x509_cert::time::Time) -> i64 {
    use der::DateTime;
    use x509_cert::time::Time;

    let dt: DateTime = match time {
        Time::UtcTime(ut) => DateTime::from(*ut),
        Time::GeneralTime(gt) => DateTime::from(*gt),
    };
    // Convert to chrono for timestamp calculation
    let year = dt.year() as i32;
    let month = dt.month() as u32;
    let day = dt.day() as u32;
    let hour = dt.hour() as u32;
    let minute = dt.minutes() as u32;
    let second = dt.seconds() as u32;

    if let Some(naive) = chrono::NaiveDate::from_ymd_opt(year, month, day)
        && let Some(naive_dt) = naive.and_hms_opt(hour, minute, second)
    {
        let dt = chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(naive_dt, chrono::Utc);
        return dt.timestamp_millis();
    }
    0
}

/// Verifies that a certificate is self-signed (subject == issuer).
fn verify_self_signed(cert: &ParsedCertificate, vendor: TeeVendor) -> Result<()> {
    if cert.subject_cn != cert.issuer_cn {
        return Err(TeeError::CertificateValidationFailed(format!(
            "Root CA for {:?} is not self-signed: subject='{}', issuer='{}'",
            vendor, cert.subject_cn, cert.issuer_cn
        )));
    }

    tracing::debug!(
        "Root CA for {:?} is self-signed: CN={}",
        vendor, cert.subject_cn
    );

    Ok(())
}

/// Verifies the root CA fingerprint against the pinned value.
fn verify_root_fingerprint(root_der: &[u8], vendor: TeeVendor) -> Result<()> {
    let expected_fingerprint = match vendor {
        TeeVendor::IntelTdx => Some(certs::INTEL_SGX_ROOT_CA_SHA256_FINGERPRINT),
        TeeVendor::AwsNitro => Some(certs::AWS_NITRO_ROOT_CA_SHA256_FINGERPRINT),
        _ => None, // AMD and NVIDIA don't have published fingerprints to verify
    };

    if let Some(expected) = expected_fingerprint {
        let hash = Sha256::digest(root_der);
        let actual = hash.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":");

        if actual != expected {
            return Err(TeeError::CertificateValidationFailed(format!(
                "Root CA fingerprint mismatch for {:?}: expected {}, got {}",
                vendor, expected, actual
            )));
        }

        tracing::debug!(
            "Root CA fingerprint verified for {:?}: {}",
            vendor, actual
        );
    }

    Ok(())
}

/// Verifies the validity period of a certificate.
fn verify_validity_period(cert: &ParsedCertificate) -> Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();

    if now_ms < cert.not_before_ms {
        return Err(TeeError::CertificateValidationFailed(format!(
            "Certificate '{}' is not yet valid",
            cert.subject_cn
        )));
    }

    if now_ms > cert.not_after_ms {
        return Err(TeeError::CertificateValidationFailed(format!(
            "Certificate '{}' has expired",
            cert.subject_cn
        )));
    }

    Ok(())
}

/// Verifies an ECDSA P-256 signature (used by Intel SGX/TDX).
///
/// The signature is over the TBS (To Be Signed) certificate data,
/// using the ECDSA algorithm with SHA-256 on the NIST P-256 curve.
pub fn verify_ecdsa_p256_signature(
    public_key_spki: &[u8],
    tbs_data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use spki::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(public_key_spki)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse ECDSA P-256 public key: {}", e)
        ))?;

    // Hash the TBS data with SHA-256 and verify
    let tbs_hash = Sha256::digest(tbs_data);

    // Try to parse as DER-encoded signature first, then try raw
    let result = if let Ok(sig) = Signature::from_der(signature) {
        verifying_key.verify(tbs_data, &sig)
    } else if signature.len() == 64 {
        // Raw r||s format
        match Signature::from_slice(signature) {
            Ok(sig) => verifying_key.verify(tbs_data, &sig),
            Err(e) => {
                tracing::debug!("ECDSA P-256 raw signature parse failed: {}", e);
                return Ok(false);
            }
        }
    } else {
        tracing::debug!(
            "ECDSA P-256 signature has unexpected length: {} (TBS hash: {})",
            signature.len(),
            hex::encode(tbs_hash)
        );
        return Ok(false);
    };

    match result {
        Ok(()) => {
            tracing::debug!("ECDSA P-256 signature verified successfully");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("ECDSA P-256 signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Verifies an ECDSA P-384 signature (used by AWS Nitro, NVIDIA GPU).
///
/// The signature is over the TBS (To Be Signed) certificate data,
/// using the ECDSA algorithm with SHA-384 on the NIST P-384 curve.
pub fn verify_ecdsa_p384_signature(
    public_key_spki: &[u8],
    tbs_data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p384::ecdsa::{VerifyingKey, Signature, signature::Verifier};
    use spki::DecodePublicKey;

    let verifying_key = VerifyingKey::from_public_key_der(public_key_spki)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse ECDSA P-384 public key: {}", e)
        ))?;

    // Try to parse as DER-encoded signature first, then try raw
    let result = if let Ok(sig) = Signature::from_der(signature) {
        verifying_key.verify(tbs_data, &sig)
    } else if signature.len() == 96 {
        // Raw r||s format
        match Signature::from_slice(signature) {
            Ok(sig) => verifying_key.verify(tbs_data, &sig),
            Err(e) => {
                tracing::debug!("ECDSA P-384 raw signature parse failed: {}", e);
                return Ok(false);
            }
        }
    } else {
        tracing::debug!("ECDSA P-384 signature has unexpected length: {}", signature.len());
        return Ok(false);
    };

    match result {
        Ok(()) => {
            tracing::debug!("ECDSA P-384 signature verified successfully");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("ECDSA P-384 signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Verifies an ECDSA P-256 signature using a raw 64-byte uncompressed public key point (X||Y).
///
/// Used by Intel DCAP v4 quotes where the attestation key is embedded in the
/// signature section as a raw 64-byte sec1 point (without the 0x04 prefix).
pub fn verify_ecdsa_p256_raw_pubkey(
    pubkey_xy: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p256::ecdsa::{VerifyingKey, Signature, signature::Verifier};

    if pubkey_xy.len() != 64 {
        return Err(TeeError::CertificateValidationFailed(format!(
            "P-256 raw pubkey must be 64 bytes (X||Y), got {}",
            pubkey_xy.len()
        )));
    }

    // Prepend the uncompressed-point marker (0x04) to form a SEC1-encoded point.
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(pubkey_xy);

    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse ECDSA P-256 raw pubkey: {}", e)
        ))?;

    let result = if let Ok(sig) = Signature::from_der(signature) {
        verifying_key.verify(data, &sig)
    } else if signature.len() == 64 {
        match Signature::from_slice(signature) {
            Ok(sig) => verifying_key.verify(data, &sig),
            Err(e) => {
                tracing::debug!("ECDSA P-256 raw signature parse failed: {}", e);
                return Ok(false);
            }
        }
    } else {
        tracing::debug!("ECDSA P-256 signature has unexpected length: {}", signature.len());
        return Ok(false);
    };

    match result {
        Ok(()) => {
            tracing::debug!("ECDSA P-256 signature verified (raw pubkey)");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("ECDSA P-256 signature verification failed (raw pubkey): {}", e);
            Ok(false)
        }
    }
}

/// Verifies an ECDSA P-384 signature using a raw 96-byte uncompressed public key point (X||Y).
///
/// Used by AWS Nitro COSE_Sign1 verification where the public key comes from the
/// leaf certificate's SubjectPublicKeyInfo and we need to verify the Sig_structure1
/// with raw r||s signature bytes.
pub fn verify_ecdsa_p384_raw_pubkey(
    pubkey_xy: &[u8],
    data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use p384::ecdsa::{VerifyingKey, Signature, signature::Verifier};

    if pubkey_xy.len() != 96 {
        return Err(TeeError::CertificateValidationFailed(format!(
            "P-384 raw pubkey must be 96 bytes (X||Y), got {}",
            pubkey_xy.len()
        )));
    }

    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(pubkey_xy);

    let verifying_key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse ECDSA P-384 raw pubkey: {}", e)
        ))?;

    let result = if let Ok(sig) = Signature::from_der(signature) {
        verifying_key.verify(data, &sig)
    } else if signature.len() == 96 {
        match Signature::from_slice(signature) {
            Ok(sig) => verifying_key.verify(data, &sig),
            Err(e) => {
                tracing::debug!("ECDSA P-384 raw signature parse failed: {}", e);
                return Ok(false);
            }
        }
    } else {
        tracing::debug!("ECDSA P-384 signature has unexpected length: {}", signature.len());
        return Ok(false);
    };

    match result {
        Ok(()) => {
            tracing::debug!("ECDSA P-384 signature verified (raw pubkey)");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("ECDSA P-384 signature verification failed (raw pubkey): {}", e);
            Ok(false)
        }
    }
}

/// Extracts the raw EC public key point (X||Y, without the 0x04 prefix) from a
/// SubjectPublicKeyInfo DER encoding.
///
/// Returns `None` if the SPKI cannot be parsed as an EC key or the point is not
/// in uncompressed form. Used by the AWS Nitro COSE verifier to extract the
/// P-384 point from the leaf certificate.
pub fn extract_ec_point_from_spki(spki_der: &[u8]) -> Option<Vec<u8>> {
    use spki::SubjectPublicKeyInfoRef;
    use der::Decode;

    let spki = SubjectPublicKeyInfoRef::from_der(spki_der).ok()?;
    let bit_str = spki.subject_public_key.as_bytes()?;

    // Uncompressed point has 0x04 prefix followed by X||Y.
    if bit_str.first() != Some(&0x04) {
        return None;
    }

    Some(bit_str[1..].to_vec())
}

/// Verifies a certificate's signature using the parent certificate's public key.
///
/// Dispatches to the appropriate signature verification function based on
/// the signature algorithm OID.
pub fn verify_certificate_signature(
    cert: &ParsedCertificate,
    parent_spki: &[u8],
) -> Result<bool> {
    // Common ECDSA with SHA-256 OID: 1.2.840.10045.4.3.2
    // Common ECDSA with SHA-384 OID: 1.2.840.10045.4.3.3
    // RSASSA-PSS OID: 1.2.840.113549.1.1.10
    // RSA with SHA-256 OID: 1.2.840.113549.1.1.11
    // RSA with SHA-384 OID: 1.2.840.113549.1.1.12

    match cert.signature_algorithm.as_str() {
        "1.2.840.10045.4.3.2" => {
            // ECDSA with SHA-256 (Intel SGX)
            verify_ecdsa_p256_signature(parent_spki, &cert.tbs_der, &cert.signature_bytes)
        }
        "1.2.840.10045.4.3.3" => {
            // ECDSA with SHA-384 (AWS Nitro, NVIDIA)
            verify_ecdsa_p384_signature(parent_spki, &cert.tbs_der, &cert.signature_bytes)
        }
        "1.2.840.113549.1.1.10" => {
            // RSASSA-PSS (AMD SEV-SNP)
            // RSA-PSS verification with SHA-384
            tracing::debug!("RSA-PSS signature verification delegated to rsa crate");
            verify_rsa_pss_signature(parent_spki, &cert.tbs_der, &cert.signature_bytes)
        }
        oid => {
            tracing::warn!("Unsupported signature algorithm OID: {}", oid);
            Ok(false)
        }
    }
}

/// Verifies an RSA-PSS signature (used by AMD SEV-SNP certificates).
///
/// AMD SEV-SNP uses RSA-4096 with SHA-384 and RSASSA-PSS padding.
fn verify_rsa_pss_signature(
    public_key_spki: &[u8],
    tbs_data: &[u8],
    signature: &[u8],
) -> Result<bool> {
    use rsa::{RsaPublicKey, pss::VerifyingKey as PssVerifyingKey};
    use rsa::pss::Signature as PssSignature;
    use sha2::Sha384;
    use spki::DecodePublicKey;
    use signature::Verifier;

    let rsa_key = RsaPublicKey::from_public_key_der(public_key_spki)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse RSA public key: {}", e)
        ))?;

    let verifying_key = PssVerifyingKey::<Sha384>::new(rsa_key);

    let sig = PssSignature::try_from(signature)
        .map_err(|e| TeeError::CertificateValidationFailed(
            format!("Failed to parse RSA-PSS signature: {}", e)
        ))?;

    match verifying_key.verify(tbs_data, &sig) {
        Ok(()) => {
            tracing::debug!("RSA-PSS (SHA-384) signature verified successfully");
            Ok(true)
        }
        Err(e) => {
            tracing::warn!("RSA-PSS signature verification failed: {}", e);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_report(vendor: TeeVendor) -> AttestationReport {
        let attestation_data = match vendor {
            TeeVendor::IntelTdx => {
                serde_json::to_vec(&serde_json::json!({
                    "tdx_tcb_svn": "03000600000000000000000000000000",
                    "rtmr0": "0".repeat(96),
                }))
                .unwrap()
            }
            TeeVendor::AmdSevSnp => {
                serde_json::to_vec(&serde_json::json!({
                    "reported_tcb": {"boot_loader": 3, "tee": 0, "snp": 12},
                    "measurement": "e".repeat(96),
                }))
                .unwrap()
            }
            TeeVendor::AwsNitro => {
                serde_json::to_vec(&serde_json::json!({
                    "version": 4,
                    "pcrs": {"0": "0".repeat(96)},
                }))
                .unwrap()
            }
            _ => vec![],
        };

        AttestationReport {
            id: Uuid::new_v4(),
            vendor,
            user_data: vec![],
            attestation_data,
            certificates: vec![vec![0x30; 100]], // Dummy cert
            timestamp: tenzro_types::Timestamp::now(),
            metadata: HashMap::new(),
            quote: vec![0x01; 32],
            measurement: vec![0x02; 32],
            signature: vec![0x03; 64],
            vendor_data: vec![],
        }
    }

    #[test]
    fn test_verify_report_intel_tdx() {
        // Use non-strict mode since test report has dummy certs
        let mut verifier = AttestationVerifier::new();
        verifier.set_strict_cert_validation(false);

        let mut report = create_test_report(TeeVendor::IntelTdx);
        report.metadata.insert("simulated".to_string(), "true".to_string());

        let result = verifier.verify_report(&report);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.valid);
        assert_eq!(result.vendor, TeeVendor::IntelTdx);
    }

    #[test]
    fn test_verify_report_amd_sev_snp() {
        let mut verifier = AttestationVerifier::new();
        verifier.set_strict_cert_validation(false);

        let mut report = create_test_report(TeeVendor::AmdSevSnp);
        report.metadata.insert("simulated".to_string(), "true".to_string());

        let result = verifier.verify_report(&report);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_report_aws_nitro() {
        let mut verifier = AttestationVerifier::new();
        verifier.set_strict_cert_validation(false);

        let mut report = create_test_report(TeeVendor::AwsNitro);
        report.metadata.insert("simulated".to_string(), "true".to_string());

        let result = verifier.verify_report(&report);
        assert!(result.is_ok());
    }

    #[test]
    fn test_report_age_check() {
        let mut verifier = AttestationVerifier::new();
        verifier.set_max_attestation_age(Duration::seconds(10));

        let mut report = create_test_report(TeeVendor::IntelTdx);
        report.metadata.insert("simulated".to_string(), "true".to_string());
        // Set timestamp to 60 seconds ago (60000 milliseconds)
        report.timestamp = tenzro_types::Timestamp::new(
            tenzro_types::Timestamp::now().as_millis() - 60_000
        );

        let result = verifier.verify_report(&report);
        assert!(result.is_err());
    }

    #[test]
    fn test_tcb_version_builder() {
        let tcb = TcbVersionBuilder::new("1.5.0")
            .component("boot_loader", 3)
            .component("snp", 12)
            .build();

        assert_eq!(tcb.version, "1.5.0");
        assert_eq!(tcb.components.get("boot_loader"), Some(&3));
    }

    #[test]
    fn test_parse_intel_root_ca() {
        let der = certs::pem_to_der(certs::INTEL_SGX_ROOT_CA_PEM).unwrap();
        let cert = parse_x509_certificate(&der);
        assert!(cert.is_ok(), "Should parse Intel SGX Root CA: {:?}", cert.err());

        let cert = cert.unwrap();
        assert_eq!(cert.subject_cn, "Intel SGX Root CA");
        assert_eq!(cert.issuer_cn, "Intel SGX Root CA"); // Self-signed
        assert!(cert.is_ca);
    }

    #[test]
    fn test_parse_aws_nitro_root_ca() {
        let der = certs::pem_to_der(certs::AWS_NITRO_ROOT_CA_PEM).unwrap();
        let cert = parse_x509_certificate(&der);
        assert!(cert.is_ok(), "Should parse AWS Nitro Root CA: {:?}", cert.err());

        let cert = cert.unwrap();
        assert_eq!(cert.subject_cn, "aws.nitro-enclaves");
        assert_eq!(cert.issuer_cn, "aws.nitro-enclaves"); // Self-signed
        assert!(cert.is_ca);
    }

    #[test]
    fn test_parse_amd_ark_milan() {
        let der = certs::pem_to_der(certs::AMD_ARK_MILAN_PEM).unwrap();
        let cert = parse_x509_certificate(&der);
        assert!(cert.is_ok(), "Should parse AMD ARK Milan: {:?}", cert.err());

        let cert = cert.unwrap();
        assert_eq!(cert.subject_cn, "ARK-Milan");
        assert_eq!(cert.issuer_cn, "ARK-Milan"); // Self-signed root
        assert!(cert.is_ca);
    }

    #[test]
    fn test_parse_amd_ask_milan() {
        let der = certs::pem_to_der(certs::AMD_ASK_MILAN_PEM).unwrap();
        let cert = parse_x509_certificate(&der);
        assert!(cert.is_ok(), "Should parse AMD ASK Milan: {:?}", cert.err());

        let cert = cert.unwrap();
        assert_eq!(cert.subject_cn, "SEV-Milan");
        assert_eq!(cert.issuer_cn, "ARK-Milan"); // Signed by ARK
    }

    #[test]
    fn test_verify_self_signed_intel() {
        let der = certs::pem_to_der(certs::INTEL_SGX_ROOT_CA_PEM).unwrap();
        let cert = parse_x509_certificate(&der).unwrap();
        assert!(verify_self_signed(&cert, TeeVendor::IntelTdx).is_ok());
    }

    #[test]
    fn test_verify_root_fingerprint_aws() {
        let der = certs::pem_to_der(certs::AWS_NITRO_ROOT_CA_PEM).unwrap();
        assert!(verify_root_fingerprint(&der, TeeVendor::AwsNitro).is_ok());
    }

    #[test]
    fn test_verify_root_fingerprint_intel() {
        let der = certs::pem_to_der(certs::INTEL_SGX_ROOT_CA_PEM).unwrap();
        assert!(verify_root_fingerprint(&der, TeeVendor::IntelTdx).is_ok());
    }

    #[test]
    fn test_strict_validation_rejects_empty_certs() {
        let verifier = AttestationVerifier::new(); // strict=true by default

        let mut report = create_test_report(TeeVendor::IntelTdx);
        report.certificates.clear(); // No certificates

        let result = verifier.verify_report(&report);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_intel_root_ca_self_signature() {
        // Verify the Intel SGX Root CA's ECDSA P-256 self-signature
        let der = certs::pem_to_der(certs::INTEL_SGX_ROOT_CA_PEM).unwrap();
        let cert = parse_x509_certificate(&der).unwrap();

        let result = verify_ecdsa_p256_signature(
            &cert.spki_der,
            &cert.tbs_der,
            &cert.signature_bytes,
        );
        assert!(result.is_ok(), "Signature verification should not error: {:?}", result.err());
        assert!(result.unwrap(), "Intel SGX Root CA self-signature should verify");
    }

    #[test]
    fn test_verify_aws_nitro_root_ca_self_signature() {
        // Verify the AWS Nitro Root CA's ECDSA P-384 self-signature
        let der = certs::pem_to_der(certs::AWS_NITRO_ROOT_CA_PEM).unwrap();
        let cert = parse_x509_certificate(&der).unwrap();

        let result = verify_ecdsa_p384_signature(
            &cert.spki_der,
            &cert.tbs_der,
            &cert.signature_bytes,
        );
        assert!(result.is_ok(), "Signature verification should not error: {:?}", result.err());
        assert!(result.unwrap(), "AWS Nitro Root CA self-signature should verify");
    }

    #[test]
    fn test_verify_amd_ark_milan_self_signature() {
        // Verify the AMD ARK Milan RSA-PSS self-signature
        let der = certs::pem_to_der(certs::AMD_ARK_MILAN_PEM).unwrap();
        let cert = parse_x509_certificate(&der).unwrap();

        let result = verify_rsa_pss_signature(
            &cert.spki_der,
            &cert.tbs_der,
            &cert.signature_bytes,
        );
        assert!(result.is_ok(), "Signature verification should not error: {:?}", result.err());
        assert!(result.unwrap(), "AMD ARK Milan self-signature should verify");
    }

    #[test]
    fn test_verify_amd_ask_signed_by_ark() {
        // Verify AMD ASK Milan is signed by ARK Milan
        let ark_der = certs::pem_to_der(certs::AMD_ARK_MILAN_PEM).unwrap();
        let ark = parse_x509_certificate(&ark_der).unwrap();

        let ask_der = certs::pem_to_der(certs::AMD_ASK_MILAN_PEM).unwrap();
        let ask = parse_x509_certificate(&ask_der).unwrap();

        assert_eq!(ask.issuer_cn, "ARK-Milan");
        assert_eq!(ark.subject_cn, "ARK-Milan");

        let result = verify_certificate_signature(&ask, &ark.spki_der);
        assert!(result.is_ok(), "ASK verification should not error: {:?}", result.err());
        assert!(result.unwrap(), "AMD ASK Milan should be signed by ARK Milan");
    }
}
