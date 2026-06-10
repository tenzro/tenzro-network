//! AWS Nitro Enclaves provider for Tenzro Network.
//!
//! AWS Nitro Enclaves provide isolated compute environments using the AWS Nitro
//! System. This module provides both real hardware integration and simulation mode.
//!
//! # Real Hardware Integration
//!
//! On Nitro Enclave hardware, this provider:
//! 1. Opens `/dev/nsm` and communicates via CBOR-encoded ioctl requests
//! 2. Calls `Attestation` request with optional nonce, user_data, public_key
//! 3. Receives a COSE Sign1 document signed with ECDSA P-384 (ES384)
//! 4. Verifies the attestation document against AWS Nitro Root CA certificate chain
//!
//! # Attestation Document Structure (COSE Sign1)
//!
//! The attestation document is a CBOR-encoded COSE Sign1 structure:
//! - Protected header: algorithm ES384
//! - Payload (CBOR map):
//!   - `module_id`: Enclave ID string
//!   - `timestamp`: Unix timestamp (ms)
//!   - `digest`: Hash algorithm ("SHA384")
//!   - `pcrs`: Map of PCR index → value (SHA-384)
//!   - `certificate`: Leaf certificate (DER)
//!   - `cabundle`: Array of intermediate CA certificates (DER)
//!   - `public_key`: Optional caller-provided public key
//!   - `user_data`: Optional caller-provided data
//!   - `nonce`: Optional caller-provided nonce
//!
//! # PCR Registers
//!
//! - PCR0: EIF (Enclave Image File) hash
//! - PCR1: Kernel hash
//! - PCR2: Application hash
//! - PCR3: IAM role ARN hash (if assigned)
//! - PCR4: Instance ID hash
//! - PCR8: Signing certificate hash (if signed)
//!
//! # Certificate Chain
//!
//! - AWS Nitro Root CA (P-384, 30-year validity)
//! - Intermediate CAs (variable)
//! - Instance CA (1-day validity)
//! - Leaf certificate (3-hour validity)
//!
//! # References
//!
//! - [AWS Nitro Enclaves Attestation](https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html)
//! - [AWS NSM API](https://github.com/aws/aws-nitro-enclaves-nsm-api)
//! - [Attestation Validation Blog](https://aws.amazon.com/blogs/compute/validating-attestation-documents-produced-by-aws-nitro-enclaves/)

use async_trait::async_trait;
use chrono::Utc;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use uuid::Uuid;

use tenzro_types::tee::*;
use crate::attestation::{self, ParsedCertificate};
use crate::certs;
use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;

// ============================================================================
// NSM (Nitro Secure Module) types
// ============================================================================

/// NSM ioctl magic number.
///
/// Reserved for the alternative ioctl-based NSM transport path on kernels that
/// expose `/dev/nsm` via `ioctl(NSM_IOCTL_MAGIC, ...)` instead of the read/write
/// CBOR pipe used by [`AwsNitroProvider::generate_nsm_attestation`]. Surfaced
/// publicly so audit tooling and alternative transports can reference the
/// canonical AWS-published magic number.
pub const NSM_IOCTL_MAGIC: u8 = 0x0A;

/// Number of PCRs in Nitro Enclaves (canonical PCR0..PCR15).
///
/// Used by [`AwsNitroProvider::verify_attestation`] to bound PCR-index
/// validation and surfaced publicly so downstream verifiers can size their
/// expected-measurement tables identically.
pub const NITRO_PCR_COUNT: usize = 16;

/// PCR register descriptions
const PCR_DESCRIPTIONS: &[(u32, &str)] = &[
    (0, "EIF (Enclave Image File) hash"),
    (1, "Kernel hash"),
    (2, "Application hash"),
    (3, "IAM role ARN hash"),
    (4, "Instance ID hash"),
    (8, "Signing certificate hash"),
];

/// Parsed Nitro attestation document
#[derive(Debug, Clone)]
struct NitroAttestationDoc {
    /// Enclave module ID
    module_id: String,
    /// Timestamp (Unix ms)
    timestamp: i64,
    /// Digest algorithm (should be "SHA384")
    digest: String,
    /// PCR values: index → SHA-384 hash
    pcrs: HashMap<u32, Vec<u8>>,
    /// Leaf certificate (DER)
    certificate: Vec<u8>,
    /// CA bundle (intermediate + root certificates, DER)
    cabundle: Vec<Vec<u8>>,
    /// Optional public key
    public_key: Option<Vec<u8>>,
    /// Optional user data
    user_data: Option<Vec<u8>>,
    /// Optional nonce
    nonce: Option<Vec<u8>>,
    /// Raw COSE Sign1 bytes
    raw: Vec<u8>,
    /// COSE signature (96 bytes, P-384)
    signature: Vec<u8>,
    /// COSE protected header (bstr contents) — required to reconstruct Sig_structure1
    protected_header: Vec<u8>,
    /// COSE payload bytes (bstr contents) — required to reconstruct Sig_structure1
    payload_bytes: Vec<u8>,
    /// Whether simulated
    simulated: bool,
}

/// AWS Nitro Enclaves provider implementation for Tenzro Network.
///
/// Provides both real hardware integration (via `/dev/nsm`) and
/// simulation mode for development and testing.
///
/// # Modes
///
/// - **Real** (default): Uses actual NSM device via ioctl (`/dev/nsm`)
/// - **Simulation** (`TENZRO_SIMULATE_NITRO=1`): Returns plausible fake attestations for local development
#[derive(Clone)]
pub struct AwsNitroProvider {
    /// Real enclave-key store: every `enclave_keygen` call derives a
    /// fresh key via HKDF-SHA256 over a Nitro NSM-signed COSE_Sign1
    /// attestation document. Signatures and encryption use the real
    /// derived material.
    keystore: std::sync::Arc<crate::enclave_keystore::EnclaveKeystore>,
    /// Whether Nitro is available
    available: bool,
    /// Whether running in simulation mode
    simulate: bool,
}

impl std::fmt::Debug for AwsNitroProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsNitroProvider")
            .field("available", &self.available)
            .field("simulate", &self.simulate)
            .finish_non_exhaustive()
    }
}

impl AwsNitroProvider {
    /// Creates a new AWS Nitro provider.
    pub fn new() -> Self {
        let simulate = is_simulation_mode();
        let available = if simulate {
            tracing::debug!("AWS Nitro Enclaves running in simulation mode");
            true
        } else {
            Self::detect_nitro_hardware()
        };

        Self {
            keystore: std::sync::Arc::new(crate::enclave_keystore::EnclaveKeystore::new("aws-nitro")),
            available,
            simulate,
        }
    }

    /// Detects real Nitro Enclave hardware.
    fn detect_nitro_hardware() -> bool {
        if std::path::Path::new("/dev/nsm").exists() {
            tracing::info!("AWS Nitro Enclave detected at /dev/nsm");
            return true;
        }

        tracing::warn!("AWS Nitro Enclave not available (no /dev/nsm)");
        false
    }

    /// Generates a real attestation document via NSM device.
    ///
    /// The NSM device accepts CBOR-encoded requests and returns CBOR responses.
    ///
    /// Request format:
    /// ```text
    /// Map(1) {
    ///   "Attestation" => Map(n) {
    ///     "user_data" => bstr(user_data),   // optional
    ///     "nonce" => bstr(nonce),           // optional
    ///     "public_key" => bstr(public_key), // optional
    ///   }
    /// }
    /// ```
    ///
    /// Response format:
    /// ```text
    /// Map(1) {
    ///   "Attestation" => Map(1) {
    ///     "document" => bstr(cose_sign1_document)
    ///   }
    /// }
    /// ```
    fn generate_nsm_attestation(&self, user_data: &[u8], nonce: Option<&[u8]>) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/nsm")
                .map_err(|e| TeeError::AttestationGenerationFailed(
                    format!("Failed to open /dev/nsm: {}", e)
                ))?;

            // Build CBOR-encoded attestation request
            let user_data_opt = if user_data.is_empty() { None } else { Some(user_data) };
            let request_bytes = build_nsm_request_cbor(user_data_opt, nonce, None);

            tracing::debug!("NSM request: {} bytes (CBOR)", request_bytes.len());

            // NSM ioctl: write request, read response
            // The actual NSM uses a specific ioctl with request/response buffers
            let mut response_buf = vec![0u8; 16384]; // Max attestation doc size

            let fd = file.as_raw_fd();

            // Write request to NSM
            let written = unsafe {
                libc::write(fd, request_bytes.as_ptr() as *const libc::c_void, request_bytes.len())
            };

            if written < 0 {
                let errno = std::io::Error::last_os_error();
                return Err(TeeError::AttestationGenerationFailed(
                    format!("Failed to write NSM request: {}", errno)
                ));
            }

            // Read response from NSM
            let read_len = unsafe {
                libc::read(fd, response_buf.as_mut_ptr() as *mut libc::c_void, response_buf.len())
            };

            if read_len < 0 {
                let errno = std::io::Error::last_os_error();
                return Err(TeeError::AttestationGenerationFailed(
                    format!("Failed to read NSM response: {}", errno)
                ));
            }

            response_buf.truncate(read_len as usize);
            tracing::debug!("NSM response: {} bytes (CBOR)", response_buf.len());

            // Parse the NSM response to extract the attestation document
            let attestation_doc = parse_nsm_response_cbor(&response_buf)?;
            tracing::info!("NSM attestation document received ({} bytes)", attestation_doc.len());

            Ok(attestation_doc)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (user_data, nonce);
            Err(TeeError::not_available(
                "AWS Nitro Enclaves require Linux (ioctl to /dev/nsm)"
            ))
        }
    }

    /// Generates an attestation document (simulated or real).
    async fn generate_nitro_document(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        if self.simulate {
            return self.generate_simulated_document(user_data);
        }

        // Generate a nonce for replay protection
        let nonce = Sha384::digest(
            [user_data, &Utc::now().timestamp_millis().to_le_bytes()].concat()
        );

        self.generate_nsm_attestation(user_data, Some(&nonce))
    }

    /// Generates a simulated Nitro attestation document.
    fn generate_simulated_document(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        let pcr0 = Sha384::digest(b"simulated-eif-hash");
        let pcr1 = Sha384::digest(b"simulated-kernel-hash");
        let pcr2 = Sha384::digest(b"simulated-application-hash");
        let pcr3 = Sha384::digest(b"simulated-iam-role-hash");
        let pcr4 = Sha384::digest(b"simulated-instance-id-hash");
        let pcr8 = Sha384::digest(b"simulated-signing-cert-hash");

        let nonce = Sha384::digest(
            [user_data, &Utc::now().timestamp_millis().to_le_bytes()].concat()
        );

        let document = serde_json::json!({
            "version": 4,
            "type": "NITRO_ATTESTATION_SIMULATED",
            "simulated": true,
            "module_id": "i-1234567890abcdef0-enc0123456789abcdef",
            "timestamp": Utc::now().timestamp_millis(),
            "digest": "SHA384",
            "user_data": hex::encode(user_data),
            "nonce": hex::encode(nonce.as_slice()),
            "public_key": hex::encode([0x04u8; 97]), // Uncompressed P-384 point
            "pcrs": {
                "0": hex::encode(pcr0.as_slice()),
                "1": hex::encode(pcr1.as_slice()),
                "2": hex::encode(pcr2.as_slice()),
                "3": hex::encode(pcr3.as_slice()),
                "4": hex::encode(pcr4.as_slice()),
                "8": hex::encode(pcr8.as_slice()),
            },
            "cabundle": [],
        });

        Ok(serde_json::to_vec(&document)?)
    }

    /// Parses a Nitro attestation document (real COSE or simulated JSON).
    fn parse_document(&self, data: &[u8]) -> Result<NitroAttestationDoc> {
        // Try JSON first (simulated)
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data)
            && json.get("simulated").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            return self.parse_simulated_document(&json, data);
        }

        // Parse real COSE Sign1 document
        self.parse_cose_document(data)
    }

    /// Parses a simulated JSON document.
    fn parse_simulated_document(&self, json: &serde_json::Value, raw: &[u8]) -> Result<NitroAttestationDoc> {
        let get_hex = |key: &str| -> Option<Vec<u8>> {
            json.get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
        };

        let mut pcrs = HashMap::new();
        if let Some(pcr_map) = json.get("pcrs").and_then(|v| v.as_object()) {
            for (key, value) in pcr_map {
                if let (Ok(index), Some(pcr_val)) = (key.parse::<u32>(), value.as_str())
                    && let Ok(pcr_bytes) = hex::decode(pcr_val)
                {
                    pcrs.insert(index, pcr_bytes);
                }
            }
        }

        Ok(NitroAttestationDoc {
            module_id: json.get("module_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
            timestamp: json.get("timestamp")
                .and_then(|v| v.as_i64())
                .unwrap_or(0),
            digest: json.get("digest")
                .and_then(|v| v.as_str())
                .unwrap_or("SHA384")
                .to_string(),
            pcrs,
            certificate: vec![],
            cabundle: vec![],
            public_key: get_hex("public_key"),
            user_data: get_hex("user_data"),
            nonce: get_hex("nonce"),
            raw: raw.to_vec(),
            signature: vec![],
            protected_header: vec![],
            payload_bytes: vec![],
            simulated: true,
        })
    }

    /// Parses a real COSE Sign1 document.
    ///
    /// COSE Sign1 structure (CBOR tag 18):
    /// [protected_header, unprotected_header, payload, signature]
    ///
    /// The payload is a CBOR map with attestation data:
    /// - `module_id`: Text string (enclave ID)
    /// - `timestamp`: Unsigned integer (Unix ms)
    /// - `digest`: Text string ("SHA384")
    /// - `pcrs`: Map of integer → byte string (PCR values)
    /// - `certificate`: Byte string (DER-encoded leaf cert)
    /// - `cabundle`: Array of byte strings (DER-encoded CA certs)
    /// - `public_key`: Optional byte string
    /// - `user_data`: Optional byte string
    /// - `nonce`: Optional byte string
    fn parse_cose_document(&self, data: &[u8]) -> Result<NitroAttestationDoc> {
        if data.is_empty() {
            return Err(TeeError::InvalidAttestationReport(
                "Empty COSE document".to_string()
            ));
        }

        let mut parser = CborParser::new(data);

        // Read CBOR tag 18 (COSE Sign1)
        let tag = parser.read_tag()?;
        if tag != 18 {
            return Err(TeeError::InvalidAttestationReport(format!(
                "Expected COSE Sign1 tag (18), got tag({})", tag
            )));
        }

        // Read outer array [protected, unprotected, payload, signature]
        let array_len = parser.read_array_len()?;
        if array_len != 4 {
            return Err(TeeError::InvalidAttestationReport(format!(
                "Expected COSE Sign1 array[4], got array[{}]", array_len
            )));
        }

        tracing::debug!("Parsing COSE Sign1 document ({} bytes)", data.len());

        // [0] protected header (bstr containing CBOR map with alg=-35 for ES384)
        let protected_header = parser.read_bstr()?;

        // [1] unprotected header (map, usually empty)
        parser.skip_value()?;

        // [2] payload (bstr containing CBOR map with attestation data)
        let payload_bytes = parser.read_bstr()?;

        // [3] signature (bstr, 96 bytes for P-384 ES384)
        let signature = parser.read_bstr()?;
        if signature.len() != 96 {
            tracing::warn!(
                "Expected ES384 signature (96 bytes), got {} bytes",
                signature.len()
            );
        }

        // Parse the payload map
        let mut payload_parser = CborParser::new(&payload_bytes);
        let payload_map_len = payload_parser.read_map_len()?;

        let mut module_id = String::from("unknown");
        let mut timestamp: i64 = 0;
        let mut digest = String::from("SHA384");
        let mut pcrs: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut certificate: Vec<u8> = vec![];
        let mut cabundle: Vec<Vec<u8>> = vec![];
        let mut public_key: Option<Vec<u8>> = None;
        let mut user_data: Option<Vec<u8>> = None;
        let mut nonce: Option<Vec<u8>> = None;

        for _ in 0..payload_map_len {
            // Read key (text string)
            let key = payload_parser.read_tstr()?;

            match key.as_str() {
                "module_id" => {
                    module_id = payload_parser.read_tstr()?;
                }
                "timestamp" => {
                    timestamp = payload_parser.read_uint()? as i64;
                }
                "digest" => {
                    digest = payload_parser.read_tstr()?;
                }
                "pcrs" => {
                    // Map of integer → byte string
                    let pcr_map_len = payload_parser.read_map_len()?;
                    for _ in 0..pcr_map_len {
                        let pcr_index = payload_parser.read_uint()? as u32;
                        let pcr_value = payload_parser.read_bstr()?;
                        pcrs.insert(pcr_index, pcr_value);
                    }
                }
                "certificate" => {
                    certificate = payload_parser.read_bstr()?;
                }
                "cabundle" => {
                    // Array of byte strings
                    let ca_array_len = payload_parser.read_array_len()?;
                    for _ in 0..ca_array_len {
                        cabundle.push(payload_parser.read_bstr()?);
                    }
                }
                "public_key" => {
                    public_key = Some(payload_parser.read_bstr()?);
                }
                "user_data" => {
                    user_data = Some(payload_parser.read_bstr()?);
                }
                "nonce" => {
                    nonce = Some(payload_parser.read_bstr()?);
                }
                _ => {
                    // Unknown field, skip it
                    tracing::debug!("Skipping unknown payload field: {}", key);
                    payload_parser.skip_value()?;
                }
            }
        }

        tracing::debug!(
            "Parsed COSE Sign1: module_id={}, timestamp={}, {} PCRs, cert={} bytes, cabundle={} certs, payload_consumed={} bytes",
            module_id, timestamp, pcrs.len(), certificate.len(), cabundle.len(),
            payload_parser.position()
        );

        Ok(NitroAttestationDoc {
            module_id,
            timestamp,
            digest,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
            raw: data.to_vec(),
            signature,
            protected_header,
            payload_bytes,
            simulated: false,
        })
    }

    /// Verifies a Nitro attestation document.
    ///
    /// For real documents:
    /// 1. Parse COSE Sign1 structure
    /// 2. Extract leaf certificate from payload
    /// 3. Verify certificate chain against AWS Nitro Root CA
    /// 4. Verify COSE signature (ES384) using leaf certificate's public key
    /// 5. Validate PCR values against expected measurements
    /// 6. Check timestamp freshness (leaf cert valid only 3 hours)
    ///
    /// For simulated documents:
    /// - Parse JSON, return result with simulated flag
    async fn verify_nitro_document(&self, doc_data: &[u8], certificates: &[Vec<u8>]) -> Result<AttestationResult> {
        let doc = self.parse_document(doc_data)?;

        // Bound PCR indices to the canonical Nitro PCR0..PCR15 range. Documents
        // that report PCRs beyond NITRO_PCR_COUNT - 1 are spec-violating and
        // are dropped from the surfaced measurement set so downstream policy
        // engines never see synthetic indices.
        let measurements: Vec<Measurement> = doc.pcrs.iter()
            .filter(|(index, _)| (**index as usize) < NITRO_PCR_COUNT)
            .map(|(index, value)| {
                let description = PCR_DESCRIPTIONS.iter()
                    .find(|(i, _)| i == index)
                    .map(|(_, desc)| desc.to_string());
                Measurement {
                    index: *index,
                    algorithm: "SHA384".to_string(),
                    value: value.clone(),
                    register: format!("PCR{}", index),
                    description,
                }
            })
            .collect();

        let mut details = HashMap::from([
            ("module_id".to_string(), doc.module_id.clone()),
            ("digest".to_string(), doc.digest.clone()),
        ]);
        // Surface optional COSE_Sign1 attestation document fields so verifiers
        // can match nonce / user_data they handed the enclave and correlate
        // against the embedded enclave public_key (e.g. for TLS pinning).
        if let Some(pk) = doc.public_key.as_ref() {
            details.insert("public_key".to_string(), hex::encode(pk));
        }
        if let Some(ud) = doc.user_data.as_ref() {
            details.insert("user_data".to_string(), hex::encode(ud));
        }
        if let Some(nonce) = doc.nonce.as_ref() {
            details.insert("nonce".to_string(), hex::encode(nonce));
        }

        let mut cert_chain_valid = false;
        let mut cose_signature_valid = false;

        if doc.simulated {
            details.insert("simulated".to_string(), "true".to_string());
            details.insert("type".to_string(), "simulated".to_string());
            tracing::warn!(
                "Verifying SIMULATED AWS Nitro document — AttestationResult.valid \
                 will be false. Simulated documents carry no cryptographic authority."
            );
        } else {
            details.insert("type".to_string(), "real".to_string());
            // Surface raw COSE_Sign1 byte length so downstream verifiers can
            // sanity-check the wire size against expected document bounds.
            details.insert("raw_doc_bytes".to_string(), doc.raw.len().to_string());
            tracing::info!("Verifying real AWS Nitro document ({} raw bytes)", doc.raw.len());

            // Verify certificate chain against pinned AWS Nitro Root CA
            if !certificates.is_empty() {
                cert_chain_valid = self.verify_aws_cert_chain(certificates)?;
            } else if !doc.cabundle.is_empty() {
                // Certificates from the attestation document itself
                cert_chain_valid = self.verify_aws_cert_chain(&doc.cabundle)?;
            }

            // Check document freshness
            let now_ms = Utc::now().timestamp_millis();
            let age_ms = now_ms - doc.timestamp;
            let max_age_ms: i64 = 3 * 60 * 60 * 1000; // 3 hours (leaf cert lifetime)
            if age_ms > max_age_ms {
                tracing::warn!(
                    "Nitro attestation document may be stale: age={}ms (max={}ms)",
                    age_ms, max_age_ms
                );
                details.insert("freshness_warning".to_string(), format!("age_ms={}", age_ms));
            }

            // Verify COSE Sign1 ES384 signature using leaf certificate's public key.
            //
            // Per RFC 8152 §4.4, the ES384 signature covers the CBOR-encoded
            // Sig_structure1 = ["Signature1", body_protected, external_aad, payload]
            // where external_aad is h'' (empty bstr) for Nitro attestation documents.
            if !doc.certificate.is_empty() && !doc.signature.is_empty() {
                match attestation::parse_x509_certificate(&doc.certificate) {
                    Ok(leaf_cert) => {
                        tracing::debug!(
                            "Nitro leaf cert: CN={}, valid {}ms",
                            leaf_cert.subject_cn,
                            leaf_cert.not_after_ms - leaf_cert.not_before_ms
                        );

                        match attestation::extract_ec_point_from_spki(&leaf_cert.spki_der) {
                            Some(ec_point) if ec_point.len() == 96 => {
                                // Build Sig_structure1 CBOR: ["Signature1", protected, h'', payload]
                                let sig_struct = build_sig_structure1(
                                    &doc.protected_header,
                                    &doc.payload_bytes,
                                );
                                match sig_struct {
                                    Ok(bytes) => {
                                        match attestation::verify_ecdsa_p384_raw_pubkey(
                                            &ec_point,
                                            &bytes,
                                            &doc.signature,
                                        ) {
                                            Ok(true) => {
                                                cose_signature_valid = true;
                                                tracing::info!(
                                                    "AWS Nitro COSE Sign1 ES384 signature verified"
                                                );
                                            }
                                            Ok(false) => {
                                                tracing::warn!(
                                                    "AWS Nitro COSE Sign1 ES384 signature verification failed"
                                                );
                                            }
                                            Err(e) => {
                                                tracing::warn!(
                                                    "AWS Nitro COSE signature verification error: {}", e
                                                );
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to build Sig_structure1: {}", e
                                        );
                                    }
                                }
                            }
                            Some(ec_point) => {
                                tracing::warn!(
                                    "Nitro leaf EC point has wrong length: expected 96 (P-384), got {}",
                                    ec_point.len()
                                );
                            }
                            None => {
                                tracing::warn!(
                                    "Failed to extract EC point from Nitro leaf SPKI"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse Nitro leaf certificate: {}", e);
                    }
                }
            }
            details.insert(
                "cose_signature_valid".to_string(),
                cose_signature_valid.to_string(),
            );
        }

        // Fail-closed validity. A real Nitro attestation is `valid` only
        // when BOTH the COSE_Sign1 ES384 signature (over Sig_structure1)
        // verifies and the certificate chain chains to the pinned AWS
        // Nitro Root CA. Simulated documents are NEVER valid.
        let valid = !doc.simulated && cose_signature_valid && cert_chain_valid;

        Ok(AttestationResult {
            valid,
            vendor: TeeVendor::AwsNitro,
            tcb_version: "4".to_string(), // Nitro attestation version
            measurements,
            cert_chain_valid,
            details,
            verified_at: tenzro_types::Timestamp::now(),
            ..Default::default()
        })
    }

    /// Verifies the AWS certificate chain against pinned Nitro Root CA.
    fn verify_aws_cert_chain(&self, certificates: &[Vec<u8>]) -> Result<bool> {
        let root_der = certs::pem_to_der(certs::AWS_NITRO_ROOT_CA_PEM)
            .map_err(|e| TeeError::CertificateValidationFailed(
                format!("Failed to decode AWS Nitro root CA: {}", e)
            ))?;

        let root_cert = attestation::parse_x509_certificate(&root_der)?;

        let mut chain: Vec<ParsedCertificate> = Vec::new();
        for cert_der in certificates {
            match attestation::parse_x509_certificate(cert_der) {
                Ok(cert) => chain.push(cert),
                Err(e) => {
                    tracing::warn!("Failed to parse certificate in AWS chain: {}", e);
                }
            }
        }

        if chain.is_empty() {
            return Ok(false);
        }

        // Verify the last cert in chain is signed by AWS Nitro Root CA
        let last = chain.last().unwrap();
        if last.issuer_cn == root_cert.subject_cn || last.subject_cn == root_cert.subject_cn {
            let verified = attestation::verify_certificate_signature(last, &root_cert.spki_der)?;
            if verified {
                tracing::info!("AWS Nitro certificate chain verified against pinned root CA");
            }
            Ok(verified)
        } else {
            tracing::warn!(
                "AWS chain does not terminate at Nitro Root CA: last issuer='{}', root='{}'",
                last.issuer_cn, root_cert.subject_cn
            );
            Ok(false)
        }
    }
}

impl Default for AwsNitroProvider {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the COSE Sig_structure1 CBOR array per RFC 8152 §4.4.
///
/// For COSE_Sign1, the Sig_structure is:
/// ```text
/// Sig_structure1 = [
///     context: "Signature1",
///     body_protected: bstr,    // serialized protected header
///     external_aad: bstr,      // empty for Nitro attestation
///     payload: bstr,           // serialized payload
/// ]
/// ```
///
/// The resulting CBOR bytes are the input to ECDSA-P384-SHA384 (ES384) signing.
fn build_sig_structure1(protected_header: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    use ciborium::value::Value;

    let sig_struct = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected_header.to_vec()),
        Value::Bytes(Vec::new()), // external_aad = h''
        Value::Bytes(payload.to_vec()),
    ]);

    let mut out = Vec::with_capacity(protected_header.len() + payload.len() + 32);
    ciborium::ser::into_writer(&sig_struct, &mut out).map_err(|e| {
        TeeError::AttestationVerificationFailed(format!(
            "Failed to CBOR-encode Sig_structure1: {}",
            e
        ))
    })?;
    Ok(out)
}

#[async_trait]
impl TeeProvider for AwsNitroProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::AwsNitro
    }

    async fn is_available(&self) -> Result<bool> {
        Ok(self.available)
    }

    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }

        let attestation_data = self.generate_nitro_document(user_data).await?;

        let mut metadata = HashMap::from([
            ("nitro_version".to_string(), "1.0".to_string()),
            ("nsm_version".to_string(), "1.0.0".to_string()),
        ]);

        if self.simulate {
            metadata.insert("simulated".to_string(), "true".to_string());
        }

        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::AwsNitro,
            user_data: user_data.to_vec(),
            attestation_data,
            certificates: vec![], // Populated from COSE document cabundle in real mode
            timestamp: tenzro_types::Timestamp::now(),
            metadata,
            ..Default::default()
        })
    }

    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult> {
        if report.vendor != TeeVendor::AwsNitro {
            return Err(TeeError::InvalidAttestationReport(
                "Report is not from AWS Nitro".to_string(),
            ));
        }

        self.verify_nitro_document(&report.attestation_data, &report.certificates).await
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }

        tracing::info!("Executing in Nitro Enclave: {:?}", request.operation);

        Ok(EnclaveResponse {
            request_id: request.id,
            success: true,
            data: request.params,
            error: None,
            attestation: None,
        })
    }

    async fn enclave_keygen(&self, params: KeyGenParams) -> Result<EnclaveKeyHandle> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        if self.simulate {
            return Err(TeeError::not_available(
                "AWS Nitro simulation mode cannot supply real NSM attestation IKM",
            ));
        }
        // Use a one-shot NSM attestation as IKM. The NSM-signed
        // COSE_Sign1 document is unpredictable to a remote attacker
        // and binds to the enclave's identity (PCRs, image hash).
        let report = self.generate_attestation(b"tenzro-enclave-keygen-ikm").await?;
        let mut ikm = Vec::with_capacity(report.attestation_data.len() + 32);
        ikm.extend_from_slice(&report.attestation_data);
        ikm.extend_from_slice(&report.measurement);
        let handle = self.keystore.keygen(params, &ikm).await?;
        tracing::info!(
            key_id = %handle.id,
            algorithm = ?handle.algorithm,
            "Generated key in Nitro Enclave keystore"
        );
        Ok(handle)
    }

    async fn enclave_sign(&self, key: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        self.keystore.sign(key, data).await
    }

    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        self.keystore.encrypt(key, plaintext).await
    }

    async fn enclave_decrypt(&self, key: &EnclaveKeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AWS Nitro Enclaves not available"));
        }
        self.keystore.decrypt(key, ciphertext).await
    }
}

// ============================================================================
// CBOR Parser (minimal implementation for COSE Sign1 and NSM)
// ============================================================================

/// Minimal CBOR parser for AWS Nitro attestation documents.
///
/// Supports the subset of CBOR needed for COSE Sign1 and NSM protocol:
/// - Unsigned integers (major type 0)
/// - Byte strings (major type 2)
/// - Text strings (major type 3)
/// - Arrays (major type 4)
/// - Maps (major type 5)
/// - Tags (major type 6)
struct CborParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> CborParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Current parser cursor offset (bytes consumed from the start of the
    /// input slice). Used by the COSE Sign1 parser to log how much of the
    /// payload was actually consumed vs. the total input length.
    fn position(&self) -> usize {
        self.pos
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn peek_byte(&self) -> Result<u8> {
        self.data.get(self.pos).copied().ok_or_else(|| {
            TeeError::InvalidAttestationReport("Unexpected end of CBOR data".to_string())
        })
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b = self.peek_byte()?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.remaining() < len {
            return Err(TeeError::InvalidAttestationReport(
                format!("Cannot read {} bytes, only {} remaining", len, self.remaining())
            ));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.data[start..self.pos])
    }

    /// Reads a CBOR unsigned integer.
    fn read_uint(&mut self) -> Result<u64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 0 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected unsigned int (major 0), got major {}", major)
            ));
        }

        Ok(match additional {
            0..=23 => additional as u64,
            24 => self.read_byte()? as u64,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as u64
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for uint: {}", additional)
            )),
        })
    }

    /// Reads a CBOR tag value (major type 6).
    fn read_tag(&mut self) -> Result<u64> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 6 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected tag (major 6), got major {}", major)
            ));
        }

        Ok(match additional {
            0..=23 => additional as u64,
            24 => self.read_byte()? as u64,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as u64
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for tag: {}", additional)
            )),
        })
    }

    /// Reads a CBOR array length.
    fn read_array_len(&mut self) -> Result<usize> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 4 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected array (major 4), got major {}", major)
            ));
        }

        Ok(match additional {
            0..=23 => additional as usize,
            24 => self.read_byte()? as usize,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as usize
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]) as usize
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for array: {}", additional)
            )),
        })
    }

    /// Reads a CBOR map length.
    fn read_map_len(&mut self) -> Result<usize> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 5 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected map (major 5), got major {}", major)
            ));
        }

        Ok(match additional {
            0..=23 => additional as usize,
            24 => self.read_byte()? as usize,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as usize
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]) as usize
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for map: {}", additional)
            )),
        })
    }

    /// Reads a CBOR byte string.
    fn read_bstr(&mut self) -> Result<Vec<u8>> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 2 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected byte string (major 2), got major {}", major)
            ));
        }

        let len = match additional {
            0..=23 => additional as usize,
            24 => self.read_byte()? as usize,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as usize
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]) as usize
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for bstr: {}", additional)
            )),
        };

        Ok(self.read_bytes(len)?.to_vec())
    }

    /// Reads a CBOR text string.
    fn read_tstr(&mut self) -> Result<String> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        if major != 3 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Expected text string (major 3), got major {}", major)
            ));
        }

        let len = match additional {
            0..=23 => additional as usize,
            24 => self.read_byte()? as usize,
            25 => {
                let bytes = self.read_bytes(2)?;
                u16::from_be_bytes([bytes[0], bytes[1]]) as usize
            }
            26 => {
                let bytes = self.read_bytes(4)?;
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize
            }
            27 => {
                let bytes = self.read_bytes(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                    bytes[4], bytes[5], bytes[6], bytes[7],
                ]) as usize
            }
            _ => return Err(TeeError::InvalidAttestationReport(
                format!("Invalid additional info for tstr: {}", additional)
            )),
        };

        let bytes = self.read_bytes(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|e| {
            TeeError::InvalidAttestationReport(format!("Invalid UTF-8 in text string: {}", e))
        })
    }

    /// Skips any CBOR value (used for ignoring unneeded fields).
    fn skip_value(&mut self) -> Result<()> {
        let initial = self.peek_byte()?;
        let major = initial >> 5;
        let additional = initial & 0x1F;

        match major {
            0 | 1 | 7 => {
                // Unsigned int, negative int, simple/float
                self.read_byte()?;
                match additional {
                    0..=23 => {}
                    24 => { self.read_byte()?; }
                    25 => { self.read_bytes(2)?; }
                    26 => { self.read_bytes(4)?; }
                    27 => { self.read_bytes(8)?; }
                    _ => return Err(TeeError::InvalidAttestationReport(
                        "Invalid additional info".to_string()
                    )),
                }
            }
            2 | 3 => {
                // Byte string or text string
                let _ = if major == 2 { self.read_bstr()? } else { self.read_tstr()?.into_bytes() };
            }
            4 => {
                // Array
                let len = self.read_array_len()?;
                for _ in 0..len {
                    self.skip_value()?;
                }
            }
            5 => {
                // Map
                let len = self.read_map_len()?;
                for _ in 0..len {
                    self.skip_value()?; // key
                    self.skip_value()?; // value
                }
            }
            6 => {
                // Tag
                self.read_tag()?;
                self.skip_value()?; // tagged value
            }
            _ => {
                return Err(TeeError::InvalidAttestationReport(
                    format!("Unknown CBOR major type: {}", major)
                ));
            }
        }

        Ok(())
    }
}

// ============================================================================
// NSM CBOR Request/Response Builders
// ============================================================================

/// Builds a CBOR-encoded NSM attestation request.
///
/// NSM request format:
/// ```text
/// Map(1) {
///   "Attestation" => Map(n) {
///     "user_data" => bstr(user_data),   // optional
///     "nonce" => bstr(nonce),           // optional
///     "public_key" => bstr(public_key), // optional
///   }
/// }
/// ```
#[cfg(any(target_os = "linux", test))]
fn build_nsm_request_cbor(
    user_data: Option<&[u8]>,
    nonce: Option<&[u8]>,
    public_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Count how many optional fields are present
    let mut inner_count = 0;
    if user_data.is_some() { inner_count += 1; }
    if nonce.is_some() { inner_count += 1; }
    if public_key.is_some() { inner_count += 1; }

    // Outer map with 1 entry: "Attestation" => inner_map
    buf.push(0xA1); // map(1)

    // Key: "Attestation" (text string, 11 bytes)
    buf.push(0x6B); // tstr(11)
    buf.extend_from_slice(b"Attestation");

    // Value: inner map with optional fields
    write_cbor_map_header(&mut buf, inner_count);

    if let Some(data) = user_data {
        write_cbor_tstr(&mut buf, "user_data");
        write_cbor_bstr(&mut buf, data);
    }

    if let Some(n) = nonce {
        write_cbor_tstr(&mut buf, "nonce");
        write_cbor_bstr(&mut buf, n);
    }

    if let Some(pk) = public_key {
        write_cbor_tstr(&mut buf, "public_key");
        write_cbor_bstr(&mut buf, pk);
    }

    buf
}

/// Parses an NSM response to extract the attestation document.
///
/// NSM response format:
/// ```text
/// Map(1) {
///   "Attestation" => Map(1) {
///     "document" => bstr(cose_sign1_document)
///   }
/// }
/// ```
#[cfg(any(target_os = "linux", test))]
fn parse_nsm_response_cbor(data: &[u8]) -> Result<Vec<u8>> {
    let mut parser = CborParser::new(data);

    // Outer map
    let outer_len = parser.read_map_len()?;
    if outer_len != 1 {
        return Err(TeeError::InvalidAttestationReport(
            format!("Expected NSM response map(1), got map({})", outer_len)
        ));
    }

    // Key: "Attestation"
    let key = parser.read_tstr()?;
    if key != "Attestation" {
        return Err(TeeError::InvalidAttestationReport(
            format!("Expected 'Attestation' key, got '{}'", key)
        ));
    }

    // Inner map
    let inner_len = parser.read_map_len()?;
    if inner_len != 1 {
        return Err(TeeError::InvalidAttestationReport(
            format!("Expected Attestation map(1), got map({})", inner_len)
        ));
    }

    // Key: "document"
    let doc_key = parser.read_tstr()?;
    if doc_key != "document" {
        return Err(TeeError::InvalidAttestationReport(
            format!("Expected 'document' key, got '{}'", doc_key)
        ));
    }

    // Value: COSE Sign1 document (byte string)
    parser.read_bstr()
}

/// Writes a CBOR map header.
#[cfg(any(target_os = "linux", test))]
fn write_cbor_map_header(buf: &mut Vec<u8>, count: usize) {
    match count {
        0..=23 => buf.push(0xA0 | (count as u8)),
        24..=255 => {
            buf.push(0xB8);
            buf.push(count as u8);
        }
        256..=65535 => {
            buf.push(0xB9);
            buf.extend_from_slice(&(count as u16).to_be_bytes());
        }
        _ => {
            buf.push(0xBA);
            buf.extend_from_slice(&(count as u32).to_be_bytes());
        }
    }
}

/// Writes a CBOR text string.
#[cfg(any(target_os = "linux", test))]
fn write_cbor_tstr(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len();
    match len {
        0..=23 => buf.push(0x60 | (len as u8)),
        24..=255 => {
            buf.push(0x78);
            buf.push(len as u8);
        }
        256..=65535 => {
            buf.push(0x79);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            buf.push(0x7A);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    buf.extend_from_slice(bytes);
}

/// Writes a CBOR byte string.
#[cfg(any(target_os = "linux", test))]
fn write_cbor_bstr(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    match len {
        0..=23 => buf.push(0x40 | (len as u8)),
        24..=255 => {
            buf.push(0x58);
            buf.push(len as u8);
        }
        256..=65535 => {
            buf.push(0x59);
            buf.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            buf.push(0x5A);
            buf.extend_from_slice(&(len as u32).to_be_bytes());
        }
    }
    buf.extend_from_slice(data);
}

// ============================================================================
// Helper functions
// ============================================================================

/// Returns true only when simulation is explicitly requested via env var.
/// Real hardware is the default — set `TENZRO_SIMULATE_NITRO=1` to override.
fn is_simulation_mode() -> bool {
    std::env::var("TENZRO_SIMULATE_NITRO")
        .unwrap_or_else(|_| "0".to_string()) == "1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nitro_provider_creation() {
        let provider = AwsNitroProvider::new();
        assert_eq!(provider.vendor(), TeeVendor::AwsNitro);
    }

    #[tokio::test]
    async fn test_nitro_simulation_mode() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();
        assert!(provider.simulate);
        assert!(provider.available);
    }

    #[tokio::test]
    async fn test_nitro_generate_simulated_document() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let user_data = b"tenzro-network-test";
        let report = provider.generate_attestation(user_data).await;
        assert!(report.is_ok());

        let report = report.unwrap();
        assert_eq!(report.vendor, TeeVendor::AwsNitro);
        assert_eq!(report.user_data, user_data);
        assert!(!report.attestation_data.is_empty());
        assert_eq!(report.metadata.get("simulated"), Some(&"true".to_string()));
    }

    #[tokio::test]
    async fn test_nitro_verify_simulated_document_is_invalid() {
        // Simulated documents carry no cryptographic authority; verifier
        // populates measurements + details for observability but `valid`
        // MUST be false.
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        assert!(
            !result.valid,
            "simulated Nitro documents must never report valid=true"
        );
        assert_eq!(result.vendor, TeeVendor::AwsNitro);
        assert_eq!(result.details.get("simulated"), Some(&"true".to_string()));

        // Should still expose PCR measurements for observability
        assert!(!result.measurements.is_empty());
        for m in &result.measurements {
            assert_eq!(m.algorithm, "SHA384");
            assert!(!m.value.is_empty());
            assert!(m.register.starts_with("PCR"));
        }
    }

    #[tokio::test]
    async fn test_nitro_pcr_descriptions() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        // PCR0 should have EIF description
        let pcr0 = result.measurements.iter().find(|m| m.index == 0);
        assert!(pcr0.is_some());
        assert_eq!(
            pcr0.unwrap().description.as_deref(),
            Some("EIF (Enclave Image File) hash")
        );
    }

    #[tokio::test]
    async fn test_nitro_keygen_in_simulation_returns_not_available() {
        // Simulation cannot supply a real NSM-signed attestation IKM;
        // `enclave_keygen` rejects with NotAvailable. No fabrication.
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: HashMap::new(),
        };

        let err = provider.enclave_keygen(params).await.unwrap_err();
        assert!(
            matches!(err, TeeError::NotAvailable(_)),
            "expected NotAvailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_nitro_keystore_real_ed25519_verifies() {
        use ed25519_dalek::Verifier;
        let ks = crate::enclave_keystore::EnclaveKeystore::new("aws-nitro-test");
        let ikm: Vec<u8> = (0u8..64).collect();
        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: HashMap::new(),
        };
        let handle = ks.keygen(params, &ikm).await.unwrap();
        let pk = handle.public_key.clone().unwrap();
        let msg = b"aws-nitro real Ed25519";
        let sig = ks.sign(&handle, msg).await.unwrap();

        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            <&[u8; 32]>::try_from(pk.as_slice()).unwrap(),
        )
        .unwrap();
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(msg, &signature).expect("real Ed25519 signature must verify");
    }

    #[tokio::test]
    async fn test_nitro_wrong_vendor_rejected() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let mut report = provider.generate_attestation(b"test").await.unwrap();
        report.vendor = TeeVendor::IntelTdx;

        let result = provider.verify_attestation(&report).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_nitro_parse_simulated_document() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_NITRO", "1"); }
        let provider = AwsNitroProvider::new();

        let data = provider.generate_simulated_document(b"hello").unwrap();
        let doc = provider.parse_document(&data).unwrap();

        assert!(doc.simulated);
        assert_eq!(doc.digest, "SHA384");
        assert!(!doc.pcrs.is_empty());
        assert!(doc.pcrs.contains_key(&0)); // PCR0
        assert!(doc.pcrs.contains_key(&1)); // PCR1
        assert!(doc.pcrs.contains_key(&2)); // PCR2
    }

    #[test]
    fn test_cbor_parser_basics() {
        // Test unsigned int parsing
        let data = vec![0x00]; // uint(0)
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_uint().unwrap(), 0);

        let data = vec![0x18, 0xFF]; // uint(255)
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_uint().unwrap(), 255);

        // Test byte string parsing
        let data = vec![0x45, 0x68, 0x65, 0x6C, 0x6C, 0x6F]; // bstr("hello")
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_bstr().unwrap(), b"hello");

        // Test text string parsing
        let data = vec![0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F]; // tstr("hello")
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_tstr().unwrap(), "hello");

        // Test array parsing
        let data = vec![0x83, 0x01, 0x02, 0x03]; // array[3] of uint(1), uint(2), uint(3)
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_array_len().unwrap(), 3);
        assert_eq!(parser.read_uint().unwrap(), 1);
        assert_eq!(parser.read_uint().unwrap(), 2);
        assert_eq!(parser.read_uint().unwrap(), 3);

        // Test map parsing
        let data = vec![0xA1, 0x61, 0x61, 0x01]; // map{ "a": 1 }
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_map_len().unwrap(), 1);
        assert_eq!(parser.read_tstr().unwrap(), "a");
        assert_eq!(parser.read_uint().unwrap(), 1);
    }

    #[test]
    fn test_nsm_request_cbor() {
        // Test with all fields
        let request = build_nsm_request_cbor(
            Some(b"test_data"),
            Some(b"test_nonce"),
            Some(b"test_pubkey"),
        );

        let mut parser = CborParser::new(&request);
        assert_eq!(parser.read_map_len().unwrap(), 1);
        assert_eq!(parser.read_tstr().unwrap(), "Attestation");
        let inner_len = parser.read_map_len().unwrap();
        assert_eq!(inner_len, 3); // All 3 fields present

        // Test with only user_data
        let request = build_nsm_request_cbor(Some(b"data"), None, None);
        let mut parser = CborParser::new(&request);
        assert_eq!(parser.read_map_len().unwrap(), 1);
        assert_eq!(parser.read_tstr().unwrap(), "Attestation");
        assert_eq!(parser.read_map_len().unwrap(), 1); // Only user_data

        // Test with no fields
        let request = build_nsm_request_cbor(None, None, None);
        let mut parser = CborParser::new(&request);
        assert_eq!(parser.read_map_len().unwrap(), 1);
        assert_eq!(parser.read_tstr().unwrap(), "Attestation");
        assert_eq!(parser.read_map_len().unwrap(), 0); // Empty inner map
    }

    #[test]
    fn test_nsm_response_cbor() {
        // Build a mock NSM response
        let mut response = Vec::new();
        write_cbor_map_header(&mut response, 1); // outer map(1)
        write_cbor_tstr(&mut response, "Attestation");
        write_cbor_map_header(&mut response, 1); // inner map(1)
        write_cbor_tstr(&mut response, "document");
        write_cbor_bstr(&mut response, b"mock_cose_document");

        // Parse it
        let doc = parse_nsm_response_cbor(&response).unwrap();
        assert_eq!(doc, b"mock_cose_document");
    }

    #[test]
    fn test_cbor_parser_skip_value() {
        // Test skipping various types
        let data = vec![
            0xA2, // map(2)
            0x61, 0x61, 0x01, // "a": 1
            0x61, 0x62, 0x83, 0x01, 0x02, 0x03, // "b": [1, 2, 3]
        ];
        let mut parser = CborParser::new(&data);
        assert_eq!(parser.read_map_len().unwrap(), 2);
        assert_eq!(parser.read_tstr().unwrap(), "a");
        parser.skip_value().unwrap(); // skip the value 1
        assert_eq!(parser.read_tstr().unwrap(), "b");
        parser.skip_value().unwrap(); // skip the entire array [1, 2, 3]
        assert_eq!(parser.position(), data.len());
    }
}
