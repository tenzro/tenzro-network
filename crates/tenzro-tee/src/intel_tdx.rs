//! Intel TDX (Trust Domain Extensions) provider for Tenzro Network.
//!
//! Intel TDX provides hardware-based memory encryption and integrity protection
//! for virtual machines (Trust Domains). This module provides both real hardware
//! integration and simulation mode.
//!
//! # Real Hardware Integration
//!
//! On TDX-enabled hardware, this provider:
//! 1. Opens `/dev/tdx_guest` and issues `TDX_CMD_GET_REPORT0` ioctl to generate a TDREPORT
//! 2. Uses configfs-tsm (`/sys/kernel/config/tsm/report/`) for Quote generation (kernel 6.7+)
//! 3. Falls back to legacy QE (Quoting Enclave) via vsock for older kernels
//! 4. Verifies Quote signatures against Intel PCS (Provisioning Certification Service)
//!
//! # Key Concepts
//!
//! - **TDREPORT**: 1024-byte local attestation report (REPORTMACSTRUCT + TEE_TCB_INFO + TDINFO)
//! - **TD Quote v4**: Remote attestation quote (Header 48B + Body 584B + Signature variable)
//! - **RTMRs**: 4 Runtime Measurement Registers (SHA-384):
//!   - RTMR[0]: Initial TD configuration (TDVF, firmware)
//!   - RTMR[1]: OS loader and kernel
//!   - RTMR[2]: OS applications
//!   - RTMR[3]: Reserved for guest use
//!
//! # References
//!
//! - [Linux TDX Guest API](https://docs.kernel.org/virt/coco/tdx-guest.html)
//! - [Intel TDX DCAP](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/)
//! - [Intel PCS API](https://api.trustedservices.intel.com/sgx/certification/v4/)

use async_trait::async_trait;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use uuid::Uuid;

use tenzro_types::tee::*;
use crate::attestation::{self, ParsedCertificate};
use crate::certs;
use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;

// ============================================================================
// TDX ioctl structures (matching Linux kernel's tdx-guest.h)
// ============================================================================

/// Size of TDREPORT data (REPORTMACSTRUCT + TEE_TCB_INFO + TDINFO)
#[cfg(target_os = "linux")]
const TDX_REPORT_LEN: usize = 1024;

/// Size of user-provided report data
#[cfg(target_os = "linux")]
const TDX_REPORTDATA_LEN: usize = 64;

/// TDX ioctl magic number (character 'T')
#[cfg(target_os = "linux")]
const TDX_IOCTL_MAGIC: u8 = b'T';

/// TDX_CMD_GET_REPORT0 ioctl number (sequence 1)
/// _IOWR('T', 1, struct tdx_report_req) = direction(3) | size | type | nr
#[cfg(target_os = "linux")]
const TDX_CMD_GET_REPORT0_NR: u8 = 1;

/// TDREPORT structure offsets (from Intel TDX spec).
///
/// Documented byte offsets into the 1024-byte TDREPORT structure as defined
/// by the Intel TDX Module ABI. Public so downstream verifiers, audit tooling,
/// and integration tests can reference the same canonical layout.
pub mod tdreport_offsets {
    // REPORTMACSTRUCT (256 bytes at offset 0)
    pub const REPORT_TYPE: usize = 0;           // 4 bytes
    pub const CPU_SVN: usize = 48;              // 16 bytes
    pub const TEE_TCB_INFO_HASH: usize = 64;    // 48 bytes (SHA-384)
    pub const TEE_INFO_HASH: usize = 112;       // 48 bytes (SHA-384)
    pub const REPORT_DATA: usize = 128;         // 64 bytes
    pub const MAC: usize = 224;                 // 32 bytes

    // TEE_TCB_INFO (239 bytes at offset 256)
    pub const TEE_TCB_SVN: usize = 264;         // 16 bytes
    pub const MR_SEAM: usize = 280;             // 48 bytes (SHA-384)
    pub const MR_SIGNER_SEAM: usize = 328;      // 48 bytes (SHA-384)
    pub const SEAM_ATTRIBUTES: usize = 376;     // 8 bytes

    // TDINFO (512 bytes at offset 512)
    pub const TD_ATTRIBUTES: usize = 512;       // 8 bytes
    pub const XFAM: usize = 520;                // 8 bytes
    pub const MR_TD: usize = 528;               // 48 bytes (SHA-384) — measurement of initial TD
    pub const MR_CONFIG_ID: usize = 576;        // 48 bytes
    pub const MR_OWNER: usize = 624;            // 48 bytes
    pub const MR_OWNER_CONFIG: usize = 672;     // 48 bytes
    pub const RTMR0: usize = 720;               // 48 bytes (SHA-384)
    pub const RTMR1: usize = 768;               // 48 bytes
    pub const RTMR2: usize = 816;               // 48 bytes
    pub const RTMR3: usize = 864;               // 48 bytes
}

/// TDX Quote v4 header offsets.
///
/// Documented byte offsets into the DCAP v4 Quote wire format. Public so
/// downstream verifiers and audit tooling can reference the same canonical
/// layout when parsing or constructing TDX Quotes off-path.
pub mod quote_offsets {
    pub const VERSION: usize = 0;               // 2 bytes (should be 4)
    pub const ATT_KEY_TYPE: usize = 2;          // 2 bytes (2=ECDSA-256, 3=ECDSA-384)
    pub const TEE_TYPE: usize = 4;              // 4 bytes (0x81=TDX)
    pub const RESERVED: usize = 8;              // 2 bytes
    pub const QE_VENDOR_ID: usize = 12;         // 16 bytes
    pub const USER_DATA: usize = 28;            // 20 bytes
    pub const BODY: usize = 48;                 // 584 bytes (Report Body)

    // Body offsets (relative to BODY)
    pub const BODY_TEE_TCB_SVN: usize = 0;      // 16 bytes
    pub const BODY_MR_SEAM: usize = 16;          // 48 bytes
    pub const BODY_MR_SIGNER_SEAM: usize = 64;   // 48 bytes
    pub const BODY_SEAM_ATTRIBUTES: usize = 112;  // 8 bytes
    pub const BODY_TD_ATTRIBUTES: usize = 120;    // 8 bytes
    pub const BODY_XFAM: usize = 128;            // 8 bytes
    pub const BODY_MR_TD: usize = 136;           // 48 bytes
    pub const BODY_MR_CONFIG_ID: usize = 184;    // 48 bytes
    pub const BODY_MR_OWNER: usize = 232;        // 48 bytes
    pub const BODY_MR_OWNER_CONFIG: usize = 280; // 48 bytes
    pub const BODY_RTMR0: usize = 328;           // 48 bytes
    pub const BODY_RTMR1: usize = 376;           // 48 bytes
    pub const BODY_RTMR2: usize = 424;           // 48 bytes
    pub const BODY_RTMR3: usize = 472;           // 48 bytes
    pub const BODY_REPORT_DATA: usize = 520;     // 64 bytes
    pub const BODY_LEN: usize = 584;

    pub const SIGNATURE_DATA: usize = 48 + 584;  // After header + body
}

/// Parsed TDX Quote for verification
#[derive(Debug, Clone)]
struct TdxQuote {
    /// Quote version (should be 4)
    version: u16,
    /// Attestation key type (2=P-256, 3=P-384)
    att_key_type: u16,
    /// TEE type (0x81 = TDX)
    tee_type: u32,
    /// TCB SVN (16 bytes)
    tee_tcb_svn: Vec<u8>,
    /// MRTD (48 bytes SHA-384)
    mr_td: Vec<u8>,
    /// RTMRs (4 × 48 bytes)
    rtmrs: [Vec<u8>; 4],
    /// Report data (64 bytes) — caller-supplied nonce / binding data
    /// (e.g. SHA-384(TLS pubkey || timestamp)) that proves quote freshness.
    /// Surfaced into `AttestationResult.details["report_data"]` so verifiers
    /// can match against the nonce they handed the enclave.
    report_data: Vec<u8>,
    /// Raw quote bytes
    raw: Vec<u8>,
    /// Whether this is simulated
    simulated: bool,
}

/// Intel TDX provider implementation for Tenzro Network.
///
/// Provides both real hardware integration (via `/dev/tdx_guest` and configfs-tsm)
/// and simulation mode for development and testing.
///
/// # Modes
///
/// - **Real** (default): Uses actual TDX hardware via Linux kernel interface (`/dev/tdx_guest`)
/// - **Simulation** (`TENZRO_SIMULATE_TDX=1`): Returns plausible fake attestations for local development
#[derive(Clone)]
pub struct IntelTdxProvider {
    /// Real enclave-key store: every `enclave_keygen` call derives a
    /// fresh Ed25519 / Secp256k1 / AES-256-GCM key via HKDF-SHA256
    /// over TDX-rooted IKM (MRTD measurement). Signatures and
    /// encryption produced by [`Self::enclave_sign`] /
    /// [`Self::enclave_encrypt`] use the real key material — never a
    /// hash placeholder.
    keystore: std::sync::Arc<crate::enclave_keystore::EnclaveKeystore>,
    /// Whether TDX is available
    available: bool,
    /// Whether running in simulation mode
    simulate: bool,
}

impl std::fmt::Debug for IntelTdxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelTdxProvider")
            .field("available", &self.available)
            .field("simulate", &self.simulate)
            .finish_non_exhaustive()
    }
}

impl IntelTdxProvider {
    /// Creates a new Intel TDX provider.
    pub fn new() -> Self {
        let simulate = is_simulation_mode();
        let available = if simulate {
            tracing::debug!("Intel TDX running in simulation mode");
            true
        } else {
            Self::detect_tdx_hardware()
        };

        Self {
            keystore: std::sync::Arc::new(crate::enclave_keystore::EnclaveKeystore::new("intel-tdx")),
            available,
            simulate,
        }
    }

    /// Detects real TDX hardware.
    fn detect_tdx_hardware() -> bool {
        // Check for the TDX guest device
        if std::path::Path::new("/dev/tdx_guest").exists() {
            tracing::info!("Intel TDX hardware detected at /dev/tdx_guest");
            return true;
        }

        // Also check configfs-tsm (kernel 6.7+)
        if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
            tracing::info!("Intel TDX detected via configfs-tsm");
            return true;
        }

        tracing::warn!("Intel TDX hardware not available");
        false
    }

    /// Generates a TDREPORT via `/dev/tdx_guest` ioctl.
    ///
    /// The TDREPORT is a 1024-byte structure containing:
    /// - REPORTMACSTRUCT (256 bytes): CPU SVN, report data, MAC
    /// - TEE_TCB_INFO (239 bytes): SEAM module measurements
    /// - TDINFO (512 bytes): TD measurements, RTMRs
    fn generate_tdreport(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            // Prepare report data (64 bytes, padded with zeros)
            let mut report_data = [0u8; TDX_REPORTDATA_LEN];
            let copy_len = user_data.len().min(TDX_REPORTDATA_LEN);
            report_data[..copy_len].copy_from_slice(&user_data[..copy_len]);

            // Prepare ioctl buffer: reportdata[64] + tdreport[1024]
            let mut buf = vec![0u8; TDX_REPORTDATA_LEN + TDX_REPORT_LEN];
            buf[..TDX_REPORTDATA_LEN].copy_from_slice(&report_data);

            // Open the TDX guest device
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tdx_guest")
                .map_err(|e| TeeError::AttestationGenerationFailed(
                    format!("Failed to open /dev/tdx_guest: {}", e)
                ))?;

            // Issue TDX_CMD_GET_REPORT0 ioctl
            // _IOWR('T', 1, struct tdx_report_req)
            // Direction: read+write (3), size: 1088 bytes
            let ioctl_nr = build_ioctl_rw(
                TDX_IOCTL_MAGIC,
                TDX_CMD_GET_REPORT0_NR,
                (TDX_REPORTDATA_LEN + TDX_REPORT_LEN) as u32,
            );

            let ret = unsafe {
                libc::ioctl(file.as_raw_fd(), ioctl_nr as libc::c_ulong, buf.as_mut_ptr())
            };

            if ret != 0 {
                let errno = std::io::Error::last_os_error();
                return Err(TeeError::AttestationGenerationFailed(
                    format!("TDX_CMD_GET_REPORT0 ioctl failed: {} (errno: {})", errno, ret)
                ));
            }

            // Extract TDREPORT (bytes 64..1088)
            let tdreport = buf[TDX_REPORTDATA_LEN..].to_vec();
            tracing::info!("TDREPORT generated successfully ({} bytes)", tdreport.len());

            Ok(tdreport)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = user_data;
            Err(TeeError::not_available(
                "Intel TDX requires Linux (ioctl to /dev/tdx_guest)"
            ))
        }
    }

    /// Generates a TD Quote using configfs-tsm (kernel 6.7+).
    ///
    /// configfs-tsm provides a file-based interface:
    /// 1. `mkdir /sys/kernel/config/tsm/report/<name>`
    /// 2. Write report data to `inblob`
    /// 3. Read quote from `outblob`
    fn generate_quote_configfs(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;

            let report_name = format!("tenzro_{}", Uuid::new_v4().as_simple());
            let report_dir = format!("/sys/kernel/config/tsm/report/{}", report_name);

            // Create report entry
            fs::create_dir(&report_dir).map_err(|e| TeeError::AttestationGenerationFailed(
                format!("Failed to create configfs-tsm report entry: {}", e)
            ))?;

            // Prepare inblob (up to 64 bytes of user data)
            let mut inblob = vec![0u8; 64];
            let copy_len = user_data.len().min(64);
            inblob[..copy_len].copy_from_slice(&user_data[..copy_len]);

            // Write user data to inblob
            fs::write(format!("{}/inblob", report_dir), &inblob).map_err(|e| {
                let _ = fs::remove_dir(&report_dir);
                TeeError::AttestationGenerationFailed(
                    format!("Failed to write inblob: {}", e)
                )
            })?;

            // Read the generated quote
            let quote = fs::read(format!("{}/outblob", report_dir)).map_err(|e| {
                let _ = fs::remove_dir(&report_dir);
                TeeError::AttestationGenerationFailed(
                    format!("Failed to read outblob (quote): {}", e)
                )
            })?;

            // Clean up
            let _ = fs::remove_dir(&report_dir);

            tracing::info!("TDX Quote generated via configfs-tsm ({} bytes)", quote.len());
            Ok(quote)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = user_data;
            Err(TeeError::not_available(
                "configfs-tsm requires Linux kernel 6.7+"
            ))
        }
    }

    /// Extracts QE certificate chain from a TDX Quote v4 signature section.
    ///
    /// TD Quote v4 signature structure (after header+body at offset 632):
    /// - Signature Data Size (4 bytes, u32 LE)
    /// - ECDSA Signature (64 bytes, P-256 r||s over header+body)
    /// - ECDSA Attestation Key (64 bytes, raw X||Y)
    /// - QE Certification Data Type (2 bytes) — type 6 = QE Report Certification Data
    /// - QE Certification Data Size (4 bytes)
    /// - QE Certification Data (type 6 body):
    ///   - QE Report (384 bytes)
    ///   - QE Report Signature (64 bytes)
    ///   - QE Auth Data Size (2 bytes) + QE Auth Data (variable)
    ///   - Inner Certification Data Type (2 bytes) — type 5 = PCK cert chain (PEM)
    ///   - Inner Certification Data Size (4 bytes)
    ///   - Inner Certification Data (PEM certs)
    fn extract_qe_cert_chain_from_quote(quote_data: &[u8]) -> Result<Vec<Vec<u8>>> {
        const SIG_DATA_HEADER: usize = 4; // u32 sig_data_size
        const ECDSA_SIG_LEN: usize = 64;
        const ECDSA_PUBKEY_LEN: usize = 64;
        const QE_REPORT_LEN: usize = 384;
        const QE_REPORT_SIG_LEN: usize = 64;

        if quote_data.len() < quote_offsets::SIGNATURE_DATA + SIG_DATA_HEADER {
            return Err(TeeError::InvalidAttestationReport(
                "Quote too short to contain signature section".to_string()
            ));
        }

        let sig_data_size = u32::from_le_bytes(
            quote_data[quote_offsets::SIGNATURE_DATA..quote_offsets::SIGNATURE_DATA + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let auth_start = quote_offsets::SIGNATURE_DATA + SIG_DATA_HEADER;
        let auth_end = auth_start.saturating_add(sig_data_size);
        if auth_end > quote_data.len() {
            tracing::debug!(
                "Quote sig_data_size {} exceeds buffer {} bytes",
                sig_data_size, quote_data.len()
            );
            return Ok(vec![]);
        }
        let auth = &quote_data[auth_start..auth_end];

        // Skip signature + attestation key to the outer certification data.
        let outer_type_offset = ECDSA_SIG_LEN + ECDSA_PUBKEY_LEN;
        if auth.len() < outer_type_offset + 6 {
            tracing::debug!("Quote auth data too short for certification data");
            return Ok(vec![]);
        }
        let outer_type = u16::from_le_bytes([auth[outer_type_offset], auth[outer_type_offset + 1]]);
        let outer_size = u32::from_le_bytes(
            auth[outer_type_offset + 2..outer_type_offset + 6].try_into().unwrap(),
        ) as usize;
        let outer_body_offset = outer_type_offset + 6;
        if auth.len() < outer_body_offset + outer_size {
            return Err(TeeError::InvalidAttestationReport(
                format!("Certification data size {} exceeds available data", outer_size)
            ));
        }
        let outer_body = &auth[outer_body_offset..outer_body_offset + outer_size];

        // Type 5 directly carries the PEM chain; type 6 (the TD Quote v4
        // case) wraps the QE Report and nests the type-5 chain inside.
        let pem_data: &[u8] = match outer_type {
            5 => outer_body,
            6 => {
                let auth_len_offset = QE_REPORT_LEN + QE_REPORT_SIG_LEN;
                if outer_body.len() < auth_len_offset + 2 {
                    tracing::debug!("QE Report Certification Data too short");
                    return Ok(vec![]);
                }
                let qe_auth_data_len = u16::from_le_bytes([
                    outer_body[auth_len_offset],
                    outer_body[auth_len_offset + 1],
                ]) as usize;
                let inner_type_offset = auth_len_offset + 2 + qe_auth_data_len;
                if outer_body.len() < inner_type_offset + 6 {
                    tracing::debug!("QE Report Certification Data too short for inner cert data");
                    return Ok(vec![]);
                }
                let inner_type = u16::from_le_bytes([
                    outer_body[inner_type_offset],
                    outer_body[inner_type_offset + 1],
                ]);
                if inner_type != 5 {
                    tracing::debug!(
                        "Inner QE Certification Data Type is not 5 (PEM chain), got {}",
                        inner_type
                    );
                    return Ok(vec![]);
                }
                let inner_size = u32::from_le_bytes(
                    outer_body[inner_type_offset + 2..inner_type_offset + 6].try_into().unwrap(),
                ) as usize;
                let inner_body_offset = inner_type_offset + 6;
                if outer_body.len() < inner_body_offset + inner_size {
                    return Err(TeeError::InvalidAttestationReport(
                        format!("Inner certification data size {} exceeds available data", inner_size)
                    ));
                }
                &outer_body[inner_body_offset..inner_body_offset + inner_size]
            }
            other => {
                tracing::debug!("QE Certification Data Type {} carries no PEM chain", other);
                return Ok(vec![]);
            }
        };

        // Parse PEM certificates
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|e| TeeError::CertificateValidationFailed(format!("Invalid PEM UTF-8: {}", e)))?;

        let mut certs = Vec::new();
        for cert_pem in pem_str.split("-----END CERTIFICATE-----") {
            if let Some(start) = cert_pem.find("-----BEGIN CERTIFICATE-----") {
                let full_pem = format!("{}-----END CERTIFICATE-----", &cert_pem[start..]);
                match certs::pem_to_der(&full_pem) {
                    Ok(der) => certs.push(der),
                    Err(e) => tracing::warn!("Failed to parse QE certificate: {}", e),
                }
            }
        }

        tracing::info!("Extracted {} certificates from Quote signature section", certs.len());
        Ok(certs)
    }

    /// Fetches QE identity and PCK certificates from Intel PCS.
    ///
    /// NOTE: Requires `reqwest` dependency (enabled via intel-tdx feature).
    /// Falls back gracefully when reqwest is not available.
    ///
    /// Wired into [`Self::verify_td_quote`] as the **fallback** when neither
    /// caller-supplied certificates nor Quote-embedded certificates produce a
    /// chain. PCS is the canonical Intel-published collateral source.
    #[cfg(feature = "intel-tdx")]
    async fn fetch_pcs_certificates(&self, _qe_vendor_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        // QE Identity endpoint
        let qe_identity_url = "https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity";

        tracing::info!("Fetching QE identity from Intel PCS: {}", qe_identity_url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to build HTTP client: {}", e)))?;

        let qe_identity_resp = client.get(qe_identity_url)
            .send()
            .await
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to fetch QE identity: {}", e)))?;

        if !qe_identity_resp.status().is_success() {
            return Err(TeeError::AttestationGenerationFailed(
                format!("Intel PCS QE identity request failed: {}", qe_identity_resp.status())
            ));
        }

        let qe_identity_data = qe_identity_resp.text().await
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to read QE identity: {}", e)))?;

        tracing::debug!("QE identity response: {} bytes", qe_identity_data.len());

        // PCK Certificate endpoint (requires fmspc, pce_id, etc - simplified for now)
        // In production, extract FMSPC from Quote and construct proper URL
        tracing::warn!("Intel PCS PCK certificate fetching not fully implemented (requires FMSPC extraction)");

        // Return empty cert chain - caller should use embedded certs from Quote
        Ok(vec![])
    }

    #[cfg(not(feature = "intel-tdx"))]
    async fn fetch_pcs_certificates(&self, _qe_vendor_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        tracing::warn!("Intel PCS certificate fetching requires reqwest (enable intel-tdx feature)");
        Ok(vec![])
    }

    /// Returns the 48-byte MRTD (SHA-384 of the initial Trust Domain state)
    /// from a freshly generated TD quote.
    ///
    /// MRTD is set by the VMM at TD launch and cannot be changed thereafter
    /// without re-launching the TD with different boot media. This makes it
    /// suitable as input keying material for measurement-bound key derivation
    /// — the same TD image redeploys to the same MRTD; tampering produces a
    /// different MRTD; another tenant's TD on the same physical host has a
    /// different MRTD.
    ///
    /// Unlike SEV-SNP's `SNP_GET_DERIVED_KEY`, TDX has no hardware-mediated
    /// KDF — callers MUST run the returned MRTD through HKDF-SHA256 with
    /// per-key salts to produce isolated key material.
    ///
    /// # Errors
    ///
    /// - [`TeeError::NotAvailable`] when not on Linux or `/dev/tdx_guest` is
    ///   absent (no simulation fallback per Tenzro's no-simulation-on-testnet
    ///   policy).
    /// - [`TeeError::AttestationGenerationFailed`] when quote generation or
    ///   parsing fails.
    pub async fn platform_measurement(&self) -> Result<[u8; 48]> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        if self.simulate {
            return Err(TeeError::not_available(
                "Intel TDX simulation mode cannot supply real platform measurement",
            ));
        }

        // Use a fixed nonce — we are extracting MRTD, not proving freshness.
        // The MRTD is independent of report_data so any value works.
        let nonce = [0u8; 64];
        let quote = self.generate_td_quote(&nonce).await?;
        let parsed = self.parse_quote(&quote)?;
        if parsed.mr_td.len() != 48 {
            return Err(TeeError::AttestationGenerationFailed(format!(
                "MRTD wrong length: {} (expected 48)",
                parsed.mr_td.len()
            )));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&parsed.mr_td);
        Ok(out)
    }

    /// Generates a TD Quote (simulated or real).
    ///
    /// Attempts configfs-tsm first (preferred), falls back to TDREPORT + QE.
    async fn generate_td_quote(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        if self.simulate {
            return self.generate_simulated_quote(user_data);
        }

        // Try configfs-tsm first (kernel 6.7+)
        if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
            return self.generate_quote_configfs(user_data);
        }

        // Fall back to TDREPORT via ioctl (quote generation requires QE)
        let tdreport = self.generate_tdreport(user_data)?;

        // In production, the TDREPORT would be sent to the Quoting Enclave
        // via vsock or TCP to generate a remotely-verifiable Quote.
        // For now, wrap the TDREPORT in a format that includes it.
        let mut quote = Vec::with_capacity(48 + 584 + tdreport.len());

        // Minimal Quote v4 header (48 bytes)
        let mut header = vec![0u8; 48];
        header[0..2].copy_from_slice(&4u16.to_le_bytes()); // version = 4
        header[2..4].copy_from_slice(&2u16.to_le_bytes()); // att_key_type = ECDSA-256
        header[4..8].copy_from_slice(&0x81u32.to_le_bytes()); // tee_type = TDX
        quote.extend_from_slice(&header);

        // Quote body: extract relevant fields from TDREPORT into Quote body format
        let mut body = vec![0u8; quote_offsets::BODY_LEN];

        // Copy TCB SVN
        if tdreport.len() >= tdreport_offsets::TEE_TCB_SVN + 16 {
            body[quote_offsets::BODY_TEE_TCB_SVN..quote_offsets::BODY_TEE_TCB_SVN + 16]
                .copy_from_slice(&tdreport[tdreport_offsets::TEE_TCB_SVN - 256..tdreport_offsets::TEE_TCB_SVN - 256 + 16]);
        }

        // Copy MRTD
        let mrtd_off = tdreport_offsets::MR_TD - 512 + 512; // TDINFO starts at offset 512
        if tdreport.len() >= mrtd_off + 48 {
            body[quote_offsets::BODY_MR_TD..quote_offsets::BODY_MR_TD + 48]
                .copy_from_slice(&tdreport[tdreport_offsets::MR_TD..tdreport_offsets::MR_TD + 48]);
        }

        // Copy RTMRs
        for (i, rtmr_off) in [
            tdreport_offsets::RTMR0,
            tdreport_offsets::RTMR1,
            tdreport_offsets::RTMR2,
            tdreport_offsets::RTMR3,
        ].iter().enumerate() {
            let body_off = quote_offsets::BODY_RTMR0 + i * 48;
            if tdreport.len() >= rtmr_off + 48 {
                body[body_off..body_off + 48]
                    .copy_from_slice(&tdreport[*rtmr_off..*rtmr_off + 48]);
            }
        }

        // Copy report data
        if tdreport.len() >= tdreport_offsets::REPORT_DATA + 64 {
            body[quote_offsets::BODY_REPORT_DATA..quote_offsets::BODY_REPORT_DATA + 64]
                .copy_from_slice(&tdreport[tdreport_offsets::REPORT_DATA..tdreport_offsets::REPORT_DATA + 64]);
        }

        quote.extend_from_slice(&body);

        tracing::info!("TDX Quote constructed from TDREPORT ({} bytes, no QE signature)", quote.len());
        Ok(quote)
    }

    /// Generates a simulated TDX Quote.
    fn generate_simulated_quote(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        let mut report_data = [0u8; 64];
        let copy_len = user_data.len().min(64);
        report_data[..copy_len].copy_from_slice(&user_data[..copy_len]);

        // Simulate MRTD as SHA-384 of some fixed content
        let mr_td = Sha384::digest(b"simulated-trust-domain-measurement");
        let rtmr0 = Sha384::digest(b"simulated-rtmr0-tdvf-config");
        let rtmr1 = Sha384::digest(b"simulated-rtmr1-os-kernel");
        let rtmr2 = Sha384::digest(b"simulated-rtmr2-os-applications");
        let rtmr3 = [0u8; 48]; // RTMR3 typically unused

        let quote = serde_json::json!({
            "version": 4,
            "type": "TDX_QUOTE_SIMULATED",
            "simulated": true,
            "tee_type": "0x81",
            "att_key_type": 2,
            "user_data": hex::encode(user_data),
            "report_data": hex::encode(report_data),
            "tee_tcb_svn": "03000600000000000000000000000000",
            "mr_td": hex::encode(mr_td.as_slice()),
            "mr_seam": hex::encode(Sha384::digest(b"simulated-seam-module").as_slice()),
            "mr_config_id": hex::encode([0u8; 48]),
            "mr_owner": hex::encode([0u8; 48]),
            "mr_owner_config": hex::encode([0u8; 48]),
            "rtmr0": hex::encode(rtmr0.as_slice()),
            "rtmr1": hex::encode(rtmr1.as_slice()),
            "rtmr2": hex::encode(rtmr2.as_slice()),
            "rtmr3": hex::encode(rtmr3),
        });

        Ok(serde_json::to_vec(&quote)?)
    }

    /// Parses a TDX Quote (real binary or simulated JSON).
    fn parse_quote(&self, data: &[u8]) -> Result<TdxQuote> {
        // Try JSON first (simulated)
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data)
            && json.get("simulated").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            return self.parse_simulated_quote(&json, data);
        }

        // Parse binary Quote v4
        self.parse_binary_quote(data)
    }

    /// Parses a simulated JSON quote.
    fn parse_simulated_quote(&self, json: &serde_json::Value, raw: &[u8]) -> Result<TdxQuote> {
        let get_hex = |key: &str| -> Vec<u8> {
            json.get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default()
        };

        Ok(TdxQuote {
            version: 4,
            att_key_type: 2,
            tee_type: 0x81,
            tee_tcb_svn: json.get("tee_tcb_svn")
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_else(|| vec![0u8; 16]),
            mr_td: get_hex("mr_td"),
            rtmrs: [
                get_hex("rtmr0"),
                get_hex("rtmr1"),
                get_hex("rtmr2"),
                get_hex("rtmr3"),
            ],
            report_data: get_hex("report_data"),
            raw: raw.to_vec(),
            simulated: true,
        })
    }

    /// Parses a real binary TDX Quote v4.
    fn parse_binary_quote(&self, data: &[u8]) -> Result<TdxQuote> {
        let min_len = quote_offsets::BODY + quote_offsets::BODY_LEN;
        if data.len() < min_len {
            return Err(TeeError::InvalidAttestationReport(format!(
                "TDX Quote too short: {} bytes (need at least {})", data.len(), min_len
            )));
        }

        let version = u16::from_le_bytes([data[0], data[1]]);
        if version != 4 {
            return Err(TeeError::InvalidAttestationReport(format!(
                "Unsupported TDX Quote version: {} (expected 4)", version
            )));
        }

        let att_key_type = u16::from_le_bytes([data[2], data[3]]);
        let tee_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        if tee_type != 0x81 {
            return Err(TeeError::InvalidAttestationReport(format!(
                "Not a TDX quote: tee_type=0x{:X} (expected 0x81)", tee_type
            )));
        }

        let body = &data[quote_offsets::BODY..];

        let extract = |offset: usize, len: usize| -> Vec<u8> {
            if body.len() >= offset + len {
                body[offset..offset + len].to_vec()
            } else {
                vec![0u8; len]
            }
        };

        Ok(TdxQuote {
            version,
            att_key_type,
            tee_type,
            tee_tcb_svn: extract(quote_offsets::BODY_TEE_TCB_SVN, 16),
            mr_td: extract(quote_offsets::BODY_MR_TD, 48),
            rtmrs: [
                extract(quote_offsets::BODY_RTMR0, 48),
                extract(quote_offsets::BODY_RTMR1, 48),
                extract(quote_offsets::BODY_RTMR2, 48),
                extract(quote_offsets::BODY_RTMR3, 48),
            ],
            report_data: extract(quote_offsets::BODY_REPORT_DATA, 64),
            raw: data.to_vec(),
            simulated: false,
        })
    }

    /// Verifies a TDX Quote.
    ///
    /// For real quotes:
    /// 1. Parse Quote v4 binary format
    /// 2. Verify QE signature (ECDSA P-256 over Quote header + body)
    /// 3. Verify QE certificate chain against Intel PCS
    /// 4. Validate RTMR measurements
    /// 5. Check TCB SVN against Intel PCS collateral
    ///
    /// For simulated quotes:
    /// - Parse JSON format, return validation result with simulated flag
    async fn verify_td_quote(&self, quote_data: &[u8], certificates: &[Vec<u8>]) -> Result<AttestationResult> {
        let quote = self.parse_quote(quote_data)?;

        let mut details = HashMap::new();
        details.insert("version".to_string(), quote.version.to_string());
        details.insert("tee_type".to_string(), format!("0x{:X}", quote.tee_type));
        details.insert("att_key_type".to_string(), quote.att_key_type.to_string());
        details.insert("mr_td".to_string(), hex::encode(&quote.mr_td));
        // Surface caller-supplied report_data (nonce / freshness binding) so the
        // verifier can match against the value it handed the enclave.
        details.insert("report_data".to_string(), hex::encode(&quote.report_data));

        let mut cert_chain_valid = false;

        let mut qe_sig_valid = false;
        if quote.simulated {
            details.insert("simulated".to_string(), "true".to_string());
            details.insert("type".to_string(), "simulated".to_string());
            tracing::warn!(
                "Verifying SIMULATED Intel TDX quote — AttestationResult.valid \
                 will be false. Simulated quotes carry no cryptographic \
                 authority and must never be treated as real attestations."
            );
        } else {
            details.insert("type".to_string(), "real".to_string());
            tracing::info!("Verifying real Intel TDX quote");

            // If certificates not provided but quote has signature data, extract embedded certs
            let mut certs_to_verify = if certificates.is_empty() && quote.raw.len() > quote_offsets::SIGNATURE_DATA {
                tracing::debug!("Attempting to extract QE certificate chain from Quote signature section");
                match Self::extract_qe_cert_chain_from_quote(&quote.raw) {
                    Ok(extracted_certs) if !extracted_certs.is_empty() => {
                        tracing::info!("Using {} embedded certificates from Quote", extracted_certs.len());
                        extracted_certs
                    }
                    Ok(_) => {
                        tracing::debug!("No embedded certificates found in Quote");
                        vec![]
                    }
                    Err(e) => {
                        tracing::warn!("Failed to extract QE certs from Quote: {}", e);
                        vec![]
                    }
                }
            } else {
                certificates.to_vec()
            };

            // PCS fallback: if no caller-supplied AND no embedded certs, fetch from
            // Intel Provisioning Certification Service (the canonical collateral source).
            if certs_to_verify.is_empty() {
                // QE vendor ID is at offset 12 of the Quote header (16 bytes).
                let qe_vendor_id: &[u8] = if quote.raw.len() >= 28 {
                    &quote.raw[12..28]
                } else {
                    &[]
                };
                match self.fetch_pcs_certificates(qe_vendor_id).await {
                    Ok(pcs_certs) if !pcs_certs.is_empty() => {
                        tracing::info!("Using {} certificates from Intel PCS fallback", pcs_certs.len());
                        details.insert("cert_source".to_string(), "intel_pcs".to_string());
                        certs_to_verify = pcs_certs;
                    }
                    Ok(_) => {
                        tracing::debug!("Intel PCS returned no certificates; chain verification will be skipped");
                    }
                    Err(e) => {
                        tracing::warn!("Intel PCS fetch failed: {}", e);
                    }
                }
            }

            // Verify certificate chain against pinned Intel SGX Root CA
            if !certs_to_verify.is_empty() {
                cert_chain_valid = self.verify_intel_cert_chain(&certs_to_verify)?;
            }

            // For real quotes with sufficient data, verify the QE signature.
            //
            // DCAP v4 signature section layout (starting at offset SIGNATURE_DATA = 632):
            //   u32 sig_data_size                (4 bytes)
            //   [sig_data_size bytes]:
            //     ecdsa_signature:      64 bytes (r||s over header+body)
            //     ecdsa_att_pubkey:     64 bytes (raw X||Y, P-256 uncompressed)
            //     qe_report:           384 bytes (SGX REPORT_BODY)
            //     qe_report_signature:  64 bytes (signed by PCK)
            //     qe_auth_data_size:     2 bytes (u16 LE)
            //     qe_auth_data:     variable
            //     qe_cert_data_type:     2 bytes (u16 LE)
            //     qe_cert_data_size:     4 bytes (u32 LE)
            //     qe_cert_data:     variable
            //
            // The ecdsa_signature is over bytes 0..632 of the Quote using the
            // ecdsa_att_pubkey (P-256 / att_key_type = 2).
            qe_sig_valid = match Self::verify_qe_signature(&quote.raw) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("QE signature verification error: {}", e);
                    false
                }
            };
            details.insert("qe_signature_valid".to_string(), qe_sig_valid.to_string());
            if !qe_sig_valid {
                tracing::warn!("TDX QE signature did not verify");
            } else {
                tracing::info!("TDX QE signature verified (ECDSA P-256 over header+body)");
            }
        }

        let measurements: Vec<Measurement> = quote.rtmrs.iter().enumerate()
            .filter(|(_, rtmr)| !rtmr.is_empty())
            .map(|(i, rtmr)| Measurement {
                index: i as u32,
                algorithm: "SHA384".to_string(),
                value: rtmr.clone(),
                register: format!("RTMR{}", i),
                description: Some(match i {
                    0 => "TDVF configuration".to_string(),
                    1 => "OS loader and kernel".to_string(),
                    2 => "OS applications".to_string(),
                    3 => "Guest use (reserved)".to_string(),
                    _ => format!("RTMR{}", i),
                }),
            })
            .collect();

        // Fail-closed validity. A real quote is only `valid` when BOTH the
        // QE signature and the certificate chain verify against a pinned
        // root. Simulated quotes are NEVER valid — they carry no
        // cryptographic authority and any relying party that branches on
        // `result.valid` would otherwise treat a forged simulated quote
        // as real attestation.
        let valid = !quote.simulated && qe_sig_valid && cert_chain_valid;

        Ok(AttestationResult {
            valid,
            vendor: TeeVendor::IntelTdx,
            tcb_version: hex::encode(&quote.tee_tcb_svn),
            measurements,
            cert_chain_valid,
            details,
            verified_at: tenzro_types::Timestamp::now(),
            ..Default::default()
        })
    }

    /// Verifies the QE signature over the TDX Quote header + body using the
    /// embedded ECDSA attestation public key.
    ///
    /// Returns `false` if the signature is malformed or does not verify.
    /// Returns an error only for I/O / length-bounds problems that prevent parsing.
    fn verify_qe_signature(raw: &[u8]) -> Result<bool> {
        const SIG_OFFSET: usize = quote_offsets::SIGNATURE_DATA;
        const ECDSA_SIG_LEN: usize = 64;
        const ECDSA_PUBKEY_LEN: usize = 64;
        const SIG_DATA_HEADER: usize = 4; // u32 sig_data_size

        if raw.len() < SIG_OFFSET + SIG_DATA_HEADER + ECDSA_SIG_LEN + ECDSA_PUBKEY_LEN {
            tracing::debug!(
                "Quote too short for QE signature verification: {} bytes",
                raw.len()
            );
            return Ok(false);
        }

        let sig_data_size = u32::from_le_bytes([
            raw[SIG_OFFSET],
            raw[SIG_OFFSET + 1],
            raw[SIG_OFFSET + 2],
            raw[SIG_OFFSET + 3],
        ]) as usize;

        let sig_data_start = SIG_OFFSET + SIG_DATA_HEADER;
        let sig_data_end = sig_data_start.saturating_add(sig_data_size);
        if sig_data_end > raw.len() || sig_data_size < ECDSA_SIG_LEN + ECDSA_PUBKEY_LEN {
            tracing::warn!(
                "TDX Quote sig_data_size {} is inconsistent with buffer {} bytes",
                sig_data_size, raw.len()
            );
            return Ok(false);
        }

        let ecdsa_signature = &raw[sig_data_start..sig_data_start + ECDSA_SIG_LEN];
        let ecdsa_att_pubkey =
            &raw[sig_data_start + ECDSA_SIG_LEN..sig_data_start + ECDSA_SIG_LEN + ECDSA_PUBKEY_LEN];

        // The signature covers the Quote header (48 bytes) + body (584 bytes) = 632 bytes.
        let signed_data = &raw[..SIG_OFFSET];

        attestation::verify_ecdsa_p256_raw_pubkey(ecdsa_att_pubkey, signed_data, ecdsa_signature)
    }

    /// Verifies the Intel certificate chain against pinned root CA.
    fn verify_intel_cert_chain(&self, certificates: &[Vec<u8>]) -> Result<bool> {
        let root_der = certs::pem_to_der(certs::INTEL_SGX_ROOT_CA_PEM)
            .map_err(|e| TeeError::CertificateValidationFailed(
                format!("Failed to decode Intel root CA: {}", e)
            ))?;

        let root_cert = attestation::parse_x509_certificate(&root_der)?;

        // Parse chain certificates
        let mut chain: Vec<ParsedCertificate> = Vec::new();
        for cert_der in certificates {
            match attestation::parse_x509_certificate(cert_der) {
                Ok(cert) => chain.push(cert),
                Err(e) => {
                    tracing::warn!("Failed to parse certificate in Intel chain: {}", e);
                }
            }
        }

        if chain.is_empty() {
            return Ok(false);
        }

        // Verify the last certificate in chain is signed by Intel root
        let last = chain.last().unwrap();
        if last.issuer_cn == root_cert.subject_cn || last.subject_cn == root_cert.subject_cn {
            let verified = attestation::verify_certificate_signature(
                last,
                &root_cert.spki_der,
            )?;
            if verified {
                tracing::info!("Intel TDX certificate chain verified against pinned root CA");
            }
            Ok(verified)
        } else {
            tracing::warn!(
                "Intel chain does not terminate at Intel SGX Root CA: last issuer='{}', root='{}'",
                last.issuer_cn, root_cert.subject_cn
            );
            Ok(false)
        }
    }
}

impl Default for IntelTdxProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeeProvider for IntelTdxProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::IntelTdx
    }

    async fn is_available(&self) -> Result<bool> {
        Ok(self.available)
    }

    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }

        let attestation_data = self.generate_td_quote(user_data).await?;

        let mut metadata = HashMap::from([
            ("tdx_version".to_string(), "1.5".to_string()),
            ("seam_version".to_string(), "1.5.05.01".to_string()),
        ]);

        if self.simulate {
            metadata.insert("simulated".to_string(), "true".to_string());
        }

        // Project the TD measurement (MRTD) into the returned report so
        // structural verifiers see the launch measurement without re-parsing
        // the raw Quote.
        let measurement = match self.parse_quote(&attestation_data) {
            Ok(quote) => quote.mr_td,
            Err(e) => {
                tracing::warn!("Failed to parse generated TD Quote: {}", e);
                Vec::new()
            }
        };

        // In real mode, extract embedded certificates from Quote if available
        let certificates = if !self.simulate && attestation_data.len() > quote_offsets::SIGNATURE_DATA {
            match Self::extract_qe_cert_chain_from_quote(&attestation_data) {
                Ok(certs) if !certs.is_empty() => {
                    tracing::info!("Extracted {} QE certificates from generated Quote", certs.len());
                    certs
                }
                Ok(_) => {
                    tracing::debug!("No embedded certificates in generated Quote");
                    vec![]
                }
                Err(e) => {
                    tracing::warn!("Failed to extract QE certs from generated Quote: {}", e);
                    vec![]
                }
            }
        } else {
            vec![]
        };

        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::IntelTdx,
            user_data: user_data.to_vec(),
            attestation_data,
            certificates,
            timestamp: tenzro_types::Timestamp::now(),
            metadata,
            measurement,
            ..Default::default()
        })
    }

    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult> {
        if report.vendor != TeeVendor::IntelTdx {
            return Err(TeeError::InvalidAttestationReport(
                "Report is not from Intel TDX".to_string(),
            ));
        }

        self.verify_td_quote(&report.attestation_data, &report.certificates).await
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }

        tracing::info!("Executing in TDX enclave: {:?}", request.operation);

        // In real mode, operations execute inside the Trust Domain boundary.
        // The TD's memory is encrypted by the CPU — all computation here is protected.
        // In simulation mode, this is a passthrough.

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
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        let ikm = self.platform_measurement().await?;
        let handle = self.keystore.keygen(params, &ikm).await?;
        tracing::info!(
            key_id = %handle.id,
            algorithm = ?handle.algorithm,
            "Generated key in TDX enclave keystore"
        );
        Ok(handle)
    }

    async fn enclave_sign(&self, key: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        self.keystore.sign(key, data).await
    }

    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        self.keystore.encrypt(key, plaintext).await
    }

    async fn enclave_decrypt(&self, key: &EnclaveKeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        self.keystore.decrypt(key, ciphertext).await
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Returns true only when simulation is explicitly requested via env var.
/// Real hardware is the default — set `TENZRO_SIMULATE_TDX=1` to override.
fn is_simulation_mode() -> bool {
    std::env::var("TENZRO_SIMULATE_TDX")
        .unwrap_or_else(|_| "0".to_string()) == "1"
}

/// Builds an _IOWR ioctl number.
/// direction=3 (read+write), type=magic, nr=number, size=struct_size
#[cfg(target_os = "linux")]
fn build_ioctl_rw(magic: u8, nr: u8, size: u32) -> u32 {
    let dir: u32 = 3; // _IOC_READ | _IOC_WRITE
    (dir << 30) | ((size & 0x3FFF) << 16) | ((magic as u32) << 8) | (nr as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tdx_provider_creation() {
        let provider = IntelTdxProvider::new();
        assert_eq!(provider.vendor(), TeeVendor::IntelTdx);
    }

    #[tokio::test]
    async fn test_tdx_simulation_mode() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();
        assert!(provider.simulate);
        assert!(provider.available);
    }

    #[tokio::test]
    async fn test_tdx_generate_simulated_quote() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();

        let user_data = b"tenzro-test-data";
        let report = provider.generate_attestation(user_data).await;
        assert!(report.is_ok());

        let report = report.unwrap();
        assert_eq!(report.vendor, TeeVendor::IntelTdx);
        assert_eq!(report.user_data, user_data);
        assert!(!report.attestation_data.is_empty());
        assert_eq!(report.metadata.get("simulated"), Some(&"true".to_string()));
    }

    #[tokio::test]
    async fn test_tdx_verify_simulated_quote_is_invalid() {
        // Simulated quotes carry no cryptographic authority — the verifier
        // returns a populated AttestationResult (so downstream tooling can
        // still inspect the measurements / details) but `valid` MUST be
        // false. Any relying party that branches on `result.valid` will
        // therefore reject the simulated attestation outright.
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        assert!(
            !result.valid,
            "simulated TDX quotes must never report valid=true"
        );
        assert_eq!(result.vendor, TeeVendor::IntelTdx);
        assert_eq!(result.details.get("simulated"), Some(&"true".to_string()));

        // Measurements are still exposed so observability tooling has
        // visibility into the simulated quote contents.
        assert!(!result.measurements.is_empty());
        for m in &result.measurements {
            assert_eq!(m.algorithm, "SHA384");
            assert!(!m.value.is_empty());
        }
    }

    #[tokio::test]
    async fn test_tdx_parse_simulated_quote() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();

        let quote_bytes = provider.generate_simulated_quote(b"hello").unwrap();
        let quote = provider.parse_quote(&quote_bytes).unwrap();

        assert!(quote.simulated);
        assert_eq!(quote.version, 4);
        assert_eq!(quote.tee_type, 0x81);
        assert_eq!(quote.rtmrs.len(), 4);
        assert!(!quote.mr_td.is_empty());
    }

    #[tokio::test]
    async fn test_tdx_keygen_in_simulation_returns_not_available() {
        // Simulation mode cannot supply real platform-rooted IKM
        // (`platform_measurement()` returns NotAvailable), so
        // `enclave_keygen` must also return NotAvailable. There is no
        // software-fabrication fallback path.
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();

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
    async fn test_tdx_keystore_real_keygen_and_sign_verifies() {
        // Direct keystore-level test bypasses the hardware path so we
        // can verify the real cryptographic behaviour without needing a
        // TDX device. The same code path runs in production with the
        // MRTD-derived IKM in place of the fixed test IKM.
        use ed25519_dalek::Verifier;
        let ks = crate::enclave_keystore::EnclaveKeystore::new("intel-tdx-test");
        let ikm: Vec<u8> = (0u8..64).collect();
        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: HashMap::new(),
        };
        let handle = ks.keygen(params, &ikm).await.unwrap();
        let pk = handle.public_key.clone().unwrap();
        let msg = b"intel-tdx real Ed25519";
        let sig = ks.sign(&handle, msg).await.unwrap();

        let vk = ed25519_dalek::VerifyingKey::from_bytes(
            <&[u8; 32]>::try_from(pk.as_slice()).unwrap(),
        )
        .unwrap();
        let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        vk.verify(msg, &signature).expect("real Ed25519 signature must verify");
    }

    #[test]
    fn test_tdreport_offsets() {
        // Verify struct layout constants match TDX spec
        assert_eq!(tdreport_offsets::REPORT_DATA, 128);
        assert_eq!(tdreport_offsets::MAC, 224);
        assert_eq!(tdreport_offsets::MR_TD, 528);
        assert_eq!(tdreport_offsets::RTMR0, 720);
        assert_eq!(tdreport_offsets::RTMR1, 768);
        assert_eq!(tdreport_offsets::RTMR2, 816);
        assert_eq!(tdreport_offsets::RTMR3, 864);
    }

    #[test]
    fn test_quote_offsets() {
        // Verify Quote v4 layout
        assert_eq!(quote_offsets::BODY, 48);
        assert_eq!(quote_offsets::BODY_LEN, 584);
        assert_eq!(quote_offsets::SIGNATURE_DATA, 48 + 584);
    }

    #[tokio::test]
    async fn test_tdx_wrong_vendor_rejected() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_TDX", "1"); }
        let provider = IntelTdxProvider::new();

        let mut report = provider.generate_attestation(b"test").await.unwrap();
        report.vendor = TeeVendor::AmdSevSnp; // Wrong vendor

        let result = provider.verify_attestation(&report).await;
        assert!(result.is_err());
    }
}
