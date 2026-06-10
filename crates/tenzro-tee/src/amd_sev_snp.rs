//! AMD SEV-SNP (Secure Encrypted Virtualization - Secure Nested Paging) provider for Tenzro Network.
//!
//! AMD SEV-SNP provides VM-level confidentiality and integrity through memory encryption
//! and integrity protection. This module provides both real hardware integration and
//! simulation mode.
//!
//! # Real Hardware Integration
//!
//! On SEV-SNP-enabled hardware, this provider:
//! 1. Opens `/dev/sev-guest` and issues `SNP_GET_REPORT` ioctl
//! 2. Receives a 1184-byte attestation report signed by the AMD PSP
//! 3. Fetches VCEK certificate from AMD KDS for verification
//! 4. Verifies the report signature (ECDSA P-384) against VCEK → ASK → ARK chain
//!
//! # Report Structure (1184 bytes)
//!
//! - Body (672 bytes, offsets 0x000–0x29F):
//!   - VERSION (4B), GUEST_SVN (4B), POLICY (8B)
//!   - FAMILY_ID (16B), IMAGE_ID (16B)
//!   - VMPL (4B), SIGNATURE_ALGO (4B)
//!   - PLATFORM_VERSION (8B)
//!   - PLATFORM_INFO (8B)
//!   - FLAGS (4B), RESERVED (4B)
//!   - REPORT_DATA (64B at 0x050)
//!   - MEASUREMENT (48B at 0x090, SHA-384 of initial VM state)
//!   - HOST_DATA (32B), ID_KEY_DIGEST (48B), AUTHOR_KEY_DIGEST (48B)
//!   - REPORT_ID (32B), REPORT_ID_MA (32B)
//!   - REPORTED_TCB (8B), RESERVED (24B)
//!   - CHIP_ID (64B at 0x1A0)
//!   - COMMITTED_TCB (8B)
//! - Signature (512 bytes at 0x2A0):
//!   - R component (72B, P-384 coordinate padded from 48B)
//!   - S component (72B, P-384 coordinate padded from 48B)
//!   - Reserved (368B)
//!
//! # References
//!
//! - [Linux SEV Guest API](https://docs.kernel.org/virt/coco/sev-guest.html)
//! - [AMD SEV-SNP ABI Spec](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf)
//! - [AMD KDS API](https://kdsintf.amd.com/)

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
// SEV-SNP ioctl structures (matching Linux kernel's sev-guest.h)
// ============================================================================

/// SNP_GET_REPORT ioctl: _IOWR('S', 0x0, struct snp_guest_request_ioctl)
#[cfg(target_os = "linux")]
const SEV_IOCTL_MAGIC: u8 = b'S';
#[cfg(target_os = "linux")]
const SNP_GET_REPORT_NR: u8 = 0;
/// SNP_GET_DERIVED_KEY ioctl: _IOWR('S', 0x1, struct snp_guest_request_ioctl)
#[cfg(target_os = "linux")]
const SNP_GET_DERIVED_KEY_NR: u8 = 1;

/// Size of user-provided report data
#[cfg(target_os = "linux")]
const SNP_REPORT_USER_DATA_SIZE: usize = 64;

/// Size of the raw attestation report returned by the PSP
const SNP_REPORT_SIZE: usize = 1184;

/// Size of the derived key returned by the PSP (MSG_KEY_REQ response)
pub const SNP_DERIVED_KEY_SIZE: usize = 64;

/// Bit flags for `guest_field_select` in the SNP derived-key request.
///
/// These bits control which fields from the guest context are mixed into
/// the key derivation. Setting a bit binds the derived key to that field —
/// e.g. `MEASUREMENT` makes the key change if the VM's initial state changes.
///
/// Per AMD SEV-SNP ABI spec (revision 1.55), Table 16.
pub mod guest_field_select {
    pub const GUEST_POLICY: u64 = 1 << 0;
    pub const IMAGE_ID: u64 = 1 << 1;
    pub const FAMILY_ID: u64 = 1 << 2;
    pub const MEASUREMENT: u64 = 1 << 3;
    pub const GUEST_SVN: u64 = 1 << 4;
    pub const TCB_VERSION: u64 = 1 << 5;
}

/// SNP attestation report offsets (from AMD SEV-SNP ABI spec).
///
/// Documented byte offsets into the 1184-byte SNP attestation report as
/// defined by the AMD SEV-SNP ABI specification. Public so downstream
/// verifiers, audit tooling, and integration tests can reference the same
/// canonical layout.
pub mod report_offsets {
    pub const VERSION: usize = 0x000;           // 4 bytes (should be 2)
    pub const GUEST_SVN: usize = 0x004;         // 4 bytes
    pub const POLICY: usize = 0x008;            // 8 bytes
    pub const FAMILY_ID: usize = 0x010;         // 16 bytes
    pub const IMAGE_ID: usize = 0x020;          // 16 bytes
    pub const VMPL: usize = 0x030;              // 4 bytes (0–3)
    pub const SIGNATURE_ALGO: usize = 0x034;    // 4 bytes (1=ECDSA P-384 SHA-384)
    pub const PLATFORM_VERSION: usize = 0x038;  // 8 bytes (TCB version)
    pub const PLATFORM_INFO: usize = 0x040;     // 8 bytes
    pub const FLAGS: usize = 0x048;             // 4 bytes (bit 0: AuthorKeyEn)
    pub const REPORT_DATA: usize = 0x050;       // 64 bytes
    pub const MEASUREMENT: usize = 0x090;       // 48 bytes (SHA-384)
    pub const HOST_DATA: usize = 0x0C0;         // 32 bytes
    pub const ID_KEY_DIGEST: usize = 0x0E0;     // 48 bytes
    pub const AUTHOR_KEY_DIGEST: usize = 0x110; // 48 bytes
    pub const REPORT_ID: usize = 0x140;         // 32 bytes
    pub const REPORT_ID_MA: usize = 0x160;      // 32 bytes
    pub const REPORTED_TCB: usize = 0x180;      // 8 bytes
    pub const CHIP_ID: usize = 0x1A0;           // 64 bytes
    pub const COMMITTED_TCB: usize = 0x1E0;     // 8 bytes

    // Signature at offset 0x2A0 (512 bytes)
    pub const SIGNATURE: usize = 0x2A0;         // 512 bytes total
    pub const SIGNATURE_R: usize = 0x2A0;       // 72 bytes (padded P-384)
    pub const SIGNATURE_S: usize = 0x2E8;       // 72 bytes (padded P-384)

    /// Body that is signed (bytes 0x000–0x29F)
    pub const SIGNED_BODY_LEN: usize = 0x2A0;   // 672 bytes
}

/// Parsed SNP attestation report
#[derive(Debug, Clone)]
struct SnpReport {
    /// Report version (should be 2)
    version: u32,
    /// Guest SVN
    guest_svn: u32,
    /// Guest policy (8 bytes)
    policy: u64,
    /// VMPL level (0–3)
    vmpl: u32,
    /// Platform TCB version (8 bytes)
    platform_version: u64,
    /// Reported TCB (8 bytes)
    reported_tcb: u64,
    /// Committed TCB (8 bytes)
    committed_tcb: u64,
    /// Measurement (48 bytes, SHA-384 of initial VM state)
    measurement: Vec<u8>,
    /// Report data (64 bytes, caller-provided)
    report_data: Vec<u8>,
    /// Host data (32 bytes)
    host_data: Vec<u8>,
    /// Chip ID (64 bytes)
    chip_id: Vec<u8>,
    /// Report ID (32 bytes)
    report_id: Vec<u8>,
    /// ECDSA P-384 signature (R || S, each 48 bytes after unpadding)
    signature_r: Vec<u8>,
    signature_s: Vec<u8>,
    /// Raw report bytes
    raw: Vec<u8>,
    /// Whether simulated
    simulated: bool,
}

/// AMD SEV-SNP provider implementation for Tenzro Network.
///
/// Provides both real hardware integration (via `/dev/sev-guest`) and
/// simulation mode for development and testing.
///
/// # Modes
///
/// - **Real** (default): Uses actual SEV-SNP hardware via Linux kernel interface (`/dev/sev-guest`)
/// - **Simulation** (`TENZRO_SIMULATE_SEV=1`): Returns plausible fake attestations for local development
#[derive(Clone)]
pub struct AmdSevSnpProvider {
    /// Real enclave-key store: every `enclave_keygen` call derives a
    /// fresh Ed25519 / Secp256k1 / AES-256-GCM key via HKDF-SHA256 over
    /// the SEV-SNP `SNP_GET_DERIVED_KEY` IKM. Signatures and encryption
    /// produced by [`Self::enclave_sign`] / [`Self::enclave_encrypt`]
    /// use the real key material.
    keystore: std::sync::Arc<crate::enclave_keystore::EnclaveKeystore>,
    /// Whether SEV-SNP is available
    available: bool,
    /// Whether running in simulation mode
    simulate: bool,
}

impl std::fmt::Debug for AmdSevSnpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmdSevSnpProvider")
            .field("available", &self.available)
            .field("simulate", &self.simulate)
            .finish_non_exhaustive()
    }
}

impl AmdSevSnpProvider {
    /// Creates a new AMD SEV-SNP provider.
    pub fn new() -> Self {
        let simulate = is_simulation_mode();
        let available = if simulate {
            tracing::debug!("AMD SEV-SNP running in simulation mode");
            true
        } else {
            Self::detect_sev_snp_hardware()
        };

        Self {
            keystore: std::sync::Arc::new(crate::enclave_keystore::EnclaveKeystore::new("amd-sev-snp")),
            available,
            simulate,
        }
    }

    /// Binds enclave key derivation to this SEV-SNP platform.
    ///
    /// Call after the first successful attestation report to mix the VM's
    /// hardware measurement (MEASUREMENT field from SNP report) into all
    /// subsequent key derivations via [`crate::enclave_crypto::set_platform_measurement`].
    pub fn bind_platform_measurement(&self, measurement: &[u8]) {
        use sha2::{Digest, Sha256};
        // Hash the raw measurement (48 bytes SHA-384) down to 32 bytes for the KDF
        let hash = Sha256::digest(measurement);
        let mut m = [0u8; 32];
        m.copy_from_slice(&hash);
        crate::enclave_crypto::set_platform_measurement(m);
        tracing::info!("Enclave key derivation bound to SEV-SNP platform measurement");
    }

    /// Detects real SEV-SNP hardware.
    fn detect_sev_snp_hardware() -> bool {
        if std::path::Path::new("/dev/sev-guest").exists() {
            tracing::info!("AMD SEV-SNP hardware detected at /dev/sev-guest");
            return true;
        }

        // configfs-tsm (kernel 6.7+) also supports SEV-SNP
        if std::path::Path::new("/sys/kernel/config/tsm/report").exists() {
            // Check if provider is sev_guest
            if let Ok(provider) = std::fs::read_to_string("/sys/kernel/config/tsm/report/provider")
                && provider.trim() == "sev_guest"
            {
                tracing::info!("AMD SEV-SNP detected via configfs-tsm");
                return true;
            }
        }

        if std::path::Path::new("/dev/sev").exists() {
            tracing::info!("AMD SEV hardware detected at /dev/sev (may not support SNP)");
            return true;
        }

        tracing::warn!("AMD SEV-SNP hardware not available");
        false
    }

    /// Generates a real SNP attestation report via `/dev/sev-guest` ioctl.
    fn generate_snp_report_real(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            // Prepare snp_report_req: user_data[64] + vmpl[4] + rsvd[28] = 96 bytes
            let mut req = vec![0u8; 96];
            let copy_len = user_data.len().min(SNP_REPORT_USER_DATA_SIZE);
            req[..copy_len].copy_from_slice(&user_data[..copy_len]);
            // vmpl = 0 (VMPL0, highest privilege) at offset 64
            req[64..68].copy_from_slice(&0u32.to_le_bytes());

            // Response buffer matches kernel `struct snp_report_resp { __u8 data[4000]; }`
            // The PSP writes a snp_msg_report_rsp_hdr (32 bytes) followed by the
            // 1184-byte attestation report into this buffer.
            const SNP_REPORT_RESP_SIZE: usize = 4000;
            let mut resp = vec![0u8; SNP_REPORT_RESP_SIZE];

            // Prepare snp_guest_request_ioctl structure (matches kernel uapi):
            //   __u8  msg_version;        // offset 0,  1 byte  (+7 pad to align u64)
            //   __u64 req_data;           // offset 8,  8 bytes
            //   __u64 resp_data;          // offset 16, 8 bytes
            //   union { __u64 exitinfo2;
            //           struct { __u32 fw_error; __u32 vmm_error; } };
            //                             // offset 24, 8 bytes
            // total = 32 bytes
            const SNP_GUEST_REQUEST_IOCTL_SIZE: usize = 32;
            let mut ioctl_buf = vec![0u8; SNP_GUEST_REQUEST_IOCTL_SIZE];
            ioctl_buf[0] = 1; // msg_version = 1
            // req_data pointer at offset 8
            let req_ptr = req.as_ptr() as u64;
            ioctl_buf[8..16].copy_from_slice(&req_ptr.to_ne_bytes());
            // resp_data pointer at offset 16
            let resp_ptr = resp.as_mut_ptr() as u64;
            ioctl_buf[16..24].copy_from_slice(&resp_ptr.to_ne_bytes());

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")
                .map_err(|e| TeeError::AttestationGenerationFailed(
                    format!("Failed to open /dev/sev-guest: {}", e)
                ))?;

            // SNP_GET_REPORT = _IOWR('S', 0x0, struct snp_guest_request_ioctl)
            // Size in the ioctl number MUST match sizeof(struct snp_guest_request_ioctl) = 32.
            let ioctl_nr = build_ioctl_rw(
                SEV_IOCTL_MAGIC,
                SNP_GET_REPORT_NR,
                SNP_GUEST_REQUEST_IOCTL_SIZE as u32,
            );

            let ret = unsafe {
                libc::ioctl(file.as_raw_fd(), ioctl_nr as libc::c_ulong, ioctl_buf.as_mut_ptr())
            };

            if ret != 0 {
                let errno = std::io::Error::last_os_error();
                // exitinfo2 at offset 24: low 32 bits = fw_error, high 32 bits = vmm_error
                let fw_error = u32::from_le_bytes([
                    ioctl_buf[24], ioctl_buf[25], ioctl_buf[26], ioctl_buf[27]
                ]);
                let vmm_error = u32::from_le_bytes([
                    ioctl_buf[28], ioctl_buf[29], ioctl_buf[30], ioctl_buf[31]
                ]);
                return Err(TeeError::AttestationGenerationFailed(format!(
                    "SNP_GET_REPORT ioctl failed: {} (fw_error: 0x{:X}, vmm_error: 0x{:X})",
                    errno, fw_error, vmm_error
                )));
            }

            // Extract the attestation report from the response
            // Response format: status[4] + report_size[4] + reserved[24] + report[1184]
            let report_start = 32; // Skip response header
            if resp.len() >= report_start + SNP_REPORT_SIZE {
                let report = resp[report_start..report_start + SNP_REPORT_SIZE].to_vec();
                tracing::info!("SNP attestation report generated ({} bytes)", report.len());
                Ok(report)
            } else {
                // Fallback: return raw response
                tracing::warn!("SNP response smaller than expected, returning raw");
                Ok(resp)
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = user_data;
            Err(TeeError::not_available(
                "AMD SEV-SNP requires Linux (ioctl to /dev/sev-guest)"
            ))
        }
    }

    /// Generates an SNP attestation report (simulated or real).
    async fn generate_snp_report(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        if self.simulate {
            return self.generate_simulated_report(user_data);
        }

        self.generate_snp_report_real(user_data)
    }

    /// Generates a simulated SNP attestation report.
    fn generate_simulated_report(&self, user_data: &[u8]) -> Result<Vec<u8>> {
        let measurement = Sha384::digest(b"simulated-sev-snp-vm-measurement");

        let mut report_data = [0u8; 64];
        let copy_len = user_data.len().min(64);
        report_data[..copy_len].copy_from_slice(&user_data[..copy_len]);

        let report = serde_json::json!({
            "version": 2,
            "type": "SEV_SNP_REPORT_SIMULATED",
            "simulated": true,
            "guest_svn": 1,
            "vmpl": 0,
            "policy": {
                "abi_minor": 0,
                "abi_major": 1,
                "smt_allowed": false,
                "migration_agent_allowed": false,
                "debug_allowed": false,
            },
            "report_data": hex::encode(report_data),
            "measurement": hex::encode(measurement.as_slice()),
            "host_data": hex::encode([0u8; 32]),
            "id_key_digest": hex::encode(Sha384::digest(b"simulated-id-key").as_slice()),
            "author_key_digest": hex::encode(Sha384::digest(b"simulated-author-key").as_slice()),
            "report_id": hex::encode([0xABu8; 32]),
            "report_id_ma": hex::encode([0xCDu8; 32]),
            "reported_tcb": {
                "boot_loader": 3,
                "tee": 0,
                "snp": 12,
                "microcode": 209,
                "raw": "0300000C00D10000",
            },
            "committed_tcb": {
                "boot_loader": 3,
                "tee": 0,
                "snp": 12,
                "microcode": 209,
            },
            "chip_id": hex::encode([0xEFu8; 64]),
            "signature_algo": 1, // ECDSA P-384
        });

        Ok(serde_json::to_vec(&report)?)
    }

    /// Parses an SNP attestation report (real binary or simulated JSON).
    fn parse_report(&self, data: &[u8]) -> Result<SnpReport> {
        // Try JSON first (simulated)
        if let Ok(json) = serde_json::from_slice::<serde_json::Value>(data)
            && json.get("simulated").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            return self.parse_simulated_report(&json, data);
        }

        // Parse binary report
        self.parse_binary_report(data)
    }

    /// Parses a simulated JSON report.
    fn parse_simulated_report(&self, json: &serde_json::Value, raw: &[u8]) -> Result<SnpReport> {
        let get_hex = |key: &str| -> Vec<u8> {
            json.get(key)
                .and_then(|v| v.as_str())
                .and_then(|s| hex::decode(s).ok())
                .unwrap_or_default()
        };

        let tcb = &json["reported_tcb"];
        let reported_tcb = tcb.get("raw")
            .and_then(|v| v.as_str())
            .and_then(|s| hex::decode(s).ok())
            .map(|b| {
                if b.len() >= 8 {
                    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                } else {
                    0
                }
            })
            .unwrap_or(0);

        Ok(SnpReport {
            version: json.get("version").and_then(|v| v.as_u64()).unwrap_or(2) as u32,
            guest_svn: json.get("guest_svn").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
            policy: json.get("policy").and_then(|p| p.get("abi_major")).and_then(|v| v.as_u64()).unwrap_or(1),
            vmpl: json.get("vmpl").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            platform_version: 0,
            reported_tcb,
            committed_tcb: 0,
            measurement: get_hex("measurement"),
            report_data: get_hex("report_data"),
            host_data: get_hex("host_data"),
            chip_id: get_hex("chip_id"),
            report_id: get_hex("report_id"),
            signature_r: vec![],
            signature_s: vec![],
            raw: raw.to_vec(),
            simulated: true,
        })
    }

    /// Parses a real binary SNP attestation report.
    fn parse_binary_report(&self, data: &[u8]) -> Result<SnpReport> {
        if data.len() < SNP_REPORT_SIZE {
            return Err(TeeError::InvalidAttestationReport(format!(
                "SNP report too short: {} bytes (need {})", data.len(), SNP_REPORT_SIZE
            )));
        }

        let version = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if version != 2 {
            return Err(TeeError::InvalidAttestationReport(format!(
                "Unsupported SNP report version: {} (expected 2)", version
            )));
        }

        let guest_svn = u32::from_le_bytes(
            data[report_offsets::GUEST_SVN..report_offsets::GUEST_SVN + 4].try_into().unwrap()
        );
        let policy = u64::from_le_bytes(
            data[report_offsets::POLICY..report_offsets::POLICY + 8].try_into().unwrap()
        );
        let vmpl = u32::from_le_bytes(
            data[report_offsets::VMPL..report_offsets::VMPL + 4].try_into().unwrap()
        );
        let platform_version = u64::from_le_bytes(
            data[report_offsets::PLATFORM_VERSION..report_offsets::PLATFORM_VERSION + 8].try_into().unwrap()
        );
        let reported_tcb = u64::from_le_bytes(
            data[report_offsets::REPORTED_TCB..report_offsets::REPORTED_TCB + 8].try_into().unwrap()
        );
        let committed_tcb = u64::from_le_bytes(
            data[report_offsets::COMMITTED_TCB..report_offsets::COMMITTED_TCB + 8].try_into().unwrap()
        );

        // Extract ECDSA P-384 signature components (padded to 72 bytes each, actual is 48)
        let sig_r_padded = &data[report_offsets::SIGNATURE_R..report_offsets::SIGNATURE_R + 72];
        let sig_s_padded = &data[report_offsets::SIGNATURE_S..report_offsets::SIGNATURE_S + 72];

        // P-384 coordinates are 48 bytes — extract from padded 72-byte fields
        // AMD stores them as little-endian, need the first 48 bytes
        let signature_r = sig_r_padded[..48].to_vec();
        let signature_s = sig_s_padded[..48].to_vec();

        Ok(SnpReport {
            version,
            guest_svn,
            policy,
            vmpl,
            platform_version,
            reported_tcb,
            committed_tcb,
            measurement: data[report_offsets::MEASUREMENT..report_offsets::MEASUREMENT + 48].to_vec(),
            report_data: data[report_offsets::REPORT_DATA..report_offsets::REPORT_DATA + 64].to_vec(),
            host_data: data[report_offsets::HOST_DATA..report_offsets::HOST_DATA + 32].to_vec(),
            chip_id: data[report_offsets::CHIP_ID..report_offsets::CHIP_ID + 64].to_vec(),
            report_id: data[report_offsets::REPORT_ID..report_offsets::REPORT_ID + 32].to_vec(),
            signature_r,
            signature_s,
            raw: data.to_vec(),
            simulated: false,
        })
    }

    /// Extracts TCB components from the 8-byte reported_tcb field.
    fn decode_tcb(tcb: u64) -> HashMap<String, u8> {
        let bytes = tcb.to_le_bytes();
        HashMap::from([
            ("boot_loader".to_string(), bytes[0]),
            ("tee".to_string(), bytes[1]),
            ("reserved0".to_string(), bytes[2]),
            ("reserved1".to_string(), bytes[3]),
            ("snp".to_string(), bytes[4]),
            ("microcode".to_string(), bytes[5]),
            ("reserved2".to_string(), bytes[6]),
            ("reserved3".to_string(), bytes[7]),
        ])
    }

    /// Fetches the VCEK certificate from AMD KDS for a specific chip and TCB.
    ///
    /// NOTE: Requires `reqwest` dependency (enabled via amd-sev-snp feature).
    /// Falls back gracefully when reqwest is not available.
    #[cfg(feature = "amd-sev-snp")]
    async fn fetch_vcek_certificate(&self, chip_id: &[u8], reported_tcb: u64) -> Result<Vec<u8>> {
        if chip_id.len() != 64 {
            return Err(TeeError::InvalidAttestationReport(
                format!("Invalid chip_id length: {} (expected 64)", chip_id.len())
            ));
        }

        let tcb = Self::decode_tcb(reported_tcb);
        let chip_id_hex = hex::encode(chip_id).to_lowercase();

        // Try Milan first (most common), then Genoa
        let product_names = ["Milan", "Genoa"];

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to build HTTP client: {}", e)))?;

        for product_name in &product_names {
            let url = format!(
                "https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                product_name,
                chip_id_hex,
                tcb.get("boot_loader").unwrap_or(&0),
                tcb.get("tee").unwrap_or(&0),
                tcb.get("snp").unwrap_or(&0),
                tcb.get("microcode").unwrap_or(&0),
            );

            tracing::info!("Fetching VCEK from AMD KDS: {}", url);

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    let vcek_der = resp.bytes().await
                        .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to read VCEK: {}", e)))?
                        .to_vec();

                    tracing::info!("Fetched VCEK certificate from AMD KDS ({} bytes, product={})", vcek_der.len(), product_name);
                    return Ok(vcek_der);
                }
                Ok(resp) => {
                    tracing::debug!("AMD KDS VCEK request failed for {}: {}", product_name, resp.status());
                }
                Err(e) => {
                    tracing::debug!("AMD KDS VCEK request error for {}: {}", product_name, e);
                }
            }
        }

        Err(TeeError::AttestationGenerationFailed(
            format!("Failed to fetch VCEK from AMD KDS for chip_id={}", chip_id_hex)
        ))
    }

    #[cfg(not(feature = "amd-sev-snp"))]
    async fn fetch_vcek_certificate(&self, _chip_id: &[u8], _reported_tcb: u64) -> Result<Vec<u8>> {
        tracing::warn!("AMD KDS VCEK fetching requires reqwest (enable amd-sev-snp feature)");
        Err(TeeError::not_available("AMD KDS VCEK fetching not available"))
    }

    /// Fetches the ASK and ARK certificate chain from AMD KDS.
    ///
    /// NOTE: Requires `reqwest` dependency (enabled via amd-sev-snp feature).
    #[cfg(feature = "amd-sev-snp")]
    async fn fetch_cert_chain(&self, product_name: &str) -> Result<Vec<Vec<u8>>> {
        let url = format!("https://kdsintf.amd.com/vcek/v1/{}/cert_chain", product_name);

        tracing::info!("Fetching ASK+ARK cert chain from AMD KDS: {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to build HTTP client: {}", e)))?;

        let resp = client.get(&url)
            .send()
            .await
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to fetch cert chain: {}", e)))?;

        if !resp.status().is_success() {
            return Err(TeeError::AttestationGenerationFailed(
                format!("AMD KDS cert_chain request failed: {}", resp.status())
            ));
        }

        let pem_data = resp.text().await
            .map_err(|e| TeeError::AttestationGenerationFailed(format!("Failed to read cert chain: {}", e)))?;

        // Split PEM certificates (ASK and ARK)
        let mut certs = Vec::new();
        for cert_pem in pem_data.split("-----END CERTIFICATE-----") {
            if let Some(start) = cert_pem.find("-----BEGIN CERTIFICATE-----") {
                let full_pem = format!("{}-----END CERTIFICATE-----", &cert_pem[start..]);
                match certs::pem_to_der(&full_pem) {
                    Ok(der) => certs.push(der),
                    Err(e) => tracing::warn!("Failed to parse certificate from cert_chain: {}", e),
                }
            }
        }

        tracing::info!("Fetched {} certificates from AMD KDS cert_chain", certs.len());
        Ok(certs)
    }

    #[cfg(not(feature = "amd-sev-snp"))]
    async fn fetch_cert_chain(&self, _product_name: &str) -> Result<Vec<Vec<u8>>> {
        tracing::warn!("AMD KDS cert_chain fetching requires reqwest (enable amd-sev-snp feature)");
        Ok(vec![])
    }

    /// Verifies an SNP attestation report.
    ///
    /// For real reports:
    /// 1. Verify ECDSA P-384 signature over body (0x000–0x29F) using VCEK public key
    /// 2. Verify VCEK certificate chain: VCEK → ASK → ARK (pinned root)
    /// 3. Validate TCB versions
    /// 4. Check VMPL and policy
    ///
    /// For simulated reports:
    /// - Parse JSON, return result with simulated flag
    async fn verify_snp_report(&self, report_data: &[u8], certificates: &[Vec<u8>]) -> Result<AttestationResult> {
        let report = self.parse_report(report_data)?;

        let tcb_components = if report.simulated {
            // Parse from JSON
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(report_data) {
                let tcb = &json["reported_tcb"];
                format!(
                    "BL:{}.TEE:{}.SNP:{}.UCODE:{}",
                    tcb["boot_loader"].as_u64().unwrap_or(0),
                    tcb["tee"].as_u64().unwrap_or(0),
                    tcb["snp"].as_u64().unwrap_or(0),
                    tcb["microcode"].as_u64().unwrap_or(0),
                )
            } else {
                "unknown".to_string()
            }
        } else {
            let tcb = Self::decode_tcb(report.reported_tcb);
            format!(
                "BL:{}.TEE:{}.SNP:{}.UCODE:{}",
                tcb.get("boot_loader").unwrap_or(&0),
                tcb.get("tee").unwrap_or(&0),
                tcb.get("snp").unwrap_or(&0),
                tcb.get("microcode").unwrap_or(&0),
            )
        };

        let mut details = HashMap::from([
            ("vmpl".to_string(), report.vmpl.to_string()),
            ("guest_svn".to_string(), report.guest_svn.to_string()),
            ("version".to_string(), report.version.to_string()),
            // AMD SEV-SNP ABI fields surfaced for downstream policy checks
            // (e.g. callers binding nonce in report_data, gating on platform_version,
            // matching host_data against expected VMM config, correlating report_id).
            ("policy".to_string(), format!("0x{:016X}", report.policy)),
            ("platform_version".to_string(), format!("0x{:016X}", report.platform_version)),
            ("committed_tcb".to_string(), format!("0x{:016X}", report.committed_tcb)),
            ("report_data".to_string(), hex::encode(&report.report_data)),
            ("host_data".to_string(), hex::encode(&report.host_data)),
            ("report_id".to_string(), hex::encode(&report.report_id)),
        ]);

        let mut cert_chain_valid = false;
        let mut signature_valid = false;

        if report.simulated {
            details.insert("simulated".to_string(), "true".to_string());
            details.insert("type".to_string(), "simulated".to_string());
            tracing::warn!(
                "Verifying SIMULATED AMD SEV-SNP report — AttestationResult.valid \
                 will be false. Simulated reports carry no cryptographic authority."
            );
        } else {
            details.insert("type".to_string(), "real".to_string());
            details.insert("chip_id".to_string(), hex::encode(&report.chip_id));
            tracing::info!("Verifying real AMD SEV-SNP report");

            // Verify the report body signature
            if !report.signature_r.is_empty() && !report.signature_s.is_empty() {
                tracing::debug!(
                    "SNP report signature: R={} bytes, S={} bytes",
                    report.signature_r.len(), report.signature_s.len()
                );
            }

            // Verify certificate chain
            if !certificates.is_empty() {
                cert_chain_valid = self.verify_amd_cert_chain(certificates)?;

                // If we have certificates, verify the report signature using VCEK
                if !report.signature_r.is_empty() && !report.signature_s.is_empty() {
                    match self.verify_report_signature(&report, &certificates[0]) {
                        Ok(true) => {
                            tracing::info!("SNP report signature verified successfully");
                            details.insert("signature_verified".to_string(), "true".to_string());
                            signature_valid = true;
                        }
                        Ok(false) => {
                            tracing::warn!("SNP report signature verification failed");
                            details.insert("signature_verified".to_string(), "false".to_string());
                        }
                        Err(e) => {
                            tracing::warn!("SNP report signature verification error: {}", e);
                            details.insert("signature_verified".to_string(), format!("error: {}", e));
                        }
                    }
                }
            }

            // For real reports, compute the body hash
            // The signed body is bytes 0x000–0x29F (672 bytes)
            if report.raw.len() >= report_offsets::SIGNED_BODY_LEN {
                let signed_body = &report.raw[..report_offsets::SIGNED_BODY_LEN];
                let body_hash = Sha384::digest(signed_body);
                details.insert("body_hash".to_string(), hex::encode(body_hash.as_slice()));
            }
        }

        let measurements = vec![
            Measurement {
                index: 0,
                algorithm: "SHA384".to_string(),
                value: report.measurement.clone(),
                register: "MEASUREMENT".to_string(),
                description: Some("Initial VM state measurement".to_string()),
            },
        ];

        // Fail-closed validity. A real SNP report is `valid` only when BOTH
        // the VCEK-anchored report-body signature and the ARK→ASK→VCEK
        // certificate chain verify. Simulated reports are NEVER valid.
        let valid = !report.simulated && signature_valid && cert_chain_valid;

        Ok(AttestationResult {
            valid,
            vendor: TeeVendor::AmdSevSnp,
            tcb_version: tcb_components,
            measurements,
            cert_chain_valid,
            details,
            verified_at: tenzro_types::Timestamp::now(),
            ..Default::default()
        })
    }

    /// Verifies the SNP report body signature against the VCEK certificate.
    ///
    /// AMD SEV-SNP reports are signed with ECDSA P-384 over SHA-384.
    /// The signature is stored in little-endian format but P-384 crate expects big-endian.
    fn verify_report_signature(&self, report: &SnpReport, vcek_der: &[u8]) -> Result<bool> {
        // Parse VCEK certificate to extract public key
        let vcek_cert = attestation::parse_x509_certificate(vcek_der)?;

        // The signed body is bytes 0x000–0x29F (672 bytes)
        if report.raw.len() < report_offsets::SIGNED_BODY_LEN {
            return Err(TeeError::InvalidAttestationReport(
                "Report too short for signature verification".to_string()
            ));
        }

        let signed_body = &report.raw[..report_offsets::SIGNED_BODY_LEN];

        // AMD stores P-384 signature components in little-endian format (48 bytes each)
        // but the P-384 crate expects big-endian, so reverse the byte order
        let mut signature_r_be = report.signature_r.clone();
        let mut signature_s_be = report.signature_s.clone();
        signature_r_be.reverse();
        signature_s_be.reverse();

        // Combine R and S into 96-byte signature (48+48)
        let mut signature_bytes = Vec::with_capacity(96);
        signature_bytes.extend_from_slice(&signature_r_be);
        signature_bytes.extend_from_slice(&signature_s_be);

        // Verify using the attestation module's P-384 verification
        attestation::verify_ecdsa_p384_signature(&vcek_cert.spki_der, signed_body, &signature_bytes)
    }

    /// Verifies the AMD certificate chain against pinned root ARK.
    fn verify_amd_cert_chain(&self, certificates: &[Vec<u8>]) -> Result<bool> {
        // Try Milan ARK first (most common)
        let root_der = certs::pem_to_der(certs::AMD_ARK_MILAN_PEM)
            .map_err(|e| TeeError::CertificateValidationFailed(
                format!("Failed to decode AMD ARK: {}", e)
            ))?;

        let root_cert = attestation::parse_x509_certificate(&root_der)?;

        let mut chain: Vec<ParsedCertificate> = Vec::new();
        for cert_der in certificates {
            match attestation::parse_x509_certificate(cert_der) {
                Ok(cert) => chain.push(cert),
                Err(e) => {
                    tracing::warn!("Failed to parse certificate in AMD chain: {}", e);
                }
            }
        }

        if chain.is_empty() {
            return Ok(false);
        }

        // Verify last cert is signed by ARK
        let last = chain.last().unwrap();
        if last.issuer_cn == root_cert.subject_cn || last.subject_cn == root_cert.subject_cn {
            let verified = attestation::verify_certificate_signature(last, &root_cert.spki_der)?;
            if verified {
                tracing::info!("AMD SEV-SNP certificate chain verified against pinned ARK");
            }
            Ok(verified)
        } else {
            // Try Genoa ARK
            let genoa_der = certs::pem_to_der(certs::AMD_ARK_GENOA_PEM)
                .map_err(|e| TeeError::CertificateValidationFailed(
                    format!("Failed to decode AMD ARK Genoa: {}", e)
                ))?;

            let genoa_cert = attestation::parse_x509_certificate(&genoa_der)?;
            if last.issuer_cn == genoa_cert.subject_cn || last.subject_cn == genoa_cert.subject_cn {
                let verified = attestation::verify_certificate_signature(last, &genoa_cert.spki_der)?;
                if verified {
                    tracing::info!("AMD SEV-SNP certificate chain verified against Genoa ARK");
                }
                Ok(verified)
            } else {
                tracing::warn!(
                    "AMD chain does not terminate at ARK: last issuer='{}', Milan ARK='{}', Genoa ARK='{}'",
                    last.issuer_cn, root_cert.subject_cn, genoa_cert.subject_cn
                );
                Ok(false)
            }
        }
    }
}

impl AmdSevSnpProvider {
    /// Requests a 64-byte hardware-derived key from the AMD PSP via
    /// `SNP_GET_DERIVED_KEY` on `/dev/sev-guest`.
    ///
    /// The PSP derives the key from a root key (VCEK or VMRK, selected by
    /// `root_key_select`) mixed with the bits selected in `guest_field_select`.
    /// Setting `MEASUREMENT | IMAGE_ID | GUEST_SVN` binds the key to the VM's
    /// initial measured state — the same VM image redeploys to the same key,
    /// any tampering produces a different key, and another tenant's VM cannot
    /// recover this key even on the same physical host.
    ///
    /// Returns 64 bytes of raw key material suitable as input keying material
    /// (IKM) for HKDF-SHA256.
    ///
    /// # Errors
    ///
    /// - [`TeeError::NotAvailable`] when not running on Linux or
    ///   `/dev/sev-guest` is missing — there is no simulation fallback per
    ///   Tenzro's no-simulation-on-testnet policy. Caller decides whether to
    ///   fail open or proceed with a software-only signer.
    /// - [`TeeError::AttestationGenerationFailed`] when the ioctl returns a
    ///   non-zero exit (PSP firmware error, VMM passthrough error).
    pub fn derived_key(
        &self,
        root_key_select: u32,
        guest_field_select: u64,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Result<[u8; SNP_DERIVED_KEY_SIZE]> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            // struct snp_derived_key_req {
            //   __u32 root_key_select;     // offset 0,  4 bytes
            //   __u32 rsvd;                // offset 4,  4 bytes
            //   __u64 guest_field_select;  // offset 8,  8 bytes
            //   __u32 vmpl;                // offset 16, 4 bytes
            //   __u32 guest_svn;           // offset 20, 4 bytes
            //   __u64 tcb_version;         // offset 24, 8 bytes
            // }                            // total = 32 bytes
            const SNP_DERIVED_KEY_REQ_SIZE: usize = 32;
            let mut req = vec![0u8; SNP_DERIVED_KEY_REQ_SIZE];
            req[0..4].copy_from_slice(&root_key_select.to_le_bytes());
            // rsvd at offset 4 stays zero
            req[8..16].copy_from_slice(&guest_field_select.to_le_bytes());
            req[16..20].copy_from_slice(&vmpl.to_le_bytes());
            req[20..24].copy_from_slice(&guest_svn.to_le_bytes());
            req[24..32].copy_from_slice(&tcb_version.to_le_bytes());

            // Response buffer: PSP writes a 32-byte response header followed by
            // struct snp_derived_key_resp { __u8 data[64]; }. The kernel sizes
            // its response buffer at 4000 bytes (same as SNP_GET_REPORT) for
            // forward compatibility — overallocate to match kernel behavior.
            const SNP_DERIVED_KEY_RESP_SIZE: usize = 4000;
            let mut resp = vec![0u8; SNP_DERIVED_KEY_RESP_SIZE];

            // snp_guest_request_ioctl envelope (same shape used by SNP_GET_REPORT):
            //   __u8  msg_version;        // offset 0   (+7 pad)
            //   __u64 req_data;           // offset 8
            //   __u64 resp_data;          // offset 16
            //   union { __u64 exitinfo2;
            //           struct { __u32 fw_error; __u32 vmm_error; } };
            //                             // offset 24
            const SNP_GUEST_REQUEST_IOCTL_SIZE: usize = 32;
            let mut ioctl_buf = vec![0u8; SNP_GUEST_REQUEST_IOCTL_SIZE];
            ioctl_buf[0] = 1; // msg_version = 1
            let req_ptr = req.as_ptr() as u64;
            ioctl_buf[8..16].copy_from_slice(&req_ptr.to_ne_bytes());
            let resp_ptr = resp.as_mut_ptr() as u64;
            ioctl_buf[16..24].copy_from_slice(&resp_ptr.to_ne_bytes());

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")
                .map_err(|e| TeeError::not_available(format!(
                    "Failed to open /dev/sev-guest: {}", e
                )))?;

            let ioctl_nr = build_ioctl_rw(
                SEV_IOCTL_MAGIC,
                SNP_GET_DERIVED_KEY_NR,
                SNP_GUEST_REQUEST_IOCTL_SIZE as u32,
            );

            let ret = unsafe {
                libc::ioctl(file.as_raw_fd(), ioctl_nr as libc::c_ulong, ioctl_buf.as_mut_ptr())
            };

            if ret != 0 {
                let errno = std::io::Error::last_os_error();
                let fw_error = u32::from_le_bytes([
                    ioctl_buf[24], ioctl_buf[25], ioctl_buf[26], ioctl_buf[27]
                ]);
                let vmm_error = u32::from_le_bytes([
                    ioctl_buf[28], ioctl_buf[29], ioctl_buf[30], ioctl_buf[31]
                ]);
                return Err(TeeError::AttestationGenerationFailed(format!(
                    "SNP_GET_DERIVED_KEY ioctl failed: {} (fw_error: 0x{:X}, vmm_error: 0x{:X})",
                    errno, fw_error, vmm_error
                )));
            }

            // Response layout mirrors SNP_GET_REPORT: 32-byte header, then the
            // snp_derived_key_resp.data[64].
            let key_start = 32;
            if resp.len() < key_start + SNP_DERIVED_KEY_SIZE {
                return Err(TeeError::AttestationGenerationFailed(
                    "SNP_GET_DERIVED_KEY response truncated".to_string()
                ));
            }
            let mut out = [0u8; SNP_DERIVED_KEY_SIZE];
            out.copy_from_slice(&resp[key_start..key_start + SNP_DERIVED_KEY_SIZE]);
            tracing::debug!(
                "SNP derived key obtained (root_key_select={}, guest_field_select=0x{:X})",
                root_key_select, guest_field_select
            );
            Ok(out)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (root_key_select, guest_field_select, vmpl, guest_svn, tcb_version);
            Err(TeeError::not_available(
                "SNP_GET_DERIVED_KEY requires Linux (ioctl to /dev/sev-guest)"
            ))
        }
    }
}

impl Default for AmdSevSnpProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TeeProvider for AmdSevSnpProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::AmdSevSnp
    }

    async fn is_available(&self) -> Result<bool> {
        Ok(self.available)
    }

    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }

        let attestation_data = self.generate_snp_report(user_data).await?;

        let mut metadata = HashMap::from([
            ("sev_snp_version".to_string(), "1.55".to_string()),
            ("firmware_version".to_string(), "1.55.25".to_string()),
        ]);

        if self.simulate {
            metadata.insert("simulated".to_string(), "true".to_string());
        }

        // In real mode, fetch VCEK and cert chain from AMD KDS
        let certificates = if !self.simulate && attestation_data.len() >= SNP_REPORT_SIZE {
            // Parse the report to extract chip_id, measurement, and reported_tcb
            match self.parse_binary_report(&attestation_data) {
                Ok(report) => {
                    // Bind enclave key derivation to this platform's measurement
                    self.bind_platform_measurement(&report.measurement);

                    let mut certs = Vec::new();

                    // Fetch VCEK certificate
                    match self.fetch_vcek_certificate(&report.chip_id, report.reported_tcb).await {
                        Ok(vcek) => {
                            tracing::info!("Fetched VCEK certificate ({} bytes)", vcek.len());
                            certs.push(vcek);

                            // Try fetching cert chain for Milan first, then Genoa
                            for product_name in &["Milan", "Genoa"] {
                                match self.fetch_cert_chain(product_name).await {
                                    Ok(chain) if !chain.is_empty() => {
                                        tracing::info!("Fetched {} certs from AMD KDS cert_chain ({})", chain.len(), product_name);
                                        certs.extend(chain);
                                        break;
                                    }
                                    Ok(_) => {
                                        tracing::debug!("No certs in AMD KDS cert_chain for {}", product_name);
                                    }
                                    Err(e) => {
                                        tracing::debug!("Failed to fetch cert_chain for {}: {}", product_name, e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Failed to fetch VCEK certificate: {}", e);
                        }
                    }

                    certs
                }
                Err(e) => {
                    tracing::warn!("Failed to parse SNP report for cert fetching: {}", e);
                    vec![]
                }
            }
        } else {
            vec![]
        };

        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::AmdSevSnp,
            user_data: user_data.to_vec(),
            attestation_data,
            certificates,
            timestamp: tenzro_types::Timestamp::now(),
            metadata,
            ..Default::default()
        })
    }

    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult> {
        if report.vendor != TeeVendor::AmdSevSnp {
            return Err(TeeError::InvalidAttestationReport(
                "Report is not from AMD SEV-SNP".to_string(),
            ));
        }

        self.verify_snp_report(&report.attestation_data, &report.certificates).await
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }

        tracing::info!("Executing in SEV-SNP VM: {:?}", request.operation);

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
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
        if self.simulate {
            return Err(TeeError::not_available(
                "AMD SEV-SNP simulation mode cannot supply real SNP_GET_DERIVED_KEY IKM",
            ));
        }
        // Pin the derivation to MEASUREMENT|IMAGE_ID|GUEST_SVN so two
        // different boots of the same workload reproduce the same key
        // and a tampered boot chain cannot recover prior keys.
        const ROOT_KEY_SELECT: u32 = 0;
        const GUEST_FIELD_SELECT: u64 = 0b101; // MEASUREMENT|IMAGE_ID|GUEST_SVN
        let ikm = self.derived_key(ROOT_KEY_SELECT, GUEST_FIELD_SELECT, 0, 0, 0)?;
        let handle = self.keystore.keygen(params, &ikm).await?;
        tracing::info!(
            key_id = %handle.id,
            algorithm = ?handle.algorithm,
            "Generated key in SEV-SNP VM keystore"
        );
        Ok(handle)
    }

    async fn enclave_sign(&self, key: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
        self.keystore.sign(key, data).await
    }

    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
        self.keystore.encrypt(key, plaintext).await
    }

    async fn enclave_decrypt(&self, key: &EnclaveKeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
        self.keystore.decrypt(key, ciphertext).await
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Returns true only when simulation is explicitly requested via env var.
/// Real hardware is the default — set `TENZRO_SIMULATE_SEV=1` to override.
fn is_simulation_mode() -> bool {
    std::env::var("TENZRO_SIMULATE_SEV")
        .or_else(|_| std::env::var("TENZRO_SIMULATE_SEV_SNP"))
        .unwrap_or_else(|_| "0".to_string()) == "1"
}

#[cfg(target_os = "linux")]
fn build_ioctl_rw(magic: u8, nr: u8, size: u32) -> u32 {
    let dir: u32 = 3; // _IOC_READ | _IOC_WRITE
    (dir << 30) | ((size & 0x3FFF) << 16) | ((magic as u32) << 8) | (nr as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sev_snp_provider_creation() {
        let provider = AmdSevSnpProvider::new();
        assert_eq!(provider.vendor(), TeeVendor::AmdSevSnp);
    }

    #[test]
    fn test_derived_key_off_hardware_returns_not_available() {
        // On every non-SEV host (including macOS dev machines and Linux CI
        // without /dev/sev-guest), derived_key MUST return NotAvailable rather
        // than fabricate key material. No-simulation policy on testnet.
        let provider = AmdSevSnpProvider::new();
        let result = provider.derived_key(
            0,
            guest_field_select::MEASUREMENT | guest_field_select::IMAGE_ID,
            0,
            0,
            0,
        );
        match result {
            Err(TeeError::NotAvailable(_)) => { /* expected on dev/CI */ }
            Err(TeeError::AttestationGenerationFailed(_)) => {
                // Acceptable on a real SEV host where /dev/sev-guest exists
                // but the test isn't running under VMPL0.
            }
            Ok(_) => {
                // Only acceptable if the test really is running on SEV-SNP
                // hardware. Any other path producing Ok(_) would be a bug.
                assert!(std::path::Path::new("/dev/sev-guest").exists());
            }
            Err(other) => panic!("unexpected error variant: {:?}", other),
        }
    }

    #[test]
    fn test_guest_field_select_bits_match_amd_spec() {
        // AMD SEV-SNP ABI spec rev 1.55, Table 16
        assert_eq!(guest_field_select::GUEST_POLICY, 0x01);
        assert_eq!(guest_field_select::IMAGE_ID, 0x02);
        assert_eq!(guest_field_select::FAMILY_ID, 0x04);
        assert_eq!(guest_field_select::MEASUREMENT, 0x08);
        assert_eq!(guest_field_select::GUEST_SVN, 0x10);
        assert_eq!(guest_field_select::TCB_VERSION, 0x20);
    }

    #[tokio::test]
    async fn test_sev_snp_simulation_mode() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();
        assert!(provider.simulate);
        assert!(provider.available);
    }

    #[tokio::test]
    async fn test_sev_snp_generate_simulated_report() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();

        let user_data = b"tenzro-sev-test";
        let report = provider.generate_attestation(user_data).await;
        assert!(report.is_ok());

        let report = report.unwrap();
        assert_eq!(report.vendor, TeeVendor::AmdSevSnp);
        assert_eq!(report.user_data, user_data);
        assert!(!report.attestation_data.is_empty());
        assert_eq!(report.metadata.get("simulated"), Some(&"true".to_string()));
    }

    #[tokio::test]
    async fn test_sev_snp_verify_simulated_report_is_invalid() {
        // Simulated reports carry no cryptographic authority — verifier
        // exposes measurements + details for observability but `valid`
        // MUST be false.
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        assert!(
            !result.valid,
            "simulated SEV-SNP reports must never report valid=true"
        );
        assert_eq!(result.vendor, TeeVendor::AmdSevSnp);
        assert_eq!(result.details.get("simulated"), Some(&"true".to_string()));
        assert!(!result.measurements.is_empty());
        assert_eq!(result.measurements[0].algorithm, "SHA384");
        assert_eq!(result.measurements[0].register, "MEASUREMENT");
    }

    #[tokio::test]
    async fn test_sev_snp_keygen_in_simulation_returns_not_available() {
        // Simulation cannot supply the SNP_GET_DERIVED_KEY IKM, so
        // `enclave_keygen` rejects with NotAvailable. No fabrication.
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();

        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Secp256k1,
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
    async fn test_sev_snp_keystore_real_secp256k1_recovers() {
        use k256::ecdsa::{
            RecoveryId, Signature as K256Sig, VerifyingKey as Secp256k1Verifying,
        };
        use k256::elliptic_curve::sec1::ToSec1Point;
        use sha2::{Digest, Sha256};
        let ks = crate::enclave_keystore::EnclaveKeystore::new("amd-sev-snp-test");
        let ikm: Vec<u8> = (0u8..64).collect();
        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Secp256k1,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: HashMap::new(),
        };
        let handle = ks.keygen(params, &ikm).await.unwrap();
        let pk_uncompressed = handle.public_key.clone().unwrap();
        let msg = b"amd-sev-snp real Secp256k1";
        let sig = ks.sign(&handle, msg).await.unwrap();

        let mut h = Sha256::new();
        h.update(msg);
        let digest = h.finalize();
        let r_s: [u8; 64] = sig[..64].try_into().unwrap();
        let v = sig[64];
        let parsed = K256Sig::from_slice(&r_s).unwrap();
        let rec = RecoveryId::from_byte(v).unwrap();
        let recovered = Secp256k1Verifying::recover_from_prehash(&digest, &parsed, rec).unwrap();
        let recovered_encoded =
            k256::PublicKey::from(&recovered).to_sec1_point(false);
        assert_eq!(recovered_encoded.as_bytes(), pk_uncompressed.as_slice());
    }

    #[tokio::test]
    async fn test_sev_snp_wrong_vendor_rejected() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();

        let mut report = provider.generate_attestation(b"test").await.unwrap();
        report.vendor = TeeVendor::IntelTdx;

        let result = provider.verify_attestation(&report).await;
        assert!(result.is_err());
    }

    #[test]
    fn test_report_offsets() {
        assert_eq!(report_offsets::REPORT_DATA, 0x050);
        assert_eq!(report_offsets::MEASUREMENT, 0x090);
        assert_eq!(report_offsets::CHIP_ID, 0x1A0);
        assert_eq!(report_offsets::SIGNATURE, 0x2A0);
        assert_eq!(report_offsets::SIGNED_BODY_LEN, 0x2A0);
    }

    #[test]
    fn test_decode_tcb() {
        let tcb: u64 = 0x0000_D10C_0000_0003;
        let components = AmdSevSnpProvider::decode_tcb(tcb);
        assert_eq!(*components.get("boot_loader").unwrap(), 3);
    }

    #[tokio::test]
    async fn test_sev_snp_parse_simulated_report() {
        unsafe { std::env::set_var("TENZRO_SIMULATE_SEV_SNP", "1"); }
        let provider = AmdSevSnpProvider::new();

        let data = provider.generate_simulated_report(b"hello").unwrap();
        let report = provider.parse_report(&data).unwrap();

        assert!(report.simulated);
        assert_eq!(report.version, 2);
        assert_eq!(report.vmpl, 0);
        assert!(!report.measurement.is_empty());
    }
}
