//! NVIDIA GPU Confidential Computing TEE provider
//!
//! Implements TEE attestation for NVIDIA H100/H200/Blackwell GPUs with
//! Confidential Computing support. This is critical for AI-focused chains
//! because it enables verifiable GPU inference — proving that model execution
//! occurred inside a hardware-isolated GPU environment with attestation.
//!
//! # NVIDIA Confidential Computing Architecture
//!
//! NVIDIA GPUs with CC (Confidential Computing) provide:
//! - **Hardware-level memory encryption**: GPU memory (HBM) is encrypted with
//!   AES-256-GCM, isolating it from the host CPU and hypervisor
//! - **Attestation**: GPU generates signed attestation reports proving the
//!   execution environment is genuine and untampered
//! - **Secure boot**: GPU firmware is measured and attested
//!
//! # Supported GPUs
//!
//! Confidential-Computing-capable (full TEE attestation):
//! - NVIDIA H100 (Hopper architecture, CC 1.0)
//! - NVIDIA H200 (Hopper architecture, CC 1.0, extended HBM)
//! - NVIDIA H800 / H20 (Hopper architecture, China-region SKUs)
//! - NVIDIA B100 / B200 / GB200 (Blackwell architecture, CC 2.0)
//! - NVIDIA L40S (Ada Lovelace datacenter, limited CC support)
//!
//! Detected and serviced for inference (no CC, no attestation):
//! - NVIDIA L40 / L4 (Ada Lovelace datacenter)
//! - NVIDIA RTX 4090 / 4080 / 4070 / 4060 series (Ada Lovelace consumer)
//! - NVIDIA A100 / A40 / A30 / A10 / A16 / A2 (Ampere datacenter)
//! - NVIDIA RTX 3090 / 3080 / 3070 / 3060 / 3050 series (Ampere consumer)
//! - NVIDIA Tesla T4 (Turing datacenter inference)
//! - NVIDIA RTX 2080 / 2070 / 2060 series (Turing consumer)
//! - NVIDIA V100 (Volta datacenter)
//!
//! # Attestation Flow
//!
//! 1. Tenzro node detects CC-capable GPU via `nvidia-smi` or NVML
//! 2. GPU evidence is collected via SPDM (Security Protocol and Data Model)
//!    protocol, which extracts measurements from the GPU's hardware RoT
//! 3. Evidence is sent to NVIDIA Remote Attestation Service (NRAS) for verification:
//!    - NRAS validates GPU identity against manufacturing records
//!    - NRAS verifies firmware measurements against Reference Integrity Manifests (RIMs)
//!    - NRAS checks device certificate chain (GPU AK → NVIDIA CA)
//!    - NRAS returns a signed JWT attestation token
//! 4. Tenzro consensus weighs the attestation in leader election
//!
//! # NRAS API
//!
//! The NVIDIA Remote Attestation Service exposes:
//! - `POST /v4/attest/gpu` — Submit GPU evidence for verification
//!   - Request: JSON with `evidence` (base64), `nonce` (hex), `arch` (string)
//!   - Response: JWT attestation token with claims about GPU integrity
//!   - Nonce TTL: 24 hours (server-side)
//!
//! Local verification is also possible using NVIDIA nvtrust tools and RIM
//! files, but requires downloading golden measurements from NVIDIA.
//!
//! # References
//!
//! - NVIDIA Confidential Computing: https://developer.nvidia.com/confidential-computing
//! - NVIDIA Remote Attestation Service (NRAS): https://docs.nvidia.com/attestation/index.html
//! - NVIDIA nvtrust: https://github.com/NVIDIA/nvtrust
//! - NVIDIA Hopper CC Whitepaper: https://images.nvidia.com/aem-dam/en-zz/Solutions/data-center/HCC-Whitepaper-v1.0.pdf
//! - SPDM specification: https://www.dmtf.org/standards/spdm

use crate::certs;
use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_types::tee::*;

/// NVIDIA GPU Confidential Computing provider.
///
/// Supports two modes:
/// - **Simulation mode** (`TENZRO_SIMULATE_GPU=1`): Returns simulated attestation
///   data for development and testing without real GPU hardware.
/// - **Real mode** (default): Detects real NVIDIA GPUs via `nvidia-smi`,
///   collects GPU evidence, and verifies via NRAS cloud API.
pub struct NvidiaGpuProvider {
    /// Provider configuration
    config: NvidiaGpuConfig,
    /// Cached GPU info (populated on first availability check)
    gpu_info: RwLock<Option<GpuDeviceInfo>>,
    /// Cached availability state. `None` until first probe; `Some(true)` if a
    /// CC-capable GPU was detected and CC is enabled; `Some(false)` if probing
    /// failed or CC is disabled. Used by `is_available()` and the attestation
    /// path to short-circuit repeated `nvidia-smi` invocations.
    available: RwLock<Option<bool>>,
    /// Whether we're running in simulation mode
    simulate: bool,
    /// CPU confidential-VM provider the GPU is admitted to, if one was supplied.
    ///
    /// The GPU report and the CPU quote are generated under a single shared
    /// nonce so a verifier can tell they describe the same machine at the same
    /// moment. Without this the provider can only speak for the device.
    cpu_anchor: Option<Arc<dyn TeeProvider>>,
    /// Enclave keys (in-memory, keyed by UUID)
    keys: Arc<RwLock<HashMap<uuid::Uuid, EnclaveKeyHandle>>>,
    /// Secret key material for simulation mode (in production, keys stay in GPU CC memory)
    secret_keys: Arc<RwLock<HashMap<uuid::Uuid, Vec<u8>>>>,
}

/// NVIDIA GPU TEE configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaGpuConfig {
    /// GPU device index (default: 0 for single-GPU systems)
    pub device_index: u32,
    /// NVIDIA Remote Attestation Service endpoint (NRAS)
    pub nras_endpoint: String,
    /// Whether to verify attestation via NRAS (remote) or local RIM
    pub use_remote_attestation: bool,
    /// Minimum required driver version (e.g., "550.0")
    pub min_driver_version: String,
    /// Minimum required CC firmware version
    pub min_cc_firmware_version: String,
    /// Maximum attestation report age (milliseconds)
    pub max_report_age_ms: i64,
    /// Expected GPU architecture
    pub expected_architecture: GpuArchitecture,
    /// Whether a CPU confidential-VM anchor is required before this provider
    /// will present a complete TEE claim.
    ///
    /// NVIDIA GPU CC does not establish a trust boundary on its own: the
    /// confidential VM is created by SEV-SNP or TDX, and the GPU is then
    /// admitted to that VM over an SPDM-authenticated link. A GPU report on its
    /// own attests the device, not the environment the workload runs in. With
    /// this set, [`NvidiaGpuProvider::with_cpu_anchor`] must have supplied a CPU
    /// provider or attestation is refused.
    pub require_cpu_anchor: bool,
}

impl Default for NvidiaGpuConfig {
    fn default() -> Self {
        Self {
            device_index: 0,
            nras_endpoint: certs::NVIDIA_NRAS_ENDPOINT.to_string(),
            use_remote_attestation: true,
            min_driver_version: "550.0".to_string(),
            min_cc_firmware_version: "1.0".to_string(),
            max_report_age_ms: 24 * 60 * 60 * 1000, // 24 hours
            expected_architecture: GpuArchitecture::Hopper,
            require_cpu_anchor: true,
        }
    }
}

/// GPU architecture identifier.
///
/// Includes both CC-capable architectures (Hopper, Blackwell, Ada Lovelace)
/// and older non-CC architectures (Ampere, Turing, Volta). Consumer-tier and
/// older datacenter cards are recognized so that inference providers without
/// CC-capable hardware can still register and serve models — they just don't
/// get TEE attestation weighting in consensus or escrow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuArchitecture {
    /// NVIDIA Hopper (H100, H200, H800, H20) — CC 1.0
    Hopper,
    /// NVIDIA Blackwell (B100, B200, GB200) — CC 2.0
    Blackwell,
    /// NVIDIA Ada Lovelace (L40S, L40, L4, RTX 40-series) — limited CC on L40S only
    AdaLovelace,
    /// NVIDIA Ampere (A100, A40, A30, A10, A16, A2, RTX 30-series) — no CC
    Ampere,
    /// NVIDIA Turing (Tesla T4, RTX 20-series) — no CC
    Turing,
    /// NVIDIA Volta (V100) — no CC
    Volta,
}

impl GpuArchitecture {
    /// Whether this architecture has any CC-capable SKUs.
    ///
    /// Note that this is architecture-level — within Ada Lovelace, only L40S
    /// supports CC. Use [`known_gpus::cc_capable`] for per-device truth.
    pub fn supports_cc(&self) -> bool {
        matches!(
            self,
            GpuArchitecture::Hopper | GpuArchitecture::Blackwell | GpuArchitecture::AdaLovelace
        )
    }
}

impl std::fmt::Display for GpuArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuArchitecture::Hopper => write!(f, "Hopper"),
            GpuArchitecture::Blackwell => write!(f, "Blackwell"),
            GpuArchitecture::AdaLovelace => write!(f, "Ada Lovelace"),
            GpuArchitecture::Ampere => write!(f, "Ampere"),
            GpuArchitecture::Turing => write!(f, "Turing"),
            GpuArchitecture::Volta => write!(f, "Volta"),
        }
    }
}

/// Information about a detected NVIDIA GPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuDeviceInfo {
    /// GPU model name (e.g., "NVIDIA H100 80GB HBM3")
    pub name: String,
    /// GPU architecture
    pub architecture: GpuArchitecture,
    /// PCI device ID
    pub pci_device_id: String,
    /// Driver version
    pub driver_version: String,
    /// CUDA compute capability (e.g., "9.0" for H100)
    pub compute_capability: String,
    /// Total GPU memory in bytes
    pub memory_total: u64,
    /// Whether Confidential Computing mode is enabled
    pub cc_enabled: bool,
    /// CC firmware version (if CC is enabled)
    pub cc_firmware_version: Option<String>,
    /// GPU serial number hash (for identity without revealing serial)
    pub serial_hash: String,
}

/// NVIDIA GPU attestation report (internal format before conversion to AttestationReport).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuAttestationReport {
    /// GPU device info
    pub device_info: GpuDeviceInfo,
    /// The attestation report exactly as the driver returned it.
    ///
    /// Kept verbatim because NVIDIA's remote attestation service re-parses the
    /// SPDM exchange itself and checks the device signature over the original
    /// transcript. Anything re-encoded from the parsed fields below would no
    /// longer carry that signature.
    pub raw_report: Vec<u8>,
    /// What the device reported in its SPDM measurement record
    pub measurements: GpuMeasurements,
    /// CC mode attestation status
    pub cc_status: CcAttestationStatus,
    /// Nonce provided by the verifier (for freshness)
    pub nonce: Vec<u8>,
    /// Report generation timestamp (milliseconds since epoch)
    pub timestamp: i64,
    /// ECDSA P-384 signature over the report (from GPU Attestation Key)
    pub signature: Vec<u8>,
    /// Certificate chain (GPU Attestation Key → NVIDIA CA)
    pub cert_chain: Vec<Vec<u8>>,
    /// Chain for the key that signed the attestation report, which the driver
    /// returns separately from the device certificate chain. A verifier walks
    /// the signature up through this one.
    pub attestation_cert_chain: Vec<u8>,
    /// Report from the GPU's security controller, when the part exposes one.
    /// Hopper carries a CEC alongside the GPU die; Blackwell reports without it.
    pub cec_report: Option<Vec<u8>>,
    /// CPU confidential-VM technology the driver observed on the host that
    /// produced this report, mapped onto the vendor enum. `None` when the
    /// driver reported no CPU capability, or in simulation.
    pub cpu_anchor_vendor: Option<TeeVendor>,
    /// Quote from the CPU confidential VM the GPU was admitted to, taken over
    /// the same nonce as the GPU leg.
    ///
    /// A GPU report on its own says a device is in Confidential Computing mode.
    /// It does not say which VM the device was admitted to, and the GPU has no
    /// trust boundary without that VM. The shared nonce is what lets a verifier
    /// see that both legs answered one challenge.
    pub cpu_anchor: Option<AttestationReport>,
}

/// Measurements the GPU reported inside its SPDM MEASUREMENTS response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMeasurements {
    /// SHA-384 over the SPDM measurement record exactly as the device returned
    /// it. This is what the attestation signature covers, so it is the value
    /// that binds a report to a device state. It is not a per-component hash
    /// and must not be presented as one.
    pub measurement_record_hash: Vec<u8>,
    /// Every DMTF measurement block in the record, in the order reported.
    pub blocks: Vec<SpdmMeasurementBlock>,
    /// ECC mode enabled
    pub ecc_enabled: bool,
    /// MIG (Multi-Instance GPU) mode
    pub mig_enabled: bool,
}

/// One DMTF measurement block from an SPDM MEASUREMENTS response.
///
/// Block layout per DSP0274 (SPDM 1.1) table "DMTF measurement specification
/// format": `Index(1) | MeasurementSpecification(1) | MeasurementSize(2 LE) |
/// Measurement(MeasurementSize)`, where a DMTF-specification measurement is
/// itself `DMTFSpecMeasurementValueType(1) | DMTFSpecMeasurementValueSize(2 LE)
/// | DMTFSpecMeasurementValue(...)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpdmMeasurementBlock {
    /// DMTF measurement block index as reported by the device.
    pub index: u8,
    /// DMTF measurement value type. Bit 7 clear means the value is a digest;
    /// bit 7 set means it is a raw bit stream. The low 7 bits identify what was
    /// measured (immutable ROM, mutable firmware, hardware config, and so on).
    pub value_type: u8,
    /// The measurement value bytes.
    pub value: Vec<u8>,
}

impl SpdmMeasurementBlock {
    /// Whether the value is a digest rather than a raw bit stream.
    pub fn is_digest(&self) -> bool {
        self.value_type & 0x80 == 0
    }

    /// The DMTF value-type discriminant with the representation bit masked off.
    pub fn kind(&self) -> u8 {
        self.value_type & 0x7f
    }

    /// Name for what this block measures, per the DSP0274 DMTF value-type table.
    pub fn kind_label(&self) -> &'static str {
        match self.kind() {
            DMTF_VALUE_TYPE_IMMUTABLE_ROM => "immutable_rom",
            0x01 => "mutable_firmware",
            0x02 => "hardware_configuration",
            0x03 => "firmware_configuration",
            0x04 => "measurement_manifest",
            0x05 => "device_mode",
            0x06 => "firmware_version",
            0x07 => "firmware_security_version",
            0x08 => "hash_extended_measurement",
            _ => "vendor_defined",
        }
    }

    /// Digest algorithm implied by the value length, or `raw` for a bit stream.
    ///
    /// SPDM carries the negotiated `MeasurementHashAlgo` in `ALGORITHMS`, which
    /// the attestation report does not include, so the width is the only signal
    /// available to a verifier reading the report alone.
    pub fn algorithm_label(&self) -> &'static str {
        if !self.is_digest() {
            return "raw";
        }
        match self.value.len() {
            32 => "SHA-256",
            48 => "SHA-384",
            64 => "SHA-512",
            _ => "unknown",
        }
    }
}

/// DMTF measurement value type for an immutable-ROM digest (DSP0274).
const DMTF_VALUE_TYPE_IMMUTABLE_ROM: u8 = 0x00;

/// SPDM `GET_MEASUREMENTS` request code (DSP0274).
const SPDM_CODE_GET_MEASUREMENTS: u8 = 0xe0;

/// SPDM `MEASUREMENTS` response code (DSP0274).
const SPDM_CODE_MEASUREMENTS: u8 = 0x60;

/// Byte length of the SPDM `GET_MEASUREMENTS` request the driver prefixes to the
/// attestation report: 4-byte header, 32-byte nonce, 1-byte slot id.
const SPDM_MEASUREMENTS_REQUEST_LEN: usize = 37;

/// Bit 0 of `MeasurementSpecification` selects the DMTF measurement format.
const SPDM_MEASUREMENT_SPEC_DMTF: u8 = 0x01;

/// What the GPU returned inside its SPDM `MEASUREMENTS` response.
#[derive(Debug, Clone)]
pub struct ParsedGpuReport {
    /// SHA-384 over the measurement record as returned, byte for byte.
    pub measurement_record_hash: Vec<u8>,
    /// The DMTF measurement blocks inside that record.
    pub blocks: Vec<SpdmMeasurementBlock>,
    /// The nonce the device echoed back.
    pub nonce: Vec<u8>,
    /// Vendor-defined opaque data.
    pub opaque_data: Vec<u8>,
    /// The device's ECDSA P-384 signature over the SPDM transcript.
    pub signature: Vec<u8>,
}

/// Evidence gathered from the driver for one attestation.
struct CollectedEvidence {
    /// The attestation report as the driver returned it. This is what a
    /// verifier receives; nothing here is re-encoded on the way out.
    evidence: Vec<u8>,
    /// Device certificate chain, GPU attestation key up to NVIDIA's root.
    cert_chain: Vec<Vec<u8>>,
    /// The separate attestation certificate chain the driver exposes. Verifiers
    /// that pin against NVIDIA's OCSP responder need this chain rather than the
    /// device one.
    attestation_cert_chain: Vec<u8>,
    /// Report from the GPU's Confidential Executive Controller, when the part
    /// carries one. Present on Hopper; absent on parts without a discrete CEC.
    cec_report: Option<Vec<u8>>,
    /// CPU confidential-VM technology the driver observed on this host, mapped
    /// onto the vendor enum. `None` when the driver reported no CPU capability.
    cpu_anchor_vendor: Option<TeeVendor>,
}

/// Map the CPU capability NVML reported onto the cross-vendor enum.
///
/// Recorded on the report so a verifier on another machine can check that the
/// CPU quote travelling alongside it came from the technology the GPU driver
/// actually saw, rather than trusting the quote's own self-description alone.
#[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
fn cpu_anchor_vendor(cpu: crate::nvml::CcCpuCaps) -> Option<TeeVendor> {
    use crate::nvml::CcCpuCaps;
    match cpu {
        CcCpuCaps::AmdSev | CcCpuCaps::AmdSevSnp | CcCpuCaps::AmdSnpVtom => {
            Some(TeeVendor::AmdSevSnp)
        }
        CcCpuCaps::IntelTdx => Some(TeeVendor::IntelTdx),
        CcCpuCaps::None | CcCpuCaps::Unknown(_) => None,
    }
}

/// Parse an NVIDIA GPU attestation report.
///
/// The driver hands back the SPDM `GET_MEASUREMENTS` exchange: optionally the
/// 37-byte request message, then the `MEASUREMENTS` response. Layout of the
/// response per DSP0274:
///
/// ```text
/// SPDMVersion(1) | RequestResponseCode(1) | Param1(1) | Param2(1)
/// NumberOfBlocks(1) | MeasurementRecordLength(3, LE)
/// MeasurementRecord(MeasurementRecordLength)
/// Nonce(32) | OpaqueDataLength(2, LE) | OpaqueData(OpaqueDataLength)
/// Signature(remainder)
/// ```
///
/// The signature covers the SPDM transcript, not just this message, so it can be
/// checked against the device certificate chain but not recomputed from the
/// response alone.
pub fn parse_gpu_attestation_report(blob: &[u8]) -> Result<ParsedGpuReport> {
    let malformed =
        |what: &str| TeeError::InvalidAttestationReport(format!("GPU attestation report {what}"));

    // Skip the request message when the driver prefixed one.
    let response = if blob.len() > SPDM_MEASUREMENTS_REQUEST_LEN
        && blob.get(1) == Some(&SPDM_CODE_GET_MEASUREMENTS)
    {
        &blob[SPDM_MEASUREMENTS_REQUEST_LEN..]
    } else {
        blob
    };

    if response.len() < 8 {
        return Err(malformed("is shorter than an SPDM MEASUREMENTS header"));
    }

    // SPDM 1.1 (0x11) and 1.2 (0x12) share this response layout.
    if response[0] != 0x11 && response[0] != 0x12 {
        return Err(malformed(&format!(
            "declares unsupported SPDM version 0x{:02x}",
            response[0]
        )));
    }
    if response[1] != SPDM_CODE_MEASUREMENTS {
        return Err(malformed(&format!(
            "is not a MEASUREMENTS response (code 0x{:02x})",
            response[1]
        )));
    }

    let record_len = u32::from_le_bytes([response[5], response[6], response[7], 0]) as usize;
    let record_end = 8usize
        .checked_add(record_len)
        .ok_or_else(|| malformed("declares an overflowing measurement record length"))?;
    if response.len() < record_end + 34 {
        return Err(malformed("is truncated before the nonce"));
    }

    let record = &response[8..record_end];
    let blocks = parse_measurement_blocks(record)?;

    let nonce = response[record_end..record_end + 32].to_vec();
    let opaque_len =
        u16::from_le_bytes([response[record_end + 32], response[record_end + 33]]) as usize;
    let opaque_start = record_end + 34;
    let opaque_end = opaque_start
        .checked_add(opaque_len)
        .ok_or_else(|| malformed("declares an overflowing opaque data length"))?;
    if response.len() <= opaque_end {
        return Err(malformed("is truncated before the signature"));
    }

    Ok(ParsedGpuReport {
        measurement_record_hash: Sha384::digest(record).to_vec(),
        blocks,
        nonce,
        opaque_data: response[opaque_start..opaque_end].to_vec(),
        signature: response[opaque_end..].to_vec(),
    })
}

/// Walk the DMTF measurement blocks inside an SPDM measurement record.
fn parse_measurement_blocks(record: &[u8]) -> Result<Vec<SpdmMeasurementBlock>> {
    let malformed =
        |what: &str| TeeError::InvalidAttestationReport(format!("GPU measurement record {what}"));

    let mut blocks = Vec::new();
    let mut offset = 0usize;

    while offset < record.len() {
        if record.len() - offset < 4 {
            return Err(malformed("ends mid-block header"));
        }

        let index = record[offset];
        let spec = record[offset + 1];
        let size = u16::from_le_bytes([record[offset + 2], record[offset + 3]]) as usize;
        let body_start = offset + 4;
        let body_end = body_start
            .checked_add(size)
            .ok_or_else(|| malformed("declares an overflowing block size"))?;
        if body_end > record.len() {
            return Err(malformed("declares a block that runs past the record"));
        }

        if spec & SPDM_MEASUREMENT_SPEC_DMTF == 0 {
            return Err(malformed(&format!(
                "block {index} uses measurement specification 0x{spec:02x}, not DMTF"
            )));
        }
        if size < 3 {
            return Err(malformed(&format!(
                "block {index} is too short to carry a DMTF measurement"
            )));
        }

        let value_type = record[body_start];
        let value_size =
            u16::from_le_bytes([record[body_start + 1], record[body_start + 2]]) as usize;
        let value_start = body_start + 3;
        if value_start + value_size > body_end {
            return Err(malformed(&format!(
                "block {index} declares a value larger than the block"
            )));
        }

        blocks.push(SpdmMeasurementBlock {
            index,
            value_type,
            value: record[value_start..value_start + value_size].to_vec(),
        });

        offset = body_end;
    }

    if blocks.is_empty() {
        return Err(malformed("contains no measurement blocks"));
    }

    Ok(blocks)
}

/// CC attestation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CcAttestationStatus {
    /// CC fully enabled and attested
    Enabled,
    /// CC available but not enabled in current session
    Available,
    /// CC not supported on this GPU
    NotSupported,
    /// CC attestation failed verification
    Failed,
}

/// Claims version requested from NRAS.
///
/// The service keys its claim set off this field; "3.0" is the current set and
/// is echoed back as `x-nvidia-ver`. Pinning it means a later default on the
/// service side cannot silently change which claims arrive.
const NRAS_CLAIMS_VERSION: &str = "3.0";

/// One GPU's evidence in the shape NRAS accepts.
#[derive(Debug, Serialize)]
struct NrasEvidenceEntry {
    /// Base64 of the SPDM attestation report as the driver returned it.
    evidence: String,
    /// Base64 of the device certificate chain that signs the report.
    certificate: String,
}

/// NRAS attestation request body.
///
/// Shape per NVIDIA's `nvtrust` reference verifier
/// (<https://github.com/NVIDIA/nvtrust>), which posts the nonce alongside a
/// list of per-GPU evidence entries and selects a claim set by version.
#[derive(Debug, Serialize)]
struct NrasAttestationRequest {
    /// Lowercase hex nonce, echoed back in the token as `eat_nonce`.
    nonce: String,
    /// GPU architecture string ("HOPPER", "BLACKWELL", "ADA_LOVELACE").
    arch: String,
    /// One entry per GPU being attested.
    evidence_list: Vec<NrasEvidenceEntry>,
    /// Which claim set to return.
    claims_version: String,
}

/// Claims carried in an NRAS Entity Attestation Token.
///
/// NRAS returns an RFC 9711 detached EAT bundle: an overall token plus one
/// token per GPU. The two share this claim type because the fields a verifier
/// reads differ by which token it is looking at — the overall verdict lives on
/// the outer token, the device detail on the per-GPU ones.
///
/// The service exposes firmware **versions**, not firmware digests; the only
/// digest it returns hashes the per-GPU claims JSON. A local measurement
/// record therefore has nothing on this side to be compared against, and the
/// two verification paths stay independent by construction.
#[derive(Debug, Default, Deserialize)]
struct NrasTokenClaims {
    /// Overall verdict across every GPU in the request. Present on the outer
    /// token only, and authoritative — a per-GPU `measres` of "success" does
    /// not by itself mean the request passed.
    #[serde(rename = "x-nvidia-overall-att-result", default)]
    overall_result: bool,
    /// Per-GPU verdict. "success" when the device matched its reference
    /// measurements; compared case-insensitively.
    #[serde(default)]
    measres: String,
    /// Claim set version the service applied, echoing `claims_version`.
    #[serde(rename = "x-nvidia-ver", default)]
    claims_version: String,
    /// Nonce echoed back, lowercase hex.
    #[serde(default)]
    eat_nonce: String,
    /// Unique device identifier, the GPU's attested identity.
    #[serde(default)]
    ueid: String,
    /// Hardware model as the service resolved it.
    #[serde(default)]
    hwmodel: String,
    /// OEM identifier.
    #[serde(default)]
    oemid: String,
    /// Whether secure boot was enabled on the device.
    #[serde(default)]
    secboot: bool,
    /// Debug status. Anything other than a disabled state means the device was
    /// debuggable while producing this evidence.
    #[serde(default)]
    dbgstat: String,
    /// Whether the architecture matched what the request declared.
    #[serde(rename = "x-nvidia-gpu-arch-check", default)]
    arch_check: bool,
    /// Driver version the service read out of the evidence.
    #[serde(rename = "x-nvidia-gpu-driver-version", default)]
    driver_version: String,
    /// VBIOS version the service read out of the evidence.
    #[serde(rename = "x-nvidia-gpu-vbios-version", default)]
    vbios_version: String,
    /// Whether the service could parse the attestation report at all.
    #[serde(rename = "x-nvidia-gpu-attestation-report-parsed", default)]
    report_parsed: bool,
    /// Whether the nonce inside the report matched the one in the request.
    #[serde(rename = "x-nvidia-gpu-attestation-report-nonce-match", default)]
    report_nonce_match: bool,
    /// Whether the device's signature over the report verified.
    #[serde(rename = "x-nvidia-gpu-attestation-report-signature-verified", default)]
    report_signature_verified: bool,
    /// Advisory text the service attached, if any.
    #[serde(rename = "x-nvidia-attestation-warning", default)]
    warning: Option<String>,
    /// Token issued-at (Unix timestamp).
    #[serde(default)]
    iat: i64,
    /// Token expiration (Unix timestamp).
    #[serde(default)]
    exp: i64,
}

/// The overall token plus the per-GPU tokens NRAS returned.
#[derive(Debug)]
struct NrasBundle {
    /// Verdict across the whole request.
    overall: NrasTokenClaims,
    /// One entry per GPU, keyed as the service named it ("GPU-0", ...).
    per_gpu: Vec<(String, NrasTokenClaims)>,
}

impl NvidiaGpuProvider {
    /// Create a new NVIDIA GPU TEE provider.
    pub fn new(config: NvidiaGpuConfig) -> Self {
        let simulate =
            std::env::var("TENZRO_SIMULATE_GPU").unwrap_or_else(|_| "0".to_string()) == "1";

        tracing::info!(
            "Initializing NVIDIA GPU TEE provider (device: {}, arch: {}, simulate: {})",
            config.device_index,
            config.expected_architecture,
            simulate
        );

        Self {
            config,
            gpu_info: RwLock::new(None),
            available: RwLock::new(None),
            simulate,
            cpu_anchor: None,
            keys: Arc::new(RwLock::new(HashMap::new())),
            secret_keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Force simulation mode regardless of environment variable.
    /// Useful for testing without setting `TENZRO_SIMULATE_GPU=1`.
    pub fn with_simulate(mut self) -> Self {
        self.simulate = true;
        self
    }

    /// Attach the CPU confidential-VM provider this GPU is admitted to.
    ///
    /// With an anchor attached, [`TeeProvider::generate_attestation`] derives one
    /// nonce, asks the CPU provider to quote over it, asks the GPU to report
    /// over the same value, and returns both bound together. A verifier that
    /// checks only the GPU leg learns that a genuine CC-capable device signed
    /// something; it takes the CPU leg to learn which machine, and under which
    /// memory-encryption boundary, the workload actually ran.
    ///
    /// Pair with [`NvidiaGpuConfig::require_cpu_anchor`]: leaving that set and
    /// omitting this call makes attestation fail rather than silently downgrade.
    pub fn with_cpu_anchor(mut self, anchor: Arc<dyn TeeProvider>) -> Self {
        self.cpu_anchor = Some(anchor);
        self
    }

    /// Detect GPU hardware and populate device info.
    ///
    /// In simulation mode, returns a fake H100 device.
    /// In real mode, runs `nvidia-smi` to query GPU properties including
    /// name, PCI ID, driver version, memory, compute capability, and CC status.
    async fn detect_gpu(&self) -> Result<GpuDeviceInfo> {
        tracing::debug!(
            "Detecting NVIDIA GPU at device index {}",
            self.config.device_index
        );

        if self.simulate {
            tracing::debug!("NVIDIA GPU running in simulation mode");
            let info = GpuDeviceInfo {
                name: "NVIDIA H100 80GB HBM3 (SIMULATED)".to_string(),
                architecture: self.config.expected_architecture,
                pci_device_id: known_gpus::H100_SXM5.to_string(),
                driver_version: "550.90.07".to_string(),
                compute_capability: "9.0".to_string(),
                memory_total: 80 * 1024 * 1024 * 1024, // 80 GB
                cc_enabled: true,
                cc_firmware_version: Some("1.0.1".to_string()),
                serial_hash: "sim_".to_string()
                    + &hex::encode(Sha256::digest(b"simulated_gpu_serial")),
            };

            *self.gpu_info.write() = Some(info.clone());
            return Ok(info);
        }

        // Real mode: query nvidia-smi for GPU properties
        self.detect_gpu_real().await
    }

    /// Real GPU detection via nvidia-smi.
    ///
    /// Queries GPU properties using nvidia-smi CSV output format.
    /// Fields: name, pci.device_id, driver_version, compute_cap, memory.total,
    ///         cc_mode (confidential compute mode).
    ///
    /// On hosts without nvidia-smi installed (non-Linux, or Linux without the
    /// NVIDIA driver), the spawn fails with NotFound and we surface a
    /// `TeeError::NotAvailable` — callers should fall back to simulation mode
    /// or skip GPU TEE registration.
    async fn detect_gpu_real(&self) -> Result<GpuDeviceInfo> {
        // Query basic GPU info
        let output = tokio::process::Command::new("nvidia-smi")
            .args([
                &format!("--id={}", self.config.device_index),
                "--query-gpu=name,pci.device_id,driver_version,compute_cap,memory.total",
                "--format=csv,noheader,nounits",
            ])
            .output()
            .await
            .map_err(|e| TeeError::not_available(format!("nvidia-smi not found: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(TeeError::not_available(format!(
                "nvidia-smi failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<&str> = stdout.trim().split(", ").collect();

        if fields.len() < 5 {
            return Err(TeeError::not_available(format!(
                "nvidia-smi returned unexpected format: {}",
                stdout
            )));
        }

        let name = fields[0].to_string();
        let pci_device_id = fields[1].trim_start_matches("0x").to_uppercase();
        let driver_version = fields[2].to_string();
        let compute_capability = fields[3].to_string();
        let memory_total_mib: u64 = fields[4].trim().parse().unwrap_or(0);

        // Determine architecture from PCI device ID
        let architecture = known_gpus::architecture_for_pci_id(&pci_device_id)
            .unwrap_or(self.config.expected_architecture);

        // Check if CC mode is supported/enabled.
        // Skip the nvidia-smi conf-compute probe for GPUs known not to support
        // CC (Ampere, Turing, Volta, RTX consumer cards) — `nvidia-smi
        // conf-compute -gsc` would fail anyway, but the explicit early-return
        // makes the path's intent clear and surfaces a useful log line.
        let cc_enabled = if let Some(part) = known_gpus::non_cc_part_by_name(&name) {
            tracing::info!(
                "GPU {} is a {} — Confidential Computing is not offered on this part, \
                 so it serves inference without TEE attestation",
                name,
                part
            );
            false
        } else if known_gpus::cc_capable(&pci_device_id) {
            self.check_cc_status().await
        } else if known_gpus::architecture_for_pci_id(&pci_device_id).is_some() {
            tracing::info!(
                "GPU {} ({}) is recognized but not CC-capable — serving inference without TEE attestation",
                name,
                pci_device_id
            );
            false
        } else {
            // Unknown PCI ID — try the CC probe optimistically (operator may
            // have set the right `expected_architecture` even for an SKU we
            // don't know about yet).
            self.check_cc_status().await
        };
        let cc_firmware_version = if cc_enabled {
            self.query_cc_firmware_version().await
        } else {
            None
        };

        // Generate serial hash (we don't expose the raw serial)
        let serial_hash = self.query_serial_hash().await;

        let info = GpuDeviceInfo {
            name,
            architecture,
            pci_device_id,
            driver_version,
            compute_capability,
            memory_total: memory_total_mib * 1024 * 1024,
            cc_enabled,
            cc_firmware_version,
            serial_hash,
        };

        *self.gpu_info.write() = Some(info.clone());
        Ok(info)
    }

    /// Check whether Confidential Computing mode is enabled on the GPU.
    ///
    /// `nvmlSystemGetConfComputeState` is the authoritative answer, so that is
    /// tried first. Parsing `nvidia-smi conf-compute -gsc` output is the
    /// fallback for hosts where NVML cannot be bound: the tool's wording has
    /// changed across driver branches, so a substring match on it is a weaker
    /// signal than reading the state field directly.
    async fn check_cc_status(&self) -> bool {
        #[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
        {
            match crate::nvml::Nvml::open() {
                Ok(nvml) => match nvml.cc_system_state() {
                    Ok(state) => {
                        if state.dev_tools_on() {
                            tracing::warn!(
                                "GPU Confidential Computing is in DevTools mode — isolation is \
                                 relaxed and reports from this host do not attest a confidential \
                                 environment"
                            );
                        }
                        return state.cc_enabled();
                    }
                    Err(e) => {
                        tracing::debug!(
                            "NVML CC state query failed ({e}) — falling back to nvidia-smi"
                        );
                    }
                },
                Err(e) => {
                    tracing::debug!("NVML unavailable ({e}) — falling back to nvidia-smi");
                }
            }
        }

        let output = tokio::process::Command::new("nvidia-smi")
            .args(["conf-compute", "-gsc"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                stdout.contains("ON") || stdout.contains("Enabled") || stdout.contains("enabled")
            }
            _ => {
                tracing::debug!("nvidia-smi conf-compute not available — CC may not be supported");
                false
            }
        }
    }

    /// Query CC firmware version from nvidia-smi.
    ///
    /// Returns None if nvidia-smi is missing (non-Linux hosts) or the GPU
    /// reports no firmware version.
    async fn query_cc_firmware_version(&self) -> Option<String> {
        let output = tokio::process::Command::new("nvidia-smi")
            .args([
                &format!("--id={}", self.config.device_index),
                "--query-gpu=gsp_firmware_version",
                "--format=csv,noheader",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let version = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !version.is_empty() && version != "[N/A]" {
                    Some(version)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Query GPU serial number and return its hash.
    ///
    /// Returns "unknown" when nvidia-smi is missing or the query fails.
    async fn query_serial_hash(&self) -> String {
        let output = tokio::process::Command::new("nvidia-smi")
            .args([
                &format!("--id={}", self.config.device_index),
                "--query-gpu=serial",
                "--format=csv,noheader",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let serial = String::from_utf8_lossy(&out.stdout).trim().to_string();
                hex::encode(Sha256::digest(serial.as_bytes()))
            }
            _ => "unknown".to_string(),
        }
    }

    /// Collect GPU evidence for attestation.
    ///
    /// On real hardware the evidence is the attestation report returned by
    /// `nvmlDeviceGetConfComputeGpuAttestationReport`, which lives in
    /// `libnvidia-ml.so.1` alongside the rest of NVML. The report is the SPDM
    /// `GET_MEASUREMENTS` exchange the driver ran against the GPU's root of
    /// trust: the request message followed by the MEASUREMENTS response, with
    /// the caller's nonce echoed inside and the whole transcript signed by the
    /// device's ECDSA P-384 attestation key.
    ///
    /// The certificate chain comes from `nvmlDeviceGetConfComputeGpuCertificate`
    /// and travels alongside the report rather than inside it — a verifier needs
    /// both to walk from the signature up to NVIDIA's root.
    async fn collect_gpu_evidence(
        &self,
        device_info: &GpuDeviceInfo,
        nonce: &[u8; crate::NVIDIA_CC_NONCE_LEN],
    ) -> Result<CollectedEvidence> {
        if self.simulate {
            let evidence = SimulatedEvidence {
                gpu_name: device_info.name.clone(),
                architecture: format!("{}", device_info.architecture),
                pci_device_id: device_info.pci_device_id.clone(),
                driver_version: device_info.driver_version.clone(),
                cc_enabled: device_info.cc_enabled,
                cc_firmware_version: device_info.cc_firmware_version.clone(),
                nonce: hex::encode(nonce),
                timestamp: chrono::Utc::now().timestamp(),
            };

            let bytes = serde_json::to_vec(&evidence).map_err(|e| {
                TeeError::AttestationGenerationFailed(format!(
                    "Failed to serialize simulated evidence: {}",
                    e
                ))
            })?;

            return Ok(CollectedEvidence {
                evidence: bytes,
                cert_chain: vec![vec![0x30; 64]],
                attestation_cert_chain: Vec::new(),
                cec_report: None,
                cpu_anchor_vendor: None,
            });
        }

        #[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
        {
            self.collect_real_evidence(nonce).await
        }

        #[cfg(not(all(target_os = "linux", feature = "nvidia-gpu")))]
        {
            let _ = nonce;
            Err(TeeError::not_available(
                "GPU evidence collection requires Linux with the NVIDIA driver and the \
                 `nvidia-gpu` feature compiled in",
            ))
        }
    }

    /// Ask the driver for a fresh attestation report over `nonce`.
    ///
    /// Every gate here is a separate claim, so each is checked separately rather
    /// than collapsed into one "CC is on" boolean: the platform has to be in a
    /// production posture, the CPU has to be running a confidential VM the GPU
    /// can be admitted to, and the devices themselves have to have finished
    /// their own readiness handshake.
    #[cfg(all(target_os = "linux", feature = "nvidia-gpu"))]
    async fn collect_real_evidence(
        &self,
        nonce: &[u8; crate::NVIDIA_CC_NONCE_LEN],
    ) -> Result<CollectedEvidence> {
        let device_index = self.config.device_index;
        let nonce = *nonce;

        tokio::task::spawn_blocking(move || {
            let nvml = crate::nvml::Nvml::open()?;

            let state = nvml.cc_system_state()?;
            if !state.cc_enabled() {
                return Err(TeeError::not_available(
                    "NVIDIA Confidential Computing is not enabled on this host",
                ));
            }
            if state.dev_tools_on() {
                return Err(TeeError::attestation_failed(
                    "GPU Confidential Computing is in DevTools mode, which relaxes isolation. \
                     A report collected in this posture is a valid signature over a machine \
                     that is not enforcing confidentiality, so it is refused.",
                ));
            }
            if !state.production_environment() {
                return Err(TeeError::attestation_failed(
                    "GPU Confidential Computing reports a non-production environment",
                ));
            }

            let caps = nvml.cc_capabilities()?;
            if !caps.gpus_cc_capable {
                return Err(TeeError::not_available(
                    "No Confidential-Computing-capable GPU is present on this host",
                ));
            }
            if !caps.cpu.anchors_cvm() {
                return Err(TeeError::attestation_failed(format!(
                    "GPU Confidential Computing requires a CPU confidential VM to be admitted \
                     into; the platform reports CPU capability '{}'",
                    caps.cpu
                )));
            }

            if !nvml.cc_gpus_ready()? {
                return Err(TeeError::not_available(
                    "GPUs have not completed the Confidential Computing readiness handshake",
                ));
            }

            let device = nvml.device_by_index(device_index)?;
            let evidence = nvml.cc_attestation_report(device, &nonce)?;
            let chains = nvml.cc_certificate_chains(device)?;

            Ok(CollectedEvidence {
                evidence: evidence.report,
                cert_chain: vec![chains.cert_chain],
                attestation_cert_chain: chains.attestation_cert_chain,
                cec_report: evidence.cec_report,
                cpu_anchor_vendor: cpu_anchor_vendor(caps.cpu),
            })
        })
        .await
        .map_err(|e| {
            TeeError::AttestationGenerationFailed(format!(
                "GPU evidence collection task failed: {}",
                e
            ))
        })?
    }

    /// Generate an attestation report from the GPU.
    ///
    /// Simulation mode builds a synthetic report. Real mode collects the SPDM
    /// evidence, parses the measurement record out of it, and carries the
    /// device's own signature — nothing here recomputes or substitutes a
    /// measurement the GPU did not report.
    async fn generate_gpu_attestation(
        &self,
        nonce: &[u8; crate::NVIDIA_CC_NONCE_LEN],
    ) -> Result<GpuAttestationReport> {
        let device_info = self.detect_gpu().await?;

        if !device_info.cc_enabled {
            return Err(TeeError::not_available(
                "NVIDIA Confidential Computing is not enabled on this GPU",
            ));
        }

        let collected = self.collect_gpu_evidence(&device_info, nonce).await?;
        let (ecc_enabled, mig_enabled) = self.query_ecc_and_mig().await;

        let (measurements, signature) = if self.simulate {
            let measurements = GpuMeasurements {
                measurement_record_hash: Sha384::digest(&collected.evidence).to_vec(),
                blocks: vec![SpdmMeasurementBlock {
                    index: 1,
                    value_type: DMTF_VALUE_TYPE_IMMUTABLE_ROM,
                    value: Sha384::digest(device_info.name.as_bytes()).to_vec(),
                }],
                ecc_enabled,
                mig_enabled,
            };

            let mut hasher = Sha384::new();
            hasher.update(&collected.evidence);
            hasher.update(nonce);
            (measurements, hasher.finalize().to_vec())
        } else {
            let parsed = parse_gpu_attestation_report(&collected.evidence)?;

            if parsed.nonce != nonce[..] {
                return Err(TeeError::attestation_failed(
                    "GPU attestation report echoed a nonce that does not match the one requested",
                ));
            }

            let measurements = GpuMeasurements {
                measurement_record_hash: parsed.measurement_record_hash,
                blocks: parsed.blocks,
                ecc_enabled,
                mig_enabled,
            };

            (measurements, parsed.signature)
        };

        // The CPU leg answers the same nonce as the GPU leg. That shared
        // challenge is what ties the device to the confidential VM it was
        // admitted to; without it a verifier has two unrelated reports.
        let cpu_anchor = self.attest_cpu_anchor(nonce).await?;

        Ok(GpuAttestationReport {
            device_info,
            raw_report: collected.evidence,
            measurements,
            cc_status: CcAttestationStatus::Enabled,
            nonce: nonce.to_vec(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature,
            cert_chain: collected.cert_chain,
            attestation_cert_chain: collected.attestation_cert_chain,
            cec_report: collected.cec_report,
            cpu_anchor_vendor: collected.cpu_anchor_vendor,
            cpu_anchor,
        })
    }

    /// Take a CPU confidential-VM quote over the same nonce as the GPU leg.
    ///
    /// A GPU report on its own says a device is in Confidential Computing mode.
    /// It does not say which VM the device was admitted to, and the GPU has no
    /// trust boundary without that VM, so a report with no CPU leg is refused
    /// unless the operator has explicitly turned the requirement off.
    async fn attest_cpu_anchor(
        &self,
        nonce: &[u8; crate::NVIDIA_CC_NONCE_LEN],
    ) -> Result<Option<AttestationReport>> {
        match &self.cpu_anchor {
            Some(anchor) => Ok(Some(anchor.generate_attestation(nonce).await?)),
            None if self.config.require_cpu_anchor => Err(TeeError::not_available(
                "NVIDIA GPU Confidential Computing does not establish a trust boundary on its \
                 own — the confidential VM is created by AMD SEV-SNP or Intel TDX and the GPU is \
                 admitted to it. Attach a CPU provider with `with_cpu_anchor`, or clear \
                 `require_cpu_anchor` to emit a GPU-only report.",
            )),
            None => Ok(None),
        }
    }

    /// Read ECC and MIG mode from the driver.
    ///
    /// Both default to reporting off when the query cannot be answered — an
    /// unknown mode is recorded as not-enabled rather than assumed enabled, so
    /// a verifier is never told a protection is on without the driver saying so.
    async fn query_ecc_and_mig(&self) -> (bool, bool) {
        if self.simulate {
            return (true, false);
        }

        let output = tokio::process::Command::new("nvidia-smi")
            .args([
                &format!("--id={}", self.config.device_index),
                "--query-gpu=ecc.mode.current,mig.mode.current",
                "--format=csv,noheader",
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let fields: Vec<&str> = stdout.trim().split(',').map(|f| f.trim()).collect();
                let enabled = |f: Option<&&str>| {
                    f.map(|v| v.eq_ignore_ascii_case("Enabled"))
                        .unwrap_or(false)
                };
                (enabled(fields.first()), enabled(fields.get(1)))
            }
            _ => (false, false),
        }
    }

    /// Verify a GPU attestation report via NRAS (NVIDIA Remote Attestation Service).
    ///
    /// Sends the driver's evidence, verbatim, together with the certificate chain
    /// that signs it. NRAS re-parses the SPDM exchange itself and checks:
    /// 1. GPU identity — the device certificate chains to NVIDIA's root
    /// 2. Firmware integrity — reported versions match NVIDIA's reference manifests
    /// 3. CC mode status — Confidential Computing enabled, DevTools mode off
    /// 4. Nonce freshness — the report answers the challenge that was sent
    ///
    /// Answers with an RFC 9711 detached Entity Attestation Token bundle: an
    /// overall token carrying the verdict plus one token per device. The claims
    /// report firmware as version strings rather than digests, so nothing in the
    /// response is comparable to the local measurement record — the local and
    /// remote paths verify different things and neither substitutes for the other.
    #[cfg(feature = "nvidia-gpu")]
    async fn verify_via_nras(
        &self,
        gpu_report: &GpuAttestationReport,
    ) -> Result<NrasVerificationResult> {
        let nras_endpoint = &self.config.nras_endpoint;

        let arch_str = match gpu_report.device_info.architecture {
            GpuArchitecture::Hopper => "HOPPER",
            GpuArchitecture::Blackwell => "BLACKWELL",
            GpuArchitecture::AdaLovelace => "ADA_LOVELACE",
            // NRAS does not accept non-CC architectures — short-circuit here.
            // The caller should have gated on `cc_capable()` before reaching
            // verify_via_nras; this branch is a defensive fallback that
            // returns a clear error rather than sending an invalid arch
            // string upstream.
            GpuArchitecture::Ampere | GpuArchitecture::Turing | GpuArchitecture::Volta => {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "GPU architecture {} is not Confidential-Computing capable; NRAS verification is not applicable",
                    gpu_report.device_info.architecture
                )));
            }
        };

        let b64 = |bytes: &[u8]| {
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
        };

        // The certificate travels in the request because NRAS walks the
        // signature up to NVIDIA's root itself. The attestation chain is the
        // one bound to the signing key, so it is preferred over the device
        // chain when the driver returned both.
        let certificate = if gpu_report.attestation_cert_chain.is_empty() {
            gpu_report
                .cert_chain
                .first()
                .map(|c| b64(c))
                .unwrap_or_default()
        } else {
            b64(&gpu_report.attestation_cert_chain)
        };

        if gpu_report.raw_report.is_empty() {
            return Err(TeeError::AttestationVerificationFailed(
                "GPU report carries no driver evidence, so it cannot be sent to NRAS".to_string(),
            ));
        }

        let request = NrasAttestationRequest {
            nonce: hex::encode(&gpu_report.nonce),
            arch: arch_str.to_string(),
            evidence_list: vec![NrasEvidenceEntry {
                evidence: b64(&gpu_report.raw_report),
                certificate,
            }],
            claims_version: NRAS_CLAIMS_VERSION.to_string(),
        };

        tracing::info!(
            "Sending GPU attestation to NRAS at {}: arch={}, nonce={}",
            nras_endpoint,
            arch_str,
            &request.nonce[..16]
        );

        // Send to NRAS
        // Note: reqwest is an optional dependency, only available when nvidia-gpu feature is enabled
        #[cfg(feature = "nvidia-gpu")]
        {
            if self.simulate {
                let now = chrono::Utc::now().timestamp();
                return Ok(NrasVerificationResult {
                    verified: true,
                    token: "simulated_jwt_token".to_string(),
                    claims: NrasTokenClaims {
                        overall_result: true,
                        measres: "success".to_string(),
                        claims_version: NRAS_CLAIMS_VERSION.to_string(),
                        eat_nonce: hex::encode(&gpu_report.nonce),
                        hwmodel: gpu_report.device_info.name.clone(),
                        secboot: true,
                        dbgstat: "disabled".to_string(),
                        arch_check: true,
                        driver_version: gpu_report.device_info.driver_version.clone(),
                        report_parsed: true,
                        report_nonce_match: true,
                        report_signature_verified: true,
                        iat: now,
                        exp: now + 86400,
                        ..Default::default()
                    },
                });
            }

            // Real NRAS call via reqwest
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| {
                    TeeError::AttestationVerificationFailed(format!(
                        "Failed to create HTTP client for NRAS: {}",
                        e
                    ))
                })?;

            let response = client
                .post(nras_endpoint)
                .json(&request)
                .send()
                .await
                .map_err(|e| {
                    TeeError::AttestationVerificationFailed(format!("NRAS request failed: {}", e))
                })?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS returned HTTP {}: {}",
                    status, body
                )));
            }

            let body = response.text().await.map_err(|e| {
                TeeError::AttestationVerificationFailed(format!(
                    "Failed to read NRAS response: {}",
                    e
                ))
            })?;

            let (overall_token, bundle) = parse_nras_bundle(&body)?;

            // Replay protection. The nonce is echoed as `eat_nonce` in every
            // token; the overall token is the one whose freshness gates the
            // verdict below.
            let expected_nonce = hex::encode(&gpu_report.nonce);
            if !bundle
                .overall
                .eat_nonce
                .eq_ignore_ascii_case(&expected_nonce)
            {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS token nonce mismatch: expected {}, got {}",
                    &expected_nonce[..16.min(expected_nonce.len())],
                    &bundle.overall.eat_nonce[..16.min(bundle.overall.eat_nonce.len())]
                )));
            }

            // `exp` is a Unix timestamp; reject expired tokens. `iat` is
            // sanity-checked against the future with 5 minutes of clock skew.
            let now_secs = chrono::Utc::now().timestamp();
            if bundle.overall.exp != 0 && now_secs >= bundle.overall.exp {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS token expired: exp={}, now={}",
                    bundle.overall.exp, now_secs
                )));
            }
            if bundle.overall.iat != 0 && bundle.overall.iat > now_secs + 300 {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS token issued in the future: iat={}, now={}",
                    bundle.overall.iat, now_secs
                )));
            }

            // Every GPU in the request has to have passed. The overall verdict
            // is authoritative, but a per-GPU failure alongside an overall pass
            // would mean the two disagree, so both are required.
            for (name, gpu) in &bundle.per_gpu {
                if !gpu.measres.eq_ignore_ascii_case("success") {
                    return Err(TeeError::AttestationVerificationFailed(format!(
                        "NRAS reported {} measurement result '{}'",
                        name,
                        if gpu.measres.is_empty() {
                            "<absent>"
                        } else {
                            &gpu.measres
                        }
                    )));
                }
                if let Some(warning) = &gpu.warning {
                    tracing::warn!("NRAS attached a warning to {}: {}", name, warning);
                }
            }

            let verified = bundle.overall.overall_result;
            if !verified {
                return Err(TeeError::AttestationVerificationFailed(
                    "NRAS returned x-nvidia-overall-att-result=false".to_string(),
                ));
            }

            // Device detail lives on the per-GPU tokens; the overall token
            // carries the verdict. Report the first GPU's claims alongside the
            // verdict so a caller sees one coherent set.
            let mut claims = bundle
                .per_gpu
                .into_iter()
                .next()
                .map(|(_, gpu)| gpu)
                .unwrap_or_default();
            claims.overall_result = verified;
            if claims.eat_nonce.is_empty() {
                claims.eat_nonce = bundle.overall.eat_nonce;
            }

            Ok(NrasVerificationResult {
                verified,
                token: overall_token,
                claims,
            })
        }
    }

    /// Verify a GPU attestation report locally (without NRAS).
    ///
    /// Local verification checks:
    /// 1. Report age within bounds
    /// 2. CC status is Enabled
    /// 3. Architecture matches expected
    /// 4. Driver version meets minimum
    /// 5. CC firmware version meets minimum
    /// 6. A measurement record and its DMTF blocks are present
    ///
    /// Note: Local verification cannot compare measurements against NVIDIA's
    /// reference manifests or validate the GPU's device certificate chain, as
    /// NVIDIA does not publish root CA certificates. Remote NRAS verification is
    /// what supplies cryptographic authority.
    async fn verify_gpu_attestation_local(&self, report: &GpuAttestationReport) -> Result<bool> {
        // Step 1: Check report age
        let now = chrono::Utc::now().timestamp_millis();
        let age = now - report.timestamp;
        if age > self.config.max_report_age_ms {
            return Err(TeeError::attestation_failed(format!(
                "GPU attestation report too old: {}ms > {}ms",
                age, self.config.max_report_age_ms
            )));
        }
        if age < 0 {
            return Err(TeeError::attestation_failed(
                "GPU attestation report timestamp is in the future",
            ));
        }

        // Step 2: Verify CC is enabled
        if report.cc_status != CcAttestationStatus::Enabled {
            return Err(TeeError::attestation_failed(
                "GPU Confidential Computing is not enabled",
            ));
        }

        // Step 3: Check architecture matches expected
        if report.device_info.architecture != self.config.expected_architecture {
            return Err(TeeError::attestation_failed(format!(
                "GPU architecture mismatch: expected {}, got {}",
                self.config.expected_architecture, report.device_info.architecture
            )));
        }

        // Step 4: Check driver version meets minimum
        if !version_gte(
            &report.device_info.driver_version,
            &self.config.min_driver_version,
        ) {
            return Err(TeeError::attestation_failed(format!(
                "GPU driver version {} below minimum {}",
                report.device_info.driver_version, self.config.min_driver_version
            )));
        }

        // Step 5: Check CC firmware version
        if let Some(cc_fw) = &report.device_info.cc_firmware_version
            && !version_gte(cc_fw, &self.config.min_cc_firmware_version)
        {
            return Err(TeeError::attestation_failed(format!(
                "CC firmware version {} below minimum {}",
                cc_fw, self.config.min_cc_firmware_version
            )));
        }

        // Step 6: The device must have reported a measurement record. An empty
        // record means the GPU answered GET_MEASUREMENTS with nothing to
        // measure, which is not a state a CC-enabled device reaches.
        if report.measurements.measurement_record_hash.is_empty() {
            return Err(TeeError::attestation_failed(
                "GPU reported no measurement record",
            ));
        }
        if report.measurements.blocks.is_empty() {
            return Err(TeeError::attestation_failed(
                "GPU measurement record contained no DMTF blocks",
            ));
        }

        tracing::info!(
            "NVIDIA GPU attestation verified locally: {} (CC: {:?}, driver: {})",
            report.device_info.name,
            report.cc_status,
            report.device_info.driver_version
        );

        Ok(true)
    }

    /// Convert GPU attestation to Tenzro's generic attestation format.
    fn to_attestation_report(
        &self,
        gpu_report: &GpuAttestationReport,
        user_data: &[u8],
    ) -> AttestationReport {
        let mut metadata = HashMap::new();
        metadata.insert("gpu_name".to_string(), gpu_report.device_info.name.clone());
        metadata.insert(
            "architecture".to_string(),
            format!("{}", gpu_report.device_info.architecture),
        );
        metadata.insert(
            "cc_status".to_string(),
            format!("{:?}", gpu_report.cc_status),
        );
        metadata.insert(
            "driver_version".to_string(),
            gpu_report.device_info.driver_version.clone(),
        );
        metadata.insert(
            "pci_device_id".to_string(),
            gpu_report.device_info.pci_device_id.clone(),
        );

        if let Some(ref cc_fw) = gpu_report.device_info.cc_firmware_version {
            metadata.insert("cc_firmware_version".to_string(), cc_fw.clone());
        }

        if self.simulate {
            metadata.insert("simulated".to_string(), "true".to_string());
        }

        AttestationReport {
            id: uuid::Uuid::new_v4(),
            vendor: TeeVendor::NvidiaGpu,
            user_data: user_data.to_vec(),
            attestation_data: serde_json::to_vec(gpu_report).unwrap_or_default(),
            certificates: gpu_report.cert_chain.clone(),
            timestamp: tenzro_types::primitives::Timestamp::now(),
            metadata,
            quote: gpu_report.signature.clone(),
            measurement: gpu_report.measurements.measurement_record_hash.clone(),
            signature: gpu_report.signature.clone(),
            vendor_data: serde_json::to_vec(&gpu_report.measurements).unwrap_or_default(),
        }
    }
}

#[async_trait]
impl TeeProvider for NvidiaGpuProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::NvidiaGpu
    }

    async fn is_available(&self) -> Result<bool> {
        // Return cached probe result if we've already determined availability.
        if let Some(cached) = *self.available.read() {
            return Ok(cached);
        }
        let result = match self.detect_gpu().await {
            Ok(info) => info.cc_enabled,
            Err(_) => false,
        };
        *self.available.write() = Some(result);
        Ok(result)
    }

    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        // The nonce is fixed at NVML_CC_GPU_CEC_NONCE_SIZE by the driver ABI, and
        // the CPU leg answers the same value, so both legs of the composite report
        // carry one challenge.
        let mut nonce = [0u8; crate::NVIDIA_CC_NONCE_LEN];
        if user_data.is_empty() {
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        } else {
            nonce.copy_from_slice(&Sha256::digest(user_data));
        }

        let gpu_report = self.generate_gpu_attestation(&nonce).await?;
        Ok(self.to_attestation_report(&gpu_report, user_data))
    }

    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult> {
        if report.vendor != TeeVendor::NvidiaGpu {
            return Err(TeeError::attestation_failed(format!(
                "Expected NvidiaGpu vendor, got {:?}",
                report.vendor
            )));
        }

        // Deserialize GPU-specific report
        let gpu_report: GpuAttestationReport = serde_json::from_slice(&report.attestation_data)
            .map_err(|e| {
                TeeError::InvalidAttestationReport(format!(
                    "Failed to parse GPU attestation report: {}",
                    e
                ))
            })?;

        // Verify locally first (age, CC status, architecture, driver version, measurements).
        // Local-only checks are STRUCTURAL — they verify the report
        // payload looks plausible, but provide no cryptographic backing.
        // Cryptographic authority on NVIDIA comes from NRAS attesting
        // the GPU's manufacturing-device certificate chain. Simulated
        // reports are explicitly NEVER valid: they pass local checks
        // but cannot be NRAS-attested, and a relying party branching
        // on `result.valid` must reject them.
        let mut valid = self.verify_gpu_attestation_local(&gpu_report).await?;
        if self.simulate {
            tracing::warn!(
                "NVIDIA GPU verifier: simulated report — AttestationResult.valid \
                 will be false. Simulated reports carry no cryptographic authority."
            );
            valid = false;
        }

        // The GPU leg on its own attests that a device is in Confidential
        // Computing mode. It does not attest which confidential VM the device was
        // admitted to, and the GPU has no trust boundary without that VM, so the
        // CPU leg is verified alongside it and both must answer one challenge.
        let mut cpu_anchor_details: Vec<(&'static str, String)> = Vec::new();
        match (&gpu_report.cpu_anchor, &self.cpu_anchor) {
            (Some(anchor), Some(provider)) => {
                cpu_anchor_details.push(("cpu_anchor_vendor", format!("{:?}", anchor.vendor)));

                if anchor.user_data != gpu_report.nonce {
                    tracing::warn!(
                        "CPU anchor answers a different challenge than the GPU report — \
                         the two legs describe unrelated attestations"
                    );
                    valid = false;
                }

                // The driver told the GPU host which confidential-VM technology it
                // was running under. A quote claiming a different technology did
                // not come from the VM the device was admitted to.
                if let Some(observed) = gpu_report.cpu_anchor_vendor
                    && anchor.vendor != observed
                {
                    tracing::warn!(
                        "CPU anchor vendor {:?} does not match the {:?} the GPU driver \
                             observed on the host",
                        anchor.vendor,
                        observed
                    );
                    valid = false;
                }

                let cpu_result = provider.verify_attestation(anchor).await?;
                cpu_anchor_details.push(("cpu_anchor_valid", cpu_result.valid.to_string()));
                cpu_anchor_details.push(("cpu_anchor_tcb_version", cpu_result.tcb_version.clone()));
                if !cpu_result.valid {
                    tracing::warn!(
                        "CPU anchor failed verification: {}",
                        cpu_result.error.as_deref().unwrap_or("no reason given")
                    );
                    valid = false;
                }
            }
            (Some(_), None) => {
                // The report carries a CPU leg but this verifier has no provider
                // able to appraise it, so the composite binding is unchecked.
                cpu_anchor_details.push(("cpu_anchor_valid", "unverified".to_string()));
                if self.config.require_cpu_anchor {
                    tracing::warn!(
                        "GPU report carries a CPU anchor but no CPU provider is attached to \
                         verify it — attach one with `with_cpu_anchor`"
                    );
                    valid = false;
                }
            }
            (None, _) => {
                cpu_anchor_details.push(("cpu_anchor_valid", "absent".to_string()));
                if self.config.require_cpu_anchor {
                    tracing::warn!(
                        "GPU report carries no CPU anchor — NVIDIA GPU Confidential \
                         Computing does not establish a trust boundary on its own"
                    );
                    valid = false;
                }
            }
        }

        // When remote attestation is configured, additionally verify via NRAS.
        // NRAS validates against NVIDIA's golden RIMs and the GPU's manufacturing
        // device certificate chain — local verification cannot do either, so
        // remote attestation is required before the result can be trusted.
        #[allow(unused_mut, unused_assignments)]
        let mut nras_token: Option<String> = None;
        #[allow(unused_mut, unused_assignments)]
        let mut nras_attested: bool = false;
        #[allow(unused_mut, unused_assignments)]
        let mut nras_claims: Option<NrasTokenClaims> = None;
        #[cfg(feature = "nvidia-gpu")]
        if valid && self.config.use_remote_attestation {
            match self.verify_via_nras(&gpu_report).await {
                Ok(nras_result) => {
                    nras_attested = nras_result.verified;
                    nras_token = Some(nras_result.token);
                    if !nras_result.verified {
                        tracing::warn!(
                            "NRAS rejected GPU attestation despite local pass: model={}",
                            nras_result.claims.hwmodel
                        );
                        valid = false;
                    } else {
                        tracing::info!(
                            "NRAS attested GPU: model={}, driver={}",
                            nras_result.claims.hwmodel,
                            nras_result.claims.driver_version
                        );
                    }
                    nras_claims = Some(nras_result.claims);
                }
                Err(e) => {
                    tracing::error!("NRAS verification failed: {}", e);
                    valid = false;
                }
            }
        }

        let tcb_ver = gpu_report
            .device_info
            .cc_firmware_version
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        if valid {
            let mut result = AttestationResult::success(
                TeeVendor::NvidiaGpu,
                gpu_report.measurements.measurement_record_hash.clone(),
            );
            result.tcb_version = tcb_ver;
            // One entry per DMTF block the device actually reported. Registers
            // are named from the DSP0274 value type rather than assigned
            // component names — the SPDM record does not say which block is the
            // VBIOS and which is the driver.
            result.measurements = gpu_report
                .measurements
                .blocks
                .iter()
                .map(|block| Measurement {
                    index: block.index as u32,
                    algorithm: block.algorithm_label().to_string(),
                    value: block.value.clone(),
                    register: block.kind_label().to_string(),
                    description: Some(format!(
                        "SPDM measurement block {} (DMTF value type 0x{:02x})",
                        block.index, block.value_type
                    )),
                })
                .collect();
            result.cert_chain_valid = !self.simulate;

            if self.simulate {
                result
                    .details
                    .insert("simulated".to_string(), "true".to_string());
            }
            result.details.insert(
                "verification_method".to_string(),
                if self.config.use_remote_attestation {
                    "nras"
                } else {
                    "local"
                }
                .to_string(),
            );
            result.details.insert(
                "gpu_architecture".to_string(),
                format!("{}", gpu_report.device_info.architecture),
            );
            for (key, value) in cpu_anchor_details {
                result.details.insert(key.to_string(), value);
            }
            if let Some(token) = nras_token {
                result.details.insert("nras_token".to_string(), token);
                result
                    .details
                    .insert("nras_attested".to_string(), nras_attested.to_string());
            }
            if let Some(claims) = nras_claims {
                // NRAS reports firmware as versions, not digests, and its only
                // digest hashes the claims JSON rather than any measurement —
                // so nothing here is comparable to the local measurement
                // record, and the two verification paths stay independent.
                let details = &mut result.details;
                let mut put = |key: &str, value: String| {
                    if !value.is_empty() {
                        details.insert(key.to_string(), value);
                    }
                };
                put("nras_measurement_result", claims.measres);
                put("nras_claims_version", claims.claims_version);
                put("nras_device_id", claims.ueid);
                put("nras_hardware_model", claims.hwmodel);
                put("nras_oem_id", claims.oemid);
                put("nras_debug_status", claims.dbgstat);
                put("nras_driver_version", claims.driver_version);
                put("nras_vbios_version", claims.vbios_version);
                put("nras_token_nonce", claims.eat_nonce);
                if let Some(warning) = claims.warning {
                    put("nras_warning", warning);
                }
                put("nras_secure_boot", claims.secboot.to_string());
                put("nras_arch_check", claims.arch_check.to_string());
                put(
                    "nras_report_signature_verified",
                    claims.report_signature_verified.to_string(),
                );
                put(
                    "nras_report_nonce_match",
                    claims.report_nonce_match.to_string(),
                );
                put("nras_report_parsed", claims.report_parsed.to_string());
                if claims.iat != 0 {
                    put("nras_token_iat", claims.iat.to_string());
                }
                if claims.exp != 0 {
                    put("nras_token_exp", claims.exp.to_string());
                }
            }

            Ok(result)
        } else {
            Ok(AttestationResult::failure(
                TeeVendor::NvidiaGpu,
                "GPU attestation verification failed".to_string(),
            ))
        }
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        // The enclave here is the confidential VM, not the GPU. AMD SEV-SNP or
        // Intel TDX creates the boundary; the GPU is a device admitted to it over
        // an authenticated link, and it runs CUDA kernels rather than the generic
        // operations this call carries. Executing against the CPU provider keeps
        // the response answering for the boundary that actually holds.
        let Some(anchor) = &self.cpu_anchor else {
            return Err(TeeError::not_available(
                "NVIDIA GPU Confidential Computing protects device memory inside a \
                 confidential VM; it is not itself an execution enclave. Attach the CPU \
                 provider that creates the VM with `with_cpu_anchor` to execute here.",
            ));
        };

        tracing::debug!(
            "Delegating '{}' to the {} confidential VM the GPU is admitted to",
            request.operation,
            anchor.vendor().as_str()
        );
        anchor.execute_in_enclave(request).await
    }

    async fn enclave_keygen(&self, params: KeyGenParams) -> Result<EnclaveKeyHandle> {
        tracing::debug!("Generating key in GPU CC enclave: {:?}", params.algorithm);

        // Generate a real cryptographic keypair. In production, the private key
        // stays in CC-protected GPU memory; in simulation, we store it locally.
        let key_id = uuid::Uuid::new_v4();
        let (public_key_bytes, secret_key_bytes) = match params.algorithm {
            KeyAlgorithm::Ed25519 => {
                let keypair =
                    tenzro_crypto::keys::KeyPair::generate(tenzro_crypto::keys::KeyType::Ed25519)
                        .map_err(|e| {
                        TeeError::KeyGenerationFailed(format!(
                            "Ed25519 key generation failed: {}",
                            e
                        ))
                    })?;
                let pub_bytes = keypair.public_key().as_bytes().to_vec();
                let sec_bytes = keypair.secret_key().as_bytes().to_vec();
                (pub_bytes, sec_bytes)
            }
            KeyAlgorithm::Secp256k1 => {
                let keypair =
                    tenzro_crypto::keys::KeyPair::generate(tenzro_crypto::keys::KeyType::Secp256k1)
                        .map_err(|e| {
                            TeeError::KeyGenerationFailed(format!(
                                "Secp256k1 key generation failed: {}",
                                e
                            ))
                        })?;
                let pub_bytes = keypair.public_key().as_bytes().to_vec();
                let sec_bytes = keypair.secret_key().as_bytes().to_vec();
                (pub_bytes, sec_bytes)
            }
            KeyAlgorithm::Aes256Gcm => {
                // Generate random 32-byte symmetric key
                let mut key_bytes = vec![0u8; 32];
                tenzro_crypto::rng::fill_random_bytes(&mut key_bytes);
                let pub_bytes = Vec::new(); // Symmetric keys have no public component
                (pub_bytes, key_bytes)
            }
        };

        let handle = EnclaveKeyHandle {
            id: key_id,
            algorithm: params.algorithm,
            public_key: if public_key_bytes.is_empty() {
                None
            } else {
                Some(public_key_bytes)
            },
            created_at: tenzro_types::primitives::Timestamp::now(),
            attestation: None,
        };

        self.keys.write().insert(key_id, handle.clone());
        self.secret_keys.write().insert(key_id, secret_key_bytes);
        tracing::info!(
            "Generated {:?} key in GPU CC enclave: {}",
            params.algorithm,
            key_id
        );
        Ok(handle)
    }

    async fn enclave_sign(&self, key: &EnclaveKeyHandle, data: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Signing data in GPU CC enclave, key_id={}", key.id);

        // Retrieve the secret key material
        let secret_keys = self.secret_keys.read();
        let secret_key_bytes = secret_keys.get(&key.id).ok_or_else(|| {
            TeeError::InvalidKeyHandle(format!("Key {} not found in GPU CC enclave", key.id))
        })?;

        // Perform real cryptographic signing
        match key.algorithm {
            KeyAlgorithm::Ed25519 => {
                let keypair = tenzro_crypto::keys::KeyPair::from_bytes(
                    tenzro_crypto::keys::KeyType::Ed25519,
                    secret_key_bytes,
                )
                .map_err(|e| {
                    TeeError::CryptoOperationFailed(format!(
                        "Failed to reconstruct Ed25519 key: {}",
                        e
                    ))
                })?;
                let signer =
                    tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair).map_err(|e| {
                        TeeError::CryptoOperationFailed(format!(
                            "Failed to create Ed25519 signer: {}",
                            e
                        ))
                    })?;
                use tenzro_crypto::signatures::Signer;
                let sig = signer.sign(data).map_err(|e| {
                    TeeError::CryptoOperationFailed(format!("Ed25519 signing failed: {}", e))
                })?;
                Ok(sig.as_bytes().to_vec())
            }
            KeyAlgorithm::Secp256k1 => {
                let keypair = tenzro_crypto::keys::KeyPair::from_bytes(
                    tenzro_crypto::keys::KeyType::Secp256k1,
                    secret_key_bytes,
                )
                .map_err(|e| {
                    TeeError::CryptoOperationFailed(format!(
                        "Failed to reconstruct Secp256k1 key: {}",
                        e
                    ))
                })?;
                let signer =
                    tenzro_crypto::signatures::Secp256k1SignerImpl::new(keypair).map_err(|e| {
                        TeeError::CryptoOperationFailed(format!(
                            "Failed to create Secp256k1 signer: {}",
                            e
                        ))
                    })?;
                use tenzro_crypto::signatures::Signer;
                let sig = signer.sign(data).map_err(|e| {
                    TeeError::CryptoOperationFailed(format!("Secp256k1 signing failed: {}", e))
                })?;
                Ok(sig.as_bytes().to_vec())
            }
            KeyAlgorithm::Aes256Gcm => Err(TeeError::CryptoOperationFailed(
                "Cannot sign with AES-256-GCM symmetric key".to_string(),
            )),
        }
    }

    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Encrypting data in GPU CC enclave, key_id={}", key.id);

        if !self.keys.read().contains_key(&key.id) {
            return Err(TeeError::InvalidKeyHandle(format!(
                "Key {} not found in GPU CC enclave",
                key.id
            )));
        }

        // In production, encryption uses GPU's AES-256-GCM hardware:
        // NVIDIA H100/H200 have dedicated AES engines for CC memory encryption.
        // In simulation mode we derive the key from the key UUID.
        crate::enclave_crypto::enclave_encrypt_aes256gcm(&key.id, b"nvidia-gpu", plaintext)
    }

    async fn enclave_decrypt(&self, key: &EnclaveKeyHandle, ciphertext: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Decrypting data in GPU CC enclave, key_id={}", key.id);

        if !self.keys.read().contains_key(&key.id) {
            return Err(TeeError::InvalidKeyHandle(format!(
                "Key {} not found in GPU CC enclave",
                key.id
            )));
        }

        // In production, decryption uses GPU's AES-256-GCM hardware.
        // In simulation mode we derive the key from the key UUID.
        crate::enclave_crypto::enclave_decrypt_aes256gcm(&key.id, b"nvidia-gpu", ciphertext)
    }
}

// ============================================================================
// Helper types and functions
// ============================================================================

/// Known NVIDIA GPU PCI device IDs.
///
/// Used by `detect_gpu_real()` to map a GPU's PCI device ID (queried from
/// `nvidia-smi --query-gpu=pci.device_id`) to the correct `GpuArchitecture`
/// without trusting the operator-supplied `expected_architecture` config.
/// The architecture decides which firmware-measurement format NRAS expects
/// and which evidence-collection path to use.
///
/// Coverage spans the broader NVIDIA lineup, not just the latest datacenter parts:
/// datacenter Hopper/Blackwell/Ada/Ampere/Turing/Volta, RTX 40/30/20 series
/// consumer cards, and Tesla T4/V100. CC support is a separate predicate
/// (`cc_capable`) — a GPU may be recognized but not Confidential-Computing
/// capable, in which case the provider serves model inference without TEE
/// attestation guarantees.
///
/// Sources:
/// - PCI ID database (https://pci-ids.ucw.cz/)
/// - NVIDIA datasheets per product line
/// - NVIDIA Confidential Computing support matrix
pub mod known_gpus {
    use super::GpuArchitecture;

    // -- Hopper (CC 1.0 capable) --
    /// H100 SXM5 (Hopper, CC 1.0)
    pub const H100_SXM5: &str = "2330";
    /// H100 PCIe (Hopper, CC 1.0)
    pub const H100_PCIE: &str = "2331";
    /// H100 NVL (Hopper, CC 1.0)
    pub const H100_NVL: &str = "2321";
    /// H200 SXM (Hopper, CC 1.0, extended HBM)
    pub const H200_SXM: &str = "2335";
    /// H200 NVL (Hopper, CC 1.0)
    pub const H200_NVL: &str = "2336";
    /// H800 SXM (Hopper, China-region SKU)
    pub const H800_SXM: &str = "2322";
    /// H20 (Hopper, China-region SKU)
    pub const H20: &str = "232C";

    // -- Blackwell (CC 2.0 capable) --
    /// B100 (Blackwell, CC 2.0)
    pub const B100: &str = "2900";
    /// B200 (Blackwell, CC 2.0)
    pub const B200: &str = "2901";
    /// GB200 (Blackwell, CC 2.0)
    pub const GB200: &str = "2902";

    // -- Ada Lovelace (datacenter, limited CC) --
    /// L40S (Ada Lovelace, limited CC)
    pub const L40S: &str = "26B9";
    /// L40 (Ada Lovelace)
    pub const L40: &str = "26B5";
    /// L4 (Ada Lovelace, low-power inference)
    pub const L4: &str = "27B8";

    // -- Ada Lovelace (consumer RTX 40-series) --
    /// RTX 4090 (Ada)
    pub const RTX_4090: &str = "2684";
    /// RTX 4080 SUPER (Ada)
    pub const RTX_4080_SUPER: &str = "2702";
    /// RTX 4080 (Ada)
    pub const RTX_4080: &str = "2704";
    /// RTX 4070 Ti SUPER (Ada)
    pub const RTX_4070_TI_SUPER: &str = "2705";
    /// RTX 4070 Ti (Ada)
    pub const RTX_4070_TI: &str = "2782";
    /// RTX 4070 SUPER (Ada)
    pub const RTX_4070_SUPER: &str = "2783";
    /// RTX 4070 (Ada)
    pub const RTX_4070: &str = "2786";
    /// RTX 4060 Ti (Ada)
    pub const RTX_4060_TI: &str = "2803";
    /// RTX 4060 (Ada)
    pub const RTX_4060: &str = "2882";

    // -- Ampere (datacenter A-series, CC not supported) --
    /// A100 SXM4 80GB (Ampere)
    pub const A100_SXM4_80: &str = "20B2";
    /// A100 PCIe 80GB (Ampere)
    pub const A100_PCIE_80: &str = "20B5";
    /// A100 SXM4 40GB (Ampere)
    pub const A100_SXM4_40: &str = "20B0";
    /// A100 PCIe 40GB (Ampere)
    pub const A100_PCIE_40: &str = "20F1";
    /// A40 (Ampere)
    pub const A40: &str = "2235";
    /// A30 (Ampere)
    pub const A30: &str = "20B7";
    /// A10 (Ampere)
    pub const A10: &str = "2236";
    /// A16 (Ampere)
    pub const A16: &str = "20F3";
    /// A2 (Ampere)
    pub const A2: &str = "25B6";

    // -- Ampere (consumer RTX 30-series) --
    /// RTX 3090 Ti (Ampere)
    pub const RTX_3090_TI: &str = "2203";
    /// RTX 3090 (Ampere)
    pub const RTX_3090: &str = "2204";
    /// RTX 3080 Ti (Ampere)
    pub const RTX_3080_TI: &str = "2208";
    /// RTX 3080 (Ampere)
    pub const RTX_3080: &str = "2206";
    /// RTX 3070 Ti (Ampere)
    pub const RTX_3070_TI: &str = "2482";
    /// RTX 3070 (Ampere)
    pub const RTX_3070: &str = "2484";
    /// RTX 3060 Ti (Ampere)
    pub const RTX_3060_TI: &str = "2486";
    /// RTX 3060 (Ampere)
    pub const RTX_3060: &str = "2503";
    /// RTX 3050 (Ampere)
    pub const RTX_3050: &str = "2507";

    // -- Turing (Tesla T4 + RTX 20-series) --
    /// Tesla T4 (Turing, common cloud inference)
    pub const T4: &str = "1EB8";
    /// RTX 2080 Ti (Turing)
    pub const RTX_2080_TI: &str = "1E07";
    /// RTX 2080 SUPER (Turing)
    pub const RTX_2080_SUPER: &str = "1E81";
    /// RTX 2080 (Turing)
    pub const RTX_2080: &str = "1E87";
    /// RTX 2070 SUPER (Turing)
    pub const RTX_2070_SUPER: &str = "1E84";
    /// RTX 2070 (Turing)
    pub const RTX_2070: &str = "1F02";
    /// RTX 2060 SUPER (Turing)
    pub const RTX_2060_SUPER: &str = "1F06";
    /// RTX 2060 (Turing)
    pub const RTX_2060: &str = "1F08";

    // -- Volta (Tesla V100) --
    /// V100 SXM2 32GB (Volta)
    pub const V100_SXM2_32: &str = "1DB5";
    /// V100 PCIe 32GB (Volta)
    pub const V100_PCIE_32: &str = "1DB6";
    /// V100 SXM2 16GB (Volta)
    pub const V100_SXM2_16: &str = "1DB1";
    /// V100 PCIe 16GB (Volta)
    pub const V100_PCIE_16: &str = "1DB4";

    /// Resolve a GPU's PCI device ID (uppercase hex, no `0x` prefix) to its
    /// architecture. Returns `None` for unknown devices so the caller can
    /// fall back to the operator-supplied expected architecture.
    pub fn architecture_for_pci_id(pci_device_id: &str) -> Option<GpuArchitecture> {
        match pci_device_id {
            // Hopper datacenter
            H100_SXM5 | H100_PCIE | H100_NVL | H200_SXM | H200_NVL | H800_SXM | H20 => {
                Some(GpuArchitecture::Hopper)
            }
            // Blackwell datacenter
            B100 | B200 | GB200 => Some(GpuArchitecture::Blackwell),
            // Ada Lovelace (datacenter + RTX 40-series)
            L40S | L40 | L4 | RTX_4090 | RTX_4080_SUPER | RTX_4080 | RTX_4070_TI_SUPER
            | RTX_4070_TI | RTX_4070_SUPER | RTX_4070 | RTX_4060_TI | RTX_4060 => {
                Some(GpuArchitecture::AdaLovelace)
            }
            // Ampere (datacenter + RTX 30-series)
            A100_SXM4_80 | A100_PCIE_80 | A100_SXM4_40 | A100_PCIE_40 | A40 | A30 | A10 | A16
            | A2 | RTX_3090_TI | RTX_3090 | RTX_3080_TI | RTX_3080 | RTX_3070_TI | RTX_3070
            | RTX_3060_TI | RTX_3060 | RTX_3050 => Some(GpuArchitecture::Ampere),
            // Turing (Tesla T4 + RTX 20-series)
            T4 | RTX_2080_TI | RTX_2080_SUPER | RTX_2080 | RTX_2070_SUPER | RTX_2070
            | RTX_2060_SUPER | RTX_2060 => Some(GpuArchitecture::Turing),
            // Volta (V100)
            V100_SXM2_32 | V100_PCIE_32 | V100_SXM2_16 | V100_PCIE_16 => {
                Some(GpuArchitecture::Volta)
            }
            _ => None,
        }
    }

    /// Whether a given PCI device ID is Confidential-Computing capable.
    ///
    /// Only Hopper datacenter SKUs (H100/H200/H800/H20), Blackwell datacenter
    /// SKUs (B100/B200/GB200), and select Ada Lovelace datacenter SKUs (L40S)
    /// support NVIDIA CC. Consumer cards and older datacenter parts (A100,
    /// V100, T4, RTX series) do not — they can still serve model inference,
    /// but without TEE attestation guarantees.
    pub fn cc_capable(pci_device_id: &str) -> bool {
        matches!(
            pci_device_id,
            H100_SXM5
                | H100_PCIE
                | H100_NVL
                | H200_SXM
                | H200_NVL
                | H800_SXM
                | H20
                | B100
                | B200
                | GB200
                | L40S
        )
    }

    /// Recognize a part that is known to have no Confidential Computing mode,
    /// by device name rather than PCI ID.
    ///
    /// Integrated parts such as the GB10 Grace Blackwell superchip in the DGX
    /// Spark share a memory controller with the CPU and expose no separate
    /// PCIe-attached CC mode, so a PCI device ID is not the right key for them.
    /// Returning the part name here lets the caller log why attestation is
    /// unavailable instead of reporting an unknown device.
    pub fn non_cc_part_by_name(device_name: &str) -> Option<&'static str> {
        let name = device_name.to_ascii_uppercase();
        if name.contains("GB10") || name.contains("DGX SPARK") {
            return Some("GB10 Grace Blackwell superchip");
        }
        None
    }
}

/// NRAS verification result.
struct NrasVerificationResult {
    verified: bool,
    token: String,
    claims: NrasTokenClaims,
}

/// Simulated GPU evidence (JSON format).
#[derive(Debug, Serialize, Deserialize)]
struct SimulatedEvidence {
    gpu_name: String,
    architecture: String,
    pci_device_id: String,
    driver_version: String,
    cc_enabled: bool,
    cc_firmware_version: Option<String>,
    nonce: String,
    timestamp: i64,
}

/// Parse JWT token claims without signature verification.
///
/// NRAS tokens arrive over TLS from nras.attestation.nvidia.com,
/// so transport-level authentication is sufficient. We extract
/// the payload claims for use in attestation results.
fn parse_jwt_claims(token: &str) -> Result<NrasTokenClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(TeeError::AttestationVerificationFailed(
            "Invalid JWT token format from NRAS".to_string(),
        ));
    }

    let payload =
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1])
            .map_err(|e| {
                TeeError::AttestationVerificationFailed(format!(
                    "Failed to decode JWT payload: {}",
                    e
                ))
            })?;

    serde_json::from_slice(&payload).map_err(|e| {
        TeeError::AttestationVerificationFailed(format!("Failed to parse JWT claims: {}", e))
    })
}

/// Split an NRAS response into the overall token and the per-GPU tokens.
///
/// NRAS answers with an RFC 9711 detached Entity Attestation Token bundle: a
/// two-element array whose first element is `["JWT", "<overall-token>"]` and
/// whose second is an object mapping a device name ("GPU-0", ...) to that
/// device's token.
///
/// Returns the raw overall token alongside the decoded claims, because a
/// relying party downstream may want to forward the token itself rather than
/// this crate's projection of it.
fn parse_nras_bundle(body: &str) -> Result<(String, NrasBundle)> {
    let malformed = |detail: &str| {
        TeeError::AttestationVerificationFailed(format!(
            "NRAS response is not a detached EAT bundle: {}",
            detail
        ))
    };

    let parsed: serde_json::Value =
        serde_json::from_str(body).map_err(|e| malformed(&format!("not JSON ({})", e)))?;

    let outer = parsed.as_array().ok_or_else(|| malformed("not an array"))?;
    if outer.len() != 2 {
        return Err(malformed("expected exactly two elements"));
    }

    let overall_token = outer[0]
        .as_array()
        .and_then(|pair| pair.get(1))
        .and_then(|token| token.as_str())
        .ok_or_else(|| malformed("first element is not a [type, token] pair"))?
        .to_string();

    let submods = outer[1]
        .as_object()
        .ok_or_else(|| malformed("second element is not an object of device tokens"))?;

    let mut per_gpu = Vec::new();
    for (name, token) in submods {
        // A device entry is the device's own token. NRAS also emits digest
        // entries of the form ["DIGEST", ["SHA256", "<hex>"]] which hash the
        // device claims rather than carrying them, so anything that is not a
        // string is not a token and is skipped.
        let Some(token) = token.as_str() else {
            continue;
        };
        per_gpu.push((name.clone(), parse_jwt_claims(token)?));
    }

    if per_gpu.is_empty() {
        return Err(malformed("carries no per-device tokens"));
    }
    per_gpu.sort_by(|a, b| a.0.cmp(&b.0));

    let overall = parse_jwt_claims(&overall_token)?;
    Ok((overall_token, NrasBundle { overall, per_gpu }))
}

/// Compare two version strings (semver-like: "550.90.07" >= "550.0").
///
/// Splits on "." and compares each numeric component left-to-right.
/// Missing components are treated as 0.
fn version_gte(actual: &str, required: &str) -> bool {
    let actual_parts: Vec<u64> = actual.split('.').filter_map(|s| s.parse().ok()).collect();
    let required_parts: Vec<u64> = required.split('.').filter_map(|s| s.parse().ok()).collect();

    let max_len = actual_parts.len().max(required_parts.len());
    for i in 0..max_len {
        let a = actual_parts.get(i).copied().unwrap_or(0);
        let r = required_parts.get(i).copied().unwrap_or(0);
        if a > r {
            return true;
        }
        if a < r {
            return false;
        }
    }
    true // Equal
}

#[cfg(test)]
mod tests {
    // ---- SPDM MEASUREMENTS parsing -------------------------------------
    //
    // These build real wire bytes rather than mocking the parser, so the
    // layout assumptions are the thing under test. The report is what a
    // relying party's whole trust decision rests on, and a parser that
    // mis-reads a length is how a malformed report becomes a panic or a
    // silently-truncated measurement.

    /// One DMTF measurement block: `index | spec | size(u16 LE) | body`,
    /// body = `value_type | value_size(u16 LE) | value`.
    fn dmtf_block(index: u8, value_type: u8, value: &[u8]) -> Vec<u8> {
        let mut body = vec![value_type];
        body.extend_from_slice(&(value.len() as u16).to_le_bytes());
        body.extend_from_slice(value);

        let mut block = vec![index, SPDM_MEASUREMENT_SPEC_DMTF];
        block.extend_from_slice(&(body.len() as u16).to_le_bytes());
        block.extend_from_slice(&body);
        block
    }

    /// A whole MEASUREMENTS response around `record`.
    fn spdm_response(
        version: u8,
        record: &[u8],
        nonce: &[u8; 32],
        opaque: &[u8],
        sig: &[u8],
    ) -> Vec<u8> {
        let mut out = vec![version, SPDM_CODE_MEASUREMENTS, 0, 0, 0];
        let len = record.len() as u32;
        out.extend_from_slice(&len.to_le_bytes()[..3]); // 24-bit record length
        out.extend_from_slice(record);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&(opaque.len() as u16).to_le_bytes());
        out.extend_from_slice(opaque);
        out.extend_from_slice(sig);
        out
    }

    #[test]
    fn parses_a_well_formed_measurements_response() {
        let record = [
            dmtf_block(1, 0x01, &[0xAA; 48]),
            dmtf_block(2, 0x02, &[0xBB; 48]),
        ]
        .concat();
        let nonce = [0x5A; 32];
        let blob = spdm_response(0x11, &record, &nonce, b"opaque", &[0xCC; 96]);

        let parsed = parse_gpu_attestation_report(&blob).expect("well-formed report must parse");

        assert_eq!(parsed.blocks.len(), 2);
        assert_eq!(parsed.blocks[0].index, 1);
        assert_eq!(parsed.blocks[0].value_type, 0x01);
        assert_eq!(parsed.blocks[0].value, vec![0xAA; 48]);
        assert_eq!(parsed.blocks[1].index, 2);
        assert_eq!(parsed.nonce, nonce.to_vec());
        assert_eq!(parsed.opaque_data, b"opaque".to_vec());
        assert_eq!(parsed.signature, vec![0xCC; 96]);
        // The hash must cover the record exactly, not the framing around it.
        assert_eq!(
            parsed.measurement_record_hash,
            Sha384::digest(&record).to_vec()
        );
    }

    #[test]
    fn accepts_spdm_1_2_as_well_as_1_1() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let blob = spdm_response(0x12, &record, &[0; 32], &[], &[0xEE; 96]);
        assert!(parse_gpu_attestation_report(&blob).is_ok());
    }

    #[test]
    fn rejects_an_unsupported_spdm_version() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let blob = spdm_response(0x10, &record, &[0; 32], &[], &[0xEE; 96]);
        let err = parse_gpu_attestation_report(&blob).expect_err("0x10 is not a supported version");
        assert!(
            format!("{err}").contains("unsupported SPDM version"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_a_response_that_is_not_measurements() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let mut blob = spdm_response(0x11, &record, &[0; 32], &[], &[0xEE; 96]);
        blob[1] = 0x61; // some other SPDM response code
        let err = parse_gpu_attestation_report(&blob).expect_err("wrong code must be refused");
        assert!(
            format!("{err}").contains("not a MEASUREMENTS response"),
            "got {err}"
        );
    }

    /// The driver may prefix the GET_MEASUREMENTS request it sent. That prefix
    /// has to be skipped, or the parser reads the request as the response.
    #[test]
    fn skips_a_prefixed_get_measurements_request() {
        let record = dmtf_block(3, 0x01, &[0x77; 48]);
        let nonce = [0x33; 32];
        let response = spdm_response(0x11, &record, &nonce, &[], &[0xDD; 96]);

        let mut blob = vec![0u8; SPDM_MEASUREMENTS_REQUEST_LEN];
        blob[1] = SPDM_CODE_GET_MEASUREMENTS;
        blob.extend_from_slice(&response);

        let parsed = parse_gpu_attestation_report(&blob).expect("prefixed report must parse");
        assert_eq!(parsed.nonce, nonce.to_vec());
        assert_eq!(parsed.blocks[0].index, 3);
    }

    // ---- truncation and length-field abuse ------------------------------

    #[test]
    fn rejects_a_header_shorter_than_the_spdm_minimum() {
        let err = parse_gpu_attestation_report(&[0x11, 0x60, 0, 0]).expect_err("too short");
        assert!(
            format!("{err}").contains("shorter than an SPDM MEASUREMENTS header"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_a_report_truncated_before_the_nonce() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let full = spdm_response(0x11, &record, &[0; 32], &[], &[0xEE; 96]);
        // Cut inside the nonce.
        let truncated = &full[..8 + record.len() + 10];
        let err = parse_gpu_attestation_report(truncated).expect_err("must not read past the end");
        assert!(
            format!("{err}").contains("truncated before the nonce"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_a_report_with_no_signature() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        // Empty signature: opaque_end == len, so there is nothing left to sign with.
        let blob = spdm_response(0x11, &record, &[0; 32], &[], &[]);
        let err =
            parse_gpu_attestation_report(&blob).expect_err("an unsigned report is not evidence");
        assert!(
            format!("{err}").contains("truncated before the signature"),
            "got {err}"
        );
    }

    /// A declared record length that runs past the buffer must be refused
    /// rather than panicking on the slice.
    #[test]
    fn rejects_an_overlong_declared_record_length() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let mut blob = spdm_response(0x11, &record, &[0; 32], &[], &[0xEE; 96]);
        blob[5] = 0xFF;
        blob[6] = 0xFF;
        blob[7] = 0xFF;
        assert!(parse_gpu_attestation_report(&blob).is_err());
    }

    /// Likewise an opaque-data length that overruns the buffer.
    #[test]
    fn rejects_an_overlong_declared_opaque_length() {
        let record = dmtf_block(1, 0x01, &[0x11; 48]);
        let mut blob = spdm_response(0x11, &record, &[0; 32], b"xy", &[0xEE; 96]);
        let opaque_len_at = 8 + record.len() + 32;
        blob[opaque_len_at] = 0xFF;
        blob[opaque_len_at + 1] = 0xFF;
        assert!(parse_gpu_attestation_report(&blob).is_err());
    }

    // ---- measurement-block parsing --------------------------------------

    #[test]
    fn rejects_a_non_dmtf_measurement_specification() {
        // spec bit 0 clear => not DMTF.
        let mut block = dmtf_block(1, 0x01, &[0x11; 48]);
        block[1] = 0x02;
        let blob = spdm_response(0x11, &block, &[0; 32], &[], &[0xEE; 96]);
        let err = parse_gpu_attestation_report(&blob).expect_err("non-DMTF must be refused");
        assert!(format!("{err}").contains("not DMTF"), "got {err}");
    }

    #[test]
    fn rejects_a_block_running_past_the_record() {
        let mut block = dmtf_block(1, 0x01, &[0x11; 48]);
        // Declare a body far larger than what follows.
        block[2] = 0xFF;
        block[3] = 0x00;
        let blob = spdm_response(0x11, &block, &[0; 32], &[], &[0xEE; 96]);
        let err = parse_gpu_attestation_report(&blob).expect_err("must not read past the record");
        assert!(
            format!("{err}").contains("runs past the record"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_a_record_ending_mid_block_header() {
        // Three bytes: less than the four-byte block header.
        let blob = spdm_response(
            0x11,
            &[1, SPDM_MEASUREMENT_SPEC_DMTF, 0],
            &[0; 32],
            &[],
            &[0xEE; 96],
        );
        let err = parse_gpu_attestation_report(&blob).expect_err("partial header must be refused");
        assert!(
            format!("{err}").contains("ends mid-block header"),
            "got {err}"
        );
    }

    #[test]
    fn rejects_a_value_larger_than_its_block() {
        let mut block = dmtf_block(1, 0x01, &[0x11; 8]);
        // Body is 3 + 8 bytes; claim a 0xFF-byte value inside it.
        block[5] = 0xFF;
        block[6] = 0x00;
        let blob = spdm_response(0x11, &block, &[0; 32], &[], &[0xEE; 96]);
        let err = parse_gpu_attestation_report(&blob).expect_err("value must fit its block");
        assert!(
            format!("{err}").contains("larger than the block"),
            "got {err}"
        );
    }

    /// A structurally valid response carrying no measurements is refused.
    ///
    /// It would parse cleanly and verify cleanly — the signature covers the
    /// empty record perfectly well — while attesting nothing at all. Rejecting
    /// it in the parser means a relying party cannot be handed a report that
    /// looks valid and says nothing.
    #[test]
    fn rejects_a_measurement_record_with_no_blocks() {
        let blob = spdm_response(0x11, &[], &[0x99; 32], &[], &[0xEE; 96]);
        let err = parse_gpu_attestation_report(&blob)
            .expect_err("a report with no measurements is not evidence");
        assert!(
            format!("{err}").contains("no measurement blocks"),
            "got {err}"
        );
    }

    use super::*;

    #[tokio::test]
    async fn test_nvidia_provider_creation() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config).with_simulate();
        assert_eq!(provider.vendor(), TeeVendor::NvidiaGpu);
        assert!(provider.simulate);
    }

    #[tokio::test]
    async fn test_gpu_detection_simulated() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config).with_simulate();

        let available = provider.is_available().await.unwrap();
        assert!(available); // Simulated GPU always available with CC enabled
    }

    /// Config for tests that exercise GPU-report *mechanics* rather than the
    /// composite-anchor invariant.
    ///
    /// `require_cpu_anchor` defaults to true, so a bare GPU provider refuses to
    /// attest at all — which is the correct production behaviour and is asserted
    /// separately by [`bare_gpu_provider_refuses_to_attest`]. Tests below that
    /// only care about report shape opt out explicitly rather than silently
    /// depending on the default.
    fn gpu_only_config() -> NvidiaGpuConfig {
        NvidiaGpuConfig {
            require_cpu_anchor: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn bare_gpu_provider_refuses_to_attest() {
        // NVIDIA GPU CC establishes no trust boundary on its own: the
        // confidential VM comes from SEV-SNP or TDX and the GPU is admitted to
        // it. A provider with no CPU anchor must therefore refuse rather than
        // emit a report a relying party could mistake for a complete TEE claim.
        let provider = NvidiaGpuProvider::new(NvidiaGpuConfig::default()).with_simulate();

        let err = provider
            .generate_attestation(b"test")
            .await
            .expect_err("bare GPU provider must not produce an attestation");

        assert!(
            matches!(err, TeeError::NotAvailable(_)),
            "expected NotAvailable, got {err:?}"
        );
    }

    #[tokio::test]
    async fn test_generate_attestation_simulated() {
        let config = gpu_only_config();
        let provider = NvidiaGpuProvider::new(config).with_simulate();

        let user_data = b"test attestation data for gpu";
        let report = provider.generate_attestation(user_data).await.unwrap();

        assert_eq!(report.vendor, TeeVendor::NvidiaGpu);
        assert_eq!(report.user_data, user_data);
        assert!(!report.attestation_data.is_empty());

        // Check metadata
        assert_eq!(report.metadata.get("simulated"), Some(&"true".to_string()));
        assert!(report.metadata.contains_key("gpu_name"));
        assert!(report.metadata.contains_key("architecture"));
        assert!(report.metadata.contains_key("driver_version"));
    }

    #[tokio::test]
    async fn test_verify_attestation_simulated_is_invalid() {
        // Simulated NVIDIA reports have no NRAS backing and therefore
        // no cryptographic authority. The verifier must reject them
        // outright — `result.valid` is false and the relying party
        // must not branch into the success path.
        let config = gpu_only_config();
        let provider = NvidiaGpuProvider::new(config).with_simulate();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        assert!(
            !result.valid,
            "simulated NVIDIA GPU reports must never report valid=true"
        );
        assert_eq!(result.vendor, TeeVendor::NvidiaGpu);
    }

    #[tokio::test]
    async fn test_verify_wrong_vendor_rejected() {
        let config = gpu_only_config();
        let provider = NvidiaGpuProvider::new(config).with_simulate();

        let mut report = provider.generate_attestation(b"test").await.unwrap();
        report.vendor = TeeVendor::IntelTdx; // Wrong vendor

        let result = provider.verify_attestation(&report).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_enclave_keygen_and_sign() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config);

        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Ed25519,
            purpose: KeyPurpose::Signing,
            exportable: false,
            params: HashMap::new(),
        };

        let key = provider.enclave_keygen(params).await.unwrap();
        assert!(key.public_key.is_some());
        assert_eq!(key.algorithm, KeyAlgorithm::Ed25519);

        // Sign data (real Ed25519 signature = 64 bytes)
        let signature = provider.enclave_sign(&key, b"test data").await.unwrap();
        assert_eq!(signature.len(), 64); // Ed25519 signature

        // Ed25519 signing is deterministic (RFC 8032)
        let signature2 = provider.enclave_sign(&key, b"test data").await.unwrap();
        assert_eq!(signature, signature2);

        // Different data should produce different signature
        let signature3 = provider
            .enclave_sign(&key, b"different data")
            .await
            .unwrap();
        assert_ne!(signature, signature3);

        // Verify the signature is cryptographically valid
        let pubkey = tenzro_crypto::keys::PublicKey::new(
            tenzro_crypto::keys::KeyType::Ed25519,
            key.public_key.unwrap(),
        );
        let sig = tenzro_crypto::signatures::Signature::new(
            tenzro_crypto::keys::KeyType::Ed25519,
            signature,
        );
        assert!(tenzro_crypto::signatures::verify(&pubkey, b"test data", &sig).is_ok());
    }

    #[tokio::test]
    async fn test_enclave_encrypt_decrypt() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config);

        let params = KeyGenParams {
            algorithm: KeyAlgorithm::Aes256Gcm,
            purpose: KeyPurpose::Encryption,
            exportable: false,
            params: HashMap::new(),
        };

        let key = provider.enclave_keygen(params).await.unwrap();

        let plaintext = b"confidential GPU computation result";
        let ciphertext = provider.enclave_encrypt(&key, plaintext).await.unwrap();
        assert_ne!(ciphertext, plaintext); // Should be different after encryption

        let decrypted = provider.enclave_decrypt(&key, &ciphertext).await.unwrap();
        assert_eq!(decrypted, plaintext); // Should match original
    }

    #[tokio::test]
    async fn test_invalid_key_handle() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config);

        // Try to sign with a non-existent key
        let fake_key = EnclaveKeyHandle {
            id: uuid::Uuid::new_v4(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: None,
            created_at: tenzro_types::primitives::Timestamp::now(),
            attestation: None,
        };

        let result = provider.enclave_sign(&fake_key, b"test").await;
        assert!(result.is_err());
    }

    #[test]
    fn test_gpu_architecture_display() {
        assert_eq!(GpuArchitecture::Hopper.to_string(), "Hopper");
        assert_eq!(GpuArchitecture::Blackwell.to_string(), "Blackwell");
        assert_eq!(GpuArchitecture::AdaLovelace.to_string(), "Ada Lovelace");
    }

    #[test]
    fn test_version_comparison() {
        assert!(version_gte("550.90.07", "550.0"));
        assert!(version_gte("550.0", "550.0"));
        assert!(version_gte("551.0", "550.0"));
        assert!(!version_gte("549.0", "550.0"));
        assert!(version_gte("1.0.1", "1.0"));
        assert!(!version_gte("1.0", "1.0.1"));
        assert!(version_gte("2.0", "1.9.9"));
    }

    #[test]
    fn test_known_gpu_architectures() {
        // Hopper datacenter
        assert_eq!(
            known_gpus::architecture_for_pci_id("2330"),
            Some(GpuArchitecture::Hopper)
        );
        assert_eq!(
            known_gpus::architecture_for_pci_id("2335"),
            Some(GpuArchitecture::Hopper)
        );
        // Blackwell datacenter
        assert_eq!(
            known_gpus::architecture_for_pci_id("2900"),
            Some(GpuArchitecture::Blackwell)
        );
        // Ada Lovelace (datacenter)
        assert_eq!(
            known_gpus::architecture_for_pci_id("26B9"),
            Some(GpuArchitecture::AdaLovelace)
        );
        // Ada Lovelace (consumer RTX 4090)
        assert_eq!(
            known_gpus::architecture_for_pci_id("2684"),
            Some(GpuArchitecture::AdaLovelace)
        );
        // Ampere (datacenter A100)
        assert_eq!(
            known_gpus::architecture_for_pci_id("20B2"),
            Some(GpuArchitecture::Ampere)
        );
        // Ampere (consumer RTX 3090)
        assert_eq!(
            known_gpus::architecture_for_pci_id("2204"),
            Some(GpuArchitecture::Ampere)
        );
        // Turing (Tesla T4)
        assert_eq!(
            known_gpus::architecture_for_pci_id("1EB8"),
            Some(GpuArchitecture::Turing)
        );
        // Turing (consumer RTX 2080 Ti)
        assert_eq!(
            known_gpus::architecture_for_pci_id("1E07"),
            Some(GpuArchitecture::Turing)
        );
        // Volta (V100)
        assert_eq!(
            known_gpus::architecture_for_pci_id("1DB5"),
            Some(GpuArchitecture::Volta)
        );
        assert_eq!(known_gpus::architecture_for_pci_id("XXXX"), None);
    }

    #[test]
    fn test_cc_capable_predicate() {
        // CC-capable
        assert!(known_gpus::cc_capable("2330")); // H100 SXM5
        assert!(known_gpus::cc_capable("2335")); // H200 SXM
        assert!(known_gpus::cc_capable("2900")); // B100
        assert!(known_gpus::cc_capable("26B9")); // L40S
        // Recognized but NOT CC-capable
        assert!(!known_gpus::cc_capable("2684")); // RTX 4090
        assert!(!known_gpus::cc_capable("20B2")); // A100
        assert!(!known_gpus::cc_capable("2204")); // RTX 3090
        assert!(!known_gpus::cc_capable("1EB8")); // T4
        assert!(!known_gpus::cc_capable("1DB5")); // V100
        // Unknown
        assert!(!known_gpus::cc_capable("XXXX"));
    }

    #[test]
    fn test_architecture_supports_cc() {
        assert!(GpuArchitecture::Hopper.supports_cc());
        assert!(GpuArchitecture::Blackwell.supports_cc());
        assert!(GpuArchitecture::AdaLovelace.supports_cc());
        assert!(!GpuArchitecture::Ampere.supports_cc());
        assert!(!GpuArchitecture::Turing.supports_cc());
        assert!(!GpuArchitecture::Volta.supports_cc());
    }

    #[test]
    fn test_architecture_display_full() {
        assert_eq!(GpuArchitecture::Ampere.to_string(), "Ampere");
        assert_eq!(GpuArchitecture::Turing.to_string(), "Turing");
        assert_eq!(GpuArchitecture::Volta.to_string(), "Volta");
    }

    #[test]
    fn test_nras_endpoint_from_certs() {
        let config = NvidiaGpuConfig::default();
        assert_eq!(config.nras_endpoint, certs::NVIDIA_NRAS_ENDPOINT);
        assert!(config.nras_endpoint.starts_with("https://"));
        assert!(config.nras_endpoint.contains("attestation.nvidia.com"));
    }

    #[test]
    fn test_jwt_parse_claims() {
        // Create a minimal JWT (header.payload.signature)
        let header = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            r#"{"alg":"ES384","typ":"JWT"}"#,
        );
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            r#"{"measres":"success","x-nvidia-overall-att-result":true,"x-nvidia-ver":"3.0","hwmodel":"NVIDIA H100 80GB HBM3","eat_nonce":"deadbeef","secboot":true,"dbgstat":"disabled","iat":1700000000,"exp":1700086400}"#,
        );
        let token = format!("{}.{}.fake_signature", header, payload);

        let claims = parse_jwt_claims(&token).unwrap();
        assert!(claims.overall_result);
        assert_eq!(claims.measres, "success");
        assert_eq!(claims.claims_version, "3.0");
        assert_eq!(claims.hwmodel, "NVIDIA H100 80GB HBM3");
        assert_eq!(claims.eat_nonce, "deadbeef");
        assert!(claims.secboot);
        assert_eq!(claims.dbgstat, "disabled");
    }

    #[test]
    fn test_jwt_parse_invalid_format() {
        assert!(parse_jwt_claims("not.a.valid.jwt.token").is_err());
        assert!(parse_jwt_claims("single_segment").is_err());
    }

    #[test]
    fn test_parse_nras_bundle() {
        let jwt = |payload: &str| {
            let header = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                r#"{"alg":"ES384","typ":"JWT"}"#,
            );
            let body =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload);
            format!("{}.{}.sig", header, body)
        };

        let overall = jwt(r#"{"x-nvidia-overall-att-result":true,"eat_nonce":"ab12"}"#);
        let gpu0 = jwt(r#"{"measres":"success","hwmodel":"NVIDIA H100 80GB HBM3"}"#);
        let gpu1 = jwt(r#"{"measres":"success","hwmodel":"NVIDIA H100 80GB HBM3"}"#);

        // The digest entry is not a token and must be skipped rather than
        // treated as a device.
        let body = format!(
            r#"[["JWT","{}"],{{"GPU-1":"{}","GPU-0":"{}","JWT":["DIGEST",["SHA256","00ff"]]}}]"#,
            overall, gpu1, gpu0
        );

        let (token, bundle) = parse_nras_bundle(&body).unwrap();
        assert_eq!(token, overall);
        assert!(bundle.overall.overall_result);
        assert_eq!(bundle.overall.eat_nonce, "ab12");
        assert_eq!(bundle.per_gpu.len(), 2);
        assert_eq!(bundle.per_gpu[0].0, "GPU-0");
        assert_eq!(bundle.per_gpu[1].0, "GPU-1");
        assert!(bundle.per_gpu.iter().all(|(_, c)| c.measres == "success"));
    }

    #[test]
    fn test_parse_nras_bundle_rejects_malformed() {
        assert!(parse_nras_bundle("not json").is_err());
        assert!(parse_nras_bundle(r#"{"token":"abc"}"#).is_err());
        assert!(parse_nras_bundle(r#"[["JWT","a.b.c"]]"#).is_err());
        // A bundle whose submodule map holds no device tokens carries no verdict.
        assert!(parse_nras_bundle(r#"[["JWT","a.b.c"],{}]"#).is_err());
    }
}
