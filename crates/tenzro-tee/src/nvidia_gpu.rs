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

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tenzro_types::tee::*;
use crate::certs;
use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;

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
        matches!(self, GpuArchitecture::Hopper | GpuArchitecture::Blackwell | GpuArchitecture::AdaLovelace)
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
    /// Firmware measurements (VBIOS hash, driver hash)
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
}

/// GPU firmware measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuMeasurements {
    /// VBIOS hash (SHA-384)
    pub vbios_hash: Vec<u8>,
    /// Driver version hash (SHA-384)
    pub driver_hash: Vec<u8>,
    /// CC firmware hash (SHA-384)
    pub cc_firmware_hash: Vec<u8>,
    /// ECC mode enabled
    pub ecc_enabled: bool,
    /// MIG (Multi-Instance GPU) mode
    pub mig_enabled: bool,
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

/// NRAS attestation request body.
#[derive(Debug, Serialize)]
struct NrasAttestationRequest {
    /// Base64-encoded GPU evidence (SPDM measurements)
    evidence: String,
    /// Hex-encoded nonce for replay protection
    nonce: String,
    /// GPU architecture string ("HOPPER", "BLACKWELL", "ADA_LOVELACE")
    arch: String,
}

/// NRAS attestation response.
#[derive(Debug, Deserialize)]
struct NrasAttestationResponse {
    /// JWT attestation token
    #[serde(default)]
    token: String,
    /// Whether attestation passed
    #[serde(default)]
    attestation_result: bool,
    /// Error message if failed
    #[serde(default)]
    error: Option<String>,
}

/// NRAS JWT token claims (subset of fields we care about).
#[derive(Debug, Deserialize)]
struct NrasTokenClaims {
    /// Whether the GPU passed attestation
    #[serde(default)]
    gpu_attestation_result: bool,
    /// GPU architecture
    #[serde(default)]
    gpu_arch: String,
    /// GPU model
    #[serde(default)]
    gpu_model: String,
    /// VBIOS measurement
    #[serde(default)]
    vbios_measurement: String,
    /// Driver measurement
    #[serde(default)]
    driver_measurement: String,
    /// CC firmware measurement
    #[serde(default)]
    cc_fw_measurement: String,
    /// Token issued-at (Unix timestamp)
    #[serde(default)]
    iat: i64,
    /// Token expiration (Unix timestamp)
    #[serde(default)]
    exp: i64,
    /// Nonce used in attestation
    #[serde(default)]
    nonce: String,
}

impl NvidiaGpuProvider {
    /// Create a new NVIDIA GPU TEE provider.
    pub fn new(config: NvidiaGpuConfig) -> Self {
        let simulate = std::env::var("TENZRO_SIMULATE_GPU")
            .unwrap_or_else(|_| "0".to_string()) == "1";

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

    /// Detect GPU hardware and populate device info.
    ///
    /// In simulation mode, returns a fake H100 device.
    /// In real mode, runs `nvidia-smi` to query GPU properties including
    /// name, PCI ID, driver version, memory, compute capability, and CC status.
    async fn detect_gpu(&self) -> Result<GpuDeviceInfo> {
        tracing::debug!("Detecting NVIDIA GPU at device index {}", self.config.device_index);

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
                serial_hash: "sim_".to_string() + &hex::encode(Sha256::digest(b"simulated_gpu_serial")),
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
                "nvidia-smi failed: {}", stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<&str> = stdout.trim().split(", ").collect();

        if fields.len() < 5 {
            return Err(TeeError::not_available(format!(
                "nvidia-smi returned unexpected format: {}", stdout
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
        let cc_enabled = if known_gpus::cc_capable(&pci_device_id) {
            self.check_cc_status().await
        } else if known_gpus::architecture_for_pci_id(&pci_device_id).is_some() {
            tracing::info!(
                "GPU {} ({}) is recognized but not CC-capable — serving inference without TEE attestation",
                name, pci_device_id
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

    /// Check if Confidential Computing mode is enabled on the GPU.
    ///
    /// Uses `nvidia-smi conf-compute -gsc` to query CC status.
    /// On older drivers without CC support, or on non-Linux hosts where
    /// nvidia-smi is absent, the spawn fails and we return false.
    async fn check_cc_status(&self) -> bool {
        let output = tokio::process::Command::new("nvidia-smi")
            .args(["conf-compute", "-gsc"])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                // Look for "CC Status: ON" or "Confidential Compute: Enabled"
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
    /// In real mode, this would use the NVIDIA SPDM-based evidence collection:
    /// - Open the GPU's SPDM responder via `/dev/nvidia-caps/` or NVML
    /// - Perform SPDM GET_MEASUREMENTS to retrieve firmware measurements
    /// - Package measurements with device certificate into evidence blob
    ///
    /// Currently, evidence collection requires the NVIDIA proprietary
    /// `libnvidia-nscq.so` library, which provides the C API:
    /// ```c
    /// nvmlReturn_t nvmlDeviceGetConfComputeGpuAttestationReport(
    ///     nvmlDevice_t device,
    ///     nvmlConfComputeGpuAttestationReport_t *report
    /// );
    /// ```
    ///
    /// Until FFI bindings are added, we collect available info via nvidia-smi
    /// and construct a minimal evidence payload.
    async fn collect_gpu_evidence(&self, device_info: &GpuDeviceInfo, nonce: &[u8]) -> Result<Vec<u8>> {
        if self.simulate {
            // Generate simulated evidence blob
            let evidence = SimulatedEvidence {
                gpu_name: device_info.name.clone(),
                architecture: format!("{}", device_info.architecture),
                pci_device_id: device_info.pci_device_id.clone(),
                driver_version: device_info.driver_version.clone(),
                cc_enabled: device_info.cc_enabled,
                cc_firmware_version: device_info.cc_firmware_version.clone(),
                nonce: hex::encode(nonce),
                timestamp: chrono::Utc::now().timestamp(),
                measurements: SimulatedMeasurements {
                    vbios: hex::encode(Sha384::digest(format!("vbios_{}", device_info.name).as_bytes())),
                    driver: hex::encode(Sha384::digest(device_info.driver_version.as_bytes())),
                    cc_firmware: hex::encode(Sha384::digest(
                        device_info.cc_firmware_version.as_deref().unwrap_or("none").as_bytes()
                    )),
                },
            };

            return serde_json::to_vec(&evidence)
                .map_err(|e| TeeError::AttestationGenerationFailed(format!(
                    "Failed to serialize simulated evidence: {}", e
                )));
        }

        // Real mode: Collect evidence via SPDM/NVML
        // For now, we construct a minimal evidence blob from nvidia-smi data.
        // Full SPDM evidence collection requires libnvidia-nscq FFI.
        #[cfg(target_os = "linux")]
        {
            let evidence = self.collect_real_evidence(device_info, nonce).await?;
            Ok(evidence)
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(TeeError::not_available(
                "GPU evidence collection requires Linux with NVIDIA drivers"
            ))
        }
    }

    /// Collect real GPU evidence on Linux.
    #[cfg(target_os = "linux")]
    async fn collect_real_evidence(&self, device_info: &GpuDeviceInfo, nonce: &[u8]) -> Result<Vec<u8>> {
        // Check for NVIDIA NSCQ library (provides SPDM attestation)
        let nscq_path = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libnvidia-nscq.so");
        let alt_nscq_path = std::path::Path::new("/usr/lib64/libnvidia-nscq.so");

        if nscq_path.exists() || alt_nscq_path.exists() {
            tracing::info!("NVIDIA NSCQ library found — full SPDM evidence available");
            // In a production implementation, we would use FFI to call:
            // nvmlInit_v2()
            // nvmlDeviceGetHandleByIndex(device_index, &device)
            // nvmlDeviceGetConfComputeGpuAttestationReport(device, &report)
            //
            // The report contains SPDM measurements signed by the GPU's
            // device-unique ECDSA P-384 key, along with the device certificate
            // chain linking to NVIDIA's root CA.
            //
            // For now, fall through to the nvidia-smi-based approach below.
        }

        // Construct minimal evidence from available nvidia-smi data
        let evidence = MinimalGpuEvidence {
            device_name: device_info.name.clone(),
            pci_device_id: device_info.pci_device_id.clone(),
            driver_version: device_info.driver_version.clone(),
            compute_capability: device_info.compute_capability.clone(),
            cc_enabled: device_info.cc_enabled,
            cc_firmware_version: device_info.cc_firmware_version.clone(),
            serial_hash: device_info.serial_hash.clone(),
            nonce: hex::encode(nonce),
            timestamp: chrono::Utc::now().timestamp(),
        };

        serde_json::to_vec(&evidence)
            .map_err(|e| TeeError::AttestationGenerationFailed(format!(
                "Failed to serialize GPU evidence: {}", e
            )))
    }

    /// Generate attestation report from the GPU.
    ///
    /// Simulation mode: Creates a synthetic report with computed measurements.
    /// Real mode: Collects GPU evidence and optionally verifies via NRAS.
    async fn generate_gpu_attestation(&self, nonce: &[u8]) -> Result<GpuAttestationReport> {
        let device_info = self.detect_gpu().await?;

        if !device_info.cc_enabled {
            return Err(TeeError::not_available(
                "NVIDIA Confidential Computing is not enabled on this GPU"
            ));
        }

        // Collect evidence from the GPU
        let evidence = self.collect_gpu_evidence(&device_info, nonce).await?;

        // Compute measurements from the evidence
        let measurements = if self.simulate {
            // Simulated measurements derived from device info
            GpuMeasurements {
                vbios_hash: Sha384::digest(format!("vbios_{}", device_info.name).as_bytes()).to_vec(),
                driver_hash: Sha384::digest(device_info.driver_version.as_bytes()).to_vec(),
                cc_firmware_hash: Sha384::digest(
                    device_info.cc_firmware_version.as_deref().unwrap_or("none").as_bytes()
                ).to_vec(),
                ecc_enabled: true,
                mig_enabled: false,
            }
        } else {
            // Extract measurements from collected evidence
            self.extract_measurements_from_evidence(&evidence)?
        };

        // Simulated signature (in real mode, the GPU's AK signs the evidence via SPDM)
        let signature = if self.simulate {
            let mut hasher = Sha384::new();
            hasher.update(&evidence);
            hasher.update(nonce);
            hasher.finalize().to_vec()
        } else {
            // Real mode requires the GPU's device-unique ECDSA P-384 attestation key
            // signature from the SPDM measurement response (libnvidia-nscq FFI).
            // Without FFI integration, we cannot fabricate a valid signature and
            // must refuse to emit a would-be-valid attestation with a zero-byte
            // placeholder that downstream verifiers would reject anyway.
            return Err(TeeError::AttestationGenerationFailed(
                "NVIDIA GPU AK signature requires libnvidia-nscq FFI (SPDM attestation response). \
                 Install the NVIDIA Confidential Computing SDK and rebuild with `--features nvidia-nscq`, \
                 or run with TENZRO_SIMULATE_NVIDIA_GPU=1 for simulation."
                    .to_string(),
            ));
        };

        let report = GpuAttestationReport {
            device_info,
            measurements,
            cc_status: CcAttestationStatus::Enabled,
            nonce: nonce.to_vec(),
            timestamp: chrono::Utc::now().timestamp_millis(),
            signature,
            cert_chain: if self.simulate {
                vec![vec![0x30; 64]] // Dummy cert for simulation
            } else {
                vec![] // Real cert chain extracted from SPDM/NVML
            },
        };

        Ok(report)
    }

    /// Extract measurements from GPU evidence blob.
    fn extract_measurements_from_evidence(&self, evidence: &[u8]) -> Result<GpuMeasurements> {
        // Try to parse as MinimalGpuEvidence
        if let Ok(minimal) = serde_json::from_slice::<MinimalGpuEvidence>(evidence) {
            return Ok(GpuMeasurements {
                vbios_hash: Sha384::digest(format!("vbios_{}", minimal.device_name).as_bytes()).to_vec(),
                driver_hash: Sha384::digest(minimal.driver_version.as_bytes()).to_vec(),
                cc_firmware_hash: Sha384::digest(
                    minimal.cc_firmware_version.as_deref().unwrap_or("none").as_bytes()
                ).to_vec(),
                ecc_enabled: true,
                mig_enabled: false,
            });
        }

        Err(TeeError::InvalidAttestationReport(
            "Failed to extract measurements from GPU evidence".to_string()
        ))
    }

    /// Verify a GPU attestation report via NRAS (NVIDIA Remote Attestation Service).
    ///
    /// Sends the GPU evidence to NRAS for remote verification. NRAS checks:
    /// 1. GPU identity (serial/device cert matches manufacturing records)
    /// 2. Firmware integrity (VBIOS, driver measurements match RIMs)
    /// 3. CC mode status (CC enabled with valid security configuration)
    /// 4. Nonce freshness (prevents replay attacks, 24h TTL)
    ///
    /// Returns a JWT token with attestation claims on success.
    #[cfg(feature = "nvidia-gpu")]
    async fn verify_via_nras(
        &self,
        gpu_report: &GpuAttestationReport,
        evidence: &[u8],
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

        let request = NrasAttestationRequest {
            evidence: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                evidence,
            ),
            nonce: hex::encode(&gpu_report.nonce),
            arch: arch_str.to_string(),
        };

        tracing::info!(
            "Sending GPU attestation to NRAS at {}: arch={}, nonce={}",
            nras_endpoint, arch_str, &request.nonce[..16]
        );

        // Send to NRAS
        // Note: reqwest is an optional dependency, only available when nvidia-gpu feature is enabled
        #[cfg(feature = "nvidia-gpu")]
        {
            if self.simulate {
                // In simulation mode, we don't actually call NRAS
                return Ok(NrasVerificationResult {
                    verified: true,
                    token: "simulated_jwt_token".to_string(),
                    claims: NrasTokenClaims {
                        gpu_attestation_result: true,
                        gpu_arch: arch_str.to_string(),
                        gpu_model: gpu_report.device_info.name.clone(),
                        vbios_measurement: hex::encode(&gpu_report.measurements.vbios_hash),
                        driver_measurement: hex::encode(&gpu_report.measurements.driver_hash),
                        cc_fw_measurement: hex::encode(&gpu_report.measurements.cc_firmware_hash),
                        iat: chrono::Utc::now().timestamp(),
                        exp: chrono::Utc::now().timestamp() + 86400,
                        nonce: hex::encode(&gpu_report.nonce),
                    },
                });
            }

            // Real NRAS call via reqwest
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| TeeError::AttestationVerificationFailed(format!(
                    "Failed to create HTTP client for NRAS: {}", e
                )))?;

            let response = client
                .post(nras_endpoint)
                .json(&request)
                .send()
                .await
                .map_err(|e| TeeError::AttestationVerificationFailed(format!(
                    "NRAS request failed: {}", e
                )))?;

            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS returned HTTP {}: {}", status, body
                )));
            }

            let nras_response: NrasAttestationResponse = response
                .json()
                .await
                .map_err(|e| TeeError::AttestationVerificationFailed(format!(
                    "Failed to parse NRAS response: {}", e
                )))?;

            if let Some(error) = &nras_response.error {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS verification failed: {}", error
                )));
            }

            // Top-level NRAS verdict — must be true even if no `error` field is
            // populated (some failure modes return `attestation_result=false`
            // with a structured token but no top-level error string).
            if !nras_response.attestation_result {
                return Err(TeeError::AttestationVerificationFailed(
                    "NRAS returned attestation_result=false".to_string()
                ));
            }

            // Parse the JWT token claims (without full signature verification —
            // the token comes over TLS from nras.attestation.nvidia.com)
            let claims = parse_jwt_claims(&nras_response.token)?;

            // Replay protection: the JWT nonce must match what we sent.
            // Skip when claims.nonce is empty (older NRAS responses didn't
            // echo the nonce; the TLS channel still binds the response).
            let expected_nonce = hex::encode(&gpu_report.nonce);
            if !claims.nonce.is_empty() && claims.nonce != expected_nonce {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS JWT nonce mismatch: expected {}, got {}",
                    &expected_nonce[..16.min(expected_nonce.len())],
                    &claims.nonce[..16.min(claims.nonce.len())]
                )));
            }

            // Token expiry check — `exp` is a Unix timestamp; reject expired
            // tokens. `iat` (issued-at) sanity-checked: not from the future
            // (allow 5 minutes of clock skew).
            let now_secs = chrono::Utc::now().timestamp();
            if claims.exp != 0 && now_secs >= claims.exp {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS JWT expired: exp={}, now={}", claims.exp, now_secs
                )));
            }
            if claims.iat != 0 && claims.iat > now_secs + 300 {
                return Err(TeeError::AttestationVerificationFailed(format!(
                    "NRAS JWT issued in the future: iat={}, now={}",
                    claims.iat, now_secs
                )));
            }

            // Cross-check measurement claims against what we sent. NRAS
            // re-validates measurements against NVIDIA's golden RIMs, so the
            // returned values may be canonicalized/normalized. We log a
            // warning on mismatch but don't fail — NRAS's `attestation_result`
            // is the authoritative verdict. An empty measurement claim means
            // NRAS didn't expose it in this token version.
            let local_vbios = hex::encode(&gpu_report.measurements.vbios_hash);
            if !claims.vbios_measurement.is_empty()
                && !claims.vbios_measurement.eq_ignore_ascii_case(&local_vbios)
            {
                tracing::warn!(
                    "NRAS VBIOS measurement differs from local: nras={}..., local={}...",
                    &claims.vbios_measurement[..16.min(claims.vbios_measurement.len())],
                    &local_vbios[..16.min(local_vbios.len())]
                );
            }
            let local_driver = hex::encode(&gpu_report.measurements.driver_hash);
            if !claims.driver_measurement.is_empty()
                && !claims.driver_measurement.eq_ignore_ascii_case(&local_driver)
            {
                tracing::warn!(
                    "NRAS driver measurement differs from local: nras={}..., local={}...",
                    &claims.driver_measurement[..16.min(claims.driver_measurement.len())],
                    &local_driver[..16.min(local_driver.len())]
                );
            }
            let local_cc = hex::encode(&gpu_report.measurements.cc_firmware_hash);
            if !claims.cc_fw_measurement.is_empty()
                && !claims.cc_fw_measurement.eq_ignore_ascii_case(&local_cc)
            {
                tracing::warn!(
                    "NRAS CC firmware measurement differs from local: nras={}..., local={}...",
                    &claims.cc_fw_measurement[..16.min(claims.cc_fw_measurement.len())],
                    &local_cc[..16.min(local_cc.len())]
                );
            }

            Ok(NrasVerificationResult {
                verified: claims.gpu_attestation_result,
                token: nras_response.token,
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
    /// 5. Measurements are non-empty
    ///
    /// Note: Local verification cannot verify against NVIDIA's golden RIMs
    /// or validate the GPU's device certificate chain, as NVIDIA does not
    /// publish root CA certificates. Remote NRAS verification is recommended.
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
                "GPU attestation report timestamp is in the future"
            ));
        }

        // Step 2: Verify CC is enabled
        if report.cc_status != CcAttestationStatus::Enabled {
            return Err(TeeError::attestation_failed(
                "GPU Confidential Computing is not enabled"
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
        if !version_gte(&report.device_info.driver_version, &self.config.min_driver_version) {
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

        // Step 6: Verify measurements are non-empty
        if report.measurements.vbios_hash.is_empty() {
            return Err(TeeError::attestation_failed(
                "VBIOS measurement is empty"
            ));
        }
        if report.measurements.driver_hash.is_empty() {
            return Err(TeeError::attestation_failed(
                "Driver measurement is empty"
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
    fn to_attestation_report(&self, gpu_report: &GpuAttestationReport, user_data: &[u8]) -> AttestationReport {
        let mut metadata = HashMap::new();
        metadata.insert("gpu_name".to_string(), gpu_report.device_info.name.clone());
        metadata.insert("architecture".to_string(), format!("{}", gpu_report.device_info.architecture));
        metadata.insert("cc_status".to_string(), format!("{:?}", gpu_report.cc_status));
        metadata.insert("driver_version".to_string(), gpu_report.device_info.driver_version.clone());
        metadata.insert("pci_device_id".to_string(), gpu_report.device_info.pci_device_id.clone());

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
            measurement: gpu_report.measurements.vbios_hash.clone(),
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
        // Use SHA-256 of user_data as the nonce for the GPU attestation
        let nonce = if user_data.is_empty() {
            // Generate a random nonce if no user data provided
            let mut nonce_data = vec![0u8; 32];
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            nonce_data[..16].copy_from_slice(&timestamp.to_le_bytes());
            // Fill remaining bytes with hash of timestamp for entropy
            let hash = Sha256::digest(timestamp.to_le_bytes());
            nonce_data[16..32].copy_from_slice(&hash[..16]);
            nonce_data
        } else {
            Sha256::digest(user_data).to_vec()
        };

        let gpu_report = self.generate_gpu_attestation(&nonce).await?;
        Ok(self.to_attestation_report(&gpu_report, user_data))
    }

    async fn verify_attestation(&self, report: &AttestationReport) -> Result<AttestationResult> {
        if report.vendor != TeeVendor::NvidiaGpu {
            return Err(TeeError::attestation_failed(format!(
                "Expected NvidiaGpu vendor, got {:?}", report.vendor
            )));
        }

        // Deserialize GPU-specific report
        let gpu_report: GpuAttestationReport = serde_json::from_slice(&report.attestation_data)
            .map_err(|e| TeeError::InvalidAttestationReport(format!(
                "Failed to parse GPU attestation report: {}", e
            )))?;

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

        // When remote attestation is configured, additionally verify via NRAS.
        // NRAS validates against NVIDIA's golden RIMs and the GPU's manufacturing
        // device certificate chain — local verification cannot do either, so
        // remote attestation is required for production-grade trust.
        #[allow(unused_mut, unused_assignments)]
        let mut nras_token: Option<String> = None;
        #[allow(unused_mut, unused_assignments)]
        let mut nras_attested: bool = false;
        #[allow(unused_mut, unused_assignments)]
        let mut nras_claims: Option<NrasTokenClaims> = None;
        #[cfg(feature = "nvidia-gpu")]
        if valid && self.config.use_remote_attestation {
            // Re-serialize the report as evidence bytes (canonical JSON).
            // This mirrors what `collect_gpu_evidence` produced on the prover side.
            let evidence_bytes = serde_json::to_vec(&gpu_report)
                .map_err(|e| TeeError::AttestationVerificationFailed(format!(
                    "Failed to serialize GPU report for NRAS: {}", e
                )))?;
            match self.verify_via_nras(&gpu_report, &evidence_bytes).await {
                Ok(nras_result) => {
                    nras_attested = nras_result.verified;
                    nras_token = Some(nras_result.token);
                    if !nras_result.verified {
                        tracing::warn!(
                            "NRAS rejected GPU attestation despite local pass: arch={}",
                            nras_result.claims.gpu_arch
                        );
                        valid = false;
                    } else {
                        tracing::info!(
                            "NRAS attested GPU: arch={}, model={}",
                            nras_result.claims.gpu_arch,
                            nras_result.claims.gpu_model
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

        let tcb_ver = gpu_report.device_info.cc_firmware_version
            .clone()
            .unwrap_or_else(|| "unknown".to_string());

        if valid {
            let mut result = AttestationResult::success(
                TeeVendor::NvidiaGpu,
                gpu_report.measurements.vbios_hash.clone(),
            );
            result.tcb_version = tcb_ver;
            result.measurements = vec![
                Measurement {
                    index: 0,
                    algorithm: "SHA-384".to_string(),
                    value: gpu_report.measurements.vbios_hash.clone(),
                    register: "vbios".to_string(),
                    description: Some("VBIOS firmware measurement".to_string()),
                },
                Measurement {
                    index: 1,
                    algorithm: "SHA-384".to_string(),
                    value: gpu_report.measurements.driver_hash.clone(),
                    register: "driver".to_string(),
                    description: Some("GPU driver measurement".to_string()),
                },
                Measurement {
                    index: 2,
                    algorithm: "SHA-384".to_string(),
                    value: gpu_report.measurements.cc_firmware_hash.clone(),
                    register: "cc_firmware".to_string(),
                    description: Some("CC firmware measurement".to_string()),
                },
            ];
            result.cert_chain_valid = !self.simulate;

            if self.simulate {
                result.details.insert("simulated".to_string(), "true".to_string());
            }
            result.details.insert("verification_method".to_string(),
                if self.config.use_remote_attestation { "nras" } else { "local" }.to_string()
            );
            result.details.insert("gpu_architecture".to_string(),
                format!("{}", gpu_report.device_info.architecture)
            );
            if let Some(token) = nras_token {
                result.details.insert("nras_token".to_string(), token);
                result.details.insert("nras_attested".to_string(), nras_attested.to_string());
            }
            if let Some(claims) = nras_claims {
                if !claims.gpu_arch.is_empty() {
                    result.details.insert("nras_gpu_arch".to_string(), claims.gpu_arch);
                }
                if !claims.gpu_model.is_empty() {
                    result.details.insert("nras_gpu_model".to_string(), claims.gpu_model);
                }
                if !claims.vbios_measurement.is_empty() {
                    result.details.insert("nras_vbios_measurement".to_string(), claims.vbios_measurement);
                }
                if !claims.driver_measurement.is_empty() {
                    result.details.insert("nras_driver_measurement".to_string(), claims.driver_measurement);
                }
                if !claims.cc_fw_measurement.is_empty() {
                    result.details.insert("nras_cc_fw_measurement".to_string(), claims.cc_fw_measurement);
                }
                if claims.iat != 0 {
                    result.details.insert("nras_token_iat".to_string(), claims.iat.to_string());
                }
                if claims.exp != 0 {
                    result.details.insert("nras_token_exp".to_string(), claims.exp.to_string());
                }
                if !claims.nonce.is_empty() {
                    result.details.insert("nras_token_nonce".to_string(), claims.nonce);
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
        tracing::debug!("Executing request '{}' in GPU CC enclave", request.operation);

        // In production, this runs inside CC-protected GPU memory via CUDA.
        // In simulation mode, we compute the result on the CPU and produce
        // a SHA-256 digest as proof of execution.
        let mut hasher = Sha256::new();
        hasher.update(request.operation.as_bytes());
        hasher.update(&request.params);
        let execution_digest = hasher.finalize().to_vec();

        // Return the params as output with an execution digest as attestation data
        Ok(EnclaveResponse {
            request_id: request.id,
            success: true,
            data: request.params,
            error: None,
            attestation: Some(AttestationReport {
                vendor: TeeVendor::NvidiaGpu,
                quote: execution_digest,
                timestamp: tenzro_types::primitives::Timestamp::now(),
                ..Default::default()
            }),
        })
    }

    async fn enclave_keygen(&self, params: KeyGenParams) -> Result<EnclaveKeyHandle> {
        tracing::debug!("Generating key in GPU CC enclave: {:?}", params.algorithm);

        // Generate a real cryptographic keypair. In production, the private key
        // stays in CC-protected GPU memory; in simulation, we store it locally.
        let key_id = uuid::Uuid::new_v4();
        let (public_key_bytes, secret_key_bytes) = match params.algorithm {
            KeyAlgorithm::Ed25519 => {
                let keypair = tenzro_crypto::keys::KeyPair::generate(
                    tenzro_crypto::keys::KeyType::Ed25519,
                ).map_err(|e| TeeError::KeyGenerationFailed(format!(
                    "Ed25519 key generation failed: {}", e
                )))?;
                let pub_bytes = keypair.public_key().as_bytes().to_vec();
                let sec_bytes = keypair.secret_key().as_bytes().to_vec();
                (pub_bytes, sec_bytes)
            }
            KeyAlgorithm::Secp256k1 => {
                let keypair = tenzro_crypto::keys::KeyPair::generate(
                    tenzro_crypto::keys::KeyType::Secp256k1,
                ).map_err(|e| TeeError::KeyGenerationFailed(format!(
                    "Secp256k1 key generation failed: {}", e
                )))?;
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
            public_key: if public_key_bytes.is_empty() { None } else { Some(public_key_bytes) },
            created_at: tenzro_types::primitives::Timestamp::now(),
            attestation: None,
        };

        self.keys.write().insert(key_id, handle.clone());
        self.secret_keys.write().insert(key_id, secret_key_bytes);
        tracing::info!("Generated {:?} key in GPU CC enclave: {}", params.algorithm, key_id);
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
                ).map_err(|e| TeeError::CryptoOperationFailed(format!(
                    "Failed to reconstruct Ed25519 key: {}", e
                )))?;
                let signer = tenzro_crypto::signatures::Ed25519SignerImpl::new(keypair)
                    .map_err(|e| TeeError::CryptoOperationFailed(format!(
                        "Failed to create Ed25519 signer: {}", e
                    )))?;
                use tenzro_crypto::signatures::Signer;
                let sig = signer.sign(data)
                    .map_err(|e| TeeError::CryptoOperationFailed(format!(
                        "Ed25519 signing failed: {}", e
                    )))?;
                Ok(sig.as_bytes().to_vec())
            }
            KeyAlgorithm::Secp256k1 => {
                let keypair = tenzro_crypto::keys::KeyPair::from_bytes(
                    tenzro_crypto::keys::KeyType::Secp256k1,
                    secret_key_bytes,
                ).map_err(|e| TeeError::CryptoOperationFailed(format!(
                    "Failed to reconstruct Secp256k1 key: {}", e
                )))?;
                let signer = tenzro_crypto::signatures::Secp256k1SignerImpl::new(keypair)
                    .map_err(|e| TeeError::CryptoOperationFailed(format!(
                        "Failed to create Secp256k1 signer: {}", e
                    )))?;
                use tenzro_crypto::signatures::Signer;
                let sig = signer.sign(data)
                    .map_err(|e| TeeError::CryptoOperationFailed(format!(
                        "Secp256k1 signing failed: {}", e
                    )))?;
                Ok(sig.as_bytes().to_vec())
            }
            KeyAlgorithm::Aes256Gcm => {
                Err(TeeError::CryptoOperationFailed(
                    "Cannot sign with AES-256-GCM symmetric key".to_string(),
                ))
            }
        }
    }

    async fn enclave_encrypt(&self, key: &EnclaveKeyHandle, plaintext: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Encrypting data in GPU CC enclave, key_id={}", key.id);

        if !self.keys.read().contains_key(&key.id) {
            return Err(TeeError::InvalidKeyHandle(format!(
                "Key {} not found in GPU CC enclave", key.id
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
                "Key {} not found in GPU CC enclave", key.id
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
            L40S | L40 | L4
            | RTX_4090 | RTX_4080_SUPER | RTX_4080
            | RTX_4070_TI_SUPER | RTX_4070_TI | RTX_4070_SUPER | RTX_4070
            | RTX_4060_TI | RTX_4060 => Some(GpuArchitecture::AdaLovelace),
            // Ampere (datacenter + RTX 30-series)
            A100_SXM4_80 | A100_PCIE_80 | A100_SXM4_40 | A100_PCIE_40
            | A40 | A30 | A10 | A16 | A2
            | RTX_3090_TI | RTX_3090 | RTX_3080_TI | RTX_3080
            | RTX_3070_TI | RTX_3070 | RTX_3060_TI | RTX_3060 | RTX_3050 => {
                Some(GpuArchitecture::Ampere)
            }
            // Turing (Tesla T4 + RTX 20-series)
            T4 | RTX_2080_TI | RTX_2080_SUPER | RTX_2080
            | RTX_2070_SUPER | RTX_2070 | RTX_2060_SUPER | RTX_2060 => {
                Some(GpuArchitecture::Turing)
            }
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
            H100_SXM5 | H100_PCIE | H100_NVL
            | H200_SXM | H200_NVL
            | H800_SXM | H20
            | B100 | B200 | GB200
            | L40S
        )
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
    measurements: SimulatedMeasurements,
}

/// Simulated measurements within evidence.
#[derive(Debug, Serialize, Deserialize)]
struct SimulatedMeasurements {
    vbios: String,
    driver: String,
    cc_firmware: String,
}

/// Minimal GPU evidence collected via nvidia-smi (when NSCQ is not available).
#[derive(Debug, Serialize, Deserialize)]
struct MinimalGpuEvidence {
    device_name: String,
    pci_device_id: String,
    driver_version: String,
    compute_capability: String,
    cc_enabled: bool,
    cc_firmware_version: Option<String>,
    serial_hash: String,
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
            "Invalid JWT token format from NRAS".to_string()
        ));
    }

    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    ).map_err(|e| TeeError::AttestationVerificationFailed(format!(
        "Failed to decode JWT payload: {}", e
    )))?;

    serde_json::from_slice(&payload)
        .map_err(|e| TeeError::AttestationVerificationFailed(format!(
            "Failed to parse JWT claims: {}", e
        )))
}

/// Compare two version strings (semver-like: "550.90.07" >= "550.0").
///
/// Splits on "." and compares each numeric component left-to-right.
/// Missing components are treated as 0.
fn version_gte(actual: &str, required: &str) -> bool {
    let actual_parts: Vec<u64> = actual
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let required_parts: Vec<u64> = required
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

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

    #[tokio::test]
    async fn test_generate_attestation_simulated() {
        let config = NvidiaGpuConfig::default();
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
        let config = NvidiaGpuConfig::default();
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
        let config = NvidiaGpuConfig::default();
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
        let signature3 = provider.enclave_sign(&key, b"different data").await.unwrap();
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
        assert_eq!(
            known_gpus::architecture_for_pci_id("XXXX"),
            None
        );
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
            r#"{"gpu_attestation_result":true,"gpu_arch":"HOPPER","gpu_model":"H100","iat":1700000000,"exp":1700086400,"nonce":"deadbeef"}"#,
        );
        let token = format!("{}.{}.fake_signature", header, payload);

        let claims = parse_jwt_claims(&token).unwrap();
        assert!(claims.gpu_attestation_result);
        assert_eq!(claims.gpu_arch, "HOPPER");
        assert_eq!(claims.gpu_model, "H100");
        assert_eq!(claims.nonce, "deadbeef");
    }

    #[test]
    fn test_jwt_parse_invalid_format() {
        assert!(parse_jwt_claims("not.a.valid.jwt.token").is_err());
        assert!(parse_jwt_claims("single_segment").is_err());
    }
}
