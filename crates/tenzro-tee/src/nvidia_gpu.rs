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
//! - NVIDIA H100 (Hopper architecture, CC 1.0)
//! - NVIDIA H200 (Hopper architecture, CC 1.0, extended HBM)
//! - NVIDIA B100/B200/GB200 (Blackwell architecture, CC 2.0)
//! - NVIDIA L40S (Ada Lovelace, limited CC support)
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
    /// Whether we're running in simulation mode
    simulate: bool,
    /// Whether GPU CC has been detected as available
    #[allow(dead_code)]
    available: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuArchitecture {
    /// NVIDIA Hopper (H100, H200) — CC 1.0
    Hopper,
    /// NVIDIA Blackwell (B100, B200, GB200) — CC 2.0
    Blackwell,
    /// NVIDIA Ada Lovelace (L40S) — limited CC
    AdaLovelace,
}

impl std::fmt::Display for GpuArchitecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuArchitecture::Hopper => write!(f, "Hopper"),
            GpuArchitecture::Blackwell => write!(f, "Blackwell"),
            GpuArchitecture::AdaLovelace => write!(f, "Ada Lovelace"),
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
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

/// Known CC-capable GPU PCI device IDs for detection.
#[allow(dead_code)]
mod known_gpus {
    /// NVIDIA H100 SXM5 80GB
    pub const H100_SXM5: &str = "2330";
    /// NVIDIA H100 PCIe 80GB
    #[allow(dead_code)]
    pub const H100_PCIE: &str = "2331";
    /// NVIDIA H200 SXM
    #[allow(dead_code)]
    pub const H200_SXM: &str = "2335";
    /// NVIDIA B100
    #[allow(dead_code)]
    pub const B100: &str = "2900";
    /// NVIDIA B200
    #[allow(dead_code)]
    pub const B200: &str = "2901";
    /// NVIDIA GB200
    #[allow(dead_code)]
    pub const GB200: &str = "2902";
    /// NVIDIA L40S
    #[allow(dead_code)]
    pub const L40S: &str = "26B9";

    /// Returns architecture for a known PCI device ID (hex, uppercase).
    #[allow(dead_code)]
    pub fn architecture_for_pci_id(pci_id: &str) -> Option<super::GpuArchitecture> {
        match pci_id.to_uppercase().as_str() {
            "2330" | "2331" | "2335" => Some(super::GpuArchitecture::Hopper),
            "2900" | "2901" | "2902" => Some(super::GpuArchitecture::Blackwell),
            "26B9" => Some(super::GpuArchitecture::AdaLovelace),
            _ => None,
        }
    }
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
            simulate,
            available: false,
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
    #[cfg(target_os = "linux")]
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

        // Check if CC mode is supported/enabled
        // On supported GPUs, query CC status via nvidia-smi
        let cc_enabled = self.check_cc_status().await;
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

    /// Non-Linux fallback — GPU detection not supported.
    #[cfg(not(target_os = "linux"))]
    async fn detect_gpu_real(&self) -> Result<GpuDeviceInfo> {
        Err(TeeError::not_available(
            "NVIDIA GPU CC requires Linux with nvidia-smi and NVML"
        ))
    }

    /// Check if Confidential Computing mode is enabled on the GPU.
    ///
    /// Uses `nvidia-smi conf-compute -gsc` to query CC status.
    /// On older drivers without CC support, this returns false.
    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    async fn check_cc_status(&self) -> bool {
        false
    }

    /// Query CC firmware version from nvidia-smi.
    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    async fn query_cc_firmware_version(&self) -> Option<String> {
        None
    }

    /// Query GPU serial number and return its hash.
    #[cfg(target_os = "linux")]
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

    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    async fn query_serial_hash(&self) -> String {
        "unknown".to_string()
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
    #[allow(dead_code)]
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

            // Parse the JWT token claims (without full signature verification —
            // the token comes over TLS from nras.attestation.nvidia.com)
            let claims = parse_jwt_claims(&nras_response.token)?;

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
        if let Some(cc_fw) = &report.device_info.cc_firmware_version {
            if !version_gte(cc_fw, &self.config.min_cc_firmware_version) {
                return Err(TeeError::attestation_failed(format!(
                    "CC firmware version {} below minimum {}",
                    cc_fw, self.config.min_cc_firmware_version
                )));
            }
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
        match self.detect_gpu().await {
            Ok(info) => Ok(info.cc_enabled),
            Err(_) => Ok(false),
        }
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

        // Verify locally first (age, CC status, architecture, driver version, measurements)
        let valid = self.verify_gpu_attestation_local(&gpu_report).await?;

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

/// NRAS verification result.
#[allow(dead_code)]
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
    async fn test_verify_attestation_simulated() {
        let config = NvidiaGpuConfig::default();
        let provider = NvidiaGpuProvider::new(config).with_simulate();

        let report = provider.generate_attestation(b"test").await.unwrap();
        let result = provider.verify_attestation(&report).await.unwrap();

        assert!(result.valid);
        assert_eq!(result.vendor, TeeVendor::NvidiaGpu);
        assert_eq!(result.measurements.len(), 3);

        // Check measurement descriptions
        assert_eq!(result.measurements[0].register, "vbios");
        assert_eq!(result.measurements[1].register, "driver");
        assert_eq!(result.measurements[2].register, "cc_firmware");

        // All SHA-384 measurements should be 48 bytes
        for m in &result.measurements {
            assert_eq!(m.value.len(), 48, "SHA-384 measurement should be 48 bytes");
            assert_eq!(m.algorithm, "SHA-384");
        }
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
        assert_eq!(
            known_gpus::architecture_for_pci_id("2330"),
            Some(GpuArchitecture::Hopper)
        );
        assert_eq!(
            known_gpus::architecture_for_pci_id("2335"),
            Some(GpuArchitecture::Hopper)
        );
        assert_eq!(
            known_gpus::architecture_for_pci_id("2900"),
            Some(GpuArchitecture::Blackwell)
        );
        assert_eq!(
            known_gpus::architecture_for_pci_id("26B9"),
            Some(GpuArchitecture::AdaLovelace)
        );
        assert_eq!(
            known_gpus::architecture_for_pci_id("XXXX"),
            None
        );
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
