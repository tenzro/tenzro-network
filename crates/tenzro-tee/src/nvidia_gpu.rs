//! NVIDIA GPU confidential-computing evidence, produced as a composite with
//! the CPU confidential VM the GPU is admitted to.
//!
//! A GPU in CC mode does not establish a trust boundary of its own: SEV-SNP or
//! TDX creates the confidential VM, and the GPU joins it over an
//! SPDM-authenticated link. This provider therefore always attests both:
//!
//! 1. the CPU provider quotes over the caller's packet (its report data is
//!    SHA-256 of the packet, twice);
//! 2. the GPU is asked, through NVML, for an SPDM measurement report over the
//!    first 32 bytes of that report data, so both legs answer one challenge;
//! 3. the GPU evidence and its certificate chains are submitted to the NVIDIA
//!    attestation service, whose signed token bundle is attached.
//!
//! Verification ([`crate::verify::nvidia`]) checks the CPU leg in full, the
//! token signatures against a configured key set, the shared nonce, and the
//! per-device claims. There is no simulated mode.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tenzro_types::tee::*;
use uuid::Uuid;

use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;

/// NVIDIA attestation service claims version this provider requests.
const NRAS_CLAIMS_VERSION: &str = "3.0";

/// GPU architecture, as the attestation service names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuArchitecture {
    Hopper,
    Blackwell,
}

impl GpuArchitecture {
    fn nras_name(self) -> &'static str {
        match self {
            Self::Hopper => "HOPPER",
            Self::Blackwell => "BLACKWELL",
        }
    }
}

/// Provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NvidiaGpuConfig {
    /// GPU device index.
    pub device_index: u32,
    /// NVIDIA attestation service endpoint.
    pub nras_endpoint: String,
    /// Architecture of the attested GPU.
    pub architecture: GpuArchitecture,
}

impl Default for NvidiaGpuConfig {
    fn default() -> Self {
        Self {
            device_index: 0,
            nras_endpoint: crate::certs::NVIDIA_NRAS_ENDPOINT.to_string(),
            architecture: GpuArchitecture::Hopper,
        }
    }
}

/// Composite CPU + GPU provider.
pub struct NvidiaGpuProvider {
    config: NvidiaGpuConfig,
    cpu_anchor: Option<Arc<dyn TeeProvider>>,
}

#[derive(Serialize)]
struct NrasEvidenceEntry {
    evidence: String,
    certificate: String,
}

#[derive(Serialize)]
struct NrasRequest {
    nonce: String,
    arch: String,
    evidence_list: Vec<NrasEvidenceEntry>,
    claims_version: String,
}

/// Evidence gathered from the driver for one attestation.
struct GpuEvidence {
    report: Vec<u8>,
    certificate_chain: Vec<u8>,
}

impl NvidiaGpuProvider {
    pub fn new(config: NvidiaGpuConfig) -> Self {
        Self {
            config,
            cpu_anchor: None,
        }
    }

    /// Attach the CPU confidential-VM provider this GPU is admitted to.
    /// Without one the provider refuses to attest.
    pub fn with_cpu_anchor(mut self, anchor: Arc<dyn TeeProvider>) -> Self {
        self.cpu_anchor = Some(anchor);
        self
    }

    fn anchor(&self) -> Result<&Arc<dyn TeeProvider>> {
        self.cpu_anchor.as_ref().ok_or_else(|| {
            TeeError::not_available(
                "a GPU is attested only inside the SEV-SNP or TDX VM it is admitted to, and no \
                 CPU provider is attached",
            )
        })
    }

    /// Ask the driver for an attestation report over `nonce`, refusing any
    /// platform posture that does not enforce confidentiality.
    #[cfg(target_os = "linux")]
    async fn collect(&self, nonce: [u8; crate::NVIDIA_CC_NONCE_LEN]) -> Result<GpuEvidence> {
        let device_index = self.config.device_index;
        tokio::task::spawn_blocking(move || {
            let nvml = crate::nvml::Nvml::open()?;
            let state = nvml.cc_system_state()?;
            if !state.cc_enabled() {
                return Err(TeeError::not_available(
                    "GPU confidential computing is not enabled",
                ));
            }
            if state.dev_tools_on() || !state.production_environment() {
                return Err(TeeError::attestation_failed(
                    "GPU confidential computing is in a development posture",
                ));
            }
            let caps = nvml.cc_capabilities()?;
            if !caps.gpus_cc_capable || !caps.cpu.anchors_cvm() {
                return Err(TeeError::not_available(
                    "no CC-capable GPU admitted to a CPU confidential VM",
                ));
            }
            if !nvml.cc_gpus_ready()? {
                return Err(TeeError::not_available(
                    "GPUs have not completed CC readiness",
                ));
            }
            let device = nvml.device_by_index(device_index)?;
            let evidence = nvml.cc_attestation_report(device, &nonce)?;
            let chains = nvml.cc_certificate_chains(device)?;
            Ok(GpuEvidence {
                report: evidence.report,
                certificate_chain: if chains.attestation_cert_chain.is_empty() {
                    chains.cert_chain
                } else {
                    chains.attestation_cert_chain
                },
            })
        })
        .await
        .map_err(|e| TeeError::AttestationGenerationFailed(format!("GPU evidence task: {e}")))?
    }

    #[cfg(not(target_os = "linux"))]
    async fn collect(&self, _nonce: [u8; crate::NVIDIA_CC_NONCE_LEN]) -> Result<GpuEvidence> {
        Err(TeeError::not_available(
            "GPU evidence requires Linux and the NVIDIA driver",
        ))
    }

    /// Submit GPU evidence to the attestation service and return its token
    /// bundle verbatim.
    async fn attest_remotely(&self, evidence: &GpuEvidence, nonce: &[u8]) -> Result<String> {
        use base64::Engine;
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let request = NrasRequest {
            nonce: hex::encode(nonce),
            arch: self.config.architecture.nras_name().to_string(),
            evidence_list: vec![NrasEvidenceEntry {
                evidence: b64(&evidence.report),
                certificate: b64(&evidence.certificate_chain),
            }],
            claims_version: NRAS_CLAIMS_VERSION.to_string(),
        };
        let err = |m: String| TeeError::AttestationGenerationFailed(m);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| err(format!("HTTP client: {e}")))?;
        let resp = client
            .post(&self.config.nras_endpoint)
            .json(&request)
            .send()
            .await
            .map_err(|e| err(format!("attestation service: {e}")))?;
        if !resp.status().is_success() {
            return Err(err(format!(
                "attestation service returned HTTP {}",
                resp.status()
            )));
        }
        resp.text().await.map_err(|e| err(e.to_string()))
    }
}

#[async_trait]
impl TeeProvider for NvidiaGpuProvider {
    fn vendor(&self) -> TeeVendor {
        TeeVendor::NvidiaGpu
    }

    async fn is_available(&self) -> Result<bool> {
        match &self.cpu_anchor {
            Some(a) => Ok(a.is_available().await? && std::path::Path::new("/dev/nvidia0").exists()),
            None => Ok(false),
        }
    }

    /// Both legs over one challenge derived from `user_data`.
    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        let anchor = self.anchor()?;
        let cpu = anchor.generate_attestation(user_data).await?;
        if cpu.user_data.len() < crate::NVIDIA_CC_NONCE_LEN {
            return Err(TeeError::AttestationGenerationFailed(
                "CPU leg carries no 32-byte challenge".into(),
            ));
        }
        let mut nonce = [0u8; crate::NVIDIA_CC_NONCE_LEN];
        nonce.copy_from_slice(&cpu.user_data[..crate::NVIDIA_CC_NONCE_LEN]);
        let evidence = self.collect(nonce).await?;
        let bundle = self.attest_remotely(&evidence, &nonce).await?;

        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            crate::verify::nvidia::CPU_ANCHOR_KEY.to_string(),
            serde_json::to_string(&cpu)
                .map_err(|e| TeeError::AttestationGenerationFailed(e.to_string()))?,
        );
        metadata.insert(crate::verify::nvidia::NRAS_TOKEN_KEY.to_string(), bundle);
        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::NvidiaGpu,
            user_data: cpu.user_data.clone(),
            attestation_data: evidence.report,
            certificates: vec![evidence.certificate_chain],
            measurement: cpu.measurement.clone(),
            timestamp: tenzro_types::Timestamp::now(),
            metadata,
            ..Default::default()
        })
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        self.anchor()?;
        let data = request.params;
        let attestation = if request.include_attestation {
            let binding =
                crate::traits::enclave_response_binding(&request.id, &request.operation, &data);
            Some(self.generate_attestation(&binding).await?)
        } else {
            None
        };
        Ok(EnclaveResponse {
            request_id: request.id,
            success: true,
            data,
            error: None,
            attestation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_bare_gpu_provider_refuses_to_attest() {
        let provider = NvidiaGpuProvider::new(NvidiaGpuConfig::default());
        assert!(!provider.is_available().await.unwrap());
        assert!(provider.generate_attestation(b"x").await.is_err());
        let request = EnclaveRequest::new("infer".to_string(), b"p".to_vec());
        assert!(provider.execute_in_enclave(request).await.is_err());
    }

    #[test]
    fn architectures_use_the_service_names() {
        assert_eq!(GpuArchitecture::Hopper.nras_name(), "HOPPER");
        assert_eq!(GpuArchitecture::Blackwell.nras_name(), "BLACKWELL");
    }
}
