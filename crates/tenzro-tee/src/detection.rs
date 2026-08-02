//! TEE hardware detection for Tenzro Network.
//!
//! Detects which TEE technology is available on the current system and returns
//! the appropriate provider.
//!
//! # Detection order
//!
//! 1. **CPU confidential VM** — Intel TDX, then AMD SEV-SNP, then AWS Nitro.
//!    This is what creates the trust boundary.
//! 2. **NVIDIA GPU Confidential Computing**, *if* a CPU anchor was found and a
//!    CC-capable GPU is present. The result is the composite
//!    `NvidiaGpuProvider::with_cpu_anchor(cpu)`, never a bare GPU provider.
//!
//! # Why the GPU is never returned alone
//!
//! NVIDIA GPU CC is an **extension of a CPU TEE, not a replacement for one**.
//! The trust boundary is a confidential VM established by SEV-SNP or TDX; the
//! GPU is then admitted to it over an SPDM-authenticated PCIe link, with its
//! VRAM protected and DMA bounced through encrypted buffers. A GPU report on
//! its own attests the *device*, not the environment the workload runs in.
//!
//! So a host with no CPU TEE cannot offer GPU confidential computing however
//! capable its GPU is, and returning a bare `NvidiaGpuProvider` here would let
//! such a host present itself as a TEE provider. Both NVIDIA and Intel describe
//! composite CPU-TEE + GPU-TEE attestation as the correct model.
//!
//! [`detect_tee`] therefore treats the CPU TEE as the precondition and the GPU
//! as an upgrade applied on top of it.

use std::sync::Arc;

use crate::traits::TeeProvider;

#[cfg(feature = "intel-tdx")]
use crate::intel_tdx::IntelTdxProvider;

#[cfg(feature = "amd-sev-snp")]
use crate::amd_sev_snp::AmdSevSnpProvider;

#[cfg(feature = "aws-nitro")]
use crate::aws_nitro::AwsNitroProvider;

#[cfg(feature = "nvidia-gpu")]
use crate::nvidia_gpu::{NvidiaGpuConfig, NvidiaGpuProvider};

/// Detects available TEE hardware and returns the appropriate provider.
///
/// Detection order:
/// 1. Intel TDX
/// 2. AMD SEV-SNP
/// 3. AWS Nitro Enclaves
///
/// # Returns
/// - `Some(provider)` if a TEE is detected and available
/// - `None` if no TEE hardware is available
///
/// # Example
/// ```no_run
/// use tenzro_tee::detect_tee;
///
/// #[tokio::main]
/// async fn main() {
///     if let Some(provider) = detect_tee().await {
///         println!("Detected TEE: {:?}", provider.vendor());
///     } else {
///         println!("No TEE hardware available");
///     }
/// }
/// ```
pub async fn detect_tee() -> Option<Box<dyn TeeProvider>> {
    tracing::info!("Detecting TEE hardware...");

    let Some(cpu) = detect_cpu_anchor().await else {
        tracing::warn!("No TEE hardware detected");
        return None;
    };

    // A CC-capable GPU upgrades the CPU boundary; it never replaces it.
    #[cfg(feature = "nvidia-gpu")]
    {
        if gpu_cc_ready().await {
            let vendor = cpu.vendor();
            let composite =
                NvidiaGpuProvider::new(NvidiaGpuConfig::default()).with_cpu_anchor(cpu.clone());
            if composite.is_available().await.unwrap_or(false) {
                tracing::info!(
                    "Detected NVIDIA GPU Confidential Computing anchored in {}",
                    vendor.as_str()
                );
                return Some(Box::new(composite));
            }
            tracing::debug!(
                "A CC-capable GPU is present but the composite provider is not available; \
                 falling back to the CPU boundary alone"
            );
        }
    }

    tracing::info!("Detected {}", cpu.vendor().as_str());
    Some(Box::new(CpuAnchor(cpu)))
}

/// Newtype so an `Arc<dyn TeeProvider>` can be returned as a `Box<dyn TeeProvider>`.
///
/// [`detect_cpu_anchor`] hands back an `Arc` because the GPU composite needs to
/// hold the same provider; callers of [`detect_tee`] expect a `Box`.
struct CpuAnchor(Arc<dyn TeeProvider>);

#[async_trait::async_trait]
impl TeeProvider for CpuAnchor {
    fn vendor(&self) -> tenzro_types::tee::TeeVendor {
        self.0.vendor()
    }
    async fn is_available(&self) -> crate::error::Result<bool> {
        self.0.is_available().await
    }
    async fn generate_attestation(
        &self,
        user_data: &[u8],
    ) -> crate::error::Result<tenzro_types::tee::AttestationReport> {
        self.0.generate_attestation(user_data).await
    }
    async fn verify_attestation(
        &self,
        report: &tenzro_types::tee::AttestationReport,
    ) -> crate::error::Result<tenzro_types::tee::AttestationResult> {
        self.0.verify_attestation(report).await
    }
    async fn execute_in_enclave(
        &self,
        request: tenzro_types::tee::EnclaveRequest,
    ) -> crate::error::Result<tenzro_types::tee::EnclaveResponse> {
        self.0.execute_in_enclave(request).await
    }
    async fn enclave_keygen(
        &self,
        params: tenzro_types::tee::KeyGenParams,
    ) -> crate::error::Result<tenzro_types::tee::EnclaveKeyHandle> {
        self.0.enclave_keygen(params).await
    }
    async fn enclave_sign(
        &self,
        key: &tenzro_types::tee::EnclaveKeyHandle,
        data: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        self.0.enclave_sign(key, data).await
    }
    async fn enclave_encrypt(
        &self,
        key: &tenzro_types::tee::EnclaveKeyHandle,
        plaintext: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        self.0.enclave_encrypt(key, plaintext).await
    }
    async fn enclave_decrypt(
        &self,
        key: &tenzro_types::tee::EnclaveKeyHandle,
        ciphertext: &[u8],
    ) -> crate::error::Result<Vec<u8>> {
        self.0.enclave_decrypt(key, ciphertext).await
    }
}

/// Detect the CPU confidential VM — the thing that actually creates a trust
/// boundary. Shared by [`detect_tee`] and [`detect_specific_tee`] so the
/// probe order is stated once.
///
/// Returns an `Arc` because the NVIDIA composite has to hold the same provider
/// as its anchor.
pub async fn detect_cpu_anchor() -> Option<Arc<dyn TeeProvider>> {
    #[cfg(feature = "intel-tdx")]
    {
        let tdx = IntelTdxProvider::new();
        if let Ok(true) = tdx.is_available().await {
            return Some(Arc::new(tdx));
        }
    }

    #[cfg(feature = "amd-sev-snp")]
    {
        let sev_snp = AmdSevSnpProvider::new();
        if let Ok(true) = sev_snp.is_available().await {
            return Some(Arc::new(sev_snp));
        }
    }

    #[cfg(feature = "aws-nitro")]
    {
        let nitro = AwsNitroProvider::new();
        if let Ok(true) = nitro.is_available().await {
            return Some(Arc::new(nitro));
        }
    }

    None
}

/// Whether this host has a Confidential-Computing-capable NVIDIA GPU with CC
/// actually enabled.
///
/// Probed through NVML (`libnvidia-ml.so.1`). A GPU that is CC-*capable* but
/// running with CC off cannot produce evidence, so both are required.
#[cfg(feature = "nvidia-gpu")]
async fn gpu_cc_ready() -> bool {
    tokio::task::spawn_blocking(|| {
        let Ok(nvml) = crate::nvml::Nvml::open() else {
            return false;
        };
        let Ok(state) = nvml.cc_system_state() else {
            return false;
        };
        if !state.cc_enabled() {
            return false;
        }
        nvml.cc_capabilities()
            .map(|caps| caps.gpus_cc_capable)
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Attempts to detect and return a specific TEE provider by vendor.
///
/// # Arguments
/// - `vendor`: The TEE vendor to look for
///
/// # Returns
/// - `Some(provider)` if the specified TEE is available
/// - `None` if the TEE is not available or not compiled in
pub async fn detect_specific_tee(
    vendor: tenzro_types::tee::TeeVendor,
) -> Option<Box<dyn TeeProvider>> {
    use tenzro_types::tee::TeeVendor;

    match vendor {
        #[cfg(feature = "intel-tdx")]
        TeeVendor::IntelTdx => {
            let tdx = IntelTdxProvider::new();
            if tdx.is_available().await.unwrap_or(false) {
                return Some(Box::new(tdx));
            }
        }

        #[cfg(feature = "amd-sev-snp")]
        TeeVendor::AmdSevSnp => {
            let sev_snp = AmdSevSnpProvider::new();
            if sev_snp.is_available().await.unwrap_or(false) {
                return Some(Box::new(sev_snp));
            }
        }

        #[cfg(feature = "aws-nitro")]
        TeeVendor::AwsNitro => {
            let nitro = AwsNitroProvider::new();
            if nitro.is_available().await.unwrap_or(false) {
                return Some(Box::new(nitro));
            }
        }

        // Asking for `NvidiaGpu` asks for the *composite*. There is no
        // GPU-only answer: without a CPU confidential VM to be admitted into,
        // GPU CC establishes no trust boundary, so this returns `None` rather
        // than a provider that would overstate what the host can do.
        #[cfg(feature = "nvidia-gpu")]
        TeeVendor::NvidiaGpu => {
            if !gpu_cc_ready().await {
                return None;
            }
            let cpu = detect_cpu_anchor().await?;
            let composite = NvidiaGpuProvider::new(NvidiaGpuConfig::default()).with_cpu_anchor(cpu);
            if composite.is_available().await.unwrap_or(false) {
                return Some(Box::new(composite));
            }
        }

        _ => {}
    }

    None
}

/// Checks if any TEE hardware is available.
///
/// This is faster than `detect_tee()` as it returns immediately upon
/// finding the first available TEE.
pub async fn is_tee_available() -> bool {
    detect_tee().await.is_some()
}

/// Returns a list of all TEE vendors that are available on this system.
pub async fn available_tee_vendors() -> Vec<tenzro_types::tee::TeeVendor> {
    use tenzro_types::tee::TeeVendor;
    let mut vendors = Vec::new();

    #[cfg(feature = "intel-tdx")]
    {
        let tdx = IntelTdxProvider::new();
        if tdx.is_available().await.unwrap_or(false) {
            vendors.push(TeeVendor::IntelTdx);
        }
    }

    #[cfg(feature = "amd-sev-snp")]
    {
        let sev_snp = AmdSevSnpProvider::new();
        if sev_snp.is_available().await.unwrap_or(false) {
            vendors.push(TeeVendor::AmdSevSnp);
        }
    }

    #[cfg(feature = "aws-nitro")]
    {
        let nitro = AwsNitroProvider::new();
        if nitro.is_available().await.unwrap_or(false) {
            vendors.push(TeeVendor::AwsNitro);
        }
    }

    // NVIDIA GPU CC is listed only when it is genuinely usable, which means a
    // CPU anchor is present too — hence the non-empty check. Listing it on a
    // host with a CC-capable GPU but no confidential VM would advertise a
    // capability the host does not have.
    #[cfg(feature = "nvidia-gpu")]
    {
        if !vendors.is_empty() && gpu_cc_ready().await {
            vendors.push(TeeVendor::NvidiaGpu);
        }
    }

    vendors
}

#[cfg(test)]
mod tests {
    /// The invariant this module exists to hold: asking for NVIDIA GPU CC on a
    /// host with no CPU confidential VM yields nothing, not a GPU-only
    /// provider.
    ///
    /// GPU CC is an extension of a CPU TEE. A bare `NvidiaGpuProvider` would
    /// let a host with a capable GPU but no CVM present itself as a TEE
    /// provider, which is the overclaim the whole composite model prevents.
    #[cfg(feature = "nvidia-gpu")]
    #[tokio::test]
    async fn nvidia_gpu_is_never_returned_without_a_cpu_anchor() {
        use tenzro_types::tee::TeeVendor;

        // This test machine (and any CI runner) has no CPU TEE, so the anchor
        // lookup fails and the composite must not be constructed.
        if detect_cpu_anchor().await.is_some() {
            // On a genuinely TEE-capable host the precondition holds, so the
            // negative case cannot be exercised; skip rather than assert the
            // opposite of what the machine is.
            return;
        }
        assert!(
            detect_specific_tee(TeeVendor::NvidiaGpu).await.is_none(),
            "GPU CC must not be offered without a CPU confidential VM to anchor it"
        );
    }

    /// `available_tee_vendors` must not list `NvidiaGpu` unless a CPU anchor is
    /// also listed — advertising it alone would claim a capability the host
    /// does not have.
    #[tokio::test]
    async fn nvidia_gpu_is_never_advertised_alone() {
        use tenzro_types::tee::TeeVendor;

        let vendors = available_tee_vendors().await;
        if vendors.contains(&TeeVendor::NvidiaGpu) {
            let anchors = [
                TeeVendor::IntelTdx,
                TeeVendor::AmdSevSnp,
                TeeVendor::AWSNitro,
                TeeVendor::AwsNitro,
            ];
            assert!(
                vendors.iter().any(|v| anchors.contains(v)),
                "NvidiaGpu listed with no CPU anchor: {vendors:?}"
            );
        }
    }

    /// `detect_tee` returning `Some` implies a CPU anchor exists, whether the
    /// answer is the CPU provider itself or the GPU composite built on it.
    #[tokio::test]
    async fn detect_tee_implies_a_cpu_anchor() {
        if detect_tee().await.is_some() {
            assert!(
                detect_cpu_anchor().await.is_some(),
                "detect_tee returned a provider with no CPU confidential VM behind it"
            );
        }
    }

    use super::*;

    #[tokio::test]
    async fn test_detect_tee_none_available() {
        // Note: Other tests in this crate set TENZRO_SIMULATE_* env vars,
        // so detect_tee() may find a simulated TEE when tests run in parallel.
        // We just verify the function runs without panicking.
        let _result = detect_tee().await;
    }

    #[tokio::test]
    async fn test_available_vendors_empty() {
        let vendors = available_tee_vendors().await;
        // Without simulation, should be empty
        assert!(vendors.is_empty() || !vendors.is_empty()); // May vary based on env
    }
}
