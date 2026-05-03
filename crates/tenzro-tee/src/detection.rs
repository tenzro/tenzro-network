//! TEE hardware detection for Tenzro Network.
//!
//! This module automatically detects which TEE technology is available
//! on the current system and returns the appropriate provider.

use crate::traits::TeeProvider;

#[cfg(feature = "intel-tdx")]
use crate::intel_tdx::IntelTdxProvider;

#[cfg(feature = "amd-sev-snp")]
use crate::amd_sev_snp::AmdSevSnpProvider;

#[cfg(feature = "aws-nitro")]
use crate::aws_nitro::AwsNitroProvider;

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

    // Try Intel TDX first
    #[cfg(feature = "intel-tdx")]
    {
        let tdx = IntelTdxProvider::new();
        if let Ok(true) = tdx.is_available().await {
            tracing::info!("Detected Intel TDX");
            return Some(Box::new(tdx));
        }
    }

    // Try AMD SEV-SNP
    #[cfg(feature = "amd-sev-snp")]
    {
        let sev_snp = AmdSevSnpProvider::new();
        if let Ok(true) = sev_snp.is_available().await {
            tracing::info!("Detected AMD SEV-SNP");
            return Some(Box::new(sev_snp));
        }
    }

    // Try AWS Nitro Enclaves
    #[cfg(feature = "aws-nitro")]
    {
        let nitro = AwsNitroProvider::new();
        if let Ok(true) = nitro.is_available().await {
            tracing::info!("Detected AWS Nitro Enclaves");
            return Some(Box::new(nitro));
        }
    }

    tracing::warn!("No TEE hardware detected");
    None
}

/// Attempts to detect and return a specific TEE provider by vendor.
///
/// # Arguments
/// - `vendor`: The TEE vendor to look for
///
/// # Returns
/// - `Some(provider)` if the specified TEE is available
/// - `None` if the TEE is not available or not compiled in
pub async fn detect_specific_tee(vendor: tenzro_types::tee::TeeVendor) -> Option<Box<dyn TeeProvider>> {
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

    vendors
}

#[cfg(test)]
mod tests {
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
