//! Intel TDX (Trust Domain Extensions) evidence generation.
//!
//! Inside a Trust Domain this provider produces DCAP TD quotes through the
//! kernel's configfs-tsm interface (`/sys/kernel/config/tsm/report`, Linux
//! 6.7+), which hands the TDREPORT to the platform's Quoting Enclave and
//! returns a quote signed by it. The Intel-signed collateral a verifier needs
//! (TCB info, QE identity, PCK and root CRLs, with their issuer chains) is
//! fetched from Intel's Provisioning Certification Service and attached to the
//! report, so verification ([`crate::verify::tdx`]) needs no network access.
//!
//! There is no simulated mode. A host without TDX reports itself unavailable,
//! and every evidence-producing call fails.
//!
//! # Key concepts
//!
//! - **TD Quote v4**: header (48 bytes) + TD report body (584 bytes) + a
//!   signature section holding the attestation key, the QE report and the
//!   PCK certificate chain.
//! - **RTMRs**: four runtime measurement registers (SHA-384).
//! - **REPORT_DATA**: 64 bytes the caller chooses; this is where a verifier's
//!   challenge goes.

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;
use tenzro_types::tee::*;

/// Intel's Provisioning Certification Service base URL.
const PCS_BASE: &str = "https://api.trustedservices.intel.com";

/// How a provider obtains quotes.
#[derive(Clone)]
enum QuoteSource {
    /// configfs-tsm on real TDX hardware.
    Hardware,
    /// Tests only: an unsigned stand-in carrying the report data, which no
    /// verifier accepts.
    #[cfg(test)]
    Unsigned,
}

/// Intel TDX provider.
#[derive(Clone)]
pub struct IntelTdxProvider {
    available: bool,
    source: QuoteSource,
}

impl std::fmt::Debug for IntelTdxProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelTdxProvider")
            .field("available", &self.available)
            .finish_non_exhaustive()
    }
}

impl IntelTdxProvider {
    /// A provider for this host's TDX hardware, if any.
    pub fn new() -> Self {
        Self {
            available: Self::detect_tdx_hardware(),
            source: QuoteSource::Hardware,
        }
    }

    #[cfg(test)]
    fn unsigned_for_tests() -> Self {
        Self {
            available: true,
            source: QuoteSource::Unsigned,
        }
    }

    fn detect_tdx_hardware() -> bool {
        std::path::Path::new("/sys/kernel/config/tsm/report").exists()
            && std::path::Path::new("/dev/tdx_guest").exists()
    }

    /// Generate a quote over `report_data` through configfs-tsm.
    fn generate_quote_configfs(report_data: &[u8; 64]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let dir = format!(
                "/sys/kernel/config/tsm/report/tenzro_{}",
                Uuid::new_v4().as_simple()
            );
            fs::create_dir(&dir).map_err(|e| {
                TeeError::AttestationGenerationFailed(format!("configfs-tsm report entry: {e}"))
            })?;
            let result = fs::write(format!("{dir}/inblob"), report_data)
                .and_then(|_| fs::read(format!("{dir}/outblob")));
            let _ = fs::remove_dir(&dir);
            result.map_err(|e| {
                TeeError::AttestationGenerationFailed(format!("configfs-tsm quote: {e}"))
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = report_data;
            Err(TeeError::not_available("configfs-tsm requires Linux"))
        }
    }

    async fn quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        match self.source {
            QuoteSource::Hardware => Self::generate_quote_configfs(report_data),
            #[cfg(test)]
            QuoteSource::Unsigned => Ok(report_data.to_vec()),
        }
    }
}

/// Fetch the DCAP collateral for `quote` from Intel PCS.
async fn fetch_collateral(quote: &[u8]) -> Result<dcap_qvl::QuoteCollateralV3> {
    let err = |m: String| TeeError::AttestationGenerationFailed(m);
    let parsed = dcap_qvl::quote::Quote::parse(quote).map_err(|e| err(format!("quote: {e}")))?;
    let fmspc = hex::encode_upper(
        dcap_qvl::intel::quote_fmspc(&parsed).map_err(|e| err(format!("FMSPC: {e}")))?,
    );
    let ca = dcap_qvl::intel::quote_ca(&parsed)
        .map_err(|e| err(format!("PCK CA: {e}")))?
        .as_id_str();
    let pck_chain = String::from_utf8_lossy(parsed.inner_cert_data()).to_string();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| err(format!("HTTP client: {e}")))?;
    let get = |url: String| {
        let client = client.clone();
        async move {
            let resp = client
                .get(&url)
                .send()
                .await
                .map_err(|e| err(format!("GET {url}: {e}")))?;
            if !resp.status().is_success() {
                return Err(err(format!("GET {url}: HTTP {}", resp.status())));
            }
            Ok(resp)
        }
    };
    let header = |resp: &reqwest::Response, names: &[&str]| -> Result<String> {
        for n in names {
            if let Some(v) = resp.headers().get(*n).and_then(|v| v.to_str().ok()) {
                return urlencoding_decode(v);
            }
        }
        Err(err(format!("PCS response has no {} header", names[0])))
    };

    let resp = get(format!(
        "{PCS_BASE}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der"
    ))
    .await?;
    let pck_crl_issuer_chain = header(&resp, &["SGX-PCK-CRL-Issuer-Chain"])?;
    let pck_crl = resp.bytes().await.map_err(|e| err(e.to_string()))?.to_vec();

    let resp = get(format!("{PCS_BASE}/tdx/certification/v4/tcb?fmspc={fmspc}")).await?;
    let tcb_info_issuer_chain = header(
        &resp,
        &["TCB-Info-Issuer-Chain", "SGX-TCB-Info-Issuer-Chain"],
    )?;
    let tcb: serde_json::Value = resp.json().await.map_err(|e| err(e.to_string()))?;

    let resp = get(format!("{PCS_BASE}/tdx/certification/v4/qe/identity")).await?;
    let qe_identity_issuer_chain = header(&resp, &["SGX-Enclave-Identity-Issuer-Chain"])?;
    let qe: serde_json::Value = resp.json().await.map_err(|e| err(e.to_string()))?;

    let root_ca_crl = get(crate::certs::INTEL_SGX_ROOT_CA_CRL_URL.to_string())
        .await?
        .bytes()
        .await
        .map_err(|e| err(e.to_string()))?
        .to_vec();

    let signature = |v: &serde_json::Value| -> Result<Vec<u8>> {
        hex::decode(
            v.get("signature")
                .and_then(|s| s.as_str())
                .unwrap_or_default(),
        )
        .map_err(|e| err(format!("PCS signature: {e}")))
    };
    Ok(dcap_qvl::QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info: tcb
            .get("tcbInfo")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        tcb_info_signature: signature(&tcb)?,
        qe_identity_issuer_chain,
        qe_identity: qe
            .get("enclaveIdentity")
            .map(|v| v.to_string())
            .unwrap_or_default(),
        qe_identity_signature: signature(&qe)?,
        pck_certificate_chain: Some(pck_chain),
    })
}

/// Percent-decode an HTTP header value (PCS URL-encodes its PEM chains).
fn urlencoding_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = std::str::from_utf8(&bytes[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or_else(|| {
                    TeeError::AttestationGenerationFailed("bad percent escape".into())
                })?;
            out.push(h);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| TeeError::AttestationGenerationFailed(e.to_string()))
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

    /// `user_data` becomes `REPORT_DATA` after packing
    /// ([`tenzro_types::tee::pack_user_data_for_vendor`]).
    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        let packed = tenzro_types::tee::pack_user_data_for_vendor(TeeVendor::IntelTdx, user_data);
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&packed);
        let attestation_data = self.quote(&report_data).await?;

        let mut metadata = HashMap::new();
        if matches!(self.source, QuoteSource::Hardware) {
            let collateral = fetch_collateral(&attestation_data).await?;
            metadata.insert(
                crate::verify::tdx::COLLATERAL_KEY.to_string(),
                serde_json::to_string(&collateral)
                    .map_err(|e| TeeError::AttestationGenerationFailed(e.to_string()))?,
            );
        }
        let measurement = crate::measurements::tdx_registers(&attestation_data)
            .into_iter()
            .next()
            .map(|mrtd| mrtd.value)
            .unwrap_or_default();
        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::IntelTdx,
            user_data: packed,
            measurement,
            attestation_data,
            timestamp: tenzro_types::Timestamp::now(),
            metadata,
            ..Default::default()
        })
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("Intel TDX not available"));
        }
        // The node process already runs inside the Trust Domain; this call
        // is how a caller gets evidence of that for one result. Fails closed:
        // a caller that requested evidence never receives an unproven result.
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
    async fn off_hardware_nothing_is_produced() {
        let provider = IntelTdxProvider::new();
        if provider.is_available().await.unwrap() {
            return;
        }
        assert!(provider.generate_attestation(b"x").await.is_err());
    }

    #[tokio::test]
    async fn execute_in_enclave_binds_the_response_when_asked() {
        let provider = IntelTdxProvider::unsigned_for_tests();
        let mut request = EnclaveRequest::new("infer".to_string(), b"payload".to_vec());
        request.include_attestation = true;
        let response = provider.execute_in_enclave(request.clone()).await.unwrap();
        let report = response.attestation.expect("attestation was requested");
        let binding = crate::traits::enclave_response_binding(
            &request.id,
            &request.operation,
            &response.data,
        );
        assert!(crate::report_data::user_data_matches(
            TeeVendor::IntelTdx,
            &binding,
            &report.user_data
        ));
    }

    #[tokio::test]
    async fn an_unsigned_quote_never_verifies() {
        let provider = IntelTdxProvider::unsigned_for_tests();
        let report = provider.generate_attestation(b"challenge").await.unwrap();
        let policy = crate::verify::VerifyPolicy::now(report.user_data.clone());
        assert!(crate::verify::verify_report(&report, &policy).is_err());
    }

    #[tokio::test]
    async fn execute_in_enclave_skips_attestation_by_default() {
        let provider = IntelTdxProvider::unsigned_for_tests();
        let request = EnclaveRequest::new("infer".to_string(), b"payload".to_vec());
        assert!(
            provider
                .execute_in_enclave(request)
                .await
                .unwrap()
                .attestation
                .is_none()
        );
    }

    #[test]
    fn enclave_response_binding_separates_its_fields() {
        use crate::traits::enclave_response_binding;
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        let base = enclave_response_binding(&id_a, "infer", b"result");
        assert_ne!(base, enclave_response_binding(&id_b, "infer", b"result"));
        assert_ne!(base, enclave_response_binding(&id_a, "train", b"result"));
        assert_ne!(base, enclave_response_binding(&id_a, "infer", b"other"));
    }

    #[test]
    fn pcs_headers_are_percent_decoded() {
        assert_eq!(
            urlencoding_decode("-----BEGIN%20CERTIFICATE-----%0A").unwrap(),
            "-----BEGIN CERTIFICATE-----\n"
        );
    }
}
