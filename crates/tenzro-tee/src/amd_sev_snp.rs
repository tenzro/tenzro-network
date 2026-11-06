//! AMD SEV-SNP evidence generation.
//!
//! Inside an SNP guest this provider asks the AMD secure processor for an
//! attestation report through `/dev/sev-guest` (`SNP_GET_REPORT`, at VMPL 0),
//! then fetches the chip's VCEK and the product's ASK from AMD's Key
//! Distribution Service and attaches them, so verification
//! ([`crate::verify::snp`]) needs no network access. The ARK is never taken
//! from the evidence; the verifier pins it.
//!
//! There is no simulated mode. A host without SEV-SNP reports itself
//! unavailable, and every evidence-producing call fails.
//!
//! # Report structure (1184 bytes)
//!
//! Body 0x000-0x29F (signed): version, guest SVN, policy, family and image
//! ids, VMPL, signature algorithm, platform version and info, `REPORT_DATA`
//! (64 bytes at 0x050), `MEASUREMENT` (48 bytes at 0x090), host data, key
//! digests, report ids, `REPORTED_TCB` (0x180), `CHIP_ID` (64 bytes at
//! 0x1A0). Signature at 0x2A0: little-endian P-384 r and s in 72-byte fields.

use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{Result, TeeError};
use crate::traits::TeeProvider;
use tenzro_types::tee::*;

#[cfg(target_os = "linux")]
const SEV_IOCTL_MAGIC: u8 = b'S';
#[cfg(target_os = "linux")]
const SNP_GET_REPORT_NR: u8 = 0;

const SNP_REPORT_SIZE: usize = 1184;
const OFF_REPORTED_TCB: usize = 0x180;
const OFF_CHIP_ID: usize = 0x1A0;

#[derive(Clone)]
enum ReportSource {
    Hardware,
    /// Tests only: an unsigned report layout that no verifier accepts.
    #[cfg(test)]
    Unsigned,
}

/// AMD SEV-SNP provider.
#[derive(Clone)]
pub struct AmdSevSnpProvider {
    available: bool,
    source: ReportSource,
}

impl std::fmt::Debug for AmdSevSnpProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AmdSevSnpProvider")
            .field("available", &self.available)
            .finish_non_exhaustive()
    }
}

impl AmdSevSnpProvider {
    /// A provider for this host's SEV-SNP hardware, if any.
    pub fn new() -> Self {
        Self {
            available: std::path::Path::new("/dev/sev-guest").exists(),
            source: ReportSource::Hardware,
        }
    }

    #[cfg(test)]
    fn unsigned_for_tests() -> Self {
        Self {
            available: true,
            source: ReportSource::Unsigned,
        }
    }

    /// `SNP_GET_REPORT` at VMPL 0 over `report_data`.
    fn get_report(report_data: &[u8; 64]) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        {
            use std::fs::OpenOptions;
            use std::os::unix::io::AsRawFd;

            // snp_report_req: user_data[64], vmpl u32 = 0, reserved[28].
            let mut req = [0u8; 96];
            req[..64].copy_from_slice(report_data);
            // snp_report_resp: 4000 bytes; a 32-byte header then the report.
            let mut resp = vec![0u8; 4000];
            // snp_guest_request_ioctl: msg_version, req ptr, resp ptr, exitinfo2.
            let mut ioctl_buf = [0u8; 32];
            ioctl_buf[0] = 1;
            ioctl_buf[8..16].copy_from_slice(&(req.as_ptr() as u64).to_ne_bytes());
            ioctl_buf[16..24].copy_from_slice(&(resp.as_mut_ptr() as u64).to_ne_bytes());
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/sev-guest")
                .map_err(|e| {
                    TeeError::AttestationGenerationFailed(format!("open /dev/sev-guest: {e}"))
                })?;
            let nr = (3u32 << 30)
                | (32 << 16)
                | ((SEV_IOCTL_MAGIC as u32) << 8)
                | SNP_GET_REPORT_NR as u32;
            // SAFETY: `ioctl_buf` holds valid pointers to `req` and `resp`,
            // both alive and sized as the kernel ABI requires for the call.
            let ret = unsafe {
                libc::ioctl(
                    file.as_raw_fd(),
                    nr as libc::c_ulong,
                    ioctl_buf.as_mut_ptr(),
                )
            };
            if ret != 0 {
                let fw = u32::from_le_bytes(ioctl_buf[24..28].try_into().unwrap());
                return Err(TeeError::AttestationGenerationFailed(format!(
                    "SNP_GET_REPORT failed: {} (fw_error 0x{fw:X})",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(resp[32..32 + SNP_REPORT_SIZE].to_vec())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = report_data;
            Err(TeeError::not_available("AMD SEV-SNP requires Linux"))
        }
    }

    /// Fetch `[VCEK, ASK]` for this report from AMD KDS.
    async fn fetch_chain(report: &[u8]) -> Result<Vec<Vec<u8>>> {
        let err = |m: String| TeeError::AttestationGenerationFailed(m);
        let chip = hex::encode(&report[OFF_CHIP_ID..OFF_CHIP_ID + 64]);
        let tcb = &report[OFF_REPORTED_TCB..OFF_REPORTED_TCB + 8];
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| err(format!("HTTP client: {e}")))?;
        for product in ["Milan", "Genoa"] {
            let url = format!(
                "{}/vcek/v1/{product}/{chip}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
                crate::certs::AMD_KDS_BASE_URL,
                tcb[0],
                tcb[1],
                tcb[6],
                tcb[7]
            );
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            if !resp.status().is_success() {
                continue;
            }
            let vcek = resp.bytes().await.map_err(|e| err(e.to_string()))?.to_vec();
            let chain_url = format!(
                "{}/vcek/v1/{product}/cert_chain",
                crate::certs::AMD_KDS_BASE_URL
            );
            let pem = client
                .get(&chain_url)
                .send()
                .await
                .map_err(|e| err(format!("GET {chain_url}: {e}")))?
                .text()
                .await
                .map_err(|e| err(e.to_string()))?;
            // cert_chain is ASK then ARK; the ARK is pinned by the verifier.
            let ask = crate::x509::parse_pem_chain(&pem)
                .map_err(|e| err(e.to_string()))?
                .into_iter()
                .next()
                .ok_or_else(|| err("AMD KDS returned an empty chain".into()))?;
            return Ok(vec![vcek, ask.der]);
        }
        Err(err(format!("AMD KDS has no VCEK for chip {chip}")))
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

    /// `user_data` becomes `REPORT_DATA` after packing
    /// ([`tenzro_types::tee::pack_user_data_for_vendor`]).
    async fn generate_attestation(&self, user_data: &[u8]) -> Result<AttestationReport> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
        let packed = tenzro_types::tee::pack_user_data_for_vendor(TeeVendor::AmdSevSnp, user_data);
        let mut report_data = [0u8; 64];
        report_data.copy_from_slice(&packed);
        let (attestation_data, certificates) = match self.source {
            ReportSource::Hardware => {
                let r = Self::get_report(&report_data)?;
                let chain = Self::fetch_chain(&r).await?;
                (r, chain)
            }
            #[cfg(test)]
            ReportSource::Unsigned => {
                let mut r = vec![0u8; SNP_REPORT_SIZE];
                r[0x50..0x90].copy_from_slice(&report_data);
                (r, Vec::new())
            }
        };
        Ok(AttestationReport {
            id: Uuid::new_v4(),
            vendor: TeeVendor::AmdSevSnp,
            user_data: packed,
            measurement: attestation_data[0x90..0xC0].to_vec(),
            attestation_data,
            certificates,
            timestamp: tenzro_types::Timestamp::now(),
            metadata: HashMap::new(),
            ..Default::default()
        })
    }

    async fn execute_in_enclave(&self, request: EnclaveRequest) -> Result<EnclaveResponse> {
        if !self.available {
            return Err(TeeError::not_available("AMD SEV-SNP not available"));
        }
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
        let provider = AmdSevSnpProvider::new();
        if provider.is_available().await.unwrap() {
            return;
        }
        assert!(provider.generate_attestation(b"x").await.is_err());
    }

    #[tokio::test]
    async fn an_unsigned_report_never_verifies() {
        let provider = AmdSevSnpProvider::unsigned_for_tests();
        let report = provider.generate_attestation(b"challenge").await.unwrap();
        let policy = crate::verify::VerifyPolicy::now(report.user_data.clone());
        assert!(crate::verify::verify_report(&report, &policy).is_err());
    }

    #[tokio::test]
    async fn the_report_carries_the_packed_challenge() {
        let provider = AmdSevSnpProvider::unsigned_for_tests();
        let report = provider.generate_attestation(b"challenge").await.unwrap();
        assert!(crate::report_data::user_data_matches(
            TeeVendor::AmdSevSnp,
            b"challenge",
            &report.attestation_data[0x50..0x90]
        ));
    }
}
