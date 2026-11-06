//! Revocation of the certificates behind a GPU proof, asked of an OCSP
//! responder (NVIDIA's by default) before the proof enters this node's pool,
//! when the operator turns it on (`[gpu_revocation]`).
//!
//! The chain verifies a GPU proof offline and never asks: an online answer
//! cannot be part of what every node agrees on. A node that asks keeps a
//! proof out of its own pool, and so out of the blocks it proposes, when a
//! certificate in it is revoked, unknown to the responder, or cannot be
//! checked at all.

use std::time::Duration;

use tenzro_tee::{nvidia_device, ocsp};
use tenzro_types::TransactionType;
use tenzro_types::hardware_level::HardwareProofOp;

use crate::config::GpuRevocationConfig;

/// The certificate chains the GPU proofs in `tx` carry, each whole: one
/// for a GPU proof, one per GPU for a fleet proof, none otherwise.
pub fn gpu_chains(tx: &TransactionType) -> Vec<Vec<u8>> {
    match tx {
        TransactionType::HardwareProof {
            op: HardwareProofOp::GpuDevice { chain, .. },
        } => vec![chain.clone()],
        TransactionType::HardwareProof {
            op: HardwareProofOp::Fleet { issuers, units },
        } => units
            .iter()
            .flat_map(|u| u.hosts())
            .flat_map(|h| h.gpus.iter())
            .map(|g| [g.chain.as_slice(), issuers].concat())
            .collect(),
        _ => Vec::new(),
    }
}

/// Ask `config`'s responder about each certificate of `chain_der` (alias
/// first) from the device identity certificate up to the one below the
/// root, at unix time `now`. The alias certificate is made on the device for
/// its own firmware and is known to no responder, so it is not asked about.
pub async fn check_chain(
    config: &GpuRevocationConfig,
    http: &reqwest::Client,
    chain_der: &[u8],
    now: u64,
) -> Result<(), String> {
    let certs = nvidia_device::parse_chain(chain_der).map_err(|e| e.to_string())?;
    if certs.len() < 3 {
        return Err(
            "the chain carries no device identity certificate with its issuer to ask about".into(),
        );
    }
    for pair in certs[1..].windows(2) {
        let (cert, issuer) = (&pair[0], &pair[1]);
        let nonce: [u8; 32] = rand::random();
        let body = ocsp::request(cert, issuer, &nonce).map_err(|e| e.to_string())?;
        let answer = http
            .post(&config.ocsp_url)
            .header(reqwest::header::CONTENT_TYPE, "application/ocsp-request")
            .timeout(Duration::from_secs(config.timeout_secs))
            .body(body)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("the OCSP responder: {e}"))?
            .bytes()
            .await
            .map_err(|e| format!("the OCSP responder: {e}"))?;
        ocsp::check_response(&answer, cert, issuer, &nonce, now).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_tee::nvidia_device::testgpu::SoftGpu;

    #[test]
    fn asking_is_off_by_default_and_named_in_its_own_table() {
        let config = GpuRevocationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.ocsp_url, "https://ocsp.ndis.nvidia.com/");
        let on: crate::config::NodeConfig =
            toml::from_str("[gpu_revocation]\nenabled = true\n").unwrap();
        assert!(on.gpu_revocation.enabled);
        assert_eq!(on.gpu_revocation.timeout_secs, config.timeout_secs);
    }

    #[test]
    fn only_a_gpu_proof_carries_a_chain_to_ask_about() {
        let gpu = SoftGpu::new(0x31, 0x30);
        let tx = TransactionType::HardwareProof {
            op: HardwareProofOp::GpuDevice {
                epoch: 0,
                report: gpu.report(&[1; 32]),
                chain: gpu.chain.clone(),
            },
        };
        assert_eq!(gpu_chains(&tx), vec![gpu.chain.clone()]);
        assert!(gpu_chains(&TransactionType::Transfer { amount: 1 }).is_empty());
    }

    /// No answer is a refusal: an unreachable responder, or a chain with no
    /// device certificate to ask about, never lets a proof through.
    #[tokio::test]
    async fn a_proof_that_cannot_be_checked_is_refused() {
        let gpu = SoftGpu::new(0x41, 0x40);
        let config = GpuRevocationConfig {
            enabled: true,
            ocsp_url: "http://127.0.0.1:9/".into(),
            timeout_secs: 2,
        };
        let http = reqwest::Client::new();
        let err = check_chain(&config, &http, &gpu.chain, 1_792_886_400)
            .await
            .unwrap_err();
        assert!(err.contains("OCSP responder"), "{err}");
        let certs = nvidia_device::parse_chain(&gpu.chain).unwrap();
        let short: Vec<u8> = certs[..2].iter().flat_map(|c| c.der.clone()).collect();
        assert!(
            check_chain(&config, &http, &short, 1_792_886_400)
                .await
                .is_err()
        );
    }
}
