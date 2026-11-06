//! This machine's proof, every reward epoch, that it still holds the TPM its
//! hardware level rests on (see `tenzro_vm::native::hardware_level`).
//!
//! Once the randomness beacon has taken its first value of the epoch, the
//! epoch's possession challenge is known. The TPM's attestation key quotes
//! it and the quote is sent as a `HardwareProof` from the node's account,
//! whose identity is the machine. A machine that sends none, or whose quote
//! is refused, is level 0 at the epoch's close.
//!
//! A machine with an NVIDIA GPU also answers the epoch's GPU challenge, drawn
//! from the possession challenge: NVML asks the GPU for an SPDM measurement
//! report over it, sent with the GPU's certificate chain as a `HardwareProof`.
//! Beside the TPM's quote it is the second hardware scheme of level 3.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tenzro_types::hardware_level::{HardwareProofOp, gpu_challenge};
use tenzro_vm::native::hardware_level::{
    GAS_HARDWARE_PROOF, current_challenge, read_gpu, read_possession,
};
use tracing::{debug, info};

use crate::node::TenzroNode;

/// How often the node looks for a challenge it has not answered.
const TICK: Duration = Duration::from_secs(60);
/// How long a sent proof is left to land before it is sent again.
const RESEND_AFTER: Duration = Duration::from_secs(600);

/// Quote this epoch's challenge and send it, when the node's account is a
/// machine identity that has not yet answered it. Returns the epoch proven.
async fn prove_once(
    node: &Arc<TenzroNode>,
    sent: Option<(u64, Instant)>,
) -> Result<Option<u64>, String> {
    let Some(submitter) = node.ledger_submitter() else {
        return Ok(None);
    };
    let account = submitter.address();
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    let Some(did) = tenzro_vm::native::identity_of_wallet(&chain, account.as_bytes()) else {
        return Ok(None);
    };
    let Some((epoch, _, challenge)) = current_challenge(&chain, &did) else {
        return Ok(None);
    };
    if read_possession(&chain, &did).is_some_and(|p| p.epoch == epoch) {
        return Ok(None);
    }
    if sent.is_some_and(|(e, at)| e == epoch && at.elapsed() < RESEND_AFTER) {
        return Ok(None);
    }
    let (quoting, evidence) = quote(challenge).await?;
    if quoting != did {
        return Err(format!(
            "this machine's TPM roots {quoting}, not the account's identity {did}"
        ));
    }
    let op = HardwareProofOp::Possession {
        epoch,
        quote: evidence.quote,
        signature: evidence.quote_signature,
    };
    crate::rpc::submit_as_validator(
        node,
        tenzro_types::TransactionType::HardwareProof { op },
        GAS_HARDWARE_PROOF * 2,
    )
    .await
    .map_err(|e| e.message)?;
    Ok(Some(epoch))
}

/// The GPU proof of `epoch` from NVML's `report` over `nonce` and the chain
/// of the key that signed it, refused before sending when the report answers
/// another nonce or is not shaped as the chain admits.
pub(crate) fn gpu_proof(
    epoch: u64,
    nonce: &[u8; 32],
    report: Vec<u8>,
    chain: Vec<u8>,
) -> Result<HardwareProofOp, String> {
    if report.get(4..36) != Some(&nonce[..]) {
        return Err("NVML returned a report over another nonce".into());
    }
    let op = HardwareProofOp::GpuDevice {
        epoch,
        report,
        chain,
    };
    op.validate()?;
    Ok(op)
}

/// Have this machine's GPU sign this epoch's GPU challenge and send it, when
/// the node's account is a machine identity whose GPU has not answered it.
/// Returns the epoch proven.
async fn prove_gpu_once(
    node: &Arc<TenzroNode>,
    sent: Option<(u64, Instant)>,
) -> Result<Option<u64>, String> {
    let Some(submitter) = node.ledger_submitter() else {
        return Ok(None);
    };
    let account = submitter.address();
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    let Some(did) = tenzro_vm::native::identity_of_wallet(&chain, account.as_bytes()) else {
        return Ok(None);
    };
    let Some((epoch, _, possession)) = current_challenge(&chain, &did) else {
        return Ok(None);
    };
    if read_gpu(&chain, &did).is_some_and(|g| g.epoch == epoch) {
        return Ok(None);
    }
    if sent.is_some_and(|(e, at)| e == epoch && at.elapsed() < RESEND_AFTER) {
        return Ok(None);
    }
    let nonce = gpu_challenge(&possession);
    let (report, certs) = gpu_report(nonce).await?;
    let op = gpu_proof(epoch, &nonce, report, certs)?;
    crate::rpc::submit_as_validator(
        node,
        tenzro_types::TransactionType::HardwareProof { op },
        GAS_HARDWARE_PROOF * 2,
    )
    .await
    .map_err(|e| e.message)?;
    Ok(Some(epoch))
}

#[cfg(target_os = "linux")]
async fn gpu_report(nonce: [u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
    tokio::task::spawn_blocking(move || tenzro_tee::nvidia_device::collect_local(&nonce))
        .await
        .map_err(|e| format!("GPU report task failed: {e}"))?
        .map_err(|e| format!("GPU report: {e}"))
}

#[cfg(not(target_os = "linux"))]
async fn gpu_report(_nonce: [u8; 32]) -> Result<(Vec<u8>, Vec<u8>), String> {
    Err("GPU reports are collected through NVML, which this node reads on Linux only".into())
}

#[cfg(any(target_os = "linux", windows))]
async fn quote(
    challenge: [u8; 32],
) -> Result<(String, tenzro_tee::tpm_attest::TpmEvidence), String> {
    tokio::task::spawn_blocking(move || tenzro_tee::tpm_attest::quote_local_machine(&challenge))
        .await
        .map_err(|e| format!("TPM quote task failed: {e}"))?
        .map_err(|e| format!("TPM quote failed: {e}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn quote(
    _challenge: [u8; 32],
) -> Result<(String, tenzro_tee::tpm_attest::TpmEvidence), String> {
    Err(
        "possession is quoted by a TPM 2.0 resource manager, which this platform has none of"
            .into(),
    )
}

/// Answer each reward epoch's possession challenge while this node's account
/// is a TPM-attested machine.
pub fn spawn(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let mut sent: Option<(u64, Instant)> = None;
        let mut gpu_sent: Option<(u64, Instant)> = None;
        loop {
            match prove_once(&node, sent).await {
                Ok(Some(epoch)) => {
                    sent = Some((epoch, Instant::now()));
                    info!(target: "hardware", epoch, "sent this epoch's TPM possession quote");
                }
                Ok(None) => {}
                Err(e) => debug!(target: "hardware", error = %e, "no possession quote this round"),
            }
            match prove_gpu_once(&node, gpu_sent).await {
                Ok(Some(epoch)) => {
                    gpu_sent = Some((epoch, Instant::now()));
                    info!(target: "hardware", epoch, "sent this epoch's GPU report");
                }
                Ok(None) => {}
                Err(e) => debug!(target: "hardware", error = %e, "no GPU report this round"),
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_tee::nvidia_device::testgpu::SoftGpu;

    /// The report NVML returns over the epoch's GPU challenge becomes the
    /// proof the chain verifies; one over another nonce, or without its
    /// chain, is not sent.
    #[test]
    fn the_gpu_proof_carries_the_report_over_the_challenge_and_its_chain() {
        let gpu = SoftGpu::new(0x61, 0x60);
        let nonce = gpu_challenge(&[9; 32]);
        let op = gpu_proof(4, &nonce, gpu.report(&nonce), gpu.chain.clone()).unwrap();
        let HardwareProofOp::GpuDevice {
            epoch,
            report,
            chain,
        } = &op
        else {
            panic!("{op:?}");
        };
        assert_eq!(*epoch, 4);
        let roots = tenzro_tee::x509::parse_pem_chain(&gpu.root_pem).unwrap();
        let certs = tenzro_tee::nvidia_device::parse_chain(chain).unwrap();
        tenzro_tee::nvidia_device::verify_device_report(
            report,
            &certs,
            &roots,
            1_792_886_400,
            &nonce,
        )
        .unwrap();
        assert!(gpu_proof(4, &nonce, gpu.report(&[9; 32]), gpu.chain.clone()).is_err());
        assert!(gpu_proof(4, &nonce, gpu.report(&nonce), Vec::new()).is_err());
    }
}
