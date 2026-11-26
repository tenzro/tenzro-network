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

use tenzro_types::hardware_level::{
    FleetHost, GpuEvidence, HardwareProofOp, TpmQuote, fleet_binding, gpu_challenge,
};
use tenzro_vm::native::hardware_level::{
    GAS_HARDWARE_PROOF, current_challenge, current_draw, read_gpu, read_possession,
};
use tracing::{debug, info};

use crate::node::TenzroNode;

/// How often the node looks for a challenge it has not answered.
const TICK: Duration = Duration::from_secs(60);
/// How long a sent proof is left to land before it is sent again.
const RESEND_AFTER: Duration = Duration::from_secs(600);
/// How long a GPU that gave no report is left alone before it is asked again.
const ASK_GPU_AGAIN_AFTER: Duration = Duration::from_secs(600);

/// Requests to the machine that holds this machine's identity key that may
/// go unanswered, or be answered by a TPM other than the admitted one, in a
/// row before the node stops asking; a restart asks again.
const HOLDER_ASKS: u32 = 8;
/// The longest pause between two such requests.
const HOLDER_PAUSE_MAX: Duration = Duration::from_secs(3600);

/// When the machine that holds this machine's identity key is next asked
/// for a possession quote. Each request is an audited request there and a
/// command to its TPM, so one that brings no usable quote is followed by a
/// growing pause, and after [`HOLDER_ASKS`] of them in a row by none.
#[derive(Default)]
struct HolderAsks {
    failures: u32,
    not_before: Option<Instant>,
}

impl HolderAsks {
    fn may_ask(&self, now: Instant) -> bool {
        self.failures < HOLDER_ASKS && self.not_before.is_none_or(|t| now >= t)
    }

    /// Notes a request that brought no usable quote. Returns whether it was
    /// the last one the node makes.
    fn failed(&mut self, now: Instant) -> bool {
        let pause = TICK
            .saturating_mul(1u32.checked_shl(self.failures + 1).unwrap_or(u32::MAX))
            .min(HOLDER_PAUSE_MAX);
        self.failures += 1;
        self.not_before = Some(now + pause);
        self.failures == HOLDER_ASKS
    }

    fn answered(&mut self) {
        *self = Self::default();
    }
}

/// Quote this epoch's challenge and send it, when the node's account is a
/// machine identity that has not yet answered it. Returns the epoch proven.
async fn prove_once(
    node: &Arc<TenzroNode>,
    sent: Option<(u64, Instant)>,
    holder: &mut HolderAsks,
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
    let Ok(admitted) = tenzro_vm::native::funding::machine_attestation(&chain, &did) else {
        return Ok(None);
    };
    let quoted = if tenzro_device_key::signer::keys_are_remote() {
        if !holder.may_ask(Instant::now()) {
            return Ok(None);
        }
        let draw = current_draw(&chain).ok_or("no beacon value in this reward epoch")?;
        let quoted = match held_quote(draw).await {
            Ok(evidence) => admitted_quote(&did, &admitted, evidence),
            Err(e) => Err(e),
        };
        match quoted {
            Ok(quoted) => {
                holder.answered();
                quoted
            }
            Err(e) => {
                if holder.failed(Instant::now()) {
                    tracing::warn!(
                        target: "hardware",
                        error = %e,
                        "the machine that holds this machine's key gave no usable possession \
                         quote {HOLDER_ASKS} times in a row; it is not asked again"
                    );
                }
                return Err(e);
            }
        }
    } else {
        admitted_quote(&did, &admitted, quote(challenge).await?)?
    };
    let op = HardwareProofOp::Possession {
        epoch,
        quote: quoted.quote,
        signature: quoted.signature,
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

/// This machine's TPM quote over `statement` for `did`, refused when the key
/// that quoted is not the attestation key `did` was admitted with in
/// `chain`: the chain checks the quote against that key, whether the identity
/// is the one the attestation key roots or a machine root whose DID derives
/// from its own identity key.
async fn quote_as(
    chain: &dyn tenzro_vm::traits::VmState,
    did: &str,
    statement: [u8; 32],
) -> Result<TpmQuote, String> {
    let admitted = tenzro_vm::native::funding::machine_attestation(chain, did)?;
    let evidence = quote(statement).await?;
    admitted_quote(did, &admitted, evidence)
}

/// The quote in `evidence`, refused when the key that quoted is not the
/// attestation key `did` was admitted with.
pub(crate) fn admitted_quote(
    did: &str,
    admitted: &tenzro_tee::tpm_attest::MachineAttestation,
    evidence: tenzro_tee::tpm_attest::TpmEvidence,
) -> Result<TpmQuote, String> {
    if evidence.ak_public != admitted.evidence.ak_public {
        return Err(format!(
            "the TPM that quoted is not the one {did} was admitted with"
        ));
    }
    Ok(TpmQuote {
        quote: evidence.quote,
        signature: evidence.quote_signature,
    })
}

/// This machine's evidence for the fleet proof `operator` sends for the
/// current reward epoch: its TPM's quote over the epoch's possession
/// challenge, with `bind` the quote that joins it to the operator's fleet,
/// and with `gpu` its GPU's report over the epoch's GPU challenge. Nothing
/// is sent: the operator's wallet sends the hosts' evidence together.
pub(crate) async fn fleet_host_evidence(
    node: &Arc<TenzroNode>,
    operator: &str,
    bind: bool,
    gpu: bool,
) -> Result<FleetHost, String> {
    let submitter = node.ledger_submitter().ok_or("this node has no account")?;
    let account = submitter.address();
    let chain = crate::rpc::chain_state_of(node).ok_or("no chain state")?;
    let did = tenzro_vm::native::identity_of_wallet(&chain, account.as_bytes())
        .ok_or("this node's account is not a registered machine identity")?;
    let (epoch, _, challenge) = current_challenge(&chain, &did)
        .ok_or("this reward epoch's possession challenge is not known yet")?;
    let possession = quote_as(&chain, &did, challenge).await?;
    let binding = if bind {
        Some(quote_as(&chain, &did, fleet_binding(operator, &did)).await?)
    } else {
        None
    };
    let gpus = if gpu {
        let nonce = gpu_challenge(&challenge);
        let (report, chain) = gpu_report(nonce).await?;
        if report.get(4..36) != Some(&nonce[..]) {
            return Err("NVML returned a report over another nonce".into());
        }
        vec![GpuEvidence { report, chain }]
    } else {
        Vec::new()
    };
    Ok(FleetHost {
        did,
        binding,
        epoch,
        possession,
        gpus,
    })
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
/// Returns the epoch proven. A GPU that gives no report is noted in `refused`
/// and is not asked again until [`ASK_GPU_AGAIN_AFTER`] has passed.
async fn prove_gpu_once(
    node: &Arc<TenzroNode>,
    sent: Option<(u64, Instant)>,
    refused: &mut Option<Instant>,
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
    if refused.is_some_and(|at| at.elapsed() < ASK_GPU_AGAIN_AFTER) {
        return Ok(None);
    }
    let nonce = gpu_challenge(&possession);
    let (report, certs) = match gpu_report(nonce).await {
        Ok(evidence) => evidence,
        Err(e) => {
            *refused = Some(Instant::now());
            return Err(e);
        }
    };
    *refused = None;
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

/// The possession quote of the reward epoch drawn as `draw` (epoch, beacon
/// round and value), by the TPM of the machine that holds this machine's
/// identity key.
async fn held_quote(
    (epoch, round, mix): (u64, u64, [u8; 32]),
) -> Result<tenzro_tee::tpm_attest::TpmEvidence, String> {
    tokio::task::spawn_blocking(move || {
        use tenzro_crypto::composite::HybridSigner;
        let signer = tenzro_device_key::HardwareHybridSigner::open_or_create(
            tenzro_types::did_derivation::MACHINE_KEY_LABEL,
        )
        .map_err(|e| format!("the machine identity key: {e}"))?;
        let key = [&[0x04u8][..], &signer.public_key().p256].concat();
        tenzro_tee::holder_attest::possession(
            |request| {
                signer
                    .holder_attestation(request)
                    .map_err(|e| e.to_string())
            },
            &key,
            epoch,
            round,
            &mix,
        )
        .map_err(|e| format!("the key holder's TPM quote failed: {e}"))
    })
    .await
    .map_err(|e| format!("TPM quote task failed: {e}"))?
}

#[cfg(any(target_os = "linux", windows))]
async fn quote(challenge: [u8; 32]) -> Result<tenzro_tee::tpm_attest::TpmEvidence, String> {
    tokio::task::spawn_blocking(move || tenzro_tee::tpm_attest::quote_local_machine(&challenge))
        .await
        .map_err(|e| format!("TPM quote task failed: {e}"))?
        .map(|(_, evidence)| evidence)
        .map_err(|e| format!("TPM quote failed: {e}"))
}

#[cfg(not(any(target_os = "linux", windows)))]
async fn quote(_challenge: [u8; 32]) -> Result<tenzro_tee::tpm_attest::TpmEvidence, String> {
    Err(
        "possession is quoted by a TPM 2.0 resource manager, which this platform has none of"
            .into(),
    )
}

/// Answer each reward epoch's possession challenge while this node's account
/// is a TPM-attested machine, and its GPU challenge when `[gpu_proof]` is
/// enabled: a GPU proof publishes the device's identifiers on chain.
pub fn spawn(node: Arc<TenzroNode>) {
    let gpu_proof_enabled = node.config().gpu_proof.enabled;
    tokio::spawn(async move {
        let mut sent: Option<(u64, Instant)> = None;
        let mut gpu_sent: Option<(u64, Instant)> = None;
        let mut gpu_refused: Option<Instant> = None;
        let mut holder = HolderAsks::default();
        loop {
            match prove_once(&node, sent, &mut holder).await {
                Ok(Some(epoch)) => {
                    sent = Some((epoch, Instant::now()));
                    info!(target: "hardware", epoch, "sent this epoch's TPM possession quote");
                }
                Ok(None) => {}
                Err(e) => debug!(target: "hardware", error = %e, "no possession quote this round"),
            }
            if gpu_proof_enabled {
                match prove_gpu_once(&node, gpu_sent, &mut gpu_refused).await {
                    Ok(Some(epoch)) => {
                        gpu_sent = Some((epoch, Instant::now()));
                        info!(target: "hardware", epoch, "sent this epoch's GPU report");
                    }
                    Ok(None) => {}
                    Err(e) => debug!(target: "hardware", error = %e, "no GPU report this round"),
                }
            }
            tokio::time::sleep(TICK).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_tee::nvidia_device::testgpu::SoftGpu;

    /// A key holder that gives no usable quote is asked again after a
    /// growing pause and, after a bounded number of requests in a row, not
    /// at all; a usable quote starts the count again.
    #[test]
    fn a_key_holder_that_gives_no_quote_is_asked_less_and_then_not_at_all() {
        let start = Instant::now();
        let mut asks = HolderAsks::default();
        assert!(asks.may_ask(start));
        assert!(!asks.failed(start));
        assert!(!asks.may_ask(start + TICK));
        assert!(asks.may_ask(start + 2 * TICK));
        asks.answered();
        assert!(asks.may_ask(start));

        let mut now = start;
        let mut made = 0;
        let mut last_pause = Duration::ZERO;
        while asks.may_ask(now) {
            made += 1;
            let stopped = asks.failed(now);
            assert_eq!(stopped, made == HOLDER_ASKS);
            let pause = asks.not_before.unwrap() - now;
            assert!(pause >= last_pause && pause <= HOLDER_PAUSE_MAX);
            last_pause = pause;
            now += pause;
        }
        assert_eq!(made, HOLDER_ASKS);
        assert!(!asks.may_ask(now + 100 * HOLDER_PAUSE_MAX));
    }

    /// A machine root's DID derives from its identity key, not from its
    /// TPM's attestation key: the quote of the TPM it was admitted with is
    /// taken for its possession proof and for its fleet binding, and the
    /// chain's check of each quote passes. A quote by another TPM is not.
    #[test]
    fn a_machine_root_quotes_with_the_tpm_it_was_admitted_with() {
        use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
        use tenzro_tee::tpm_attest::{
            MachineAttestation, admission_challenge, attestation_key_sec1,
            machine_did_for_attestation_key, verify_quote,
        };
        let tpm = SoftTpm::new(30);
        let identity_key = p256::ecdsa::SigningKey::from_slice(&[33u8; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let did = tenzro_types::did_derivation::machine_did(&identity_key);
        let nonce = [7u8; 32];
        let (admission, _) = evidence(&tpm, &admission_challenge(&did, &identity_key, &nonce));
        assert_ne!(
            machine_did_for_attestation_key(&attestation_key_sec1(&admission).unwrap()),
            did
        );
        let admitted = MachineAttestation {
            evidence: admission,
            nonce: nonce.to_vec(),
            activated: true,
        };

        let possession = tenzro_types::hardware_level::possession_challenge(&did, 4, 9, &[5; 32]);
        let binding = fleet_binding("did:tenzro:human:operator", &did);
        for statement in [possession, binding] {
            let (quoted, _) = evidence(&tpm, &statement);
            let q = admitted_quote(&did, &admitted, quoted).unwrap();
            let mut presented = admitted.evidence.clone();
            presented.quote = q.quote;
            presented.quote_signature = q.signature;
            verify_quote(&presented, &statement).unwrap();

            let (other, _) = evidence(&SoftTpm::new(40), &statement);
            let err = admitted_quote(&did, &admitted, other).unwrap_err();
            assert!(err.contains("not the one"), "{err}");
        }
    }

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
