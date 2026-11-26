//! Zero-knowledge proofs this node verifies outside the block.
//!
//! A proof envelope is larger than a block can carry, so provers send it to
//! validators over the zk-proof protocol. A validator runs the verifier on
//! it off the block and, when it verifies, sends a ZK verdict (a native
//! call): the proof is recorded once validators holding two thirds of the
//! bonded stake stated it. [`send_to_validators`] is how a node passes a
//! proof a client gave it to the current committee.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tenzro_crypto::composite::HybridSigner;
use tenzro_storage::RocksDbStore;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::TransactionType;

use crate::consensus_driver::ConsensusHandle;

/// Gas limit of one verdict.
const VERDICT_GAS: u64 = 100_000;

/// The verdict this node states for `envelope`, or why it states none: it
/// decodes as one proof envelope and verifies.
fn verdict_for(envelope: &[u8]) -> Result<tenzro_native_ops::zk_verdict::ZkVerdictOp, String> {
    let proof: tenzro_zk::Proof =
        bincode::deserialize(envelope).map_err(|e| format!("it is no proof envelope: {e}"))?;
    tenzro_zk::verify_proof_envelope(&proof).map_err(|e| format!("it does not verify: {e}"))?;
    Ok(tenzro_native_ops::zk_verdict::ZkVerdictOp {
        statement: tenzro_zk::statement_commitment(&proof.circuit_id, &proof.public_inputs)
            .to_vec(),
        proof: tenzro_vm::precompiles::compute_zk_commitment(&proof).to_vec(),
        system: proof.system.as_str().to_string(),
    })
}

/// The verifier behind the zk-proof protocol on a validator.
pub struct ProofVerifier {
    consensus: Arc<ConsensusHandle>,
    signer: Arc<dyn HybridSigner>,
    storage: Arc<RocksDbStore>,
    chain_id: u64,
    nonces: Arc<crate::payment_rails::NonceReservation>,
    gossip: crate::payment_rails::GossipSlot,
    /// One proof is verified at a time; another offered meanwhile is
    /// refused, to be sent again.
    busy: AtomicBool,
}

impl ProofVerifier {
    /// A verifier stating verdicts as the account of `signer`.
    pub fn new(
        consensus: Arc<ConsensusHandle>,
        signer: Arc<dyn HybridSigner>,
        storage: Arc<RocksDbStore>,
        chain_id: u64,
        nonces: Arc<crate::payment_rails::NonceReservation>,
        gossip: crate::payment_rails::GossipSlot,
    ) -> Self {
        Self {
            consensus,
            signer,
            storage,
            chain_id,
            nonces,
            gossip,
            busy: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl tenzro_iroh::ProofSink for ProofVerifier {
    async fn offer(&self, envelope: Vec<u8>) -> Result<(), String> {
        {
            let state = tenzro_vm::StateAdapter::with_storage(
                self.storage.clone() as Arc<dyn tenzro_storage::KvStore>
            );
            if !tenzro_vm::feature_gate::is_live_now(&state, tenzro_vm::native::zk_verdict::GATE) {
                return Err("ZK verdicts are not in force on this chain yet".to_string());
            }
            let account = Address::new(self.signer.public_key().account_slot());
            if !tenzro_vm::native::zk_verdict::may_state(&state, account.as_bytes()) {
                return Err(
                    "this node holds no validator bond; send the proof to a validator".to_string(),
                );
            }
        }
        if self.busy.swap(true, Ordering::AcqRel) {
            return Err("this validator is verifying another proof; send it again later".into());
        }
        let verified = tokio::task::spawn_blocking(move || verdict_for(&envelope)).await;
        self.busy.store(false, Ordering::Release);
        let op = verified.map_err(|e| format!("verification failed: {e}"))??;
        let tx_type = TransactionType::NativeCall {
            selector: tenzro_native_ops::SELECTOR_ZK_VERDICT,
            data: tenzro_native_ops::encode(&op),
        };
        let (consensus, signer, storage, nonces, gossip, chain_id) = (
            self.consensus.clone(),
            self.signer.clone(),
            self.storage.clone(),
            self.nonces.clone(),
            self.gossip.clone(),
            self.chain_id,
        );
        tokio::task::spawn_blocking(move || {
            crate::node::submit_validator_transaction(
                &consensus,
                &signer,
                &storage,
                chain_id,
                &nonces,
                &gossip,
                tx_type,
                VERDICT_GAS,
            )
        })
        .await
        .map_err(|e| format!("the verdict was not sent: {e}"))?
        .map_err(|e| format!("the verdict was not sent: {e}"))?;
        tracing::info!(system = %op.system, proof = %hex::encode(&op.proof), "stated a ZK verdict");
        Ok(())
    }
}

/// What each validator of the current committee said to `envelope`, by
/// endpoint: taken, or why not.
pub async fn send_to_validators(
    consensus: &ConsensusHandle,
    endpoint: &tenzro_iroh::Endpoint,
    envelope: Vec<u8>,
) -> Vec<(String, Result<(), String>)> {
    let epoch = consensus.epoch_manager().current_epoch().number;
    let peers: Vec<[u8; 32]> = consensus
        .committee(epoch)
        .map(|c| {
            c.members()
                .iter()
                .filter_map(|m| consensus.announced_endpoint(&m.public_key))
                .collect()
        })
        .unwrap_or_default();
    let envelope = Arc::new(envelope);
    let sends = peers.into_iter().map(|peer| {
        let envelope = envelope.clone();
        async move {
            let answer = match tenzro_iroh::EndpointId::from_bytes(&peer) {
                Ok(id) => tenzro_iroh::send_proof(endpoint, id, &envelope)
                    .await
                    .unwrap_or_else(|e| Err(e.to_string())),
                Err(e) => Err(format!("not an endpoint id: {e}")),
            };
            (hex::encode(peer), answer)
        }
    });
    futures::future::join_all(sends).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A verdict is stated only for bytes that decode as a proof envelope
    /// and verify; each refusal says which.
    #[test]
    fn only_a_verifying_envelope_earns_a_verdict() {
        let refused = verdict_for(b"not a proof").unwrap_err();
        assert!(refused.contains("no proof envelope"), "{refused}");
        let proof = tenzro_zk::Proof {
            system: tenzro_zk::ProofSystem::ALL[0],
            proof_bytes: vec![0; 16],
            public_inputs: vec![vec![0; 32], vec![0; 32]],
            circuit_id: "identity".to_string(),
            created_at: tenzro_types::primitives::Timestamp::now(),
        };
        let refused = verdict_for(&bincode::serialize(&proof).unwrap()).unwrap_err();
        assert!(refused.contains("does not verify"), "{refused}");
    }
}
