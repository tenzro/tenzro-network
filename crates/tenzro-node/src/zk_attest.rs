//! Submitting verified ZK proofs to consensus.
//!
//! The record the EVM `ZK_VERIFY` precompile reads is consensus state, written
//! only by an `AttestZkProof` transaction that every validator re-verifies
//! while executing the block. This module builds that transaction for a proof
//! the node has itself verified, signs it with the node's hybrid signer and
//! hands it to the mempool.

use std::sync::Arc;

use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tracing::info;

use crate::error::{NodeError, Result};
use crate::event_loop::NodeEvent;
use crate::node::TenzroNode;

impl TenzroNode {
    /// Submit an `AttestZkProof` transaction for `envelope`, signed by this
    /// node's hybrid signer. Returns the transaction hash.
    ///
    /// Only a node that runs consensus holds the signer, so only validators
    /// submit attestations on their own account. Anyone else attests by
    /// signing the same transaction type with their own key.
    pub async fn submit_zk_attestation(&self, envelope: &tenzro_zk::Proof) -> Result<String> {
        let proof = bincode::serialize(envelope)
            .map_err(|e| NodeError::Config(format!("proof envelope encode failed: {e}")))?;
        let gas_limit = tenzro_vm::native::zk_attest_gas(proof.len());

        let signer = self
            .identity_signer()
            .ok_or_else(|| {
                NodeError::Config("no hybrid signer on this node; cannot attest".to_string())
            })?
            .clone();
        let from_addr = Address::new(signer.public_key().account_slot());
        let chain_id = self.config().chain_id();
        let consensus = self
            .consensus()
            .ok_or_else(|| NodeError::Config("consensus not wired; cannot attest".to_string()))?;
        let gas_price = consensus.node_tx_gas_price();
        let nonce = {
            let storage = self
                .storage()
                .ok_or_else(|| NodeError::Config("storage not wired; cannot attest".to_string()))?;
            let state = tenzro_vm::StateAdapter::with_storage(
                storage.clone() as Arc<dyn tenzro_storage::KvStore>
            );
            use tenzro_vm::traits::VmState as _;
            state.get_nonce(from_addr.as_bytes())
        };
        let tx = Transaction::new(
            ChainId::from(chain_id),
            from_addr,
            Address::new([0u8; 32]),
            Nonce::from(nonce),
            TransactionType::AttestZkProof { proof },
            gas_limit,
            gas_price,
        );
        let tx_hash = tx.hash();
        let composite = signer
            .sign(
                tenzro_crypto::composite::SignatureContext::Transaction,
                tx_hash.as_bytes(),
            )
            .map_err(|e| NodeError::Config(format!("attestation signing failed: {e}")))?;
        let signed_tx = SignedTransaction::new(tx, signer.public_key().p256.clone(), composite);
        let hash_str = format!("{}", signed_tx.clone().hash());
        consensus
            .submit_transaction(signed_tx.clone())
            .map_err(|e| NodeError::Config(format!("attestation rejected by mempool: {e}")))?;
        if let Some(sender) = self.event_sender() {
            let _ = sender
                .send(NodeEvent::LocallyAdmittedTransaction(signed_tx))
                .await;
        }
        info!(circuit = %envelope.circuit_id, tx = %hash_str, "Submitted AttestZkProof");
        Ok(hash_str)
    }
}
