//! The keys of the sending account.
//!
//! An account is named by its hardware P-256 key, which never changes. Its
//! hardware ML-DSA-65 key is enrolled with one `AccountKeys` transaction and
//! can afterwards only be replaced, never removed. The transaction carries
//! both signature legs, and a proof that the hardware holds the new key: the
//! new key's ML-DSA-65 signature over the account slot followed by the key.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
use crate::wallet::{HybridSigner, account_address, composite_message_representative};
use serde_json::{Value, json};
use std::sync::Arc;

/// Length of an ML-DSA-65 verifying key.
pub const ML_DSA_65_PUBLIC_KEY_LEN: usize = 1952;

/// Signature context of the proof that the hardware holds the ML-DSA-65 key
/// being enrolled.
pub const PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT: &[u8] = b"tenzro/account/pq-key-enrollment";

/// What the new key signs to prove possession: the account slot of the
/// sender's P-256 key followed by the new key, so the proof enrolls that key
/// for that account and nothing else.
pub fn pq_enrollment_message(account_slot: &[u8; 32], ml_dsa_public_key: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(32 + ml_dsa_public_key.len());
    m.extend_from_slice(account_slot);
    m.extend_from_slice(ml_dsa_public_key);
    m
}

/// The `op` of an `AccountKeys` transaction that enrolls (or replaces) the
/// account's ML-DSA-65 key.
pub fn enroll_pq_key_op(ml_dsa_public_key: &[u8], possession: &[u8]) -> SdkResult<Value> {
    if ml_dsa_public_key.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        return Err(SdkError::InvalidParameter(format!(
            "an ML-DSA-65 key is {ML_DSA_65_PUBLIC_KEY_LEN} bytes, got {}",
            ml_dsa_public_key.len()
        )));
    }
    if possession.is_empty() {
        return Err(SdkError::InvalidParameter(
            "the proof of possession is empty".to_string(),
        ));
    }
    Ok(json!({
        "enroll_pq_key": {
            "ml_dsa_public_key": hex::encode(ml_dsa_public_key),
            "possession": hex::encode(possession),
        }
    }))
}

/// Operations on the keys of the signer's own account.
#[derive(Clone)]
pub struct AccountKeysClient {
    rpc: Arc<RpcClient>,
}

impl AccountKeysClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Enroll the hardware's ML-DSA-65 key as the account's post-quantum key,
    /// or replace the enrolled one. The hardware signs the proof of
    /// possession and the transaction; no key leaves it.
    pub async fn enroll_pq_key(&self, signer: &dyn HybridSigner) -> SdkResult<Value> {
        let key = signer.ml_dsa_public_key().ok_or_else(|| {
            SdkError::InvalidParameter("the hardware holds no ML-DSA-65 key to enroll".to_string())
        })?;
        let slot = account_address(&signer.p256_public_key());
        let m_prime = composite_message_representative(
            PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT,
            &pq_enrollment_message(&slot, &key),
        );
        let (_, possession) = signer.sign_composite(&m_prime).await?;
        let possession = possession.ok_or_else(|| {
            SdkError::InvalidParameter(
                "the hardware did not sign with its ML-DSA-65 key".to_string(),
            )
        })?;
        let tx = TypedTransaction::new(
            TxKind::AccountKeys,
            json!({ "op": enroll_pq_key_op(&key, &possession)? }),
        )?;
        TypedTxClient::new(self.rpc.clone()).send(signer, &tx).await
    }

    /// Send `tx`; if the node answers that the account has no ML-DSA-65 key
    /// enrolled, enroll the hardware's key and send it again. An account signs
    /// nothing until it has enrolled one, so this is how a new account sends
    /// its first transaction.
    pub async fn send_enrolling(
        &self,
        signer: &dyn HybridSigner,
        tx: &TypedTransaction,
    ) -> SdkResult<Value> {
        let client = TypedTxClient::new(self.rpc.clone());
        match client.send(signer, tx).await {
            Err(e) if tx.kind != TxKind::AccountKeys && e.to_string().contains(NOT_ENROLLED) => {
                self.enroll_pq_key(signer).await?;
                client.send(signer, tx).await
            }
            other => other,
        }
    }
}

/// What a node answers when an account that has not enrolled an ML-DSA-65
/// key sends a transaction carrying that leg.
const NOT_ENROLLED: &str = "no ML-DSA-65 key enrolled";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_op_matches_the_node_encoding() {
        let op = enroll_pq_key_op(&[1u8; ML_DSA_65_PUBLIC_KEY_LEN], &[2u8; 3]).unwrap();
        let inner = &op["enroll_pq_key"];
        assert_eq!(
            inner["ml_dsa_public_key"].as_str().unwrap(),
            hex::encode([1u8; ML_DSA_65_PUBLIC_KEY_LEN])
        );
        assert_eq!(inner["possession"], "020202");
        assert_eq!(op.as_object().unwrap().len(), 1);
    }

    #[test]
    fn enroll_op_refuses_a_wrong_key_length() {
        assert!(enroll_pq_key_op(&[1u8; 32], &[2u8; 3]).is_err());
    }

    #[test]
    fn the_not_enrolled_answer_is_the_nodes_text() {
        // The node refuses a leg for an account with no key enrolled with
        // this sentence (tenzro_crypto::composite::verify_pq_component).
        assert!(
            "invalid signature: ML-DSA-65 leg present for a key with no ML-DSA-65 key enrolled"
                .contains(NOT_ENROLLED)
        );
    }

    #[test]
    fn enrollment_message_is_slot_then_key() {
        let m = pq_enrollment_message(&[9u8; 32], &[1, 2]);
        assert_eq!(&m[..32], &[9u8; 32]);
        assert_eq!(&m[32..], &[1, 2]);
    }
}
