//! Native transactions signed by this machine's hardware key.
//!
//! Control's account is the embedded node's operator account: the ledger
//! account of the machine's hardware wallet key (TPM 2.0 or Secure Enclave
//! P-256), the key the node itself holds its identity under. A role stake
//! bonded from it therefore activates the node's roles. The P-256 leg is
//! signed by that key; the ML-DSA-65 leg is added only where the hardware
//! implements ML-DSA. There is no software or derived key.
//!
//! Transactions are built with the SDK's typed-transaction builder. The node
//! only encodes them (`tenzro_getSigningPayload`); the SDK checks that the
//! encoding is the transaction it built before the key signs.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tenzro_device_key::signer::{HardwareMlDsaSigner, HardwareSigner, MlDsaSupport};
use tenzro_sdk::error::{SdkError, SdkResult};
use tenzro_sdk::wallet::{account_address, COMPOSITE_LABEL_MLDSA65_P256};
use tenzro_sdk::{HybridSigner, NodeRpc, TxKind, TypedTransaction, TypedTxClient};
use tenzro_types::did_derivation::MACHINE_WALLET_KEY_LABEL;
use tenzro_crypto::composite::SignatureContext;
use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
use tenzro_types::token::StakeOp;
use tenzro_types::TransactionType;

use crate::state::AppState;

/// What signs for this machine: `"tpm"`, `"secure-enclave"`, or `None` when
/// it has neither and cannot sign native transactions.
pub fn hardware_backend() -> Option<&'static str> {
    tenzro_device_key::signer::platform_backend().map(|b| b.as_str())
}

/// The operator account's signer: the machine's hardware wallet key, and its
/// hardware ML-DSA-65 key where the chip has one.
pub struct OperatorSigner {
    p256: Box<dyn HardwareSigner>,
    ml_dsa: Option<Box<dyn HardwareMlDsaSigner>>,
    ml_dsa_public: Option<Vec<u8>>,
    public: [u8; 64],
}

impl OperatorSigner {
    /// Open the machine's hardware wallet key. Refused on a machine without a
    /// TPM or Secure Enclave, and on hardware that reports ML-DSA but cannot
    /// drive it.
    pub fn open() -> Result<Self, String> {
        let p256 = tenzro_device_key::signer::open_or_create(MACHINE_WALLET_KEY_LABEL)
            .map_err(|e| e.to_string())?;
        let ml_dsa = match tenzro_device_key::signer::ml_dsa_support() {
            MlDsaSupport::Hardware(_) => Some(
                tenzro_device_key::signer::open_or_create_ml_dsa(&format!("{MACHINE_WALLET_KEY_LABEL}/ml-dsa-65"))
                    .map_err(|e| e.to_string())?,
            ),
            MlDsaSupport::Unavailable(_) => None,
        };
        Self::from_parts(p256, ml_dsa)
    }

    fn from_parts(
        p256: Box<dyn HardwareSigner>,
        ml_dsa: Option<Box<dyn HardwareMlDsaSigner>>,
    ) -> Result<Self, String> {
        let sec1 = p256.public_key_sec1().map_err(|e| e.to_string())?;
        let mut public = [0u8; 64];
        public.copy_from_slice(&sec1[1..]);
        let ml_dsa_public = ml_dsa
            .as_ref()
            .map(|k| k.verifying_key().map_err(|e| format!("ML-DSA-65 key: {e}")))
            .transpose()?;
        Ok(Self { p256, ml_dsa, ml_dsa_public, public })
    }

    /// The operator account, `0x`-prefixed hex.
    pub fn address(&self) -> String {
        format!("0x{}", hex::encode(account_address(&self.public)))
    }

    fn source(&self) -> &'static str {
        self.p256.backend().as_str()
    }

    /// The P-256 public key, SEC1 uncompressed (`0x04 || x || y`).
    pub fn public_key_sec1(&self) -> Vec<u8> {
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&self.public);
        sec1
    }


    /// A composite signature over `message` for `context`: the P-256 leg and,
    /// where the hardware holds one, the ML-DSA-65 leg.
    pub async fn sign_for(&self, context: SignatureContext, message: &[u8]) -> Result<CompositeSignature, String> {
        let m_prime = tenzro_crypto::composite::message_representative(context, message);
        let (rs, pq) = self.sign_composite(&m_prime).await.map_err(|e| e.to_string())?;
        Ok(CompositeSignature {
            classical: ClassicalProof::Raw { signature: rs.to_vec() },
            pq,
        })
    }

}

#[async_trait]
impl HybridSigner for OperatorSigner {
    fn p256_public_key(&self) -> [u8; 64] {
        self.public
    }

    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        self.ml_dsa_public.clone()
    }

    async fn sign_composite(&self, m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        let failed = |e: tenzro_device_key::DeviceKeyError| {
            SdkError::WalletError(format!("{} signature: {e}", self.source()))
        };
        let digest: [u8; 32] = Sha256::digest(m_prime).into();
        let rs = self.p256.sign_prehash(&digest).map_err(failed)?;
        let pq = match &self.ml_dsa {
            Some(k) => Some(k.sign(COMPOSITE_LABEL_MLDSA65_P256, m_prime).map_err(failed)?),
            None => None,
        };
        Ok((rs, pq))
    }

    async fn sign_p256(&self, message: &[u8]) -> SdkResult<[u8; 64]> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        self.p256
            .sign_prehash(&digest)
            .map_err(|e| SdkError::WalletError(format!("{} signature: {e}", self.source())))
    }
}

/// The operator account and what signs for it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StakeAccount {
    /// Empty on a machine without a TPM or Secure Enclave.
    pub address: String,
    /// `"tpm"`, `"secure-enclave"`, or empty when nothing can sign.
    pub signer: String,
}

/// The operator account, read from the hardware key once and kept.
pub fn stake_account() -> StakeAccount {
    static KNOWN: std::sync::OnceLock<StakeAccount> = std::sync::OnceLock::new();
    if let Some(known) = KNOWN.get() {
        return known.clone();
    }
    match OperatorSigner::open() {
        Ok(signer) => KNOWN
            .get_or_init(|| StakeAccount { address: signer.address(), signer: signer.source().to_string() })
            .clone(),
        Err(_) => StakeAccount::default(),
    }
}

/// The embedded node as the SDK's [`NodeRpc`]. Keeps the nonce of the
/// transaction it submitted, which names what the transaction creates (an
/// escrow id is derived from its payer and nonce).
pub(crate) struct EmbeddedNode {
    node: Arc<tenzro_node::TenzroNode>,
    sent_nonce: std::sync::Mutex<Option<u64>>,
}

impl EmbeddedNode {
    pub(crate) fn new(node: Arc<tenzro_node::TenzroNode>) -> Self {
        Self { node, sent_nonce: std::sync::Mutex::new(None) }
    }
}

#[async_trait]
impl NodeRpc for EmbeddedNode {
    async fn call_value(&self, method: &str, params: Value) -> SdkResult<Value> {
        if method == "tenzro_sendRawTransaction" {
            if let Ok(mut n) = self.sent_nonce.lock() {
                *n = params["nonce"].as_u64();
            }
            #[cfg(test)]
            tests::SUBMITTED.lock().unwrap().push(params.clone());
        }
        crate::rpc::call_node(&self.node, method, params)
            .await
            .map_err(SdkError::RpcError)
    }
}

/// A submitted native transaction.
#[derive(Debug, Clone)]
pub struct Sent {
    /// The node's answer: the transaction hash.
    pub hash: Value,
    /// The nonce it was sent with.
    pub nonce: u64,
}

/// The typed-transaction builder's form of `tx_type`.
pub fn typed(tx_type: &TransactionType) -> Result<TypedTransaction, String> {
    let value = serde_json::to_value(tx_type).map_err(|e| e.to_string())?;
    let (name, fields) = value
        .as_object()
        .and_then(|o| o.iter().next())
        .ok_or_else(|| "transaction type did not encode as a tagged object".to_string())?;
    let kind = TxKind::ALL
        .into_iter()
        .find(|k| k.as_str() == name)
        .ok_or_else(|| format!("the SDK has no builder for {name}"))?;
    TypedTransaction::new(kind, fields.clone()).map_err(|e| e.to_string())
}

/// Sign `tx_type` with `signer` through the SDK's builder and submit it to
/// `node`.
pub async fn send_native(
    node: Arc<tenzro_node::TenzroNode>,
    signer: &OperatorSigner,
    tx_type: &TransactionType,
) -> Result<Sent, String> {
    send_typed(node, signer, &typed(tx_type)?).await
}

/// Sign `tx` with `signer` and submit it to `node`.
pub async fn send_typed(
    node: Arc<tenzro_node::TenzroNode>,
    signer: &OperatorSigner,
    tx: &TypedTransaction,
) -> Result<Sent, String> {
    let rpc = Arc::new(EmbeddedNode::new(node));
    let hash = TypedTxClient::over(rpc.clone())
        .send(signer, tx)
        .await
        .map_err(|e| e.to_string())?;
    let nonce = rpc
        .sent_nonce
        .lock()
        .ok()
        .and_then(|n| *n)
        .ok_or_else(|| "the transaction was sent without a nonce".to_string())?;
    Ok(Sent { hash, nonce })
}

/// The running embedded node.
pub async fn running_node(state: &AppState) -> Result<Arc<tenzro_node::TenzroNode>, String> {
    let guard = state.node.read().await;
    Ok(guard.as_ref().ok_or_else(|| "node is not running yet".to_string())?.node())
}

/// The operator signer, opened off the async runtime (hardware calls block).
pub async fn open_signer() -> Result<OperatorSigner, String> {
    tokio::task::spawn_blocking(OperatorSigner::open)
        .await
        .map_err(|e| e.to_string())?
}

/// The running node and the operator signer, with the machine's identity
/// ready on chain ([`crate::machine_identity::ensure_ready`]). Every native
/// transaction Control sends is signed by a signer taken from here.
pub async fn ready(state: &AppState) -> Result<(Arc<tenzro_node::TenzroNode>, OperatorSigner), String> {
    let node = running_node(state).await?;
    let signer = open_signer().await?;
    crate::machine_identity::ensure_ready(&node, &signer).await?;
    Ok((node, signer))
}

/// Sign `op` as a `Stake` transaction with the operator account and submit it.
/// Returns the node's answer (the transaction hash).
pub async fn submit_stake(op: StakeOp, state: &AppState) -> Result<Value, String> {
    let (node, signer) = ready(state).await?;
    Ok(send_native(node, &signer, &TransactionType::Stake { op }).await?.hash)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Every request the embedded node was sent, in order; a node without a
    /// validator set keeps no mempool, so tests read submissions from here.
    pub(crate) static SUBMITTED: std::sync::Mutex<Vec<Value>> = std::sync::Mutex::new(Vec::new());
    use serde_json::json;
    use tenzro_types::network::NetworkRole;
    use tenzro_types::token::StakeCapacity;

    struct TestP256(p256::ecdsa::SigningKey);

    impl HardwareSigner for TestP256 {
        fn backend(&self) -> tenzro_device_key::signer::HardwareBackend {
            tenzro_device_key::signer::HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            MACHINE_WALLET_KEY_LABEL
        }
        fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
            let point = self.0.verifying_key().to_sec1_point(false);
            Ok(point.as_bytes().try_into().unwrap())
        }
        fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<tenzro_device_key::DeviceSignature> {
            use p256::ecdsa::signature::hazmat::PrehashSigner;
            let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
            Ok(sig.to_bytes().into())
        }
    }

    struct TestMlDsa(tenzro_crypto::pq::MlDsaSigningKey);

    impl HardwareMlDsaSigner for TestMlDsa {
        fn backend(&self) -> tenzro_device_key::signer::HardwareBackend {
            tenzro_device_key::signer::HardwareBackend::Tpm
        }
        fn label(&self) -> &str {
            MACHINE_WALLET_KEY_LABEL
        }
        fn verifying_key(&self) -> tenzro_device_key::Result<Vec<u8>> {
            Ok(self.0.verifying_key_bytes().to_vec())
        }
        fn sign(&self, ctx: &[u8], message: &[u8]) -> tenzro_device_key::Result<Vec<u8>> {
            assert_eq!(ctx, tenzro_crypto::composite::LABEL_MLDSA65_P256);
            Ok(self.0.sign(tenzro_crypto::composite::LABEL_MLDSA65_P256, message))
        }
    }

    pub(crate) fn signer(seed: u8) -> OperatorSigner {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        OperatorSigner::from_parts(Box::new(TestP256(key)), None).unwrap()
    }

    /// A signer whose hardware holds both a P-256 and an ML-DSA-65 key.
    pub(crate) fn hybrid_signer(seed: u8) -> OperatorSigner {
        let key = p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let pq = tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[seed; 32]).unwrap();
        OperatorSigner::from_parts(Box::new(TestP256(key)), Some(Box::new(TestMlDsa(pq)))).unwrap()
    }

    /// A started node, in process, with its data in `tmp`.
    pub(crate) async fn in_process_node(tmp: &tempfile::TempDir) -> Arc<tenzro_node::TenzroNode> {
        let config = tenzro_node::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..Default::default()
        };
        let mut node = tenzro_node::TenzroNode::new(config).await.unwrap();
        node.start().await.unwrap();
        Arc::new(node)
    }

    #[test]
    fn the_account_is_the_hardware_keys_ledger_slot() {
        let s = signer(7);
        let slot = tenzro_crypto::composite::account_slot(&s.public);
        assert_eq!(s.address(), format!("0x{}", hex::encode(slot)));
        assert_ne!(s.address(), signer(8).address());
    }

    #[tokio::test]
    async fn the_p256_leg_verifies_under_the_hardware_key() {
        let s = signer(3);
        let m_prime = b"composite message representative";
        let (rs, pq) = s.sign_composite(m_prime).await.unwrap();
        assert!(pq.is_none());
        let mut sec1 = vec![4u8];
        sec1.extend_from_slice(&s.public);
        assert!(tenzro_device_key::signer::verify_p256(&sec1, m_prime, &rs));
    }

    #[test]
    fn a_bond_encodes_as_the_stake_transaction_the_network_decodes() {
        let op = StakeOp::Bond { role: NetworkRole::StorageProvider, amount: 5, capacity: StakeCapacity::None };
        let tx = TypedTransaction::new(TxKind::Stake, json!({ "op": serde_json::to_value(&op).unwrap() })).unwrap();
        let decoded: tenzro_types::transaction::TransactionType = serde_json::from_value(tx.tx_type()).unwrap();
        assert!(matches!(decoded, tenzro_types::transaction::TransactionType::Stake { op: StakeOp::Bond { amount: 5, .. } }));
    }

    /// The node's answers to the SDK's calls, recorded on the way through.
    pub(crate) struct Recording {
        pub(crate) node: Arc<tenzro_node::TenzroNode>,
        pub(crate) payload: tokio::sync::Mutex<Option<Value>>,
        pub(crate) submitted: tokio::sync::Mutex<Option<Value>>,
    }

    impl Recording {
        pub(crate) fn over(node: Arc<tenzro_node::TenzroNode>) -> Arc<Self> {
            Arc::new(Self { node, payload: Default::default(), submitted: Default::default() })
        }
    }

    #[async_trait]
    impl NodeRpc for Recording {
        async fn call_value(&self, method: &str, params: Value) -> SdkResult<Value> {
            if method == "tenzro_sendRawTransaction" {
                *self.submitted.lock().await = Some(params.clone());
            }
            let answer = crate::rpc::call_node(&self.node, method, params).await;
            if method == "tenzro_getSigningPayload" {
                *self.payload.lock().await = answer.as_ref().ok().cloned();
            }
            answer.map_err(SdkError::RpcError)
        }
    }

    /// The transaction a `tenzro_sendRawTransaction` request carries.
    pub(crate) fn submitted_tx(req: &Value) -> tenzro_types::Transaction {
        use tenzro_types::primitives::{Address, ChainId, Nonce, Timestamp};
        let addr = |v: &Value| {
            let bytes: [u8; 32] = hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap().try_into().unwrap();
            Address::new(bytes)
        };
        tenzro_types::Transaction {
            chain_id: ChainId(req["chain_id"].as_u64().unwrap()),
            from: addr(&req["from"]),
            to: addr(&req["to"]),
            nonce: Nonce::from(req["nonce"].as_u64().unwrap()),
            tx_type: serde_json::from_value(req["tx_type"].clone()).unwrap(),
            gas_limit: req["gas_limit"].as_u64().unwrap(),
            gas_price: req["gas_price"].as_u64().unwrap(),
            timestamp: Timestamp::new(req["timestamp"].as_i64().unwrap()),
            valid_until: Timestamp::new(req["valid_until"].as_i64().unwrap()),
            memo: None,
        }
    }

    /// A bond built by the SDK's typed-transaction builder is signed over the
    /// digest a real node's `tenzro_getSigningPayload` names, that digest is
    /// the hash of exactly the transaction submitted, and the node accepts the
    /// operator's signature over it.
    #[tokio::test]
    async fn the_stake_view_signs_the_nodes_own_signing_payload() {
        let tmp = tempfile::tempdir().unwrap();
        let rpc = Recording::over(in_process_node(&tmp).await);

        let s = signer(11);
        let op = StakeOp::Bond { role: NetworkRole::StorageProvider, amount: 5, capacity: StakeCapacity::None };
        let tx = TypedTransaction::new(TxKind::Stake, json!({ "op": serde_json::to_value(&op).unwrap() })).unwrap();
        let sent = TypedTxClient::over(rpc.clone()).send(&s, &tx).await;
        if let Err(e) = &sent {
            let e = e.to_string().to_lowercase();
            assert!(!e.contains("signature") && !e.contains("signing payload"), "{e}");
        }

        let payload = rpc.payload.lock().await.clone().expect("the node answered getSigningPayload");
        let req = rpc.submitted.lock().await.clone().expect("the signed bond was submitted");
        assert_eq!(req["from"], s.address());
        let submitted = submitted_tx(&req);
        assert!(matches!(
            submitted.tx_type,
            tenzro_types::TransactionType::Stake { op: StakeOp::Bond { amount: 5, .. } }
        ));
        let digest = submitted.hash();
        assert_eq!(payload["digest"], hex::encode(digest.as_bytes()));

        let rs: [u8; 64] = hex::decode(req["signature"]["classical"]["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
        let m_prime = tenzro_sdk::wallet::composite_message_representative(
            tenzro_sdk::wallet::TRANSACTION_SIGNATURE_CONTEXT,
            digest.as_bytes(),
        );
        let mut sec1 = vec![4u8];
        sec1.extend_from_slice(&s.public);
        assert!(tenzro_device_key::signer::verify_p256(&sec1, &m_prime, &rs));
    }
}
