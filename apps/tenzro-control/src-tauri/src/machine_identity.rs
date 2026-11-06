//! The machine's on-chain identity, made ready before it transacts.
//!
//! Every native transaction Control sends is signed by this machine's
//! hardware wallet key. When that hardware also holds an ML-DSA-65 key, every
//! signature carries both legs, and the network verifies the ML-DSA-65 leg
//! against the key enrolled for the account; until one is enrolled such a
//! signature is refused. So before its first transaction the machine puts two
//! records on chain, each once: its ML-DSA-65 key enrolled for the account,
//! and its wallet identity (the machine DID of the hardware key, bound to that
//! key's account). Each is a native transaction built by the SDK and signed by
//! the hardware key, and Control waits until chain state shows it before the
//! next step.
//!
//! A machine whose hardware holds only a P-256 key has nothing to put on
//! chain: its account is its P-256 key, and a wallet identity needs an
//! ML-DSA-65 key.

use std::sync::Arc;
use std::time::Duration;

use tenzro_crypto::composite::SignatureContext;
use tenzro_node::TenzroNode;
use tenzro_sdk::{HybridSigner, TxKind, TypedTransaction};
use tenzro_types::identity::{registration_statement, RegisterIdentityPayload, RegistrationProof};
use tenzro_types::primitives::Address;
use tenzro_types::TransactionType;

use crate::native_tx::{self, OperatorSigner, Sent};

/// How long Control waits for a submitted transaction to reach chain state.
const INCLUSION_WAIT: Duration = Duration::from_secs(90);
const INCLUSION_POLL: Duration = Duration::from_millis(500);

/// This machine's wallet identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineIdentity {
    pub did: String,
    pub address: Address,
}

/// The identity of the hardware key `signer` holds.
pub fn identity_of(signer: &OperatorSigner) -> Result<MachineIdentity, String> {
    Ok(MachineIdentity {
        did: tenzro_types::did_derivation::machine_did(&signer.public_key_sec1()),
        address: Address::from_hex(&signer.address()).map_err(|e| e.to_string())?,
    })
}

/// A one-time record the machine still has to put on chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setup {
    EnrollPqKey,
    RegisterIdentity,
}

impl Setup {
    pub fn describe(self) -> &'static str {
        match self {
            Setup::EnrollPqKey => "enrol this machine's hardware ML-DSA-65 key for its account",
            Setup::RegisterIdentity => "register this machine's wallet identity",
        }
    }

    pub fn gas(self) -> u64 {
        match self {
            Setup::EnrollPqKey => tenzro_vm::account_keys::GAS_ACCOUNT_KEYS,
            Setup::RegisterIdentity => tenzro_vm::native::GAS_IDENTITY_REGISTER,
        }
    }
}

fn pq_enrolled(node: &TenzroNode, signer: &OperatorSigner) -> bool {
    let sec1 = signer.public_key_sec1();
    node.chain_state()
        .and_then(|s| tenzro_vm::account_keys::enrolled_pq_key(&s, &sec1[1..]))
        .is_some()
}

pub(crate) fn registered(node: &TenzroNode, did: &str) -> bool {
    node.identity_registry().is_some_and(|r| r.resolve(did).is_ok())
}

/// The records `signer`'s machine still has to put on chain, in order.
pub fn pending(node: &TenzroNode, signer: &OperatorSigner) -> Result<Vec<Setup>, String> {
    let mut steps = Vec::new();
    if signer.ml_dsa_public_key().is_none() {
        return Ok(steps);
    }
    if !pq_enrolled(node, signer) {
        steps.push(Setup::EnrollPqKey);
    }
    if !registered(node, &identity_of(signer)?.did) {
        steps.push(Setup::RegisterIdentity);
    }
    Ok(steps)
}

/// Put every record `signer`'s machine is missing on chain, waiting for each,
/// so that the next transaction it signs is accepted.
pub async fn ensure_ready(node: &Arc<TenzroNode>, signer: &OperatorSigner) -> Result<(), String> {
    let identity = identity_of(signer)?;
    for step in pending(node, signer)? {
        let tx = match step {
            Setup::EnrollPqKey => enroll_pq_tx(signer).await?,
            Setup::RegisterIdentity => native_tx::typed(&register_tx(registration(signer, &identity).await?))?,
        };
        let sent = native_tx::send_typed(node.clone(), signer, &tx).await?;
        match step {
            Setup::EnrollPqKey => wait_for(step.describe(), &sent, || pq_enrolled(node, signer)).await?,
            Setup::RegisterIdentity => wait_for(step.describe(), &sent, || registered(node, &identity.did)).await?,
        }
    }
    Ok(())
}

/// Wait until `done` holds, at most [`INCLUSION_WAIT`] after `sent`.
pub async fn wait_for(what: &str, sent: &Sent, mut done: impl FnMut() -> bool) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + INCLUSION_WAIT;
    loop {
        if done() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "{what}: transaction {} was submitted but chain state does not show it after {} s",
                sent.hash,
                INCLUSION_WAIT.as_secs()
            ));
        }
        tokio::time::sleep(INCLUSION_POLL).await;
    }
}

/// The `AccountKeys` transaction that enrols the signer's ML-DSA-65 key,
/// built as the SDK's account-keys client builds it.
async fn enroll_pq_tx(signer: &OperatorSigner) -> Result<TypedTransaction, String> {
    use tenzro_sdk::account_keys::{enroll_pq_key_op, pq_enrollment_message, PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT};
    let key = signer
        .ml_dsa_public_key()
        .ok_or_else(|| "this machine's hardware has no ML-DSA-65 key".to_string())?;
    let slot = tenzro_sdk::wallet::account_address(&signer.p256_public_key());
    let m_prime = tenzro_sdk::wallet::composite_message_representative(
        PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT,
        &pq_enrollment_message(&slot, &key),
    );
    let (_, possession) = signer.sign_composite(&m_prime).await.map_err(|e| e.to_string())?;
    let possession = possession.ok_or_else(|| "the hardware did not sign with its ML-DSA-65 key".to_string())?;
    let op = enroll_pq_key_op(&key, &possession).map_err(|e| e.to_string())?;
    TypedTransaction::new(TxKind::AccountKeys, serde_json::json!({ "op": op })).map_err(|e| e.to_string())
}

/// The machine wallet identity record, signed by the hardware key.
pub async fn registration(
    signer: &OperatorSigner,
    identity: &MachineIdentity,
) -> Result<RegisterIdentityPayload, String> {
    let pq_verifying_key = signer
        .ml_dsa_public_key()
        .ok_or_else(|| "this machine's hardware has no ML-DSA-65 key, which a wallet identity needs".to_string())?;
    let mut payload = RegisterIdentityPayload {
        did: identity.did.clone(),
        identity_type: "machine".to_string(),
        display_name: "Tenzro Control".to_string(),
        controller_pubkey: signer.public_key_sec1(),
        key_type: "P-256".to_string(),
        wallet_id: signer.address(),
        wallet_address: identity.address,
        pq_verifying_key,
        metadata: Default::default(),
        proof: RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(tenzro_types::account_signature::ClassicalProof::Raw { signature: Vec::new() }),
        },
    };
    let signature = signer
        .sign_for(SignatureContext::IdentityRegistration, &registration_statement(&payload))
        .await?;
    payload.proof = RegistrationProof::Hardware { signature };
    Ok(payload)
}

fn register_tx(p: RegisterIdentityPayload) -> TransactionType {
    TransactionType::RegisterIdentity {
        did: p.did,
        identity_type: p.identity_type,
        display_name: p.display_name,
        controller_pubkey: p.controller_pubkey,
        key_type: p.key_type,
        wallet_id: p.wallet_id,
        wallet_address: p.wallet_address,
        pq_verifying_key: p.pq_verifying_key,
        metadata: p.metadata,
        proof: p.proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_tx::tests::{hybrid_signer, in_process_node, signer, submitted_tx, SUBMITTED};
    use tenzro_types::account_signature::AccountKeysOp;
    use tenzro_types::network::NetworkRole;
    use tenzro_types::token::{StakeCapacity, StakeOp};
    use tenzro_vm::traits::VmState as _;

    fn fund(node: &TenzroNode, address: &Address) {
        let mut state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("node storage").clone());
        state.set_balance(address.as_bytes(), 1_000_000_000_000_000_000);
        state.commit().expect("commit funded balance");
    }

    /// The requests `machine` sent, oldest first, removing them from the log.
    fn take_sent(machine: &Address) -> Vec<serde_json::Value> {
        let mut log = SUBMITTED.lock().unwrap();
        let (ours, rest): (Vec<_>, Vec<_>) =
            log.drain(..).partition(|r| submitted_tx(r).from == *machine);
        *log = rest;
        ours
    }

    /// Stands in for block production on a node with no validator set: writes
    /// the one-time records `machine` sent to chain state as block execution
    /// does, and advances its nonce.
    async fn include_setup(node: Arc<TenzroNode>, machine: Address) {
        loop {
            for req in take_sent(&machine) {
                let tx = submitted_tx(&req);
                let mut state =
                    tenzro_vm::StateAdapter::with_storage(node.storage().expect("node storage").clone());
                match &tx.tx_type {
                    TransactionType::AccountKeys { op: AccountKeysOp::EnrollPqKey { ml_dsa_public_key, .. } } => {
                        let p256 = hex::decode(req["public_key"].as_str().unwrap().trim_start_matches("0x")).unwrap();
                        tenzro_vm::account_keys::set_enrolled_pq_key(
                            &mut state,
                            &p256,
                            ml_dsa_public_key.clone(),
                            &mut Vec::new(),
                        );
                    }
                    TransactionType::RegisterIdentity {
                        did,
                        identity_type,
                        display_name,
                        controller_pubkey,
                        key_type,
                        wallet_id,
                        wallet_address,
                        pq_verifying_key,
                        metadata,
                        proof,
                    } => {
                        let payload = RegisterIdentityPayload {
                            did: did.clone(),
                            identity_type: identity_type.clone(),
                            display_name: display_name.clone(),
                            controller_pubkey: controller_pubkey.clone(),
                            key_type: key_type.clone(),
                            wallet_id: wallet_id.clone(),
                            wallet_address: *wallet_address,
                            pq_verifying_key: pq_verifying_key.clone(),
                            metadata: metadata.clone(),
                            proof: proof.clone(),
                        };
                        node.identity_registry().expect("identity registry").upsert_from_chain(&payload).unwrap();
                    }
                    _ => continue,
                }
                state.set_nonce(tx.from.as_bytes(), tx.nonce.0 + 1);
                state.commit().expect("commit included record");
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Runs block execution's signature check on the `Stake` `machine` last
    /// sent, against chain state: the ML-DSA-65 leg must verify under the key
    /// enrolled for the sender.
    fn sent_stake_executes(node: &TenzroNode, machine: &OperatorSigner) -> bool {
        let address = identity_of(machine).unwrap().address;
        let req = take_sent(&address)
            .into_iter()
            .rfind(|r| matches!(submitted_tx(r).tx_type, TransactionType::Stake { .. }))
            .expect("the stake was submitted");
        let signature: tenzro_types::account_signature::CompositeSignature =
            serde_json::from_value(req["signature"].clone()).unwrap();
        let state = node.chain_state().expect("chain state");
        let p256 = machine.public_key_sec1();
        let (expected, policy) = tenzro_vm::account_keys::pq_key_for(&state, &p256[1..], None);
        tenzro_crypto::composite::verify_pq_component(
            expected.as_deref(),
            SignatureContext::Transaction,
            submitted_tx(&req).hash().as_bytes(),
            signature.pq.as_deref(),
            policy,
        )
        .is_ok()
    }

    /// A fresh machine whose hardware holds an ML-DSA-65 key signs every
    /// transaction with both legs, so its stake fails in block execution until
    /// the key is enrolled; once `ensure_ready` has put its records on chain,
    /// the same stake is admitted and passes execution's signature check.
    #[tokio::test]
    async fn a_fresh_machine_with_an_ml_dsa_key_stakes_once_its_identity_is_ready() {
        let tmp = tempfile::tempdir().unwrap();
        let node = in_process_node(&tmp).await;
        let machine = hybrid_signer(31);
        fund(&node, &identity_of(&machine).unwrap().address);
        let stake = TransactionType::Stake {
            op: StakeOp::Bond { role: NetworkRole::StorageProvider, amount: 5, capacity: StakeCapacity::None },
        };

        native_tx::send_native(node.clone(), &machine, &stake).await.unwrap();
        assert!(!sent_stake_executes(&node, &machine));
        assert_eq!(pending(&node, &machine).unwrap(), vec![Setup::EnrollPqKey, Setup::RegisterIdentity]);

        let chain = tokio::spawn(include_setup(node.clone(), identity_of(&machine).unwrap().address));
        ensure_ready(&node, &machine).await.unwrap();
        chain.abort();
        assert!(pending(&node, &machine).unwrap().is_empty());

        native_tx::send_native(node.clone(), &machine, &stake).await.unwrap();
        assert!(sent_stake_executes(&node, &machine));
    }

    /// A machine whose hardware holds only a P-256 key has nothing to set up.
    #[tokio::test]
    async fn a_p256_only_machine_has_nothing_to_set_up() {
        let tmp = tempfile::tempdir().unwrap();
        let node = in_process_node(&tmp).await;
        assert!(pending(&node, &signer(32)).unwrap().is_empty());
    }

    /// The identity is derived from the hardware key: the same key always
    /// yields the same DID and account, another key another.
    #[test]
    fn the_identity_is_derived_from_the_hardware_key() {
        let a = identity_of(&signer(51)).unwrap();
        assert_eq!(a, identity_of(&signer(51)).unwrap());
        assert_eq!(a.did, tenzro_types::did_derivation::machine_did(&signer(51).public_key_sec1()));
        assert_eq!(a.address, Address::from_hex(&signer(51).address()).unwrap());
        let b = identity_of(&signer(52)).unwrap();
        assert_ne!(a.did, b.did);
        assert_ne!(a.address, b.address);
    }

    /// No code path outside tests creates, imports or randomly generates a
    /// key: every key is opened from the TPM or Secure Enclave.
    #[test]
    fn no_code_path_holds_a_software_key() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let banned = ["OsRng", "thread_rng", "getrandom", "rand::", "SigningKey::random", "SigningKey::from", "from_seed"];
        for entry in std::fs::read_dir(root.join("src")).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            let code = src.split("#[cfg(test)]").next().unwrap();
            for token in banned {
                assert!(!code.contains(token), "{} holds a software key path: {token}", path.display());
            }
        }
        let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
        let deps = manifest.split("[dev-dependencies]").next().unwrap();
        for krate in ["rand", "getrandom", "p256", "k256", "ed25519-dalek"] {
            assert!(
                !deps.lines().any(|l| l.trim_start().starts_with(&format!("{krate} ")) || l.trim_start().starts_with(&format!("{krate}="))),
                "the app depends on {krate} outside tests"
            );
        }
    }
}
