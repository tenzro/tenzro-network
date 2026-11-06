//! Records the node derives from finalized blocks and commits alongside the
//! execution writes of an epoch's first block.
//!
//! Two things a node needs to follow the chain are computed by the node
//! rather than written by transaction execution: the validator set of each
//! epoch, which every later commit certificate is checked against, and the
//! validator registry that the next epoch transition is computed from.
//! Committing both at each epoch's first block puts them under a state root
//! that a certificate signs, so a light client can prove the validator set it
//! should expect next, and a node restoring from a snapshot restores them
//! verified rather than taking a peer's word for them.
//!
//! Only fields every node computes identically are committed. The one
//! wall-clock field of a registry entry, `updated_at`, differs between nodes
//! and is zeroed in the committed projection; the registration epoch
//! (`registered_at_epoch`) comes from the chain and is committed as is.

use serde::{Deserialize, Serialize};
use tenzro_consensus::EpochManager;
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::state_trie::{NS_EPOCH, NS_VALIDATOR_REGISTRY};
use tenzro_token::ValidatorRegistry;
use tenzro_token::validator_registry::ValidatorRegistryEntry;
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};

/// Key of the registry index under [`NS_VALIDATOR_REGISTRY`].
pub const REGISTRY_INDEX_KEY: &[u8] = b"index";

/// One validator of a committed epoch record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochValidator {
    /// Validator address.
    pub address: Address,
    /// ML-DSA-65 half of the composite consensus key.
    pub ml_dsa_public_key: Vec<u8>,
    /// P-256 half of the composite consensus key.
    pub p256_public_key: Vec<u8>,
    /// The node's Ed25519 key, whose address is `address`.
    pub node_key: [u8; 32],
    /// Voting power.
    pub stake: u128,
}

/// The committed record of one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRecord {
    /// Epoch number.
    pub number: u64,
    /// First height of the epoch.
    pub start_height: u64,
    /// The epoch's validator set, in set order (the order the committee's
    /// seats are apportioned in).
    pub validators: Vec<EpochValidator>,
}

/// The trie key of epoch `number`'s record.
pub fn epoch_key(number: u64) -> Vec<u8> {
    number.to_be_bytes().to_vec()
}

/// The committed form of a registry entry: the entry with its wall-clock
/// update time zeroed.
pub fn registry_projection(entry: &ValidatorRegistryEntry) -> ValidatorRegistryEntry {
    let mut e = entry.clone();
    e.updated_at = Timestamp::default();
    e
}

/// The records to commit with block `height`: empty unless `height` is the
/// first block of an epoch, in which case the epoch's record and the full
/// registry projection (with deletions for entries that left it since the
/// last epoch's record). `previous_index` is the committed registry index as
/// of the latest version.
pub fn epoch_start_records(
    epochs: &EpochManager,
    registry: Option<&ValidatorRegistry>,
    height: BlockHeight,
    previous_index: Option<Vec<Address>>,
) -> Writes {
    let mut out = Writes::new();
    let Some(epoch) = epochs.get_epoch_for_height(height) else {
        return out;
    };
    if epoch.start_height != height {
        return out;
    }
    let record = EpochRecord {
        number: epoch.number,
        start_height: epoch.start_height.as_u64(),
        validators: epoch
            .validator_set
            .iter()
            .map(|v| EpochValidator {
                address: v.address,
                ml_dsa_public_key: v.public_key.ml_dsa.clone(),
                p256_public_key: v.public_key.p256.clone(),
                node_key: v.node_key,
                stake: v.stake,
            })
            .collect(),
    };
    if let Ok(bytes) = bincode::serialize(&record) {
        out.insert((NS_EPOCH.to_string(), epoch_key(epoch.number)), Some(bytes));
    }

    if let Some(registry) = registry {
        let mut entries = registry.list();
        entries.sort_by(|a, b| a.address.as_bytes().cmp(b.address.as_bytes()));
        let index: Vec<Address> = entries.iter().map(|e| e.address).collect();
        for entry in &entries {
            if let Ok(bytes) = bincode::serialize(&registry_projection(entry)) {
                out.insert(
                    (
                        NS_VALIDATOR_REGISTRY.to_string(),
                        entry.address.as_bytes().to_vec(),
                    ),
                    Some(bytes),
                );
            }
        }
        for gone in previous_index
            .unwrap_or_default()
            .into_iter()
            .filter(|a| !index.contains(a))
        {
            out.insert(
                (NS_VALIDATOR_REGISTRY.to_string(), gone.as_bytes().to_vec()),
                None,
            );
        }
        if let Ok(bytes) = bincode::serialize(&index) {
            out.insert(
                (
                    NS_VALIDATOR_REGISTRY.to_string(),
                    REGISTRY_INDEX_KEY.to_vec(),
                ),
                Some(bytes),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn the_projection_drops_the_wall_clock() {
        let reg = ValidatorRegistry::new();
        let a = Address::new([7u8; 32]);
        let mut p256 = vec![0u8; 65];
        p256[0] = 0x04;
        reg.register_candidate(a, vec![0u8; 1952], p256, [0u8; 32], a, 0, 0, String::new())
            .unwrap();
        let entry = reg.get(&a).unwrap();
        let mut later = entry.clone();
        later.updated_at = Timestamp::new(entry.updated_at.as_millis() + 12_345);
        assert_eq!(
            bincode::serialize(&registry_projection(&entry)).unwrap(),
            bincode::serialize(&registry_projection(&later)).unwrap(),
        );
    }

    /// Two nodes that register the same candidate at different wall-clock
    /// times commit the same registry projection: nothing a local clock
    /// stamps reaches the committed bytes.
    #[test]
    fn nodes_registering_at_different_times_commit_the_same_projection() {
        let a = Address::new([9u8; 32]);
        let mut p256 = vec![0u8; 65];
        p256[0] = 0x04;
        let register = || {
            let reg = ValidatorRegistry::new();
            reg.register_candidate(
                a,
                vec![0u8; 1952],
                p256.clone(),
                [0u8; 32],
                a,
                0,
                3,
                String::new(),
            )
            .unwrap();
            reg.get(&a).unwrap()
        };
        let first = register();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = register();
        assert_ne!(first.updated_at, second.updated_at);
        assert_eq!(
            bincode::serialize(&registry_projection(&first)).unwrap(),
            bincode::serialize(&registry_projection(&second)).unwrap(),
        );
    }

    /// Executes a transaction the way block execution does: its writes are
    /// captured and committed into the trie at `version`.
    async fn execute_and_commit(
        store: &Arc<dyn tenzro_storage::KvStore>,
        tx: &tenzro_vm::VmTransaction,
        version: u64,
    ) -> tenzro_types::primitives::Hash {
        use tenzro_storage::state_trie::capture;
        let runtime = tenzro_vm::MultiVmRuntime::new(tenzro_vm::VmConfig::default())
            .await
            .unwrap();
        let writes = capture::WriteSet::new();
        let mut state = tenzro_vm::StateAdapter::with_storage(store.clone());
        let outcome =
            capture::in_task(writes.clone(), runtime.execute_transaction(tx, &mut state)).await;
        assert!(outcome.unwrap().success, "the transaction executes");
        capture::in_thread(writes.clone(), || state.commit()).unwrap();
        tenzro_storage::StateTrie::new(store.clone())
            .commit(version, &writes.take())
            .unwrap()
    }

    #[tokio::test]
    async fn an_agent_bond_and_the_bonded_balance_are_provable_under_the_committed_root() {
        use tenzro_storage::{CF_ACCOUNTS, CF_STATE, KvStore, StateTrie, verify_state_proof};
        use tenzro_types::hash_scheme::HashScheme::Sha256;
        let dir = tempfile::tempdir().unwrap();
        let store: Arc<dyn KvStore> =
            Arc::new(tenzro_storage::RocksDbStore::open_default(dir.path()).unwrap());

        // An autonomous agent bonds itself from the account of its device key.
        use tenzro_crypto::composite::HybridSigner as _;
        let device = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(7);
        let key = device.public_key().p256.clone();
        let controller = tenzro_crypto::composite::account_slot(&key);
        let agent = tenzro_types::did_derivation::machine_did(&key);
        let mut balance_key = b"balance:".to_vec();
        balance_key.extend_from_slice(&controller);
        let funded: u128 = 1_000_000 * 10u128.pow(18);
        store
            .put(CF_ACCOUNTS, &balance_key, &funded.to_le_bytes())
            .unwrap();

        let bond: u128 = 5 * 10u128.pow(18);
        let mut data = tenzro_vm::native::SELECTOR_POST_AGENT_BOND.to_vec();
        data.extend_from_slice(
            &serde_json::to_vec(&serde_json::json!({
                "agent_did": agent,
                "controller_did": agent,
                "amount": bond,
            }))
            .unwrap(),
        );
        let mut tx = tenzro_vm::VmTransaction::new(
            controller.to_vec(),
            None,
            0,
            data,
            1_000_000,
            5_000_000_000,
            0,
            tenzro_vm::VmType::Tenzro,
            1337,
        );
        tx.public_key = Some(key);
        let root = execute_and_commit(&store, &tx, 1).await;
        let trie = StateTrie::new(store.clone());
        assert_eq!(trie.root_at(1).unwrap(), Some(root));

        // The bond marker the VM wrote, proven by its committed key.
        let bond_key = format!(
            "storage:{}:{}",
            hex::encode([0xFFu8; 20]),
            hex::encode(format!("bond:{agent}"))
        )
        .into_bytes();
        let (marker, proof) = trie.prove(1, CF_STATE, &bond_key).unwrap();
        let marker = marker.expect("the bond marker is committed");
        verify_state_proof(Sha256, &root.0, CF_STATE, &bond_key, Some(&marker), &proof).unwrap();

        // The controller's balance after the bond and gas were debited.
        let (balance, proof) = trie.prove(1, CF_ACCOUNTS, &balance_key).unwrap();
        let balance = balance.expect("the debited balance is committed");
        let remaining = u128::from_le_bytes(balance.as_slice().try_into().unwrap());
        assert!(remaining < funded - bond + 1);
        verify_state_proof(
            Sha256,
            &root.0,
            CF_ACCOUNTS,
            &balance_key,
            Some(&balance),
            &proof,
        )
        .unwrap();

        // A proof does not verify a different balance.
        let forged = funded.to_le_bytes();
        assert!(
            verify_state_proof(
                Sha256,
                &root.0,
                CF_ACCOUNTS,
                &balance_key,
                Some(&forged),
                &proof
            )
            .is_err()
        );

        // An account that holds nothing is proven absent.
        let mut other = b"balance:".to_vec();
        other.extend_from_slice(&[8u8; 32]);
        let (none, proof) = trie.prove(1, CF_ACCOUNTS, &other).unwrap();
        assert!(none.is_none());
        verify_state_proof(Sha256, &root.0, CF_ACCOUNTS, &other, None, &proof).unwrap();
        assert!(
            verify_state_proof(Sha256, &root.0, CF_ACCOUNTS, &other, Some(&forged), &proof)
                .is_err()
        );
    }
}
