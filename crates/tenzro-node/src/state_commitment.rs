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

impl EpochRecord {
    /// The record's validators as a validator set of its epoch.
    pub fn validator_set(&self) -> std::result::Result<tenzro_consensus::ValidatorSet, String> {
        let validators = self
            .validators
            .iter()
            .map(|v| {
                let key = tenzro_consensus::ValidatorPublicKey::new(
                    v.ml_dsa_public_key.clone(),
                    v.p256_public_key.clone(),
                )
                .map_err(|e| format!("epoch {} validator key: {e}", self.number))?;
                Ok(tenzro_consensus::ValidatorInfo::new(
                    v.address, key, v.node_key, v.stake,
                ))
            })
            .collect::<std::result::Result<Vec<_>, String>>()?;
        tenzro_consensus::ValidatorSet::new(self.number, validators)
            .map_err(|e| format!("epoch {} validator set: {e}", self.number))
    }
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

/// Whether the block at `height` is the first block of its epoch. That is
/// read from the chain alone: the block carries the epoch it was ordered in,
/// and it is the first of that epoch when its parent carries an earlier one.
/// The first block after genesis opens the first epoch.
pub fn opens_epoch(height: BlockHeight, block_epoch: u64, parent_epoch: u64) -> bool {
    height.as_u64() == 1 || block_epoch > parent_epoch
}

/// Key of the epoch side state under [`NS_VALIDATOR_REGISTRY`]: what a node
/// needs, besides the registry's entries and their index, to continue the
/// registry from a snapshot at an epoch's first block. The validator queues
/// are not part of it: they are derived from the registry at each boundary,
/// so they are the same on every node whatever it executed or stopped at.
pub const REGISTRY_SIDE_KEY: &[u8] = b"side";

/// Version of the encoding of [`EpochSide`]. Every field is written out in
/// full, so a binary that later changes a default cannot change what an
/// existing epoch commits.
pub const EPOCH_SIDE_VERSION: u32 = 1;

/// The epoch side state committed with each epoch's record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSide {
    /// [`EPOCH_SIDE_VERSION`].
    pub version: u32,
    /// The registry's configuration, pending key rotations and unadmitted-key
    /// epochs, when the node runs a registry.
    pub registry: Option<tenzro_token::validator_registry::RegistrySide>,
}

/// The record of the epoch that block `height`, which carries epoch
/// `block_epoch` while its parent carries `parent_epoch`, opens; `None` when
/// the block opens no epoch ([`opens_epoch`]).
///
/// Which block carries a record, and what it holds, depend only on the
/// chain: the epoch in the block header, and the validator set the closing
/// epoch's executed state derives for the next one, which every node holds
/// before it executes the epoch's first block. A node that cannot find that
/// set refuses the block; it never skips the record, because a skipped
/// record would give it another state root than its peers. The check reads
/// nothing a block's execution changes, so a node makes it before it
/// executes the block and a refusal leaves nothing to undo.
pub fn epoch_open_record(
    epochs: &EpochManager,
    height: BlockHeight,
    block_epoch: u64,
    parent_epoch: u64,
) -> std::result::Result<Option<EpochRecord>, String> {
    if !opens_epoch(height, block_epoch, parent_epoch) {
        return Ok(None);
    }
    let set = epochs.get_validator_set(block_epoch).ok_or_else(|| {
        format!(
            "the validator set of epoch {block_epoch} is not known when its first block {} executes",
            height.as_u64()
        )
    })?;
    Ok(Some(EpochRecord {
        number: block_epoch,
        start_height: height.as_u64(),
        validators: set
            .iter()
            .map(|v| EpochValidator {
                address: v.address,
                ml_dsa_public_key: v.public_key.ml_dsa.clone(),
                p256_public_key: v.public_key.p256.clone(),
                node_key: v.node_key,
                stake: v.stake,
            })
            .collect(),
    }))
}

/// The writes that commit `record` and the registry as it stands after the
/// block that opens the epoch has executed: the full registry projection
/// (with deletions for entries that left it since the last record), its
/// index and its side state. `previous_index` is the committed registry
/// index as of the latest version.
pub fn epoch_open_writes(
    record: Option<EpochRecord>,
    registry: Option<&ValidatorRegistry>,
    previous_index: Option<Vec<Address>>,
) -> Writes {
    let mut out = Writes::new();
    let Some(record) = record else {
        return out;
    };
    if let Ok(bytes) = bincode::serialize(&record) {
        out.insert(
            (NS_EPOCH.to_string(), epoch_key(record.number)),
            Some(bytes),
        );
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
    let side = EpochSide {
        version: EPOCH_SIDE_VERSION,
        registry: registry.map(|r| r.side_state()),
    };
    if let Ok(bytes) = bincode::serialize(&side) {
        out.insert(
            (
                NS_VALIDATOR_REGISTRY.to_string(),
                REGISTRY_SIDE_KEY.to_vec(),
            ),
            Some(bytes),
        );
    }
    out
}

/// The record and writes of block `height` in one step; see
/// [`epoch_open_record`] and [`epoch_open_writes`].
pub fn epoch_start_records(
    epochs: &EpochManager,
    registry: Option<&ValidatorRegistry>,
    height: BlockHeight,
    block_epoch: u64,
    parent_epoch: u64,
    previous_index: Option<Vec<Address>>,
) -> std::result::Result<Writes, String> {
    let record = epoch_open_record(epochs, height, block_epoch, parent_epoch)?;
    Ok(epoch_open_writes(record, registry, previous_index))
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

    fn validator(stake: u128) -> tenzro_consensus::ValidatorInfo {
        let key = tenzro_consensus::ValidatorPublicKey::new(
            tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
        )
        .unwrap();
        let node_key = tenzro_crypto::P256KeyPair::generate().public_key_sec1();
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&blake3::hash(&node_key).as_bytes()[..32]);
        tenzro_consensus::ValidatorInfo::new(Address::new(raw), key, raw, stake)
    }

    /// Executes blocks 1..=35 (epochs of ten blocks, the header of each
    /// naming its epoch) on a node whose epoch manager learns each new
    /// epoch at `learns(closing_height)`; returns the state root after every
    /// block.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Timing {
        /// Every epoch is known before the node executes its first block.
        Eager,
        /// Each epoch is derived right after its closing block executes.
        JustInTime,
        /// Each epoch is derived only after the node first tried, and
        /// refused, its first block.
        Late,
    }

    fn run_chain(
        dir: &std::path::Path,
        epochs: &EpochManager,
        extra: &[tenzro_consensus::ValidatorInfo],
        timing: Timing,
    ) -> (
        Vec<tenzro_types::primitives::Hash>,
        Arc<tenzro_storage::StateTrie>,
    ) {
        let store: Arc<dyn tenzro_storage::KvStore> =
            Arc::new(tenzro_storage::RocksDbStore::open_default(dir).unwrap());
        let trie = Arc::new(tenzro_storage::StateTrie::new(store));
        let transition = |closing: u64| {
            // The same stake changes reach every node before the epoch
            // closes: they come from the executed state.
            if let Some(v) = extra.get((closing / 10 - 1) as usize) {
                epochs.add_pending_validator(v.clone());
            }
            epochs.transition_epoch(BlockHeight::from(closing)).unwrap();
        };
        if timing == Timing::Eager {
            // This node's consensus view is ahead of its execution: it
            // knows every epoch before it executes the first block.
            for closing in [10u64, 20, 30] {
                transition(closing);
            }
        }
        let epoch_of = |h: u64| (h - 1) / 10;
        let mut roots = Vec::new();
        for h in 1..=35u64 {
            let parent = if h == 1 { 0 } else { epoch_of(h - 1) };
            if timing == Timing::Late && h > 1 && h % 10 == 1 {
                // The node reaches the epoch's first block before it has
                // derived the epoch: it refuses the block, changes nothing,
                // and takes the block again once it has.
                let refused = epoch_start_records(
                    epochs,
                    None,
                    BlockHeight::from(h),
                    epoch_of(h),
                    parent,
                    None,
                );
                assert!(refused.is_err());
                transition(h - 1);
            }
            let records = epoch_start_records(
                epochs,
                None,
                BlockHeight::from(h),
                epoch_of(h),
                parent,
                None,
            )
            .unwrap();
            roots.push(trie.commit(h, &records).unwrap());
            if timing == Timing::JustInTime && h % 10 == 0 && h <= 30 {
                // The transition is derived once the closing block is
                // executed, which is just before the next one.
                transition(h);
            }
        }
        (roots, trie)
    }

    #[test]
    fn nodes_with_different_epoch_timing_commit_the_same_records_and_roots() {
        let base: Vec<_> = (0..3).map(|_| validator(1000)).collect();
        let extra: Vec<_> = (0..3).map(|i| validator(2000 + i)).collect();
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let a_epochs = EpochManager::new(base.clone(), 10).unwrap();
        let b_epochs = EpochManager::new(base, 10).unwrap();
        let (a_roots, a_trie) = run_chain(a_dir.path(), &a_epochs, &extra, Timing::Eager);
        let (b_roots, b_trie) = run_chain(b_dir.path(), &b_epochs, &extra, Timing::JustInTime);
        assert_eq!(
            a_roots, b_roots,
            "the same blocks give the same state roots"
        );
        for number in 0..=3u64 {
            let a = a_trie
                .get(35, tenzro_storage::state_trie::NS_EPOCH, &epoch_key(number))
                .unwrap()
                .unwrap_or_else(|| panic!("node A holds the record of epoch {number}"));
            let b = b_trie
                .get(35, tenzro_storage::state_trie::NS_EPOCH, &epoch_key(number))
                .unwrap()
                .unwrap_or_else(|| panic!("node B holds the record of epoch {number}"));
            assert_eq!(a, b);
            let record: EpochRecord = bincode::deserialize(&a).unwrap();
            assert_eq!(record.number, number);
            assert_eq!(
                record.start_height,
                number * 10 + 1,
                "the epoch's first block"
            );
        }
    }

    #[test]
    fn a_block_refused_and_taken_again_gives_the_root_of_a_block_never_refused() {
        let base: Vec<_> = (0..3).map(|_| validator(1000)).collect();
        let extra: Vec<_> = (0..3).map(|i| validator(2000 + i)).collect();
        let a_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        let a_epochs = EpochManager::new(base.clone(), 10).unwrap();
        let c_epochs = EpochManager::new(base, 10).unwrap();
        let (a_roots, _) = run_chain(a_dir.path(), &a_epochs, &extra, Timing::JustInTime);
        let (c_roots, _) = run_chain(c_dir.path(), &c_epochs, &extra, Timing::Late);
        assert_eq!(a_roots, c_roots);
    }

    #[test]
    fn a_node_that_does_not_know_the_epoch_refuses_its_first_block() {
        let base: Vec<_> = (0..3).map(|_| validator(1000)).collect();
        let epochs = EpochManager::new(base, 10).unwrap();
        assert!(
            epoch_start_records(&epochs, None, BlockHeight::from(5), 0, 0, None)
                .unwrap()
                .is_empty()
        );
        let refused = epoch_start_records(&epochs, None, BlockHeight::from(11), 1, 0, None);
        assert!(refused.unwrap_err().contains("epoch 1"));
    }

    /// An epoch whose time ran out before any block was made leaves no
    /// record, and the block that opens the epoch after it commits its own.
    #[test]
    fn an_epoch_without_blocks_leaves_no_record_and_the_next_opening_block_commits_its_own() {
        let v: Vec<_> = (0..3).map(|_| validator(1000)).collect();
        let epochs = EpochManager::new(v, 10).unwrap();
        epochs.transition_epoch(BlockHeight::from(10)).unwrap();
        epochs.transition_epoch(BlockHeight::from(20)).unwrap();
        // Parent in epoch 0, block in epoch 2: epoch 1 had no block.
        assert!(opens_epoch(BlockHeight::from(11), 2, 0));
        let record = epoch_open_record(&epochs, BlockHeight::from(11), 2, 0)
            .unwrap()
            .expect("opens epoch 2");
        assert_eq!(record.number, 2);
        assert_eq!(record.start_height, 11);
    }
}
