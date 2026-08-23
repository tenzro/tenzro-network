//! State adapter between VM and storage layer

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::parallel::BaseState;
use crate::traits::VmState;
use tenzro_storage::{CF_ACCOUNTS, CF_STATE, KvStore, MerklePatriciaTrie, WriteOp};
use tenzro_types::Hash;

/// Build the native TNZO balance key in the same format as
/// `tenzro_token::tnzo::RocksDbBackend::balance_key()`:
/// `b"balance:"` followed by the 32-byte Tenzro address.
///
/// The node's `parse_address` helper (in `tenzro-node/src/rpc.rs`) produces a
/// Tenzro `Address([u8; 32])` by copying the hex-decoded input into
/// `addr_bytes[..len]` — i.e. the raw address occupies the *leading* bytes
/// and any unused tail bytes are zero. For a 20-byte EVM address that gives:
/// ```text
///   addr_bytes[0..20]  = <EVM address bytes>
///   addr_bytes[20..32] = 0x00 × 12   (trailing zero pad)
/// ```
/// `RocksDbBackend::balance_key()` then writes to CF_ACCOUNTS under
/// `b"balance:" || addr_bytes[..]`. To read that same balance from the VM
/// layer (where revm / the SVM executor hand us a raw 20-byte address) we
/// must reproduce the *trailing* zero pad, not a leading one.
fn tnzo_balance_key(address: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + 32);
    key.extend_from_slice(b"balance:");
    match address.len() {
        20 => {
            // Right-zero-pad: <20 addr bytes> || <12 zeros>.
            key.extend_from_slice(address);
            key.extend_from_slice(&[0u8; 12]);
        }
        32 => {
            key.extend_from_slice(address);
        }
        _ => {
            // Non-standard length: use raw bytes. Test fixtures and synthetic
            // addresses fall through here; real EVM/Tenzro paths always hit
            // one of the two branches above.
            key.extend_from_slice(address);
        }
    }
    key
}

/// In-memory state adapter with optional RocksDB persistence
///
/// This adapter sits between the VM and the underlying storage layer,
/// providing caching and batching capabilities for improved performance.
/// When configured with a RocksDB store, it persists state changes to disk.
/// One reverted mutation: the key touched and the value it displaced.
///
/// `None` means the key was absent. Absence has to be distinguishable from a
/// stored zero — restoring a zero where there was nothing invents a balance
/// that was never written, and later reads cannot tell the difference.
#[derive(Debug, Clone)]
enum JournalEntry {
    Balance(Vec<u8>, Option<u128>),
    Storage(Vec<u8>, Vec<u8>, Option<Vec<u8>>),
    Code(Vec<u8>, Option<Vec<u8>>),
}


pub struct StateAdapter {
    /// Account code cache
    code_cache: Arc<DashMap<Vec<u8>, Vec<u8>>>,

    /// Storage cache: address -> key -> value
    storage_cache: Arc<DashMap<Vec<u8>, DashMap<Vec<u8>, Vec<u8>>>>,

    /// Undo log for the transaction currently executing, if one is open.
    ///
    /// `None` means nothing is being recorded and mutations are permanent as
    /// before. Entries hold the value each mutation *displaced*, so reverting
    /// is a backwards replay. Recording the displaced value rather than the new
    /// one is what makes repeated writes to the same key revert correctly: the
    /// last entry replayed is the earliest one recorded, which holds the value
    /// from before the transaction began.
    journal: Arc<parking_lot::RwLock<Option<Vec<JournalEntry>>>>,

    /// Balance cache
    balance_cache: Arc<DashMap<Vec<u8>, u128>>,

    /// Nonce cache
    nonce_cache: Arc<DashMap<Vec<u8>, u64>>,

    /// Dirty flags for modified entries
    dirty_code: Arc<DashMap<Vec<u8>, bool>>,
    dirty_storage: Arc<DashMap<Vec<u8>, DashMap<Vec<u8>, bool>>>,
    dirty_balance: Arc<DashMap<Vec<u8>, bool>>,
    dirty_nonce: Arc<DashMap<Vec<u8>, bool>>,

    /// Optional storage backend for persistent state
    storage: Option<Arc<dyn KvStore>>,
}

impl StateAdapter {
    /// Create a new in-memory state adapter (no persistence)
    pub fn new() -> Self {
        Self {
            code_cache: Arc::new(DashMap::new()),
            storage_cache: Arc::new(DashMap::new()),
            journal: Arc::new(parking_lot::RwLock::new(None)),
            balance_cache: Arc::new(DashMap::new()),
            nonce_cache: Arc::new(DashMap::new()),
            dirty_code: Arc::new(DashMap::new()),
            dirty_storage: Arc::new(DashMap::new()),
            dirty_balance: Arc::new(DashMap::new()),
            dirty_nonce: Arc::new(DashMap::new()),
            storage: None,
        }
    }

    /// Create a state adapter backed by a persistent storage backend
    ///
    /// # Arguments
    ///
    /// * `store` - Storage backend (RocksDB or MemoryStore) for persistent state
    ///
    /// # Returns
    ///
    /// A new StateAdapter that persists all state changes to the storage backend
    pub fn with_storage(store: Arc<dyn KvStore>) -> Self {
        Self {
            code_cache: Arc::new(DashMap::new()),
            storage_cache: Arc::new(DashMap::new()),
            journal: Arc::new(parking_lot::RwLock::new(None)),
            balance_cache: Arc::new(DashMap::new()),
            nonce_cache: Arc::new(DashMap::new()),
            dirty_code: Arc::new(DashMap::new()),
            dirty_storage: Arc::new(DashMap::new()),
            dirty_balance: Arc::new(DashMap::new()),
            dirty_nonce: Arc::new(DashMap::new()),
            storage: Some(store),
        }
    }

    /// Clear all caches
    pub fn clear(&self) {
        self.code_cache.clear();
        self.storage_cache.clear();
        self.balance_cache.clear();
        self.nonce_cache.clear();
        self.dirty_code.clear();
        self.dirty_storage.clear();
        self.dirty_balance.clear();
        self.dirty_nonce.clear();
    }

    /// Commit changes to underlying storage
    ///
    /// When a RocksDB store is configured, this writes all dirty entries to persistent storage.
    /// Uses fsync for durability to ensure data survives power loss.
    pub fn commit(&self) -> crate::error::Result<()> {
        tracing::debug!("Committing state changes");

        // Count dirty entries
        let dirty_code_count = self.dirty_code.len();
        let dirty_balance_count = self.dirty_balance.len();
        let dirty_nonce_count = self.dirty_nonce.len();
        let dirty_storage_count: usize = self
            .dirty_storage
            .iter()
            .map(|entry| entry.value().len())
            .sum();

        tracing::info!(
            "Committing changes: {} code, {} balance, {} nonce, {} storage",
            dirty_code_count,
            dirty_balance_count,
            dirty_nonce_count,
            dirty_storage_count
        );

        // Write to RocksDB if available
        if let Some(store) = &self.storage {
            let mut ops = Vec::new();

            // Write dirty code entries
            for entry in self.dirty_code.iter() {
                let addr = entry.key();
                if let Some(code) = self.code_cache.get(addr) {
                    let key = format!("code:{}", hex::encode(addr));
                    ops.push(WriteOp::Put {
                        cf: CF_STATE.to_string(),
                        key: key.into_bytes(),
                        value: code.value().clone(),
                    });
                }
            }

            // Write dirty balance entries.
            //
            // Per the Sei V2 pointer model — wTNZO ERC-20 pointer, wTNZO SPL
            // adapter, and the CIP-56 TNZO holding all share the same underlying
            // native balance via the TnzoToken layer — the native TNZO ledger
            // is the *single source of truth* for account balances. Writes from VM execution must land in CF_ACCOUNTS
            // using TnzoToken's key format so that:
            //   - `eth_getBalance`, `tenzro_getBalance`, and revm's
            //     `Database::basic()` all see the same number,
            //   - gas debits / value transfers inside the EVM reduce the
            //     native balance, and
            //   - no duplicate/shadow balance view can drift out of sync.
            for entry in self.dirty_balance.iter() {
                let addr = entry.key();
                if let Some(balance) = self.balance_cache.get(addr) {
                    let balance_bytes = balance.value().to_le_bytes().to_vec();

                    // Single canonical home: the native TNZO ledger
                    // (CF_ACCOUNTS). No CF_STATE mirror — the state root is
                    // computed from the in-memory caches and every balance read
                    // goes through CF_ACCOUNTS, so a second on-disk copy could
                    // only drift.
                    ops.push(WriteOp::Put {
                        cf: CF_ACCOUNTS.to_string(),
                        key: tnzo_balance_key(addr),
                        value: balance_bytes,
                    });
                }
            }

            // Write dirty nonce entries.
            //
            // Like balance, the account nonce has a single canonical home in
            // CF_ACCOUNTS under `b"nonce:" + <address bytes>` — byte-identical
            // to `AccountStoreImpl`'s key + value layout (raw u64 LE == bincode
            // default u64). The VM is the only writer of execution nonces, so
            // mirroring here makes `eth_getTransactionCount` / faucet / signing
            // (which read through `AccountStore` over CF_ACCOUNTS) observe the
            // exact nonce the VM enforced on the last applied transaction.
            for entry in self.dirty_nonce.iter() {
                let addr = entry.key();
                if let Some(nonce) = self.nonce_cache.get(addr) {
                    let nonce_bytes = nonce.value().to_le_bytes().to_vec();

                    // Single canonical home: CF_ACCOUNTS, AccountStore layout —
                    // no CF_STATE mirror (see balance rationale above).
                    let mut canonical_key = b"nonce:".to_vec();
                    canonical_key.extend_from_slice(addr);
                    ops.push(WriteOp::Put {
                        cf: CF_ACCOUNTS.to_string(),
                        key: canonical_key,
                        value: nonce_bytes,
                    });
                }
            }

            // Write dirty storage entries
            for entry in self.dirty_storage.iter() {
                let addr = entry.key();
                let dirty_keys = entry.value();
                if let Some(storage_map) = self.storage_cache.get(addr) {
                    for dirty_entry in dirty_keys.iter() {
                        let storage_key = dirty_entry.key();
                        if let Some(value) = storage_map.get(storage_key) {
                            let key = format!(
                                "storage:{}:{}",
                                hex::encode(addr),
                                hex::encode(storage_key)
                            );
                            ops.push(WriteOp::Put {
                                cf: CF_STATE.to_string(),
                                key: key.into_bytes(),
                                value: value.value().clone(),
                            });
                        }
                    }
                }
            }

            if !ops.is_empty() {
                // Use sync write for durability
                store.write_batch_sync(ops)?;

                tracing::debug!(
                    "Wrote {} state entries to RocksDB",
                    dirty_code_count
                        + dirty_balance_count
                        + dirty_nonce_count
                        + dirty_storage_count
                );
            }
        }

        // Clear dirty flags
        self.dirty_code.clear();
        self.dirty_storage.clear();
        self.dirty_balance.clear();
        self.dirty_nonce.clear();

        Ok(())
    }

    /// Opens an undo log for one transaction.
    ///
    /// Every mutation from here until [`Self::commit_transaction`] or
    /// [`Self::revert_transaction`] records the value it displaced. Nesting is
    /// not supported and would silently discard the outer log, so an already
    /// open journal is left alone and reported.
    pub fn begin_transaction(&self) -> bool {
        let mut j = self.journal.write();
        if j.is_some() {
            tracing::warn!("begin_transaction called with a journal already open");
            return false;
        }
        *j = Some(Vec::new());
        true
    }

    /// Accepts the transaction's mutations and closes the undo log.
    pub fn commit_transaction(&self) {
        *self.journal.write() = None;
    }

    /// Undoes everything the open transaction changed, and nothing else.
    ///
    /// Replayed backwards, so a key written more than once lands on the value
    /// it held before the transaction started rather than an intermediate one.
    /// Earlier transactions in the same block keep their mutations — that is
    /// the whole reason this exists rather than the all-or-nothing `rollback`.
    pub fn revert_transaction(&self) {
        let Some(entries) = self.journal.write().take() else {
            return;
        };
        for entry in entries.into_iter().rev() {
            match entry {
                JournalEntry::Balance(addr, prior) => match prior {
                    Some(v) => {
                        self.balance_cache.insert(addr.clone(), v);
                    }
                    None => {
                        self.balance_cache.remove(&addr);
                        self.dirty_balance.remove(&addr);
                    }
                },
                JournalEntry::Storage(addr, key, prior) => {
                    if let Some(slot) = self.storage_cache.get(&addr) {
                        match prior {
                            Some(v) => {
                                slot.insert(key, v);
                            }
                            None => {
                                slot.remove(&key);
                            }
                        }
                    }
                }
                JournalEntry::Code(addr, prior) => match prior {
                    Some(v) => {
                        self.code_cache.insert(addr.clone(), v);
                    }
                    None => {
                        self.code_cache.remove(&addr);
                        self.dirty_code.remove(&addr);
                    }
                },
            }
        }
    }

    /// Net change in value across every balance the open transaction touched.
    ///
    /// `Some(0)` means value was conserved — moved between accounts, not
    /// created or destroyed. A non-zero result means the transaction minted or
    /// burned, which is legitimate for some paths and a leak for the rest.
    /// `None` means no transaction is open and there is nothing to measure.
    ///
    /// Computed against the *earliest* value recorded for each address, so a
    /// transaction that writes the same balance repeatedly is measured from
    /// where it started rather than from its last intermediate step.
    ///
    /// Must be read before `commit_transaction` or `revert_transaction`, both
    /// of which consume the journal.
    pub fn journal_balance_delta(&self) -> Option<i128> {
        use std::collections::HashMap;

        let guard = self.journal.read();
        let entries = guard.as_ref()?;

        // Earliest displaced value per address.
        let mut before: HashMap<Vec<u8>, Option<u128>> = HashMap::new();
        for entry in entries.iter() {
            if let JournalEntry::Balance(addr, prior) = entry {
                before.entry(addr.clone()).or_insert(*prior);
            }
        }

        let mut delta: i128 = 0;
        for (addr, prior) in before {
            let now = self
                .balance_cache
                .get(&addr)
                .map(|v| *v.value())
                .unwrap_or(0);
            delta += now as i128 - prior.unwrap_or(0) as i128;
        }
        Some(delta)
    }

    /// Records a displaced value when a transaction is open. No-op otherwise.
    fn journal_push(&self, entry: JournalEntry) {
        if let Some(log) = self.journal.write().as_mut() {
            log.push(entry);
        }
    }

    /// Rollback changes (discard cache)
    pub fn rollback(&self) {
        tracing::debug!("Rolling back state changes");
        self.clear();
    }

    /// Get the number of cached entries
    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            code_entries: self.code_cache.len(),
            storage_entries: self
                .storage_cache
                .iter()
                .map(|entry| entry.value().len())
                .sum(),
            balance_entries: self.balance_cache.len(),
            nonce_entries: self.nonce_cache.len(),
        }
    }

    /// Returns a reference to the underlying storage backend, if configured.
    ///
    /// This is used by the revm database adapter to query block hashes from
    /// the block store without duplicating storage handles.
    pub fn kv_store(&self) -> Option<&Arc<dyn KvStore>> {
        self.storage.as_ref()
    }

    /// Flush state to persistent storage
    ///
    /// Serializes all cached state for future integration with RocksDB.
    /// Returns serialized state snapshot.
    pub fn flush_to_storage(&self) -> crate::error::Result<Vec<u8>> {
        tracing::debug!("Flushing state to storage");

        let snapshot = StateSnapshot {
            code: self
                .code_cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().clone()))
                .collect(),
            storage: self
                .storage_cache
                .iter()
                .map(|entry| {
                    let storage_map: Vec<(Vec<u8>, Vec<u8>)> = entry
                        .value()
                        .iter()
                        .map(|inner| (inner.key().clone(), inner.value().clone()))
                        .collect();
                    (entry.key().clone(), storage_map)
                })
                .collect(),
            balances: self
                .balance_cache
                .iter()
                .map(|entry| (entry.key().clone(), *entry.value()))
                .collect(),
            nonces: self
                .nonce_cache
                .iter()
                .map(|entry| (entry.key().clone(), *entry.value()))
                .collect(),
        };

        bincode::serialize(&snapshot).map_err(|e| {
            crate::VmError::StateError(format!("Failed to serialize state snapshot: {}", e))
        })
    }

    /// Load state from persistent storage
    ///
    /// Deserializes state snapshot and populates caches.
    pub fn load_from_storage(&self, data: &[u8]) -> crate::error::Result<()> {
        tracing::debug!("Loading state from storage");

        let snapshot: StateSnapshot = bincode::deserialize(data).map_err(|e| {
            crate::VmError::StateError(format!("Failed to deserialize state snapshot: {}", e))
        })?;

        // Clear existing state
        self.clear();

        // Populate caches
        for (address, code) in snapshot.code {
            self.code_cache.insert(address, code);
        }

        for (address, storage_entries) in snapshot.storage {
            let storage_map = DashMap::new();
            for (key, value) in storage_entries {
                storage_map.insert(key, value);
            }
            self.storage_cache.insert(address, storage_map);
        }

        for (address, balance) in snapshot.balances {
            self.balance_cache.insert(address, balance);
        }

        for (address, nonce) in snapshot.nonces {
            self.nonce_cache.insert(address, nonce);
        }

        tracing::info!(
            "Loaded state from storage: {} accounts",
            self.balance_cache.len()
        );
        Ok(())
    }

    /// Compute state root hash using a Merkle Patricia Trie.
    ///
    /// Each logical state entry is encoded as a canonical key and inserted into
    /// a fresh MPT. The MPT is then committed and the resulting root hash is
    /// returned. Using the MPT means the root is provably bound to the exact
    /// set of state entries — any insertion, deletion or modification produces
    /// a different root and the corresponding proof can be verified by
    /// `MerklePatriciaTrie::verify_proof`.
    ///
    /// Key encoding scheme (prefix ensures different namespaces never collide):
    /// Compute the state root as a Merkle-Patricia-Trie commitment over the
    /// **canonical persistent state**, overlaid with this block's in-flight
    /// (uncommitted) writes.
    ///
    /// The trie is keyed by the *raw on-disk storage key*, namespaced by column
    /// family (`b"A/"` for CF_ACCOUNTS, `b"S/"` for CF_STATE):
    /// - `A/balance:<addr>`  — account balance (16-byte LE u128)
    /// - `A/nonce:<addr>`    — account nonce (8-byte LE u64)
    /// - `S/code:<hex-addr>` — contract code
    /// - `S/storage:<hex-addr>:<hex-slot>` — storage slot
    ///
    /// Committing to the exact bytes RocksDB holds — rather than re-deriving
    /// addresses — means the root is a commitment to precisely what is
    /// persisted, is identical on every node, and **survives restart** (it never
    /// depends on which accounts a given process happens to have cached). The
    /// in-memory maps are a read-through / write-buffer tier only; the root is
    /// never computed from them alone. In-flight dirty writes are overlaid in
    /// their exact eventual on-disk key form (byte-identical to what `commit()`
    /// writes), so a value written this block overrides its committed copy and a
    /// brand-new account is included before it is flushed.
    pub fn compute_state_root(&self) -> Hash {
        use std::collections::BTreeMap;

        // Deterministic, deduplicated key -> value set. Dirty (in-flight)
        // writes are applied last so they override the committed on-disk copy.
        let mut entries: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();

        // 1. Canonical persistent state: hash the account ledger (CF_ACCOUNTS)
        //    and VM state (CF_STATE) by their raw on-disk keys.
        if let Some(store) = &self.storage {
            for (cf, prefix, ns) in [
                (CF_ACCOUNTS, b"balance:".as_ref(), b'A'),
                (CF_ACCOUNTS, b"nonce:".as_ref(), b'A'),
                (CF_STATE, b"code:".as_ref(), b'S'),
                (CF_STATE, b"storage:".as_ref(), b'S'),
            ] {
                let _ = store.scan_prefix_for_each(cf, prefix, &mut |k, v| {
                    let mut tk = Vec::with_capacity(2 + k.len());
                    tk.push(ns);
                    tk.push(b'/');
                    tk.extend_from_slice(k);
                    entries.insert(tk, v.to_vec());
                    Ok(())
                });
            }
        }

        // 2. Overlay in-flight writes in their exact on-disk key form so the
        //    root reflects post-execution state before `commit()` flushes it.
        for entry in self.balance_cache.iter() {
            let dk = tnzo_balance_key(entry.key());
            let mut tk = vec![b'A', b'/'];
            tk.extend_from_slice(&dk);
            entries.insert(tk, entry.value().to_le_bytes().to_vec());
        }
        for entry in self.nonce_cache.iter() {
            let mut tk = vec![b'A', b'/'];
            tk.extend_from_slice(b"nonce:");
            tk.extend_from_slice(entry.key());
            entries.insert(tk, entry.value().to_le_bytes().to_vec());
        }
        for entry in self.code_cache.iter() {
            let dk = format!("code:{}", hex::encode(entry.key())).into_bytes();
            let mut tk = vec![b'S', b'/'];
            tk.extend_from_slice(&dk);
            entries.insert(tk, entry.value().clone());
        }
        for entry in self.storage_cache.iter() {
            let addr = entry.key();
            for slot in entry.value().iter() {
                let dk = format!("storage:{}:{}", hex::encode(addr), hex::encode(slot.key()))
                    .into_bytes();
                let mut tk = vec![b'S', b'/'];
                tk.extend_from_slice(&dk);
                entries.insert(tk, slot.value().clone());
            }
        }

        // 3. Build the trie from the merged, sorted entry set.
        let mut trie = MerklePatriciaTrie::new();
        for (k, v) in &entries {
            if let Err(e) = trie.insert(k, v) {
                tracing::warn!("MPT insert failed during state root computation: {}", e);
            }
        }
        match trie.commit() {
            Ok(root) => root,
            Err(e) => {
                tracing::error!("MPT commit failed during state root computation: {}", e);
                Hash::zero()
            }
        }
    }

    /// Warm the balance / nonce / code / storage caches for the accounts and
    /// slots a block is statically known to touch, before the Block-STM loop
    /// runs.
    ///
    /// Each `read_through_*` call below already populates the corresponding
    /// cache on a RocksDB hit, so a plain read is the warm. Deltas fold onto
    /// the pre-block base read here, and the parallel executor's per-tx reads
    /// then hit the cache instead of RocksDB — moving the I/O off the
    /// execution critical path.
    ///
    /// The keys come from static transaction fields (`from` / `to`) plus any
    /// caller-supplied access-list slots (`PrefetchKeys::storage`). There is no
    /// correctness coupling: prefetching an account that is never read, or
    /// missing one that is, only changes cache-hit rates, never results. A cold
    /// read during execution still falls through to RocksDB.
    pub fn prefetch(&self, keys: &PrefetchKeys) {
        // No backend → caches are the only tier; nothing to warm.
        if self.storage.is_none() {
            return;
        }
        for addr in &keys.accounts {
            // Reads that miss the cache populate it from CF_ACCOUNTS / CF_STATE.
            let _ = self.get_balance(addr);
            let _ = self.get_nonce(addr);
            let _ = self.get_code(addr);
        }
        for (addr, key) in &keys.storage {
            let _ = self.get_storage(addr, key);
        }
    }

    /// Warm the caches on a background pool so the block's execution thread is
    /// not blocked on RocksDB I/O. Clones the `Arc`-backed cache handles into a
    /// detached task; the caches are shared, so warming there is visible to the
    /// executor. Requires a Tokio runtime context (the node always has one).
    ///
    /// Returns immediately. Any slot the task has not finished warming by the
    /// time the executor reaches it simply takes the RocksDB fall-through path —
    /// no correctness coupling, only a cache-hit-rate effect.
    pub fn prefetch_async(self: &Arc<Self>, keys: PrefetchKeys) {
        let adapter = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            adapter.prefetch(&keys);
        });
    }
}

/// Static set of accounts and storage slots a block is known to touch, used to
/// warm the [`StateAdapter`] caches ahead of Block-STM execution.
///
/// Built from transaction `from` / `to` fields and any EVM access-list slots
/// the caller can supply. Purely an I/O hint — see [`StateAdapter::prefetch`].
#[derive(Debug, Clone, Default)]
pub struct PrefetchKeys {
    /// Account addresses to warm (balance + nonce + code).
    pub accounts: Vec<Vec<u8>>,
    /// Storage slots to warm: `(address, key)`.
    pub storage: Vec<(Vec<u8>, Vec<u8>)>,
}

impl PrefetchKeys {
    /// Empty prefetch set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an account address to warm.
    pub fn add_account(&mut self, address: &[u8]) {
        self.accounts.push(address.to_vec());
    }

    /// Add a storage slot to warm.
    pub fn add_storage(&mut self, address: &[u8], key: &[u8]) {
        self.storage.push((address.to_vec(), key.to_vec()));
    }

    /// Collect the statically-known touched accounts from a batch of VM
    /// transactions — each tx contributes its `from` and (when present) `to`.
    /// This is the reliable static hint for the EVM/SVM (bytecode-decided
    /// write sets are not knowable pre-execution); callers with an EVM
    /// access-list add those slots via [`Self::add_storage`].
    pub fn from_transactions(txs: &[crate::types::VmTransaction]) -> Self {
        let mut keys = Self::new();
        for tx in txs {
            keys.add_account(&tx.from);
            if let Some(to) = &tx.to {
                keys.add_account(to);
            }
        }
        keys
    }
}

/// The `StateAdapter` is the pre-block base a commutative delta lane folds onto.
/// `base_balance` / `base_storage` read through the cache (warmed by
/// [`StateAdapter::prefetch`]) then RocksDB — the exact values the block started
/// from, before any in-block delta or write.
impl BaseState for StateAdapter {
    fn base_balance(&self, address: &[u8]) -> u128 {
        self.get_balance(address)
    }

    fn base_storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        self.get_storage(address, key)
    }
}

impl Default for StateAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl VmState for StateAdapter {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }

    fn get_code(&self, address: &[u8]) -> Option<Vec<u8>> {
        // Check cache first
        if let Some(entry) = self.code_cache.get(address) {
            return Some(entry.value().clone());
        }

        // Fall back to RocksDB
        if let Some(store) = &self.storage {
            let key = format!("code:{}", hex::encode(address));
            if let Ok(Some(code)) = store.get(CF_STATE, key.as_bytes()) {
                // Populate cache
                self.code_cache.insert(address.to_vec(), code.clone());
                return Some(code);
            }
        }

        None
    }

    fn set_code(&mut self, address: &[u8], code: Vec<u8>) {
        self.journal_push(JournalEntry::Code(
            address.to_vec(),
            self.code_cache.get(address).map(|v| v.value().clone()),
        ));
        self.code_cache.insert(address.to_vec(), code);
        self.dirty_code.insert(address.to_vec(), true);
    }

    fn get_storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        // Check cache first
        if let Some(storage) = self.storage_cache.get(address)
            && let Some(entry) = storage.get(key)
        {
            return Some(entry.value().clone());
        }

        // Fall back to RocksDB
        if let Some(store) = &self.storage {
            let db_key = format!("storage:{}:{}", hex::encode(address), hex::encode(key));
            if let Ok(Some(value)) = store.get(CF_STATE, db_key.as_bytes()) {
                // Populate cache
                let storage = self.storage_cache.entry(address.to_vec()).or_default();
                storage.insert(key.to_vec(), value.clone());
                return Some(value);
            }
        }

        None
    }

    fn set_storage(&mut self, address: &[u8], key: &[u8], value: Vec<u8>) {
        self.journal_push(JournalEntry::Storage(
            address.to_vec(),
            key.to_vec(),
            self.storage_cache
                .get(address)
                .and_then(|s| s.get(key).map(|v| v.value().clone())),
        ));
        let storage = self.storage_cache.entry(address.to_vec()).or_default();
        storage.insert(key.to_vec(), value);

        let dirty = self.dirty_storage.entry(address.to_vec()).or_default();
        dirty.insert(key.to_vec(), true);
    }

    fn get_balance(&self, address: &[u8]) -> u128 {
        // Check cache first
        if let Some(entry) = self.balance_cache.get(address) {
            return *entry.value();
        }

        // In the Sei V2 pointer model, the native TNZO ledger (managed by
        // `tenzro_token::tnzo::TnzoToken`, persisted to CF_ACCOUNTS under
        // `b"balance:" + <32-byte address>`) is the single source of truth
        // for account balances. revm's `Database::basic()` and the SVM
        // executor both call through here, so reading from CF_ACCOUNTS with
        // the canonical key ensures the EVM/SVM execution context sees the
        // same balance as `eth_getBalance` / `tenzro_getBalance` and the
        // faucet credit path.
        if let Some(store) = &self.storage {
            // Canonical and only home: native TNZO ledger (CF_ACCOUNTS).
            let native_key = tnzo_balance_key(address);
            if let Ok(Some(bytes)) = store.get(CF_ACCOUNTS, &native_key)
                && bytes.len() == 16
                && let Ok(arr) = bytes.as_slice().try_into()
            {
                let balance = u128::from_le_bytes(arr);
                self.balance_cache.insert(address.to_vec(), balance);
                return balance;
            }
        }

        0
    }

    fn set_balance(&mut self, address: &[u8], balance: u128) {
        self.journal_push(JournalEntry::Balance(
            address.to_vec(),
            self.balance_cache.get(address).map(|v| *v.value()),
        ));
        self.balance_cache.insert(address.to_vec(), balance);
        self.dirty_balance.insert(address.to_vec(), true);
    }

    fn get_nonce(&self, address: &[u8]) -> u64 {
        // Check cache first
        if let Some(entry) = self.nonce_cache.get(address) {
            return *entry.value();
        }

        // Fall back to RocksDB, canonical store first (same order as balance).
        if let Some(store) = &self.storage {
            // Canonical and only home: account ledger (CF_ACCOUNTS layout).
            let mut canonical_key = b"nonce:".to_vec();
            canonical_key.extend_from_slice(address);
            if let Ok(Some(bytes)) = store.get(CF_ACCOUNTS, &canonical_key)
                && bytes.len() == 8
                && let Ok(arr) = bytes.as_slice().try_into()
            {
                let nonce = u64::from_le_bytes(arr);
                self.nonce_cache.insert(address.to_vec(), nonce);
                return nonce;
            }
        }

        0
    }

    fn set_nonce(&mut self, address: &[u8], nonce: u64) {
        // Deliberately not journalled: the nonce survives a revert.
        //
        // A failed transaction must still consume its nonce, or the identical
        // transaction can be submitted again — same sender, same nonce, same
        // hash. ethermint shipped the reverting version (#808) and got exactly
        // that: two transactions sharing a hash, and a replay window. It is
        // also what turns this chain's documented unsatisfiable-nonce retry
        // loop from a bug into the specified behaviour.
        self.nonce_cache.insert(address.to_vec(), nonce);
        self.dirty_nonce.insert(address.to_vec(), true);
    }

    fn exists(&self, address: &[u8]) -> bool {
        self.get_code(address).is_some()
            || self.get_balance(address) > 0
            || self.get_nonce(address) > 0
    }
}

impl PersistentState for StateAdapter {
    fn get_account_code(&self, address: &[u8]) -> Option<Vec<u8>> {
        self.get_code(address)
    }

    fn set_account_code(&mut self, address: &[u8], code: Vec<u8>) {
        self.set_code(address, code);
    }

    fn get_storage_value(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>> {
        self.get_storage(address, key)
    }

    fn set_storage_value(&mut self, address: &[u8], key: &[u8], value: Vec<u8>) {
        self.set_storage(address, key, value);
    }

    fn commit_changes(&mut self) -> crate::error::Result<Hash> {
        // Compute state root before clearing dirty flags
        let state_root = self.compute_state_root();

        // Commit would write to RocksDB here
        self.commit()?;

        Ok(state_root)
    }

    fn flush(&self) -> crate::error::Result<Vec<u8>> {
        self.flush_to_storage()
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of code entries
    pub code_entries: usize,

    /// Number of storage entries
    pub storage_entries: usize,

    /// Number of balance entries
    pub balance_entries: usize,

    /// Number of nonce entries
    pub nonce_entries: usize,
}

/// Persistent state trait
///
/// Defines methods for persisting VM state to storage.
/// In production, this would integrate with tenzro-storage's RocksDB backend.
pub trait PersistentState {
    /// Get account code
    fn get_account_code(&self, address: &[u8]) -> Option<Vec<u8>>;

    /// Set account code
    fn set_account_code(&mut self, address: &[u8], code: Vec<u8>);

    /// Get storage value
    fn get_storage_value(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>>;

    /// Set storage value
    fn set_storage_value(&mut self, address: &[u8], key: &[u8], value: Vec<u8>);

    /// Commit all pending changes and return state root
    fn commit_changes(&mut self) -> crate::error::Result<Hash>;

    /// Flush state to persistent backend (e.g., RocksDB)
    fn flush(&self) -> crate::error::Result<Vec<u8>>;
}

/// State snapshot for serialization
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSnapshot {
    /// Contract code: address -> bytecode
    code: Vec<(Vec<u8>, Vec<u8>)>,

    /// Storage: address -> (key -> value)
    storage: Vec<(Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)>,

    /// Balances: address -> balance
    balances: Vec<(Vec<u8>, u128)>,

    /// Nonces: address -> nonce
    nonces: Vec<(Vec<u8>, u64)>,
}

#[cfg(test)]
mod atomicity_tests {
    use super::*;
    use crate::traits::VmState;

    fn addr(b: u8) -> Vec<u8> {
        vec![b; 20]
    }

    /// A reverted transaction returns the sender's money.
    ///
    /// This is the shape that lost 10,000,000 TNZO on the live chain: the
    /// sender was debited, the transaction then failed, and nothing put the
    /// balance back. The funds sat in the vault credited to nobody.
    #[test]
    fn a_reverted_transaction_returns_the_debit() {
        let mut a = StateAdapter::new();
        let sender = addr(1);
        let vault = addr(0xFE);
        a.set_balance(&sender, 10_000_000);

        assert!(a.begin_transaction());
        a.set_balance(&sender, 0);
        a.set_balance(&vault, 10_000_000);
        a.revert_transaction();

        assert_eq!(
            a.get_balance(&sender),
            10_000_000,
            "the sender was not made whole by the revert"
        );
        assert_eq!(a.get_balance(&vault), 0, "the vault kept a credit for a failed transfer");
    }

    /// Reverting one transaction must not undo the ones before it in the block.
    ///
    /// The pre-existing `rollback` clears the whole cache, which is why it
    /// could never be used here — one bad transaction would have erased every
    /// good one sharing the block.
    #[test]
    fn a_revert_leaves_earlier_transactions_alone() {
        let mut a = StateAdapter::new();
        let first = addr(1);
        let second = addr(2);

        // A transaction that succeeds.
        assert!(a.begin_transaction());
        a.set_balance(&first, 500);
        a.commit_transaction();

        // A transaction that fails.
        assert!(a.begin_transaction());
        a.set_balance(&second, 900);
        a.revert_transaction();

        assert_eq!(a.get_balance(&first), 500, "a committed transaction was undone");
        assert_eq!(a.get_balance(&second), 0, "a reverted transaction persisted");
    }

    /// Repeated writes to one key revert to the value from before the
    /// transaction, not to an intermediate one.
    #[test]
    fn repeated_writes_revert_to_the_pre_transaction_value() {
        let mut a = StateAdapter::new();
        let who = addr(3);
        a.set_balance(&who, 100);

        assert!(a.begin_transaction());
        a.set_balance(&who, 50);
        a.set_balance(&who, 25);
        a.set_balance(&who, 0);
        a.revert_transaction();

        assert_eq!(a.get_balance(&who), 100);
    }

    /// A key that did not exist goes back to not existing.
    ///
    /// Restoring a zero instead would invent a balance that was never written,
    /// and nothing downstream could tell the difference.
    #[test]
    fn a_key_absent_before_the_transaction_is_absent_after_revert() {
        let mut a = StateAdapter::new();
        let fresh = addr(4);

        assert!(a.begin_transaction());
        a.set_balance(&fresh, 777);
        a.set_nonce(&fresh, 3);
        a.revert_transaction();

        assert_eq!(a.get_balance(&fresh), 0);
        assert!(!a.balance_cache.contains_key(&fresh), "an absent key was resurrected as zero");
        // The nonce is deliberately outside the revert boundary — see set_nonce.
        assert_eq!(a.get_nonce(&fresh), 3, "the nonce must survive so the tx cannot replay");
    }

    /// Storage reverts; the nonce does not.
    ///
    /// A failed transaction still consumes its nonce, otherwise the identical
    /// transaction can be resubmitted with the same hash — ethermint #808.
    #[test]
    fn storage_reverts_but_the_nonce_survives() {
        let mut a = StateAdapter::new();
        let who = addr(5);
        a.set_nonce(&who, 7);
        a.set_storage(&who, b"k", b"before".to_vec());

        assert!(a.begin_transaction());
        a.set_nonce(&who, 8);
        a.set_storage(&who, b"k", b"after".to_vec());
        a.revert_transaction();

        assert_eq!(a.get_nonce(&who), 8, "the nonce was rolled back, enabling replay");
        assert_eq!(a.get_storage(&who, b"k"), Some(b"before".to_vec()));
    }

    /// A transfer moves value; it does not create any.
    #[test]
    fn a_balanced_transfer_reports_zero_delta() {
        let mut a = StateAdapter::new();
        let from = addr(1);
        let to = addr(2);
        a.set_balance(&from, 1_000);

        assert!(a.begin_transaction());
        a.set_balance(&from, 400);
        a.set_balance(&to, 600);
        assert_eq!(a.journal_balance_delta(), Some(0));
        a.commit_transaction();
    }

    /// The shape that lost the money: a debit with no matching credit.
    ///
    /// 10,000,000 left an account and nothing anywhere gained it. The delta is
    /// exactly the missing amount, and negative because value was destroyed
    /// rather than moved.
    #[test]
    fn a_debit_with_no_credit_is_reported_as_a_loss() {
        let mut a = StateAdapter::new();
        let from = addr(1);
        a.set_balance(&from, 10_000_000);

        assert!(a.begin_transaction());
        a.set_balance(&from, 0); // debited, credited nowhere
        assert_eq!(a.journal_balance_delta(), Some(-10_000_000));
        a.revert_transaction();
    }

    /// Value appearing from nowhere is caught the same way, with the opposite
    /// sign.
    #[test]
    fn a_credit_with_no_debit_is_reported_as_a_mint() {
        let mut a = StateAdapter::new();
        let to = addr(2);

        assert!(a.begin_transaction());
        a.set_balance(&to, 5_000);
        assert_eq!(a.journal_balance_delta(), Some(5_000));
        a.revert_transaction();
    }

    /// Repeated writes are measured from where the transaction started, not
    /// from the last intermediate value.
    #[test]
    fn the_delta_is_measured_from_the_pre_transaction_value() {
        let mut a = StateAdapter::new();
        let who = addr(3);
        a.set_balance(&who, 100);

        assert!(a.begin_transaction());
        a.set_balance(&who, 90);
        a.set_balance(&who, 80);
        a.set_balance(&who, 70);
        assert_eq!(a.journal_balance_delta(), Some(-30));
        a.revert_transaction();
    }

    /// Nothing to measure when no transaction is open.
    #[test]
    fn there_is_no_delta_without_an_open_transaction() {
        let a = StateAdapter::new();
        assert_eq!(a.journal_balance_delta(), None);
    }

    /// With no transaction open, behaviour is exactly as before.
    #[test]
    fn mutations_outside_a_transaction_are_unaffected() {
        let mut a = StateAdapter::new();
        let who = addr(6);
        a.set_balance(&who, 42);
        a.revert_transaction(); // no journal open — must do nothing
        assert_eq!(a.get_balance(&who), 42);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    #[test]
    fn test_state_adapter_code() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        let code = vec![0x60, 0x80, 0x60, 0x40]; // Some bytecode

        assert_eq!(adapter.get_code(&address), None);

        adapter.set_code(&address, code.clone());
        assert_eq!(adapter.get_code(&address), Some(code));
    }

    #[test]
    fn test_state_adapter_storage() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        let key = vec![0u8; 32];
        let value = vec![1, 2, 3, 4];

        assert_eq!(adapter.get_storage(&address, &key), None);

        adapter.set_storage(&address, &key, value.clone());
        assert_eq!(adapter.get_storage(&address, &key), Some(value));
    }

    #[test]
    fn test_state_adapter_balance() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];

        assert_eq!(adapter.get_balance(&address), 0);

        adapter.set_balance(&address, 1000);
        assert_eq!(adapter.get_balance(&address), 1000);
    }

    #[test]
    fn test_state_adapter_nonce() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];

        assert_eq!(adapter.get_nonce(&address), 0);

        adapter.set_nonce(&address, 5);
        assert_eq!(adapter.get_nonce(&address), 5);
    }

    #[test]
    fn test_commit_rollback() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        adapter.set_balance(&address, 1000);

        adapter.commit().unwrap();

        // After commit, cache should still have the value
        assert_eq!(adapter.get_balance(&address), 1000);

        adapter.set_balance(&address, 2000);
        adapter.rollback();

        // After rollback, cache should be cleared
        assert_eq!(adapter.get_balance(&address), 0);
    }

    #[test]
    fn test_flush_and_load() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        let code = vec![0x60, 0x80];

        adapter.set_balance(&address, 5000);
        adapter.set_nonce(&address, 10);
        adapter.set_code(&address, code.clone());

        // Flush to bytes
        let snapshot = adapter.flush_to_storage().unwrap();
        assert!(!snapshot.is_empty());

        // Create new adapter and load
        let adapter2 = StateAdapter::new();
        adapter2.load_from_storage(&snapshot).unwrap();

        assert_eq!(adapter2.get_balance(&address), 5000);
        assert_eq!(adapter2.get_nonce(&address), 10);
        assert_eq!(adapter2.get_code(&address), Some(code));
    }

    #[test]
    fn test_compute_state_root() {
        let mut adapter = StateAdapter::new();

        let address1 = vec![1u8; 20];
        let address2 = vec![2u8; 20];

        adapter.set_balance(&address1, 1000);
        adapter.set_balance(&address2, 2000);

        let root1 = adapter.compute_state_root();

        // Change state
        adapter.set_balance(&address1, 1500);
        let root2 = adapter.compute_state_root();

        // State roots should be different
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_persistent_state_trait() {
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        let code = vec![0x60, 0x80];

        adapter.set_account_code(&address, code.clone());
        assert_eq!(adapter.get_account_code(&address), Some(code));

        let key = vec![0u8; 32];
        let value = vec![1, 2, 3];
        adapter.set_storage_value(&address, &key, value.clone());
        assert_eq!(adapter.get_storage_value(&address, &key), Some(value));

        // Commit and get state root
        let state_root = adapter.commit_changes().unwrap();
        assert_eq!(state_root.0.len(), 32);
    }

    #[test]
    fn test_with_storage_persistence() {
        // Create a MemoryStore for testing
        let store = Arc::new(MemoryStore::new());
        let mut adapter = StateAdapter::with_storage(store);

        let address = vec![1u8; 20];
        let code = vec![0x60, 0x80, 0x60, 0x40];

        // Set some state
        adapter.set_code(&address, code.clone());
        adapter.set_balance(&address, 5000);
        adapter.set_nonce(&address, 10);

        let key = vec![0u8; 32];
        let value = vec![1, 2, 3, 4];
        adapter.set_storage(&address, &key, value.clone());

        // Commit to storage
        adapter.commit().unwrap();

        // Clear caches to force reading from storage
        adapter.code_cache.clear();
        adapter.balance_cache.clear();
        adapter.nonce_cache.clear();
        adapter.storage_cache.clear();

        // Verify data can be read from storage
        assert_eq!(adapter.get_code(&address), Some(code));
        assert_eq!(adapter.get_balance(&address), 5000);
        assert_eq!(adapter.get_nonce(&address), 10);
        assert_eq!(adapter.get_storage(&address, &key), Some(value));
    }

    #[test]
    fn test_storage_fallback() {
        // Create a MemoryStore
        let store = Arc::new(MemoryStore::new());
        let adapter = StateAdapter::with_storage(store.clone());

        let address = vec![1u8; 20];

        // Manually write to storage bypassing the adapter, using the
        // canonical CF_ACCOUNTS key. There is no second location to read
        // from — CF_ACCOUNTS is the only home for a balance.
        let balance: u128 = 99999;
        store
            .put(
                CF_ACCOUNTS,
                &tnzo_balance_key(&address),
                &balance.to_le_bytes(),
            )
            .unwrap();

        // Adapter should read from storage on cache miss
        assert_eq!(adapter.get_balance(&address), 99999);

        // Value should now be cached
        assert!(adapter.balance_cache.contains_key(&address));
    }

    #[test]
    fn test_batch_commit() {
        let store = Arc::new(MemoryStore::new());
        let mut adapter = StateAdapter::with_storage(store);

        // Create multiple accounts
        for i in 0..10 {
            let mut address = vec![0u8; 20];
            address[19] = i;
            adapter.set_balance(&address, (i as u128) * 1000);
            adapter.set_nonce(&address, i as u64);
        }

        // Commit all at once
        adapter.commit().unwrap();

        // Clear cache
        adapter.balance_cache.clear();
        adapter.nonce_cache.clear();

        // Verify all were written
        for i in 0..10 {
            let mut address = vec![0u8; 20];
            address[19] = i;
            assert_eq!(adapter.get_balance(&address), (i as u128) * 1000);
            assert_eq!(adapter.get_nonce(&address), i as u64);
        }
    }

    #[test]
    fn test_storage_persistence() {
        let store = Arc::new(MemoryStore::new());
        let mut adapter = StateAdapter::with_storage(store);

        let contract = vec![5u8; 20];

        // Set multiple storage slots
        for i in 0..5 {
            let mut key = vec![0u8; 32];
            key[31] = i;
            let mut value = vec![0u8; 32];
            value[31] = i * 10;
            adapter.set_storage(&contract, &key, value);
        }

        // Commit
        adapter.commit().unwrap();

        // Clear cache
        adapter.storage_cache.clear();

        // Verify all storage slots were persisted
        for i in 0..5 {
            let mut key = vec![0u8; 32];
            key[31] = i;
            let mut expected_value = vec![0u8; 32];
            expected_value[31] = i * 10;
            assert_eq!(adapter.get_storage(&contract, &key), Some(expected_value));
        }
    }

    #[test]
    fn test_prefetch_warms_caches_from_rocksdb() {
        let store = Arc::new(MemoryStore::new());
        let adapter = StateAdapter::with_storage(store.clone());

        let addr = vec![7u8; 20];
        // Seed the backend directly, bypassing the adapter, so the only way
        // the cache gets the value is via a read-through.
        let balance: u128 = 42_000;
        store
            .put(CF_ACCOUNTS, &tnzo_balance_key(&addr), &balance.to_le_bytes())
            .unwrap();

        // Cold: not yet cached.
        assert!(!adapter.balance_cache.contains_key(&addr));

        let mut keys = PrefetchKeys::new();
        keys.add_account(&addr);
        adapter.prefetch(&keys);

        // Warm: the balance is now resident, so execution reads hit the cache.
        assert!(adapter.balance_cache.contains_key(&addr));
        assert_eq!(adapter.get_balance(&addr), 42_000);
    }

    #[test]
    fn test_prefetch_keys_from_transactions() {
        use crate::VmType;
        use crate::types::VmTransaction;

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];
        let tx = VmTransaction {
            from: from.clone(),
            to: Some(to.clone()),
            value: 0,
            data: Vec::new(),
            gas_limit: 21_000,
            gas_price: 1,
            nonce: 0,
            vm_type: VmType::Evm,
            chain_id: 1337,
            signature: None,
            public_key: None,
            signing_digest: None,
            block_timestamp_ms: None,
        };

        let keys = PrefetchKeys::from_transactions(std::slice::from_ref(&tx));
        assert!(keys.accounts.contains(&from));
        assert!(keys.accounts.contains(&to));
    }

    #[test]
    fn test_state_adapter_is_base_state() {
        let store = Arc::new(MemoryStore::new());
        let mut adapter = StateAdapter::with_storage(store);

        let addr = vec![9u8; 20];
        let key = vec![3u8; 32];
        adapter.set_balance(&addr, 1234);
        adapter.set_storage(&addr, &key, vec![5, 6, 7]);

        // BaseState reads the pre-block values a delta lane folds onto.
        assert_eq!(BaseState::base_balance(&adapter, &addr), 1234);
        assert_eq!(
            BaseState::base_storage(&adapter, &addr, &key),
            Some(vec![5, 6, 7])
        );
    }

    #[test]
    fn test_prefetch_no_storage_is_noop() {
        // No backend → prefetch does nothing and must not panic.
        let adapter = StateAdapter::new();
        let mut keys = PrefetchKeys::new();
        keys.add_account(&[1u8; 20]);
        keys.add_storage(&[1u8; 20], &[0u8; 32]);
        adapter.prefetch(&keys);
    }

    #[test]
    fn test_no_storage_mode() {
        // Adapter without storage should work but not persist
        let mut adapter = StateAdapter::new();

        let address = vec![1u8; 20];
        adapter.set_balance(&address, 1000);

        // Commit should succeed even without storage
        adapter.commit().unwrap();

        // Value still in cache
        assert_eq!(adapter.get_balance(&address), 1000);

        // Clear cache
        adapter.balance_cache.clear();

        // Value lost (no persistence)
        assert_eq!(adapter.get_balance(&address), 0);
    }

    /// Regression: the state root must commit to the *canonical persistent
    /// state* (CF_ACCOUNTS), not the in-memory cache. Genesis writes balances
    /// straight to disk, and a node restart starts with empty caches — the old
    /// cache-only `compute_state_root` returned an empty-trie root in both
    /// cases, so post-genesis blocks (and every block after a restart) carried
    /// a meaningless state root.
    #[test]
    fn state_root_commits_to_persistent_state_not_cache() {
        let store = Arc::new(MemoryStore::new());

        // Simulate genesis: write balances directly to CF_ACCOUNTS, bypassing
        // the adapter's caches entirely.
        let addr_a = vec![0xAAu8; 32];
        let addr_b = vec![0xBBu8; 32];
        let mut kbal_a = b"balance:".to_vec();
        kbal_a.extend_from_slice(&addr_a);
        let mut kbal_b = b"balance:".to_vec();
        kbal_b.extend_from_slice(&addr_b);
        store
            .put(CF_ACCOUNTS, &kbal_a, &1_000_000u128.to_le_bytes())
            .unwrap();
        store
            .put(CF_ACCOUNTS, &kbal_b, &42u128.to_le_bytes())
            .unwrap();

        // A fresh adapter (empty caches, as after a restart) MUST still root the
        // on-disk state — this is the exact bug that produced a zero root.
        let cold = StateAdapter::with_storage(store.clone());
        let root_cold = cold.compute_state_root();
        assert_ne!(
            root_cold,
            Hash::zero(),
            "state root must reflect on-disk balances even with empty caches"
        );

        // Deterministic and restart-stable: a second independent adapter over
        // the same store yields the identical root.
        let cold2 = StateAdapter::with_storage(store.clone());
        assert_eq!(
            root_cold,
            cold2.compute_state_root(),
            "state root must be deterministic and survive restart"
        );

        // It truly commits to state: mutating a persisted balance changes it.
        store
            .put(CF_ACCOUNTS, &kbal_b, &99u128.to_le_bytes())
            .unwrap();
        assert_ne!(
            root_cold,
            StateAdapter::with_storage(store.clone()).compute_state_root(),
            "state root must change when persistent state changes"
        );

        // In-flight (uncommitted) cache writes overlay disk, and the pre-commit
        // root equals the post-commit disk root — the write buffer and the
        // canonical store agree.
        let mut warm = StateAdapter::with_storage(store.clone());
        let base = warm.compute_state_root();
        warm.set_balance(&[0xCCu8; 32], 7);
        let with_overlay = warm.compute_state_root();
        assert_ne!(base, with_overlay, "in-flight write must affect the root");
        warm.commit().unwrap();
        assert_eq!(
            with_overlay,
            StateAdapter::with_storage(store.clone()).compute_state_root(),
            "pre-commit overlay root must equal the post-commit disk root"
        );
    }
}
