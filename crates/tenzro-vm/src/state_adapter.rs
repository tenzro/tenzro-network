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
pub struct StateAdapter {
    /// Account code cache
    code_cache: Arc<DashMap<Vec<u8>, Vec<u8>>>,

    /// Storage cache: address -> key -> value
    storage_cache: Arc<DashMap<Vec<u8>, DashMap<Vec<u8>, Vec<u8>>>>,

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
            //
            // We also mirror-write the legacy CF_STATE key so existing
            // snapshots, MPT state-root proofs, and unit tests that insert
            // fixtures under `CF_STATE:balance:<hex>` continue to work.
            for entry in self.dirty_balance.iter() {
                let addr = entry.key();
                if let Some(balance) = self.balance_cache.get(addr) {
                    let balance_bytes = balance.value().to_le_bytes().to_vec();

                    // Canonical: native TNZO ledger (CF_ACCOUNTS)
                    ops.push(WriteOp::Put {
                        cf: CF_ACCOUNTS.to_string(),
                        key: tnzo_balance_key(addr),
                        value: balance_bytes.clone(),
                    });

                    // Mirror: legacy VM state key (CF_STATE) for back-compat
                    let legacy_key = format!("balance:{}", hex::encode(addr));
                    ops.push(WriteOp::Put {
                        cf: CF_STATE.to_string(),
                        key: legacy_key.into_bytes(),
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
            // exact nonce the VM enforced on the last applied transaction. The
            // legacy CF_STATE `nonce:<hex>` key is also kept so VM-internal
            // reads and historical snapshots stay valid.
            for entry in self.dirty_nonce.iter() {
                let addr = entry.key();
                if let Some(nonce) = self.nonce_cache.get(addr) {
                    let nonce_bytes = nonce.value().to_le_bytes().to_vec();

                    // Canonical: account ledger (CF_ACCOUNTS), AccountStore layout.
                    let mut canonical_key = b"nonce:".to_vec();
                    canonical_key.extend_from_slice(addr);
                    ops.push(WriteOp::Put {
                        cf: CF_ACCOUNTS.to_string(),
                        key: canonical_key,
                        value: nonce_bytes.clone(),
                    });

                    // Mirror: VM state key (CF_STATE) for VM-internal reads.
                    let legacy_key = format!("nonce:{}", hex::encode(addr));
                    ops.push(WriteOp::Put {
                        cf: CF_STATE.to_string(),
                        key: legacy_key.into_bytes(),
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
    /// - code:    `b"c" || address`
    /// - balance: `b"b" || address`
    /// - nonce:   `b"n" || address`
    /// - storage: `b"s" || address || storage_key`
    pub fn compute_state_root(&self) -> Hash {
        let mut trie = MerklePatriciaTrie::new();

        // Insert code entries
        let mut code_entries: Vec<_> = self
            .code_cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        code_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (addr, code) in &code_entries {
            let mut key = Vec::with_capacity(1 + addr.len());
            key.push(b'c');
            key.extend_from_slice(addr);
            if let Err(e) = trie.insert(&key, code) {
                tracing::warn!("MPT insert (code) failed: {}", e);
            }
        }

        // Insert balance entries
        let mut balance_entries: Vec<_> = self
            .balance_cache
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        balance_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (addr, balance) in &balance_entries {
            let mut key = Vec::with_capacity(1 + addr.len());
            key.push(b'b');
            key.extend_from_slice(addr);
            if let Err(e) = trie.insert(&key, &balance.to_le_bytes()) {
                tracing::warn!("MPT insert (balance) failed: {}", e);
            }
        }

        // Insert nonce entries
        let mut nonce_entries: Vec<_> = self
            .nonce_cache
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect();
        nonce_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (addr, nonce) in &nonce_entries {
            let mut key = Vec::with_capacity(1 + addr.len());
            key.push(b'n');
            key.extend_from_slice(addr);
            if let Err(e) = trie.insert(&key, &nonce.to_le_bytes()) {
                tracing::warn!("MPT insert (nonce) failed: {}", e);
            }
        }

        // Insert storage entries (sorted for determinism)
        let mut storage_entries: Vec<_> = self
            .storage_cache
            .iter()
            .map(|entry| {
                let mut inner: Vec<_> = entry
                    .value()
                    .iter()
                    .map(|e| (e.key().clone(), e.value().clone()))
                    .collect();
                inner.sort_by(|a, b| a.0.cmp(&b.0));
                (entry.key().clone(), inner)
            })
            .collect();
        storage_entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (addr, slots) in &storage_entries {
            for (storage_key, value) in slots {
                let mut key = Vec::with_capacity(1 + addr.len() + storage_key.len());
                key.push(b's');
                key.extend_from_slice(addr);
                key.extend_from_slice(storage_key);
                if let Err(e) = trie.insert(&key, value) {
                    tracing::warn!("MPT insert (storage) failed: {}", e);
                }
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
            // 1. Canonical: native TNZO ledger (CF_ACCOUNTS).
            let native_key = tnzo_balance_key(address);
            if let Ok(Some(bytes)) = store.get(CF_ACCOUNTS, &native_key)
                && bytes.len() == 16
                && let Ok(arr) = bytes.as_slice().try_into()
            {
                let balance = u128::from_le_bytes(arr);
                self.balance_cache.insert(address.to_vec(), balance);
                return balance;
            }

            // 2. Legacy fallback: VM state key (CF_STATE). Preserved for
            //    older snapshots, fixtures, and tests that populate balance
            //    via `CF_STATE:balance:<hex>`.
            let legacy_key = format!("balance:{}", hex::encode(address));
            if let Ok(Some(bytes)) = store.get(CF_STATE, legacy_key.as_bytes())
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
            // 1. Canonical: account ledger (CF_ACCOUNTS, AccountStore layout).
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

            // 2. Legacy fallback: VM state key (CF_STATE) for old snapshots.
            let legacy_key = format!("nonce:{}", hex::encode(address));
            if let Ok(Some(bytes)) = store.get(CF_STATE, legacy_key.as_bytes())
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

        // Manually write to storage bypassing the adapter
        let balance_key = format!("balance:{}", hex::encode(&address));
        let balance: u128 = 99999;
        store
            .put(CF_STATE, balance_key.as_bytes(), &balance.to_le_bytes())
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
        let balance_key = format!("balance:{}", hex::encode(&addr));
        let balance: u128 = 42_000;
        store
            .put(CF_STATE, balance_key.as_bytes(), &balance.to_le_bytes())
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
}
