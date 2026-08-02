//! Wallet state synchronization for Tenzro Network.
//!
//! Defines the interface for synchronizing wallet state with on-chain data.
//! This includes balance queries, nonce synchronization, and transaction
//! status tracking from the blockchain.

use crate::balance::{Balance, BalanceTracker};
use crate::error::{Result, WalletError};
use crate::history::{TransactionHistory, TxRecord, TxStatus};
use crate::nonce::NonceManager;
use async_trait::async_trait;
use std::sync::Arc;
use tenzro_types::primitives::{Address, Hash, Signature};
use tenzro_types::{AssetId, Transaction};
use tracing::{debug, info, warn};

/// Trait for providing on-chain state to the wallet.
///
/// Implementations connect to a Tenzro node (or light client) to query
/// current blockchain state. The wallet service uses this to sync
/// local state with the canonical chain.
#[async_trait]
pub trait ChainStateProvider: Send + Sync {
    /// Get the current balance for an address and asset from on-chain state.
    async fn get_on_chain_balance(&self, address: &Address, asset_id: &AssetId) -> Result<u128>;

    /// Get all asset balances for an address from on-chain state.
    async fn get_on_chain_balances(&self, address: &Address) -> Result<Vec<(AssetId, u128)>>;

    /// Get the current confirmed nonce for an address.
    async fn get_on_chain_nonce(&self, address: &Address) -> Result<u64>;

    /// Get the status of a transaction by its hash.
    async fn get_transaction_status(&self, tx_hash: &Hash) -> Result<TxStatus>;

    /// Get the current block height.
    async fn get_block_height(&self) -> Result<u64>;

    /// Submit a hybrid post-quantum signed transaction to the network.
    ///
    /// The wire format matches Tenzro's `eth_sendRawTransaction` JSON-RPC
    /// shape: a structured object with explicit `from`, `to`, `value`,
    /// `nonce`, `chain_id`, `timestamp`, `tx_type`, plus the classical
    /// Ed25519 (`signature` + `public_key`, 64 + 32 bytes) and post-quantum
    /// ML-DSA-65 (`pq_signature` 3309 bytes + `pq_public_key` 1952 bytes)
    /// legs. Both legs MUST verify against `Transaction::hash()` server-side
    /// or the node returns JSON-RPC error `-32003`.
    ///
    /// The classical signature (and its embedded `public_key`) and `pq_sig`
    /// are passed separately so the trait can be satisfied by callers that
    /// produce signatures via `WalletService::sign_transaction` without
    /// re-serializing into a hex blob.
    async fn submit_signed_transaction(
        &self,
        tx: &Transaction,
        classical_sig: &Signature,
        pq_sig: &[u8],
    ) -> Result<Hash>;
}

/// Wallet state synchronizer.
///
/// Coordinates between local wallet state (balances, nonces, history)
/// and on-chain state via a ChainStateProvider. Handles:
/// - Initial sync when connecting to a node
/// - Periodic balance refresh
/// - Transaction confirmation tracking
/// - Nonce synchronization after reconnection
pub struct WalletStateSync {
    /// Balance tracker (local cache)
    balances: Arc<BalanceTracker>,
    /// Nonce manager
    nonces: Arc<NonceManager>,
    /// Transaction history
    history: Arc<TransactionHistory>,
    /// Chain state provider (optional — works offline without it)
    chain_provider: Option<Arc<dyn ChainStateProvider>>,
}

impl WalletStateSync {
    /// Create a new state sync manager.
    pub fn new(
        balances: Arc<BalanceTracker>,
        nonces: Arc<NonceManager>,
        history: Arc<TransactionHistory>,
    ) -> Self {
        Self {
            balances,
            nonces,
            history,
            chain_provider: None,
        }
    }

    /// Connect a chain state provider for on-chain synchronization.
    pub fn with_chain_provider(mut self, provider: Arc<dyn ChainStateProvider>) -> Self {
        self.chain_provider = Some(provider);
        self
    }

    /// Check if connected to a chain state provider.
    pub fn is_connected(&self) -> bool {
        self.chain_provider.is_some()
    }

    /// Perform a full sync for an address.
    ///
    /// Syncs balances, nonces, and pending transaction statuses
    /// from on-chain state.
    pub async fn sync_address(&self, address: &Address, assets: &[AssetId]) -> Result<()> {
        let provider = self
            .chain_provider
            .as_ref()
            .ok_or_else(|| WalletError::Other("No chain state provider connected".to_string()))?;

        // Sync balances
        self.sync_balances(address, assets, provider.as_ref())
            .await?;

        // Sync nonce
        self.sync_nonce(address, provider.as_ref()).await?;

        // Sync pending transactions
        self.sync_pending_transactions(address, provider.as_ref())
            .await?;

        info!("Completed full sync for address {}", address);
        Ok(())
    }

    /// Sync balances for an address from on-chain state.
    async fn sync_balances(
        &self,
        address: &Address,
        assets: &[AssetId],
        provider: &dyn ChainStateProvider,
    ) -> Result<()> {
        for asset_id in assets {
            match provider.get_on_chain_balance(address, asset_id).await {
                Ok(on_chain_balance) => {
                    let current = self.balances.get_balance(address, asset_id);

                    // Update available balance from chain, preserving local pending state
                    let synced = Balance {
                        available: on_chain_balance,
                        locked: current.locked,
                        pending_in: current.pending_in,
                        pending_out: current.pending_out,
                    };
                    self.balances.set_balance(address, asset_id, synced);

                    debug!(
                        "Synced balance for {} {}: {} → {}",
                        address,
                        asset_id.as_str(),
                        current.available,
                        on_chain_balance
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to sync balance for {} {}: {}",
                        address,
                        asset_id.as_str(),
                        e
                    );
                }
            }
        }
        Ok(())
    }

    /// Sync the nonce for an address from on-chain state.
    async fn sync_nonce(&self, address: &Address, provider: &dyn ChainStateProvider) -> Result<()> {
        match provider.get_on_chain_nonce(address).await {
            Ok(on_chain_nonce) => {
                self.nonces.sync_from_chain(address, on_chain_nonce);
                debug!("Synced nonce for {}: on-chain={}", address, on_chain_nonce);
            }
            Err(e) => {
                warn!("Failed to sync nonce for {}: {}", address, e);
            }
        }
        Ok(())
    }

    /// Check and update the status of pending transactions.
    async fn sync_pending_transactions(
        &self,
        address: &Address,
        provider: &dyn ChainStateProvider,
    ) -> Result<()> {
        let pending_records: Vec<TxRecord> = self
            .history
            .get_history(address)
            .into_iter()
            .filter(|r| r.is_pending())
            .collect();

        for record in pending_records {
            match provider.get_transaction_status(&record.tx_hash).await {
                Ok(new_status) => {
                    if new_status != record.status {
                        if let Err(e) = self.history.update_status(&record.tx_hash, new_status) {
                            warn!("Failed to update tx status for {}: {}", record.tx_hash, e);
                        } else {
                            debug!(
                                "Updated tx {} status: {} → {}",
                                record.tx_hash, record.status, new_status
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to check status for tx {}: {}", record.tx_hash, e);
                }
            }
        }

        Ok(())
    }

    /// Get the balance, preferring on-chain data when available.
    pub async fn get_balance(&self, address: &Address, asset_id: &AssetId) -> Result<Balance> {
        // If connected, try to get fresh on-chain balance
        if let Some(provider) = &self.chain_provider {
            match provider.get_on_chain_balance(address, asset_id).await {
                Ok(on_chain) => {
                    let current = self.balances.get_balance(address, asset_id);
                    return Ok(Balance {
                        available: on_chain,
                        locked: current.locked,
                        pending_in: current.pending_in,
                        pending_out: current.pending_out,
                    });
                }
                Err(e) => {
                    debug!(
                        "Falling back to cached balance for {} {}: {}",
                        address,
                        asset_id.as_str(),
                        e
                    );
                }
            }
        }

        // Fall back to local cached balance
        Ok(self.balances.get_balance(address, asset_id))
    }

    /// Submit a hybrid post-quantum signed transaction and track it in history.
    ///
    /// `tx`, `classical_sig`, and `pq_sig` together form the wire payload the
    /// node's `eth_sendRawTransaction` parser expects. Both signature legs
    /// must verify against `Transaction::hash()` server-side or the call
    /// returns `WalletError::Other` carrying JSON-RPC error `-32003`.
    pub async fn submit_and_track(
        &self,
        address: &Address,
        tx: &Transaction,
        classical_sig: &Signature,
        pq_sig: &[u8],
        record: TxRecord,
    ) -> Result<Hash> {
        let provider = self
            .chain_provider
            .as_ref()
            .ok_or_else(|| WalletError::Other("No chain state provider connected".to_string()))?;

        // Submit to network
        let tx_hash = provider
            .submit_signed_transaction(tx, classical_sig, pq_sig)
            .await?;

        // Record in history
        let mut tracked = record;
        tracked.tx_hash = tx_hash;
        tracked.mark_pending();
        self.history.record(address, tracked);

        info!("Submitted and tracking transaction {}", tx_hash);
        Ok(tx_hash)
    }
}

/// Local-only chain state provider for offline/testing use.
///
/// Uses the in-memory balance tracker and nonce manager as the
/// "source of truth" — no actual chain connection.
pub struct LocalStateProvider {
    balances: Arc<BalanceTracker>,
    nonces: Arc<NonceManager>,
}

impl LocalStateProvider {
    /// Create a new local state provider.
    pub fn new(balances: Arc<BalanceTracker>, nonces: Arc<NonceManager>) -> Self {
        Self { balances, nonces }
    }
}

#[async_trait]
impl ChainStateProvider for LocalStateProvider {
    async fn get_on_chain_balance(&self, address: &Address, asset_id: &AssetId) -> Result<u128> {
        Ok(self.balances.get_balance(address, asset_id).available)
    }

    async fn get_on_chain_balances(&self, address: &Address) -> Result<Vec<(AssetId, u128)>> {
        Ok(self
            .balances
            .get_all_balances(address)
            .into_iter()
            .map(|(id, bal)| (id, bal.available))
            .collect())
    }

    async fn get_on_chain_nonce(&self, address: &Address) -> Result<u64> {
        Ok(self.nonces.confirmed_nonce(address).0)
    }

    async fn get_transaction_status(&self, _tx_hash: &Hash) -> Result<TxStatus> {
        // Local provider: assume pending until proven otherwise
        Ok(TxStatus::Pending)
    }

    async fn get_block_height(&self) -> Result<u64> {
        Ok(0)
    }

    async fn submit_signed_transaction(
        &self,
        tx: &Transaction,
        _classical_sig: &Signature,
        _pq_sig: &[u8],
    ) -> Result<Hash> {
        // Local provider: just return the canonical transaction hash. There
        // is no real network to submit to; signature legs are not verified
        // here because the wallet has already signed and the test caller
        // wants the same hash the network would emit.
        Ok(tx.hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_local_state_provider() {
        let balances = Arc::new(BalanceTracker::new());
        let nonces = Arc::new(NonceManager::new());

        let addr = Address::new([1u8; 32]);
        let asset = AssetId::tnzo();

        // Set up local state
        balances.add_balance(&addr, &asset, 1000);
        nonces.next_nonce(&addr); // 0
        nonces.confirm_nonce(&addr, 0);

        let provider = LocalStateProvider::new(balances.clone(), nonces.clone());

        let balance = provider.get_on_chain_balance(&addr, &asset).await.unwrap();
        assert_eq!(balance, 1000);

        let nonce = provider.get_on_chain_nonce(&addr).await.unwrap();
        assert_eq!(nonce, 1);
    }

    #[tokio::test]
    async fn test_wallet_state_sync() {
        let balances = Arc::new(BalanceTracker::new());
        let nonces = Arc::new(NonceManager::new());
        let history = Arc::new(TransactionHistory::new());

        let addr = Address::new([1u8; 32]);
        let asset = AssetId::tnzo();

        // Set up local state
        balances.add_balance(&addr, &asset, 1000);

        let provider = Arc::new(LocalStateProvider::new(balances.clone(), nonces.clone()));

        let sync = WalletStateSync::new(balances.clone(), nonces.clone(), history.clone())
            .with_chain_provider(provider);

        assert!(sync.is_connected());

        let balance = sync.get_balance(&addr, &asset).await.unwrap();
        assert_eq!(balance.available, 1000);
    }

    #[tokio::test]
    async fn test_sync_address() {
        let balances = Arc::new(BalanceTracker::new());
        let nonces = Arc::new(NonceManager::new());
        let history = Arc::new(TransactionHistory::new());

        let addr = Address::new([1u8; 32]);
        let asset = AssetId::tnzo();

        balances.add_balance(&addr, &asset, 5000);

        let provider = Arc::new(LocalStateProvider::new(balances.clone(), nonces.clone()));

        let sync = WalletStateSync::new(balances.clone(), nonces.clone(), history.clone())
            .with_chain_provider(provider);

        sync.sync_address(&addr, std::slice::from_ref(&asset))
            .await
            .unwrap();

        let balance = balances.get_balance(&addr, &asset);
        assert_eq!(balance.available, 5000);
    }

    #[tokio::test]
    async fn test_offline_fallback() {
        let balances = Arc::new(BalanceTracker::new());
        let nonces = Arc::new(NonceManager::new());
        let history = Arc::new(TransactionHistory::new());

        let addr = Address::new([1u8; 32]);
        let asset = AssetId::tnzo();

        balances.add_balance(&addr, &asset, 2000);

        // No chain provider — offline mode
        let sync = WalletStateSync::new(balances.clone(), nonces.clone(), history.clone());

        assert!(!sync.is_connected());

        // Should fall back to cached balance
        let balance = sync.get_balance(&addr, &asset).await.unwrap();
        assert_eq!(balance.available, 2000);
    }
}
