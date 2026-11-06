//! Wallet service implementation for Tenzro Network.
//!
//! This module provides the main `TenzroWalletService` implementation
//! of the `WalletService` trait.

use crate::asset_manager::AssetManager;
use crate::balance::{Balance, BalanceTracker};
use crate::contacts::{AddressBook, Contact};
use crate::error::{Result, WalletError};
use crate::history::{HistoryFilter, TransactionHistory, TxRecord};
use crate::identity_binding::WalletIdentity;
use crate::keystore::Keystore;
use crate::nonce::NonceManager;
use crate::state_sync::{ChainStateProvider, WalletStateSync};
use crate::traits::WalletService;
use crate::validation::{TransactionValidator, ValidationConfig};
use crate::wallet::{Wallet, WalletId};
use async_trait::async_trait;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tenzro_crypto::{CompositeSignature, HybridSigner};
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Hash, Nonce};
use tenzro_types::transaction::Transaction;
use tracing::{debug, info};

/// Configuration for the wallet service
#[derive(Debug, Clone)]
pub struct WalletServiceConfig {
    /// Path to keystore directory
    pub keystore_path: PathBuf,
    /// Path to contacts file
    pub contacts_path: PathBuf,
    /// Default password for auto-provisioning (for demo/testing only)
    pub default_password: Option<String>,
    /// Transaction validation configuration
    pub validation_config: ValidationConfig,
}

impl Default for WalletServiceConfig {
    fn default() -> Self {
        Self {
            keystore_path: tenzro_types::paths::default_data_dir().join("wallets"),
            contacts_path: tenzro_types::paths::default_data_dir().join("contacts.json"),
            default_password: None,
            validation_config: ValidationConfig::default(),
        }
    }
}

impl WalletServiceConfig {
    /// Create a new configuration
    pub fn new(keystore_path: PathBuf) -> Self {
        Self {
            keystore_path: keystore_path.clone(),
            contacts_path: keystore_path.join("contacts.json"),
            default_password: None,
            validation_config: ValidationConfig::default(),
        }
    }

    /// Set default password (for testing only)
    pub fn with_default_password(mut self, password: String) -> Self {
        self.default_password = Some(password);
        self
    }

    /// Set validation configuration
    pub fn with_validation_config(mut self, config: ValidationConfig) -> Self {
        self.validation_config = config;
        self
    }
}

/// Main wallet service implementation for Tenzro Network.
///
/// This service manages:
/// - Provisioning of identity-bound wallets
/// - In-memory wallet cache with persistent keystore
/// - Balance tracking (local + on-chain sync)
/// - Transaction validation, signing, and verification
/// - Nonce management for replay protection
/// - Transaction history tracking
/// - Address book / contact management
/// - Asset management
pub struct TenzroWalletService {
    /// Configuration
    config: WalletServiceConfig,
    /// In-memory wallet store
    wallets: Arc<DashMap<WalletId, Wallet>>,
    /// Balance tracker
    balances: Arc<BalanceTracker>,
    /// Asset manager
    assets: Arc<AssetManager>,
    /// Keystore for persistent storage
    keystore: Arc<tokio::sync::Mutex<Keystore>>,
    /// Transaction validator
    validator: TransactionValidator,
    /// Nonce manager
    nonces: Arc<NonceManager>,
    /// Transaction history
    history: Arc<TransactionHistory>,
    /// Address book
    contacts: Arc<AddressBook>,
    /// State sync manager
    state_sync: Arc<WalletStateSync>,
    /// Per-wallet external hybrid-signing backends (custody seam).
    ///
    /// When a wallet id is present here, `sign_transaction` / `sign_data`
    /// delegate both legs to the registered [`HybridSigner`] — the secret
    /// never enters node memory. Autonomous-machine wallets bind their
    /// TEE-sealed agent key here; absent an entry, signing falls back to
    /// the former server-custodial path.
    hybrid_signers: Arc<DashMap<WalletId, Arc<dyn HybridSigner>>>,
}

impl TenzroWalletService {
    /// Create a new wallet service with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(WalletServiceConfig::default())
    }

    /// Create a new wallet service with custom configuration
    pub fn with_config(config: WalletServiceConfig) -> Result<Self> {
        let keystore = Keystore::new(&config.keystore_path)?;
        let validator = TransactionValidator::with_config(config.validation_config.clone());
        let nonces = Arc::new(NonceManager::new());
        let balances = Arc::new(BalanceTracker::new());
        let history = Arc::new(TransactionHistory::new());

        let contacts = Arc::new(
            AddressBook::with_storage(&config.contacts_path).unwrap_or_else(|_| AddressBook::new()),
        );

        let state_sync = Arc::new(WalletStateSync::new(
            balances.clone(),
            nonces.clone(),
            history.clone(),
        ));

        Ok(Self {
            config,
            wallets: Arc::new(DashMap::new()),
            balances,
            assets: Arc::new(AssetManager::new()),
            keystore: Arc::new(tokio::sync::Mutex::new(keystore)),
            validator,
            nonces,
            history,
            contacts,
            state_sync,
            hybrid_signers: Arc::new(DashMap::new()),
        })
    }

    /// Get the balance tracker
    pub fn balance_tracker(&self) -> Arc<BalanceTracker> {
        self.balances.clone()
    }

    /// Get the asset manager
    pub fn asset_manager(&self) -> Arc<AssetManager> {
        self.assets.clone()
    }

    /// Get the nonce manager
    pub fn nonce_manager(&self) -> Arc<NonceManager> {
        self.nonces.clone()
    }

    /// Get the transaction history
    pub fn transaction_history(&self) -> Arc<TransactionHistory> {
        self.history.clone()
    }

    /// Get the address book
    pub fn address_book(&self) -> Arc<AddressBook> {
        self.contacts.clone()
    }

    /// Get the state sync manager
    pub fn state_sync(&self) -> Arc<WalletStateSync> {
        self.state_sync.clone()
    }

    /// Bind an external hybrid-signing backend to a wallet.
    ///
    /// After this call, `sign_transaction` / `sign_data` for `wallet_id`
    /// delegate both signature legs to `signer` — the wallet's secret
    /// never enters node memory. This is the custody seam autonomous-machine
    /// wallets use to route through their TEE-sealed agent key
    /// (`SealedAgentWalletSigner`) instead of a server-side custodial key
    /// reconstruction.
    pub fn set_hybrid_signer(&self, wallet_id: WalletId, signer: Arc<dyn HybridSigner>) {
        self.hybrid_signers.insert(wallet_id, signer);
    }

    fn signer_for(&self, wallet_id: &WalletId) -> Result<Arc<dyn HybridSigner>> {
        self.hybrid_signers
            .get(wallet_id)
            .map(|r| r.value().clone())
            .ok_or_else(|| {
                WalletError::SignatureFailed(format!(
                    "no hardware signer bound to wallet {wallet_id}; bind one with set_hybrid_signer"
                ))
            })
    }

    /// Whether `wallet_id` has an external hybrid-signing backend bound.
    pub fn has_hybrid_signer(&self, wallet_id: &WalletId) -> bool {
        self.hybrid_signers.contains_key(wallet_id)
    }

    /// Provision a watch-only wallet whose public keys are those of a hardware
    /// signer, then bind that signer as the wallet's [`HybridSigner`]. The
    /// wallet holds no secret; every signature is minted by `signer`.
    pub async fn provision_watch_only_wallet(
        &self,
        signer: Arc<dyn HybridSigner>,
    ) -> Result<Wallet> {
        let wallet_id = WalletId::new();
        let wallet = Wallet::new(wallet_id.clone(), signer.public_key().clone());

        self.wallets.insert(wallet_id.clone(), wallet.clone());
        self.hybrid_signers.insert(wallet_id.clone(), signer);

        for asset_id in &wallet.supported_assets {
            self.balances
                .set_balance(&wallet.address, asset_id, Balance::zero());
        }

        info!(
            "Provisioned watch-only wallet {} (external hybrid signer bound)",
            wallet_id
        );

        Ok(wallet)
    }

    /// Connect a chain state provider for on-chain synchronization.
    pub fn connect_chain_provider(&mut self, provider: Arc<dyn ChainStateProvider>) {
        self.state_sync = Arc::new(
            WalletStateSync::new(
                self.balances.clone(),
                self.nonces.clone(),
                self.history.clone(),
            )
            .with_chain_provider(provider),
        );
    }

    /// Load a wallet from its sealed record.
    async fn load_wallet_from_keystore(
        &self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<Wallet> {
        let record = self
            .keystore
            .lock()
            .await
            .load_record(wallet_id, password)?;
        let wallet = Wallet::new(wallet_id.clone(), record.public_key);
        debug!("Loaded wallet {} from keystore", wallet_id);
        Ok(wallet)
    }

    /// Seal a wallet's record into the keystore.
    async fn store_wallet_to_keystore(&self, wallet: &Wallet, password: &str) -> Result<()> {
        self.keystore.lock().await.store_record(
            &wallet.wallet_id,
            &crate::keystore::WalletRecord {
                public_key: wallet.public_key.clone(),
            },
            password,
        )
    }

    /// Get wallet by ID (from cache or keystore)
    async fn get_wallet_internal(&self, wallet_id: &WalletId) -> Result<Option<Wallet>> {
        // Check cache first
        if let Some(wallet) = self.wallets.get(wallet_id) {
            return Ok(Some(wallet.clone()));
        }

        // Try to load from keystore with default password
        if let Some(password) = &self.config.default_password {
            let keystore = self.keystore.lock().await;
            if keystore.has_wallet(wallet_id) {
                drop(keystore); // Release lock before loading
                let wallet = self.load_wallet_from_keystore(wallet_id, password).await?;
                self.wallets.insert(wallet_id.clone(), wallet.clone());
                return Ok(Some(wallet));
            }
        }

        Ok(None)
    }
}

impl Default for TenzroWalletService {
    fn default() -> Self {
        Self::new().expect("Failed to create default wallet service")
    }
}

#[async_trait]
impl WalletService for TenzroWalletService {
    // === Wallet Lifecycle ===

    async fn provision_wallet(&self, identity: WalletIdentity) -> Result<Wallet> {
        info!("Provisioning {} wallet", identity.kind());

        // Nothing is minted here. The signing key belongs to the identity and
        // this service never sees its secret half; a post-quantum key, when the
        // holder has one, is the holder's own and is added by a rotation the
        // holder signs. A key generated in this process would be a key this
        // process holds.
        let wallet = Wallet::new(WalletId::new(), identity.public_key().clone());

        debug!(
            "Provisioned wallet {} at address {}",
            wallet.wallet_id, wallet.address
        );

        // Store in cache
        self.wallets
            .insert(wallet.wallet_id.clone(), wallet.clone());

        // Store to keystore if default password is set
        if let Some(password) = &self.config.default_password {
            self.store_wallet_to_keystore(&wallet, password).await?;
        }

        // Initialize balances for supported assets
        for asset_id in &wallet.supported_assets {
            self.balances
                .set_balance(&wallet.address, asset_id, Balance::zero());
        }

        info!("Successfully provisioned wallet {}", wallet.wallet_id);

        Ok(wallet)
    }

    async fn get_wallet(&self, wallet_id: &WalletId) -> Result<Option<Wallet>> {
        self.get_wallet_internal(wallet_id).await
    }

    async fn list_wallets(&self) -> Result<Vec<WalletId>> {
        let mut wallet_ids: Vec<_> = self.wallets.iter().map(|e| e.key().clone()).collect();

        let keystore = self.keystore.lock().await;
        let keystore_ids = keystore.list_wallets()?;
        for id in keystore_ids {
            if !wallet_ids.contains(&id) {
                wallet_ids.push(id);
            }
        }

        Ok(wallet_ids)
    }

    async fn delete_wallet(&self, wallet_id: &WalletId) -> Result<()> {
        self.wallets.remove(wallet_id);

        let mut keystore = self.keystore.lock().await;
        keystore.delete_wallet(wallet_id)?;

        info!("Deleted wallet {}", wallet_id);
        Ok(())
    }

    async fn set_wallet_label(&self, wallet_id: &WalletId, label: String) -> Result<()> {
        let mut wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        wallet.set_label(label);
        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(())
    }

    // === Balance ===

    async fn get_balance(&self, address: &Address, asset: &AssetId) -> Result<Balance> {
        if !self.assets.is_supported(asset) {
            return Err(WalletError::AssetNotSupported(asset.as_str().to_string()));
        }

        // Try on-chain sync first, fall back to local
        self.state_sync.get_balance(address, asset).await
    }

    async fn available_balance(&self, address: &Address, asset: &AssetId) -> Result<u128> {
        let balance = self.get_balance(address, asset).await?;
        Ok(balance.spendable())
    }

    // === Signing ===

    async fn sign_transaction(
        &self,
        wallet_id: &WalletId,
        tx: &Transaction,
    ) -> Result<CompositeSignature> {
        debug!("Signing transaction with wallet {}", wallet_id);
        self.validator.validate(tx)?;
        let wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;
        if tx.from != wallet.address {
            return Err(WalletError::TransactionValidationFailed(format!(
                "transaction sender {} does not match wallet address {}",
                tx.from, wallet.address
            )));
        }
        let tx_hash = tx.hash();
        // Signing always goes through the bound hardware signer; the node
        // never holds a wallet secret, so it cannot be compelled to sign.
        let signature = self.signer_for(wallet_id)?.sign(
            tenzro_crypto::SignatureContext::Transaction,
            tx_hash.as_bytes(),
        )?;

        let record = TxRecord::new_outgoing(
            tx_hash,
            tx.from,
            tx.to,
            tx.nonce,
            tx.tx_type.clone(),
            tx.gas_limit,
            tx.gas_price,
            tx.memo.clone(),
        );
        self.history.record(&wallet.address, record);
        info!("Signed and recorded transaction with wallet {}", wallet_id);
        Ok(signature)
    }

    async fn sign_data(
        &self,
        wallet_id: &WalletId,
        context: tenzro_crypto::SignatureContext,
        data: &[u8],
    ) -> Result<CompositeSignature> {
        Ok(self.signer_for(wallet_id)?.sign(context, data)?)
    }

    async fn sign_external(&self, wallet_id: &WalletId, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signer_for(wallet_id)?.sign_external(data)?)
    }

    // === Nonce ===

    fn next_nonce(&self, address: &Address) -> Nonce {
        self.nonces.next_nonce(address)
    }

    fn peek_nonce(&self, address: &Address) -> Nonce {
        self.nonces.peek_nonce(address)
    }

    fn rebase_nonce(&self, address: &Address, chain_nonce: u64, max_inflight: u64) {
        self.nonces.rebase_nonce(address, chain_nonce, max_inflight)
    }

    // === History ===

    async fn get_history(&self, address: &Address) -> Result<Vec<TxRecord>> {
        Ok(self.history.get_history(address))
    }

    async fn get_filtered_history(
        &self,
        address: &Address,
        filter: &HistoryFilter,
    ) -> Result<Vec<TxRecord>> {
        Ok(self.history.get_filtered(address, filter))
    }

    async fn get_transaction(&self, tx_hash: &Hash) -> Result<Option<TxRecord>> {
        Ok(self.history.get_by_hash(tx_hash))
    }

    // === Contacts ===

    async fn add_contact(&self, contact: Contact) -> Result<()> {
        self.contacts.add_contact(contact)
    }

    async fn get_contact(&self, address: &Address) -> Result<Option<Contact>> {
        Ok(self.contacts.get_by_address(address))
    }

    async fn resolve_contact(&self, name: &str) -> Result<Option<Address>> {
        Ok(self.contacts.resolve_name(name))
    }

    // === Assets ===

    async fn supported_assets(&self) -> Vec<AssetId> {
        self.assets
            .list_assets()
            .iter()
            .map(|a| a.asset_id.clone())
            .collect()
    }

    async fn add_asset_support(&self, wallet_id: &WalletId, asset_id: AssetId) -> Result<()> {
        if !self.assets.is_supported(&asset_id) {
            return Err(WalletError::AssetNotSupported(
                asset_id.as_str().to_string(),
            ));
        }

        let mut wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        wallet.add_supported_asset(asset_id.clone());

        self.balances
            .set_balance(&wallet.address, &asset_id, Balance::zero());

        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(())
    }

    async fn remove_asset_support(&self, wallet_id: &WalletId, asset_id: &AssetId) -> Result<()> {
        let mut wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        wallet.remove_supported_asset(asset_id);
        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(())
    }

    // === Export/Import ===

    async fn export_wallet_metadata(&self, wallet_id: &WalletId) -> Result<String> {
        let wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        wallet.to_metadata_json()
    }

    async fn import_wallet_metadata(&self, metadata: &str) -> Result<WalletId> {
        let wallet = Wallet::from_metadata_json(metadata)?;
        let wallet_id = wallet.wallet_id.clone();
        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(wallet_id)
    }
}

#[cfg(test)]
mod tests {
    use crate::identity_binding::WalletIdentity;

    use tenzro_crypto::composite::testing::TestHybridSigner;

    /// Signing goes through the bound hardware signer precisely so the service
    /// never holds the secret; the tests bind an in-memory one for the same
    /// reason a node binds its TPM or Secure Enclave.
    fn bind_test_signer(service: &TenzroWalletService, wallet_id: &WalletId) {
        service.set_hybrid_signer(wallet_id.clone(), Arc::new(TestHybridSigner::hybrid(9)));
    }

    fn test_identity() -> WalletIdentity {
        WalletIdentity::machine(
            "test-machine",
            TestHybridSigner::hybrid(9).public_key().clone(),
        )
        .expect("valid machine identity")
    }

    use super::*;
    use crate::history::TxStatus;
    use tempfile::TempDir;
    use tenzro_types::primitives::ChainId;
    use tenzro_types::transaction::TransactionType;

    fn test_config() -> (TempDir, WalletServiceConfig) {
        let temp_dir = TempDir::new().unwrap();
        let config = WalletServiceConfig::new(temp_dir.path().to_path_buf())
            .with_default_password("test-password".to_string());
        (temp_dir, config)
    }

    #[tokio::test]
    async fn test_provision_wallet() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();
        assert!(!wallet.supported_assets.is_empty());
    }

    #[tokio::test]
    async fn test_get_wallet() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        let retrieved = service.get_wallet(&wallet.wallet_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().wallet_id, wallet.wallet_id);
    }

    #[tokio::test]
    async fn test_balance_query() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        let balance = service
            .get_balance(&wallet.address, &AssetId::tnzo())
            .await
            .unwrap();

        assert_eq!(balance.available, 0);
        assert_eq!(balance.spendable(), 0);
    }

    #[tokio::test]
    async fn test_sign_validated_transaction() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();
        bind_test_signer(&service, &wallet.wallet_id);

        let tx = Transaction::new(
            ChainId(1337),
            wallet.address,
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
        );

        let signature = service
            .sign_transaction(&wallet.wallet_id, &tx)
            .await
            .unwrap();

        assert!(signature.has_classical_leg());
        assert_eq!(signature.pq.as_ref().map(Vec::len), Some(3309));

        // Verify history was recorded
        let history = service.get_history(&wallet.address).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, TxStatus::Created);
    }

    #[tokio::test]
    async fn test_sign_invalid_transaction_fails() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        // Wrong chain ID
        let tx = Transaction::new(
            ChainId(999),
            wallet.address,
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
        );

        let result = service.sign_transaction(&wallet.wallet_id, &tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain ID"));
    }

    #[tokio::test]
    async fn test_sign_wrong_sender_fails() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        // Sender doesn't match wallet
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([99u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
        );

        let result = service.sign_transaction(&wallet.wallet_id, &tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn test_nonce_management() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        assert_eq!(service.peek_nonce(&wallet.address), Nonce(0));
        assert_eq!(service.next_nonce(&wallet.address), Nonce(0));
        assert_eq!(service.next_nonce(&wallet.address), Nonce(1));
        assert_eq!(service.peek_nonce(&wallet.address), Nonce(2));
    }

    #[tokio::test]
    async fn test_contact_management() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();

        let contact = Contact::new("Alice".to_string(), Address::new([1u8; 32]));

        service.add_contact(contact).await.unwrap();

        let resolved = service.resolve_contact("Alice").await.unwrap();
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap(), Address::new([1u8; 32]));

        let contact = service.get_contact(&Address::new([1u8; 32])).await.unwrap();
        assert!(contact.is_some());
    }

    #[tokio::test]
    async fn test_list_wallets() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();

        let wallet1 = service.provision_wallet(test_identity()).await.unwrap();
        let wallet2 = service.provision_wallet(test_identity()).await.unwrap();

        let wallets = service.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 2);
        assert!(wallets.contains(&wallet1.wallet_id));
        assert!(wallets.contains(&wallet2.wallet_id));
    }

    #[tokio::test]
    async fn test_delete_wallet() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        service.delete_wallet(&wallet.wallet_id).await.unwrap();

        let retrieved = service.get_wallet(&wallet.wallet_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_asset_support() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        let new_asset = AssetId::from("TEST");
        service
            .asset_manager()
            .register_asset(tenzro_types::AssetInfo::new(
                new_asset.clone(),
                "Test Token".to_string(),
                "TEST".to_string(),
                18,
                1000000,
                tenzro_types::AssetType::Fungible,
            ));

        service
            .add_asset_support(&wallet.wallet_id, new_asset.clone())
            .await
            .unwrap();

        let updated_wallet = service
            .get_wallet(&wallet.wallet_id)
            .await
            .unwrap()
            .unwrap();
        assert!(updated_wallet.supports_asset(&new_asset));
    }

    #[tokio::test]
    async fn test_sign_data() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();

        bind_test_signer(&service, &wallet.wallet_id);

        let data = b"arbitrary data to sign";
        let signature = service
            .sign_data(
                &wallet.wallet_id,
                tenzro_crypto::composite::SignatureContext::X402Payment,
                data,
            )
            .await
            .unwrap();
        assert!(signature.has_classical_leg());
        assert_eq!(signature.pq.as_ref().map(Vec::len), Some(3309));
    }

    #[tokio::test]
    async fn external_signing_refuses_a_composite_message_representative() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet(test_identity()).await.unwrap();
        bind_test_signer(&service, &wallet.wallet_id);

        let m_prime = tenzro_crypto::composite::message_representative(
            tenzro_crypto::composite::SignatureContext::Transaction,
            &[7u8; 32],
        );
        assert!(
            service
                .sign_external(&wallet.wallet_id, &m_prime)
                .await
                .is_err()
        );
        assert!(
            service
                .sign_external(&wallet.wallet_id, b"{\"ap2\":1}")
                .await
                .is_ok()
        );
    }
}
