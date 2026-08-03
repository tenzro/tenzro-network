//! Wallet service implementation for Tenzro Network.
//!
//! This module provides the main `TenzroWalletService` implementation
//! of the `WalletService` trait.

use crate::asset_manager::AssetManager;
use crate::balance::{Balance, BalanceTracker};
use crate::contacts::{AddressBook, Contact};
use crate::error::{Result, WalletError};
use crate::history::{HistoryFilter, TransactionHistory, TxRecord};
use crate::keystore::Keystore;
use crate::mpc_signing::TransactionSigner;
use crate::nonce::NonceManager;
use crate::provisioning::{ProvisioningConfig, WalletProvisioner};
use crate::signing::{HybridSignatureBytes, HybridSigner};
use crate::state_sync::{ChainStateProvider, WalletStateSync};
use crate::traits::WalletService;
use crate::validation::{TransactionValidator, ValidationConfig};
use crate::wallet::{MpcWallet, WalletId};
use async_trait::async_trait;
use dashmap::DashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Hash, Nonce};
use tenzro_types::transaction::Transaction;
use tracing::{debug, info, warn};

/// Configuration for the wallet service
#[derive(Debug, Clone)]
pub struct WalletServiceConfig {
    /// Path to keystore directory
    pub keystore_path: PathBuf,
    /// Path to contacts file
    pub contacts_path: PathBuf,
    /// Provisioning configuration
    pub provisioning_config: ProvisioningConfig,
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
            provisioning_config: ProvisioningConfig::default(),
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
            provisioning_config: ProvisioningConfig::default(),
            default_password: None,
            validation_config: ValidationConfig::default(),
        }
    }

    /// Set the provisioning configuration
    pub fn with_provisioning_config(mut self, config: ProvisioningConfig) -> Self {
        self.provisioning_config = config;
        self
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
/// - Auto-provisioning of MPC wallets
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
    /// Wallet provisioner
    provisioner: WalletProvisioner,
    /// In-memory wallet store
    wallets: Arc<DashMap<WalletId, MpcWallet>>,
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
    /// the server-custodial FROST + ML-DSA path.
    hybrid_signers: Arc<DashMap<WalletId, Arc<dyn HybridSigner>>>,
}

impl TenzroWalletService {
    /// Create a new wallet service with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(WalletServiceConfig::default())
    }

    /// Create a new wallet service with custom configuration
    pub fn with_config(config: WalletServiceConfig) -> Result<Self> {
        let provisioner = WalletProvisioner::with_config(config.provisioning_config.clone())?;
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
            provisioner,
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
    /// (`SealedAgentWalletSigner`) instead of server-side FROST + ML-DSA
    /// reconstruction.
    pub fn set_hybrid_signer(&self, wallet_id: WalletId, signer: Arc<dyn HybridSigner>) {
        self.hybrid_signers.insert(wallet_id, signer);
    }

    /// Whether `wallet_id` has an external hybrid-signing backend bound.
    pub fn has_hybrid_signer(&self, wallet_id: &WalletId) -> bool {
        self.hybrid_signers.contains_key(wallet_id)
    }

    /// Provision a watch-only wallet whose public keys mirror an external
    /// custody backend (a TEE-sealed agent key), then bind that backend as
    /// the wallet's [`HybridSigner`].
    ///
    /// The wallet holds no secret: `signer.classical_public_key()`,
    /// `signer.pq_verifying_key()`, and `bls_verifying_key` become the
    /// wallet's public identity, and all signatures are minted by `signer`.
    /// This is the autonomous-machine custody path — the node never
    /// reconstructs a signing key.
    ///
    /// `classical_key_type` selects how the address is derived from
    /// `signer.classical_public_key()` (Ed25519 → SHA-256 prefix,
    /// Secp256k1 → Keccak tail). Autonomous machines use Ed25519.
    pub async fn provision_watch_only_wallet(
        &self,
        signer: Arc<dyn HybridSigner>,
        classical_key_type: tenzro_crypto::KeyType,
        bls_verifying_key: Vec<u8>,
    ) -> Result<MpcWallet> {
        let public_key =
            tenzro_crypto::PublicKey::new(classical_key_type, signer.classical_public_key());
        let pq_verifying_key = signer.pq_verifying_key();

        let wallet_id = WalletId::new();
        let wallet = MpcWallet::new_watch_only(
            wallet_id.clone(),
            public_key,
            pq_verifying_key,
            bls_verifying_key,
        )?;

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

    /// Load a wallet from keystore.
    ///
    /// The keystore returns the `(PublicKeyPackage, Vec<KeyShare>)` pair
    /// atomically — the FROST group public key is required for signing and
    /// is not reconstructible from individual shares, so it is sealed in the
    /// same Argon2id-derived bundle.
    async fn load_wallet_from_keystore(
        &self,
        wallet_id: &WalletId,
        password: &str,
    ) -> Result<MpcWallet> {
        let mut keystore = self.keystore.lock().await;
        let (pubkey_package, key_shares) = keystore.load_shares(wallet_id, password)?;

        if key_shares.is_empty() {
            return Err(WalletError::KeystoreError(
                "No key shares found in keystore".to_string(),
            ));
        }

        // Derive address from the FROST group public key.
        let group_pk = pubkey_package.group_public_key.as_public_key();
        let crypto_addr = group_pk.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        // Load the ML-DSA-65 + BLS12-381 signing keys persisted alongside
        // the classical bundle. We reuse the existing keystore lock guard so
        // we never double-acquire `self.keystore`.
        let pq_signing_key = keystore.load_pq_seed(wallet_id, password)?;
        let bls_signing_key = keystore.load_bls_seed(wallet_id, password)?;
        drop(keystore);

        let wallet = MpcWallet::new(
            wallet_id.clone(),
            address,
            key_shares,
            pubkey_package,
            pq_signing_key,
            bls_signing_key,
        )?;

        warn!(
            "Loaded wallet {} from keystore (metadata reconstructed from shares)",
            wallet_id
        );

        Ok(wallet)
    }

    /// Store a wallet to keystore (FROST bundle + PQ signing seed + BLS
    /// signing seed).
    async fn store_wallet_to_keystore(&self, wallet: &MpcWallet, password: &str) -> Result<()> {
        let mut keystore = self.keystore.lock().await;
        let pubkey_package = wallet.frost_pubkey_package()?;
        keystore.store_shares(
            &wallet.wallet_id,
            pubkey_package,
            &wallet.key_shares,
            password,
        )?;
        // Mandatory PQ leg — persist the 32-byte canonical FIPS 204 seed
        // sealed with the same Argon2id-derived key. `pq_signing_key()`
        // returns an error only when the wallet was never decrypted, which
        // cannot happen on the provisioning / re-encryption path.
        let pq_key = wallet.pq_signing_key()?;
        keystore.store_pq_seed(&wallet.wallet_id, pq_key, password)?;
        // Mandatory BLS leg — persist the 32-byte BLS12-381 secret key bytes
        // sealed under the same key.
        let bls_key = wallet.bls_signing_key()?;
        keystore.store_bls_seed(&wallet.wallet_id, bls_key, password)?;
        Ok(())
    }

    /// Read the three encrypted keystore files for `wallet_id` as raw bytes
    /// (no decryption). Used by the identity CAR export flow (C.6) to ship a
    /// wallet across machines without ever exposing the password in transit.
    pub async fn export_encrypted_wallet_files(
        &self,
        wallet_id: &WalletId,
    ) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        let keystore = self.keystore.lock().await;
        keystore.export_encrypted_wallet_files(wallet_id)
    }

    /// Write encrypted keystore files received from another node (C.6 import).
    /// Refuses to overwrite an existing wallet of the same ID — callers must
    /// delete first if they really mean to clobber.
    pub async fn import_encrypted_wallet_files(
        &self,
        wallet_id: &WalletId,
        files: &std::collections::HashMap<String, Vec<u8>>,
    ) -> Result<()> {
        let mut keystore = self.keystore.lock().await;
        keystore.import_encrypted_wallet_files(wallet_id, files)
    }

    /// Get wallet by ID (from cache or keystore)
    async fn get_wallet_internal(&self, wallet_id: &WalletId) -> Result<Option<MpcWallet>> {
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

    async fn provision_wallet(&self) -> Result<MpcWallet> {
        info!("Provisioning new wallet");

        let wallet = self.provisioner.provision_wallet()?;

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

        info!(
            "Successfully provisioned wallet {} with {} shares",
            wallet.wallet_id,
            wallet.share_count()
        );

        Ok(wallet)
    }

    async fn get_wallet(&self, wallet_id: &WalletId) -> Result<Option<MpcWallet>> {
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
    ) -> Result<HybridSignatureBytes> {
        debug!("Signing transaction with wallet {}", wallet_id);

        // Validate the transaction before signing
        self.validator.validate(tx)?;

        // Get wallet
        let wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        // Verify sender matches wallet address or public key (hex canonical address)
        let pubkey_matches = Address::from_bytes(wallet.public_key.as_bytes())
            .map(|a| tx.from == a)
            .unwrap_or(false);
        if tx.from != wallet.address && !pubkey_matches {
            return Err(WalletError::TransactionValidationFailed(format!(
                "transaction sender {} does not match wallet address {} or public key",
                tx.from, wallet.address
            )));
        }

        // The transaction must commit to the wallet's PQ verifying key — this
        // closes the door on key-substitution attacks that the `Transaction::hash()`
        // PQ-binding already covers, but enforced here so callers get an early
        // error rather than a silent admission failure.
        if tx.pq_public_key != wallet.pq_verifying_key {
            return Err(WalletError::TransactionValidationFailed(
                "transaction pq_public_key does not match wallet ML-DSA-65 verifying key"
                    .to_string(),
            ));
        }

        // Hash the transaction for signing
        let tx_hash = tx.hash();

        // Custody seam: if an external hybrid signer is bound to this wallet
        // (autonomous-machine TEE-sealed key), delegate both legs to it — the
        // secret never enters node memory. Otherwise fall back to the
        // server-custodial FROST + ML-DSA path below.
        let external_signer = self
            .hybrid_signers
            .get(wallet_id)
            .map(|r| r.value().clone());
        let HybridSignatureBytes { classical, pq } = if let Some(signer) = external_signer {
            signer.sign_hybrid(tx_hash.as_bytes()).await?
        } else {
            // Classical leg — threshold MPC signature with post-signing verification.
            let classical = TransactionSigner::sign_transaction(&wallet, tx_hash.as_bytes())?;
            // Post-quantum leg — ML-DSA-65 signature over the same hash.
            let pq = wallet.pq_signing_key()?.sign(tx_hash.as_bytes());
            HybridSignatureBytes::new(classical, pq)
        };

        // Record in history
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

        info!(
            "Successfully signed and recorded transaction with wallet {}",
            wallet_id
        );

        Ok(HybridSignatureBytes { classical, pq })
    }

    async fn sign_data(&self, wallet_id: &WalletId, data: &[u8]) -> Result<HybridSignatureBytes> {
        let external_signer = self
            .hybrid_signers
            .get(wallet_id)
            .map(|r| r.value().clone());
        if let Some(signer) = external_signer {
            return signer.sign_hybrid(data).await;
        }

        let wallet = self
            .get_wallet_internal(wallet_id)
            .await?
            .ok_or_else(|| WalletError::WalletNotFound(wallet_id.to_string()))?;

        let classical = TransactionSigner::sign_raw(&wallet, data)?;
        let pq = wallet.pq_signing_key()?.sign(data);
        Ok(HybridSignatureBytes::new(classical, pq))
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
        let wallet = MpcWallet::from_metadata_json(metadata)?;
        let wallet_id = wallet.wallet_id.clone();
        self.wallets.insert(wallet_id.clone(), wallet);
        Ok(wallet_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::TxStatus;
    use tempfile::TempDir;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::ChainId;
    use tenzro_types::transaction::TransactionType;

    fn pq_pk() -> Vec<u8> {
        MlDsaSigningKey::generate().verifying_key_bytes().to_vec()
    }

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
        let wallet = service.provision_wallet().await.unwrap();

        assert!(wallet.can_sign());
        assert!(!wallet.supported_assets.is_empty());
    }

    #[tokio::test]
    async fn test_get_wallet() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

        let retrieved = service.get_wallet(&wallet.wallet_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().wallet_id, wallet.wallet_id);
    }

    #[tokio::test]
    async fn test_balance_query() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

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
        let wallet = service.provision_wallet().await.unwrap();

        let tx = Transaction::new(
            ChainId(1337),
            wallet.address,
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            wallet.pq_verifying_key_bytes(),
        );

        let signature = service
            .sign_transaction(&wallet.wallet_id, &tx)
            .await
            .unwrap();

        assert!(!signature.classical.is_empty());
        assert_eq!(signature.pq.len(), 3309);

        // Verify history was recorded
        let history = service.get_history(&wallet.address).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].status, TxStatus::Created);
    }

    #[tokio::test]
    async fn test_sign_invalid_transaction_fails() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

        // Wrong chain ID
        let tx = Transaction::new(
            ChainId(999),
            wallet.address,
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );

        let result = service.sign_transaction(&wallet.wallet_id, &tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("chain ID"));
    }

    #[tokio::test]
    async fn test_sign_wrong_sender_fails() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

        // Sender doesn't match wallet
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([99u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );

        let result = service.sign_transaction(&wallet.wallet_id, &tx).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[tokio::test]
    async fn test_nonce_management() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

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

        let wallet1 = service.provision_wallet().await.unwrap();
        let wallet2 = service.provision_wallet().await.unwrap();

        let wallets = service.list_wallets().await.unwrap();
        assert_eq!(wallets.len(), 2);
        assert!(wallets.contains(&wallet1.wallet_id));
        assert!(wallets.contains(&wallet2.wallet_id));
    }

    #[tokio::test]
    async fn test_delete_wallet() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

        service.delete_wallet(&wallet.wallet_id).await.unwrap();

        let retrieved = service.get_wallet(&wallet.wallet_id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_asset_support() {
        let (_dir, config) = test_config();
        let service = TenzroWalletService::with_config(config).unwrap();
        let wallet = service.provision_wallet().await.unwrap();

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
        let wallet = service.provision_wallet().await.unwrap();

        let data = b"arbitrary data to sign";
        let signature = service.sign_data(&wallet.wallet_id, data).await.unwrap();
        assert!(!signature.classical.is_empty());
        assert_eq!(signature.pq.len(), 3309);
    }
}
