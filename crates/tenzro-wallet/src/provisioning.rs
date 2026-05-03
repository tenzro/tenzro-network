//! Auto-provisioning for MPC wallets in Tenzro Network.
//!
//! This module handles the seamless creation of MPC wallets when users join the network.
//! No seed phrases, no manual key management - just automatic threshold wallet generation.

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, MpcWallet, WalletId};
use tenzro_crypto::mpc::{generate_key_shares, ThresholdConfig};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::KeyType;
use tenzro_types::primitives::Address;
use tracing::{debug, info};

/// Configuration for wallet provisioning.
#[derive(Debug, Clone)]
pub struct ProvisioningConfig {
    /// Threshold for MPC signing (default: 2)
    pub threshold: usize,
    /// Total number of shares to generate (default: 3)
    pub total_shares: usize,
    /// Key type to use (default: Ed25519)
    pub key_type: KeyType,
    /// Participant ID prefix
    pub participant_id_prefix: String,
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
            key_type: KeyType::Ed25519,
            participant_id_prefix: "tenzro-participant".to_string(),
        }
    }
}

impl ProvisioningConfig {
    /// Create a new provisioning config
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        if threshold == 0 || threshold > total_shares {
            return Err(WalletError::ProvisioningFailed(
                "Invalid threshold configuration".to_string(),
            ));
        }

        Ok(Self {
            threshold,
            total_shares,
            key_type: KeyType::Ed25519,
            participant_id_prefix: "tenzro-participant".to_string(),
        })
    }

    /// Set the key type
    pub fn with_key_type(mut self, key_type: KeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the participant ID prefix
    pub fn with_participant_prefix(mut self, prefix: String) -> Self {
        self.participant_id_prefix = prefix;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.threshold == 0 {
            return Err(WalletError::ProvisioningFailed(
                "Threshold must be at least 1".to_string(),
            ));
        }

        if self.threshold > self.total_shares {
            return Err(WalletError::ProvisioningFailed(
                "Threshold cannot exceed total shares".to_string(),
            ));
        }

        if self.total_shares > 100 {
            return Err(WalletError::ProvisioningFailed(
                "Total shares cannot exceed 100".to_string(),
            ));
        }

        Ok(())
    }
}

/// Wallet provisioner for auto-generating MPC wallets.
///
/// The provisioner handles the entire wallet creation process:
/// 1. Generate threshold key shares
/// 2. Create wallet with metadata
/// 3. Return fully-functional MPC wallet
#[derive(Debug, Clone)]
pub struct WalletProvisioner {
    /// Provisioning configuration
    config: ProvisioningConfig,
}

impl WalletProvisioner {
    /// Create a new wallet provisioner with default config
    pub fn new() -> Self {
        Self {
            config: ProvisioningConfig::default(),
        }
    }

    /// Create a new wallet provisioner with custom config
    pub fn with_config(config: ProvisioningConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Get the provisioning configuration
    pub fn config(&self) -> &ProvisioningConfig {
        &self.config
    }

    /// Provision a new MPC wallet automatically.
    ///
    /// This is the main entry point for seamless wallet creation.
    /// The wallet is ready to use immediately after provisioning.
    pub fn provision_wallet(&self) -> Result<MpcWallet> {
        self.provision_wallet_with_id(WalletId::new())
    }

    /// Provision a wallet with a specific ID
    pub fn provision_wallet_with_id(&self, wallet_id: WalletId) -> Result<MpcWallet> {
        info!(
            "Provisioning new MPC wallet: {} ({}-of-{})",
            wallet_id, self.config.threshold, self.config.total_shares
        );

        // Create threshold configuration
        let threshold_config = ThresholdConfig::new(self.config.threshold, self.config.total_shares)
            .map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        // Generate MPC key shares
        debug!("Generating {} key shares", self.config.total_shares);
        let mpc_shares = generate_key_shares(self.config.key_type, threshold_config)
            .map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        // Wrap shares with participant information
        let key_shares: Vec<KeyShare> = mpc_shares
            .into_iter()
            .enumerate()
            .map(|(i, mpc_share)| {
                let participant_id = format!("{}-{}", self.config.participant_id_prefix, i + 1);
                KeyShare::new((i + 1) as u32, participant_id, mpc_share)
            })
            .collect();

        // All shares have the same public key - extract it from the first share
        let public_key = key_shares[0].mpc_share.public_key.clone();

        // Derive the wallet address from the public key
        let address = self.derive_address(&public_key);

        debug!("Wallet address: {}", address);

        // Generate a fresh ML-DSA-65 signing key — every wallet carries a
        // mandatory PQ leg per the post-quantum migration.
        let pq_signing_key = MlDsaSigningKey::generate();

        // Create the MPC wallet
        let wallet = MpcWallet::new(
            wallet_id.clone(),
            address,
            self.config.threshold,
            self.config.total_shares,
            key_shares,
            public_key,
            self.config.key_type,
            pq_signing_key,
        )?;

        info!(
            "Successfully provisioned wallet {} at address {}",
            wallet_id, address
        );

        Ok(wallet)
    }

    /// Provision a wallet with a custom label
    pub fn provision_wallet_with_label(&self, label: String) -> Result<MpcWallet> {
        let mut wallet = self.provision_wallet()?;
        wallet.set_label(label);
        Ok(wallet)
    }

    /// Derive an address from a public key
    fn derive_address(&self, public_key: &tenzro_crypto::PublicKey) -> Address {
        // The crypto module's public key has a to_address method that returns a 20-byte address
        // We need to convert it to the 32-byte Address type from tenzro-types
        let crypto_address = public_key.to_address();
        let mut addr_bytes = [0u8; 32];

        // Copy the 20 bytes into the first 20 bytes of our 32-byte address
        addr_bytes[..20].copy_from_slice(crypto_address.as_bytes());

        Address::new(addr_bytes)
    }

    /// Re-provision shares for an existing wallet (for recovery or expansion)
    pub fn reprovision_shares(
        &self,
        wallet_id: &WalletId,
        _existing_public_key: &tenzro_crypto::PublicKey,
    ) -> Result<Vec<KeyShare>> {
        info!(
            "Re-provisioning shares for wallet: {}",
            wallet_id
        );

        // In a production system, this would use proper key recovery mechanisms
        // For now, we'll generate new shares (this is a simplified approach)

        // Create threshold configuration
        let threshold_config = ThresholdConfig::new(self.config.threshold, self.config.total_shares)
            .map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        // Generate new MPC key shares
        let mpc_shares = generate_key_shares(self.config.key_type, threshold_config)
            .map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        // Wrap shares with participant information
        let key_shares: Vec<KeyShare> = mpc_shares
            .into_iter()
            .enumerate()
            .map(|(i, mpc_share)| {
                let participant_id = format!("{}-recovered-{}", self.config.participant_id_prefix, i + 1);
                KeyShare::new((i + 1) as u32, participant_id, mpc_share)
            })
            .collect();

        info!(
            "Re-provisioned {} shares for wallet {}",
            key_shares.len(),
            wallet_id
        );

        Ok(key_shares)
    }
}

impl Default for WalletProvisioner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provisioning_config_default() {
        let config = ProvisioningConfig::default();
        assert_eq!(config.threshold, 2);
        assert_eq!(config.total_shares, 3);
        assert_eq!(config.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_provisioning_config_validation() {
        // Valid config
        let config = ProvisioningConfig::new(2, 3).unwrap();
        assert!(config.validate().is_ok());

        // Invalid: threshold > total
        let result = ProvisioningConfig::new(4, 3);
        assert!(result.is_err());

        // Invalid: threshold = 0
        let result = ProvisioningConfig::new(0, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_provision_wallet() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        assert_eq!(wallet.threshold, 2);
        assert_eq!(wallet.total_shares, 3);
        assert_eq!(wallet.share_count(), 3);
        assert!(wallet.can_sign());
        assert_eq!(wallet.key_type, KeyType::Ed25519);
    }

    #[test]
    fn test_provision_wallet_with_label() {
        let provisioner = WalletProvisioner::new();
        let label = "My Tenzro Wallet".to_string();
        let wallet = provisioner.provision_wallet_with_label(label.clone()).unwrap();

        assert_eq!(wallet.label, Some(label));
    }

    #[test]
    fn test_provision_wallet_custom_config() {
        let config = ProvisioningConfig::new(3, 5)
            .unwrap()
            .with_key_type(KeyType::Secp256k1);

        let provisioner = WalletProvisioner::with_config(config).unwrap();
        let wallet = provisioner.provision_wallet().unwrap();

        assert_eq!(wallet.threshold, 3);
        assert_eq!(wallet.total_shares, 5);
        assert_eq!(wallet.key_type, KeyType::Secp256k1);
        assert!(wallet.can_sign());
    }

    #[test]
    fn test_provision_multiple_wallets() {
        let provisioner = WalletProvisioner::new();

        let wallet1 = provisioner.provision_wallet().unwrap();
        let wallet2 = provisioner.provision_wallet().unwrap();

        // Each wallet should have a unique ID and address
        assert_ne!(wallet1.wallet_id, wallet2.wallet_id);
        assert_ne!(wallet1.address, wallet2.address);
    }

    #[test]
    fn test_reprovision_shares() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let new_shares = provisioner
            .reprovision_shares(&wallet.wallet_id, &wallet.public_key)
            .unwrap();

        assert_eq!(new_shares.len(), 3);
    }
}
