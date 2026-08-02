//! Auto-provisioning for FROST-Ed25519 threshold wallets.
//!
//! Generates a fresh threshold key with a trusted dealer (in-process) and
//! returns a fully-functional [`MpcWallet`] ready to sign immediately. No
//! seed phrases, no manual key management.
//!
//! For the no-trusted-dealer path (each signer runs DKG in their own
//! process), use the `tenzro_crypto::frost::dkg_part1/2/3` primitives
//! directly — the wallet provisioner does not coordinate cross-node DKG.

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, MpcWallet, WalletId};
use tenzro_crypto::bls::BlsKeyPair;
use tenzro_crypto::frost::keygen_with_trusted_dealer;
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_types::primitives::Address;
use tracing::{debug, info};

/// Configuration for wallet provisioning.
#[derive(Debug, Clone)]
pub struct ProvisioningConfig {
    /// FROST threshold (default: 2). Minimum number of signers required to
    /// produce a valid signature.
    pub threshold: u16,
    /// Total number of FROST signers (default: 3).
    pub total_shares: u16,
    /// Participant ID prefix used to label each signer's [`KeyShare`].
    pub participant_id_prefix: String,
}

impl Default for ProvisioningConfig {
    fn default() -> Self {
        Self {
            threshold: 2,
            total_shares: 3,
            participant_id_prefix: "tenzro-participant".to_string(),
        }
    }
}

impl ProvisioningConfig {
    /// Create a new provisioning config.
    pub fn new(threshold: u16, total_shares: u16) -> Result<Self> {
        let cfg = Self {
            threshold,
            total_shares,
            participant_id_prefix: "tenzro-participant".to_string(),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Set the participant ID prefix.
    pub fn with_participant_prefix(mut self, prefix: String) -> Self {
        self.participant_id_prefix = prefix;
        self
    }

    /// Validate the configuration.
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

/// Wallet provisioner for auto-generating FROST-Ed25519 threshold wallets.
#[derive(Debug, Clone)]
pub struct WalletProvisioner {
    config: ProvisioningConfig,
}

impl WalletProvisioner {
    /// Create a new wallet provisioner with default config (2-of-3, Ed25519).
    pub fn new() -> Self {
        Self {
            config: ProvisioningConfig::default(),
        }
    }

    /// Create a new wallet provisioner with custom config.
    pub fn with_config(config: ProvisioningConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Get the provisioning configuration.
    pub fn config(&self) -> &ProvisioningConfig {
        &self.config
    }

    /// Provision a new FROST threshold wallet.
    pub fn provision_wallet(&self) -> Result<MpcWallet> {
        self.provision_wallet_with_id(WalletId::new())
    }

    /// Provision a wallet with a specific ID.
    pub fn provision_wallet_with_id(&self, wallet_id: WalletId) -> Result<MpcWallet> {
        info!(
            "Provisioning new FROST wallet: {} ({}-of-{})",
            wallet_id, self.config.threshold, self.config.total_shares
        );

        debug!("Generating {} FROST shares", self.config.total_shares);
        let (pubkey_pkg, secret_shares) =
            keygen_with_trusted_dealer(self.config.threshold, self.config.total_shares)
                .map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        let key_shares: Vec<KeyShare> = secret_shares
            .into_iter()
            .map(|s| {
                let participant_id = format!("{}-{}", self.config.participant_id_prefix, s.index.0);
                KeyShare::new(s.index, participant_id, s)
            })
            .collect();

        let group_pk = pubkey_pkg.group_public_key.as_public_key();
        let address = self.derive_address(&group_pk);
        debug!("Wallet address: {}", address);

        // Mandatory PQ leg.
        let pq_signing_key = MlDsaSigningKey::generate();

        // Mandatory BLS leg for HotStuff-2 vote aggregation.
        let bls_signing_key =
            BlsKeyPair::generate().map_err(|e| WalletError::ProvisioningFailed(e.to_string()))?;

        let wallet = MpcWallet::new(
            wallet_id.clone(),
            address,
            key_shares,
            pubkey_pkg,
            pq_signing_key,
            bls_signing_key,
        )?;

        info!(
            "Successfully provisioned FROST wallet {} at address {}",
            wallet_id, address
        );

        Ok(wallet)
    }

    /// Provision a wallet with a custom label.
    pub fn provision_wallet_with_label(&self, label: String) -> Result<MpcWallet> {
        let mut wallet = self.provision_wallet()?;
        wallet.set_label(label);
        Ok(wallet)
    }

    /// Derive a Tenzro address from a public key.
    fn derive_address(&self, public_key: &tenzro_crypto::PublicKey) -> Address {
        let crypto_address = public_key.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_address.as_bytes());
        Address::new(addr_bytes)
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
    }

    #[test]
    fn test_provisioning_config_validation() {
        let config = ProvisioningConfig::new(2, 3).unwrap();
        assert!(config.validate().is_ok());

        // Invalid: threshold > total
        assert!(ProvisioningConfig::new(4, 3).is_err());

        // Invalid: threshold = 0
        assert!(ProvisioningConfig::new(0, 3).is_err());
    }

    #[test]
    fn test_provision_wallet_default() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        assert_eq!(wallet.threshold, 2);
        assert_eq!(wallet.total_shares, 3);
        assert_eq!(wallet.share_count(), 3);
        assert!(wallet.can_sign());
        assert_eq!(wallet.key_type(), tenzro_crypto::KeyType::Ed25519);
    }

    #[test]
    fn test_provision_wallet_with_label() {
        let provisioner = WalletProvisioner::new();
        let label = "My Tenzro Wallet".to_string();
        let wallet = provisioner
            .provision_wallet_with_label(label.clone())
            .unwrap();
        assert_eq!(wallet.label, Some(label));
    }

    #[test]
    fn test_provision_wallet_3_of_5() {
        let config = ProvisioningConfig::new(3, 5).unwrap();
        let provisioner = WalletProvisioner::with_config(config).unwrap();
        let wallet = provisioner.provision_wallet().unwrap();

        assert_eq!(wallet.threshold, 3);
        assert_eq!(wallet.total_shares, 5);
        assert!(wallet.can_sign());
    }

    #[test]
    fn test_provision_multiple_wallets_distinct() {
        let provisioner = WalletProvisioner::new();
        let wallet1 = provisioner.provision_wallet().unwrap();
        let wallet2 = provisioner.provision_wallet().unwrap();

        assert_ne!(wallet1.wallet_id, wallet2.wallet_id);
        assert_ne!(wallet1.address, wallet2.address);
        // Different keygen sessions → different group public keys.
        assert_ne!(wallet1.public_key, wallet2.public_key);
    }
}
