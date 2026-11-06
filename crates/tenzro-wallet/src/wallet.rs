//! Identity-bound wallet types for Tenzro Network.
//!
//! Each wallet holds:
//!   * the identity's classical public key (the private half lives in the
//!     holder's hardware — a passkey for a human, a TPM 2.0 / Secure Enclave
//!     for a machine — and never enters this process),
//!   * the ML-DSA-65 verifying key the holder registered, when it has one.
//!
//! A wallet holds no secret of any kind. Every signature comes from a
//! [`crate::signing::HybridSigner`] bound to the wallet, which reaches the
//! holder's hardware.

use crate::error::{Result, WalletError};
use serde::{Deserialize, Serialize};
use tenzro_crypto::CompositePublicKey;
use tenzro_types::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use uuid::Uuid;

/// Unique identifier for a wallet in Tenzro Network.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletId(pub String);

impl WalletId {
    /// Generate a new random wallet ID
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    /// Create from string
    pub fn from_string(id: String) -> Self {
        Self(id)
    }

    /// Get the ID as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for WalletId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for WalletId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for WalletId {
    fn from(id: String) -> Self {
        Self(id)
    }
}

/// An identity-bound wallet.
///
/// The classical key is held by the holder's secure element and never appears
/// here; the wallet carries public keys only.
#[derive(Clone, Serialize, Deserialize)]
pub struct Wallet {
    /// Unique wallet identifier.
    pub wallet_id: WalletId,
    /// Wallet's address on the network (derived from the identity public key).
    pub address: Address,
    /// The holder's hardware public keys: the P-256 key that names the account
    /// and, once enrolled, its hardware ML-DSA-65 key.
    pub public_key: CompositePublicKey,
    /// List of supported assets.
    pub supported_assets: Vec<AssetId>,
    /// Wallet creation timestamp.
    pub created_at: Timestamp,
    /// Last used timestamp.
    pub last_used: Option<Timestamp>,
    /// Optional wallet label.
    pub label: Option<String>,
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("wallet_id", &self.wallet_id)
            .field("address", &self.address)
            .field("public_key", &self.public_key)
            .field("supported_assets", &self.supported_assets)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("label", &self.label)
            .finish()
    }
}

impl Wallet {
    /// Create a wallet for keys held in the holder's hardware. The address is
    /// the account the P-256 key names ([`CompositePublicKey::account_slot`]).
    pub fn new(wallet_id: WalletId, public_key: CompositePublicKey) -> Self {
        let supported_assets = vec![
            AssetId::tnzo(),
            AssetId::from("USDT"),
            AssetId::from("USDC"),
        ];
        Self {
            wallet_id,
            address: Address::new(public_key.account_slot()),
            public_key,
            supported_assets,
            created_at: Timestamp::now(),
            last_used: None,
            label: None,
        }
    }

    /// Get the wallet ID.
    pub fn id(&self) -> &WalletId {
        &self.wallet_id
    }

    /// Get the wallet address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Check if an asset is supported.
    pub fn supports_asset(&self, asset_id: &AssetId) -> bool {
        self.supported_assets.contains(asset_id)
    }

    /// Add support for a new asset.
    pub fn add_supported_asset(&mut self, asset_id: AssetId) {
        if !self.supported_assets.contains(&asset_id) {
            self.supported_assets.push(asset_id);
        }
    }

    /// Remove asset support.
    pub fn remove_supported_asset(&mut self, asset_id: &AssetId) {
        self.supported_assets.retain(|a| a != asset_id);
    }

    /// Set the wallet label.
    pub fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    /// Update last used timestamp.
    pub fn update_last_used(&mut self) {
        self.last_used = Some(Timestamp::now());
    }

    /// Serialize wallet metadata to JSON (excludes secret material).
    pub fn to_metadata_json(&self) -> Result<String> {
        serde_json::to_string(&self).map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    /// Deserialize wallet metadata from JSON.
    pub fn from_metadata_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| WalletError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;

    fn build_wallet() -> Wallet {
        Wallet::new(
            WalletId::new(),
            TestHybridSigner::hybrid(7).public_key().clone(),
        )
    }

    #[test]
    fn test_wallet_id_generation() {
        let id1 = WalletId::new();
        let id2 = WalletId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn a_wallet_is_named_by_its_p256_key() {
        let signer = TestHybridSigner::hybrid(7);
        let wallet = build_wallet();
        assert_eq!(wallet.address, signer.address());
        assert_eq!(wallet.public_key.pq.as_ref().map(Vec::len), Some(1952));
    }

    #[test]
    fn test_wallet_asset_management() {
        let mut wallet = build_wallet();

        assert!(wallet.supports_asset(&AssetId::tnzo()));
        assert!(wallet.supports_asset(&AssetId::from("USDT")));

        let new_asset = AssetId::from("ETH");
        wallet.add_supported_asset(new_asset.clone());
        assert!(wallet.supports_asset(&new_asset));

        wallet.remove_supported_asset(&new_asset);
        assert!(!wallet.supports_asset(&new_asset));
    }

    #[test]
    fn test_wallet_metadata_serialization() {
        let wallet = build_wallet();

        let json = wallet.to_metadata_json().unwrap();
        let restored = Wallet::from_metadata_json(&json).unwrap();

        assert_eq!(wallet.wallet_id, restored.wallet_id);
        assert_eq!(wallet.address, restored.address);
    }
}
