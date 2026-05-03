//! MPC wallet types for Tenzro Network.
//!
//! This module defines the core wallet structures including MPC wallets,
//! key shares, and wallet identifiers.

use crate::error::{Result, WalletError};
use serde::{Deserialize, Serialize};
use tenzro_crypto::mpc::{MpcKeyShare, ThresholdConfig};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyType, PublicKey};
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::AssetId;
use uuid::Uuid;
use zeroize::Zeroize;

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

/// A key share in an MPC wallet.
///
/// Each participant in the MPC protocol holds one key share.
/// A threshold number of shares are required to generate signatures.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeyShare {
    /// Index of this share (1-based)
    pub share_index: u32,
    /// Identifier of the participant holding this share
    pub participant_id: String,
    /// The actual MPC key share data
    #[serde(skip)]
    pub mpc_share: MpcKeyShare,
}

impl KeyShare {
    /// Create a new key share
    pub fn new(share_index: u32, participant_id: String, mpc_share: MpcKeyShare) -> Self {
        Self {
            share_index,
            participant_id,
            mpc_share,
        }
    }

    /// Get the share ID
    pub fn share_id(&self) -> u32 {
        self.mpc_share.share_id
    }

    /// Get the key type
    pub fn key_type(&self) -> KeyType {
        self.mpc_share.key_type
    }

    /// Get the threshold configuration
    pub fn config(&self) -> ThresholdConfig {
        self.mpc_share.config
    }

    /// Export to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        // Serialize the entire KeyShare including metadata
        let serializable = SerializableKeyShare {
            share_index: self.share_index,
            participant_id: self.participant_id.clone(),
            mpc_share_bytes: self.mpc_share.to_bytes(),
        };
        serde_json::to_vec(&serializable).unwrap_or_default()
    }

    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], mpc_share: MpcKeyShare) -> Result<Self> {
        let serializable: SerializableKeyShare = serde_json::from_slice(bytes)
            .map_err(|e| WalletError::SerializationError(e.to_string()))?;

        Ok(Self {
            share_index: serializable.share_index,
            participant_id: serializable.participant_id,
            mpc_share,
        })
    }
}

/// Serializable version of KeyShare for storage
#[derive(Serialize, Deserialize)]
struct SerializableKeyShare {
    share_index: u32,
    participant_id: String,
    mpc_share_bytes: Vec<u8>,
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("share_index", &self.share_index)
            .field("participant_id", &self.participant_id)
            .field("share_id", &self.mpc_share.share_id)
            .field("key_type", &self.mpc_share.key_type)
            .finish()
    }
}

/// An MPC (Multi-Party Computation) wallet for Tenzro Network.
///
/// MPC wallets provide seamless, auto-provisioned threshold signature
/// capabilities without requiring users to manage seed phrases.
#[derive(Clone, Serialize, Deserialize)]
pub struct MpcWallet {
    /// Unique wallet identifier
    pub wallet_id: WalletId,
    /// The wallet's address on the network
    pub address: Address,
    /// Threshold configuration (e.g., 2-of-3)
    pub threshold: usize,
    /// Total number of key shares
    pub total_shares: usize,
    /// Key shares held by this wallet instance
    #[serde(skip)]
    pub key_shares: Vec<KeyShare>,
    /// Combined public key (same for all shares)
    pub public_key: PublicKey,
    /// List of supported assets
    pub supported_assets: Vec<AssetId>,
    /// Key type (Ed25519 or Secp256k1)
    pub key_type: KeyType,
    /// Wallet creation timestamp
    pub created_at: Timestamp,
    /// Last used timestamp
    pub last_used: Option<Timestamp>,
    /// Optional wallet label
    pub label: Option<String>,
    /// ML-DSA-65 signing key (FIPS 204) for the post-quantum leg of the
    /// hybrid signature. Mandatory — every wallet carries one.
    ///
    /// `#[serde(skip)]` because `MlDsaSigningKey` does not implement
    /// `Serialize`; secret durability is handled by the keystore
    /// (Argon2id-encrypted) which persists the 32-byte canonical seed
    /// alongside the classical key shares.
    #[serde(skip)]
    pub pq_signing_key: Option<MlDsaSigningKey>,
    /// ML-DSA-65 verifying key bytes (FIPS 204, exactly 1952 bytes).
    /// Cached so it survives serialization round-trips for metadata-only
    /// callers; must always match `pq_signing_key.verifying_key_bytes()`
    /// when the signing key is loaded.
    pub pq_verifying_key: Vec<u8>,
}

impl std::fmt::Debug for MpcWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact `pq_signing_key` and `key_shares` so secret material never
        // leaks via tracing/println. Surface the loaded-vs-not state of the
        // PQ key for debugging the keystore unlock flow.
        f.debug_struct("MpcWallet")
            .field("wallet_id", &self.wallet_id)
            .field("address", &self.address)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("key_shares", &format_args!("<{} share(s) redacted>", self.key_shares.len()))
            .field("public_key", &self.public_key)
            .field("supported_assets", &self.supported_assets)
            .field("key_type", &self.key_type)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("label", &self.label)
            .field(
                "pq_signing_key",
                &format_args!("{}", if self.pq_signing_key.is_some() { "<loaded>" } else { "<not loaded>" }),
            )
            .field("pq_verifying_key", &format_args!("<{} bytes>", self.pq_verifying_key.len()))
            .finish()
    }
}

impl MpcWallet {
    /// Create a new MPC wallet.
    ///
    /// The `pq_signing_key` parameter is mandatory and bound directly into the
    /// wallet alongside the classical MPC key shares. There is no fallback to
    /// classical-only wallets.
    pub fn new(
        wallet_id: WalletId,
        address: Address,
        threshold: usize,
        total_shares: usize,
        key_shares: Vec<KeyShare>,
        public_key: PublicKey,
        key_type: KeyType,
        pq_signing_key: MlDsaSigningKey,
    ) -> Result<Self> {
        if key_shares.is_empty() {
            return Err(WalletError::InvalidKeyShare(
                "Must have at least one key share".to_string(),
            ));
        }

        // Default supported assets: TNZO, USDT, USDC
        let supported_assets = vec![
            AssetId::tnzo(),
            AssetId::from("USDT"),
            AssetId::from("USDC"),
        ];

        let pq_verifying_key = pq_signing_key.verifying_key_bytes().to_vec();

        Ok(Self {
            wallet_id,
            address,
            threshold,
            total_shares,
            key_shares,
            public_key,
            supported_assets,
            key_type,
            created_at: Timestamp::now(),
            last_used: None,
            label: None,
            pq_signing_key: Some(pq_signing_key),
            pq_verifying_key,
        })
    }

    /// Borrow the post-quantum (ML-DSA-65) signing key.
    ///
    /// Returns an error when the wallet was rehydrated from metadata-only
    /// storage and the keystore has not yet decrypted the secret seed.
    pub fn pq_signing_key(&self) -> Result<&MlDsaSigningKey> {
        self.pq_signing_key.as_ref().ok_or_else(|| {
            WalletError::SignatureFailed(
                "ML-DSA-65 signing key not loaded — keystore must decrypt the wallet first"
                    .to_string(),
            )
        })
    }

    /// 1952-byte ML-DSA-65 verifying key bytes (FIPS 204) for the wallet.
    ///
    /// Always available — cached on the wallet so metadata-only consumers
    /// can attach the PQ verifying key to a `Transaction` without needing the
    /// secret seed.
    pub fn pq_verifying_key_bytes(&self) -> Vec<u8> {
        self.pq_verifying_key.clone()
    }

    /// Get the wallet ID
    pub fn id(&self) -> &WalletId {
        &self.wallet_id
    }

    /// Get the wallet address
    pub fn address(&self) -> Address {
        self.address
    }

    /// Get the threshold configuration
    pub fn threshold_config(&self) -> ThresholdConfig {
        ThresholdConfig {
            threshold: self.threshold,
            total_shares: self.total_shares,
        }
    }

    /// Check if an asset is supported
    pub fn supports_asset(&self, asset_id: &AssetId) -> bool {
        self.supported_assets.contains(asset_id)
    }

    /// Add support for a new asset
    pub fn add_supported_asset(&mut self, asset_id: AssetId) {
        if !self.supported_assets.contains(&asset_id) {
            self.supported_assets.push(asset_id);
        }
    }

    /// Remove asset support
    pub fn remove_supported_asset(&mut self, asset_id: &AssetId) {
        self.supported_assets.retain(|a| a != asset_id);
    }

    /// Set the wallet label
    pub fn set_label(&mut self, label: String) {
        self.label = Some(label);
    }

    /// Update last used timestamp
    pub fn update_last_used(&mut self) {
        self.last_used = Some(Timestamp::now());
    }

    /// Get the number of key shares held by this wallet
    pub fn share_count(&self) -> usize {
        self.key_shares.len()
    }

    /// Check if we have enough shares to meet the threshold
    pub fn can_sign(&self) -> bool {
        self.key_shares.len() >= self.threshold
    }

    /// Get a reference to the key shares
    pub fn key_shares(&self) -> &[KeyShare] {
        &self.key_shares
    }

    /// Add a key share to the wallet
    pub fn add_key_share(&mut self, share: KeyShare) -> Result<()> {
        // Verify the share belongs to this wallet
        if share.mpc_share.public_key != self.public_key {
            return Err(WalletError::InvalidKeyShare(
                "Public key mismatch".to_string(),
            ));
        }

        // Check if we already have this share
        if self
            .key_shares
            .iter()
            .any(|s| s.share_id() == share.share_id())
        {
            return Err(WalletError::InvalidKeyShare(
                "Share already exists".to_string(),
            ));
        }

        self.key_shares.push(share);
        Ok(())
    }

    /// Serialize wallet metadata to JSON (excludes key shares)
    pub fn to_metadata_json(&self) -> Result<String> {
        serde_json::to_string(&self)
            .map_err(|e| WalletError::SerializationError(e.to_string()))
    }

    /// Deserialize wallet metadata from JSON
    pub fn from_metadata_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| WalletError::SerializationError(e.to_string()))
    }
}

impl Drop for MpcWallet {
    fn drop(&mut self) {
        // Zeroize sensitive key material on drop to prevent memory leaks
        // The key_shares contain the actual MPC secret shares
        for share in &mut self.key_shares {
            // Zeroize the participant ID
            share.participant_id.zeroize();
            // The MpcKeyShare's share_data is zeroized via its own Drop
        }
        self.key_shares.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::mpc::generate_key_shares;

    #[test]
    fn test_wallet_id_generation() {
        let id1 = WalletId::new();
        let id2 = WalletId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_mpc_wallet_creation() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let mpc_shares = generate_key_shares(KeyType::Ed25519, config).unwrap();

        let key_shares: Vec<_> = mpc_shares
            .into_iter()
            .enumerate()
            .map(|(i, share)| {
                KeyShare::new(
                    (i + 1) as u32,
                    format!("participant_{}", i + 1),
                    share,
                )
            })
            .collect();

        let public_key = key_shares[0].mpc_share.public_key.clone();
        let crypto_addr = public_key.to_address();
        // Convert 20-byte crypto address to 32-byte types address (zero-padded)
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        let wallet = MpcWallet::new(
            WalletId::new(),
            address,
            2,
            3,
            key_shares,
            public_key,
            KeyType::Ed25519,
            MlDsaSigningKey::generate(),
        )
        .unwrap();

        assert_eq!(wallet.threshold, 2);
        assert_eq!(wallet.total_shares, 3);
        assert_eq!(wallet.share_count(), 3);
        assert!(wallet.can_sign());
        assert_eq!(wallet.pq_verifying_key_bytes().len(), 1952);
    }

    #[test]
    fn test_wallet_asset_management() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let mpc_shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let key_shares: Vec<_> = mpc_shares
            .into_iter()
            .enumerate()
            .map(|(i, share)| {
                KeyShare::new(
                    (i + 1) as u32,
                    format!("participant_{}", i + 1),
                    share,
                )
            })
            .collect();

        let public_key = key_shares[0].mpc_share.public_key.clone();
        let crypto_addr = public_key.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        let mut wallet = MpcWallet::new(
            WalletId::new(),
            address,
            2,
            3,
            key_shares,
            public_key,
            KeyType::Ed25519,
            MlDsaSigningKey::generate(),
        )
        .unwrap();

        // Check default assets
        assert!(wallet.supports_asset(&AssetId::tnzo()));
        assert!(wallet.supports_asset(&AssetId::from("USDT")));

        // Add new asset
        let new_asset = AssetId::from("ETH");
        wallet.add_supported_asset(new_asset.clone());
        assert!(wallet.supports_asset(&new_asset));

        // Remove asset
        wallet.remove_supported_asset(&new_asset);
        assert!(!wallet.supports_asset(&new_asset));
    }

    #[test]
    fn test_wallet_metadata_serialization() {
        let config = ThresholdConfig::new(2, 3).unwrap();
        let mpc_shares = generate_key_shares(KeyType::Ed25519, config).unwrap();
        let key_shares: Vec<_> = mpc_shares
            .into_iter()
            .enumerate()
            .map(|(i, share)| {
                KeyShare::new(
                    (i + 1) as u32,
                    format!("participant_{}", i + 1),
                    share,
                )
            })
            .collect();

        let public_key = key_shares[0].mpc_share.public_key.clone();
        let crypto_addr = public_key.to_address();
        // Convert 20-byte crypto address to 32-byte types address (zero-padded)
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let address = Address::new(addr_bytes);

        let wallet = MpcWallet::new(
            WalletId::new(),
            address,
            2,
            3,
            key_shares,
            public_key,
            KeyType::Ed25519,
            MlDsaSigningKey::generate(),
        )
        .unwrap();

        let json = wallet.to_metadata_json().unwrap();
        let restored = MpcWallet::from_metadata_json(&json).unwrap();

        assert_eq!(wallet.wallet_id, restored.wallet_id);
        assert_eq!(wallet.address, restored.address);
        assert_eq!(wallet.threshold, restored.threshold);
        assert_eq!(wallet.total_shares, restored.total_shares);
    }
}
