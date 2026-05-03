//! Wallet binding for the Tenzro Decentralized Identity Protocol
//!
//! Automatically provisions MPC wallets for new identities and binds
//! wallet addresses to identity DIDs.

use crate::error::{IdentityError, Result};
use tenzro_types::primitives::Address;
use tenzro_wallet::{HybridSignatureBytes, TenzroWalletService, WalletId, WalletService};
use tracing::info;

/// Wallet provisioning result
pub struct WalletBinding {
    /// The wallet ID
    pub wallet_id: String,
    /// The wallet address
    pub address: Address,
    /// The wallet's ML-DSA-65 verifying key bytes (FIPS 204, exactly 1952 bytes).
    /// Mandatory under the Wave 3d hybrid migration — every wallet carries
    /// a PQ key, so identities bound to a wallet inherit it directly.
    pub pq_verifying_key: Vec<u8>,
}

/// Binds MPC wallets to TDIP identities
///
/// Handles auto-provisioning of threshold wallets when new identities
/// are registered, ensuring every identity has a wallet for on-chain operations.
pub struct WalletBinder {
    wallet_service: TenzroWalletService,
}

impl WalletBinder {
    /// Creates a new wallet binder
    pub fn new() -> Result<Self> {
        let wallet_service =
            TenzroWalletService::new().map_err(|e| IdentityError::WalletError(e.to_string()))?;
        Ok(Self { wallet_service })
    }

    /// Provisions a new MPC wallet for an identity
    pub async fn provision_wallet(&self, did: &str) -> Result<WalletBinding> {
        info!("Provisioning wallet for identity: {}", did);

        let wallet = self
            .wallet_service
            .provision_wallet()
            .await
            .map_err(|e| IdentityError::WalletError(e.to_string()))?;

        let mut addr_bytes = [0u8; 32];
        let src = wallet.address.as_bytes();
        let len = src.len().min(32);
        addr_bytes[..len].copy_from_slice(&src[..len]);

        let pq_verifying_key = wallet.pq_verifying_key_bytes();

        Ok(WalletBinding {
            wallet_id: wallet.wallet_id.to_string(),
            address: Address::new(addr_bytes),
            pq_verifying_key,
        })
    }

    /// Signs data using an identity's wallet, producing a hybrid
    /// (classical + ML-DSA-65) signature.
    pub async fn sign(&self, wallet_id: &str, data: &[u8]) -> Result<HybridSignatureBytes> {
        let wid = WalletId::from_string(wallet_id.to_string());
        self.wallet_service
            .sign_data(&wid, data)
            .await
            .map_err(|e| IdentityError::WalletError(e.to_string()))
    }
}
