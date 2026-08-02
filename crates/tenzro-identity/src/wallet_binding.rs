//! Wallet binding for the Tenzro Decentralized Identity Protocol
//!
//! Automatically provisions MPC wallets for new identities and binds
//! wallet addresses to identity DIDs.

use crate::error::{IdentityError, Result};
use std::sync::Arc;
use tenzro_types::primitives::Address;
use tenzro_wallet::{HybridSignatureBytes, TenzroWalletService, WalletId, WalletService};
use tracing::info;

/// Wallet provisioning result
pub struct WalletBinding {
    /// The wallet ID
    pub wallet_id: String,
    /// The wallet address
    pub address: Address,
    /// The wallet's classical public key bytes (Ed25519 or Secp256k1, depending
    /// on the wallet service's configured key type). Used by registration
    /// flows that want the identity's `public_keys[0]` to match the
    /// signable wallet keypair, so the identity can authenticate itself
    /// directly via the wallet without a separate keypair binding.
    pub public_key: Vec<u8>,
    /// The classical public key type ("Ed25519" or "Secp256k1").
    pub key_type: String,
    /// The wallet's ML-DSA-65 verifying key bytes (FIPS 204, exactly 1952 bytes).
    /// Mandatory under the hybrid migration — every wallet carries
    /// a PQ key, so identities bound to a wallet inherit it directly.
    pub pq_verifying_key: Vec<u8>,
    /// The wallet's BLS12-381 G1-compressed verifying key (`min_pk` scheme,
    /// exactly 48 bytes). Mandatory under ROADMAP B.1 — every wallet
    /// carries a BLS key so the identity inherits the public key needed for
    /// HotStuff-2 vote aggregation when the identity stakes as a validator.
    pub bls_verifying_key: Vec<u8>,
}

/// Binds MPC wallets to TDIP identities
///
/// Handles auto-provisioning of threshold wallets when new identities
/// are registered, ensuring every identity has a wallet for on-chain operations.
///
/// The binder holds an `Arc<TenzroWalletService>` so the registry and the
/// node-level RPC handlers share a single wallet service instance — wallets
/// provisioned during identity registration are immediately resolvable by
/// `WalletService::sign_transaction` against the same `wallet_id`.
pub struct WalletBinder {
    wallet_service: Arc<TenzroWalletService>,
}

impl WalletBinder {
    /// Creates a new wallet binder backed by a fresh in-process wallet service.
    ///
    /// Suitable for tests; production node startup must use
    /// [`Self::from_service`] so the binder shares the node's `WalletService`.
    pub fn new() -> Result<Self> {
        let wallet_service = Arc::new(
            TenzroWalletService::new().map_err(|e| IdentityError::WalletError(e.to_string()))?,
        );
        Ok(Self { wallet_service })
    }

    /// Creates a wallet binder backed by an existing shared wallet service.
    ///
    /// This is the production wiring used by the node: the same
    /// `Arc<TenzroWalletService>` that backs `tenzro_*` RPC handlers is
    /// passed in here, so wallets provisioned via
    /// `IdentityRegistry::register_human_with_fee` are signable by the
    /// auth-mediated `tenzro_signTransaction` / `tenzro_signAndSendTransaction`
    /// paths without any wallet-id translation.
    pub fn from_service(wallet_service: Arc<TenzroWalletService>) -> Self {
        Self { wallet_service }
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
        let bls_verifying_key = wallet.bls_verifying_key_bytes().to_vec();
        let public_key = wallet.public_key.to_bytes();
        let key_type = match wallet.public_key.key_type() {
            tenzro_crypto::KeyType::Ed25519 => "Ed25519".to_string(),
            tenzro_crypto::KeyType::Secp256k1 => "Secp256k1".to_string(),
        };

        Ok(WalletBinding {
            wallet_id: wallet.wallet_id.to_string(),
            address: Address::new(addr_bytes),
            public_key,
            key_type,
            pq_verifying_key,
            bls_verifying_key,
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
