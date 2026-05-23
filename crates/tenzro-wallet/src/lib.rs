//! MPC Wallet System for Tenzro Network
//!
//! This crate provides auto-provisioned threshold wallets for Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Key Features
//!
//! - **Seamless Onboarding**: Auto-provisioned MPC wallets - no seed phrases to manage
//! - **Threshold Signatures**: 2-of-3 (configurable) multi-party signing
//! - **Multi-Asset Support**: TNZO (native settlement), plus USDC, USDT, and major tokens
//! - **Encrypted Storage**: Password-protected keystore for key shares (Argon2id)
//! - **Transaction Validation**: Chain ID, nonce, gas, address, and data size checks
//! - **Signature Verification**: Automatic post-signing cryptographic verification
//! - **Nonce Management**: Per-address sequential nonces with replay protection
//! - **Transaction History**: Full lifecycle tracking with filtering and pagination
//! - **Address Book**: Contact management with name resolution and tag filtering
//! - **State Sync**: On-chain balance/nonce synchronization via ChainStateProvider
//! - **Transaction Builder**: Type-safe builder pattern with auto gas estimation
//! - **Key Zeroization**: Sensitive key material zeroized on drop
//!
//! # Architecture
//!
//! The wallet system uses Multi-Party Computation (MPC) to distribute key shares
//! across multiple parties. A threshold number of shares (e.g., 2 out of 3) are
//! required to generate signatures, providing security without single points of failure.
//!
//! # Examples
//!
//! ## Provisioning a new wallet
//!
//! ```no_run
//! use tenzro_wallet::service::TenzroWalletService;
//! use tenzro_wallet::traits::WalletService;
//!
//! # async fn example() -> tenzro_wallet::error::Result<()> {
//! let service = TenzroWalletService::new()?;
//!
//! // Auto-provision a new MPC wallet
//! let wallet = service.provision_wallet().await?;
//!
//! println!("Wallet created: {}", wallet.wallet_id);
//! println!("Address: {}", wallet.address);
//! println!("Threshold: {}-of-{}", wallet.threshold, wallet.total_shares);
//! # Ok(())
//! # }
//! ```
//!
//! ## Building and signing a transaction
//!
//! ```no_run
//! use tenzro_wallet::service::TenzroWalletService;
//! use tenzro_wallet::traits::WalletService;
//! use tenzro_wallet::builder::TransactionBuilder;
//! use tenzro_types::primitives::{Address, Nonce};
//!
//! # async fn example() -> tenzro_wallet::error::Result<()> {
//! let service = TenzroWalletService::new()?;
//! let wallet = service.provision_wallet().await?;
//!
//! // Build a validated transfer transaction. `from_wallet_pq` binds the
//! // wallet's classical address AND its ML-DSA-65 verifying key into the
//! // transaction so the hybrid signature stays self-consistent.
//! let tx = TransactionBuilder::default_chain()
//!     .from_wallet_pq(&wallet)
//!     .to(Address::new([2u8; 32]))
//!     .nonce(service.next_nonce(&wallet.address))
//!     .transfer(1000)
//!     .build_validated()?;
//!
//! // Sign (validates, signs with MPC threshold + ML-DSA-65, verifies both legs)
//! let signature = service.sign_transaction(&wallet.wallet_id, &tx).await?;
//! println!(
//!     "Signature: classical={} bytes, pq={} bytes",
//!     signature.classical.len(),
//!     signature.pq.len(),
//! );
//! # Ok(())
//! # }
//! ```

pub mod asset_manager;
pub mod balance;
pub mod builder;
pub mod contacts;
pub mod error;
pub mod history;
pub mod keystore;
pub mod mpc_signing;
pub mod nonce;
pub mod provisioning;
pub mod rpc_provider;
pub mod service;
pub mod signing;
pub mod state_sync;
pub mod traits;
pub mod userop;
pub mod validation;
pub mod wallet;

// Re-export commonly used types
pub use asset_manager::{AssetManager, DefaultAssetConfig, SharedAssetManager};
pub use balance::{Balance, BalanceProvider, BalanceTracker};
pub use builder::TransactionBuilder;
pub use contacts::{AddressBook, Contact};
pub use error::{Result, WalletError};
pub use history::{HistoryFilter, TransactionHistory, TxDirection, TxRecord, TxStatus};
pub use keystore::Keystore;
pub use mpc_signing::{MpcSigner, TransactionSigner};
pub use nonce::NonceManager;
pub use provisioning::{ProvisioningConfig, WalletProvisioner};
pub use service::{TenzroWalletService, WalletServiceConfig};
pub use signing::HybridSignatureBytes;
pub use state_sync::{ChainStateProvider, LocalStateProvider, WalletStateSync};
pub use traits::WalletService;
pub use userop::{
    encode_user_op_json, pack_validator_signature, user_op_hash, UserOp, UserOpBuilder,
};
pub use validation::{TransactionValidator, ValidationConfig};
pub use wallet::{KeyShare, MpcWallet, WalletId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_exports() {
        // Ensure main types are accessible
        let _ = ProvisioningConfig::default();
        let _ = WalletServiceConfig::default();
        let _ = WalletId::new();
        let _ = ValidationConfig::default();
        let _ = NonceManager::new();
        let _ = TransactionHistory::new();
        let _ = AddressBook::new();
    }
}
