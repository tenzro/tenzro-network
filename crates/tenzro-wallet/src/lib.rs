//! Wallet System for Tenzro Network
//!
//! This crate provides identity-bound wallets for Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Key Features
//!
//! - **Seamless Onboarding**: Identity-bound wallets - no seed phrases to manage
//! - **Hardware-Rooted Custody**: passkey (human) or secure element (machine)
//! - **Multi-Asset Support**: TNZO (native settlement), plus USDC, USDT, and major tokens
//! - **Encrypted Storage**: Password-protected keystore (Argon2id)
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
//! Every wallet is bound to an identity at construction — there is no way to
//! build one without. A human identity is rooted in a passkey; an autonomous
//! machine identity is rooted in a TPM or Apple Secure Enclave key. The signing
//! key never leaves that hardware and this crate never holds it: a wallet
//! carries the public half plus the ML-DSA-65 and BLS legs, which have no
//! hardware backing on any current platform.
//!
//! The binding is structural rather than a runtime check — see
//! [`WalletIdentity`], which has no `Default` and no constructor that omits the
//! key, so a wallet with no identity behind it does not typecheck.
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
//! // Provision a wallet bound to a human identity. The passkey holds the
//! // signing key; only its public half is passed here.
//! let identity = tenzro_wallet::WalletIdentity::human(
//!     b"passkey-credential-id".to_vec(),
//!     tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, vec![7u8; 32]),
//! )?;
//! let wallet = service.provision_wallet(identity).await?;
//!
//! println!("Wallet created: {}", wallet.wallet_id);
//! println!("Address: {}", wallet.address);
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
//! let identity = tenzro_wallet::WalletIdentity::human(
//!     b"passkey-credential-id".to_vec(),
//!     tenzro_crypto::PublicKey::new(tenzro_crypto::KeyType::Ed25519, vec![7u8; 32]),
//! )?;
//! let wallet = service.provision_wallet(identity).await?;
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
//! // Sign (validates, signs with the identity key + ML-DSA-65, verifies both legs)
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
pub mod device_custody;
/// Secure Enclave backend for [`device_custody`]. Apple targets only; the
/// pq-companion feature carries the ML-DSA leg.
#[cfg(all(
    any(target_os = "macos", target_os = "ios"),
    feature = "device-custody-se"
))]
pub mod device_custody_se;
pub mod error;
pub mod history;
pub mod identity_binding;
pub mod keystore;
pub mod nonce;
pub mod pluggable_signer;
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
pub use nonce::NonceManager;
pub use service::{TenzroWalletService, WalletServiceConfig};
pub use signing::{HybridSignatureBytes, HybridSigner};
pub use state_sync::{ChainStateProvider, LocalStateProvider, WalletStateSync};
pub use traits::WalletService;
pub use userop::{
    UserOp, UserOpBuilder, encode_user_op_json, pack_validator_signature, user_op_hash,
};
pub use validation::{TransactionValidator, ValidationConfig};
pub use wallet::{Wallet, WalletId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_exports() {
        // Ensure main types are accessible
        let _ = WalletServiceConfig::default();
        let _ = WalletId::new();
        let _ = ValidationConfig::default();
        let _ = NonceManager::new();
        let _ = TransactionHistory::new();
        let _ = AddressBook::new();
    }
}

pub use identity_binding::WalletIdentity;
