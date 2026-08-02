//! Wallet types for Tenzro Network
//!
//! This module defines types for wallet management, key storage,
//! and account access.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};

/// Information about a wallet on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletInfo {
    /// Wallet identifier
    pub wallet_id: String,
    /// Wallet type
    pub wallet_type: WalletType,
    /// Accounts associated with this wallet
    pub accounts: Vec<Address>,
    /// Wallet label/name
    pub label: Option<String>,
    /// Wallet creation timestamp
    pub created_at: Timestamp,
    /// Last access timestamp
    pub last_accessed: Option<Timestamp>,
}

impl WalletInfo {
    /// Creates a new wallet info
    pub fn new(wallet_id: String, wallet_type: WalletType) -> Self {
        Self {
            wallet_id,
            wallet_type,
            accounts: Vec::new(),
            label: None,
            created_at: Timestamp::now(),
            last_accessed: None,
        }
    }

    /// Adds a label to the wallet
    pub fn with_label(mut self, label: String) -> Self {
        self.label = Some(label);
        self
    }

    /// Adds an account to the wallet
    pub fn add_account(&mut self, address: Address) {
        if !self.accounts.contains(&address) {
            self.accounts.push(address);
        }
    }

    /// Updates the last accessed timestamp
    pub fn update_last_accessed(&mut self) {
        self.last_accessed = Some(Timestamp::now());
    }

    /// Returns the number of accounts in the wallet
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }
}

/// Type of wallet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WalletType {
    /// HD (Hierarchical Deterministic) wallet
    HD,
    /// Single-key wallet
    SingleKey,
    /// Multi-signature wallet
    MultiSig,
    /// Hardware wallet
    Hardware,
    /// Smart contract wallet
    SmartContract,
    /// Custodial wallet
    Custodial,
}

impl WalletType {
    /// Returns the wallet type name
    pub fn as_str(&self) -> &str {
        match self {
            Self::HD => "HD",
            Self::SingleKey => "Single Key",
            Self::MultiSig => "Multi-Signature",
            Self::Hardware => "Hardware",
            Self::SmartContract => "Smart Contract",
            Self::Custodial => "Custodial",
        }
    }

    /// Checks if this wallet type supports multiple accounts
    pub fn supports_multiple_accounts(&self) -> bool {
        matches!(
            self,
            Self::HD | Self::MultiSig | Self::SmartContract | Self::Custodial
        )
    }
}

/// Multi-signature wallet configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiSigConfig {
    /// Required number of signatures
    pub threshold: u32,
    /// Total number of signers
    pub total_signers: u32,
    /// Signer addresses
    pub signers: Vec<Address>,
}

impl MultiSigConfig {
    /// Creates a new multi-sig configuration
    pub fn new(threshold: u32, signers: Vec<Address>) -> Self {
        Self {
            threshold,
            total_signers: signers.len() as u32,
            signers,
        }
    }

    /// Validates the configuration
    pub fn is_valid(&self) -> bool {
        self.threshold > 0
            && self.threshold <= self.total_signers
            && self.signers.len() == self.total_signers as usize
    }

    /// Checks if an address is a signer
    pub fn is_signer(&self, address: &Address) -> bool {
        self.signers.contains(address)
    }
}
