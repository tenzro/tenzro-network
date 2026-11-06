//! Account types for Tenzro Network
//!
//! This module defines account structures and state management for the
//! Tenzro Network blockchain.

use crate::primitives::{Address, Hash, Nonce};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An account on Tenzro Network
///
/// Accounts can hold TNZO tokens, stake as providers, and interact with
/// smart contracts and AI services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// The account's address
    pub address: Address,
    /// Current nonce (transaction count)
    pub nonce: Nonce,
    /// Account balance in the smallest unit of TNZO (18 decimals, u128 for full precision)
    #[serde(with = "crate::primitives::u128_serde")]
    pub balance: u128,
    /// Staked amount for provider operations
    #[serde(with = "crate::primitives::u128_serde")]
    pub staked: u128,
    /// Account state data
    pub state: AccountState,
    /// Storage root for contract storage (if this is a contract account)
    pub storage_root: Hash,
    /// Code hash for contract accounts
    pub code_hash: Option<Hash>,
}

impl Account {
    /// Creates a new account with the given address
    pub fn new(address: Address) -> Self {
        Self {
            address,
            nonce: Nonce::initial(),
            balance: 0,
            staked: 0,
            state: AccountState::default(),
            storage_root: Hash::zero(),
            code_hash: None,
        }
    }

    /// Creates a new account with an initial balance
    pub fn with_balance(address: Address, balance: u128) -> Self {
        Self {
            address,
            nonce: Nonce::initial(),
            balance,
            staked: 0,
            state: AccountState::default(),
            storage_root: Hash::zero(),
            code_hash: None,
        }
    }

    /// Checks if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash.is_some()
    }

    /// Returns the total locked value (balance + staked)
    pub fn total_value(&self) -> u128 {
        self.balance.saturating_add(self.staked)
    }

    /// Increments the account nonce
    pub fn increment_nonce(&mut self) {
        self.nonce = self.nonce.next();
    }

    /// Adds to the account balance
    pub fn add_balance(&mut self, amount: u128) {
        self.balance = self.balance.saturating_add(amount);
    }

    /// Subtracts from the account balance
    ///
    /// Returns false if insufficient balance
    pub fn sub_balance(&mut self, amount: u128) -> bool {
        if self.balance >= amount {
            self.balance -= amount;
            true
        } else {
            false
        }
    }

    /// Stakes an amount from the account balance
    ///
    /// Returns false if insufficient balance
    pub fn stake(&mut self, amount: u128) -> bool {
        if self.balance >= amount {
            self.balance -= amount;
            self.staked = self.staked.saturating_add(amount);
            true
        } else {
            false
        }
    }

    /// Unstakes an amount to the account balance
    ///
    /// Returns false if insufficient staked amount
    pub fn unstake(&mut self, amount: u128) -> bool {
        if self.staked >= amount {
            self.staked -= amount;
            self.balance = self.balance.saturating_add(amount);
            true
        } else {
            false
        }
    }
}

/// Account state data
///
/// Contains additional metadata and state specific to different account types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    /// Account type
    pub account_type: AccountType,
    /// Provider-specific data (if this account is a provider)
    pub provider_data: Option<ProviderData>,
    /// Agent-specific data (if this account is an agent)
    pub agent_data: Option<AgentData>,
    /// Custom key-value storage
    pub metadata: HashMap<String, String>,
}

impl AccountState {
    /// Creates a new default account state
    pub fn new(account_type: AccountType) -> Self {
        Self {
            account_type,
            provider_data: None,
            agent_data: None,
            metadata: HashMap::new(),
        }
    }

    /// Sets provider data
    pub fn with_provider_data(mut self, data: ProviderData) -> Self {
        self.provider_data = Some(data);
        self
    }

    /// Sets agent data
    pub fn with_agent_data(mut self, data: AgentData) -> Self {
        self.agent_data = Some(data);
        self
    }

    /// Adds metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// The type of account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AccountType {
    /// Standard user account
    #[default]
    User,
    /// Smart contract account
    Contract,
    /// AI agent account
    Agent,
    /// TEE provider account
    TeeProvider,
    /// Model inference provider account
    ModelProvider,
    /// Storage provider account
    StorageProvider,
    /// Validator account
    Validator,
}

/// Provider-specific account data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderData {
    /// Provider type
    pub provider_type: String,
    /// Provider reputation score
    pub reputation: u64,
    /// Total services provided
    pub total_services: u64,
    /// Provider capacity
    pub capacity: HashMap<String, u64>,
    /// Provider status
    pub status: ProviderStatus,
}

/// Provider operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    /// Provider is active and accepting requests
    Active,
    /// Provider is temporarily inactive
    Inactive,
    /// Provider is suspended due to violations
    Suspended,
}

/// Agent-specific account data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentData {
    /// Agent identifier
    pub agent_id: String,
    /// Agent capabilities
    pub capabilities: Vec<String>,
    /// Total tasks completed
    pub total_tasks: u64,
    /// Agent status
    pub status: AgentStatus,
}

/// Agent operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Agent is active
    Active,
    /// Agent is idle
    Idle,
    /// Agent is paused
    Paused,
}
