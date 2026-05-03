//! Core VM traits and interfaces

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::any::Any;

use crate::{
    error::Result,
    types::{CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, VmTransaction},
};

/// Virtual machine type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VmType {
    /// Ethereum Virtual Machine
    Evm,
    /// Solana Virtual Machine
    Svm,
    /// Canton DAML Virtual Machine
    Daml,
    /// Tenzro Native (transfers, staking, identity, payments, agents, models)
    Tenzro,
}

impl VmType {
    /// Returns the typical address length for this VM type
    pub fn address_len(&self) -> usize {
        match self {
            VmType::Evm => 20,  // EVM uses 20-byte addresses
            VmType::Svm => 32,  // SVM uses 32-byte addresses (Pubkey)
            VmType::Daml => 32, // Daml uses 32-byte addresses (same length as SVM, different prefix)
            VmType::Tenzro => 20, // Tenzro native uses 20-byte addresses (EVM-compatible)
        }
    }

    /// Detect VM type from address format
    pub fn from_address(address: &[u8]) -> Option<Self> {
        match address.len() {
            20 => Some(VmType::Evm),
            32 => Some(VmType::Svm),
            _ => None,
        }
    }
}

/// Virtual machine executor trait
///
/// This trait defines the interface that all VM implementations must provide.
/// It allows Tenzro Network to support multiple execution environments with
/// a unified interface.
#[async_trait]
pub trait VmExecutor: Send + Sync {
    /// Returns the VM type this executor handles
    fn vm_type(&self) -> VmType;

    /// Execute a transaction and update state
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to execute
    /// * `state` - Mutable reference to the VM state
    ///
    /// # Returns
    ///
    /// The execution result including gas used, output, and state changes
    async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult>;

    /// Perform a read-only contract call
    ///
    /// # Arguments
    ///
    /// * `call` - The contract call parameters
    /// * `state` - Read-only reference to the VM state
    ///
    /// # Returns
    ///
    /// The call result including output and gas used
    async fn call(&self, call: &ContractCall, state: &dyn VmState) -> Result<CallResult>;

    /// Deploy a new contract
    ///
    /// # Arguments
    ///
    /// * `deployment` - The contract deployment parameters
    /// * `state` - Mutable reference to the VM state
    ///
    /// # Returns
    ///
    /// The deployment result including contract address and gas used
    async fn deploy_contract(
        &self,
        deployment: &ContractDeployment,
        state: &mut dyn VmState,
    ) -> Result<DeployResult>;

    /// Estimate gas required for a transaction
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to estimate
    /// * `state` - Read-only reference to the VM state
    ///
    /// # Returns
    ///
    /// Estimated gas amount
    async fn estimate_gas(&self, tx: &VmTransaction, state: &dyn VmState) -> Result<u64>;
}

/// VM state interface
///
/// This trait provides access to the blockchain state from within VM execution.
/// It abstracts over the underlying storage layer and provides a simple
/// key-value interface for contracts.
pub trait VmState: Send + Sync {
    /// Downcast to concrete type for VM-specific optimizations
    fn as_any(&self) -> &dyn Any;

    /// Downcast to concrete mutable type for VM-specific optimizations
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Get contract code at the given address
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    ///
    /// # Returns
    ///
    /// The contract bytecode, or None if no contract exists at this address
    fn get_code(&self, address: &[u8]) -> Option<Vec<u8>>;

    /// Set contract code at the given address
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    /// * `code` - The contract bytecode
    fn set_code(&mut self, address: &[u8], code: Vec<u8>);

    /// Get storage value at the given key for the given address
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    /// * `key` - The storage key
    ///
    /// # Returns
    ///
    /// The storage value, or None if the key doesn't exist
    fn get_storage(&self, address: &[u8], key: &[u8]) -> Option<Vec<u8>>;

    /// Set storage value at the given key for the given address
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    /// * `key` - The storage key
    /// * `value` - The storage value
    fn set_storage(&mut self, address: &[u8], key: &[u8], value: Vec<u8>);

    /// Get account balance
    ///
    /// # Arguments
    ///
    /// * `address` - The account address
    ///
    /// # Returns
    ///
    /// The account balance in smallest units
    fn get_balance(&self, address: &[u8]) -> u128;

    /// Set account balance
    ///
    /// # Arguments
    ///
    /// * `address` - The account address
    /// * `balance` - The new balance in smallest units
    fn set_balance(&mut self, address: &[u8], balance: u128);

    /// Get account nonce
    ///
    /// # Arguments
    ///
    /// * `address` - The account address
    ///
    /// # Returns
    ///
    /// The account nonce
    fn get_nonce(&self, address: &[u8]) -> u64;

    /// Set account nonce
    ///
    /// # Arguments
    ///
    /// * `address` - The account address
    /// * `nonce` - The new nonce
    fn set_nonce(&mut self, address: &[u8], nonce: u64);

    /// Check if an account exists
    ///
    /// # Arguments
    ///
    /// * `address` - The account address
    ///
    /// # Returns
    ///
    /// True if the account exists (has code, balance, or nonce > 0)
    fn exists(&self, address: &[u8]) -> bool;
}
