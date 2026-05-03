//! VM configuration

use serde::{Deserialize, Serialize};

use crate::VmType;

/// VM runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Maximum gas limit per transaction
    pub max_gas_limit: u64,

    /// Default gas limit
    pub default_gas_limit: u64,

    /// Minimum gas price
    pub min_gas_price: u128,

    /// Maximum call depth
    pub max_call_depth: usize,

    /// Maximum contract size (in bytes)
    pub max_contract_size: usize,

    /// Enabled VM types
    pub enabled_vms: Vec<VmType>,

    /// Enable EVM precompiles
    pub enable_evm_precompiles: bool,

    /// Enable Tenzro-specific precompiles
    pub enable_tenzro_precompiles: bool,

    /// Gas price oracle update interval (in seconds)
    pub gas_price_update_interval: u64,

    /// Base fee per gas (EIP-1559 style)
    pub base_fee_per_gas: u128,

    /// Chain ID
    pub chain_id: u64,

    /// Enable debug mode (extra logging)
    pub debug: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            max_gas_limit: crate::MAX_GAS_LIMIT,
            default_gas_limit: crate::DEFAULT_GAS_LIMIT,
            min_gas_price: 1_000_000_000, // 1 Gwei
            max_call_depth: 1024,
            max_contract_size: 24_576, // 24 KB (Ethereum limit)
            enabled_vms: vec![VmType::Evm, VmType::Svm, VmType::Daml, VmType::Tenzro],
            enable_evm_precompiles: true,
            enable_tenzro_precompiles: true,
            gas_price_update_interval: 12, // 12 seconds (1 block)
            base_fee_per_gas: 1_000_000_000, // 1 Gwei
            chain_id: 1337, // Default testnet chain ID
            debug: false,
        }
    }
}

impl VmConfig {
    /// Create a new VM configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum gas limit
    pub fn with_max_gas_limit(mut self, max_gas_limit: u64) -> Self {
        self.max_gas_limit = max_gas_limit;
        self
    }

    /// Set default gas limit
    pub fn with_default_gas_limit(mut self, default_gas_limit: u64) -> Self {
        self.default_gas_limit = default_gas_limit;
        self
    }

    /// Set minimum gas price
    pub fn with_min_gas_price(mut self, min_gas_price: u128) -> Self {
        self.min_gas_price = min_gas_price;
        self
    }

    /// Set enabled VMs
    pub fn with_enabled_vms(mut self, enabled_vms: Vec<VmType>) -> Self {
        self.enabled_vms = enabled_vms;
        self
    }

    /// Set chain ID
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Enable debug mode
    pub fn with_debug(mut self, debug: bool) -> Self {
        self.debug = debug;
        self
    }

    /// Check if a VM type is enabled
    pub fn is_vm_enabled(&self, vm_type: VmType) -> bool {
        self.enabled_vms.contains(&vm_type)
    }

    /// Validate gas limit
    pub fn validate_gas_limit(&self, gas_limit: u64) -> crate::error::Result<()> {
        if gas_limit == 0 {
            return Err(crate::VmError::InvalidTransaction("Gas limit must be greater than 0".to_string()));
        }
        if gas_limit > self.max_gas_limit {
            return Err(crate::VmError::InvalidTransaction(format!(
                "Gas limit {} exceeds maximum {}",
                gas_limit, self.max_gas_limit
            )));
        }
        Ok(())
    }

    /// Validate gas price
    pub fn validate_gas_price(&self, gas_price: u128) -> crate::error::Result<()> {
        if gas_price < self.min_gas_price {
            return Err(crate::VmError::InvalidTransaction(format!(
                "Gas price {} is below minimum {}",
                gas_price, self.min_gas_price
            )));
        }
        Ok(())
    }

    /// Validate contract size
    pub fn validate_contract_size(&self, size: usize) -> crate::error::Result<()> {
        if size > self.max_contract_size {
            return Err(crate::VmError::InvalidTransaction(format!(
                "Contract size {} exceeds maximum {}",
                size, self.max_contract_size
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = VmConfig::default();
        assert_eq!(config.max_gas_limit, crate::MAX_GAS_LIMIT);
        assert_eq!(config.enabled_vms.len(), 4);
        assert!(config.is_vm_enabled(VmType::Evm));
        assert!(config.is_vm_enabled(VmType::Svm));
        assert!(config.is_vm_enabled(VmType::Daml));
        assert!(config.is_vm_enabled(VmType::Tenzro));
    }

    #[test]
    fn test_config_builder() {
        let config = VmConfig::new()
            .with_max_gas_limit(50_000_000)
            .with_chain_id(42)
            .with_debug(true);

        assert_eq!(config.max_gas_limit, 50_000_000);
        assert_eq!(config.chain_id, 42);
        assert!(config.debug);
    }

    #[test]
    fn test_gas_validation() {
        let config = VmConfig::default();

        assert!(config.validate_gas_limit(0).is_err());
        assert!(config.validate_gas_limit(1_000_000).is_ok());
        assert!(config.validate_gas_limit(config.max_gas_limit + 1).is_err());

        assert!(config.validate_gas_price(0).is_err());
        assert!(config.validate_gas_price(config.min_gas_price).is_ok());
    }
}
