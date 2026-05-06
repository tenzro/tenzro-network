//! Transaction validation for Tenzro Network wallets.
//!
//! This module validates transactions before signing, ensuring:
//! - Chain ID is correct for the target network
//! - Nonce is valid (sequential, not replayed)
//! - Gas parameters are within bounds
//! - Addresses are valid (non-zero sender, valid format)
//! - Transaction data size is within limits
//! - Sufficient balance for value + gas

use crate::error::{Result, WalletError};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{Transaction, TransactionType};

/// Maximum transaction data size (256 KB)
const MAX_TX_DATA_SIZE: usize = 262_144;

/// Maximum gas limit per transaction (30M, matches tenzro-vm)
const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Minimum gas limit
const MIN_GAS_LIMIT: u64 = 21_000;

/// Maximum gas price (1000 Gwei = 1_000_000_000_000)
const MAX_GAS_PRICE: u64 = 1_000_000_000_000;

/// Minimum gas price (1 Gwei = 1_000_000_000)
const MIN_GAS_PRICE: u64 = 1_000_000_000;

/// Maximum memo length (1 KB)
const MAX_MEMO_LENGTH: usize = 1024;

/// Validation configuration for transaction checks.
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Expected chain ID for this network
    pub chain_id: ChainId,
    /// Maximum allowed gas limit
    pub max_gas_limit: u64,
    /// Minimum gas limit
    pub min_gas_limit: u64,
    /// Maximum gas price
    pub max_gas_price: u64,
    /// Minimum gas price
    pub min_gas_price: u64,
    /// Maximum transaction data size in bytes
    pub max_data_size: usize,
    /// Maximum memo length
    pub max_memo_length: usize,
    /// Whether to enforce strict nonce ordering
    pub strict_nonce: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId(1337), // Tenzro default chain ID
            max_gas_limit: MAX_GAS_LIMIT,
            min_gas_limit: MIN_GAS_LIMIT,
            max_gas_price: MAX_GAS_PRICE,
            min_gas_price: MIN_GAS_PRICE,
            max_data_size: MAX_TX_DATA_SIZE,
            max_memo_length: MAX_MEMO_LENGTH,
            strict_nonce: true,
        }
    }
}

impl ValidationConfig {
    /// Create a new validation config with a specific chain ID
    pub fn with_chain_id(mut self, chain_id: ChainId) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Set strict nonce enforcement
    pub fn with_strict_nonce(mut self, strict: bool) -> Self {
        self.strict_nonce = strict;
        self
    }

    /// Set gas bounds
    pub fn with_gas_bounds(mut self, min: u64, max: u64) -> Self {
        self.min_gas_limit = min;
        self.max_gas_limit = max;
        self
    }
}

/// Validation error details providing specific failure reasons.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// The field that failed validation
    pub field: String,
    /// Human-readable error message
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Transaction validator enforcing network rules before signing.
pub struct TransactionValidator {
    config: ValidationConfig,
}

impl TransactionValidator {
    /// Create a new validator with default configuration
    pub fn new() -> Self {
        Self {
            config: ValidationConfig::default(),
        }
    }

    /// Create a new validator with custom configuration
    pub fn with_config(config: ValidationConfig) -> Self {
        Self { config }
    }

    /// Validate a transaction against all rules.
    ///
    /// Returns Ok(()) if valid, or a WalletError with details if invalid.
    pub fn validate(&self, tx: &Transaction) -> Result<()> {
        let mut errors = Vec::new();

        self.validate_chain_id(tx, &mut errors);
        self.validate_addresses(tx, &mut errors);
        self.validate_gas(tx, &mut errors);
        self.validate_data_size(tx, &mut errors);
        self.validate_memo(tx, &mut errors);
        self.validate_tx_type(tx, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            let msg = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            Err(WalletError::TransactionValidationFailed(msg))
        }
    }

    /// Validate a transaction with a known expected nonce.
    pub fn validate_with_nonce(
        &self,
        tx: &Transaction,
        expected_nonce: Nonce,
    ) -> Result<()> {
        let mut errors = Vec::new();

        self.validate_chain_id(tx, &mut errors);
        self.validate_addresses(tx, &mut errors);
        self.validate_gas(tx, &mut errors);
        self.validate_data_size(tx, &mut errors);
        self.validate_memo(tx, &mut errors);
        self.validate_tx_type(tx, &mut errors);

        if self.config.strict_nonce && tx.nonce != expected_nonce {
            errors.push(ValidationError {
                field: "nonce".to_string(),
                message: format!(
                    "expected nonce {}, got {}",
                    expected_nonce.0, tx.nonce.0
                ),
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            let msg = errors
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            Err(WalletError::TransactionValidationFailed(msg))
        }
    }

    /// Validate with balance check.
    pub fn validate_with_balance(
        &self,
        tx: &Transaction,
        available_balance: u128,
    ) -> Result<()> {
        self.validate(tx)?;

        // Calculate total cost: value + gas
        let gas_cost = (tx.gas_limit as u128)
            .checked_mul(tx.gas_price as u128)
            .ok_or_else(|| {
                WalletError::TransactionValidationFailed(
                    "gas cost overflow".to_string(),
                )
            })?;

        let value = match &tx.tx_type {
            TransactionType::Transfer { amount } => *amount,
            TransactionType::ProviderStake { amount, .. } => *amount,
            TransactionType::BridgeTransfer { amount, .. } => *amount,
            _ => 0,
        };

        let total_cost = value
            .checked_add(gas_cost)
            .ok_or_else(|| {
                WalletError::TransactionValidationFailed(
                    "total cost overflow".to_string(),
                )
            })?;

        if available_balance < total_cost {
            return Err(WalletError::InsufficientBalance {
                have: available_balance,
                need: total_cost,
            });
        }

        Ok(())
    }

    fn validate_chain_id(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        if tx.chain_id != self.config.chain_id {
            errors.push(ValidationError {
                field: "chain_id".to_string(),
                message: format!(
                    "expected chain ID {}, got {}",
                    self.config.chain_id.0, tx.chain_id.0
                ),
            });
        }
    }

    fn validate_addresses(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        if tx.from == Address::zero() {
            errors.push(ValidationError {
                field: "from".to_string(),
                message: "sender address cannot be zero".to_string(),
            });
        }

        // Recipient can be zero only for contract deployment
        if tx.to == Address::zero() {
            match &tx.tx_type {
                TransactionType::ContractDeploy { .. } => {
                    // Zero address is valid for contract creation
                }
                _ => {
                    errors.push(ValidationError {
                        field: "to".to_string(),
                        message: "recipient address cannot be zero (except for contract deployment)".to_string(),
                    });
                }
            }
        }

        // Sender and recipient should be different for transfers
        if tx.from == tx.to
            && let TransactionType::Transfer { .. } = &tx.tx_type
        {
            errors.push(ValidationError {
                field: "to".to_string(),
                message: "cannot transfer to self".to_string(),
            });
        }
    }

    fn validate_gas(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        if tx.gas_limit == 0 {
            errors.push(ValidationError {
                field: "gas_limit".to_string(),
                message: "gas limit cannot be zero".to_string(),
            });
        } else if tx.gas_limit < self.config.min_gas_limit {
            errors.push(ValidationError {
                field: "gas_limit".to_string(),
                message: format!(
                    "gas limit {} below minimum {}",
                    tx.gas_limit, self.config.min_gas_limit
                ),
            });
        } else if tx.gas_limit > self.config.max_gas_limit {
            errors.push(ValidationError {
                field: "gas_limit".to_string(),
                message: format!(
                    "gas limit {} exceeds maximum {}",
                    tx.gas_limit, self.config.max_gas_limit
                ),
            });
        }

        if tx.gas_price == 0 {
            errors.push(ValidationError {
                field: "gas_price".to_string(),
                message: "gas price cannot be zero".to_string(),
            });
        } else if tx.gas_price < self.config.min_gas_price {
            errors.push(ValidationError {
                field: "gas_price".to_string(),
                message: format!(
                    "gas price {} below minimum {}",
                    tx.gas_price, self.config.min_gas_price
                ),
            });
        } else if tx.gas_price > self.config.max_gas_price {
            errors.push(ValidationError {
                field: "gas_price".to_string(),
                message: format!(
                    "gas price {} exceeds maximum {}",
                    tx.gas_price, self.config.max_gas_price
                ),
            });
        }
    }

    fn validate_data_size(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        let data_size = match &tx.tx_type {
            TransactionType::ContractDeploy { code, args } => code.len() + args.len(),
            TransactionType::ContractCall { function, args } => function.len() + args.len(),
            TransactionType::AgentRegister { config } => config.len(),
            TransactionType::AgentExecute { task } => task.len(),
            TransactionType::ModelInference { model_id, input } => model_id.len() + input.len(),
            TransactionType::TeeProviderRegister { attestation, info } => {
                attestation.len() + info.len()
            }
            TransactionType::GovernancePropose { proposal } => proposal.len(),
            _ => 0,
        };

        if data_size > self.config.max_data_size {
            errors.push(ValidationError {
                field: "data".to_string(),
                message: format!(
                    "transaction data size {} exceeds maximum {}",
                    data_size, self.config.max_data_size
                ),
            });
        }
    }

    fn validate_memo(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        if let Some(ref memo) = tx.memo
            && memo.len() > self.config.max_memo_length
        {
            errors.push(ValidationError {
                field: "memo".to_string(),
                message: format!(
                    "memo length {} exceeds maximum {}",
                    memo.len(),
                    self.config.max_memo_length
                ),
            });
        }
    }

    fn validate_tx_type(&self, tx: &Transaction, errors: &mut Vec<ValidationError>) {
        match &tx.tx_type {
            TransactionType::Transfer { amount } => {
                if *amount == 0 {
                    errors.push(ValidationError {
                        field: "amount".to_string(),
                        message: "transfer amount cannot be zero".to_string(),
                    });
                }
            }
            TransactionType::ProviderStake { amount, provider_type } => {
                if *amount == 0 {
                    errors.push(ValidationError {
                        field: "amount".to_string(),
                        message: "stake amount cannot be zero".to_string(),
                    });
                }
                if provider_type.is_empty() {
                    errors.push(ValidationError {
                        field: "provider_type".to_string(),
                        message: "provider type cannot be empty".to_string(),
                    });
                }
            }
            TransactionType::ProviderUnstake { amount } => {
                if *amount == 0 {
                    errors.push(ValidationError {
                        field: "amount".to_string(),
                        message: "unstake amount cannot be zero".to_string(),
                    });
                }
            }
            TransactionType::ContractDeploy { code, .. } => {
                if code.is_empty() {
                    errors.push(ValidationError {
                        field: "code".to_string(),
                        message: "contract code cannot be empty".to_string(),
                    });
                }
                if code.len() > 24_576 {
                    errors.push(ValidationError {
                        field: "code".to_string(),
                        message: format!(
                            "contract code size {} exceeds maximum 24576 bytes",
                            code.len()
                        ),
                    });
                }
            }
            TransactionType::ContractCall { function, .. } => {
                if function.is_empty() {
                    errors.push(ValidationError {
                        field: "function".to_string(),
                        message: "function name cannot be empty".to_string(),
                    });
                }
            }
            TransactionType::ModelInference { model_id, input } => {
                if model_id.is_empty() {
                    errors.push(ValidationError {
                        field: "model_id".to_string(),
                        message: "model ID cannot be empty".to_string(),
                    });
                }
                if input.is_empty() {
                    errors.push(ValidationError {
                        field: "input".to_string(),
                        message: "inference input cannot be empty".to_string(),
                    });
                }
            }
            TransactionType::GovernanceVote { proposal_id, .. } => {
                if proposal_id.is_empty() {
                    errors.push(ValidationError {
                        field: "proposal_id".to_string(),
                        message: "proposal ID cannot be empty".to_string(),
                    });
                }
            }
            TransactionType::BridgeTransfer {
                target_chain,
                target_address,
                amount,
            } => {
                if *amount == 0 {
                    errors.push(ValidationError {
                        field: "amount".to_string(),
                        message: "bridge transfer amount cannot be zero".to_string(),
                    });
                }
                if target_chain.is_empty() {
                    errors.push(ValidationError {
                        field: "target_chain".to_string(),
                        message: "target chain cannot be empty".to_string(),
                    });
                }
                if target_address.is_empty() {
                    errors.push(ValidationError {
                        field: "target_address".to_string(),
                        message: "target address cannot be empty".to_string(),
                    });
                }
            }
            _ => {}
        }
    }
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;

    fn pq_pk() -> Vec<u8> {
        MlDsaSigningKey::generate().verifying_key_bytes().to_vec()
    }

    fn create_valid_transfer() -> Transaction {
        Transaction::new(
            ChainId(1337),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000, // 1 Gwei
            pq_pk(),
        )
    }

    #[test]
    fn test_valid_transfer() {
        let validator = TransactionValidator::new();
        let tx = create_valid_transfer();
        assert!(validator.validate(&tx).is_ok());
    }

    #[test]
    fn test_wrong_chain_id() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(999),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("chain ID"));
    }

    #[test]
    fn test_zero_sender() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(1337),
            Address::zero(),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("sender"));
    }

    #[test]
    fn test_self_transfer() {
        let validator = TransactionValidator::new();
        let addr = Address::new([1u8; 32]);
        let tx = Transaction::new(
            ChainId(1337),
            addr,
            addr,
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("self"));
    }

    #[test]
    fn test_gas_limit_too_low() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            100, // way too low
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("gas limit"));
    }

    #[test]
    fn test_gas_limit_too_high() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            50_000_000, // exceeds 30M max
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("gas limit"));
    }

    #[test]
    fn test_zero_transfer_amount() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 0 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("amount"));
    }

    #[test]
    fn test_nonce_validation() {
        let validator = TransactionValidator::new();
        let tx = create_valid_transfer();

        // Expected nonce 0, tx has nonce 0 → OK
        assert!(validator.validate_with_nonce(&tx, Nonce(0)).is_ok());

        // Expected nonce 1, tx has nonce 0 → fail
        let err = validator.validate_with_nonce(&tx, Nonce(1)).unwrap_err();
        assert!(err.to_string().contains("nonce"));
    }

    #[test]
    fn test_balance_validation() {
        let validator = TransactionValidator::new();
        let tx = create_valid_transfer();

        // gas_cost = 21_000 * 1_000_000_000 = 21_000_000_000_000
        // value = 1000
        // total = 21_000_000_001_000
        let sufficient = 22_000_000_000_000u128;
        assert!(validator.validate_with_balance(&tx, sufficient).is_ok());

        let insufficient = 100u128;
        let err = validator.validate_with_balance(&tx, insufficient).unwrap_err();
        assert!(err.to_string().contains("Insufficient"));
    }

    #[test]
    fn test_contract_code_too_large() {
        let validator = TransactionValidator::new();
        let tx = Transaction::new(
            ChainId(1337),
            Address::new([1u8; 32]),
            Address::zero(), // zero for contract deploy
            Nonce(0),
            TransactionType::ContractDeploy {
                code: vec![0u8; 25_000], // exceeds 24576
                args: vec![],
            },
            1_000_000,
            1_000_000_000,
            pq_pk(),
        );
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("contract code size"));
    }

    #[test]
    fn test_memo_too_long() {
        let validator = TransactionValidator::new();
        let mut tx = create_valid_transfer();
        tx.memo = Some("x".repeat(2000));
        let err = validator.validate(&tx).unwrap_err();
        assert!(err.to_string().contains("memo"));
    }

    #[test]
    fn test_custom_config() {
        let config = ValidationConfig::default()
            .with_chain_id(ChainId(42))
            .with_gas_bounds(10_000, 50_000_000);

        let validator = TransactionValidator::with_config(config);

        let tx = Transaction::new(
            ChainId(42),
            Address::new([1u8; 32]),
            Address::new([2u8; 32]),
            Nonce(0),
            TransactionType::Transfer { amount: 1000 },
            21_000,
            1_000_000_000,
            pq_pk(),
        );
        assert!(validator.validate(&tx).is_ok());
    }
}
