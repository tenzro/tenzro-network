//! Transaction builder for Tenzro Network wallets.
//!
//! Provides a type-safe builder pattern for constructing transactions
//! with validation, automatic nonce assignment, and gas estimation.

use crate::error::{Result, WalletError};
use crate::nonce::NonceManager;
use crate::validation::{TransactionValidator, ValidationConfig};
use crate::wallet::MpcWallet;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};
use tenzro_types::transaction::{Transaction, TransactionType};

/// Default gas limit for simple transfers
const DEFAULT_TRANSFER_GAS: u64 = 21_000;

/// Default gas limit for contract calls
const DEFAULT_CALL_GAS: u64 = 100_000;

/// Default gas limit for contract deployment
const DEFAULT_DEPLOY_GAS: u64 = 1_000_000;

/// Default gas limit for governance operations
const DEFAULT_GOVERNANCE_GAS: u64 = 50_000;

/// Default gas limit for bridge transfers
const DEFAULT_BRIDGE_GAS: u64 = 200_000;

/// Default gas limit for agent/model operations
const DEFAULT_AGENT_GAS: u64 = 150_000;

/// Default gas limit for `CreateEscrow` (matches `GAS_ESCROW_CREATE` in `tenzro-vm`).
const DEFAULT_ESCROW_CREATE_GAS: u64 = 75_000;

/// Default gas limit for `ReleaseEscrow` (matches `GAS_ESCROW_RELEASE` in `tenzro-vm`).
const DEFAULT_ESCROW_RELEASE_GAS: u64 = 60_000;

/// Default gas limit for `RefundEscrow` (matches `GAS_ESCROW_REFUND` in `tenzro-vm`).
const DEFAULT_ESCROW_REFUND_GAS: u64 = 50_000;

/// Default gas price (1 Gwei)
const DEFAULT_GAS_PRICE: u64 = 1_000_000_000;

/// Transaction builder for constructing validated transactions.
///
/// Uses the builder pattern to ensure all required fields are set
/// and validates the transaction before returning it.
pub struct TransactionBuilder {
    chain_id: ChainId,
    from: Option<Address>,
    to: Option<Address>,
    nonce: Option<Nonce>,
    tx_type: Option<TransactionType>,
    gas_limit: Option<u64>,
    gas_price: Option<u64>,
    memo: Option<String>,
    pq_public_key: Option<Vec<u8>>,
}

impl TransactionBuilder {
    /// Create a new transaction builder with the given chain ID.
    pub fn new(chain_id: ChainId) -> Self {
        Self {
            chain_id,
            from: None,
            to: None,
            nonce: None,
            tx_type: None,
            gas_limit: None,
            gas_price: None,
            memo: None,
            pq_public_key: None,
        }
    }

    /// Set the ML-DSA-65 verifying key bytes (1952 bytes, FIPS 204).
    /// Mandatory: every transaction must commit to a PQ identity.
    pub fn pq_public_key(mut self, pq_public_key: Vec<u8>) -> Self {
        self.pq_public_key = Some(pq_public_key);
        self
    }

    /// Create a builder with the default Tenzro chain ID (1337).
    pub fn default_chain() -> Self {
        Self::new(ChainId(1337))
    }

    /// Set the sender address.
    pub fn from(mut self, address: Address) -> Self {
        self.from = Some(address);
        self
    }

    /// Set the sender from a wallet.
    pub fn from_wallet(mut self, wallet: &MpcWallet) -> Self {
        self.from = Some(wallet.address);
        self
    }

    /// Set the sender address AND the ML-DSA-65 verifying key from a wallet.
    ///
    /// This is the canonical way to bind a transaction to a wallet's hybrid
    /// identity: the resulting transaction commits to both the wallet's
    /// classical address and its FIPS-204 verifying key, ensuring the
    /// `Transaction::hash()` preimage is locked to the same key pair that
    /// will later sign it.
    pub fn from_wallet_pq(mut self, wallet: &MpcWallet) -> Self {
        self.from = Some(wallet.address);
        self.pq_public_key = Some(wallet.pq_verifying_key_bytes());
        self
    }

    /// Set the recipient address.
    pub fn to(mut self, address: Address) -> Self {
        self.to = Some(address);
        self
    }

    /// Set the nonce explicitly.
    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Auto-assign nonce from a nonce manager.
    pub fn auto_nonce(mut self, nonce_manager: &NonceManager) -> Self {
        if let Some(from) = &self.from {
            self.nonce = Some(nonce_manager.next_nonce(from));
        }
        self
    }

    /// Set the gas limit explicitly.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Set the gas price explicitly.
    pub fn gas_price(mut self, gas_price: u64) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Add a memo to the transaction.
    pub fn memo(mut self, memo: String) -> Self {
        self.memo = Some(memo);
        self
    }

    /// Build a TNZO transfer transaction.
    pub fn transfer(mut self, amount: u128) -> Self {
        self.tx_type = Some(TransactionType::Transfer { amount });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_TRANSFER_GAS);
        }
        self
    }

    /// Build a contract deployment transaction.
    pub fn deploy_contract(mut self, code: Vec<u8>, args: Vec<u8>) -> Self {
        self.to = Some(Address::zero());
        self.tx_type = Some(TransactionType::ContractDeploy { code, args });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_DEPLOY_GAS);
        }
        self
    }

    /// Build a contract call transaction.
    pub fn call_contract(mut self, function: String, args: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::ContractCall { function, args });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_CALL_GAS);
        }
        self
    }

    /// Build an agent registration transaction.
    pub fn register_agent(mut self, config: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::AgentRegister { config });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_AGENT_GAS);
        }
        self
    }

    /// Build an agent execution transaction.
    pub fn execute_agent(mut self, task: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::AgentExecute { task });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_AGENT_GAS);
        }
        self
    }

    /// Build a model inference transaction.
    pub fn model_inference(mut self, model_id: String, input: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::ModelInference { model_id, input });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_AGENT_GAS);
        }
        self
    }

    /// Build a TEE provider registration transaction.
    pub fn register_tee_provider(mut self, attestation: Vec<u8>, info: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::TeeProviderRegister { attestation, info });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_AGENT_GAS);
        }
        self
    }

    /// Build a staking transaction.
    pub fn stake(mut self, amount: u128, provider_type: String) -> Self {
        self.tx_type = Some(TransactionType::ProviderStake {
            amount,
            provider_type,
        });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_GOVERNANCE_GAS);
        }
        self
    }

    /// Build an unstaking transaction.
    pub fn unstake(mut self, amount: u128) -> Self {
        self.tx_type = Some(TransactionType::ProviderUnstake { amount });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_GOVERNANCE_GAS);
        }
        self
    }

    /// Build a governance proposal transaction.
    pub fn governance_propose(mut self, proposal: Vec<u8>) -> Self {
        self.tx_type = Some(TransactionType::GovernancePropose { proposal });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_GOVERNANCE_GAS);
        }
        self
    }

    /// Build a governance vote transaction.
    pub fn governance_vote(mut self, proposal_id: String, vote: bool) -> Self {
        self.tx_type = Some(TransactionType::GovernanceVote { proposal_id, vote });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_GOVERNANCE_GAS);
        }
        self
    }

    /// Build a bridge transfer transaction.
    pub fn bridge_transfer(
        mut self,
        target_chain: String,
        target_address: String,
        amount: u128,
    ) -> Self {
        self.tx_type = Some(TransactionType::BridgeTransfer {
            target_chain,
            target_address,
            amount,
        });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_BRIDGE_GAS);
        }
        self
    }

    /// Build a `CreateEscrow` transaction.
    ///
    /// The `escrow_id` is derived deterministically by the VM from the payer
    /// address and the transaction nonce; callers can recompute it as
    /// `SHA-256("tenzro/escrow/id" || payer || nonce_le)`.
    pub fn create_escrow(
        mut self,
        payee: Address,
        amount: u128,
        asset_id: AssetId,
        expires_at: u64,
        release_conditions: ReleaseConditions,
    ) -> Self {
        self.tx_type = Some(TransactionType::CreateEscrow {
            payee,
            amount,
            asset_id,
            expires_at,
            release_conditions,
        });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_ESCROW_CREATE_GAS);
        }
        self
    }

    /// Build a `ReleaseEscrow` transaction.
    ///
    /// Authorization: `tx.from` must be the original payer.
    pub fn release_escrow(mut self, escrow_id: [u8; 32], proof: ServiceProof) -> Self {
        self.tx_type = Some(TransactionType::ReleaseEscrow { escrow_id, proof });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_ESCROW_RELEASE_GAS);
        }
        self
    }

    /// Build a `RefundEscrow` transaction.
    ///
    /// Authorization: `tx.from` must be the original payer AND the escrow must
    /// be expired (or use `Timeout`/`Custom` release conditions).
    pub fn refund_escrow(mut self, escrow_id: [u8; 32]) -> Self {
        self.tx_type = Some(TransactionType::RefundEscrow { escrow_id });
        if self.gas_limit.is_none() {
            self.gas_limit = Some(DEFAULT_ESCROW_REFUND_GAS);
        }
        self
    }

    /// Build and validate the transaction.
    pub fn build(self) -> Result<Transaction> {
        let from = self.from.ok_or_else(|| {
            WalletError::TransactionValidationFailed("sender address not set".to_string())
        })?;
        let to = self.to.unwrap_or(Address::zero());
        let tx_type = self.tx_type.ok_or_else(|| {
            WalletError::TransactionValidationFailed("transaction type not set".to_string())
        })?;
        let nonce = self.nonce.unwrap_or(Nonce(0));
        let gas_limit = self.gas_limit.unwrap_or(DEFAULT_TRANSFER_GAS);
        let gas_price = self.gas_price.unwrap_or(DEFAULT_GAS_PRICE);
        let pq_public_key = self.pq_public_key.ok_or_else(|| {
            WalletError::TransactionValidationFailed(
                "ML-DSA-65 pq_public_key not set (mandatory for hybrid signing)".to_string(),
            )
        })?;

        let mut tx = Transaction::new(
            self.chain_id,
            from,
            to,
            nonce,
            tx_type,
            gas_limit,
            gas_price,
            pq_public_key,
        );

        if let Some(memo) = self.memo {
            tx = tx.with_memo(memo);
        }

        Ok(tx)
    }

    /// Build, validate, and return the transaction.
    ///
    /// Unlike `build()`, this also runs the validator to ensure the
    /// transaction meets all network rules.
    pub fn build_validated(self) -> Result<Transaction> {
        let validator = TransactionValidator::with_config(
            ValidationConfig::default().with_chain_id(self.chain_id),
        );
        let tx = self.build()?;
        validator.validate(&tx)?;
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::pq::MlDsaSigningKey;

    fn pq_pk() -> Vec<u8> {
        MlDsaSigningKey::generate().verifying_key_bytes().to_vec()
    }

    #[test]
    fn test_build_transfer() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([2u8; 32]))
            .nonce(Nonce(0))
            .transfer(1000)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx.chain_id, ChainId(1337));
        assert_eq!(tx.gas_limit, DEFAULT_TRANSFER_GAS);
        assert!(matches!(tx.tx_type, TransactionType::Transfer { amount: 1000 }));
    }

    #[test]
    fn test_build_with_wallet() {
        let provisioner = crate::provisioning::WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let tx = TransactionBuilder::default_chain()
            .from_wallet(&wallet)
            .to(Address::new([2u8; 32]))
            .nonce(Nonce(0))
            .transfer(500)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx.from, wallet.address);
    }

    #[test]
    fn test_build_contract_deploy() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .nonce(Nonce(0))
            .deploy_contract(vec![0x60, 0x80], vec![])
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx.to, Address::zero());
        assert!(matches!(tx.tx_type, TransactionType::ContractDeploy { .. }));
        assert_eq!(tx.gas_limit, DEFAULT_DEPLOY_GAS);
    }

    #[test]
    fn test_build_with_auto_nonce() {
        let nonce_manager = NonceManager::new();
        let from = Address::new([1u8; 32]);

        let tx1 = TransactionBuilder::default_chain()
            .from(from)
            .to(Address::new([2u8; 32]))
            .auto_nonce(&nonce_manager)
            .transfer(100)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        let tx2 = TransactionBuilder::default_chain()
            .from(from)
            .to(Address::new([2u8; 32]))
            .auto_nonce(&nonce_manager)
            .transfer(200)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx1.nonce, Nonce(0));
        assert_eq!(tx2.nonce, Nonce(1));
    }

    #[test]
    fn test_build_validated() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([2u8; 32]))
            .nonce(Nonce(0))
            .transfer(1000)
            .pq_public_key(pq_pk())
            .build_validated()
            .unwrap();

        assert_eq!(tx.chain_id, ChainId(1337));
    }

    #[test]
    fn test_build_validated_fails() {
        // Missing sender
        let result = TransactionBuilder::default_chain()
            .to(Address::new([2u8; 32]))
            .transfer(1000)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_build_with_memo() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([2u8; 32]))
            .nonce(Nonce(0))
            .transfer(1000)
            .memo("Payment for inference".to_string())
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx.memo, Some("Payment for inference".to_string()));
    }

    #[test]
    fn test_build_governance_vote() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([3u8; 32]))
            .nonce(Nonce(0))
            .governance_vote("prop-001".to_string(), true)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert!(matches!(
            tx.tx_type,
            TransactionType::GovernanceVote { .. }
        ));
    }

    #[test]
    fn test_build_bridge_transfer() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([4u8; 32]))
            .nonce(Nonce(0))
            .bridge_transfer(
                "ethereum".to_string(),
                "0x1234567890abcdef".to_string(),
                5000,
            )
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert!(matches!(
            tx.tx_type,
            TransactionType::BridgeTransfer { .. }
        ));
        assert_eq!(tx.gas_limit, DEFAULT_BRIDGE_GAS);
    }

    #[test]
    fn test_custom_gas() {
        let tx = TransactionBuilder::default_chain()
            .from(Address::new([1u8; 32]))
            .to(Address::new([2u8; 32]))
            .nonce(Nonce(0))
            .transfer(1000)
            .gas_limit(50_000)
            .gas_price(2_000_000_000)
            .pq_public_key(pq_pk())
            .build()
            .unwrap();

        assert_eq!(tx.gas_limit, 50_000);
        assert_eq!(tx.gas_price, 2_000_000_000);
    }
}
