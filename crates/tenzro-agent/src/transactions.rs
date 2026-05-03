//! Agent transaction execution with spending policy enforcement and delegation scope checks.
//!
//! This module provides the [`AgentTransactionExecutor`] that bridges agent wallets
//! to on-chain transactions. Agents can autonomously submit token transfers, token
//! creation, contract deployments, and cross-VM transfers using their provisioned
//! MPC wallets, subject to spending policy enforcement.
//!
//! # Architecture
//!
//! The executor sits between the agent identity layer and the actual chain
//! submission layer:
//!
//! ```text
//! Agent code
//!   │
//!   ▼
//! AgentTransactionExecutor
//!   ├── verify agent exists + is Active
//!   ├── check SpendingPolicy (per-tx + daily limits)
//!   ├── delegate to TransactionSubmitter (implemented by node)
//!   ├── record spend in SpendingPolicy
//!   └── append to per-agent tx history
//! ```
//!
//! The [`TransactionSubmitter`] trait is implemented by the node binary to
//! provide actual RPC submission. This decouples the agent crate from the
//! node/RPC layer.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{info, warn};

use tenzro_types::Address;

use crate::autonomy::SpendingPolicy;
use crate::error::{AgentError, Result};
use crate::identity::{AgentIdentityManager, AgentStatus};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of an agent-submitted transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentTransactionResult {
    /// Transaction hash (hex-encoded).
    pub tx_hash: String,
    /// Transaction status (e.g. "confirmed", "pending").
    pub status: String,
    /// Gas consumed by the transaction.
    pub gas_used: u64,
    /// Agent that submitted the transaction.
    pub agent_id: String,
    /// Value transferred (in smallest TNZO unit), 0 for gas-only operations.
    pub amount: u128,
}

/// Describes a transaction an agent wants to execute.
#[derive(Debug, Clone)]
pub enum AgentTransaction {
    /// Transfer native TNZO tokens.
    Transfer {
        to: Address,
        amount: u128,
        memo: Option<String>,
    },
    /// Create a new token via the token factory.
    CreateToken {
        name: String,
        symbol: String,
        initial_supply: u128,
        decimals: u8,
    },
    /// Deploy a smart contract to the specified VM.
    DeployContract {
        vm_type: String,
        bytecode: Vec<u8>,
        constructor_args: Option<Vec<u8>>,
    },
    /// Atomic cross-VM token transfer (Sei V2 pointer model).
    CrossVmTransfer {
        token: String,
        amount: u128,
        to_vm: String,
        to_address: Address,
    },
}

impl AgentTransaction {
    /// Returns the TNZO value carried by this transaction. Gas-only operations
    /// (token creation, contract deployment) return 0.
    pub fn value(&self) -> u128 {
        match self {
            AgentTransaction::Transfer { amount, .. } => *amount,
            AgentTransaction::CreateToken { .. } => 0,
            AgentTransaction::DeployContract { .. } => 0,
            AgentTransaction::CrossVmTransfer { amount, .. } => *amount,
        }
    }

    /// Returns a human-readable label for the transaction type.
    pub fn type_label(&self) -> &'static str {
        match self {
            AgentTransaction::Transfer { .. } => "transfer",
            AgentTransaction::CreateToken { .. } => "create_token",
            AgentTransaction::DeployContract { .. } => "deploy_contract",
            AgentTransaction::CrossVmTransfer { .. } => "cross_vm_transfer",
        }
    }
}

// ---------------------------------------------------------------------------
// Submitter trait
// ---------------------------------------------------------------------------

/// Trait for submitting transactions to the network.
///
/// Implemented by the node to provide actual RPC submission. The agent crate
/// only depends on this trait, not on the node binary, keeping the dependency
/// graph clean.
#[async_trait::async_trait]
pub trait TransactionSubmitter: Send + Sync {
    /// Submit a native TNZO transfer.
    async fn submit_transfer(
        &self,
        from: &Address,
        to: &Address,
        amount: u128,
        memo: Option<&str>,
    ) -> Result<AgentTransactionResult>;

    /// Submit a token creation via the token factory.
    async fn submit_create_token(
        &self,
        creator: &Address,
        name: &str,
        symbol: &str,
        initial_supply: u128,
        decimals: u8,
    ) -> Result<AgentTransactionResult>;

    /// Submit a contract deployment.
    async fn submit_deploy_contract(
        &self,
        deployer: &Address,
        vm_type: &str,
        bytecode: &[u8],
        constructor_args: Option<&[u8]>,
    ) -> Result<AgentTransactionResult>;

    /// Submit a cross-VM token transfer.
    async fn submit_cross_vm_transfer(
        &self,
        from: &Address,
        token: &str,
        amount: u128,
        to_vm: &str,
        to_address: &Address,
    ) -> Result<AgentTransactionResult>;
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

/// Executes transactions on behalf of agents with spending policy enforcement.
///
/// # Usage
///
/// ```no_run
/// use std::sync::Arc;
/// use tenzro_agent::transactions::{AgentTransactionExecutor, AgentTransaction};
/// use tenzro_agent::identity::AgentIdentityManager;
/// use tenzro_agent::autonomy::SpendingPolicy;
/// use tenzro_types::Address;
///
/// # async fn example() -> tenzro_agent::error::Result<()> {
/// let identity_mgr = Arc::new(AgentIdentityManager::new()?);
/// let executor = AgentTransactionExecutor::new(identity_mgr);
///
/// // Set a spending policy for the agent
/// executor.set_spending_policy("agent-1", SpendingPolicy::new(
///     1_000_000_000,   // 1 TNZO per tx
///     10_000_000_000,  // 10 TNZO per day
/// ));
/// # Ok(())
/// # }
/// ```
pub struct AgentTransactionExecutor {
    /// Identity manager for agent lookup and wallet address resolution.
    identity_manager: Arc<AgentIdentityManager>,
    /// Per-agent spending policies. Agents without a policy entry are
    /// unrestricted (no limits enforced).
    spending_policies: DashMap<String, Arc<RwLock<SpendingPolicy>>>,
    /// Pluggable transaction submitter (provided by the node).
    submitter: Option<Arc<dyn TransactionSubmitter>>,
    /// Per-agent transaction history.
    tx_history: DashMap<String, Vec<AgentTransactionResult>>,
    /// Total transactions successfully executed.
    total_executed: Arc<parking_lot::Mutex<u64>>,
    /// Total transactions rejected by spending policy.
    total_rejected: Arc<parking_lot::Mutex<u64>>,
}

impl AgentTransactionExecutor {
    /// Creates a new executor without a submitter. Call [`with_submitter`] to
    /// attach one before executing transactions.
    pub fn new(identity_manager: Arc<AgentIdentityManager>) -> Self {
        Self {
            identity_manager,
            spending_policies: DashMap::new(),
            submitter: None,
            tx_history: DashMap::new(),
            total_executed: Arc::new(parking_lot::Mutex::new(0)),
            total_rejected: Arc::new(parking_lot::Mutex::new(0)),
        }
    }

    /// Attaches a transaction submitter (builder pattern).
    pub fn with_submitter(mut self, submitter: Arc<dyn TransactionSubmitter>) -> Self {
        self.submitter = Some(submitter);
        self
    }

    /// Registers or replaces the spending policy for an agent.
    pub fn set_spending_policy(&self, agent_id: &str, policy: SpendingPolicy) {
        self.spending_policies
            .insert(agent_id.to_string(), Arc::new(RwLock::new(policy)));
    }

    /// Removes the spending policy for an agent, making it unrestricted.
    pub fn remove_spending_policy(&self, agent_id: &str) {
        self.spending_policies.remove(agent_id);
    }

    /// Executes a transaction on behalf of an agent.
    ///
    /// The execution pipeline:
    /// 1. Verify the agent exists and is [`AgentStatus::Active`].
    /// 2. Extract the transaction value and check the spending policy.
    /// 3. Delegate to the [`TransactionSubmitter`].
    /// 4. Record the spend in the spending policy.
    /// 5. Append to the per-agent transaction history.
    pub async fn execute(
        &self,
        agent_id: &str,
        transaction: AgentTransaction,
    ) -> Result<AgentTransactionResult> {
        // 1. Verify agent exists and is active.
        let agent = self.identity_manager.get_agent(agent_id)?;

        if agent.status != AgentStatus::Active {
            return Err(AgentError::AgentNotActive(agent_id.to_string()));
        }

        // 2. Extract transaction value for spending policy check.
        let tx_value = transaction.value();
        let tx_type = transaction.type_label();

        // 3. Check spending policy (before touching the network).
        if let Some(policy_ref) = self.spending_policies.get(agent_id) {
            let mut policy = policy_ref.write();
            if tx_value > 0 {
                // SpendingPolicy uses u64; clamp to u64::MAX for safety.
                let clamped = if tx_value > u64::MAX as u128 {
                    return Err(AgentError::SpendingPolicyViolation(format!(
                        "Transaction value {} exceeds maximum trackable amount",
                        tx_value,
                    )));
                } else {
                    tx_value as u64
                };
                policy.is_allowed(clamped).map_err(|e| {
                    *self.total_rejected.lock() += 1;
                    warn!(
                        agent_id = %agent_id,
                        tx_type = %tx_type,
                        amount = tx_value,
                        "Transaction rejected by spending policy: {}",
                        e
                    );
                    AgentError::SpendingPolicyViolation(e.to_string())
                })?;
            }
        }

        // 4. Get the submitter.
        let submitter = self.submitter.as_ref().ok_or_else(|| {
            AgentError::ProtocolError(
                "No transaction submitter configured — call with_submitter() first".to_string(),
            )
        })?;

        // 5. Execute the transaction via the submitter.
        let result = match &transaction {
            AgentTransaction::Transfer { to, amount, memo } => {
                submitter
                    .submit_transfer(&agent.wallet_address, to, *amount, memo.as_deref())
                    .await?
            }
            AgentTransaction::CreateToken {
                name,
                symbol,
                initial_supply,
                decimals,
            } => {
                submitter
                    .submit_create_token(
                        &agent.wallet_address,
                        name,
                        symbol,
                        *initial_supply,
                        *decimals,
                    )
                    .await?
            }
            AgentTransaction::DeployContract {
                vm_type,
                bytecode,
                constructor_args,
            } => {
                submitter
                    .submit_deploy_contract(
                        &agent.wallet_address,
                        vm_type,
                        bytecode,
                        constructor_args.as_deref(),
                    )
                    .await?
            }
            AgentTransaction::CrossVmTransfer {
                token,
                amount,
                to_vm,
                to_address,
            } => {
                submitter
                    .submit_cross_vm_transfer(
                        &agent.wallet_address,
                        token,
                        *amount,
                        to_vm,
                        to_address,
                    )
                    .await?
            }
        };

        // 6. Record the spend in the spending policy.
        if let Some(policy_ref) = self.spending_policies.get(agent_id) {
            let mut policy = policy_ref.write();
            if tx_value > 0 {
                let clamped = tx_value.min(u64::MAX as u128) as u64;
                let _ = policy.record_transaction(clamped);
            }
        }

        // 7. Append to transaction history.
        self.tx_history
            .entry(agent_id.to_string())
            .or_default()
            .push(result.clone());
        *self.total_executed.lock() += 1;

        info!(
            agent_id = %agent_id,
            tx_hash = %result.tx_hash,
            tx_type = %tx_type,
            status = %result.status,
            amount = tx_value,
            gas_used = result.gas_used,
            "Agent transaction executed"
        );

        Ok(result)
    }

    /// Returns the transaction history for an agent.
    pub fn get_history(&self, agent_id: &str) -> Vec<AgentTransactionResult> {
        self.tx_history
            .get(agent_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Returns the most recent `n` transactions for an agent.
    pub fn get_recent_history(&self, agent_id: &str, n: usize) -> Vec<AgentTransactionResult> {
        self.tx_history
            .get(agent_id)
            .map(|v| {
                let history = v.value();
                let start = history.len().saturating_sub(n);
                history[start..].to_vec()
            })
            .unwrap_or_default()
    }

    /// Returns executor metrics: (total_executed, total_rejected).
    pub fn metrics(&self) -> (u64, u64) {
        (*self.total_executed.lock(), *self.total_rejected.lock())
    }

    /// Returns a reference to the identity manager.
    pub fn identity_manager(&self) -> &Arc<AgentIdentityManager> {
        &self.identity_manager
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentIdentityManager;
    use tenzro_types::agent::Capability;

    /// A mock submitter that always succeeds with a deterministic tx hash.
    struct MockSubmitter;

    #[async_trait::async_trait]
    impl TransactionSubmitter for MockSubmitter {
        async fn submit_transfer(
            &self,
            _from: &Address,
            _to: &Address,
            amount: u128,
            _memo: Option<&str>,
        ) -> Result<AgentTransactionResult> {
            Ok(AgentTransactionResult {
                tx_hash: "0xabc123".to_string(),
                status: "confirmed".to_string(),
                gas_used: 21000,
                agent_id: String::new(),
                amount,
            })
        }

        async fn submit_create_token(
            &self,
            _creator: &Address,
            _name: &str,
            _symbol: &str,
            _initial_supply: u128,
            _decimals: u8,
        ) -> Result<AgentTransactionResult> {
            Ok(AgentTransactionResult {
                tx_hash: "0xdef456".to_string(),
                status: "confirmed".to_string(),
                gas_used: 100_000,
                agent_id: String::new(),
                amount: 0,
            })
        }

        async fn submit_deploy_contract(
            &self,
            _deployer: &Address,
            _vm_type: &str,
            _bytecode: &[u8],
            _constructor_args: Option<&[u8]>,
        ) -> Result<AgentTransactionResult> {
            Ok(AgentTransactionResult {
                tx_hash: "0x789ghi".to_string(),
                status: "confirmed".to_string(),
                gas_used: 500_000,
                agent_id: String::new(),
                amount: 0,
            })
        }

        async fn submit_cross_vm_transfer(
            &self,
            _from: &Address,
            _token: &str,
            amount: u128,
            _to_vm: &str,
            _to_address: &Address,
        ) -> Result<AgentTransactionResult> {
            Ok(AgentTransactionResult {
                tx_hash: "0xjkl012".to_string(),
                status: "confirmed".to_string(),
                gas_used: 80_000,
                agent_id: String::new(),
                amount,
            })
        }
    }

    /// A mock submitter that always fails.
    struct FailingSubmitter;

    #[async_trait::async_trait]
    impl TransactionSubmitter for FailingSubmitter {
        async fn submit_transfer(
            &self,
            _from: &Address,
            _to: &Address,
            _amount: u128,
            _memo: Option<&str>,
        ) -> Result<AgentTransactionResult> {
            Err(AgentError::ProtocolError("network unavailable".to_string()))
        }

        async fn submit_create_token(
            &self,
            _creator: &Address,
            _name: &str,
            _symbol: &str,
            _initial_supply: u128,
            _decimals: u8,
        ) -> Result<AgentTransactionResult> {
            Err(AgentError::ProtocolError("network unavailable".to_string()))
        }

        async fn submit_deploy_contract(
            &self,
            _deployer: &Address,
            _vm_type: &str,
            _bytecode: &[u8],
            _constructor_args: Option<&[u8]>,
        ) -> Result<AgentTransactionResult> {
            Err(AgentError::ProtocolError("network unavailable".to_string()))
        }

        async fn submit_cross_vm_transfer(
            &self,
            _from: &Address,
            _token: &str,
            _amount: u128,
            _to_vm: &str,
            _to_address: &Address,
        ) -> Result<AgentTransactionResult> {
            Err(AgentError::ProtocolError("network unavailable".to_string()))
        }
    }

    /// Helper: create an AgentIdentityManager (unwrapping the Result).
    fn make_mgr() -> Arc<AgentIdentityManager> {
        Arc::new(AgentIdentityManager::new().unwrap())
    }

    /// Helper: register and activate an agent, returning its ID.
    async fn setup_active_agent(mgr: &AgentIdentityManager) -> String {
        let creator = Address::from([1u8; 32]);
        let caps = vec![Capability::SmartContractExecution];
        let agent = mgr.register_agent("test-agent".to_string(), creator, caps, false, 0).await.unwrap();
        let agent_id = agent.identity.agent_id.clone();
        mgr.update_agent(&agent_id, |a| a.status = AgentStatus::Active).unwrap();
        agent_id
    }

    #[tokio::test]
    async fn test_execute_transfer_succeeds() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 1_000_000,
            memo: Some("test payment".to_string()),
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.tx_hash, "0xabc123");
        assert_eq!(result.status, "confirmed");
        assert_eq!(result.amount, 1_000_000);

        // History should contain one entry.
        let history = executor.get_history(&agent_id);
        assert_eq!(history.len(), 1);

        // Metrics: 1 executed, 0 rejected.
        assert_eq!(executor.metrics(), (1, 0));
    }

    #[tokio::test]
    async fn test_execute_create_token_succeeds() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::CreateToken {
            name: "TestToken".to_string(),
            symbol: "TT".to_string(),
            initial_supply: 1_000_000,
            decimals: 18,
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.tx_hash, "0xdef456");
        assert_eq!(result.gas_used, 100_000);
    }

    #[tokio::test]
    async fn test_execute_deploy_contract_succeeds() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::DeployContract {
            vm_type: "evm".to_string(),
            bytecode: vec![0x60, 0x80],
            constructor_args: None,
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.tx_hash, "0x789ghi");
    }

    #[tokio::test]
    async fn test_execute_cross_vm_transfer_succeeds() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::CrossVmTransfer {
            token: "TNZO".to_string(),
            amount: 500_000,
            to_vm: "svm".to_string(),
            to_address: Address::from([3u8; 32]),
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.tx_hash, "0xjkl012");
        assert_eq!(result.amount, 500_000);
    }

    #[tokio::test]
    async fn test_execute_rejects_nonexistent_agent() {
        let mgr = make_mgr();
        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 100,
            memo: None,
        };

        let err = executor.execute("nonexistent", tx).await.unwrap_err();
        assert!(matches!(err, AgentError::AgentNotFound(_)));
    }

    #[tokio::test]
    async fn test_execute_rejects_suspended_agent() {
        let mgr = make_mgr();
        let creator = Address::from([1u8; 32]);
        let agent = mgr
            .register_agent("suspended-agent".to_string(), creator, vec![], false, 0)
            .await
            .unwrap();
        let agent_id = agent.identity.agent_id.clone();
        mgr.update_agent(&agent_id, |a| a.status = AgentStatus::Suspended)
            .unwrap();

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 100,
            memo: None,
        };

        let err = executor.execute(&agent_id, tx).await.unwrap_err();
        assert!(matches!(err, AgentError::AgentNotActive(_)));
    }

    #[tokio::test]
    async fn test_spending_policy_per_tx_limit() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // Allow max 500 per tx, 10000 per day.
        executor.set_spending_policy(&agent_id, SpendingPolicy::new(500, 10_000));

        // This should be rejected (amount 1000 > max_per_tx 500).
        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 1000,
            memo: None,
        };

        let err = executor.execute(&agent_id, tx).await.unwrap_err();
        assert!(matches!(err, AgentError::SpendingPolicyViolation(_)));

        // Metrics: 0 executed, 1 rejected.
        assert_eq!(executor.metrics(), (0, 1));
    }

    #[tokio::test]
    async fn test_spending_policy_daily_limit() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // Allow max 1000 per tx, 1500 per day.
        executor.set_spending_policy(&agent_id, SpendingPolicy::new(1000, 1500));

        // First tx: 1000 — should succeed.
        let tx1 = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 1000,
            memo: None,
        };
        executor.execute(&agent_id, tx1).await.unwrap();

        // Second tx: 1000 — should be rejected (daily total would be 2000 > 1500).
        let tx2 = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 1000,
            memo: None,
        };
        let err = executor.execute(&agent_id, tx2).await.unwrap_err();
        assert!(matches!(err, AgentError::SpendingPolicyViolation(_)));

        assert_eq!(executor.metrics(), (1, 1));
    }

    #[tokio::test]
    async fn test_no_submitter_returns_error() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        // No submitter attached.
        let executor = AgentTransactionExecutor::new(mgr);

        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 100,
            memo: None,
        };

        let err = executor.execute(&agent_id, tx).await.unwrap_err();
        assert!(matches!(err, AgentError::ProtocolError(_)));
    }

    #[tokio::test]
    async fn test_submitter_failure_does_not_record_spend() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(FailingSubmitter));

        executor.set_spending_policy(&agent_id, SpendingPolicy::new(10_000, 100_000));

        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 500,
            memo: None,
        };

        // Should fail from the submitter.
        assert!(executor.execute(&agent_id, tx).await.is_err());

        // History should be empty (tx was not recorded).
        assert!(executor.get_history(&agent_id).is_empty());

        // The spending policy should NOT have recorded the spend.
        let policy_ref = executor.spending_policies.get(&agent_id).unwrap();
        let policy = policy_ref.read();
        assert_eq!(policy.current_daily_spend, 0);
    }

    #[tokio::test]
    async fn test_gas_only_tx_skips_spending_check() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // Very restrictive policy: 0 per tx, 0 per day.
        executor.set_spending_policy(&agent_id, SpendingPolicy::new(0, 0));

        // Token creation has value=0, so it should bypass the spending check.
        let tx = AgentTransaction::CreateToken {
            name: "Test".to_string(),
            symbol: "T".to_string(),
            initial_supply: 1_000_000,
            decimals: 18,
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.tx_hash, "0xdef456");
    }

    #[tokio::test]
    async fn test_no_policy_allows_any_amount() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // No spending policy set — should allow any amount.
        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 999_999_999_999,
            memo: None,
        };

        let result = executor.execute(&agent_id, tx).await.unwrap();
        assert_eq!(result.amount, 999_999_999_999);
    }

    #[tokio::test]
    async fn test_get_recent_history() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // Execute 3 transactions.
        for i in 0..3 {
            let tx = AgentTransaction::Transfer {
                to: Address::from([2u8; 32]),
                amount: (i + 1) * 100,
                memo: None,
            };
            executor.execute(&agent_id, tx).await.unwrap();
        }

        let recent = executor.get_recent_history(&agent_id, 2);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0].amount, 200);
        assert_eq!(recent[1].amount, 300);
    }

    #[test]
    fn test_agent_transaction_value() {
        let transfer = AgentTransaction::Transfer {
            to: Address::from([0u8; 32]),
            amount: 42,
            memo: None,
        };
        assert_eq!(transfer.value(), 42);

        let create = AgentTransaction::CreateToken {
            name: "X".to_string(),
            symbol: "X".to_string(),
            initial_supply: 100,
            decimals: 18,
        };
        assert_eq!(create.value(), 0);

        let deploy = AgentTransaction::DeployContract {
            vm_type: "evm".to_string(),
            bytecode: vec![],
            constructor_args: None,
        };
        assert_eq!(deploy.value(), 0);

        let xvm = AgentTransaction::CrossVmTransfer {
            token: "TNZO".to_string(),
            amount: 99,
            to_vm: "svm".to_string(),
            to_address: Address::from([0u8; 32]),
        };
        assert_eq!(xvm.value(), 99);
    }

    #[test]
    fn test_agent_transaction_type_label() {
        let t = AgentTransaction::Transfer {
            to: Address::from([0u8; 32]),
            amount: 0,
            memo: None,
        };
        assert_eq!(t.type_label(), "transfer");

        let c = AgentTransaction::CreateToken {
            name: "X".to_string(),
            symbol: "X".to_string(),
            initial_supply: 0,
            decimals: 0,
        };
        assert_eq!(c.type_label(), "create_token");
    }

    #[tokio::test]
    async fn test_remove_spending_policy() {
        let mgr = make_mgr();
        let agent_id = setup_active_agent(&mgr).await;

        let executor = AgentTransactionExecutor::new(mgr)
            .with_submitter(Arc::new(MockSubmitter));

        // Set a restrictive policy.
        executor.set_spending_policy(&agent_id, SpendingPolicy::new(0, 0));

        // Transfer should fail.
        let tx = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 100,
            memo: None,
        };
        assert!(executor.execute(&agent_id, tx).await.is_err());

        // Remove the policy.
        executor.remove_spending_policy(&agent_id);

        // Now the same transfer should succeed.
        let tx2 = AgentTransaction::Transfer {
            to: Address::from([2u8; 32]),
            amount: 100,
            memo: None,
        };
        assert!(executor.execute(&agent_id, tx2).await.is_ok());
    }
}
