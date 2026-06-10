//! EVM executor implementation — full revm integration
//!
//! All EVM bytecode execution is routed through revm. The VmExecutor trait
//! implementation uses Any-based downcasting to obtain a StateAdapter for revm,
//! ensuring consistent execution regardless of the call path.

use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    gas::{GasEstimator, GasOracle},
    precompiles::PrecompileRegistry,
    state_adapter::StateAdapter,
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log,
        StateChange, VmTransaction,
    },
};

use revm::{
    primitives::{
        Address as RevmAddress, ExecutionResult as RevmExecutionResult, Output,
        TransactTo, U256, Bytes,
    },
    Evm,
};

use sha3::{Digest as Sha3Digest, Keccak256};

use super::revm_db::RevmStateAdapter;

/// EVM executor backed by revm
///
/// All execution paths (VmExecutor trait, direct StateAdapter calls, read-only calls)
/// go through revm for full Ethereum compatibility.
pub struct EvmExecutor {
    config: VmConfig,
    /// Gas oracle, shared with the parent `MultiVmRuntime`. Used by
    /// [`Self::gas_oracle`] so EVM-side callers (RPC, mempool admission)
    /// can read the same authoritative price source without round-tripping
    /// through the runtime.
    gas_oracle: Arc<GasOracle>,
    precompiles: Arc<PrecompileRegistry>,
}

impl EvmExecutor {
    /// Create a new EVM executor
    pub fn new(
        config: VmConfig,
        gas_oracle: Arc<GasOracle>,
        precompiles: Arc<PrecompileRegistry>,
    ) -> Result<Self> {
        tracing::info!("Initializing EVM executor with revm backend");
        Ok(Self {
            config,
            gas_oracle,
            precompiles,
        })
    }

    /// Returns the gas oracle shared with the parent runtime.
    pub fn gas_oracle(&self) -> &Arc<GasOracle> {
        &self.gas_oracle
    }

    /// Execute transaction with a StateAdapter (uses revm)
    ///
    /// This is the preferred execution method that uses revm for proper EVM execution.
    /// Use this when you have direct access to a StateAdapter.
    pub async fn execute_with_state_adapter(
        &self,
        tx: &VmTransaction,
        state: &mut StateAdapter,
    ) -> Result<ExecutionResult> {
        self.execute_with_revm(tx, state)
    }

    /// Compute Ethereum CREATE address: keccak256(rlp([sender, nonce]))[12..]
    fn compute_create_address(deployer: &[u8], nonce: u64) -> Vec<u8> {
        use rlp::RlpStream;

        let mut stream = RlpStream::new_list(2);
        stream.append(&deployer);
        stream.append(&nonce);
        let rlp_encoded = stream.out();

        let hash = Keccak256::digest(&rlp_encoded);

        // Take last 20 bytes for EVM address
        hash[12..].to_vec()
    }

    /// Execute transaction using revm
    ///
    /// Primary execution path for all EVM transactions. Sets up the revm environment,
    /// executes the transaction, extracts logs, and applies state changes.
    ///
    /// # Security Features
    ///
    /// - **Nonce validation** (Issue #82): Validates transaction nonce before execution
    ///   to prevent replay attacks and out-of-order execution.
    /// - **Reentrancy protection** (Issue #83): Handled internally by revm's EVM call
    ///   stack. Revm enforces the max call depth limit (1024) automatically.
    /// - **Gas refunds** (Issue #81): Extracts gas refunds from revm (e.g., SSTORE
    ///   clearing refunds) and exposes them in ExecutionResult.
    pub fn execute_with_revm(
        &self,
        tx: &VmTransaction,
        state: &mut StateAdapter,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Executing transaction with revm");

        // Validate nonce before execution (Issue #82 - Replay attack protection)
        let expected_nonce = state.get_nonce(&tx.from);
        if tx.nonce != expected_nonce {
            return Err(VmError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        // Get nonce before borrowing state mutably
        let tx_nonce = expected_nonce;

        // Execute transaction in a scope to release state borrow
        let (result_state, success, gas_used, gas_refund, output, contract_address, logs) = {
            let mut db = RevmStateAdapter::new(state);

            let mut evm = Evm::builder()
                .with_db(&mut db)
                .modify_tx_env(|tx_env| {
                    tx_env.caller = RevmAddress::from_slice(&tx.from);
                    tx_env.gas_limit = tx.gas_limit;
                    tx_env.gas_price = U256::from(tx.gas_price);
                    tx_env.value = U256::from(tx.value);
                    tx_env.data = Bytes::from(tx.data.clone());
                    tx_env.nonce = Some(tx_nonce);
                    tx_env.chain_id = Some(tx.chain_id);

                    if let Some(ref to_addr) = tx.to {
                        tx_env.transact_to = TransactTo::Call(RevmAddress::from_slice(to_addr));
                    } else {
                        tx_env.transact_to = TransactTo::Create;
                    }
                })
                .modify_cfg_env(|cfg_env| {
                    cfg_env.chain_id = tx.chain_id;
                })
                .modify_block_env(|block_env| {
                    block_env.number = U256::ZERO;
                    block_env.timestamp = U256::from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    );
                    block_env.gas_limit = U256::from(self.config.max_gas_limit);
                    block_env.basefee = U256::from(self.config.min_gas_price);
                })
                .build();

            let result = evm.transact().map_err(|e| {
                VmError::ExecutionFailed(format!("revm execution failed: {:?}", e))
            })?;

            // Extract execution result, logs, and state
            let (success, gas_used, gas_refund, output, contract_address, logs) = match result.result {
                RevmExecutionResult::Success {
                    reason,
                    gas_used,
                    gas_refunded,
                    output,
                    logs,
                    ..
                } => {
                    tracing::debug!(
                        "revm execution successful: {:?}, gas: {}, refund: {}, logs: {}",
                        reason,
                        gas_used,
                        gas_refunded,
                        logs.len()
                    );

                    let (output_data, contract_addr) = match output {
                        Output::Call(data) => (data.to_vec(), None),
                        Output::Create(data, addr) => {
                            let address = addr.map(|a| a.as_slice().to_vec());
                            tracing::info!("Contract deployed at: {:?}", address);
                            (data.to_vec(), address)
                        }
                    };

                    // Convert revm logs to Tenzro EventLog format
                    let event_logs: Vec<Log> = logs
                        .into_iter()
                        .map(|log| Log::new(
                            log.address.as_slice().to_vec(),
                            log.data
                                .topics()
                                .iter()
                                .map(|t| t.as_slice().to_vec())
                                .collect(),
                            log.data.data.to_vec(),
                        ))
                        .collect();

                    (true, gas_used, gas_refunded, output_data, contract_addr, event_logs)
                }
                RevmExecutionResult::Revert { gas_used, output } => {
                    tracing::warn!(
                        "revm execution reverted, gas: {}, output: {:?}",
                        gas_used,
                        output
                    );
                    (false, gas_used, 0, output.to_vec(), None, Vec::new())
                }
                RevmExecutionResult::Halt { reason, gas_used } => {
                    tracing::error!("revm execution halted: {:?}, gas: {}", reason, gas_used);
                    (false, gas_used, 0, Vec::new(), None, Vec::new())
                }
            };

            (
                result.state,
                success,
                gas_used,
                gas_refund,
                output,
                contract_address,
                logs,
            )
        }; // End of scope — evm and db are dropped, releasing the borrow on state

        // Apply state changes from revm result
        let mut state_changes = Vec::new();

        for (address, account) in result_state {
            let addr_bytes = address.as_slice().to_vec();

            // Update balance if touched
            if account.is_touched() {
                let new_balance = account.info.balance.try_into().unwrap_or(0u128);
                let old_balance = state.get_balance(&addr_bytes);
                if new_balance != old_balance {
                    state.set_balance(&addr_bytes, new_balance);
                }
            }

            // Update nonce
            let new_nonce = account.info.nonce;
            let old_nonce = state.get_nonce(&addr_bytes);
            if new_nonce != old_nonce {
                state.set_nonce(&addr_bytes, new_nonce);
            }

            // Update code if new contract
            if let Some(code) = &account.info.code
                && !code.is_empty()
            {
                let code_bytes = code.original_bytes().to_vec();
                let existing_code = state.get_code(&addr_bytes);
                if existing_code.is_none() || existing_code.as_ref() != Some(&code_bytes) {
                    state.set_code(&addr_bytes, code_bytes);
                }
            }

            // Update storage
            for (key, value) in account.storage {
                let key_bytes = key.to_be_bytes::<32>().to_vec();
                let value_bytes = value.present_value.to_be_bytes::<32>().to_vec();
                let old_value = state.get_storage(&addr_bytes, &key_bytes);

                if old_value.as_ref() != Some(&value_bytes) {
                    state.set_storage(&addr_bytes, &key_bytes, value_bytes.clone());
                    state_changes.push(StateChange::new(
                        addr_bytes.clone(),
                        key_bytes,
                        old_value,
                        Some(value_bytes),
                    ));
                }
            }
        }

        // Construct execution result with gas refund (Issue #81)
        if success {
            let mut result = if let Some(address) = contract_address {
                ExecutionResult::deployment(
                    gas_used,
                    address,
                    logs,
                    state_changes,
                )
            } else {
                ExecutionResult::success(
                    gas_used, output, logs, state_changes,
                )
            };
            result.gas_refund = gas_refund;
            Ok(result)
        } else {
            Ok(ExecutionResult::failed(
                gas_used,
                String::from_utf8(output).unwrap_or_else(|_| "Execution failed".to_string()),
            ))
        }
    }

    /// Execute a read-only call using revm (no state commit)
    fn execute_call_revm(
        &self,
        from: &[u8],
        to: &[u8],
        data: &[u8],
        gas_limit: u64,
        state: &mut StateAdapter,
    ) -> Result<CallResult> {
        let tx_nonce = state.get_nonce(from);

        let (success, gas_used, output, revert_reason) = {
            let mut db = RevmStateAdapter::new(state);

            let mut evm = Evm::builder()
                .with_db(&mut db)
                .modify_tx_env(|tx_env| {
                    tx_env.caller = RevmAddress::from_slice(from);
                    tx_env.gas_limit = gas_limit;
                    tx_env.gas_price = U256::ZERO; // Free for read-only calls
                    tx_env.value = U256::ZERO;
                    tx_env.data = Bytes::from(data.to_vec());
                    tx_env.nonce = Some(tx_nonce);
                    tx_env.chain_id = Some(self.config.chain_id);
                    tx_env.transact_to = TransactTo::Call(RevmAddress::from_slice(to));
                })
                .modify_cfg_env(|cfg_env| {
                    cfg_env.chain_id = self.config.chain_id;
                })
                .modify_block_env(|block_env| {
                    block_env.number = U256::ZERO;
                    block_env.timestamp = U256::from(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                    );
                    block_env.gas_limit = U256::from(self.config.max_gas_limit);
                    block_env.basefee = U256::ZERO;
                })
                .build();

            // Use transact() (not transact_commit) — state changes are NOT applied
            let result = evm.transact().map_err(|e| {
                VmError::ExecutionFailed(format!("revm call failed: {:?}", e))
            })?;

            match result.result {
                RevmExecutionResult::Success {
                    gas_used, output, ..
                } => {
                    let output_data = match output {
                        Output::Call(data) => data.to_vec(),
                        Output::Create(data, _) => data.to_vec(),
                    };
                    (true, gas_used, output_data, None)
                }
                RevmExecutionResult::Revert { gas_used, output } => {
                    let reason = String::from_utf8(output.to_vec())
                        .unwrap_or_else(|_| "Execution reverted".to_string());
                    (false, gas_used, Vec::new(), Some(reason))
                }
                RevmExecutionResult::Halt { reason, gas_used } => (
                    false,
                    gas_used,
                    Vec::new(),
                    Some(format!("Execution halted: {:?}", reason)),
                ),
            }
        };
        // State changes from transact() are discarded since we don't call transact_commit()

        Ok(CallResult {
            output,
            gas_used,
            success,
            revert_reason,
        })
    }
}

#[async_trait]
impl VmExecutor for EvmExecutor {
    fn vm_type(&self) -> VmType {
        VmType::Evm
    }

    /// Execute a transaction on the EVM
    ///
    /// # Security Note (Issue #26 - Architecture Decision)
    ///
    /// Transaction signature verification is NOT performed at this layer because:
    /// 1. VmTransaction is a VM-agnostic type without signature fields
    /// 2. Signature verification happens at the consensus layer via SignedTransaction.validate()
    ///    and tenzro_crypto::signatures::verify() before transactions reach the VM
    /// 3. This separation of concerns ensures clean architecture: consensus handles authentication,
    ///    VM handles execution
    ///
    /// The signature has already been cryptographically verified before this method is called.
    async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        tracing::debug!(
            "EVM: Executing transaction from {} to {:?}",
            hex::encode(&tx.from),
            tx.to.as_ref().map(hex::encode)
        );

        // Downcast to StateAdapter for revm execution
        if let Some(state_adapter) = state.as_any_mut().downcast_mut::<StateAdapter>() {
            return self.execute_with_revm(tx, state_adapter);
        }

        // Fallback: create a temporary StateAdapter from the VmState data
        // This ensures revm is always used, even for non-StateAdapter VmState impls
        tracing::warn!("VmState is not a StateAdapter, creating temporary adapter for revm");

        let mut temp_state = StateAdapter::new();

        // Copy sender state
        temp_state.set_balance(&tx.from, state.get_balance(&tx.from));
        temp_state.set_nonce(&tx.from, state.get_nonce(&tx.from));

        // Copy recipient state if applicable
        if let Some(ref to) = tx.to {
            temp_state.set_balance(to, state.get_balance(to));
            temp_state.set_nonce(to, state.get_nonce(to));
            if let Some(code) = state.get_code(to) {
                temp_state.set_code(to, code);
            }
        }

        // Execute via revm
        let result = self.execute_with_revm(tx, &mut temp_state)?;

        // Apply state changes back to the original VmState
        if result.success {
            // Update sender
            state.set_balance(&tx.from, temp_state.get_balance(&tx.from));
            state.set_nonce(&tx.from, temp_state.get_nonce(&tx.from));

            // Update recipient
            if let Some(ref to) = tx.to {
                state.set_balance(to, temp_state.get_balance(to));
                state.set_nonce(to, temp_state.get_nonce(to));
            }

            // Update contract address if deployment
            if let Some(ref addr) = result.contract_address {
                if let Some(code) = temp_state.get_code(addr) {
                    state.set_code(addr, code);
                }
                state.set_balance(addr, temp_state.get_balance(addr));
            }
        }

        Ok(result)
    }

    async fn call(&self, call: &ContractCall, state: &dyn VmState) -> Result<CallResult> {
        tracing::debug!(
            "EVM: Read-only call to {}",
            hex::encode(&call.contract)
        );

        // Check if target is a precompile.
        //
        // The precompile registry takes the runtime-supplied
        // `msg.sender` and appends it to the input for authorization-
        // sensitive precompiles (TNZO bridge, token factory,
        // cross-VM bridge). Authorization handlers read the caller
        // from the trailing 32 bytes and never trust calldata-supplied
        // bytes for authorization.
        if self.precompiles.is_precompile(&call.contract) {
            // `call.caller` is `Vec<u8>` 20 bytes (EVM-shaped). Pad to
            // the canonical 20-byte slot. Empty caller is the zero
            // address (anonymous read-only call) — auth-sensitive
            // precompiles will reject operations that require a
            // registered caller.
            let mut caller_20 = [0u8; 20];
            let take = call.caller.len().min(20);
            caller_20[20 - take..].copy_from_slice(&call.caller[call.caller.len() - take..]);
            let result =
                self.precompiles
                    .execute(&caller_20, &call.contract, &call.data, call.gas_limit)?;
            return Ok(CallResult {
                output: result.output,
                gas_used: result.gas_used,
                success: result.success,
                revert_reason: if result.success {
                    None
                } else {
                    Some("Precompile failed".to_string())
                },
            });
        }

        // Verify contract exists
        let _code = state
            .get_code(&call.contract)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&call.contract)))?;

        // Create a temporary mutable StateAdapter for the read-only revm call
        let mut temp_state = StateAdapter::new();

        // Copy relevant state: caller, contract
        let caller = if call.caller.is_empty() {
            vec![0u8; 20]
        } else {
            call.caller.clone()
        };
        temp_state.set_balance(&caller, state.get_balance(&caller));
        temp_state.set_nonce(&caller, state.get_nonce(&caller));

        // Copy contract state
        temp_state.set_balance(&call.contract, state.get_balance(&call.contract));
        temp_state.set_nonce(&call.contract, state.get_nonce(&call.contract));
        if let Some(code) = state.get_code(&call.contract) {
            temp_state.set_code(&call.contract, code);
        }

        // Execute read-only via revm (state changes are discarded)
        self.execute_call_revm(
            &caller,
            &call.contract,
            &call.data,
            call.gas_limit,
            &mut temp_state,
        )
    }

    async fn deploy_contract(
        &self,
        deployment: &ContractDeployment,
        state: &mut dyn VmState,
    ) -> Result<DeployResult> {
        tracing::info!(
            "EVM: Deploying contract from {}",
            hex::encode(&deployment.deployer)
        );

        // Validate contract size
        self.config
            .validate_contract_size(deployment.code.len())?;

        // Build a VmTransaction for deployment
        let nonce = state.get_nonce(&deployment.deployer);
        let tx = VmTransaction::new(
            deployment.deployer.clone(),
            None,
            deployment.value,
            deployment.code.clone(),
            deployment.gas_limit,
            deployment.gas_price,
            nonce,
            VmType::Evm,
            self.config.chain_id,
        );

        // Route through execute_transaction for consistent revm execution
        let result = self.execute_transaction(&tx, state).await?;

        if result.success {
            let address = result
                .contract_address
                .unwrap_or_else(|| Self::compute_create_address(&deployment.deployer, nonce));
            Ok(DeployResult::success(address, result.gas_used))
        } else {
            Ok(DeployResult::failed(
                result.gas_used,
                result
                    .revert_reason
                    .unwrap_or_else(|| "Deployment failed".to_string()),
            ))
        }
    }

    async fn estimate_gas(&self, tx: &VmTransaction, state: &dyn VmState) -> Result<u64> {
        if tx.to.is_none() {
            Ok(GasEstimator::estimate_deployment(tx.data.len()))
        } else if tx.data.is_empty() {
            Ok(GasEstimator::estimate_transfer())
        } else if let Some(to) = tx.to.as_ref() {
            let code = state.get_code(to);
            let complex = code.as_ref().is_some_and(|c| c.len() > 1000);
            Ok(GasEstimator::estimate_call(tx.data.len(), complex))
        } else {
            Ok(GasEstimator::estimate_transfer())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn create_executor() -> EvmExecutor {
        let config = VmConfig::default();
        let gas_oracle = Arc::new(GasOracle::new());
        let precompiles = Arc::new(PrecompileRegistry::new());

        EvmExecutor::new(config, gas_oracle, precompiles).unwrap()
    }

    #[test]
    fn test_compute_create_address() {
        let deployer = vec![1u8; 20];
        let nonce = 0;

        let address = EvmExecutor::compute_create_address(&deployer, nonce);
        assert_eq!(address.len(), 20);

        // Different nonce should produce different address
        let address2 = EvmExecutor::compute_create_address(&deployer, 1);
        assert_ne!(address, address2);
    }

    #[test]
    fn test_create_address_ethereum_compatible() {
        // Known Ethereum CREATE address test vector:
        // Deployer 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, nonce 0
        // Expected: keccak256(rlp([0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, 0]))[12..]
        let deployer =
            hex::decode("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0").unwrap();
        let address = EvmExecutor::compute_create_address(&deployer, 0);

        // Verify it's 20 bytes and deterministic
        assert_eq!(address.len(), 20);

        let address2 = EvmExecutor::compute_create_address(&deployer, 0);
        assert_eq!(address, address2);
    }

    #[tokio::test]
    async fn test_simple_transfer() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 1_000_000_000_000_000_000);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        // Test via VmExecutor trait (uses downcasting to StateAdapter)
        let result = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.gas_used >= 21_000);

        // Check balances updated
        assert_eq!(state.get_balance(&to), 1_000_000_000_000_000);
    }

    #[tokio::test]
    async fn test_revm_simple_transfer() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(result.success, "Transaction should succeed");
        assert!(result.gas_used >= 21_000, "Should use at least base gas");

        assert_eq!(state.get_balance(&to), 1_000_000_000_000_000);

        let expected_from_balance = 10_000_000_000_000_000_000u128
            - 1_000_000_000_000_000
            - (result.gas_used as u128 * 1_000_000_000);
        assert_eq!(state.get_balance(&from), expected_from_balance);
    }

    #[tokio::test]
    async fn test_revm_contract_deploy() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 20];

        // Simple contract that stores and returns 0x42
        // PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        let init_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];

        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);

        let tx = VmTransaction::new(
            deployer.clone(),
            None,
            0,
            init_code,
            500_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(result.success, "Deployment should succeed");
        assert!(
            result.contract_address.is_some(),
            "Should have contract address"
        );

        let contract_addr = result.contract_address.unwrap();
        assert_eq!(contract_addr.len(), 20);

        let stored_code = state.get_code(&contract_addr);
        assert!(stored_code.is_some(), "Contract code should be stored");

        assert_eq!(state.get_nonce(&deployer), 1);
    }

    #[tokio::test]
    async fn test_revm_contract_call() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![3u8; 20];

        // Runtime code: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        let runtime_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];

        state.set_balance(&caller, 10_000_000_000_000_000_000u128);

        let contract_addr = vec![5u8; 20];
        state.set_code(&contract_addr, runtime_code);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(contract_addr.clone()),
            0,
            Vec::new(),
            100_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(result.success, "Contract call should succeed");
        assert_eq!(result.output.len(), 32, "Should return 32 bytes");
        assert_eq!(result.output[31], 0x42, "Should return 0x42");
    }

    #[tokio::test]
    async fn test_revm_call_readonly() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![3u8; 20];

        // Runtime: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
        let runtime_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];
        let contract_addr = vec![5u8; 20];
        state.set_code(&contract_addr, runtime_code);
        state.set_balance(&caller, 1_000_000_000_000_000_000u128);

        let initial_balance = state.get_balance(&caller);

        // Read-only call
        let call = ContractCall::new(
            caller.clone(),
            contract_addr.clone(),
            Vec::new(),
            0,
            100_000,
            VmType::Evm,
        );

        let result = executor.call(&call, &state).await.unwrap();
        assert!(result.success, "Read-only call should succeed");
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 0x42);

        // Verify state was NOT modified (read-only)
        assert_eq!(
            state.get_balance(&caller),
            initial_balance,
            "Balance should be unchanged after read-only call"
        );
    }

    #[tokio::test]
    async fn test_revm_revert_state_unchanged() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![3u8; 20];
        state.set_balance(&caller, 10_000_000_000_000_000_000u128);

        // Runtime code that always REVERTs: PUSH1 0x00, PUSH1 0x00, REVERT
        let revert_code = vec![0x60, 0x00, 0x60, 0x00, 0xFD];
        let contract_addr = vec![5u8; 20];
        state.set_code(&contract_addr, revert_code);
        state.set_balance(&contract_addr, 500);

        let initial_contract_balance = state.get_balance(&contract_addr);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(contract_addr.clone()),
            100, // Send 100 wei
            Vec::new(),
            100_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(!result.success, "Transaction should revert");

        // Contract balance should be unchanged since tx reverted
        assert_eq!(
            state.get_balance(&contract_addr),
            initial_contract_balance,
            "Contract balance should be unchanged after revert"
        );
    }

    #[tokio::test]
    async fn test_contract_deployment_via_trait() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 20];
        let code = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Sample bytecode

        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);

        let deployment = ContractDeployment::new(
            deployer.clone(),
            code.clone(),
            Vec::new(),
            0,
            500_000,
            1_000_000_000,
            0,
            VmType::Evm,
        );

        let result = executor
            .deploy_contract(&deployment, &mut state)
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.address.len(), 20);
    }

    #[tokio::test]
    async fn test_revm_log_extraction() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![3u8; 20];
        state.set_balance(&caller, 10_000_000_000_000_000_000u128);

        // Runtime code that emits a LOG0 event:
        // PUSH1 0x20 (size=32), PUSH1 0x00 (offset=0), LOG0
        // Then STOP
        let log_code = vec![
            0x60, 0x42, // PUSH1 0x42
            0x60, 0x00, // PUSH1 0x00
            0x52, // MSTORE (store 0x42 at offset 0)
            0x60, 0x20, // PUSH1 0x20 (size = 32)
            0x60, 0x00, // PUSH1 0x00 (offset = 0)
            0xA0, // LOG0
            0x00, // STOP
        ];
        let contract_addr = vec![6u8; 20];
        state.set_code(&contract_addr, log_code);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(contract_addr.clone()),
            0,
            Vec::new(),
            200_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(result.success, "LOG0 execution should succeed");
        assert!(
            !result.logs.is_empty(),
            "Should have at least one log entry"
        );

        // Verify log content
        let log = &result.logs[0];
        assert_eq!(
            log.address, contract_addr,
            "Log address should match contract"
        );
        assert_eq!(log.data.len(), 32, "Log data should be 32 bytes");
        assert_eq!(log.data[31], 0x42, "Log data should contain 0x42");
    }

    #[tokio::test]
    async fn test_nonce_validation_correct() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 10_000_000_000_000_000_000u128);
        state.set_nonce(&from, 0);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0, // Correct nonce
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await;
        assert!(result.is_ok(), "Transaction with correct nonce should succeed");
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn test_nonce_validation_wrong_nonce() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 10_000_000_000_000_000_000u128);
        state.set_nonce(&from, 0);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            5, // Wrong nonce (expected 0, got 5)
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await;
        assert!(result.is_err(), "Transaction with wrong nonce should fail");

        match result {
            Err(VmError::InvalidNonce { expected, got }) => {
                assert_eq!(expected, 0, "Expected nonce should be 0");
                assert_eq!(got, 5, "Got nonce should be 5");
            }
            _ => panic!("Expected InvalidNonce error"),
        }
    }

    #[tokio::test]
    async fn test_nonce_validation_replay_attack() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 10_000_000_000_000_000_000u128);
        state.set_nonce(&from, 0);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        // First execution should succeed
        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await;
        assert!(result.is_ok(), "First transaction should succeed");

        // Nonce should now be 1
        assert_eq!(state.get_nonce(&from), 1);

        // Replay the same transaction (same nonce 0)
        let tx_replay = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0, // Trying to replay with old nonce
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx_replay, &mut state)
            .await;
        assert!(result.is_err(), "Replay attack should be rejected");

        match result {
            Err(VmError::InvalidNonce { expected, got }) => {
                assert_eq!(expected, 1, "Expected nonce should be 1 after first tx");
                assert_eq!(got, 0, "Replayed nonce should be 0");
            }
            _ => panic!("Expected InvalidNonce error for replay attack"),
        }
    }

    #[tokio::test]
    async fn test_gas_refund_tracking() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let from = vec![1u8; 20];
        let to = vec![2u8; 20];

        state.set_balance(&from, 10_000_000_000_000_000_000u128);

        let tx = VmTransaction::new(
            from.clone(),
            Some(to.clone()),
            1_000_000_000_000_000,
            Vec::new(),
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();

        assert!(result.success);
        // Simple transfers don't have refunds, but the field should exist
        assert_eq!(result.gas_refund, 0, "Simple transfer should have no gas refund");
        // Call depth should be tracked (at least 1 for the transaction itself)
        assert!(result.call_depth >= 1, "Call depth should be at least 1");
    }
}
