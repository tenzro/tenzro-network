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
    types::{CallResult, ContractCall, ExecutionResult, Log, StateChange, VmTransaction},
};

use revm::{
    Evm,
    primitives::{
        Address as RevmAddress, Bytes, ExecutionResult as RevmExecutionResult, Output, TransactTo,
        U256,
    },
};

use super::precompile_host::{HostContext, register_tenzro_precompiles};
use super::revm_db::RevmStateAdapter;

/// Normalize a caller/callee address to the 20-byte EVM form.
///
/// `RevmAddress::from_slice` panics on any input that is not exactly 20
/// bytes, and consensus-layer transactions carry 32-byte Tenzro addresses —
/// an unchecked pass-through lets a single malformed transaction crash every
/// validator during block execution. Accepted forms:
///
/// - 20 bytes — native EVM address, used as-is.
/// - 32 bytes — must be the canonical left-aligned slot (addr20 followed by
///   12 zero bytes, the same layout `tnzo_balance_key` / `parse_address`
///   use); the first 20 bytes are extracted. A non-zero tail means the value
///   is a full 32-byte native address with no EVM representation — rejected
///   rather than silently truncated to an aliased address.
///
/// Everything else is a `VmError::InvalidTransaction`.
pub(super) fn evm_address(bytes: &[u8]) -> Result<RevmAddress> {
    match bytes.len() {
        20 => Ok(RevmAddress::from_slice(bytes)),
        32 => {
            if bytes[20..].iter().any(|b| *b != 0) {
                return Err(VmError::InvalidTransaction(format!(
                    "32-byte address 0x{} is not a canonical left-aligned EVM slot \
                     (non-zero tail) — no EVM representation",
                    hex::encode(bytes)
                )));
            }
            Ok(RevmAddress::from_slice(&bytes[..20]))
        }
        n => Err(VmError::InvalidTransaction(format!(
            "EVM address must be 20 bytes or a canonical 32-byte slot, got {} bytes",
            n
        ))),
    }
}

/// How the failure of a transaction reads when the engine itself returned
/// an error.
const ENGINE_ERROR: &str = "revm execution failed: ";

/// Whether `reason`, the whole failure a transaction's result reports, is an
/// error the transaction made the EVM engine return after it had run: a
/// precompile or engine fault. A transaction the engine refused before
/// running it is not one, and neither is a fault of this node's own storage.
pub fn is_engine_fault(reason: &str) -> bool {
    let outer = VmError::ExecutionFailed(String::new()).to_string();
    reason
        .strip_prefix(outer.as_str())
        .and_then(|rest| rest.strip_prefix(ENGINE_ERROR))
        .is_some_and(|error| {
            ["Precompile(", "Custom("]
                .iter()
                .any(|kind| error.starts_with(kind))
        })
}

/// What an error of the engine itself comes to. A transaction the engine
/// refuses before running it (an invalid transaction or header) is refused
/// here too. Any other error ends a transaction that has already run: once
/// the conformance rules are live it is a failed transaction that spent its
/// whole gas limit, as an exceptional halt does; until then it is refused
/// like the first kind, which charges it as a transaction that never ran.
fn engine_error(
    tx: &VmTransaction,
    error: revm::primitives::EVMError<String>,
    conformance: bool,
) -> Result<ExecutionResult> {
    use revm::primitives::EVMError;
    let refused = VmError::ExecutionFailed(format!("{ENGINE_ERROR}{error:?}"));
    match error {
        EVMError::Transaction(_) | EVMError::Header(_) => Err(refused),
        _ if conformance => Ok(ExecutionResult::failed(tx.gas_limit, refused.to_string())),
        _ => Err(refused),
    }
}

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

    /// Execute transaction using revm
    ///
    /// Primary execution path for all EVM transactions. Sets up the revm environment,
    /// executes the transaction, extracts logs, and applies state changes.
    ///
    /// # Security Features
    ///
    /// - **Nonce validation**: validates the transaction nonce before execution
    ///   to prevent replay attacks and out-of-order execution.
    /// - **Reentrancy protection**: handled internally by revm's EVM call
    ///   stack. Revm enforces the max call depth limit (1024) automatically.
    /// - **Gas refunds**: extracts gas refunds from revm (e.g., SSTORE
    ///   clearing refunds) and exposes them in ExecutionResult.
    pub fn execute_with_revm(
        &self,
        tx: &VmTransaction,
        state: &mut StateAdapter,
    ) -> Result<ExecutionResult> {
        self.transact(tx, state, false)
    }

    /// The call the ERC-7786 gateway makes to hand a received message to its
    /// recipient. `call` comes from the gateway's address at gas price zero:
    /// the transaction that delivers the message has paid for its gas. The
    /// block's base fee stays visible to the contract, and the gateway
    /// refuses to send while the call runs.
    pub(crate) fn deliver(
        &self,
        call: &VmTransaction,
        state: &mut StateAdapter,
    ) -> Result<ExecutionResult> {
        self.transact(call, state, true)
    }

    fn transact(
        &self,
        tx: &VmTransaction,
        state: &mut StateAdapter,
        delivering: bool,
    ) -> Result<ExecutionResult> {
        tracing::debug!("Executing transaction with revm");

        // Validate nonce before execution (replay attack protection)
        let expected_nonce = state.get_nonce(&tx.from);
        if tx.nonce != expected_nonce {
            return Err(VmError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        if super::osaka_live(state) {
            return super::osaka::execute(&self.config, &self.precompiles, tx, state, delivering);
        }

        // Get nonce before borrowing state mutably
        let tx_nonce = expected_nonce;

        // Normalize addresses before entering the infallible closure below —
        // RevmAddress::from_slice panics on non-20-byte input.
        let caller = evm_address(&tx.from)?;
        let transact_to = match tx.to {
            Some(ref to_addr) => TransactTo::Call(evm_address(to_addr)?),
            None => TransactTo::Create,
        };

        // Block context comes from the block being executed, never from the
        // local clock: every validator must see the same `block.number`,
        // `block.timestamp` and `block.basefee`.
        let block_number = tx.block_height.unwrap_or(0);
        let block_timestamp = tx
            .block_timestamp_ms
            .map(|ms| u64::try_from(ms / 1000).unwrap_or(0))
            .unwrap_or(0);
        let block_base_fee = tx.block_base_fee.unwrap_or(0);
        let registry = self.precompiles.clone();
        // EIP-7702: the EVM applies the authorization list itself, after the
        // sender's nonce is spent: each valid authorization sets its
        // authority's delegation and spends its nonce, an invalid one is
        // skipped, intrinsic gas charges every entry and an authority that
        // already exists refunds part of it.
        let authorization_list = (!tx.authorization_list.is_empty()).then(|| {
            revm::primitives::AuthorizationList::Recovered(
                tx.authorization_list
                    .iter()
                    .map(|a| a.recovered())
                    .collect(),
            )
        });
        let access_list: Vec<revm::primitives::AccessListItem> = tx
            .access_list
            .iter()
            .map(|(a, keys)| revm::primitives::AccessListItem {
                address: RevmAddress::from(*a),
                storage_keys: keys
                    .iter()
                    .map(|k| revm::primitives::B256::from(*k))
                    .collect(),
            })
            .collect();

        // Execute transaction in a scope to release state borrow
        let (result_state, success, gas_used, gas_refund, output, contract_address, logs) = {
            let rule_set = super::rule_set(state);
            let conformance = super::conformance_live(state);
            let mut db = RevmStateAdapter::new(state);

            let mut evm = Evm::builder()
                .with_db(&mut db)
                .with_spec_id(rule_set)
                .modify_tx_env(|tx_env| {
                    tx_env.caller = caller;
                    tx_env.gas_limit = tx.gas_limit;
                    tx_env.gas_price = U256::from(tx.gas_price);
                    tx_env.value = U256::from(tx.value);
                    tx_env.data = Bytes::from(tx.data.clone());
                    tx_env.nonce = Some(tx_nonce);
                    tx_env.chain_id = Some(tx.chain_id);
                    tx_env.transact_to = transact_to;
                    tx_env.authorization_list = authorization_list;
                    tx_env.access_list = access_list;
                })
                .modify_cfg_env(|cfg_env| {
                    cfg_env.chain_id = tx.chain_id;
                    cfg_env.disable_base_fee = delivering;
                })
                .modify_block_env(|block_env| {
                    block_env.number = U256::from(block_number);
                    block_env.timestamp = U256::from(block_timestamp);
                    block_env.gas_limit = U256::from(self.config.max_gas_limit);
                    block_env.basefee = U256::from(block_base_fee);
                })
                .append_handler_register_box(Box::new(move |handler| {
                    register_tenzro_precompiles(
                        handler,
                        registry.clone(),
                        HostContext {
                            read_only: false,
                            conformance,
                            delivering,
                        },
                    )
                }))
                .build();

            let result = match evm.transact() {
                Ok(result) => result,
                Err(e) => return engine_error(tx, e, conformance),
            };

            // Extract execution result, logs, and state
            let (success, gas_used, gas_refund, output, contract_address, logs) =
                match result.result {
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
                            .map(|log| {
                                Log::new(
                                    log.address.as_slice().to_vec(),
                                    log.data
                                        .topics()
                                        .iter()
                                        .map(|t| t.as_slice().to_vec())
                                        .collect(),
                                    log.data.data.to_vec(),
                                )
                            })
                            .collect();

                        (
                            true,
                            gas_used,
                            gas_refunded,
                            output_data,
                            contract_addr,
                            event_logs,
                        )
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
                        // The halt reason is the failure the receipt reports.
                        (
                            false,
                            gas_used,
                            0,
                            format!("halted: {reason:?}").into_bytes(),
                            None,
                            Vec::new(),
                        )
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
        let mut delegations = Vec::new();
        let conformance = super::conformance_live(state);

        // The engine's state is a hash map whose order differs per process:
        // build the changes and delegations in address and key order.
        let mut result_state: Vec<_> = result_state.into_iter().collect();
        result_state.sort_by_key(|entry| entry.0);
        for (address, account) in result_state {
            let addr_bytes = address.as_slice().to_vec();

            // An account destroyed in the transaction that created it leaves
            // nothing behind: its balance has already moved to the
            // beneficiary, and its nonce, code and storage are not written.
            if conformance && account.is_selfdestructed() {
                if state.get_balance(&addr_bytes) != 0 {
                    state.set_balance(&addr_bytes, 0);
                }
                continue;
            }

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

            // Update code: a new contract, an EIP-7702 delegation, or a
            // delegation cleared by an authorization to the zero address.
            if let Some(code) = &account.info.code {
                let code_bytes = code.original_bytes().to_vec();
                let existing_code = state.get_code(&addr_bytes);
                let changed = match &existing_code {
                    Some(existing) => existing != &code_bytes,
                    None => !code_bytes.is_empty(),
                };
                if changed {
                    let was_delegated = existing_code.as_deref().is_some_and(|c| {
                        crate::account_abstraction::parse_7702_designator(c).is_some()
                    });
                    if code.is_eip7702() || (code_bytes.is_empty() && was_delegated) {
                        delegations.push((addr_bytes.clone(), code_bytes.clone()));
                    }
                    state.set_code(&addr_bytes, code_bytes);
                }
            }

            // Update storage
            let mut slots: Vec<_> = account.storage.into_iter().collect();
            slots.sort_by_key(|entry| entry.0);
            for (key, value) in slots {
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

        // Construct execution result with gas refund
        if success {
            let mut result = if let Some(address) = contract_address {
                ExecutionResult::deployment(gas_used, address, logs, state_changes)
            } else {
                ExecutionResult::success(gas_used, output, logs, state_changes)
            };
            result.gas_refund = gas_refund;
            result.delegations = delegations;
            Ok(result)
        } else {
            let mut result = ExecutionResult::failed(
                gas_used,
                String::from_utf8(output).unwrap_or_else(|_| "Execution failed".to_string()),
            );
            result.delegations = delegations;
            Ok(result)
        }
    }

    /// Execute a read-only call using revm against `state`, which the caller
    /// owns and discards: nothing here commits it.
    fn execute_call_revm(
        &self,
        call: &ContractCall,
        state: &mut StateAdapter,
    ) -> Result<CallResult> {
        if super::osaka_live(state) {
            return super::osaka::call(&self.config, &self.precompiles, call, state);
        }
        let from: Vec<u8> = if call.caller.is_empty() {
            vec![0u8; 20]
        } else {
            call.caller.clone()
        };
        let tx_nonce = state.get_nonce(&from);

        // Normalize before the infallible closure — from_slice panics on
        // non-20-byte input.
        let caller = evm_address(&from)?;
        // No callee simulates a contract creation: the data is the init code
        // and the output the code it would deploy.
        let transact_to = if call.contract.is_empty() {
            TransactTo::Create
        } else {
            TransactTo::Call(evm_address(&call.contract)?)
        };
        let gas_limit = call.gas_limit;
        let data = call.data.clone();
        let block_number = call.block_height;
        let block_timestamp = u64::try_from(call.block_timestamp_ms / 1000).unwrap_or(0);
        let registry = self.precompiles.clone();

        let (success, gas_used, output, revert_reason) = {
            let rule_set = super::rule_set(state);
            let conformance = super::conformance_live(state);
            let mut db = RevmStateAdapter::new(state);

            let mut evm = Evm::builder()
                .with_db(&mut db)
                .with_spec_id(rule_set)
                .modify_tx_env(|tx_env| {
                    tx_env.caller = caller;
                    tx_env.gas_limit = gas_limit;
                    tx_env.gas_price = U256::ZERO; // Free for read-only calls
                    tx_env.value = U256::from(call.value);
                    tx_env.data = Bytes::from(data);
                    tx_env.nonce = Some(tx_nonce);
                    tx_env.chain_id = Some(self.config.chain_id);
                    tx_env.transact_to = transact_to;
                })
                .modify_cfg_env(|cfg_env| {
                    cfg_env.chain_id = self.config.chain_id;
                })
                .modify_block_env(|block_env| {
                    block_env.number = U256::from(block_number);
                    block_env.timestamp = U256::from(block_timestamp);
                    block_env.gas_limit = U256::from(self.config.max_gas_limit);
                    block_env.basefee = U256::ZERO;
                })
                .append_handler_register_box(Box::new(move |handler| {
                    register_tenzro_precompiles(
                        handler,
                        registry.clone(),
                        HostContext {
                            read_only: true,
                            conformance,
                            delivering: false,
                        },
                    )
                }))
                .build();

            // Use transact() (not transact_commit) — state changes are NOT applied
            let result = evm
                .transact()
                .map_err(|e| VmError::ExecutionFailed(format!("revm call failed: {:?}", e)))?;

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
                // The revert data is the caller's to decode: a reason string,
                // a custom error, or nothing.
                RevmExecutionResult::Revert { gas_used, output } => {
                    let reason = String::from_utf8(output.to_vec())
                        .unwrap_or_else(|_| "Execution reverted".to_string());
                    (false, gas_used, output.to_vec(), Some(reason))
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
    /// # Security Note (signature verification happens upstream)
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

        let state_adapter = state
            .as_any_mut()
            .downcast_mut::<StateAdapter>()
            .ok_or_else(|| {
                VmError::Internal("EVM execution requires the node StateAdapter".to_string())
            })?;
        self.execute_with_revm(tx, state_adapter)
    }

    /// Read-only call. Runs the full EVM, Tenzro precompiles included, against
    /// a fork of `state` that is dropped afterwards, so no call can change
    /// state; state-changing precompile selectors refuse outright.
    async fn call(&self, call: &ContractCall, state: &dyn VmState) -> Result<CallResult> {
        tracing::debug!("EVM: Read-only call to {}", hex::encode(&call.contract));
        let base = state
            .as_any()
            .downcast_ref::<StateAdapter>()
            .ok_or_else(|| {
                VmError::Internal("EVM calls require the node StateAdapter".to_string())
            })?;
        let mut fork = base.fork();
        self.execute_call_revm(call, &mut fork)
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

    /// The Ethereum CREATE address: keccak256(rlp([sender, nonce]))[12..]
    fn compute_create_address(deployer: &[u8], nonce: u64) -> Vec<u8> {
        use rlp::RlpStream;
        use sha3::{Digest, Keccak256};

        let mut stream = RlpStream::new_list(2);
        stream.append(&deployer);
        stream.append(&nonce);
        let rlp_encoded = stream.out();

        let hash = Keccak256::digest(&rlp_encoded);

        // Take last 20 bytes for EVM address
        hash[12..].to_vec()
    }

    fn create_executor() -> EvmExecutor {
        let config = VmConfig::default();
        let gas_oracle = Arc::new(GasOracle::new());
        let precompiles = Arc::new(PrecompileRegistry::new());

        EvmExecutor::new(config, gas_oracle, precompiles).unwrap()
    }

    #[test]
    fn evm_address_accepts_20_bytes() {
        let addr = vec![0xABu8; 20];
        assert_eq!(evm_address(&addr).unwrap().as_slice(), addr.as_slice());
    }

    #[test]
    fn evm_address_accepts_canonical_32_byte_slot() {
        let mut slot = vec![0u8; 32];
        slot[..20].copy_from_slice(&[0xABu8; 20]);
        assert_eq!(evm_address(&slot).unwrap().as_slice(), &slot[..20]);
    }

    #[test]
    fn evm_address_rejects_32_byte_nonzero_tail() {
        // Full 32-byte native address (non-zero tail) has no EVM
        // representation — must error, never silently truncate.
        let slot = vec![0xABu8; 32];
        assert!(matches!(
            evm_address(&slot),
            Err(VmError::InvalidTransaction(_))
        ));
    }

    #[test]
    fn evm_address_rejects_other_lengths() {
        for len in [0usize, 1, 19, 21, 31, 33, 64] {
            let bytes = vec![0x01u8; len];
            assert!(
                matches!(evm_address(&bytes), Err(VmError::InvalidTransaction(_))),
                "len {} must be rejected",
                len
            );
        }
    }

    #[test]
    fn test_compute_create_address() {
        let deployer = vec![1u8; 20];
        let nonce = 0;

        let address = compute_create_address(&deployer, nonce);
        assert_eq!(address.len(), 20);

        // Different nonce should produce different address
        let address2 = compute_create_address(&deployer, 1);
        assert_ne!(address, address2);
    }

    #[test]
    fn test_create_address_ethereum_compatible() {
        // Known Ethereum CREATE address test vector:
        // Deployer 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, nonce 0
        // Expected: keccak256(rlp([0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0, 0]))[12..]
        let deployer = hex::decode("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0").unwrap();
        let address = compute_create_address(&deployer, 0);

        // Verify it's 20 bytes and deterministic
        assert_eq!(address.len(), 20);

        let address2 = compute_create_address(&deployer, 0);
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
        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
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

    /// A call to the KZG point evaluation address is an engine error, and
    /// its failure is recognised as one; a refused transaction is not.
    #[test]
    fn an_engine_error_is_told_from_a_refused_transaction() {
        let mut state = StateAdapter::new();
        let sender = vec![1u8; 20];
        state.set_balance(&sender, 10_000_000_000_000_000_000u128);
        let mut kzg = vec![0u8; 20];
        kzg[19] = 0x0a;
        let tx = VmTransaction::new(
            sender,
            Some(kzg),
            0,
            vec![0u8; 192],
            1_000_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        let error = create_executor()
            .execute_with_revm(&tx, &mut state)
            .expect_err("the engine fails");
        assert!(is_engine_fault(&error.to_string()), "{error}");

        assert!(!is_engine_fault(
            "Execution failed: revm execution failed: Transaction(NonceTooLow { tx: 0, state: 1 })"
        ));
        assert!(!is_engine_fault("Execution reverted"));
        // This node's own storage failing is not the sender's doing, and the
        // marker counts only at the start of the failure.
        assert!(!is_engine_fault(
            "Execution failed: revm execution failed: Database(\"io\")"
        ));
        assert!(!is_engine_fault(
            "reverted: Execution failed: revm execution failed: Precompile(\"x\")"
        ));
    }

    /// A well-formed EOF v1 init container: its code section returns the
    /// embedded container (PUSH0 PUSH0 RETURNCONTRACT 0), whose own code
    /// section is a single STOP.
    fn eof_init_code() -> Vec<u8> {
        hex::decode(concat!(
            "ef0001",
            "010004",
            "0200010004",
            "0300010014",
            "040000",
            "00",
            "00800002",
            "5f5fee00",
            "ef0001",
            "010004",
            "0200010001",
            "040000",
            "00",
            "00800000",
            "00",
        ))
        .unwrap()
    }

    async fn create_from_eof_init_code(state: &mut StateAdapter) -> ExecutionResult {
        let deployer = vec![1u8; 20];
        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);
        let tx = VmTransaction::new(
            deployer,
            None,
            0,
            eof_init_code(),
            500_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        create_executor()
            .execute_with_state_adapter(&tx, state)
            .await
            .unwrap()
    }

    /// While the Prague-only rule is dormant the engine runs under its own
    /// default, which deploys an EOF container.
    #[tokio::test]
    async fn eof_init_code_deploys_while_the_prague_only_rule_is_dormant() {
        let mut state = StateAdapter::new();
        let result = create_from_eof_init_code(&mut state).await;
        assert!(result.success, "{:?}", result.revert_reason);
        let created = result.contract_address.expect("a created address");
        assert!(
            state
                .get_code(&created)
                .is_some_and(|c| c.starts_with(&[0xef, 0x00])),
            "an EOF container is deployed"
        );
    }

    /// Once the rule is live, init code that opens with the EOF magic is
    /// ordinary legacy code: its first byte is an undefined opcode, so the
    /// creation halts and nothing is deployed.
    #[tokio::test]
    async fn eof_init_code_halts_once_the_prague_only_rule_is_live() {
        let mut state = StateAdapter::new();
        crate::native::set_governed_param_for_test(&mut state, crate::evm::PRAGUE_ONLY_KEY, 0);
        let result = create_from_eof_init_code(&mut state).await;
        assert!(!result.success, "EOF init code must not deploy");
        let reason = result.revert_reason.unwrap_or_default();
        assert!(
            reason.contains("OpcodeNotFound"),
            "expected the legacy undefined-opcode halt, got: {reason}"
        );
        let created = compute_create_address(&[1u8; 20], 0);
        assert!(state.get_code(&created).is_none_or(|c| c.is_empty()));
    }

    /// An EOF container deployed while the rule was dormant is legacy code
    /// once it is live: a transaction that calls it halts on its first byte,
    /// the read-only call path answers the same, and the code opcodes read
    /// its bytes whole.
    #[tokio::test]
    async fn a_deployed_eof_container_is_legacy_code_once_the_rule_is_live() {
        let mut state = StateAdapter::new();
        let deployed = create_from_eof_init_code(&mut state).await;
        let container = deployed.contract_address.expect("a created address");
        let stored = state.get_code(&container).expect("the container");
        let caller = vec![1u8; 20];
        let call = |nonce: u64| {
            VmTransaction::new(
                caller.clone(),
                Some(container.clone()),
                0,
                Vec::new(),
                200_000,
                1_000_000_000,
                nonce,
                VmType::Evm,
                1337,
            )
        };
        let read_only = ContractCall::new(
            caller.clone(),
            container.clone(),
            Vec::new(),
            0,
            200_000,
            VmType::Evm,
        );
        let executor = create_executor();

        // Dormant: the container runs (a single STOP).
        let ran = executor
            .execute_with_state_adapter(&call(1), &mut state)
            .await
            .unwrap();
        assert!(ran.success, "{:?}", ran.revert_reason);
        assert!(
            executor
                .execute_call_revm(&read_only, &mut state)
                .unwrap()
                .success
        );

        crate::native::set_governed_param_for_test(&mut state, crate::evm::PRAGUE_ONLY_KEY, 0);
        let halted = executor
            .execute_with_state_adapter(&call(2), &mut state)
            .await
            .unwrap();
        assert!(!halted.success);
        let reason = halted.revert_reason.unwrap_or_default();
        assert!(reason.contains("OpcodeNotFound"), "{reason}");
        let answered = executor.execute_call_revm(&read_only, &mut state).unwrap();
        assert!(!answered.success);
        assert!(
            answered
                .revert_reason
                .is_some_and(|r| r.contains("OpcodeNotFound"))
        );

        // EXTCODESIZE of the container, returned as a word: the whole
        // stored length, where the dormant engine answers 2 for a container.
        let mut probe = vec![0x73];
        probe.extend_from_slice(&container);
        probe.extend_from_slice(&[0x3b, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);
        let reader = vec![0x7eu8; 20];
        state.set_code(&reader, probe);
        let size = ContractCall::new(caller, reader, Vec::new(), 0, 200_000, VmType::Evm);
        let out = executor.execute_call_revm(&size, &mut state).unwrap();
        assert!(out.success, "{:?}", out.revert_reason);
        assert_eq!(out.output[31] as usize, stored.len());
    }

    /// An engine error after the transaction ran spends the whole gas limit
    /// once the conformance rules are live; a transaction the engine never
    /// ran is refused on both sides.
    #[test]
    fn an_engine_error_spends_the_whole_gas_limit_once_conformance_is_live() {
        use revm::primitives::{EVMError, InvalidTransaction};
        let tx = VmTransaction::new(
            vec![1u8; 20],
            Some(vec![2u8; 20]),
            0,
            Vec::new(),
            700_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        let fault = || EVMError::<String>::Precompile("fault".into());
        assert!(engine_error(&tx, fault(), false).is_err());
        let failed = engine_error(&tx, fault(), true).unwrap();
        assert!(!failed.success);
        assert_eq!(failed.gas_used, 700_000);
        for conformance in [false, true] {
            let never_ran = EVMError::<String>::Transaction(InvalidTransaction::NonceTooLow {
                tx: 0,
                state: 1,
            });
            assert!(engine_error(&tx, never_ran, conformance).is_err());
        }
    }

    /// A read-only call to a standard precompile at `address`.
    fn precompile_call(state: &mut StateAdapter, address: u8, data: Vec<u8>) -> Result<CallResult> {
        let mut to = vec![0u8; 20];
        to[19] = address;
        let call = ContractCall::new(vec![1u8; 20], to, data, 0, 1_000_000, VmType::Evm);
        create_executor().execute_call_revm(&call, state)
    }

    fn conformance_live() -> StateAdapter {
        let mut state = StateAdapter::new();
        crate::native::set_governed_param_for_test(&mut state, crate::evm::CONFORMANCE_KEY, 0);
        state
    }

    /// BLS12-381 G1 addition of the point at infinity to itself: served once
    /// the conformance rules are live, an account with no code before.
    #[test]
    fn the_bls12_381_precompiles_are_served_once_conformance_is_live() {
        let dormant = precompile_call(&mut StateAdapter::new(), 0x0b, vec![0u8; 256]).unwrap();
        assert!(dormant.success);
        assert!(
            dormant.output.is_empty(),
            "no precompile answers while dormant"
        );

        let live = precompile_call(&mut conformance_live(), 0x0b, vec![0u8; 256]).unwrap();
        assert!(live.success, "{:?}", live.revert_reason);
        assert_eq!(live.output, vec![0u8; 128], "infinity plus infinity");
    }

    /// KZG point evaluation at `0x0a`: while dormant any call to it fails
    /// the whole transaction; once live a malformed input fails that call
    /// alone, as a precompile does.
    #[test]
    fn kzg_point_evaluation_is_a_precompile_once_conformance_is_live() {
        let dormant = precompile_call(&mut StateAdapter::new(), 0x0a, vec![0u8; 192]);
        assert!(
            dormant
                .as_ref()
                .is_err_and(|e| e.to_string().contains("c-kzg feature is not enabled")),
            "{dormant:?}"
        );

        let live = precompile_call(&mut conformance_live(), 0x0a, vec![0u8; 192]).unwrap();
        assert!(
            !live.success,
            "a malformed input is refused by the precompile"
        );
    }

    /// A transaction priced below the block's base fee is refused by the
    /// EVM itself: only the gateway's delivery call runs without that check.
    #[tokio::test]
    async fn a_transaction_below_the_base_fee_is_refused() {
        let executor = create_executor();
        let mut state = StateAdapter::new();
        let from = vec![1u8; 20];
        state.set_balance(&from, 10_000_000_000_000_000_000u128);
        let priced = |gas_price: u128| {
            VmTransaction::new(
                from.clone(),
                Some(vec![2u8; 20]),
                0,
                Vec::new(),
                21_000,
                gas_price,
                0,
                VmType::Evm,
                1337,
            )
            .with_block_base_fee(10_000_000_000)
        };

        let refused = executor
            .execute_with_revm(&priced(1_000_000_000), &mut state)
            .unwrap_err();
        assert!(
            refused.to_string().contains("GasPriceLessThanBasefee"),
            "{refused}"
        );
        let free = executor
            .execute_with_revm(&priced(0), &mut state)
            .unwrap_err();
        assert!(
            free.to_string().contains("GasPriceLessThanBasefee"),
            "{free}"
        );

        let delivered = executor.deliver(&priced(0), &mut state).unwrap();
        assert!(delivered.success);
        assert_eq!(state.get_balance(&from), 10_000_000_000_000_000_000u128);
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

    /// A read-only call that reverts returns the revert data, which is what
    /// `eth_call` hands a wallet. A transaction that reverts the same way is
    /// unchanged by it: no output, the same reason, no state change beyond
    /// what the block applies, and the call itself leaves state untouched.
    #[tokio::test]
    async fn a_reverted_call_returns_its_data_and_a_reverted_transaction_is_unchanged() {
        let executor = create_executor();
        let mut state = StateAdapter::new();
        let caller = vec![3u8; 20];
        state.set_balance(&caller, 10_000_000_000_000_000_000u128);
        // PUSH4 0xdeadbeef PUSH1 0 MSTORE PUSH1 4 PUSH1 28 REVERT
        let reverts = vec![
            0x63, 0xde, 0xad, 0xbe, 0xef, 0x60, 0x00, 0x52, 0x60, 0x04, 0x60, 0x1c, 0xfd,
        ];
        let contract = vec![6u8; 20];
        state.set_code(&contract, reverts);

        let call = ContractCall::new(
            caller.clone(),
            contract.clone(),
            Vec::new(),
            0,
            100_000,
            VmType::Evm,
        );
        let balance = state.get_balance(&caller);
        let nonce = state.get_nonce(&caller);
        let called = executor.call(&call, &state).await.unwrap();
        assert!(!called.success);
        assert_eq!(called.output, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(state.get_balance(&caller), balance);
        assert_eq!(state.get_nonce(&caller), nonce);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(contract),
            0,
            Vec::new(),
            100_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );
        let sent = executor
            .execute_with_state_adapter(&tx, &mut state)
            .await
            .unwrap();
        assert!(!sent.success);
        assert!(sent.output.is_empty());
        assert!(sent.logs.is_empty());
        assert!(sent.state_changes.is_empty());
        assert_eq!(sent.revert_reason.as_deref(), Some("Execution failed"));
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
    async fn a_creation_transaction_deploys_a_contract() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 20];
        let code = vec![0x60, 0x80, 0x60, 0x40, 0x52]; // Sample bytecode

        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);

        let tx = VmTransaction::new(
            deployer.clone(),
            None,
            0,
            code,
            500_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(result.success, "{:?}", result.revert_reason);
        assert_eq!(result.contract_address.map(|a| a.len()), Some(20));
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

        let result = executor.execute_with_state_adapter(&tx, &mut state).await;
        assert!(
            result.is_ok(),
            "Transaction with correct nonce should succeed"
        );
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

        let result = executor.execute_with_state_adapter(&tx, &mut state).await;
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
        let result = executor.execute_with_state_adapter(&tx, &mut state).await;
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
        assert_eq!(
            result.gas_refund, 0,
            "Simple transfer should have no gas refund"
        );
        // Call depth should be tracked (at least 1 for the transaction itself)
        assert!(result.call_depth >= 1, "Call depth should be at least 1");
    }
}
