//! Multi-VM runtime router

use std::sync::Arc;

use crate::{
    account_abstraction::{EIP_7702_TX_TYPE, Eip7702Authorization, process_7702_authorizations},
    config::VmConfig,
    daml::DamlExecutor,
    error::{Result, VmError},
    evm::EvmExecutor,
    gas::GasOracle,
    native::NativeExecutor,
    precompiles::{PrecompileRegistry, TransientReentrancyGuard},
    svm::SvmExecutor,
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, VmTransaction,
    },
};

/// Multi-VM runtime that routes transactions to the appropriate executor
pub struct MultiVmRuntime {
    /// EVM executor
    evm: Arc<EvmExecutor>,

    /// SVM executor
    svm: Arc<SvmExecutor>,

    /// Daml executor
    daml: Arc<DamlExecutor>,

    /// Native executor for Tenzro-specific transactions
    native: Arc<NativeExecutor>,

    /// Configuration
    config: VmConfig,

    /// Gas oracle
    gas_oracle: Arc<GasOracle>,

    /// Precompile registry
    precompiles: Arc<PrecompileRegistry>,

    /// EIP-1153 transient reentrancy guard for precompile calls
    reentrancy_guard: Arc<TransientReentrancyGuard>,
}

/// VM health status for each executor
#[derive(Debug, Clone)]
pub struct VmStatus {
    pub evm: &'static str,
    pub svm: &'static str,
    pub daml: &'static str,
    pub daml_connected: bool,
}

impl MultiVmRuntime {
    /// Create a new multi-VM runtime
    pub async fn new(config: VmConfig) -> Result<Self> {
        Self::with_canton_config(config, "localhost", 5001).await
    }

    /// Create a new multi-VM runtime with configurable Canton endpoint
    pub async fn with_canton_config(
        config: VmConfig,
        canton_host: &str,
        canton_port: u16,
    ) -> Result<Self> {
        tracing::info!("Initializing multi-VM runtime");

        let gas_oracle = Arc::new(GasOracle::new());
        let precompiles = Arc::new(PrecompileRegistry::new());

        // Initialize EVM executor
        let evm = Arc::new(EvmExecutor::new(
            config.clone(),
            gas_oracle.clone(),
            precompiles.clone(),
        )?);

        // Initialize SVM executor
        let svm = Arc::new(SvmExecutor::new(config.clone(), gas_oracle.clone())?);

        // Initialize Daml executor (connects to co-located Canton participant)
        let daml = Arc::new(DamlExecutor::new(config.clone(), canton_host, canton_port)?);

        // Initialize Native executor for Tenzro-specific transactions
        let native = Arc::new(NativeExecutor::new(config.clone())?);

        tracing::info!(
            "Multi-VM runtime initialized with VMs: {:?} (Canton: {}:{})",
            config.enabled_vms,
            canton_host,
            canton_port,
        );

        Ok(Self {
            evm,
            svm,
            daml,
            native,
            config,
            gas_oracle,
            precompiles,
            reentrancy_guard: Arc::new(TransientReentrancyGuard::new()),
        })
    }

    /// Get the appropriate executor for a VM type
    fn get_executor(&self, vm_type: VmType) -> Result<&dyn VmExecutor> {
        if !self.config.is_vm_enabled(vm_type) {
            return Err(VmError::VmNotEnabled(vm_type));
        }

        match vm_type {
            VmType::Evm => Ok(self.evm.as_ref() as &dyn VmExecutor),
            VmType::Svm => Ok(self.svm.as_ref() as &dyn VmExecutor),
            VmType::Daml => Ok(self.daml.as_ref() as &dyn VmExecutor),
            VmType::Tenzro => Ok(self.native.as_ref() as &dyn VmExecutor),
        }
    }

    /// Detect VM type from address
    #[cfg(test)]
    fn detect_vm_type(&self, address: &[u8]) -> Result<VmType> {
        // Try to detect from address length
        if let Some(vm_type) = VmType::from_address(address)
            && self.config.is_vm_enabled(vm_type)
        {
            return Ok(vm_type);
        }

        // Try to detect from address prefix
        if address.len() >= 2 {
            match &address[0..2] {
                [0x00, _] => {
                    // EVM-style address
                    if self.config.is_vm_enabled(VmType::Evm) {
                        return Ok(VmType::Evm);
                    }
                }
                [0xDA, 0x71] => {
                    // Daml-style address
                    if self.config.is_vm_enabled(VmType::Daml) {
                        return Ok(VmType::Daml);
                    }
                }
                _ => {
                    // Assume SVM for other formats
                    if self.config.is_vm_enabled(VmType::Svm) {
                        return Ok(VmType::Svm);
                    }
                }
            }
        }

        Err(VmError::InvalidAddress(
            "Unable to determine VM type from address".to_string(),
        ))
    }

    /// Execute a transaction with automatic VM routing
    pub async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        tracing::debug!(
            "Executing transaction: from={}, vm_type={:?}",
            hex::encode(&tx.from),
            tx.vm_type
        );

        // CRITICAL: Verify transaction signature before execution.
        //
        // Production txs carry a `signing_digest` populated by
        // `convert_transaction` from the originating `SignedTransaction`
        // (`tenzro_types::Transaction::hash()`). That is the exact preimage
        // the admission boundary already verified against, so re-using it
        // here is consistent and cannot diverge from the signing surface.
        //
        // For synthetic txs built directly in tests/examples there is no
        // `signing_digest` (and typically no signature either); the in-VM
        // verifier skips when the canonical preimage is unavailable rather
        // than re-deriving a different one — that re-derivation was the
        // source of the hash-divergence bug.
        if let Some(ref signature_bytes) = tx.signature {
            if signature_bytes.is_empty() {
                return Err(VmError::InvalidSignature);
            }

            let pk_bytes = tx.public_key.as_ref().ok_or_else(|| {
                VmError::ExecutionFailed("Transaction has signature but no public key".to_string())
            })?;
            if pk_bytes.is_empty() {
                return Err(VmError::ExecutionFailed(
                    "Transaction has signature but empty public key".to_string(),
                ));
            }

            match tx.signing_digest.as_ref() {
                Some(digest) => {
                    let key_type = if pk_bytes.len() == 32 {
                        tenzro_crypto::keys::KeyType::Ed25519
                    } else {
                        tenzro_crypto::keys::KeyType::Secp256k1
                    };

                    let public_key =
                        tenzro_crypto::keys::PublicKey::new(key_type, pk_bytes.clone());
                    let signature = tenzro_crypto::signatures::Signature::new(
                        key_type,
                        signature_bytes.clone(),
                    );

                    tenzro_crypto::signatures::verify(&public_key, digest, &signature).map_err(
                        |e| {
                            VmError::ExecutionFailed(format!(
                                "Transaction signature verification failed: {}",
                                e
                            ))
                        },
                    )?;

                    tracing::debug!(
                        "Transaction signature verified for {}",
                        hex::encode(tx.from.get(..8).unwrap_or(&tx.from))
                    );
                }
                None => {
                    // Tx is signed but the canonical digest wasn't plumbed
                    // through. The admission boundary already verified the
                    // signature against the canonical preimage — skip the
                    // in-VM re-check rather than recompute an inconsistent
                    // preimage from VmTransaction fields.
                    tracing::trace!(
                        "Transaction from {} has signature but no signing_digest \
                         (synthetic build path); admission verifier already checked",
                        hex::encode(tx.from.get(..8).unwrap_or(&tx.from))
                    );
                }
            }
        } else {
            // Allow unsigned transactions from internal/RPC sources during testnet
            tracing::trace!(
                "Transaction from {} has no signature (testnet mode)",
                hex::encode(tx.from.get(..8).unwrap_or(&tx.from))
            );
        }

        // Validate transaction data size (MAX 128KB)
        const MAX_TX_DATA_SIZE: usize = 128 * 1024; // 128KB
        if tx.data.len() > MAX_TX_DATA_SIZE {
            return Err(VmError::InvalidTransaction(format!(
                "Transaction data too large: {} bytes (max: {})",
                tx.data.len(),
                MAX_TX_DATA_SIZE
            )));
        }

        // Validate chain ID — prevent cross-chain replay attacks
        if tx.chain_id != self.config.chain_id {
            return Err(VmError::InvalidTransaction(format!(
                "Chain ID mismatch: transaction has {}, expected {}",
                tx.chain_id, self.config.chain_id
            )));
        }

        // Validate gas limit and price
        self.config.validate_gas_limit(tx.gas_limit)?;
        self.config.validate_gas_price(tx.gas_price)?;

        // Validate nonce
        let account_nonce = state.get_nonce(&tx.from);
        if tx.nonce != account_nonce {
            return Err(VmError::InvalidNonce {
                expected: account_nonce,
                got: tx.nonce,
            });
        }

        // EIP-7702: Process authorization list if present in tx data
        // Check for EIP-7702 marker prefix (0x04 followed by CBOR-encoded auth list)
        // Per EIP-7702 the designator is persistent — once installed
        // it survives the transaction (success or revert) and only
        // changes when a subsequent authorization is consumed.
        if tx.data.first() == Some(&EIP_7702_TX_TYPE)
            && tx.data.len() > 1
            && let Ok(authorizations) =
                serde_json::from_slice::<Vec<Eip7702Authorization>>(&tx.data[1..])
        {
            process_7702_authorizations(&authorizations, self.config.chain_id, state)?;
        }

        // Get the appropriate executor
        let executor = self.get_executor(tx.vm_type)?;

        // Execute transaction with timeout (30 seconds default)
        let execution_future = executor.execute_transaction(tx, state);
        let timeout_duration = std::time::Duration::from_secs(30);

        let result = match tokio::time::timeout(timeout_duration, execution_future).await {
            Ok(result) => result?,
            Err(_) => {
                // EIP-1153: Clear transient reentrancy guard
                self.reentrancy_guard.clear();
                return Err(VmError::Internal(format!(
                    "Transaction execution timed out after {} seconds",
                    timeout_duration.as_secs()
                )));
            }
        };

        // EIP-1153: Clear transient reentrancy guard at end of transaction
        self.reentrancy_guard.clear();

        // Increment nonce on successful execution
        state.set_nonce(&tx.from, account_nonce + 1);

        Ok(result)
    }

    /// Perform a read-only contract call with automatic VM routing
    pub async fn call(&self, call: &ContractCall, state: &dyn VmState) -> Result<CallResult> {
        tracing::debug!(
            "Executing call: contract={}, vm_type={:?}",
            hex::encode(&call.contract),
            call.vm_type
        );

        // Get the appropriate executor
        let executor = self.get_executor(call.vm_type)?;

        // Execute call
        executor.call(call, state).await
    }

    /// Deploy a contract with automatic VM routing
    pub async fn deploy_contract(
        &self,
        deployment: &ContractDeployment,
        state: &mut dyn VmState,
    ) -> Result<DeployResult> {
        tracing::info!(
            "Deploying contract: deployer={}, code_size={}, vm_type={:?}",
            hex::encode(&deployment.deployer),
            deployment.code.len(),
            deployment.vm_type
        );

        // Validate contract size
        self.config.validate_contract_size(deployment.code.len())?;

        // Get the appropriate executor
        let executor = self.get_executor(deployment.vm_type)?;

        // Execute deployment
        executor.deploy_contract(deployment, state).await
    }

    /// Estimate gas for a transaction
    pub async fn estimate_gas(&self, tx: &VmTransaction, state: &dyn VmState) -> Result<u64> {
        // Get the appropriate executor
        let executor = self.get_executor(tx.vm_type)?;

        // Estimate gas
        executor.estimate_gas(tx, state).await
    }

    /// Get gas oracle
    pub fn gas_oracle(&self) -> &GasOracle {
        &self.gas_oracle
    }

    /// Get precompile registry
    pub fn precompiles(&self) -> &PrecompileRegistry {
        &self.precompiles
    }

    /// Get the transient reentrancy guard (EIP-1153 pattern)
    ///
    /// Callers (e.g., EVM precompile execution) should acquire the guard before
    /// invoking a Tenzro precompile and release it afterward. The runtime clears
    /// all locks at the end of each transaction automatically.
    pub fn reentrancy_guard(&self) -> &TransientReentrancyGuard {
        &self.reentrancy_guard
    }

    /// Get configuration
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// Get native executor for direct access
    pub fn native_executor(&self) -> &NativeExecutor {
        &self.native
    }

    /// Get health status of all VM executors
    pub async fn vm_status(&self) -> VmStatus {
        let daml_connected = self.daml.is_canton_connected().await;
        VmStatus {
            evm: "ready",
            svm: "ready",
            daml: if daml_connected {
                "connected"
            } else {
                "disconnected"
            },
            daml_connected,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    #[tokio::test]
    async fn test_runtime_creation() {
        let config = VmConfig::default();
        let runtime = MultiVmRuntime::new(config).await.unwrap();

        assert!(runtime.config().is_vm_enabled(VmType::Evm));
        assert!(runtime.config().is_vm_enabled(VmType::Svm));
    }

    #[tokio::test]
    async fn test_vm_type_detection() {
        let config = VmConfig::default();
        let runtime = MultiVmRuntime::new(config).await.unwrap();

        // EVM address (20 bytes)
        let evm_address = vec![0u8; 20];
        let vm_type = runtime.detect_vm_type(&evm_address).unwrap();
        assert_eq!(vm_type, VmType::Evm);

        // SVM address (32 bytes)
        let svm_address = vec![0u8; 32];
        let vm_type = runtime.detect_vm_type(&svm_address).unwrap();
        assert_eq!(vm_type, VmType::Svm);
    }

    #[tokio::test]
    async fn test_transaction_execution() {
        let config = VmConfig::default();
        let runtime = MultiVmRuntime::new(config).await.unwrap();
        let mut state = StateAdapter::new();

        let sender = vec![1u8; 20];
        let recipient = vec![2u8; 20];

        // Fund the sender so gas can be paid
        state.set_balance(&sender, 1_000_000_000_000_000_000u128); // 1 ETH

        // No signature — unsigned transactions are allowed in testnet mode
        let tx = VmTransaction::new(
            sender,
            Some(recipient),
            0,
            vec![],
            21_000,
            1_000_000_000,
            0,
            VmType::Evm,
            1337,
        );

        let result = runtime.execute_transaction(&tx, &mut state).await;
        assert!(result.is_ok(), "EVM transfer failed: {:?}", result.err());
    }
}
