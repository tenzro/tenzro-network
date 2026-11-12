//! Multi-VM runtime router

use std::sync::Arc;

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    evm::EvmExecutor,
    gas::GasOracle,
    native::NativeExecutor,
    precompiles::PrecompileRegistry,
    svm::SvmExecutor,
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, VmTransaction,
    },
};

/// Evidence that [`MultiVmRuntime::check_signature`] accepted a transaction's
/// P-256 leg and account binding. Only that function constructs it; parallel
/// block execution keeps it per transaction and hands a copy to every
/// re-execution, which checks the ML-DSA-65 leg against the key the sender
/// has enrolled in state.
#[derive(Clone, Copy)]
pub(crate) struct SignatureChecked {
    /// The P-256 leg verified against `signing_digest`, so execution owes
    /// the ML-DSA-65 check against the enrolled key.
    pq_check_due: bool,
    /// The P-256 key does not name the sender, so execution owes the check
    /// that it is a passkey of the sender's keystore.
    keystore_signer: bool,
    /// The signature has no P-256 leg, so execution owes the check that the
    /// account has retired it.
    p256_retirement_due: bool,
}

/// Multi-VM runtime that routes transactions to the appropriate executor
pub struct MultiVmRuntime {
    /// EVM executor
    evm: Arc<EvmExecutor>,

    /// SVM executor
    svm: Arc<SvmExecutor>,

    /// Native executor for Tenzro-specific transactions
    native: Arc<NativeExecutor>,

    /// Configuration
    config: VmConfig,

    /// Gas oracle
    gas_oracle: Arc<GasOracle>,

    /// Precompile registry
    precompiles: Arc<PrecompileRegistry>,
}

/// VM health status for each executor
#[derive(Debug, Clone)]
pub struct VmStatus {
    pub evm: &'static str,
    pub svm: &'static str,
}

impl MultiVmRuntime {
    /// Create a new multi-VM runtime
    pub async fn new(config: VmConfig) -> Result<Self> {
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

        // Initialize Native executor for Tenzro-specific transactions
        let native = Arc::new(NativeExecutor::new(config.clone())?);

        tracing::info!(
            "Multi-VM runtime initialized with VMs: {:?}",
            config.enabled_vms,
        );

        Ok(Self {
            evm,
            svm,
            native,
            config,
            gas_oracle,
            precompiles,
        })
    }

    /// Get the appropriate executor for a VM type
    pub(crate) fn get_executor(&self, vm_type: VmType) -> Result<&dyn VmExecutor> {
        if !self.config.is_vm_enabled(vm_type) {
            return Err(VmError::VmNotEnabled(vm_type));
        }

        match vm_type {
            VmType::Evm => Ok(self.evm.as_ref() as &dyn VmExecutor),
            VmType::Svm => Ok(self.svm.as_ref() as &dyn VmExecutor),
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
        let checked = self.check_signature(tx)?;
        self.execute_checked(tx, state, checked).await
    }

    /// Verifies the transaction's signature. It reads no state, so parallel
    /// block execution runs it once per transaction, ahead of the
    /// speculative executions, rather than on every re-execution.
    pub(crate) fn check_signature(&self, tx: &VmTransaction) -> Result<SignatureChecked> {
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
        if let Some(ref signature) = tx.signature {
            let classical = signature.has_classical_leg();
            if !classical && signature.pq.is_none() {
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
                    use tenzro_crypto::composite::{SignatureContext, verify_classical_component};

                    // A key that does not name the sender must be a passkey
                    // of the sender's keystore. Execution checks that, and
                    // verifies the assertion for the relying party the
                    // keystore records for it, which only state knows.
                    if !tenzro_crypto::controls_account(pk_bytes, &tx.from) {
                        if !classical {
                            return Err(VmError::InvalidSignature);
                        }
                        return Ok(SignatureChecked {
                            pq_check_due: true,
                            keystore_signer: true,
                            p256_retirement_due: false,
                        });
                    }
                    if !classical {
                        return Ok(SignatureChecked {
                            pq_check_due: true,
                            keystore_signer: false,
                            p256_retirement_due: true,
                        });
                    }
                    verify_classical_component(
                        pk_bytes,
                        SignatureContext::Transaction,
                        digest,
                        &signature.classical,
                    )
                    .map_err(|e| {
                        VmError::ExecutionFailed(format!(
                            "Transaction signature verification failed: {}",
                            e
                        ))
                    })?;
                    tracing::debug!(
                        "Transaction P-256 leg verified for {}",
                        hex::encode(tx.from.get(..8).unwrap_or(&tx.from))
                    );
                    return Ok(SignatureChecked {
                        pq_check_due: true,
                        keystore_signer: false,
                        p256_retirement_due: false,
                    });
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
        Ok(SignatureChecked {
            pq_check_due: false,
            keystore_signer: false,
            p256_retirement_due: false,
        })
    }

    /// Executes a transaction whose signature [`Self::check_signature`] has
    /// accepted.
    pub(crate) async fn execute_checked(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        checked: SignatureChecked,
    ) -> Result<ExecutionResult> {
        // The ML-DSA-65 leg is checked against the key the sender enrolled
        // in state, never one the transaction carries: once enrolled, a
        // signature without that leg is refused, so a stolen P-256 key
        // alone cannot spend the account.
        if checked.keystore_signer {
            let now_ms = crate::native::deterministic_now_ms(tx).max(0) as u64;
            crate::keystore::authorize_sender(state, tx, now_ms)
                .map_err(|e| VmError::ExecutionFailed(format!("Transaction sender: {e}")))?;
        }
        if checked.p256_retirement_due
            && !tx
                .public_key
                .as_deref()
                .is_some_and(|pk| crate::account_keys::p256_retired(state, pk))
        {
            return Err(VmError::ExecutionFailed(
                "Transaction signature verification failed: no P-256 leg, and the account has \
                 not retired it"
                    .to_string(),
            ));
        }
        if checked.pq_check_due
            && let (Some(sig), Some(pk), Some(digest)) = (
                tx.signature.as_ref(),
                tx.public_key.as_ref(),
                tx.signing_digest.as_ref(),
            )
        {
            let (expected, mut policy) = crate::account_keys::tx_pq_key(state, tx, pk);
            // An account that requires the ML-DSA-65 leg holds every key
            // acting for it to it, a linked passkey included.
            if crate::account_keys::pq_required(state, &tx.from) {
                policy = tenzro_crypto::composite::PqPolicy::Required;
            }
            tenzro_crypto::composite::verify_pq_component(
                expected.as_deref(),
                tenzro_crypto::composite::SignatureContext::Transaction,
                digest,
                sig.pq.as_deref(),
                policy,
            )
            .map_err(|e| {
                VmError::ExecutionFailed(format!("Transaction signature verification failed: {e}"))
            })?;
        }
        tracing::debug!(
            "Executing transaction: from={}, vm_type={:?}",
            hex::encode(&tx.from),
            tx.vm_type
        );

        // Validate chain ID — prevent cross-chain replay attacks. A
        // transaction signed for another chain spends nothing here.
        if tx.chain_id != self.config.chain_id {
            return Err(VmError::InvalidTransaction(format!(
                "Chain ID mismatch: transaction has {}, expected {}",
                tx.chain_id, self.config.chain_id
            )));
        }

        // Validate nonce. One ahead of the account waits for the ones before
        // it; one behind it was decided at its nonce already. Neither spends.
        let account_nonce = state.get_nonce(&tx.from);
        if tx.nonce != account_nonce {
            return Err(VmError::InvalidNonce {
                expected: account_nonce,
                got: tx.nonce,
            });
        }

        // Signed by its sender for this chain at the account's next nonce:
        // whatever is decided about it from here is final. A transaction
        // refused by a rule below spends its nonce and pays for the base
        // transaction gas, as one its handler refuses does, so the same
        // signed transaction can never execute later, once the rule that
        // refused it no longer would.
        if let Err(refused) = self.admissible(tx, &*state) {
            state.set_nonce(&tx.from, account_nonce + 1);
            return Ok(ExecutionResult::failed(
                tx.gas_limit.min(crate::gas::evm_gas_costs::TRANSACTION),
                refused.to_string(),
            ));
        }

        // Execution is bounded by gas, never by wall-clock time: a timeout
        // would make the outcome depend on how fast this validator is.
        //
        // Past this point the transaction is valid for its account at this
        // nonce, so it spends the nonce whatever its handler decides. A
        // handler that refuses it yields a failed result, which block
        // execution reverts and charges; were it refused outright, the nonce
        // would stay open, the transaction would be ordered again in every
        // block, and every later transaction of the account would wait
        // behind it.
        let delegations = crate::delegation_guard::snapshot(tx, state);
        let outflow_now = crate::native::deterministic_now_ms(tx);
        let mut watched: Vec<(Vec<u8>, u128)> = Vec::new();
        if !crate::account_outflow::is_outflow_op(tx) {
            let mut who: Vec<Vec<u8>> = vec![tx.from.clone()];
            who.extend(delegations.iter().map(|(a, _, _)| a.to_vec()));
            who.dedup();
            for w in who {
                if crate::account_outflow::policy_in_force(state, &w, outflow_now).is_some() {
                    let bal = state.get_balance(&w);
                    watched.push((w, bal));
                }
            }
        }
        let mut result = match self.dispatch(tx, state).await {
            Ok(result) => result,
            Err(e) => ExecutionResult::failed(
                tx.gas_limit.min(crate::gas::evm_gas_costs::TRANSACTION),
                e.to_string(),
            ),
        };
        if !delegations.is_empty() {
            crate::delegation_guard::record(tx, state, &delegations, &mut result);
        }
        // An account that set an outflow limit on itself: what left it in
        // this transaction, by whatever path (a call, a delegated contract,
        // a transfer), counts against its cap. Past the cap the result is a
        // failure, which block execution reverts.
        if result.success {
            for (who, before) in &watched {
                let after = state.get_balance(who);
                if after < *before
                    && let Err(why) = crate::account_outflow::charge_outflow(
                        state,
                        who,
                        before - after,
                        outflow_now,
                    )
                {
                    result = ExecutionResult::failed(
                        result.gas_used,
                        format!("account outflow limit: {why}"),
                    );
                    break;
                }
            }
        }

        // The transaction spends its nonce. An EVM transaction the EVM ran
        // has already spent it, and once more for each authorization its
        // sender signed for itself (EIP-7702).
        let spent = match tx.vm_type {
            VmType::Evm => state.get_nonce(&tx.from).max(account_nonce + 1),
            _ => account_nonce + 1,
        };
        state.set_nonce(&tx.from, spent);

        Ok(result)
    }

    /// The rules a signed transaction at its account's next nonce must meet
    /// to run: its size, its validity window, its sender's identity and
    /// delegations, its gas, and an enabled VM.
    fn admissible(&self, tx: &VmTransaction, state: &dyn VmState) -> Result<()> {
        const MAX_TX_DATA_SIZE: usize = 128 * 1024; // 128KB
        // A ZK attestation carries a whole STARK proof, which every validator
        // re-verifies, so it has its own bound (priced per byte by the handler).
        let limit = if tx.vm_type == VmType::Tenzro
            && tx.data.starts_with(&crate::native::SELECTOR_ZK_ATTEST)
        {
            tenzro_types::transaction::MAX_ZK_PROOF_SIZE + 4
        } else {
            MAX_TX_DATA_SIZE
        };
        if tx.data.len() > limit {
            return Err(VmError::InvalidTransaction(format!(
                "Transaction data too large: {} bytes (max: {})",
                tx.data.len(),
                limit
            )));
        }

        crate::tx_validity::check(tx, state)?;
        crate::identity_required::check(tx, state)?;
        crate::delegation_guard::check(tx, state)?;

        self.config.validate_gas_limit(tx.gas_limit)?;
        if !crate::native::pays_no_fee(tx) {
            self.config.validate_gas_price(tx.gas_price)?;
        }

        // EIP-7702: a set-code transaction's authorization list is applied
        // by the EVM (see `EvmExecutor::execute_with_revm`).
        if !tx.authorization_list.is_empty() && tx.vm_type != VmType::Evm {
            return Err(VmError::InvalidTransaction(
                "EIP-7702 authorizations are only valid on EVM transactions".to_string(),
            ));
        }

        // The transaction's VM must be enabled.
        self.get_executor(tx.vm_type)?;
        Ok(())
    }

    /// Run a transaction in its VM. Contract calls and delegated agents'
    /// actions may reach several VMs, so the runtime runs those itself
    /// ([`crate::calls`]).
    async fn dispatch(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        use crate::native::{SELECTOR_AGENT_ACT, SELECTOR_CONTRACT_CALL};
        if tx.vm_type == VmType::Tenzro {
            if let Some(payload) = tx.data.strip_prefix(SELECTOR_CONTRACT_CALL.as_slice()) {
                let calls = tenzro_types::VmCall::decode_list(payload)
                    .map_err(|e| VmError::InvalidTransaction(e.to_string()))?;
                return self
                    .execute_calls(
                        tx,
                        state,
                        &calls,
                        tx.gas_limit,
                        crate::calls::Caller::Sender,
                    )
                    .await;
            }
            if tx.data.starts_with(&SELECTOR_AGENT_ACT) {
                return self.execute_agent_act(tx, state).await;
            }
        }
        self.get_executor(tx.vm_type)?
            .execute_transaction(tx, state)
            .await
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

    /// Get configuration
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// Get native executor for direct access
    pub fn native_executor(&self) -> &NativeExecutor {
        &self.native
    }

    /// Get health status of all VM executors
    pub fn vm_status(&self) -> VmStatus {
        VmStatus {
            evm: "ready",
            svm: "ready",
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

    fn transfer_at(nonce: u64, gas_price: u128, chain_id: u64) -> VmTransaction {
        VmTransaction::new(
            vec![1u8; 20],
            Some(vec![2u8; 20]),
            0,
            vec![],
            21_000,
            gas_price,
            nonce,
            VmType::Evm,
            chain_id,
        )
    }

    /// A transaction at its account's next nonce that a rule refuses spends
    /// the nonce and comes back failed, as one its handler refuses does. The
    /// same signed transaction can then never execute, even once the rule
    /// that refused it would let it through.
    #[tokio::test]
    async fn a_refused_transaction_spends_its_nonce_and_never_executes_later() {
        let strict = MultiVmRuntime::new(VmConfig::default().with_min_gas_price(10))
            .await
            .unwrap();
        let mut state = StateAdapter::new();
        state.set_balance(&[1u8; 20], 1_000_000_000_000_000_000u128);
        let cheap = transfer_at(0, 1, strict.config().chain_id);

        let refused = strict
            .execute_transaction(&cheap, &mut state)
            .await
            .unwrap();
        assert!(!refused.success);
        assert!(
            refused
                .revert_reason
                .as_deref()
                .unwrap_or("")
                .contains("below minimum"),
            "{:?}",
            refused.revert_reason
        );
        assert_eq!(
            state.get_nonce(&[1u8; 20]),
            1,
            "the refusal spent the nonce"
        );

        let relaxed = MultiVmRuntime::new(VmConfig::default().with_min_gas_price(1))
            .await
            .unwrap();
        match relaxed.execute_transaction(&cheap, &mut state).await {
            Err(VmError::InvalidNonce {
                expected: 1,
                got: 0,
            }) => {}
            other => panic!("the refused transaction ran again: {other:?}"),
        }
        assert_eq!(state.get_nonce(&[1u8; 20]), 1);
    }

    /// A protocol record pays no fee but is held to its sender's account
    /// nonce like any transaction, so no transaction type is exempt from the
    /// account nonce: one behind it is refused, and spends nothing.
    #[tokio::test]
    async fn a_protocol_record_is_held_to_its_sender_nonce_like_any_transaction() {
        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        let sender = vec![7u8; 32];
        state.set_nonce(&sender, 1);
        let record = VmTransaction::new(
            sender.clone(),
            None,
            0,
            crate::native::SELECTOR_CHECKPOINT_SIGNERS.to_vec(),
            100_000,
            0,
            0,
            VmType::Tenzro,
            runtime.config().chain_id,
        );
        assert!(crate::native::pays_no_fee(&record));
        assert!(matches!(
            runtime.execute_transaction(&record, &mut state).await,
            Err(VmError::InvalidNonce {
                expected: 1,
                got: 0
            })
        ));
        assert_eq!(state.get_nonce(&sender), 1);
    }

    /// What is not this account's next transaction on this chain spends
    /// nothing: one signed for another chain, and one ahead of the nonce
    /// (it waits for the ones before it).
    #[tokio::test]
    async fn another_chain_or_a_later_nonce_spends_nothing() {
        let runtime = MultiVmRuntime::new(VmConfig::default()).await.unwrap();
        let mut state = StateAdapter::new();
        state.set_balance(&[1u8; 20], 1_000_000_000_000_000_000u128);
        let chain = runtime.config().chain_id;

        assert!(matches!(
            runtime
                .execute_transaction(&transfer_at(0, 1_000_000_000, chain + 1), &mut state)
                .await,
            Err(VmError::InvalidTransaction(_))
        ));
        assert!(matches!(
            runtime
                .execute_transaction(&transfer_at(3, 1_000_000_000, chain), &mut state)
                .await,
            Err(VmError::InvalidNonce {
                expected: 0,
                got: 3
            })
        ));
        assert_eq!(state.get_nonce(&[1u8; 20]), 0);

        let ran = runtime
            .execute_transaction(&transfer_at(0, 1_000_000_000, chain), &mut state)
            .await
            .unwrap();
        assert!(ran.success, "{:?}", ran.revert_reason);
        assert_eq!(state.get_nonce(&[1u8; 20]), 1);
    }
}
