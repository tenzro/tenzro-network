//! Real Solana transaction processing via Anza's `solana-svm`.
//!
//! This module is compiled only under the `svm-full` cargo feature (it is
//! `mod`-declared inside `executor.rs` behind `#[cfg(feature = "svm-full")]`).
//! It drives a [`TransactionBatchProcessor`] over a [`VmState`]-backed account
//! loader so that an unmodified mainnet SBF ELF (the SPL Token program, a CPI
//! program, etc.) executes with syscalls under the Tenzro runtime.
//!
//! # Account model
//!
//! Solana identifies accounts by 32-byte `Pubkey`. Tenzro's SVM address space
//! is also 32-byte, so a `Pubkey` maps directly to a Tenzro SVM address with no
//! translation. The loader ([`VmStateAccountLoader`]) resolves each account
//! through the shared [`VmState`]:
//!
//!   * `lamports` — Tenzro tracks native balances as 18-decimal `u128`; Solana
//!     lamports are `u64`. Balances cross the boundary through
//!     [`tenzro_token::native_to_spl`], the same 9-decimal conversion the SPL
//!     adapter uses.
//!   * `data` — the account's stored code (SBF ELF for programs, account state
//!     otherwise) is read from [`VmState::get_code`].
//!   * `owner` — the program under test is owned by the BPF loader; other
//!     accounts default to the system program.
//!
//! # Fork graph
//!
//! HotStuff-2 finalizes a single canonical chain — there is exactly one active
//! fork at any height and finalized blocks never reorganize. The
//! [`SingleForkGraph`] stub therefore reports the lower of any two slots as an
//! ancestor of the higher (and equal slots as `Equal`), which is the correct
//! relationship for a linear finalized history.
//!
//! # Compute units
//!
//! This function returns the raw compute units the processor metered
//! (`executed_units`). The CU→gas mapping onto the Tenzro gas schedule is the
//! single deterministic ratio in [`crate::gas::gas_normalizer`], applied at the
//! `MultiVmRuntime` boundary — not here.

use std::collections::HashSet;
use std::sync::{Arc, RwLock, Weak};

use solana_account::{AccountSharedData, ReadableAccount, WritableAccount};
use solana_clock::{Clock, Slot};
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_program_runtime::execution_budget::{
    SVMTransactionExecutionAndFeeBudgetLimits, SVMTransactionExecutionBudget,
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES,
};
use solana_program_runtime::loaded_programs::{
    BlockRelation, ForkGraph, ProgramCacheEntry, ProgramRuntimeEnvironments,
};
use solana_pubkey::Pubkey;
use solana_svm::account_loader::CheckedTransactionDetails;
use solana_svm::transaction_processing_result::ProcessedTransaction;
use solana_svm::transaction_processor::{
    ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig,
    TransactionProcessingEnvironment,
};
use solana_svm_callback::TransactionProcessingCallback;
use solana_svm_feature_set::SVMFeatureSet;
use solana_transaction::sanitized::SanitizedTransaction;
use solana_transaction::Transaction;

use crate::error::{Result, VmError};
use crate::traits::VmState;

/// Slot used for the single finalized batch. HotStuff-2 finality is linear;
/// per-transaction execution does not depend on the absolute slot value.
const EXECUTION_SLOT: Slot = 1;

/// Epoch used for the batch processor. Rent/epoch schedule effects are not
/// exercised by stateless program execution.
const EXECUTION_EPOCH: u64 = 0;

/// Single-active-fork graph.
///
/// HotStuff-2 finalizes a linear chain with no reorganization, so any two
/// finalized slots are directly related. `relationship` reports the lower slot
/// as an ancestor of the higher (and equal slots as `Equal`), which is exactly
/// the ancestry a linear finalized history exposes to the program cache.
struct SingleForkGraph;

impl ForkGraph for SingleForkGraph {
    fn relationship(&self, a: Slot, b: Slot) -> BlockRelation {
        match a.cmp(&b) {
            std::cmp::Ordering::Less => BlockRelation::Ancestor,
            std::cmp::Ordering::Equal => BlockRelation::Equal,
            std::cmp::Ordering::Greater => BlockRelation::Descendant,
        }
    }
}

/// Account loader bridging `solana-svm`'s account queries onto [`VmState`].
///
/// A 32-byte Solana `Pubkey` is used directly as the Tenzro SVM address. The
/// loader is read-only from `solana-svm`'s perspective: `solana-svm` computes
/// the post-execution account set itself; the executor layer applies the
/// resulting deltas back through `VmState`. Here the callback answers "what does
/// this account look like before execution".
///
/// The [`TransactionProcessingCallback::get_account_shared_data`] contract
/// returns `(account, slot)`; the slot is the slot the account was last
/// modified. Under linear HotStuff-2 finality every served account is reported
/// at [`EXECUTION_SLOT`].
struct VmStateAccountLoader<'a> {
    state: &'a dyn VmState,
    /// The program under test — its stored ELF is served as executable account
    /// data owned by the BPF loader so the processor can JIT and run it.
    program_id: Pubkey,
    program_elf: Vec<u8>,
    /// Serialized `Clock` sysvar bytes, served for the clock sysvar pubkey so
    /// on-chain programs observe the finalized block's time via
    /// `fill_missing_sysvar_cache_entries`.
    clock_account: AccountSharedData,
}

impl<'a> VmStateAccountLoader<'a> {
    fn new(
        state: &'a dyn VmState,
        program_id: Pubkey,
        program_elf: Vec<u8>,
        clock_account: AccountSharedData,
    ) -> Self {
        Self {
            state,
            program_id,
            program_elf,
            clock_account,
        }
    }
}

impl TransactionProcessingCallback for VmStateAccountLoader<'_> {
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<(AccountSharedData, Slot)> {
        // Clock sysvar: served from block context.
        if *pubkey == solana_sdk_ids::sysvar::clock::id() {
            return Some((self.clock_account.clone(), EXECUTION_SLOT));
        }

        // The program under test: serve its ELF as an executable, BPF-loader
        // owned account so the processor loads and runs it.
        if *pubkey == self.program_id {
            let mut account =
                AccountSharedData::new(0, self.program_elf.len(), &solana_sdk_ids::bpf_loader::id());
            account.set_data_from_slice(&self.program_elf);
            account.set_executable(true);
            return Some((account, EXECUTION_SLOT));
        }

        let addr = pubkey.to_bytes().to_vec();
        let exists = self.state.exists(&addr);
        let code = self.state.get_code(&addr);
        let native_balance = self.state.get_balance(&addr);

        if !exists && code.is_none() && native_balance == 0 {
            return None;
        }

        // Convert the 18-decimal native balance to lamports (9-decimal SPL
        // convention), saturating on the u64 boundary.
        let lamports = tenzro_token::native_to_spl(native_balance).unwrap_or(u64::MAX);

        let data = code.unwrap_or_default();
        let mut account =
            AccountSharedData::new(lamports, data.len(), &solana_sdk_ids::system_program::id());
        if !data.is_empty() {
            account.set_data_from_slice(&data);
        }
        Some((account, EXECUTION_SLOT))
    }
}

/// Build the syscall-registered sBPF runtime environment for the given feature
/// set and budget. Both the execution and deployment environments use the same
/// registered syscall surface here.
fn runtime_environments(
    feature_set: &SVMFeatureSet,
    budget: &SVMTransactionExecutionBudget,
) -> Result<ProgramRuntimeEnvironments> {
    let execution = Arc::new(
        solana_syscalls::create_program_runtime_environment(feature_set, budget, false, false)
            .map_err(|e| VmError::ExecutionFailed(format!("SVM runtime environment: {e}")))?,
    );
    let deployment = Arc::new(
        solana_syscalls::create_program_runtime_environment(feature_set, budget, true, false)
            .map_err(|e| VmError::ExecutionFailed(format!("SVM deployment environment: {e}")))?,
    );
    Ok(ProgramRuntimeEnvironments::new(execution, deployment))
}

/// Serialize a `Clock` into the sysvar account bytes the runtime expects.
fn clock_sysvar_account(unix_timestamp: i64) -> AccountSharedData {
    let clock = Clock {
        slot: EXECUTION_SLOT,
        epoch: EXECUTION_EPOCH,
        unix_timestamp,
        ..Clock::default()
    };
    let data = bincode::serialize(&clock).unwrap_or_default();
    let mut account =
        AccountSharedData::new(1, data.len(), &solana_sdk_ids::sysvar::id());
    account.set_data_from_slice(&data);
    account
}

/// Execute a stored SBF program against `solana-svm`.
///
/// Builds a single-instruction legacy transaction targeting `program_id` with
/// `instruction_data`, runs it through a [`TransactionBatchProcessor`] backed by
/// a [`VmStateAccountLoader`], and returns
/// `(return_data, executed_compute_units, log_messages)`.
///
/// `compute_unit_limit` is the caller's requested budget; it is clamped to
/// `max_compute_unit_limit` (the Solana per-transaction CU ceiling).
pub(crate) fn process_sbf_transaction(
    program_id: &[u8],
    program_elf: &[u8],
    instruction_data: &[u8],
    compute_unit_limit: u64,
    max_compute_unit_limit: u64,
    state: &dyn VmState,
) -> Result<(Vec<u8>, u64, Vec<String>)> {
    if program_id.len() != 32 {
        return Err(VmError::InvalidAddress(format!(
            "SVM program id must be 32 bytes, got {}",
            program_id.len()
        )));
    }

    let program_pubkey =
        Pubkey::try_from(program_id).map_err(|_| VmError::InvalidAddress(hex::encode(program_id)))?;

    let cu_limit = compute_unit_limit.min(max_compute_unit_limit).max(1);

    // Feature set + execution budget. The explicit constructors are used
    // because the `Default` impls are gated behind `dev-context-only-utils`.
    let feature_set = SVMFeatureSet::all_enabled();
    let mut budget = SVMTransactionExecutionBudget::new_with_defaults(false);
    budget.compute_unit_limit = cu_limit;

    // A deterministic fee payer derived from the program id, so the same
    // program always uses the same synthetic payer. Real fee/nonce accounting
    // happens in the executor against `VmState`; the processor needs a payer
    // only to form a valid transaction.
    let payer = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"tenzro/svm/fee-payer");
        h.update(program_id);
        let d: [u8; 32] = h.finalize().into();
        Pubkey::new_from_array(d)
    };

    // Single instruction: the program is invoked with the raw instruction data
    // and the fee payer as a writable signer account.
    let instruction = Instruction::new_with_bytes(
        program_pubkey,
        instruction_data,
        vec![AccountMeta::new(payer, true)],
    );
    let message = Message::new(&[instruction], Some(&payer));
    let transaction = Transaction::new_unsigned(message);

    let sanitized =
        SanitizedTransaction::try_from_legacy_transaction(transaction, &HashSet::default())
            .map_err(|e| VmError::ExecutionFailed(format!("SVM transaction sanitize: {e}")))?;

    let environments = runtime_environments(&feature_set, &budget)?;

    // Processor. `new_uninitialized` is the production constructor (the `new`
    // constructor is gated behind `dev-context-only-utils`). The runtime
    // environment is installed via the public `set_program_runtime_environment`
    // setter; the fork graph is installed through the public
    // `global_program_cache` field (there is no free-standing
    // `set_fork_graph_in_program_cache` method in this release).
    let mut processor: TransactionBatchProcessor<SingleForkGraph> =
        TransactionBatchProcessor::new_uninitialized(EXECUTION_SLOT, EXECUTION_EPOCH);
    processor.set_program_runtime_environment(environments.get_env_for_execution().clone());

    let fork_graph: Arc<RwLock<SingleForkGraph>> = Arc::new(RwLock::new(SingleForkGraph));
    let weak: Weak<RwLock<SingleForkGraph>> = Arc::downgrade(&fork_graph);
    processor
        .global_program_cache
        .write()
        .map_err(|_| VmError::Internal("SVM program cache lock poisoned".into()))?
        .set_fork_graph(weak);

    // Register the builtins the program may invoke: the BPF loader (to load and
    // run the ELF) and the system program (for CPI to account creation /
    // transfers).
    processor.add_builtin(
        solana_sdk_ids::bpf_loader::id(),
        ProgramCacheEntry::new_builtin(0, 0, solana_bpf_loader_program::Entrypoint::register),
    );
    processor.add_builtin(
        solana_sdk_ids::system_program::id(),
        ProgramCacheEntry::new_builtin(
            0,
            0,
            solana_system_program::system_processor::Entrypoint::register,
        ),
    );

    let clock_account = clock_sysvar_account(chrono::Utc::now().timestamp());
    let loader =
        VmStateAccountLoader::new(state, program_pubkey, program_elf.to_vec(), clock_account);

    // Populate the sysvar cache. `fill_missing_sysvar_cache_entries` reads each
    // sysvar account through the callback — the clock is served from block
    // context by the loader; the rest come from their default accounts.
    processor.fill_missing_sysvar_cache_entries(&loader);

    // Per-transaction budget/fee limits. The CU limit rides here (there is no
    // `compute_budget` field on `TransactionProcessingConfig`); fees are zero
    // because the executor does fee accounting against `VmState`.
    let check_results = vec![Ok(CheckedTransactionDetails::new(
        None,
        SVMTransactionExecutionAndFeeBudgetLimits {
            budget,
            loaded_accounts_data_size_limit: MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES.get(),
            fee_details: solana_fee_structure::FeeDetails::default(),
        },
    ))];

    let processing_environment = TransactionProcessingEnvironment {
        blockhash: solana_hash::Hash::default(),
        blockhash_lamports_per_signature: 0,
        alpenglow_migration_succeeded: false,
        epoch_total_stake: 0,
        feature_set,
        program_runtime_environments: environments,
        rent: solana_rent::Rent::default(),
    };

    let config = TransactionProcessingConfig {
        recording_config: ExecutionRecordingConfig::new_single_setting(true),
        ..TransactionProcessingConfig::default()
    };

    let output = processor.load_and_execute_sanitized_transactions(
        &loader,
        &[sanitized],
        check_results,
        &processing_environment,
        &config,
    );

    let processing_result = output
        .processing_results
        .into_iter()
        .next()
        .ok_or_else(|| VmError::ExecutionFailed("SVM produced no processing result".into()))?;

    let processed = processing_result
        .map_err(|e| VmError::ExecutionFailed(format!("SVM transaction not processed: {e:?}")))?;

    match processed {
        ProcessedTransaction::Executed(executed) => {
            let details = &executed.execution_details;
            if let Err(err) = &details.status {
                return Err(VmError::ExecutionReverted(format!("{err:?}")));
            }
            let return_data = details
                .return_data
                .as_ref()
                .map(|rd| rd.data.clone())
                .unwrap_or_default();
            let logs = details.log_messages.clone().unwrap_or_default();
            let executed_units = details.executed_units;
            Ok((return_data, executed_units, logs))
        }
        ProcessedTransaction::FeesOnly(fees_only) => Err(VmError::ExecutionReverted(format!(
            "SVM transaction charged fees only: {:?}",
            fees_only.load_error
        ))),
    }
}
