//! Real Solana transaction processing via Anza's `solana-svm`.
//!
//! This module is compiled only under the `svm-full` cargo feature (it is
//! `mod`-declared in `svm/mod.rs` behind `#[cfg(feature = "svm-full")]`).
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
//! Consensus orders a single canonical chain — there is exactly one active
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

use solana_account::{AccountSharedData, WritableAccount};
use solana_clock::{Clock, Slot};
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;
use solana_program_runtime::execution_budget::{
    MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES, SVMTransactionExecutionAndFeeBudgetLimits,
    SVMTransactionExecutionBudget,
};
use solana_program_runtime::loaded_programs::{
    BlockRelation, ForkGraph, ProgramRuntimeEnvironments,
};
use solana_program_runtime::program_cache_entry::ProgramCacheEntry;
// `register` is a provided method on `BuiltinFunctionDefinition`, not an
// inherent one on the generated `Entrypoint` struct, so the trait has to be in
// scope for `Entrypoint::register` to resolve.
use solana_program_runtime::solana_sbpf::program::BuiltinFunctionDefinition;
use solana_pubkey::Pubkey;
use solana_svm::account_loader::CheckedTransactionDetails;
use solana_svm::transaction_processing_result::ProcessedTransaction;
use solana_svm::transaction_processor::{
    ExecutionRecordingConfig, TransactionBatchProcessor, TransactionProcessingConfig,
    TransactionProcessingEnvironment,
};
use solana_svm_callback::{InvokeContextCallback, TransactionProcessingCallback};
use solana_svm_feature_set::SVMFeatureSet;
use solana_transaction::Transaction;
use solana_transaction::sanitized::SanitizedTransaction;

use crate::error::{Result, VmError};
use crate::traits::VmState;

/// Slot used for the single finalized batch. Finality is linear;
/// per-transaction execution does not depend on the absolute slot value.
const EXECUTION_SLOT: Slot = 1;

/// Epoch used for the batch processor. Rent/epoch schedule effects are not
/// exercised by stateless program execution.
const EXECUTION_EPOCH: u64 = 0;

/// Single-active-fork graph.
///
/// Consensus finalizes a linear chain with no reorganization, so any two
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
    /// The transaction's synthetic fee payer, served as a rent-exempt system
    /// account: fees are zero, so nothing is taken from it, and the processor
    /// refuses a transaction whose payer does not exist.
    payer: Pubkey,
}

impl<'a> VmStateAccountLoader<'a> {
    fn new(
        state: &'a dyn VmState,
        program_id: Pubkey,
        program_elf: Vec<u8>,
        clock_account: AccountSharedData,
        payer: Pubkey,
    ) -> Self {
        Self {
            state,
            program_id,
            program_elf,
            clock_account,
            payer,
        }
    }
}

/// Supertrait of [`TransactionProcessingCallback`]. Every method has a
/// default, and every default is right here: this node is not a Solana
/// validator, so it has no epoch stake to report, and it runs no precompiles —
/// Tenzro's precompiles live on the EVM side of the `MultiVmRuntime`.
impl InvokeContextCallback for VmStateAccountLoader<'_> {}

impl TransactionProcessingCallback for VmStateAccountLoader<'_> {
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        // Clock sysvar: served from block context.
        if *pubkey == solana_sdk_ids::sysvar::clock::id() {
            return Some(self.clock_account.clone());
        }

        if *pubkey == self.payer {
            return Some(AccountSharedData::new(
                solana_rent::Rent::default().minimum_balance(0),
                0,
                &solana_sdk_ids::system_program::id(),
            ));
        }

        // The program under test: serve its ELF as an executable, BPF-loader
        // owned account so the processor loads and runs it.
        if *pubkey == self.program_id {
            // A zero-lamport account reads as absent once the processor has
            // loaded it, so the program holds its rent-exempt balance.
            let mut account = AccountSharedData::new(
                solana_rent::Rent::default().minimum_balance(self.program_elf.len()),
                self.program_elf.len(),
                &solana_sdk_ids::bpf_loader::id(),
            );
            account.set_data_from_slice(&self.program_elf);
            account.set_executable(true);
            return Some(account);
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
        Some(account)
    }
}

/// Build the syscall-registered sBPF runtime environment for the given feature
/// set and budget. Both the execution and deployment environments use the same
/// registered syscall surface here.
fn runtime_environments(
    feature_set: &SVMFeatureSet,
    budget: &SVMTransactionExecutionBudget,
) -> Result<ProgramRuntimeEnvironments> {
    // `create_program_runtime_environment` already hands back a
    // `ProgramRuntimeEnvironment`, which owns the `Arc` internally — wrapping
    // it again would not typecheck.
    let execution =
        solana_syscalls::create_program_runtime_environment(feature_set, budget, false, false)
            .map_err(|e| VmError::ExecutionFailed(format!("SVM runtime environment: {e}")))?;
    let deployment =
        solana_syscalls::create_program_runtime_environment(feature_set, budget, true, false)
            .map_err(|e| VmError::ExecutionFailed(format!("SVM deployment environment: {e}")))?;
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
    let mut account = AccountSharedData::new(1, data.len(), &solana_sdk_ids::sysvar::id());
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
    block_unix_timestamp: i64,
    state: &dyn VmState,
) -> Result<(Vec<u8>, u64, Vec<String>)> {
    if program_id.len() != 32 {
        return Err(VmError::InvalidAddress(format!(
            "SVM program id must be 32 bytes, got {}",
            program_id.len()
        )));
    }

    let program_pubkey = Pubkey::try_from(program_id)
        .map_err(|_| VmError::InvalidAddress(hex::encode(program_id)))?;

    let cu_limit = compute_unit_limit.min(max_compute_unit_limit).max(1);

    // Execution budget. The explicit constructor is used because the
    // `Default` impl is gated behind `dev-context-only-utils`.
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

    let clock_account = clock_sysvar_account(block_unix_timestamp);
    let loader = VmStateAccountLoader::new(
        state,
        program_pubkey,
        program_elf.to_vec(),
        clock_account,
        payer,
    );

    match process(&loader, sanitized, budget)? {
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
        ProcessedTransaction::NoOp(no_op) => Err(VmError::ExecutionReverted(format!(
            "SVM transaction changed no state: {:?}",
            no_op.validation_error
        ))),
    }
}

/// The feature set every SVM transaction runs under: every feature the
/// pinned `solana-svm` line knows, active.
fn feature_set() -> SVMFeatureSet {
    SVMFeatureSet::all_enabled()
}

/// Load and execute `sanitized` against `accounts` in a processor with the
/// BPF loader and the system program, under [`feature_set`] and `budget`.
fn process<CB: TransactionProcessingCallback + InvokeContextCallback>(
    accounts: &CB,
    sanitized: SanitizedTransaction,
    budget: SVMTransactionExecutionBudget,
) -> Result<ProcessedTransaction> {
    let feature_set = feature_set();
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
        ProgramCacheEntry::new_builtin(solana_bpf_loader_program::Entrypoint::register),
    );
    processor.add_builtin(
        solana_sdk_ids::system_program::id(),
        ProgramCacheEntry::new_builtin(
            solana_system_program::system_processor::Entrypoint::register,
        ),
    );

    // Populate the sysvar cache. `fill_missing_sysvar_cache_entries` reads each
    // sysvar account through the callback — the clock is served from block
    // context by the account loader; the rest come from their default accounts.
    processor.fill_missing_sysvar_cache_entries(accounts);

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
        accounts,
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

    processing_result
        .map_err(|e| VmError::ExecutionFailed(format!("SVM transaction not processed: {e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    /// A program in the sBPFv3 format loads and runs to success. The program
    /// is the loader's own fixture, which returns without an error.
    #[test]
    fn an_sbpf_v3_program_loads_and_runs() {
        let elf = include_bytes!("../../tests/fixtures/sbpf/sbpfv3_return_ok.so");
        // `e_flags` of the ELF header names the sBPF version.
        assert_eq!(elf[0x30..0x34], 3u32.to_le_bytes());
        let state = StateAdapter::new();
        let (return_data, units, _logs) = process_sbf_transaction(
            &[7u8; 32],
            elf,
            &[],
            200_000,
            1_400_000,
            1_700_000_000,
            &state,
        )
        .expect("the program runs");
        assert!(return_data.is_empty());
        assert!(units > 0 && units <= 200_000, "{units} compute units");
    }

    /// Accounts served from a map, for transactions the VM state cannot form.
    struct MapAccounts(std::collections::HashMap<Pubkey, AccountSharedData>);

    impl InvokeContextCallback for MapAccounts {}

    impl TransactionProcessingCallback for MapAccounts {
        fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
            self.0.get(pubkey).cloned()
        }
    }

    /// The loaded size a transaction is counted at when it names a loader-v3
    /// program whose ProgramData holds `programdata_len` bytes (`None`: no
    /// ProgramData account).
    fn counted_size_with_programdata(programdata_len: Option<usize>) -> u32 {
        let elf = include_bytes!("../../tests/fixtures/sbpf/sbpfv3_return_ok.so");
        let rent = solana_rent::Rent::default();
        let program = Pubkey::new_from_array([7; 32]);
        let payer = Pubkey::new_from_array([8; 32]);
        let v3_program = Pubkey::new_from_array([9; 32]);
        let programdata = Pubkey::new_from_array([10; 32]);

        let mut accounts = std::collections::HashMap::new();
        let mut account = AccountSharedData::new(
            rent.minimum_balance(elf.len()),
            elf.len(),
            &solana_sdk_ids::bpf_loader::id(),
        );
        account.set_data_from_slice(elf);
        account.set_executable(true);
        accounts.insert(program, account);
        accounts.insert(
            payer,
            AccountSharedData::new(
                rent.minimum_balance(0),
                0,
                &solana_sdk_ids::system_program::id(),
            ),
        );
        // `UpgradeableLoaderState::Program { programdata_address }` in bincode:
        // the variant index 2 as a u32, then the address.
        let mut state = 2u32.to_le_bytes().to_vec();
        state.extend_from_slice(programdata.as_ref());
        let mut account = AccountSharedData::new(
            rent.minimum_balance(state.len()),
            state.len(),
            &solana_sdk_ids::bpf_loader_upgradeable::id(),
        );
        account.set_data_from_slice(&state);
        account.set_executable(true);
        accounts.insert(v3_program, account);
        if let Some(len) = programdata_len {
            accounts.insert(
                programdata,
                AccountSharedData::new(
                    rent.minimum_balance(len),
                    len,
                    &solana_sdk_ids::bpf_loader_upgradeable::id(),
                ),
            );
        }

        let instruction = Instruction::new_with_bytes(
            program,
            &[],
            vec![
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(v3_program, false),
            ],
        );
        let transaction = Transaction::new_unsigned(Message::new(&[instruction], Some(&payer)));
        let sanitized =
            SanitizedTransaction::try_from_legacy_transaction(transaction, &HashSet::default())
                .expect("the transaction sanitizes");
        let mut budget = SVMTransactionExecutionBudget::new_with_defaults(false);
        budget.compute_unit_limit = 200_000;
        match process(&MapAccounts(accounts), sanitized, budget).expect("the transaction loads") {
            ProcessedTransaction::Executed(executed) => {
                executed.loaded_transaction.loaded_accounts_data_size
            }
            ProcessedTransaction::FeesOnly(fees_only) => {
                panic!("the transaction did not load: {:?}", fees_only.load_error)
            }
            ProcessedTransaction::NoOp(no_op) => {
                panic!(
                    "the transaction changed nothing: {:?}",
                    no_op.validation_error
                )
            }
        }
    }

    /// A loader-v3 program's ProgramData is counted at least at its metadata
    /// size (45 bytes: state tag, slot, and an optional upgrade authority),
    /// whether it is smaller or missing, as from `solana-svm` 4.4.1.
    #[test]
    fn a_small_programdata_account_is_counted_at_its_metadata_size() {
        assert!(feature_set().loaderv3_programdata_size_floor);
        let missing = counted_size_with_programdata(None);
        let small = counted_size_with_programdata(Some(4));
        let large = counted_size_with_programdata(Some(100));
        assert_eq!(missing, small);
        assert_eq!(large - small, 100 - 45);
    }
}
