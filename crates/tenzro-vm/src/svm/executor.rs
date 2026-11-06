//! SVM executor implementing Solana Virtual Machine compatibility for Tenzro.
//!
//! This executor serves two code paths, dispatched in
//! [`SvmExecutor::execute_transaction`] on the destination program id:
//!
//! 1. **SPL Token program** (`tx.to == SPL_TOKEN_PROGRAM_ID`) — the SPL view
//!    of the one token ledger, implemented in Rust over `VmState`: native
//!    TNZO under the wTNZO mint (9-decimal truncation) and every other token
//!    under its token id as mint. Its destinations are any ledger account,
//!    EVM ones included. See [`Self::execute_spl_native`].
//! 2. **SBF/BPF program execution** (any other stored ELF) — real Solana
//!    transaction processing via Anza's `solana-svm`
//!    `TransactionBatchProcessor`, compiled in only under the `svm-full` cargo
//!    feature. Without that feature, executing a stored ELF returns
//!    [`VmError::SvmFullFeatureRequired`].
//!
//! Program-derived addresses (PDAs) are derived with a Solana-compatible
//! off-curve algorithm in [`Self::derive_pda`], available on every build.
//!
//! # Compute units → gas
//!
//! Solana meters in compute units (CU). The CU↔gas mapping onto the Tenzro gas
//! schedule is the single deterministic ratio in
//! [`crate::gas::gas_normalizer`] (`VmType::Svm`), applied at the
//! `MultiVmRuntime` boundary. Per-instruction CU costs for the native paths
//! mirror Solana's documented program costs (System transfer ~150 CU, SPL
//! Token transfer ~5_000 CU).

use async_trait::async_trait;
use std::sync::Arc;

use crate::{
    config::VmConfig,
    error::{Result, VmError},
    gas::{GasOracle, svm_gas_costs},
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log,
        StateChange, VmTransaction,
    },
};

/// SVM executor dispatching SPL / cross-VM native paths and, under the
/// `svm-full` feature, real SBF program execution via Anza's `solana-svm`.
pub struct SvmExecutor {
    /// Configuration
    config: VmConfig,

    /// Gas oracle, shared with the parent `MultiVmRuntime`. Exposed via
    /// [`Self::gas_oracle`] so SVM-side callers can read the same
    /// authoritative price source as EVM/Native paths.
    gas_oracle: Arc<GasOracle>,

    /// Default compute unit limit per transaction
    default_compute_unit_limit: u64,

    /// Maximum compute unit limit per transaction
    max_compute_unit_limit: u64,
}

impl SvmExecutor {
    /// Create a new SVM executor.
    pub fn new(config: VmConfig, gas_oracle: Arc<GasOracle>) -> Result<Self> {
        #[cfg(feature = "svm-full")]
        tracing::info!("Initializing SVM executor (solana-svm TransactionBatchProcessor)");
        #[cfg(not(feature = "svm-full"))]
        tracing::info!(
            "Initializing SVM executor (SPL + cross-VM native paths; SBF programs require `svm-full`)"
        );

        Ok(Self {
            config,
            gas_oracle,
            default_compute_unit_limit: 200_000,
            max_compute_unit_limit: svm_gas_costs::MAX_COMPUTE_UNITS,
        })
    }

    /// Returns the gas oracle shared with the parent runtime.
    pub fn gas_oracle(&self) -> &Arc<GasOracle> {
        &self.gas_oracle
    }

    /// Derive program-derived address (PDA) using Solana-compatible algorithm.
    ///
    /// PDAs are off-curve Ed25519 points derived deterministically from a
    /// program ID and seeds. They enable programs to "sign" for accounts
    /// without a private key.
    ///
    /// Algorithm (Solana-compatible `find_program_address`):
    /// 1. Iterate bump seed from 255 down to 0
    /// 2. Hash: SHA-256(seeds || [bump] || program_id || "ProgramDerivedAddress")
    /// 3. Check if the resulting 32-byte hash is NOT a valid Ed25519 public key
    ///    (off-curve)
    /// 4. Return the first off-curve result as the PDA
    fn derive_pda(program_id: &[u8], seeds: &[&[u8]]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        for bump in (0u8..=255).rev() {
            let mut hasher = Sha256::new();
            for seed in seeds {
                hasher.update(seed);
            }
            hasher.update([bump]);
            hasher.update(program_id);
            hasher.update(b"ProgramDerivedAddress");

            let hash = hasher.finalize();
            let hash_bytes: [u8; 32] = hash.into();

            // Off-curve check: if CompressedEdwardsY decompression fails, the
            // point has no corresponding private key → valid PDA.
            let compressed = curve25519_dalek::edwards::CompressedEdwardsY(hash_bytes);
            if compressed.decompress().is_none() {
                return hash_bytes.to_vec();
            }
        }

        // Fallback: all 256 bumps on-curve (astronomically unlikely).
        // Deterministic bump=0 result — deployment address derivation needs a
        // total function.
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([0u8]);
        hasher.update(program_id);
        hasher.update(b"ProgramDerivedAddress");
        hasher.finalize().to_vec()
    }

    /// Native SPL Token Program dispatch for wTNZO.
    ///
    /// The Tenzro SVM dispatches a single instruction per transaction (vs.
    /// Solana's multi-instruction Message). To carry the per-instruction
    /// account list across the dispatch boundary, callers prepend a serialized
    /// account vector to `tx.data` for `SPL_TOKEN_PROGRAM_ID` calls:
    ///
    /// ```text
    ///   [n_accounts: u8] [account_0: 32] ... [account_{n-1}: 32] [spl_data: variable]
    /// ```
    ///
    /// Per-instruction SPL accounts (per Solana SPL Token v0.3+):
    /// - Transfer:    accounts[0]=source (must be the signer), [1]=destination,
    ///   [2]=authority (must be the signer)
    /// - GetBalance:  accounts[0]=token_account
    ///
    /// MintTo, Burn, Approve and Revoke are refused. Balance accounting is
    /// performed directly against `VmState` (the native TNZO ledger) using
    /// `tenzro_token::spl_to_native` for the 9-decimal SPL to 18-decimal
    /// native conversion.
    fn execute_spl_native(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        sender_balance: u128,
        compute_units: u64,
        token_2022: bool,
    ) -> Result<ExecutionResult> {
        use super::spl_adapter::{
            SPL_TOKEN_PROGRAM_ID, SplInstruction, TOKEN_2022_PROGRAM_ID, WTNZO_SPL_MINT,
        };
        let program = if token_2022 {
            TOKEN_2022_PROGRAM_ID
        } else {
            SPL_TOKEN_PROGRAM_ID
        };
        use tenzro_token::spl_to_native;

        // Conservative fixed CU cost for pure-Rust SPL dispatch. Matches
        // Solana SPL Token program's documented Transfer cost (~5_000 CU).
        let actual_cu = compute_units.max(5_000);
        let nonce = state.get_nonce(&tx.from);
        let gas_cost = actual_cu as u128 * tx.gas_price;
        let new_sender_balance = sender_balance.saturating_sub(gas_cost);

        // Helper that bumps nonce + debits gas before returning a failure.
        // Solana semantics: failed tx still bumps nonce and charges fees.
        let charge_and_fail = |state: &mut dyn VmState, msg: String| -> ExecutionResult {
            state.set_nonce(&tx.from, nonce + 1);
            state.set_balance(&tx.from, new_sender_balance);
            ExecutionResult::failed(actual_cu, msg)
        };

        // Decode the account prefix.
        if tx.data.is_empty() {
            return Ok(charge_and_fail(
                state,
                "SPL: empty calldata (expected [n_accounts: u8] [accounts: 32*n] [spl_data])"
                    .into(),
            ));
        }
        let n_accounts = tx.data[0] as usize;
        let prefix_len = 1 + n_accounts * 32;
        if tx.data.len() < prefix_len + 1 {
            return Ok(charge_and_fail(
                state,
                format!(
                    "SPL: calldata too short — expected {} bytes for {} accounts + instruction",
                    prefix_len + 1,
                    n_accounts
                ),
            ));
        }
        let mut accounts: Vec<[u8; 32]> = Vec::with_capacity(n_accounts);
        for i in 0..n_accounts {
            let off = 1 + i * 32;
            let mut acc = [0u8; 32];
            acc.copy_from_slice(&tx.data[off..off + 32]);
            accounts.push(acc);
        }
        let spl_data = &tx.data[prefix_len..];

        let opcode = spl_data[0];
        if token_2022 {
            if let Some(refusal) = super::spl_adapter::token_2022_refusal(opcode) {
                return Ok(charge_and_fail(state, format!("Token-2022 {refusal}")));
            }
        } else if opcode == super::spl_adapter::GET_MINT_EXTENSIONS {
            return Ok(charge_and_fail(
                state,
                "SPL: mint extensions are read through Token-2022".into(),
            ));
        }
        let instruction = match SplInstruction::from_byte(opcode) {
            Some(i) => i,
            None => {
                return Ok(charge_and_fail(
                    state,
                    format!("SPL: unknown instruction opcode {}", opcode),
                ));
            }
        };

        // Track whether the handler has already committed gas + nonce. The
        // Transfer path commits early to avoid clobbering the source balance
        // when authority == source == tx.from; other paths defer to the
        // common commit at the end of this function.
        let mut gas_already_committed = false;
        // The mint the receipt's log names.
        let mut log_mint = WTNZO_SPL_MINT;

        // Dispatch. Returns logs + state_changes to merge into the receipt.
        let (instruction_name, output_data, extra_state_changes) = match instruction {
            SplInstruction::Transfer => {
                if accounts.len() < 3 {
                    return Ok(charge_and_fail(
                        state,
                        "SPL Transfer: need 3 accounts (source, destination, authority)".into(),
                    ));
                }
                if spl_data.len() < 9 {
                    return Ok(charge_and_fail(
                        state,
                        "SPL Transfer: need 8-byte LE u64 amount after opcode".into(),
                    ));
                }
                let amount_spl = u64::from_le_bytes(spl_data[1..9].try_into().unwrap());
                let amount_native = spl_to_native(amount_spl);

                // Authority must equal the tx signer — SPL semantics require
                // the authority to sign the instruction.
                if accounts[2].as_slice() != tx.from.as_slice() {
                    return Ok(charge_and_fail(
                        state,
                        "SPL Transfer: authority does not match tx signer".into(),
                    ));
                }
                // In the pointer model an SPL token account is the owner's
                // native account, so the only source an authority may debit
                // is its own.
                if accounts[0].as_slice() != tx.from.as_slice() {
                    return Ok(charge_and_fail(
                        state,
                        "SPL Transfer: source account is not owned by the signer".into(),
                    ));
                }
                // Commit gas + nonce BEFORE the transfer write. In the
                // single-owner ATA pointer-model authority == source == tx.from,
                // so the gas-deduction write to tx.from must not overwrite the
                // post-transfer source balance. Pre-debit here, then read the
                // post-gas source balance for the transfer math.
                state.set_nonce(&tx.from, nonce + 1);
                state.set_balance(&tx.from, new_sender_balance);
                gas_already_committed = true;

                let source_balance = state.get_balance(&accounts[0]);
                if source_balance < amount_native {
                    // Rollback the gas deduction is impossible without a
                    // checkpoint; per Solana semantics nonce+gas are sticky
                    // even on failure, so leave them and return.
                    return Ok(ExecutionResult::failed(
                        actual_cu,
                        format!(
                            "SPL Transfer: insufficient balance {} < {}",
                            source_balance, amount_native
                        ),
                    ));
                }
                state.set_balance(&accounts[0], source_balance - amount_native);
                // Read the destination after the debit, so a transfer to the
                // source itself nets to zero.
                let dest = accounts[1].to_vec();
                let dest_balance_before = state.get_balance(&dest);
                state.set_balance(&dest, dest_balance_before + amount_native);
                let changes = vec![
                    StateChange::new(
                        accounts[0].to_vec(),
                        b"balance".to_vec(),
                        Some(source_balance.to_le_bytes().to_vec()),
                        Some((source_balance - amount_native).to_le_bytes().to_vec()),
                    ),
                    StateChange::new(
                        dest.clone(),
                        b"balance".to_vec(),
                        Some(dest_balance_before.to_le_bytes().to_vec()),
                        Some((dest_balance_before + amount_native).to_le_bytes().to_vec()),
                    ),
                ];
                ("spl_transfer", amount_spl.to_le_bytes().to_vec(), changes)
            }
            SplInstruction::TransferChecked => {
                if accounts.len() < 4 {
                    return Ok(charge_and_fail(
                        state,
                        "SPL TransferChecked: need 4 accounts (source, mint, destination, authority)"
                            .into(),
                    ));
                }
                if spl_data.len() < 10 {
                    return Ok(charge_and_fail(
                        state,
                        "SPL TransferChecked: need an 8-byte LE u64 amount and a decimals byte"
                            .into(),
                    ));
                }
                let amount = u64::from_le_bytes(spl_data[1..9].try_into().unwrap());
                let decimals = spl_data[9];
                let mint = accounts[1];
                let (token, expected_decimals, amount_base) = if mint == WTNZO_SPL_MINT {
                    (
                        crate::token_ledger::tnzo_id(),
                        Some(9u8),
                        spl_to_native(amount),
                    )
                } else {
                    (
                        mint,
                        crate::evm::token_factory::token_decimals(state, &mint),
                        amount as u128,
                    )
                };
                match expected_decimals {
                    None => {
                        return Ok(charge_and_fail(
                            state,
                            "SPL TransferChecked: unknown mint".into(),
                        ));
                    }
                    Some(d) if d != decimals => {
                        return Ok(charge_and_fail(
                            state,
                            format!("SPL TransferChecked: mint has {d} decimals, not {decimals}"),
                        ));
                    }
                    Some(_) => {}
                }
                if accounts[3].as_slice() != tx.from.as_slice() {
                    return Ok(charge_and_fail(
                        state,
                        "SPL TransferChecked: authority does not match tx signer".into(),
                    ));
                }
                if accounts[0].as_slice() != tx.from.as_slice() {
                    return Ok(charge_and_fail(
                        state,
                        "SPL TransferChecked: source account is not owned by the signer".into(),
                    ));
                }
                // Gas first, as for Transfer: the source may be the account
                // that pays it.
                state.set_nonce(&tx.from, nonce + 1);
                state.set_balance(&tx.from, new_sender_balance);
                gas_already_committed = true;
                log_mint = mint;
                match crate::token_ledger::transfer(
                    state,
                    &token,
                    &accounts[0],
                    &accounts[2],
                    amount_base,
                    crate::native::deterministic_now_ms(tx),
                )? {
                    Some(changes) => (
                        "spl_transfer_checked",
                        amount.to_le_bytes().to_vec(),
                        changes,
                    ),
                    None => {
                        return Ok(ExecutionResult::failed(
                            actual_cu,
                            "SPL TransferChecked: insufficient balance".to_string(),
                        ));
                    }
                }
            }
            SplInstruction::GetBalance => {
                if accounts.is_empty() {
                    return Ok(charge_and_fail(
                        state,
                        "SPL GetBalance: need account address".into(),
                    ));
                }
                let native_balance = state.get_balance(&accounts[0]);
                let spl_balance = tenzro_token::native_to_spl(native_balance).unwrap_or(0);
                (
                    "spl_get_balance",
                    spl_balance.to_le_bytes().to_vec(),
                    vec![],
                )
            }
            SplInstruction::GetMintExtensions => {
                let Some(mint) = accounts.first() else {
                    return Ok(charge_and_fail(
                        state,
                        "Token-2022 GetMintExtensions: need the mint".into(),
                    ));
                };
                let Some(extensions) = super::spl_adapter::mint_extensions(state, mint) else {
                    return Ok(charge_and_fail(
                        state,
                        "Token-2022 GetMintExtensions: unknown mint".into(),
                    ));
                };
                log_mint = *mint;
                (
                    "token_2022_mint_extensions",
                    super::spl_adapter::encode_tlv(&extensions),
                    vec![],
                )
            }
            SplInstruction::MintTo
            | SplInstruction::Burn
            | SplInstruction::Approve
            | SplInstruction::Revoke => {
                // The SPL view cannot change native supply, and it keeps no
                // delegations of its own, so these are refused rather than
                // acknowledged as if something had happened.
                return Ok(charge_and_fail(
                    state,
                    format!("SPL {:?}: not supported by the ledger view", instruction),
                ));
            }
            SplInstruction::InitializeMint
            | SplInstruction::InitializeAccount
            | SplInstruction::CloseAccount => {
                // Token accounts are the owners' native accounts and the mint
                // exists by construction, so there is nothing to create or
                // close.
                ("spl_account_noop", Vec::new(), vec![])
            }
        };

        // Commit gas + nonce (unless the handler already did it).
        if !gas_already_committed {
            state.set_nonce(&tx.from, nonce + 1);
            state.set_balance(&tx.from, new_sender_balance);
        }

        let logs = vec![Log::new(
            program.to_vec(),
            vec![
                b"spl_token".to_vec(),
                instruction_name.as_bytes().to_vec(),
                log_mint.to_vec(),
                tx.from.clone(),
            ],
            output_data.clone(),
        )];

        let mut state_changes = vec![
            StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(nonce.to_le_bytes().to_vec()),
                Some((nonce + 1).to_le_bytes().to_vec()),
            ),
            StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ),
        ];
        state_changes.extend(extra_state_changes);

        tracing::debug!(
            "SVM: spl_token {} (cu={}) from {}",
            instruction_name,
            actual_cu,
            hex::encode(&tx.from),
        );

        Ok(ExecutionResult::success(
            actual_cu,
            output_data,
            logs,
            state_changes,
        ))
    }

    /// Execute a stored SBF/BPF program.
    ///
    /// Under the `svm-full` feature this drives Anza's `solana-svm`
    /// `TransactionBatchProcessor` against a `VmState`-backed account loader
    /// (see [`full`]). Without the feature it returns
    /// [`VmError::SvmFullFeatureRequired`] — there is no interpreter fallback.
    #[cfg(feature = "svm-full")]
    fn execute_sbf_program(
        &self,
        program_id: &[u8],
        program_elf: &[u8],
        instruction_data: &[u8],
        compute_unit_limit: u64,
        block_unix_timestamp: i64,
        state: &dyn VmState,
    ) -> Result<(Vec<u8>, u64, Vec<String>)> {
        super::full::process_sbf_transaction(
            program_id,
            program_elf,
            instruction_data,
            compute_unit_limit,
            self.max_compute_unit_limit,
            block_unix_timestamp,
            state,
        )
    }

    /// Off-feature path: executing a stored SBF program requires the
    /// `svm-full` feature. Returns [`VmError::SvmFullFeatureRequired`].
    #[cfg(not(feature = "svm-full"))]
    fn execute_sbf_program(
        &self,
        _program_id: &[u8],
        _program_elf: &[u8],
        _instruction_data: &[u8],
        _compute_unit_limit: u64,
        _block_unix_timestamp: i64,
        _state: &dyn VmState,
    ) -> Result<(Vec<u8>, u64, Vec<String>)> {
        Err(VmError::SvmFullFeatureRequired)
    }

    /// Calculate compute units for a transaction.
    ///
    /// Maps transaction properties to Solana compute unit costs.
    /// When actual BPF execution occurs, the real CU consumption is metered by
    /// the processor.
    fn calculate_compute_units(&self, data_len: usize, num_accounts: usize) -> u64 {
        let base = svm_gas_costs::TRANSACTION;
        let data_cost = (data_len as u64) * svm_gas_costs::DATA_BYTE;
        let account_cost = (num_accounts as u64) * 1000;

        let total = base + data_cost + account_cost;
        total.min(self.max_compute_unit_limit)
    }

    /// Parse compute budget instructions from transaction data.
    ///
    /// Solana transactions can include `ComputeBudgetInstruction` to request
    /// higher CU limits or set priority fees.
    fn parse_compute_budget(&self, _data: &[u8]) -> (u64, u64) {
        // Returns (compute_unit_limit, compute_unit_price)
        (self.default_compute_unit_limit, 0)
    }
}

#[async_trait]
impl VmExecutor for SvmExecutor {
    fn vm_type(&self) -> VmType {
        VmType::Svm
    }

    async fn execute_transaction(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
    ) -> Result<ExecutionResult> {
        tracing::debug!("SVM: Executing transaction from {}", hex::encode(&tx.from));

        // Validate sender has sufficient balance
        let sender_balance = state.get_balance(&tx.from);
        let Some(total_cost) = (tx.gas_limit as u128)
            .checked_mul(tx.gas_price)
            .and_then(|gas| gas.checked_add(tx.value))
        else {
            return Ok(ExecutionResult::failed(
                0,
                "Transaction cost overflows: value plus gas exceeds the largest balance"
                    .to_string(),
            ));
        };

        if sender_balance < total_cost {
            return Ok(ExecutionResult::failed(
                0,
                format!(
                    "Insufficient balance: have {}, need {}",
                    sender_balance, total_cost
                ),
            ));
        }

        // Calculate compute units
        let compute_units = self.calculate_compute_units(tx.data.len(), 2);

        if compute_units > tx.gas_limit {
            return Ok(ExecutionResult::failed(
                compute_units,
                format!(
                    "Insufficient compute units: need {}, have {}",
                    compute_units, tx.gas_limit
                ),
            ));
        }

        // Check if this is a deployment or call
        if tx.to.is_none() {
            // Program deployment via BPF Loader
            let nonce = state.get_nonce(&tx.from);
            let program_id = Self::derive_pda(&tx.from, &[&nonce.to_le_bytes()]);

            tracing::info!("SVM: Deploying program to {}", hex::encode(&program_id));

            // Validate program size
            self.config.validate_contract_size(tx.data.len())?;

            // Store program code
            state.set_code(&program_id, tx.data.clone());

            // Update sender nonce
            state.set_nonce(&tx.from, nonce + 1);

            // Deduct costs
            // Bounded by total_cost, which the balance check above admitted.
            let new_sender_balance = (compute_units as u128)
                .checked_mul(tx.gas_price)
                .and_then(|gas_cost| sender_balance.checked_sub(gas_cost))
                .and_then(|left| left.checked_sub(tx.value))
                .ok_or_else(|| {
                    VmError::InvalidTransaction(
                        "deploy cost exceeds the sender's balance".to_string(),
                    )
                })?;
            state.set_balance(&tx.from, new_sender_balance);

            // Credit the program account. It may already hold a balance
            // (anyone can send to a derived address before deployment), so
            // add rather than overwrite.
            let program_balance_before = state.get_balance(&program_id);
            if tx.value > 0 {
                state.set_balance(&program_id, program_balance_before.saturating_add(tx.value));
            }

            // Track state changes
            let mut state_changes = Vec::new();

            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(nonce.to_le_bytes().to_vec()),
                Some((nonce + 1).to_le_bytes().to_vec()),
            ));

            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ));

            state_changes.push(StateChange::new(
                program_id.clone(),
                b"code".to_vec(),
                None,
                Some(tx.data.clone()),
            ));

            if tx.value > 0 {
                state_changes.push(StateChange::new(
                    program_id.clone(),
                    b"balance".to_vec(),
                    Some(program_balance_before.to_le_bytes().to_vec()),
                    Some(
                        program_balance_before
                            .saturating_add(tx.value)
                            .to_le_bytes()
                            .to_vec(),
                    ),
                ));
            }

            Ok(ExecutionResult::deployment(
                compute_units,
                program_id,
                Vec::new(),
                state_changes,
            ))
        } else if let Some(program_id) = tx.to.as_ref() {
            // SPL Token Program short-circuit: the wTNZO SPL adapter is
            // implemented in Rust over the native VmState balance layer.
            if program_id.as_slice() == super::spl_adapter::SPL_TOKEN_PROGRAM_ID.as_slice() {
                return self.execute_spl_native(tx, state, sender_balance, compute_units, false);
            }
            if program_id.as_slice() == super::spl_adapter::TOKEN_2022_PROGRAM_ID.as_slice() {
                return self.execute_spl_native(tx, state, sender_balance, compute_units, true);
            }

            // A target with no stored code is not a program — it is an ordinary
            // account, and sending to one is a plain value transfer. Solana
            // treats a transfer to a non-executable account as routine (it is
            // what the System Program does), so returning `ContractNotFound`
            // here would make it impossible to move value between SVM accounts
            // at all: every `to`-bearing SVM transaction would have to name a
            // deployed program.
            let Some(program) = state.get_code(program_id) else {
                let gas_cost = compute_units as u128 * tx.gas_price;
                let total = gas_cost.saturating_add(tx.value);
                if sender_balance < total {
                    return Ok(ExecutionResult::failed(
                        compute_units,
                        format!(
                            "SVM: insufficient balance for transfer: have {sender_balance}, need {total}"
                        ),
                    ));
                }

                let nonce = state.get_nonce(&tx.from);
                let new_sender_balance = sender_balance - total;

                state.set_nonce(&tx.from, nonce + 1);
                state.set_balance(&tx.from, new_sender_balance);
                // Read the recipient after the debit, so a transfer to the
                // sender's own account nets to minus the fee.
                let old_recipient_balance = state.get_balance(program_id);
                let new_recipient_balance = old_recipient_balance.saturating_add(tx.value);
                if tx.value > 0 {
                    state.set_balance(program_id, new_recipient_balance);
                }

                // Emit the same state-change records a program call would, so
                // conservation accounting sees the movement.
                let mut state_changes = vec![
                    StateChange::new(
                        tx.from.clone(),
                        b"nonce".to_vec(),
                        Some(nonce.to_le_bytes().to_vec()),
                        Some((nonce + 1).to_le_bytes().to_vec()),
                    ),
                    StateChange::new(
                        tx.from.clone(),
                        b"balance".to_vec(),
                        Some(sender_balance.to_le_bytes().to_vec()),
                        Some(new_sender_balance.to_le_bytes().to_vec()),
                    ),
                ];
                if tx.value > 0 {
                    state_changes.push(StateChange::new(
                        program_id.clone(),
                        b"balance".to_vec(),
                        Some(old_recipient_balance.to_le_bytes().to_vec()),
                        Some(new_recipient_balance.to_le_bytes().to_vec()),
                    ));
                }

                tracing::debug!(
                    "SVM: value transfer of {} to non-program account {}",
                    tx.value,
                    hex::encode(program_id)
                );
                return Ok(ExecutionResult::success(
                    compute_units,
                    Vec::new(),
                    Vec::new(),
                    state_changes,
                ));
            };

            tracing::debug!("SVM: Executing program at {}", hex::encode(program_id));

            // Real SBF execution via solana-svm (feature-gated). Non-ELF
            // program bytes at a call target are a client error.
            if !(program.len() >= 4 && &program[..4] == b"\x7fELF") {
                let nonce = state.get_nonce(&tx.from);
                state.set_nonce(&tx.from, nonce + 1);
                let gas_cost = compute_units as u128 * tx.gas_price;
                state.set_balance(&tx.from, sender_balance - gas_cost);
                return Ok(ExecutionResult::failed(
                    compute_units,
                    "SVM: program at target is not a valid SBF ELF".to_string(),
                ));
            }

            let (output, cu_consumed, log_messages) = match self.execute_sbf_program(
                program_id,
                &program,
                &tx.data,
                tx.gas_limit,
                tx.block_timestamp_ms.unwrap_or(0) / 1000,
                state,
            ) {
                Ok(result) => result,
                Err(VmError::SvmFullFeatureRequired) => {
                    // No interpreter fallback — the operator must build with
                    // `svm-full` to run stored SBF programs. Do not charge the
                    // sender for an unsupported build configuration.
                    return Err(VmError::SvmFullFeatureRequired);
                }
                Err(e) => {
                    // Program execution failed — charge gas + bump nonce
                    // (Solana semantics) and return a failed result.
                    let nonce = state.get_nonce(&tx.from);
                    state.set_nonce(&tx.from, nonce + 1);
                    let gas_cost = compute_units as u128 * tx.gas_price;
                    state.set_balance(&tx.from, sender_balance - gas_cost);
                    return Ok(ExecutionResult::failed(
                        compute_units,
                        format!("SBF execution failed: {}", e),
                    ));
                }
            };

            let nonce = state.get_nonce(&tx.from);
            state.set_nonce(&tx.from, nonce + 1);

            // Deduct costs (use actual CU consumed by the processor).
            let actual_cu = cu_consumed.max(compute_units);
            let gas_cost = actual_cu as u128 * tx.gas_price;
            let new_sender_balance = sender_balance
                .checked_sub(gas_cost)
                .and_then(|b| b.checked_sub(tx.value))
                .ok_or_else(|| {
                    VmError::InvalidTransaction("insufficient balance for SBF call".to_string())
                })?;
            state.set_balance(&tx.from, new_sender_balance);
            // Read the recipient after the debit so that value sent to the
            // sender's own account is not counted twice.
            let old_recipient_balance = if tx.value > 0 {
                Some(state.get_balance(program_id))
            } else {
                None
            };

            // Transfer value if any (lamport transfer)
            if tx.value > 0 {
                let recipient_balance = old_recipient_balance.unwrap_or(0);
                state.set_balance(program_id, recipient_balance + tx.value);
            }

            let logs: Vec<Log> = log_messages
                .iter()
                .map(|msg| Log::new(program_id.clone(), Vec::new(), msg.as_bytes().to_vec()))
                .collect();

            let mut state_changes = Vec::new();

            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(nonce.to_le_bytes().to_vec()),
                Some((nonce + 1).to_le_bytes().to_vec()),
            ));

            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ));

            if tx.value > 0 {
                let old_bal = old_recipient_balance.unwrap_or(0);
                state_changes.push(StateChange::new(
                    program_id.clone(),
                    b"balance".to_vec(),
                    Some(old_bal.to_le_bytes().to_vec()),
                    Some((old_bal + tx.value).to_le_bytes().to_vec()),
                ));
            }

            Ok(ExecutionResult::success(
                actual_cu,
                output,
                logs,
                state_changes,
            ))
        } else {
            // Unreachable: tx.to.is_none() was already handled above
            Err(VmError::InvalidTransaction(
                "Missing destination address".to_string(),
            ))
        }
    }

    async fn call(&self, call: &ContractCall, state: &dyn VmState) -> Result<CallResult> {
        tracing::debug!("SVM: Read-only call to {}", hex::encode(&call.contract));

        // Get program code
        let program = state
            .get_code(&call.contract)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&call.contract)))?;

        if !(program.len() >= 4 && &program[..4] == b"\x7fELF") {
            return Err(VmError::ContractNotFound(hex::encode(&call.contract)));
        }

        let compute_limit = call.gas_limit.min(self.max_compute_unit_limit);
        match self.execute_sbf_program(
            &call.contract,
            &program,
            &call.data,
            compute_limit,
            call.block_timestamp_ms / 1000,
            state,
        ) {
            Ok((output, cu_consumed, _logs)) => Ok(CallResult::success(output, cu_consumed)),
            Err(VmError::SvmFullFeatureRequired) => Err(VmError::SvmFullFeatureRequired),
            Err(e) => {
                let cu = self.calculate_compute_units(call.data.len(), 2);
                Ok(CallResult::failed(cu, format!("SBF call failed: {}", e)))
            }
        }
    }

    async fn deploy_contract(
        &self,
        deployment: &ContractDeployment,
        state: &mut dyn VmState,
    ) -> Result<DeployResult> {
        tracing::info!(
            "SVM: Deploying program from {}",
            hex::encode(&deployment.deployer)
        );

        // Validate program size
        self.config.validate_contract_size(deployment.code.len())?;

        // Derive program ID
        let nonce = state.get_nonce(&deployment.deployer);
        let program_id = Self::derive_pda(&deployment.deployer, &[&nonce.to_le_bytes()]);

        // Calculate compute units
        let compute_units = svm_gas_costs::CREATE_ACCOUNT
            + (deployment.code.len() as u64 * svm_gas_costs::DATA_BYTE);

        if compute_units > deployment.gas_limit {
            return Ok(DeployResult::failed(
                compute_units,
                format!(
                    "Insufficient compute units: need {}, have {}",
                    compute_units, deployment.gas_limit
                ),
            ));
        }

        // Check balance
        let deployer_balance = state.get_balance(&deployment.deployer);
        let total_cost = deployment.value + (compute_units as u128 * deployment.gas_price);

        if deployer_balance < total_cost {
            return Ok(DeployResult::failed(
                0,
                format!(
                    "Insufficient balance: have {}, need {}",
                    deployer_balance, total_cost
                ),
            ));
        }

        // Deploy program
        state.set_code(&program_id, deployment.code.clone());
        state.set_nonce(&deployment.deployer, nonce + 1);

        // Deduct costs
        state.set_balance(&deployment.deployer, deployer_balance - total_cost);

        // Credit the program account on top of whatever it already holds.
        if deployment.value > 0 {
            let before = state.get_balance(&program_id);
            state.set_balance(&program_id, before.saturating_add(deployment.value));
        }

        Ok(DeployResult::success(program_id, compute_units))
    }

    async fn estimate_gas(&self, tx: &VmTransaction, _state: &dyn VmState) -> Result<u64> {
        let compute_units = if tx.to.is_none() {
            // Deployment
            svm_gas_costs::CREATE_ACCOUNT + (tx.data.len() as u64 * svm_gas_costs::DATA_BYTE)
        } else {
            // Call — parse compute budget if present
            let (requested_limit, _price) = self.parse_compute_budget(&tx.data);
            let calculated = self.calculate_compute_units(tx.data.len(), 2);
            calculated.max(requested_limit)
        };

        Ok(compute_units)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    fn create_executor() -> SvmExecutor {
        let config = VmConfig::default();
        let gas_oracle = Arc::new(GasOracle::new());

        SvmExecutor::new(config, gas_oracle).unwrap()
    }

    #[test]
    fn test_derive_pda() {
        let program_id = vec![1u8; 32];
        let seeds = &[b"test".as_ref()];

        let pda = SvmExecutor::derive_pda(&program_id, seeds);
        assert_eq!(pda.len(), 32);
    }

    #[tokio::test]
    async fn deploy_cost_that_wraps_u128_is_refused_without_minting() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![7u8; 32];
        state.set_balance(&deployer, 1_000);

        // gas_limit * gas_price = 1_000_000, so this value makes value + gas wrap to exactly 0.
        let value = u128::MAX - 1_000_000 + 1;
        let tx = VmTransaction::new(
            deployer.clone(),
            None,
            value,
            vec![0x00, 0x61, 0x73, 0x6D],
            1_000_000,
            1,
            0,
            VmType::Svm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(!result.success);
        assert_eq!(state.get_balance(&deployer), 1_000);
        let program_id = SvmExecutor::derive_pda(&deployer, &[&0u64.to_le_bytes()]);
        assert_eq!(state.get_balance(&program_id), 0);
        assert!(state.get_code(&program_id).is_none());
    }

    #[tokio::test]
    async fn test_program_deployment() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 32];
        // Non-ELF payload — deployment stores code verbatim without invoking
        // the SBF processor (validation happens at execution time).
        let code = vec![0x00, 0x61, 0x73, 0x6D];

        state.set_balance(&deployer, 10_000_000_000_000_000_000u128);

        let deployment = ContractDeployment::new(
            deployer.clone(),
            code.clone(),
            Vec::new(),
            0,
            500_000,
            1_000_000_000,
            0,
            VmType::Svm,
        );

        let result = executor
            .deploy_contract(&deployment, &mut state)
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.address.len(), 32);

        let stored_code = state.get_code(&result.address).unwrap();
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn test_non_elf_call_target_fails() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![1u8; 32];
        let program_id = vec![2u8; 32];
        // Non-ELF bytes stored at a call target — must be rejected as an
        // invalid SBF program regardless of build features.
        let program_code = vec![0x00, 0x61, 0x73, 0x6D];

        state.set_balance(&caller, 10_000_000_000_000_000_000u128);
        state.set_code(&program_id, program_code);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(program_id.clone()),
            0,
            vec![1, 2, 3, 4],
            100_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .revert_reason
                .unwrap()
                .contains("not a valid SBF ELF")
        );
    }

    #[tokio::test]
    async fn test_compute_unit_limit() {
        let executor = create_executor();
        assert_eq!(
            executor.max_compute_unit_limit,
            svm_gas_costs::MAX_COMPUTE_UNITS
        );
        assert_eq!(executor.default_compute_unit_limit, 200_000);
    }

    #[tokio::test]
    async fn test_insufficient_balance() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![1u8; 32];
        let program_id = vec![2u8; 32];
        state.set_balance(&caller, 100); // Very low balance
        state.set_code(&program_id, vec![0x00]);

        let tx = VmTransaction::new(
            caller,
            Some(program_id),
            1000, // Value exceeds balance
            vec![],
            100_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        );

        let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
        assert!(!result.success);
        assert!(
            result
                .revert_reason
                .unwrap()
                .contains("Insufficient balance")
        );
    }

    #[tokio::test]
    async fn test_call_nonexistent_program() {
        let executor = create_executor();
        let state = StateAdapter::new();

        let call = ContractCall::new(
            vec![1u8; 32],
            vec![2u8; 32],
            vec![],
            0,
            100_000,
            VmType::Svm,
        );

        let result = executor.call(&call, &state).await;
        assert!(result.is_err());
    }

    /// Full SPL Transfer dispatch via the native short-circuit:
    /// `tx.to = SPL_TOKEN_PROGRAM_ID`, data prefixed with [n=3][source][dest]
    /// [authority] then SPL Transfer opcode 3 + LE u64 amount. Verifies that
    /// source → dest balance moves and authority signing parity is enforced.
    #[tokio::test]
    async fn test_spl_native_transfer() {
        use crate::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
        use crate::traits::VmState;
        use tenzro_token::spl_to_native;

        let executor = create_executor();
        let mut state = StateAdapter::new();

        let source = [0x11u8; 32];
        let dest = [0x22u8; 32];
        let authority = source; // single-owner ATA model

        // Fund source with 100 native TNZO (18 dec) — enough to cover gas + transfer.
        let one_tnzo: u128 = 1_000_000_000_000_000_000;
        state.set_balance(&source, 100 * one_tnzo);

        // Build calldata: [n_accounts=3][source][dest][authority][opcode=3][amount_le_u64].
        let amount_spl: u64 = 5_000_000_000; // 5.0 wTNZO at 9 decimals
        let mut data = Vec::new();
        data.push(3u8);
        data.extend_from_slice(&source);
        data.extend_from_slice(&dest);
        data.extend_from_slice(&authority);
        data.push(3u8); // SPL Transfer opcode
        data.extend_from_slice(&amount_spl.to_le_bytes());

        let vm_tx = VmTransaction::new(
            source.to_vec(),
            Some(SPL_TOKEN_PROGRAM_ID.to_vec()),
            0,
            data,
            200_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        );

        let result = executor
            .execute_transaction(&vm_tx, &mut state)
            .await
            .unwrap();

        assert!(
            result.success,
            "SPL transfer should succeed: {:?}",
            result.revert_reason
        );

        let amount_native = spl_to_native(amount_spl);
        let dest_after = state.get_balance(&dest);
        assert_eq!(
            dest_after, amount_native,
            "destination should receive native amount"
        );

        // Source balance: started at 100 TNZO, lost gas + 5 TNZO transfer.
        let src_after = state.get_balance(&source);
        assert!(
            src_after < (100 * one_tnzo) - amount_native,
            "source must pay gas"
        );
        assert!(
            src_after >= (100 * one_tnzo) - amount_native - one_tnzo,
            "gas should be modest"
        );

        // Nonce bumped.
        assert_eq!(state.get_nonce(&source), 1);
    }

    /// SPL Transfer must fail when authority != tx signer.
    #[tokio::test]
    async fn test_spl_native_transfer_authority_mismatch() {
        use crate::svm::spl_adapter::SPL_TOKEN_PROGRAM_ID;
        use crate::traits::VmState;

        let executor = create_executor();
        let mut state = StateAdapter::new();

        let source = [0x11u8; 32];
        let dest = [0x22u8; 32];
        let wrong_authority = [0x33u8; 32]; // not the signer

        let one_tnzo: u128 = 1_000_000_000_000_000_000;
        state.set_balance(&source, 100 * one_tnzo);

        let amount_spl: u64 = 1_000_000_000;
        let mut data = Vec::new();
        data.push(3u8);
        data.extend_from_slice(&source);
        data.extend_from_slice(&dest);
        data.extend_from_slice(&wrong_authority);
        data.push(3u8);
        data.extend_from_slice(&amount_spl.to_le_bytes());

        let vm_tx = VmTransaction::new(
            source.to_vec(),
            Some(SPL_TOKEN_PROGRAM_ID.to_vec()),
            0,
            data,
            200_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        );

        let result = executor
            .execute_transaction(&vm_tx, &mut state)
            .await
            .unwrap();

        assert!(!result.success, "authority mismatch should fail");
        // But nonce is still bumped (Solana semantics).
        assert_eq!(state.get_nonce(&source), 1);
    }

    /// Without the `svm-full` feature, executing a stored SBF ELF at a call
    /// target must surface [`VmError::SvmFullFeatureRequired`] — no
    /// interpreter fallback and no silent success.
    #[cfg(not(feature = "svm-full"))]
    #[tokio::test]
    async fn test_sbf_requires_svm_full_feature() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![1u8; 32];
        let program_id = vec![2u8; 32];
        // Minimal ELF magic — enough to route into the SBF path.
        let program_code = b"\x7fELF".to_vec();

        state.set_balance(&caller, 10_000_000_000_000_000_000u128);
        state.set_code(&program_id, program_code);

        let tx = VmTransaction::new(
            caller,
            Some(program_id),
            0,
            vec![1, 2, 3, 4],
            100_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        );

        let err = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap_err();
        assert!(matches!(err, VmError::SvmFullFeatureRequired));
    }

    fn token_2022_tx(from: [u8; 32], accounts: &[[u8; 32]], ix: &[u8]) -> VmTransaction {
        let mut data = vec![accounts.len() as u8];
        for a in accounts {
            data.extend_from_slice(a);
        }
        data.extend_from_slice(ix);
        VmTransaction::new(
            from.to_vec(),
            Some(crate::svm::spl_adapter::TOKEN_2022_PROGRAM_ID.to_vec()),
            0,
            data,
            200_000,
            1_000_000_000,
            0,
            VmType::Svm,
            1337,
        )
    }

    #[test]
    fn token_2022_extension_tlv_round_trips() {
        use crate::svm::spl_adapter::{MintExtension, decode_tlv, encode_tlv};
        let exts = vec![
            MintExtension::DefaultAccountState { frozen: true },
            MintExtension::PermanentDelegate { delegate: [7; 32] },
            MintExtension::Pausable {
                authority: [9; 32],
                paused: true,
            },
            MintExtension::ScaledUiAmount { multiplier: 1.0 },
        ];
        assert_eq!(decode_tlv(&encode_tlv(&exts)).unwrap(), exts);
        assert!(
            decode_tlv(&[14, 0, 1, 0, 0]).is_err(),
            "a transfer hook extension is not part of the view"
        );
    }

    #[tokio::test]
    async fn token_2022_moves_the_ledger_and_refuses_by_name() {
        use crate::traits::VmState;
        let executor = create_executor();
        let mut state = StateAdapter::new();
        let holder = [0x11u8; 32];
        let dest = [0x22u8; 32];
        state.set_balance(&holder, 10u128.pow(20));
        let token = crate::token_ledger::test_token(&mut state, Vec::new());

        let mut ix = vec![12u8];
        ix.extend_from_slice(&40u64.to_le_bytes());
        ix.push(0);
        let r = executor
            .execute_transaction(
                &token_2022_tx(holder, &[holder, token, dest, holder], &ix),
                &mut state,
            )
            .await
            .unwrap();
        assert!(r.success, "{:?}", r.revert_reason);
        assert_eq!(crate::token_ledger::balance(&state, &token, &dest), 40);

        // The extension read reports the halt; a halted token refuses.
        let mut changes = Vec::new();
        crate::token_ledger::set_halted(&mut state, &token, true, &mut changes);
        let r = executor
            .execute_transaction(
                &token_2022_tx(
                    holder,
                    &[token],
                    &[crate::svm::spl_adapter::GET_MINT_EXTENSIONS],
                ),
                &mut state,
            )
            .await
            .unwrap();
        assert!(r.success);
        let exts = crate::svm::spl_adapter::decode_tlv(&r.output).unwrap();
        assert!(
            exts.contains(&crate::svm::spl_adapter::MintExtension::Pausable {
                authority: [0; 32],
                paused: true
            })
        );
        let refused = executor
            .execute_transaction(
                &token_2022_tx(holder, &[holder, token, dest, holder], &ix),
                &mut state,
            )
            .await
            .map_or(true, |r| !r.success);
        assert!(refused, "a halted token refuses TransferChecked");
        assert_eq!(crate::token_ledger::balance(&state, &token, &dest), 40);

        for (opcode, name) in [
            (36u8, "TransferHookUnsupported"),
            (27, "ConfidentialTransferUnsupported"),
            (7, "SupplyOutsideTokenOp"),
            (8, "SupplyOutsideTokenOp"),
            (3, "UncheckedTransfer"),
        ] {
            let r = executor
                .execute_transaction(
                    &token_2022_tx(holder, &[holder], &[opcode, 0, 0, 0, 0, 0, 0, 0, 0]),
                    &mut state,
                )
                .await
                .unwrap();
            assert!(!r.success);
            let why = r.revert_reason.unwrap_or_default();
            assert!(why.contains(name), "opcode {opcode}: {why}");
        }
        let _ = state.get_nonce(&holder);
    }
}
