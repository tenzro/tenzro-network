//! SVM executor implementing Solana Virtual Machine compatibility for Tenzro.
//!
//! This executor serves three code paths, dispatched in
//! [`SvmExecutor::execute_transaction`] on the destination program id:
//!
//! 1. **SPL Token adapter** (`tx.to == SPL_TOKEN_PROGRAM_ID`) — the wTNZO SPL
//!    Token program is implemented in Rust over the native `VmState` balance
//!    layer (9-decimal truncation, ATA derivation). See [`Self::execute_spl_native`].
//! 2. **`tenzro_cross_vm` native program** (`tx.to == TENZRO_CROSS_VM_PROGRAM_ID`)
//!    — a Rust-implemented native program (analogous to Solana's System /
//!    BPFLoader) that decodes cross-VM intents and emits canonical structured
//!    logs. See [`Self::execute_cross_vm_native`].
//! 3. **SBF/BPF program execution** (any other stored ELF) — real Solana
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
    gas::{svm_gas_costs, GasOracle},
    traits::{VmExecutor, VmState, VmType},
    types::{
        CallResult, ContractCall, ContractDeployment, DeployResult, ExecutionResult, Log,
        StateChange, VmTransaction,
    },
};

#[cfg(feature = "svm-full")]
mod full;

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

    /// Execute the native `tenzro_cross_vm` program.
    ///
    /// `tenzro_cross_vm` has no stored ELF — it is a Rust-implemented native
    /// program. The dispatch site in [`Self::execute_transaction`]
    /// short-circuits the ELF lookup whenever
    /// `tx.to == TENZRO_CROSS_VM_PROGRAM_ID`.
    ///
    /// # Execution model
    ///
    /// This method is a **decoder + intent emitter**, not a direct cross-VM
    /// mutator. It:
    ///
    ///   1. Decodes `tx.data` via [`CrossVmInstruction::decode`].
    ///   2. Validates instruction shape (decoder enforces payload size + dest_vm bounds).
    ///   3. Charges a fixed compute-unit cost per instruction kind.
    ///   4. Emits a structured log carrying the canonical encoded instruction
    ///      bytes (hex). Off-chain consumers and the EVM follow-on path read
    ///      this log to drive the actual cross-VM balance transition through
    ///      the `cross_vm_bridge` precompile at EVM `0x1003`.
    ///   5. Increments sender nonce and deducts gas cost from sender balance.
    ///
    /// # Why intent-emission, not direct mutation
    ///
    /// The consensus-mediated cross-VM atomicity invariant lives in the
    /// EVM-side `cross_vm_bridge` precompile (and its parallel handlers in
    /// `MultiVmRuntime`). Replicating it here would create two independent
    /// authoritative paths for the same global invariant. By having the SVM
    /// program emit a canonical, signed structured intent that flows into the
    /// existing EVM precompile, we preserve a single source of truth for
    /// cross-VM transitions while still allowing SVM transactions to
    /// originate them.
    fn execute_cross_vm_native(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        sender_balance: u128,
        compute_units: u64,
    ) -> Result<ExecutionResult> {
        use super::cross_vm::{CrossVmInstruction, TENZRO_CROSS_VM_PROGRAM_ID};

        // Decode the instruction. Decoder errors are programmer / client
        // errors (malformed calldata) → return failed with a clear reason
        // rather than aborting the whole tx pipeline.
        let instruction = match CrossVmInstruction::decode(&tx.data) {
            Ok(i) => i,
            Err(e) => {
                // Charge nonce + minimum compute units even on decode failure
                // (Solana semantics: failed tx still bumps nonce and fees).
                let nonce = state.get_nonce(&tx.from);
                state.set_nonce(&tx.from, nonce + 1);
                let gas_cost = compute_units as u128 * tx.gas_price;
                let new_sender_balance = sender_balance.saturating_sub(gas_cost);
                state.set_balance(&tx.from, new_sender_balance);
                return Ok(ExecutionResult::failed(
                    compute_units,
                    format!("tenzro_cross_vm: decode error: {}", e),
                ));
            }
        };

        // Per-instruction CU cost. Conservative fixed costs — these are
        // pure-Rust handlers, not BPF execution, so the dominant cost is
        // signature verification on the outer transaction. The amounts here
        // mirror Solana's System program transfer (~150 CU baseline) plus a
        // headroom factor for the structured log emission.
        let (instruction_name, cu_cost) = match &instruction {
            CrossVmInstruction::BridgeToEvm { .. } => ("bridge_to_evm", 5_000u64),
            CrossVmInstruction::BridgeFromEvm { .. } => ("bridge_from_evm", 5_000u64),
            CrossVmInstruction::RegisterTokenPointer { .. } => ("register_token_pointer", 7_500u64),
            CrossVmInstruction::TransferCrossVm { .. } => ("transfer_cross_vm", 5_000u64),
        };

        let actual_cu = compute_units.max(cu_cost);

        // Capture pre-state for state-change tracking.
        let nonce = state.get_nonce(&tx.from);

        // Charge gas + bump nonce. Cross-VM intents do not transfer SVM-side
        // SOL/lamports — `tx.value` is required to be zero by upstream
        // validation (the cross-VM bridge moves token-registry-tracked assets,
        // not native SOL). Reject value transfer here defensively.
        if tx.value != 0 {
            state.set_nonce(&tx.from, nonce + 1);
            let gas_cost = actual_cu as u128 * tx.gas_price;
            let new_sender_balance = sender_balance.saturating_sub(gas_cost);
            state.set_balance(&tx.from, new_sender_balance);
            return Ok(ExecutionResult::failed(
                actual_cu,
                "tenzro_cross_vm: tx.value must be zero (use bridge_to_evm/transfer_cross_vm)"
                    .to_string(),
            ));
        }

        let gas_cost = actual_cu as u128 * tx.gas_price;
        let new_sender_balance = sender_balance.saturating_sub(gas_cost);
        state.set_nonce(&tx.from, nonce + 1);
        state.set_balance(&tx.from, new_sender_balance);

        // Emit the canonical structured log. Format:
        //
        //   topic[0] = b"tenzro_cross_vm"     (event family)
        //   topic[1] = instruction_name       (UTF-8)
        //   topic[2] = sender                 (raw bytes)
        //   data     = re-encoded instruction (discriminator || payload)
        //
        // Off-chain processors and the EVM follow-on path consume this log
        // by re-decoding `data` via `CrossVmInstruction::decode`.
        let encoded = instruction.encode();
        let logs = vec![Log::new(
            TENZRO_CROSS_VM_PROGRAM_ID.to_vec(),
            vec![
                b"tenzro_cross_vm".to_vec(),
                instruction_name.as_bytes().to_vec(),
                tx.from.clone(),
            ],
            encoded,
        )];

        // Track state changes for the receipt.
        let state_changes = vec![
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

        tracing::debug!(
            "SVM: tenzro_cross_vm dispatched {} (cu={}) from {}",
            instruction_name,
            actual_cu,
            hex::encode(&tx.from),
        );

        Ok(ExecutionResult::success(
            actual_cu,
            Vec::new(),
            logs,
            state_changes,
        ))
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
    /// - Transfer:    accounts[0]=source, [1]=destination, [2]=authority
    /// - MintTo:      accounts[0]=mint,   [1]=destination, [2]=mint_authority
    /// - Burn:        accounts[0]=source, [1]=mint,        [2]=authority
    /// - GetBalance:  accounts[0]=token_account
    ///
    /// Balance accounting is performed directly against `VmState` (the unified
    /// TNZO balance layer) using `tenzro_token::spl_to_native` for the
    /// 9-decimal SPL → 18-decimal native conversion. There is no separate
    /// TnzoToken `Arc` because the SVM executor and the unified token registry
    /// share the same RocksDB-backed balance column family via `VmState`.
    fn execute_spl_native(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        sender_balance: u128,
        compute_units: u64,
    ) -> Result<ExecutionResult> {
        use super::spl_adapter::{SplInstruction, SPL_TOKEN_PROGRAM_ID, WTNZO_SPL_MINT};
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
                let dest_balance_before = state.get_balance(&accounts[1]);
                state.set_balance(&accounts[0], source_balance - amount_native);
                state.set_balance(&accounts[1], dest_balance_before + amount_native);
                let changes = vec![
                    StateChange::new(
                        accounts[0].to_vec(),
                        b"balance".to_vec(),
                        Some(source_balance.to_le_bytes().to_vec()),
                        Some((source_balance - amount_native).to_le_bytes().to_vec()),
                    ),
                    StateChange::new(
                        accounts[1].to_vec(),
                        b"balance".to_vec(),
                        Some(dest_balance_before.to_le_bytes().to_vec()),
                        Some((dest_balance_before + amount_native).to_le_bytes().to_vec()),
                    ),
                ];
                ("spl_transfer", amount_spl.to_le_bytes().to_vec(), changes)
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
                ("spl_get_balance", spl_balance.to_le_bytes().to_vec(), vec![])
            }
            SplInstruction::MintTo | SplInstruction::Burn => {
                // In the pointer model the bridge layer is the authority for
                // mint/burn — the SPL adapter only acknowledges. Surface this
                // as a successful no-op so callers can build SPL workflows but
                // the actual issuance happens via the bridge crate.
                tracing::debug!(
                    "SPL {:?}: no-op in pointer model — handled by bridge layer",
                    instruction
                );
                (
                    match instruction {
                        SplInstruction::MintTo => "spl_mint_to",
                        SplInstruction::Burn => "spl_burn",
                        _ => unreachable!(),
                    },
                    Vec::new(),
                    vec![],
                )
            }
            _ => {
                // InitializeMint / InitializeAccount / Approve / Revoke /
                // CloseAccount are administrative; treated as successful
                // no-ops at the pointer-model adapter layer.
                tracing::debug!("SPL {:?}: administrative no-op", instruction);
                ("spl_admin_noop", Vec::new(), vec![])
            }
        };

        // Commit gas + nonce (unless the handler already did it).
        if !gas_already_committed {
            state.set_nonce(&tx.from, nonce + 1);
            state.set_balance(&tx.from, new_sender_balance);
        }

        let logs = vec![Log::new(
            SPL_TOKEN_PROGRAM_ID.to_vec(),
            vec![
                b"spl_token".to_vec(),
                instruction_name.as_bytes().to_vec(),
                WTNZO_SPL_MINT.to_vec(),
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
        state: &dyn VmState,
    ) -> Result<(Vec<u8>, u64, Vec<String>)> {
        full::process_sbf_transaction(
            program_id,
            program_elf,
            instruction_data,
            compute_unit_limit,
            self.max_compute_unit_limit,
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
        let total_cost = tx.value + (tx.gas_limit as u128 * tx.gas_price);

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
            let gas_cost = compute_units as u128 * tx.gas_price;
            let new_sender_balance = sender_balance - gas_cost - tx.value;
            state.set_balance(&tx.from, new_sender_balance);

            // Initialize program account balance
            if tx.value > 0 {
                state.set_balance(&program_id, tx.value);
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
                    Some(0u128.to_le_bytes().to_vec()),
                    Some(tx.value.to_le_bytes().to_vec()),
                ));
            }

            Ok(ExecutionResult::deployment(
                compute_units,
                program_id,
                Vec::new(),
                state_changes,
            ))
        } else if let Some(program_id) = tx.to.as_ref() {
            // Native program short-circuit: tenzro_cross_vm is implemented in
            // Rust, has no stored ELF, and is dispatched directly here.
            if program_id.as_slice() == super::cross_vm::TENZRO_CROSS_VM_PROGRAM_ID.as_slice() {
                return self.execute_cross_vm_native(tx, state, sender_balance, compute_units);
            }

            // SPL Token Program short-circuit: the wTNZO SPL adapter is
            // implemented in Rust over the native VmState balance layer.
            if program_id.as_slice() == super::spl_adapter::SPL_TOKEN_PROGRAM_ID.as_slice() {
                return self.execute_spl_native(tx, state, sender_balance, compute_units);
            }

            // Get program code
            let program = state
                .get_code(program_id)
                .ok_or_else(|| VmError::ContractNotFound(hex::encode(program_id)))?;

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

            // Capture pre-state for state change tracking
            let nonce = state.get_nonce(&tx.from);
            let old_recipient_balance = if tx.value > 0 {
                Some(state.get_balance(program_id))
            } else {
                None
            };

            state.set_nonce(&tx.from, nonce + 1);

            // Deduct costs (use actual CU consumed by the processor).
            let actual_cu = cu_consumed.max(compute_units);
            let gas_cost = actual_cu as u128 * tx.gas_price;
            let new_sender_balance = sender_balance - gas_cost - tx.value;
            state.set_balance(&tx.from, new_sender_balance);

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

        // Set initial program balance
        if deployment.value > 0 {
            state.set_balance(&program_id, deployment.value);
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

        let result = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result
            .revert_reason
            .unwrap()
            .contains("not a valid SBF ELF"));
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

        let result = executor
            .execute_transaction(&tx, &mut state)
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.revert_reason.unwrap().contains("Insufficient balance"));
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
}
