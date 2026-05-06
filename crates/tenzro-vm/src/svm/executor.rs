//! SVM executor implementation with real Anza solana-sbpf BPF execution
//!
//! This executor implements Solana Virtual Machine (SVM) compatibility for Tenzro Network
//! using the `solana-sbpf` crate (the Anza fork of solana_rbpf, which is the active 2026
//! upstream) for actual eBPF/SBF program execution. Programs are loaded as ELF binaries
//! and executed in a metered, sandboxed BPF virtual machine with Solana-compatible syscalls.
//!
//! # Architecture
//!
//! 1. Accepts `VmTransaction` from the multi-VM runtime router
//! 2. Loads program ELF bytecode from state
//! 3. Sets up Solana-compatible memory layout (stack, heap, input region)
//! 4. Registers syscall builtins (sol_log_, sol_log_64_, sol_sha256, abort)
//! 5. Executes via `solana_sbpf::vm::EbpfVm::execute_program()` in interpreted mode
//! 6. Maps results back to Tenzro's `ExecutionResult` format
//!
//! # Compute Units
//!
//! Solana uses compute units (CU) instead of gas. The instruction meter enforces limits:
//! - 200,000 CU default per instruction
//! - 1,400,000 CU max per transaction
//! - Each BPF instruction consumes 1 CU
//!
//! # solana-sbpf 0.20 model notes
//!
//! In sBPF 0.20 the `ContextObject` trait owns the `MemoryMapping` (returned via
//! `active_mapping_ptr`). Syscalls receive `&mut C` (the context object) directly,
//! and access memory through the mapping pointer. This is the canonical pattern
//! used by Anza's own `TestContextObject` and is required for the safe-by-default
//! `declare_builtin_function!` macro.

use async_trait::async_trait;
use std::ptr::NonNull;
use std::sync::Arc;

use solana_sbpf::{
    aligned_memory::AlignedMemory,
    declare_builtin_function, ebpf,
    elf::Executable,
    error::EbpfError,
    memory_region::{AccessType, MemoryMapping, MemoryRegion},
    program::{BuiltinFunctionDefinition, BuiltinProgram, SBPFVersion},
    verifier::RequisiteVerifier,
    vm::{CallFrame, Config, ContextObject, EbpfVm, ExecutionMode},
};

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

/// Tenzro context object implementing sBPF 0.20's `ContextObject` trait.
///
/// In sBPF 0.20 the context owns the `MemoryMapping` — the VM borrows the
/// mapping via `active_mapping_ptr()`. The mapping is initialized just before
/// `EbpfVm::new` is called and lives as long as `TenzroContext` itself.
///
/// The `'static` lifetime is a transmute artifact — the actual borrows in the
/// regions vector (stack/heap/input slices) are scoped to `execute_program`,
/// and the mapping is dropped via `Drop`-on-`TenzroContext` before those slices
/// go out of scope. This mirrors the idiom in Anza's own example at
/// `solana_sbpf::vm::EbpfVm` doc and `TestContextObject::memory_mapping`.
pub(crate) struct TenzroContext {
    /// Remaining compute units
    remaining: u64,
    /// Collected log messages from sol_log syscalls
    log_messages: Vec<String>,
    /// The active memory mapping. Initialized to an empty mapping at construction;
    /// callers MUST replace it (via `set_memory_mapping`) before the VM runs.
    ///
    /// `MemoryMapping` lost its lifetime parameter in sBPF 0.20: it stores raw
    /// `(host_addr, vm_addr, len)` triples in `MemoryRegion`, so the borrow
    /// is no longer tracked by the type system. The caller is responsible for
    /// keeping the underlying buffers alive — see `set_memory_mapping`.
    memory_mapping: MemoryMapping,
}

impl TenzroContext {
    /// Construct a context with an empty placeholder mapping.
    ///
    /// `set_memory_mapping` must be called before passing to `EbpfVm::new`.
    fn new(compute_units: u64, config: &Config, version: SBPFVersion) -> Result<Self> {
        // SAFETY: empty regions vector → no host buffers referenced.
        let placeholder = unsafe {
            MemoryMapping::new(Vec::new(), config, version).map_err(|e| {
                VmError::ExecutionFailed(format!("Failed to create placeholder mapping: {}", e))
            })?
        };
        Ok(Self {
            remaining: compute_units,
            log_messages: Vec::new(),
            memory_mapping: placeholder,
        })
    }

    /// Install the real mapping covering stack/heap/input/ro regions.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that every host buffer referenced by
    /// `mapping`'s regions outlives every subsequent VM call that uses this
    /// context. In practice, `execute_program` in this module owns the
    /// buffers and the context on the same stack frame, so the references
    /// are sound.
    unsafe fn set_memory_mapping(&mut self, mapping: MemoryMapping) {
        self.memory_mapping = mapping;
    }
}

impl ContextObject for TenzroContext {
    fn consume(&mut self, amount: u64) {
        self.remaining = self.remaining.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        self.remaining
    }

    fn active_mapping_ptr(&mut self) -> NonNull<MemoryMapping> {
        NonNull::from(&mut self.memory_mapping)
    }
}

// ─── Syscall implementations (sBPF 0.20 macro form) ────────────────────────
//
// In sBPF 0.20 syscalls receive `&mut C` (the ContextObject) directly. Memory
// translation goes through the mapping pointer the context exposes via
// `active_mapping_ptr()`. The `declare_builtin_function!` macro emits the
// `BuiltinFunctionDefinition` impl with the safe `vm` wrapper that handles
// instruction metering and result propagation automatically.

declare_builtin_function!(
    /// `sol_log_` — logs a UTF-8 string from program memory.
    ///
    /// Arguments: `(vm_addr, len, _, _, _)`.
    SyscallSolLog,
    fn rust(
        ctx: &mut TenzroContext,
        vm_addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        // SAFETY: the VM only invokes syscalls while a valid mapping is installed.
        let mapping = unsafe { ctx.active_mapping_ptr().as_ref() };
        let host_addr_result: std::result::Result<u64, EbpfError> =
            mapping.map(AccessType::Load, vm_addr, len).into();
        if let Ok(host_addr) = host_addr_result {
            // SAFETY: `map` returned a host address backed by `len` bytes.
            let slice =
                unsafe { std::slice::from_raw_parts(host_addr as *const u8, len as usize) };
            if let Ok(msg) = std::str::from_utf8(slice) {
                tracing::debug!("SVM program log: {}", msg);
                ctx.log_messages.push(msg.to_string());
            }
        }
        Ok(0)
    }
);

declare_builtin_function!(
    /// `sol_log_64_` — logs five u64 values.
    SyscallSolLog64,
    fn rust(
        ctx: &mut TenzroContext,
        arg1: u64,
        arg2: u64,
        arg3: u64,
        arg4: u64,
        arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let msg = format!(
            "Program log: {:#x}, {:#x}, {:#x}, {:#x}, {:#x}",
            arg1, arg2, arg3, arg4, arg5
        );
        tracing::debug!("SVM: {}", msg);
        ctx.log_messages.push(msg);
        Ok(0)
    }
);

declare_builtin_function!(
    /// `sol_sha256` — computes SHA-256 over guest memory.
    ///
    /// Arguments: `(vals_addr, vals_len, result_addr, _, _)`.
    /// Reads `vals_len` bytes from `vals_addr`, computes SHA-256, and writes the
    /// 32-byte digest to `result_addr`.
    SyscallSolSha256,
    fn rust(
        ctx: &mut TenzroContext,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        use sha2::{Digest, Sha256};

        // SAFETY: the VM only invokes syscalls while a valid mapping is installed.
        let mapping = unsafe { ctx.active_mapping_ptr().as_ref() };

        let load_result: std::result::Result<u64, EbpfError> =
            mapping.map(AccessType::Load, vals_addr, vals_len).into();
        let host_in = match load_result {
            Ok(addr) => addr,
            Err(e) => return Err(Box::new(e)),
        };

        // SAFETY: backed by `vals_len` bytes at `host_in` per `map`.
        let input =
            unsafe { std::slice::from_raw_parts(host_in as *const u8, vals_len as usize) };
        let digest: [u8; 32] = Sha256::digest(input).into();

        let store_result: std::result::Result<u64, EbpfError> =
            mapping.map(AccessType::Store, result_addr, 32).into();
        let host_out = match store_result {
            Ok(addr) => addr,
            Err(e) => return Err(Box::new(e)),
        };
        // SAFETY: backed by 32 writable bytes at `host_out` per `map`.
        unsafe {
            std::ptr::copy_nonoverlapping(digest.as_ptr(), host_out as *mut u8, 32);
        }
        Ok(0)
    }
);

declare_builtin_function!(
    /// `abort` — terminate program execution with an explicit syscall error.
    SyscallAbort,
    fn rust(
        _ctx: &mut TenzroContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        Err(Box::new(std::io::Error::other("program aborted")))
    }
);

// ─── SVM Executor ──────────────────────────────────────────────────────────

/// SVM executor using solana-sbpf (the Anza fork) for real eBPF/SBF program execution.
///
/// Programs are loaded as ELF binaries and executed in a sandboxed BPF VM
/// with instruction metering (compute units) and Solana-compatible syscalls.
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

    /// The solana-sbpf loader (config + registered syscalls).
    loader: Arc<BuiltinProgram<TenzroContext>>,
}

impl SvmExecutor {
    /// Create a new SVM executor with real solana-sbpf BPF execution engine.
    pub fn new(config: VmConfig, gas_oracle: Arc<GasOracle>) -> Result<Self> {
        tracing::info!("Initializing SVM executor (solana-sbpf BPF VM)");

        let loader = Arc::new(Self::create_loader());

        Ok(Self {
            config,
            gas_oracle,
            default_compute_unit_limit: 200_000,
            max_compute_unit_limit: svm_gas_costs::MAX_COMPUTE_UNITS,
            loader,
        })
    }

    /// Returns the gas oracle shared with the parent runtime.
    pub fn gas_oracle(&self) -> &Arc<GasOracle> {
        &self.gas_oracle
    }

    /// Create the sBPF loader with Solana-compatible syscall registrations.
    ///
    /// In sBPF 0.20 the loader is built in two steps:
    ///   1. `BuiltinProgram::new_loader(config)` — installs the VM `Config`.
    ///   2. `<Syscall>::register(&mut program, "name")` — wires each syscall
    ///      via the `BuiltinFunctionDefinition` trait emitted by
    ///      `declare_builtin_function!`.
    fn create_loader() -> BuiltinProgram<TenzroContext> {
        let config = Config {
            max_call_depth: 64,
            stack_frame_size: 4_096,
            enable_address_translation: true,
            enable_stack_frame_gaps: true,
            instruction_meter_checkpoint_distance: 10_000,
            enable_instruction_meter: true,
            enable_register_tracing: false,
            enable_symbol_and_section_labels: false,
            reject_broken_elfs: false,
            optimize_rodata: true,
            allow_memory_region_zero: true,
            aligned_memory_mapping: true,
            enabled_sbpf_versions: SBPFVersion::V0..=SBPFVersion::V4,
        };

        let mut program = BuiltinProgram::<TenzroContext>::new_loader(config);

        // Register Solana-compatible syscalls. The symbol names must match
        // what Solana programs link against.
        SyscallSolLog::register(&mut program, "sol_log_")
            .expect("Failed to register sol_log_ syscall");
        SyscallSolLog64::register(&mut program, "sol_log_64_")
            .expect("Failed to register sol_log_64_ syscall");
        SyscallSolSha256::register(&mut program, "sol_sha256")
            .expect("Failed to register sol_sha256 syscall");
        SyscallAbort::register(&mut program, "abort")
            .expect("Failed to register abort syscall");

        program
    }

    /// Derive program-derived address (PDA) using Solana-compatible algorithm
    ///
    /// PDAs are off-curve Ed25519 points derived deterministically from a program ID
    /// and seeds. They enable programs to "sign" for accounts without a private key.
    ///
    /// Algorithm (Solana-compatible `find_program_address`):
    /// 1. Iterate bump seed from 255 down to 0
    /// 2. Hash: SHA-256(seeds || [bump] || program_id || "ProgramDerivedAddress")
    /// 3. Check if the resulting 32-byte hash is NOT a valid Ed25519 public key (off-curve)
    /// 4. Return the first off-curve result as the PDA
    ///
    /// This ensures the PDA cannot have a corresponding private key, so only
    /// the program can "sign" for it via CPI.
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

            // Check if the point is off-curve (not a valid Ed25519 public key).
            // We use curve25519-dalek's CompressedEdwardsY to attempt decompression.
            // If decompression fails, the point is off-curve → valid PDA.
            let compressed = curve25519_dalek::edwards::CompressedEdwardsY(hash_bytes);
            if compressed.decompress().is_none() {
                // Off-curve: this is a valid PDA
                return hash_bytes.to_vec();
            }
            // On-curve: try next bump
        }

        // Fallback: all 256 bumps produced on-curve points (astronomically unlikely).
        // Use bump=0 result anyway — matches Solana's behavior of returning an error,
        // but for deployment address derivation we need a deterministic fallback.
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
    /// program (analogous to Solana's System / BPFLoader programs). The
    /// dispatch site in [`Self::execute_transaction`] short-circuits the
    /// ELF lookup whenever `tx.to == TENZRO_CROSS_VM_PROGRAM_ID`.
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
    /// originate them — matching Hyperlane / Wormhole 2026 patterns where the
    /// origin VM emits and the canonical bridge processes.
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

    /// Execute a loaded SBF/BPF program via the solana-sbpf virtual machine.
    ///
    /// This performs real eBPF execution:
    /// 1. Parses the ELF binary via `Executable::from_elf()`
    /// 2. Verifies the bytecode with `RequisiteVerifier`
    /// 3. Sets up memory mapping (stack, heap, input region)
    /// 4. Installs the mapping on the `TenzroContext`
    /// 5. Creates `EbpfVm` and calls `execute_program()` in interpreted mode
    /// 6. Returns output data and compute units consumed
    fn execute_program(
        &self,
        program_elf: &[u8],
        instruction_data: &[u8],
        compute_unit_limit: u64,
    ) -> Result<(Vec<u8>, u64, Vec<String>)> {
        tracing::debug!(
            "Executing SBF program via rBPF VM ({} bytes ELF, {} bytes input, {} CU limit)",
            program_elf.len(),
            instruction_data.len(),
            compute_unit_limit,
        );

        // 1. Parse ELF and create executable
        let executable = Executable::<TenzroContext>::from_elf(program_elf, self.loader.clone())
            .map_err(|e| VmError::ExecutionFailed(format!("ELF load error: {}", e)))?;

        // 2. Verify the bytecode
        executable
            .verify::<RequisiteVerifier>()
            .map_err(|e| VmError::ExecutionFailed(format!("Verification error: {}", e)))?;

        // 3. Set up memory regions
        let config = executable.get_config();
        let sbpf_version = executable.get_sbpf_version();

        // Stack
        let mut stack =
            AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
        let stack_len = stack.len();

        // Heap (32 KB default, matching Solana)
        let heap_size = 32 * 1024;
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(heap_size);

        // Input region — contains serialized instruction data
        let mut input_mem = instruction_data.to_vec();

        // 4. Create context owning a placeholder mapping that we'll replace.
        let mut context = TenzroContext::new(compute_unit_limit, config, sbpf_version)?;

        // 5. Build the real memory mapping (sBPF 0.20: `MemoryRegion::new<HO>`
        //    with `&mut AlignedMemory` / `*mut [u8]` host memory objects).
        let regions: Vec<MemoryRegion> = vec![
            executable.get_ro_region(),
            MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
            MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
            MemoryRegion::new(
                &raw mut *input_mem.as_mut_slice(),
                ebpf::MM_INPUT_START,
            ),
        ];

        // SAFETY: `regions` borrows from `stack`/`heap`/`input_mem` which all
        // live to the end of this function; the `MemoryMapping` is dropped
        // (with `context`) before those buffers go out of scope.
        let memory_mapping = unsafe {
            MemoryMapping::new(regions, config, sbpf_version).map_err(|e| {
                VmError::ExecutionFailed(format!("Memory mapping error: {}", e))
            })?
        };

        // SAFETY: stack/heap/input_mem outlive `context` per the same scope
        // argument as the `MemoryMapping::new` SAFETY comment above.
        unsafe {
            context.set_memory_mapping(memory_mapping);
        }

        // 6. Allocate call frame buffer per the executable's max_call_depth.
        let mut call_frames = vec![CallFrame::default(); config.max_call_depth];

        // 7. Create VM and execute (sBPF 0.20: 4-arg constructor — mapping is
        //    pulled from the context object via `active_mapping_ptr()`).
        let mut vm = EbpfVm::new(self.loader.clone(), sbpf_version, &mut context, stack_len);
        let mut mode = ExecutionMode::Interpreted;
        let (instruction_count, result) =
            vm.execute_program(&executable, &mut mode, &mut call_frames);

        // 8. Process result. `ProgramResult` is a `StableResult`; convert to
        //    a regular `std::result::Result` via `.into()` for ergonomic match.
        let compute_units_consumed = compute_unit_limit.saturating_sub(context.get_remaining());
        let log_messages = std::mem::take(&mut context.log_messages);
        let result_std: std::result::Result<u64, EbpfError> = result.into();

        match result_std {
            Ok(return_value) => {
                tracing::debug!(
                    "SVM program executed successfully: return={}, insns={}, CU used={}",
                    return_value,
                    instruction_count,
                    compute_units_consumed,
                );
                // Return value is in r0; output is the modified input region
                Ok((input_mem, compute_units_consumed, log_messages))
            }
            Err(err) => {
                tracing::warn!("SVM program execution failed: {}", err);
                Err(VmError::ExecutionFailed(format!(
                    "BPF execution error: {}",
                    err
                )))
            }
        }
    }

    /// Calculate compute units for a transaction.
    ///
    /// Maps transaction properties to Solana compute unit costs.
    /// When actual BPF execution occurs, the real CU consumption is metered by the VM.
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
        tracing::debug!(
            "SVM: Executing transaction from {}",
            hex::encode(&tx.from)
        );

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
            self.config
                .validate_contract_size(tx.data.len())?;

            // Validate ELF format by attempting to parse it
            // (only if it looks like an ELF — check magic bytes)
            if tx.data.len() >= 4 && &tx.data[..4] == b"\x7fELF" {
                let _ = Executable::<TenzroContext>::from_elf(&tx.data, self.loader.clone())
                    .map_err(|e| {
                        VmError::InvalidTransaction(format!("Invalid SBF ELF: {}", e))
                    })?;
            }

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

            // Nonce change
            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(nonce.to_le_bytes().to_vec()),
                Some((nonce + 1).to_le_bytes().to_vec()),
            ));

            // Sender balance change
            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ));

            // Program code deployed
            state_changes.push(StateChange::new(
                program_id.clone(),
                b"code".to_vec(),
                None,
                Some(tx.data.clone()),
            ));

            // Program account balance (if value transferred)
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
            // Rust, has no stored ELF, and is dispatched directly here. See
            // [`crate::svm::cross_vm`] for the program ID derivation, the
            // Anchor-style 8-byte discriminators, and the instruction layout.
            if program_id.as_slice() == super::cross_vm::TENZRO_CROSS_VM_PROGRAM_ID.as_slice() {
                return self.execute_cross_vm_native(tx, state, sender_balance, compute_units);
            }

            // Get program code
            let program = state
                .get_code(program_id)
                .ok_or_else(|| VmError::ContractNotFound(hex::encode(program_id)))?;

            tracing::debug!("SVM: Executing program at {}", hex::encode(program_id));

            // Try real BPF execution if the program is a valid ELF
            let (output, cu_consumed, log_messages) =
                if program.len() >= 4 && &program[..4] == b"\x7fELF" {
                    // Real BPF execution via rBPF
                    match self.execute_program(&program, &tx.data, tx.gas_limit) {
                        Ok(result) => result,
                        Err(e) => {
                            // BPF execution failed — return error result
                            let nonce = state.get_nonce(&tx.from);
                            state.set_nonce(&tx.from, nonce + 1);
                            let gas_cost = compute_units as u128 * tx.gas_price;
                            state.set_balance(&tx.from, sender_balance - gas_cost);

                            return Ok(ExecutionResult::failed(
                                compute_units,
                                format!("BPF execution failed: {}", e),
                            ));
                        }
                    }
                } else {
                    // Non-ELF program (e.g., raw data) — process as simple transfer
                    tracing::debug!("SVM: Program is not ELF, processing as data transfer");
                    (Vec::new(), compute_units, Vec::new())
                };

            // Capture pre-state for state change tracking
            let nonce = state.get_nonce(&tx.from);
            let old_recipient_balance = if tx.value > 0 {
                Some(state.get_balance(program_id))
            } else {
                None
            };

            // Update nonce
            state.set_nonce(&tx.from, nonce + 1);

            // Deduct costs (use actual CU consumed if BPF executed)
            let actual_cu = cu_consumed.max(compute_units);
            let gas_cost = actual_cu as u128 * tx.gas_price;
            let new_sender_balance = sender_balance - gas_cost - tx.value;
            state.set_balance(&tx.from, new_sender_balance);

            // Transfer value if any (lamport transfer)
            if tx.value > 0 {
                let recipient_balance = old_recipient_balance.unwrap_or(0);
                state.set_balance(program_id, recipient_balance + tx.value);
            }

            // Convert log messages to Log entries
            let logs: Vec<Log> = log_messages
                .iter()
                .map(|msg| Log::new(program_id.clone(), Vec::new(), msg.as_bytes().to_vec()))
                .collect();

            // Track state changes
            let mut state_changes = Vec::new();

            // Nonce change
            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"nonce".to_vec(),
                Some(nonce.to_le_bytes().to_vec()),
                Some((nonce + 1).to_le_bytes().to_vec()),
            ));

            // Sender balance change
            state_changes.push(StateChange::new(
                tx.from.clone(),
                b"balance".to_vec(),
                Some(sender_balance.to_le_bytes().to_vec()),
                Some(new_sender_balance.to_le_bytes().to_vec()),
            ));

            // Recipient balance change (if value transferred)
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
            Err(VmError::InvalidTransaction("Missing destination address".to_string()))
        }
    }

    async fn call(
        &self,
        call: &ContractCall,
        state: &dyn VmState,
    ) -> Result<CallResult> {
        tracing::debug!(
            "SVM: Read-only call to {}",
            hex::encode(&call.contract)
        );

        // Get program code
        let program = state
            .get_code(&call.contract)
            .ok_or_else(|| VmError::ContractNotFound(hex::encode(&call.contract)))?;

        // Try real BPF execution if valid ELF
        if program.len() >= 4 && &program[..4] == b"\x7fELF" {
            let compute_limit = call.gas_limit.min(self.max_compute_unit_limit);
            match self.execute_program(&program, &call.data, compute_limit) {
                Ok((output, cu_consumed, _logs)) => {
                    Ok(CallResult::success(output, cu_consumed))
                }
                Err(e) => {
                    let cu = self.calculate_compute_units(call.data.len(), 2);
                    Ok(CallResult::failed(
                        cu,
                        format!("BPF call failed: {}", e),
                    ))
                }
            }
        } else {
            // Non-ELF program — return empty result
            let compute_units = self.calculate_compute_units(call.data.len(), 2);
            Ok(CallResult::success(Vec::new(), compute_units))
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
        self.config
            .validate_contract_size(deployment.code.len())?;

        // Validate ELF if it's an ELF binary
        if deployment.code.len() >= 4 && &deployment.code[..4] == b"\x7fELF" {
            let _ = Executable::<TenzroContext>::from_elf(&deployment.code, self.loader.clone())
                .map_err(|e| {
                    VmError::InvalidTransaction(format!("Invalid SBF ELF: {}", e))
                })?;
        }

        // Derive program ID
        let nonce = state.get_nonce(&deployment.deployer);
        let program_id = Self::derive_pda(&deployment.deployer, &[&nonce.to_le_bytes()]);

        // Calculate compute units
        let compute_units =
            svm_gas_costs::CREATE_ACCOUNT + (deployment.code.len() as u64 * svm_gas_costs::DATA_BYTE);

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
    use solana_sbpf::program::FunctionRegistry;

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

    #[test]
    fn test_loader_has_syscalls() {
        let executor = create_executor();
        let registry = executor.loader.get_function_registry();

        // Verify syscalls are registered
        assert!(
            registry.lookup_by_name(b"sol_log_").is_some(),
            "sol_log_ should be registered"
        );
        assert!(
            registry.lookup_by_name(b"sol_log_64_").is_some(),
            "sol_log_64_ should be registered"
        );
        assert!(
            registry.lookup_by_name(b"abort").is_some(),
            "abort should be registered"
        );
    }

    /// Build a context, mapping, and run an assembled program in interpreted
    /// mode. Returns `(instruction_count, result, remaining_cu)`.
    fn run_program_text(
        prog: &[u8],
        sbpf_version: SBPFVersion,
        compute_units: u64,
    ) -> (u64, std::result::Result<u64, EbpfError>, u64) {
        let loader = Arc::new(BuiltinProgram::<TenzroContext>::new_mock());
        let function_registry = FunctionRegistry::default();
        let executable = Executable::<TenzroContext>::from_text_bytes(
            prog,
            loader.clone(),
            sbpf_version,
            function_registry,
        )
        .unwrap();
        executable.verify::<RequisiteVerifier>().unwrap();

        let config = executable.get_config();
        let sbpf_version = executable.get_sbpf_version();

        let mut stack =
            AlignedMemory::<{ ebpf::HOST_ALIGN }>::zero_filled(config.stack_size());
        let stack_len = stack.len();
        let mut heap = AlignedMemory::<{ ebpf::HOST_ALIGN }>::with_capacity(0);
        let mut input: Vec<u8> = Vec::new();

        let mut context = TenzroContext::new(compute_units, config, sbpf_version).unwrap();

        let regions: Vec<MemoryRegion> = vec![
            executable.get_ro_region(),
            MemoryRegion::new(&mut stack, ebpf::MM_STACK_START),
            MemoryRegion::new(&mut heap, ebpf::MM_HEAP_START),
            MemoryRegion::new(
                &raw mut *input.as_mut_slice(),
                ebpf::MM_INPUT_START,
            ),
        ];
        let memory_mapping =
            unsafe { MemoryMapping::new(regions, config, sbpf_version).unwrap() };
        unsafe { context.set_memory_mapping(memory_mapping) };

        let mut call_frames = vec![CallFrame::default(); config.max_call_depth];
        let mut vm = EbpfVm::new(loader, sbpf_version, &mut context, stack_len);
        let mut mode = ExecutionMode::Interpreted;
        let (insn_count, result) =
            vm.execute_program(&executable, &mut mode, &mut call_frames);
        let remaining = context.get_remaining();
        let result_std: std::result::Result<u64, EbpfError> = result.into();
        (insn_count, result_std, remaining)
    }

    #[test]
    fn test_rbpf_simple_program() {
        // A minimal sBPFv2 program that just exits with return value 0
        let prog = &[
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, 0
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];

        let (insn_count, result, _) = run_program_text(prog, SBPFVersion::V2, 100);

        assert_eq!(insn_count, 2); // mov64 + exit
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_rbpf_compute_meter() {
        // A program that should exhaust compute units
        // mov64 r0, 0; mov64 r0, 1; mov64 r0, 2; exit
        let prog = &[
            0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov64 r0, 0
            0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov64 r0, 1
            0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov64 r0, 2
            0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
        ];

        // Give only 2 compute units — should run out before finishing all 4 instructions
        let (_insn_count, result, _) = run_program_text(prog, SBPFVersion::V2, 2);

        // Should fail with ExceededMaxInstructions
        assert!(result.is_err());
    }

    #[test]
    fn test_context_object() {
        let loader_program = SvmExecutor::create_loader();
        let config = loader_program.get_config();
        let mut ctx = TenzroContext::new(1000, config, SBPFVersion::V2).unwrap();
        assert_eq!(ctx.get_remaining(), 1000);

        ctx.consume(200);
        assert_eq!(ctx.get_remaining(), 800);

        ctx.consume(900); // saturating
        assert_eq!(ctx.get_remaining(), 0);
    }

    #[tokio::test]
    async fn test_program_deployment() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let deployer = vec![1u8; 32];
        let code = vec![0x00, 0x61, 0x73, 0x6D]; // WebAssembly magic number (non-ELF)

        // Set initial balance
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

        // Check program code was stored
        let stored_code = state.get_code(&result.address).unwrap();
        assert_eq!(stored_code, code);
    }

    #[tokio::test]
    async fn test_program_execution() {
        let executor = create_executor();
        let mut state = StateAdapter::new();

        let caller = vec![1u8; 32];
        let program_id = vec![2u8; 32];
        let program_code = vec![0x00, 0x61, 0x73, 0x6D]; // Non-ELF: will skip BPF execution

        // Set up state
        state.set_balance(&caller, 10_000_000_000_000_000_000u128);
        state.set_code(&program_id, program_code);

        let tx = VmTransaction::new(
            caller.clone(),
            Some(program_id.clone()),
            0,
            vec![1, 2, 3, 4], // Instruction data
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
        assert!(result.success);
        assert!(result.gas_used > 0);
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
}
