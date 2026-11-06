//! Tenzro precompiles inside revm.
//!
//! revm's own precompile interface hands a precompile its input and gas limit
//! but not `msg.sender`, `msg.value` or the static flag, and Tenzro
//! precompiles need all three: the NFT factory must know who is transferring,
//! the wTNZO pointer must know whose balance to debit, and nothing may write
//! under `STATICCALL`. So this module replaces revm's call handler: a call
//! whose code address is a registered Tenzro precompile is served here, with
//! the call frame's real caller, value and static flag, and every state access
//! goes through revm's journal. A reverted frame therefore reverts whatever the
//! precompile wrote, and a read-only `eth_call` (which never commits the
//! journal) can never persist anything.
//!
//! Every other call falls through to revm's stock handler, which still serves
//! the standard Ethereum precompiles.

use std::sync::Arc;

use revm::{
    Context, Database, FrameOrResult,
    handler::register::EvmHandler,
    interpreter::{CallInputs, CallValue, Gas, InstructionResult, InterpreterResult},
    primitives::{Address as RevmAddress, Bytes, EVMError, U256},
};
use sha3::{Digest, Keccak256};

use crate::error::{Result, VmError};
use crate::precompiles::{PrecompileRegistry, PrecompileResult};

/// Gas charged for each storage slot a Tenzro precompile reads.
pub const PRECOMPILE_SLOAD_GAS: u64 = 2_100;
/// Gas charged for each storage slot a Tenzro precompile writes.
pub const PRECOMPILE_SSTORE_GAS: u64 = 5_000;
/// Gas charged for a balance read or a balance move.
pub const PRECOMPILE_BALANCE_GAS: u64 = 2_600;

/// The call frame a Tenzro precompile runs in.
#[derive(Debug, Clone, Copy)]
pub struct PrecompileEnv {
    /// The precompile's own address.
    pub address: [u8; 20],
    /// `msg.sender` of the frame that called the precompile.
    pub caller: [u8; 20],
    /// `msg.value` of the call. It has already been moved from `caller` to
    /// `address` when the precompile runs.
    pub value: u128,
    /// Called through `STATICCALL`, or from inside a static frame.
    pub is_static: bool,
    /// Called from the read-only `eth_call` path.
    pub read_only: bool,
    /// Height of the block being executed (0 outside block execution).
    pub block_number: u64,
    /// Timestamp of the block being executed, in Unix seconds.
    pub block_timestamp: u64,
}

impl PrecompileEnv {
    /// Whether this call may change state.
    pub fn can_write(&self) -> bool {
        !self.is_static && !self.read_only
    }
}

/// State access for a Tenzro precompile. Every method charges gas against the
/// call's limit and fails with [`VmError::OutOfGas`] once it is exhausted.
pub trait PrecompileState {
    /// Read a storage slot of `address`.
    fn sload(&mut self, address: [u8; 20], key: [u8; 32]) -> Result<[u8; 32]>;
    /// Write a storage slot of `address`.
    fn sstore(&mut self, address: [u8; 20], key: [u8; 32], value: [u8; 32]) -> Result<()>;
    /// Native TNZO balance of `address`.
    fn balance(&mut self, address: [u8; 20]) -> Result<u128>;
    /// Move native TNZO between two accounts. Returns `false` and moves
    /// nothing when `from` holds less than `amount`.
    fn transfer(&mut self, from: [u8; 20], to: [u8; 20], amount: u128) -> Result<bool>;
    /// Hash of a finalized block, or zero when it is unknown.
    fn block_hash(&mut self, number: u64) -> Result<[u8; 32]>;
    /// Native TNZO total supply as last committed.
    fn native_total_supply(&mut self) -> Result<u128>;
    /// A system-storage entry (identities, Terms) as last committed. The EVM
    /// never writes system storage, so the committed value is current.
    fn system_storage(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    /// Emit an EVM log from `address`.
    fn emit_log(&mut self, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<()>;
    /// Gas charged so far by state access and [`PrecompileCall::charge`].
    fn gas_used(&self) -> u64;
    /// Charge `gas` against the call's limit.
    fn charge(&mut self, gas: u64) -> Result<()>;
}

/// One invocation of a Tenzro precompile.
pub struct PrecompileCall<'a> {
    /// Calldata.
    pub input: &'a [u8],
    /// Gas available to the call.
    pub gas_limit: u64,
    /// Caller, value, static flag and block context.
    pub env: PrecompileEnv,
    /// Journaled state.
    pub state: &'a mut dyn PrecompileState,
}

impl PrecompileCall<'_> {
    /// Charge `gas` against the call's limit.
    pub fn charge(&mut self, gas: u64) -> Result<()> {
        self.state.charge(gas)
    }

    /// Gas charged so far.
    pub fn gas_used(&self) -> u64 {
        self.state.gas_used()
    }

    /// Fails unless the call may change state.
    pub fn require_write(&self) -> Result<()> {
        if self.env.can_write() {
            Ok(())
        } else {
            Err(VmError::PrecompileFailed(
                "state-changing precompile call in a static or read-only context".to_string(),
            ))
        }
    }

    /// Emit a log from the precompile's address.
    pub fn emit(&mut self, topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<()> {
        let address = self.env.address;
        self.state.emit_log(address, topics, data)
    }

    /// Read a slot of the precompile's own storage.
    pub fn sload(&mut self, key: [u8; 32]) -> Result<[u8; 32]> {
        let address = self.env.address;
        self.state.sload(address, key)
    }

    /// Write a slot of the precompile's own storage.
    pub fn sstore(&mut self, key: [u8; 32], value: [u8; 32]) -> Result<()> {
        self.require_write()?;
        let address = self.env.address;
        self.state.sstore(address, key, value)
    }

    /// Read a u128 held in the low 16 bytes of a slot.
    pub fn sload_u128(&mut self, key: [u8; 32]) -> Result<u128> {
        let word = self.sload(key)?;
        Ok(word_to_u128(&word))
    }

    /// Write a u128 into the low 16 bytes of a slot.
    pub fn sstore_u128(&mut self, key: [u8; 32], value: u128) -> Result<()> {
        self.sstore(key, u128_to_word(value))
    }

    /// Read a variable-length value stored with [`Self::write_blob`].
    /// Returns `None` when nothing is stored under `key`.
    pub fn read_blob(&mut self, key: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let header = self.sload(key)?;
        let marked_len = word_to_u128(&header);
        if marked_len == 0 {
            return Ok(None);
        }
        let len = usize::try_from(marked_len - 1)
            .map_err(|_| VmError::PrecompileFailed("stored blob length overflow".to_string()))?;
        let mut out = Vec::with_capacity(len);
        let base = blob_data_base(&key);
        let words = len.div_ceil(32);
        for i in 0..words {
            let word = self.sload(slot_offset(&base, i as u64))?;
            let take = (len - i * 32).min(32);
            out.extend_from_slice(&word[..take]);
        }
        Ok(Some(out))
    }

    /// Store a variable-length value under `key`: the length (plus one, so
    /// an empty value is distinguishable from absence) in the key's slot and
    /// the bytes in consecutive slots starting at `keccak(key)`.
    pub fn write_blob(&mut self, key: [u8; 32], value: &[u8]) -> Result<()> {
        self.require_write()?;
        let previous_words = {
            let header = self.sload(key)?;
            let marked_len = word_to_u128(&header);
            if marked_len == 0 {
                0
            } else {
                ((marked_len - 1) as usize).div_ceil(32)
            }
        };
        self.sstore_u128(key, value.len() as u128 + 1)?;
        let base = blob_data_base(&key);
        let words = value.len().div_ceil(32);
        for i in 0..words {
            let mut word = [0u8; 32];
            let start = i * 32;
            let end = (start + 32).min(value.len());
            word[..end - start].copy_from_slice(&value[start..end]);
            self.sstore(slot_offset(&base, i as u64), word)?;
        }
        for i in words..previous_words {
            self.sstore(slot_offset(&base, i as u64), [0u8; 32])?;
        }
        Ok(())
    }
}

/// Storage key for a named field: `keccak256(tag || parts...)`.
pub fn slot_key(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update((tag.len() as u32).to_be_bytes());
    h.update(tag);
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn blob_data_base(key: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(key));
    out
}

fn slot_offset(base: &[u8; 32], i: u64) -> [u8; 32] {
    let v = U256::from_be_bytes(*base).wrapping_add(U256::from(i));
    v.to_be_bytes::<32>()
}

/// A storage word of `address` read straight from VM state, for the views
/// of a precompile's ledger that other VMs serve.
pub fn state_word(
    state: &dyn crate::traits::VmState,
    address: &[u8; 20],
    key: &[u8; 32],
) -> [u8; 32] {
    state
        .get_storage(address, key)
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .unwrap_or([0u8; 32])
}

/// A blob stored with [`PrecompileCall::write_blob`], read one word at a
/// time through `word`.
pub fn blob_via(
    mut word: impl FnMut(&[u8; 32]) -> Result<[u8; 32]>,
    key: [u8; 32],
) -> Result<Option<Vec<u8>>> {
    let marked_len = word_to_u128(&word(&key)?);
    if marked_len == 0 {
        return Ok(None);
    }
    let len = usize::try_from(marked_len - 1)
        .map_err(|_| VmError::PrecompileFailed("stored blob length overflow".to_string()))?;
    let base = blob_data_base(&key);
    let mut out = Vec::with_capacity(len);
    for i in 0..len.div_ceil(32) {
        let w = word(&slot_offset(&base, i as u64))?;
        out.extend_from_slice(&w[..(len - i * 32).min(32)]);
    }
    Ok(Some(out))
}

/// [`PrecompileCall::read_blob`] over VM state.
pub fn state_blob(
    state: &dyn crate::traits::VmState,
    address: &[u8; 20],
    key: [u8; 32],
) -> Option<Vec<u8>> {
    let marked_len = word_to_u128(&state_word(state, address, &key));
    if marked_len == 0 {
        return None;
    }
    let len = usize::try_from(marked_len - 1).ok()?;
    let base = blob_data_base(&key);
    let mut out = Vec::with_capacity(len);
    for i in 0..len.div_ceil(32) {
        let word = state_word(state, address, &slot_offset(&base, i as u64));
        out.extend_from_slice(&word[..(len - i * 32).min(32)]);
    }
    Some(out)
}

/// [`PrecompileCall::write_blob`] over VM state, for native transactions
/// that write a precompile's records.
pub fn state_write_blob(
    state: &mut dyn crate::traits::VmState,
    address: &[u8; 20],
    key: [u8; 32],
    value: &[u8],
) {
    let previous_words = match word_to_u128(&state_word(state, address, &key)) {
        0 => 0,
        marked_len => ((marked_len - 1) as usize).div_ceil(32),
    };
    state.set_storage(
        address,
        &key,
        u128_to_word(value.len() as u128 + 1).to_vec(),
    );
    let base = blob_data_base(&key);
    let words = value.len().div_ceil(32);
    for i in 0..words {
        let mut word = [0u8; 32];
        let start = i * 32;
        let end = (start + 32).min(value.len());
        word[..end - start].copy_from_slice(&value[start..end]);
        state.set_storage(address, &slot_offset(&base, i as u64), word.to_vec());
    }
    for i in words..previous_words {
        state.set_storage(address, &slot_offset(&base, i as u64), [0u8; 32].to_vec());
    }
}

/// Big-endian 32-byte word to u128 (low 16 bytes; high bytes must be zero to
/// be meaningful and are ignored here).
pub fn word_to_u128(word: &[u8; 32]) -> u128 {
    let mut b = [0u8; 16];
    b.copy_from_slice(&word[16..]);
    u128::from_be_bytes(b)
}

/// u128 to a big-endian 32-byte word.
pub fn u128_to_word(v: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&v.to_be_bytes());
    out
}

/// Committed native state precompiles read: the native total supply (the
/// wTNZO pointer's `totalSupply()`) and system storage (the token rule
/// engine's identity and Terms lookups). Implemented by the revm database
/// adapter.
pub trait NativeSupplySource {
    /// Native TNZO total supply as last committed.
    fn native_total_supply(&mut self) -> std::result::Result<u128, String>;
    /// A system-storage entry as last committed.
    fn system_storage(&mut self, key: &[u8]) -> Option<Vec<u8>>;
}

impl<T: NativeSupplySource + ?Sized> NativeSupplySource for &mut T {
    fn native_total_supply(&mut self) -> std::result::Result<u128, String> {
        (**self).native_total_supply()
    }
    fn system_storage(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        (**self).system_storage(key)
    }
}

/// [`PrecompileState`] over revm's journal.
struct JournalState<'c, EXT, DB: Database> {
    ctx: &'c mut Context<EXT, DB>,
    gas_limit: u64,
    gas_used: u64,
}

fn db_err<E: std::fmt::Debug>(e: EVMError<E>) -> VmError {
    VmError::Internal(format!("state access failed in precompile: {:?}", e))
}

impl<EXT, DB> PrecompileState for JournalState<'_, EXT, DB>
where
    DB: Database + NativeSupplySource,
    DB::Error: std::fmt::Debug,
{
    fn sload(&mut self, address: [u8; 20], key: [u8; 32]) -> Result<[u8; 32]> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        let addr = RevmAddress::from(address);
        self.ctx.evm.inner.load_account(addr).map_err(db_err)?;
        let v = self
            .ctx
            .evm
            .inner
            .sload(addr, U256::from_be_bytes(key))
            .map_err(db_err)?;
        Ok(v.data.to_be_bytes::<32>())
    }

    fn sstore(&mut self, address: [u8; 20], key: [u8; 32], value: [u8; 32]) -> Result<()> {
        self.charge(PRECOMPILE_SSTORE_GAS)?;
        let addr = RevmAddress::from(address);
        self.ctx.evm.inner.load_account(addr).map_err(db_err)?;
        self.ctx.evm.inner.touch(&addr);
        self.ctx
            .evm
            .inner
            .sstore(addr, U256::from_be_bytes(key), U256::from_be_bytes(value))
            .map_err(db_err)?;
        Ok(())
    }

    fn balance(&mut self, address: [u8; 20]) -> Result<u128> {
        self.charge(PRECOMPILE_BALANCE_GAS)?;
        let v = self
            .ctx
            .evm
            .inner
            .balance(RevmAddress::from(address))
            .map_err(db_err)?;
        u128::try_from(v.data).map_err(|_| VmError::Internal("balance exceeds u128".to_string()))
    }

    fn transfer(&mut self, from: [u8; 20], to: [u8; 20], amount: u128) -> Result<bool> {
        self.charge(PRECOMPILE_BALANCE_GAS)?;
        let inner = &mut self.ctx.evm.inner;
        let outcome = inner
            .journaled_state
            .transfer(
                &RevmAddress::from(from),
                &RevmAddress::from(to),
                U256::from(amount),
                &mut inner.db,
            )
            .map_err(db_err)?;
        Ok(outcome.is_none())
    }

    fn block_hash(&mut self, number: u64) -> Result<[u8; 32]> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        let h = self.ctx.evm.inner.block_hash(number).map_err(db_err)?;
        Ok(h.0)
    }

    fn native_total_supply(&mut self) -> Result<u128> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        self.ctx
            .evm
            .inner
            .db
            .native_total_supply()
            .map_err(VmError::Internal)
    }

    fn system_storage(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        Ok(self.ctx.evm.inner.db.system_storage(key))
    }

    fn emit_log(&mut self, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<()> {
        self.charge(375u64.saturating_add(375u64.saturating_mul(topics.len() as u64)))?;
        self.charge(8u64.saturating_mul(data.len() as u64))?;
        let log = revm::primitives::Log::new_unchecked(
            RevmAddress::from(address),
            topics
                .into_iter()
                .map(revm::primitives::B256::from)
                .collect(),
            Bytes::from(data),
        );
        self.ctx.evm.inner.journaled_state.log(log);
        Ok(())
    }

    fn gas_used(&self) -> u64 {
        self.gas_used
    }

    fn charge(&mut self, gas: u64) -> Result<()> {
        let next = self.gas_used.saturating_add(gas);
        if next > self.gas_limit {
            self.gas_used = self.gas_limit;
            return Err(VmError::OutOfGas);
        }
        self.gas_used = next;
        Ok(())
    }
}

/// Context the executor supplies to every Tenzro precompile call.
#[derive(Debug, Clone, Copy)]
pub struct HostContext {
    /// The call comes from the read-only `eth_call` path.
    pub read_only: bool,
}

/// Install the Tenzro precompile call handler into an EVM handler.
pub fn register_tenzro_precompiles<EXT, DB>(
    handler: &mut EvmHandler<'_, EXT, DB>,
    registry: Arc<PrecompileRegistry>,
    host: HostContext,
) where
    DB: Database + NativeSupplySource,
    DB::Error: std::fmt::Debug,
{
    let previous = handler.execution.call.clone();
    handler.execution.call = Arc::new(move |ctx, inputs: Box<CallInputs>| {
        let code_address: [u8; 20] = inputs.bytecode_address.into_array();
        match registry.get(&code_address) {
            Some(precompile) => {
                let stateless = registry.is_stateless(&code_address);
                run_precompile(ctx, &inputs, &precompile, code_address, stateless, host)
            }
            None => previous(ctx, inputs),
        }
    });
    // Fees are settled by the node in-block from what the sender paid, so
    // nothing is credited to a block beneficiary here: the sender's debit is
    // the whole of the fee.
    handler.post_execution.reward_beneficiary = Arc::new(|_ctx, _gas| Ok(()));
}

fn call_result(
    inputs: &CallInputs,
    result: InstructionResult,
    gas: Gas,
    output: Bytes,
) -> FrameOrResult {
    FrameOrResult::new_call_result(
        InterpreterResult {
            result,
            gas,
            output,
        },
        inputs.return_memory_offset.clone(),
    )
}

fn run_precompile<EXT, DB>(
    ctx: &mut Context<EXT, DB>,
    inputs: &CallInputs,
    precompile: &crate::precompiles::PrecompileFn,
    code_address: [u8; 20],
    stateless: bool,
    host: HostContext,
) -> std::result::Result<FrameOrResult, EVMError<DB::Error>>
where
    DB: Database + NativeSupplySource,
    DB::Error: std::fmt::Debug,
{
    let mut gas = Gas::new(inputs.gas_limit);

    // A precompile's storage belongs to the precompile. DELEGATECALL and
    // CALLCODE would run it against the caller's storage and balance, which
    // no stateful Tenzro precompile is written for. A stateless one (such as
    // P256VERIFY) answers every call type alike, as Ethereum's precompiles do.
    if inputs.target_address != inputs.bytecode_address && !stateless {
        return Ok(call_result(
            inputs,
            InstructionResult::Revert,
            gas,
            Bytes::new(),
        ));
    }

    let checkpoint = ctx.evm.journaled_state.checkpoint();

    let value: u128 = match inputs.value {
        CallValue::Transfer(v) if !v.is_zero() => {
            let Ok(amount) = u128::try_from(v) else {
                ctx.evm.journaled_state.checkpoint_revert(checkpoint);
                return Ok(call_result(
                    inputs,
                    InstructionResult::Revert,
                    gas,
                    Bytes::new(),
                ));
            };
            let inner = &mut ctx.evm.inner;
            if let Some(fail) = inner.journaled_state.transfer(
                &inputs.caller,
                &inputs.target_address,
                v,
                &mut inner.db,
            )? {
                ctx.evm.journaled_state.checkpoint_revert(checkpoint);
                return Ok(call_result(inputs, fail, gas, Bytes::new()));
            }
            amount
        }
        _ => 0,
    };

    let env = PrecompileEnv {
        address: code_address,
        caller: inputs.caller.into_array(),
        value,
        is_static: inputs.is_static,
        read_only: host.read_only,
        block_number: u64::try_from(ctx.evm.env.block.number).unwrap_or(u64::MAX),
        block_timestamp: u64::try_from(ctx.evm.env.block.timestamp).unwrap_or(u64::MAX),
    };

    let (outcome, gas_used) = {
        let mut state = JournalState {
            ctx: &mut *ctx,
            gas_limit: inputs.gas_limit,
            gas_used: 0,
        };
        let mut call = PrecompileCall {
            input: &inputs.input,
            gas_limit: inputs.gas_limit,
            env,
            state: &mut state,
        };
        let outcome = precompile(&mut call);
        let charged = state.gas_used;
        (outcome, charged)
    };

    match outcome {
        Ok(PrecompileResult {
            output,
            gas_used: own_gas,
            success,
        }) => {
            let total = gas_used.saturating_add(own_gas);
            if !gas.record_cost(total) {
                ctx.evm.journaled_state.checkpoint_revert(checkpoint);
                return Ok(call_result(
                    inputs,
                    InstructionResult::PrecompileOOG,
                    Gas::new_spent(inputs.gas_limit),
                    Bytes::new(),
                ));
            }
            if success {
                ctx.evm.journaled_state.checkpoint_commit();
                Ok(call_result(
                    inputs,
                    InstructionResult::Return,
                    gas,
                    Bytes::from(output),
                ))
            } else {
                ctx.evm.journaled_state.checkpoint_revert(checkpoint);
                Ok(call_result(
                    inputs,
                    InstructionResult::Revert,
                    gas,
                    Bytes::from(output),
                ))
            }
        }
        Err(VmError::OutOfGas) => {
            ctx.evm.journaled_state.checkpoint_revert(checkpoint);
            Ok(call_result(
                inputs,
                InstructionResult::PrecompileOOG,
                Gas::new_spent(inputs.gas_limit),
                Bytes::new(),
            ))
        }
        Err(e) => {
            ctx.evm.journaled_state.checkpoint_revert(checkpoint);
            let _ = gas.record_cost(gas_used);
            Ok(call_result(
                inputs,
                InstructionResult::Revert,
                gas,
                Bytes::from(abi_error_string(&e.to_string())),
            ))
        }
    }
}

/// ABI-encode `Error(string)` revert data.
pub fn abi_error_string(msg: &str) -> Vec<u8> {
    let mut out = vec![0x08, 0xc3, 0x79, 0xa0];
    out.extend_from_slice(&u128_to_word(32));
    out.extend_from_slice(&u128_to_word(msg.len() as u128));
    let mut data = msg.as_bytes().to_vec();
    let pad = (32 - data.len() % 32) % 32;
    data.extend(std::iter::repeat_n(0u8, pad));
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_key_is_injective_over_part_boundaries() {
        assert_ne!(
            slot_key(b"t", &[b"ab", b"c"]),
            slot_key(b"t", &[b"a", b"bc"])
        );
    }

    #[test]
    fn word_round_trip() {
        assert_eq!(word_to_u128(&u128_to_word(u128::MAX)), u128::MAX);
        assert_eq!(word_to_u128(&u128_to_word(7)), 7);
    }
}
