//! The EVM engine of the Osaka rule set.
//!
//! Blocks execute their EVM transactions here once
//! [`super::OSAKA_KEY`] is live; until then [`super::executor`] runs them on
//! the engine the network started with. Both engines read and write the same
//! [`StateAdapter`], serve the same Tenzro precompiles through
//! [`PrecompileState`] and credit no fee to a block beneficiary.

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;

use revm_osaka::{
    Database,
    context::{BlockEnv, CfgEnv, Context, Evm, Journal, TxEnv},
    context_interface::{
        Block, Cfg, ContextTr, JournalTr,
        result::{
            EVMError, ExecutionResult as EngineResult, HaltReason, InvalidTransaction, Output,
        },
        transaction::{
            AccessList, AccessListItem, Authorization, RecoveredAuthority, RecoveredAuthorization,
        },
    },
    handler::{
        EthFrame, EthPrecompiles, EvmTr, FrameResult, Handler, PrecompileProvider,
        instructions::EthInstructions,
    },
    interpreter::{
        CallInputs, CallValue, Gas, InstructionResult, InterpreterResult,
        interpreter::EthInterpreter,
    },
    primitives::{
        Address, AddressSet, B256, Bytes, KECCAK_EMPTY, Log as EngineLog, TxKind, U256, eip7825,
        hardfork::SpecId,
    },
    state::{AccountInfo, Bytecode, EvmState},
};
use sha3::{Digest, Keccak256};

use super::executor::evm_address;
use super::precompile_host::{
    NativeSupplySource, PRECOMPILE_BALANCE_GAS, PRECOMPILE_SLOAD_GAS, PRECOMPILE_SSTORE_GAS,
    PrecompileCall, PrecompileEnv, PrecompileState, abi_error_string,
};
use crate::{
    account_abstraction::{
        Eip7702Authorization, parse_7702_designator, recover_eoa_from_7702_signature,
    },
    config::VmConfig,
    error::{Result, VmError},
    precompiles::{PrecompileRegistry, PrecompileResult},
    state_adapter::StateAdapter,
    traits::VmState,
    types::{CallResult, ContractCall, ExecutionResult, Log, StateChange, VmTransaction},
};

/// The rule set this engine runs.
const RULE_SET: SpecId = SpecId::OSAKA;

/// The highest gas limit a transaction may carry under [`RULE_SET`]
/// (EIP-7825).
pub(super) const TRANSACTION_GAS_CAP: u64 = eip7825::TX_GAS_LIMIT_CAP;

/// [`StateAdapter`] as the engine's database.
struct StateDb<'a> {
    state: &'a mut StateAdapter,
}

impl NativeSupplySource for StateDb<'_> {
    fn native_total_supply(&mut self) -> std::result::Result<u128, String> {
        Ok(self.state.total_supply())
    }

    fn system_storage(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get_storage(&crate::native::SYSTEM_ADDRESS, key)
    }
}

impl Database for StateDb<'_> {
    type Error = Infallible;

    fn basic(&mut self, address: Address) -> std::result::Result<Option<AccountInfo>, Infallible> {
        let addr = address.as_slice();
        let code = self.state.get_code(addr).unwrap_or_default();
        let balance = self.state.get_balance(addr);
        let nonce = self.state.get_nonce(addr);
        // An account with no balance, no nonce and no code does not exist
        // (EIP-161): the engine then charges for creating it and gives no
        // EIP-7702 refund for authorizing it. Its storage is still read
        // from here, as the Tenzro precompiles keep theirs at such
        // addresses.
        if balance == 0 && nonce == 0 && code.is_empty() {
            return Ok(None);
        }
        let code_hash = if code.is_empty() {
            KECCAK_EMPTY
        } else {
            B256::from_slice(&Keccak256::digest(&code))
        };
        // Stored code is an EIP-7702 designator or legacy code. Bytes that
        // open with the designator prefix without being one are legacy code
        // too: they halt on their first byte.
        let code = Bytes::from(code);
        let bytecode =
            Bytecode::new_raw_checked(code.clone()).unwrap_or_else(|_| Bytecode::new_legacy(code));
        Ok(Some(AccountInfo::new(
            U256::from(balance),
            nonce,
            code_hash,
            bytecode,
        )))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> std::result::Result<Bytecode, Infallible> {
        // Code is stored by address and always loaded with its account.
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: Address, index: U256) -> std::result::Result<U256, Infallible> {
        let key = index.to_be_bytes::<32>();
        Ok(self
            .state
            .get_storage(address.as_slice(), &key)
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .map_or(U256::ZERO, U256::from_be_bytes::<32>))
    }

    fn block_hash(&mut self, number: u64) -> std::result::Result<B256, Infallible> {
        Ok(B256::from(super::revm_db::stored_block_hash(
            self.state, number,
        )))
    }
}

/// [`PrecompileState`] over the engine's journal.
struct JournalState<'c, CTX> {
    ctx: &'c mut CTX,
    gas_limit: u64,
    gas_used: u64,
}

fn db_err<E: std::fmt::Debug>(e: E) -> VmError {
    VmError::Internal(format!("state access failed in precompile: {:?}", e))
}

impl<CTX> PrecompileState for JournalState<'_, CTX>
where
    CTX: ContextTr,
    CTX::Db: NativeSupplySource,
{
    fn sload(&mut self, address: [u8; 20], key: [u8; 32]) -> Result<[u8; 32]> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        let addr = Address::from(address);
        let journal = self.ctx.journal_mut();
        journal.load_account(addr).map_err(db_err)?;
        let v = journal
            .sload(addr, U256::from_be_bytes(key))
            .map_err(db_err)?;
        Ok(v.data.to_be_bytes::<32>())
    }

    fn sstore(&mut self, address: [u8; 20], key: [u8; 32], value: [u8; 32]) -> Result<()> {
        self.charge(PRECOMPILE_SSTORE_GAS)?;
        let addr = Address::from(address);
        let journal = self.ctx.journal_mut();
        journal.load_account(addr).map_err(db_err)?;
        journal.touch_account(addr);
        journal
            .sstore(addr, U256::from_be_bytes(key), U256::from_be_bytes(value))
            .map_err(db_err)?;
        Ok(())
    }

    fn balance(&mut self, address: [u8; 20]) -> Result<u128> {
        self.charge(PRECOMPILE_BALANCE_GAS)?;
        let balance = self
            .ctx
            .journal_mut()
            .load_account(Address::from(address))
            .map_err(db_err)?
            .data
            .info
            .balance;
        u128::try_from(balance).map_err(|_| VmError::Internal("balance exceeds u128".to_string()))
    }

    fn transfer(&mut self, from: [u8; 20], to: [u8; 20], amount: u128) -> Result<bool> {
        self.charge(PRECOMPILE_BALANCE_GAS)?;
        let outcome = self
            .ctx
            .journal_mut()
            .transfer(Address::from(from), Address::from(to), U256::from(amount))
            .map_err(db_err)?;
        Ok(outcome.is_none())
    }

    fn block_hash(&mut self, number: u64) -> Result<[u8; 32]> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        let h = self.ctx.db_mut().block_hash(number).map_err(db_err)?;
        Ok(h.0)
    }

    fn native_total_supply(&mut self) -> Result<u128> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        self.ctx
            .db_mut()
            .native_total_supply()
            .map_err(VmError::Internal)
    }

    fn system_storage(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.charge(PRECOMPILE_SLOAD_GAS)?;
        Ok(self.ctx.db_mut().system_storage(key))
    }

    fn feature_live(&mut self, gate: &str) -> bool {
        let db = self.ctx.db_mut();
        crate::feature_gate::is_live_through(|key| db.system_storage(key), gate)
    }

    fn emit_log(&mut self, address: [u8; 20], topics: Vec<[u8; 32]>, data: Vec<u8>) -> Result<()> {
        self.charge(375u64.saturating_add(375u64.saturating_mul(topics.len() as u64)))?;
        self.charge(8u64.saturating_mul(data.len() as u64))?;
        self.ctx.journal_mut().log(EngineLog::new_unchecked(
            Address::from(address),
            topics.into_iter().map(B256::from).collect(),
            Bytes::from(data),
        ));
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

/// The precompiles of a call: the rule set's own, then the Tenzro registry.
/// An address the rule set serves itself (P256VERIFY at `0x100` from Osaka
/// on) is answered by the engine, exactly as on Ethereum. The engine has
/// already moved the call's value and opened a checkpoint when it asks here,
/// and it commits or reverts that checkpoint on the result.
struct Precompiles {
    standard: EthPrecompiles,
    registry: Arc<PrecompileRegistry>,
    /// The call comes from the read-only `eth_call` path.
    read_only: bool,
    /// The call is the ERC-7786 gateway's delivery of a received message.
    delivering: bool,
}

impl<CTX> PrecompileProvider<CTX> for Precompiles
where
    CTX: ContextTr<Cfg: Cfg<Spec = SpecId>>,
    CTX::Db: NativeSupplySource,
{
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: SpecId) -> bool {
        <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.standard, spec)
    }

    fn run(
        &mut self,
        ctx: &mut CTX,
        inputs: &CallInputs,
    ) -> std::result::Result<Option<InterpreterResult>, String> {
        if self.standard.contains(&inputs.bytecode_address) {
            return <EthPrecompiles as PrecompileProvider<CTX>>::run(
                &mut self.standard,
                ctx,
                inputs,
            );
        }
        let code_address: [u8; 20] = inputs.bytecode_address.into_array();
        let Some(precompile) = self.registry.get(&code_address) else {
            return Ok(None);
        };
        let mut gas = Gas::new_with_regular_gas_and_reservoir(inputs.gas_limit, inputs.reservoir);
        let spent = || Gas::new_spent_with_reservoir(inputs.gas_limit, inputs.reservoir);
        let ended = |result, output, gas| Ok(Some(InterpreterResult::new(result, output, gas)));

        // A precompile's storage belongs to the precompile. DELEGATECALL and
        // CALLCODE would run it against the caller's storage and balance,
        // which no stateful Tenzro precompile is written for. A stateless
        // one answers every call type alike, as Ethereum's precompiles do.
        if inputs.target_address != inputs.bytecode_address
            && !self.registry.is_stateless(&code_address)
        {
            return ended(InstructionResult::Revert, Bytes::new(), gas);
        }
        let value = match inputs.value {
            CallValue::Transfer(v) if !v.is_zero() => match u128::try_from(v) {
                Ok(amount) => amount,
                Err(_) => return ended(InstructionResult::Revert, Bytes::new(), gas),
            },
            _ => 0,
        };
        let env = PrecompileEnv {
            address: code_address,
            caller: inputs.caller.into_array(),
            value,
            is_static: inputs.is_static,
            read_only: self.read_only,
            delivering: self.delivering,
            chain_id: ctx.cfg().chain_id(),
            block_number: u64::try_from(ctx.block().number()).unwrap_or(u64::MAX),
            block_timestamp: u64::try_from(ctx.block().timestamp()).unwrap_or(u64::MAX),
        };
        let input = inputs.input.bytes(ctx);

        let (outcome, charged) = {
            let mut state = JournalState {
                ctx: &mut *ctx,
                gas_limit: inputs.gas_limit,
                gas_used: 0,
            };
            let mut call = PrecompileCall {
                input: &input,
                gas_limit: inputs.gas_limit,
                env,
                state: &mut state,
            };
            let outcome = precompile(&mut call);
            (outcome, state.gas_used)
        };

        match outcome {
            Ok(PrecompileResult {
                output,
                gas_used: own_gas,
                success,
            }) => {
                if !gas.record_regular_cost(charged.saturating_add(own_gas)) {
                    return ended(InstructionResult::PrecompileOOG, Bytes::new(), spent());
                }
                let result = if success {
                    InstructionResult::Return
                } else {
                    InstructionResult::Revert
                };
                ended(result, Bytes::from(output), gas)
            }
            Err(VmError::OutOfGas) => {
                ended(InstructionResult::PrecompileOOG, Bytes::new(), spent())
            }
            Err(e) => {
                // `charged` never exceeds the call's gas limit.
                let _ = gas.record_regular_cost(charged);
                ended(
                    InstructionResult::Revert,
                    Bytes::from(abi_error_string(&e.to_string())),
                    gas,
                )
            }
        }
    }

    fn warm_addresses(&self) -> &AddressSet {
        self.standard.warm_addresses()
    }
}

/// The engine's own transaction handling with one change: fees are settled
/// by the node in-block from what the sender paid, so nothing is credited to
/// a block beneficiary and the sender's debit is the whole of the fee.
struct NoBeneficiary<EVM>(PhantomData<EVM>);

impl<EVM> Handler for NoBeneficiary<EVM>
where
    EVM: EvmTr<
            Context: ContextTr<Journal: JournalTr<State = EvmState>>,
            Frame = EthFrame<EthInterpreter>,
        >,
{
    type Evm = EVM;
    type Error = EVMError<<<EVM::Context as ContextTr>::Db as Database>::Error, InvalidTransaction>;
    type HaltReason = HaltReason;

    fn reward_beneficiary(
        &self,
        _evm: &mut Self::Evm,
        _exec_result: &mut FrameResult,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

type EngineContext<'a> = Context<BlockEnv, TxEnv, CfgEnv, StateDb<'a>, Journal<StateDb<'a>>, ()>;

/// What the engine saw of the block.
struct BlockView {
    number: u64,
    timestamp: u64,
    gas_limit: u64,
    base_fee: u64,
}

/// Runs `tx_env` against `state` without writing to it and returns the
/// engine's result with every account it touched.
fn transact(
    state: &mut StateAdapter,
    registry: &Arc<PrecompileRegistry>,
    chain_id: u64,
    block: BlockView,
    tx_env: TxEnv,
    read_only: bool,
    delivering: bool,
) -> (
    std::result::Result<EngineResult<HaltReason>, EVMError<Infallible, InvalidTransaction>>,
    EvmState,
) {
    let mut ctx: EngineContext<'_> = Context::new(StateDb { state }, RULE_SET)
        .modify_cfg_chained(|cfg: &mut CfgEnv| {
            cfg.chain_id = chain_id;
            cfg.disable_base_fee = delivering;
        })
        .modify_block_chained(|env: &mut BlockEnv| {
            env.number = U256::from(block.number);
            env.timestamp = U256::from(block.timestamp);
            env.gas_limit = block.gas_limit;
            env.basefee = block.base_fee;
        });
    ctx.tx = tx_env;
    let mut evm: Evm<_, (), _, _, EthFrame<EthInterpreter>> = Evm::new(
        ctx,
        EthInstructions::new_mainnet_with_spec(RULE_SET),
        Precompiles {
            standard: EthPrecompiles::new(RULE_SET),
            registry: registry.clone(),
            read_only,
            delivering,
        },
    );
    let ran = NoBeneficiary(PhantomData).run(&mut evm);
    let accounts = evm.ctx.journal_mut().finalize();
    (ran, accounts)
}

/// The authorization as the engine applies it. One whose signature does not
/// recover carries no authority, so execution skips it (EIP-7702) while the
/// transaction still runs.
fn authorization(auth: &Eip7702Authorization) -> RecoveredAuthorization {
    let address = <[u8; 20]>::try_from(auth.delegate_address.as_slice()).unwrap_or([0u8; 20]);
    let authority = match recover_eoa_from_7702_signature(auth) {
        Ok(a) => RecoveredAuthority::Valid(Address::from_slice(&a)),
        Err(_) => RecoveredAuthority::Invalid,
    };
    RecoveredAuthorization::new_unchecked(
        Authorization {
            chain_id: U256::from_be_bytes(auth.chain_id.to_be_bytes::<32>()),
            address: Address::from(address),
            nonce: auth.nonce,
        },
        authority,
    )
}

fn engine_address(bytes: &[u8]) -> Result<Address> {
    Ok(Address::from_slice(evm_address(bytes)?.as_slice()))
}

/// Executes a transaction of a block and applies what it changed to `state`.
pub(super) fn execute(
    config: &VmConfig,
    registry: &Arc<PrecompileRegistry>,
    tx: &VmTransaction,
    state: &mut StateAdapter,
    delivering: bool,
) -> Result<ExecutionResult> {
    let kind = match tx.to {
        Some(ref to) => TxKind::Call(engine_address(to)?),
        None => TxKind::Create,
    };
    let access_list = AccessList(
        tx.access_list
            .iter()
            .map(|(address, keys)| AccessListItem {
                address: Address::from(*address),
                storage_keys: keys.iter().map(|k| B256::from(*k)).collect(),
            })
            .collect(),
    );
    let tx_env = TxEnv::builder()
        .caller(engine_address(&tx.from)?)
        .gas_limit(tx.gas_limit)
        .gas_price(tx.gas_price)
        .value(U256::from(tx.value))
        .data(Bytes::from(tx.data.clone()))
        .nonce(tx.nonce)
        .chain_id(Some(tx.chain_id))
        .kind(kind)
        .access_list(access_list)
        .authorization_list_recovered(tx.authorization_list.iter().map(authorization).collect())
        .build()
        .map_err(|e| VmError::InvalidTransaction(format!("{e:?}")))?;
    // Block context comes from the block being executed, never from the
    // local clock.
    let block = BlockView {
        number: tx.block_height.unwrap_or(0),
        timestamp: tx
            .block_timestamp_ms
            .map_or(0, |ms| u64::try_from(ms / 1000).unwrap_or(0)),
        gas_limit: config.max_gas_limit,
        base_fee: u64::try_from(tx.block_base_fee.unwrap_or(0)).unwrap_or(u64::MAX),
    };

    let (ran, accounts) = transact(
        state,
        registry,
        tx.chain_id,
        block,
        tx_env,
        false,
        delivering,
    );
    let ran = match ran {
        Ok(ran) => ran,
        // A transaction the engine refuses before running it is refused
        // here too. Any other error ends a transaction that has already
        // run: it failed and spent its whole gas limit, as an exceptional
        // halt does.
        Err(e @ (EVMError::Transaction(_) | EVMError::Header(_))) => {
            return Err(VmError::ExecutionFailed(format!(
                "EVM execution failed: {e:?}"
            )));
        }
        Err(e) => {
            return Ok(ExecutionResult::failed(
                tx.gas_limit,
                format!("EVM execution failed: {e:?}"),
            ));
        }
    };

    let gas_used = ran.tx_gas_used();
    let (success, gas_refund, output, contract_address, logs) = match ran {
        EngineResult::Success {
            gas, output, logs, ..
        } => {
            let (data, created) = match output {
                Output::Call(data) => (data.to_vec(), None),
                Output::Create(data, address) => {
                    (data.to_vec(), address.map(|a| a.as_slice().to_vec()))
                }
            };
            let logs = logs
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
            (true, gas.final_refunded(), data, created, logs)
        }
        EngineResult::Revert { output, .. } => (false, 0, output.to_vec(), None, Vec::new()),
        // The halt reason is the failure the receipt reports.
        EngineResult::Halt { reason, .. } => (
            false,
            0,
            format!("halted: {reason:?}").into_bytes(),
            None,
            Vec::new(),
        ),
    };

    let mut state_changes = Vec::new();
    let mut delegations = Vec::new();
    // The engine's state is a hash map whose order differs per process:
    // the changes and delegations are built in address and key order, so
    // every node produces them in the same one.
    let mut accounts: Vec<_> = accounts.into_iter().collect();
    accounts.sort_by_key(|entry| entry.0);
    for (address, account) in accounts {
        let addr = address.as_slice().to_vec();

        // An account destroyed in the transaction that created it leaves
        // nothing behind: its balance has already moved to the beneficiary
        // of the destruction, and its nonce, code and storage are not
        // written.
        if account.is_selfdestructed() {
            if state.get_balance(&addr) != 0 {
                state.set_balance(&addr, 0);
            }
            continue;
        }

        if account.is_touched() {
            let balance = account.info.balance.try_into().unwrap_or(0u128);
            if balance != state.get_balance(&addr) {
                state.set_balance(&addr, balance);
            }
        }
        if account.info.nonce != state.get_nonce(&addr) {
            state.set_nonce(&addr, account.info.nonce);
        }

        // A new contract, an EIP-7702 delegation, or a delegation cleared
        // by an authorization to the zero address.
        if let Some(code) = &account.info.code {
            let code_bytes = code.original_bytes().to_vec();
            let existing = state.get_code(&addr);
            let changed = match &existing {
                Some(existing) => existing != &code_bytes,
                None => !code_bytes.is_empty(),
            };
            if changed {
                let was_delegated = existing
                    .as_deref()
                    .is_some_and(|c| parse_7702_designator(c).is_some());
                if code.is_eip7702() || (code_bytes.is_empty() && was_delegated) {
                    delegations.push((addr.clone(), code_bytes.clone()));
                }
                state.set_code(&addr, code_bytes);
            }
        }

        let mut slots: Vec<_> = account.storage.into_iter().collect();
        slots.sort_by_key(|entry| entry.0);
        for (key, slot) in slots {
            let key = key.to_be_bytes::<32>().to_vec();
            let value = slot.present_value.to_be_bytes::<32>().to_vec();
            let old = state.get_storage(&addr, &key);
            if old.as_ref() != Some(&value) {
                state.set_storage(&addr, &key, value.clone());
                state_changes.push(StateChange::new(addr.clone(), key, old, Some(value)));
            }
        }
    }

    let mut result = if !success {
        ExecutionResult::failed(
            gas_used,
            String::from_utf8(output).unwrap_or_else(|_| "Execution failed".to_string()),
        )
    } else if let Some(address) = contract_address {
        ExecutionResult::deployment(gas_used, address, logs, state_changes)
    } else {
        ExecutionResult::success(gas_used, output, logs, state_changes)
    };
    result.gas_refund = gas_refund;
    result.delegations = delegations;
    Ok(result)
}

/// A read-only call against `state`, which the caller owns and discards:
/// nothing here writes to it.
pub(super) fn call(
    config: &VmConfig,
    registry: &Arc<PrecompileRegistry>,
    call: &ContractCall,
    state: &mut StateAdapter,
) -> Result<CallResult> {
    let from: Vec<u8> = if call.caller.is_empty() {
        vec![0u8; 20]
    } else {
        call.caller.clone()
    };
    // No callee simulates a contract creation: the data is the init code
    // and the output the code it would deploy.
    let kind = if call.contract.is_empty() {
        TxKind::Create
    } else {
        TxKind::Call(engine_address(&call.contract)?)
    };
    let tx_env = TxEnv::builder()
        .caller(engine_address(&from)?)
        // No transaction can carry more gas than the rule set's cap, so a
        // call is answered with at most that much.
        .gas_limit(call.gas_limit.min(TRANSACTION_GAS_CAP))
        .gas_price(0)
        .value(U256::from(call.value))
        .data(Bytes::from(call.data.clone()))
        .nonce(state.get_nonce(&from))
        .chain_id(Some(config.chain_id))
        .kind(kind)
        .build()
        .map_err(|e| VmError::InvalidTransaction(format!("{e:?}")))?;
    let block = BlockView {
        number: call.block_height,
        timestamp: u64::try_from(call.block_timestamp_ms / 1000).unwrap_or(0),
        gas_limit: config.max_gas_limit,
        base_fee: 0,
    };

    let (ran, _) = transact(state, registry, config.chain_id, block, tx_env, true, false);
    let ran = ran.map_err(|e| VmError::ExecutionFailed(format!("EVM call failed: {e:?}")))?;
    let gas_used = ran.tx_gas_used();
    let (success, output, revert_reason) = match ran {
        EngineResult::Success { output, .. } => {
            let data = match output {
                Output::Call(data) | Output::Create(data, _) => data.to_vec(),
            };
            (true, data, None)
        }
        EngineResult::Revert { output, .. } => (
            false,
            Vec::new(),
            Some(
                String::from_utf8(output.to_vec())
                    .unwrap_or_else(|_| "Execution reverted".to_string()),
            ),
        ),
        EngineResult::Halt { reason, .. } => (
            false,
            Vec::new(),
            Some(format!("Execution halted: {reason:?}")),
        ),
    };
    Ok(CallResult {
        output,
        gas_used,
        success,
        revert_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::{EvmExecutor, OSAKA_KEY};
    use crate::gas::GasOracle;
    use crate::traits::{VmExecutor, VmType};

    const CHAIN: u64 = 1337;
    const PRICE: u128 = 1_000_000_000;

    fn executor() -> EvmExecutor {
        let config = VmConfig {
            chain_id: CHAIN,
            ..VmConfig::default()
        };
        EvmExecutor::new(
            config,
            Arc::new(GasOracle::new()),
            Arc::new(PrecompileRegistry::new()),
        )
        .unwrap()
    }

    /// A state with `feature.evm_osaka` dormant or live.
    fn state(live: bool) -> StateAdapter {
        let mut state = StateAdapter::new();
        if live {
            crate::native::set_governed_param_for_test(&mut state, OSAKA_KEY, 0);
        }
        state
    }

    fn sender() -> Vec<u8> {
        vec![1u8; 20]
    }

    fn tx(to: Option<Vec<u8>>, value: u128, data: Vec<u8>, gas_limit: u64) -> VmTransaction {
        VmTransaction::new(
            sender(),
            to,
            value,
            data,
            gas_limit,
            PRICE,
            0,
            VmType::Evm,
            CHAIN,
        )
    }

    async fn read(state: &StateAdapter, contract: Vec<u8>, data: Vec<u8>) -> CallResult {
        let call = ContractCall::new(sender(), contract, data, 0, 1_000_000, VmType::Evm);
        executor().call(&call, state).await.unwrap()
    }

    /// CLZ (`0x1e`) is an opcode of Osaka and undefined before it: code that
    /// returns `CLZ(1)` halts while the gate is dormant and answers 255
    /// once it is live.
    #[tokio::test]
    async fn clz_is_an_opcode_once_osaka_is_live() {
        let contract = vec![0xc1u8; 20];
        // PUSH1 1, CLZ, PUSH0, MSTORE, PUSH1 32, PUSH0, RETURN
        let code = vec![0x60, 0x01, 0x1e, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3];

        let mut dormant = state(false);
        dormant.set_code(&contract, code.clone());
        let halted = read(&dormant, contract.clone(), Vec::new()).await;
        assert!(!halted.success, "CLZ is undefined under Prague");

        let mut live = state(true);
        live.set_code(&contract, code);
        let answered = read(&live, contract, Vec::new()).await;
        assert!(answered.success, "{:?}", answered.revert_reason);
        let mut word = [0u8; 32];
        word[31] = 255;
        assert_eq!(answered.output, word);
    }

    /// On both sides of the gate a transfer costs its sender the value and
    /// the whole fee, pays the recipient the value and credits the fee to
    /// no account.
    #[test]
    fn a_transfer_debits_the_whole_fee_and_credits_no_beneficiary() {
        for live in [false, true] {
            let mut state = state(live);
            let recipient = vec![2u8; 20];
            let funded = 10_000_000_000_000_000_000u128;
            state.set_balance(&sender(), funded);
            let result = executor()
                .execute_with_revm(
                    &tx(Some(recipient.clone()), 1_000, Vec::new(), 100_000),
                    &mut state,
                )
                .unwrap();
            assert!(result.success, "live={live}: {:?}", result.revert_reason);
            assert_eq!(result.gas_used, 21_000, "live={live}");
            assert_eq!(
                state.get_balance(&sender()),
                funded - 1_000 - 21_000 * PRICE,
                "live={live}"
            );
            assert_eq!(state.get_balance(&recipient), 1_000, "live={live}");
            assert_eq!(state.get_balance(&[0u8; 20]), 0, "live={live}");
            assert_eq!(state.get_nonce(&sender()), 1, "live={live}");
        }
    }

    /// Osaka caps a transaction's gas limit at 16,777,216: a transaction
    /// above it runs while the gate is dormant and is refused once live.
    #[test]
    fn a_gas_limit_above_the_osaka_cap_is_refused_once_live() {
        let over = tx(Some(vec![2u8; 20]), 0, Vec::new(), 20_000_000);

        let mut dormant = state(false);
        dormant.set_balance(&sender(), u128::MAX / 2);
        assert!(
            executor()
                .execute_with_revm(&over, &mut dormant)
                .unwrap()
                .success
        );

        let mut live = state(true);
        live.set_balance(&sender(), u128::MAX / 2);
        let refused = executor().execute_with_revm(&over, &mut live);
        assert!(refused.is_err(), "{refused:?}");
        assert_eq!(
            live.get_nonce(&sender()),
            0,
            "a refused transaction changes nothing"
        );
        assert_eq!(live.get_balance(&sender()), u128::MAX / 2);
    }

    /// A contract that destroys itself in the transaction that creates it
    /// leaves nothing behind once the gate is live. The first engine's
    /// result was applied without that removal, so the account kept the
    /// nonce its creation gave it.
    #[test]
    fn an_account_destroyed_where_it_was_created_leaves_nothing_once_live() {
        // Init code: PUSH0, SELFDESTRUCT.
        let create = tx(None, 0, vec![0x5f, 0xff], 200_000);
        let mut created = None;
        for live in [false, true] {
            let mut state = state(live);
            state.set_balance(&sender(), 10_000_000_000_000_000_000u128);
            let result = executor().execute_with_revm(&create, &mut state).unwrap();
            assert!(result.success, "live={live}: {:?}", result.revert_reason);
            let address = result.contract_address.expect("a created address");
            assert_eq!(*created.get_or_insert(address.clone()), address);
            assert_eq!(state.get_nonce(&address), u64::from(!live), "live={live}");
            assert!(state.get_code(&address).is_none_or(|c| c.is_empty()));
        }
    }

    /// The Tenzro precompiles answer through either engine alike: the
    /// wTNZO pointer at `0x1001` reads a native balance.
    #[tokio::test]
    async fn a_tenzro_precompile_answers_alike_on_both_sides() {
        let mut wtnzo = vec![0u8; 20];
        wtnzo[18] = 0x10;
        wtnzo[19] = 0x01;
        let holder = vec![7u8; 20];
        // balanceOf(address)
        let mut data = vec![0x70, 0xa0, 0x82, 0x31];
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(&holder);

        let mut answers = Vec::new();
        for live in [false, true] {
            let mut state = state(live);
            state.set_balance(&holder, 12_345);
            let answer = read(&state, wtnzo.clone(), data.clone()).await;
            assert!(answer.success, "live={live}: {:?}", answer.revert_reason);
            assert_eq!(
                answer.output,
                crate::evm::precompile_host::u128_to_word(12_345)
            );
            answers.push(answer.gas_used);
        }
        assert_eq!(answers[0], answers[1], "the same gas on both sides");
    }

    /// What one transaction leaves behind on a state with the Osaka rule
    /// dormant or live: its outcome, gas and logs, three storage slots of
    /// the contract it touched, the contract's code, and the sender's and
    /// the contract's balances and the sender's nonce.
    async fn end_of(
        live: bool,
        contract: &[u8],
        code: &[u8],
        to: Option<Vec<u8>>,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> (
        bool,
        String,
        Vec<Option<Vec<u8>>>,
        Option<Vec<u8>>,
        [u128; 2],
        u64,
    ) {
        let mut state = state(live);
        state.set_balance(&sender(), 10_000_000_000_000_000_000);
        state.set_code(contract, code.to_vec());
        let result = executor()
            .execute_transaction(&tx(to, 7, data, gas_limit), &mut state)
            .await
            .unwrap();
        let slots = (0u8..3)
            .map(|k| state.get_storage(contract, &[&[0u8; 31][..], &[k]].concat()))
            .collect();
        (
            result.success,
            format!("{result:?}"),
            slots,
            state.get_code(contract),
            [state.get_balance(&sender()), state.get_balance(contract)],
            state.get_nonce(&sender()),
        )
    }

    /// An ordinary transaction ends alike before and after the epoch, in
    /// each way one ends: kept (three storage writes and a log), reverted,
    /// out of gas, and a contract creation.
    #[tokio::test]
    async fn an_ordinary_transaction_ends_alike_on_both_sides_of_the_epoch() {
        let contract = vec![0xc2u8; 20];
        // SSTORE 1 at 0, 2 at 1, 3 at 2; LOG0 of nothing; STOP.
        let writes = vec![
            0x60, 0x01, 0x60, 0x00, 0x55, 0x60, 0x02, 0x60, 0x01, 0x55, 0x60, 0x03, 0x60, 0x02,
            0x55, 0x5f, 0x5f, 0xa0, 0x00,
        ];
        // SSTORE 1 at 0, then REVERT with no data.
        let reverts = vec![0x60, 0x01, 0x60, 0x00, 0x55, 0x5f, 0x5f, 0xfd];
        // Init code returning one STOP byte as the runtime code:
        // PUSH1 0, PUSH0, MSTORE8, PUSH1 1, PUSH0, RETURN.
        let creates = vec![0x60, 0x00, 0x5f, 0x53, 0x60, 0x01, 0x5f, 0xf3];

        // (name, code at the contract, to, data, gas limit, must succeed)
        let shapes: Vec<(&str, Vec<u8>, Option<Vec<u8>>, Vec<u8>, u64, bool)> = vec![
            (
                "kept",
                writes.clone(),
                Some(contract.clone()),
                Vec::new(),
                200_000,
                true,
            ),
            (
                "reverted",
                reverts,
                Some(contract.clone()),
                Vec::new(),
                200_000,
                false,
            ),
            (
                "out of gas",
                writes,
                Some(contract.clone()),
                Vec::new(),
                30_000,
                false,
            ),
            ("creation", Vec::new(), None, creates, 200_000, true),
        ];
        for (name, code, to, data, gas_limit, ok) in shapes {
            let dormant =
                end_of(false, &contract, &code, to.clone(), data.clone(), gas_limit).await;
            let live = end_of(true, &contract, &code, to, data, gas_limit).await;
            assert_eq!(dormant.0, ok, "{name}: the outcome the shape is built for");
            assert_eq!(dormant, live, "{name}: the same end on both sides");
        }
    }

    /// KZG point evaluation at `0x0a`, verified by the engine's BLS12-381
    /// backend: the correct proof of the c-kzg-4844 mainnet vectors
    /// (`verify_kzg_proof_case_correct_proof_4_4`) is accepted with the
    /// standard return value, and the same proof against another value is
    /// refused. The first engine has no such precompile: a call to it ends
    /// in an engine error.
    #[tokio::test]
    async fn kzg_point_evaluation_verifies_a_proof_once_live() {
        use sha2::{Digest as _, Sha256};
        let commitment = hex::decode("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").unwrap();
        let z = hex::decode("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000")
            .unwrap();
        let y = hex::decode("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9")
            .unwrap();
        let proof = hex::decode("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c").unwrap();
        let mut versioned_hash = Sha256::digest(&commitment).to_vec();
        versioned_hash[0] = 0x01;
        let input = |y: &[u8]| [&versioned_hash[..], &z, y, &commitment, &proof].concat();
        let mut precompile = vec![0u8; 20];
        precompile[19] = 0x0a;

        let live = state(true);
        let accepted = read(&live, precompile.clone(), input(&y)).await;
        assert!(accepted.success, "{:?}", accepted.revert_reason);
        assert_eq!(
            hex::encode(&accepted.output),
            "0000000000000000000000000000000000000000000000000000000000001000\
             73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
        );
        let mut other = y.clone();
        other[31] ^= 1;
        assert!(!read(&live, precompile.clone(), input(&other)).await.success);

        let call = ContractCall::new(sender(), precompile, input(&y), 0, 1_000_000, VmType::Evm);
        assert!(executor().call(&call, &state(false)).await.is_err());
    }
}
