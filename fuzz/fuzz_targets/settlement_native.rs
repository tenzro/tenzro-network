//! Fuzzes the settlement plan native entry: arbitrary calldata after the
//! settlement selector, executed by the native executor against a funded
//! payer.
//!
//! Properties:
//! - no calldata panics the executor;
//! - a refused call changes no balance once reverted, as in a block;
//! - an accepted call creates no value across the balances it touches.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tenzro_vm::native::SELECTOR_SETTLEMENT_PLAN;
use tenzro_vm::{NativeExecutor, StateAdapter, VmConfig, VmExecutor, VmState, VmTransaction, VmType};

const PAYER: [u8; 20] = [0x11; 20];
const FUNDS: u128 = 1_000_000_000_000_000_000_000;
const CHAIN: u64 = 1337;
const T0: i64 = 1_800_000_000_000;

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
    })
}

fn executor() -> &'static NativeExecutor {
    static EX: OnceLock<NativeExecutor> = OnceLock::new();
    EX.get_or_init(|| NativeExecutor::new(VmConfig::default()).expect("executor"))
}

fuzz_target!(|data: &[u8]| {
    let mut state = StateAdapter::new();
    state.set_balance(&PAYER, FUNDS);
    let mut calldata = SELECTOR_SETTLEMENT_PLAN.to_vec();
    calldata.extend_from_slice(data);
    let tx = VmTransaction::new(
        PAYER.to_vec(),
        None,
        0,
        calldata,
        50_000_000,
        0,
        0,
        VmType::Tenzro,
        CHAIN,
    )
    .with_block_timestamp_ms(T0);
    state.begin_transaction();
    let out = runtime().block_on(executor().execute_transaction(&tx, &mut state));
    match out {
        Ok(r) if r.success => {
            assert!(
                state.journal_balance_delta().unwrap_or(0) <= 0,
                "an accepted settlement call created value"
            );
            state.commit_transaction();
        }
        _ => {
            state.revert_transaction();
            assert_eq!(state.get_balance(&PAYER), FUNDS, "a refused call moved value");
        }
    }
});
