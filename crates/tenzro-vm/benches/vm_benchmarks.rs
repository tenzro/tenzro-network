//! Criterion benchmarks for tenzro-vm critical execution paths
//!
//! Run with: cargo bench -p tenzro-vm

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

fn bench_evm_transfer(c: &mut Criterion) {
    use tenzro_vm::{VmConfig, MultiVmRuntime, VmState};
    use tenzro_vm::state_adapter::StateAdapter;
    use tenzro_vm::types::VmTransaction;
    use tenzro_vm::VmType;

    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("evm_execution");

    group.bench_function("simple_transfer", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = VmConfig::default();
                let runtime = MultiVmRuntime::new(config).await.unwrap();
                let mut state = StateAdapter::new();

                let from = vec![1u8; 20];
                let to = vec![2u8; 20];
                state.set_balance(&from, 1_000_000_000_000_000_000u128);

                let tx = VmTransaction::new(
                    from.clone(),
                    Some(to.clone()),
                    1_000_000_000_000_000,
                    Vec::new(),
                    21_000,
                    1_000_000_000,
                    0,
                    VmType::Evm,
                    1337,
                );

                black_box(runtime.execute_transaction(&tx, &mut state).await.unwrap());
            });
        });
    });

    group.bench_function("contract_call", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = VmConfig::default();
                let runtime = MultiVmRuntime::new(config).await.unwrap();
                let mut state = StateAdapter::new();

                let caller = vec![3u8; 20];
                let contract_addr = vec![5u8; 20];

                // Runtime code: PUSH1 0x42, PUSH1 0x00, MSTORE, PUSH1 0x20, PUSH1 0x00, RETURN
                let runtime_code = vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xF3];

                state.set_balance(&caller, 10_000_000_000_000_000_000u128);
                state.set_code(&contract_addr, runtime_code);

                let tx = VmTransaction::new(
                    caller.clone(),
                    Some(contract_addr.clone()),
                    0,
                    Vec::new(),
                    100_000,
                    1_000_000_000,
                    0,
                    VmType::Evm,
                    1337,
                );

                black_box(runtime.execute_transaction(&tx, &mut state).await.unwrap());
            });
        });
    });

    group.finish();
}

fn bench_state_adapter(c: &mut Criterion) {
    use tenzro_vm::VmState;
    use tenzro_vm::state_adapter::StateAdapter;

    let mut group = c.benchmark_group("state_adapter");

    group.bench_function("get_set_balance", |b| {
        let mut state = StateAdapter::new();
        let addr = vec![1u8; 20];

        b.iter(|| {
            state.set_balance(black_box(&addr), black_box(1_000_000u128));
            black_box(state.get_balance(black_box(&addr)));
        });
    });

    group.bench_function("get_set_storage", |b| {
        let mut state = StateAdapter::new();
        let addr = vec![1u8; 20];
        let key = vec![0u8; 32];
        let value = vec![42u8; 32];

        b.iter(|| {
            state.set_storage(black_box(&addr), black_box(&key), black_box(value.clone()));
            black_box(state.get_storage(black_box(&addr), black_box(&key)));
        });
    });

    group.bench_function("compute_state_root", |b| {
        let mut state = StateAdapter::new();
        // Populate with some data
        for i in 0..100u8 {
            let addr = vec![i; 20];
            state.set_balance(&addr, i as u128 * 1_000_000);
            state.set_nonce(&addr, i as u64);
        }

        b.iter(|| {
            black_box(state.compute_state_root());
        });
    });

    group.finish();
}

fn bench_gas_estimation(c: &mut Criterion) {
    use tenzro_vm::GasEstimator;

    let mut group = c.benchmark_group("gas_estimation");

    group.bench_function("estimate_transfer", |b| {
        b.iter(|| {
            black_box(GasEstimator::estimate_transfer());
        });
    });

    for &size in &[32, 256, 1024, 4096] {
        group.bench_with_input(BenchmarkId::new("estimate_call", size), &size, |b, &size| {
            b.iter(|| {
                black_box(GasEstimator::estimate_call(black_box(size), black_box(false)));
            });
        });

        group.bench_with_input(
            BenchmarkId::new("estimate_deployment", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    black_box(GasEstimator::estimate_deployment(black_box(size)));
                });
            },
        );
    }

    group.finish();
}

/// Block-STM commutative delta lanes vs concrete read-modify-write.
///
/// The high-conflict batch models many transactions all crediting/debiting one
/// hot account (the archetype: concurrent TNZO transfers hitting a shared
/// sender or beneficiary). With concrete `read + write` on the shared balance,
/// every tx after the first conflicts and re-executes (or the batch falls back
/// to sequential). With commutative delta lanes, those same transactions
/// commute — zero re-executions — and the balance folds at commit. The
/// no-conflict batch (distinct accounts) is the baseline both paths share.
fn bench_block_stm_delta_lanes(c: &mut Criterion) {
    use tenzro_vm::{
        BaseState, BlockStmExecutor, ReadWriteSet, TxExecutionStatus, ZeroBaseState,
    };

    struct HotBase(Vec<u8>, u128);
    impl BaseState for HotBase {
        fn base_balance(&self, address: &[u8]) -> u128 {
            if address == self.0 { self.1 } else { 0 }
        }
        fn base_storage(&self, _a: &[u8], _k: &[u8]) -> Option<Vec<u8>> {
            None
        }
    }

    let mut group = c.benchmark_group("block_stm");

    for &tx_count in &[16usize, 64, 256] {
        // High-conflict, concrete RMW on a shared hot balance: forces the
        // conflict/re-execution machinery.
        group.bench_with_input(
            BenchmarkId::new("hot_account_concrete_rmw", tx_count),
            &tx_count,
            |b, &n| {
                let executor = BlockStmExecutor::default();
                let hot = vec![0xaau8; 32];
                b.iter(|| {
                    let (result, _) = executor.execute_block(
                        black_box(n),
                        &ZeroBaseState,
                        |_i, rw: &mut ReadWriteSet| {
                            rw.record_balance_read(&hot, 1_000_000);
                            rw.record_balance_write(&hot, 999_999);
                            TxExecutionStatus::Success { gas_used: 21_000 }
                        },
                    );
                    black_box(result);
                });
            },
        );

        // Same hot account, commutative delta lane: commutes → no re-execution.
        group.bench_with_input(
            BenchmarkId::new("hot_account_delta_lane", tx_count),
            &tx_count,
            |b, &n| {
                let executor = BlockStmExecutor::default();
                let hot = vec![0xaau8; 32];
                let base = HotBase(hot.clone(), 1_000_000);
                b.iter(|| {
                    let (result, resolved) = executor.execute_block(
                        black_box(n),
                        &base,
                        |_i, rw: &mut ReadWriteSet| {
                            rw.record_balance_delta(&hot, -1);
                            TxExecutionStatus::Success { gas_used: 21_000 }
                        },
                    );
                    black_box((result, resolved));
                });
            },
        );

        // No-conflict baseline: each tx touches a distinct account.
        group.bench_with_input(
            BenchmarkId::new("distinct_accounts", tx_count),
            &tx_count,
            |b, &n| {
                let executor = BlockStmExecutor::default();
                b.iter(|| {
                    let (result, _) = executor.execute_block(
                        black_box(n),
                        &ZeroBaseState,
                        |i, rw: &mut ReadWriteSet| {
                            let addr = vec![i as u8; 32];
                            rw.record_balance_read(&addr, 1_000);
                            rw.record_balance_write(&addr, 900);
                            TxExecutionStatus::Success { gas_used: 21_000 }
                        },
                    );
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_evm_transfer,
    bench_state_adapter,
    bench_gas_estimation,
    bench_block_stm_delta_lanes,
);
criterion_main!(benches);
