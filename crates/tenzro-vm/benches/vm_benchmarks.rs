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

criterion_group!(
    benches,
    bench_evm_transfer,
    bench_state_adapter,
    bench_gas_estimation,
);
criterion_main!(benches);
