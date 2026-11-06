//! Criterion benchmarks for tenzro-vm critical execution paths
//!
//! Run with: cargo bench -p tenzro-vm

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

fn bench_evm_transfer(c: &mut Criterion) {
    use tenzro_vm::VmType;
    use tenzro_vm::state_adapter::StateAdapter;
    use tenzro_vm::types::VmTransaction;
    use tenzro_vm::{MultiVmRuntime, VmConfig, VmState};

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
        group.bench_with_input(
            BenchmarkId::new("estimate_call", size),
            &size,
            |b, &size| {
                b.iter(|| {
                    black_box(GasEstimator::estimate_call(
                        black_box(size),
                        black_box(false),
                    ));
                });
            },
        );

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

/// Parallel block execution against in-order execution, on blocks of native
/// transfers.
///
/// - `distinct`: every transfer has its own sender and recipient, so nothing
///   conflicts.
/// - `hot_recipient`: every transfer pays the same recipient, so every one
///   reads the balance the one before it wrote.
/// - `signed_distinct` / `signed_hot_recipient`: the same blocks with every
///   transaction carrying a composite (Ed25519 + ML-DSA-65) signature, which
///   the runtime verifies before executing it, as it does for every
///   transaction in a finalized block.
///
/// `sequential` is the in-order loop; `workers_N` is the parallel executor
/// with N threads.
fn bench_block_stm(c: &mut Criterion) {
    use criterion::BatchSize;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::composite::{HybridSigner, SignatureContext};
    use tenzro_vm::ledger::{BlockFees, execute_in_block};
    use tenzro_vm::parallel::execute_block;
    use tenzro_vm::state_adapter::StateAdapter;
    use tenzro_vm::types::VmTransaction;
    use tenzro_vm::{BlockStmConfig, MultiVmRuntime, VmConfig, VmState, VmType};

    const BASE_FEE: u128 = 1_000_000_000;
    const N: usize = 512;

    fn addr(i: usize) -> Vec<u8> {
        let mut a = vec![0x22u8; 20];
        a[16..20].copy_from_slice(&(i as u32).to_be_bytes());
        a
    }

    struct Account {
        address: Vec<u8>,
        keys: Option<TestHybridSigner>,
    }

    fn accounts(signed: bool) -> Vec<Account> {
        (0..N)
            .map(|i| {
                if signed {
                    let signer = TestHybridSigner::random();
                    Account {
                        address: signer.address().as_bytes().to_vec(),
                        keys: Some(signer),
                    }
                } else {
                    Account {
                        address: addr(i),
                        keys: None,
                    }
                }
            })
            .collect()
    }

    fn block(senders: &[Account], hot: bool) -> Vec<VmTransaction> {
        senders
            .iter()
            .enumerate()
            .map(|(i, sender)| {
                let to = if hot { addr(1_000_000) } else { addr(N + i) };
                let mut tx = VmTransaction::new(
                    sender.address.clone(),
                    Some(to),
                    1_000,
                    Vec::new(),
                    21_000,
                    BASE_FEE,
                    0,
                    VmType::Tenzro,
                    VmConfig::default().chain_id,
                );
                if let Some(signer) = &sender.keys {
                    let mut digest = [0u8; 32];
                    digest[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    let sig = signer.sign(SignatureContext::Transaction, &digest).unwrap();
                    tx.signature = Some(sig);
                    tx.public_key = Some(signer.public_key().p256.clone());
                    tx.signing_digest = Some(digest.to_vec());
                }
                tx
            })
            .collect()
    }

    fn funded(senders: &[Account]) -> StateAdapter {
        let mut s = StateAdapter::new();
        for sender in senders {
            s.set_balance(&sender.address, 1_000_000_000_000_000_000);
        }
        s
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let runtime = rt
        .block_on(MultiVmRuntime::new(VmConfig::default()))
        .unwrap();

    let mut group = c.benchmark_group("block_stm");
    group.sample_size(10);

    for signed in [false, true] {
        let senders = accounts(signed);
        for (shape, hot) in [("distinct", false), ("hot_recipient", true)] {
            let name = if signed {
                format!("signed_{shape}")
            } else {
                shape.to_string()
            };
            let txs = block(&senders, hot);

            group.bench_function(BenchmarkId::new(&name, "sequential"), |b| {
                b.iter_batched(
                    || funded(&senders),
                    |mut state| {
                        rt.block_on(async {
                            let mut fees = BlockFees::default();
                            for tx in &txs {
                                black_box(
                                    execute_in_block(&runtime, &mut state, tx, BASE_FEE, &mut fees)
                                        .await,
                                );
                            }
                        })
                    },
                    BatchSize::LargeInput,
                );
            });

            for workers in [2usize, 4, 8] {
                let config = BlockStmConfig {
                    workers,
                    min_parallel_run: 2,
                };
                group.bench_function(BenchmarkId::new(&name, format!("workers_{workers}")), |b| {
                    b.iter_batched(
                        || funded(&senders),
                        |mut state| {
                            rt.block_on(async {
                                let mut fees = BlockFees::default();
                                black_box(
                                    execute_block(
                                        &runtime, &mut state, &txs, BASE_FEE, &mut fees, &config,
                                    )
                                    .await,
                                );
                            })
                        },
                        BatchSize::LargeInput,
                    );
                });
            }
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_evm_transfer,
    bench_state_adapter,
    bench_gas_estimation,
    bench_block_stm,
);
criterion_main!(benches);
