//! Criterion benchmarks for the tenzro-storage hot path.
//!
//! Covers:
//! - RocksDB single-key `put` / `get` / `delete`
//! - `write_batch` (async, non-fsync) for batched writes
//! - `write_batch_sync` (fsync on every commit — the path used for finalized
//!   block writes; this is what bounds block-finalization latency)
//! - Prefix scan via `get_keys_with_prefix`
//! - `MemoryStore` baseline for the same operations
//! - Merkle Patricia Trie `insert` + `root_hash` (state-commitment hot path)
//! - Trie `generate_proof` + `verify_proof` round-trip

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use tenzro_storage::{CF_STATE, KvStore, MemoryStore, MerklePatriciaTrie, RocksDbStore, WriteOp};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_db_path(label: &str) -> std::path::PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tenzro-storage-bench-{}-{}-{}-{}",
        label, pid, id, nanos
    ))
}

fn open_rocksdb(label: &str) -> (Arc<RocksDbStore>, std::path::PathBuf) {
    let path = unique_db_path(label);
    let store = RocksDbStore::open_default(&path).expect("open rocksdb");
    (Arc::new(store), path)
}

// --------------------------------- RocksDB ----------------------------------

fn bench_rocksdb_put(c: &mut Criterion) {
    let (store, _path) = open_rocksdb("put");
    let mut group = c.benchmark_group("rocksdb_put");
    let value = vec![0u8; 256];
    let mut i: u64 = 0;
    group.bench_function("256B_value", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            let key = i.to_le_bytes();
            store
                .put(CF_STATE, black_box(&key), black_box(&value))
                .expect("put");
        });
    });
    group.finish();
}

fn bench_rocksdb_get_hit(c: &mut Criterion) {
    let (store, _path) = open_rocksdb("get-hit");
    // Pre-populate 10_000 keys.
    let value = vec![0u8; 256];
    for i in 0..10_000u64 {
        store
            .put(CF_STATE, &i.to_le_bytes(), &value)
            .expect("seed put");
    }
    let mut group = c.benchmark_group("rocksdb_get");
    let mut i: u64 = 0;
    group.bench_function("hit_256B", |b| {
        b.iter(|| {
            i = (i + 1) % 10_000;
            let v = store
                .get(CF_STATE, black_box(&i.to_le_bytes()))
                .expect("get");
            black_box(v);
        });
    });
    group.finish();
}

fn bench_rocksdb_write_batch(c: &mut Criterion) {
    let (store, _path) = open_rocksdb("batch");
    let mut group = c.benchmark_group("rocksdb_write_batch");
    let mut base: u64 = 0;
    for batch_size in [10usize, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let start = base;
                        base = base.wrapping_add(size as u64);
                        (0..size)
                            .map(|j| WriteOp::Put {
                                cf: CF_STATE.to_string(),
                                key: (start + j as u64).to_le_bytes().to_vec(),
                                value: vec![0u8; 64],
                            })
                            .collect::<Vec<_>>()
                    },
                    |ops| {
                        store.write_batch(black_box(ops)).expect("write_batch");
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_rocksdb_write_batch_sync(c: &mut Criterion) {
    let (store, _path) = open_rocksdb("batch-sync");
    let mut group = c.benchmark_group("rocksdb_write_batch_sync");
    // fsync-on-commit is slow; small sample sizes are sufficient to characterise.
    group.sample_size(20);
    let mut base: u64 = 0;
    for batch_size in [10usize, 100] {
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_size),
            &batch_size,
            |b, &size| {
                b.iter_batched(
                    || {
                        let start = base;
                        base = base.wrapping_add(size as u64);
                        (0..size)
                            .map(|j| WriteOp::Put {
                                cf: CF_STATE.to_string(),
                                key: (start + j as u64).to_le_bytes().to_vec(),
                                value: vec![0u8; 64],
                            })
                            .collect::<Vec<_>>()
                    },
                    |ops| {
                        store
                            .write_batch_sync(black_box(ops))
                            .expect("write_batch_sync");
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_rocksdb_prefix_scan(c: &mut Criterion) {
    let (store, _path) = open_rocksdb("prefix");
    // Seed two prefixes — one we'll scan, one we won't.
    for i in 0..5_000u64 {
        let mut key = b"hit:".to_vec();
        key.extend_from_slice(&i.to_le_bytes());
        store.put(CF_STATE, &key, &[]).expect("seed");
    }
    for i in 0..5_000u64 {
        let mut key = b"miss:".to_vec();
        key.extend_from_slice(&i.to_le_bytes());
        store.put(CF_STATE, &key, &[]).expect("seed");
    }
    let mut group = c.benchmark_group("rocksdb_prefix_scan");
    group.bench_function("5k_matching", |b| {
        b.iter(|| {
            let keys = store
                .get_keys_with_prefix(CF_STATE, black_box(b"hit:"))
                .expect("scan");
            black_box(keys);
        });
    });
    group.finish();
}

// -------------------------------- MemoryStore -------------------------------

fn bench_memory_put_get(c: &mut Criterion) {
    let store = MemoryStore::new();
    let value = vec![0u8; 256];
    let mut group = c.benchmark_group("memory_store");
    let mut i: u64 = 0;
    group.bench_function("put_256B", |b| {
        b.iter(|| {
            i = i.wrapping_add(1);
            store
                .put(CF_STATE, &i.to_le_bytes(), black_box(&value))
                .expect("put");
        });
    });
    // Pre-populate for get.
    for k in 0..10_000u64 {
        store.put(CF_STATE, &k.to_le_bytes(), &value).expect("seed");
    }
    let mut j: u64 = 0;
    group.bench_function("get_hit_256B", |b| {
        b.iter(|| {
            j = (j + 1) % 10_000;
            let v = store.get(CF_STATE, &j.to_le_bytes()).expect("get");
            black_box(v);
        });
    });
    group.finish();
}

// ------------------------------ Merkle trie ---------------------------------

fn bench_trie_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_trie_insert");
    for size in [10usize, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &n| {
            b.iter_batched(
                MerklePatriciaTrie::new,
                |mut trie| {
                    for i in 0..n {
                        let key = (i as u64).to_le_bytes();
                        trie.insert(&key, b"v").expect("insert");
                    }
                    black_box(trie.root_hash());
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_trie_proof_roundtrip(c: &mut Criterion) {
    let mut trie = MerklePatriciaTrie::new();
    for i in 0..1_000u64 {
        trie.insert(&i.to_le_bytes(), b"v").expect("insert");
    }
    let root = trie.root_hash();
    let mut group = c.benchmark_group("merkle_trie_proof");
    let mut i: u64 = 0;
    group.bench_function("generate_proof", |b| {
        b.iter(|| {
            i = (i + 1) % 1000;
            let proof = trie.generate_proof(&i.to_le_bytes()).expect("proof");
            black_box(proof);
        });
    });
    let proof = trie.generate_proof(&500u64.to_le_bytes()).expect("proof");
    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            let ok = MerklePatriciaTrie::verify_proof(black_box(&proof), root, Some(b"v"))
                .expect("verify");
            black_box(ok);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_rocksdb_put,
    bench_rocksdb_get_hit,
    bench_rocksdb_write_batch,
    bench_rocksdb_write_batch_sync,
    bench_rocksdb_prefix_scan,
    bench_memory_put_get,
    bench_trie_insert,
    bench_trie_proof_roundtrip,
);
criterion_main!(benches);
