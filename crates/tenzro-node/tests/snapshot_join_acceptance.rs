//! Acceptance: a wiped non-validator node joins by snapshot, over real
//! iroh endpoints and real RocksDB stores, and refuses a snapshot it cannot
//! tie to the checkpoint it trusts.
//!
//! The producer and the joiner are two iroh endpoints on loopback with
//! blob stores of their own on disk; nothing is shared between them but the
//! network path. `F29_ACCOUNTS` scales the state (default 50,000 accounts);
//! `F29_VALUE_BYTES` sizes each record (default 160). Every measurement is
//! printed as an `SNAPSHOT-METRIC` line.
//!
//! Bars checked: time to restore under five minutes, disk used by the
//! joiner (store plus the transient blob copy) under 1 GiB, and a snapshot
//! that is stale, foreign or anchored to the wrong block refused with
//! nothing written.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tenzro_consensus::STATE_ROOT_LAG;
use tenzro_iroh::{IrohBackedResolver, TenzroIrohConfig};
use tenzro_node::snapshot::{
    BlobStore, IrohSnapshotTransport, SnapshotConfig, SnapshotStore, state_sync,
};
use tenzro_node::state_commitment::{EpochRecord, EpochValidator, epoch_key};
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::state_trie::{NS_EPOCH, StateTrie};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{BlockStoreImpl, CF_ACCOUNTS, KvStore, RocksDbStore, WriteOp};
use tenzro_types::block::{Block, BlockHeader};
use tenzro_types::primitives::{Address, BlockHeight, Hash};

const HEIGHT: u64 = 10_000;
const EPOCH_DURATION: u64 = 10_000;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Bytes of the tree under `path`.
fn dir_bytes(path: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// This process's cumulative I/O counters.
#[derive(Debug, Clone, Copy, Default)]
struct Io {
    read_bytes: u64,
    write_bytes: u64,
    rchar: u64,
    wchar: u64,
}

fn io() -> Io {
    let text = std::fs::read_to_string("/proc/self/io").unwrap_or_default();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    Io {
        read_bytes: field("read_bytes:"),
        write_bytes: field("write_bytes:"),
        rchar: field("rchar:"),
        wchar: field("wchar:"),
    }
}

fn io_since(before: Io) -> Io {
    let now = io();
    Io {
        read_bytes: now.read_bytes - before.read_bytes,
        write_bytes: now.write_bytes - before.write_bytes,
        rchar: now.rchar - before.rchar,
        wchar: now.wchar - before.wchar,
    }
}

/// Samples the combined size of `dirs` until stopped, keeping the peak.
struct PeakDisk {
    peak: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

impl PeakDisk {
    fn start(dirs: Vec<PathBuf>) -> Self {
        let peak = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (p, s) = (peak.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let total: u64 = dirs.iter().map(|d| dir_bytes(d)).sum();
                p.fetch_max(total, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(40));
            }
            let total: u64 = dirs.iter().map(|d| dir_bytes(d)).sum();
            p.fetch_max(total, Ordering::Relaxed);
        });
        Self { peak, stop, handle }
    }

    fn finish(self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap();
        self.peak.load(Ordering::Relaxed)
    }
}

/// A producer chain: committed state at [`HEIGHT`] (`accounts` records of
/// `value_len` bytes, derived from `salt`, and an epoch record) and blocks
/// `HEIGHT ..= HEIGHT + LAG`, the last committing the state root. Returns the
/// store and the hash of the last block, the trusted checkpoint.
async fn chain(
    dir: &Path,
    accounts: u64,
    value_len: usize,
    salt: u64,
) -> (Arc<RocksDbStore>, Hash) {
    let store = Arc::new(RocksDbStore::open_default(dir).unwrap());
    let trie = StateTrie::new(store.clone() as Arc<dyn KvStore>);
    let mut writes = Writes::new();
    let mut ops = Vec::new();
    for i in 0..accounts {
        let key: Vec<u8> = Sha256::digest(i.to_le_bytes()).to_vec();
        let mut value = Sha256::digest((i ^ salt).to_le_bytes()).to_vec();
        value.resize(value_len, (i % 251) as u8);
        ops.push(WriteOp::Put {
            cf: CF_ACCOUNTS.to_string(),
            key: key.clone(),
            value: value.clone(),
        });
        writes.insert((CF_ACCOUNTS.to_string(), key), Some(value));
        if ops.len() == 50_000 {
            store.write_batch(std::mem::take(&mut ops)).unwrap();
        }
    }
    let record = EpochRecord {
        number: 1,
        start_height: HEIGHT,
        validators: vec![EpochValidator {
            address: Address::new([3u8; 32]),
            ml_dsa_public_key: tenzro_crypto::pq::MlDsaSigningKey::generate()
                .verifying_key_bytes()
                .to_vec(),
            p256_public_key: tenzro_crypto::P256KeyPair::generate()
                .public_key_sec1()
                .to_vec(),
            node_key: [4u8; 32],
            stake: 1000,
        }],
    };
    writes.insert(
        (NS_EPOCH.to_string(), epoch_key(1)),
        Some(bincode::serialize(&record).unwrap()),
    );
    store.write_batch(ops).unwrap();
    let root = trie.commit(HEIGHT, &writes).unwrap();

    let mut blocks = BlockStoreImpl::new(store.clone()).unwrap();
    let mut prev = Hash::new([1u8; 32]);
    let mut last = Hash::zero();
    for h in HEIGHT - 1..=HEIGHT + STATE_ROOT_LAG {
        let state_root = if h == HEIGHT + STATE_ROOT_LAG {
            root
        } else {
            Hash::new([h as u8; 32])
        };
        let mut header = BlockHeader::new(
            BlockHeight(h),
            prev,
            Hash::zero(),
            state_root,
            Address::new([2u8; 32]),
        );
        header.epoch = if h >= HEIGHT { 1 } else { 0 };
        let block = Block::new(header, vec![]);
        prev = block.hash();
        last = prev;
        blocks.put_block(&block).await.unwrap();
    }
    (store, last)
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A node's iroh endpoint on loopback with a blob store under `root`.
async fn endpoint(root: &Path, dial_only: bool) -> Arc<IrohBackedResolver> {
    let mut cfg = TenzroIrohConfig::with_data_dir(root.to_path_buf());
    cfg.bind_addr = SocketAddr::from(([127, 0, 0, 1], free_port()));
    cfg.port_mapping = false;
    let cfg = if dial_only { cfg.dial_only() } else { cfg };
    IrohBackedResolver::bind_with_config(&cfg, None)
        .await
        .expect("bind iroh endpoint")
}

struct Producer {
    store: Arc<RocksDbStore>,
    resolver: Arc<IrohBackedResolver>,
    snapshots: Arc<SnapshotStore>,
    peer: tenzro_iroh::EndpointId,
    addr: SocketAddr,
    anchor: Hash,
    iroh_dir: PathBuf,
    db_dir: PathBuf,
}

async fn producer(root: &Path, accounts: u64, value_len: usize, salt: u64) -> Producer {
    let db_dir = root.join("db");
    let (store, anchor) = chain(&db_dir, accounts, value_len, salt).await;
    let resolver = endpoint(root, false).await;
    let transport = Arc::new(IrohSnapshotTransport::new(resolver.clone(), None));
    let snapshots = Arc::new(SnapshotStore::new(
        store.clone(),
        transport,
        SnapshotConfig::default().resolved(true),
    ));
    resolver.snapshot_directory().set(snapshots.clone());
    let addr = *resolver
        .endpoint()
        .bound_sockets()
        .first()
        .expect("a bound socket");
    Producer {
        store,
        peer: resolver.endpoint_id(),
        resolver,
        snapshots,
        addr,
        anchor,
        iroh_dir: root.join("iroh"),
        db_dir,
    }
}

struct Joiner {
    store: Arc<RocksDbStore>,
    resolver: Arc<IrohBackedResolver>,
    db_dir: PathBuf,
    iroh_dir: PathBuf,
}

/// A wiped node: an empty store and a dial-only endpoint that knows where
/// the producer is.
async fn joiner(root: &Path, producer: &Producer) -> Joiner {
    let db_dir = root.join("db");
    let store = Arc::new(RocksDbStore::open_default(&db_dir).unwrap());
    let resolver = endpoint(root, true).await;
    resolver
        .remember_addr(
            tenzro_iroh::parse_peer(&format!("{}@{}", producer.peer, producer.addr)).unwrap(),
        )
        .unwrap();
    Joiner {
        store,
        resolver,
        db_dir,
        iroh_dir: root.join("iroh").join("state-sync"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wiped_node_joins_by_snapshot_within_the_bars() {
    let accounts = env_u64("F29_ACCOUNTS", 50_000);
    let value_len = env_u64("F29_VALUE_BYTES", 160) as usize;
    let tmp =
        tempfile::tempdir_in(std::env::var("F29_TMP").unwrap_or_else(|_| "/tmp".into())).unwrap();
    let prod = producer(&tmp.path().join("producer"), accounts, value_len, 0).await;
    println!("SNAPSHOT-METRIC accounts={accounts} value_bytes={value_len}");
    println!(
        "SNAPSHOT-METRIC producer_db_bytes_before={}",
        dir_bytes(&prod.db_dir)
    );

    // Production: one snapshot of the committed state.
    let io0 = io();
    let t0 = Instant::now();
    let manifest = prod.snapshots.produce(HEIGHT).await.expect("produce");
    let produce_time = t0.elapsed();
    let produce_io = io_since(io0);
    let blob_bytes = dir_bytes(&prod.iroh_dir.join("blobs"));
    println!(
        "SNAPSHOT-METRIC produce_secs={:.3} buckets={} published_bytes={} blob_store_bytes={} \
         io_read_bytes={} io_write_bytes={} io_rchar={} io_wchar={}",
        produce_time.as_secs_f64(),
        manifest.buckets.len(),
        prod.snapshots.published_bytes().unwrap(),
        blob_bytes,
        produce_io.read_bytes,
        produce_io.write_bytes,
        produce_io.rchar,
        produce_io.wchar
    );

    // A second snapshot of the same state: the blob store keeps every blob it
    // is given, and identical blobs are stored once.
    let before = dir_bytes(&prod.iroh_dir.join("blobs"));
    prod.snapshots.produce(HEIGHT).await.expect("produce again");
    println!(
        "SNAPSHOT-METRIC blob_store_bytes_after_second_identical_snapshot={} (was {before})",
        dir_bytes(&prod.iroh_dir.join("blobs"))
    );

    // The join: wipe, restore, verify.
    let join = joiner(&tmp.path().join("joiner"), &prod).await;
    let peak = PeakDisk::start(vec![join.db_dir.clone(), join.iroh_dir.clone()]);
    let io1 = io();
    let t1 = Instant::now();
    let transport = IrohSnapshotTransport::new(join.resolver.clone(), Some(prod.peer));
    let synced = state_sync(
        &join.store,
        &transport,
        &transport,
        HEIGHT + STATE_ROOT_LAG,
        prod.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect("the joiner restores from the producer");
    let join_time = t1.elapsed();
    let join_io = io_since(io1);
    let peak_bytes = peak.finish();
    println!(
        "SNAPSHOT-METRIC join_secs={:.3} buckets_fetched={} joiner_db_bytes={} joiner_blob_copy_bytes={} \
         joiner_peak_disk_bytes={} io_read_bytes={} io_write_bytes={} io_rchar={} io_wchar={}",
        join_time.as_secs_f64(),
        synced.buckets_fetched,
        dir_bytes(&join.db_dir),
        dir_bytes(&join.iroh_dir),
        peak_bytes,
        join_io.read_bytes,
        join_io.write_bytes,
        join_io.rchar,
        join_io.wchar
    );

    assert_eq!(synced.state_root, manifest.state_root);
    assert_eq!(synced.height, HEIGHT);
    // Spot-check restored records against the producer's.
    for i in [0u64, accounts / 3, accounts - 1] {
        let key: Vec<u8> = Sha256::digest(i.to_le_bytes()).to_vec();
        let mut expected = Sha256::digest(i.to_le_bytes()).to_vec();
        expected.resize(value_len, (i % 251) as u8);
        assert_eq!(
            join.store.get(CF_ACCOUNTS, &key).unwrap(),
            Some(expected),
            "account {i} restored"
        );
    }
    let tip = BlockStoreImpl::new(join.store.clone())
        .unwrap()
        .get_block_by_height(BlockHeight(HEIGHT))
        .await
        .unwrap();
    assert!(
        tip.is_some(),
        "the restored height's block is the local tip"
    );

    assert!(
        join_time < Duration::from_secs(300),
        "restore took {join_time:?}"
    );
    assert!(
        peak_bytes < 1 << 30,
        "joiner disk peaked at {peak_bytes} bytes"
    );

    let _ = join.resolver.shutdown().await;
    let _ = prod.resolver.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_not_tied_to_the_trusted_checkpoint_is_refused_with_nothing_written() {
    let tmp = tempfile::tempdir().unwrap();
    // The honest chain, and an attacker's chain with the same shape whose
    // snapshot is internally valid.
    let honest = producer(&tmp.path().join("honest"), 2_000, 160, 0).await;
    let evil = producer(&tmp.path().join("evil"), 2_000, 160, 99).await;
    assert_ne!(honest.anchor, evil.anchor);
    evil.snapshots.produce(HEIGHT).await.unwrap();
    honest.snapshots.produce(HEIGHT).await.unwrap();

    let account = |i: u64| Sha256::digest(i.to_le_bytes()).to_vec();

    // 1. The joiner trusts the honest block and asks the attacker.
    let j1 = joiner(&tmp.path().join("j1"), &evil).await;
    let t1 = IrohSnapshotTransport::new(j1.resolver.clone(), Some(evil.peer));
    let err = state_sync(
        &j1.store,
        &t1,
        &t1,
        HEIGHT + STATE_ROOT_LAG,
        honest.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect_err("a foreign chain's snapshot is refused")
    .to_string();
    assert!(err.contains("trusted checkpoint"), "{err}");
    assert_eq!(j1.store.get(CF_ACCOUNTS, &account(5)).unwrap(), None);
    assert!(
        !tenzro_node::snapshot::restore_interrupted(&j1.store)
            .await
            .unwrap()
    );

    // 2. The right peer, a checkpoint hash with one bit flipped.
    let j2 = joiner(&tmp.path().join("j2"), &honest).await;
    let t2 = IrohSnapshotTransport::new(j2.resolver.clone(), Some(honest.peer));
    let mut wrong: [u8; 32] = honest.anchor.as_bytes().try_into().unwrap();
    wrong[7] ^= 1;
    let err = state_sync(
        &j2.store,
        &t2,
        &t2,
        HEIGHT + STATE_ROOT_LAG,
        Hash::new(wrong),
        EPOCH_DURATION,
    )
    .await
    .expect_err("a checkpoint the snapshot does not end in is refused")
    .to_string();
    assert!(err.contains("trusted checkpoint"), "{err}");
    assert_eq!(j2.store.get(CF_ACCOUNTS, &account(5)).unwrap(), None);

    // 3. Stale: the checkpoint is a later epoch than any snapshot the peer holds.
    let err = state_sync(
        &j2.store,
        &t2,
        &t2,
        HEIGHT + EPOCH_DURATION + STATE_ROOT_LAG,
        honest.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect_err("the peer holds no snapshot at the checkpoint's height")
    .to_string();
    assert!(err.contains("holds no snapshot"), "{err}");
    assert_eq!(j2.store.get(CF_ACCOUNTS, &account(5)).unwrap(), None);

    // Control: the right peer and the right checkpoint restore.
    state_sync(
        &j2.store,
        &t2,
        &t2,
        HEIGHT + STATE_ROOT_LAG,
        honest.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect("the honest snapshot is accepted");
    assert!(j2.store.get(CF_ACCOUNTS, &account(5)).unwrap().is_some());

    for r in [&j1.resolver, &j2.resolver, &honest.resolver, &evil.resolver] {
        let _ = r.shutdown().await;
    }
}

/// A transport that flips the last byte of one blob on its way in, as a peer
/// serving altered content under a valid-looking name would.
struct Tamper {
    inner: IrohSnapshotTransport,
    target: [u8; 32],
}

#[async_trait::async_trait]
impl BlobStore for Tamper {
    async fn publish(&self, bytes: Vec<u8>) -> tenzro_node::error::Result<[u8; 32]> {
        self.inner.publish(bytes).await
    }

    async fn fetch(&self, hash: &[u8; 32]) -> tenzro_node::error::Result<Vec<u8>> {
        let mut bytes = self.inner.fetch(hash).await?;
        if *hash == self.target {
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
        }
        Ok(bytes)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tampered_snapshot_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let prod = producer(&tmp.path().join("p"), 2_000, 160, 0).await;
    let manifest = prod.snapshots.produce(HEIGHT).await.unwrap();
    let account = |i: u64| Sha256::digest(i.to_le_bytes()).to_vec();

    // A bucket whose bytes were altered: the right peer, the right checkpoint.
    let j1 = joiner(&tmp.path().join("j1"), &prod).await;
    let inner = IrohSnapshotTransport::new(j1.resolver.clone(), Some(prod.peer));
    let tampered = Tamper {
        inner,
        target: manifest.buckets[0].blob,
    };
    let plain = IrohSnapshotTransport::new(j1.resolver.clone(), Some(prod.peer));
    let err = state_sync(
        &j1.store,
        &plain,
        &tampered,
        HEIGHT + STATE_ROOT_LAG,
        prod.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect_err("an altered bucket is refused");
    println!("SNAPSHOT-METRIC tampered_bucket_error={err}");
    assert!(
        j1.store.get(CF_ACCOUNTS, &account(0)).unwrap().is_none()
            || tenzro_node::snapshot::restore_interrupted(&j1.store)
                .await
                .unwrap(),
        "a refused bucket never lands as if the restore had finished"
    );

    // The anchor chain altered: nothing at all is written.
    let j2 = joiner(&tmp.path().join("j2"), &prod).await;
    let inner = IrohSnapshotTransport::new(j2.resolver.clone(), Some(prod.peer));
    let tampered = Tamper {
        inner,
        target: manifest.anchor_chain,
    };
    let plain = IrohSnapshotTransport::new(j2.resolver.clone(), Some(prod.peer));
    state_sync(
        &j2.store,
        &plain,
        &tampered,
        HEIGHT + STATE_ROOT_LAG,
        prod.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect_err("an altered anchor chain is refused");
    assert!(
        !tenzro_node::snapshot::restore_interrupted(&j2.store)
            .await
            .unwrap()
    );
    for i in [0u64, 1, 1999] {
        assert_eq!(j2.store.get(CF_ACCOUNTS, &account(i)).unwrap(), None);
    }

    // Control: the same joiner path with nothing altered restores.
    let j3 = joiner(&tmp.path().join("j3"), &prod).await;
    let ok = IrohSnapshotTransport::new(j3.resolver.clone(), Some(prod.peer));
    state_sync(
        &j3.store,
        &ok,
        &ok,
        HEIGHT + STATE_ROOT_LAG,
        prod.anchor,
        EPOCH_DURATION,
    )
    .await
    .expect("the unaltered snapshot restores");

    for r in [&j1.resolver, &j2.resolver, &j3.resolver, &prod.resolver] {
        let _ = r.shutdown().await;
    }
}

/// Appends `count` blocks after `(height, prev)` to `store`, each linked to the one before. Returns the new tip.
async fn extend(
    store: &Arc<RocksDbStore>,
    mut height: u64,
    mut prev: Hash,
    count: u64,
) -> (u64, Hash) {
    let mut blocks = BlockStoreImpl::new(store.clone()).unwrap();
    for _ in 0..count {
        height += 1;
        let mut header = BlockHeader::new(
            BlockHeight(height),
            prev,
            Hash::zero(),
            Hash::new([height as u8; 32]),
            Address::new([2u8; 32]),
        );
        header.epoch = 1;
        let block = Block::new(header, vec![]);
        prev = block.hash();
        blocks.put_block(&block).await.unwrap();
    }
    (height, prev)
}

/// Follows the producer's blocks from the joiner's tip to the producer's tip, each linked to the one before.
async fn follow(joiner: &Arc<RocksDbStore>, producer: &Arc<RocksDbStore>) -> u64 {
    let from = BlockStoreImpl::new(producer.clone()).unwrap();
    let mut to = BlockStoreImpl::new(joiner.clone()).unwrap();
    let mut tip = to.latest_height().await.unwrap().expect("a restored tip").0;
    let end = from.latest_height().await.unwrap().unwrap().0;
    let mut prev = to
        .get_block_by_height(BlockHeight(tip))
        .await
        .unwrap()
        .unwrap()
        .hash();
    let mut synced = 0;
    while tip < end {
        tip += 1;
        let block = from
            .get_block_by_height(BlockHeight(tip))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            block.header.prev_hash, prev,
            "block {tip} links to the joiner's tip"
        );
        prev = block.hash();
        to.put_block(&block).await.unwrap();
        synced += 1;
    }
    synced
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wiped_node_rejoins_at_the_producer_tip_twice() {
    let accounts = env_u64("F29_ACCOUNTS", 50_000);
    let tail = env_u64("F29_TAIL_BLOCKS", 500);
    let tmp =
        tempfile::tempdir_in(std::env::var("F29_TMP").unwrap_or_else(|_| "/tmp".into())).unwrap();
    let prod = producer(&tmp.path().join("producer"), accounts, 160, 0).await;
    let manifest = prod.snapshots.produce(HEIGHT).await.expect("produce");
    let producer_store = prod.store.clone();
    let (mut tip_height, mut tip_hash) =
        extend(&producer_store, HEIGHT + STATE_ROOT_LAG, prod.anchor, tail).await;

    for round in 1..=2 {
        // The node's disk is gone: a new directory, an empty store.
        let join = joiner(&tmp.path().join(format!("joiner{round}")), &prod).await;
        let started = Instant::now();
        let transport = IrohSnapshotTransport::new(join.resolver.clone(), Some(prod.peer));
        let synced = state_sync(
            &join.store,
            &transport,
            &transport,
            HEIGHT + STATE_ROOT_LAG,
            prod.anchor,
            EPOCH_DURATION,
        )
        .await
        .expect("restore from the producer");
        let restored = started.elapsed();
        let followed = follow(&join.store, &producer_store).await;
        let total = started.elapsed();
        println!(
            "SNAPSHOT-METRIC rejoin_round={round} accounts={accounts} restore_secs={:.3} tail_blocks={followed} rejoin_to_tip_secs={:.3}",
            restored.as_secs_f64(),
            total.as_secs_f64()
        );

        let blocks = BlockStoreImpl::new(join.store.clone()).unwrap();
        assert_eq!(
            blocks.latest_height().await.unwrap().unwrap().0,
            tip_height,
            "the joiner is at the producer tip"
        );
        let joiner_tip = blocks
            .get_block_by_height(BlockHeight(tip_height))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            joiner_tip.hash(),
            tip_hash,
            "and holds the producer's tip block"
        );
        assert_eq!(
            followed,
            tip_height - HEIGHT,
            "it fetched only the blocks after the restored height, not the history"
        );
        assert_eq!(synced.state_root, manifest.state_root);
        let key: Vec<u8> = Sha256::digest((accounts / 2).to_le_bytes()).to_vec();
        assert!(
            join.store.get(CF_ACCOUNTS, &key).unwrap().is_some(),
            "restored state is readable"
        );
        let _ = join.resolver.shutdown().await;

        // The chain moves on while the node is down; the next round starts from nothing again.
        (tip_height, tip_hash) = extend(&producer_store, tip_height, tip_hash, 200).await;
    }
    let _ = prod.resolver.shutdown().await;
}
