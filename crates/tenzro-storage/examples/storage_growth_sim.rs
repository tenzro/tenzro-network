//! Storage-growth simulation. Replays the per-block write pattern of an
//! otherwise-idle validator (no user transactions, just consensus + block
//! housekeeping) for a configurable number of blocks, then reports on-disk
//! size broken down by SST vs WAL vs other. Run the same workload under the
//! current ("baseline") RocksDB options and a "tuned" config so the two can
//! be compared directly.
//!
//! Usage:
//!   cargo run --release --example storage_growth_sim -- <blocks> <baseline|tuned> <dir>
//!
//! It deliberately does NOT depend on tenzro-storage's own open(): it builds
//! the Options inline so baseline exactly mirrors kv.rs::open + the bare
//! Options::default() per-CF descriptors, and tuned is the proposed fix. That
//! way the sim is a faithful model of what the node actually does on disk.

use rocksdb::{ColumnFamilyDescriptor, DB, Options, WriteBatch, WriteOptions};
use std::path::Path;
use std::time::Instant;

// The hot keys an idle validator overwrites every block. These are the keys
// whose *superseded versions* pile up in un-compacted SSTs and uncapped WAL —
// the empty-chain bloat mechanism. Sizes are representative of the real rows.
const HOT_KEYS_PER_BLOCK: &[(&str, &str, usize)] = &[
    // (cf, logical key, value size in bytes)
    ("metadata", "latest_height", 8),
    ("metadata", "latest_block_hash", 32),
    ("metadata", "consensus_view", 8),
    ("metadata", "high_qc", 256), // quorum cert blob, rewritten each view
    ("metadata", "finality_marker", 48),
    ("state", "validator_set", 512),   // re-serialized each block
    ("audit", "last_vote_marker", 75), // bounded vote (pruned), still churns
];

// Per-block append-only rows (block index). These are NOT overwrites — they
// legitimately grow, but slowly: ~3 small rows/block. Included so the sim's
// "legitimate" floor is realistic and we can see how much is genuine vs churn.
const APPEND_ROWS_PER_BLOCK: &[(&str, usize)] = &[
    ("blocks", 200), // block by hash
    ("blocks", 40),  // height -> hash index
    ("blocks", 16),  // hash -> height index
];

// The node runs 35 column families. Only a handful are written on an idle
// chain (the HOT_KEYS_PER_BLOCK / APPEND_ROWS_PER_BLOCK CFs above); the other
// ~31 are effectively idle. That asymmetry is the crux of facebook/rocksdb#662:
// max_total_wal_size flushes the ONE CF holding the oldest WAL, but the old
// WAL file can't be deleted while the other 31 idle CFs still have unflushed
// (here: zero) data pinning earlier log segments. So with many CFs the WAL cap
// barely reclaims anything — which is what production showed (375–640 MB live
// WAL above a 256 MB cap, climbing). The earlier 4-CF sim never hit this.
fn cfs() -> Vec<String> {
    let mut v: Vec<String> = vec![
        "blocks".into(),
        "state".into(),
        "metadata".into(),
        "audit".into(),
    ];
    for i in 0..31 {
        v.push(format!("idle_cf_{i}"));
    }
    v
}

fn cf_descriptors(tuned: bool) -> Vec<ColumnFamilyDescriptor> {
    cfs()
        .iter()
        .map(|name| {
            let mut o = Options::default();
            if tuned {
                // Mirrors kv.rs::cf_options after the fix: a periodic-
                // compaction floor + dynamic leveling so reclamation keeps
                // pace with hot-key churn on a low-write chain.
                o.set_periodic_compaction_seconds(24 * 60 * 60);
                o.set_level_compaction_dynamic_level_bytes(true);
                o.set_compression_type(rocksdb::DBCompressionType::Lz4);
            } else {
                // Baseline = exactly what kv.rs did: bare default per CF.
            }
            ColumnFamilyDescriptor::new(name.clone(), o)
        })
        .collect()
}

/// Which storage option set to model.
#[derive(Clone, Copy, PartialEq)]
enum Policy {
    /// Stock RocksDB defaults (no WAL/memtable tuning at all).
    Baseline,
    /// The earlier "fix" that turned WAL ARCHIVAL ON via set_wal_size_limit_mb.
    /// This is the configuration that bloated: live WAL stayed small but
    /// every rotated log was moved to db/archive and parked there.
    ArchivedWal,
    /// The corrected policy: aggregate memtable budget + a live-WAL ceiling, with WAL
    /// archival left OFF so rotated logs are deleted as soon as they flush.
    Tuned,
}

fn db_options(policy: Policy) -> Options {
    let mut opts = Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);
    opts.set_max_open_files(1000);
    opts.set_write_buffer_size(64 * 1024 * 1024);
    opts.set_max_write_buffer_number(3);
    opts.set_target_file_size_base(64 * 1024 * 1024);
    opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
    match policy {
        Policy::Baseline => {}
        Policy::ArchivedWal => {
            opts.set_db_write_buffer_size(128 * 1024 * 1024);
            opts.set_max_total_wal_size(128 * 1024 * 1024);
            // The bug: a non-zero size limit enables archival. Rotated WALs are
            // MOVED to db/archive, not deleted, and only purged once the archive
            // itself passes this limit — so it parks at hundreds of MB forever.
            opts.set_wal_size_limit_mb(256);
            opts.set_keep_log_file_num(4);
        }
        Policy::Tuned => {
            // Aggregate memtable budget across all CFs.
            opts.set_db_write_buffer_size(128 * 1024 * 1024);
            // Live-WAL ceiling: force-flush CFs pinning the oldest log past this.
            opts.set_max_total_wal_size(128 * 1024 * 1024);
            // WAL archival left OFF (wal_size_limit_mb = wal_ttl_seconds = 0):
            // rotated logs are deleted as soon as their data is in SST.
        }
    }
    opts
}

fn dir_size_breakdown(path: &Path) -> (u64, u64, u64) {
    // Returns (sst_bytes, wal_bytes, other_bytes). Recurses so the db/archive
    // subdir (where archived WAL lands when archival is on) is counted — the
    // top-level-only version hid the archive bloat that was the real leak.
    let mut sst = 0u64;
    let mut wal = 0u64;
    let mut other = 0u64;
    for entry in std::fs::read_dir(path).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            let (s, w, o) = dir_size_breakdown(&p);
            sst += s;
            wal += w;
            other += o;
            continue;
        }
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        match p.extension().and_then(|e| e.to_str()) {
            Some("sst") => sst += len,
            // Live WAL (db/*.log) and archived WAL (db/archive/*.log) both
            // count as WAL on-disk cost.
            Some("log") => wal += len,
            _ => other += len,
        }
    }
    (sst, wal, other)
}

fn mb(b: u64) -> f64 {
    b as f64 / (1024.0 * 1024.0)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let blocks: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(100_000);
    let mode = args.get(2).map(|s| s.as_str()).unwrap_or("baseline");
    let dir = args
        .get(3)
        .cloned()
        .unwrap_or_else(|| format!("/tmp/tenzro_growth_sim_{mode}"));
    let policy = match mode {
        "tuned" => Policy::Tuned,
        "archived" => Policy::ArchivedWal,
        _ => Policy::Baseline,
    };
    // `tuned` here means "apply the per-CF tuning + flush-on-open path"; both
    // the real fix and the archived-WAL variant share it.
    let tuned = policy != Policy::Baseline;

    // `rescue` mode reopens an ALREADY-bloated DB (produced by a prior `archived`
    // run at the same dir) using the real Tuned options, which flush every CF on
    // open AND have archival OFF. This is the exact production scenario: a
    // validator whose RocksDB already carries hundreds of MB of archived WAL,
    // restarted onto the fixed binary. It must show the accumulated WAL DROP.
    if mode == "rescue" {
        let (sst0, wal0, other0) = dir_size_breakdown(Path::new(&dir));
        println!(
            "rescue: reopening existing DB at {dir}\n  BEFORE: total={:.1}MB sst={:.1}MB wal={:.1}MB other={:.1}MB",
            mb(sst0 + wal0 + other0),
            mb(sst0),
            mb(wal0),
            mb(other0)
        );
        {
            let db =
                DB::open_cf_descriptors(&db_options(Policy::Tuned), &dir, cf_descriptors(true))
                    .unwrap();
            let names = cfs();
            let handles: Vec<_> = names.iter().map(|n| db.cf_handle(n).unwrap()).collect();
            let mut fopts = rocksdb::FlushOptions::default();
            fopts.set_wait(true);
            db.flush_cfs_opt(&handles, &fopts).unwrap();
            // Drop closes the DB; RocksDB deletes WALs whose data is now in SST.
        }
        let (sst1, wal1, other1) = dir_size_breakdown(Path::new(&dir));
        println!(
            "  AFTER : total={:.1}MB sst={:.1}MB wal={:.1}MB other={:.1}MB",
            mb(sst1 + wal1 + other1),
            mb(sst1),
            mb(wal1),
            mb(other1)
        );
        println!(
            "  WAL reclaimed: {:.1}MB -> {:.1}MB ({:.0}% freed)",
            mb(wal0),
            mb(wal1),
            if wal0 > 0 {
                100.0 * (wal0 - wal1) as f64 / wal0 as f64
            } else {
                0.0
            }
        );
        return;
    }

    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    println!(
        "sim: blocks={blocks} mode={mode} tuned={tuned} dir={dir}\n\
         modeling an idle validator: {} hot-key overwrites + {} append rows per block",
        HOT_KEYS_PER_BLOCK.len(),
        APPEND_ROWS_PER_BLOCK.len()
    );

    let db = DB::open_cf_descriptors(&db_options(policy), &dir, cf_descriptors(tuned)).unwrap();

    let mut wopts = WriteOptions::default();
    wopts.set_sync(true); // matches write_batch_sync in kv.rs

    // Seed every idle CF once so the DB matches a real validator (all 35 CFs
    // have some data). Under the archived-WAL policy this still bloats because
    // rotated logs are kept in db/archive regardless of which CF they came from.
    {
        let mut seed = WriteBatch::default();
        for name in cfs() {
            if !["blocks", "state", "metadata", "audit"].contains(&name.as_str()) {
                let h = db.cf_handle(&name).unwrap();
                seed.put_cf(&h, b"seed", [7u8; 64]);
            }
        }
        db.write_opt(seed, &wopts).unwrap();
    }

    // Tuned mode flushes every CF once on open, exactly like kv.rs::open after
    // the fix — this releases the WAL pinned by the seeded idle CFs.
    if tuned {
        let names = cfs();
        let handles: Vec<_> = names.iter().map(|n| db.cf_handle(n).unwrap()).collect();
        let mut fopts = rocksdb::FlushOptions::default();
        fopts.set_wait(true);
        db.flush_cfs_opt(&handles, &fopts).unwrap();
    }

    let start = Instant::now();
    let mut append_counter: u64 = 0;

    for h in 0..blocks {
        let mut batch = WriteBatch::default();

        // Hot-key overwrites: SAME key each block, new value. This is what
        // generates superseded versions that compaction must reclaim.
        for (cf, key, vsize) in HOT_KEYS_PER_BLOCK {
            let handle = db.cf_handle(cf).unwrap();
            let mut val = vec![0u8; *vsize];
            val[..8.min(*vsize)].copy_from_slice(&h.to_le_bytes()[..8.min(*vsize)]);
            batch.put_cf(&handle, key.as_bytes(), &val);
        }

        // Append rows: unique key each block, legitimate growth.
        for (cf, vsize) in APPEND_ROWS_PER_BLOCK {
            let handle = db.cf_handle(cf).unwrap();
            let key = format!("blk:{append_counter}");
            append_counter += 1;
            let val = vec![1u8; *vsize];
            batch.put_cf(&handle, key.as_bytes(), val);
        }

        db.write_opt(batch, &wopts).unwrap();

        // NOTE: no manual flush/compaction here. The whole point is to prove
        // the *config* bounds storage on its own. In `tuned` mode the
        // max_total_wal_size cap forces RocksDB to flush the oldest CFs once
        // live WAL crosses the cap, which both bounds WAL and moves data into
        // SSTs that periodic compaction then keeps reclaimed. Baseline has no
        // cap and no periodic floor, so nothing ever forces the flush.

        if h > 0 && h % 50_000 == 0 {
            let (sst, wal, other) = dir_size_breakdown(Path::new(&dir));
            println!(
                "  block {h:>8}: total={:>8.1}MB  sst={:>8.1}MB  wal={:>8.1}MB  other={:>6.1}MB  ({:?})",
                mb(sst + wal + other),
                mb(sst),
                mb(wal),
                mb(other),
                start.elapsed()
            );
        }
    }

    // Final on-disk size as it would sit after the process exits WITHOUT a
    // clean compaction (baseline) vs after the periodic compaction (tuned).
    db.flush().ok();
    let (sst, wal, other) = dir_size_breakdown(Path::new(&dir));
    let total = sst + wal + other;

    // Theoretical floor: only the append rows are genuine data.
    let append_bytes_per_block: u64 = APPEND_ROWS_PER_BLOCK.iter().map(|(_, s)| *s as u64).sum();
    let genuine = append_bytes_per_block * blocks;

    println!("\n=== RESULT mode={mode} blocks={blocks} ===");
    println!("  total on-disk : {:>10.1} MB", mb(total));
    println!("    sst         : {:>10.1} MB", mb(sst));
    println!("    wal         : {:>10.1} MB", mb(wal));
    println!("    other       : {:>10.1} MB", mb(other));
    println!(
        "  genuine data  : {:>10.1} MB (append rows only)",
        mb(genuine)
    );
    println!(
        "  bloat factor  : {:>10.1}x over genuine data",
        total as f64 / genuine.max(1) as f64
    );
    println!("  bytes/block   : {:>10.1}", total as f64 / blocks as f64);
}
