//! Crash-recovery integration tests for `RocksDbStore`.
//!
//! These tests follow the same pattern RocksDB's `db_stress` +
//! `db_crashtest.py` use and the one FoundationDB documented in their 2026
//! TSS analysis: a child process drives the DB through a known write
//! sequence; the parent kills it with `SIGKILL` mid-sequence; the parent
//! reopens the DB and asserts that **everything reported as fsync'd by the
//! child survived** and that the DB never refuses to open afterward.
//!
//! Process model
//! -------------
//!
//! Each test binary is its own executable. We re-exec the current test
//! binary as the child with `TENZRO_STORAGE_CRASH_CHILD=1` set in the env;
//! when the child sees that env var on entry, it skips the test harness
//! entirely and runs `child_main(...)` instead. The parent reads the child's
//! stdout for "synced N" markers (flushed line-by-line after each
//! `write_batch_sync`), kills the child once it has observed at least
//! `min_synced` markers, then reopens the DB and verifies the survivors.
//!
//! This is the *only* way to faithfully simulate process death in Rust —
//! `panic!()` runs destructors, `std::process::exit()` runs `at_exit`
//! handlers; neither matches a real kernel-level SIGKILL on the running
//! process. Using a subprocess + `kill(SIGKILL)` from the parent is the
//! pattern used by every mature crash-consistency suite (LevelDB, RocksDB,
//! etcd, TiKV, FoundationDB).

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Serializes parent-side child spawning across `#[test]` threads. Without
/// this, two `cargo test` worker threads can race on `current_exe()`,
/// stdout pipe setup, and the SIGKILL/wait combo, which produces flaky
/// "0 markers observed" failures because pipe reads start before the
/// child has finished its harness startup. With this lock, only one
/// child runs at a time even under default parallel `cargo test`.
fn spawn_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

use tenzro_storage::{CF_STATE, KvStore, RocksDbStore, WriteOp};

/// Env var the parent sets when re-execing the test binary as the child
/// crash-driver. Carries `<db-path>;<batches-to-write>` so the child knows
/// where to open and how far to push before sleeping.
const CHILD_ENV: &str = "TENZRO_STORAGE_CRASH_CHILD";

/// Marker the child writes to stdout after every `write_batch_sync` returns.
/// The parent reads markers line-by-line and only kills once it has seen at
/// least `min_synced` of them — the post-condition we verify is "every
/// marker-reported batch is present after reopen".
const SYNCED_MARKER: &str = "synced ";

fn unique_temp_db_path(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "tenzro-storage-crash-{}-{}-{}-{}",
        label, pid, id, nanos
    ))
}

/// Entrypoint when re-execed as the child. Opens the DB, writes
/// `batches` of `write_batch_sync` (each batch is a single Put under
/// `CF_STATE` with a known shape), prints the marker for each completed
/// fsync, then sleeps forever waiting for the parent's SIGKILL.
///
/// The body deliberately does NOT call any cleanup logic — the whole point
/// is that the process dies abruptly.
fn child_main(db_path: PathBuf, batches: u64) -> ! {
    // No `?` operator — we want explicit aborts on any setup failure so the
    // parent sees a non-zero exit rather than a hang.
    let store = match RocksDbStore::open_default(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("child: open_default failed: {}", e);
            std::process::exit(101);
        }
    };

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    for i in 0..batches {
        let key = format!("crash-key-{}", i).into_bytes();
        let value = format!("crash-value-{}", i).into_bytes();
        let ops = vec![WriteOp::Put {
            cf: CF_STATE.to_string(),
            key,
            value,
        }];
        if let Err(e) = store.write_batch_sync(ops) {
            eprintln!("child: write_batch_sync failed at i={}: {}", i, e);
            std::process::exit(102);
        }
        // Print AFTER write_batch_sync returns Ok — this is our durability
        // claim to the parent.
        if writeln!(handle, "{}{}", SYNCED_MARKER, i).is_err() {
            std::process::exit(103);
        }
        if handle.flush().is_err() {
            std::process::exit(104);
        }
    }

    // All requested batches done — signal "done" and sleep forever waiting
    // for kill. The parent can then either kill here (post-completion crash)
    // or earlier (mid-sequence crash).
    let _ = writeln!(handle, "done");
    let _ = handle.flush();
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// Common parent-side driver. Spawns the child, waits for at least
/// `min_synced` markers, kills it with SIGKILL, then returns the highest
/// `n` observed in `synced N` markers.
fn run_child_until_synced(db_path: &std::path::Path, batches: u64, min_synced: u64) -> u64 {
    // Serialize across test threads — see `spawn_lock` docs.
    let _guard = spawn_lock().lock().expect("spawn_lock poisoned");

    let test_binary = std::env::current_exe().expect("current_exe");
    let child_arg = format!("{};{}", db_path.display(), batches);

    // We re-exec the test binary and ask the harness to run the
    // `child_driver` test specifically. That test checks the env var at
    // entry and switches to `child_main` — so the harness runs exactly
    // one test which never returns control to libtest. Passing
    // `--nocapture` would just inherit stdout, but we use `Stdio::piped()`
    // for line-by-line marker observation.
    let mut child = Command::new(&test_binary)
        .env(CHILD_ENV, &child_arg)
        .arg("--exact")
        .arg("--quiet")
        .arg("--nocapture")
        .arg("child_driver")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");

    let stdout = child.stdout.take().expect("child stdout");
    let reader = BufReader::new(stdout);

    let mut highest_synced: u64 = 0;
    let mut synced_count: u64 = 0;
    let start = std::time::Instant::now();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Some(rest) = line.strip_prefix(SYNCED_MARKER)
            && let Ok(n) = rest.parse::<u64>()
        {
            highest_synced = highest_synced.max(n);
            synced_count += 1;
            if synced_count >= min_synced {
                break;
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            break;
        }
    }

    // If we did not reach the requested marker count, surface the child's
    // stderr to help debug — most common failure is the harness reporting
    // "no such test" or rocksdb open failing.
    if synced_count < min_synced
        && let Some(mut stderr) = child.stderr.take()
    {
        use std::io::Read;
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        if !buf.is_empty() {
            eprintln!(
                "child stderr (only saw {} markers, expected {}):\n{}",
                synced_count, min_synced, buf
            );
        }
    }

    // SIGKILL — does NOT run drop. The DB inside the child does not get a
    // chance to flush memtables or close cleanly.
    let _ = child.kill();
    let _ = child.wait();

    highest_synced
}

/// Trampoline `#[test]` the parent invokes by name when re-execing this
/// binary. When `TENZRO_STORAGE_CRASH_CHILD` is set, this test reads the
/// arg, runs `child_main` (which never returns), and the harness waits
/// forever until the parent kills the process. When the env var is NOT
/// set, this test is a no-op so a regular `cargo test` run stays green.
#[test]
fn child_driver() {
    if let Ok(arg) = std::env::var(CHILD_ENV) {
        let (path_str, batches_str) = arg
            .split_once(';')
            .expect("CHILD_ENV format: <path>;<batches>");
        let path = PathBuf::from(path_str);
        let batches: u64 = batches_str.parse().expect("batches parse");
        child_main(path, batches);
    }
}

#[test]
fn fsynced_writes_survive_sigkill() {
    // Parent path. Belt-and-braces: also short-circuit here if the env
    // var is set, so this test isn't picked up if someone runs the
    // binary with `--exact fsynced_writes_survive_sigkill` from a
    // crash-child context.
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }

    let db_path = unique_temp_db_path("fsync-survive");
    // Ask the child to perform 200 fsync'd batches. We wait until at least
    // 20 are reported, then SIGKILL. `observed` is the highest 0-based
    // marker index seen, so observing 20 markers means `observed >= 19`.
    let observed = run_child_until_synced(&db_path, 200, 20);
    assert!(
        observed >= 19,
        "expected at least index 19 (=20 markers), saw {}",
        observed
    );

    // Reopen and assert every observed-as-synced batch survived. Anything
    // strictly past `observed` may or may not survive depending on whether
    // its marker was buffered in the pipe at kill time — we make no claim
    // about those.
    let store = RocksDbStore::open_default(&db_path).expect("reopen after kill");
    for i in 0..=observed {
        let key = format!("crash-key-{}", i).into_bytes();
        let value = store.get(CF_STATE, &key).expect("get after reopen");
        assert!(
            value.is_some(),
            "key crash-key-{} was reported synced but missing after SIGKILL+reopen",
            i
        );
        assert_eq!(
            value.unwrap(),
            format!("crash-value-{}", i).into_bytes(),
            "key crash-key-{} value mismatch after reopen",
            i
        );
    }
    drop(store);

    let _ = std::fs::remove_dir_all(&db_path);
}

#[test]
fn reopen_succeeds_after_sigkill_mid_write() {
    // Child-context short-circuit (see fsynced_writes_survive_sigkill).
    if std::env::var(CHILD_ENV).is_ok() {
        return;
    }

    // Even tighter test: only wait for 5 synced markers, then SIGKILL. The
    // DB still must reopen — `RocksDbStore::open_default` already has the
    // auto-repair-on-corruption branch wired in via the production open
    // path. This is the test that exercises that branch after an actual
    // process kill, not a synthetic WAL truncation.
    let db_path = unique_temp_db_path("reopen-mid-write");
    let observed = run_child_until_synced(&db_path, 100, 5);
    assert!(
        observed >= 4,
        "child died before 5 sync markers (observed index = {})",
        observed
    );

    let store = RocksDbStore::open_default(&db_path).expect("reopen after SIGKILL");
    // Confirm we can read at least one of the surviving keys.
    let v = store
        .get(CF_STATE, format!("crash-key-{}", observed).as_bytes())
        .expect("read after reopen");
    assert!(
        v.is_some(),
        "last-reported synced key crash-key-{} missing after kill+reopen",
        observed
    );
    drop(store);

    let _ = std::fs::remove_dir_all(&db_path);
}
