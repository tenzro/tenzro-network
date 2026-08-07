//! One node per data directory, refused early and said plainly.
//!
//! # What goes wrong without this
//!
//! Two nodes sharing a data directory is not a degraded configuration, it is a
//! corrupt one: they open the same RocksDB, the same keystore, and the same
//! snapshot tree. RocksDB does hold its own `LOCK` file, so the second process
//! does fail — but it fails deep inside storage initialisation with an IO error
//! naming a path, long after the banner has printed and several subsystems have
//! started. An operator reading it cannot tell whether they have a permissions
//! problem, a stale lock from a crash, or a second node they forgot about.
//!
//! Two nodes on *different* data directories fail differently and just as
//! opaquely: whichever binds second gets `EADDRINUSE` on a port, reported as an
//! address rather than as "something else is already listening there".
//!
//! This module answers both before anything is opened or bound, and names the
//! process to kill.
//!
//! # Why an flock rather than a PID file
//!
//! A bare PID file has to be cleaned up, and the one time it never is, is the
//! one that matters — a `SIGKILL`, an OOM kill, a power loss. The stale file
//! then blocks every subsequent start, so operators learn to delete it
//! reflexively, which defeats the guard.
//!
//! An advisory `flock` is released by the kernel when the holding process dies,
//! however it dies. A lock file left behind by a crash is therefore *not* held,
//! and the next start acquires it immediately. The file's contents are only
//! ever a diagnostic; the lock itself is the truth.
//!
//! # Keyed on the canonical directory
//!
//! `~/.tenzro/data/default`, `$HOME/.tenzro/data/default`, a relative
//! `./data/default`, and a symlink to any of them are one directory, and a
//! guard that treated them as four would not be a guard. The path is
//! canonicalised before the lock is taken, so aliasing cannot produce a second
//! "instance" over the same bytes.
//!
//! Genuinely separate instances — a second testnet, a scratch node — are
//! unaffected: they have their own [`tenzro_types::paths::instance_data_dir`],
//! so their canonical paths differ and both locks are granted. That is also why
//! the containerised local testnet works: each container has its own mount
//! namespace, so `/data/tenzro` is a different directory in each.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

/// File name of the per-instance lock, inside the data directory.
///
/// Deliberately alongside the data it guards rather than in `/var/run` or
/// `/tmp`: the lock's scope *is* the directory, so a data directory copied to
/// another machine or bind-mounted into a container carries no stale claim from
/// where it came from.
pub const LOCK_FILE_NAME: &str = "tenzro-node.lock";

/// Why a node may not start.
#[derive(Debug)]
pub enum InstanceError {
    /// Another live process holds the lock on this data directory.
    AlreadyRunning {
        /// Canonical data directory both processes want.
        data_dir: PathBuf,
        /// PID recorded by the holder, if the file was readable.
        pid: Option<i32>,
        /// The holder's command line, if `/proc` could supply it.
        command: Option<String>,
    },
    /// One or more of the addresses this node would bind is already taken.
    PortsBusy {
        /// Each occupied address, with the label of the service that wanted it.
        conflicts: Vec<(&'static str, String)>,
    },
    /// The lock file itself could not be opened or written.
    Unusable {
        /// The lock path that failed.
        path: PathBuf,
        /// The underlying IO error.
        source: std::io::Error,
    },
}

impl std::fmt::Display for InstanceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyRunning {
                data_dir,
                pid,
                command,
            } => {
                writeln!(
                    f,
                    "A Tenzro node is already running on this machine using the same data \
                     directory.\n"
                )?;
                writeln!(f, "  data directory  {}", data_dir.display())?;
                match pid {
                    Some(pid) => writeln!(f, "  held by         PID {pid}")?,
                    None => writeln!(f, "  held by         another process (PID unreadable)")?,
                }
                if let Some(command) = command {
                    writeln!(f, "  command         {command}")?;
                }
                writeln!(
                    f,
                    "\nTwo nodes cannot share a data directory: they would open the same RocksDB, \
                     the same keystore and the same snapshots, and corrupt all three."
                )?;
                match pid {
                    Some(pid) => write!(
                        f,
                        "\nStop the running node first:\n\n  \
                         tenzro-node graceful-exit --rpc-url http://127.0.0.1:8545   # clean, \
                         waits until it is not the leader\n  \
                         kill {pid}                                                  # or ask it \
                         to exit\n  \
                         kill -9 {pid}                                               # only if it \
                         will not\n\nOr start this one against its own directory with \
                         --data-dir, which gives it a separate instance."
                    ),
                    None => write!(
                        f,
                        "\nFind and stop it:\n\n  pgrep -af tenzro-node\n\nOr start this one \
                         against its own directory with --data-dir."
                    ),
                }
            }
            Self::PortsBusy { conflicts } => {
                writeln!(
                    f,
                    "Cannot start: {} of this node's addresses are already in use.\n",
                    conflicts.len()
                )?;
                for (label, addr) in conflicts {
                    writeln!(f, "  {label:<16} {addr}")?;
                }
                write!(
                    f,
                    "\nSomething is already listening there — most often another Tenzro node. \
                     Find it and stop it:\n\n  pgrep -af tenzro-node\n  ss -ltnp | grep -E \
                     '{}'\n\nOr move this node's listeners with --rpc-addr / --web-addr / \
                     --mcp-addr / --a2a-addr.",
                    conflicts
                        .iter()
                        .filter_map(|(_, a)| a.rsplit(':').next())
                        .collect::<Vec<_>>()
                        .join("|")
                )
            }
            Self::Unusable { path, source } => write!(
                f,
                "Could not take the single-instance lock at {}: {source}\n\nThe node refuses to \
                 start rather than risk a second instance over the same data.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for InstanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Unusable { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Proof that this process is the only node on its data directory.
///
/// Hold it for as long as the node runs. Dropping it — or the process exiting
/// by any means, including a signal it never handles — releases the lock.
#[derive(Debug)]
pub struct InstanceLock {
    /// Kept open because the lock lives on the descriptor, not the path.
    /// Closing it releases the lock, so this field is the whole point of the
    /// type even though nothing reads it.
    _file: File,
    data_dir: PathBuf,
}

impl InstanceLock {
    /// The canonical data directory this lock covers.
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

/// Take the single-instance lock for `data_dir`, creating the directory if it
/// does not exist.
///
/// # Errors
///
/// [`InstanceError::AlreadyRunning`] when another live process holds it, and
/// [`InstanceError::Unusable`] when the lock file cannot be created — a
/// read-only mount, a permissions problem. Both refuse the start; neither
/// degrades to running anyway, because the failure mode being prevented is
/// silent data corruption.
pub fn acquire(data_dir: &Path) -> Result<InstanceLock, InstanceError> {
    std::fs::create_dir_all(data_dir).map_err(|source| InstanceError::Unusable {
        path: data_dir.to_path_buf(),
        source,
    })?;

    // Canonicalise *after* creating, so the resolved path exists. Aliases —
    // `~`, a relative path, a symlink — collapse here, which is what stops two
    // spellings of one directory from taking two locks over the same bytes.
    let data_dir = data_dir
        .canonicalize()
        .map_err(|source| InstanceError::Unusable {
            path: data_dir.to_path_buf(),
            source,
        })?;
    let lock_path = data_dir.join(LOCK_FILE_NAME);

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|source| InstanceError::Unusable {
            path: lock_path.clone(),
            source,
        })?;

    // SAFETY: `file` owns a valid descriptor for the duration of the call.
    // `LOCK_NB` makes this non-blocking, so a held lock returns immediately
    // rather than parking node startup behind another process's lifetime.
    let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if !locked {
        let err = std::io::Error::last_os_error();
        // `EWOULDBLOCK` is "someone else holds it" — the case this module
        // exists for. Anything else is a real IO failure and is reported as
        // one rather than being misattributed to a running node.
        if err.raw_os_error() != Some(libc::EWOULDBLOCK) {
            return Err(InstanceError::Unusable {
                path: lock_path,
                source: err,
            });
        }
        let pid = read_pid(&mut file);
        return Err(InstanceError::AlreadyRunning {
            data_dir,
            command: pid.and_then(process_command),
            pid,
        });
    }

    // Record who holds it. Purely diagnostic — the lock is what enforces, and
    // this is what lets the *next* operator be told which PID to stop.
    let pid = std::process::id();
    let _ = file.set_len(0);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = writeln!(file, "{pid}");
    let _ = file.flush();

    Ok(InstanceLock {
        _file: file,
        data_dir,
    })
}

/// Check every address this node intends to bind, and report the ones already
/// taken.
///
/// Probing by binding and immediately closing is a time-of-check/time-of-use
/// race in principle: something could claim the port between the probe and the
/// real bind. In practice the real bind then fails as it would have anyway, so
/// the probe never makes anything worse — it only converts the common case from
/// a bare `EADDRINUSE` deep in startup into an answer naming every conflict at
/// once, before any subsystem has started.
///
/// # Errors
///
/// [`InstanceError::PortsBusy`] listing every occupied address. Reported
/// together rather than one at a time so an operator moving listeners does not
/// have to restart once per conflict to discover the next one.
pub fn check_ports(addrs: &[(&'static str, &str)]) -> Result<(), InstanceError> {
    let conflicts: Vec<(&'static str, String)> = addrs
        .iter()
        .filter(|(_, addr)| !addr.is_empty() && is_taken(addr))
        .map(|(label, addr)| (*label, (*addr).to_string()))
        .collect();

    if conflicts.is_empty() {
        Ok(())
    } else {
        Err(InstanceError::PortsBusy { conflicts })
    }
}

/// Whether `addr` currently refuses a bind.
///
/// An address that cannot be parsed or resolved is *not* reported as taken:
/// that is a configuration error, and the bind that follows will report it far
/// better than this probe could.
fn is_taken(addr: &str) -> bool {
    use std::net::{TcpListener, ToSocketAddrs};

    let Ok(mut resolved) = addr.to_socket_addrs() else {
        return false;
    };
    let Some(socket_addr) = resolved.next() else {
        return false;
    };
    match TcpListener::bind(socket_addr) {
        Ok(listener) => {
            drop(listener);
            false
        }
        Err(e) => e.kind() == std::io::ErrorKind::AddrInUse,
    }
}

/// Read the PID a previous holder recorded, if it is still legible.
fn read_pid(file: &mut File) -> Option<i32> {
    let mut contents = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_to_string(&mut contents).ok()?;
    contents.trim().parse().ok()
}

/// The holder's command line, so the operator can confirm what they are about
/// to kill before killing it.
///
/// Linux-only and best-effort: an unreadable `/proc` entry yields `None`, and
/// the error message degrades to naming the PID alone.
#[cfg(target_os = "linux")]
fn process_command(pid: i32) -> Option<String> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let command = raw
        .split(|b| *b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    (!command.is_empty()).then_some(command)
}

#[cfg(not(target_os = "linux"))]
fn process_command(_pid: i32) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_lock_is_granted_on_a_fresh_directory_and_records_our_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lock = acquire(dir.path()).expect("first acquire must succeed");

        let recorded = std::fs::read_to_string(lock.data_dir().join(LOCK_FILE_NAME))
            .expect("lock file readable");
        assert_eq!(
            recorded.trim().parse::<u32>().expect("a pid"),
            std::process::id(),
            "the lock file names the holder so the next operator knows what to stop"
        );
    }

    /// The lock lives on the descriptor, so releasing it is what a crash does
    /// for free. A second acquire after a drop must succeed — otherwise a
    /// killed node would wedge every restart and operators would learn to
    /// delete the file, defeating the guard.
    #[test]
    fn releasing_the_lock_lets_the_next_start_take_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = acquire(dir.path()).expect("first acquire");
        drop(first);
        acquire(dir.path()).expect("a released lock must be re-acquirable");
    }

    /// A stale lock *file* is not a held lock. This is the crash case: the file
    /// is left behind with a PID that is long gone.
    #[test]
    fn a_leftover_lock_file_does_not_block_a_start() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(LOCK_FILE_NAME), "999999\n").expect("write stale file");
        acquire(dir.path()).expect("a stale file is not a held lock");
    }

    /// Two spellings of one directory must not yield two locks — that would be
    /// two nodes over the same bytes, which is the whole failure being
    /// prevented.
    #[test]
    fn an_aliased_path_resolves_to_the_same_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("data");
        std::fs::create_dir_all(&nested).expect("mkdir");

        let _held = acquire(&nested).expect("first acquire");

        // Same directory reached through `.` and `..` indirection.
        let aliased = nested.join(".").join("..").join("data");
        let err = acquire(&aliased).expect_err("an alias must not get a second lock");
        assert!(
            matches!(err, InstanceError::AlreadyRunning { .. }),
            "got {err:?}"
        );
    }

    /// Genuinely separate instances are unaffected — that is what keeps a
    /// second testnet, and the containerised local fleet, working.
    #[test]
    fn separate_directories_each_get_their_own_lock() {
        let a = tempfile::tempdir().expect("tempdir");
        let b = tempfile::tempdir().expect("tempdir");
        let _first = acquire(a.path()).expect("a");
        let _second = acquire(b.path()).expect("b — a different instance is not a conflict");
    }

    #[test]
    fn the_refusal_names_the_pid_and_what_to_do() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _held = acquire(dir.path()).expect("first acquire");
        let err = acquire(dir.path()).expect_err("second acquire must be refused");

        let rendered = err.to_string();
        assert!(rendered.contains("already running"), "{rendered}");
        assert!(
            rendered.contains(&std::process::id().to_string()),
            "the message must name the PID to stop: {rendered}"
        );
        assert!(
            rendered.contains("kill"),
            "the message must say how to stop it: {rendered}"
        );
        assert!(
            rendered.contains("--data-dir"),
            "and offer the separate-instance alternative: {rendered}"
        );
    }

    #[test]
    fn a_free_port_is_not_reported_as_a_conflict() {
        // Bind, read the assigned port, release: a port that was free a moment
        // ago is the closest thing to a guaranteed-free port available.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = probe.local_addr().expect("addr").to_string();
        drop(probe);
        check_ports(&[("rpc", &addr)]).expect("a free port must not be a conflict");
    }

    #[test]
    fn an_occupied_port_is_reported_with_its_service_label() {
        let held = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = held.local_addr().expect("addr").to_string();

        let err = check_ports(&[("rpc", &addr)]).expect_err("an occupied port must be refused");
        let InstanceError::PortsBusy { conflicts } = &err else {
            panic!("got {err:?}");
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0, "rpc");

        let rendered = err.to_string();
        assert!(rendered.contains("already in use"), "{rendered}");
        assert!(
            rendered.contains("pgrep -af tenzro-node"),
            "the message must say how to find the holder: {rendered}"
        );
    }

    /// Every conflict at once, so moving listeners does not become one restart
    /// per port to discover the next one.
    #[test]
    fn all_conflicts_are_reported_together() {
        let a = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let b = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr_a = a.local_addr().expect("addr").to_string();
        let addr_b = b.local_addr().expect("addr").to_string();

        let err =
            check_ports(&[("rpc", &addr_a), ("mcp", &addr_b)]).expect_err("both must be refused");
        let InstanceError::PortsBusy { conflicts } = &err else {
            panic!("got {err:?}");
        };
        assert_eq!(conflicts.len(), 2, "both conflicts reported in one pass");
    }

    /// An empty address means the service is not configured to bind, which is
    /// not a conflict.
    #[test]
    fn an_unconfigured_address_is_skipped() {
        check_ports(&[("mcp", "")]).expect("an unset listener cannot conflict");
    }
}
