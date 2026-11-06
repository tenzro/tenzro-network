//! Where compact certificates are proven and checked.
//!
//! Proving one takes about 16 core-seconds and 1.3 GB at its peak; checking
//! one sets up about 300 MB. Neither is on the critical path, so both run
//! one at a time per node, on a pool of lowered priority that uses at most
//! half the cores, so that consensus, execution and the RPC keep the rest;
//! and the memory they freed is handed back to the system afterwards
//! instead of staying in the allocator's free lists.

use parking_lot::Mutex;

/// Runs compact-certificate work one job at a time.
pub struct CompactWork {
    pool: rayon::ThreadPool,
    busy: Mutex<()>,
}

/// Niceness of the pool's threads: below the node's own work.
#[cfg(target_os = "linux")]
const WORKER_NICENESS: libc::c_int = 10;

impl Default for CompactWork {
    fn default() -> Self {
        Self::new()
    }
}

impl CompactWork {
    /// A pool of half this machine's cores, at least one.
    pub fn new() -> Self {
        Self::with_threads(0)
    }

    /// A pool of `threads` threads, or of half this machine's cores, at
    /// least one, when `threads` is 0.
    pub fn with_threads(threads: usize) -> Self {
        let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
        let threads = if threads == 0 {
            (cores / 2).max(1)
        } else {
            threads
        };
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("compact-{i}"))
            .start_handler(|_| lower_priority())
            .build()
            .expect("the compact certificate pool starts");
        Self {
            pool,
            busy: Mutex::new(()),
        }
    }

    /// Runs `job` on the pool once no other job runs, blocking the caller.
    pub fn run<T: Send>(&self, job: impl FnOnce() -> T + Send) -> T {
        let _turn = self.busy.lock();
        let out = self.pool.install(job);
        release_freed_memory();
        out
    }

    /// Runs `job` on the pool if no other job runs; None if one does.
    pub fn try_run<T: Send>(&self, job: impl FnOnce() -> T + Send) -> Option<T> {
        let _turn = self.busy.try_lock()?;
        let out = self.pool.install(job);
        release_freed_memory();
        Some(out)
    }
}

/// Lowers the calling thread's scheduling priority.
fn lower_priority() {
    #[cfg(target_os = "linux")]
    // SAFETY: setpriority with `who` 0 changes only the calling thread (on
    // Linux a thread is its own scheduling entity) and reads no memory.
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, WORKER_NICENESS);
    }
}

/// Returns the allocator's free memory to the system.
fn release_freed_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim only releases free pages of the allocator's heaps.
    unsafe {
        libc::malloc_trim(0);
    }
}
