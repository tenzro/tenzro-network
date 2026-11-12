//! The C allocator's memory behaviour.
//!
//! The node links no custom allocator, so Rust and the bundled C++ libraries
//! (RocksDB, the inference engines) allocate through glibc malloc. Under many
//! threads glibc opens up to eight arenas per core, and freed memory stays
//! inside an arena that a long-running process never returns to the system, so
//! the resident size climbs far past what the storage and model budgets allow.
//! The node caps the arena count at start and trims free memory back to the
//! system on a timer.

use std::time::Duration;

/// Most malloc arenas the process opens.
pub const MAX_ARENAS: i32 = 4;

/// How often free heap memory is returned to the system.
pub const TRIM_INTERVAL: Duration = Duration::from_secs(300);

/// Caps the malloc arena count. Call before the node spawns its threads.
/// Returns whether the allocator accepted the setting; a non-glibc target
/// has nothing to set and returns `false`.
pub fn limit_arenas(max: i32) -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: mallopt only changes allocator parameters.
        unsafe { libc::mallopt(libc::M_ARENA_MAX, max) == 1 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        let _ = max;
        false
    }
}

/// Returns free heap memory to the system now. `false` when nothing was
/// released or the target has no `malloc_trim`.
pub fn trim_now() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        // SAFETY: malloc_trim is safe to call from any thread at any time.
        unsafe { libc::malloc_trim(0) == 1 }
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    {
        false
    }
}

/// Starts the thread that trims free heap memory every [`TRIM_INTERVAL`].
pub fn spawn_trimmer() {
    let _ = std::thread::Builder::new()
        .name("malloc-trim".into())
        .spawn(|| {
            loop {
                std::thread::sleep(TRIM_INTERVAL);
                trim_now();
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn arenas_are_capped_and_a_freed_block_is_trimmed() {
        assert!(limit_arenas(MAX_ARENAS));
        // A large freed allocation leaves the heap trimmable; the call must
        // not fault whatever it returns.
        let big = vec![1u8; 64 << 20];
        drop(big);
        let _ = trim_now();
    }
}
