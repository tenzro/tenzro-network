//! The stack the command runs on.
//!
//! A command's whole work, parsing the command tree included, runs inside one
//! async runtime. The operating system sizes a process's main thread: a
//! Windows linker reserves 1 MiB by default, where Linux and macOS give 8 MiB,
//! and a build of this command overflows the smaller one before it prints a
//! line. The command therefore runs on a thread this crate sizes, on every
//! platform, and its runtime's workers get a stack of their own size.

use std::thread;

/// The stack of the thread that runs a command.
pub const MAIN_STACK_BYTES: usize = 64 * 1024 * 1024;

/// The stack of each worker of a command's async runtime.
pub const WORKER_STACK_BYTES: usize = 16 * 1024 * 1024;

/// Runs `body` on a thread with [`MAIN_STACK_BYTES`] of stack and returns its
/// result. A panic in `body` continues on the caller's thread, so the
/// process reports it as it would have without the thread.
pub fn run_on_large_stack<R, F>(body: F) -> R
where
    R: Send + 'static,
    F: FnOnce() -> R + Send + 'static,
{
    let handle = thread::Builder::new()
        .name("tenzro-main".into())
        .stack_size(MAIN_STACK_BYTES)
        .spawn(body)
        .expect("the operating system starts the command's thread");
    match handle.join() {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call chain whose frames add up to `depth` KiB, kept from being
    /// folded away.
    fn descend(depth: usize) -> usize {
        let frame = std::hint::black_box([1u8; 1024]);
        if depth == 0 {
            return frame.len();
        }
        descend(std::hint::black_box(depth - 1)) + usize::from(frame[0])
    }

    #[test]
    fn the_command_thread_holds_a_call_chain_the_default_stacks_cannot() {
        // 24 MiB: past the 8 MiB a Linux main thread has and the 1 MiB a
        // Windows one has, inside the 64 MiB this thread is given.
        let depth = 24 * 1024;
        assert_eq!(run_on_large_stack(move || descend(depth)), depth + 1024);
    }

    #[test]
    fn the_command_thread_is_the_sized_one() {
        let name = run_on_large_stack(|| thread::current().name().map(str::to_owned));
        assert_eq!(name.as_deref(), Some("tenzro-main"));
    }

    #[test]
    fn a_panic_in_the_command_reaches_the_caller() {
        let caught = std::panic::catch_unwind(|| run_on_large_stack(|| panic!("boom")));
        assert!(caught.is_err());
    }
}
