//! The `--list` part of the libtest command line, for test binaries with their
//! own `main`.

/// Answers libtest's `--list` for a binary that is one test called `name`, so
/// a runner that lists tests before it runs them (cargo nextest) can schedule
/// it. Returns true when the arguments asked for a list and the process should
/// exit. With `runnable` false the test is reported as ignored: it also
/// appears in the `--ignored` listing, and the runner shows it as skipped
/// rather than passed.
pub fn answered_list(name: &str, runnable: bool) -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.iter().any(|a| a == "--list") {
        return false;
    }
    if !runnable || !args.iter().any(|a| a == "--ignored") {
        println!("{name}: test");
    }
    true
}
