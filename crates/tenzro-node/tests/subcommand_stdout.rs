//! A subcommand's stdout carries only what the subcommand prints: logs go
//! to stderr, so `tenzro-node -c node.toml validator-entry > entry.toml`
//! writes a file that parses.

use std::path::PathBuf;
use std::process::Command;

/// The `tenzro-node` binary `cargo test` built for this test. Cargo names
/// it at compile time when it builds the binary; a `cargo check`, which
/// builds none, leaves the name out, so it is not required at compile time
/// and `cargo check --all-targets` still compiles this test.
fn node_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_tenzro-node")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_tenzro-node").map(PathBuf::from))
        .expect("cargo test names the tenzro-node binary in CARGO_BIN_EXE_tenzro-node")
}

#[test]
fn logs_never_reach_a_subcommands_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("node.toml");
    std::fs::write(&config, "").unwrap();
    let out = Command::new(node_binary())
        .args(["--log-level", "info", "-c"])
        .arg(&config)
        .args(["validator-entry", "--stake", "1"])
        .arg("--data-dir")
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Loading configuration"),
        "the log line is on stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Loading configuration"),
        "stdout has a log line: {stdout}"
    );
    assert!(
        !stdout.contains(" INFO "),
        "stdout has a log line: {stdout}"
    );
}
