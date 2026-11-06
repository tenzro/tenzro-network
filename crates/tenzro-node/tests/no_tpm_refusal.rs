//! A node refuses to start on a machine with no TPM 2.0 or Secure Enclave:
//! it exits non-zero and names what is missing, rather than running without
//! a machine identity.
//!
//! The binary is started only where this test process sees no hardware key
//! store. On a machine with a TPM it would open that TPM's keys, so there
//! the test only reports that it did not run; the start verdict itself is
//! covered by the unit tests in `identity_bootstrap`.

use std::path::PathBuf;
use std::process::Command;

/// The `tenzro-node` binary `cargo test` built for this test. A `cargo
/// check`, which builds none, leaves the name out, so it is not required at
/// compile time.
fn node_binary() -> PathBuf {
    option_env!("CARGO_BIN_EXE_tenzro-node")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_tenzro-node").map(PathBuf::from))
        .expect("cargo test names the tenzro-node binary in CARGO_BIN_EXE_tenzro-node")
}

#[test]
fn a_node_without_a_tpm_refuses_to_start() {
    if tenzro_device_key::signer::platform_backend().is_some() {
        eprintln!("this machine has a hardware key store; the no-TPM start is not run here");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("node.toml");
    std::fs::write(&config, "").unwrap();
    let out = Command::new(node_binary())
        .args(["--log-format", "json", "-c"])
        .arg(&config)
        .arg("--data-dir")
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "a node without a TPM started:\n{stderr}"
    );
    assert!(
        stderr.contains(tenzro_node::identity_bootstrap::NO_HARDWARE_IDENTITY),
        "the refusal does not name the missing TPM:\n{stderr}"
    );
}
