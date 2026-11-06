//! The light build (`--no-default-features`, no model engines) refuses the
//! roles that run models: started with one of them it exits non-zero and
//! names the roles it cannot serve, before it opens any key or file.
//!
//! The refusal comes before the TPM check, so this runs on any machine.
#![cfg(not(feature = "inference"))]

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

fn start_with_roles(roles: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(node_binary())
        .args(["--log-format", "json", "--roles", roles, "--data-dir"])
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_light_build_refuses_each_role_that_runs_models() {
    for role in ["ai", "compute", "tee"] {
        let (started, stderr) = start_with_roles(role);
        assert!(
            !started,
            "the light build started with --roles {role}:\n{stderr}"
        );
        assert!(
            stderr.contains(tenzro_node::engine_roles::LIGHT_BUILD_REFUSAL),
            "the refusal for --roles {role} does not say this is the light build:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("the {role} role")),
            "the refusal does not name the {role} role:\n{stderr}"
        );
    }
}

#[test]
fn the_light_build_refuses_an_engine_role_mixed_with_others() {
    let (started, stderr) = start_with_roles("light,rpc,ai");
    assert!(
        !started,
        "the light build started with an ai role:\n{stderr}"
    );
    assert!(
        stderr.contains("the ai role"),
        "the refusal does not name the ai role:\n{stderr}"
    );
}

#[test]
fn the_light_build_refuses_an_engine_role_from_the_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("node.toml");
    std::fs::write(&config, "roles = [\"ComputeProvider\"]\n").unwrap();
    let out = Command::new(node_binary())
        .args(["--log-format", "json", "-c"])
        .arg(&config)
        .arg("--data-dir")
        .arg(dir.path())
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the light build started:\n{stderr}");
    assert!(
        stderr.contains("the compute role"),
        "the refusal does not name the compute role:\n{stderr}"
    );
}
