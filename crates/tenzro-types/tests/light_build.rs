//! The light build of the node compiles.
//!
//! The light build is `tenzro-node` without its default `inference` feature
//! (`scripts/build-tier.sh edge` and `validator`, docs/operations/light-build.md):
//! no model engines, and nothing that serves a model. Code that reaches an
//! engine-only function from outside an `inference`-gated item breaks it while
//! the standard build, which every other check compiles, still passes. This
//! check compiles the light build's library, binary and tests.
//!
//! It runs cargo once more, into a target directory of its own beside the one
//! this test was built into, so it never waits on that directory's lock and
//! later runs are incremental.

use std::path::{Path, PathBuf};
use std::process::Command;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the workspace root holds crates/tenzro-types")
        .to_path_buf()
}

/// `<target>/light-build`, where `<target>` holds this test binary
/// (`<target>/<profile>/deps/light_build-<hash>`).
fn light_target_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let target = exe
        .ancestors()
        .nth(3)
        .expect("the test binary lies in <target>/<profile>/deps");
    target.join("light-build")
}

#[test]
fn the_light_build_compiles() {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(root())
        .env("CARGO_TARGET_DIR", light_target_dir())
        .args([
            "check",
            "--locked",
            "-p",
            "tenzro-node",
            "--no-default-features",
            "--lib",
            "--bins",
            "--tests",
        ])
        .output()
        .expect("cargo runs");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let errors: Vec<&str> = stderr
        .lines()
        .filter(|l| l.starts_with("error"))
        .take(20)
        .collect();
    assert!(
        out.status.success(),
        "the light build (tenzro-node --no-default-features) does not compile:\n{}\n\n{}",
        errors.join("\n"),
        stderr
            .lines()
            .rev()
            .take(60)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    );
}
