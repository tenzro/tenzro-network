//! The CLI run where neither `$TENZRO_HOME` nor `$HOME` is set says which
//! variable to set and fails, instead of panicking in the first path lookup.

use std::process::Command;

#[test]
fn the_cli_with_no_home_says_which_variable_to_set_and_fails() {
    let out = Command::new(env!("CARGO_BIN_EXE_tenzro"))
        .env_clear()
        .args(["node", "status"])
        .output()
        .expect("run the cli");
    assert!(!out.status.success(), "the cli ran without a home");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TENZRO_HOME"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
