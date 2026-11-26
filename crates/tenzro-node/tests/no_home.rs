//! A node started where neither `$TENZRO_HOME` nor `$HOME` is set says which
//! variable to set and exits, instead of panicking in the first path lookup.

use std::process::Command;

#[test]
fn a_node_with_no_home_says_which_variable_to_set_and_fails() {
    let out = Command::new(env!("CARGO_BIN_EXE_tenzro-node"))
        .env_clear()
        .arg("--dev")
        .output()
        .expect("run the node");
    assert!(!out.status.success(), "the node started without a home");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TENZRO_HOME"), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
}
