//! A node configured with a bonded role its operator holds no bond for starts
//! and serves without it, rather than failing to start and being restarted
//! over and over by its service manager; and the runtime a role needs is in
//! place whichever roles are configured, so a role taken up later finds it.

use tenzro_node::{NodeConfig, TenzroNode};
use tenzro_types::RoleSet;

#[tokio::test]
#[ignore = "starts a node: needs this machine's hardware key; run under scripts/tests/cargo-test-with-swtpm.sh with --ignored"]
async fn a_node_with_an_unbonded_storage_role_starts_without_it() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        roles: RoleSet::storage_only(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("the node starts");
    assert!(
        !node.runtime_roles.read().serves_storage(),
        "the unbonded storage role is not served"
    );
    if let Some(runtime) = node.storage_runtime() {
        assert!(
            runtime.admit_new_object().is_err(),
            "no new object is taken without the bond"
        );
    }
}

/// A node configured with no provider role still has the storage runtime
/// built, serving nothing, so a storage role taken up later by a hand-set
/// role list finds it in place.
#[tokio::test]
#[ignore = "starts a node: needs this machine's hardware key; run under scripts/tests/cargo-test-with-swtpm.sh with --ignored"]
async fn a_node_configured_without_storage_has_its_runtime_in_place() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        roles: RoleSet::client(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("the node starts");
    let runtime = node
        .storage_runtime()
        .expect("the storage runtime is built");
    assert!(runtime.admit_new_object().is_err(), "it serves nothing yet");
}
