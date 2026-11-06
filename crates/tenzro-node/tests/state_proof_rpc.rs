//! `tenzro_getStateRoot` and `tenzro_getStateProof` through the node's real
//! JSON-RPC server, with the returned proof checked the way a light client
//! checks it.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_storage::{CF_ACCOUNTS, KvStore, StateProof, StateTrie, verify_state_proof};
use tokio::sync::broadcast;

async fn call(client: &reqwest::Client, url: &str, method: &str, params: Value) -> Value {
    client
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
        .send()
        .await
        .expect("HTTP request")
        .json::<Value>()
        .await
        .expect("JSON parse")
}

fn root_of(v: &Value) -> [u8; 32] {
    let bytes = hex::decode(v.as_str().expect("state_root is a string")).expect("hex root");
    bytes.try_into().expect("32-byte root")
}

#[tokio::test]
async fn a_served_state_proof_verifies_against_the_served_root() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    // Commit a height whose state this test knows, on top of whatever the
    // node committed at start.
    let store = node.storage().expect("storage").clone() as Arc<dyn KvStore>;
    let trie = StateTrie::new(store);
    let height = trie.latest_version().expect("version").map_or(0, |v| v + 1);
    let key = b"balance:proof-test".to_vec();
    let value = 42u128.to_le_bytes().to_vec();
    let mut writes = tenzro_storage::state_trie::capture::Writes::new();
    writes.insert((CF_ACCOUNTS.to_string(), key.clone()), Some(value.clone()));
    let committed = trie.commit(height, &writes).expect("commit");

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let url = format!("http://{}", addr_rx.await.expect("bound address"));
    let client = reqwest::Client::new();

    // The root served for the height is the one committed.
    let root = call(
        &client,
        &url,
        "tenzro_getStateRoot",
        json!({ "height": height }),
    )
    .await;
    assert_eq!(
        root_of(&root["result"]["state_root"]),
        committed.0,
        "{root}"
    );

    // A present entry: the served value and proof verify under that root.
    let resp = call(
        &client,
        &url,
        "tenzro_getStateProof",
        json!({ "namespace": CF_ACCOUNTS, "key": hex::encode(&key), "height": height }),
    )
    .await;
    let result = &resp["result"];
    assert_eq!(
        result["value"].as_str(),
        Some(hex::encode(&value).as_str()),
        "{resp}"
    );
    let proof: StateProof = serde_json::from_value(result["proof"].clone()).expect("proof decodes");
    let served_root = root_of(&result["state_root"]);
    let scheme: tenzro_types::hash_scheme::HashScheme =
        serde_json::from_value(result["state_trie_hash"].clone()).expect("the trie hash is named");
    verify_state_proof(
        scheme,
        &served_root,
        CF_ACCOUNTS,
        &key,
        Some(&value),
        &proof,
    )
    .expect("the served proof verifies");
    assert!(
        verify_state_proof(
            scheme,
            &served_root,
            CF_ACCOUNTS,
            &key,
            Some(b"forged"),
            &proof
        )
        .is_err(),
        "the proof does not verify another value"
    );

    // An absent entry: null value, and a proof of absence.
    let absent = b"balance:nobody".to_vec();
    let resp = call(
        &client,
        &url,
        "tenzro_getStateProof",
        json!({ "namespace": CF_ACCOUNTS, "key": hex::encode(&absent), "height": height }),
    )
    .await;
    assert!(resp["result"]["value"].is_null(), "{resp}");
    let proof: StateProof =
        serde_json::from_value(resp["result"]["proof"].clone()).expect("proof decodes");
    verify_state_proof(scheme, &served_root, CF_ACCOUNTS, &absent, None, &proof)
        .expect("the absence proof verifies");

    // A namespace outside the committed state is refused.
    let resp = call(
        &client,
        &url,
        "tenzro_getStateProof",
        json!({ "namespace": "metadata", "key": "00", "height": height }),
    )
    .await;
    assert!(resp["error"].is_object(), "{resp}");

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
}
