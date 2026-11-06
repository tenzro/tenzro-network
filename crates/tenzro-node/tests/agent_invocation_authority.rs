//! Who may move value between agents: a settlement debits only a payer that signed for it.
//!
//! Each test boots a full node with RocksDB and its RPC server, then drives
//! the JSON-RPC surface the way a client does: onboarding to get a
//! DPoP-bound bearer, signed DID envelopes for ownership proofs, and plain
//! unauthenticated requests for the refusals.
//!
//! Run with a raised descriptor limit: `ulimit -n 65536`.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;

use serde_json::{Value, json};
use tokio::sync::broadcast;

use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::Address;

use dpop_bearer::Bearer;

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

struct TestNode {
    url: String,
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
}

impl TestNode {
    async fn start() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let cfg = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(cfg).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        let (tx, rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(async move { rpc.start_with_shutdown_and_addr(rx, addr_tx).await });
        let addr = addr_rx.await.expect("bound address");
        Self {
            url: format!("http://{}", addr),
            tx,
            handle,
            _tmp: tmp,
            node,
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .expect("HTTP")
            .json()
            .await
            .expect("JSON")
    }

    async fn call_as(&self, who: &Bearer, method: &str, params: Value) -> Value {
        who.call(&self.client, &self.url, method, params).await
    }

    /// Seeds a balance the way block execution writes one.
    fn fund(&self, to: &Address, amount: u128) {
        use tenzro_storage::KvStore;
        let held = self.balance(to);
        self.node
            .storage()
            .expect("storage")
            .put(
                tenzro_storage::kv::CF_ACCOUNTS,
                &tenzro_token::tnzo::balance_key(to),
                &(held + amount).to_le_bytes(),
            )
            .expect("fund");
    }

    fn balance(&self, of: &Address) -> u128 {
        self.node.token().expect("token").balance_of(of)
    }

    async fn stop(self) {
        let _ = self.tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), self.handle).await;
    }
}

// ---------------------------------------------------------------------------
// Cross-VM transfer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn settlement_debits_only_a_payer_that_signed_for_it() {
    let n = TestNode::start().await;
    let thief = Bearer::onboard(&n.client, &n.url, "Provider").await;
    let victim = Bearer::onboard(&n.client, &n.url, "Customer").await;
    n.fund(&victim.address, 5_000);
    let payee = format!("0x{}", hex::encode(thief.address.as_bytes()));
    let payer = format!("0x{}", hex::encode(victim.address.as_bytes()));

    // No authorization at all.
    let resp = n
        .call("tenzro_settle", json!({ "payee": payee, "amount": "5000" }))
        .await;
    assert!(resp["error"].is_object(), "{resp}");

    // An authorization naming the victim as payer but carrying another key.
    let forged = json!({
        "payee": payee,
        "amount": "5000",
        "payment": {
            "payer": payer,
            "payment_id": "forged-1",
            "authorization": {
                "public_key": hex::encode([7u8; 64]),
                "signature": { "classical": { "form": "raw", "signature": hex::encode([0u8; 64]) } },
                "max_amount": "5000",
                "asset": "TNZO",
            },
        },
    });
    let resp = n.call_as(&thief, "tenzro_settle", forged).await;
    assert!(resp["error"].is_object(), "{resp}");
    assert_eq!(n.balance(&victim.address), 5_000);
    n.stop().await;
}
