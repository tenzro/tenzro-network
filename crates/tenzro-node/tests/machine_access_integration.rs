//! Machine access through the real RPC surface: only the machine owner's
//! passkey and ML-DSA-65 signature add, list or revoke a grant, and a grant
//! opens exactly the destination it names until it is revoked.

use std::net::IpAddr;
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

mod common;
mod dpop_bearer;
mod passkey_holder;
use common::{MachineOwner, network_terms, rpc};

/// The operator every test node admits.
fn operator() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
    client: reqwest::Client,
    owner: MachineOwner,
}

impl TestNode {
    /// A node whose machine identity is owned by a freshly enrolled passkey
    /// account.
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        dpop_bearer::admit_operator(tmp.path(), &operator().did());
        let mut owner = MachineOwner::generate(0x51);
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            operator_did: Some(owner.machine_did()),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc_server = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle = tokio::spawn(async move {
            rpc_server
                .start_with_shutdown_and_addr(shutdown_rx, addr_tx)
                .await
        });
        let addr = addr_rx.await.expect("bound address");
        let base_url = format!("http://{addr}");
        let client = reqwest::Client::new();
        owner.enroll(&client, &base_url, &node).await;
        owner.register_machine(&node).await;

        Self {
            base_url,
            shutdown,
            handle,
            _tmp: tmp,
            node,
            client,
            owner,
        }
    }

    async fn rpc(&self, method: &str, params: Value) -> Value {
        rpc(&self.client, &self.base_url, method, params).await
    }

    async fn signed(&mut self, method: &str, params: Value) -> Value {
        self.owner
            .signed(&self.client, &self.base_url, method, params)
            .await
    }

    /// Whether the node's egress guard would connect to `ip:port`.
    fn reachable(&self, ip: &str, port: u16) -> bool {
        let ip: IpAddr = ip.parse().unwrap();
        self.node
            .egress()
            .address_policy()
            .check("test", ip, port)
            .is_ok()
    }

    fn terms(&self, cidr: &str, port: Option<u16>) -> Value {
        network_terms(&self.owner.machine_did(), cidr, port)
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

fn refused(resp: &Value) -> bool {
    resp.get("result").is_none() && resp.get("error").is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsigned_grant_is_refused_and_opens_nothing() {
    let n = TestNode::boot().await;
    let resp = n
        .rpc(
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", Some(9000)),
        )
        .await;
    assert!(refused(&resp), "{resp}");
    assert_eq!(resp["error"]["code"], -32001);
    assert_eq!(resp["error"]["data"]["operation"], "machine_access");
    assert!(!n.reachable("127.0.0.1", 9000));

    // The operator's access token authorises nothing here either.
    let op = operator().sign_in(&n.client, &n.base_url).await;
    let resp = op
        .call(
            &n.client,
            &n.base_url,
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", Some(9000)),
        )
        .await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.1", 9000));
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrongly_signed_grant_is_refused() {
    let mut n = TestNode::boot().await;
    let narrow = n.terms("127.0.0.1/32", Some(9000));
    let wide = n.terms("127.0.0.0/8", None);

    // A signature collected for narrow terms does not add wider ones.
    let (challenge_id, digest) = n
        .owner
        .challenge_for(&n.client, &n.base_url, "tenzro_addMachineAccess", &narrow)
        .await;
    let mut swapped = wide.clone();
    swapped["authorization"] = n.owner.authorize(&challenge_id, &digest);
    let resp = n.rpc("tenzro_addMachineAccess", swapped).await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.2", 80));

    // The owner's passkey over a different digest is refused.
    let (challenge_id, _) = n
        .owner
        .challenge_for(&n.client, &n.base_url, "tenzro_addMachineAccess", &narrow)
        .await;
    let mut forged = narrow.clone();
    forged["authorization"] = n.owner.authorize(&challenge_id, &[0x42u8; 32]);
    let resp = n.rpc("tenzro_addMachineAccess", forged).await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.1", 9000));
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_signed_by_anyone_but_the_owner_is_refused() {
    let n = TestNode::boot().await;
    // Another enrolled account: an agent's or a stranger's passkey.
    let mut other = MachineOwner::generate(0x52);
    other.enroll(&n.client, &n.base_url, &n.node).await;

    let terms = n.terms("127.0.0.1/32", Some(9000));
    let (challenge_id, digest) = other
        .challenge_for(&n.client, &n.base_url, "tenzro_addMachineAccess", &terms)
        .await;
    let mut attempt = terms.clone();
    attempt["authorization"] = other.authorize(&challenge_id, &digest);
    let resp = n.rpc("tenzro_addMachineAccess", attempt).await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.1", 9000));
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_with_its_own_credentials_cannot_add_a_grant() {
    let n = TestNode::boot().await;
    let agent = dpop_bearer::OperatorKey::new()
        .sign_in(&n.client, &n.base_url)
        .await;
    let resp = agent
        .call(
            &n.client,
            &n.base_url,
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", None),
        )
        .await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.1", 9000));
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owners_grant_opens_exactly_its_destination_until_revoked() {
    let mut n = TestNode::boot().await;
    assert!(!n.reachable("127.0.0.1", 9000));

    let added = n
        .signed(
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", Some(9000)),
        )
        .await;
    let grant_id = added["result"]["grant_id"]
        .as_str()
        .unwrap_or_else(|| panic!("grant refused: {added}"))
        .to_string();
    assert_eq!(added["result"]["owner_did"], n.owner.did());

    assert!(n.reachable("127.0.0.1", 9000));
    assert!(!n.reachable("127.0.0.1", 9001));
    assert!(!n.reachable("127.0.0.2", 9000));
    assert!(!n.reachable("10.0.0.1", 9000));
    assert!(!n.reachable("169.254.169.254", 9000));

    // Listing needs the owner too, and reports the use.
    assert!(refused(&n.rpc("tenzro_listMachineAccess", json!({})).await));
    let listed = n.signed("tenzro_listMachineAccess", json!({})).await;
    let grant = &listed["result"]["grants"][0];
    assert_eq!(grant["grant_id"], grant_id.as_str(), "{listed}");
    assert_eq!(grant["uses"], 1);

    // Revoking needs the owner, and takes effect on the next check.
    assert!(refused(
        &n.rpc(
            "tenzro_revokeMachineAccess",
            json!({ "grant_id": grant_id })
        )
        .await
    ));
    assert!(n.reachable("127.0.0.1", 9000));
    let revoked = n
        .signed(
            "tenzro_revokeMachineAccess",
            json!({ "grant_id": grant_id }),
        )
        .await;
    assert!(revoked["result"]["revoked_at"].is_string(), "{revoked}");
    assert!(!n.reachable("127.0.0.1", 9000));

    let listed = n.signed("tenzro_listMachineAccess", json!({})).await;
    let grant = &listed["result"]["grants"][0];
    assert_eq!(grant["revoked"], true);
    assert_eq!(grant["refusals"], 1);
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_expired_grant_is_refused_before_anyone_signs() {
    let n = TestNode::boot().await;
    let mut terms = n.terms("127.0.0.1/32", None);
    terms["expires_at_ms"] = json!(chrono::Utc::now().timestamp_millis() - 1);
    let resp = n.rpc("tenzro_addMachineAccess", terms).await;
    assert!(refused(&resp), "{resp}");
    assert_eq!(resp["error"]["code"], -32602);
    n.shutdown().await;
}

/// Ask the node for the challenge of a machine-access change it describes
/// itself, the way the CLI and SDKs do. Returns `(challenge_id, digest)`.
async fn challenge_for_change(n: &TestNode, change: Value) -> (String, Vec<u8>) {
    let issued = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({ "operation": "machine_access", "machine_access": change }),
        )
        .await;
    let id = issued["result"]["challenge_id"]
        .as_str()
        .unwrap_or_else(|| panic!("no challenge: {issued}"))
        .to_string();
    let digest = hex::decode(
        issued["result"]["challenge_hex"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    (id, digest)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_node_names_the_challenge_for_a_change_it_is_given() {
    let mut n = TestNode::boot().await;
    let terms = n.terms("127.0.0.1/32", Some(9000));
    let mut change = terms.clone();
    change["action"] = json!("add");
    let (challenge_id, digest) = challenge_for_change(&n, change).await;
    let mut signed = terms.clone();
    signed["authorization"] = n.owner.authorize(&challenge_id, &digest);
    let added = n.rpc("tenzro_addMachineAccess", signed).await;
    assert!(added["result"]["grant_id"].is_string(), "{added}");
    assert!(n.reachable("127.0.0.1", 9000));

    // A challenge for one change does not authorise another.
    let (challenge_id, digest) = challenge_for_change(&n, json!({ "action": "list" })).await;
    let mut wider = n.terms("127.0.0.0/8", None);
    wider["authorization"] = n.owner.authorize(&challenge_id, &digest);
    assert!(refused(&n.rpc("tenzro_addMachineAccess", wider).await));

    // Terms the node would refuse are refused before a challenge is issued.
    let mut expired = n.terms("127.0.0.1/32", None);
    expired["action"] = json!("add");
    expired["expires_at_ms"] = json!(1);
    let resp = n
        .rpc(
            "tenzro_createCustodyChallenge",
            json!({ "operation": "machine_access", "machine_access": expired }),
        )
        .await;
    assert!(refused(&resp), "{resp}");
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_network_grant_to_an_agent_opens_only_that_agents_requests() {
    let mut n = TestNode::boot().await;
    let agent = "did:tenzro:machine:agent-under-test";
    let added = n
        .signed(
            "tenzro_addMachineAccess",
            network_terms(agent, "127.0.0.1/32", Some(9000)),
        )
        .await;
    assert!(added["result"]["grant_id"].is_string(), "{added}");
    let url = "http://127.0.0.1:9000/";
    let scheme = tenzro_node::egress_guard::Scheme::HttpOrHttps;
    assert!(n.node.egress().check_url(url, scheme).is_err());
    assert!(
        n.node
            .egress()
            .for_grantee(Some("did:tenzro:machine:someone-else"))
            .check_url(url, scheme)
            .is_err()
    );
    assert!(
        n.node
            .egress()
            .for_grantee(Some(agent))
            .check_url(url, scheme)
            .is_ok()
    );
    n.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn grants_end_when_the_machine_changes_hands() {
    let mut n = TestNode::boot().await;
    let added = n
        .signed(
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", Some(9000)),
        )
        .await;
    assert!(added["result"]["grant_id"].is_string(), "{added}");
    assert!(n.reachable("127.0.0.1", 9000));

    // The same owner reconciling changes nothing.
    tenzro_node::machine_access::reconcile_owner(&n.node);
    assert!(n.reachable("127.0.0.1", 9000));

    let mut buyer = MachineOwner::generate(0x53);
    buyer.enroll(&n.client, &n.base_url, &n.node).await;
    n.node
        .identity_registry()
        .unwrap()
        .set_machine_controller(&n.owner.machine_did(), &buyer.did())
        .unwrap();
    tenzro_node::machine_access::reconcile_owner(&n.node);
    assert!(!n.reachable("127.0.0.1", 9000));

    // The previous owner's signature no longer adds anything.
    let resp = n
        .signed(
            "tenzro_addMachineAccess",
            n.terms("127.0.0.1/32", Some(9000)),
        )
        .await;
    assert!(refused(&resp), "{resp}");
    assert!(!n.reachable("127.0.0.1", 9000));
    n.shutdown().await;
}
