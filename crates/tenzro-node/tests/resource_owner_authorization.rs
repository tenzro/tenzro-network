//! A resource that belongs to a tenant needs an owner check, not a token.
//!
//! The operator's admin token authenticates whoever runs the machine. It is the
//! wrong gate for anything belonging to somebody *using* the machine — a task
//! someone posted, an NFT they hold, a template they published — because
//! accepting it would let a shared node's host mutate their tenants'
//! resources. Those need the owner to prove themselves.
//!
//! Every method below was reachable with no credential at all. The ids they key
//! on are public: task ids come back from `tenzro_listTasks`, collection ids
//! from the collection record, template ids from `tenzro_listAgentTemplates`.
//! Knowing one was the whole of the authorization.
//!
//! What a stranger could do, before:
//!
//! - `tenzro_transferNft` — move a token out of someone's wallet. The handler
//!   compared the caller-supplied `from` against the recorded owner, which
//!   confirms the caller typed the right name and nothing else.
//! - `tenzro_mintNft` / `tenzro_mintNftBatch` — inflate a collection they did
//!   not create and assign the new tokens to themselves.
//! - `tenzro_cancelTask` — withdraw someone else's offer, or pull a task out
//!   from under the provider already working it.
//! - `tenzro_assignTask` — assign every open task to an address they control,
//!   at the task's `max_price`.
//! - `tenzro_completeTask` — declare another provider's work done and release
//!   the escrow behind it.
//! - `tenzro_delegateTask` — order a fee transfer out of any funded address
//!   they named. Small per call, unbounded in aggregate.
//! - `tenzro_claimRewards` / `tenzro_releaseVesting` — force the start of
//!   someone else's vesting clock.
//! - `tenzro_updateAgentTemplate` — rewrite what everyone instantiating a
//!   template gets. The same class as the skill/tool registry hole.
//! - `tenzro_spawnChildAgent` — spawn children under another parent's DID,
//!   each carrying that parent's authority and spending its budget.
//! - `tenzro_terminateSwarm` — destroy another controller's running agents.
//! - `tenzro_setUsername` — claim names against DIDs they do not control.
//!
//! Each test asserts the call is now *refused*. A refusal for the right reason
//! matters as much as the refusal: an id that does not exist must not be the
//! way to tell an ungated method from a gated one, so where the resource is
//! absent these assert that the answer is an error either way, and where it can
//! be reached they assert the error names the missing proof.

use serde_json::{Value, json};
use std::sync::Arc;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tokio::sync::broadcast;

struct TestNode {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    client: reqwest::Client,
}

impl TestNode {
    async fn boot() -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);

        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        Self {
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            client: reqwest::Client::new(),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .expect("HTTP request")
            .json::<Value>()
            .await
            .expect("JSON parse")
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// Post a task so the lifecycle probes hit a real record rather than a
/// not-found path — otherwise "refused" could just mean "no such task".
async fn post_task(n: &TestNode) -> String {
    let res = n
        .call(
            "tenzro_postTask",
            json!({
                "title": "victim task",
                "description": "work someone else posted",
                "task_type": "Inference",
                "poster": "0x1111111111111111111111111111111111111111",
                "max_price": "1000",
            }),
        )
        .await;
    res["result"]["task_id"]
        .as_str()
        .unwrap_or_else(|| panic!("postTask did not return a task_id: {res}"))
        .to_string()
}

/// Create an NFT collection owned by an address the prober does not control.
async fn create_collection(n: &TestNode) -> String {
    let res = n
        .call(
            "tenzro_createNftCollection",
            json!({
                "name": "Victim Collection",
                "symbol": "VIC",
                "standard": "erc721",
                "creator": "0x2222222222222222222222222222222222222222",
            }),
        )
        .await;
    res["result"]["collection_id"]
        .as_str()
        .or_else(|| res["result"]["collection"].as_str())
        .unwrap_or_else(|| panic!("createNftCollection did not return an id: {res}"))
        .to_string()
}

fn assert_refused(res: &Value, method: &str, what: &str) {
    assert!(
        res.get("error").is_some(),
        "{method} succeeded with no credential — {what}. Response: {res}"
    );
    assert!(
        res.get("result").is_none() || res["result"].is_null(),
        "{method} returned a result alongside an error: {res}"
    );
}

#[tokio::test]
async fn a_stranger_cannot_move_or_mint_someone_elses_nfts() {
    let n = TestNode::boot().await;
    let collection = create_collection(&n).await;

    // Mint into a collection whose creator is somebody else.
    let res = n
        .call(
            "tenzro_mintNft",
            json!({
                "collection": collection,
                "token_id": 1,
                "to": "0xdead00000000000000000000000000000000dead",
            }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_mintNft",
        "a stranger inflated a collection they did not create",
    );
    // The refusal must be about the missing proof, not about the collection.
    let msg = res["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("signature") || msg.contains("public_key"),
        "mintNft refused for the wrong reason: {msg}"
    );

    let res = n
        .call(
            "tenzro_mintNftBatch",
            json!({
                "collection": collection,
                "to": "0xdead00000000000000000000000000000000dead",
                "token_ids": [2, 3],
                "uris": ["ipfs://a", "ipfs://b"],
            }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_mintNftBatch",
        "a stranger batch-inflated someone else's collection",
    );

    // Transfer needs a minted token; with none minted the call must still fail,
    // and it must not be the ownership comparison that lets it through.
    let res = n
        .call(
            "tenzro_transferNft",
            json!({
                "collection": collection,
                "token_id": 1,
                "from": "0x2222222222222222222222222222222222222222",
                "to": "0xdead00000000000000000000000000000000dead",
            }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_transferNft",
        "a stranger moved a token out of someone's wallet",
    );

    n.shutdown().await;
}

#[tokio::test]
async fn a_stranger_cannot_interfere_with_someone_elses_task() {
    let n = TestNode::boot().await;
    let task_id = post_task(&n).await;

    for (method, params, what) in [
        (
            "tenzro_cancelTask",
            json!({ "task_id": task_id }),
            "a stranger withdrew someone else's posted work",
        ),
        (
            "tenzro_assignTask",
            json!({
                "task_id": task_id,
                "provider": "0xdead00000000000000000000000000000000dead",
            }),
            "a stranger assigned another poster's task to themselves",
        ),
    ] {
        let res = n.call(method, params).await;
        assert_refused(&res, method, what);
        let msg = res["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("signature") || msg.contains("public_key"),
            "{method} refused for the wrong reason: {msg}"
        );
    }

    // Completion is the assignee's call, and the task is still Open, so this
    // must fail on the status check before authorization is even reached —
    // which is the point: there is no ordering in which it succeeds.
    let res = n
        .call(
            "tenzro_completeTask",
            json!({ "task_id": task_id, "output": "done" }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_completeTask",
        "a stranger declared another provider's work complete",
    );

    n.shutdown().await;
}

#[tokio::test]
async fn delegation_cannot_bill_an_address_the_caller_does_not_hold() {
    let n = TestNode::boot().await;

    // The fee transfer used to fire off whatever `caller_address` named.
    let res = n
        .call(
            "tenzro_delegateTask",
            json!({
                "sender_id": "agent-a",
                "receiver_id": "agent-b",
                "task_type": "GenericTask",
                "caller_address": "0x1111111111111111111111111111111111111111",
                "receiver_address": "0xdead00000000000000000000000000000000dead",
            }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_delegateTask",
        "a stranger ordered a transfer out of an address they do not hold",
    );

    // Omitting the address must not be the way around it either.
    let res = n
        .call(
            "tenzro_delegateTask",
            json!({
                "sender_id": "agent-a",
                "receiver_id": "agent-b",
                "task_type": "GenericTask",
            }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_delegateTask",
        "dropping caller_address skipped the proof instead of the billing",
    );

    n.shutdown().await;
}

#[tokio::test]
async fn a_stranger_cannot_start_someone_elses_payout_clock() {
    let n = TestNode::boot().await;
    let victim = "0x1111111111111111111111111111111111111111";

    for (method, what) in [
        (
            "tenzro_claimRewards",
            "a stranger forced a claim, locking the holder's rewards into a schedule \
             starting now",
        ),
        (
            "tenzro_releaseVesting",
            "a stranger drew against someone else's vesting schedule",
        ),
    ] {
        let res = n.call(method, json!({ "address": victim })).await;
        assert_refused(&res, method, what);
        let msg = res["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("signature") || msg.contains("public_key"),
            "{method} refused for the wrong reason: {msg}"
        );
    }

    n.shutdown().await;
}

#[tokio::test]
async fn a_stranger_cannot_act_under_another_identity() {
    let n = TestNode::boot().await;
    let victim_did = "did:tenzro:human:victim";

    for (method, params, what) in [
        (
            "tenzro_spawnChildAgent",
            json!({ "parent_did": victim_did, "display_name": "impostor" }),
            "a stranger spawned an agent carrying another parent's authority",
        ),
        (
            "tenzro_setUsername",
            json!({ "did": victim_did, "username": "squatted" }),
            "a stranger claimed a name against a DID they do not control",
        ),
    ] {
        let res = n.call(method, params).await;
        assert_refused(&res, method, what);
        let msg = res["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("did_envelope"),
            "{method} refused for the wrong reason: {msg}"
        );
    }

    n.shutdown().await;
}

#[tokio::test]
async fn a_registry_entry_cannot_be_rewritten_by_a_stranger() {
    let n = TestNode::boot().await;

    // The five built-in templates are registered at boot under the system
    // creator DID, so this hits a real record rather than a not-found path.
    let listed = n.call("tenzro_listAgentTemplates", json!({})).await;
    let template_id = listed["result"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|t| t.get("template_id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let template_id = template_id
        .unwrap_or_else(|| panic!("no built-in agent templates were registered at boot: {listed}"));
    {
        let res = n
            .call(
                "tenzro_updateAgentTemplate",
                json!({
                    "template_id": template_id,
                    "description": "rewritten by a stranger",
                }),
            )
            .await;
        assert_refused(
            &res,
            "tenzro_updateAgentTemplate",
            "a stranger rewrote what everyone instantiating this template gets",
        );
        let msg = res["error"]["message"].as_str().unwrap_or_default();
        assert!(
            msg.contains("did_envelope") || msg.contains("signature"),
            "updateAgentTemplate refused for the wrong reason: {msg}"
        );
    }

    n.shutdown().await;
}

#[tokio::test]
async fn a_stranger_cannot_destroy_another_controllers_swarm() {
    let n = TestNode::boot().await;

    // No swarm with this id exists, so the assertion here is narrow: the call
    // must not report success. A swarm id is returned by `tenzro_createSwarm`
    // and appears in every status response, so guessing is not the barrier.
    let res = n
        .call(
            "tenzro_terminateSwarm",
            json!({ "swarm_id": "00000000-0000-0000-0000-000000000000" }),
        )
        .await;
    assert_refused(
        &res,
        "tenzro_terminateSwarm",
        "a stranger destroyed another controller's running agents",
    );

    n.shutdown().await;
}

/// The gate must accept a correct proof, not merely refuse everything.
///
/// Derives the creator address the way `PublicKey::to_address()` does for
/// Ed25519 — SHA-256 of the public key, first 20 bytes — creates a collection
/// owned by it, then mints with a signature over the same domain-separated
/// preimage `require_address_owner` builds. A gate that only ever denies would
/// pass every test above and still be broken.
#[tokio::test]
async fn a_proven_owner_can_still_act() {
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};

    let n = TestNode::boot().await;

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let public = signing.verifying_key().to_bytes();
    let addr20 = &Sha256::digest(public)[..20];
    let creator = format!("0x{}", to_hex(addr20));

    let res = n
        .call(
            "tenzro_createNftCollection",
            json!({
                "name": "Owned Collection",
                "symbol": "OWN",
                "standard": "erc721",
                "creator": creator,
            }),
        )
        .await;
    let collection = res["result"]["collection_id"]
        .as_str()
        .unwrap_or_else(|| panic!("createNftCollection did not return an id: {res}"))
        .to_string();

    let to = "0xdead00000000000000000000000000000000dead";
    let to_hex_body = to.trim_start_matches("0x");
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"tenzro/rpc-owner/v1");
    preimage.push(0);
    preimage.extend_from_slice(b"tenzro_mintNft");
    preimage.push(0);
    preimage.extend_from_slice(format!("{collection}:1:{to_hex_body}").as_bytes());
    let signature = signing.sign(&preimage).to_bytes();

    let res = n
        .call(
            "tenzro_mintNft",
            json!({
                "collection": collection,
                "token_id": 1,
                "to": to,
                "signature": to_hex(&signature),
                "public_key": to_hex(&public),
            }),
        )
        .await;
    assert!(
        res.get("error").is_none(),
        "the collection's own creator was refused: {res}"
    );

    n.shutdown().await;
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
