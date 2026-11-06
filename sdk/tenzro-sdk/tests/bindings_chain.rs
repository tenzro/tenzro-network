//! Node and chain bindings against a recording JSON-RPC node: each binding
//! names the method the node dispatches, sends the parameters its handler
//! reads, and decodes the shape the handler returns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tenzro_sdk::TenzroClient;
use tenzro_sdk::error::SdkResult;
use tenzro_sdk::types::Address;
use tenzro_sdk::wallet::HybridSigner;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A node that answers each method from a reply table (`"0x1"` for a method
/// with no entry) and records every request.
struct Node {
    url: String,
    replies: Arc<Mutex<HashMap<String, Value>>>,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl Node {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let replies: Arc<Mutex<HashMap<String, Value>>> = Arc::default();
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let (r, s) = (replies.clone(), seen.clone());
        tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (r, s) = (r.clone(), s.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let body_start = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break i + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..body_start]).to_lowercase();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    while buf.len() < body_start + len {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    let request: Value = serde_json::from_slice(&buf[body_start..]).unwrap();
                    let method = request["method"].as_str().unwrap_or("").to_string();
                    let result = r
                        .lock()
                        .unwrap()
                        .get(&method)
                        .cloned()
                        .unwrap_or(json!("0x1"));
                    s.lock().unwrap().push(request.clone());
                    let body = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
                        .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { url, replies, seen }
    }

    async fn client(&self) -> TenzroClient {
        TenzroClient::new(&self.url).await.unwrap()
    }

    fn answer(&self, method: &str, result: Value) {
        self.replies
            .lock()
            .unwrap()
            .insert(method.to_string(), result);
    }

    /// The last request sent for `method`.
    fn sent(&self, method: &str) -> Value {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|r| r["method"] == method)
            .cloned()
            .unwrap_or_else(|| panic!("no request for {method}"))
    }

    /// Answers `method` with `result`, runs `call`, and checks the request
    /// carried `params`: every key of an object, or the whole array.
    async fn check<T>(
        &self,
        method: &str,
        result: Value,
        call: impl std::future::Future<Output = SdkResult<T>>,
        params: Value,
    ) -> T {
        self.answer(method, result);
        let out = call.await.unwrap_or_else(|e| panic!("{method}: {e}"));
        let sent = self.sent(method)["params"].clone();
        assert_params(method, &sent, &params);
        out
    }
}

fn assert_params(method: &str, sent: &Value, want: &Value) {
    match want {
        Value::Object(keys) => {
            let obj = sent
                .as_object()
                .or_else(|| sent.get(0).and_then(Value::as_object))
                .unwrap_or_else(|| panic!("{method}: params {sent} are not an object"));
            for (k, v) in keys {
                assert_eq!(
                    obj.get(k).unwrap_or(&Value::Null),
                    v,
                    "{method}: {k} in {sent}"
                );
            }
        }
        other => assert_eq!(sent, other, "{method}"),
    }
}

const ADDR: &str = "0x0303030303030303030303030303030303030303030303030303030303030303";

#[tokio::test]
async fn chain_reads() {
    let node = Node::start().await;
    let c = node.client().await;
    let a = Address::new([3; 32]);

    assert_eq!(
        node.check(
            "tenzro_blockNumber",
            json!("0x2a"),
            c.block_number(),
            json!([])
        )
        .await,
        42
    );
    let block = json!({"height": 7, "hash": "0xab", "prev_hash": "0x00", "state_root": "0x01", "tx_root": "0x02", "timestamp": 5, "proposer": "p", "tx_count": 0, "gas_used": 0, "gas_limit": 1});
    assert_eq!(
        node.check(
            "tenzro_getBlock",
            block.clone(),
            c.get_block(7),
            json!([{"block_number": 7}])
        )
        .await
        .height,
        7
    );
    node.check(
        "tenzro_getBlock",
        block,
        c.get_latest_block(),
        json!([{"height": "latest"}]),
    )
    .await;
    let range = node
        .check(
            "tenzro_getBlockRange",
            json!({"blocks": [], "nextHeight": 11, "moreAvailable": false, "localTip": 10}),
            c.get_block_range(1, 10, Some(5)),
            json!({"startHeight": 1, "endHeight": 10, "maxResults": 5}),
        )
        .await;
    assert_eq!(range.next_height, 11);
    assert_eq!(
        node.check(
            "tenzro_getBalance",
            json!("0x10"),
            c.get_balance(a.clone()),
            json!([ADDR])
        )
        .await,
        16
    );
    assert_eq!(
        node.check(
            "tenzro_getNonce",
            json!("0x3"),
            c.get_nonce(a),
            json!([ADDR])
        )
        .await,
        3
    );
    node.answer("web3_clientVersion", json!("tenzro-node/0.9.0"));
    node.answer("eth_chainId", json!("0x3444"));
    node.answer("tenzro_syncing", json!(false));
    let info = node
        .check(
            "tenzro_getNodeStatus",
            json!({"state": "Running", "block_height": 9, "peer_count": 2}),
            c.node_info(),
            json!([]),
        )
        .await;
    assert_eq!(
        (
            info.version.as_str(),
            info.chain_id,
            info.block_height,
            info.peer_count,
            info.syncing
        ),
        ("tenzro-node/0.9.0", 13380, 9, 2, false)
    );
    assert_eq!(
        node.check(
            "tenzro_totalSupply",
            json!("1000"),
            c.total_supply(),
            json!([])
        )
        .await,
        "1000"
    );
    assert_eq!(
        node.check("tenzro_peerCount", json!("0x4"), c.peer_count(), json!([]))
            .await,
        4
    );
    let stats = node
        .check(
            "tenzro_getNetworkStats",
            json!({"available": false, "reason": "network service not initialized"}),
            c.network_stats(),
            json!([]),
        )
        .await;
    assert!(!stats.available);
    node.check(
        "tenzro_getBeacon",
        json!({"round": 3, "mix": "0x00"}),
        c.beacon(Some(3), None),
        json!({"round": 3}),
    )
    .await;
    node.check(
        "tenzro_getFeeMarket",
        json!({"compute": {"base_fee": "1", "base_fee_usd": "0.1", "target_per_block": 5}}),
        c.fee_market(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getTransaction",
        json!({"hash": "0xaa", "status": "pending"}),
        c.get_transaction("0xaa"),
        json!(["0xaa"]),
    )
    .await;
    assert!(
        !node
            .check("tenzro_syncing", json!(false), c.syncing(), json!([]))
            .await
    );
    assert!(
        node.check("tenzro_syncing", json!({"syncing": true, "startingBlock": "0x0", "currentBlock": "0x1", "highestBlock": "0x9"}), c.syncing(), json!([]))
            .await
    );
    assert_eq!(
        node.check(
            "tenzro_getFinalizedBlock",
            json!("0x8"),
            c.get_finalized_block(),
            json!([])
        )
        .await,
        8
    );
    node.check(
        "tenzro_exportConfig",
        json!({"config": {}, "exported_path": "/tmp/x"}),
        c.export_config(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_getTransactionHistory",
        json!({"transactions": []}),
        c.get_transaction_history(ADDR, Some(5), Some("9:0")),
        json!({"address": ADDR, "limit": 5, "cursor": "9:0"}),
    )
    .await;
    node.check(
        "tenzro_listSettlements",
        json!({"settlements": []}),
        c.list_settlements(json!({"payer": ADDR, "limit": 3})),
        json!({"payer": ADDR, "limit": 3}),
    )
    .await;
    node.check(
        "tenzro_listPeers",
        json!({"peers": []}),
        c.list_peers(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_getProviderScorecard",
        json!({"provider": ADDR}),
        c.get_provider_scorecard(ADDR),
        json!({"provider": ADDR}),
    )
    .await;
    node.check(
        "tenzro_getNetworkActivity",
        json!({"epochs": []}),
        c.get_network_activity(Some(24)),
        json!({"epochs": 24}),
    )
    .await;
    node.check(
        "tenzro_sponsoredInference",
        json!({"output": "hi"}),
        c.sponsored_inference("m", "hello", "did:a", Some(16)),
        json!({"model": "m", "input": "hello", "sponsor": "did:a", "max_tokens": 16}),
    )
    .await;
}

#[tokio::test]
async fn node_operation() {
    let node = Node::start().await;
    let n = node.client().await.node();
    type Call<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = SdkResult<Value>> + 'a>>;
    let calls: Vec<(&str, Call<'_>, Value)> = vec![
        (
            "tenzro_autotuneDecisions",
            Box::pin(n.autotune_decisions()),
            json!({}),
        ),
        (
            "tenzro_memoryBudget",
            Box::pin(n.memory_budget()),
            json!({}),
        ),
        (
            "tenzro_trafficStats",
            Box::pin(n.traffic_stats()),
            json!({}),
        ),
        (
            "tenzro_nodeDidDocument",
            Box::pin(n.node_did_document()),
            json!({}),
        ),
        ("tenzro_nodeVisibility", Box::pin(n.visibility()), json!({})),
        ("tenzro_shutdown", Box::pin(n.shutdown()), json!({})),
        (
            "tenzro_validatorPublicKeys",
            Box::pin(n.validator_public_keys()),
            json!({}),
        ),
        (
            "tenzro_fabricProfile",
            Box::pin(n.fabric_profile()),
            Value::Null,
        ),
        (
            "tenzro_gossipStats",
            Box::pin(n.gossip_stats()),
            Value::Null,
        ),
        (
            "tenzro_livenessStats",
            Box::pin(n.liveness_stats()),
            Value::Null,
        ),
        (
            "tenzro_cleanupIdleLocalModelServices",
            Box::pin(n.cleanup_idle_local_model_services()),
            Value::Null,
        ),
        (
            "tenzro_layerPipelineStatus",
            Box::pin(n.layer_pipeline_status()),
            Value::Null,
        ),
        (
            "tenzro_produceSnapshot",
            Box::pin(n.produce_snapshot()),
            Value::Null,
        ),
    ];
    for (method, call, params) in calls {
        let out = node
            .check(method, json!({"ok": method}), call, params)
            .await;
        assert_eq!(out["ok"], method);
    }
    node.check(
        "tenzro_setNodeVisibility",
        json!({}),
        n.set_visibility("gated"),
        json!({"visibility": "gated"}),
    )
    .await;
    node.check(
        "tenzro_gracefulExit",
        json!({"accepted": true}),
        n.graceful_exit(Some(30), Some(false)),
        json!({"max_wait_secs": 30, "force": false}),
    )
    .await;
    node.check(
        "tenzro_iroh_resolveTenzroUri",
        json!({}),
        n.iroh_resolve_tenzro_uri("tenzro://blob/ab"),
        json!({"tenzro_uri": "tenzro://blob/ab"}),
    )
    .await;
    node.check(
        "tenzro_setDraining",
        json!({"draining": true}),
        n.set_draining(Some(true)),
        json!({"draining": true}),
    )
    .await;
    node.check(
        "tenzro_getAccountContention",
        json!({"address": ADDR}),
        n.get_account_contention(ADDR),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_previewServe",
        json!({"model_id": "m", "fits": true}),
        n.preview_serve("m", Some("q4_k_m"), Some(4096), None),
        json!({"model_id": "m", "quant": "q4_k_m", "context_length": 4096}),
    )
    .await;
    let header = node
        .check(
            "tenzro_currentHeader",
            json!({"height": 9, "hash": "0xab", "timestamp_secs": 1, "now_secs": 2, "age_secs": 1, "tier": "live"}),
            n.current_header(),
            Value::Null,
        )
        .await;
    assert_eq!(header.tier, "live");
    let root = node
        .check(
            "tenzro_getStateRoot",
            json!({"height": 9, "state_root": "0xaa", "certified_by_checkpoint": null}),
            n.get_state_root(),
            Value::Null,
        )
        .await;
    assert_eq!(root.certified_by_checkpoint, None);
    let proof = node
        .check(
            "tenzro_getStateProof",
            json!({"height": 9, "state_root": "0xaa", "certified_by_checkpoint": 2, "namespace": "accounts", "key": "ab", "value": null, "proof": {}}),
            n.get_state_proof("accounts", "ab"),
            json!({"namespace": "accounts", "key": "ab"}),
        )
        .await;
    assert_eq!(proof.value, None);
}

#[tokio::test]
async fn consensus_reads() {
    let node = Node::start().await;
    let c = node.client().await.consensus();
    let cert = json!({"epoch": 1, "index": 4, "last_height": 40, "digest": "0xdd", "certificate": "0x01", "sessions": "0x02"});
    assert_eq!(
        node.check(
            "tenzro_getCheckpointCertificate",
            cert.clone(),
            c.get_checkpoint_certificate(Some(4)),
            json!([4])
        )
        .await
        .index,
        4
    );
    node.check(
        "tenzro_getCheckpointCertificate",
        cert,
        c.get_checkpoint_certificate(None),
        json!([]),
    )
    .await;
    let compact = json!({"epoch": 1, "index": 4, "last_height": 40, "certificate": "0x01", "sessions": "0x02"});
    assert_eq!(
        node.check(
            "tenzro_getCompactCertificate",
            compact,
            c.get_compact_certificate(),
            json!([])
        )
        .await
        .digest,
        None
    );
    node.check(
        "tenzro_getCommittee",
        json!({"epoch": 2, "root": "0x0r", "members": "0x0m"}),
        c.get_committee(2),
        json!([2]),
    )
    .await;
    node.check(
        "tenzro_getEpochHandover",
        json!({"epoch": 2, "index": 9, "certificate": "0x01", "sessions": "0x02", "next_members": "0x03"}),
        c.get_epoch_handover(2),
        json!([2]),
    )
    .await;
    node.check(
        "tenzro_getMempoolLane",
        json!({"lane": "public"}),
        c.get_mempool_lane(ADDR),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_getMempoolStats",
        json!({"lanes": []}),
        c.get_mempool_stats(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_getConsensusMetrics",
        json!({}),
        c.get_consensus_metrics(),
        Value::Null,
    )
    .await;
    let fin = node
        .check(
            "tenzro_getFinality",
            json!({"ordered": 12, "certified": 10, "certificate": {"epoch": 1, "index": 2, "first_height": 1, "last_height": 10, "state_height": 9, "state_root": "0xaa", "signers": 3}}),
            c.get_finality(),
            Value::Null,
        )
        .await;
    assert_eq!(fin.certificate.unwrap().signers, 3);
    node.check(
        "tenzro_getRewardEpoch",
        json!({"epoch": 3}),
        c.get_reward_epoch(3),
        json!({"epoch": 3}),
    )
    .await;
    node.check(
        "tenzro_getRewardSchedule",
        json!({}),
        c.get_reward_schedule(),
        Value::Null,
    )
    .await;
    node.check(
        "tenzro_listRewardCoupons",
        json!({"coupons": []}),
        c.list_reward_coupons(ADDR),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_getHardwareLevel",
        json!({"current": {"level": "l0"}}),
        c.get_hardware_level(ADDR),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_getVesting",
        json!({"schedules": []}),
        c.get_vesting(ADDR),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_validatorSelfStake",
        json!("0xhash"),
        c.validator_self_stake(Some(5)),
        json!({"additional": 5}),
    )
    .await;
}

#[tokio::test]
async fn discovery_and_moe() {
    let node = Node::start().await;
    let d = node.client().await.discovery();
    node.check(
        "tenzro_moeShardMap",
        json!({}),
        d.moe_shard_map("m"),
        json!({"model_id": "m"}),
    )
    .await;
    let routings = json!([{"token_index": 0, "experts": [{"layer": 1, "expert": 2}]}]);
    node.check(
        "tenzro_moePlanDispatch",
        json!({}),
        d.moe_plan_dispatch("m", routings.clone(), true),
        json!({"model_id": "m", "routings": routings, "allow_cold": true}),
    )
    .await;
    node.check(
        "tenzro_moeReplicationPolicy",
        json!({}),
        d.moe_replication_policy(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_moeCatalogShape",
        json!({}),
        d.moe_catalog_shape("m"),
        json!({"model_id": "m"}),
    )
    .await;
    node.check(
        "tenzro_moeExpertStatus",
        json!({}),
        d.moe_expert_status(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_moePrepareExperts",
        json!({}),
        d.moe_prepare_experts("m", 1, vec![2, 3], true, Value::Null),
        json!({"model_id": "m", "layer": 1, "experts": [2, 3], "include_gate": true}),
    )
    .await;
    let hidden = [1.0f32, -2.5, 0.25];
    let encoded = tenzro_sdk::discovery::encode_f32_base64(&hidden);
    node.check(
        "tenzro_moeForward",
        json!({"outputs": encoded}),
        d.moe_forward("m", 1, 3, &hidden),
        json!({"model_id": "m", "layer": 1, "d_model": 3, "hidden_states": encoded}),
    )
    .await;
    assert_eq!(
        tenzro_sdk::discovery::decode_f32_base64(&encoded).unwrap(),
        hidden.to_vec()
    );
    node.check("tenzro_nodeProfile", json!({}), d.node_profile(), json!([]))
        .await;
    node.check(
        "tenzro_deriveClusterMembership",
        json!({}),
        d.derive_cluster_membership("did:op", "c", 1, &["did:m".to_string()]),
        json!({"operator_did": "did:op", "name": "c", "seq": 1, "members": ["did:m"]}),
    )
    .await;
    node.check(
        "tenzro_setClusterMembership",
        json!({}),
        d.set_cluster_membership(json!({"m": 1}), "ch"),
        json!({"membership": {"m": 1}, "challenge_id": "ch"}),
    )
    .await;
    node.check(
        "tenzro_clusterMembers",
        json!({}),
        d.cluster_members(Some("did:c")),
        json!({"entry": "did:c"}),
    )
    .await;
    node.check(
        "tenzro_acceptClusterMembership",
        json!({}),
        d.accept_cluster_membership("did:c", 2),
        json!({"cluster_did": "did:c", "seq": 2}),
    )
    .await;
}

#[tokio::test]
async fn data_availability() {
    let node = Node::start().await;
    let da = node.client().await.da();
    node.check(
        "tenzro_daAvailability",
        json!({}),
        da.availability(Some(ADDR)),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_daChallenge",
        json!({}),
        da.challenge("0xcc", 3),
        json!({"commitment": "0xcc", "target_index": 3}),
    )
    .await;
    node.check("tenzro_daCommittee", json!({}), da.committee(), json!({}))
        .await;
    node.check("tenzro_daListBlobs", json!({}), da.list_blobs(), json!({}))
        .await;
    node.check(
        "tenzro_daListChallenges",
        json!({}),
        da.list_challenges(Some(4)),
        json!({"limit": 4}),
    )
    .await;
    node.check(
        "tenzro_getDaObject",
        json!({}),
        da.da_object("0xcc"),
        json!({"commitment": "0xcc"}),
    )
    .await;
    node.check(
        "tenzro_getDaRetention",
        json!({}),
        da.da_retention(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getDaBackends",
        json!([]),
        da.get_da_backends(),
        Value::Null,
    )
    .await;
    let pointer = json!({"backend": "inline"});
    node.check(
        "tenzro_verifyDaPointer",
        json!({}),
        da.verify_da_pointer(pointer.clone()),
        json!({"pointer": pointer}),
    )
    .await;
}

#[tokio::test]
async fn zero_knowledge() {
    let node = Node::start().await;
    let zk = node.client().await.zk();
    let proof = node
        .check(
            "tenzro_createZkProof",
            json!({"circuit_id": "settlement", "public_inputs": ["0x01", "0x02"], "statement_commitment": "0xsc", "proofs": [{"system": "koala-bear", "proof": "0xpp", "proof_size_bytes": 2}]}),
            zk.prove_settlement("0xw", "0xb"),
            json!({"circuit_id": "settlement", "witness": "0xw", "binding": "0xb"}),
        )
        .await;
    assert_eq!(proof.proofs[0].proof_size_bytes, Some(2));
    let verdict = node
        .check(
            "tenzro_verifyZkProof",
            json!({"valid": true, "circuit_id": "settlement", "statement_commitment": "0xsc", "legs": 1, "verified_systems": ["koala-bear"], "diverse_threshold": 2, "meets_diverse_threshold": false, "attestations": [], "error": null, "note": "n"}),
            zk.verify_proof(&proof.circuit_id, proof.public_inputs.clone(), proof.proofs.clone()),
            json!({"circuit_id": "settlement", "public_inputs": ["0x01", "0x02"], "proofs": [{"system": "koala-bear", "proof": "0xpp"}]}),
        )
        .await;
    assert!(verdict.valid && !verdict.meets_diverse_threshold);
    let circuit = json!({"type": "settlement", "name": "PreimageAir", "statement": "s", "public_inputs": [], "in_circuit_hash": "h", "node_provable": true, "proof_systems": [], "diverse_threshold": 2});
    let list = node
        .check(
            "tenzro_listCircuits",
            json!({"circuits": [circuit.clone()], "total": 1}),
            zk.list_circuits(),
            json!({}),
        )
        .await;
    assert_eq!(list[0].circuit_type, "settlement");
    assert_eq!(
        node.check(
            "tenzro_listZkCircuits",
            json!([circuit]),
            zk.list_zk_circuits(),
            json!({})
        )
        .await
        .len(),
        1
    );
    node.check(
        "tenzro_verifyTeeZkProof",
        json!({"admitted": false, "circuit_id": "settlement", "system": "s", "proof_and_binding_valid": true, "proof_and_binding_error": null, "attestation_valid": false, "attestation_error": "x", "vendor": "IntelTdx", "binding_digest": "0xbd"}),
        zk.verify_tee_zk_proof(json!({"b": 1})),
        json!({"tee_zk_proof": {"b": 1}}),
    )
    .await;
    node.check(
        "tenzro_attestFinalityProof",
        json!({"vendor": "IntelTdx", "binding_digest": "0xbd", "measurements": [], "tee_finality_proof": {}}),
        zk.attest_finality_proof("0xi", "0xj", "0xs"),
        json!({"image_id": "0xi", "journal": "0xj", "seal": "0xs"}),
    )
    .await;
    node.check(
        "tenzro_verifyTeeFinalityProof",
        json!({"admitted": true}),
        zk.verify_tee_finality_proof(json!({"b": 2})),
        json!({"tee_finality_proof": {"b": 2}}),
    )
    .await;
    node.check(
        "tenzro_createTeeZkProof",
        json!({"tee_zk_proof": {}, "binding_digest": "0xbd", "circuit_id": "settlement", "vendor": "intel-tdx"}),
        zk.create_tee_zk_proof("settlement", "intel-tdx", "0xw", "0xb"),
        json!({"circuit_id": "settlement", "vendor": "intel-tdx", "witness": "0xw", "binding": "0xb"}),
    )
    .await;
}

#[tokio::test]
async fn tee_and_crypto() {
    let node = Node::start().await;
    let c = node.client().await;
    let tee = c.tee();
    node.check(
        "tenzro_detectTee",
        json!({"available": false, "available_vendors": [], "vendor": null}),
        tee.detect_tee(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_getTeeAttestation",
        json!({"vendor": "IntelTdx", "user_data_hex": "0x00", "measurement_hex": "0x01", "measurements": [{"register": "MRTD", "algorithm": "sha384", "value_hex": "0x02"}], "report_hex": "0x03", "timestamp": 1}),
        tee.get_attestation(Some("0xab")),
        json!({"user_data": "0xab"}),
    )
    .await;
    node.check(
        "tenzro_teeAttestationChallenge",
        json!({"nonce": "0xn", "expires_in_secs": 60}),
        tee.attestation_challenge(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_verifyTeeAttestation",
        json!({"valid": false, "error": "x"}),
        tee.verify_attestation("0xr", "0xn", None, None),
        json!({"report_hex": "0xr", "nonce": "0xn"}),
    )
    .await;
    let list = node
        .check(
            "tenzro_listTeeProviders",
            json!({"providers": [{"id": "tee:ab", "info": {"vendor": "IntelTdx"}}], "total": 1, "local_tee_available": false, "local_vendor": null}),
            tee.list_tee_providers(),
            json!([]),
        )
        .await;
    assert_eq!(list.providers[0].id, "tee:ab");
    node.check(
        "tenzro_getZkAttestation",
        json!({"commitment_hex": "0xcc", "attested": true}),
        tee.get_zk_attestation("0xcc"),
        json!({"commitment": "0xcc"}),
    )
    .await;

    let crypto = c.crypto();
    let sig = json!({"p256": "aa", "ml_dsa": null});
    let v = node
        .check(
            "tenzro_verifySignature",
            json!({"valid": true, "pq_leg_verified": false, "pq_enrolled": false}),
            crypto.verify_signature("0x04ab", b"hi", &sig),
            json!({"public_key": "0x04ab", "message_hex": "6869", "signature": sig}),
        )
        .await;
    assert!(v.valid);
    let vrf = node
        .check(
            "tenzro_verifyVrfProof",
            json!({"valid": true, "output": "0xoo", "output_len": 1}),
            crypto.verify_vrf_proof("0xk", "0xp", "0xa"),
            json!({"pubkey": "0xk", "proof": "0xp", "alpha": "0xa"}),
        )
        .await;
    assert_eq!(vrf.output.as_deref(), Some("0xoo"));
}

#[tokio::test]
async fn events_and_iroh() {
    let node = Node::start().await;
    let c = node.client().await;
    let ev = c.events();
    let filter = json!({"event_types": ["Log"]});
    node.check(
        "tenzro_subscribe",
        json!({"events": [], "cursor": null}),
        ev.subscribe(&filter, Some("1:0:0"), 100, true),
        json!({"filter": filter, "wait_ms": 100, "proofs": true, "from_cursor": "1:0:0"}),
    )
    .await;
    node.check(
        "tenzro_queryEvents",
        json!({"events": []}),
        ev.query(&filter, None, Some("9:0:0"), 10, false, None),
        json!({"filter": filter, "limit": 10, "completeness": false, "to_cursor": "9:0:0"}),
    )
    .await;
    node.check(
        "tenzro_getEventProof",
        json!({"proof": {"p": 1}}),
        ev.proof("1:0:0", Some(2)),
        json!({"cursor": "1:0:0", "anchor_index": 2}),
    )
    .await;
    node.check(
        "tenzro_eventStatus",
        json!({}),
        ev.event_status(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_verifyEventProof",
        json!({"valid": true}),
        ev.verify_event_proof(Some(json!({"p": 1})), None),
        json!({"proof": {"p": 1}}),
    )
    .await;

    let iroh = c.iroh();
    let info = node
        .check(
            "tenzro_iroh_getInfo",
            json!({"endpoint_id": "e", "endpoint_id_hex": "ab", "machine_did": "did:m", "relays": [], "boot_peers": [], "known_identities": 2, "docs_enabled": false, "bound_alpns": ["iroh-blobs"]}),
            iroh.get_info(),
            json!({}),
        )
        .await;
    assert_eq!(info.bound_alpns, vec!["iroh-blobs".to_string()]);
    node.check(
        "tenzro_iroh_getEndpointId",
        json!({"endpoint_id": "e", "endpoint_id_hex": "ab"}),
        iroh.get_endpoint_id(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_iroh_listAlpns",
        json!({"alpns": [{"alpn": "iroh-blobs", "description": "d"}]}),
        iroh.list_alpns(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_iroh_publishBlob",
        json!({"tenzro_uri": "tenzro://blob/ab", "size_bytes": 2}),
        iroh.publish_blob(b"hi".to_vec()),
        json!({"bytes_b64": "aGk="}),
    )
    .await;
    let bytes = node
        .check(
            "tenzro_iroh_fetchBlob",
            json!({"tenzro_uri": "u", "bytes_b64": "aGk=", "size_bytes": 2}),
            iroh.fetch_blob("u"),
            json!({"tenzro_uri": "u"}),
        )
        .await;
    assert_eq!(bytes, b"hi");
}

#[tokio::test]
async fn staking_validators_and_sla() {
    let node = Node::start().await;
    let c = node.client().await;
    let s = c.staking();
    node.check(
        "tenzro_getRoleStakes",
        json!({"address": ADDR, "stakes": [], "totals": []}),
        s.role_stakes(Some(ADDR)),
        json!({"address": ADDR}),
    )
    .await;
    node.check(
        "tenzro_listRoleEndpoints",
        json!({"role": "rpc", "endpoints": []}),
        s.role_endpoints("rpc"),
        json!({"role": "rpc"}),
    )
    .await;
    node.check(
        "tenzro_listRelays",
        json!({"relays": []}),
        s.relays(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getConnectivity",
        json!({"reachability": "direct", "nat": "none", "observers": 0, "port_mapped": false, "external_addresses": 0, "ipv4": true, "ipv6": false, "relays": [], "punched_paths": 0, "peer_relays": []}),
        s.connectivity(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getWalletProvider",
        json!({"rp_id": "tenzro.com", "staked": false, "providers": []}),
        s.wallet_provider("tenzro.com"),
        json!({"rp_id": "tenzro.com"}),
    )
    .await;

    let v = c.validators();
    assert!(
        node.check(
            "tenzro_getValidatorState",
            json!({"status": "Active"}),
            v.get_state(ADDR),
            json!({"address": ADDR})
        )
        .await
        .is_some()
    );
    node.check(
        "tenzro_listValidators",
        json!({"count": 0, "validators": []}),
        v.list(Some(tenzro_sdk::ValidatorStatus::Active)),
        json!({"status": "Active"}),
    )
    .await;
    node.check(
        "tenzro_listActiveValidators",
        json!({"count": 0, "validators": []}),
        v.list_active(),
        json!({}),
    )
    .await;

    let sla = c.sla();
    node.check(
        "tenzro_slaIssueProbe",
        json!({"provider_did": "did:p", "epoch": 1, "round": 2}),
        sla.issue_probe("did:p", 1, 2, 99),
        json!({"provider_did": "did:p", "epoch": 1, "round": 2, "deadline_ms": 99}),
    )
    .await;
    node.check(
        "tenzro_slaListOutstandingProbes",
        json!({"count": 0, "probes": []}),
        sla.list_outstanding_probes(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_slaGetParams",
        json!({"unavailable_penalty_wei": "1", "vrf_pubkey": "0x"}),
        sla.get_params(),
        json!([]),
    )
    .await;
    node.check(
        "tenzro_slaVerdict",
        json!({"available": true}),
        sla.sla_verdict("did:p", 4),
        json!({"provider_did": "did:p", "epoch": 4}),
    )
    .await;

    let duty = c.duty();
    node.check(
        "tenzro_listDuties",
        json!({"count": 0, "duties": []}),
        duty.list(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getDuty",
        json!({"duty_id": "0xd"}),
        duty.get("0xd"),
        json!({"duty_id": "0xd"}),
    )
    .await;
    node.check(
        "tenzro_verifyEvidence",
        json!({"items": []}),
        duty.verify_evidence(json!([])),
        json!({"items": []}),
    )
    .await;

    let ins = c.insurance();
    node.check(
        "tenzro_getInsurancePoolBalance",
        json!({}),
        ins.pool(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_listInsuranceClaims",
        json!({"count": 0, "claims": []}),
        ins.list_claims(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getInsuranceClaim",
        json!({"claim_id": "0xc"}),
        ins.get_claim("0xc"),
        json!({"claim_id": "0xc"}),
    )
    .await;
}

#[tokio::test]
async fn snapshots_storage_tokens_and_reserves() {
    let node = Node::start().await;
    let c = node.client().await;
    let snap = c.snapshot();
    node.check("tenzro_listSnapshots", json!({"snapshots": [{"height": 1, "state_root": "0xa", "manifest_blob": "b", "buckets": 2}], "endpoint_id": null}), snap.list_snapshots(), json!([])).await;
    node.check(
        "tenzro_getSnapshotManifest",
        json!({"height": 1, "state_root": [0], "anchor_chain": [0], "buckets": []}),
        snap.get_snapshot_manifest(1),
        json!({"height": 1}),
    )
    .await;

    let st = c.storage();
    node.check(
        "tenzro_storageStoreObject",
        json!({"object_id": "o", "size_bytes": 2, "data_shards": 4, "parity_shards": 2}),
        st.store_object("o", ADDR, b"hi", 4, 2, "did:tenzro:human:o", &FixedSigner),
        json!({"object_id": "o", "owner": ADDR, "data": "aGk=", "data_shards": 4, "parity_shards": 2, "owner_did": "did:tenzro:human:o"}),
    )
    .await;
    assert_eq!(
        node.check(
            "tenzro_storageRetrieveObject",
            json!({"object_id": "o", "data": "aGk=", "size_bytes": 2}),
            st.retrieve_object("o", "did:tenzro:human:o", &FixedSigner),
            json!({"object_id": "o"})
        )
        .await,
        b"hi"
    );
    node.check(
        "tenzro_storageSetPricing",
        json!({"mode": "fixed"}),
        st.set_fixed_rate(7),
        json!({"mode": "fixed", "rate": "7"}),
    )
    .await;
    node.check(
        "tenzro_storageStatus",
        json!({"is_storage_provider": true, "effective_rate_wei": "7", "object_count": 1}),
        st.status(),
        json!([]),
    )
    .await;

    let t = c.token();
    node.check(
        "tenzro_canTransfer",
        json!({"allowed": true}),
        t.can_transfer("0xt", ADDR, ADDR, 5),
        json!({"token_id": "0xt", "from": ADDR, "to": ADDR, "amount": "5"}),
    )
    .await;
    node.check(
        "tenzro_getToken",
        json!({"symbol": "TNZO"}),
        t.get_token_info(Some("TNZO"), None, None),
        json!({"symbol": "TNZO"}),
    )
    .await;
    node.check(
        "tenzro_listTokens",
        json!({"count": 0, "tokens": []}),
        t.list_tokens(Some("evm"), Some(3)),
        json!({"vm_type": "evm", "limit": 3}),
    )
    .await;
    let bal = node
        .check(
            "tenzro_getTokenBalance",
            json!({"address": ADDR, "native": {"balance_wei": "5", "decimals": 18}, "evm_wtnzo": {"balance_wei": "5", "decimals": 18}, "svm_wtnzo": {"balance_base_units": "0", "decimals": 9}}),
            t.get_token_balance(ADDR),
            json!({"address": ADDR}),
        )
        .await;
    assert_eq!(bal.native.balance_wei, "5");
    node.check(
        "tenzro_readPorReserve",
        json!({}),
        t.read_por_reserve("a"),
        json!({"asset_id": "a"}),
    )
    .await;
    node.check(
        "tenzro_getReserveFeed",
        json!({"asset_id": "a", "feed": null}),
        t.get_reserve_feed("a"),
        json!({"asset_id": "a"}),
    )
    .await;

    let r = c.reserve();
    node.check(
        "tenzro_submitReserveAttestation",
        json!({}),
        r.submit_reserve_attestation(json!({"asset_id": "a"})),
        json!({"attestation": {"asset_id": "a"}}),
    )
    .await;
    node.check(
        "tenzro_getReserve",
        json!({}),
        r.get_reserve("a"),
        json!({"asset_id": "a"}),
    )
    .await;
    node.check(
        "tenzro_buildReserveAttestationFromPor",
        json!({}),
        r.build_reserve_attestation_from_por("a", "did:x"),
        json!({"asset_id": "a", "attestor_did": "did:x"}),
    )
    .await;

    let u = c.urwa();
    node.check(
        "tenzro_urwaIsKillSwitched",
        json!({"token_id_hex": "ab", "active": false}),
        u.is_kill_switched("ab"),
        json!({"token_id_hex": "ab"}),
    )
    .await;
    node.check(
        "tenzro_urwaGetFrozenTokens",
        json!({"token_id_hex": "ab", "account_hex": "cd", "frozen_amount": "0"}),
        u.get_frozen_tokens("ab", "cd"),
        json!({"token_id_hex": "ab", "account_hex": "cd"}),
    )
    .await;
}

#[tokio::test]
async fn economics_gateway_and_payments() {
    let node = Node::start().await;
    let c = node.client().await;
    let b = c.adaptive_burn();
    node.check(
        "tenzro_getBurnRateConfig",
        json!({}),
        b.get_burn_rate_config(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getEconomicPolicy",
        json!({}),
        b.get_economic_policy(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getSupplyMetrics",
        json!({}),
        b.get_supply_metrics(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getBurnRateRecommendation",
        json!({}),
        b.get_burn_rate_recommendation(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getFeeRate",
        json!({"rate_nano_usd": "5"}),
        b.get_fee_rate(),
        json!({}),
    )
    .await;
    node.check(
        "tenzro_getFeeRate",
        json!({"symbol": "ETH"}),
        b.get_symbol_rate("ETH"),
        json!({"symbol": "ETH"}),
    )
    .await;
    node.check(
        "tenzro_getEconomyMetrics",
        json!({}),
        b.get_economy_metrics(Some(2)),
        json!({"epoch": 2}),
    )
    .await;
    assert_eq!(
        node.check(
            "tenzro_getFeeRate",
            json!({"rate_nano_usd": "5"}),
            c.registry().tnzo_usd_nano(),
            json!({})
        )
        .await,
        5
    );

    let dir = node
        .check(
            "tenzro_listRpcMethods",
            json!({"methods": [{"method": "tenzro_getBalance", "gate": "open", "class": "read", "namespace": "tenzro"}], "count": 1, "total": 400, "namespaces": ["tenzro"]}),
            c.gateway().methods(Some("tenzro"), Some("Balance")),
            json!({"namespace": "tenzro", "contains": "Balance"}),
        )
        .await;
    assert_eq!(dir.methods[0].method, "tenzro_getBalance");
    node.check(
        "tenzro_quotePayment",
        json!({"usd_e6": 1, "unit": {"basket": "USD", "version": 1}, "rate_epoch": null, "assets": [{"asset": "TNZO", "amount": "5", "fee": "1", "fee_asset": "TNZO", "rate_epoch": null}]}),
        c.payment().quote(1, &[]),
        json!({"usd_e6": 1}),
    )
    .await;
}

struct FixedSigner;

#[async_trait::async_trait]
impl HybridSigner for FixedSigner {
    fn p256_public_key(&self) -> [u8; 64] {
        [7; 64]
    }
    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    async fn sign_composite(&self, _m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        Ok(([9; 64], None))
    }
    async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
        Ok([9; 64])
    }
}

#[tokio::test]
async fn a_contract_deploy_sends_nothing_when_the_node_payload_does_not_match() {
    let node = Node::start().await;
    let c = node.client().await;
    node.answer("tenzro_getNonce", json!("0x2"));
    node.answer("eth_chainId", json!("0x3444"));
    node.answer("eth_gasPrice", json!("0x1"));
    node.answer(
        "tenzro_getSigningPayload",
        json!({"kind": "plain", "tx_type_json": "{}"}),
    );
    let err = c
        .contract()
        .deploy(&FixedSigner, &[0x60, 0x00], &[], None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("signing payload"), "{err}");
    let seen = node.seen.lock().unwrap();
    assert!(
        seen.iter()
            .any(|r| r["method"] == "tenzro_getSigningPayload")
    );
    assert!(!seen.iter().any(|r| r["method"] == "tenzro_deployContract"));
}
