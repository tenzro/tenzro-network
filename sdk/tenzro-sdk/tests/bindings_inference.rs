//! Every inference binding against a recording JSON-RPC node: each sends the
//! method and the params the node's handler reads, and decodes the answer the
//! handler writes.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tenzro_sdk::TenzroClient;
use tenzro_sdk::inference::{IntentParams, RouteOutcome};
use tenzro_sdk::multimodal::{
    DecisionOption, DecisionQuestion, DetectParams, EmbedInput, ForecastParams, ImageEmbedParams,
    LoadModelParams, LoadVideoModelParams, SegmentParams, TaskRouting, TextEmbedParams,
    TextSegmentParams, TranscribeParams, VideoEmbedParams,
};
use tenzro_sdk::provider::{
    ChatMessage, ChatOptions, InstallSealedModelRequest, MicroNodeIdentity, SealModelRequest,
    SealRecipient, ServeOptions, Visibility,
};
use tenzro_sdk::rpc::RpcClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MODEL: &str = "qwen3-0.6b";

/// A node answering each method from `answers` (anything else answers
/// `{"ok": <method>}`) and recording every request it is sent.
struct Node {
    url: String,
    sent: Arc<Mutex<Vec<Value>>>,
}

impl Node {
    async fn start(answers: HashMap<&'static str, Value>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let sent = Arc::new(Mutex::new(Vec::new()));
        let record = sent.clone();
        let answers = Arc::new(answers);
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let record = record.clone();
                let answers = answers.clone();
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
                    let result = answers
                        .get(method.as_str())
                        .cloned()
                        .unwrap_or_else(|| json!({ "ok": method }));
                    record.lock().unwrap().push(request.clone());
                    let body = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result })
                        .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    sock.write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        Self { url, sent }
    }

    async fn client(&self) -> TenzroClient {
        TenzroClient::new(&self.url).await.unwrap()
    }

    /// The one request sent since the last call, as (method, params).
    fn take(&self) -> (String, Value) {
        let mut sent = self.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "expected one request, got {sent:?}");
        let r = sent.remove(0);
        (
            r["method"].as_str().unwrap().to_string(),
            r["params"].clone(),
        )
    }

    /// Every method seen across `take` calls is collected by the caller.
    fn expect(&self, seen: &mut BTreeSet<String>, method: &str, params: Value) {
        let (m, p) = self.take();
        assert_eq!(m, method);
        assert_eq!(p, params, "{method}");
        seen.insert(m);
    }

    /// Like [`Self::expect`], checking only the named fields of an object
    /// (or of the object in a one-element array).
    fn expect_fields(&self, seen: &mut BTreeSet<String>, method: &str, fields: Value) {
        let (m, p) = self.take();
        assert_eq!(m, method);
        let obj = if p.is_array() { p[0].clone() } else { p };
        for (k, v) in fields.as_object().unwrap() {
            assert_eq!(&obj[k], v, "{method}: {k} in {obj}");
        }
        seen.insert(m);
    }
}

fn registry_entry() -> Value {
    json!({
        "id": "id-1", "kind": "price-card", "owner": "0xab", "version": 2, "anchor": "00",
        "data": "", "digest": "00", "put_at_ms": 1, "retired_at_ms": null, "standing": true,
    })
}

fn answers() -> HashMap<&'static str, Value> {
    HashMap::from([
        (
            "tenzro_chat",
            json!({
                "model": MODEL,
                "content": [{ "type": "text", "text": "he" }, { "type": "text", "text": "llo" }],
                "usage": { "input_tokens": 3, "output_tokens": 2 },
            }),
        ),
        (
            "tenzro_getHardwareProfile",
            json!({
                "cpu_model": "x", "cpu_cores": 8, "cpu_threads": 16, "total_ram_gb": 64.0,
                "gpus": [{ "vendor": "Nvidia", "name": "GB10", "vram_gb": 128, "compute_capability": "12.1", "fp8": true, "fp4": true }],
                "storage_available_gb": 100.0, "tee_available": false, "tee_vendor": null,
                "os": "linux", "arch": "aarch64", "device_fingerprint": "fp",
                "hardware_root": null, "hardware_root_sources": [],
            }),
        ),
        (
            "tenzro_getRole",
            json!({ "roles": ["ai", "validator"], "roles_str": "ai,validator" }),
        ),
        (
            "tenzro_getProviderStats",
            json!({
                "address": "0xab", "total_requests": 4, "successful": 3, "failed": 1,
                "avg_latency_ms": 20, "p95_latency_ms": null, "uptime_percentage": 99.5,
                "reputation": null, "inference_count": 3, "total_input_tokens": 10,
                "total_output_tokens": 20, "measured_tokens_per_sec": 41.5,
                "total_revenue_wei": "700", "last_inference_ms": 1_700_000_000_000_i64,
                "max_concurrent": 4, "current_active": 0, "advertised_requests_per_second": 2,
                "served_models": 1, "role_stakes": [{ "role": "ai", "bonded": "1" }], "utilization": "Active",
            }),
        ),
        (
            "tenzro_computeBondParams",
            json!({ "min_bond_wei": "1000", "cooldown_ms": 60000 }),
        ),
        (
            "tenzro_getComputeBond",
            json!({
                "provider_did": "did:tenzro:machine:a", "provider_address": "0xab", "amount": "5",
                "status": "Active", "cooldown_until": null, "vault": "0xcd", "is_eligible": true,
                "effective_amount": "5",
            }),
        ),
        (
            "tenzro_listComputeBonds",
            json!({ "count": 0, "bonds": [] }),
        ),
        ("tenzro_listModelEndpoints", json!([])),
        (
            "tenzro_listProviders",
            json!({
                "providers": [
                    { "endpoint_id": "e1", "provider_address": "0xab", "is_local": true },
                    { "did": "did:tenzro:machine:agent", "source": "delegated" }
                ],
                "next_cursor": null
            }),
        ),
        (
            "tenzro_listModels",
            json!([{ "id": MODEL, "name": "Qwen3 0.6B", "description": "d", "architecture": "qwen3" }]),
        ),
        (
            "tenzro_inferenceRequest",
            json!({
                "model_id": MODEL, "output": "hi", "thinking": null, "input_tokens": 2,
                "output_tokens": 5, "generation_time_ms": 9, "tokens_per_second": 50.0,
                "cost_wei": "12", "settlement": {}, "provider": "local",
                "tenzro_receipt": null, "commitment": null,
            }),
        ),
        (
            "tenzro_routeIntent",
            json!({ "model_id": MODEL, "tier": "fast", "reason": "cheapest" }),
        ),
        (
            "tenzro_getGeneration",
            json!({ "id": "gen-1", "model": MODEL, "input_tokens": 2 }),
        ),
        ("tenzro_listInferenceUsage", json!({ "records": [] })),
        (
            "tenzro_signChallengeVote",
            json!({ "voter": "0xvv", "public_key": "pk", "signature": "sig" }),
        ),
        ("tenzro_listForecastCatalog", json!({ "models": [] })),
        ("tenzro_listVisionCatalog", json!({ "models": [] })),
        ("tenzro_listTextEmbeddingCatalog", json!({ "models": [] })),
        ("tenzro_listSegmentationCatalog", json!({ "models": [] })),
        (
            "tenzro_listTextSegmentationCatalog",
            json!({ "models": [] }),
        ),
        ("tenzro_listDetectionCatalog", json!({ "models": [] })),
        ("tenzro_listAudioCatalog", json!({ "models": [] })),
        ("tenzro_listVideoCatalog", json!({ "models": [] })),
        (
            "tenzro_imageEmbed",
            json!({ "embedding": [0.5, 0.5], "dim": 2, "generation_time_ms": 3 }),
        ),
        (
            "tenzro_videoEmbed",
            json!({ "embedding": [1.0], "dim": 1, "frames_consumed": 8 }),
        ),
        (
            "tenzro_textEmbed",
            json!({ "embeddings": [[1.0, 0.0]], "dim": 2, "prompt_tokens": 1 }),
        ),
        (
            "tenzro_imageTextSimilarity",
            json!({ "similarity": 0.25, "dim": 2 }),
        ),
        (
            "tenzro_detect",
            json!({
                "detections": [{ "bbox": [0.0, 0.0, 4.0, 4.0], "label_id": 3, "label": "car", "score": 0.9 }],
                "generation_time_ms": 7, "cost_wei": "0", "units": {}, "settlement": {},
            }),
        ),
        (
            "tenzro_mediaGen_listCatalog",
            json!({ "count": 0, "models": [] }),
        ),
        (
            "tenzro_listRegistry",
            json!({ "kind": "price-card", "entries": [], "next": null }),
        ),
        ("tenzro_getRegistryEntry", registry_entry()),
        ("tenzro_getPriceCard", {
            let mut e = registry_entry();
            e["card"] = json!({ "model_id": MODEL, "model_hash": "00", "rates": {} });
            e
        }),
        (
            "tenzro_getFeeRate",
            json!({ "rate_nano_usd": "1500000000" }),
        ),
        (
            "tenzro_iroh_fetchBlob",
            json!({ "tenzro_uri": "tenzro://blob/aa", "size_bytes": 3, "bytes_b64": "AQID" }),
        ),
        (
            "tenzro_getNodeStatus",
            json!({ "state": "running", "block_height": 7, "peer_count": 2 }),
        ),
        ("tenzro_serveModel", json!({ "success": true })),
        ("tenzro_stopModel", json!({ "success": true })),
        ("tenzro_deleteModel", json!({ "success": true })),
        ("tenzro_setRole", json!({ "success": true })),
        (
            "tenzro_loadForecastModel",
            json!({ "model_id": "chronos", "loaded": true }),
        ),
        (
            "tenzro_loadVisionModel",
            json!({ "model_id": "clip", "loaded": true }),
        ),
        (
            "tenzro_loadTextEmbeddingModel",
            json!({ "model_id": "e5", "loaded": true }),
        ),
        (
            "tenzro_loadSegmentationModel",
            json!({ "model_id": "sam", "loaded": true }),
        ),
        (
            "tenzro_loadTextSegmentationModel",
            json!({ "model_id": "sam3", "loaded": true }),
        ),
        (
            "tenzro_loadDetectionModel",
            json!({ "model_id": "rfdetr", "loaded": true }),
        ),
        (
            "tenzro_loadRerankModel",
            json!({ "model_id": "bge", "loaded": true }),
        ),
        (
            "tenzro_loadDecisionModel",
            json!({ "model_id": "laya", "loaded": true }),
        ),
        (
            "tenzro_loadTrainingModel",
            json!({ "model_id": MODEL, "loaded": true }),
        ),
        (
            "tenzro_loadSpeechModel",
            json!({ "model_id": "kokoro", "loaded": true }),
        ),
        (
            "tenzro_loadAudioModel",
            json!({ "model_id": "whisper", "loaded": true }),
        ),
        (
            "tenzro_loadVideoModel",
            json!({ "model_id": "vjepa", "loaded": true }),
        ),
        (
            "tenzro_unloadForecastModel",
            json!({ "model_id": "chronos", "removed": true }),
        ),
        (
            "tenzro_unloadVisionModel",
            json!({ "model_id": "clip", "removed": true }),
        ),
        (
            "tenzro_unloadTextEmbeddingModel",
            json!({ "model_id": "e5", "removed": true }),
        ),
        (
            "tenzro_unloadSegmentationModel",
            json!({ "model_id": "sam", "removed": true }),
        ),
        (
            "tenzro_unloadTextSegmentationModel",
            json!({ "model_id": "sam3", "removed": true }),
        ),
        (
            "tenzro_unloadDetectionModel",
            json!({ "model_id": "rfdetr", "removed": true }),
        ),
        (
            "tenzro_unloadRerankModel",
            json!({ "model_id": "bge", "removed": true }),
        ),
        (
            "tenzro_unloadDecisionModel",
            json!({ "model_id": "laya", "removed": true }),
        ),
        (
            "tenzro_unloadTrainingModel",
            json!({ "model_id": MODEL, "removed": true }),
        ),
        (
            "tenzro_unloadSpeechModel",
            json!({ "model_id": "kokoro", "removed": true }),
        ),
        (
            "tenzro_unloadAudioModel",
            json!({ "model_id": "whisper", "removed": true }),
        ),
        (
            "tenzro_unloadVideoModel",
            json!({ "model_id": "vjepa", "removed": true }),
        ),
    ])
}

#[tokio::test]
async fn provider_bindings_send_what_the_node_reads() {
    let node = Node::start(answers()).await;
    let c = node.client().await;
    let p = c.provider();
    let mut seen = BTreeSet::new();

    p.serve_model(MODEL).await.unwrap();
    node.expect(&mut seen, "tenzro_serveModel", json!({ "model_id": MODEL }));
    p.serve_model_with(
        MODEL,
        ServeOptions {
            visibility: Some(Visibility::Gated),
            max_concurrent: Some(4),
            load_drafter: Some(false),
        },
    )
    .await
    .unwrap();
    node.expect(
        &mut seen,
        "tenzro_serveModel",
        json!({ "model_id": MODEL, "visibility": "gated", "max_concurrent": 4, "load_drafter": false }),
    );
    p.stop_model(MODEL).await.unwrap();
    node.expect(&mut seen, "tenzro_stopModel", json!({ "model_id": MODEL }));
    p.delete_model(MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_deleteModel",
        json!({ "model_id": MODEL }),
    );

    let chat = p.chat(MODEL, vec![ChatMessage::user("hi")]).await.unwrap();
    assert_eq!(chat.response, "hello");
    assert_eq!(chat.model_id, MODEL);
    assert_eq!(chat.tokens_used, 5);
    node.expect_fields(&mut seen, "tenzro_chat", json!({ "model_id": MODEL }));
    p.chat_with(
        MODEL,
        vec![ChatMessage::user("hi")],
        ChatOptions {
            max_tokens: Some(8),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_chat",
        json!({ "model_id": MODEL, "max_tokens": 8 }),
    );

    let hw = p.get_hardware_profile().await.unwrap();
    assert_eq!(hw.gpus[0].vram_gb, 128);
    node.expect(&mut seen, "tenzro_getHardwareProfile", json!([]));
    p.set_roles("ai,validator").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_setRole",
        json!([{ "roles": "ai,validator" }]),
    );
    assert_eq!(p.get_roles().await.unwrap(), vec!["ai", "validator"]);
    node.expect(&mut seen, "tenzro_getRole", json!([]));

    let stats = p.stats().await.unwrap();
    assert_eq!(stats.total_requests, 4);
    assert_eq!(stats.served_models, 1);
    assert_eq!(stats.total_revenue_wei, "700");
    assert_eq!(stats.utilization, "Active");
    node.expect(&mut seen, "tenzro_getProviderStats", json!({}));
    p.get_provider_stats("0xab").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getProviderStats",
        json!({ "address": "0xab" }),
    );

    assert!(p.list_model_endpoints().await.unwrap().is_empty());
    node.expect(&mut seen, "tenzro_listModelEndpoints", json!([]));
    p.join_as_micro_node(
        &MicroNodeIdentity::Human {
            public_key: "04ab".into(),
            credential_id: "cd".into(),
        },
        Some("alice"),
        None,
    )
    .await
    .unwrap();
    node.expect(
        &mut seen,
        "tenzro_joinAsMicroNode",
        json!({ "public_key": "04ab", "credential_id": "cd", "display_name": "alice" }),
    );
    p.join_as_micro_node(
        &MicroNodeIdentity::Machine {
            public_key: "04ab".into(),
            machine_id: "m1".into(),
        },
        None,
        Some("machine"),
    )
    .await
    .unwrap();
    node.expect(
        &mut seen,
        "tenzro_joinAsMicroNode",
        json!({ "public_key": "04ab", "machine_id": "m1", "participant_type": "machine" }),
    );
    p.preview_serve(MODEL, Some("q4_k_m"), Some(4096), None)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_previewServe",
        json!({ "model_id": MODEL, "quant": "q4_k_m", "context_length": 4096 }),
    );
    p.get_model_stacks().await.unwrap();
    node.expect(&mut seen, "tenzro_getModelStacks", json!([]));
    p.set_provider_pricing(json!({ "default": { "lines": {} } }))
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_setProviderPricing",
        json!({ "default": { "lines": {} } }),
    );
    p.get_provider_pricing().await.unwrap();
    node.expect(&mut seen, "tenzro_getProviderPricing", json!([]));
    p.get_model_endpoint("i1").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getModelEndpoint",
        json!({ "instance_id": "i1" }),
    );
    p.register_model_endpoint(MODEL, Some("https://m.test/mcp"), None, None)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_registerModelEndpoint",
        json!({ "model_id": MODEL, "mcp_endpoint": "https://m.test/mcp", "model_name": null, "provider_name": null }),
    );
    p.unregister_model_endpoint("i1").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_unregisterModelEndpoint",
        json!({ "instance_id": "i1" }),
    );
    p.get_node_status().await.unwrap();
    node.expect(&mut seen, "tenzro_getNodeStatus", json!([]));

    let params = p.compute_bond_params().await.unwrap();
    assert_eq!(params.min_bond_wei, "1000");
    node.expect(&mut seen, "tenzro_computeBondParams", json!([]));
    let bond = p
        .get_compute_bond("did:tenzro:machine:a")
        .await
        .unwrap()
        .unwrap();
    assert!(bond.is_eligible);
    node.expect(
        &mut seen,
        "tenzro_getComputeBond",
        json!([{ "provider_did": "did:tenzro:machine:a" }]),
    );
    assert!(p.list_compute_bonds().await.unwrap().is_empty());
    node.expect(&mut seen, "tenzro_listComputeBonds", json!([]));
    assert_eq!(
        p.list_providers().await.unwrap()[0].provider_address,
        "0xab"
    );
    node.expect(
        &mut seen,
        "tenzro_listProviders",
        json!({ "limit": 200, "cursor": null }),
    );
    p.quote_inference(MODEL, json!({ "input_tokens": 800 }), Some("receipt"), None)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_quoteInference",
        json!({ "model": MODEL, "units": { "input_tokens": 800 }, "verification": "receipt", "provider": null }),
    );

    p.get_sealed_model(MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getSealedModel",
        json!({ "model_id": MODEL }),
    );
    p.list_sealed_models().await.unwrap();
    let (m, _) = node.take();
    assert_eq!(m, "tenzro_listSealedModels");
    seen.insert(m);
    p.seal_model(&SealModelRequest {
        model_id: MODEL.into(),
        path: "/m".into(),
        owner_did: "did:o".into(),
        artifact_name: None,
        shard_bytes: None,
        recipients: vec![SealRecipient {
            did: "did:r".into(),
            recipient_key: "aa".into(),
            enclave_measurement_hex: None,
        }],
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_sealModel",
        json!({ "model_id": MODEL, "path": "/m", "owner_did": "did:o", "recipients": [{ "did": "did:r", "recipient_key": "aa" }] }),
    );
    p.install_sealed_model(&InstallSealedModelRequest {
        recipient_did: "did:r".into(),
        manifest: None,
        model_id: Some(MODEL.into()),
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_installSealedModel",
        json!({ "recipient_did": "did:r", "model_id": MODEL }),
    );
    p.model_recipient_key().await.unwrap();
    let (m, _) = node.take();
    assert_eq!(m, "tenzro_modelRecipientKey");
    seen.insert(m);
    p.prune_model_registry().await.unwrap();
    let (m, _) = node.take();
    assert_eq!(m, "tenzro_pruneModelRegistry");
    seen.insert(m);
    p.get_territory_policy().await.unwrap();
    node.expect(&mut seen, "tenzro_getTerritoryPolicy", json!([]));
    p.model_lifecycle(None).await.unwrap();
    node.expect(&mut seen, "tenzro_modelLifecycle", json!({}));
    p.model_lifecycle(Some(MODEL)).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_modelLifecycle",
        json!({ "model_id": MODEL }),
    );

    p.moe_expert_load(MODEL, 1, 2, "tenzro://blob/aa")
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeExpertLoad",
        json!({ "model_id": MODEL, "layer": 1, "expert": 2, "uri": "tenzro://blob/aa" }),
    );
    p.moe_expert_unload(MODEL, 1, 2).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeExpertUnload",
        json!({ "model_id": MODEL, "layer": 1, "expert": 2 }),
    );
    p.moe_gate_load(MODEL, 1, "tenzro://blob/bb").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeGateLoad",
        json!({ "model_id": MODEL, "layer": 1, "uri": "tenzro://blob/bb" }),
    );
    p.moe_gate_unload(MODEL, 1).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeGateUnload",
        json!({ "model_id": MODEL, "layer": 1 }),
    );
    p.moe_prepare_status("j").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moePrepareStatus",
        json!({ "job_id": "j" }),
    );
    p.moe_list_receipts(Some(MODEL), Some(2)).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeListReceipts",
        json!({ "model_id": MODEL, "limit": 2 }),
    );

    p.compute_get_claim("0x01").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_computeGetClaim",
        json!({ "claim_id": "0x01" }),
    );
    p.compute_list_claims("0xab", Some(5)).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_computeListClaims",
        json!({ "party": "0xab", "limit": 5 }),
    );
    p.compute_price_feed(Some(MODEL), None, Some(true), None)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_computePriceFeed",
        json!({ "model_id": MODEL, "region": null, "attested_only": true, "limit": null }),
    );
    p.build_model_manifest(MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_buildModelManifest",
        json!({ "name": MODEL }),
    );
    p.pin_model(MODEL).await.unwrap();
    node.expect(&mut seen, "tenzro_pinModel", json!({ "model_id": MODEL }));
    p.unpin_model(MODEL).await.unwrap();
    node.expect(&mut seen, "tenzro_unpinModel", json!({ "model_id": MODEL }));
    p.model_metadata(MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_modelMetadata",
        json!({ "model_id": MODEL }),
    );
    p.get_attestation_log().await.unwrap();
    node.expect(&mut seen, "tenzro_getAttestationLog", json!({}));

    c.sponsored_inference(MODEL, "hi", "did:tenzro:machine:s", Some(32))
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_sponsoredInference",
        json!([{ "model": MODEL, "input": "hi", "sponsor": "did:tenzro:machine:s", "max_tokens": 32 }]),
    );

    assert_eq!(seen.len(), 46, "{seen:?}");
}

#[tokio::test]
async fn inference_bindings_send_what_the_node_reads() {
    let node = Node::start(answers()).await;
    let c = node.client().await;
    let i = c.inference();
    let mut seen = BTreeSet::new();

    let models = i.list_models().await.unwrap();
    assert_eq!(
        models[0].model_id, MODEL,
        "listModels names each model `id`"
    );
    node.expect(&mut seen, "tenzro_listModels", json!([]));
    let out = i.request(MODEL, "hi", Some(16)).await.unwrap();
    assert_eq!(out.output, "hi");
    assert_eq!(out.tokens_used(), 7);
    assert_eq!(out.cost_wei, "12");
    node.expect(
        &mut seen,
        "tenzro_inferenceRequest",
        json!([{ "model_id": MODEL, "input": "hi", "max_tokens": 16 }]),
    );
    let decision = i.route_intent(&IntentParams::new("chat")).await.unwrap();
    assert_eq!(decision.model_id, MODEL);
    node.expect_fields(
        &mut seen,
        "tenzro_routeIntent",
        json!({ "use_case": "chat" }),
    );
    i.chat_by_intent(
        &IntentParams::new("chat"),
        json!([{ "role": "user", "content": "hi" }]),
    )
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_chatByIntent",
        json!({ "use_case": "chat", "messages": [{ "role": "user", "content": "hi" }] }),
    );
    i.record_route_outcome(MODEL, 3, RouteOutcome::Resolved)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_recordRouteOutcome",
        json!({ "model_id": MODEL, "cluster": 3, "outcome": "resolved" }),
    );
    i.route_difficulty_stats(Some(MODEL)).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_routeDifficultyStats",
        json!({ "model_id": MODEL }),
    );
    i.router_metrics().await.unwrap();
    node.expect(&mut seen, "tenzro_getRouterMetrics", json!({}));
    i.get_provenance("ab").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getContentProvenance",
        json!({ "content_hash": "ab" }),
    );
    let generation = i.get_generation("gen-1").await.unwrap();
    assert_eq!(generation.input_tokens, 2);
    node.expect(&mut seen, "tenzro_getGeneration", json!({ "id": "gen-1" }));
    i.list_inference_usage(Some(MODEL), None).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_listInferenceUsage",
        json!({ "model_id": MODEL }),
    );

    let voter = RpcClient::new(&node.url, std::time::Duration::from_secs(10), None).unwrap();
    i.commit_challenge_vote(&voter, "c1", "h").await.unwrap();
    {
        let mut sent = node.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        let commit = sent.pop().unwrap();
        let sign = sent.pop().unwrap();
        assert_eq!(sign["method"], "tenzro_signChallengeVote");
        assert_eq!(
            sign["params"],
            json!({ "challenge_id": "c1", "commit_hash": "h" })
        );
        assert_eq!(commit["method"], "tenzro_commitChallengeVote");
        assert_eq!(
            commit["params"],
            json!({ "challenge_id": "c1", "voter": "0xvv", "commit_hash": "h", "signature": "sig" })
        );
        seen.insert("tenzro_signChallengeVote".into());
        seen.insert("tenzro_commitChallengeVote".into());
    }
    i.reveal_challenge_vote(&voter, "c1", true, "s")
        .await
        .unwrap();
    {
        let mut sent = node.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        let reveal = sent.pop().unwrap();
        let sign = sent.pop().unwrap();
        assert_eq!(
            sign["params"],
            json!({ "challenge_id": "c1", "verdict": true, "salt": "s" })
        );
        assert_eq!(reveal["method"], "tenzro_revealChallengeVote");
        assert_eq!(
            reveal["params"],
            json!({ "challenge_id": "c1", "voter": "0xvv", "verdict": true, "salt": "s", "signature": "sig" })
        );
        seen.insert("tenzro_revealChallengeVote".into());
    }
    i.file_inference_challenge("h", "0xab", Some("r"))
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_fileInferenceChallenge",
        json!({ "commitment_hash": "h", "challenger": "0xab", "reason": "r" }),
    );
    i.finalize_challenge("c1").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_finalizeChallenge",
        json!({ "challenge_id": "c1" }),
    );
    i.get_inference_challenge("c1").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getInferenceChallenge",
        json!({ "challenge_id": "c1" }),
    );
    i.list_inference_challenges(Some("open"), None)
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_listInferenceChallenges",
        json!({ "status": "open", "provider": null }),
    );
    i.get_inference_commitment("h").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getInferenceCommitment",
        json!({ "commitment_hash": "h" }),
    );
    i.verify_inference_commitment("h", "p", Some(json!({ "steps": 1 })))
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_verifyInferenceCommitment",
        json!({ "commitment_hash": "h", "prompt": "p", "receipt": { "steps": 1 } }),
    );
    i.audit_inference_challenge("c1").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_auditInferenceChallenge",
        json!({ "challenge_id": "c1" }),
    );
    i.verify_inference_receipt("tee", json!({ "model_id": MODEL }))
        .await
        .unwrap();
    node.expect(
        &mut seen,
        "tenzro_verifyInferenceReceipt",
        json!({ "level": "tee", "receipt": { "model_id": MODEL } }),
    );
    i.prefix_probe(&["aa".to_string()]).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_prefixProbe",
        json!({ "digests": ["aa"] }),
    );
    i.moe_route(MODEL, 1, 8, "AAAA", Some(2)).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_moeRoute",
        json!({ "model_id": MODEL, "layer": 1, "d_model": 8, "hidden_states": "AAAA", "top_k": 2 }),
    );
    i.moe_execute(
        json!({ "model_id": MODEL, "layer": 1, "expert": 2, "token_indices": [0], "d_model": 8 }),
    )
    .await
    .unwrap();
    node.expect_fields(&mut seen, "tenzro_moeExecute", json!({ "expert": 2 }));
    i.moe_dispute_receipt("k").await.unwrap();
    node.expect(&mut seen, "tenzro_moeDisputeReceipt", json!({ "key": "k" }));

    assert_eq!(seen.len(), 25, "{seen:?}");
}

#[tokio::test]
async fn multimodal_bindings_send_what_the_node_reads() {
    let node = Node::start(answers()).await;
    let c = node.client().await;
    let m = c.multimodal();
    let mut seen = BTreeSet::new();
    let load = |id: &str| LoadModelParams {
        model_id: id.into(),
        ..Default::default()
    };
    let routing = TaskRouting {
        verification: Some("receipt".into()),
        provider: None,
    };

    macro_rules! catalog {
        ($list:ident, $method:literal) => {
            assert!(m.$list().await.unwrap().models.is_empty());
            node.expect(&mut seen, $method, json!([]));
        };
    }
    macro_rules! load_unload {
        ($load:ident, $load_m:literal, $unload:ident, $unload_m:literal, $id:literal) => {
            assert!(m.$load(&load($id)).await.unwrap().loaded);
            node.expect_fields(&mut seen, $load_m, json!({ "model_id": $id }));
            assert!(m.$unload($id).await.unwrap().removed);
            node.expect(&mut seen, $unload_m, json!([{ "model_id": $id }]));
        };
    }

    catalog!(list_forecast_catalog, "tenzro_listForecastCatalog");
    load_unload!(
        load_forecast_model,
        "tenzro_loadForecastModel",
        unload_forecast_model,
        "tenzro_unloadForecastModel",
        "chronos"
    );
    m.forecast(&ForecastParams {
        model_id: "chronos".into(),
        history: vec![1.0, 2.0],
        horizon: 3,
        routing: routing.clone(),
        ..Default::default()
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_forecast",
        json!({ "model_id": "chronos", "history": [1.0, 2.0], "horizon": 3, "verification": "receipt" }),
    );

    catalog!(list_vision_catalog, "tenzro_listVisionCatalog");
    load_unload!(
        load_vision_model,
        "tenzro_loadVisionModel",
        unload_vision_model,
        "tenzro_unloadVisionModel",
        "clip"
    );
    let emb = m
        .image_embed(&ImageEmbedParams {
            model_id: "clip".into(),
            image_base64: "AA==".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(emb.dim, 2);
    node.expect_fields(
        &mut seen,
        "tenzro_imageEmbed",
        json!({ "model_id": "clip", "image_base64": "AA==" }),
    );
    let sim = m
        .image_text_similarity(&[1.0, 0.0], &[0.0, 1.0])
        .await
        .unwrap();
    assert_eq!(sim.dim, 2);
    node.expect(
        &mut seen,
        "tenzro_imageTextSimilarity",
        json!({ "image_embedding": [1.0, 0.0], "text_embedding": [0.0, 1.0] }),
    );

    catalog!(
        list_text_embedding_catalog,
        "tenzro_listTextEmbeddingCatalog"
    );
    load_unload!(
        load_text_embedding_model,
        "tenzro_loadTextEmbeddingModel",
        unload_text_embedding_model,
        "tenzro_unloadTextEmbeddingModel",
        "e5"
    );
    let te = m
        .text_embed(&TextEmbedParams {
            model_id: "e5".into(),
            inputs: vec![EmbedInput::from("a")],
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(te.embeddings.len(), 1);
    node.expect_fields(
        &mut seen,
        "tenzro_textEmbed",
        json!({ "model_id": "e5", "inputs": ["a"] }),
    );

    catalog!(list_segmentation_catalog, "tenzro_listSegmentationCatalog");
    load_unload!(
        load_segmentation_model,
        "tenzro_loadSegmentationModel",
        unload_segmentation_model,
        "tenzro_unloadSegmentationModel",
        "sam"
    );
    m.segment(&SegmentParams {
        model_id: "sam".into(),
        image_base64: "AA==".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_segment",
        json!({ "model_id": "sam", "prompts": [] }),
    );

    catalog!(
        list_text_segmentation_catalog,
        "tenzro_listTextSegmentationCatalog"
    );
    load_unload!(
        load_text_segmentation_model,
        "tenzro_loadTextSegmentationModel",
        unload_text_segmentation_model,
        "tenzro_unloadTextSegmentationModel",
        "sam3"
    );
    m.text_segment(&TextSegmentParams {
        model_id: "sam3".into(),
        image_base64: "AA==".into(),
        text_prompt: "cat".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_textSegment",
        json!({ "model_id": "sam3", "text_prompt": "cat" }),
    );

    catalog!(list_detection_catalog, "tenzro_listDetectionCatalog");
    load_unload!(
        load_detection_model,
        "tenzro_loadDetectionModel",
        unload_detection_model,
        "tenzro_unloadDetectionModel",
        "rfdetr"
    );
    let found = m
        .detect(&DetectParams {
            model_id: "rfdetr".into(),
            image_base64: "AA==".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(found.detections.len(), 1);
    assert_eq!(found.detections[0].label.as_deref(), Some("car"));
    assert_eq!(found.generation_time_ms, 7);
    node.expect_fields(
        &mut seen,
        "tenzro_detect",
        json!({ "model_id": "rfdetr", "image_base64": "AA==" }),
    );

    m.list_rerank_catalog().await.unwrap();
    node.expect(&mut seen, "tenzro_listRerankCatalog", json!([]));
    load_unload!(
        load_rerank_model,
        "tenzro_loadRerankModel",
        unload_rerank_model,
        "tenzro_unloadRerankModel",
        "bge"
    );
    m.rerank(
        "bge",
        &EmbedInput::from("q"),
        &[EmbedInput::from("a")],
        Some(1),
        &routing,
    )
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_rerank",
        json!({ "model_id": "bge", "query": "q", "documents": ["a"], "top_n": 1, "verification": "receipt" }),
    );

    m.list_decision_catalog().await.unwrap();
    node.expect(&mut seen, "tenzro_listDecisionCatalog", json!([]));
    load_unload!(
        load_decision_model,
        "tenzro_loadDecisionModel",
        unload_decision_model,
        "tenzro_unloadDecisionModel",
        "laya"
    );
    m.decide(
        "laya",
        &json!("Win a free phone now"),
        &[
            DecisionQuestion::yes_no("spam", "Is this spam?"),
            DecisionQuestion::choice(
                "kind",
                "Which kind?",
                &[
                    DecisionOption::new("promo", "an advertisement"),
                    DecisionOption::key("other"),
                ],
            ),
            DecisionQuestion::score("urgency", "How urgent?", &[json!("low"), json!("high")]),
        ],
        &routing,
    )
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_decide",
        json!({
            "model_id": "laya",
            "state": "Win a free phone now",
            "questions": [
                { "id": "spam", "type": "noul", "instructions": "Is this spam?" },
                { "id": "kind", "type": "choice", "instructions": "Which kind?",
                  "criteria": [{ "key": "promo", "description": "an advertisement" }, { "key": "other" }] },
                { "id": "urgency", "type": "score", "instructions": "How urgent?",
                  "criteria": ["low", "high"] },
            ],
            "verification": "receipt",
        }),
    );

    assert!(m.load_training_model(MODEL).await.unwrap().loaded);
    node.expect(
        &mut seen,
        "tenzro_loadTrainingModel",
        json!({ "model_id": MODEL }),
    );
    assert!(m.unload_training_model(MODEL).await.unwrap().removed);
    node.expect(
        &mut seen,
        "tenzro_unloadTrainingModel",
        json!({ "model_id": MODEL }),
    );
    let round = json!({ "model_id": MODEL, "recipe": { "rank": 8 }, "records": [], "sample_seed": 1, "steps": 2 });
    m.train_round(&round).await.unwrap();
    node.expect(&mut seen, "tenzro_trainRound", round);

    load_unload!(
        load_speech_model,
        "tenzro_loadSpeechModel",
        unload_speech_model,
        "tenzro_unloadSpeechModel",
        "kokoro"
    );
    m.speak("kokoro", "hello", None, Some(1), &routing)
        .await
        .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_speak",
        json!({ "model_id": "kokoro", "input": "hello", "seed": 1, "verification": "receipt" }),
    );

    catalog!(list_audio_catalog, "tenzro_listAudioCatalog");
    load_unload!(
        load_audio_model,
        "tenzro_loadAudioModel",
        unload_audio_model,
        "tenzro_unloadAudioModel",
        "whisper"
    );
    m.transcribe(&TranscribeParams {
        model_id: "whisper".into(),
        audio_base64: "AA==".into(),
        ..Default::default()
    })
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_transcribe",
        json!({ "model_id": "whisper", "audio_base64": "AA==" }),
    );

    catalog!(list_video_catalog, "tenzro_listVideoCatalog");
    assert!(
        m.load_video_model(&LoadVideoModelParams {
            model_id: "vjepa".into(),
            vision_model_id: "clip".into(),
            num_frames: Some(8),
            ..Default::default()
        })
        .await
        .unwrap()
        .loaded
    );
    node.expect_fields(
        &mut seen,
        "tenzro_loadVideoModel",
        json!({ "model_id": "vjepa", "vision_model_id": "clip", "num_frames": 8 }),
    );
    assert!(m.unload_video_model("vjepa").await.unwrap().removed);
    node.expect(
        &mut seen,
        "tenzro_unloadVideoModel",
        json!([{ "model_id": "vjepa" }]),
    );
    let ve = m
        .video_embed(&VideoEmbedParams {
            model_id: "vjepa".into(),
            video_base64: "AA==".into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(ve.dim, 1);
    node.expect_fields(
        &mut seen,
        "tenzro_videoEmbed",
        json!({ "model_id": "vjepa", "video_base64": "AA==" }),
    );

    m.list_tts_catalog().await.unwrap();
    node.expect(&mut seen, "tenzro_listTtsCatalog", json!({}));

    assert_eq!(seen.len(), 48, "{seen:?}");
}

#[tokio::test]
async fn media_catalog_registry_and_blob_bindings_send_what_the_node_reads() {
    let node = Node::start(answers()).await;
    let c = node.client().await;
    let mut seen = BTreeSet::new();

    let mg = c.media_gen();
    mg.list_catalog().await.unwrap();
    node.expect(&mut seen, "tenzro_mediaGen_listCatalog", json!({}));
    mg.render(
        "flux",
        "image",
        json!({ "prompt": "p" }),
        &[],
        Some("receipt"),
    )
    .await
    .unwrap();
    node.expect_fields(
        &mut seen,
        "tenzro_mediaGen_render",
        json!({ "model_id": "flux", "kind": "image", "params": { "prompt": "p" }, "verification": "receipt" }),
    );
    mg.load_media_model("flux").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_loadMediaModel",
        json!({ "model_id": "flux" }),
    );
    mg.unload_media_model("flux").await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_unloadMediaModel",
        json!({ "model_id": "flux" }),
    );

    let cat = c.catalog();
    cat.list(Some("praecise")).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_listCatalog",
        json!({ "engine": "praecise" }),
    );
    cat.entry(MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_getCatalogEntry",
        json!({ "model": MODEL }),
    );
    cat.engine_releases().await.unwrap();
    node.expect(&mut seen, "tenzro_getEngineReleases", json!({}));

    let reg = c.registry();
    let page = reg.list("price-card", Some("a"), Some(10)).await.unwrap();
    assert!(page.entries.is_empty());
    node.expect(
        &mut seen,
        "tenzro_listRegistry",
        json!({ "kind": "price-card", "after": "a", "limit": 10 }),
    );
    assert_eq!(reg.get("id-1", Some(2)).await.unwrap().unwrap().version, 2);
    node.expect(
        &mut seen,
        "tenzro_getRegistryEntry",
        json!({ "id": "id-1", "version": 2 }),
    );
    let (entry, card) = reg.price_card("0xab", MODEL).await.unwrap().unwrap();
    assert_eq!((entry.id.as_str(), card.model_id.as_str()), ("id-1", MODEL));
    node.expect(
        &mut seen,
        "tenzro_getPriceCard",
        json!({ "provider": "0xab", "model_id": MODEL }),
    );
    reg.price_card_to_publish("0xab", MODEL).await.unwrap();
    node.expect(
        &mut seen,
        "tenzro_priceCardToPublish",
        json!({ "provider": "0xab", "model_id": MODEL }),
    );
    assert_eq!(reg.tnzo_usd_nano().await.unwrap(), 1_500_000_000);
    node.expect(&mut seen, "tenzro_getFeeRate", json!({}));

    assert_eq!(
        c.iroh().fetch_blob("tenzro://blob/aa").await.unwrap(),
        vec![1, 2, 3]
    );
    node.expect(
        &mut seen,
        "tenzro_iroh_fetchBlob",
        json!({ "tenzro_uri": "tenzro://blob/aa" }),
    );

    assert_eq!(seen.len(), 13, "{seen:?}");
}
