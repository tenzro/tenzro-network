//! End-to-end tests for the operator connector: a node serving models from
//! an existing OpenAI-compatible endpoint.
//!
//! A mock endpoint stands in for the operator's serving stack (vLLM, NIM,
//! TGI, SGLang, llama.cpp server). The connector is a real node configured
//! with a `[connector]` section and the endpoint's API key sealed to it; the
//! gateway is a second real node that routes to the connector over
//! `tenzro/infer`, the way the network routes to any provider.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tenzro_crypto::batch::RecordSigner as _;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use iroh::address_lookup::MemoryLookup;
use serde_json::{Value, json};
use tenzro_node::connector::{ConnectorConfig, UpstreamModelConfig, WorkClass};
use tenzro_node::forward_billing::{BillingBasis, ForwardLeg, StreamedOutput, UsageBound};
use tenzro_node::inference_admission::NodeInferenceAdmission;
use tenzro_node::inference_receipt::{InferenceReceipt, UPSTREAM_ENGINE, upstream_identity};
use tenzro_node::node::NetworkModelEntry;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::model::BillableUnits;
use tokio::sync::broadcast;

mod dpop_bearer;
mod passkey_holder;

/// The endpoint's API key the operator sealed to the connector.
const UPSTREAM_KEY: &str = "sk-operator-upstream-7f3a";
/// The usage the mock endpoint reports for every chat.
const PROMPT_TOKENS: u32 = 11;
const COMPLETION_TOKENS: u32 = 7;
const ANSWER: &str = "hello from upstream";
/// What the operator charges per image.
const IMAGE_PRICE_WEI: u128 = 3_000_000_000_000_000;

/// A caller the access policies admit by name.
fn member() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

/// An access policy admitting `member()` by name and anyone else openly.
fn write_policy(dir: &std::path::Path) {
    use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, Rule, SurfaceRule};
    let mut policy = NodeAccessPolicy::default();
    policy.rules.push(SurfaceRule {
        surface: None,
        class: MethodClass::Inference,
        rule: Rule::Any {
            rules: vec![
                Rule::Allow {
                    dids: vec![member().did()],
                    orgs: vec![],
                },
                Rule::Open,
            ],
        },
    });
    dpop_bearer::write_policy(dir, &policy);
}

/// A P-256 key standing in for the TPM, one per label, so the nodes in this
/// process have a hardware identity to sign announcements and receipts with.
/// Test-only: a release build opens these keys in a TPM or Secure Enclave.
struct TestHardwareKey {
    label: String,
    key: p256::ecdsa::SigningKey,
}

impl tenzro_device_key::HardwareSigner for TestHardwareKey {
    fn backend(&self) -> tenzro_device_key::HardwareBackend {
        tenzro_device_key::HardwareBackend::Tpm
    }
    fn label(&self) -> &str {
        &self.label
    }
    fn public_key_sec1(&self) -> tenzro_device_key::Result<[u8; 65]> {
        let point = self.key.verifying_key().to_sec1_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        Ok(out)
    }
    fn sign_prehash(&self, digest: &[u8; 32]) -> tenzro_device_key::Result<[u8; 64]> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature = self.key.sign_prehash(digest).expect("sign");
        Ok(sig.to_bytes().into())
    }
}

fn install_test_hardware() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        tenzro_device_key::signer::use_remote_signers(Box::new(|label: &str| {
            use sha2::Digest as _;
            let seed: [u8; 32] = sha2::Sha256::digest(label.as_bytes()).into();
            Ok(Box::new(TestHardwareKey {
                label: label.to_string(),
                key: p256::ecdsa::SigningKey::from_slice(&seed).expect("a scalar"),
            }) as Box<dyn tenzro_device_key::HardwareSigner>)
        }))
        .expect("install the test keys");
    });
}

/// An endpoint key of the node's own, from its data directory: the nodes of
/// this process share the machine's hardware root, from which each would
/// otherwise derive the same endpoint id.
fn endpoint_secret(dir: &std::path::Path) -> tenzro_iroh::EndpointSecret {
    use sha2::Digest as _;
    let seed: [u8; 32] = sha2::Sha256::digest(dir.to_string_lossy().as_bytes()).into();
    tenzro_iroh::EndpointSecret(Some(seed))
}

/// The onboarding table with a handshake window short enough that a peer
/// with no identity record is admitted without a minute's wait.
fn quick_admission() -> tenzro_node::identity_gate::OnboardingConfig {
    let mut cfg = tenzro_node::identity_gate::OnboardingConfig::default();
    cfg.policy.handshake_timeout = std::time::Duration::from_millis(500);
    cfg
}

fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
}

// ---------------------------------------------------------------------------
// The mock endpoint
// ---------------------------------------------------------------------------

/// What the mock endpoint received: the path, the Authorization header and
/// the body.
#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<(String, Option<String>, Value)>>>);

impl Seen {
    fn record(&self, path: &str, headers: &HeaderMap, body: &Value) {
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        self.0
            .lock()
            .unwrap()
            .push((path.to_string(), auth, body.clone()));
    }

    fn last(&self) -> (String, Option<String>, Value) {
        self.0.lock().unwrap().last().cloned().expect("a request")
    }

    fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }
}

fn completion(model: &str) -> Value {
    json!({
        "id": "chatcmpl-upstream-1",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": ANSWER},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": PROMPT_TOKENS, "completion_tokens": COMPLETION_TOKENS,
                  "total_tokens": PROMPT_TOKENS + COMPLETION_TOKENS}
    })
}

fn sse(frames: &[Value]) -> String {
    let mut out = String::new();
    for f in frames {
        out.push_str(&format!("data: {f}\n\n"));
    }
    out.push_str("data: [DONE]\n\n");
    out
}

fn chunk(model: &str, delta: Value, finish: Value) -> Value {
    json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": model,
           "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]})
}

async fn chat(State(seen): State<Seen>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    seen.record("/v1/chat/completions", &headers, &body);
    let model = body["model"].as_str().unwrap_or_default().to_string();
    let stream = body["stream"].as_bool().unwrap_or(false);
    match model.as_str() {
        "broken" => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": {"message": "engine overloaded"}})),
        )
            .into_response(),
        "refusing" => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": {"message": "context length exceeded"}})),
        )
            .into_response(),
        "slow" => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Json(completion(&model)).into_response()
        }
        "stalling" => {
            // One chunk, then nothing.
            let first = format!(
                "data: {}\n\n",
                chunk(
                    &model,
                    json!({"role": "assistant", "content": "partial"}),
                    Value::Null
                )
            );
            let body = futures::stream::once(async move { Ok::<_, std::io::Error>(first) })
                .chain(futures::stream::pending());
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from_stream(body))
                .unwrap()
        }
        _ if stream => {
            let frames = vec![
                chunk(
                    &model,
                    json!({"role": "assistant", "content": ""}),
                    Value::Null,
                ),
                chunk(&model, json!({"content": "hello "}), Value::Null),
                chunk(&model, json!({"content": "from "}), Value::Null),
                chunk(&model, json!({"content": "upstream"}), Value::Null),
                chunk(&model, json!({}), json!("stop")),
                json!({"id": "c", "object": "chat.completion.chunk", "created": 1, "model": model,
                       "choices": [],
                       "usage": {"prompt_tokens": PROMPT_TOKENS, "completion_tokens": COMPLETION_TOKENS,
                                 "total_tokens": PROMPT_TOKENS + COMPLETION_TOKENS}}),
            ];
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(axum::body::Body::from(sse(&frames)))
                .unwrap()
        }
        _ => Json(completion(&model)).into_response(),
    }
}

async fn embeddings(
    State(seen): State<Seen>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    seen.record("/v1/embeddings", &headers, &body);
    let n = body["input"].as_array().map(Vec::len).unwrap_or(0);
    // Out of order, as some servers answer: the index places each row.
    let data: Vec<Value> = (0..n)
        .rev()
        .map(|i| json!({"object": "embedding", "index": i, "embedding": [3.0, 4.0, i as f64]}))
        .collect();
    Json(
        json!({"object": "list", "data": data, "model": body["model"],
                "usage": {"prompt_tokens": 9, "total_tokens": 9}}),
    )
    .into_response()
}

async fn images(State(seen): State<Seen>, headers: HeaderMap, Json(body): Json<Value>) -> Response {
    seen.record("/v1/images/generations", &headers, &body);
    // A JPEG, which the connector re-encodes to the PNG a render commits to.
    let img = image::RgbImage::from_fn(64, 64, |x, y| {
        image::Rgb([(x * 4) as u8, (y * 4) as u8, 90])
    });
    let mut jpeg = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgb8(img)
        .write_to(&mut jpeg, image::ImageFormat::Jpeg)
        .unwrap();
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(jpeg.into_inner());
    Json(json!({"created": 1, "data": [{"b64_json": b64}]})).into_response()
}

use futures::StreamExt as _;

/// The mock endpoint on loopback; its base URL and what it saw.
async fn mock_upstream() -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new()
        .route("/v1/chat/completions", post(chat))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/images/generations", post(images))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/v1"), seen)
}

// ---------------------------------------------------------------------------
// Nodes
// ---------------------------------------------------------------------------

struct Node {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
}

impl Node {
    async fn boot(config: NodeConfig, tmp: tempfile::TempDir) -> Self {
        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        // As `main` does once the node is shared: the `tenzro/infer` ALPN
        // answers through the node's own handlers.
        if let Some(deferred) = node.iroh_infer_dispatcher.as_ref() {
            deferred.set(Arc::new(tenzro_node::infer::IrohInferDispatcher::new(
                node.clone(),
            )));
        }
        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string())
            .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)));
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
            node,
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }

    /// A `/v1/chat/completions` request from the member, signed in fresh.
    async fn chat(&self) -> reqwest::RequestBuilder {
        let client = reqwest::Client::new();
        let caller = member().sign_in(&client, &self.base_url).await;
        let route = format!("{}/v1/chat/completions", self.base_url);
        caller.authorize_route(client.post(&route), &route)
    }

    /// A JSON-RPC call from the member.
    async fn rpc(&self, method: &str, params: Value) -> Value {
        let client = reqwest::Client::new();
        let caller = member().sign_in(&client, &self.base_url).await;
        caller
            .authorize(client.post(&self.base_url), &self.base_url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap()
    }
}

fn model(id: &str, upstream: &str, work: WorkClass) -> UpstreamModelConfig {
    UpstreamModelConfig {
        id: id.to_string(),
        upstream_model: upstream.to_string(),
        work,
        visibility: None,
    }
}

/// The connector's models, each named for the mock behaviour it gets.
fn models() -> Vec<UpstreamModelConfig> {
    vec![
        model("acme/chat", "served-chat", WorkClass::Chat),
        model("acme/broken", "broken", WorkClass::Chat),
        model("acme/refusing", "refusing", WorkClass::Chat),
        model("acme/slow", "slow", WorkClass::Chat),
        model("acme/stalling", "stalling", WorkClass::Chat),
        model("acme/embed", "served-embed", WorkClass::Embeddings),
        model("acme/image", "served-image", WorkClass::Images),
    ]
}

/// A connector node in front of `upstream_url`, with the endpoint's key
/// sealed to it as `tenzro-node credentials set upstream` seals it.
async fn connector(upstream_url: &str) -> Node {
    install_test_hardware();
    let tmp = tempfile::tempdir().unwrap();
    write_policy(tmp.path());
    let keys = tenzro_keygen::NodeKeys::open(tmp.path()).expect("node keys");
    tenzro_node::credentials::seal(
        tmp.path(),
        &keys,
        tenzro_node::credentials::Secret::Upstream,
        UPSTREAM_KEY,
    )
    .expect("seal the upstream key");
    let mut config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig {
            bind_addr: free_udp_port(),
            endpoint_secret: endpoint_secret(tmp.path()),
            ..Default::default()
        },
        // These nodes publish no identity record, so the identity gate waits
        // its handshake window for a name before it admits a dial; the
        // window is shortened so a dial is admitted at once.
        onboarding: quick_admission(),
        connector: Some(ConnectorConfig {
            upstream_url: upstream_url.to_string(),
            request_timeout_secs: 2,
            idle_timeout_secs: 1,
            max_concurrent: 8,
            api_key: None,
            models: models(),
        }),
        ..Default::default()
    };
    // Routed calls arrive with no payment of their own: the gateway pays the
    // leg on the ledger.
    config.payments.default_amount = 0;
    // The default card prices no `images`; the operator prices its image
    // model with a card of its own.
    let mut image_card = tenzro_node::node::default_rate_card();
    image_card.lines.insert(
        tenzro_types::meter::unit::IMAGES.to_string(),
        tenzro_types::price_card::Rate::per(IMAGE_PRICE_WEI, 0),
    );
    config
        .provider_rates
        .inference
        .models
        .insert("acme/image".to_string(), image_card);
    Node::boot(config, tmp).await
}

async fn gateway() -> Node {
    install_test_hardware();
    let tmp = tempfile::tempdir().unwrap();
    write_policy(tmp.path());
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        iroh: tenzro_iroh::TenzroIrohConfig {
            bind_addr: free_udp_port(),
            endpoint_secret: endpoint_secret(tmp.path()),
            ..Default::default()
        },
        // These nodes publish no identity record, so the identity gate waits
        // its handshake window for a name before it admits a dial; the
        // window is shortened so a dial is admitted at once.
        onboarding: quick_admission(),
        ..Default::default()
    };
    Node::boot(config, tmp).await
}

/// Make `connector`'s offer of `model` known to `gateway`, as its signed
/// announcement would: its endpoint, its payee and the card it announced.
fn learn_offer(gateway: &Node, connector: &Node, model: &str) {
    let endpoint = gateway
        .node
        .iroh_resolver
        .as_ref()
        .expect("gateway endpoint")
        .endpoint();
    let provider_endpoint = connector
        .node
        .iroh_resolver
        .as_ref()
        .expect("connector endpoint")
        .endpoint();
    let lookup = MemoryLookup::new();
    lookup.add_endpoint_info(provider_endpoint.addr());
    endpoint
        .address_lookup()
        .expect("open endpoint")
        .add(lookup);
    let registration = tenzro_network::ModelRegistrationMessage {
        model_id: model.to_string(),
        name: model.to_string(),
        provider: hex::encode(payee(connector).as_bytes()),
        pricing: card(connector, model),
        iroh_endpoint_id: provider_endpoint.id().to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
        ttl_secs: 600,
        ..Default::default()
    };
    gateway.node.network_models.insert(
        model.to_string(),
        NetworkModelEntry {
            registration,
            last_seen: Instant::now(),
        },
    );
}

fn payee(n: &Node) -> tenzro_types::primitives::Address {
    n.node.operator_payee().expect("the connector's payee")
}

fn card(n: &Node, model: &str) -> tenzro_types::price_card::RateCard {
    n.node.provider_pricing.read().card_for(model).clone()
}

fn tokens() -> BillableUnits {
    BillableUnits::tokens(PROMPT_TOKENS, COMPLETION_TOKENS)
}

/// Check `receipt` the way a gateway checks a provider's: signed by the
/// connector's hardware identity, naming the upstream identity of `model`,
/// binding the output hash and the units, and billable as signed.
fn assert_billable_receipt(connector: &Node, model: &str, receipt: &Value, output_hash: &str) {
    let parsed: InferenceReceipt =
        serde_json::from_value(receipt.clone()).unwrap_or_else(|e| panic!("{e}: {receipt}"));
    assert_eq!(parsed.model_id, model);
    assert_eq!(parsed.engine, UPSTREAM_ENGINE);
    assert_eq!(parsed.model_hash, upstream_identity(model).model_hash);
    assert_eq!(parsed.decode.hardware_class, UPSTREAM_ENGINE);
    assert_eq!(
        parsed.units,
        tokens(),
        "the receipt binds the endpoint's usage"
    );
    assert_eq!(
        parsed.nonce.len(),
        32,
        "the gateway's nonce for this request"
    );
    let key = connector
        .node
        .records()
        .expect("the connector signs with its hardware identity")
        .identity()
        .clone();
    let leg = ForwardLeg {
        model_id: model,
        nonce: &parsed.nonce,
        pinned_key: Some(&key),
        bound: UsageBound {
            max_output_tokens: Some(512),
            request_bytes: 10_000,
            response_bytes: 10_000,
            pixel_steps: 0,
        },
    };
    assert_eq!(
        leg.billable(Some(tokens()), Some(receipt), output_hash),
        (tokens(), BillingBasis::SignedReceipt),
        "a gateway bills the leg from this receipt"
    );
}

/// What the endpoint was sent for a chat: its own model name, the key, the
/// decode stated in full, and nothing only the network reads.
fn assert_upstream_chat(seen: &Seen, upstream_model: &str, stream: bool) {
    let (path, auth, body) = seen.last();
    assert_eq!(path, "/v1/chat/completions");
    assert_eq!(
        auth.as_deref(),
        Some(format!("Bearer {UPSTREAM_KEY}").as_str())
    );
    assert_eq!(body["model"], upstream_model);
    assert_eq!(body["messages"][0]["content"], "hello");
    assert_eq!(body["stream"], stream);
    assert_eq!(body["temperature"], 0.7);
    assert_eq!(body["max_tokens"], 512);
    assert!(body["seed"].is_u64());
    for local in [
        "receipt_nonce",
        "verification",
        "cache_salt",
        "provider",
        "jurisdiction",
    ] {
        assert!(
            body.get(local).is_none(),
            "{local} was sent upstream: {body}"
        );
    }
    if stream {
        assert_eq!(body["stream_options"]["include_usage"], true);
    }
}

fn hello(model: &str, stream: bool) -> Value {
    json!({"model": model, "stream": stream, "messages": [{"role": "user", "content": "hello"}]})
}

/// SSE payloads of a response body, `[DONE]` included.
fn payloads(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(|p| p.trim().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A request the gateway routes to the connector reaches the operator's
/// endpoint under its own model name and key, comes back metered from the
/// endpoint's usage with a receipt the gateway bills from, and is priced at
/// the card the connector announced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_routed_request_is_forwarded_metered_receipted_and_priced() {
    let (upstream, seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    let gw = gateway().await;
    learn_offer(&gw, &conn, "acme/chat");

    let resp = gw
        .chat()
        .await
        .json(&hello("acme/chat", false))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let body: Value = resp.json().await.unwrap();
    assert_upstream_chat(&seen, "served-chat", false);

    assert_eq!(body["model"], "acme/chat");
    assert_eq!(body["choices"][0]["message"]["content"], ANSWER);
    assert_eq!(body["usage"]["prompt_tokens"], PROMPT_TOKENS);
    assert_eq!(body["usage"]["completion_tokens"], COMPLETION_TOKENS);
    // The gateway priced the leg on the card the connector announced, for
    // the units the endpoint reported.
    let expected =
        tenzro_node::inference_pricing::charge_wei(&gw.node, &card(&conn, "acme/chat"), &tokens())
            .expect("the card prices tokens");
    assert!(expected > 0);
    assert_eq!(body["cost_wei"], expected.to_string(), "{body}");
    assert_billable_receipt(
        &conn,
        "acme/chat",
        &body["tenzro_receipt"],
        &tenzro_node::forward_billing::completion_output_hash(&body),
    );
    gw.shutdown().await;
    conn.shutdown().await;
}

/// A streamed request is relayed chunk by chunk and finishes with the usage,
/// the cost and a receipt over exactly what was streamed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_routed_stream_is_relayed_and_receipted_over_what_was_streamed() {
    let (upstream, seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    let gw = gateway().await;
    learn_offer(&gw, &conn, "acme/chat");

    let resp = gw
        .chat()
        .await
        .json(&hello("acme/chat", true))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let text = resp.text().await.unwrap();
    assert_upstream_chat(&seen, "served-chat", true);

    let frames = payloads(&text);
    assert_eq!(frames.last().map(String::as_str), Some("[DONE]"), "{text}");
    let mut streamed = StreamedOutput::default();
    let mut content = String::new();
    let mut finish: Option<Value> = None;
    for f in &frames {
        streamed.absorb(f);
        let Ok(v) = serde_json::from_str::<Value>(f) else {
            continue;
        };
        assert!(v.get("error").is_none(), "{v}");
        if let Some(s) = v
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            content.push_str(s);
        }
        if v.get("tenzro_receipt").is_some_and(|r| !r.is_null()) {
            finish = Some(v);
        }
    }
    assert_eq!(content, ANSWER);
    let finish = finish.expect("a finish chunk carrying the receipt");
    assert_eq!(finish["choices"][0]["finish_reason"], "stop");
    assert_eq!(finish["usage"]["completion_tokens"], COMPLETION_TOKENS);
    let expected = tenzro_node::inference_pricing::charge_wei(
        &conn.node,
        &card(&conn, "acme/chat"),
        &tokens(),
    )
    .unwrap();
    assert_eq!(finish["cost_wei"], expected.to_string());
    assert_billable_receipt(
        &conn,
        "acme/chat",
        &finish["tenzro_receipt"],
        &streamed.output_hash(),
    );
    gw.shutdown().await;
    conn.shutdown().await;
}

/// A `tenzro_chat` frame routed to the connector is answered in the frame
/// shape, metered from the endpoint's usage and receipted over its output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_routed_chat_frame_is_answered_in_the_frame_shape() {
    let (upstream, seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    let gw = gateway().await;
    learn_offer(&gw, &conn, "acme/chat");
    let reply = gw
        .rpc(
            "tenzro_chat",
            json!({"model_id": "acme/chat", "message": "hello"}),
        )
        .await;
    let result = &reply["result"];
    assert_eq!(result["output"], ANSWER, "{reply}");
    assert_upstream_chat(&seen, "served-chat", false);
    assert_eq!(result["input_tokens"], PROMPT_TOKENS);
    assert_eq!(result["output_tokens"], COMPLETION_TOKENS);
    assert_billable_receipt(
        &conn,
        "acme/chat",
        &result["tenzro_receipt"],
        &tenzro_node::inference_receipt::output_hash(ANSWER, "", ""),
    );
    gw.shutdown().await;
    conn.shutdown().await;
}

/// The endpoint's errors reach the caller with their status class and
/// message, and never the endpoint's address or key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_endpoints_errors_reach_the_caller_bounded() {
    let (upstream, _seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    for (model, status, code, says) in [
        ("acme/broken", 502, "upstream_error", "engine overloaded"),
        (
            "acme/refusing",
            400,
            "upstream_error",
            "context length exceeded",
        ),
    ] {
        let resp = conn
            .chat()
            .await
            .json(&hello(model, false))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), status, "{model}");
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["code"], code, "{body}");
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(says), "{message}");
        assert!(!message.contains(&upstream) && !message.contains(UPSTREAM_KEY));
    }
    conn.shutdown().await;
}

/// An endpoint that does not answer, or stops mid-stream, costs the caller
/// at most the configured time: never a hung request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_endpoint_is_cut_off_at_the_configured_time() {
    let (upstream, _seen) = mock_upstream().await;
    let conn = connector(&upstream).await;

    let started = Instant::now();
    let resp = conn
        .chat()
        .await
        .json(&hello("acme/slow", false))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 504);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "upstream_timeout");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );

    let started = Instant::now();
    let resp = conn
        .chat()
        .await
        .json(&hello("acme/stalling", true))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let text = tokio::time::timeout(Duration::from_secs(10), resp.text())
        .await
        .expect("the stream ends")
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    let frames = payloads(&text);
    assert!(frames.iter().any(|f| f.contains("partial")), "{text}");
    let error: Value = frames
        .iter()
        .find_map(|f| {
            serde_json::from_str::<Value>(f)
                .ok()
                .filter(|v| v.get("error").is_some())
        })
        .unwrap_or_else(|| panic!("no error frame in {text}"));
    assert_eq!(error["error"]["code"], "upstream_timeout");
    assert_eq!(frames.last().map(String::as_str), Some("[DONE]"));
    conn.shutdown().await;
}

/// An endpoint that is down is an error naming that, not the address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreachable_endpoint_is_an_error_without_its_address() {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1", closed.local_addr().unwrap());
    drop(closed);
    let conn = connector(&url).await;
    let resp = conn
        .chat()
        .await
        .json(&hello("acme/chat", false))
        .send()
        .await
        .unwrap();
    // Windows takes about two seconds to refuse a connection to a closed
    // loopback port (it retries the SYN), so the connect deadline can answer
    // first: the endpoint is still reported as down, as a timeout.
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    if cfg!(windows) && status == 504 {
        assert_eq!(body["error"]["code"], "upstream_timeout", "{body}");
    } else {
        assert_eq!(status, 502);
        assert_eq!(body["error"]["code"], "upstream_unreachable", "{body}");
    }
    assert!(!body.to_string().contains(&url));
    conn.shutdown().await;
}

/// The connector's models are on offer as this node's own, at the prices
/// its card sets, and nothing above the receipt level is offered for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_connectors_models_and_prices_are_registered() {
    let (upstream, _seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    for m in models() {
        assert!(conn.node.served_models.contains_key(&m.id), "{}", m.id);
        assert!(conn.node.upstream_model(&m.id).is_some());
    }
    let providers = conn.rpc("tenzro_listProviders", json!({})).await;
    let own = providers["result"]["providers"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["source"] == "local"))
        .unwrap_or_else(|| panic!("no own entry: {providers}"));
    let served: Vec<&str> = own["served_models"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for m in models() {
        assert!(
            served.contains(&m.id.as_str()),
            "{} not announced: {own}",
            m.id
        );
    }

    let quote = conn
        .rpc(
            "tenzro_quoteInference",
            json!({"model": "acme/chat", "units": {"input_tokens": 1000, "output_tokens": 100}}),
        )
        .await;
    let offer = quote["result"]["offers"]
        .as_array()
        .and_then(|o| o.iter().find(|o| o["source"] == "local"))
        .unwrap_or_else(|| panic!("no local offer: {quote}"));
    let expected = tenzro_node::inference_pricing::charge_wei(
        &conn.node,
        &card(&conn, "acme/chat"),
        &BillableUnits::tokens(1000, 100),
    )
    .unwrap();
    assert_eq!(offer["price_wei"], expected.to_string(), "{offer}");

    let levels = tenzro_node::verifiable_inference::offered_levels(&conn.node);
    assert!(levels.iter().all(|l| matches!(
        l,
        tenzro_types::inference_verification::VerificationLevel::None
            | tenzro_types::inference_verification::VerificationLevel::Receipt
    )));
    let optimistic = conn
        .chat()
        .await
        .json(&json!({"model": "acme/chat", "verification": "optimistic",
                      "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert!(!optimistic.status().is_success());
    conn.shutdown().await;
}

/// Embeddings from the endpoint, routed through the gateway: the inputs reach
/// the endpoint, the vectors come back in order, and the call is metered
/// from the endpoint's usage under a receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn embeddings_are_served_from_the_endpoint() {
    let (upstream, seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    let gw = gateway().await;
    learn_offer(&gw, &conn, "acme/embed");
    let reply = gw
        .rpc(
            "tenzro_textEmbed",
            json!({"model_id": "acme/embed", "inputs": ["a", "b"], "normalize": true}),
        )
        .await;
    let result = &reply["result"];
    assert!(result.is_object(), "{reply}");
    let (path, auth, body) = seen.last();
    assert_eq!(path, "/v1/embeddings");
    assert_eq!(
        auth.as_deref(),
        Some(format!("Bearer {UPSTREAM_KEY}").as_str())
    );
    assert_eq!(body["model"], "served-embed");
    assert_eq!(body["input"], json!(["a", "b"]));
    let vectors = result["embeddings"].as_array().unwrap();
    assert_eq!(vectors.len(), 2);
    // Row 0 is [3, 4, 0] normalized.
    assert!(
        (vectors[0][0].as_f64().unwrap() - 0.6).abs() < 1e-6,
        "{result}"
    );
    assert!((vectors[1][2].as_f64().unwrap() - 1.0 / 26f64.sqrt()).abs() < 1e-6);
    assert_eq!(result["prompt_tokens"], 9);
    assert_eq!(result["units"]["input_tokens"], 9, "{result}");
    let receipt: InferenceReceipt = serde_json::from_value(result["tenzro_receipt"].clone())
        .unwrap_or_else(|e| panic!("{e}: {result}"));
    assert_eq!(receipt.engine, UPSTREAM_ENGINE);
    assert_eq!(receipt.units, BillableUnits::tokens(9, 0));
    gw.shutdown().await;
    conn.shutdown().await;
}

/// An image from the endpoint is served as a render: re-encoded to PNG,
/// committed to, stored for delivery and metered as one image.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_image_is_served_from_the_endpoint_as_a_render() {
    let (upstream, seen) = mock_upstream().await;
    let conn = connector(&upstream).await;
    let reply = conn
        .rpc(
            "tenzro_mediaGen_render",
            json!({"model_id": "acme/image", "kind": "text2image", "verification": "receipt",
                   "params": {"prompt": "a lighthouse", "negative_prompt": null, "width": 64,
                              "height": 64, "num_frames": null, "fps": null, "steps": 4,
                              "guidance_scale": 3.5, "seed": 7}}),
        )
        .await;
    let result = &reply["result"];
    assert!(result.is_object(), "{reply}");
    let (path, _, body) = seen.last();
    assert_eq!(path, "/v1/images/generations");
    assert_eq!(body["size"], "64x64");
    assert_eq!(body["seed"], 7);
    assert_eq!(result["mime"], "image/png");
    assert!(result["output_blake3"].is_string());
    assert_eq!(result["units"]["images"], 1, "{result}");
    assert_eq!(
        result["cost_wei"],
        IMAGE_PRICE_WEI.to_string(),
        "priced on the image card"
    );
    let receipt: InferenceReceipt =
        serde_json::from_value(result["tenzro_receipt"].clone()).unwrap();
    assert_eq!(receipt.engine, UPSTREAM_ENGINE);
    assert_eq!(seen.count(), 1);
    conn.shutdown().await;
}
