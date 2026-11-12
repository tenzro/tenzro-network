//! End-to-end tests for inference this node forwards to another provider,
//! and for the OpenAI surface's refusals, through the real HTTP routes.
//!
//! A mock provider stands in for the serving peer: it serves the
//! `tenzro/infer` ALPN on its own endpoint, records each request it was sent
//! and answers in the OpenAI shape. The gateway is a real node with the
//! inference admission layer mounted exactly as `main` mounts it.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::presets;
use iroh::protocol::Router;
use iroh::{Endpoint, EndpointId};
use serde_json::{Value, json};
use tenzro_iroh::{ALPN_INFER, MAX_INFER_BYTES, Reply, RequestHandler, RequestProtocol};
use tenzro_node::inference_admission::NodeInferenceAdmission;
use tenzro_node::node::NetworkModelEntry;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_payments::middleware::InferenceAccess;
use tokio::sync::broadcast;

mod common;
mod dpop_bearer;
mod passkey_holder;

struct Gateway {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
}

/// A caller the access policy admits to inference by name.
fn member() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

/// An administrator of every test gateway.
fn admin() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

impl Gateway {
    async fn boot() -> Self {
        Self::boot_with(false).await
    }

    /// A gateway that is also the chain's only validator, so the ledger
    /// account its hardware keys derive can pay provider legs on chain.
    async fn boot_validator() -> Self {
        Self::boot_with(true).await
    }

    async fn boot_with(validator: bool) -> Self {
        let tmp = tempfile::tempdir().expect("temp dir");
        {
            use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, Rule, SurfaceRule};
            let mut policy = NodeAccessPolicy::default();
            policy.admins.push(admin().did());
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
            policy.rules.push(SurfaceRule {
                surface: None,
                class: MethodClass::Media,
                rule: Rule::Allow {
                    dids: vec![member().did()],
                    orgs: vec![],
                },
            });
            dpop_bearer::write_policy(tmp.path(), &policy);
        }
        let mut owner = common::MachineOwner::generate(0x61);
        // A loopback endpoint that publishes nowhere: providers are made
        // known to it directly by `announce`.
        let iroh = tenzro_iroh::TenzroIrohConfig {
            bind_addr: free_udp_port(),
            ..Default::default()
        };
        let mut config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            operator_did: Some(owner.machine_did()),
            iroh,
            ..Default::default()
        };
        if validator {
            config.roles.insert(tenzro_types::NetworkRole::Validator);
            config.consensus = Some(tenzro_consensus::ConsensusConfig::default());
            config.genesis = Some(tenzro_node::config::GenesisConfig {
                protocol: None,
                consensus: Default::default(),
                validator_registry: Default::default(),
                version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
                chain_id: 1337,
                timestamp: 0,
                validators: vec![
                    tenzro_node::config::GenesisValidator::from_local_hardware(
                        tmp.path(),
                        1_000_000,
                    )
                    .expect("a hardware consensus key"),
                ],
                accounts: Vec::new(),
                weak_subjectivity: None,
                time: tenzro_consensus::TimeRules::default(),
                network_params: Default::default(),
                economy: Default::default(),
                role_stakes: Vec::new(),
            });
        }
        let mut node = TenzroNode::new(config).await.expect("node creation");
        // A fixed quiet reading, so the machine running the tests does not
        // decide whether the node takes model work.
        node.set_load_reading(std::sync::Arc::new(|s| {
            *s = tenzro_node::load_monitor::LoadSample {
                cores: 8,
                load_per_core: Some(0.0),
                runnable_per_core: Some(0.0),
                cpu_psi: Some(0.0),
                mem_psi_some: Some(0.0),
                mem_psi_full: Some(0.0),
                io_psi: Some(0.0),
                mem_total: 64 << 30,
                mem_available: 60 << 30,
                loop_lag_ms: Some(0.0),
                ..Default::default()
            };
        }));
        node.start().await.expect("node start");
        let node = Arc::new(node);
        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string())
            .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)));
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");

        // Loopback is granted, so an HTTP request to a stub on loopback would
        // pass the egress guard: a forward that tried HTTP would reach it.
        let client = reqwest::Client::new();
        let base_url = format!("http://{addr}");
        owner.enroll(&client, &base_url, &node).await;
        owner.register_machine(&node).await;
        let granted = owner
            .signed(
                &client,
                &base_url,
                "tenzro_addMachineAccess",
                common::network_terms(&owner.machine_did(), "127.0.0.1/32", None),
            )
            .await;
        assert!(
            granted["result"]["grant_id"].is_string(),
            "grant refused: {granted}"
        );

        Self {
            base_url,
            shutdown,
            handle,
            _tmp: tmp,
            node,
        }
    }

    /// A chat-completions request from the caller the policy admits by name,
    /// signed in fresh.
    async fn authorized_chat(&self) -> reqwest::RequestBuilder {
        let client = reqwest::Client::new();
        let caller = member().sign_in(&client, &self.base_url).await;
        let route = format!("{}/v1/chat/completions", self.base_url);
        caller.authorize_route(client.post(&route), &route)
    }

    /// Announce `model` as served by `provider`, and make the provider's
    /// addresses known to this node's endpoint.
    fn announce(&self, model: &str, provider: &MockProvider) {
        self.announce_priced(model, provider, Default::default());
    }

    /// Announce `model` as served by `provider` at `pricing`.
    fn announce_priced(
        &self,
        model: &str,
        provider: &MockProvider,
        pricing: tenzro_types::price_card::RateCard,
    ) {
        let endpoint = self
            .node
            .iroh_resolver
            .as_ref()
            .expect("bound endpoint")
            .endpoint();
        let lookup = MemoryLookup::new();
        lookup.add_endpoint_info(provider.router.endpoint().addr());
        endpoint
            .address_lookup()
            .expect("open endpoint")
            .add(lookup);
        let registration = tenzro_network::ModelRegistrationMessage {
            model_id: model.to_string(),
            name: model.to_string(),
            provider: "11".repeat(32),
            iroh_endpoint_id: provider.id().to_string(),
            pricing,
            timestamp: 1_700_000_000_000,
            ttl_secs: 600,
            ..Default::default()
        };
        self.node.network_models.insert(
            model.to_string(),
            NetworkModelEntry {
                registration,
                last_seen: std::time::Instant::now(),
            },
        );
    }

    /// The provider legs this gateway owes, over its open RPC.
    async fn network_legs(&self) -> Vec<Value> {
        let v = common::rpc(
            &reqwest::Client::new(),
            &self.base_url,
            "tenzro_listNetworkLegs",
            json!({}),
        )
        .await;
        v["result"]["legs"]
            .as_array()
            .cloned()
            .unwrap_or_else(|| panic!("no legs in {v}"))
    }

    /// Poll the legs until `done` holds of the first, for at most `secs`.
    async fn leg_when(&self, secs: u64, done: impl Fn(&Value) -> bool) -> Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
        loop {
            let legs = self.network_legs().await;
            if let Some(leg) = legs.first()
                && done(leg)
            {
                return leg.clone();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the leg never reached the state awaited: {legs:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

/// A UDP port on loopback that was free a moment ago.
fn free_udp_port() -> std::net::SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .expect("a free loopback port")
}

/// A provider on its own endpoint serving `tenzro/infer`: records the body
/// of each request it serves and answers with `reply`.
struct MockProvider {
    router: Router,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl MockProvider {
    fn id(&self) -> EndpointId {
        self.router.endpoint().id()
    }
}

#[derive(Debug)]
struct Recorder {
    reply: Value,
    seen: Arc<Mutex<Vec<Value>>>,
}

#[async_trait::async_trait]
impl RequestHandler for Recorder {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let body: Value = serde_json::from_slice(&request).unwrap_or(Value::Null);
        self.seen.lock().unwrap().push(body);
        Reply::full(200, serde_json::to_vec(&self.reply).unwrap())
    }
}

async fn mock_provider(reply: Value) -> MockProvider {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    // A provider speaks the node endpoints' TLS: the hybrid key exchange only.
    let endpoint = Endpoint::builder(presets::Minimal)
        .crypto_provider(Arc::new(
            tenzro_iroh::identity_transport::peer_crypto_provider(),
        ))
        // Loopback only, as the gateway is: a provider bound to every address
        // advertises 0.0.0.0, which Windows does not route to this machine.
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let handler = Arc::new(Recorder {
        reply,
        seen: seen.clone(),
    });
    let router = Router::builder(endpoint)
        .accept(
            ALPN_INFER,
            RequestProtocol::new(
                "infer",
                handler,
                MAX_INFER_BYTES,
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
        .spawn();
    MockProvider { router, seen }
}

fn completion() -> Value {
    json!({
        "id": "chatcmpl-x",
        "object": "chat.completion",
        "model": "remote-model",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 4_000_000_000u64, "total_tokens": 1}
    })
}

/// A caller with no credential gets no forwarded inference: the operator
/// would pay the provider for it.
#[tokio::test]
async fn an_anonymous_caller_cannot_spend_the_operators_money_on_a_forward() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);

    let admission = NodeInferenceAdmission::for_node(&gw.node);
    assert!(
        !matches!(
            admission.decide_as(
                tenzro_types::node_access::Surface::Openai,
                None,
                Some("remote-model")
            ),
            InferenceAccess::Allow
        ),
        "a forwarded model must never be free to an anonymous caller"
    );

    let resp = reqwest::Client::new()
        .post(format!("{}/v1/chat/completions", gw.base_url))
        .json(&json!({"model": "remote-model",
                      "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        402,
        "{}",
        resp.text().await.unwrap()
    );
    assert!(
        provider.seen.lock().unwrap().is_empty(),
        "nothing reached the provider"
    );
    gw.shutdown().await;
}

/// The caller's own access token authenticates it here and is never
/// replayed to the provider; only a credential addressed to the provider
/// travels.
#[tokio::test]
async fn the_callers_key_never_reaches_the_provider() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);
    let client = reqwest::Client::new();
    let caller = member().sign_in(&client, &gw.base_url).await;
    let route = format!("{}/v1/chat/completions", gw.base_url);
    let resp = caller
        .authorize_route(client.post(&route), &route)
        .json(&json!({"model": "remote-model",
                      "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    {
        let seen = provider.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].get("access_token").is_none(), "caller token leaked");
        assert!(seen[0].get("dpop").is_none());
    }

    let resp = caller
        .authorize_route(client.post(&route), &route)
        .header("x-tenzro-provider-access-token", "issued-by-provider")
        .header("x-tenzro-provider-dpop", "proof-for-provider")
        .json(&json!({"model": "remote-model",
                      "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    {
        let seen = provider.seen.lock().unwrap();
        assert_eq!(
            seen[1].get("access_token").and_then(|v| v.as_str()),
            Some("issued-by-provider")
        );
    }
    gw.shutdown().await;
}

/// Tools, tool choice and the receipt nonce reach the provider, so a
/// provider renders the same prompt and binds its receipt to the request.
#[tokio::test]
async fn tool_declarations_and_the_receipt_nonce_are_forwarded() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);

    let tools = json!([{"type": "function", "function": {"name": "get_weather",
        "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}}}]);
    let resp = gw.authorized_chat().await
        .json(&json!({"model": "remote-model", "tools": tools, "tool_choice": "auto",
                      "messages": [
                          {"role": "user", "content": "weather?"},
                          {"role": "assistant", "content": null, "tool_calls": [
                              {"id": "c1", "type": "function",
                               "function": {"name": "get_weather", "arguments": "{\"city\":\"Oslo\"}"}}]},
                          {"role": "tool", "tool_call_id": "c1", "content": "3C"}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let body = provider.seen.lock().unwrap()[0].clone();
    assert_eq!(body["tools"], tools);
    assert_eq!(body["tool_choice"], "auto");
    assert_eq!(body["messages"][1]["tool_calls"][0]["id"], "c1");
    assert_eq!(body["messages"][2]["tool_call_id"], "c1");
    assert_eq!(body["receipt_nonce"].as_str().map(str::len), Some(32));
    // A seed is always sent, drawn per request when the caller sent none.
    assert!(body["seed"].is_u64());
    gw.shutdown().await;
}

/// Malformed tool declarations are refused before anything is admitted or
/// forwarded.
#[tokio::test]
async fn malformed_tools_are_refused_with_a_named_code() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);
    for (tools, choice, code) in [
        (
            json!([{"type": "function", "function": {"name": "bad name"}}]),
            json!("auto"),
            "invalid_tool_name",
        ),
        (json!([]), json!("required"), "invalid_tool_choice"),
        (
            json!([{"type": "retrieval", "function": {"name": "x"}}]),
            json!("auto"),
            "unsupported_tool_type",
        ),
    ] {
        let resp = gw
            .authorized_chat()
            .await
            .json(
                &json!({"model": "remote-model", "tools": tools, "tool_choice": choice,
                          "messages": [{"role": "user", "content": "x"}]}),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 400);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["error"]["code"], code, "{body}");
    }
    assert!(provider.seen.lock().unwrap().is_empty());
    gw.shutdown().await;
}

/// `verifiable` with streaming is refused rather than served unverifiable.
#[tokio::test]
async fn a_streamed_verifiable_request_is_refused() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);
    let resp = gw
        .authorized_chat()
        .await
        .json(
            &json!({"model": "remote-model", "stream": true, "verifiable": true,
                      "messages": [{"role": "user", "content": "x"}]}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "verifiable_stream_unsupported");
    gw.shutdown().await;
}

/// A provider that cannot be reached over its endpoint id is an error to the
/// caller.
#[tokio::test]
async fn an_unreachable_provider_is_an_error() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce("remote-model", &provider);
    provider.router.shutdown().await.unwrap();

    let resp = gw
        .authorized_chat()
        .await
        .json(&json!({"model": "remote-model",
                      "messages": [{"role": "user", "content": "hello"}]}))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "an unreachable provider cannot answer"
    );
    gw.shutdown().await;
}

/// The per-call floor the priced provider charges, in TNZO base units.
const LEG_FLOOR: u128 = 10_000_000_000_000_000;

/// A card pricing input tokens with a per-call floor of [`LEG_FLOOR`].
fn priced_card() -> tenzro_types::price_card::RateCard {
    tenzro_types::price_card::RateCard {
        denom: tenzro_types::price_card::Denom::Wei,
        lines: [(
            "input_tokens".to_string(),
            tenzro_types::price_card::Rate::per(1, 0),
        )]
        .into_iter()
        .collect(),
        min_charge: LEG_FLOOR,
    }
}

/// A completion carrying a provider receipt, and the receipt.
fn receipted_completion() -> (Value, Value) {
    let receipt = json!({"version": 1, "model_id": "remote-model", "output_hash": "abc",
                         "signature": "00"});
    let mut reply = completion();
    reply["tenzro_receipt"] = receipt.clone();
    (reply, receipt)
}

fn sha256_hex(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(serde_json::to_vec(v).unwrap()))
}

/// Forward one priced call and return the leg it owes, as first written.
async fn forward_priced_call(gw: &Gateway, provider: &MockProvider) -> Value {
    gw.announce_priced("remote-model", provider, priced_card());
    let resp = gw
        .authorized_chat()
        .await
        .json(&json!({"model": "remote-model", "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    // The leg is written before the answer goes out.
    let legs = gw.network_legs().await;
    assert_eq!(legs.len(), 1, "one forwarded call owes one leg: {legs:?}");
    legs[0].clone()
}

/// A forwarded call is never fire-and-forget: it owes its provider a payment
/// record bound to the request nonce the provider was sent, the receipt it
/// returned and the offer it was routed under, listed over RPC; a payment
/// that cannot be made is recorded attempt by attempt, never dropped.
#[tokio::test]
async fn a_forwarded_call_owes_its_provider_a_bound_leg_listed_over_rpc() {
    let gw = Gateway::boot().await;
    let (reply, receipt) = receipted_completion();
    let provider = mock_provider(reply).await;
    let leg = forward_priced_call(&gw, &provider).await;

    let nonce = provider.seen.lock().unwrap()[0]["receipt_nonce"]
        .as_str()
        .expect("a receipt nonce was sent")
        .to_string();
    assert_eq!(leg["nonce"], nonce);
    assert_eq!(leg["model_id"], "remote-model");
    assert_eq!(leg["provider"], format!("0x{}", "11".repeat(32)));
    assert_eq!(leg["cost_wei"], LEG_FLOOR.to_string());
    assert_eq!(leg["receipt_digest"], sha256_hex(&receipt));
    assert_eq!(leg["payment_id"], leg["request_digest"]);
    assert_eq!(leg["request_digest"].as_str().map(str::len), Some(64));
    assert_eq!(leg["quote_digest"].as_str().map(str::len), Some(64));

    // This gateway holds no ledger account: the attempt is refused and the
    // refusal is on the record, with the leg still owed.
    let leg = gw
        .leg_when(10, |l| {
            l["attempts"].as_u64() >= Some(1)
                && l["errors"].as_array().is_some_and(|e| !e.is_empty())
        })
        .await;
    assert!(
        leg["errors"][0]
            .as_str()
            .is_some_and(|e| e.contains("submits no ledger transactions")),
        "{leg}"
    );
    assert!(
        matches!(leg["status"].as_str(), Some("queued" | "failed")),
        "{leg}"
    );
    assert!(leg["tx_hash"].is_null());

    // The listing filters by status.
    let settled = common::rpc(
        &reqwest::Client::new(),
        &gw.base_url,
        "tenzro_listNetworkLegs",
        json!({"status": "settled"}),
    )
    .await;
    assert_eq!(settled["result"]["legs"], json!([]), "{settled}");
    gw.shutdown().await;
}

/// The node's own ledger account, the one its hardware keys derive.
fn ledger_account(node: &TenzroNode) -> tenzro_types::primitives::Address {
    tenzro_types::primitives::Address::new(
        node.identity_signer()
            .expect("validator signer")
            .public_key()
            .account_slot(),
    )
}

fn balance(node: &TenzroNode, a: &tenzro_types::primitives::Address) -> u128 {
    use tenzro_vm::traits::VmState as _;
    let state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone());
    state.get_balance(a.as_bytes())
}

fn fund(node: &TenzroNode, a: &tenzro_types::primitives::Address, amount: u128) {
    use tenzro_vm::traits::VmState as _;
    let mut state = tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone());
    let before = state.get_balance(a.as_bytes());
    state.set_balance(a.as_bytes(), before + amount);
    state.commit().expect("commit funded balance");
}

/// The provider leg of a forwarded call settles on chain from the gateway's
/// own account, net of the network fee: refused while the account cannot
/// pay, retried under the same payment, and paid exactly once.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_forwarded_calls_provider_is_paid_on_chain_net_of_the_fee() {
    let gw = Gateway::boot_validator().await;
    let (reply, _) = receipted_completion();
    let provider = mock_provider(reply).await;
    let payee = tenzro_types::primitives::Address::new([0x11; 32]);
    let leg = forward_priced_call(&gw, &provider).await;
    let payment_id = leg["payment_id"].as_str().unwrap().to_string();

    // The gateway's account holds nothing yet: every attempt is refused.
    let failed = gw.leg_when(60, |l| l["status"] == "failed").await;
    assert_eq!(failed["attempts"], 5, "{failed}");
    assert_eq!(
        failed["errors"].as_array().map(Vec::len),
        Some(5),
        "{failed}"
    );
    assert_eq!(balance(&gw.node, &payee), 0);

    // Funded, the operator drives it again and it settles once.
    let one_tnzo = 1_000_000_000_000_000_000u128;
    fund(&gw.node, &ledger_account(&gw.node), one_tnzo);
    let client = reqwest::Client::new();
    let op = admin().sign_in(&client, &gw.base_url).await;
    let retried = op
        .call(
            &client,
            &gw.base_url,
            "tenzro_retryNetworkLeg",
            json!({"payment_id": payment_id}),
        )
        .await;
    let settled = &retried["result"];
    assert_eq!(settled["status"], "settled", "{retried}");
    assert_eq!(settled["payment_id"], payment_id.as_str());
    let fee: u128 = settled["network_fee"].as_str().unwrap().parse().unwrap();
    let credit: u128 = settled["payee_credit"].as_str().unwrap().parse().unwrap();
    assert_eq!(fee + credit, LEG_FLOOR);
    assert_eq!(
        balance(&gw.node, &payee),
        credit,
        "the provider is credited net of the fee"
    );

    // A settled leg is not paid again.
    let again = op
        .call(
            &client,
            &gw.base_url,
            "tenzro_retryNetworkLeg",
            json!({"payment_id": payment_id}),
        )
        .await;
    assert!(again["error"].is_object(), "{again}");
    assert_eq!(balance(&gw.node, &payee), credit);
    gw.shutdown().await;
}

/// A caller that pins a jurisdiction this node cannot claim is refused
/// before the model is ever touched: the fail-closed check is this node's
/// own locality claim, known upfront, so it runs before admission or
/// loading — a local model announced with no weights behind it is enough to
/// prove the 412 never waited on the serving runtime.
#[tokio::test]
async fn a_pin_this_node_cannot_satisfy_gets_412_before_the_model_loads() {
    let gw = Gateway::boot().await;
    gw.node.served_models.insert(
        "local-model".to_string(),
        Some(tenzro_types::Visibility::Public),
    );

    for stream in [false, true] {
        let resp = gw
            .authorized_chat()
            .await
            .json(
                &json!({"model": "local-model", "jurisdiction": "DE", "stream": stream,
                          "messages": [{"role": "user", "content": "hi"}]}),
            )
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap();
        assert_eq!(status, 412, "stream={stream}: {body}");
        assert!(
            body.contains("jurisdiction_not_satisfied"),
            "stream={stream}: {body}"
        );
    }
    gw.shutdown().await;
}

/// A pinned forward to a provider that never attests the pin is refused by
/// this gateway itself, whether or not the caller also asked for
/// `jurisdiction_receipt: "required"` — the pin is this gateway's own
/// promise to its caller, not something it can leave to the provider's
/// discretion.
#[tokio::test]
async fn a_pinned_forward_to_a_provider_with_no_attesting_receipt_gets_412() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce_priced("remote-model", &provider, priced_card());

    let resp = gw
        .authorized_chat()
        .await
        .json(&json!({"model": "remote-model", "jurisdiction": "DE",
                      "messages": [{"role": "user", "content": "hi"}]}))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 412, "{body}");
    assert!(body.contains("jurisdiction_not_satisfied"), "{body}");
    gw.shutdown().await;
}

/// The same pin on a streamed forward is refused up front, before any byte
/// of the provider's stream is relayed: this gateway cannot verify a
/// forwarded provider's attestation without buffering the whole response,
/// which a raw SSE proxy never does, so it never starts one it cannot vouch
/// for.
#[tokio::test]
async fn a_pinned_streamed_forward_gets_412_before_any_bytes() {
    let gw = Gateway::boot().await;
    let provider = mock_provider(completion()).await;
    gw.announce_priced("remote-model", &provider, priced_card());

    let resp = gw
        .authorized_chat()
        .await
        .json(
            &json!({"model": "remote-model", "jurisdiction": "DE", "stream": true,
                      "messages": [{"role": "user", "content": "hi"}]}),
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap();
    assert_eq!(status, 412, "{body}");
    assert!(body.contains("jurisdiction_not_satisfied"), "{body}");
    gw.shutdown().await;
}

/// A provider that signs a real receipt for what it serves: bound to the
/// nonce the gateway sent it and to the output it returns, whole or as an
/// SSE stream whose final chunk carries the receipt.
struct ReceiptingProvider {
    signer: tenzro_crypto::batch::ImmediateRecordSigner,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl std::fmt::Debug for ReceiptingProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReceiptingProvider")
    }
}

/// The model identity the receipting provider signs under.
const SERVED_MODEL_HASH: &str = "ab";

impl ReceiptingProvider {
    fn receipt(&self, nonce: &str, text: &str) -> Value {
        use tenzro_node::inference_receipt::{
            InferenceReceipt, ModelIdentity, ReceiptClaims, SamplingParams, output_hash,
        };
        let receipt = InferenceReceipt::sign(
            &self.signer,
            ReceiptClaims {
                decode: Default::default(),
                model_id: "remote-model".into(),
                identity: ModelIdentity {
                    model_hash: SERVED_MODEL_HASH.into(),
                    engine: "llama.cpp".into(),
                },
                machine_did: "did:tenzro:machine:provider".into(),
                nonce: nonce.into(),
                input_commitment: "11".into(),
                output_hash: output_hash(text, "", ""),
                units: tenzro_types::model::BillableUnits::tokens(5, 2),
                priced: None,
                provenance: Vec::new(),
                sampling: SamplingParams {
                    seed: 7,
                    temperature: 0.0,
                    top_p: 1.0,
                    top_k: None,
                    min_p: None,
                    max_output_tokens: 16,
                    keyed_sampler: false,
                },
                commitment_hash: None,
                tee: None,
                activation_fingerprint: None,
            },
        )
        .unwrap();
        serde_json::to_value(receipt).unwrap()
    }
}

#[async_trait::async_trait]
impl RequestHandler for ReceiptingProvider {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let body: Value = serde_json::from_slice(&request).unwrap_or(Value::Null);
        self.seen.lock().unwrap().push(body.clone());
        let nonce = body["receipt_nonce"].as_str().unwrap_or("").to_string();
        let usage = json!({"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7});
        if body["stream"] == json!(true) {
            let mut sse = String::new();
            for piece in ["Hel", "lo"] {
                let chunk = json!({"id": "chatcmpl-x", "object": "chat.completion.chunk",
                    "model": "remote-model",
                    "choices": [{"index": 0, "delta": {"content": piece}, "finish_reason": null}]});
                sse.push_str(&format!("data: {chunk}\n\n"));
            }
            let last = json!({"id": "chatcmpl-x", "object": "chat.completion.chunk",
                "model": "remote-model",
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                "usage": usage, "tenzro_receipt": self.receipt(&nonce, "Hello")});
            sse.push_str(&format!("data: {last}\n\ndata: [DONE]\n\n"));
            Reply::full(200, sse.into_bytes())
        } else {
            let reply = json!({"id": "chatcmpl-x", "object": "chat.completion",
                "model": "remote-model",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hello"},
                             "finish_reason": "stop"}],
                "usage": usage, "tenzro_receipt": self.receipt(&nonce, "Hello")});
            Reply::full(200, serde_json::to_vec(&reply).unwrap())
        }
    }
}

async fn receipting_provider() -> MockProvider {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    // A provider speaks the node endpoints' TLS: the hybrid key exchange only.
    let endpoint = Endpoint::builder(presets::Minimal)
        .crypto_provider(Arc::new(
            tenzro_iroh::identity_transport::peer_crypto_provider(),
        ))
        // Loopback only, as the gateway is: a provider bound to every address
        // advertises 0.0.0.0, which Windows does not route to this machine.
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .bind()
        .await
        .unwrap();
    let handler = Arc::new(ReceiptingProvider {
        signer: tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(
            tenzro_crypto::composite::testing::TestHybridSigner::random(),
        )),
        seen: seen.clone(),
    });
    let router = Router::builder(endpoint)
        .accept(
            ALPN_INFER,
            RequestProtocol::new(
                "infer",
                handler,
                MAX_INFER_BYTES,
                tenzro_iroh::limits::AdmissionLimits::default(),
            ),
        )
        .spawn();
    MockProvider { router, seen }
}

/// Check that `receipt` is a signed receipt that verifies on its own, names
/// the nonce the provider was sent, and binds `text`, the output the caller
/// actually received.
fn assert_receipt_binds(receipt: &Value, nonce: &str, text: &str) {
    use tenzro_node::inference_receipt::{InferenceReceipt, output_hash};
    let receipt: InferenceReceipt = serde_json::from_value(receipt.clone())
        .unwrap_or_else(|e| panic!("not a receipt ({e}): {receipt}"));
    receipt
        .verify_offline(SERVED_MODEL_HASH)
        .expect("the receipt verifies with nothing but the model hash");
    assert_eq!(receipt.nonce, nonce);
    assert_eq!(receipt.output_hash, output_hash(text, "", ""));
}

/// `/v1/chat/completions` hands its caller the serving provider's signed
/// `tenzro_receipt`: in the body of a whole completion, and on the final
/// chunk of a stream and no chunk before it. Each receipt verifies on its
/// own and binds the output the caller received.
#[tokio::test]
async fn a_chat_completion_carries_a_tenzro_receipt_streamed_and_not() {
    let gw = Gateway::boot().await;
    let provider = receipting_provider().await;
    gw.announce("remote-model", &provider);

    // Whole completion.
    let resp = gw
        .authorized_chat()
        .await
        .json(&json!({"model": "remote-model",
                      "messages": [{"role": "user", "content": "Say hello."}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let body: Value = resp.json().await.unwrap();
    let nonce = provider.seen.lock().unwrap()[0]["receipt_nonce"]
        .as_str()
        .expect("a receipt nonce was sent")
        .to_string();
    let text = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert_receipt_binds(&body["tenzro_receipt"], &nonce, text);

    // Stream.
    let resp = gw
        .authorized_chat()
        .await
        .json(&json!({"model": "remote-model", "stream": true,
                      "messages": [{"role": "user", "content": "Say hello."}]}))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.text().await.unwrap());
    let sse = resp.text().await.unwrap();
    let chunks: Vec<Value> = sse
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .filter(|d| *d != "[DONE]")
        .map(|d| serde_json::from_str(d).unwrap_or_else(|e| panic!("bad chunk ({e}): {d}")))
        .collect();
    let (last, earlier) = chunks
        .split_last()
        .unwrap_or_else(|| panic!("no chunks in {sse}"));
    for chunk in earlier {
        assert!(
            chunk.get("tenzro_receipt").is_none_or(Value::is_null),
            "a chunk before the last carries a receipt: {chunk}"
        );
    }
    let streamed: String = chunks
        .iter()
        .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
        .collect();
    assert_eq!(streamed, "Hello");
    let nonce = provider.seen.lock().unwrap()[1]["receipt_nonce"]
        .as_str()
        .expect("a receipt nonce was sent")
        .to_string();
    assert_receipt_binds(&last["tenzro_receipt"], &nonce, &streamed);
    gw.shutdown().await;
}

/// Announce `model` from a provider that is never called, at `pricing`.
fn announce_offer(
    gw: &Gateway,
    model: &str,
    provider: &str,
    pricing: tenzro_types::price_card::RateCard,
) {
    let registration = tenzro_network::ModelRegistrationMessage {
        model_id: model.to_string(),
        name: model.to_string(),
        provider: provider.to_string(),
        iroh_endpoint_id: format!("endpoint-{provider}"),
        pricing,
        timestamp: 1_700_000_000_000,
        ttl_secs: 600,
        ..Default::default()
    };
    gw.node.network_models.insert(
        format!("{model}@{provider}"),
        NetworkModelEntry {
            registration,
            last_seen: std::time::Instant::now(),
        },
    );
}

/// `tenzro_quoteInference` prices a request on every provider announcing the
/// model, at each provider's own card, cheapest first; `provider` narrows the
/// quote to one, and a unit no card meters is refused.
#[tokio::test]
async fn a_quote_prices_each_offer_at_its_card_cheapest_first() {
    let gw = Gateway::boot().await;
    let card = |per_token: u128| tenzro_types::price_card::RateCard {
        denom: tenzro_types::price_card::Denom::Wei,
        lines: [(
            "input_tokens".to_string(),
            tenzro_types::price_card::Rate::per(per_token, 0),
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    let dear = "22".repeat(32);
    let cheap = "33".repeat(32);
    announce_offer(&gw, "quoted-model", &dear, card(7));
    announce_offer(&gw, "quoted-model", &cheap, card(3));
    announce_offer(&gw, "other-model", &cheap, card(1));
    let quote = |params: Value| {
        let base = gw.base_url.clone();
        async move {
            common::rpc(
                &reqwest::Client::new(),
                &base,
                "tenzro_quoteInference",
                params,
            )
            .await
        }
    };

    let v = quote(json!({"model": "quoted-model", "units": {"input_tokens": 1000}})).await;
    let offers = v["result"]["offers"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(offers.len(), 2, "{offers:?}");
    assert_eq!(offers[0]["provider_address"], json!(cheap));
    assert_eq!(offers[0]["price_wei"], json!("3000"));
    assert_eq!(offers[1]["provider_address"], json!(dear));
    assert_eq!(offers[1]["price_wei"], json!("7000"));
    assert!(offers.iter().all(|o| o["source"] == "network"));

    let v = quote(
        json!({"model": "quoted-model", "units": {"input_tokens": 1000},
                         "provider": format!("0x{dear}")}),
    )
    .await;
    let offers = v["result"]["offers"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(offers.len(), 1, "{offers:?}");
    assert_eq!(offers[0]["provider_address"], json!(dear));

    let v = quote(json!({"model": "quoted-model", "units": {"Bad Key": 1}})).await;
    assert!(
        v["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("Bad Key")),
        "{v}"
    );

    // A unit no card meters is quoted, at no price.
    let v =
        quote(json!({"model": "quoted-model", "units": {"input_tokens": 1, "furlongs": 2}})).await;
    let offers = v["result"]["offers"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(offers.len(), 2, "{offers:?}");
    assert!(
        offers.iter().all(|o| o["price_wei"].is_null()),
        "{offers:?}"
    );

    let v = quote(json!({"model": "unannounced", "units": {"input_tokens": 1}})).await;
    assert_eq!(v["result"]["offers"], json!([]), "{v}");
    gw.shutdown().await;
}

/// A provider's settlement statement, built from `tenzro_listSettlements`,
/// checks against the chain over RPC: each settled line matches its payment
/// record (`tenzro_getPayment`) and its transaction receipt
/// (`eth_getTransactionReceipt`), and a line the chain does not back is
/// reported.
#[tokio::test]
#[ignore = "needs this machine's hardware consensus key (TPM 2.0 or Secure Enclave)"]
async fn a_providers_statement_verifies_against_the_chain_over_rpc() {
    use tenzro_types::statement::{ChainFacts, Line, Period, build, verify};
    let gw = Gateway::boot_validator().await;
    let (reply, _) = receipted_completion();
    let provider = mock_provider(reply).await;
    fund(
        &gw.node,
        &ledger_account(&gw.node),
        1_000_000_000_000_000_000,
    );
    let leg = forward_priced_call(&gw, &provider).await;
    let settled = gw.leg_when(60, |l| l["status"] == "settled").await;
    assert_eq!(settled["payment_id"], leg["payment_id"]);

    let client = reqwest::Client::new();
    let call = |method: &'static str, params: Value| {
        let client = client.clone();
        let base = gw.base_url.clone();
        async move {
            let v = common::rpc(&client, &base, method, params).await;
            assert!(v["error"].is_null(), "{method}: {v}");
            v["result"].clone()
        }
    };
    let payee = format!("0x{}", "11".repeat(32));
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let (from_ms, to_ms) = (now - 3_600_000, now + 3_600_000);
    let page = call(
        "tenzro_listSettlements",
        json!({"provider": payee, "from_ms": from_ms, "to_ms": to_ms, "limit": 200}),
    )
    .await;
    let lines: Vec<Line> = page["settlements"]
        .as_array()
        .unwrap_or_else(|| panic!("{page}"))
        .iter()
        .map(|e| Line::from_settlement(e).expect("a settlement line"))
        .collect();
    assert_eq!(lines.len(), 1, "{page}");
    let statement = build(&payee, from_ms, to_ms, Period::Day, true, lines);

    let mut facts = std::collections::BTreeMap::new();
    for line in statement.lines.iter().filter(|l| l.settled()) {
        let pay_ref = line
            .pay_ref
            .clone()
            .expect("a settled line names its payment");
        let tx_hash = line
            .tx_hash
            .clone()
            .expect("a settled line names its transaction");
        let record = call("tenzro_getPayment", json!({"pay_ref": pay_ref})).await;
        let receipt = call(
            "eth_getTransactionReceipt",
            json!([format!("0x{}", tx_hash.trim_start_matches("0x"))]),
        )
        .await;
        facts.insert(
            pay_ref,
            ChainFacts::from_rpc(&record, &receipt).expect("chain facts"),
        );
    }
    assert_eq!(facts.len(), 1, "the settled line has its chain facts");
    let differences = verify(&statement, &facts);
    assert!(differences.is_empty(), "{differences:?}");

    // A payment record that says otherwise is reported.
    let mut wrong = facts.clone();
    for f in wrong.values_mut() {
        f.amount += 1;
    }
    assert!(!verify(&statement, &wrong).is_empty());
    // So is a settled line the chain has no record of.
    assert!(!verify(&statement, &Default::default()).is_empty());
    gw.shutdown().await;
}

/// The OpenAI image route maps onto `tenzro_mediaGen_render`: the request is
/// read as a render, what it cannot be is refused by name, and a model no
/// provider serves is answered as a JSON error from the render.
#[tokio::test]
async fn the_image_route_renders_through_the_media_render() {
    let gw = Gateway::boot().await;
    let client = reqwest::Client::new();
    let caller = member().sign_in(&client, &gw.base_url).await;
    let route = format!("{}/v1/images/generations", gw.base_url);
    let send = |body: Value| {
        caller
            .authorize_route(client.post(&route), &route)
            .json(&body)
            .send()
    };
    let resp = send(json!({"model": "qwen-image", "prompt": "a lighthouse", "n": 2}))
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_n", "{body}");

    let resp = send(json!({"model": "qwen-image", "prompt": "a lighthouse"}))
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert!(status >= 400 && status != 404, "{status} {body}");
    assert!(body["error"]["message"].is_string(), "{body}");
    gw.shutdown().await;
}

/// The OpenAI video route maps onto `tenzro_mediaGen_render` the same way:
/// what the request cannot be is refused by name, a model no provider serves
/// is answered as a JSON error from the render, and a content id that is not
/// a content hash is refused.
#[tokio::test]
async fn the_video_route_renders_through_the_media_render() {
    let gw = Gateway::boot().await;
    let client = reqwest::Client::new();
    let caller = member().sign_in(&client, &gw.base_url).await;
    let route = format!("{}/v1/videos", gw.base_url);
    let send = |body: Value| {
        caller
            .authorize_route(client.post(&route), &route)
            .json(&body)
            .send()
    };
    let resp = send(json!({"model": "cosmos3-edge"})).await.unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"]["code"], "missing_prompt", "{body}");

    let resp = send(json!({"model": "cosmos3-edge", "prompt": "waves", "seconds": "4"}))
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body: Value = resp.json().await.unwrap();
    assert!(status >= 400 && status != 404, "{status} {body}");
    assert!(body["error"]["message"].is_string(), "{body}");

    // The content route serves stored outputs by hash, as a read.
    let content = format!("{}/v1/videos/not-a-hash/content", gw.base_url);
    let resp = caller
        .authorize_method(client.get(&content), "GET", &content)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 400);
    gw.shutdown().await;
}
