//! Who paid for a generation, end to end.
//!
//! A real `TenzroNode` runs as a solo validator, its hardware keys held by
//! software stand-ins, and serves a chat model from an OpenAI-compatible
//! endpoint (a mock standing in for the operator's serving stack). A payer
//! holding its own key pays for a generation two ways, and the node's
//! generation record names that payer each time:
//!
//! - over `/v1/chat/completions`, behind the HTTP 402 gate: the payer answers
//!   the challenge with a signed x402 credential, which the gate settles on
//!   the ledger before the call is served;
//! - in a `tenzro_chat` frame carrying the payer's signed authorization, which
//!   the node settles on the ledger for the metered cost of the call.

mod dpop_bearer;
mod passkey_holder;

use std::sync::Arc;

use axum::Json;
use axum::routing::post;
use serde_json::{Value, json};
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{CompositePublicKey, HybridSigner, SignatureContext};
use tenzro_node::connector::{ConnectorConfig, UpstreamModelConfig, WorkClass};
use tenzro_node::inference_admission::NodeInferenceAdmission;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::RoleSet;
use tenzro_types::node_access::{MethodClass, NodeAccessPolicy, PaidVia, Rule, SurfaceRule};
use tenzro_types::payment_authorization::{
    PaymentAuthorization, PaymentBinding, payment_authorization_preimage,
};
use tenzro_types::primitives::Address;
use tokio::sync::broadcast;

const CHAIN_ID: u64 = 1337;
const MODEL: &str = "acme/chat";
/// One TNZO (18 decimals).
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
/// What the gate charges per call on the OpenAI-compatible routes.
const GATE_PRICE: u128 = 20_000_000_000_000_000;
/// The operator's price per token of `MODEL`: the call's metered cost clears
/// the network's micro-settlement floor, so it settles in its own transaction.
const TOKEN_PRICE: u128 = 1_000_000_000_000_000;
const UPSTREAM_KEY: &str = "sk-operator-upstream-payer";

/// A P-256 key standing in for the TPM, one per label. Test-only: a release
/// build opens these keys in a TPM or Secure Enclave.
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

/// The machine's labelled keys and its derivation root, both in software, so
/// this process's node holds a consensus key with no TPM present.
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
        tenzro_device_key::derive::use_remote_root(Arc::new(
            tenzro_device_key::DerivationRoot::for_tests([0x5a; 32]),
        ))
        .expect("install the test root");
    });
}

/// The OpenAI-compatible endpoint the connector serves `MODEL` from.
async fn mock_upstream() -> String {
    let chat = post(|Json(body): Json<Value>| async move {
        Json(json!({
            "id": "chatcmpl-upstream-1",
            "object": "chat.completion",
            "created": 1_700_000_000,
            "model": body["model"],
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "paid answer"},
                         "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}
        }))
    });
    let app = axum::Router::new().route("/v1/chat/completions", chat);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}/v1")
}

/// Who the gate's x402 challenges pay.
fn gate_payee() -> Address {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&[0x02; 20]);
    Address::new(b)
}

struct Harness {
    base_url: String,
    shutdown: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
    _tmp: tempfile::TempDir,
    node: Arc<TenzroNode>,
}

impl Harness {
    /// A solo validator serving `MODEL` through its connector, with the RPC
    /// server's payment gate built as the node binary builds it, and an
    /// access policy that makes inference on the OpenAI-compatible routes
    /// paid and leaves JSON-RPC open.
    async fn start() -> Self {
        install_test_hardware();
        let upstream = mock_upstream().await;
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut policy = NodeAccessPolicy::default();
        policy.rules.push(SurfaceRule {
            surface: Some(tenzro_types::node_access::Surface::Openai),
            class: MethodClass::Inference,
            rule: Rule::Paid {
                via: PaidVia::X402,
                price: GATE_PRICE.to_string(),
                asset: "TNZO".to_string(),
            },
        });
        // A caller the policy names is admitted without the node's price, and
        // is who a call carrying its own payment authorization comes from;
        // anyone else is held to the model's visibility.
        policy.rules.push(SurfaceRule {
            surface: None,
            class: MethodClass::Inference,
            rule: Rule::Any {
                rules: vec![
                    Rule::Allow {
                        dids: vec![member().did()],
                        orgs: Vec::new(),
                    },
                    Rule::Open,
                ],
            },
        });
        dpop_bearer::write_policy(tmp.path(), &policy);
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
            roles: RoleSet::validator_only(),
            consensus: Some(tenzro_consensus::ConsensusConfig::default()),
            iroh: tenzro_iroh::TenzroIrohConfig {
                bind_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
                port_mapping: false,
                ..Default::default()
            },
            genesis: Some(tenzro_node::config::GenesisConfig {
                protocol: None,
                consensus: Default::default(),
                validator_registry: Default::default(),
                version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
                chain_id: CHAIN_ID,
                timestamp: 0,
                validators: vec![
                    tenzro_node::config::GenesisValidator::from_local_hardware(
                        tmp.path(),
                        1_000_000,
                    )
                    .expect("a consensus key"),
                ],
                accounts: Vec::new(),
                weak_subjectivity: None,
                time: tenzro_consensus::TimeRules::default(),
                network_params: Default::default(),
                economy: Default::default(),
                role_stakes: Vec::new(),
            }),
            connector: Some(ConnectorConfig {
                upstream_url: upstream,
                request_timeout_secs: 5,
                idle_timeout_secs: 5,
                max_concurrent: 4,
                api_key: None,
                models: vec![UpstreamModelConfig {
                    id: MODEL.to_string(),
                    upstream_model: "served-chat".to_string(),
                    work: WorkClass::Chat,
                    visibility: None,
                }],
            }),
            ..Default::default()
        };
        config.payments.recipient = hex::encode(&gate_payee().as_bytes()[..20]);
        config.payments.default_amount = GATE_PRICE;
        config.payments.default_asset = "TNZO".to_string();
        config.payments.default_protocol = "x402".to_string();
        let mut card = tenzro_node::node::default_rate_card();
        for unit in [
            tenzro_types::meter::unit::INPUT_TOKENS,
            tenzro_types::meter::unit::OUTPUT_TOKENS,
        ] {
            card.lines.insert(
                unit.to_string(),
                tenzro_types::price_card::Rate::per(TOKEN_PRICE, 0),
            );
        }
        config
            .provider_rates
            .inference
            .models
            .insert(MODEL.to_string(), card);
        let payments = config.payments.clone();

        let mut node = TenzroNode::new(config).await.expect("node creation");
        node.start().await.expect("node start");
        let node = Arc::new(node);
        let gateway = node.payment_gateway().expect("a payment gateway").clone();
        let gate = tenzro_payments::middleware::PaymentGateMiddleware::new(
            gateway.clone(),
            tenzro_payments::middleware::PaymentGateConfig {
                default_amount: payments.default_amount,
                default_asset: payments.default_asset.clone(),
                recipient: payments.recipient.clone(),
                default_protocol: payments.default_protocol.clone(),
            },
            gateway.challenge_store(),
        );
        let gate =
            tenzro_node::payment_gate::with_metering(&node, gate, payments.metered_settlement)
                .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)));
        let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
        let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
        let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string())
            .with_inference_admission(Arc::new(NodeInferenceAdmission::for_node(&node)))
            .with_payment_gate(gate);
        let handle =
            tokio::spawn(
                async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await },
            );
        let addr = addr_rx.await.expect("bound address");
        let harness = Self {
            base_url: format!("http://{addr}"),
            shutdown,
            handle,
            _tmp: tmp,
            node,
        };
        // The node's own account pays the gas of the settlements it submits,
        // and submits nothing before its ML-DSA-65 key is enrolled.
        harness.fund(&harness.ledger_account(), ONE_TNZO);
        let node_key = harness
            .node
            .identity_signer()
            .expect("validator signer")
            .public_key()
            .clone();
        harness.enroll(&node_key);
        harness
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }

    fn ledger_account(&self) -> Address {
        Address::new(
            self.node
                .identity_signer()
                .expect("validator signer")
                .public_key()
                .account_slot(),
        )
    }

    fn fund(&self, a: &Address, amount: u128) {
        use tenzro_vm::traits::VmState as _;
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        let before = state.get_balance(a.as_bytes());
        state.set_balance(a.as_bytes(), before + amount);
        state.commit().expect("commit funded balance");
    }

    /// Enrolls the ML-DSA-65 key of `key`'s account, as its first
    /// hybrid-signed transaction would; a payment needs that leg.
    fn enroll(&self, key: &CompositePublicKey) {
        let mut state =
            tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone());
        tenzro_vm::account_keys::set_enrolled_pq_key(
            &mut state,
            &key.p256,
            key.pq.clone().expect("a hybrid key"),
            &mut Vec::new(),
        );
        state.commit().expect("commit the enrolled key");
    }

    fn balance(&self, a: &Address) -> u128 {
        use tenzro_vm::traits::VmState as _;
        tenzro_vm::StateAdapter::with_storage(self.node.storage().expect("storage").clone())
            .get_balance(a.as_bytes())
    }

    /// The node's record of the generation `id`.
    async fn generation(&self, id: &str) -> Value {
        let reply = reqwest::Client::new()
            .get(format!("{}/tenzro/generation", self.base_url))
            .query(&[("id", id)])
            .send()
            .await
            .unwrap();
        assert!(
            reply.status().is_success(),
            "{}",
            reply.text().await.unwrap()
        );
        reply.json().await.unwrap()
    }
}

/// The caller the access policy names, who signs in for a call the node
/// settles from the authorization it carries.
fn member() -> &'static dpop_bearer::OperatorKey {
    static KEY: std::sync::OnceLock<dpop_bearer::OperatorKey> = std::sync::OnceLock::new();
    KEY.get_or_init(dpop_bearer::OperatorKey::new)
}

fn hex_account(a: &Address) -> String {
    format!("0x{}", hex::encode(a.as_bytes()))
}

fn hello() -> Value {
    json!({"model": MODEL, "messages": [{"role": "user", "content": "hello"}]})
}

/// A generation paid at the 402 gate is recorded with the payer whose
/// credential the gate settled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_generation_paid_at_the_gate_names_its_payer() {
    let h = Harness::start().await;
    let payer = TestHybridSigner::hybrid(41);
    h.fund(&payer.address(), ONE_TNZO);
    h.enroll(payer.public_key());
    let client = reqwest::Client::new();
    let route = format!("{}/v1/chat/completions", h.base_url);

    let unpaid = client.post(&route).json(&hello()).send().await.unwrap();
    assert_eq!(unpaid.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
    let challenge: tenzro_payments::PaymentChallenge = unpaid.json().await.expect("a challenge");
    let credential = tenzro_payments::payer_auth::sign_credential(
        &challenge,
        "x402",
        "",
        &payer,
        challenge.amount,
        challenge.amount,
    )
    .expect("credential");
    let encoded = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_string(&credential).unwrap())
    };
    let paid = client
        .post(&route)
        .header("Payment-Credential", encoded)
        .json(&hello())
        .send()
        .await
        .unwrap();
    assert!(paid.status().is_success(), "{}", paid.text().await.unwrap());
    let answer: Value = paid.json().await.unwrap();
    assert_eq!(answer["choices"][0]["message"]["content"], "paid answer");
    assert_eq!(
        h.balance(&payer.address()),
        ONE_TNZO - GATE_PRICE,
        "the gate settled the credential"
    );

    let id = answer["id"].as_str().expect("a completion id");
    let generation = h.generation(id).await;
    assert_eq!(
        generation["payer"],
        hex_account(&payer.address()),
        "{generation}"
    );
    h.shutdown().await;
}

/// A generation a `tenzro_chat` frame paid for, settled by the node itself,
/// is recorded with the payer who signed the authorization.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_generation_settled_by_the_node_names_its_payer() {
    let h = Harness::start().await;
    let payer = TestHybridSigner::hybrid(42);
    h.fund(&payer.address(), ONE_TNZO);
    h.enroll(payer.public_key());
    let payee = h.node.operator_payee().expect("the operator's payee");
    let ceiling = ONE_TNZO / 10;
    let payment_id = "frame-payment-1";
    let binding = PaymentBinding {
        request_digest: [1; 32],
        ..Default::default()
    };
    let preimage = payment_authorization_preimage(
        CHAIN_ID,
        payment_id,
        &payer.address(),
        &payee,
        ceiling,
        "TNZO",
        &binding,
    );
    let signature = payer
        .sign(SignatureContext::PaymentAuthorization, &preimage)
        .expect("sign");
    let authorization = PaymentAuthorization {
        public_key: payer.public_key().p256.clone(),
        signature,
        max_amount: ceiling,
        asset: "TNZO".to_string(),
        binding,
        resellers: Vec::new(),
    };
    let client = reqwest::Client::new();
    let caller = member().sign_in(&client, &h.base_url).await;
    let reply: Value = caller
        .call(
            &client,
            &h.base_url,
            "tenzro_chat",
            json!({
                "model": MODEL,
                "message": "hello",
                "payment": {
                    "payer": hex_account(&payer.address()),
                    "payment_id": payment_id,
                    "authorization": authorization,
                },
            }),
        )
        .await;
    let result = &reply["result"];
    assert!(result.is_object(), "{reply}");
    assert!(
        h.balance(&payer.address()) < ONE_TNZO,
        "the node settled the call: {reply}"
    );

    let id = result["generation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the reply names its generation: {result}"));
    let generation = h.generation(id).await;
    assert_eq!(
        generation["payer"],
        hex_account(&payer.address()),
        "{generation}"
    );
    h.shutdown().await;
}
