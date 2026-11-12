//! End to end against a live OpenShell gateway on Docker and a running
//! Tenzro node, with this machine's TPM as the serving node's identity.
//!
//! Run through `tests/e2e/run-docker.sh`, which uses OpenShell's own e2e
//! support scripts to issue the gateway's PKI and JWT keys and register it
//! with the CLI, then runs this test. The test starts a Tenzro developer
//! chain (`tenzro-node --dev` on a TPM of its own, through
//! `TENZRO_NODE_LAUNCH`), on which two machine roots each bond and delegate
//! an agent under Terms. It starts
//! the Tenzro extensions (credential driver, gateway interceptor, supervisor
//! middleware), which read every agent's delegation from that node, each
//! accepting only calls it authenticated as the gateway's or a supervisor's;
//! the Tenzro inference provider and an outside paid service; then the
//! OpenShell gateway with the extensions configured, and drives a sandbox
//! through OpenShell's e2e harness:
//!
//! 0. an extension refuses a call the gateway did not sign or a process
//!    other than the gateway makes;
//! 1. the sandbox is created only for an agent the caller's account
//!    delegated, and only on a host whose TPM quote verified;
//! 2. it reaches Tenzro inference with a credential minted under the Terms,
//!    which it never sees, and each call settles per unit against a signed
//!    receipt;
//! 3. a 402 from the outside service is paid inside the Terms and refused
//!    over the per-payment cap;
//! 4. revoking the agent's root on Tenzro (a revocation its root approves,
//!    on chain) stops inference, egress, payments and policy changes;
//! 5. every decision is a record signed under the TPM identity, carrying the
//!    host binding.

#![cfg(feature = "openshell-e2e")]

#[path = "e2e/tenzro_node.rs"]
mod tenzro_node;
#[path = "e2e/unauthenticated.rs"]
mod unauthenticated;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tenzro_crypto::batch::ImmediateRecordSigner;
use tenzro_crypto::composite::HybridSigner;
use tenzro_openshell::authority::StateAuthority;
use tenzro_openshell::credential_driver::TenzroCredentialDriver;
use tenzro_openshell::gateway_auth::{CallerKind, GatewayKey, Guard, PeerRule, TokenRule};
use tenzro_openshell::interceptor::{AGENT_LABEL, HOST_ANNOTATION, TenzroInterceptor};
use tenzro_openshell::middleware::{PAYMENT_HEADER, RECEIPT_HEADER, TenzroMiddleware};
use tenzro_openshell::node::NodeDelegations;
use tenzro_openshell::openshell::credentials::v1::credential_driver_server::CredentialDriverServer;
use tenzro_openshell::openshell::gateway_interceptor::v1::gateway_interceptor_server::GatewayInterceptorServer;
use tenzro_openshell::openshell::middleware::v1::http_response_pre_return_server::HttpResponsePreReturnServer;
use tenzro_openshell::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tenzro_openshell::payments::Payer;
use tenzro_openshell::provider::{NodeRoute, Pricing, TenzroProvider};
use tenzro_openshell::records::{RecordLog, verify_session};
use tenzro_openshell::{attestation, digest, gateway_auth};
use tenzro_payments::middleware::{PaymentGateConfig, PaymentGateMiddleware, payment_gate_handler};
use tenzro_types::agent_audit::{ActionKind, ActionOutcome};
use tenzro_types::primitives::Address;

use tenzro_node::DevNode;

const INTERCEPTOR_AUDIENCE: &str = "urn:tenzro:openshell:interceptor";
const MIDDLEWARE_AUDIENCE: &str = "urn:openshell:extension:middleware:tenzro";
const GATEWAY_ID: &str = "tenzro-openshell-e2e";
const PAYEE: &str = "0909090909090909090909090909090909090909";
const PROFILE: &str = "tenzro-e2e";
const PER_UNIT: u128 = 2;
const UNITS: u64 = 30;
const SUPERVISOR_IMAGE: &str = "ghcr.io/nvidia/openshell/supervisor:0.1.5";
const RUNTIME_IMAGE: &str = "ghcr.io/nvidia/openshell/sandbox:0.1.5";
const SANDBOX_IMAGE: &str = "nvcr.io/nvidia/base/ubuntu:24.04";

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("{k} is required: run tests/e2e/run-docker.sh"))
}

async fn listen(addr: &str) -> (tokio::net::TcpListener, u16) {
    let l = tokio::net::TcpListener::bind(addr).await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// The model the Tenzro route serves in this test: a fixed answer with a
/// fixed usage, standing in for a Tenzro node's OpenAI-compatible API.
async fn upstream() -> u16 {
    let (l, port) = listen("127.0.0.1:0").await;
    let app = axum::Router::new().route(
        "/v1/chat/completions",
        axum::routing::post(|axum::Json(b): axum::Json<serde_json::Value>| async move {
            axum::Json(serde_json::json!({
                "object": "chat.completion", "model": b["model"],
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "from tenzro"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": UNITS}
            }))
        }),
    );
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    port
}

/// An outside service that charges per request through `tenzro-payments`'
/// 402 gate: `/report` inside the agent's per-payment cap, `/dear` over it.
async fn payee(authority: &Arc<StateAuthority>) -> u16 {
    let gw = tenzro_payments::gateway::TenzroPaymentGateway::new(1337, authority.clone())
        .with_rail(authority.clone())
        .with_payer_resolver(authority.clone());
    gw.set_terms_gate(authority.clone());
    gw.register_protocol(Arc::new(tenzro_payments::x402::X402PaymentServer::new(
        1337,
        vec!["tenzro".to_string()],
        authority.clone(),
    )));
    let gw = Arc::new(gw);
    let gate = |amount: u128| {
        let config = PaymentGateConfig {
            default_amount: amount,
            default_asset: "TNZO".into(),
            recipient: PAYEE.into(),
            default_protocol: "x402".into(),
        };
        let m = PaymentGateMiddleware::new(gw.clone(), config, gw.challenge_store());
        axum::middleware::from_fn_with_state(m, payment_gate_handler)
    };
    let report = axum::Router::new()
        .route("/report", axum::routing::get(|| async { "paid report" }))
        .layer(gate(300));
    let dear = axum::Router::new()
        .route("/dear", axum::routing::get(|| async { "dear report" }))
        .layer(gate(700));
    let (l, port) = listen("0.0.0.0:0").await;
    tokio::spawn(async move { axum::serve(l, report.merge(dear)).await.unwrap() });
    port
}

async fn run(bin: &str, args: &[&str]) -> (bool, String) {
    let out = tokio::process::Command::new(bin)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

async fn cli(args: &[&str]) -> (bool, String) {
    let out = openshell_cmd()
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A raw HTTP/1.1 exchange from inside the sandbox through bash's /dev/tcp,
/// so the request is exactly what the test states.
fn http(method: &str, port: u16, path: &str, extra: &str, body: &str) -> String {
    format!(
        r#"exec 3<>/dev/tcp/host.openshell.internal/{port}; printf "{method} {path} HTTP/1.1\r\nHost: host.openshell.internal:{port}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n%s" '{body}' >&3; timeout 15 cat <&3; exit 0"#,
        body.len()
    )
}

fn chat(port: u16) -> String {
    let body =
        r#"{"model":"tenzro/e2e","messages":[{"role":"user","content":"hi"}],"max_tokens":50}"#;
    http(
        "POST",
        port,
        "/v1/chat/completions",
        r"Authorization: Bearer ${TENZRO_AGENT_TOKEN}\r\n",
        body,
    )
}

fn status(out: &str) -> Option<u16> {
    out.lines()
        .find(|l| l.starts_with("HTTP/1."))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_openshell_sandbox_acts_under_tenzro_terms() {
    let work = PathBuf::from(env("TENZRO_E2E_WORK"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter("tenzro_openshell=debug")
        .try_init();
    // The middleware's TLS server, like any rustls host, runs on the process
    // provider; tenzro-node installs the same one.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let gateway_port = env("TENZRO_E2E_PORT");
    let health_port = env("TENZRO_E2E_HEALTH_PORT");
    let gateway_bin = env("OPENSHELL_GATEWAY_BIN");

    // The serving node's identity is this machine's TPM; the host is
    // verified by a TPM quote over a challenge naming that identity.
    let identity: Arc<dyn HybridSigner> = Arc::new(
        tenzro_device_key::signer::HardwareHybridSigner::open_or_create("tenzro-openshell-e2e")
            .expect("a TPM-held identity"),
    );
    let serving_key = identity.public_key().clone();
    let session = Arc::new(tenzro_crypto::batch::ImmediateRecordSigner::new(
        identity.clone(),
    ));
    let nonce = digest(b"e2e-nonce", &[uuid::Uuid::new_v4().as_bytes()]);
    let (_, host) =
        attestation::attest_local_tpm(identity.public_key(), &nonce).expect("TPM quote");
    println!("host binding: {}", host.binding);

    // Tenzro: a developer chain on a TPM of its own. Each of two roots bonds
    // and delegates an agent under Terms the node records on chain, served
    // by this node.
    let node = DevNode::start().await;
    println!("tenzro node {} machine {}", node.url, node.machine_did);
    let scope = serde_json::json!({
        "allowed_operations": ["sandbox", "sandbox.policy", "fetch", "inference", "pay"],
        "max_transaction_value": "500",
        "max_daily_spend": "100000",
        "allowed_payment_protocols": ["x402"],
        "allowed_models": ["tenzro/e2e"]
    });
    let (agent, root) = node
        .delegate("root-a", "openshell-e2e", scope.clone())
        .await;
    let (strangers_agent, _) = node.delegate("root-b", "openshell-e2e", scope).await;
    println!("agent {agent} of {root}");

    // Every decision is signed under the TPM identity and written where a
    // verifier reads it.
    let export = work.join("records");
    let records = Arc::new(
        RecordLog::new(session.clone(), Some(host.binding.clone()))
            .with_gateway(GATEWAY_ID)
            .with_node(node.machine_did.clone())
            .with_export_dir(&export)
            .unwrap(),
    );

    // The extensions read every delegation from the node, as its serving
    // host; principals and balances are this host's.
    let delegations = Arc::new(NodeDelegations::new(node.url.clone()).expect("node reader"));
    let authority = StateAuthority::over(node.machine_did.clone(), serving_key, 1337, delegations);
    authority.fund(StateAuthority::wallet(&agent), 100_000);
    authority.bind_principal("openshell-client", &root);
    let provider_payee = Address::new([0x7e; 32]);

    // The Tenzro inference provider and the outside paid service.
    let upstream_port = upstream().await;
    let provider = TenzroProvider::new(
        authority.clone(),
        identity.public_key().clone(),
        records.clone(),
        Arc::new(NodeRoute::new(format!("http://127.0.0.1:{upstream_port}"))),
        Pricing {
            per_unit: PER_UNIT,
            default_max_units: 100,
            payee: provider_payee,
        },
    );
    let (l, provider_port) = listen("0.0.0.0:0").await;
    tokio::spawn(async move { axum::serve(l, provider.router()).await.unwrap() });
    let payee_port = payee(&authority).await;

    // Who may call the extensions: tokens the gateway signs with its JWT
    // key, and over Unix sockets the gateway's own process.
    let pki = work.join("pki");
    let jwt = work.join("jwt");
    let gateway_key = Arc::new(
        GatewayKey::from_files(&jwt.join("public.pem"), Some(&jwt.join("kid")), GATEWAY_ID)
            .expect("the gateway's JWT key"),
    );
    let gateway_process = PeerRule::same_user(Some(Path::new(&gateway_bin))).unwrap();

    // The OpenShell extensions.
    let driver = TenzroCredentialDriver::new(
        authority.clone(),
        session.clone(),
        records.clone(),
        Duration::from_secs(120),
        "inference",
    )
    .with_store(Arc::new(
        tenzro_openshell::credential_driver::DeviceKeyStore(
            tenzro_device_key::open("tenzro-openshell-e2e/secrets")
                .or_else(|_| tenzro_device_key::create("tenzro-openshell-e2e/secrets"))
                .expect("a TPM wrapping key"),
        ),
    ));
    let cred_sock = work.join("tenzro-credentials.sock");
    let incoming = gateway_auth::unix_listener(&cred_sock).unwrap();
    let guard = Guard::peer(gateway_process.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(CredentialDriverServer::with_interceptor(driver, guard))
            .serve_with_incoming(incoming)
            .await
            .unwrap()
    });
    let icpt_sock = work.join("tenzro-interceptor.sock");
    let incoming = gateway_auth::unix_listener(&icpt_sock).unwrap();
    let interceptor = TenzroInterceptor::new(authority.clone(), records.clone())
        .with_audience(INTERCEPTOR_AUDIENCE);
    let guard = Guard::token(TokenRule::new(
        gateway_key.clone(),
        INTERCEPTOR_AUDIENCE,
        &[CallerKind::Gateway],
    ))
    .and_peer(gateway_process.clone());
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(GatewayInterceptorServer::with_interceptor(
                interceptor,
                guard,
            ))
            .serve_with_incoming(incoming)
            .await
            .unwrap()
    });
    let payer = Arc::new(Payer::new(
        authority.clone(),
        authority.clone(),
        authority.clone(),
        authority.clone(),
        identity.clone(),
        records.clone(),
    ));
    let middleware = TenzroMiddleware::new(authority.clone(), records.clone(), payer)
        .with_audience(MIDDLEWARE_AUDIENCE);
    let guard = Guard::token(TokenRule::new(
        gateway_key.clone(),
        MIDDLEWARE_AUDIENCE,
        &[CallerKind::Gateway, CallerKind::Supervisor],
    ));
    // The middleware is reached over TCP, so over TLS under its own CA.
    let ext_pki = work.join("ext-pki");
    let (ok, out) = run(
        &gateway_bin,
        &["generate-certs", "--output-dir", ext_pki.to_str().unwrap()],
    )
    .await;
    assert!(ok, "extension PKI: {out}");
    let tls =
        tonic::transport::ServerTlsConfig::new().identity(tonic::transport::Identity::from_pem(
            std::fs::read(ext_pki.join("server/tls.crt")).unwrap(),
            std::fs::read(ext_pki.join("server/tls.key")).unwrap(),
        ));
    let (l, mw_port) = listen("127.0.0.1:0").await;
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(l);
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(SupervisorMiddlewareServer::with_interceptor(
                middleware.clone(),
                guard.clone(),
            ))
            .add_service(HttpResponsePreReturnServer::with_interceptor(
                middleware, guard,
            ))
            .serve_with_incoming(incoming)
            .await
            .unwrap()
    });

    // The gateway, configured with the extensions.
    let s = |p: &Path| format!("{:?}", p.to_str().unwrap());
    let config = format!(
        r#"[openshell]
version = 2

[openshell.gateway]
log_level = "info"
guest_tls_ca = {ca}
credential_drivers = ["tenzro"]

[openshell.gateway.gateway_jwt]
signing_key_path = {sk}
public_key_path = {pk}
kid_path = {kid}
gateway_id = "{GATEWAY_ID}"

[openshell.gateway.mtls_auth]
enabled = true

[[openshell.gateway.interceptors]]
name = "tenzro"
grpc_endpoint = "unix://{icpt}"
audience = "{INTERCEPTOR_AUDIENCE}"
failure_policy = "fail_closed"
timeout = "2s"

[[openshell.supervisor.middleware]]
name = "tenzro"
grpc_endpoint = "https://127.0.0.1:{mw_port}"
tls_ca_cert_path = {ext_ca}
audience = "{MIDDLEWARE_AUDIENCE}"
max_payload_bytes = 262144
timeout = "5s"

[openshell.credential_drivers.tenzro]
transport = "uds"
socket_path = {cred}

[openshell.drivers.docker]
allow_driver_config = true
sandbox_label = "tenzro-e2e-{gateway_port}"
default_image = "{SANDBOX_IMAGE}"
image_pull_policy = "if_not_present"
sandbox_runtime_image = "{RUNTIME_IMAGE}"
supervisor_image = "{SUPERVISOR_IMAGE}"

[openshell.drivers.docker.resource_admission]
enabled = false
"#,
        ca = s(&pki.join("ca.crt")),
        sk = s(&jwt.join("signing.pem")),
        pk = s(&jwt.join("public.pem")),
        kid = s(&jwt.join("kid")),
        icpt = icpt_sock.display(),
        cred = s(&cred_sock),
        ext_ca = s(&ext_pki.join("ca.crt")),
    );
    let config_path = work.join("gateway.toml");
    write(&config_path, &config);
    let log = std::fs::File::create(work.join("gateway.log")).unwrap();
    let mut gateway = tokio::process::Command::new(&gateway_bin)
        .args(["--config", config_path.to_str().unwrap()])
        .args([
            "--bind-address",
            "127.0.0.1",
            "--port",
            &gateway_port,
            "--health-port",
            &health_port,
        ])
        .args(["--compute-driver", "docker"])
        .args(["--tls-cert", pki.join("server/tls.crt").to_str().unwrap()])
        .args(["--tls-key", pki.join("server/tls.key").to_str().unwrap()])
        .args(["--tls-client-ca", pki.join("ca.crt").to_str().unwrap()])
        .args([
            "--db-url",
            &format!("sqlite:{}?mode=rwc", work.join("gateway.db").display()),
        ])
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let health = format!("http://127.0.0.1:{health_port}/healthz");
    let client = reqwest::Client::new();
    let mut healthy = false;
    for _ in 0..60 {
        if let Some(status) = gateway.try_wait().unwrap() {
            panic!(
                "gateway exited {status}; see {}",
                work.join("gateway.log").display()
            );
        }
        if client
            .get(&health)
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            healthy = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(
        healthy,
        "gateway not healthy; see {}",
        work.join("gateway.log").display()
    );

    println!("step: 0. Unauthenticated calls");
    // 0. Nothing but the gateway and its supervisors gets an answer.
    unauthenticated::driver_refuses_another_process(&cred_sock).await;
    unauthenticated::interceptor_refuses_another_process(&icpt_sock).await;
    unauthenticated::middleware_refuses_without_the_gateways_token(
        mw_port,
        &std::fs::read(ext_pki.join("ca.crt")).unwrap(),
        MIDDLEWARE_AUDIENCE,
        GATEWAY_ID,
    )
    .await;

    // The Tenzro provider profile, copied from providers/tenzro.yaml and
    // pointed at this test's provider, and a provider for the agent.
    let profile = work.join("tenzro-e2e.yaml");
    write(
        &profile,
        &format!(
            "id: {PROFILE}\ndisplay_name: Tenzro (e2e)\ncategory: inference\ninference_capable: true\n\
             credentials:\n  - name: api_key\n    env_vars: [TENZRO_AGENT_TOKEN]\n    required: true\n    auth_style: bearer\n    header_name: authorization\n\
             endpoints:\n  - host: host.openshell.internal\n    port: {provider_port}\n    protocol: rest\n    access: read-write\n    enforcement: enforce\n\
             binaries: [/usr/bin/bash]\n"
        ),
    );
    let (ok, out) = cli(&["profile", "import", "--file", profile.to_str().unwrap()]).await;
    assert!(ok, "profile import: {out}");
    let (ok, out) = cli(&[
        "provider",
        "create",
        "--name",
        PROFILE,
        "--type",
        PROFILE,
        "--credential",
        "TENZRO_AGENT_TOKEN=sk-live-raw-key",
    ])
    .await;
    assert!(!ok, "a provider holding a raw key was accepted: {out}");
    let credential = format!("TENZRO_AGENT_TOKEN={agent}");
    let (ok, out) = cli(&[
        "provider",
        "create",
        "--name",
        PROFILE,
        "--type",
        PROFILE,
        "--credential",
        &credential,
    ])
    .await;
    assert!(ok, "provider create: {out}");

    let policy = work.join("policy.yaml");
    let policy_text = format!(
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/bin, /usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

network_policies:
  paid_service:
    name: paid_service
    endpoints:
      - host: host.openshell.internal
        port: {payee_port}
        path: /**
        protocol: rest
        access: full
        enforcement: enforce
    binaries:
      - path: /usr/bin/bash

network_middlewares:
  tenzro:
    middleware: tenzro
    endpoints:
      include: ["host.openshell.internal"]
"#
    );
    write(&policy, &policy_text);
    let label_for = |a: &str| format!("{AGENT_LABEL}={a}");
    let base_args = |label: &str| -> Vec<String> {
        vec![
            "--provider".into(),
            PROFILE.into(),
            "--annotation".into(),
            label.into(),
            "--policy".into(),
            policy.to_str().unwrap().into(),
            "--no-auto-providers".into(),
        ]
    };

    // 1. Only the delegating account's agent gets a sandbox.
    let (ok, out) = cli(&[
        "sandbox",
        "create",
        "--no-auto-providers",
        "--policy",
        policy.to_str().unwrap(),
        "--",
        "true",
    ])
    .await;
    assert!(!ok, "a sandbox naming no agent was created: {out}");
    let stranger: Vec<String> = base_args(&label_for(&strangers_agent));
    let mut args: Vec<&str> = vec!["sandbox", "create"];
    args.extend(stranger.iter().map(String::as_str));
    args.extend(["--", "true"]);
    let (ok, out) = cli(&args).await;
    assert!(
        !ok,
        "a sandbox for another account's agent was created: {out}"
    );
    assert!(out.contains("not delegated"), "{out}");

    let mine = base_args(&label_for(&agent));
    let mine: Vec<&str> = mine.iter().map(String::as_str).collect();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &mine,
        &["bash", "-c", "echo tenzro-ready; sleep 900"],
        "tenzro-ready",
    )
    .await
    .expect("sandbox for the delegated agent");
    let name = sandbox.name.clone();
    println!("sandbox {name}");
    let (_, out) = cli(&["sandbox", "get", &name, "-o", "json"]).await;
    assert!(
        out.contains(HOST_ANNOTATION) && out.contains(&host.binding),
        "sandbox not annotated with the host: {out}"
    );

    println!("step: 2. The sandbox holds");
    // 2. The sandbox holds no credential; Tenzro inference settles per unit.
    let env_out = sandbox
        .exec(&["bash", "-c", "printenv TENZRO_AGENT_TOKEN"])
        .await
        .unwrap();
    assert!(
        !env_out.contains("tzs1.") && !env_out.contains(&agent),
        "the sandbox sees the credential: {env_out}"
    );
    let wallet = StateAuthority::wallet(&agent);
    let before = authority.balance(&wallet);
    let out = sandbox
        .exec(&["bash", "-c", &chat(provider_port)])
        .await
        .unwrap();
    assert_eq!(status(&out), Some(200), "inference: {out}");
    assert!(
        out.to_ascii_lowercase().contains(RECEIPT_HEADER),
        "no receipt: {out}"
    );
    assert!(out.contains("from tenzro"));
    assert_eq!(
        authority.balance(&wallet),
        before - PER_UNIT * UNITS as u128
    );
    assert_eq!(authority.balance(&provider_payee), PER_UNIT * UNITS as u128);

    println!("step: 3. A 402 inside");
    // 3. A 402 inside the cap is paid on the retry; one over it is refused.
    let before = authority.balance(&wallet);
    let get_report = http("GET", payee_port, "/report", "", "");
    let first = sandbox.exec(&["bash", "-c", &get_report]).await.unwrap();
    assert_eq!(status(&first), Some(402), "{first}");
    assert!(
        first
            .to_ascii_lowercase()
            .contains(&format!("{PAYMENT_HEADER}: authorized")),
        "{first}"
    );
    let retry = sandbox.exec(&["bash", "-c", &get_report]).await.unwrap();
    assert_eq!(status(&retry), Some(200), "paid retry: {retry}");
    assert!(retry.contains("paid report"));
    assert_eq!(authority.balance(&wallet), before - 300);
    let dear = sandbox
        .exec(&["bash", "-c", &http("GET", payee_port, "/dear", "", "")])
        .await
        .unwrap();
    assert_eq!(status(&dear), Some(402), "{dear}");
    assert!(
        dear.contains("refused") && dear.contains("per-transaction"),
        "{dear}"
    );
    assert_eq!(authority.balance(&wallet), before - 300);

    println!("step: A policy change by");
    // A policy change by the delegating account passes.
    let (ok, out) = cli(&["policy", "set", &name, "--policy", policy.to_str().unwrap()]).await;
    assert!(ok, "policy change before revocation: {out}");

    println!("step: 4. Revocation on");
    // 4. Revocation on Tenzro stops it.
    node.revoke_root("root-a", "kill switch").await;
    node.agent_status(&agent, "revoked").await;
    let before = authority.balance(&wallet);
    let out = sandbox
        .exec(&["bash", "-c", &chat(provider_port)])
        .await
        .unwrap_or_else(|e| e);
    assert_ne!(status(&out), Some(200), "inference after revocation: {out}");
    let out = sandbox
        .exec(&["bash", "-c", &get_report])
        .await
        .unwrap_or_else(|e| e);
    assert_ne!(
        status(&out),
        Some(200),
        "paid egress after revocation: {out}"
    );
    assert_eq!(authority.balance(&wallet), before);
    let (ok, out) = cli(&["policy", "set", &name, "--policy", policy.to_str().unwrap()]).await;
    assert!(!ok, "policy change after revocation: {out}");
    assert!(out.contains("revoked"), "{out}");

    println!("step: 5. Every decision");
    // 5. Every decision is a record signed under the TPM identity.
    // As a verifier reads them: the exported files and the identity beside
    // them, checked against the TPM identity this test holds.
    let exported = |session: &str| -> Vec<tenzro_types::agent_audit::SignedAuditEntry> {
        let id = RecordLog::session_id_on(GATEWAY_ID, session);
        std::fs::read_to_string(export.join(format!("{}.jsonl", hex::encode(id))))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    };
    let named: tenzro_crypto::composite::CompositePublicKey =
        serde_json::from_str(&std::fs::read_to_string(export.join("identity.json")).unwrap())
            .unwrap();
    assert_eq!(
        &named,
        identity.public_key(),
        "the export names the TPM identity"
    );
    assert_eq!(exported(&name).len(), records.entries(&name).len());
    let entries = verify_session(&named, &exported(&name)).expect("sandbox records");
    let agent_entries = verify_session(&named, &exported(&agent)).expect("agent records");
    assert!(
        entries
            .iter()
            .chain(&agent_entries)
            .all(|e| e.image.as_deref() == Some(host.binding.as_str()))
    );
    let count = |kind: ActionKind, allowed: bool| {
        entries
            .iter()
            .chain(&agent_entries)
            .filter(|e| e.kind == kind && matches!(e.outcome, ActionOutcome::Allowed) == allowed)
            .count()
    };
    println!(
        "records: sandbox {} agent {}; egress {}/{} refused, spend {}/{} refused, model {}/{} refused, grant {}/{} refused",
        entries.len(),
        agent_entries.len(),
        count(ActionKind::Egress, true),
        count(ActionKind::Egress, false),
        count(ActionKind::Spend, true),
        count(ActionKind::Spend, false),
        count(ActionKind::ModelCall, true),
        count(ActionKind::ModelCall, false),
        count(ActionKind::GrantUse, true),
        count(ActionKind::GrantUse, false),
    );
    assert!(
        count(ActionKind::GrantUse, true) >= 2,
        "sandbox creation and policy change"
    );
    assert!(count(ActionKind::Egress, true) >= 4);
    let revoked = entries
        .iter()
        .chain(&agent_entries)
        .filter(|e| {
            e.kind == ActionKind::GrantUse
                && e.outcome == ActionOutcome::Refused("agent revoked".into())
        })
        .count();
    assert!(
        revoked >= 2,
        "refusals after revocation are recorded as agent revoked"
    );
    assert_eq!(count(ActionKind::Spend, true), 1, "the settled payment");
    assert!(
        count(ActionKind::Spend, false) >= 1,
        "the payment over the cap"
    );
    assert!(count(ActionKind::ModelCall, true) >= 1);
    let paid = entries
        .iter()
        .find(|e| e.kind == ActionKind::Spend && matches!(e.outcome, ActionOutcome::Allowed))
        .unwrap();
    assert!(paid.linked_tx.is_some(), "the payment links to its receipt");

    sandbox.cleanup().await;
    let _ = cli(&["provider", "delete", PROFILE]).await;
    gateway.kill().await.ok();
    node.stop().await;
}
