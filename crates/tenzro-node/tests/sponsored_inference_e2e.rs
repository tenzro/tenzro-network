//! A caller with no key, no account and no TNZO completes a paid inference
//! through a sponsoring app, end to end on a live node.
//!
//! The app pays from its own funds: its account moves TNZO into the wallet of
//! a delegated agent it controls, and the agent's terms on chain (the grant)
//! name this node as a serving node, the model it pays for and its caps. The
//! caller sends `tenzro_sponsoredInference` over plain HTTP with nothing but
//! the prompt and the sponsor's DID. The node checks the call against the
//! grant, serves it from a real model, and pays its operator out of the
//! agent's wallet with an `AgentAct` signed by the key this machine's TPM
//! holds for the agent. The node submits that payment and pays its network
//! fee from its own ledger account, as it does on every paid route.
//!
//! What is asserted:
//!
//! - the sponsor wallet pays exactly the call's cost, and the operator's
//!   payee receives it net of the governed settlement fee, on chain;
//! - the payment record names the agent, the payee and the cost, and binds
//!   the model, the prompt and the output the caller received, so the paid
//!   work is the work that was served;
//! - the caller is charged nothing and no account of its own exists;
//! - a call outside the grant (a model it does not cover) is refused before
//!   anything is served or paid, and the sponsor wallet does not move.
//!
//! Ignored by default: it needs this machine's hardware consensus key (TPM 2.0
//! or Secure Enclave) and downloads a model it runs on CPU. Run with
//! `--ignored`; `TENZRO_LIVE_MODEL` picks the catalog id (default
//! `qwen3-0.6b`) and `TENZRO_MODELS_DIR` where it is stored.
//!
//! The binary has its own `main` (no test harness) because the node parses a
//! model file in a child process started from the current executable, which
//! must enter the parser before anything else runs.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_consensus::ConsensusConfig;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner, SignatureContext};
use tenzro_model::hf_download::{DownloadProgress, DownloadState, HfDownloader, SourcePolicy};
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::primitives::{Address, ChainId, Nonce};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
use tenzro_types::{NetworkRole, RoleSet};
use tokio::sync::broadcast;

const CHAIN_ID: u64 = 1337;
const ONE_TNZO: u128 = 1_000_000_000_000_000_000;
/// Open-lane fee floor: four times the genesis base fee.
const GAS_PRICE: u64 = 40_000_000_000;
/// The sponsoring app's delegated agent.
const SPONSOR: &str = "did:tenzro:machine:5f1d2c3b-8a4e-4c6f-9d2a-7e3b1c0a9f42";
/// The app's own identity, the agent's controller.
const APP: &str = "did:tenzro:human:0b7e4a2d-3c1f-4e9a-8b6d-2f5a1c7e9d30";
/// The node operator's identity; its wallet is the payee.
const OPERATOR: &str = "did:tenzro:human:9e2c6b1a-7d4f-4a3e-b5c8-1d0f2e3a4b5c";
/// A model this node serves and sponsors, but the grant does not cover.
const UNCOVERED: &str = "sponsored-e2e-uncovered";
/// Wei per token on the operator's rate card.
const PER_TOKEN: u128 = 1_000_000_000_000;
/// The grant's per-payment and daily caps, micro-units of account.
const PER_PAYMENT_E6: u128 = 1_000_000;
const DAILY_E6: u128 = 5_000_000;

fn models_dir() -> PathBuf {
    std::env::var("TENZRO_MODELS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("tenzro-live-models"))
}

fn operator_payee() -> Address {
    let mut b = [0u8; 32];
    b[..20].copy_from_slice(&[0x5a; 20]);
    Address::new(b)
}

fn sponsor_wallet() -> Address {
    Address::new(tenzro_types::agent_terms::agent_wallet(SPONSOR))
}

fn state_of(node: &TenzroNode) -> tenzro_vm::StateAdapter {
    tenzro_vm::StateAdapter::with_storage(node.storage().expect("storage").clone())
}

fn balance(node: &TenzroNode, a: &Address) -> u128 {
    use tenzro_vm::traits::VmState as _;
    state_of(node).get_balance(a.as_bytes())
}

fn fund(node: &TenzroNode, a: &Address, amount: u128) {
    use tenzro_vm::traits::VmState as _;
    let mut state = state_of(node);
    let before = state.get_balance(a.as_bytes());
    state.set_balance(a.as_bytes(), before + amount);
    state.commit().expect("commit funded balance");
}

/// The node's own ledger account: the transactions it submits pay their
/// network fee from here.
fn ledger_account(node: &TenzroNode) -> Address {
    Address::new(
        node.identity_signer()
            .expect("validator signer")
            .public_key()
            .account_slot(),
    )
}

/// The digest `tenzro_sponsoredInference` binds its payment to.
fn request_digest(model: &str, input: &str, output: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/sponsored-inference");
    for part in [model, input, output] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    h.finalize().into()
}

async fn executed(node: &TenzroNode, tx_hash: &str) -> bool {
    use tenzro_storage::KvStore as _;
    let storage = node.storage().expect("storage").clone();
    let key = format!("receipt:{tx_hash}");
    for _ in 0..600 {
        if let Ok(Some(bytes)) = storage.get(tenzro_storage::CF_TRANSACTIONS, key.as_bytes()) {
            let v: Value = serde_json::from_slice(&bytes).expect("receipt json");
            return v["success"].as_bool().unwrap_or(false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("transaction {tx_hash} did not execute within 60s");
}

fn rate_card() -> tenzro_types::price_card::RateCard {
    use tenzro_types::price_card::{Denom, Rate, RateCard};
    RateCard {
        denom: Denom::Wei,
        lines: [
            ("input_tokens".to_string(), Rate::per(PER_TOKEN, 0)),
            ("output_tokens".to_string(), Rate::per(PER_TOKEN, 0)),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    }
}

async fn sponsored_call(base_url: &str, model: &str, input: &str) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_sponsoredInference",
        "params": [{ "model": model, "input": input, "sponsor": SPONSOR, "max_tokens": 16 }],
    });
    // No key, no signature, no account, no token: only the request.
    reqwest::Client::new()
        .post(base_url)
        .json(&body)
        .send()
        .await
        .expect("the node answers")
        .json()
        .await
        .expect("a JSON-RPC reply")
}

const NAME: &str = "a_caller_with_no_tnzo_completes_a_paid_inference_through_a_sponsoring_app";

fn main() {
    tenzro_model::parse_jail::enter_if_requested();
    if !std::env::args().any(|a| a == "--ignored" || a == "--include-ignored") {
        println!(
            "test {NAME} ... ignored, needs this machine's hardware consensus key (TPM 2.0 or \
             Secure Enclave) and downloads a model; run with --ignored"
        );
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime")
        .block_on(a_caller_with_no_tnzo_completes_a_paid_inference_through_a_sponsoring_app());
    println!("test {NAME} ... ok");
}

async fn a_caller_with_no_tnzo_completes_a_paid_inference_through_a_sponsoring_app() {
    use tenzro_vm::traits::VmState as _;
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    tenzro_catalog::install_test_seed();
    let model_id = std::env::var("TENZRO_LIVE_MODEL").unwrap_or_else(|_| "qwen3-0.6b".into());
    let entry = tenzro_model::catalog::get_model_by_id(&model_id).expect("catalog entry");
    let dir = models_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: model_id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: 0,
    });
    let downloader = HfDownloader::new(dir.clone());
    let path = if downloader.is_downloaded(&model_id) {
        downloader.model_path(&model_id)
    } else {
        downloader
            .download_model(&entry, None, SourcePolicy::HuggingFace, tx)
            .await
            .expect("pinned download")
    };

    // A solo validator that also serves models and offers sponsored calls
    // for the app's agent.
    let tmp = tempfile::tempdir().expect("temp dir");
    let validator =
        tenzro_node::config::GenesisValidator::from_local_hardware(tmp.path(), 1_000_000)
            .expect("a hardware consensus key");
    // The model-serving role is bonded at genesis from the operator account.
    let ai_bond = tenzro_node::config::GenesisRoleStake {
        address: validator.address.clone(),
        role: "ai".to_string(),
        stake: None,
        capacity: Default::default(),
        endpoint: None,
    };
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        models_dir: Some(dir.clone()),
        roles: RoleSet::from_roles([NetworkRole::Validator, NetworkRole::ModelProvider]),
        consensus: Some(ConsensusConfig::default()),
        operator_did: Some(OPERATOR.to_string()),
        iroh: tenzro_iroh::TenzroIrohConfig {
            bind_addr: (std::net::Ipv4Addr::LOCALHOST, 0).into(),
            port_mapping: false,
            ..Default::default()
        },
        genesis: Some(tenzro_node::config::GenesisConfig {
            version: tenzro_node::config::GENESIS_SCHEMA_VERSION,
            chain_id: CHAIN_ID,
            timestamp: 0,
            validators: vec![validator],
            accounts: Vec::new(),
            weak_subjectivity: None,
            time: tenzro_consensus::TimeRules::default(),
            network_params: Default::default(),
            economy: Default::default(),
            role_stakes: vec![ai_bond],
        }),
        sponsored_inference: Some(tenzro_node::config::SponsoredInferenceConfig {
            sponsor: SPONSOR.to_string(),
            models: vec![model_id.clone(), UNCOVERED.to_string()],
            max_tokens: 16,
            per_source_per_minute: 60,
            global_per_minute: 60,
            daily_budget: 10 * ONE_TNZO,
        }),
        ..Default::default()
    };
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);
    let runtime = node.model_runtime.clone().expect("a model runtime");
    runtime.load_model(&model_id, &path).await.expect("load");
    for m in [model_id.as_str(), UNCOVERED] {
        node.served_models
            .insert(m.to_string(), Some(tenzro_types::Visibility::Public));
        node.provider_pricing
            .write()
            .models
            .insert(m.to_string(), rate_card());
    }
    let (shutdown, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();
    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let server =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });
    let base_url = format!("http://{}", addr_rx.await.expect("bound address"));
    // The node pays the network fee of the payments it submits.
    fund(&node, &ledger_account(&node), ONE_TNZO);

    // The operator's identity, whose wallet is the payee.
    let registry = node.identity_registry().expect("identity registry");
    registry.upsert_identity_for_test(tenzro_identity::TenzroIdentity {
        did: tenzro_identity::TenzroDid::parse(OPERATOR).expect("operator DID"),
        public_keys: Vec::new(),
        identity_data: tenzro_identity::IdentityData::Human {
            display_name: "Operator".into(),
            controlled_machines: Vec::new(),
        },
        status: tenzro_identity::IdentityStatus::Active,
        wallet_address: operator_payee(),
        wallet_id: String::new(),
        pq_verifying_key: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        metadata: Default::default(),
    });
    assert_eq!(node.operator_payee(), Some(operator_payee()));

    // The key this machine's TPM holds for the agent, certified by the TPM,
    // as the node answers an agent-key request at onboarding.
    let serving = tokio::task::spawn_blocking(|| {
        tenzro_node::agent_delegation::answer_key_request(
            Some(OPERATOR),
            None,
            &tenzro_node::agent_delegation::AgentKeyRequest {
                agent_did: SPONSOR.to_string(),
                controller_did: APP.to_string(),
                agent_name: "sponsor".to_string(),
            },
        )
    })
    .await
    .expect("join")
    .expect("this machine's key for the agent");

    // The grant: the app's terms for its agent, naming this node, the one
    // model it pays for and the caps, with the bond those caps need.
    {
        use tenzro_types::agent_terms::{AgentTerms, OP_PAY, RootKind, TermsScope};
        let terms = AgentTerms {
            controller_did: APP.to_string(),
            agent_name: "sponsor".into(),
            delegation_scope: TermsScope {
                max_transaction_value: Some(PER_PAYMENT_E6.to_string()),
                max_daily_spend: Some(DAILY_E6.to_string()),
                allowed_operations: vec![OP_PAY.into()],
                allowed_models: vec![model_id.clone()],
                ..Default::default()
            },
            capabilities: Vec::new(),
            serving_nodes: vec![serving],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        let mut state = state_of(&node);
        let ceiling = tenzro_vm::native::economy::agent_spend_ceiling(&terms)
            .expect("the terms have a spend ceiling");
        let spend = tenzro_vm::native::economy::usd_to_wei(&state, ceiling * 1_000_000_000_000);
        let bond = tenzro_vm::native::economy::required_agent_bond(&state, spend);
        let stored = tenzro_vm::native::StoredAgentTerms {
            terms,
            root: RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: chrono::Utc::now().timestamp_millis(),
            renewed_at_ms: None,
        };
        state.set_storage(
            &tenzro_vm::native::SYSTEM_ADDRESS,
            tenzro_vm::native::agent_terms::terms_key(SPONSOR).as_bytes(),
            serde_json::to_vec(&stored).expect("terms json"),
        );
        state.set_balance(
            tenzro_token::derive_bond_vault_address(SPONSOR).as_bytes(),
            bond.max(1),
        );
        state.commit().expect("commit terms");
    }

    // The app funds its sponsor wallet from its own account, on chain.
    let app = TestHybridSigner::random();
    fund(&node, &app.address(), 2 * ONE_TNZO);
    let funding = Transaction::new(
        ChainId::from(CHAIN_ID),
        app.address(),
        sponsor_wallet(),
        Nonce::from(0),
        TransactionType::Transfer { amount: ONE_TNZO },
        2_000_000,
        GAS_PRICE,
    );
    let hash = funding.hash();
    let sig = app
        .sign(SignatureContext::Transaction, hash.as_bytes())
        .expect("sign");
    node.consensus()
        .expect("consensus")
        .submit_transaction(SignedTransaction::new(
            funding,
            app.public_key().p256.clone(),
            sig,
        ))
        .expect("admitted");
    assert!(
        executed(&node, &hash.to_string()).await,
        "the app funds its sponsor wallet"
    );
    assert_eq!(balance(&node, &sponsor_wallet()), ONE_TNZO);

    // The caller: a fresh account that holds nothing and never signs.
    let caller = TestHybridSigner::random().address();
    let caller_nonce = || state_of(&node).get_nonce(caller.as_bytes());
    assert_eq!(balance(&node, &caller), 0);

    let wallet_before = balance(&node, &sponsor_wallet());
    let payee_before = balance(&node, &operator_payee());
    let input = "Name one primary colour.";
    let reply = sponsored_call(&base_url, &model_id, input).await;
    assert!(reply["error"].is_null(), "sponsored call refused: {reply}");
    let result = &reply["result"];
    let output = result["output"].as_str().expect("output").to_string();
    assert!(!output.is_empty(), "the model served nothing: {result}");
    let cost: u128 = result["cost"]
        .as_str()
        .expect("cost")
        .parse()
        .expect("cost");
    assert!(cost > 0, "a paid call costs something: {result}");
    assert_eq!(result["sponsor"], SPONSOR);
    assert_eq!(
        result["provider"],
        format!("0x{}", hex::encode(operator_payee().as_bytes()))
    );
    let tx_hash = result["tx_hash"].as_str().expect("tx_hash");
    assert!(
        executed(&node, tx_hash).await,
        "the sponsor's payment executes: {result}"
    );

    // The paid work on chain: the agent paid the operator the cost, bound to
    // what was served.
    let pay_ref: [u8; 32] = hex::decode(result["pay_ref"].as_str().expect("pay_ref"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let record = tenzro_vm::native::read_payment(&state_of(&node), &pay_ref)
        .expect("a payment record on chain");
    assert_eq!(record.amount, cost);
    assert_eq!(record.payee, operator_payee());
    assert_eq!(record.payer, hex::encode(sponsor_wallet().as_bytes()));
    assert_eq!(record.agent_did.as_deref(), Some(SPONSOR));
    assert_eq!(
        record.binding.request_digest,
        request_digest(&model_id, input, &output),
        "the payment binds the model, the prompt and the output the caller received"
    );

    // The app paid exactly the cost; the operator received it net of the
    // governed settlement fee; the caller paid nothing and has no account.
    assert_eq!(wallet_before - balance(&node, &sponsor_wallet()), cost);
    assert_eq!(
        balance(&node, &operator_payee()) - payee_before,
        cost - record.fee
    );
    assert_eq!(balance(&node, &caller), 0);
    assert_eq!(caller_nonce(), 0);

    // Outside the grant: refused before anything is served or paid.
    let wallet_before = balance(&node, &sponsor_wallet());
    let refused = sponsored_call(&base_url, UNCOVERED, input).await;
    let message = refused["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("outside the sponsor's grant"),
        "a model the grant does not cover is refused: {refused}"
    );
    assert_eq!(balance(&node, &sponsor_wallet()), wallet_before);

    let _ = shutdown.send(());
    let _ = server.await;
}
