//! Integration tests for the AgentKit ↔ NodeAuthIssuer seam.
//!
//! These tests spin up a full in-process [`TenzroNode`] (storage, RPC,
//! AuthEngine, IdentityRegistry, AgentRuntime), wire a fresh `AgentKit`
//! around the node's shared subsystems plus a [`NodeAuthIssuer`] adapter,
//! publish the bundled reference template manifests to the in-process
//! registry, then exercise the full spawn → DPoP credential mint → run
//! pipeline for two cross-VM templates:
//!
//!   * `ref-solana-jupiter-swap-v1`  — `MultiVm` backend, SVM dispatch.
//!   * `ref-cross-chain-liquidity-aggregator-v1` — `Bridge` backend, mixed
//!     ToolInvoke + When/SvmDispatch + When/BridgeTransfer steps.
//!
//! Per the standing directive *"yes and no shortcuts — implement all in
//! full"*: there is no mocking of the executor, the spawner, the registry,
//! the identity registry, or the agent runtime. Every test drives a real
//! `AgentKit::spawn()` through real RPCs against a real RocksDB-backed
//! node, asserts the spawned agent carries a DPoP-bound credential
//! (`jkt` non-empty, `jwt` parses), and asserts that
//! `RunOptions::dry_run()` walks each template step through the full
//! delegation + predicate gating logic without making outbound calls.
//!
//! Per `feedback_implement_dont_delete`: every assertion in these tests
//! is wired to a real call site; nothing is suppressed or stubbed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use tenzro_agent_kit::{
    AgentKit, AgentKitError, RegistryClient, RunOptions, SpawnArgs, SpawnedAgent,
    bootstrap_reference_templates,
};
use tenzro_node::agent_kit_auth::NodeAuthIssuer;
use tenzro_node::{NodeConfig, RpcServer, TenzroNode};
use tenzro_types::identity::KycTier;

const TEMPLATE_SOLANA_JUPITER_SWAP: &str = "ref-solana-jupiter-swap-v1";
const TEMPLATE_CROSS_CHAIN_LIQUIDITY: &str = "ref-cross-chain-liquidity-aggregator-v1";

// ---------------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------------

fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let mut cfg = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..Default::default()
    };
    // Register the `oneinch-aggregator` skill. Built-in skills are registered
    // conditionally on what the node can actually serve, and this one is gated
    // on `builtins.oneinch_api_key` — without it the row is never inserted and
    // the `ref-cross-chain-liquidity-aggregator-v1` template fails to spawn
    // with `UnresolvedSkillTag("oneinch-aggregator")`. The value is never
    // dialled in these tests; its presence is what registers the skill.
    cfg.builtins.oneinch_api_key = Some("test-oneinch-key".to_string());
    (cfg, tmp)
}

/// Spins up an in-process node + RPC server on a random loopback port.
/// Returns the bound base URL, a shutdown sender, the RPC server's join
/// handle, the `TempDir` keeping the RocksDB instance alive, and the
/// shared `Arc<TenzroNode>` so callers can reach into the identity
/// registry, agent runtime, and auth engine.
async fn setup_test_server() -> (
    String,
    broadcast::Sender<()>,
    tokio::task::JoinHandle<tenzro_node::Result<()>>,
    tempfile::TempDir,
    Arc<TenzroNode>,
) {
    let (cfg, tmp) = test_config();
    let mut node = TenzroNode::new(cfg).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
    let (addr_tx, addr_rx) = tokio::sync::oneshot::channel();

    let rpc = RpcServer::new(node.clone(), "127.0.0.1:0".to_string());
    let handle =
        tokio::spawn(async move { rpc.start_with_shutdown_and_addr(shutdown_rx, addr_tx).await });

    let addr = addr_rx.await.expect("bound address");
    let base_url = format!("http://{}", addr);

    (base_url, shutdown_tx, handle, tmp, node)
}

async fn shutdown(
    tx: broadcast::Sender<()>,
    handle: tokio::task::JoinHandle<tenzro_node::Result<()>>,
) {
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
}

/// Builds an `AgentKit` pointed at the *actual* bound RPC URL, sharing
/// the node's identity registry + agent runtime + a fresh
/// `NodeAuthIssuer` over the node's `AuthEngine`.
///
/// We do not reuse `node.agent_kit()` because the node's own kit is
/// constructed against `config.rpc_addr` (default `127.0.0.1:8545`)
/// rather than the random port the test's `RpcServer` binds to — every
/// in-process spawn would hit a connection-refused error. Building a
/// fresh kit with the same wired-in dependencies gives us the full
/// authenticated path without the address mismatch.
fn build_kit_for(node: &Arc<TenzroNode>, base_url: &str) -> AgentKit {
    let identity_registry = node
        .identity_registry()
        .expect("node identity registry")
        .clone();
    let agent_runtime = node.agent_runtime().expect("node agent runtime").clone();
    let auth_engine = node
        .auth_engine()
        .expect("node auth engine (default config wires AuthEngine)")
        .clone();
    let issuer: Arc<dyn tenzro_agent_kit::AuthIssuer> = Arc::new(NodeAuthIssuer::new(auth_engine));
    AgentKit::with_auth_issuer(base_url, identity_registry, agent_runtime, issuer)
}

/// Publishes the bundled reference templates to the in-process registry
/// via the kit's own `RegistryClient`. This is the same call path the
/// node's deferred bootstrap takes, just driven explicitly so the test
/// doesn't race against the deferred TCP-probe loop in
/// `bootstrap_agent_templates()`.
async fn bootstrap_templates(base_url: &str) {
    let registry = Arc::new(RegistryClient::new(base_url.to_string()));
    let report = bootstrap_reference_templates(&registry)
        .await
        .expect("bootstrap reference templates");
    // `published + skipped` should cover every bundled manifest; `failed`
    // must be empty — any failure here would mean the registry RPC
    // surface diverged from the bundled manifest schema.
    assert!(
        report.failed.is_empty(),
        "template bootstrap had failures: {:?}",
        report.failed
    );
    assert!(
        report.published.len() + report.skipped.len() >= 18,
        "expected at least 18 bundled templates, saw published={} skipped={}",
        report.published.len(),
        report.skipped.len()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_node_auth_engine_and_agent_kit_wired() {
    let (_base_url, tx, handle, _tmp, node) = setup_test_server().await;

    // Default `NodeConfig` is expected to wire AuthEngine, IdentityRegistry,
    // and AgentRuntime — any of these missing would mean a regression in
    // node init that breaks the entire AgentKit seam.
    assert!(
        node.auth_engine().is_some(),
        "default config should wire AuthEngine"
    );
    assert!(
        node.identity_registry().is_some(),
        "default config should wire IdentityRegistry"
    );
    assert!(
        node.agent_runtime().is_some(),
        "default config should wire AgentRuntime"
    );
    assert!(
        node.agent_kit().is_some(),
        "default config should wire AgentKit"
    );

    // The IdentityRegistry must have a WalletBinder — the spawner refuses
    // to provision identities against a registry without one (it would
    // produce un-signable placeholder addresses).
    let ir = node.identity_registry().unwrap();
    assert!(
        ir.has_wallet_binder(),
        "IdentityRegistry must carry a WalletBinder for spawn() to work"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_spawn_solana_jupiter_swap_mints_dpop_credentials() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    bootstrap_templates(&base_url).await;

    let kit = build_kit_for(&node, &base_url);

    let args = SpawnArgs {
        controller_display_name: "Solana Swap Test Controller".to_string(),
        kyc_tier: KycTier::Basic, // template requires Basic
        context: HashMap::new(),
        parent_machine_did: None,
    };

    let spawned: SpawnedAgent = kit
        .spawn(TEMPLATE_SOLANA_JUPITER_SWAP, args)
        .await
        .expect("spawn ref-solana-jupiter-swap-v1");

    // Identity provisioning sanity.
    let machine_did = spawned.machine_did();
    let controller_did = spawned.controller_did();
    assert!(
        machine_did.starts_with("did:tenzro:machine:"),
        "machine DID must follow TDIP format, got {}",
        machine_did
    );
    assert!(
        controller_did.starts_with("did:tenzro:human:"),
        "controller DID must follow TDIP format, got {}",
        controller_did
    );

    // Template fetched + execution_spec attached.
    assert_eq!(spawned.template.template_id, TEMPLATE_SOLANA_JUPITER_SWAP);
    assert!(spawned.template.execution_spec.is_some());

    // MultiVm backend → no Canton party allocation.
    assert!(
        spawned.canton_party_id.is_none(),
        "MultiVm-backed template should not allocate a Canton party"
    );

    // DPoP-bound credentials must be present and well-formed.
    let creds = spawned
        .credentials
        .as_ref()
        .expect("NodeAuthIssuer must mint credentials at spawn time");
    assert!(!creds.jwt.is_empty(), "JWT must be non-empty");
    assert!(
        creds.jwt.chars().filter(|c| *c == '.').count() == 2,
        "JWT must be compact JWS (3 segments), got {}",
        creds.jwt
    );
    assert!(!creds.jkt.is_empty(), "DPoP jkt must be non-empty");
    // jkt is base64url(SHA-256(canonical_jwk)) = 43 chars unpadded.
    assert_eq!(
        creds.jkt.len(),
        43,
        "DPoP jkt must be 43 base64url chars (32-byte SHA-256), got {}",
        creds.jkt
    );
    assert!(
        creds.expires_at_unix
            > std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        "credential expiry must be in the future"
    );

    // The DPoP signer must produce a parseable proof for an arbitrary
    // (htm, htu) — proves the trait object is wired through to the signer.
    let proof = creds
        .dpop
        .sign_proof("POST", &format!("{}/", base_url), &creds.jwt)
        .await
        .expect("dpop sign_proof");
    assert!(
        proof.chars().filter(|c| *c == '.').count() == 2,
        "DPoP proof must be compact JWS"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_spawn_with_insufficient_kyc_tier_is_rejected() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    bootstrap_templates(&base_url).await;

    let kit = build_kit_for(&node, &base_url);

    // `ref-cross-chain-liquidity-aggregator-v1` requires KycTier::Enhanced.
    let args = SpawnArgs {
        controller_display_name: "Underqualified Controller".to_string(),
        kyc_tier: KycTier::Basic, // below Enhanced
        context: HashMap::new(),
        parent_machine_did: None,
    };

    let err = kit
        .spawn(TEMPLATE_CROSS_CHAIN_LIQUIDITY, args)
        .await
        .expect_err("spawn should reject sub-tier controller");

    match err {
        AgentKitError::DelegationRejected(msg) => {
            assert!(
                msg.contains("kyc"),
                "rejection should mention kyc tier, got {}",
                msg
            );
        }
        other => panic!("expected DelegationRejected, got {:?}", other),
    }

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_dry_run_walks_solana_jupiter_swap_steps() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    bootstrap_templates(&base_url).await;

    let kit = build_kit_for(&node, &base_url);

    let mut context = HashMap::new();
    context.insert(
        "input_mint".to_string(),
        "So11111111111111111111111111111111111111112".to_string(),
    );
    context.insert(
        "output_mint".to_string(),
        "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string(),
    );
    context.insert("amount".to_string(), "1000000000".to_string());
    context.insert("slippage_bps".to_string(), "50".to_string());

    let spawned = kit
        .spawn(
            TEMPLATE_SOLANA_JUPITER_SWAP,
            SpawnArgs {
                controller_display_name: "Dry Run Solana Controller".to_string(),
                kyc_tier: KycTier::Basic,
                context,
                parent_machine_did: None,
            },
        )
        .await
        .expect("spawn ref-solana-jupiter-swap-v1");

    let report = kit
        .run(&spawned, RunOptions::dry_run())
        .await
        .expect("dry-run executor.run");

    // The template has exactly 2 top-level steps: ToolInvoke + When(SvmDispatch).
    assert_eq!(
        report.total_steps(),
        2,
        "ref-solana-jupiter-swap-v1 has 2 top-level steps, walked: {:?}",
        report
            .step_results
            .iter()
            .map(|r| (r.step_kind.clone(), r.status.clone()))
            .collect::<Vec<_>>()
    );

    // Dry-run must never count anything as Executed or Failed — every
    // step either short-circuits at the dry-run gate, gets skipped by
    // delegation/predicate, or gets skipped by hard caps.
    assert_eq!(
        report.steps_executed, 0,
        "dry-run must not execute any step"
    );
    assert_eq!(
        report.steps_failed, 0,
        "dry-run must not fail any step (any failure indicates a wiring bug, not external state)"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_dry_run_walks_cross_chain_aggregator_steps() {
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    bootstrap_templates(&base_url).await;

    let kit = build_kit_for(&node, &base_url);

    let mut context = HashMap::new();
    context.insert("from_chain".to_string(), "ethereum".to_string());
    context.insert("to_chain".to_string(), "base".to_string());
    context.insert("asset".to_string(), "USDC".to_string());
    context.insert("amount".to_string(), "1000000000".to_string());

    let spawned = kit
        .spawn(
            TEMPLATE_CROSS_CHAIN_LIQUIDITY,
            SpawnArgs {
                controller_display_name: "Cross-Chain Aggregator Controller".to_string(),
                kyc_tier: KycTier::Enhanced,
                context,
                parent_machine_did: None,
            },
        )
        .await
        .expect("spawn ref-cross-chain-liquidity-aggregator-v1");

    // Credentials minted for the Enhanced-tier controller.
    assert!(spawned.credentials.is_some());

    let report = kit
        .run(&spawned, RunOptions::dry_run())
        .await
        .expect("dry-run executor.run");

    // Template has 8 top-level steps: 4 ToolInvoke + 4 When (intra-Solana
    // tool, layerzero/debridge bridge, ccip bridge, jupiter SvmDispatch).
    assert_eq!(
        report.total_steps(),
        8,
        "ref-cross-chain-liquidity-aggregator-v1 has 8 top-level steps, walked: {:?}",
        report
            .step_results
            .iter()
            .map(|r| (r.step_kind.clone(), r.status.clone()))
            .collect::<Vec<_>>()
    );

    assert_eq!(
        report.steps_executed, 0,
        "dry-run must not execute any step"
    );
    assert_eq!(
        report.steps_failed, 0,
        "dry-run must not fail any step (failure indicates wiring bug)"
    );

    shutdown(tx, handle).await;
}

#[tokio::test]
async fn test_kit_without_auth_issuer_produces_no_credentials() {
    // Build a node, but construct a kit with the unauthenticated
    // constructor. The spawned agent must come back with `credentials =
    // None` — the executor's authenticated dispatch paths (EvmDispatch /
    // SvmDispatch / DamlSubmit) will then fail loudly per `auth.rs`
    // docstring rather than silently dispatching un-credentialed calls.
    let (base_url, tx, handle, _tmp, node) = setup_test_server().await;
    bootstrap_templates(&base_url).await;

    let identity_registry = node.identity_registry().unwrap().clone();
    let agent_runtime = node.agent_runtime().unwrap().clone();
    let kit = AgentKit::new(&base_url, identity_registry, agent_runtime);

    let spawned = kit
        .spawn(
            TEMPLATE_SOLANA_JUPITER_SWAP,
            SpawnArgs {
                controller_display_name: "Unauthenticated Controller".to_string(),
                kyc_tier: KycTier::Basic,
                context: HashMap::new(),
                parent_machine_did: None,
            },
        )
        .await
        .expect("spawn should succeed even without auth issuer");

    assert!(
        spawned.credentials.is_none(),
        "kit constructed without AuthIssuer must not mint credentials"
    );

    shutdown(tx, handle).await;
}
