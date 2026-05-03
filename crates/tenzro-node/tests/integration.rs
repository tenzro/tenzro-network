//! Integration tests for tenzro-node
//!
//! Tests exercise real subsystems together: storage, VM, event loop, RPC, etc.
//! Each test gets its own temp directory to avoid RocksDB lock contention.

use std::sync::Arc;
use tenzro_node::{NodeConfig, TenzroNode, MetricsCollector};

/// Helper: create a NodeConfig with a unique temp data directory
fn test_config() -> (NodeConfig, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("create temp dir");
    let mut config = NodeConfig::default();
    config.data_dir = tmp.path().to_path_buf();
    (config, tmp)
}

/// Test: Node creates with default config and starts all subsystems
#[tokio::test]
async fn test_node_lifecycle() {
    let (config, _tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");

    let status = node.status().await;
    assert_eq!(status.state, "Running");
}

/// Test: Event loop processes transactions and blocks
#[tokio::test]
async fn test_event_loop_processes_block() {
    use tenzro_types::block::{Block, BlockHeader, ConsensusProof, ConsensusAlgorithm};
    use tenzro_types::primitives::{Address, BlockHeight, Hash};

    let (config, _tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");

    // Build a block
    let header = BlockHeader::new(
        BlockHeight::from(1),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::default(),
        ConsensusProof::new(ConsensusAlgorithm::PBFT, vec![]),
    );
    let block = Block::new(header, vec![]);

    // Submit to event loop
    node.submit_block(block).await.expect("submit block");

    // Give event loop time to process
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// Test: Metrics collector tracks all counters
#[test]
fn test_metrics_prometheus_output() {
    let metrics = MetricsCollector::new();

    metrics.record_block();
    metrics.record_block();
    metrics.record_transaction(10);
    metrics.record_inference();
    metrics.record_inference();
    metrics.record_inference();
    metrics.record_settlement();
    metrics.set_peer_count(5);

    let snapshot = metrics.get_metrics();
    assert_eq!(snapshot.blocks_processed, 2);
    assert_eq!(snapshot.transactions_processed, 10);
    assert_eq!(snapshot.inference_requests, 3);
    assert_eq!(snapshot.settlements, 1);
    assert_eq!(snapshot.peer_count, 5);
    assert!(snapshot.uptime_secs < 5); // test runs fast
}

/// Test: Model service registration and lookup
#[tokio::test]
async fn test_model_service_registry() {
    use tenzro_types::model::ModelLocation;

    let (config, _tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node = Arc::new(node);

    // Register a local model service
    let instance_id = node.register_model_service(
        "qwen3-8b",
        "Qwen3 8B",
        "test-provider",
        ModelLocation::Local,
        "http://localhost:8545/v1",
        "http://localhost:3001/mcp",
        "8B",
    );

    // List services
    let services = node.list_model_services();
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].model_id, "qwen3-8b");
    assert_eq!(services[0].location, ModelLocation::Local);

    // Find by model_id
    let found = node.find_model_service_by_model_id("qwen3-8b");
    assert!(found.is_some());
    assert_eq!(found.unwrap().instance_id, instance_id);

    // Get by instance_id
    let got = node.get_model_service(&instance_id);
    assert!(got.is_some());

    // Unregister
    node.unregister_model_service(&instance_id);
    let services = node.list_model_services();
    assert_eq!(services.len(), 0);
}

/// Test: Health monitor correctly aggregates subsystem status
#[tokio::test]
async fn test_health_subsystem_status() {
    use tenzro_node::HealthMonitor;

    let monitor = HealthMonitor::new();

    // Initially unknown
    assert_eq!(monitor.check_health(), tenzro_node::OverallHealth::Unknown);

    // Mark subsystems healthy
    monitor.mark_healthy("storage");
    monitor.mark_healthy("network");
    monitor.mark_healthy("vm");
    assert_eq!(monitor.check_health(), tenzro_node::OverallHealth::Healthy);

    // Degrade one
    monitor.mark_degraded("network", "Low peer count".to_string());
    assert_eq!(monitor.check_health(), tenzro_node::OverallHealth::Degraded);

    // Make one unhealthy
    monitor.mark_unhealthy("consensus", "No quorum".to_string());
    assert_eq!(monitor.check_health(), tenzro_node::OverallHealth::Unhealthy);
}

/// Test: Node configuration validation
#[test]
fn test_config_validation() {
    let (config, _tmp) = test_config();
    assert!(config.validate().is_ok());
}

/// Test: Shutdown broadcast channel propagation
#[tokio::test]
async fn test_shutdown_broadcast() {
    let (shutdown_tx, mut rx1) = tokio::sync::broadcast::channel::<()>(1);
    let mut rx2 = shutdown_tx.subscribe();
    let mut rx3 = shutdown_tx.subscribe();

    // Send shutdown
    let _ = shutdown_tx.send(());

    // All receivers should get the signal
    assert!(rx1.recv().await.is_ok());
    assert!(rx2.recv().await.is_ok());
    assert!(rx3.recv().await.is_ok());
}

/// Test: RPC server can be constructed and started with shutdown
#[tokio::test]
async fn test_rpc_server_graceful_shutdown() {
    use tenzro_node::RpcServer;

    let (config, _tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");
    let node_arc = Arc::new(node);

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    // Bind to port 0 for auto-assigned port
    let rpc_server = RpcServer::new(node_arc.clone(), "127.0.0.1:0".to_string());
    let handle = tokio::spawn(async move {
        rpc_server.start_with_shutdown(shutdown_rx).await
    });

    // Give server time to start
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send shutdown signal
    let _ = shutdown_tx.send(());

    // Server should exit cleanly
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        handle,
    ).await;

    assert!(result.is_ok(), "Server should shut down within 5s");
}

/// Test: Transaction submitted through event loop
#[tokio::test]
async fn test_transaction_submission() {
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, SignedTransaction, TransactionType};
    use tenzro_types::Signature;
    use tenzro_node::event_loop::NodeEvent;

    let (config, _tmp) = test_config();
    let mut node = TenzroNode::new(config).await.expect("node creation");
    node.start().await.expect("node start");

    let event_sender = node.event_sender().expect("event sender");

    let pq_key = MlDsaSigningKey::generate();
    let tx = Transaction::new(
        ChainId::from(1337),
        Address::default(),
        Address::default(),
        Nonce::from(0u64),
        TransactionType::Transfer { amount: 1000 },
        21000,
        1_000_000_000,
        pq_key.verifying_key_bytes().to_vec(),
    );
    let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
    let signed_tx = SignedTransaction::new(tx, Signature::new(vec![0x42; 64], vec![0x42; 32]), pq_sig);

    // Submit transaction
    event_sender.send(NodeEvent::NewTransaction(signed_tx)).await
        .expect("send tx");

    // Give event loop time to process
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
}
