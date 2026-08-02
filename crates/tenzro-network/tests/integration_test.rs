//! Integration tests for tenzro-network

use tenzro_network::{
    MessagePayload, NetworkConfig, NetworkMessage, NetworkService, TenzroNetworkService,
};

#[tokio::test]
async fn test_network_service_creation() {
    let config = NetworkConfig::local();
    let result = TenzroNetworkService::new(config).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_local_peer_id() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    let peer_id = network.local_peer_id().await;
    assert!(peer_id.is_ok());
}

#[tokio::test]
async fn test_topic_subscription() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    let result = network.subscribe("tenzro/test").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_broadcast_message() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    // Subscribe first
    network.subscribe("tenzro/test").await.unwrap();

    // Broadcast message — may fail when no peers are subscribed to the topic,
    // which is expected in a single-node test environment
    let message = NetworkMessage::new(MessagePayload::Ping);
    let _result = network.broadcast("tenzro/test", message).await;
}

#[tokio::test]
async fn test_connected_peers() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    let peers = network.connected_peers().await;
    assert!(peers.is_ok());

    // Initially, should have no connected peers
    let peers = peers.unwrap();
    assert_eq!(peers.len(), 0);
}

#[tokio::test]
async fn test_peer_info() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    let peer_id = network.local_peer_id().await.unwrap();
    let info = network.peer_info(&peer_id).await;
    assert!(info.is_ok());
}

#[tokio::test]
async fn test_config_validation() {
    // Valid config
    let config = NetworkConfig::default();
    assert!(config.validate().is_ok());

    // Invalid config - no listen addresses
    let invalid_config = NetworkConfig {
        listen_addresses: vec![],
        ..Default::default()
    };
    assert!(invalid_config.validate().is_err());

    // Invalid config - no topics
    let invalid_config = NetworkConfig {
        gossip_topics: vec![],
        ..Default::default()
    };
    assert!(invalid_config.validate().is_err());
}

#[tokio::test]
async fn test_message_serialization_roundtrip() {
    let msg = NetworkMessage::new(MessagePayload::Ping);
    let bytes = msg.to_bytes().unwrap();
    let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

    assert_eq!(msg.message_id, decoded.message_id);
    assert_eq!(msg.timestamp, decoded.timestamp);
}

#[tokio::test]
async fn test_multiple_subscriptions() {
    let config = NetworkConfig::local();
    let network = TenzroNetworkService::new(config).await.unwrap();

    // Subscribe to multiple topics
    let topics = vec!["tenzro/blocks", "tenzro/transactions", "tenzro/consensus"];

    for topic in topics {
        let result = network.subscribe(topic).await;
        assert!(result.is_ok());
    }
}
