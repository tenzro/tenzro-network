//! Basic network example for Tenzro Network
//!
//! This example demonstrates how to create a network service,
//! subscribe to topics, and broadcast messages.

use tenzro_network::{
    NetworkConfig, NetworkMessage, NetworkService, TenzroNetworkService, MessagePayload,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create a local network configuration
    let config = NetworkConfig::local();

    // Create the network service
    let network = TenzroNetworkService::new(config).await?;

    println!("Network service started!");

    // Get local peer ID
    let peer_id = network.local_peer_id().await?;
    println!("Local peer ID: {}", peer_id);

    // Subscribe to blocks topic
    let mut blocks_rx = network.subscribe("tenzro/blocks").await?;
    println!("Subscribed to blocks topic");

    // Subscribe to transactions topic
    let mut txs_rx = network.subscribe("tenzro/transactions").await?;
    println!("Subscribed to transactions topic");

    // Spawn a task to handle incoming blocks
    tokio::spawn(async move {
        while let Some(msg) = blocks_rx.recv().await {
            println!("Received block message: {:?}", msg.payload);
        }
    });

    // Spawn a task to handle incoming transactions
    tokio::spawn(async move {
        while let Some(msg) = txs_rx.recv().await {
            println!("Received transaction message: {:?}", msg.payload);
        }
    });

    // Broadcast a ping message
    let ping_message = NetworkMessage::new(MessagePayload::Ping);
    network.broadcast("tenzro/status", ping_message).await?;
    println!("Broadcasted ping message");

    // Get connected peers
    let peers = network.connected_peers().await?;
    println!("Connected peers: {} peers", peers.len());
    for peer in peers {
        println!("  - {}", peer);
    }

    // Keep the service running
    println!("\nNetwork service is running. Press Ctrl+C to exit.");
    tokio::signal::ctrl_c().await?;

    println!("Shutting down...");
    Ok(())
}
