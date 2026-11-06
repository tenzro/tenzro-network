//! Basic usage example for Tenzro SDK
//!
//! This example demonstrates:
//! - Connecting to a Tenzro Network node
//! - Getting block information
//! - Checking node status

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("=== Tenzro SDK Basic Usage Example ===\n");

    // The preview network: its staked RPC operators, found on chain
    println!("Connecting to the Tenzro preview network...");
    let client =
        tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default())
            .await?;
    println!("Connected successfully!\n");

    // Check connection
    if client.is_connected().await {
        println!("Client is connected");
    }

    // Get current block number
    println!("\nFetching current block number...");
    let block_number = client.block_number().await?;
    println!("Current block: {}", block_number);

    // Get node information
    println!("\nFetching node information...");
    let info = client.node_info().await?;
    println!("Node version: {}", info.version);
    println!("Chain ID: {}", info.chain_id);
    println!("Block height: {}", info.block_height);
    println!("Peer count: {}", info.peer_count);
    println!("Syncing: {}", info.syncing);

    println!("\n=== Example completed successfully! ===");

    Ok(())
}
