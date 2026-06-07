# tenzro-network

P2P networking layer for Tenzro Network — the AI verification and settlement protocol.

## Overview

The `tenzro-network` crate provides the networking infrastructure for **Tenzro Network**, built on [libp2p](https://libp2p.io/). It handles peer discovery, message propagation, and network topology management across the Tenzro Network protocol. This P2P layer enables communication between nodes running Tenzro Ledger (the L1 settlement layer with TNZO governance token).

## Modules

**8 modules:** behaviour, config, discovery, error, gossip, message, peer_manager, service, transport

- `behaviour` - TenzroBehaviour combining Gossipsub, Kademlia, Identify, Ping
- `config` - NetworkConfig for local/testnet/mainnet
- `discovery` - Peer discovery via DHT and mDNS, BootstrapConfig
- `error` - NetworkError and Result types
- `gossip` - GossipTopics, MessageDeduplicator, MessageValidation, TopicSubscriptions
- `message` - NetworkMessage, MessagePayload with 11 message types
- `peer_manager` - PeerManager, ValidatorRegistry, VALIDATOR_ONLY_TOPICS, reputation scoring
- `service` - NetworkService trait, TenzroNetworkService implementation
- `transport` - TCP and QUIC transport with Noise encryption

## Features

- **Gossipsub**: Pub/sub messaging for blocks, transactions, consensus messages, and more
- **Kademlia DHT**: Distributed peer discovery and content routing
- **Identify Protocol**: Peer information exchange and capability discovery
- **Ping Protocol**: Connection health monitoring and keep-alive
- **Peer Management**: Reputation scoring, peer banning, and connection limits
- **Message Validation**: Automatic validation with timestamp checks, size limits, and age verification
- **Multi-Transport**: TCP and QUIC support with Noise encryption
- **Validator Authentication**: ValidatorRegistry trait with topic-based authorization (consensus/block/attestation topics)

## Architecture

The network service uses an event loop pattern with async channels for communication:

```
┌─────────────────┐
│  Application    │
│     Layer       │
└────────┬────────┘
         │ async channels
┌────────▼────────┐
│ NetworkService  │ ← API Layer (trait-based)
└────────┬────────┘
         │
┌────────▼────────┐
│  Event Loop     │ ← libp2p Swarm
│  (background)   │
└────────┬────────┘
         │
┌────────▼────────┐
│  TenzroBehaviour│ ← Combines protocols:
│                 │   - Gossipsub
│                 │   - Kademlia
│                 │   - Identify
│                 │   - Ping
└─────────────────┘
```

## Usage

### Creating a Network Service

```rust
use tenzro_network::{NetworkConfig, TenzroNetworkService, NetworkService};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create configuration
    let config = NetworkConfig::testnet();

    // Create network service
    let network = TenzroNetworkService::new(config).await?;

    // Get local peer ID
    let peer_id = network.local_peer_id().await?;
    println!("Local peer ID: {}", peer_id);

    Ok(())
}
```

### Subscribing to Topics

```rust
use tenzro_network::{NetworkMessage, MessagePayload};

// Subscribe to blocks
let mut blocks_rx = network.subscribe("tenzro/blocks").await?;

// Handle incoming messages
tokio::spawn(async move {
    while let Some(msg) = blocks_rx.recv().await {
        match msg.payload {
            MessagePayload::Block(block) => {
                println!("Received block at height {}", block.header.height);
            }
            _ => {}
        }
    }
});
```

### Broadcasting Messages

```rust
use tenzro_network::{NetworkMessage, MessagePayload};

// Create a message
let message = NetworkMessage::new(MessagePayload::Ping);

// Broadcast to all peers on a topic
network.broadcast("tenzro/status", message).await?;
```

### Peer Management

```rust
// Get connected peers
let peers = network.connected_peers().await?;
println!("Connected to {} peers", peers.len());

// Get peer information
for peer_id in peers {
    if let Some(info) = network.peer_info(&peer_id).await? {
        println!("Peer {}: role={:?}, reputation={}",
            peer_id, info.role, info.reputation);
    }
}

// Ban a misbehaving peer
network.ban_peer(&peer_id).await?;
```

## Gossipsub Topics

The network uses different topics for different message types (8 topics):

| Topic | Purpose |
|-------|---------|
| `tenzro/blocks` | Block propagation |
| `tenzro/transactions` | Transaction broadcasting |
| `tenzro/consensus` | Consensus messages (proposals, votes) - **validator-only** |
| `tenzro/attestations` | TEE attestation reports |
| `tenzro/models` | Model registration announcements |
| `tenzro/inference` | Inference requests and responses |
| `tenzro/status` | Node status and health checks |
| `tenzro/agents` | Agent-to-agent messages |

For testnet and mainnet, topics are prefixed:
- Testnet: `tenzro/testnet/blocks/1.0.0`
- Mainnet: `tenzro/mainnet/blocks/1.0.0`

## Network Configurations

### Local Development

```rust
let config = NetworkConfig::local();
```

- Listens on localhost only
- No bootstrap nodes
- mDNS enabled for local peer discovery
- Suitable for testing on a single machine

### Testnet

```rust
let config = NetworkConfig::testnet();
```

- Connects to testnet bootstrap nodes
- Full DHT and gossipsub enabled
- Testnet-specific topics

### Mainnet

```rust
let config = NetworkConfig::mainnet();
```

- Connects to mainnet bootstrap nodes
- Production settings
- Mainnet-specific topics

### Custom Configuration

```rust
use tenzro_network::NetworkConfig;
use std::time::Duration;

let config = NetworkConfig {
    listen_addresses: vec![
        "/ip4/0.0.0.0/tcp/9000".parse().unwrap(),
    ],
    boot_nodes: vec![
        "/dns4/boot-1.example.com/tcp/9000".parse().unwrap(),
    ],
    max_inbound_peers: 100,
    max_outbound_peers: 50,
    enable_dht: true,
    enable_mdns: false,
    connection_idle_timeout: Duration::from_secs(60),
    ..Default::default()
};
```

## Peer Discovery

The network supports multiple peer discovery mechanisms:

### Kademlia DHT

- Distributed hash table for peer routing
- Random walks for discovering new peers
- Provider records for finding specific node types (validators, inference providers, etc.)

### mDNS

- Local network peer discovery
- Enabled by default for development
- Automatically finds peers on the same LAN

### Bootstrap Nodes

- Well-known nodes for initial connections
- Configured per network (testnet/mainnet)
- Used to bootstrap the DHT

## Message Validation

All incoming messages are automatically validated:

1. **Timestamp validation**: Messages must have recent timestamps (within 5 minutes)
2. **Message age**: Messages older than 1 hour are rejected
3. **Size limits**: Messages must be under 10MB
4. **Payload validation**: Type-specific validation for each message type

Invalid messages result in reputation penalties for the sender.

## Peer Reputation

Peers are assigned reputation scores based on their behavior:

- **Good behavior**: Valid messages, successful pings → +reputation
- **Bad behavior**: Invalid messages, failed pings → -reputation
- **Auto-ban**: Peers with reputation < -50 are automatically banned
- **Bans**: Temporary (1 hour default) or permanent

## Validator Authentication

Validators are authenticated for consensus-critical topics via `ValidatorRegistry` trait:
- `authorize_peer_for_topic()` checks validator status
- Validator-only topics: `tenzro/consensus`, `tenzro/blocks` (for block proposals), `tenzro/attestations`
- Non-validators are rejected from these topics

## Message Types (15 variants)

- `Ping` / `Pong` - Health checks
- `Block(Block)` / `BlockRequest(Hash)` / `BlockResponse(Option<Block>)` - Block propagation + targeted fetch
- `Transaction(SignedTransaction)` / `TransactionRequest(Hash)` / `TransactionResponse(Option<SignedTransaction>)` - Transaction broadcast + targeted fetch
- `Attestation(AttestationMessage)` - TEE attestations
- `ModelRegistration(ModelRegistrationMessage)` - Model announcements
- `InferenceRequest(InferenceRequestMessage)` / `InferenceResponse(InferenceResponseMessage)` - Inference operations
- `Status(StatusMessage)` - Node status
- `ProviderAnnouncement(ProviderAnnouncementMessage)` - Provider registration
- `AgentAnnouncement(AgentAnnouncementMessage)` - Agent discovery

## Dependencies

- `tenzro-types` - Shared types
- `tenzro-crypto` - Cryptographic primitives
- `libp2p` - P2P networking (Gossipsub, Kademlia, Identify, Ping)
- `tokio` - Async runtime
- `async-trait` - Async traits
- `serde`, `serde_json` - Serialization
- `thiserror` - Error handling
- `tracing` - Logging
- `futures` - Async utilities
- `bytes`, `prost` - Data encoding
- `dashmap` - Concurrent maps
- `uuid`, `chrono`, `sha2` - Utilities
- `parking_lot` - High-performance locks

## Test Coverage

3 unit tests + 1 doc test covering:
- Config validation
- Message serialization/deserialization
- Network service creation

## Examples

See the `examples/` directory:
- `basic_network.rs`: Basic network setup and messaging

Run an example:

```bash
cargo run --example basic_network
```

## License

Licensed under either of:

- MIT license ([LICENSE](../../LICENSE) or http://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)

at your option.
