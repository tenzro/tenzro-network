# tenzro-network

Gossip messages, topics and validation for Tenzro Network — the AI verification and settlement protocol.

## Overview

The `tenzro-network` crate defines what Tenzro nodes say to each other over gossip and carries it on iroh-gossip over the node's iroh endpoint. Finding peers (signed identity endpoint records and relays), point-to-point protocols on their own ALPNs, and bulk transfer all live in `tenzro-iroh`; this crate owns the message types, the topic service, and the checks a message passes before it is delivered or passed on.

## Modules

- `error` - NetworkError and Result types
- `gossip` - NetworkGossip: the node's gossip topics over its iroh endpoint (`tenzro_iroh::gossip`)
- `gossip_validation` - per-message checks and the validation ticket a judged topic hands its subscriber
- `message` - NetworkMessage, MessagePayload and the signed announcement types
- `metrics` - Prometheus counters for gossip traffic
- `peer_status` - Tracks peer-advertised block heights from `tenzro/status`, keyed by iroh endpoint id, feeding the `eth_syncing` / `tenzro_syncing` answers
- `service` - NetworkService trait and the TenzroNetworkService implementation

## Usage

```rust
use std::time::Duration;
use tenzro_network::{
    GossipLimits, MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService,
};

# async fn example() -> tenzro_network::Result<()> {
// Per-neighbour gossip budgets; a node reads them from the network's
// governed parameters (gossip.*).
let limits = GossipLimits {
    window: Duration::from_secs(10),
    consensus_messages: 20_000,
    general_messages: 50_000,
    ban: Duration::from_secs(300),
};
let network = TenzroNetworkService::new(limits).await?;

// Topics open once the node attaches its iroh gossip transport:
// network.attach_gossip(transport, chain_id)?;

let mut blocks = network.subscribe("tenzro/blocks").await?;
network
    .broadcast("tenzro/status", NetworkMessage::new(MessagePayload::Ping))
    .await?;
# Ok(())
# }
```

## Topics

- `tenzro/blocks` - Block propagation
- `tenzro/transactions` - Transaction propagation
- `tenzro/certificates` - Checkpoint certificates, for followers
- `tenzro/validators` - Validators' signed per-boot endpoint announcements
- `tenzro/models` - Model registrations
- `tenzro/providers` - Provider announcements
- `tenzro/status` - Status and chain-tip messages

## Announcement binding

A provider announcement is signed as the node's machine DID (a session signature its hardware identity key certified, verified against the key registered for the DID) and bound to the iroh endpoint it names: the endpoint key signs the machine DID, and consumers verify that binding against `iroh_endpoint_id` before keying the provider by it. An announcement whose binding is missing or does not verify is dropped.
