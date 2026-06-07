# tenzro-agent

AI agent infrastructure with self-sovereign identity and inter-agent communication for the Tenzro Network.

## Overview

**tenzro-agent** provides the foundational infrastructure for AI agents to operate autonomously on the Tenzro Network. Each agent receives a self-sovereign identity with an auto-provisioned FROST-Ed25519 threshold wallet, can communicate with other agents using the A2A (Agent-to-Agent) protocol, and integrates with Anthropic's Model Context Protocol (MCP).

Agents are first-class citizens on the network, with identity anchored in the Tenzro Decentralized Identity Protocol (TDIP) and support for fine-grained delegation from human controllers.

## Key Features

- **Self-Sovereign Identity** — Every agent gets a unique TDIP identity with auto-provisioned 2-of-3 FROST-Ed25519 threshold wallet (RFC 9591)
- **A2A Protocol** — Agent-to-Agent messaging protocol for inter-agent communication with task delegation
- **MCP Bridge** — Real MCP Streamable HTTP client transport (JSON-RPC 2.0, `Mcp-Session-Id` sessions, `tools/list`, `tools/call`)
- **MCP Client** — Connect to remote MCP servers (protocol version 2025-11-25)
- **Lifecycle Management** — State machine: Created → Active → Suspended → Terminated
- **Capability Registry** — Attestation and discovery of agent capabilities
- **Delegation Scopes** — Fine-grained permissions inherited from human controllers (max spend, operations, contracts, protocols, chains)
- **Message Routing** — Local message delivery with mpsc channels, optional gossipsub transport for cross-node messaging
- **Swarm Coordination** — Multi-agent swarm management with shared state and broadcast tasks
- **Durable State** — Write-through persistence to RocksDB (CF_AGENTS) for agent identity, lifecycle, spawn tree, and swarm state; hydration on startup restores all agents and swarms

## Key Types

### Core Infrastructure
- **AgentRuntime** — Manages agent lifecycle, execution, and resource allocation; coordinates all subsystems
- **AgentIdentityManager** — Self-sovereign agent identities with TDIP integration and auto-provisioned FROST-Ed25519 threshold wallets
- **AgentLifecycle** — State machine with transitions: Created, Active, Suspended, Terminated; heartbeat monitoring

### Communication
- **MessageRouter** — Routes messages between agents using local mpsc channels; optional gossipsub transport for cross-node delivery
- **A2aProtocol** — Agent-to-Agent protocol implementation (task delegation, capability query, message passing)
- **McpBridge** — Converts between A2A and Anthropic MCP message formats
- **McpClient** — Real MCP Streamable HTTP client (JSON-RPC 2.0, protocol version 2025-11-25)
- **AgentMessage** — Structured message type with sender, receiver, message type, and payload

### Capabilities
- **CapabilityRegistry** — Registry for agent capability discovery
- **CapabilityAttestation** — Cryptographic attestation of agent capabilities (signature-based or TEE-backed)

### Autonomy
- **AgentAutonomy** — Autonomous execution system coordinating task execution, scheduling, and spending policy
- **TaskExecutor** — Processes tasks from queues with registered handlers; configurable concurrency limits
- **AutonomousScheduler** — Interval-based task scheduling with pause/resume
- **SpendingPolicy** — Per-transaction and daily spending limits with automatic daily reset, registered per-machine-DID on `AgentRuntime` (separate from the protocol-level `DelegationScope` ceiling). Accessors: `set_spending_policy(machine_did, policy)`, `get_spending_policy(machine_did)`, `record_spend(machine_did, amount)`. Default-populated by `tenzro-agent-kit` at machine spawn time from the spec's `DelegationSpec`.
- **TaskHandler** — Trait for implementing task handlers by capability
- **PendingApproval** — Out-of-scope agent operations queue for controller review. When a delegated machine attempts an operation outside its `DelegationScope` or `SpendingPolicy`, the runtime queues a `PendingApproval` keyed by controller DID. Controllers list/inspect/decide via `tenzro_listPendingApprovals`, `tenzro_getApproval`, `tenzro_decideApproval` RPCs (CLI: `tenzro approval list/get/decide`).

### Swarm
- **SwarmManager** — Multi-agent swarm coordination with shared state and broadcast task execution
- **SwarmState** — Swarm lifecycle: Active, Paused, Completed, Terminated

### Identity
- **RegisteredAgent** — Agent identity with wallet ID, capabilities, status, TDIP DID, and registration fee
- **AgentStatus** — Created, Active, Suspended, Terminated

## Usage

```rust
use tenzro_agent::{AgentRuntime, AgentRuntimeConfig};
use tenzro_agent::capabilities::CapabilityRegistry;
use tenzro_types::{primitives::Address, agent::Capability};

// Create agent runtime
let runtime = AgentRuntime::new()?;

// Register agent with capabilities
let creator = Address::from([1u8; 32]);
let capabilities = vec![
    Capability::NaturalLanguageProcessing { languages: vec!["en".into()] },
    Capability::MultiAgentCoordination,
];

let agent = runtime.register_agent(
    "trading-agent-001".to_string(),
    creator,
    capabilities.clone(),
    false, // not TEE-backed
    0,     // nonce
).await?;

println!("Agent ID: {}", agent.identity.agent_id);
println!("Wallet ID: {}", agent.wallet_id);

// Activate agent
runtime.activate_agent(&agent.identity.agent_id).await?;

// Send message to another agent
use tenzro_types::{AgentMessage, AgentMessageType};

let message = AgentMessage::new(
    agent.identity,
    recipient_identity,
    AgentMessageType::Query,
    b"fetch_price:BTC/USD".to_vec(),
);

runtime.send_message(message).await?;

// Query agent capabilities
let agents_with_nlp = runtime.find_agents_with_capability(
    &Capability::NaturalLanguageProcessing { languages: vec!["en".into()] },
);
println!("Found {} agents with inference capability", agents_with_inference.len());
```

## Agent Lifecycle

```
Created ──activate──> Active ──suspend──> Suspended
                        │                     │
                        │                     │
                        └────terminate────────┴──> Terminated
```

- **Created** — Agent registered but not yet active
- **Active** — Agent is running and can send/receive messages
- **Suspended** — Agent temporarily paused, can be reactivated
- **Terminated** — Agent permanently shut down; retained in storage for audit

## Durable State Persistence

When initialized with `AgentRuntime::with_storage(storage, transport)`, the runtime persists:

- **Agent identities** — `RegisteredAgent` under `agent:<id>` in CF_AGENTS
- **Lifecycle state** — `AgentLifecycleInfo` under `lifecycle:<id>` in CF_AGENTS
- **Spawn tree** — Parent → children mappings under `children:<parent_id>` in CF_AGENTS
- **Swarm state** — `SwarmState` under `swarm:<swarm_id>` in CF_AGENTS (via `SwarmManager::with_storage`)

On startup, hydration restores all agents, lifecycles, spawn relationships, and swarms. Agents are re-registered with the `MessageRouter`. Terminated agents are retained for audit of `state_history`, `registration_fee`, and `tenzro_did`.

The `insert_hydrated()` method on `AgentIdentityManager` and `AgentLifecycle` bypasses wallet provisioning and TDIP gas charges during rehydration.

## Dependencies

- **tenzro-types** — Core types and primitives
- **tenzro-crypto** — Cryptographic operations
- **tenzro-wallet** — FROST-Ed25519 threshold wallet provisioning
- **tenzro-identity** — TDIP identity integration
- **tenzro-storage** — RocksDB persistence (CF_AGENTS)

## Testing

The crate includes 114 unit tests covering agent lifecycle, messaging, capabilities, autonomy, swarms, and persistence.

```bash
cargo test -p tenzro-agent
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](../../LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
