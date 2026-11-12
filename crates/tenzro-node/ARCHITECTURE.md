# Tenzro Node Architecture

This document describes the architecture and design of the Tenzro Network full node implementation.

## Overview

The `tenzro-node` crate is the top-level integration crate that orchestrates all Tenzro Network subsystems into a cohesive blockchain node. It is the binary operators run to participate in Tenzro Network, operating on Tenzro Ledger (the L1 settlement layer).

## Layers

The node carries the protocol core and the role services a bonded node performs. Applications are not part of the node: they run outside it, in harnesses, and reach the node only over its public surfaces.

```
 Applications and harness modules (outside the node)
   markets, task markets, reputation, pricing, routers, hosting,
   workflows, agent templates, third-party connectors
        |  JSON-RPC, MCP, A2A, SDKs, events
        v
 Node role services (bonded, metered, paid through the rails)
   model serving (every modality), storage, TEE attestation
        |
        v
 Protocol core (consensus state)
   consensus, identity, accounts and tokens, staking and roles,
   settlement and escrow, metered receipts, service registry,
   disputes and slashing, governance and governed parameters, bridges
```

## Design Principles

1. **Modular Architecture**: Each subsystem is initialized in its own step of `TenzroNode::start()`
2. **Ordered Initialization**: Subsystems start in dependency order to ensure proper setup
3. **Health Monitoring**: Subsystems report health status for observability
4. **Bonded Roles Only**: A node does not serve a role it has not bonded in chain state
5. **Clean Shutdown**: Subsystems are released in reverse order on stop

## Module Structure

```
tenzro-node/
├── src/
│   ├── main.rs          # CLI entry point: argument parsing, server startup, shutdown
│   ├── lib.rs           # Library exports for testing and reuse
│   ├── node.rs          # Core TenzroNode orchestration logic
│   ├── config.rs        # Configuration management
│   ├── error.rs         # Error types
│   ├── health.rs        # Health monitoring
│   ├── metrics.rs       # Metrics collection
│   ├── genesis.rs       # Genesis initialization
│   ├── event_loop.rs    # Event loop coordination
│   ├── consensus_driver.rs  # ConsensusHandle: mempool, certificates, finality
│   ├── rpc.rs           # JSON-RPC server
│   ├── rpc_gates.rs     # Per-method access classes for the RPC surface
│   ├── *_rpc.rs         # JSON-RPC handler groups (governance, staking, tokens,
│   │                    #   payments, identity, attestation, storage, ...)
│   ├── infer.rs         # Inference dispatch (HTTP and the `tenzro/infer` iroh ALPN)
│   ├── streaming/       # Streaming inference: cursors, deltas, failover, SLA metrics
│   ├── web/             # Web API: verification, health, readiness, metrics, OAuth, passkeys
│   ├── mcp/             # MCP server (Streamable HTTP and the `tenzro/mcp` iroh ALPN), OAuth
│   └── a2a/             # A2A server (agent card, JSON-RPC, SSE, `tenzro/a2a` iroh ALPN)
├── Cargo.toml           # Dependencies on the workspace crates
├── README.md            # User documentation
├── QUICKSTART.md        # Getting started guide
├── ARCHITECTURE.md      # This file
└── tenzro-node.service  # systemd service file
```

`src/` holds many more single-purpose modules (admission, receipts, role bonds, DA committee, state sync, snapshots, attestation, payment channels and others); `ls crates/tenzro-node/src` is the authoritative list.

## Component Breakdown

### 1. Main Entry Point (`main.rs`)

**Responsibilities:**
- Parse CLI arguments with `clap`
- Initialize logging with `tracing-subscriber`
- Load configuration from file or defaults, then apply CLI overrides
- Create and start the `TenzroNode`
- Start the RPC, Web API, MCP and A2A servers
- Install the iroh-side MCP, A2A and inference handlers once the node is running
- Handle graceful shutdown signals (Ctrl+C, SIGTERM)

**Listeners:**

| Flag | Default | Surface |
|------|---------|---------|
| `--rpc-addr` | `127.0.0.1:8545` | JSON-RPC |
| `--web-addr` | `127.0.0.1:8080` | Web API |
| `--mcp-addr` | `127.0.0.1:3001` | MCP |
| `--a2a-addr` | `127.0.0.1:3002` | A2A |
| `--relay-listen` (with `--relay-url`) | none | Relay role HTTP listener |

All four API listeners are loopback only. To serve RPC or MCP publicly, an operator puts their own reverse proxy in front of the loopback address and passes its https URL as `--external-rpc-addr` or `--external-mcp-addr`; the node publishes only those URLs. Peer traffic (consensus, gossip, block sync, state sync, inference, MCP and A2A between nodes) runs over the node's iroh endpoint on per-protocol ALPNs such as `tenzro/consensus`, `tenzro/gossip`, `tenzro/block-sync`, `tenzro/infer` and `tenzro/mcp`.

### 2. Node Orchestrator (`node.rs`)

**Responsibilities:**
- Create and manage all subsystem instances
- Coordinate startup in proper dependency order
- Manage node lifecycle state machine
- Provide unified status API
- Coordinate shutdown

**State Machine:**
```
Created → Starting → Running → Stopping → Stopped
```

**Subsystem Initialization Order (`TenzroNode::start()`):**

1. **Storage** (`tenzro-storage`)
   - RocksDB initialization with column families
   - Identity transport: boot relays admitted, the relay role started if configured
   - Optional state sync from peers against a weak-subjectivity checkpoint

2. **Network** (`tenzro-network`)
   - Peer discovery through boot identities and signed endpoint records
   - Gossip topic subscriptions (over the iroh endpoint)

3. **TEE** (`tenzro-tee`) [Optional]
   - Detect TEE vendor (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
   - Generate attestation via the hardware ioctl interface
   - Configured roles the hardware cannot back are dropped

4. **VM Runtime** (`tenzro-vm`)
   - EVM executor (revm), SVM executor
   - Native executors for bonds, stakes, slashes, governance and settlement
   - Chain id bound to the genesis chain id

5. **Token Economics**
   - TNZO token and token registry (`tenzro-token`)
   - Network treasury and fee market

6. **Wallet** (`tenzro-wallet`)
   - Wallet service; the keystore password comes from the configured `tenzro-keystore-unlock` source
   - The machine's hardware identity key (TPM or Secure Enclave) and the session signer it certifies

7. **Consensus** (`tenzro-consensus`)
   - Every role builds the engine so block sync can verify commit certificates; only validators start it
   - Genesis committee decoded (each entry's proof of possession checked)
   - Epoch manager and `ConsensusHandle` (mempool, certificates, finality)
   - Hardware validator key opened if present (`HardwareValidatorSigner::open`); otherwise the node follows
   - Each boot: an endpoint announcement, signed by that key, naming the iroh endpoint and the in-memory session key that signs channel handshakes

8. **Auth** — OAuth 2.1 with DPoP and rich authorization requests

9. **AI Infrastructure** (`tenzro-model`)
   - Model registry with durable persistence
   - Provider manager and inference router
   - Committee DA served on the iroh endpoint (validators only)

10. **Identity** (`tenzro-identity`)
    - Identity registry (TDIP)
    - Bonded-role check: every configured bonded role must be bonded in chain state
    - Per-DID admission and the account state reader wired into the consensus mempool

11. **Payments** (`tenzro-payments`) — payment gateway (MPP, x402)

12. **Bridge** (`tenzro-bridge`)
    - Route framework and bridge adapters

13. **Account abstraction** and passkey custody

14. **Event loop**, including the `EquivocationJailer`, which drops a validator whose equivocation consensus recorded from the next committee and jails it; the slash itself is applied in consensus state

15. **Maintenance** — stale model services cleaned up, streaming cursor GC, storage maintenance (history retention into the committee DA)

### 3. Configuration (`config.rs`)

**Configuration Sources (in order of precedence):**
1. Command-line arguments (highest priority)
2. Configuration file
3. Built-in defaults (lowest priority)

**Selected `NodeConfig` fields:**
```rust
pub struct NodeConfig {
    rpc_addr: String,                    // [default: 127.0.0.1:8545]
    web_addr: String,                    // [default: 127.0.0.1:8080]
    mcp_addr: String,                    // [default: 127.0.0.1:3001]
    a2a_addr: String,                    // [default: 127.0.0.1:3002]
    external_rpc_addr: Option<String>,   // public https URL of the operator's edge
    external_mcp_addr: Option<String>,
    external_a2a_addr: Option<String>,
    metrics_enabled: bool,
    health_enabled: bool,
    genesis: Option<GenesisConfig>,
    cors_allowed_origins: Vec<String>,
    // ... roles, data directory, iroh, consensus, bridge and other sections
}
```

### 4. Health Monitoring (`health.rs`)

**Purpose:**
Track and report health status for subsystems to enable observability and automated monitoring.

**Health Levels:**
- `Healthy`: Subsystem operating normally
- `Degraded`: Subsystem experiencing issues but functional
- `Unhealthy`: Subsystem not functional

**Overall Health Calculation:**
- `Healthy`: All subsystems healthy
- `Degraded`: Some subsystems degraded, none unhealthy
- `Unhealthy`: One or more subsystems unhealthy
- `Unknown`: No subsystems registered

**Reported Subsystems:**
storage, network, tee, vm, token, wallet, consensus, auth, ai, identity, payments, bridge, event_loop

### 5. Metrics Collection (`metrics.rs`)

**Purpose:**
Collect operational metrics for performance monitoring, alerting, and capacity planning. Metrics, including the `tenzro_network_*` series, are served at `/metrics` on the Web API listener.

**Thread-Safe Implementation:**
Uses atomic counters for lock-free concurrent metric updates.

### 6. JSON-RPC Server (`rpc.rs`)

**Purpose:**
Provide a JSON-RPC 2.0 API for querying and interacting with the node.

**Server Design:**
- Async HTTP server using `axum`
- CORS configuration with allowed origins
- Concurrency limit: 1000 in-flight requests
- Per-address rate limit (GCRA) ahead of the concurrency limit
- JSON request body size limit: 2 MB
- Batch request support (JSON array)
- Per-method access classes in `rpc_gates.rs`

**Representative Methods (not exhaustive):**

- **Tokens**: `tenzro_tokenBalance`, `tenzro_totalSupply`, `tenzro_getToken`, `tenzro_listTokens`, `tenzro_getTokenBalance`, `tenzro_deployContract`
- **Settlement**: `tenzro_settle`
- **Network**: `tenzro_getNodeStatus`, `tenzro_peerCount`, `tenzro_syncing`, `tenzro_getHardwareProfile`, `tenzro_getRole`
- **Governance** (reads; proposing, voting, enacting and vetoing are signed `Governance*` transactions): `tenzro_listProposals`, `tenzro_getProposal`, `tenzro_getVotingPower`, `tenzro_getPolicy`
- **Payments**: `tenzro_createPaymentChallenge`, `tenzro_verifyPayment`
- **Staking** (stakes change only through signed `Stake` transactions): `tenzro_getRoleStakes`, `tenzro_getWalletProvider`, `tenzro_getProviderStats`
- **Duties and evidence** (reads): `tenzro_listDuties`, `tenzro_getDuty`, `tenzro_verifyEvidence`
- **Agents** (accounts acting under consensus Terms): `tenzro_getAgentTerms`, `tenzro_getAgentBond`, `tenzro_resolveAgentKey`
- **EVM-compatible**: `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_chainId`, `eth_getTransactionReceipt`, `tenzro_sendRawTransaction`

**Error Codes:**
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error
- `-32000`: Server error (implementation-specific)

### 7. MCP Server (`mcp/`)

**Purpose:**
Expose the node's tools via the Model Context Protocol. `mcp/server.rs` and `mcp/rpc_tools.rs` hold the authoritative tool inventory.

**Transports:**
- Streamable HTTP at `/mcp` on the MCP listener, with OAuth token and revocation endpoints beside it (`mcp/oauth.rs`)
- The `tenzro/mcp` ALPN on the iroh endpoint (`mcp/iroh_transport.rs`), where each bi-stream is a full MCP session in newline-delimited JSON-RPC

**Protocol:** MCP revision `2026-07-28`, stateless (no session endpoints), JSON replies, with the revision's per-request `_meta` required on every request.

The node runs this one MCP server. It does not run separate per-chain MCP servers.

### 8. A2A Protocol Server (`a2a/`)

**Purpose:**
A2A 1.0 server with agent card discovery and JSON-RPC 2.0 task execution.

**Endpoints:**
- `GET /.well-known/agent-card.json`: the agent card, carrying a detached JWS by the operator's wallet key; a node that cannot sign serves no card
- `POST /a2a`: JSON-RPC 2.0 dispatcher; streaming messages are answered with a server-sent-event stream on the same route
- The `tenzro/a2a` ALPN on the iroh endpoint

Every request declares the protocol version in the `A2A-Version` header.

### 9. Error Handling (`error.rs`)

**Error Type Hierarchy:**
```
NodeError
├── Network(NetworkError)
├── Storage(StorageError)
├── Consensus(ConsensusError)
├── Vm(VmError)
├── Wallet(WalletError)
├── Token(TokenError)
├── Model(ModelError)
├── Settlement(SettlementError)
├── Bridge(BridgeError)
├── Tee(TeeError)
├── Config(String)
├── AlreadyStarted(String)
├── NotStarted(String)
├── InvalidState(String)
├── InvalidTransaction(String)
├── Io(std::io::Error)
├── Serialization(serde_json::Error)
├── Internal(String)
└── Other(String)
```

**Error Propagation:**
Subsystem errors are wrapped in `NodeError` variants using `#[from]` conversions, providing a single `Result<T>` type for the crate.

## Lifecycle Management

### Startup Sequence

```
1. Parse CLI arguments
2. Initialize logging
3. Load configuration and apply CLI overrides
4. Create TenzroNode (state: Created)
5. node.start():
   a. Transition to Starting state
   b. Storage (identity transport, optional state sync)
   c. Network
   d. TEE (if enabled)
   e. VM runtime
   f. Token economics
   g. Wallet, hardware identity key, session signer
   h. Consensus (started on validators only)
   i. Auth
   j. AI infrastructure, committee DA
   k. Identity, bonded-role check
   l. Payments
   m. Bridge
   n. Account abstraction
   o. Event loop
   p. Maintenance tasks
   q. Transition to Running state
6. Start the RPC, Web API, MCP and A2A servers
7. Install the iroh-side A2A, MCP and inference handlers
8. Wait for shutdown signal
```

### Shutdown Sequence

```
1. Receive Ctrl+C or SIGTERM signal
2. node.stop():
   a. Transition to Stopping state
   b. Stop the DA possession challenger and storage maintenance
   c. Release payments, identity, AI infrastructure, auth, token,
      wallet and VM
   d. Stop consensus
   e. Release TEE, network and storage
   f. Transition to Stopped state
3. Exit process
```

### State Transitions

Only valid transitions:
- `Created → Starting` (via `start()`)
- `Starting → Running` (after successful initialization)
- `Running → Stopping` (via `stop()` or signal)
- `Stopping → Stopped` (after cleanup)

Starting a node twice is refused with `NodeError::AlreadyStarted`; stopping a node that has not reached `Running` is refused with `NodeError::NotStarted`; any other invalid transition raises `NodeError::InvalidState`.

## Roles

A node runs one or more roles (`NetworkRole` in `tenzro-types`). Bonded roles are served only once bonded in chain state from the operator account. Roles include:

- **Validator**: block production and consensus participation; requires a validator bond and a hardware validator key
- **FullNode**: follows the chain and verifies blocks without voting
- **LightClient**: submits transactions and queries state
- **ModelProvider**: serves model inference of any modality and is paid through metered receipts
- **ComputeProvider**: rents accelerator capacity for fixed terms
- **StorageProvider**: stores data for others
- **TeeProvider**: provides confidential computing and hardware attestation; requires TEE-capable hardware (Intel TDX, AMD SEV-SNP, AWS Nitro, or NVIDIA GPU)
- **Rpc**, **Attestor**, **WalletProvider**, **CatalogPublisher**, **Edge**, **Archive**, **Bootstrap**: see the `NetworkRole` documentation

## Security Considerations

1. **Key Custody**: Node keys are created and held in the machine's TPM or Secure Enclave and never leave it
2. **Network Security**: Peer traffic runs over encrypted iroh QUIC connections between identified endpoints
3. **TEE Attestation**: Remote attestation for TEE providers over the hardware ioctl interfaces
4. **API Exposure**: All API listeners bind loopback; public exposure is the operator's reverse proxy
5. **RPC Access Control**: Per-method access classes, CORS configuration, rate and concurrency limits, body size limits
6. **Equivocation Detection**: Double-vote evidence is slashed in consensus state and the validator is jailed

## Testing Strategy

### Unit Tests
- Individual function correctness
- Error handling edge cases
- Configuration validation

### Integration Tests
- Subsystem interaction
- Startup/shutdown sequences
- State transitions

### Full-Node Tests
- Full node lifecycle
- Multi-node scenarios
- Network partition handling

## Observability

### Logs
- Structured logging with `tracing`
- Multiple log levels per module

### Metrics
- Metrics served at `/metrics` on the Web API listener
- Health and readiness at `/health` and `/ready`
- Atomic counters

### Tracing
- Span tracking across subsystems
