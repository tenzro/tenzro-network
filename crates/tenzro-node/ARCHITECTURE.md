# Tenzro Node Architecture

This document describes the architecture and design of the Tenzro Network full node implementation.

## Overview

The `tenzro-node` crate is the top-level integration crate that orchestrates all Tenzro Network subsystems into a cohesive, production-ready blockchain node. It acts as the "main" binary that users run to participate in Tenzro Network, operating on Tenzro Ledger (the L1 settlement layer).

## Design Principles

1. **Modular Architecture**: Each subsystem is independent and can be initialized/stopped separately
2. **Ordered Initialization**: Subsystems start in dependency order to ensure proper setup
3. **Health Monitoring**: All subsystems report health status for observability
4. **Graceful Degradation**: Node can operate with degraded subsystems when possible
5. **Clean Shutdown**: Reverse-order shutdown ensures proper resource cleanup

## Module Structure

```
tenzro-node/
├── src/
│   ├── main.rs          # CLI entry point with argument parsing
│   ├── lib.rs           # Library exports for testing and reuse
│   ├── node.rs          # Core TenzroNode orchestration logic
│   ├── config.rs        # Configuration management
│   ├── error.rs         # Error types
│   ├── health.rs        # Health monitoring
│   ├── metrics.rs       # Metrics collection
│   ├── rpc.rs           # JSON-RPC server (242 methods, 26 namespaces)
│   ├── event_loop.rs    # Event loop coordination
│   ├── genesis.rs       # Genesis block initialization
│   ├── web/             # Web verification API
│   ├── mcp/             # MCP server (167 tools) + 6 ecosystem servers (Solana, Ethereum, Canton, LayerZero, Chainlink, Li.Fi)
│   └── a2a/             # A2A protocol server (Agent Card, JSON-RPC, SSE)
├── Cargo.toml           # Dependencies on all workspace crates
├── README.md            # User documentation
├── QUICKSTART.md        # Getting started guide
├── ARCHITECTURE.md      # This file
├── config.example.json  # Example configuration
└── tenzro-node.service  # systemd service file
```

## Component Breakdown

### 1. Main Entry Point (`main.rs`)

**Responsibilities:**
- Parse CLI arguments with `clap`
- Initialize logging with `tracing-subscriber`
- Load configuration from file or defaults
- Create and start the `TenzroNode`
- Handle graceful shutdown signals (Ctrl+C, SIGTERM)
- Print startup banner and node information

**Key Features:**
- Environment variable support via `EnvFilter`
- CLI argument overrides for config file values
- Structured logging configuration
- Support for 10 independent server addresses (RPC, Web, MCP, A2A, 6 ecosystem MCPs)

### 2. Node Orchestrator (`node.rs`)

**Responsibilities:**
- Create and manage all subsystem instances
- Coordinate startup in proper dependency order
- Manage node lifecycle state machine
- Provide unified status API
- Coordinate graceful shutdown

**State Machine:**
```
Created → Starting → Running → Stopping → Stopped
```

**Subsystem Initialization Order:**

1. **Storage** (`tenzro-storage`)
   - RocksDB initialization with column families
   - Block store, account store setup
   - State trie initialization

2. **Network** (`tenzro-network`)
   - libp2p swarm creation
   - Peer discovery bootstrap
   - Gossipsub topic subscriptions
   - Validator peer authentication via NodeValidatorRegistry

3. **TEE** (`tenzro-tee`) [Optional]
   - Detect TEE vendor (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA GPU)
   - Generate attestation with real hardware ioctl
   - Register with TEE registry

4. **VM Runtime** (`tenzro-vm`)
   - EVM executor initialization (revm)
   - SVM executor initialization (agave-svm)
   - DAML executor initialization (Canton gRPC)
   - Precompile registration (9 standard + 7 BLS12-381 + 8 Tenzro-specific)
   - State adapter setup with RocksDB persistence

5. **Token Economics**
   - TNZO token manager (`tenzro-token`)
   - Staking manager with RocksDB persistence
   - Governance engine (stake-weighted voting)
   - Network treasury (multisig withdrawals)
   - Liquid staking (stTNZO with rebasing exchange rate)

6. **Wallet** (`tenzro-wallet`)
   - MPC wallet service (2-of-3 threshold)
   - Keystore initialization (Argon2id KDF)
   - Asset manager setup

7. **Consensus** (`tenzro-consensus`) [Validators Only]
   - HotStuff-2 engine creation
   - Validator set initialization
   - Epoch manager setup
   - Equivocation detection wired to VoteCollector
   - Start participating in consensus

8. **Settlement** (`tenzro-settlement`)
   - Settlement engine initialization
   - Fee collector setup
   - Escrow manager creation
   - Micropayment channel manager

9. **AI Infrastructure**
   - Model registry (`tenzro-model`) with durable persistence via with_storage()
   - Provider manager with health monitoring
   - Inference router
   - Agent runtime (`tenzro-agent`) with durable persistence (RegisteredAgent, AgentLifecycleInfo, spawn tree)
   - Swarm manager with durable persistence (SwarmState)
   - init_ai_infrastructure() wires Arc<dyn KvStore> into all AI subsystems

10. **Bridge** (`tenzro-bridge`)
    - Bridge router initialization
    - Adapter registration (LayerZero, CCIP, deBridge, Canton)
    - Real message signing and verification with Ed25519/Secp256k1

11. **StakingSlashingCallback**
    - Bridges consensus equivocation detection to token staking
    - Slashes 10% of validator stake on double-vote

### 3. Configuration (`config.rs`)

**Configuration Sources (in order of precedence):**
1. Command-line arguments (highest priority)
2. Environment variables
3. Configuration file (TOML/JSON)
4. Built-in defaults (lowest priority)

**NodeConfig Structure:**
```rust
pub struct NodeConfig {
    role: NetworkRole,           // Validator, ModelProvider, TeeProvider, LightClient
    data_dir: PathBuf,           // Storage location
    network: NetworkConfig,      // P2P networking config
    consensus: Option<ConsensusConfig>,  // Consensus (validators only)
    tee_enabled: bool,           // Enable TEE features
    log_level: String,           // trace/debug/info/warn/error
    rpc_addr: String,            // RPC server bind address [default: 127.0.0.1:8545]
    web_addr: String,            // Web API bind address [default: 0.0.0.0:8080]
    mcp_addr: String,            // MCP server bind address [default: 0.0.0.0:3001]
    a2a_addr: String,            // A2A server bind address [default: 0.0.0.0:3002]
    solana_mcp_addr: String,     // Solana MCP [default: 0.0.0.0:3003]
    ethereum_mcp_addr: String,   // Ethereum MCP [default: 0.0.0.0:3004]
    canton_mcp_addr: String,     // Canton MCP [default: 0.0.0.0:3005]
    layerzero_mcp_addr: String,  // LayerZero MCP [default: 0.0.0.0:3006]
    chainlink_mcp_addr: String,  // Chainlink MCP [default: 0.0.0.0:3007]
    lifi_mcp_addr: String,       // LI.FI MCP [default: 0.0.0.0:3008]
    metrics_enabled: bool,       // Enable metrics
    health_enabled: bool,        // Enable health monitoring
    cors_allowed_origins: Vec<String>, // CORS configuration
}
```

**Role-Specific Defaults:**
- **Validator**: Consensus enabled, metrics enabled
- **ModelProvider**: TEE optional
- **TeeProvider**: TEE enabled
- **LightClient**: Minimal config, no special requirements

### 4. Health Monitoring (`health.rs`)

**Purpose:**
Track and report health status for all subsystems to enable observability and automated monitoring.

**Health Levels:**
- `Healthy`: Subsystem operating normally
- `Degraded`: Subsystem experiencing issues but functional
- `Unhealthy`: Subsystem not functional

**Overall Health Calculation:**
- `Healthy`: All subsystems healthy
- `Degraded`: Some subsystems degraded, none unhealthy
- `Unhealthy`: One or more subsystems unhealthy
- `Unknown`: No subsystems registered

**Monitored Subsystems:**
- storage
- network
- tee (optional)
- vm
- consensus (validators only)
- token
- wallet
- settlement
- ai (model registry, agents, swarms)
- bridge

### 5. Metrics Collection (`metrics.rs`)

**Purpose:**
Collect operational metrics for performance monitoring, alerting, and capacity planning.

**Tracked Metrics:**
- `blocks_processed`: Total blocks processed
- `transactions_processed`: Total transactions processed
- `inference_requests`: Total inference requests handled
- `settlements`: Total settlements completed
- `peer_count`: Current peer connections
- `uptime_secs`: Node uptime in seconds

**Computed Metrics:**
- `blocks_per_second`: Average block processing rate
- `transactions_per_second`: Average transaction processing rate

**Thread-Safe Implementation:**
Uses `Arc<AtomicU64>` for lock-free concurrent metric updates.

### 6. JSON-RPC Server (`rpc.rs`)

**Purpose:**
Provide a standard JSON-RPC 2.0 API for querying and interacting with the node.

**Server Design:**
- Async HTTP server using `axum`
- CORS configuration with allowed origins
- Concurrency limit: max 200 in-flight requests
- Request body size limit: 2 MB
- Batch request support (JSON array)
- Graceful shutdown support

**API Categories (242 methods, 26 namespaces):**

1. **Blockchain Methods**
   - `tenzro_blockNumber`, `tenzro_getBlock`, `tenzro_getTransaction`, `tenzro_signTransaction`, `tenzro_signAndSendTransaction`, `tenzro_submitBlock`

2. **Account Methods**
   - `tenzro_createAccount`, `tenzro_createWallet`, `tenzro_getBalance`, `tenzro_getNonce`, `tenzro_listAccounts`

3. **Token Methods**
   - `tenzro_tokenBalance`, `tenzro_totalSupply`

4. **Model Methods**
   - `tenzro_listModels`, `tenzro_inferenceRequest`, `tenzro_downloadModel`, `tenzro_serveModel`, `tenzro_stopModel`, `tenzro_chat`, `tenzro_deleteModel`, `tenzro_listModelEndpoints`, `tenzro_getModelEndpoint`

5. **Settlement Methods**
   - `tenzro_settle`, `tenzro_getSettlement`

6. **Agent Methods**
   - `tenzro_registerAgent`, `tenzro_sendAgentMessage`

7. **Identity Methods**
   - `tenzro_registerIdentity`, `tenzro_importIdentity`, `tenzro_resolveDidDocument`, `tenzro_resolveIdentity`, `tenzro_participate`

8. **Network Methods**
   - `tenzro_nodeInfo`, `tenzro_peerCount`, `tenzro_syncing`, `tenzro_hardwareProfile`, `tenzro_role`

9. **Governance Methods**
   - `tenzro_listProposals`, `tenzro_vote`, `tenzro_getVotingPower`

10. **Payment Methods**
    - `tenzro_createPaymentChallenge`, `tenzro_payMpp`, `tenzro_payX402`, `tenzro_listPaymentSessions`, `tenzro_paymentGatewayInfo`

11. **Staking Methods**
    - `tenzro_stake`, `tenzro_unstake`, `tenzro_registerProvider`, `tenzro_providerStats`

12. **Canton Methods**
    - `tenzro_listCantonDomains`, `tenzro_listDamlContracts`, `tenzro_submitDamlCommand`

13. **TaskMarketplace Methods**
    - `tenzro_postTask`, `tenzro_listTasks`, `tenzro_getTask`, `tenzro_cancelTask`, `tenzro_submitQuote`

14. **AgentMarketplace Methods**
    - `tenzro_listAgentTemplates`, `tenzro_registerAgentTemplate`, `tenzro_getAgentTemplate`

15. **TokenRegistry Methods**
    - `tenzro_createToken`, `tenzro_getToken`, `tenzro_listTokens`, `tenzro_crossVmTransfer`, `tenzro_wrapTnzo`, `tenzro_getTokenBalance`, `tenzro_deployContract`

**EVM-Compatible Methods:**
- `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionCount`, `eth_sendRawTransaction`, `eth_getBlockByNumber`, `eth_getBlockByHash`, `eth_chainId`, `eth_getTransactionReceipt`

**Error Codes:**
- `-32700`: Parse error
- `-32600`: Invalid request
- `-32601`: Method not found
- `-32602`: Invalid params
- `-32603`: Internal error
- `-32000`: Server error (implementation-specific)

### 7. MCP Server (`mcp/server.rs`)

**Purpose:**
Expose 167 tools via Model Context Protocol (Streamable HTTP transport at `/mcp`). Consult `crates/tenzro-node/src/mcp/server.rs` for the authoritative inventory.

**Representative Categories (not exhaustive):**
- Wallet & Ledger (4 tools)
- Network & Blocks (3 tools)
- Identity & Delegation (3 tools)
- Payments (3 tools)
- AI Models & Inference (3 tools)
- Cross-Chain Bridge (3 tools)
- Verification (3 tools)
- Staking & Providers (4 tools)
- Tokens & Contracts (7 tools)

**Transport:** Streamable HTTP on port 3001, protocol version 2025-11-25, `Mcp-Session-Id` header support.

### 8. Ecosystem MCP Servers

Five additional MCP servers for direct blockchain interaction:

- **Solana MCP** (port 3003): 14 tools — Jupiter, SPL, Metaplex, Bonfida SNS
- **Ethereum MCP** (port 3004): 16 tools — Chainlink, ENS, ERC-20, ERC-8004, EAS
- **Canton MCP** (port 3005): 14 tools — DAML, CIP-56, DvP, tokenization
- **LayerZero MCP** (port 3006): 20 tools — V2 messaging, OFT, Value Transfer API, Stargate V2
- **Chainlink MCP** (port 3007): 20 tools — CCIP, data feeds, VRF v2.5, PoR, automation

### 9. A2A Protocol Server (`a2a/server.rs`)

**Purpose:**
Google A2A spec implementation with Agent Card discovery, JSON-RPC 2.0 task execution, and SSE streaming.

**Endpoints:**
- `GET /.well-known/agent.json` — Agent Card discovery
- `POST /a2a` — JSON-RPC 2.0 dispatcher
- `POST /a2a/stream` — Server-Sent Events streaming

**Skills:** wallet, identity, inference, settlement, verification, staking

### 10. Error Handling (`error.rs`)

**Error Type Hierarchy:**
```
NodeError
├── Network(NetworkError)
├── Storage(StorageError)
├── Consensus(ConsensusError)
├── Vm(VmError)
├── Wallet(WalletError)
├── Token(TokenError)
├── Agent(AgentError)
├── Model(ModelError)
├── Settlement(SettlementError)
├── Bridge(BridgeError)
├── Tee(TeeError)
├── Config(String)
├── AlreadyStarted(String)
├── NotStarted(String)
├── InvalidState(String)
├── Io(std::io::Error)
├── Serialization(serde_json::Error)
└── Other(String)
```

**Error Propagation:**
All subsystem errors are wrapped in `NodeError` variants using `#[from]` conversions, providing a single `Result<T>` type for the entire crate.

## Subsystem Dependencies

```
┌─────────────────────────────────────────────────────────┐
│                      TenzroNode                         │
│                 (Orchestration Layer)                   │
└─────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐
   │ Storage │      │  Network  │     │    TEE    │
   └────┬────┘      └─────┬─────┘     └─────┬─────┘
        │                 │                  │
   ┌────▼─────────────────▼──────────────────▼────┐
   │              VM Runtime                       │
   └────┬──────────────────────────────────────────┘
        │
   ┌────▼────┐      ┌──────────┐      ┌──────────┐
   │  Token  │──────│  Wallet  │──────│Settlement│
   └────┬────┘      └──────────┘      └──────────┘
        │
   ┌────▼────┐      ┌──────────┐      ┌──────────┐
   │Consensus│      │    AI    │      │  Bridge  │
   └─────────┘      └──────────┘      └──────────┘
```

**Dependency Rules:**
- Storage has no dependencies (base layer)
- Network depends only on configuration
- VM depends on storage for state
- Consensus depends on network and storage
- Settlement depends on token and treasury
- AI subsystems depend on network and storage
- Bridge depends on network

## Lifecycle Management

### Startup Sequence

```
1. Parse CLI arguments
2. Initialize logging
3. Load configuration
4. Validate configuration
5. Create TenzroNode (state: Created)
6. node.start():
   a. Transition to Starting state
   b. Initialize storage
   c. Initialize network
   d. Initialize TEE (if enabled)
   e. Initialize VM runtime
   f. Initialize token economics
   g. Initialize wallet
   h. Initialize consensus (validators only)
   i. Initialize settlement
   j. Initialize AI infrastructure (with durable persistence)
   k. Initialize bridge
   l. Wire StakingSlashingCallback
   m. Transition to Running state
7. Start RPC server (async)
8. Start Web API server (async)
9. Start MCP server (async)
10. Start A2A server (async)
11. Start ecosystem MCP servers (5 async)
12. Wait for shutdown signal
```

### Shutdown Sequence

```
1. Receive Ctrl+C or SIGTERM signal
2. node.stop():
   a. Transition to Stopping state
   b. Stop bridge
   c. Stop AI infrastructure
   d. Stop settlement
   e. Stop consensus
   f. Stop wallet
   g. Stop token economics
   h. Stop VM runtime
   i. Stop TEE
   j. Stop network
   k. Stop storage
   l. Transition to Stopped state
3. Exit process
```

### State Transitions

Only valid transitions:
- `Created → Starting` (via `start()`)
- `Starting → Running` (after successful initialization)
- `Running → Stopping` (via `stop()` or signal)
- `Stopping → Stopped` (after cleanup)

Invalid transitions raise `NodeError::InvalidState`.

## Multi-Role Support

The node adapts its behavior based on the configured role:

### Validator Node
- **Enabled**: Storage, Network, VM, Token, Wallet, **Consensus**, Settlement, AI (optional), Bridge
- **Responsibilities**: Block production, consensus participation, transaction validation
- **Requirements**: Staked TNZO tokens, reliable network connection, sufficient compute

### ModelProvider
- **Enabled**: Storage, Network, VM, Token, Wallet, Settlement, **AI**, Bridge
- **Responsibilities**: Serve AI model inference requests, earn fees
- **Requirements**: Network bandwidth

### TeeProvider
- **Enabled**: Storage, Network, **TEE**, VM, Token, Wallet, Settlement, AI (optional), Bridge
- **Responsibilities**: Provide confidential computing, hardware attestation
- **Requirements**: TEE-capable hardware (Intel TDX, AMD SEV-SNP, AWS Nitro, or NVIDIA GPU)

### LightClient
- **Enabled**: Storage, Network, VM (light), Wallet, Bridge
- **Responsibilities**: Submit transactions, query state, interact with dApps
- **Requirements**: Minimal resources

## Performance Considerations

### Startup Time
- **Storage**: ~1-2 seconds (RocksDB initialization)
- **Network**: ~2-5 seconds (peer discovery)
- **VM**: ~1 second (executor initialization)
- **Total**: ~5-10 seconds for typical startup

### Memory Usage
- **Base**: ~100-200 MB (node infrastructure)
- **Storage**: ~500 MB (RocksDB cache)
- **Network**: ~100 MB (peer connections, gossipsub)
- **VM**: ~200-500 MB (executor state)
- **AI Models**: ~1-10 GB per model (providers)
- **Total**: ~1-12 GB depending on role

### CPU Usage
- **Idle**: ~1-5% (event loops, heartbeats)
- **Syncing**: ~50-100% (block validation, state updates)
- **Consensus**: ~10-30% (validators during block production)
- **Inference**: ~80-100% (providers serving requests)

## Security Considerations

1. **Keystore Protection**: Validator keys stored encrypted at rest (Argon2id KDF)
2. **Network Security**: Noise protocol for encrypted P2P communication
3. **TEE Attestation**: Remote attestation for TEE providers with real hardware ioctl
4. **RPC Access Control**: CORS configuration, concurrency limits, body size limits
5. **Resource Limits**: Configurable limits on memory, connections, request sizes
6. **Equivocation Detection**: Double-vote detection with 10% stake slashing

## Testing Strategy

### Unit Tests
- Individual function correctness
- Error handling edge cases
- Configuration validation

### Integration Tests
- Subsystem interaction
- Startup/shutdown sequences
- State transitions

### End-to-End Tests
- Full node lifecycle
- Multi-node scenarios
- Network partition handling

### Performance Tests
- Startup time benchmarks
- Memory usage profiling
- Transaction throughput

## Observability

### Logs
- Structured logging with `tracing`
- Multiple log levels per module
- JSON format support

### Metrics
- In-memory metrics collection
- Health check endpoint
- Atomic counters

### Tracing
- Span tracking across subsystems
- Performance profiling

## Conclusion

The `tenzro-node` crate provides a production-ready, feature-complete full node implementation for Tenzro Network. Its modular architecture, comprehensive health monitoring, multi-role support, and durable AI infrastructure persistence make it suitable for diverse deployment scenarios from local development to large-scale production networks.
