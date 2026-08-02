# Tenzro Network Protocol Buffers

This directory contains the Protocol Buffer definitions for Tenzro Network's P2P communication and RPC interfaces. These messages are used across Tenzro Ledger (the settlement layer).

## Directory Structure

```
proto/
└── tenzro/
    └── v1/
        ├── types.proto           # Core types (Hash, Address, Signature, etc.)
        ├── transaction.proto     # Transaction messages
        ├── block.proto           # Block messages
        ├── consensus.proto       # HotStuff-2 consensus messages
        ├── network.proto         # P2P network messages
        ├── tee.proto             # TEE attestation messages
        ├── model.proto           # AI model and inference messages
        ├── settlement.proto      # Payment settlement messages
        ├── agent.proto           # AI agent messages
        ├── governance.proto      # Governance proposal and voting messages
        ├── bridge.proto          # Cross-chain bridge messages
        ├── canton.proto          # Canton/DAML 3.x integration
        └── rpc.proto             # gRPC service definitions
```

## Message Categories

### Core Protocol Messages

- **types.proto**: Foundational types used across all messages
  - Hash, Address, Signature, Timestamp
  - ChainId, BlockHeight, AssetId

- **transaction.proto**: Transaction structures
  - Transaction with support for transfers, contract calls, agent actions, inference requests
  - TransactionReceipt with execution results
  - Support for multiple transaction types

- **block.proto**: Block structures
  - BlockHeader with state roots and consensus proof
  - Block with transactions and TEE attestations
  - CompactBlock for efficient propagation

- **consensus.proto**: HotStuff-2 consensus protocol
  - Proposal, Vote, QuorumCertificate
  - ViewChange, NewView, TimeoutCertificate
  - ValidatorSet and Validator information

### Network Layer

- **network.proto**: P2P networking
  - NetworkMessage envelope for all P2P messages
  - PeerInfo and peer discovery
  - BlockAnnounce, DataRequest/Response
  - Ping/Pong for connectivity

### TEE & Security

- **tee.proto**: Trusted Execution Environment
  - TeeAttestation for Intel TDX, AMD SEV-SNP, AWS Nitro
  - AttestationResult with security level assessment
  - TeeRequest/Response for secure computation

### AI Infrastructure

- **model.proto**: AI model registry and inference
  - ModelInfo with modalities (text, image, audio, multimodal)
  - InferenceRequest/Response with TEE support
  - InferenceParameters for model configuration
  - ModelStatistics for usage tracking

- **agent.proto**: AI agent framework
  - AgentIdentity and AgentConfig
  - AgentMessage for inter-agent communication
  - AgentTask for task execution
  - AgentCoordination for multi-agent workflows

### Economic Layer

- **settlement.proto**: Payment and settlement
  - SettlementRequest/Receipt for service payments
  - ServiceProof for delivery verification
  - BatchSettlement for efficient processing
  - PaymentChannel for instant settlements
  - SettlementDispute for conflict resolution

### Governance

- **governance.proto**: On-chain governance
  - GovernanceProposal with multiple proposal types
  - GovernanceVote (For, Against, Abstain, Veto)
  - ParameterChange, TreasurySpend, ValidatorSetChange
  - Delegation for voting power delegation

### Interoperability

- **bridge.proto**: Cross-chain bridges
  - BridgeMessage and BridgeTransfer envelopes
  - Adapter targets: Wormhole NTT (canonical TNZO), LayerZero V2 (with mandatory Tenzro DVN), Chainlink CCIP + CCT v1.6+, deBridge DLN, Li.Fi aggregator
  - BridgeChallenge for dispute resolution
  - LiquidityPool for liquidity-based bridges

- **canton.proto**: Canton/DAML 3.x integration
  - DamlContractId, DamlTemplateId, DamlParty, DamlValue
  - DamlCommand, DamlEvent, DamlTransaction
  - Synchronizer topology and Ledger API types

### RPC Interface

- **rpc.proto**: gRPC service definitions
  - TenzroNode service with 40+ RPC methods
  - Chain queries (blocks, transactions, receipts)
  - Account operations (balance, nonce)
  - Model operations (list, register, inference)
  - Settlement operations
  - Agent operations
  - Governance operations
  - Bridge operations
  - Node status and metrics
  - Streaming subscriptions for blocks, transactions, events

## Compilation Status

**These proto files are documentation-only.** No `build.rs` or `prost-build`
compilation exists. All Rust types are hand-coded in the respective crates
(primarily `tenzro-types`) to allow richer semantics (builder patterns,
custom serde, trait impls) that generated code cannot provide.

This is an intentional design decision — the proto definitions serve as the
canonical API specification and are kept in sync manually with the Rust types.

If you need to generate client code for other languages, you can use:

```bash
# Go
protoc --go_out=../go/proto --go-grpc_out=../go/proto proto/tenzro/v1/*.proto

# TypeScript
protoc --ts_out=../sdk/tenzro-ts-sdk/src/proto proto/tenzro/v1/*.proto
```

## Usage Examples

### Submitting a Transaction (Rust)

```rust
use tenzro::v1::{Transaction, TransactionType, Address, AssetId};

let tx = Transaction {
    chain_id: Some(ChainId { value: 1 }),
    nonce: 42,
    from: Some(Address { value: sender_bytes }),
    to: Some(Address { value: recipient_bytes }),
    value: amount_bytes.to_vec(),
    asset: Some(AssetId { value: "TENZ".to_string() }),
    data: vec![],
    gas_limit: 21000,
    gas_price: gas_price_bytes.to_vec(),
    signature: Some(signature),
    tx_type: TransactionType::Transfer as i32,
};
```

### Requesting Inference

```rust
use tenzro::v1::{InferenceRequest, InferenceParameters};

let request = InferenceRequest {
    request_id: "req_12345".to_string(),
    model_id: "llama-3-70b".to_string(),
    requester: Some(Address { value: user_address }),
    input: prompt_bytes,
    parameters: Some(InferenceParameters {
        temperature: 700, // 0.7
        max_tokens: 1000,
        ..Default::default()
    }),
    max_price: 1000000,
    require_tee: true,
    ..Default::default()
};
```

### Consensus Voting

```rust
use tenzro::v1::{Vote, VotePhase};

let vote = Vote {
    block_hash: Some(block_hash),
    view: 42,
    voter: Some(validator_address),
    signature: Some(signature),
    phase: VotePhase::Commit as i32,
    partial_signature: bls_partial_sig,
};
```

## Message Design Principles

1. **Extensibility**: All messages use proto3
2. **Type Safety**: Strong typing with explicit enums and message types
3. **Efficiency**: Uses bytes for large integers (u128) to avoid precision loss
4. **Security**: All sensitive operations require signatures
5. **Modularity**: Clear separation of concerns across proto files
6. **Documentation**: Comprehensive comments on all messages and fields

## Integration with Rust Crates

The Rust types corresponding to these proto definitions are hand-coded in:

- `tenzro-types`: Core types and message structures
- `tenzro-network`: P2P networking layer
- `tenzro-consensus`: HotStuff-2 consensus implementation
- `tenzro-node`: RPC server implementation
- `tenzro-cli`: Client for interacting with nodes

## Versioning

Pre-alpha. The package is `tenzro.v1`. Schemas may change without notice while the network has no live external users.

## Contributing

When adding new messages:
1. Choose the appropriate proto file or create a new one
2. Add comprehensive comments
3. Follow existing naming conventions (PascalCase for messages, SCREAMING_SNAKE_CASE for enums)
4. Update this README
5. Update the corresponding hand-coded Rust types (primarily in `tenzro-types`) to match — the proto definitions are documentation-only and stay in sync with the Rust source manually

## License

See the main project LICENSE file.
