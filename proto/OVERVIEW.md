# Tenzro Network Protocol Buffers - Overview

## Quick Stats

- **Total Proto Files**: 12
- **Package**: `tenzro.v1`
- **Syntax**: `proto3`
- **Primary Service**: `TenzroNode` with 40+ RPC methods
- **Token**: TNZO (governance token for Tenzro Ledger)

## File Structure

```
proto/
├── buf.yaml                    # Buf configuration
├── buf.gen.yaml                # Code generation config
├── Makefile                    # Build automation
├── README.md                   # Detailed documentation
├── OVERVIEW.md                 # This file
└── tenzro/v1/
    ├── types.proto             # 7 core types
    ├── transaction.proto       # Transaction messages
    ├── block.proto             # Block structures
    ├── consensus.proto         # HotStuff-2 consensus
    ├── network.proto           # P2P networking
    ├── tee.proto              # TEE attestations
    ├── model.proto            # AI models & inference
    ├── settlement.proto       # Payment settlements
    ├── agent.proto            # AI agents
    ├── governance.proto       # On-chain governance
    ├── bridge.proto           # Cross-chain bridges
    └── rpc.proto              # gRPC service
```

## Core Message Types

### types.proto
Foundation types used throughout the protocol:
- `Hash` - Cryptographic hash (32 bytes)
- `Address` - Account address (20 bytes)
- `Signature` - Digital signature with public key
- `Timestamp` - Unix timestamp in milliseconds
- `ChainId` - Blockchain network identifier
- `BlockHeight` - Block number
- `AssetId` - Token/asset identifier

### transaction.proto
Transaction handling:
- `Transaction` - Core transaction structure with 11 fields
- `TransactionReceipt` - Execution result with logs
- `TransactionType` enum - 7 types (Transfer, ContractCall, AgentAction, InferenceRequest, etc.)
- `TransactionStatus` enum - Success/Failure/Pending
- `Log` - Event logs from execution

### block.proto
Blockchain blocks:
- `Block` - Header + transactions + attestations
- `BlockHeader` - Metadata with Merkle roots
- `ConsensusProof` - Validator signatures
- `CompactBlock` - Efficient propagation format

### consensus.proto
HotStuff-2 Byzantine Fault Tolerant consensus:
- `Proposal` - Leader's block proposal
- `Vote` - Validator vote (Prepare/Commit/Decide phases)
- `QuorumCertificate` - Proof of quorum with BLS aggregation
- `ViewChange` - Leader change mechanism
- `TimeoutCertificate` - View timeout proof
- `ValidatorSet` - Active validators with voting power

### network.proto
P2P networking layer:
- `NetworkMessage` - Envelope for all P2P messages
- `MessageType` enum - 12 message types
- `PeerInfo` - Peer discovery and metadata
- `BlockAnnounce` - New block propagation
- `DataRequest/Response` - Sync protocol
- `Ping/Pong` - Connectivity checks

### tee.proto
Trusted Execution Environment:
- `TeeAttestation` - TEE proof (Intel TDX, AMD SEV-SNP, AWS Nitro)
- `AttestationResult` - Verification result with security level
- `TeeIdentity` - TEE instance identity
- `TeeRequest/Response` - Secure computation
- `TeeVendor` enum - 5 TEE platforms

### model.proto
AI model infrastructure:
- `ModelInfo` - Model registry entry
- `ModelModality` enum - 9 types (Text, Image, Audio, Multimodal, Code, etc.)
- `InferenceRequest/Response` - Model execution
- `InferenceParameters` - Model configuration (temperature, top_p, etc.)
- `InferenceMetadata` - Token counts, latency, etc.
- `ModelStatistics` - Usage tracking

### settlement.proto
Economic layer:
- `SettlementRequest/Receipt` - Service payment flow
- `ServiceType` enum - 9 service types
- `ServiceProof` - Delivery verification
- `BatchSettlement` - Multi-service settlement
- `SettlementDispute` - Conflict resolution
- `PaymentChannel` - State channels for instant payments

### agent.proto
AI agent framework:
- `AgentIdentity` - Agent registration
- `AgentMessage` - Inter-agent communication
- `AgentMessageType` enum - 10 types
- `AgentTask` - Task execution
- `AgentCoordination` - Multi-agent workflows
- `AgentReputation` - Trust scoring

### governance.proto
On-chain governance:
- `GovernanceProposal` - Proposal structure
- `ProposalType` enum - 10 types (ParameterChange, ProtocolUpgrade, etc.)
- `GovernanceVote` - Voting (For/Against/Abstain/Veto)
- `ParameterChange` - Network parameter updates
- `TreasurySpend` - Treasury disbursement with milestones
- `ValidatorSetChange` - Validator management

### bridge.proto
Cross-chain interoperability:
- `BridgeMessage` - Cross-chain message
- `BridgeProtocol` enum - 6 protocols (Lock&Mint, Burn&Mint, AtomicSwap, ZK, etc.)
- `BridgeTransfer` - Asset transfer across chains
- `TransferProof` - Cryptographic proof types
- `BridgeChallenge` - Dispute mechanism
- `LiquidityPool` - Bridge liquidity management

### rpc.proto
gRPC service interface:
- **Chain Methods**: GetBlock, GetTransaction, GetTransactionReceipt, SubmitTransaction
- **Account Methods**: GetBalance, GetNonce, GetAccount
- **Model Methods**: ListModels, GetModel, SubmitInference, RegisterModel
- **Settlement Methods**: Settle, GetSettlementReceipt, DisputeSettlement
- **Agent Methods**: RegisterAgent, SendAgentMessage, SubmitAgentTask, ListAgents
- **Governance Methods**: ListProposals, SubmitProposal, Vote
- **Bridge Methods**: InitiateBridgeTransfer, GetBridgeTransfer, ListBridges
- **Node Methods**: NodeInfo, NodeStatus, GetPeers, GetMetrics
- **Streaming**: SubscribeBlocks, SubscribeTransactions, SubscribeEvents

## Key Design Features

### 1. Economic Primitives
- Payment settlements with proof of service
- Multi-asset support
- Payment channels for instant settlements
- Dispute resolution mechanisms

### 2. AI-First Design
- Native model registry and inference
- TEE support for confidential compute
- Agent-to-agent messaging
- Multimodal model support

### 3. Security
- All sensitive operations require signatures
- TEE attestations for secure execution
- Multi-signature support
- BLS signature aggregation for efficiency

### 4. Scalability
- Compact block propagation
- State channels for off-chain payments
- Batch settlements
- Efficient serialization with Protocol Buffers

### 5. Interoperability
- Multiple bridge protocols
- Cross-chain message passing
- Asset mapping between chains
- Challenge-based fraud proofs

### 6. Governance
- On-chain parameter changes
- Treasury management with milestones
- Validator set updates
- Multiple proposal types

## Integration Points

### Rust Crates
```
tenzro-types      → Core types and message structures
tenzro-network    → P2P networking implementation
tenzro-consensus  → HotStuff-2 consensus engine
tenzro-tee        → TEE attestation verification
tenzro-model      → Model registry and inference
tenzro-settlement → Payment settlement logic
tenzro-agent      → Agent runtime and messaging
tenzro-node       → RPC server implementation
```

### SDKs
```
tenzro-sdk        → Rust SDK for building applications
tenzro-ts-sdk     → TypeScript/JavaScript SDK
```

## Message Flow Examples

### Transaction Flow
```
User → SubmitTransaction(Transaction)
  → Node validates & broadcasts
  → Consensus reaches quorum
  → Transaction included in Block
  → Receipt generated
  → User queries GetTransactionReceipt
```

### Inference Flow
```
User → SubmitInference(InferenceRequest)
  → Node routes to model provider
  → Provider executes in TEE
  → TeeAttestation generated
  → InferenceResponse with attestation
  → SettlementRequest for payment
  → SettlementReceipt confirms payment
```

### Cross-Chain Transfer Flow
```
User → InitiateBridgeTransfer(BridgeTransfer)
  → Lock/burn assets on source chain
  → BridgeMessage created with proof
  → Relayers relay to destination
  → Mint/unlock on destination chain
  → BridgeTransfer status updated
```

### Agent Coordination Flow
```
User → SubmitAgentTask(AgentTask)
  → AgentCoordination created
  → Multiple AgentMessage exchanges
  → Each AgentStep executed
  → Results aggregated
  → SettlementRequest for each agent
```

## Compilation

### Quick Start
```bash
cd proto/
make generate
```

### Using Buf
```bash
buf generate
```

### Using Protoc
```bash
make protoc-rust
make protoc-go
```

## Versioning Strategy

Pre-alpha. The package is `tenzro.v1`. Schemas may change without notice while the network has no live external users.

## Standards Compliance

- **Proto3 Syntax**: Modern protocol buffers
- **gRPC**: Standard RPC framework
- **BLS Signatures**: Efficient signature aggregation
- **Merkle Proofs**: State verification
- **TEE Standards**: Intel TDX, AMD SEV-SNP, AWS Nitro

## Performance Considerations

- **Compact Encoding**: Protocol Buffers are highly efficient
- **Lazy Deserialization**: Only parse needed fields
- **Streaming RPCs**: For real-time data (blocks, events)
- **Batch Operations**: BatchSettlement, multiple votes
- **Signature Aggregation**: BLS for consensus efficiency

## Security Considerations

- All state-changing operations require signatures
- TEE attestations verified before accepting results
- Challenge periods for optimistic bridges
- Dispute resolution for settlements
- Reputation system for agents and providers

## Future Enhancements

Potential additions in future versions:
- Zero-knowledge proof primitives
- Privacy-preserving transactions
- Advanced smart contract ABIs
- Layer 2 scaling solutions
- Advanced bridge mechanisms
- Federated learning protocols

## Resources

- [Protocol Buffers Documentation](https://protobuf.dev/)
- [gRPC Documentation](https://grpc.io/)
- [Buf Documentation](https://buf.build/docs/)
- [HotStuff-2 Paper](https://arxiv.org/abs/2305.00216)
- [TEE Attestation Standards](https://confidentialcomputing.io/)

## Contributing

See the main README.md for detailed contribution guidelines. When modifying proto files:
1. Add comprehensive comments
2. Follow existing naming conventions
3. Update documentation
4. Run `make lint` and `make validate`
