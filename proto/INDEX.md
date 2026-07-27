# Tenzro Network Protocol Buffers - Index

Protocol definitions for Tenzro Network (the verification and settlement protocol) and Tenzro Ledger (the settlement layer with TNZO governance token).

## Quick Navigation

### Documentation
- **[README.md](README.md)** - Comprehensive guide with usage examples
- **[OVERVIEW.md](OVERVIEW.md)** - High-level architecture and design
- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick reference for common patterns
- **[STRUCTURE.txt](STRUCTURE.txt)** - Directory structure and statistics
- **[INDEX.md](INDEX.md)** - This file

### Configuration
- **[buf.yaml](buf.yaml)** - Buf linting and breaking change configuration
- **[buf.gen.yaml](buf.gen.yaml)** - Code generation configuration
- **[Makefile](Makefile)** - Build automation

### Proto Definitions (`tenzro/v1/`)

#### Core Protocol
1. **[types.proto](tenzro/v1/types.proto)** - Foundation types
   - Hash, Address, Signature, Timestamp
   - ChainId, BlockHeight, AssetId

2. **[transaction.proto](tenzro/v1/transaction.proto)** - Transaction structures
   - Transaction, TransactionReceipt, Log
   - TransactionType, TransactionStatus enums

3. **[block.proto](tenzro/v1/block.proto)** - Block structures
   - Block, BlockHeader, ConsensusProof
   - CompactBlock for efficient propagation

#### Consensus
4. **[consensus.proto](tenzro/v1/consensus.proto)** - HotStuff-2 consensus
   - Proposal, Vote, QuorumCertificate
   - ViewChange, TimeoutCertificate, ValidatorSet

#### Network
5. **[network.proto](tenzro/v1/network.proto)** - P2P networking
   - NetworkMessage, PeerInfo, PeerExchange
   - BlockAnnounce, DataRequest/Response, Ping/Pong

#### Security
6. **[tee.proto](tenzro/v1/tee.proto)** - Trusted Execution Environments
   - TeeAttestation, AttestationResult
   - TeeIdentity, TeeRequest/Response

#### AI Infrastructure
7. **[model.proto](tenzro/v1/model.proto)** - AI models and inference
   - ModelInfo, InferenceRequest/Response
   - InferenceParameters, ModelStatistics

8. **[agent.proto](tenzro/v1/agent.proto)** - AI agents
   - AgentIdentity, AgentMessage, AgentTask
   - AgentCoordination, AgentReputation

#### Economics
9. **[settlement.proto](tenzro/v1/settlement.proto)** - Payment settlements
   - SettlementRequest/Receipt, ServiceProof
   - BatchSettlement, SettlementDispute, PaymentChannel

#### Governance
10. **[governance.proto](tenzro/v1/governance.proto)** - On-chain governance
    - GovernanceProposal, GovernanceVote
    - ParameterChange, TreasurySpend, ValidatorSetChange

#### Interoperability
11. **[bridge.proto](tenzro/v1/bridge.proto)** - Cross-chain bridges
    - BridgeMessage, BridgeTransfer, TransferProof
    - BridgeConfig, BridgeChallenge, LiquidityPool

#### RPC
12. **[rpc.proto](tenzro/v1/rpc.proto)** - gRPC service definitions
    - TenzroNode service with 40+ RPC methods
    - Request/response messages for all operations

## By Use Case

### Building a Blockchain Client
Start here:
1. [rpc.proto](tenzro/v1/rpc.proto) - RPC methods
2. [types.proto](tenzro/v1/types.proto) - Core types
3. [transaction.proto](tenzro/v1/transaction.proto) - Sending transactions
4. [block.proto](tenzro/v1/block.proto) - Reading blocks

### Building an AI Model Provider
Start here:
1. [model.proto](tenzro/v1/model.proto) - Model registration and inference
2. [tee.proto](tenzro/v1/tee.proto) - TEE attestations
3. [settlement.proto](tenzro/v1/settlement.proto) - Receiving payments
4. [rpc.proto](tenzro/v1/rpc.proto) - RPC integration

### Building an AI Agent
Start here:
1. [agent.proto](tenzro/v1/agent.proto) - Agent identity and messaging
2. [model.proto](tenzro/v1/model.proto) - Using models
3. [settlement.proto](tenzro/v1/settlement.proto) - Payments
4. [rpc.proto](tenzro/v1/rpc.proto) - Node communication

### Building a Validator Node
Start here:
1. [consensus.proto](tenzro/v1/consensus.proto) - Consensus protocol
2. [block.proto](tenzro/v1/block.proto) - Block production
3. [network.proto](tenzro/v1/network.proto) - P2P communication
4. [governance.proto](tenzro/v1/governance.proto) - Governance participation

### Building a Bridge
Start here:
1. [bridge.proto](tenzro/v1/bridge.proto) - Bridge protocols
2. [network.proto](tenzro/v1/network.proto) - Message relay
3. [settlement.proto](tenzro/v1/settlement.proto) - Fee collection
4. [rpc.proto](tenzro/v1/rpc.proto) - RPC methods

### Participating in Governance
Start here:
1. [governance.proto](tenzro/v1/governance.proto) - Proposals and voting
2. [transaction.proto](tenzro/v1/transaction.proto) - Vote transactions
3. [rpc.proto](tenzro/v1/rpc.proto) - Governance RPCs

## By Message Type

### Core Types
- **[types.proto](tenzro/v1/types.proto)**: Hash, Address, Signature, Timestamp, ChainId, BlockHeight, AssetId

### Data Structures
- **[block.proto](tenzro/v1/block.proto)**: Block, BlockHeader, ConsensusProof
- **[transaction.proto](tenzro/v1/transaction.proto)**: Transaction, TransactionReceipt, Log

### Consensus Messages
- **[consensus.proto](tenzro/v1/consensus.proto)**: Proposal, Vote, QuorumCertificate, ViewChange, TimeoutCertificate

### Network Messages
- **[network.proto](tenzro/v1/network.proto)**: NetworkMessage, PeerInfo, BlockAnnounce, DataRequest/Response

### AI Messages
- **[model.proto](tenzro/v1/model.proto)**: ModelInfo, InferenceRequest/Response, InferenceParameters
- **[agent.proto](tenzro/v1/agent.proto)**: AgentIdentity, AgentMessage, AgentTask, AgentCoordination

### Economic Messages
- **[settlement.proto](tenzro/v1/settlement.proto)**: SettlementRequest/Receipt, ServiceProof, PaymentChannel

### Governance Messages
- **[governance.proto](tenzro/v1/governance.proto)**: GovernanceProposal, GovernanceVote, ParameterChange

### Security Messages
- **[tee.proto](tenzro/v1/tee.proto)**: TeeAttestation, AttestationResult, TeeRequest/Response

### Bridge Messages
- **[bridge.proto](tenzro/v1/bridge.proto)**: BridgeMessage, BridgeTransfer, BridgeConfig

## Quick Commands

```bash
# Navigate to proto directory
cd /Users/hilarl/AI/tenzronetwork/proto

# Generate all code
make generate

# Lint proto files
make lint

# Format proto files
make format

# Validate proto files
make validate

# Check for breaking changes
make check

# Clean generated files
make clean

# Show help
make help
```

## Common Tasks

### View a specific proto file
```bash
cat tenzro/v1/types.proto
```

### Search for a message type
```bash
grep -r "message ModelInfo" tenzro/
```

### Count messages in a file
```bash
grep -c "^message" tenzro/v1/model.proto
```

### Find all enums
```bash
grep "^enum" tenzro/v1/*.proto
```

### Generate code for specific language
```bash
make protoc-rust   # Rust
make protoc-go     # Go
```

## Integration Examples

### Rust
```rust
use tenzro::v1::{Transaction, TransactionType};

let tx = Transaction {
    chain_id: Some(ChainId { value: 1 }),
    // ... other fields
};
```

### Go
```go
import "github.com/tenzronetwork/tenzro/gen/go/tenzro/v1"

tx := &v1.Transaction{
    ChainId: &v1.ChainId{Value: 1},
    // ... other fields
}
```

### TypeScript
```typescript
import { Transaction, TransactionType } from './proto/tenzro/v1/transaction_pb';

const tx = new Transaction();
tx.setChainId(new ChainId().setValue(1));
```

## File Dependencies

```
types.proto (no dependencies)
  ├── transaction.proto
  ├── tee.proto
  ├── network.proto
  ├── settlement.proto
  ├── agent.proto
  ├── governance.proto
  ├── bridge.proto
  ├── block.proto (also imports transaction, tee)
  ├── consensus.proto (also imports block)
  ├── model.proto (also imports tee)
  └── rpc.proto (imports ALL)
```

## Message Statistics

| File | Messages | Enums | Services | LOC |
|------|----------|-------|----------|-----|
| types.proto | 7 | 0 | 0 | 43 |
| transaction.proto | 4 | 2 | 0 | 102 |
| block.proto | 4 | 0 | 0 | 67 |
| consensus.proto | 9 | 2 | 0 | 158 |
| network.proto | 9 | 3 | 0 | 154 |
| tee.proto | 9 | 4 | 0 | 169 |
| model.proto | 10 | 3 | 0 | 224 |
| settlement.proto | 13 | 6 | 0 | 217 |
| agent.proto | 12 | 4 | 0 | 237 |
| governance.proto | 13 | 6 | 0 | 263 |
| bridge.proto | 15 | 7 | 0 | 284 |
| rpc.proto | 40+ | 0 | 1 | 433 |
| **TOTAL** | **150+** | **37** | **1** | **~2,500** |

## Version History

- **v1** (2026-03-17) - Initial release
  - Core protocol messages
  - HotStuff-2 consensus
  - AI model and agent support
  - TEE attestation
  - Cross-chain bridges
  - On-chain governance
  - Complete RPC interface

## Support

For questions or issues:
1. Check [README.md](README.md) for detailed documentation
2. See [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for common patterns
3. Review [OVERVIEW.md](OVERVIEW.md) for architecture
4. Refer to individual proto files for specific messages

## Contributing

When modifying proto files:
1. Follow proto3 naming conventions
2. Add comprehensive comments
3. Update documentation
4. Run `make lint` and `make validate`
5. Update this index if adding new files

## License

See the main project LICENSE file.
