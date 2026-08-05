# Tenzro Protocol Buffers - Quick Reference

## Most Common Messages

### Sending a Transaction
```protobuf
// From: transaction.proto
message Transaction {
  ChainId chain_id = 1;
  uint64 nonce = 2;
  Address from = 3;
  Address to = 4;
  bytes value = 5;              // u128 as bytes
  AssetId asset = 6;
  bytes data = 7;
  uint64 gas_limit = 8;
  bytes gas_price = 9;          // u128 as bytes
  Signature signature = 10;
  TransactionType tx_type = 11;
}
```

### Requesting Inference
```protobuf
// From: model.proto
message InferenceRequest {
  string request_id = 1;
  string model_id = 2;
  Address requester = 3;
  bytes input = 4;
  InferenceParameters parameters = 5;
  uint64 max_price = 6;
  bool require_tee = 7;
}

message InferenceResponse {
  string request_id = 1;
  string model_id = 2;
  Address provider = 3;
  bytes output = 4;
  InferenceMetadata metadata = 5;
  uint64 price = 6;
  TeeAttestation attestation = 7;
}
```

### Block Structure
```protobuf
// From: block.proto
message Block {
  BlockHeader header = 1;
  repeated Transaction transactions = 2;
  repeated TeeAttestation attestations = 3;
}

message BlockHeader {
  BlockHeight height = 1;
  Timestamp timestamp = 2;
  Hash parent_hash = 3;
  Hash state_root = 4;
  Hash transactions_root = 5;
  Address proposer = 6;
  ConsensusProof consensus_proof = 7;
}
```

### Settlement/Payment
```protobuf
// From: settlement.proto
message SettlementRequest {
  string request_id = 1;
  Address payer = 2;
  Address payee = 3;
  bytes amount = 4;           // u128 as bytes
  AssetId asset = 5;
  ServiceType service_type = 6;
  ServiceProof proof = 7;
}

message SettlementReceipt {
  string receipt_id = 1;
  Hash transaction_hash = 2;
  Address payer = 3;
  Address payee = 4;
  bytes amount = 5;
  bytes network_fee = 6;
  SettlementStatus status = 7;
}
```

## RPC Methods Cheat Sheet

### Chain Queries
```protobuf
rpc GetBlockNumber(Empty) returns (BlockNumberResponse);
rpc GetBlock(GetBlockRequest) returns (Block);
rpc GetTransaction(GetTransactionRequest) returns (Transaction);
rpc GetTransactionReceipt(GetTransactionRequest) returns (TransactionReceipt);
rpc SubmitTransaction(Transaction) returns (SubmitTransactionResponse);
```

### Account Queries
```protobuf
rpc GetBalance(GetBalanceRequest) returns (BalanceResponse);
rpc GetNonce(GetNonceRequest) returns (NonceResponse);
rpc GetAccount(GetAccountRequest) returns (AccountResponse);
```

### Model & Inference
```protobuf
rpc ListModels(ListModelsRequest) returns (ListModelsResponse);
rpc GetModel(GetModelRequest) returns (ModelInfo);
rpc SubmitInference(InferenceRequest) returns (InferenceResponse);
rpc RegisterModel(ModelRegistration) returns (RegisterModelResponse);
```

### Agent Operations
```protobuf
rpc RegisterAgent(AgentConfig) returns (AgentIdentity);
rpc SendAgentMessage(AgentMessage) returns (SendMessageResponse);
rpc SubmitAgentTask(AgentTask) returns (AgentTaskResponse);
rpc ListAgents(ListAgentsRequest) returns (ListAgentsResponse);
```

### Governance
```protobuf
rpc ListProposals(ListProposalsRequest) returns (ListProposalsResponse);
rpc SubmitProposal(GovernanceProposal) returns (SubmitProposalResponse);
rpc Vote(GovernanceVote) returns (VoteResponse);
```

## Enum Quick Reference

### TransactionType
```protobuf
TRANSFER = 0;
CONTRACT_CALL = 1;
AGENT_ACTION = 2;
INFERENCE_REQUEST = 3;
TEE_OPERATION = 4;
STAKE_DEPOSIT = 5;
GOVERNANCE_VOTE = 6;
```

### ModelModality
```protobuf
TEXT = 0;
IMAGE = 1;
AUDIO = 2;
VIDEO = 3;
TEXT_IMAGE = 4;
TEXT_AUDIO = 5;
MULTIMODAL = 6;
CODE = 7;
EMBEDDING = 8;
```

### ServiceType
```protobuf
INFERENCE = 0;
STORAGE = 1;
COMPUTE = 2;
BANDWIDTH = 3;
TEE_EXECUTION = 4;
AGENT_SERVICE = 5;
TRAINING = 6;
DATA_ACCESS = 7;
CUSTOM = 8;
```

### TeeVendor
```protobuf
INTEL_TDX = 0;
AMD_SEV_SNP = 1;
AWS_NITRO = 2;
INTEL_SGX = 3;
ARM_TRUSTZONE = 4;
```

### BridgeProtocol
```protobuf
LOCK_AND_MINT = 0;
BURN_AND_MINT = 1;
LIQUIDITY_POOL = 2;
ATOMIC_SWAP = 3;
OPTIMISTIC = 4;
ZK_BRIDGE = 5;
```

### VotePhase (Consensus)
```protobuf
PREPARE = 0;
COMMIT = 1;
DECIDE = 2;
```

### ProposalType (Governance)
```protobuf
PARAMETER_CHANGE = 0;
PROTOCOL_UPGRADE = 1;
VALIDATOR_SET_CHANGE = 2;
TREASURY_SPEND = 3;
MODEL_REGISTRY_UPDATE = 4;
FEE_CHANGE = 5;
EMERGENCY_ACTION = 6;
TEXT_PROPOSAL = 7;
AGENT_POLICY = 8;
TEE_POLICY = 9;
```

## Import Relationships

```
types.proto (base)
  ↓
  ├─→ transaction.proto
  ├─→ block.proto (imports transaction)
  ├─→ consensus.proto (imports block)
  ├─→ network.proto
  ├─→ tee.proto
  ├─→ model.proto (imports tee)
  ├─→ settlement.proto
  ├─→ agent.proto
  ├─→ governance.proto
  ├─→ bridge.proto
  └─→ rpc.proto (imports all)
```

## Common Patterns

### Address Pattern
```protobuf
message Address {
  bytes value = 1;  // 20 bytes
}
```

### Hash Pattern
```protobuf
message Hash {
  bytes value = 1;  // 32 bytes
}
```

### Large Numbers (u128)
```protobuf
// Always use bytes for u128 to avoid precision loss
bytes value = 1;  // 16 bytes, little-endian
```

### Signature Pattern
```protobuf
message Signature {
  bytes bytes = 1;        // Signature bytes (64 bytes for Ed25519)
  bytes public_key = 2;   // Public key (32 bytes for Ed25519)
}
```

### Timestamp Pattern
```protobuf
message Timestamp {
  int64 millis = 1;  // Unix timestamp in milliseconds
}
```

## Field Numbering Convention

- 1-15: Most common fields (single byte encoding)
- 16+: Less common fields
- Never reuse field numbers
- Reserve deprecated field numbers

## Common Request/Response Patterns

### List Pattern
```protobuf
message ListXRequest {
  uint32 limit = 1;   // Max items to return
  uint32 offset = 2;  // Pagination offset
  // filters...
}

message ListXResponse {
  repeated X items = 1;
  uint32 total_count = 2;
}
```

### Get Pattern
```protobuf
message GetXRequest {
  string x_id = 1;
}

// Response is the X message itself
```

### Submit Pattern
```protobuf
message SubmitXRequest {
  // X data...
}

message SubmitXResponse {
  string x_id = 1;
  bool accepted = 2;
  string error_message = 3;
}
```

## Size Guidelines

### Fixed Size Types
- Address: 20 bytes
- Hash: 32 bytes
- Signature: 64 bytes (Ed25519)
- Public Key: 32 bytes (Ed25519)
- u128: 16 bytes

### Variable Size Limits
- Model input: Configurable by model
- Agent messages: Typically < 1MB
- Transaction data: < 1MB recommended
- Block size: Target ~1MB

## Code Generation Commands

```bash
# Generate all
make generate

# Generate Rust only
make protoc-rust

# Generate Go only
make protoc-go

# Lint
make lint

# Format
make format

# Validate
make validate
```

## Testing Proto Changes

```bash
# Validate syntax
buf build

# Check breaking changes
buf breaking --against '.git#branch=main'

# Lint
buf lint

# Generate and test
make generate && cargo test
```

## Common Errors

### Missing Import
```
Error: "Address" is not defined
Fix: Add import "tenzro/v1/types.proto";
```

### Field Number Conflict
```
Error: Field number 5 has already been used
Fix: Use a different field number
```

### Circular Import
```
Error: Circular dependency detected
Fix: Refactor to break the cycle
```

## Performance Tips

1. **Use bytes for large integers**: Avoids precision loss for u128/u256
2. **Mark rarely used fields with higher numbers**: Single-byte encoding for 1-15
3. **Use oneof for alternatives**: Saves space when only one option used
4. **Batch operations**: Use repeated fields instead of multiple RPCs
5. **Stream large datasets**: Use streaming RPCs for subscriptions

## Security Checklist

- [ ] All state changes require signatures
- [ ] TEE attestations verified for sensitive operations
- [ ] Nonces prevent replay attacks
- [ ] Timestamps within acceptable range
- [ ] Gas limits prevent DoS
- [ ] Input validation on all fields
- [ ] Rate limiting on RPCs

## Documentation Links

- Full docs: `proto/README.md`
- Overview: `proto/OVERVIEW.md`
- Proto files: `proto/tenzro/v1/`
