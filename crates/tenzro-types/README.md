# tenzro-types

Foundation crate providing shared types for the Tenzro Network.

## Overview

`tenzro-types` is the foundational crate with zero internal dependencies. It defines all shared types, primitives, and data structures used across the Tenzro Network workspace, including blockchain primitives, AI-specific types, financial structures, and Canton/DAML integration types.

## Modules

**Public modules:** primitives, transaction, block, account, asset, network, tee, agent, model, settlement, token, governance, bridge, wallet, canton, identity, fees, task, agent_template, skill, tool, error, config, constants, runtime, validation, cortex, training, principal_chain, kill_switch, intent_7683

### Primitives
- `Hash` - 32-byte hash type
- `Address` - Variable-length address type (32 bytes default)
- `Signature` - Cryptographic signature
- `BlockHeight`, `Nonce`, `Timestamp`, `ChainId`

### Domain Types
- `Account`, `AccountState` - Account information and state
- `Block`, `BlockHeader`, `ConsensusProof` - Block structures
- `Transaction`, `TransactionType`, `SignedTransaction` - Transaction types
- `Asset`, `AssetId`, `AssetType`, `StablecoinType`, `AssetInfo` - Asset management
- `NetworkRole`, `PeerInfo`, `NodeInfo` - Network peer information

### AI & Agent Types
- `AgentIdentity`, `AgentConfig`, `AgentMessage`, `AgentMessageType`, `Capability` - AI agent infrastructure
- `ModelInfo`, `ModelLoadInfo`, `ModelModality` - Model registry. `ModelModality` covers Text, Image, Audio, Video, Embedding, Multimodal, Code, and Timeseries.
- `VisionParameters`, `AudioParameters`, `VideoParameters`, `TimeseriesParameters` - Optional sidecar parameters on `ModelInfo`
- `InferenceRequest`, `InferenceResponse`, `InferenceParameters`, `InferencePayload` - Inference operations. `InferencePayload` is a typed enum (`Chat | Forecast | VisionEmbed | VisionSimilarity | TextEmbed | Segment | Detect | Transcribe | VideoEmbed`) consumed by the modality-aware `InferenceRouter`.
- `InferenceProvider`, `ProviderCapacity`, `PricingConfig` - Provider management

### Financial Types
- `SettlementRequest`, `SettlementReceipt`, `SettlementStatus` - Payment settlement
- `ReleaseConditions`, `ServiceType`, `PaymentIntent`, `ServiceProof`, `ProofType` - Settlement conditions
- `TokenConfig`, `Treasury`, `StakingPool` - Token economics
- `ProviderStake`, `ProviderType` - Staking infrastructure

### Governance Types
- `GovernanceProposal`, `ProposalStatus`, `ProposalType` - Governance proposals
- `GovernanceVote`, `VoteType` - Voting

### Identity Types
- `KycTier` - KYC verification levels (Unverified, Basic, Enhanced, Full)
- `IdentityType` - Human or Machine identity
- `PaymentProtocolId` - Payment protocol identifiers (Mpp, X402, Direct, Channel, Custom)

### Canton/DAML Types
- `DamlContractId`, `DamlTemplateId`, `DamlParty`
- `DamlValue`, `DamlCommand`, `DamlEvent`, `DamlTransaction`
- `CantonSynchronizerId`, `CantonDomainId`, `CantonParticipantConfig`
- `CantonCommandStatus`, `DamlPackageInfo`, `TopologyTransaction`
- `ParticipantPermission`, `SynchronizerConfig`

### Bridge Types
- `BridgeMessage`, `BridgeProtocol`, `BridgeTransfer` - Cross-chain bridge operations

### ERC-7683 Cross-Chain Intents (`intent_7683` module)
- `CrossChainOrder`, `GaslessCrossChainOrder` - User-signed open envelopes
- `ResolvedCrossChainOrder` - `IOriginSettler.resolve` return shape
- `Output`, `TargetOutput` - Chain-discriminated 32-byte recipient + uint256 amount
- `FillInstruction` - Per-output destination dispatch
- `TenzroOrderData` - Tenzro-native opaque payload carried inside the 7683 envelope
- `TokenAmount` - 32-byte token id + uint256 amount
- `ProofRoute` - LayerZero / Wormhole / DeBridge / Hyperlane fill-proof route
- `OrderState` - Open → AwaitingProof → Settled / Refunded / ForceRefundEligible
- `Tenzro7683Order` - On-chain envelope persisted under the `7683_origin:` keyspace
- `compute_order_id(order)` - `SHA-256("tenzro/7683/order" || swapper || nonce_le || origin_chain_id_le || fill_deadline_le || order_data_type || order_data)`
- `u128_to_uint256_be` / `uint256_be_to_u128` - Big-endian uint256 conversion (rejects non-zero high 128 bits)
- CAIP-2 chain IDs: `TENZRO_MAINNET_CHAIN_ID = 0x10ED20`, `TENZRO_TESTNET_CHAIN_ID = 0x10ED21`

### Wallet Types
- `WalletInfo`, `WalletType` - Wallet management

### Task & Marketplace Types
- `TaskInfo`, `TaskStatus`, `TaskType`, `TaskPriority`, `TaskQuote`, `TaskFilter`
- `AgentTemplate`, `AgentTemplateStatus`, `AgentTemplateType`, `AgentCapability`
- `AgentRuntimeRequirements`, `AgentPricingModel`, `AgentExample`
- `AgentTemplateFilter`, `AgentTemplateInstance`
- `SkillDefinition`, `SkillStatus`, `SkillFilter`, `SkillInvocationResult`
- `ToolDefinition`, `ToolStatus`, `ToolFilter`, `ToolInvocationResult`

### Runtime Types (RFC-0007: Adaptive Execution Upgrade)
- `ModelClass`, `ExecutionMode`, `ArtifactCompleteness`, `ArtifactType`
- `KVProfile`, `WorkerRole`, `ExecutionSupport`, `ModelTopology`
- `PlacementConstraints`, `RoutingPolicy`, `RequiredExecution`
- `RuntimeSupport`, `TrustProfile`, `NodeNetworkProfile`
- `ArtifactMetadata`, `ExecutionPlan`, `ExecutionReceipt`, `CapabilityResolution`

### Configuration & Fees
- `NetworkConfig`, `NodeConfig` - Network configuration
- `ServiceFeeSchedule`, `NetworkCommissionRates` - Fee structures

### TEE Types
- `TeeVendor`, `AttestationReport`, `AttestationResult`
- `TeeCapacity`, `TeeProviderInfo`

### Error Types
- `TenzroError` - Unified error type for the network

### Constants
- Chain constants and parameters exported via `constants` module

## Usage

Add to `Cargo.toml`:

```toml
[dependencies]
tenzro-types = { path = "../tenzro-types" }
```

Example:

```rust
use tenzro_types::primitives::{Hash, Address, BlockHeight};
use tenzro_types::transaction::{Transaction, TransactionType};
use tenzro_types::block::Block;
use tenzro_types::NetworkRole;

// Create a new address
let address = Address::from_bytes(&[0u8; 32])?;

// Work with transactions
let tx = Transaction {
    nonce: 0,
    from: address.clone(),
    to: Some(address.clone()),
    tx_type: TransactionType::Transfer,
    // ...
};
```

## Dependencies

- `serde`, `serde_json` - Serialization
- `thiserror` - Error handling
- `bytes`, `hex`, `bs58` - Data encoding
- `chrono` - Timestamp handling
- `uuid` - Unique identifiers
- `sha2`, `sha3` - Hashing utilities

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your option.
