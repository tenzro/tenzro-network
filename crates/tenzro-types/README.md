# tenzro-types

Foundation crate providing shared types for the Tenzro Network.

## Overview

`tenzro-types` is the foundational crate with zero internal dependencies. It defines all shared types, primitives, and data structures used across the Tenzro Network workspace, including blockchain primitives, AI-specific types, and financial structures.

## Modules

**Public modules:** `access_policy`, `access_tier`, `account`, `account_signature`, `agent`, `agent_audit`, `agent_terms`, `asset`, `block`, `bridge_route`, `bridge_transfer`, `chain_event`, `cluster_membership`, `config`, `constants`, `da_retention`, `device_binding`, `did_derivation`, `did_services`, `duty`, `economics`, `error`, `eth_receipt`, `eu_ai_disclosure`, `evidence`, `evidence_pack`, `fabric`, `fees`, `funding`, `hardware`, `identity`, `inference_verification`, `insurance`, `jsonrpc`, `keystore`, `kill_switch`, `machine_id`, `media_gen`, `merkle`, `metering`, `model`, `network`, `node_access`, `omni_account`, `paths`, `payment_authorization`, `primitives`, `principal_chain`, `provenance`, `provider_listing`, `remote_grant`, `reserve`, `resource_access`, `runtime`, `settlement`, `settlement_network`, `siwt`, `split`, `tee`, `tenzro_uri`, `token`, `token_op`, `token_policy`, `transaction`, `typed_action`, `validation`, `visibility`, `wallet`

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

### Generative Media Types (`media_gen` module)
- `MediaGenKind` - Text2Image, Image2Image, Text2Video, Image2Video and the audio, 3D, action and world kinds
- `MediaGenParams`, `MediaGenInput`, `MediaGenInputRole` - What one render is asked to produce and from which inputs
- `MediaGenExpertRole` - Which half of a two-expert denoising schedule a pass runs
- `pixel_steps`, `world_model_units` - The work units a render is metered in (`width × height × steps × frames` for pixel kinds)
- `MAX_MEDIA_GEN_DIMENSION`, `MAX_MEDIA_GEN_STEPS`, `MAX_MEDIA_GEN_FRAMES`, `MAX_MEDIA_GEN_PROMPT_BYTES` - Request bounds

### Financial Types
- `SettlementPlan`, `Leg`, `LegReceipt`, `PaymentRecord` - Consensus settlement records
- `ReleaseConditions`, `ServiceType`, `PaymentIntent`, `ServiceProof`, `ProofType` - Settlement conditions
- `TokenConfig`, `Treasury` - Token economics
- `StakeOp`, `RoleStake`, `StakeCapacity` - Role stakes in consensus; roles are `NetworkRole` (`--roles`), which carries each role's required stake

### Governance Types
- `GovernanceProposal`, `ProposalStatus`, `ProposalType` - Governance proposals
- `GovernanceVote`, `VoteType` - Voting

### Identity Types
- `KycTier` - KYC verification levels (Unverified, Basic, Enhanced, Full)
- `IdentityType` - Human or Machine identity
- `PaymentProtocolId` - Payment protocol identifiers (Mpp, X402, Direct, Channel, Custom)

### Bridge Types
- `BridgeMessage`, `BridgeProtocol`, `BridgeTransfer` - Cross-chain bridge operations

### Wallet Types
- `WalletInfo`, `WalletType` - Wallet management

### Task & Marketplace Types
- `TaskInfo`, `TaskStatus`, `TaskType`, `TaskPriority`, `TaskQuote`, `TaskFilter`
- `AgentTemplate`, `AgentTemplateStatus`, `AgentTemplateType`, `AgentCapability`
- `AgentRuntimeRequirements`, `AgentPricingModel`, `AgentExample`
- `AgentTemplateFilter`, `AgentTemplateInstance`
- `SkillDefinition`, `SkillStatus`, `SkillFilter`, `SkillInvocationResult`
- `ToolDefinition`, `ToolStatus`, `ToolFilter`, `ToolInvocationResult`

### Runtime Types (adaptive execution)
- `ModelClass`, `ExecutionMode`, `ArtifactCompleteness`, `ArtifactType`
- `KVProfile`, `WorkerRole`, `ExecutionSupport`, `ModelTopology`
- `PlacementConstraints`, `RoutingPolicy`, `RequiredExecution`
- `RuntimeSupport`, `TrustProfile`, `NodeNetworkProfile`
- `ArtifactMetadata`, `ExecutionPlan`, `ExecutionReceipt`, `CapabilityResolution`

### Configuration & Fees
- `NetworkConfig`, `NodeConfig` - Network configuration
- `ServiceFeeSchedule` - Flat ledger service fees
- `EconomicPolicy`, `NodeEconomicMode`, `PayeeRole` - The governance-set revenue split (see `docs/ECONOMICS.md`)
- `AccessTier`, `PayerKind`, `RentableResource` - Subscriber / renter / user tiers
- `InteractionProvenance` - Who, what, when, how, how much for every metered interaction
- `MachineIdentity`, `IdentifierGrade` - Graded machine-identity sources

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

Apache-2.0.

## Identity, devices and machines

- `device_binding` — devices bound to an identity. `BoundDevice`,
  `BindingPolicy`, `AttestationEvidence`, `KeyProtection`, `AttestationFormat`,
  `Aaguid`, plus `DeviceSession` and the wallet second-device gate
  (`wallet_readiness`). A device counts as hardware-bound only when the
  credential cannot sync **and** an attestation verified to a pinned vendor root
  says the key lives in hardware — no platform account is an identity authority.
- `provenance` — one accounting record per interaction, and the attestation
  digest that makes it checkable by a third party. `Authority` records what
  *specifically* permitted an interaction (delegation / AP2 mandate / x402
  payment / credential), and `ChargeRef` separates *free* from *accrued into a
  channel* — a distinction `settlement_tx: None` cannot make and one that is
  opposite facts to an auditor. `InteractionKind::Access` covers the web fetch
  alongside inference, so access and inference audit through the same row.
- `settlement_network` — the rails a payment can settle on, ordered
  cheapest-first, each with an indicative fee floor. Supporting x402 and being
  able to carry a micropayment are different properties, and this table is what
  keeps them apart: `cheapest_rail_for` returns the cheapest rail that both
  carries the payee's asset and is worth using at that size, or `None` when the
  charge must accumulate instead.
- `machine_id` — graded machine-identity sources. `IdentifierGrade` separates
  `Model` (Arm `MIDR_EL1`, x86 CPUID — a design, not a unit), `Fused` (Intel/AMD
  PPIN, Apple ECID, SMBIOS — per-unit but readable) and `Attestable` (TPM EK,
  TCM/TPCM, Secure Enclave, SEV-SNP VCEK, ATECC608, SE050, ESP32 DS). Only
  `Attestable` can anchor a machine no human delegated. Accelerator identifiers
  are excluded by design.
- `paths` — one root, and a third scope beside shared and per-instance:
  per-identity (`identity_dir`, `identity_sessions_dir`,
  `identity_devices_dir`). State about *who* is filed under the identity, not
  the machine hosting it.
- `economics` / `provenance` / `access_tier` — see `docs/ECONOMICS.md`.
