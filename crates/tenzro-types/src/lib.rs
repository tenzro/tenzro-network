//! Core types and constants for Tenzro Network
//!
//! This crate provides the foundational types used throughout the Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Modules
//!
//! - `primitives` - Core primitive types (Hash, Address, Signature, etc.)
//! - `transaction` - Transaction types and related structures
//! - `block` - Block and block header types
//! - `account` - Account and account state types
//! - `asset` - Asset and stablecoin types
//! - `network` - Network and peer information types
//! - `tee` - Trusted Execution Environment types
//! - `agent` - AI agent types and configurations
//! - `model` - AI model inference types
//! - `settlement` - Settlement and payment types
//! - `token` - TNZO token economics and governance types
//! - `governance` - Governance and voting types
//! - `bridge` - Cross-chain bridge types
//! - `wallet` - Wallet types
//! - `error` - Error types for Tenzro Network
//! - `config` - Configuration types
//! - `constants` - Chain constants and parameters
//! - `runtime` - RFC-0007: Adaptive Execution Upgrade — runtime types, enums, and capability resolver

pub mod primitives;
pub mod transaction;
pub mod block;
pub mod account;
pub mod asset;
pub mod network;
pub mod tee;
pub mod agent;
pub mod model;
pub mod settlement;
pub mod token;
pub mod governance;
pub mod bridge;
pub mod wallet;
pub mod canton;
pub mod identity;
pub mod fees;
pub mod task;
pub mod saga;
pub mod capital_intent;
pub mod reserve;
pub mod marketplace;
pub mod agent_template;
pub mod skill;
pub mod tool;
pub mod knowledge;
pub mod workflow_template;
pub mod resource;
pub mod error;
pub mod config;
pub mod constants;
pub mod runtime;
pub mod validation;
pub mod cortex;
pub mod training;
pub mod principal_chain;
pub mod kill_switch;
pub mod intent_7683;
pub mod hardware;
pub mod tenzro_uri;
pub mod access_policy;

// Re-export commonly used types
pub use primitives::{Hash, Address, Signature, BlockHeight, Nonce, Timestamp, ChainId};
pub use transaction::{Transaction, TransactionType, SignedTransaction};
pub use block::{Block, BlockHeader, ConsensusProof};
pub use account::{Account, AccountState};
pub use asset::{AssetId, AssetType, StablecoinType, AssetInfo};
pub use network::{NetworkRole, NodeInfo, PeerInfo, RoleSet};
pub use tee::{TeeVendor, AttestationReport, AttestationResult, TeeCapacity, TeeProviderInfo};
pub use agent::{AgentIdentity, AgentConfig, AgentMessage, AgentMessageType, Capability};
pub use model::{AcceptancePolicy, LicenseTier, ModelInfo, ModelLoadInfo, PeerHintRecord, ModelModality, ModelVisibility, MoeMetadata, MoeRoutingStrategy, MoeExpertHolding, MoeExpertResidency, MoeProviderRole, PrefixCacheSummary, PrefixCacheNode, prefix_run_hashes, PREFIX_RUN_BYTES, InferenceRequest, InferenceResponse, InferenceParameters, InferenceProvider, JurisdictionClaim, JurisdictionReceipt, ProvenanceManifest, ProviderCapacity, AdvertisedCapacity, PricingConfig};
pub use settlement::{SettlementRequest, SettlementReceipt, SettlementStatus, ReleaseConditions, ServiceType, PaymentIntent, ServiceProof, ProofType, SettlementAuthorization, SETTLEMENT_AUTHORIZATION_DOMAIN};
pub use token::{TokenConfig, Treasury, StakingPool, ProviderStake, ProviderType, GovernanceProposal, ProposalStatus, ProposalType};
pub use governance::{GovernanceVote, VoteType};
pub use bridge::{BridgeMessage, BridgeProtocol, BridgeTransfer};
pub use wallet::{WalletInfo, WalletType};
pub use canton::{
    DamlContractId, DamlTemplateId, DamlParty, DamlValue, DamlCommand, DamlEvent,
    DamlTransaction, CantonSynchronizerId, CantonDomainId, CantonParticipantConfig,
    CantonCommandStatus, DamlPackageInfo, TopologyTransaction, ParticipantPermission,
    SynchronizerConfig,
};
pub use identity::{KycTier, PaymentProtocolId, IdentityType};
pub use fees::{ServiceFeeSchedule, NetworkCommissionRates, MAX_DEVELOPER_MARGIN_BPS, apply_developer_margin, SETTLEMENT_AUTHORIZATION_COMMISSION_BPS, split_settlement_authorization};
pub use task::{TaskInfo, TaskStatus, TaskType, TaskPriority, TaskQuote, TaskFilter,
    AcceptanceCriteria, ProofRequirement, ReputationProof, TaskDispute, DisputeResolution};
pub use saga::{SagaWorkflow, SagaStep, SagaStepStatus, SagaStatus, AttestedDeadline};
pub use capital_intent::{
    CapitalIntent, CapitalIntentRecord, CapitalIntentStatus, CapitalQuote, CapitalLeg, LegStatus,
    Objective, Constraints, ComplianceReq, Authorization, SettlementReq, RegRegime, Side,
    AssetWeight, VenueQuote, best_execution_ok,
};
pub use reserve::{ReserveAttestation, ReserveSource};
pub use agent_template::{AgentTemplate, AgentTemplateStatus, AgentTemplateType, AgentCapability, AgentRuntimeRequirements, AgentPricingModel, AgentExample, AgentTemplateFilter, AgentTemplateInstance};
pub use skill::{SkillDefinition, SkillStatus, SkillFilter, SkillInvocationResult, SYSTEM_CREATOR_DID};
pub use tool::{
    StdioSpawnSpec, ToolDefinition, ToolFilter, ToolInvocationResult, ToolStatus,
    ToolTransportMode, UpstreamAuth,
};
pub use knowledge::{
    KnowledgeFilter, KnowledgeInvocationResult, KnowledgeKind, KnowledgeRecord,
    KnowledgeStatus,
};
pub use workflow_template::{
    WorkflowInstantiationResult, WorkflowStepSpec, WorkflowTemplate, WorkflowTemplateFilter,
    WorkflowTemplateStatus,
};
pub use resource::{ResourceClass, ResourceDescriptor, ResourceFilter};
pub use access_policy::{
    AccessPolicy, ConfidentialSeal, WrappedDataKey, DEFAULT_READ_ACTION, DEFAULT_WRITE_ACTION,
    WRAP_ALG,
};
pub use tenzro_uri::{TenzroUri, TenzroUriError, TENZRO_URI_SCHEME};
pub use error::TenzroError;
pub use config::{NetworkConfig, NodeConfig};
pub use constants::*;
pub use runtime::{
    ModelClass, ExecutionMode, ArtifactCompleteness, ArtifactType, KVProfile, WorkerRole,
    ExecutionSupport, ModelTopology, PlacementConstraints, RoutingPolicy, RequiredExecution,
    RuntimeSupport, TrustProfile, NodeNetworkProfile, ClusterProfile, ArtifactMetadata,
    ExecutionPlan, ExecutionReceipt, CapabilityResolution,
};
pub use cortex::{
    AttestationRequirement, CortexMetadata, CortexModelFamily, CortexPricing, CortexReceipt,
    CortexRequest, CortexResponse, ReasoningBudget, ReasoningTier, CORTEX_FAMILY_KEY,
};
pub use training::{
    ActivationCommitment, AggregationRule, ArchitectureSpec, DeltaProbe, FragmentQuorumStatus,
    OuterGradient, RlConfig, SealedDatasetManifest, SealedShardEnvelope, SyncRound,
    TrainingAttestation, TrainingModality, TrainingObjective, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier, ACTIVATION_COMMITMENT_DOMAIN_TAG,
    DEFAULT_PROBE_K, MAX_PROBE_K,
};
pub use principal_chain::{
    ControllerActivitySummary, PrincipalChain, PrincipalChainSummary, PrincipalLink,
    PrincipalRole, MAX_DELEGATION_DEPTH,
};
pub use kill_switch::{KillSwitchAction, KillSwitchReceipt};
pub use hardware::{GpuDevice, GpuVendor, HardwareCapabilities, HardwareClass, Interconnect};
pub use intent_7683::{
    compute_order_id, fill_storage_key, order_storage_key, u128_to_uint256_be,
    uint256_be_to_u128, BridgeFeeHint, CrossChainOrder, FillInstruction, FillRecord,
    GaslessCrossChainOrder, OrderState, Output, ProofRoute, ResolvedCrossChainOrder,
    TargetOutput, Tenzro7683Order, TenzroOrderData, TokenAmount, FILL_KEY_PREFIX,
    ORDER_KEY_PREFIX, TENZRO_MAINNET_CHAIN_ID, TENZRO_TESTNET_CHAIN_ID,
};
