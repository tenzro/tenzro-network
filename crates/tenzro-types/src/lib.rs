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

pub mod access_policy;
pub mod access_tier;
pub mod account;
pub mod agent;
pub mod agent_template;
pub mod asset;
pub mod block;
pub mod bridge;
pub mod canton;
pub mod capital_intent;
pub mod config;
pub mod constants;
pub mod cortex;
pub mod device_binding;
pub mod economics;
pub mod error;
pub mod fabric;
pub mod fees;
pub mod funding;
pub mod governance;
pub mod hardware;
pub mod identity;
pub mod intent_7683;
pub mod kill_switch;
pub mod knowledge;
pub mod machine_id;
pub mod marketplace;
pub mod media_gen;
pub mod model;
pub mod network;
pub mod node_alias;
pub mod node_visibility;
pub mod paths;
pub mod primitives;
pub mod principal_chain;
pub mod provenance;
pub mod reserve;
pub mod resource;
pub mod runtime;
pub mod saga;
pub mod settlement;
pub mod settlement_network;
pub mod skill;
pub mod task;
pub mod tee;
pub mod tenzro_uri;
pub mod token;
pub mod tool;
pub mod training;
pub mod transaction;
pub mod validation;
pub mod wallet;
pub mod workflow_template;

// Re-export commonly used types
pub use access_policy::{
    AccessPolicy, ConfidentialSeal, DEFAULT_READ_ACTION, DEFAULT_WRITE_ACTION, WRAP_ALG,
    WrappedDataKey,
};
pub use access_tier::{
    AccessTier, CredentialKind, PayerKind, RentableResource, RentalFunding, RpcServiceGrant,
};
pub use account::{Account, AccountState};
pub use agent::{AgentConfig, AgentIdentity, AgentMessage, AgentMessageType, Capability};
pub use agent_template::{
    AgentCapability, AgentExample, AgentPricingModel, AgentRuntimeRequirements, AgentTemplate,
    AgentTemplateFilter, AgentTemplateInstance, AgentTemplateStatus, AgentTemplateType,
};
pub use asset::{AssetId, AssetInfo, AssetType, StablecoinType};
pub use block::{Block, BlockHeader, ConsensusProof};
pub use bridge::{BridgeMessage, BridgeProtocol, BridgeTransfer};
pub use canton::{
    CantonCommandStatus, CantonDomainId, CantonParticipantConfig, CantonSynchronizerId,
    DamlCommand, DamlContractId, DamlEvent, DamlPackageInfo, DamlParty, DamlTemplateId,
    DamlTransaction, DamlValue, ParticipantPermission, SynchronizerConfig, TopologyTransaction,
};
pub use capital_intent::{
    AssetWeight, Authorization, CapitalIntent, CapitalIntentRecord, CapitalIntentStatus,
    CapitalLeg, CapitalQuote, ComplianceReq, Constraints, LegStatus, Objective, RegRegime,
    SettlementReq, Side, VenueQuote, best_execution_ok,
};
pub use config::{NetworkConfig, NodeConfig};
pub use constants::*;
pub use cortex::{
    AttestationRequirement, CORTEX_FAMILY_KEY, CortexMetadata, CortexModelFamily, CortexPricing,
    CortexReceipt, CortexRequest, CortexResponse, ReasoningBudget, ReasoningTier,
};
pub use device_binding::{
    Aaguid, AttestationEvidence, AttestationFormat, BindingError, BindingPolicy, BoundDevice,
    DeviceSession, KeyProtection, WalletReadiness, active_sessions, revoke_sessions_for_device,
    wallet_readiness,
};
pub use economics::{
    BPS_DENOMINATOR, ConversionPolicy, DelegatedSchedule, EconomicPolicy, EconomicPolicyError,
    NodeEconomicMode, PayeeRole, ValidatingSchedule,
};
pub use error::TenzroError;
pub use fees::{
    MAX_DEVELOPER_MARGIN_BPS, ServiceFeeSchedule, apply_developer_margin, network_treasury_address,
    split_settlement_authorization,
};
pub use funding::{CustodyModel, FundingDirection, FundingError, FundingProvider, FundingSource};
pub use governance::{GovernanceVote, VoteType};
pub use hardware::{GpuDevice, GpuVendor, HardwareCapabilities, HardwareClass, Interconnect};
pub use identity::{IdentityType, KycTier, PaymentProtocolId};
pub use intent_7683::{
    BridgeFeeHint, CrossChainOrder, FILL_KEY_PREFIX, FillInstruction, FillRecord,
    GaslessCrossChainOrder, ORDER_KEY_PREFIX, OrderState, Output, ProofRoute,
    ResolvedCrossChainOrder, TENZRO_MAINNET_CHAIN_ID, TENZRO_TESTNET_CHAIN_ID, TargetOutput,
    Tenzro7683Order, TenzroOrderData, TokenAmount, compute_order_id, fill_storage_key,
    order_storage_key, u128_to_uint256_be, uint256_be_to_u128,
};
pub use kill_switch::{KillSwitchAction, KillSwitchReceipt};
pub use knowledge::{
    KnowledgeFilter, KnowledgeInvocationResult, KnowledgeKind, KnowledgeRecord, KnowledgeStatus,
};
pub use machine_id::{
    IdentifierDomain, IdentifierGrade, IdentifierSource, MachineIdentifier, MachineIdentity,
};
pub use media_gen::{
    MAX_MEDIA_GEN_DIMENSION, MAX_MEDIA_GEN_FRAMES, MAX_MEDIA_GEN_PROMPT_BYTES, MAX_MEDIA_GEN_STEPS,
    MediaGenAssignment, MediaGenExpertHolding, MediaGenExpertRole, MediaGenHandoff, MediaGenJob,
    MediaGenKind, MediaGenParams, MediaGenReceipt, MediaGenStatus, MediaGenTaskSpec,
    MediaGenWorkerCapability,
};
pub use model::{
    AcceptancePolicy, AdvertisedCapacity, BillableUnits, ContentProvenanceManifest,
    ImageTokenization, InferenceMetadata, InferenceParameters, InferenceProvider, InferenceRequest,
    InferenceResponse, JurisdictionClaim, JurisdictionReceipt, LicenseTier, ModalityRates,
    ModelInfo, ModelLoadInfo, ModelModality, ModelParameters, ModelVisibility, MoeExpertHolding,
    MoeExpertResidency, MoeMetadata, MoeProviderRole, MoeRoutingStrategy, PREFIX_RUN_BYTES,
    PeerHintRecord, PrefixCacheNode, PrefixCacheSummary, PricingConfig, PricingModel,
    ProviderCapacity, meter_units_wei, prefix_run_hashes,
};
pub use network::{NetworkRole, NodeInfo, PeerInfo, RoleSet};
pub use primitives::{Address, BlockHeight, ChainId, Hash, Nonce, Signature, Timestamp};
pub use principal_chain::{
    ControllerActivitySummary, MAX_DELEGATION_DEPTH, PrincipalChain, PrincipalChainSummary,
    PrincipalLink, PrincipalRole,
};
pub use provenance::{
    ATTESTATION_DOMAIN, AttestationError, Authority, ChargeRef, InboundRail, InteractionKind,
    InteractionProvenance, PayeeRecord, SecondarySettlement,
};
pub use reserve::{ReserveAttestation, ReserveSource};
pub use resource::{ResourceClass, ResourceDescriptor, ResourceFilter};
pub use runtime::{
    ArtifactCompleteness, ArtifactMetadata, ArtifactType, CapabilityResolution, ClusterProfile,
    ExecutionMode, ExecutionPlan, ExecutionReceipt, ExecutionSupport, KVProfile, ModelClass,
    ModelTopology, NodeNetworkProfile, PlacementConstraints, RequiredExecution, RoutingPolicy,
    RuntimeSupport, TrustProfile, WorkerRole,
};
pub use saga::{AttestedDeadline, SagaStatus, SagaStep, SagaStepStatus, SagaWorkflow};
pub use settlement::{
    PaymentIntent, ProofType, ReleaseConditions, SETTLEMENT_AUTHORIZATION_DOMAIN, ServiceProof,
    ServiceType, SettlementAuthorization, SettlementReceipt, SettlementRequest, SettlementStatus,
};
pub use settlement_network::{
    DEFAULT_FEE_RATIO, MICRO_USD, NetworkFamily, SETTLEMENT_NETWORKS, SettlementNetwork,
    caip2_for_chain_name, chain_name_for_caip2, cheapest_rail_for, network_by_caip2, x402_networks,
};
pub use skill::{
    BLOB_URI_PREFIX, SYSTEM_CREATOR_DID, SkillBundle, SkillDefinition, SkillFilter,
    SkillInvocationResult, SkillPinError, SkillStatus,
};
pub use task::{
    AcceptanceCriteria, DisputeResolution, ProofRequirement, ReputationProof, TaskDispute,
    TaskFilter, TaskInfo, TaskPriority, TaskQuote, TaskStatus, TaskType,
};
pub use tee::{AttestationReport, AttestationResult, TeeCapacity, TeeProviderInfo, TeeVendor};
pub use tenzro_uri::{TENZRO_URI_SCHEME, TenzroUri, TenzroUriError};
pub use token::{
    GovernanceProposal, ProposalStatus, ProposalType, ProviderStake, ProviderType, StakingPool,
    TokenConfig, Treasury,
};
pub use tool::{
    StdioSpawnSpec, ToolDefinition, ToolFilter, ToolInvocationResult, ToolStatus,
    ToolTransportMode, UpstreamAuth,
};
pub use training::{
    ACTIVATION_COMMITMENT_DOMAIN_TAG, ActivationCommitment, AggregationRule, ArchitectureSpec,
    DEFAULT_PROBE_K, DeltaProbe, FragmentQuorumStatus, MAX_PROBE_K, OuterGradient, RlConfig,
    SealedDatasetManifest, SealedShardEnvelope, SyncRound, TrainingAttestation, TrainingModality,
    TrainingObjective, TrainingReceipt, TrainingRun, TrainingRunStatus, TrainingTaskSpec,
    TrainingTier,
};
pub use transaction::{SignedTransaction, Transaction, TransactionType};
pub use wallet::{WalletInfo, WalletType};
pub use workflow_template::{
    WorkflowInstantiationResult, WorkflowStepSpec, WorkflowTemplate, WorkflowTemplateFilter,
    WorkflowTemplateStatus,
};
