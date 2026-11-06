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
//! - `statement` - Provider settlement statements built from settled calls
//! - `token` - TNZO token economics and the network policy updates governance decides
//! - `bridge` - Cross-chain bridge types
//! - `wallet` - Wallet types
//! - `error` - Error types for Tenzro Network
//! - `config` - Configuration types
//! - `constants` - Chain constants and parameters
//! - `runtime` - adaptive execution runtime types, enums, and capability resolver

pub mod access_policy;
pub mod access_tier;
pub mod account;
pub mod account_signature;
pub mod admission;
pub mod agent;
pub mod agent_audit;
pub mod agent_terms;
pub mod asset;
pub mod block;
pub mod bridge_route;
pub mod bridge_transfer;
pub mod chain_event;
pub mod cluster_membership;
pub mod config;
pub mod constants;
pub mod da_retention;
pub mod device_binding;
pub mod did_derivation;
pub mod did_services;
pub mod duty;
pub mod economics;
pub mod error;
pub mod eth_receipt;
/// The EU AI Act disclosure, and how each surface renders it.
///
/// Here rather than in the node because the node emits it and the CLI renders
/// it, and the text has to be the same string in both. It has no dependencies
/// — constants and two string functions — so it costs nothing to share.
pub mod eu_ai_disclosure;
pub mod evidence;
pub mod evidence_pack;
pub mod fabric;
pub mod fees;
pub mod funding;
pub mod hardware;
pub mod hardware_level;
pub mod hash_scheme;
pub mod identity;
pub mod inference_verification;
pub mod insurance;
pub mod jsonrpc;
pub mod key_release;
pub mod keystore;
pub mod launch_rule;
pub mod kill_switch;
pub mod leg_statement;
pub mod machine_id;
pub mod media_gen;
pub mod merkle;
pub mod meter;
pub mod metering;
pub mod model;
pub mod network;
pub mod node_access;
pub mod omni_account;
pub mod paths;
pub mod payment_authorization;
pub mod price_card;
pub mod primitives;
pub mod account_outflow_ui;
pub mod delegation_ui;
pub mod recipient_guard;
pub mod transfer_policy;
pub mod principal_chain;
pub mod provenance;
pub mod provider_listing;
pub mod registry;
pub mod remote_grant;
pub mod reserve;
pub mod resource_access;
pub mod runtime;
pub mod settlement;
pub mod settlement_asset;
pub mod settlement_network;
pub mod signature_scheme;
pub mod siwt;
pub mod split;
pub mod statement;
pub mod tee;
pub mod tenzro_uri;
pub mod token;
pub mod token_op;
pub mod token_policy;
pub mod training_provenance;
pub mod training_verification;
pub mod transaction;
pub mod typed_action;
pub mod validation;
pub mod visibility;
pub mod wallet;

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
pub use asset::{AssetId, AssetInfo, AssetType, StablecoinType};
pub use block::{Block, BlockHeader, LogsBloom};
pub use config::{NetworkConfig, NodeConfig};
pub use constants::*;
pub use device_binding::{
    Aaguid, AttestationEvidence, AttestationFormat, BindingError, BindingPolicy, BoundDevice,
    ControlRoot, CredentialProvenance, CustodyCredential, DeviceSession, KeyProtection,
    WalletReadiness, active_sessions, custody_counts, independent_roots,
    revoke_sessions_for_device, wallet_readiness,
};
pub use economics::{
    BPS_DENOMINATOR, ConversionPolicy, DelegatedSchedule, EconomicPolicy, EconomicPolicyError,
    NodeEconomicMode, PayeeRole, ValidatingSchedule,
};
pub use error::TenzroError;
pub use fees::{
    DEFAULT_MAX_DEVELOPER_MARGIN_BPS, ServiceFeeSchedule, apply_developer_margin,
    network_treasury_address,
};
pub use funding::{CustodyModel, FundingDirection, FundingError, FundingProvider, FundingSource};
pub use hardware::{GpuDevice, GpuVendor, HardwareCapabilities, HardwareClass, Interconnect};
pub use identity::{IdentityType, KycTier, PaymentProtocolId};
pub use kill_switch::{KillSwitchAction, KillSwitchReceipt};
pub use machine_id::{
    IdentifierDomain, IdentifierGrade, IdentifierSource, MachineIdentifier, MachineIdentity,
};
pub use media_gen::{
    MAX_MEDIA_GEN_DIMENSION, MAX_MEDIA_GEN_FRAMES, MAX_MEDIA_GEN_INPUTS,
    MAX_MEDIA_GEN_PROMPT_BYTES, MAX_MEDIA_GEN_STEPS, MediaGenExpertRole, MediaGenInput,
    MediaGenInputRole, MediaGenKind, MediaGenParams,
};
pub use model::{
    AcceptancePolicy, AdvertisedCapacity, BillableUnits, ContentProvenanceManifest,
    ImageTokenization, InferenceMetadata, InferenceParameters, InferenceProvider, InferenceRequest,
    InferenceResponse, JurisdictionClaim, JurisdictionReceipt, LicenseTier, ModelInfo,
    ModelLoadInfo, ModelModality, ModelParameters, MoeExpertHolding, MoeExpertResidency,
    MoeMetadata, MoeProviderRole, MoeRoutingStrategy, PREFIX_RUN_BYTES, PeerHintRecord,
    PrefixCacheSummary, PrefixDigest, ProviderCapacity, salted_prefix_digests,
};
pub use network::{NetworkRole, NodeInfo, PeerInfo, RoleSet};
pub use primitives::{Address, BlockHeight, ChainId, Hash, Nonce, Signature, Timestamp};
pub use principal_chain::{
    MAX_DELEGATION_DEPTH, PrincipalChain, PrincipalChainSummary, PrincipalLink, PrincipalRole,
};
pub use provenance::{
    ATTESTATION_DOMAIN, AttestationError, Authority, ChargeRef, InboundRail, InteractionKind,
    InteractionProvenance, PayeeRecord, SecondarySettlement,
};
pub use reserve::{ReserveAttestation, ReserveSource};
pub use runtime::{
    ArtifactCompleteness, ArtifactMetadata, ArtifactType, CapabilityResolution, ClusterProfile,
    ExecutionMode, ExecutionPlan, ExecutionReceipt, ExecutionSupport, KVProfile, ModelClass,
    ModelTopology, NodeNetworkProfile, PlacementConstraints, RequiredExecution, RoutingPolicy,
    RuntimeSupport, TrustProfile, WorkerRole,
};
pub use settlement::{PaymentIntent, ProofType, ReleaseConditions, ServiceProof, ServiceType};
pub use settlement_network::{
    DEFAULT_FEE_RATIO, MICRO_USD, NetworkFamily, SECONDARY_NETWORKS, SettlementNetwork,
    TENZRO_NAMESPACE, caip2_for_chain_name, chain_name_for_caip2, cheapest_rail_for,
    cheapest_secondary_rail_for, family_of_caip2, network_by_caip2, secondary_network_by_caip2,
    settlement_networks, tenzro_caip2, tenzro_chain_id_of, tenzro_ledger, x402_networks,
};
pub use tee::{AttestationReport, AttestationResult, TeeCapacity, TeeProviderInfo, TeeVendor};
pub use tenzro_uri::{TENZRO_URI_SCHEME, TenzroUri, TenzroUriError};
pub use token::{PolicyUpdate, StakeCapacity, Treasury};
pub use transaction::{
    CallVm, ComputeClaimOp, FeeRateQuote, FeeRateReveal, RateStreamSigner, RateStreamSigners,
    ReserveFeed, SignedTransaction, SlaOutcome, Transaction, TransactionType, VmCall,
    external_svm_hash, fee_rate_commitment, svm_signature_hash,
};
pub use visibility::Visibility;
pub use wallet::{WalletInfo, WalletType};
