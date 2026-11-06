//! Tenzro Network Rust SDK
//!
//! The official Rust SDK for building applications on Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Overview
//!
//! This SDK provides a clean, ergonomic API for developers to:
//! - Connect to Tenzro Network nodes
//! - Manage wallets and transactions
//! - Perform AI model inference
//! - Execute settlement and payments
//! - Register and interact with AI agents
//! - Participate in governance
//! - Bridge tokens cross-chain
//! - Manage identity (DIDs, credentials)
//! - Use TEE attestation and ZK proofs
//! - Deploy and interact with smart contracts
//!
//! # Quick Start
//!
//! ```no_run
//! use tenzro_sdk::TenzroClient;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Connect to the preview network
//!     let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
//!
//!     // Read an account's balances
//!     let address = tenzro_sdk::types::Address::zero();
//!     let balances = client.wallet().get_all_balances(address).await?;
//!     println!("Balances: {:?}", balances);
//!
//!     // Resolve an identity
//!     let identity = client.identity().resolve("did:tenzro:human:abc123").await?;
//!     println!("Status: {}", identity.status);
//!
//!     // List AI models
//!     let models = client.inference().list_models().await?;
//!     println!("{} models available", models.len());
//!
//!     Ok(())
//! }
//! ```
//!
//! # Core and capabilities
//!
//! The core is always built: the node client ([`RpcClient`], [`TenzroClient`]
//! with discovery and by-name calls), configuration, errors and types, access
//! and sign-in, [`wallet`] with hardware and passkey signers and the typed
//! transaction builders ([`typed_tx`]). Each
//! capability is a cargo feature that adds its modules, its
//! [`TenzroClient`] accessors and only the dependencies they need:
//!
//! | Feature | Modules |
//! |---|---|
//! | `payments` | `web` (x402 payers, the publisher gate as a tower layer), `payment`, `permit2`, `funding` |
//! | `settlement` | `settle` (split engine, settlement plans), `settlement` (escrow) |
//! | `agents` | `agent`, `agent_payments` |
//! | `bridge` | `bridge`, `bridge_fee`, `eip7702`, `agent_accounts` |
//! | `inference` | `inference`, `chat`, `streaming`, `multimodal`, `media_gen`, `provider`, `catalog` |
//! | `chain` | `governance`, `token`, `staking`, `validator`, `contract`, `tee`, `zk`, `storage`, `events`, and the other registries |
//!
//! `full`, the default, enables all of them. A thin build names what it uses:
//!
//! ```toml
//! tenzro-sdk = { version = "0.8", default-features = false, features = ["payments"] }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]

// The core.
pub mod access;
pub mod account_keys;
pub mod auth;
pub mod client;
pub mod config;
pub mod crypto;
pub mod device;
pub mod did_envelope;
pub mod discovery;
pub mod error;
pub mod gateway;
pub mod identity;
pub mod keystore;
pub mod network;
pub mod node;
pub mod passkey_client;
pub mod rpc;
pub mod sse;
pub mod typed_tx;
pub mod account_outflow;
pub mod recipient_guard;
pub mod types;
pub mod wallet;

// payments
#[cfg(feature = "payments")]
pub mod funding;
#[cfg(feature = "payments")]
pub mod ledger_pay;
#[cfg(feature = "payments")]
pub mod payment;
#[cfg(feature = "payments")]
pub mod permit2;
#[cfg(feature = "payments")]
pub mod web;

// settlement
#[cfg(feature = "settlement")]
pub mod settle;
#[cfg(feature = "settlement")]
pub mod settlement;

// agents
#[cfg(feature = "agents")]
pub mod agent;
#[cfg(feature = "agents")]
pub mod agent_payments;
/// OpenShell sandboxes: Terms from a grant, the provider credential, and the extensions signed records.
#[cfg(feature = "agents")]
pub mod openshell;

// bridge
#[cfg(feature = "bridge")]
pub mod agent_accounts;
#[cfg(feature = "bridge")]
#[cfg(feature = "bridge")]
pub mod bridge;
#[cfg(feature = "bridge")]
pub mod bridge_fee;
#[cfg(feature = "bridge")]
pub mod eip7702;

// inference
#[cfg(feature = "inference")]
pub mod catalog;
#[cfg(feature = "inference")]
pub mod chat;
#[cfg(feature = "inference")]
#[cfg(feature = "inference")]
pub mod inference;
#[cfg(feature = "inference")]
pub mod media_gen;
#[cfg(feature = "inference")]
pub mod multimodal;
#[cfg(feature = "inference")]
pub mod provider;
#[cfg(feature = "inference")]
pub mod streaming;

// chain
#[cfg(feature = "chain")]
pub mod adaptive_burn;
#[cfg(feature = "chain")]
pub mod consensus;
#[cfg(feature = "chain")]
pub mod contract;
#[cfg(feature = "chain")]
pub mod da;
#[cfg(feature = "chain")]
pub mod duty;
#[cfg(feature = "chain")]
pub mod events;
#[cfg(feature = "chain")]
pub mod governance;
#[cfg(feature = "chain")]
pub mod insurance;
#[cfg(feature = "chain")]
pub mod iroh;
#[cfg(feature = "chain")]
pub mod machine_access;
#[cfg(feature = "chain")]
pub mod nft;
pub mod pricing;
#[cfg(feature = "chain")]
pub mod reserve;
#[cfg(feature = "chain")]
pub mod sla;
#[cfg(feature = "chain")]
pub mod snapshot;
#[cfg(feature = "chain")]
pub mod staking;
#[cfg(feature = "chain")]
pub mod storage;
#[cfg(feature = "chain")]
pub mod tee;
#[cfg(feature = "chain")]
pub mod token;
#[cfg(feature = "chain")]
pub mod trust;
#[cfg(feature = "chain")]
pub mod urwa;
#[cfg(feature = "chain")]
pub mod validator;
#[cfg(feature = "chain")]
pub mod zk;

// Re-exports of the main types.
pub use access::{
    AccessChallenge, AccessClient, AccessCredential, AuditEntry, AuditFilter, AuditLine, AuditLog,
    AuditRecord, AuditVerification, DpopProver, IssuedAccessToken, SignInProof,
};
pub use account_keys::AccountKeysClient;
#[cfg(feature = "chain")]
pub use adaptive_burn::AdaptiveBurnClient;
#[cfg(feature = "agents")]
pub use agent::{AgentClient, KillSwitchPage, KillSwitchReceipt};
#[cfg(feature = "agents")]
pub use agent_payments::AgentPaymentClient;
pub use auth::{
    AuthClient, IntrospectionResult, MachineRootAuthorization, OAuthDiscovery, OnboardSession,
    RefreshedToken, RevokeResponse, TokenExchangeResult, machine_root_authorization,
    machine_root_ballot, machine_root_step_up,
};
#[cfg(feature = "bridge")]
pub use bridge::BridgeClient;
#[cfg(feature = "inference")]
pub use chat::{
    ChatCompletion, ChatRequest, ChatStreamAssembler, ChatStreamEvent, ChatTool,
    ProviderPreferences, ReasoningEffort, StreamOptions, ToolCall, Usage,
};
pub use client::{BlockInfo, BlockRange, NodeInfo, NodeStatus, TenzroClient};
pub use config::SdkConfig;
#[cfg(feature = "chain")]
pub use contract::{CallResult, CallVm, ContractClient, DeployResult, VmCall};
#[cfg(feature = "inference")]
pub use crypto::{CryptoClient, VerifyResult, VrfVerifyResult};
pub use error::ApiError;
pub use error::{NodeError, SdkError, SdkResult};
#[cfg(feature = "chain")]
pub use events::{
    EventClient, EventPage, checkpoint_digest, filter_index_keys, filter_selects,
    verify_completeness, verify_event_proof, verify_index_answer,
};
#[cfg(feature = "chain")]
pub use funding::{
    GrantReleaseOption, GrantRequest, release_milestone, request_grant, request_tranche,
    verify_milestone,
};
pub use governance::{
    GovernanceClient, GovernanceReceiptReport, PayoutAddress, PayoutCaps, PayoutRecord,
    ProposalPage, ProposalView, SponsoredBond, Tally, TreasuryAccount, TreasuryAccounts,
    TreasuryGrant, TreasuryPayouts, VotingPower, approve_grantee_proposal,
    approve_operator_proposal, parameter_change_proposal, recall_sponsored_bond_proposal,
    reinstate_validator_proposal, release_sponsored_bond, revoke_grantee_proposal, revoke_operator_proposal,
    sponsor_operator_running_cost_proposal, sponsor_operator_stable_proposal,
    sponsor_validator_bond_proposal,
    verify_governance_receipt,
};
pub use identity::{
    IdentityClient, IdentityInfo, IdentityType, PqRotationKey, RegisterHumanParams,
};
#[cfg(feature = "inference")]
pub use inference::{
    BillableUnits, GenerationStats, GlobalUsageStats, InferenceClient, InferenceUsage,
    IntentParams, LoadedModel, LoadedModels, ModelUsageStats, ProviderUsageStats, RouteDecision,
    RouteOutcome, UsageRecord,
};
#[cfg(feature = "chain")]
pub use iroh::{
    IrohAlpnEntry, IrohAlpnList, IrohClient, IrohEndpointId, IrohInfo, IrohPublishResult,
};
#[cfg(feature = "inference")]
pub use media_gen::{MediaGenCatalog, MediaGenClient, MediaGenInput, MediaGenInputRole};
#[cfg(feature = "payments")]
pub use payment::{PaymentChallenge, PaymentClient, PaymentCredential, PaymentReceipt};
#[cfg(feature = "inference")]
pub use provider::{
    ChatMessage, ChatOptions, ChatResponse, ComputeBond, ComputeBondParams, GpuDevice, GpuVendor,
    HardwareProfile, MicroNodeIdentity, ModelEndpoint, ModelLoad, ProviderClient,
    ProviderModelLoad, ProviderStats, ServeOptions, Visibility,
};
pub use rpc::RpcClient;
#[cfg(feature = "settlement")]
pub use settle::{PlanBuilder, SettleClient, SplitRule, preview_split};
#[cfg(feature = "settlement")]
pub use settlement::{
    ChannelClose, EscrowPage, MeterBond, SettleResponse, SettlementClient, SettlementRequest,
    owner_request_message,
};
#[cfg(feature = "chain")]
pub use sla::{SlaClient, SlaOutstandingProbe, SlaOutstandingProbes, SlaParams, SlaProbeIssued};
#[cfg(feature = "chain")]
pub use snapshot::{SnapshotClient, SnapshotList, SnapshotManifest, SnapshotSummary};
pub use sse::{SseDecoder, SseEvent};
#[cfg(feature = "chain")]
pub use staking::StakingClient;
#[cfg(feature = "inference")]
pub use streaming::{SseConnection, StreamingClient};
#[cfg(feature = "chain")]
pub use tee::{
    AttestationChallenge, AttestationResult, MeasurementRegister, TeeClient, TeeInfo, TeeProvider,
    TeeProviderList, TeeVerifyResult,
};
#[cfg(feature = "chain")]
pub use token::{
    TokenBalance, TokenClient, TokenInfo, TokenList, TokenListEntry, WTNZO_EVM_ADDRESS,
};
pub use typed_tx::{NodeRpc, PreparedTransaction, TxKind, TypedTransaction, TypedTxClient};
pub use types::{
    Address, AgentIdentity, MmprojSpec, ModelInfo, PageRequest, PeerHintRecord, ServingProfile,
};
#[cfg(feature = "chain")]
pub use validator::{
    ListValidatorsResult, ValidatorClient, ValidatorRegistryEntry, ValidatorStatus,
};
pub use wallet::{AssetBalance, HybridSigner, WalletBalance, WalletClient};
#[cfg(feature = "chain")]
pub use zk::{
    AttestedFinalityProof, CircuitInfo, TeeZkProofResult, TeeZkVerifyResult, ZkClient, ZkProof,
    ZkProofLeg, ZkVerifyResult,
};

#[cfg(all(doctest, feature = "full"))]
#[doc = include_str!("../README.md")]
pub struct ReadmeDoctests;
