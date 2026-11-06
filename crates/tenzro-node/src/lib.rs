//! Tenzro Network Full Node
//!
//! This crate provides the full node implementation for Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Overview
//!
//! The `tenzro-node` crate ties together all Tenzro Network subsystems into
//! a running node that can participate in the network as:
//!
//! - **Validator**: Participate in consensus and block production
//! - **Inference Provider**: Serve AI model inference requests
//! - **TEE Provider**: Provide confidential computing services
//! - **User Node**: Interact with the network without providing services
//!
//! # Architecture
//!
//! The node orchestrates the following subsystems in a specific startup order:
//!
//! 1. **Storage** - RocksDB-backed persistent state
//! 2. **Network** - iroh gossip, identity endpoint records and relays
//! 3. **TEE** - Trusted Execution Environment (optional)
//! 4. **VM Runtime** - Multi-VM execution (EVM + SVM)
//! 5. **Token Economics** - TNZO token, staking, governance, treasury
//! 6. **Wallet** - permissionless wallet service
//! 7. **Consensus** - DAG BFT consensus with checkpoint certificates
//! 8. **Settlement** - Payment settlement engine
//! 9. **AI Infrastructure** - Models, providers, agents
//! 10. **Bridge** - Cross-chain interoperability
//!
//! # Features
//!
//! - **Multi-role Support**: Configure the node for different network roles
//! - **Health Monitoring**: Track subsystem health and overall node status
//! - **Metrics Collection**: Collect performance and usage metrics
//! - **JSON-RPC API**: Query and interact with the node via RPC
//! - **Graceful Shutdown**: Clean shutdown of all subsystems
//!
//! # Example
//!
//! ```no_run
//! use tenzro_node::{NodeConfig, TenzroNode};
//!
//! #[tokio::main]
//! async fn main() -> tenzro_node::Result<()> {
//!     // Create node with default config
//!     let config = NodeConfig::default_validator();
//!     let mut node = TenzroNode::new(config).await?;
//!
//!     // Start all subsystems
//!     node.start().await?;
//!
//!     // Node is now running...
//!
//!     // Stop the node
//!     node.stop().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Configuration
//!
//! The node can be configured via:
//! - Configuration file (TOML/JSON)
//! - Environment variables
//! - Command-line arguments
//!
//! See [`NodeConfig`] for available configuration options.

// The light build (no `inference` feature) leaves out the local-serving half
// of handlers whose shared helpers (billing, receipts, catalog loading) the
// standard build uses. Those helpers are compiled in both builds and unused in
// the light one; warning about each would be noise, so the light build allows
// it. The standard build keeps every lint.
#![cfg_attr(
    not(feature = "inference"),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

/// The model parser child is this executable started with the parse-jail
/// argument (`tenzro_model::parse_jail`). The node's `main` enters it first
/// thing; a test binary has no `main` of its own, so it enters it from an
/// initialiser that runs before the test harness starts (after the standard
/// library has read the arguments): the unit-test binary through the static
/// below, an integration-test binary through
/// [`enter_parse_jail_child_before_tests!`].
#[cfg(all(
    test,
    feature = "inference",
    any(target_os = "linux", target_vendor = "apple")
))]
#[used]
#[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
#[cfg_attr(
    target_vendor = "apple",
    unsafe(link_section = "__DATA,__mod_init_func")
)]
static ENTER_PARSE_JAIL_CHILD: InitFn = __enter_parse_jail_child;

/// The same entry on Windows, where the C runtime calls its initialisers with
/// no arguments. `.CRT$XCV` sorts after `.CRT$XCU`, where the C++ static
/// constructors (ONNX Runtime's among them) are, so those have run when the
/// parser child starts.
#[cfg(all(test, feature = "inference", windows))]
#[used]
#[unsafe(link_section = ".CRT$XCV")]
static ENTER_PARSE_JAIL_CHILD_WINDOWS: extern "C" fn() = __enter_parse_jail_child_windows;

/// The initialiser that enters the model parser child on Windows; see
/// [`__enter_parse_jail_child`].
#[cfg(all(feature = "inference", windows))]
#[doc(hidden)]
pub extern "C" fn __enter_parse_jail_child_windows() {
    tenzro_model::parse_jail::enter_if_requested();
}

/// The initialiser that enters the model parser child when this executable
/// was started as one. Installed by the test binaries; never called directly.
#[cfg(all(
    feature = "inference",
    any(target_os = "linux", target_vendor = "apple")
))]
#[doc(hidden)]
// The pointers are the C runtime's own, handed on unread to the initialisers
// after this one.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn __enter_parse_jail_child(
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
) {
    #[cfg(target_os = "linux")]
    if std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new(
            tenzro_model::parse_jail::PARSE_JAIL_ARG,
        ))
    {
        // SAFETY: called from the C runtime's initialiser loop with the
        // arguments it passes every initialiser.
        unsafe { run_later_initialisers(__enter_parse_jail_child, argc, argv, envp) };
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (argc, argv, envp);
    tenzro_model::parse_jail::enter_if_requested();
}

/// Installs [`__enter_parse_jail_child`] as an initialiser of an
/// integration-test binary whose tests load a model, so the parser child it
/// starts as itself parses the model instead of running the test harness.
#[cfg(feature = "inference")]
#[macro_export]
macro_rules! enter_parse_jail_child_before_tests {
    () => {
        #[cfg(any(target_os = "linux", target_vendor = "apple"))]
        #[used]
        #[cfg_attr(target_os = "linux", unsafe(link_section = ".init_array"))]
        #[cfg_attr(
            target_vendor = "apple",
            unsafe(link_section = "__DATA,__mod_init_func")
        )]
        static ENTER_PARSE_JAIL_CHILD: extern "C" fn(i32, *const *const u8, *const *const u8) =
            $crate::__enter_parse_jail_child;

        #[cfg(windows)]
        #[used]
        #[unsafe(link_section = ".CRT$XCV")]
        static ENTER_PARSE_JAIL_CHILD_WINDOWS: extern "C" fn() =
            $crate::__enter_parse_jail_child_windows;
    };
}

/// The signature the C runtime calls an initialiser with.
#[cfg(all(
    feature = "inference",
    any(target_os = "linux", target_vendor = "apple")
))]
type InitFn = extern "C" fn(i32, *const *const u8, *const *const u8);

/// Runs the initialisers that follow `this` in the executable's
/// `.init_array`, in order, as the C runtime would before `main`.
///
/// This initialiser comes before those of the C++ code linked in after the
/// Rust crates, ONNX Runtime's static objects among them, and the parse
/// needs them. The parser child exits inside the parse and never returns to
/// the C runtime, so no initialiser runs twice; any other process returns
/// before this is reached.
#[cfg(all(feature = "inference", target_os = "linux"))]
unsafe fn run_later_initialisers(
    this: InitFn,
    argc: i32,
    argv: *const *const u8,
    envp: *const *const u8,
) {
    unsafe extern "C" {
        static __init_array_start: [InitFn; 0];
        static __init_array_end: [InitFn; 0];
    }
    let start = (&raw const __init_array_start).cast::<InitFn>();
    let end = (&raw const __init_array_end).cast::<InitFn>();
    let len = (end as usize - start as usize) / std::mem::size_of::<InitFn>();
    // SAFETY: the linker bounds the array with these two symbols; each slot
    // holds an initialiser.
    let all = unsafe { std::slice::from_raw_parts(start, len) };
    if let Some(at) = all.iter().position(|f| *f as usize == this as usize) {
        for init in &all[at + 1..] {
            init(argc, argv, envp);
        }
    }
}

pub mod a2a;
pub mod access;
pub mod access_signer;
mod acp_seller;
pub mod admin_audit;
pub mod agent_accounts;
pub mod agent_audit;
pub mod agent_delegation;
pub mod agent_guardrails;
mod agent_http_signature;
pub mod announce;
pub mod approval_effects;
pub mod attestation_log;
pub mod attestation_rpc;
pub mod autotune_sampler;
pub mod batch_signing;
pub mod block_sync;
pub mod bridge_reserve;
pub mod bridge_routes;
pub mod calendar;
pub mod capacity_probe;
mod catalog_fault;
mod catalog_rpc;
pub mod catalog_sync;
pub mod certified_import;
pub mod challenge_rpc;
pub mod chat_content;
pub mod cluster_identity;
pub mod compute_index_reporter;
pub mod compute_observations;
pub mod config;
pub mod connector;
pub mod consensus_driver;
pub mod continuity;
pub mod credentials;
pub mod da_committee;
pub mod da_committee_surface;
pub mod data_integrity;
pub mod decode_check;
pub mod device_rpc;
pub mod doctor;
mod duty_rpc;
pub mod egress_guard;
pub mod engine_roles;
pub mod epoch_state_store;
pub mod erc8004_mirror;
pub mod error;
mod eth_block_param;
#[cfg(test)]
#[path = "../tests/eth_compat/node.rs"]
mod eth_wallets;
mod evidence_pack;
pub mod exposure;
pub mod fd_limit;
pub mod gcra;
mod governance_rpc;
pub mod hash_vouchers;
pub mod hosted_operators;
mod insurance_rpc;
pub mod policy_reflection;
mod provider_listing_rpc;
mod token_rpc;
pub mod tool_call_record;
pub mod training_provenance;
#[cfg(test)]
mod validator_net_tests;
/// The EU AI Act disclosure. Lives in `tenzro-types` now, because the CLI
/// renders the same text this emits and the two must not drift.
pub use tenzro_types::eu_ai_disclosure;
pub mod account_outflow_rpc;
pub mod beacon;
pub mod da_retention;
pub mod event_index;
pub mod event_loop;
pub mod fee_market_rpc;
pub mod forward_billing;
pub mod genesis;
pub mod gpu_revocation;
pub mod handle;
pub mod hardware_evm_signer;
pub mod hardware_possession;
pub mod health;
pub mod history_archive;
pub mod host_firewall;
pub mod http_client;
pub mod http_surface;
pub mod identity_bootstrap;
pub mod identity_mirror;
pub mod infer;
pub mod inference_admission;
pub mod inference_challenge;
pub mod inference_pricing;
pub mod inference_receipt;
pub mod ip_rate_limit;
pub mod key_release_rpc;
mod mirror_rpc;
pub mod network_params_rpc;
mod network_rpc;
pub mod optimistic;
pub mod relay_health;
pub mod remote_tpm;
#[cfg(unix)]
pub mod tpm_key_holder;
mod trust_hooks;
mod trust_rpc;
pub mod verifiable_inference;
/// Validator keyset generation and on-disk layout.
///
/// Lives in `tenzro-keygen` now, re-exported here so every existing
/// `tenzro_node::keygen::...` path still resolves. It moved because the CLI
/// needs it — provisioning a validator's keys happens before there is a node
/// to do it with — and reaching it through this crate meant `tenzro-cli`
/// pulled 1062 crates, llama.cpp's C++ build among them, to offer `setup`.
pub use tenzro_keygen as keygen;
pub mod decision_rpc;
pub mod images_http;
#[cfg(feature = "inference")]
pub mod kv_continuity;
pub mod kya_credential;
pub mod lane_resolver;
pub mod layer_pipeline;
pub mod ledger_payment;
pub mod liveness;
#[cfg(feature = "inference")]
pub mod loaded_models;
pub mod machine_access;
pub mod machine_admission;
pub mod mcp;
#[cfg(feature = "inference")]
pub mod media_models;
pub mod media_verify;
pub mod metrics;
pub mod modality_http;
pub mod model_blob_fetcher_bridge;
#[cfg(feature = "inference")]
pub mod moe;
pub mod moe_placement;
pub mod network_catalog;
/// Opening a sealed keyset from hardware.
///
/// Moved with `keygen`, which is its only caller here besides `main`.
pub mod node;
#[cfg(feature = "inference")]
pub mod realtime_rpc;
pub mod rerank_rpc;

pub mod speech_rpc;
pub mod task_route;
#[cfg(feature = "inference")]
pub mod training_rpc;
pub mod video_http;
#[cfg(feature = "inference")]
pub mod voice_rpc;

pub mod keystore_rpc;
mod network_legs;
pub mod node_did_document;
pub mod openai_responses;
pub mod openai_tools;
pub mod passkey_rpc;
pub mod payment_channels;
pub mod payment_gate;
pub mod payment_rails;
pub mod payment_receipt_store;
pub mod payment_rpc;
mod plan_rpc;
pub mod pq_rotation_rpc;
pub mod prefix_probe;
pub mod pricing;
pub mod proof_log;
pub mod provider_heartbeat;
mod provider_standing;
mod offer_ranking;
pub mod recovery;
pub mod role_bonds;
pub mod router_inputs;
pub mod rpc;
pub mod rpc_gates;
pub mod rpc_gateway;
pub mod rpc_integrations;
pub mod sealed_delivery;
pub mod sealed_model_attester;
pub mod serving_admission;
pub mod settlement_mirror_dispatch;
pub mod settlement_preferences_bridge;
mod shard_quarantine;
pub mod single_instance;
pub mod sla_attest;
pub mod snapshot;
#[cfg(feature = "inference")]
mod sponsored_inference;
pub mod standby;
pub mod state_commitment;
pub(crate) mod state_reads;
mod state_rpc;
pub mod storage_maintenance;
pub mod storage_provider_runtime;
pub mod streaming;
pub mod surge;
mod svm_rpc;
pub mod terms_gate;
pub mod territory;
pub mod tier;
mod transaction_index;
pub mod validator_signer;
pub mod visibility_rpc;
pub mod web;
mod work_settlements;
mod zk_attest;
mod zk_rpc;

// Re-export commonly used types
// `EconomicsConfig` is the type of a public `NodeConfig` field, so it has to
// be nameable by anyone constructing a config — otherwise the field can be
// read but never set from outside the crate.
pub use config::{EconomicsConfig, NodeConfig};
pub use error::{NodeError, Result};
pub use handle::{NodeHandle, spawn_in_background, spawn_in_background_with_unlocker};
pub use health::{HealthMonitor, HealthStatus, OverallHealth, SubsystemStatus};
pub use metrics::{MetricsCollector, NodeMetrics};
pub use node::{NodeStatus, TenzroNode};
pub use rpc::{EmbeddedAuth, RpcServer, dispatch_embedded};

/// Node crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default data directory
pub const DEFAULT_DATA_DIR: &str = "./data";

/// A node that has not been initialised: no storage, no payment rails, no
/// consensus. Handlers run on it reach their refusal paths.
#[cfg(test)]
pub(crate) async fn bare_node() -> (std::sync::Arc<TenzroNode>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("temp dir");
    let config = NodeConfig {
        data_dir: tmp.path().to_path_buf(),
        ..NodeConfig::default()
    };
    let node = TenzroNode::new(config).await.expect("node");
    (std::sync::Arc::new(node), tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_default_config() {
        let config = NodeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[tokio::test]
    async fn test_node_creation() {
        // Own directory, for the same reason as `handle.rs`: the default data
        // dir is a real one now.
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..NodeConfig::default()
        };
        let node = TenzroNode::new(config).await;
        assert!(node.is_ok());
    }
}
