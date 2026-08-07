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
//! 2. **Network** - libp2p-based P2P networking
//! 3. **TEE** - Trusted Execution Environment (optional)
//! 4. **VM Runtime** - Multi-VM execution (EVM + SVM)
//! 5. **Token Economics** - TNZO token, staking, governance, treasury
//! 6. **Wallet** - MPC wallet service
//! 7. **Consensus** - HotStuff-2 BFT consensus (validators only)
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

pub mod a2a;
pub mod account_record;
pub mod admission;
pub mod agent_kit_auth;
pub mod api_key;
pub mod app_registry;
pub mod autotune_sampler;
pub mod bazaar_store;
pub mod block_sync;
pub mod bootstrap_dns;
pub mod bridge_analytics;
pub mod builtin_dispatch;
pub mod canton_analytics;
pub mod canton_jwt;
pub mod canton_network;
pub mod chat_content;
pub mod cluster_serving_runtime;
pub mod commission_policy;
pub mod compute_rental_runtime;
pub mod config;
pub mod cortex_gossip;
pub mod da_committee;
pub mod da_committee_surface;
pub mod database_routes;
pub mod db_engine_registry;
pub mod db_engines;
pub mod db_holder_dispatch;
pub mod delegation_scope_oracle;
pub mod device_rpc;
pub mod did_resolution;
pub mod epoch_state_store;
pub mod erc8004_daml_mirror;
pub mod erc8004_mirror;
pub mod erc8004_reputation_dispatcher;
pub mod erc8004_svm_mirror;
pub mod error;
pub mod escrow_resolver_bridge;
pub mod eu_ai_disclosure;
pub mod event_loop;
pub mod files_api;
pub mod files_routes;
pub mod files_rpc;
pub mod files_store;
pub mod functions;
pub mod genesis;
pub mod handle;
pub mod health;
pub mod http_client;
pub mod identity_gossip;
pub mod infer;
pub mod inference_challenge;
pub mod ingress;
mod interaction_rpc;
pub mod ip_rate_limit;
pub mod keygen;
pub mod lane_resolver;
pub mod lifecycle_state_bridge;
pub mod liveness;
pub mod machines;
pub mod mandate_store;
pub mod mcp;
pub mod mcp_plugin_host;
pub mod metrics;
pub mod model_blob_fetcher_bridge;
pub mod moe;
pub mod mpc_keygen;
pub mod mpc_keyshare_store;
pub mod mpc_libp2p_adapter;
pub mod mpc_threshold_signer;
pub mod network_catalog;
pub mod node;
pub mod node_did_document;
pub mod openai_responses;
pub mod orchestrator;
pub mod orchestrator_bridge;
pub mod passkey_rpc;
pub mod placement;
pub mod prepaid_account_ledger;
pub mod pricing;
pub mod remote_access;
pub mod remote_access_rpc;
pub mod remote_access_session;
pub mod rpc;
pub mod rpc_gates;
pub mod rpc_gateway;
pub mod rpc_integrations;
pub mod saga_executor;
pub mod sealed_agent_wallet_signer;
pub mod sealed_model_attester;
pub mod serving_admission;
pub mod settle_authorized;
pub mod settlement_mirror_dispatch;
pub mod settlement_preferences_bridge;
pub mod single_instance;
pub mod sites;
pub mod skill_sandbox;
pub mod sla_slashing_bridge;
pub mod snapshot;
pub mod spending_policy_bridge;
pub mod spt_ceiling_bridge;
pub mod spt_revocation_dispatcher;
pub mod stable_controller_driver;
pub mod stable_conversion;
pub mod storage_provider_runtime;
pub mod streaming;
#[cfg(feature = "visa-tap")]
pub mod tap_reputation_dispatcher;
pub mod train_slashing_bridge;
pub mod trainer_daemon;
pub mod training_enclave_verifier;
pub mod visibility_rpc;
pub mod web;
pub mod workflow_dispatcher;
pub mod workflow_executor;
pub mod workflow_runtime;
pub mod x402_idempotency_store;

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

/// Default RPC bind address.
///
/// Validators are the public infrastructure class of the network: they
/// produce blocks AND serve RPC to wallets, dApps, and joiner nodes that
/// need to read chain state. A network is only "open" when more than
/// one validator can be dialled directly — otherwise the chain has
/// decentralized consensus but a centralized gateway.
///
/// The default therefore binds to `0.0.0.0:8545`. Operators who want a
/// loopback-only RPC (e.g. a model/TEE provider operated behind a
/// trusted controller, or a dev node) opt in with
/// `--rpc-addr 127.0.0.1:8545`. Per-role defaults in `NodeConfig::default_*`
/// follow the same rule: validator binds public, provider/TEE bind loopback.
pub const DEFAULT_RPC_ADDR: &str = "0.0.0.0:8545";

/// Default data directory
pub const DEFAULT_DATA_DIR: &str = "./data";

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
