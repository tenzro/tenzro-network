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
pub mod commission_policy;
pub mod config;
pub mod cortex_gossip;
pub mod erc8004_mirror;
pub mod error;
pub mod eu_ai_disclosure;
pub mod event_loop;
pub mod genesis;
pub mod health;
pub mod liveness;
pub mod mcp;
pub mod metrics;
pub mod node;
pub mod rpc;
pub mod rpc_integrations;
pub mod spending_policy_bridge;
pub mod web;

// Re-export commonly used types
pub use config::NodeConfig;
pub use error::{NodeError, Result};
pub use health::{HealthMonitor, HealthStatus, OverallHealth, SubsystemStatus};
pub use metrics::{MetricsCollector, NodeMetrics};
pub use node::{TenzroNode, NodeStatus};
pub use rpc::RpcServer;

/// Node crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default RPC address
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:8545";

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
        let config = NodeConfig::default();
        let node = TenzroNode::new(config).await;
        assert!(node.is_ok());
    }
}
