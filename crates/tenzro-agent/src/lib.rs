//! AI Agent Infrastructure for Tenzro Network
//!
//! This crate provides the core infrastructure for self-sovereign AI agents on
//! the Tenzro Network, an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Features
//!
//! - **Agent Identity Management**: Self-sovereign agent identities with auto-provisioned MPC wallets
//! - **Lifecycle Management**: State machine for agent lifecycle (Created → Active → Suspended → Terminated)
//! - **Inter-Agent Messaging**: Message routing, queuing, and delivery between agents
//! - **Capability Registry**: Register, verify, and discover agent capabilities
//! - **A2A Protocol**: Agent-to-Agent communication protocol (inspired by Google A2A + Anthropic MCP)
//! - **Agent Runtime**: Unified runtime environment coordinating all subsystems
//!
//! # Architecture
//!
//! The agent system consists of several interconnected components:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                      Agent Runtime                          │
//! │  Coordinates all subsystems and provides unified interface  │
//! └─────────────────────────────────────────────────────────────┘
//!                              │
//!              ┌───────────────┼───────────────┐
//!              │               │               │
//!    ┌─────────▼────────┐  ┌──▼─────────┐  ┌─▼────────────┐
//!    │ Identity Manager │  │ Lifecycle  │  │   Message    │
//!    │  - Registration  │  │  - States  │  │   Router     │
//!    │  - MPC Wallets  │  │  - Events  │  │  - Queuing   │
//!    └──────────────────┘  └────────────┘  └──────────────┘
//!              │                                   │
//!    ┌─────────▼────────┐           ┌─────────────▼────────┐
//!    │   Capability     │           │   A2A Protocol       │
//!    │    Registry      │           │  - Task Delegation   │
//!    │  - Discovery     │           │  - MCP Bridge        │
//!    └──────────────────┘           └──────────────────────┘
//! ```
//!
//! # Examples
//!
//! ## Registering and activating an agent
//!
//! ```no_run
//! use tenzro_agent::{AgentRuntime, error::Result};
//! use tenzro_types::{primitives::Address, agent::Capability};
//!
//! # async fn example() -> Result<()> {
//! let runtime = AgentRuntime::new()?;
//!
//! // Register a new agent
//! let creator = Address::from([1u8; 32]);
//! let capabilities = vec![Capability::MultiAgentCoordination];
//!
//! let agent = runtime.register_agent(
//!     "MyAgent".to_string(),
//!     creator,
//!     capabilities,
//!     false, // not TEE-backed
//!     0,     // nonce
//! ).await?;
//!
//! // Activate the agent
//! runtime.activate_agent(&agent.identity.agent_id).await?;
//!
//! println!("Agent {} is now active!", agent.identity.agent_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Sending messages between agents
//!
//! ```no_run
//! use tenzro_agent::{AgentRuntime, error::Result};
//! use tenzro_types::{AgentMessage, AgentMessageType};
//!
//! # async fn example(runtime: &AgentRuntime, sender: tenzro_types::AgentIdentity, receiver: tenzro_types::AgentIdentity) -> Result<()> {
//! // Create a message
//! let message = AgentMessage::new(
//!     sender,
//!     receiver,
//!     AgentMessageType::Query,
//!     b"Hello, agent!".to_vec(),
//! );
//!
//! // Send the message
//! runtime.send_message(message).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Delegating tasks using A2A protocol
//!
//! ```no_run
//! use tenzro_agent::{AgentRuntime, error::Result};
//! use std::collections::HashMap;
//!
//! # async fn example(runtime: &AgentRuntime, sender: tenzro_types::AgentIdentity, receiver: tenzro_types::AgentIdentity) -> Result<()> {
//! let mut parameters = HashMap::new();
//! parameters.insert("input".to_string(), serde_json::json!("data to process"));
//!
//! let task_id = runtime.delegate_task(
//!     sender,
//!     receiver,
//!     "data_analysis".to_string(),
//!     parameters,
//! ).await?;
//!
//! println!("Task {} delegated successfully", task_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## Discovering agents by capability
//!
//! ```no_run
//! use tenzro_agent::{AgentRuntime, error::Result};
//! use tenzro_types::agent::Capability;
//!
//! # fn example(runtime: &AgentRuntime) -> Result<()> {
//! let capability = Capability::MultiAgentCoordination;
//! let agents = runtime.find_agents_with_capability(&capability);
//!
//! println!("Found {} agents with coordination capability", agents.len());
//! # Ok(())
//! # }
//! ```

pub mod a2a_protocol;
pub mod autonomy;
pub mod capabilities;
pub mod error;
pub mod identity;
pub mod lifecycle;
pub mod messaging;
pub mod pdis;
pub mod runtime;
pub mod swarm;
pub mod transactions;

// Re-export commonly used types
pub use a2a_protocol::{
    A2aMessage, A2aMessageType, A2aProtocol, CapabilityInfo, CapabilityQuery, CapabilityResponse,
    McpBridge, McpClient, McpMessage, McpMessageType, TaskRequest, TaskResponse, ToolCall, ToolResult,
};
pub use autonomy::{
    AgentAutonomy, AgentExecutionLoop, AutonomousScheduler, ScheduledTask, SpendingPolicy,
    TaskExecutor, TaskHandler, TaskResult,
};
pub use swarm::SwarmManager;
pub use capabilities::{AttestationConfig, CapabilityAttestation, CapabilityRegistry};
pub use error::{AgentError, Result};
pub use identity::{AgentIdentityManager, AgentStatus, RegisteredAgent};
pub use lifecycle::{AgentLifecycle, AgentLifecycleEvent, AgentLifecycleInfo, AgentState, HeartbeatConfig};
pub use messaging::{
    EchoMessageHandler, GossipsubTransport, MessageHandler, MessageRouter, MessageRouterConfig,
    NetworkTransport, RateLimitConfig,
};

pub use pdis::{
    CredentialType, DelegationScope, DidResolutionResult, GuardianIdentity, IdentityStatus,
    InheritedCredential, KycTier, PdisAgentIdentity, PdisRegistry, TimeBound,
};

pub use runtime::{AgentRuntime, AgentRuntimeConfig, RuntimeStatistics};
pub use transactions::{
    AgentTransaction, AgentTransactionExecutor, AgentTransactionResult, TransactionSubmitter,
};

// Re-export tenzro-identity types for the migration path
pub mod tip {
    //! Tenzro Decentralized Identity Protocol (TDIP) types — the successor to PDIS.
    //!
    //! Consumers should migrate from `tenzro_agent::pdis::*` to `tenzro_agent::tip::*`
    //! (or depend on `tenzro-identity` directly).
    pub use tenzro_identity::*;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_exports() {
        // Ensure main types are accessible
        let _ = AgentRuntime::new();
        let _ = CapabilityRegistry::new();
        let _ = MessageRouter::new();
        let _ = A2aProtocol::new();
    }

    #[tokio::test]
    async fn test_end_to_end_workflow() {
        use tenzro_types::{agent::Capability, primitives::Address};

        // Create runtime
        let runtime = AgentRuntime::new().unwrap();

        // Register two agents
        let creator = Address::from([1u8; 32]);
        let cap = Capability::MultiAgentCoordination;

        runtime
            .register_agent("Agent1".to_string(), creator, vec![cap.clone()], false, 0)
            .await
            .unwrap();

        runtime
            .register_agent("Agent2".to_string(), creator, vec![cap.clone()], false, 1)
            .await
            .unwrap();

        // Both agents are auto-activated by `register_agent` (see
        // runtime.rs:559) — no separate activation step needed.

        // Find agents with capability
        let agents = runtime.find_agents_with_capability(&cap);
        assert_eq!(agents.len(), 2);

        // Check statistics
        let stats = runtime.get_statistics().await;
        assert_eq!(stats.total_agents, 2);
        assert_eq!(stats.active_agents, 2);
    }
}
