//! Mastercard Agent Pay implementation
//!
//! Implements the Mastercard agentic commerce framework with Know Your Agent (KYA)
//! verification, agentic token issuance, and purchase intent management.
//!
//! # Overview
//!
//! Mastercard Agent Pay is a payment protocol designed for AI agents to make
//! autonomous purchases. It includes:
//!
//! - **Know Your Agent (KYA)**: Identity verification using TDIP
//! - **Agentic Tokens**: Tokenized payment credentials (mapping to MDES)
//! - **Purchase Intent**: Structured representation of what an agent wants to buy
//! - **RFC 9421 Signatures**: HTTP message signatures for agent authentication
//!
//! # Example
//!
//! ```no_run
//! use tenzro_payments::mastercard::{MastercardAgentPayServer, KyaVerifier};
//! use tenzro_payments::PaymentProtocol;
//! use tenzro_identity::IdentityRegistry;
//! use tenzro_payments::rfc9421::TenzroAgentRegistry;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let identity_registry = Arc::new(IdentityRegistry::new());
//! let agent_registry = Arc::new(TenzroAgentRegistry::new(identity_registry.clone()));
//!
//! let server = MastercardAgentPayServer::new(
//!     "merchant_123",
//!     "0xrecipient",
//!     agent_registry,
//!     identity_registry,
//! )
//! .with_default_asset("USDC")
//! .with_default_chain("tempo");
//!
//! // Create a payment challenge
//! let challenge = server
//!     .create_challenge("/api/product", 1000, "USDC", "0xrecipient")
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod kya;
pub mod server;
pub mod token_service;
pub mod types;

pub use client::MastercardAgentPayClient;
pub use kya::KyaVerifier;
pub use server::MastercardAgentPayServer;
pub use token_service::AgenticTokenService;
pub use types::{
    AgentPayChallenge, AgentPayDomainEvent, AgenticToken, AgenticTokenType, KyaLevel,
    KyaVerification, PurchaseIntent, PurchaseItem,
};
