//! Visa Trusted Agent Protocol (TAP) implementation
//!
//! Implements agent verification using RFC 9421 HTTP Message Signatures
//! for agentic commerce. Provides both server-side verification and
//! client-side request signing capabilities.

pub mod types;
pub mod server;
pub mod client;
pub mod registry;
pub mod did_registry;
pub mod verifier;

pub use types::{
    AgentRecognition, AgentTag, ConsumerRecognition, PaymentContainer,
    PaymentMethod, VisaTapChallenge,
};
pub use server::VisaTapServer;
pub use client::VisaTapClient;
pub use registry::VisaAgentRegistryClient;
pub use did_registry::DidResolverAgentRegistry;
pub use verifier::{TapVerifier, VerificationResult};
