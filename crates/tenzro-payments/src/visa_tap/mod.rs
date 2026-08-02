//! Visa Trusted Agent Protocol (TAP) implementation
//!
//! Implements agent verification using RFC 9421 HTTP Message Signatures
//! for agentic commerce. Provides both server-side verification and
//! client-side request signing capabilities.

pub mod client;
pub mod did_registry;
pub mod facilitator_server;
pub mod issuer;
pub mod registry;
pub mod server;
pub mod types;
pub mod verifier;

pub use client::VisaTapClient;
pub use did_registry::DidResolverAgentRegistry;
pub use facilitator_server::{
    TapFacilitatorState, TapSupportedResponse, TapVerifyRequest, TapVerifyResponse,
    tap_facilitator_router,
};
pub use issuer::{
    AgentToken, AgentTokenStatus, CreatePaymentInstructionRequest, CredentialVerification,
    DEFAULT_ISSUER_API_BASE, IssuerApiError, PaymentInstruction, PaymentInstructionStatus,
    ProvisionAgentTokenRequest, VerifyCredentialRequest, VisaTapIssuerClient,
};
pub use registry::VisaAgentRegistryClient;
pub use server::VisaTapServer;
pub use types::{
    AgentRecognition, AgentTag, ConsumerRecognition, PaymentContainer, PaymentMethod,
    VisaTapChallenge,
};
pub use verifier::{TapVerifier, VerificationResult};
