//! x402 payment protocol implementation (Coinbase)
//!
//! Implements the x402 specification for HTTP 402-based payments.

pub mod payment_required;
pub mod payment_payload;
pub mod facilitator;
pub mod server;
pub mod client;
pub mod coinbase;
pub mod scheme;

pub use payment_required::X402PaymentRequired;
pub use payment_payload::X402PaymentPayload;
pub use facilitator::X402Facilitator;
pub use server::X402PaymentServer;
pub use client::X402Client;
pub use coinbase::CdpFacilitatorClient;
pub use scheme::{
    CdpFacilitatorVerifier, DelegationVerifier, Eip3009Backend, Erc7710Backend,
    FacilitatorVerifier, NullDelegationVerifier, Permit2Backend, SchemeBackend,
    SchemeRegistry, TenzroHybridBackend, DEFAULT_SCHEME,
};
