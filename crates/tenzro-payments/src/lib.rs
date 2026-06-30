//! Payment protocol support for Tenzro Network
//!
//! Implements multi-protocol payment support for AI agents and humans.
//!
//! # Protocols
//!
//! - **MPP** (Machine Payments Protocol) — HTTP 402-based payments co-authored by Stripe and Tempo
//! - **x402** — Coinbase's HTTP 402 payment protocol
//! - **Tempo** — Direct participation in the Tempo network for stablecoin settlement
//! - **Visa TAP** (Trusted Agent Protocol) — RFC 9421 agent verification for agentic commerce
//! - **Mastercard Agent Pay** — Agentic commerce with Know Your Agent (KYA) and agentic tokens

pub mod error;
pub mod traits;
pub mod types;
pub mod challenge_store;

// Shared RFC 9421 HTTP Message Signatures foundation (used by Visa TAP and Mastercard Agent Pay)
pub mod rfc9421;

#[cfg(feature = "mpp")]
pub mod mpp;

#[cfg(feature = "x402")]
pub mod x402;

pub mod tempo;

#[cfg(feature = "visa-tap")]
pub mod visa_tap;

#[cfg(feature = "mastercard-agent-pay")]
pub mod mastercard;

#[cfg(feature = "ap2")]
pub mod ap2;

pub mod identity_binding;
pub mod gateway;
pub mod middleware;

// Re-export commonly used types
pub use error::{PaymentError, Result};
pub use traits::{PaymentProtocol, PaymentGateway};
pub use types::{PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification};
pub use challenge_store::ChallengeStore;
pub use gateway::{Conversion, ConversionHook, IdentityConversionHook, SettlementCallback};
pub use identity_binding::{
    EscrowResolver, EscrowSnapshot, IdentityPaymentBinder, LifecyclePosture,
    LifecycleStateResolver, SpendingPolicyResolver, SpendingPolicySnapshot,
};
