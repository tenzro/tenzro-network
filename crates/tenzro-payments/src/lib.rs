//! Payment protocol support for Tenzro Network
//!
//! Implements multi-protocol payment support for AI agents and humans.
//!
//! # Protocols
//!
//! - **MPP** (Machine Payments Protocol) — HTTP 402-based session payments
//! - **x402** — HTTP 402 one-shot payments

pub mod challenge_store;
pub mod dvp;
pub mod error;
pub mod traits;
pub mod types;

// RFC 9421 HTTP Message Signatures on the requests agents send
pub mod rfc9421;

// Bridge (bridge.xyz) stablecoin rail: wallets, transfers, webhooks.

#[cfg(feature = "mpp")]
pub mod mpp;

#[cfg(feature = "x402")]
pub mod x402;

pub mod acp;
pub mod ap2;
pub mod gateway;
pub mod metering;
pub mod micropayment_route;
pub mod middleware;
pub mod payer_auth;
pub mod receipt_ledger;
pub mod revenue_split;
pub mod settlement_asset;
pub mod settlement_mirror;
pub mod terms_gate;
pub mod ucp;

#[cfg(test)]
mod test_support;

// Re-export commonly used types
pub use challenge_store::ChallengeStore;
pub use error::{PaymentError, Result};
pub use gateway::{
    PaymentExpectation, PlanRail, RailOutcome, SettlementInstruction,
    SettlementPreferencesResolver, SettlementRail, TenzroPaymentGateway,
};
pub use payer_auth::{EnrolledKeys, PayerKeyResolver, VerifiedPayer};
pub use receipt_ledger::{ReceiptLedger, ReceiptStore};
pub use revenue_split::{RevenueSplit, SplitPayees, SplitShare, split_revenue};
pub use settlement_asset::{
    Caip19, SettlementAsset, SettlementPreferences, SettlementRoute, SwapQuoter, route_settlement,
};
pub use terms_gate::{PaymentIntent, TermsGate};
pub use traits::{PaymentGateway, PaymentProtocol};
pub use types::{
    PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification, SettlementLeg,
};
