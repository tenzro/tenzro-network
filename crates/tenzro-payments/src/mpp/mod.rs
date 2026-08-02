//! Machine Payments Protocol (MPP) implementation
//!
//! Implements the MPP specification co-authored by Stripe and Tempo.
//! HTTP 402 → Challenge → Credential → Receipt flow with session support.

pub mod challenge;
pub mod client;
pub mod credential;
pub mod receipt;
pub mod server;
pub mod session;
pub mod stripe;
pub mod stripe_spt;

pub use challenge::MppChallenge;
pub use client::MppClient;
pub use credential::{
    IetfPaymentBody, MppCredential, TenzroMandateExtension, TenzroSettlementProof,
};
pub use receipt::MppReceipt;
pub use server::MppPaymentServer;
pub use session::{MppSession, MppSessionManager};
pub use stripe::StripeClient;
pub use stripe_spt::{
    SharedPaymentGrantedToken, SharedPaymentIssuedToken, SptCeilingResolver, SptCeilingSnapshot,
    SptOutcome, SptStatus, SptWebhookEvent, UsageLimits, classify_spt_webhook,
    extract_granted_token, extract_issued_token,
};
