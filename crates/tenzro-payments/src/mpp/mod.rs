//! Machine Payments Protocol (MPP) implementation
//!
//! Implements the MPP specification co-authored by Stripe and Tempo.
//! HTTP 402 → Challenge → Credential → Receipt flow with session support.

pub mod challenge;
pub mod credential;
pub mod receipt;
pub mod session;
pub mod server;
pub mod client;
pub mod stripe;

pub use challenge::MppChallenge;
pub use credential::MppCredential;
pub use receipt::MppReceipt;
pub use session::{MppSession, MppSessionManager};
pub use server::MppPaymentServer;
pub use client::MppClient;
pub use stripe::StripeClient;
