//! Machine Payments Protocol (MPP) implementation
//!
//! Implements the MPP specification co-authored by Stripe and Tempo:
//! HTTP 402 → Challenge → Credential → Receipt, with the `charge` intent
//! (one-shot) and the `session` intent (capped streaming over an on-chain
//! escrow, paid with cumulative vouchers).

pub mod challenge;
pub mod credential;
pub mod receipt;
pub mod server;
pub mod session;

pub use challenge::MppChallenge;
pub use credential::IetfPaymentBody;
pub use receipt::{MppReceipt, PAYMENT_RECEIPT_HEADER};
pub use server::{MPP_INTENT_CHARGE, MPP_INTENT_SESSION, MppPaymentServer};
pub use session::{EscrowReader, EscrowView, MppSession, MppSessionManager, MppSessionState};
