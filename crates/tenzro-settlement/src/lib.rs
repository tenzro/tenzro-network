//! Shared settlement pieces for Tenzro Network
//!
//! Value moves only in consensus: payments, escrows, settlement plans and
//! their netting are VM transactions. This crate holds the pure pieces the
//! VM and the node share: the escrow record and its release-proof check
//! and the netting algorithm. It keeps no books of its own.

pub mod error;
pub mod escrow;
pub mod netting;

pub use error::{Result, SettlementError};
pub use escrow::{EscrowAccount, EscrowStatus};
pub use netting::{
    NettingBatch, Obligation, SettlementInstruction, compute_batch, compute_batch_id,
    verify_netting_invariant,
};
