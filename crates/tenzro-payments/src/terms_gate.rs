//! The one authority check a payment passes.
//!
//! A payer that is a delegated agent pays only inside its consensus Terms:
//! the scope, the per-transaction and per-period limits, the counterparties
//! and chains its root granted. The node implements [`TermsGate`] over
//! consensus state; nothing else in this crate decides whether an agent may
//! pay.

use crate::error::Result;

/// What a payer proposes to pay, as the Terms check sees it.
#[derive(Debug, Clone, Copy)]
pub struct PaymentIntent<'a> {
    /// The paying DID.
    pub payer_did: &'a str,
    /// Value moved, smallest unit.
    pub amount: u128,
    /// The operation, as Terms name it.
    pub operation: &'a str,
    /// The payment protocol (`x402`, `mpp`, ...).
    pub protocol: Option<&'a str>,
    /// The chain the payment settles on.
    pub chain: Option<&'a str>,
    /// The payee, hex address or DID.
    pub counterparty: Option<&'a str>,
}

/// Decides a payment from the payer's consensus Terms. A payer with no Terms
/// is not a delegated agent and pays under its own key; a delegated agent is
/// held to its Terms and to its kill-switch state.
pub trait TermsGate: Send + Sync {
    /// `Ok` when the payer may make this payment.
    fn authorize(&self, intent: &PaymentIntent<'_>) -> Result<()>;
}
