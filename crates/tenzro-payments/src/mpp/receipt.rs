//! MPP Receipt types (payment confirmation)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tenzro_types::principal_chain::PrincipalChain;

/// An MPP receipt confirming payment was received and settled.
///
/// Carries the frozen `PrincipalChain` (Agent-Swarm Spec 5) of the payer at
/// the time of settlement. Resolved via `IdentityPaymentBinder`'s
/// `PrincipalChainResolver` from the credential's payer DID; falls back to
/// a synthetic anonymous chain when the credential is unbound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MppReceipt {
    /// Receipt ID
    pub receipt_id: String,
    /// Credential ID this receipt is for
    pub credential_id: String,
    /// Challenge ID
    pub challenge_id: String,
    /// Amount settled
    pub amount: u128,
    /// Asset
    pub asset: String,
    /// Settlement transaction hash (if on-chain)
    pub settlement_tx: Option<String>,
    /// Settlement chain
    pub chain: String,
    /// Receipt timestamp
    pub settled_at: DateTime<Utc>,
    /// Frozen principal chain for the payer at settlement time.
    pub principal_chain: PrincipalChain,
}

impl MppReceipt {
    /// Creates a new MPP receipt with an explicit principal chain.
    ///
    /// Callers must resolve the chain through a `PrincipalChainResolver`
    /// (typically `IdentityRegistry::resolve_by_did` or `resolve_by_address`)
    /// and pass it in. There is no implicit fallback inside the type —
    /// callers without identity context should use
    /// `tenzro_types::principal_chain::anonymous_chain_for_address`.
    pub fn new(
        credential_id: impl Into<String>,
        challenge_id: impl Into<String>,
        amount: u128,
        principal_chain: PrincipalChain,
    ) -> Self {
        Self {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            credential_id: credential_id.into(),
            challenge_id: challenge_id.into(),
            amount,
            asset: "USDC".to_string(),
            settlement_tx: None,
            chain: "tempo".to_string(),
            settled_at: Utc::now(),
            principal_chain,
        }
    }
}
