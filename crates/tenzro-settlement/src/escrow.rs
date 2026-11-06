//! Escrow system for pre-funded settlements with release conditions.
//!
//! # On-chain primitive
//!
//! Escrow is a **consensus-mediated** primitive. Funds are locked on-chain at
//! a vault address derived deterministically from the escrow id; only the
//! original signing payer can later release funds to the payee or refund them
//! to themselves. The Native VM is the source of truth for funds and state.
//!
//! Clients submit signed `CreateEscrow` / `ReleaseEscrow` / `RefundEscrow`
//! transactions through the standard transaction pipeline (mempool → block →
//! VM dispatch). The convenience RPC handlers `tenzro_createEscrow` and
//! `tenzro_releaseEscrow` have been removed; the only writes are signed
//! transactions.
//!
//! ## Deterministic identifiers
//!
//! - **`escrow_id`** = `SHA-256("tenzro/escrow/id" || payer || nonce_le)`,
//!   derived by the VM at `CreateEscrow` execution time and surfaced via the
//!   receipt log.
//! - **Vault address** = `Address(SHA-256("tenzro/escrow/vault" || escrow_id))`.
//!   Has no private key. Release/refund payouts are a privileged VM operation
//!   that calls `state.set_balance` directly via a single auditable helper,
//!   never via normal `TnzoToken::transfer`.
//!
//! ## Authorization invariants (enforced by VM)
//!
//! - `CreateEscrow.from` must match the signing payer (verified at mempool
//!   admission). The payload has no separate `payer` field.
//! - `ReleaseEscrow` requires `tx.from == escrow.payer`, status `Funded`,
//!   not expired, and a proof that satisfies the recorded `release_conditions`.
//! - `RefundEscrow` requires `tx.from == escrow.payer` AND (the escrow is
//!   expired OR `release_conditions ∈ {Timeout, Custom}`).
//!
//! The record lives only in VM state at `escrow:<id>` under the system
//! address; readers load it from state, and list by payer or payee from the
//! `EscrowCreated` event log.

use crate::error::{Result, SettlementError};
use serde::{Deserialize, Serialize};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};
use tracing::debug;

/// Status of an escrow account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EscrowStatus {
    /// Funds are locked in escrow
    Funded,
    /// Funds have been released to payee
    Released,
    /// Funds have been refunded to payer
    Refunded,
    /// Escrow has expired
    Expired,
}

/// An escrow account holding funds for a settlement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowAccount {
    /// Unique escrow identifier
    pub escrow_id: String,
    /// Address of the payer (funds locked from this address)
    pub payer: Address,
    /// Address of the payee (funds will be released to this address)
    pub payee: Address,
    /// Amount held in escrow
    pub amount: u128,
    /// Asset being held: `TNZO` or a token id, `0x`-prefixed hex.
    pub asset_id: AssetId,
    /// USD price of the whole amount, micro-units, as the payer signed it
    /// at creation. Required for an asset other than TNZO: each claim's
    /// settlement fee is charged in TNZO on its share of this price.
    pub usd_e6: u64,
    /// Timestamp when escrow was created
    pub created_at: Timestamp,
    /// Timestamp when escrow expires
    pub expires_at: Timestamp,
    /// Current status
    pub status: EscrowStatus,
    /// Conditions for release
    pub release_conditions: ReleaseConditions,
    /// Total already paid to the payee through voucher claims. The payee may
    /// claim up to `amount`; a refund after expiry returns `amount - claimed`.
    pub claimed: u128,
    /// For an escrow both parties approve: the party whose release
    /// transaction came first. The other party's release completes it.
    pub approved_by: Option<Address>,
    /// An opaque reference the payer set at creation, so the application
    /// that opened the escrow can find it again (a task milestone, a session).
    #[serde(default, with = "tenzro_types::settlement::opt_hex32")]
    pub reference: Option<[u8; 32]>,
}

impl EscrowAccount {
    /// Creates a new escrow account
    pub fn new(
        payer: Address,
        payee: Address,
        amount: u128,
        asset_id: AssetId,
        expires_at: Timestamp,
        release_conditions: ReleaseConditions,
    ) -> Self {
        Self {
            escrow_id: uuid::Uuid::new_v4().to_string(),
            payer,
            payee,
            amount,
            asset_id,
            usd_e6: 0,
            created_at: Timestamp::now(),
            expires_at,
            status: EscrowStatus::Funded,
            release_conditions,
            claimed: 0,
            approved_by: None,
            reference: None,
        }
    }

    /// Checks if the escrow has expired
    pub fn is_expired(&self) -> bool {
        Timestamp::now() > self.expires_at
    }

    /// Checks if the escrow can be released
    pub fn can_release(&self) -> bool {
        self.status == EscrowStatus::Funded && !self.is_expired()
    }

    /// Checks if the escrow can be refunded: only once it has expired, so the
    /// payer cannot pull funds from under a payee still performing.
    pub fn can_refund(&self) -> bool {
        self.status == EscrowStatus::Funded && self.is_expired()
    }
}

/// Stand-alone verification of release conditions against a proof.
///
/// Run by the Native VM during `ReleaseEscrow` execution, after it has
/// admitted the caller the escrow's kind names. Every party authorises with
/// its own signed transaction (passkey or TPM-rooted account authorisation);
/// no key carried in the proof stands for a party, so for those kinds the
/// proof asks for nothing.
pub fn verify_release_conditions(
    conditions: &ReleaseConditions,
    proof: &ServiceProof,
) -> Result<()> {
    match conditions {
        ReleaseConditions::ConsumerSignature
        | ReleaseConditions::ProviderSignature
        | ReleaseConditions::BothSignatures
        | ReleaseConditions::Timeout => Ok(()),
        // The payer releasing a hash-locked escrow early is its own consent;
        // the payee's path is the preimage claim.
        ReleaseConditions::HashLock { .. }
        | ReleaseConditions::Stream { .. }
        | ReleaseConditions::Executor { .. } => Ok(()),
        ReleaseConditions::Custom { condition } => {
            if proof.proof_data.is_empty() {
                return Err(SettlementError::InvalidProof(
                    "No proof data for custom condition".to_string(),
                ));
            }
            debug!("Verifying custom condition: {}", condition);
            Ok(())
        }
        ReleaseConditions::QuorumAttestation { .. } => Err(SettlementError::InvalidProof(
            "a quorum-attested escrow is released only by the on-chain ReleaseEscrow \
             transaction, which binds the attestation to the escrow id"
                .to_string(),
        )),
    }
}
