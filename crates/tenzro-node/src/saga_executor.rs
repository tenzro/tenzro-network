//! Node-layer [`LegExecutor`] for DvP sagas.
//!
//! Drives a saga's legs against the node's real settlement venues. A DvP
//! saga bundles delivery and payment legs into an all-or-compensate unit;
//! the orchestrator (in `tenzro-settlement`) owns the state machine and
//! calls this executor to move value per leg.
//!
//! # Supported venues
//!
//! - [`LegVenue::Escrow`] — the payer pre-funds an on-chain escrow, then the
//!   saga *release*s it to the payee (forward) or *refund*s it back to the
//!   payer (compensate). This is the only venue where the saga holds
//!   sufficient authorization on its own: the escrow was already funded and
//!   authorized by the payer, so release/refund needs no fresh signature.
//!   Signature-gated escrows (`ProviderSignature` / `ConsumerSignature` /
//!   `BothSignatures` / `VerifierSignature`) additionally require the caller
//!   to supply the release proof at execute time via [`SagaProofBook`].
//!
//! Other venues (`Native`, `Channel`, `External`) require caller
//! authorization the saga does not hold — a native transfer needs the
//! payer's transaction signature, a channel update needs the counterparty's
//! signed state, a bridge/Canton leg needs an outbound dispatch. Those legs
//! are rejected with a typed error so the saga compensates cleanly rather
//! than silently faking a settlement.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tenzro_settlement::{
    EscrowManager, LegExecutor, LegReceipt, LegVenue, Result as SettlementResult, SagaLeg,
    SettlementError,
};
use tenzro_types::primitives::Timestamp;
use tenzro_types::settlement::{ReleaseConditions, ServiceProof};

/// Per-leg release proofs supplied by the caller at execute time, keyed by
/// `leg_id`. Signature-gated escrow legs consult this book; timeout / custom
/// escrows release without one.
pub type SagaProofBook = HashMap<String, ServiceProof>;

/// Node-layer executor that settles saga legs against on-chain escrows.
pub struct NodeLegExecutor {
    escrow_manager: Arc<EscrowManager>,
    proofs: SagaProofBook,
}

impl NodeLegExecutor {
    /// Builds an executor over the node's escrow manager with no release
    /// proofs — only timeout / custom escrows can be released.
    pub fn new(escrow_manager: Arc<EscrowManager>) -> Self {
        Self {
            escrow_manager,
            proofs: SagaProofBook::new(),
        }
    }

    /// Builds an executor with a per-leg proof book for signature-gated
    /// escrow release.
    pub fn with_proofs(escrow_manager: Arc<EscrowManager>, proofs: SagaProofBook) -> Self {
        Self {
            escrow_manager,
            proofs,
        }
    }

    /// Validates that a pre-funded escrow matches the leg it settles, so a
    /// saga cannot release an unrelated escrow.
    fn validate_escrow(&self, leg: &SagaLeg, escrow_id: &str) -> SettlementResult<()> {
        let escrow = self.escrow_manager.get_escrow(escrow_id)?;
        if escrow.payer != leg.payer {
            return Err(SettlementError::SagaError(format!(
                "escrow {escrow_id} payer does not match leg {}",
                leg.leg_id
            )));
        }
        if escrow.payee != leg.payee {
            return Err(SettlementError::SagaError(format!(
                "escrow {escrow_id} payee does not match leg {}",
                leg.leg_id
            )));
        }
        if escrow.amount != leg.amount {
            return Err(SettlementError::SagaError(format!(
                "escrow {escrow_id} amount does not match leg {}",
                leg.leg_id
            )));
        }
        if escrow.asset_id.0 != leg.asset {
            return Err(SettlementError::SagaError(format!(
                "escrow {escrow_id} asset does not match leg {}",
                leg.leg_id
            )));
        }
        Ok(())
    }

    /// Resolves the release proof for a leg. Timeout escrows release with a
    /// trivial proof; signature-gated escrows require the caller's proof from
    /// the proof book.
    fn release_proof(&self, leg: &SagaLeg, escrow_id: &str) -> SettlementResult<ServiceProof> {
        let escrow = self.escrow_manager.get_escrow(escrow_id)?;
        match escrow.release_conditions {
            ReleaseConditions::Timeout => Ok(ServiceProof::new(
                tenzro_types::settlement::ProofType::Cryptographic,
                Vec::new(),
            )),
            ReleaseConditions::Custom { .. } => self
                .proofs
                .get(&leg.leg_id)
                .cloned()
                .ok_or_else(|| {
                    SettlementError::SagaError(format!(
                        "custom-condition escrow {escrow_id} requires a release proof for leg {}",
                        leg.leg_id
                    ))
                }),
            ReleaseConditions::ProviderSignature
            | ReleaseConditions::ConsumerSignature
            | ReleaseConditions::BothSignatures
            | ReleaseConditions::VerifierSignature => self
                .proofs
                .get(&leg.leg_id)
                .cloned()
                .ok_or_else(|| {
                    SettlementError::SagaError(format!(
                        "signature-gated escrow {escrow_id} requires a release proof for leg {}",
                        leg.leg_id
                    ))
                }),
        }
    }
}

#[async_trait]
impl LegExecutor for NodeLegExecutor {
    async fn execute(&self, leg: &SagaLeg) -> SettlementResult<LegReceipt> {
        match &leg.venue {
            LegVenue::Escrow { escrow_id } => {
                self.validate_escrow(leg, escrow_id)?;
                let proof = self.release_proof(leg, escrow_id)?;
                self.escrow_manager.release_escrow(escrow_id, &proof)?;
                Ok(LegReceipt {
                    leg_id: leg.leg_id.clone(),
                    reference: escrow_id.clone(),
                    executed_at: Timestamp::now(),
                })
            }
            LegVenue::Native => Err(SettlementError::SagaError(format!(
                "native venue leg {} is not saga-executable: a native transfer \
                 requires the payer's signed transaction",
                leg.leg_id
            ))),
            LegVenue::Channel { .. } => Err(SettlementError::SagaError(format!(
                "channel venue leg {} is not saga-executable: a channel update \
                 requires the counterparty's signed state",
                leg.leg_id
            ))),
            LegVenue::External { .. } => Err(SettlementError::SagaError(format!(
                "external venue leg {} is not saga-executable: an external \
                 (bridge/Canton) leg requires an authorized outbound dispatch",
                leg.leg_id
            ))),
        }
    }

    async fn compensate(&self, leg: &SagaLeg, receipt: &LegReceipt) -> SettlementResult<()> {
        match &leg.venue {
            LegVenue::Escrow { escrow_id } => {
                // Compensation refunds the released escrow back to the payer.
                // The receipt's reference is the escrow id; guard on parity.
                if &receipt.reference != escrow_id {
                    return Err(SettlementError::SagaError(format!(
                        "compensation receipt reference does not match escrow for leg {}",
                        leg.leg_id
                    )));
                }
                self.escrow_manager.refund_escrow(escrow_id)?;
                Ok(())
            }
            // Non-escrow venues never execute, so they are never compensated.
            _ => Ok(()),
        }
    }
}
