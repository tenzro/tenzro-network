//! Executing a mirror plan: fanning one settlement out across chains.
//!
//! `tenzro-payments::settlement_mirror` decides *what* a mirror plan is and
//! whether it survives losing the primary. This module is the half that
//! actually writes to the chains, through the bridge router that already
//! carries every adapter — LayerZero, Chainlink CCIP, Wormhole, deBridge,
//! Li.Fi, Hyperlane, Axelar, Stargate, IBC Eureka, Hyperbridge, NEAR chain
//! signatures and Canton.
//!
//! # Each target is dispatched on its own
//!
//! There is no two-phase commit across chains that do not know about each
//! other. A congested chain, a reorg, or a rejected transaction must not roll
//! back a settlement that already committed elsewhere, so every target is
//! attempted independently and the report says plainly which landed. Partial
//! success is the normal case, not an error state.
//!
//! # What actually gets written
//!
//! For a `SelfContained` mirror the payload is the **canonical settlement
//! bytes**, so the record stays readable with no Tenzro node in existence —
//! that is what survives a testnet reset or a mainnet cutover. For a
//! `DigestOnly` mirror it is the 32-byte attestation digest alone, which
//! proves a payload you already hold is the one that settled but cannot tell
//! you what settled.
//!
//! The digest is recomputable from the payload by anyone, so a self-contained
//! record needs nothing from us to be checked.

use std::sync::Arc;

use tenzro_payments::settlement_mirror::{
    MirrorDurability, MirrorOutcome, MirrorPlan, MirrorReport, MirrorState, MirrorTarget,
};
use tenzro_types::provenance::InteractionProvenance;
use tenzro_types::settlement_network::chain_name_for_caip2;

use crate::node::TenzroNode;

/// Unix ms, for stamping confirmations.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The bytes written to a chain for one target.
///
/// Separated from dispatch so the payload a caller can verify offline is
/// produced by exactly one function, rather than assembled differently per
/// adapter.
pub fn mirror_payload(
    record: &InteractionProvenance,
    durability: MirrorDurability,
) -> Result<Vec<u8>, String> {
    match durability {
        // The canonical settlement bytes. A holder recomputes the digest from
        // these and reads the parties, asset and amount without us.
        MirrorDurability::SelfContained => {
            serde_json::to_vec(record).map_err(|e| format!("encode settlement: {e}"))
        }
        // The commitment alone.
        MirrorDurability::DigestOnly => Ok(record.attestation_digest().to_vec()),
    }
}

/// Execute a mirror plan.
///
/// `primary_committed` is passed in rather than inferred: this module writes to
/// secondary chains and has no view of whether the Tenzro Ledger transaction
/// landed. Reporting durability requires both, and guessing the primary's state
/// here would let a mirror claim durability for a settlement that never
/// committed.
pub async fn execute_mirror_plan(
    node: &Arc<TenzroNode>,
    record: &InteractionProvenance,
    plan: &MirrorPlan,
    primary_committed: bool,
) -> MirrorReport {
    let mut outcomes = Vec::with_capacity(plan.targets.len());

    for target in &plan.targets {
        outcomes.push(dispatch_one(node, record, target).await);
    }

    MirrorReport {
        primary_committed,
        outcomes,
    }
}

/// Write one settlement to one chain.
async fn dispatch_one(
    node: &Arc<TenzroNode>,
    record: &InteractionProvenance,
    target: &MirrorTarget,
) -> MirrorOutcome {
    let fail = |reason: String| MirrorOutcome {
        target: target.clone(),
        state: MirrorState::Failed { reason },
    };

    let payload = match mirror_payload(record, target.durability) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };

    let Some(router) = node.bridge_router() else {
        return fail(
            "no bridge router on this node, so nothing can carry a record to another chain"
                .to_string(),
        );
    };

    // The router routes on the adapter's own chain name. Targets are held as
    // CAIP-2 where one exists, so resolve back; a target that is already a
    // plain name (a chain with no registered CAIP-2) passes through unchanged.
    let dest = chain_name_for_caip2(&target.caip2).unwrap_or(target.caip2.as_str());

    match router.send_message(dest, payload).await {
        Ok(reference) => MirrorOutcome {
            target: target.clone(),
            state: MirrorState::Confirmed {
                reference,
                confirmed_at_ms: now_ms(),
            },
        },
        // The adapter's own message is preserved. "Mirroring failed" without a
        // cause is not something an operator can act on.
        Err(e) => fail(format!("{dest}: {e}")),
    }
}

/// Execute a plan and fold the confirmed mirrors into the record.
///
/// This is the path that finally gives `SecondarySettlement` a live producer:
/// only confirmed mirrors are folded in, because the provenance record lists
/// settlements that *happened*, and a pending or failed mirror would claim one
/// that does not exist on that chain.
pub async fn mirror_and_record(
    node: &Arc<TenzroNode>,
    record: &mut InteractionProvenance,
    plan: &MirrorPlan,
    primary_committed: bool,
) -> MirrorReport {
    let report = execute_mirror_plan(node, record, plan, primary_committed).await;
    record.secondary_settlements = report.secondaries();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::access_tier::AccessTier;
    use tenzro_types::access_tier::PayerKind;
    use tenzro_types::economics::NodeEconomicMode;
    use tenzro_types::provenance::InboundRail;
    use tenzro_types::provenance::{Authority, ChargeRef, InteractionKind, InteractionProvenance};
    use tenzro_types::{Address, BillableUnits, Timestamp};

    fn record() -> InteractionProvenance {
        InteractionProvenance {
            interaction_id: "int-1".into(),
            payer_did: "did:tenzro:machine:agent".into(),
            payer_kind: PayerKind::Agent,
            payer_wallet: Address::default(),
            on_behalf_of: None,
            kind: InteractionKind::Access,
            resource_id: "https://example.com/a".into(),
            units: BillableUnits::default(),
            occurred_at: Timestamp::new(1_700_000_000_000),
            attester_did: "did:tenzro:machine:node".into(),
            authority: Authority::Open,
            charge: ChargeRef::Free,
            tier: AccessTier::User,
            credential_digest: None,
            mode: NodeEconomicMode::Private,
            inbound_rail: InboundRail::Tenzro,
            amount_charged: 0,
            settled_asset: "TNZO".into(),
            payees: Vec::new(),
            settlement_tx: None,
            secondary_settlements: Vec::new(),
        }
    }

    #[test]
    fn a_self_contained_payload_is_the_whole_record_and_verifies_offline() {
        // The durability requirement: a holder must be able to read the parties
        // and amount, and recompute the digest, with no Tenzro node.
        let r = record();
        let bytes = mirror_payload(&r, MirrorDurability::SelfContained).unwrap();
        let decoded: InteractionProvenance = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.payer_did, r.payer_did);
        assert_eq!(decoded.resource_id, r.resource_id);
        assert_eq!(decoded.attestation_digest(), r.attestation_digest());
    }

    #[test]
    fn a_digest_only_payload_is_the_commitment_and_nothing_else() {
        let r = record();
        let bytes = mirror_payload(&r, MirrorDurability::DigestOnly).unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes, r.attestation_digest().to_vec());
        // It cannot be read back into a record — that is the tradeoff.
        assert!(serde_json::from_slice::<InteractionProvenance>(&bytes).is_err());
    }

    #[test]
    fn the_two_payload_kinds_are_not_interchangeable() {
        let r = record();
        let full = mirror_payload(&r, MirrorDurability::SelfContained).unwrap();
        let digest = mirror_payload(&r, MirrorDurability::DigestOnly).unwrap();
        assert_ne!(full, digest);
        assert!(full.len() > digest.len());
    }

    #[test]
    fn a_caip2_target_resolves_to_the_adapters_chain_name() {
        // The router routes on names; targets are held as CAIP-2.
        assert_eq!(chain_name_for_caip2("eip155:8453"), Some("base"));
        assert_eq!(chain_name_for_caip2("xrpl:0"), Some("xrpl"));
        // A chain with no registered CAIP-2 passes through as its own name.
        assert_eq!(chain_name_for_caip2("osmosis"), None);
    }
}
