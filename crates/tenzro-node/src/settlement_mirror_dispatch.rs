//! Executing a mirror plan: fanning one settlement out across chains.
//!
//! `tenzro-payments::settlement_mirror` decides *what* a mirror plan is and
//! whether it survives losing the primary. This module is the half that
//! builds, for each chain, the `Bridge` transaction that queues the record as
//! a data message on the governed bridge route serving it. The caller (the
//! payer or a relayer) signs it in hardware and submits it pre-signed; the
//! node never signs it.
//! The route's relayers carry it; until a relayer confirms delivery the
//! mirror is pending.
//!
//! # A mirror is evidence, not an instruction
//!
//! This is the property that keeps mirroring from double-paying, and it is
//! worth stating because the payload makes it look otherwise: a self-contained
//! mirror writes the whole settlement record, `payees` and `amount_charged`
//! included, onto another chain.
//!
//! Those fields are a **record of a division that already happened on the
//! Tenzro Ledger**, not a request for that chain to perform one. The ledger
//! divides a payment exactly once, at settlement (its split rule, the
//! settlement fee and any treasury leg), before any mirror is dispatched;
//! nothing in this module divides it again (it never calls `split_revenue`),
//! and a test asserts the record is byte-identical before and after
//! mirroring.
//!
//! So mirroring onto five chains produces five copies of one settlement, not
//! five settlements. A reader of a mirrored record learns who was paid and how
//! much; it does not learn that it owes anyone anything.
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

use tenzro_payments::settlement_mirror::{
    MirrorDurability, MirrorOutcome, MirrorPlan, MirrorReport, MirrorState, MirrorTarget,
};
use tenzro_types::provenance::InteractionProvenance;
use tenzro_types::settlement_network::chain_name_for_caip2;

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

/// A mirror plan turned into the transactions that carry it.
pub struct MirrorDispatch {
    /// One outcome per target: pending until its transaction is signed,
    /// submitted and delivered, or failed with the reason.
    pub report: MirrorReport,
    /// The `Bridge` transaction payload (`tx_type`) to sign for each pending
    /// target, keyed by the route's chain name.
    pub transactions: Vec<(String, serde_json::Value)>,
}

/// Build the transactions for a mirror plan.
///
/// `primary_committed` is passed in rather than inferred: this module writes to
/// secondary chains and has no view of whether the Tenzro Ledger transaction
/// landed. Reporting durability requires both, and guessing the primary's state
/// here would let a mirror claim durability for a settlement that never
/// committed.
pub fn build_mirror_plan(
    record: &InteractionProvenance,
    plan: &MirrorPlan,
    primary_committed: bool,
) -> MirrorDispatch {
    let mut outcomes = Vec::with_capacity(plan.targets.len());
    let mut transactions = Vec::new();
    for target in &plan.targets {
        match build_one(record, target) {
            Ok((dest, tx_type)) => {
                transactions.push((dest, tx_type));
                outcomes.push(MirrorOutcome {
                    target: target.clone(),
                    state: MirrorState::Pending,
                });
            }
            Err(reason) => outcomes.push(MirrorOutcome {
                target: target.clone(),
                state: MirrorState::Failed { reason },
            }),
        }
    }
    MirrorDispatch {
        report: MirrorReport {
            primary_committed,
            outcomes,
        },
        transactions,
    }
}

/// The `Bridge` transaction that writes one settlement to one chain.
fn build_one(
    record: &InteractionProvenance,
    target: &MirrorTarget,
) -> Result<(String, serde_json::Value), String> {
    let payload = mirror_payload(record, target.durability)?;
    // Routes are keyed by chain name. Targets are held as CAIP-2 where one
    // exists, so resolve back; a target that is already a plain name (a chain
    // with no registered CAIP-2) passes through unchanged.
    let dest = chain_name_for_caip2(&target.caip2)
        .unwrap_or(target.caip2.as_str())
        .to_string();
    let op = tenzro_types::bridge_transfer::BridgeOp::SendMessage {
        target_chain: dest.clone(),
        payload,
    };
    let tx_type = serde_json::to_value(tenzro_types::TransactionType::Bridge { op })
        .map_err(|e| e.to_string())?;
    Ok((dest, tx_type))
}

/// Build the plan's transactions and fold the confirmed mirrors into the
/// record. Only confirmed mirrors are folded in, because the provenance record
/// lists settlements that *happened*, and a pending or failed mirror would
/// claim one that does not exist on that chain.
pub fn mirror_and_record(
    record: &mut InteractionProvenance,
    plan: &MirrorPlan,
    primary_committed: bool,
) -> MirrorDispatch {
    let dispatch = build_mirror_plan(record, plan, primary_committed);
    record.secondary_settlements = dispatch.report.secondaries();
    dispatch
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
    fn a_caip2_target_resolves_to_the_routes_chain_name() {
        // Routes are keyed by chain name; targets are held as CAIP-2.
        assert_eq!(chain_name_for_caip2("eip155:8453"), Some("base"));
        assert_eq!(chain_name_for_caip2("xrpl:0"), Some("xrpl"));
        // A chain with no registered CAIP-2 passes through as its own name.
        assert_eq!(chain_name_for_caip2("osmosis"), None);
    }

    #[test]
    fn mirroring_does_not_alter_the_settled_amounts_or_payees() {
        // The no-double-charge invariant. The split runs once at settlement;
        // a mirror copies the result and must not touch it. If this ever
        // fails, mirroring onto N chains has started to mean N divisions.
        let r = record();
        let before = serde_json::to_vec(&r).unwrap();
        let payload = mirror_payload(&r, MirrorDurability::SelfContained).unwrap();
        assert_eq!(
            payload, before,
            "the mirrored payload must be the settlement verbatim"
        );
        let decoded: InteractionProvenance = serde_json::from_slice(&payload).unwrap();
        assert_eq!(decoded.amount_charged, r.amount_charged);
        assert_eq!(decoded.payees.len(), r.payees.len());
    }

    #[test]
    fn mirroring_to_many_chains_still_describes_one_settlement() {
        // Five copies of one settlement, not five settlements. Each payload is
        // identical, so no chain sees a different amount or a different set of
        // payees that it might act on.
        let r = record();
        let payloads: Vec<Vec<u8>> = ["eip155:8453", "eip155:1", "xrpl:0", "stellar:pubnet"]
            .iter()
            .map(|_| mirror_payload(&r, MirrorDurability::SelfContained).unwrap())
            .collect();
        assert!(
            payloads.windows(2).all(|w| w[0] == w[1]),
            "every target must carry the same settlement"
        );
        // And the total charged is what it always was, however many carry it.
        let decoded: InteractionProvenance = serde_json::from_slice(&payloads[0]).unwrap();
        assert_eq!(decoded.amount_charged, r.amount_charged);
    }

    #[test]
    fn this_module_never_reaches_the_revenue_split() {
        // A structural guard rather than a behavioural one: the split lives in
        // tenzro-payments::revenue_split and is applied at settlement. If a
        // future edit imports it here, that is the moment mirroring starts
        // dividing a payment a second time.
        // Scoped to the implementation, not this module's own tests — the
        // assertion text below necessarily contains the very name it forbids.
        let src = include_str!("settlement_mirror_dispatch.rs");
        let impl_only = src.split("#[cfg(test)]").next().unwrap();
        // A call, not a mention — the module docs name it descriptively, and
        // forbidding the word would make the documentation trip its own guard.
        let forbidden = concat!("split", "_revenue(");
        assert!(
            !impl_only.contains(forbidden),
            "the mirror path must never divide a payment; the split runs once, at settlement"
        );
    }
}
