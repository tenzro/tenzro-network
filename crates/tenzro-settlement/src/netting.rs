//! Multilateral netting: the pure function the VM runs when an epoch's
//! batch of netted obligations closes.
//!
//! Compresses a set of gross bilateral obligations into a minimal set of
//! settlement instructions per asset using the standard greedy algorithm:
//! net each party's position per asset, then repeatedly match the largest
//! net debtor against the largest net creditor. All ordering is by address
//! bytes (and asset string) so every node computes the identical batch from
//! the same obligation set regardless of input order.
//!
//! The obligations are committed by a Merkle root over their canonical
//! order, so any participant's gross-to-net position is provable from the
//! batch record: its obligations with their inclusion paths, and the
//! instructions naming it (see [`statement`] and [`verify_statement`]).

use crate::error::{Result, SettlementError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tenzro_types::merkle;
use tenzro_types::primitives::Address;

/// Domain tag for batch id derivation.
const NETTING_ID_DOMAIN: &[u8] = b"tenzro/settlement/netting";

/// A gross bilateral obligation: `debtor` owes `creditor` `amount` of `asset`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Obligation {
    /// Party that owes.
    pub debtor: Address,
    /// Party that is owed.
    pub creditor: Address,
    /// CAIP-19-style asset identifier.
    pub asset: String,
    /// Amount in the asset's base units.
    pub amount: u128,
}

/// A net settlement instruction produced by the netting algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementInstruction {
    /// Net debtor.
    pub from: Address,
    /// Net creditor.
    pub to: Address,
    /// CAIP-19-style asset identifier.
    pub asset: String,
    /// Amount in the asset's base units.
    pub amount: u128,
}

/// A computed netting batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NettingBatch {
    /// `hex(SHA-256("tenzro/settlement/netting" || canonical sorted obligations))`.
    pub batch_id: String,
    /// Input obligations in canonical sorted order.
    pub obligations: Vec<Obligation>,
    /// Minimal instruction set, deterministic across nodes.
    pub instructions: Vec<SettlementInstruction>,
    /// Sum of all obligation amounts.
    pub gross_total: u128,
    /// Sum of all instruction amounts.
    pub net_total: u128,
}

fn addr_key(a: &Address) -> [u8; 32] {
    let mut k = [0u8; 32];
    k.copy_from_slice(a.as_bytes());
    k
}

/// Canonical obligation ordering: (debtor, creditor, asset, amount).
fn sort_obligations(obligations: &mut [Obligation]) {
    obligations.sort_by(|a, b| {
        addr_key(&a.debtor)
            .cmp(&addr_key(&b.debtor))
            .then_with(|| addr_key(&a.creditor).cmp(&addr_key(&b.creditor)))
            .then_with(|| a.asset.cmp(&b.asset))
            .then_with(|| a.amount.cmp(&b.amount))
    });
}

/// Computes the deterministic batch id over canonically-sorted obligations.
pub fn compute_batch_id(sorted_obligations: &[Obligation]) -> String {
    let mut preimage = Vec::with_capacity(NETTING_ID_DOMAIN.len() + sorted_obligations.len() * 96);
    preimage.extend_from_slice(NETTING_ID_DOMAIN);
    for ob in sorted_obligations {
        preimage.extend_from_slice(ob.debtor.as_bytes());
        preimage.extend_from_slice(ob.creditor.as_bytes());
        preimage.extend_from_slice(&(ob.asset.len() as u32).to_le_bytes());
        preimage.extend_from_slice(ob.asset.as_bytes());
        preimage.extend_from_slice(&ob.amount.to_le_bytes());
    }
    hex::encode(tenzro_crypto::hash::sha256(&preimage).as_bytes())
}

/// Signed net position per (asset, party): positive = net creditor.
/// Returned as `(credit, debit)` totals to stay in u128.
type PositionMap = BTreeMap<(String, [u8; 32]), (u128, u128)>;

/// Per-asset reduced positions grouped as `(debtors, creditors)`, each a list
/// of `(party_address, net_amount)` pairs.
type PerAssetLedger = BTreeMap<String, (Vec<([u8; 32], u128)>, Vec<([u8; 32], u128)>)>;

fn accumulate(
    positions: &mut PositionMap,
    asset: &str,
    debtor: &Address,
    creditor: &Address,
    amount: u128,
) -> Result<()> {
    let d = positions
        .entry((asset.to_string(), addr_key(debtor)))
        .or_insert((0, 0));
    d.1 = d.1.checked_add(amount).ok_or_else(|| {
        SettlementError::ArithmeticOverflow("netting debit sum overflow".to_string())
    })?;
    let c = positions
        .entry((asset.to_string(), addr_key(creditor)))
        .or_insert((0, 0));
    c.0 = c.0.checked_add(amount).ok_or_else(|| {
        SettlementError::ArithmeticOverflow("netting credit sum overflow".to_string())
    })?;
    Ok(())
}

/// Reduces `(credit, debit)` pairs to net positions, dropping flat parties.
/// Value is `(is_creditor, net_amount)`.
fn reduce(positions: &PositionMap) -> BTreeMap<(String, [u8; 32]), (bool, u128)> {
    positions
        .iter()
        .filter_map(|((asset, party), (credit, debit))| {
            if credit > debit {
                Some(((asset.clone(), *party), (true, credit - debit)))
            } else if debit > credit {
                Some(((asset.clone(), *party), (false, debit - credit)))
            } else {
                None
            }
        })
        .collect()
}

fn net_positions(obligations: &[Obligation]) -> Result<PositionMap> {
    let mut positions = PositionMap::new();
    for ob in obligations {
        accumulate(
            &mut positions,
            &ob.asset,
            &ob.debtor,
            &ob.creditor,
            ob.amount,
        )?;
    }
    Ok(positions)
}

fn instruction_positions(instructions: &[SettlementInstruction]) -> Result<PositionMap> {
    let mut positions = PositionMap::new();
    for ins in instructions {
        accumulate(&mut positions, &ins.asset, &ins.from, &ins.to, ins.amount)?;
    }
    Ok(positions)
}

/// Verifies that per (party, asset) the instruction flows equal the net
/// positions implied by the obligations.
pub fn verify_netting_invariant(
    obligations: &[Obligation],
    instructions: &[SettlementInstruction],
) -> Result<()> {
    let expected = reduce(&net_positions(obligations)?);
    let actual = reduce(&instruction_positions(instructions)?);
    if expected != actual {
        return Err(SettlementError::NettingError(
            "instruction flows do not match net positions".to_string(),
        ));
    }
    Ok(())
}

/// Computes the minimal instruction set for a set of obligations.
///
/// Returns `(sorted_obligations, instructions, gross_total, net_total)`.
fn compute_netting(
    mut obligations: Vec<Obligation>,
) -> Result<(Vec<Obligation>, Vec<SettlementInstruction>, u128, u128)> {
    if obligations.is_empty() {
        return Err(SettlementError::NettingError(
            "obligation set is empty".to_string(),
        ));
    }
    for ob in &obligations {
        if ob.amount == 0 {
            return Err(SettlementError::InvalidAmount(
                "obligation amount must be greater than zero".to_string(),
            ));
        }
        if ob.debtor == ob.creditor {
            return Err(SettlementError::NettingError(
                "obligation debtor equals creditor".to_string(),
            ));
        }
        if ob.asset.is_empty() {
            return Err(SettlementError::NettingError(
                "obligation asset is empty".to_string(),
            ));
        }
    }
    sort_obligations(&mut obligations);

    let mut gross_total: u128 = 0;
    for ob in &obligations {
        gross_total = gross_total.checked_add(ob.amount).ok_or_else(|| {
            SettlementError::ArithmeticOverflow("netting gross total overflow".to_string())
        })?;
    }

    let positions = net_positions(&obligations)?;

    // Group reduced positions by asset, deterministically.
    let mut per_asset: PerAssetLedger = BTreeMap::new();
    for ((asset, party), (is_creditor, net)) in reduce(&positions) {
        let entry = per_asset.entry(asset).or_default();
        if is_creditor {
            entry.1.push((party, net));
        } else {
            entry.0.push((party, net));
        }
    }

    let mut instructions = Vec::new();
    let mut net_total: u128 = 0;
    for (asset, (mut debtors, mut creditors)) in per_asset {
        // Largest amount first; ties broken by ascending address bytes.
        let cmp =
            |a: &([u8; 32], u128), b: &([u8; 32], u128)| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0));
        while !debtors.is_empty() && !creditors.is_empty() {
            debtors.sort_by(cmp);
            creditors.sort_by(cmp);
            let matched = debtors[0].1.min(creditors[0].1);
            instructions.push(SettlementInstruction {
                from: Address::new(debtors[0].0),
                to: Address::new(creditors[0].0),
                asset: asset.clone(),
                amount: matched,
            });
            net_total = net_total.checked_add(matched).ok_or_else(|| {
                SettlementError::ArithmeticOverflow("netting net total overflow".to_string())
            })?;
            debtors[0].1 -= matched;
            creditors[0].1 -= matched;
            debtors.retain(|(_, amt)| *amt > 0);
            creditors.retain(|(_, amt)| *amt > 0);
        }
        // Per-asset debit and credit sums are equal by construction, so both
        // sides drain together.
        debug_assert!(debtors.is_empty() && creditors.is_empty());
    }

    debug_assert!(verify_netting_invariant(&obligations, &instructions).is_ok());

    Ok((obligations, instructions, gross_total, net_total))
}

/// Compute the netting batch for a set of gross obligations: a pure function
/// of the set, the same on every node and for any input order.
pub fn compute_batch(obligations: Vec<Obligation>) -> Result<NettingBatch> {
    let (sorted, instructions, gross_total, net_total) = compute_netting(obligations)?;
    let batch_id = compute_batch_id(&sorted);
    Ok(NettingBatch {
        batch_id,
        obligations: sorted,
        instructions,
        gross_total,
        net_total,
    })
}

const OBLIGATION_LEAF_DOMAIN: &[u8] = b"tenzro/settlement/netting/obligation";

/// The Merkle leaf committing one obligation.
pub fn obligation_leaf(o: &Obligation) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(OBLIGATION_LEAF_DOMAIN);
    h.update(o.debtor.as_bytes());
    h.update(o.creditor.as_bytes());
    h.update((o.asset.len() as u32).to_be_bytes());
    h.update(o.asset.as_bytes());
    h.update(o.amount.to_be_bytes());
    h.finalize().into()
}

/// Merkle root over canonically sorted obligations.
pub fn obligations_root(sorted_obligations: &[Obligation]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = sorted_obligations.iter().map(obligation_leaf).collect();
    merkle::merkle_root(&leaves)
}

/// One obligation a participant is party to, with its inclusion path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenObligation {
    /// Position in the batch's canonical order.
    pub index: u32,
    /// The obligation.
    pub obligation: Obligation,
    /// Its path to the batch's obligations root.
    pub path: Vec<merkle::PathStep>,
}

/// A participant's gross-to-net statement for one batch: every obligation
/// it is party to, proven against the root, and the instructions naming it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    /// The participant.
    pub participant: Address,
    /// Its obligations (as debtor or creditor).
    pub obligations: Vec<ProvenObligation>,
    /// The batch instructions it pays or receives.
    pub instructions: Vec<SettlementInstruction>,
}

/// `participant`'s statement in `batch`.
pub fn statement(batch: &NettingBatch, participant: &Address) -> Statement {
    let leaves: Vec<[u8; 32]> = batch.obligations.iter().map(obligation_leaf).collect();
    let obligations = batch
        .obligations
        .iter()
        .enumerate()
        .filter(|(_, o)| o.debtor == *participant || o.creditor == *participant)
        .map(|(i, o)| ProvenObligation {
            index: i as u32,
            obligation: o.clone(),
            path: merkle::merkle_path(&leaves, i).unwrap_or_default(),
        })
        .collect();
    let instructions = batch
        .instructions
        .iter()
        .filter(|i| i.from == *participant || i.to == *participant)
        .cloned()
        .collect();
    Statement {
        participant: *participant,
        obligations,
        instructions,
    }
}

/// Check a statement against a batch's obligations root: every obligation is
/// included and names the participant, and the participant's net position
/// over them equals its net over the instructions. Completeness (that no
/// obligation of the participant was left out) holds because the VM writes
/// the instructions from the same root, so a missing obligation changes the
/// gross side and the equation fails.
pub fn verify_statement(root: &[u8; 32], s: &Statement) -> Result<()> {
    let mut gross: i128 = 0;
    for p in &s.obligations {
        let o = &p.obligation;
        if merkle::root_from_path(&obligation_leaf(o), &p.path) != *root {
            return Err(SettlementError::NettingError(format!(
                "obligation {} is not in the batch",
                p.index
            )));
        }
        let amount = i128::try_from(o.amount)
            .map_err(|_| SettlementError::NettingError("amount overflows".into()))?;
        if o.creditor == s.participant {
            gross += amount;
        }
        if o.debtor == s.participant {
            gross -= amount;
        }
    }
    let mut net: i128 = 0;
    for i in &s.instructions {
        let amount = i128::try_from(i.amount)
            .map_err(|_| SettlementError::NettingError("amount overflows".into()))?;
        if i.to == s.participant {
            net += amount;
        }
        if i.from == s.participant {
            net -= amount;
        }
    }
    if gross != net {
        return Err(SettlementError::NettingError(format!(
            "gross position {gross} differs from net {net}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    const TNZO: &str = "tenzro:1337/slip44:0";
    const USDC: &str = "eip155:1/erc20:0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";

    fn ob(debtor: u8, creditor: u8, asset: &str, amount: u128) -> Obligation {
        Obligation {
            debtor: addr(debtor),
            creditor: addr(creditor),
            asset: asset.to_string(),
            amount,
        }
    }

    #[test]
    fn bilateral_netting() {
        // A owes B 100; B owes A 30 -> single A->B 70.
        let batch = compute_batch(vec![ob(1, 2, TNZO, 100), ob(2, 1, TNZO, 30)]).unwrap();
        assert_eq!(batch.instructions.len(), 1);
        assert_eq!(batch.instructions[0].from, addr(1));
        assert_eq!(batch.instructions[0].to, addr(2));
        assert_eq!(batch.instructions[0].amount, 70);
        assert_eq!(batch.gross_total, 130);
        assert_eq!(batch.net_total, 70);
        verify_netting_invariant(&batch.obligations, &batch.instructions).unwrap();
    }

    #[test]
    fn cycle_nets_to_zero_instructions() {
        // A->B->C->A each 50: every party is flat.
        let batch = compute_batch(vec![
            ob(1, 2, TNZO, 50),
            ob(2, 3, TNZO, 50),
            ob(3, 1, TNZO, 50),
        ])
        .unwrap();
        assert!(batch.instructions.is_empty());
        assert_eq!(batch.gross_total, 150);
        assert_eq!(batch.net_total, 0);
        verify_netting_invariant(&batch.obligations, &batch.instructions).unwrap();
    }

    #[test]
    fn multilateral_netting_matches_positions() {
        // `ob(a, b, _, n)` is "a owes b n".
        //
        //   1 owes 2: 70,  1 owes 3: 60   → 1 = -130
        //   2 owes 3: 30,  3 owes 2: 30   → these cancel between 2 and 3
        //
        // Net positions: 1 → -130, 2 → +70, 3 → +60 (sums to zero).
        let batch = compute_batch(vec![
            ob(1, 2, TNZO, 70),
            ob(1, 3, TNZO, 60),
            ob(2, 3, TNZO, 30),
            ob(3, 2, TNZO, 30),
        ])
        .unwrap();
        verify_netting_invariant(&batch.obligations, &batch.instructions).unwrap();

        // Only the single net debtor pays; total paid = 130.
        assert!(batch.instructions.iter().all(|i| i.from == addr(1)));
        let total: u128 = batch.instructions.iter().map(|i| i.amount).sum();
        assert_eq!(total, 130);
        assert_eq!(batch.net_total, 130);
        // Minimal set: 2 instructions for 1 debtor x 2 creditors.
        assert_eq!(batch.instructions.len(), 2);
    }

    #[test]
    fn assets_net_independently() {
        let batch = compute_batch(vec![ob(1, 2, TNZO, 100), ob(2, 1, USDC, 100)]).unwrap();
        // Different assets do not offset each other.
        assert_eq!(batch.instructions.len(), 2);
        verify_netting_invariant(&batch.obligations, &batch.instructions).unwrap();
        let tnzo_ins = batch.instructions.iter().find(|i| i.asset == TNZO).unwrap();
        assert_eq!(tnzo_ins.from, addr(1));
        assert_eq!(tnzo_ins.to, addr(2));
        let usdc_ins = batch.instructions.iter().find(|i| i.asset == USDC).unwrap();
        assert_eq!(usdc_ins.from, addr(2));
        assert_eq!(usdc_ins.to, addr(1));
    }

    #[test]
    fn deterministic_across_input_order() {
        let obs = vec![
            ob(1, 2, TNZO, 70),
            ob(1, 3, TNZO, 60),
            ob(2, 3, TNZO, 30),
            ob(3, 2, TNZO, 30),
        ];
        let mut shuffled = obs.clone();
        shuffled.reverse();
        shuffled.swap(0, 2);
        let b1 = compute_batch(obs).unwrap();
        let b2 = compute_batch(shuffled).unwrap();
        assert_eq!(b1.batch_id, b2.batch_id);
        assert_eq!(b1.obligations, b2.obligations);
        assert_eq!(b1.instructions, b2.instructions);
    }

    #[test]
    fn validation_rejects_bad_input() {
        assert!(matches!(
            compute_batch(vec![]).unwrap_err(),
            SettlementError::NettingError(_)
        ));
        assert!(matches!(
            compute_batch(vec![ob(1, 2, TNZO, 0)]).unwrap_err(),
            SettlementError::InvalidAmount(_)
        ));
        assert!(matches!(
            compute_batch(vec![ob(1, 1, TNZO, 10)]).unwrap_err(),
            SettlementError::NettingError(_)
        ));
    }

    #[test]
    fn overflow_is_typed_error() {
        let r = compute_batch(vec![ob(1, 2, TNZO, u128::MAX), ob(3, 2, TNZO, 1)]);
        assert!(matches!(
            r.unwrap_err(),
            SettlementError::ArithmeticOverflow(_)
        ));
    }

    #[test]
    fn invariant_detects_bad_instructions() {
        let obs = vec![ob(1, 2, TNZO, 100)];
        let bad = vec![SettlementInstruction {
            from: addr(1),
            to: addr(2),
            asset: TNZO.to_string(),
            amount: 99,
        }];
        assert!(verify_netting_invariant(&obs, &bad).is_err());
        let good = vec![SettlementInstruction {
            from: addr(1),
            to: addr(2),
            asset: TNZO.to_string(),
            amount: 100,
        }];
        verify_netting_invariant(&obs, &good).unwrap();
    }

    #[test]
    fn a_statement_proves_gross_equals_net_and_a_dropped_obligation_fails() {
        let batch = compute_batch(vec![
            ob(1, 2, TNZO, 100),
            ob(2, 3, TNZO, 60),
            ob(3, 1, TNZO, 30),
        ])
        .unwrap();
        let root = obligations_root(&batch.obligations);
        for p in [1u8, 2, 3] {
            verify_statement(&root, &statement(&batch, &addr(p))).unwrap();
        }
        let mut st = statement(&batch, &addr(2));
        st.obligations.pop();
        assert!(verify_statement(&root, &st).is_err());
        let mut st = statement(&batch, &addr(2));
        st.obligations[0].obligation.amount += 1;
        assert!(verify_statement(&root, &st).is_err());
    }
}
