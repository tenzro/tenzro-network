//! The insurance pool: how it is funded and the claims it pays.
//!
//! The pool vault is credited by every agent-bond slash and by
//! `fees.insurance_pool_bps` of the fee revenue bound for the treasury (the
//! block fee pool and the settlement fee). `PayInsuranceClaim` pays the party
//! that evidence in chain state names (see `tenzro_types::insurance`), once
//! per evidence, at most `insurance.max_claim_bps` of the pool's value with
//! its TNZO at the safety rate, at most `insurance.max_claim_tnzo`, and in
//! all claims of one epoch at most `insurance.max_paid_tnzo_epoch`.
//!
//! Each epoch the pool's coverage is published: its value with TNZO at the
//! safety rate against `insurance.cover_target_units`, so a falling TNZO
//! price shows in the coverage before claims arrive.

use tenzro_types::insurance::{InsuranceClaim, InsuranceEvidence, InsurancePoolTotals, claim_id};

use super::funding::{read_json, refuse, write_json};
use super::*;

/// Governed: share of treasury-bound fee revenue credited to the pool, bps.
pub const POOL_FEE_SHARE_PARAM: &str = "fees.insurance_pool_bps";
/// Governed: most of the pool one claim may take, bps.
pub const MAX_CLAIM_BPS_PARAM: &str = "insurance.max_claim_bps";
/// Governed: most one claim may take, whole TNZO.
pub const MAX_CLAIM_TNZO_PARAM: &str = "insurance.max_claim_tnzo";
/// Governed: most all claims pay in one epoch, whole TNZO.
pub const MAX_PAID_EPOCH_PARAM: &str = "insurance.max_paid_tnzo_epoch";
/// Governed: the value the pool is meant to cover, whole units of account;
/// the coverage ratio is the pool's value at the safety rate against it.
pub const COVER_TARGET_PARAM: &str = "insurance.cover_target_units";
/// Genesis values of the governed parameters above.
pub const DEFAULT_POOL_FEE_SHARE_BPS: u64 = 1_000;
pub const DEFAULT_MAX_CLAIM_BPS: u64 = 1_000;
pub const DEFAULT_MAX_CLAIM_TNZO: u64 = 10_000;
pub const DEFAULT_COVER_TARGET_UNITS: u64 = 1_000_000;
pub const DEFAULT_MAX_PAID_TNZO_EPOCH: u64 = 30_000;
/// Greatest value of [`MAX_PAID_EPOCH_PARAM`].
pub const MAX_PAID_TNZO_EPOCH: u64 = 1_000_000_000;
/// Greatest value of [`COVER_TARGET_PARAM`].
pub const MAX_COVER_TARGET_UNITS: u64 = 1_000_000_000_000;

/// Topic of the log the coverage published at each epoch boundary emits.
pub const INSURANCE_COVERAGE_TOPIC: &[u8] = b"InsuranceCoverage";
const COVER_KEY: &str = "insurance_cover";
const PAID_EPOCH_KEY: &str = "insurance_paid_epoch";

const TOTALS_KEY: &str = "insurance_totals";
const CLAIM_IDS_KEY: &str = "insurance_claims";
const WEI_PER_TNZO: u128 = 1_000_000_000_000_000_000;

/// Topic of the log a paid claim emits.
pub const INSURANCE_CLAIM_PAID_TOPIC: &[u8] = b"InsuranceClaimPaid";

/// System storage slot of a paid claim.
pub fn claim_key(claim_id_hex: &str) -> String {
    format!("insurance_claim:{claim_id_hex}")
}

/// A paid claim.
pub fn read_claim(state: &dyn VmState, claim_id_hex: &str) -> Option<InsuranceClaim> {
    read_json(state, &claim_key(claim_id_hex))
}

/// Every paid claim's id, oldest first.
pub fn claim_ids(state: &dyn VmState) -> Vec<String> {
    read_json(state, CLAIM_IDS_KEY).unwrap_or_default()
}

/// The pool's history.
pub fn read_totals(state: &dyn VmState) -> InsurancePoolTotals {
    read_json(state, TOTALS_KEY).unwrap_or_default()
}

/// The pool vault's address.
pub fn pool_address() -> Address {
    derive_insurance_pool_address()
}

/// Where a credit to the pool came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolSource {
    /// Fee revenue.
    Fees,
    /// A slashed bond.
    Slash,
}

/// Record a credit already made to the pool vault in its totals.
pub fn note_credit(
    state: &mut dyn VmState,
    amount: u128,
    source: PoolSource,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let mut t = read_totals(state);
    match source {
        PoolSource::Fees => t.from_fees = t.from_fees.saturating_add(amount),
        PoolSource::Slash => t.from_slashes = t.from_slashes.saturating_add(amount),
    }
    write_json(state, TOTALS_KEY, &t, changes)?;
    Ok(())
}

/// The pool's share of `treasury_bound` fee revenue.
pub fn fee_share(state: &dyn VmState, treasury_bound: u128) -> u128 {
    tenzro_types::split::bps_of(treasury_bound, u128::from(fee_share_bps(state)))
}

/// The pool's governed share of treasury-bound fee revenue, basis points.
pub fn fee_share_bps(state: &dyn VmState) -> u16 {
    network_param(state, POOL_FEE_SHARE_PARAM).min(10_000) as u16
}

/// What the pool holds, wei: its TNZO and its settlement-asset holdings at
/// their validator rates.
pub fn pool_value(state: &dyn VmState) -> u128 {
    let pool = pool_address();
    state
        .get_balance(pool.as_bytes())
        .saturating_add(super::settlement_asset::holdings_tnzo_eq(
            state,
            pool.as_bytes(),
        ))
}

/// The pool's value, micro-units of account, with it holding `pool_tnzo`
/// wei of TNZO: the TNZO at the safety rate, its settlement-asset holdings
/// at their validator rates.
pub fn value_e6_at_safety(state: &dyn VmState, pool_tnzo: u128) -> u128 {
    super::settlement_asset::tnzo_value_e6(pool_tnzo, super::economy::safety_rate(state))
        .saturating_add(super::settlement_asset::holdings_value_e6(
            state,
            pool_address().as_bytes(),
        ))
}

/// TNZO base units `e6` micro-units of account buy at the rate in force,
/// rounded down.
fn wei_for_e6(state: &dyn VmState, e6: u128) -> u128 {
    use revm::primitives::U256;
    let rate = super::economy::read_fee_rate(state).rate_nano_usd.max(1);
    let wei = U256::from(e6) * U256::from(1_000u32) * U256::from(WEI_PER_TNZO) / U256::from(rate);
    u128::try_from(wei).unwrap_or(u128::MAX)
}

/// The most one claim may take with the pool holding `pool` wei of TNZO:
/// `insurance.max_claim_bps` of the pool's value with its TNZO at the safety
/// rate, paid in TNZO at the rate in force (never above the safety rate, so
/// never more TNZO than the safety rate gives), and never more than
/// `insurance.max_claim_tnzo`.
pub fn claim_cap(state: &dyn VmState, pool: u128) -> u128 {
    let bps = u128::from(network_param(state, MAX_CLAIM_BPS_PARAM).min(10_000));
    let abs = u128::from(network_param(state, MAX_CLAIM_TNZO_PARAM)).saturating_mul(WEI_PER_TNZO);
    let cap_e6 = super::staking::bps_share(value_e6_at_safety(state, pool), bps);
    wei_for_e6(state, cap_e6).min(abs)
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct PaidEpoch {
    epoch: u64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    paid: u128,
}

/// What claims have paid in the current epoch, wei.
pub fn read_epoch_paid(state: &dyn VmState) -> u128 {
    let epoch = super::economy::read_current_epoch(state);
    read_json::<PaidEpoch>(state, PAID_EPOCH_KEY)
        .filter(|p| p.epoch == epoch)
        .map_or(0, |p| p.paid)
}

/// The per-epoch ceiling on what claims pay, wei.
pub fn epoch_ceiling(state: &dyn VmState) -> u128 {
    u128::from(network_param(state, MAX_PAID_EPOCH_PARAM).min(MAX_PAID_TNZO_EPOCH))
        .saturating_mul(WEI_PER_TNZO)
}

/// What a claim proving `loss` wei is paid now: the loss, at most the claim
/// cap, what the epoch's ceiling has left, and the pool's TNZO.
pub fn payable(state: &dyn VmState, loss: u128) -> u128 {
    let held = state.get_balance(pool_address().as_bytes());
    loss.min(claim_cap(state, held))
        .min(epoch_ceiling(state).saturating_sub(read_epoch_paid(state)))
        .min(held)
}

/// Counts `paid` against the current epoch's ceiling.
pub(super) fn book_paid(
    state: &mut dyn VmState,
    paid: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let record = PaidEpoch {
        epoch: super::economy::read_current_epoch(state),
        paid: read_epoch_paid(state).saturating_add(paid),
    };
    write_json(state, PAID_EPOCH_KEY, &record, changes)?;
    Ok(())
}

/// The pool's coverage as published at an epoch boundary.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Coverage {
    /// The epoch it was published for.
    pub epoch: u64,
    /// The pool's value with its TNZO at the safety rate, micro-units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub value_e6: u128,
    /// The safety rate it was valued at, nano-USD per TNZO.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub safety_rate_nano_usd: u128,
    /// `insurance.cover_target_units` in force, micro-units.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub target_e6: u128,
    /// `value_e6` against `target_e6`, bps; `None` with no target.
    pub ratio_bps: Option<u64>,
    /// What one claim may take now, wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub claim_cap: u128,
}

/// The coverage last published.
pub fn read_coverage(state: &dyn VmState) -> Option<Coverage> {
    read_json(state, COVER_KEY)
}

/// The pool's coverage now, labelled with `epoch`.
pub fn coverage(state: &dyn VmState, epoch: u64) -> Coverage {
    let held = state.get_balance(pool_address().as_bytes());
    let value_e6 = value_e6_at_safety(state, held);
    let target_e6 =
        u128::from(network_param(state, COVER_TARGET_PARAM).min(MAX_COVER_TARGET_UNITS))
            .saturating_mul(1_000_000);
    Coverage {
        epoch,
        value_e6,
        safety_rate_nano_usd: super::economy::safety_rate(state),
        target_e6,
        ratio_bps: (target_e6 > 0).then(|| {
            u64::try_from(value_e6.saturating_mul(10_000) / target_e6).unwrap_or(u64::MAX)
        }),
        claim_cap: claim_cap(state, held),
    }
}

/// Publishes the pool's coverage for the closed `epoch`: stores it and logs
/// it.
pub(super) fn publish_coverage(
    state: &mut dyn VmState,
    epoch: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let c = coverage(state, epoch);
    write_json(state, COVER_KEY, &c, changes)?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![INSURANCE_COVERAGE_TOPIC.to_vec()],
        serde_json::to_vec(&c)
            .map_err(|e| VmError::Internal(format!("encode coverage log: {e}")))?,
    ));
    Ok(())
}

/// The most one claim may take: `bps` of `pool`, and never more than `abs`.
/// Only the Kani harness in proofs/insurance.rs calls it.
#[cfg(all(kani, feature = "kani"))]
pub(crate) fn claim_cap_of(pool: u128, bps: u128, abs: u128) -> u128 {
    super::staking::bps_share(pool, bps).min(abs)
}

/// The loss `evidence` proves and the account it is owed to.
fn prove_loss(state: &dyn VmState, evidence: &InsuranceEvidence) -> Result<(Vec<u8>, u128)> {
    match evidence {
        InsuranceEvidence::ReconMismatch {
            adapter,
            chain,
            position,
        } => {
            let m = read_mismatch(state, *adapter, chain, *position)
                .ok_or_else(|| refuse("no reconciliation mismatch is stored at that position"))?;
            if !m.attested {
                return Err(refuse(
                    "the route proves its lock by light client; no committee answers for it",
                ));
            }
            let harmed = m
                .harmed
                .ok_or_else(|| refuse("the mismatch cost no account on Tenzro"))?;
            if m.loss == 0 {
                return Err(refuse("the mismatched leg carries no value"));
            }
            Ok((harmed.as_bytes().to_vec(), m.loss))
        }
    }
}

impl NativeExecutor {
    /// Handle `PayInsuranceClaim`: pay the sender the loss its evidence
    /// proves, capped by governance, from the pool vault.
    pub(super) fn execute_pay_insurance_claim(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        gas_meter.consume(GAS_PAY_INSURANCE_CLAIM)?;
        crate::invariant_monitor::require_unfrozen(
            state,
            crate::invariant_monitor::GuardedModule::Insurance,
        )?;
        let evidence: InsuranceEvidence = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid PayInsuranceClaim payload: {e}")))?;
        let id = hex::encode(claim_id(&evidence));
        if read_claim(state, &id).is_some() {
            return Err(refuse("this evidence has already been paid"));
        }
        let cost = tx
            .gas_price
            .saturating_mul(u128::from(GAS_PAY_INSURANCE_CLAIM));
        let balance = state.get_balance(&tx.from);
        if balance < cost {
            return Err(VmError::InsufficientBalance {
                required: cost,
                available: balance,
            });
        }
        state.set_balance(&tx.from, balance - cost);
        let mut changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - cost).to_le_bytes().to_vec()),
        )];

        let (owed_to, loss) = prove_loss(state, &evidence)?;
        if owed_to != tx.from {
            return Err(refuse(
                "the evidence names another account as the one harmed",
            ));
        }
        let pool = pool_address().as_bytes().to_vec();
        let held = state.get_balance(&pool);
        // The cap counts everything the pool holds, its TNZO at the safety
        // rate; a claim is paid in TNZO, at most what the pool holds in TNZO
        // and what the epoch's ceiling has left.
        let paid = payable(state, loss);
        if held == 0 {
            return Err(refuse("the insurance pool is empty"));
        }
        if paid == 0 {
            return Err(refuse(format!(
                "insurance claims have paid this epoch's ceiling of {} wei",
                epoch_ceiling(state)
            )));
        }
        state.set_balance(&pool, held - paid);
        let claimant_before = state.get_balance(&tx.from);
        state.set_balance(&tx.from, claimant_before + paid);
        changes.push(StateChange::new(
            pool,
            b"balance".to_vec(),
            Some(held.to_le_bytes().to_vec()),
            Some((held - paid).to_le_bytes().to_vec()),
        ));
        changes.push(StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(claimant_before.to_le_bytes().to_vec()),
            Some((claimant_before + paid).to_le_bytes().to_vec()),
        ));
        let claim = InsuranceClaim {
            claim_id: id.clone(),
            claimant: hex::encode(&tx.from),
            evidence,
            loss,
            paid,
            paid_at_ms: deterministic_now_ms(tx),
        };
        write_json(state, &claim_key(&id), &claim, &mut changes)?;
        let mut ids = claim_ids(state);
        ids.push(id.clone());
        write_json(state, CLAIM_IDS_KEY, &ids, &mut changes)?;
        book_paid(state, paid, &mut changes)?;
        let mut totals = read_totals(state);
        totals.claims_paid += 1;
        totals.total_paid = totals.total_paid.saturating_add(paid);
        write_json(state, TOTALS_KEY, &totals, &mut changes)?;

        let old_nonce = state.get_nonce(&tx.from);
        state.set_nonce(&tx.from, old_nonce + 1);
        changes.push(StateChange::new(
            tx.from.clone(),
            b"nonce".to_vec(),
            Some(old_nonce.to_le_bytes().to_vec()),
            Some((old_nonce + 1).to_le_bytes().to_vec()),
        ));
        let log = Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![INSURANCE_CLAIM_PAID_TOPIC.to_vec()],
            serde_json::to_vec(&claim)
                .map_err(|e| VmError::Internal(format!("encode claim log: {e}")))?,
        );
        Ok(ExecutionResult::success(
            gas_meter.final_used(),
            paid.to_le_bytes().to_vec(),
            vec![log],
            changes,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const ONE: u128 = WEI_PER_TNZO;

    fn pool_with(tnzo: u128) -> StateAdapter {
        let mut state = StateAdapter::new();
        state.set_balance(pool_address().as_bytes(), tnzo);
        state
    }

    #[test]
    fn claims_in_one_epoch_pay_at_most_the_epoch_ceiling() {
        let mut state = pool_with(10_000_000 * ONE);
        super::super::set_governed_param_for_test(&mut state, MAX_PAID_EPOCH_PARAM, 15_000);
        let mut paid = 0;
        for _ in 0..5 {
            let p = payable(&state, 10_000 * ONE);
            book_paid(&mut state, p, &mut Vec::new()).unwrap();
            paid += p;
        }
        assert_eq!(paid, 15_000 * ONE);
        assert_eq!(payable(&state, ONE), 0);
    }

    #[test]
    fn the_claim_cap_values_the_pool_at_the_safety_rate() {
        // A pool of 100,000 TNZO, 10% per claim, at $1 in force.
        let mut state = pool_with(100_000 * ONE);
        super::super::set_governed_param_for_test(&mut state, MAX_CLAIM_TNZO_PARAM, 1_000_000);
        super::super::economy::write_rate_for_tests(&mut state, 10, 1_000_000_000, 1_000_000_000);
        assert_eq!(claim_cap(&state, 100_000 * ONE), 10_000 * ONE);
        // The latest median says $0.20 while the rate in force is still
        // $1: the pool is worth $20,000 at the safety rate, so one claim
        // takes at most $2,000, 2,000 TNZO at the rate in force.
        super::super::economy::write_rate_for_tests(&mut state, 11, 200_000_000, 1_000_000_000);
        assert_eq!(super::super::economy::safety_rate(&state), 200_000_000);
        assert_eq!(claim_cap(&state, 100_000 * ONE), 2_000 * ONE);
        let c = coverage(&state, 11);
        assert_eq!(c.value_e6, 20_000 * 1_000_000);
        assert_eq!(
            c.target_e6,
            u128::from(DEFAULT_COVER_TARGET_UNITS) * 1_000_000
        );
        assert_eq!(c.ratio_bps, Some(200));
        assert_eq!(c.claim_cap, 2_000 * ONE);
    }

    #[test]
    fn coverage_is_published_at_each_epoch_boundary() {
        let mut state = pool_with(50_000 * ONE);
        let mut logs = Vec::new();
        publish_coverage(&mut state, 7, &mut Vec::new(), &mut logs).unwrap();
        assert_eq!(read_coverage(&state).unwrap().epoch, 7);
        assert_eq!(logs[0].topics[0], INSURANCE_COVERAGE_TOPIC.to_vec());
    }
}
