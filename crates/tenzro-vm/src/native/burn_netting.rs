//! Burn-equivalent netting against epoch issuance.
//!
//! A settlement fee collected in a token other than TNZO pays its burn share
//! to the treasury's stable holdings and books that share's TNZO equivalent
//! for the epoch ([`super::economy::EpochActivity::burn_eq`]). When the
//! epoch closes, its burn-equivalent and the burn debt carried from earlier
//! epochs are netted against the epoch's issuance: that much is withheld
//! from the epoch's reward rights and burned from the rewards pool, so
//! supply falls by what it would have had the fee been burned in TNZO.
//!
//! What issuance cannot cover is carried as burn debt, at most
//! `fees.burn_debt_cap_epochs` epochs of the schedule's issuance. Past the
//! cap the treasury burns TNZO, at most `fees.treasury_burn_max_tnzo_epoch`
//! whole TNZO per epoch and never more than the reserve's per-epoch sale
//! cap. Anything past both caps is written off, and the epoch's netting
//! record says how much.
//!
//! Records under `SYSTEM_ADDRESS`: `econ_burn_debt` (the debt carried, TNZO
//! base units) and `econ_netting:<epoch>` (what each closed epoch netted).

use serde::{Deserialize, Serialize};

use super::funding::{read_json, write_json};
use super::*;

/// Governed key: most burn debt carried, in epochs of scheduled issuance.
pub const BURN_DEBT_CAP_PARAM: &str = "fees.burn_debt_cap_epochs";
/// Genesis value of [`BURN_DEBT_CAP_PARAM`].
pub const DEFAULT_BURN_DEBT_CAP_EPOCHS: u64 = 24;
/// Greatest value of [`BURN_DEBT_CAP_PARAM`]: one week of hourly epochs.
pub const MAX_BURN_DEBT_CAP_EPOCHS: u64 = 168;
/// Governed key: most TNZO the treasury burns in one epoch for burn debt
/// past its cap, whole TNZO.
pub const TREASURY_BURN_MAX_PARAM: &str = "fees.treasury_burn_max_tnzo_epoch";
/// Genesis value of [`TREASURY_BURN_MAX_PARAM`].
pub const DEFAULT_TREASURY_BURN_MAX_TNZO_EPOCH: u64 = 10_000;

/// Topic of the log an epoch emits when it writes burn debt off; data is
/// the epoch's [`EpochNetting`] as JSON.
pub const FEE_NETTING_WRITE_OFF_TOPIC: &[u8] = b"FeeNettingWriteOff";

const BURN_DEBT_KEY: &str = "econ_burn_debt";

fn netting_key(epoch: u64) -> String {
    format!("econ_netting:{epoch:016x}")
}

/// What one closed epoch netted, TNZO base units.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochNetting {
    /// The epoch closed.
    pub epoch: u64,
    /// Burn-equivalent the epoch's fees in kind booked.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub burn_eq: u128,
    /// Burn debt carried into the epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub debt_in: u128,
    /// The epoch's reward rights before netting.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub issuance: u128,
    /// Rights withheld and burned from the rewards pool.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub withheld: u128,
    /// The most burn debt that may be carried out of the epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub debt_cap: u128,
    /// TNZO the treasury burned for debt past the cap.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub treasury_burned: u128,
    /// Debt past both caps, written off.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub written_off: u128,
    /// Burn debt carried out of the epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub debt_out: u128,
}

/// The burn debt carried, TNZO base units.
pub fn read_burn_debt(state: &dyn VmState) -> u128 {
    read_json::<String>(state, BURN_DEBT_KEY)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// What closed epoch `epoch` netted, when it had anything to net.
pub fn read_epoch_netting(state: &dyn VmState, epoch: u64) -> Option<EpochNetting> {
    read_json(state, &netting_key(epoch))
}

/// Deletes the netting record of `epoch`, with its other reward records.
pub(super) fn prune_epoch(state: &mut dyn VmState, epoch: u64, changes: &mut Vec<StateChange>) {
    super::funding::delete_record(state, &netting_key(epoch), changes);
}

/// Most TNZO the treasury may burn in one epoch, base units: the governed
/// cap, never above the reserve's per-epoch sale cap.
pub fn treasury_burn_cap(state: &dyn VmState) -> u128 {
    let whole = network_param(state, TREASURY_BURN_MAX_PARAM).min(network_param(
        state,
        super::treasury_reserve::MAX_SALE_PARAM,
    ));
    u128::from(whole).saturating_mul(tenzro_types::constants::ONE_TNZO)
}

fn burn_from(
    state: &mut dyn VmState,
    account: &[u8],
    amount: u128,
    changes: &mut Vec<StateChange>,
) {
    if amount == 0 {
        return;
    }
    let old = state.get_balance(account);
    let new = old - amount;
    state.set_balance(account, new);
    changes.push(StateChange::new(
        account.to_vec(),
        b"balance".to_vec(),
        Some(old.to_le_bytes().to_vec()),
        Some(new.to_le_bytes().to_vec()),
    ));
    state.record_native_burn(amount);
}

/// Nets closing epoch `epoch`'s burn-equivalent and the carried burn debt
/// against its `issuance`, with `per_epoch` the schedule's issuance per
/// epoch that the debt cap is counted in. Returns the rights withheld from
/// the epoch, already burned from the rewards pool; a write-off pushes a
/// `FeeNettingWriteOff` log onto `logs`.
pub(super) fn net_epoch(
    state: &mut dyn VmState,
    epoch: u64,
    issuance: u128,
    per_epoch: u128,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<u128> {
    let burn_eq = super::economy::read_epoch_activity(state, epoch).burn_eq;
    let debt_in = read_burn_debt(state);
    let owed = burn_eq.saturating_add(debt_in);
    if owed == 0 {
        return Ok(0);
    }
    let pool = tenzro_token::rewards::rewards_pool_address();
    let withheld = owed.min(issuance).min(state.get_balance(pool.as_bytes()));
    burn_from(state, pool.as_bytes(), withheld, changes);
    let mut debt = owed - withheld;
    let debt_cap = per_epoch.saturating_mul(u128::from(
        network_param(state, BURN_DEBT_CAP_PARAM).min(MAX_BURN_DEBT_CAP_EPOCHS),
    ));
    let (mut treasury_burned, mut written_off) = (0, 0);
    if debt > debt_cap {
        let excess = debt - debt_cap;
        let treasury = derive_treasury_address();
        treasury_burned = excess
            .min(treasury_burn_cap(state))
            .min(state.get_balance(treasury.as_bytes()));
        burn_from(state, treasury.as_bytes(), treasury_burned, changes);
        written_off = excess - treasury_burned;
        debt = debt_cap;
    }
    write_json(state, BURN_DEBT_KEY, &debt.to_string(), changes)?;
    let record = EpochNetting {
        epoch,
        burn_eq,
        debt_in,
        issuance,
        withheld,
        debt_cap,
        treasury_burned,
        written_off,
        debt_out: debt,
    };
    write_json(state, &netting_key(epoch), &record, changes)?;
    if written_off > 0 {
        let data = serde_json::to_vec(&record)
            .map_err(|e| VmError::Internal(format!("encode netting log: {e}")))?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![FEE_NETTING_WRITE_OFF_TOPIC.to_vec()],
            data,
        ));
    }
    Ok(withheld)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;
    use tenzro_token::rewards::{NETWORK_REWARDS_POOL, rewards_pool_address};
    use tenzro_types::constants::ONE_TNZO;

    const TREASURY_TNZO: u128 = 1_000_000 * ONE_TNZO;

    fn world() -> StateAdapter {
        let mut state = StateAdapter::new();
        let schedule = super::super::rewards::genesis_reward_schedule(86_400_000).unwrap();
        state.set_storage(
            &SYSTEM_ADDRESS,
            super::super::rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            schedule,
        );
        state.set_balance(rewards_pool_address().as_bytes(), NETWORK_REWARDS_POOL);
        state.set_balance(derive_treasury_address().as_bytes(), TREASURY_TNZO);
        state
    }

    fn proposer() -> Address {
        Address::new([0x31; 32])
    }

    /// Opens epoch `epoch` with one block, books `burn_eq` and `burned` in it,
    /// and closes it with the next epoch's first block.
    fn run_epoch(state: &mut StateAdapter, epoch: u64, burn_eq: u128, burned: u128) {
        let at = epoch as i64 * 86_400_000;
        super::super::rewards::begin_block(state, epoch, &proposer(), at).unwrap();
        super::super::economy::book_for_tests(state, burned, burn_eq);
        let logs =
            super::super::rewards::begin_block(state, epoch + 1, &proposer(), at + 86_400_000)
                .unwrap();
        let written_off = read_epoch_netting(state, epoch).map_or(0, |n| n.written_off);
        let alerts: Vec<_> = logs
            .iter()
            .filter(|l| l.topics.first().map(Vec::as_slice) == Some(FEE_NETTING_WRITE_OFF_TOPIC))
            .collect();
        assert_eq!(
            alerts.len(),
            usize::from(written_off > 0),
            "one alert per write-off"
        );
        if let Some(log) = alerts.first() {
            let logged: EpochNetting = serde_json::from_slice(&log.data).unwrap();
            assert_eq!(logged.written_off, written_off);
        }
    }

    fn summary(state: &StateAdapter, epoch: u64) -> tenzro_token::rewards::EpochRewardSummary {
        super::super::rewards::read_epoch_summary(state, epoch)
            .unwrap()
            .unwrap()
    }

    fn pool(state: &StateAdapter) -> u128 {
        state.get_balance(rewards_pool_address().as_bytes())
    }

    #[test]
    fn a_burn_equivalent_within_issuance_is_withheld_and_burned_from_the_pool() {
        let b = 1_000 * ONE_TNZO;
        // The same fees, burned in TNZO.
        let mut paid_in_tnzo = world();
        run_epoch(&mut paid_in_tnzo, 0, 0, b);
        // The same fees, collected in kind.
        let mut in_kind = world();
        run_epoch(&mut in_kind, 0, b, 0);

        let t = summary(&paid_in_tnzo, 0);
        let k = summary(&in_kind, 0);
        assert_eq!(k.withheld, b);
        assert_eq!(k.rights_issued + b, t.rights_issued);
        // Supply falls by the same amount: the TNZO payer's burn happened in
        // its transaction, the in-kind burn from the pool.
        assert_eq!(in_kind.total_burned(), b);
        assert_eq!(pool(&in_kind), NETWORK_REWARDS_POOL - b);
        // What reaches holders is the same net of the burn.
        assert_eq!(k.rights_issued, t.rights_issued - b);
        let n = read_epoch_netting(&in_kind, 0).unwrap();
        assert_eq!((n.burn_eq, n.withheld, n.debt_out), (b, b, 0));
        assert_eq!(read_burn_debt(&in_kind), 0);
        // The pool is not asked for the withheld rights again.
        let rs = super::super::rewards::read_reward_state(&in_kind).unwrap();
        assert_eq!(rs.cumulative_rights_issued, k.rights_issued + k.withheld);
        assert!(read_epoch_netting(&paid_in_tnzo, 0).is_none());
    }

    #[test]
    fn a_burn_equivalent_past_issuance_is_carried_then_burned_by_the_treasury_up_to_its_caps() {
        let mut state = world();
        super::super::set_governed_param_for_test(&mut state, BURN_DEBT_CAP_PARAM, 1);
        // No validator base rights, so the epoch's issuance is the schedule's.
        super::super::set_governed_param_for_test(
            &mut state,
            super::super::rewards::VALIDATOR_BURN_SHARE_PARAM,
            0,
        );
        run_epoch(&mut state, 0, 0, 0);
        let issuance = summary(&state, 0).rights_issued;

        // Twice the epoch's issuance: one issuance withheld, one carried (the
        // cap is one epoch of issuance), nothing for the treasury.
        let mut state = world();
        super::super::set_governed_param_for_test(&mut state, BURN_DEBT_CAP_PARAM, 1);
        // No validator base rights, so the epoch's issuance is the schedule's.
        super::super::set_governed_param_for_test(
            &mut state,
            super::super::rewards::VALIDATOR_BURN_SHARE_PARAM,
            0,
        );
        run_epoch(&mut state, 0, 2 * issuance, 0);
        let n = read_epoch_netting(&state, 0).unwrap();
        assert_eq!(n.withheld, issuance);
        assert!(n.debt_cap >= issuance);
        assert_eq!(n.debt_out, issuance);
        assert_eq!((n.treasury_burned, n.written_off), (0, 0));
        assert_eq!(summary(&state, 0).rights_issued, 0);

        // The next epoch nets the carried debt first.
        run_epoch(&mut state, 1, 0, 0);
        let n1 = read_epoch_netting(&state, 1).unwrap();
        assert_eq!(n1.debt_in, issuance);
        assert_eq!(n1.withheld, n1.issuance.min(issuance));
        assert_eq!(n1.debt_out, issuance - n1.withheld);
        assert_eq!(read_burn_debt(&state), n1.debt_out);

        // Far past the cap: the debt stops at the cap, the treasury burns at
        // most its per-epoch cap, and the rest is written off.
        let cap = treasury_burn_cap(&state);
        assert_eq!(cap, DEFAULT_TREASURY_BURN_MAX_TNZO_EPOCH as u128 * ONE_TNZO);
        let burned_before = state.total_burned();
        run_epoch(&mut state, 2, 3 * issuance + 2 * cap, 0);
        let n2 = read_epoch_netting(&state, 2).unwrap();
        assert_eq!(n2.debt_out, n2.debt_cap);
        assert_eq!(n2.treasury_burned, cap);
        assert_eq!(
            n2.withheld + n2.debt_out + n2.treasury_burned + n2.written_off,
            n2.burn_eq + n2.debt_in
        );
        assert!(n2.written_off > 0);
        assert_eq!(
            state.get_balance(derive_treasury_address().as_bytes()),
            TREASURY_TNZO - cap
        );
        assert_eq!(state.total_burned() - burned_before, n2.withheld + cap);
        assert!(read_burn_debt(&state) <= n2.debt_cap);
    }

    #[test]
    fn the_treasury_burn_never_passes_the_reserve_sale_cap() {
        let mut state = world();
        super::super::set_governed_param_for_test(&mut state, TREASURY_BURN_MAX_PARAM, 1_000_000);
        super::super::set_governed_param_for_test(
            &mut state,
            super::super::treasury_reserve::MAX_SALE_PARAM,
            7,
        );
        assert_eq!(treasury_burn_cap(&state), 7 * ONE_TNZO);
    }

    #[test]
    fn netting_is_the_same_on_every_execution() {
        let run = || {
            let mut state = world();
            super::super::set_governed_param_for_test(&mut state, BURN_DEBT_CAP_PARAM, 2);
            for (epoch, eq) in [(0u64, 5u128), (1, 900_000), (2, 0), (3, 1_234_567)] {
                run_epoch(&mut state, epoch, eq * ONE_TNZO, 3 * ONE_TNZO);
            }
            (
                (0..4)
                    .map(|e| {
                        (
                            read_epoch_netting(&state, e),
                            summary(&state, e).rights_issued,
                        )
                    })
                    .collect::<Vec<_>>(),
                read_burn_debt(&state),
                pool(&state),
                state.get_balance(derive_treasury_address().as_bytes()),
                state.total_burned(),
            )
        };
        assert_eq!(run(), run());
    }
}
