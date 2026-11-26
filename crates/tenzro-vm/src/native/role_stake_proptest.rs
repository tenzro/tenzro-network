//! Role staking driven as a sequence: any order of bonds, unbonds,
//! withdrawals, slashes and passing time, through the `Stake` executor and
//! the slash path, keeps two things true after every step. No TNZO is made
//! or lost (the accounts, the role-stake vault and the insurance pool hold
//! what they held at the start), and the vault holds exactly what the
//! stakes say it owes, bonded and unbonding. A refused step changes nothing.

use super::*;
use crate::VmConfig;
use crate::VmType;
use crate::native::staking::{SlashedStake, slash_to_insurance};
use crate::state_adapter::StateAdapter;
use crate::types::VmTransaction;
use proptest::prelude::*;
use tenzro_types::token::{StakeCapacity, StakeOp};

const ROLE: NetworkRole = NetworkRole::Rpc;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
enum Step {
    /// Bond this many units more.
    Bond(usize, u8),
    /// Start unbonding this many units.
    Unbond(usize, u8),
    Withdraw(usize),
    /// Let this many days pass.
    Wait(u8),
    /// Slash this many basis points of the role stake.
    Slash(usize, u16),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0..3usize, 1..4u8).prop_map(|(w, n)| Step::Bond(w, n)),
        (0..3usize, 0..3u8).prop_map(|(w, n)| Step::Unbond(w, n)),
        (0..3usize).prop_map(Step::Withdraw),
        (0..10u8).prop_map(Step::Wait),
        (0..3usize, 0..3_000u16).prop_map(|(w, b)| Step::Slash(w, b)),
    ]
}

fn account(who: usize) -> Vec<u8> {
    vec![0x40 + who as u8; 20]
}

/// What the accounts, the vault and the pool hold together.
fn held(state: &StateAdapter) -> u128 {
    let vault = state.get_balance(role_stake_vault().as_bytes());
    let pool = state.get_balance(crate::native::derive_insurance_pool_address().as_bytes());
    (0..3).map(|w| state.get_balance(&account(w))).sum::<u128>() + vault + pool
}

/// What the stakes say the vault owes.
fn owed(state: &StateAdapter) -> u128 {
    (0..3)
        .filter_map(|w| read_role_stake(state, &account(w), ROLE))
        .map(|s| s.bonded + s.unbonding)
        .sum()
}

async fn stake(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    from: &[u8],
    op: &StakeOp,
    at: i64,
) -> Result<()> {
    let mut data = SELECTOR_STAKE.to_vec();
    data.extend(serde_json::to_vec(op).unwrap());
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        10_000_000,
        0,
        0,
        VmType::Tenzro,
        1337,
    );
    tx.block_timestamp_ms = Some(at);
    ex.execute_transaction(&tx, state).await.map(|_| ())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn any_sequence_of_role_stake_steps_conserves_value_and_keeps_the_vault_whole(
        steps in proptest::collection::vec(step(), 1..40),
    ) {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let ex = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let unit = ROLE
            .required_stake(&StakeCapacity::None, &entry_stake_ladder(&state))
            .max(1);
        for w in 0..3 {
            state.set_balance(&account(w), 20 * unit);
        }
        let start = held(&state);
        let mut now = 1_000_000i64;
        for s in steps {
            let before = (held(&state), owed(&state));
            state.begin_transaction();
            let done = match &s {
                Step::Bond(w, n) => runtime.block_on(stake(
                    &ex,
                    &mut state,
                    &account(*w),
                    &StakeOp::Bond { role: ROLE, amount: unit * u128::from(*n), capacity: StakeCapacity::None },
                    now,
                )),
                Step::Unbond(w, n) => runtime.block_on(stake(
                    &ex,
                    &mut state,
                    &account(*w),
                    &StakeOp::Unbond { role: ROLE, amount: unit * u128::from(*n) },
                    now,
                )),
                Step::Withdraw(w) => runtime.block_on(stake(
                    &ex,
                    &mut state,
                    &account(*w),
                    &StakeOp::Withdraw { role: ROLE },
                    now,
                )),
                Step::Wait(days) => {
                    now += i64::from(*days) * DAY_MS;
                    Ok(())
                }
                Step::Slash(w, bps) => {
                    slash_to_insurance(&mut state, &account(*w), SlashedStake::Role(ROLE), *bps, &mut Vec::new())
                        .map(|_| ())
                }
            };
            if done.is_ok() {
                state.commit_transaction();
            } else {
                state.revert_transaction();
                prop_assert_eq!((held(&state), owed(&state)), before, "a refused {:?} changed something", s);
            }
            prop_assert_eq!(held(&state), start, "TNZO made or lost after {:?}", s);
            prop_assert_eq!(
                state.get_balance(role_stake_vault().as_bytes()),
                owed(&state),
                "the vault does not hold what the stakes owe after {:?}",
                s
            );
        }
    }
}
