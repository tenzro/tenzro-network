//! Governance-sponsored validator bonds: existing treasury TNZO bonded on a
//! validator's behalf counts toward the bond, is slashed like it, never
//! votes, earns or moves a reward, returns to the treasury on recall or exit,
//! and no path creates or destroys TNZO.

use super::sponsored_bond::{self, MAX_PER_VALIDATOR_PARAM, MAX_TOTAL_PARAM};
use super::staking::{self, SlashedStake};
use super::*;
use crate::governance::{MIN_BOND_AGE_MS, ProposalAction, TIMELOCK_DELAY_MS, VOTING_PERIOD_MS};
use crate::state_adapter::StateAdapter;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SponsoredBondOp;

const TNZO: u128 = tenzro_types::constants::ONE_TNZO;
const GAS_BALANCE: u128 = 10_000_000_000_000_000_000;
const TREASURY: u128 = 10_000_000 * TNZO;
const OWN: u128 = 50_000 * TNZO;
const SPONSORED: u128 = 50_000 * TNZO;
const VOTER: [u8; 32] = [0x0a; 32];
const VALIDATOR: [u8; 32] = [0x0b; 32];
const STRANGER: [u8; 32] = [0x0c; 32];

fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(key).as_bytes(),
        value.to_le_bytes().to_vec(),
    );
}

/// A registered validator with `own` bonded, aged past the minimum bond age.
fn validator(state: &mut StateAdapter, who: &[u8], own: u128) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        format!("validator_register:{}", hex::encode(who)).as_bytes(),
        b"{}".to_vec(),
    );
    staking::add_bond(state, who, own, -MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + own);
    state.set_balance(who, GAS_BALANCE);
    test_operate_own_validator(state, who);
}

/// A chain with a funded treasury, a large voting validator, the sponsored
/// validator, and caps that admit `SPONSORED`.
fn chain() -> StateAdapter {
    let mut state = StateAdapter::new();
    state.set_balance(derive_treasury_address().as_bytes(), TREASURY);
    validator(&mut state, &VOTER, 1_000_000 * TNZO);
    validator(&mut state, &VALIDATOR, OWN);
    state.set_balance(&STRANGER, GAS_BALANCE);
    set_param(&mut state, MAX_PER_VALIDATOR_PARAM, 100_000);
    set_param(&mut state, MAX_TOTAL_PARAM, 1_000_000);
    super::payout_gates::approve_operator_for_test(
        &mut state,
        &VALIDATOR,
        crate::governance::OperatorClass::Validator,
    );
    state
}

fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        500_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    tx.block_timestamp_ms = Some(at_ms);
    tx
}

/// Propose `action` at `at_ms`, vote it through with the voter, queue it and
/// enact it. Returns the enactment's result and its block time.
async fn enact(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    action: &ProposalAction,
    at_ms: i64,
) -> (ExecutionResult, i64) {
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(action).unwrap());
    let created = executor
        .execute_transaction(&tx(&VOTER, data, at_ms), state)
        .await
        .expect("proposal accepted");
    let id = created.output.clone();
    executor
        .execute_transaction(
            &tx(&VOTER, test_vote_data(&id, true, &VOTER), at_ms + 10),
            state,
        )
        .await
        .expect("vote accepted");
    let mut exec = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
    exec.extend_from_slice(&id);
    let queued = at_ms + VOTING_PERIOD_MS + 1;
    executor
        .execute_transaction(&tx(&VOTER, exec.clone(), queued), state)
        .await
        .expect("queued");
    let enacted = queued + TIMELOCK_DELAY_MS + 1;
    let result = executor
        .execute_transaction(&tx(&VOTER, exec, enacted), state)
        .await
        .expect("enacted");
    (result, enacted)
}

fn sponsor_action(amount: u128) -> ProposalAction {
    ProposalAction::SponsorValidatorBond {
        validator: Address::new(VALIDATOR),
        amount,
        memo: "bond cover for the minimum validator set".into(),
    }
}

fn recall_action(amount: u128) -> ProposalAction {
    ProposalAction::RecallSponsoredBond {
        validator: Address::new(VALIDATOR),
        amount,
        memo: "recalled".into(),
    }
}

fn has_topic(result: &ExecutionResult, topic: &[u8]) -> bool {
    result
        .logs
        .iter()
        .any(|l| l.topics.first().map(Vec::as_slice) == Some(topic))
}

fn treasury(state: &StateAdapter) -> u128 {
    state.get_balance(derive_treasury_address().as_bytes())
}

#[tokio::test]
async fn sponsorship_is_refused_while_the_caps_are_at_their_genesis_zero() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    for key in [MAX_PER_VALIDATOR_PARAM, MAX_TOTAL_PARAM] {
        state.set_storage(
            &SYSTEM_ADDRESS,
            governed_param_key(key).as_bytes(),
            Vec::new(),
        );
        assert_eq!(network_param(&state, key), 0, "{key} starts disabled");
    }
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&sponsor_action(SPONSORED)).unwrap());
    let refused = executor
        .execute_transaction(&tx(&VOTER, data, 1_000), &mut state)
        .await;
    assert!(
        refused.is_err() || !refused.unwrap().success,
        "no bond can be sponsored before governance sets the caps"
    );
    assert_eq!(treasury(&state), TREASURY);
}

#[tokio::test]
async fn a_sponsored_bond_counts_toward_the_bond() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    let total = staking::total_bonded(&state);
    let (result, _) = enact(&executor, &mut state, &sponsor_action(SPONSORED), 1_000).await;
    assert!(result.success);
    assert!(has_topic(&result, sponsored_bond::SPONSORED_TOPIC));

    assert_eq!(
        staking::bonded_stake_of(&state, &VALIDATOR),
        OWN + SPONSORED
    );
    assert_eq!(staking::sponsored_bond_of(&state, &VALIDATOR), SPONSORED);
    assert_eq!(staking::own_bonded_stake_of(&state, &VALIDATOR), OWN);
    assert_eq!(staking::total_bonded(&state), total + SPONSORED);
    // Existing treasury TNZO moved into the vault; the validator was paid
    // nothing.
    assert_eq!(treasury(&state), TREASURY - SPONSORED);
    assert_eq!(state.get_balance(&STAKING_VAULT_ADDRESS), vault + SPONSORED);
    assert_eq!(state.get_balance(&VALIDATOR), GAS_BALANCE);
}

#[tokio::test]
async fn a_sponsored_bond_above_the_cap_is_refused() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    set_param(&mut state, MAX_PER_VALIDATOR_PARAM, 10_000);
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&sponsor_action(SPONSORED)).unwrap());
    let refused = executor
        .execute_transaction(&tx(&VOTER, data, 1_000), &mut state)
        .await;
    assert!(refused.is_err() || !refused.unwrap().success);
}

#[tokio::test]
async fn a_recall_returns_the_sponsored_stake_to_the_treasury() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let (_, at) = enact(&executor, &mut state, &sponsor_action(SPONSORED), 1_000).await;
    let (recalled, at) = enact(&executor, &mut state, &recall_action(SPONSORED), at + 1).await;
    assert!(has_topic(&recalled, sponsored_bond::RECALLED_TOPIC));

    // It stops counting at once, and stays slashable while it unbonds.
    assert_eq!(staking::bonded_stake_of(&state, &VALIDATOR), OWN);
    assert_eq!(staking::sponsored_bond_of(&state, &VALIDATOR), 0);
    assert_eq!(
        staking::sponsored_unbonding_of(&state, &VALIDATOR),
        SPONSORED
    );
    assert_eq!(treasury(&state), TREASURY - SPONSORED);

    let release = |at_ms| {
        let mut data = SELECTOR_SPONSORED_BOND.to_vec();
        data.extend_from_slice(
            &serde_json::to_vec(&SponsoredBondOp::Release {
                validator: Address::new(VALIDATOR),
            })
            .unwrap(),
        );
        tx(&STRANGER, data, at_ms)
    };
    assert!(
        executor
            .execute_transaction(&release(at + 1), &mut state)
            .await
            .is_err(),
        "nothing returns before the unbonding period has passed"
    );
    let matured = at + network_param(&state, staking::UNBONDING_PARAM) as i64 + 1;
    let released = executor
        .execute_transaction(&release(matured), &mut state)
        .await
        .expect("anyone may return matured sponsored stake");
    assert!(has_topic(&released, sponsored_bond::RETURNED_TOPIC));

    assert_eq!(treasury(&state), TREASURY);
    assert_eq!(staking::sponsored_unbonding_of(&state, &VALIDATOR), 0);
    assert_eq!(staking::bonded_stake_of(&state, &VALIDATOR), OWN);
    assert_eq!(state.get_balance(&VALIDATOR), GAS_BALANCE);
    assert_eq!(staking::total_sponsored_outstanding(&state), 0);
}

#[test]
fn an_exiting_validator_is_paid_its_own_bond_and_the_sponsored_part_returns_to_the_treasury() {
    let mut state = chain();
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    sponsored_bond::sponsor_bond(
        &mut state,
        "proposal",
        &VALIDATOR,
        SPONSORED,
        0,
        &mut changes,
        &mut logs,
    )
    .unwrap();
    staking::begin_unbonding(&mut state, &VALIDATOR, 1).unwrap();
    assert_eq!(
        staking::sponsored_unbonding_of(&state, &VALIDATOR),
        SPONSORED
    );
    let matured = 1 + network_param(&state, staking::UNBONDING_PARAM) as i64;
    let (paid, returned) =
        staking::withdraw_unbonded_split(&mut state, &VALIDATOR, &VALIDATOR, matured).unwrap();
    assert_eq!((paid, returned), (OWN, SPONSORED));
    assert_eq!(state.get_balance(&VALIDATOR), GAS_BALANCE + OWN);
    assert_eq!(treasury(&state), TREASURY);
}

/// Two validators with the same stake at risk, one all its own, one half
/// sponsored, slashed at the same rate: the same amount goes to the
/// insurance pool, and the sponsored lien shrinks in proportion.
#[test]
fn a_slash_takes_the_sponsored_part_into_the_pool_exactly_as_an_own_bond() {
    let mut state = chain();
    let solo: [u8; 32] = [0x0d; 32];
    validator(&mut state, &solo, OWN + SPONSORED);
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    sponsored_bond::sponsor_bond(
        &mut state,
        "proposal",
        &VALIDATOR,
        SPONSORED,
        0,
        &mut changes,
        &mut logs,
    )
    .unwrap();

    let pool = derive_insurance_pool_address();
    let before = state.get_balance(pool.as_bytes());
    let own_slash = staking::slash_to_insurance(
        &mut state,
        &solo,
        SlashedStake::Validator,
        1_000,
        &mut changes,
    )
    .unwrap();
    let mid = state.get_balance(pool.as_bytes());
    let sponsored_slash = staking::slash_to_insurance(
        &mut state,
        &VALIDATOR,
        SlashedStake::Validator,
        1_000,
        &mut changes,
    )
    .unwrap();
    let after = state.get_balance(pool.as_bytes());

    assert_eq!(own_slash, sponsored_slash);
    assert_eq!(mid - before, own_slash);
    assert_eq!(after - mid, sponsored_slash);
    assert_eq!(
        staking::bonded_stake_of(&state, &VALIDATOR),
        staking::bonded_stake_of(&state, &solo)
    );
    // Ten percent of each part.
    assert_eq!(
        staking::sponsored_bond_of(&state, &VALIDATOR),
        SPONSORED / 10 * 9
    );
    assert_eq!(
        staking::own_bonded_stake_of(&state, &VALIDATOR),
        OWN / 10 * 9
    );

    // What is left of the sponsorship is all that returns.
    let mut logs = Vec::new();
    sponsored_bond::recall_bond(&mut state, &VALIDATOR, SPONSORED / 10 * 9, 10, &mut logs).unwrap();
    // A slash while it unbonds still reaches it.
    let unbonding_slash = staking::slash_to_insurance(
        &mut state,
        &VALIDATOR,
        SlashedStake::Validator,
        1_000,
        &mut changes,
    )
    .unwrap();
    assert!(unbonding_slash > 0);
    let lien = staking::sponsored_unbonding_of(&state, &VALIDATOR);
    assert_eq!(lien, SPONSORED / 10 * 9 / 10 * 9);
    let matured = 10 + network_param(&state, staking::UNBONDING_PARAM) as i64;
    let returned = staking::release_recalled(&mut state, &VALIDATOR, matured).unwrap();
    assert_eq!(returned, lien);
    assert_eq!(treasury(&state), TREASURY - SPONSORED + lien);
}

/// A sponsored bond never votes, never counts toward the quorum, and earns
/// and moves no reward: the reward engine reaches the same state for the
/// same work with or without it, and the treasury is issued nothing.
#[tokio::test]
async fn a_sponsored_bond_never_votes_earns_or_redirects_rewards() {
    use super::rewards;
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut plain = chain();
    let mut sponsored = chain();
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    // Sponsored well before the proposal opens, so it would have aged into
    // the vote if sponsored stake voted.
    sponsored_bond::sponsor_bond(
        &mut sponsored,
        "proposal",
        &VALIDATOR,
        SPONSORED,
        -2 * MIN_BOND_AGE_MS,
        &mut changes,
        &mut logs,
    )
    .unwrap();

    assert_eq!(
        staking::governance_total_bonded(&sponsored),
        staking::governance_total_bonded(&plain)
    );
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&recall_action(1)).unwrap());
    let created = executor
        .execute_transaction(&tx(&VOTER, data, 1_000), &mut sponsored)
        .await
        .unwrap();
    let proposal = load_proposal(&sponsored, &hex::encode(&created.output)).unwrap();
    assert_eq!(
        staking::vote_weight(&sponsored, &VALIDATOR, &proposal),
        OWN,
        "only the validator's own bond votes"
    );
    assert_eq!(
        load_tally(&sponsored, &proposal.ballot_id()).total_eligible,
        staking::governance_total_bonded(&plain)
    );

    for state in [&mut plain, &mut sponsored] {
        state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        let pool = tenzro_token::rewards::rewards_pool_address();
        state.set_balance(pool.as_bytes(), tenzro_token::rewards::NETWORK_REWARDS_POOL);
        super::economy::write_rate_for_tests(state, 1, 100_000_000, 100_000_000);
        for epoch in 0..4u64 {
            for (i, v) in [VOTER, VALIDATOR].iter().enumerate() {
                rewards::begin_block(
                    state,
                    epoch,
                    &Address::new(*v),
                    epoch as i64 * 86_400_000 + i as i64 * 1_000 + 5_000,
                )
                .unwrap();
            }
        }
    }
    let key = rewards::REWARD_STATE_KEY.as_bytes();
    assert_eq!(
        plain.get_storage(&SYSTEM_ADDRESS, key),
        sponsored.get_storage(&SYSTEM_ADDRESS, key),
        "the reward engine's state does not depend on a sponsored bond"
    );
    for who in [
        Address::new(VALIDATOR),
        Address::new(VOTER),
        derive_treasury_address(),
    ] {
        assert_eq!(
            rewards::read_coupons(&plain, &who).unwrap(),
            rewards::read_coupons(&sponsored, &who).unwrap()
        );
    }
    assert!(
        rewards::read_coupons(&sponsored, &derive_treasury_address())
            .unwrap()
            .is_empty()
    );
}

/// Every path, sponsoring, slashing a sponsored bond, recalling, returning,
/// sponsoring again, exiting and withdrawing, moves TNZO between accounts
/// and never creates or destroys any.
#[test]
fn no_sponsored_bond_path_changes_the_supply() {
    let mut state = chain();
    let accounts: Vec<Vec<u8>> = vec![
        derive_treasury_address().as_bytes().to_vec(),
        STAKING_VAULT_ADDRESS.to_vec(),
        derive_insurance_pool_address().as_bytes().to_vec(),
        VALIDATOR.to_vec(),
        VOTER.to_vec(),
    ];
    let supply = |s: &StateAdapter| accounts.iter().map(|a| s.get_balance(a)).sum::<u128>();
    let start = supply(&state);
    let period = network_param(&state, staking::UNBONDING_PARAM) as i64;
    let mut changes = Vec::new();
    let mut logs = Vec::new();

    assert!(state.begin_transaction());
    sponsored_bond::sponsor_bond(
        &mut state,
        "proposal",
        &VALIDATOR,
        SPONSORED,
        0,
        &mut changes,
        &mut logs,
    )
    .unwrap();
    assert_eq!(supply(&state), start);
    staking::slash_to_insurance(
        &mut state,
        &VALIDATOR,
        SlashedStake::Validator,
        2_500,
        &mut changes,
    )
    .unwrap();
    assert_eq!(supply(&state), start);
    let left = staking::sponsored_bond_of(&state, &VALIDATOR);
    sponsored_bond::recall_bond(&mut state, &VALIDATOR, left / 2, 1, &mut logs).unwrap();
    assert_eq!(supply(&state), start);
    staking::release_recalled(&mut state, &VALIDATOR, 1 + period).unwrap();
    assert_eq!(supply(&state), start);
    sponsored_bond::sponsor_bond(
        &mut state,
        "proposal",
        &VALIDATOR,
        SPONSORED / 4,
        2 + period,
        &mut changes,
        &mut logs,
    )
    .unwrap();
    staking::begin_unbonding(&mut state, &VALIDATOR, 3 + period).unwrap();
    staking::slash_to_insurance(
        &mut state,
        &VALIDATOR,
        SlashedStake::Validator,
        500,
        &mut changes,
    )
    .unwrap();
    staking::withdraw_unbonded_split(&mut state, &VALIDATOR, &VALIDATOR, 3 + 2 * period).unwrap();
    assert_eq!(supply(&state), start);
    let delta = state.journal_balance_delta();
    state.commit_transaction();
    assert_eq!(delta, Some(0), "TNZO was created or destroyed");

    assert_eq!(staking::total_sponsored_outstanding(&state), 0);
    assert_eq!(staking::sponsored_bond_of(&state, &VALIDATOR), 0);
    assert_eq!(
        state.get_balance(&STAKING_VAULT_ADDRESS),
        staking::vault_liabilities(&state),
        "the vault holds exactly what it owes"
    );
}
