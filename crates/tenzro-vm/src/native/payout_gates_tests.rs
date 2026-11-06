//! The governance gates on sponsorship and grants: a payout goes only to an
//! approved recipient and only against verified availability or an approved
//! milestone, within the governed yearly caps and the treasury outflow
//! caps, one governance proposal at a time; every cap starts at zero and
//! nothing is issued.

use super::availability_reward;
use super::payout_gates::{
    self, COMBINED_YEARLY_PARAM, GRANTEE_YEARLY_PARAM, PAYOUT_TOPIC, PER_VERIFIED_EPOCH_PARAM,
    SPONSORSHIP_YEARLY_PARAM,
};
use super::sponsored_bond::{MAX_PER_VALIDATOR_PARAM, MAX_TOTAL_PARAM};
use super::staking;
use super::*;
use crate::governance::{
    GrantVesting, GranteeClass, GranteeCriteria, MIN_BOND_AGE_MS, OperatorClass, OperatorCriteria,
    ProposalAction, TIMELOCK_DELAY_MS, VOTING_PERIOD_MS,
};
use crate::state_adapter::StateAdapter;
use tenzro_types::primitives::Address;

const TNZO: u128 = tenzro_types::constants::ONE_TNZO;
const GAS_BALANCE: u128 = 10_000_000_000_000_000_000;
const TREASURY: u128 = 10_000_000 * TNZO;
const VOTER: [u8; 32] = [0x0a; 32];
const OP_A: u8 = 21;
const GRANTEE_A: [u8; 32] = [0x31; 32];
const GRANTEE_B: [u8; 32] = [0x32; 32];
const YEAR_MS: i64 = 365 * 24 * 60 * 60 * 1000;
/// The first proposal's time, after the test endorsement certificate's
/// validity begins.
const BASE_MS: i64 = 1_800_000_000_000;
/// Spacing between proposals: past the voting period, the timelock and any
/// per-proposer pacing.
const STEP_MS: i64 = 40 * 24 * 60 * 60 * 1000;

fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
    set_governed_param_for_test(state, key, value);
}

fn registered_validator(state: &mut StateAdapter, who: &[u8], own: u128) {
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

/// A funded treasury, a large voting validator and an identity for each
/// grantee. No cap is set: the genesis zeros are in force.
fn chain() -> StateAdapter {
    let mut state = StateAdapter::new();
    state.set_balance(derive_treasury_address().as_bytes(), TREASURY);
    registered_validator(&mut state, &VOTER, 1_000_000 * TNZO);
    for (i, g) in [GRANTEE_A, GRANTEE_B].iter().enumerate() {
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(g).as_bytes(),
            format!("did:tenzro:human:grantee{i}").into_bytes(),
        );
    }
    state
}

/// A validator whose machine identity holds a TPM endorsement a recognised
/// root signs.
fn endorsed_validator(state: &mut StateAdapter, seed: u8, own: u128) -> (Address, String) {
    let did = availability_reward::tests::register_endorsed_machine(state, seed);
    let account = [seed; 32];
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(&account).as_bytes(),
        did.clone().into_bytes(),
    );
    registered_validator(state, &account, own);
    (Address::new(account), did)
}

/// Freeze an available verdict for `did` in each of `epochs`.
fn verified(state: &mut StateAdapter, did: &str, epochs: std::ops::RangeInclusive<u64>, up: bool) {
    for epoch in epochs {
        let verdict = SlaVerdict {
            available: up,
            up_stake: 100,
            down_stake: 0,
            attesters: 1,
            measured_capacity: None,
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            format!("sla:{}", sla_bucket(did, epoch)).as_bytes(),
            serde_json::to_vec(&verdict).unwrap(),
        );
    }
}

fn criteria(did: &str, from: u64, to: u64) -> OperatorCriteria {
    OperatorCriteria {
        provider_did: did.to_string(),
        region: "eu-west".into(),
        history_from_epoch: from,
        history_to_epoch: to,
        independence: "operated by a separate legal entity on its own hardware".into(),
        link: "https://example.org/criteria".into(),
    }
}

fn approve_operator(account: Address, did: &str, from: u64, to: u64) -> ProposalAction {
    ProposalAction::ApproveOperator {
        operator: account,
        class: OperatorClass::Validator,
        criteria: criteria(did, from, to),
        memo: "meets the published criteria".into(),
    }
}

fn approve_grantee(who: [u8; 32], class: GranteeClass) -> ProposalAction {
    ProposalAction::ApproveGrantee {
        grantee: Address::new(who),
        class,
        criteria: GranteeCriteria {
            summary: "builds an application on the network".into(),
            link: "https://example.org/grantee".into(),
        },
        memo: "meets the published criteria".into(),
    }
}

fn grant(who: [u8; 32], amount: u128, tranches: Vec<u128>) -> ProposalAction {
    let milestones = (0..tranches.len().max(1))
        .map(|i| format!("milestone {i}"))
        .collect();
    ProposalAction::TreasuryGrant {
        recipient: Address::new(who),
        amount,
        memo: "grant".into(),
        category: "development".into(),
        link: String::new(),
        tranches,
        milestones,
        vesting: GrantVesting::Liquid,
        asset: None,
        release: crate::governance::GrantRelease::Governed,
    }
}

fn running_cost(account: Address, from: u64, to: u64, amount: u128) -> ProposalAction {
    ProposalAction::SponsorOperatorRunningCost {
        operator: account,
        from_epoch: from,
        to_epoch: to,
        amount,
        memo: "running cost for verified hours".into(),
    }
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

/// Propose `action` at `at_ms`, vote it through, queue and enact it. `Err`
/// names the step that refused it.
async fn try_enact(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    action: &ProposalAction,
    at_ms: i64,
) -> std::result::Result<ExecutionResult, String> {
    let at_ms = at_ms + BASE_MS;
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(action).unwrap());
    let created = executor
        .execute_transaction(&tx(&VOTER, data, at_ms), state)
        .await
        .map_err(|e| format!("propose: {e}"))?;
    if !created.success {
        return Err("propose: unsuccessful".into());
    }
    let id = created.output.clone();
    executor
        .execute_transaction(
            &tx(&VOTER, test_vote_data(&id, true, &VOTER), at_ms + 10),
            state,
        )
        .await
        .map_err(|e| format!("vote: {e}"))?;
    let mut exec = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
    exec.extend_from_slice(&id);
    let queued = at_ms + VOTING_PERIOD_MS + 1;
    executor
        .execute_transaction(&tx(&VOTER, exec.clone(), queued), state)
        .await
        .map_err(|e| format!("queue: {e}"))?;
    // A stable payout is a large spend for the vote and waits out the long
    // timelock.
    let long = matches!(
        action,
        ProposalAction::SponsorOperatorStable { .. }
            | ProposalAction::TreasuryGrant { asset: Some(_), .. }
    );
    let lock = if long {
        crate::governance::LARGE_SPEND_TIMELOCK_MS
    } else {
        TIMELOCK_DELAY_MS
    };
    let enacted = queued + lock + 1;
    let result = executor
        .execute_transaction(&tx(&VOTER, exec, enacted), state)
        .await
        .map_err(|e| format!("enact: {e}"))?;
    if !result.success {
        return Err("enact: unsuccessful".into());
    }
    Ok(result)
}

async fn enact_ok(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    action: &ProposalAction,
    at_ms: i64,
) -> ExecutionResult {
    try_enact(executor, state, action, at_ms)
        .await
        .unwrap_or_else(|e| panic!("{} should enact: {e}", action.kind()))
}

async fn refused(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    action: &ProposalAction,
    at_ms: i64,
    why: &str,
) {
    match try_enact(executor, state, action, at_ms).await {
        Ok(_) => panic!("{} should be refused", action.kind()),
        Err(e) => assert!(
            e.contains(why),
            "{} was refused, but not for {why:?}: {e}",
            action.kind()
        ),
    }
}

fn treasury(state: &StateAdapter) -> u128 {
    state.get_balance(derive_treasury_address().as_bytes())
}

fn payouts(result: &ExecutionResult) -> Vec<payout_gates::PayoutRecord> {
    result
        .logs
        .iter()
        .filter(|l| l.topics.first().map(Vec::as_slice) == Some(PAYOUT_TOPIC))
        .map(|l| serde_json::from_slice(&l.data).unwrap())
        .collect()
}

/// Open every cap so a test can reach the gate it is about.
fn open_caps(state: &mut StateAdapter) {
    set_param(state, SPONSORSHIP_YEARLY_PARAM, 900_000);
    set_param(state, GRANTEE_YEARLY_PARAM, 100_000);
    set_param(state, COMBINED_YEARLY_PARAM, 1_000_000);
    set_param(state, PER_VERIFIED_EPOCH_PARAM, 1_000_000_000_000_000_000);
    set_param(state, MAX_PER_VALIDATOR_PARAM, 100_000);
    set_param(state, MAX_TOTAL_PARAM, 1_000_000);
}

#[test]
fn every_cap_starts_at_zero_and_is_governed() {
    let state = StateAdapter::new();
    for key in [
        SPONSORSHIP_YEARLY_PARAM,
        PER_VERIFIED_EPOCH_PARAM,
        GRANTEE_YEARLY_PARAM,
        COMBINED_YEARLY_PARAM,
        MAX_PER_VALIDATOR_PARAM,
        MAX_TOTAL_PARAM,
    ] {
        let param = crate::governance::governed_param(key)
            .unwrap_or_else(|| panic!("{key} is not a governed parameter"));
        assert_eq!(param.genesis, 0, "{key} starts disabled");
        assert_eq!(network_param(&state, key), 0, "{key} reads zero at genesis");
    }
}

#[tokio::test]
async fn a_bond_is_sponsored_only_for_an_approved_operator() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=5, true);
    let sponsor = ProposalAction::SponsorValidatorBond {
        validator: account,
        amount: 50_000 * TNZO,
        memo: "bond cover".into(),
    };

    // A registered validator with a live bond and open caps, not approved.
    refused(
        &executor,
        &mut state,
        &sponsor,
        STEP_MS,
        "not an approved operator",
    )
    .await;
    assert_eq!(treasury(&state), TREASURY);

    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 5),
        2 * STEP_MS,
    )
    .await;
    let record = payout_gates::operator_approval(&state, account.as_bytes()).unwrap();
    assert!(record.hardware_attested);
    assert_eq!(record.verified_epochs, 5);
    assert_eq!(record.criteria.region, "eu-west");
    assert!(!record.revoked);

    let result = enact_ok(&executor, &mut state, &sponsor, 3 * STEP_MS).await;
    let records = payouts(&result);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, "validator");
    assert_eq!(records[0].kind, "bond_sponsorship");
    assert_eq!(records[0].amount, 50_000 * TNZO);
    assert_eq!(treasury(&state), TREASURY - 50_000 * TNZO);

    // Revoked: the next sponsorship is refused at once.
    enact_ok(
        &executor,
        &mut state,
        &ProposalAction::RevokeOperator {
            operator: account,
            memo: "no longer meets the criteria".into(),
        },
        4 * STEP_MS,
    )
    .await;
    let again = ProposalAction::SponsorValidatorBond {
        validator: account,
        amount: 10 * TNZO,
        memo: "more".into(),
    };
    refused(&executor, &mut state, &again, 5 * STEP_MS, "revoked").await;
}

#[tokio::test]
async fn an_operator_is_approved_only_with_hardware_attestation_and_verified_availability() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);

    // No verified-available hour in the history named.
    refused(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 5),
        STEP_MS,
        "no verified-available hour",
    )
    .await;
    // Unavailable hours do not count.
    verified(&mut state, &did, 1..=5, false);
    refused(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 5),
        2 * STEP_MS,
        "no verified-available hour",
    )
    .await;
    verified(&mut state, &did, 3..=3, true);

    // An account that is not the machine identity named.
    refused(
        &executor,
        &mut state,
        &approve_operator(Address::new([0x77; 32]), &did, 1, 5),
        3 * STEP_MS,
        "is not the account of",
    )
    .await;

    // A machine identity with no TPM endorsement.
    let bare = [0x66u8; 32];
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(&bare).as_bytes(),
        b"did:tenzro:machine:bare".to_vec(),
    );
    verified(&mut state, "did:tenzro:machine:bare", 1..=5, true);
    refused(
        &executor,
        &mut state,
        &approve_operator(Address::new(bare), "did:tenzro:machine:bare", 1, 5),
        4 * STEP_MS,
        "hardware attestation",
    )
    .await;

    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 5),
        5 * STEP_MS,
    )
    .await;
    assert_eq!(
        payout_gates::operator_approval(&state, account.as_bytes())
            .unwrap()
            .verified_epochs,
        1
    );
}

#[tokio::test]
async fn running_cost_is_paid_only_against_unused_verified_hours() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=3, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 3),
        STEP_MS,
    )
    .await;
    let before = state.get_balance(account.as_bytes());

    // Hours 10 to 20 were never judged available: nothing is paid.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 10, 20, TNZO),
        2 * STEP_MS,
        "nothing is paid without verified work",
    )
    .await;
    // Hours judged unavailable do not back a payment either.
    verified(&mut state, &did, 10..=20, false);
    refused(
        &executor,
        &mut state,
        &running_cost(account, 10, 20, TNZO),
        3 * STEP_MS,
        "nothing is paid without verified work",
    )
    .await;
    // Three verified hours at one TNZO back at most three TNZO.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, 3 * TNZO + 1),
        4 * STEP_MS,
        "verified hours back at most",
    )
    .await;
    assert_eq!(state.get_balance(account.as_bytes()), before);
    assert_eq!(treasury(&state), TREASURY);

    // Two and a half hours' worth uses three hours.
    let result = enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, 5 * TNZO / 2),
        5 * STEP_MS,
    )
    .await;
    assert_eq!(state.get_balance(account.as_bytes()), before + 5 * TNZO / 2);
    assert_eq!(treasury(&state), TREASURY - 5 * TNZO / 2);
    let records = payouts(&result);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].kind, "running_cost");
    assert_eq!(records[0].class, "validator");
    assert!(records[0].milestone.contains("3 verified-available hours"));

    // The same hours cannot back a second payment.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, TNZO),
        6 * STEP_MS,
        "nothing is paid without verified work",
    )
    .await;
}

#[tokio::test]
async fn running_cost_needs_a_current_approval_and_a_set_rate() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=3, true);

    // Verified hours, but never approved.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, TNZO),
        STEP_MS,
        "not an approved operator",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 3),
        2 * STEP_MS,
    )
    .await;
    // Rate at its genesis zero.
    set_param(&mut state, PER_VERIFIED_EPOCH_PARAM, 0);
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, TNZO),
        3 * STEP_MS,
        "running-cost sponsorship is disabled",
    )
    .await;
    set_param(
        &mut state,
        PER_VERIFIED_EPOCH_PARAM,
        1_000_000_000_000_000_000,
    );
    enact_ok(
        &executor,
        &mut state,
        &ProposalAction::RevokeOperator {
            operator: account,
            memo: "revoked".into(),
        },
        4 * STEP_MS,
    )
    .await;
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 3, TNZO),
        5 * STEP_MS,
        "revoked",
    )
    .await;
}

#[tokio::test]
async fn one_operator_receives_at_most_a_third_of_the_yearly_sponsorship() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    set_param(&mut state, SPONSORSHIP_YEARLY_PARAM, 300);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=400, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 400),
        STEP_MS,
    )
    .await;
    // A third of 300 TNZO is 100.
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 100, 100 * TNZO),
        2 * STEP_MS,
    )
    .await;
    refused(
        &executor,
        &mut state,
        &running_cost(account, 101, 102, 1),
        3 * STEP_MS,
        "one third",
    )
    .await;
    // The next year opens a fresh third.
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 101, 102, 2 * TNZO),
        2 * STEP_MS + YEAR_MS,
    )
    .await;
}

#[tokio::test]
async fn sponsorship_stops_at_the_treasury_outflow_caps() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    // 1,000 TNZO in the treasury: 2% a proposal is 20, 3% a period is 30.
    state.set_balance(derive_treasury_address().as_bytes(), 1_000 * TNZO);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=100, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 100),
        STEP_MS,
    )
    .await;
    // Over the per-proposal share.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 1, 25, 21 * TNZO),
        2 * STEP_MS,
        "a proposal may pay at most",
    )
    .await;
    // Inside the per-proposal share, twice: 15 and 15 fill the 30 of the period.
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 15, 15 * TNZO),
        3 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 16, 30, 15 * TNZO),
        3 * STEP_MS + 2 * VOTING_PERIOD_MS,
    )
    .await;
    // The period is spent.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 31, 32, 2 * TNZO),
        3 * STEP_MS + 4 * VOTING_PERIOD_MS,
        "may pay out",
    )
    .await;
}

#[tokio::test]
async fn a_grant_goes_only_to_an_approved_grantee_within_the_caps() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let one = grant(GRANTEE_A, 1_000 * TNZO, Vec::new());

    // Not approved.
    refused(
        &executor,
        &mut state,
        &one,
        STEP_MS,
        "not an approved grantee",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        2 * STEP_MS,
    )
    .await;
    // Approved, caps at their genesis zero.
    refused(
        &executor,
        &mut state,
        &one,
        3 * STEP_MS,
        "grants are disabled",
    )
    .await;

    open_caps(&mut state);
    let result = enact_ok(&executor, &mut state, &one, 4 * STEP_MS).await;
    assert_eq!(state.get_balance(&GRANTEE_A), 1_000 * TNZO);
    assert_eq!(treasury(&state), TREASURY - 1_000 * TNZO);
    let records = payouts(&result);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, "developer");
    assert_eq!(records[0].kind, "grant");
    assert_eq!(records[0].recipient, hex::encode(GRANTEE_A));
    assert_eq!(records[0].amount, 1_000 * TNZO);
    assert_eq!(records[0].milestone, "milestone 0");
}

#[tokio::test]
async fn a_grant_names_a_milestone_for_each_payment() {
    let mut no_milestone = grant(GRANTEE_A, 100 * TNZO, vec![60 * TNZO, 40 * TNZO]);
    if let ProposalAction::TreasuryGrant { milestones, .. } = &mut no_milestone {
        milestones.pop();
    }
    assert!(
        no_milestone.validate().is_err(),
        "one milestone for two tranches"
    );
    let mut blank = grant(GRANTEE_A, 100 * TNZO, Vec::new());
    if let ProposalAction::TreasuryGrant { milestones, .. } = &mut blank {
        milestones[0] = "  ".into();
    }
    assert!(blank.validate().is_err(), "a blank milestone");
    assert!(
        grant(GRANTEE_A, 100 * TNZO, vec![60 * TNZO, 40 * TNZO])
            .validate()
            .is_ok()
    );
}

#[tokio::test]
async fn each_tranche_is_released_by_its_own_proposal_and_stops_when_the_grantee_is_revoked() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Contributor),
        STEP_MS,
    )
    .await;
    let three = grant(
        GRANTEE_A,
        300 * TNZO,
        vec![100 * TNZO, 100 * TNZO, 100 * TNZO],
    );
    let result = enact_ok(&executor, &mut state, &three, 2 * STEP_MS).await;
    // Only the first milestone is met by this vote.
    assert_eq!(state.get_balance(&GRANTEE_A), 100 * TNZO);
    assert_eq!(payouts(&result)[0].class, "contributor");
    let grant_id = payouts(&result)[0].proposal_id.clone();
    let release = |index: u32| ProposalAction::ReleaseGrantTranche {
        grant_id: grant_id.clone(),
        index,
        memo: "audit report accepted".into(),
    };
    // Out of order.
    refused(&executor, &mut state, &release(2), 3 * STEP_MS, "is next").await;
    let second = enact_ok(&executor, &mut state, &release(1), 4 * STEP_MS).await;
    assert_eq!(state.get_balance(&GRANTEE_A), 200 * TNZO);
    let records = payouts(&second);
    assert_eq!(records[0].milestone, "milestone 1");
    assert_eq!(records[0].class, "contributor");

    // Revoked before the last milestone: nothing more is paid.
    enact_ok(
        &executor,
        &mut state,
        &ProposalAction::RevokeGrantee {
            grantee: Address::new(GRANTEE_A),
            memo: "stopped delivering".into(),
        },
        5 * STEP_MS,
    )
    .await;
    refused(&executor, &mut state, &release(2), 6 * STEP_MS, "revoked").await;
    assert_eq!(state.get_balance(&GRANTEE_A), 200 * TNZO);
}

#[tokio::test]
async fn a_grantee_yearly_cap_and_the_combined_cap_bind_everyone_alike() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    set_param(&mut state, GRANTEE_YEARLY_PARAM, 1_000);
    set_param(&mut state, COMBINED_YEARLY_PARAM, 1_500);
    for who in [GRANTEE_A, GRANTEE_B] {
        enact_ok(
            &executor,
            &mut state,
            &approve_grantee(who, GranteeClass::Developer),
            STEP_MS,
        )
        .await;
    }
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 1_000 * TNZO, Vec::new()),
        2 * STEP_MS,
    )
    .await;
    // The same grantee, one more unit over its cap.
    refused(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 1, Vec::new()),
        3 * STEP_MS,
        "one grantee may receive",
    )
    .await;
    // Another grantee is inside its own cap and over the combined cap.
    refused(
        &executor,
        &mut state,
        &grant(GRANTEE_B, 501 * TNZO, Vec::new()),
        4 * STEP_MS,
        "together",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_B, 500 * TNZO, Vec::new()),
        5 * STEP_MS,
    )
    .await;
    // The caps are per 365-day period.
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 1_000 * TNZO, Vec::new()),
        5 * STEP_MS + YEAR_MS,
    )
    .await;
}

#[tokio::test]
async fn sponsorship_and_grants_share_one_combined_yearly_cap() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    set_param(&mut state, COMBINED_YEARLY_PARAM, 150);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=200, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 200),
        STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Community),
        2 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 100, 100 * TNZO),
        3 * STEP_MS,
    )
    .await;
    // 100 of the 150 is spent on sponsorship: a 51 TNZO grant is over.
    refused(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 51 * TNZO, Vec::new()),
        4 * STEP_MS,
        "together",
    )
    .await;
    let result = enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 50 * TNZO, Vec::new()),
        5 * STEP_MS,
    )
    .await;
    assert_eq!(payouts(&result)[0].class, "community");
    // And sponsorship is now over the combined cap too.
    refused(
        &executor,
        &mut state,
        &running_cost(account, 101, 102, TNZO),
        6 * STEP_MS,
        "together",
    )
    .await;
}

#[tokio::test]
async fn the_payout_report_names_every_recipient_amount_and_class() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=10, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 10),
        STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        2 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_B, GranteeClass::Contributor),
        3 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 40 * TNZO, Vec::new()),
        4 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_B, 25 * TNZO, Vec::new()),
        5 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 10, 7 * TNZO),
        6 * STEP_MS,
    )
    .await;

    let report = payout_gates::payout_report(&state, 0, 100);
    assert_eq!(report.count, 3);
    assert_eq!(report.records.len(), 3);
    assert_eq!(report.by_class["developer"], (40 * TNZO).to_string());
    assert_eq!(report.by_class["contributor"], (25 * TNZO).to_string());
    assert_eq!(report.by_class["validator"], (7 * TNZO).to_string());
    assert_eq!(report.by_class["provider"], "0");
    assert_eq!(payout_gates::recipient_total(&state, &GRANTEE_A), 40 * TNZO);
    assert_eq!(payout_gates::recipient_total(&state, &GRANTEE_B), 25 * TNZO);
    assert_eq!(
        payout_gates::recipient_total(&state, account.as_bytes()),
        7 * TNZO
    );
    // A page.
    let page = payout_gates::payout_report(&state, 1, 1);
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].n, 1);
}

#[tokio::test]
async fn no_sponsorship_or_grant_path_changes_the_supply() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=10, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 10),
        STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        2 * STEP_MS,
    )
    .await;
    // Gas moves value between accounts the sum above leaves out, so measure
    // the treasury against the recipients it paid.
    let treasury_before = treasury(&state);
    let operator_before = state.get_balance(account.as_bytes());
    let grantee_before = state.get_balance(&GRANTEE_A);
    enact_ok(
        &executor,
        &mut state,
        &running_cost(account, 1, 10, 6 * TNZO),
        3 * STEP_MS,
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &grant(GRANTEE_A, 9 * TNZO, vec![4 * TNZO, 5 * TNZO]),
        4 * STEP_MS,
    )
    .await;
    let paid_out = treasury_before - treasury(&state);
    assert_eq!(paid_out, 6 * TNZO + 4 * TNZO);
    assert_eq!(
        state.get_balance(account.as_bytes()) - operator_before + state.get_balance(&GRANTEE_A)
            - grantee_before,
        paid_out,
        "everything the treasury paid out is held by the recipients"
    );
}

#[tokio::test]
async fn a_proposal_can_change_the_launch_rate_before_the_validator_median_takes_over() {
    use super::economy::{GOVERNANCE_RATE_PARAM, RATE_MODE_PARAM, read_fee_rate, usd_to_wei};
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let launch = read_fee_rate(&state);
    assert_eq!(launch.mode, "governance", "mode 0 at genesis");
    assert_eq!(
        launch.rate_nano_usd,
        u128::from(economy::DEFAULT_TNZO_USD_NANO)
    );
    let before = usd_to_wei(&state, 1_000_000_000_000_000_000);

    let change = ProposalAction::ParameterChange {
        key: GOVERNANCE_RATE_PARAM.into(),
        value: 250_000_000,
        memo: "launch rate".into(),
    };
    enact_ok(&executor, &mut state, &change, STEP_MS).await;
    // Enacted for the next epoch: the rate in force does not move mid-epoch.
    let pending = pending_param(&state, GOVERNANCE_RATE_PARAM).expect("scheduled");
    assert_eq!(pending.value, 250_000_000);
    assert_eq!(read_fee_rate(&state).rate_nano_usd, launch.rate_nano_usd);
    begin_block_params(&mut state, pending.activates_epoch).unwrap();
    let after = read_fee_rate(&state);
    assert_eq!(after.mode, "governance");
    assert_eq!(after.rate_nano_usd, 250_000_000);
    assert_ne!(usd_to_wei(&state, 1_000_000_000_000_000_000), before);

    // A later vote hands the rate to the validator median, which starts from
    // the governance rate until its first epoch is frozen.
    let hand_over = ProposalAction::ParameterChange {
        key: RATE_MODE_PARAM.into(),
        value: 1,
        memo: "validator median".into(),
    };
    enact_ok(&executor, &mut state, &hand_over, 2 * STEP_MS).await;
    let pending = pending_param(&state, RATE_MODE_PARAM).expect("scheduled");
    begin_block_params(&mut state, pending.activates_epoch).unwrap();
    let handed = read_fee_rate(&state);
    assert_eq!(handed.mode, "validators");
    assert_eq!(handed.rate_nano_usd, 250_000_000);
}

#[tokio::test]
async fn a_recipient_without_an_identity_cannot_be_approved() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    refused(
        &executor,
        &mut state,
        &approve_grantee([0x55; 32], GranteeClass::Developer),
        STEP_MS,
        "no registered identity",
    )
    .await;
}

// ---------------------------------------------------------------------
// The reserve payment, unowned-funds recovery, the stable-asset path and
// scheduled grant release.
// ---------------------------------------------------------------------

use super::funding::{MILESTONE_VERIFIED_TOPIC, SELECTOR_FUNDING};
use super::stable_payout::PROPOSAL_EXCEPTION_PARAM;
use crate::funding::FundingOp;
use crate::governance::GrantRelease;

fn reserve_payment(account: Address, from: u64, to: u64, amount: u128) -> ProposalAction {
    ProposalAction::RunningCostPayment {
        recipient: account,
        from_epoch: from,
        to_epoch: to,
        amount,
        memo: "running cost for verified hours".into(),
        link: "https://example.org/costs".into(),
    }
}

#[tokio::test]
async fn a_reserve_payment_goes_only_to_an_approved_operator_against_verified_hours() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=3, true);
    let pay = reserve_payment(account, 1, 3, 2 * TNZO);

    // A registered validator with open caps and verified hours, not approved.
    refused(
        &executor,
        &mut state,
        &pay,
        STEP_MS,
        "not an approved operator",
    )
    .await;

    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 3),
        2 * STEP_MS,
    )
    .await;
    // More than the verified hours back (three hours at one TNZO).
    refused(
        &executor,
        &mut state,
        &reserve_payment(account, 1, 3, 4 * TNZO),
        3 * STEP_MS,
        "verified hours back at most",
    )
    .await;
    // No verified hour in the range.
    refused(
        &executor,
        &mut state,
        &reserve_payment(account, 50, 52, TNZO),
        4 * STEP_MS,
        "no verified-available hour",
    )
    .await;

    let result = enact_ok(&executor, &mut state, &pay, 5 * STEP_MS).await;
    let records = payouts(&result);
    assert_eq!(records.len(), 1, "the payment logs a TreasuryPayout");
    assert_eq!(records[0].recipient, hex::encode(account.as_bytes()));
    assert_eq!(records[0].amount, 2 * TNZO);
    assert_eq!(records[0].class, "validator");
    assert!(records[0].milestone.contains("running-cost reserve"));
    assert_eq!(super::treasury_reserve::read_queue(&state).len(), 1);

    // The two hours it used are spent for any later payment.
    refused(
        &executor,
        &mut state,
        &reserve_payment(account, 1, 3, 2 * TNZO),
        6 * STEP_MS,
        "verified hours back at most",
    )
    .await;
}

#[tokio::test]
async fn a_reserve_payment_counts_against_the_yearly_caps_and_the_proposal_limit() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    state.set_balance(derive_treasury_address().as_bytes(), 1_000 * TNZO);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=100, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 100),
        STEP_MS,
    )
    .await;
    // 2% of the 1,000 TNZO treasury is the most one proposal may commit.
    refused(
        &executor,
        &mut state,
        &reserve_payment(account, 1, 30, 21 * TNZO),
        2 * STEP_MS,
        "a proposal may pay at most",
    )
    .await;
    // The yearly sponsorship cap closes the reserve route too.
    set_param(&mut state, SPONSORSHIP_YEARLY_PARAM, 30);
    refused(
        &executor,
        &mut state,
        &reserve_payment(account, 1, 30, 11 * TNZO),
        3 * STEP_MS,
        "one third",
    )
    .await;
}

fn vault() -> Address {
    vault_recovery_address()
}

#[tokio::test]
async fn unowned_funds_are_proven_against_the_books_and_return_to_the_treasury() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    let treasury_address = Address::from_bytes(derive_treasury_address().as_bytes()).unwrap();
    // 1,000 TNZO sit in the vault beyond what it owes validators.
    let held = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, held + 1_000 * TNZO);
    let recover = |from: Address, to: Address, amount: u128| ProposalAction::RecoverUnownedFunds {
        from,
        to,
        amount,
        memo: "vault surplus the books attribute to nobody".into(),
    };

    // The treasury is never a source: drawing on it is a payout, not a recovery.
    refused(
        &executor,
        &mut state,
        &recover(treasury_address, Address::new(GRANTEE_A), 10 * TNZO),
        STEP_MS,
        "owned",
    )
    .await;
    // A person is never the destination.
    refused(
        &executor,
        &mut state,
        &recover(vault(), Address::new(GRANTEE_A), 10 * TNZO),
        2 * STEP_MS,
        "return to the treasury",
    )
    .await;
    // More than the surplus: bonded stake is never recoverable.
    refused(
        &executor,
        &mut state,
        &recover(vault(), treasury_address, 1_001 * TNZO),
        3 * STEP_MS,
        "",
    )
    .await;

    let treasury_before = treasury(&state);
    let vault_before = state.get_balance(&STAKING_VAULT_ADDRESS);
    enact_ok(
        &executor,
        &mut state,
        &recover(vault(), treasury_address, 1_000 * TNZO),
        4 * STEP_MS,
    )
    .await;
    assert_eq!(
        state.get_balance(&STAKING_VAULT_ADDRESS),
        vault_before - 1_000 * TNZO
    );
    assert!(
        treasury(&state) >= treasury_before + 1_000 * TNZO - 10 * GAS_BALANCE,
        "the surplus moved to the treasury"
    );
    // No payout record: it was not a payout, and no outflow was counted.
    assert_eq!(payout_gates::payout_count(&state), 0);
}

// ----- the stable-asset path -----

/// The id the test token is issued under, found by issuing it once.
fn stable_token() -> [u8; 32] {
    static ID: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *ID.get_or_init(|| {
        let mut scratch = StateAdapter::new();
        issue_stable(&mut scratch, 5_000_000 * USD)
    })
}
const USD: u128 = 1_000_000;
const USD_PARAMS: [(&str, u64); 4] = [
    (payout_gates::SPONSORSHIP_YEARLY_USD_PARAM, 900_000),
    (payout_gates::GRANTEE_YEARLY_USD_PARAM, 100_000),
    (payout_gates::COMBINED_YEARLY_USD_PARAM, 1_000_000),
    // 20,000 dollars one verified hour backs.
    (payout_gates::PER_VERIFIED_EPOCH_USD_PARAM, 20_000_000_000),
];

fn stable_id() -> String {
    format!("0x{}", hex::encode(stable_token()))
}

/// Issue the test token to the treasury.
fn issue_stable(state: &mut StateAdapter, units: u128) -> [u8; 32] {
    let spec = crate::token_ledger::TokenRecord {
        name: "Test dollar".into(),
        symbol: "TUSD".into(),
        decimals: 6,
        total_supply: units,
        creator: Vec::new(),
        max_supply: None,
        powers: tenzro_types::token_policy::PowerManifest::NONE,
        policy: tenzro_types::token_policy::TokenPolicy::default(),
        council: None,
        reserve_backing: None,
        pending: None,
    };
    crate::token_ledger::create(
        state,
        derive_treasury_address().as_bytes(),
        &spec,
        &mut Vec::new(),
    )
    .unwrap()
}

/// The treasury holds `units` of a priced, on-peg USD token with six decimals.
fn stable_world(state: &mut StateAdapter, units: u128) {
    let id = issue_stable(state, units);
    assert_eq!(
        id,
        stable_token(),
        "the test token id is the one the entry names"
    );
    let asset =
        tenzro_types::settlement_asset::SettlementAsset::new(&stable_id(), "TUSD", "USD", 6);
    super::settlement_asset::install_for_test(state, &asset);
    super::economy::write_symbol_rate_for_tests(state, "TUSD", 1, 1_000_000_000);
    for (key, value) in USD_PARAMS {
        set_param(state, key, value);
    }
}

fn held(state: &StateAdapter, who: &[u8]) -> u128 {
    crate::token_ledger::balance(state, &stable_token(), who)
}

fn stable_cost(
    account: Address,
    from: u64,
    to: u64,
    dollars: u128,
    exception: bool,
) -> ProposalAction {
    ProposalAction::SponsorOperatorStable {
        operator: account,
        from_epoch: from,
        to_epoch: to,
        token_id: stable_id(),
        amount: dollars * USD,
        period_exception: exception,
        memo: "running cost sized in dollars".into(),
    }
}

#[tokio::test]
async fn a_stable_sponsorship_pays_dollars_to_an_approved_operator_for_verified_hours() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    stable_world(&mut state, 5_000_000 * USD);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=3, true);
    let treasury_tnzo = treasury(&state);

    // Not approved.
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 3, 100, false),
        STEP_MS,
        "not an approved operator",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 3),
        2 * STEP_MS,
    )
    .await;
    // Three verified hours back 60,000 dollars; more is refused.
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 3, 60_001, false),
        3 * STEP_MS,
        "verified hours back at most",
    )
    .await;
    // A depegged asset pays nothing.
    super::economy::write_symbol_rate_for_tests(&mut state, "TUSD", 2, 800_000_000);
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 3, 100, false),
        4 * STEP_MS,
        "peg",
    )
    .await;
    super::economy::write_symbol_rate_for_tests(&mut state, "TUSD", 3, 1_000_000_000);

    let result = enact_ok(
        &executor,
        &mut state,
        &stable_cost(account, 1, 3, 30_000, false),
        5 * STEP_MS,
    )
    .await;
    let records = payouts(&result);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].asset, stable_id());
    assert_eq!(records[0].usd_e6, 30_000 * USD);
    assert_eq!(records[0].amount, 30_000 * USD);
    assert_eq!(records[0].class, "validator");
    assert_eq!(held(&state, account.as_bytes()), 30_000 * USD);
    // Conservation: the asset moved between balances, none was issued, and
    // the treasury's TNZO did not move.
    assert_eq!(
        held(&state, derive_treasury_address().as_bytes()) + held(&state, account.as_bytes()),
        5_000_000 * USD
    );
    assert!(
        treasury(&state) <= treasury_tnzo,
        "no TNZO was minted to anyone"
    );
    assert_eq!(
        payout_gates::class_total_usd(&state, "validator"),
        30_000 * USD
    );
    assert_eq!(
        payout_gates::recipient_total_usd(&state, account.as_bytes()),
        30_000 * USD
    );
    assert_eq!(payout_gates::class_total(&state, "validator"), 0);

    // Two hours of the three are used; the same hours back no second payment.
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 3, 40_000, false),
        6 * STEP_MS,
        "verified hours back at most",
    )
    .await;
}

#[tokio::test]
async fn stable_payouts_obey_the_usd_caps_and_start_disabled() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    stable_world(&mut state, 5_000_000 * USD);
    for (key, _) in USD_PARAMS {
        assert_eq!(
            crate::governance::governed_param(key).unwrap().genesis,
            0,
            "{key} starts disabled"
        );
    }
    assert_eq!(
        crate::governance::governed_param(PROPOSAL_EXCEPTION_PARAM)
            .unwrap()
            .genesis,
        0
    );
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=10, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 10),
        STEP_MS,
    )
    .await;
    // The operator may take one third of the 900,000 dollar yearly cap.
    set_param(
        &mut state,
        payout_gates::SPONSORSHIP_YEARLY_USD_PARAM,
        90_000,
    );
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 5, 30_001, false),
        2 * STEP_MS,
        "one third",
    )
    .await;
    // Disabled again: a zero cap pays nothing.
    set_param(&mut state, payout_gates::SPONSORSHIP_YEARLY_USD_PARAM, 0);
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 5, 10, false),
        3 * STEP_MS,
        "disabled",
    )
    .await;
    set_param(
        &mut state,
        payout_gates::SPONSORSHIP_YEARLY_USD_PARAM,
        900_000,
    );
    // The TNZO caps are separate: closing them leaves stable sponsorship open.
    set_param(&mut state, SPONSORSHIP_YEARLY_PARAM, 0);
    enact_ok(
        &executor,
        &mut state,
        &stable_cost(account, 1, 5, 10, false),
        4 * STEP_MS,
    )
    .await;
}

#[tokio::test]
async fn the_stable_outflow_limit_binds_and_the_governed_exception_widens_one_payment() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    // 5,000,000 dollars held: 2% a proposal is 100,000 and 3% a period 150,000.
    stable_world(&mut state, 5_000_000 * USD);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=10, true);
    enact_ok(
        &executor,
        &mut state,
        &approve_operator(account, &did, 1, 10),
        STEP_MS,
    )
    .await;
    // Over the per-proposal share.
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 10, 100_001, false),
        2 * STEP_MS,
        "a proposal may pay at most",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &stable_cost(account, 1, 5, 90_000, false),
        3 * STEP_MS,
    )
    .await;
    // The period has 60,000 left.
    let second = stable_cost(account, 6, 10, 90_000, false);
    refused(
        &executor,
        &mut state,
        &second,
        3 * STEP_MS + 2 * VOTING_PERIOD_MS,
        "outflow period",
    )
    .await;
    // The exception is zero at genesis: asking for it changes nothing.
    let flagged = stable_cost(account, 6, 10, 90_000, true);
    refused(
        &executor,
        &mut state,
        &flagged,
        3 * STEP_MS + 4 * VOTING_PERIOD_MS,
        "outflow period",
    )
    .await;
    // Governance grants one percent of the opening value as headroom: only
    // the payment that asks for it may use it.
    set_param(&mut state, PROPOSAL_EXCEPTION_PARAM, 100);
    refused(
        &executor,
        &mut state,
        &second,
        3 * STEP_MS + 6 * VOTING_PERIOD_MS,
        "outflow period",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &flagged,
        3 * STEP_MS + 8 * VOTING_PERIOD_MS,
    )
    .await;
    assert_eq!(held(&state, account.as_bytes()), 180_000 * USD);
    // The exception never lifts the per-proposal limit or the yearly caps.
    refused(
        &executor,
        &mut state,
        &stable_cost(account, 1, 10, 100_001, true),
        3 * STEP_MS + 10 * VOTING_PERIOD_MS,
        "",
    )
    .await;
}

fn stable_grant(who: [u8; 32], tranches: Vec<u128>, release: GrantRelease) -> ProposalAction {
    let mut action = grant(who, tranches.iter().sum(), tranches);
    if let ProposalAction::TreasuryGrant {
        asset, release: r, ..
    } = &mut action
    {
        *asset = Some(stable_id());
        *r = release;
    }
    action
}

#[tokio::test]
async fn a_stable_grant_pays_dollars_to_an_approved_grantee_per_milestone() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    stable_world(&mut state, 5_000_000 * USD);
    let grant_of = stable_grant(
        GRANTEE_A,
        vec![20_000 * USD, 30_000 * USD],
        GrantRelease::Governed,
    );
    refused(
        &executor,
        &mut state,
        &grant_of,
        STEP_MS,
        "not an approved grantee",
    )
    .await;
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        2 * STEP_MS,
    )
    .await;
    let result = enact_ok(&executor, &mut state, &grant_of, 3 * STEP_MS).await;
    let records = payouts(&result);
    assert_eq!(records[0].asset, stable_id());
    assert_eq!(records[0].milestone, "milestone 0");
    assert_eq!(records[0].class, "developer");
    assert_eq!(held(&state, &GRANTEE_A), 20_000 * USD);
    // The whole 50,000 dollars was checked against the proposal limit up
    // front, and 150,000 a year per grantee binds the second grant.
    let id = records[0].proposal_id.clone();
    let second = enact_ok(
        &executor,
        &mut state,
        &ProposalAction::ReleaseGrantTranche {
            grant_id: id,
            index: 1,
            memo: "audit report accepted".into(),
        },
        4 * STEP_MS,
    )
    .await;
    assert_eq!(payouts(&second)[0].usd_e6, 30_000 * USD);
    assert_eq!(held(&state, &GRANTEE_A), 50_000 * USD);
    assert_eq!(
        held(&state, derive_treasury_address().as_bytes()) + held(&state, &GRANTEE_A),
        5_000_000 * USD,
        "conservation"
    );
    // A stable grant cannot vest through the TNZO schedule.
    let mut vesting = stable_grant(GRANTEE_A, vec![USD], GrantRelease::Governed);
    if let ProposalAction::TreasuryGrant { vesting: v, .. } = &mut vesting {
        *v = GrantVesting::Grant;
    }
    assert!(vesting.validate().is_err());
    // A grant over the per-proposal limit is refused up front.
    let big = stable_grant(
        GRANTEE_A,
        vec![60_000 * USD, 60_000 * USD],
        GrantRelease::Governed,
    );
    refused(
        &executor,
        &mut state,
        &big,
        5 * STEP_MS,
        "a proposal may pay at most",
    )
    .await;
    // The USD grantee cap binds: 100,000 a year, 50,000 already paid.
    let over = stable_grant(GRANTEE_A, vec![51_000 * USD], GrantRelease::Governed);
    refused(
        &executor,
        &mut state,
        &over,
        6 * STEP_MS,
        "one grantee may receive",
    )
    .await;
}

// ----- scheduled release -----

const VERIFIER_1: [u8; 32] = [0x41; 32];
const VERIFIER_2: [u8; 32] = [0x42; 32];

fn funding_tx(from: &[u8], op: &FundingOp, at_ms: i64) -> VmTransaction {
    let mut data = SELECTOR_FUNDING.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).unwrap());
    tx(from, data, BASE_MS + at_ms)
}

async fn fund_op(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    from: &[u8],
    op: FundingOp,
    at_ms: i64,
) -> std::result::Result<ExecutionResult, String> {
    executor
        .execute_transaction(&funding_tx(from, &op, at_ms), state)
        .await
        .map_err(|e| e.to_string())
}

fn scheduled(who: [u8; 32], tranches: Vec<u128>, threshold: u32) -> ProposalAction {
    let mut action = grant(who, tranches.iter().sum(), tranches);
    if let ProposalAction::TreasuryGrant { release, .. } = &mut action {
        *release = GrantRelease::Scheduled {
            verifiers: vec![Address::new(VERIFIER_1), Address::new(VERIFIER_2)],
            threshold,
        };
    }
    action
}

fn with_verifier_identities(state: &mut StateAdapter) {
    for (i, v) in [VERIFIER_1, VERIFIER_2].iter().enumerate() {
        state.set_storage(
            &SYSTEM_ADDRESS,
            identity_wallet_index_key(v).as_bytes(),
            format!("did:tenzro:human:verifier{i}").into_bytes(),
        );
        state.set_balance(v, GAS_BALANCE);
    }
}

#[tokio::test]
async fn a_scheduled_grant_releases_each_tranche_against_its_verified_milestone() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    with_verifier_identities(&mut state);
    state.set_balance(&GRANTEE_A, GAS_BALANCE);
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Contributor),
        STEP_MS,
    )
    .await;
    let three = scheduled(GRANTEE_A, vec![100 * TNZO, 100 * TNZO, 100 * TNZO], 2);
    let result = enact_ok(&executor, &mut state, &three, 2 * STEP_MS).await;
    let grant_id = payouts(&result)[0].proposal_id.clone();
    assert_eq!(state.get_balance(&GRANTEE_A) - GAS_BALANCE, 100 * TNZO);
    let at = 3 * STEP_MS;
    let verify = |index: u32| FundingOp::VerifyMilestone {
        grant_id: grant_id.clone(),
        index,
        evidence: "audit report published".into(),
    };
    let release = |index: u32| FundingOp::ReleaseMilestone {
        grant_id: grant_id.clone(),
        index,
    };

    // Nothing is released before the milestone is verified.
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(1), at)
        .await
        .unwrap_err();
    assert!(err.contains("has not been verified"), "{err}");
    // The grantee does not verify its own milestone, nor does a stranger.
    let err = fund_op(&executor, &mut state, &GRANTEE_A, verify(1), at)
        .await
        .unwrap_err();
    assert!(err.contains("only a verifier"), "{err}");
    // One of two verifiers is short of the threshold.
    fund_op(&executor, &mut state, &VERIFIER_1, verify(1), at)
        .await
        .unwrap();
    let err = fund_op(&executor, &mut state, &VERIFIER_1, verify(1), at)
        .await
        .unwrap_err();
    assert!(err.contains("already"), "{err}");
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(1), at)
        .await
        .unwrap_err();
    assert!(err.contains("1 of the verifiers"), "{err}");
    // A release proposal is the other route and is closed for this grant.
    let proposal = ProposalAction::ReleaseGrantTranche {
        grant_id: grant_id.clone(),
        index: 1,
        memo: "by proposal".into(),
    };
    refused(
        &executor,
        &mut state,
        &proposal,
        4 * STEP_MS,
        "verified milestones",
    )
    .await;

    let verified_now = fund_op(&executor, &mut state, &VERIFIER_2, verify(1), at)
        .await
        .unwrap();
    assert!(
        verified_now
            .logs
            .iter()
            .any(|l| l.topics.first().map(Vec::as_slice) == Some(MILESTONE_VERIFIED_TOPIC))
    );
    // Out of order: tranche 2 waits for tranche 1.
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(2), at)
        .await
        .unwrap_err();
    assert!(err.contains("is next"), "{err}");
    let paid = fund_op(&executor, &mut state, &VERIFIER_1, release(1), at)
        .await
        .unwrap();
    assert_eq!(payouts(&paid)[0].milestone, "milestone 1");
    assert_eq!(payouts(&paid)[0].amount, 100 * TNZO);
    assert_eq!(payouts(&paid)[0].recipient, hex::encode(GRANTEE_A));
    assert_eq!(state.get_balance(&GRANTEE_A) - GAS_BALANCE, 200 * TNZO);
    // Once only.
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(1), at)
        .await
        .unwrap_err();
    assert!(err.contains("is next"), "{err}");

    // Every tranche keeps the approval check: revoked before the last one.
    fund_op(&executor, &mut state, &VERIFIER_1, verify(2), at)
        .await
        .unwrap();
    fund_op(&executor, &mut state, &VERIFIER_2, verify(2), at)
        .await
        .unwrap();
    enact_ok(
        &executor,
        &mut state,
        &ProposalAction::RevokeGrantee {
            grantee: Address::new(GRANTEE_A),
            memo: "stopped delivering".into(),
        },
        5 * STEP_MS,
    )
    .await;
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(2), 5 * STEP_MS)
        .await
        .unwrap_err();
    assert!(err.contains("revoked"), "{err}");
}

#[tokio::test]
async fn a_scheduled_tranche_keeps_the_caps_and_the_outflow_limit() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    with_verifier_identities(&mut state);
    state.set_balance(&GRANTEE_A, GAS_BALANCE);
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        STEP_MS,
    )
    .await;
    set_param(&mut state, GRANTEE_YEARLY_PARAM, 1_000_000);
    // 10,000,000 TNZO: 2% a proposal is 200,000 and 3% a period 300,000.
    let g = scheduled(
        GRANTEE_A,
        vec![30_000 * TNZO, 30_000 * TNZO, 30_000 * TNZO],
        1,
    );
    let result = enact_ok(&executor, &mut state, &g, 2 * STEP_MS).await;
    let id = payouts(&result)[0].proposal_id.clone();
    let at = 2 * STEP_MS + 2 * VOTING_PERIOD_MS;
    for i in [1u32, 2] {
        fund_op(
            &executor,
            &mut state,
            &VERIFIER_1,
            FundingOp::VerifyMilestone {
                grant_id: id.clone(),
                index: i,
                evidence: "delivered".into(),
            },
            at,
        )
        .await
        .unwrap();
    }
    let release = |i: u32| FundingOp::ReleaseMilestone {
        grant_id: id.clone(),
        index: i,
    };
    fund_op(&executor, &mut state, &GRANTEE_A, release(1), at)
        .await
        .unwrap();
    // 60,000 paid in the period: a limit of 0.01% refuses the third tranche.
    set_param(&mut state, crate::governance::MAX_PERIOD_OUTFLOW_PARAM, 1);
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(2), at)
        .await
        .unwrap_err();
    assert!(
        err.contains("outflow period") || err.contains("may pay out"),
        "{err}"
    );
    set_param(&mut state, crate::governance::MAX_PERIOD_OUTFLOW_PARAM, 300);
    // The yearly grantee cap binds each tranche.
    set_param(&mut state, GRANTEE_YEARLY_PARAM, 70_000);
    let err = fund_op(&executor, &mut state, &GRANTEE_A, release(2), at)
        .await
        .unwrap_err();
    assert!(err.contains("one grantee may receive"), "{err}");
    set_param(&mut state, GRANTEE_YEARLY_PARAM, 1_000_000);
    fund_op(&executor, &mut state, &GRANTEE_A, release(2), at)
        .await
        .unwrap();
}

#[tokio::test]
async fn a_governed_grant_cannot_be_released_by_milestone_and_the_default_is_governed() {
    assert_eq!(GrantRelease::default(), GrantRelease::Governed);
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = chain();
    open_caps(&mut state);
    with_verifier_identities(&mut state);
    state.set_balance(&GRANTEE_A, GAS_BALANCE);
    enact_ok(
        &executor,
        &mut state,
        &approve_grantee(GRANTEE_A, GranteeClass::Developer),
        STEP_MS,
    )
    .await;
    let g = grant(GRANTEE_A, 200 * TNZO, vec![100 * TNZO, 100 * TNZO]);
    let result = enact_ok(&executor, &mut state, &g, 2 * STEP_MS).await;
    let id = payouts(&result)[0].proposal_id.clone();
    let err = fund_op(
        &executor,
        &mut state,
        &GRANTEE_A,
        FundingOp::ReleaseMilestone {
            grant_id: id.clone(),
            index: 1,
        },
        3 * STEP_MS,
    )
    .await
    .unwrap_err();
    assert!(err.contains("by release proposal"), "{err}");
    let err = fund_op(
        &executor,
        &mut state,
        &VERIFIER_1,
        FundingOp::VerifyMilestone {
            grant_id: id,
            index: 1,
            evidence: "delivered".into(),
        },
        3 * STEP_MS,
    )
    .await
    .unwrap_err();
    assert!(err.contains("by release proposal"), "{err}");
    // A scheduled release needs verifiers other than the grantee, a threshold
    // within them, and a grant of more than one tranche.
    let mut bad = scheduled(GRANTEE_A, vec![TNZO, TNZO], 3);
    assert!(bad.validate().is_err(), "threshold above the verifiers");
    bad = scheduled(GRANTEE_A, vec![TNZO], 1);
    assert!(bad.validate().is_err(), "a single payment has no schedule");
    if let ProposalAction::TreasuryGrant { release, .. } = &mut bad {
        *release = GrantRelease::Scheduled {
            verifiers: vec![Address::new(GRANTEE_A)],
            threshold: 1,
        };
    }
    assert!(bad.validate().is_err());
}

// ----- the remote action -----

#[tokio::test]
async fn a_treasury_remote_action_that_moves_value_names_an_approved_operator() {
    use tenzro_types::remote_grant::RemoteAction;
    let mut state = chain();
    open_caps(&mut state);
    stable_world(&mut state, 5_000_000 * USD);
    let (account, did) = endorsed_validator(&mut state, OP_A, 50_000 * TNZO);
    verified(&mut state, &did, 1..=3, true);
    let moves = RemoteAction {
        target: vec![0xaa; 20],
        selector: vec![0xa9, 0x05, 0x9c, 0xbb],
        amount: 1_000 * USD,
        relay_refund: 0,
        data: vec![],
    };
    let payout = crate::governance::RemotePayout {
        payee: account,
        from_epoch: 1,
        to_epoch: 3,
        priced_by: stable_id(),
    };
    // Value with no payee is refused outright.
    let err = super::stable_payout::check_remote(&state, &moves, None).unwrap_err();
    assert!(
        err.to_string().contains("names the approved operator"),
        "{err}"
    );
    // A payee that is not approved is refused.
    let err = super::stable_payout::check_remote(&state, &moves, Some(&payout)).unwrap_err();
    assert!(
        err.to_string().contains("not an approved operator"),
        "{err}"
    );
    payout_gates::approve_operator_for_test(
        &mut state,
        account.as_bytes(),
        OperatorClass::Validator,
    );
    // approve_operator_for_test records no machine identity, so the hours are
    // looked up under the empty did and none verify.
    let err = super::stable_payout::check_remote(&state, &moves, Some(&payout)).unwrap_err();
    assert!(
        err.to_string().contains("no verified-available hour"),
        "{err}"
    );
    // An action that moves nothing needs no payee.
    let idle = RemoteAction {
        amount: 0,
        ..moves.clone()
    };
    super::stable_payout::check_remote(&state, &idle, None).unwrap();
}
