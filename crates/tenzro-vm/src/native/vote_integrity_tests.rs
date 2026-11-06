//! Who may cast a governance ballot, and with what weight.

use super::*;
use crate::VmType;
use crate::config::VmConfig;
use crate::governance::ProposalAction;
use crate::state_adapter::StateAdapter;
use crate::types::{ExecutionResult, VmTransaction};

const STAKE: u128 = 1_000_000;
const GAS: u128 = 10_000_000_000_000_000_000;

fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        200_000,
        1_000_000_000,
        0,
        VmType::Evm,
        1337,
    );
    tx.block_timestamp_ms = Some(at_ms);
    tx
}

fn bind(state: &mut StateAdapter, addr: &[u8], did: &str) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(addr).as_bytes(),
        did.as_bytes().to_vec(),
    );
    state.set_balance(addr, GAS);
}

/// A validator account held by a machine key whose identity is delegated
/// from `operator_did`, and that operator's own passkey account.
fn operated_validator(state: &mut StateAdapter, tag: u8) -> (Vec<u8>, Vec<u8>) {
    let validator = vec![tag; 32];
    let operator = vec![tag + 1; 32];
    let operator_did = format!("did:tenzro:human:op{tag}");
    staking::add_bond(
        state,
        &validator,
        STAKE,
        -crate::governance::MIN_BOND_AGE_MS,
    )
    .unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + STAKE);
    bind(
        state,
        &validator,
        &format!("did:tenzro:machine:op{tag}:v{tag}"),
    );
    bind(state, &operator, &operator_did);
    (validator, operator)
}

async fn open(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    proposer: &[u8],
    at: i64,
) -> Vec<u8> {
    let action = ProposalAction::ParameterChange {
        key: "agent.remote_grant_budget_divisor".into(),
        value: 4,
        memo: "m".into(),
    };
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&action).unwrap());
    executor
        .execute_transaction(&tx(proposer, data, at), state)
        .await
        .expect("propose")
        .output
}

async fn ballot(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    signer: &[u8],
    id: &[u8],
    validator: &[u8],
    at: i64,
) -> Result<ExecutionResult> {
    executor
        .execute_transaction(&tx(signer, test_vote_data(id, true, validator), at), state)
        .await
}

#[tokio::test]
async fn a_machine_key_ballot_is_refused_and_the_operator_ballot_counts() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let (validator, operator) = operated_validator(&mut state, 0x10);
    let id = open(&executor, &mut state, &validator, 0).await;

    let err = ballot(&executor, &mut state, &validator, &id, &validator, 10)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("not a live human identity"),
        "{err}"
    );

    let (_, stranger) = operated_validator(&mut state, 0x30);
    let err = ballot(&executor, &mut state, &stranger, &id, &validator, 10)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not operate"), "{err}");

    ballot(&executor, &mut state, &operator, &id, &validator, 10)
        .await
        .expect("operator ballot");
    assert_eq!(load_tally(&state, &hex::encode(&id)).yes, STAKE);
}

#[tokio::test]
async fn bonding_mid_vote_adds_nothing() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let (validator, operator) = operated_validator(&mut state, 0x10);
    let id = open(&executor, &mut state, &validator, 100).await;

    // After the proposal opened, the validator triples its bond.
    staking::add_bond(&mut state, &validator, 2 * STAKE, 200).unwrap();
    assert_eq!(bonded_stake_of(&state, &validator), 3 * STAKE);

    ballot(&executor, &mut state, &operator, &id, &validator, 300)
        .await
        .expect("ballot");
    assert_eq!(
        load_tally(&state, &hex::encode(&id)).yes,
        STAKE,
        "weight is the bond at open"
    );
}

#[tokio::test]
async fn stake_younger_than_the_minimum_bond_age_weighs_nothing() {
    const DAY: i64 = 24 * 60 * 60 * 1000;
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let (validator, operator) = operated_validator(&mut state, 0x10);
    let opens = 30 * DAY;

    // A day before the proposal opens, the validator triples its bond.
    staking::add_bond(&mut state, &validator, 2 * STAKE, opens - DAY).unwrap();
    let id = open(&executor, &mut state, &validator, opens).await;
    ballot(
        &executor,
        &mut state,
        &operator,
        &id,
        &validator,
        opens + 10,
    )
    .await
    .expect("ballot");
    assert_eq!(
        load_tally(&state, &hex::encode(&id)).yes,
        STAKE,
        "only the aged bond counts"
    );

    // A validator whose whole bond is younger than the minimum cannot vote.
    let fresh = vec![0x50u8; 32];
    let fresh_operator = vec![0x51u8; 32];
    staking::add_bond(&mut state, &fresh, STAKE, opens - DAY).unwrap();
    bind(&mut state, &fresh, "did:tenzro:machine:op80:v80");
    bind(&mut state, &fresh_operator, "did:tenzro:human:op80");
    let err = ballot(
        &executor,
        &mut state,
        &fresh_operator,
        &id,
        &fresh,
        opens + 20,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no bonded stake"), "{err}");
}

#[tokio::test]
async fn the_bond_age_a_proposal_opened_under_decides_it() {
    const DAY: i64 = 24 * 60 * 60 * 1000;
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let (validator, operator) = operated_validator(&mut state, 0x10);
    let opens = 30 * DAY;
    staking::add_bond(&mut state, &validator, 2 * STAKE, opens - DAY).unwrap();
    let id = open(&executor, &mut state, &validator, opens).await;

    // The minimum is lowered to zero after the proposal opened; the proposal
    // keeps the minimum it opened under.
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(crate::governance::MIN_BOND_AGE_PARAM).as_bytes(),
        0u64.to_le_bytes().to_vec(),
    );
    ballot(
        &executor,
        &mut state,
        &operator,
        &id,
        &validator,
        opens + 10,
    )
    .await
    .expect("ballot");
    assert_eq!(load_tally(&state, &hex::encode(&id)).yes, STAKE);
}

#[test]
fn bond_at_reads_the_bond_before_each_increase() {
    let mut state = StateAdapter::new();
    let a = vec![9u8; 32];
    staking::add_bond(&mut state, &a, 10, 100).unwrap();
    staking::add_bond(&mut state, &a, 5, 200).unwrap();
    assert_eq!(staking::bond_at(&state, &a, 50), 0);
    assert_eq!(staking::bond_at(&state, &a, 150), 10);
    assert_eq!(staking::bond_at(&state, &a, 250), 15);
}

mod machine_root_ballots {
    use super::*;
    use crate::account_keys::set_enrolled_pq_key;
    use crate::native::agent_terms::tests::machine_approval;
    use tenzro_crypto::composite::HybridSigner;
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_types::agent_terms::{AgentTermsApproval, OP_ROOT_BALLOT, governance_vote_target};

    /// A bonded validator whose identity is the autonomous machine `m`,
    /// registered on chain with its hardware key (and its ML-DSA-65 key
    /// enrolled). The validator account is the machine's wallet.
    fn machine_validator(state: &mut StateAdapter, m: &TestHybridSigner) -> Vec<u8> {
        let xy = m.public_key().p256.clone();
        let sec1 = [&[0x04u8][..], &xy].concat();
        let did = tenzro_types::did_derivation::machine_did(&sec1);
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: did.clone(),
            identity_type: "machine".into(),
            display_name: "validator".into(),
            controller_pubkey: sec1,
            key_type: "P-256".into(),
            wallet_id: "w".into(),
            wallet_address: m.address(),
            pq_verifying_key: m.public_key().pq.clone().unwrap_or_default(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        state.set_storage(
            &SYSTEM_ADDRESS,
            &identity_storage_key(&did),
            serde_json::to_vec(&record).unwrap(),
        );
        if let Some(pq) = m.public_key().pq.clone() {
            set_enrolled_pq_key(state, &xy, pq, &mut Vec::new());
        }
        let validator = m.address().as_bytes().to_vec();
        bind(state, &validator, &did);
        staking::add_bond(
            state,
            &validator,
            STAKE,
            -crate::governance::MIN_BOND_AGE_MS,
        )
        .unwrap();
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + STAKE);
        validator
    }

    fn approve(
        m: &TestHybridSigner,
        id: &[u8],
        in_favour: bool,
        validator: &[u8],
    ) -> AgentTermsApproval {
        let target = governance_vote_target(id.try_into().unwrap(), in_favour, validator);
        machine_approval(OP_ROOT_BALLOT, &target, m)
    }

    fn data(
        id: &[u8],
        in_favour: bool,
        validator: &[u8],
        approval: &AgentTermsApproval,
    ) -> Vec<u8> {
        let mut data = test_vote_data(id, in_favour, validator);
        data.extend_from_slice(&serde_json::to_vec(approval).unwrap());
        data
    }

    async fn cast(
        executor: &NativeExecutor,
        state: &mut StateAdapter,
        submitter: &[u8],
        body: Vec<u8>,
        at: i64,
    ) -> Result<ExecutionResult> {
        executor
            .execute_transaction(&tx(submitter, body, at), state)
            .await
    }

    #[tokio::test]
    async fn a_machine_roots_ballot_counts_its_validators_bond() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let m = TestHybridSigner::hybrid(41);
        let validator = machine_validator(&mut state, &m);
        let id = open(&executor, &mut state, &validator, 0).await;

        // Any account may carry the approval and pay its gas.
        let (_, relayer) = operated_validator(&mut state, 0x50);
        let approval = approve(&m, &id, true, &validator);
        cast(
            &executor,
            &mut state,
            &relayer,
            data(&id, true, &validator, &approval),
            10,
        )
        .await
        .expect("machine root ballot");
        assert_eq!(load_tally(&state, &hex::encode(&id)).yes, STAKE);
    }

    #[tokio::test]
    async fn a_forged_or_foreign_machine_approval_is_refused() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let m = TestHybridSigner::hybrid(42);
        let validator = machine_validator(&mut state, &m);
        let other = TestHybridSigner::hybrid(43);
        let other_validator = machine_validator(&mut state, &other);
        let id = open(&executor, &mut state, &validator, 0).await;

        // Another registered machine approving this validator's ballot.
        let mut foreign = approve(&other, &id, true, &validator);
        foreign.account = validator.clone();
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &foreign),
            10,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("machine root ballot refused"),
            "{err}"
        );

        // An approval for "no" carried on a "yes" ballot.
        let flipped = approve(&m, &id, false, &validator);
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &flipped),
            10,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        // The ML-DSA leg stripped from an enrolled machine's approval.
        let mut stripped = approve(&m, &id, true, &validator);
        stripped.signature.pq = None;
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &stripped),
            10,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("machine root ballot refused"),
            "{err}"
        );

        // A machine root's approval for a validator rooted in a person.
        let (operated, _) = operated_validator(&mut state, 0x60);
        let mut misplaced = approve(&m, &id, true, &operated);
        misplaced.account = operated.clone();
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &operated, &misplaced),
            10,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string().contains("not an autonomous machine"),
            "{err}"
        );

        // The other machine's own ballot for its own validator counts.
        let own = approve(&other, &id, true, &other_validator);
        cast(
            &executor,
            &mut state,
            &other_validator,
            data(&id, true, &other_validator, &own),
            10,
        )
        .await
        .expect("own ballot");
        assert_eq!(load_tally(&state, &hex::encode(&id)).yes, STAKE);
    }

    #[tokio::test]
    async fn a_machine_validator_has_one_ballot() {
        let executor = NativeExecutor::new(VmConfig::default()).unwrap();
        let mut state = StateAdapter::new();
        let m = TestHybridSigner::hybrid(44);
        let validator = machine_validator(&mut state, &m);
        let id = open(&executor, &mut state, &validator, 0).await;
        let yes = approve(&m, &id, true, &validator);
        cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &yes),
            10,
        )
        .await
        .expect("ballot");

        // No passkey ballot beside the machine root's: not from the
        // machine's own wallet, not from a person.
        let err = ballot(&executor, &mut state, &validator, &id, &validator, 20)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("carries that machine root's approval"),
            "{err}"
        );
        let (_, person) = operated_validator(&mut state, 0x70);
        let err = ballot(&executor, &mut state, &person, &id, &validator, 20)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("carries that machine root's approval"),
            "{err}"
        );

        // The same approval counts once.
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &yes),
            20,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already been counted"), "{err}");

        // The root changing its vote moves the bond; it is never counted twice.
        let no = approve(&m, &id, false, &validator);
        cast(
            &executor,
            &mut state,
            &validator,
            data(&id, false, &validator, &no),
            30,
        )
        .await
        .expect("changed ballot");
        let tally = load_tally(&state, &hex::encode(&id));
        assert_eq!((tally.yes, tally.no), (0, STAKE));

        // Replaying the earlier "yes" cannot restore it.
        let err = cast(
            &executor,
            &mut state,
            &validator,
            data(&id, true, &validator, &yes),
            40,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("already been counted"), "{err}");
    }
}

async fn open_change(
    executor: &NativeExecutor,
    state: &mut StateAdapter,
    proposer: &[u8],
    key: &str,
    value: u64,
) -> Vec<u8> {
    let action = ProposalAction::ParameterChange {
        key: key.into(),
        value,
        memo: "m".into(),
    };
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&action).unwrap());
    executor
        .execute_transaction(&tx(proposer, data, 0), state)
        .await
        .expect("propose")
        .output
}

/// Two thirds of the eligible stake carry a tightening of the fee-rate step
/// cap, and the same two thirds cannot carry its loosening: that needs three
/// quarters of all eligible stake, as a large spend does.
#[tokio::test]
async fn two_thirds_of_stake_cannot_loosen_a_safety_bound_but_can_tighten_it() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let (v1, o1) = operated_validator(&mut state, 0x10);
    let (v2, o2) = operated_validator(&mut state, 0x30);
    let (_v3, _o3) = operated_validator(&mut state, 0x50);
    let key = economy::RATE_MAX_CHANGE_PARAM;
    let in_force = network_param(&state, key);
    for (value, loosens) in [(in_force + 1, true), (in_force - 1, false)] {
        let id = open_change(&executor, &mut state, &v1, key, value).await;
        ballot(&executor, &mut state, &o1, &id, &v1, 10)
            .await
            .expect("ballot");
        ballot(&executor, &mut state, &o2, &id, &v2, 10)
            .await
            .expect("ballot");
        let ends = load_proposal(&state, &hex::encode(&id))
            .unwrap()
            .voting_ends_ms;
        let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
        data.extend_from_slice(&id);
        let result = executor
            .execute_transaction(&tx(&v1, data, ends + 1), &mut state)
            .await;
        if loosens {
            let err = result.unwrap_err();
            assert!(
                err.to_string().contains("loosens an economic safety bound"),
                "{err}"
            );
        } else {
            result.expect("a tightening carries at two thirds");
        }
    }
}
