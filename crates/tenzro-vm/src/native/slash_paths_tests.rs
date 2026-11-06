//! Every slash runs in consensus and funds the insurance pool: frozen SLA
//! verdicts, validator findings (policy violations), and
//! the renter's claim on an unavailable epoch. A paused or quarantined agent's
//! bond cannot be withdrawn, and only the account that posted it withdraws it.

use super::*;
use crate::VmConfig;
use crate::VmType;
use crate::state_adapter::StateAdapter;
use tenzro_types::agent_audit::AuditFinding;

const CHAIN: u64 = 1337;
const TNZO: u128 = 1_000_000_000_000_000_000;
const DID: &str = "did:tenzro:machine:provider";
const AGENT: &str = "did:tenzro:machine:controller:agent";
const CONTROLLER: &str = "did:tenzro:human:controller";

fn tx(from: &[u8], selector: [u8; 4], body: Vec<u8>, nonce: u64, at: i64) -> VmTransaction {
    let mut data = selector.to_vec();
    data.extend(body);
    let mut t = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        5_000_000,
        0,
        nonce,
        VmType::Tenzro,
        CHAIN,
    );
    t.block_timestamp_ms = Some(at);
    t
}

fn bond_validator(state: &mut StateAdapter, who: &[u8], stake: u128) {
    staking::add_bond(state, who, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
    state.set_balance(who, 10 * TNZO);
}

fn compute_bond(state: &mut StateAdapter, did: &str, provider: &[u8], amount: u128) {
    let marker = serde_json::json!({
        "provider_did": did,
        "provider_address": hex::encode(provider),
        "amount": amount.to_string(),
        "op": "Posted",
    });
    state.set_storage(
        &SYSTEM_ADDRESS,
        compute_bond_storage_key(did).as_bytes(),
        serde_json::to_vec(&marker).unwrap(),
    );
    state.set_balance(derive_compute_bond_vault_address(did).as_bytes(), amount);
}

fn pool(state: &StateAdapter) -> u128 {
    state.get_balance(derive_insurance_pool_address().as_bytes())
}

fn validators(state: &mut StateAdapter) -> Vec<Vec<u8>> {
    let vs = vec![vec![1u8; 32], vec![2u8; 32], vec![3u8; 32]];
    for v in &vs {
        bond_validator(state, v, 100 * TNZO);
    }
    vs
}

fn sla_attest(from: &[u8], epoch: u64, available: bool) -> VmTransaction {
    let body = serde_json::to_vec(&serde_json::json!({
        "epoch": epoch,
        "outcomes": [{ "provider_did": DID, "available": available, "capacity": null }],
    }))
    .unwrap();
    tx(
        from,
        SELECTOR_SLA_ATTEST,
        body,
        0,
        (epoch as i64 + 1) * MARKET_EPOCH_MS + 1,
    )
}

fn flag(from: &[u8], finding: &AuditFinding) -> VmTransaction {
    let body =
        serde_json::to_vec(&serde_json::json!({ "epoch": 0, "findings": [finding] })).unwrap();
    tx(from, SELECTOR_AGENT_AUDIT_FLAG, body, 0, 1_000)
}

const HOUR: i64 = 3_600_000;

fn set_param(state: &mut StateAdapter, key: &str, v: u64) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(key).as_bytes(),
        v.to_le_bytes().to_vec(),
    );
}

fn put_escrow(
    state: &mut StateAdapter,
    n: u8,
    payer: [u8; 32],
    payee: [u8; 32],
    amount: u128,
    expires_ms: i64,
    release_conditions: ReleaseConditions,
) -> [u8; 32] {
    let id = [n; 32];
    let e = EscrowAccount {
        escrow_id: hex::encode(id),
        payer: Address::new(payer),
        payee: Address::new(payee),
        amount,
        asset_id: AssetId::tnzo(),
        usd_e6: 0,
        created_at: Timestamp::new(0),
        expires_at: Timestamp::new(expires_ms),
        status: EscrowStatus::Funded,
        release_conditions,
        claimed: 0,
        approved_by: None,
        reference: None,
    };
    write_escrow_record(state, &escrow_storage_key(&hex::encode(id)), None, &e).unwrap();
    state.set_balance(derive_vault_address(&id).as_bytes(), amount);
    id
}

/// A bonded provider at `[5; 32]` whose bond must cover all it holds in escrow.
fn bonded_provider(state: &mut StateAdapter, bond: u128) -> [u8; 32] {
    let p = [5u8; 32];
    compute_bond(state, DID, &p, bond);
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(&p).as_bytes(),
        DID.as_bytes().to_vec(),
    );
    set_param(state, economy::VAR_RATIO_PARAM, 10_000);
    set_param(state, COMPUTE_BOND_MIN_PARAM, 0);
    p
}

/// An expired stream that served nothing no longer counts against its
/// provider's bond, and leaves the list of open escrows.
#[test]
fn an_expired_stream_holds_its_provider_only_to_what_it_accrued() {
    let mut state = StateAdapter::new();
    let p = bonded_provider(&mut state, 10 * TNZO);
    let stream = ReleaseConditions::Stream {
        rate_per_epoch: 0,
        epoch_ms: HOUR as u64,
    };
    let a = put_escrow(
        &mut state,
        1,
        [7; 32],
        p,
        10 * TNZO,
        2 * HOUR,
        stream.clone(),
    );
    let mut ch = Vec::new();
    economy::check_provider_exposure(
        &mut state,
        &Address::new(p),
        &AssetId::tnzo(),
        10 * TNZO,
        &a,
        0,
        &mut ch,
    )
    .unwrap();
    let b = put_escrow(&mut state, 2, [7; 32], p, 5 * TNZO, 9 * HOUR, stream);
    economy::check_provider_exposure(
        &mut state,
        &Address::new(p),
        &AssetId::tnzo(),
        5 * TNZO,
        &b,
        3 * HOUR,
        &mut ch,
    )
    .expect("the expired stream holds the provider to nothing");
    let (live, open) = economy::provider_exposure(&state, DID, 3 * HOUR);
    assert_eq!((live, open), (5 * TNZO, vec![hex::encode(b)]));
}

/// Below the governed minimum an escrow toward a bonded provider is refused.
#[test]
fn an_escrow_below_the_minimum_toward_a_bonded_provider_is_refused() {
    let mut state = StateAdapter::new();
    let p = bonded_provider(&mut state, 10 * TNZO);
    let a = put_escrow(
        &mut state,
        1,
        [7; 32],
        p,
        1_000,
        HOUR,
        ReleaseConditions::Timeout,
    );
    let mut ch = Vec::new();
    let r = economy::check_provider_exposure(
        &mut state,
        &Address::new(p),
        &AssetId::tnzo(),
        1_000,
        &a,
        0,
        &mut ch,
    );
    assert!(format!("{r:?}").contains("at least"), "{r:?}");
}

/// Past its expiry and the grace, anyone closes an escrow; the money goes to
/// the payer as if the payer had closed it.
#[test]
fn anyone_closes_an_escrow_left_past_its_expiry_and_grace() {
    let mut state = StateAdapter::new();
    let (payer, payee, stranger) = ([7u8; 32], [8u8; 32], [9u8; 32]);
    let id = put_escrow(
        &mut state,
        3,
        payer,
        payee,
        3 * TNZO,
        HOUR,
        ReleaseConditions::Timeout,
    );
    let grace = 168 * HOUR;
    assert!(refund_escrow(&mut state, &id, &stranger, HOUR + grace).is_err());
    refund_escrow(&mut state, &id, &stranger, HOUR + grace + 1).unwrap();
    assert_eq!(state.get_balance(&payer), 3 * TNZO);
    assert_eq!(state.get_balance(&stranger), 0);
    assert_eq!(
        read_escrow(&state, &id).unwrap().status,
        EscrowStatus::Refunded
    );
}

/// A closed escrow's record is deleted once its retention has passed, with
/// a log carrying it; a funded one stays and is looked at again.
#[test]
fn closed_escrow_records_are_deleted_after_their_retention() {
    let mut state = StateAdapter::new();
    let mut ch = Vec::new();
    let closed = put_escrow(
        &mut state,
        4,
        [7; 32],
        [8; 32],
        TNZO,
        2 * HOUR,
        ReleaseConditions::Timeout,
    );
    let open = put_escrow(
        &mut state,
        5,
        [7; 32],
        [8; 32],
        TNZO,
        2 * HOUR,
        ReleaseConditions::Timeout,
    );
    for id in [closed, open] {
        let e = read_escrow(&state, &id).unwrap();
        let review = escrow_review_ms(&state, &e);
        schedule_escrow_record(&mut state, &id, review, &mut ch).unwrap();
    }
    refund_escrow(&mut state, &closed, &[7; 32], 3 * HOUR).unwrap();
    // 722 h: the retention after the expiry, in day 30.
    assert!(
        sweep_escrow_records(&mut state, 700 * HOUR, &mut ch)
            .unwrap()
            .is_empty()
    );
    assert!(read_escrow(&state, &closed).is_some());
    let logs = sweep_escrow_records(&mut state, 32 * 24 * HOUR, &mut ch).unwrap();
    assert_eq!(logs.len(), 1);
    assert!(read_escrow(&state, &closed).is_none());
    assert!(read_escrow(&state, &open).is_some());
    let archived: EscrowAccount = serde_json::from_slice(&logs[0].data).unwrap();
    assert_eq!(archived.status, EscrowStatus::Refunded);
}

fn held(state: &StateAdapter, key: &str) -> bool {
    state
        .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
        .is_some_and(|b| !b.is_empty())
}

/// A verdict takes its attestations with it; attestations that never reach
/// one are deleted once their epoch can no longer be attested.
#[tokio::test]
async fn sla_attestations_do_not_outlive_their_epoch() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    compute_bond(&mut state, DID, &[5u8; 32], 100 * TNZO);
    for v in &vs[..2] {
        ex.execute_transaction(&sla_attest(v, 10, true), &mut state)
            .await
            .unwrap();
    }
    assert!(held(&state, &format!("sla:10:{DID}")));
    assert!(!held(&state, &format!("sla_sub:10:{DID}")));

    // One third of the stake never reaches a verdict.
    ex.execute_transaction(&sla_attest(&vs[0], 11, true), &mut state)
        .await
        .unwrap();
    assert!(held(&state, &format!("sla_sub:11:{DID}")));
    // An hour judged unavailable.
    for v in &vs[..2] {
        ex.execute_transaction(&sla_attest(v, 12, false), &mut state)
            .await
            .unwrap();
    }
    // A retention later the verdicts and the leftovers are gone; the
    // unavailable hour still reads as unavailable.
    ex.execute_transaction(&sla_attest(&vs[0], 13 + 168, true), &mut state)
        .await
        .unwrap();
    assert!(!held(&state, &format!("sla_sub:11:{DID}")));
    assert!(!held(&state, &format!("sla:10:{DID}")));
    assert!(!held(&state, &format!("sla:12:{DID}")));
    assert_eq!(read_sla_verdict(&state, DID, 10), None);
    assert!(!read_sla_verdict(&state, DID, 12).unwrap().available);
}

/// A stream claim records how far it judged, so a later claim neither reads
/// those hours again nor counts their withheld time twice.
#[tokio::test]
async fn a_stream_claim_goes_on_from_where_the_last_stopped() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    let p = bonded_provider(&mut state, 100 * TNZO);
    set_param(&mut state, economy::VAR_RATIO_PARAM, 0);
    let rate = TNZO / 10;
    let stream = ReleaseConditions::Stream {
        rate_per_epoch: rate,
        epoch_ms: HOUR as u64,
    };
    let id = put_escrow(&mut state, 6, [7; 32], p, 10 * TNZO, 60 * HOUR, stream);
    // Hour 1 judged unavailable.
    for v in &vs[..2] {
        ex.execute_transaction(&sla_attest(v, 1, false), &mut state)
            .await
            .unwrap();
    }
    let claim = |at: i64| {
        let body = serde_json::to_vec(&serde_json::json!({ "escrow_id": id })).unwrap();
        tx(&[9u8; 32], SELECTOR_ESCROW_STREAM_CLAIM, body, 0, at)
    };
    state.set_balance(&[9u8; 32], TNZO);
    let before = state.get_balance(&p);
    ex.execute_transaction(&claim(30 * HOUR), &mut state)
        .await
        .unwrap();
    let first = state.get_balance(&p) - before;
    let c: payment_settlement::StreamCursor =
        funding::read_json(&state, &payment_settlement::stream_cursor_key(&id)).unwrap();
    // Hours from 6 on are still inside the attest window at hour 30.
    assert_eq!((c.judged_ms, c.withheld_ms), (6 * HOUR, HOUR as u128));
    ex.execute_transaction(&claim(40 * HOUR), &mut state)
        .await
        .unwrap();
    let second = state.get_balance(&p) - before - first;
    assert!(first > 0 && second > 0, "{first} {second}");
    // Through hour 16, less the hour withheld, counted once.
    assert_eq!(read_escrow(&state, &id).unwrap().claimed, 15 * rate);
}

#[tokio::test]
async fn an_unavailable_verdict_slashes_the_compute_bond_into_the_pool() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    compute_bond(&mut state, DID, &[5u8; 32], 100 * TNZO);
    let epoch = 10;
    ex.execute_transaction(&sla_attest(&vs[0], epoch, false), &mut state)
        .await
        .unwrap();
    assert_eq!(pool(&state), 0, "a third of the stake freezes nothing");
    ex.execute_transaction(&sla_attest(&vs[1], epoch, false), &mut state)
        .await
        .unwrap();
    let penalty = DEFAULT_SLA_UNAVAILABLE_PENALTY_GWEI as u128 * 1_000_000_000;
    assert_eq!(pool(&state), penalty);
    assert_eq!(insurance::read_totals(&state).from_slashes, penalty);
    assert_eq!(
        state.get_balance(derive_compute_bond_vault_address(DID).as_bytes()),
        100 * TNZO - penalty
    );

    // An available verdict slashes nothing.
    ex.execute_transaction(&sla_attest(&vs[0], epoch + 1, true), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&sla_attest(&vs[1], epoch + 1, true), &mut state)
        .await
        .unwrap();
    assert_eq!(pool(&state), penalty);
}

#[tokio::test]
async fn a_storage_only_stake_is_attested_and_slashed_without_a_compute_bond() {
    use tenzro_types::network::NetworkRole;
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    let owner = vec![7u8; 32];
    let subject = role_stake_subject(&owner, NetworkRole::StorageProvider);
    // No stake: nothing owes an SLA.
    assert!(sla_subject(&state, &subject).is_none());

    let stake = 100 * TNZO;
    role_stake::bond_role_for_test(&mut state, &owner, NetworkRole::StorageProvider, stake);
    // Bonded, but no identity holds the account yet: nobody may answer.
    let resolved = sla_subject(&state, &subject).unwrap();
    assert_eq!(
        resolved.kind,
        SlaSubjectKind::RoleStake(NetworkRole::StorageProvider)
    );
    assert_eq!(resolved.owner, owner);
    assert_eq!(resolved.identity, None);
    // The account's machine identity answers with its hardware key.
    let key = tenzro_crypto::composite::HybridSigner::public_key(
        &tenzro_crypto::testing::TestHybridSigner::hybrid(7),
    )
    .clone();
    let did = "did:tenzro:machine:storage";
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.into(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: key.p256.clone(),
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: tenzro_types::primitives::Address::new([7; 32]),
        pq_verifying_key: key.pq.clone().unwrap_or_default(),
        metadata: Default::default(),
        proof: tenzro_types::identity::RegistrationProof::TpmQuote {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    state.set_storage(
        &SYSTEM_ADDRESS,
        &super::identity_storage_key(did),
        serde_json::to_vec(&record).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        super::identity_wallet_index_key(&owner).as_bytes(),
        did.as_bytes().to_vec(),
    );
    assert_eq!(sla_subject(&state, &subject).unwrap().identity, Some(key));

    let attest = |from: &[u8], available| {
        let body = serde_json::to_vec(&serde_json::json!({
            "epoch": 10,
            "outcomes": [{ "provider_did": subject, "available": available, "capacity": null }],
        }))
        .unwrap();
        tx(from, SELECTOR_SLA_ATTEST, body, 0, 11 * MARKET_EPOCH_MS + 1)
    };
    ex.execute_transaction(&attest(&vs[0], false), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&attest(&vs[1], false), &mut state)
        .await
        .unwrap();
    assert!(read_sla_verdict(&state, &subject, 10).is_some_and(|v| !v.available));
    let penalty = DEFAULT_SLA_UNAVAILABLE_PENALTY_GWEI as u128 * 1_000_000_000;
    assert_eq!(pool(&state), penalty);
    assert_eq!(insurance::read_totals(&state).from_slashes, penalty);
    assert_eq!(
        read_role_stake(&state, &owner, NetworkRole::StorageProvider)
            .unwrap()
            .bonded,
        stake - penalty
    );
}

#[tokio::test]
async fn a_proven_policy_violation_slashes_the_operator_once() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    compute_bond(&mut state, DID, &[5u8; 32], 50 * TNZO);
    let finding = AuditFinding::PolicyViolation {
        violation_id: "cd".repeat(32),
        operator_did: DID.into(),
    };
    ex.execute_transaction(&flag(&vs[0], &finding), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&flag(&vs[1], &finding), &mut state)
        .await
        .unwrap();
    let penalty = inference_fault::penalty_due(&state, 0);
    assert_eq!(pool(&state), penalty);
    // The violation has taken effect; making it again changes nothing.
    assert!(
        ex.execute_transaction(&flag(&vs[2], &finding), &mut state)
            .await
            .is_err()
    );
    assert_eq!(pool(&state), penalty);
}

#[tokio::test]
async fn stake_that_left_after_flagging_does_not_count_toward_the_quorum() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    compute_bond(&mut state, DID, &[5u8; 32], 50 * TNZO);
    let finding = AuditFinding::PolicyViolation {
        violation_id: "ab".repeat(32),
        operator_did: DID.into(),
    };
    ex.execute_transaction(&flag(&vs[0], &finding), &mut state)
        .await
        .unwrap();
    // The first flagger leaves and the same amount is bonded again by a new account.
    staking::begin_unbonding(&mut state, &vs[0], 1_000).unwrap();
    let newcomer = vec![9u8; 32];
    bond_validator(&mut state, &newcomer, 100 * TNZO);
    ex.execute_transaction(&flag(&newcomer, &finding), &mut state)
        .await
        .unwrap();
    // Only a third of the stake bonded now stands behind the finding.
    assert_eq!(pool(&state), 0);
}

/// A renter rents a provider's capacity with a stream escrow; an
/// equivocation slash has funded the insurance pool; the validators freeze
/// the provider unavailable in `epoch`, and the renter is paid that epoch
/// from the pool.
/// A ten-hour stream from `renter` to the compute-bonded provider from the
/// start of `epoch`, at one TNZO an hour; its escrow id.
async fn open_stream(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    renter: &[u8],
    provider: &[u8],
    epoch: u64,
) -> [u8; 32] {
    let start = epoch as i64 * MARKET_EPOCH_MS;
    let create = serde_json::json!({
        "payee": tenzro_types::primitives::Address::new(provider.to_vec().try_into().unwrap()),
        "amount": (10 * TNZO) as u64,
        "asset_id": "TNZO",
        "expires_at": (start + 10 * MARKET_EPOCH_MS) as u64,
        "release_conditions": { "Stream": { "rate_per_epoch": TNZO.to_string(), "epoch_ms": MARKET_EPOCH_MS as u64 } },
    });
    let r = ex
        .execute_transaction(
            &tx(
                renter,
                SELECTOR_ESCROW_CREATE,
                serde_json::to_vec(&create).unwrap(),
                0,
                start,
            ),
            state,
        )
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    r.output.try_into().unwrap()
}

fn escrow_call(
    from: &[u8],
    selector: [u8; 4],
    escrow_id: [u8; 32],
    nonce: u64,
    at: i64,
) -> VmTransaction {
    tx(
        from,
        selector,
        serde_json::to_vec(&serde_json::json!({ "escrow_id": escrow_id })).unwrap(),
        nonce,
        at,
    )
}

/// An hour judged unavailable is never paid out of the stream: the provider
/// claims only the hour judged available, and the stopped stream returns the
/// rest to the renter. Nobody is harmed, so nothing is drawn from the
/// insurance pool; one party on both sides of the stream gets back only its
/// own payment.
#[tokio::test]
async fn a_stream_does_not_pay_an_hour_judged_unavailable() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    let provider = vec![5u8; 32];
    let renter = vec![6u8; 32];
    state.set_balance(&renter, 100 * TNZO);
    state.set_balance(&provider, TNZO);
    compute_bond(&mut state, DID, &provider, 100 * TNZO);
    bind_identity(&mut state, &provider, DID);
    let epoch = 10u64;
    let escrow_id = open_stream(&ex, &mut state, &renter, &provider, epoch).await;
    let pool_before = pool(&state);

    // Hour 10 judged unavailable, hour 11 available.
    for v in &vs[..2] {
        ex.execute_transaction(&sla_attest(v, epoch, false), &mut state)
            .await
            .unwrap();
        ex.execute_transaction(&sla_attest(v, epoch + 1, true), &mut state)
            .await
            .unwrap();
    }
    let at = (epoch as i64 + 2) * MARKET_EPOCH_MS + 1;
    let provider_before = state.get_balance(&provider);
    let r = ex
        .execute_transaction(
            &escrow_call(&provider, SELECTOR_ESCROW_STREAM_CLAIM, escrow_id, 0, at),
            &mut state,
        )
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    let received = state.get_balance(&provider) - provider_before;
    assert!(
        received > 0 && received <= TNZO,
        "the provider is paid the available hour only: {received}"
    );

    // Stopped now: the renter gets back everything but the hour it was served.
    let renter_before = state.get_balance(&renter);
    let r = ex
        .execute_transaction(
            &escrow_call(&renter, SELECTOR_ESCROW_REFUND, escrow_id, 1, at),
            &mut state,
        )
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    let returned = state.get_balance(&renter) - renter_before;
    assert_eq!(
        returned,
        9 * TNZO,
        "the unavailable hour and the unused term return"
    );
    // The unavailable hour still costs the provider its penalty, into the
    // pool; nothing is paid out of it.
    assert!(
        pool(&state) >= pool_before,
        "the insurance pool pays nothing"
    );
}

/// An hour no verdict has judged is not paid while validators may still
/// judge it, and is paid once its attestation window has closed.
#[tokio::test]
async fn an_unjudged_hour_is_paid_once_its_window_closes() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    validators(&mut state);
    let provider = vec![5u8; 32];
    let renter = vec![6u8; 32];
    state.set_balance(&renter, 100 * TNZO);
    state.set_balance(&provider, TNZO);
    compute_bond(&mut state, DID, &provider, 100 * TNZO);
    bind_identity(&mut state, &provider, DID);
    let epoch = 10u64;
    let escrow_id = open_stream(&ex, &mut state, &renter, &provider, epoch).await;

    let early = (epoch as i64 + 2) * MARKET_EPOCH_MS + 1;
    let r = ex
        .execute_transaction(
            &escrow_call(&provider, SELECTOR_ESCROW_STREAM_CLAIM, escrow_id, 0, early),
            &mut state,
        )
        .await;
    assert!(
        r.is_err() || !r.unwrap().success,
        "nothing is paid while the hours may still be judged"
    );

    let late = (epoch as i64 + 1 + MARKET_SUBMIT_WINDOW as i64 + 1) * MARKET_EPOCH_MS + 1;
    let before = state.get_balance(&provider);
    let r = ex
        .execute_transaction(
            &escrow_call(&provider, SELECTOR_ESCROW_STREAM_CLAIM, escrow_id, 0, late),
            &mut state,
        )
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);
    let received = state.get_balance(&provider) - before;
    assert!(
        received >= TNZO,
        "hours past their window are paid: {received}"
    );
}

fn post_bond(owner: &[u8], amount: u128) -> VmTransaction {
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_did": AGENT,
        "controller_did": CONTROLLER,
        "amount": amount,
    }))
    .unwrap();
    tx(owner, SELECTOR_POST_AGENT_BOND, body, 0, 1_000)
}

fn withdraw(from: &[u8], nonce: u64, at: i64) -> VmTransaction {
    let body = serde_json::to_vec(&serde_json::json!({ "agent_did": AGENT })).unwrap();
    tx(from, SELECTOR_WITHDRAW_AGENT_BOND, body, nonce, at)
}

fn pause(from: &[u8], nonce: u64, until: Option<u64>) -> VmTransaction {
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_did": AGENT,
        "controller_did": CONTROLLER,
        "reason_code": 1,
        "until": until,
    }))
    .unwrap();
    tx(from, SELECTOR_KILLSWITCH_PAUSE, body, nonce, 2_000)
}

#[tokio::test]
async fn a_paused_agents_bond_cannot_be_withdrawn() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let owner = vec![4u8; 32];
    state.set_balance(&owner, 100 * TNZO);
    bind_identity(&mut state, &owner, CONTROLLER);
    let r = ex
        .execute_transaction(&post_bond(&owner, 10 * TNZO), &mut state)
        .await
        .unwrap();
    assert!(r.success, "{:?}", r.revert_reason);

    // Only the controller pauses.
    assert!(
        ex.execute_transaction(&pause(&[8u8; 32], 0, None), &mut state)
            .await
            .is_err()
    );
    ex.execute_transaction(&pause(&owner, 1, Some(50_000)), &mut state)
        .await
        .unwrap();
    let err = ex
        .execute_transaction(&withdraw(&owner, 2, 3_000), &mut state)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("frozen"), "{err}");
    // The pause has ended: the cooldown starts.
    ex.execute_transaction(&withdraw(&owner, 2, 60_000), &mut state)
        .await
        .unwrap();
    assert!(!agent_bond_frozen(&state, AGENT, 60_000));
}

#[tokio::test]
async fn a_quarantined_agents_bond_cannot_be_withdrawn() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let owner = vec![4u8; 32];
    state.set_balance(&owner, 100 * TNZO);
    bind_identity(&mut state, &owner, CONTROLLER);
    ex.execute_transaction(&post_bond(&owner, 10 * TNZO), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&withdraw(&owner, 1, 3_000), &mut state)
        .await
        .unwrap();
    // The account that posted the bond quarantines the agent.
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_did": AGENT,
        "controller_did": CONTROLLER,
        "reason_code": 2,
        "evidence_hash": "ef".repeat(32),
    }))
    .unwrap();
    ex.execute_transaction(
        &tx(&owner, SELECTOR_KILLSWITCH_QUARANTINE, body, 2, 4_000),
        &mut state,
    )
    .await
    .unwrap();
    assert!(agent_bond_frozen(&state, AGENT, 4_000));
    let after_cooldown = 3_000 + (crate::native::DEFAULT_AGENT_BOND_COOLDOWN_MS as i64);
    let err = ex
        .execute_transaction(&withdraw(&owner, 3, after_cooldown), &mut state)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("frozen"), "{err}");
}

#[tokio::test]
async fn a_bond_returns_to_its_owner_after_the_cooldown() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let owner = vec![4u8; 32];
    state.set_balance(&owner, 100 * TNZO);
    bind_identity(&mut state, &owner, CONTROLLER);
    ex.execute_transaction(&post_bond(&owner, 10 * TNZO), &mut state)
        .await
        .unwrap();
    // Nobody else withdraws it.
    assert!(
        ex.execute_transaction(&withdraw(&[8u8; 32], 0, 3_000), &mut state)
            .await
            .is_err()
    );
    ex.execute_transaction(&withdraw(&owner, 1, 3_000), &mut state)
        .await
        .unwrap();
    let early = ex
        .execute_transaction(&withdraw(&owner, 2, 4_000), &mut state)
        .await
        .unwrap_err();
    assert!(early.to_string().contains("cooldown"), "{early}");
    let before = state.get_balance(&owner);
    let r = ex
        .execute_transaction(
            &withdraw(
                &owner,
                2,
                3_000 + (crate::native::DEFAULT_AGENT_BOND_COOLDOWN_MS as i64),
            ),
            &mut state,
        )
        .await
        .unwrap();
    assert_eq!(r.logs[0].topics[0], b"BondReturned".to_vec());
    assert_eq!(state.get_balance(&owner) - before, 10 * TNZO);
    assert_eq!(
        state.get_balance(derive_bond_vault_address(AGENT).as_bytes()),
        0
    );
}

#[tokio::test]
async fn the_bond_record_in_chain_state_is_the_one_every_reader_sees() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let owner = vec![4u8; 32];
    state.set_balance(&owner, 100 * TNZO);
    bind_identity(&mut state, &owner, CONTROLLER);
    assert!(super::economy::agent_bond(&state, AGENT).is_none());
    ex.execute_transaction(&post_bond(&owner, 16 * TNZO), &mut state)
        .await
        .unwrap();
    let bond = super::economy::agent_bond(&state, AGENT).unwrap();
    assert_eq!(
        (
            bond.controller_did.as_str(),
            bond.amount,
            bond.state.as_str()
        ),
        (CONTROLLER, 16 * TNZO, "Active")
    );
    assert_eq!(
        super::economy::agent_bonds_of_controller(&state, CONTROLLER),
        vec![bond]
    );

    // A slash moves the record itself: every reader sees the residual.
    let pool_before = pool(&state);
    let (mut changes, mut logs) = (Vec::new(), Vec::new());
    let taken = super::economy::slash_agent_bond(&mut state, AGENT, 2_500, &mut changes, &mut logs)
        .unwrap();
    assert_eq!(taken, 4 * TNZO);
    assert_eq!(pool(&state) - pool_before, taken);
    let bond = super::economy::agent_bond(&state, AGENT).unwrap();
    assert_eq!((bond.amount, bond.state.as_str()), (12 * TNZO, "Active"));

    ex.execute_transaction(&withdraw(&owner, 1, 3_000), &mut state)
        .await
        .unwrap();
    let listed = super::economy::agent_bonds_of_controller(&state, CONTROLLER);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, "Cooldown");
    assert!(!listed[0].is_active());
}

/// Every serving role's stake owes its service: an RPC operator judged
/// unavailable pays the SLA penalty from its `rpc` stake. Roles that answer
/// through their own evidence, and spellings other than the canonical one,
/// name no subject.
#[tokio::test]
async fn an_unavailable_rpc_stake_is_slashed_into_the_pool() {
    use tenzro_types::network::NetworkRole;
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let vs = validators(&mut state);
    let owner = vec![9u8; 32];
    let stake = 100_000 * TNZO;
    role_stake::bond_role_for_test(&mut state, &owner, NetworkRole::Rpc, stake);
    role_stake::bond_role_for_test(&mut state, &owner, NetworkRole::Attestor, stake);
    let subject = role_stake_subject(&owner, NetworkRole::Rpc);
    assert_eq!(
        sla_subject(&state, &subject).unwrap().kind,
        SlaSubjectKind::RoleStake(NetworkRole::Rpc)
    );
    for role in [NetworkRole::Validator, NetworkRole::Attestor] {
        assert!(
            sla_subject(&state, &role_stake_subject(&owner, role)).is_none(),
            "{role:?}"
        );
    }
    assert!(
        sla_subject(
            &state,
            &format!("did:tenzro:role:RPC:{}", hex::encode(&owner))
        )
        .is_none()
    );
    // Unbonded for this role: no subject.

    let attest = |from: &[u8]| {
        let body = serde_json::to_vec(&serde_json::json!({
            "epoch": 10,
            "outcomes": [{ "provider_did": subject, "available": false, "capacity": null }],
        }))
        .unwrap();
        tx(from, SELECTOR_SLA_ATTEST, body, 0, 11 * MARKET_EPOCH_MS + 1)
    };
    ex.execute_transaction(&attest(&vs[0]), &mut state)
        .await
        .unwrap();
    ex.execute_transaction(&attest(&vs[1]), &mut state)
        .await
        .unwrap();
    let penalty = DEFAULT_SLA_UNAVAILABLE_PENALTY_GWEI as u128 * 1_000_000_000;
    assert_eq!(pool(&state), penalty);
    assert_eq!(
        read_role_stake(&state, &owner, NetworkRole::Rpc)
            .unwrap()
            .bonded,
        stake - penalty
    );
    assert_eq!(
        read_role_stake(&state, &owner, NetworkRole::Attestor)
            .unwrap()
            .bonded,
        stake
    );
}

const DELEGATED: &str = "did:tenzro:machine:controller:delegated";

/// Bind `account` to `did`, as a registration does.
fn bind_identity(state: &mut StateAdapter, account: &[u8], did: &str) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(account).as_bytes(),
        did.as_bytes().to_vec(),
    );
}

fn post_bond_for(owner: &[u8], agent: &str, controller: &str, nonce: u64) -> VmTransaction {
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_did": agent,
        "controller_did": controller,
        "amount": TNZO,
    }))
    .unwrap();
    tx(owner, SELECTOR_POST_AGENT_BOND, body, nonce, 1_000)
}

fn increase_bond(from: &[u8], agent: &str, amount: u128, nonce: u64, at: i64) -> VmTransaction {
    let body =
        serde_json::to_vec(&serde_json::json!({ "agent_did": agent, "amount": amount })).unwrap();
    tx(from, SELECTOR_INCREASE_AGENT_BOND, body, nonce, at)
}

#[tokio::test]
async fn a_bond_is_posted_only_by_the_agents_controller() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let stranger = vec![9u8; 32];
    let controller = vec![4u8; 32];
    state.set_balance(&stranger, 100 * TNZO);
    state.set_balance(&controller, 100 * TNZO);
    bind_identity(&mut state, &controller, CONTROLLER);

    // An account that is not the controller cannot post in its name.
    assert!(
        ex.execute_transaction(
            &post_bond_for(&stranger, DELEGATED, CONTROLLER, 0),
            &mut state
        )
        .await
        .is_err(),
        "a stranger squatted the agent's bond"
    );
    assert!(super::economy::agent_bond(&state, DELEGATED).is_none());
    // The controller cannot bond an agent that is not its own.
    let elsewhere = "did:tenzro:machine:someoneelse:agent";
    assert!(
        ex.execute_transaction(
            &post_bond_for(&controller, elsewhere, CONTROLLER, 0),
            &mut state
        )
        .await
        .is_err()
    );
    ex.execute_transaction(
        &post_bond_for(&controller, DELEGATED, CONTROLLER, 0),
        &mut state,
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn an_autonomous_agent_posts_its_own_bond_with_its_device_key() {
    use tenzro_crypto::composite::HybridSigner as _;
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let device = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(0x41);
    let key = device.public_key().p256.clone();
    let account = tenzro_crypto::composite::account_slot(&key).to_vec();
    state.set_balance(&account, 100 * TNZO);
    let did = tenzro_types::did_derivation::machine_did(&key);

    // Another key cannot post as that agent.
    let other = tenzro_crypto::composite::testing::TestHybridSigner::p256_only(0x42);
    let other_key = other.public_key().p256.clone();
    let other_account = tenzro_crypto::composite::account_slot(&other_key).to_vec();
    state.set_balance(&other_account, 100 * TNZO);
    let mut forged = post_bond_for(&other_account, &did, &did, 0);
    forged.public_key = Some(other_key);
    assert!(ex.execute_transaction(&forged, &mut state).await.is_err());

    let mut own = post_bond_for(&account, &did, &did, 0);
    own.public_key = Some(key);
    ex.execute_transaction(&own, &mut state).await.unwrap();
    assert!(
        super::economy::agent_bond(&state, &did)
            .unwrap()
            .is_active()
    );
}

#[tokio::test]
async fn only_the_owner_tops_up_an_active_bond() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let owner = vec![4u8; 32];
    let stranger = vec![9u8; 32];
    state.set_balance(&owner, 100 * TNZO);
    state.set_balance(&stranger, 100 * TNZO);
    bind_identity(&mut state, &owner, CONTROLLER);
    ex.execute_transaction(&post_bond_for(&owner, DELEGATED, CONTROLLER, 0), &mut state)
        .await
        .unwrap();
    assert!(
        ex.execute_transaction(
            &increase_bond(&stranger, DELEGATED, 1, 0, 2_000),
            &mut state
        )
        .await
        .is_err(),
        "a stranger topped up someone else's bond"
    );
    let body = serde_json::to_vec(&serde_json::json!({ "agent_did": DELEGATED })).unwrap();
    ex.execute_transaction(
        &tx(&owner, SELECTOR_WITHDRAW_AGENT_BOND, body, 1, 3_000),
        &mut state,
    )
    .await
    .unwrap();
    // A pending withdrawal is not reset by a top-up, the owner's included.
    assert!(
        ex.execute_transaction(&increase_bond(&owner, DELEGATED, 1, 2, 4_000), &mut state)
            .await
            .is_err()
    );
    assert_eq!(
        super::economy::agent_bond(&state, DELEGATED).unwrap().state,
        "Cooldown"
    );
}

#[tokio::test]
async fn a_kill_switch_needs_the_agents_real_controller() {
    let ex = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let attacker = vec![7u8; 32];
    let attacker_did = "did:tenzro:human:attacker";
    state.set_balance(&attacker, 100 * TNZO);
    bind_identity(&mut state, &attacker, attacker_did);
    for (selector, extra) in [
        (
            SELECTOR_KILLSWITCH_PAUSE,
            serde_json::json!({ "until": null }),
        ),
        (
            SELECTOR_KILLSWITCH_TERMINATE,
            serde_json::json!({ "slash_bps": 0 }),
        ),
    ] {
        let mut body = serde_json::json!({
            "agent_did": DELEGATED,
            "controller_did": attacker_did,
            "reason_code": 1,
        });
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let t = tx(
            &attacker,
            selector,
            serde_json::to_vec(&body).unwrap(),
            0,
            2_000,
        );
        assert!(
            ex.execute_transaction(&t, &mut state).await.is_err(),
            "an unrelated identity used the kill switch"
        );
    }
    // The real controller of an agent that does not exist has nothing to pause.
    let controller = vec![4u8; 32];
    bind_identity(&mut state, &controller, CONTROLLER);
    state.set_balance(&controller, 100 * TNZO);
    let body = serde_json::to_vec(&serde_json::json!({
        "agent_did": DELEGATED,
        "controller_did": CONTROLLER,
        "reason_code": 1,
        "until": null,
    }))
    .unwrap();
    assert!(
        ex.execute_transaction(
            &tx(&controller, SELECTOR_KILLSWITCH_PAUSE, body, 0, 2_000),
            &mut state
        )
        .await
        .is_err()
    );
}
