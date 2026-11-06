//! What one settlement earns: provider work by the class its payee's bond
//! makes it, activity and royalty for the creators the payer attributed it
//! to, the treasury leg, and the bound that keeps every settlement costing
//! its parties more than it earns them.

use super::*;
use crate::state_adapter::StateAdapter;
use proptest::prelude::*;
use tenzro_token::rewards::{WorkClass, WorkRecord};
use tenzro_types::network::NetworkRole;
use tenzro_types::settlement::CallAttribution;

const TNZO: u128 = 1_000_000_000_000_000_000;

fn account(byte: u8) -> Address {
    Address::new([byte; 32])
}

/// Register `did` with `account` as its wallet, as a registration does.
fn register(state: &mut StateAdapter, account: Address, did: &str) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(account.as_bytes()).as_bytes(),
        did.as_bytes().to_vec(),
    );
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.into(),
        identity_type: "human".into(),
        display_name: String::new(),
        controller_pubkey: Vec::new(),
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: account,
        pq_verifying_key: Vec::new(),
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
        &super::super::identity_storage_key(did),
        serde_json::to_vec(&record).unwrap(),
    );
}

fn set_param(state: &mut StateAdapter, key: &str, value: u64) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        governed_param_key(key).as_bytes(),
        value.to_le_bytes().to_vec(),
    );
}

/// A compute bond under `did`, posted by `owner`.
fn bond_compute(state: &mut StateAdapter, owner: Address, did: &str) {
    let marker = serde_json::json!({
        "op": "Posted",
        "provider_address": hex::encode(owner.as_bytes()),
        "amount": (u128::MAX / 4).to_string(),
    });
    state.set_storage(
        &SYSTEM_ADDRESS,
        compute_bond_storage_key(did).as_bytes(),
        serde_json::to_vec(&marker).unwrap(),
    );
}

fn work(state: &StateAdapter) -> Vec<WorkRecord> {
    rewards::pending_work(state, 0)
}

fn weight_of(state: &StateAdapter, who: Address, class: WorkClass) -> u128 {
    work(state)
        .iter()
        .filter(|r| r.address == who && r.class == class)
        .map(|r| r.weight)
        .sum()
}

fn app(did: &str) -> Option<CallAttribution> {
    Some(CallAttribution {
        app_did: Some(did.into()),
        ..Default::default()
    })
}

/// A payer and a payee with distinct roots, both registered.
fn parties() -> (StateAdapter, Address, Address) {
    let mut state = StateAdapter::new();
    let (payer, payee) = (account(1), account(2));
    register(&mut state, payer, "did:tenzro:human:bob");
    register(&mut state, payee, "did:tenzro:human:carol");
    (state, payer, payee)
}

fn settle(
    state: &mut StateAdapter,
    payer: Address,
    payee: Address,
    value: u128,
    earning: &Earning,
) -> Payout {
    settle_payout(
        state,
        payer.as_bytes(),
        payee.as_bytes(),
        value,
        earning,
        &mut Vec::new(),
    )
    .unwrap()
}

/// Being paid earns the payee no activity reward: the ecosystem bucket is
/// for the apps, agents and tools a payer attributes its payment to.
#[test]
fn a_payee_earns_no_activity_reward_for_being_paid() {
    let (mut state, payer, payee) = parties();
    settle(&mut state, payer, payee, 100 * TNZO, &Earning::default());
    assert!(work(&state).is_empty(), "{:?}", work(&state));
}

/// The app a payer attributes a settlement to earns the activity share of
/// the fee, and the governed royalty out of the fee's treasury part: the
/// payer pays nothing more and the treasury takes less.
#[test]
fn an_attributed_app_earns_the_activity_share_and_its_royalty() {
    let (mut state, payer, payee) = parties();
    let maker = account(3);
    register(&mut state, maker, "did:tenzro:human:dana");
    set_param(&mut state, ACTIVITY_REWARD_FEE_PARAM, 4_000);
    set_param(&mut state, CREATOR_ROYALTY_FEE_PARAM, 1_000);
    let value = 100 * TNZO;
    let fee = tenzro_types::split::fee_allocation(value, &fee_params(&state));
    let treasury = derive_treasury_address();
    let before = state.get_balance(treasury.as_bytes());
    let earning = Earning {
        attribution: app("did:tenzro:human:dana"),
        ..Default::default()
    };
    let paid = settle(&mut state, payer, payee, value, &earning);
    assert_eq!(paid.credit, value - fee.fee, "the payee is paid as before");
    let royalty = tenzro_types::split::bps_of(fee.fee, 1_000);
    assert!(royalty > 0);
    assert_eq!(state.get_balance(maker.as_bytes()), royalty);
    assert_eq!(
        state.get_balance(treasury.as_bytes()) - before,
        fee.treasury - royalty
    );
    assert_eq!(
        weight_of(&state, maker, WorkClass::AppUsage),
        tenzro_types::split::bps_of(fee.fee, 4_000)
    );
    assert_eq!(weight_of(&state, payee, WorkClass::AppUsage), 0);
}

/// An attributed creator that shares a root with the payer or the payee, or
/// is not a registered identity, earns nothing.
#[test]
fn a_related_or_unregistered_creator_earns_nothing() {
    for did in [
        "did:tenzro:machine:bob:app",
        "did:tenzro:machine:carol:app",
        "did:tenzro:human:nobody",
    ] {
        let (mut state, payer, payee) = parties();
        set_param(&mut state, ACTIVITY_REWARD_FEE_PARAM, 4_000);
        set_param(&mut state, CREATOR_ROYALTY_FEE_PARAM, 1_000);
        if did != "did:tenzro:human:nobody" {
            register(&mut state, account(3), did);
        }
        let earning = Earning {
            attribution: app(did),
            ..Default::default()
        };
        settle(&mut state, payer, payee, 100 * TNZO, &earning);
        assert!(work(&state).is_empty(), "{did}: {:?}", work(&state));
        assert_eq!(state.get_balance(account(3).as_bytes()), 0, "{did}");
    }
}

/// A controller paid through an agent its terms name is one party with it,
/// whatever DID the agent carries: no provider work, no activity, no
/// royalty.
#[test]
fn a_controller_paying_through_its_own_agent_earns_nothing() {
    let mut state = StateAdapter::new();
    let (agent_wallet, controller, maker) = (account(1), account(2), account(3));
    let agent = "did:tenzro:machine:device1";
    register(&mut state, agent_wallet, agent);
    register(&mut state, controller, "did:tenzro:human:alice");
    register(&mut state, maker, "did:tenzro:human:dana");
    let terms = super::super::agent_terms::tests::Agent::terms(
        "did:tenzro:human:alice".into(),
        Default::default(),
    );
    super::super::agent_terms::store_terms_unapproved(
        &mut state,
        agent,
        &super::super::agent_terms::StoredAgentTerms {
            terms,
            root: tenzro_types::agent_terms::RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: None,
        },
    );
    bond_compute(&mut state, controller, "did:tenzro:human:alice");
    set_param(&mut state, ACTIVITY_REWARD_FEE_PARAM, 4_000);
    set_param(&mut state, CREATOR_ROYALTY_FEE_PARAM, 1_000);
    let earning = Earning {
        provider: Some(WorkClass::InferenceServed),
        payer_agent: Some(agent.into()),
        attribution: app("did:tenzro:human:dana"),
        network_share_paid: false,
    };
    settle(&mut state, agent_wallet, controller, 100 * TNZO, &earning);
    assert!(work(&state).is_empty(), "{:?}", work(&state));
    assert_eq!(state.get_balance(maker.as_bytes()), 0);
}

/// A payment to a bonded provider is provider work of the class its bond
/// makes it, at most the governed share of the fee; a payment to an account
/// holding no bond is none.
#[test]
fn a_bonded_payee_earns_provider_work_of_its_class() {
    let value = 100 * TNZO;
    let cases: [(&str, bool, Option<WorkClass>); 5] = [
        ("compute", true, Some(WorkClass::ComputeLease)),
        ("compute", false, Some(WorkClass::InferenceServed)),
        ("tee", false, Some(WorkClass::TeeSession)),
        ("rpc", false, Some(WorkClass::RpcTraffic)),
        ("none", true, None),
    ];
    for (bond, stream, class) in cases {
        let (mut state, payer, payee) = parties();
        match bond {
            "compute" => bond_compute(&mut state, payee, "did:tenzro:human:carol"),
            "tee" => super::super::role_stake::bond_role_for_test(
                &mut state,
                payee.as_bytes(),
                NetworkRole::TeeProvider,
                u128::MAX / 4,
            ),
            "rpc" => super::super::role_stake::bond_role_for_test(
                &mut state,
                payee.as_bytes(),
                NetworkRole::Rpc,
                u128::MAX / 4,
            ),
            _ => {}
        }
        let earning = super::super::payment_settlement::escrow_earning(
            &state,
            payee.as_bytes(),
            stream,
            None,
        );
        assert_eq!(earning.provider, class, "{bond} stream={stream}");
        let fee = tenzro_types::split::fee_allocation(value, &fee_params(&state)).fee;
        settle(&mut state, payer, payee, value, &earning);
        let rows = work(&state);
        match class {
            Some(c) => {
                assert_eq!(rows.len(), 1, "{rows:?}");
                assert_eq!((rows[0].address, rows[0].class), (payee, c));
                assert_eq!(rows[0].weight, tenzro_types::split::bps_of(fee, 4_000));
            }
            None => assert!(rows.is_empty(), "{rows:?}"),
        }
    }
}

/// The treasury leg of a class comes out of the provider's credit, is
/// credited to the treasury, and counts with the fee toward what the
/// settlement may earn.
#[test]
fn a_treasury_leg_is_collected_and_widens_the_reward_base() {
    let (mut state, payer, payee) = parties();
    bond_compute(&mut state, payee, "did:tenzro:human:carol");
    set_param(&mut state, TREASURY_LEG_COMPUTE_PARAM, 1_000);
    let value = 100 * TNZO;
    let fee = tenzro_types::split::fee_allocation(value, &fee_params(&state));
    let leg = tenzro_types::split::bps_of(value - fee.fee, 1_000);
    let treasury = derive_treasury_address();
    let before = state.get_balance(treasury.as_bytes());
    let earning =
        super::super::payment_settlement::escrow_earning(&state, payee.as_bytes(), true, None);
    let paid = settle(&mut state, payer, payee, value, &earning);
    assert_eq!(paid.credit, value - fee.fee - leg);
    assert_eq!(paid.treasury_leg, leg);
    assert_eq!(paid.burned, fee.burn);
    assert_eq!(
        state.get_balance(treasury.as_bytes()) - before,
        fee.treasury + leg
    );
    assert_eq!(
        weight_of(&state, payee, WorkClass::ComputeLease),
        tenzro_types::split::bps_of(fee.fee + leg, 4_000)
    );
    // Other classes keep their own rate: none at genesis.
    assert_eq!(treasury_leg_bps(&state, WorkClass::StorageServed), 0);
    assert_eq!(treasury_leg_bps(&state, WorkClass::AppUsage), 0);
}

/// Who a party in the property test is: a root, the account it is paid at,
/// and the DID it is registered under.
fn party(root: u8, slot: u8) -> (Address, String) {
    (
        Address::new([slot; 32]),
        format!("did:tenzro:machine:root{root}:p{slot}"),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For any settlement, any reward settings governance can reach, any
    /// treasury leg and any arrangement of roots among payer, provider and
    /// creators: everything the settlement hands back to its parties
    /// (provider weight, activity weight and royalty) stays within 90% of
    /// what it paid outside the trade, and the parties taken together, one
    /// root or several colluding ones, end poorer than they started.
    #[test]
    fn a_settlement_never_earns_its_parties_what_it_cost_them(
        value in 1u128..1_000_000 * TNZO,
        activity in 0u64..=9_000,
        provider_cut in 0u64..=9_000,
        royalty_cut in 0u64..=9_000,
        leg_bps in 0u64..=5_000,
        fee_bps in 0u64..=1_000,
        roots in proptest::collection::vec(0u8..3, 5),
        stream in any::<bool>(),
    ) {
        let activity = activity.min(9_000);
        let provider = provider_cut.min(9_000 - activity);
        let royalty = royalty_cut.min(9_000 - activity - provider);
        let mut state = StateAdapter::new();
        set_param(&mut state, ACTIVITY_REWARD_FEE_PARAM, activity);
        set_param(&mut state, rewards::PROVIDER_REWARD_COST_PARAM, provider);
        set_param(&mut state, CREATOR_ROYALTY_FEE_PARAM, royalty);
        set_param(&mut state, TREASURY_LEG_COMPUTE_PARAM, leg_bps);
        set_param(&mut state, TREASURY_LEG_INFERENCE_PARAM, leg_bps);
        set_param(&mut state, SETTLEMENT_FEE_PARAM, fee_bps);
        // Payer, payee and three creators, each under one of three roots.
        let people: Vec<(Address, String)> = roots
            .iter()
            .enumerate()
            .map(|(i, r)| party(*r, i as u8 + 1))
            .collect();
        for (a, did) in &people {
            register(&mut state, *a, did);
        }
        let (payer, payee) = (people[0].0, people[1].0);
        bond_compute(&mut state, payee, &people[1].1);
        let attribution = CallAttribution {
            app_did: Some(people[2].1.clone()),
            agent_did: Some(people[3].1.clone()),
            tool_did: Some(people[4].1.clone()),
        };
        let mut earning =
            super::super::payment_settlement::escrow_earning(&state, payee.as_bytes(), stream, None);
        earning.attribution = Some(attribution);
        let held_before: u128 = people.iter().map(|(a, _)| state.get_balance(a.as_bytes())).sum();
        state.set_balance(payer.as_bytes(), value);
        let held_before = held_before + value;
        let fee = tenzro_types::split::fee_allocation(value, &fee_params(&state));
        let paid = settle(&mut state, payer, payee, value, &earning);
        // The payer's value leaves; the payee is credited its share.
        state.set_balance(payer.as_bytes(), 0);
        let payee_bal = state.get_balance(payee.as_bytes());
        state.set_balance(payee.as_bytes(), payee_bal + paid.credit);
        let outside = value - paid.credit;
        prop_assert!(outside >= fee.fee);
        let rows = work(&state);
        let weights: u128 = rows.iter().map(|r| r.weight).sum();
        let held_after: u128 = people.iter().map(|(a, _)| state.get_balance(a.as_bytes())).sum();
        let royalties = held_after - paid.credit;
        // Everything handed back is within 90% of the outside cost.
        prop_assert!(
            (weights + royalties) * 10 <= outside * 9,
            "weights {weights} royalties {royalties} outside {outside}"
        );
        // A coupon never exceeds the weight it was matched to.
        let schedule = tenzro_token::rewards::MintingSchedule::for_epoch_ms(86_400_000).unwrap();
        let generous = tenzro_token::rewards::MintPolicy {
            base_tnzo_per_year: u64::MAX / 2,
            decay_bps_per_year: 0,
            floor_tnzo_per_year: 0,
            mult_ppm: tenzro_token::rewards::MINT_MULT_ONE_PPM,
            validator_bps: 0,
            provider_bps: 5_000,
            ecosystem_bps: 5_000,
            revenue_peg_bps: 10_000,
            validator_base_rights: 0,
            withheld_rights: 0,
        };
        let (_, coupons) = tenzro_token::rewards::settle_epoch(
            &schedule,
            &generous,
            0,
            0,
            &rows,
            tenzro_types::primitives::Timestamp::new(0),
        );
        let minted: u128 = coupons.iter().map(|c| c.amount).sum();
        prop_assert!(minted <= weights);
        // Taken together, the parties end poorer by at least a tenth of the
        // outside cost, however their roots are arranged.
        if outside > 0 {
            prop_assert!(
                (held_after + minted) * 10 + outside <= held_before * 10,
                "before {held_before} after {held_after} minted {minted} outside {outside}"
            );
        }
        // No party sharing the payer's or the payee's root earned anything.
        for (i, (a, _)) in people.iter().enumerate().skip(2) {
            if roots[i] == roots[0] || roots[i] == roots[1] {
                prop_assert_eq!(weight_of(&state, *a, WorkClass::AppUsage), 0);
            }
        }
        if roots[0] == roots[1] {
            prop_assert!(rows.is_empty());
        }
    }
}
