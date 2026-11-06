// SPDX-License-Identifier: Apache-2.0
// The shared vectors (sdk/fixtures/settlement_lock) as Sui constants.
#[test_only, allow(implicit_const_copy)]
module tenzro_bridge::settlement_lock_tests;

use sui::clock;
use sui::coin::{Self, Coin};
use sui::sui::SUI;
use sui::test_scenario as ts;
use tenzro_bridge::finality_client::{Self, FinalityClient};
use tenzro_bridge::settlement_lock::{Self, Accumulator, SettlementLock};

const ROOT: vector<u8> = x"a92146f006b15bd5dbc0c94eceffa98d48c4b0ef7319a11186ddcbf8f6d638db";
const COMMITTED: vector<u8> = x"ff39945f610e67d55c8c0ec52e62f47d49dd7a293527cd1c5d17b8401f33a02c";
const COMMITTED_LEG2: vector<u8> = x"bf631a93064b26e3c1e160a9d730ec40ac9ae0b26b4e207291f92d08e6b95406";
const COMMITTED_TREE_KEY: vector<u8> = x"6bfc720a2c166093f96acc594729391f3d7664a2e44d9b57567db1b783ae79f7";
const COMMIT_DECISION: vector<u8> = x"0101000001a3185c5000ff39945f610e67d55c8c0ec52e62f47d49dd7a293527cd1c5d17b8401f33a02c";
const COMMIT_PROOF: vector<u8> = x"000688721350fc3844c843af6e25e165c2ef88375225e7943129cac4e1953f21e59804e265ed3eaaa3cc015a322dc92af855c0815108a3e76f6b9c108a58fe5e956c977d9c5cb7ad273d262f782c296480989f5f47689d411dada6dfbbd8bdc9a9e803fb9b9977aa13d4fbef0aa862d0306eaeef9c96dfa886eb304d1b1ce3dcd47210487e9c5ee173182379369f9ed6420c28cb2d8679b6c42a748547a7d7529b0f8294c2c49cafe0c1a0e5306ea3da6ab3e4a3d8df48d12c579a1ef01b91c69ed20200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const ABORTED: vector<u8> = x"e84cdb4c63130097f6d891fe8d7e41e16dfe54f26f7e365d68227ce183f8d614";
const ABORT_DECISION: vector<u8> = x"0102000001a3185c5001e84cdb4c63130097f6d891fe8d7e41e16dfe54f26f7e365d68227ce183f8d614";
const ABORT_PROOF: vector<u8> = x"000988721350fc3844c843af6e25e165c2ef88375225e7943129cac4e1953f21e5989332eb71a7f419c871af869c0066943696a370089a79ca1e7c59bd6c954d742a1d9a12aea8a8ac8a0729e2bc71f30f90e3b96855deb84c4d1b4b29299a57b3b06d26bc466c3cb04f3a0a8cf0dc409141e8b595f8dadcc1f367929ce88b45460400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002b6fd26bfbc7f0fe5db62b0be125a3e885d033278e806b8763263e4dcc772dd70200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const UNDECIDED: vector<u8> = x"560e4d6671b804b2de028358b359be8b884adbcc3aa1e2926163a66d99d8bdc8";
const UNDECIDED_LEG0: vector<u8> = x"a7a2c1d7119554e52b3f93f4edbfb13c89cae0a8664c0ab6d876b9387ac446fc";
/// The commit decision rewritten to the undecided plan.
const FORGED: vector<u8> = x"0101000001a3185c5000560e4d6671b804b2de028358b359be8b884adbcc3aa1e2926163a66d99d8bdc8";
const OTHER_ROOT: vector<u8> = x"0707070707070707070707070707070707070707070707070707070707070707";
const PAYER: address = @0xB;
const RECIPIENT: address = @0xC;
const NOW_MS: u64 = 1_800_000_000_000;
const HORIZON_MS: u64 = 1_209_600_000;

fun setup(): (ts::Scenario, clock::Clock) {
    let mut s = ts::begin(@0xA);
    finality_client::create(x"0101010101010101010101010101010101010101010101010101010101010101", 1337, x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e", x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481", s.ctx());
    s.next_tx(@0xA);
    let mut c = s.take_shared<FinalityClient>();
    c.record_for_testing(7, ROOT, NOW_MS);
    c.record_for_testing(8, OTHER_ROOT, NOW_MS);
    settlement_lock::create(&c, HORIZON_MS, s.ctx());
    ts::return_shared(c);
    s.next_tx(PAYER);
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(NOW_MS);
    (s, clk)
}

fun lock(s: &mut ts::Scenario, clk: &clock::Clock, plan_id: vector<u8>, index: u8, amount: u64) {
    let mut l = s.take_shared<SettlementLock>();
    let c = coin::mint_for_testing<SUI>(amount, s.ctx());
    settlement_lock::lock(&mut l, plan_id, index, c, RECIPIENT, clk, s.ctx());
    ts::return_shared(l);
    s.next_tx(@0xD);
}

fun settle(s: &mut ts::Scenario, plan_id: vector<u8>, index: u8, checkpoint: u64, decision: vector<u8>, proof: vector<u8>) {
    let mut l = s.take_shared<SettlementLock>();
    let c = s.take_shared<FinalityClient>();
    settlement_lock::settle<SUI>(&mut l, &c, plan_id, index, checkpoint, decision, proof, s.ctx());
    ts::return_shared(l);
    ts::return_shared(c);
    s.next_tx(@0xD);
}

fun escape(s: &mut ts::Scenario, clk: &clock::Clock, plan_id: vector<u8>, index: u8) {
    let mut l = s.take_shared<SettlementLock>();
    settlement_lock::escape<SUI>(&mut l, plan_id, index, clk, s.ctx());
    ts::return_shared(l);
    s.next_tx(@0xD);
}

fun received(s: &ts::Scenario, who: address): u64 {
    let c = ts::take_from_address<Coin<SUI>>(s, who);
    let v = c.value();
    ts::return_to_address(who, c);
    v
}

fun stage(s: &mut ts::Scenario, plan_id: vector<u8>, index: u8): u8 {
    let l = s.take_shared<SettlementLock>();
    let st = settlement_lock::stage<SUI>(&l, plan_id, index);
    ts::return_shared(l);
    st
}

fun done(s: ts::Scenario, clk: clock::Clock) {
    clk.destroy_for_testing();
    s.end();
}

#[test]
fun leg_ids_and_the_decision_key_match_tenzro() {
    assert!(settlement_lock::leg_id(COMMITTED, 2) == COMMITTED_LEG2);
    assert!(settlement_lock::leg_id(UNDECIDED, 0) == UNDECIDED_LEG0);
    assert!(settlement_lock::decision_tree_key(COMMITTED) == COMMITTED_TREE_KEY);
}

/// The asset a Tenzro lock leg names for SUI (shared with the Tenzro decoder test).
#[test]
fun the_asset_of_sui_is_the_hash_of_its_type_name() {
    assert!(settlement_lock::asset_id<SUI>() == @0xbe4507e04f555448ca05c0c9f8345c5ea9f3e40e8616a20f5d5c18b40ef399eb);
}

#[test]
fun a_commit_pays_the_recipient() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 2, 400);
    settle(&mut s, COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
    assert!(received(&s, RECIPIENT) == 400);
    assert!(stage(&mut s, COMMITTED, 2) == 2);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::ENotLocked)]
fun a_leg_settles_once() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 2, 400);
    settle(&mut s, COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
    settle(&mut s, COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
    done(s, clk);
}

#[test]
fun an_abort_refunds_the_payer() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, ABORTED, 0, 250);
    settle(&mut s, ABORTED, 0, 7, ABORT_DECISION, ABORT_PROOF);
    assert!(received(&s, PAYER) == 250);
    assert!(stage(&mut s, ABORTED, 0) == 3);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::EUnproven)]
fun another_plans_decision_is_refused() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, UNDECIDED, 1, 300);
    settle(&mut s, UNDECIDED, 1, 7, COMMIT_DECISION, COMMIT_PROOF);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::EUnproven)]
fun a_forged_decision_is_refused() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, UNDECIDED, 1, 300);
    settle(&mut s, UNDECIDED, 1, 7, FORGED, COMMIT_PROOF);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::EUnproven)]
fun a_decision_not_under_the_root_is_refused() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 0, 100);
    settle(&mut s, COMMITTED, 0, 8, COMMIT_DECISION, COMMIT_PROOF);
    done(s, clk);
}

#[test, expected_failure(abort_code = finality_client::EUnknownCheckpoint)]
fun an_unknown_checkpoint_is_refused() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 0, 100);
    settle(&mut s, COMMITTED, 0, 9, COMMIT_DECISION, COMMIT_PROOF);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::ETooEarly)]
fun no_escape_before_the_horizon() {
    let (mut s, mut clk) = setup();
    lock(&mut s, &clk, UNDECIDED, 0, 500);
    clk.set_for_testing(NOW_MS + HORIZON_MS - 1);
    escape(&mut s, &clk, UNDECIDED, 0);
    done(s, clk);
}

#[test]
fun an_undecided_leg_escapes_after_the_horizon() {
    let (mut s, mut clk) = setup();
    lock(&mut s, &clk, UNDECIDED, 0, 500);
    clk.set_for_testing(NOW_MS + HORIZON_MS);
    escape(&mut s, &clk, UNDECIDED, 0);
    assert!(received(&s, PAYER) == 500);
    assert!(stage(&mut s, UNDECIDED, 0) == 3);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::EAlreadyLocked)]
fun a_leg_locks_once() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 1, 10);
    lock(&mut s, &clk, COMMITTED, 1, 10);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::EBadAmount)]
fun an_empty_coin_is_refused() {
    let (mut s, clk) = setup();
    lock(&mut s, &clk, COMMITTED, 1, 0);
    done(s, clk);
}

// recon.json: the running hash after its first entry and after all six, and
// the BCS of the Accumulator event (move_accumulator_event.hex).
const RECON_ACC_1: vector<u8> = x"87f572fcea568bf192ccb0e6b0485da44549bdcb28b5e9e3d1de73de97d6d344";
const RECON_ACC: vector<u8> = x"375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a";
const ACCUMULATOR_EVENT: vector<u8> = x"060000000000000020375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a";

fun recon(s: &mut ts::Scenario): (u64, vector<u8>) {
    let l = s.take_shared<SettlementLock>();
    let (n, acc) = settlement_lock::reconciliation(&l);
    ts::return_shared(l);
    s.next_tx(@0xD);
    (n, acc)
}

#[test]
fun the_reconciliation_hash_matches_the_shared_vector() {
    let (mut s, mut clk) = setup();
    lock(&mut s, &clk, COMMITTED, 0, 400);
    let (n, acc) = recon(&mut s);
    assert!(n == 1 && acc == RECON_ACC_1);
    lock(&mut s, &clk, ABORTED, 2, 1_000_000_000_000_000_000);
    settle(&mut s, COMMITTED, 0, 7, COMMIT_DECISION, COMMIT_PROOF);
    settle(&mut s, ABORTED, 2, 7, ABORT_DECISION, ABORT_PROOF);
    lock(&mut s, &clk, UNDECIDED, 1, 250);
    clk.set_for_testing(NOW_MS + HORIZON_MS);
    escape(&mut s, &clk, UNDECIDED, 1);
    let (n, acc) = recon(&mut s);
    assert!(n == 6 && acc == RECON_ACC);
    let l = s.take_shared<SettlementLock>();
    settlement_lock::checkpoint(&l);
    let events = sui::event::events_by_type<Accumulator>();
    assert!(events.length() == 1);
    assert!(sui::bcs::to_bytes(&events[0]) == ACCUMULATOR_EVENT);
    ts::return_shared(l);
    done(s, clk);
}
