// SPDX-License-Identifier: Apache-2.0
#[test_only, allow(implicit_const_copy)]
module tenzro_bridge::finality_client_tests;

use sui::test_scenario as ts;
use tenzro_bridge::finality_client::{Self, FinalityClient};

const ADMIN: address = @0xA;
/// A real finality proof of a test build of the finality program.
const IMAGE_ID: vector<u8> = x"517522e01ae5337fd174185532e72ab8312f6acd746357eb60327c30206c0c17";
const JOURNAL: vector<u8> = x"00000000000000000000000000000000000000000000000000000000000005396e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e0000000000000000000000000000000000000000000000000000000000000000f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e4810000000000000000000000000000000000000000000000000000000000000007773a42135c308e8437e8c24a5361639a088273159620a6099d0c82822b75b09f000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000265e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5eb1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b15757575757575757575757575757575757575757575757575757575757575757c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2000000000000000000000000000000000000000000000000000001a0c4506c00";
const SEAL: vector<u8> = x"73c457ba06bef3c4faaf51de1a9a9e981649531edfeb7615622853360df9fc869ad4f81327e61d048c194ed7ce47b9a72a1edf667714f58288b5f01f8bb2cda133db45222e585c9c0fe583e5f1bae75685e87570c90238b1ce121c40e5ba12de3c78ff090be0f13975a5da7ec68de2db52394cb9ce062e717af61cf5b7c23c2867c79d771a272fde6f81d77b80b06af002fbfbdb85b70d57dfc2fb3fad797e01c2604b7a0c601f308a74da9178fc1f89780c4c8682e76a0a2ac7313ae46545f8f9616c232875468ad44c2c251a25b9ef126425dda4d8faefba3649508592d2d380be29f314f0a24280dd0c30962255d456565b8868a7c647bf33eacd0a6275bba67a9117";
const GENESIS: vector<u8> = x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e";
const COMMITTEE: vector<u8> = x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481";
const STATE_ROOT: vector<u8> = x"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
const NEXT_COMMITTEE: vector<u8> = x"c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";

fun client(chain_id: u64, committee: vector<u8>): ts::Scenario {
    let mut s = ts::begin(ADMIN);
    finality_client::create(IMAGE_ID, chain_id, GENESIS, committee, s.ctx());
    s.next_tx(ADMIN);
    s
}

#[test]
fun a_real_proof_finalizes_its_checkpoint_and_hands_over() {
    let mut s = client(1337, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    assert!(c.submit(JOURNAL, SEAL) == 7);
    assert!(c.state_root(7) == STATE_ROOT);
    assert!(c.timestamp_ms(7) == 1790000000000);
    assert!(c.latest_index() == 7);
    assert!(c.committee_root(1) == NEXT_COMMITTEE);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EAlreadyFinal)]
fun a_checkpoint_is_final_once() {
    let mut s = client(1337, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    c.submit(JOURNAL, SEAL);
    c.submit(JOURNAL, SEAL);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EInvalidProof)]
fun a_journal_the_proof_does_not_commit_is_refused() {
    let mut s = client(1337, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    let mut j = JOURNAL;
    *&mut j[8 * 32] = 0x5f;
    c.submit(j, SEAL);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EInvalidProof)]
fun a_tampered_seal_is_refused() {
    let mut s = client(1337, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    let mut seal = SEAL;
    // C's y word: the point stays well formed only if it is still on the curve.
    let last = seal[4 + 7 * 32 + 31];
    *&mut seal[4 + 6 * 32 + 31] = last;
    c.submit(JOURNAL, seal);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EWrongSelector)]
fun a_seal_for_another_verifier_is_refused() {
    let mut s = client(1337, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    let mut seal = SEAL;
    *&mut seal[0] = 0;
    c.submit(JOURNAL, seal);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EWrongChain)]
fun a_proof_of_another_chain_is_refused() {
    let mut s = client(1, COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    c.submit(JOURNAL, SEAL);
    ts::return_shared(c);
    s.end();
}

#[test, expected_failure(abort_code = finality_client::EUnknownCommittee)]
fun a_checkpoint_of_another_committee_is_refused() {
    let mut s = client(1337, NEXT_COMMITTEE);
    let mut c = s.take_shared<FinalityClient>();
    c.submit(JOURNAL, SEAL);
    ts::return_shared(c);
    s.end();
}
