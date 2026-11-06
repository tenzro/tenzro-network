// SPDX-License-Identifier: Apache-2.0
#[test_only, allow(implicit_const_copy)]
module tenzro_bridge::bridge_tests;

use sui::bcs;
use sui::clock;
use sui::coin::Coin;
use sui::ecdsa_k1;
use sui::event;
use sui::hash::keccak256;
use sui::test_scenario as ts;
use tenzro_bridge::bridge::{Self, AdminCap, BRIDGE, Bridge, TransferOut};

const ADMIN: address = @0xA;
const USER: address = @0xB;
const TENZRO_CHAIN_ID: u64 = 1337;
const SUI_SELECTOR: u64 = 101;
const TENZRO_SELECTOR: u64 = 7777;
const RAMP: address = @0x3333333333333333333333333333333333333333333333333333333333333333;
const TOKEN: address = @0x2222222222222222222222222222222222222222222222222222222222222222;
const ENDPOINT: address = @0x4444444444444444444444444444444444444444444444444444444444444444;

/// The record Tenzro's Sui route decodes for the transfer sent in
/// `a_transfer_to_tenzro_emits_the_record_tenzro_decodes`.
const TRANSFER_OUT: vector<u8> = x"01000000000000006500000000000000611e000000000000000000000000000000000000000000000000000000000000000000000000000b22222222222222222222222222222222222222222222222222222222222222224444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500002cf61a24a2290000000000000000";

/// An outbound record Tenzro stores, and the digest its committee signs
/// (Keccak-256 of the outbound domain, chain id, route key and record).
const OUTBOUND: vector<u8> = x"0700000000000000611e0000000000006500000000000000111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000b0000f444829163450000000000000000";
const OUTBOUND_DIGEST: vector<u8> = x"acd22395cc48dfd1ef3fe31ba9e247340c6e3471882dce2651b746c278428214";

/// The digest that hands this module over to set 2 of members `[0x41; 20]`,
/// `[0x42; 20]`, `[0x43; 20]`, threshold 2, expiring at Unix second
/// 2,000,000,000.
const HANDOVER_DIGEST: vector<u8> = x"e9164c73275dcd8c53dfa69e8e2cdbaf8aa8a9aa17a3ee109eef88d53b9b1257";

fun keypair(seed: u8): ecdsa_k1::KeyPair {
    let mut s = vector[];
    let mut i = 0u64;
    while (i < 32) { s.push_back(seed); i = i + 1; };
    ecdsa_k1::secp256k1_keypair_from_seed(&s)
}

fun eth_address(kp: &ecdsa_k1::KeyPair): vector<u8> {
    let full = ecdsa_k1::decompress_pubkey(ecdsa_k1::public_key(kp));
    let mut key = vector[];
    let mut i = 1;
    while (i < 65) { key.push_back(full[i]); i = i + 1; };
    let h = keccak256(&key);
    let mut a = vector[];
    let mut j = 12;
    while (j < 32) { a.push_back(h[j]); j = j + 1; };
    a
}

fun setup(): ts::Scenario {
    let mut s = ts::begin(ADMIN);
    bridge::init_for_testing(s.ctx());
    s.next_tx(ADMIN);
    let cap = s.take_from_sender<AdminCap>();
    let mut b = s.take_shared<Bridge>();
    let committee = vector[eth_address(&keypair(1)), eth_address(&keypair(2)), eth_address(&keypair(3))];
    bridge::configure(cap, &mut b, TENZRO_CHAIN_ID, b"bridge_route:contract:sui", SUI_SELECTOR, TENZRO_SELECTOR, RAMP, TOKEN, ENDPOINT, committee, 2, 1, 1_000_000);
    ts::return_shared(b);
    s
}

fun sign(seeds: vector<u8>, preimage: &vector<u8>): vector<vector<u8>> {
    let mut out = vector[];
    let mut i = 0;
    while (i < seeds.length()) {
        let kp = keypair(seeds[i]);
        out.push_back(ecdsa_k1::secp256k1_sign(ecdsa_k1::private_key(&kp), preimage, 0, true));
        i = i + 1;
    };
    out
}

#[test]
fun a_transfer_to_tenzro_emits_the_record_tenzro_decodes() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let coin = bridge::mint_for_testing(&mut b, 3_000_000_000, s.ctx());
    bridge::send_to_tenzro(&mut b, coin, @0x5555555555555555555555555555555555555555555555555555555555555555, s.ctx());
    let events = event::events_by_type<TransferOut>();
    assert!(events.length() == 1);
    assert!(bcs::to_bytes(&events[0]) == TRANSFER_OUT);
    assert!(bridge::sequence(&b) == 1);
    ts::return_shared(b);
    s.end();
}

#[test]
fun the_committee_digest_is_the_one_tenzro_computes() {
    let mut s = setup();
    s.next_tx(USER);
    let b = s.take_shared<Bridge>();
    assert!(keccak256(&bridge::outbound_preimage(&b, &OUTBOUND)) == OUTBOUND_DIGEST);
    ts::return_shared(b);
    s.end();
}

#[test]
fun a_record_the_committee_signed_is_executed_once() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[1, 3], &preimage), &c, s.ctx());
    assert!(bridge::is_executed(&b, 7));
    c.destroy_for_testing();
    ts::return_shared(b);
    s.next_tx(USER);
    let coin = s.take_from_address<Coin<BRIDGE>>(USER);
    assert!(coin.value() == 5_000_000_000);
    ts::return_to_address(USER, coin);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EAlreadyExecuted, location = tenzro_bridge::bridge)]
fun a_record_is_not_executed_twice() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[1, 2], &preimage), &c, s.ctx());
    bridge::execute(&mut b, OUTBOUND, sign(vector[2, 3], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EBelowThreshold, location = tenzro_bridge::bridge)]
fun one_signer_or_one_signer_twice_is_not_a_quorum() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[2, 2], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EBelowThreshold, location = tenzro_bridge::bridge)]
fun signatures_by_strangers_are_refused() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[8, 9], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EBelowThreshold, location = tenzro_bridge::bridge)]
fun a_tampered_record_is_refused() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    let mut record = OUTBOUND;
    *vector::borrow_mut(&mut record, 150) = 0x0c;
    bridge::execute(&mut b, record, sign(vector[1, 2], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test]
fun the_handover_digest_is_the_one_tenzro_computes() {
    let mut s = setup();
    s.next_tx(USER);
    let b = s.take_shared<Bridge>();
    let members = vector[x"4141414141414141414141414141414141414141", x"4242424242424242424242424242424242424242", x"4343434343434343434343434343434343434343"];
    assert!(keccak256(&bridge::handover_preimage(&b, 2, &members, 2, 2_000_000_000)) == HANDOVER_DIGEST);
    ts::return_shared(b);
    s.end();
}

#[test]
fun the_committee_hands_over_only_with_its_own_quorum() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let next = vector[eth_address(&keypair(4)), eth_address(&keypair(5)), eth_address(&keypair(6))];
    let m = bridge::handover_preimage(&b, 2, &next, 2, 2_000_000);
    bridge::rotate_committee(&mut b, 2, next, 2, 2_000_000, sign(vector[1, 2], &m), &c);
    assert!(bridge::set_index(&b) == 2 && bridge::expires_at(&b) == 2_000_000);
    // The new committee executes.
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[4, 6], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EBelowThreshold, location = tenzro_bridge::bridge)]
fun a_handover_signed_by_the_next_committee_itself_is_refused() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let next = vector[eth_address(&keypair(4)), eth_address(&keypair(5)), eth_address(&keypair(6))];
    let m = bridge::handover_preimage(&b, 2, &next, 2, 2_000_000);
    bridge::rotate_committee(&mut b, 2, next, 2, 2_000_000, sign(vector[4, 5], &m), &c);
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EStaleSet, location = tenzro_bridge::bridge)]
fun a_handover_to_the_set_held_or_lower_is_refused() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let c = clock::create_for_testing(s.ctx());
    let next = vector[eth_address(&keypair(4)), eth_address(&keypair(5)), eth_address(&keypair(6))];
    let m = bridge::handover_preimage(&b, 1, &next, 2, 2_000_000);
    bridge::rotate_committee(&mut b, 1, next, 2, 2_000_000, sign(vector[1, 2], &m), &c);
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}

#[test, expected_failure(abort_code = tenzro_bridge::bridge::EExpired, location = tenzro_bridge::bridge)]
fun an_expired_committee_no_longer_executes() {
    let mut s = setup();
    s.next_tx(USER);
    let mut b = s.take_shared<Bridge>();
    let mut c = clock::create_for_testing(s.ctx());
    c.set_for_testing(1_000_001_000);
    let preimage = bridge::outbound_preimage(&b, &OUTBOUND);
    bridge::execute(&mut b, OUTBOUND, sign(vector[1, 2], &preimage), &c, s.ctx());
    c.destroy_for_testing();
    ts::return_shared(b);
    s.end();
}
