// SPDX-License-Identifier: Apache-2.0
// The shared vectors (sdk/fixtures/remote_grant) as Sui constants.
#[test_only, allow(implicit_const_copy)]
module tenzro_bridge::agent_account_tests;

use sui::clock;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;
use tenzro_bridge::agent_account::{Self, AgentAccount, Registry};
use tenzro_bridge::finality_client::{Self, FinalityClient};
use tenzro_bridge::settlement_lock::{Self, SettlementLock};

const DID: vector<u8> = b"did:tenzro:machine:vectors:agent";
const ACCOUNT: address = @0xd18320f52843d490821d1ac88c5fb2598ec66897a4fdac2c7a72c25fc258c125;
const CAIP19: vector<u8> = b"sui:mainnet/coin:0000000000000000000000000000000000000000000000000000000000000002::sui::SUI";
const ROOT_V1: vector<u8> = x"fbd4a40025f4621b24d48405281eca86121a7cd8b581cd784395f5f8496d8613";
const ROOT_V2: vector<u8> = x"661604fa855e0255632754119be4a773df36f6fefdbda76b616bee74f73e9b36";
const GRANT_V1: vector<u8> = x"01f24241fafd31d91854235524b8a718cbbcba3cac9175281e083117bd325f2cd0d18320f52843d490821d1ac88c5fb2598ec66897a4fdac2c7a72c25fc258c1258d23e2fc446f04e7bc15113c3b53dbf2426f3fa2d62f0614ffd7409b4837318400000000000000010000000000000001000001a3185c5000000001a3186577c07655bfc262be84a14a4641fcfe99a5c64de85763de3ce9e9f0403e7c1e69dcde000000000000000000000000000003e8000000000000000000000000000001900000000000000000000000000000012c97f9b7a0c1cb347afda41eb96cc4b76555e3f70aa5e0513ed512500e731f9c1f259983f7572ebcd4beeb3d0929068978a0b1f4093e6da8cffc370010c9da24d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00";
const PROOF_V1: vector<u8> = x"0009d86093dc7fca5b1b31dc4114fda728039e5f50689097e3d56fde58e04e32e2133375385a5d75aa66f98386c1318e37e6cfac5ce48f5172c87289753e361356f6977d9c5cb7ad273d262f782c296480989f5f47689d411dada6dfbbd8bdc9a9e8b5710ace03a3541bd16fd73808cf08688510ca06c0adfaeda8920e7fc73b09d0f1d7bff8a5bef673f1a9eb5f75dde1e4463a962ad1290ee493a45065a42bcc53be8d8bd8e2a9411718cbfd5164d8dd9de4949987c6d490672a1a4ede9ca29a6bd6cd33fee0195a0de0b3f9e34e860d6bbe3d0d3d8d6901a23097ec47c387b5830000000000000000000000000000000000000000000000000000000000000000b52b759720eab2e5eae8e3ae4ba0c9db85c684fda1102a4702561ab4053c39be0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const GRANT_V2: vector<u8> = x"01f24241fafd31d91854235524b8a718cbbcba3cac9175281e083117bd325f2cd0d18320f52843d490821d1ac88c5fb2598ec66897a4fdac2c7a72c25fc258c1258d23e2fc446f04e7bc15113c3b53dbf2426f3fa2d62f0614ffd7409b4837318400000000000000010000000000000002000001a3185c5000000001a3186577c07655bfc262be84a14a4641fcfe99a5c64de85763de3ce9e9f0403e7c1e69dcde000000000000000000000000000003e8000000000000000000000000000001900000000000000000000000000000012c97f9b7a0c1cb347afda41eb96cc4b76555e3f70aa5e0513ed512500e731f9c1f259983f7572ebcd4beeb3d0929068978a0b1f4093e6da8cffc370010c9da24d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a01";
const PROOF_V2: vector<u8> = x"000912bc435c79d9c30961350c61e39d15e65f0d176f45ac113a5d450826953635150ab99dcd970a3319e3dc82582f09214566e68a49940d3597462fac66ae6ec421977d9c5cb7ad273d262f782c296480989f5f47689d411dada6dfbbd8bdc9a9e8b5710ace03a3541bd16fd73808cf08688510ca06c0adfaeda8920e7fc73b09d0f1d7bff8a5bef673f1a9eb5f75dde1e4463a962ad1290ee493a45065a42bcc5368ba792df76f46cbac7c44b0cde3328afbce9811a18aa728973678bad1ae80fed6cd33fee0195a0de0b3f9e34e860d6bbe3d0d3d8d6901a23097ec47c387b5830000000000000000000000000000000000000000000000000000000000000000b52b759720eab2e5eae8e3ae4ba0c9db85c684fda1102a4702561ab4053c39be0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const TREE_KEY: vector<u8> = x"71bbbe400119d78bffc7295c773a615f7ae833d3ae753609b49099970b260ed1";
const ACTION: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00177061793a3a73706c69745f616e645f7472616e73666572000000000000000000000000000000640000000000000000000000000000000500000003010203";
const BIG: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00177061793a3a73706c69745f616e645f7472616e736665720000000000000000000000000000015e0000000000000000000000000000000500000003010203";
const OTHER_TARGET: vector<u8> = x"0020cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc00177061793a3a73706c69745f616e645f7472616e73666572000000000000000000000000000000640000000000000000000000000000000500000003010203";
const OVER_REFUND: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00177061793a3a73706c69745f616e645f7472616e73666572000000000000000000000000000000640000000000000000000000000000000b00000003010203";
const SIG: vector<u8> = x"0782ab06da0fbb34c4c4b84e7a6b83dcaf60e69d949e0f952bb4d96a85bdd0de0b46632c63904af2e72c8ebfc85bbd27f32867a172575428940369af855b1750";
const SIG_HIGH_S: vector<u8> = x"0782ab06da0fbb34c4c4b84e7a6b83dcaf60e69d949e0f952bb4d96a85bdd0def4b99cd29c6fb50e18d3714037a442d7c9be930c34c04a5c5fb6611377080e01";
const STRANGER_KEY: vector<u8> = x"045b36890dacbd7c9a96bb74a1ee28b3d2d75b72e09a20ef25cf8e6fd8a9f0350d0e14bed8d4682a34d83538bdff5b96e89a6666ec0db5745d02fa1210072df75a";
const STRANGER_SIG: vector<u8> = x"897e520e853173a0407fbfb4a2aea248d7426301d757d990858a7ba1bd39edc4208c7716f7de100b6d747339c2fdd3cbdfc9c13f52cf9f6d65bc0a4ed0895859";
const BIG_SIG0: vector<u8> = x"d4e1ee387029571e626e14352c60edecb522d9042386ebb3ae59962c9eef1f6c32a1212f6313280a073a26c508fb8031d7689a43b4efd5166df1b766ba89f463";
const BIG_SIG1: vector<u8> = x"5841127db47dd148637e41379289c8703428041f76007f14171baa8ed39cb9de49da4fba7107ffab10892af519e1c865c33ab98b8f7c4fca22cf0225a74c583a";
const BIG_SIG2: vector<u8> = x"608fbb76073280b022c89bdd514e545e1f670d34fc2cdaff22909c9c6dbfecc7261161ead86f25be577bca33a7ad86dfc56929b99a9f1ca04a5d654604054671";
const OTHER_SIG: vector<u8> = x"8c330e08cdd1d7dc3c98b349fc3c6e92ed2c2e31367e15adb3441bb0ab0168d30f42b9852724ac0fca53c3b6ae6907811e3980ea38c026946db5f38cf5e7efd9";
const KEY0: vector<u8> = x"040217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794";
const KEY1: vector<u8> = x"04d65a93977caa3d1b081852ff57a79e465f1660577304baead505dd3a48589cf350185e895372df6221ea3a137557e473fddb6755f05bd507c3c533fce9c91285";
const KEY2: vector<u8> = x"0451a7580833898ea1b183cbd7350a4099078c6ef1c1e18e970cd7683035f25e7d0110522712b0b5a7cff081685486984a94e6831edac46e7360fa9d834a7a81a1";
const OP0: vector<u8> = b"did:tenzro:human:operator-a";
const OP1: vector<u8> = b"did:tenzro:human:operator-b";
const OP2: vector<u8> = b"did:tenzro:human:operator-a";
const PROOF0: vector<u8> = x"c6474d27a0d5c3decf7957d4cbad724f98af1089ca35abf0d71af7f088b7febb6185632464d9f8b8720fcd8e42674f61d9de47e4f532c06f91d37ecb53c9e365";
const PROOF1: vector<u8> = x"12a04b8a95ed6fcb7056a72b531aaef2175da321292c69b4b4710b584c251cb16185632464d9f8b8720fcd8e42674f61d9de47e4f532c06f91d37ecb53c9e365";
const PROOF2: vector<u8> = x"195df72aa20bcdf8479c7ff054a0a0adfc8142483d7db619635f2820dfc191a4";
const TARGET_PROOF: vector<u8> = x"0fe9f34c6f69fc9e369b8d1648303978933209dc4f0defc673e71226c577160a";
const NOW_MS: u64 = 1800000001000;
const NOT_AFTER_MS: u64 = 1800000600000;
const TARGET: address = @0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

fun setup(): (ts::Scenario, clock::Clock) {
    let mut s = ts::begin(@0xA);
    finality_client::create(x"0101010101010101010101010101010101010101010101010101010101010101", 1337, x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e", x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481", s.ctx());
    s.next_tx(@0xA);
    let mut c = s.take_shared<FinalityClient>();
    c.record_for_testing(1, ROOT_V1, NOW_MS);
    c.record_for_testing(2, ROOT_V2, NOW_MS);
    agent_account::create_registry(&c, b"sui:mainnet", s.ctx());
    ts::return_shared(c);
    s.next_tx(@0xA);
    let mut r = s.take_shared<Registry>();
    assert!(agent_account::create_account(&mut r, DID) == ACCOUNT);
    ts::return_shared(r);
    s.next_tx(@0xA);
    let mut a = s.take_shared<AgentAccount>();
    agent_account::deposit(&mut a, coin::mint_for_testing<SUI>(1_000_000, s.ctx()));
    ts::return_shared(a);
    s.next_tx(@0xB);
    let mut clk = clock::create_for_testing(s.ctx());
    clk.set_for_testing(NOW_MS);
    (s, clk)
}

fun sync(s: &mut ts::Scenario, index: u64, grant: vector<u8>, proof: vector<u8>) {
    let mut a = s.take_shared<AgentAccount>();
    let r = s.take_shared<Registry>();
    let c = s.take_shared<FinalityClient>();
    agent_account::sync(&mut a, &r, &c, index, grant, proof, CAIP19, x"77");
    ts::return_shared(a);
    ts::return_shared(r);
    ts::return_shared(c);
    s.next_tx(@0xB);
}

fun act(s: &mut ts::Scenario, clk: &clock::Clock, action: vector<u8>, keys: vector<vector<u8>>, ops: vector<vector<u8>>, proofs: vector<vector<u8>>, sigs: vector<vector<u8>>) {
    let mut a = s.take_shared<AgentAccount>();
    agent_account::act<SUI>(&mut a, clk, action, keys, ops, proofs, sigs, TARGET_PROOF, s.ctx());
    ts::return_shared(a);
    s.next_tx(@0xB);
}

fun done(s: ts::Scenario, clk: clock::Clock) {
    clk.destroy_for_testing();
    s.end();
}

#[test]
fun the_account_is_where_tenzro_derives_it() {
    let (s, clk) = setup();
    assert!(agent_account::grant_tree_key(&DID, &b"sui:mainnet") == TREE_KEY);
    done(s, clk);
}

#[test]
fun a_signed_action_runs_under_a_synced_grant() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    let paid = s.take_from_address<coin::Coin<SUI>>(TARGET);
    assert!(paid.value() == 100);
    ts::return_to_address(TARGET, paid);
    let refund = s.take_from_address<coin::Coin<SUI>>(@0xB);
    assert!(refund.value() == 5);
    ts::return_to_address(@0xB, refund);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EBadSignature)]
fun a_replayed_action_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EKeyNotInRoot)]
fun a_key_outside_the_root_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, ACTION, vector[STRANGER_KEY], vector[OP0], vector[PROOF0], vector[STRANGER_SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EBadSignature)]
fun a_signature_by_another_key_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[STRANGER_SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EHighS)]
fun a_high_s_signature_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG_HIGH_S]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::ECosignRequired)]
fun a_large_action_needs_a_cosign() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, BIG, vector[KEY0], vector[OP0], vector[PROOF0], vector[BIG_SIG0]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::ECosignRequired)]
fun a_cosign_by_the_same_operator_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, BIG, vector[KEY0, KEY2], vector[OP0, OP2], vector[PROOF0, PROOF2], vector[BIG_SIG0, BIG_SIG2]);
    done(s, clk);
}

#[test]
fun a_cosign_by_two_operators_runs() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, BIG, vector[KEY0, KEY1], vector[OP0, OP1], vector[PROOF0, PROOF1], vector[BIG_SIG0, BIG_SIG1]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::ETargetNotAllowed)]
fun a_target_outside_the_grant_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, OTHER_TARGET, vector[KEY0], vector[OP0], vector[PROOF0], vector[OTHER_SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::ERelayOverCap)]
fun a_refund_above_the_cap_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, OVER_REFUND, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EGrantVoid)]
fun a_void_stops_every_action() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    sync(&mut s, 2, GRANT_V2, PROOF_V2);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EStaleGrant)]
fun a_stale_grant_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 2, GRANT_V2, PROOF_V2);
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EBadStateProof)]
fun a_grant_not_under_the_root_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 2, GRANT_V1, PROOF_V1);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EOutsideWindow)]
fun an_expired_grant_acts_no_more() {
    let (mut s, mut clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    clk.set_for_testing(NOT_AFTER_MS + 1);
    act(&mut s, &clk, ACTION, vector[KEY0], vector[OP0], vector[PROOF0], vector[SIG]);
    done(s, clk);
}

const OVER: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00177061793a3a73706c69745f616e645f7472616e73666572000000000000000000000000000001910000000000000000000000000000000500000003010203";
const OVER_SIG: vector<u8> = x"12ae8319ad5282967ce91fb10a266297b4f1e2ae3060feb86412bd74ffa2c5d14253a3394267c42690afa87cb18f68cb170387d1f7ffc6993d82366addfe85b2";
const BIG1_SIG0: vector<u8> = x"10fbf789968db308dff50bddb1be4bf39966ad05039d03951386a2e6a5ad73e3292147128edeba518525182a32a1f48c8db780f4f9d3d1decf24cfddf1177302";
const BIG1_SIG1: vector<u8> = x"59edff6ba6e13ce5ecd2e9f3f05c88b044ac8b78e588106aaf90cb2bbe9f09f3694a47e667a53088a7681eca10f6a1406aa6c0263f8501382170ffa8e353ab92";
const BIG2_SIG0: vector<u8> = x"f846a27d8f9db29304377647c4f8ac7ba13f9e7f3af21a9de7b6e76ebb2a3d344cb85791757de9fb48a5a452169dbee1cad5a08df853a3c534c2a21c12e322b3";
const BIG2_SIG1: vector<u8> = x"8ca25a644c5cd0c95025c48b435ca899a060a58ddf86a632eebac575659e766b3e3cc95f8f66da9203874d7d5fe68504765c65de95010c633e24e8b4cad5f17e";

#[test, expected_failure(abort_code = agent_account::EOverPerAction)]
fun an_action_above_the_per_action_limit_is_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, OVER, vector[KEY0], vector[OP0], vector[PROOF0], vector[OVER_SIG]);
    done(s, clk);
}

#[test, expected_failure(abort_code = agent_account::EOverBudget)]
fun actions_past_the_budget_are_refused() {
    let (mut s, clk) = setup();
    sync(&mut s, 1, GRANT_V1, PROOF_V1);
    act(&mut s, &clk, BIG, vector[KEY0, KEY1], vector[OP0, OP1], vector[PROOF0, PROOF1], vector[BIG_SIG0, BIG_SIG1]);
    act(&mut s, &clk, BIG, vector[KEY0, KEY1], vector[OP0, OP1], vector[PROOF0, PROOF1], vector[BIG1_SIG0, BIG1_SIG1]);
    act(&mut s, &clk, BIG, vector[KEY0, KEY1], vector[OP0, OP1], vector[PROOF0, PROOF1], vector[BIG2_SIG0, BIG2_SIG1]);
    done(s, clk);
}

#[test]
fun a_paying_action_reports_in_the_layout_tenzro_decodes() {
    let mut data = vector[];
    let mut i = 0u64;
    while (i < 104) { data.push_back(((i % 251) as u8)); i = i + 1; };
    let mut action = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0003";
    action.append(b"pay");
    action.append(x"00000000000000000000000000000064");
    action.append(x"00000000000000000000000000000000");
    action.append(x"00000068");
    action.append(data);
    let report = agent_account::paid_report(&GRANT_V1, 7, &action, 100);
    let mut expected = x"04";
    expected.append(std::hash::sha2_256(b"sui:mainnet"));
    expected.append(sui::address::to_bytes(ACCOUNT));
    expected.append(std::hash::sha2_256(DID));
    expected.append(x"0000000000000001");
    expected.append(x"0000000000000007");
    expected.append(data);
    expected.append(x"00000000000000000000000000000064");
    assert!(report == expected);
}

#[test, expected_failure(abort_code = agent_account::EMalformedPayment)]
fun a_payment_without_its_pay_data_is_refused() {
    let mut action = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0003";
    action.append(b"pay");
    action.append(x"0000000000000000000000000000006400000000000000000000000000000000");
    action.append(x"00000001ff");
    agent_account::paid_report(&GRANT_V1, 0, &action, 100);
}


/// An exact grant whose one action locks 100 of SUI into `lock` for
/// recipient 0xcc..cc.
fun lock_action(lock: address, index: u8): vector<u8> {
    let mut a = x"0020";
    a.append(sui::address::to_bytes(lock));
    a.append(x"0004");
    a.append(b"lock");
    a.append(x"00000000000000000000000000000064");
    a.append(x"00000000000000000000000000000000");
    a.append(x"00000041");
    a.append(x"0707070707070707070707070707070707070707070707070707070707070707");
    a.push_back(index);
    a.append(x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    a
}

fun exact_grant(action: vector<u8>): vector<u8> {
    let mut g = vector[];
    let mut i = 0;
    while (i < 273) { g.push_back(GRANT_V1[i]); i = i + 1; };
    g.append(std::hash::sha2_256(action));
    i = 305;
    while (i < GRANT_V1.length()) { g.push_back(GRANT_V1[i]); i = i + 1; };
    g
}

#[test]
fun an_agent_locks_exactly_its_amount_and_gets_an_escape_back() {
    let (mut s, mut clk) = setup();
    let c = s.take_shared<FinalityClient>();
    settlement_lock::create(&c, 1000, s.ctx());
    ts::return_shared(c);
    s.next_tx(@0xB);
    let mut lock = s.take_shared<SettlementLock>();
    let mut a = s.take_shared<AgentAccount>();
    let action = lock_action(object::id_address(&lock), 0);
    agent_account::install_for_testing(&mut a, exact_grant(action), CAIP19);
    settlement_lock::lock_exact_from_agent<SUI>(&mut lock, &mut a, &clk, action, s.ctx());
    assert!(agent_account::balance_of<SUI>(&a) == 1_000_000 - 100);
    assert!(settlement_lock::stage<SUI>(&lock, x"0707070707070707070707070707070707070707070707070707070707070707", 0) == 1);
    // The account is the payer: an escape returns the coin to it.
    clk.set_for_testing(NOW_MS + 1000);
    settlement_lock::escape<SUI>(&mut lock, x"0707070707070707070707070707070707070707070707070707070707070707", 0, &clk, s.ctx());
    ts::return_shared(lock);
    ts::return_shared(a);
    s.next_tx(@0xB);
    let mut a = s.take_shared<AgentAccount>();
    let ticket = ts::most_recent_receiving_ticket<coin::Coin<SUI>>(&object::id(&a));
    agent_account::receive<SUI>(&mut a, ticket);
    assert!(agent_account::balance_of<SUI>(&a) == 1_000_000);
    ts::return_shared(a);
    done(s, clk);
}

#[test, expected_failure(abort_code = settlement_lock::ENotThisLock)]
fun an_agent_action_for_another_lock_is_refused() {
    let (mut s, clk) = setup();
    let c = s.take_shared<FinalityClient>();
    settlement_lock::create(&c, 1000, s.ctx());
    ts::return_shared(c);
    s.next_tx(@0xB);
    let mut lock = s.take_shared<SettlementLock>();
    let mut a = s.take_shared<AgentAccount>();
    let action = lock_action(@0xcafe, 0);
    agent_account::install_for_testing(&mut a, exact_grant(action), CAIP19);
    settlement_lock::lock_exact_from_agent<SUI>(&mut lock, &mut a, &clk, action, s.ctx());
    abort 0
}
