// SPDX-License-Identifier: Apache-2.0
// The shared vectors (sdk/fixtures/settlement_lock) as Aptos constants.
#[test_only]
module tenzro_bridge::settlement_lock_tests {
    use std::option;
    use std::string;
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use aptos_std::crypto_algebra;
    use tenzro_bridge::finality_client;
    use tenzro_bridge::settlement_lock;

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
    const PAYER: address = @0xb0b;
    const RECIPIENT: address = @0xc0c;
    const NOW_MS: u64 = 1800000000000;
    const HORIZON_MS: u64 = 1209600000;

    fun setup(fx: &signer, publisher: &signer) {
        setup_minting(fx, publisher, 1_000);
    }

    fun setup_minting(fx: &signer, publisher: &signer, minted: u64) {
        crypto_algebra::enable_cryptography_algebra_natives(fx);
        timestamp::set_time_has_started_for_testing(fx);
        timestamp::update_global_time_for_test(NOW_MS * 1000);
        let client = finality_client::create(publisher, x"0101010101010101010101010101010101010101010101010101010101010101", 1337, x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e", x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481");
        finality_client::record_for_testing(client, 7, ROOT, NOW_MS);
        finality_client::record_for_testing(client, 8, OTHER_ROOT, NOW_MS);
        settlement_lock::initialize(publisher, client, HORIZON_MS);
        let constructor = object::create_named_object(publisher, b"TUSD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Test USD"), string::utf8(b"TUSD"), 6, string::utf8(b""), string::utf8(b""),
        );
        let mint = fungible_asset::generate_mint_ref(&constructor);
        primary_fungible_store::mint(&mint, PAYER, minted);
    }

    fun asset(): object::Object<Metadata> {
        object::address_to_object<Metadata>(object::create_object_address(&@tenzro_bridge, b"TUSD"))
    }

    fun balance(who: address): u64 {
        primary_fungible_store::balance(who, asset())
    }

    #[test]
    fun leg_ids_and_the_decision_key_match_tenzro() {
        assert!(settlement_lock::leg_id(COMMITTED, 2) == COMMITTED_LEG2, 0);
        assert!(settlement_lock::leg_id(UNDECIDED, 0) == UNDECIDED_LEG0, 1);
        assert!(settlement_lock::decision_tree_key(COMMITTED) == COMMITTED_TREE_KEY, 2);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    fun a_commit_pays_the_recipient(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 2, asset(), 400, RECIPIENT);
        assert!(balance(settlement_lock::lock_address()) == 400, 0);
        settlement_lock::settle(COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
        assert!(balance(RECIPIENT) == 400 && balance(PAYER) == 600, 1);
        assert!(settlement_lock::stage(COMMITTED, 2) == 2, 2);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 403, location = tenzro_bridge::settlement_lock)]
    fun a_leg_settles_once(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 2, asset(), 400, RECIPIENT);
        settlement_lock::settle(COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
        settlement_lock::settle(COMMITTED, 2, 7, COMMIT_DECISION, COMMIT_PROOF);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    fun an_abort_refunds_the_payer(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, ABORTED, 0, asset(), 250, RECIPIENT);
        assert!(balance(PAYER) == 750, 0);
        settlement_lock::settle(ABORTED, 0, 7, ABORT_DECISION, ABORT_PROOF);
        assert!(balance(PAYER) == 1_000 && balance(RECIPIENT) == 0, 1);
        assert!(settlement_lock::stage(ABORTED, 0) == 3, 2);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 405, location = tenzro_bridge::settlement_lock)]
    fun another_plans_decision_is_refused(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, UNDECIDED, 1, asset(), 300, RECIPIENT);
        settlement_lock::settle(UNDECIDED, 1, 7, COMMIT_DECISION, COMMIT_PROOF);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 405, location = tenzro_bridge::settlement_lock)]
    fun a_forged_decision_is_refused(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, UNDECIDED, 1, asset(), 300, RECIPIENT);
        settlement_lock::settle(UNDECIDED, 1, 7, FORGED, COMMIT_PROOF);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 405, location = tenzro_bridge::settlement_lock)]
    fun a_decision_not_under_the_root_is_refused(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 0, asset(), 100, RECIPIENT);
        settlement_lock::settle(COMMITTED, 0, 8, COMMIT_DECISION, COMMIT_PROOF);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 107, location = tenzro_bridge::finality_client)]
    fun an_unknown_checkpoint_is_refused(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 0, asset(), 100, RECIPIENT);
        settlement_lock::settle(COMMITTED, 0, 9, COMMIT_DECISION, COMMIT_PROOF);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 406, location = tenzro_bridge::settlement_lock)]
    fun no_escape_before_the_horizon(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, UNDECIDED, 0, asset(), 500, RECIPIENT);
        timestamp::update_global_time_for_test((NOW_MS + HORIZON_MS - 1) * 1000);
        settlement_lock::escape(UNDECIDED, 0);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    fun an_undecided_leg_escapes_after_the_horizon(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, UNDECIDED, 0, asset(), 500, RECIPIENT);
        timestamp::update_global_time_for_test((NOW_MS + HORIZON_MS) * 1000);
        settlement_lock::escape(UNDECIDED, 0);
        assert!(balance(PAYER) == 1_000, 0);
        assert!(settlement_lock::stage(UNDECIDED, 0) == 3, 1);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 402, location = tenzro_bridge::settlement_lock)]
    fun a_leg_locks_once(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 1, asset(), 10, RECIPIENT);
        settlement_lock::lock(&payer, COMMITTED, 1, asset(), 10, RECIPIENT);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    #[expected_failure(abort_code = 404, location = tenzro_bridge::settlement_lock)]
    fun an_empty_amount_is_refused(fx: signer, publisher: signer, payer: signer) {
        setup(&fx, &publisher);
        settlement_lock::lock(&payer, COMMITTED, 1, asset(), 0, RECIPIENT);
    }

    // recon.json: the running hash after its first entry and after all six,
    // and the BCS of the Accumulator event (move_accumulator_event.hex).
    const RECON_ACC_1: vector<u8> = x"87f572fcea568bf192ccb0e6b0485da44549bdcb28b5e9e3d1de73de97d6d344";
    const RECON_ACC: vector<u8> = x"375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a";
    const ACCUMULATOR_EVENT: vector<u8> = x"060000000000000020375111922b0be21f25ad54b505467229080fd12340e5b01e4f56220cb3ecb58a";

    #[test(fx = @std, publisher = @tenzro_bridge, payer = @0xb0b)]
    fun the_reconciliation_hash_matches_the_shared_vector(fx: signer, publisher: signer, payer: signer) {
        setup_minting(&fx, &publisher, 2_000_000_000_000_000_000);
        settlement_lock::lock(&payer, COMMITTED, 0, asset(), 400, RECIPIENT);
        let (n, acc) = settlement_lock::reconciliation();
        assert!(n == 1 && acc == RECON_ACC_1, 0);
        settlement_lock::lock(&payer, ABORTED, 2, asset(), 1_000_000_000_000_000_000, RECIPIENT);
        settlement_lock::settle(COMMITTED, 0, 7, COMMIT_DECISION, COMMIT_PROOF);
        settlement_lock::settle(ABORTED, 2, 7, ABORT_DECISION, ABORT_PROOF);
        settlement_lock::lock(&payer, UNDECIDED, 1, asset(), 250, RECIPIENT);
        timestamp::update_global_time_for_test((NOW_MS + HORIZON_MS) * 1000);
        settlement_lock::escape(UNDECIDED, 1);
        let (n, acc) = settlement_lock::reconciliation();
        assert!(n == 6 && acc == RECON_ACC, 1);
        settlement_lock::checkpoint();
        let events = aptos_framework::event::emitted_events<settlement_lock::Accumulator>();
        assert!(std::vector::length(&events) == 1, 2);
        assert!(std::bcs::to_bytes(std::vector::borrow(&events, 0)) == ACCUMULATOR_EVENT, 3);
    }
}
