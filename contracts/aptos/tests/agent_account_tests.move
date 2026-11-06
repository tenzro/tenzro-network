// SPDX-License-Identifier: Apache-2.0
// The shared vectors (sdk/fixtures/remote_grant) as Aptos constants.
#[test_only]
module tenzro_bridge::agent_account_tests {
    use std::option;
    use std::string;
    use aptos_framework::fungible_asset::{Self, Metadata};
    use aptos_framework::object;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use aptos_std::crypto_algebra;
    use tenzro_bridge::agent_account;
    use tenzro_bridge::finality_client;
    use tenzro_bridge::settlement_lock;

    const DID: vector<u8> = b"did:tenzro:machine:vectors:agent";
    const ACCOUNT: address = @0x9d7aa6079144fa1d887686fef284faf8e7ab283dbd225268d95f0858a292cb31;
    const CAIP19: vector<u8> = b"aptos:1/fa:0x8d511fc4968ed0dd4703bd70e7537a152e9b2b96a2d61d647270958bf93301f1";
    const ROOT_V1: vector<u8> = x"fbd4a40025f4621b24d48405281eca86121a7cd8b581cd784395f5f8496d8613";
    const ROOT_V2: vector<u8> = x"661604fa855e0255632754119be4a773df36f6fefdbda76b616bee74f73e9b36";
    const GRANT_V1: vector<u8> = x"01c624a777962b26a9e5b1265bc8e3299489e57be86a9f70c581637108684b646e9d7aa6079144fa1d887686fef284faf8e7ab283dbd225268d95f0858a292cb318d23e2fc446f04e7bc15113c3b53dbf2426f3fa2d62f0614ffd7409b4837318400000000000000010000000000000001000001a3185c5000000001a3186577c02dad7a9df5a3e6d79f53a80f16cb4c1e5f37dc106ad1c073985ac5da893782ae000000000000000000000000000003e8000000000000000000000000000001900000000000000000000000000000012c97f9b7a0c1cb347afda41eb96cc4b76555e3f70aa5e0513ed512500e731f9c1f000000000000000000000000000000000000000000000000000000000000000000410f536fe1c1e7632b8b18d0fe63bb6c4f990893bb7cfc0575421d3c70106f0000000000000000000000000000000a00";
    const PROOF_V1: vector<u8> = x"0005d86093dc7fca5b1b31dc4114fda728039e5f50689097e3d56fde58e04e32e213193df37bdb785829acfd38fe30540a3ab63f337d3e3587e4327fc0acae3cc0b1ee8370dfc8b1a2ff408b3e20114e4811b920de973b7e7b8418dcfd0714bf03846a5bf81c16f7b5cf46552fd06a46dfe5bd9889319f09302a328de83cace60e3a0a76136213bbd564025cf2a7f00698af50042b91539f1d304b1eec608aed11dd0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const GRANT_V2: vector<u8> = x"01c624a777962b26a9e5b1265bc8e3299489e57be86a9f70c581637108684b646e9d7aa6079144fa1d887686fef284faf8e7ab283dbd225268d95f0858a292cb318d23e2fc446f04e7bc15113c3b53dbf2426f3fa2d62f0614ffd7409b4837318400000000000000010000000000000002000001a3185c5000000001a3186577c02dad7a9df5a3e6d79f53a80f16cb4c1e5f37dc106ad1c073985ac5da893782ae000000000000000000000000000003e8000000000000000000000000000001900000000000000000000000000000012c97f9b7a0c1cb347afda41eb96cc4b76555e3f70aa5e0513ed512500e731f9c1f000000000000000000000000000000000000000000000000000000000000000000410f536fe1c1e7632b8b18d0fe63bb6c4f990893bb7cfc0575421d3c70106f0000000000000000000000000000000a01";
    const PROOF_V2: vector<u8> = x"000512bc435c79d9c30961350c61e39d15e65f0d176f45ac113a5d45082695363515d3b412b924f87b540d6f3f55762642b5b61bef29f04b7e4b1146decb0fc32e76ee8370dfc8b1a2ff408b3e20114e4811b920de973b7e7b8418dcfd0714bf03846a5bf81c16f7b5cf46552fd06a46dfe5bd9889319f09302a328de83cace60e3a7305ccec8c14f7264a79ede0a4b827593e873b0bb37beec0b458fbeb7b7c27d90200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const TREE_KEY: vector<u8> = x"30a4876aa0f18ab6cb4e71b494c76f93a21705eb240e1605e2d864dfbf79b126";
    const ACTION: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00176170746f735f6163636f756e743a3a7472616e73666572000000000000000000000000000000640000000000000000000000000000000500000003010203";
    const OTHER: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00176170746f735f6163636f756e743a3a7472616e736665720000000000000000000000000000015e0000000000000000000000000000000500000003010203";
    const OVER_REFUND: vector<u8> = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00176170746f735f6163636f756e743a3a7472616e73666572000000000000000000000000000000640000000000000000000000000000000b00000003010203";
    const NOW_MS: u64 = 1800000001000;
    const NOT_AFTER_MS: u64 = 1800000600000;
    const TARGET: address = @0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;

    fun setup(fx: &signer, publisher: &signer, relayer: &signer) {
        crypto_algebra::enable_cryptography_algebra_natives(fx);
        timestamp::set_time_has_started_for_testing(fx);
        timestamp::update_global_time_for_test(NOW_MS * 1000);
        let client = finality_client::create(publisher, x"0101010101010101010101010101010101010101010101010101010101010101", 1337, x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e", x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481");
        finality_client::record_for_testing(client, 1, ROOT_V1, NOW_MS);
        finality_client::record_for_testing(client, 2, ROOT_V2, NOW_MS);
        agent_account::initialize_registry(publisher, client, b"aptos:1");
        agent_account::create_account(DID);
        assert!(agent_account::account_address(DID) == ACCOUNT, 0);
        // The grant's asset: a fungible asset the account holds.
        let constructor = object::create_named_object(publisher, b"TUSD");
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor, option::none(), string::utf8(b"Test USD"), string::utf8(b"TUSD"), 6, string::utf8(b""), string::utf8(b""),
        );
        let mint = fungible_asset::generate_mint_ref(&constructor);
        primary_fungible_store::mint(&mint, ACCOUNT, 1_000_000);
        let _ = relayer;
    }

    fun metadata(): object::Object<Metadata> {
        object::address_to_object<Metadata>(object::create_object_address(&@tenzro_bridge, b"TUSD"))
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    fun the_account_is_where_tenzro_derives_it(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        assert!(agent_account::grant_tree_key(&DID, &b"aptos:1") == TREE_KEY, 0);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    fun an_exact_grant_runs_its_one_action_once(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
        assert!(primary_fungible_store::balance(TARGET, metadata()) == 100, 1);
        assert!(primary_fungible_store::balance(@0xb0b, metadata()) == 5, 2);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 312, location = tenzro_bridge::agent_account)]
    fun an_exact_grant_is_used_once(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 313, location = tenzro_bridge::agent_account)]
    fun another_action_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
        agent_account::act_exact(&relayer, ACCOUNT, OTHER);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 309, location = tenzro_bridge::agent_account)]
    fun a_void_stops_the_action(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
        agent_account::sync(ACCOUNT, 2, GRANT_V2, PROOF_V2, CAIP19, x"77");
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 306, location = tenzro_bridge::agent_account)]
    fun a_stale_grant_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 2, GRANT_V2, PROOF_V2, CAIP19, x"77");
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 303, location = tenzro_bridge::agent_account)]
    fun a_grant_not_under_the_root_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 2, GRANT_V1, PROOF_V1, CAIP19, x"77");
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 310, location = tenzro_bridge::agent_account)]
    fun an_expired_grant_acts_no_more(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, CAIP19, x"77");
        timestamp::update_global_time_for_test((NOT_AFTER_MS + 1) * 1000);
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 307, location = tenzro_bridge::agent_account)]
    fun a_grant_with_another_asset_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        agent_account::sync(ACCOUNT, 1, GRANT_V1, PROOF_V1, b"aptos:1/fa:0x0a", x"77");
    }

    /// The root of a state tree whose only entry is `value` at `tk`, and the
    /// proof of it.
    fun single(tk: &vector<u8>, value: vector<u8>): (vector<u8>, vector<u8>) {
        let leaf = x"00";
        std::vector::append(&mut leaf, value);
        let s = std::hash::sha2_256(leaf);
        let index = *std::vector::borrow(tk, 31);
        let zero = x"0000000000000000000000000000000000000000000000000000000000000000";
        let i = 0;
        while (i < 8) {
            let b = x"03";
            if (index & 1 == 0) {
                std::vector::append(&mut b, s);
                std::vector::append(&mut b, zero);
            } else {
                std::vector::append(&mut b, zero);
                std::vector::append(&mut b, s);
            };
            s = std::hash::sha2_256(b);
            index = index >> 1;
            i = i + 1;
        };
        let b = x"02";
        std::vector::append(&mut b, std::vector::slice(tk, 0, 31));
        std::vector::append(&mut b, s);
        let proof = x"000002";
        let j = 0;
        while (j < 256) {
            std::vector::push_back(&mut proof, 0);
            j = j + 1;
        };
        (std::hash::sha2_256(b), proof)
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 311, location = tenzro_bridge::agent_account)]
    fun an_open_grant_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        // The vectors' grant with its payload hash cleared, seq 3.
        let g = std::vector::slice(&GRANT_V1, 0, 105);
        std::vector::append(&mut g, x"0000000000000003");
        std::vector::append(&mut g, std::vector::slice(&GRANT_V1, 113, 273));
        std::vector::append(&mut g, x"0000000000000000000000000000000000000000000000000000000000000000");
        std::vector::append(&mut g, std::vector::slice(&GRANT_V1, 305, 322));
        let (root, proof) = single(&TREE_KEY, g);
        finality_client::record_for_testing(agent_account::finality_client(), 3, root, NOW_MS);
        agent_account::sync(ACCOUNT, 3, g, proof, CAIP19, x"77");
        agent_account::act_exact(&relayer, ACCOUNT, ACTION);
    }

    #[test]
    fun a_paying_action_reports_in_the_layout_tenzro_decodes() {
        let data = vector[];
        let i = 0;
        while (i < 104) { std::vector::push_back(&mut data, ((i % 251) as u8)); i = i + 1; };
        let action = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0003";
        std::vector::append(&mut action, b"pay");
        std::vector::append(&mut action, x"0000000000000000000000000000006400000000000000000000000000000000");
        std::vector::append(&mut action, x"00000068");
        std::vector::append(&mut action, data);
        let report = agent_account::paid_report(&GRANT_V1, 0, &action, 100);
        let expected = x"04";
        std::vector::append(&mut expected, std::hash::sha2_256(b"aptos:1"));
        std::vector::append(&mut expected, std::bcs::to_bytes(&ACCOUNT));
        std::vector::append(&mut expected, std::hash::sha2_256(DID));
        std::vector::append(&mut expected, x"0000000000000001");
        std::vector::append(&mut expected, x"0000000000000000");
        std::vector::append(&mut expected, data);
        std::vector::append(&mut expected, x"00000000000000000000000000000064");
        assert!(report == expected, 0);
    }

    #[test]
    #[expected_failure(abort_code = 317, location = tenzro_bridge::agent_account)]
    fun a_payment_without_its_pay_data_is_refused() {
        let action = x"0020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0003";
        std::vector::append(&mut action, b"pay");
        std::vector::append(&mut action, x"000000000000000000000000000000640000000000000000000000000000000000000001ff");
        agent_account::paid_report(&GRANT_V1, 0, &action, 100);
    }

    /// An exact grant (seq 3) whose one action locks 100 into the settlement
    /// lock as leg `index` of plan 0x07..07 for 0xcc..cc, synced.
    fun lock_grant(target: address, index: u8): vector<u8> {
        let a = x"0020";
        std::vector::append(&mut a, std::bcs::to_bytes(&target));
        std::vector::append(&mut a, x"0004");
        std::vector::append(&mut a, b"lock");
        std::vector::append(&mut a, x"00000000000000000000000000000064");
        std::vector::append(&mut a, x"00000000000000000000000000000000");
        std::vector::append(&mut a, x"00000041");
        std::vector::append(&mut a, x"0707070707070707070707070707070707070707070707070707070707070707");
        std::vector::push_back(&mut a, index);
        std::vector::append(&mut a, x"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        let g = std::vector::slice(&GRANT_V1, 0, 105);
        std::vector::append(&mut g, x"0000000000000003");
        std::vector::append(&mut g, std::vector::slice(&GRANT_V1, 113, 273));
        std::vector::append(&mut g, std::hash::sha2_256(a));
        std::vector::append(&mut g, std::vector::slice(&GRANT_V1, 305, 322));
        let (root, proof) = single(&TREE_KEY, g);
        finality_client::record_for_testing(agent_account::finality_client(), 3, root, NOW_MS);
        agent_account::sync(ACCOUNT, 3, g, proof, CAIP19, x"77");
        a
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    fun an_agent_locks_exactly_its_amount_and_gets_an_escape_back(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        settlement_lock::initialize(&publisher, agent_account::finality_client(), 1000);
        let action = lock_grant(settlement_lock::lock_address(), 0);
        settlement_lock::lock_exact_from_agent(&relayer, ACCOUNT, action);
        assert!(primary_fungible_store::balance(ACCOUNT, metadata()) == 1_000_000 - 100, 1);
        assert!(primary_fungible_store::balance(settlement_lock::lock_address(), metadata()) == 100, 2);
        let plan = x"0707070707070707070707070707070707070707070707070707070707070707";
        assert!(settlement_lock::stage(plan, 0) == 1, 3);
        // The account is the payer: an escape returns the amount to it.
        timestamp::update_global_time_for_test((NOW_MS + 1000) * 1000);
        settlement_lock::escape(plan, 0);
        assert!(primary_fungible_store::balance(ACCOUNT, metadata()) == 1_000_000, 4);
    }

    #[test(fx = @std, publisher = @tenzro_bridge, relayer = @0xb0b)]
    #[expected_failure(abort_code = 408, location = tenzro_bridge::settlement_lock)]
    fun an_agent_action_for_another_lock_is_refused(fx: signer, publisher: signer, relayer: signer) {
        setup(&fx, &publisher, &relayer);
        settlement_lock::initialize(&publisher, agent_account::finality_client(), 1000);
        let action = lock_grant(@0xcafe0, 0);
        settlement_lock::lock_exact_from_agent(&relayer, ACCOUNT, action);
    }
}
