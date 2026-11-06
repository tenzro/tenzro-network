// SPDX-License-Identifier: Apache-2.0
#[test_only]
module tenzro_bridge::bridge_tests {
    use std::bcs;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use tenzro_bridge::bridge::{Self, TransferOut};

    const TENZRO_CHAIN_ID: u64 = 1337;
    const APTOS_SELECTOR: u64 = 101;
    const TENZRO_SELECTOR: u64 = 7777;
    const TOKEN: address = @0x2222222222222222222222222222222222222222222222222222222222222222;
    const ENDPOINT: address = @0x4444444444444444444444444444444444444444444444444444444444444444;

    /// The record Tenzro's Aptos route decodes for the transfer sent in
    /// `a_transfer_to_tenzro_emits_the_record_tenzro_decodes`.
    const TRANSFER_OUT: vector<u8> = x"01000000000000006500000000000000611e000000000000000000000000000000000000000000000000000000000000000000000000000b22222222222222222222222222222222222222222222222222222222222222224444444444444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555555555555555500002cf61a24a2290000000000000000";

    /// An outbound record Tenzro stores, the digest its committee signs, and
    /// the committee's secp256k1 signatures over it (keys `[n; 32]`).
    const OUTBOUND: vector<u8> = x"0700000000000000611e000000000000650000000000000011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000cafe000000000000000000000000000000000000000000000000000000000000000b0000f444829163450000000000000000";
    const OUTBOUND_DIGEST: vector<u8> = x"48fe1d8093e1d6955c4b485de05884b70b5102cd3fce911a6a21634907d927ce";
    const SIG_1: vector<u8> = x"735a321fc255302589790f476316895995a54d3cf4a65b97155ee4b3a429be277d4f5bcab5f8c7ae4c066240e4359dce917250f95b28906ff265355e0a5861e401";
    const SIG_2: vector<u8> = x"71e8f1b77f5cbadbbbcce347d839509d86c7412e1972c9acb9c997790950895000272d9034fe2eadbd38c88b1ffcc7d961abbfd670eac55ee7e3e660a174bafe00";
    const SIG_3: vector<u8> = x"cfd32c33a1473dcdcd4ed9509cedf00c5a466c13171083b1d7dcafd50cd4f75c28fecd74762cb6bfd0b798054e3be88f492e1b445eb3d65ae7d1d1951746543901";
    /// Keys `[4; 32]` and `[6; 32]` over `OUTBOUND_DIGEST`.
    const SIG_4: vector<u8> = x"7a48277b8b5b344b792789629704bd3ef00aaf87e2905766e27f070cb00b0adf0f01edfffc2df5e089421bff22f2b9e6dba3de61668b2bafdae066e1d69b13cf01";
    const SIG_6: vector<u8> = x"d260d1e1f9c4127b1b60dcb1a1ba3c040cf4551c9efb5a85b087c1a565b3927e37d628e568df33e781992f498de6d6aba69a664add4ba1737e388d971b220ea401";

    /// The digest that hands this module over to set 2 of members
    /// `[0x41; 20]`, `[0x42; 20]`, `[0x43; 20]`, threshold 2, expiring at
    /// Unix second 2,000,000,000.
    const HANDOVER_DIGEST: vector<u8> = x"5b9fa92d65c0129dbe62a1aeef851bf7d0ae16d5f1e7cafbc5b6c10502323d60";

    /// Keys `[1; 32]` and `[2; 32]` over the digest handing the module over
    /// to set 2 of `next()`, threshold 2, expiring at Unix second 2,000,000.
    const HANDOVER_SIG_1: vector<u8> = x"cfd220a7d37bf11145acf6019e570997bc564fae8f664bcdfae76c067fbf508a71eb427e780901961467b95774d4cf78d3ec043cb8b2b65091e02655371187e900";
    const HANDOVER_SIG_2: vector<u8> = x"488d30274eaff3f6cc3e4aa43e60625434236611a61c57faf921541b1cf1d93511f9161f310ea327021a8d76cc4091ead4d67f08d471c5d764da699d03b4d10e01";
    const SIG_STRANGER: vector<u8> = x"d05258e846f3d34e2078aa2cbf86196482a06821bee87f827c637bd945f858652c1f182dc5db35faee8cd28acbacc4f260f87bc65c66f4257cf794b2b3af1f4401";

    fun committee(): vector<vector<u8>> {
        vector[
            x"1a642f0e3c3af545e7acbd38b07251b3990914f1",
            x"5050a4f4b3f9338c3472dcc01a87c76a144b3c9c",
            x"3325a78425f17a7e487eb5666b2bfd93abb06c70",
        ]
    }

    /// The addresses of keys `[4; 32]`, `[5; 32]` and `[6; 32]`.
    fun next(): vector<vector<u8>> {
        vector[x"c48b812bb43401392c037381aca934f4069c0517", x"d09ad14080d4b257a819a4f579b8485be88f086c", x"0cb030d11a8be48b60418857874deee61d1071e0"]
    }

    fun setup(publisher: &signer, fw: &signer) {
        timestamp::set_time_has_started_for_testing(fw);
        bridge::initialize(
            publisher,
            TENZRO_CHAIN_ID,
            b"bridge_route:contract:aptos",
            APTOS_SELECTOR,
            TENZRO_SELECTOR,
            TOKEN,
            ENDPOINT,
            committee(),
            2,
            1,
            1_000_000,
        );
    }

    #[test(publisher = @tenzro_bridge, user = @0xb, fw = @aptos_framework)]
    fun a_transfer_to_tenzro_emits_the_record_tenzro_decodes(publisher: &signer, user: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::mint_for_testing(@0xb, 300_000_000);
        bridge::send_to_tenzro(user, 300_000_000, @0x5555555555555555555555555555555555555555555555555555555555555555);
        let events = event::emitted_events<TransferOut>();
        assert!(vector::length(&events) == 1, 0);
        assert!(bcs::to_bytes(vector::borrow(&events, 0)) == TRANSFER_OUT, 1);
        assert!(bridge::sequence() == 1, 2);
        assert!(primary_fungible_store::balance(@0xb, bridge::asset()) == 0, 3);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    fun the_committee_digest_is_the_one_tenzro_computes(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        assert!(bridge::outbound_digest(OUTBOUND) == OUTBOUND_DIGEST, 0);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    fun a_record_the_committee_signed_is_executed_once(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::execute(OUTBOUND, vector[SIG_1, SIG_3]);
        assert!(bridge::is_executed(7), 0);
        assert!(primary_fungible_store::balance(@0xb, bridge::asset()) == 500_000_000, 1);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 4, location = tenzro_bridge::bridge)]
    fun a_record_is_not_executed_twice(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::execute(OUTBOUND, vector[SIG_1, SIG_2]);
        bridge::execute(OUTBOUND, vector[SIG_2, SIG_3]);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 2, location = tenzro_bridge::bridge)]
    fun one_signer_twice_is_not_a_quorum(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::execute(OUTBOUND, vector[SIG_2, SIG_2]);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 2, location = tenzro_bridge::bridge)]
    fun a_stranger_does_not_count(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::execute(OUTBOUND, vector[SIG_1, SIG_STRANGER]);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 2, location = tenzro_bridge::bridge)]
    fun a_tampered_record_is_refused(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        let record = OUTBOUND;
        *vector::borrow_mut(&mut record, 150) = 0x0c;
        bridge::execute(record, vector[SIG_1, SIG_2]);
    }

    #[test(publisher = @0xbad, fw = @aptos_framework)]
    #[expected_failure(abort_code = 1, location = tenzro_bridge::bridge)]
    fun only_the_publisher_initializes(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    fun the_handover_digest_is_the_one_tenzro_computes(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        let members = vector[
            x"4141414141414141414141414141414141414141",
            x"4242424242424242424242424242424242424242",
            x"4343434343434343434343434343434343434343",
        ];
        assert!(bridge::handover_digest(2, members, 2, 2_000_000_000) == HANDOVER_DIGEST, 0);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    fun the_committee_hands_over_only_with_its_own_quorum(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::rotate_committee(2, next(), 2, 2_000_000, vector[HANDOVER_SIG_1, HANDOVER_SIG_2]);
        let (set_index, expires_at) = bridge::committee_set();
        assert!(set_index == 2 && expires_at == 2_000_000, 0);
        bridge::execute(OUTBOUND, vector[SIG_4, SIG_6]);
        assert!(bridge::is_executed(7), 1);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 2, location = tenzro_bridge::bridge)]
    fun the_old_committee_no_longer_executes_after_a_handover(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::rotate_committee(2, next(), 2, 2_000_000, vector[HANDOVER_SIG_1, HANDOVER_SIG_2]);
        bridge::execute(OUTBOUND, vector[SIG_1, SIG_2]);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 9, location = tenzro_bridge::bridge)]
    fun a_handover_is_not_replayed(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        bridge::rotate_committee(2, next(), 2, 2_000_000, vector[HANDOVER_SIG_1, HANDOVER_SIG_2]);
        bridge::rotate_committee(2, next(), 2, 2_000_000, vector[HANDOVER_SIG_1, HANDOVER_SIG_2]);
    }

    #[test(publisher = @tenzro_bridge, fw = @aptos_framework)]
    #[expected_failure(abort_code = 8, location = tenzro_bridge::bridge)]
    fun an_expired_committee_no_longer_executes(publisher: &signer, fw: &signer) {
        setup(publisher, fw);
        timestamp::update_global_time_for_test_secs(1_000_001);
        bridge::execute(OUTBOUND, vector[SIG_1, SIG_2]);
    }
}
