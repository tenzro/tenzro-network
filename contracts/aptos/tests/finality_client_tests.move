// SPDX-License-Identifier: Apache-2.0
#[test_only]
module tenzro_bridge::finality_client_tests {
    use std::vector;
    use aptos_std::crypto_algebra;
    use tenzro_bridge::finality_client;

    /// A real finality proof of a test build of the finality program.
    const IMAGE_ID: vector<u8> = x"517522e01ae5337fd174185532e72ab8312f6acd746357eb60327c30206c0c17";
    const JOURNAL: vector<u8> = x"00000000000000000000000000000000000000000000000000000000000005396e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e0000000000000000000000000000000000000000000000000000000000000000f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e4810000000000000000000000000000000000000000000000000000000000000007773a42135c308e8437e8c24a5361639a088273159620a6099d0c82822b75b09f000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000265e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5eb1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b15757575757575757575757575757575757575757575757575757575757575757c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2000000000000000000000000000000000000000000000000000001a0c4506c00";
    const SEAL: vector<u8> = x"73c457ba06bef3c4faaf51de1a9a9e981649531edfeb7615622853360df9fc869ad4f81327e61d048c194ed7ce47b9a72a1edf667714f58288b5f01f8bb2cda133db45222e585c9c0fe583e5f1bae75685e87570c90238b1ce121c40e5ba12de3c78ff090be0f13975a5da7ec68de2db52394cb9ce062e717af61cf5b7c23c2867c79d771a272fde6f81d77b80b06af002fbfbdb85b70d57dfc2fb3fad797e01c2604b7a0c601f308a74da9178fc1f89780c4c8682e76a0a2ac7313ae46545f8f9616c232875468ad44c2c251a25b9ef126425dda4d8faefba3649508592d2d380be29f314f0a24280dd0c30962255d456565b8868a7c647bf33eacd0a6275bba67a9117";
    const GENESIS: vector<u8> = x"6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e6e";
    const COMMITTEE: vector<u8> = x"f17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481";
    const STATE_ROOT: vector<u8> = x"5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";
    const NEXT_COMMITTEE: vector<u8> = x"c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";

    fun client(fx: &signer, creator: &signer, chain_id: u64, committee: vector<u8>): address {
        crypto_algebra::enable_cryptography_algebra_natives(fx);
        finality_client::create(creator, IMAGE_ID, chain_id, GENESIS, committee)
    }

    #[test(fx = @std, creator = @0xc0)]
    fun a_real_proof_finalizes_its_checkpoint_and_hands_over(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1337, COMMITTEE);
        assert!(finality_client::submit_checkpoint(c, JOURNAL, SEAL) == 7, 0);
        assert!(finality_client::state_root(c, 7) == STATE_ROOT, 1);
        assert!(finality_client::timestamp_ms(c, 7) == 1790000000000, 2);
        assert!(finality_client::latest_index(c) == 7, 3);
        assert!(finality_client::committee_root(c, 1) == NEXT_COMMITTEE, 4);
    }

    #[test(fx = @std, creator = @0xc0)]
    #[expected_failure(abort_code = 106, location = tenzro_bridge::finality_client)]
    fun a_checkpoint_is_final_once(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1337, COMMITTEE);
        finality_client::submit(c, JOURNAL, SEAL);
        finality_client::submit(c, JOURNAL, SEAL);
    }

    #[test(fx = @std, creator = @0xc0)]
    #[expected_failure(abort_code = 102, location = tenzro_bridge::finality_client)]
    fun a_journal_the_proof_does_not_commit_is_refused(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1337, COMMITTEE);
        let j = JOURNAL;
        *vector::borrow_mut(&mut j, 8 * 32) = 0x5f;
        finality_client::submit(c, j, SEAL);
    }

    #[test(fx = @std, creator = @0xc0)]
    #[expected_failure(abort_code = 101, location = tenzro_bridge::finality_client)]
    fun a_seal_for_another_verifier_is_refused(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1337, COMMITTEE);
        let s = SEAL;
        *vector::borrow_mut(&mut s, 0) = 0;
        finality_client::submit(c, JOURNAL, s);
    }

    #[test(fx = @std, creator = @0xc0)]
    #[expected_failure(abort_code = 104, location = tenzro_bridge::finality_client)]
    fun a_proof_of_another_chain_is_refused(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1, COMMITTEE);
        finality_client::submit(c, JOURNAL, SEAL);
    }

    #[test(fx = @std, creator = @0xc0)]
    #[expected_failure(abort_code = 105, location = tenzro_bridge::finality_client)]
    fun a_checkpoint_of_another_committee_is_refused(fx: signer, creator: signer) {
        let c = client(&fx, &creator, 1337, NEXT_COMMITTEE);
        finality_client::submit(c, JOURNAL, SEAL);
    }
}
