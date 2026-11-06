// SPDX-License-Identifier: Apache-2.0
/// Tenzro finality on Aptos.
///
/// A finality proof is a Groth16 proof (BN254) that RISC Zero's recursion
/// circuit accepted a receipt of Tenzro's finality program. Its journal states
/// one checkpoint that the program verified under the committee of its epoch.
/// The client takes the seal and journal every chain's client takes (points in
/// the Ethereum precompile encoding), checks the pairing equation with the
/// BN254 natives, and records the checkpoint's state root. A checkpoint that
/// ends an epoch hands over to the next committee.
module tenzro_bridge::finality_client {
    use std::option;
    use std::signer;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::object;
    use std::hash::sha2_256;
    use aptos_std::bn254_algebra::{Fr, FormatFrLsb, FormatG1Uncompr, FormatG2Uncompr, G1, G2, Gt};
    use aptos_std::crypto_algebra::{Self, Element};
    use aptos_std::smart_table::{Self, SmartTable};

    const EMALFORMED_SEAL: u64 = 100;
    const EWRONG_SELECTOR: u64 = 101;
    const EINVALID_PROOF: u64 = 102;
    const EMALFORMED_JOURNAL: u64 = 103;
    const EWRONG_CHAIN: u64 = 104;
    const EUNKNOWN_COMMITTEE: u64 = 105;
    const EALREADY_FINAL: u64 = 106;
    const EUNKNOWN_CHECKPOINT: u64 = 107;
    const ENO_CLIENT: u64 = 108;
    const EBAD_POINT: u64 = 109;

    /// Bytes of an encoded journal: thirteen words.
    const JOURNAL_LEN: u64 = 416;
    /// The seals this client accepts: RISC Zero's Groth16 verifier parameters.
    const SELECTOR: vector<u8> = x"73c457ba";
    const CONTROL_ROOT: vector<u8> = x"a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";
    const BN254_CONTROL_ID: vector<u8> = x"04446e66d300eb7fb45c9726bb53c793dda407a62e9601618bb43c5c14657ac0";
    /// The terminal state of a halted program.
    const POST_STATE: vector<u8> = x"a3acc27117418996340b84e5a90f3ef4c49d22c79e44aad822ec9c313e1eb8e2";
    const ZERO16: vector<u8> = x"00000000000000000000000000000000";
    const ZERO32: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
    /// The recursion circuit's verifying key in the precompile encoding:
    /// alpha (G1), beta, gamma, delta (G2: x_im, x_re, y_im, y_re), then the
    /// input commitments IC0..IC5 (G1).
    const VK: vector<u8> = x"2d4d9aa7e302d9df41749d5507949d05dbea33fbb16c643b22f599a2be6df2e214bedd503c37ceb061d8ec60209fe345ce89830a19230301f076caff004d19260967032fcbf776d1afc985f88877f182d38480a653f2decaa9794cbc3bf3060c0e187847ad4c798374d0d6732bf501847dd68bc0e071241e0213bc7fc13db7ab304cfbd1e08a704a99f5e847d93f8c3caafddec46b7a0d379da69a4d112346a71739c1b1a457a8c7313123d24d2f9192f896b7c63eea05a9d57f06547ad0cec8198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa03b03cd5effa95ac9bee94f1f5ef907157bda4812ccf0b4c91f42bb629f83a1c1aa085ff28179a12d922dba0547057ccaae94b9d69cfaa4e60401fea7f3e0333110c10134f200b19f6490846d518c9aea868366efb7228ca5c91d2940d0307621e60f31fcbf757e837e867178318832d0b2d74d59e2fea1c7142df187d3fc6d312ac9a25dcd5e1a832a9061a082c15dd1d61aa9c4d553505739d0f5d65dc3be4025aa744581ebe7ad91731911c898569106ff5a2d30f3eee2b23c60ee980acd40707b920bc978c02f292fae2036e057be54294114ccc3c8769d883f688a1423f2e32a094b7589554f7bc357bf63481acd2d55555c203383782a4650787ff66420bca36e2cbe6394b3e249751853f961511011c7148e336f4fd974644850fc3472ede7c9acf48cf3a3729fa3d68714e2a8435d4fa6db8f7f409c153b1fcdf9b8b1b8af999dbfbb3927c091cc2aaf201e488cbacc3e2c6b6fb5a25f9112e04f2a72b91a26aa92e1b6f5722949f192a81c850d586d81a60157f3e9cf04f679cccd62b5f494ed674235b8ac1750bdfd5a7615f002d4a1dcefeddd06eda5a076ccd0d2fe520ad2020aab9cbba817fcbb9a863b8a76ff88f14f912c5e71665b2ad5e820f1c3c0d5d9da0fa03666843cde4e82e869ba5252fce3c25d5940320b1c4d493214bfcff74f425f6fe8c0d07b307482d8bc8bb2f3608f68287aa01bd0b69e809";

    /// What the client keeps of a final checkpoint.
    struct Checkpoint has copy, drop, store {
        digest: vector<u8>,
        state_root: vector<u8>,
        state_height: u64,
        last_height: u64,
        timestamp_ms: u64,
    }

    /// A client of one Tenzro chain, held by its own object.
    struct FinalityClient has key {
        image_id: vector<u8>,
        chain_id: u64,
        genesis_hash: vector<u8>,
        /// Committee roots by epoch.
        committees: SmartTable<u64, vector<u8>>,
        /// Final checkpoints by index.
        checkpoints: SmartTable<u64, Checkpoint>,
        latest_index: u64,
    }

    #[event]
    struct ClientCreated has drop, store {
        client: address,
        chain_id: u64,
    }

    #[event]
    struct CheckpointFinalized has drop, store {
        client: address,
        index: u64,
        epoch: u64,
        digest: vector<u8>,
        state_root: vector<u8>,
        state_height: u64,
    }

    #[event]
    struct CommitteeHandedOver has drop, store {
        client: address,
        epoch: u64,
        root: vector<u8>,
    }

    /// Create a client of the chain `chain_id` with genesis `genesis_hash`,
    /// whose epoch-0 committee has root `genesis_committee_root`, accepting
    /// proofs of the finality program `image_id`. Returns its address.
    public fun create(
        creator: &signer,
        image_id: vector<u8>,
        chain_id: u64,
        genesis_hash: vector<u8>,
        genesis_committee_root: vector<u8>,
    ): address {
        assert!(vector::length(&image_id) == 32 && vector::length(&genesis_hash) == 32, EMALFORMED_JOURNAL);
        assert!(vector::length(&genesis_committee_root) == 32, EUNKNOWN_COMMITTEE);
        let constructor = object::create_object(signer::address_of(creator));
        let holder = object::generate_signer(&constructor);
        let committees = smart_table::new();
        smart_table::add(&mut committees, 0, genesis_committee_root);
        move_to(&holder, FinalityClient {
            image_id,
            chain_id,
            genesis_hash,
            committees,
            checkpoints: smart_table::new(),
            latest_index: 0,
        });
        let client = signer::address_of(&holder);
        event::emit(ClientCreated { client, chain_id });
        client
    }

    public entry fun create_client(
        creator: &signer,
        image_id: vector<u8>,
        chain_id: u64,
        genesis_hash: vector<u8>,
        genesis_committee_root: vector<u8>,
    ) {
        create(creator, image_id, chain_id, genesis_hash, genesis_committee_root);
    }

    /// Accept the checkpoint `journal` states, proven by `seal`.
    public entry fun submit(client: address, journal: vector<u8>, seal: vector<u8>) acquires FinalityClient {
        submit_checkpoint(client, journal, seal);
    }

    /// Accept the checkpoint `journal` states, proven by `seal`. Returns its index.
    public fun submit_checkpoint(client: address, journal: vector<u8>, seal: vector<u8>): u64 acquires FinalityClient {
        assert!(exists<FinalityClient>(client), ENO_CLIENT);
        let c = borrow_global_mut<FinalityClient>(client);
        assert!(vector::length(&journal) == JOURNAL_LEN, EMALFORMED_JOURNAL);
        let claim = claim_digest(&c.image_id, &sha2_256(journal));
        assert!(verify_seal(&seal, &claim), EINVALID_PROOF);
        let chain_id = int(&journal, 0);
        let epoch = int(&journal, 2);
        let index = int(&journal, 4);
        assert!(chain_id == c.chain_id && word(&journal, 1) == c.genesis_hash, EWRONG_CHAIN);
        assert!(smart_table::contains(&c.committees, epoch), EUNKNOWN_COMMITTEE);
        let root = *smart_table::borrow(&c.committees, epoch);
        assert!(root == word(&journal, 3) && root != ZERO32, EUNKNOWN_COMMITTEE);
        assert!(!smart_table::contains(&c.checkpoints, index), EALREADY_FINAL);
        let checkpoint = Checkpoint {
            digest: word(&journal, 5),
            state_root: word(&journal, 8),
            state_height: int(&journal, 7),
            last_height: int(&journal, 6),
            timestamp_ms: int(&journal, 12),
        };
        smart_table::add(&mut c.checkpoints, index, checkpoint);
        if (index > c.latest_index) c.latest_index = index;
        event::emit(CheckpointFinalized {
            client,
            index,
            epoch,
            digest: checkpoint.digest,
            state_root: checkpoint.state_root,
            state_height: checkpoint.state_height,
        });
        let next = word(&journal, 11);
        if (next != ZERO32 && !smart_table::contains(&c.committees, epoch + 1)) {
            smart_table::add(&mut c.committees, epoch + 1, next);
            event::emit(CommitteeHandedOver { client, epoch: epoch + 1, root: next });
        };
        index
    }

    #[view]
    /// The state root of the final checkpoint `index`.
    public fun state_root(client: address, index: u64): vector<u8> acquires FinalityClient {
        checkpoint(client, index).state_root
    }

    #[view]
    /// When the final checkpoint `index` was made, in milliseconds.
    public fun timestamp_ms(client: address, index: u64): u64 acquires FinalityClient {
        checkpoint(client, index).timestamp_ms
    }

    #[view]
    public fun latest_index(client: address): u64 acquires FinalityClient {
        assert!(exists<FinalityClient>(client), ENO_CLIENT);
        borrow_global<FinalityClient>(client).latest_index
    }

    #[view]
    public fun committee_root(client: address, epoch: u64): vector<u8> acquires FinalityClient {
        assert!(exists<FinalityClient>(client), ENO_CLIENT);
        let c = borrow_global<FinalityClient>(client);
        assert!(smart_table::contains(&c.committees, epoch), EUNKNOWN_COMMITTEE);
        *smart_table::borrow(&c.committees, epoch)
    }

    fun checkpoint(client: address, index: u64): Checkpoint acquires FinalityClient {
        assert!(exists<FinalityClient>(client), ENO_CLIENT);
        let c = borrow_global<FinalityClient>(client);
        assert!(smart_table::contains(&c.checkpoints, index), EUNKNOWN_CHECKPOINT);
        *smart_table::borrow(&c.checkpoints, index)
    }

    /// The digest of a successful receipt claim of `image_id` with journal
    /// digest `journal_digest`.
    public fun claim_digest(image_id: &vector<u8>, journal_digest: &vector<u8>): vector<u8> {
        let b = sha2_256(b"risc0.Output");
        vector::append(&mut b, *journal_digest);
        vector::append(&mut b, ZERO32);
        vector::append(&mut b, x"0200");
        let output = sha2_256(b);
        let b = sha2_256(b"risc0.ReceiptClaim");
        vector::append(&mut b, ZERO32);
        vector::append(&mut b, *image_id);
        vector::append(&mut b, POST_STATE);
        vector::append(&mut b, output);
        vector::append(&mut b, x"0000000000000000");
        vector::append(&mut b, x"0400");
        sha2_256(b)
    }

    /// Whether `seal` (selector, then the words of A, B and C) proves a
    /// receipt with claim `claim`: e(-A, B) e(alpha, beta) e(vk_x, gamma)
    /// e(C, delta) = 1.
    public fun verify_seal(seal: &vector<u8>, claim: &vector<u8>): bool {
        assert!(vector::length(seal) == 4 + 8 * 32, EMALFORMED_SEAL);
        assert!(slice(seal, 0, 4) == SELECTOR, EWRONG_SELECTOR);
        let inputs = vector[
            half_le(&CONTROL_ROOT, 0),
            half_le(&CONTROL_ROOT, 16),
            half_le(claim, 0),
            half_le(claim, 16),
            reversed(&BN254_CONTROL_ID),
        ];
        let vk = VK;
        let vk_x = g1(&slice(&vk, 448, 480), &slice(&vk, 480, 512));
        let i = 0;
        while (i < 5) {
            let at = 512 + 64 * i;
            let ic = g1(&slice(&vk, at, at + 32), &slice(&vk, at + 32, at + 64));
            let s = crypto_algebra::deserialize<Fr, FormatFrLsb>(vector::borrow(&inputs, i));
            assert!(option::is_some(&s), EBAD_POINT);
            vk_x = crypto_algebra::add(&vk_x, &crypto_algebra::scalar_mul(&ic, &option::extract(&mut s)));
            i = i + 1;
        };
        let a = g1(&seal_word(seal, 0), &seal_word(seal, 1));
        let b = g2(&slice(seal, 4 + 64, 4 + 192));
        let c = g1(&seal_word(seal, 6), &seal_word(seal, 7));
        let g1s = vector[
            crypto_algebra::neg(&a),
            g1(&slice(&vk, 0, 32), &slice(&vk, 32, 64)),
            vk_x,
            c,
        ];
        let g2s = vector[b, g2(&slice(&vk, 64, 192)), g2(&slice(&vk, 192, 320)), g2(&slice(&vk, 320, 448))];
        let product = crypto_algebra::multi_pairing<G1, G2, Gt>(&g1s, &g2s);
        crypto_algebra::eq(&product, &crypto_algebra::zero<Gt>())
    }

    /// A G1 point from big-endian coordinates.
    fun g1(x: &vector<u8>, y: &vector<u8>): Element<G1> {
        let b = reversed(x);
        vector::append(&mut b, reversed(y));
        let p = crypto_algebra::deserialize<G1, FormatG1Uncompr>(&b);
        assert!(option::is_some(&p), EBAD_POINT);
        option::extract(&mut p)
    }

    /// A G2 point from the precompile encoding (x_im, x_re, y_im, y_re).
    fun g2(w: &vector<u8>): Element<G2> {
        let b = reversed(&slice(w, 32, 64));
        vector::append(&mut b, reversed(&slice(w, 0, 32)));
        vector::append(&mut b, reversed(&slice(w, 96, 128)));
        vector::append(&mut b, reversed(&slice(w, 64, 96)));
        let p = crypto_algebra::deserialize<G2, FormatG2Uncompr>(&b);
        assert!(option::is_some(&p), EBAD_POINT);
        option::extract(&mut p)
    }

    /// One half of a digest as a little-endian scalar: the digest's bytes
    /// reversed, split into its low and high 128 bits.
    fun half_le(d: &vector<u8>, from: u64): vector<u8> {
        let out = slice(d, from, from + 16);
        vector::append(&mut out, ZERO16);
        out
    }

    fun reversed(v: &vector<u8>): vector<u8> {
        let out = *v;
        vector::reverse(&mut out);
        out
    }

    fun slice(v: &vector<u8>, from: u64, to: u64): vector<u8> {
        vector::slice(v, from, to)
    }

    fun seal_word(seal: &vector<u8>, i: u64): vector<u8> {
        slice(seal, 4 + 32 * i, 36 + 32 * i)
    }

    fun word(journal: &vector<u8>, i: u64): vector<u8> {
        slice(journal, 32 * i, 32 * (i + 1))
    }

    /// A journal word holding an integer: right-aligned, at most 64 bits.
    fun int(journal: &vector<u8>, i: u64): u64 {
        let w = word(journal, i);
        let j = 0;
        while (j < 24) {
            assert!(*vector::borrow(&w, j) == 0, EMALFORMED_JOURNAL);
            j = j + 1;
        };
        let v: u64 = 0;
        while (j < 32) {
            v = (v << 8) | (*vector::borrow(&w, j) as u64);
            j = j + 1;
        };
        v
    }

    #[test_only]
    /// Record a checkpoint without a proof, so accounts can be tested against
    /// a state root of their own.
    public fun record_for_testing(client: address, index: u64, state_root: vector<u8>, timestamp_ms: u64) acquires FinalityClient {
        let c = borrow_global_mut<FinalityClient>(client);
        smart_table::add(&mut c.checkpoints, index, Checkpoint {
            digest: ZERO32, state_root, state_height: 0, last_height: 0, timestamp_ms,
        });
        if (index > c.latest_index) c.latest_index = index;
    }
}
