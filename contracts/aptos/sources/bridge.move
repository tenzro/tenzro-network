// SPDX-License-Identifier: Apache-2.0
/// Tenzro's bridge module on Aptos.
///
/// TNZO on Aptos is a fungible asset this module alone mints, against TNZO
/// locked on Tenzro, and burns when it goes back. A transfer to Tenzro burns
/// the asset and emits `TransferOut`, the record Tenzro's Aptos route
/// decodes. A transfer from Tenzro is the record Tenzro stored for it,
/// executed once the route's committee signed its digest: `threshold`
/// distinct members, each recovered from a secp256k1 signature over
/// Keccak-256 of the outbound domain, Tenzro's chain id, the route key and
/// the record.
///
/// Tenzro draws each committee from its bonded attestors and numbers it with
/// a set index. The committee this module trusts hands it over to a later
/// one by signing that committee's set index, members, threshold and expiry
/// (`handover_digest`); any relayer submits the handover, which is accepted
/// only for a higher set index. The module stops trusting a committee at its
/// expiry, so a committee whose members may have left their bonds on Tenzro
/// can never act here.
///
/// Amounts in records are TNZO's smallest unit (18 decimals); the asset has
/// 8, so a record's amount is the asset amount times 10^10.
module tenzro_bridge::bridge {
    use std::bcs;
    use std::option;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, BurnRef, Metadata, MintRef};
    use aptos_framework::object::{Self, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use aptos_std::aptos_hash::keccak256;
    use aptos_std::from_bcs;
    use aptos_std::secp256k1;
    use aptos_std::smart_table::{Self, SmartTable};

    /// Smallest TNZO units per asset unit.
    const SCALE: u128 = 10_000_000_000;
    const OUTBOUND_DOMAIN: vector<u8> = b"tenzro/bridge/route-outbound";
    const COMMITTEE_DOMAIN: vector<u8> = b"tenzro/bridge/route-committee";
    const ASSET_SEED: vector<u8> = b"TNZO";

    const E_NOT_PUBLISHER: u64 = 1;
    const E_BELOW_THRESHOLD: u64 = 2;
    const E_WRONG_ROUTE: u64 = 3;
    const E_ALREADY_EXECUTED: u64 = 4;
    const E_BAD_AMOUNT: u64 = 5;
    const E_BAD_COMMITTEE: u64 = 6;
    const E_MALFORMED_RECORD: u64 = 7;
    const E_EXPIRED: u64 = 8;
    const E_STALE_SET: u64 = 9;

    struct Bridge has key {
        mint_ref: MintRef,
        burn_ref: BurnRef,
        asset: Object<Metadata>,
        tenzro_chain_id: u64,
        route_key: vector<u8>,
        aptos_selector: u64,
        tenzro_selector: u64,
        token: address,
        tenzro_endpoint: address,
        committee: vector<vector<u8>>,
        threshold: u64,
        set_index: u64,
        expires_at: u64,
        sequence: u64,
        executed: SmartTable<u64, bool>,
    }

    #[event]
    /// A transfer to Tenzro.
    struct TransferOut has drop, store {
        sequence: u64,
        source_selector: u64,
        dest_selector: u64,
        sender: address,
        token: address,
        endpoint: address,
        recipient: address,
        amount: u128,
    }

    #[event]
    /// A transfer from Tenzro, executed.
    struct TransferIn has drop, store {
        sequence: u64,
        recipient: address,
        amount: u128,
    }

    /// Create the asset and set the route's identifiers and the committee
    /// Tenzro drew, with its set index and expiry. Only the publisher may,
    /// once; afterwards only the committee hands itself over.
    public entry fun initialize(
        publisher: &signer,
        tenzro_chain_id: u64,
        route_key: vector<u8>,
        aptos_selector: u64,
        tenzro_selector: u64,
        token: address,
        tenzro_endpoint: address,
        committee: vector<vector<u8>>,
        threshold: u64,
        set_index: u64,
        expires_at: u64,
    ) {
        assert!(signer::address_of(publisher) == @tenzro_bridge, E_NOT_PUBLISHER);
        check_committee(&committee, threshold);
        let constructor = object::create_named_object(publisher, ASSET_SEED);
        primary_fungible_store::create_primary_store_enabled_fungible_asset(
            &constructor,
            option::none(),
            string::utf8(b"Tenzro"),
            string::utf8(b"TNZO"),
            8,
            string::utf8(b""),
            string::utf8(b""),
        );
        let mint_ref = fungible_asset::generate_mint_ref(&constructor);
        let burn_ref = fungible_asset::generate_burn_ref(&constructor);
        let asset = object::object_from_constructor_ref<Metadata>(&constructor);
        move_to(publisher, Bridge {
            mint_ref,
            burn_ref,
            asset,
            tenzro_chain_id,
            route_key,
            aptos_selector,
            tenzro_selector,
            token,
            tenzro_endpoint,
            committee,
            threshold,
            set_index,
            expires_at,
            sequence: 0,
            executed: smart_table::new(),
        });
    }

    fun check_committee(committee: &vector<vector<u8>>, threshold: u64) {
        let n = vector::length(committee);
        assert!(n > 0 && threshold > n / 2 && threshold <= n, E_BAD_COMMITTEE);
        let i = 0;
        while (i < n) {
            assert!(vector::length(vector::borrow(committee, i)) == 20, E_BAD_COMMITTEE);
            let j = i + 1;
            while (j < n) {
                assert!(vector::borrow(committee, i) != vector::borrow(committee, j), E_BAD_COMMITTEE);
                j = j + 1;
            };
            i = i + 1;
        };
    }

    #[view]
    /// The asset.
    public fun asset(): Object<Metadata> acquires Bridge {
        borrow_global<Bridge>(@tenzro_bridge).asset
    }

    /// Send `amount` of the asset to `recipient` on Tenzro: burn it and emit
    /// the record.
    public entry fun send_to_tenzro(sender: &signer, amount: u64, recipient: address) acquires Bridge {
        assert!(amount > 0, E_BAD_AMOUNT);
        let b = borrow_global_mut<Bridge>(@tenzro_bridge);
        let from = signer::address_of(sender);
        let store = primary_fungible_store::primary_store(from, b.asset);
        fungible_asset::burn_from(&b.burn_ref, store, amount);
        b.sequence = b.sequence + 1;
        event::emit(TransferOut {
            sequence: b.sequence,
            source_selector: b.aptos_selector,
            dest_selector: b.tenzro_selector,
            sender: from,
            token: b.token,
            endpoint: b.tenzro_endpoint,
            recipient,
            amount: (amount as u128) * SCALE,
        });
    }

    fun be_u64(v: u64): vector<u8> {
        let out = bcs::to_bytes(&v);
        vector::reverse(&mut out);
        out
    }

    #[view]
    /// The digest the committee signs for outbound `record`.
    public fun outbound_digest(record: vector<u8>): vector<u8> acquires Bridge {
        let b = borrow_global<Bridge>(@tenzro_bridge);
        let m = OUTBOUND_DOMAIN;
        vector::append(&mut m, be_u64(b.tenzro_chain_id));
        vector::append(&mut m, be_u64(vector::length(&b.route_key)));
        vector::append(&mut m, b.route_key);
        vector::append(&mut m, record);
        keccak256(m)
    }

    /// The Ethereum-style address of the key that signed `digest`.
    fun signer_of(digest: vector<u8>, signature: &vector<u8>): vector<u8> {
        assert!(vector::length(signature) == 65, E_BELOW_THRESHOLD);
        let rs = vector::slice(signature, 0, 64);
        let v = *vector::borrow(signature, 64);
        if (v >= 27) { v = v - 27 };
        let key = secp256k1::ecdsa_recover(digest, v, &secp256k1::ecdsa_signature_from_bytes(rs));
        if (option::is_none(&key)) return vector[];
        let raw = secp256k1::ecdsa_raw_public_key_to_bytes(&option::extract(&mut key));
        vector::slice(&keccak256(raw), 12, 32)
    }

    fun check_quorum(b: &Bridge, digest: vector<u8>, signatures: &vector<vector<u8>>) {
        assert!(timestamp::now_seconds() <= b.expires_at, E_EXPIRED);
        let seen = vector[];
        let i = 0;
        while (i < vector::length(signatures)) {
            let who = signer_of(digest, vector::borrow(signatures, i));
            if (vector::contains(&b.committee, &who) && !vector::contains(&seen, &who)) {
                vector::push_back(&mut seen, who);
            };
            i = i + 1;
        };
        assert!(vector::length(&seen) >= b.threshold, E_BELOW_THRESHOLD);
    }

    /// Execute outbound `record` from Tenzro, signed by the committee: mint
    /// the asset to its recipient, once.
    public entry fun execute(record: vector<u8>, signatures: vector<vector<u8>>) acquires Bridge {
        let digest = outbound_digest(record);
        let b = borrow_global_mut<Bridge>(@tenzro_bridge);
        check_quorum(b, digest, &signatures);
        assert!(vector::length(&record) == 168, E_MALFORMED_RECORD);
        let sequence = from_bcs::to_u64(vector::slice(&record, 0, 8));
        let source_selector = from_bcs::to_u64(vector::slice(&record, 8, 16));
        let dest_selector = from_bcs::to_u64(vector::slice(&record, 16, 24));
        let token = from_bcs::to_address(vector::slice(&record, 56, 88));
        let endpoint = from_bcs::to_address(vector::slice(&record, 88, 120));
        let recipient = from_bcs::to_address(vector::slice(&record, 120, 152));
        let amount = from_bcs::to_u128(vector::slice(&record, 152, 168));
        assert!(
            source_selector == b.tenzro_selector && dest_selector == b.aptos_selector
                && endpoint == @tenzro_bridge && token == b.token,
            E_WRONG_ROUTE,
        );
        assert!(!smart_table::contains(&b.executed, sequence), E_ALREADY_EXECUTED);
        assert!(amount > 0 && amount % SCALE == 0 && amount / SCALE <= 18446744073709551615, E_BAD_AMOUNT);
        smart_table::add(&mut b.executed, sequence, true);
        primary_fungible_store::mint(&b.mint_ref, recipient, ((amount / SCALE) as u64));
        event::emit(TransferIn { sequence, recipient, amount });
    }

    fun be_u32(v: u64): vector<u8> {
        let out = be_u64(v);
        vector::slice(&out, 4, 8)
    }

    #[view]
    /// The digest the trusted committee signs to hand the module over to
    /// committee `set_index`: Keccak-256 of the committee domain, Tenzro's
    /// chain id, the route key, the set index, the member count, the
    /// members, the threshold and the expiry.
    public fun handover_digest(set_index: u64, committee: vector<vector<u8>>, threshold: u64, expires_at: u64): vector<u8> acquires Bridge {
        let b = borrow_global<Bridge>(@tenzro_bridge);
        let m = COMMITTEE_DOMAIN;
        vector::append(&mut m, be_u64(b.tenzro_chain_id));
        vector::append(&mut m, be_u64(vector::length(&b.route_key)));
        vector::append(&mut m, b.route_key);
        vector::append(&mut m, be_u32(set_index));
        vector::append(&mut m, be_u32(vector::length(&committee)));
        let i = 0;
        while (i < vector::length(&committee)) {
            vector::append(&mut m, *vector::borrow(&committee, i));
            i = i + 1;
        };
        vector::append(&mut m, be_u32(threshold));
        vector::append(&mut m, be_u64(expires_at));
        keccak256(m)
    }

    /// Hand the module over to committee `set_index`, signed by the committee
    /// it trusts. Only a higher set index is accepted.
    public entry fun rotate_committee(
        set_index: u64,
        committee: vector<vector<u8>>,
        threshold: u64,
        expires_at: u64,
        signatures: vector<vector<u8>>,
    ) acquires Bridge {
        assert!(set_index <= 4294967295, E_STALE_SET);
        check_committee(&committee, threshold);
        let digest = handover_digest(set_index, copy committee, threshold, expires_at);
        let b = borrow_global_mut<Bridge>(@tenzro_bridge);
        assert!(set_index > b.set_index, E_STALE_SET);
        check_quorum(b, digest, &signatures);
        b.committee = committee;
        b.threshold = threshold;
        b.set_index = set_index;
        b.expires_at = expires_at;
    }

    #[view]
    /// The trusted committee's set index and expiry (Unix seconds).
    public fun committee_set(): (u64, u64) acquires Bridge {
        let b = borrow_global<Bridge>(@tenzro_bridge);
        (b.set_index, b.expires_at)
    }

    #[view]
    public fun sequence(): u64 acquires Bridge { borrow_global<Bridge>(@tenzro_bridge).sequence }

    #[view]
    public fun is_executed(sequence: u64): bool acquires Bridge {
        smart_table::contains(&borrow_global<Bridge>(@tenzro_bridge).executed, sequence)
    }

    #[test_only]
    public fun mint_for_testing(to: address, amount: u64) acquires Bridge {
        let b = borrow_global<Bridge>(@tenzro_bridge);
        primary_fungible_store::mint(&b.mint_ref, to, amount);
    }
}
