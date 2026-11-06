// SPDX-License-Identifier: Apache-2.0
/// Tenzro settlement-plan legs on Aptos.
///
/// A payer locks an amount of a fungible asset as leg `index` of plan
/// `plan_id`, payable to a recipient. The leg settles once, on the plan's
/// decision proven under the state root of a final checkpoint held by
/// Tenzro's finality client on Aptos: a commit pays the recipient, an abort
/// refunds the payer. Without a proven decision the payer reclaims the leg
/// only after the escape horizon. No key holds any authority here: the lock
/// object's signer is reachable only through this module.
///
/// The decision commitment at `decision:<plan_id>` is
/// `version (1) || outcome (1: 1 commit, 2 abort) || decided_at_ms (8) || plan_id (32)`.
///
/// Every lock, release and refund folds into a running reconciliation hash;
/// `checkpoint` emits it with the entry count, for Tenzro to compare with its
/// own books.
module tenzro_bridge::settlement_lock {
    use std::hash::sha2_256;
    use std::signer;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use aptos_framework::object::{Self, ExtendRef, Object};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use aptos_std::table::{Self, Table};
    use tenzro_bridge::agent_account;
    use tenzro_bridge::finality_client;

    const ENOT_PUBLISHER: u64 = 400;
    const ENO_LOCK: u64 = 401;
    const EALREADY_LOCKED: u64 = 402;
    const ENOT_LOCKED: u64 = 403;
    const EBAD_AMOUNT: u64 = 404;
    const EUNPROVEN: u64 = 405;
    const ETOO_EARLY: u64 = 406;
    const EBAD_PLAN_ID: u64 = 407;
    const ENOT_THIS_LOCK: u64 = 408;
    const EBAD_LOCK_DATA: u64 = 409;

    const LOCKED: u8 = 1;
    const RELEASED: u8 = 2;
    const REFUNDED: u8 = 3;
    const DECISION_LEN: u64 = 42;
    const LOCK_SEED: vector<u8> = b"tenzro/settlement-lock";
    const HEX: vector<u8> = b"0123456789abcdef";
    const RECON_DOMAIN: vector<u8> = b"tenzro/settlement/recon/v1";

    struct Leg has store, drop {
        payer: address,
        recipient: address,
        asset: Object<Metadata>,
        amount: u64,
        escape_at_ms: u64,
        stage: u8,
    }

    /// The lock, held at its object's address with the locked assets.
    struct Lock has key {
        extend: ExtendRef,
        client: address,
        escape_horizon_ms: u64,
        legs: Table<vector<u8>, Leg>,
        /// Entries recorded and the running reconciliation hash over them.
        recon_count: u64,
        recon_acc: vector<u8>,
    }

    #[event]
    /// The lock's reconciliation checkpoint.
    struct Accumulator has drop, store {
        count: u64,
        acc: vector<u8>,
    }

    #[event]
    struct Locked has drop, store {
        plan_id: vector<u8>,
        leg_id: vector<u8>,
        index: u8,
        payer: address,
        recipient: address,
        asset: address,
        amount: u64,
        escape_at_ms: u64,
    }

    #[event]
    struct Released has drop, store {
        plan_id: vector<u8>,
        leg_id: vector<u8>,
        to: address,
        amount: u64,
    }

    #[event]
    struct Refunded has drop, store {
        plan_id: vector<u8>,
        leg_id: vector<u8>,
        to: address,
        amount: u64,
        escaped: bool,
    }

    /// Create the lock, reading final state roots from `client` and letting
    /// an undecided leg escape `escape_horizon_ms` after it was locked.
    public entry fun initialize(publisher: &signer, client: address, escape_horizon_ms: u64) {
        assert!(signer::address_of(publisher) == @tenzro_bridge, ENOT_PUBLISHER);
        let constructor = object::create_named_object(publisher, LOCK_SEED);
        let holder = object::generate_signer(&constructor);
        move_to(&holder, Lock {
            extend: object::generate_extend_ref(&constructor),
            client,
            escape_horizon_ms,
            legs: table::new(),
            recon_count: 0,
            recon_acc: x"0000000000000000000000000000000000000000000000000000000000000000",
        });
    }

    #[view]
    /// Where the lock and its assets are.
    public fun lock_address(): address {
        object::create_object_address(&@tenzro_bridge, LOCK_SEED)
    }

    #[view]
    /// The id Tenzro gives leg `index` of `plan_id`.
    public fun leg_id(plan_id: vector<u8>, index: u8): vector<u8> {
        assert!(vector::length(&plan_id) == 32, EBAD_PLAN_ID);
        let b = b"tenzro/plan/leg/v1";
        vector::append(&mut b, plan_id);
        vector::push_back(&mut b, index);
        sha2_256(b)
    }

    #[view]
    /// The state tree key of `decision:<plan_id>`: VM system storage, keyed
    /// by the hex of the record key.
    public fun decision_tree_key(plan_id: vector<u8>): vector<u8> {
        let record = b"decision:";
        vector::append(&mut record, hex(&plan_id));
        let b = b"tenzro.state-trie.key";
        vector::append(&mut b, x"0500");
        vector::append(&mut b, b"state");
        vector::append(&mut b, b"storage:");
        let i = 0;
        while (i < 40) {
            vector::push_back(&mut b, 0x66);
            i = i + 1;
        };
        vector::push_back(&mut b, 0x3a);
        vector::append(&mut b, hex(&record));
        sha2_256(b)
    }

    fun hex(v: &vector<u8>): vector<u8> {
        let digits = HEX;
        let out = vector[];
        let i = 0;
        while (i < vector::length(v)) {
            let byte = *vector::borrow(v, i);
            vector::push_back(&mut out, *vector::borrow(&digits, ((byte >> 4) as u64)));
            vector::push_back(&mut out, *vector::borrow(&digits, ((byte & 15) as u64)));
            i = i + 1;
        };
        out
    }

    #[view]
    /// The stage of leg `index` of `plan_id` (1 locked, 2 released, 3 refunded).
    public fun stage(plan_id: vector<u8>, index: u8): u8 acquires Lock {
        let l = borrow_global<Lock>(lock_address());
        let id = leg_id(plan_id, index);
        assert!(table::contains(&l.legs, id), ENOT_LOCKED);
        table::borrow(&l.legs, id).stage
    }

    /// Lock `amount` of `asset` from `payer` as leg `index` of `plan_id`,
    /// payable to `recipient`.
    public entry fun lock(
        payer: &signer,
        plan_id: vector<u8>,
        index: u8,
        asset: Object<Metadata>,
        amount: u64,
        recipient: address,
    ) acquires Lock {
        let from = signer::address_of(payer);
        lock_as(plan_id, index, primary_fungible_store::withdraw(payer, asset, amount), from, recipient);
    }

    /// Lock a leg paid by agent account `account` with its exact grant's one
    /// action: the action names this lock as the target, `lock` as the
    /// selector, and plan id (32 bytes), leg index (1 byte) and recipient (32
    /// bytes) as the data. The account hands over exactly the action's amount
    /// and is the leg's payer.
    public entry fun lock_exact_from_agent(sender: &signer, account: address, action: vector<u8>) acquires Lock {
        let (target, selector, data, fa) = agent_account::act_exact_take(sender, account, action);
        assert!(target == lock_address() && selector == b"lock", ENOT_THIS_LOCK);
        assert!(vector::length(&data) == 65, EBAD_LOCK_DATA);
        let recipient = aptos_std::from_bcs::to_address(vector::slice(&data, 33, 65));
        lock_as(vector::slice(&data, 0, 32), *vector::borrow(&data, 32), fa, account, recipient);
    }

    fun lock_as(plan_id: vector<u8>, index: u8, fa: FungibleAsset, payer: address, recipient: address) acquires Lock {
        let at = lock_address();
        assert!(exists<Lock>(at), ENO_LOCK);
        let l = borrow_global_mut<Lock>(at);
        let id = leg_id(plan_id, index);
        assert!(!table::contains(&l.legs, id), EALREADY_LOCKED);
        let amount = fungible_asset::amount(&fa);
        assert!(amount > 0, EBAD_AMOUNT);
        let asset = fungible_asset::metadata_from_asset(&fa);
        primary_fungible_store::deposit(at, fa);
        let escape_at_ms = timestamp::now_microseconds() / 1000 + l.escape_horizon_ms;
        table::add(&mut l.legs, id, Leg { payer, recipient, asset, amount, escape_at_ms, stage: LOCKED });
        record(l, plan_id, id, LOCKED, amount);
        event::emit(Locked {
            plan_id,
            leg_id: id,
            index,
            payer,
            recipient,
            asset: object::object_address(&asset),
            amount,
            escape_at_ms,
        });
    }

    /// Settle leg `index` of `plan_id` on the decision at `decision:<plan_id>`,
    /// proven by `proof` under final checkpoint `checkpoint`. Anyone may call.
    public entry fun settle(
        plan_id: vector<u8>,
        index: u8,
        checkpoint: u64,
        decision: vector<u8>,
        proof: vector<u8>,
    ) acquires Lock {
        let at = lock_address();
        assert!(exists<Lock>(at), ENO_LOCK);
        let l = borrow_global_mut<Lock>(at);
        let id = leg_id(plan_id, index);
        assert!(table::contains(&l.legs, id), ENOT_LOCKED);
        let root = finality_client::state_root(l.client, checkpoint);
        assert!(vector::length(&decision) == DECISION_LEN && *vector::borrow(&decision, 0) == 1, EUNPROVEN);
        let i = 0;
        while (i < 32) {
            assert!(*vector::borrow(&decision, 10 + i) == *vector::borrow(&plan_id, i), EUNPROVEN);
            i = i + 1;
        };
        let outcome = *vector::borrow(&decision, 1);
        assert!(outcome == 1 || outcome == 2, EUNPROVEN);
        assert!(agent_account::verify_at(&root, &decision_tree_key(plan_id), &decision, &proof), EUNPROVEN);
        let holder = object::generate_signer_for_extending(&l.extend);
        let leg = table::borrow_mut(&mut l.legs, id);
        assert!(leg.stage == LOCKED, ENOT_LOCKED);
        let amount = leg.amount;
        let (stage, to) = if (outcome == 1) (RELEASED, leg.recipient) else (REFUNDED, leg.payer);
        leg.stage = stage;
        primary_fungible_store::transfer(&holder, leg.asset, to, amount);
        record(l, plan_id, id, stage, amount);
        if (outcome == 1) event::emit(Released { plan_id, leg_id: id, to, amount })
        else event::emit(Refunded { plan_id, leg_id: id, to, amount, escaped: false });
    }

    /// Reclaim an undecided leg once its escape horizon has passed.
    public entry fun escape(plan_id: vector<u8>, index: u8) acquires Lock {
        let at = lock_address();
        assert!(exists<Lock>(at), ENO_LOCK);
        let l = borrow_global_mut<Lock>(at);
        let id = leg_id(plan_id, index);
        assert!(table::contains(&l.legs, id), ENOT_LOCKED);
        let holder = object::generate_signer_for_extending(&l.extend);
        let leg = table::borrow_mut(&mut l.legs, id);
        assert!(leg.stage == LOCKED, ENOT_LOCKED);
        assert!(timestamp::now_microseconds() / 1000 >= leg.escape_at_ms, ETOO_EARLY);
        leg.stage = REFUNDED;
        let (to, amount) = (leg.payer, leg.amount);
        primary_fungible_store::transfer(&holder, leg.asset, to, amount);
        record(l, plan_id, id, REFUNDED, amount);
        event::emit(Refunded { plan_id, leg_id: id, to, amount, escaped: true });
    }

    #[view]
    /// The entries recorded and the running reconciliation hash over them.
    public fun reconciliation(): (u64, vector<u8>) acquires Lock {
        let at = lock_address();
        assert!(exists<Lock>(at), ENO_LOCK);
        let l = borrow_global<Lock>(at);
        (l.recon_count, l.recon_acc)
    }

    /// Emit the running reconciliation hash and its entry count, for Tenzro
    /// to prove and compare with its own books.
    public entry fun checkpoint() acquires Lock {
        let (count, acc) = reconciliation();
        event::emit(Accumulator { count, acc });
    }

    /// Fold one entry into the running reconciliation hash:
    /// `sha256(domain || acc || plan_id || leg_id || kind || amount)`, the
    /// amount as a 32-byte big-endian word.
    fun record(l: &mut Lock, plan_id: vector<u8>, leg_id: vector<u8>, kind: u8, amount: u64) {
        let b = RECON_DOMAIN;
        vector::append(&mut b, l.recon_acc);
        vector::append(&mut b, plan_id);
        vector::append(&mut b, leg_id);
        vector::push_back(&mut b, kind);
        let i = 0;
        while (i < 24) {
            vector::push_back(&mut b, 0);
            i = i + 1;
        };
        let shift = 64;
        while (shift > 0) {
            shift = shift - 8;
            vector::push_back(&mut b, (((amount >> (shift as u8)) & 0xff) as u8));
        };
        l.recon_acc = sha2_256(b);
        l.recon_count = l.recon_count + 1;
    }
}
