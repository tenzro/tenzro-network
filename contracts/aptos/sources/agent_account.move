// SPDX-License-Identifier: Apache-2.0
/// Tenzro agent accounts on Aptos.
///
/// An agent's account is the object the registry names after the SHA-256 of
/// `"tenzro/omni-account/v1" || did`. It holds no key: its authority is the
/// grant Tenzro issued for the agent on this chain, installed by anyone with
/// `sync` (the grant bytes and their state proof under the state root of a
/// checkpoint the registry's finality client accepted). Aptos has no P-256
/// verification in Move, so the account takes exact grants only: each grant
/// carries the one action it allows, run once with `act_exact`, and an open
/// grant is refused. A void grant stops the action. The sender of the action
/// is refunded from the account up to the grant's cap.
module tenzro_bridge::agent_account {
    use std::hash::sha2_256;
    use std::signer;
    use std::vector;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::{FungibleAsset, Metadata};
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use tenzro_bridge::finality_client;

    friend tenzro_bridge::settlement_lock;

    const ENOT_PUBLISHER: u64 = 300;
    const ENO_REGISTRY: u64 = 301;
    const ENO_ACCOUNT: u64 = 302;
    const EBAD_STATE_PROOF: u64 = 303;
    const EMALFORMED_GRANT: u64 = 304;
    const ENOT_THIS_ACCOUNT: u64 = 305;
    const ESTALE_GRANT: u64 = 306;
    const EASSET_MISMATCH: u64 = 307;
    const ENO_LIVE_GRANT: u64 = 308;
    const EGRANT_VOID: u64 = 309;
    const EOUTSIDE_WINDOW: u64 = 310;
    const EOPEN_GRANT: u64 = 311;
    const EEXACT_USED: u64 = 312;
    const EPAYLOAD_MISMATCH: u64 = 313;
    const ERELAY_OVER_CAP: u64 = 314;
    const EMALFORMED_ACTION: u64 = 315;
    const EACCOUNT_EXISTS: u64 = 316;
    const EMALFORMED_PAYMENT: u64 = 317;

    /// The selector of an action that pays and reports the payment.
    const PAY_SELECTOR: vector<u8> = b"pay";
    /// What a paying action's data carries: payee (32), request and quote
    /// digests (32 each), USD price (u64).
    const PAY_DATA_LEN: u64 = 104;

    const GRANT_LEN: u64 = 322;
    const REGISTRY_SEED: vector<u8> = b"tenzro/agent-registry";
    const SALT_DOMAIN: vector<u8> = b"tenzro/omni-account/v1";
    const ZERO32: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";

    /// The parent of this chain's agent accounts, bound to a finality client.
    struct Registry has key {
        extend: ExtendRef,
        client: address,
        caip2: vector<u8>,
        chain: vector<u8>,
    }

    /// One agent's account.
    struct AgentAccount has key {
        extend: ExtendRef,
        agent: vector<u8>,
        tree_key: vector<u8>,
        installed: bool,
        grant: vector<u8>,
        caip19: vector<u8>,
        spent: u128,
        exact_used: bool,
    }

    #[event]
    struct Synced has drop, store {
        account: address,
        seq: u64,
        void: bool,
        payee: vector<u8>,
    }

    #[event]
    struct GrantClosed has drop, store {
        account: address,
        seq: u64,
        spent: u128,
    }

    /// A report Tenzro records through the chain's report route, in the
    /// layout Tenzro decodes.
    #[event]
    struct Reported has drop, store {
        account: address,
        report: vector<u8>,
    }

    #[event]
    struct Acted has drop, store {
        account: address,
        seq: u64,
        nonce: u64,
        digest: vector<u8>,
        amount: u128,
    }

    /// Create the registry for the chain `caip2` that follows Tenzro through
    /// the finality client at `client`. Only the package's publisher may.
    public entry fun initialize_registry(publisher: &signer, client: address, caip2: vector<u8>) {
        assert!(signer::address_of(publisher) == @tenzro_bridge, ENOT_PUBLISHER);
        let constructor = object::create_named_object(publisher, REGISTRY_SEED);
        let holder = object::generate_signer(&constructor);
        move_to(&holder, Registry {
            extend: object::generate_extend_ref(&constructor),
            client,
            caip2,
            chain: sha2_256(caip2),
        });
    }

    #[view]
    public fun registry_address(): address {
        object::create_object_address(&@tenzro_bridge, REGISTRY_SEED)
    }

    #[view]
    /// The finality client the registry reads state roots from.
    public fun finality_client(): address acquires Registry {
        assert!(exists<Registry>(registry_address()), ENO_REGISTRY);
        borrow_global<Registry>(registry_address()).client
    }

    fun salt(did: vector<u8>): vector<u8> {
        let b = SALT_DOMAIN;
        vector::append(&mut b, did);
        sha2_256(b)
    }

    #[view]
    /// Where the account of `did` is, created or not.
    public fun account_address(did: vector<u8>): address {
        object::create_object_address(&registry_address(), salt(did))
    }

    /// Create the account of `did`. Anyone may.
    public entry fun create_account(did: vector<u8>) acquires Registry {
        let at = account_address(did);
        assert!(!exists<AgentAccount>(at), EACCOUNT_EXISTS);
        let registry = borrow_global<Registry>(registry_address());
        let registry_signer = object::generate_signer_for_extending(&registry.extend);
        let constructor = object::create_named_object(&registry_signer, salt(did));
        let holder = object::generate_signer(&constructor);
        move_to(&holder, AgentAccount {
            extend: object::generate_extend_ref(&constructor),
            agent: sha2_256(did),
            tree_key: grant_tree_key(&did, &registry.caip2),
            installed: false,
            grant: vector[],
            caip19: vector[],
            spent: 0,
            exact_used: false,
        });
    }

    /// Install `grant`, proven by `proof` under the state root of final
    /// checkpoint `index`: a later grant, or the void of the current one.
    public entry fun sync(
        account: address,
        index: u64,
        grant: vector<u8>,
        proof: vector<u8>,
        caip19: vector<u8>,
        payee: vector<u8>,
    ) acquires Registry, AgentAccount {
        assert!(exists<AgentAccount>(account), ENO_ACCOUNT);
        let registry = borrow_global<Registry>(registry_address());
        let root = finality_client::state_root(registry.client, index);
        let a = borrow_global_mut<AgentAccount>(account);
        assert!(verify_at(&root, &a.tree_key, &grant, &proof), EBAD_STATE_PROOF);
        assert!(vector::length(&grant) == GRANT_LEN && *vector::borrow(&grant, 0) == 1 && *vector::borrow(&grant, 321) <= 1, EMALFORMED_GRANT);
        assert!(
            vector::slice(&grant, 1, 33) == registry.chain
                && vector::slice(&grant, 65, 97) == a.agent
                && vector::slice(&grant, 33, 65) == std::bcs::to_bytes(&account),
            ENOT_THIS_ACCOUNT,
        );
        let seq = be(&grant, 105, 8);
        let void = *vector::borrow(&grant, 321) == 1;
        let new_seq = true;
        if (a.installed) {
            let cur_seq = be(&a.grant, 105, 8);
            let cur_void = *vector::borrow(&a.grant, 321) == 1;
            let later = seq > cur_seq;
            assert!(later || (seq == cur_seq && void && !cur_void), ESTALE_GRANT);
            if (later) {
                event::emit(GrantClosed { account, seq: (cur_seq as u64), spent: a.spent });
            } else {
                new_seq = false;
            };
        };
        assert!(sha2_256(caip19) == vector::slice(&grant, 129, 161), EASSET_MISMATCH);
        if (new_seq) {
            a.exact_used = false;
            a.spent = 0;
        };
        a.grant = grant;
        a.caip19 = caip19;
        a.installed = true;
        event::emit(Synced { account, seq: (seq as u64), void, payee });
    }

    /// Run the one action the live exact grant carries, once: move its
    /// amount of the grant's fungible asset to its target, and refund the
    /// sender up to the grant's cap.
    public entry fun act_exact(sender: &signer, account: address, action: vector<u8>) acquires AgentAccount {
        let (target, out) = spend_exact(sender, account, &action);
        primary_fungible_store::deposit(target, out);
    }

    /// The exact grant's action, spent: its target, selector and data, the
    /// asset of exactly its amount, for a module of this package that passes
    /// it on (a settlement lock).
    public(friend) fun act_exact_take(
        sender: &signer,
        account: address,
        action: vector<u8>,
    ): (address, vector<u8>, vector<u8>, FungibleAsset) acquires AgentAccount {
        let (target, out) = spend_exact(sender, account, &action);
        (target, action_selector(&action), action_data(&action), out)
    }

    fun spend_exact(sender: &signer, account: address, action: &vector<u8>): (address, FungibleAsset) acquires AgentAccount {
        assert!(exists<AgentAccount>(account), ENO_ACCOUNT);
        let a = borrow_global_mut<AgentAccount>(account);
        assert!(a.installed, ENO_LIVE_GRANT);
        assert!(*vector::borrow(&a.grant, 321) == 0, EGRANT_VOID);
        let now = timestamp::now_microseconds() / 1000;
        assert!(now >= (be(&a.grant, 113, 8) as u64) && now <= (be(&a.grant, 121, 8) as u64), EOUTSIDE_WINDOW);
        let payload = vector::slice(&a.grant, 273, 305);
        assert!(payload != ZERO32, EOPEN_GRANT);
        assert!(!a.exact_used, EEXACT_USED);
        let digest = sha2_256(*action);
        assert!(digest == payload, EPAYLOAD_MISMATCH);
        let (target, amount, refund) = decode_action(action);
        assert!(refund <= (be(&a.grant, 305, 16) as u128), ERELAY_OVER_CAP);
        a.exact_used = true;
        a.spent = amount;
        let metadata = object::address_to_object<Metadata>(asset_address(&a.caip19));
        let holder = object::generate_signer_for_extending(&a.extend);
        let out = primary_fungible_store::withdraw(&holder, metadata, (amount as u64));
        if (refund > 0) {
            primary_fungible_store::transfer(&holder, metadata, signer::address_of(sender), (refund as u64));
        };
        event::emit(Acted { account, seq: (be(&a.grant, 105, 8) as u64), nonce: 0, digest, amount });
        // A paying action reports the payment, bound to what it bought, for
        // Tenzro to record as this agent's.
        if (action_selector(action) == PAY_SELECTOR) {
            event::emit(Reported { account, report: paid_report(&a.grant, 0, action, amount) });
        };
        (target, out)
    }

    fun action_data(a: &vector<u8>): vector<u8> {
        let sl = (be(a, 34, 2) as u64);
        let at = 36 + sl + 32;
        vector::slice(a, at + 4, vector::length(a))
    }

    fun action_selector(a: &vector<u8>): vector<u8> {
        let sl = (be(a, 34, 2) as u64);
        vector::slice(a, 36, 36 + sl)
    }

    /// The report of a paying action: kind 4, the grant's chain, account,
    /// agent and seq, the nonce, the action's pay data and the amount.
    public fun paid_report(grant: &vector<u8>, nonce: u64, action: &vector<u8>, amount: u128): vector<u8> {
        let sl = (be(action, 34, 2) as u64);
        let at = 36 + sl + 36;
        assert!(vector::length(action) == at + PAY_DATA_LEN, EMALFORMED_PAYMENT);
        let r = vector[4u8];
        vector::append(&mut r, vector::slice(grant, 1, 97));
        vector::append(&mut r, vector::slice(grant, 105, 113));
        vector::append(&mut r, be_out((nonce as u256), 8));
        vector::append(&mut r, vector::slice(action, at, at + PAY_DATA_LEN));
        vector::append(&mut r, be_out((amount as u256), 16));
        r
    }

    fun be_out(v: u256, n: u64): vector<u8> {
        let out = vector[];
        let i = 0;
        while (i < n) {
            vector::push_back(&mut out, (((v >> (((n - 1 - i) * 8) as u8)) & 0xff) as u8));
            i = i + 1;
        };
        out
    }

    /// The metadata address of `<caip2>/fa:0x<64 hex>`.
    fun asset_address(caip19: &vector<u8>): address {
        let n = vector::length(caip19);
        assert!(n > 66, EASSET_MISMATCH);
        let hex = vector::slice(caip19, n - 64, n);
        assert!(vector::slice(caip19, n - 68, n - 64) == b"/fa:" || vector::slice(caip19, n - 70, n - 64) == b"/fa:0x", EASSET_MISMATCH);
        let bytes = vector[];
        let i = 0;
        while (i < 64) {
            let hi = nibble(*vector::borrow(&hex, i));
            let lo = nibble(*vector::borrow(&hex, i + 1));
            vector::push_back(&mut bytes, hi * 16 + lo);
            i = i + 2;
        };
        aptos_std::from_bcs::to_address(bytes)
    }

    fun nibble(c: u8): u8 {
        if (c >= 48 && c <= 57) c - 48
        else if (c >= 97 && c <= 102) c - 87
        else {
            assert!(c >= 65 && c <= 70, EASSET_MISMATCH);
            c - 55
        }
    }

    /// target (u16-prefixed, 32 bytes), selector (u16-prefixed), amount
    /// (u128), refund (u128), data (u32-prefixed); nothing after.
    fun decode_action(a: &vector<u8>): (address, u128, u128) {
        let tl = (be(a, 0, 2) as u64);
        assert!(tl == 32, EMALFORMED_ACTION);
        let target = aptos_std::from_bcs::to_address(vector::slice(a, 2, 34));
        let sl = (be(a, 34, 2) as u64);
        let at = 36 + sl;
        let amount = (be(a, at, 16) as u128);
        let refund = (be(a, at + 16, 16) as u128);
        let dl = (be(a, at + 32, 4) as u64);
        assert!(vector::length(a) == at + 36 + dl, EMALFORMED_ACTION);
        (target, amount, refund)
    }

    /// The tree key of the grant of `did` on `caip2`: VM system storage,
    /// keyed by the hex of `agent_grant:<did>:<caip2>`.
    public fun grant_tree_key(did: &vector<u8>, caip2: &vector<u8>): vector<u8> {
        let key = b"agent_grant:";
        vector::append(&mut key, *did);
        vector::append(&mut key, b":");
        vector::append(&mut key, *caip2);
        let digits = b"0123456789abcdef";
        let out = b"tenzro.state-trie.key";
        vector::append(&mut out, x"0500");
        vector::append(&mut out, b"state");
        vector::append(&mut out, b"storage:ffffffffffffffffffffffffffffffffffffffff:");
        let i = 0;
        while (i < vector::length(&key)) {
            let b = *vector::borrow(&key, i);
            vector::push_back(&mut out, *vector::borrow(&digits, ((b >> 4) as u64)));
            vector::push_back(&mut out, *vector::borrow(&digits, ((b & 15) as u64)));
            i = i + 1;
        };
        sha2_256(out)
    }

    /// Whether, under `root`, the entry with tree key `tk` holds `value`, by
    /// the encoded state proof `proof` (a present entry ends at its stem).
    public fun verify_at(root: &vector<u8>, tk: &vector<u8>, value: &vector<u8>, proof: &vector<u8>): bool {
        if (vector::length(proof) < 3) return false;
        let depth = (be(proof, 0, 2) as u64);
        if (depth > 248) return false;
        let t = 2 + 32 * depth;
        if (vector::length(proof) != t + 1 + 256 || *vector::borrow(proof, t) != 2) return false;
        let stem = vector::slice(tk, 0, 31);
        let leaf = x"00";
        vector::append(&mut leaf, *value);
        let s = sha2_256(leaf);
        let index = *vector::borrow(tk, 31);
        let i = 0;
        while (i < 8) {
            let sib = vector::slice(proof, t + 1 + 32 * i, t + 33 + 32 * i);
            s = if (index & 1 == 0) slot_pair(s, sib) else slot_pair(sib, s);
            index = index >> 1;
            i = i + 1;
        };
        if (s == ZERO32) return false;
        let b = x"02";
        vector::append(&mut b, stem);
        vector::append(&mut b, s);
        let acc = sha2_256(b);
        let d = depth;
        while (d > 0) {
            d = d - 1;
            let sib = vector::slice(proof, 2 + 32 * d, 34 + 32 * d);
            let n = x"01";
            if (bit(&stem, d) == 0) {
                vector::append(&mut n, acc);
                vector::append(&mut n, sib);
            } else {
                vector::append(&mut n, sib);
                vector::append(&mut n, acc);
            };
            acc = sha2_256(n);
        };
        &acc == root
    }

    fun slot_pair(l: vector<u8>, r: vector<u8>): vector<u8> {
        if (l == ZERO32 && r == ZERO32) return ZERO32;
        let b = x"03";
        vector::append(&mut b, l);
        vector::append(&mut b, r);
        sha2_256(b)
    }

    fun bit(stem: &vector<u8>, depth: u64): u8 {
        (*vector::borrow(stem, depth / 8) >> ((7 - depth % 8) as u8)) & 1
    }

    fun be(v: &vector<u8>, at: u64, n: u64): u256 {
        let out: u256 = 0;
        let i = 0;
        while (i < n) {
            out = (out << 8) | (*vector::borrow(v, at + i) as u256);
            i = i + 1;
        };
        out
    }
}
