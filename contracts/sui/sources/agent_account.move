// SPDX-License-Identifier: Apache-2.0
/// Tenzro agent accounts on Sui.
///
/// An agent's account is the object a registry derives from the SHA-256 of
/// the agent's DID. It holds no key: its authority is the grant Tenzro issued
/// for the agent on this chain. Anyone installs a grant with `sync`: the grant
/// bytes and their state proof under the state root of a checkpoint the
/// registry's finality client accepted. An action moves coins of the grant's
/// asset to its target when serving nodes of the agent signed the action's
/// digest preimage with P-256 keys in the grant's key root (two of distinct
/// operators above the cosign threshold), within the grant's budget,
/// per-action limit, time window and targets. An exact grant carries one
/// action, run once with `act_exact`. A void grant stops every action. The
/// sender of an action is refunded from the account up to the grant's cap.
#[allow(implicit_const_copy)]
module tenzro_bridge::agent_account;

use std::hash::sha2_256;
use std::type_name;
use sui::balance::{Self, Balance};
use sui::bcs;
use sui::clock::Clock;
use sui::coin::{Self, Coin};
use sui::derived_object;
use sui::dynamic_field as df;
use sui::ecdsa_r1;
use sui::event;
use tenzro_bridge::finality_client::{Self, FinalityClient};

const EWrongRegistry: u64 = 200;
const EBadStateProof: u64 = 201;
const EMalformedGrant: u64 = 202;
const ENotThisAccount: u64 = 203;
const EStaleGrant: u64 = 204;
const EAssetMismatch: u64 = 205;
const ENoLiveGrant: u64 = 206;
const EGrantVoid: u64 = 207;
const EOutsideWindow: u64 = 208;
const EExactGrant: u64 = 209;
const ENotExact: u64 = 210;
const EExactUsed: u64 = 211;
const EPayloadMismatch: u64 = 212;
const EHighS: u64 = 213;
const EBadSignature: u64 = 214;
const EKeyNotInRoot: u64 = 215;
const ECosignRequired: u64 = 216;
const ETargetNotAllowed: u64 = 217;
const EOverPerAction: u64 = 218;
const EOverBudget: u64 = 219;
const ERelayOverCap: u64 = 220;
const EMalformedAction: u64 = 221;
const EMalformedPayment: u64 = 222;

/// The selector of an action that pays and reports the payment.
const PAY_SELECTOR: vector<u8> = b"pay";
/// What a paying action's data carries: payee (32), request and quote
/// digests (32 each), USD price (u64).
const PAY_DATA_LEN: u64 = 104;

const GRANT_LEN: u64 = 322;
const ACT_DOMAIN: vector<u8> = b"tenzro/agent-act/v1";
const ZERO32: vector<u8> = x"0000000000000000000000000000000000000000000000000000000000000000";
/// Half the order of P-256.
const P256_HALF_N: u256 = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;
const SHA256: u8 = 1;

/// The parent of a chain's agent accounts, bound to Tenzro's finality client.
public struct Registry has key {
    id: UID,
    client: ID,
    caip2: vector<u8>,
    chain: vector<u8>,
}

/// One agent's account.
public struct AgentAccount has key {
    id: UID,
    registry: ID,
    agent: vector<u8>,
    tree_key: vector<u8>,
    installed: bool,
    grant: vector<u8>,
    caip19: vector<u8>,
    spent: u128,
    nonce: u64,
    exact_used: bool,
}

/// Where the account keeps a balance of coin type `T`.
public struct BalanceKey<phantom T> has copy, drop, store {}

public struct Synced has copy, drop {
    account: address,
    seq: u64,
    void: bool,
    payee: vector<u8>,
}

public struct GrantClosed has copy, drop {
    account: address,
    seq: u64,
    spent: u128,
}

/// A report Tenzro records through the chain's report route, in the
/// layout Tenzro decodes.
public struct Reported has copy, drop {
    account: address,
    report: vector<u8>,
}

public struct Acted has copy, drop {
    account: address,
    seq: u64,
    nonce: u64,
    digest: vector<u8>,
    amount: u128,
}

/// Share the registry of agent accounts on the chain `caip2` that follows
/// Tenzro through `client`. Returns its id.
public fun create_registry(client: &FinalityClient, caip2: vector<u8>, ctx: &mut TxContext): ID {
    let registry = Registry { id: object::new(ctx), client: object::id(client), caip2, chain: sha2_256(caip2) };
    let id = object::id(&registry);
    transfer::share_object(registry);
    id
}

/// Where the account of `did` is, created or not.
public fun account_address(registry: &Registry, did: vector<u8>): address {
    derived_object::derive_address(object::id(registry), sha2_256(salt_input(did)))
}

fun salt_input(did: vector<u8>): vector<u8> {
    let mut b = b"tenzro/omni-account/v1";
    b.append(did);
    b
}

/// Create and share the account of `did`. Anyone may.
public fun create_account(registry: &mut Registry, did: vector<u8>): address {
    let uid = derived_object::claim(&mut registry.id, sha2_256(salt_input(did)));
    let account = AgentAccount {
        id: uid,
        registry: object::id(registry),
        agent: sha2_256(did),
        tree_key: grant_tree_key(&did, &registry.caip2),
        installed: false,
        grant: vector[],
        caip19: vector[],
        spent: 0,
        nonce: 0,
        exact_used: false,
    };
    let at = object::id_address(&account);
    transfer::share_object(account);
    at
}

/// Add `coin` to the account's balance. Anyone may.
public fun deposit<T>(account: &mut AgentAccount, coin: Coin<T>) {
    let key = BalanceKey<T> {};
    if (!df::exists_(&account.id, key)) {
        df::add(&mut account.id, key, balance::zero<T>());
    };
    let b: &mut Balance<T> = df::borrow_mut(&mut account.id, key);
    b.join(coin.into_balance());
}

/// Take into the balance a coin sent to this account's address (a lock's
/// refund). Anyone may call.
public fun receive<T>(account: &mut AgentAccount, sent: transfer::Receiving<Coin<T>>) {
    let coin = transfer::public_receive(&mut account.id, sent);
    deposit<T>(account, coin);
}

/// The account's balance of `T`.
public fun balance_of<T>(account: &AgentAccount): u64 {
    let key = BalanceKey<T> {};
    if (!df::exists_(&account.id, key)) return 0;
    let b: &Balance<T> = df::borrow(&account.id, key);
    b.value()
}

/// Install `grant`, proven by `proof` under the state root of final
/// checkpoint `index`: a later grant, or the void of the current one.
/// `caip19` names the grant's asset; `payee` is the Tenzro account a relay
/// task pays for installing a void.
public fun sync(
    account: &mut AgentAccount,
    registry: &Registry,
    client: &FinalityClient,
    index: u64,
    grant: vector<u8>,
    proof: vector<u8>,
    caip19: vector<u8>,
    payee: vector<u8>,
) {
    assert!(account.registry == object::id(registry) && registry.client == object::id(client), EWrongRegistry);
    let root = finality_client::state_root(client, index);
    assert!(verify_at(&root, &account.tree_key, &grant, &proof), EBadStateProof);
    assert!(grant.length() == GRANT_LEN && grant[0] == 1 && grant[321] <= 1, EMalformedGrant);
    let here = bcs::to_bytes(&object::id_address(account));
    assert!(slice(&grant, 1, 33) == registry.chain && slice(&grant, 65, 97) == account.agent && slice(&grant, 33, 65) == here, ENotThisAccount);
    let seq = be_u64(&grant, 105);
    let void = grant[321] == 1;
    let mut new_seq = true;
    if (account.installed) {
        let cur_seq = be_u64(&account.grant, 105);
        let cur_void = account.grant[321] == 1;
        let later = seq > cur_seq;
        assert!(later || (seq == cur_seq && void && !cur_void), EStaleGrant);
        if (later) {
            event::emit(GrantClosed { account: object::id_address(account), seq: cur_seq, spent: account.spent });
        } else {
            new_seq = false;
        };
    };
    assert!(sha2_256(caip19) == slice(&grant, 129, 161), EAssetMismatch);
    if (new_seq) {
        account.spent = 0;
        account.exact_used = false;
    };
    account.grant = grant;
    account.caip19 = caip19;
    account.installed = true;
    event::emit(Synced { account: object::id_address(account), seq, void, payee });
}

/// Move coins of `T` as the action `action` (encoded) says, signed by serving
/// nodes: `keys` (SEC1, 65 bytes), their `operators`, their Merkle proofs
/// into the key root (`key_proofs`, 32-byte siblings concatenated) and their
/// `signatures` (r || s, low-S) over the digest preimage. `target_proof` is
/// the target's Merkle proof when the grant names targets.
public fun act<T>(
    account: &mut AgentAccount,
    clock: &Clock,
    action: vector<u8>,
    keys: vector<vector<u8>>,
    operators: vector<vector<u8>>,
    key_proofs: vector<vector<u8>>,
    signatures: vector<vector<u8>>,
    target_proof: vector<u8>,
    ctx: &mut TxContext,
) {
    let digest = authorize<T>(account, clock, &action, keys, operators, key_proofs, signatures, target_proof);
    pay<T>(account, &action, digest, ctx);
}

/// Run the one action an exact grant carries, once.
public fun act_exact<T>(account: &mut AgentAccount, clock: &Clock, action: vector<u8>, ctx: &mut TxContext) {
    let digest = authorize_exact<T>(account, clock, &action);
    pay<T>(account, &action, digest, ctx);
}

/// A signed action's coin of exactly its amount, for a module of this
/// package that passes it on (a settlement lock), with the action's target,
/// selector and data and this account's address.
public(package) fun act_take<T>(
    account: &mut AgentAccount,
    clock: &Clock,
    action: vector<u8>,
    keys: vector<vector<u8>>,
    operators: vector<vector<u8>>,
    key_proofs: vector<vector<u8>>,
    signatures: vector<vector<u8>>,
    target_proof: vector<u8>,
    ctx: &mut TxContext,
): (vector<u8>, vector<u8>, vector<u8>, Coin<T>, address) {
    let digest = authorize<T>(account, clock, &action, keys, operators, key_proofs, signatures, target_proof);
    taken<T>(account, action, digest, ctx)
}

/// `act_take` for the one action of an exact grant.
public(package) fun act_exact_take<T>(
    account: &mut AgentAccount,
    clock: &Clock,
    action: vector<u8>,
    ctx: &mut TxContext,
): (vector<u8>, vector<u8>, vector<u8>, Coin<T>, address) {
    let digest = authorize_exact<T>(account, clock, &action);
    taken<T>(account, action, digest, ctx)
}

fun taken<T>(account: &mut AgentAccount, action: vector<u8>, digest: vector<u8>, ctx: &mut TxContext): (vector<u8>, vector<u8>, vector<u8>, Coin<T>, address) {
    let (target, selector, _, _) = decode_action(&action);
    let coin = take<T>(account, &action, digest, ctx);
    (target, selector, action_data(&action), coin, object::id_address(account))
}

fun authorize<T>(
    account: &AgentAccount,
    clock: &Clock,
    action: &vector<u8>,
    keys: vector<vector<u8>>,
    operators: vector<vector<u8>>,
    key_proofs: vector<vector<u8>>,
    signatures: vector<vector<u8>>,
    target_proof: vector<u8>,
): vector<u8> {
    live(account, clock, &type_name_caip19<T>(account));
    assert!(slice(&account.grant, 273, 305) == ZERO32, EExactGrant);
    let (target, selector, amount, refund) = decode_action(action);
    assert!(amount <= be_u128(&account.grant, 177), EOverPerAction);
    assert!(account.spent + amount <= be_u128(&account.grant, 161), EOverBudget);
    assert!(refund <= be_u128(&account.grant, 305), ERelayOverCap);
    let targets_root = slice(&account.grant, 241, 273);
    if (targets_root != ZERO32) {
        assert!(merkle_verify(&targets_root, &target_leaf(&target, &selector), &target_proof), ETargetNotAllowed);
    };
    let mut preimage = ACT_DOMAIN;
    preimage.append(slice(&account.grant, 1, 33));
    preimage.append(slice(&account.grant, 33, 65));
    preimage.append(slice(&account.grant, 105, 113));
    preimage.append(be_bytes(account.nonce as u256, 8));
    preimage.append(*action);
    let need = if (amount > be_u128(&account.grant, 193)) 2 else 1;
    assert!(signatures.length() >= need && keys.length() >= need && operators.length() >= need && key_proofs.length() >= need, ECosignRequired);
    let keys_root = slice(&account.grant, 209, 241);
    let mut i = 0;
    while (i < need) {
        let key = &keys[i];
        let sig = &signatures[i];
        assert!(key.length() == 65 && sig.length() == 64, EBadSignature);
        assert!(to_u256(&slice(sig, 32, 64)) <= P256_HALF_N, EHighS);
        assert!(ecdsa_r1::secp256r1_verify(sig, &compress(key), &preimage, SHA256), EBadSignature);
        let mut leaf_in = x"00";
        leaf_in.append(*key);
        leaf_in.append(operators[i]);
        assert!(merkle_verify(&keys_root, &sha2_256(leaf_in), &key_proofs[i]), EKeyNotInRoot);
        if (i == 1) {
            assert!(operators[0] != operators[1], ECosignRequired);
        };
        i = i + 1;
    };
    sha2_256(preimage)
}

fun authorize_exact<T>(account: &mut AgentAccount, clock: &Clock, action: &vector<u8>): vector<u8> {
    live(account, clock, &type_name_caip19<T>(account));
    let payload = slice(&account.grant, 273, 305);
    assert!(payload != ZERO32, ENotExact);
    assert!(!account.exact_used, EExactUsed);
    let digest = sha2_256(*action);
    assert!(digest == payload, EPayloadMismatch);
    let (_, _, _, refund) = decode_action(action);
    assert!(refund <= be_u128(&account.grant, 305), ERelayOverCap);
    account.exact_used = true;
    digest
}

fun pay<T>(account: &mut AgentAccount, action: &vector<u8>, digest: vector<u8>, ctx: &mut TxContext) {
    let (target, _, _, _) = decode_action(action);
    let out = take<T>(account, action, digest, ctx);
    transfer::public_transfer(out, sui::address::from_bytes(target));
}

/// Spend the action: report a payment, move the nonce and the spent total,
/// refund the relayer, and return a coin of exactly the action's amount.
#[allow(lint(self_transfer))]
fun take<T>(account: &mut AgentAccount, action: &vector<u8>, digest: vector<u8>, ctx: &mut TxContext): Coin<T> {
    let (_, selector, amount, refund) = decode_action(action);
    let n = account.nonce;
    // A paying action reports the payment, bound to what it bought, for
    // Tenzro to record as this agent's.
    if (selector == PAY_SELECTOR) {
        let report = paid_report(&account.grant, n, action, amount);
        event::emit(Reported { account: object::id_address(account), report });
    };
    account.nonce = n + 1;
    account.spent = account.spent + amount;
    let b: &mut Balance<T> = df::borrow_mut(&mut account.id, BalanceKey<T> {});
    let out = coin::from_balance(b.split(amount as u64), ctx);
    if (refund > 0) {
        let r = coin::from_balance(b.split(refund as u64), ctx);
        transfer::public_transfer(r, ctx.sender());
    };
    event::emit(Acted { account: object::id_address(account), seq: be_u64(&account.grant, 105), nonce: n, digest, amount });
    out
}

/// The data of an encoded action.
fun action_data(a: &vector<u8>): vector<u8> {
    let tl = (be(a, 0, 2) as u64);
    let sl = (be(a, 2 + tl, 2) as u64);
    let at = 4 + tl + sl + 32;
    slice(a, at + 4, a.length())
}

#[test_only]
/// Install `grant` without a state proof, for tests of modules that act
/// through an account.
public fun install_for_testing(account: &mut AgentAccount, grant: vector<u8>, caip19: vector<u8>) {
    account.grant = grant;
    account.caip19 = caip19;
    account.installed = true;
    account.spent = 0;
    account.exact_used = false;
}

fun live(account: &AgentAccount, clock: &Clock, caip19: &vector<u8>) {
    assert!(account.installed, ENoLiveGrant);
    assert!(account.grant[321] == 0, EGrantVoid);
    let now = clock.timestamp_ms();
    assert!(now >= be_u64(&account.grant, 113) && now <= be_u64(&account.grant, 121), EOutsideWindow);
    assert!(&account.caip19 == caip19, EAssetMismatch);
}

/// The CAIP-19 id of coin type `T` on the account's chain.
fun type_name_caip19<T>(account: &AgentAccount): vector<u8> {
    let caip2_end = find(&account.caip19, b"/");
    let mut out = slice(&account.caip19, 0, caip2_end);
    out.append(b"/coin:");
    out.append(type_name::with_defining_ids<T>().into_string().into_bytes());
    out
}

fun find(v: &vector<u8>, needle: vector<u8>): u64 {
    let mut i = 0;
    while (i < v.length()) {
        if (v[i] == needle[0]) return i;
        i = i + 1;
    };
    v.length()
}

/// target (u16-prefixed, 32 bytes), selector (u16-prefixed), amount (u128),
/// refund (u128), data (u32-prefixed); nothing after.
fun decode_action(a: &vector<u8>): (vector<u8>, vector<u8>, u128, u128) {
    let tl = (be(a, 0, 2) as u64);
    assert!(tl == 32, EMalformedAction);
    let target = slice(a, 2, 2 + tl);
    let sl = (be(a, 2 + tl, 2) as u64);
    let s0 = 4 + tl;
    let selector = slice(a, s0, s0 + sl);
    let at = s0 + sl;
    let amount = (be(a, at, 16) as u128);
    let refund = (be(a, at + 16, 16) as u128);
    let dl = (be(a, at + 32, 4) as u64);
    assert!(a.length() == at + 36 + dl, EMalformedAction);
    (target, selector, amount, refund)
}

/// The report of a paying action: kind 4, the grant's chain, account,
/// agent and seq, the nonce, the action's pay data and the amount.
public fun paid_report(grant: &vector<u8>, nonce: u64, action: &vector<u8>, amount: u128): vector<u8> {
    let tl = (be(action, 0, 2) as u64);
    let sl = (be(action, 2 + tl, 2) as u64);
    let at = 4 + tl + sl + 36;
    assert!(action.length() == at + PAY_DATA_LEN, EMalformedPayment);
    let mut r = x"04";
    r.append(slice(grant, 1, 97));
    r.append(slice(grant, 105, 113));
    r.append(be_bytes(nonce as u256, 8));
    r.append(slice(action, at, at + PAY_DATA_LEN));
    r.append(be_bytes(amount as u256, 16));
    r
}

/// The tree key of the grant of `did` on `caip2`: VM system storage, keyed
/// by the hex of `agent_grant:<did>:<caip2>`.
public fun grant_tree_key(did: &vector<u8>, caip2: &vector<u8>): vector<u8> {
    let mut key = b"agent_grant:";
    key.append(*did);
    key.append(b":");
    key.append(*caip2);
    let digits = b"0123456789abcdef";
    let mut out = b"tenzro.state-trie.key";
    out.append(x"0500");
    out.append(b"state");
    out.append(b"storage:ffffffffffffffffffffffffffffffffffffffff:");
    let mut i = 0;
    while (i < key.length()) {
        out.push_back(digits[((key[i] >> 4) as u64)]);
        out.push_back(digits[((key[i] & 15) as u64)]);
        i = i + 1;
    };
    sha2_256(out)
}

public fun target_leaf(target: &vector<u8>, selector: &vector<u8>): vector<u8> {
    let mut b = x"00";
    b.append(be_bytes(target.length() as u256, 2));
    b.append(*target);
    b.append(be_bytes(selector.length() as u256, 2));
    b.append(*selector);
    sha2_256(b)
}

/// Whether `leaf` is under `root` with `proof` (32-byte siblings, pairs
/// hashed in sorted order).
public fun merkle_verify(root: &vector<u8>, leaf: &vector<u8>, proof: &vector<u8>): bool {
    if (proof.length() % 32 != 0) return false;
    let mut acc = *leaf;
    let mut i = 0;
    while (i < proof.length()) {
        let s = slice(proof, i, i + 32);
        let mut b = x"01";
        if (to_u256(&acc) <= to_u256(&s)) {
            b.append(acc);
            b.append(s);
        } else {
            b.append(s);
            b.append(acc);
        };
        acc = sha2_256(b);
        i = i + 32;
    };
    &acc == root
}

/// Whether, under `root`, the entry with tree key `tk` holds `value`, by
/// the encoded state proof `proof`.
public fun verify_at(root: &vector<u8>, tk: &vector<u8>, value: &vector<u8>, proof: &vector<u8>): bool {
    if (proof.length() < 3) return false;
    let depth = (be(proof, 0, 2) as u64);
    if (depth > 248) return false;
    let t = 2 + 32 * depth;
    if (proof.length() != t + 1 + 256 || proof[t] != 2) return false;
    let stem = slice(tk, 0, 31);
    let mut s = {
        let mut b = x"00";
        b.append(*value);
        sha2_256(b)
    };
    let mut index = tk[31];
    let mut i = 0;
    while (i < 8) {
        let sib = slice(proof, t + 1 + 32 * i, t + 33 + 32 * i);
        s = if (index & 1 == 0) slot_pair(s, sib) else slot_pair(sib, s);
        index = index >> 1;
        i = i + 1;
    };
    if (s == ZERO32) return false;
    let mut acc = {
        let mut b = x"02";
        b.append(stem);
        b.append(s);
        sha2_256(b)
    };
    let mut d = depth;
    while (d > 0) {
        d = d - 1;
        let sib = slice(proof, 2 + 32 * d, 34 + 32 * d);
        let mut b = x"01";
        if (bit(&stem, d) == 0) {
            b.append(acc);
            b.append(sib);
        } else {
            b.append(sib);
            b.append(acc);
        };
        acc = sha2_256(b);
    };
    &acc == root
}

fun slot_pair(l: vector<u8>, r: vector<u8>): vector<u8> {
    if (l == ZERO32 && r == ZERO32) return ZERO32;
    let mut b = x"03";
    b.append(l);
    b.append(r);
    sha2_256(b)
}

fun bit(stem: &vector<u8>, depth: u64): u8 {
    (stem[depth / 8] >> ((7 - depth % 8) as u8)) & 1
}

/// A SEC1 point (0x04 || x || y), compressed.
fun compress(key: &vector<u8>): vector<u8> {
    let mut out = vector[2 + (key[64] & 1)];
    out.append(slice(key, 1, 33));
    out
}

fun be(v: &vector<u8>, at: u64, n: u64): u256 {
    let mut out: u256 = 0;
    let mut i = 0;
    while (i < n) {
        out = (out << 8) | (v[at + i] as u256);
        i = i + 1;
    };
    out
}

fun be_u64(v: &vector<u8>, at: u64): u64 {
    (be(v, at, 8) as u64)
}

fun be_u128(v: &vector<u8>, at: u64): u128 {
    (be(v, at, 16) as u128)
}

fun be_bytes(v: u256, n: u64): vector<u8> {
    let mut out = vector[];
    let mut i = n;
    while (i > 0) {
        i = i - 1;
        out.push_back(((v >> ((8 * i) as u8)) & 0xff) as u8);
    };
    out
}

fun to_u256(v: &vector<u8>): u256 {
    be(v, 0, v.length())
}

fun slice(v: &vector<u8>, from: u64, to: u64): vector<u8> {
    let mut out = vector[];
    let mut i = from;
    while (i < to) {
        out.push_back(v[i]);
        i = i + 1;
    };
    out
}
